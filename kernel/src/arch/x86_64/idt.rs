//! Interrupt Descriptor Table (IDT) for the x86_64 kernel.
//!
//! The IDT is the CPU's dispatch table for every interrupt and exception:
//! each of its 256 16-byte gate descriptors tells the processor, "when
//! vector N fires, jump to this handler address, using this code segment
//! selector, on this IST stack, with these privilege rules." Until the IDT
//! is loaded with `lidt`, *any* interrupt or exception causes an
//! unrecoverable triple fault — so loading this table is one of the very
//! first things the kernel does after the GDT is in place.
//!
//! # Layout
//!
//! [`Idt`] is a fixed array of 256 [`IdtEntry`] words. Vectors 0..=31 are
//! the architecture-defined CPU exceptions (`#DE`..reserved) and are
//! installed by [`install_exception_handlers`]. Vectors 32..=255 are the
//! IRQ and software-interrupt region; timer, SMP IPI, and device gates are
//! installed by their owning live subsystems via
//! [`Idt::set_interrupt_handler`].
//!
//! # Gate type
//!
//! All kernel handlers are installed as 64-bit *interrupt gates*
//! (`type_attr = 0x8E`): Present, DPL 0, type 0xE. An interrupt gate clears
//! `EFLAGS.IF` on entry, so the handler runs with maskable interrupts
//! disabled and a nested interrupt cannot preempt it. `iretq` restores the
//! saved `RFLAGS`, re-enabling interrupts if they were on before the fault.
//! Trap gates (type 0xF) would leave `IF` set; we reserve those for the
//! syscall/debug paths that explicitly want to stay interruptible.
//!
//! # Safety
//!
//! Building an [`IdtEntry`] is pure arithmetic and is safe. *Loading* a
//! table with [`Idt::load`] is `unsafe` because a malformed table (a
//! non-present gate that the CPU dispatches into, a handler address that
//! points at non-code, a selector that does not index the GDT) turns the
//! next interrupt into a fatal fault. The safe wrappers
//! [`install_exception_handlers`] and [`load`] establish the invariants
//! (every installed entry is present and points at a real asm stub; the
//! selector is `KERNEL_CODE_SELECTOR`, which the GDT always provides) before
//! loading, so callers above this module never have to reason about the
//! `unsafe` themselves.
//!
//! # The static table
//!
//! A single shared [`IDT`] lives in a [`SpinLock`] for the whole kernel.
//! Subsystems publish gates before the relevant IRQ source is unmasked, and
//! every AP loads this same table before enabling interrupts. The table is
//! `static`, so its
//! address is stable for the lifetime of the kernel — a hard requirement,
//! because `lidt` stores the base address in the IDTR and the CPU keeps
//! reading from it on every interrupt.

use super::asm;
use super::gdt::KERNEL_CODE_SELECTOR;
use super::instructions::{lidt, DescriptorTablePointer};
use crate::sync::SpinLock;

// ---------------------------------------------------------------------------
// Gate-type / attribute encoding
// ---------------------------------------------------------------------------

/// The gate-type nibble (bits 0..=3 of `type_attr`) for a 64-bit interrupt
/// gate. The CPU clears `EFLAGS.IF` on entry through an interrupt gate.
const GATE_INTERRUPT_64: u8 = 0x0E;

/// The gate-type nibble for a 64-bit trap gate. The CPU leaves `EFLAGS.IF`
/// untouched on entry through a trap gate.
const GATE_TRAP_64: u8 = 0x0F;

/// Present bit (bit 7 of `type_attr`). Every usable gate has this set; a
/// clear present bit makes the CPU raise a #GP if the vector fires.
const PRESENT: u8 = 1 << 7;

/// DPL (descriptor privilege level) shift: bits 5..=6 of `type_attr`. A DPL
/// of 0 means only ring-0 code can reach the gate via `int $n`; a DPL of 3
/// allows ring-3 code to invoke it with `int $n` (used for syscall-style
/// software interrupts). Hardware exceptions honour DPL only for `int`
/// instructions, not for hardware-generated faults.
const DPL_SHIFT: u8 = 5;

/// A ring-0 interrupt gate: Present | DPL 0 | type 0xE. This is the
/// attribute byte for every CPU-exception handler installed in this phase.
const ATTR_INTERRUPT_KERNEL: u8 = PRESENT | (0 << DPL_SHIFT) | GATE_INTERRUPT_64;

/// A ring-0 trap gate: Present | DPL 0 | type 0xF. Reserved for handlers
/// that must stay interruptible (debug, syscall software interrupts).
const ATTR_TRAP_KERNEL: u8 = PRESENT | (0 << DPL_SHIFT) | GATE_TRAP_64;

/// Mask for the IST index field of the entry's `ist` byte: bits 0..=2. A
/// value of 0 means "do not switch stacks"; 1..=7 selects the matching IST
/// entry in the current TSS.
const IST_MASK: u8 = 0x07;

/// The number of vectors in a full IDT. Vectors 0..=255: the first 32 are
/// CPU exceptions, the remaining 224 are IRQs and software interrupts.
pub const VECTORS: usize = 256;

/// The number of architecture-defined CPU exception vectors (0..=31).
pub const EXCEPTION_VECTORS: usize = 32;

// ---------------------------------------------------------------------------
// IDT gate descriptor (16 bytes)
// ---------------------------------------------------------------------------

/// A single 64-bit IDT gate descriptor.
///
/// The in-memory layout exactly matches the hardware descriptor the CPU
/// reads via `lidt`: a 64-bit handler address is split across three fields
/// (`offset_low`, `offset_mid`, `offset_high`), a segment selector names
/// the code segment the CPU loads into `CS`, the `ist` byte selects an
/// Interrupt Stack Table entry, and `type_attr` encodes present/DPL/gate
/// type. `reserved` must be zero.
///
/// We use `repr(C, packed)` so there is no padding between fields and the
/// struct is exactly 16 bytes. Every field is naturally aligned within the
/// 16-byte descriptor (u16 at even offsets, u32 at offset 8), so the
/// `packed` attribute does not create any unaligned accesses — it is
/// belt-and-braces to guarantee the hardware layout.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct IdtEntry {
    /// Bits 0..15 of the handler's virtual address.
    offset_low: u16,
    /// Segment selector the CPU loads into `CS` before jumping to the
    /// handler. Always [`KERNEL_CODE_SELECTOR`] for kernel handlers.
    selector: u16,
    /// Low 3 bits select an IST stack (1..=7) or 0 for "no stack switch".
    /// Bits 3..=7 are reserved and must be zero.
    ist: u8,
    /// Present bit, DPL, and gate type. Built from the `ATTR_*` / `GATE_*`
    /// constants above.
    type_attr: u8,
    /// Bits 16..31 of the handler's virtual address.
    offset_mid: u16,
    /// Bits 32..63 of the handler's virtual address.
    offset_high: u32,
    /// Reserved; the CPU ignores this field and it must be zero.
    reserved: u32,
}

impl IdtEntry {
    /// An absent entry: all fields zero. A vector whose entry is `missing`
    /// has its present bit clear, so the CPU raises a #GP if that vector
    /// fires. Every [`Idt`] starts full of `missing` entries; the loader
    /// overwrites the ones it wants active.
    #[inline]
    #[must_use]
    pub const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    /// Build a gate descriptor from its raw parts.
    ///
    /// `handler` is the full 64-bit virtual address of the entry stub.
    /// `selector` is the code segment selector (almost always
    /// [`KERNEL_CODE_SELECTOR`]). `type_attr` is a complete attribute byte
    /// (e.g. [`ATTR_INTERRUPT_KERNEL`]). `ist` is the IST index (0 for no
    /// stack switch, 1..=7 to switch to the matching TSS IST stack); only
    /// its low 3 bits are used.
    #[inline]
    #[must_use]
    pub const fn new(handler: u64, selector: u16, type_attr: u8, ist: u8) -> Self {
        Self {
            offset_low: (handler & 0xFFFF) as u16,
            selector,
            ist: ist & IST_MASK,
            type_attr,
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: ((handler >> 32) & 0xFFFF_FFFF) as u32,
            reserved: 0,
        }
    }

    /// Whether this entry's present bit is set.
    ///
    /// Used by diagnostics to confirm which vectors are actually wired up
    /// before the table is loaded.
    #[inline]
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.type_attr & PRESENT != 0
    }
}

// ---------------------------------------------------------------------------
// The IDT table
// ---------------------------------------------------------------------------

/// The 256-entry Interrupt Descriptor Table.
///
/// Wraps a fixed array of [`IdtEntry`] so callers can index by vector
/// number and load the whole table with a single `lidt`. The table is
/// initialised to all-`missing` entries by [`Idt::new`]; active gates are
/// installed with [`set_handler`](Self::set_handler) or the
/// `set_*_handler` convenience methods.
#[repr(align(16))]
#[repr(C)]
pub struct Idt {
    entries: [IdtEntry; VECTORS],
}

impl Idt {
    /// A table whose every entry is [`IdtEntry::missing`].
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [IdtEntry::missing(); VECTORS],
        }
    }

    /// Install a gate at `index` from its raw parts.
    ///
    /// `index` is the vector number (0..255). `handler` is the entry stub's
    /// address; `type_attr` controls present/DPL/gate type; `ist` selects an
    /// IST stack. Out-of-range `index` is silently ignored — the IDT loader
    /// only ever passes in-bounds indices, and panicking inside the loader
    /// (which runs before the IDT is active) would itself need an IDT.
    #[inline]
    pub fn set_handler(&mut self, index: u16, handler: u64, type_attr: u8, ist: u8) {
        let i = usize::from(index);
        if i >= VECTORS {
            return;
        }
        self.entries[i] = IdtEntry::new(handler, KERNEL_CODE_SELECTOR, type_attr, ist);
    }

    /// Install a ring-0 interrupt gate at `index` with IST stack 0 (no
    /// stack switch).
    ///
    /// This is the shape used by every CPU-exception handler: present, DPL
    /// 0, interrupt-gate type (so `EFLAGS.IF` is cleared on entry), running
    /// on the interrupted stack.
    #[inline]
    pub fn set_interrupt_handler(&mut self, index: u16, handler: unsafe extern "C" fn()) {
        self.set_interrupt_handler_ist(index, handler, 0);
    }

    /// Install a ring-0 interrupt gate at `index` that switches to IST
    /// stack `ist` (1..=7) on entry. `ist = 0` means "no stack switch" and
    /// matches [`set_interrupt_handler`](Self::set_interrupt_handler).
    ///
    /// IST stacks matter for faults that corrupt the current stack
    /// (`#DF`, `#SS`, `#MC`, a kernel `#PF` taken while on a bad stack):
    /// switching to a known-good stack lets the handler run and report the
    /// fault instead of double-faulting into the broken stack. The IST
    /// stacks themselves are owned by the TSS module; this function only
    /// records the index in the gate.
    #[inline]
    pub fn set_interrupt_handler_ist(
        &mut self,
        index: u16,
        handler: unsafe extern "C" fn(),
        ist: u8,
    ) {
        self.set_handler(index, handler as usize as u64, ATTR_INTERRUPT_KERNEL, ist);
    }

    /// Install a ring-0 trap gate at `index`. A trap gate leaves
    /// `EFLAGS.IF` as it was, so the handler remains interruptible. Used for
    /// the debug and syscall software-interrupt paths.
    #[inline]
    pub fn set_trap_handler(&mut self, index: u16, handler: unsafe extern "C" fn()) {
        self.set_handler(index, handler as usize as u64, ATTR_TRAP_KERNEL, 0);
    }

    /// Read back the entry at `index`, or [`IdtEntry::missing`] if `index`
    /// is out of range. Used by diagnostics; not on the hot path.
    #[inline]
    #[must_use]
    pub fn entry(&self, index: u16) -> IdtEntry {
        let i = usize::from(index);
        if i >= VECTORS {
            return IdtEntry::missing();
        }
        self.entries[i]
    }

    /// Load this table into the CPU's IDTR via `lidt`.
    ///
    /// After this call the CPU dispatches every interrupt and exception
    /// through `self`. The table must outlive the CPU's use of it — in
    /// practice it lives in the [`IDT`] static, so it lives forever.
    ///
    /// # Safety
    ///
    /// Every installed entry must be a valid gate: present where the CPU
    /// might dispatch, with a handler address pointing at real executable
    /// code and a selector indexing a present, executable, ring-0 code
    /// descriptor in the current GDT. Loading a malformed IDT turns the
    /// next interrupt into a fatal fault. The safe wrappers above build
    /// only valid entries from real asm stubs and `KERNEL_CODE_SELECTOR`,
    /// so callers that use them do not need to invoke this directly.
    #[inline]
    pub unsafe fn load(&self) {
        let pointer = DescriptorTablePointer::new(
            core::mem::size_of::<Self>() as u16 - 1,
            core::ptr::addr_of!(*self) as u64,
        );
        // SAFETY: the caller (or the safe wrapper that built `self`) vouches
        // for every installed entry being a valid gate. `pointer` describes
        // this very table: the limit covers all 256 entries and the base is
        // the table's own stable address. `lidt` reads the 10-byte
        // descriptor from `pointer` and stores its base/limit in the IDTR.
        unsafe {
            lidt(&pointer);
        }
    }
}

impl Default for Idt {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Idt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Report only the count of present gates — a full 256-entry dump is
        // noise, and most entries are `missing` until the IRQ phase wires
        // them up. The vector index is not needed here; if a future caller
        // wants the list of live vectors, it can iterate `entry(v)` itself.
        let mut present = 0u16;
        for e in self.entries.iter() {
            if e.is_present() {
                present += 1;
            }
        }
        f.debug_struct("Idt")
            .field("vectors", &VECTORS)
            .field("present", &present)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// The global table and the public load / install API
// ---------------------------------------------------------------------------

/// The kernel's single Interrupt Descriptor Table.
///
/// Behind a [`SpinLock`] because timer, SMP, and device initialization publish
/// gates at different points before their sources are unmasked. Every CPU
/// loads this shared table; its static address remains valid in each IDTR for
/// the lifetime of the kernel.
pub static IDT: SpinLock<Idt> = SpinLock::new(Idt::new());

/// Install handlers for the 32 architecture CPU exceptions (vectors 0..31).
///
/// Each vector is wired to the matching `isr_N` stub from
/// [`asm::isr`] as a ring-0 interrupt gate on IST 0. The stubs normalise
/// the stack frame and call [`super::interrupts::exceptions::rust_isr_dispatch`],
/// which matches on the vector and routes to the per-exception Rust
/// handler.
///
/// This only mutates the in-memory [`IDT`]; it does not load it into the
/// CPU. Pair it with [`load`] (or call [`super::interrupts::init`], which
/// does both) before enabling interrupts.
pub fn install_exception_handlers() {
    let mut idt = IDT.lock();
    for v in 0u8..EXCEPTION_VECTORS as u8 {
        // SAFETY: `asm::isr::entry` is exhaustive over 0..=31 by construction
        // (a match over all 32 stubs), so `v` in range yields a real asm
        // entry pointer. The cast to `u64` is a plain address-of.
        let handler = asm::isr::entry(v);
        if v == 8 {
            idt.set_interrupt_handler_ist(u16::from(v), handler, super::tss::DOUBLE_FAULT_IST);
        } else {
            idt.set_interrupt_handler(u16::from(v), handler);
        }
    }
}

/// Install the local-APIC timer interrupt gate at `vector`.
///
/// The timer stub preserves the interrupted register file, conditionally
/// swaps GS when the interrupt arrived from ring 3, calls the scheduler's
/// Rust tick entry, and returns through `iretq`. The caller must install this
/// gate before unmasking/arming the LAPIC timer.
///
/// `vector` must be in the hardware-interrupt range (`0x20..=0xFF`). An
/// out-of-range value is rejected in debug builds; production boot passes the
/// fixed scheduler vector.
pub fn install_timer_handler(vector: u8) {
    debug_assert!(
        usize::from(vector) >= EXCEPTION_VECTORS,
        "LAPIC timer vector overlaps CPU exceptions"
    );
    let mut idt = IDT.lock();
    idt.set_interrupt_handler(u16::from(vector), asm::irq::lapic_timer_isr);
}

/// Install the two fixed SMP inter-processor interrupt gates.
///
/// The shared IDT is live on every CPU; publishing these entries before the
/// first SIPI guarantees APs can enable interrupts immediately after loading
/// the table.
pub fn install_ipi_handlers(reschedule_vector: u8, tlb_vector: u8) {
    debug_assert!(usize::from(reschedule_vector) >= EXCEPTION_VECTORS);
    debug_assert!(usize::from(tlb_vector) >= EXCEPTION_VECTORS);
    debug_assert_ne!(reschedule_vector, tlb_vector);
    let mut idt = IDT.lock();
    idt.set_interrupt_handler(u16::from(reschedule_vector), asm::irq::reschedule_ipi_isr);
    idt.set_interrupt_handler(u16::from(tlb_vector), asm::irq::tlb_shootdown_ipi_isr);
}

/// Load the kernel IDT into the CPU's IDTR.
///
/// The table must already have been populated (typically by
/// [`install_exception_handlers`]); loading an all-`missing` table would
/// turn the next interrupt into a #GP. The caller is also responsible for
/// having loaded the GDT first, so that [`KERNEL_CODE_SELECTOR`] resolves
/// to a real code segment when the CPU dispatches a gate.
///
/// # Panics
///
/// This wrapper cannot panic — it delegates to the `unsafe` [`Idt::load`]
/// under the invariants established by [`install_exception_handlers`].
pub fn load() {
    let idt = IDT.lock();
    // SAFETY: `install_exception_handlers` (run by `interrupts::init` before
    // this) filled vectors 0..31 with present gates pointing at real asm
    // stubs, all using `KERNEL_CODE_SELECTOR`, which the GDT — loaded
    // earlier in the boot sequence — provides as a present ring-0 code
    // descriptor. The remaining vectors are `missing` (present bit clear),
    // which is a valid, non-fatal state as long as nothing dispatches them
    // before the IRQ phase installs handlers. `idt` borrows the `IDT`
    // static, so its address is stable for the CPU's lifetime.
    unsafe {
        idt.load();
    }
}
