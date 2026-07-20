//! Raw x86_64 instruction wrappers.
//!
//! Each function here corresponds to exactly one privileged or
//! architecturally-significant instruction. The wrappers exist so the rest of
//! the kernel never has to spell `core::arch::asm!` inline — every access to
//! a control register, MSR, or descriptor-table register goes through a
//! named, type-safe, documented function in this file.
//!
//! # Convention
//!
//! * Every wrapper is `unsafe` unless it is provably side-effect-free in
//!   Rust's memory model (`hlt`, `pause`). Privileged instructions are unsafe
//!   because the caller must be in ring 0 (or hold the relevant IOPL/CPL
//!   privilege) — a contract the type system cannot check.
//! * Every `unsafe fn` carries a `# Safety` doc explaining the invariant.
//! * Inline asm is annotated with the narrowest correct `options(...)` set.
//!   In particular `preserves_flags` is only set for instructions that
//!   genuinely leave EFLAGS alone, and `nomem`/`nostack` are only set when
//!   the instruction touches neither.
//! * Functions that read a register return the value; functions that write a
//!   register take the new value by value. There is no "read-then-write"
//!   helper here — those belong in `registers.rs`, which builds the flag-set
//!   abstractions on top of these primitives.

use core::arch::asm;
use core::marker::PhantomData;

// ---------------------------------------------------------------------------
// Interrupt-control / halt
// ---------------------------------------------------------------------------

/// Halt the CPU until the next interrupt.
///
/// `hlt` puts the processor into a halted state until an unmasked interrupt
/// (or NMI/SMI) arrives. With interrupts disabled it halts indefinitely
/// (the only way out is an NMI or reset). It is the lowest-power state the
/// CPU can enter without architecture support for deeper C-states.
///
/// # Safety
///
/// `hlt` performs no memory access and touches no register state beyond the
/// instruction pointer, so it is safe to call from any context. It is marked
/// safe (not unsafe) for that reason — the only consequence of calling it at
/// a bad time is that the CPU sleeps when the caller did not intend it to,
/// which is a logic bug rather than a safety violation.
#[inline]
pub fn hlt() {
    // SAFETY: `hlt` halts until the next interrupt. It reads/writes no
    // memory and no general-purpose registers; only RIP advances. The
    // `nostack` and `nomem` options reflect that. It does not modify EFLAGS,
    // so `preserves_flags` is correct.
    unsafe {
        asm!("hlt", options(nostack, nomem, preserves_flags));
    }
}

/// Disable maskable interrupts by clearing EFLAGS.IF.
///
/// After `cli`, the CPU will not deliver maskable interrupts until either
/// `sti` is executed or EFLAGS.IF is restored by `iretq` / a task switch.
/// NMI, SMI, and machine-check exceptions are not masked.
///
/// # Safety
///
/// `cli` modifies EFLAGS.IF, which is a privileged bit. Executing it at
/// CPL > IOPL raises a #GP. The kernel always runs at CPL 0 with IOPL 0, so
/// the call is valid in any kernel context; the caller is responsible for
/// pairing it with `sti` (or a saved-flags restore) so interrupts do not stay
/// masked indefinitely.
#[inline]
pub unsafe fn cli() {
    // SAFETY: `cli` clears IF in EFLAGS. It touches no memory and no stack,
    // but it DOES modify EFLAGS so we must NOT pass `preserves_flags`.
    unsafe {
        asm!("cli", options(nostack, nomem));
    }
}

/// Enable maskable interrupts by setting EFLAGS.IF.
///
/// On x86, `sti` defers interrupt delivery for one instruction so a `sti; hlt`
/// pair is safe: an interrupt that arrives between the two cannot race the
/// `hlt` and leave the CPU spinning.
///
/// # Safety
///
/// `sti` sets EFLAGS.IF, a privileged bit. CPL > IOPL raises #GP. The caller
/// is responsible for ensuring it is safe to accept interrupts in the current
/// context (e.g. the IDT is loaded and the per-CPU stack is valid).
#[inline]
pub unsafe fn sti() {
    // SAFETY: `sti` sets IF in EFLAGS. Same caveats as `cli` re: flags.
    unsafe {
        asm!("sti", options(nostack, nomem));
    }
}

/// Return whether maskable interrupts are enabled on the current CPU.
///
/// Reading RFLAGS is non-privileged and has no side effects, so callers may
/// use this to defer long work that would otherwise run inside an exception
/// or interrupt-disabled critical section.
#[inline]
#[must_use]
pub fn interrupts_enabled() -> bool {
    let flags: u64;
    // SAFETY: the balanced push/pop only snapshots RFLAGS into a general
    // register. It changes neither flags nor memory visible to Rust.
    unsafe {
        asm!(
            "pushfq",
            "pop {flags}",
            flags = out(reg) flags,
        );
    }
    flags & (1 << 9) != 0
}

/// An RAII guard that restores the caller's complete RFLAGS image on drop.
///
/// Create one with [`InterruptGuard::disable`] before a short critical
/// section that must not be interrupted. Construction snapshots RFLAGS and
/// executes `cli`; dropping the guard restores that snapshot with `popfq`.
/// Consequently IF is re-enabled only when it was set before the critical
/// section. This is the x86 `local_irq_save`/`local_irq_restore` pattern and
/// is safe to nest: an inner guard observes IF clear and keeps it clear when
/// it drops, while the outer guard eventually restores the original state.
///
/// The guard must remain on the CPU that created it. Its `PhantomData<*mut
/// ()>` marker makes it `!Send` and `!Sync`, while maskable interrupts remain
/// disabled throughout its lifetime so Xenith's interrupt-driven scheduler
/// cannot migrate the holder before the guard is dropped.
#[must_use = "dropping the interrupt guard immediately restores the saved RFLAGS"]
pub struct InterruptGuard {
    saved_rflags: u64,
    /// Compile-time CPU-affinity invariant: raw mutable pointers implement
    /// neither `Send` nor `Sync`, so safe code cannot transfer this guard to
    /// another CPU before its saved flags are restored.
    _pin: PhantomData<*mut ()>,
}

impl InterruptGuard {
    /// Snapshot RFLAGS and disable maskable interrupts on this CPU.
    ///
    /// # Safety
    ///
    /// The caller must run at CPL 0 (or with sufficient IOPL for `cli`) and
    /// must drop the returned guard on the same CPU. The guard must not be
    /// leaked: doing so would leave maskable interrupts disabled.
    #[inline]
    pub unsafe fn disable() -> Self {
        let saved_rflags: u64;
        // SAFETY: `pushfq`/`pop` is stack-balanced and captures the complete
        // pre-`cli` flags image. `cli` is permitted by the caller's CPL/IOPL
        // contract. No asm options are declared because the sequence touches
        // the stack, modifies flags, and acts as a compiler memory barrier
        // around the critical section.
        unsafe {
            asm!(
                "pushfq",
                "pop {saved}",
                "cli",
                saved = out(reg) saved_rflags,
            );
        }
        Self {
            saved_rflags,
            _pin: PhantomData,
        }
    }
}

impl Drop for InterruptGuard {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: `saved_rflags` was captured by `disable` on this CPU, and
        // maskable interrupts have remained disabled since then. The
        // push/pop pair is balanced and restores IF exactly as the caller
        // supplied it rather than enabling interrupts unconditionally.
        unsafe {
            asm!(
                "push {saved}",
                "popfq",
                saved = in(reg) self.saved_rflags,
            );
        }
    }
}

/// Yield the current CPU core to a peer hyperthread.
///
/// `pause` is a hint to the CPU that the caller is in a spin-wait loop. It
/// improves performance and power on SMT parts by releasing execution
/// resources to the sibling thread for the duration of the spin. It is a
/// no-op on non-SMT hardware. It does not modify any architectural state.
#[inline]
pub fn pause() {
    // SAFETY: `pause` is a no-op hint; it touches no memory, no stack, and
    // no registers. `preserves_flags` is valid because `pause` does not
    // modify EFLAGS.
    unsafe {
        asm!("pause", options(nostack, nomem, preserves_flags));
    }
}

// ---------------------------------------------------------------------------
// Descriptor-table registers: GDT, IDT, LTR
// ---------------------------------------------------------------------------

/// The `lgdt` operand: a 10-byte pseudo-descriptor.
///
/// The x86 `lgdt` / `sidt` instructions take a 10-byte memory operand whose
/// first 16 bits are the table limit (one less than the table size in bytes)
/// and whose next 64 bits are the linear base address of the table. We model
/// it as a `#[repr(C, packed)]` struct so the layout matches what the
/// instruction expects regardless of the compiler's field padding rules.
///
/// Because the struct is `packed`, the `base` field at offset 2 is unaligned.
/// We deliberately do not derive `Debug`/`Clone` through the usual macro,
/// since that would take an unaligned reference to `base` (undefined
/// behaviour). [`DescriptorTablePointer::new`] and the manual [`Debug`] impl
/// below copy fields through aligned locals instead.
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct DescriptorTablePointer {
    /// The limit: `table_size_in_bytes - 1`. Stored as a 16-bit little-endian
    /// value at offset 0.
    pub limit: u16,
    /// The linear base address of the table. Stored as a 64-bit little-endian
    /// value at offset 2 (unaligned, hence `packed`). Access this only via
    /// [`base`](Self::base) / [`set_base`](Self::set_base), which copy
    /// through an aligned local to avoid an unaligned reference.
    pub base: u64,
}

impl DescriptorTablePointer {
    /// Construct a pseudo-descriptor from a limit and a base address.
    ///
    /// The fields are written through aligned locals and then stored, so no
    /// unaligned reference is ever created.
    #[inline]
    #[must_use]
    pub const fn new(limit: u16, base: u64) -> Self {
        Self { limit, base }
    }

    /// Read the base address as an aligned copy.
    ///
    /// Accessing `self.base` directly would create an unaligned reference
    /// (the field sits at offset 2 in a packed struct); this method copies
    /// the value into an aligned `u64` first.
    #[inline]
    #[must_use]
    pub fn base(&self) -> u64 {
        // SAFETY: We read the field via a raw pointer copy rather than a
        // reference, so no unaligned reference is formed. The struct is
        // `#[repr(C, packed)]`, so the field is at offset 2 and is a valid
        // `u64` even though unaligned.
        let addr = core::ptr::addr_of!(self.base);
        // SAFETY: `addr` points to a valid, initialized `u64` inside `self`.
        // `read_unaligned` copies the value without requiring alignment.
        unsafe { core::ptr::read_unaligned(addr) }
    }

    /// Read the limit as an aligned copy. The limit is at offset 0 and is
    /// naturally aligned, but we provide this for symmetry with
    /// [`base`](Self::base).
    #[inline]
    #[must_use]
    pub fn limit(&self) -> u16 {
        self.limit
    }
}

impl core::fmt::Debug for DescriptorTablePointer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Copy both fields into aligned locals before formatting, so the
        // formatter never takes a reference to the packed, unaligned `base`.
        let limit = self.limit;
        let base = self.base();
        f.debug_struct("DescriptorTablePointer")
            .field("limit", &limit)
            .field("base", &base)
            .finish()
    }
}

/// Load a new Global Descriptor Table.
///
/// `lgdt` loads the GDTR from the 10-byte pseudo-descriptor at `pointer`. The
/// CPU immediately treats segment-selector loads against the new GDT.
///
/// # Safety
///
/// The caller must ensure `pointer` points to a valid 10-byte
/// [`DescriptorTablePointer`] describing a GDT whose entries are all valid and
/// whose base/limit cover the whole table. Loading a malformed GDT will #GP
/// on the next segment load, which in ring 0 is fatal.
#[inline]
pub unsafe fn lgdt(pointer: &DescriptorTablePointer) {
    // SAFETY: `lgdt [mem]` reads 10 bytes from the operand. We pass a
    // reference to a packed struct of exactly that size. The caller vouches
    // for the descriptor's contents. `lgdt` does not modify EFLAGS and
    // touches no stack, but it DOES read memory so `nomem` is wrong; we leave
    // the memory options at default.
    unsafe {
        asm!(
            "lgdt [{ptr}]",
            ptr = in(reg) pointer as *const DescriptorTablePointer as u64,
            options(nostack, preserves_flags),
        );
    }
}

/// Store the current GDTR into the 10-byte buffer at `pointer`.
///
/// `sgdt` writes the current GDT base and limit into the operand. It is one
/// of the few descriptor-register reads that is non-privileged.
///
/// # Safety
///
/// The caller must ensure `pointer` points to at least 10 bytes of writable
/// memory. The write is unconditionally performed by the instruction.
#[inline]
pub unsafe fn sgdt(pointer: &mut DescriptorTablePointer) {
    // SAFETY: `sgdt [mem]` writes 10 bytes to the operand. The caller
    // provides a writable reference of the right size. `sgdt` is
    // non-privileged but we keep the fn unsafe to match the symmetric `lgdt`
    // and to make the memory-aliasing contract explicit.
    unsafe {
        asm!(
            "sgdt [{ptr}]",
            ptr = in(reg) pointer as *mut DescriptorTablePointer as u64,
            options(nostack, preserves_flags),
        );
    }
}

/// Load a new Interrupt Descriptor Table.
///
/// `lidt` loads the IDTR from the 10-byte pseudo-descriptor at `pointer`.
/// Until the IDT is loaded, any interrupt raises a #GP/DF cascade that the
/// CPU cannot route — `lidt` is therefore one of the very first instructions
/// the kernel executes after gaining control.
///
/// # Safety
///
/// The caller must ensure `pointer` describes a valid IDT whose entries cover
/// every interrupt vector the kernel might receive. Loading a malformed IDT
/// turns the next interrupt into a fatal fault.
#[inline]
pub unsafe fn lidt(pointer: &DescriptorTablePointer) {
    unsafe {
        asm!(
            "lidt [{ptr}]",
            ptr = in(reg) pointer as *const DescriptorTablePointer as u64,
            options(nostack, preserves_flags),
        );
    }
}

/// Store the current IDTR into the 10-byte buffer at `pointer`.
///
/// # Safety
///
/// The caller must ensure `pointer` points to at least 10 bytes of writable
/// memory.
#[inline]
pub unsafe fn sidt(pointer: &mut DescriptorTablePointer) {
    unsafe {
        asm!(
            "sidt [{ptr}]",
            ptr = in(reg) pointer as *mut DescriptorTablePointer as u64,
            options(nostack, preserves_flags),
        );
    }
}

/// Load the Task Register with the given segment selector.
///
/// `ltr` loads the TR with a 16-bit selector that must index a TSS
/// descriptor in the GDT. The CPU uses the TSS for IST stacks and, on a
/// task switch that uses the legacy hardware task mechanism, for register
/// state. Xenith uses IST only; the legacy task mechanism is unused.
///
/// # Safety
///
/// The caller must ensure `selector` indexes a valid TSS descriptor in the
/// currently-loaded GDT and that the referenced TSS is properly aligned and
/// initialised. `ltr` with a bad selector #GPs immediately.
#[inline]
pub unsafe fn ltr(selector: u16) {
    // SAFETY: `ltr ax` loads TR from the 16-bit operand. The caller vouches
    // for the selector. `ltr` touches no memory and no stack; it does not
    // modify EFLAGS.
    unsafe {
        asm!("ltr {sel:x}", sel = in(reg) selector, options(nostack, nomem, preserves_flags));
    }
}

// ---------------------------------------------------------------------------
// TLB management
// ---------------------------------------------------------------------------

/// Invalidate the TLB entry for a single 4 KiB page at `addr`.
///
/// `invlpg` flushes the TLB entry that maps the page containing `addr`. Other
/// translations, including global pages, are unaffected. Use
/// [`tlb_flush_all`] to flush every non-global entry, or write CR3 to flush
/// non-global entries process-wide.
///
/// # Safety
///
/// `invlpg` is privileged (CPL 0). The caller must ensure the address is a
/// canonical virtual address — a non-canonical `invlpg` is ignored silently,
/// which is usually not what the caller intended.
#[inline]
pub unsafe fn invlpg(addr: u64) {
    // SAFETY: `invlpg [rax]` takes a memory operand; the CPU only uses the
    // virtual address it encodes, it does not read memory. We pass the
    // address in a register and let the assembler encode it as a
    // RIP-relative or register-indirect operand. `invlpg` does not modify
    // EFLAGS and touches no stack.
    unsafe {
        asm!(
            "invlpg [{addr}]",
            addr = in(reg) addr,
            options(nostack, preserves_flags),
        );
    }
}

/// Write back every modified cache line and invalidate the processor caches.
///
/// Xenith uses this once during single-CPU boot immediately before changing
/// the framebuffer's page-table memory type from write-back to
/// write-combining. This prevents dirty lines produced by the early splash or
/// console from surviving across the cache-policy transition.
///
/// # Safety
///
/// The caller must execute at CPL 0, must serialize this instruction with any
/// accesses to mappings whose cache policy is changing, and must ensure other
/// processors cannot concurrently access those mappings.
#[inline]
pub unsafe fn wbinvd() {
    // SAFETY: the caller supplies the privilege and cache-policy transition
    // invariants. WBINVD uses no stack or general-purpose registers and
    // preserves RFLAGS, but it has global memory/cache effects, so `nomem` is
    // deliberately omitted to keep this a compiler memory barrier.
    unsafe {
        asm!("wbinvd", options(nostack, preserves_flags));
    }
}

/// Order every earlier store before any later store.
///
/// This also drains write-combining buffers, which gives framebuffer present
/// calls a real completion boundary after their final damaged rectangle.
#[inline]
pub fn sfence() {
    // SAFETY: SFENCE is available on every x86_64 processor, takes no
    // operands, and preserves RFLAGS. `nomem` is intentionally omitted so
    // the compiler cannot move framebuffer stores across the fence.
    unsafe {
        asm!("sfence", options(nostack, preserves_flags));
    }
}

/// Flush all non-global TLB entries by reloading CR3.
///
/// Writing CR3 invalidates every non-global TLB entry on the local core. It
/// is the canonical way to force a fresh walk after a page-table change that
/// affects many entries. Global-page entries survive; flush those with a
/// CR4.PGE toggle if needed.
#[inline]
pub fn tlb_flush_all() {
    // SAFETY: Reading and writing back CR3 preserves the current page-table
    // root (the address bits are unchanged) and only has the side effect of
    // flushing non-global TLB entries. This is safe in any ring-0 context
    // because the page tables are not actually changed — only the TLB is.
    // We use the raw read/write_cr3 pair rather than the Cr3 type so this
    // leaf helper has no dependency on registers.rs.
    let cr3 = unsafe { read_cr3() };
    unsafe { write_cr3(cr3) };
}

// ---------------------------------------------------------------------------
// Control registers
// ---------------------------------------------------------------------------

/// Read CR0.
///
/// CR0 holds the system control flags that gate protected mode, paging, write
/// protect, and x87 emulation. See [`Cr0`](crate::arch::x86_64::registers::Cr0)
/// for the decoded flag set.
///
/// # Safety
///
/// `mov cr0, reg` is privileged. The read itself has no side effects, but the
/// caller must be in ring 0.
#[inline]
#[must_use]
pub unsafe fn read_cr0() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {out}, cr0", out = out(reg) value, options(nostack, preserves_flags));
    }
    value
}

/// Write CR0.
///
/// # Safety
///
/// The caller must ensure `value` is a sensible CR0 image: paging (bit 31)
/// must not be cleared while the kernel is running in a paged context, and
/// clearing protected mode (bit 0) is fatal in long mode. Most bits have
/// architectural constraints documented in the SDM Vol. 3, Ch. 2.
#[inline]
pub unsafe fn write_cr0(value: u64) {
    unsafe {
        asm!("mov cr0, {val}", val = in(reg) value, options(nostack, preserves_flags));
    }
}

/// Read CR2, the page-fault linear address.
///
/// CR2 holds the virtual address that triggered the most recent page fault.
/// It is read-only in the sense that writes are ignored; the CPU updates it
/// on every page fault.
///
/// # Safety
///
/// `mov cr2, reg` is privileged. The read has no side effects.
#[inline]
#[must_use]
pub unsafe fn read_cr2() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {out}, cr2", out = out(reg) value, options(nostack, preserves_flags));
    }
    value
}

/// Read CR3, the page-table root physical address.
///
/// CR3 holds the physical address of the PML4 table (bits 12..=51) plus a
/// couple of feature bits (PCID, PWT, PCD). Reading it does not flush the
/// TLB.
///
/// # Safety
///
/// `mov cr3, reg` is privileged. The read has no side effects.
#[inline]
#[must_use]
pub unsafe fn read_cr3() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {out}, cr3", out = out(reg) value, options(nostack, preserves_flags));
    }
    value
}

/// Write CR3, loading a new page-table root.
///
/// Writing CR3 switches the active address space and flushes non-global TLB
/// entries on the local core. If the PCID feature is enabled and the new CR3
/// carries a PCID, only the entries for the outgoing PCID are flushed.
///
/// # Safety
///
/// The caller must ensure `value` is a valid CR3 image: bits 12..=51 must be
/// the physical address of a valid, present PML4 table, and the reserved bits
/// must be zero. A bad CR3 image faults on the next memory access.
#[inline]
pub unsafe fn write_cr3(value: u64) {
    unsafe {
        asm!("mov cr3, {val}", val = in(reg) value, options(nostack, preserves_flags));
    }
}

/// Read CR4.
///
/// CR4 gates architectural feature enablement: PAE, PGE, OSFXSR, SMEP/SMAP,
/// PCID, FSGSBASE, XSAVE, and many others. See
/// [`Cr4`](crate::arch::x86_64::registers::Cr4) for the decoded flag set.
///
/// # Safety
///
/// `mov cr4, reg` is privileged. The read has no side effects.
#[inline]
#[must_use]
pub unsafe fn read_cr4() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {out}, cr4", out = out(reg) value, options(nostack, preserves_flags));
    }
    value
}

/// Write CR4.
///
/// # Safety
///
/// The caller must ensure every bit set in `value` corresponds to a feature
/// the CPU actually advertises via CPUID. Setting an unsupported feature bit
/// raises a #GP. The ordering relative to other enablement (e.g. setting
/// CR4.PAE before EFER.LME) is documented in the SDM and is the caller's
/// responsibility.
#[inline]
pub unsafe fn write_cr4(value: u64) {
    unsafe {
        asm!("mov cr4, {val}", val = in(reg) value, options(nostack, preserves_flags));
    }
}

// ---------------------------------------------------------------------------
// Model-Specific Registers
// ---------------------------------------------------------------------------

/// Read a model-specific register.
///
/// `rdmsr` reads the 64-bit MSR identified by `ecx` into
/// `edx:eax` (high 32 bits in `edx`, low 32 in `eax`). We return it as a
/// single `u64`.
///
/// # Safety
///
/// `rdmsr` is privileged (CPL 0). Reading a reserved or non-existent MSR
/// raises a #GP. The caller must ensure `msr` is a valid MSR address for the
/// running CPU model.
#[inline]
#[must_use]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Write a model-specific register.
///
/// `wrmsr` writes the 64-bit `value` to the MSR identified by `ecx`,
/// splitting it as `edx:eax`.
///
/// # Safety
///
/// `wrmsr` is privileged. Writing a reserved or non-existent MSR raises a
/// #GP. Many MSRs have field encodings with reserved bits that must be zero;
/// setting a reserved bit also #GP's. The caller is responsible for
/// constructing a well-formed value for the target MSR.
#[inline]
pub unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// CPUID
// ---------------------------------------------------------------------------

/// The four CPUID output registers for a given `(leaf, subleaf)` query.
///
/// `cpuid` returns four 32-bit registers (`eax`, `ebx`, `ecx`, `edx`) whose
/// meaning depends on the requested leaf. This struct carries them
/// uninterpreted; leaf-specific decoders live in [`cpu`](super::cpu).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CpuidResult {
    /// `eax` output. Usually the "max leaf" or a count.
    pub eax: u32,
    /// `ebx` output. Often a vendor string fragment or a feature bitmask.
    pub ebx: u32,
    /// `ecx` output. Often a feature bitmask or a subleaf selector.
    pub ecx: u32,
    /// `edx` output. Often a feature bitmask.
    pub edx: u32,
}

/// Execute a `cpuid` query with a subleaf of zero.
///
/// Most CPUID leaves do not use the subleaf (`ecx` input); this convenience
/// covers them. Leaves that do use a subleaf (e.g. leaf 4, 7, 0xB, 0xD)
/// should call [`cpuid_subleaf`].
///
/// # Safety
///
/// `cpuid` is non-privileged, but it is marked `unsafe` here only to keep the
/// surface uniform with the rest of this module. In practice it is safe to
/// call from any context; the `unsafe` is a documentation artefact and can be
/// wrapped by a safe caller.
#[inline]
#[must_use]
pub unsafe fn cpuid(leaf: u32) -> CpuidResult {
    unsafe { cpuid_subleaf(leaf, 0) }
}

/// Execute a `cpuid` query with an explicit subleaf in `ecx`.
///
/// # Safety
///
/// `cpuid` is non-privileged; see [`cpuid`]. Marked unsafe for surface
/// uniformity only.
#[inline]
#[must_use]
pub unsafe fn cpuid_subleaf(leaf: u32, subleaf: u32) -> CpuidResult {
    // SAFETY: CPUID is part of the x86_64 baseline. The architecture
    // intrinsic preserves RBX correctly under LLVM's PIC register rules.
    let result = core::arch::x86_64::__cpuid_count(leaf, subleaf);
    CpuidResult {
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}

// ---------------------------------------------------------------------------
// Random number instructions
// ---------------------------------------------------------------------------

/// The outcome of a hardware random-number read.
///
/// `rdrand` / `rdseed` set CF=1 on success and CF=0 on failure. A failure is
/// not an error in the usual sense — it means the on-die entropy pool was
/// temporarily empty (for `rdrand`) or the entropy source was not yet ready
/// (for `rdseed`). Callers should retry a bounded number of times.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RandResult<T> {
    /// A value was successfully read.
    Ok(T),
    /// The instruction returned CF=0; no value is available this call.
    Retry,
}

/// Read a hardware random `u16` via `rdrand`.
///
/// `rdrand` draws from the on-die CSPRNG, which is seeded by a NIST
/// SP800-90A-approved DRBG. It is suitable for direct use as a random value.
/// See [`rdseed_u16`] for the raw entropy source.
///
/// # Safety
///
/// `rdrand` is non-privileged and safe to execute from any context. Marked
/// unsafe only for surface uniformity with the rest of this module; a safe
/// wrapper is provided by the [`cpu`](super::cpu) module's feature probe.
#[inline]
#[must_use]
pub unsafe fn rdrand_u16() -> RandResult<u16> {
    let value: u16;
    let ok: u8;
    // SAFETY: `rdrand ax` sets CF on success and clears it on failure. We
    // capture CF via `setb` (set if below), which reads CF and writes 0/1 to
    // the destination. `rdrand` modifies no memory or stack and does not
    // touch EFLAGS beyond CF (which `setb` then consumes).
    unsafe {
        asm!(
            "rdrand {val:x}",
            "setc {ok}",
            val = out(reg) value,
            ok = out(reg_byte) ok,
            options(nostack),
        );
    }
    if ok != 0 {
        RandResult::Ok(value)
    } else {
        RandResult::Retry
    }
}

/// Read a hardware random `u32` via `rdrand`. See [`rdrand_u16`].
///
/// # Safety
///
/// See [`rdrand_u16`].
#[inline]
#[must_use]
pub unsafe fn rdrand_u32() -> RandResult<u32> {
    let value: u32;
    let ok: u8;
    unsafe {
        asm!(
            "rdrand {val:e}",
            "setc {ok}",
            val = out(reg) value,
            ok = out(reg_byte) ok,
            options(nostack),
        );
    }
    if ok != 0 {
        RandResult::Ok(value)
    } else {
        RandResult::Retry
    }
}

/// Read a hardware random `u64` via `rdrand`.
///
/// This is the primary entropy entry point used by the kernel's random
/// pool. See [`rdrand_u16`] for the width-specific variants and the safety
/// discussion.
///
/// # Safety
///
/// See [`rdrand_u16`].
#[inline]
#[must_use]
pub unsafe fn rdrand() -> RandResult<u64> {
    let value: u64;
    let ok: u8;
    unsafe {
        asm!(
            "rdrand {val}",
            "setc {ok}",
            val = out(reg) value,
            ok = out(reg_byte) ok,
            options(nostack),
        );
    }
    if ok != 0 {
        RandResult::Ok(value)
    } else {
        RandResult::Retry
    }
}

/// Read a raw entropy `u16` via `rdseed`.
///
/// `rdseed` returns raw entropy bits from the on-die entropy source, unlike
/// `rdrand` which returns output from a DRBG seeded by that source. It is
/// intended for seeding a userspace CSPRNG. It fails (CF=0) more often than
/// `rdrand` because the entropy source is slower to refill.
///
/// # Safety
///
/// `rdseed` is non-privileged and safe to execute from any context.
#[inline]
#[must_use]
pub unsafe fn rdseed_u16() -> RandResult<u16> {
    let value: u16;
    let ok: u8;
    unsafe {
        asm!(
            "rdseed {val:x}",
            "setc {ok}",
            val = out(reg) value,
            ok = out(reg_byte) ok,
            options(nostack),
        );
    }
    if ok != 0 {
        RandResult::Ok(value)
    } else {
        RandResult::Retry
    }
}

/// Read a raw entropy `u32` via `rdseed`. See [`rdseed_u16`].
///
/// # Safety
///
/// See [`rdseed_u16`].
#[inline]
#[must_use]
pub unsafe fn rdseed_u32() -> RandResult<u32> {
    let value: u32;
    let ok: u8;
    unsafe {
        asm!(
            "rdseed {val:e}",
            "setc {ok}",
            val = out(reg) value,
            ok = out(reg_byte) ok,
            options(nostack),
        );
    }
    if ok != 0 {
        RandResult::Ok(value)
    } else {
        RandResult::Retry
    }
}

/// Read a raw entropy `u64` via `rdseed`.
///
/// This is the primary raw-entropy entry point used to seed the kernel's
/// CSPRNG. See [`rdseed_u16`] for the width-specific variants and the safety
/// discussion.
///
/// # Safety
///
/// See [`rdseed_u16`].
#[inline]
#[must_use]
pub unsafe fn rdseed() -> RandResult<u64> {
    let value: u64;
    let ok: u8;
    unsafe {
        asm!(
            "rdseed {val}",
            "setc {ok}",
            val = out(reg) value,
            ok = out(reg_byte) ok,
            options(nostack),
        );
    }
    if ok != 0 {
        RandResult::Ok(value)
    } else {
        RandResult::Retry
    }
}
