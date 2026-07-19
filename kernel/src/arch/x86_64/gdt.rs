//! Global Descriptor Table for the x86_64 long-mode kernel.
//!
//! Although long mode does not use segmentation for address translation
//! (flat paging covers that), the CPU still requires a valid GDT:
//!
//! * every `iretq` between rings, every `syscall`/`sysret`, and every
//!   context switch reloads segment selectors from the GDT;
//! * the per-CPU Task State Segment (TSS) is installed as a 16-byte
//!   system descriptor here, and `ltr` must point at it so the CPU knows
//!   where to find the IST stacks and the privilege-0 stack (`RSP0`);
//! * user/kernel privilege transitions need distinct code and data
//!   selectors with the right DPL so the MMU honours ring separation.
//!
//! # Layout
//!
//! The Xenith GDT is laid out as:
//!
//! | Index | Selector | Entry                | Purpose                      |
//! |-------|----------|----------------------|------------------------------|
//! | 0     | 0x00     | null                 | required first entry         |
//! | 1     | 0x08     | kernel code (64-bit) | ring-0 L=1 code              |
//! | 2     | 0x10     | kernel data          | ring-0 data                  |
//! | 3     | 0x18     | user code32          | ring-3 compat code (L=0,D=1) |
//! | 4     | 0x20     | user data32          | ring-3 compat data           |
//! | 5     | 0x28     | user code64          | ring-3 long-mode code (L=1)  |
//! | 6     | 0x30     | user data64          | ring-3 data                  |
//! | 7     | 0x38     | TSS (16-byte)        | 64-bit Task State Segment    |
//!
//! The 32-bit user code/data descriptors are only used when running a
//! 32-bit compatibility-mode userspace process under a 64-bit kernel.
//! They cost two entries and no runtime, so we always install them.
//!
//! # Per-CPU status
//!
//! This module currently owns a single, statically-allocated TSS for the
//! BSP. When the SMP phase lands, each AP will get its own TSS via the
//! `PerCpu` area and a GDT slot pointing at it; the `bsp_tss` static and
//! `BSP_GDT.tss` reference will move into `PerCpu::tss`. The public
//! surface (`load`, `load_tss`, `set_rsp0`) is written so that swap is
//! mechanical.

use core::mem;
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Access-byte and flag bit constants
// ---------------------------------------------------------------------------

/// Access byte: present bit. Set on every usable descriptor.
const ACCESS_PRESENT: u8 = 1 << 7;

/// Access byte: descriptor type (S). 1 = code/data, 0 = system (TSS, LDT).
const ACCESS_CODE_OR_DATA: u8 = 1 << 4;

/// Access byte: executable. 1 = code segment, 0 = data segment.
const ACCESS_EXECUTABLE: u8 = 1 << 3;

/// Access byte: for code segments, readable (1). A code segment that is not
/// readable cannot be read as data; we always want code readable so the
/// kernel can inspect its own .text if needed.
const ACCESS_READABLE: u8 = 1 << 1;

/// Access byte: for data segments, writable (1).
const ACCESS_WRITABLE: u8 = 1 << 1;

/// Access byte: accessed bit. The CPU sets this when the segment is used;
/// we pre-set it to 1 so the descriptor does not change after install (a
/// mutating GDT entry can surprise the scheduler's copy-on-write logic).
const ACCESSED: u8 = 1 << 0;

/// DPL mask position in the access byte: privilege level lives in bits 5-6.
const ACCESS_DPL_SHIFT: u8 = 5;

/// Ring 0 privilege level for the access-byte DPL field.
const DPL_RING0: u8 = 0 << ACCESS_DPL_SHIFT;

/// Ring 3 privilege level for the access-byte DPL field.
const DPL_RING3: u8 = 3 << ACCESS_DPL_SHIFT;

/// Flag nibble (high 4 bits of byte 6): granularity. 1 = limit is in 4 KiB
/// pages; 0 = limit is in bytes. We use 4 KiB granularity with a full
/// 0xFFFFF limit so every segment spans the whole virtual space.
const FLAG_GRANULARITY_4K: u8 = 1 << 7;

/// Flag nibble: size bit (D/B). For 32-bit code/data this is 1; for 64-bit
/// code it must be 0 (the L bit takes over).
const FLAG_SIZE_32: u8 = 1 << 6;

/// Flag nibble: long-mode bit (L). Set on 64-bit code segments; cleared on
/// 32-bit and data segments. When L=1 the D bit must be 0.
const FLAG_LONG: u8 = 1 << 5;

// ---------------------------------------------------------------------------
// System-descriptor (TSS) access bits
// ---------------------------------------------------------------------------

/// TSS access byte: the CPU requires S=0 for system descriptors, so we do
/// not OR in `ACCESS_CODE_OR_DATA`. The 0b1001 type means "available 64-bit
/// TSS". `0b1011` would be "busy 64-bit TSS"; the CPU sets busy on `ltr`.
const TSS_AVAILABLE_64: u8 = 0b1001;

// ---------------------------------------------------------------------------
// Segment selectors
// ---------------------------------------------------------------------------

/// Requested privilege level (RPL) lives in the low two bits of a selector.
/// The ring-0 selectors below have RPL=0 and the ring-3 selectors have
/// RPL=3; each is `(index << 3) | rpl`.
const RPL_RING0: u16 = 0;

/// Ring-3 RPL. Used for user-space segment selectors and for `iretq` to
/// user mode.
const RPL_RING3: u16 = 3;

/// Selector indices. Each is the byte-offset into the GDT divided by 8,
/// i.e. the hardware "index" field of a segment selector. Index 0 is the
/// null descriptor (selector 0x00) and is never named explicitly.
const INDEX_KCODE: u16 = 1;
const INDEX_KDATA: u16 = 2;
const INDEX_UCODE32: u16 = 3;
const INDEX_UDATA32: u16 = 4;
const INDEX_UCODE64: u16 = 5;
const INDEX_UDATA64: u16 = 6;
const INDEX_TSS: u16 = 7;

/// Build a segment selector from an index and RPL.
const fn selector(index: u16, rpl: u16) -> u16 {
    (index << 3) | rpl
}

/// Kernel code selector: index 1, RPL 0 -> `0x08`.
pub const KERNEL_CODE_SELECTOR: u16 = selector(INDEX_KCODE, RPL_RING0);

/// Kernel data selector: index 2, RPL 0 -> `0x10`.
pub const KERNEL_DATA_SELECTOR: u16 = selector(INDEX_KDATA, RPL_RING0);

/// User 32-bit code selector: index 3, RPL 3 -> `0x1B`.
pub const USER_CODE32_SELECTOR: u16 = selector(INDEX_UCODE32, RPL_RING3);

/// User 32-bit data selector: index 4, RPL 3 -> `0x23`.
pub const USER_DATA32_SELECTOR: u16 = selector(INDEX_UDATA32, RPL_RING3);

/// User 64-bit code selector: index 5, RPL 3 -> `0x2B`.
pub const USER_CODE64_SELECTOR: u16 = selector(INDEX_UCODE64, RPL_RING3);

/// User 64-bit data selector: index 6, RPL 3 -> `0x33`.
pub const USER_DATA64_SELECTOR: u16 = selector(INDEX_UDATA64, RPL_RING3);

/// TSS selector: index 7, RPL 0 -> `0x38`. A system descriptor.
pub const TSS_SELECTOR: u16 = selector(INDEX_TSS, RPL_RING0);

/// The canonical user data selector used for `DS/ES/SS` when entering ring 3.
/// In long mode all user data segments are flat and interchangeable, but the
/// ABI contract is that `SS == DS == USER_DATA64_SELECTOR` for 64-bit user
/// processes and `USER_DATA32_SELECTOR` for 32-bit ones.
pub const USER_DATA_SELECTOR: u16 = USER_DATA64_SELECTOR;

/// The canonical user code selector for 64-bit user processes.
pub const USER_CODE_SELECTOR: u16 = USER_CODE64_SELECTOR;

// ---------------------------------------------------------------------------
// SegmentDescriptor (8-byte code/data entry)
// ---------------------------------------------------------------------------

/// An 8-byte code or data segment descriptor.
///
/// This is the classic protected-mode / long-mode non-system descriptor
/// format. In long mode the base and limit are ignored for code/data
/// segments (the segments are "flat"), but the access byte and the L/D
/// flag bits still matter: they select 32-bit vs 64-bit execution and
/// kernel vs user privilege.
///
/// Bit layout (little-endian bytes):
/// ```text
///   0  1  2  3  4  5  6  7
///  LL LL BB BB BB AA FLA BB
/// ```
/// where `LL` = limit low, `BB` = base bytes, `AA` = access byte,
/// `FLA` = flags nibble + limit high nibble.
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct SegmentDescriptor {
    /// Limit bits 0..15.
    limit_low: u16,
    /// Base bits 0..15.
    base_low: u16,
    /// Base bits 16..23.
    base_middle: u8,
    /// Access byte (present, DPL, type, etc.).
    access: u8,
    /// High nibble = flags (G, D/B, L, reserved); low nibble = limit 16..19.
    flags_and_limit_high: u8,
    /// Base bits 24..31.
    base_high: u8,
}

impl SegmentDescriptor {
    /// The null descriptor. Required as GDT entry 0; a selector with index 0
    /// is how "no segment" is represented and the CPU faults if you try to
    /// load it into CS/SS/DS/ES/FS/GS.
    pub const NULL: Self = Self {
        limit_low: 0,
        base_low: 0,
        base_middle: 0,
        access: 0,
        flags_and_limit_high: 0,
        base_high: 0,
    };

    /// Build a flat code or data segment descriptor.
    ///
    /// In long mode the base/limit are irrelevant for code/data (flat
    /// segments), so we hardcode base=0 and limit=0xFFFFF with 4 KiB
    /// granularity to span the whole 4 GiB (32-bit) or full 64-bit space.
    /// Only the access byte and the flags nibble vary.
    const fn new(access: u8, flags: u8) -> Self {
        Self {
            // Limit low 16 bits = 0xFFFF.
            limit_low: 0xFFFF,
            // Base is zero for flat segments.
            base_low: 0,
            base_middle: 0,
            access,
            // Flags nibble in the high 4 bits; limit bits 16..19 = 0xF.
            flags_and_limit_high: flags | 0x0F,
            base_high: 0,
        }
    }

    /// Kernel code segment: ring 0, 64-bit (L=1, D=0), non-conforming,
    /// readable. The CPU uses this selector for `CS` whenever it runs
    /// kernel code, including every `iretq` back to ring 0.
    pub const KERNEL_CODE: Self = Self::new(
        ACCESS_PRESENT
            | DPL_RING0
            | ACCESS_CODE_OR_DATA
            | ACCESS_EXECUTABLE
            | ACCESS_READABLE
            | ACCESSED,
        FLAG_GRANULARITY_4K | FLAG_LONG,
    );

    /// Kernel data segment: ring 0, writable, flat. Used for `SS`, `DS`,
    /// `ES`, `FS`, `GS` in kernel mode. In long mode `SS` is special-cased
    /// (it must always be a writable data segment or null), so this
    /// descriptor must exist.
    pub const KERNEL_DATA: Self = Self::new(
        ACCESS_PRESENT | DPL_RING0 | ACCESS_CODE_OR_DATA | ACCESS_WRITABLE | ACCESSED,
        FLAG_GRANULARITY_4K | FLAG_SIZE_32,
    );

    /// User 32-bit code segment: ring 3, compatibility mode (L=0, D=1),
    /// non-conforming, readable. Selected when a 32-bit user process is
    /// running under the 64-bit kernel via `iretq` with the 32-bit CS.
    pub const USER_CODE32: Self = Self::new(
        ACCESS_PRESENT
            | DPL_RING3
            | ACCESS_CODE_OR_DATA
            | ACCESS_EXECUTABLE
            | ACCESS_READABLE
            | ACCESSED,
        FLAG_GRANULARITY_4K | FLAG_SIZE_32,
    );

    /// User 32-bit data segment: ring 3, writable, flat. Paired with
    /// [`SegmentDescriptor::USER_CODE32`] for 32-bit user processes.
    pub const USER_DATA32: Self = Self::new(
        ACCESS_PRESENT | DPL_RING3 | ACCESS_CODE_OR_DATA | ACCESS_WRITABLE | ACCESSED,
        FLAG_GRANULARITY_4K | FLAG_SIZE_32,
    );

    /// User 64-bit code segment: ring 3, long mode (L=1, D=0),
    /// non-conforming, readable. This is the `CS` selector loaded by
    /// `iretq` / `sysretq` when entering a 64-bit user process.
    pub const USER_CODE64: Self = Self::new(
        ACCESS_PRESENT
            | DPL_RING3
            | ACCESS_CODE_OR_DATA
            | ACCESS_EXECUTABLE
            | ACCESS_READABLE
            | ACCESSED,
        FLAG_GRANULARITY_4K | FLAG_LONG,
    );

    /// User 64-bit data segment: ring 3, writable, flat. Used for `SS`,
    /// `DS`, `ES` of a 64-bit user process. Long mode requires that the
    /// `SS` selector on `iretq` to ring 3 be a writable data segment with
    /// DPL=3; this is that descriptor.
    pub const USER_DATA64: Self = Self::new(
        ACCESS_PRESENT | DPL_RING3 | ACCESS_CODE_OR_DATA | ACCESS_WRITABLE | ACCESSED,
        FLAG_GRANULARITY_4K | FLAG_SIZE_32,
    );

    /// Whether this descriptor is the null descriptor (all bytes zero).
    /// Useful for sanity-checking the table layout.
    pub const fn is_null(&self) -> bool {
        self.limit_low == 0
            && self.base_low == 0
            && self.base_middle == 0
            && self.access == 0
            && self.flags_and_limit_high == 0
            && self.base_high == 0
    }
}

// ---------------------------------------------------------------------------
// TssDescriptor (16-byte system descriptor)
// ---------------------------------------------------------------------------

/// A 16-byte system descriptor for a 64-bit Task State Segment.
///
/// In long mode every system descriptor (TSS, LDT, call/interrupt/trap
/// gates) is 16 bytes so it can carry a 64-bit base address. The format:
///
/// ```text
///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
///  LL LL BB BB BB AA FLA BB BB BB BB BB BB 00 00 00
/// ```
/// where `LL` = limit low, `BB` = base bytes (low 4 in bytes 2-4-7, high 4
/// in bytes 8-11), `AA` = access byte, `FLA` = flags + limit high.
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct TssDescriptor {
    /// Limit bits 0..15. For a 104-byte TSS this is 103 (0x67).
    limit_low: u16,
    /// Base bits 0..15.
    base_low: u16,
    /// Base bits 16..23.
    base_middle: u8,
    /// Access byte: present | DPL | S=0 | type=0b1001 (available 64-bit TSS).
    access: u8,
    /// Flags nibble (G) + limit bits 16..19.
    flags_and_limit_high: u8,
    /// Base bits 24..31.
    base_high: u8,
    /// Base bits 32..63 (the upper half of the 64-bit base address).
    base_upper: u32,
    /// Reserved, must be zero.
    _reserved: u32,
}

impl TssDescriptor {
    /// Build a TSS descriptor from a raw 64-bit base address and a 20-bit
    /// limit. `limit` is the byte size minus one; the CPU expects the
    /// limit field to be `sizeof(TSS) - 1`.
    const fn new(base: u64, limit: u32, dpl: u8) -> Self {
        // The limit field is 20 bits; we only ever pass a small value
        // (0x67 for a 104-byte TSS), so truncation is harmless. The flags
        // nibble is left zero (byte granularity, since the limit fits).
        let limit_low = (limit & 0xFFFF) as u16;
        let limit_high = ((limit >> 16) & 0x0F) as u8;

        Self {
            limit_low,
            base_low: (base & 0xFFFF) as u16,
            base_middle: ((base >> 16) & 0xFF) as u8,
            access: ACCESS_PRESENT | dpl | TSS_AVAILABLE_64,
            flags_and_limit_high: limit_high,
            base_high: ((base >> 24) & 0xFF) as u8,
            base_upper: ((base >> 32) & 0xFFFF_FFFF) as u32,
            _reserved: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Task State Segment
// ---------------------------------------------------------------------------

/// The 64-bit Task State Segment.
///
/// The TSS holds the stacks the CPU loads on privilege-level changes and on
/// interrupts that select an Interrupt Stack Table (IST) entry. Xenith uses:
///
/// * `RSP0` — the kernel stack loaded whenever the CPU transitions from
///   ring 3 to ring 0 (syscall, interrupt, exception). Updated by the
///   scheduler on every context switch so the next task's kernel stack is
///   in place.
/// * `IST[7]` — a dedicated non-reentrant stack for critical faults
///   (`#DF` double fault, and as a spare for `#MC` / NMI). Using IST[7]
///   means a stack overflow in a normal interrupt handler can still take
///   the fault without recursing on the exhausted stack.
///
/// All other RSP/IST slots are left zero: the CPU treats a zero IST entry
/// as "no stack switch", which is what we want for everything except the
/// critical-fault path.
///
/// The structure is exactly 104 bytes per the AMD64 manual. We mark it
/// `#[repr(C, packed)]` so the field offsets match the hardware layout
/// exactly and there is no inter-field padding.
#[repr(C, packed)]
pub struct TaskStateSegment {
    /// Reserved, must be zero.
    _reserved0: u32,
    /// Stack pointer loaded on a transition to CPL 0 (ring-3 -> ring-0).
    /// The scheduler updates this on every context switch.
    pub rsp0: u64,
    /// Stack pointer loaded on a transition to CPL 1. Unused (Xenith has
    /// no ring-1 code), kept zero so no stack switch happens.
    pub rsp1: u64,
    /// Stack pointer loaded on a transition to CPL 2. Unused, kept zero.
    pub rsp2: u64,
    /// Reserved, must be zero.
    _reserved1: u64,
    /// Interrupt Stack Table entries 1..7. IST[i] is loaded when an
    /// interrupt gate has its IST field set to `i`. IST[7] is used for the
    /// double-fault handler; the rest are zero.
    pub ist: [u64; 7],
    /// Reserved, must be zero.
    _reserved2: u64,
    /// Offset into this TSS of the I/O permission bitmap. 0 means "no
    /// bitmap", which disables user-space `in`/`out` access (the kernel
    /// gates all port I/O itself).
    pub iomap_base: u16,
    /// Explicit padding to bring the struct to the architectural 104 bytes.
    /// The AMD64 TSS is exactly 0x68 bytes; without this tail the packed
    /// struct would be 102 bytes and the `limit` field in the descriptor
    /// (set to `sizeof(TSS) - 1`) would undercount by one.
    _padding: [u8; 2],
}

impl TaskStateSegment {
    /// Construct a zeroed TSS. All RSP and IST entries are 0, which tells
    /// the CPU "no stack switch" for every transition until the scheduler
    /// installs a kernel stack in `rsp0`.
    pub const fn new() -> Self {
        Self {
            _reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            _reserved1: 0,
            ist: [0; 7],
            _reserved2: 0,
            iomap_base: 0,
            _padding: [0; 2],
        }
    }

    /// Set the privilege-0 stack pointer (`RSP0`).
    ///
    /// Called by the scheduler on every context switch. The address must
    /// be a valid kernel-virtual stack top and must be 8-byte aligned
    /// (the SysV ABI requires 16-byte alignment at a call boundary, so in
    /// practice the caller aligns the stack pointer to 16 before storing).
    ///
    /// # Safety contract (caller)
    ///
    /// `stack_top` must point to a writable, mapped kernel stack or be 0
    /// to disable the CPL-0 stack switch. Storing a bad pointer here will
    /// cause the CPU to jump to a garbage `RSP` on the next ring-3 ->
    /// ring-0 transition, which is unrecoverable.
    pub fn set_rsp0(&mut self, stack_top: u64) {
        // The TSS is `#[repr(C, packed)]`; assigning to `self.rsp0` directly
        // is permitted (the compiler emits the appropriate store), but we
        // use `write_unaligned` for symmetry with [`set_ist`] and to be
        // robust against future packing changes. In practice `rsp0` lands
        // at offset 4 and the TSS is naturally aligned, so the store is
        // aligned — but `write_unaligned` handles either case.
        //
        // SAFETY: `self.rsp0` is within the `&mut self` borrow; the write
        // does not alias any other access.
        unsafe {
            core::ptr::write_unaligned(addr_of_mut!(self.rsp0), stack_top);
        }
    }

    /// Set an Interrupt Stack Table entry (1-indexed: `index` in 1..=7).
    ///
    /// `IST[7]` is reserved for the double-fault / NMI stack and is set
    /// once during boot; the other entries are left to the IDT phase.
    ///
    /// # Panics
    ///
    /// Panics if `index` is 0 or > 7, since those do not correspond to a
    /// hardware IST slot.
    pub fn set_ist(&mut self, index: u8, stack_top: u64) {
        assert!(
            (1..=7).contains(&index),
            "IST index must be 1..=7, got {index}"
        );
        // The TSS is `#[repr(C, packed)]`, so indexing `self.ist[i]` would
        // form a reference to a packed field (UB under the 2024 edition).
        // Write through a raw pointer instead: `addr_of_mut!` gives us the
        // field address without going through a reference, and `write` is
        // safe here because the TSS is naturally aligned in practice (the
        // leading u32 puts `ist` at offset 36, so each 8-byte slot is
        // 8-byte aligned) — but we use `write_unaligned` to be robust
        // against any future packing change.
        //
        // SAFETY: `index` is in 1..=7 (checked above), so `(index - 1)` is
        // in 0..=6, a valid index into the 7-element `ist` array. The
        // pointer is within the `&mut self` borrow, so the write does not
        // alias any other access.
        unsafe {
            let slot = addr_of_mut!(self.ist[(index - 1) as usize]);
            core::ptr::write_unaligned(slot, stack_top);
        }
    }
}

impl Default for TaskStateSegment {
    fn default() -> Self {
        Self::new()
    }
}

/// Assert the TSS is exactly 104 bytes at compile time. The CPU's limit
/// field is set to `sizeof(TSS) - 1`, so a size mismatch would silently
/// hand the CPU the wrong limit.
const _: () = assert!(mem::size_of::<TaskStateSegment>() == 104);

// ---------------------------------------------------------------------------
// GDT
// ---------------------------------------------------------------------------

/// The Global Descriptor Table.
///
/// Contains seven 8-byte code/data descriptors plus one 16-byte TSS
/// descriptor, for a total of `7 * 8 + 16 = 72` bytes. The table is laid
/// out so that the selectors in [`KERNEL_CODE_SELECTOR`] etc. index into
/// it directly.
///
/// The TSS is held out-of-line (in a separate static) and referenced by
/// address from the TSS descriptor. This keeps the TSS mutable without
/// having to make the entire GDT `static mut`, and it matches how the
/// SMP phase will allocate one TSS per CPU from the `PerCpu` area.
#[repr(C, packed)]
pub struct GlobalDescriptorTable {
    null: SegmentDescriptor,
    kernel_code: SegmentDescriptor,
    kernel_data: SegmentDescriptor,
    user_code32: SegmentDescriptor,
    user_data32: SegmentDescriptor,
    user_code64: SegmentDescriptor,
    user_data64: SegmentDescriptor,
    tss: TssDescriptor,
}

impl GlobalDescriptorTable {
    /// Build a GDT whose TSS descriptor points at the given linear address.
    ///
    /// `tss_base` is the 64-bit virtual address of the [`TaskStateSegment`].
    /// We take a `u64` rather than a `*const TaskStateSegment` so this can
    /// run in a `const` initialiser: const evaluation cannot cast a raw
    /// pointer to an integer ("pointers do not have an integer value at
    /// compile time"), so the caller patches the base at runtime via
    /// [`Self::set_tss_base`] when the TSS address is known.
    pub(crate) const fn new(tss_base: u64) -> Self {
        // Limit is sizeof(TSS) - 1 = 103. The CPU reads `limit + 1` bytes.
        let limit = (mem::size_of::<TaskStateSegment>() - 1) as u32;
        Self {
            null: SegmentDescriptor::NULL,
            kernel_code: SegmentDescriptor::KERNEL_CODE,
            kernel_data: SegmentDescriptor::KERNEL_DATA,
            user_code32: SegmentDescriptor::USER_CODE32,
            user_data32: SegmentDescriptor::USER_DATA32,
            user_code64: SegmentDescriptor::USER_CODE64,
            user_data64: SegmentDescriptor::USER_DATA64,
            tss: TssDescriptor::new(tss_base, limit, DPL_RING0),
        }
    }

    /// Patch the TSS descriptor's base address.
    ///
    /// Called once during bring-up, after the TSS static's address is known,
    /// to fill in the value that [`Self::new`] had to leave as zero (because
    /// const evaluation cannot turn a pointer into an integer). After this
    /// call the TSS descriptor points at `tss_base` and the table is ready
    /// to [`load`].
    ///
    /// # Safety
    ///
    /// `tss_base` must be the linear address of a valid, 104-byte,
    /// naturally-aligned [`TaskStateSegment`] that outlives the CPU's use
    /// of this GDT. The caller must ensure no other CPU is using this GDT
    /// when the patch happens (true during single-threaded boot).
    pub unsafe fn set_tss_base(&mut self, tss_base: u64) {
        // Rebuild the TSS descriptor with the real base. The limit and DPL
        // are unchanged. We update in place so the rest of the GDT is not
        // disturbed.
        let limit = (mem::size_of::<TaskStateSegment>() - 1) as u32;
        self.tss = TssDescriptor::new(tss_base, limit, DPL_RING0);
    }

    /// Load this GDT into the CPU's GDTR and refresh the segment registers.
    ///
    /// After `lgdt` the CPU keeps using the old segment selectors until
    /// they are reloaded. We reload `CS` via a far return to
    /// [`KERNEL_CODE_SELECTOR`] (the only way to load `CS` in long mode is
    /// a far jump or far return), then load `SS`, `DS`, `ES`, `FS`, `GS`
    /// with [`KERNEL_DATA_SELECTOR`]. `FS`/`GS` base are managed
    /// separately via MSRs (per-CPU / thread-local), so their selectors
    /// are just set to a flat data segment here.
    ///
    /// # Safety
    ///
    /// The caller must guarantee `self` is valid for the lifetime of the
    /// CPU's use of the table — in practice that means `self` lives in a
    /// `static`. Loading a GDT whose storage has been dropped is
    /// undefined behaviour: any later segment reload dereferences the
    /// stored base. The selectors used here must match this table's
    /// layout (they do, by construction).
    pub unsafe fn load(&self) {
        // Build the 10-byte GDTR pseudo-descriptor and hand it to the
        // shared `lgdt` wrapper in `instructions`. limit is one less than
        // the table size in bytes; base is the linear address of `self`.
        let pointer = super::instructions::DescriptorTablePointer {
            limit: (mem::size_of::<Self>() - 1) as u16,
            base: addr_of!(*self) as u64,
        };

        // SAFETY: `pointer` is fully initialised and describes this GDT
        // exactly: limit = sizeof(Self)-1, base = &self. The caller
        // guarantees `self` outlives the CPU's use of the table (it lives
        // in a `static`). `lgdt` only records base/limit into the hidden
        // GDTR; it does not touch EFLAGS.
        unsafe {
            super::instructions::lgdt(&pointer);
        }

        // Reload the data segments. `SS` must be a writable data segment
        // in long mode; the rest can be a flat data segment or null. We
        // use KERNEL_DATA_SELECTOR for all of them for uniformity.
        load_data_segments(KERNEL_DATA_SELECTOR);

        // Reload `CS` by far-returning to the kernel code selector. The
        // sequence pushes the selector and a return address, then `retf`
        // pops them into CS:RIP. We use a label-relative `lea` to get the
        // return address so the far return resumes right after the
        // instruction.
        //
        // SAFETY: We push `KERNEL_CODE_SELECTOR` (matches this GDT's
        // entry 1) and the address of the `2:` label onto the stack, then
        // `retf`. The CPU loads CS from the stack and jumps to the return
        // address, which is the very next instruction. This is the
        // canonical way to reload CS in long mode. The stack must have 16
        // bytes of scratch space, which it does (we are in kernel code
        // with a valid kernel stack).
        unsafe {
            core::arch::asm!(
                "push {sel}",
                "lea {tmp}, [rip + 2f]",
                "push {tmp}",
                // LLVM's bare `retf` encodes the legacy 32-bit form (CB),
                // which truncates the canonical return RIP in 64-bit mode.
                // REX.W + CB is the architectural 64-bit far return.
                ".byte 0x48, 0xcb",
                "2:",
                sel = in(reg) KERNEL_CODE_SELECTOR as u64,
                tmp = out(reg) _,
                options(preserves_flags),
            );
        }
    }
}

/// Load `selector` into `SS`, `DS`, `ES`, `FS`, `GS`.
///
/// In long mode loading a data segment selector only updates the hidden
/// part of the register (the visible part is ignored). `FS` and `GS` base
/// are set separately via MSRs, so their selectors just need to be a
/// writable data segment (or null).
///
/// # Safety
///
/// `selector` must index a present, writable data descriptor in the
/// currently loaded GDT with DPL >= current CPL. The kernel data
/// selector satisfies this for ring 0.
unsafe fn load_data_segments(selector: u16) {
    // SAFETY: `mov` into a segment register with an in-range selector does
    // not access memory (beyond the descriptor table read, which is the
    // whole point) and does not touch the stack. We rely on the caller's
    // invariant that `selector` is valid in the loaded GDT. The `:x`
    // template modifier forces the 16-bit register form (`ax`) so the
    // assembler encodes `mov ss, ax` rather than warning about a
    // sub-register operand.
    unsafe {
        core::arch::asm!(
            "mov ss, {sel:x}",
            "mov ds, {sel:x}",
            "mov es, {sel:x}",
            "mov fs, {sel:x}",
            "mov gs, {sel:x}",
            sel = in(reg) selector,
            options(nostack, nomem, preserves_flags),
        );
    }
}

/// Load the Task Register with `selector` via `ltr`.
///
/// `ltr` marks the TSS descriptor "busy" (the CPU sets the type field to
/// 0b1011) and records the selector in the visible part of TR. After
/// `ltr`, the CPU will load `RSP0` / the selected IST entry on
/// privilege-level changes and IST-armed interrupts.
///
/// This is a thin wrapper around [`super::instructions::ltr`] that exists
/// so the GDT module owns the TSS-loading entry point the rest of `arch`
/// calls during bring-up. The actual `ltr` instruction (and its safety
/// contract) lives in `instructions`; see that file for the asm.
///
/// # Safety
///
/// `selector` must index a present, available 64-bit TSS descriptor in
/// the loaded GDT. Calling `ltr` twice with a different selector on the
/// same CPU faults; this is intended to be called exactly once per CPU
/// during bring-up.
#[inline]
pub unsafe fn load_tss(selector: u16) {
    // Delegate to the shared instruction wrapper. The safety contract is
    // identical and is documented on `instructions::ltr`.
    unsafe {
        super::instructions::ltr(selector);
    }
}

// ---------------------------------------------------------------------------
// BSP statics
// ---------------------------------------------------------------------------

/// The BSP's Task State Segment.
///
/// Statically allocated so the GDT can reference its address at
/// const-evaluation time. The scheduler overwrites `rsp0` on every
/// context switch and the IDT phase sets `ist[6]` (IST7) for the
/// double-fault stack.
///
/// This is `static mut` because the scheduler mutates `rsp0` on every
/// context switch. Access is mediated by [`bsp_tss`] which hands out a
/// `&mut` guarded by the fact that only the BSP touches its own TSS and
/// only after `load_tss` has run.
// Future: when the SMP phase lands, this moves into `PerCpu::tss` and
// each AP gets its own TSS allocated from the per-CPU area. The `BSP_GDT`
// below will be replaced by a per-CPU GDT whose TSS descriptor points at
// that CPU's TSS. Until then this static is the single source of truth.
static mut BSP_TSS: TaskStateSegment = TaskStateSegment::new();

/// The BSP's Global Descriptor Table.
///
/// Constructed at compile time with a placeholder TSS base of zero; the
/// real TSS address is patched in by [`init_bsp`] via
/// [`GlobalDescriptorTable::set_tss_base`] before the table is loaded. This
/// two-step init is required because const evaluation cannot cast a pointer
/// to a `static` into an integer, so the TSS descriptor's base field cannot
/// be filled until runtime.
///
/// This is `static mut` because [`GlobalDescriptorTable::set_tss_base`]
/// mutates it during bring-up. After [`init_bsp`] returns the table is
/// never written again — only the out-of-line [`BSP_TSS`] is mutated by
/// the scheduler — so the `&self` handed to [`GlobalDescriptorTable::load`]
/// is sound for the rest of the boot.
// SAFETY of the static: the GDT contains only descriptor constants. The
// TSS descriptor base is patched once during single-threaded boot before
// any CPU uses the table, so there is no concurrent access. We never form
// a Rust reference to `BSP_TSS` through the GDT — the descriptor stores a
// raw address that the CPU reads — so the `&mut` access via
// `set_tss_base` and the `&self` access via `load` do not alias the TSS
// reference handed out by `bsp_tss()`.
static mut BSP_GDT: GlobalDescriptorTable = GlobalDescriptorTable::new(0);

/// Monotonic count of `set_rsp0` calls on the BSP TSS.
///
/// Not used for correctness — the scheduler writes `rsp0` directly. This
/// exists so a future scheduler-profiler can snapshot how often the BSP
/// TSS is being touched without taking a lock, and as a sanity counter
/// that the boot path can read to confirm the TSS is wired up. Kept as an
/// `AtomicU64` so it is sound to read from any CPU even before SMP is up.
static BSP_RSP0_WRITES: AtomicU64 = AtomicU64::new(0);

/// Borrow the BSP's TSS for mutation.
///
/// Returns a `&mut TaskStateSegment` that the scheduler / IDT phase can
/// use to set `rsp0` and the IST entries. This is safe because:
///
/// * only the BSP calls this (APs use their own per-CPU TSS later);
/// * the BSP runs single-threaded until the scheduler starts, and after
///   that only the scheduler on the BSP touches `rsp0`;
/// * the GDT's TSS descriptor only stores the TSS's *address*, so
///   mutating the TSS through this reference cannot invalidate the
///   descriptor.
///
/// When the SMP phase lands this function is replaced by
/// `PerCpu::current().tss()` and the BSP static is retired.
pub fn bsp_tss() -> &'static mut TaskStateSegment {
    // SAFETY: `BSP_TSS` is a `static mut` aliased by the GDT's TSS
    // descriptor (which only holds the address). We hand out an exclusive
    // `&mut` on the basis that only the BSP accesses its own TSS and the
    // GDT never accesses it through the Rust reference — the CPU reads
    // it as a raw pointer. See the safety note on `BSP_TSS`.
    unsafe { &mut *addr_of_mut!(BSP_TSS) }
}

/// Load the BSP GDT and TSS on the boot CPU.
///
/// This is the public entry point called from `arch::init`. It:
///
/// 1. loads the GDT (reloading all segment registers to the kernel
///    selectors),
/// 2. loads the TSS selector into TR so privilege changes pick up
///    `rsp0` and IST entries.
///
/// After this returns, `bsp_tss().rsp0` is still zero — the scheduler
/// must set it before entering ring 3, and the IDT phase must set
/// `ist[6]` (IST7) for the double-fault stack. We do not set them here
/// because the stacks are allocated by the mm/sched phases, which run
/// later.
pub fn init_bsp() {
    // Patch the TSS descriptor base with the real address of `BSP_TSS`.
    // `BSP_GDT::new(0)` left this as zero because const evaluation cannot
    // cast a pointer to an integer; now that we are in runtime code the
    // address is known and we fill it in before loading.
    //
    // SAFETY: We are single-threaded on the BSP at this point (the
    // scheduler has not started), so the exclusive borrow is sound.
    // `addr_of_mut!(BSP_TSS)` is the linear address of the statically-
    // allocated TSS, which outlives the CPU's use of the GDT. We access
    // `BSP_GDT` through a raw pointer (via `addr_of_mut!`) rather than
    // naming the static directly, to avoid forming a reference to a
    // `static mut` (which the 2024 edition flags as undefined behaviour
    // under `static_mut_refs`). No other code reads `BSP_GDT` until
    // `load()` below.
    unsafe {
        let tss_base = addr_of_mut!(BSP_TSS) as u64;
        (*addr_of_mut!(BSP_GDT)).set_tss_base(tss_base);
    }

    // SAFETY: Same single-threaded-boot argument as above. `BSP_GDT`'s
    // storage lives for the program's entire lifetime, so the GDT base
    // handed to `lgdt` remains valid. The table contents are correct by
    // construction and the TSS base was patched above. This is called
    // exactly once on the BSP before any ring-3 transition. We access the
    // static through a raw pointer to avoid `static_mut_refs`.
    unsafe {
        (*addr_of_mut!(BSP_GDT)).load();
    }

    // SAFETY: `TSS_SELECTOR` indexes the 16-byte TSS descriptor at GDT
    // entry 7, which now points at the static `BSP_TSS`. Called exactly
    // once per CPU; on the BSP this is the first and only `ltr`.
    unsafe {
        load_tss(TSS_SELECTOR);
    }

    ::log::info!(
        "gdt: BSP loaded, selectors kcode=0x{:02x} kdata=0x{:02x} ucode64=0x{:02x} tss=0x{:02x}",
        KERNEL_CODE_SELECTOR,
        KERNEL_DATA_SELECTOR,
        USER_CODE64_SELECTOR,
        TSS_SELECTOR,
    );
}

/// Load a CPU-local GDT whose TSS descriptor references `tss`.
///
/// AP bring-up owns the backing storage for both objects and guarantees that
/// they remain live for the lifetime of the CPU.  Keeping the descriptor
/// construction here avoids duplicating the system-descriptor encoding in
/// the SMP layer.
///
/// # Safety
///
/// `gdt` and `tss` must be valid, uniquely owned pointers to permanent
/// CPU-local storage. This must run exactly once on the AP, before interrupts
/// or ring-3 transitions are enabled on that CPU.
pub(crate) unsafe fn init_for_ap(gdt: *mut GlobalDescriptorTable, tss: *mut TaskStateSegment) {
    // SAFETY: the caller supplies permanent, exclusively owned CPU-local
    // objects. The descriptor is patched before the table is loaded.
    unsafe {
        (*gdt).set_tss_base(tss as u64);
        (*gdt).load();
        load_tss(TSS_SELECTOR);
    }
}

/// Update the BSP TSS `RSP0` field.
///
/// Convenience wrapper around [`bsp_tss`] for the scheduler. Records the
/// write in [`BSP_RSP0_WRITES`] so the boot path can confirm the TSS is
/// being maintained.
pub fn set_bsp_rsp0(stack_top: u64) {
    let tss = bsp_tss();
    tss.set_rsp0(stack_top);
    BSP_RSP0_WRITES.fetch_add(1, Ordering::Relaxed);
}

/// Read the number of times [`set_bsp_rsp0`] has been called.
///
/// Primarily a boot-time sanity check. Relaxed ordering is sufficient
/// because the counter carries no synchronization meaning.
pub fn bsp_rsp0_write_count() -> u64 {
    BSP_RSP0_WRITES.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Compile-time layout assertions
// ---------------------------------------------------------------------------

/// The GDT must be exactly 72 bytes: seven 8-byte descriptors plus one
/// 16-byte TSS descriptor. A size mismatch would mean the selectors no
/// longer index the right entries, which is a silent boot-time bug.
const _: () = assert!(mem::size_of::<GlobalDescriptorTable>() == 72);

/// A `SegmentDescriptor` must be exactly 8 bytes — the CPU indexes the
/// GDT in 8-byte strides.
const _: () = assert!(mem::size_of::<SegmentDescriptor>() == 8);

/// A `TssDescriptor` must be exactly 16 bytes — long-mode system
/// descriptors are double-width so they can carry a 64-bit base.
const _: () = assert!(mem::size_of::<TssDescriptor>() == 16);

// ---------------------------------------------------------------------------
// Tests (host target only)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_are_correct() {
        // The selector values are part of the ABI the rest of the kernel
        // (syscall entry, iretq frames, context switch) hardcodes, so
        // they must not drift.
        assert_eq!(KERNEL_CODE_SELECTOR, 0x08);
        assert_eq!(KERNEL_DATA_SELECTOR, 0x10);
        assert_eq!(USER_CODE32_SELECTOR, 0x1B);
        assert_eq!(USER_DATA32_SELECTOR, 0x23);
        assert_eq!(USER_CODE64_SELECTOR, 0x2B);
        assert_eq!(USER_DATA64_SELECTOR, 0x33);
        assert_eq!(TSS_SELECTOR, 0x38);
    }

    #[test]
    fn null_descriptor_is_null() {
        assert!(SegmentDescriptor::NULL.is_null());
        assert!(!SegmentDescriptor::KERNEL_CODE.is_null());
    }

    #[test]
    fn gdt_size_matches_layout() {
        // 7 * 8 (code/data) + 16 (TSS) = 72.
        assert_eq!(mem::size_of::<GlobalDescriptorTable>(), 72);
    }

    #[test]
    fn tss_size_is_104() {
        assert_eq!(mem::size_of::<TaskStateSegment>(), 104);
    }

    #[test]
    fn tss_set_ist_bounds() {
        use core::ptr;
        let mut tss = TaskStateSegment::new();
        // Valid indices 1..=7 must work.
        tss.set_ist(1, 0x1000);
        tss.set_ist(7, 0x7000);
        // The TSS is `#[repr(C, packed)]`, so taking a reference to a field
        // (which `assert_eq!` does) would be unaligned. Read through raw
        // pointers with `read_unaligned` instead.
        unsafe {
            let ist0 = ptr::addr_of!(tss.ist[0]);
            let ist6 = ptr::addr_of!(tss.ist[6]);
            assert_eq!(ptr::read_unaligned(ist0), 0x1000);
            assert_eq!(ptr::read_unaligned(ist6), 0x7000);
        }
        // Out-of-range indices must panic; we do not exercise that here
        // because `catch_unwind` is std-only, but the `assert!` in
        // `set_ist` fires on a bad index in the kernel build.
    }
}
