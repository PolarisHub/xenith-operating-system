//! Task State Segment management: IST stacks, `build_tss`, and BSP bring-up.
//!
//! The hardware [`TaskStateSegment`] layout (the 104-byte `repr(C, packed)`
//! struct the CPU reads on every privilege-level change and IST-armed
//! interrupt) lives in [`super::gdt`], because the GDT's TSS descriptor
//! references that struct by linear address. This module owns the *policy*
//! layered on top of that raw layout: which IST entries are populated
//! (IST[7] for the double-fault stack), what `RSP0` is (refreshed by the
//! scheduler on every context switch), how the I/O Permission Bitmap is
//! configured (disabled — `iomap_base` points past the TSS so the CPU denies
//! every port for CPL > IOPL), and the BSP bring-up in [`init_bsp`] that
//! configures the static `BSP_TSS` and loads the GDT + TSS.
//!
//! The struct is re-exported here rather than defined here so the dependency
//! stays natural: `gdt` owns the CPU table entries, `tss` owns the runtime
//! policy. The BSP uses the static owned by `gdt`; APs use the TSS embedded in
//! their permanent per-CPU area and call [`build_tss_with_ist`] with their own
//! critical-fault stacks during SMP bring-up.
//!
//! # IST[7] — the critical-fault stack
//!
//! A normal interrupt handler runs on the stack it interrupted, which is
//! correct until that stack is the problem: a kernel stack overflow pushes
//! the handler's frame into unmapped memory and the resulting `#PF` recurses
//! on the same broken stack, triple-faulting the CPU. IST entries break that
//! cycle: when an IDT gate selects IST[i], the CPU loads `RSP` from
//! `TSS.ist[i-1]` *before* pushing the frame, so the handler runs on a
//! private, known-good stack. Xenith reserves IST[7] for `#DF` / `#MC` / NMI;
//! the other entries are left zero ("no stack switch").

use core::mem;
use core::ptr::{addr_of, addr_of_mut};

// `TaskStateSegment` is re-exported so callers can write
// `arch::x86_64::tss::TaskStateSegment` without reaching into the `gdt`
// module. The type itself is defined in `gdt` (see the module docs for why);
// the private `use` brings it into scope for the assertions and helpers
// below, and the `pub use` re-exports it to the rest of the kernel.
use super::gdt;
pub use super::gdt::TaskStateSegment;

/// The IST index reserved for the double-fault (`#DF`) / critical-fault stack.
///
/// IDT gates that select this IST switch to the current CPU's configured
/// critical-fault stack, breaking the recursion that a kernel-stack overflow
/// would otherwise cause. The BSP uses [`BSP_DF_STACK`]; APs have permanent
/// stacks in the SMP module. The value is 7, the highest IST slot; the matching
/// TSS field is `ist[6]` (IDT entries are 1-indexed, the array 0-indexed).
pub const DOUBLE_FAULT_IST: u8 = 7;

/// The size of each IST stack in bytes.
///
/// 16 KiB is comfortably more than a fault handler needs (it dumps registers
/// and parks the core), and a power of two keeps the stack top naturally
/// 16-byte aligned. Increasing this only costs static BSS; it does not
/// affect runtime unless a handler actually exceeds it.
pub const IST_STACK_SIZE: usize = 16 * 1024;

/// The architectural size of a 64-bit TSS in bytes.
///
/// The CPU's TSS descriptor limit field is set to `sizeof(TSS) - 1`, and the
/// "no IOPB" sentinel for `iomap_base` is any value `>= sizeof(TSS)`. We
/// keep the literal here so both computations read from the same source.
pub const TSS_SIZE: u16 = mem::size_of::<TaskStateSegment>() as u16;

// ---------------------------------------------------------------------------
// IST stack storage
// ---------------------------------------------------------------------------

/// A naturally-16-byte-aligned IST stack.
///
/// The `align(16)` guarantees the stack top (`base + IST_STACK_SIZE`) is
/// 16-byte aligned, which satisfies the SysV AMD64 ABI's stack-alignment
/// requirement at the handler entry point. The CPU itself only requires 8
/// bytes of alignment for the IST value, but the extra alignment is free and
/// keeps the handler's prologue correct if it ever uses aligned SSE.
#[repr(C, align(16))]
struct IstStack {
    /// The raw backing bytes. The stack grows down from the end, so the CPU
    /// loads `base + IST_STACK_SIZE` as `RSP` and the first push lands at
    /// `base + IST_STACK_SIZE - 8`. The contents are left zero; a fault
    /// handler writes its frame into them and never reads prior contents.
    bytes: [u8; IST_STACK_SIZE],
}

/// The BSP's double-fault / critical-fault IST stack.
///
/// Statically allocated in BSS so its address is known at link time and the
/// BSP TSS can reference it without an allocator. APs use their own permanent
/// IST stacks prepared by the SMP bring-up path.
///
/// This is `static mut` because [`df_stack_top`] takes its address for the
/// CPU to read, and the stack is never accessed through a Rust reference —
/// the CPU writes the interrupt frame into it directly. We reach the address
/// via `addr_of_mut!` to avoid forming a reference to a `static mut`, which
/// the 2024 edition flags as undefined behaviour under `static_mut_refs`.
static mut BSP_DF_STACK: IstStack = IstStack {
    bytes: [0; IST_STACK_SIZE],
};

/// The stack-pointer value to load into the TSS IST[7] slot.
///
/// Returns the *top* of [`BSP_DF_STACK`] (one past the highest byte), which
/// is the value the CPU loads into `RSP` before pushing the interrupt frame.
/// The stack grows down, so the first push writes at `top - 8` and descends
/// from there.
///
/// The result is 16-byte aligned because `BSP_DF_STACK` is `align(16)` and
/// `IST_STACK_SIZE` is a multiple of 16.
#[must_use]
pub fn df_stack_top() -> u64 {
    // SAFETY: We only take the address of `BSP_DF_STACK` and do pointer
    // arithmetic to compute the one-past-the-end address; we never form a
    // Rust reference to the `static mut` and never read its contents. The
    // address is a link-time constant, so this is sound from any context
    // (including early boot before any CPU has touched the TSS).
    unsafe {
        let base = addr_of_mut!(BSP_DF_STACK) as *const u8;
        base.add(IST_STACK_SIZE) as u64
    }
}

// ---------------------------------------------------------------------------
// build_tss — configure a TSS for a given kernel stack
// ---------------------------------------------------------------------------

/// Configure a [`TaskStateSegment`] for use as the current CPU's TSS.
///
/// Sets `RSP0` to `kernel_stack_top` (the kernel stack loaded on every
/// ring-3 -> ring-0 transition, refreshed by the scheduler on each context
/// switch); `IST[7]` to [`df_stack_top()`] (the dedicated double-fault
/// stack); and `iomap_base` to [`TSS_SIZE`] — the "no IOPB" sentinel. With
/// `iomap_base >= sizeof(TSS)`, the CPU denies every I/O port for CPL > IOPL,
/// so ring-3 `in`/`out` fault with `#GP`. Setting `iomap_base` to 0 would
/// *appear* to mean "no bitmap" but in fact makes the CPU read the TSS's own
/// leading bytes as the bitmap — and an all-zero bitmap *allows* every port,
/// so the sentinel is the safe choice. The remaining RSP/IST slots stay zero
/// ("no stack switch"), matching [`TaskStateSegment::new`].
///
/// `kernel_stack_top` must be a valid, mapped, writable kernel-virtual
/// address with room below it for the IRETQ frame the CPU pushes on a
/// ring-3 -> ring-0 entry. A garbage value causes the CPU to jump to a
/// garbage `RSP` on the next privilege change, which is unrecoverable. The
/// function itself is safe (it only writes the `&mut TSS`); the *value* it
/// stores is only safe for the CPU to use if the above holds.
pub fn build_tss(tss: &mut TaskStateSegment, kernel_stack_top: u64) {
    build_tss_with_ist(tss, kernel_stack_top, df_stack_top());
}

/// Configure a TSS with caller-owned kernel and critical-fault stacks.
///
/// The BSP uses [`build_tss`], whose IST stack is the BSP static. APs need a
/// distinct IST stack per logical CPU, so the SMP bring-up path calls this
/// variant with that CPU's permanent stack top.
pub fn build_tss_with_ist(
    tss: &mut TaskStateSegment,
    kernel_stack_top: u64,
    critical_stack_top: u64,
) {
    // RSP0: the privilege-0 stack. `set_rsp0` handles the packed-field write.
    tss.set_rsp0(kernel_stack_top);
    // IST[7]: the critical-fault stack. `set_ist` validates the 1..=7 range
    // and handles the packed-field write.
    tss.set_ist(DOUBLE_FAULT_IST, critical_stack_top);
    // IOPB: point `iomap_base` past the end of the TSS so the CPU denies
    // every port for ring 3. The struct is `#[repr(C, packed)]`, so a direct
    // assignment would form an unaligned reference; write through a raw
    // pointer instead, matching `set_rsp0` / `set_ist`.
    set_iomap_base(tss, TSS_SIZE);
}

/// Write the `iomap_base` field of a TSS.
///
/// `base` is the offset from the TSS's start to its I/O Permission Bitmap.
/// A value `>= sizeof(TSS)` means "no IOPB" — the CPU denies every port for
/// CPL > IOPL. A value inside the TSS would make the CPU read TSS bytes as
/// the permission bitmap, which is almost never what a caller wants; see
/// [`build_tss`] for the safe sentinel.
///
/// The TSS is `#[repr(C, packed)]` and `iomap_base` is a `u16` at offset
/// 102 (2-byte aligned in practice), but we write through `addr_of_mut!` +
/// `write_unaligned` to stay robust against future packing changes and to
/// avoid forming a reference to a packed field.
pub fn set_iomap_base(tss: &mut TaskStateSegment, base: u16) {
    // SAFETY: `tss.iomap_base` is within the `&mut tss` borrow; the write
    // does not alias any other access. `write_unaligned` copies the value
    // without requiring alignment, so the packed layout is handled.
    unsafe {
        core::ptr::write_unaligned(addr_of_mut!(tss.iomap_base), base);
    }
}

/// Read the `iomap_base` field of a TSS — a diagnostic helper so boot code
/// can confirm the IOPB was configured. The CPU reads this field directly on
/// a CPL > IOPL I/O access, not through this function.
#[must_use]
pub fn iomap_base(tss: &TaskStateSegment) -> u16 {
    // SAFETY: read-only access through a raw pointer copy; no reference to a
    // packed field is formed.
    unsafe { core::ptr::read_unaligned(addr_of!(tss.iomap_base)) }
}

// ---------------------------------------------------------------------------
// BSP bring-up
// ---------------------------------------------------------------------------

/// Bring up the BSP's TSS and load the GDT + TR.
///
/// This is the public entry point called from [`super::init`] (or the
/// scheduler's first-task path) once the kernel stack for the BSP's
/// initial task is known. It:
///
/// 1. Configures the static [`BSP_TSS`](super::gdt::bsp_tss) via
///    [`build_tss`] — `RSP0 = kernel_stack_top`, IST[7] = the critical-fault
///    stack, IOPB disabled.
/// 2. Loads the GDT and TR via [`gdt::init_bsp`], which patches the TSS
///    descriptor base, runs `lgdt`, reloads the segment registers, and runs
///    `ltr` with [`super::gdt::TSS_SELECTOR`].
///
/// After this returns, the CPU will load `RSP0` on the next ring-3 -> ring-0
/// transition and switch to IST[7] on a `#DF`, whose IDT gate selects that
/// stack. Interrupts may be safely enabled; the TSS is ready.
///
/// # Safety contract (caller)
///
/// `kernel_stack_top` must be a valid kernel stack top (see [`build_tss`]).
/// Must be called exactly once on the BSP, after [`super::early_init`] and
/// before the first ring-3 transition or the first IST-armed interrupt.
pub fn init_bsp(kernel_stack_top: u64) {
    // Configure the BSP's static TSS before loading it. `bsp_tss()` hands out
    // an exclusive `&mut` to `BSP_TSS`; the borrow ends when `build_tss`
    // returns, so the subsequent `gdt::init_bsp` (which reads the TSS only
    // through the CPU) does not alias.
    let tss = gdt::bsp_tss();
    build_tss(tss, kernel_stack_top);

    // Patch the TSS descriptor base, `lgdt`, reload segment registers, and
    // `ltr` with `TSS_SELECTOR`. After this the CPU can find the `RSP0` and
    // IST entries we just installed.
    gdt::init_bsp();

    ::log::info!(
        "tss: BSP loaded, RSP0=0x{:016x}, IST7=0x{:016x}, IOPB disabled (base=0x{:x})",
        kernel_stack_top,
        df_stack_top(),
        TSS_SIZE,
    );
}

/// Refresh the BSP TSS `RSP0` for a new kernel stack.
///
/// Thin convenience over [`gdt::set_bsp_rsp0`] so the scheduler and the
/// ring-3 entry path can update the privilege-0 stack through the `tss`
/// module without reaching into `gdt` directly. The IST[7] and IOPB settings
/// installed by [`init_bsp`] / [`build_tss`] are preserved — only `RSP0`
/// changes.
///
/// `kernel_stack_top` must be a valid kernel stack top (see [`build_tss`]).
pub fn set_bsp_rsp0(kernel_stack_top: u64) {
    gdt::set_bsp_rsp0(kernel_stack_top);
}

// ---------------------------------------------------------------------------
// Compile-time layout assertions
// ---------------------------------------------------------------------------

/// The TSS must be exactly 104 bytes — the architectural 64-bit TSS size.
/// A mismatch would make the GDT's `limit` field (set to `sizeof(TSS) - 1`)
/// hand the CPU the wrong limit, silently truncating or extending the
/// structure the CPU reads.
const _: () = assert!(mem::size_of::<TaskStateSegment>() == 104);

/// `TSS_SIZE` must equal `sizeof(TaskStateSegment)`. The IOPB sentinel value
/// depends on this equality; if it drifts, `iomap_base = TSS_SIZE` would no
/// longer point past the end of the TSS.
const _: () = assert!(TSS_SIZE == 104);

/// The IST stack size must be a multiple of 16 so the stack top stays
/// 16-byte aligned regardless of where the static is placed.
const _: () = assert!(IST_STACK_SIZE.is_multiple_of(16));

/// The double-fault IST index must be in the hardware range 1..=7. IDT gates
/// store a 3-bit IST field, so any value outside that range would be masked
/// and silently select the wrong stack (or no stack switch).
const _: () = assert!((DOUBLE_FAULT_IST >= 1) && (DOUBLE_FAULT_IST <= 7));

// ---------------------------------------------------------------------------
// Tests (host target only)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tss_size_is_104() {
        assert_eq!(mem::size_of::<TaskStateSegment>(), 104);
        assert_eq!(TSS_SIZE, 104);
    }

    #[test]
    fn df_stack_top_is_aligned_and_in_bounds() {
        // The stack top must be 16-byte aligned and greater than the base.
        let top = df_stack_top();
        assert_eq!(top % 16, 0, "IST stack top must be 16-byte aligned");
        // The top is `base + IST_STACK_SIZE`; the base is a BSS address, so
        // the top is non-zero on any real host. We only check alignment and
        // that it is representable; the exact value depends on linkage.
        assert!(top != 0, "df_stack_top must not be null");
    }

    #[test]
    fn build_tss_sets_rsp0_ist7_and_iomap() {
        let mut tss = TaskStateSegment::new();
        build_tss(&mut tss, 0xFFFF_8000_DEAD_B000);
        // RSP0: read through the packed-field accessor the gdt module
        // exposes via `set_rsp0` (there is no public reader, so we read the
        // field directly with read_unaligned, matching the gdt's pattern).
        unsafe {
            let rsp0 = core::ptr::read_unaligned(addr_of!(tss.rsp0));
            assert_eq!(rsp0, 0xFFFF_8000_DEAD_B000);
            let ist6 = core::ptr::read_unaligned(addr_of!(tss.ist[6]));
            assert_eq!(ist6, df_stack_top());
        }
        // IOPB: the sentinel points past the end of the TSS.
        assert_eq!(iomap_base(&tss), TSS_SIZE);
    }

    #[test]
    fn set_iomap_base_round_trips() {
        let mut tss = TaskStateSegment::new();
        set_iomap_base(&mut tss, 0x68);
        assert_eq!(iomap_base(&tss), 0x68);
        set_iomap_base(&mut tss, 0x00);
        assert_eq!(iomap_base(&tss), 0x00);
    }

    #[test]
    fn double_fault_ist_is_in_range() {
        const { assert!(DOUBLE_FAULT_IST >= 1 && DOUBLE_FAULT_IST <= 7) };
    }
}
