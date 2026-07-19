//! Architecture-specific subsystem.
//!
//! This module is the root of everything CPU-specific in Xenith. The kernel
//! proper is written target-agnostically wherever practical — address types,
//! the page-table walker, the frame allocator, the scheduler, and the syscall
//! layer all live above this module and depend only on the abstract surface
//! re-exported here. When Xenith is ported to a second architecture, this file
//! is the single `cfg`-switch point that selects the right sub-architecture.
//!
//! Today only x86_64 is supported, exposed through [`x86_64`]. The submodule
//! owns the GDT, IDT, TSS, per-CPU area, FPU/SSE state, interrupt entry
//! trampolines, and the raw instruction wrappers (`cli`/`sti`/`hlt`, MSR and
//! control-register access, `invlpg`, `cpuid`, ...). See
//! [`x86_64::early_init`] for the bring-up sequence.
//!
//! # Layering
//!
//! `arch` sits below every other kernel subsystem but above the leaf crates
//! (`console`, `log`, `util`) and the shared `xenith-types` / `xenith-bitflags`
//! crates. Other modules reach CPU primitives through the re-exports below so
//! they never have to name the `x86_64` submodule directly — that keeps the
//! rest of the kernel portable.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

// Flat re-exports so callers write `crate::arch::hlt()` / `crate::arch::cli()`
// rather than drilling into the sub-architecture. When a second arch is added,
// a `cfg`-gated match arm here will pick the right primitives; for now every
// re-export is x86_64-only.
#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    early_init,
    // Control-register and CPUID surface used by mm, sched, and the syscall
    // entry code. Re-exported at the arch root so those modules do not have to
    // reach into x86_64::instructions.
    instructions,
    // MSR handle + the named constants (IA32_EFER, IA32_LSTAR, ...) are needed
    // by the syscall trampoline and the LAPIC driver.
    msr,
    // The Port abstraction is consumed by the serial console and device
    // drivers; re-export the type aliases so call sites stay short.
    port::{Port, Port16, Port32, Port8},
    // Cr0/Cr3/Cr4 flag types. Paging code constructs these to flip feature
    // bits such as PAE, PGE, or write-protect.
    registers::{Cr0, Cr3, Cr4},
};

/// Architecture bring-up entry point.
///
/// Called by [`init`](crate::init) once the early console and log backend are
/// up. Delegates to [`x86_64::init`], which runs the full CPU setup sequence
/// (GDT, IDT, TSS, per-CPU area, FPU enablement, CPU feature flags). Earlier
/// first calls [`early_init`] for allocation-free control-register policy,
/// then installs the BSP descriptor tables, per-CPU area, FPU state, and IDT.
///
/// Keeping both an `init` and an `early_init` lets AP bring-up reuse the
/// allocation-free register policy before installing its CPU-local tables,
/// while the BSP uses this complete entry point.
pub fn init(boot_info: &'static limine::BootInfo) {
    #[cfg(target_arch = "x86_64")]
    x86_64::init(boot_info);
    // No other arch is targeted today; the cfg above is the single point a
    // future port hooks into. We deliberately do not panic on an untargeted
    // arch here because such a build would already have failed to compile the
    // rest of the kernel — the function body would be empty, not erroneous.
    let _ = boot_info;
}
