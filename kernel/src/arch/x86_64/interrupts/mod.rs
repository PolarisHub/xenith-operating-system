//! Interrupt controller surface: exception handlers, the IDT, and the
//! platform interrupt controllers (8259 PIC, local APIC, I/O APIC).
//!
//! This module is the top of the interrupt subsystem. Its public surface is
//! [`init`], which installs the CPU-exception handlers and loads the IDT,
//! and the submodule tree is:
//!
//! ```text
//!   interrupts/
//!     exceptions.rs  — ExceptionContext + per-vector Rust handlers + dispatch
//!     handlers.rs    — dump_and_panic: shared terminal policy
//!     apic.rs        — per-CPU x2APIC setup, timer, EOI, and IPI delivery
//!     ioapic.rs      — ACPI discovery and device-IRQ redirection
//!     pic.rs         — legacy 8259 remap and quiescing
//! ```
//!
//! # Bring-up order
//!
//! Descriptor-table setup runs after the GDT and TSS are loaded (the IDT's
//! gates reference [`super::gdt::KERNEL_CODE_SELECTOR`] and critical gates
//! select TSS IST stacks) and before interrupts are enabled. The normal BSP
//! boot loads exception gates during architecture initialization, then brings
//! up the controllers after ACPI discovery. The aggregate [`init`] helper
//! performs both parts in one call for an already-discovered platform:
//!
//! 1. Installs the 32 CPU-exception gates into the static IDT
//!    ([`super::idt::install_exception_handlers`]).
//! 2. Loads the IDT into the CPU ([`super::idt::load`]).
//! 3. Remaps and masks the legacy PIC, enables the local x2APIC, and discovers
//!    and masks the I/O APIC redirection tables.
//!
//! After controller initialization, exceptions and installed IRQ vectors have
//! live dispatch paths. Device routes remain masked until their drivers claim
//! them, and `sti` happens only after scheduler/device setup (see
//! [`crate::init`]).

pub mod apic;
pub mod exceptions;
pub mod handlers;
pub mod ioapic;
pub mod pic;

// Re-export controller entry points for callers that prefer the aggregate
// interrupt namespace.
pub use apic::init as init_apic;
pub use ioapic::init as init_ioapic;
pub use pic::init as init_pic;

/// Rust-side local-APIC timer dispatch called by `lapic_timer_isr`.
///
/// The assembly entry has already disabled nested maskable interrupts (the
/// IDT entry is an interrupt gate), selected the kernel GS base when needed,
/// and saved every GPR. Preemption may context-switch away inside this call;
/// when this task is selected again it resumes here and the assembly entry
/// restores the retained interrupt frame before `iretq`. Pending caught
/// signals are checked after the tick and may rewrite that return frame.
#[no_mangle]
pub extern "sysv64" fn rust_timer_interrupt(context: &mut exceptions::ExceptionContext) {
    crate::sched::preempt::on_timer_tick();
    match exceptions::dispatch_pending_on_user_return(context) {
        Some(crate::user::signal::DispatchOutcome::DefaultActionTaken {
            sig,
            action:
                crate::user::signal::DefaultAction::Terminate
                | crate::user::signal::DefaultAction::TerminateCoreDump,
        }) => crate::user::process::exit_signal(sig),
        Some(crate::user::signal::DispatchOutcome::DefaultActionTaken {
            action: crate::user::signal::DefaultAction::Stop,
            ..
        }) => crate::user::process::enforce_current_state(),
        _ => {},
    }
}

// ---------------------------------------------------------------------------
// Top-level interrupt bring-up
// ---------------------------------------------------------------------------

/// Bring up the interrupt subsystem on the BSP.
///
/// Installs the 32 CPU-exception handlers into the static IDT and loads the
/// IDT into the CPU, then defers to the controller submodules. After this
/// returns, any architecture exception (`#DE`..reserved) is routed to its
/// per-vector Rust handler in [`exceptions`] rather than triple-faulting.
///
/// # Panics
///
/// This function itself cannot panic. Unrecoverable per-exception handlers
/// panic through [`handlers::dump_and_panic`]; recognized user-copy page
/// faults return through their exception-table fixup; recoverable user faults
/// return through caught/ignored signal policy.
///
/// # Safety of calling
///
/// Safe to call exactly once on the BSP, after the GDT/TSS and platform ACPI
/// data have been published (so the code selector and I/O APIC topology are
/// valid) and before `EFLAGS.IF` is set. APs load the shared IDT and initialize
/// only their CPU-local LAPIC in the SMP entry path.
pub fn init() {
    // 1. Fill vectors 0..31 with present interrupt-gate descriptors
    //    pointing at the matching asm exception stubs. The stubs normalise
    //    the stack frame and call `exceptions::rust_isr_dispatch`, which
    //    routes to the per-vector Rust handler.
    super::idt::install_exception_handlers();

    // 2. Publish the table to the CPU. Until this `lidt` runs, any
    //    exception finds no IDT and triple-faults; after it, the handlers
    //    installed above are live.
    super::idt::load();

    // 3. Quiesce legacy delivery, initialize this CPU's LAPIC, then discover
    //    and mask the platform I/O APICs ready for explicit device routes.
    init_pic();
    init_apic();
    init_ioapic();
}
