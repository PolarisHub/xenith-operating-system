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
//!     apic.rs        — local APIC (stub, replaced by the apic phase)
//!     ioapic.rs      — I/O APIC  (stub, replaced by the devices phase)
//!     pic.rs         — 8259 PIC   (stub, replaced by the devices phase)
//! ```
//!
//! # Bring-up order
//!
//! [`init`] runs *after* the GDT and TSS are loaded (the IDT's gates
//! reference [`super::gdt::KERNEL_CODE_SELECTOR`], and IST indices — once
//! any are used — point at TSS stacks) and *before* interrupts are
//! enabled. It:
//!
//! 1. Installs the 32 CPU-exception gates into the static IDT
//!    ([`super::idt::install_exception_handlers`]).
//! 2. Loads the IDT into the CPU ([`super::idt::load`]).
//! 3. Defers to the controller submodules' own `init`s. Today these are
//!    no-ops; the apic phase will wire the local APIC and mask the legacy
//!    PIC, and the devices phase will route IRQs through the I/O APIC.
//!
//! After [`init`] returns, a CPU exception is delivered to a real Rust
//! handler instead of triple-faulting the machine. Maskable IRQs are still
//! off at this point — the local APIC init and `sti` happen later in the
//! boot sequence (see [`crate::init`]).

pub mod apic;
pub mod exceptions;
pub mod handlers;
pub mod ioapic;
pub mod pic;

// Re-export the controller `init` entry points so the boot sequence and
// later phases can reach them without naming the submodule. Each is a
// no-op today; replacing the stub body with the real bring-up does not
// change the call site.
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
/// Safe to call exactly once on the BSP, after the GDT has been loaded
/// (so [`super::gdt::KERNEL_CODE_SELECTOR`] resolves) and before
/// `EFLAGS.IF` is set. Calling it on an AP before the BSP has run it is
/// harmless but the AP's own per-CPU tables are a later-phase concern.
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

    // 3. Controller bring-up. Each is a stub today (the apic and devices
    //    phases replace the bodies). Kept here — and called unconditionally
    //    — so the boot sequence does not change when the real controllers
    //    land; a later phase only swaps a stub body for a real one.
    init_pic();
    init_apic();
    init_ioapic();
}
