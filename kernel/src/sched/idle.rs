//! Scheduler idle-task entry.
//!
//! The scheduler owns one fallback [`TaskNode`](super::scheduler::TaskNode)
//! per online CPU and selects it only when that CPU's run queue is empty.
//! This module owns the task body so idle dispatch has one implementation;
//! task creation and the authoritative per-CPU pointers remain in
//! [`super::scheduler`].
//!
//! The loop dispatches work once after every wake, then uses the x86
//! `sti; hlt` pair. `sti` defers interrupt recognition through the following
//! instruction, so a pending interrupt either prevents the CPU from staying
//! halted or a later interrupt wakes it. That closes the enable-to-halt race
//! without a polling flag.

use crate::arch::x86_64::{hlt, sti};

/// Run the permanent fallback task for one logical CPU.
///
/// `arg` is the compact CPU id supplied during scheduler bring-up. The entry
/// does not need to read it because the scheduler and per-CPU layer already
/// derive the current CPU from GS state.
///
/// # Safety
///
/// This must be entered only through the scheduler's fresh-task trampoline on
/// a live, CPU-private kernel stack. It never returns, so the idle task cannot
/// accidentally pass through the ordinary task-exit path.
pub(super) unsafe extern "C" fn entry(_arg: u64) -> ! {
    loop {
        // An interrupt may have made work runnable while the CPU was halted.
        // Re-pick immediately instead of waiting for the idle task to consume
        // a timer slice.
        super::scheduler::schedule_next();

        // SAFETY: the scheduler enters idle at CPL 0 after installing the IDT
        // and interrupt controllers. The adjacent `sti; hlt` instructions are
        // the architectural race-free idle sequence described above.
        unsafe {
            sti();
            hlt();
        }
    }
}
