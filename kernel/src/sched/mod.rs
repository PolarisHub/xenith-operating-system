//! The Xenith scheduler: tasks, run queues, preemption, and the context
//! switch.
//!
//! This module is the top of the kernel's scheduling subsystem. It groups the
//! pieces that decide which task runs where and perform the switch into one
//! layered tree:
//!
//! ```text
//!   sched/
//!     context.rs   — `Context`: the saved-register image the asm switch reads
//!     task.rs      — `Task`: the task control block (id, state, stack, prio)
//!     thread.rs    — thread-vs-task distinctions (parallel phase)
//!     scheduler.rs — `Scheduler`: run queues, dispatch, spawn/exit/yield/sleep
//!     fpu.rs       — FPU/SSE lazy-save wiring (parallel phase)
//!     idle.rs      — per-CPU idle task and `sti;hlt` idle loop
//!     kthread.rs   — kernel-thread spawn helpers (parallel phase)
//!     preempt.rs   — preemption counter, `need_resched`, the timer-tick path
//! ```
//!
//! # Layering
//!
//! `sched` sits above `arch` (for the `context_switch` asm trampoline and the
//! `hlt`/`sti` instructions the idle loop uses), `mm` (for kernel-stack
//! allocation via the heap), `sync` (for the scheduler spinlock and the
//! per-CPU current-task slot), `time` (for `Instant`/`Duration` sleep
//! deadlines and the LAPIC timer tick), and `util` (for the intrusive
//! run-queue list). It sits below `syscall` (the
//! `sched_yield`/`nanosleep`/`exit` syscalls delegate here) and `user` (the
//! first ring-3 process is a task the scheduler dispatches).
//!
//! # Boot-time wiring
//!
//! [`init`] runs once during kernel bring-up, after `mm` and `time` are
//! online. It initialises the preemption state, spawns the BSP's idle task,
//! flips the scheduler's "initialised" flag, installs the LAPIC timer IDT
//! gate, and arms the calibrated periodic timer at
//! [`scheduler::SCHED_TICK_HZ`]. Once interrupts are enabled,
//! [`preempt::on_timer_tick`] drives preemption by calling
//! [`scheduler::tick`] and [`schedule_next`].
//!
//! # Public surface
//!
//! The two free functions the rest of the kernel reaches for most often —
//! [`init`] and [`schedule_next`] — are re-exported here at the module root so
//! callers write `crate::sched::schedule_next()` rather than drilling into the
//! `scheduler` submodule. The task and context types are similarly
//! re-exported so sibling modules and `syscall`/`user` can name them without a
//! deep `use` path.

pub mod context;
pub mod fpu;
pub mod idle;
pub mod kthread;
pub mod preempt;
pub mod scheduler;
pub mod task;
pub mod thread;

// Flat re-exports so callers can write `use crate::sched::Task` instead of
// drilling into submodules. The submodule paths remain available for callers
// that prefer to scope imports explicitly.
//
// `Context` comes from `context` (the asm-matching layout); `Task`, `TaskId`,
// `TaskState`, and `ExitStatus` come from `task`. These are the types sibling
// modules like `idle` and `kthread` reference as `super::Task` etc.
pub use context::Context;
// Re-export the preempt entry points the rest of the kernel reaches for. The
// timer-vector IRQ handler installed by the interrupt phase calls
// `preempt::on_timer_tick`; `preempt_disable`/`preempt_enable` are used by
// long kernel paths that opt into cooperative preemption. The `yield_point!`
// macro is exported by `preempt` via `#[macro_export]`, so it is already
// reachable at the crate root as `crate::yield_point!` and is not re-listed
// here (re-exporting a `macro_export` item through `pub use` is redundant and
// can confuse the macro namespace).
pub use preempt::{
    init as init_preempt, on_timer_tick, preempt_disable, preempt_disabled, preempt_enable,
    set_need_resched, should_preempt, LAPIC_TIMER_VECTOR,
};
pub use scheduler::{
    sleep_until, spawn, spawn_on, stats, SchedulerStats, AGING_THRESHOLD_TICKS, SCHED_TICK_HZ,
};
pub use task::{ExitStatus, Task, TaskId, TaskState};

// ---------------------------------------------------------------------------
// Boot-time entry point
// ---------------------------------------------------------------------------

/// Bring the scheduler up on the boot CPU.
///
/// Called exactly once from [`crate::init`] (step 9 of the boot sequence)
/// after the memory and time subsystems are online — the scheduler allocates
/// kernel stacks from the heap and reads sleep deadlines from the monotonic
/// clock, so both must be ready. This is a thin wrapper around
/// [`scheduler::init`] that keeps the boot call site (`crate::init::init`)
/// stable as the scheduler internals evolve.
///
/// After this returns, [`schedule_next`] is safe to call, [`spawn`] accepts
/// work, and the LAPIC timer is armed at [`SCHED_TICK_HZ`]. The IDT gate is
/// installed before the timer is unmasked, and the boot path keeps IF clear
/// until all remaining device/userspace setup is complete.
pub fn init(boot_info: &'static limine::BootInfo) {
    // Topology discovery consumes the globally parsed ACPI tables, so the
    // scheduler keeps this boot-sequence parameter only for API stability.
    let _ = boot_info;
    scheduler::init();

    // Publish the interrupt gate before unmasking the LVT source. The IDT is
    // already loaded, but its static backing table remains live and may be
    // extended while boot still has IF clear.
    crate::arch::x86_64::idt::install_timer_handler(LAPIC_TIMER_VECTOR);

    // `time::init` calibrated and left the LAPIC timer masked. Programming the
    // periodic count here is the final scheduler wiring step; no interrupt can
    // be delivered until the outer boot path executes STI.
    crate::time::lapic_timer::set_tick(SCHED_TICK_HZ, LAPIC_TIMER_VECTOR);
    ::log::info!(
        "xenith.sched: LAPIC tick armed at {} Hz on vector {:#04x}",
        SCHED_TICK_HZ,
        LAPIC_TIMER_VECTOR,
    );
}

// ---------------------------------------------------------------------------
// The dispatch entry point re-exported at the module root
// ---------------------------------------------------------------------------

/// Pick the next runnable task and context-switch into it.
///
/// This is the single dispatch entry point shared by the preemption path
/// (the LAPIC timer tick), the reactive `preempt_enable`, the voluntary
/// [`yield_now`], and the post-exit switch in [`scheduler::exit`]. It is
/// re-exported here from [`scheduler::schedule_next`] so the rest of the
/// kernel (and [`preempt::scheduler_schedule_next`]) can call it as
/// `crate::sched::schedule_next()`.
///
/// See [`scheduler::schedule_next`] for the full contract. In brief: the head
/// of the current CPU's run queue is picked (or the idle task if the queue is
/// empty); if that is already the current task the call is a no-op; otherwise
/// the asm context-switch trampoline exchanges the saved register files and
/// the caller resumes on the new task's stack.
///
/// # Preemption safety
///
/// May be called from process context (`yield`, `exit`, `preempt_enable`) or
/// from the timer IRQ handler (with `EFLAGS.IF` clear). The scheduler disables
/// interrupts across every dispatch and does not hold its spinlock across the
/// context switch, so re-entrancy from a timer interrupt on the same CPU
/// cannot deadlock.
#[inline]
pub fn schedule_next() {
    scheduler::schedule_next();
}

// ---------------------------------------------------------------------------
// Convenience: cooperative yield re-exported at the module root
// ---------------------------------------------------------------------------

/// Cooperatively yield the CPU to the scheduler.
///
/// Re-exported from [`scheduler::yield_now`] so callers can write
/// `crate::sched::yield_now()`. The current task is moved to the back of its
/// priority level on the run queue and the next runnable task is dispatched.
/// If nothing else is runnable the call returns immediately without a switch.
#[inline]
pub fn yield_now() {
    scheduler::yield_now();
}

// ---------------------------------------------------------------------------
// Status accessor for early-boot callers
// ---------------------------------------------------------------------------

/// `true` once the scheduler has been initialised and is dispatching tasks.
///
/// Re-exported from [`scheduler::is_initialised`] so callers can check it as
/// `crate::sched::is_initialised()`. Uses an `Acquire` load so any writes
/// performed by [`init`] (notably the idle-task installation under the
/// scheduler lock) are visible to a caller that observes `true`.
#[inline]
#[must_use]
pub fn is_initialised() -> bool {
    scheduler::is_initialised()
}
