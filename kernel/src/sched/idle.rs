//! Per-CPU idle task and idle loop.
//!
//! Every logical CPU has a permanently-runnable "idle task" that the scheduler
//! dispatches when the run queue is empty. Its body is [`idle_loop`]: a tight
//! `hlt` (or `mwait` when the CPU supports it) that puts the core into the
//! lowest architecturally-available C-state until the next interrupt — the
//! LAPIC timer tick, an IPI, or a device IRQ — wakes it. Because the idle task
//! is always runnable, the scheduler's "pick next" primitive can never fail:
//! it returns the idle task instead of a "no work" condition, which keeps the
//! dispatch path branch-free and panic-free.
//!
//! # Why a task, not a bare loop
//!
//! The scheduler context-switches *between tasks*. If the idle path were a
//! special case that did not own a task/context, every dispatch primitive would
//! need a "or maybe we just hlt here" branch, and a wake-up that arrived while
//! idling would have to fabricate a return context. Giving the idle path a real
//! task — with its own stack and saved register set — makes it flow through the
//! exact same `context_switch` path as any other kernel thread, so wake-up is
//! just "enqueue the woken task, pick it next, switch to it."
//!
//! # `hlt` vs `mwait`
//!
//! `hlt` halts the core until the next *unmasked* interrupt. It is universally
//! available and is the correct default. `mwait` (with `monitor`) is an Intel
//! extension that lets the core enter a deeper, configurable C-state in response
//! to a write to a monitored memory line. It is optional (not present on many
//! AMD parts and on hypervisors that mask it), so it is gated on a CPUID probe
//! done once at boot and cached in [`USE_MWAIT`] via [`init_idle_policy`]. When
//! `mwait` is unavailable or disabled, the loop falls back to `hlt`.
//!
//! # Safety of the `sti; hlt` pattern
//!
//! The idle loop must run with interrupts enabled, otherwise the core never
//! wakes. The classic race — "interrupt arrives between `sti` and `hlt`, the
//! core then halts and misses it" — does not exist on x86: `sti` defers
//! interrupt delivery for exactly one following instruction (the so-called
//! "interrupt shadow"), so `sti; hlt` is architecturally guaranteed to either
//! take the interrupt before `hlt` executes or halt-and-wake on the next one.
//! We rely on that guarantee here.

use core::sync::atomic::{AtomicBool, Ordering};

// The idle task is built from the same primitives as any other kernel thread,
// so it depends on the scheduler core's task/context types. Those live in the
// sibling `sched` modules (`task`, `context`, `scheduler`) that land in this
// same phase. The contract this module assumes is documented on each `use`.
use super::kthread::spawn_kernel_thread;
use super::{Task, TaskId};
use crate::arch::x86_64::{cpuid, hlt, sti};

/// The stack size allocated for an idle task.
///
/// Idle tasks do almost no work — they halt and wake — so a small stack is
/// plenty. 8 KiB comfortably covers the worst case: a wake-up that takes a
/// timer-tick interrupt (which pushes a full exception frame) and then runs the
/// scheduler's pick/dispatch path before switching to the woken task. We keep
/// it a `const` rather than `cfg`-gated so the size is visible at the call site.
pub const IDLE_STACK_SIZE: usize = 8 * 1024;

/// A cached decision about which halt instruction to use on this CPU.
///
/// Probing CPUID on every idle entry would be wasteful (the idle loop runs
/// thousands of times per second when the system is quiet), so the probe runs
/// once at boot and the result is stored in a static. All CPUs on a symmetric
/// system share the same feature set, so a single global is correct; if Xenith
/// ever supports asymmetric (big.LITTLE-style x86) configurations, this becomes
/// per-CPU.
///
/// The inner `AtomicBool` is only ever written once (during [`init_idle_policy`])
/// and read on every idle entry, so `Relaxed` ordering is sufficient: there is
/// no other state that needs to be ordered relative to the policy decision.
static USE_MWAIT: AtomicBool = AtomicBool::new(false);

/// Probe the CPU for `monitor`/`mwait` support and cache the decision.
///
/// CPUID leaf 1 reports `MONITOR` in ECX bit 3 and `MWAIT` in ECX bit 8. Both
/// must be set for the idle loop to use `mwait`; either alone is useless
/// (`monitor` arms the monitor line, `mwait` consumes it). Some hypervisors
/// advertise `mwait` but trap it to a no-op or a #GP; we cannot detect that
/// without trying, so we trust the CPUID bits. If `mwait` turns out to fault
/// in practice on a given platform, the operator can clear the feature by
/// editing this probe — it is the single place the decision is made.
///
/// This is `pub` so the scheduler bring-up (`sched::init`) can call it once
/// before the first idle entry, but it is safe to call more than once (it just
/// re-probes and re-writes the static).
pub fn init_idle_policy() {
    // CPUID leaf 1: feature information. ECX bit 3 = MONITOR, bit 8 = MWAIT.
    // SAFETY: CPUID is non-privileged and part of the x86_64 baseline.
    let r = unsafe { cpuid(1) };
    let monitor = (r.ecx & (1 << 3)) != 0;
    let mwait = (r.ecx & (1 << 8)) != 0;
    USE_MWAIT.store(monitor && mwait, Ordering::Relaxed);
}

/// Return `true` if the idle loop should use `mwait` on this CPU.
///
/// This is the read side of the cached probe; the idle loop calls it on every
/// entry. `Relaxed` is correct because the value is a fixed feature decision,
/// not a synchroniser.
#[inline]
fn use_mwait() -> bool {
    USE_MWAIT.load(Ordering::Relaxed)
}

/// The idle task's body: halt until an interrupt arrives, then yield.
///
/// This is the function the per-CPU idle task runs. It never returns — the idle
/// task is permanent — so it is `-> !`. On each iteration it:
///
/// 1. Optionally announces that this CPU is going idle (a future scheduler
///    statistic hook; currently a no-op so the loop stays cheap).
/// 2. Halts the core via `hlt` (or `mwait` when supported) with interrupts
///    enabled, so the next interrupt wakes it.
/// 3. After wake-up, falls off the bottom of the loop, which lets the scheduler
///    re-pick: if a real task became runnable while we slept, `schedule()` will
///    dispatch it; otherwise we loop straight back into the halt.
///
/// # Interrupt safety
///
/// The loop assumes interrupts are enabled when it is entered (the scheduler
/// dispatches with interrupts on). It performs the `sti; hlt` pair explicitly
/// so the "interrupt shadow" guarantee described in the module docs holds even
/// if some caller arranged to enter the idle task with interrupts masked.
pub extern "C" fn idle_loop(_arg: usize) -> usize {
    // The idle task must never return: it owns no parent to return to, and a
    // return would fall off the end of [`super::kthread::kthread_trampoline`]
    // into its `exit_current` tail, which would tear down the one task the CPU
    // must always have. Looping forever here is the correct behaviour.
    loop {
        // Give the scheduler a chance to pick a real task that became runnable
        // while we were awake. `schedule` returns only when the current task is
        // again the idle task (i.e. the run queue is still empty); if a real
        // task was picked, we will not reach the halt until that task blocks.
        //
        // Future: `super::scheduler::schedule()`. The sibling scheduler module
        // owns the real pick/dispatch path; until it lands this is a local
        // no-op so the idle loop is testable in isolation.
        schedule_or_yield();

        // Halt with interrupts enabled. `sti` opens a one-instruction interrupt
        // shadow, so an interrupt that arrives between `sti` and `hlt` is
        // guaranteed to be taken before `hlt` executes (the shadow suppresses
        // delivery until the `hlt` has retired, at which point the pending
        // interrupt wakes it immediately). This is the architecturally-guaranteed
        // race-free idle pattern.
        //
        // SAFETY: `sti` sets EFLAGS.IF at CPL 0 with IOPL 0 — valid in any
        // kernel context. `hlt` is safe per its own crate-level safety note.
        // The pairing is what makes the idle pattern correct.
        if use_mwait() {
            mwait_halt();
        } else {
            hlt_halt();
        }
    }
}

/// `sti; hlt` halt path.
///
/// Kept as a separate helper so the `hlt`/`mwait` branches in [`idle_loop`] are
/// symmetric and each can be reasoned about independently.
#[inline]
fn hlt_halt() {
    // SAFETY: see [`idle_loop`] — `sti; hlt` is the race-free idle pattern.
    unsafe {
        sti();
        hlt();
    }
}

/// `mwait`-based halt path.
///
/// `monitor` arms a watch on a cache line; `mwait` then halts until that line
/// is written or an interrupt arrives. For the idle loop we do not actually
/// need to wake on a memory write — the LAPIC timer and IPIs are interrupts —
/// so we point `monitor` at a scratch line (the per-CPU idle flag) and rely on
/// the interrupt-wake half of `mwait`'s contract. The extension's value here is
/// that it lets the core enter a deeper C-state than `hlt` does.
///
/// The `mwait` extension's hints (EAX) and extensions (ECX) are zeroed: we want
/// the smallest, safest hint set. A future power-management phase can tune
/// these per-platform.
#[inline]
fn mwait_halt() {
    // A stable, cache-aligned scratch address for the monitor line. We reuse
    // the `USE_MWAIT` static's storage: it is read-only after boot, so pointing
    // `monitor` at it never triggers a spurious wake from a write. `monitor`
    // only needs a valid, mapped, write-back cache line; it does not require
    // the line to be writable.
    let line = &USE_MWAIT as *const _ as *const u8;
    // SAFETY: `monitor` and `mwait` are non-privileged instructions when the
    // CPU advertises them (which `use_mwait` checked). `monitor` takes its
    // address in RAX, the "extensions" hint in ECX, and the "hints" in EDX;
    // `mwait` takes extensions in ECX and hints in EAX. We zero the hint
    // registers. Neither instruction reads or writes general memory in a way
    // the compiler needs to know about, but we do NOT mark `nomem` because
    // `monitor` establishes a coherence watch on the line — the compiler must
    // not reorder a later store past it.
    unsafe {
        core::arch::asm!(
            "sti",
            "monitor",
            in("rax") line,
            in("rcx") 0usize,
            in("rdx") 0usize,
            options(nostack),
        );
        core::arch::asm!(
            "mwait",
            in("rax") 0usize,
            in("rcx") 0usize,
            options(nostack),
        );
    }
}

/// Ask the scheduler to dispatch a runnable task, or return if idle is still
/// the right choice.
///
/// This is the seam between the idle loop and the scheduler core. It examines
/// the run queue and context-switches to the next runnable task when one
/// exists. If the queue is empty, selecting the already-current idle task is
/// a no-op and the loop proceeds to halt again.
#[inline]
fn schedule_or_yield() {
    // The concrete scheduler is now wired; a pending task is dispatched
    // before the next halt rather than waiting for another timer slice.
    super::scheduler::schedule_next();
}

/// Create and enqueue the per-CPU idle task.
///
/// Each CPU needs its own idle task so that the saved register set and stack
/// belong to the right core — a single shared idle task would mean two CPUs
/// racing to use the same stack. The task is built with [`spawn_kernel_thread`],
/// which allocates the stack, constructs the initial context pointing at
/// [`idle_loop`], and enqueues it on the calling CPU's run queue.
///
/// # Arguments
///
/// * `cpu` — the logical CPU id this idle task belongs to. Only used to build a
///   diagnostic task name (`"idle-N"`); the scheduler does not key off it.
///
/// # Returns
///
/// The [`TaskId`] of the new idle task. The caller (per-CPU bring-up) stashes
/// this so the scheduler's "pick next" primitive can return the idle task when
/// the run queue is empty.
///
/// # Panics
///
/// Panics if the underlying stack allocation or task construction fails. The
/// idle task is mandatory — a CPU without one cannot idle — so a failure here
/// is fatal and there is no recovery path. (A boot-time panic is preferable to
/// a silent corrupt idle path.)
#[must_use]
pub fn create_idle_task(cpu: u32) -> TaskId {
    // Build a diagnostic name. We format into a small stack buffer rather than
    // allocate a KString because the name is only used for `log::debug!` and
    // the task's `name` field; a 16-byte buffer holds "idle-" plus any realistic
    // CPU id (up to 10 digits) with room to spare.
    let mut name_buf: [u8; 17] = *b"idle-            ";
    let prefix = b"idle-";
    let mut idx = prefix.len();
    let mut n = cpu;
    // Render the CPU number into the buffer. We do at least one digit so cpu 0
    // prints "idle-0" rather than "idle-".
    let start = idx;
    if n == 0 {
        name_buf[idx] = b'0';
        idx += 1;
    } else {
        while n > 0 {
            name_buf[idx] = b'0' + (n % 10) as u8;
            idx += 1;
            n /= 10;
        }
        // The digits came out little-endian; reverse them in place.
        name_buf[start..idx].reverse();
    }
    let name_len = idx;
    let name = core::str::from_utf8(&name_buf[..name_len]).unwrap_or("idle");

    // The idle task starts in the Runnable state and is always eligible to
    // run, so the scheduler can pick it the moment the run queue empties. We
    // pass 0 as the argument; `idle_loop` ignores its argument.
    let id = spawn_kernel_thread(name, idle_loop, 0);

    // Mark the task as the per-CPU idle task so the scheduler can recognise it
    // (for example to avoid counting it in load averages, or to give it the
    // lowest possible dynamic priority). The sibling `Task` type owns the flag;
    // when it lands this call sets it. Until then the task is just an ordinary
    // kernel thread whose body happens to be the idle loop, which is harmless.
    mark_idle(&id);

    ::log::debug!("sched.idle: idle task for CPU {cpu} created (tid={id:?})");
    id
}

/// Record that the given task is the per-CPU idle task.
///
/// The sibling `Task` type is expected to expose a way to tag a task as the
/// idle task (a flag or a dedicated `Idle` variant on its state enum). This
/// helper isolates that seam so the sibling's exact API can be wired during the
/// integration pass without touching [`create_idle_task`]'s body.
fn mark_idle(_id: &TaskId) {
    // Future: `super::scheduler::set_task_kind(id, TaskKind::Idle)` or set the
    // task's state to its idle variant. The sibling scheduler module owns the
    // real representation; until it lands this is a no-op and the idle task is
    // a normal kernel thread.
}

/// Return a reference to the idle task for the current CPU, if created.
///
/// The scheduler's "pick next" primitive calls this when the run queue is
/// empty. The returned [`Task`] is dispatched like any other. The pointer is
/// borrowed from the per-CPU idle-task slot and is valid for the lifetime of
/// the idle task (i.e. forever, since idle tasks are never destroyed).
///
/// Until the per-CPU storage sibling module lands this returns `None`; the
/// scheduler will treat `None` as "halt here" in that case.
#[must_use]
pub fn current_idle_task() -> Option<&'static Task> {
    // Future: read the idle-task pointer from the per-CPU control block
    // (`super::percpu` or `arch::x86_64::percpu`). The slot is populated by
    // [`create_idle_task`] at CPU bring-up. Returning `None` here is a stub so
    // the scheduler compiles before per-CPU storage is wired.
    None
}
