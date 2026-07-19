//! Preemption wiring: the path from the LAPIC timer tick to the scheduler.
//!
//! This module is the glue between three subsystems that otherwise do not
//! know about each other:
//!
//! * the **LAPIC timer** (`time::lapic_timer`), which fires a periodic
//!   per-CPU interrupt at the scheduler's tick rate;
//! * the **scheduler** (`sched::scheduler`), which owns the run queue, the
//!   time-slice accounting, and the context-switch routine;
//! * the **preemption policy** lived here — the per-CPU counter that records
//!   whether the running task may be interrupted, the `need_resched` flag
//!   that records whether anyone has asked for a switch, and the
//!   [`yield_point!`] macro that lets long kernel paths volunteer.
//!
//! # The tick path
//!
//! When the LAPIC timer fires, the timer-vector IRQ dispatch calls
//! [`on_timer_tick`]. That function, in order:
//!
//! 1. advances the LAPIC monotonic accumulator ([`lapic_timer::on_tick`]);
//! 2. sends EOI so the LAPIC can deliver the next tick — **before** any
//!    context switch, because once [`scheduler::schedule_next`] switches
//!    away we do not return to this handler frame for an unbounded time and
//!    a pending EOI would starve the whole CPU of interrupts;
//! 3. hands the tick to the scheduler ([`scheduler::tick`]) for its own
//!    accounting — run-queue ageing, woken-task promotion, stats;
//! 4. does the local time-slice bookkeeping — bumps this CPU's tick counter
//!    and raises `need_resched` when the current slice expires, so the
//!    preemption decision is owned here even if the scheduler does not set
//!    the flag itself;
//! 5. if [`should_preempt`] is true — preemption enabled *and* a reschedule
//!    is pending — calls [`scheduler::schedule_next`] to switch tasks.
//!
//! Steps 1-4 are pure accounting and never switch. Only step 5 can leave the
//! current task's stack, and it does so only when the policy allows.
//!
//! # The preemption counter
//!
//! [`preempt_disable`] / [`preempt_enable`] manipulate a per-CPU depth
//! counter. While the counter is non-zero the current task is
//! **non-preemptible**: [`should_preempt`] returns false and the timer tick
//! skips the switch. This is the kernel analogue of Linux's
//! `preempt_disable()`/`preempt_count`; it protects regions that hold a
//! resource the scheduler would need (a run-queue lock, a per-CPU data
//! structure mid-update) or that simply must run to completion before a
//! switch is safe.
//!
//! The counter is stored as an [`AtomicU32`] in a per-CPU array indexed by
//! [`crate::sync::current_cpu`]. Atomic operations are used (rather than the
//! `PerCpu::with` borrow model) because the same CPU's slot is touched from
//! *both* process context (`preempt_disable`/`enable`, `yield_point!`) and
//! IRQ context (the timer handler reads the counter in
//! [`should_preempt`]). A `&mut` borrow taken in process context would alias
//! an IRQ-context access that arrives mid-borrow; a single atomic
//! `fetch_add`/`fetch_sub` is one instruction on x86 and is therefore
//! non-interruptible, which is the property that makes the counter safe
//! without disabling interrupts around every access.
//!
//! `preempt_enable` is *reactive*: when the counter drops to zero it checks
//! `need_resched` and, if set, calls [`scheduler::schedule_next`] before
//! returning. This closes the window where an IRQ requested a reschedule
//! while preemption was disabled — without it, the request would sit idle
//! until the next voluntary yield or timer tick.
//!
//! # Voluntary yield
//!
//! [`yield_point!`] is a cooperative checkpoint for kernel code paths that
//! run for a long time without naturally crossing a preemption boundary
//! (a giant loop in a driver probe, a ramfs bulk copy). It expands to a
//! cheap `should_preempt()` test and, only if a reschedule is pending, a
//! call to [`yield_now`]. Sprinkling it through a long path bounds the
//! latency a runnable task can suffer to one slice.
//!
//! # Expected scheduler interface
//!
//! This module calls two functions in [`crate::sched::scheduler`], built in
//! a parallel phase:
//!
//! * `scheduler::tick()` — called once per LAPIC timer tick to update
//!   scheduler state. Must be safe to call from the timer IRQ context
//!   (interrupts off, no scheduler locks held by the caller).
//! * `scheduler::schedule_next()` — selects the next runnable task and
//!   performs the context switch. May be called from IRQ context (the timer
//!   path) or process context (`preempt_enable`, `yield_now`). The
//!   scheduler is expected to clear `need_resched` (via
//!   [`clear_need_resched`]) when it performs a switch, so a stale flag
//!   cannot re-trigger a switch immediately on resume.
//!
//! If the scheduler exposes these under different names, only the two
//! private wrappers at the bottom of this file need repointing; every other
//! call site goes through them.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::sync::{current_cpu, MAX_CPUS};
use crate::time::lapic_timer;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The default time slice, measured in LAPIC timer ticks.
///
/// At the conventional 100 Hz scheduler tick this is 50 ms; at 250 Hz it is
/// 20 ms. The value is a per-CPU default only — [`set_slice_length`] can
/// tune it per CPU (for example to give a real-time task a shorter slice).
/// It is deliberately small enough that a CPU-bound task cannot stall
/// interactive work for a perceptible interval, and large enough that the
/// context-switch overhead is a negligible fraction of useful work.
pub const DEFAULT_TIME_SLICE_TICKS: u32 = 5;

/// The IDT vector the LAPIC timer is programmed to deliver.
///
/// The interrupt-controller layer owns the fixed assignment (`0xFD`), above
/// the legacy PIC/IOAPIC device range and below the LAPIC error/spurious
/// vectors. Referencing that assignment here gives the IDT gate and
/// [`lapic_timer::set_tick`] one source of truth.
pub const LAPIC_TIMER_VECTOR: u8 = crate::arch::x86_64::interrupts::apic::TIMER_VECTOR;

// ---------------------------------------------------------------------------
// Per-CPU preemption state
// ---------------------------------------------------------------------------

/// The preemption state for one CPU.
///
/// Every field is an atomic. The hot fields (`disable_count`,
/// `need_resched`, `ticks_this_slice`) are touched from both process and
/// IRQ context and need the single-instruction atomicity that x86 gives a
/// `lock`-free atomic RMW; `slice_length` is configuration (written only by
/// [`set_slice_length`]) and `total_ticks` is a stat (written only from the
/// timer handler), but both are kept atomic so every field goes through the
/// same `&self` accessor and the struct is uniformly `Sync` without a
/// manual impl.
///
/// [`slice_length`]: PreemptState::slice_length
#[derive(Debug)]
pub struct PreemptState {
    /// The preemption-disable depth. `0` means the current task is
    /// preemptible; any positive value means at least one
    /// [`preempt_disable`] is outstanding. Manipulated only with
    /// `fetch_add`/`fetch_sub` so an interrupting IRQ handler reading it
    /// never sees a half-updated value.
    disable_count: AtomicU32,
    /// Whether a context switch has been requested and is awaiting the next
    /// preemptible point. Set by the timer tick when the slice expires, by
    /// the scheduler when a higher-priority task wakes, and by anyone
    /// calling [`set_need_resched`]. Cleared by the scheduler when it
    /// performs the switch.
    need_resched: AtomicBool,
    /// Ticks elapsed in the current time slice on this CPU. Bumped by
    /// [`on_timer_tick`] and reset when the slice expires. Only written
    /// from the timer IRQ handler (which runs with interrupts off), so it
    /// is free of same-CPU races; it is an atomic only so the `load` in
    /// diagnostics is a clean read.
    ticks_this_slice: AtomicU32,
    /// Total timer ticks this CPU has taken since boot. A monotonic per-CPU
    /// stat, useful for `/proc`-style accounting and scheduler debugging.
    /// Same access pattern as `ticks_this_slice`.
    total_ticks: AtomicU64,
    /// The configured slice length for this CPU, in ticks. See
    /// [`DEFAULT_TIME_SLICE_TICKS`]. Read-only after
    /// [`set_slice_length`].
    slice_length: AtomicU32,
}

impl PreemptState {
    /// Construct a fresh, preemptible per-CPU state with the default slice
    /// length.
    ///
    /// `const` so the per-CPU array can be initialised at load time without
    /// a runtime constructor (the array-backed `PerCpu::new` is not
    /// `const`-constructible because it uses `array::from_fn`, so this
    /// module owns its own `[PreemptState; MAX_CPUS]` storage instead).
    const fn new() -> Self {
        Self {
            disable_count: AtomicU32::new(0),
            need_resched: AtomicBool::new(false),
            ticks_this_slice: AtomicU32::new(0),
            total_ticks: AtomicU64::new(0),
            slice_length: AtomicU32::new(DEFAULT_TIME_SLICE_TICKS),
        }
    }
}

// One preemption state per possible CPU. Indexed by [`current_cpu`]. The
// array is `Sync` because `PreemptState` contains only atomics and a plain
// `u32` (all `Sync`), and the per-CPU ownership rule — slot *i* is only
// touched on CPU *i* — means a shared `&PreemptState` never aliases a
// mutating access from another CPU. The inline-const array repeat is the
// stable way to initialise an array of a non-`Copy` type in a `static`.
static PREEMPT_STATE: [PreemptState; MAX_CPUS] = [const { PreemptState::new() }; MAX_CPUS];

/// Borrow the running CPU's preemption state as a shared reference.
///
/// The reference is `'static` because the backing array is a `static`. All
/// access is through atomic methods (`&self`), so a shared reference is
/// sufficient for every operation this module performs.
///
/// # Safety of the dereference
///
/// `current_cpu()` is guaranteed in `0..MAX_CPUS` (pre-init returns 0; the
/// arch primitive later reads `gs:[8]`, which bring-up sets to the compact
/// CPU id), so the pointer arithmetic is in bounds. The per-CPU ownership
/// invariant means no other CPU touches this slot, so the shared reference
/// is race-free even though the slot is also reached from IRQ context on
/// this same CPU — the atomic fields handle that interleaving.
#[inline]
fn state() -> &'static PreemptState {
    let cpu = current_cpu();
    // `current_cpu` is in range by contract; the debug_assert catches an
    // arch bug returning a bogus id before it becomes an out-of-bounds
    // access.
    debug_assert!(cpu < MAX_CPUS, "current_cpu {cpu} out of range");
    // SAFETY: `cpu < MAX_CPUS` (asserted above) and the per-CPU ownership
    // invariant gives safe shared access to this CPU's slot. The array is
    // `static`, so the returned reference is valid for `'static`.
    unsafe { &*PREEMPT_STATE.as_ptr().add(cpu) }
}

// ---------------------------------------------------------------------------
// Preempt disable / enable
// ---------------------------------------------------------------------------

/// Disable preemption on the current CPU.
///
/// Increments the per-CPU preemption-disable depth counter. While the
/// counter is non-zero, [`should_preempt`] returns false and the timer tick
/// will not switch tasks. Every `preempt_disable` must be paired with a
/// [`preempt_enable`] on the same CPU; the pairing is checked by a
/// debug-build underflow assertion in [`preempt_enable`].
///
/// Must **not** be called from a hard-IRQ handler: the timer IRQ path does
/// not touch the counter, and an unbalanced disable from IRQ context would
/// leak into the interrupted task's context. Use [`with_preempt_disabled`]
/// in process context for paired regions.
#[inline]
pub fn preempt_disable() {
    let prev = state().disable_count.fetch_add(1, Ordering::Relaxed);
    // `Relaxed` is sufficient: the counter is per-CPU, and the only
    // cross-context reader is the timer IRQ on this same CPU, which (under
    // x86 TSO) observes the store before it reads the counter in
    // `should_preempt`. No other CPU ever reads this slot.
    let _ = prev;
}

/// Re-enable preemption on the current CPU.
///
/// Decrements the per-CPU depth counter. When the counter reaches zero and
/// a reschedule is pending ([`need_resched`] set), this calls
/// [`scheduler::schedule_next`] before returning — the "preempt on enable"
/// rule that prevents a reschedule request made during a preempt-disabled
/// region from being lost.
///
/// # Panics
///
/// In debug builds, panics if the counter would underflow — i.e. if this
/// call is not paired with a prior [`preempt_disable`]. In release builds
/// the underflow is saturating (the counter stays at zero) so a kernel with
/// a leaky enable path remains runnable, but the imbalance is a bug.
///
/// Must not be called from a hard-IRQ handler; see [`preempt_disable`].
#[inline]
pub fn preempt_enable() {
    let s = state();
    let prev = s.disable_count.fetch_sub(1, Ordering::Relaxed);
    if prev == 0 {
        // An unpaired enable. Saturate at zero in release so a leaky path
        // does not wrap to `u32::MAX` and permanently disable preemption;
        // in debug, surface the bug immediately.
        s.disable_count.store(0, Ordering::Relaxed);
        debug_assert!(false, "preempt_enable without a matching preempt_disable");
        return;
    }
    // `prev` was the value *before* the decrement; `prev == 1` means we
    // just dropped to zero. Only at that transition do we need to check for
    // a pending reschedule — a decrement that leaves the counter positive
    // is still inside a preempt-disabled region.
    if prev == 1 && should_preempt() {
        scheduler_schedule_next();
    }
}

/// Whether preemption is currently disabled on this CPU.
///
/// Cheaper than [`should_preempt`] (no `need_resched` load) and usable by
/// assertions that only care about the counter, not the reschedule flag.
#[inline]
#[must_use]
pub fn preempt_disabled() -> bool {
    state().disable_count.load(Ordering::Relaxed) != 0
}

/// The current preemption-disable depth for this CPU.
///
/// Zero means preemptible; any positive value is the number of outstanding
/// [`preempt_disable`] calls. Intended for diagnostics and scheduler
/// assertions.
#[inline]
#[must_use]
pub fn preempt_disable_count() -> u32 {
    state().disable_count.load(Ordering::Relaxed)
}

/// Run `f` with preemption disabled on the current CPU, re-enabling on
/// exit.
///
/// This is the RAII-shaped safe wrapper around [`preempt_disable`] /
/// [`preempt_enable`]. It guarantees the counter is balanced even if `f`
/// returns early, because `panic = abort` means a panic inside `f` halts the
/// kernel rather than unwinding past the enable. (If panic ever becomes
/// unwinding, this helper must move to a guard `Drop` implementation.)
///
/// Use it for short, bounded regions that must not be preempted — e.g. a
/// per-CPU data-structure update. Do not use it for long holds: a
/// preempt-disabled region stalls the scheduler for its entire duration.
#[inline]
pub fn with_preempt_disabled<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    preempt_disable();
    let result = f();
    preempt_enable();
    result
}

// ---------------------------------------------------------------------------
// need_resched
// ---------------------------------------------------------------------------

/// Mark that a context switch should happen at the next preemptible point.
///
/// Called by the timer tick when the slice expires and by the scheduler
/// when it wants to preempt the current task (for example because a
/// higher-priority task woke on this CPU). Idempotent: setting it when
/// already set is a no-op store.
#[inline]
pub fn set_need_resched() {
    state().need_resched.store(true, Ordering::Relaxed);
}

/// Clear a pending reschedule request.
///
/// Called by the scheduler once it has performed the context switch (or
/// decided no switch is needed), so a stale request cannot re-trigger
/// [`scheduler::schedule_next`] immediately on resume. Safe to call when
/// the flag is already clear.
#[inline]
pub fn clear_need_resched() {
    state().need_resched.store(false, Ordering::Relaxed);
}

/// Whether a reschedule has been requested on this CPU.
#[inline]
#[must_use]
pub fn need_resched() -> bool {
    state().need_resched.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// should_preempt
// ---------------------------------------------------------------------------

/// Whether the current task should be preempted *now*.
///
/// True iff preemption is enabled (the disable counter is zero) **and** a
/// reschedule has been requested (`need_resched` is set). This is the
/// single predicate the timer tick, [`preempt_enable`], and
/// [`yield_point!`] all consult before calling
/// [`scheduler::schedule_next`].
///
/// Both loads are `Relaxed`: the flag and the counter are per-CPU, and the
/// only cross-context access is the timer IRQ on this same CPU, whose
/// stores are visible to a subsequent process-context load under x86 TSO
/// without an explicit fence. A consistent snapshot across the two fields
/// is not required — if the counter changes between the two loads the
/// worst case is a one-tick-early or one-tick-late switch, which the
/// scheduler tolerates.
#[inline]
#[must_use]
pub fn should_preempt() -> bool {
    let s = state();
    // Preemption is allowed only when the disable counter is zero (no
    // preempt-disabled region is active on this CPU) and a reschedule has
    // been requested. Reading the counter first short-circuits the common
    // "preempt disabled" case without touching `need_resched`; on the
    // preemptible fast path the second relaxed load is the only extra cost.
    s.disable_count.load(Ordering::Relaxed) == 0 && s.need_resched.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Slice configuration
// ---------------------------------------------------------------------------

/// Set the time-slice length, in timer ticks, for the current CPU.
///
/// Takes effect from the next slice boundary: the current slice is not
/// truncated, but when it expires the new length governs the following one.
/// A value of zero is rejected (a zero-length slice would spin the
/// scheduler) and left unchanged.
#[inline]
pub fn set_slice_length(ticks: u32) {
    if ticks == 0 {
        ::log::warn!("xenith.sched.preempt: ignoring zero slice length");
        return;
    }
    state().slice_length.store(ticks, Ordering::Relaxed);
}

/// The configured time-slice length for the current CPU, in ticks.
#[inline]
#[must_use]
pub fn slice_length() -> u32 {
    state().slice_length.load(Ordering::Relaxed)
}

/// Reset the current CPU's tick accounting.
///
/// Called by the scheduler on a context switch: the incoming task starts a
/// fresh slice, so `ticks_this_slice` is zeroed and any stale `need_resched`
/// is cleared. The scheduler invokes this (via [`on_context_switch_in`])
/// after it has selected the new task but before returning into it.
#[inline]
pub fn on_context_switch_in() {
    let s = state();
    s.ticks_this_slice.store(0, Ordering::Relaxed);
    s.need_resched.store(false, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// The timer tick entry point
// ---------------------------------------------------------------------------

/// LAPIC timer-tick entry point, called by the timer-vector IRQ dispatch.
///
/// This is the function the interrupt wiring installs as the Rust-side
/// handler for [`LAPIC_TIMER_VECTOR`]. It runs in hard-IRQ context with
/// `EFLAGS.IF` clear (the IDT gate is an interrupt gate), so no nested
/// maskable IRQ can fire for its duration.
///
/// The order of operations is load-bearing:
///
/// 1. [`lapic_timer::on_tick`] advances the monotonic accumulator first, so
///    the clocksource sees the tick even if a later step faults.
/// 2. [`lapic_timer::send_eoi`] acknowledges the interrupt at the LAPIC
///    *before* any context switch. Once [`scheduler::schedule_next`]
///    switches away we do not return to this frame for an unbounded time,
///    and an un-acked LAPIC would block same-and-lower-priority interrupts
///    on this CPU until we come back.
/// 3. [`scheduler::tick`] gets the tick for scheduler accounting.
/// 4. Local slice bookkeeping bumps the per-CPU counters and raises
///    `need_resched` when the slice expires.
/// 5. [`should_preempt`] gates the actual switch: only if preemption is
///    enabled *and* a reschedule is pending does
///    [`scheduler::schedule_next`] run.
///
/// Steps 1-4 are pure accounting and never leave this function. Only step 5
/// can switch tasks, and it is the single point where the timer path
/// crosses into the scheduler.
pub fn on_timer_tick() {
    // 1. Monotonic accumulator. Cheap (a single relaxed fetch_add) and
    //    must precede EOI so the clocksource's double-read sees the tick.
    // The LAPIC clocksource accumulator represents wall time, not aggregate
    // CPU time. Only the BSP advances it; every CPU still performs scheduler
    // accounting below from its own local timer interrupt.
    if current_cpu() == 0 {
        lapic_timer::on_tick();
    }

    // 2. End-of-interrupt. Frees the LAPIC to deliver the next tick and any
    //    other same-or-lower-priority interrupt. Must come before a context
    //    switch because we do not return to this frame after one.
    lapic_timer::send_eoi();

    // 3. Scheduler accounting. The scheduler may set `need_resched` here
    //    (e.g. a higher-priority task woke); our local slice check below
    //    may also set it. Both paths are fine — the flag is idempotent.
    scheduler_tick();

    // 4. Local time-slice accounting. Bump the per-CPU tick counters and
    //    flag a reschedule when the current slice has elapsed. This makes
    //    the preemption decision self-contained: even if the scheduler's
    //    own `tick` does not set `need_resched`, the slice boundary does.
    let s = state();
    let _total = s.total_ticks.fetch_add(1, Ordering::Relaxed);
    let slice = s.slice_length.load(Ordering::Relaxed);
    let elapsed = s.ticks_this_slice.fetch_add(1, Ordering::Relaxed) + 1;
    if elapsed >= slice {
        // Slice expired: reset the per-slice counter and ask for a switch.
        // The actual switch happens in step 5 only if preemption is
        // enabled; if it is not, the request waits for `preempt_enable`.
        s.ticks_this_slice.store(0, Ordering::Relaxed);
        s.need_resched.store(true, Ordering::Relaxed);
    }

    // 5. Switch if the policy allows. `should_preempt` re-reads the
    //    counter and the flag, so a `preempt_disable` that landed between
    //    step 4 and here is honoured (the switch is skipped and the
    //    request waits).
    if should_preempt() {
        scheduler_schedule_next();
    }
}

// ---------------------------------------------------------------------------
// Voluntary yield
// ---------------------------------------------------------------------------

/// Voluntarily yield the current CPU to the scheduler.
///
/// Unlike [`yield_point!`], this yields unconditionally (subject only to the
/// preemption counter — yielding from a preempt-disabled region would
/// re-enter the scheduler while the caller holds a resource, so it is
/// refused). Use it when a kernel path knows it is about to block for a
/// while and wants to donate the remainder of its slice; use
/// [`yield_point!`] for the "am I hogging?" checkpoint in long loops.
///
/// Clearing `need_resched` is the scheduler's job, not ours — see the module
/// docs.
#[inline]
pub fn yield_now() {
    if preempt_disabled() {
        // The caller holds a preempt-disabled region; switching here could
        // re-enter the scheduler with a lock or per-CPU invariant held.
        // Refuse and let the pending reschedule be serviced when the region
        // ends (preempt_enable checks should_preempt at that point).
        return;
    }
    scheduler_schedule_next();
}

/// Cooperative preemption checkpoint for long kernel paths.
///
/// Expands to a cheap [`should_preempt`] test and, only if a reschedule is
/// pending, a call to [`yield_now`]. Sprinkle it through any kernel code
/// path that may run for longer than a time slice without naturally
/// crossing a preemption boundary — bulk copies, long probe loops, ramfs
/// population — to bound the latency a runnable task can suffer.
///
/// The expansion is a block expression (`{{ ... }}`), so it is safe in any
/// position (statement, tail expression, arm body). It does not return a
/// value.
///
/// # Example
///
/// ```ignore
/// for chunk in huge_buffer.chunks(4096) {
///     copy_chunk(chunk, dst);
///     yield_point!();
/// }
/// ```
#[macro_export]
macro_rules! yield_point {
    () => {{
        if $crate::sched::preempt::should_preempt() {
            $crate::sched::preempt::yield_now();
        }
    }};
}

// ---------------------------------------------------------------------------
// Bring-up
// ---------------------------------------------------------------------------

/// Initialise preemption state for the boot CPU.
///
/// Resets the BSP's per-CPU counter and flags to the preemptible default
/// and installs the default slice length. Called by `sched::init` during
/// kernel bring-up, after the per-CPU primitives are online and before the
/// LAPIC timer is armed. Idempotent: a second call just re-zeroes the
/// state, which is harmless.
pub fn init() {
    let s = state();
    s.disable_count.store(0, Ordering::Relaxed);
    s.need_resched.store(false, Ordering::Relaxed);
    s.ticks_this_slice.store(0, Ordering::Relaxed);
    s.total_ticks.store(0, Ordering::Relaxed);
    s.slice_length
        .store(DEFAULT_TIME_SLICE_TICKS, Ordering::Relaxed);
    ::log::info!(
        "xenith.sched.preempt: BSP preemption online (slice = {} ticks, vector {:#04x})",
        DEFAULT_TIME_SLICE_TICKS,
        LAPIC_TIMER_VECTOR,
    );
}

/// Initialise preemption state for an application processor.
///
/// Mirrors [`init`] for an AP being brought up by the SMP phase. The AP's
/// slot is indexed by [`current_cpu`], which must already return the AP's
/// id (i.e. the arch per-CPU area must be published first). A zero
/// `slice_ticks` falls back to [`DEFAULT_TIME_SLICE_TICKS`].
pub fn init_for_ap(slice_ticks: u32) {
    let s = state();
    s.disable_count.store(0, Ordering::Relaxed);
    s.need_resched.store(false, Ordering::Relaxed);
    s.ticks_this_slice.store(0, Ordering::Relaxed);
    s.total_ticks.store(0, Ordering::Relaxed);
    s.slice_length.store(
        if slice_ticks == 0 {
            DEFAULT_TIME_SLICE_TICKS
        } else {
            slice_ticks
        },
        Ordering::Relaxed,
    );
}

// ---------------------------------------------------------------------------
// Scheduler glue — the two call sites that tie this module to the scheduler
// ---------------------------------------------------------------------------

/// Hand a timer tick to the scheduler.
///
/// This is the single point at which the LAPIC tick feeds
/// [`crate::sched::scheduler::tick`]; repoint it if the scheduler exposes
/// its tick entry under a different path. Must be safe to call from the
/// timer IRQ context.
#[inline]
fn scheduler_tick() {
    crate::sched::scheduler::tick();
}

/// Ask the scheduler to perform a context switch now.
///
/// This is the single point at which the preemption path calls
/// [`crate::sched::scheduler::schedule_next`]; repoint it if the scheduler
/// exposes its switch entry under a different path. May be called from the
/// timer IRQ handler (with interrupts off) or from process context
/// (`preempt_enable`, `yield_now`). The scheduler is expected to clear
/// `need_resched` via [`clear_need_resched`] when it performs the switch.
#[inline]
fn scheduler_schedule_next() {
    crate::sched::scheduler::schedule_next();
}

// ---------------------------------------------------------------------------
// Tests (host target — exercise the non-asm, non-scheduler surface)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The per-CPU array must be fully initialised to the preemptible
    /// default at load time. Host tests safely inspect slot 0, so we verify
    /// that slot and trust the
    /// const initialiser for the rest.
    #[test]
    fn state_slot_zero_starts_preemptible() {
        let s = &PREEMPT_STATE[0];
        assert_eq!(s.disable_count.load(Ordering::Relaxed), 0);
        assert!(!s.need_resched.load(Ordering::Relaxed));
        assert_eq!(s.ticks_this_slice.load(Ordering::Relaxed), 0);
        assert_eq!(s.total_ticks.load(Ordering::Relaxed), 0);
        assert_eq!(
            s.slice_length.load(Ordering::Relaxed),
            DEFAULT_TIME_SLICE_TICKS
        );
    }

    #[test]
    fn preempt_disable_enable_balances() {
        // The counter is per-CPU and tests run on the host where
        // host tests have no GS-based CPU setup, so we touch slot 0.
        let s = &PREEMPT_STATE[0];
        // Clear `need_resched` so the `preempt_enable` "preempt on enable"
        // path does not route into `scheduler::schedule_next`, which is not
        // safe to call from a host test harness.
        s.need_resched.store(false, Ordering::Relaxed);
        let before = s.disable_count.load(Ordering::Relaxed);
        preempt_disable();
        assert_eq!(s.disable_count.load(Ordering::Relaxed), before + 1);
        assert!(preempt_disabled());
        preempt_enable();
        assert_eq!(s.disable_count.load(Ordering::Relaxed), before);
        assert!(!preempt_disabled());
    }

    #[test]
    fn with_preempt_disabled_restores_count() {
        let s = &PREEMPT_STATE[0];
        s.need_resched.store(false, Ordering::Relaxed);
        let before = s.disable_count.load(Ordering::Relaxed);
        let out = with_preempt_disabled(|| {
            assert!(preempt_disabled());
            42
        });
        assert_eq!(out, 42);
        assert_eq!(s.disable_count.load(Ordering::Relaxed), before);
    }

    #[test]
    fn nested_disable_requires_nested_enable() {
        let s = &PREEMPT_STATE[0];
        s.need_resched.store(false, Ordering::Relaxed);
        let before = s.disable_count.load(Ordering::Relaxed);
        preempt_disable();
        preempt_disable();
        assert_eq!(s.disable_count.load(Ordering::Relaxed), before + 2);
        preempt_enable();
        assert!(preempt_disabled());
        preempt_enable();
        assert!(!preempt_disabled());
        assert_eq!(s.disable_count.load(Ordering::Relaxed), before);
    }

    #[test]
    fn need_resched_flag_roundtrips() {
        // Use slot 0 directly to avoid touching the scheduler glue.
        let s = &PREEMPT_STATE[0];
        s.need_resched.store(false, Ordering::Relaxed);
        assert!(!need_resched());
        set_need_resched();
        assert!(need_resched());
        clear_need_resched();
        assert!(!need_resched());
    }

    #[test]
    fn should_preempt_requires_both_conditions() {
        let s = &PREEMPT_STATE[0];
        // Preemptible, no reschedule pending -> false.
        s.disable_count.store(0, Ordering::Relaxed);
        s.need_resched.store(false, Ordering::Relaxed);
        assert!(!should_preempt());
        // Reschedule pending but preempt disabled -> false.
        s.disable_count.store(1, Ordering::Relaxed);
        s.need_resched.store(true, Ordering::Relaxed);
        assert!(!should_preempt());
        // Both: preemptible and reschedule pending -> true.
        s.disable_count.store(0, Ordering::Relaxed);
        s.need_resched.store(true, Ordering::Relaxed);
        assert!(should_preempt());
        // Restore.
        s.disable_count.store(0, Ordering::Relaxed);
        s.need_resched.store(false, Ordering::Relaxed);
    }

    #[test]
    fn set_slice_length_rejects_zero() {
        let s = &PREEMPT_STATE[0];
        let saved = s.slice_length.load(Ordering::Relaxed);
        set_slice_length(0);
        assert_eq!(s.slice_length.load(Ordering::Relaxed), saved);
        set_slice_length(7);
        assert_eq!(s.slice_length.load(Ordering::Relaxed), 7);
        // Restore for other tests.
        s.slice_length
            .store(DEFAULT_TIME_SLICE_TICKS, Ordering::Relaxed);
    }

    #[test]
    fn on_context_switch_in_clears_slice_state() {
        let s = &PREEMPT_STATE[0];
        s.ticks_this_slice.store(3, Ordering::Relaxed);
        s.need_resched.store(true, Ordering::Relaxed);
        on_context_switch_in();
        assert_eq!(s.ticks_this_slice.load(Ordering::Relaxed), 0);
        assert!(!s.need_resched.load(Ordering::Relaxed));
    }

    #[test]
    fn timer_vector_matches_interrupt_controller_assignment() {
        assert_eq!(LAPIC_TIMER_VECTOR, 0xFD);
        assert_eq!(
            LAPIC_TIMER_VECTOR,
            crate::arch::x86_64::interrupts::apic::TIMER_VECTOR
        );
    }

    #[test]
    fn default_slice_is_positive_and_small() {
        const {
            assert!(DEFAULT_TIME_SLICE_TICKS > 0);
            assert!(DEFAULT_TIME_SLICE_TICKS < 100);
        }
    }
}
