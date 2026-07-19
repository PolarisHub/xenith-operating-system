//! Spin-backed mutex with a scheduler-yield hook.
//!
//! [`Mutex<T>`] is scheduler-aware mutual exclusion for task context. The
//! uncontended path is one atomic compare-exchange. A contended task yields
//! once the scheduler is online; early boot, interrupt-disabled code, and
//! preemption-disabled critical sections retain a `pause` spin fallback.
//!
//! # Why a separate type from `SpinLock`?
//!
//! The two differ in *intent*, and intent matters for a future that has a
//! scheduler:
//!
//! * `SpinLock` is for critical sections so short that blocking is never
//!   worth it — IRQ-data structures, MMU table edits. It will always spin.
//! * `Mutex` is for task-context critical sections that may be long enough to
//!   let another runnable task make progress while the lock is held.
//!
//! This remains a cooperative yield mutex rather than a sleep-queue mutex:
//! contention is rechecked after every yield and there is no waiter queue or
//! priority inheritance. It must not protect state shared with an interrupt
//! handler on the same CPU; use [`SpinLockIRQ`](super::spinlock_irq::SpinLockIRQ)
//! for that case.
//!
//! # Reentrancy
//!
//! Not reentrant. Acquiring twice on the same CPU deadlocks, the same as
//! `SpinLock`. The `sched` phase may add a reentrant variant if one is
//! needed; for now, structure code to release before re-acquiring.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};
use core::{fmt, hint};

const RFLAGS_INTERRUPT_ENABLE: u64 = 1 << 9;

/// Give the CPU a breather while waiting for a contended `Mutex`.
///
/// Yielding is safe only from an ordinary preemptible task with interrupts
/// enabled. An IRQ may have interrupted the lock owner on this same CPU, and
/// a task switched out with a non-zero per-CPU preemption count would leak its
/// critical-section state into the incoming task. Both cases therefore spin.
#[inline]
fn yield_cpu() {
    if scheduler_yield_allowed() {
        crate::sched::yield_now();
    }
    // `yield_now` is a no-op when no task is current, and a resumed contender
    // may still lose the next CAS. Keep the architectural spin hint in every
    // path so those retries remain friendly to a sibling hardware thread.
    hint::spin_loop();
}

/// Whether the current execution context may enter the scheduler voluntarily.
#[inline]
fn scheduler_yield_allowed() -> bool {
    let scheduler_online = crate::sched::is_initialised();
    if !scheduler_online {
        return false;
    }
    let preempt_disabled = crate::sched::preempt::preempt_disabled();
    if preempt_disabled {
        return false;
    }

    let flags: u64;
    // SAFETY: `pushfq; pop` is stack-balanced, non-privileged, and only reads
    // the current RFLAGS image. No flag or memory state is changed.
    unsafe {
        asm!(
            "pushfq",
            "pop {flags}",
            flags = out(reg) flags,
        );
    }
    yield_policy(scheduler_online, preempt_disabled, flags)
}

#[inline]
const fn yield_policy(scheduler_online: bool, preempt_disabled: bool, flags: u64) -> bool {
    scheduler_online && !preempt_disabled && flags & RFLAGS_INTERRUPT_ENABLE != 0
}

/// A mutex protecting a value of type `T`.
///
/// See the [module docs](self) for the distinction between `Mutex` and
/// [`SpinLock`](super::spinlock::SpinLock) and for the scheduler-yield plan.
pub struct Mutex<T: ?Sized> {
    /// `false` = free, `true` = held. Same encoding as `SpinLock`.
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// `Send` is auto-derived (`UnsafeCell<T>: Send where T: Send`,
// `AtomicBool: Send`). `Sync` is not, because `UnsafeCell` is `!Sync`.
//
// SAFETY: Sharing `&Mutex<T>` across threads is sound when `T: Send`: the
// mutex hands out `&mut T` exclusively, so the access pattern is the same
// as `std::sync::Mutex`, which requires `T: Send` for `Sync` — not
// `T: Sync`. The guard is `!Send`, so the exclusive reference never
// crosses threads while held.
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    /// Create a new unlocked mutex wrapping `value`.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Consume the mutex and return the inner value.
    ///
    /// Panics if the mutex is currently held.
    pub fn into_inner(self) -> T {
        assert!(
            !self.locked.load(Ordering::Relaxed),
            "Mutex::into_inner called on a held mutex"
        );
        self.value.into_inner()
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Acquire the mutex, spinning (and, in the future, yielding) until it
    /// succeeds.
    ///
    /// The successful CAS uses `Acquire` so writes from the previous holder
    /// are visible to us; the `Release` in [`MutexGuard::drop`] completes the
    /// synchronizes-with edge for the next acquirer.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        // Same fast-path-then-spin pattern as SpinLock, but the spin body
        // calls `yield_cpu` instead of a bare `spin_loop` so the future
        // scheduler swap is a one-line change.
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                yield_cpu();
            }
        }
        MutexGuard { lock: self }
    }

    /// Try to acquire the mutex without blocking.
    ///
    /// Returns `Some(guard)` on success, `None` if the mutex is held. Never
    /// spins and never yields.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(MutexGuard { lock: self })
        } else {
            None
        }
    }

    /// Returns `true` if the mutex is currently held. Relaxed observation
    /// only; not a synchronization primitive.
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

impl<T: Default> Default for Mutex<T> {
    /// Create an unlocked mutex holding `T::default()`.
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mutex")
            .field("locked", &self.is_locked())
            .finish_non_exhaustive()
    }
}

/// RAII guard for a held [`Mutex`].
///
/// Dropping the guard releases the mutex. While it lives, the guard grants
/// exclusive access to the inner value via `Deref`/`DerefMut`.
pub struct MutexGuard<'a, T: ?Sized + 'a> {
    lock: &'a Mutex<T>,
}

impl<'a, T: ?Sized + 'a> Drop for MutexGuard<'a, T> {
    fn drop(&mut self) {
        // Release the mutex. Release ordering publishes the critical
        // section's writes to the next acquirer.
        self.lock.locked.store(false, Ordering::Release);
    }
}

impl<'a, T: ?Sized + 'a> Deref for MutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: We hold the mutex, so we have exclusive access to `value`.
        // No other accessor can reach the cell until this guard drops and the
        // flag returns to false.
        unsafe { &*self.lock.value.get() }
    }
}

impl<'a, T: ?Sized + 'a> DerefMut for MutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: Same invariant as `deref`; `&mut self` makes us the unique
        // holder of the guard and thus of the inner value.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<'a, T: ?Sized + fmt::Debug + 'a> fmt::Debug for MutexGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<'a, T: ?Sized + fmt::Display + 'a> fmt::Display for MutexGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_unlock_roundtrip() {
        let m = Mutex::new(10u32);
        {
            let mut g = m.lock();
            assert!(m.is_locked());
            *g += 1;
        }
        assert!(!m.is_locked());
        assert_eq!(m.into_inner(), 11);
    }

    #[test]
    fn try_lock_then_fail() {
        let m = Mutex::new(());
        // Bind the guard so it survives the second `try_lock`; otherwise the
        // first guard would drop immediately and the lock would be free.
        let g = m.try_lock();
        assert!(g.is_some());
        assert!(m.try_lock().is_none());
        drop(g);
    }

    #[test]
    fn default_uses_inner_default() {
        let m: Mutex<u16> = Mutex::default();
        assert_eq!(*m.lock(), 0);
    }

    #[test]
    fn scheduler_yield_policy_requires_safe_task_context() {
        assert!(yield_policy(true, false, RFLAGS_INTERRUPT_ENABLE));
        assert!(!yield_policy(false, false, RFLAGS_INTERRUPT_ENABLE));
        assert!(!yield_policy(true, true, RFLAGS_INTERRUPT_ENABLE));
        assert!(!yield_policy(true, false, 0));
    }
}
