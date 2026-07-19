//! Test-and-set spinlock with a `spin_loop` hint.
//!
//! [`SpinLock<T>`] is the lowest-level mutual-exclusion primitive in Xenith:
//! a single atomic bit is CAS'd from "free" to "held" and the caller spins
//! until it wins the CAS. While spinning the lock uses [`core::hint::spin_loop`]
//! (which emits a `pause` on x86_64) so the core does not hammer the cache
//! coherence protocol or waste memory bandwidth on a tight read loop.
//!
//! # When to use this vs. the other primitives
//!
//! * Use [`SpinLock`](crate::sync::SpinLock) for short, non-IRQ critical
//!   sections where you do **not** need to block interrupts. It is the
//!   cheapest lock and the right default for data-only critical sections.
//! * Use [`SpinLockIRQ`](crate::sync::SpinLockIRQ) when the critical section
//!   can be entered from an interrupt handler — that variant saves RFLAGS and
//!   disables interrupts across the section so the handler cannot re-enter
//!   the lock and deadlock.
//! * Use [`Mutex`](crate::sync::Mutex) when a real scheduler is available and
//!   the critical section may be long; it is currently spin-backed but will
//!   yield to the scheduler once one exists.
//!
//! # Fairness
//!
//! This is a simple test-and-set lock with no ticket queue. It is **not
//! fair**: under contention a thread that happened to observe the lock free
//! wins, regardless of how long others have waited. This is acceptable for
//! the short critical sections the kernel uses it for; a ticket or MCS lock
//! can be dropped in later without changing the public surface.
//!
//! # Reentrancy
//!
//! The lock is **not reentrant**. Acquiring it twice on the same CPU without
//! releasing will deadlock. If you need reentrant semantics, structure the
//! code to release before re-acquiring or use a separate lock for the inner
//! section.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};
use core::{fmt, hint};

/// A test-and-set spinlock protecting a value of type `T`.
///
/// The lock is a single [`AtomicBool`] flag: `false` = free, `true` = held.
/// [`SpinLock::lock`] performs a compare-exchange loop to flip the flag and
/// returns a [`SpinLockGuard`] that releases the flag on drop. See the
/// [module docs](self) for when to pick this over the IRQ-aware or
/// scheduler-aware variants.
pub struct SpinLock<T: ?Sized> {
    /// `false` while the lock is free, `true` while it is held.
    ///
    /// We use `Acquire` on lock and `Release` on unlock so writes performed
    /// inside the critical section are visible to the next acquirer and are
    /// not reordered before the CAS. See the ordering discussion below.
    locked: AtomicBool,
    /// The protected value. Access is gated entirely by `locked`; the
    /// `UnsafeCell` is the standard Rust device for asserting "interior
    /// mutability with a manual synchronization invariant" to the compiler.
    value: UnsafeCell<T>,
}

// `Send` is auto-derived: `UnsafeCell<T>: Send where T: Send` and
// `AtomicBool: Send`, so `SpinLock<T>` is `Send` when `T: Send` without a
// manual impl. We only need to spell out `Sync`, which the auto trait
// refuses because `UnsafeCell` is `!Sync`.
//
// SAFETY: Sharing `&SpinLock<T>` across threads is sound when `T: Send`:
// concurrent callers race for the lock bit, and exactly one winner at a
// time gets `&mut T`. We do not need `T: Sync` because no shared `&T` is
// ever handed out without the lock being held (which is exclusive).
unsafe impl<T: ?Sized + Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Create a new unlocked spinlock wrapping `value`.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Consume the lock and return the inner value.
    ///
    /// Panics if the lock is currently held. This is a debug affordance —
    /// consuming a held lock would be a use-after-free in the making and
    /// must never happen, so we fail loudly rather than silently leak.
    pub fn into_inner(self) -> T {
        // The assert is a plain `load` and does not synchronize with any
        // prior release, but that is fine: if the value is true someone is
        // inside the critical section and `self` should not be moving anyway.
        assert!(
            !self.locked.load(Ordering::Relaxed),
            "SpinLock::into_inner called on a held lock"
        );
        self.value.into_inner()
    }
}

impl<T: ?Sized> SpinLock<T> {
    /// Acquire the lock, spinning until the CAS succeeds.
    ///
    /// This is a blocking call in the sense that it does not return until it
    /// owns the lock; it never yields to a scheduler. Each spin iteration
    /// emits a `pause` hint via [`core::hint::spin_loop`] to reduce power
    /// consumption and cache-coherence traffic while waiting.
    ///
    /// # Ordering
    ///
    /// The successful CAS uses `Acquire` on the load half so all writes from
    /// the previous holder's critical section are visible to us before we
    /// touch `value`. The store half uses `Relaxed` because we do not need
    /// to publish anything on the successful path — the `Acquire` of the
    /// next acquirer is what synchronizes with our later `Release` in
    /// [`SpinLockGuard::drop`].
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        // First do a cheap relaxed load. If the lock is already free we skip
        // the expensive CAS entirely — this is the uncontended fast path and
        // is the common case for short critical sections.
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Wait for the lock to look free before retrying the CAS. Spinning
            // on a CAS directly would pour retry traffic onto the inter-core
            // bus on every iteration; reading first means each core only CASes
            // once per observed release.
            while self.locked.load(Ordering::Relaxed) {
                hint::spin_loop();
            }
        }

        SpinLockGuard { lock: self }
    }

    /// Try to acquire the lock without spinning.
    ///
    /// Returns `Some(guard)` if the lock was free and is now held, or `None`
    /// if it was already held by another caller. Never blocks.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        // Single CAS, same ordering rationale as `lock`. On failure we do not
        // spin — the caller decides whether to retry, back off, or give up.
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinLockGuard { lock: self })
        } else {
            None
        }
    }

    /// Returns `true` if the lock is currently held.
    ///
    /// This is a *relaxed* observation only: the lock can be acquired or
    /// released immediately after this returns. It is useful for assertions
    /// and diagnostics, never for synchronization.
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

impl<T: Default> Default for SpinLock<T> {
    /// Create an unlocked spinlock holding `T::default()`.
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for SpinLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let held = self.is_locked();
        // Avoid recursing into a held lock's value: a Debug impl that tries
        // to lock() would deadlock if the caller already holds the lock, and
        // would race with the holder if they do not. Show the held/free state
        // only, matching the upstream `spin` crate's behaviour.
        f.debug_struct("SpinLock")
            .field("locked", &held)
            .finish_non_exhaustive()
    }
}

/// RAII guard for a held [`SpinLock`].
///
/// Dropping the guard releases the lock. While it lives, the guard grants
/// exclusive access to the inner value via `Deref` / `DerefMut`.
pub struct SpinLockGuard<'a, T: ?Sized + 'a> {
    lock: &'a SpinLock<T>,
}

impl<'a, T: ?Sized + 'a> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        // Release the lock. `Release` ordering ensures every write performed
        // inside the critical section is visible to the next acquirer before
        // the flag flips back to `false`; the next acquirer's `Acquire` CAS
        // forms the synchronizes-with edge.
        self.lock.locked.store(false, Ordering::Release);
    }
}

impl<'a, T: ?Sized + 'a> Deref for SpinLockGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: We hold the lock, so we have exclusive access to `value`.
        // No other code can reach the cell while the guard exists, because
        // the only other accessors (`lock`, `try_lock`) cannot succeed until
        // this guard drops and the flag returns to `false`.
        unsafe { &*self.lock.value.get() }
    }
}

impl<'a, T: ?Sized + 'a> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: Same invariant as `deref`, plus `&mut self` ensures we are
        // the unique holder of the guard and therefore of the inner value.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<'a, T: ?Sized + fmt::Debug + 'a> fmt::Debug for SpinLockGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // We hold the lock, so reading the inner value is safe and cannot
        // race. Delegating to the inner Debug impl is the expected behaviour
        // for an RAII guard.
        fmt::Debug::fmt(&**self, f)
    }
}

impl<'a, T: ?Sized + fmt::Display + 'a> fmt::Display for SpinLockGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_unlock_roundtrip() {
        let lock = SpinLock::new(42u32);
        assert!(!lock.is_locked());
        {
            let mut g = lock.lock();
            assert!(lock.is_locked());
            *g += 1;
        }
        assert!(!lock.is_locked());
        assert_eq!(lock.into_inner(), 43);
    }

    #[test]
    fn try_lock_succeeds_when_free() {
        let lock = SpinLock::new(());
        // Bind the guard so it stays alive across the second `try_lock`.
        // If we wrote `lock.try_lock().is_some()` the guard would drop at the
        // end of that statement and the lock would be free again.
        let g = lock.try_lock();
        assert!(g.is_some());
        // Held now — a second try must fail without spinning.
        assert!(lock.try_lock().is_none());
        drop(g);
    }

    #[test]
    fn default_uses_inner_default() {
        let lock: SpinLock<u8> = SpinLock::default();
        let g = lock.lock();
        assert_eq!(*g, 0);
    }
}
