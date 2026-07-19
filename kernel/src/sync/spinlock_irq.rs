//! IRQ-safe spinlock.
//!
//! [`SpinLockIRQ<T>`] is [`SpinLock`](super::spinlock::SpinLock) augmented to
//! save the interrupt-enable state on acquire and disable interrupts across
//! the critical section. It is the lock to reach for whenever the protected
//! data is touched **both** in process context and in an interrupt handler on
//! the same CPU — the classic Linux `spin_lock_irqsave` use case.
//!
//! # How it works
//!
//! Acquire does, in order:
//!
//! 1. Read RFLAGS (via `pushfq`/`pop`) and execute `cli` to clear the
//!    interrupt-enable flag. The saved RFLAGS remembers whether interrupts
//!    were **on** before we disabled them.
//! 2. Spin on the atomic lock bit exactly like [`SpinLock`] does.
//!
//! The ordering is deliberate: interrupts are disabled **before** the lock is
//! taken. If we did it the other way around, an interrupt could fire after we
//! acquire the lock but before `cli`, and a handler that tried to take the
//! same lock would deadlock against us. With `cli` first, no IRQ handler on
//! this core can run until we explicitly restore the flag.
//!
//! Release does the reverse:
//!
//! 1. Store the lock bit back to `false` with `Release` ordering.
//! 2. Restore RFLAGS via `push`/`popfq`, which re-enables interrupts iff they
//!    were enabled when we acquired.
//!
//! The lock is released **before** interrupts are restored, so any IRQ that
//! fires after RFLAGS is restored finds the lock already free and cannot
//! deadlock against us.
//!
//! # CPU affinity
//!
//! The saved RFLAGS is meaningful only on the CPU that captured it: it
//! describes *that* core's interrupt-enable state at acquire time. A guard
//! must therefore be dropped on the same CPU that created it. The guard is
//! `!Send` to make that a compile-time guarantee; on a single-CPU bring-up
//! kernel this is trivially satisfied, and once SMP lands the scheduler must
//! not migrate a task that holds an IRQ guard.
//!
//! # Arch dependency
//!
//! Standalone critical sections use
//! [`crate::arch::x86_64::InterruptGuard`]. This lock keeps its save/restore
//! sequence local because guard destruction must be deliberately ordered
//! after the lock-bit release: an IRQ restored before unlock could enter a
//! handler and deadlock on this same lock.

#[cfg(not(test))]
use core::arch::asm;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};
use core::{fmt, hint};

/// Bit 9 of RFLAGS is the interrupt-enable flag (IF). Used to test the saved
/// flags without needing a full `popfq` for the common "interrupts were on"
/// case — though we restore via `popfq` anyway so the whole EFLAGS word is
/// preserved, not just IF.
const RFLAGS_IF: u64 = 1 << 9;

/// Snapshot RFLAGS and disable interrupts on this CPU.
///
/// Returns the pre-`cli` RFLAGS so the caller can restore it later with
/// [`restore_rflags`]. Interrupts are guaranteed off when this returns.
///
/// # Safety
///
/// This is safe to call from any ring-0 context. It uses the stack for the
/// `pushfq`/`pop` sequence and modifies RFLAGS (clearing IF), which is the
/// entire point. The caller is responsible for pairing it with a
/// [`restore_rflags`] call to avoid leaving interrupts disabled forever.
#[cfg(not(test))]
fn save_and_disable_interrupts() -> u64 {
    let flags: u64;
    // SAFETY: `pushfq` pushes the 8-byte RFLAGS onto the stack; `pop {r}`
    // pops it into a general register the compiler allocated; `cli` clears
    // IF. We touch the stack (balanced push + pop) and RFLAGS, and no other
    // state. The compiler-chosen register is written before `cli` runs, so
    // the saved value reflects the pre-`cli` IF state — exactly what we need
    // to restore later.
    unsafe {
        asm!(
            "pushfq",
            "pop {0}",
            "cli",
            out(reg) flags,
        );
    }
    flags
}

/// Host tests cannot execute `cli`; model an initially enabled IF while the
/// atomic lock still exercises all mutual-exclusion and guard-drop behavior.
#[cfg(test)]
fn save_and_disable_interrupts() -> u64 {
    RFLAGS_IF
}

/// Restore RFLAGS from a snapshot taken by [`save_and_disable_interrupts`].
///
/// Re-enables interrupts iff they were enabled when the snapshot was taken.
///
/// # Safety
///
/// `flags` must be a value previously produced by
/// [`save_and_disable_interrupts`] **on this CPU**. Restoring an RFLAGS from
/// another CPU, or a stale snapshot taken after the flag has since changed,
/// can leave this core in an interrupt state that does not match the rest of
/// the kernel's expectations. Callers that hold a guard own this invariant.
#[cfg(not(test))]
unsafe fn restore_rflags(flags: u64) {
    // SAFETY: `push {r}` pushes the saved RFLAGS onto the stack; `popfq`
    // pops it back into RFLAGS, restoring the full flag word including IF.
    // The push/pop pair is stack-balanced. The caller guarantees `flags`
    // came from this CPU's `save_and_disable_interrupts`.
    unsafe {
        asm!(
            "push {0}",
            "popfq",
            in(reg) flags,
        );
    }
}

#[cfg(test)]
unsafe fn restore_rflags(_flags: u64) {}

/// An IRQ-safe spinlock protecting a value of type `T`.
///
/// See the [module docs](self) for the acquire/release protocol and the
/// rationale for disabling interrupts before taking the lock bit.
pub struct SpinLockIRQ<T: ?Sized> {
    /// The spin bit, identical in semantics to [`super::spinlock::SpinLock`]'s
    /// `locked` field. We keep a second atomic here rather than embedding a
    /// `SpinLock<T>` so the IRQ-safe variant owns its full invariant and
    /// cannot be accidentally bypassed by reaching for an inner lock.
    locked: AtomicBool,
    /// The protected value, accessed only while `locked` is true and
    /// interrupts are off on this CPU.
    value: UnsafeCell<T>,
}

// `Send` is auto-derived (`UnsafeCell<T>: Send where T: Send`,
// `AtomicBool: Send`). `Sync` is not, because `UnsafeCell` is `!Sync`.
//
// SAFETY: Sharing `&SpinLockIRQ<T>` across threads is sound when
// `T: Send`: the lock hands out `&mut T` exclusively (there is no shared
// read mode), so the access pattern is the same as `std::sync::Mutex`,
// which requires `T: Send` for `Sync` — not `T: Sync`. The guard is
// `!Send`, so the exclusive reference never crosses CPUs while held.
unsafe impl<T: ?Sized + Send> Sync for SpinLockIRQ<T> {}

impl<T> SpinLockIRQ<T> {
    /// Create a new unlocked IRQ-safe spinlock wrapping `value`.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Consume the lock and return the inner value.
    ///
    /// Panics if the lock is held. Like [`super::spinlock::SpinLock::into_inner`]
    /// this is a debug affordance — moving out of a held lock is a bug.
    pub fn into_inner(self) -> T {
        assert!(
            !self.locked.load(Ordering::Relaxed),
            "SpinLockIRQ::into_inner called on a held lock"
        );
        self.value.into_inner()
    }
}

impl<T: ?Sized> SpinLockIRQ<T> {
    /// Acquire the lock and disable interrupts on this CPU.
    ///
    /// Disables interrupts **first**, then spins on the lock bit, so that no
    /// interrupt handler can race with the acquisition. Returns a guard that
    /// restores the interrupt state on drop. See the [module docs](self) for
    /// the full protocol.
    pub fn lock(&self) -> SpinLockIRQGuard<'_, T> {
        // Step 1: snapshot RFLAGS and cli. Interrupts are now off on this core.
        let flags = save_and_disable_interrupts();

        // Step 2: spin to acquire the bit. Because interrupts are off, no IRQ
        // handler on this CPU can interleave and try to take the same lock,
        // so we cannot self-deadlock. Other CPUs may still contend and that
        // is fine — the CAS sorts it out.
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                hint::spin_loop();
            }
        }

        SpinLockIRQGuard {
            lock: self,
            flags,
            _pin: PhantomData,
        }
    }

    /// Try to acquire the lock and disable interrupts, without spinning.
    ///
    /// Disables interrupts, attempts a single CAS, and on failure restores
    /// the interrupt state before returning `None`. Never blocks.
    pub fn try_lock(&self) -> Option<SpinLockIRQGuard<'_, T>> {
        let flags = save_and_disable_interrupts();
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinLockIRQGuard {
                lock: self,
                flags,
                _pin: PhantomData,
            })
        } else {
            // We did not get the lock — undo the cli so we do not leak
            // disabled interrupts into the caller's context.
            // SAFETY: `flags` was captured on this CPU a few instructions
            // ago and is the correct RFLAGS to restore.
            unsafe { restore_rflags(flags) };
            None
        }
    }

    /// Returns `true` if the lock bit is currently held.
    ///
    /// Like [`super::spinlock::SpinLock::is_locked`] this is a relaxed
    /// observation only and is not a synchronization primitive.
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for SpinLockIRQ<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpinLockIRQ")
            .field("locked", &self.is_locked())
            .finish_non_exhaustive()
    }
}

/// RAII guard for a held [`SpinLockIRQ`].
///
/// Dropping the guard releases the lock bit and restores the interrupt-enable
/// state to what it was when the guard was created. The guard is `!Send` and
/// `!Sync`: it must be dropped on the same CPU that acquired it, because the
/// saved RFLAGS describes *that* core's pre-acquire interrupt state. The
/// `PhantomData<*mut ()>` marker opts out of both auto traits without
/// requiring the unstable `negative_impls` feature.
pub struct SpinLockIRQGuard<'a, T: ?Sized + 'a> {
    lock: &'a SpinLockIRQ<T>,
    /// The RFLAGS captured at acquire time. Restored verbatim on drop so the
    /// full flag word — not just IF — is preserved across the critical
    /// section.
    flags: u64,
    /// Marker that pins the guard to the CPU that created it. `*mut ()` is
    /// `!Send` and `!Sync`, so the guard inherits both opt-outs automatically.
    _pin: PhantomData<*mut ()>,
}

impl<'a, T: ?Sized + 'a> Drop for SpinLockIRQGuard<'a, T> {
    fn drop(&mut self) {
        // Release the lock first, then restore interrupts. If we restored
        // interrupts first, an IRQ could fire before the lock bit was cleared
        // and a handler taking the same lock would deadlock against our
        // still-held bit. Releasing first means any post-restore interrupt
        // finds the lock free.
        self.lock.locked.store(false, Ordering::Release);
        // SAFETY: `self.flags` was captured on this CPU by the `lock` or
        // `try_lock` call that created this guard, and this `Drop` runs on
        // the same CPU (the guard is `!Send`). Restoring it returns RFLAGS
        // to its pre-acquire state.
        unsafe { restore_rflags(self.flags) };
    }
}

impl<'a, T: ?Sized + 'a> Deref for SpinLockIRQGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: We hold the lock bit and interrupts are disabled on this
        // CPU, so no interrupt handler can reach the cell and no other
        // thread can have acquired the bit. Exclusive access is guaranteed.
        unsafe { &*self.lock.value.get() }
    }
}

impl<'a, T: ?Sized + 'a> DerefMut for SpinLockIRQGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: Same invariant as `deref`; `&mut self` makes us the unique
        // holder of the guard and thus of the inner value.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<'a, T: ?Sized + fmt::Debug + 'a> fmt::Debug for SpinLockIRQGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpinLockIRQGuard")
            .field("flags_if", &(self.flags & RFLAGS_IF != 0))
            .field("value", &&**self)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_roundtrip_preserves_inner() {
        let lock = SpinLockIRQ::new(7u32);
        {
            let mut g = lock.lock();
            *g += 5;
        }
        // After the guard drops the lock must be free again.
        assert!(!lock.is_locked());
        assert_eq!(lock.into_inner(), 12);
    }

    #[test]
    fn try_lock_then_fail() {
        let lock = SpinLockIRQ::new(());
        let g = lock.try_lock();
        assert!(g.is_some());
        // Held — a second try must fail and, crucially, must not leave
        // interrupts disabled after the failed attempt.
        assert!(lock.try_lock().is_none());
        drop(g);
    }
}
