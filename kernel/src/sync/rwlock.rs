//! Reader-preferred reader-writer lock.
//!
//! [`RwLock<T>`] allows any number of concurrent readers **or** a single
//! exclusive writer, but not both at once. This implementation is
//! **reader-preferred**: as long as readers keep arriving, a waiting writer
//! does not get to run. That is the right trade-off for read-heavy kernel
//! data structures (e.g. the live module list, device tables) where readers
//! are common and write critical sections are short and rare. A fair/queued
//! rwlock can replace this one later without changing the public surface.
//!
//! # State encoding
//!
//! The entire lock state lives in one [`AtomicU64`]:
//!
//! ```text
//!   bit 63        : writer-held flag (1 << 63)
//!   bits 0..=62   : active reader count
//! ```
//!
//! * `0`                      → unlocked.
//! * `WRITER_BIT`             → held by a writer.
//! * `1..` (no writer bit)    → held by N readers.
//!
//! Using a single atomic for both the writer flag and the reader count means
//! acquire and release are each one atomic op, so there is no window where
//! the writer flag and reader count can disagree.
//!
//! # Ordering
//!
//! * Reader acquire uses `Acquire` on the successful CAS so writes from a
//!   prior writer's critical section are visible.
//! * Reader release uses `Release` on the decrement so the next writer's
//!   `Acquire` sees the readers' reads completed.
//! * Writer acquire uses `Acquire`; writer release uses `Release`. Same
//!   reasoning, mirrored.
//!
//! # Reentrancy
//!
//! Not reentrant. A task that already holds a read lock and calls `read()`
//! again may deadlock if a writer is waiting between the two calls (the
//! classic reader-writer reentrancy hazard). Callers must structure code to
//! release before re-acquiring.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};
use core::{fmt, hint};

/// The writer-held bit, occupying the top of the 64-bit state word so the
/// reader count can use the entire low 63 bits without ever colliding.
const WRITER_BIT: u64 = 1u64 << 63;

/// A reader-writer lock protecting a value of type `T`.
///
/// See the [module docs](self) for the state encoding and the
/// reader-preferred fairness policy.
pub struct RwLock<T: ?Sized> {
    /// Packed writer bit + reader count, as described in the module docs.
    state: AtomicU64,
    /// The protected value. Access is gated by `state`: shared via a read
    /// guard when only reader bits are set, exclusive via a write guard when
    /// the writer bit is set.
    value: UnsafeCell<T>,
}

// `Send` is auto-derived (`UnsafeCell<T>: Send where T: Send`,
// `AtomicU64: Send`). `Sync` is not, because `UnsafeCell` is `!Sync`.
//
// SAFETY: Sharing `&RwLock<T>` across threads is sound when `T: Send +
// Sync`: a write guard hands out `&mut T` exclusively (needs `T: Send` for
// the holder thread to be allowed to mutate), and a read guard hands out
// shared `&T` which may be observed by multiple reader threads at once
// (needs `T: Sync`).
unsafe impl<T: ?Sized + Send + Sync> Sync for RwLock<T> {}

impl<T> RwLock<T> {
    /// Create a new unlocked rwlock wrapping `value`.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicU64::new(0),
            value: UnsafeCell::new(value),
        }
    }

    /// Consume the lock and return the inner value.
    ///
    /// Panics if the lock is currently held in either mode.
    pub fn into_inner(self) -> T {
        let s = self.state.load(Ordering::Relaxed);
        assert!(
            s == 0,
            "RwLock::into_inner called on a held lock (state={s:#x})"
        );
        self.value.into_inner()
    }
}

impl<T: ?Sized> RwLock<T> {
    /// Acquire a shared read lock, spinning until it succeeds.
    ///
    /// Blocks (by spinning) only if a writer currently holds the lock. While
    /// readers are active, additional readers are admitted without waiting —
    /// that is the reader-preferred policy.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            let cur = self.state.load(Ordering::Relaxed);
            // A writer holds the lock: spin until it releases. We use a
            // relaxed load here and retry the CAS below; the CAS is what
            // provides the Acquire edge.
            if cur & WRITER_BIT != 0 {
                while self.state.load(Ordering::Relaxed) & WRITER_BIT != 0 {
                    hint::spin_loop();
                }
                continue;
            }
            // No writer: try to bump the reader count. The CAS must preserve
            // the (clear) writer bit and only add 1 to the reader count. We
            // use `Acquire` so a prior writer's writes are visible to us.
            match self
                .state
                .compare_exchange(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return RwLockReadGuard { lock: self },
                // Someone changed the state (a reader left or a writer
                // arrived) between our load and our CAS — reload and retry.
                Err(_) => hint::spin_loop(),
            }
        }
    }

    /// Try to acquire a read lock without spinning.
    ///
    /// Returns `Some(guard)` if a reader can be admitted immediately, or
    /// `None` if a writer holds the lock. Never blocks.
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        let cur = self.state.load(Ordering::Relaxed);
        if cur & WRITER_BIT != 0 {
            return None;
        }
        if self
            .state
            .compare_exchange(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(RwLockReadGuard { lock: self })
        } else {
            None
        }
    }

    /// Acquire an exclusive write lock, spinning until it succeeds.
    ///
    /// Blocks (by spinning) while any readers are active or another writer
    /// holds the lock. Because the lock is reader-preferred, a steady stream
    /// of readers can delay a writer indefinitely; callers that need
    /// bounded write latency should use a different primitive.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        loop {
            let cur = self.state.load(Ordering::Relaxed);
            // The lock is free only when the whole word is zero: no writer
            // bit and no readers. Anything else means we must wait.
            if cur != 0 {
                while self.state.load(Ordering::Relaxed) != 0 {
                    hint::spin_loop();
                }
                continue;
            }
            // Atomically plant the writer bit. Acquire so prior readers'/
            // writers' accesses are visible to us.
            match self.state.compare_exchange(
                cur,
                cur | WRITER_BIT,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return RwLockWriteGuard { lock: self },
                // State changed under us — reload and retry.
                Err(_) => hint::spin_loop(),
            }
        }
    }

    /// Try to acquire a write lock without spinning.
    ///
    /// Returns `Some(guard)` if the lock is completely free, else `None`.
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        let cur = self.state.load(Ordering::Relaxed);
        if cur != 0 {
            return None;
        }
        if self
            .state
            .compare_exchange(cur, cur | WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(RwLockWriteGuard { lock: self })
        } else {
            None
        }
    }

    /// Returns a snapshot of the lock state for diagnostics.
    ///
    /// The returned tuple is `(writer_held, reader_count)`. This is a relaxed
    /// observation and can change immediately after it is taken; it is useful
    /// for `Debug` output and assertions only.
    pub fn debug_state(&self) -> (bool, u64) {
        let s = self.state.load(Ordering::Relaxed);
        (s & WRITER_BIT != 0, s & !WRITER_BIT)
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for RwLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (writer, readers) = self.debug_state();
        f.debug_struct("RwLock")
            .field("writer_held", &writer)
            .field("readers", &readers)
            .finish_non_exhaustive()
    }
}

/// RAII guard for a shared read lock.
///
/// Dropping the guard releases the read lock (decrements the reader count).
/// While it lives, the guard grants shared `&T` access via `Deref`.
pub struct RwLockReadGuard<'a, T: ?Sized + 'a> {
    lock: &'a RwLock<T>,
}

impl<'a, T: ?Sized + 'a> Drop for RwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        // Decrement the reader count. Release ordering ensures our reads
        // inside the critical section are visible to a writer that next
        // acquires the lock via an Acquire CAS on the zero state.
        // We subtract 1 from the reader-count portion only; the writer bit
        // is never set while readers exist, so a plain `fetch_sub(1)` is
        // correct and cannot accidentally clear the writer bit.
        self.lock.state.fetch_sub(1, Ordering::Release);
    }
}

impl<'a, T: ?Sized + 'a> core::ops::Deref for RwLockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: We hold one of possibly many read locks. All holders have
        // shared access; no writer can be present because write acquire
        // requires the state to be exactly zero. The UnsafeCell is therefore
        // safely shared among the active readers.
        unsafe { &*self.lock.value.get() }
    }
}

impl<'a, T: ?Sized + fmt::Debug + 'a> fmt::Debug for RwLockReadGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<'a, T: ?Sized + fmt::Display + 'a> fmt::Display for RwLockReadGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

/// RAII guard for an exclusive write lock.
///
/// Dropping the guard releases the write lock (clears the writer bit). While
/// it lives, the guard grants exclusive `&mut T` access via `Deref`/`DerefMut`.
pub struct RwLockWriteGuard<'a, T: ?Sized + 'a> {
    lock: &'a RwLock<T>,
}

impl<'a, T: ?Sized + 'a> Drop for RwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        // Clear the entire state: the writer bit is the only thing set while
        // we hold the write lock (readers are excluded), so storing 0 is
        // correct. Release ordering publishes our writes to the next
        // acquirer, which will observe them via its Acquire CAS/load.
        self.lock.state.store(0, Ordering::Release);
    }
}

impl<'a, T: ?Sized + 'a> core::ops::Deref for RwLockWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: We hold the exclusive write lock, so we are the only
        // accessor. No reader or other writer can reach the cell while the
        // writer bit is set.
        unsafe { &*self.lock.value.get() }
    }
}

impl<'a, T: ?Sized + 'a> core::ops::DerefMut for RwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: Same invariant as `deref`; `&mut self` makes us the unique
        // holder of the guard and therefore of the inner value.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<'a, T: ?Sized + fmt::Debug + 'a> fmt::Debug for RwLockWriteGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<'a, T: ?Sized + fmt::Display + 'a> fmt::Display for RwLockWriteGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_lock_shared() {
        let lock = RwLock::new(100u32);
        let a = lock.read();
        let b = lock.read();
        assert_eq!(*a, 100);
        assert_eq!(*b, 100);
        let (_, readers) = lock.debug_state();
        assert_eq!(readers, 2);
        drop(a);
        drop(b);
        assert_eq!(lock.debug_state(), (false, 0));
    }

    #[test]
    fn write_lock_exclusive() {
        let lock = RwLock::new(0u32);
        {
            let mut g = lock.write();
            *g = 55;
        }
        let r = lock.read();
        assert_eq!(*r, 55);
    }

    #[test]
    fn try_write_fails_with_reader() {
        let lock = RwLock::new(());
        let _r = lock.read();
        assert!(lock.try_write().is_none());
    }

    #[test]
    fn try_read_fails_with_writer() {
        let lock = RwLock::new(());
        let _w = lock.write();
        assert!(lock.try_read().is_none());
    }

    #[test]
    fn into_inner_when_unlocked() {
        let lock = RwLock::new(42u32);
        assert_eq!(lock.into_inner(), 42);
    }
}
