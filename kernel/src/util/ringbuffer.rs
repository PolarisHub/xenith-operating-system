//! Single-producer, single-consumer bounded ring buffer.
//!
//! [`RingBuffer<T, N>`] is a fixed-capacity FIFO queue backed by an inline
//! array of `MaybeUninit<T>` — no allocator required. It exists for the kernel
//! channels that move data between two cooperating contexts before the heap
//! is up, and for the lightweight per-CPU event/log queues that never want to
//! touch `alloc`:
//!
//! * the early boot log ring that buffers lines until the console is ready;
//! * the keyboard input path (IRQ producer, userspace consumer);
//! * per-CPU work queues whose capacity is a compile-time constant.
//!
//! # The SPSC contract
//!
//! `RingBuffer` is correct under a **single-producer, single-consumer**
//! discipline: exactly one call site pushes, exactly one call site pops, and
//! the two never alias the same logical slot. The implementation is
//! non-atomic: `head` and `tail` are plain `usize` indices. This is safe
//! because:
//!
//! 1. Only the producer ever writes `head` (in [`push`](Self::push)) and only
//!    the consumer ever writes `tail` (in [`pop`](Self::pop)).
//! 2. The producer reads `tail` only to test fullness; the consumer reads
//!    `head` only to test emptiness. A stale read simply reports "not yet
//!    full"/"not yet empty", which is the correct conservative answer under
//!    SPSC.
//!
//! For a queue that crosses CPU cores or an IRQ/main boundary on real
//! hardware, the producer and consumer still see consistent values *in
//! practice* on x86 because of TSO, but a portable caller that wants to share
//! a `RingBuffer` across contexts should wrap it in a [`crate::sync`] lock or
//! wait for the future atomic SPSC variant. The type is deliberately simple
//! and correct; the memory-ordering story is the caller's responsibility, as
//! it is for every other lock-free structure in a kernel.
//!
//! # Capacity
//!
//! The const generic `N` is the **usable slot count**, not a rounded-up
//! power of two. A `RingBuffer<T, 8>` holds exactly eight items. The
//! implementation uses a full/empty flag rather than the classic "waste one
//! slot" trick so `N` slots means `N` items.
//!
//! # Drop
//!
//! Items remaining in the buffer when it is dropped are dropped in push order.
//! Because the backing array is `MaybeUninit`, the destructor must walk the
//! live slots only — dropping an uninitialised slot would be unsound.

use core::mem::MaybeUninit;

/// A bounded, single-producer/single-consumer ring buffer of `T` with a
/// compile-time capacity of `N` slots.
///
/// See the [module documentation](crate::util::ringbuffer) for the SPSC
/// contract and the memory-ordering caveats.
#[derive(Debug)]
pub struct RingBuffer<T, const N: usize> {
    /// Inline backing storage. Slots are `MaybeUninit` because the buffer is
    /// reused: a slot is initialised on `push` and deinitialised on `pop`.
    /// At any instant, slots in `[tail, head)` (mod N) hold live `T`s.
    buf: [MaybeUninit<T>; N],
    /// Index of the next slot to write. Owned by the producer.
    head: usize,
    /// Index of the next slot to read. Owned by the consumer.
    tail: usize,
    /// Number of items currently in the buffer. Tracked explicitly so that
    /// `head == tail` is unambiguous (it is both the empty and the full
    /// condition under the "waste a slot" scheme, which we avoid here).
    len: usize,
}

impl<T, const N: usize> RingBuffer<T, N> {
    /// Compile a `const`-constructible empty ring buffer.
    ///
    /// The backing array is left uninitialised; `len` is zero so no slot is
    /// considered live until the first `push`.
    ///
    /// # Panics
    ///
    /// Panics at const-evaluation time if `N == 0` — a zero-capacity ring
    /// buffer cannot accept any item and has no legitimate use. The panic is
    /// a const-evaluable assertion, so it fires at the call site for `static`
    /// declarations.
    #[inline]
    pub const fn new() -> Self {
        assert!(N > 0, "RingBuffer: capacity must be non-zero");
        RingBuffer {
            // SAFETY: `MaybeUninit::<T>::uninit()` is always sound to call, and
            // an array of `[MaybeUninit<T>; N]` can be built from a repeating
            // expression in const context. The slots are uninitialised, which
            // is the correct state for an empty buffer.
            buf: [const { MaybeUninit::uninit() }; N],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    /// Usable capacity in items. Always `N`.
    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Number of items currently buffered.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// `true` if no items are buffered.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `true` if the buffer is at capacity and a subsequent [`push`](Self::push)
    /// would fail.
    #[inline]
    pub const fn is_full(&self) -> bool {
        self.len == N
    }

    /// Append `item` to the tail of the queue.
    ///
    /// Returns `Ok(())` on success or `Err(item)` if the buffer is full, so
    /// the caller does not lose ownership of the value on rejection. Under the
    /// SPSC contract only the producer calls this.
    #[inline]
    pub fn push(&mut self, item: T) -> Result<(), T> {
        if self.len == N {
            return Err(item);
        }
        // SAFETY: `head` is always in `0..N` because we take `% N` on write,
        // and the slot at `head` is currently uninitialised (it is either
        // fresh or was deinitialised by a prior `pop`). Writing through it
        // initialises the slot without reading or dropping the previous
        // contents, which is the MaybeUninit contract.
        let slot = self.head;
        unsafe {
            self.buf[slot].as_mut_ptr().write(item);
        }
        self.head = (self.head + 1) % N;
        self.len += 1;
        Ok(())
    }

    /// Remove and return the oldest item from the head of the queue.
    ///
    /// Returns `None` if the buffer is empty. Under the SPSC contract only the
    /// consumer calls this.
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        // SAFETY: `tail` is always in `0..N` and the slot at `tail` currently
        // holds a live `T` (it was initialised by a prior `push` and not yet
        // read out). `read` moves the value out, leaving the slot
        // uninitialised again — which is exactly the state `push` expects next
        // time it wraps around to this index.
        let slot = self.tail;
        let item = unsafe { self.buf[slot].as_ptr().read() };
        self.tail = (self.tail + 1) % N;
        self.len -= 1;
        Some(item)
    }

    /// Borrow the oldest item without removing it.
    ///
    /// Returns `None` if the buffer is empty. The borrow is tied to `&self`,
    /// so it is safe even though the underlying slot is `MaybeUninit`: the
    /// lifetime prevents `pop` (which needs `&mut self`) from running while
    /// the borrow is live.
    #[inline]
    pub fn peek(&self) -> Option<&T> {
        if self.len == 0 {
            return None;
        }
        // SAFETY: the slot at `tail` holds a live `T` (see `pop`). We only
        // hand out a shared reference with the lifetime of `&self`, so no
        // mutable aliasing can occur while the borrow is outstanding.
        let slot = self.tail;
        Some(unsafe { &*self.buf[slot].as_ptr() })
    }

    /// Borrow the oldest item mutably without removing it.
    ///
    /// Useful when the consumer wants to update an entry in place before
    /// releasing it. Returns `None` if the buffer is empty.
    #[inline]
    pub fn peek_mut(&mut self) -> Option<&mut T> {
        if self.len == 0 {
            return None;
        }
        // SAFETY: same invariant as `peek`, but we hold `&mut self` so the
        // borrow is exclusive and cannot conflict with `push`/`pop` for the
        // duration of the loan.
        let slot = self.tail;
        Some(unsafe { &mut *self.buf[slot].as_mut_ptr() })
    }

    /// Clear the buffer, dropping every live item in push order.
    ///
    /// After this returns the buffer is empty. Safe to call multiple times.
    #[inline]
    pub fn clear(&mut self) {
        // Drop items by popping them one at a time. We do not bypass `pop`
        // because the index bookkeeping and the slot deinitialisation are
        // already correct there; duplicating them here would be a second
        // place to get wrong.
        while self.pop().is_some() {}
    }
}

impl<T, const N: usize> Default for RingBuffer<T, N> {
    /// `RingBuffer` defaults to an empty queue, matching [`new`](Self::new).
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for RingBuffer<T, N> {
    fn drop(&mut self) {
        // Drop any items still in the buffer. Slots that were never written or
        // were already `pop`ped are `MaybeUninit` and must NOT be dropped —
        // `pop` handles the bookkeeping, so reuse it to drain exactly the live
        // range.
        while self.pop().is_some() {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let rb: RingBuffer<u32, 4> = RingBuffer::new();
        assert!(rb.is_empty());
        assert!(!rb.is_full());
        assert_eq!(rb.len(), 0);
        assert_eq!(rb.capacity(), 4);
    }

    #[test]
    fn push_pop_single() {
        let mut rb: RingBuffer<u32, 4> = RingBuffer::new();
        assert!(rb.push(42).is_ok());
        assert!(!rb.is_empty());
        assert_eq!(rb.len(), 1);
        assert_eq!(rb.pop(), Some(42));
        assert!(rb.is_empty());
        assert_eq!(rb.pop(), None);
    }

    #[test]
    fn push_until_full_then_reject() {
        let mut rb: RingBuffer<u8, 3> = RingBuffer::new();
        assert!(rb.push(1).is_ok());
        assert!(rb.push(2).is_ok());
        assert!(rb.push(3).is_ok());
        assert!(rb.is_full());
        // The fourth push must fail and hand ownership back.
        let rejected = rb.push(4);
        assert!(rejected.is_err());
        assert_eq!(rejected.err(), Some(4));
        // Capacity is exactly N, not N-1.
        assert_eq!(rb.len(), 3);
    }

    #[test]
    fn fifo_order_preserved() {
        let mut rb: RingBuffer<u32, 4> = RingBuffer::new();
        for v in 10..14 {
            rb.push(v).unwrap();
        }
        assert_eq!(rb.pop(), Some(10));
        assert_eq!(rb.pop(), Some(11));
        assert_eq!(rb.pop(), Some(12));
        assert_eq!(rb.pop(), Some(13));
        assert!(rb.is_empty());
    }

    #[test]
    fn wrap_around_reuses_slots() {
        // Push and pop more items than the capacity to exercise the wrap-around
        // at `head = N - 1 -> 0` and `tail = N - 1 -> 0`.
        let mut rb: RingBuffer<u32, 2> = RingBuffer::new();
        for round in 0..8u32 {
            // Each round fills, drains, and refills.
            rb.push(round).unwrap();
            rb.push(round + 100).unwrap();
            assert_eq!(rb.pop(), Some(round));
            assert_eq!(rb.pop(), Some(round + 100));
            assert!(rb.is_empty());
        }
    }

    #[test]
    fn interleaved_push_pop() {
        let mut rb: RingBuffer<u32, 4> = RingBuffer::new();
        rb.push(1).unwrap();
        rb.push(2).unwrap();
        assert_eq!(rb.pop(), Some(1));
        rb.push(3).unwrap();
        assert_eq!(rb.pop(), Some(2));
        assert_eq!(rb.pop(), Some(3));
        assert_eq!(rb.pop(), None);
    }

    #[test]
    fn peek_does_not_advance() {
        let mut rb: RingBuffer<u32, 4> = RingBuffer::new();
        assert_eq!(rb.peek(), None);
        rb.push(7).unwrap();
        rb.push(8).unwrap();
        assert_eq!(rb.peek(), Some(&7));
        // Peeking twice yields the same item; the buffer length is unchanged.
        assert_eq!(rb.peek(), Some(&7));
        assert_eq!(rb.len(), 2);
        assert_eq!(rb.pop(), Some(7));
        assert_eq!(rb.peek(), Some(&8));
    }

    #[test]
    fn peek_mut_updates_in_place() {
        let mut rb: RingBuffer<u32, 4> = RingBuffer::new();
        rb.push(5).unwrap();
        if let Some(head) = rb.peek_mut() {
            *head = 99;
        }
        assert_eq!(rb.pop(), Some(99));
    }

    #[test]
    fn clear_drops_all_items() {
        let mut rb: RingBuffer<u32, 4> = RingBuffer::new();
        for v in 0..4 {
            rb.push(v).unwrap();
        }
        rb.clear();
        assert!(rb.is_empty());
        assert_eq!(rb.pop(), None);
        // The buffer must still be usable after a clear.
        rb.push(123).unwrap();
        assert_eq!(rb.pop(), Some(123));
    }

    #[test]
    fn drop_drops_remaining_items() {
        // Track drops with a counter stored in a static. We cannot use a
        // `Box` (no allocator) but we can observe `Drop` via a side-effecting
        // newtype that increments a shared `Cell`.
        use core::cell::Cell;

        // `#[derive(Debug)]` is required so `Result::unwrap` (whose error
        // bound is `E: Debug`) can format the rejected value on a push
        // failure. Both `&Cell<u32>` and `u32` implement `Debug` in `core`.
        #[derive(Debug)]
        struct DropCounter<'a>(&'a Cell<u32>, u32);
        impl Drop for DropCounter<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }

        let counter = Cell::new(0);
        {
            let mut rb: RingBuffer<DropCounter<'_>, 4> = RingBuffer::new();
            rb.push(DropCounter(&counter, 1)).unwrap();
            rb.push(DropCounter(&counter, 2)).unwrap();
            rb.push(DropCounter(&counter, 3)).unwrap();
            // Drop one explicitly; two remain and must be dropped by the
            // RingBuffer's Drop.
            assert_eq!(rb.pop().unwrap().1, 1);
            assert_eq!(counter.get(), 1);
        }
        // The two remaining items were dropped when `rb` went out of scope.
        assert_eq!(counter.get(), 3);
    }

    #[test]
    fn default_is_empty() {
        let rb: RingBuffer<u32, 4> = RingBuffer::default();
        assert!(rb.is_empty());
        assert_eq!(rb.capacity(), 4);
    }
}
