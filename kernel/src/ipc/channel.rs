//! Bounded, message-preserving local channels.

extern crate alloc;

use alloc::sync::Arc;
use core::alloc::Layout;
use core::array;
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicUsize, Ordering};

use xenith_abi::wait::{
    WAIT_INTEREST_READABLE, WAIT_INTEREST_WRITABLE, WAIT_READY_HANGUP, WAIT_READY_READABLE,
    WAIT_READY_WRITABLE,
};

use crate::fs::fd::FileRef;
use crate::mm::kmalloc::{kfree, kmalloc, kmalloc_zeroed};
use crate::sched::TaskId;
use crate::sync::SpinLockIRQ;
use crate::time::Instant;

pub const CHANNEL_MESSAGE_BYTES: usize = 4096;
pub const CHANNEL_TRANSFER_CAPACITY: usize = 4;
pub const CHANNEL_QUEUE_DEPTH: usize = 8;
/// Global channel-pair bound. With the fixed preallocated queues this caps
/// live channel storage at roughly five MiB instead of allowing unbounded
/// kernel-heap claims.
pub const MAX_CHANNEL_PAIRS: usize = 64;

static LIVE_CHANNEL_PAIRS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
pub struct ChannelTransfer {
    pub file: FileRef,
    pub rights: u32,
    pub tag: u64,
}

impl core::fmt::Debug for ChannelTransfer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChannelTransfer")
            .field("rights", &self.rights)
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

pub type ChannelTransfers = [Option<ChannelTransfer>; CHANNEL_TRANSFER_CAPACITY];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelError {
    Fault,
    InvalidMessage,
    MessageTooLarge,
    TooManyTransfers,
    WouldBlock,
    BrokenPipe,
    Interrupted,
    TimedOut,
    Busy,
    NoCurrentTask,
    StateCorrupt,
    ResourceExhausted,
}

struct MessageSlot {
    length: usize,
    transfers: ChannelTransfers,
}

impl MessageSlot {
    fn new() -> Self {
        Self {
            length: 0,
            transfers: array::from_fn(|_| None),
        }
    }

    fn clear(&mut self) {
        self.length = 0;
        for transfer in &mut self.transfers {
            *transfer = None;
        }
    }
}

const PAYLOAD_STORAGE_BYTES: usize = CHANNEL_QUEUE_DEPTH * CHANNEL_MESSAGE_BYTES;

/// Heap-owned contiguous payload bytes for one channel direction.
///
/// Keeping this 32 KiB block out of `DirectionState` prevents channel
/// construction from materializing a pair-sized temporary on a 16 KiB kernel
/// stack. Access is only exposed through the containing direction's IRQ lock.
struct PayloadStorage {
    base: NonNull<u8>,
}

// SAFETY: the allocation is uniquely owned and every access is mediated by
// the `SpinLockIRQ<DirectionState>` containing this owner.
unsafe impl Send for PayloadStorage {}

impl PayloadStorage {
    fn try_new() -> Result<Self, ChannelError> {
        let base = kmalloc_zeroed(Self::layout()).map_err(|_| ChannelError::ResourceExhausted)?;
        Ok(Self { base })
    }

    const fn layout() -> Layout {
        // 4096 is nonzero and 16 is a valid power-of-two alignment.
        match Layout::from_size_align(PAYLOAD_STORAGE_BYTES, 16) {
            Ok(layout) => layout,
            Err(_) => unreachable!(),
        }
    }

    fn slot(&self, index: usize) -> &[u8; CHANNEL_MESSAGE_BYTES] {
        debug_assert!(index < CHANNEL_QUEUE_DEPTH);
        // SAFETY: every slot is an aligned, disjoint 4096-byte subrange of
        // the live zeroed allocation. The shared borrow is bounded by the
        // direction lock guard held by the caller.
        unsafe {
            &*self
                .base
                .as_ptr()
                .add(index * CHANNEL_MESSAGE_BYTES)
                .cast::<[u8; CHANNEL_MESSAGE_BYTES]>()
        }
    }

    fn slot_mut(&mut self, index: usize) -> &mut [u8; CHANNEL_MESSAGE_BYTES] {
        debug_assert!(index < CHANNEL_QUEUE_DEPTH);
        // SAFETY: `&mut self` plus the direction lock gives exclusive access
        // to this disjoint slot for the returned borrow.
        unsafe {
            &mut *self
                .base
                .as_ptr()
                .add(index * CHANNEL_MESSAGE_BYTES)
                .cast::<[u8; CHANNEL_MESSAGE_BYTES]>()
        }
    }
}

impl Drop for PayloadStorage {
    fn drop(&mut self) {
        // SAFETY: `base` came from `kmalloc_zeroed` with this exact layout and
        // this unique owner frees it exactly once.
        unsafe { kfree(self.base, Self::layout()) };
    }
}

struct DirectionState {
    slots: [MessageSlot; CHANNEL_QUEUE_DEPTH],
    payloads: PayloadStorage,
    head: usize,
    len: usize,
    sender_open: bool,
    receiver_open: bool,
    reader_waiter: Option<TaskId>,
    writer_waiter: Option<TaskId>,
    receive_owner: Option<(TaskId, u64)>,
    next_receive_token: u64,
}

/// Fallibly allocated owner for one direction's metadata.
///
/// A regular `Box` cannot own memory returned by `kmalloc`: although both
/// ultimately use the kernel heap, freeing it through `Box` would bypass the
/// matching `kfree` accounting path. This owner keeps allocation and release
/// paired exactly and avoids materializing the metadata on the kernel stack.
struct DirectionOwner {
    pointer: NonNull<DirectionState>,
}

// SAFETY: ownership is unique and access is serialized by the containing
// `SpinLockIRQ`; moving the owner between tasks does not expose the pointer.
unsafe impl Send for DirectionOwner {}

impl Deref for DirectionOwner {
    type Target = DirectionState;

    fn deref(&self) -> &Self::Target {
        // SAFETY: `pointer` holds a live DirectionState for this owner's
        // entire lifetime and shared access follows the direction lock.
        unsafe { self.pointer.as_ref() }
    }
}

impl DerefMut for DirectionOwner {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: the unique owner is mutably borrowed through the direction
        // lock, so no other mutable reference can coexist.
        unsafe { self.pointer.as_mut() }
    }
}

impl Drop for DirectionOwner {
    fn drop(&mut self) {
        // SAFETY: the pointer was initialized exactly once by `try_boxed`.
        // Drop the value first so its payload allocation is released, then
        // return the metadata block with the matching raw allocator API.
        unsafe {
            ptr::drop_in_place(self.pointer.as_ptr());
            kfree(self.pointer.cast(), Layout::new::<DirectionState>());
        }
    }
}

impl DirectionState {
    fn try_new() -> Result<Self, ChannelError> {
        Ok(Self {
            slots: array::from_fn(|_| MessageSlot::new()),
            payloads: PayloadStorage::try_new()?,
            head: 0,
            len: 0,
            sender_open: true,
            receiver_open: true,
            reader_waiter: None,
            writer_waiter: None,
            receive_owner: None,
            next_receive_token: 1,
        })
    }

    fn try_boxed() -> Result<DirectionOwner, ChannelError> {
        let state = Self::try_new()?;
        let raw = kmalloc(Layout::new::<Self>()).map_err(|_| ChannelError::ResourceExhausted)?;
        let pointer = raw.cast::<Self>();
        // SAFETY: `raw` is uniquely owned, correctly aligned, and sized for
        // one DirectionState. Moving the fully initialized value into it lets
        // DirectionOwner own both metadata and payload storage.
        unsafe {
            pointer.as_ptr().write(state);
        }
        Ok(DirectionOwner { pointer })
    }

    fn tail(&self) -> usize {
        (self.head + self.len) % CHANNEL_QUEUE_DEPTH
    }

    fn next_token(&mut self) -> u64 {
        let token = self.next_receive_token.max(1);
        self.next_receive_token = token.wrapping_add(1).max(1);
        token
    }

    fn clear_slot(&mut self, index: usize) {
        let length = self.slots[index].length;
        self.payloads.slot_mut(index)[..length].fill(0);
        self.slots[index].clear();
    }
}

/// Reservation token deliberately declared after both directions in
/// `ChannelPair`. Rust drops fields in declaration order, so the global quota
/// is released only after all storage belonging to the pair has been freed.
struct ChannelPairReservation;

impl Drop for ChannelPairReservation {
    fn drop(&mut self) {
        release_channel_pair_reservation();
    }
}

struct ChannelPair {
    a_to_b: SpinLockIRQ<DirectionOwner>,
    b_to_a: SpinLockIRQ<DirectionOwner>,
    _reservation: ChannelPairReservation,
}

impl ChannelPair {
    fn try_new() -> Result<Self, ChannelError> {
        let a_to_b = DirectionState::try_boxed()?;
        let b_to_a = DirectionState::try_boxed()?;
        Ok(Self {
            a_to_b: SpinLockIRQ::new(a_to_b),
            b_to_a: SpinLockIRQ::new(b_to_a),
            _reservation: ChannelPairReservation,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Side {
    A,
    B,
}

/// One shared open description for one side of a bidirectional channel.
pub struct ChannelEndpoint {
    pair: Arc<ChannelPair>,
    side: Side,
}

impl ChannelEndpoint {
    fn new(pair: Arc<ChannelPair>, side: Side) -> Self {
        Self { pair, side }
    }

    fn outgoing(&self) -> &SpinLockIRQ<DirectionOwner> {
        match self.side {
            Side::A => &self.pair.a_to_b,
            Side::B => &self.pair.b_to_a,
        }
    }

    fn incoming(&self) -> &SpinLockIRQ<DirectionOwner> {
        match self.side {
            Side::A => &self.pair.b_to_a,
            Side::B => &self.pair.a_to_b,
        }
    }

    #[must_use]
    pub(crate) fn poll_ready(&self, interests: u32) -> u32 {
        let mut ready = 0;
        if interests & WAIT_INTEREST_READABLE != 0 {
            let incoming = self.incoming().lock();
            if incoming.len != 0 {
                ready |= WAIT_READY_READABLE;
            }
            if !incoming.sender_open {
                ready |= WAIT_READY_HANGUP;
            }
        }
        if interests & WAIT_INTEREST_WRITABLE != 0 {
            let outgoing = self.outgoing().lock();
            if outgoing.receiver_open && outgoing.len < CHANNEL_QUEUE_DEPTH {
                ready |= WAIT_READY_WRITABLE;
            }
            if !outgoing.receiver_open {
                ready |= WAIT_READY_HANGUP;
            }
        }
        ready
    }

    /// Register a generic wait task and return readiness observed while each
    /// source lock is held. Callers must disarm every registration before
    /// returning to userspace.
    pub(crate) fn arm_wait(&self, task: TaskId, interests: u32) -> Result<u32, ChannelError> {
        if interests == 0 || interests & !(WAIT_INTEREST_READABLE | WAIT_INTEREST_WRITABLE) != 0 {
            return Err(ChannelError::InvalidMessage);
        }
        let mut ready = 0;
        let mut armed_read = false;
        if interests & WAIT_INTEREST_READABLE != 0 {
            let mut incoming = self.incoming().lock();
            if incoming.len != 0 {
                ready |= WAIT_READY_READABLE;
            }
            if !incoming.sender_open {
                ready |= WAIT_READY_HANGUP;
            }
            if ready == 0 {
                arm_waiter(&mut incoming.reader_waiter, task)?;
                armed_read = true;
            }
        }
        if interests & WAIT_INTEREST_WRITABLE != 0 {
            let mut outgoing = self.outgoing().lock();
            let mut write_ready = 0;
            if outgoing.receiver_open && outgoing.len < CHANNEL_QUEUE_DEPTH {
                write_ready |= WAIT_READY_WRITABLE;
            }
            if !outgoing.receiver_open {
                write_ready |= WAIT_READY_HANGUP;
            }
            ready |= write_ready;
            if write_ready == 0 {
                if let Err(error) = arm_waiter(&mut outgoing.writer_waiter, task) {
                    drop(outgoing);
                    if armed_read {
                        let mut incoming = self.incoming().lock();
                        clear_waiter(&mut incoming.reader_waiter, task);
                    }
                    return Err(error);
                }
            }
        }
        Ok(ready)
    }

    pub(crate) fn disarm_wait(&self, task: TaskId, interests: u32) {
        if interests & WAIT_INTEREST_READABLE != 0 {
            let mut incoming = self.incoming().lock();
            clear_waiter(&mut incoming.reader_waiter, task);
        }
        if interests & WAIT_INTEREST_WRITABLE != 0 {
            let mut outgoing = self.outgoing().lock();
            clear_waiter(&mut outgoing.writer_waiter, task);
        }
    }

    /// Atomically publish one message after `copy` has filled its private
    /// queue slot. The closure runs under the queue's IRQ-safe lock and must
    /// not allocate, block, or acquire the process table.
    pub fn send_with<F>(
        &self,
        length: usize,
        transfers: ChannelTransfers,
        nonblocking: bool,
        deadline: Option<Instant>,
        copy: F,
    ) -> Result<(), ChannelError>
    where
        F: FnOnce(&mut [u8; CHANNEL_MESSAGE_BYTES]) -> Result<(), ChannelError>,
    {
        let task = current_task_id()?;
        self.send_with_task(task, length, transfers, nonblocking, deadline, copy)
    }

    fn send_with_task<F>(
        &self,
        task: TaskId,
        length: usize,
        transfers: ChannelTransfers,
        nonblocking: bool,
        deadline: Option<Instant>,
        copy: F,
    ) -> Result<(), ChannelError>
    where
        F: FnOnce(&mut [u8; CHANNEL_MESSAGE_BYTES]) -> Result<(), ChannelError>,
    {
        if length > CHANNEL_MESSAGE_BYTES {
            return Err(ChannelError::MessageTooLarge);
        }
        let transfer_count = transfers.iter().filter(|slot| slot.is_some()).count();
        if transfers[..transfer_count].iter().any(Option::is_none)
            || transfers[transfer_count..].iter().any(Option::is_some)
        {
            return Err(ChannelError::TooManyTransfers);
        }

        let mut copy = Some(copy);
        let mut transfers = Some(transfers);
        loop {
            let mut state = self.outgoing().lock();
            clear_waiter(&mut state.writer_waiter, task);
            if !state.receiver_open {
                return Err(ChannelError::BrokenPipe);
            }
            if state.len < CHANNEL_QUEUE_DEPTH {
                let tail = state.tail();
                debug_assert_eq!(state.slots[tail].length, 0);
                let copier = copy.take().ok_or(ChannelError::StateCorrupt)?;
                if let Err(error) = copier(state.payloads.slot_mut(tail)) {
                    state.payloads.slot_mut(tail).fill(0);
                    return Err(error);
                }
                // The inactive payload tail must never retain bytes from a
                // rejected or earlier message, both for canonical receive
                // records and cross-process information-leak prevention.
                state.payloads.slot_mut(tail)[length..].fill(0);
                let slot = &mut state.slots[tail];
                slot.length = length;
                slot.transfers = transfers.take().ok_or(ChannelError::StateCorrupt)?;
                state.len += 1;
                let waiter = state.reader_waiter.take();
                drop(state);
                wake(waiter);
                return Ok(());
            }
            if nonblocking {
                return Err(ChannelError::WouldBlock);
            }
            if current_interrupted() {
                return Err(ChannelError::Interrupted);
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(ChannelError::TimedOut);
            }
            arm_waiter(&mut state.writer_waiter, task)?;
            crate::sched::scheduler::block_current_until_releasing(deadline, state);
        }
    }

    /// Reserve the front message without consuming it.
    ///
    /// The syscall layer installs every transferred descriptor before copying
    /// output through [`copy_receive_with`](Self::copy_receive_with). Failed
    /// installation can therefore cancel without modifying either the queue
    /// or the user's receive record.
    pub fn begin_receive(
        &self,
        nonblocking: bool,
        deadline: Option<Instant>,
    ) -> Result<PendingReceive, ChannelError> {
        let task = current_task_id()?;
        self.begin_receive_for_task(task, nonblocking, deadline)
    }

    fn begin_receive_for_task(
        &self,
        task: TaskId,
        nonblocking: bool,
        deadline: Option<Instant>,
    ) -> Result<PendingReceive, ChannelError> {
        loop {
            let mut state = self.incoming().lock();
            clear_waiter(&mut state.reader_waiter, task);
            if let Some((owner, _)) = state.receive_owner {
                if owner != task {
                    return Err(ChannelError::Busy);
                }
                return Err(ChannelError::StateCorrupt);
            }
            if state.len != 0 {
                let head = state.head;
                let transfers = array::from_fn(|index| state.slots[head].transfers[index].clone());
                let length = state.slots[head].length;
                let token = state.next_token();
                state.receive_owner = Some((task, token));
                return Ok(PendingReceive {
                    task,
                    token,
                    length,
                    transfers,
                });
            }
            if !state.sender_open {
                return Err(ChannelError::BrokenPipe);
            }
            if nonblocking {
                return Err(ChannelError::WouldBlock);
            }
            if current_interrupted() {
                return Err(ChannelError::Interrupted);
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(ChannelError::TimedOut);
            }
            arm_waiter(&mut state.reader_waiter, task)?;
            crate::sched::scheduler::block_current_until_releasing(deadline, state);
        }
    }

    /// Copy the complete canonical payload of a reserved receive record.
    /// The closure runs under the IRQ-safe queue lock and must not allocate,
    /// block, or acquire the process table.
    pub fn copy_receive_with<F>(
        &self,
        pending: &PendingReceive,
        copy: F,
    ) -> Result<(), ChannelError>
    where
        F: FnOnce(&[u8; CHANNEL_MESSAGE_BYTES], usize) -> Result<(), ChannelError>,
    {
        let state = self.incoming().lock();
        if state.receive_owner != Some((pending.task, pending.token)) || state.len == 0 {
            return Err(ChannelError::StateCorrupt);
        }
        let slot = &state.slots[state.head];
        if slot.length != pending.length {
            return Err(ChannelError::StateCorrupt);
        }
        copy(state.payloads.slot(state.head), slot.length)
    }

    pub fn finish_receive(&self, pending: PendingReceive) -> Result<(), ChannelError> {
        let mut state = self.incoming().lock();
        if state.receive_owner != Some((pending.task, pending.token)) || state.len == 0 {
            return Err(ChannelError::StateCorrupt);
        }
        let head = state.head;
        state.clear_slot(head);
        state.head = (head + 1) % CHANNEL_QUEUE_DEPTH;
        state.len -= 1;
        state.receive_owner = None;
        let waiter = state.writer_waiter.take();
        drop(state);
        wake(waiter);
        Ok(())
    }

    pub fn cancel_receive(&self, pending: &PendingReceive) -> Result<(), ChannelError> {
        let mut state = self.incoming().lock();
        if state.receive_owner != Some((pending.task, pending.token)) {
            return Err(ChannelError::StateCorrupt);
        }
        state.receive_owner = None;
        Ok(())
    }

    #[cfg(test)]
    fn queued_incoming(&self) -> usize {
        self.incoming().lock().len
    }
}

impl Drop for ChannelEndpoint {
    fn drop(&mut self) {
        let mut retired: [Option<ChannelTransfer>;
            CHANNEL_QUEUE_DEPTH * CHANNEL_TRANSFER_CAPACITY] = array::from_fn(|_| None);
        let mut retired_count = 0usize;
        let (incoming_waiter, incoming_writer) = {
            let mut incoming = self.incoming().lock();
            incoming.receiver_open = false;
            for queued in 0..incoming.len {
                let index = (incoming.head + queued) % CHANNEL_QUEUE_DEPTH;
                let length = incoming.slots[index].length;
                incoming.payloads.slot_mut(index)[..length].fill(0);
                let slot = &mut incoming.slots[index];
                slot.length = 0;
                for transfer in &mut slot.transfers {
                    if let Some(transfer) = transfer.take() {
                        retired[retired_count] = Some(transfer);
                        retired_count += 1;
                    }
                }
            }
            incoming.head = 0;
            incoming.len = 0;
            incoming.receive_owner = None;
            (incoming.reader_waiter.take(), incoming.writer_waiter.take())
        };
        wake(incoming_waiter);
        wake(incoming_writer);

        let (outgoing_reader, outgoing_waiter) = {
            let mut outgoing = self.outgoing().lock();
            outgoing.sender_open = false;
            (outgoing.reader_waiter.take(), outgoing.writer_waiter.take())
        };
        wake(outgoing_reader);
        wake(outgoing_waiter);
        // Transferred backends may wake their own peers on final drop. Keep
        // every destructor outside both channel IRQ locks.
        drop(retired);
    }
}

impl core::fmt::Debug for ChannelEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChannelEndpoint")
            .field("side", &self.side)
            .finish_non_exhaustive()
    }
}

pub struct PendingReceive {
    task: TaskId,
    token: u64,
    pub length: usize,
    pub transfers: ChannelTransfers,
}

impl core::fmt::Debug for PendingReceive {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingReceive")
            .field("task", &self.task)
            .field("token", &self.token)
            .field("length", &self.length)
            .field(
                "transfer_count",
                &self.transfers.iter().filter(|slot| slot.is_some()).count(),
            )
            .finish()
    }
}

pub fn create() -> Result<(ChannelEndpoint, ChannelEndpoint), ChannelError> {
    reserve_channel_pair()?;
    let pair = match ChannelPair::try_new() {
        Ok(pair) => Arc::new(pair),
        Err(error) => {
            release_channel_pair_reservation();
            return Err(error);
        },
    };
    Ok((
        ChannelEndpoint::new(Arc::clone(&pair), Side::A),
        ChannelEndpoint::new(pair, Side::B),
    ))
}

fn release_channel_pair_reservation() {
    let previous = LIVE_CHANNEL_PAIRS.fetch_sub(1, Ordering::AcqRel);
    debug_assert!(previous != 0, "channel-pair quota underflow");
}

fn reserve_channel_pair() -> Result<(), ChannelError> {
    reserve_bounded(&LIVE_CHANNEL_PAIRS, MAX_CHANNEL_PAIRS)
}

fn reserve_bounded(counter: &AtomicUsize, limit: usize) -> Result<(), ChannelError> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= limit {
            return Err(ChannelError::ResourceExhausted);
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

fn current_task_id() -> Result<TaskId, ChannelError> {
    crate::sched::scheduler::with_current_node(|node| node.task.id)
        .ok_or(ChannelError::NoCurrentTask)
}

fn current_interrupted() -> bool {
    crate::user::process::with_current_process(|process| {
        process.signals.has_interrupting_delivery()
    })
    .unwrap_or(false)
}

fn arm_waiter(slot: &mut Option<TaskId>, task: TaskId) -> Result<(), ChannelError> {
    match *slot {
        None => {
            *slot = Some(task);
            Ok(())
        },
        Some(existing) if existing == task => Ok(()),
        Some(_) => Err(ChannelError::Busy),
    }
}

fn clear_waiter(slot: &mut Option<TaskId>, task: TaskId) {
    if *slot == Some(task) {
        *slot = None;
    }
}

fn wake(waiter: Option<TaskId>) {
    if let Some(waiter) = waiter {
        let _ = crate::sched::scheduler::interrupt_task_from_task(waiter);
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::*;
    use crate::fs::fd::{FileObject, OpenFlags};
    use crate::fs::ramfs::RamFs;

    fn no_transfers() -> ChannelTransfers {
        array::from_fn(|_| None)
    }

    // Host tests have no scheduler task. Exercise the storage/lifetime core
    // directly; scheduler-integrated blocking is covered by kernel runtime
    // tests once the syscalls are wired.
    fn enqueue_for_test(endpoint: &ChannelEndpoint, bytes: &[u8], transfers: ChannelTransfers) {
        let mut state = endpoint.outgoing().lock();
        let tail = state.tail();
        state.payloads.slot_mut(tail)[..bytes.len()].copy_from_slice(bytes);
        state.slots[tail].length = bytes.len();
        state.slots[tail].transfers = transfers;
        state.len += 1;
    }

    #[test]
    fn messages_are_bounded_fifo_datagrams() {
        let (a, b) = create().unwrap();
        enqueue_for_test(&a, b"first", no_transfers());
        enqueue_for_test(&a, b"second", no_transfers());
        assert_eq!(b.queued_incoming(), 2);
        let state = b.incoming().lock();
        assert_eq!(
            &state.payloads.slot(state.head)[..state.slots[state.head].length],
            b"first"
        );
        let second = (state.head + 1) % CHANNEL_QUEUE_DEPTH;
        assert_eq!(
            &state.payloads.slot(second)[..state.slots[second].length],
            b"second"
        );
    }

    #[test]
    fn queued_transfer_keeps_open_description_alive() {
        let fs = RamFs::new();
        let node = fs.write_file("/capability", b"x", 0o644).unwrap();
        let file = Arc::new(FileObject::new(node, OpenFlags::READ_ONLY));
        let weak = Arc::downgrade(&file);
        let (a, b) = create().unwrap();
        let mut transfers = no_transfers();
        transfers[0] = Some(ChannelTransfer {
            file: Arc::clone(&file),
            rights: 1,
            tag: 7,
        });
        enqueue_for_test(&a, b"x", transfers);
        drop(file);
        assert!(weak.upgrade().is_some());
        drop(b);
        assert!(weak.upgrade().is_none());
        drop(a);
    }

    #[test]
    fn endpoint_close_marks_both_directions() {
        let (a, b) = create().unwrap();
        drop(a);
        assert!(!b.incoming().lock().sender_open);
        assert!(!b.outgoing().lock().receiver_open);
    }

    #[test]
    fn readiness_tracks_queue_capacity_data_and_peer_close() {
        let (a, b) = create().unwrap();
        assert_eq!(
            a.poll_ready(WAIT_INTEREST_READABLE | WAIT_INTEREST_WRITABLE),
            WAIT_READY_WRITABLE
        );
        assert_eq!(
            b.poll_ready(WAIT_INTEREST_READABLE | WAIT_INTEREST_WRITABLE),
            WAIT_READY_WRITABLE
        );

        enqueue_for_test(&a, b"message", no_transfers());
        assert_eq!(
            b.poll_ready(WAIT_INTEREST_READABLE | WAIT_INTEREST_WRITABLE),
            WAIT_READY_READABLE | WAIT_READY_WRITABLE
        );
        for _ in 1..CHANNEL_QUEUE_DEPTH {
            enqueue_for_test(&a, b"full", no_transfers());
        }
        assert_eq!(a.poll_ready(WAIT_INTEREST_WRITABLE), 0);

        drop(b);
        assert_eq!(
            a.poll_ready(WAIT_INTEREST_READABLE | WAIT_INTEREST_WRITABLE),
            WAIT_READY_HANGUP
        );
    }

    #[test]
    fn generic_wait_registration_is_exclusive_and_reversible() {
        let (a, _b) = create().unwrap();
        let first = TaskId(31);
        let second = TaskId(32);

        assert_eq!(a.arm_wait(first, WAIT_INTEREST_READABLE), Ok(0));
        assert_eq!(
            a.arm_wait(second, WAIT_INTEREST_READABLE),
            Err(ChannelError::Busy)
        );
        a.disarm_wait(first, WAIT_INTEREST_READABLE);
        assert_eq!(a.arm_wait(second, WAIT_INTEREST_READABLE), Ok(0));
        a.disarm_wait(second, WAIT_INTEREST_READABLE);
    }

    #[test]
    fn channel_pair_storage_and_global_quota_are_explicitly_bounded() {
        assert!(
            core::mem::size_of::<ChannelPair>() < crate::sched::task::KERNEL_STACK_SIZE / 4,
            "channel pair metadata must stay well below one kernel stack"
        );
        assert_eq!(PAYLOAD_STORAGE_BYTES, 32 * 1024);
        assert_eq!(MAX_CHANNEL_PAIRS, 64);
        let counter = AtomicUsize::new(0);
        assert_eq!(reserve_bounded(&counter, 1), Ok(()));
        assert_eq!(counter.load(Ordering::Acquire), 1);
        assert_eq!(
            reserve_bounded(&counter, 1),
            Err(ChannelError::ResourceExhausted)
        );
    }

    #[test]
    fn nonblocking_transaction_reserves_copies_and_consumes_exactly_once() {
        let (sender, receiver) = create().unwrap();
        sender
            .send_with_task(TaskId(11), 5, no_transfers(), true, None, |slot| {
                slot[..5].copy_from_slice(b"hello");
                Ok(())
            })
            .unwrap();

        let pending = receiver
            .begin_receive_for_task(TaskId(12), true, None)
            .unwrap();
        assert_eq!(pending.length, 5);
        let mut copied = [0u8; CHANNEL_MESSAGE_BYTES];
        receiver
            .copy_receive_with(&pending, |source, length| {
                assert_eq!(length, 5);
                copied.copy_from_slice(source);
                Ok(())
            })
            .unwrap();
        assert_eq!(&copied[..5], b"hello");
        assert!(copied[5..].iter().all(|byte| *byte == 0));
        receiver.finish_receive(pending).unwrap();
        assert!(matches!(
            receiver.begin_receive_for_task(TaskId(12), true, None),
            Err(ChannelError::WouldBlock)
        ));
    }

    #[test]
    fn failed_send_and_cancelled_receive_leave_the_queue_transactional() {
        let (sender, receiver) = create().unwrap();
        assert_eq!(
            sender.send_with_task(TaskId(21), 1, no_transfers(), true, None, |slot| {
                slot[0] = 0xA5;
                Err(ChannelError::InvalidMessage)
            },),
            Err(ChannelError::InvalidMessage)
        );
        assert_eq!(receiver.queued_incoming(), 0);

        enqueue_for_test(&sender, b"kept", no_transfers());
        let first = receiver
            .begin_receive_for_task(TaskId(22), true, None)
            .unwrap();
        receiver.cancel_receive(&first).unwrap();
        assert_eq!(receiver.queued_incoming(), 1);
        let second = receiver
            .begin_receive_for_task(TaskId(22), true, None)
            .unwrap();
        receiver.finish_receive(second).unwrap();
        assert_eq!(receiver.queued_incoming(), 0);
    }
}
