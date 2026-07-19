//! Thread metadata layered over scheduler tasks.
//!
//! A process may own several threads. Each thread receives a private kernel
//! stack and user stack pointer while retaining a copy of the process's
//! [`AddressSpace`] handle; copying that handle shares the same PML4 rather
//! than cloning its mappings.

use core::fmt;
use core::sync::atomic::{AtomicI64, AtomicU64, AtomicU8, Ordering};

use super::task::{ExitStatus, KernelStack, Task, TaskId, TaskState};
use crate::mm::r#virtual::AddressSpace;

/// A globally unique thread identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ThreadId(pub u64);

impl ThreadId {
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "thread#{}", self.0)
    }
}

static NEXT_THREAD_ID: AtomicU64 = AtomicU64::new(1);

fn next_thread_id() -> ThreadId {
    ThreadId(NEXT_THREAD_ID.fetch_add(1, Ordering::Relaxed))
}

/// Atomic form of [`TaskState`] used by joiners and the exiting thread.
pub struct ThreadState(AtomicU8);

impl ThreadState {
    const fn encode(state: TaskState) -> u8 {
        match state {
            TaskState::Ready => 0,
            TaskState::Running => 1,
            TaskState::Sleeping => 2,
            TaskState::Blocked => 3,
            TaskState::Zombie => 4,
            TaskState::Dead => 5,
        }
    }

    const fn decode(value: u8) -> TaskState {
        match value {
            1 => TaskState::Running,
            2 => TaskState::Sleeping,
            3 => TaskState::Blocked,
            4 => TaskState::Zombie,
            5 => TaskState::Dead,
            _ => TaskState::Ready,
        }
    }

    #[must_use]
    pub const fn new(state: TaskState) -> Self {
        Self(AtomicU8::new(Self::encode(state)))
    }

    #[inline]
    #[must_use]
    pub fn load(&self) -> TaskState {
        Self::decode(self.0.load(Ordering::Acquire))
    }

    #[inline]
    pub fn store(&self, state: TaskState) {
        self.0.store(Self::encode(state), Ordering::Release);
    }
}

impl fmt::Debug for ThreadState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.load().fmt(f)
    }
}

const EXIT_PENDING: u8 = 0;
const EXIT_CODE: u8 = 1;
const EXIT_SIGNAL: u8 = 2;

/// One schedulable execution stream belonging to a process task.
pub struct Thread {
    /// Scheduler task/process that owns the shared address space.
    pub task: TaskId,
    /// Identifier unique across all threads.
    pub tid: ThreadId,
    /// Lifecycle state visible to joiners.
    pub state: ThreadState,
    /// Private ring-0 stack used while the thread executes in the kernel.
    pub stack: KernelStack,
    /// User-mode stack pointer restored on return to ring 3.
    pub user_rsp: AtomicU64,
    address_space: Option<AddressSpace>,
    exit_kind: AtomicU8,
    exit_value: AtomicI64,
}

impl Thread {
    /// Create a thread that shares `task`'s address space.
    ///
    /// Returns `None` if its private kernel stack cannot be allocated.
    #[must_use]
    pub fn new(task: &Task, user_rsp: u64) -> Option<Self> {
        Self::from_parts(task.id, task.address_space, user_rsp)
    }

    /// Create a thread from process metadata without borrowing a full task.
    #[must_use]
    pub fn from_parts(
        task: TaskId,
        address_space: Option<AddressSpace>,
        user_rsp: u64,
    ) -> Option<Self> {
        Some(Self {
            task,
            tid: next_thread_id(),
            state: ThreadState::new(TaskState::Ready),
            stack: KernelStack::new()?,
            user_rsp: AtomicU64::new(user_rsp),
            address_space,
            exit_kind: AtomicU8::new(EXIT_PENDING),
            exit_value: AtomicI64::new(0),
        })
    }

    /// Shared page-table root inherited from the owning task.
    #[inline]
    #[must_use]
    pub const fn address_space(&self) -> Option<AddressSpace> {
        self.address_space
    }

    /// Read the current user stack pointer.
    #[inline]
    #[must_use]
    pub fn user_rsp(&self) -> u64 {
        self.user_rsp.load(Ordering::Acquire)
    }

    /// Update the saved user stack pointer after a trap or signal frame.
    #[inline]
    pub fn set_user_rsp(&self, rsp: u64) {
        self.user_rsp.store(rsp, Ordering::Release);
    }

    /// Record completion and wake observers waiting in [`join`](Self::join).
    pub fn exit(&self, status: ExitStatus) {
        let (kind, value) = match status {
            ExitStatus::Pending => return,
            ExitStatus::Code(code) => (EXIT_CODE, code),
            ExitStatus::Signal(signal) => (EXIT_SIGNAL, signal as i64),
        };
        self.exit_value.store(value, Ordering::Relaxed);
        self.exit_kind.store(kind, Ordering::Release);
        self.state.store(TaskState::Zombie);
    }

    /// Return the completion status if this thread has exited.
    #[must_use]
    pub fn try_join(&self) -> Option<ExitStatus> {
        let kind = self.exit_kind.load(Ordering::Acquire);
        let value = self.exit_value.load(Ordering::Relaxed);
        match kind {
            EXIT_CODE => Some(ExitStatus::Code(value)),
            EXIT_SIGNAL => Some(ExitStatus::Signal(value as i32)),
            _ => None,
        }
    }

    /// Cooperatively wait until this thread exits and return its status.
    pub fn join(&self) -> ExitStatus {
        loop {
            if let Some(status) = self.try_join() {
                return status;
            }
            if super::scheduler::is_initialised() {
                super::scheduler::yield_now();
            } else {
                core::hint::spin_loop();
            }
        }
    }
}

impl fmt::Debug for Thread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Thread")
            .field("task", &self.task)
            .field("tid", &self.tid)
            .field("state", &self.state)
            .field("kernel_stack", &self.stack)
            .field("user_rsp", &format_args!("{:#018x}", self.user_rsp()))
            .field("address_space", &self.address_space)
            .field("exit_status", &self.try_join())
            .finish()
    }
}
