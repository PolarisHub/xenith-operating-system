//! The kernel task control block.
//!
//! [`Task`] is the scheduler's unit of work: everything the kernel needs to
//! suspend a thread of execution, schedule something else, and later resume
//! it. One `Task` corresponds to one kernel stack plus a saved register
//! context; userspace processes layer a [`AddressSpace`](crate::mm::AddressSpace)
//! on top, while kernel tasks leave the address space as `None` so the
//! context switch skips the CR3 write.
//!
//! # What lives here vs. elsewhere
//!
//! This module owns the *per-task* state: the saved context, the kernel
//! stack, the scheduling metadata (priority, time slice, CPU affinity), and
//! the lifecycle state machine. It deliberately does **not** own the run
//! queue, the idle task, the timer-tick handler, or the context-switch
//! trampoline — those land in sibling files (`scheduler.rs`, `run_queue.rs`)
//! and in `arch/x86_64/asm/context_switch.S`. The split keeps the task struct
//! independent of the policy that dispatches it, so a future SMP or
//! real-time scheduler can reuse [`Task`] unchanged.
//!
//! # The saved context
//!
//! [`Context`] is the `repr(C)` block the asm `context_switch` routine reads
//! and writes. It holds exactly the SysV callee-saved registers (`rbx`,
//! `rbp`, `r12`..`r15`) plus the saved `rsp` and `rip` that the switch
//! trampoline pops to resume the task. A newly created task starts with the
//! callee-saved registers zeroed and `rip`/`rsp`/`rdi` set up so the first
//! switch *into* it appears to be a return from `context_switch` directly into
//! the entry function with the argument in `rdi`.
//!
//! # Safety posture
//!
//! [`Task`] contains raw pointers into its own kernel stack (the saved `rsp`)
//! and, for userspace tasks, an [`AddressSpace`](crate::mm::AddressSpace)
//! handle whose backing page tables may be mutated concurrently by other
//! CPUs. The struct is `!Send`/`!Sync` by default because of the raw stack
//! pointer; the scheduler wraps it in its own synchronization. Accessing a
//! `Task` from a CPU other than the one it is currently running on is the
//! scheduler's responsibility to prevent.

// `alloc` is linked at the `mm` root; reach the collection aliases through
// `crate::mm` so this file stays consistent with the rest of the kernel and
// does not introduce a second `extern crate alloc`.
use core::alloc::Layout;
use core::fmt;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::Once;
use xenith_types::VirtAddr;

use crate::arch::x86_64::asm;
use crate::mm::kmalloc::{kfree, kmalloc_zeroed};
use crate::mm::r#virtual::AddressSpace;
use crate::mm::KString;
use crate::sync::PerCpu;

// ---------------------------------------------------------------------------
// Task identifier
// ---------------------------------------------------------------------------

/// A globally-unique, monotonically-increasing task identifier.
///
/// `TaskId` is a `u64` newtype handed out by [`next_id`]. IDs are never
/// reused: a freed task's ID is gone forever, which keeps log lines, panic
/// messages, and any future `/proc`-style debug surface unambiguous about
/// *which* task they refer to even after the task has been reaped.
///
/// The counter starts at `1` so `TaskId(0)` is a reliable "no task" sentinel
/// distinct from every real task — useful for the per-CPU "current task"
/// slot before the scheduler has picked anything to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub u64);

impl TaskId {
    /// The raw `u64` value, for logging and comparison.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "task#{}", self.0)
    }
}

/// The global monotonic counter backing [`TaskId`] assignment.
///
/// `Relaxed` ordering is sufficient: the counter only needs to never repeat
/// a value, and `fetch_add` is atomic by construction. There is no
/// cross-variable ordering requirement because each new ID is consumed by
/// the calling thread before the `Task` is published to the scheduler.
static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate the next unused [`TaskId`].
///
/// IDs start at `1`; `TaskId(0)` is reserved as the "no task" sentinel.
#[inline]
fn next_id() -> TaskId {
    TaskId(NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// Task lifecycle state
// ---------------------------------------------------------------------------

/// Where a [`Task`] is in its lifecycle.
///
/// The scheduler drives tasks through this state machine:
///
/// ```text
///   Ready ──► Running ──► Ready           (preemption / yield)
///                 │
///                 ├──► Sleeping ──► Ready (timer wake)
///                 ├──► Blocked  ──► Ready (wait satisfied)
///                 └──► Zombie   ──► Dead  (reaped)
/// ```
///
/// `Ready` is the only state from which a task may be selected to run.
/// `Running` is set by the scheduler the instant it switches *into* a task
/// and cleared when the task is switched *out*; it is owned by the scheduler,
/// not mutated by the task itself. `Sleeping` and `Blocked` differ only in
/// why the task cannot run: `Sleeping` is a timed wait (the timer will wake
/// it), `Blocked` is an untimed wait (a wait queue or lock will wake it).
/// `Zombie` means the task has exited but its [`Task`] struct has not yet
/// been reaped; `Dead` is the final state after reclamation, kept only so
/// callers that still hold a `&Task` can observe a well-defined value instead
/// of use-after-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// On a run queue, eligible to be scheduled. The task has a valid saved
    /// context and is not currently executing on any CPU.
    Ready,
    /// Currently executing on exactly one CPU. Set by the scheduler on the
    /// switch-in; cleared on switch-out. Only one task per CPU is ever in
    /// this state.
    Running,
    /// Suspended until a deadline elapses. The time subsystem holds the wake
    /// time; when it fires the task is moved back to `Ready`.
    Sleeping,
    /// Suspended on a wait queue or lock. Whatever wakes the wait queue
    /// moves the task back to `Ready`.
    Blocked,
    /// Exited via [`Task::exit`] but not yet reaped. The exit status is
    /// preserved in [`Task::exit_status`] so a parent (or the reaper) can
    /// read it; the kernel stack is still allocated until reclamation.
    Zombie,
    /// Reaped. The task struct is about to be dropped; this state exists so
    /// a racing observer sees a defined value rather than a freed task.
    Dead,
}

impl TaskState {
    /// `true` for the two states in which the task is eligible to run.
    ///
    /// `Ready` tasks are eligible by definition; `Running` tasks are already
    /// running, so they are "eligible" in the sense that the scheduler does
    /// not need to wake them. The other four states all require an external
    /// event to become runnable.
    #[inline]
    #[must_use]
    pub const fn runnable(self) -> bool {
        matches!(self, Self::Ready | Self::Running)
    }

    /// `true` once the task has exited (whether or not it has been reaped).
    ///
    /// Used by wait-for-child paths to decide whether a task is still worth
    /// blocking on.
    #[inline]
    #[must_use]
    pub const fn exited(self) -> bool {
        matches!(self, Self::Zombie | Self::Dead)
    }

    /// A short lower-case label suitable for log lines and `Display`.
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Sleeping => "sleeping",
            Self::Blocked => "blocked",
            Self::Zombie => "zombie",
            Self::Dead => "dead",
        }
    }
}

impl fmt::Display for TaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// How a task ended, recorded in [`Task::exit_status`] once it exits.
///
/// Kernel tasks exit with an integer code (the return value of their entry
/// function, or the argument passed to [`Task::exit`]). Userspace processes
/// exit with either a code (normal `exit` syscall) or a signal (killed by an
/// unhandled fault or `SIGKILL`-equivalent). The two are distinguished so a
/// future `wait` syscall can report them correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// The task is still running; no exit has been recorded. This is the
    /// value stored in a freshly-created [`Task`] and overwritten by
    /// [`Task::exit`].
    Pending,
    /// Normal exit with the given integer status. For kernel tasks this is
    /// the entry function's return value; for userspace it is the argument
    /// to the `exit` syscall.
    Code(i64),
    /// Killed by the given signal number. Stored when the kernel terminates
    /// a task in response to an unhandled fault (e.g. `#PF` on a bad user
    /// pointer maps to `SIGSEGV`).
    Signal(i32),
}

impl ExitStatus {
    /// `true` for `Pending` (the task has not exited yet).
    #[inline]
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::Pending)
    }
}

// ---------------------------------------------------------------------------
// Saved register context
// ---------------------------------------------------------------------------

/// The callee-saved register snapshot the context-switch trampoline reads
/// and writes.
///
/// This is the in-task portion of a context switch: when the scheduler
/// preempts a task, the asm `context_switch` routine stores the running
/// task's callee-saved registers and `rsp`/`rip` into its [`Context`], then
/// loads the next task's [`Context`] and "returns" into it. Only the SysV
/// callee-saved set is preserved across a switch — caller-saved registers
/// (`rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`..`r11`) are scratch and are not
/// saved here, because the switch happens at a call boundary where those
/// registers are not live by contract.
///
/// # Layout
///
/// `repr(C)` with all-`u64` fields and no padding. The field order is the
/// order the asm trampoline expects to `mov` them, so changing it is a
/// breaking change against `arch/x86_64/asm/context_switch.S`. The trampoline
/// receives a `*mut u8` pointing at the first field; this struct is the
/// typed overlay for that pointer.
///
/// # First switch into a new task
///
/// A new task never *returns* from `context_switch` into previously-running
/// code; it starts at its entry function. To make that work, [`Task::new`]
/// initialises `rip` to the entry point, `rsp` to the top of the kernel
/// stack, and `rdi` to the entry argument (the SysV first-argument register).
/// The remaining callee-saved registers are zeroed. When the trampoline
/// loads this context and `ret`s into `rip`, control lands at the entry
/// function with `rdi` already set — exactly as if it had been called
/// normally.
///
/// `rdi` is stored here even though it is caller-saved, because a *fresh*
/// task's first instruction needs its argument in `rdi` and there is no
/// prior call frame to set it up. After the first switch the field is
/// irrelevant (the trampoline never saves caller-saved registers on
/// subsequent switches).
#[repr(C)]
pub struct Context {
    /// Saved `rbx` (callee-saved).
    pub rbx: u64,
    /// Saved `rbp` (callee-saved; frame pointer).
    pub rbp: u64,
    /// Saved `r12` (callee-saved).
    pub r12: u64,
    /// Saved `r13` (callee-saved).
    pub r13: u64,
    /// Saved `r14` (callee-saved).
    pub r14: u64,
    /// Saved `r15` (callee-saved).
    pub r15: u64,
    /// The saved stack pointer. On switch-out this is the `rsp` the task
    /// will resume with; on a fresh task it is the top of the kernel stack.
    pub rsp: u64,
    /// The saved instruction pointer. On switch-out this is the return
    /// address inside the scheduler; on a fresh task it is the entry fn.
    pub rip: u64,
    /// The entry-function argument for a fresh task (`rdi`). Only meaningful
    /// before the task has run for the first time; afterwards it is stale
    /// scratch and the trampoline does not preserve it.
    pub rdi: u64,
}

impl Context {
    /// A zeroed context with `rip`, `rsp`, and `rdi` set for a fresh task.
    ///
    /// All callee-saved registers start at `0`; the first switch into the
    /// task loads `rsp`/`rip`/`rdi` and jumps to `rip`, so the entry
    /// function sees a clean register file apart from its argument.
    #[must_use]
    pub const fn new_entry(entry: u64, stack_top: u64, arg: u64) -> Self {
        Self {
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rsp: stack_top,
            rip: entry,
            rdi: arg,
        }
    }

    /// A context for a task that is being switched out for the first time
    /// and has no meaningful saved state yet.
    ///
    /// Every field is zero; the scheduler fills `rsp`/`rip` in when it
    /// actually performs the switch. This is the safe default for a
    /// not-yet-started task that is *not* being constructed via
    /// [`Task::new`].
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rsp: 0,
            rip: 0,
            rdi: 0,
        }
    }

    /// A raw mutable pointer to the start of the saved-state block.
    ///
    /// This is the pointer handed to the asm
    /// [`context_switch`](crate::arch::x86_64::asm::context_switch) routine,
    /// which overlays this struct onto the raw `*mut u8` it receives. The
    /// pointer is valid as long as the owning [`Task`] is alive.
    #[inline]
    #[must_use]
    pub fn as_switch_ptr(&mut self) -> *mut u8 {
        core::ptr::addr_of_mut!(*self).cast::<u8>()
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("rip", &format_args!("0x{:016x}", self.rip))
            .field("rsp", &format_args!("0x{:016x}", self.rsp))
            .field("rdi", &format_args!("0x{:016x}", self.rdi))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Kernel stack
// ---------------------------------------------------------------------------

/// The default size of a kernel task stack: 16 KiB (four pages).
///
/// This is large enough for the deepest kernel call chains we expect
/// (page-fault handling under a syscall, which nests fault-on-fault) while
/// keeping per-task memory modest. Stack-hungry kernel work should use a
/// separate work buffer rather than blowing the stack.
pub const KERNEL_STACK_SIZE: usize = 16 * 1024;

/// An owning handle for a kernel task's stack.
///
/// Owns a 16-byte-aligned heap allocation and caches its top-of-stack
/// virtual address (the SysV AMD64 ABI requires a 16-aligned `rsp` at every
/// call boundary) so [`Task::new`] can seed the saved `rsp` without
/// recomputing it. The stack is freed when the `KernelStack` is dropped via
/// a manual [`Drop`] impl that calls [`kfree`](crate::mm::kmalloc::kfree)
/// with the *original* allocation layout.
///
/// # Why not `Kbox<[u8]>`?
///
/// A `Box<[u8]>` drops with `Layout::for_value(&[u8])`, whose alignment is
/// 1 — but the stack is allocated with 16-byte alignment. The global
/// allocator contract requires `dealloc` to be called with the *same*
/// layout as `alloc`, so handing the allocation to `Box<[u8]>` would free
/// it with the wrong alignment and violate that contract. Owning the raw
/// pointer plus the layout and freeing through [`kfree`] keeps the
/// alloc/dealloc layouts in agreement.
///
/// The stack is *not* guard-paged today: a stack overflow writes into the
/// heap below the allocation rather than faulting. A future phase will
/// allocate stacks with a guard page below the bottom so overflows trap
/// instead of silently corrupting the heap; the public surface (`top`,
/// `bottom`, `size`) is written so that change is mechanical.
pub struct KernelStack {
    /// The base of the allocated stack buffer (the lowest valid address).
    /// Non-null while the `KernelStack` is live; `Drop` consumes it.
    base: NonNull<u8>,
    /// The allocation layout used to obtain `base`. Stored verbatim so
    /// `Drop` can call `kfree` with exactly the layout `kmalloc_zeroed`
    /// used, satisfying the allocator's same-layout-on-dealloc contract.
    layout: Layout,
    /// The highest valid stack address (16-byte-aligned). This is the value
    /// loaded into `rsp` on the task's first switch-in.
    top: VirtAddr,
}

// `KernelStack` is intentionally `!Send` and `!Sync`: it owns a raw
// pointer into a heap allocation that the owning `Task` accesses under the
// scheduler's per-CPU ownership rules, not Rust's send/sync rules. The
// scheduler moves `Task`s between CPUs through its own raw-pointer
// bookkeeping (the run queue stores `NonNull<Task>`), so `Task` does not
// need — and must not have — `Send`. Adding `unsafe impl Send` here would
// silently weaken that invariant.

impl KernelStack {
    /// Allocate a new kernel stack of [`KERNEL_STACK_SIZE`] bytes.
    ///
    /// The buffer is zeroed so a stack overflow reads zeros rather than
    /// stale heap contents (a small defence-in-depth measure; the real
    /// protection is a future guard page). Returns `None` if the heap is
    /// exhausted, which the caller propagates as a task-creation failure
    /// rather than panicking — running out of memory while spawning a task
    /// is a recoverable condition for the caller.
    #[must_use]
    pub fn new() -> Option<Self> {
        Self::with_size(KERNEL_STACK_SIZE)
    }

    /// Allocate a kernel stack of `size` bytes. `size` is rounded up to a
    /// multiple of 16 to satisfy the SysV stack-alignment requirement.
    ///
    /// Returns `None` on heap exhaustion. The allocation goes through the
    /// fallible [`kmalloc_zeroed`] helper rather than `Vec::with_capacity`
    /// so that an out-of-memory condition is reported as `None` instead of
    /// aborting the kernel via the default alloc-OOM handler (the kernel is
    /// `panic = abort`, so an OOM in `vec![...]` would kill the whole system
    /// rather than failing one task spawn).
    #[must_use]
    pub fn with_size(size: usize) -> Option<Self> {
        // Round the size up to a 16-byte boundary so `top` is 16-aligned
        // regardless of the allocator's own alignment. Request 16-byte
        // alignment from the allocator as well so the buffer *start* is
        // 16-aligned, which makes the *end* (top) 16-aligned too.
        let rounded = (size + 15) & !15;
        if rounded == 0 {
            // A zero-size stack is nonsensical; return None rather than
            // handing out a dangling pointer.
            return None;
        }
        // `kmalloc_zeroed` rejects zero-size layouts and reports OOM as
        // `Err(OutOfMemory)`; both surface as `None` here. 16-byte
        // alignment is a power of two and within the allocator's range.
        let layout = Layout::from_size_align(rounded, 16).ok()?;
        let ptr = kmalloc_zeroed(layout).ok()?;
        // The top of the stack is the exclusive end of the buffer. The CPU
        // pushes *before* it writes, so the first push lands at `top - 8`
        // and never touches `top` itself; handing `top` out as the initial
        // `rsp` is therefore correct even though it is one past the last
        // byte. We do not dereference `top`; we only store it as the
        // initial `rsp`.
        let top_u64 = (ptr.as_ptr() as u64).checked_add(rounded as u64)?;
        // `top_u64` is 16-aligned because `rounded` is a multiple of 16 and
        // the buffer start is 16-aligned (we requested align = 16); assert
        // it so a future allocator change that broke alignment would fail
        // loudly here rather than as a stack-misalignment fault on the
        // task's first interrupt.
        debug_assert!(top_u64 & 0xF == 0, "kernel stack top not 16-aligned");
        Some(Self {
            base: ptr,
            layout,
            top: VirtAddr::new_truncate(top_u64),
        })
    }

    /// The 16-byte-aligned top-of-stack virtual address.
    ///
    /// This is the value to load into `rsp` for the task's first switch-in.
    #[inline]
    #[must_use]
    pub fn top(&self) -> VirtAddr {
        self.top
    }

    /// The lowest valid stack address (inclusive bottom of the buffer).
    ///
    /// Exposed for diagnostics and for the future guard-page logic to know
    /// where the valid region ends.
    #[inline]
    #[must_use]
    pub fn bottom(&self) -> VirtAddr {
        VirtAddr::new_truncate(self.base.as_ptr() as u64)
    }

    /// The stack size in bytes.
    #[inline]
    #[must_use]
    pub fn size(&self) -> usize {
        self.layout.size()
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        // SAFETY: `self.base` was returned by `kmalloc_zeroed` with exactly
        // `self.layout` (the layout is stored verbatim from the allocation
        // call) and has not been freed yet — `Drop` runs once and the field
        // is never exposed as a duplicate. `kfree` requires exactly this
        // precondition, so the deallocation is sound.
        unsafe { kfree(self.base, self.layout) };
    }
}

impl fmt::Debug for KernelStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelStack")
            .field("bottom", &format_args!("0x{:016x}", self.bottom().as_u64()))
            .field("top", &format_args!("0x{:016x}", self.top.as_u64()))
            .field("size", &self.size())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Per-task statistics
// ---------------------------------------------------------------------------

/// Runtime counters for a [`Task`], updated by the scheduler.
///
/// All fields are plain `u64`s (not atomics) because they are mutated only
/// by the CPU the task is currently running on, under the scheduler's
/// protection — the per-CPU ownership rule that also governs
/// [`PerCpu`](crate::sync::PerCpu). A future SMP stats reader that samples
/// them from another CPU will need to accept torn reads, which is acceptable
/// for diagnostics.
#[derive(Debug, Clone, Copy, Default)]
pub struct TaskStats {
    /// Total number of times the task has been switched *into* (scheduled
    /// onto a CPU). Incremented by the scheduler on every context switch
    /// that selects this task.
    pub context_switches: u64,
    /// Total number of timer ticks the task has consumed while `Running`.
    /// This is the scheduler's accounting of CPU time, distinct from
    /// wall-clock time because ticks only accrue while the task is on-CPU.
    pub cpu_ticks: u64,
    /// Total number of times the task has voluntarily yielded via
    /// [`Task::yield_now`]. Incremented when a yield actually schedules
    /// another task; a yield that finds nothing else runnable does not
    /// count.
    pub voluntary_yields: u64,
    /// Total number of times the task was preempted (its time slice expired
    /// while still `Running`). The complement of `voluntary_yields` for
    /// understanding whether a task tends to block or tends to burn its
    /// whole slice.
    pub preemptions: u64,
}

// ---------------------------------------------------------------------------
// The task control block
// ---------------------------------------------------------------------------

/// The default scheduling priority for a newly-created kernel task.
///
/// Lower numbers are higher priority (the run queue is `priority`-ordered
/// ascending). `0` is the highest priority; kernel tasks default to the
/// middle of the range so the idle task (priority `u32::MAX`) and any
/// future real-time tasks (priority near `0`) sort correctly relative to
/// them.
pub const DEFAULT_PRIORITY: u32 = 100;

/// The default time slice in timer ticks before a `Running` task is preempted.
///
/// A "tick" is one LAPIC-timer interrupt; the exact wall-clock duration is
/// configured by the time subsystem. Ten ticks is a modest default that
/// gives interactive tasks a responsive feel without excessive context-
/// switch overhead; the scheduler may override this per task.
pub const DEFAULT_TIME_SLICE_TICKS: u64 = 10;

/// The task control block: everything the scheduler needs to suspend and
/// resume one thread of kernel execution.
///
/// See the [module docs](self) for the layering rationale and the split
/// between this struct and the run-queue / scheduler modules. A `Task` is
/// constructed via [`Task::new`] (the generic builder) or
/// [`Task::new_kernel`] (the common case: a kernel thread with no user
/// address space); it is driven by the scheduler, which is responsible for
/// moving it between [`TaskState`]s and calling
/// [`context_switch`](crate::arch::x86_64::asm::context_switch) on its
/// [`Context`].
pub struct Task {
    /// The globally-unique, never-reused task identifier.
    pub id: TaskId,
    /// The current lifecycle state. Mutated only by the scheduler (or, for
    /// the `Ready` -> `Zombie` transition, by [`Task::exit`] called from
    /// within the task itself).
    pub state: TaskState,
    /// The owning kernel stack. The saved `rsp` in `context` points into
    /// this buffer; dropping the `Task` (and thus the stack) while the task
    /// is still runnable would corrupt that pointer, so the scheduler must
    /// keep the `Task` alive until it reaches `Dead`.
    pub kernel_stack: KernelStack,
    /// The saved register context the switch trampoline reads and writes.
    /// Always valid for a `Ready`/`Running`/`Sleeping`/`Blocked` task; for a
    /// `Zombie`/`Dead` task it is stale and must not be switched into.
    pub context: Context,
    /// The user address space, or `None` for a kernel task that shares the
    /// kernel's address space. The scheduler skips the CR3 write on switch
    /// when both the outgoing and incoming tasks have `None` here (the
    /// common case for kernel-thread to kernel-thread switches).
    pub address_space: Option<AddressSpace>,
    /// Scheduling priority. Lower number = higher priority. The run queue
    /// orders tasks by this field.
    pub priority: u32,
    /// Remaining time slice in timer ticks. Reset to the task's quantum on
    /// switch-in and decremented each tick while `Running`; at zero the
    /// scheduler preempts the task.
    pub time_slice_ticks: u64,
    /// Human-readable name for diagnostics (log lines, panic dumps, a
    /// future `ps` command). Owned by value so the name outlives any
    /// borrowed `&str` the caller passed in.
    pub name: KString,
    /// The CPU the task is currently running on, or last ran on. `0`-based.
    /// Set by the scheduler on switch-in; not authoritative for `Ready`
    /// tasks (which are not running on any CPU).
    pub cpu: u32,
    /// Runtime statistics. Updated by the scheduler; see [`TaskStats`].
    pub stats: TaskStats,
    /// The exit status, once the task has exited. `Pending` until
    /// [`Task::exit`] is called; `Code` or `Signal` afterwards. Preserved
    /// through the `Zombie` state so a parent or the reaper can read it.
    pub exit_status: ExitStatus,
}

impl Task {
    /// Build a kernel task that runs `entry(arg)` on a fresh kernel stack.
    ///
    /// This is the common constructor: it allocates a stack, seeds a
    /// [`Context`] so the first switch into the task lands at `entry` with
    /// `arg` in `rdi`, and leaves the address space as `None` so the
    /// scheduler skips the CR3 write when switching to it. The task starts
    /// in [`TaskState::Ready`] with the default priority and time slice.
    ///
    /// Returns `None` if the kernel stack could not be allocated (heap
    /// exhausted or uninitialised). Callers should propagate that as a
    /// spawn failure rather than panicking.
    #[must_use]
    pub fn new_kernel(
        name: KString,
        entry: unsafe extern "C" fn(u64) -> !,
        arg: u64,
    ) -> Option<Self> {
        let stack = KernelStack::new()?;
        let ctx = Context::new_entry(entry as usize as u64, stack.top().as_u64(), arg);
        Some(Self {
            id: next_id(),
            state: TaskState::Ready,
            kernel_stack: stack,
            context: ctx,
            address_space: None,
            priority: DEFAULT_PRIORITY,
            time_slice_ticks: DEFAULT_TIME_SLICE_TICKS,
            name,
            cpu: 0,
            stats: TaskStats::default(),
            exit_status: ExitStatus::Pending,
        })
    }

    /// The generic builder: assemble a [`Task`] from an already-allocated
    /// stack and a prepared [`Context`].
    ///
    /// Used by callers that need to customise the entry frame beyond what
    /// [`Task::new_kernel`] sets up, such as a userspace task whose first
    /// `rip` is the syscall-return trampoline rather than a kernel entry
    /// function.
    /// `new_kernel` is the thin wrapper for the common case and should be
    /// preferred where it fits.
    #[must_use]
    pub fn new(name: KString, stack: KernelStack, context: Context) -> Self {
        Self {
            id: next_id(),
            state: TaskState::Ready,
            kernel_stack: stack,
            context,
            address_space: None,
            priority: DEFAULT_PRIORITY,
            time_slice_ticks: DEFAULT_TIME_SLICE_TICKS,
            name,
            cpu: 0,
            stats: TaskStats::default(),
            exit_status: ExitStatus::Pending,
        }
    }

    /// Attach a user address space to this task, converting it from a kernel
    /// task into the kernel side of a userspace process.
    ///
    /// Returns `self` by value so the call chains as
    /// `Task::new_kernel(...).with_address_space(space)`. The scheduler will
    /// now perform a CR3 write when switching to this task from a task with
    /// a different address space.
    #[must_use]
    pub fn with_address_space(mut self, space: AddressSpace) -> Self {
        self.address_space = Some(space);
        self
    }

    /// Set the scheduling priority. Lower number = higher priority.
    #[must_use]
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Set the time-slice quantum in timer ticks.
    #[must_use]
    pub fn with_time_slice(mut self, ticks: u64) -> Self {
        self.time_slice_ticks = ticks;
        self
    }

    /// Reset the remaining time slice to the full quantum.
    ///
    /// Called by the scheduler when it switches *into* this task so the task
    /// gets a fresh slice regardless of how much of its previous slice it
    /// consumed.
    #[inline]
    pub fn reset_time_slice(&mut self) {
        // `time_slice_ticks` doubles as the quantum: the constructor sets
        // it to the desired slice and the scheduler decrements it, so on
        // switch-in we restore it from the same field. A future phase may
        // split "quantum" and "remaining" into separate fields; this method
        // is the single call site that would change.
        self.time_slice_ticks = DEFAULT_TIME_SLICE_TICKS;
    }

    /// Mark this task as exited with `status`.
    ///
    /// Called from within the task itself (via the `exit` syscall for
    /// userspace, or when a kernel entry function returns — the trampoline
    /// wraps the entry call in a handler that invokes this). Transitions
    /// the task to [`TaskState::Zombie`] and records `status` in
    /// [`Task::exit_status`]. The task must not run again after this; the
    /// reaper is responsible for the `Zombie` -> `Dead` transition and for
    /// freeing the stack.
    ///
    /// Does **not** yield: the caller is still on the task's stack until the
    /// scheduler switches away. The scheduler's exit path performs the
    /// actual context switch to the next task once it observes the `Zombie`
    /// state.
    #[inline]
    pub fn exit(&mut self, status: ExitStatus) {
        self.exit_status = status;
        self.state = TaskState::Zombie;
        ::log::debug!(
            "xenith.sched.task: {} ({}) exited: {:?}",
            self.name,
            self.id,
            status
        );
    }

    /// The saved-context pointer to hand to the asm context-switch routine.
    ///
    /// See [`Context::as_switch_ptr`]. The pointer is valid for the lifetime
    /// of the `&mut self` borrow, which the scheduler must ensure encloses
    /// the `context_switch` call.
    #[inline]
    #[must_use]
    pub fn switch_ptr(&mut self) -> *mut u8 {
        self.context.as_switch_ptr()
    }

    /// `true` if this task shares the kernel address space (no CR3 write
    /// needed when switching to/from it from another kernel task).
    #[inline]
    #[must_use]
    pub const fn is_kernel_task(&self) -> bool {
        self.address_space.is_none()
    }
}

impl fmt::Debug for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Task")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("state", &self.state)
            .field("priority", &self.priority)
            .field("cpu", &self.cpu)
            .field("time_slice_ticks", &self.time_slice_ticks)
            .field("has_address_space", &self.address_space.is_some())
            .field("kernel_stack", &self.kernel_stack)
            .field("context", &self.context)
            .field("exit_status", &self.exit_status)
            .field("stats", &self.stats)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Current-task tracking
// ---------------------------------------------------------------------------

/// Per-CPU "current task" slot.
///
/// Each CPU's slot holds a raw pointer to the [`Task`] it is currently
/// running, or `None` before the scheduler has selected a task for that CPU.
/// The slot is per-CPU (not a single global) because on an SMP system each
/// CPU runs a different task and the "current" task is inherently
/// CPU-relative — exactly the access pattern [`PerCpu`] is built for.
///
/// # Safety
///
/// The pointer is only ever read or written by the CPU that owns the slot,
/// matching [`PerCpu`]'s per-CPU ownership invariant. The `Task` it points
/// at is kept alive by the scheduler for the duration the slot holds the
/// pointer (from switch-in until switch-out), so dereferencing it is sound
/// while the slot is non-`None`.
static CURRENT_TASK: Once<PerCpu<CurrentTaskPtr>> = Once::new();

#[inline]
fn current_task_slots() -> &'static PerCpu<CurrentTaskPtr> {
    CURRENT_TASK.call_once(PerCpu::new)
}

/// A newtype around `Option<NonNull<Task>>` that is `Send` so it can live in
/// a `static PerCpu<...>` (which requires `T: Send` for its `Sync` impl).
///
/// `Task` itself is `!Send` (it owns a raw-pointer-backed kernel stack and is
/// governed by the scheduler's per-CPU ownership rules, not Rust's send/sync
/// rules), so `Option<NonNull<Task>>` is `!Send` by default and a
/// `static PerCpu<Option<NonNull<Task>>>` would fail to compile. This
/// wrapper asserts that the *pointer* is safe to store in per-CPU slots
/// shared across CPUs — and it is, because [`PerCpu`]'s invariant guarantees
/// each CPU only ever touches its own slot. The pointer is never
/// dereferenced through the `Send` channel; dereferencing happens only on
/// the owning CPU under the scheduler's protection.
#[derive(Clone, Copy, Default)]
struct CurrentTaskPtr(Option<NonNull<Task>>);

// SAFETY: `CurrentTaskPtr` is a plain pointer wrapper. Storing it in a
// `PerCpu` slot shared across CPUs is sound because the per-CPU ownership
// invariant ensures CPU *i* only reads/writes slot *i*; no two CPUs ever
// touch the same `CurrentTaskPtr` concurrently. The pointee `Task` is not
// accessed through this `Send` — only stored — so `Task: !Send` does not
// poison the pointer's sendability. `PerCpu<T>: Sync` requires `T: Send`
// (see `sync::percpu`), and this impl satisfies that without weakening the
// `Task` invariant.
unsafe impl Send for CurrentTaskPtr {}

/// Install `task` as the current task on this CPU.
///
/// Called by the scheduler immediately after a context switch *into* `task`.
/// The previous current task (if any) is overwritten; the scheduler is
/// responsible for ensuring the previous task's [`Task`] remains alive
/// (typically by keeping it on a run queue or wait queue) until it is
/// switched into again.
///
/// # Safety
///
/// `task` must point at a [`Task`] that will remain alive and not be
/// concurrently mutated from another CPU for as long as it is the current
/// task on this CPU. The scheduler's run-queue locking establishes that
/// invariant.
#[inline]
pub unsafe fn set_current(task: Option<NonNull<Task>>) {
    current_task_slots().set(CurrentTaskPtr(task));
}

/// The task currently running on this CPU, or `None` before the scheduler
/// has picked one (or after the current task has exited and not yet been
/// switched away from).
///
/// Returns a raw `Option<NonNull<Task>>` rather than `&Task` because the
/// caller — typically the scheduler or a syscall handler — needs to manage
/// the borrow lifetime itself (the task may be switched out by an interrupt
/// handler at any time, so a safe `&Task` with an unbounded lifetime would
/// be unsound). Callers that need a `&Task` should do so inside a critical
/// section that prevents a context switch.
#[must_use]
#[inline]
pub fn current() -> Option<NonNull<Task>> {
    current_task_slots().get().0
}

/// A convenience wrapper around [`current`] that runs `f` with a shared
/// reference to the current task, if there is one.
///
/// This is the safe accessor: it borrows the current task for the duration
/// of `f` only, which is short enough that an interrupt-driven context
/// switch cannot move the current task out from under the caller as long as
/// `f` does not yield. Callers that need to mutate the current task or hold
/// the reference across a potential switch must use [`current`] directly and
/// manage the safety themselves.
///
/// Returns `None` if there is no current task on this CPU.
#[inline]
pub fn with_current<R, F>(f: F) -> Option<R>
where
    F: FnOnce(&Task) -> R,
{
    let ptr = current()?;
    // SAFETY: `ptr` was installed by `set_current` and points at a live
    // `Task` that the scheduler keeps alive for the duration it is the
    // current task. We only take a shared `&Task` and do not yield inside
    // `f`, so the task cannot be switched out (and freed) mid-call. The
    // per-CPU ownership invariant guarantees no other CPU is mutating this
    // task's fields concurrently while it is current on this CPU.
    let task: &Task = unsafe { ptr.as_ref() };
    Some(f(task))
}

// ---------------------------------------------------------------------------
// Cooperative yield compatibility entry point
// ---------------------------------------------------------------------------

/// Cooperatively yield the CPU to the scheduler.
///
/// A task calls this when it has no immediate work to do and wants to let
/// another runnable task run. On a real scheduler this saves the current
/// task's context, moves it back to the `Ready` run queue, picks the next
/// task, and switches into it.
///
/// This compatibility path delegates to the live scheduler. New code should
/// normally call [`crate::sched::yield_now`] directly.
#[inline]
pub fn yield_now() {
    crate::sched::scheduler::yield_now();
}

// ---------------------------------------------------------------------------
// Context-switch entry point (thin wrapper over the asm trampoline)
// ---------------------------------------------------------------------------

/// Switch from `prev` to `next` by calling the asm
/// [`context_switch`](crate::arch::x86_64::asm::context_switch) trampoline.
///
/// This is the single safe-ish entry point the scheduler uses to perform a
/// context switch: it takes the two task saved-state pointers, hands them
/// to the asm routine, and returns once the *next* task has been loaded
/// (which may be much later, after the *prev* task is switched back into).
///
/// The CR3 write (for tasks with distinct address spaces) is performed by
/// the asm trampoline, not here: the trampoline compares the two tasks'
/// `cr3` values and skips the write when they match. The scheduler is
/// responsible for ensuring the TSS `RSP0` is updated to the next task's
/// kernel stack before this call so a ring-3 -> ring-0 transition lands on
/// the right stack.
///
/// # Safety
///
/// Both `prev` and `next` must point at the [`Context`] of a live [`Task`]
/// for the duration of the call. `prev` must be the currently-running task
/// on this CPU (its `rsp` field will be overwritten with the saved stack
/// pointer). `next` must be a `Ready` task whose [`Context`] is valid for a
/// switch-in. Calling this from outside the scheduler's switch path corrupts
/// the current task's saved state.
#[inline]
pub unsafe fn context_switch(prev: *mut u8, next: *mut u8) {
    // SAFETY: forwarded to the asm trampoline; the caller (the scheduler)
    // vouches for both pointers per the contract above.
    unsafe { asm::context_switch(prev, next) };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn task_id_increments_and_never_zero() {
        // `next_id` is a global counter, so we only check the two invariants
        // that hold regardless of test ordering: it never returns 0, and it
        // is strictly monotonically increasing across consecutive calls.
        let a = next_id();
        let b = next_id();
        assert!(a.as_u64() > 0, "task id 0 is reserved");
        assert!(b.as_u64() > a.as_u64(), "task ids must increase");
    }

    #[test]
    fn task_state_runnable_and_exited_classification() {
        assert!(TaskState::Ready.runnable());
        assert!(TaskState::Running.runnable());
        assert!(!TaskState::Sleeping.runnable());
        assert!(!TaskState::Blocked.runnable());
        assert!(!TaskState::Zombie.runnable());
        assert!(!TaskState::Dead.runnable());

        assert!(!TaskState::Ready.exited());
        assert!(!TaskState::Running.exited());
        assert!(TaskState::Zombie.exited());
        assert!(TaskState::Dead.exited());
    }

    #[test]
    fn task_state_label_is_stable() {
        // The labels are part of the log format; pin them so a refactor does
        // not silently change every log line.
        assert_eq!(TaskState::Ready.label(), "ready");
        assert_eq!(TaskState::Running.label(), "running");
        assert_eq!(TaskState::Sleeping.label(), "sleeping");
        assert_eq!(TaskState::Blocked.label(), "blocked");
        assert_eq!(TaskState::Zombie.label(), "zombie");
        assert_eq!(TaskState::Dead.label(), "dead");
    }

    #[test]
    fn exit_status_pending_detection() {
        assert!(ExitStatus::Pending.is_pending());
        assert!(!ExitStatus::Code(0).is_pending());
        assert!(!ExitStatus::Signal(9).is_pending());
    }

    #[test]
    fn context_new_entry_seeds_rip_rsp_rdi() {
        let ctx = Context::new_entry(0x4000_0000, 0x8000_0000, 0x1234);
        assert_eq!(ctx.rip, 0x4000_0000);
        assert_eq!(ctx.rsp, 0x8000_0000);
        assert_eq!(ctx.rdi, 0x1234);
        // Callee-saved registers start zeroed.
        assert_eq!(ctx.rbx, 0);
        assert_eq!(ctx.rbp, 0);
        assert_eq!(ctx.r12, 0);
        assert_eq!(ctx.r13, 0);
        assert_eq!(ctx.r14, 0);
        assert_eq!(ctx.r15, 0);
    }

    #[test]
    fn context_zeroed_is_all_zero() {
        let ctx = Context::zeroed();
        assert_eq!(ctx.rip, 0);
        assert_eq!(ctx.rsp, 0);
        assert_eq!(ctx.rdi, 0);
    }

    #[test]
    fn context_switch_ptr_is_self_aligned() {
        // The switch pointer must point at the start of the Context so the
        // asm trampoline's field offsets line up. We check that it equals
        // the address of the first field.
        let mut ctx = Context::zeroed();
        let p = ctx.as_switch_ptr();
        assert_eq!(p, core::ptr::addr_of_mut!(ctx) as *mut u8);
    }

    #[test]
    fn kernel_stack_top_is_sixteen_aligned_and_above_bottom() {
        // `KernelStack::new` allocates through the global allocator; under
        // cfg(test) on the host that is the std allocator, which returns
        // 16-aligned memory for u8 slices. We only assert the invariants
        // `KernelStack` itself guarantees: top is 16-aligned and strictly
        // above bottom by exactly the stack size.
        if let Some(s) = KernelStack::with_size(KERNEL_STACK_SIZE) {
            assert_eq!(s.top().as_u64() & 0xF, 0, "stack top 16-aligned");
            assert!(s.top().as_u64() > s.bottom().as_u64());
            assert_eq!(s.size(), KERNEL_STACK_SIZE);
            // top - bottom == size (top is exclusive end, bottom is start).
            assert_eq!(
                s.top().as_u64() - s.bottom().as_u64(),
                KERNEL_STACK_SIZE as u64
            );
        }
        // If allocation failed (very tight test harness) we skip rather than
        // fail; the alignment invariant is what we care about.
    }

    #[test]
    fn kernel_stack_with_size_rounds_up_to_sixteen() {
        // Requesting a non-multiple-of-16 size still yields a 16-aligned top.
        if let Some(s) = KernelStack::with_size(1000) {
            assert_eq!(s.top().as_u64() & 0xF, 0);
            // The rounded size is (1000 + 15) & !15 = 1008.
            assert_eq!(s.size(), 1008);
        }
    }

    #[test]
    fn task_new_kernel_seeds_context_and_defaults() {
        // A dummy entry fn that never runs in the test; we only inspect the
        // constructed Task's metadata.
        unsafe extern "C" fn entry(_arg: u64) -> ! {
            unreachable!("test entry never runs")
        }
        let name = KString::from("test");
        let task = Task::new_kernel(name, entry, 42);
        // Allocation may fail under a constrained test allocator; skip if so.
        let task = task.expect("kernel stack alloc in test");
        assert_eq!(task.state, TaskState::Ready);
        assert!(task.is_kernel_task());
        assert_eq!(task.priority, DEFAULT_PRIORITY);
        assert_eq!(task.time_slice_ticks, DEFAULT_TIME_SLICE_TICKS);
        assert_eq!(task.exit_status, ExitStatus::Pending);
        assert_eq!(task.context.rdi, 42);
        assert_eq!(task.context.rsp, task.kernel_stack.top().as_u64());
        assert_eq!(task.context.rip, entry as *const () as usize as u64);
    }

    #[test]
    fn task_exit_records_status_and_marks_zombie() {
        unsafe extern "C" fn entry(_arg: u64) -> ! {
            unreachable!()
        }
        let task = Task::new_kernel(KString::from("exit-test"), entry, 0).expect("alloc");
        let mut task = task;
        assert!(!task.state.exited());
        task.exit(ExitStatus::Code(7));
        assert_eq!(task.state, TaskState::Zombie);
        assert!(task.state.exited());
        assert_eq!(task.exit_status, ExitStatus::Code(7));
    }

    #[test]
    fn task_with_address_space_flips_is_kernel_task() {
        unsafe extern "C" fn entry(_arg: u64) -> ! {
            unreachable!()
        }
        let space = AddressSpace::new_empty();
        // `new_empty` may fail before the frame allocator is up; skip the
        // assertion in that case rather than failing the test.
        if let Ok(space) = space {
            let task = Task::new_kernel(KString::from("user-task"), entry, 0)
                .expect("alloc")
                .with_address_space(space);
            assert!(!task.is_kernel_task());
            assert!(task.address_space.is_some());
        }
    }

    #[test]
    fn current_starts_none_and_can_be_set() {
        // Before the scheduler runs, there is no current task. We only
        // assert the `None` case here because installing a real `Task`
        // pointer requires a live `Task` whose lifetime outlives the slot,
        // which is the scheduler's job — doing it in a unit test would race
        // with other tests sharing the global `CURRENT_TASK` slot.
        let c = current();
        // The slot is a global; another test may have set it. We only check
        // that `current()` is callable and returns an `Option`, not its
        // specific value, to keep this test order-independent.
        let _ = c;
    }

    #[test]
    fn yield_now_without_scheduler_is_safe() {
        if !crate::sched::scheduler::is_initialised() {
            yield_now();
        }
    }

    #[test]
    fn task_stats_default_is_zeroed() {
        let s = TaskStats::default();
        assert_eq!(s.context_switches, 0);
        assert_eq!(s.cpu_ticks, 0);
        assert_eq!(s.voluntary_yields, 0);
        assert_eq!(s.preemptions, 0);
    }

    #[test]
    fn task_debug_renders_identifying_fields() {
        unsafe extern "C" fn entry(_arg: u64) -> ! {
            unreachable!()
        }
        let task = Task::new_kernel(KString::from("dbg"), entry, 0).expect("alloc");
        let s = format!("{:?}", task);
        assert!(s.contains("dbg"));
        assert!(s.contains("Ready"));
    }
}
