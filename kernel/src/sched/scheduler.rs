//! The Xenith scheduler core: per-CPU run queues, the current-task slot,
//! timer-tick accounting, and the context-switch dispatch path.
//!
//! This module owns the *policy* that decides which task runs next and the
//! *mechanism* that performs the switch. It builds on three sibling modules:
//!
//! * [`super::context`] — the [`Context`] saved-register image that the
//!   `arch/x86_64/asm/context_switch.S` trampoline reads and writes. The
//!   scheduler stores one [`Context`] per task and hands its address to the
//!   trampoline on every dispatch.
//! * [`super::task`] — the [`Task`] control block: identity, lifecycle state,
//!   priority, the owning kernel stack, and exit status. The scheduler drives
//!   tasks through their [`TaskState`] transitions but does not own the struct
//!   layout; it wraps each `Task` in a [`TaskNode`] (defined here) that adds
//!   the run-queue link storage and the asm-matching saved context.
//! * [`super::preempt`] — the preemption counter, the `need_resched` flag, and
//!   the timer-tick entry point. The BSP calls back into [`tick`] once per
//!   global tick while every CPU keeps its own preemption counters; all CPUs
//!   may call [`schedule_next`]. This module never reads the LAPIC timer
//!   itself, so the hardware dependency stays isolated in `preempt`.
//!
//! # The run queue
//!
//! Each CPU has its own [`RunQueue`], a single intrusive doubly-linked list of
//! [`TaskNode`]s in FIFO (round-robin) order. [`RunQueue::enqueue`] appends to
//! the tail and [`RunQueue::pop_front`] removes the head, so equal-priority
//! tasks rotate in the order they became ready. Enqueue is O(1); the
//! intrusive-list ownership model (nodes heap-allocated and owned by the
//! master task list, the queue holding only raw pointers) keeps it allocation-
//! free on the hot path.
//!
//! # The priority bump (aging)
//!
//! To prevent a steady stream of newly-ready tasks from starving an older
//! runnable task, the BSP-owned [`tick`] walks every online run queue and
//! bumps `wait_ticks` for every queued task. When a task has waited longer than
//! [`AGING_THRESHOLD_TICKS`], its `priority` value is decremented by one
//! (lower number = higher priority, saturating at zero) and it is promoted to
//! the head of the queue via [`RunQueue::promote_front`], so it is the next
//! task `pop_front` returns. This is the "round-robin with a priority bump"
//! the design calls for: round-robin in arrival order, with aging that jumps a
//! starved task ahead of the rotation so it cannot wait forever.
//!
//! # Sleeping tasks
//!
//! [`sleep_until`] moves the current task off the run queue onto a separate
//! [`SleepQueue`] keyed by wake deadline. [`tick`] scans the sleep queue each
//! tick and re-enqueues any task whose deadline has elapsed. The sleep queue
//! is a simple unsorted `KVec` of node pointers; a sorted timer-wheel is a
//! future optimisation and the linear scan is fine for the modest number of
//! simultaneously-sleeping kernel tasks we expect.
//!
//! # The global scheduler and locking
//!
//! A single [`SCHEDULER`] static wraps a [`SchedulerInner`] in a plain
//! [`SpinLock`](crate::sync::SpinLock). The lock is **not** held across the
//! context switch — holding it across `context_switch` would leave the lock
//! bit set while the outgoing task is suspended, deadlocking the incoming
//! task's own `lock()` acquisition. Instead every public entry point manages
//! the interrupt-enable flag itself: [`save_flags_and_cli`] snapshots RFLAGS
//! and clears IF on entry, the lock is taken purely for the run-queue
//! manipulation and released before the switch, and [`restore_flags`]
//! re-applies the snapshot on the resuming side. The switch itself runs with
//! interrupts off and no lock held.
//!
//! [`tick`] and [`schedule_next`] are reachable from timer interrupt handlers,
//! which run with `EFLAGS.IF` already clear (the IDT gate is an interrupt
//! gate). Only CPU 0 runs the shared [`tick`] pass, avoiding one global-lock
//! acquisition per AP per tick; local slice accounting remains per-CPU.
//!
//! Per-CPU state that does *not* need cross-CPU consistency — the current
//! task pointer and first-dispatch bootstrap context — lives in fixed arrays
//! indexed by the GS-derived compact CPU id. Each CPU touches only its own
//! slot with interrupts disabled during dispatch.
//!
//! # Safety posture
//!
//! The context switch is the one genuinely unsafe operation here. The
//! scheduler upholds the [`Context::switch`] contract by ensuring both
//! contexts are live, non-aliased, and that the incoming task's saved `rsp`
//! refers to a valid mapped stack. Switching is always performed with
//! interrupts disabled and the scheduler lock released, so no other CPU can
//! observe a half-switched state and no IRQ on this CPU can re-enter the
//! scheduler mid-switch.

// `alloc` is linked at the `mm` root (`extern crate alloc` in `mm::mod`); reach
// the collection aliases through `crate::mm` so this file does not introduce a
// second `extern crate alloc` declaration.
use core::cell::UnsafeCell;
use core::fmt;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::context::Context;
use super::preempt;
use super::task::{ExitStatus, Task, TaskId, TaskState};
use crate::arch::x86_64::{hlt, percpu, sti, tss, Cr3};
use crate::mm::{KString, KVec, Kbox};
use crate::sync::{current_cpu, MAX_CPUS};
use crate::time::Instant;

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// How many timer ticks a ready task may wait on the run queue before its
/// priority is bumped (aged) by one level.
///
/// At the conventional scheduler tick this is roughly the threshold at which a
/// runnable task is considered to be "starving" and gets a priority boost so
/// it sorts ahead of younger same-or-higher-priority work. The value is a
/// per-kernel default; a future tuning phase may make it per-CPU or per-task.
pub const AGING_THRESHOLD_TICKS: u64 = 20;

/// The scheduler tick rate in Hz, used to arm the LAPIC timer.
///
/// `100` is the traditional Unix scheduler frequency: a 10 ms slice at the
/// default quantum, fine-grained enough for interactive responsiveness and
/// coarse enough that context-switch overhead is negligible. The value is
/// published here so [`super::init`] and the LAPIC timer arming agree.
pub const SCHED_TICK_HZ: u64 = 100;

/// Logical CPU that owns wall-clock scheduler accounting.
///
/// CPU 0 already exclusively advances the LAPIC monotonic accumulator. Xenith
/// does not offline the BSP, so using the same interrupt for sleep expiry and
/// run-queue aging keeps those operations at exactly [`SCHED_TICK_HZ`] instead
/// of multiplying global-lock acquisitions by the number of online CPUs.
const GLOBAL_TICK_CPU: usize = 0;

/// Whether `cpu` owns the shared scheduler tick.
///
/// Kept as a pure policy function so SMP scaling can be verified by host tests
/// without executing privileged timer or per-CPU instructions.
#[inline]
pub(crate) const fn owns_global_tick(cpu: usize) -> bool {
    cpu == GLOBAL_TICK_CPU
}

/// Include the permanently-online BSP in a topology snapshot.
///
/// During early bring-up the SMP online mask is published immediately after
/// the scheduler timer is armed. Treating CPU 0 as online unconditionally
/// makes the policy robust across that short interrupts-disabled interval.
#[inline]
const fn scheduler_online_mask(observed: u64) -> u64 {
    observed | (1u64 << GLOBAL_TICK_CPU)
}

/// Keep a woken task on its last CPU when possible, otherwise use the BSP.
#[inline]
const fn wake_target_cpu(last_cpu: usize, online: u64) -> usize {
    if last_cpu < MAX_CPUS && online & (1u64 << last_cpu) != 0 {
        last_cpu
    } else {
        GLOBAL_TICK_CPU
    }
}

// ---------------------------------------------------------------------------
// TaskNode — the scheduler's per-task wrapper
// ---------------------------------------------------------------------------

/// The scheduler-internal wrapper around a [`Task`].
///
/// A `TaskNode` owns the [`Task`] control block (which in turn owns the kernel
/// stack) and adds the two pieces of state the scheduler needs that do not
/// belong on the task struct itself:
///
/// * [`ctx`](Self::ctx) — the [`Context`] saved-register image that the
///   `context_switch` asm trampoline reads and writes. This is the
///   asm-matching layout from [`super::context`], distinct from the
///   `task::Context` field on [`Task`] which the sibling `task` module uses
///   for its own first-frame bookkeeping. The scheduler switches through
///   *this* `Context` because its layout is the one the assembly addresses by
///   fixed byte offset.
/// * [`links`](Self::links) — the [`LinkEntry`](crate::util::LinkEntry) that
///   threads the node into a [`RunQueue`]. One entry is enough because a task
///   is on exactly one queue (run queue *or* sleep queue *or* the current
///   slot) at any time.
///
/// Plus the bookkeeping for sleeping and aging: `wake_deadline` and
/// `wait_ticks`.
///
/// `TaskNode` is heap-allocated (`Kbox<TaskNode>`) so its address is stable
/// for the duration of its membership in a run queue; the intrusive list holds
/// `NonNull<TaskNode>` raw pointers into that stable heap allocation. The
/// master [`SchedulerInner::all_tasks`] vector owns the `Kbox`es; moving a
/// `Kbox` within the vector (e.g. during swap-remove reap) moves only the
/// ownership handle, never the heap data, so the raw pointers stay valid.
pub struct TaskNode {
    /// The task control block: identity, state, priority, kernel stack.
    pub task: Kbox<Task>,
    /// The asm-matching saved-register image. `rsp` points into
    /// `task.kernel_stack`; the rest of the callee-saved file is zeroed until
    /// the first switch-out populates it.
    pub ctx: Context,
    /// Run-queue / sleep-queue link storage. `None`-initialised; the intrusive
    /// list mutates this through the [`Links`] impl below.
    pub links: crate::util::LinkEntry<TaskNode>,
    /// The kernel-thread entry point and its argument. Stored here so the
    /// scheduler's first-switch trampoline ([`task_trampoline`]) can find them
    /// via the per-CPU current-node slot and dispatch into the real entry.
    pub entry: unsafe extern "C" fn(u64) -> !,
    /// The argument passed to `entry` on the task's first switch-in.
    pub arg: u64,
    /// The monotonic deadline at which a `Sleeping` task should be woken, or
    /// `None` when the task is not sleeping. Set by [`sleep_until`], cleared
    /// when [`tick`] re-enqueues the task.
    pub wake_deadline: Option<Instant>,
    /// Timer ticks this task has spent `Ready` on the run queue without being
    /// dispatched. Reset to zero on dispatch; bumped by [`tick`] for every
    /// queued task; drives the priority-bump aging in [`tick`].
    pub wait_ticks: u64,
    /// One-shot generic interrupt wake credit.
    ///
    /// Signal delivery does not hold every producer lock a task may be
    /// sleeping behind. If it races just before an explicit-event park, the
    /// scheduler records this credit while holding its own lock; the park
    /// path consumes it instead of blocking. This closes that cross-lock
    /// lost-wake window without polling.
    interrupt_pending: bool,
    /// Eager, feature-sized x87/SSE/AVX image. Keeping this on the live
    /// scheduler node makes FP state follow task migration and lets signal
    /// delivery materialize a CR0.TS-armed task before building its frame.
    fpu: Option<crate::arch::x86_64::fpu::FpuSaveArea>,
    /// `true` once the node's `ctx` has been initialised for a first switch.
    /// Until then the node is a fresh spawn whose `ctx` was built by
    /// [`Context::new`] and whose trampoline has not yet run.
    pub started: bool,
}

impl TaskNode {
    /// Construct a scheduler node wrapping a freshly-spawned kernel task.
    ///
    /// `task` must already own its kernel stack; `entry` and `arg` are stored
    /// for the trampoline. The saved [`Context`] is built by [`Context::new`]
    /// against the task's stack top and the scheduler trampoline, so the first
    /// `ret` into the task lands in [`task_trampoline`] with `rsp` correctly
    /// aligned.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `task.kernel_stack.top()` points at a
    /// writable, mapped, 16-byte-aligned stack region that remains valid for
    /// the lifetime of this node. [`Task::new_kernel`] establishes that when
    /// it allocates the stack, so the public [`spawn`] path is safe.
    pub unsafe fn new(
        task: Kbox<Task>,
        entry: unsafe extern "C" fn(u64) -> !,
        arg: u64,
    ) -> Option<Self> {
        let stack_top = task.kernel_stack.top();
        // SAFETY: `stack_top` is the 16-aligned top of the task's owned kernel
        // stack; `task_trampoline` is a valid `unsafe extern "C" fn() -> !`.
        // `Context::new` writes the entry address to `stack_top - 16`, which
        // is inside the stack the `Task` owns and not concurrently touched.
        let ctx = unsafe { Context::new(stack_top, task_trampoline) };
        #[cfg(not(test))]
        let fpu = Some(crate::arch::x86_64::fpu::FpuSaveArea::new().ok()?);
        // Host scheduler unit tests do not run privileged FPU bring-up or the
        // assembly switch; retaining `None` keeps their metadata tests pure.
        #[cfg(test)]
        let fpu = crate::arch::x86_64::fpu::FpuSaveArea::new().ok();
        Some(Self {
            task,
            ctx,
            links: crate::util::LinkEntry::new(),
            entry,
            arg,
            wake_deadline: None,
            wait_ticks: 0,
            interrupt_pending: false,
            fpu,
            started: false,
        })
    }

    /// The task's identity, for logging and lookup.
    #[inline]
    pub fn id(&self) -> TaskId {
        self.task.id
    }

    /// A stable raw pointer to this node, for enqueuing into an intrusive list.
    ///
    /// Valid as long as the owning `Kbox<TaskNode>` is alive (i.e. the node is
    /// in `SchedulerInner::all_tasks`).
    #[inline]
    pub fn as_nonnull(&mut self) -> NonNull<TaskNode> {
        // SAFETY: `self` is a live, non-null `&mut`; the pointer is non-null.
        // The caller (the scheduler) guarantees the `Kbox` stays alive while
        // the pointer is in a queue.
        unsafe { NonNull::new_unchecked(self as *mut TaskNode) }
    }
}

impl fmt::Debug for TaskNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskNode")
            .field("id", &self.task.id)
            .field("name", &self.task.name)
            .field("state", &self.task.state)
            .field("priority", &self.task.priority)
            .field("started", &self.started)
            .field("wait_ticks", &self.wait_ticks)
            .field("interrupt_pending", &self.interrupt_pending)
            .field("wake_deadline", &self.wake_deadline)
            .finish()
    }
}

// Thread the `TaskNode` into an `IntrusiveLinkedList` via its `links` field.
// The list only ever touches the `LinkEntry`; every other field is private to
// the scheduler.
impl crate::util::Links for TaskNode {
    fn links(&self) -> &crate::util::LinkEntry<TaskNode> {
        &self.links
    }
    fn links_mut(&mut self) -> &mut crate::util::LinkEntry<TaskNode> {
        &mut self.links
    }
}

// ---------------------------------------------------------------------------
// The first-switch trampoline
// ---------------------------------------------------------------------------

/// The entry point every freshly-spawned task begins executing at.
///
/// [`Context::new`] arranges the new task's stack so the first `ret` out of
/// `context_switch` lands here. The trampoline reads the per-CPU current-node
/// slot (which the scheduler populated before the switch) to recover the real
/// kernel-thread entry point and its argument, then dispatches into it. This
/// indirection exists because the asm switch can only `ret` to a single
/// address — it cannot set `rdi` — so a per-task trampoline is the standard
/// way to bridge from "switch into a fresh context" to "call entry(arg)".
///
/// The function diverges (`-> !`): a kernel thread that returns would fall off
/// the end of its stack frame, so the entry contract requires `-> !`. Tasks
/// that want to terminate call [`exit`] explicitly, which never returns into
/// the entry.
///
/// # Safety
///
/// This is only ever reached as the first instruction of a freshly-switched-in
/// task. The scheduler guarantees [`current_node`] returns `Some` pointing at
/// the node that owns this task, and that `node.entry` is a sound
/// `unsafe extern "C" fn(u64) -> !`. Calling it from any other context is
/// undefined.
unsafe extern "C" fn task_trampoline() -> ! {
    // We are now executing on the freshly-selected task's stack with
    // interrupts still disabled.  Any task that exited immediately before
    // this first dispatch can therefore be destroyed without freeing the
    // stack beneath the CPU.
    reclaim_retired_after_switch();
    let node_ptr = current_node().expect("sched: trampoline with no current task");
    // Read the entry point and argument through a shared borrow, then end the
    // borrow before the `started` write below. Keeping the `&TaskNode` alive
    // across a raw-pointer mutation of the same `TaskNode` would alias a
    // shared reference against a mutable access, which the borrow model
    // forbids; copying the two `Copy` values out first lets the borrow drop.
    // SAFETY: `node_ptr` was installed by the scheduler immediately before the
    // switch into this task and points at the live `TaskNode` that owns us.
    // We are the only CPU touching it (per-CPU slot) and no switch can happen
    // before this read completes.
    let (entry, arg) = {
        let node: &TaskNode = unsafe { node_ptr.as_ref() };
        (node.entry, node.arg)
    };
    // Mark the node as having started so a subsequent switch-out knows the
    // `ctx` is now a real saved frame rather than the synthetic first-frame.
    // The shared borrow above has ended, so this raw-pointer write does not
    // alias any live Rust reference.
    // SAFETY: the field is only mutated here (first entry) or from the
    // scheduler on the same CPU with interrupts off; no race is possible.
    unsafe {
        let started = core::ptr::addr_of_mut!((*node_ptr.as_ptr()).started);
        *started = true;
    }
    // Re-enable interrupts before dispatching into the entry. The scheduler
    // switched in with `EFLAGS.IF` clear (the dispatch path's `cli`); a kernel
    // thread expects to run with interrupts on so the timer tick and device
    // IRQs reach it. `sti` is the one-instruction-shadow-safe way to do this.
    // SAFETY: `sti` sets IF at CPL 0 with IOPL 0 — valid in any kernel
    // context. The IDT is loaded and the per-CPU stack is valid, so accepting
    // interrupts here is safe.
    unsafe { sti() };
    // SAFETY: `entry` is the kernel-thread entry the spawner registered; the
    // spawner vouches for its soundness as a `fn(u64) -> !`.
    unsafe { entry(arg) }
}

// ---------------------------------------------------------------------------
// Current-task slot
// ---------------------------------------------------------------------------

/// The current task node on this CPU, stored as the raw `NonNull<TaskNode>`
/// pointer in an atomic.
///
/// This uses a const-constructible atomic array rather than
/// [`crate::sync::PerCpu`], whose generic constructors use `array::from_fn`.
/// The compact logical id selects one slot for each online CPU.
///
/// The pointer is only ever read or written by the owning CPU, and the
/// scheduler keeps the `Kbox<TaskNode>` alive in `all_tasks` for the entire
/// duration the slot holds the pointer, so dereferencing a loaded non-zero
/// value is sound. `0` is the "no current task" sentinel.
static CURRENT_NODE: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Task awaiting destruction after each CPU's next completed stack switch.
///
/// A task cannot free its own kernel stack.  [`exit`] publishes its stable
/// `TaskNode` pointer here while interrupts are disabled, then switches away.
/// The incoming context drains the same CPU's slot before enabling interrupts.
/// One slot per CPU is sufficient: a second task cannot begin executing on a
/// CPU until the incoming context has drained the predecessor's slot.
static RETIRED_TASK: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// The task node currently running on this CPU, or `None` if the scheduler has
/// not yet dispatched a task (or the current task has just exited and not been
/// switched away from).
///
/// Returns a raw `Option<NonNull<TaskNode>>` because the caller must manage
/// the borrow lifetime: a context switch can replace the current task at any
/// interrupt boundary, so a safe `&TaskNode` with an unbounded lifetime would
/// be unsound. Callers that need a brief shared access should use
/// [`with_current_node`].
#[inline]
#[must_use]
pub fn current_node() -> Option<NonNull<TaskNode>> {
    let v = CURRENT_NODE[current_cpu()].load(Ordering::Acquire);
    if v == 0 {
        None
    } else {
        // SAFETY: a non-zero value was stored by `set_current_node` as the
        // raw representation of a valid `NonNull<TaskNode>` pointing at a
        // node kept alive in `all_tasks`. Reconstructing the `NonNull` is
        // sound because the store preserved a non-null pointer.
        Some(unsafe { NonNull::new_unchecked(v as *mut TaskNode) })
    }
}

/// Run `f` with a shared reference to the current task node, if there is one.
///
/// This is the safe accessor: the borrow lasts only for the duration of `f`,
/// which is short enough that an interrupt-driven switch cannot move the
/// current task out from under the caller as long as `f` does not yield or
/// enable preemption. Returns `None` if there is no current task on this CPU.
#[inline]
pub fn with_current_node<R, F>(f: F) -> Option<R>
where
    F: FnOnce(&TaskNode) -> R,
{
    let ptr = current_node()?;
    // SAFETY: `ptr` was installed by the scheduler and points at a live
    // `TaskNode` kept alive by `all_tasks`. We take only a shared `&TaskNode`
    // and do not yield inside `f`, so the node cannot be reaped mid-call. The
    // per-CPU ownership invariant excludes concurrent mutation from another
    // CPU while the node is current on this CPU.
    let node: &TaskNode = unsafe { ptr.as_ref() };
    Some(f(node))
}

/// Install `node` as the current task on this CPU.
///
/// Called by the scheduler immediately before a context switch *into* `node`.
/// The previous current task (if any) is overwritten; the scheduler must keep
/// the previous node alive (on a run queue or sleep queue) until it is
/// switched into again.
///
/// # Safety
///
/// `node` must point at a [`TaskNode`] that will remain alive and not be
/// concurrently mutated from another CPU for as long as it is the current
/// task on this CPU. The scheduler's locking establishes that invariant.
#[inline]
pub unsafe fn set_current_node(node: Option<NonNull<TaskNode>>) {
    let v = match node {
        Some(p) => p.as_ptr() as u64,
        None => 0,
    };
    CURRENT_NODE[current_cpu()].store(v, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Bootstrap context
// ---------------------------------------------------------------------------

/// The saved-register image used as the "old" context for a CPU's very first
/// context switch, before that CPU has dispatched a task.
///
/// The first [`schedule_next`] has no current task to switch out of, so it
/// switches from this placeholder. The switch writes the CPU's then-current
/// callee-saved state into it; that state is never resumed because the
/// scheduler always has a real task or the idle task to run afterwards. The
/// context is `UnsafeCell` because the switch needs `&mut` access without a
/// lock. Every CPU owns a distinct array slot and switches with interrupts
/// disabled, preventing same-CPU re-entry.
///
/// The newtype wrapper exists so we can attach a manual `unsafe impl Sync`:
/// `UnsafeCell<Context>` is `!Sync` by default (interior mutability), and a
/// `static` requires its type to be `Sync`. The wrapper is ours, so the impl
/// is not an orphan.
struct BootstrapCtx(UnsafeCell<Context>);

impl BootstrapCtx {
    /// Construct the bootstrap context, zeroed.
    const fn new() -> Self {
        Self(UnsafeCell::new(Context::empty()))
    }

    /// `&mut` access to the saved-register image inside.
    ///
    /// # Safety
    ///
    /// The caller must access only the running CPU's slot and must prevent
    /// re-entrant access, in practice by keeping interrupts disabled across
    /// every switch.
    #[inline]
    unsafe fn get_mut(&self) -> &'static mut Context {
        // SAFETY: caller guarantees exclusive, interrupt-disabled access.
        unsafe { &mut *self.0.get() }
    }
}

// SAFETY: Each array element is touched only by its owning CPU, with
// interrupts disabled across the switch, so no two accessors race one
// `UnsafeCell`.
unsafe impl Sync for BootstrapCtx {}

static BOOTSTRAP_CTX: [BootstrapCtx; MAX_CPUS] = [const { BootstrapCtx::new() }; MAX_CPUS];

/// A mutable reference to this CPU's bootstrap context.
///
/// # Safety
///
/// The caller must prevent same-CPU re-entrant access, in practice by holding
/// interrupts off as the scheduler does across every switch.
#[inline]
unsafe fn bootstrap_ctx() -> &'static mut Context {
    // SAFETY: the logical CPU id chooses a private slot and interrupts are
    // disabled, so there is no concurrent or re-entrant access.
    unsafe { BOOTSTRAP_CTX[current_cpu()].get_mut() }
}

// ---------------------------------------------------------------------------
// RunQueue — per-CPU FIFO run queue with aging-based promotion
// ---------------------------------------------------------------------------

/// A per-CPU run queue: ready tasks in FIFO (round-robin) order, with aging
/// that promotes starved tasks to the front.
///
/// The queue is a single [`IntrusiveLinkedList`] of [`TaskNode`]s.
/// [`enqueue`](Self::enqueue) appends to the tail (round-robin: a newly-ready
/// task goes behind everything already waiting) and
/// [`pop_front`](Self::pop_front) removes the head — the next task to run.
/// Priority influences scheduling through aging: [`tick_aging`](Self::tick_aging)
/// bumps each queued task's `wait_ticks` and, when a task has waited past
/// [`AGING_THRESHOLD_TICKS`], decrements its `priority` and moves it to the
/// head via [`promote_front`](Self::promote_front). This is the "round-robin
/// with a priority bump": equal-priority tasks rotate in arrival order, and a
/// task that would otherwise starve jumps ahead once it has waited long
/// enough.
///
/// The list holds raw `NonNull<TaskNode>` pointers into the heap-allocated
/// nodes owned by [`SchedulerInner::all_tasks`]; the queue itself owns nothing
/// and is `Copy`-free. A node is on at most one queue at a time (run queue,
/// sleep queue, or the current slot), enforced by the `LinkEntry` membership
/// flag in the intrusive list.
pub struct RunQueue {
    queue: crate::util::IntrusiveLinkedList<TaskNode>,
}

impl RunQueue {
    /// Construct an empty run queue.
    pub const fn new() -> Self {
        Self {
            queue: crate::util::IntrusiveLinkedList::new(),
        }
    }

    /// Number of ready tasks on this queue.
    #[inline]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// `true` if there are no ready tasks.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Append `node` to the tail of the run queue (round-robin order).
    ///
    /// The queue is a single FIFO list: a newly-ready task goes to the back
    /// and [`pop_front`](Self::pop_front) takes the front, so equal-priority
    /// tasks rotate in the order they became ready. Priority influences
    /// scheduling through aging in [`tick`], which promotes a starved task to
    /// the front via [`promote_front`](Self::promote_front) rather than through
    /// a sorted insert. This keeps enqueue O(1) and avoids the ordered-insert
    /// traversal a priority-sorted list would need.
    ///
    /// The node must be unlinked (not currently on any queue). After this call
    /// the node is linked into this queue and its `wait_ticks` is reset to
    /// zero so aging starts fresh for this readiness episode.
    pub fn enqueue(&mut self, mut node: NonNull<TaskNode>) {
        // Reset aging: a task that just became ready starts a fresh wait.
        // SAFETY: we have exclusive access to the node (it is unlinked and the
        // caller — the scheduler — holds the lock that serialises access), so
        // a mutable borrow through the `NonNull` is sound.
        unsafe { node.as_mut() }.wait_ticks = 0;
        self.queue.push_back(node);
    }

    /// Move `node` to the front of the queue (the priority-bump promotion).
    ///
    /// Called by [`tick`] when a task's `wait_ticks` crosses the aging
    /// threshold: the task is unlinked from its current position and pushed
    /// to the head, so it is the next task [`pop_front`] returns. This is the
    /// "priority bump" — a starved runnable task jumps ahead of the round-
    /// robin order instead of waiting behind younger work.
    ///
    /// # Safety
    ///
    /// `node` must be a member of this queue.
    #[inline]
    pub unsafe fn promote_front(&mut self, node: NonNull<TaskNode>) {
        // SAFETY: caller asserts `node` is linked into this queue.
        unsafe { self.queue.remove(node) };
        self.queue.push_front(node);
    }

    /// Remove and return the next task to run (the head), or `None` if empty.
    #[inline]
    pub fn pop_front(&mut self) -> Option<NonNull<TaskNode>> {
        self.queue.pop_front()
    }

    /// Remove `node` from this queue if it is linked.
    ///
    /// # Safety
    ///
    /// `node` must be a member of this queue.
    #[inline]
    #[allow(dead_code)] // Public API; used by future migration/diagnostics paths.
    pub unsafe fn remove(&mut self, node: NonNull<TaskNode>) {
        unsafe { self.queue.remove(node) };
    }

    /// Borrowing iterator over the ready tasks, head to tail.
    #[inline]
    #[allow(dead_code)] // Public API; used by future diagnostics/`ps` paths.
    pub fn iter(&self) -> crate::util::LinkedIter<'_, TaskNode> {
        self.queue.iter()
    }

    /// Advance the aging counter for every ready task and promote starved ones
    /// to the front (the "priority bump").
    ///
    /// For each task on the queue this bumps `wait_ticks` by one. When a
    /// task's `wait_ticks` reaches [`AGING_THRESHOLD_TICKS`] and its
    /// `priority` is still above zero, its `priority` is decremented (lower
    /// number = higher priority), its `wait_ticks` is reset, and it is moved
    /// to the head of the queue so [`pop_front`](Self::pop_front) returns it
    /// next. Multiple promotions in one tick preserve their original relative
    /// order at the front (the front-most aged task stays front-most) because
    /// the promotions are applied in reverse collection order.
    ///
    /// The walk is in-place: it does not pop-and-re-enqueue non-aged tasks, so
    /// the round-robin order of the unaffected tasks is preserved across the
    /// tick. Each node's fields are read through a short-lived shared borrow
    /// that ends before the `wait_ticks` write, so no shared reference is
    /// held across a raw-pointer mutation.
    pub fn tick_aging(&mut self) {
        // Collect the nodes to promote during the walk, then apply the
        // promotions after the walk so we never hold `&TaskNode` across a
        // `remove`/`push_front` (which need `&mut self.queue`).
        let mut to_promote: KVec<NonNull<TaskNode>> = KVec::new();
        // Walk via raw `head`/`links.next` pointers rather than `iter()` so we
        // can end each shared borrow before mutating `wait_ticks`.
        let mut cur = self.queue.head();
        while let Some(node) = cur {
            // Read the fields we need through a short-lived shared borrow.
            // SAFETY: `node` is a live, linked member of this queue; we hold
            // `&mut self` so no other accessor can touch the list.
            let (wait_ticks, priority, next) = {
                let n = unsafe { node.as_ref() };
                (n.wait_ticks, n.task.priority, n.links.next)
            };
            // Bump `wait_ticks` via the raw pointer. The shared borrow above
            // has ended, so this mutation does not alias any live reference.
            // SAFETY: we hold `&mut self` (exclusive access to the queue) and
            // the node is a member of this queue; no other CPU can reach it
            // because the scheduler lock is held by the caller.
            unsafe {
                (*node.as_ptr()).wait_ticks = wait_ticks.saturating_add(1);
            }
            if wait_ticks.saturating_add(1) >= AGING_THRESHOLD_TICKS && priority > 0 {
                to_promote.push(node);
            }
            cur = next;
        }
        // Apply promotions in reverse order so the front-most aged task (the
        // first collected) ends up at the very front. The priority bump and
        // `wait_ticks` reset go through raw pointers (no `&self` borrow), then
        // `promote_front` moves the node to the head.
        for node in to_promote.into_iter().rev() {
            // SAFETY: `node` is still a member of this queue (we have not
            // removed anything yet, and each promotion is independent). We
            // hold `&mut self`, and the raw-pointer writes do not alias any
            // live Rust reference because the walk's shared borrows have ended.
            unsafe {
                let task = core::ptr::addr_of_mut!((*node.as_ptr()).task);
                (*task).priority = priority_bump((*task).priority);
                (*node.as_ptr()).wait_ticks = 0;
                self.promote_front(node);
            }
        }
    }
}

/// Decrement a priority value by one for aging, saturating at zero.
///
/// Lower numbers are higher priority, so a "bump" decrements the value. Zero
/// is the floor: a task already at the highest priority cannot be bumped
/// further. Kept as a free function so the saturation policy is in one place.
#[inline]
fn priority_bump(priority: u32) -> u32 {
    priority.saturating_sub(1)
}

impl Default for RunQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RunQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunQueue")
            .field("len", &self.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// SleepQueue — unsorted list of sleeping tasks keyed by wake deadline
// ---------------------------------------------------------------------------

/// The queue of tasks waiting for a [`Instant`] deadline to elapse.
///
/// Stored as a flat `KVec` of node pointers. [`tick`] scans it linearly each
/// tick; for the modest number of simultaneously-sleeping kernel tasks this is
/// fine and avoids the complexity of a sorted timer wheel. A future
/// high-resolution-timer phase can replace this with a hierarchical wheel
/// without changing [`sleep_until`]'s signature.
pub struct SleepQueue {
    entries: KVec<NonNull<TaskNode>>,
}

impl SleepQueue {
    /// Construct an empty sleep queue.
    ///
    /// `const` so the scheduler inner state can be built in a `static`
    /// initializer. `KVec::new` (i.e. `alloc::vec::Vec::new`) is itself
    /// `const`, so this is a trivial pass-through.
    pub const fn new() -> Self {
        Self {
            entries: KVec::new(),
        }
    }

    /// Add a sleeping task with the given wake deadline.
    pub fn add(&mut self, mut node: NonNull<TaskNode>, deadline: Instant) {
        // SAFETY: the scheduler holds the lock; `node` is live and not on the
        // run queue (the caller moved it off before sleeping), so a mutable
        // borrow through the `NonNull` is sound.
        let n = unsafe { node.as_mut() };
        n.wait_ticks = 0;
        // Record the deadline on the node itself so `drain_expired` can read it
        // without a side table.
        n.wake_deadline = Some(deadline);
        self.entries.push(node);
    }

    /// Remove every task whose wake deadline has elapsed without allocating.
    ///
    /// Each removed pointer is passed immediately to `wake`. This avoids a
    /// temporary vector (and potentially growing the heap) in timer IRQ
    /// context while retaining a single O(n) scan.
    fn drain_expired<F>(&mut self, now: Instant, mut wake: F)
    where
        F: FnMut(NonNull<TaskNode>),
    {
        let mut i = 0;
        while i < self.entries.len() {
            let node = self.entries[i];
            // SAFETY: `node` is live; we hold the scheduler lock.
            let dl = unsafe { node.as_ref() }.wake_deadline;
            if dl.is_some_and(|deadline| deadline <= now) {
                // SAFETY: the node remains live in `all_tasks`; clearing the
                // deadline is part of moving it to a run queue.
                unsafe { (*node.as_ptr()).wake_deadline = None };
                wake(self.entries.swap_remove(i));
            } else {
                i += 1;
            }
        }
    }

    /// Remove one sleeping task by id without allocating.
    ///
    /// Device interrupt paths use this narrow operation to wake a known
    /// worker.  `swap_remove` keeps the operation bounded by the number of
    /// sleepers and does not grow or allocate a side buffer.
    fn take_task(&mut self, id: TaskId) -> Option<NonNull<TaskNode>> {
        let index = self.entries.iter().position(|node| {
            // SAFETY: every entry is owned by `SchedulerInner::all_tasks` and
            // the scheduler lock protects both its lifetime and task fields.
            unsafe { node.as_ref() }.task.id == id
        })?;
        let node = self.entries.swap_remove(index);
        // SAFETY: the node remains live in `all_tasks`; clearing the deadline
        // is part of moving it from the sleep queue to a run queue.
        unsafe { (*node.as_ptr()).wake_deadline = None };
        Some(node)
    }

    /// Number of tasks currently sleeping.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether no tasks are currently sleeping.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for SleepQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SleepQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SleepQueue")
            .field("len", &self.entries.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// BlockedQueue — allocation-free event waits
// ---------------------------------------------------------------------------

/// Tasks parked on an explicit event, optionally with a timeout.
///
/// Unlike [`SleepQueue`], this queue is intrusive: parking a task only links
/// its existing [`TaskNode`] and therefore cannot allocate. That property is
/// required by IRQ-driven waits, whose producer must also be able to unlink a
/// known waiter without allocating. A task is linked here only while its state
/// is [`TaskState::Blocked`].
struct BlockedQueue {
    queue: crate::util::IntrusiveLinkedList<TaskNode>,
}

impl BlockedQueue {
    const fn new() -> Self {
        Self {
            queue: crate::util::IntrusiveLinkedList::new(),
        }
    }

    fn add(&mut self, mut node: NonNull<TaskNode>, deadline: Option<Instant>) {
        // SAFETY: the scheduler lock is held, `node` is the current task and
        // therefore unlinked, and no other CPU may mutate its metadata.
        let node_ref = unsafe { node.as_mut() };
        node_ref.wait_ticks = 0;
        node_ref.wake_deadline = deadline;
        self.queue.push_back(node);
    }

    /// Remove a waiter by id. The scan and unlink are allocation-free.
    fn take_task(&mut self, id: TaskId) -> Option<NonNull<TaskNode>> {
        let mut current = self.queue.head();
        while let Some(node) = current {
            // Read the next link before removal invalidates this node's list
            // membership. The scheduler lock keeps the list stable.
            let (task_id, next) = {
                // SAFETY: every linked node remains owned by `all_tasks`.
                let node_ref = unsafe { node.as_ref() };
                (node_ref.task.id, node_ref.links.next)
            };
            if task_id == id {
                // SAFETY: `node` is a member of this queue and the scheduler
                // lock gives us exclusive access to its links.
                unsafe { self.queue.remove(node) };
                // SAFETY: the node remains live and is now unlinked.
                unsafe { (*node.as_ptr()).wake_deadline = None };
                return Some(node);
            }
            current = next;
        }
        None
    }

    /// Remove one expired timed waiter, if any, without allocating.
    fn take_expired(&mut self, now: Instant) -> Option<NonNull<TaskNode>> {
        let mut current = self.queue.head();
        while let Some(node) = current {
            let (expired, next) = {
                // SAFETY: every linked node remains owned by `all_tasks`.
                let node_ref = unsafe { node.as_ref() };
                (
                    node_ref
                        .wake_deadline
                        .is_some_and(|deadline| deadline <= now),
                    node_ref.links.next,
                )
            };
            if expired {
                // SAFETY: `node` is linked in this queue under our exclusive
                // scheduler-lock ownership.
                unsafe { self.queue.remove(node) };
                // SAFETY: the node remains live and is now unlinked.
                unsafe { (*node.as_ptr()).wake_deadline = None };
                return Some(node);
            }
            current = next;
        }
        None
    }

    #[inline]
    fn len(&self) -> usize {
        self.queue.len()
    }
}

// ---------------------------------------------------------------------------
// SchedulerInner — the lock-protected shared state
// ---------------------------------------------------------------------------

/// The shared scheduler state protected by [`SCHEDULER`].
///
/// All cross-CPU state lives here: the per-CPU run queues, the sleep queue,
/// the master task list that owns every `TaskNode`, the per-CPU idle-task
/// pointers, and the "scheduler initialised" flag. The current-task pointer
/// is *not* here — it lives in the per-CPU [`CURRENT_NODE`] slot, because it
/// is touched on every switch without contending the lock.
pub struct SchedulerInner {
    /// One run queue per possible CPU. Indexed by [`current_cpu`]. Only the
    /// online CPUs' queues are ever touched; the rest stay empty.
    run_queues: [RunQueue; MAX_CPUS],
    /// Tasks waiting on a wake deadline.
    sleep_queue: SleepQueue,
    /// Tasks waiting for an explicit event, optionally with a timeout. This
    /// queue is intrusive so park/wake and timer expiry never allocate.
    blocked_queue: BlockedQueue,
    /// Master ownership list of every spawned `TaskNode`. A `TaskNode` is
    /// alive (and its raw pointers are valid) for exactly as long as its
    /// `Kbox` is in this vector. Reaping moves the `Kbox` out and drops it,
    /// freeing the task's kernel stack.
    all_tasks: KVec<Kbox<TaskNode>>,
    /// The idle task node for each CPU, or `None` before [`init`] creates it.
    /// The idle task is never destroyed, so these pointers stay valid for the
    /// kernel's lifetime once installed.
    idle_tasks: [Option<NonNull<TaskNode>>; MAX_CPUS],
    /// `true` once [`init`] has brought the scheduler up. Public operations
    /// before this are programmer errors and assert in debug builds.
    initialised: bool,
}

// SAFETY: every pointer stored in SchedulerInner refers to a TaskNode owned
// by `all_tasks`; all access and cross-CPU migration is serialized by the
// global scheduler lock. Moving the container between CPUs cannot expose an
// unguarded pointee.
unsafe impl Send for SchedulerInner {}

impl SchedulerInner {
    /// Construct the uninitialised inner state. Every run queue and idle slot
    /// starts empty; [`init`] populates the BSP's idle task and flips
    /// `initialised`.
    ///
    /// `const` so the whole inner state can back the [`SCHEDULER`] `static`
    /// via `SpinLock::new`. The run-queue array uses the inline-const
    /// repeat syntax (`[const { RunQueue::new() }; N]`) because `RunQueue`
    /// is not `Copy` (it owns an intrusive list) and `array::from_fn` is not
    /// `const`; the idle-task array is `Copy` so a plain repeat suffices.
    const fn new() -> Self {
        Self {
            run_queues: [const { RunQueue::new() }; MAX_CPUS],
            sleep_queue: SleepQueue::new(),
            blocked_queue: BlockedQueue::new(),
            all_tasks: KVec::new(),
            idle_tasks: [None; MAX_CPUS],
            initialised: false,
        }
    }

    /// Borrow the run queue for the current CPU.
    fn current_run_queue(&mut self) -> &mut RunQueue {
        let cpu = current_cpu();
        debug_assert!(cpu < MAX_CPUS, "current_cpu out of range");
        &mut self.run_queues[cpu]
    }

    /// Borrow the idle task pointer for the current CPU.
    fn current_idle(&self) -> Option<NonNull<TaskNode>> {
        let cpu = current_cpu();
        debug_assert!(cpu < MAX_CPUS, "current_cpu out of range");
        self.idle_tasks[cpu]
    }
}

impl fmt::Debug for SchedulerInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchedulerInner")
            .field("initialised", &self.initialised)
            .field("total_tasks", &self.all_tasks.len())
            .field("sleeping", &self.sleep_queue.len())
            .field("blocked", &self.blocked_queue.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// The global scheduler
// ---------------------------------------------------------------------------

/// The global scheduler state.
///
/// Wrapped in a plain [`SpinLock`] rather than an IRQ-safe lock, because the
/// lock must **not** be held across the context switch. Holding an IRQ-safe
/// guard across `context_switch` would leave the lock bit set while the
/// outgoing task is suspended — and the incoming task would then spin forever
/// trying to acquire the same bit. The classic deadlock a scheduler must
/// avoid.
///
/// Instead, every public entry point manages the interrupt-enable flag
/// itself: [`save_flags_and_cli`] snapshots RFLAGS and clears IF on entry,
/// the lock is taken purely for the run-queue manipulation, the lock is
/// **released before** the context switch, and [`restore_flags`] re-applies
/// the snapshot on the resuming side. The switch itself therefore runs with
/// interrupts off and no lock held — exactly the contract the asm trampoline
/// and the rest of the kernel expect.
static SCHEDULER: crate::sync::SpinLock<SchedulerInner> =
    crate::sync::SpinLock::new(SchedulerInner::new());

/// `true` once [`init`] has run and the scheduler is dispatching tasks.
///
/// Distinct from `SchedulerInner::initialised` (which is protected by the
/// lock): this atomic lets [`is_initialised`] answer without taking the lock,
/// which matters for callers in early-boot paths that must not spin.
static SCHED_INITIALISED: AtomicBool = AtomicBool::new(false);

/// Rotating tie-breaker for equally loaded online run queues.
static NEXT_PLACEMENT_CPU: AtomicU64 = AtomicU64::new(0);

/// Coalesced explicit-event wake request. Task id zero means no request.
///
/// Xenith currently has one exclusive UI input seat, hence at most one task
/// can be parked on the IRQ-driven event path. The atomic bridges a hard IRQ
/// that cannot take the scheduler lock: every scheduler guard drains it after
/// releasing the lock, while an uncontended producer drains it directly.
static PENDING_BLOCKED_WAKE: AtomicU64 = AtomicU64::new(0);

/// The boot CPU's kernel page-table root, captured before the first task runs.
///
/// Kernel tasks do not own an [`AddressSpace`](crate::mm::AddressSpace), so a
/// switch from userspace back to a kernel task needs this explicit CR3 rather
/// than inheriting the outgoing process's page tables. Xenith currently shares
/// one kernel PML4 across all CPUs; when per-CPU kernel roots land this becomes
/// part of the architecture per-CPU area.
static KERNEL_CR3: AtomicU64 = AtomicU64::new(0);

/// Result of a non-blocking device-IRQ wake attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqWakeResult {
    /// The task was sleeping and is now ready on the interrupting CPU.
    Woken,
    /// The task is running, ready, exited, or otherwise not on the sleep queue.
    NotSleeping,
    /// Another CPU owns the scheduler lock; the IRQ path did not spin.
    Contended,
}

/// `true` once the scheduler is up and dispatching tasks.
#[inline]
#[must_use]
pub fn is_initialised() -> bool {
    SCHED_INITIALISED.load(Ordering::Acquire)
}

/// Lock the global scheduler and return a guard.
///
/// Callers must have already disabled interrupts via [`save_flags_and_cli`]
/// (or be already in an interrupt-off context such as the timer IRQ handler).
/// The lock is a plain `SpinLock`; it does not touch EFLAGS, so the interrupt
/// state established by the caller is preserved across the critical section.
/// The guard must be dropped **before** a context switch.
#[inline]
fn lock() -> SchedulerLockGuard {
    SchedulerLockGuard {
        guard: Some(SCHEDULER.lock()),
    }
}

fn try_lock() -> Option<SchedulerLockGuard> {
    Some(SchedulerLockGuard {
        guard: Some(SCHEDULER.try_lock()?),
    })
}

/// Scheduler guard with an unlock-then-drain hand-off for deferred IRQ wakes.
///
/// Releasing the raw spinlock before checking `PENDING_BLOCKED_WAKE` is
/// deliberate. A producer that races after unlock either acquires the raw lock
/// itself or observes the next owner; it can never fall between the final
/// pending check and a still-held lock.
struct SchedulerLockGuard {
    guard: Option<crate::sync::SpinLockGuard<'static, SchedulerInner>>,
}

impl core::ops::Deref for SchedulerLockGuard {
    type Target = SchedulerInner;

    fn deref(&self) -> &Self::Target {
        self.guard.as_deref().expect("scheduler guard consumed")
    }
}

impl core::ops::DerefMut for SchedulerLockGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard.as_deref_mut().expect("scheduler guard consumed")
    }
}

impl Drop for SchedulerLockGuard {
    fn drop(&mut self) {
        // Release first. See the type-level comment for the race proof.
        drop(self.guard.take());
        drain_pending_blocked_wakes();
    }
}

/// Wake one known sleeping worker from hard-IRQ context without blocking.
///
/// The scheduler lock is attempted exactly once.  On contention the caller
/// must retain its work-pending flag and rely on a periodic polling deadline
/// or a later interrupt; spinning in a hard IRQ could deadlock against the
/// CPU that owns the lock.  A successful wake performs no allocation: the
/// existing node is removed from the flat sleep queue and linked directly
/// onto this CPU's run queue.
#[must_use]
pub fn wake_sleeping_task_from_irq(id: TaskId) -> IrqWakeResult {
    let Some(mut inner) = try_lock() else {
        return IrqWakeResult::Contended;
    };
    let Some(node) = inner.sleep_queue.take_task(id) else {
        return IrqWakeResult::NotSleeping;
    };
    let cpu = current_cpu();
    // SAFETY: `node` was just unlinked from the sleep queue, remains owned by
    // `all_tasks`, and the scheduler lock gives exclusive metadata access.
    unsafe {
        (*node.as_ptr()).task.state = TaskState::Ready;
        (*node.as_ptr()).task.cpu = cpu as u32;
    }
    inner.run_queues[cpu].enqueue(node);
    drop(inner);
    preempt::set_need_resched();
    IrqWakeResult::Woken
}

/// Request a wake for a task parked by [`block_current_until_releasing`].
///
/// This is safe in a hard IRQ even when another CPU owns the scheduler lock:
/// it publishes the task id atomically and makes one non-blocking drain
/// attempt. Every scheduler guard performs an unlock-then-drain hand-off, so a
/// contended request is consumed by the owner as it releases the lock and can
/// never be lost. The request slot coalesces duplicate wakes for Xenith's one
/// exclusive UI waiter. No path allocates or spins behind a remote lock.
pub fn wake_blocked_task(id: TaskId) {
    if id.as_u64() == 0 {
        return;
    }
    let previous = PENDING_BLOCKED_WAKE.swap(id.as_u64(), Ordering::AcqRel);
    debug_assert!(
        previous == 0 || previous == id.as_u64(),
        "multiple explicit event waiters exceed the coalesced wake slot"
    );

    let flags = save_flags_and_cli();
    drain_pending_blocked_wakes();
    // SAFETY: `flags` was captured on this CPU at entry.
    unsafe { restore_flags(flags) };
}

/// Wake one explicitly blocked task from ordinary task context.
///
/// Unlike [`wake_blocked_task`], this path may wait briefly for the scheduler
/// lock and therefore supports any number of independent waiters without a
/// coalescing slot. It is intended for process-state producers such as child
/// exit and signal delivery, never for hard IRQ handlers. The wake is
/// allocation-free and returns the task to the CPU where it last ran.
///
/// A caller may still hold the IRQ-safe lock that protects its readiness
/// predicate. Such wait paths acquire that producer lock before the scheduler
/// lock both while parking and while waking, so the ordering is consistent and
/// the registration-to-block hand-off cannot lose an event.
#[must_use]
pub fn wake_blocked_task_from_task(id: TaskId) -> bool {
    if id.as_u64() == 0 {
        return false;
    }

    let flags = save_flags_and_cli();
    let target_cpu = {
        let mut inner = lock();
        inner.blocked_queue.take_task(id).map(|node| {
            // Keep the task on its last CPU for cache locality. A blocked
            // task's CPU remains online for the lifetime of today's static
            // SMP topology.
            let target_cpu = unsafe { node.as_ref() }.task.cpu as usize;
            // SAFETY: `node` was just unlinked from the blocked queue,
            // remains owned by `all_tasks`, and the scheduler lock excludes
            // every other metadata mutation.
            unsafe { (*node.as_ptr()).task.state = TaskState::Ready };
            inner.run_queues[target_cpu].enqueue(node);
            target_cpu
        })
    };

    if let Some(target_cpu) = target_cpu {
        request_prompt_reschedule(target_cpu);
    }
    // SAFETY: `flags` was captured on this CPU at entry and the scheduler
    // lock has been released.
    unsafe { restore_flags(flags) };
    target_cpu.is_some()
}

/// Interrupt one task blocked on an explicit event, or leave a one-shot wake
/// credit if it has not parked yet.
///
/// Unlike readiness producers, signal delivery cannot acquire an arbitrary
/// wait object's lock. The credit is checked under the scheduler lock by
/// [`block_current_until_releasing`], making both race orders lossless:
/// already-blocked tasks are dequeued immediately, while running/ready tasks
/// consume the credit at their next attempted park.
#[must_use]
pub fn interrupt_task_from_task(id: TaskId) -> bool {
    if id.as_u64() == 0 {
        return false;
    }

    let flags = save_flags_and_cli();
    let (found, target_cpu) = {
        let mut inner = lock();
        if let Some(node) = inner.blocked_queue.take_task(id) {
            let target_cpu = unsafe { node.as_ref() }.task.cpu as usize;
            // SAFETY: the node was removed from the blocked queue under the
            // scheduler lock and remains owned by `all_tasks`.
            unsafe { (*node.as_ptr()).task.state = TaskState::Ready };
            inner.run_queues[target_cpu].enqueue(node);
            (true, Some(target_cpu))
        } else if let Some(node) = inner.all_tasks.iter_mut().find(|node| node.task.id == id) {
            node.interrupt_pending = true;
            (true, None)
        } else {
            (false, None)
        }
    };

    if let Some(target_cpu) = target_cpu {
        request_prompt_reschedule(target_cpu);
    }
    // SAFETY: `flags` was captured on this CPU at entry and the scheduler
    // lock has been released.
    unsafe { restore_flags(flags) };
    found
}

#[inline]
fn consume_interrupt_credit(pending: &mut bool) -> bool {
    core::mem::replace(pending, false)
}

/// Drain the coalesced event-wake slot with one non-blocking scheduler-lock
/// acquisition per observed request.
///
/// Callers keep local interrupts disabled. On lock contention the current
/// scheduler owner is responsible for draining after unlock; see
/// [`SchedulerLockGuard`].
fn drain_pending_blocked_wakes() {
    loop {
        if PENDING_BLOCKED_WAKE.load(Ordering::Acquire) == 0 {
            return;
        }
        let Some(mut inner) = SCHEDULER.try_lock() else {
            return;
        };
        let requested = PENDING_BLOCKED_WAKE.swap(0, Ordering::AcqRel);
        let target_cpu = if requested == 0 {
            None
        } else if let Some(node) = inner.blocked_queue.take_task(TaskId(requested)) {
            Some({
                // Return the task to the CPU it last ran on. This
                // preserves cache locality and enables a prompt IPI.
                let target_cpu = unsafe { node.as_ref() }.task.cpu as usize;
                // SAFETY: the node was just unlinked from the blocked
                // queue, remains owned by `all_tasks`, and this raw guard
                // gives exclusive scheduler metadata access.
                unsafe { (*node.as_ptr()).task.state = TaskState::Ready };
                inner.run_queues[target_cpu].enqueue(node);
                target_cpu
            })
        } else {
            if let Some(node) = inner
                .all_tasks
                .iter_mut()
                .find(|node| node.task.id == TaskId(requested))
            {
                node.interrupt_pending = true;
            }
            None
        };
        // Release before requesting reschedule: the target CPU's IPI handler
        // may enter the scheduler immediately.
        drop(inner);
        if let Some(target_cpu) = target_cpu {
            request_prompt_reschedule(target_cpu);
        }
        // A producer can publish while the raw guard is held. Loop after
        // unlock so that race is consumed here rather than deferred to a tick.
    }
}

/// Arrange a scheduling point promptly after an event wake.
///
/// A remote target receives the scheduler's normal reschedule IPI. For the
/// local CPU we also queue that IPI to self: if this runs inside a device IRQ,
/// it remains pending until the device EOI and `iretq`; in task context it is
/// delivered as soon as interrupts are enabled. This removes the otherwise
/// unavoidable wait for the next 100 Hz timer tick.
fn request_prompt_reschedule(target_cpu: usize) {
    if target_cpu == current_cpu() {
        preempt::set_need_resched();
        crate::arch::x86_64::interrupts::apic::send_ipi(
            crate::arch::x86_64::interrupts::apic::current_id(),
            crate::arch::x86_64::smp::RESCHEDULE_VECTOR,
        );
    } else {
        crate::arch::x86_64::smp::request_reschedule(target_cpu);
    }
}

// ---------------------------------------------------------------------------
// Interrupt-state helpers
// ---------------------------------------------------------------------------

/// Snapshot RFLAGS and clear EFLAGS.IF on this CPU.
///
/// Returns the pre-`cli` RFLAGS so the caller can restore it with
/// [`restore_flags`]. This is the same primitive `sync::spinlock_irq` uses
/// internally; it is duplicated here because that module's helpers are
/// private. When `arch::x86_64::irq` exposes a public save/restore pair, both
/// this and `spinlock_irq` should delegate to it and this duplication goes
/// away.
///
/// # Safety
///
/// Safe to call from any ring-0 context. The caller is responsible for pairing
/// the call with [`restore_flags`] so interrupts are not left disabled.
#[inline]
fn save_flags_and_cli() -> u64 {
    let flags: u64;
    // SAFETY: `pushfq` pushes RFLAGS onto the stack; `pop {r}` pops it into a
    // register; `cli` clears IF. The push/pop pair is stack-balanced and the
    // register is written before `cli` runs, so the snapshot reflects the
    // pre-`cli` IF state. We do not pass `nostack` because the instructions
    // touch the stack, and we do not pass `preserves_flags` because `cli`
    // modifies IF.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {0}",
            "cli",
            out(reg) flags,
        );
    }
    flags
}

/// Restore RFLAGS from a snapshot taken by [`save_flags_and_cli`].
///
/// Re-enables interrupts iff they were enabled when the snapshot was taken.
///
/// # Safety
///
/// `flags` must be a value previously produced by [`save_flags_and_cli`] on
/// this CPU. Restoring a stale or cross-CPU snapshot can leave this core in an
/// interrupt state that does not match the kernel's expectations.
#[inline]
unsafe fn restore_flags(flags: u64) {
    // SAFETY: `push {r}` pushes the saved RFLAGS; `popfq` pops it into RFLAGS,
    // restoring the full flag word including IF. Stack-balanced.
    unsafe {
        core::arch::asm!("push {0}", "popfq", in(reg) flags);
    }
}

// ---------------------------------------------------------------------------
// Bring-up
// ---------------------------------------------------------------------------

/// Bring the scheduler up on the boot CPU.
///
/// Called once from [`super::init`] after the memory and time subsystems are
/// online (the scheduler allocates task stacks from the heap and reads
/// deadlines from the monotonic clock). This:
///
/// 1. Captures the boot kernel CR3 used whenever a kernel task follows a user
///    task.
/// 2. Initialises the preemption subsystem (per-CPU counters, slice length,
///    `need_resched` flag).
/// 3. Creates the BSP's idle task and records it so [`pick_next`] can return
///    it when the run queue is empty.
/// 4. Marks the scheduler initialised so [`spawn`] and friends accept work.
///
/// After this returns, [`schedule_next`] can be called and the LAPIC timer can
/// be armed to deliver ticks at [`SCHED_TICK_HZ`].
pub fn init() {
    // Capture CR3 before any task can enter a userspace address space. Keeping
    // the complete raw image preserves the kernel PML4 cache flags (and a
    // future kernel PCID) when a kernel task is restored after a user task.
    //
    // SAFETY: scheduler initialisation runs once in ring 0 while the boot
    // address space is active. Reading CR3 has no side effects.
    let kernel_cr3 = unsafe { Cr3::read_raw() };
    KERNEL_CR3.store(kernel_cr3, Ordering::Release);

    // 1. Preemption state: reset the BSP's per-CPU counters and install the
    //    default slice length. Must precede the first tick.
    preempt::init();

    // 2. Idle task for the BSP. The canonical entry lives in the sibling
    //    `idle` module; this scheduler remains the sole owner of its task node
    //    and per-CPU fallback pointer. The lock-plus-spawn block runs with
    //    interrupts off because `lock()` requires it.
    let flags = save_flags_and_cli();
    let idle_node = {
        let mut inner = lock();
        let idle_name = KString::from("idle-0");
        // The idle task is owned like every other task, but it is deliberately
        // not placed on the normal run queue. `pick_next` selects it only when
        // that queue is empty, so runnable work can never sit behind idle in
        // FIFO order.
        let idle_node = match create_task_inner(&mut inner, idle_name, super::idle::entry, 0) {
            Some(id) => id,
            None => {
                ::log::error!("xenith.sched: failed to allocate idle task — halting");
                // Without an idle task the scheduler cannot run; halt the core.
                // SAFETY: `sti; hlt` halts until the next interrupt. We have no
                // scheduler to fall back to, so this is a fatal park.
                loop {
                    unsafe {
                        sti();
                        hlt();
                    }
                }
            },
        };
        let cpu = current_cpu();
        inner.idle_tasks[cpu] = Some(idle_node);
        inner.initialised = true;
        idle_node
    }; // lock released here
       // SAFETY: `flags` was captured on this CPU a few instructions above and
       // is the correct RFLAGS to restore.
    unsafe { restore_flags(flags) };
    let _ = idle_node;

    SCHED_INITIALISED.store(true, Ordering::Release);
    ::log::info!(
        "xenith.sched: scheduler online (tick = {} Hz, aging = {} ticks)",
        SCHED_TICK_HZ,
        AGING_THRESHOLD_TICKS,
    );
}

/// Initialise scheduler-local state for an application processor.
///
/// Global scheduler ownership and the kernel CR3 were published by the BSP's
/// [`init`]. Each AP only needs its own preemption counters, bootstrap/current
/// slots, and fallback idle task before its LAPIC timer can be unmasked.
pub fn init_ap() {
    debug_assert!(is_initialised(), "scheduler AP init before BSP init");
    preempt::init_for_ap(super::preempt::DEFAULT_TIME_SLICE_TICKS);

    let cpu = current_cpu();
    debug_assert!((1..MAX_CPUS).contains(&cpu), "invalid AP logical id");
    let flags = save_flags_and_cli();
    {
        let mut inner = lock();
        if inner.idle_tasks[cpu].is_none() {
            let idle = create_task_inner(
                &mut inner,
                KString::from("idle-ap"),
                super::idle::entry,
                cpu as u64,
            )
            .unwrap_or_else(|| {
                ::log::error!("xenith.sched: failed to allocate idle task for CPU {cpu}");
                loop {
                    hlt();
                }
            });
            inner.idle_tasks[cpu] = Some(idle);
        }
    }
    // SAFETY: no task has been dispatched on this AP yet; its private slot is
    // exclusively owned by this CPU.
    unsafe { set_current_node(None) };
    // SAFETY: `flags` was captured on this CPU above (normally IF=0 during AP
    // bring-up) and restores exactly that state.
    unsafe { restore_flags(flags) };
    ::log::info!("xenith.sched: CPU {cpu} run queue and idle task ready");
}

// ---------------------------------------------------------------------------
// spawn
// ---------------------------------------------------------------------------

/// A fully allocated scheduler task that is owned but not yet runnable.
///
/// The node is retained in the scheduler's master ownership list, but remains
/// off every run/wait queue until [`commit`](Self::commit). This gives callers
/// a transaction boundary for publishing metadata keyed by [`TaskId`] before
/// another CPU can dispatch the task. Dropping an uncommitted value removes
/// and frees the unstarted node.
#[must_use = "a staged task must be committed or deliberately dropped"]
pub struct StagedTask {
    id: TaskId,
    target_cpu: usize,
    committed: bool,
}

impl StagedTask {
    /// Identity reserved for this task before runnable publication.
    #[inline]
    pub const fn id(&self) -> TaskId {
        self.id
    }

    /// Attach a shared userspace page-table root before runnable publication.
    ///
    /// This is intentionally available only on an uncommitted token. The
    /// scheduler lock keeps the task off every CPU while the address-space
    /// identity is installed, so its very first dispatch uses the right CR3.
    #[must_use]
    pub fn attach_address_space(&mut self, space: crate::mm::r#virtual::AddressSpace) -> bool {
        if self.committed {
            return false;
        }
        let flags = save_flags_and_cli();
        let attached = {
            let mut inner = lock();
            inner
                .all_tasks
                .iter_mut()
                .find(|node| node.task.id == self.id)
                .filter(|node| {
                    staged_node_cancellable(node.links.is_unlinked(), node.started, node.task.state)
                })
                .is_some_and(|node| {
                    node.task.address_space = Some(space);
                    true
                })
        };
        // SAFETY: `flags` was captured on this CPU immediately before locking.
        unsafe { restore_flags(flags) };
        attached
    }

    #[inline]
    fn mark_committed(&mut self) -> bool {
        !core::mem::replace(&mut self.committed, true)
    }

    /// Publish the staged task to its selected run queue.
    ///
    /// The scheduler lock publishes the queue link before any remote
    /// reschedule IPI is sent. `None` indicates scheduler ownership corruption;
    /// the uncommitted token then attempts its normal cancellation rollback.
    #[must_use]
    pub fn commit(mut self) -> Option<TaskId> {
        let flags = save_flags_and_cli();
        let target_cpu = {
            let mut inner = lock();
            let node = inner
                .all_tasks
                .iter_mut()
                .find(|node| node.task.id == self.id)
                .map(|node| NonNull::from(&mut **node));
            node.map(|node| {
                let target_cpu = if crate::arch::x86_64::smp::is_online(self.target_cpu) {
                    self.target_cpu
                } else {
                    select_least_loaded_cpu(&inner)
                };
                // Mark the token committed before linking the node. If an
                // invariant panic occurs inside the intrusive queue, Drop must
                // never mistake a linked node for cancellable staged state.
                let first_commit = self.mark_committed();
                debug_assert!(first_commit);
                // SAFETY: the token proves this newly-created node is still
                // owned by `all_tasks`, unstarted, and off every queue. The
                // scheduler lock gives exclusive metadata access.
                unsafe { (*node.as_ptr()).task.cpu = target_cpu as u32 };
                inner.run_queues[target_cpu].enqueue(node);
                target_cpu
            })
        };
        // SAFETY: `flags` was captured on this CPU immediately before locking.
        unsafe { restore_flags(flags) };

        let target_cpu = target_cpu?;
        if target_cpu != current_cpu() {
            crate::arch::x86_64::smp::request_reschedule(target_cpu);
        }
        Some(self.id)
    }
}

#[inline]
const fn staged_node_cancellable(unlinked: bool, started: bool, state: TaskState) -> bool {
    unlinked && !started && matches!(state, TaskState::Ready)
}

impl Drop for StagedTask {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        let flags = save_flags_and_cli();
        let removed = {
            let mut inner = lock();
            inner
                .all_tasks
                .iter()
                .position(|node| node.task.id == self.id)
                .and_then(|index| {
                    let node = &inner.all_tasks[index];
                    if !staged_node_cancellable(
                        node.links.is_unlinked(),
                        node.started,
                        node.task.state,
                    ) {
                        // A linked, started, or non-ready node may still be
                        // observed by a CPU. Refuse reclamation rather than
                        // turning scheduler corruption into a use-after-free.
                        ::log::error!(
                            "xenith.sched: refusing to cancel non-staged {} (tid={}, state={}, started={}, linked={})",
                            node.task.name,
                            node.task.id,
                            node.task.state,
                            node.started,
                            node.links.is_linked(),
                        );
                        return None;
                    }
                    let mut removed = inner.all_tasks.swap_remove(index);
                    removed.task.state = TaskState::Dead;
                    Some(removed)
                })
        };
        // SAFETY: `flags` was captured on this CPU immediately before locking.
        unsafe { restore_flags(flags) };
        // Kernel-stack reclamation may touch the allocator, so keep it outside
        // the scheduler lock just like ordinary post-switch task reaping.
        drop(removed);
    }
}

/// Spawn a kernel thread that runs `entry(arg)` on a fresh kernel stack.
///
/// Allocates a [`Task`] (with stack) and a [`TaskNode`] (with the
/// asm-matching saved context), records the node in the master task list, and
/// enqueues it on the least-loaded online CPU's run queue as
/// [`TaskState::Ready`]. The task begins running the next time that CPU's
/// scheduler picks it from the queue.
///
/// Returns the new [`TaskId`] on success, or `None` if the kernel stack could
/// not be allocated (heap exhausted). Callers should propagate `None` rather
/// than panicking — running out of memory while spawning is a recoverable
/// condition for the caller.
///
/// # Panics
///
/// In debug builds, panics if called before [`init`] has run, because a spawn
/// before the scheduler is up would enqueue onto an uninitialised queue and
/// the idle task would not yet exist.
#[must_use]
pub fn spawn(name: KString, entry: unsafe extern "C" fn(u64) -> !, arg: u64) -> Option<TaskId> {
    stage_spawn_inner(name, entry, arg, None)?.commit()
}

/// Spawn a kernel task directly onto one online CPU's run queue.
///
/// A remote enqueue is followed by a reschedule IPI after the scheduler lock
/// and local interrupt state have been restored, so an idle target observes
/// the new work immediately.
#[must_use]
pub fn spawn_on(
    cpu: usize,
    name: KString,
    entry: unsafe extern "C" fn(u64) -> !,
    arg: u64,
) -> Option<TaskId> {
    if !crate::arch::x86_64::smp::is_online(cpu) {
        return None;
    }
    stage_spawn_inner(name, entry, arg, Some(cpu))?.commit()
}

/// Allocate and retain a task without making it runnable.
///
/// Callers may publish external metadata using [`StagedTask::id`] and then
/// invoke [`StagedTask::commit`]. Until commit, no run queue contains the node
/// and no reschedule IPI is sent.
#[must_use]
pub fn stage_spawn(
    name: KString,
    entry: unsafe extern "C" fn(u64) -> !,
    arg: u64,
) -> Option<StagedTask> {
    stage_spawn_inner(name, entry, arg, None)
}

fn stage_spawn_inner(
    name: KString,
    entry: unsafe extern "C" fn(u64) -> !,
    arg: u64,
    requested_cpu: Option<usize>,
) -> Option<StagedTask> {
    // Task ownership and target selection are scheduler metadata, so stage
    // them with local interrupts off under the scheduler lock. The node stays
    // deliberately absent from all run queues.
    let flags = save_flags_and_cli();
    let staged = {
        let mut inner = lock();
        debug_assert!(
            inner.initialised,
            "sched::stage_spawn before init is not permitted"
        );
        let node = match create_task_inner(&mut inner, name, entry, arg) {
            Some(node) => node,
            None => {
                drop(inner);
                // SAFETY: `flags` was captured on this CPU immediately
                // before locking; restore it on the allocation-failure path.
                unsafe { restore_flags(flags) };
                return None;
            },
        };
        let target_cpu = requested_cpu.unwrap_or_else(|| select_least_loaded_cpu(&inner));
        // Record the intended placement for diagnostics and signal wake
        // locality, but do not enqueue or notify that CPU until commit.
        // SAFETY: `node` is newly created, owned by `all_tasks`, unstarted,
        // and still off every queue under the scheduler lock.
        unsafe { (*node.as_ptr()).task.cpu = target_cpu as u32 };
        StagedTask {
            // SAFETY: the node remains live in `all_tasks`.
            id: unsafe { node.as_ref() }.task.id,
            target_cpu,
            committed: false,
        }
    }; // lock released
       // SAFETY: `flags` was captured on this CPU just above.
    unsafe { restore_flags(flags) };
    Some(staged)
}

fn select_least_loaded_cpu(inner: &SchedulerInner) -> usize {
    let online = {
        let mask = crate::arch::x86_64::smp::online_mask();
        if mask == 0 {
            1
        } else {
            mask
        }
    };
    let start = NEXT_PLACEMENT_CPU.fetch_add(1, Ordering::Relaxed) as usize % MAX_CPUS;
    let mut selected = current_cpu();
    let mut selected_len = usize::MAX;
    for offset in 0..MAX_CPUS {
        let cpu = (start + offset) % MAX_CPUS;
        if online & (1u64 << cpu) == 0 {
            continue;
        }
        let len = inner.run_queues[cpu].len();
        if len < selected_len {
            selected = cpu;
            selected_len = len;
        }
    }
    selected
}

/// Create and retain a task node without making it runnable.
///
/// Builds the [`Task`] and [`TaskNode`] and takes ownership in `all_tasks`.
/// The caller decides how the node becomes selectable: [`stage_spawn`] returns
/// an RAII token whose commit enqueues an ordinary task, while [`init`] records
/// the idle task only in `idle_tasks` so [`pick_next`] can use it as the
/// empty-queue fallback.
fn create_task_inner(
    inner: &mut SchedulerInner,
    name: KString,
    entry: unsafe extern "C" fn(u64) -> !,
    arg: u64,
) -> Option<NonNull<TaskNode>> {
    // Build the task control block. `new_kernel` allocates the stack and
    // seeds the (task-local) context; the scheduler ignores that context and
    // builds its own asm-matching one in `TaskNode::new`.
    let task = Task::new_kernel(name, entry, arg)?;
    // SAFETY: `task` owns a freshly-allocated, 16-aligned kernel stack whose
    // top is valid for the lifetime of the node we are about to build.
    let mut node = Kbox::new(unsafe { TaskNode::new(Kbox::new(task), entry, arg) }?);
    let node_ptr = node.as_nonnull();
    // The node's task starts Ready; record that explicitly even though
    // `new_kernel` already sets it, so the transition is visible at the
    // scheduler layer.
    node.task.state = TaskState::Ready;
    // Track the node in the master list so its lifetime outlives any queue
    // membership. `Kbox` move into the vec does not move the heap data, so
    // `node_ptr` stays valid.
    inner.all_tasks.push(node);
    ::log::debug!(
        "xenith.sched: created {} (tid={}) on CPU {}",
        unsafe { node_ptr.as_ref() }.task.name,
        unsafe { node_ptr.as_ref() }.task.id,
        current_cpu(),
    );
    Some(node_ptr)
}

// ---------------------------------------------------------------------------
// exit
// ---------------------------------------------------------------------------

/// Exit the current task with `status` and switch to the next runnable task.
///
/// Marks the current task [`TaskState::Zombie`], records `status` in its
/// `exit_status`, removes it from the current slot so it will not be picked
/// again, and performs a context switch to the next task (or the idle task).
/// This function diverges — it never returns to the caller, because the
/// caller's stack belongs to a task that is now a zombie and must not be
/// resumed.
///
/// # Panics
///
/// Panics if there is no current task (called outside a task context).
pub fn exit(status: ExitStatus) -> ! {
    let cur = current_node().expect("sched::exit with no current task");
    // Mark the current task zombie under the lock, then release the lock and
    // clear the current slot. The actual switch happens in `schedule_next`,
    // which manages its own interrupt state; we do NOT hold the lock across
    // the switch.
    let flags = save_flags_and_cli();
    {
        let _guard = lock();
        // SAFETY: `cur` is the current task on this CPU; the lock is held so
        // no other CPU touches it. We mark it Zombie via the task's own `exit`
        // helper, which records the status and state atomically. The path
        // through `addr_of_mut!` gives a `*mut Kbox<Task>`; dereferencing that
        // yields the `Kbox<Task>` whose `DerefMut` exposes the `&mut Task` that
        // `exit` expects.
        let task_ptr = unsafe { core::ptr::addr_of_mut!((*cur.as_ptr()).task) };
        // SAFETY: `task_ptr` is a valid, non-aliased `*mut Kbox<Task>` (the
        // lock and per-CPU ownership guarantee exclusive access), so a mutable
        // borrow of the `Kbox` — and through its `DerefMut`, the `Task` — is
        // sound for the duration of the `exit` call.
        let task: &mut Task = unsafe { &mut *task_ptr };
        task.exit(status);
        // The zombie remains owned by `all_tasks` while this CPU is still
        // executing on its kernel stack. Publish it to this CPU's single
        // post-switch retirement slot; the incoming context removes and
        // drops it only after the hardware stack pointer has changed.
        let cpu = current_cpu();
        let retired = cur.as_ptr() as u64;
        assert_ne!(retired, 0, "sched: null retirement pointer");
        assert!(
            RETIRED_TASK[cpu]
                .compare_exchange(0, retired, Ordering::Release, Ordering::Relaxed)
                .is_ok(),
            "sched: CPU {cpu} retirement slot was not drained before task exit"
        );
    } // lock released
      // Clear the current-node slot so `schedule_next` does not try to re-enqueue
      // the zombie. `schedule_next` treats a `None` current as "switch from the
      // bootstrap context", which is exactly what we want: the zombie's stack
      // must not be saved back into.
      // SAFETY: we are on the CPU that owns the slot; clearing it is sound.
    unsafe { set_current_node(None) };
    // Drop into the scheduler with interrupts still disabled (we do NOT
    // restore `flags` here): `schedule_next` will save+cli again on its own
    // entry, and the resuming task restores *its own* saved flags — not ours —
    // so the interrupt state we leave here is irrelevant to the resuming task.
    // Keeping interrupts off across the call avoids a window in which a timer
    // IRQ could re-enter the scheduler while the zombie is half-exited.
    let _ = flags;
    // `schedule_next` will pick the next task (or the idle task) and switch
    // into it; it never returns to this frame.
    schedule_next();
    // `schedule_next` is typed as `()` for the IRQ/preempt call sites, so
    // convince the compiler we diverge — the switch away means this is
    // unreachable on the exiting task's stack.
    unreachable!("sched::exit: schedule_next returned into an exited task")
}

/// Detach the current task from its userspace page-table root.
///
/// Process teardown calls this before publishing an observable exit status.
/// Loading the shared kernel CR3 first means a parent on another CPU may
/// immediately reap the process address space without freeing a root that the
/// exiting CPU is still executing under. The task continues on its globally
/// mapped kernel stack and reaches [`exit`] without touching userspace again.
///
/// The CR3 write and task metadata update happen with local interrupts off and
/// the scheduler lock held. The later process-table unlock is a release
/// publication, so a parent that observes the exit also observes this detach.
///
/// # Panics
///
/// Panics if called outside a scheduled task.
pub fn detach_current_address_space() {
    let cur = current_node().expect("sched::detach_address_space with no current task");
    let flags = save_flags_and_cli();
    {
        let _guard = lock();
        // SAFETY: `cur` is current on this CPU, interrupts are disabled, and
        // the scheduler lock excludes metadata mutation from every other CPU.
        unsafe { (*cur.as_ptr()).task.address_space = None };
        let kernel_cr3 = KERNEL_CR3.load(Ordering::Acquire);
        debug_assert_ne!(kernel_cr3, 0, "kernel CR3 unavailable during task exit");
        // SAFETY: scheduler initialisation captured a live kernel PML4 whose
        // higher half maps this code and the current kernel stack.
        if unsafe { Cr3::read_raw() } != kernel_cr3 {
            unsafe { Cr3::write_raw(kernel_cr3) };
        }
        debug_assert!(exit_detach_complete(
            unsafe { (*cur.as_ptr()).task.address_space.is_some() },
            unsafe { Cr3::read_raw() },
            kernel_cr3,
        ));
    }
    // SAFETY: `flags` was captured on this CPU at entry.
    unsafe { restore_flags(flags) };
}

/// Pure policy check used by the exit publication assertion and host test.
const fn exit_detach_complete(
    task_has_address_space: bool,
    active_cr3: u64,
    kernel_cr3: u64,
) -> bool {
    !task_has_address_space && kernel_cr3 != 0 && active_cr3 == kernel_cr3
}

// ---------------------------------------------------------------------------
// yield
// ---------------------------------------------------------------------------

/// Cooperatively yield the CPU: move the current task to the back of its
/// priority level and switch to the next runnable task.
///
/// Unlike preemption, a yield is voluntary and may be called from a preempt-
/// disabled region (the scheduler will still switch, because the caller has
/// explicitly asked it to). The current task is re-enqueued as `Ready` before
/// the switch so it can be picked again later.
///
/// If there is no current task, this is a no-op (the scheduler has not started
/// dispatching). If the run queue is empty after re-enqueueing the current
/// task, the switch is skipped — there is nothing else to run.
pub fn yield_now() {
    let Some(cur) = current_node() else { return };
    let flags = save_flags_and_cli();
    // Under the lock: re-enqueue the current task as Ready, clear the current
    // slot, and pick the next task. The lock is released before the switch.
    let next = {
        let mut inner = lock();
        // SAFETY: `cur` is current on this CPU; the lock is held so no other
        // CPU touches it. It is not currently on any queue (it is the current
        // task), so `enqueue`'s unlinked precondition holds.
        unsafe { (*cur.as_ptr()).task.state = TaskState::Ready };
        let rq = inner.current_run_queue();
        rq.enqueue(cur);
        // SAFETY: clearing the current slot is sound on the owning CPU.
        unsafe { set_current_node(None) };
        pick_next(&mut inner)
    }; // lock released
    match next {
        None => {
            // No runnable task and no idle task: re-establish the current task
            // and return. This only happens before `init` installs the idle
            // task, which is a bug — but we degrade gracefully instead of
            // faulting.
            // SAFETY: `cur` is live, off every queue, and remains the task
            // executing on this CPU.
            unsafe {
                (*cur.as_ptr()).task.state = TaskState::Running;
                set_current_node(Some(cur));
            }
            preempt::clear_need_resched();
            // SAFETY: `flags` was captured on this CPU just above.
            unsafe { restore_flags(flags) };
        },
        Some(next) if Some(next) == Some(cur) => {
            // Nothing else to run; stay on the current task.
            // `cur` was temporarily marked Ready before it was enqueued and
            // immediately selected again. Restore the lifecycle state so a
            // later timer dispatch recognises it as the running task and
            // cannot drop it when falling back to idle.
            // SAFETY: `cur` is current again, off the run queue after
            // `pick_next`, and interrupts remain disabled on this CPU.
            unsafe { (*cur.as_ptr()).task.state = TaskState::Running };
            // SAFETY: we are on the CPU that owns the slot.
            unsafe { set_current_node(Some(cur)) };
            preempt::clear_need_resched();
            // SAFETY: `flags` was captured on this CPU just above.
            unsafe { restore_flags(flags) };
        },
        Some(next) => {
            // `do_switch` requires the caller to publish the selected task
            // before a fresh task can enter `task_trampoline`. Unlike the
            // same-task branch above, this is a real switch, so install the
            // incoming lifecycle/CPU/current state and reset its slice.
            // SAFETY: `next` was removed from the run queue under the lock,
            // remains live in `all_tasks`, and interrupts are disabled.
            unsafe {
                let task = core::ptr::addr_of_mut!((*next.as_ptr()).task);
                (*task).state = TaskState::Running;
                (*task).cpu = current_cpu() as u32;
                (*task).stats.context_switches = (*task).stats.context_switches.saturating_add(1);
                set_current_node(Some(next));
            }
            preempt::on_context_switch_in();
            // Perform the switch with the lock released and interrupts off.
            // `cur` is the outgoing task (saved into by the switch); `next` is
            // the incoming task. The switch runs inside `do_switch`, which
            // restores `flags` on the resuming side.
            do_switch(Some(cur), next, flags);
        },
    }
}

// ---------------------------------------------------------------------------
// sleep_until
// ---------------------------------------------------------------------------

/// Sleep until the monotonic clock reaches `deadline`, then wake ready.
///
/// Moves the current task off the run queue and onto the sleep queue with the
/// given wake deadline, then switches to the next runnable task (or the idle
/// task). When [`tick`] observes that `deadline` has elapsed it re-enqueues
/// the task as `Ready`; the task resumes the next time it is picked.
///
/// A `deadline` in the past (including `Instant::now()` at call time) is
/// treated as "wake as soon as possible": the task is still moved off the
/// queue for one switch, but the very next [`tick`] will wake it. This keeps
/// the sleep path uniform — there is no special "yield with a deadline" case.
///
/// # Panics
///
/// Panics if there is no current task.
pub fn sleep_until(deadline: Instant) {
    let cur = current_node().expect("sched::sleep_until with no current task");
    let flags = save_flags_and_cli();
    let next = {
        let mut inner = lock();
        // Mark the task Sleeping and move it to the sleep queue. It is removed
        // from the run queue implicitly because it was the current task (not
        // on any queue).
        // SAFETY: `cur` is current on this CPU; the lock is held.
        unsafe { (*cur.as_ptr()).task.state = TaskState::Sleeping };
        inner.sleep_queue.add(cur, deadline);
        // SAFETY: clear the current slot; the switch will install the next
        // task as current.
        unsafe { set_current_node(None) };
        pick_next(&mut inner)
    }; // lock released
    match next {
        None => {
            // No idle task available — should not happen post-`init`. Restore
            // the sleeper as current and return immediately; `tick` will wake
            // it when the deadline elapses.
            // SAFETY: we are on the CPU that owns the slot; the lock is not
            // held and no other task can be running here.
            unsafe {
                (*cur.as_ptr()).task.state = TaskState::Running;
                set_current_node(Some(cur));
                restore_flags(flags);
            }
            preempt::clear_need_resched();
        },
        Some(next) => {
            // Publish the selected task before switching. A freshly spawned
            // task enters `task_trampoline`, which resolves its process state
            // through the current-task slot immediately.
            // SAFETY: `next` was removed from the run queue under the lock,
            // remains live in `all_tasks`, and interrupts are disabled.
            unsafe {
                let task = core::ptr::addr_of_mut!((*next.as_ptr()).task);
                (*task).state = TaskState::Running;
                (*task).cpu = current_cpu() as u32;
                (*task).stats.context_switches = (*task).stats.context_switches.saturating_add(1);
                set_current_node(Some(next));
            }
            preempt::on_context_switch_in();
            // Switch to the next task with the lock released and interrupts
            // off. The sleeper's `cur` is saved into by the switch.
            do_switch(Some(cur), next, flags);
        },
    }
}

/// Park the current task on an explicit event while atomically releasing an
/// IRQ-safe producer lock.
///
/// The caller must hold the lock that protects both its readiness predicate
/// and waiter registration. This function links the current task into the
/// allocation-free blocked queue *before* releasing that lock, closing the
/// classic lost-wake window: a producer cannot observe the registration until
/// the scheduler can successfully wake the blocked task. The guard is then
/// unlocked without restoring IF, and its original RFLAGS are restored only
/// when this task resumes from the context switch.
///
/// `deadline == None` is an untimed wait. A finite deadline is processed by
/// [`tick`] without allocating. Producers wake the task with
/// [`wake_blocked_task`].
///
/// # Panics
///
/// Panics if there is no current task.
pub fn block_current_until_releasing<T: ?Sized>(
    deadline: Option<Instant>,
    producer_guard: crate::sync::SpinLockIRQGuard<'_, T>,
) {
    let cur = current_node().expect("sched::block_current with no current task");
    // SAFETY: `cur` is the live current node while the producer guard pins
    // execution to this CPU with interrupts disabled.
    let task_id = unsafe { cur.as_ref() }.task.id;

    // Keep the producer lock and IF=0 while publishing the blocked state.
    let next = {
        let mut inner = lock();
        // SAFETY: `cur` is the live current node and the scheduler lock
        // serializes the wake credit with cross-lock signal delivery.
        let interrupted =
            unsafe { consume_interrupt_credit(&mut (*cur.as_ptr()).interrupt_pending) };
        if interrupted {
            None
        } else {
            // SAFETY: `cur` is current and unlinked; the scheduler lock
            // excludes every other metadata mutation while it moves to the
            // blocked queue.
            unsafe { (*cur.as_ptr()).task.state = TaskState::Blocked };
            inner.blocked_queue.add(cur, deadline);
            // SAFETY: this CPU exclusively owns its current slot with IF
            // clear.
            unsafe { set_current_node(None) };

            let next = pick_next(&mut inner);
            if next.is_none() {
                // Pre-init/misconfigured fallback: undo the park while the
                // producer lock still prevents a concurrent wake.
                let restored = inner
                    .blocked_queue
                    .take_task(task_id)
                    .expect("newly blocked task disappeared");
                debug_assert_eq!(restored, cur);
                // SAFETY: `cur` is unlinked again and exclusively owned here.
                unsafe {
                    (*cur.as_ptr()).task.state = TaskState::Running;
                    set_current_node(Some(cur));
                }
            } else if let Some(next) = next {
                // Publish the selected task before the switch, matching
                // `sleep_until` and the normal dispatch path.
                // SAFETY: `next` was removed from a run queue under the lock
                // and remains live in `all_tasks`.
                unsafe {
                    let task = core::ptr::addr_of_mut!((*next.as_ptr()).task);
                    (*task).state = TaskState::Running;
                    (*task).cpu = current_cpu() as u32;
                    (*task).stats.context_switches =
                        (*task).stats.context_switches.saturating_add(1);
                    set_current_node(Some(next));
                }
            }
            next
        }
    };

    // SAFETY: the scheduler immediately consumes the guard's same-CPU RFLAGS
    // and either restores them below or passes them to `do_switch`, whose
    // resuming side restores them. IF remains clear across the hand-off.
    let flags = unsafe { producer_guard.unlock_without_restoring_interrupts() };
    let Some(next) = next else {
        preempt::clear_need_resched();
        // SAFETY: `flags` came from this CPU's producer guard above.
        unsafe { restore_flags(flags) };
        return;
    };

    preempt::on_context_switch_in();
    do_switch(Some(cur), next, flags);
}

/// Park on the scheduler's generic interrupt token without a producer lock.
///
/// Multi-source waits register with several independent objects, so no one
/// producer guard can cover the final park. Every registered producer uses
/// [`interrupt_task_from_task`] (or the IRQ-safe [`wake_blocked_task`]), which
/// either dequeues an already-blocked task or records `interrupt_pending`
/// under this same scheduler lock. The token therefore closes the last race
/// without polling.
pub fn block_current_interruptible(deadline: Option<Instant>) {
    let cur = current_node().expect("sched::block_current with no current task");
    let flags = save_flags_and_cli();
    let task_id = unsafe { cur.as_ref() }.task.id;
    let next = {
        let mut inner = lock();
        // SAFETY: `cur` is current and the scheduler lock serializes the
        // generic wake token with every producer.
        if unsafe { consume_interrupt_credit(&mut (*cur.as_ptr()).interrupt_pending) } {
            None
        } else {
            // SAFETY: current tasks are unlinked and exclusively owned by
            // this CPU until publication into the blocked queue.
            unsafe { (*cur.as_ptr()).task.state = TaskState::Blocked };
            inner.blocked_queue.add(cur, deadline);
            // SAFETY: interrupts are disabled on this CPU.
            unsafe { set_current_node(None) };
            let next = pick_next(&mut inner);
            if next.is_none() {
                let restored = inner
                    .blocked_queue
                    .take_task(task_id)
                    .expect("newly blocked task disappeared");
                debug_assert_eq!(restored, cur);
                // SAFETY: `cur` is unlinked again and remains the current
                // task on this CPU.
                unsafe {
                    (*cur.as_ptr()).task.state = TaskState::Running;
                    set_current_node(Some(cur));
                }
            } else if let Some(next) = next {
                // SAFETY: `next` was removed from a run queue under the lock.
                unsafe {
                    let task = core::ptr::addr_of_mut!((*next.as_ptr()).task);
                    (*task).state = TaskState::Running;
                    (*task).cpu = current_cpu() as u32;
                    (*task).stats.context_switches =
                        (*task).stats.context_switches.saturating_add(1);
                    set_current_node(Some(next));
                }
            }
            next
        }
    };

    let Some(next) = next else {
        preempt::clear_need_resched();
        // SAFETY: `flags` was captured on this CPU above.
        unsafe { restore_flags(flags) };
        return;
    };
    preempt::on_context_switch_in();
    do_switch(Some(cur), next, flags);
}

// ---------------------------------------------------------------------------
// tick — the scheduler's per-tick accounting
// ---------------------------------------------------------------------------

/// Advance global scheduler state by one timer tick.
///
/// Called only from CPU 0's [`preempt::on_timer_tick`]. Every CPU still runs
/// its independent slice accounting on its own LAPIC interrupt, but sleep
/// expiry and aging share one BSP-owned pass. Consequently an N-CPU machine
/// takes the global scheduler lock once per 10 ms, not N times.
///
/// 1. Wakes expired sleepers onto the CPU where each task last ran.
/// 2. Expires timed explicit-event waits onto their last CPUs.
/// 3. Ages every online CPU's run queue exactly once.
/// 4. After releasing the lock, requests a prompt reschedule on every CPU that
///    received an expired waiter.
///
/// The task moves and aging run under the scheduler lock. Reschedule IPIs are
/// sent only after releasing it, so a target CPU may enter the scheduler
/// immediately without spinning behind the producer.
///
/// # Interrupt context
///
/// `tick` is reached only from CPU 0's timer interrupt with `EFLAGS.IF` clear.
/// Calling it from process context or another CPU violates its contract.
pub fn tick() {
    debug_assert!(
        owns_global_tick(current_cpu()),
        "global scheduler tick must run on the BSP"
    );
    let now = Instant::now();
    let online = scheduler_online_mask(crate::arch::x86_64::smp::online_mask());
    let mut reschedule_mask = 0u64;

    {
        let mut inner = lock();

        // 1. Keep expired sleepers on the CPU where they last ran. A woken
        // task whose deadline was already in the past is still moved here:
        // `drain_expired` compares `deadline <= now`. Split the disjoint field
        // borrows so the allocation-free drain can enqueue each node during
        // the same O(n) pass.
        let inner_ref: &mut SchedulerInner = &mut inner;
        let sleep_queue = &mut inner_ref.sleep_queue;
        let run_queues = &mut inner_ref.run_queues;
        sleep_queue.drain_expired(now, |node| {
            // SAFETY: the node remains live in `all_tasks` while scheduler
            // metadata is protected by the lock.
            let last_cpu = unsafe { node.as_ref() }.task.cpu as usize;
            let target_cpu = wake_target_cpu(last_cpu, online);
            // SAFETY: the node is live (in `all_tasks`) and was removed from
            // the sleep queue by `drain_expired`. We hold the lock, so no
            // other CPU touches it.
            unsafe {
                (*node.as_ptr()).task.state = TaskState::Ready;
                (*node.as_ptr()).task.cpu = target_cpu as u32;
            }
            run_queues[target_cpu].enqueue(node);
            reschedule_mask |= 1u64 << target_cpu;
        });

        // 2. Expire explicit event waits in place. The blocked queue is
        // intrusive, so neither this IRQ path nor the producer wake allocates.
        while let Some(node) = inner.blocked_queue.take_expired(now) {
            // SAFETY: the node remains live in `all_tasks` while scheduler
            // metadata is protected by the lock.
            let last_cpu = unsafe { node.as_ref() }.task.cpu as usize;
            let target_cpu = wake_target_cpu(last_cpu, online);
            // SAFETY: `node` was just unlinked from `blocked_queue`, remains
            // owned by `all_tasks`, and the scheduler lock is exclusive.
            unsafe {
                (*node.as_ptr()).task.state = TaskState::Ready;
                (*node.as_ptr()).task.cpu = target_cpu as u32;
            }
            inner.run_queues[target_cpu].enqueue(node);
            reschedule_mask |= 1u64 << target_cpu;
        }

        // 3. Age every online queue in the one global pass. This preserves the
        // original 100 Hz aging rate while removing one lock acquisition per
        // AP tick. Offline slots remain untouched.
        for cpu in 0..MAX_CPUS {
            if online & (1u64 << cpu) != 0 {
                inner.run_queues[cpu].tick_aging();
            }
        }
    }

    // 4. Do not send IPIs under the scheduler lock. Coalesce multiple expired
    // waiters for the same CPU into one request.
    for cpu in 0..MAX_CPUS {
        if reschedule_mask & (1u64 << cpu) != 0 {
            if owns_global_tick(cpu) {
                // `preempt::on_timer_tick` tests this flag immediately after
                // `tick` returns. A self-IPI would only create a redundant
                // second scheduling point after the timer frame unwinds.
                preempt::set_need_resched();
            } else {
                crate::arch::x86_64::smp::request_reschedule(cpu);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// schedule_next — the context-switch dispatch
// ---------------------------------------------------------------------------

/// Pick the next runnable task and context-switch into it.
///
/// This is the single dispatch entry point shared by the preemption path
/// ([`preempt::on_timer_tick`] -> [`preempt::scheduler_schedule_next`]), the
/// reactive [`preempt::preempt_enable`], the voluntary [`yield_now`], and the
/// post-exit switch in [`exit`]. It:
///
/// 1. Moves a running non-idle current task to the back of the run queue. This
///    is the `Running -> Ready` half of timer preemption; without it the
///    outgoing task would be lost after its first expired slice.
/// 2. Picks the next task: the head of the current CPU's run queue, or the
///    idle task if the queue is empty.
/// 3. If the picked task is already the current task, restores its `Running`
///    state, clears `need_resched`, and returns (no switch needed).
/// 4. Otherwise saves the outgoing task's context, loads the incoming task's
///    context via the asm trampoline, installs the incoming task as current,
///    and resets the per-CPU slice accounting.
///
/// When there is no current task (the first ever dispatch, or after [`exit`]
/// cleared the slot), the outgoing context is that CPU's bootstrap context —
/// its saved state is discarded and never resumed.
pub fn schedule_next() {
    // `schedule_next` is reached from process context (`preempt_enable`,
    // `yield_now`, `exit`) where interrupts may be on, and from the timer IRQ
    // handler where they are already off. Save+cli unifies both: the snapshot
    // captures whichever state the caller came in with, and the resuming side
    // restores it.
    let flags = save_flags_and_cli();
    let cur = current_node();
    // Under the lock: pick the next task and install it as current. The lock
    // is released before the switch so it is not held across `context_switch`
    // (which would deadlock the incoming task's own `lock()` acquisition).
    let next = {
        let mut inner = lock();
        // A preempted/rerouted ordinary task remains runnable. Put it at the
        // FIFO tail before selecting the next task so round-robin scheduling
        // cannot drop the outgoing task. Idle is a fallback-only task and must
        // never enter the normal run queue.
        if let Some(current) = cur {
            let current_is_idle = inner.current_idle() == Some(current);
            // SAFETY: `current` is the live current task on this CPU. IF is
            // clear and the scheduler lock is held, so its state cannot race.
            let state = unsafe { (*current.as_ptr()).task.state };
            if should_requeue_for_dispatch(current_is_idle, state) {
                // SAFETY: the running task is not linked into any queue and we
                // hold the scheduler lock, satisfying `enqueue`'s invariant.
                unsafe { (*current.as_ptr()).task.state = TaskState::Ready };
                inner.current_run_queue().enqueue(current);
            }
        }
        let next = match pick_next(&mut inner) {
            Some(n) => n,
            None => {
                // No runnable task and no idle task. This is a fatal
                // configuration (the scheduler must always have an idle task
                // post-`init`); clear the reschedule flag and return.
                preempt::clear_need_resched();
                // Release the run-queue lock before restoring IF. In process
                // context `flags` may have interrupts enabled; restoring it
                // while still locked would let a timer IRQ self-deadlock.
                drop(inner);
                // SAFETY: `flags` was captured on this CPU just above.
                unsafe { restore_flags(flags) };
                return;
            },
        };
        // Same task? No switch needed — clear the flag and return.
        if Some(next) == cur {
            // `cur` may have been requeued and immediately selected because
            // it was the only runnable ordinary task. Restore the lifecycle
            // state to match the current-task slot before returning.
            // SAFETY: `next` is current, off all queues after `pick_next`, and
            // protected by the scheduler lock with interrupts disabled.
            unsafe { (*next.as_ptr()).task.state = TaskState::Running };
            preempt::clear_need_resched();
            // As above, the scheduler lock must be gone before IF can be
            // restored for a process-context dispatch.
            drop(inner);
            // SAFETY: `flags` was captured on this CPU just above.
            unsafe { restore_flags(flags) };
            return;
        }
        // Mark the incoming task Running, stamp its CPU, and bump its stats.
        // SAFETY: `next` is live and we hold the lock; it is off all queues.
        unsafe {
            let task = core::ptr::addr_of_mut!((*next.as_ptr()).task);
            (*task).state = TaskState::Running;
            (*task).cpu = current_cpu() as u32;
            (*task).stats.context_switches = (*task).stats.context_switches.saturating_add(1);
        }
        // Install `next` as current *before* the switch so the trampoline
        // (reached on a first switch-in) can find it via `current_node`.
        // SAFETY: we are on the CPU that owns the slot.
        unsafe { set_current_node(Some(next)) };
        // Reset the per-CPU slice accounting for the incoming task so it gets
        // a fresh slice and a stale `need_resched` cannot immediately
        // re-trigger a switch into itself.
        preempt::on_context_switch_in();
        next
    }; // lock released here
       // `cur` is `Some` for a normal preemption/yield and `None` for the first
       // dispatch or after `exit` (bootstrap context).
    do_switch(cur, next, flags);
}

/// Whether a current task participates in round-robin requeue on dispatch.
///
/// Kept as a pure policy helper so the critical regression (ordinary running
/// tasks requeue; idle and non-running tasks do not) is host-testable without
/// constructing kernel stacks or touching the global scheduler.
#[inline]
fn should_requeue_for_dispatch(current_is_idle: bool, state: TaskState) -> bool {
    !current_is_idle && state == TaskState::Running
}

/// Choose the next task to run on this CPU.
///
/// Returns the head of the current CPU's run queue if non-empty, otherwise the
/// idle task. `None` is returned only if neither exists (a pre-`init` call or
/// a misconfiguration). The picked task is removed from the run queue; the
/// caller installs it as current.
fn pick_next(inner: &mut SchedulerInner) -> Option<NonNull<TaskNode>> {
    let cpu = current_cpu();
    if let Some(node) = inner.run_queues[cpu].pop_front() {
        return Some(node);
    }
    inner.current_idle()
}

/// Perform the context switch from `prev` (or the bootstrap context when
/// `None`) to `next`, then restore the saved interrupt state on the resuming
/// side.
///
/// This is the lowest layer of dispatch: the caller has already picked `next`,
/// installed it as current, and released the scheduler lock. `do_switch` runs
/// the asm trampoline with interrupts off (the caller's `save_flags_and_cli`
/// already cleared IF) and no lock held, so the incoming task can freely
/// re-acquire the lock when it next calls into the scheduler.
///
/// On the resuming side — when a previously-suspended task is switched back
/// into and `context_switch` returns into its `do_switch` frame — the saved
/// `flags` (captured by that task's own earlier `schedule_next`/`yield`/
/// `sleep_until` call) are restored, re-enabling interrupts iff the task had
/// them on when it was suspended. For a freshly-spawned task the trampoline
/// runs instead and this function never returns on the incoming stack, so the
/// restore is only reached by resuming tasks.
///
/// # Safety
///
/// `next` must point at a live `TaskNode` whose `ctx` is valid for a
/// switch-in. `prev`, when `Some`, must be the current task on this CPU.
/// Interrupts must be off and the scheduler lock must NOT be held.
fn do_switch(prev: Option<NonNull<TaskNode>>, next: NonNull<TaskNode>, flags: u64) {
    // Obtain the outgoing context. `prev` is the current task (its `ctx` will
    // be overwritten with the saved state); `None` means use the bootstrap
    // context for this CPU's first dispatch.
    let prev_ptr: *mut Context = match prev {
        Some(p) => {
            // SAFETY: `p` is live and is the current task; its `ctx` field is
            // what the trampoline writes the outgoing state into.
            unsafe { core::ptr::addr_of_mut!((*p.as_ptr()).ctx) }
        },
        None => unsafe { bootstrap_ctx() },
    };
    exchange_fpu_state(prev, next);

    // The incoming context is read-only from the trampoline's perspective.
    // SAFETY: `next` is live; we borrow its `ctx` shared for the duration of
    // the switch. The lock is not held but per-CPU ownership plus the
    // interrupt-off state prevent any other accessor on this CPU.
    let next_ctx: &Context = unsafe { &(*next.as_ptr()).ctx };

    // The asm trampoline takes `*mut u8` / `*mut u8` per its extern decl.
    let old = prev_ptr.cast::<u8>();
    let new = (next_ctx as *const Context) as *mut u8;

    // Publish every architecture-visible part of the incoming task before
    // loading its saved registers. This updates the syscall stack, both TSS
    // representations used by the BSP/AP paths, and the active page-table
    // root while interrupts are off. A userspace PML4 must retain the shared
    // kernel higher half, so `old`, `new`, and the switch code remain mapped
    // after the CR3 write.
    prepare_incoming_task(next);

    // Perform the switch. After this call returns we are running on `next`'s
    // stack (for a resuming task) or in `task_trampoline` (for a fresh task).
    //
    // SAFETY: upheld by the caller (the scheduler): both contexts are live and
    // non-aliased, `next`'s saved rsp is a valid mapped stack, and interrupts
    // are off (the caller's `save_flags_and_cli` cleared IF).
    unsafe { super::task::context_switch(old, new) };

    // --- Resuming task wakes up here on its own stack ---
    //
    // The callee-saved registers and rsp have been restored from this task's
    // `ctx`. The `flags` local was spilled to this stack across the
    // `extern "C"` call (per the SysV ABI), so it is the snapshot this task
    // captured when it was suspended. Restore it to re-enable interrupts iff
    // this task had them on at suspension time.
    //
    // The outgoing task may have exited instead of saving a resumable
    // context. We are now conclusively on this task's different kernel stack,
    // so it is safe to remove and destroy that retired node before IF is
    // restored. Fresh tasks perform the same hand-off in `task_trampoline`.
    reclaim_retired_after_switch();

    // SAFETY: `flags` was captured by this task's own `schedule_next` (or
    // sibling) call on this CPU before it was switched out; the stack
    // preservation of the trampoline guarantees it is the correct snapshot.
    unsafe { restore_flags(flags) };
}

/// Save the outgoing task's feature-sized FP/SIMD image and restore the
/// incoming task before switching stacks. Interrupts are disabled and both
/// nodes are off their queues, so their private save areas cannot race.
fn exchange_fpu_state(prev: Option<NonNull<TaskNode>>, next: NonNull<TaskNode>) {
    if let Some(mut previous) = prev {
        // SAFETY: `previous` is the current, exclusively-owned task node.
        if let Some(area) = unsafe { previous.as_mut() }.fpu.as_mut() {
            if !area.capture_current() {
                // A TS-armed task's authoritative image is already in its
                // scheduler area. Materialize it, then take a normalized
                // snapshot before ownership moves to the next task.
                area.restore_trusted();
                let captured = area.capture_current();
                debug_assert!(captured);
            }
        }
    }
    // SAFETY: `next` was removed from its run queue and is exclusively owned
    // by this dispatch until the context switch publishes it as current.
    if let Some(area) = unsafe { &mut *next.as_ptr() }.fpu.as_ref() {
        area.restore_trusted();
    }
}

/// Materialize the current task's scheduler-owned FP/SIMD image after a
/// CR0.TS trap or before signal-frame capture. This is the live bridge the
/// architecture-level save area cannot discover on its own.
pub fn materialize_current_fpu() -> bool {
    let flags = save_flags_and_cli();
    let restored = current_node().is_some_and(|node| {
        // SAFETY: interrupts are disabled and `node` is current on this CPU,
        // so no scheduler entry can move or mutate its private FPU area.
        let node = unsafe { &*node.as_ptr() };
        node.fpu.as_ref().is_some_and(|area| {
            area.restore_trusted();
            true
        })
    });
    // SAFETY: paired with the same-CPU flag snapshot above.
    unsafe { restore_flags(flags) };
    restored
}

/// Install the incoming task's architecture state before changing `rsp`.
///
/// Interrupts are disabled by every caller, so the TSS, GS-relative fields,
/// and CR3 change become visible as one scheduler transition on this CPU. A
/// CR3 write is skipped only when the exact target image is already active;
/// this preserves the local TLB for threads sharing an address space.
fn prepare_incoming_task(next: NonNull<TaskNode>) {
    // Copy every value out before CR3 changes. The task/node allocations live
    // in the shared kernel half, but ending the Rust borrow here also makes the
    // raw-pointer ownership around the architecture writes explicit.
    let (task_ptr, kernel_rsp, target_cr3) = unsafe {
        // SAFETY: `next` is the live, exclusively-owned incoming node and the
        // scheduler lock has removed it from all queues. Interrupts are off,
        // so no same-CPU scheduler entry can race these reads.
        let task: &mut Task = &mut (*next.as_ptr()).task;
        let target_cr3 = task
            .address_space
            .as_ref()
            .map_or_else(|| KERNEL_CR3.load(Ordering::Acquire), |space| space.cr3());
        (
            task as *mut Task,
            task.kernel_stack.top().as_u64(),
            target_cr3,
        )
    };

    // Keep the scheduler's TaskNode slot and the architecture per-CPU Task
    // pointer in agreement. Syscall/interrupt paths consume the latter.
    // SAFETY: `task_ptr` points into the live incoming TaskNode, which remains
    // owned by `all_tasks` for the entire time it can be current.
    unsafe { percpu::set_current_task(task_ptr) };

    // The syscall entry trampoline reads this GS-relative stack top. The AP
    // GDT path uses the TSS embedded in the same per-CPU area.
    // SAFETY: the task owns this mapped, 16-byte-aligned kernel stack and
    // remains alive throughout the switch.
    unsafe { percpu::set_kernel_rsp(kernel_rsp) };
    percpu::with(|cpu| cpu.tss.set_rsp0(kernel_rsp));

    // The current BSP GDT still references gdt.rs's static TSS rather than the
    // per-CPU copy, so keep that live hardware TSS synchronized as well. APs
    // use their per-CPU TSS and therefore need no BSP-static write.
    if current_cpu() == 0 {
        tss::set_bsp_rsp0(kernel_rsp);
    }

    // Avoid flushing non-global translations when two threads share a PML4.
    // SAFETY: both values come from a live AddressSpace or the CR3 captured at
    // scheduler init. Every process PML4 is required to map the kernel higher
    // half, so executing the remainder of this function after the write is
    // valid.
    let active_cr3 = unsafe { Cr3::read_raw() };
    if active_cr3 != target_cr3 {
        unsafe { Cr3::write_raw(target_cr3) };
    }
}

// ---------------------------------------------------------------------------
// Reaping
// ---------------------------------------------------------------------------

/// A zombie becomes reclaimable only after its owner CPU completes a switch.
///
/// `Zombie` records the logical exit; the per-CPU retirement hand-off proves
/// the CPU no longer uses the task's kernel stack. Removal uses `swap_remove`,
/// which moves the last `Kbox` into the freed slot; that moves only ownership
/// handle, not the heap data, so the raw pointers other tasks hold into their
/// own nodes stay valid.
#[inline]
const fn retired_task_reclaimable(state: TaskState, switch_completed: bool) -> bool {
    switch_completed && matches!(state, TaskState::Zombie)
}

/// Destroy the task retired by the immediately preceding switch on this CPU.
///
/// Every caller runs on the incoming task's stack with interrupts disabled.
/// Taking the per-CPU slot is therefore an allocation-free proof that the
/// retired node is no longer current and that its kernel stack is inactive.
/// The global scheduler lock removes the owning box from `all_tasks`; the box
/// is dropped only after the lock is released.
fn reclaim_retired_after_switch() {
    let cpu = current_cpu();
    let raw = RETIRED_TASK[cpu].swap(0, Ordering::AcqRel);
    if raw == 0 {
        return;
    }
    // SAFETY: `exit` stored a non-null TaskNode address that remains owned by
    // `all_tasks` until this exact post-switch hand-off removes it.
    let retired = unsafe { NonNull::new_unchecked(raw as *mut TaskNode) };
    let removed = {
        let mut inner = lock();
        let index = inner
            .all_tasks
            .iter()
            .position(|node| core::ptr::eq(&**node, retired.as_ptr()))
            .expect("sched: retired task disappeared from ownership list");
        let mut removed = inner.all_tasks.swap_remove(index);
        assert!(
            retired_task_reclaimable(removed.task.state, true),
            "sched: retirement slot contained a non-zombie task"
        );
        removed.task.state = TaskState::Dead;
        removed
    };
    ::log::debug!(
        "xenith.sched: reaped {} (tid={}) after CPU {} stack switch",
        removed.task.name,
        removed.task.id,
        cpu,
    );
    debug_assert_eq!(removed.task.state, TaskState::Dead);
    drop(removed);
}

/// Reclaim a completed per-CPU retirement, if one is pending.
///
/// Unlike a global zombie sweep, this cannot free a task merely because it is
/// marked `Zombie`; the same CPU must first have switched to another stack.
/// Context switches drain the slot automatically, so this public hook is only
/// a conservative maintenance entry point.
pub fn reap_zombies() {
    let flags = save_flags_and_cli();
    reclaim_retired_after_switch();
    // SAFETY: `flags` was captured on this CPU just above.
    unsafe { restore_flags(flags) };
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// A snapshot of scheduler counters for diagnostics.
///
/// All fields are sampled under the scheduler lock so the snapshot is
/// internally consistent. Intended for a future `ps`/`schedstat` debug surface
/// and for log lines during bring-up.
#[derive(Debug, Clone, Copy)]
pub struct SchedulerStats {
    /// Total tasks ever spawned and still tracked (not yet reaped).
    pub total_tasks: usize,
    /// Tasks currently on a run queue (summed across all CPUs).
    pub ready: usize,
    /// Tasks currently sleeping.
    pub sleeping: usize,
    /// Whether the scheduler has been initialised.
    pub initialised: bool,
}

/// Sample the current scheduler statistics under the lock.
#[must_use]
pub fn stats() -> SchedulerStats {
    let flags = save_flags_and_cli();
    let s = {
        let inner = lock();
        let ready: usize = inner.run_queues.iter().map(RunQueue::len).sum();
        SchedulerStats {
            total_tasks: inner.all_tasks.len(),
            ready,
            sleeping: inner.sleep_queue.len(),
            initialised: inner.initialised,
        }
    }; // lock released
       // SAFETY: `flags` was captured on this CPU just above.
    unsafe { restore_flags(flags) };
    s
}

// ---------------------------------------------------------------------------
// Tests (host target — exercise the pure-Rust queue and policy logic)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_one_cpu_owns_global_tick_accounting() {
        assert!(owns_global_tick(0));
        assert_eq!(
            (0..MAX_CPUS).filter(|cpu| owns_global_tick(*cpu)).count(),
            1
        );
    }

    #[test]
    fn scheduler_topology_always_contains_bsp() {
        assert_eq!(scheduler_online_mask(0), 1);
        assert_eq!(scheduler_online_mask(0b1010), 0b1011);
    }

    #[test]
    fn expired_wait_preserves_online_cpu_locality() {
        let online = scheduler_online_mask(0b1011);
        assert_eq!(wake_target_cpu(0, online), 0);
        assert_eq!(wake_target_cpu(1, online), 1);
        assert_eq!(wake_target_cpu(3, online), 3);
    }

    #[test]
    fn expired_wait_falls_back_to_bsp_for_offline_cpu() {
        let online = scheduler_online_mask(0b0011);
        assert_eq!(wake_target_cpu(3, online), GLOBAL_TICK_CPU);
        assert_eq!(wake_target_cpu(MAX_CPUS, online), GLOBAL_TICK_CPU);
    }

    #[test]
    fn run_queue_starts_empty() {
        let mut rq = RunQueue::new();
        assert!(rq.is_empty());
        assert_eq!(rq.len(), 0);
        assert!(rq.pop_front().is_none());
    }

    #[test]
    fn sleep_queue_starts_empty() {
        let sq = SleepQueue::new();
        assert_eq!(sq.len(), 0);
    }

    #[test]
    fn allocation_free_blocked_queue_starts_empty() {
        let queue = BlockedQueue::new();
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn interrupt_wake_credit_is_consumed_exactly_once() {
        let mut pending = true;
        assert!(consume_interrupt_credit(&mut pending));
        assert!(!pending);
        assert!(!consume_interrupt_credit(&mut pending));
    }

    #[test]
    fn process_exit_may_publish_only_after_kernel_cr3_detach() {
        let kernel_cr3 = 0x1234_5000;
        assert!(!exit_detach_complete(true, kernel_cr3, kernel_cr3));
        assert!(!exit_detach_complete(false, 0x9876_5000, kernel_cr3));
        assert!(!exit_detach_complete(false, kernel_cr3, 0));
        assert!(exit_detach_complete(false, kernel_cr3, kernel_cr3));
    }

    #[test]
    fn zombie_stack_is_never_reclaimed_before_the_switch_handoff() {
        assert!(!retired_task_reclaimable(TaskState::Zombie, false));
        assert!(retired_task_reclaimable(TaskState::Zombie, true));
        assert!(!retired_task_reclaimable(TaskState::Running, true));
        assert!(!retired_task_reclaimable(TaskState::Dead, true));
    }

    #[test]
    fn scheduler_inner_constructs_empty() {
        let inner = SchedulerInner::new();
        assert!(!inner.initialised);
        assert!(inner.all_tasks.is_empty());
        assert_eq!(inner.sleep_queue.len(), 0);
        assert_eq!(inner.blocked_queue.len(), 0);
        assert!(inner.idle_tasks.iter().all(|s| s.is_none()));
    }

    #[test]
    fn idle_task_is_fallback_only() {
        let mut inner = SchedulerInner::new();
        let idle = NonNull::<TaskNode>::dangling();
        inner.idle_tasks[0] = Some(idle);

        assert!(inner.run_queues[0].is_empty());
        assert_eq!(pick_next(&mut inner), Some(idle));
        assert!(inner.run_queues[0].is_empty());
    }

    #[test]
    fn preemption_requeues_only_running_non_idle_tasks() {
        assert!(should_requeue_for_dispatch(false, TaskState::Running));
        assert!(!should_requeue_for_dispatch(true, TaskState::Running));
        assert!(!should_requeue_for_dispatch(false, TaskState::Ready));
        assert!(!should_requeue_for_dispatch(false, TaskState::Sleeping));
        assert!(!should_requeue_for_dispatch(false, TaskState::Blocked));
        assert!(!should_requeue_for_dispatch(false, TaskState::Zombie));
    }

    #[test]
    fn staged_task_publication_token_commits_exactly_once() {
        let mut staged = StagedTask {
            id: TaskId(73),
            target_cpu: 3,
            committed: false,
        };

        assert_eq!(staged.id(), TaskId(73));
        assert_eq!(staged.target_cpu, 3);
        assert!(staged.mark_committed());
        assert!(!staged.mark_committed());
        // A committed token's Drop is intentionally inert and therefore does
        // not touch privileged scheduler state in this host-side test.
        drop(staged);
    }

    #[test]
    fn staged_rollback_reclaims_only_unlinked_unstarted_ready_nodes() {
        assert!(staged_node_cancellable(true, false, TaskState::Ready));
        assert!(!staged_node_cancellable(false, false, TaskState::Ready));
        assert!(!staged_node_cancellable(true, true, TaskState::Ready));
        assert!(!staged_node_cancellable(true, false, TaskState::Running));
        assert!(!staged_node_cancellable(true, false, TaskState::Blocked));
        assert!(!staged_node_cancellable(true, false, TaskState::Zombie));
    }

    #[test]
    fn is_initialised_is_queryable() {
        // `is_initialised` is a plain atomic load with no asm and no lock, so
        // it is safe to call from the host test harness. We do not assert a
        // specific value because the global may have been flipped by another
        // test or a prior `init`.
        let _ = is_initialised();
    }

    #[test]
    fn scheduler_stats_struct_is_constructible() {
        // The stats struct is `Copy`; we only confirm it can be built and read
        // without invoking `stats()` (which disables interrupts via asm and is
        // not safe to run from the host test harness).
        let s = SchedulerStats {
            total_tasks: 0,
            ready: 0,
            sleeping: 0,
            initialised: false,
        };
        assert_eq!(s.total_tasks, 0);
        assert!(!s.initialised);
    }
}
