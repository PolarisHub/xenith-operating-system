//! Userspace process ownership, launch, exit, and waiting.
//!
//! A [`UserProcess`] is deliberately separate from the scheduler's [`Task`]:
//! the scheduler owns execution state and kernel stacks, while this module
//! owns the POSIX-like process resources shared by those tasks (address
//! space, descriptors, children, exit status, and signals).  The global table
//! is protected by an IRQ-safe lock because syscall handlers run preemptibly.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::{fmt, ptr};

use xenith_types::{Page, VirtAddr, PAGE_SIZE};

use super::elf::{self, ElfError, UserPage};
use super::ring3;
use super::signal::{
    deliver_signal, deliver_signal_with_info, DefaultAction, DeliverOutcome, Signal, SignalAction,
    SignalState,
};
use crate::arch::x86_64::instructions::read_cr3;
use crate::fs::fd::{FdTable, RetiredFiles};
use crate::fs::inode::FileType;
use crate::fs::path::Path;
use crate::fs::vfs::{self, FsError};
use crate::ipc::shared_memory::SharedMemoryRef;
use crate::mm::physical;
use crate::mm::r#virtual::address_space::{self, AddressSpace, MapError, PageTableFlags, USER_MAX};
use crate::sched::{self, ExitStatus, TaskId};
use crate::sync::SpinLockIRQ;

/// PID 0 represents kernel context and is never inserted in the process table.
pub const KERNEL_PROCESS_ID: ProcessId = ProcessId(0);

/// Maximum argument count accepted by the initial stack builder.
pub const MAX_ARGUMENTS: usize = 256;

/// Maximum combined argument-string storage for one process.
pub const MAX_ARGUMENT_BYTES: usize = 64 * 1024;

/// Hard bound for live and waitable process records.
///
/// Besides bounding kernel ownership metadata, this lets signal delivery use
/// fixed stack batches for waiter hand-off instead of allocating while an
/// IRQ-safe process-table guard is held.
pub const MAX_PROCESSES: usize = 256;

/// Global bound for live userspace scheduler tasks. Keeping it equal to the
/// process bound preserves allocation-free signal wake batches even after a
/// process gains several threads.
const MAX_USER_THREADS: usize = MAX_PROCESSES;
const MAX_PROCESS_WAITERS: usize = MAX_USER_THREADS;
const PROCESS_MASK_WORDS: usize = MAX_PROCESSES.div_ceil(64);

/// Per-process live plus unjoined thread-record bound exposed by the ABI.
pub const MAX_THREADS_PER_PROCESS: usize = xenith_abi::THREAD_MAX_PER_PROCESS;

/// Maximum heap growth above an executable's initial break.
const MAX_BRK_BYTES: u64 = 256 * 1024 * 1024;

/// First-fit base for anonymous mappings. This leaves the low 4 GiB to the
/// executable and its conventional heap while remaining far below the stack.
const MMAP_BASE: u64 = 0x0000_0001_0000_0000;

/// Per-call private-allocation and combined dynamic-VA bounds. They prevent
/// one bad request from monopolising physical memory, page tables, or syscall
/// time. Shared objects have a tighter object-size bound in the IPC layer.
const MAX_ANONYMOUS_MAPPING: u64 = 256 * 1024 * 1024;
const MAX_DYNAMIC_MAPPING_TOTAL: u64 = 1024 * 1024 * 1024;

/// Dynamic mappings stop below the deliberately-unmapped stack guard page.
const DYNAMIC_LIMIT: u64 = elf::USER_STACK_TOP - elf::USER_STACK_SIZE - PAGE_SIZE;

/// Permissions retained for one dynamic mapping region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmProtection {
    pub writable: bool,
    pub executable: bool,
}

/// Physical backing retained for one `mmap` region.
#[derive(Clone, Debug)]
pub enum VmBacking {
    /// Private zero-filled frames owned through [`UserProcess::pages`].
    AnonymousPrivate,
    /// Existing object frames borrowed by the page table. The object owns and
    /// ultimately frees the frames after its final descriptor and mapping go
    /// away.
    Shared {
        object: SharedMemoryRef,
        object_offset: u64,
        /// Maximum write authority captured from the descriptor that
        /// created this mapping. Splits preserve it after the descriptor is
        /// closed, preventing `mprotect` from restoring attenuated rights.
        writable_allowed: bool,
    },
}

impl VmBacking {
    #[inline]
    #[must_use]
    pub const fn is_shared(&self) -> bool {
        matches!(self, Self::Shared { .. })
    }
}

impl PartialEq for VmBacking {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::AnonymousPrivate, Self::AnonymousPrivate) => true,
            (
                Self::Shared {
                    object: left,
                    object_offset: left_offset,
                    writable_allowed: left_writable,
                },
                Self::Shared {
                    object: right,
                    object_offset: right_offset,
                    writable_allowed: right_writable,
                },
            ) => {
                left_offset == right_offset
                    && left_writable == right_writable
                    && Arc::ptr_eq(left, right)
            },
            _ => false,
        }
    }
}

impl Eq for VmBacking {}

/// One page-aligned dynamic region created by `mmap`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmRegion {
    pub start: u64,
    pub end: u64,
    pub protection: VmProtection,
    pub backing: VmBacking,
}

/// A stable process identifier.  Values are monotonically allocated and never
/// reused during one boot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProcessId(pub u64);

impl ProcessId {
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    #[inline]
    #[must_use]
    pub const fn is_kernel(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pid#{}", self.0)
    }
}

/// Conventional short name used by syscall and init code.
pub type Pid = ProcessId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UserThread {
    task: TaskId,
    stack_start: u64,
    stack_end: u64,
    entry: u64,
    argument: u64,
    joiner: Option<TaskId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExitedThread {
    task: TaskId,
    status: ExitStatus,
}

/// Atomic process-group placement requested while spawning a child.
///
/// Placement happens before the scheduler can run the new task, avoiding the
/// parent-side `spawn`/`setpgid` race for short-lived pipeline stages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpawnGroup {
    /// Inherit the caller's process group.
    Inherit,
    /// Create a new process group led by the child.
    New,
    /// Join an existing process group in the caller's session.
    Join(ProcessId),
}

#[derive(Clone, Copy)]
enum SpawnDescriptorPolicy<'a> {
    InheritAll,
    Restricted {
        actions: &'a [xenith_abi::SpawnFileAction; xenith_abi::SPAWN_RESTRICTED_MAX_FILE_ACTIONS],
        count: usize,
    },
}

/// All resources owned by one user process.
pub struct UserProcess {
    pub pid: ProcessId,
    /// POSIX process group used by terminal job control and group signals.
    pub process_group: ProcessId,
    /// Session containing this process and its process group.
    pub session: ProcessId,
    pub address_space: AddressSpace,
    /// Live scheduler tasks which execute in this process's address space.
    threads: Vec<UserThread>,
    /// Completed joinable threads retained until `thread_join` consumes them.
    exited_threads: Vec<ExitedThread>,
    pub fd_table: FdTable,
    pub parent: Option<ProcessId>,
    pub children: Vec<ProcessId>,
    pub exit_status: ExitStatus,
    pub signals: SignalState,
    /// Cooperative stop state. A stopped task parks at the syscall boundary
    /// until a group-directed `SIGCONT` clears this flag.
    pub stopped: bool,
    wait_change: Option<WaitStatus>,
    /// The one task currently registered while blocked in `waitpid`. Registration
    /// is protected by `PROCESS_TABLE` and handed directly to the scheduler's
    /// intrusive blocked queue, so waiting never allocates.
    child_waiter: Option<TaskId>,
    /// First process-wide termination request. All live tasks observe this at
    /// the next kernel boundary; the last task publishes `exit_status`.
    termination_status: Option<ExitStatus>,
    pub path: String,
    entry: VirtAddr,
    user_rsp: VirtAddr,
    startup: VirtAddr,
    pages: Vec<UserPage>,
    /// Image-derived lower bound and exact current value of the program
    /// break. Only whole pages above/below `brk` are mapped or released.
    brk_base: u64,
    brk_current: u64,
    /// Sorted mmap-owned ranges. ELF, stack, trampoline, and heap mappings
    /// are intentionally absent so `munmap` cannot remove them. Shared
    /// backings keep their object alive independently of descriptor lifetime.
    vm_regions: Vec<VmRegion>,
    mmap_hint: u64,
    /// Saved post-syscall register image used only for the child's first
    /// dispatch after `fork`. Freshly spawned and exec-replaced images start
    /// through their ELF entry point and leave this as `None`.
    fork_resume: Option<ring3::UserContext>,
}

// Process records are moved through fixed-size kernel-stack locals during
// spawn/fork/exec. Keep their inline footprint small; bounded signal payload
// storage and other large tables must remain out of line.
const _: () = assert!(core::mem::size_of::<UserProcess>() <= 1024);

impl UserProcess {
    #[inline]
    #[must_use]
    pub const fn entry(&self) -> VirtAddr {
        self.entry
    }

    #[inline]
    #[must_use]
    pub const fn user_rsp(&self) -> VirtAddr {
        self.user_rsp
    }

    #[inline]
    #[must_use]
    pub const fn startup(&self) -> VirtAddr {
        self.startup
    }

    #[inline]
    #[must_use]
    pub fn pages(&self) -> &[UserPage] {
        &self.pages
    }

    #[inline]
    #[must_use]
    pub const fn program_break(&self) -> u64 {
        self.brk_current
    }

    #[inline]
    #[must_use]
    pub fn vm_regions(&self) -> &[VmRegion] {
        &self.vm_regions
    }

    #[inline]
    #[must_use]
    pub const fn has_exited(&self) -> bool {
        !self.exit_status.is_pending()
    }
}

impl fmt::Debug for UserProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserProcess")
            .field("pid", &self.pid)
            .field("path", &self.path)
            .field("parent", &self.parent)
            .field("process_group", &self.process_group)
            .field("session", &self.session)
            .field("stopped", &self.stopped)
            .field("children", &self.children)
            .field("threads", &self.threads)
            .field("exit_status", &self.exit_status)
            .field("entry", &self.entry)
            .field("user_rsp", &self.user_rsp)
            .field("mapped_pages", &self.pages.len())
            .field("brk", &self.brk_current)
            .field("dynamic_regions", &self.vm_regions.len())
            .field("fd_table", &self.fd_table)
            .finish()
    }
}

/// Observable child state returned by the wait family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitStatus {
    Exited(ExitStatus),
    Stopped(Signal),
    Continued,
}

/// Child-selection rules accepted by `waitpid(2)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitSelector {
    Any,
    Process(ProcessId),
    CurrentGroup,
    Group(ProcessId),
}

impl WaitSelector {
    fn matches(self, pid: ProcessId, process_group: ProcessId, parent_group: ProcessId) -> bool {
        match self {
            Self::Any => true,
            Self::Process(selected) => pid == selected,
            Self::CurrentGroup => process_group == parent_group,
            Self::Group(selected) => process_group == selected,
        }
    }
}

/// Result returned when a parent observes one child state change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitResult {
    pub pid: ProcessId,
    pub status: WaitStatus,
}

static NEXT_PID: AtomicU64 = AtomicU64::new(1);
static PROCESS_TABLE: SpinLockIRQ<Vec<UserProcess>> = SpinLockIRQ::new(Vec::new());

/// Compact fixed-capacity set of process-table indices used during group
/// delivery. Three instances consume 96 bytes at today's 256-process limit,
/// avoiding large boolean arrays on a 16 KiB kernel stack.
struct ProcessIndexSet {
    words: [u64; PROCESS_MASK_WORDS],
}

impl ProcessIndexSet {
    const fn new() -> Self {
        Self {
            words: [0; PROCESS_MASK_WORDS],
        }
    }

    fn insert(&mut self, index: usize) {
        assert!(index < MAX_PROCESSES, "process index exceeds fixed mask");
        self.words[index / 64] |= 1u64 << (index % 64);
    }

    fn contains(&self, index: usize) -> bool {
        index < MAX_PROCESSES && self.words[index / 64] & (1u64 << (index % 64)) != 0
    }
}

/// Allocation-free baton from process-table state publication to scheduler
/// wakeup. Waiter slots are taken while `PROCESS_TABLE` is locked, then every
/// task is woken only after that guard has been released.
struct ProcessWaiterBatch {
    tasks: [TaskId; MAX_PROCESS_WAITERS],
    len: usize,
}

/// Allocation-free list of parentless exited records to reclaim after
/// releasing `PROCESS_TABLE`. This covers both an already-zombie child whose
/// parent exits without waiting and a process which exits after it was
/// orphaned. Without this handoff those records could never have a waiter and
/// would permanently retain their address spaces.
struct OrphanReapBatch {
    pids: [ProcessId; MAX_PROCESSES],
    len: usize,
}

impl OrphanReapBatch {
    const fn new() -> Self {
        Self {
            pids: [KERNEL_PROCESS_ID; MAX_PROCESSES],
            len: 0,
        }
    }

    fn push(&mut self, pid: ProcessId) {
        if pid.is_kernel() || self.pids[..self.len].contains(&pid) {
            return;
        }
        assert!(
            self.len < self.pids.len(),
            "orphan reap batch exceeded MAX_PROCESSES invariant"
        );
        self.pids[self.len] = pid;
        self.len += 1;
    }

    fn as_slice(&self) -> &[ProcessId] {
        &self.pids[..self.len]
    }
}

const _: () = assert!(core::mem::size_of::<OrphanReapBatch>() <= 3 * 1024);

impl ProcessWaiterBatch {
    const fn new() -> Self {
        Self {
            tasks: [TaskId(0); MAX_PROCESS_WAITERS],
            len: 0,
        }
    }

    fn push(&mut self, waiter: Option<TaskId>) {
        let Some(waiter) = waiter else { return };
        if self.tasks[..self.len].contains(&waiter) {
            return;
        }
        assert!(
            self.len < self.tasks.len(),
            "process waiter batch exceeded MAX_PROCESSES invariant"
        );
        self.tasks[self.len] = waiter;
        self.len += 1;
    }

    fn wake_all(&self) {
        for waiter in &self.tasks[..self.len] {
            let _ = sched::scheduler::wake_blocked_task_from_task(*waiter);
        }
    }

    fn interrupt_all(&self) {
        for task in &self.tasks[..self.len] {
            let _ = sched::scheduler::interrupt_task_from_task(*task);
        }
    }
}

/// A process blocked in `waitpid` needs a group-signal wake only when it was a
/// delivery target itself or when one of its children acquired an observable
/// stop/continue state transition.
#[inline]
const fn group_child_waiter_relevant(
    target_accepted_signal: bool,
    parent_of_changed_child: bool,
) -> bool {
    target_accepted_signal || parent_of_changed_child
}

/// Finish the metadata-before-runnable half of process task publication.
///
/// Keeping the commit behind this pure gate makes the essential ordering
/// explicit and testable: a missing process-table record must drop the staged
/// task through the uncalled closure without ever enqueueing it.
fn finish_staged_task_publication<F>(
    pid: ProcessId,
    metadata_recorded: bool,
    commit: F,
) -> Result<ProcessId, ProcessError>
where
    F: FnOnce() -> bool,
{
    if !metadata_recorded || !commit() {
        return Err(ProcessError::TableCorrupt);
    }
    Ok(pid)
}

/// Spawn `path` with `argv`, returning once the process is installed on the
/// scheduler run queue.  An empty `argv` is normalised to `[path]`.
pub fn spawn(path: &str, argv: &[&str]) -> Result<ProcessId, ProcessError> {
    spawn_in_group(path, argv, SpawnGroup::Inherit)
}

/// Spawn a child with process-group placement completed before publication.
pub fn spawn_in_group(
    path: &str,
    argv: &[&str],
    group: SpawnGroup,
) -> Result<ProcessId, ProcessError> {
    spawn_with_descriptor_policy(path, argv, group, SpawnDescriptorPolicy::InheritAll)
}

/// Spawn a child whose descriptor table contains only the canonical
/// attenuated mappings in `request`.
pub fn spawn_restricted_in_group(
    path: &str,
    argv: &[&str],
    group: SpawnGroup,
    request: &xenith_abi::SpawnRestrictedRequest,
) -> Result<ProcessId, ProcessError> {
    if !request.is_canonical() {
        return Err(ProcessError::InvalidArgument);
    }
    spawn_with_descriptor_policy(path, argv, group, SpawnDescriptorPolicy::Restricted {
        actions: &request.file_actions,
        count: usize::from(request.file_action_count),
    })
}

fn spawn_with_descriptor_policy(
    path: &str,
    argv: &[&str],
    group: SpawnGroup,
    descriptor_policy: SpawnDescriptorPolicy<'_>,
) -> Result<ProcessId, ProcessError> {
    if path.is_empty() || !path.starts_with('/') || path.as_bytes().contains(&0) {
        return Err(ProcessError::InvalidPath);
    }
    validate_arguments(argv)?;
    let image = read_executable(path)?;

    // Complete every fallible bookkeeping allocation before creating page
    // tables, so an allocation failure cannot strand physical frames.
    let pid = allocate_pid()?;
    let parent = try_current_pid();
    let (fd_table, process_group, session) = if let Some(parent_pid) = parent {
        let table = PROCESS_TABLE.lock();
        let parent = table
            .iter()
            .find(|process| process.pid == parent_pid)
            .ok_or(ProcessError::NoCurrentProcess)?;
        let session = parent.session;
        let process_group = match group {
            SpawnGroup::Inherit => parent.process_group,
            SpawnGroup::New => pid,
            SpawnGroup::Join(requested) => {
                if requested.is_kernel()
                    || !table.iter().any(|process| {
                        process.process_group == requested && process.session == session
                    })
                {
                    return Err(ProcessError::NoSuchProcess(requested));
                }
                requested
            },
        };
        // Keep descriptor snapshotting last in this lock scope. A successful
        // restricted clone owns new FileRefs and has no fallible step after
        // it, so an error can never perform a final backend drop while
        // PROCESS_TABLE is held.
        let fd_table = match descriptor_policy {
            SpawnDescriptorPolicy::InheritAll => parent.fd_table.clone(),
            SpawnDescriptorPolicy::Restricted { actions, count } => parent
                .fd_table
                .clone_restricted(actions, count)
                .map_err(ProcessError::Filesystem)?,
        };
        (fd_table, process_group, session)
    } else {
        let process_group = match group {
            SpawnGroup::Inherit | SpawnGroup::New => pid,
            SpawnGroup::Join(requested) => return Err(ProcessError::NoSuchProcess(requested)),
        };
        let fd_table = match descriptor_policy {
            SpawnDescriptorPolicy::InheritAll => FdTable::new_process(),
            SpawnDescriptorPolicy::Restricted { .. } => return Err(ProcessError::NoCurrentProcess),
        };
        (fd_table, process_group, pid)
    };
    let mut process_path = String::new();
    process_path
        .try_reserve_exact(path.len())
        .map_err(|_| ProcessError::OutOfMemory)?;
    process_path.push_str(path);
    let task_name = make_task_name(path)?;
    let mut threads = Vec::new();
    threads
        .try_reserve_exact(MAX_THREADS_PER_PROCESS)
        .map_err(|_| ProcessError::OutOfMemory)?;
    let mut exited_threads = Vec::new();
    exited_threads
        .try_reserve_exact(MAX_THREADS_PER_PROCESS)
        .map_err(|_| ProcessError::OutOfMemory)?;
    let mut children = Vec::new();
    children
        .try_reserve(1)
        .map_err(|_| ProcessError::OutOfMemory)?;
    let signals = SignalState::try_new().map_err(|_| ProcessError::OutOfMemory)?;

    let mut space = AddressSpace::new_empty().map_err(ProcessError::AddressSpace)?;
    let loaded = match elf::load_image(&image, &mut space) {
        Ok(loaded) => loaded,
        Err(error) => {
            // SAFETY: the fresh space was never published or activated.  The
            // loader removed any leaf mappings before returning an error.
            unsafe { elf::destroy(space, &[]) };
            return Err(ProcessError::Elf(error));
        },
    };

    let (user_rsp, startup) = match build_initial_stack(&space, loaded.stack_top, path, argv) {
        Ok(stack) => stack,
        Err(error) => {
            let pages = loaded.pages();
            // SAFETY: the address space is still private and inactive.
            unsafe { elf::destroy(space, pages) };
            return Err(error);
        },
    };

    let initial_break = loaded.initial_break();
    let process = UserProcess {
        pid,
        process_group,
        session,
        address_space: space,
        threads,
        exited_threads,
        fd_table,
        parent,
        children,
        exit_status: ExitStatus::Pending,
        signals,
        stopped: false,
        wait_change: None,
        child_waiter: None,
        termination_status: None,
        path: process_path,
        entry: loaded.entry,
        user_rsp,
        startup,
        pages: loaded.into_pages(),
        brk_base: initial_break,
        brk_current: initial_break,
        vm_regions: Vec::new(),
        mmap_hint: MMAP_BASE,
        fork_resume: None,
    };

    let mut pending_process = Some(process);
    if let Err(error) = install_process(&mut pending_process) {
        if let Some(process) = pending_process.take() {
            reclaim_process(process);
        }
        return Err(error);
    }

    // Allocate scheduler ownership without putting the task on any run queue.
    // This gap is the cross-CPU publication transaction: record the TaskId
    // under PROCESS_TABLE first, then commit can enqueue and notify a remote
    // CPU. Local preemption control alone cannot close that remote race.
    let result = match sched::stage_spawn(task_name, launch_process, pid.as_u64()) {
        Some(staged) => {
            let task_id = staged.id();
            let recorded = {
                let mut table = PROCESS_TABLE.lock();
                match table.iter_mut().find(|process| process.pid == pid) {
                    Some(process) => {
                        debug_assert!(process.threads.len() < process.threads.capacity());
                        process.threads.push(UserThread {
                            task: task_id,
                            stack_start: elf::USER_STACK_TOP - elf::USER_STACK_SIZE,
                            stack_end: elf::USER_STACK_TOP,
                            entry: process.entry.as_u64(),
                            argument: process.startup.as_u64(),
                            joiner: None,
                        });
                        true
                    },
                    None => false,
                }
            };
            finish_staged_task_publication(pid, recorded, || staged.commit().is_some())
        },
        None => Err(ProcessError::OutOfMemory),
    };

    if let Err(error) = result {
        if let Some(process) = remove_process(pid) {
            reclaim_process(process);
        }
        return Err(error);
    }

    ::log::info!("user.process: spawned {} as {}", path, pid);
    Ok(pid)
}

/// Duplicate the current process and arrange for the child to return from the
/// same syscall with RAX=0.
pub fn fork(context: ring3::UserContext) -> Result<ProcessId, ProcessError> {
    let parent_pid = try_current_pid().ok_or(ProcessError::NoCurrentProcess)?;
    let pid = allocate_pid()?;
    let child_signals = SignalState::try_new().map_err(|_| ProcessError::OutOfMemory)?;

    // Snapshot all inherited process resources while the table is stable.
    // Heap-backed metadata uses fallible reservation so OOM is reported to
    // userspace rather than panicking inside the kernel.
    let (
        parent_space,
        parent_pages,
        process_path,
        fd_table,
        signals,
        process_group,
        session,
        entry,
        user_rsp,
        startup,
        brk_base,
        brk_current,
        vm_regions,
        mmap_hint,
    ) = {
        let table = PROCESS_TABLE.lock();
        let parent = table
            .iter()
            .find(|record| record.pid == parent_pid)
            .ok_or(ProcessError::NoCurrentProcess)?;
        if !process_image_change_allowed(parent.threads.len(), parent.termination_status.is_some())
        {
            // Xenith snapshots process-wide mappings and signal state. Until
            // those resources gain a stop-the-world protocol, cloning them
            // while another task can mutate userspace is not safe.
            return Err(ProcessError::Busy);
        }
        if parent
            .vm_regions
            .iter()
            .any(|region| region.backing.is_shared())
        {
            // AddressSpace::fork currently applies private COW semantics to
            // every user PTE. Refuse the operation before it can turn a
            // genuinely shared mapping into a private snapshot.
            return Err(ProcessError::SharedMappingsUnsupported);
        }
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(parent.pages.len())
            .map_err(|_| ProcessError::OutOfMemory)?;
        pages.extend_from_slice(&parent.pages);
        let mut path = String::new();
        path.try_reserve_exact(parent.path.len())
            .map_err(|_| ProcessError::OutOfMemory)?;
        path.push_str(&parent.path);
        let mut regions = Vec::new();
        regions
            .try_reserve_exact(parent.vm_regions.len())
            .map_err(|_| ProcessError::OutOfMemory)?;
        regions.extend(parent.vm_regions.iter().cloned());
        parent.signals.copy_for_fork_into(&child_signals);
        (
            parent.address_space,
            pages,
            path,
            parent.fd_table.clone(),
            child_signals,
            parent.process_group,
            parent.session,
            parent.entry,
            parent.user_rsp,
            parent.startup,
            parent.brk_base,
            parent.brk_current,
            regions,
            parent.mmap_hint,
        )
    };

    let task_name = make_task_name(&process_path)?;
    let mut threads = Vec::new();
    threads
        .try_reserve_exact(MAX_THREADS_PER_PROCESS)
        .map_err(|_| ProcessError::OutOfMemory)?;
    let mut exited_threads = Vec::new();
    exited_threads
        .try_reserve_exact(MAX_THREADS_PER_PROCESS)
        .map_err(|_| ProcessError::OutOfMemory)?;
    let mut children = Vec::new();
    children
        .try_reserve(1)
        .map_err(|_| ProcessError::OutOfMemory)?;

    let mut child_pages = Vec::new();
    child_pages
        .try_reserve_exact(parent_pages.len())
        .map_err(|_| ProcessError::OutOfMemory)?;
    let child_space = parent_space.fork().map_err(ProcessError::AddressSpace)?;
    for mapping in &parent_pages {
        let Some((frame, _)) = child_space.translate(mapping.page) else {
            // The fork walker just copied every present user mapping; failure
            // here means its page-table invariant was violated.
            unsafe { elf::destroy(child_space, &child_pages) };
            return Err(ProcessError::TableCorrupt);
        };
        child_pages.push(UserPage {
            page: mapping.page,
            frame,
        });
    }

    let process = UserProcess {
        pid,
        process_group,
        session,
        address_space: child_space,
        threads,
        exited_threads,
        fd_table,
        parent: Some(parent_pid),
        children,
        exit_status: ExitStatus::Pending,
        signals,
        stopped: false,
        wait_change: None,
        child_waiter: None,
        termination_status: None,
        path: process_path,
        entry,
        user_rsp,
        startup,
        pages: child_pages,
        brk_base,
        brk_current,
        vm_regions,
        mmap_hint,
        fork_resume: Some(context),
    };

    let mut pending_process = Some(process);
    if let Err(error) = install_process(&mut pending_process) {
        if let Some(process) = pending_process.take() {
            reclaim_process(process);
        }
        return Err(error);
    }

    // As in spawn, a staged scheduler node cannot execute on another CPU
    // until its TaskId is visible in the installed process record.
    let result = match sched::stage_spawn(task_name, launch_process, pid.as_u64()) {
        Some(staged) => {
            let task_id = staged.id();
            let recorded = {
                let mut table = PROCESS_TABLE.lock();
                match table.iter_mut().find(|record| record.pid == pid) {
                    Some(record) => {
                        debug_assert!(record.threads.len() < record.threads.capacity());
                        record.threads.push(UserThread {
                            task: task_id,
                            stack_start: elf::USER_STACK_TOP - elf::USER_STACK_SIZE,
                            stack_end: elf::USER_STACK_TOP,
                            entry: record.entry.as_u64(),
                            argument: record.startup.as_u64(),
                            joiner: None,
                        });
                        true
                    },
                    None => false,
                }
            };
            finish_staged_task_publication(pid, recorded, || staged.commit().is_some())
        },
        None => Err(ProcessError::OutOfMemory),
    };
    if let Err(error) = result {
        if let Some(process) = remove_process(pid) {
            reclaim_process(process);
        }
        return Err(error);
    }
    ::log::info!("user.process: forked {} from {}", pid, parent_pid);
    result
}

/// Replace the current process image without changing its PID, parent,
/// children, or scheduler task. On success this switches CR3, reclaims the old
/// image, and enters the new ELF entry point, so it never returns.
pub fn exec(path: &str, argv: &[&str]) -> Result<(), ProcessError> {
    if path.is_empty() || !path.starts_with('/') || path.as_bytes().contains(&0) {
        return Err(ProcessError::InvalidPath);
    }
    let pid = try_current_pid().ok_or(ProcessError::NoCurrentProcess)?;
    let node = sched::scheduler::current_node().ok_or(ProcessError::NoCurrentProcess)?;
    let current_task = unsafe { node.as_ref() }.task.id;
    {
        let table = PROCESS_TABLE.lock();
        let process = table
            .iter()
            .find(|record| record.pid == pid)
            .ok_or(ProcessError::NoCurrentProcess)?;
        if !process_image_change_allowed(
            process.threads.len(),
            process.termination_status.is_some(),
        ) || process.threads[0].task != current_task
        {
            return Err(ProcessError::Busy);
        }
    }
    validate_arguments(argv)?;
    // Reserve every signal table before allocating an address space. The
    // commit below only copies into this backing while holding PROCESS_TABLE,
    // so it cannot fail or lose a signal delivered during exec.
    let replacement_signals = SignalState::try_new().map_err(|_| ProcessError::OutOfMemory)?;
    let image = read_executable(path)?;
    let mut process_path = String::new();
    process_path
        .try_reserve_exact(path.len())
        .map_err(|_| ProcessError::OutOfMemory)?;
    process_path.push_str(path);
    let task_name = make_task_name(path)?;

    let mut space = AddressSpace::new_empty().map_err(ProcessError::AddressSpace)?;
    let loaded = match elf::load_image(&image, &mut space) {
        Ok(loaded) => loaded,
        Err(error) => {
            // SAFETY: this new image is private and inactive.
            unsafe { elf::destroy(space, &[]) };
            return Err(ProcessError::Elf(error));
        },
    };
    let (user_rsp, startup) = match build_initial_stack(&space, loaded.stack_top, path, argv) {
        Ok(stack) => stack,
        Err(error) => {
            // SAFETY: this new image is private and inactive.
            unsafe { elf::destroy(space, loaded.pages()) };
            return Err(error);
        },
    };
    let entry = loaded.entry;
    let initial_break = loaded.initial_break();
    let pages = loaded.into_pages();
    // The UI session is an implicit, process-bound capability rather than an
    // ordinary file descriptor. Do not transfer it across exec into an
    // unrelated image; restore the text console only after the replacement
    // image has been fully prepared so a failed exec preserves ownership.
    let _ = crate::ui::release_if_owner(pid);
    // From publication through the CR3 switch and old-image teardown, no
    // timer interrupt may switch this task against a half-committed process
    // record. The guard intentionally lives through the diverging ring3 jump.
    // SAFETY: exec runs at CPL0 on the current task and the guard remains on
    // this CPU through the diverging user transition.
    let _interrupts = unsafe { crate::arch::x86_64::instructions::InterruptGuard::disable() };
    let (old_space, old_pages, old_regions, kernel_rsp, closed_files) = {
        let mut table = PROCESS_TABLE.lock();
        let process = table
            .iter_mut()
            .find(|record| record.pid == pid)
            .ok_or(ProcessError::NoCurrentProcess)?;
        let old_space = core::mem::replace(&mut process.address_space, space);
        let old_pages = core::mem::replace(&mut process.pages, pages);
        let old_regions = core::mem::take(&mut process.vm_regions);
        process.path = process_path;
        process.entry = entry;
        process.user_rsp = user_rsp;
        process.startup = startup;
        process.brk_base = initial_break;
        process.brk_current = initial_break;
        process.mmap_hint = MMAP_BASE;
        process.fork_resume = None;
        process.exited_threads.clear();
        process.threads[0].stack_start = elf::USER_STACK_TOP - elf::USER_STACK_SIZE;
        process.threads[0].stack_end = elf::USER_STACK_TOP;
        process.threads[0].entry = entry.as_u64();
        process.threads[0].argument = startup.as_u64();
        process.threads[0].joiner = None;
        process.termination_status = None;
        let closed_files = process.fd_table.close_on_exec();
        process.signals.copy_for_exec_into(&replacement_signals);
        process.signals = replacement_signals;

        // SAFETY: interrupts are disabled and `node` is this CPU's current,
        // scheduler-owned task. No other CPU can mutate its address-space or
        // stack fields during this commit.
        let kernel_rsp = unsafe {
            let task = &mut *(*node.as_ptr()).task;
            task.address_space = Some(space);
            task.name = task_name;
            task.kernel_stack.top().as_u64()
        };
        (old_space, old_pages, old_regions, kernel_rsp, closed_files)
    };
    // Backend destruction may wake blocked peers. Keep that work outside the
    // global process table even though exec remains IRQ-pinned through ring3.
    drop(closed_files);

    // Switch first, then reclaim: executing kernel text/stack/heap are shared
    // in the new upper half, while the old user hierarchy is now inactive.
    // SAFETY: ELF loading installed a valid PML4 with the shared kernel half.
    unsafe { space.load() };
    // SAFETY: CR3 now names `space`; exec's admission gate proved the caller
    // is the only live task, so the old hierarchy is unpublished everywhere.
    unsafe { elf::destroy(old_space, &old_pages) };
    // `destroy` has removed the old page-table hierarchy. Shared-memory
    // objects may now release their physical frames if these mappings were
    // their final references. Keep that destructor outside PROCESS_TABLE.
    drop(old_regions);
    ::log::info!("user.process: exec {} in {}", path, pid);
    // SAFETY: the loaded image validated entry/stack permissions and `space`
    // is already active with this task's live kernel stack installed below.
    unsafe {
        ring3::jump_to_user(
            entry.as_u64(),
            user_rsp.as_u64(),
            startup.as_u64(),
            space.cr3(),
            kernel_rsp,
        )
    }
}

/// Mark the current process exited and permanently leave its scheduler task.
pub fn exit(code: i32) -> ! {
    exit_with_status(ExitStatus::Code(i64::from(code)))
}

/// Terminate the current process due to an unhandled signal.
pub fn exit_signal(signal: Signal) -> ! {
    exit_with_status(ExitStatus::Signal(signal.as_number() as i32))
}

fn exit_with_status(status: ExitStatus) -> ! {
    let pid = current_pid();
    if pid.is_kernel() {
        sched::scheduler::exit(status);
    }
    let current_task =
        sched::scheduler::with_current_node(|node| node.task.id).unwrap_or(TaskId(0));
    let mut peers = ProcessWaiterBatch::new();
    {
        let mut table = PROCESS_TABLE.lock();
        if let Some(process) = table.iter_mut().find(|process| process.pid == pid) {
            if process.termination_status.is_none() {
                process.termination_status = Some(status);
            }
            for thread in &process.threads {
                if thread.task != current_task {
                    peers.push(Some(thread.task));
                }
            }
        }
    }
    // Revoke scanout/input as soon as process-wide termination is requested.
    // Every blocked peer receives an interrupt credit and observes the same
    // request before it can return to userspace.
    let _ = crate::ui::release_if_owner(pid);
    peers.interrupt_all();
    exit_current_thread(status)
}

/// Exit only the calling thread. The last live thread performs process
/// teardown and publishes its code as the process result.
pub fn thread_exit(code: i32) -> ! {
    exit_current_thread(ExitStatus::Code(i64::from(code)))
}

fn exit_current_thread(status: ExitStatus) -> ! {
    let pid = current_pid();
    if pid.is_kernel() {
        sched::scheduler::exit(status);
    }
    let task = sched::scheduler::with_current_node(|node| node.task.id).unwrap_or(TaskId(0));

    // Every task drops its CR3 ownership before it disappears from the live
    // thread set. Consequently the last-thread publication proves that no CPU
    // can still execute through the process page-table root.
    sched::scheduler::detach_current_address_space();

    let mut thread_joiner = None;
    let mut parent_waiter = None;
    let mut closed_files = RetiredFiles::new();
    let mut orphan_reaps = OrphanReapBatch::new();
    let mut last_thread = false;
    {
        let mut table = PROCESS_TABLE.lock();
        if let Some(index) = table.iter().position(|process| process.pid == pid) {
            if let Some(thread_index) = table[index]
                .threads
                .iter()
                .position(|thread| thread.task == task)
            {
                let thread = table[index].threads.swap_remove(thread_index);
                thread_joiner = thread.joiner;
                last_thread = should_publish_process_exit(table[index].threads.len());
                if !last_thread && table[index].termination_status.is_none() {
                    debug_assert!(
                        table[index].exited_threads.len() < table[index].exited_threads.capacity()
                    );
                    table[index]
                        .exited_threads
                        .push(ExitedThread { task, status });
                }
            }

            let parent = if last_thread && table[index].exit_status.is_pending() {
                let process_status = final_process_status(table[index].termination_status, status);
                table[index].exit_status = process_status;
                closed_files = table[index].fd_table.close_all();
                // Orphan live children without allocating under the global
                // table lock. Children which already exited have no future
                // execution path that could auto-reap them, so hand their
                // PIDs to the post-lock reaper now.
                let child_count = table[index].children.len();
                for child_offset in 0..child_count {
                    let child = table[index].children[child_offset];
                    if let Some(record) = table.iter_mut().find(|record| record.pid == child) {
                        record.parent = None;
                        if !record.exit_status.is_pending() {
                            orphan_reaps.push(child);
                        }
                    }
                }
                table[index].children.clear();
                let parent = table[index].parent;
                if parent.is_none() {
                    orphan_reaps.push(pid);
                }
                parent
            } else {
                None
            };
            if let Some(parent) = parent {
                parent_waiter = table
                    .iter_mut()
                    .find(|record| record.pid == parent)
                    .and_then(|record| record.child_waiter.take());
            }
        }
    }
    // A final pipe/PTY reference may wake blocked peers during backend drop.
    // The process-table guard is gone before any such destructor can run.
    drop(closed_files);
    for orphan in orphan_reaps.as_slice() {
        if let Some(process) = remove_parentless_exited_process(*orphan) {
            reclaim_process(process);
        }
    }
    wake_process_waiter(thread_joiner);
    wake_process_waiter(parent_waiter);
    if last_thread {
        let _ = crate::ui::release_if_owner(pid);
    }
    sched::scheduler::exit(status)
}

/// Create one joinable userspace task sharing the caller's address space.
///
/// The stack mapping remains owned by userspace. Xenith validates that every
/// page is present, private-by-contract, writable, and non-executable, then
/// prevents every address-space mutation while more than one thread is live.
pub fn create_thread(request: xenith_abi::ThreadCreate) -> Result<u64, ProcessError> {
    validate_thread_request(&request)?;
    let pid = try_current_pid().ok_or(ProcessError::NoCurrentProcess)?;
    let stack_end = request
        .stack_base
        .checked_add(request.stack_size)
        .ok_or(ProcessError::InvalidArgument)?;

    let space = {
        let table = PROCESS_TABLE.lock();
        let process = table
            .iter()
            .find(|process| process.pid == pid)
            .ok_or(ProcessError::NoCurrentProcess)?;
        validate_thread_publication(&table, process, &request, stack_end)?;
        process.address_space
    };

    let task_name = make_thread_task_name()?;
    let mut staged = sched::stage_spawn(task_name, launch_thread, pid.as_u64())
        .ok_or(ProcessError::OutOfMemory)?;
    if !staged.attach_address_space(space) {
        return Err(ProcessError::TableCorrupt);
    }
    let task = staged.id();

    let recorded = {
        let mut table = PROCESS_TABLE.lock();
        let Some(index) = table.iter().position(|process| process.pid == pid) else {
            return Err(ProcessError::NoCurrentProcess);
        };
        let valid = {
            let process = &table[index];
            validate_thread_publication(&table, process, &request, stack_end).is_ok()
                && process.address_space == space
        };
        if !valid {
            false
        } else {
            let process = &mut table[index];
            debug_assert!(process.threads.len() < process.threads.capacity());
            process.threads.push(UserThread {
                task,
                stack_start: request.stack_base,
                stack_end,
                entry: request.entry,
                argument: request.argument,
                joiner: None,
            });
            true
        }
    };

    if !recorded {
        return Err(ProcessError::Busy);
    }
    if staged.commit().is_none() {
        let mut table = PROCESS_TABLE.lock();
        if let Some(process) = table.iter_mut().find(|process| process.pid == pid) {
            process.threads.retain(|thread| thread.task != task);
        }
        return Err(ProcessError::TableCorrupt);
    }
    Ok(task.as_u64())
}

/// Block until `thread` exits, consume its join record, and return its code.
pub fn join_thread(thread: u64) -> Result<i32, ProcessError> {
    let target = TaskId(thread);
    let current = sched::scheduler::with_current_node(|node| node.task.id)
        .ok_or(ProcessError::NoCurrentProcess)?;
    if target.as_u64() == 0 || target == current {
        return Err(ProcessError::InvalidArgument);
    }
    let pid = try_current_pid().ok_or(ProcessError::NoCurrentProcess)?;

    loop {
        let mut table = PROCESS_TABLE.lock();
        let process = table
            .iter_mut()
            .find(|process| process.pid == pid)
            .ok_or(ProcessError::NoCurrentProcess)?;

        if let Some(index) = process
            .exited_threads
            .iter()
            .position(|record| record.task == target)
        {
            let completed = process.exited_threads.swap_remove(index);
            return Ok(thread_exit_code(completed.status));
        }

        let target_thread = process
            .threads
            .iter_mut()
            .find(|record| record.task == target)
            .ok_or(ProcessError::NoSuchThread)?;
        match target_thread.joiner {
            None => target_thread.joiner = Some(current),
            Some(joiner) if joiner == current => {},
            Some(_) => return Err(ProcessError::Busy),
        }
        if process.termination_status.is_some() || process.signals.has_interrupting_delivery() {
            target_thread.joiner = None;
            return Err(ProcessError::Interrupted);
        }
        sched::scheduler::block_current_until_releasing(None, table);
    }
}

/// Globally unique id of the calling scheduler task.
#[must_use]
pub fn current_thread_id() -> Option<u64> {
    sched::scheduler::with_current_node(|node| node.task.id.as_u64())
}

/// Number of live tasks in the calling process.
#[must_use]
pub fn current_live_thread_count() -> Option<usize> {
    with_current_process(|process| process.threads.len())
}

fn validate_thread_request(request: &xenith_abi::ThreadCreate) -> Result<(), ProcessError> {
    if request.version != xenith_abi::THREAD_ABI_VERSION
        || request.flags != 0
        || request.reserved != [0; 2]
        || request.entry == 0
        || request.entry > USER_MAX
    {
        return Err(ProcessError::InvalidArgument);
    }
    if request.tls_base != 0 {
        return Err(ProcessError::TlsUnsupported);
    }
    if request.stack_base == 0
        || request.stack_base & (PAGE_SIZE - 1) != 0
        || request.stack_size & (PAGE_SIZE - 1) != 0
        || !(xenith_abi::THREAD_STACK_MIN..=xenith_abi::THREAD_STACK_MAX)
            .contains(&request.stack_size)
    {
        return Err(ProcessError::InvalidArgument);
    }
    let end = request
        .stack_base
        .checked_add(request.stack_size)
        .ok_or(ProcessError::InvalidArgument)?;
    if end <= request.stack_base || end - 1 > USER_MAX {
        return Err(ProcessError::InvalidArgument);
    }
    Ok(())
}

fn validate_thread_publication(
    table: &[UserProcess],
    process: &UserProcess,
    request: &xenith_abi::ThreadCreate,
    stack_end: u64,
) -> Result<(), ProcessError> {
    if process.termination_status.is_some()
        || process.threads.len() + process.exited_threads.len() >= MAX_THREADS_PER_PROCESS
        || table
            .iter()
            .map(|record| record.threads.len())
            .sum::<usize>()
            >= MAX_USER_THREADS
    {
        return Err(ProcessError::Busy);
    }
    if process.threads.iter().any(|thread| {
        stack_ranges_overlap(
            request.stack_base,
            stack_end,
            thread.stack_start,
            thread.stack_end,
        )
    }) {
        return Err(ProcessError::InvalidArgument);
    }

    let entry_page = Page::containing_addr(VirtAddr::new_truncate(request.entry));
    let Some((_, entry_flags)) = process.address_space.translate(entry_page) else {
        return Err(ProcessError::InvalidArgument);
    };
    if !entry_flags.contains(PageTableFlags::PRESENT | PageTableFlags::USER)
        || entry_flags.contains(PageTableFlags::NO_EXECUTE)
    {
        return Err(ProcessError::PermissionDenied);
    }

    let required = PageTableFlags::PRESENT
        | PageTableFlags::USER
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE;
    let mut address = request.stack_base;
    while address < stack_end {
        let page = Page::containing_addr(VirtAddr::new_truncate(address));
        let Some((_, flags)) = process.address_space.translate(page) else {
            return Err(ProcessError::InvalidArgument);
        };
        if !flags.contains(required) {
            return Err(ProcessError::PermissionDenied);
        }
        address += PAGE_SIZE;
    }
    Ok(())
}

#[inline]
fn thread_exit_code(status: ExitStatus) -> i32 {
    match status {
        ExitStatus::Code(code) => code.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
        ExitStatus::Signal(signal) => -signal.abs(),
        ExitStatus::Pending => 0,
    }
}

#[inline]
const fn process_image_change_allowed(live_threads: usize, terminating: bool) -> bool {
    live_threads == 1 && !terminating
}

#[inline]
const fn should_publish_process_exit(remaining_live_threads: usize) -> bool {
    remaining_live_threads == 0
}

#[inline]
const fn final_process_status(
    termination_status: Option<ExitStatus>,
    last_thread_status: ExitStatus,
) -> ExitStatus {
    match termination_status {
        Some(status) => status,
        None => last_thread_status,
    }
}

#[inline]
const fn stack_ranges_overlap(
    left_start: u64,
    left_end: u64,
    right_start: u64,
    right_end: u64,
) -> bool {
    left_start < right_end && right_start < left_end
}

/// Non-blocking wait for an exited child. `pid == ProcessId(0)` selects any
/// child, preserving the original kernel-internal convenience API.
pub fn try_wait(pid: ProcessId) -> Result<Option<WaitResult>, ProcessError> {
    let selector = if pid.is_kernel() {
        WaitSelector::Any
    } else {
        WaitSelector::Process(pid)
    };
    try_wait_selector(selector, false, false)
}

/// Non-blocking POSIX child-state wait with process-group selection.
pub fn try_wait_selector(
    selector: WaitSelector,
    include_stopped: bool,
    include_continued: bool,
) -> Result<Option<WaitResult>, ProcessError> {
    let parent = try_current_pid().ok_or(ProcessError::NoCurrentProcess)?;
    let (result, reaped) = {
        let mut table = PROCESS_TABLE.lock();
        poll_wait_selector_locked(
            &mut table,
            parent,
            selector,
            include_stopped,
            include_continued,
        )?
    };

    if let Some(reaped) = reaped {
        reclaim_process(reaped);
    }
    Ok(result)
}

/// Block until the selected child exits, then reap it.
pub fn wait(pid: ProcessId) -> Result<WaitResult, ProcessError> {
    let selector = if pid.is_kernel() {
        WaitSelector::Any
    } else {
        WaitSelector::Process(pid)
    };
    wait_selector(selector, false, false)
}

/// Block without allocating until any selected child state changes.
///
/// The process-table guard protects both the child predicate and the waiter
/// slot. [`sched::scheduler::block_current_until_releasing`] links the task in
/// the scheduler before releasing that guard, so an exit/signal producer can
/// neither miss the registration nor attempt to wake an unparked task.
pub fn wait_selector(
    selector: WaitSelector,
    include_stopped: bool,
    include_continued: bool,
) -> Result<WaitResult, ProcessError> {
    let parent = try_current_pid().ok_or(ProcessError::NoCurrentProcess)?;
    let task = sched::scheduler::with_current_node(|node| node.task.id)
        .ok_or(ProcessError::NoCurrentProcess)?;

    loop {
        let mut table = PROCESS_TABLE.lock();
        let parent_index = table
            .iter()
            .position(|process| process.pid == parent)
            .ok_or(ProcessError::NoCurrentProcess)?;
        clear_waiter(&mut table[parent_index].child_waiter, task);

        let (result, reaped) = poll_wait_selector_locked(
            &mut table,
            parent,
            selector,
            include_stopped,
            include_continued,
        )?;
        if let Some(result) = result {
            drop(table);
            if let Some(reaped) = reaped {
                reclaim_process(reaped);
            }
            return Ok(result);
        }
        debug_assert!(reaped.is_none());

        let parent_index = table
            .iter()
            .position(|process| process.pid == parent)
            .ok_or(ProcessError::NoCurrentProcess)?;
        if table[parent_index].signals.has_interrupting_delivery() {
            return Err(ProcessError::Interrupted);
        }
        if !register_waiter(&mut table[parent_index].child_waiter, task) {
            // A second thread in the same process may legitimately wait for a
            // different child. The fixed waiter slot cannot represent that
            // state, so report a concurrency limit rather than corruption.
            return Err(ProcessError::Busy);
        }
        sched::scheduler::block_current_until_releasing(None, table);
    }
}

fn poll_wait_selector_locked(
    table: &mut Vec<UserProcess>,
    parent: ProcessId,
    selector: WaitSelector,
    include_stopped: bool,
    include_continued: bool,
) -> Result<(Option<WaitResult>, Option<UserProcess>), ProcessError> {
    let parent_index = table
        .iter()
        .position(|process| process.pid == parent)
        .ok_or(ProcessError::NoCurrentProcess)?;
    let parent_group = table[parent_index].process_group;
    let mut matching_child = false;
    let mut selected = None;
    for child in table[parent_index].children.iter().copied() {
        let child_index = table
            .iter()
            .position(|record| record.pid == child)
            .ok_or(ProcessError::TableCorrupt)?;
        let record = &table[child_index];
        if !selector.matches(record.pid, record.process_group, parent_group) {
            continue;
        }
        matching_child = true;
        let status = if !record.exit_status.is_pending() {
            Some(WaitStatus::Exited(record.exit_status))
        } else {
            match record.wait_change {
                Some(WaitStatus::Stopped(signal)) if include_stopped => {
                    Some(WaitStatus::Stopped(signal))
                },
                Some(WaitStatus::Continued) if include_continued => Some(WaitStatus::Continued),
                _ => None,
            }
        };
        if let Some(status) = status {
            selected = Some((child_index, status));
            break;
        }
    }

    if !matching_child {
        return if table[parent_index].children.is_empty() {
            Err(ProcessError::NoChildren)
        } else {
            Err(ProcessError::NotChild(match selector {
                WaitSelector::Process(pid) | WaitSelector::Group(pid) => pid,
                WaitSelector::Any | WaitSelector::CurrentGroup => KERNEL_PROCESS_ID,
            }))
        };
    }
    let Some((child_index, status)) = selected else {
        return Ok((None, None));
    };
    let selected_pid = table[child_index].pid;
    if matches!(status, WaitStatus::Exited(_)) {
        table[parent_index]
            .children
            .retain(|child| *child != selected_pid);
        let reaped = table.swap_remove(child_index);
        Ok((
            Some(WaitResult {
                pid: selected_pid,
                status,
            }),
            Some(reaped),
        ))
    } else {
        table[child_index].wait_change = None;
        Ok((
            Some(WaitResult {
                pid: selected_pid,
                status,
            }),
            None,
        ))
    }
}

fn register_waiter(slot: &mut Option<TaskId>, task: TaskId) -> bool {
    match *slot {
        None => {
            *slot = Some(task);
            true
        },
        Some(task_id) if task_id == task => {
            *slot = Some(task);
            true
        },
        Some(_) => false,
    }
}

fn clear_waiter(slot: &mut Option<TaskId>, task: TaskId) {
    if *slot == Some(task) {
        *slot = None;
    }
}

fn wake_process_waiter(waiter: Option<TaskId>) {
    if let Some(waiter) = waiter {
        let _ = sched::scheduler::wake_blocked_task_from_task(waiter);
    }
}

/// Current PID, or PID 0 while running outside a userspace task.
#[must_use]
pub fn current_pid() -> ProcessId {
    try_current_pid().unwrap_or(KERNEL_PROCESS_ID)
}

/// Current PID when the scheduler task belongs to a registered process.
#[must_use]
pub fn try_current_pid() -> Option<ProcessId> {
    let task = sched::scheduler::with_current_node(|node| node.task.id)?;
    let table = PROCESS_TABLE.lock();
    table
        .iter()
        .find(|process| process.threads.iter().any(|thread| thread.task == task))
        .map(|process| process.pid)
}

/// Parent PID, or PID 0 for a kernel-spawned process and kernel context.
#[must_use]
pub fn current_ppid() -> ProcessId {
    let pid = current_pid();
    if pid.is_kernel() {
        return KERNEL_PROCESS_ID;
    }
    let table = PROCESS_TABLE.lock();
    table
        .iter()
        .find(|process| process.pid == pid)
        .and_then(|process| process.parent)
        .unwrap_or(KERNEL_PROCESS_ID)
}

/// Return the caller's process-group id.
#[must_use]
pub fn current_process_group() -> ProcessId {
    with_current_process(|process| process.process_group).unwrap_or(KERNEL_PROCESS_ID)
}

/// Return the caller's session id.
#[must_use]
pub fn current_session() -> ProcessId {
    with_current_process(|process| process.session).unwrap_or(KERNEL_PROCESS_ID)
}

#[must_use]
pub fn current_is_stopped() -> bool {
    with_current_process(|process| process.stopped).unwrap_or(false)
}

/// Place the caller or one of its children into a process group in the same
/// session. Passing PID/PGID zero is normalized by the syscall handler.
pub fn set_process_group(target: ProcessId, process_group: ProcessId) -> Result<(), ProcessError> {
    let caller = try_current_pid().ok_or(ProcessError::NoCurrentProcess)?;
    let mut table = PROCESS_TABLE.lock();
    let target_index = table
        .iter()
        .position(|process| process.pid == target)
        .ok_or(ProcessError::NoSuchProcess(target))?;
    if target != caller && table[target_index].parent != Some(caller) {
        return Err(ProcessError::PermissionDenied);
    }
    if table[target_index].session == target {
        return Err(ProcessError::PermissionDenied);
    }
    let session = table[target_index].session;
    if process_group != target
        && !table
            .iter()
            .any(|process| process.process_group == process_group && process.session == session)
    {
        return Err(ProcessError::NoSuchProcess(process_group));
    }
    table[target_index].process_group = process_group;
    Ok(())
}

/// Create a new session with the caller as both session and process-group
/// leader, matching `setsid(2)`.
pub fn create_session() -> Result<ProcessId, ProcessError> {
    let caller = try_current_pid().ok_or(ProcessError::NoCurrentProcess)?;
    let mut table = PROCESS_TABLE.lock();
    if table.iter().any(|process| process.process_group == caller) {
        return Err(ProcessError::PermissionDenied);
    }
    let process = table
        .iter_mut()
        .find(|process| process.pid == caller)
        .ok_or(ProcessError::NoCurrentProcess)?;
    process.session = caller;
    process.process_group = caller;
    Ok(caller)
}

/// Verify that a process group exists in the caller's session before a
/// terminal transfers foreground ownership to it.
pub fn can_control_process_group(process_group: ProcessId) -> bool {
    let Some(session) = with_current_process(|process| process.session) else {
        return false;
    };
    PROCESS_TABLE.lock().iter().any(|process| {
        process.process_group == process_group
            && process.session == session
            && !process.has_exited()
    })
}

/// Deliver a signal to a live process.
pub fn signal(pid: ProcessId, signal: Signal) -> Result<DeliverOutcome, ProcessError> {
    let (result, waiters, interrupt_tasks) = signal_one_inner(pid, signal, None)?;
    interrupt_tasks.interrupt_all();
    for waiter in waiters {
        wake_process_waiter(waiter);
    }
    // UI readers inspect process signal state while holding their event lock,
    // so PROCESS_TABLE must be dropped before taking that lock to notify them.
    crate::ui::notify_signal(pid);
    Ok(result)
}

/// Deliver a signal with an explicit stable `siginfo` source payload.
pub fn signal_with_info(
    pid: ProcessId,
    signal: Signal,
    info: xenith_abi::SigInfo,
) -> Result<DeliverOutcome, ProcessError> {
    let (result, waiters, interrupt_tasks) = signal_one_inner(pid, signal, Some(info))?;
    interrupt_tasks.interrupt_all();
    for waiter in waiters {
        wake_process_waiter(waiter);
    }
    crate::ui::notify_signal(pid);
    Ok(result)
}

fn signal_one_inner(
    pid: ProcessId,
    signal: Signal,
    info: Option<xenith_abi::SigInfo>,
) -> Result<(DeliverOutcome, [Option<TaskId>; 2], ProcessWaiterBatch), ProcessError> {
    let mut table = PROCESS_TABLE.lock();
    let index = table
        .iter()
        .position(|process| process.pid == pid && !process.has_exited())
        .ok_or(ProcessError::NoSuchProcess(pid))?;
    let previous_change = table[index].wait_change;
    let outcome = delivery_result(apply_signal_with_info(&mut table[index], signal, info))?;
    let parent = (table[index].wait_change != previous_change)
        .then_some(table[index].parent)
        .flatten();
    let child_waiter = table[index].child_waiter.take();
    let state_changed = table[index].wait_change != previous_change;
    let must_interrupt = state_changed
        || table[index].termination_status.is_some()
        || table[index].signals.has_interrupting_delivery();
    let mut interrupt_tasks = ProcessWaiterBatch::new();
    if must_interrupt {
        for thread in &table[index].threads {
            interrupt_tasks.push(Some(thread.task));
        }
    }
    let parent_waiter = parent.and_then(|parent| {
        table
            .iter_mut()
            .find(|record| record.pid == parent)
            .and_then(|record| record.child_waiter.take())
    });
    Ok((outcome, [child_waiter, parent_waiter], interrupt_tasks))
}

/// Deliver a signal to every live member of a process group.
///
/// Real-time delivery is best-effort across members: the returned count is
/// the number that accepted the signal. If members exist but every queue is
/// full, [`ProcessError::SignalQueueFull`] is returned.
pub fn signal_group(process_group: ProcessId, signal: Signal) -> Result<usize, ProcessError> {
    signal_group_inner(process_group, signal, None)
}

/// Group delivery variant used by `kill(2)` to preserve sender metadata.
pub fn signal_group_with_info(
    process_group: ProcessId,
    signal: Signal,
    info: xenith_abi::SigInfo,
) -> Result<usize, ProcessError> {
    signal_group_inner(process_group, signal, Some(info))
}

fn signal_group_inner(
    process_group: ProcessId,
    signal: Signal,
    info: Option<xenith_abi::SigInfo>,
) -> Result<usize, ProcessError> {
    let mut table = PROCESS_TABLE.lock();
    assert!(
        table.len() <= MAX_PROCESSES,
        "process table exceeded fixed signal-wake capacity"
    );
    let mut matched = 0usize;
    let mut delivered = 0usize;
    let mut queue_full = false;
    let mut ui_owner_to_wake = None;
    let mut fatal_error = None;
    let mut accepted_targets = ProcessIndexSet::new();
    let mut changed_children = ProcessIndexSet::new();
    let mut changed_parents = ProcessIndexSet::new();
    let mut waiters = ProcessWaiterBatch::new();
    let mut interrupt_tasks = ProcessWaiterBatch::new();

    for index in 0..table.len() {
        if table[index].process_group != process_group || table[index].has_exited() {
            continue;
        }
        matched += 1;
        let previous_change = table[index].wait_change;
        match delivery_result(apply_signal_with_info(&mut table[index], signal, info)) {
            Ok(_) => {
                delivered += 1;
                accepted_targets.insert(index);
                if table[index].wait_change != previous_change {
                    changed_children.insert(index);
                }
                if crate::ui::is_owner(table[index].pid) {
                    ui_owner_to_wake = Some(table[index].pid);
                }
            },
            Err(ProcessError::SignalQueueFull) => queue_full = true,
            Err(error) => {
                fatal_error = Some(error);
                break;
            },
        }
    }

    // Resolve changed children to their actual parents while indices remain
    // stable under the table lock. Parents outside the target group are
    // included; unrelated waiters are not.
    for child_index in 0..table.len() {
        if !changed_children.contains(child_index) {
            continue;
        }
        let Some(parent) = table[child_index].parent else {
            continue;
        };
        if let Some(parent_index) = table.iter().position(|record| record.pid == parent) {
            changed_parents.insert(parent_index);
        }
    }

    // Claim the exact waiter slots before publication is unlocked. The
    // registration-to-block protocol guarantees each claimed task is already
    // in the scheduler's blocked queue. Waking happens below, after unlock.
    for index in 0..table.len() {
        if accepted_targets.contains(index)
            && (table[index].termination_status.is_some()
                || table[index].signals.has_interrupting_delivery()
                || changed_children.contains(index))
        {
            for thread in &table[index].threads {
                interrupt_tasks.push(Some(thread.task));
            }
        }
        if group_child_waiter_relevant(
            accepted_targets.contains(index),
            changed_parents.contains(index),
        ) {
            waiters.push(table[index].child_waiter.take());
        }
    }

    let result = if let Some(error) = fatal_error {
        Err(error)
    } else if matched == 0 {
        Err(ProcessError::NoSuchProcess(process_group))
    } else if delivered == 0 && queue_full {
        Err(ProcessError::SignalQueueFull)
    } else {
        Ok(delivered)
    };
    drop(table);
    // Signal interruption is cross-lock: record a wake credit when the task
    // has not reached its event park yet, or dequeue it if already blocked.
    // This must precede ordinary waiter wakes so a shared task id does not
    // acquire a stale credit after being made ready.
    interrupt_tasks.interrupt_all();
    waiters.wake_all();
    if result.is_ok() {
        if let Some(pid) = ui_owner_to_wake {
            crate::ui::notify_signal(pid);
        }
    }
    result
}

fn delivery_result(outcome: DeliverOutcome) -> Result<DeliverOutcome, ProcessError> {
    match outcome {
        DeliverOutcome::RealtimeQueueFull { .. } => Err(ProcessError::SignalQueueFull),
        DeliverOutcome::Invalid => Err(ProcessError::InvalidArgument),
        accepted => Ok(accepted),
    }
}

fn apply_signal_with_info(
    process: &mut UserProcess,
    signal: Signal,
    info: Option<xenith_abi::SigInfo>,
) -> DeliverOutcome {
    let outcome = info.map_or_else(
        || deliver_signal(&process.signals, signal),
        |info| deliver_signal_with_info(&process.signals, signal, info),
    );
    if matches!(
        outcome,
        DeliverOutcome::RealtimeQueueFull { .. } | DeliverOutcome::Invalid
    ) {
        return outcome;
    }

    let disposition = process.signals.disposition(signal);
    let uses_default = signal.is_uncatchable() || matches!(disposition, SignalAction::Default);
    if uses_default {
        match signal.default_action() {
            DefaultAction::Stop => {
                // The interactive shell is the session leader and protects
                // itself from terminal stop signals while it supervises jobs.
                let protected_session_leader =
                    process.pid == process.session && !matches!(signal, Signal::Stop);
                if !protected_session_leader && !process.stopped {
                    process.stopped = true;
                    process.wait_change = Some(WaitStatus::Stopped(signal));
                }
            },
            DefaultAction::Continue => {
                if process.stopped {
                    process.stopped = false;
                    process.wait_change = Some(WaitStatus::Continued);
                }
            },
            DefaultAction::Terminate | DefaultAction::TerminateCoreDump => {
                if process.termination_status.is_none() {
                    process.termination_status =
                        Some(ExitStatus::Signal(signal.as_number() as i32));
                }
                process.stopped = false;
            },
            DefaultAction::Ignore => {},
        }
    }
    outcome
}

/// Park a stopped process at a syscall boundary and apply a pending default
/// termination before returning to ring 3.
pub fn enforce_current_state() {
    let Some(pid) = try_current_pid() else { return };
    loop {
        let table = PROCESS_TABLE.lock();
        let Some(index) = table.iter().position(|process| process.pid == pid) else {
            return;
        };
        if let Some(status) = table[index].termination_status {
            drop(table);
            exit_current_thread(status);
        }
        if !table[index].stopped {
            return;
        }
        drop(table);
        // Every stop/continue/termination producer records a scheduler
        // interrupt credit for every live task. The generic park consumes a
        // credit that raced before blocking or is dequeued by a later change.
        sched::scheduler::block_current_interruptible(None);
    }
}

/// Run a short, non-yielding closure with the current process record.
pub fn with_current_process<R>(f: impl FnOnce(&UserProcess) -> R) -> Option<R> {
    let pid = try_current_pid()?;
    let table = PROCESS_TABLE.lock();
    table.iter().find(|process| process.pid == pid).map(f)
}

/// Run a short, non-yielding closure with mutable access to the current
/// process record (for descriptor-table syscalls and signal disposition).
pub fn with_current_process_mut<R>(f: impl FnOnce(&mut UserProcess) -> R) -> Option<R> {
    let pid = try_current_pid()?;
    let mut table = PROCESS_TABLE.lock();
    table.iter_mut().find(|process| process.pid == pid).map(f)
}

/// Query or change the calling process's program break.
///
/// The exact requested byte address is retained while page mappings are
/// rounded outward. Growth is transactional: a collision or allocation
/// failure returns without changing either the break or any data mapping.
pub fn set_program_break(request: u64) -> Result<u64, VmError> {
    with_current_process_mut(|process| {
        if request != 0 {
            require_exclusive_address_space(process)?;
        }
        set_process_break(process, request)
    })
    .ok_or(VmError::NoCurrentProcess)?
}

/// Create one zero-filled anonymous/private mapping for the calling process.
/// ABI flag validation is performed by the syscall layer; this function owns
/// collision avoidance, physical frames, and process metadata.
pub fn map_anonymous(
    address_hint: u64,
    length: u64,
    protection: VmProtection,
) -> Result<u64, VmError> {
    with_current_process_mut(|process| {
        require_exclusive_address_space(process)?;
        let length = align_page_up(length).ok_or(VmError::InvalidRange)?;
        if length == 0 {
            return Err(VmError::InvalidRange);
        }
        if length > MAX_ANONYMOUS_MAPPING {
            return Err(VmError::OutOfMemory);
        }
        validate_dynamic_mapping_budget(process, length)?;
        let start = select_mapping_address(process, address_hint, length)?;
        let end = start + length;

        process
            .vm_regions
            .try_reserve(1)
            .map_err(|_| VmError::OutOfMemory)?;
        map_zeroed_range(process, start, end, page_flags(protection))?;
        process.vm_regions.push(VmRegion {
            start,
            end,
            protection,
            backing: VmBacking::AnonymousPrivate,
        });
        process
            .vm_regions
            .sort_unstable_by_key(|region| region.start);
        process.mmap_hint = end;
        Ok(start)
    })
    .ok_or(VmError::NoCurrentProcess)?
}

/// Map existing frames from a shared-memory object into the calling process.
///
/// The descriptor layer must enforce `MAP` rights before handing this
/// function an object reference. Writable mappings additionally require
/// descriptor `WRITE` rights. `writable_allowed` permanently records whether
/// that right was present, and the object reference stored in [`VmBacking`]
/// keeps its frames alive after the creating or received descriptor closes.
pub fn map_shared(
    address_hint: u64,
    length: u64,
    object_offset: u64,
    protection: VmProtection,
    writable_allowed: bool,
    object: SharedMemoryRef,
) -> Result<u64, VmError> {
    let pid = try_current_pid().ok_or(VmError::NoCurrentProcess)?;
    let result = {
        let mut table = PROCESS_TABLE.lock();
        let process = table
            .iter_mut()
            .find(|process| process.pid == pid)
            .ok_or(VmError::NoCurrentProcess)?;
        map_shared_for_process(
            process,
            address_hint,
            length,
            object_offset,
            protection,
            writable_allowed,
            &object,
        )
    };
    // On success the region retained a clone. On failure this may be the
    // final transient reference returned by descriptor lookup, so release it
    // only after PROCESS_TABLE is unlocked.
    drop(object);
    result
}

fn map_shared_for_process(
    process: &mut UserProcess,
    address_hint: u64,
    length: u64,
    object_offset: u64,
    protection: VmProtection,
    writable_allowed: bool,
    object: &SharedMemoryRef,
) -> Result<u64, VmError> {
    require_exclusive_address_space(process)?;
    if protection.writable && !writable_allowed {
        return Err(VmError::PermissionDenied);
    }
    let length = validate_shared_mapping_request(object.len(), object_offset, length, protection)?;
    validate_dynamic_mapping_budget(process, length)?;
    let start = select_mapping_address(process, address_hint, length)?;
    let end = start + length;

    process
        .vm_regions
        .try_reserve(1)
        .map_err(|_| VmError::OutOfMemory)?;
    map_shared_range(
        process,
        start,
        end,
        object_offset,
        object,
        page_flags(protection),
    )?;
    process.vm_regions.push(VmRegion {
        start,
        end,
        protection,
        backing: VmBacking::Shared {
            object: Arc::clone(object),
            object_offset,
            writable_allowed,
        },
    });
    process
        .vm_regions
        .sort_unstable_by_key(|region| region.start);
    process.mmap_hint = end;
    Ok(start)
}

fn validate_shared_mapping_request(
    object_length: u64,
    object_offset: u64,
    requested_length: u64,
    protection: VmProtection,
) -> Result<u64, VmError> {
    if protection.executable {
        return Err(VmError::PermissionDenied);
    }
    if object_offset & (PAGE_SIZE - 1) != 0 {
        return Err(VmError::InvalidRange);
    }
    let length = align_page_up(requested_length).ok_or(VmError::InvalidRange)?;
    if length == 0 {
        return Err(VmError::InvalidRange);
    }
    let object_end = object_offset
        .checked_add(length)
        .ok_or(VmError::InvalidRange)?;
    if object_end > object_length {
        return Err(VmError::InvalidRange);
    }
    Ok(length)
}

/// Remove a page-aligned range wholly covered by dynamic mappings. Static
/// ELF/stack/trampoline pages and the `brk` heap are not members of
/// `vm_regions`, so they remain protected by construction.
pub fn unmap_dynamic(address: u64, length: u64) -> Result<(), VmError> {
    let pid = try_current_pid().ok_or(VmError::NoCurrentProcess)?;
    let retired_regions = {
        let mut table = PROCESS_TABLE.lock();
        let process = table
            .iter_mut()
            .find(|process| process.pid == pid)
            .ok_or(VmError::NoCurrentProcess)?;
        require_exclusive_address_space(process)?;
        unmap_dynamic_for_process(process, address, length)?
    };
    // Removed shared mappings can hold the final object references. Their
    // destructors return physical frames, so never run them under the global
    // process-table lock.
    drop(retired_regions);
    Ok(())
}

/// Compatibility name retained for in-kernel callers predating shared mmap.
pub fn unmap_anonymous(address: u64, length: u64) -> Result<(), VmError> {
    unmap_dynamic(address, length)
}

/// Change permissions on a page-aligned range wholly owned by dynamic mmap
/// regions. Static ELF, stack, signal-trampoline, and brk mappings are not
/// eligible. Region metadata is prepared before any PTE changes, and W^X is
/// enforced by the syscall layer.
pub fn protect_dynamic(address: u64, length: u64, protection: VmProtection) -> Result<(), VmError> {
    let pid = try_current_pid().ok_or(VmError::NoCurrentProcess)?;
    let retired_regions = {
        let mut table = PROCESS_TABLE.lock();
        let process = table
            .iter_mut()
            .find(|process| process.pid == pid)
            .ok_or(VmError::NoCurrentProcess)?;
        require_exclusive_address_space(process)?;
        protect_dynamic_for_process(process, address, length, protection)?
    };
    // Metadata for shared regions contains Arc references. Keep every
    // possible final object drop outside the process-table critical section.
    drop(retired_regions);
    Ok(())
}

fn protect_dynamic_for_process(
    process: &mut UserProcess,
    address: u64,
    length: u64,
    protection: VmProtection,
) -> Result<Vec<VmRegion>, VmError> {
    if address & (PAGE_SIZE - 1) != 0 {
        return Err(VmError::InvalidRange);
    }
    let length = align_page_up(length).ok_or(VmError::InvalidRange)?;
    if length == 0 {
        return Err(VmError::InvalidRange);
    }
    let end = address.checked_add(length).ok_or(VmError::InvalidRange)?;
    if end > DYNAMIC_LIMIT || !range_covered_by_regions(&process.vm_regions, address, end) {
        return Err(VmError::NotOwned);
    }
    let disallowed_shared_protection = process.vm_regions.iter().any(|region| {
        if region.start >= end || address >= region.end {
            return false;
        }
        match &region.backing {
            VmBacking::AnonymousPrivate => false,
            VmBacking::Shared {
                writable_allowed, ..
            } => !shared_protection_allowed(*writable_allowed, protection),
        }
    });
    if disallowed_shared_protection {
        // Shared-memory mappings are data capabilities: they are never
        // executable, and write access can never exceed the rights captured
        // from the descriptor which created the mapping.
        return Err(VmError::PermissionDenied);
    }

    let updated = build_protected_regions(&process.vm_regions, address, end, protection)?;
    validate_dynamic_pages(process, address, end)?;

    let requested_flags = page_flags(protection);
    let mut current = address;
    while current < end {
        let page = Page::containing_addr(VirtAddr::new_truncate(current));
        if let Err(error) = process.address_space.protect_user(page, requested_flags) {
            // Every page was validated while PROCESS_TABLE excluded mapping
            // changes, so this is corruption rather than an ordinary race.
            // Restore the already-updated prefix from authoritative old
            // region metadata before reporting the failure.
            let mut rollback = address;
            while rollback < current {
                let old = process
                    .vm_regions
                    .iter()
                    .find(|region| region.start <= rollback && rollback < region.end)
                    .map(|region| region.protection)
                    .ok_or(VmError::TableCorrupt)?;
                let rollback_page = Page::containing_addr(VirtAddr::new_truncate(rollback));
                process
                    .address_space
                    .protect_user(rollback_page, page_flags(old))
                    .map_err(|_| VmError::TableCorrupt)?;
                rollback += PAGE_SIZE;
            }
            return Err(vm_map_error(error));
        }
        current += PAGE_SIZE;
    }

    Ok(core::mem::replace(&mut process.vm_regions, updated))
}

#[inline]
const fn shared_protection_allowed(writable_allowed: bool, protection: VmProtection) -> bool {
    !protection.executable && (!protection.writable || writable_allowed)
}

#[inline]
fn require_exclusive_address_space(process: &UserProcess) -> Result<(), VmError> {
    if address_space_mutation_allowed(process.threads.len()) {
        Ok(())
    } else {
        Err(VmError::Busy)
    }
}

#[inline]
const fn address_space_mutation_allowed(live_threads: usize) -> bool {
    live_threads == 1
}

fn build_protected_regions(
    regions: &[VmRegion],
    address: u64,
    end: u64,
    protection: VmProtection,
) -> Result<Vec<VmRegion>, VmError> {
    let mut updated = Vec::new();
    updated
        .try_reserve(regions.len().saturating_add(2))
        .map_err(|_| VmError::OutOfMemory)?;
    for region in regions {
        if region.end <= address || region.start >= end {
            updated.push(region.clone());
            continue;
        }
        if region.start < address {
            let mut left = region.clone();
            left.end = address;
            updated.push(left);
        }

        let middle_start = region.start.max(address);
        let middle_end = region.end.min(end);
        let mut middle = region.clone();
        if middle_start != region.start {
            middle.backing = right_split_backing(region, middle_start)?;
        }
        middle.start = middle_start;
        middle.end = middle_end;
        middle.protection = protection;
        updated.push(middle);

        if region.end > end {
            let mut right = region.clone();
            right.backing = right_split_backing(region, end)?;
            right.start = end;
            updated.push(right);
        }
    }
    Ok(updated)
}

fn unmap_dynamic_for_process(
    process: &mut UserProcess,
    address: u64,
    length: u64,
) -> Result<Vec<VmRegion>, VmError> {
    if address & (PAGE_SIZE - 1) != 0 {
        return Err(VmError::InvalidRange);
    }
    let length = align_page_up(length).ok_or(VmError::InvalidRange)?;
    if length == 0 {
        return Err(VmError::InvalidRange);
    }
    let end = address.checked_add(length).ok_or(VmError::InvalidRange)?;
    if end > DYNAMIC_LIMIT || !range_covered_by_regions(&process.vm_regions, address, end) {
        return Err(VmError::NotOwned);
    }

    // Build the post-unmap region list before changing page tables. A split
    // can add one entry, and allocation failure must leave the mapping intact.
    let mut updated = Vec::new();
    updated
        .try_reserve(process.vm_regions.len().saturating_add(1))
        .map_err(|_| VmError::OutOfMemory)?;
    for region in &process.vm_regions {
        if region.end <= address || region.start >= end {
            updated.push(region.clone());
            continue;
        }
        if region.start < address {
            let mut left = region.clone();
            left.end = address;
            updated.push(left);
        }
        if region.end > end {
            let mut right = region.clone();
            right.backing = right_split_backing(region, end)?;
            right.start = end;
            updated.push(right);
        }
    }

    validate_dynamic_pages(process, address, end)?;
    unmap_dynamic_range(process, address, end)?;
    let retired = core::mem::replace(&mut process.vm_regions, updated);
    process.mmap_hint = process.mmap_hint.min(address.max(MMAP_BASE));
    Ok(retired)
}

fn set_process_break(process: &mut UserProcess, request: u64) -> Result<u64, VmError> {
    if request == 0 {
        return Ok(process.brk_current);
    }
    let maximum = process
        .brk_base
        .checked_add(MAX_BRK_BYTES)
        .unwrap_or(DYNAMIC_LIMIT)
        .min(DYNAMIC_LIMIT)
        .min(USER_MAX);
    if request < process.brk_base {
        return Err(VmError::InvalidRange);
    }
    if request > maximum {
        return Err(VmError::OutOfMemory);
    }

    let old_end = align_page_up(process.brk_current).ok_or(VmError::InvalidRange)?;
    let new_end = align_page_up(request).ok_or(VmError::InvalidRange)?;
    if new_end > old_end {
        if !range_is_free(process, old_end, new_end) {
            return Err(VmError::AddressInUse);
        }
        map_zeroed_range(
            process,
            old_end,
            new_end,
            PageTableFlags::USER | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
        )?;
    } else if new_end < old_end {
        validate_owned_pages(process, new_end, old_end)?;
        unmap_owned_range(process, new_end, old_end)?;
    }
    process.brk_current = request;
    Ok(request)
}

fn validate_dynamic_mapping_budget(process: &UserProcess, length: u64) -> Result<(), VmError> {
    let total = process
        .vm_regions
        .iter()
        .try_fold(0u64, |total, region| {
            total.checked_add(region.end - region.start)
        })
        .ok_or(VmError::OutOfMemory)?;
    let new_total = total.checked_add(length).ok_or(VmError::OutOfMemory)?;
    if new_total > MAX_DYNAMIC_MAPPING_TOTAL {
        return Err(VmError::OutOfMemory);
    }
    Ok(())
}

fn select_mapping_address(
    process: &UserProcess,
    address_hint: u64,
    length: u64,
) -> Result<u64, VmError> {
    let hinted = (address_hint != 0)
        .then_some(address_hint & !(PAGE_SIZE - 1))
        .filter(|start| valid_dynamic_range(*start, length))
        .filter(|start| range_is_free(process, *start, *start + length));
    if let Some(start) = hinted {
        return Ok(start);
    }

    let search = process.mmap_hint.max(MMAP_BASE);
    find_free_range(process, search, length)
        .or_else(|| {
            (search > MMAP_BASE)
                .then(|| find_free_range(process, MMAP_BASE, length))
                .flatten()
        })
        .ok_or(VmError::OutOfMemory)
}

fn map_shared_range(
    process: &mut UserProcess,
    start: u64,
    end: u64,
    object_offset: u64,
    object: &SharedMemoryRef,
    flags: PageTableFlags,
) -> Result<(), VmError> {
    let mut address = start;
    while address < end {
        let Some(offset) = object_offset.checked_add(address - start) else {
            rollback_shared_pages(process, start, address);
            return Err(VmError::InvalidRange);
        };
        let frame = match object.frame_at_offset(offset) {
            Ok(frame) => frame,
            Err(_) => {
                rollback_shared_pages(process, start, address);
                return Err(VmError::InvalidRange);
            },
        };
        let page = Page::containing_addr(VirtAddr::new_truncate(address));
        if let Err(error) = process.address_space.map_user(page, frame, flags) {
            rollback_shared_pages(process, start, address);
            return Err(vm_map_error(error));
        }
        address += PAGE_SIZE;
    }
    Ok(())
}

fn rollback_shared_pages(process: &mut UserProcess, start: u64, end: u64) {
    let mut address = start;
    while address < end {
        let page = Page::containing_addr(VirtAddr::new_truncate(address));
        // The shared-memory object, not the mapping, owns this returned frame.
        let _ = process.address_space.unmap(page);
        address += PAGE_SIZE;
    }
}

fn map_zeroed_range(
    process: &mut UserProcess,
    start: u64,
    end: u64,
    flags: PageTableFlags,
) -> Result<(), VmError> {
    let page_count =
        usize::try_from((end - start) / PAGE_SIZE).map_err(|_| VmError::OutOfMemory)?;
    process
        .pages
        .try_reserve(page_count)
        .map_err(|_| VmError::OutOfMemory)?;
    let original_len = process.pages.len();
    let mut address = start;
    while address < end {
        let Some(frame) = physical::allocate_frame() else {
            rollback_new_pages(process, original_len);
            return Err(VmError::OutOfMemory);
        };
        zero_user_frame(frame);
        let page = Page::containing_addr(VirtAddr::new_truncate(address));
        if let Err(error) = process.address_space.map_user(page, frame, flags) {
            let _ = physical::deallocate(frame);
            rollback_new_pages(process, original_len);
            return Err(vm_map_error(error));
        }
        process.pages.push(UserPage { page, frame });
        address += PAGE_SIZE;
    }
    Ok(())
}

fn rollback_new_pages(process: &mut UserProcess, original_len: usize) {
    while process.pages.len() > original_len {
        let mapping = process.pages.pop().expect("new user page is present");
        if let Ok(frame) = process.address_space.unmap(mapping.page) {
            free_user_frame(frame);
        }
    }
}

fn validate_owned_pages(process: &UserProcess, start: u64, end: u64) -> Result<(), VmError> {
    let mut address = start;
    while address < end {
        let page = Page::containing_addr(VirtAddr::new_truncate(address));
        if !process.pages.iter().any(|mapping| mapping.page == page)
            || process.address_space.translate(page).is_none()
        {
            return Err(VmError::TableCorrupt);
        }
        address += PAGE_SIZE;
    }
    Ok(())
}

fn validate_dynamic_pages(process: &UserProcess, start: u64, end: u64) -> Result<(), VmError> {
    let mut address = start;
    let mut region_index = process
        .vm_regions
        .iter()
        .position(|region| region.end > start)
        .ok_or(VmError::TableCorrupt)?;
    while address < end {
        while process.vm_regions[region_index].end <= address {
            region_index = region_index
                .checked_add(1)
                .filter(|index| *index < process.vm_regions.len())
                .ok_or(VmError::TableCorrupt)?;
        }
        let region = &process.vm_regions[region_index];
        if address < region.start {
            return Err(VmError::TableCorrupt);
        }
        let page = Page::containing_addr(VirtAddr::new_truncate(address));
        let (mapped_frame, _) = process
            .address_space
            .translate(page)
            .ok_or(VmError::TableCorrupt)?;
        let expected_shared_frame = match &region.backing {
            VmBacking::AnonymousPrivate => {
                // A post-fork COW fault can replace the PTE frame without
                // rewriting the historical UserPage record. Page ownership,
                // not stale frame identity, is the private-mapping invariant.
                if !process.pages.iter().any(|mapping| mapping.page == page) {
                    return Err(VmError::TableCorrupt);
                }
                None
            },
            VmBacking::Shared {
                object,
                object_offset,
                ..
            } => Some(
                object
                    .frame_at_offset(
                        object_offset
                            .checked_add(address - region.start)
                            .ok_or(VmError::TableCorrupt)?,
                    )
                    .map_err(|_| VmError::TableCorrupt)?,
            ),
        };
        if expected_shared_frame.is_some_and(|expected| mapped_frame != expected) {
            return Err(VmError::TableCorrupt);
        }
        address += PAGE_SIZE;
    }
    Ok(())
}

fn unmap_owned_range(process: &mut UserProcess, start: u64, end: u64) -> Result<(), VmError> {
    let mut address = start;
    while address < end {
        let page = Page::containing_addr(VirtAddr::new_truncate(address));
        let index = process
            .pages
            .iter()
            .position(|mapping| mapping.page == page)
            .ok_or(VmError::TableCorrupt)?;
        let frame = process
            .address_space
            .unmap(page)
            .map_err(|_| VmError::TableCorrupt)?;
        process.pages.swap_remove(index);
        free_user_frame(frame);
        address += PAGE_SIZE;
    }
    Ok(())
}

fn unmap_dynamic_range(process: &mut UserProcess, start: u64, end: u64) -> Result<(), VmError> {
    let mut address = start;
    let mut region_index = process
        .vm_regions
        .iter()
        .position(|region| region.end > start)
        .ok_or(VmError::TableCorrupt)?;
    while address < end {
        while process.vm_regions[region_index].end <= address {
            region_index = region_index
                .checked_add(1)
                .filter(|index| *index < process.vm_regions.len())
                .ok_or(VmError::TableCorrupt)?;
        }
        let region = &process.vm_regions[region_index];
        if address < region.start {
            return Err(VmError::TableCorrupt);
        }
        let page = Page::containing_addr(VirtAddr::new_truncate(address));
        let private_index = match &region.backing {
            VmBacking::AnonymousPrivate => Some(
                process
                    .pages
                    .iter()
                    .position(|mapping| mapping.page == page)
                    .ok_or(VmError::TableCorrupt)?,
            ),
            VmBacking::Shared { .. } => None,
        };
        let frame = process
            .address_space
            .unmap(page)
            .map_err(|_| VmError::TableCorrupt)?;
        if let Some(index) = private_index {
            process.pages.swap_remove(index);
            free_user_frame(frame);
        }
        address += PAGE_SIZE;
    }
    Ok(())
}

fn right_split_backing(region: &VmRegion, new_start: u64) -> Result<VmBacking, VmError> {
    match &region.backing {
        VmBacking::AnonymousPrivate => Ok(VmBacking::AnonymousPrivate),
        VmBacking::Shared {
            object,
            object_offset,
            writable_allowed,
        } => Ok(VmBacking::Shared {
            object: Arc::clone(object),
            object_offset: object_offset
                .checked_add(
                    new_start
                        .checked_sub(region.start)
                        .ok_or(VmError::TableCorrupt)?,
                )
                .ok_or(VmError::TableCorrupt)?,
            writable_allowed: *writable_allowed,
        }),
    }
}

fn free_user_frame(frame: xenith_types::PhysFrame) {
    if address_space::release_user_frame(frame) {
        if let Err(error) = physical::deallocate(frame) {
            ::log::error!("user.process: failed to free {:?}: {}", frame, error);
        }
    }
}

fn zero_user_frame(frame: xenith_types::PhysFrame) {
    let address = address_space::phys_to_virt(frame.start_address()).as_u64();
    // SAFETY: the physical allocator returned an exclusive writable frame;
    // its HHDM alias covers exactly PAGE_SIZE bytes.
    unsafe { ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE as usize) };
}

fn page_flags(protection: VmProtection) -> PageTableFlags {
    let mut flags = PageTableFlags::USER;
    if protection.writable {
        flags |= PageTableFlags::WRITABLE;
    }
    if !protection.executable {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    flags
}

fn range_is_free(process: &UserProcess, start: u64, end: u64) -> bool {
    process.pages.iter().all(|mapping| {
        let mapped_start = mapping.page.start_address().as_u64();
        let mapped_end = mapped_start + PAGE_SIZE;
        end <= mapped_start || start >= mapped_end
    }) && process
        .vm_regions
        .iter()
        .all(|region| end <= region.start || start >= region.end)
}

fn find_free_range(process: &UserProcess, start: u64, length: u64) -> Option<u64> {
    let mut candidate = align_page_up(start.max(elf::USER_IMAGE_MIN))?;
    loop {
        if !valid_dynamic_range(candidate, length) {
            return None;
        }
        let end = candidate.checked_add(length)?;
        let next_page = process
            .pages
            .iter()
            .filter_map(|mapping| {
                let mapped_start = mapping.page.start_address().as_u64();
                let mapped_end = mapped_start.checked_add(PAGE_SIZE)?;
                (candidate < mapped_end && mapped_start < end).then_some(mapped_end)
            })
            .max();
        let next_region = process
            .vm_regions
            .iter()
            .filter(|region| candidate < region.end && region.start < end)
            .map(|region| region.end)
            .max();
        let next = match (next_page, next_region) {
            (Some(page), Some(region)) => Some(page.max(region)),
            (Some(page), None) => Some(page),
            (None, Some(region)) => Some(region),
            (None, None) => None,
        };
        match next {
            Some(next) => candidate = align_page_up(next)?,
            None => return Some(candidate),
        }
    }
}

fn valid_dynamic_range(start: u64, length: u64) -> bool {
    start >= elf::USER_IMAGE_MIN
        && start & (PAGE_SIZE - 1) == 0
        && length != 0
        && start
            .checked_add(length)
            .is_some_and(|end| end <= DYNAMIC_LIMIT && end - 1 <= USER_MAX)
}

fn align_page_up(value: u64) -> Option<u64> {
    value
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
}

fn range_covered_by_regions(regions: &[VmRegion], start: u64, end: u64) -> bool {
    let mut cursor = start;
    for region in regions {
        if region.end <= cursor {
            continue;
        }
        if region.start > cursor {
            return false;
        }
        cursor = cursor.max(region.end).min(end);
        if cursor == end {
            return true;
        }
    }
    false
}

fn vm_map_error(error: MapError) -> VmError {
    match error {
        MapError::OutOfMemory => VmError::OutOfMemory,
        MapError::AlreadyMapped => VmError::AddressInUse,
        MapError::OutOfRange => VmError::InvalidRange,
        MapError::CorruptPageTable | MapError::HugePageUnsupported => VmError::TableCorrupt,
    }
}

/// User virtual-memory operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmError {
    InvalidRange,
    OutOfMemory,
    AddressInUse,
    PermissionDenied,
    NotOwned,
    NoCurrentProcess,
    Busy,
    TableCorrupt,
}

#[must_use]
pub fn process_count() -> usize {
    PROCESS_TABLE.lock().len()
}

/// Scheduler entry used for every newly spawned user process.
unsafe extern "C" fn launch_process(raw_pid: u64) -> ! {
    let pid = ProcessId(raw_pid);
    let launch = {
        let table = PROCESS_TABLE.lock();
        table
            .iter()
            .find(|process| process.pid == pid)
            .map(|process| {
                (
                    process.entry.as_u64(),
                    process.user_rsp.as_u64(),
                    process.startup.as_u64(),
                    process.address_space,
                    process.fork_resume,
                )
            })
    };
    let Some((entry, user_rsp, startup, space, fork_resume)) = launch else {
        sched::scheduler::exit(ExitStatus::Code(127));
    };

    let Some(node) = sched::scheduler::current_node() else {
        sched::scheduler::exit(ExitStatus::Code(127));
    };
    // SAFETY: `node` is the scheduler's current task on this CPU.  No other
    // CPU can mutate it, and the address space is the process record selected
    // by the PID passed to this task's private launch trampoline.
    let kernel_rsp = unsafe {
        let task = &mut *(*node.as_ptr()).task;
        task.address_space = Some(space);
        task.kernel_stack.top().as_u64()
    };

    // SAFETY: ELF loading established executable `entry`, writable aligned
    // `user_rsp`, a kernel-sharing CR3, and this task's valid kernel stack.
    if let Some(context) = fork_resume {
        // SAFETY: AddressSpace::fork cloned the complete user mapping set and
        // the saved context came from the parent's validated syscall frame.
        unsafe { ring3::resume_user_context(&context, space.cr3(), kernel_rsp) }
    }
    // SAFETY: ordinary spawn/exec launch invariants established by ELF load.
    unsafe { ring3::jump_to_user(entry, user_rsp, startup, space.cr3(), kernel_rsp) }
}

/// First-dispatch trampoline for a task created by `thread_create`.
unsafe extern "C" fn launch_thread(raw_pid: u64) -> ! {
    let pid = ProcessId(raw_pid);
    let Some(task) = sched::scheduler::with_current_node(|node| node.task.id) else {
        sched::scheduler::exit(ExitStatus::Code(127));
    };
    let launch = {
        let table = PROCESS_TABLE.lock();
        table
            .iter()
            .find(|process| process.pid == pid)
            .and_then(|process| {
                process
                    .threads
                    .iter()
                    .find(|thread| thread.task == task)
                    .map(|thread| {
                        (
                            thread.entry,
                            thread.stack_end - 8,
                            thread.argument,
                            process.address_space,
                        )
                    })
            })
    };
    let Some((entry, user_rsp, argument, space)) = launch else {
        sched::scheduler::exit(ExitStatus::Code(127));
    };
    let Some(node) = sched::scheduler::current_node() else {
        sched::scheduler::exit(ExitStatus::Code(127));
    };
    // SAFETY: this is the current scheduler-owned task. Its staged
    // publication attached the same shared address-space root before commit.
    let kernel_rsp = unsafe { (*node.as_ptr()).task.kernel_stack.top().as_u64() };
    // SAFETY: publication validated an executable entry and a writable NX
    // stack. Subtracting eight gives a SysV function-entry stack alignment;
    // the supported libuser trampoline diverges through `thread_exit`.
    unsafe { ring3::jump_to_user(entry, user_rsp, argument, space.cr3(), kernel_rsp) }
}

fn install_process(process: &mut Option<UserProcess>) -> Result<(), ProcessError> {
    let record = process.as_ref().ok_or(ProcessError::TableCorrupt)?;
    let pid = record.pid;
    let parent = record.parent;
    let mut table = PROCESS_TABLE.lock();
    if table.len() >= MAX_PROCESSES {
        return Err(ProcessError::OutOfMemory);
    }
    if table.try_reserve(1).is_err() {
        return Err(ProcessError::OutOfMemory);
    }
    if let Some(parent_pid) = parent {
        let Some(parent_record) = table.iter_mut().find(|record| record.pid == parent_pid) else {
            return Err(ProcessError::NoCurrentProcess);
        };
        if parent_record.children.try_reserve(1).is_err() {
            return Err(ProcessError::OutOfMemory);
        }
        parent_record.children.push(pid);
    }
    table.push(process.take().ok_or(ProcessError::TableCorrupt)?);
    Ok(())
}

fn remove_process(pid: ProcessId) -> Option<UserProcess> {
    let mut table = PROCESS_TABLE.lock();
    let index = table.iter().position(|process| process.pid == pid)?;
    let parent = table[index].parent;
    if let Some(parent) = parent {
        if let Some(parent_record) = table.iter_mut().find(|record| record.pid == parent) {
            parent_record.children.retain(|child| *child != pid);
        }
    }
    Some(table.swap_remove(index))
}

fn remove_parentless_exited_process(pid: ProcessId) -> Option<UserProcess> {
    let mut table = PROCESS_TABLE.lock();
    let index = table.iter().position(|process| process.pid == pid)?;
    let process = &table[index];
    if process.parent.is_some() || process.exit_status.is_pending() {
        return None;
    }
    Some(table.swap_remove(index))
}

fn reclaim_process(process: UserProcess) {
    // A process must be inactive before its PML4 hierarchy is freed.  If a
    // broken scheduler attempts to reap the active address space, leak it
    // safely and report the invariant violation rather than use-after-free.
    // SAFETY: ring-0 CR3 read.
    let active = unsafe { read_cr3() } & 0x000F_FFFF_FFFF_F000;
    if active == process.address_space.cr3() {
        ::log::error!(
            "user.process: refusing to reclaim active address space for {}",
            process.pid
        );
        // Private page records are inert values, but shared-region Arcs own
        // their backing frames. Dropping this record while its page table is
        // still active could free frames the CPU can access. Leak the entire
        // corrupt record deliberately, matching the existing safe-leak policy.
        core::mem::forget(process);
        return;
    }
    // SAFETY: the process has exited, was removed from the table, and its
    // scheduler task has detached this address space before exit publication.
    // An automatically reaped task may still be finishing its kernel-only
    // exit path, but it can no longer access this inactive userspace root.
    unsafe { elf::destroy(process.address_space, &process.pages) };
}

fn read_executable(path: &str) -> Result<Vec<u8>, ProcessError> {
    let node = vfs::resolve(&Path::new(path)).map_err(ProcessError::Filesystem)?;
    let metadata = node.metadata();
    if metadata.kind != FileType::Regular {
        return Err(ProcessError::NotExecutable);
    }
    let size = usize::try_from(metadata.size).map_err(|_| ProcessError::ImageTooLarge)?;
    if size == 0 {
        return Err(ProcessError::NotExecutable);
    }
    let mut image = Vec::new();
    image
        .try_reserve_exact(size)
        .map_err(|_| ProcessError::OutOfMemory)?;
    image.resize(size, 0);
    let mut offset = 0usize;
    while offset < size {
        let count = node
            .read_at(offset as u64, &mut image[offset..])
            .map_err(ProcessError::Filesystem)?;
        if count == 0 || count > size - offset {
            return Err(ProcessError::ShortRead);
        }
        offset += count;
    }
    Ok(image)
}

fn validate_arguments(argv: &[&str]) -> Result<(), ProcessError> {
    if argv.len() > MAX_ARGUMENTS {
        return Err(ProcessError::TooManyArguments);
    }
    let mut bytes = 0usize;
    for argument in argv {
        if argument.as_bytes().contains(&0) {
            return Err(ProcessError::InvalidArgument);
        }
        bytes = bytes
            .checked_add(argument.len() + 1)
            .ok_or(ProcessError::ArgumentListTooLong)?;
        if bytes > MAX_ARGUMENT_BYTES {
            return Err(ProcessError::ArgumentListTooLong);
        }
    }
    Ok(())
}

fn build_initial_stack(
    space: &AddressSpace,
    top: VirtAddr,
    path: &str,
    argv: &[&str],
) -> Result<(VirtAddr, VirtAddr), ProcessError> {
    let argument_count = if argv.is_empty() { 1 } else { argv.len() };
    let mut pointers = Vec::new();
    pointers
        .try_reserve_exact(argument_count)
        .map_err(|_| ProcessError::OutOfMemory)?;
    pointers.resize(argument_count, 0u64);

    let bottom = elf::USER_STACK_TOP - elf::USER_STACK_SIZE;
    let mut cursor = top.as_u64();
    for index in (0..argument_count).rev() {
        let argument = if argv.is_empty() { path } else { argv[index] };
        let needed = argument
            .len()
            .checked_add(1)
            .ok_or(ProcessError::ArgumentListTooLong)? as u64;
        cursor = cursor
            .checked_sub(needed)
            .ok_or(ProcessError::ArgumentListTooLong)?;
        ensure_stack(cursor, bottom)?;
        elf::write_user(space, cursor, argument.as_bytes()).map_err(ProcessError::Elf)?;
        elf::write_user(space, cursor + argument.len() as u64, &[0]).map_err(ProcessError::Elf)?;
        pointers[index] = cursor;
    }

    cursor &= !0xFu64;
    // envp contains only its terminating null pointer for the initial spawn.
    cursor = cursor
        .checked_sub(8)
        .ok_or(ProcessError::ArgumentListTooLong)?;
    ensure_stack(cursor, bottom)?;
    write_u64(space, cursor, 0)?;
    let envp = cursor;

    let argv_bytes = (argument_count + 1)
        .checked_mul(8)
        .ok_or(ProcessError::ArgumentListTooLong)? as u64;
    cursor = cursor
        .checked_sub(argv_bytes)
        .ok_or(ProcessError::ArgumentListTooLong)?;
    ensure_stack(cursor, bottom)?;
    let argv_pointer = cursor;
    for (index, pointer) in pointers.iter().copied().enumerate() {
        write_u64(space, argv_pointer + index as u64 * 8, pointer)?;
    }
    write_u64(space, argv_pointer + argument_count as u64 * 8, 0)?;

    // libuser::args::Startup: argc, argv, envc, envp (four 64-bit fields).
    cursor &= !0xFu64;
    cursor = cursor
        .checked_sub(32)
        .ok_or(ProcessError::ArgumentListTooLong)?;
    ensure_stack(cursor, bottom)?;
    write_u64(space, cursor, argument_count as u64)?;
    write_u64(space, cursor + 8, argv_pointer)?;
    write_u64(space, cursor + 16, 0)?;
    write_u64(space, cursor + 24, envp)?;

    let stack = VirtAddr::new(cursor).ok_or(ProcessError::ArgumentListTooLong)?;
    Ok((stack, stack))
}

fn write_u64(space: &AddressSpace, address: u64, value: u64) -> Result<(), ProcessError> {
    elf::write_user(space, address, &value.to_le_bytes()).map_err(ProcessError::Elf)
}

fn ensure_stack(address: u64, bottom: u64) -> Result<(), ProcessError> {
    if address < bottom + 16 {
        Err(ProcessError::ArgumentListTooLong)
    } else {
        Ok(())
    }
}

fn make_task_name(path: &str) -> Result<String, ProcessError> {
    let basename = path
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("user");
    let mut name = String::new();
    name.try_reserve_exact(basename.len())
        .map_err(|_| ProcessError::OutOfMemory)?;
    name.push_str(basename);
    Ok(name)
}

fn make_thread_task_name() -> Result<String, ProcessError> {
    const NAME: &str = "user-thread";
    let mut name = String::new();
    name.try_reserve_exact(NAME.len())
        .map_err(|_| ProcessError::OutOfMemory)?;
    name.push_str(NAME);
    Ok(name)
}

fn allocate_pid() -> Result<ProcessId, ProcessError> {
    loop {
        let current = NEXT_PID.load(Ordering::Relaxed);
        if current == 0 || current == u64::MAX {
            return Err(ProcessError::PidExhausted);
        }
        if NEXT_PID
            .compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(ProcessId(current));
        }
    }
}

/// Process creation, lookup, or waiting failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    InvalidPath,
    InvalidArgument,
    TooManyArguments,
    ArgumentListTooLong,
    ImageTooLarge,
    ShortRead,
    NotExecutable,
    OutOfMemory,
    PidExhausted,
    NoCurrentProcess,
    NoChildren,
    NotChild(ProcessId),
    NoSuchProcess(ProcessId),
    NoSuchThread,
    PermissionDenied,
    Busy,
    TlsUnsupported,
    Interrupted,
    SignalQueueFull,
    SharedMappingsUnsupported,
    TableCorrupt,
    Filesystem(FsError),
    AddressSpace(MapError),
    Elf(ElfError),
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath => f.write_str("invalid executable path"),
            Self::InvalidArgument => f.write_str("invalid process argument"),
            Self::TooManyArguments => f.write_str("too many process arguments"),
            Self::ArgumentListTooLong => f.write_str("process argument list is too long"),
            Self::ImageTooLarge => f.write_str("executable image is too large"),
            Self::ShortRead => f.write_str("short executable read"),
            Self::NotExecutable => f.write_str("path is not a regular executable file"),
            Self::OutOfMemory => f.write_str("out of memory while creating process"),
            Self::PidExhausted => f.write_str("process identifier space exhausted"),
            Self::NoCurrentProcess => f.write_str("current task is not a user process"),
            Self::NoChildren => f.write_str("process has no children"),
            Self::NotChild(pid) => write!(f, "{pid} is not a child of the current process"),
            Self::NoSuchProcess(pid) => write!(f, "no such process {pid}"),
            Self::NoSuchThread => f.write_str("no such thread in the current process"),
            Self::PermissionDenied => f.write_str("process operation is not permitted"),
            Self::Busy => f.write_str("process state is busy"),
            Self::TlsUnsupported => f.write_str("userspace TLS base is not supported yet"),
            Self::Interrupted => f.write_str("process wait interrupted by a signal"),
            Self::SignalQueueFull => f.write_str("real-time signal queue is full"),
            Self::SharedMappingsUnsupported => {
                f.write_str("fork with active shared mappings is not supported")
            },
            Self::TableCorrupt => f.write_str("process table invariant violated"),
            Self::Filesystem(error) => write!(f, "filesystem error: {error}"),
            Self::AddressSpace(error) => write!(f, "address-space error: {error:?}"),
            Self::Elf(error) => write!(f, "ELF load error: {error}"),
        }
    }
}

#[cfg(test)]
mod thread_tests {
    use super::*;

    fn valid_request() -> xenith_abi::ThreadCreate {
        xenith_abi::ThreadCreate {
            version: xenith_abi::THREAD_ABI_VERSION,
            flags: 0,
            entry: 0x0040_1000,
            stack_base: 0x0000_0001_2000_0000,
            stack_size: xenith_abi::THREAD_STACK_MIN,
            argument: 0x1234,
            tls_base: 0,
            reserved: [0; 2],
        }
    }

    #[test]
    fn thread_request_shape_is_strict_and_tls_fails_closed() {
        assert_eq!(validate_thread_request(&valid_request()), Ok(()));

        let mut request = valid_request();
        request.version += 1;
        assert_eq!(
            validate_thread_request(&request),
            Err(ProcessError::InvalidArgument)
        );

        let mut request = valid_request();
        request.flags = 1;
        assert_eq!(
            validate_thread_request(&request),
            Err(ProcessError::InvalidArgument)
        );

        let mut request = valid_request();
        request.reserved[1] = 1;
        assert_eq!(
            validate_thread_request(&request),
            Err(ProcessError::InvalidArgument)
        );

        let mut request = valid_request();
        request.tls_base = 0x7000;
        assert_eq!(
            validate_thread_request(&request),
            Err(ProcessError::TlsUnsupported)
        );
    }

    #[test]
    fn thread_stack_bounds_and_alignment_are_exact() {
        let mut request = valid_request();
        request.stack_base += 1;
        assert_eq!(
            validate_thread_request(&request),
            Err(ProcessError::InvalidArgument)
        );

        let mut request = valid_request();
        request.stack_size = xenith_abi::THREAD_STACK_MIN - PAGE_SIZE;
        assert_eq!(
            validate_thread_request(&request),
            Err(ProcessError::InvalidArgument)
        );

        let mut request = valid_request();
        request.stack_size = xenith_abi::THREAD_STACK_MAX + PAGE_SIZE;
        assert_eq!(
            validate_thread_request(&request),
            Err(ProcessError::InvalidArgument)
        );

        let mut request = valid_request();
        request.stack_base = USER_MAX & !(PAGE_SIZE - 1);
        assert_eq!(
            validate_thread_request(&request),
            Err(ProcessError::InvalidArgument)
        );
    }

    #[test]
    fn live_stack_ranges_may_touch_but_never_overlap() {
        assert!(!stack_ranges_overlap(0x1000, 0x2000, 0x2000, 0x3000));
        assert!(stack_ranges_overlap(0x1000, 0x3000, 0x2000, 0x4000));
        assert!(stack_ranges_overlap(0x2000, 0x4000, 0x1000, 0x3000));
    }

    #[test]
    fn unsafe_process_wide_operations_require_one_live_thread() {
        assert!(process_image_change_allowed(1, false));
        assert!(!process_image_change_allowed(2, false));
        assert!(!process_image_change_allowed(1, true));
        assert!(address_space_mutation_allowed(1));
        assert!(!address_space_mutation_allowed(0));
        assert!(!address_space_mutation_allowed(2));
    }

    #[test]
    fn only_last_thread_publishes_the_process_result() {
        assert!(!should_publish_process_exit(1));
        assert!(should_publish_process_exit(0));
        assert_eq!(
            final_process_status(Some(ExitStatus::Code(41)), ExitStatus::Code(7)),
            ExitStatus::Code(41)
        );
        assert_eq!(
            final_process_status(None, ExitStatus::Code(7)),
            ExitStatus::Code(7)
        );
        assert_eq!(thread_exit_code(ExitStatus::Code(i64::MAX)), i32::MAX);
        assert_eq!(thread_exit_code(ExitStatus::Signal(9)), -9);
    }

    #[test]
    fn restricted_spawn_rejects_noncanonical_request_before_path_work() {
        let request = xenith_abi::SpawnRestrictedRequest {
            reserved: 1,
            ..xenith_abi::SpawnRestrictedRequest::default()
        };
        assert_eq!(
            spawn_restricted_in_group("/path-is-never-opened", &[], SpawnGroup::Inherit, &request,),
            Err(ProcessError::InvalidArgument)
        );
    }
}

#[cfg(test)]
mod job_control_tests {
    extern crate std;

    use super::*;

    #[test]
    fn user_process_inline_record_fits_the_kernel_stack_budget() {
        assert!(core::mem::size_of::<UserProcess>() <= 1024);
        std::eprintln!(
            "UserProcess inline bytes={}",
            core::mem::size_of::<UserProcess>()
        );
    }

    #[test]
    fn realtime_queue_full_is_a_process_delivery_error() {
        assert_eq!(
            delivery_result(DeliverOutcome::RealtimeQueueFull { capacity: 128 }),
            Err(ProcessError::SignalQueueFull)
        );
        assert_eq!(
            delivery_result(DeliverOutcome::RealtimeQueued { count: 1 }),
            Ok(DeliverOutcome::RealtimeQueued { count: 1 })
        );
    }

    #[test]
    fn wait_selectors_distinguish_pid_current_and_explicit_groups() {
        let pid = ProcessId(42);
        let group = ProcessId(7);
        assert!(WaitSelector::Any.matches(pid, group, ProcessId(9)));
        assert!(WaitSelector::Process(pid).matches(pid, group, ProcessId(9)));
        assert!(!WaitSelector::Process(ProcessId(41)).matches(pid, group, ProcessId(9)));
        assert!(WaitSelector::CurrentGroup.matches(pid, group, group));
        assert!(!WaitSelector::CurrentGroup.matches(pid, group, ProcessId(9)));
        assert!(WaitSelector::Group(group).matches(pid, group, ProcessId(9)));
    }

    #[test]
    fn waiter_registration_is_single_owner_and_explicitly_cleared() {
        let first = TaskId(11);
        let second = TaskId(12);
        let mut waiter = None;

        assert!(register_waiter(&mut waiter, first));
        assert!(register_waiter(&mut waiter, first));
        assert!(!register_waiter(&mut waiter, second));
        clear_waiter(&mut waiter, second);
        assert_eq!(waiter, Some(first));
        clear_waiter(&mut waiter, first);
        assert_eq!(waiter, None);
        assert!(register_waiter(&mut waiter, second));
    }

    #[test]
    fn group_signal_wait_scope_excludes_unrelated_processes() {
        assert!(group_child_waiter_relevant(true, false));
        assert!(group_child_waiter_relevant(false, true));
        assert!(group_child_waiter_relevant(true, true));
        assert!(!group_child_waiter_relevant(false, false));
    }

    #[test]
    fn staged_process_task_cannot_commit_before_metadata_is_recorded() {
        let called = core::cell::Cell::new(false);
        let result = finish_staged_task_publication(ProcessId(51), false, || {
            called.set(true);
            true
        });

        assert!(matches!(result, Err(ProcessError::TableCorrupt)));
        assert!(!called.get());
    }

    #[test]
    fn staged_process_task_propagates_commit_success_and_failure() {
        let pid = ProcessId(52);
        assert_eq!(finish_staged_task_publication(pid, true, || true), Ok(pid));
        assert!(matches!(
            finish_staged_task_publication(pid, true, || false),
            Err(ProcessError::TableCorrupt)
        ));
    }

    #[test]
    fn fixed_waiter_batch_deduplicates_without_allocation() {
        let mut batch = ProcessWaiterBatch::new();
        batch.push(None);
        batch.push(Some(TaskId(41)));
        batch.push(Some(TaskId(41)));
        batch.push(Some(TaskId(42)));

        assert_eq!(batch.len, 2);
        assert_eq!(&batch.tasks[..batch.len], &[TaskId(41), TaskId(42)]);
        assert_eq!(batch.tasks.len(), MAX_PROCESSES);
    }

    #[test]
    fn orphan_reap_batch_is_bounded_and_deduplicated() {
        let mut batch = OrphanReapBatch::new();
        batch.push(KERNEL_PROCESS_ID);
        batch.push(ProcessId(7));
        batch.push(ProcessId(7));
        batch.push(ProcessId(9));

        assert_eq!(batch.as_slice(), &[ProcessId(7), ProcessId(9)]);
        assert_eq!(batch.pids.len(), MAX_PROCESSES);
    }

    #[test]
    fn process_index_set_covers_the_full_process_bound() {
        let mut set = ProcessIndexSet::new();
        set.insert(0);
        set.insert(63);
        set.insert(64);
        set.insert(MAX_PROCESSES - 1);

        assert!(set.contains(0));
        assert!(set.contains(63));
        assert!(set.contains(64));
        assert!(set.contains(MAX_PROCESSES - 1));
        assert!(!set.contains(MAX_PROCESSES));
        assert!(!set.contains(65));
    }

    #[test]
    fn stopped_and_continued_wait_states_remain_distinct_from_exit() {
        assert_ne!(WaitStatus::Stopped(Signal::Tstp), WaitStatus::Continued);
        assert_ne!(
            WaitStatus::Stopped(Signal::Tstp),
            WaitStatus::Exited(ExitStatus::Signal(Signal::Tstp.as_number() as i32))
        );
    }
}

#[cfg(test)]
mod vm_tests {
    use super::*;

    const RW: VmProtection = VmProtection {
        writable: true,
        executable: false,
    };

    #[test]
    fn page_rounding_is_checked_and_exact() {
        assert_eq!(align_page_up(1), Some(PAGE_SIZE));
        assert_eq!(align_page_up(PAGE_SIZE), Some(PAGE_SIZE));
        assert_eq!(align_page_up(PAGE_SIZE + 1), Some(PAGE_SIZE * 2));
        assert_eq!(align_page_up(u64::MAX), None);
    }

    #[test]
    fn shared_subranges_are_page_aligned_bounded_and_non_executable() {
        assert_eq!(
            validate_shared_mapping_request(PAGE_SIZE * 2, PAGE_SIZE, 1, RW),
            Ok(PAGE_SIZE)
        );
        assert_eq!(
            validate_shared_mapping_request(PAGE_SIZE * 2, 1, PAGE_SIZE, RW),
            Err(VmError::InvalidRange)
        );
        assert_eq!(
            validate_shared_mapping_request(PAGE_SIZE * 2, PAGE_SIZE, PAGE_SIZE + 1, RW),
            Err(VmError::InvalidRange)
        );
        assert_eq!(
            validate_shared_mapping_request(PAGE_SIZE, 0, PAGE_SIZE, VmProtection {
                writable: false,
                executable: true,
            },),
            Err(VmError::PermissionDenied)
        );
    }

    #[test]
    fn shared_protection_never_exceeds_captured_descriptor_rights() {
        let read_only = VmProtection {
            writable: false,
            executable: false,
        };
        let executable = VmProtection {
            writable: false,
            executable: true,
        };

        assert!(shared_protection_allowed(false, read_only));
        assert!(!shared_protection_allowed(false, RW));
        assert!(shared_protection_allowed(true, RW));
        assert!(!shared_protection_allowed(true, executable));
    }

    #[test]
    fn anonymous_region_coverage_accepts_adjacent_ranges_but_not_holes() {
        let regions = [
            VmRegion {
                start: 0x1000,
                end: 0x3000,
                protection: RW,
                backing: VmBacking::AnonymousPrivate,
            },
            VmRegion {
                start: 0x3000,
                end: 0x5000,
                protection: RW,
                backing: VmBacking::AnonymousPrivate,
            },
        ];
        assert!(range_covered_by_regions(&regions, 0x2000, 0x5000));
        assert!(!range_covered_by_regions(&regions, 0x2000, 0x6000));

        let with_hole = [regions[0].clone(), VmRegion {
            start: 0x4000,
            ..regions[1].clone()
        }];
        assert!(!range_covered_by_regions(&with_hole, 0x2000, 0x5000));
    }

    #[test]
    fn page_permissions_encode_read_write_and_read_execute_without_wx() {
        let writable = page_flags(RW);
        assert!(writable.contains(PageTableFlags::USER | PageTableFlags::WRITABLE));
        assert!(writable.contains(PageTableFlags::NO_EXECUTE));

        let executable = page_flags(VmProtection {
            writable: false,
            executable: true,
        });
        assert!(executable.contains(PageTableFlags::USER));
        assert!(!executable.contains(PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE));
    }

    #[test]
    fn protection_metadata_is_split_before_page_table_mutation() {
        let rx = VmProtection {
            writable: false,
            executable: true,
        };
        let regions = [VmRegion {
            start: 0x1000,
            end: 0x5000,
            protection: RW,
            backing: VmBacking::AnonymousPrivate,
        }];
        let updated = build_protected_regions(&regions, 0x2000, 0x4000, rx).unwrap();
        assert_eq!(updated.len(), 3);
        assert_eq!((updated[0].start, updated[0].end), (0x1000, 0x2000));
        assert_eq!(updated[0].protection, RW);
        assert_eq!((updated[1].start, updated[1].end), (0x2000, 0x4000));
        assert_eq!(updated[1].protection, rx);
        assert_eq!((updated[2].start, updated[2].end), (0x4000, 0x5000));
        assert_eq!(updated[2].protection, RW);
    }

    #[test]
    fn dynamic_bounds_exclude_stack_guard_and_overflow() {
        assert!(valid_dynamic_range(MMAP_BASE, PAGE_SIZE));
        assert!(valid_dynamic_range(DYNAMIC_LIMIT - PAGE_SIZE, PAGE_SIZE));
        assert!(!valid_dynamic_range(DYNAMIC_LIMIT, PAGE_SIZE));
        assert!(!valid_dynamic_range(u64::MAX - (PAGE_SIZE - 1), PAGE_SIZE));
    }
}
