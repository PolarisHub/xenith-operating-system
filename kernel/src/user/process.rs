//! Userspace process ownership, launch, exit, and waiting.
//!
//! A [`UserProcess`] is deliberately separate from the scheduler's [`Task`]:
//! the scheduler owns execution state and kernel stacks, while this module
//! owns the POSIX-like process resources shared by those tasks (address
//! space, descriptors, children, exit status, and signals).  The global table
//! is protected by an IRQ-safe lock because syscall handlers run preemptibly.

extern crate alloc;

use alloc::string::String;
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
use crate::fs::fd::FdTable;
use crate::fs::inode::FileType;
use crate::fs::path::Path;
use crate::fs::vfs::{self, FsError};
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

/// Xenith currently has one scheduler task per process, so deduplicating the
/// two possible waiter roles needs at most one task id per process.
const MAX_PROCESS_WAITERS: usize = MAX_PROCESSES;
const PROCESS_MASK_WORDS: usize = MAX_PROCESSES.div_ceil(64);

/// Maximum heap growth above an executable's initial break.
const MAX_BRK_BYTES: u64 = 256 * 1024 * 1024;

/// First-fit base for anonymous mappings. This leaves the low 4 GiB to the
/// executable and its conventional heap while remaining far below the stack.
const MMAP_BASE: u64 = 0x0000_0001_0000_0000;

/// Per-call and per-process anonymous-memory bounds. They prevent one bad
/// request from monopolising the physical allocator or spending unbounded
/// time in a syscall.
const MAX_ANONYMOUS_MAPPING: u64 = 256 * 1024 * 1024;
const MAX_ANONYMOUS_TOTAL: u64 = 1024 * 1024 * 1024;

/// Anonymous mappings stop below the deliberately-unmapped stack guard page.
const DYNAMIC_LIMIT: u64 = elf::USER_STACK_TOP - elf::USER_STACK_SIZE - PAGE_SIZE;

/// Permissions retained for one anonymous region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmProtection {
    pub writable: bool,
    pub executable: bool,
}

/// One page-aligned anonymous/private region created by `mmap`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmRegion {
    pub start: u64,
    pub end: u64,
    pub protection: VmProtection,
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

/// All resources owned by one user process.
pub struct UserProcess {
    pub pid: ProcessId,
    /// POSIX process group used by terminal job control and group signals.
    pub process_group: ProcessId,
    /// Session containing this process and its process group.
    pub session: ProcessId,
    pub address_space: AddressSpace,
    /// Scheduler tasks which execute in this process's address space.
    pub threads: Vec<TaskId>,
    pub fd_table: FdTable,
    pub parent: Option<ProcessId>,
    pub children: Vec<ProcessId>,
    pub exit_status: ExitStatus,
    pub signals: SignalState,
    /// Cooperative stop state. A stopped task parks at the syscall boundary
    /// until a group-directed `SIGCONT` clears this flag.
    pub stopped: bool,
    wait_change: Option<WaitStatus>,
    /// The process's sole task while it is blocked in `waitpid`. Registration
    /// is protected by `PROCESS_TABLE` and handed directly to the scheduler's
    /// intrusive blocked queue, so waiting never allocates.
    child_waiter: Option<TaskId>,
    /// The process's sole task while a default stop disposition is active.
    state_waiter: Option<TaskId>,
    termination_signal: Option<Signal>,
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
    /// are intentionally absent so `munmap` cannot remove them.
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
            .field("anonymous_regions", &self.vm_regions.len())
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
        (parent.fd_table.clone(), process_group, session)
    } else {
        let process_group = match group {
            SpawnGroup::Inherit | SpawnGroup::New => pid,
            SpawnGroup::Join(requested) => return Err(ProcessError::NoSuchProcess(requested)),
        };
        (FdTable::new_process(), process_group, pid)
    };
    let mut process_path = String::new();
    process_path
        .try_reserve_exact(path.len())
        .map_err(|_| ProcessError::OutOfMemory)?;
    process_path.push_str(path);
    let task_name = make_task_name(path)?;
    let mut threads = Vec::new();
    threads
        .try_reserve_exact(1)
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
        fd_table,
        parent,
        children,
        exit_status: ExitStatus::Pending,
        signals,
        stopped: false,
        wait_change: None,
        child_waiter: None,
        state_waiter: None,
        termination_signal: None,
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

    // Keep a timer tick from dispatching the new task between scheduler
    // insertion and recording its TaskId in the process table.
    sched::preempt_disable();
    let task = sched::spawn(task_name, launch_process, pid.as_u64());
    let result = match task {
        Some(task_id) => {
            let mut table = PROCESS_TABLE.lock();
            match table.iter_mut().find(|process| process.pid == pid) {
                Some(process) => {
                    process.threads.push(task_id);
                    Ok(pid)
                },
                None => Err(ProcessError::TableCorrupt),
            }
        },
        None => Err(ProcessError::OutOfMemory),
    };
    sched::preempt_enable();

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
        regions.extend_from_slice(&parent.vm_regions);
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
        .try_reserve_exact(1)
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
        fd_table,
        parent: Some(parent_pid),
        children,
        exit_status: ExitStatus::Pending,
        signals,
        stopped: false,
        wait_change: None,
        child_waiter: None,
        state_waiter: None,
        termination_signal: None,
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

    sched::preempt_disable();
    let result = match sched::spawn(task_name, launch_process, pid.as_u64()) {
        Some(task_id) => {
            let mut table = PROCESS_TABLE.lock();
            match table.iter_mut().find(|record| record.pid == pid) {
                Some(record) => {
                    record.threads.push(task_id);
                    Ok(pid)
                },
                None => Err(ProcessError::TableCorrupt),
            }
        },
        None => Err(ProcessError::OutOfMemory),
    };
    sched::preempt_enable();
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
    {
        let table = PROCESS_TABLE.lock();
        if !table.iter().any(|record| record.pid == pid) {
            return Err(ProcessError::NoCurrentProcess);
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
    let (old_space, old_pages, kernel_rsp) = {
        let mut table = PROCESS_TABLE.lock();
        let process = table
            .iter_mut()
            .find(|record| record.pid == pid)
            .ok_or(ProcessError::NoCurrentProcess)?;
        let old_space = core::mem::replace(&mut process.address_space, space);
        let old_pages = core::mem::replace(&mut process.pages, pages);
        process.path = process_path;
        process.entry = entry;
        process.user_rsp = user_rsp;
        process.startup = startup;
        process.brk_base = initial_break;
        process.brk_current = initial_break;
        process.vm_regions.clear();
        process.mmap_hint = MMAP_BASE;
        process.fork_resume = None;
        process.fd_table.close_on_exec();
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
        (old_space, old_pages, kernel_rsp)
    };

    // Switch first, then reclaim: executing kernel text/stack/heap are shared
    // in the new upper half, while the old user hierarchy is now inactive.
    // SAFETY: ELF loading installed a valid PML4 with the shared kernel half.
    unsafe { space.load() };
    // SAFETY: CR3 now names `space`; the old hierarchy is unpublished and no
    // other thread exists in Xenith's current one-thread-per-process model.
    unsafe { elf::destroy(old_space, &old_pages) };
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
    // Revoke scanout/input before descriptor or child cleanup can allocate,
    // fail, or contend. A crashing compositor must never retain the session
    // merely because later process teardown cannot make progress.
    let _ = crate::ui::release_if_owner(pid);
    let mut parent_waiter = None;
    if !pid.is_kernel() {
        // This must precede the PROCESS_TABLE release that publishes
        // `exit_status`: a parent may wake and destroy this address space on
        // another CPU immediately after that publication. From here onward
        // teardown touches only globally mapped kernel memory.
        sched::scheduler::detach_current_address_space();
        let mut table = PROCESS_TABLE.lock();
        if let Some(index) = table.iter().position(|process| process.pid == pid) {
            let parent = if table[index].exit_status.is_pending() {
                table[index].exit_status = status;
                table[index].fd_table.close_all();
                // Orphan children rather than leaving dangling parent ids.
                let children = table[index].children.clone();
                for child in children {
                    if let Some(record) = table.iter_mut().find(|record| record.pid == child) {
                        record.parent = None;
                    }
                }
                table[index].parent
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
    wake_process_waiter(parent_waiter);
    sched::scheduler::exit(status)
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
            return Err(ProcessError::TableCorrupt);
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
        .find(|process| process.threads.contains(&task))
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
    let (result, waiters) = signal_one_inner(pid, signal, None)?;
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
    let (result, waiters) = signal_one_inner(pid, signal, Some(info))?;
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
) -> Result<(DeliverOutcome, [Option<TaskId>; 3]), ProcessError> {
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
    let state_waiter = table[index].state_waiter.take();
    let parent_waiter = parent.and_then(|parent| {
        table
            .iter_mut()
            .find(|record| record.pid == parent)
            .and_then(|record| record.child_waiter.take())
    });
    Ok((outcome, [child_waiter, state_waiter, parent_waiter]))
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
        if accepted_targets.contains(index) {
            waiters.push(table[index].state_waiter.take());
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
                process.termination_signal = Some(signal);
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
    let Some(task) = sched::scheduler::with_current_node(|node| node.task.id) else {
        return;
    };
    loop {
        let mut table = PROCESS_TABLE.lock();
        let Some(index) = table.iter().position(|process| process.pid == pid) else {
            return;
        };
        clear_waiter(&mut table[index].state_waiter, task);
        if let Some(signal) = table[index].termination_signal {
            drop(table);
            exit_signal(signal);
        }
        if !table[index].stopped {
            return;
        }
        if !register_waiter(&mut table[index].state_waiter, task) {
            return;
        }
        // SIGCONT/termination takes the registration only after this call has
        // linked the task into the scheduler's allocation-free blocked queue.
        sched::scheduler::block_current_until_releasing(None, table);
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
    with_current_process_mut(|process| set_process_break(process, request))
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
        let length = align_page_up(length).ok_or(VmError::InvalidRange)?;
        if length == 0 {
            return Err(VmError::InvalidRange);
        }
        if length > MAX_ANONYMOUS_MAPPING {
            return Err(VmError::OutOfMemory);
        }
        let total = process
            .vm_regions
            .iter()
            .try_fold(0u64, |total, region| {
                total.checked_add(region.end - region.start)
            })
            .ok_or(VmError::OutOfMemory)?;
        let new_total = total.checked_add(length).ok_or(VmError::OutOfMemory)?;
        if new_total > MAX_ANONYMOUS_TOTAL {
            return Err(VmError::OutOfMemory);
        }

        let hinted = (address_hint != 0)
            .then_some(address_hint & !(PAGE_SIZE - 1))
            .filter(|start| valid_dynamic_range(*start, length))
            .filter(|start| range_is_free(process, *start, *start + length));
        let start = match hinted {
            Some(start) => start,
            None => {
                let search = process.mmap_hint.max(MMAP_BASE);
                find_free_range(process, search, length)
                    .or_else(|| {
                        (search > MMAP_BASE)
                            .then(|| find_free_range(process, MMAP_BASE, length))
                            .flatten()
                    })
                    .ok_or(VmError::OutOfMemory)?
            },
        };
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
        });
        process
            .vm_regions
            .sort_unstable_by_key(|region| region.start);
        process.mmap_hint = end;
        Ok(start)
    })
    .ok_or(VmError::NoCurrentProcess)?
}

/// Remove a page-aligned range wholly covered by mappings created through
/// [`map_anonymous`]. Static ELF/stack/trampoline pages and the `brk` heap are
/// not members of `vm_regions`, so they cannot be removed through this path.
pub fn unmap_anonymous(address: u64, length: u64) -> Result<(), VmError> {
    with_current_process_mut(|process| {
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

        // Build the post-unmap region list before changing page tables. A
        // split can add one entry, and allocation failure must be harmless.
        let mut updated = Vec::new();
        updated
            .try_reserve(process.vm_regions.len().saturating_add(1))
            .map_err(|_| VmError::OutOfMemory)?;
        for region in process.vm_regions.iter().copied() {
            if region.end <= address || region.start >= end {
                updated.push(region);
                continue;
            }
            if region.start < address {
                updated.push(VmRegion {
                    end: address,
                    ..region
                });
            }
            if region.end > end {
                updated.push(VmRegion {
                    start: end,
                    ..region
                });
            }
        }

        validate_owned_pages(process, address, end)?;
        unmap_owned_range(process, address, end)?;
        process.vm_regions = updated;
        process.mmap_hint = process.mmap_hint.min(address.max(MMAP_BASE));
        Ok(())
    })
    .ok_or(VmError::NoCurrentProcess)?
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
    })
}

fn find_free_range(process: &UserProcess, start: u64, length: u64) -> Option<u64> {
    let mut candidate = align_page_up(start.max(elf::USER_IMAGE_MIN))?;
    loop {
        if !valid_dynamic_range(candidate, length) {
            return None;
        }
        let end = candidate.checked_add(length)?;
        let next = process
            .pages
            .iter()
            .filter_map(|mapping| {
                let mapped_start = mapping.page.start_address().as_u64();
                let mapped_end = mapped_start.checked_add(PAGE_SIZE)?;
                (candidate < mapped_end && mapped_start < end).then_some(mapped_end)
            })
            .max();
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
    NotOwned,
    NoCurrentProcess,
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
        return;
    }
    // SAFETY: the process has exited, was removed from the table, and its
    // scheduler task is no longer runnable.  Its address space is inactive.
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
    PermissionDenied,
    Interrupted,
    SignalQueueFull,
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
            Self::PermissionDenied => f.write_str("process operation is not permitted"),
            Self::Interrupted => f.write_str("process wait interrupted by a signal"),
            Self::SignalQueueFull => f.write_str("real-time signal queue is full"),
            Self::TableCorrupt => f.write_str("process table invariant violated"),
            Self::Filesystem(error) => write!(f, "filesystem error: {error}"),
            Self::AddressSpace(error) => write!(f, "address-space error: {error:?}"),
            Self::Elf(error) => write!(f, "ELF load error: {error}"),
        }
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
    fn anonymous_region_coverage_accepts_adjacent_ranges_but_not_holes() {
        let regions = [
            VmRegion {
                start: 0x1000,
                end: 0x3000,
                protection: RW,
            },
            VmRegion {
                start: 0x3000,
                end: 0x5000,
                protection: RW,
            },
        ];
        assert!(range_covered_by_regions(&regions, 0x2000, 0x5000));
        assert!(!range_covered_by_regions(&regions, 0x2000, 0x6000));

        let with_hole = [regions[0], VmRegion {
            start: 0x4000,
            ..regions[1]
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
    fn dynamic_bounds_exclude_stack_guard_and_overflow() {
        assert!(valid_dynamic_range(MMAP_BASE, PAGE_SIZE));
        assert!(valid_dynamic_range(DYNAMIC_LIMIT - PAGE_SIZE, PAGE_SIZE));
        assert!(!valid_dynamic_range(DYNAMIC_LIMIT, PAGE_SIZE));
        assert!(!valid_dynamic_range(u64::MAX - (PAGE_SIZE - 1), PAGE_SIZE));
    }
}
