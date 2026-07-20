//! Raw `syscall` instruction and typed wrappers.

use core::arch::asm;

use xenith_abi::{
    DirectoryEntry, IpcChannelPair, IpcReceiveMessage, IpcSendMessage, NetInterfaceInfo, OpenFlags,
    SigAction, SigAltStack, SigSet, SockAddrV4, SpawnRestrictedRequest, Stat, SyscallNumber,
    ThreadCreate, ThreadJoinResult, Timespec, UiDisplayInfo, UiInputEvent, UiRect, UtsName,
    WaitItem, UI_MAX_EVENTS_PER_READ, WAIT_MAX_ITEMS,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error(pub i32);

pub type Result<T> = core::result::Result<T, Error>;

#[inline]
fn decode(value: i64) -> Result<usize> {
    if value < 0 {
        Err(Error((-value) as i32))
    } else {
        Ok(value as usize)
    }
}

#[inline]
unsafe fn raw6(number: SyscallNumber, args: [usize; 6]) -> i64 {
    let mut rax = number as u64;
    // SAFETY: this is the Xenith userspace trap ABI. RCX/R11 are architectural clobbers.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") rax,
            in("rdi") args[0], in("rsi") args[1], in("rdx") args[2],
            in("r10") args[3], in("r8") args[4], in("r9") args[5],
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
    }
    rax as i64
}

#[inline]
fn call(number: SyscallNumber, args: [usize; 6]) -> Result<usize> {
    // SAFETY: wrappers provide the argument order and preserve pointer lifetimes for the call.
    decode(unsafe { raw6(number, args) })
}

pub fn read(fd: i32, buffer: &mut [u8]) -> Result<usize> {
    call(SyscallNumber::Read, [
        fd as usize,
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        0,
        0,
        0,
    ])
}

pub fn write(fd: i32, buffer: &[u8]) -> Result<usize> {
    call(SyscallNumber::Write, [
        fd as usize,
        buffer.as_ptr() as usize,
        buffer.len(),
        0,
        0,
        0,
    ])
}

/// Submit a raw userspace address to Xenith's checked `write` syscall path.
///
/// Unlike [`write`], this wrapper never creates or dereferences a Rust slice.
/// The kernel validates and copies the address range before the descriptor
/// backend observes it, returning `EFAULT` for an inaccessible range.
///
/// # Safety
/// The address and length must remain stable for the synchronous syscall. The
/// pointer is intentionally allowed to originate outside Rust's reference
/// model; no Rust validity or alignment assumption is made by this wrapper.
pub unsafe fn write_raw(fd: i32, buffer: *const u8, length: usize) -> Result<usize> {
    call(SyscallNumber::Write, [
        fd as usize,
        buffer as usize,
        length,
        0,
        0,
        0,
    ])
}

pub fn open(path: &[u8], flags: OpenFlags, mode: u32) -> Result<i32> {
    call(SyscallNumber::Open, [
        path.as_ptr() as usize,
        path.len(),
        flags.0 as usize,
        mode as usize,
        0,
        0,
    ])
    .map(|v| v as i32)
}

pub fn close(fd: i32) -> Result<()> {
    call(SyscallNumber::Close, [fd as usize, 0, 0, 0, 0, 0]).map(|_| ())
}

/// Query (`address == 0`) or set the calling process's program break.
pub fn brk(address: usize) -> Result<usize> {
    call(SyscallNumber::Brk, [address, 0, 0, 0, 0, 0])
}

/// Create a private anonymous or shared descriptor-backed mapping.
pub fn mmap(
    address: *mut u8,
    length: usize,
    protection: u32,
    flags: u32,
    fd: i32,
    offset: isize,
) -> Result<*mut u8> {
    call(SyscallNumber::Mmap, [
        address as usize,
        length,
        protection as usize,
        flags as usize,
        fd as usize,
        offset as usize,
    ])
    .map(|value| value as *mut u8)
}

/// Remove a page-aligned range previously returned by [`mmap`].
pub fn munmap(address: *mut u8, length: usize) -> Result<()> {
    call(SyscallNumber::Munmap, [
        address as usize,
        length,
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

/// Change permissions on a page-aligned range returned by [`mmap`].
pub fn mprotect(address: *mut u8, length: usize, protection: u32) -> Result<()> {
    call(SyscallNumber::Mprotect, [
        address as usize,
        length,
        protection as usize,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn ioctl(fd: i32, command: u32, argument: usize) -> Result<usize> {
    call(SyscallNumber::Ioctl, [
        fd as usize,
        command as usize,
        argument,
        0,
        0,
        0,
    ])
}

pub fn dup(fd: i32) -> Result<i32> {
    call(SyscallNumber::Dup, [fd as usize, 0, 0, 0, 0, 0]).map(|value| value as i32)
}

pub fn dup2(old_fd: i32, new_fd: i32) -> Result<i32> {
    call(SyscallNumber::Dup2, [
        old_fd as usize,
        new_fd as usize,
        0,
        0,
        0,
        0,
    ])
    .map(|value| value as i32)
}

pub fn pipe(descriptors: &mut [i32; 2]) -> Result<()> {
    call(SyscallNumber::Pipe, [
        descriptors.as_mut_ptr() as usize,
        0,
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn exit(code: i32) -> ! {
    let _ = call(SyscallNumber::Exit, [code as usize, 0, 0, 0, 0, 0]);
    loop {
        core::hint::spin_loop();
    }
}

/// Return the globally unique scheduler task id of the calling thread.
pub fn gettid() -> Result<u64> {
    call(SyscallNumber::Gettid, [0; 6]).map(|value| value as u64)
}

/// Create a raw joinable thread from an ABI request.
pub fn thread_create(request: &ThreadCreate) -> Result<u64> {
    call(SyscallNumber::ThreadCreate, [
        request as *const ThreadCreate as usize,
        0,
        0,
        0,
        0,
        0,
    ])
    .map(|value| value as u64)
}

/// Terminate only the calling thread.
pub fn thread_exit(code: i32) -> ! {
    let _ = call(SyscallNumber::ThreadExit, [code as usize, 0, 0, 0, 0, 0]);
    loop {
        core::hint::spin_loop();
    }
}

/// Wait for and consume one completed thread.
pub fn thread_join(thread: u64, result: &mut ThreadJoinResult) -> Result<()> {
    call(SyscallNumber::ThreadJoin, [
        thread as usize,
        result as *mut ThreadJoinResult as usize,
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

/// Entry signature accepted by [`spawn_thread`].
pub type ThreadEntry = extern "C" fn(usize) -> i32;

#[derive(Clone, Copy)]
#[repr(C)]
struct ThreadStart {
    entry: ThreadEntry,
    argument: usize,
}

unsafe extern "C" fn thread_bootstrap(raw_start: usize) -> ! {
    // SAFETY: spawn_thread stores an aligned ThreadStart at the base of the
    // exclusively-owned mapping before publishing this task.
    let start = unsafe { (raw_start as *const ThreadStart).read() };
    thread_exit((start.entry)(start.argument))
}

/// Start a joinable function on a caller-owned private stack mapping.
///
/// # Safety
///
/// `stack` must be a page-aligned, page-sized, writable and non-executable
/// mapping which no other execution context reads or writes until the returned
/// thread has been joined. The mapping must remain live for that entire time.
pub unsafe fn spawn_thread(entry: ThreadEntry, argument: usize, stack: &mut [u8]) -> Result<u64> {
    const PAGE_SIZE: usize = 4096;
    let base = stack.as_mut_ptr() as usize;
    if base == 0
        || base & (PAGE_SIZE - 1) != 0
        || stack.len() & (PAGE_SIZE - 1) != 0
        || stack.len() < core::mem::size_of::<ThreadStart>()
    {
        return Err(Error(xenith_abi::Errno::Einval as i32));
    }
    let start = ThreadStart { entry, argument };
    // SAFETY: the caller grants exclusive writable ownership of the complete
    // mapping, and the alignment check is stronger than ThreadStart requires.
    unsafe { (base as *mut ThreadStart).write(start) };
    thread_create(&ThreadCreate {
        version: xenith_abi::THREAD_ABI_VERSION,
        flags: 0,
        entry: thread_bootstrap as *const () as usize as u64,
        stack_base: base as u64,
        stack_size: stack.len() as u64,
        argument: base as u64,
        tls_base: 0,
        reserved: [0; 2],
    })
}

pub fn getpid() -> Result<u64> {
    call(SyscallNumber::Getpid, [0; 6]).map(|v| v as u64)
}

pub fn getppid() -> Result<u64> {
    call(SyscallNumber::Getppid, [0; 6]).map(|v| v as u64)
}

pub fn yield_now() -> Result<()> {
    call(SyscallNumber::Yield, [0; 6]).map(|_| ())
}

pub fn nanosleep(duration: Timespec) -> Result<()> {
    call(SyscallNumber::Nanosleep, [
        &duration as *const Timespec as usize,
        0,
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn fork() -> Result<i64> {
    call(SyscallNumber::Fork, [0; 6]).map(|v| v as i64)
}

pub fn exec(path: &[u8], argv: *const *const u8, envp: *const *const u8) -> Result<()> {
    call(SyscallNumber::Exec, [
        path.as_ptr() as usize,
        path.len(),
        argv as usize,
        envp as usize,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn waitpid(pid: i64, status: &mut i32, options: u32) -> Result<i64> {
    call(SyscallNumber::Waitpid, [
        pid as usize,
        status as *mut i32 as usize,
        options as usize,
        0,
        0,
        0,
    ])
    .map(|v| v as i64)
}

pub fn uname(out: &mut UtsName) -> Result<()> {
    call(SyscallNumber::Uname, [
        out as *mut UtsName as usize,
        0,
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn lseek(fd: i32, offset: i64, whence: u32) -> Result<u64> {
    call(SyscallNumber::Lseek, [
        fd as usize,
        offset as usize,
        whence as usize,
        0,
        0,
        0,
    ])
    .map(|v| v as u64)
}

pub fn stat(path: &[u8], out: &mut Stat) -> Result<()> {
    call(SyscallNumber::Stat, [
        path.as_ptr() as usize,
        path.len(),
        out as *mut Stat as usize,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn chdir(path: &[u8]) -> Result<()> {
    call(SyscallNumber::Chdir, [
        path.as_ptr() as usize,
        path.len(),
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn getcwd(buffer: &mut [u8]) -> Result<usize> {
    call(SyscallNumber::Getcwd, [
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        0,
        0,
        0,
        0,
    ])
}

pub fn mkdir(path: &[u8], mode: u32) -> Result<()> {
    call(SyscallNumber::Mkdir, [
        path.as_ptr() as usize,
        path.len(),
        mode as usize,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn unlink(path: &[u8]) -> Result<()> {
    call(SyscallNumber::Unlink, [
        path.as_ptr() as usize,
        path.len(),
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn read_dir(path: &[u8], entries: &mut [DirectoryEntry]) -> Result<usize> {
    call(SyscallNumber::ReadDir, [
        path.as_ptr() as usize,
        path.len(),
        entries.as_mut_ptr() as usize,
        entries.len(),
        0,
        0,
    ])
}

pub fn clock_gettime() -> Result<Timespec> {
    let mut value = Timespec::default();
    call(SyscallNumber::ClockGettime, [
        &mut value as *mut Timespec as usize,
        0,
        0,
        0,
        0,
        0,
    ])
    .map(|_| value)
}

pub fn spawn(path: &[u8], argv: *const *const u8, envp: *const *const u8) -> Result<i64> {
    spawn_with_group_argument(path, argv, envp, xenith_abi::SPAWN_GROUP_INHERIT as usize)
}

/// Spawn with process-group placement completed before the child is runnable.
/// A zero group creates a new group led by the child; a positive value joins
/// an existing group in the caller's session.
pub fn spawn_in_process_group(
    path: &[u8],
    argv: *const *const u8,
    envp: *const *const u8,
    process_group: i64,
) -> Result<i64> {
    if process_group < 0 {
        return Err(Error(xenith_abi::Errno::Einval as i32));
    }
    let group = if process_group == 0 {
        xenith_abi::SPAWN_GROUP_NEW
    } else {
        process_group as u64
    };
    spawn_with_group_argument(path, argv, envp, group as usize)
}

fn spawn_with_group_argument(
    path: &[u8],
    argv: *const *const u8,
    envp: *const *const u8,
    group: usize,
) -> Result<i64> {
    call(SyscallNumber::Spawn, [
        path.as_ptr() as usize,
        path.len(),
        argv as usize,
        envp as usize,
        group,
        0,
    ])
    .map(|pid| pid as i64)
}

/// Spawn a child with only the descriptor mappings named by `request`.
///
/// The request also carries the ordinary spawn process-group token. The
/// kernel validates and snapshots the complete action batch before publishing
/// the child, leaving the caller's descriptor table unchanged on failure.
pub fn spawn_restricted(
    path: &[u8],
    argv: *const *const u8,
    envp: *const *const u8,
    request: &SpawnRestrictedRequest,
) -> Result<i64> {
    call(
        SyscallNumber::SpawnRestricted,
        spawn_restricted_arguments(path, argv, envp, request),
    )
    .map(|pid| pid as i64)
}

#[inline]
fn spawn_restricted_arguments(
    path: &[u8],
    argv: *const *const u8,
    envp: *const *const u8,
    request: &SpawnRestrictedRequest,
) -> [usize; 6] {
    [
        path.as_ptr() as usize,
        path.len(),
        argv as usize,
        envp as usize,
        request as *const SpawnRestrictedRequest as usize,
        0,
    ]
}

pub fn socket(domain: u32, socket_type: u32, protocol: u32) -> Result<i32> {
    call(SyscallNumber::Socket, [
        domain as usize,
        socket_type as usize,
        protocol as usize,
        0,
        0,
        0,
    ])
    .map(|fd| fd as i32)
}

pub fn bind(fd: i32, address: &SockAddrV4) -> Result<()> {
    call(SyscallNumber::Bind, [
        fd as usize,
        address as *const SockAddrV4 as usize,
        core::mem::size_of::<SockAddrV4>(),
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn listen(fd: i32, backlog: usize) -> Result<()> {
    call(SyscallNumber::Listen, [fd as usize, backlog, 0, 0, 0, 0]).map(|_| ())
}

pub fn accept(fd: i32, peer: Option<&mut SockAddrV4>) -> Result<i32> {
    let (pointer, length) = match peer {
        Some(peer) => (
            peer as *mut SockAddrV4 as usize,
            core::mem::size_of::<SockAddrV4>(),
        ),
        None => (0, 0),
    };
    call(SyscallNumber::Accept, [
        fd as usize,
        pointer,
        length,
        0,
        0,
        0,
    ])
    .map(|accepted| accepted as i32)
}

pub fn connect(fd: i32, peer: &SockAddrV4) -> Result<()> {
    call(SyscallNumber::Connect, [
        fd as usize,
        peer as *const SockAddrV4 as usize,
        core::mem::size_of::<SockAddrV4>(),
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn send(fd: i32, payload: &[u8]) -> Result<usize> {
    call(SyscallNumber::Send, [
        fd as usize,
        payload.as_ptr() as usize,
        payload.len(),
        0,
        0,
        0,
    ])
}

pub fn recv(fd: i32, payload: &mut [u8]) -> Result<usize> {
    call(SyscallNumber::Recv, [
        fd as usize,
        payload.as_mut_ptr() as usize,
        payload.len(),
        0,
        0,
        0,
    ])
}

pub fn net_info(index: usize) -> Result<NetInterfaceInfo> {
    let mut info = NetInterfaceInfo::default();
    call(SyscallNumber::NetInfo, [
        index,
        &mut info as *mut NetInterfaceInfo as usize,
        0,
        0,
        0,
        0,
    ])
    .map(|_| info)
}

pub fn kill(pid: i64, signal: u32) -> Result<()> {
    call(SyscallNumber::Kill, [
        pid as usize,
        signal as usize,
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn setpgid(pid: i64, process_group: i64) -> Result<()> {
    call(SyscallNumber::Setpgid, [
        pid as usize,
        process_group as usize,
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn getpgrp() -> Result<i64> {
    call(SyscallNumber::Getpgrp, [0; 6]).map(|value| value as i64)
}

pub fn setsid() -> Result<i64> {
    call(SyscallNumber::Setsid, [0; 6]).map(|value| value as i64)
}

pub fn openpty(descriptors: &mut [i32; 2]) -> Result<()> {
    call(SyscallNumber::OpenPty, [
        descriptors.as_mut_ptr() as usize,
        0,
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

/// Restore the frame created by the kernel for the active caught signal.
/// A successful call resumes the interrupted context and therefore does not
/// return to the caller; an invalid frame returns `EINVAL`.
///
/// # Safety
/// The current stack pointer must name the kernel-created signal frame.
pub unsafe fn sigreturn() -> Result<()> {
    call(SyscallNumber::Sigreturn, [0; 6]).map(|_| ())
}

pub fn sigaction(
    signal: u32,
    action: Option<&SigAction>,
    old_action: Option<&mut SigAction>,
) -> Result<()> {
    let action_pointer = action.map_or(0, |value| core::ptr::from_ref(value) as usize);
    let old_pointer = old_action.map_or(0, |value| core::ptr::from_mut(value) as usize);
    call(SyscallNumber::Sigaction, [
        signal as usize,
        action_pointer,
        old_pointer,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn sigprocmask(how: u32, set: Option<&SigSet>, old_set: Option<&mut SigSet>) -> Result<()> {
    let set_pointer = set.map_or(0, |value| core::ptr::from_ref(value) as usize);
    let old_pointer = old_set.map_or(0, |value| core::ptr::from_mut(value) as usize);
    call(SyscallNumber::Sigprocmask, [
        how as usize,
        set_pointer,
        old_pointer,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn getrandom(buffer: &mut [u8], flags: u32) -> Result<usize> {
    call(SyscallNumber::GetRandom, [
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        flags as usize,
        0,
        0,
        0,
    ])
}

/// Install, disable, or query the calling thread's alternate signal stack.
pub fn sigaltstack(
    new_stack: Option<&SigAltStack>,
    old_stack: Option<&mut SigAltStack>,
) -> Result<()> {
    let new_pointer = new_stack.map_or(0, |value| core::ptr::from_ref(value) as usize);
    let old_pointer = old_stack.map_or(0, |value| core::ptr::from_mut(value) as usize);
    call(SyscallNumber::Sigaltstack, [
        new_pointer,
        old_pointer,
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn mount_ramfs(path: &[u8]) -> Result<()> {
    call(SyscallNumber::MountRamfs, [
        path.as_ptr() as usize,
        path.len(),
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn unmount(path: &[u8]) -> Result<()> {
    call(SyscallNumber::Unmount, [
        path.as_ptr() as usize,
        path.len(),
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn symlink(target: &[u8], link: &[u8]) -> Result<()> {
    call(SyscallNumber::Symlink, [
        target.as_ptr() as usize,
        target.len(),
        link.as_ptr() as usize,
        link.len(),
        0,
        0,
    ])
    .map(|_| ())
}

pub fn chmod(path: &[u8], mode: u32) -> Result<()> {
    call(SyscallNumber::Chmod, [
        path.as_ptr() as usize,
        path.len(),
        mode as usize,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn chown(path: &[u8], uid: u32, gid: u32) -> Result<()> {
    call(SyscallNumber::Chown, [
        path.as_ptr() as usize,
        path.len(),
        uid as usize,
        gid as usize,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn utimens(path: &[u8], accessed_ns: u64, modified_ns: u64) -> Result<()> {
    call(SyscallNumber::Utimens, [
        path.as_ptr() as usize,
        path.len(),
        accessed_ns as usize,
        modified_ns as usize,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn rmdir(path: &[u8]) -> Result<()> {
    call(SyscallNumber::Rmdir, [
        path.as_ptr() as usize,
        path.len(),
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn ui_acquire(display: &mut UiDisplayInfo) -> Result<()> {
    call(SyscallNumber::UiAcquire, [
        core::ptr::from_mut(display) as usize,
        0,
        0,
        0,
        0,
        0,
    ])
    .map(|_| ())
}

pub fn ui_present(pixels: &[u8], source_stride: usize, damage: &[UiRect]) -> Result<()> {
    let (damage_pointer, damage_count) = if damage.is_empty() {
        (0, 0)
    } else {
        (damage.as_ptr() as usize, damage.len())
    };

    call(SyscallNumber::UiPresent, [
        pixels.as_ptr() as usize,
        pixels.len(),
        source_stride,
        damage_pointer,
        damage_count,
        0,
    ])
    .map(|_| ())
}

pub fn ui_read_events(events: &mut [UiInputEvent], timeout_ns: u64) -> Result<usize> {
    if events.is_empty() {
        return Ok(0);
    }
    let capacity = events.len().min(UI_MAX_EVENTS_PER_READ);

    call(SyscallNumber::UiReadEvents, [
        events.as_mut_ptr() as usize,
        capacity,
        timeout_ns as usize,
        0,
        0,
        0,
    ])
}

pub fn ui_release() -> Result<()> {
    call(SyscallNumber::UiRelease, [0, 0, 0, 0, 0, 0]).map(|_| ())
}

/// Create a connected pair of bidirectional, message-preserving channels.
pub fn channel_create() -> Result<IpcChannelPair> {
    let mut pair = IpcChannelPair::default();
    call(SyscallNumber::ChannelCreate, [
        core::ptr::from_mut(&mut pair) as usize,
        0,
        0,
        0,
        0,
        0,
    ])?;
    Ok(pair)
}

/// Atomically enqueue one bounded payload and its attenuated descriptor set.
pub fn channel_send(fd: i32, message: &IpcSendMessage, timeout_ns: u64) -> Result<usize> {
    call(SyscallNumber::ChannelSend, [
        fd as usize,
        core::ptr::from_ref(message) as usize,
        timeout_ns as usize,
        0,
        0,
        0,
    ])
}

/// Receive one complete channel message and atomically install its transfers.
pub fn channel_recv(fd: i32, message: &mut IpcReceiveMessage, timeout_ns: u64) -> Result<usize> {
    call(SyscallNumber::ChannelRecv, [
        fd as usize,
        core::ptr::from_mut(message) as usize,
        timeout_ns as usize,
        0,
        0,
        0,
    ])
}

/// Create a zero-filled page-rounded shared-memory object and return its FD.
pub fn shm_create(length: usize) -> Result<i32> {
    call(SyscallNumber::ShmCreate, [length, 0, 0, 0, 0, 0]).map(|fd| fd as i32)
}

/// Wait until at least one channel or the exclusive UI seat is ready.
///
/// The kernel updates every item transactionally and returns the number of
/// entries whose `ready` field is nonzero. An empty or oversized set is
/// rejected without entering the kernel.
pub fn wait(items: &mut [WaitItem], timeout_ns: u64) -> Result<usize> {
    if items.is_empty() || items.len() > WAIT_MAX_ITEMS {
        return Err(Error(xenith_abi::Errno::Einval as i32));
    }
    call(SyscallNumber::Wait, [
        items.as_mut_ptr() as usize,
        items.len(),
        timeout_ns as usize,
        0,
        0,
        0,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restricted_spawn_wrapper_uses_the_fixed_request_pointer_slot() {
        let path = b"/bin/client";
        let request = SpawnRestrictedRequest::default();
        let argv = 0x1000usize as *const *const u8;
        let envp = 0x2000usize as *const *const u8;
        let arguments = spawn_restricted_arguments(path, argv, envp, &request);

        assert_eq!(arguments[0], path.as_ptr() as usize);
        assert_eq!(arguments[1], path.len());
        assert_eq!(arguments[2], argv as usize);
        assert_eq!(arguments[3], envp as usize);
        assert_eq!(arguments[4], core::ptr::from_ref(&request) as usize);
        assert_eq!(arguments[5], 0);
        assert_eq!(SyscallNumber::SpawnRestricted as u64, 68);
    }
}
