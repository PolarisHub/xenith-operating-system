//! Raw `syscall` instruction and typed wrappers.

use core::arch::asm;

use xenith_abi::{
    DirectoryEntry, NetInterfaceInfo, OpenFlags, SigAction, SigSet, SockAddrV4, Stat,
    SyscallNumber, Timespec, UtsName,
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

/// Create a mapping. The kernel currently accepts the bounded anonymous,
/// private subset (`MAP_PRIVATE | MAP_ANONYMOUS`, `fd == -1`, offset zero).
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
    call(SyscallNumber::Spawn, [
        path.as_ptr() as usize,
        path.len(),
        argv as usize,
        envp as usize,
        0,
        0,
    ])
    .map(|pid| pid as i64)
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
