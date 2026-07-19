//! The syscall dispatch table: a fixed array indexed by syscall number.
//!
//! [`SYSCALLS`] is an `[Option<SyscallFn>; NUM_SYSCALLS]` where slot *n* holds
//! the handler for syscall number *n*, or `None` if that number is reserved
//! or unimplemented. The table is `const` so it lives in read-only data and
//! is resolved with a single indexed load in [`lookup`]; there is no hashing,
//! no match ladder, and no runtime registration.
//!
//! # Numbering
//!
//! The numbers are Xenith's own sequential assignment (0 read, 1 write, ...),
//! documented inline at each constant. They are *not* Linux syscall numbers:
//! Xenith userspace goes through `libuser`, which wraps each call by name, so
//! the wire numbers are a kernel-internal contract that we are free to choose
//! for clarity rather than binary compatibility with another OS. Keeping the
//! numbers dense and small keeps the table compact and the `lookup` index in
//! range.
//!
//! # Adding a syscall
//!
//! 1. Pick the next free number (or reuse a reserved slot) and add a `pub const`
//!    below plus an entry in the [`SyscallNumber`] enum.
//! 2. Write the handler in [`super::handlers`] as `pub fn sys_foo(ctx) -> i64`.
//! 3. Wire it into [`SYSCALLS`] at the matching index. If the index is past the
//!    current `NUM_SYSCALLS`, grow the array and the constant together.
//!
//! A `None` slot is the explicit "reserved / not yet wired" state; [`lookup`]
//! returns `None` for it and [`super::dispatch`] converts that into `-ENOSYS`.

use super::{Errno, SyscallFn};

// ---------------------------------------------------------------------------
// Syscall numbers
// ---------------------------------------------------------------------------

/// Xenith syscall numbers.
///
/// The constants below are the canonical numbers used by `libuser` and the
/// kernel table. They are kept in a single enum so a diagnostic dump or a
/// future `strace`-like tracer can map a number back to a name with one
/// `match`. The discriminants are explicit so reordering an arm never
/// silently shifts a number.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum SyscallNumber {
    /// `read(fd, buf, count)` — read from a file descriptor.
    Read = 0,
    /// `write(fd, buf, count)` — write to a file descriptor.
    Write = 1,
    /// `open(path, flags, mode)` — open a file.
    Open = 2,
    /// `close(fd)` — close a file descriptor.
    Close = 3,
    /// `exit(code)` — terminate the current process.
    Exit = 4,
    /// `brk(new)` — get/set the program break.
    Brk = 5,
    /// `mmap(addr, len, prot, flags, fd, off)` — map memory.
    Mmap = 6,
    /// `munmap(addr, len)` — unmap memory.
    Munmap = 7,
    /// `getpid()` — return the current process id.
    Getpid = 8,
    /// `getppid()` — return the parent process id.
    Getppid = 9,
    /// `yield()` — yield the CPU to the scheduler.
    Yield = 10,
    /// `nanosleep(req, rem)` — sleep for a duration.
    Nanosleep = 11,
    /// `fork()` — duplicate the current process.
    Fork = 12,
    /// `exec(path, argv, envp)` — replace the process image.
    Exec = 13,
    /// `waitpid(pid, status, options)` — wait for a child.
    Waitpid = 14,
    /// `uname(buf)` — return system identification.
    Uname = 15,
    /// `ioctl(fd, cmd, arg)` — device control.
    Ioctl = 16,
    /// `lseek(fd, offset, whence)` — reposition read/write offset.
    Lseek = 17,
    /// `stat(path, buf)` — get file status.
    Stat = 18,
    /// `dup(fd)` — duplicate a file descriptor.
    Dup = 19,
    /// `dup2(oldfd, newfd)` — duplicate a file descriptor to a target.
    Dup2 = 20,
    /// `pipe(fds)` — create a pipe.
    Pipe = 21,
    /// `chdir(path)` — change working directory.
    Chdir = 22,
    /// `getcwd(buf, size)` — get current working directory.
    Getcwd = 23,
    /// `mkdir(path, mode)` — create a directory.
    Mkdir = 24,
    /// `unlink(path)` — remove a directory entry.
    Unlink = 25,
    /// `read_dir(path, entries, capacity)` — enumerate a directory.
    ReadDir = 26,
    /// `clock_gettime(out)` — read Xenith wall time.
    ClockGettime = 27,
    /// `spawn(path, argv, envp, _, group)` — create and atomically group a child.
    Spawn = 28,
    Socket = 29,
    Bind = 30,
    Listen = 31,
    Accept = 32,
    Connect = 33,
    Send = 34,
    Recv = 35,
    NetInfo = 36,
    Kill = 37,
    MountRamfs = 38,
    Unmount = 39,
    Symlink = 40,
    Chmod = 41,
    Chown = 42,
    Utimens = 43,
    Rmdir = 44,
    Setpgid = 45,
    Getpgrp = 46,
    Setsid = 47,
    OpenPty = 48,
    Sigreturn = 49,
    Sigaction = 50,
    Sigprocmask = 51,
    GetRandom = 52,
    Sigaltstack = 53,
}

/// `read` — read up to `count` bytes from `fd` into `buf`.
pub const SYS_READ: u64 = SyscallNumber::Read as u64;
/// `write` — write up to `count` bytes from `buf` to `fd`.
pub const SYS_WRITE: u64 = SyscallNumber::Write as u64;
/// `open` — open the file at `path` with `flags` and `mode`.
pub const SYS_OPEN: u64 = SyscallNumber::Open as u64;
/// `close` — close the file descriptor `fd`.
pub const SYS_CLOSE: u64 = SyscallNumber::Close as u64;
/// `exit` — terminate the calling process with `code`.
pub const SYS_EXIT: u64 = SyscallNumber::Exit as u64;
/// `brk` — get or set the program break.
pub const SYS_BRK: u64 = SyscallNumber::Brk as u64;
/// `mmap` — map `len` bytes of memory.
pub const SYS_MMAP: u64 = SyscallNumber::Mmap as u64;
/// `munmap` — unmap a previously mapped region.
pub const SYS_MUNMAP: u64 = SyscallNumber::Munmap as u64;
/// `getpid` — return the caller's process id.
pub const SYS_GETPID: u64 = SyscallNumber::Getpid as u64;
/// `getppid` — return the caller's parent process id.
pub const SYS_GETPPID: u64 = SyscallNumber::Getppid as u64;
/// `yield` — voluntarily yield the CPU.
pub const SYS_YIELD: u64 = SyscallNumber::Yield as u64;
/// `nanosleep` — sleep for a duration expressed in nanoseconds.
pub const SYS_NANOSLEEP: u64 = SyscallNumber::Nanosleep as u64;
/// `fork` — create a child process as a duplicate of the caller.
pub const SYS_FORK: u64 = SyscallNumber::Fork as u64;
/// `exec` — replace the caller's image with a new executable.
pub const SYS_EXEC: u64 = SyscallNumber::Exec as u64;
/// `waitpid` — wait for a child process to change state.
pub const SYS_WAITPID: u64 = SyscallNumber::Waitpid as u64;
/// `uname` — fill a `utsname` struct with system identification.
pub const SYS_UNAME: u64 = SyscallNumber::Uname as u64;
/// `ioctl` — perform a device-specific control operation.
pub const SYS_IOCTL: u64 = SyscallNumber::Ioctl as u64;
/// `lseek` — reposition the file offset of `fd`.
pub const SYS_LSEEK: u64 = SyscallNumber::Lseek as u64;
/// `stat` — fill a `stat` struct for the file at `path`.
pub const SYS_STAT: u64 = SyscallNumber::Stat as u64;
/// `dup` — duplicate `fd` and return the lowest free descriptor.
pub const SYS_DUP: u64 = SyscallNumber::Dup as u64;
/// `dup2` — duplicate `oldfd` onto `newfd`.
pub const SYS_DUP2: u64 = SyscallNumber::Dup2 as u64;
/// `pipe` — create a pipe and return its read/write descriptors.
pub const SYS_PIPE: u64 = SyscallNumber::Pipe as u64;
/// `chdir` — change the caller's working directory.
pub const SYS_CHDIR: u64 = SyscallNumber::Chdir as u64;
/// `getcwd` — copy the caller's working directory into `buf`.
pub const SYS_GETCWD: u64 = SyscallNumber::Getcwd as u64;
pub const SYS_MKDIR: u64 = SyscallNumber::Mkdir as u64;
pub const SYS_UNLINK: u64 = SyscallNumber::Unlink as u64;
pub const SYS_READ_DIR: u64 = SyscallNumber::ReadDir as u64;
pub const SYS_CLOCK_GETTIME: u64 = SyscallNumber::ClockGettime as u64;
pub const SYS_SPAWN: u64 = SyscallNumber::Spawn as u64;
pub const SYS_SOCKET: u64 = SyscallNumber::Socket as u64;
pub const SYS_BIND: u64 = SyscallNumber::Bind as u64;
pub const SYS_LISTEN: u64 = SyscallNumber::Listen as u64;
pub const SYS_ACCEPT: u64 = SyscallNumber::Accept as u64;
pub const SYS_CONNECT: u64 = SyscallNumber::Connect as u64;
pub const SYS_SEND: u64 = SyscallNumber::Send as u64;
pub const SYS_RECV: u64 = SyscallNumber::Recv as u64;
pub const SYS_NET_INFO: u64 = SyscallNumber::NetInfo as u64;
pub const SYS_KILL: u64 = SyscallNumber::Kill as u64;
pub const SYS_MOUNT_RAMFS: u64 = SyscallNumber::MountRamfs as u64;
pub const SYS_UNMOUNT: u64 = SyscallNumber::Unmount as u64;
pub const SYS_SYMLINK: u64 = SyscallNumber::Symlink as u64;
pub const SYS_CHMOD: u64 = SyscallNumber::Chmod as u64;
pub const SYS_CHOWN: u64 = SyscallNumber::Chown as u64;
pub const SYS_UTIMENS: u64 = SyscallNumber::Utimens as u64;
pub const SYS_RMDIR: u64 = SyscallNumber::Rmdir as u64;
pub const SYS_SETPGID: u64 = SyscallNumber::Setpgid as u64;
pub const SYS_GETPGRP: u64 = SyscallNumber::Getpgrp as u64;
pub const SYS_SETSID: u64 = SyscallNumber::Setsid as u64;
pub const SYS_OPEN_PTY: u64 = SyscallNumber::OpenPty as u64;
pub const SYS_SIGRETURN: u64 = SyscallNumber::Sigreturn as u64;
pub const SYS_SIGACTION: u64 = SyscallNumber::Sigaction as u64;
pub const SYS_SIGPROCMASK: u64 = SyscallNumber::Sigprocmask as u64;
pub const SYS_GETRANDOM: u64 = SyscallNumber::GetRandom as u64;
pub const SYS_SIGALTSTACK: u64 = SyscallNumber::Sigaltstack as u64;

/// The number of slots in the [`SYSCALLS`] table.
///
/// This is one past the highest assigned syscall number so that every assigned
/// number is a valid in-bounds index. Growing the table means bumping this and
/// extending the array initialiser in lockstep.
pub const NUM_SYSCALLS: usize = 54;

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

/// The syscall dispatch table.
///
/// Slot *n* holds `Some(handler)` for syscall number *n*, or `None` if the
/// number is reserved or unimplemented. The array is `const` and lives in
/// read-only data; [`lookup`] is a bounds-checked indexed load, so dispatch
/// is a single memory access with no branching beyond the bounds check.
///
/// Every entry is a plain `fn` pointer (not a closure) so the table is
/// `'static` and needs no allocator. Handlers are defined in
/// [`super::handlers`] and referenced here by name.
pub static SYSCALLS: [Option<SyscallFn>; NUM_SYSCALLS] = [
    Some(super::handlers::sys_read),          // 0  read
    Some(super::handlers::sys_write),         // 1  write
    Some(super::handlers::sys_open),          // 2  open
    Some(super::handlers::sys_close),         // 3  close
    Some(super::handlers::sys_exit),          // 4  exit
    Some(super::handlers::sys_brk),           // 5  brk
    Some(super::handlers::sys_mmap),          // 6  mmap
    Some(super::handlers::sys_munmap),        // 7  munmap
    Some(super::handlers::sys_getpid),        // 8  getpid
    Some(super::handlers::sys_getppid),       // 9  getppid
    Some(super::handlers::sys_yield),         // 10 yield
    Some(super::handlers::sys_nanosleep),     // 11 nanosleep
    Some(super::handlers::sys_fork),          // 12 fork
    Some(super::handlers::sys_exec),          // 13 exec
    Some(super::handlers::sys_waitpid),       // 14 waitpid
    Some(super::handlers::sys_uname),         // 15 uname
    Some(super::handlers::sys_ioctl),         // 16 ioctl
    Some(super::handlers::sys_lseek),         // 17 lseek
    Some(super::handlers::sys_stat),          // 18 stat
    Some(super::handlers::sys_dup),           // 19 dup
    Some(super::handlers::sys_dup2),          // 20 dup2
    Some(super::handlers::sys_pipe),          // 21 pipe
    Some(super::handlers::sys_chdir),         // 22 chdir
    Some(super::handlers::sys_getcwd),        // 23 getcwd
    Some(super::handlers::sys_mkdir),         // 24 mkdir
    Some(super::handlers::sys_unlink),        // 25 unlink
    Some(super::handlers::sys_read_dir),      // 26 read_dir
    Some(super::handlers::sys_clock_gettime), // 27 clock_gettime
    Some(super::handlers::sys_spawn),         // 28 spawn
    Some(super::handlers::sys_socket),        // 29 socket
    Some(super::handlers::sys_bind),          // 30 bind
    Some(super::handlers::sys_listen),        // 31 listen
    Some(super::handlers::sys_accept),        // 32 accept
    Some(super::handlers::sys_connect),       // 33 connect
    Some(super::handlers::sys_send),          // 34 send
    Some(super::handlers::sys_recv),          // 35 recv
    Some(super::handlers::sys_net_info),      // 36 net_info
    Some(super::handlers::sys_kill),          // 37 kill
    Some(super::handlers::sys_mount_ramfs),   // 38 mount_ramfs
    Some(super::handlers::sys_unmount),       // 39 unmount
    Some(super::handlers::sys_symlink),       // 40 symlink
    Some(super::handlers::sys_chmod),         // 41 chmod
    Some(super::handlers::sys_chown),         // 42 chown
    Some(super::handlers::sys_utimens),       // 43 utimens
    Some(super::handlers::sys_rmdir),         // 44 rmdir
    Some(super::handlers::sys_setpgid),       // 45 setpgid
    Some(super::handlers::sys_getpgrp),       // 46 getpgrp
    Some(super::handlers::sys_setsid),        // 47 setsid
    Some(super::handlers::sys_open_pty),      // 48 openpty
    Some(super::handlers::sys_sigreturn),     // 49 sigreturn (live-frame entry special-case)
    Some(super::handlers::sys_sigaction),     // 50 sigaction
    Some(super::handlers::sys_sigprocmask),   // 51 sigprocmask
    Some(crate::devices::rng::sys_getrandom), // 52 getrandom
    Some(super::handlers::sys_sigaltstack),   // 53 sigaltstack
];

/// Look up the handler for syscall number `num`.
///
/// Returns `None` for out-of-range numbers and for in-range but unimplemented
/// (`None`) slots. [`super::dispatch`] turns a `None` into `-ENOSYS` so
/// userspace sees a consistent "not implemented" failure for any number the
/// kernel does not know about.
#[inline]
#[must_use]
pub fn lookup(num: u64) -> Option<SyscallFn> {
    let idx = usize::try_from(num).ok()?;
    // `get` performs the bounds check; for an out-of-range number it returns
    // `None`, which is the same result as an unimplemented in-range slot, so
    // callers do not need to distinguish the two cases.
    SYSCALLS.get(idx).copied().flatten()
}

/// Map a syscall number back to its name, for diagnostics.
///
/// Returns `"unknown"` for numbers outside the table or slots that are
/// present but not in the [`SyscallNumber`] enum (which, today, is every
/// implemented number — the enum covers the whole table). This is intended
/// for `strace`-style logging and panic dumps; it is not on the hot path.
#[must_use]
pub fn name_for(num: u64) -> &'static str {
    match num {
        SYS_READ => "read",
        SYS_WRITE => "write",
        SYS_OPEN => "open",
        SYS_CLOSE => "close",
        SYS_EXIT => "exit",
        SYS_BRK => "brk",
        SYS_MMAP => "mmap",
        SYS_MUNMAP => "munmap",
        SYS_GETPID => "getpid",
        SYS_GETPPID => "getppid",
        SYS_YIELD => "yield",
        SYS_NANOSLEEP => "nanosleep",
        SYS_FORK => "fork",
        SYS_EXEC => "exec",
        SYS_WAITPID => "waitpid",
        SYS_UNAME => "uname",
        SYS_IOCTL => "ioctl",
        SYS_LSEEK => "lseek",
        SYS_STAT => "stat",
        SYS_DUP => "dup",
        SYS_DUP2 => "dup2",
        SYS_PIPE => "pipe",
        SYS_CHDIR => "chdir",
        SYS_GETCWD => "getcwd",
        SYS_MKDIR => "mkdir",
        SYS_UNLINK => "unlink",
        SYS_READ_DIR => "read_dir",
        SYS_CLOCK_GETTIME => "clock_gettime",
        SYS_SPAWN => "spawn",
        SYS_SOCKET => "socket",
        SYS_BIND => "bind",
        SYS_LISTEN => "listen",
        SYS_ACCEPT => "accept",
        SYS_CONNECT => "connect",
        SYS_SEND => "send",
        SYS_RECV => "recv",
        SYS_NET_INFO => "net_info",
        SYS_KILL => "kill",
        SYS_MOUNT_RAMFS => "mount_ramfs",
        SYS_UNMOUNT => "unmount",
        SYS_SYMLINK => "symlink",
        SYS_CHMOD => "chmod",
        SYS_CHOWN => "chown",
        SYS_UTIMENS => "utimens",
        SYS_RMDIR => "rmdir",
        SYS_SETPGID => "setpgid",
        SYS_GETPGRP => "getpgrp",
        SYS_SETSID => "setsid",
        SYS_OPEN_PTY => "openpty",
        SYS_SIGRETURN => "sigreturn",
        SYS_SIGACTION => "sigaction",
        SYS_SIGPROCMASK => "sigprocmask",
        SYS_GETRANDOM => "getrandom",
        SYS_SIGALTSTACK => "sigaltstack",
        _ => "unknown",
    }
}

// A compile-time assertion that the table size matches the highest number.
// If a future edit adds a syscall past `NUM_SYSCALLS` without growing the
// constant, this const-evaluates an out-of-bounds array access and fails the
// build. The `assert` is a no-op at runtime; it exists purely to trip the
// compiler.
const _TABLE_SIZE_ASSERT: () = {
    const fn max_assigned() -> usize {
        let n = SYS_SIGALTSTACK as usize;
        // The table must be at least `n + 1` long so index `n` is in bounds.
        n + 1
    }
    assert!(NUM_SYSCALLS >= max_assigned());
};

// Keep `Errno` referenced so a future tighter linkage (e.g. a per-syscall
// capability table keyed on Errno) does not trip an unused-import warning at
// this module. The binding is zero-cost.
const _ERRNO_LINK: () = {
    let _ = Errno::Enosys.as_ret();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_coreutils_syscalls_are_dense_and_named() {
        assert_eq!(NUM_SYSCALLS, SYS_SIGALTSTACK as usize + 1);
        for (number, name) in [
            (SYS_KILL, "kill"),
            (SYS_MOUNT_RAMFS, "mount_ramfs"),
            (SYS_UNMOUNT, "unmount"),
            (SYS_SYMLINK, "symlink"),
            (SYS_CHMOD, "chmod"),
            (SYS_CHOWN, "chown"),
            (SYS_UTIMENS, "utimens"),
            (SYS_RMDIR, "rmdir"),
            (SYS_SETPGID, "setpgid"),
            (SYS_GETPGRP, "getpgrp"),
            (SYS_SETSID, "setsid"),
            (SYS_OPEN_PTY, "openpty"),
            (SYS_SIGRETURN, "sigreturn"),
            (SYS_SIGACTION, "sigaction"),
            (SYS_SIGPROCMASK, "sigprocmask"),
            (SYS_GETRANDOM, "getrandom"),
            (SYS_SIGALTSTACK, "sigaltstack"),
        ] {
            assert!(lookup(number).is_some());
            assert_eq!(name_for(number), name);
        }
    }
}
