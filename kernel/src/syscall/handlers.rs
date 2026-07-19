//! Syscall handlers: one function per syscall number.
//!
//! Each `sys_<name>` function here has the signature [`super::SyscallFn`]: it
//! takes a [`super::SyscallContext`] (the saved argument register file) and
//! returns an `i64` — non-negative on success, `-errno` on failure (see
//! [`super::Errno::as_ret`]). The table in [`super::table`] wires each syscall
//! number to its handler by name; this module is the implementation side of
//! that wiring.
//!
//! # Argument convention
//!
//! Arguments come in as raw `u64` values in `ctx.args[0..6]`, already mapped
//! from the x86_64 syscall ABI (`RDI, RSI, RDX, R10, R8, R9`). Each handler
//! extracts the arguments it needs with [`SyscallContext::arg`] /
//! [`arg_i32`](SyscallContext::arg_i32) /
//! [`arg_isize`](SyscallContext::arg_isize) and interprets them per its POSIX
//! semantics. Pointer arguments are validated through the
//! [user-memory helpers](self::user_ptr) before being dereferenced, so a
//! userspace program that passes a kernel address or an unmapped pointer gets
//! `-EFAULT` instead of corrupting kernel state.
//!
//! # What is real vs stub
//!
//! The handlers that have a real backing subsystem today are fully
//! implemented:
//!
//! * [`sys_write`] — writes to stdout/stderr (fd 1/2) through the kernel
//!   [`console`], and to any open file through the fd table.
//! * [`sys_exit`] — terminates the current task via the scheduler.
//! * [`sys_getpid`] / [`sys_getppid`] — return the current task's id (and a
//!   placeholder parent until the process tree lands).
//! * [`sys_yield`] — delegates to [`sched::yield_now`].
//! * [`sys_nanosleep`] — sleeps via [`sched::sleep_until`] against the
//!   monotonic clock.
//! * [`sys_uname`] — fills a `utsname` with static system identification.
//!
//! Handlers whose backing subsystem has not landed yet (the VFS, the user
//! allocator, the process tree) are thin local stubs that either return
//! `-ENOSYS` or implement the minimum that keeps `libuser` usable. Each stub
//! names the future replacement in a single-line comment so the wiring point
//! is greppable when the real module arrives.
//!
//! # The file-descriptor table
//!
//! There is no `Process` struct in tree yet (`user::process` is a sibling
//! phase), so the per-process file-descriptor table lives here as a thin
//! global stub: [`FD_TABLE`] is a fixed-size array of [`Option<FileHandle>`]
//! guarded by a [`SpinLock`]. Descriptors 0, 1, and 2 are pre-installed as
//! stdin/stdout/stderr backed by the kernel console. When `user::process`
//! lands, this table moves onto the `Process` struct verbatim and the global
//! is removed; the handler call sites do not change because they already go
//! through [`with_fd_table`].

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{Errno, SyscallContext};
use crate::sched;
use crate::sync::SpinLock;
use crate::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// User-memory access helpers
// ---------------------------------------------------------------------------

/// The highest virtual address a user-space mapping may use.
///
/// Re-exported here from `mm::r#virtual` so the pointer-validation helpers do
/// not depend on the full paging module; the constant is all we need to reject
/// kernel-pointer arguments. Any pointer argument whose value exceeds this is
/// in the kernel higher half and must not be dereferenced on behalf of
/// userspace — doing so would let a process read or write kernel memory.
const USER_MAX: u64 = crate::mm::r#virtual::USER_MAX;

/// Validate that `ptr` is a plausible user-space pointer.
///
/// Returns `Ok(())` if `ptr` is non-null and lies at or below [`USER_MAX`],
/// placing it in the canonical low half where user mappings live. A null
/// pointer or a kernel-high-half address yields [`Errno::Efault`]. The copy
/// helpers additionally walk the active page tables before dereferencing it.
fn check_user_ptr(ptr: u64) -> Result<(), Errno> {
    if ptr == 0 {
        return Err(Errno::Efault);
    }
    if ptr > USER_MAX {
        return Err(Errno::Efault);
    }
    Ok(())
}

/// Validate a user buffer of `len` bytes starting at `ptr`.
///
/// Checks both the start address and the inclusive last byte against
/// [`USER_MAX`]. A buffer that straddles the user/kernel boundary is rejected
/// as [`Errno::Efault`] without incorrectly rejecting the final valid byte.
fn check_user_buf(ptr: u64, len: u64) -> Result<(), Errno> {
    check_user_ptr(ptr)?;
    if len == 0 {
        return Ok(());
    }
    let Some(last) = ptr.checked_add(len - 1) else {
        return Err(Errno::Efault);
    };
    if last > USER_MAX {
        return Err(Errno::Efault);
    }
    Ok(())
}

/// Copy `len` bytes from user memory at `src` into a kernel buffer `dst`.
///
/// Both addresses are validated first: `src` must be in the user range, and
/// `len` must not exceed `dst.len()`. The architecture copy loop has a page-
/// fault fixup, so a fault during the final memory access also becomes
/// `-EFAULT` instead of a kernel panic.
fn copy_from_user(src: u64, dst: &mut [u8], len: usize) -> Result<usize, Errno> {
    let len = len.min(dst.len());
    if len == 0 {
        return Ok(0);
    }
    check_user_buf(src, len as u64)?;
    if crate::arch::x86_64::usercopy::copy_from_user_slice(&mut dst[..len], src) {
        Ok(len)
    } else {
        Err(Errno::Efault)
    }
}

/// Copy `len` bytes from a kernel buffer `src` into user memory at `dst`.
///
/// The dual of [`copy_from_user`]: validates `dst` is writable in the user
/// range, then enters the same fault-recoverable architecture copy path.
fn copy_to_user(dst: u64, src: &[u8], len: usize) -> Result<usize, Errno> {
    let len = len.min(src.len());
    if len == 0 {
        return Ok(0);
    }
    check_user_buf(dst, len as u64)?;
    if crate::arch::x86_64::usercopy::copy_to_user_slice(dst, &src[..len]) {
        Ok(len)
    } else {
        Err(Errno::Efault)
    }
}

// ---------------------------------------------------------------------------
// File-descriptor table (thin stub — moves to user::process when it lands)
// ---------------------------------------------------------------------------

/// The maximum number of open file descriptors per process.
///
/// Matches the conventional `RLIMIT_NOFILE` soft limit on a stock Linux
/// process; generous enough for `init`/`shell` and small enough that the
/// fixed array is cheap. When this moves onto `Process` the constant travels
/// with it.
/// The standard-input file descriptor number, matching POSIX.
pub const STDIN_FD: i32 = 0;
/// The standard-output file descriptor number, matching POSIX.
pub const STDOUT_FD: i32 = 1;
/// The standard-error file descriptor number, matching POSIX.
pub const STDERR_FD: i32 = 2;

const SOCKET_FD_BASE: i32 = 0x4000;
const MAX_SOCKET_FDS: usize = 256;

struct SocketFdTable {
    slots: [Option<crate::net::socket::SocketHandle>; MAX_SOCKET_FDS],
}

impl SocketFdTable {
    const fn new() -> Self {
        Self {
            slots: [const { None }; MAX_SOCKET_FDS],
        }
    }

    fn allocate(&mut self, handle: crate::net::socket::SocketHandle) -> Result<i32, Errno> {
        let Some((index, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
        else {
            return Err(Errno::Emfile);
        };
        *slot = Some(handle);
        Ok(SOCKET_FD_BASE + index as i32)
    }

    fn get(&self, fd: i32) -> Result<crate::net::socket::SocketHandle, Errno> {
        let index = fd
            .checked_sub(SOCKET_FD_BASE)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|index| *index < MAX_SOCKET_FDS)
            .ok_or(Errno::Enotsock)?;
        self.slots[index].ok_or(Errno::Enotsock)
    }

    fn take(&mut self, fd: i32) -> Result<crate::net::socket::SocketHandle, Errno> {
        let index = fd
            .checked_sub(SOCKET_FD_BASE)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|index| *index < MAX_SOCKET_FDS)
            .ok_or(Errno::Enotsock)?;
        self.slots[index].take().ok_or(Errno::Enotsock)
    }
}

static SOCKET_FDS: SpinLock<SocketFdTable> = SpinLock::new(SocketFdTable::new());

fn socket_handle(fd: i32) -> Result<crate::net::socket::SocketHandle, Errno> {
    SOCKET_FDS.lock().get(fd)
}

fn read_socket_address(pointer: u64, length: usize) -> Result<crate::net::socket::Endpoint, Errno> {
    if length != core::mem::size_of::<xenith_abi::SockAddrV4>() {
        return Err(Errno::Einval);
    }
    let mut bytes = [0u8; core::mem::size_of::<xenith_abi::SockAddrV4>()];
    let byte_count = bytes.len();
    copy_from_user(pointer, &mut bytes, byte_count)?;
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    if family != xenith_abi::AF_INET as u16 {
        return Err(Errno::Eafnosupport);
    }
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    Ok(crate::net::socket::Endpoint::new(
        crate::net::ip::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]),
        port,
    ))
}

fn write_socket_address(
    pointer: u64,
    length: usize,
    endpoint: crate::net::socket::Endpoint,
) -> Result<(), Errno> {
    if pointer == 0 && length == 0 {
        return Ok(());
    }
    if length != core::mem::size_of::<xenith_abi::SockAddrV4>() {
        return Err(Errno::Einval);
    }
    let mut bytes = [0u8; core::mem::size_of::<xenith_abi::SockAddrV4>()];
    bytes[..2].copy_from_slice(&(xenith_abi::AF_INET as u16).to_ne_bytes());
    bytes[2..4].copy_from_slice(&endpoint.port.to_be_bytes());
    bytes[4..8].copy_from_slice(&endpoint.address.octets());
    copy_to_user(pointer, &bytes, bytes.len())?;
    Ok(())
}

fn socket_errno(error: crate::net::socket::SocketError) -> Errno {
    use crate::net::socket::SocketError;
    match error {
        SocketError::TableFull | SocketError::ReceiveQueueFull | SocketError::BacklogFull => {
            Errno::Enobufs
        },
        SocketError::InvalidHandle => Errno::Enotsock,
        SocketError::InvalidPort => Errno::Einval,
        SocketError::AddressInUse => Errno::Eaddrinuse,
        SocketError::NotBound => Errno::Eaddrnotavail,
        SocketError::NotConnected => Errno::Enotconn,
        SocketError::WrongProtocol => Errno::Eopnotsupp,
        SocketError::InvalidState => Errno::Einval,
        SocketError::WouldBlock => Errno::Eagain,
        SocketError::ConnectionReset => Errno::Econnreset,
        SocketError::AlreadyConnected => Errno::Eisconn,
        SocketError::ConnectionInProgress => Errno::Einprogress,
    }
}

fn net_errno(error: crate::net::NetError) -> Errno {
    use crate::net::{NetError, PacketError};
    match error {
        NetError::Packet(PacketError::Oversized | PacketError::BufferTooSmall) => Errno::Emsgsize,
        NetError::Packet(_) | NetError::LoopbackStalled => Errno::Eio,
        NetError::Socket(error) => socket_errno(error),
        NetError::Route(_) => Errno::Enetunreach,
        NetError::InterfaceNotFound => Errno::Enodev,
        NetError::AddressNotConfigured => Errno::Eaddrnotavail,
        NetError::NoRoute => Errno::Enetunreach,
        NetError::NeighborUnresolved(_) => Errno::Ehostunreach,
        NetError::NeighborProbeExhausted(_) => Errno::Ehostunreach,
        NetError::FragmentationUnsupported | NetError::UnsupportedProtocol => Errno::Eopnotsupp,
    }
}

fn driver_errno(error: crate::devices::net::DriverError) -> Errno {
    use crate::devices::net::DriverError;
    match error {
        DriverError::FrameTooLarge | DriverError::BufferTooSmall => Errno::Emsgsize,
        DriverError::WouldBlock | DriverError::NoPacket => Errno::Eagain,
        DriverError::DmaUnavailable | DriverError::DmaAddressTooHigh => Errno::Enobufs,
        DriverError::InvalidAdapter | DriverError::UnsupportedBar => Errno::Enodev,
        DriverError::ResetTimeout | DriverError::InvalidMac | DriverError::DeviceFault => {
            Errno::Eio
        },
    }
}

fn request_neighbor(destination: crate::net::ip::Ipv4Addr) -> Result<(), Errno> {
    let frame = crate::net::probe_neighbor_for_destination(destination, crate::time::uptime_ns())
        .map_err(net_errno)?;
    match frame {
        Some(frame) => crate::devices::net::transmit_outbound(&frame).map_err(driver_errno),
        None => Ok(()),
    }
}

fn prepare_socket_destination(
    destination: crate::net::ip::Ipv4Addr,
) -> Result<crate::net::ip::Ipv4Addr, Errno> {
    match crate::net::prepare_socket_egress(destination) {
        Ok(source) => Ok(source),
        Err(crate::net::NetError::NeighborUnresolved(_)) => {
            request_neighbor(destination)?;
            Err(Errno::Eagain)
        },
        Err(error) => Err(net_errno(error)),
    }
}

fn dispatch_socket_packet(
    packet: crate::net::socket::SocketTx,
) -> Result<crate::net::SocketDispatch, Errno> {
    let dispatch = crate::net::dispatch_socket_tx(packet).map_err(net_errno)?;
    if let crate::net::SocketDispatch::Network(frame) = &dispatch {
        crate::devices::net::transmit_outbound(frame).map_err(driver_errno)?;
    }
    Ok(dispatch)
}

// ---------------------------------------------------------------------------
// utsname — the struct filled by sys_uname
// ---------------------------------------------------------------------------

fn fill_abi_field(destination: &mut [u8; 65], value: &[u8]) {
    let length = value.len().min(destination.len() - 1);
    destination[..length].copy_from_slice(&value[..length]);
    destination[length..].fill(0);
}

// ---------------------------------------------------------------------------
// timespec — the struct read by sys_nanosleep
// ---------------------------------------------------------------------------

/// A POSIX `timespec`: seconds plus nanoseconds, both non-negative.
///
/// The kernel reads this from the user's `req` pointer to learn how long
/// `nanosleep` should sleep. The layout matches the C `struct timespec` on
/// x86_64 so `libuser` can pass it through verbatim.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Timespec {
    /// Seconds since the sleep's start.
    pub tv_sec: i64,
    /// Additional nanoseconds in `[0, 999_999_999]`.
    pub tv_nsec: i64,
}

impl Timespec {
    /// Convert this `timespec` to a kernel [`Duration`], or `None` if the
    /// nanoseconds field is out of range (POSIX mandates `-EINVAL` for that).
    fn to_duration(self) -> Option<Duration> {
        if self.tv_nsec < 0 || self.tv_nsec >= 1_000_000_000 {
            return None;
        }
        if self.tv_sec < 0 {
            // A negative seconds field means a sleep in the past; treat it as
            // a zero-length sleep (wake immediately) rather than erroring, so
            // `nanosleep(0, ...)` and `nanosleep(-1, ...)` both yield.
            return Some(Duration::from_nanos(0));
        }
        let secs = self.tv_sec as u64;
        let nanos = self.tv_nsec as u64;
        // Saturating add: a request larger than ~584 years degrades to
        // "forever", which the scheduler handles by sleeping past any
        // reasonable deadline and waking on the next tick.
        Some(Duration::from_secs(secs).saturating_add(Duration::from_nanos(nanos)))
    }
}

// ---------------------------------------------------------------------------
// Process-id helpers (thin stubs — real parent tracking lands with Process)
// ---------------------------------------------------------------------------

/// Return the current task's id as a process id, or `1` if there is no
/// current task.
///
/// The scheduler identifies the running task with a [`sched::task::TaskId`];
/// until `user::process` introduces a separate `Pid` space, the task id is
/// the pid. The fallback to `1` covers the very first boot path where `init`
/// runs before the scheduler has installed a current task — `1` is the
/// conventional `init` pid.
fn current_pid() -> i64 {
    crate::user::process::current_pid().as_u64() as i64
}

/// Return the parent process id of the current task, or `0` if unknown.
///
/// There is no parent-pointer on the task struct yet — the process tree
/// (`user::process`) is a sibling phase. Until it lands, `getppid` returns
/// `0` for the first process and `1` for any other, which is the conventional
/// "init's parent is the kernel, everyone else's parent is init" shape. The
/// real implementation will read `current_process.parent.pid`.
fn current_ppid() -> i64 {
    crate::user::process::current_ppid().as_u64() as i64
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `read(fd, buf, count)` — read up to `count` bytes from `fd` into `buf`.
///
/// Arguments: `args[0]` = fd, `args[1]` = buf pointer, `args[2]` = count.
///
/// Returns the number of bytes read on success, or `-errno` on failure.
/// Console stdin consumes decoded PS/2 key presses; other descriptors use
/// the VFS. A zero-count read is a successful no-op, matching POSIX.
pub fn sys_read(ctx: &SyscallContext) -> i64 {
    let fd = ctx.arg_i32(0);
    let buf = ctx.arg(1);
    let count = ctx.arg(2) as usize;

    if count == 0 {
        return 0;
    }
    if let Err(e) = check_user_buf(buf, count as u64) {
        return e.as_ret();
    }

    const CHUNK: usize = 4096;
    let mut scratch = [0u8; CHUNK];
    let requested = count.min(CHUNK);
    match crate::fs::syscalls::sys_read(fd, &mut scratch[..requested]) {
        Ok(read) => match copy_to_user(buf, &scratch[..read], read) {
            Ok(copied) => copied as i64,
            Err(error) => error.as_ret(),
        },
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// `write(fd, buf, count)` — write up to `count` bytes from `buf` to `fd`.
///
/// Arguments: `args[0]` = fd, `args[1]` = buf pointer, `args[2]` = count.
///
/// Returns the number of bytes written on success, or `-errno` on failure.
/// Writes to stdout or stderr (fd 1 or 2) go through both the display console
/// and COM1 via a stack-local copy, keeping user pointers outside either
/// device lock. Other descriptors use the VFS.
pub fn sys_write(ctx: &SyscallContext) -> i64 {
    let fd = ctx.arg_i32(0);
    let buf = ctx.arg(1);
    let count = ctx.arg(2) as usize;

    if count == 0 {
        return 0;
    }
    if let Err(e) = check_user_buf(buf, count as u64) {
        return e.as_ret();
    }

    {
        // Copy the user bytes into a stack scratch buffer in chunks so a
        // large write does not need a heap allocation and so the console
        // never dereferences the user pointer directly (which would keep
        // the user buffer aliased across the console lock).
        const CHUNK: usize = 256;
        let mut scratch = [0u8; CHUNK];
        let mut written = 0usize;
        let mut off = 0u64;
        while off < count as u64 {
            let n = (count as u64 - off).min(CHUNK as u64) as usize;
            match copy_from_user(buf + off, &mut scratch, n) {
                Ok(copied) => {
                    // `console::write_str` requires a `&str`; for bring-up
                    // we write each byte as a Latin-1 char so binary and
                    // non-UTF-8 output stays visible without panicking on
                    // invalid UTF-8. A future console path will take bytes
                    // directly.
                    match crate::fs::syscalls::sys_write(fd, &scratch[..copied]) {
                        Ok(actual) if actual == copied => {},
                        Ok(actual) => {
                            written += actual;
                            break;
                        },
                        Err(error) => {
                            let errno = Errno::from(error);
                            if errno == Errno::Epipe {
                                let pid = crate::user::process::current_pid();
                                if !pid.is_kernel() {
                                    let _ = crate::user::process::signal(
                                        pid,
                                        crate::user::signal::Signal::Pipe,
                                    );
                                }
                            }
                            return if written == 0 {
                                errno.as_ret()
                            } else {
                                written as i64
                            };
                        },
                    }
                    written += copied;
                    off += copied as u64;
                    if copied < n {
                        break; // short read from user — stop early
                    }
                },
                Err(e) => {
                    if written == 0 {
                        return e.as_ret();
                    }
                    break; // partial write; return what we got
                },
            }
        }
        written as i64
    }
}

/// `open(path, flags, mode)` — open a file.
///
/// Arguments: `args[0]` = path pointer, `args[1]` = flags, `args[2]` = mode.
///
/// Returns a non-negative file descriptor on success, or `-errno` on failure.
/// The VFS (`fs::vfs`) is a sibling phase; until it lands, `open` returns
/// `-ENOSYS` for any path. The handler still validates the path pointer so a
/// buggy or hostile caller gets `-EFAULT` rather than reaching the not-yet-
/// existent VFS with a kernel address.
pub fn sys_open(ctx: &SyscallContext) -> i64 {
    let path_ptr = ctx.arg(0);
    let path_len = ctx.arg(1) as usize;
    let flags = ctx.arg(2) as u32;
    let mode = ctx.arg(3) as u32;

    let mut path_buf = [0u8; 256];
    if path_len == 0 || path_len >= path_buf.len() {
        return Errno::Enametoolong.as_ret();
    }
    if let Err(error) = copy_from_user(path_ptr, &mut path_buf, path_len) {
        return error.as_ret();
    }
    let Ok(path) = core::str::from_utf8(&path_buf[..path_len]) else {
        return Errno::Einval.as_ret();
    };
    match crate::fs::syscalls::sys_open(path, flags, mode) {
        Ok(fd) => i64::from(fd),
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// `close(fd)` — close a file descriptor.
///
/// Arguments: `args[0]` = fd.
///
/// Returns `0` on success or `-errno` on failure. The fd table's `close`
/// method handles the slot clearing and the `EBADF` case for an unopen fd.
/// Closing a console fd is allowed and frees the slot, so a process that
/// closes stdout and then opens a file gets the lowest free fd (which will
/// be 1) — the conventional POSIX shell trick.
pub fn sys_close(ctx: &SyscallContext) -> i64 {
    let fd = ctx.arg_i32(0);
    if (SOCKET_FD_BASE..SOCKET_FD_BASE + MAX_SOCKET_FDS as i32).contains(&fd) {
        let handle = match SOCKET_FDS.lock().take(fd) {
            Ok(handle) => handle,
            Err(error) => return error.as_ret(),
        };
        let closing = match crate::net::socket::close(handle) {
            Ok(closing) => closing,
            Err(error) => return socket_errno(error).as_ret(),
        };
        if let Some(packet) = closing {
            let tracked = packet.clone();
            if let Err(error) = dispatch_socket_packet(packet) {
                let _ = crate::net::socket::discard(handle);
                return error.as_ret();
            }
            let now = crate::time::uptime_ns();
            if let Err(error) = crate::net::socket::track_transmission(handle, tracked, now) {
                let _ = crate::net::socket::discard(handle);
                return socket_errno(error).as_ret();
            }
            if let Err(error) = crate::net::socket::detach(handle, now) {
                let _ = crate::net::socket::discard(handle);
                return socket_errno(error).as_ret();
            }
        }
        return 0;
    }
    match crate::fs::syscalls::sys_close(fd) {
        Ok(()) => 0,
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// `exit(code)` — terminate the current process.
///
/// Arguments: `args[0]` = exit status code.
///
/// Does not return: the scheduler's exit path performs a context switch to
/// the next runnable task and never resumes this one. The `i64` return type
/// is a formality the table requires; the call diverges before the function
/// would return. We mark the unreachable tail with
/// [`core::hint::unreachable_unchecked`] after the diverging
/// [`sched::scheduler::exit`] so the compiler knows the fall-through is
/// unreachable without invoking UB on a real return.
pub fn sys_exit(ctx: &SyscallContext) -> i64 {
    let code = ctx.arg_i32(0);
    ::log::debug!(
        "syscall: exit({}) called by tid {}",
        code,
        sched::task::with_current(|t| t.id.as_u64()).unwrap_or(0)
    );
    crate::user::process::exit(code);
}

/// `brk(new)` — get or set the program break.
///
/// Arguments: `args[0]` = requested new break address, or `0` to query.
///
/// Returns the exact new (or current) break on success, or `-errno` on
/// failure. The process layer derives the initial value from the highest ELF
/// segment and owns the zero-filled page mappings required for growth.
pub fn sys_brk(ctx: &SyscallContext) -> i64 {
    let req = ctx.arg(0);
    if req > USER_MAX {
        return Errno::Efault.as_ret();
    }
    match crate::user::process::set_program_break(req) {
        Ok(value) => value as i64,
        Err(error) => vm_errno(error).as_ret(),
    }
}

/// `mmap(addr, len, prot, flags, fd, off)` — map memory.
///
/// Arguments: `args[0]` = addr, `args[1]` = len, `args[2]` = prot,
/// `args[3]` = flags, `args[4]` = fd, `args[5]` = offset.
///
/// Returns the mapped address on success, or `-errno` on failure. Xenith
/// deliberately supports the bounded `MAP_PRIVATE | MAP_ANONYMOUS` subset;
/// file, shared, and fixed mappings are rejected instead of silently
/// approximated. Mappings must be readable and obey W^X.
pub fn sys_mmap(ctx: &SyscallContext) -> i64 {
    let addr = ctx.arg(0);
    let len = ctx.arg(1);
    let prot = match u32::try_from(ctx.arg(2)) {
        Ok(value) => value,
        Err(_) => return Errno::Einval.as_ret(),
    };
    let flags = match u32::try_from(ctx.arg(3)) {
        Ok(value) => value,
        Err(_) => return Errno::Einval.as_ret(),
    };
    let fd = ctx.arg_i32(4);
    let offset = ctx.arg_isize(5);

    if len == 0 {
        return Errno::Einval.as_ret();
    }
    if addr > USER_MAX {
        return Errno::Efault.as_ret();
    }
    const KNOWN_PROT: u32 = xenith_abi::PROT_READ | xenith_abi::PROT_WRITE | xenith_abi::PROT_EXEC;
    if prot & !KNOWN_PROT != 0 {
        return Errno::Einval.as_ret();
    }
    if prot & xenith_abi::PROT_READ == 0 {
        // x86 cannot express execute-only or write-only user pages honestly.
        return Errno::Eopnotsupp.as_ret();
    }
    if prot & xenith_abi::PROT_WRITE != 0 && prot & xenith_abi::PROT_EXEC != 0 {
        return Errno::Eacces.as_ret();
    }
    let supported_flags = xenith_abi::MAP_PRIVATE | xenith_abi::MAP_ANONYMOUS;
    if flags != supported_flags || fd != -1 || offset != 0 {
        return Errno::Eopnotsupp.as_ret();
    }
    let protection = crate::user::process::VmProtection {
        writable: prot & xenith_abi::PROT_WRITE != 0,
        executable: prot & xenith_abi::PROT_EXEC != 0,
    };
    match crate::user::process::map_anonymous(addr, len, protection) {
        Ok(address) => address as i64,
        Err(error) => vm_errno(error).as_ret(),
    }
}

/// `munmap(addr, len)` — unmap a previously mapped region.
///
/// Arguments: `args[0]` = addr, `args[1]` = len.
///
/// Returns `0` on success or `-errno` on failure. Only pages wholly covered
/// by anonymous regions created by [`sys_mmap`] are eligible; ELF, stack,
/// signal trampoline, and program-break pages are protected by construction.
pub fn sys_munmap(ctx: &SyscallContext) -> i64 {
    let addr = ctx.arg(0);
    let len = ctx.arg(1);

    if len == 0 {
        return Errno::Einval.as_ret();
    }
    if addr > USER_MAX {
        return Errno::Efault.as_ret();
    }
    match crate::user::process::unmap_anonymous(addr, len) {
        Ok(()) => 0,
        Err(error) => vm_errno(error).as_ret(),
    }
}

fn vm_errno(error: crate::user::process::VmError) -> Errno {
    match error {
        crate::user::process::VmError::InvalidRange | crate::user::process::VmError::NotOwned => {
            Errno::Einval
        },
        crate::user::process::VmError::OutOfMemory
        | crate::user::process::VmError::AddressInUse => Errno::Enomem,
        crate::user::process::VmError::NoCurrentProcess => Errno::Esrch,
        crate::user::process::VmError::TableCorrupt => Errno::Eio,
    }
}

/// `getpid()` — return the current process id.
///
/// Arguments: none.
///
/// Returns the pid (always non-negative). See [`current_pid`] for the
/// task-id-to-pid mapping and the `1` fallback for the very first process.
pub fn sys_getpid(_ctx: &SyscallContext) -> i64 {
    current_pid()
}

/// `getppid()` — return the parent process id.
///
/// Arguments: none.
///
/// Returns the ppid. See [`current_ppid`] for the placeholder parent-tracking
/// that will be replaced by the real process tree in `user::process`.
pub fn sys_getppid(_ctx: &SyscallContext) -> i64 {
    current_ppid()
}

/// `yield()` — voluntarily yield the CPU to the scheduler.
///
/// Arguments: none.
///
/// Returns `0` on success. Delegates to [`sched::yield_now`], which moves the
/// current task to the back of its run-queue priority level and switches to
/// the next runnable task. If nothing else is runnable the call returns
/// immediately without a switch.
pub fn sys_yield(_ctx: &SyscallContext) -> i64 {
    sched::yield_now();
    0
}

/// `nanosleep(req, rem)` — sleep for a duration expressed in nanoseconds.
///
/// Arguments: `args[0]` = pointer to a `timespec` with the requested sleep,
/// `args[1]` = pointer to a `timespec` to receive the remaining time on
/// interruption (currently unused, since we do not interrupt sleeps).
///
/// Returns `0` on success or `-errno` on failure. The requested duration is
/// read from user memory, validated (nanoseconds in `[0, 999_999_999]`), and
/// converted to a [`Duration`]. A zero or past duration yields immediately
/// (the scheduler still switches out for one tick, matching the
/// [`sched::sleep_until`] contract). The sleep blocks the current task until
/// the monotonic clock reaches the computed deadline.
pub fn sys_nanosleep(ctx: &SyscallContext) -> i64 {
    let req_ptr = ctx.arg(0);
    let rem_ptr = ctx.arg(1);

    // Validate the full 16-byte `Timespec` range up front so a pointer near
    // the top of the user region cannot cause an out-of-bounds read on the
    // second field.
    if let Err(e) = check_user_buf(req_ptr, core::mem::size_of::<Timespec>() as u64) {
        return e.as_ret();
    }

    // Read the timespec from user memory. We read each field as a volatile
    // byte sequence to avoid alignment assumptions about the user pointer,
    // then assemble the struct from little-endian bytes.
    let mut req = Timespec::default();
    let req_arr = req_ptr as *const u8;
    // SAFETY: `req_ptr` is a validated user address and the full 16-byte
    // range was checked above. The `Timespec` layout is two i64s (16 bytes);
    // we read them as raw byte sequences and reassemble so a misaligned user
    // pointer does not trip an alignment fault.
    let tv_sec = unsafe {
        let mut bytes = [0u8; 8];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = core::ptr::read_volatile(req_arr.add(i));
        }
        i64::from_le_bytes(bytes)
    };
    let tv_nsec = unsafe {
        let mut bytes = [0u8; 8];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = core::ptr::read_volatile(req_arr.add(8 + i));
        }
        i64::from_le_bytes(bytes)
    };
    req.tv_sec = tv_sec;
    req.tv_nsec = tv_nsec;

    let dur = match req.to_duration() {
        Some(d) => d,
        None => return Errno::Einval.as_ret(),
    };

    if dur.is_zero() {
        // A zero sleep is a de-facto yield: it lets the scheduler dispatch
        // another runnable task and returns here on the next pick.
        sched::yield_now();
        return 0;
    }

    // Compute the wake deadline and sleep. `Instant::now` reads the monotonic
    // clock; the scheduler moves the current task to the sleep queue and
    // switches to the next runnable task. When the deadline elapses the
    // timer tick re-enqueues this task and it resumes here.
    let deadline = Instant::now() + dur;
    sched::sleep_until(deadline);

    // We do not currently interrupt sleeps, so the remaining-time pointer
    // (`rem`) is left untouched. A future signal-delivery path that
    // interrupts `nanosleep` with `-EINTR` will write the unslept duration
    // here.
    let _ = rem_ptr;
    0
}

/// `fork()` — duplicate the current process.
///
/// Arguments: none.
///
/// Returns the child's pid in the parent, `0` in the child, or `-errno` on
/// failure. The child receives an eager, isolated copy of every 4 KiB user
/// mapping, inherited descriptors/signal dispositions, and the exact saved
/// userspace register image with RAX changed to zero.
pub fn sys_fork(ctx: &SyscallContext) -> i64 {
    match crate::user::process::fork(ctx.fork_return_context()) {
        Ok(pid) => pid.as_u64().min(i64::MAX as u64) as i64,
        Err(error) => process_errno(error).as_ret(),
    }
}

/// `exec(path, argv, envp)` — replace the process image.
///
/// Arguments: `args[0]` = path pointer, `args[1]` = argv pointer, `args[2]`
/// = envp pointer.
///
/// Does not return on success; returns `-errno` on failure. The replacement
/// ELF is loaded transactionally before the current process record changes;
/// success preserves PID/tree identity, switches CR3 in place, reclaims the
/// old image, applies close-on-exec/signal rules, and enters the new ELF.
pub fn sys_exec(ctx: &SyscallContext) -> i64 {
    let _envp = ctx.arg(3);
    let (path, owned_arguments) =
        match process_request_from_user(ctx.arg(0), ctx.arg(1) as usize, ctx.arg(2)) {
            Ok(request) => request,
            Err(error) => return error.as_ret(),
        };
    let arguments: Vec<&str> = owned_arguments.iter().map(String::as_str).collect();
    match crate::user::process::exec(&path, &arguments) {
        // Success enters the replacement image and cannot return here.
        Ok(()) => unreachable!("successful exec returned to the old image"),
        Err(error) => process_errno(error).as_ret(),
    }
}

fn process_errno(error: crate::user::ProcessError) -> Errno {
    match error {
        crate::user::ProcessError::OutOfMemory
        | crate::user::ProcessError::AddressSpace(
            crate::mm::r#virtual::address_space::MapError::OutOfMemory,
        ) => Errno::Enomem,
        crate::user::ProcessError::InvalidPath | crate::user::ProcessError::InvalidArgument => {
            Errno::Einval
        },
        crate::user::ProcessError::TooManyArguments
        | crate::user::ProcessError::ArgumentListTooLong => Errno::E2big,
        crate::user::ProcessError::Filesystem(crate::fs::FsError::PermissionDenied) => {
            Errno::Eacces
        },
        crate::user::ProcessError::NoCurrentProcess
        | crate::user::ProcessError::NoSuchProcess(_) => Errno::Esrch,
        crate::user::ProcessError::PermissionDenied => Errno::Eperm,
        crate::user::ProcessError::NoChildren | crate::user::ProcessError::NotChild(_) => {
            Errno::Echild
        },
        _ => Errno::Enoent,
    }
}

fn process_request_from_user(
    path_pointer: u64,
    path_length: usize,
    argv: u64,
) -> Result<(String, Vec<String>), Errno> {
    let mut path_storage = [0u8; 256];
    let path = user_path(path_pointer, path_length, &mut path_storage)?.to_string();
    let mut owned_arguments = Vec::<String>::new();
    if argv != 0 {
        for index in 0..32usize {
            let mut pointer_bytes = [0u8; 8];
            copy_from_user(
                argv + (index * core::mem::size_of::<u64>()) as u64,
                &mut pointer_bytes,
                8,
            )?;
            let pointer = u64::from_ne_bytes(pointer_bytes);
            if pointer == 0 {
                break;
            }
            let mut storage = [0u8; 256];
            let mut length = 0usize;
            loop {
                if length == storage.len() - 1 {
                    return Err(Errno::Enametoolong);
                }
                copy_from_user(pointer + length as u64, &mut storage[length..], 1)?;
                if storage[length] == 0 {
                    break;
                }
                length += 1;
            }
            let text = core::str::from_utf8(&storage[..length]).map_err(|_| Errno::Einval)?;
            owned_arguments.push(text.to_string());
        }
    }
    if owned_arguments.is_empty() {
        owned_arguments.push(path.clone());
    }
    Ok((path, owned_arguments))
}

/// `waitpid(pid, status, options)` — wait for a child to change state.
///
/// Arguments: `args[0]` = pid to wait on (or `-1` for any child),
/// `args[1]` = pointer to receive the child's exit status, `args[2]` =
/// options.
///
/// Returns the reaped child's pid on success, `0` for a non-blocking `WNOHANG`
/// with no changed child, or `-errno` on failure. The process tree is a
/// sibling phase; until it lands, `waitpid` returns `-ENOSYS` after
/// validating the status pointer.
pub fn sys_waitpid(ctx: &SyscallContext) -> i64 {
    let raw_pid = ctx.arg_isize(0);
    let status_ptr = ctx.arg(1);
    let options = ctx.arg(2) as u32;

    if status_ptr != 0 {
        if let Err(e) = check_user_ptr(status_ptr) {
            return e.as_ret();
        }
    }
    let known_options = xenith_abi::WNOHANG | xenith_abi::WUNTRACED | xenith_abi::WCONTINUED;
    if options & !known_options != 0 {
        return Errno::Einval.as_ret();
    }
    let selected = if raw_pid == -1 {
        crate::user::WaitSelector::Any
    } else if raw_pid == 0 {
        crate::user::WaitSelector::CurrentGroup
    } else if raw_pid < -1 {
        let Some(group) = raw_pid
            .checked_neg()
            .and_then(|value| u64::try_from(value).ok())
        else {
            return Errno::Einval.as_ret();
        };
        crate::user::WaitSelector::Group(crate::user::ProcessId(group))
    } else {
        crate::user::WaitSelector::Process(crate::user::ProcessId(raw_pid as u64))
    };
    let include_stopped = options & xenith_abi::WUNTRACED != 0;
    let include_continued = options & xenith_abi::WCONTINUED != 0;
    let result = if options & xenith_abi::WNOHANG != 0 {
        crate::user::process::try_wait_selector(selected, include_stopped, include_continued)
    } else {
        crate::user::process::wait_selector(selected, include_stopped, include_continued).map(Some)
    };
    match result {
        Ok(None) => 0,
        Ok(Some(waited)) => {
            if status_ptr != 0 {
                let status: i32 = match waited.status {
                    crate::user::WaitStatus::Exited(crate::sched::ExitStatus::Pending) => 0,
                    crate::user::WaitStatus::Exited(crate::sched::ExitStatus::Code(code)) => {
                        (code as i32) << 8
                    },
                    crate::user::WaitStatus::Exited(crate::sched::ExitStatus::Signal(signal)) => {
                        signal & 0x7f
                    },
                    crate::user::WaitStatus::Stopped(signal) => {
                        ((signal.as_number() as i32) << 8) | 0x7f
                    },
                    crate::user::WaitStatus::Continued => 0xffff,
                };
                if let Err(error) = copy_to_user(status_ptr, &status.to_ne_bytes(), 4) {
                    return error.as_ret();
                }
            }
            waited.pid.as_u64() as i64
        },
        Err(error) => process_errno(error).as_ret(),
    }
}

/// `uname(buf)` — fill a `utsname` struct with system identification.
///
/// Arguments: `args[0]` = pointer to a user `utsname`.
///
/// Returns `0` on success or `-errno` on failure. The struct is built from
/// static Xenith identification (name, release, version, machine) and copied
/// to the user buffer with [`copy_to_user`]. This is fully implemented: no
/// backing subsystem is pending, only the static fields.
pub fn sys_uname(ctx: &SyscallContext) -> i64 {
    let buf = ctx.arg(0);
    if let Err(e) = check_user_ptr(buf) {
        return e.as_ret();
    }
    let uts_size = core::mem::size_of::<xenith_abi::UtsName>() as u64;
    if let Err(e) = check_user_buf(buf, uts_size) {
        return e.as_ret();
    }
    let mut uts = xenith_abi::UtsName::default();
    fill_abi_field(&mut uts.system, b"Xenith");
    fill_abi_field(&mut uts.node, b"xenith");
    fill_abi_field(&mut uts.release, b"0.1.0");
    fill_abi_field(&mut uts.version, b"Xenith bare-metal");
    fill_abi_field(&mut uts.machine, b"x86_64");
    // SAFETY: the shared ABI structure is `repr(C)` and contains only byte
    // arrays, so its complete object representation is initialized.
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &uts as *const xenith_abi::UtsName as *const u8,
            uts_size as usize,
        )
    };
    match copy_to_user(buf, bytes, bytes.len()) {
        Ok(_) => 0,
        Err(e) => e.as_ret(),
    }
}

/// `ioctl(fd, cmd, arg)` — device control.
///
/// Arguments: `args[0]` = fd, `args[1]` = cmd, `args[2]` = arg.
///
/// Returns `0` on success or `-errno` on failure. No device exposes ioctl
/// commands yet; the handler returns `-ENOTTY` for a valid fd (the
/// conventional "inappropriate ioctl for device") and `-EBADF` for an
/// unopen one. A future terminal / framebuffer ioctl set will dispatch on
/// `cmd` here.
pub fn sys_ioctl(ctx: &SyscallContext) -> i64 {
    let fd = ctx.arg_i32(0);
    let cmd = ctx.arg(1) as u32;
    let arg = ctx.arg(2);

    let file = match crate::fs::syscalls::get_file(fd) {
        Ok(file) => file,
        Err(error) => return Errno::from(error).as_ret(),
    };
    if cmd == xenith_abi::TIOCGPTN {
        let Some(number) = file.pty_number() else {
            return Errno::Enotty.as_ret();
        };
        let Ok(number) = u32::try_from(number) else {
            return Errno::Eio.as_ret();
        };
        let bytes = number.to_ne_bytes();
        return copy_to_user(arg, &bytes, bytes.len()).map_or_else(Errno::as_ret, |_| 0);
    }
    if !file.is_terminal() {
        return Errno::Enotty.as_ret();
    }

    match cmd {
        xenith_abi::TCGETS => {
            let Some(attributes) = file.terminal_attributes() else {
                return Errno::Enotty.as_ret();
            };
            // SAFETY: TerminalAttributes is repr(C) and fully initialized.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&attributes as *const xenith_abi::TerminalAttributes).cast::<u8>(),
                    core::mem::size_of::<xenith_abi::TerminalAttributes>(),
                )
            };
            copy_to_user(arg, bytes, bytes.len()).map_or_else(Errno::as_ret, |_| 0)
        },
        xenith_abi::TCSETS | xenith_abi::TCSETSW | xenith_abi::TCSETSF => {
            let mut attributes = xenith_abi::TerminalAttributes::default();
            let length = core::mem::size_of::<xenith_abi::TerminalAttributes>();
            // SAFETY: the initialized repr(C) object is writable for its full size.
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    (&mut attributes as *mut xenith_abi::TerminalAttributes).cast::<u8>(),
                    length,
                )
            };
            if let Err(error) = copy_from_user(arg, bytes, length) {
                return error.as_ret();
            }
            if file.set_terminal_attributes(attributes, cmd == xenith_abi::TCSETSF) {
                0
            } else {
                Errno::Enotty.as_ret()
            }
        },
        xenith_abi::TIOCGWINSZ => {
            let Some(window) = file.terminal_window_size() else {
                return Errno::Enotty.as_ret();
            };
            // SAFETY: WindowSize is repr(C) and fully initialized.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&window as *const xenith_abi::WindowSize).cast::<u8>(),
                    core::mem::size_of::<xenith_abi::WindowSize>(),
                )
            };
            copy_to_user(arg, bytes, bytes.len()).map_or_else(Errno::as_ret, |_| 0)
        },
        xenith_abi::TIOCSWINSZ => {
            let mut window = xenith_abi::WindowSize::default();
            let length = core::mem::size_of::<xenith_abi::WindowSize>();
            // SAFETY: the initialized repr(C) value is writable for its full size.
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    (&mut window as *mut xenith_abi::WindowSize).cast::<u8>(),
                    length,
                )
            };
            if let Err(error) = copy_from_user(arg, bytes, length) {
                return error.as_ret();
            }
            if file.set_terminal_window_size(window) {
                0
            } else {
                Errno::Enotty.as_ret()
            }
        },
        xenith_abi::FIONREAD => {
            let Some(pending) = file.terminal_pending_input() else {
                return Errno::Enotty.as_ret();
            };
            let pending = pending.min(i32::MAX as usize) as i32;
            let bytes = pending.to_ne_bytes();
            copy_to_user(arg, &bytes, bytes.len()).map_or_else(Errno::as_ret, |_| 0)
        },
        xenith_abi::TIOCGPGRP => {
            let Some(process_group) = file.terminal_foreground_group() else {
                return Errno::Enotty.as_ret();
            };
            let process_group = process_group.min(i64::MAX as u64) as i64;
            copy_to_user(arg, &process_group.to_ne_bytes(), 8).map_or_else(Errno::as_ret, |_| 0)
        },
        xenith_abi::TIOCSPGRP => {
            let mut bytes = [0u8; 8];
            if let Err(error) = copy_from_user(arg, &mut bytes, 8) {
                return error.as_ret();
            }
            let raw_group = i64::from_ne_bytes(bytes);
            if raw_group <= 0 {
                return Errno::Einval.as_ret();
            }
            let process_group = crate::user::ProcessId(raw_group as u64);
            if !crate::user::process::can_control_process_group(process_group) {
                return Errno::Eperm.as_ret();
            }
            if file.set_terminal_foreground_group(process_group.as_u64()) {
                0
            } else {
                Errno::Enotty.as_ret()
            }
        },
        _ => Errno::Enotty.as_ret(),
    }
}

/// `lseek(fd, offset, whence)` — reposition the file offset.
///
/// Arguments: `args[0]` = fd, `args[1]` = offset, `args[2]` = whence.
///
/// Returns the new offset on success or `-errno` on failure. The VFS
/// (`fs::vfs`) tracks per-file offsets; until it lands, `lseek` returns
/// `-ESPIPE` for the console (which is not seekable) and `-ENOSYS` for a
/// VFS-backed fd placeholder.
pub fn sys_lseek(ctx: &SyscallContext) -> i64 {
    let fd = ctx.arg_i32(0);
    let offset = ctx.arg_isize(1) as i64;
    let whence = ctx.arg_i32(2);
    match crate::fs::syscalls::sys_lseek(fd, offset, whence) {
        Ok(position) => position.min(i64::MAX as u64) as i64,
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// `stat(path, buf)` — get file status.
///
/// Arguments: `args[0]` = path pointer, `args[1]` = pointer to a `stat`
/// struct.
///
/// Returns `0` on success or `-errno` on failure. The VFS (`fs::vfs`) is a
/// sibling phase; until it lands, `stat` returns `-ENOSYS` after validating
/// both pointers.
pub fn sys_stat(ctx: &SyscallContext) -> i64 {
    let path_ptr = ctx.arg(0);
    let path_len = ctx.arg(1) as usize;
    let buf_ptr = ctx.arg(2);

    let mut path_buf = [0u8; 256];
    if path_len == 0 || path_len >= path_buf.len() {
        return Errno::Enametoolong.as_ret();
    }
    if let Err(error) = copy_from_user(path_ptr, &mut path_buf, path_len) {
        return error.as_ret();
    }
    let Ok(path) = core::str::from_utf8(&path_buf[..path_len]) else {
        return Errno::Einval.as_ret();
    };
    let metadata = match crate::fs::syscalls::sys_stat(path) {
        Ok(metadata) => metadata,
        Err(error) => return Errno::from(error).as_ret(),
    };
    let stat = xenith_abi::Stat {
        inode: metadata.st_ino,
        size: metadata.st_size.max(0) as u64,
        blocks: metadata.st_blocks.max(0) as u64,
        mode: metadata.st_mode,
        links: metadata.st_nlink,
        uid: metadata.st_uid,
        gid: metadata.st_gid,
        device: metadata.st_dev,
        modified_ns: metadata.st_mtime.max(0) as u64,
    };
    // SAFETY: Stat is `repr(C)` and every field above is initialized.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &stat as *const xenith_abi::Stat as *const u8,
            core::mem::size_of::<xenith_abi::Stat>(),
        )
    };
    match copy_to_user(buf_ptr, bytes, bytes.len()) {
        Ok(_) => 0,
        Err(error) => error.as_ret(),
    }
}

/// `dup(fd)` — duplicate a file descriptor.
///
/// Arguments: `args[0]` = fd.
///
/// Returns the lowest free fd that now refers to the same file, or `-errno`
/// on failure. The duplication is handled entirely within the fd table: we
/// read the handle, then allocate a new slot for a copy of it. The console
/// handle is `Copy`, so this is a cheap clone; a future VFS `File` will need
/// a refcount bump here.
pub fn sys_dup(ctx: &SyscallContext) -> i64 {
    let fd = ctx.arg_i32(0);
    match crate::fs::syscalls::sys_dup(fd) {
        Ok(new_fd) => i64::from(new_fd),
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// `dup2(oldfd, newfd)` — duplicate `oldfd` onto `newfd`.
///
/// Arguments: `args[0]` = oldfd, `args[1]` = newfd.
///
/// Returns `newfd` on success or `-errno` on failure. If `oldfd == newfd`
/// and `oldfd` is open, the call is a no-op that returns `newfd` (POSIX). If
/// `oldfd` is not open, returns `-EBADF`. If `newfd` is already open it is
/// silently closed first (matching POSIX `dup2`).
pub fn sys_dup2(ctx: &SyscallContext) -> i64 {
    let oldfd = ctx.arg_i32(0);
    let newfd = ctx.arg_i32(1);
    match crate::fs::syscalls::sys_dup2(oldfd, newfd) {
        Ok(fd) => i64::from(fd),
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// `pipe(fds)` — create a pipe.
///
/// Arguments: `args[0]` = pointer to a two-element `int` array to receive
/// the read and write descriptors.
///
/// Returns `0` on success or `-errno` on failure. A kernel pipe
/// implementation (a ring buffer with two fds) is a sibling phase; until it
/// lands, `pipe` returns `-ENOSYS` after validating the pointer.
pub fn sys_pipe(ctx: &SyscallContext) -> i64 {
    let fds_ptr = ctx.arg(0);
    if let Err(e) = check_user_buf(fds_ptr, 8) {
        return e.as_ret();
    }
    let (reader, writer) = match crate::fs::syscalls::sys_pipe() {
        Ok(descriptors) => descriptors,
        Err(error) => return Errno::from(error).as_ret(),
    };
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&reader.to_ne_bytes());
    bytes[4..].copy_from_slice(&writer.to_ne_bytes());
    match copy_to_user(fds_ptr, &bytes, bytes.len()) {
        Ok(_) => 0,
        Err(error) => {
            let _ = crate::fs::syscalls::sys_close(reader);
            let _ = crate::fs::syscalls::sys_close(writer);
            error.as_ret()
        },
    }
}

/// `openpty(fds)` — create a PTY master/slave descriptor pair.
///
/// The returned descriptor ABI remains compatible with the original anonymous
/// operation.  While its master is live, the slave is also reopenable through
/// the bounded devpts namespace at `/dev/pts/<number>`.
pub fn sys_open_pty(ctx: &SyscallContext) -> i64 {
    let destination = ctx.arg(0);
    if let Err(error) = check_user_buf(destination, core::mem::size_of::<[i32; 2]>() as u64) {
        return error.as_ret();
    }
    let (master, slave) = match crate::fs::syscalls::sys_open_pty() {
        Ok(pair) => pair,
        Err(error) => return Errno::from(error).as_ret(),
    };
    let descriptors = [master, slave];
    // SAFETY: `[i32; 2]` has no padding and every byte is initialized.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            descriptors.as_ptr().cast::<u8>(),
            core::mem::size_of::<[i32; 2]>(),
        )
    };
    if let Err(error) = copy_to_user(destination, bytes, bytes.len()) {
        let _ = crate::fs::syscalls::sys_close(master);
        let _ = crate::fs::syscalls::sys_close(slave);
        return error.as_ret();
    }
    0
}

/// `sigreturn()` is handled by the architecture entry path because restoring
/// it requires mutable access to the live syscall frame. Reaching this table
/// handler means dispatch was attempted without that frame.
pub fn sys_sigreturn(_ctx: &SyscallContext) -> i64 {
    Errno::Einval.as_ret()
}

fn encode_signal_action(action: crate::user::signal::SignalAction) -> [u8; 24] {
    let (handler, mask, flags) = match action {
        crate::user::signal::SignalAction::Default => (xenith_abi::SIG_DFL, 0, 0),
        crate::user::signal::SignalAction::Ignore => (xenith_abi::SIG_IGN, 0, 0),
        crate::user::signal::SignalAction::Catch { entry, mask, flags } => {
            (entry, mask.bits(), flags)
        },
    };
    let mut bytes = [0u8; 24];
    bytes[..8].copy_from_slice(&handler.to_ne_bytes());
    bytes[8..16].copy_from_slice(&mask.to_ne_bytes());
    bytes[16..].copy_from_slice(&flags.to_ne_bytes());
    bytes
}

fn decode_signal_action(bytes: &[u8; 24]) -> Result<crate::user::signal::SignalAction, Errno> {
    let handler = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
    let mask = u64::from_ne_bytes(bytes[8..16].try_into().unwrap());
    let flags = u64::from_ne_bytes(bytes[16..].try_into().unwrap());
    if flags & !xenith_abi::SA_SUPPORTED != 0 {
        return Err(Errno::Einval);
    }
    match handler {
        xenith_abi::SIG_DFL => Ok(crate::user::signal::SignalAction::Default),
        xenith_abi::SIG_IGN => Ok(crate::user::signal::SignalAction::Ignore),
        entry if entry <= USER_MAX => Ok(crate::user::signal::SignalAction::Catch {
            entry,
            mask: crate::user::signal::SignalMask::from_bits_sanitized(mask),
            flags,
        }),
        _ => Err(Errno::Einval),
    }
}

/// `sigaction(signal, action, old_action)` — install or query a disposition.
pub fn sys_sigaction(ctx: &SyscallContext) -> i64 {
    let number = ctx.arg(0);
    if number > u64::from(crate::user::signal::NSIG) {
        return Errno::Einval.as_ret();
    }
    let Some(signal) = crate::user::signal::Signal::from_number(number as u32) else {
        return Errno::Einval.as_ret();
    };

    let new_pointer = ctx.arg(1);
    let old_pointer = ctx.arg(2);
    let new_action = if new_pointer == 0 {
        None
    } else {
        let mut bytes = [0u8; 24];
        let length = bytes.len();
        if let Err(error) = copy_from_user(new_pointer, &mut bytes, length) {
            return error.as_ret();
        }
        match decode_signal_action(&bytes) {
            Ok(action) => Some(action),
            Err(error) => return error.as_ret(),
        }
    };

    let Some(previous) =
        crate::user::process::with_current_process(|process| process.signals.disposition(signal))
    else {
        return Errno::Esrch.as_ret();
    };
    if old_pointer != 0 {
        let bytes = encode_signal_action(previous);
        if let Err(error) = copy_to_user(old_pointer, &bytes, bytes.len()) {
            return error.as_ret();
        }
    }
    if let Some(action) = new_action {
        let installed = crate::user::process::with_current_process(|process| {
            process.signals.set_handler(signal, action)
        })
        .unwrap_or(false);
        if !installed {
            return Errno::Einval.as_ret();
        }
    }
    0
}

/// `sigprocmask(how, set, old_set)` — atomically update the blocked mask.
pub fn sys_sigprocmask(ctx: &SyscallContext) -> i64 {
    let how = ctx.arg(0) as u32;
    let set_pointer = ctx.arg(1);
    let old_pointer = ctx.arg(2);
    let requested = if set_pointer == 0 {
        None
    } else {
        if !matches!(
            how,
            xenith_abi::SIG_BLOCK | xenith_abi::SIG_UNBLOCK | xenith_abi::SIG_SETMASK
        ) {
            return Errno::Einval.as_ret();
        }
        let mut bytes = [0u8; 8];
        let length = bytes.len();
        if let Err(error) = copy_from_user(set_pointer, &mut bytes, length) {
            return error.as_ret();
        }
        Some(crate::user::signal::SignalMask::from_bits_sanitized(
            u64::from_ne_bytes(bytes),
        ))
    };

    let Some(previous) =
        crate::user::process::with_current_process(|process| process.signals.blocked_mask())
    else {
        return Errno::Esrch.as_ret();
    };
    if old_pointer != 0 {
        let bytes = previous.bits().to_ne_bytes();
        if let Err(error) = copy_to_user(old_pointer, &bytes, bytes.len()) {
            return error.as_ret();
        }
    }
    if let Some(requested) = requested {
        let next = match how {
            xenith_abi::SIG_BLOCK => previous.union(requested),
            xenith_abi::SIG_UNBLOCK => previous.without(requested),
            xenith_abi::SIG_SETMASK => requested,
            _ => unreachable!(),
        };
        if crate::user::process::with_current_process(|process| process.signals.set_blocked(next))
            .is_none()
        {
            return Errno::Esrch.as_ret();
        }
    }
    0
}

/// `chdir(path)` — change the calling process's working directory.
pub fn sys_chdir(ctx: &SyscallContext) -> i64 {
    let path_ptr = ctx.arg(0);
    let path_len = ctx.arg(1) as usize;
    let mut path_buf = [0u8; 256];
    if path_len == 0 || path_len >= path_buf.len() {
        return Errno::Enametoolong.as_ret();
    }
    if let Err(error) = copy_from_user(path_ptr, &mut path_buf, path_len) {
        return error.as_ret();
    }
    let Ok(path) = core::str::from_utf8(&path_buf[..path_len]) else {
        return Errno::Einval.as_ret();
    };
    match crate::fs::syscalls::sys_chdir(path) {
        Ok(()) => 0,
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// `getcwd(buf, size)` — copy the current working directory into `buf`.
///
/// Arguments: `args[0]` = buf pointer, `args[1]` = size.
///
/// Returns the address of `buf` on success or `-errno` on failure. Until the
/// per-process cwd lands, `getcwd` writes a single `/` (the conventional
/// root) into the buffer and returns `buf`. This lets a shell's prompt show
/// something sensible while the VFS is still pending.
pub fn sys_getcwd(ctx: &SyscallContext) -> i64 {
    let buf = ctx.arg(0);
    let size = ctx.arg(1) as usize;

    if let Err(e) = check_user_buf(buf, size as u64) {
        return e.as_ret();
    }
    let mut path = [0u8; 256];
    match crate::fs::syscalls::sys_getcwd(&mut path[..size.min(256)]) {
        Ok(length_with_nul) => match copy_to_user(buf, &path[..length_with_nul], length_with_nul) {
            Ok(_) => length_with_nul.saturating_sub(1) as i64,
            Err(error) => error.as_ret(),
        },
        Err(error) => Errno::from(error).as_ret(),
    }
}

fn user_path(pointer: u64, length: usize, storage: &mut [u8]) -> Result<&str, Errno> {
    if length == 0 || length >= storage.len() {
        return Err(Errno::Enametoolong);
    }
    copy_from_user(pointer, storage, length)?;
    core::str::from_utf8(&storage[..length]).map_err(|_| Errno::Einval)
}

/// Create a directory in the mounted VFS.
pub fn sys_mkdir(ctx: &SyscallContext) -> i64 {
    let mut storage = [0u8; 256];
    let path = match user_path(ctx.arg(0), ctx.arg(1) as usize, &mut storage) {
        Ok(path) => path,
        Err(error) => return error.as_ret(),
    };
    match crate::fs::syscalls::sys_mkdir(path, ctx.arg(2) as u32) {
        Ok(()) => 0,
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// Remove a non-root VFS entry.
pub fn sys_unlink(ctx: &SyscallContext) -> i64 {
    let mut storage = [0u8; 256];
    let path = match user_path(ctx.arg(0), ctx.arg(1) as usize, &mut storage) {
        Ok(path) => path,
        Err(error) => return error.as_ret(),
    };
    match crate::fs::syscalls::sys_unlink(path) {
        Ok(()) => 0,
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// Remove an empty directory without following the final symlink component.
pub fn sys_rmdir(ctx: &SyscallContext) -> i64 {
    let mut storage = [0u8; 256];
    let path = match user_path(ctx.arg(0), ctx.arg(1) as usize, &mut storage) {
        Ok(path) => path,
        Err(error) => return error.as_ret(),
    };
    match crate::fs::syscalls::sys_rmdir(path) {
        Ok(()) => 0,
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// Enumerate a directory into fixed-size shared-ABI records.
pub fn sys_read_dir(ctx: &SyscallContext) -> i64 {
    let mut storage = [0u8; 256];
    let path = match user_path(ctx.arg(0), ctx.arg(1) as usize, &mut storage) {
        Ok(path) => path,
        Err(error) => return error.as_ret(),
    };
    let output = ctx.arg(2);
    let capacity = ctx.arg(3) as usize;
    if capacity == 0 {
        return 0;
    }
    let record_size = core::mem::size_of::<xenith_abi::DirectoryEntry>();
    if let Err(error) = check_user_buf(
        output,
        capacity.saturating_mul(record_size).min(u64::MAX as usize) as u64,
    ) {
        return error.as_ret();
    }
    let entries = match crate::fs::vfs::read_dir(&crate::fs::Path::new(path)) {
        Ok(entries) => entries,
        Err(error) => return Errno::from(error).as_ret(),
    };
    let mut written = 0usize;
    for entry in entries.iter().take(capacity) {
        let mut wire = xenith_abi::DirectoryEntry {
            inode: entry.inode.get(),
            kind: match entry.kind {
                crate::fs::FileType::Regular => 1,
                crate::fs::FileType::Directory => 2,
                crate::fs::FileType::Symlink => 3,
                crate::fs::FileType::CharacterDevice => 4,
                crate::fs::FileType::BlockDevice => 5,
            },
            ..xenith_abi::DirectoryEntry::default()
        };
        let name = entry.name.as_bytes();
        let length = name.len().min(wire.name.len());
        wire.name[..length].copy_from_slice(&name[..length]);
        wire.name_len = length as u16;
        // SAFETY: DirectoryEntry is repr(C) and completely initialized.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &wire as *const xenith_abi::DirectoryEntry as *const u8,
                record_size,
            )
        };
        if let Err(error) =
            copy_to_user(output + (written * record_size) as u64, bytes, bytes.len())
        {
            return error.as_ret();
        }
        written += 1;
    }
    written as i64
}

/// Mount a fresh anonymous ramfs at an existing directory.
pub fn sys_mount_ramfs(ctx: &SyscallContext) -> i64 {
    let mut storage = [0u8; 256];
    let path = match user_path(ctx.arg(0), ctx.arg(1) as usize, &mut storage) {
        Ok(path) => path,
        Err(error) => return error.as_ret(),
    };
    match crate::fs::syscalls::sys_mount_ramfs(path) {
        Ok(()) => 0,
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// Unmount a non-root filesystem by mount point.
pub fn sys_unmount(ctx: &SyscallContext) -> i64 {
    let mut storage = [0u8; 256];
    let path = match user_path(ctx.arg(0), ctx.arg(1) as usize, &mut storage) {
        Ok(path) => path,
        Err(error) => return error.as_ret(),
    };
    match crate::fs::syscalls::sys_unmount(path) {
        Ok(()) => 0,
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// Create a symbolic link. Hard links intentionally remain unsupported.
pub fn sys_symlink(ctx: &SyscallContext) -> i64 {
    let mut target_storage = [0u8; 256];
    let target = match user_path(ctx.arg(0), ctx.arg(1) as usize, &mut target_storage) {
        Ok(path) => path,
        Err(error) => return error.as_ret(),
    };
    let mut link_storage = [0u8; 256];
    let link = match user_path(ctx.arg(2), ctx.arg(3) as usize, &mut link_storage) {
        Ok(path) => path,
        Err(error) => return error.as_ret(),
    };
    match crate::fs::syscalls::sys_symlink(target, link) {
        Ok(()) => 0,
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// Change the permission bits of a path.
pub fn sys_chmod(ctx: &SyscallContext) -> i64 {
    let mut storage = [0u8; 256];
    let path = match user_path(ctx.arg(0), ctx.arg(1) as usize, &mut storage) {
        Ok(path) => path,
        Err(error) => return error.as_ret(),
    };
    match crate::fs::syscalls::sys_chmod(path, ctx.arg(2) as u32) {
        Ok(()) => 0,
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// Change the numeric owner and group of a path.
pub fn sys_chown(ctx: &SyscallContext) -> i64 {
    let mut storage = [0u8; 256];
    let path = match user_path(ctx.arg(0), ctx.arg(1) as usize, &mut storage) {
        Ok(path) => path,
        Err(error) => return error.as_ret(),
    };
    match crate::fs::syscalls::sys_chown(path, ctx.arg(2) as u32, ctx.arg(3) as u32) {
        Ok(()) => 0,
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// Set access and modification times in Unix nanoseconds.
pub fn sys_utimens(ctx: &SyscallContext) -> i64 {
    let mut storage = [0u8; 256];
    let path = match user_path(ctx.arg(0), ctx.arg(1) as usize, &mut storage) {
        Ok(path) => path,
        Err(error) => return error.as_ret(),
    };
    match crate::fs::syscalls::sys_utimens(path, ctx.arg(2), ctx.arg(3)) {
        Ok(()) => 0,
        Err(error) => Errno::from(error).as_ret(),
    }
}

/// Return wall-clock time as seconds plus nanoseconds since the Unix epoch.
pub fn sys_clock_gettime(ctx: &SyscallContext) -> i64 {
    let output = ctx.arg(0);
    let nanos = crate::time::wall_time().to_unix_nanos().unwrap_or(0);
    let value = xenith_abi::Timespec {
        seconds: (nanos / 1_000_000_000) as i64,
        nanoseconds: (nanos % 1_000_000_000) as i64,
    };
    // SAFETY: Timespec is repr(C) and contains two initialized i64 values.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &value as *const xenith_abi::Timespec as *const u8,
            core::mem::size_of::<xenith_abi::Timespec>(),
        )
    };
    match copy_to_user(output, bytes, bytes.len()) {
        Ok(_) => 0,
        Err(error) => error.as_ret(),
    }
}

fn spawn_from_user(
    path_pointer: u64,
    path_length: usize,
    argv: u64,
) -> Result<crate::user::ProcessId, Errno> {
    let (path, owned_arguments) = process_request_from_user(path_pointer, path_length, argv)?;
    let arguments: Vec<&str> = owned_arguments.iter().map(String::as_str).collect();
    crate::user::process::spawn(&path, &arguments).map_err(|error| {
        ::log::warn!("spawn {} failed: {}", path, error);
        process_errno(error)
    })
}

/// Spawn a child process without duplicating the caller's address space.
pub fn sys_spawn(ctx: &SyscallContext) -> i64 {
    match spawn_from_user(ctx.arg(0), ctx.arg(1) as usize, ctx.arg(2)) {
        Ok(pid) => pid.as_u64() as i64,
        Err(error) => error.as_ret(),
    }
}

/// Deliver one validated signal to a live process.
pub fn sys_kill(ctx: &SyscallContext) -> i64 {
    let target = ctx.arg(0) as i64;
    let number = match u32::try_from(ctx.arg(1)) {
        Ok(number) => number,
        Err(_) => return Errno::Einval.as_ret(),
    };
    let Some(signal) = crate::user::signal::Signal::from_number(number) else {
        return Errno::Einval.as_ret();
    };
    let result = if target > 0 {
        crate::user::process::signal(crate::user::ProcessId(target as u64), signal).map(|_| 1)
    } else {
        let process_group = if target == 0 {
            crate::user::process::current_process_group()
        } else {
            let Some(group) = target
                .checked_neg()
                .map(|value| crate::user::ProcessId(value as u64))
            else {
                return Errno::Einval.as_ret();
            };
            group
        };
        if process_group.is_kernel() {
            return Errno::Esrch.as_ret();
        }
        crate::user::process::signal_group(process_group, signal)
    };
    match result {
        Ok(_) => 0,
        Err(error) => process_errno(error).as_ret(),
    }
}

/// Place the caller or one of its children into a process group.
pub fn sys_setpgid(ctx: &SyscallContext) -> i64 {
    let caller = match crate::user::process::try_current_pid() {
        Some(pid) => pid,
        None => return Errno::Esrch.as_ret(),
    };
    let raw_pid = ctx.arg(0) as i64;
    let raw_group = ctx.arg(1) as i64;
    if raw_pid < 0 || raw_group < 0 {
        return Errno::Einval.as_ret();
    }
    let target = if raw_pid == 0 {
        caller
    } else {
        crate::user::ProcessId(raw_pid as u64)
    };
    let process_group = if raw_group == 0 {
        target
    } else {
        crate::user::ProcessId(raw_group as u64)
    };
    match crate::user::process::set_process_group(target, process_group) {
        Ok(()) => 0,
        Err(error) => process_errno(error).as_ret(),
    }
}

/// Return the caller's process-group id.
pub fn sys_getpgrp(_ctx: &SyscallContext) -> i64 {
    let process_group = crate::user::process::current_process_group();
    if process_group.is_kernel() {
        Errno::Esrch.as_ret()
    } else {
        process_group.as_u64().min(i64::MAX as u64) as i64
    }
}

/// Create a new session led by the caller.
pub fn sys_setsid(_ctx: &SyscallContext) -> i64 {
    match crate::user::process::create_session() {
        Ok(session) => session.as_u64().min(i64::MAX as u64) as i64,
        Err(error) => process_errno(error).as_ret(),
    }
}

/// Create an IPv4 TCP, UDP, or raw ICMP socket.
pub fn sys_socket(ctx: &SyscallContext) -> i64 {
    let domain = match u32::try_from(ctx.arg(0)) {
        Ok(value) => value,
        Err(_) => return Errno::Eafnosupport.as_ret(),
    };
    if domain != xenith_abi::AF_INET {
        return Errno::Eafnosupport.as_ret();
    }
    let socket_type = match u32::try_from(ctx.arg(1)) {
        Ok(value) => value,
        Err(_) => return Errno::Esocktnosupport.as_ret(),
    };
    let protocol = match u32::try_from(ctx.arg(2)) {
        Ok(value) => value,
        Err(_) => return Errno::Eprotonosupport.as_ret(),
    };
    let kind = match (socket_type, protocol) {
        (xenith_abi::SOCK_STREAM, 0 | xenith_abi::IPPROTO_TCP) => {
            crate::net::socket::SocketKind::Tcp
        },
        (xenith_abi::SOCK_DGRAM, 0 | xenith_abi::IPPROTO_UDP) => {
            crate::net::socket::SocketKind::Udp
        },
        (xenith_abi::SOCK_RAW, xenith_abi::IPPROTO_ICMP) => crate::net::socket::SocketKind::RawIcmp,
        (xenith_abi::SOCK_STREAM | xenith_abi::SOCK_DGRAM | xenith_abi::SOCK_RAW, _) => {
            return Errno::Eprotonosupport.as_ret();
        },
        _ => return Errno::Esocktnosupport.as_ret(),
    };
    let handle = match crate::net::socket::create(kind) {
        Ok(handle) => handle,
        Err(error) => return socket_errno(error).as_ret(),
    };
    match SOCKET_FDS.lock().allocate(handle) {
        Ok(fd) => i64::from(fd),
        Err(error) => {
            let _ = crate::net::socket::discard(handle);
            error.as_ret()
        },
    }
}

/// Bind a socket to one fixed-size IPv4 ABI address.
pub fn sys_bind(ctx: &SyscallContext) -> i64 {
    let handle = match socket_handle(ctx.arg_i32(0)) {
        Ok(handle) => handle,
        Err(error) => return error.as_ret(),
    };
    let endpoint = match read_socket_address(ctx.arg(1), ctx.arg(2) as usize) {
        Ok(endpoint) => endpoint,
        Err(error) => return error.as_ret(),
    };
    match crate::net::socket::bind(handle, endpoint) {
        Ok(()) => 0,
        Err(error) => socket_errno(error).as_ret(),
    }
}

/// Put a bound TCP socket into listen state with a bounded backlog.
pub fn sys_listen(ctx: &SyscallContext) -> i64 {
    let handle = match socket_handle(ctx.arg_i32(0)) {
        Ok(handle) => handle,
        Err(error) => return error.as_ret(),
    };
    let backlog = match usize::try_from(ctx.arg(1)) {
        Ok(backlog) => backlog,
        Err(_) => return Errno::Einval.as_ret(),
    };
    match crate::net::socket::listen(handle, backlog) {
        Ok(()) => 0,
        Err(error) => socket_errno(error).as_ret(),
    }
}

/// Accept one established TCP child, polling each adapter once when empty.
pub fn sys_accept(ctx: &SyscallContext) -> i64 {
    let handle = match socket_handle(ctx.arg_i32(0)) {
        Ok(handle) => handle,
        Err(error) => return error.as_ret(),
    };
    let address_pointer = ctx.arg(1);
    let address_length = ctx.arg(2) as usize;
    if address_pointer == 0 {
        if address_length != 0 {
            return Errno::Einval.as_ret();
        }
    } else {
        if address_length != core::mem::size_of::<xenith_abi::SockAddrV4>() {
            return Errno::Einval.as_ret();
        }
        if let Err(error) = check_user_buf(address_pointer, address_length as u64) {
            return error.as_ret();
        }
    }
    let child = match crate::net::socket::accept(handle) {
        Ok(child) => child,
        Err(crate::net::socket::SocketError::WouldBlock) => {
            let _ = crate::devices::net::poll_stack(crate::time::uptime_ns(), 64);
            match crate::net::socket::accept(handle) {
                Ok(child) => child,
                Err(error) => return socket_errno(error).as_ret(),
            }
        },
        Err(error) => return socket_errno(error).as_ret(),
    };
    let peer = match crate::net::socket::SOCKETS.lock().remote_endpoint(child) {
        Ok(Some(peer)) => peer,
        Ok(None) => {
            let _ = crate::net::socket::discard(child);
            return Errno::Enotconn.as_ret();
        },
        Err(error) => {
            let _ = crate::net::socket::discard(child);
            return socket_errno(error).as_ret();
        },
    };
    let fd = match SOCKET_FDS.lock().allocate(child) {
        Ok(fd) => fd,
        Err(error) => {
            let _ = crate::net::socket::discard(child);
            return error.as_ret();
        },
    };
    if let Err(error) = write_socket_address(address_pointer, address_length, peer) {
        let _ = SOCKET_FDS.lock().take(fd);
        let _ = crate::net::socket::discard(child);
        return error.as_ret();
    }
    i64::from(fd)
}

/// Connect a socket. Network TCP returns `EINPROGRESS`; loopback completes inline.
pub fn sys_connect(ctx: &SyscallContext) -> i64 {
    let handle = match socket_handle(ctx.arg_i32(0)) {
        Ok(handle) => handle,
        Err(error) => return error.as_ret(),
    };
    let peer = match read_socket_address(ctx.arg(1), ctx.arg(2) as usize) {
        Ok(peer) => peer,
        Err(error) => return error.as_ret(),
    };
    let _ = crate::devices::net::poll_stack(crate::time::uptime_ns(), 64);
    let source = match prepare_socket_destination(peer.address) {
        Ok(source) => source,
        Err(error) => return error.as_ret(),
    };
    let packet = match crate::net::socket::connect(handle, peer, source) {
        Ok(packet) => packet,
        Err(error) => return socket_errno(error).as_ret(),
    };
    let Some(packet) = packet else {
        return 0;
    };
    let tracked = packet.clone();
    match dispatch_socket_packet(packet) {
        Ok(crate::net::SocketDispatch::Loopback { .. }) => 0,
        Ok(crate::net::SocketDispatch::Network(_)) => {
            if let Err(error) =
                crate::net::socket::track_transmission(handle, tracked, crate::time::uptime_ns())
            {
                let _ = crate::net::socket::cancel_connect(handle);
                return socket_errno(error).as_ret();
            }
            Errno::Einprogress.as_ret()
        },
        Err(error) => {
            let _ = crate::net::socket::cancel_connect(handle);
            error.as_ret()
        },
    }
}

/// Queue at most one MTU-safe payload on a connected socket.
pub fn sys_send(ctx: &SyscallContext) -> i64 {
    let count = match usize::try_from(ctx.arg(2)) {
        Ok(0) => return 0,
        Ok(count) if count <= xenith_abi::MAX_SOCKET_IO => count,
        _ => return Errno::Emsgsize.as_ret(),
    };
    let handle = match socket_handle(ctx.arg_i32(0)) {
        Ok(handle) => handle,
        Err(error) => return error.as_ret(),
    };
    let remote = match crate::net::socket::SOCKETS.lock().remote_endpoint(handle) {
        Ok(Some(remote)) => remote,
        Ok(None) => return Errno::Enotconn.as_ret(),
        Err(error) => return socket_errno(error).as_ret(),
    };
    if let Err(error) = prepare_socket_destination(remote.address) {
        return error.as_ret();
    }
    let mut payload = [0u8; xenith_abi::MAX_SOCKET_IO];
    if let Err(error) = copy_from_user(ctx.arg(1), &mut payload, count) {
        return error.as_ret();
    }
    let result = match crate::net::socket::send(handle, &payload[..count]) {
        Ok(result) => result,
        Err(error) => return socket_errno(error).as_ret(),
    };
    match result.disposition {
        crate::net::socket::SendDisposition::QueuedLoopback(written) => written as i64,
        crate::net::socket::SendDisposition::NeedsNetwork => {
            let Some(packet) = result.packet else {
                return Errno::Eio.as_ret();
            };
            let rollback_sequence = packet.tcp.as_ref().map(|header| header.sequence);
            let tracked = packet.clone();
            if let Err(error) = dispatch_socket_packet(packet) {
                if let Some(sequence) = rollback_sequence {
                    let _ = crate::net::socket::SOCKETS
                        .lock()
                        .rollback_send(handle, sequence, count);
                }
                return error.as_ret();
            }
            if let Some(_sequence) = rollback_sequence {
                if let Err(error) = crate::net::socket::track_transmission(
                    handle,
                    tracked,
                    crate::time::uptime_ns(),
                ) {
                    return socket_errno(error).as_ret();
                }
            }
            count as i64
        },
    }
}

/// Receive one queued payload, with one bounded adapter poll before `EAGAIN`.
pub fn sys_recv(ctx: &SyscallContext) -> i64 {
    let count = match usize::try_from(ctx.arg(2)) {
        Ok(0) => return 0,
        Ok(count) if count <= xenith_abi::MAX_SOCKET_IO => count,
        _ => return Errno::Emsgsize.as_ret(),
    };
    let handle = match socket_handle(ctx.arg_i32(0)) {
        Ok(handle) => handle,
        Err(error) => return error.as_ret(),
    };
    if let Err(error) = check_user_buf(ctx.arg(1), count as u64) {
        return error.as_ret();
    }
    let received = match crate::net::socket::receive(handle) {
        Ok(received) => received,
        Err(crate::net::socket::SocketError::WouldBlock) => {
            let _ = crate::devices::net::poll_stack(crate::time::uptime_ns(), 64);
            match crate::net::socket::receive(handle) {
                Ok(received) => received,
                Err(error) => return socket_errno(error).as_ret(),
            }
        },
        Err(error) => return socket_errno(error).as_ret(),
    };
    let copied = received.payload.len().min(count);
    match copy_to_user(ctx.arg(1), &received.payload[..copied], copied) {
        Ok(_) => copied as i64,
        Err(error) => error.as_ret(),
    }
}

/// Enumerate one physical IPv4 interface and its DHCP-derived configuration.
pub fn sys_net_info(ctx: &SyscallContext) -> i64 {
    let index = match usize::try_from(ctx.arg(0)) {
        Ok(index) => index,
        Err(_) => return Errno::Enodev.as_ret(),
    };
    let Some(info) = crate::net::interface_info(index, crate::time::uptime_ns()) else {
        return Errno::Enodev.as_ret();
    };
    let size = core::mem::size_of::<xenith_abi::NetInterfaceInfo>();
    // SAFETY: NetInterfaceInfo is repr(C), Copy, and every field is initialized.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&info as *const xenith_abi::NetInterfaceInfo).cast::<u8>(),
            size,
        )
    };
    match copy_to_user(ctx.arg(1), bytes, size) {
        Ok(_) => 0,
        Err(error) => error.as_ret(),
    }
}

#[cfg(test)]
mod user_range_tests {
    use super::*;

    #[test]
    fn inclusive_user_limit_accepts_its_final_byte() {
        assert_eq!(check_user_buf(USER_MAX, 1), Ok(()));
        assert_eq!(check_user_buf(USER_MAX - 15, 16), Ok(()));
    }

    #[test]
    fn user_ranges_reject_null_crossing_and_overflow() {
        assert_eq!(check_user_buf(0, 1), Err(Errno::Efault));
        assert_eq!(check_user_buf(USER_MAX, 2), Err(Errno::Efault));
        assert_eq!(check_user_buf(u64::MAX - 1, 4), Err(Errno::Efault));
    }
}
