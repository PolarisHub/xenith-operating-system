//! Userspace syscall numbering and wire structures.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum SyscallNumber {
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    Exit = 4,
    Brk = 5,
    Mmap = 6,
    Munmap = 7,
    Getpid = 8,
    Getppid = 9,
    Yield = 10,
    Nanosleep = 11,
    Fork = 12,
    Exec = 13,
    Waitpid = 14,
    Uname = 15,
    Ioctl = 16,
    Lseek = 17,
    Stat = 18,
    Dup = 19,
    Dup2 = 20,
    Pipe = 21,
    Chdir = 22,
    Getcwd = 23,
    Mkdir = 24,
    Unlink = 25,
    ReadDir = 26,
    ClockGettime = 27,
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
    /// Restore the register frame created for a caught signal.
    Sigreturn = 49,
    /// Install or query a signal disposition.
    Sigaction = 50,
    /// Change or query the calling process's blocked-signal mask.
    Sigprocmask = 51,
    /// Fill a userspace buffer from the kernel CSPRNG.
    GetRandom = 52,
    /// Install, disable, or query the calling thread's alternate signal stack.
    Sigaltstack = 53,
    /// Acquire exclusive userspace access to the boot framebuffer.
    UiAcquire = 54,
    /// Copy a userspace pixel buffer into the acquired framebuffer.
    UiPresent = 55,
    /// Read keyboard and pointer events from the desktop input queue.
    UiReadEvents = 56,
    /// Release userspace access to the framebuffer and desktop input queue.
    UiRelease = 57,
    /// Create a connected local channel pair.
    ///
    /// `channel_create(out_pair, flags)` writes an `IpcChannelPair`; `flags`
    /// is currently reserved and must be zero.
    ChannelCreate = 58,
    /// Atomically enqueue one bounded channel message and its transfers.
    ///
    /// `channel_send(fd, message, timeout_ns, flags)` takes an
    /// `IpcSendMessage`; `flags` is currently reserved and must be zero.
    ChannelSend = 59,
    /// Atomically receive one bounded channel message and its transfers.
    ///
    /// `channel_recv(fd, message, timeout_ns, flags)` writes an
    /// `IpcReceiveMessage`; `flags` is currently reserved and must be zero.
    ChannelRecv = 60,
    /// Create a zero-filled, fixed-length shared-memory descriptor.
    ///
    /// `shm_create(length, flags)` returns a descriptor; `flags` is currently
    /// reserved and must be zero.
    ShmCreate = 61,
    /// Wait for readiness across bounded channel/UI sources.
    Wait = 62,
    /// Change permissions on a dynamic mapping while preserving W^X.
    Mprotect = 63,
    /// Create a joinable task in the caller's address space.
    ThreadCreate = 64,
    /// Exit only the calling thread, or the process when it is the last one.
    ThreadExit = 65,
    /// Wait for and consume one completed thread owned by the caller.
    ThreadJoin = 66,
    /// Return the calling scheduler task's globally unique id.
    Gettid = 67,
    /// Spawn a child with only an explicit attenuated descriptor set.
    SpawnRestricted = 68,
}

/// `spawn` argument 5: inherit the caller's process group.
pub const SPAWN_GROUP_INHERIT: u64 = 0;

/// `spawn` argument 5: create a process group led by the new child.
/// Any other nonzero value requests an existing process group by id.
pub const SPAWN_GROUP_NEW: u64 = u64::MAX;

/// Version of the userspace display and input wire ABI.
pub const UI_ABI_VERSION: u32 = 1;

/// The display uses the native framebuffer pixel layout described by [`UiDisplayInfo`].
pub const UI_DISPLAY_NATIVE_PIXEL_FORMAT: u32 = 1;

pub const UI_EVENT_KEY: u16 = 1;
pub const UI_EVENT_POINTER: u16 = 2;

pub const UI_EVENT_FLAG_PRESSED: u16 = 1 << 0;
pub const UI_EVENT_FLAG_REPEAT: u16 = 1 << 1;
pub const UI_EVENT_FLAG_OVERFLOW: u16 = 1 << 15;

pub const UI_MODIFIER_LEFT_SHIFT: u16 = 1 << 0;
pub const UI_MODIFIER_RIGHT_SHIFT: u16 = 1 << 1;
pub const UI_MODIFIER_LEFT_CTRL: u16 = 1 << 2;
pub const UI_MODIFIER_RIGHT_CTRL: u16 = 1 << 3;
pub const UI_MODIFIER_LEFT_ALT: u16 = 1 << 4;
pub const UI_MODIFIER_RIGHT_ALT: u16 = 1 << 5;
pub const UI_MODIFIER_LEFT_SUPER: u16 = 1 << 6;
pub const UI_MODIFIER_RIGHT_SUPER: u16 = 1 << 7;
pub const UI_MODIFIER_CAPS_LOCK: u16 = 1 << 8;
pub const UI_MODIFIER_NUM_LOCK: u16 = 1 << 9;
pub const UI_MODIFIER_SCROLL_LOCK: u16 = 1 << 10;

pub const UI_POINTER_BUTTON_LEFT: u16 = 1 << 0;
pub const UI_POINTER_BUTTON_RIGHT: u16 = 1 << 1;
pub const UI_POINTER_BUTTON_MIDDLE: u16 = 1 << 2;
pub const UI_POINTER_BUTTON_BACK: u16 = 1 << 4;
pub const UI_POINTER_BUTTON_FORWARD: u16 = 1 << 5;

pub const UI_MAX_DAMAGE_RECTS: usize = 64;
pub const UI_MAX_EVENTS_PER_READ: usize = 32;
pub const UI_TIMEOUT_INFINITE: u64 = u64::MAX;

/// Display geometry and native framebuffer channel layout returned by `ui_acquire`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct UiDisplayInfo {
    pub version: u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub bits_per_pixel: u16,
    pub red_shift: u8,
    pub red_size: u8,
    pub green_shift: u8,
    pub green_size: u8,
    pub blue_shift: u8,
    pub blue_size: u8,
    pub flags: u32,
    pub reserved: u32,
}

/// A damaged display region, measured in pixels from the top-left corner.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct UiRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// One keyboard or pointer event returned by `ui_read_events`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct UiInputEvent {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub kind: u16,
    pub flags: u16,
    pub modifiers: u16,
    pub buttons: u16,
    pub code: u32,
    pub value1: i32,
    pub value2: i32,
    pub value3: i32,
    /// Must be zero. Explicitly occupies the tail so raw wire copies never
    /// include implicit, potentially uninitialized structure padding.
    pub reserved: [u32; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Errno {
    Eperm = 1,
    Enoent = 2,
    Esrch = 3,
    Eintr = 4,
    Eio = 5,
    Enxio = 6,
    Ebadf = 9,
    Echild = 10,
    Eagain = 11,
    Enomem = 12,
    Eacces = 13,
    Efault = 14,
    Ebusy = 16,
    Eexist = 17,
    Enodev = 19,
    Enotdir = 20,
    Eisdir = 21,
    Einval = 22,
    Emfile = 24,
    Enospc = 28,
    Espipe = 29,
    Erofs = 30,
    Epipe = 32,
    Enosys = 38,
    Enotempty = 39,
    Enotsock = 88,
    Emsgsize = 90,
    Eprotonosupport = 93,
    Esocktnosupport = 94,
    Eopnotsupp = 95,
    Eafnosupport = 97,
    Eaddrinuse = 98,
    Eaddrnotavail = 99,
    Enetunreach = 101,
    Econnreset = 104,
    Enobufs = 105,
    Eisconn = 106,
    Enotconn = 107,
    Ehostunreach = 113,
    Einprogress = 115,
}

/// `mmap` protection bits. Xenith's anonymous subset currently accepts
/// readable mappings with at most one of WRITE and EXECUTE, enforcing W^X.
pub const PROT_NONE: u32 = 0;
pub const PROT_READ: u32 = 1 << 0;
pub const PROT_WRITE: u32 = 1 << 1;
pub const PROT_EXEC: u32 = 1 << 2;

/// Linux-compatible `mmap` flag bits used by Xenith's syscall ABI.
pub const MAP_SHARED: u32 = 1 << 0;
pub const MAP_PRIVATE: u32 = 1 << 1;
pub const MAP_FIXED: u32 = 1 << 4;
pub const MAP_ANONYMOUS: u32 = 1 << 5;

pub const AF_INET: u32 = 2;
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;
pub const IPPROTO_ICMP: u32 = 1;
pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_UDP: u32 = 17;
pub const MAX_SOCKET_IO: usize = 1400;

pub const NET_IF_LINK_UP: u16 = 1 << 0;
pub const NET_IF_CONFIGURED: u16 = 1 << 1;
pub const NET_IF_DHCP: u16 = 1 << 2;

/// Runtime information for one physical IPv4 interface. `net_info(index)`
/// enumerates these records until it returns `ENODEV`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct NetInterfaceInfo {
    pub interface: u16,
    pub flags: u16,
    pub mtu: u16,
    pub prefix_len: u8,
    pub reserved: u8,
    pub mac: [u8; 6],
    pub address: [u8; 4],
    pub gateway: [u8; 4],
    pub dns_servers: [[u8; 4]; 2],
    pub lease_remaining_seconds: u32,
}

/// Fixed IPv4 socket address used by the Xenith syscall ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct SockAddrV4 {
    pub family: u16,
    pub port_be: u16,
    pub address: [u8; 4],
    pub padding: [u8; 8],
}

impl SockAddrV4 {
    #[must_use]
    pub const fn new(address: [u8; 4], port: u16) -> Self {
        Self {
            family: AF_INET as u16,
            port_be: port.to_be(),
            address,
            padding: [0; 8],
        }
    }

    #[must_use]
    pub const fn port(self) -> u16 {
        u16::from_be(self.port_be)
    }
}

impl Default for SockAddrV4 {
    fn default() -> Self {
        Self::new([0; 4], 0)
    }
}

/// Bit-compatible `open` options.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct OpenFlags(pub u32);

impl OpenFlags {
    pub const RDONLY: Self = Self(0);
    pub const WRONLY: Self = Self(1 << 0);
    pub const RDWR: Self = Self(1 << 1);
    pub const CREATE: Self = Self(1 << 6);
    pub const EXCLUSIVE: Self = Self(1 << 7);
    pub const TRUNCATE: Self = Self(1 << 9);
    pub const APPEND: Self = Self(1 << 10);
    pub const NONBLOCK: Self = Self(1 << 11);
    pub const DIRECTORY: Self = Self(1 << 16);
    pub const CLOEXEC: Self = Self(1 << 19);

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

// Linux-compatible terminal ioctl numbers. Keeping these values familiar lets
// small freestanding libc ports use their normal termios definitions.
pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;
pub const TCSETSW: u32 = 0x5403;
pub const TCSETSF: u32 = 0x5404;
pub const TIOCGWINSZ: u32 = 0x5413;
pub const TIOCSWINSZ: u32 = 0x5414;
pub const TIOCGPGRP: u32 = 0x540F;
pub const TIOCSPGRP: u32 = 0x5410;
pub const FIONREAD: u32 = 0x541B;
/// Return the unsigned devpts number associated with a PTY master.
pub const TIOCGPTN: u32 = 0x8004_5430;

/// `waitpid(2)` option bits and job-control signal numbers.
pub const WNOHANG: u32 = 1;
pub const WUNTRACED: u32 = 2;
pub const WCONTINUED: u32 = 8;
pub const SIGCONT: u32 = 18;
pub const SIGTSTP: u32 = 20;
pub const SIGTTIN: u32 = 21;
pub const SIGTTOU: u32 = 22;
pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGUSR2: u32 = 12;
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
pub const SIGTERM: u32 = 15;
pub const SIGCHLD: u32 = 17;
pub const SIGSTOP: u32 = 19;
pub const NSIG: u32 = 63;

/// Special `SigAction::handler` values.
pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

/// Operations accepted by `sigprocmask`.
pub const SIG_BLOCK: u32 = 0;
pub const SIG_UNBLOCK: u32 = 1;
pub const SIG_SETMASK: u32 = 2;

/// Return immediately if a random source would otherwise block.
/// Xenith seeds its CSPRNG before userspace starts, so this flag is accepted
/// for source compatibility and currently has the same successful behavior as
/// a zero flag word.
pub const GRND_NONBLOCK: u32 = 1;

/// Signal-action flags understood by Xenith.
///
/// The values intentionally match the common x86_64 POSIX/Linux ABI so small
/// freestanding libc ports do not need a Xenith-only translation layer.
pub const SA_SIGINFO: u64 = 0x0000_0004;
pub const SA_ONSTACK: u64 = 0x0800_0000;
pub const SA_RESTART: u64 = 0x1000_0000;
pub const SA_NODEFER: u64 = 0x4000_0000;
pub const SA_RESETHAND: u64 = 0x8000_0000;
pub const SA_SUPPORTED: u64 = SA_SIGINFO | SA_ONSTACK | SA_RESTART | SA_NODEFER | SA_RESETHAND;

/// `sigaltstack` state bits. `SS_ONSTACK` is query-only; callers may install
/// a stack with flags zero or disable it with `SS_DISABLE`.
pub const SS_ONSTACK: u32 = 1;
pub const SS_DISABLE: u32 = 2;

/// Xenith bounds alternate stacks so a corrupt request cannot reserve an
/// unbounded virtual range. The minimum covers the largest signal frame and
/// the kernel's enabled x87/SSE/AVX XSAVE image with generous handler space.
pub const MINSIGSTKSZ: u64 = 16 * 1024;
pub const MAXSIGSTKSZ: u64 = 8 * 1024 * 1024;

/// Maximum variable XSAVE payload accepted in a signal frame. Xenith enables
/// only x87, SSE, and AVX state, whose standard-format image is at most 832
/// bytes; the larger bound leaves ABI headroom while remaining auditable.
pub const SIGNAL_XSTATE_MAX: usize = 4096;

/// Stable `siginfo` origin codes used by the kernel.
pub const SI_USER: i32 = 0;
pub const SI_KERNEL: i32 = 128;

/// Signal-frame metadata bits.
pub const SIGNAL_FRAME_XSTATE: u64 = 1 << 0;
pub const SIGNAL_FRAME_ALTSTACK: u64 = 1 << 1;
pub const SIGNAL_FRAME_RESTART: u64 = 1 << 2;

/// Stable userspace representation of a blocked or pending signal set.
/// Bit `n` represents signal number `n`; bit zero is unused.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct SigSet(pub u64);

/// Stable userspace representation of a signal disposition.
///
/// `handler` is [`SIG_DFL`], [`SIG_IGN`], or a canonical user entry address.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct SigAction {
    pub handler: u64,
    pub mask: SigSet,
    pub flags: u64,
}

/// Stable signal source/fault payload. Unused fields are zeroed, making the
/// representation deterministic and safe to extend through `reserved`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct SigInfo {
    pub signo: u32,
    pub code: i32,
    pub errno: i32,
    pub trapno: u32,
    pub address: u64,
    pub sender_pid: u64,
    pub sender_uid: u64,
    pub status: i64,
    pub value: u64,
    pub reserved: u64,
}

/// Stable `stack_t`-equivalent used by `sigaltstack`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct SigAltStack {
    pub sp: u64,
    pub size: u64,
    pub flags: u32,
    pub reserved: u32,
}

/// Register image passed as the second argument to a caught signal handler.
/// A handler may inspect or deliberately edit this frame before returning;
/// `sigreturn` validates all privilege-sensitive fields before restoring it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct SignalFrame {
    pub signo: u64,
    pub saved_mask: SigSet,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// Source/fault metadata. `SA_SIGINFO` handlers receive a pointer to this
    /// member as their second argument and the frame pointer as their third.
    pub info: SigInfo,
    /// Address, byte length, and enabled-component mask of the aligned XSAVE
    /// image immediately following this fixed record.
    pub xstate_ptr: u64,
    pub xstate_size: u64,
    pub xstate_features: u64,
    pub frame_flags: u64,
}

pub const ICRNL: u32 = 0x0100;
pub const OPOST: u32 = 0x0001;
pub const ONLCR: u32 = 0x0004;
pub const ISIG: u32 = 0x0001;
pub const ICANON: u32 = 0x0002;
pub const ECHO: u32 = 0x0008;
pub const ECHOE: u32 = 0x0010;
pub const ECHOK: u32 = 0x0020;
pub const ECHONL: u32 = 0x0040;

pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VEOL: usize = 5;
pub const VSUSP: usize = 6;
pub const VMIN: usize = 7;
pub const VTIME: usize = 8;
pub const TERMINAL_CONTROL_CHARACTERS: usize = 16;

/// Terminal input, output, and line-discipline settings used by `TCGETS` and
/// `TCSETS*`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct TerminalAttributes {
    pub input_flags: u32,
    pub output_flags: u32,
    pub control_flags: u32,
    pub local_flags: u32,
    pub control_characters: [u8; TERMINAL_CONTROL_CHARACTERS],
}

impl Default for TerminalAttributes {
    fn default() -> Self {
        let mut control_characters = [0u8; TERMINAL_CONTROL_CHARACTERS];
        control_characters[VINTR] = 3; // Ctrl-C
        control_characters[VQUIT] = 28; // Ctrl-backslash
        control_characters[VERASE] = 127;
        control_characters[VKILL] = 21; // Ctrl-U
        control_characters[VEOF] = 4; // Ctrl-D
        control_characters[VEOL] = b'\n';
        control_characters[VSUSP] = 26; // Ctrl-Z
        control_characters[VMIN] = 1;
        Self {
            input_flags: ICRNL,
            output_flags: OPOST | ONLCR,
            control_flags: 0,
            local_flags: ISIG | ICANON | ECHO | ECHOE | ECHOK,
            control_characters,
        }
    }
}

/// Text terminal geometry returned by `TIOCGWINSZ`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct WindowSize {
    pub rows: u16,
    pub columns: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl Default for WindowSize {
    fn default() -> Self {
        Self {
            rows: 25,
            columns: 80,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

impl core::ops::BitOr for OpenFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Timespec {
    pub seconds: i64,
    pub nanoseconds: i64,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Stat {
    pub inode: u64,
    pub size: u64,
    pub blocks: u64,
    pub mode: u32,
    pub links: u32,
    pub uid: u32,
    pub gid: u32,
    pub device: u64,
    pub modified_ns: u64,
}

/// Fixed-size directory record returned by `read_dir`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct DirectoryEntry {
    pub inode: u64,
    pub kind: u8,
    pub reserved: u8,
    pub name_len: u16,
    pub name: [u8; 256],
}

impl Default for DirectoryEntry {
    fn default() -> Self {
        Self {
            inode: 0,
            kind: 0,
            reserved: 0,
            name_len: 0,
            name: [0; 256],
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct UtsName {
    pub system: [u8; 65],
    pub node: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
}

impl Default for UtsName {
    fn default() -> Self {
        Self {
            system: [0; 65],
            node: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_control_syscalls_extend_the_dense_abi() {
        assert_eq!(SyscallNumber::Setpgid as u64, 45);
        assert_eq!(SyscallNumber::Getpgrp as u64, 46);
        assert_eq!(SyscallNumber::Setsid as u64, 47);
        assert_eq!(SyscallNumber::OpenPty as u64, 48);
        assert_eq!(SyscallNumber::Sigreturn as u64, 49);
        assert_eq!(SyscallNumber::Sigaction as u64, 50);
        assert_eq!(SyscallNumber::Sigprocmask as u64, 51);
        assert_eq!(SyscallNumber::GetRandom as u64, 52);
        assert_eq!(SyscallNumber::Sigaltstack as u64, 53);
        assert_eq!(SyscallNumber::UiAcquire as u64, 54);
        assert_eq!(SyscallNumber::UiPresent as u64, 55);
        assert_eq!(SyscallNumber::UiReadEvents as u64, 56);
        assert_eq!(SyscallNumber::UiRelease as u64, 57);
        assert_eq!(SyscallNumber::ChannelCreate as u64, 58);
        assert_eq!(SyscallNumber::ChannelSend as u64, 59);
        assert_eq!(SyscallNumber::ChannelRecv as u64, 60);
        assert_eq!(SyscallNumber::ShmCreate as u64, 61);
        assert_eq!(SyscallNumber::Wait as u64, 62);
        assert_eq!(SyscallNumber::Mprotect as u64, 63);
        assert_eq!(SyscallNumber::ThreadCreate as u64, 64);
        assert_eq!(SyscallNumber::ThreadExit as u64, 65);
        assert_eq!(SyscallNumber::ThreadJoin as u64, 66);
        assert_eq!(SyscallNumber::Gettid as u64, 67);
        assert_eq!(SyscallNumber::SpawnRestricted as u64, 68);
        assert_eq!(WNOHANG | WUNTRACED | WCONTINUED, 11);
    }

    #[test]
    fn ui_wire_types_have_stable_layouts() {
        assert_eq!(core::mem::size_of::<UiDisplayInfo>(), 32);
        assert_eq!(core::mem::align_of::<UiDisplayInfo>(), 4);
        assert_eq!(core::mem::offset_of!(UiDisplayInfo, version), 0);
        assert_eq!(core::mem::offset_of!(UiDisplayInfo, width), 4);
        assert_eq!(core::mem::offset_of!(UiDisplayInfo, height), 8);
        assert_eq!(core::mem::offset_of!(UiDisplayInfo, stride), 12);
        assert_eq!(core::mem::offset_of!(UiDisplayInfo, bits_per_pixel), 16);
        assert_eq!(core::mem::offset_of!(UiDisplayInfo, red_shift), 18);
        assert_eq!(core::mem::offset_of!(UiDisplayInfo, red_size), 19);
        assert_eq!(core::mem::offset_of!(UiDisplayInfo, green_shift), 20);
        assert_eq!(core::mem::offset_of!(UiDisplayInfo, green_size), 21);
        assert_eq!(core::mem::offset_of!(UiDisplayInfo, blue_shift), 22);
        assert_eq!(core::mem::offset_of!(UiDisplayInfo, blue_size), 23);
        assert_eq!(core::mem::offset_of!(UiDisplayInfo, flags), 24);
        assert_eq!(core::mem::offset_of!(UiDisplayInfo, reserved), 28);

        assert_eq!(core::mem::size_of::<UiRect>(), 16);
        assert_eq!(core::mem::align_of::<UiRect>(), 4);
        assert_eq!(core::mem::offset_of!(UiRect, x), 0);
        assert_eq!(core::mem::offset_of!(UiRect, y), 4);
        assert_eq!(core::mem::offset_of!(UiRect, width), 8);
        assert_eq!(core::mem::offset_of!(UiRect, height), 12);

        assert_eq!(core::mem::size_of::<UiInputEvent>(), 48);
        assert_eq!(core::mem::align_of::<UiInputEvent>(), 8);
        assert_eq!(core::mem::offset_of!(UiInputEvent, sequence), 0);
        assert_eq!(core::mem::offset_of!(UiInputEvent, timestamp_ns), 8);
        assert_eq!(core::mem::offset_of!(UiInputEvent, kind), 16);
        assert_eq!(core::mem::offset_of!(UiInputEvent, flags), 18);
        assert_eq!(core::mem::offset_of!(UiInputEvent, modifiers), 20);
        assert_eq!(core::mem::offset_of!(UiInputEvent, buttons), 22);
        assert_eq!(core::mem::offset_of!(UiInputEvent, code), 24);
        assert_eq!(core::mem::offset_of!(UiInputEvent, value1), 28);
        assert_eq!(core::mem::offset_of!(UiInputEvent, value2), 32);
        assert_eq!(core::mem::offset_of!(UiInputEvent, value3), 36);
        assert_eq!(core::mem::offset_of!(UiInputEvent, reserved), 40);
        assert_eq!(
            core::mem::offset_of!(UiInputEvent, reserved) + core::mem::size_of::<[u32; 2]>(),
            core::mem::size_of::<UiInputEvent>()
        );
    }

    #[test]
    fn ui_constants_match_device_event_bits() {
        assert_eq!(UI_ABI_VERSION, 1);
        assert_eq!(UI_DISPLAY_NATIVE_PIXEL_FORMAT, 1);
        assert_eq!(UI_EVENT_KEY, 1);
        assert_eq!(UI_EVENT_POINTER, 2);
        assert_eq!(UI_EVENT_FLAG_PRESSED, 1);
        assert_eq!(UI_EVENT_FLAG_REPEAT, 2);
        assert_eq!(UI_EVENT_FLAG_OVERFLOW, 0x8000);

        assert_eq!(UI_MODIFIER_LEFT_SHIFT, 1 << 0);
        assert_eq!(UI_MODIFIER_RIGHT_SHIFT, 1 << 1);
        assert_eq!(UI_MODIFIER_LEFT_CTRL, 1 << 2);
        assert_eq!(UI_MODIFIER_RIGHT_CTRL, 1 << 3);
        assert_eq!(UI_MODIFIER_LEFT_ALT, 1 << 4);
        assert_eq!(UI_MODIFIER_RIGHT_ALT, 1 << 5);
        assert_eq!(UI_MODIFIER_LEFT_SUPER, 1 << 6);
        assert_eq!(UI_MODIFIER_RIGHT_SUPER, 1 << 7);
        assert_eq!(UI_MODIFIER_CAPS_LOCK, 1 << 8);
        assert_eq!(UI_MODIFIER_NUM_LOCK, 1 << 9);
        assert_eq!(UI_MODIFIER_SCROLL_LOCK, 1 << 10);

        assert_eq!(UI_POINTER_BUTTON_LEFT, 1);
        assert_eq!(UI_POINTER_BUTTON_RIGHT, 2);
        assert_eq!(UI_POINTER_BUTTON_MIDDLE, 4);
        assert_eq!(UI_POINTER_BUTTON_BACK, 16);
        assert_eq!(UI_POINTER_BUTTON_FORWARD, 32);
        assert_eq!(UI_MAX_DAMAGE_RECTS, 64);
        assert_eq!(UI_MAX_EVENTS_PER_READ, 32);
        assert_eq!(UI_TIMEOUT_INFINITE, u64::MAX);
    }

    #[test]
    fn signal_wire_types_have_stable_layouts() {
        assert_eq!(core::mem::size_of::<SigSet>(), 8);
        assert_eq!(core::mem::size_of::<SigAction>(), 24);
        assert_eq!(core::mem::size_of::<SigInfo>(), 8 * 8);
        assert_eq!(core::mem::size_of::<SigAltStack>(), 3 * 8);
        assert_eq!(core::mem::size_of::<SignalFrame>(), 34 * 8);
        assert_eq!(core::mem::offset_of!(SigAction, handler), 0);
        assert_eq!(core::mem::offset_of!(SigAction, mask), 8);
        assert_eq!(core::mem::offset_of!(SigAction, flags), 16);
        assert_eq!(
            SA_SUPPORTED,
            SA_SIGINFO | SA_ONSTACK | SA_RESTART | SA_NODEFER | SA_RESETHAND
        );
        assert_eq!(core::mem::offset_of!(SignalFrame, info), 22 * 8);
        assert_eq!(core::mem::offset_of!(SignalFrame, xstate_ptr), 30 * 8);
    }

    #[test]
    fn terminal_process_group_ioctls_do_not_alias_termios() {
        assert_ne!(TIOCGPGRP, TIOCSPGRP);
        assert_ne!(TIOCGPGRP, TCGETS);
        assert_ne!(TIOCSPGRP, TCSETS);
        assert_ne!(TIOCGPTN, TCGETS);
        assert_eq!(TIOCGPTN, 0x8004_5430);
    }

    #[test]
    fn memory_mapping_bits_match_the_documented_abi() {
        assert_eq!(PROT_NONE, 0);
        assert_eq!(PROT_READ | PROT_WRITE | PROT_EXEC, 7);
        assert_eq!(MAP_SHARED, 1);
        assert_eq!(MAP_PRIVATE, 2);
        assert_eq!(MAP_FIXED, 0x10);
        assert_eq!(MAP_ANONYMOUS, 0x20);
    }
}
