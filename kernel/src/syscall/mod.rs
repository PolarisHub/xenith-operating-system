//! Syscall subsystem: the ring-3 -> ring-0 trap surface.
//!
//! This module is the kernel side of the `syscall`/`sysret` fast-path trap.
//! Userspace puts a syscall number in `RAX` and up to six arguments in
//! `RDI, RSI, RDX, R10, R8, R9` (note `R10` instead of the usual `RCX`,
//! because `syscall` clobbers `RCX` with the saved `RIP` and `R11` with the
//! saved `RFLAGS`). The arch entry trampoline — installed by the arch phase
//! into `IA32_LSTAR` — saves the remaining user state, loads a kernel stack,
//! and calls [`dispatch`] with the raw register file wrapped in a
//! [`SyscallContext`].
//!
//! # Submodules
//!
//! * [`table`] — the [`SYSCALLS`] array: a fixed table of
//!   `Option<SyscallFn>` indexed by syscall number, plus the syscall number
//!   constants. This is the single place the number-to-handler mapping lives,
//!   so adding or renumbering a syscall is a one-line edit.
//! * [`handlers`] — one function per syscall. Each takes a [`SyscallContext`]
//!   and returns an `i64`: a non-negative value is the success result (a file
//!   descriptor, a byte count, a pid, ...), a negative value is `-errno`.
//!
//! # Return convention
//!
//! Handlers return `i64`. The arch trampoline places this directly in `RAX`
//! for `sysret`. We follow the Linux convention: `>= 0` is success, `< 0` is
//! `-errno` (so `-EBADF` is returned as `-9`). The helper [`Errno::as_ret`]
//! converts an [`Errno`] into the negative `i64` to return.
//!
//! # Layering
//!
//! `syscall` is the ABI adapter at the top of the kernel. Handlers validate
//! and copy raw userspace arguments, then delegate ownership to the live
//! subsystems: `user::process` for process state, `fs::syscalls` for files
//! and descriptors, `sched`/`time` for blocking, `net` for sockets, and
//! `arch` for the entry trampoline. Subsystem errors are translated to the
//! stable [`Errno`] return convention here.

pub mod entry;
pub mod handlers;
pub mod table;

// Re-export the syscall number constants and the table so the arch entry
// trampoline and diagnostic code can reach them through `crate::syscall::*`
// without drilling into the submodule.
use core::fmt;

pub use entry::rust_syscall_dispatch;
pub use table::{lookup, NUM_SYSCALLS, SYSCALLS};

// ---------------------------------------------------------------------------
// Errno
// ---------------------------------------------------------------------------

/// A POSIX-style errno value returned to userspace on syscall failure.
///
/// Syscall handlers return `i64`: non-negative on success, `-errno` on
/// failure. This enum names the errnos Xenith currently uses; [`Errno::as_ret`]
/// folds one into the negative `i64` the arch trampoline writes into `RAX`.
/// The numeric values match Linux/glibc so a future dynamic linker and the
/// `libuser` wrappers see familiar codes.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Errno {
    /// Operation not permitted.
    Eperm,
    /// No such file or directory.
    Enoent,
    /// No such process.
    Esrch,
    /// Interrupted system call.
    Eintr,
    /// I/O error.
    Eio,
    /// No such device or address.
    Enxio,
    /// Argument list too long.
    E2big,
    /// Bad file descriptor.
    Ebadf,
    /// No child processes.
    Echild,
    /// Try again (resource temporarily unavailable).
    Eagain,
    /// Out of memory.
    Enomem,
    /// Permission denied.
    Eacces,
    /// Bad address.
    Efault,
    /// Device or resource busy.
    Ebusy,
    /// File exists.
    Eexist,
    /// Invalid cross-device link.
    Exdev,
    /// No such device.
    Enodev,
    /// Not a directory.
    Enotdir,
    /// Is a directory.
    Eisdir,
    /// Invalid argument.
    Einval,
    /// Too many open files in system.
    Enfile,
    /// Too many open files.
    Emfile,
    /// Inappropriate ioctl for device.
    Enotty,
    /// No space left on device.
    Enospc,
    /// Illegal seek.
    Espipe,
    /// Read-only file system.
    Erofs,
    /// Broken pipe.
    Epipe,
    /// Function not implemented.
    Enosys,
    /// Directory not empty.
    Enotempty,
    /// Too many levels of symbolic links.
    Eloop,
    /// Filename too long.
    Enametoolong,
    /// File descriptor is not a socket.
    Enotsock,
    /// Message exceeds the transport MTU.
    Emsgsize,
    /// Requested transport protocol is unsupported.
    Eprotonosupport,
    /// Requested socket type is unsupported.
    Esocktnosupport,
    /// Operation is unsupported for this socket type.
    Eopnotsupp,
    /// Requested address family is unsupported.
    Eafnosupport,
    /// Local address is already bound.
    Eaddrinuse,
    /// Local address is unavailable or not configured.
    Eaddrnotavail,
    /// No route reaches the destination network.
    Enetunreach,
    /// Peer reset the connection.
    Econnreset,
    /// Socket or packet buffers are exhausted.
    Enobufs,
    /// Socket is already connected.
    Eisconn,
    /// Socket is not connected.
    Enotconn,
    /// No resolved next hop reaches the destination host.
    Ehostunreach,
    /// Non-blocking connection establishment is in progress.
    Einprogress,
}

impl Errno {
    /// The positive POSIX errno number for this code.
    #[must_use]
    pub const fn number(self) -> i64 {
        match self {
            Self::Eperm => 1,
            Self::Enoent => 2,
            Self::Esrch => 3,
            Self::Eintr => 4,
            Self::Eio => 5,
            Self::Enxio => 6,
            Self::E2big => 7,
            Self::Ebadf => 9,
            Self::Echild => 10,
            Self::Eagain => 11,
            Self::Enomem => 12,
            Self::Eacces => 13,
            Self::Efault => 14,
            Self::Ebusy => 16,
            Self::Eexist => 17,
            Self::Exdev => 18,
            Self::Enodev => 19,
            Self::Enotdir => 20,
            Self::Eisdir => 21,
            Self::Einval => 22,
            Self::Enfile => 23,
            Self::Emfile => 24,
            Self::Enotty => 25,
            Self::Enospc => 28,
            Self::Espipe => 29,
            Self::Erofs => 30,
            Self::Epipe => 32,
            Self::Enosys => 38,
            Self::Enotempty => 39,
            Self::Eloop => 40,
            Self::Enametoolong => 36,
            Self::Enotsock => 88,
            Self::Emsgsize => 90,
            Self::Eprotonosupport => 93,
            Self::Esocktnosupport => 94,
            Self::Eopnotsupp => 95,
            Self::Eafnosupport => 97,
            Self::Eaddrinuse => 98,
            Self::Eaddrnotavail => 99,
            Self::Enetunreach => 101,
            Self::Econnreset => 104,
            Self::Enobufs => 105,
            Self::Eisconn => 106,
            Self::Enotconn => 107,
            Self::Ehostunreach => 113,
            Self::Einprogress => 115,
        }
    }

    /// The `i64` to return from the syscall handler: `-errno`.
    ///
    /// This is the value the arch trampoline loads into `RAX`. Userspace
    /// checks the sign: `>= 0` is success, `< 0` is `-errno` and the actual
    /// errno is `-result`.
    #[inline]
    #[must_use]
    pub const fn as_ret(self) -> i64 {
        -(self.number())
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The debug name is informative enough for a kernel log; we do not
        // carry a human message string per errno to keep the table compact.
        write!(f, "errno {} ({:?})", self.number(), self)
    }
}

// ---------------------------------------------------------------------------
// Syscall context
// ---------------------------------------------------------------------------

/// The register view the arch entry trampoline hands to [`dispatch`].
///
/// The trampoline saves the six syscall argument registers (`RDI, RSI, RDX,
/// R10, R8, R9`), the user `RIP` and `RSP` (recovered from `RCX`/`R11`-derived
/// state or the trampoline's own save slots), and the CPU number the syscall
/// landed on. Handlers read arguments through [`SyscallContext::arg`] so they
/// never touch the raw register file directly — the mapping from the x86_64
/// syscall register convention to "argument 0..5" lives entirely here.
///
/// The struct is constructed by the arch entry code; from the Rust side it is
/// a plain value passed by shared reference to every handler.
#[derive(Copy, Clone, Debug)]
pub struct SyscallContext {
    /// The six syscall arguments in argument order: `args[0]` is the value
    /// the user placed in `RDI`, `args[1]` in `RSI`, and so on per the x86_64
    /// syscall ABI (`RDI, RSI, RDX, R10, R8, R9`).
    pub args: [u64; 6],
    /// The user-space instruction pointer the `syscall` instruction would
    /// resume at (`RCX` on entry). Saved so handlers like `exit` and `exec`
    /// can reason about the caller, and so a future `sigreturn` can restore it.
    pub user_ip: u64,
    /// The user-space stack pointer at the `syscall` instruction (`R11`-derived
    /// / trampoline-saved). Used by `sigreturn` and by stack-pointer-validating
    /// syscalls such as a future `sigaltstack`.
    pub user_sp: u64,
    /// User RFLAGS captured by `syscall` in R11 before the entry mask is
    /// applied.  `fork` uses this to construct the child's first return to
    /// userspace with the same condition codes and control flags.
    pub user_flags: u64,
    /// Callee-saved user registers in the order RBX, RBP, R12, R13, R14,
    /// R15.  The ordinary syscall return restores these from the assembly
    /// entry frame; keeping a copy here lets a forked child resume with the
    /// exact same ABI-visible state while returning zero in RAX.
    pub preserved: [u64; 6],
    /// The CPU number the syscall landed on. Some handlers (per-CPU state,
    /// IPIs) need it; most ignore it.
    pub cpu: usize,
}

impl SyscallContext {
    /// Build a context from the raw register file the trampoline captured.
    ///
    /// This is the constructor the arch entry code calls before [`dispatch`].
    /// The argument order matches the x86_64 syscall ABI: `rdi, rsi, rdx,
    /// r10, r8, r9`.
    #[inline]
    #[must_use]
    // The nine scalars mirror the syscall entry register frame exactly.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        rdi: u64,
        rsi: u64,
        rdx: u64,
        r10: u64,
        r8: u64,
        r9: u64,
        user_ip: u64,
        user_sp: u64,
        user_flags: u64,
        preserved: [u64; 6],
        cpu: usize,
    ) -> Self {
        Self {
            args: [rdi, rsi, rdx, r10, r8, r9],
            user_ip,
            user_sp,
            user_flags,
            preserved,
            cpu,
        }
    }

    /// Build the complete userspace register image a successful `fork`
    /// installs in the child.  The child observes the same register state as
    /// the parent at the syscall boundary, except that RAX is the mandated
    /// zero return value.
    #[must_use]
    pub const fn fork_return_context(&self) -> crate::user::ring3::UserContext {
        crate::user::ring3::UserContext {
            rax: 0,
            rbx: self.preserved[0],
            rcx: self.user_ip,
            rdx: self.args[2],
            rsi: self.args[1],
            rdi: self.args[0],
            rbp: self.preserved[1],
            rsp: self.user_sp,
            r8: self.args[4],
            r9: self.args[5],
            r10: self.args[3],
            r11: self.user_flags,
            r12: self.preserved[2],
            r13: self.preserved[3],
            r14: self.preserved[4],
            r15: self.preserved[5],
            rip: self.user_ip,
            rflags: self.user_flags,
        }
    }

    /// Return argument `n` (0-indexed) as a `u64`, or `0` for out-of-range.
    ///
    /// Syscalls that take fewer than six arguments simply never read the
    /// higher slots; the trampoline leaves them as whatever the user had in
    /// those registers, so handlers must not assume unwritten slots are zero.
    /// This accessor is a plain index with a bounds clamp so a malformed
    /// handler cannot read past the array.
    #[inline]
    #[must_use]
    pub const fn arg(&self, n: usize) -> u64 {
        if n < self.args.len() {
            self.args[n]
        } else {
            0
        }
    }

    /// Argument `n` reinterpreted as a signed `isize`. Several syscalls
    /// (`brk`, `lseek` offset, `exit` code) take signed arguments; this
    /// helper centralises the cast so each handler does not repeat it.
    #[inline]
    #[must_use]
    pub const fn arg_isize(&self, n: usize) -> isize {
        self.arg(n) as isize
    }

    /// Argument `n` reinterpreted as a `i32`. Used by syscalls whose argument
    /// is a file descriptor or a small signed count.
    #[inline]
    #[must_use]
    pub const fn arg_i32(&self, n: usize) -> i32 {
        self.arg(n) as i32
    }
}

/// The signature every entry in [`SYSCALLS`] must have.
///
/// A handler receives the saved [`SyscallContext`] (read-only) and returns an
/// `i64`: non-negative on success, `-errno` on failure (see [`Errno::as_ret`]).
/// Handlers may block through scheduler-aware subsystem operations; for
/// example, [`handlers::sys_nanosleep`] parks the current task on the sleep
/// queue instead of busy-waiting.
pub type SyscallFn = fn(&SyscallContext) -> i64;

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Dispatch a syscall to its handler.
///
/// Called by the arch entry trampoline after it has saved user state and
/// built a [`SyscallContext`]. `num` is the value the user placed in `RAX`.
/// Unknown numbers (including numbers beyond the table) yield `-ENOSYS`, the
/// POSIX "function not implemented" code, so a userspace probing for an
/// unimplemented syscall gets a well-defined failure rather than a fault.
///
/// The result is the exact `i64` the trampoline should load into `RAX` for
/// `sysret`: `>= 0` for success, `< 0` for `-errno`.
#[inline]
pub fn dispatch(num: u64, ctx: &SyscallContext) -> i64 {
    crate::user::process::enforce_current_state();
    let result = match lookup(num) {
        Some(handler) => {
            // The handler does its own validation and returns either a
            // success value or `-errno`. We do not wrap the call in a
            // catch-all: a panicking handler invokes the kernel panic
            // handler, which parks the core — that is the correct policy
            // for a bare-metal kernel (there is no per-syscall fault
            // recovery yet).
            handler(ctx)
        },
        None => {
            ::log::trace!("syscall: unknown number {} (ip {:#018x})", num, ctx.user_ip);
            Errno::Enosys.as_ret()
        },
    };
    crate::user::process::enforce_current_state();
    result
}

// ---------------------------------------------------------------------------
// Architectural entry-gate initialisation
// ---------------------------------------------------------------------------

/// Enable the x86_64 `syscall`/`sysretq` fast path on the current CPU.
///
/// STAR's user selector is the descriptor two slots below the 64-bit user
/// code selector because hardware adds 16 for SYSRET.CS and 8 for SYSRET.SS.
/// In Xenith's GDT that base is `USER_CODE32_SELECTOR` (0x1b), yielding
/// user CS 0x2b and user SS 0x23. The latter is a writable DPL3 data segment;
/// its 32-bit D/B attribute is ignored for SS while executing 64-bit code.
pub fn init() {
    use crate::arch::x86_64::gdt::{KERNEL_CODE_SELECTOR, USER_CODE32_SELECTOR};
    use crate::arch::x86_64::msr::{IA32_EFER, IA32_FMASK, IA32_LSTAR, IA32_STAR};

    const EFER_SCE: u64 = 1 << 0;
    const RFLAGS_TF: u64 = 1 << 8;
    const RFLAGS_IF: u64 = 1 << 9;
    const RFLAGS_DF: u64 = 1 << 10;
    const RFLAGS_NT: u64 = 1 << 14;
    const RFLAGS_RF: u64 = 1 << 16;
    const RFLAGS_AC: u64 = 1 << 18;
    const ENTRY_FLAGS_MASK: u64 =
        RFLAGS_TF | RFLAGS_IF | RFLAGS_DF | RFLAGS_NT | RFLAGS_RF | RFLAGS_AC;

    let star = ((USER_CODE32_SELECTOR as u64) << 48) | ((KERNEL_CODE_SELECTOR as u64) << 32);
    let entry = crate::arch::x86_64::asm::syscall_entry as *const () as u64;

    // SAFETY: all four MSRs are architecturally defined on x86_64 CPUs with
    // SYSCALL support. Kernel bring-up runs at CPL0, the selector fields name
    // present GDT entries, and `entry` is a canonical kernel text address.
    unsafe {
        IA32_STAR.write(star);
        IA32_LSTAR.write(entry);
        IA32_FMASK.write(ENTRY_FLAGS_MASK);
        IA32_EFER.write(IA32_EFER.read() | EFER_SCE);
    }

    ::log::info!(
        "syscall: STAR={:#018x} LSTAR={:#018x} FMASK={:#x}",
        star,
        entry,
        ENTRY_FLAGS_MASK,
    );
}

const _: () = {
    use crate::arch::x86_64::gdt::{
        KERNEL_CODE_SELECTOR, KERNEL_DATA_SELECTOR, USER_CODE32_SELECTOR, USER_CODE_SELECTOR,
        USER_DATA32_SELECTOR,
    };

    assert!(KERNEL_DATA_SELECTOR == KERNEL_CODE_SELECTOR + 8);
    assert!(USER_DATA32_SELECTOR == USER_CODE32_SELECTOR + 8);
    assert!(USER_CODE_SELECTOR == USER_CODE32_SELECTOR + 16);
};

#[cfg(test)]
mod fork_context_tests {
    use super::SyscallContext;

    #[test]
    fn fork_child_preserves_registers_and_returns_zero() {
        let context = SyscallContext::new(
            1,
            2,
            3,
            4,
            5,
            6,
            0x400123,
            0x7fff_f000,
            0x246,
            [7, 8, 12, 13, 14, 15],
            0,
        );
        let child = context.fork_return_context();
        assert_eq!(child.rax, 0);
        assert_eq!((child.rdi, child.rsi, child.rdx), (1, 2, 3));
        assert_eq!((child.r10, child.r8, child.r9), (4, 5, 6));
        assert_eq!((child.rbx, child.rbp), (7, 8));
        assert_eq!(
            (child.r12, child.r13, child.r14, child.r15),
            (12, 13, 14, 15)
        );
        assert_eq!((child.rcx, child.r11), (0x400123, 0x246));
        assert_eq!(
            (child.rip, child.rsp, child.rflags),
            (0x400123, 0x7fff_f000, 0x246)
        );
    }
}
