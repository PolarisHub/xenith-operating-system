# Syscall ABI

Xenith uses the x86-64 `syscall` instruction. The syscall number is in `rax`; arguments are in `rdi`, `rsi`, `rdx`, `r10`, `r8`, and `r9`. `rcx` and `r11` are clobbered by the instruction. A non-negative `rax` is success; `-errno` is failure.

The shared definitions live in `crates/xenith-abi/src/syscall.rs`. Numbers 0 through 23 cover read/write/open/close, process and memory calls, uname/ioctl, seek/stat/descriptor calls, and cwd calls. Numbers 24 through 28 add mkdir, unlink, bounded directory enumeration, wall time, and direct child spawn. Numbers 29 through 36 provide IPv4 sockets and interface information. Numbers 37 through 44 provide signal delivery, anonymous ramfs mount/unmount, symbolic links, permission/owner changes, nanosecond timestamp updates, and directory removal. Numbers 45 through 48 provide `setpgid`, `getpgrp`, `setsid`, and `openpty` master/slave creation. The descriptor-pair ABI is unchanged; each live master also owns a bounded `/dev/pts/<number>` slave name. `TIOCGPTN` returns that number through a checked `u32` user pointer. Opening the character-device path creates another slave open description, and the name disappears when the last master closes.

Numbers 49 through 51 provide `sigreturn`, `sigaction`, and `sigprocmask` with
checked signal-frame restoration and a fixed RX trampoline. Number 52 is
`getrandom(buf, length, flags)`; it accepts zero or `GRND_NONBLOCK`, fills at
most 1 MiB per call from the initialized kernel CSPRNG, and rejects unknown
flag bits. Number 53 is `sigaltstack(new, old)`. Alternate stacks are bounded
from 16 KiB through 8 MiB, report `SS_ONSTACK` from the interrupted stack
pointer, cannot be changed while active, survive `fork`, and are disabled by
`exec`.

Caught-signal frames contain the complete integer/control context, stable
`siginfo`, and the exact enabled x87/SSE/YMM state. The kernel owns the xstate
location and validates its size, feature mask, MXCSR, XSAVE header, selectors,
addresses, flags, and reserved fields before `sigreturn` restores it.
`SA_SIGINFO` handlers receive `(signo, siginfo *, frame *)`; legacy handlers
receive `(signo, frame *)`. `SA_ONSTACK` selects the alternate stack unless it
is already active. `SA_RESTART` is deliberately limited to a zero-progress
`read` that returned `EINTR`; no other syscall is replayed.

Path-taking calls pass `(pointer, byte_length)` and do not require a trailing NUL. `read_dir` writes fixed `DirectoryEntry` records with a bounded 256-byte name. `spawn` and `exec` accept a NUL-terminated pointer vector with at most 32 arguments and 255 bytes per argument.

`brk(0)` queries a per-process, ELF-derived break; growth allocates zeroed
read/write/non-executable pages and shrink releases complete trailing pages.
`mmap` implements a bounded anonymous/private subset: flags must be exactly
`MAP_PRIVATE | MAP_ANONYMOUS`, `fd` must be `-1`, and offset must be zero.
Readable R, RW, and RX mappings are supported; W+X, execute-only, write-only,
fixed, shared, and file-backed mappings are rejected. A nonzero address is a
hint, not a fixed placement. `munmap` accepts page-aligned ranges wholly owned
by anonymous mappings and supports prefix, suffix, complete, and middle
removal; it cannot remove ELF, stack, signal-trampoline, or `brk` pages.

`mount_ramfs` deliberately exposes only a fresh in-memory filesystem; source-backed device mounting is not claimed by this ABI. `symlink` creates symbolic links, while hard-link creation remains unsupported. Metadata mutations are persisted by XenithFS, applied in memory by ramfs, and rejected with `EROFS` by read-only filesystems.

The entry stub performs `swapgs`, moves to the published kernel stack, saves a
mutable register frame, and dispatches in Rust. Normal calls return with
`sysretq`; a successful `sigreturn` selects an exact `iretq` restore so
RAX/RCX/R11 and the interrupted control state are preserved. STAR/LSTAR/FMASK
are initialized after the scheduler and GDT/TSS are ready.

Pointer checks reject null, overflow, kernel-half, supervisor-only, unmapped, and permission-invalid ranges. The architecture user-copy loops run with SMAP-aware STAC/CLAC bracketing and page-fault fixups, so a hostile pointer returns `-EFAULT` instead of reaching the kernel's fatal page-fault policy. Kernel writes to a fork-shared destination split its copy-on-write page before copying.
