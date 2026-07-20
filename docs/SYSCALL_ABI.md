# Syscall ABI

Xenith uses the x86-64 `syscall` instruction. The syscall number is in `rax`; arguments are in `rdi`, `rsi`, `rdx`, `r10`, `r8`, and `r9`. `rcx` and `r11` are clobbered by the instruction. A non-negative `rax` is success; `-errno` is failure.

The shared definitions live in `crates/xenith-abi`, with syscall numbers and common records in `syscall.rs` and the newer fixed records in `ipc.rs`, `wait.rs`, `thread.rs`, and `spawn.rs`. Numbers 0 through 23 cover read/write/open/close, process and memory calls, uname/ioctl, seek/stat/descriptor calls, and cwd calls. Numbers 24 through 28 add mkdir, unlink, bounded directory enumeration, wall time, and direct child spawn. Numbers 29 through 36 provide IPv4 sockets and interface information. Numbers 37 through 44 provide signal delivery, anonymous ramfs mount/unmount, symbolic links, permission/owner changes, nanosecond timestamp updates, and directory removal. Numbers 45 through 48 provide `setpgid`, `getpgrp`, `setsid`, and `openpty` master/slave creation. The descriptor-pair ABI is unchanged; each live master also owns a bounded `/dev/pts/<number>` slave name. `TIOCGPTN` returns that number through a checked `u32` user pointer. Opening the character-device path creates another slave open description, and the name disappears when the last master closes.

Numbers 49 through 51 provide `sigreturn`, `sigaction`, and `sigprocmask` with
checked signal-frame restoration and a fixed RX trampoline. Number 52 is
`getrandom(buf, length, flags)`; it accepts zero or `GRND_NONBLOCK`, fills at
most 1 MiB per call from the initialized kernel CSPRNG, and rejects unknown
flag bits. Number 53 is `sigaltstack(new, old)`. Alternate stacks are bounded
from 16 KiB through 8 MiB, report `SS_ONSTACK` from the interrupted stack
pointer, cannot be changed while active, survive `fork`, and are disabled by
`exec`.

Numbers 54 through 57 provide the exclusive userspace display/input session:
`ui_acquire`, `ui_present`, `ui_read_events`, and `ui_release`. One process owns
the boot framebuffer and ordered PS/2 input seat at a time. Presentation copies
validated damaged rows from a complete private userspace backbuffer; at most 64
damage rectangles and 32 events per read are accepted. The fixed 32-byte
`UiDisplayInfo`, 16-byte `UiRect`, and 48-byte `UiInputEvent` wire records and
the native 32-bpp RGB-mask contract are documented in
[DESKTOP_FOUNDATION](DESKTOP_FOUNDATION.md). Event delivery is transactional:
records leave the kernel queue only after the complete requested batch has
been copied successfully, and ownership epochs reject cross-session input.

Numbers 58 through 63 provide the bounded IPC and dynamic-protection layer:

| Number | Call | Result and contract |
| ---: | --- | --- |
| 58 | `channel_create(out_pair, flags)` | Atomically install both endpoints and write one 16-byte `IpcChannelPair`; `flags` must be zero. |
| 59 | `channel_send(fd, message, timeout_ns, flags)` | Send one canonical 4176-byte record; return its inline payload length. `flags` must be zero. |
| 60 | `channel_recv(fd, message, timeout_ns, flags)` | Receive one complete record and install all transferred descriptors transactionally; return its inline payload length. `flags` must be zero. |
| 61 | `shm_create(length, flags)` | Create a zero-filled, page-rounded, fixed-size shared-memory object and return its descriptor. `flags` must be zero. |
| 62 | `wait(items, count, timeout_ns, flags)` | Wait on 1-32 unique channel/UI sources, publish every readiness result, and return the number of ready records. `flags` must be zero. |
| 63 | `mprotect(addr, len, prot)` | Change permissions on a page-aligned range wholly owned by dynamic `mmap` mappings while preserving W^X and backing-object limits. |

Channel ABI version 1 uses an 80-byte header, up to 4096 inline bytes, and up
to four descriptor transfers per message. Each direction has eight bounded
queue slots and the kernel admits at most 64 channel pairs. A transfer names a
nonempty subset of the source descriptor's `READ`, `WRITE`, `MAP`, and
`TRANSFER` rights; it cannot amplify rights. Send publishes only after the
complete user payload has been copied. Receive installs the entire transfer
set and copies the complete output before consuming the queued message; a user
fault or insufficient descriptor capacity rolls back the installation. Channel
descriptors deliberately carry only `READ|WRITE`, while shared-memory
descriptors initially carry all four rights.

Shared-memory objects are non-resizable and always non-executable. A request is
rounded up to 4096-byte pages, with a 16 MiB per-object limit, 64 MiB global
committed limit, and an 8 MiB physical-memory reserve. The backing remains live
until the final descriptor and mapping reference is dropped.

Each 32-byte `WaitItem` selects channel readability/writability or the owning
UI session's input readiness and may report readable, writable, UI-input, or
hangup. Zero timeout polls, `u64::MAX` waits indefinitely, and other values are
relative nanoseconds. Registration and scheduler parking are lost-wake safe
and allocation-free; readiness is copied back as one transaction.

Numbers 64 through 68 provide native threads and restricted child launch:

| Number | Call | Result and contract |
| ---: | --- | --- |
| 64 | `thread_create(request)` | Validate one 64-byte version-1 `ThreadCreate`, publish a joinable task in the caller's address space, and return its globally unique 64-bit task ID. |
| 65 | `thread_exit(code)` | Terminate only the caller; the last live task completes process teardown and publishes the process result. This call does not return. |
| 66 | `thread_join(tid, result, flags)` | Wait for and consume one same-process thread, then write an 8-byte `ThreadJoinResult`; `flags` must be zero. |
| 67 | `gettid()` | Return the caller's globally unique scheduler task ID; all arguments must be zero. |
| 68 | `spawn_restricted(path, path_len, argv, envp, request, 0)` | Spawn a child with an initially empty descriptor table populated only by one canonical restricted-spawn request. |

`ThreadCreate` contains `u32 version, flags`, followed by `u64 entry,
stack_base, stack_size, argument, tls_base, reserved[2]`. Version is 1; flags
and reserved fields must be zero. The entry page must be present, user, and
executable. The caller-owned stack must be a distinct page-aligned private
RW/NX mapping from 16 KiB through 8 MiB and remain mapped until join consumes
the thread. The kernel starts `entry(argument)` with the SysV AMD64 convention;
`libuser::spawn_thread` supplies a trampoline that converts a normal function
return into `thread_exit`. `tls_base` must currently be zero and otherwise
returns `EOPNOTSUPP`.

One process may retain at most 32 live plus completed-unjoined thread records,
and all processes share a 256-user-task bound. Only one waiter may own a given
join. Descriptors and address space are process-wide. Until signal masks,
alternate stacks, and handler-entry state are task-local, thread creation
requires an empty blocked mask, a disabled alternate stack, and no caught
handlers; a multi-threaded process cannot change its signal mask/alternate
stack or install a caught handler. A second `waitpid` waiter receives `EBUSY`.
While more than one task is live, `fork`, `exec`, non-query `brk`, `mmap`,
`munmap`, and `mprotect` receive `EBUSY`. There is no detach API, userspace TLS,
or Windows-thread semantic layer yet.

`SpawnRestrictedRequest` is one canonical 288-byte version-1 record. Its
32-byte header contains `u16 version, header_size`, `u32 record_size, flags`,
`u16 file_action_count, file_action_size`, `u64 process_group, reserved`,
followed by sixteen 16-byte `SpawnFileAction` records. Each active action is
`i32 source_fd, target_fd; u32 rights, flags`; every unused action and reserved
or flag field must be zero. The count is at most 16, target numbers are unique
and below the 256-descriptor table bound, and requested rights must be a
nonempty subset of the source's `READ|WRITE|MAP|TRANSFER` rights. Ordinary
sources also require `TRANSFER`. A channel endpoint is the sole direct-child
exception: it may be inherited without `TRANSFER`, but only with a nonempty
subset of its existing `READ|WRITE` rights.

The kernel validates the complete action batch and snapshots every source
before it publishes the child; failures leave the parent's descriptor table
unchanged and expose no partial child. Duplicate source descriptors are
allowed, duplicate targets are not. `process_group` uses the ordinary spawn
encoding: zero inherits, `u64::MAX` creates a child-led group, and another
nonzero value joins that same-session group.

Caught-signal frames contain the complete integer/control context, stable
`siginfo`, and the exact enabled x87/SSE/YMM state. The kernel owns the xstate
location and validates its size, feature mask, MXCSR, XSAVE header, selectors,
addresses, flags, and reserved fields before `sigreturn` restores it.
`SA_SIGINFO` handlers receive `(signo, siginfo *, frame *)`; legacy handlers
receive `(signo, frame *)`. `SA_ONSTACK` selects the alternate stack unless it
is already active. `SA_RESTART` is deliberately limited to a zero-progress
`read` that returned `EINTR`; no other syscall is replayed.

Path-taking calls pass `(pointer, byte_length)` and do not require a trailing NUL. `read_dir` writes fixed `DirectoryEntry` records with a bounded 256-byte name. `spawn`, `spawn_restricted`, and `exec` accept a NUL-terminated pointer vector with at most 32 arguments and 255 bytes per argument; the environment pointer is currently not materialized. `spawn` argument 5 controls atomic process-group placement before the child becomes runnable: zero inherits, `u64::MAX` creates a child-led group, and any other nonzero value joins that same-session group. The ordinary `libuser::spawn` wrapper inherits; the shell uses `spawn_in_process_group` so short-lived pipeline stages cannot race a later `setpgid`.

`brk(0)` queries a per-process, ELF-derived break; growth allocates zeroed
read/write/non-executable pages and shrink releases complete trailing pages.
`mmap` accepts either private anonymous memory (`MAP_PRIVATE | MAP_ANONYMOUS`,
`fd = -1`, offset zero) or descriptor-backed `MAP_SHARED` memory. Every mapping
must be readable; W+X, execute-only, write-only, fixed placement, and arbitrary
file-backed mappings are rejected. A shared mapping requires `MAP|READ` rights
on a shared-memory descriptor, also requires `WRITE` for `PROT_WRITE`, and can
never be executable. A nonzero address is a hint, not a fixed placement.
`munmap` accepts page-aligned ranges wholly owned by dynamic mappings and
supports prefix, suffix, complete, and middle removal; it cannot remove ELF,
stack, signal-trampoline, or `brk` pages. `mprotect` applies only to those
dynamic mappings. It permits anonymous RW-to-RX loader transitions while
preventing shared mappings from gaining execute permission or write authority
beyond the descriptor used to map them. `fork` currently rejects a process
with an active shared mapping rather than silently applying private COW
semantics.

`mount_ramfs` deliberately exposes only a fresh in-memory filesystem; source-backed device mounting is not claimed by this ABI. `symlink` creates symbolic links, while hard-link creation remains unsupported. Metadata mutations are persisted by XenithFS, applied in memory by ramfs, and rejected with `EROFS` by read-only filesystems.

The entry stub performs `swapgs`, moves to the published kernel stack, saves a
mutable register frame, and dispatches in Rust. Normal calls return with
`sysretq`; a successful `sigreturn` selects an exact `iretq` restore so
RAX/RCX/R11 and the interrupted control state are preserved. STAR/LSTAR/FMASK
are initialized after the scheduler and GDT/TSS are ready.

Pointer checks reject null, overflow, kernel-half, supervisor-only, unmapped, and permission-invalid ranges. The architecture user-copy loops run with SMAP-aware STAC/CLAC bracketing and page-fault fixups, so a hostile pointer returns `-EFAULT` instead of reaching the kernel's fatal page-fault policy. Kernel writes to a fork-shared destination split its copy-on-write page before copying.
