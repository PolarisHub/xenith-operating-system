//! Userspace subsystem: ring-3 transition, ELF loading, the process model,
//! and signal delivery.
//!
//! This module is the kernel side of the user/kernel boundary. Everything
//! above it (`sched`, `fs`, `syscall`) talks to user tasks through the
//! abstractions declared here; everything below it (`arch`, `mm`) provides
//! the primitives this module assembles into a working ring-3 environment.
//!
//! # Submodules
//!
//! * [`ring3`] — the privilege-drop primitive. [`ring3::jump_to_user`] is the
//!   one-way trip from ring 0 to ring 3: it installs the kernel stack into
//!   `TSS.RSP0`, swaps CR3 to the user's page table, pushes a syscall-return
//!   `IRETQ` frame with `RPL=3`, and `iretq`s. The function is `-> !` because
//!   the CPU is running user code when it "returns"; control comes back to
//!   the kernel only through an interrupt, exception, or `syscall`.
//! * [`elf`] — the ELF64 loader. Parses a static executable's program headers,
//!   allocates its address space, maps the loadable segments with the right
//!   `USER`/`WRITABLE`/`NO_EXECUTE` flags, and resolves the entry point that
//!   [`ring3::jump_to_user`] jumps to.
//! * [`process`] — the process control block and the per-CPU "current
//!   process" pointer. A `Process` owns an [`AddressSpace`](crate::mm::r#virtual::AddressSpace),
//!   a kernel stack, a user stack, and the bookkeeping the scheduler needs to
//!   suspend and resume it.
//! * [`signal`] — signal (POSIX-style asynchronous notification) delivery and
//!   disposition. Pending signals are selected under an IRQ-safe lock and the
//!   syscall return path builds a checked ring-3 handler frame plus the saved
//!   integer and xstate context restored by `sigreturn`.
//!
//! # Layering
//!
//! `user` sits at the top of the kernel's layer cake alongside `sched`,
//! `fs`, and `syscall`. It depends on:
//!
//! * [`crate::arch::x86_64`] for the GDT selectors, the TSS (`RSP0`/IST), and
//!   the raw `iretq`/`cli`/`write_cr3` primitives that [`ring3`] drives.
//! * [`crate::mm::r#virtual`] for [`AddressSpace`](crate::mm::r#virtual::AddressSpace),
//!   the user page-table root whose physical address [`ring3::jump_to_user`]
//!   writes into CR3.
//! * [`crate::sched`] for the per-CPU scheduler that decides *when* a given
//!   process runs; `user` provides the process image and return context.
//!
//! # Safety posture
//!
//! The ring-3 transition is one of the most security-sensitive operations in
//! the kernel: a bug here either crashes the machine (bad `IRETQ` frame) or
//! hands ring 0 to user code (bad selector or page table). Every function
//! that touches the privilege boundary is `unsafe` and carries a `# Safety`
//! doc spelling out the invariants the caller must uphold — typically: run
//! only in ring 0 on a kernel stack, with interrupts off, after the GDT/TSS
//! are loaded and the user address space has been prepared with the kernel
//! higher-half mapped so the transition code itself remains executable.

pub mod elf;
pub mod process;
pub mod ring3;
pub mod signal;

// Keep the complete process-launch surface available at `crate::user` while
// retaining the submodule paths for callers that need lower-level controls.
pub use elf::{load as load_elf, ElfError, ElfFile, LoadedImage};
pub use process::{
    current_pid, current_ppid, exit, spawn, try_current_pid, try_wait, wait, Pid, ProcessError,
    ProcessId, UserProcess, WaitResult, WaitSelector, WaitStatus,
};
pub use ring3::{jump_to_user, IretFrame, UserLaunch};

/// The privilege level (CPL/RPL) of kernel code.
///
/// Used by the ring-3 transition code to build `IRETQ` frame selectors with
/// the correct RPL and to sanity-check that the CPU is in ring 0 before
/// dropping to ring 3. Kept here rather than in `arch` because the ring
/// numbers are part of the user/kernel contract, not the CPU table layout.
pub const RING0: u16 = 0;

/// The privilege level (CPL/RPL) of user code.
///
/// [`ring3::jump_to_user`] builds its `IRETQ` frame with `CS` and `SS`
/// selectors whose low two bits are `RING3`; the CPU reads those bits as the
/// target CPL and performs the privilege drop.
pub const RING3: u16 = 3;

/// The bit position of the Interrupt Flag (IF) in RFLAGS.
///
/// [`ring3::jump_to_user`] sets this bit in the RFLAGS value it pushes onto
/// the `IRETQ` frame so that userspace starts with maskable interrupts
/// enabled — without it, the first user process would run with interrupts
/// off and a timer tick would never preempt it.
pub const RFLAGS_IF: u64 = 1 << 9;

/// Start the first userspace process after the scheduler and VFS are online.
///
/// The boot-info parameter keeps this entry point parallel with the other
/// kernel subsystems; process creation itself consumes `/init` through the
/// mounted VFS and no longer needs to inspect boot modules directly.
#[must_use]
pub fn init(_boot_info: &'static limine::BootInfo) -> bool {
    if process::process_count() != 0 {
        ::log::warn!("user: init requested after processes already exist");
        return false;
    }
    match process::spawn("/init", &["/init"]) {
        Ok(pid) => {
            ::log::info!("user: /init installed as {}", pid);
            true
        },
        Err(error) => {
            ::log::error!("user: unable to spawn /init: {}", error);
            false
        },
    }
}
