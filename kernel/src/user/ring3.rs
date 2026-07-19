//! The ring-0 -> ring-3 transition: `jump_to_user`.
//!
//! This module owns the one-way trip from kernel mode to user mode. The
//! single public entry point, [`jump_to_user`], is what the process loader
//! calls once it has mapped an executable into a fresh address space and
//! wants to start running it. After [`jump_to_user`] executes its `iretq`,
//! the CPU is running user code at CPL 3; control returns to the kernel only
//! through an interrupt, an exception, or a `syscall` instruction.
//!
//! Dropping to ring 3 on x86_64 is a single `iretq` with a privilege-raising
//! stack frame, but the frame has to be built just so and several pieces of
//! CPU state have to be correct first. [`jump_to_user`] performs, in order:
//! install `kernel_rsp0` into `TSS.RSP0`; swap CR3 to the user page table;
//! load `DS/ES/FS/GS` with the user data selector; push an `IRETQ` frame
//! (`SS, RSP, RFLAGS, CS, RIP`) with `RPL=3` selectors and `IF` forced on;
//! zero the GPRs (with `arg` in `rdi`, the SysV first-argument register);
//! `iretq`. The function is `-> !` because the CPU is running user code when
//! the `iretq` "completes".
//!
//! # Safety
//!
//! [`jump_to_user`] is `unsafe` because the caller must guarantee a
//! constellation of invariants that the type system cannot check: ring 0,
//! kernel stack, interrupts off, GDT/TSS loaded, user CR3 valid and sharing
//! the kernel upper half, and every pointer argument referring to a real,
//! mapped, architecturally-valid target. See the function's `# Safety` doc
//! for the full list.

use core::arch::asm;

use super::{RFLAGS_IF, RING3};
use crate::arch::x86_64::gdt::{self, USER_CODE_SELECTOR, USER_DATA_SELECTOR};
use crate::arch::x86_64::percpu;

// ---------------------------------------------------------------------------
// The IRETQ frame
// ---------------------------------------------------------------------------

/// The stack frame `iretq` pops to drop from ring 0 to ring 3.
///
/// In 64-bit long mode `iretq` always pops five 8-byte words, even though
/// `CS` and `SS` are only 16-bit selectors (the CPU zero-extends them in the
/// frame). The field order below is *low address first* — it mirrors the
/// order the CPU pops, which is the reverse of the order [`jump_to_user`]
/// pushes. The struct is `repr(C)` with all-`u64` fields, so it overlays a
/// hand-built frame exactly with no padding.
///
/// `jump_to_user` does not actually instantiate this struct on the stack —
/// it pushes the five words directly in asm — but the type is declared here
/// so the syscall return path, the signal delivery code, and any future
/// ring-3 -> ring-0 -> ring-3 round-trip can name the frame layout in Rust
/// instead of re-deriving it from the SDM each time.
#[repr(C)]
pub struct IretFrame {
    /// The user instruction pointer to resume at. Popped into `RIP`.
    pub rip: u64,
    /// The user code selector with `RPL=3` ([`USER_CODE_SELECTOR`]). Popped
    /// into `CS`; the low two bits are the new CPL.
    pub cs: u64,
    /// The flags register to load. Built from the current `RFLAGS` with
    /// [`RFLAGS_IF`] set so userspace runs with maskable interrupts on.
    pub rflags: u64,
    /// The user stack pointer. Popped into `RSP`.
    pub rsp: u64,
    /// The user data selector with `RPL=3` ([`USER_DATA_SELECTOR`]). Popped
    /// into `SS`.
    pub ss: u64,
}

impl IretFrame {
    /// Build a ring-3 `IRETQ` frame from its user-visible parts.
    ///
    /// `rflags` is taken as-is; the caller is responsible for setting
    /// [`RFLAGS_IF`] (see [`jump_to_user`], which forces it on). The
    /// selectors are fixed to the Xenith user selectors with `RPL=3`, so a
    /// frame built here always targets 64-bit ring-3 code.
    #[must_use]
    pub const fn new(rip: u64, rsp: u64, rflags: u64) -> Self {
        Self {
            rip,
            cs: USER_CODE_SELECTOR as u64,
            rflags,
            rsp,
            ss: USER_DATA_SELECTOR as u64,
        }
    }
}

impl core::fmt::Debug for IretFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Render the selectors in 16-bit hex even though they are stored as
        // u64, so the dump reads like the SDM's frame diagram.
        f.debug_struct("IretFrame")
            .field("rip", &format_args!("0x{:016x}", self.rip))
            .field("cs", &format_args!("0x{:04x}", self.cs))
            .field("rflags", &format_args!("0x{:016x}", self.rflags))
            .field("rsp", &format_args!("0x{:016x}", self.rsp))
            .field("ss", &format_args!("0x{:04x}", self.ss))
            .finish()
    }
}

/// Complete general-purpose register image used to resume a forked process.
///
/// The layout is intentionally all-u64 and `repr(C)`: the final privilege
/// transition loads it directly from assembly after activating the child's
/// page tables.  `rip`, `rsp`, and `rflags` form the IRETQ frame; every other
/// field restores the value visible immediately after the parent's syscall,
/// with `rax` set to zero for the child by [`SyscallContext::fork_return_context`](crate::syscall::SyscallContext::fork_return_context).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserContext {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

// ---------------------------------------------------------------------------
// UserLaunch — a bundled set of launch parameters
// ---------------------------------------------------------------------------

/// The complete set of inputs [`jump_to_user`] needs to drop into ring 3.
///
/// Bundling them in a struct keeps the call site readable (the scheduler
/// builds one `UserLaunch` per context switch) and makes the consistency
/// invariant explicit: `user_cr3` must actually map `rip` and `rsp`, and
/// `kernel_rsp0` must be a stack belonging to the same task. Every field
/// doc below is a "must be..." clause that [`jump_to_user`]'s safety
/// contract relies on.
#[derive(Clone, Copy)]
pub struct UserLaunch {
    /// User instruction pointer. Canonical low-half, mapped executable in
    /// the address space rooted at [`UserLaunch::user_cr3`].
    pub rip: u64,
    /// User stack pointer. Canonical low-half, mapped writable, 16-byte
    /// aligned (SysV AMD64 ABI).
    pub rsp: u64,
    /// Value passed to user code in `rdi` (SysV first-argument register).
    /// For `init` this is typically a pointer to an argv/env block; for a
    /// freshly `fork`ed process it is 0.
    pub arg: u64,
    /// Raw CR3 value to load — the physical address of the user PML4, low
    /// flag bits clear. The PML4 *must* share the kernel higher-half
    /// mappings, or the `iretq` sequence (running in ring 0 after the CR3
    /// write) page-faults on its own code.
    pub user_cr3: u64,
    /// Kernel stack top to install into `TSS.RSP0`. The CPU loads `RSP`
    /// from here on the next ring-3 -> ring-0 transition. Must be a valid,
    /// mapped, writable kernel-virtual address with room below it for the
    /// interrupt frame the CPU pushes.
    pub kernel_rsp0: u64,
}

impl UserLaunch {
    /// Convenience constructor — see the field docs for the invariants each
    /// argument must satisfy.
    #[must_use]
    pub const fn new(rip: u64, rsp: u64, arg: u64, user_cr3: u64, kernel_rsp0: u64) -> Self {
        Self {
            rip,
            rsp,
            arg,
            user_cr3,
            kernel_rsp0,
        }
    }
}

impl core::fmt::Debug for UserLaunch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Full disclosure is more useful than redaction here: this is a
        // kernel-internal debug type the scheduler logs at trace level only.
        f.debug_struct("UserLaunch")
            .field("rip", &format_args!("0x{:016x}", self.rip))
            .field("rsp", &format_args!("0x{:016x}", self.rsp))
            .field("arg", &format_args!("0x{:016x}", self.arg))
            .field("user_cr3", &format_args!("0x{:016x}", self.user_cr3))
            .field("kernel_rsp0", &format_args!("0x{:016x}", self.kernel_rsp0))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// jump_to_user — the ring-0 -> ring-3 transition
// ---------------------------------------------------------------------------

/// Drop from ring 0 to ring 3 and never return.
///
/// Performs the full privilege-drop sequence described in the [module docs]:
/// installs `kernel_rsp0` into `TSS.RSP0`, swaps CR3 to the user page table,
/// loads the user data segment into `DS/ES/FS/GS`, pushes a ring-3 `IRETQ`
/// frame, zeroes the general-purpose registers (with `arg` in `rdi`), and
/// `iretq`s into user code. The function is `-> !` because the CPU is
/// running user code when the `iretq` completes; control re-enters the
/// kernel only via an interrupt, exception, or `syscall`.
///
/// # Safety
///
/// The caller must guarantee *all* of the following, or the CPU will fault
/// in a way the kernel cannot recover from:
///
/// * **Ring 0, kernel stack, interrupts off.** Executes privileged
///   instructions (`mov cr3`, `iretq`, TSS write) and runs a `cli`-to-
///   `iretq` window where an interrupt would hit a half-built frame. The
///   `cli` is defensive; the caller must ensure interrupts are already off.
/// * **GDT and TSS loaded.** `ltr` has run (so `RSP0`/IST are live) and the
///   GDT contains the user descriptors at [`USER_CODE_SELECTOR`] /
///   [`USER_DATA_SELECTOR`].
/// * **`user_cr3` shares the kernel upper half.** The user PML4 must map
///   the kernel higher half (HHDM + kernel image) identically to the
///   kernel address space — the `iretq` sequence's own code lives in the
///   kernel half and must stay mapped after the CR3 write. The loader is
///   responsible for copying the kernel upper-half entries into every user
///   address space.
/// * **`rip` / `rsp` are valid user addresses.** `rip` mapped executable,
///   `rsp` mapped writable, both canonical low-half. A non-canonical `RIP`
///   `#GP`s on the `iretq` itself.
/// * **`kernel_rsp0` is a valid kernel stack top.** The CPU pushes
///   interrupt frames here on every ring-3 -> ring-0 transition; it must be
///   mapped writable in the kernel half with room below it for those frames.
///
/// [module docs]: self
#[inline(never)]
pub unsafe fn jump_to_user(rip: u64, rsp: u64, arg: u64, user_cr3: u64, kernel_rsp0: u64) -> ! {
    // SAFETY: the caller guarantees a live task-owned kernel stack and ring-0
    // execution; this performs the shared TSS/GS preparation for the final
    // privilege transition.
    unsafe { prepare_user_entry(kernel_rsp0) };

    // Build the IRETQ frame and drop into ring 3. Inputs are bound to
    // explicit registers so the compiler cannot overlap them.  They are
    // plain inputs because `options(noreturn)` forbids output operands and no
    // continuation exists that could observe the registers after they are
    // consumed and zeroed. `rdi` carries `arg` into ring 3 and must survive.
    // `rsp` is managed by push/iretq itself.
    //
    // SAFETY: the caller has vouched for every invariant in the `# Safety`
    // section. The block performs exactly the architectural ring-0 -> ring-3
    // transition and does not return, so there is no post-block state to
    // preserve.
    unsafe {
        asm!(
            // Hold interrupts off for the CR3-swap + frame-build window.
            // The safety contract requires interrupts already off, so this
            // `cli` is defensive (idempotent if IF is already clear).
            "cli",
            // Load the user data segment into DS/ES/FS. SS is loaded by
            // `iretq` from the frame. `r8w` is the 16-bit sub-register of
            // r8, which holds the full 64-bit (zero-extended) selector.
            "mov ds, r8w",
            "mov es, r8w",
            "mov fs, r8w",
            // Do not reload GS here. MOV GS would replace the active
            // per-CPU GS base with the flat descriptor's zero base before
            // SWAPGS can save it in IA32_KERNEL_GS_BASE. The selector is
            // ignored for address generation in 64-bit mode; SWAPGS below
            // installs the already-prepared zero user base.
            // Swap to the user address space. From this point until the
            // `iretq`, every instruction fetch and every memory access
            // (including the stack pushes below) is translated by the user
            // page table — which is why that table must share the kernel
            // higher half.
            "mov cr3, rsi",
            // Build RFLAGS for the user context: read the current flags,
            // force IF on so userspace starts with maskable interrupts
            // enabled. The other bits (the always-1 bit 1, reserved bits)
            // are preserved from the kernel's RFLAGS, which is correct.
            "pushfq",
            "pop rax",
            "or rax, {if_bit}",
            // Push the IRETQ frame in reverse pop-order so RIP lands at
            // [rsp]. Each push is a full 8-byte store: in 64-bit mode the
            // CS/SS slots in the frame are 8 bytes wide even though the
            // selectors themselves are 16-bit.
            "push r8",        // SS  = USER_DATA_SELECTOR (RPL=3)
            "push rdx",       // RSP = user stack pointer
            "push rax",       // RFLAGS (with IF set)
            "push r9",        // CS  = USER_CODE_SELECTOR (RPL=3)
            "push rcx",       // RIP = user entry point
            // Zero every general-purpose register except rdi (which carries
            // `arg` into ring 3) so no kernel state leaks into userspace.
            // The 32-bit `xor` form zero-extends to the full 64-bit
            // register, clearing it completely. rax is already free (the
            // RFLAGS value it held is on the frame); rsi/rdx/rcx/r8/r9 are
            // free (their input values are on the frame); rbx/rbp/r10-r15
            // were never inputs.
            "xor eax, eax",
            "xor ebx, ebx",
            "xor ecx, ecx",
            "xor edx, edx",
            "xor esi, esi",
            "xor ebp, ebp",
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            // Activate the user GS base only after every GS-relative kernel
            // access is complete.  On the first syscall, syscall.S's leading
            // swapgs restores this CPU's per-CPU base before reading gs:24.
            "swapgs",
            // Drop into ring 3. The CPU pops RIP, CS (-> CPL 3), RFLAGS
            // (-> IF on), RSP, SS (-> user data segment) and jumps to user
            // code. This instruction never returns control to this
            // function.
            "iretq",
            // The IF bit mask as a compile-time constant so the assembler
            // sees a literal in the `or` rather than a register operand.
            if_bit = const RFLAGS_IF,
            // `rdi` is a read-only input: it carries `arg` into ring 3 and
            // must not be clobbered by the zeroing sequence.
            in("rdi") arg,
            // Each register holds an input consumed before the zeroing pass.
            // With a diverging asm block there is no Rust-side output state
            // to describe, so these remain input-only operands.
            in("rsi") user_cr3,
            in("rdx") rsp,
            in("rcx") rip,
            in("r8") USER_DATA_SELECTOR as u64,
            in("r9") USER_CODE_SELECTOR as u64,
            // The block diverges: `iretq` jumps to user code and this
            // function never returns. `noreturn` tells the compiler not to
            // emit any continuation or worry about post-block register
            // state, which is essential because the pushes have moved rsp
            // and the iretq has abandoned the kernel stack entirely.
            options(noreturn),
        );
    }
}

/// Resume a saved userspace register image in `user_cr3`.
///
/// This is the fork counterpart to [`jump_to_user`].  It restores every GPR,
/// not just a fresh process's startup argument, and constructs an IRETQ frame
/// from the saved RIP/RSP/RFLAGS.  The context is read only from kernel-half
/// memory, which remains mapped after CR3 is changed.
///
/// # Safety
///
/// The same ring-0, GDT/TSS, shared-kernel-half, valid-CR3, valid-user-RIP/RSP,
/// and live-kernel-stack requirements as [`jump_to_user`] apply.  `context`
/// must remain readable through the kernel half of `user_cr3` until IRETQ.
#[inline(never)]
pub unsafe fn resume_user_context(context: &UserContext, user_cr3: u64, kernel_rsp0: u64) -> ! {
    // SAFETY: forwarded from this function's contract.
    unsafe { prepare_user_entry(kernel_rsp0) };

    // RFLAGS values originated in ring 3.  Keep ordinary arithmetic/debug
    // state, force the architectural fixed bit and IF, and remove privilege
    // controls that IRETQ must never accept from a process.
    const SAFE_RFLAGS_AND: u64 = !((3 << 12) | (1 << 14) | (1 << 17));

    // SAFETY: `context` uses the fixed repr(C) layout asserted below.  The
    // caller guarantees all addresses and the CR3/kernel-stack invariants.
    unsafe {
        asm!(
            "cli",
            "mov ds, r8w",
            "mov es, r8w",
            "mov fs, r8w",
            // Preserve the active per-CPU GS base until SWAPGS saves it;
            // loading the flat user selector here would zero that base.
            "mov cr3, rsi",
            // Build the privilege-changing IRETQ frame.  R10 is temporary
            // until its saved value is restored below.
            "mov r10, [rax + 136]",
            "and r10, {safe_flags}",
            "or r10, {required_flags}",
            "push r8",
            "push qword ptr [rax + 56]",
            "push r10",
            "push r9",
            "push qword ptr [rax + 128]",
            // Restore every GPR.  RAX holds the context pointer and is loaded
            // last; RSI/R8/R9 may now overwrite the setup operands.
            "mov rbx, [rax + 8]",
            "mov rcx, [rax + 16]",
            "mov rdx, [rax + 24]",
            "mov rsi, [rax + 32]",
            "mov rdi, [rax + 40]",
            "mov rbp, [rax + 48]",
            "mov r8,  [rax + 64]",
            "mov r9,  [rax + 72]",
            "mov r10, [rax + 80]",
            "mov r11, [rax + 88]",
            "mov r12, [rax + 96]",
            "mov r13, [rax + 104]",
            "mov r14, [rax + 112]",
            "mov r15, [rax + 120]",
            "mov rax, [rax]",
            "swapgs",
            "iretq",
            safe_flags = const SAFE_RFLAGS_AND,
            required_flags = const (RFLAGS_IF | 2),
            in("rax") context as *const UserContext,
            in("rsi") user_cr3,
            in("r8") USER_DATA_SELECTOR as u64,
            in("r9") USER_CODE_SELECTOR as u64,
            options(noreturn),
        );
    }
}

/// Prepare the per-CPU entry state shared by fresh exec/spawn launches and
/// fork returns.
///
/// # Safety
/// Caller must execute at CPL0 and provide a live, writable kernel stack top
/// owned by the task that is about to enter userspace.
unsafe fn prepare_user_entry(kernel_rsp0: u64) {
    // SAFETY: privileged interrupt control at CPL0.
    unsafe { asm!("cli", options(nostack, nomem)) };
    if percpu::current_cpu() == 0 {
        gdt::set_bsp_rsp0(kernel_rsp0);
    }
    percpu::with(|cpu| cpu.tss.set_rsp0(kernel_rsp0));
    // SAFETY: guaranteed by the caller.
    unsafe { percpu::set_kernel_rsp(kernel_rsp0) };
    // Xenith does not expose user TLS yet; install a clean user GS base.
    // SAFETY: privileged MSR write at CPL0; zero is canonical.
    unsafe { percpu::set_kernel_gs_base(0) };
}

/// Drop into ring 3 using a bundled [`UserLaunch`].
///
/// This is a thin convenience over [`jump_to_user`] that unpacks the struct
/// at the call site. It exists so the scheduler's context-switch path reads
/// as `jump_to_user_from(&launch)` rather than five field accesses. The
/// safety contract is identical to [`jump_to_user`].
///
/// # Safety
///
/// See [`jump_to_user`]; every invariant applies to the corresponding field
/// of `launch`.
#[inline]
pub unsafe fn jump_to_user_from(launch: &UserLaunch) -> ! {
    // SAFETY: forwarded to `jump_to_user`; the caller vouches for every
    // field of `launch` per that function's safety contract.
    unsafe {
        jump_to_user(
            launch.rip,
            launch.rsp,
            launch.arg,
            launch.user_cr3,
            launch.kernel_rsp0,
        )
    }
}

// ---------------------------------------------------------------------------
// Compile-time sanity
// ---------------------------------------------------------------------------

/// The user code and data selectors must carry `RPL=3`. If the GDT layout
/// ever drifts so that one of them no longer has `RING3` in its low bits,
/// `jump_to_user` would silently drop to the wrong privilege level — a
/// compile-time check here catches that before any ring-3 transition runs.
const _: () = assert!(USER_CODE_SELECTOR & 0x3 == RING3);
const _: () = assert!(USER_DATA_SELECTOR & 0x3 == RING3);

/// The IRETQ frame must be exactly 40 bytes (five 8-byte words). A size
/// mismatch would mean the struct no longer overlays a hand-built frame, and
/// any code that casts a stack pointer to `&IretFrame` would read the wrong
/// fields.
const _: () = assert!(core::mem::size_of::<IretFrame>() == 40);
const _: () = assert!(core::mem::size_of::<UserContext>() == 18 * 8);

/// `RFLAGS_IF` must be bit 9. The `or rax, {if_bit}` in `jump_to_user` relies
/// on this constant being exactly the IF bit; if it drifts the user context
/// would start with the wrong flag set.
const _: () = assert!(RFLAGS_IF == 1 << 9);

// ---------------------------------------------------------------------------
// Tests (host target only — the transition itself cannot run on a host)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_selectors_have_ring3_rpl() {
        assert_eq!(USER_CODE_SELECTOR & 0x3, RING3);
        assert_eq!(USER_DATA_SELECTOR & 0x3, RING3);
        // The canonical Xenith selectors are 0x2B (user code64) and 0x33
        // (user data64); pin them so a GDT layout change is caught here
        // rather than silently breaking the ring-3 transition.
        assert_eq!(USER_CODE_SELECTOR, 0x2B);
        assert_eq!(USER_DATA_SELECTOR, 0x33);
    }

    #[test]
    fn iret_frame_is_40_bytes() {
        assert_eq!(core::mem::size_of::<IretFrame>(), 40);
    }

    #[test]
    fn iret_frame_new_uses_user_selectors() {
        let f = IretFrame::new(0x400000, 0x7fff_0000, RFLAGS_IF);
        assert_eq!(f.rip, 0x400000);
        assert_eq!(f.rsp, 0x7fff_0000);
        assert_eq!(f.rflags, RFLAGS_IF);
        assert_eq!(f.cs, USER_CODE_SELECTOR as u64);
        assert_eq!(f.ss, USER_DATA_SELECTOR as u64);
        // The selectors in the frame must carry RPL=3 or iretq would not
        // drop privilege.
        assert_eq!(f.cs & 0x3, u64::from(RING3));
        assert_eq!(f.ss & 0x3, u64::from(RING3));
    }

    #[test]
    fn user_launch_round_trips() {
        let l = UserLaunch::new(0x401000, 0x7fff_f000, 0x1234, 0x8000, 0xFFFF_8000_DEAD_B000);
        assert_eq!(l.rip, 0x401000);
        assert_eq!(l.rsp, 0x7fff_f000);
        assert_eq!(l.arg, 0x1234);
        assert_eq!(l.user_cr3, 0x8000);
        assert_eq!(l.kernel_rsp0, 0xFFFF_8000_DEAD_B000);
    }

    #[test]
    fn rflags_if_is_bit_9() {
        assert_eq!(RFLAGS_IF, 1 << 9);
        // IF is bit 9 of RFLAGS per the SDM; no other flag shares that bit.
        assert_eq!(RFLAGS_IF & (1 << 8), 0);
        assert_eq!(RFLAGS_IF & (1 << 10), 0);
    }
}
