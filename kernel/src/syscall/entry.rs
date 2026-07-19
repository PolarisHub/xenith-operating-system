//! Rust half of the x86_64 `syscall` entry path.

use super::{Errno, SyscallContext};
use crate::arch::x86_64::interrupts::exceptions::ExceptionContext;

/// Exact low-to-high stack image built by `asm/syscall.S` before it calls
/// Rust.  Keeping the representation here makes the assembly offsets and the
/// fork register snapshot auditable in one place.
#[repr(C)]
pub struct SyscallEntryFrame {
    return_ip: u64,
    return_cs: u64,
    return_flags: u64,
    return_sp: u64,
    return_ss: u64,
    rax: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    r10: u64,
    r8: u64,
    r9: u64,
    rcx: u64,
    r11: u64,
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

const RETURN_WITH_SYSRET: u64 = 0;
const RETURN_WITH_IRET: u64 = 1;

impl SyscallEntryFrame {
    fn syscall_context(&self) -> SyscallContext {
        SyscallContext::new(
            self.rdi,
            self.rsi,
            self.rdx,
            self.r10,
            self.r8,
            self.r9,
            self.return_ip,
            self.return_sp,
            self.return_flags,
            [self.rbx, self.rbp, self.r12, self.r13, self.r14, self.r15],
            crate::arch::x86_64::percpu::current_cpu(),
        )
    }

    fn exception_context(&self) -> ExceptionContext {
        ExceptionContext {
            rax: self.rax,
            rbx: self.rbx,
            rcx: self.rcx,
            rdx: self.rdx,
            rsi: self.rsi,
            rdi: self.rdi,
            rbp: self.rbp,
            r8: self.r8,
            r9: self.r9,
            r10: self.r10,
            r11: self.r11,
            r12: self.r12,
            r13: self.r13,
            r14: self.r14,
            r15: self.r15,
            vector: 0,
            error_code: 0,
            rip: self.return_ip,
            cs: self.return_cs,
            rflags: self.return_flags,
            rsp: self.return_sp,
            ss: self.return_ss,
        }
    }

    fn restore_exception_context(&mut self, context: &ExceptionContext) {
        self.return_ip = context.rip;
        self.return_cs = context.cs;
        self.return_flags = context.rflags;
        self.return_sp = context.rsp;
        self.return_ss = context.ss;
        self.rax = context.rax;
        self.rbx = context.rbx;
        self.rcx = context.rcx;
        self.rdx = context.rdx;
        self.rsi = context.rsi;
        self.rdi = context.rdi;
        self.rbp = context.rbp;
        self.r8 = context.r8;
        self.r9 = context.r9;
        self.r10 = context.r10;
        self.r11 = context.r11;
        self.r12 = context.r12;
        self.r13 = context.r13;
        self.r14 = context.r14;
        self.r15 = context.r15;
    }

    fn set_normal_result(&mut self, result: i64) {
        self.rax = result as u64;
        // SYSCALL architecturally exposes the return RIP in RCX and the
        // pre-entry flags in R11. Keep those values for an ordinary SYSRET
        // and for the post-syscall image saved in a signal frame.
        self.rcx = self.return_ip;
        self.r11 = self.return_flags;
    }
}

/// Dispatch a raw x86_64 syscall register file through [`super::SYSCALLS`].
///
/// The first six parameters use the normal SysV argument registers. The
/// assembly stub passes a pointer to its complete saved frame in the first
/// ABI stack argument slot.
///
/// # Safety
/// `frame` must point to the complete, live [`SyscallEntryFrame`] constructed
/// by `asm/syscall.S` on the current task's kernel stack.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "sysv64" fn rust_syscall_dispatch(
    number: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    frame: *mut SyscallEntryFrame,
) -> u64 {
    // SAFETY: `syscall.S` passes RBX, which points at the complete 20-qword
    // frame on this task's live kernel stack. The frame remains exclusively
    // owned by this entry path for the duration of the call.
    let frame = unsafe { &mut *frame };
    debug_assert_eq!(frame.rax, number);
    debug_assert_eq!(frame.rdi, arg0);
    debug_assert_eq!(frame.rsi, arg1);
    debug_assert_eq!(frame.rdx, arg2);
    debug_assert_eq!(frame.r10, arg3);
    debug_assert_eq!(frame.r8, arg4);
    if number == super::table::SYS_SIGRETURN {
        let mut context = frame.exception_context();
        let restored = crate::user::process::with_current_process(|process| {
            crate::user::signal::sigreturn(&process.signals, &mut context)
        })
        .unwrap_or(false);
        if restored {
            frame.restore_exception_context(&context);
            return RETURN_WITH_IRET;
        }
        frame.set_normal_result(Errno::Einval.as_ret());
        return RETURN_WITH_SYSRET;
    }

    let context = frame.syscall_context();
    let result = super::dispatch(number, &context);
    frame.set_normal_result(result);

    let mut return_context = frame.exception_context();
    let outcome = crate::user::process::with_current_process(|process| {
        crate::user::signal::check_and_dispatch(&process.signals, &mut return_context)
    });
    match outcome {
        Some(crate::user::signal::DispatchOutcome::HandlerEntered(_)) => {
            frame.restore_exception_context(&return_context);
            RETURN_WITH_IRET
        },
        Some(crate::user::signal::DispatchOutcome::DefaultActionTaken {
            sig,
            action:
                crate::user::signal::DefaultAction::Terminate
                | crate::user::signal::DefaultAction::TerminateCoreDump,
        }) => crate::user::process::exit_signal(sig),
        _ => RETURN_WITH_SYSRET,
    }
}

const _: () = assert!(core::mem::size_of::<SyscallEntryFrame>() == 20 * 8);
const _: () = assert!(core::mem::offset_of!(SyscallEntryFrame, rax) == 5 * 8);
const _: () = assert!(core::mem::offset_of!(SyscallEntryFrame, rcx) == 12 * 8);
const _: () = assert!(core::mem::offset_of!(SyscallEntryFrame, r15) == 19 * 8);

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> SyscallEntryFrame {
        SyscallEntryFrame {
            return_ip: 0x400100,
            return_cs: crate::arch::x86_64::gdt::USER_CODE_SELECTOR as u64,
            return_flags: 0x202,
            return_sp: 0x7fff_f000,
            return_ss: crate::arch::x86_64::gdt::USER_DATA_SELECTOR as u64,
            rax: 50,
            rdi: 1,
            rsi: 2,
            rdx: 3,
            r10: 4,
            r8: 5,
            r9: 6,
            rcx: 0x400100,
            r11: 0x202,
            rbx: 7,
            rbp: 8,
            r12: 9,
            r13: 10,
            r14: 11,
            r15: 12,
        }
    }

    #[test]
    fn normal_result_uses_saved_rax_slot() {
        let mut frame = frame();
        frame.set_normal_result(-14);
        assert_eq!(frame.rax as i64, -14);
        assert_eq!(frame.rcx, frame.return_ip);
        assert_eq!(frame.r11, frame.return_flags);
    }

    #[test]
    fn iret_restore_preserves_all_architectural_return_registers() {
        let mut frame = frame();
        let mut context = frame.exception_context();
        context.rax = 0xfeed_face;
        context.rcx = 0x1111;
        context.r11 = 0x2222;
        context.rip = 0x401000;
        context.rsp = 0x7fff_e000;
        frame.restore_exception_context(&context);
        assert_eq!(frame.rax, 0xfeed_face);
        assert_eq!(frame.rcx, 0x1111);
        assert_eq!(frame.r11, 0x2222);
        assert_eq!(frame.return_ip, 0x401000);
        assert_eq!(frame.return_sp, 0x7fff_e000);
    }
}
