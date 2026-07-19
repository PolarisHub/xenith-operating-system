//! CPU exception context frame and per-vector Rust handlers.
//!
//! This module owns the Rust side of the exception path:
//!
//! * [`ExceptionContext`] — the `repr(C)` struct that maps exactly onto the
//!   stack frame the asm trampoline in `asm/isr.S` builds before it calls
//!   [`rust_isr_dispatch`]. Reading it is how the kernel sees what the CPU
//!   was doing when the fault fired.
//! * [`rust_isr_dispatch`] — the `#[no_mangle] extern "sysv64"` entry point the
//!   asm trampoline `call`s. It matches the vector number to the matching
//!   per-exception handler.
//! * one handler function per architecture exception vector (0..=31). Kernel
//!   faults funnel into [`super::handlers::dump_and_panic`]; recoverable user
//!   faults become caught/default POSIX signals, and kernel user-copy faults
//!   first consult the exception table so bad pointers become `EFAULT`.
//!
//! # Frame layout
//!
//! The asm trampoline pushes the GPRs in an order chosen so that the frame
//! reads `rax..r15` from low to high addresses, followed by the vector
//! number, the (real or synthetic) error code, and the CPU-pushed `iretq`
//! frame. Long mode pushes `rip`, `cs`, `rflags`, `rsp`, and `ss`
//! unconditionally, so the field order of [`ExceptionContext`] matches the
//! complete low-to-high hardware layout for both same-CPL and privilege-
//! changing entries. The struct is `repr(C)` with all-`u64` fields and has no
//! padding.
//!
//! The dispatcher returns after a user-copy fixup or after rewriting a user
//! frame for caught/ignored synchronous signals. Unrecoverable kernel faults
//! remain fatal.

use super::handlers::dump_and_panic;

// ---------------------------------------------------------------------------
// Exception context frame
// ---------------------------------------------------------------------------

/// The register state saved on the stack by the ISR trampoline for a CPU
/// exception.
///
/// Field order is *low address first*: it mirrors the order the asm pushes
/// values onto the stack (GPRs first, then the vector and error code, then
/// the CPU-pushed `iretq` frame). The trampoline passes a pointer to the
/// bottom of this frame (the saved `rax`) as the first SysV argument to
/// [`rust_isr_dispatch`]. The hardware frame always includes `rsp` and `ss`
/// in 64-bit mode, even when CPL does not change.
///
/// All fields are `u64` and naturally 8-byte aligned, so `repr(C)` alone —
/// no `packed` — gives the exact hardware offsets.
#[repr(C)]
pub struct ExceptionContext {
    // --- General-purpose registers, in push order (low -> high address) ---
    /// Saved `rax`.
    pub rax: u64,
    /// Saved `rbx`.
    pub rbx: u64,
    /// Saved `rcx`.
    pub rcx: u64,
    /// Saved `rdx`.
    pub rdx: u64,
    /// Saved `rsi`.
    pub rsi: u64,
    /// Saved `rdi`.
    pub rdi: u64,
    /// Saved `rbp`.
    pub rbp: u64,
    /// Saved `r8`.
    pub r8: u64,
    /// Saved `r9`.
    pub r9: u64,
    /// Saved `r10`.
    pub r10: u64,
    /// Saved `r11`.
    pub r11: u64,
    /// Saved `r12`.
    pub r12: u64,
    /// Saved `r13`.
    pub r13: u64,
    /// Saved `r14`.
    pub r14: u64,
    /// Saved `r15`.
    pub r15: u64,

    // --- Trampoline-supplied metadata ---
    /// The interrupt vector number (0..=31 for exceptions). Pushed by the
    /// stub so the dispatch can identify the exception without decoding the
    /// stub's own address.
    pub vector: u64,
    /// The error code: either pushed by the CPU (for the eight error-code
    /// exceptions) or a synthetic `0` pushed by the stub for uniformity.
    pub error_code: u64,

    // --- CPU-pushed `iretq` frame ---
    /// The faulting instruction pointer.
    pub rip: u64,
    /// The code segment selector active at the fault.
    pub cs: u64,
    /// The flags register at the fault.
    pub rflags: u64,
    /// The stack pointer active at the fault, unconditionally saved by a
    /// 64-bit-mode interrupt or exception entry.
    pub rsp: u64,
    /// The stack segment selector active at the fault.
    pub ss: u64,
}

// Keep the Rust overlay locked to the assembly contract. A layout drift here
// would make exception dispatch interpret unrelated stack words as registers.
const _: [(); 176] = [(); core::mem::size_of::<ExceptionContext>()];
const _: [(); 120] = [(); core::mem::offset_of!(ExceptionContext, vector)];
const _: [(); 136] = [(); core::mem::offset_of!(ExceptionContext, rip)];
const _: [(); 144] = [(); core::mem::offset_of!(ExceptionContext, cs)];
const _: [(); 160] = [(); core::mem::offset_of!(ExceptionContext, rsp)];

impl ExceptionContext {
    /// Whether the exception interrupted ring 3.
    #[inline]
    #[must_use]
    pub const fn came_from_user(&self) -> bool {
        (self.cs & 3) == 3
    }

    /// Return the interrupted stack pointer and selector.
    #[inline]
    #[must_use]
    pub const fn interrupted_stack(&self) -> (u64, u64) {
        (self.rsp, self.ss)
    }

    /// The vector number as a `u8`, for callers that index handler tables.
    ///
    /// The full `vector` field is `u64` because it is a stack word; this
    /// accessor narrows it once the dispatch has validated the range.
    #[inline]
    #[must_use]
    pub fn vector_u8(&self) -> u8 {
        self.vector as u8
    }
}

impl core::fmt::Debug for ExceptionContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A compact one-liner; the full dump lives in `handlers::dump_and_panic`.
        let mut debug = f.debug_struct("ExceptionContext");
        debug
            .field("vector", &self.vector)
            .field("error_code", &self.error_code)
            .field("rip", &self.rip);
        let (rsp, ss) = self.interrupted_stack();
        debug.field("rsp", &rsp).field("ss", &ss);
        debug.finish()
    }
}

/// Dispatch one already-pending signal before an interrupt or syscall frame
/// returns to ring 3. The caller owns `ctx`, so a caught disposition can
/// rewrite it in place to enter the userspace handler.
pub fn dispatch_pending_on_user_return(
    ctx: &mut ExceptionContext,
) -> Option<crate::user::signal::DispatchOutcome> {
    if !ctx.came_from_user() {
        return None;
    }
    crate::user::process::with_current_process(|process| {
        crate::user::signal::check_and_dispatch(&process.signals, ctx)
    })
}

/// Turn a synchronous user exception into its POSIX signal. A caught signal
/// returns with `ctx` rewritten; its default terminating action leaves the
/// scheduler exactly as the old direct user-fault termination path did.
fn dispatch_synchronous_user_signal(
    ctx: &mut ExceptionContext,
    signal: crate::user::signal::Signal,
) -> bool {
    dispatch_synchronous_user_signal_at(ctx, signal, ctx.rip)
}

fn dispatch_synchronous_user_signal_at(
    ctx: &mut ExceptionContext,
    signal: crate::user::signal::Signal,
    fault_address: u64,
) -> bool {
    if !ctx.came_from_user() {
        return false;
    }
    let outcome = crate::user::process::with_current_process(|process| {
        let _ = crate::user::signal::deliver_signal_with_info(
            &process.signals,
            signal,
            xenith_abi::SigInfo {
                signo: signal.as_number(),
                code: xenith_abi::SI_KERNEL,
                trapno: u32::from(ctx.vector_u8()),
                address: fault_address,
                ..xenith_abi::SigInfo::default()
            },
        );
        crate::user::signal::check_and_dispatch(&process.signals, ctx)
    });
    match outcome {
        Some(crate::user::signal::DispatchOutcome::HandlerEntered(_))
        | Some(crate::user::signal::DispatchOutcome::DefaultActionTaken {
            action: crate::user::signal::DefaultAction::Ignore,
            ..
        }) => true,
        Some(crate::user::signal::DispatchOutcome::DefaultActionTaken {
            action:
                crate::user::signal::DefaultAction::Terminate
                | crate::user::signal::DefaultAction::TerminateCoreDump,
            ..
        })
        | Some(crate::user::signal::DispatchOutcome::NothingDeliverable) => {
            // A blocked synchronous fault cannot safely re-execute forever.
            crate::user::process::exit_signal(signal)
        },
        Some(crate::user::signal::DispatchOutcome::DefaultActionTaken { .. }) => {
            crate::user::process::exit_signal(signal)
        },
        Some(crate::user::signal::DispatchOutcome::KernelContext) | None => false,
    }
}

// ---------------------------------------------------------------------------
// Per-exception Rust handlers
// ---------------------------------------------------------------------------
//
// Each handler is a thin wrapper around `dump_and_panic` that supplies the
// exception's mnemonic and short description. They are `fn` items (not
// closures) so they coerce to `fn(&ExceptionContext) -> !` and show up as
// named symbols in a crash backtrace. The macro keeps the boilerplate
// uniform: adding a recovery path later means replacing a single
// `exc!` line with a real body.

/// Generate a per-exception handler that funnels into [`dump_and_panic`].
macro_rules! exc {
    ($id:ident, $name:literal) => {
        #[doc = concat!("Handler for exception vector: `", $name, "`.")]
        fn $id(ctx: &ExceptionContext) -> ! {
            dump_and_panic(ctx, $name)
        }
    };
}

macro_rules! user_exc {
    ($id:ident, $name:literal, $signal:expr) => {
        #[doc = concat!("Handler for recoverable user exception: `", $name, "`.")]
        fn $id(ctx: &mut ExceptionContext) {
            if dispatch_synchronous_user_signal(ctx, $signal) {
                return;
            }
            dump_and_panic(ctx, $name)
        }
    };
}

user_exc!(
    divide_error,
    "#DE Divide Error",
    crate::user::signal::Signal::Fpe
);
user_exc!(debug, "#DB Debug", crate::user::signal::Signal::Trap);
exc!(nmi, "NMI — Non-Maskable Interrupt");
user_exc!(
    breakpoint,
    "#BP Breakpoint",
    crate::user::signal::Signal::Trap
);
user_exc!(overflow, "#OF Overflow", crate::user::signal::Signal::Fpe);
user_exc!(
    bound_range,
    "#BR Bound Range Exceeded",
    crate::user::signal::Signal::Segv
);
user_exc!(
    invalid_opcode,
    "#UD Invalid Opcode",
    crate::user::signal::Signal::Ill
);
fn device_not_available(ctx: &ExceptionContext) {
    if crate::sched::scheduler::materialize_current_fpu() {
        return;
    }
    dump_and_panic(ctx, "#NM Device Not Available")
}
exc!(double_fault, "#DF Double Fault");
exc!(
    coprocessor_overrun,
    "#MF Coprocessor Segment Overrun (reserved)"
);
exc!(invalid_tss, "#TS Invalid TSS");
user_exc!(
    segment_not_present,
    "#NP Segment Not Present",
    crate::user::signal::Signal::Segv
);
user_exc!(
    stack_segment,
    "#SS Stack-Segment Fault",
    crate::user::signal::Signal::Segv
);
user_exc!(
    general_protection,
    "#GP General Protection",
    crate::user::signal::Signal::Segv
);
fn page_fault(ctx: &mut ExceptionContext) {
    // SAFETY: reading CR2 at CPL0 is side-effect free and this handler is
    // entered by #PF, so it contains the faulting linear address.
    let fault_address = unsafe { crate::arch::x86_64::read_cr2() };
    if ctx.came_from_user() {
        // P=1, W/R=1, U/S=1 identifies a user write-protection fault. A COW
        // leaf can be split and retried by returning to the same instruction.
        if ctx.error_code & 0b111 == 0b111 {
            let page = xenith_types::Page::containing_addr(xenith_types::VirtAddr::new_truncate(
                fault_address,
            ));
            // SAFETY: the exception interrupted ring 3, whose CR3 is a live
            // user address space sharing the kernel HHDM used by the walker.
            let space =
                unsafe { crate::mm::r#virtual::address_space::AddressSpace::adopt_current() };
            match space.resolve_cow_fault(page) {
                Ok(true) => return,
                Ok(false) => {},
                Err(error) => {
                    ::log::warn!(
                        "user page-fault COW resolution failed at {fault_address:#018x}: {error:?}"
                    );
                },
            }
        }
        ::log::warn!(
            "delivering SIGSEGV after user page fault at {fault_address:#018x} (error={:#x})",
            ctx.error_code
        );
        if dispatch_synchronous_user_signal_at(
            ctx,
            crate::user::signal::Signal::Segv,
            fault_address,
        ) {
            return;
        }
    }
    if !ctx.came_from_user() {
        if let Some(fixup) = crate::arch::x86_64::usercopy::fault_fixup(ctx.rip, fault_address) {
            ctx.rip = fixup;
            return;
        }
    }
    dump_and_panic(ctx, "#PF Page Fault")
}
exc!(reserved_15, "#Reserved vector 15");
user_exc!(
    x87_floating_point,
    "#MF x87 Floating-Point Error",
    crate::user::signal::Signal::Fpe
);
user_exc!(
    alignment_check,
    "#AC Alignment Check",
    crate::user::signal::Signal::Bus
);
exc!(machine_check, "#MC Machine Check");
user_exc!(
    simd_floating_point,
    "#XM SIMD Floating-Point Exception",
    crate::user::signal::Signal::Fpe
);
exc!(virtualization, "#VE Virtualization Exception");
exc!(control_protection, "#CP Control Protection");
exc!(reserved_22, "#Reserved vector 22");
exc!(reserved_23, "#Reserved vector 23");
exc!(reserved_24, "#Reserved vector 24");
exc!(reserved_25, "#Reserved vector 25");
exc!(reserved_26, "#Reserved vector 26");
exc!(reserved_27, "#Reserved vector 27");
exc!(reserved_28, "#Reserved vector 28");
exc!(reserved_29, "#Reserved vector 29");
exc!(security_exception, "#SX Security Exception");
exc!(reserved_31, "#Reserved vector 31");

// ---------------------------------------------------------------------------
// asm -> Rust dispatch entry point
// ---------------------------------------------------------------------------

/// The Rust entry point called by the `isr_common` trampoline in
/// `asm/isr.S`.
///
/// The trampoline builds an [`ExceptionContext`] on the stack and passes a
/// pointer to it in `rdi` (the first SysV AMD64 argument). This function
/// reads the vector number and dispatches to the matching handler. It returns
/// after a kernel user-copy fixup or a recoverable user-signal dispatch;
/// unrecoverable kernel exceptions panic and park the core.
///
/// `#[no_mangle]` fixes the symbol name to `rust_isr_dispatch` so the asm
/// `call rust_isr_dispatch` resolves at link time regardless of Rust
/// name-mangling. `extern "sysv64"` selects the SysV AMD64 calling convention
/// (argument in `rdi`), matching what the trampoline sets up.
///
/// # Safety contract for the asm caller
///
/// This function is `extern "sysv64"` and `#[no_mangle]` rather than `unsafe
/// extern "sysv64"` because it is not *called from Rust* — it is entered from
/// assembly with a frame the asm built. The caller (the trampoline) must
/// guarantee that `rdi` points at the fixed [`ExceptionContext`] prefix laid
/// out exactly as described in the module docs, with `vector` in `0..=31`.
/// When saved CS has RPL 3, the `rsp`/`ss` tail must also be present. A
/// violation turns a field read into a read of unrelated memory, which in
/// ring 0 is fatal.
#[no_mangle]
pub extern "sysv64" fn rust_isr_dispatch(ctx: &mut ExceptionContext) {
    // User-signal and user-copy fixup arms may return. A vector outside
    // 0..=31 is a stub/IDT configuration bug and remains fatal.
    match ctx.vector_u8() {
        0 => divide_error(ctx),
        1 => debug(ctx),
        2 => nmi(ctx),
        3 => breakpoint(ctx),
        4 => overflow(ctx),
        5 => bound_range(ctx),
        6 => invalid_opcode(ctx),
        7 => device_not_available(ctx),
        8 => double_fault(ctx),
        9 => coprocessor_overrun(ctx),
        10 => invalid_tss(ctx),
        11 => segment_not_present(ctx),
        12 => stack_segment(ctx),
        13 => general_protection(ctx),
        14 => page_fault(ctx),
        15 => reserved_15(ctx),
        16 => x87_floating_point(ctx),
        17 => alignment_check(ctx),
        18 => machine_check(ctx),
        19 => simd_floating_point(ctx),
        20 => virtualization(ctx),
        21 => control_protection(ctx),
        22 => reserved_22(ctx),
        23 => reserved_23(ctx),
        24 => reserved_24(ctx),
        25 => reserved_25(ctx),
        26 => reserved_26(ctx),
        27 => reserved_27(ctx),
        28 => reserved_28(ctx),
        29 => reserved_29(ctx),
        30 => security_exception(ctx),
        31 => reserved_31(ctx),
        // Unreachable for a real CPU exception (vectors 0..=31 are the only
        // ones these stubs handle). Reached only if an ISR stub pushes a
        // wrong vector or the IDT points a higher vector at a stub by
        // mistake. `dump_and_panic` reports the complete corrupt frame.
        _ => dump_and_panic(ctx, "UNKNOWN EXCEPTION VECTOR"),
    }
}

// ---------------------------------------------------------------------------
// Helper for the IDT loader: install all 32 exception gates
// ---------------------------------------------------------------------------

/// Install gates for vectors 0..=31 into `idt`, pointing each at the
/// matching `isr_N` stub.
///
/// This is a thin convenience over
/// [`crate::arch::x86_64::idt::Idt::set_interrupt_handler`] that keeps the
/// vector-to-stub mapping in one place. The boot-time entry point
/// [`crate::arch::x86_64::idt::install_exception_handlers`] performs the
/// same installation into the global [`IDT`](crate::arch::x86_64::idt::IDT);
/// this free function is exposed so a test or a per-CPU IDT can install the
/// same gates into a fresh table without going through the global lock.
pub fn install(idt: &mut crate::arch::x86_64::idt::Idt) {
    use crate::arch::x86_64::asm;

    for v in 0u8..crate::arch::x86_64::idt::EXCEPTION_VECTORS as u8 {
        // SAFETY: `asm::isr::entry` is exhaustive over 0..=31 (a match
        // over every stub), so `v` in range yields a real entry pointer.
        let handler = asm::isr::entry(v);
        idt.set_interrupt_handler(u16::from(v), handler);
    }
}
