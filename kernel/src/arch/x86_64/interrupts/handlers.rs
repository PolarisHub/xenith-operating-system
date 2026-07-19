//! Terminal policy for unrecoverable kernel exceptions.
//!
//! Recoverable user exceptions are translated into POSIX signals by
//! [`super::exceptions`], and bounded user-copy faults use exception-table
//! fixups. Unexpected kernel faults converge on [`dump_and_panic`]: their
//! frames cannot be resumed safely, so the kernel prints everything the CPU
//! supplied and stops the core for diagnosis.
//!
//! # Output path
//!
//! The dump goes through the `log` facade (`::log::error!`) so it lands on
//! every backend the console phase wired up (serial + framebuffer). We do
//! *not* bypass the logger here, unlike the panic handler in
//! [`crate::panic`]: a fault handler runs in a fresh interrupt context, not
//! with the logger lock already held, so re-entrant locking is not a
//! concern. If the logger itself faults, the panic handler's
//! serial-direct path takes over and the dump is still visible there.
//!
//! After the dump, `panic!()` invokes [`crate::panic::handle`], which does
//! its own serial-direct register/stack dump and parks the core. That
//! means a fault is reported twice — once in full structured form through
//! `log::error!` (here) and once through the panic banner (in
//! `panic::handle`). The redundancy is deliberate: in bare-metal bring-up,
//! losing the only fault report to a flaky output surface costs more than
//! the extra serial bandwidth.
//!
//! # Why `dump_and_panic` is `-> !`
//!
//! Once policy classifies an exception as unrecoverable, returning would
//! re-execute the faulting instruction or resume corrupted kernel state.
//! The diverging type makes that terminal decision explicit while the shared
//! dispatcher remains free to return for user signals and copy fixups.

use super::exceptions::ExceptionContext;

// ---------------------------------------------------------------------------
// dump_and_panic
// ---------------------------------------------------------------------------

/// Dump `ctx` to the log and halt the core.
///
/// `name` is the human-readable exception mnemonic and description, e.g.
/// `"#GP General Protection"` or `"#PF Page Fault"`. It is emitted as the
/// first line of the dump so a glance at the log identifies the fault
/// before the register wall.
///
/// # Panics
///
/// Always panics: this function is the terminal step for exceptions that the
/// dispatcher classified as unrecoverable kernel faults.
pub fn dump_and_panic(ctx: &ExceptionContext, name: &str) -> ! {
    // Header: the exception name and vector number. The vector is in the
    // frame so we can cross-check it against the handler that fired.
    ::log::error!(
        "EXCEPTION: {} (vector {}), error_code = {:#018x}",
        name,
        ctx.vector,
        ctx.error_code
    );

    // The CPU-saved control flow state: where the fault happened and where
    // it would resume. Long mode saves RSP/SS on every interrupt frame.
    ::log::error!("  rip   = {:#018x}   cs    = {:#06x}", ctx.rip, ctx.cs);
    let (rsp, ss) = ctx.interrupted_stack();
    ::log::error!(
        "  rflags= {:#018x}   rsp   = {:#018x}   ss = {:#06x}",
        ctx.rflags,
        rsp,
        ss
    );

    // General-purpose registers, in the same order they are laid out in
    // `ExceptionContext` (rax..r15, low to high). Grouping four per line
    // keeps the dump compact while staying greppable.
    ::log::error!(
        "  rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}",
        ctx.rax,
        ctx.rbx,
        ctx.rcx,
        ctx.rdx
    );
    ::log::error!(
        "  rsi={:#018x} rdi={:#018x} rbp={:#018x}",
        ctx.rsi,
        ctx.rdi,
        ctx.rbp
    );
    ::log::error!(
        "  r8 ={:#018x} r9 ={:#018x} r10={:#018x} r11={:#018x}",
        ctx.r8,
        ctx.r9,
        ctx.r10,
        ctx.r11
    );
    ::log::error!(
        "  r12={:#018x} r13={:#018x} r14={:#018x} r15={:#018x}",
        ctx.r12,
        ctx.r13,
        ctx.r14,
        ctx.r15
    );

    // CR2 holds the faulting virtual address for a page fault; for every
    // other exception it is stale, but reading it is cheap and a stale
    // value is harmless (and occasionally informative for a #GP that
    // happened to follow a bad access). We read it lazily here rather than
    // adding it to the frame because it is only meaningful for #PF.
    let cr2: u64;
    // SAFETY: `mov r64, cr2` reads control register 2 in ring 0. It is a
    // non-faulting privileged read; it touches no memory and no flags.
    unsafe {
        core::arch::asm!(
            "mov {cr2}, cr2",
            cr2 = out(reg) cr2,
            options(nostack, preserves_flags),
        );
    }
    ::log::error!(
        "  cr2  = {:#018x}   (faulting address for #PF; stale otherwise)",
        cr2
    );

    // Terminal: hand off to the panic handler, which prints its banner and
    // parks the core with interrupts disabled. Including the exception name
    // and rip in the panic message means the panic banner alone is enough
    // to identify the fault if the structured dump above is lost.
    panic!("{} at rip {:#018x}", name, ctx.rip);
}
