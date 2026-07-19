// context_switch.S — the thread context-switch primitive.
//
// `context_switch` is the single point in the kernel where one task's
// callee-saved register file and stack pointer are exchanged for another's.
// It is the lowest layer of the scheduler: every task dispatch eventually
// reduces to a call here, and every task that is not currently running has its
// frozen register state sitting in a `Context` struct waiting to be loaded by
// a future call into this routine.
//
// # Why assembly
//
// The switch touches state Rust cannot express directly: it must rebind the
// stack pointer itself (so the caller's frame is left in place on the old
// stack while execution continues on the new stack), and it must do so without
// a compiler prologue/epilogue touching the stack in between. A Rust `naked`
// function could express this, but keeping it in a `.S` file matches the other
// hand-written entry points (ISR stubs, the syscall gate) and lets the
// scheduler reason about the exact register contract without depending on
// nightly naked-function ABI stability.
//
// # Calling convention
//
// SysV AMD64 ABI:
//     rdi = `*mut Context`   — the task being suspended (the "old" context)
//     rsi = `*const Context` — the task being resumed (the "new" context)
//
// The function has no return value; it returns by `ret`, and the `ret` pops a
// return address off the *new* task's stack. For a freshly created task,
// `Context::new` arranges the new stack so that return address is the task's
// entry point (or a trampoline that drops into it), so the first `ret` into a
// new task lands at its first instruction.
//
// Only the callee-saved registers (rbp, rbx, r12..r15) are saved across the
// switch. The caller-saved set (rax, rcx, rdx, rsi, rdi, r8..r11) is not
// preserved by the SysV ABI across any call, so the scheduler code that calls
// `context_switch` already assumes those are clobbered. RSP is swapped
// explicitly — it is the heart of the switch.
//
// # Context layout (must match `sched::context::Context` exactly)
//
// `Context` is `#[repr(C, align(16))]` and contains only the saved stack
// pointer and callee-saved GPRs. FPU/SIMD state is exchanged by the scheduler's
// TaskNode-owned FpuSaveArea before this routine runs. The offsets used here
// are:
//
//     offset  field          saved register
//     ------  -----------    ---------------
//        0    rsp            stack pointer (swapped, not a GPR save)
//        8    rbx            callee-saved
//       16    rbp            callee-saved (frame pointer)
//       24    r12            callee-saved
//       32    r13            callee-saved
//       40    r14            callee-saved
//       48    r15            callee-saved
//
// Representation padding rounds the 56 bytes of fields up to a 64-byte
// context. Changing field order or offsets requires updating both sides.

    .section .text
    .code64

// Field offsets into `Context`. Kept as named constants rather than magic
// numbers so a future layout change is a single edit here. These mirror the
// field declaration order in `sched::context::Context` and must be updated in
// lock-step with that struct.
#define CTX_RSP          0
#define CTX_RBX          8
#define CTX_RBP          16
#define CTX_R12          24
#define CTX_R13          32
#define CTX_R14          40
#define CTX_R15          48

    .p2align 4
    .global context_switch
    .type   context_switch, @function
context_switch:
    // On entry:
    //   rdi = old Context (the task we are leaving)
    //   rsi = new Context (the task we are resuming)
    //
    // We do not touch the stack pointer until every value we need from the old
    // frame has been written into the old Context, and we do not read anything
    // from the new stack until RSP has been rebound to the new Context. This
    // keeps the old and new stacks non-aliasing from the switch's perspective.

    // ---- save the outgoing task's callee-saved register file ----------------
    //
    // Store each callee-saved GPR into its slot in the old Context. Order does
    // not matter here (every store uses the rdi base, which is stable), but we
    // save rbp/rbx first then r12..r15 to mirror the restore order below and
    // make the symmetry between the two halves obvious when reading.
    movq    %rbp, CTX_RBP(%rdi)
    movq    %rbx, CTX_RBX(%rdi)
    movq    %r12, CTX_R12(%rdi)
    movq    %r13, CTX_R13(%rdi)
    movq    %r14, CTX_R14(%rdi)
    movq    %r15, CTX_R15(%rdi)

    // Capture the current stack pointer into the old Context's rsp slot. This
    // is the single instruction that "freezes" the outgoing task: after this,
    // the old stack is quiescent with a return address on top pointing back
    // into the scheduler, and the task can be resumed by a future call that
    // loads this rsp back.
    movq    %rsp, CTX_RSP(%rdi)

    // ---- rebind the stack to the incoming task ------------------------------
    //
    // This is the switch point. After this instruction the old stack is out of
    // reach and we are running on the new task's stack. rdi and rsi still hold
    // the two Context pointers (they are not on either stack), so the load
    // sequence below can use rsi to pull the new register file.
    movq    CTX_RSP(%rsi), %rsp

    // ---- restore the incoming task's callee-saved register file -------------
    //
    // Load each callee-saved GPR from its slot in the new Context. The order
    // is the reverse of the save order, purely for readability; the only hard
    // requirement is that every callee-saved register is loaded before `ret`,
    // because `ret` will pop the return address off the new stack and transfer
    // control to code that is entitled to assume the SysV callee-saved
    // invariant holds.
    movq    CTX_R15(%rsi), %r15
    movq    CTX_R14(%rsi), %r14
    movq    CTX_R13(%rsi), %r13
    movq    CTX_R12(%rsi), %r12
    movq    CTX_RBX(%rsi), %rbx
    movq    CTX_RBP(%rsi), %rbp

    // Return into the incoming task. The return address was left on the new
    // stack by whoever last ran that task — either the scheduler call that
    // suspended it, or, for a brand-new task, the synthetic frame built by
    // `Context::new` whose top entry is the task entry point.
    ret

    .size   context_switch, . - context_switch
