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
// `Context` is `#[repr(C, align(16))]` with the GPR fields first and the
// 512-byte FXSAVE area placed at a 16-byte-aligned offset so `fxsave`/`fxrstor`
// can target it without a #GP on alignment. The offsets used here are:
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
//       56    (pad)          alignment padding to reach offset 64
//       64    fxsave_area    512-byte FXSAVE/FXRSTOR image (16-aligned)
//
// The pad at offset 56 exists only so `fxsave_area` lands on a 16-byte
// boundary (64 % 16 == 0). The GPR fields themselves are 8-byte-aligned, which
// is all `movq` requires. Changing the field order or removing the pad breaks
// the offset constants below and faults the FPU save path; update both sides
// together.
//
// # FPU / SIMD state
//
// Saving the full x87/SSE state on every switch is expensive (512+ bytes of
// memory traffic) and unnecessary for tasks that have not touched the FPU. The
// kernel therefore takes the classic lazy-FPU approach by default: the
// `fxsave_area` is part of every `Context` but the switch itself does *not*
// touch it. The FPU state is only saved/restored when a task actually uses the
// FPU, driven by the `#NM` (device-not-available) handler in a later phase
// that sets CR0.TS around the switch.
//
// For testing and for the eventual ring-3 userspace path where eager FPU
// save/restore is simpler to reason about, the `fxsave`/`fxrstor` pair can be
// compiled in by defining `XENITH_CTX_FPU` for the assembler (pass
// `-DXENITH_CTX_FPU` through `build.rs`). The `.S` extension runs the file
// through the C preprocessor, so the `#ifdef` below is honoured. With the flag
// unset the FPU instructions are omitted entirely and the `fxsave_area` is
// left untouched by the switch (the lazy path owns it).
//
// When the FPU path is enabled, `fxsave` is issued against the OLD context
// before the stack pointer is rebound, and `fxrstor` is issued against the NEW
// context after the new GPRs are loaded. Both use the `%rdi`/`%rsi` base
// pointers, which are stable across the stack swap (they live in registers,
// not on the stack). The `fxsave_area` offset (64) is 16-byte-aligned because
// `Context` is `align(16)` and the field sits at offset 64; `fxsave`/`fxrstor`
// require 16-byte alignment of their operand or they #GP.

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
#define CTX_FXSAVE_AREA  64

// The FXSAVE/FXRSTOR area requires 16-byte alignment. This is a build-time
// assert that the chosen offset is 16-aligned; if a future edit moves the
// field, the assembler fails here instead of producing an image that #GPs at
// runtime on the first FPU-using task.
.macro ctassert_fpu_align
.if (CTX_FXSAVE_AREA & 0xF) != 0
.error "CTX_FXSAVE_AREA must be 16-byte aligned for fxsave/fxrstor"
.endif
.endm

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

#ifdef XENITH_CTX_FPU
    // Eager FPU save: dump the outgoing task's x87/SSE state into its
    // fxsave_area before we leave its address space of registers. `fxsave`
    // writes 512 bytes to [rdi + CTX_FXSAVE_AREA]; the area is 16-aligned (see
    // the layout note above). We do this after the GPR saves and the RSP
    // capture but before the stack swap, so the old Context is fully populated
    // before we stop touching old-owned memory.
    .ctassert_fpu_align
    fxsave  CTX_FXSAVE_AREA(%rdi)
#endif

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

#ifdef XENITH_CTX_FPU
    // Eager FPU restore: load the incoming task's x87/SSE state from its
    // fxsave_area. `fxrstor` reads 512 bytes from [rsi + CTX_FXSAVE_AREA]; the
    // area is 16-aligned. Done after the GPR restore so a fault here (which
    // would indicate a corrupted save area, not normal operation) still leaves
    // the integer register file consistent for the fault handler.
    fxrstor CTX_FXSAVE_AREA(%rsi)
#endif

    // Return into the incoming task. The return address was left on the new
    // stack by whoever last ran that task — either the scheduler call that
    // suspended it, or, for a brand-new task, the synthetic frame built by
    // `Context::new` whose top entry is the task entry point.
    ret

    .size   context_switch, . - context_switch
