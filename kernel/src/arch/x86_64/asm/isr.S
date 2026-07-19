// isr.S — CPU exception entry stubs for vectors 0..31.
//
// Each `isr_N` symbol is the target of the matching IDT gate descriptor for
// CPU exception vector N (#DE, #DB, NMI, ..., #GP, #PF, ..., reserved). The
// stubs are *not* functions in the SysV sense: they are reached only by the
// CPU pushing an interrupt frame onto the stack and jumping to the gate's
// handler address. Their job is to normalise the vector/error-code prefix,
// save the GPRs for the shared Rust dispatch routine to read through
// `ExceptionContext`, then `iretq` back. Most exceptions are fatal; a page
// fault inside the bounded user-copy loops is redirected to an EFAULT fixup.
//
// # Stack frame contract
//
// In 64-bit mode the CPU always pushes (low address first, i.e. the order
// `iretq` will pop):
//
//     [rsp+0]  rip      (the faulting instruction)
//     [rsp+8]  cs
//     [rsp+16] rflags
//     [rsp+24] rsp      (the pre-fault stack pointer)
//     [rsp+32] ss
//
// For the seven "error code" exceptions (#DF=8, #TS=10, #NP=11, #SS=12,
// #GP=13, #PF=14, #AC=17) the CPU additionally pushes a 64-bit error code
// below `rip`, so the frame is shifted down by 8 bytes and `[rsp+0]` is the
// error code rather than `rip`. Every other exception pushes no error code.
//
// To give the Rust side a uniform layout, the no-error stubs push a
// synthetic `0` error code so that *every* stub leaves the stack as:
//
//     [rsp+0]  error_code   (real or synthetic 0)
//     [rsp+8]  rip
//     ...
//
// The stub then pushes the vector number, and `isr_common` pushes the
// general-purpose registers. The final frame, from low to high address, has
// these offsets (see `interrupts/exceptions.rs`):
//
//     rax, rbx, rcx, rdx, rsi, rdi, rbp,
//     r8, r9, r10, r11, r12, r13, r14, r15,
//     vector, error_code,
//     rip, cs, rflags, rsp, ss
//
// `isr_common` passes a pointer to the bottom of this frame (the saved
// `rax`) to `rust_isr_dispatch` in `rdi` per the SysV AMD64 ABI, after
// 16-byte-aligning the stack as the ABI requires.
//
// # Gate type
//
// The IDT loader installs these as 64-bit interrupt gates (type 0xE). An
// interrupt gate clears EFLAGS.IF on entry, so the handler runs with
// maskable interrupts off — we do not need an explicit `cli` here. `iretq`
// restores the saved RFLAGS, re-enabling interrupts if they were on before
// the fault.
//
// # Error-code vector set
//
// Only {8, 10, 11, 12, 13, 14, 17} push a real error code. The newer
// CET/SEV-class vectors (21, 28, 29, 30) may push error codes on parts that
// enable those features; Xenith does not enable CET/SEV at boot, so they
// are treated as no-error here. If a future phase enables CET, vector 21's
// stub must switch to the ERR macro.

    .section .text
    .code64

// ---------------------------------------------------------------------------
// Stub emitters
// ---------------------------------------------------------------------------

// ISR_NOERR n: for exceptions that do NOT push an error code.
//
// Push a synthetic 0 so the frame matches the error-code case, push the
// vector number, and tail-call the common trampoline. Using `jmp` (not
// `call`) keeps the stack frame free of an extra return address.
    .macro ISR_NOERR n
    .global isr_\n
    .type   isr_\n, @function
isr_\n:
    pushq   $0              // synthetic error code
    pushq   $\n             // vector number
    jmp     isr_common
    .endm

// ISR_ERR n: for exceptions that DO push an error code (#DF, #TS, #NP, #SS,
// #GP, #PF, #AC). The CPU's error code is already on top of the stack; only
// the vector number needs to be pushed.
    .macro ISR_ERR n
    .global isr_\n
    .type   isr_\n, @function
isr_\n:
    pushq   $\n             // vector number (error code already pushed by CPU)
    jmp     isr_common
    .endm

// ---------------------------------------------------------------------------
// The 32 exception entry points
// ---------------------------------------------------------------------------

    ISR_NOERR 0     // #DE  divide error
    ISR_NOERR 1     // #DB  debug
    ISR_NOERR 2     // NMI
    ISR_NOERR 3     // #BP  breakpoint
    ISR_NOERR 4     // #OF  overflow
    ISR_NOERR 5     // #BR  bound range exceeded
    ISR_NOERR 6     // #UD  invalid opcode
    ISR_NOERR 7     // #NM  device not available
    ISR_ERR   8     // #DF  double fault (error code always 0)
    ISR_NOERR 9     // coprocessor segment overrun (reserved on modern CPUs)
    ISR_ERR   10    // #TS  invalid TSS
    ISR_ERR   11    // #NP  segment not present
    ISR_ERR   12    // #SS  stack-segment fault
    ISR_ERR   13    // #GP  general protection
    ISR_ERR   14    // #PF  page fault
    ISR_NOERR 15    // reserved
    ISR_NOERR 16    // #MF  x87 floating-point error
    ISR_ERR   17    // #AC  alignment check (error code always 0)
    ISR_NOERR 18    // #MC  machine check
    ISR_NOERR 19    // #XM  SIMD floating-point exception
    ISR_NOERR 20    // #VE  virtualization exception
    ISR_NOERR 21    // reserved (CET #CP if CET enabled — see file header)
    ISR_NOERR 22    // reserved
    ISR_NOERR 23    // reserved
    ISR_NOERR 24    // reserved
    ISR_NOERR 25    // reserved
    ISR_NOERR 26    // reserved
    ISR_NOERR 27    // reserved
    ISR_NOERR 28    // reserved
    ISR_NOERR 29    // reserved
    ISR_NOERR 30    // #SX  security exception (AMD; no error code without SEV)
    ISR_NOERR 31    // reserved

// ---------------------------------------------------------------------------
// Common trampoline
// ---------------------------------------------------------------------------

    .p2align 4
    .type   isr_common, @function
isr_common:
    // At common-entry rsp points at the stub-pushed vector, hence saved CS is
    // at +24 (vector, error code, RIP, then CS). Require both RPL bits so only
    // ring 3 pulls the kernel per-CPU base into GS before Rust can use
    // gs-relative state. The tests touch no GPR and the interrupted RFLAGS
    // already live in the CPU frame.
    testb   $1, 24(%rsp)
    jz      .Lisr_frame_ready
    testb   $2, 24(%rsp)
    jz      .Lisr_frame_ready
    swapgs

.Lisr_frame_ready:
    // The SysV AMD64 ABI requires the direction flag to be clear on entry
    // to any function. The interrupted code may have set it (rare in kernel
    // code, but cheap to defend against), so clear it before any rep-string
    // work happens inside the Rust handler.
    cld

    // Save the full general-purpose register file. Push in *reverse* order
    // (r15 first, rax last) so that, with the stack growing down, the saved
    // rax ends up at the lowest address and the frame reads rax..r15 from
    // low to high — matching the field order of `ExceptionContext`.
    pushq   %r15
    pushq   %r14
    pushq   %r13
    pushq   %r12
    pushq   %r11
    pushq   %r10
    pushq   %r9
    pushq   %r8
    pushq   %rbp
    pushq   %rdi
    pushq   %rsi
    pushq   %rdx
    pushq   %rcx
    pushq   %rbx
    pushq   %rax

    // rbp is callee-saved by the SysV ABI, so it survives the call below.
    // Stash the frame pointer (the address of the saved rax, i.e.
    // &ExceptionContext) in rbp now, then 16-byte-align rsp for the call.
    // We cannot keep the frame pointer in rsp because the alignment `and`
    // would move it; rbp is the stable handle.
    movq    %rsp, %rbp

    // Align the stack to 16 bytes. The SysV ABI requires rsp % 16 == 0
    // immediately before a `call` (so that rsp % 16 == 8 inside the callee,
    // after the return address is pushed). The pre-fault rsp alignment is
    // unknowable, so we align defensively. Our target disables SSE so a
    // misalignment would not fault, but alignment is still required for any
    // future aligned-move the compiler may emit.
    andq    $-16, %rsp

    // First SysV argument (rdi) = pointer to the ExceptionContext frame.
    movq    %rbp, %rdi

    // Dispatch to the Rust side. Returning means a user-copy fault was fixed
    // up or a recoverable user exception rewrote the frame for signal entry.
    call    rust_isr_dispatch

    // Restore rsp from the callee-saved frame pointer, then pop the register
    // file in the opposite order it was pushed.
    movq    %rbp, %rsp
    popq    %rax
    popq    %rbx
    popq    %rcx
    popq    %rdx
    popq    %rsi
    popq    %rdi
    popq    %rbp
    popq    %r8
    popq    %r9
    popq    %r10
    popq    %r11
    popq    %r12
    popq    %r13
    popq    %r14
    popq    %r15

    // Discard the vector number and the (real or synthetic) error code so
    // rsp points at the untouched hardware iret frame. Saved CS is now at +8.
    addq    $16, %rsp

    // A user return must restore the user GS base immediately before iretq.
    // Same-CPL frames leave GS untouched; IRETQ pops the five-word long-mode
    // frame, including RSP/SS, regardless of whether privilege changed.
    testb   $1, 8(%rsp)
    jz      .Lisr_iret
    testb   $2, 8(%rsp)
    jz      .Lisr_iret
    swapgs

.Lisr_iret:
    iretq

    .size   isr_common, . - isr_common

// ---------------------------------------------------------------------------
// Local-APIC timer interrupt entry
// ---------------------------------------------------------------------------
//
// Unlike the exception stubs above, this handler returns normally after the
// scheduler tick has been accounted (possibly after spending time switched
// out on this task's kernel stack).  The CPU frame always places the saved CS
// at [rsp+8], both for same-CPL and privilege-changing entries.  Testing its
// RPL lets us swap the kernel GS base in only for interrupts taken from ring 3
// and swap the user GS base back immediately before iretq.  Kernel-mode timer
// interrupts leave GS untouched.
//
// The complete GPR file is retained on the interrupted task's kernel stack.
// If rust_timer_interrupt preempts the task, context_switch saves the Rust
// call chain's rsp; switching back later resumes this call and then restores
// the exact interrupted register/iret frame below.
    .p2align 4
    .global lapic_timer_isr
    .type   lapic_timer_isr, @function
lapic_timer_isr:
    // A saved CS with RPL 3 means the active GS base belongs to userspace.
    // Pull the kernel per-CPU base into IA32_GS_BASE before any Rust code can
    // use gs-relative state.  For a kernel interruption GS is already right.
    testb   $3, 8(%rsp)
    jz      1f
    swapgs
1:
    cld

    // Add the same vector/error prefix used by exception entry so Rust sees
    // a complete mutable ExceptionContext and may rewrite the return frame
    // for a caught signal. The concrete vector is diagnostic only here.
    pushq   $0
    pushq   $0xfd

    // Preserve every user/kernel-visible general-purpose register.  The push
    // order mirrors isr_common so rsp points at saved rax after the last push.
    pushq   %r15
    pushq   %r14
    pushq   %r13
    pushq   %r12
    pushq   %r11
    pushq   %r10
    pushq   %r9
    pushq   %r8
    pushq   %rbp
    pushq   %rdi
    pushq   %rsi
    pushq   %rdx
    pushq   %rcx
    pushq   %rbx
    pushq   %rax

    // Keep the unaligned frame address in callee-saved rbp while satisfying
    // the SysV call-site alignment rule for the Rust handler.
    movq    %rsp, %rbp
    andq    $-16, %rsp
    movq    %rbp, %rdi
    call    rust_timer_interrupt
    movq    %rbp, %rsp

    popq    %rax
    popq    %rbx
    popq    %rcx
    popq    %rdx
    popq    %rsi
    popq    %rdi
    popq    %rbp
    popq    %r8
    popq    %r9
    popq    %r10
    popq    %r11
    popq    %r12
    popq    %r13
    popq    %r14
    popq    %r15

    // Discard the synthetic vector/error pair; rsp is now the CPU IRET frame.
    addq    $16, %rsp

    // rsp once again points at the CPU frame. Undo the entry swap only when
    // returning to ring 3; IRETQ restores the complete five-word frame for
    // both same-CPL and privilege-changing entries.
    testb   $3, 8(%rsp)
    jz      2f
    swapgs
2:
    iretq

    .size   lapic_timer_isr, . - lapic_timer_isr
