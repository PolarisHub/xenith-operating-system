/*
 * Xenith x86_64 fast-syscall entry.
 *
 * PerCpuArea offsets are fixed by its repr(C) layout:
 *   gs:24  kernel_rsp
 *   gs:136 reserved[0], used here as the transient user_rsp slot
 *
 * The complete user RSP is copied onto the kernel stack immediately, so the
 * per-CPU scratch slot may safely be reused after a scheduler switch.
 */

    .section .text
    .code64
    .p2align 4
    .global syscall_entry
    .type syscall_entry, @function
    .extern rust_syscall_dispatch

    .equ PERCPU_KERNEL_RSP, 24
    .equ PERCPU_USER_RSP, 136

syscall_entry:
    /* Pull the kernel per-CPU base into GS before any GS-relative access. */
    swapgs
    lfence

    movq %rsp, %gs:PERCPU_USER_RSP
    cmpq $0, %gs:PERCPU_KERNEL_RSP
    je .Lmissing_kernel_stack
    movq %gs:PERCPU_KERNEL_RSP, %rsp
    cld

    /*
     * Save every register userspace expects to survive, plus syscall inputs.
     * Twenty pushes preserve the 16-byte alignment of the kernel stack.
     * The resulting low-to-high frame is:
     * return_rip, return_cs, return_rflags, return_rsp, return_ss,
     * rax, rdi, rsi, rdx, r10, r8, r9, rcx, r11, rbx, rbp,
     * r12, r13, r14, r15.
     */
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %rbp
    pushq %rbx
    pushq %r11
    pushq %rcx
    pushq %r9
    pushq %r8
    pushq %r10
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rax
    pushq $0x33                   /* canonical user SS */
    pushq %gs:PERCPU_USER_RSP
    pushq %r11
    pushq $0x2b                   /* canonical 64-bit user CS */
    pushq %rcx

    movq %rsp, %rbx

    /*
     * SysV argument 7 is a pointer to the saved frame.  One padding qword
     * plus the stack argument preserves the required 16-byte call-site
     * alignment.  Rust reads arg5, RIP, RSP, RFLAGS, and callee-saved GPRs
     * directly from this immutable frame, avoiding a fragile stack-argument
     * shuffle.
     */
    subq $8, %rsp
    pushq %rbx

    movq 40(%rbx), %rdi          /* syscall number */
    movq 48(%rbx), %rsi          /* arg0 */
    movq 56(%rbx), %rdx          /* arg1 */
    movq 64(%rbx), %rcx          /* arg2 */
    movq 72(%rbx), %r8           /* arg3 */
    movq 80(%rbx), %r9           /* arg4 */

    /* The frame is complete, so timer IRQs may preempt the Rust handler. */
    sti
    call rust_syscall_dispatch
    cli

    testq %rax, %rax
    jnz .Lreturn_with_iret

    movq %rbx, %rsp

    /* Preserve the user RSP in per-CPU scratch while restoring GPRs. */
    movq 24(%rsp), %r12
    movq %r12, %gs:PERCPU_USER_RSP
    addq $40, %rsp
    popq %rax
    popq %rdi
    popq %rsi
    popq %rdx
    popq %r10
    popq %r8
    popq %r9
    popq %rcx
    popq %r11
    popq %rbx
    popq %rbp
    popq %r12
    popq %r13
    popq %r14
    popq %r15

    movq %gs:PERCPU_USER_RSP, %rsp
    swapgs
    sysretq

.Lreturn_with_iret:
    /*
     * Caught-signal entry and sigreturn need an exact GPR restore. SYSRET
     * consumes RCX/R11 as RIP/RFLAGS, so Rust instead leaves a complete
     * five-word IRET frame at offsets 0..32 and all GPRs at offsets 40..152.
     * Loading directly relative to RSP keeps the IRET frame in place.
     */
    movq %rbx, %rsp
    movq 40(%rsp), %rax
    movq 48(%rsp), %rdi
    movq 56(%rsp), %rsi
    movq 64(%rsp), %rdx
    movq 72(%rsp), %r10
    movq 80(%rsp), %r8
    movq 88(%rsp), %r9
    movq 96(%rsp), %rcx
    movq 104(%rsp), %r11
    movq 112(%rsp), %rbx
    movq 120(%rsp), %rbp
    movq 128(%rsp), %r12
    movq 136(%rsp), %r13
    movq 144(%rsp), %r14
    movq 152(%rsp), %r15
    swapgs
    iretq

.Lmissing_kernel_stack:
    /* A ring-0 exception cannot safely build a frame on the user stack. */
    cli
.Lmissing_kernel_stack_halt:
    hlt
    jmp .Lmissing_kernel_stack_halt

    .size syscall_entry, .-syscall_entry
