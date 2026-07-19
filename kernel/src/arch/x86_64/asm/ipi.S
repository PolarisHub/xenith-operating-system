/* Fixed IPI entry stubs. See isr.S for the identical GS and frame rules. */

    .section .text
    .code64
    .extern rust_reschedule_interrupt
    .extern rust_tlb_shootdown_interrupt

    .macro XENITH_IPI_STUB name, rust_handler
    .p2align 4
    .global \name
    .type   \name, @function
\name:
    testb   $3, 8(%rsp)
    jz      1f
    swapgs
1:
    cld
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

    movq    %rsp, %rbp
    andq    $-16, %rsp
    call    \rust_handler
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

    testb   $3, 8(%rsp)
    jz      2f
    swapgs
2:
    iretq
    .size   \name, . - \name
    .endm

    XENITH_IPI_STUB reschedule_ipi_isr, rust_reschedule_interrupt
    XENITH_IPI_STUB tlb_shootdown_ipi_isr, rust_tlb_shootdown_interrupt
