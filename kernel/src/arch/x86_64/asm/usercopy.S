/*
 * Fault-recoverable user-memory copies.
 *
 * The page-fault handler recognizes RIPs inside the two marked copy regions
 * and redirects execution to the matching fixup label.  This is the same
 * exception-table pattern used by mature kernels: a bad userspace mapping
 * becomes -EFAULT instead of a ring-0 panic.  The Rust caller validates the
 * complete range and pins CR3 before entering these routines; the fixup is
 * the final defence against a stale/corrupt mapping or a future SMP race.
 *
 * SysV arguments:
 *   rdi = destination, rsi = source, rdx = byte count, rcx = SMAP enabled
 * Return:
 *   eax = 0 on success, -1 after a recovered page fault.
 */

    .section .text
    .code64

    .p2align 4
    .global xenith_copy_from_user_asm
    .global xenith_copy_from_user_start
    .global xenith_copy_from_user_end
    .global xenith_copy_from_user_fixup
    .type xenith_copy_from_user_asm, @function
xenith_copy_from_user_asm:
    cld
    movq %rcx, %r8
    movq %rdx, %rcx
    testq %r8, %r8
    jz 1f
    stac
1:
xenith_copy_from_user_start:
    rep movsb
xenith_copy_from_user_end:
    testq %r8, %r8
    jz 2f
    clac
2:
    xorl %eax, %eax
    ret
xenith_copy_from_user_fixup:
    testq %r8, %r8
    jz 3f
    clac
3:
    movl $-1, %eax
    ret
    .size xenith_copy_from_user_asm, . - xenith_copy_from_user_asm

    .p2align 4
    .global xenith_copy_to_user_asm
    .global xenith_copy_to_user_start
    .global xenith_copy_to_user_end
    .global xenith_copy_to_user_fixup
    .type xenith_copy_to_user_asm, @function
xenith_copy_to_user_asm:
    cld
    movq %rcx, %r8
    movq %rdx, %rcx
    testq %r8, %r8
    jz 4f
    stac
4:
xenith_copy_to_user_start:
    rep movsb
xenith_copy_to_user_end:
    testq %r8, %r8
    jz 5f
    clac
5:
    xorl %eax, %eax
    ret
xenith_copy_to_user_fixup:
    testq %r8, %r8
    jz 6f
    clac
6:
    movl $-1, %eax
    ret
    .size xenith_copy_to_user_asm, . - xenith_copy_to_user_asm
