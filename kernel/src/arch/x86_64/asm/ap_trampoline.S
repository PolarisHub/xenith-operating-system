/*
 * AP startup trampoline.
 *
 * The SMP layer copies this complete, relocation-free block into one reserved
 * low physical page, repatches it serially for each AP, and issues
 * INIT-SIPI-SIPI. The AP enters at offset zero in 16-bit real mode, enables
 * PAE + long mode against the BSP page tables, and jumps to the Rust AP entry
 * on a permanent high-half bootstrap stack.
 */

    .section .text
    .code16
    .p2align 4
    .global ap_trampoline_start
    .global ap_trampoline_end
    .global ap_trampoline_long_mode
    .global ap_trampoline_cr3
    .global ap_trampoline_stack
    .global ap_trampoline_entry
    .global ap_trampoline_cpu_id
    .global ap_trampoline_apic_id
    .global ap_trampoline_gdt
    .global ap_trampoline_gdtr_base
    .global ap_trampoline_far_target
    .type ap_trampoline_start, @function

ap_trampoline_start:
    cli
    cld

    /* Make local data offsets relative to the SIPI page's CS base. */
    movw    %cs, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss

    /* Load the copied page's temporary flat GDT. */
    lgdtl   (ap_trampoline_gdtr - ap_trampoline_start)

    /* PAE is mandatory before IA-32e paging can be enabled. */
    movl    %cr4, %eax
    orl     $0x20, %eax
    movl    %eax, %cr4

    /* The transition root is constrained below 4 GiB by the Rust side. */
    movl    (ap_trampoline_cr3 - ap_trampoline_start), %eax
    movl    %eax, %cr3

    /*
     * EFER.LME is mandatory. Enable EFER.NXE when this AP advertises it;
     * Xenith rejects a non-NX CPU in early_init, but probing here is required
     * because this WRMSR runs before the Rust-side check can execute.
     */
    movl    $0x100, %esi
    movl    $0x80000000, %eax
    cpuid
    cmpl    $0x80000001, %eax
    jb      1f
    movl    $0x80000001, %eax
    cpuid
    testl   $0x00100000, %edx
    jz      1f
    orl     $0x800, %esi
1:
    movl    $0xc0000080, %ecx
    rdmsr
    orl     %esi, %eax
    wrmsr

    /* CR0.PE | CR0.MP | CR0.NE | CR0.WP | CR0.PG. */
    movl    %cr0, %eax
    orl     $0x80010023, %eax
    movl    %eax, %cr0

    /* The patched far pointer contains identity-mapped linear RIP + CS. */
    ljmpl   *(ap_trampoline_far_pointer - ap_trampoline_start)

    .code64
ap_trampoline_long_mode:
    movw    $0x10, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss
    movw    %ax, %fs
    movw    %ax, %gs

    movq    ap_trampoline_stack(%rip), %rsp
    andq    $-16, %rsp
    subq    $8, %rsp
    movq    $0, (%rsp)
    xorq    %rbp, %rbp

    movl    ap_trampoline_cpu_id(%rip), %edi
    movl    ap_trampoline_apic_id(%rip), %esi
    movq    ap_trampoline_entry(%rip), %rax
    jmp     *%rax

    /* Temporary flat GDT: null, 64-bit kernel code, kernel data. */
    .p2align 3
ap_trampoline_gdt:
    .quad   0x0000000000000000
    .quad   0x00af9a000000ffff
    .quad   0x00cf92000000ffff
ap_trampoline_gdt_end:

    /* 16-bit LGDT consumes a 16-bit limit and a 32-bit linear base. */
ap_trampoline_gdtr:
    .word   ap_trampoline_gdt_end - ap_trampoline_gdt - 1
ap_trampoline_gdtr_base:
    .long   0

ap_trampoline_far_pointer:
ap_trampoline_far_target:
    .long   0
    .word   0x08

    .p2align 3
ap_trampoline_cr3:
    .quad   0
ap_trampoline_stack:
    .quad   0
ap_trampoline_entry:
    .quad   0
ap_trampoline_cpu_id:
    .long   0
ap_trampoline_apic_id:
    .long   0

ap_trampoline_end:
    .size ap_trampoline_start, ap_trampoline_end - ap_trampoline_start
    .code64
