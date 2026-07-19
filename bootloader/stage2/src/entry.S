.section .text.boot,"ax",@progbits
.global _stage2_start
.global e820_count
.type _stage2_start,@function

.set PAGE_PML4,       0x1000
.set PAGE_PDPT_LOW,   0x2000
.set PAGE_PD0,        0x3000
.set PAGE_PD1,        0x4000
.set PAGE_PD2,        0x5000
.set PAGE_PD3,        0x6000
.set PAGE_PDPT_HIGH,  0x7000
.set E820_SEGMENT,    0x5000
.set STACK_TOP,       0x4f000

.code16
_stage2_start:
    cli
    xor ax, ax
    mov ds, ax
    mov ss, ax
    mov sp, 0x7c00
    mov byte ptr [boot_drive], dl

    mov ax, E820_SEGMENT
    mov es, ax
    xor di, di
    xor ebx, ebx
    mov dword ptr [e820_count], 0

.Le820_next:
    mov eax, 0xe820
    mov edx, 0x534d4150
    mov ecx, 24
    mov dword ptr es:[di + 20], 1
    int 0x15
    jc .Le820_done
    cmp eax, 0x534d4150
    jne .Le820_done
    cmp ecx, 20
    jb .Le820_skip
    add di, 24
    inc dword ptr [e820_count]
    cmp dword ptr [e820_count], 128
    jae .Le820_done
.Le820_skip:
    test ebx, ebx
    jne .Le820_next

.Le820_done:
    xor ax, ax
    mov es, ax

    # Request A20 through the BIOS, then assert the fast gate as a hardware fallback.
    mov ax, 0x2401
    int 0x15
    in al, 0x92
    or al, 0x02
    and al, 0xfe
    out 0x92, al
    xor ax, ax
    mov ds, ax

    lgdt [gdt_pointer]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    .byte 0xea
    .word protected_mode
    .word 0x08

.code32
protected_mode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov esp, STACK_TOP

    cld
    xor eax, eax
    mov edi, PAGE_PML4
    mov ecx, (7 * 4096) / 4
    rep stosd

    mov dword ptr [PAGE_PML4 + 0 * 8], PAGE_PDPT_LOW | 3
    mov dword ptr [PAGE_PML4 + 256 * 8], PAGE_PDPT_LOW | 3
    mov dword ptr [PAGE_PML4 + 511 * 8], PAGE_PDPT_HIGH | 3
    mov dword ptr [PAGE_PDPT_LOW + 0 * 8], PAGE_PD0 | 3
    mov dword ptr [PAGE_PDPT_LOW + 1 * 8], PAGE_PD1 | 3
    mov dword ptr [PAGE_PDPT_LOW + 2 * 8], PAGE_PD2 | 3
    mov dword ptr [PAGE_PDPT_LOW + 3 * 8], PAGE_PD3 | 3
    mov dword ptr [PAGE_PDPT_HIGH + 510 * 8], PAGE_PD0 | 3
    mov dword ptr [PAGE_PDPT_HIGH + 511 * 8], PAGE_PD1 | 3

    mov edi, PAGE_PD0
    mov eax, 0x83
    mov ecx, 2048
.Lfill_large_pages:
    mov dword ptr [edi], eax
    mov dword ptr [edi + 4], 0
    add eax, 0x200000
    add edi, 8
    loop .Lfill_large_pages

    mov eax, cr0
    and eax, ~((1 << 2) | (1 << 3))
    or eax, 1 << 1
    mov cr0, eax
    mov eax, cr4
    or eax, (1 << 5) | (1 << 7) | (1 << 9) | (1 << 10)
    mov cr4, eax
    mov ecx, 0xc0000080
    rdmsr
    or eax, 1 << 8
    wrmsr
    mov eax, PAGE_PML4
    mov cr3, eax
    mov eax, cr0
    or eax, 1 << 31
    mov cr0, eax
    .byte 0xea
    .long long_mode
    .word 0x18

.code64
long_mode:
    xor eax, eax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov rsp, STACK_TOP
    xor rbp, rbp
    movzx edi, byte ptr [rip + boot_drive]
    mov esi, dword ptr [rip + e820_count]
    call stage2_main
.Lhalt:
    cli
    hlt
    jmp .Lhalt

.align 8
gdt:
    .quad 0x0000000000000000
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
    .quad 0x00af9a000000ffff
gdt_end:
gdt_pointer:
    .word gdt_end - gdt - 1
    .long gdt

boot_drive:
    .byte 0
.align 4
e820_count:
    .long 0
.size _stage2_start, . - _stage2_start
