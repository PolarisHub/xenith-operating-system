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
.set MANIFEST_BUFFER, 0x0600
.set KERNEL_ENTRY,    MANIFEST_BUFFER + 128
.set INITRD_ENTRY,    MANIFEST_BUFFER + 192
.set KERNEL_STAGING,  0x01000000
.set INITRD_STAGING,  0x02000000
.set KERNEL_SECTORS_MAX, 65536
.set INITRD_SECTORS_MAX, 131072
.set EDD_BOUNCE_SEGMENT, 0x7000
.set EDD_BOUNCE_SECTORS, 64
.set VBE_CONTROLLER_INFO, 0x0800
.set VBE_MODE_INFO,       0x0a00

.code16
_stage2_start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov esp, 0x7c00
    mov byte ptr [boot_drive], dl

    # Payload access must remain on the firmware-provided boot drive.  This is
    # especially important for El Torito hard-disk emulation: the virtual disk
    # exists behind INT 13h but is not necessarily a primary-master ATA device.
    # Enable A20 before copying conventional-memory EDD reads into the high
    # staging buffers, and retain the old ATA path as a fallback for firmware
    # that cannot service the standard packet-read interface.
    mov ax, 0x2401
    int 0x15
    in al, 0x92
    or al, 0x02
    and al, 0xfe
    out 0x92, al
    xor ax, ax
    mov ds, ax

    call init_bios_disk
    mov byte ptr [bios_preload_status], 0
    mov byte ptr [bios_preload_error], 0
    call preload_payloads
    jc .Lpreload_done
    mov byte ptr [bios_preload_status], 1
.Lpreload_done:
    # Graphics is optional.  A failed or absent VBE implementation leaves the
    # zeroed framebuffer descriptor in place and the kernel uses VGA text.
    call vbe_init

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
    .word 0x28

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
    movzx edx, byte ptr [rip + bios_preload_status]
    call stage2_main
.Lhalt:
    cli
    hlt
    jmp .Lhalt

.code16
# Copy the conventional-memory bounce buffer to its high staging destination.
# Each invocation performs complete real -> protected32 -> protected16 -> real
# transitions, so no unreal-mode segment cache has to survive a BIOS call.
copy_bounce_to_high:
    cli
    lgdt [gdt_pointer]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    .byte 0xea
    .word .Lcopy_protected32
    .word 0x08

.code32
.Lcopy_protected32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov esi, EDD_BOUNCE_SEGMENT << 4
    mov edi, dword ptr [read_destination]
    movzx ecx, word ptr [read_chunk]
    shl ecx, 7
    cld
    rep movsd
    mov dword ptr [read_destination], edi
    .byte 0xea
    .long .Lcopy_protected16
    .word 0x18

.code16
.Lcopy_protected16:
    mov ax, 0x20
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov eax, cr0
    and eax, ~1
    mov cr0, eax
    .byte 0xea
    .word .Lcopy_real
    .word 0

.Lcopy_real:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    ret

# Load one manifest entry through standard INT 13h packet reads.  SI addresses
# the entry, EDI is its fixed high-memory staging destination, and EBX is the
# maximum accepted sector count.  Each read lands in a 32-KiB conventional
# bounce buffer and is copied above 1 MiB in a bounded protected-mode window.
read_manifest_entry:
    cmp dword ptr [si + 20], 0
    jne .Lread_fail
    mov eax, dword ptr [si + 16]
    test eax, eax
    jz .Lread_fail
    cmp eax, ebx
    ja .Lread_fail
    mov dword ptr [read_remaining], eax
    mov eax, dword ptr [si + 8]
    mov dword ptr [edd_packet + 8], eax
    mov eax, dword ptr [si + 12]
    mov dword ptr [edd_packet + 12], eax
    mov dword ptr [read_destination], edi

.Lread_next:
    mov eax, dword ptr [read_remaining]
    test eax, eax
    jz .Lread_done
    cmp eax, EDD_BOUNCE_SECTORS
    jbe .Lread_chunk_ready
    mov eax, EDD_BOUNCE_SECTORS
.Lread_chunk_ready:
    mov word ptr [read_chunk], ax
    cmp byte ptr [bios_disk_mode], 1
    jne .Lread_chs
    mov word ptr [edd_packet + 2], ax
    mov si, offset edd_packet
    mov dl, byte ptr [boot_drive]
    mov ah, 0x42
    sti
    int 0x13
    cli
    jnc .Lread_copy
    call init_chs_disk
    cmp byte ptr [bios_disk_mode], 2
    jne .Lread_fail
.Lread_chs:
    cmp byte ptr [bios_disk_mode], 2
    jne .Lread_no_disk_mode
    call chs_read_chunk
    jc .Lread_fail

.Lread_copy:
    call copy_bounce_to_high

    movzx eax, word ptr [read_chunk]
    add dword ptr [edd_packet + 8], eax
    adc dword ptr [edd_packet + 12], 0
    sub dword ptr [read_remaining], eax
    jmp .Lread_next

.Lread_done:
    clc
    ret
.Lread_no_disk_mode:
    mov byte ptr [bios_preload_error], 2
.Lread_fail:
    cmp byte ptr [bios_preload_error], 0
    jne .Lread_fail_ready
    mov byte ptr [bios_preload_error], 1
.Lread_fail_ready:
    stc
    ret

preload_payloads:
    cmp dword ptr [KERNEL_ENTRY], 2
    jne .Lpreload_fail
    cmp dword ptr [INITRD_ENTRY], 3
    jne .Lpreload_fail

    mov si, KERNEL_ENTRY
    mov edi, KERNEL_STAGING
    mov ebx, KERNEL_SECTORS_MAX
    call read_manifest_entry
    jc .Lpreload_fail

    mov si, INITRD_ENTRY
    mov edi, INITRD_STAGING
    mov ebx, INITRD_SECTORS_MAX
    call read_manifest_entry
    jc .Lpreload_fail
    clc
    ret
.Lpreload_fail:
    stc
    ret

# Prefer EDD packet reads.  El Torito hard-disk emulation on older SeaBIOS
# exposes only the original CHS interface, so retain validated geometry for a
# sector-at-a-time fallback on the same firmware-provided DL.
init_bios_disk:
    mov byte ptr [bios_disk_mode], 0
    mov bx, 0x55aa
    mov dl, byte ptr [boot_drive]
    mov ah, 0x41
    sti
    int 0x13
    cli
    jc init_chs_disk
    cmp bx, 0xaa55
    jne init_chs_disk
    test cx, 1
    jz init_chs_disk
    mov byte ptr [bios_disk_mode], 1
    ret

init_chs_disk:
    mov byte ptr [bios_disk_mode], 0
    mov dl, byte ptr [boot_drive]
    mov ah, 0x08
    sti
    int 0x13
    cli
    jc .Lchs_init_done
    mov al, cl
    and al, 0x3f
    jz .Lchs_init_done
    mov byte ptr [chs_sectors_per_track], al
    xor ax, ax
    mov al, dh
    inc ax
    mov word ptr [chs_head_count], ax
    mov byte ptr [bios_disk_mode], 2
.Lchs_init_done:
    ret

# Read `read_chunk` sectors beginning at the DAP LBA into the conventional
# bounce buffer with legacy CHS function 02h, servicing the chunk as individual
# sectors so no request crosses a track or 64-KiB DMA boundary.
chs_read_chunk:
    cmp dword ptr [edd_packet + 12], 0
    jne .Lchs_high_lba
    mov eax, dword ptr [edd_packet + 8]
    mov dword ptr [chs_lba], eax
    mov ax, word ptr [read_chunk]
    mov word ptr [chs_remaining], ax
    mov word ptr [chs_buffer_offset], 0

.Lchs_read_next:
    cmp word ptr [chs_remaining], 0
    je .Lchs_read_done
    mov byte ptr [chs_retries], 3
.Lchs_read_attempt:
    mov eax, dword ptr [chs_lba]
    xor edx, edx
    movzx ecx, byte ptr [chs_sectors_per_track]
    div ecx
    inc dl
    mov byte ptr [chs_sector], dl
    xor edx, edx
    movzx ecx, word ptr [chs_head_count]
    div ecx
    cmp eax, 1023
    ja .Lchs_bad_cylinder
    mov ch, al
    shr eax, 2
    and al, 0xc0
    mov cl, byte ptr [chs_sector]
    or cl, al
    mov dh, dl
    mov dl, byte ptr [boot_drive]
    mov bx, word ptr [chs_buffer_offset]
    mov ax, EDD_BOUNCE_SEGMENT
    mov es, ax
    mov ax, 0x0201
    sti
    int 0x13
    cli
    jnc .Lchs_sector_ready
    dec byte ptr [chs_retries]
    jz .Lchs_bios_error
    mov dl, byte ptr [boot_drive]
    xor ax, ax
    sti
    int 0x13
    cli
    jmp .Lchs_read_attempt
.Lchs_sector_ready:
    inc dword ptr [chs_lba]
    add word ptr [chs_buffer_offset], 512
    dec word ptr [chs_remaining]
    jmp .Lchs_read_next

.Lchs_read_done:
    xor ax, ax
    mov es, ax
    clc
    ret
.Lchs_bios_error:
    mov byte ptr [chs_status], ah
    mov byte ptr [bios_preload_error], 5
    xor ax, ax
    mov es, ax
.Lchs_read_fail:
    stc
    ret
.Lchs_high_lba:
    mov byte ptr [bios_preload_error], 3
    jmp .Lchs_read_fail
.Lchs_bad_cylinder:
    mov byte ptr [bios_preload_error], 4
    jmp .Lchs_read_fail

# Discover a supported 32-bpp direct-color linear framebuffer, preferring the
# largest mode not exceeding 1024x768.  All VBE calls are made while still in
# real mode; only the resulting physical LFB descriptor crosses into Rust.
vbe_init:
    xor ax, ax
    mov es, ax
    mov dword ptr [VBE_CONTROLLER_INFO], 0x32454256 # "VBE2"
    mov di, VBE_CONTROLLER_INFO
    mov ax, 0x4f00
    int 0x10
    cmp ax, 0x004f
    jne .Lvbe_fail
    cmp dword ptr [VBE_CONTROLLER_INFO], 0x41534556 # "VESA"
    jne .Lvbe_fail

    mov ax, word ptr [VBE_CONTROLLER_INFO + 0x0e]
    mov word ptr [vbe_mode_offset], ax
    mov ax, word ptr [VBE_CONTROLLER_INFO + 0x10]
    mov word ptr [vbe_mode_segment], ax
    mov word ptr [vbe_selected_mode], 0xffff
    mov word ptr [vbe_selected_width], 0
    mov word ptr [vbe_selected_height], 0
    mov word ptr [vbe_modes_left], 512

.Lvbe_next_mode:
    cmp word ptr [vbe_modes_left], 0
    je .Lvbe_set_selected
    dec word ptr [vbe_modes_left]
    mov ax, word ptr [vbe_mode_segment]
    mov fs, ax
    mov si, word ptr [vbe_mode_offset]
    mov cx, word ptr fs:[si]
    add word ptr [vbe_mode_offset], 2
    jnc .Lvbe_pointer_ready
    add word ptr [vbe_mode_segment], 0x1000
.Lvbe_pointer_ready:
    cmp cx, 0xffff
    je .Lvbe_set_selected
    mov word ptr [vbe_candidate_mode], cx

    xor ax, ax
    mov es, ax
    mov di, VBE_MODE_INFO
    mov ax, 0x4f01
    int 0x10
    cmp ax, 0x004f
    jne .Lvbe_next_mode
    mov ax, word ptr [VBE_MODE_INFO]
    and ax, 0x0091
    cmp ax, 0x0091
    jne .Lvbe_next_mode
    cmp byte ptr [VBE_MODE_INFO + 0x19], 32
    jne .Lvbe_next_mode
    cmp byte ptr [VBE_MODE_INFO + 0x1b], 6
    jne .Lvbe_next_mode
    cmp dword ptr [VBE_MODE_INFO + 0x28], 0
    je .Lvbe_next_mode
    cmp word ptr [VBE_MODE_INFO + 0x12], 640
    jb .Lvbe_next_mode
    cmp word ptr [VBE_MODE_INFO + 0x14], 480
    jb .Lvbe_next_mode
    cmp word ptr [VBE_MODE_INFO + 0x12], 1024
    ja .Lvbe_next_mode
    cmp word ptr [VBE_MODE_INFO + 0x14], 768
    ja .Lvbe_next_mode

    mov ax, word ptr [VBE_MODE_INFO + 0x12]
    cmp ax, word ptr [vbe_selected_width]
    jb .Lvbe_next_mode
    ja .Lvbe_choose_mode
    mov ax, word ptr [VBE_MODE_INFO + 0x14]
    cmp ax, word ptr [vbe_selected_height]
    jbe .Lvbe_next_mode
.Lvbe_choose_mode:
    mov ax, word ptr [vbe_candidate_mode]
    mov word ptr [vbe_selected_mode], ax
    mov ax, word ptr [VBE_MODE_INFO + 0x12]
    mov word ptr [vbe_selected_width], ax
    mov ax, word ptr [VBE_MODE_INFO + 0x14]
    mov word ptr [vbe_selected_height], ax
    cmp word ptr [vbe_selected_width], 1024
    jne .Lvbe_next_mode
    cmp word ptr [vbe_selected_height], 768
    jne .Lvbe_next_mode

.Lvbe_set_selected:
    mov bx, word ptr [vbe_selected_mode]
    cmp bx, 0xffff
    je .Lvbe_fail
    or bx, 0x4000
    mov ax, 0x4f02
    int 0x10
    cmp ax, 0x004f
    jne .Lvbe_fail

    # Refresh the mode record after setting it, then publish exact geometry.
    xor ax, ax
    mov es, ax
    mov di, VBE_MODE_INFO
    mov cx, word ptr [vbe_selected_mode]
    mov ax, 0x4f01
    int 0x10
    cmp ax, 0x004f
    jne .Lvbe_fail
    mov eax, dword ptr [VBE_MODE_INFO + 0x28]
    test eax, eax
    jz .Lvbe_fail
    mov dword ptr [bios_framebuffer], eax
    mov dword ptr [bios_framebuffer + 4], 0
    movzx eax, word ptr [VBE_MODE_INFO + 0x32]
    test eax, eax
    jnz .Lvbe_pitch_ready
    movzx eax, word ptr [VBE_MODE_INFO + 0x10]
.Lvbe_pitch_ready:
    mov dword ptr [bios_framebuffer + 8], eax
    movzx eax, word ptr [VBE_MODE_INFO + 0x12]
    mov dword ptr [bios_framebuffer + 12], eax
    movzx eax, word ptr [VBE_MODE_INFO + 0x14]
    mov dword ptr [bios_framebuffer + 16], eax
    mov word ptr [bios_framebuffer + 20], 32

    cmp byte ptr [VBE_MODE_INFO + 0x36], 0
    je .Lvbe_legacy_masks
    mov al, byte ptr [VBE_MODE_INFO + 0x37]
    mov byte ptr [bios_framebuffer + 22], al
    mov al, byte ptr [VBE_MODE_INFO + 0x36]
    mov byte ptr [bios_framebuffer + 23], al
    mov al, byte ptr [VBE_MODE_INFO + 0x39]
    mov byte ptr [bios_framebuffer + 24], al
    mov al, byte ptr [VBE_MODE_INFO + 0x38]
    mov byte ptr [bios_framebuffer + 25], al
    mov al, byte ptr [VBE_MODE_INFO + 0x3b]
    mov byte ptr [bios_framebuffer + 26], al
    mov al, byte ptr [VBE_MODE_INFO + 0x3a]
    mov byte ptr [bios_framebuffer + 27], al
    jmp .Lvbe_done
.Lvbe_legacy_masks:
    mov al, byte ptr [VBE_MODE_INFO + 0x20]
    mov byte ptr [bios_framebuffer + 22], al
    mov al, byte ptr [VBE_MODE_INFO + 0x1f]
    mov byte ptr [bios_framebuffer + 23], al
    mov al, byte ptr [VBE_MODE_INFO + 0x22]
    mov byte ptr [bios_framebuffer + 24], al
    mov al, byte ptr [VBE_MODE_INFO + 0x21]
    mov byte ptr [bios_framebuffer + 25], al
    mov al, byte ptr [VBE_MODE_INFO + 0x24]
    mov byte ptr [bios_framebuffer + 26], al
    mov al, byte ptr [VBE_MODE_INFO + 0x23]
    mov byte ptr [bios_framebuffer + 27], al
.Lvbe_done:
    xor ax, ax
    mov fs, ax
    ret
.Lvbe_fail:
    xor ax, ax
    mov fs, ax
    ret

.align 8
gdt:
    .quad 0x0000000000000000
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
    .quad 0x00009a000000ffff
    .quad 0x000092000000ffff
    .quad 0x00af9a000000ffff
gdt_end:
gdt_pointer:
    .word gdt_end - gdt - 1
    .long gdt

boot_drive:
    .byte 0
bios_preload_status:
    .byte 0
.global bios_preload_error
bios_preload_error:
    .byte 0
.global bios_disk_mode
bios_disk_mode:
    .byte 0
.global chs_sectors_per_track
chs_sectors_per_track:
    .byte 0
.align 2
.global chs_head_count
chs_head_count:
    .word 0
.balign 8
.global bios_framebuffer
bios_framebuffer:
    .quad 0
    .long 0
    .long 0
    .long 0
    .word 0
    .byte 0, 0, 0, 0, 0, 0
    .long 0
.align 4
read_remaining:
    .long 0
read_destination:
    .long 0
read_chunk:
    .word 0
vbe_mode_offset:
    .word 0
vbe_mode_segment:
    .word 0
vbe_selected_mode:
    .word 0xffff
vbe_selected_width:
    .word 0
vbe_selected_height:
    .word 0
vbe_candidate_mode:
    .word 0
vbe_modes_left:
    .word 0
chs_remaining:
    .word 0
chs_buffer_offset:
    .word 0
chs_sector:
    .byte 0
chs_status:
    .byte 0
chs_retries:
    .byte 0
.align 4
.global chs_lba
chs_lba:
    .long 0
.global chs_status
.balign 16
edd_packet:
    .byte 0x10, 0x00
    .word 1
    .word 0, EDD_BOUNCE_SEGMENT
    .quad 0
.align 4
e820_count:
    .long 0
.size _stage2_start, . - _stage2_start
