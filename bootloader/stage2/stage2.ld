OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_stage2_start)

SECTIONS {
    . = 0x8000;
    __stage2_start = .;

    .text : ALIGN(16) {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }
    .rodata : ALIGN(16) { *(.rodata .rodata.*) }
    .data : ALIGN(16) { *(.data .data.*) }
    .bss : ALIGN(16) {
        __bss_start = .;
        *(.bss .bss.* COMMON)
        __bss_end = .;
    }

    __stage2_end = .;
    /DISCARD/ : { *(.eh_frame*) *(.comment*) *(.note*) }
}

