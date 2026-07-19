/* Xenith ring-3 ELF layout.
 *
 * Userspace is linked in the low canonical half, independently from the
 * higher-half kernel image. Keep PT_LOAD permissions separated so the ELF
 * loader can preserve W^X when it installs the final user mappings.
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

USER_VIRTUAL_BASE = 0x00200000;

PHDRS
{
    text   PT_LOAD FLAGS(5); /* read + execute */
    rodata PT_LOAD FLAGS(4); /* read */
    data   PT_LOAD FLAGS(6); /* read + write */
}

SECTIONS
{
    . = USER_VIRTUAL_BASE;
    __user_start = .;

    .text ALIGN(0x1000) :
    {
        KEEP(*(.text._start))
        *(.text .text.*)
    } :text

    .rodata ALIGN(0x1000) :
    {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.eh_frame_hdr)
        *(.eh_frame)
        *(.gcc_except_table .gcc_except_table.*)
    } :rodata

    .data ALIGN(0x1000) :
    {
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.got .got.*)
    } :data

    .bss ALIGN(0x1000) (NOLOAD) :
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    . = ALIGN(0x1000);
    __user_end = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.note .note.*)
        *(.gnu_debuglink)
    }
}
