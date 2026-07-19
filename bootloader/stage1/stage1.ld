/* Reference layout for inspecting the deterministic builder's output. */
OUTPUT_FORMAT(binary)
ENTRY(_start)
SECTIONS {
    . = 0x7c00;
    .boot : { *(.boot) }
    . = 0x7dfe;
    .signature : { SHORT(0xaa55) }
}
