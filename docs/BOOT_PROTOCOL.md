# Xenith boot protocol

`XenithBootInfo` is a versioned `repr(C)` record defined in `xenith-abi`. Its magic is `0x58454e4954484249` (`XENITHBI`) and the current version is 1.

The record contains:

- HHDM offset;
- physical memory-map pointer/count/entry size;
- framebuffer address and channel geometry;
- physical RSDP address;
- physical module descriptors, including the initramfs;
- command-line pointer/length;
- boot CPU APIC ID.

Descriptor pointers are physical unless documented otherwise. The kernel validates magic, version, struct size, entry size, counts, and arithmetic before translating through the HHDM. Metadata is normalized into bounded kernel-owned compatibility records before the allocator can reclaim loader memory.

BIOS stage1 occupies exactly 512 bytes and loads the manifest and stage2 with preferred INT 13h EDD packet reads or a geometry-validated single-sector CHS fallback. Before leaving real mode, stage2 uses the same EDD-first, CHS-fallback policy on the firmware-provided boot drive to preload the kernel and initramfs into a conventional-memory bounce buffer. Each bounded chunk is copied to its high staging address through an explicit real -> protected32 -> protected16 -> real transition, then its manifest checksum is verified. Primary-master ATA PIO remains a drive-`0x80` fallback when firmware preloading fails. Stage2 also attempts optional VBE discovery for a 32-bpp linear framebuffer up to 1024x768, falling back to VGA text on failure. It then collects E820, enables A20, enters long mode, builds identity/HHDM mappings, loads ELF segments, and jumps with `XenithBootInfo` in `rdi`. The UEFI path loads files through firmware protocols, captures GOP/ACPI/memory map state, retries `ExitBootServices` on a stale map key, installs its own page tables, and uses the same handoff.

The native BIOS handoff supplies the exact command-line token
`xenith.boot=bios` and keeps the entire first MiB reserved. Stage2's INT 13h
bounce buffer at `0x70000..0x77fff` is retired after its synchronous payload
reads and cannot alias a general physical allocation. When the kernel cannot
allocate another conventional-memory AP trampoline, that exact token permits
it to reuse the page at physical `0x70000` for serialized AP startup. The page
is repatched only after each AP acknowledges that it is online; an AP timeout
quarantines the page and stops further startup.

The legacy Limine-compatible aggregate remains accepted by the kernel and is used by the direct-kernel emulator path. It is optional and is not used by `xenith-build` image construction.
