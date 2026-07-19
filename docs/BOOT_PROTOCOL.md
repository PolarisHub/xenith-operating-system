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

BIOS stage1 occupies exactly 512 bytes and loads a manifest-described stage2 with INT 13h extensions. Stage2 collects E820, enables A20, enters protected and long mode, builds identity/HHDM mappings, reads verified payloads by ATA PIO, loads ELF segments, and jumps with `XenithBootInfo` in `rdi`. The UEFI path loads files through firmware protocols, captures GOP/ACPI/memory map state, retries `ExitBootServices` on a stale map key, installs its own page tables, and uses the same handoff.

The legacy Limine-compatible aggregate remains accepted by the kernel and is used by the direct-kernel emulator path. It is optional and is not used by `xenith-build` image construction.
