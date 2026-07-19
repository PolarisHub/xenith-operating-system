# Boot flow

## Firmware loaders

BIOS loads the 512-byte stage1 sector carrying the `0x55AA` boot signature. Stage1 uses EDD to read the manifest-described stage2. Stage2 verifies manifest payload checksums, reads E820, enables A20, enters protected then long mode, creates identity/HHDM/kernel page mappings, loads the kernel ELF and initramfs from legacy primary-master ATA PIO, finds RSDP, and jumps to the ELF entry with `XenithBootInfo` in `rdi`.

UEFI loads `BOOTX64.EFI`. The application reads the kernel and initramfs through Simple File System, records GOP and ACPI state, validates/loads ELF segments, captures the final firmware memory map, retries `ExitBootServices` if the map key changes, installs its page tables and stack, and uses the same `XenithBootInfo` handoff.

`xenith.iso` packages the BIOS path as a complete manifest disk in an El Torito hard-disk-emulation entry. A separate platform-`0xEF` entry exposes a FAT16 EFI System Partition with `EFI/BOOT/BOOTX64.EFI`, `EFI/XENITH/kernel.elf`, and `EFI/XENITH/initrd.cpio`. Parser tests prove those structures and bytes. The raw-image BIOS gate additionally executes the packaged stage instruction bytes as described below; UEFI and ISO catalog execution are not recorded runtime results.

The direct-kernel interpreter loads `kernel.elf` and `initramfs.cpio` itself, then supplies the accepted Limine-compatible aggregate. `--image` performs the same direct handoff after validating all `xenith.img` manifest payloads. The separate `--bios-image` path fetches and executes the packaged stage1 bytes with deterministic EDD services, then executes stage2's real/protected/long-mode assembly through its actual `call stage2_main` instruction. Unsupported stage instructions fail rather than being inferred or skipped. A trace retains instruction/byte counts, execution checksums, BIOS-call counts, E820/A20 state, and mode-transition evidence.

Execution currently stops at the `stage2_main` target. Its freestanding Rust body---ATA payload reads, ELF loading, and native `XenithBootInfo` construction---is completed by an explicitly named semantic fallback before normal kernel execution. The runner is therefore exact for the current Xenith stage streams through that call boundary, not a general PC BIOS or arbitrary real/protected-mode interpreter. UEFI and both `xenith.iso` catalog entries are not executed by this path.

## Kernel initialization

The order is load-bearing:

1. polled COM1, logger, framebuffer/VGA console;
2. CPU control state, GDT/TSS, BSP per-CPU GS, FPU, exception IDT;
3. boot heap claim, physical allocator, kernel page-table adoption;
4. ACPI tables and AML namespace;
5. PIC/LAPIC/IOAPIC, HPET/PIT/LAPIC clock;
6. scheduler and syscall MSRs;
7. CMOS, PS/2, PCI, AHCI and NIC registration;
8. network state, loopback, physical-interface registration, and the
   autonomous DHCP/RX/TX/maintenance worker;
9. ramfs root and newc initramfs population;
10. `/init` ELF mapping/process publication;
11. interrupts enabled and the scheduler dispatches the first task.

`/init` prints its banner, spawns `/bin/sh` through the kernel process-launch path, and exits. The shell uses direct child spawn/wait for external utilities. The expected serial markers used by the integration gate are `xenith: init`, `mm: ready`, `scheduler: ready`, `user: init spawned`, the userspace-init banner, and `xenith$ `.

Failures before the allocator use serial-only reporting or halt. Invalid boot metadata, corrupt initramfs, invalid ELF mappings, and exhausted critical memory fail closed rather than continuing with partial ownership.
