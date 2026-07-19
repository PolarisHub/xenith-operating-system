# Boot flow

## Firmware loaders

On BIOS, firmware loads the 512-byte stage1 sector carrying the `0x55AA` boot
signature. Stage1 uses EDD to read the manifest-described stage2. Stage2
verifies manifest payload checksums, reads E820, enables A20, enters protected
then long mode, creates identity/HHDM/kernel mappings, loads the kernel ELF and
initramfs from legacy primary-master ATA PIO, finds RSDP, and jumps to the ELF
entry with `XenithBootInfo` in `rdi`.

On UEFI, firmware loads `BOOTX64.EFI`. The application reads the kernel and
initramfs through Simple File System, records GOP and ACPI state, validates and
loads ELF segments, captures the final firmware memory map, retries
`ExitBootServices` if the map key changes, installs page tables and its kernel
stack, and transfers to the same native `XenithBootInfo` ABI.

`xenith.iso` packages the BIOS path as a complete manifest disk in an El Torito
hard-disk-emulation entry. A separate platform-`0xEF` no-emulation entry exposes
a FAT16 EFI System Partition with `EFI/BOOT/BOOTX64.EFI`,
`EFI/XENITH/kernel.elf`, and `EFI/XENITH/initrd.cpio`.

## Repository execution paths

| Command source | What executes | Handoff boundary |
| --- | --- | --- |
| `--kernel` | Directly validated kernel ELF and optional initramfs | Interpreter constructs the accepted boot aggregate; no firmware stage executes. |
| `--image` | Exact kernel/initramfs extents selected from a checksum-validated `XENITHIM` image | Same direct handoff; stage1/stage2 do not execute. |
| `--bios-image` | Exact packaged stage1 and stage2 instruction streams from reset/MBR through the real long-mode `call stage2_main` | The Rust `stage2_main` body is an explicit semantic fallback for payload loading and native kernel entry. |
| `--uefi-iso` | Exact ISO platform-`0xEF`/FAT16 payloads and actual `BOOTX64.EFI` PE32+ instructions | The application calls the strict UEFI service model, executes `ExitBootServices`, builds its native handoff, and enters the kernel; no semantic loader fallback is used. |
| `xenith-vmm --kernel` | Direct handoff executed by actual Windows Hypervisor Platform virtual processors | Uses the shared PC device bus; no BIOS/UEFI loader executes. |

The BIOS stage runner begins at architectural reset state, transfers the actual
MBR to `0x7c00`, services the loader's EDD requests, and executes its current
real/protected/long-mode instruction stream. Unsupported instructions fail
rather than being inferred or skipped. Its trace retains instruction and byte
counts, execution checksums, BIOS calls, E820/A20 state, and mode transitions.
The exact instruction boundary ends only after stage2 executes its actual
`call stage2_main`; ATA payload reads, ELF loading, handoff construction, and
kernel entry inside the Rust body are then completed semantically.

The UEFI ISO runner validates the El Torito catalog, selects the exact EFI
entry, validates its FAT16 chains and files, strictly parses the packaged PE32+
image, and runs its instructions in the ordinary long-mode interpreter. Its
minimal environment implements the loader's page allocation, memory map,
Loaded Image, Simple File System and file operations, GOP, console output, ACPI
2.0 configuration table, and `ExitBootServices` calls. Unsupported PE forms,
services, and instructions fail closed. The resulting trace includes payload
checksums, PE instruction evidence, exact service counts, boot-services exit,
GOP/ACPI state, and final CR3/kernel/handoff addresses. This is native loader
execution with no semantic fallback.

Both firmware runners are purpose-built validation environments for Xenith's
packaged loaders. They do not execute arbitrary external BIOS/UEFI firmware,
option ROMs, or a complete chipset reset model, and they do not establish
physical-hardware compatibility.

## CPU startup

The interpreter supports 1 through 64 deterministic CPUs. The BSP initially
runs alone. LAPIC INIT-SIPI-SIPI events validate the guest's actual trampoline
bytes, descriptor record, and patched CR3/stack/entry values, then establish
the AP at that validated 64-bit entry; the interpreter does not execute the
trampoline's real-mode instructions one by one. Runnable CPUs then advance in
deterministic round-robin order. The instruction subset exercised by current
loader and kernel startup includes `CLTS`, `FNINIT`, `FXSAVE`, and `FXRSTOR`
with their architectural privilege, control-bit, alignment, paging, and MXCSR
checks.

The WHP runner maps the same guest RAM and direct handoff into a Windows
Hypervisor Platform partition. Virtual-processor workers execute real WHP VPs
while a coordinator handles exits and serializes access to the shared
`Machine` device bus. Fresh artifact gates prove shell boot with one VP and an
INIT-SIPI-SIPI shell boot with two VPs in which both execute. WHP depends on
the Windows feature, hardware virtualization, and nested virtualization when
Windows itself is a guest; configurations above two VPs are not artifact-
proven.

## Kernel initialization

The order is load-bearing:

1. polled COM1, logger, framebuffer/VGA console;
2. CPU control state, GDT/TSS, BSP per-CPU GS, FPU, and exception IDT;
3. boot heap claim, physical allocator, and kernel page-table adoption;
4. ACPI tables and AML namespace;
5. PIC/LAPIC/IOAPIC, HPET/PIT/LAPIC clock;
6. scheduler and syscall MSRs;
7. CMOS, PS/2, PCI, AHCI, and NIC registration;
8. network state, loopback, physical-interface registration, and the
   autonomous DHCP/RX/TX/maintenance worker;
9. ramfs root and newc initramfs population;
10. `/init` ELF mapping and process publication;
11. interrupts enabled and scheduler dispatch of the first task.

`/init` prints its banner, spawns `/bin/sh` through the kernel process-launch
path, and exits. The shell uses the kernel spawn/wait path for external
utilities. Integration gates wait for `xenith: init`, `mm: ready`,
`scheduler: ready`, `user: init spawned`, the userspace-init banner, and
`xenith$ `.

Failures before the allocator use serial-only reporting or halt. Invalid boot
metadata, corrupt initramfs, invalid ELF mappings, and exhausted critical
memory fail closed rather than continuing with partial ownership.

The deterministic framebuffer/text dumps and RTL8139 transmit sink are testing
surfaces, not a live GUI or host network. Physical display, input, storage,
interrupt timing, inbound networking, and external firmware remain separate
runtime boundaries.
