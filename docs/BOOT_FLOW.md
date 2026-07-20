# Boot flow

## Firmware loaders

On BIOS, firmware loads the 512-byte stage1 sector carrying the `0x55AA` boot
signature. Stage1 prefers EDD packet reads for the manifest and stage2, with a
geometry-validated CHS fallback for legacy El Torito implementations. Stage2
likewise prefers bounded EDD reads on the firmware boot drive and falls back to
single-sector CHS reads to preload the kernel and initramfs through a
conventional-memory bounce buffer, copying each chunk high through explicit
protected-mode windows. It verifies manifest payload
checksums, optionally selects a 32-bpp VBE linear framebuffer, reads E820,
enables A20, enters long mode, creates identity/HHDM/kernel mappings, finds
RSDP, and jumps to the ELF entry with `XenithBootInfo` in `rdi`. If firmware
preloading fails on drive `0x80`, the legacy primary-master ATA reader remains
available as a fallback.

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
| `--bios-image` / `--bios-iso` | Exact packaged stage1 and stage2 instruction streams from reset/MBR or the validated ISO BIOS catalog entry through the real long-mode `call stage2_main` | The Rust `stage2_main` body is an explicit semantic fallback for checksum/ELF/handoff work and native kernel entry. |
| `--uefi-iso` | Exact ISO platform-`0xEF`/FAT16 payloads and actual `BOOTX64.EFI` PE32+ instructions | The application calls the strict UEFI service model, executes `ExitBootServices`, builds its native handoff, and enters the kernel; no semantic loader fallback is used. |
| `xenith-vmm --kernel` | Direct handoff executed by actual Windows Hypervisor Platform virtual processors | Uses the shared PC device bus; no BIOS/UEFI loader executes. |

The BIOS stage runner begins at architectural reset state, transfers the actual
MBR to `0x7c00`, services the loader's EDD requests, and executes its current
real/protected/long-mode instruction stream. Unsupported instructions fail
rather than being inferred or skipped. Its trace retains instruction and byte
counts, execution checksums, BIOS calls, E820/A20 state, and mode transitions.
The exact instruction boundary ends only after stage2 executes its actual
`call stage2_main`; checksum/ELF loading, handoff construction, and kernel
entry inside the Rust body are then completed semantically.

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

Both repository firmware runners are purpose-built validation environments for
Xenith's packaged loaders. They do not execute arbitrary external BIOS/UEFI
firmware, option ROMs, or a complete chipset reset model. Separately, VMware
Workstation 17.6.3 legacy BIOS cold boots of the preceding externally tested El
Torito ISO reached the framebuffer terminal and userspace shell with 1, 3, 4,
8, 16, and 24 vCPUs on 2026-07-19. QEMU/SeaBIOS passed every integer CPU count
from 1 through 64 for that ISO and passed its raw image at 64 CPUs. The current
artifact hashes and exact external-proof boundary are recorded in
[STATUS](STATUS.md); these are not physical-hardware or all-firmware proof.

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

The kernel supports the same configured range, including the BSP, and assigns
MADT processors compact logical IDs. AP startup is serialized through one low
trampoline page: the BSP patches the page, sends INIT-SIPI-SIPI, and waits for
that AP's online acknowledgement before reusing it. If an AP times out, startup
stops and the page remains quarantined so a delayed AP cannot observe the next
CPU's logical ID, stack, or expected APIC ID. The physical allocator is the
preferred page source. If it has no suitable conventional-memory frame and the
handoff command line contains the exact `xenith.boot=bios` token, the kernel
uses physical `0x70000`, the first page of stage2's retired INT 13h bounce
buffer. Other current boot paths do not supply that token and therefore do not
select the reserved BIOS fallback.

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

`/init` prints its banner and probes the exclusive framebuffer session. With a
supported display it spawns and supervises `/bin/xenith-desktop`; otherwise it
execs `/bin/sh` immediately. A clean recovery gesture, desktop crash, or spawn
failure also restores the terminal and enters the shell. The shell uses the
kernel spawn/wait path for external utilities. Graphical integration gates wait
for `XENITH_DESKTOP_READY`; text-only gates retain the userspace-init and
`xenith$ ` markers.

Failures before the allocator use serial-only reporting or halt. Invalid boot
metadata, corrupt initramfs, invalid ELF mappings, and exhausted critical
memory fail closed rather than continuing with partial ownership.

The deterministic framebuffer/text dumps and RTL8139 transmit sink are testing
surfaces, not a live GUI or host network. The VMware BIOS/VBE result proves one
virtual platform; physical display, input, storage, interrupt timing, inbound
networking, and other firmware remain separate runtime boundaries.
