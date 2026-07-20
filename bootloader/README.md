# Xenith bootloader

This tree contains two independent, dependency-free x86_64 boot paths. Both hand the
kernel a physical pointer to `xenith_abi::XenithBootInfo` in `rdi` using the System V
ABI. Pointers inside the structure are physical and `hhdm_offset` is
`0xffff800000000000`.

Run `powershell -ExecutionPolicy Bypass -File bootloader/build.ps1` from the repository
root. It produces:

- `bootloader/build/stage1.bin`: exact 512-byte BIOS sector with `55 aa` signature;
- `bootloader/build/stage2.elf`: linked diagnostic BIOS loader image;
- `bootloader/build/stage2.bin`: sector-padded flat image, at most 64 sectors;
- `bootloader/build/BOOTX64.EFI`: PE32+ UEFI application.

No assembler, C compiler, objcopy, NASM, xorriso, or Limine tool is invoked. The only
build input is the pinned Rust toolchain and its installed `x86_64-unknown-none` and
`x86_64-unknown-uefi` targets. Each crate is a nested standalone Cargo workspace, so no
root workspace member is required.

## Raw BIOS disk contract

The BIOS path consumes the `XENITHIM` v1 image emitted by `tools/xenith-iso`:

| LBA / offset | Layout |
| --- | --- |
| LBA 0 | `stage1.bin` |
| LBA 1, 0..7 | ASCII `XENITHIM` |
| 8 | `u16` version 1 |
| 10 | `u16` header size 512 |
| 12 | `u32` flags 1 (FNV-1a-64) |
| 16 | `u32` sector size 512 |
| 20 | `u32` entry count 3 |
| 24 | `u64` image sector count |
| 32 | `u64` manifest FNV-1a-64, calculated with this field zero |
| 64, 128, 192 | 64-byte stage2, kernel, and initrd entries |

Each entry is `kind:u32`, `flags:u32`, `start_lba:u64`, `sector_count:u64`,
`byte_len:u64`, payload FNV-1a-64, and a 24-byte NUL-padded name. Stage1 prefers
INT 13h EDD packet reads and falls back to geometry-validated single-sector CHS
reads. It requires entry zero to be stage2, loads 1..64 sectors to physical
`0x8000` without crossing the 64 KiB DMA boundary, and transfers control there.
Stage2 revalidates the complete manifest and the kernel/initrd payload hashes.

Stage2 enables A20 and preloads the kernel and initramfs from the firmware-provided
boot drive. It prefers EDD chunks of at most 64 sectors and falls back to
single-sector CHS reads, using a conventional-memory bounce buffer and explicit
protected-mode copy windows for the high staging addresses. It optionally selects
a 32-bpp VBE framebuffer, obtains E820, installs protected and long mode, and
builds identity and HHDM mappings for the first 4 GiB plus the conventional Xenith
kernel mapping at `0xffffffff80000000`. It stages up to 16 MiB of kernel data at
16 MiB, loads validated x86_64 `ET_EXEC` segments below 16 MiB, and places an
initrd of at most 64 MiB at 32 MiB. It then locates the RSDP, carves
loader/kernel/module reservations into the memory map, and jumps to the ELF
entry.

The firmware-read path retains the BIOS-provided drive number and supports the
hard-disk-emulated El Torito image as well as a raw BIOS disk. Legacy
primary-master ATA PIO is retained only as a drive-`0x80` fallback if firmware
preloading fails. Repository firmware gates cover the current raw and ISO
paths; external VMware legacy-BIOS and QEMU/SeaBIOS proof currently belongs to
the preceding artifact hashes recorded in `docs/STATUS.md`. Physical hardware
and arbitrary firmware remain separate validation boundaries.

The BIOS handoff sets the exact `xenith.boot=bios` command-line token and marks
the first MiB reserved. Once all synchronous INT 13h payload reads are done,
the bounce range at `0x70000..0x77fff` is retired. If the kernel's physical
allocator cannot supply another low AP-trampoline frame, the token permits
serialized AP startup to reuse physical page `0x70000`; that page never enters
the general allocator and is not reused after an AP startup timeout.

## UEFI contract

`BOOTX64.EFI` uses direct UEFI ABI definitions and no external crate. It opens its own
Simple File System volume and tries these paths:

1. `\EFI\XENITH\kernel.elf`, then `\kernel.elf`;
2. `\EFI\XENITH\initrd.cpio`, then `\initrd.cpio`.

The loader allocates all handoff objects below 4 GiB, relocates validated `ET_EXEC`
segments into loader-owned pages, maps their declared virtual addresses, maps the first
4 GiB both identity and through the HHDM, carries GOP and ACPI data into boot info,
captures the final firmware memory map, retries `ExitBootServices` on a stale map key,
switches CR3 and stack, and enters the kernel with the System V ABI.

`x86_64-unknown-uefi` produces and links the PE32+ application successfully. Firmware
runtime behavior still requires validation on OVMF or physical UEFI; this repository
pass proves format, target link, parser tests, and artifact bounds, not a completed
hardware boot log.

## Focused validation

```powershell
cargo test --manifest-path bootloader/common/Cargo.toml --target x86_64-pc-windows-msvc
cargo test --manifest-path bootloader/stage1/Cargo.toml --target x86_64-pc-windows-msvc
cargo test --manifest-path bootloader/stage2/Cargo.toml --target x86_64-pc-windows-msvc --lib
cargo test --manifest-path bootloader/uefi/Cargo.toml --target x86_64-pc-windows-msvc --lib
cargo clippy --manifest-path bootloader/common/Cargo.toml --target x86_64-pc-windows-msvc -- -D warnings
```
