# Xenith bootloader

This tree contains two independent, dependency-free x86_64 boot paths. Both hand the
kernel a physical pointer to `xenith_abi::XenithBootInfo` in `rdi` using the System V
ABI. Pointers inside the structure are physical and `hhdm_offset` is
`0xffff800000000000`.

Run `powershell -ExecutionPolicy Bypass -File bootloader/build.ps1` from the repository
root. It produces:

- `bootloader/build/stage1.bin`: exact 512-byte BIOS sector with `55 aa` signature;
- `bootloader/build/stage2.elf`: linked diagnostic BIOS loader image;
- `bootloader/build/stage2.bin`: sector-padded flat image, at most 127 sectors;
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
`byte_len:u64`, payload FNV-1a-64, and a 24-byte NUL-padded name. Stage1 reads LBA 1
with INT 13h EDD, requires entry zero to be stage2, loads 1..127 sectors to physical
`0x8000`, and transfers control there. Stage2 revalidates the complete manifest and
the kernel/initrd payload hashes.

Stage2 obtains E820, enables A20, installs protected and long mode, and builds identity
and HHDM mappings for the first 4 GiB plus the conventional Xenith kernel mapping at
`0xffffffff80000000`. It reads LBA48 sectors using the legacy primary-master ATA ports,
loads a validated x86_64 `ET_EXEC` kernel below 32 MiB, places an initrd of at most
64 MiB at 96 MiB, locates the RSDP, carves loader/kernel/module reservations into the
memory map, and jumps to the ELF entry.

The currently linked BIOS hardware path is intentionally bounded to a PC-compatible
BIOS boot disk at drive `0x80` exposed as legacy primary-master ATA PIO. AHCI-only,
NVMe-only, USB-only, drive `0x81`, and BIOS El Torito 2048-byte-sector boot are not yet
runtime paths. The raw-image layout contract is implemented and structurally tested;
firmware execution remains unvalidated. `stage1,stage2` ISO pair mode is packaging-only
until a dedicated El Torito shim handles its preload/sector semantics.

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
