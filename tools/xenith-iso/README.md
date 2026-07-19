# xenith-iso

`xenith-iso` is Xenith's dependency-free ISO9660 and raw BIOS disk image
builder. It is a normal `std` host tool, but it invokes no external programs and
uses no crates outside the Rust standard library.

## CLI

Build a hybrid ISO from an existing Xenith manifest disk and UEFI loader:

```text
xenith-iso iso --kernel build/kernel.elf --initrd build/initramfs.cpio \
  --uefi build/bootloader/BOOTX64.EFI --bios-disk build/xenith.img \
  -o build/xenith.iso
```

The tool can instead construct the embedded manifest disk from stage1/stage2:

```text
xenith-iso build --kernel build/kernel.elf --initrd build/initramfs.cpio \
  --uefi build/bootloader/BOOTX64.EFI \
  --bootloader build/bootloader/stage1.bin,build/bootloader/stage2.bin \
  -o build/xenith.iso
```

Build a raw disk image:

```text
xenith-iso disk --kernel build/kernel.elf --initrd build/initramfs.cpio \
  --stage1 build/bootloader/stage1.bin --stage2 build/bootloader/stage2.bin -o build/xenith.img
```

The ISO has a primary volume descriptor at block 16, El Torito boot record at
17, descriptor terminator at 18, both-endian root path tables, a boot catalog,
and a single ISO9660 root directory containing `BOOT.CAT;1`, `BIOS.IMG;1`,
`EFI.IMG;1`, `KERNEL.ELF;1`, and `INITRD.CPIO;1`.

The catalog's default x86 entry uses hard-disk emulation. `BIOS.IMG;1` is the
complete raw image, with one active type-`0xDA` MBR partition installed in the
partition-table area reserved by Xenith stage1. Its virtual LBA 0 is stage1,
LBA 1 is the checksummed `XENITHIM` manifest, and the manifest payload LBAs are
unchanged. The separately emitted `xenith.img` is not patched and retains its
raw-image bytes.

The final catalog section has platform ID `0xEF` and a no-emulation entry for
`EFI.IMG;1`. That 16 MiB FAT16 EFI System Partition contains:

```text
EFI/BOOT/BOOTX64.EFI
EFI/XENITH/kernel.elf
EFI/XENITH/initrd.cpio
```

The builder reparses the raw manifest and FAT tree and compares all installed
payloads byte-for-byte. These checks prove the ISO and boot-image structures;
they do not prove that a particular BIOS/UEFI implementation or hardware boots
them. In particular, stage2 still uses legacy primary-master ATA PIO after its
BIOS entry path, so firmware compatibility remains a runtime validation item.

## Raw image format (`XENITHIM` version 1)

All integers are little-endian and all LBAs use 512-byte sectors.

| LBA / offset | Size | Meaning |
|---|---:|---|
| LBA 0 | 512 | Supplied stage1 MBR. Bytes 510-511 are installed as `55 AA`. |
| LBA 1 | 512 | Xenith manifest described below. |
| LBA 2 | variable | Stage2, first manifest entry, limited to 127 sectors. |
| next 4 KiB boundary | variable | Kernel. |
| next 4 KiB boundary | variable | Initrd. |
| final 4 KiB boundary | - | End of zero-padded image. |

Manifest header:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII magic `XENITHIM` |
| 8 | 2 | Version (`1`) |
| 10 | 2 | Header/sector bytes (`512`) |
| 12 | 4 | Flags (`1` = FNV-1a 64 checksums) |
| 16 | 4 | Sector size (`512`) |
| 20 | 4 | Entry count (`3`) |
| 24 | 8 | Total image sectors |
| 32 | 8 | FNV-1a 64 of the full manifest sector with this field zero |
| 40 | 24 | Reserved, zero |
| 64 | 192 | Three 64-byte entries: stage2, kernel, initrd |
| 256 | 248 | Reserved, zero |
| 504 | 6 | ASCII trailer `XENITH` |
| 510 | 2 | Signature `55 AA` |

Each entry is:

| Relative offset | Size | Field |
|---:|---:|---|
| 0 | 4 | Kind (`1` stage2, `2` kernel, `3` initrd) |
| 4 | 4 | Flags (`1` = required) |
| 8 | 8 | Start LBA |
| 16 | 8 | Allocated sector count |
| 24 | 8 | Exact byte length |
| 32 | 8 | FNV-1a 64 of the exact payload bytes |
| 40 | 24 | NUL-padded name (`stage2`, `kernel`, or `initrd`) |

Stage1 reads entry zero from LBA 1 and loads stage2. Stage2 can then verify the
manifest checksum, use the exact byte lengths to ignore sector padding, verify
the component checksums, and load the kernel and initrd. FNV-1a detects damaged
artifacts but is not a cryptographic signature.
