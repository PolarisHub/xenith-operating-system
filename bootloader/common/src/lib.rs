//! Format handling shared by the BIOS and UEFI Xenith boot paths.

#![no_std]

pub mod checksum;
pub mod elf;
pub mod manifest;
pub mod memory;

pub use checksum::{fnv1a64, fnv1a64_with_zeroed_range, FNV1A64_OFFSET_BASIS};
pub use elf::{Elf64, ElfError, LoadSegment, ProgramHeaderIter};
pub use manifest::{
    DiskEntry, DiskEntryKind, DiskManifest, ManifestError, DISK_MANIFEST_LBA, DISK_MANIFEST_MAGIC,
    DISK_MANIFEST_SIZE, DISK_MANIFEST_VERSION, MAX_STAGE2_SECTORS,
};
pub use memory::{append_region, append_region_with_reservations, MemoryMapError, Reservation};
pub use xenith_abi::{
    BootMemoryKind, XenithBootInfo, XenithFramebuffer, XenithMemoryRegion, XenithModule,
    XENITH_BOOT_MAGIC, XENITH_BOOT_VERSION,
};

/// Xenith maps physical memory into this canonical higher-half window.
pub const HHDM_OFFSET: u64 = 0xffff_8000_0000_0000;
/// ELF images linked with the kernel code model normally start here.
pub const KERNEL_VIRTUAL_BASE: u64 = 0xffff_ffff_8000_0000;
/// Hardware and firmware page granularity.
pub const PAGE_SIZE: u64 = 4096;

#[must_use]
pub const fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

#[must_use]
pub const fn align_up(value: u64, alignment: u64) -> Option<u64> {
    match value.checked_add(alignment - 1) {
        Some(adjusted) => Some(adjusted & !(alignment - 1)),
        None => None,
    }
}
