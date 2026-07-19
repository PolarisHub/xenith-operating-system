//! Self-contained boot image construction for Xenith.
//!
//! The library emits byte-for-byte ISO9660/El Torito and raw MBR disk images.
//! It deliberately has no command-line tool dependencies: callers can use the
//! builders directly from Rust and obtain deterministic output.

mod checksum;
mod disk;
mod error;
mod fat;
mod iso9660;

pub use checksum::payload_checksum;
pub use disk::{
    build_disk_image, build_disk_image_with_layout, parse_manifest, validate_disk_image,
    DiskLayout, DiskManifest, ManifestEntry, ManifestEntryKind, DISK_MANIFEST_LBA,
    DISK_MANIFEST_MAGIC, DISK_MANIFEST_VERSION, DISK_SECTOR_SIZE,
};
pub use error::ImageError;
pub use fat::{
    build_efi_system_partition, build_efi_system_partition_with_layout,
    validate_efi_system_partition, EfiSystemPartitionLayout, EFI_SECTOR_SIZE,
    EFI_SYSTEM_PARTITION_SECTORS,
};
pub use iso9660::{
    build_iso_image, build_iso_image_with_layout, IsoConfig, IsoLayout, ISO_BLOCK_SIZE,
};
