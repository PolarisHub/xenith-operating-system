//! Deterministic ISO9660 with El Torito BIOS and UEFI boot entries.
//!
//! BIOS receives a complete Xenith manifest disk through hard-disk emulation,
//! so virtual LBAs zero and one are the stage1 MBR and `XENITHIM` manifest.
//! UEFI receives a FAT16 image through its own platform section and discovers
//! `EFI/BOOT/BOOTX64.EFI` by the standard removable-media path.

use crate::{
    build_efi_system_partition, validate_disk_image, ImageError, EFI_SYSTEM_PARTITION_SECTORS,
};

/// ISO9660 logical block size.
pub const ISO_BLOCK_SIZE: usize = 2_048;

const PRIMARY_VOLUME_DESCRIPTOR_LBA: u32 = 16;
const BOOT_RECORD_DESCRIPTOR_LBA: u32 = 17;
const TERMINATOR_DESCRIPTOR_LBA: u32 = 18;
const LITTLE_ENDIAN_PATH_TABLE_LBA: u32 = 19;
const BIG_ENDIAN_PATH_TABLE_LBA: u32 = 20;
const ROOT_DIRECTORY_LBA: u32 = 21;
const BOOT_CATALOG_LBA: u32 = 22;
const FIRST_FILE_LBA: u32 = 23;
const PATH_TABLE_SIZE: u32 = 10;

const STANDARD_IDENTIFIER: &[u8; 5] = b"CD001";
const BOOT_SYSTEM_IDENTIFIER: &[u8; 23] = b"EL TORITO SPECIFICATION";
const BOOT_CATALOG_NAME: &[u8] = b"BOOT.CAT;1";
const BIOS_IMAGE_NAME: &[u8] = b"BIOS.IMG;1";
const EFI_IMAGE_NAME: &[u8] = b"EFI.IMG;1";
const KERNEL_NAME: &[u8] = b"KERNEL.ELF;1";
const INITRD_NAME: &[u8] = b"INITRD.CPIO;1";
const MBR_PARTITION_TABLE_OFFSET: usize = 446;
const MBR_PARTITION_ENTRY_SIZE: usize = 16;
const XENITH_PARTITION_TYPE: u8 = 0xda;
const BIOS_CHS_HEADS: u64 = 16;
const BIOS_CHS_SECTORS_PER_TRACK: u64 = 63;
const BIOS_CHS_CYLINDER_SECTORS: u64 = BIOS_CHS_HEADS * BIOS_CHS_SECTORS_PER_TRACK;
const BIOS_CHS_MAX_CYLINDERS: u64 = 1_024;

/// User-configurable ISO metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsoConfig {
    /// ISO9660 D-string volume identifier (uppercase ASCII, up to 32 bytes).
    pub volume_id: String,
}

impl Default for IsoConfig {
    fn default() -> Self {
        Self {
            volume_id: "XENITH".to_owned(),
        }
    }
}

/// Block positions and byte lengths used by a generated ISO.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsoLayout {
    pub primary_volume_descriptor_lba: u32,
    pub boot_record_descriptor_lba: u32,
    pub terminator_descriptor_lba: u32,
    pub root_directory_lba: u32,
    pub boot_catalog_lba: u32,
    pub bios_boot_image_lba: u32,
    pub bios_boot_image_bytes: u32,
    pub efi_boot_image_lba: u32,
    pub efi_boot_image_bytes: u32,
    pub kernel_lba: u32,
    pub kernel_bytes: u32,
    pub initrd_lba: u32,
    pub initrd_bytes: u32,
    pub total_blocks: u32,
}

/// Borrowed El Torito images selected from a validated ISO boot catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElToritoBootImages<'a> {
    pub boot_catalog_lba: u32,
    pub bios_image_lba: u32,
    pub efi_image_lba: u32,
    pub efi_load_sectors: u16,
    pub bios_disk: &'a [u8],
    pub efi_system_partition: &'a [u8],
}

/// Builds a hybrid ISO9660 image with BIOS hard-disk and UEFI FAT boot entries.
pub fn build_iso_image(
    bios_disk: &[u8],
    bootx64: &[u8],
    kernel: &[u8],
    initrd: &[u8],
    config: &IsoConfig,
) -> Result<Vec<u8>, ImageError> {
    build_iso_image_with_layout(bios_disk, bootx64, kernel, initrd, config).map(|(image, _)| image)
}

/// Builds an ISO and returns its calculated logical-block layout.
pub fn build_iso_image_with_layout(
    bios_disk: &[u8],
    bootx64: &[u8],
    kernel: &[u8],
    initrd: &[u8],
    config: &IsoConfig,
) -> Result<(Vec<u8>, IsoLayout), ImageError> {
    validate_inputs(bios_disk, bootx64, kernel, initrd, config)?;
    let bios_boot_image = prepare_bios_boot_image(bios_disk)?;
    let efi_boot_image = build_efi_system_partition(bootx64, kernel, initrd)?;

    let bios_boot_image_blocks = blocks_for(bios_boot_image.len(), "BIOS boot image")?;
    let efi_boot_image_blocks = blocks_for(efi_boot_image.len(), "EFI boot image")?;
    let kernel_blocks = blocks_for(kernel.len(), "kernel")?;
    let initrd_blocks = blocks_for(initrd.len(), "initrd")?;
    let bios_boot_image_lba = FIRST_FILE_LBA;
    let efi_boot_image_lba = bios_boot_image_lba
        .checked_add(bios_boot_image_blocks)
        .ok_or(ImageError::ImageTooLarge("ISO image"))?;
    let kernel_lba = efi_boot_image_lba
        .checked_add(efi_boot_image_blocks)
        .ok_or(ImageError::ImageTooLarge("ISO image"))?;
    let initrd_lba = kernel_lba
        .checked_add(kernel_blocks)
        .ok_or(ImageError::ImageTooLarge("ISO image"))?;
    let total_blocks = initrd_lba
        .checked_add(initrd_blocks)
        .ok_or(ImageError::ImageTooLarge("ISO image"))?;

    let bios_boot_image_bytes = u32::try_from(bios_boot_image.len())
        .map_err(|_| ImageError::ImageTooLarge("BIOS boot image"))?;
    let efi_boot_image_bytes = u32::try_from(efi_boot_image.len())
        .map_err(|_| ImageError::ImageTooLarge("EFI boot image"))?;
    let kernel_bytes =
        u32::try_from(kernel.len()).map_err(|_| ImageError::ImageTooLarge("kernel"))?;
    let initrd_bytes =
        u32::try_from(initrd.len()).map_err(|_| ImageError::ImageTooLarge("initrd"))?;

    let layout = IsoLayout {
        primary_volume_descriptor_lba: PRIMARY_VOLUME_DESCRIPTOR_LBA,
        boot_record_descriptor_lba: BOOT_RECORD_DESCRIPTOR_LBA,
        terminator_descriptor_lba: TERMINATOR_DESCRIPTOR_LBA,
        root_directory_lba: ROOT_DIRECTORY_LBA,
        boot_catalog_lba: BOOT_CATALOG_LBA,
        bios_boot_image_lba,
        bios_boot_image_bytes,
        efi_boot_image_lba,
        efi_boot_image_bytes,
        kernel_lba,
        kernel_bytes,
        initrd_lba,
        initrd_bytes,
        total_blocks,
    };

    let total_bytes = usize::try_from(total_blocks)
        .ok()
        .and_then(|blocks| blocks.checked_mul(ISO_BLOCK_SIZE))
        .ok_or(ImageError::ImageTooLarge("ISO image"))?;
    let mut image = vec![0_u8; total_bytes];

    write_primary_volume_descriptor(&mut image, &layout, config)?;
    write_boot_record_descriptor(&mut image, &layout)?;
    write_volume_descriptor_terminator(&mut image)?;
    write_path_tables(&mut image, &layout)?;
    write_root_directory(&mut image, &layout)?;
    write_boot_catalog(&mut image, &layout)?;
    write_file(&mut image, layout.bios_boot_image_lba, &bios_boot_image)?;
    write_file(&mut image, layout.efi_boot_image_lba, &efi_boot_image)?;
    write_file(&mut image, layout.kernel_lba, kernel)?;
    write_file(&mut image, layout.initrd_lba, initrd)?;

    Ok((image, layout))
}

/// Selects Xenith's BIOS hard-disk and platform-0xEF no-emulation images from
/// the actual ISO descriptors, catalog, and root-directory extents.
pub fn extract_el_torito_boot_images(image: &[u8]) -> Result<ElToritoBootImages<'_>, ImageError> {
    if image.len() < (BOOT_CATALOG_LBA as usize + 1) * ISO_BLOCK_SIZE
        || !image.len().is_multiple_of(ISO_BLOCK_SIZE)
    {
        return Err(ImageError::InvalidInput(
            "ISO image is truncated or unaligned",
        ));
    }
    let pvd = logical_block(image, PRIMARY_VOLUME_DESCRIPTOR_LBA)?;
    require_descriptor(pvd, 1)?;
    let boot_record = logical_block(image, BOOT_RECORD_DESCRIPTOR_LBA)?;
    require_descriptor(boot_record, 0)?;
    if &boot_record[7..30] != BOOT_SYSTEM_IDENTIFIER {
        return Err(ImageError::InvalidInput(
            "El Torito boot record identifier is invalid",
        ));
    }
    let catalog_lba = read_u32_le(boot_record, 71);
    let catalog = logical_block(image, catalog_lba)?;
    if catalog[0] != 1
        || catalog[1] != 0
        || catalog[30..32] != [0x55, 0xaa]
        || el_torito_word_sum(&catalog[..32]) != 0
    {
        return Err(ImageError::InvalidInput(
            "El Torito validation entry is invalid",
        ));
    }
    if catalog[32] != 0x88
        || catalog[33] != 4
        || read_u16_le(catalog, 34) != 0
        || catalog[36] != XENITH_PARTITION_TYPE
        || catalog[37] != 0
        || read_u16_le(catalog, 38) != 1
    {
        return Err(ImageError::InvalidInput(
            "El Torito BIOS hard-disk entry is invalid",
        ));
    }
    let bios_lba = read_u32_le(catalog, 40);
    if catalog[64] != 0x91 || catalog[65] != 0xef || read_u16_le(catalog, 66) != 1 {
        return Err(ImageError::InvalidInput(
            "El Torito UEFI section is invalid",
        ));
    }
    if catalog[96] != 0x88
        || catalog[97] != 0
        || read_u16_le(catalog, 98) != 0
        || catalog[100] != 0
        || catalog[101] != 0
    {
        return Err(ImageError::InvalidInput(
            "El Torito UEFI boot entry is invalid",
        ));
    }
    let efi_load_sectors = read_u16_le(catalog, 102);
    let efi_lba = read_u32_le(catalog, 104);

    let root_lba = read_u32_le(pvd, 158);
    let root_len = read_u32_le(pvd, 166);
    let root = byte_extent(image, root_lba, root_len)?;
    let (bios_file_lba, bios_len) = find_iso_file(root, BIOS_IMAGE_NAME)?;
    let (efi_file_lba, efi_len) = find_iso_file(root, EFI_IMAGE_NAME)?;
    if bios_file_lba != bios_lba || efi_file_lba != efi_lba {
        return Err(ImageError::InvalidInput(
            "El Torito catalog and ISO extents disagree",
        ));
    }
    if usize::from(efi_load_sectors).checked_mul(crate::EFI_SECTOR_SIZE) != Some(efi_len as usize) {
        return Err(ImageError::InvalidInput(
            "El Torito UEFI load size is invalid",
        ));
    }
    let bios_disk = byte_extent(image, bios_lba, bios_len)?;
    validate_bios_boot_image(bios_disk)?;
    let efi_system_partition = byte_extent(image, efi_lba, efi_len)?;
    Ok(ElToritoBootImages {
        boot_catalog_lba: catalog_lba,
        bios_image_lba: bios_lba,
        efi_image_lba: efi_lba,
        efi_load_sectors,
        bios_disk,
        efi_system_partition,
    })
}

fn validate_bios_boot_image(image: &[u8]) -> Result<crate::DiskManifest, ImageError> {
    if image.len() < crate::DISK_SECTOR_SIZE * 2
        || !image.len().is_multiple_of(crate::DISK_SECTOR_SIZE)
    {
        return Err(ImageError::InvalidInput(
            "El Torito BIOS image is truncated or unaligned",
        ));
    }
    let manifest =
        crate::parse_manifest(&image[crate::DISK_SECTOR_SIZE..crate::DISK_SECTOR_SIZE * 2])?;
    let declared_bytes = manifest
        .image_sectors
        .checked_mul(crate::DISK_SECTOR_SIZE as u64)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or(ImageError::ImageTooLarge("BIOS manifest disk"))?;
    if declared_bytes > image.len() {
        return Err(ImageError::InvalidInput(
            "El Torito BIOS image is shorter than its manifest disk",
        ));
    }
    let validated = validate_disk_image(&image[..declared_bytes])?;
    if image[declared_bytes..].iter().any(|byte| *byte != 0) {
        return Err(ImageError::InvalidInput(
            "El Torito BIOS cylinder padding is not zero",
        ));
    }
    let emulated_sectors = u64::try_from(image.len() / crate::DISK_SECTOR_SIZE)
        .map_err(|_| ImageError::ImageTooLarge("BIOS hard-disk boot image"))?;
    let expected_sectors = validated
        .image_sectors
        .div_ceil(BIOS_CHS_CYLINDER_SECTORS)
        .checked_mul(BIOS_CHS_CYLINDER_SECTORS)
        .ok_or(ImageError::ImageTooLarge("BIOS hard-disk boot image"))?;
    if emulated_sectors != expected_sectors {
        return Err(ImageError::InvalidInput(
            "El Torito BIOS image is not cylinder aligned",
        ));
    }
    validate_bios_partition(image, emulated_sectors)?;
    Ok(validated)
}

fn validate_bios_partition(image: &[u8], image_sectors: u64) -> Result<(), ImageError> {
    let table = image
        .get(MBR_PARTITION_TABLE_OFFSET..MBR_PARTITION_TABLE_OFFSET + 64)
        .ok_or(ImageError::InvalidInput("BIOS disk MBR is truncated"))?;
    let entry = &table[..MBR_PARTITION_ENTRY_SIZE];
    let sector_count = image_sectors
        .checked_sub(1)
        .and_then(|count| u32::try_from(count).ok())
        .ok_or(ImageError::ImageTooLarge("BIOS hard-disk boot image"))?;
    if entry[0] != 0x80
        || entry[1..4] != lba_to_chs(1)
        || entry[4] != XENITH_PARTITION_TYPE
        || entry[5..8] != lba_to_chs(u64::from(sector_count))
        || read_u32_le(entry, 8) != 1
        || read_u32_le(entry, 12) != sector_count
        || table[MBR_PARTITION_ENTRY_SIZE..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(ImageError::InvalidInput(
            "El Torito BIOS partition table is invalid",
        ));
    }
    Ok(())
}

fn require_descriptor(descriptor: &[u8], kind: u8) -> Result<(), ImageError> {
    if descriptor[0] != kind || &descriptor[1..6] != STANDARD_IDENTIFIER || descriptor[6] != 1 {
        return Err(ImageError::InvalidInput("ISO volume descriptor is invalid"));
    }
    Ok(())
}

fn find_iso_file(directory: &[u8], name: &[u8]) -> Result<(u32, u32), ImageError> {
    let mut cursor = 0_usize;
    while cursor < directory.len() && directory[cursor] != 0 {
        let length = usize::from(directory[cursor]);
        let record = directory.get(cursor..cursor.saturating_add(length)).ok_or(
            ImageError::InvalidInput("ISO directory record is truncated"),
        )?;
        if record.len() < 34 {
            return Err(ImageError::InvalidInput("ISO directory record is invalid"));
        }
        let name_len = usize::from(record[32]);
        let identifier =
            record
                .get(33..33_usize.saturating_add(name_len))
                .ok_or(ImageError::InvalidInput(
                    "ISO directory identifier is truncated",
                ))?;
        if identifier == name {
            if record[25] & 2 != 0 {
                return Err(ImageError::InvalidInput("ISO boot image is a directory"));
            }
            return Ok((read_u32_le(record, 2), read_u32_le(record, 10)));
        }
        cursor = cursor
            .checked_add(length)
            .ok_or(ImageError::ImageTooLarge("ISO directory"))?;
    }
    Err(ImageError::InvalidInput(
        "required ISO boot image is missing",
    ))
}

fn logical_block(image: &[u8], lba: u32) -> Result<&[u8], ImageError> {
    let start = block_offset(lba)?;
    image
        .get(start..start + ISO_BLOCK_SIZE)
        .ok_or(ImageError::InvalidInput("ISO logical block is truncated"))
}

fn byte_extent(image: &[u8], lba: u32, byte_len: u32) -> Result<&[u8], ImageError> {
    let start = block_offset(lba)?;
    let length = usize::try_from(byte_len).map_err(|_| ImageError::ImageTooLarge("ISO extent"))?;
    image
        .get(start..start.saturating_add(length))
        .ok_or(ImageError::InvalidInput("ISO file extent is truncated"))
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn validate_inputs(
    bios_disk: &[u8],
    bootx64: &[u8],
    kernel: &[u8],
    initrd: &[u8],
    config: &IsoConfig,
) -> Result<(), ImageError> {
    validate_disk_image(bios_disk)?;
    if bootx64.len() < 2 || !bootx64.starts_with(b"MZ") {
        return Err(ImageError::InvalidInput(
            "BOOTX64.EFI must be a non-empty PE image",
        ));
    }
    if kernel.is_empty() {
        return Err(ImageError::InvalidInput("kernel must not be empty"));
    }
    if initrd.is_empty() {
        return Err(ImageError::InvalidInput("initrd must not be empty"));
    }
    if config.volume_id.is_empty()
        || config.volume_id.len() > 32
        || !config
            .volume_id
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(ImageError::InvalidVolumeId(config.volume_id.clone()));
    }
    Ok(())
}

fn prepare_bios_boot_image(bios_disk: &[u8]) -> Result<Vec<u8>, ImageError> {
    let manifest = validate_disk_image(bios_disk)?;
    let partition_area = bios_disk
        .get(MBR_PARTITION_TABLE_OFFSET..MBR_PARTITION_TABLE_OFFSET + 64)
        .ok_or(ImageError::InvalidInput("BIOS disk MBR is truncated"))?;
    if partition_area.iter().any(|byte| *byte != 0) {
        return Err(ImageError::InvalidInput(
            "BIOS disk stage1 overlaps the MBR partition table",
        ));
    }
    let emulated_sectors = manifest
        .image_sectors
        .div_ceil(BIOS_CHS_CYLINDER_SECTORS)
        .checked_mul(BIOS_CHS_CYLINDER_SECTORS)
        .filter(|sectors| *sectors <= BIOS_CHS_CYLINDER_SECTORS * BIOS_CHS_MAX_CYLINDERS)
        .ok_or(ImageError::ImageTooLarge("BIOS CHS boot image"))?;
    let sector_count = emulated_sectors
        .checked_sub(1)
        .and_then(|count| u32::try_from(count).ok())
        .ok_or(ImageError::ImageTooLarge("BIOS hard-disk boot image"))?;
    let last_lba = u64::from(sector_count);
    let emulated_bytes = emulated_sectors
        .checked_mul(crate::DISK_SECTOR_SIZE as u64)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or(ImageError::ImageTooLarge("BIOS hard-disk boot image"))?;
    let mut image = bios_disk.to_vec();
    image.resize(emulated_bytes, 0);
    let entry = &mut image
        [MBR_PARTITION_TABLE_OFFSET..MBR_PARTITION_TABLE_OFFSET + MBR_PARTITION_ENTRY_SIZE];
    entry[0] = 0x80;
    entry[1..4].copy_from_slice(&lba_to_chs(1));
    entry[4] = XENITH_PARTITION_TYPE;
    entry[5..8].copy_from_slice(&lba_to_chs(last_lba));
    entry[8..12].copy_from_slice(&1_u32.to_le_bytes());
    entry[12..16].copy_from_slice(&sector_count.to_le_bytes());
    Ok(image)
}

fn lba_to_chs(lba: u64) -> [u8; 3] {
    let cylinder = lba / BIOS_CHS_CYLINDER_SECTORS;
    if cylinder > 1_023 {
        return [0xfe, 0xff, 0xff];
    }
    let within_cylinder = lba % BIOS_CHS_CYLINDER_SECTORS;
    let head = within_cylinder / BIOS_CHS_SECTORS_PER_TRACK;
    let sector = within_cylinder % BIOS_CHS_SECTORS_PER_TRACK + 1;
    [
        head as u8,
        (sector as u8) | (((cylinder >> 8) as u8) << 6),
        cylinder as u8,
    ]
}

fn blocks_for(byte_len: usize, component: &'static str) -> Result<u32, ImageError> {
    let blocks = byte_len.div_ceil(ISO_BLOCK_SIZE);
    u32::try_from(blocks).map_err(|_| ImageError::ImageTooLarge(component))
}

fn write_primary_volume_descriptor(
    image: &mut [u8],
    layout: &IsoLayout,
    config: &IsoConfig,
) -> Result<(), ImageError> {
    let descriptor = logical_block_mut(image, PRIMARY_VOLUME_DESCRIPTOR_LBA)?;
    descriptor[0] = 1;
    descriptor[1..6].copy_from_slice(STANDARD_IDENTIFIER);
    descriptor[6] = 1;
    write_padded_ascii(&mut descriptor[8..40], "XENITH", b' ');
    write_padded_ascii(&mut descriptor[40..72], &config.volume_id, b' ');
    write_both_u32(descriptor, 80, layout.total_blocks);
    write_both_u16(descriptor, 120, 1);
    write_both_u16(descriptor, 124, 1);
    write_both_u16(descriptor, 128, ISO_BLOCK_SIZE as u16);
    write_both_u32(descriptor, 132, PATH_TABLE_SIZE);
    write_u32_le(descriptor, 140, LITTLE_ENDIAN_PATH_TABLE_LBA);
    write_u32_be(descriptor, 148, BIG_ENDIAN_PATH_TABLE_LBA);

    let root_record = directory_record(ROOT_DIRECTORY_LBA, ISO_BLOCK_SIZE as u32, 2, &[0])?;
    descriptor[156..156 + root_record.len()].copy_from_slice(&root_record);

    write_padded_ascii(&mut descriptor[318..446], "XENITH PROJECT", b' ');
    write_padded_ascii(&mut descriptor[446..574], "XENITH-ISO", b' ');
    write_padded_ascii(&mut descriptor[574..702], "XENITH-ISO", b' ');
    descriptor[702..813].fill(b' ');
    write_descriptor_time(&mut descriptor[813..830]);
    write_descriptor_time(&mut descriptor[830..847]);
    descriptor[847..881].fill(b'0');
    descriptor[863] = 0;
    descriptor[880] = 0;
    descriptor[881] = 1;
    Ok(())
}

fn write_boot_record_descriptor(image: &mut [u8], layout: &IsoLayout) -> Result<(), ImageError> {
    let descriptor = logical_block_mut(image, BOOT_RECORD_DESCRIPTOR_LBA)?;
    descriptor[0] = 0;
    descriptor[1..6].copy_from_slice(STANDARD_IDENTIFIER);
    descriptor[6] = 1;
    descriptor[7..7 + BOOT_SYSTEM_IDENTIFIER.len()].copy_from_slice(BOOT_SYSTEM_IDENTIFIER);
    write_u32_le(descriptor, 71, layout.boot_catalog_lba);
    Ok(())
}

fn write_volume_descriptor_terminator(image: &mut [u8]) -> Result<(), ImageError> {
    let descriptor = logical_block_mut(image, TERMINATOR_DESCRIPTOR_LBA)?;
    descriptor[0] = 255;
    descriptor[1..6].copy_from_slice(STANDARD_IDENTIFIER);
    descriptor[6] = 1;
    Ok(())
}

fn write_path_tables(image: &mut [u8], layout: &IsoLayout) -> Result<(), ImageError> {
    let little = logical_block_mut(image, LITTLE_ENDIAN_PATH_TABLE_LBA)?;
    little[0] = 1;
    little[1] = 0;
    write_u32_le(little, 2, layout.root_directory_lba);
    little[6..8].copy_from_slice(&1_u16.to_le_bytes());
    little[8] = 0;
    little[9] = 0;

    let big = logical_block_mut(image, BIG_ENDIAN_PATH_TABLE_LBA)?;
    big[0] = 1;
    big[1] = 0;
    write_u32_be(big, 2, layout.root_directory_lba);
    big[6..8].copy_from_slice(&1_u16.to_be_bytes());
    big[8] = 0;
    big[9] = 0;
    Ok(())
}

fn write_root_directory(image: &mut [u8], layout: &IsoLayout) -> Result<(), ImageError> {
    let records = [
        directory_record(layout.root_directory_lba, ISO_BLOCK_SIZE as u32, 2, &[0])?,
        directory_record(layout.root_directory_lba, ISO_BLOCK_SIZE as u32, 2, &[1])?,
        directory_record(
            layout.boot_catalog_lba,
            ISO_BLOCK_SIZE as u32,
            0,
            BOOT_CATALOG_NAME,
        )?,
        directory_record(
            layout.bios_boot_image_lba,
            layout.bios_boot_image_bytes,
            0,
            BIOS_IMAGE_NAME,
        )?,
        directory_record(
            layout.efi_boot_image_lba,
            layout.efi_boot_image_bytes,
            0,
            EFI_IMAGE_NAME,
        )?,
        directory_record(layout.kernel_lba, layout.kernel_bytes, 0, KERNEL_NAME)?,
        directory_record(layout.initrd_lba, layout.initrd_bytes, 0, INITRD_NAME)?,
    ];
    let required_bytes: usize = records.iter().map(Vec::len).sum();
    if required_bytes > ISO_BLOCK_SIZE {
        return Err(ImageError::ImageTooLarge("ISO root directory"));
    }

    let directory = logical_block_mut(image, ROOT_DIRECTORY_LBA)?;
    let mut cursor = 0;
    for record in records {
        let end = cursor + record.len();
        directory[cursor..end].copy_from_slice(&record);
        cursor = end;
    }
    Ok(())
}

fn write_boot_catalog(image: &mut [u8], layout: &IsoLayout) -> Result<(), ImageError> {
    let catalog = logical_block_mut(image, BOOT_CATALOG_LBA)?;

    // Validation entry, El Torito section 2.1.
    catalog[0] = 1;
    catalog[1] = 0; // x86 platform.
    write_padded_ascii(&mut catalog[4..28], "Xenith BIOS boot", b' ');
    catalog[30] = 0x55;
    catalog[31] = 0xaa;
    let validation_sum = el_torito_word_sum(&catalog[..32]);
    catalog[28..30].copy_from_slice(&validation_sum.wrapping_neg().to_le_bytes());

    // Initial/default BIOS entry in hard-disk-emulation mode. Firmware loads
    // the MBR sector and exposes the complete image through BIOS disk services.
    catalog[32] = 0x88;
    catalog[33] = 4;
    catalog[34..36].copy_from_slice(&0_u16.to_le_bytes());
    catalog[36] = XENITH_PARTITION_TYPE;
    catalog[37] = 0;
    catalog[38..40].copy_from_slice(&1_u16.to_le_bytes());
    catalog[40..44].copy_from_slice(&layout.bios_boot_image_lba.to_le_bytes());

    // Final section header and one UEFI no-emulation entry.
    catalog[64] = 0x91;
    catalog[65] = 0xef;
    catalog[66..68].copy_from_slice(&1_u16.to_le_bytes());
    write_padded_ascii(&mut catalog[68..96], "Xenith UEFI boot", b' ');
    catalog[96] = 0x88;
    catalog[97] = 0;
    catalog[98..100].copy_from_slice(&0_u16.to_le_bytes());
    catalog[100] = 0;
    catalog[101] = 0;
    let efi_load_sectors = u16::try_from(EFI_SYSTEM_PARTITION_SECTORS)
        .map_err(|_| ImageError::ImageTooLarge("EFI boot image"))?;
    catalog[102..104].copy_from_slice(&efi_load_sectors.to_le_bytes());
    catalog[104..108].copy_from_slice(&layout.efi_boot_image_lba.to_le_bytes());
    Ok(())
}

fn directory_record(
    extent_lba: u32,
    data_length: u32,
    flags: u8,
    identifier: &[u8],
) -> Result<Vec<u8>, ImageError> {
    if identifier.is_empty() || identifier.len() > usize::from(u8::MAX) {
        return Err(ImageError::InvalidInput(
            "ISO directory identifier has an invalid length",
        ));
    }
    let unpadded_length = 33_usize
        .checked_add(identifier.len())
        .ok_or(ImageError::ImageTooLarge("ISO directory record"))?;
    let record_length = if unpadded_length % 2 == 0 {
        unpadded_length
    } else {
        unpadded_length + 1
    };
    let encoded_length = u8::try_from(record_length)
        .map_err(|_| ImageError::ImageTooLarge("ISO directory record"))?;
    let mut record = vec![0_u8; record_length];
    record[0] = encoded_length;
    record[1] = 0;
    write_both_u32(&mut record, 2, extent_lba);
    write_both_u32(&mut record, 10, data_length);
    record[18..25].copy_from_slice(&[70, 1, 1, 0, 0, 0, 0]);
    record[25] = flags;
    record[26] = 0;
    record[27] = 0;
    write_both_u16(&mut record, 28, 1);
    record[32] = identifier.len() as u8;
    record[33..33 + identifier.len()].copy_from_slice(identifier);
    Ok(record)
}

fn write_file(image: &mut [u8], lba: u32, contents: &[u8]) -> Result<(), ImageError> {
    let start = block_offset(lba)?;
    let end = start
        .checked_add(contents.len())
        .ok_or(ImageError::ImageTooLarge("ISO file extent"))?;
    image[start..end].copy_from_slice(contents);
    Ok(())
}

fn el_torito_word_sum(entry: &[u8]) -> u16 {
    (0..entry.len() / 2).fold(0_u16, |sum, index| {
        let offset = index * 2;
        sum.wrapping_add(u16::from_le_bytes([entry[offset], entry[offset + 1]]))
    })
}

fn logical_block_mut(image: &mut [u8], lba: u32) -> Result<&mut [u8], ImageError> {
    let start = block_offset(lba)?;
    let end = start
        .checked_add(ISO_BLOCK_SIZE)
        .ok_or(ImageError::ImageTooLarge("ISO image"))?;
    image
        .get_mut(start..end)
        .ok_or(ImageError::ImageTooLarge("ISO image"))
}

fn block_offset(lba: u32) -> Result<usize, ImageError> {
    usize::try_from(lba)
        .ok()
        .and_then(|block| block.checked_mul(ISO_BLOCK_SIZE))
        .ok_or(ImageError::ImageTooLarge("ISO image"))
}

fn write_padded_ascii(field: &mut [u8], value: &str, padding: u8) {
    field.fill(padding);
    field[..value.len()].copy_from_slice(value.as_bytes());
}

fn write_descriptor_time(field: &mut [u8]) {
    field[..16].copy_from_slice(b"1970010100000000");
    field[16] = 0;
}

fn write_both_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn write_both_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    bytes[offset + 4..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn write_u32_le(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_be(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct ParsedRecord {
        name: Vec<u8>,
        lba: u32,
        byte_len: u32,
        flags: u8,
    }

    #[test]
    fn descriptors_catalog_and_file_extents_are_consistent() {
        let kernel = vec![0x4b; 4_097];
        let initrd = vec![0x49; 901];
        let bios_disk =
            crate::build_disk_image(&[0; 512], &[0xea; 1_301], &kernel, &initrd).unwrap();
        let bootx64 = [b'M', b'Z', 1, 2, 3];
        let config = IsoConfig {
            volume_id: "XENITH_TEST".to_owned(),
        };
        let (iso, layout) =
            build_iso_image_with_layout(&bios_disk, &bootx64, &kernel, &initrd, &config).unwrap();

        let extracted = extract_el_torito_boot_images(&iso).unwrap();
        assert_eq!(extracted.boot_catalog_lba, layout.boot_catalog_lba);
        assert_eq!(extracted.bios_image_lba, layout.bios_boot_image_lba);
        assert_eq!(extracted.efi_image_lba, layout.efi_boot_image_lba);
        assert_eq!(
            extracted.efi_load_sectors,
            EFI_SYSTEM_PARTITION_SECTORS as u16
        );
        let expected_bios_disk = prepare_bios_boot_image(&bios_disk).unwrap();
        assert_eq!(extracted.bios_disk, expected_bios_disk);
        let files = crate::extract_efi_system_partition_files(extracted.efi_system_partition)
            .expect("extract packaged UEFI payloads");
        assert_eq!(files.bootx64, bootx64);
        assert_eq!(files.kernel, kernel);
        assert_eq!(files.initrd, initrd);

        assert_eq!(iso.len() % ISO_BLOCK_SIZE, 0);
        assert_eq!(iso.len() / ISO_BLOCK_SIZE, layout.total_blocks as usize);
        assert_eq!(layout.primary_volume_descriptor_lba, 16);
        assert_eq!(layout.boot_catalog_lba, 22);
        assert_eq!(layout.bios_boot_image_lba, 23);

        let pvd = block(&iso, 16);
        assert_eq!(pvd[0], 1);
        assert_eq!(&pvd[1..6], b"CD001");
        assert_eq!(pvd[6], 1);
        assert_eq!(&pvd[40..51], b"XENITH_TEST");
        assert_both_u32(pvd, 80, layout.total_blocks);
        assert_both_u16(pvd, 128, ISO_BLOCK_SIZE as u16);
        assert_both_u32(pvd, 132, PATH_TABLE_SIZE);
        assert_eq!(read_u32_le(pvd, 140), LITTLE_ENDIAN_PATH_TABLE_LBA);
        assert_eq!(read_u32_be(pvd, 148), BIG_ENDIAN_PATH_TABLE_LBA);
        assert_eq!(read_u32_le(pvd, 158), ROOT_DIRECTORY_LBA);

        let boot_record = block(&iso, 17);
        assert_eq!(boot_record[0], 0);
        assert_eq!(&boot_record[1..6], b"CD001");
        assert_eq!(&boot_record[7..30], b"EL TORITO SPECIFICATION");
        assert_eq!(read_u32_le(boot_record, 71), BOOT_CATALOG_LBA);

        let terminator = block(&iso, 18);
        assert_eq!(terminator[0], 255);
        assert_eq!(&terminator[1..6], b"CD001");
        assert_eq!(terminator[6], 1);

        let little_path = block(&iso, 19);
        let big_path = block(&iso, 20);
        assert_eq!(little_path[0], 1);
        assert_eq!(read_u32_le(little_path, 2), ROOT_DIRECTORY_LBA);
        assert_eq!(read_u32_be(big_path, 2), ROOT_DIRECTORY_LBA);

        let catalog = block(&iso, layout.boot_catalog_lba);
        let validation_sum = el_torito_word_sum(&catalog[..32]);
        assert_eq!(validation_sum, 0);
        assert_eq!(&catalog[30..32], &[0x55, 0xaa]);
        assert_eq!(catalog[32], 0x88);
        assert_eq!(catalog[33], 4);
        assert_eq!(catalog[36], XENITH_PARTITION_TYPE);
        assert_eq!(u16::from_le_bytes([catalog[38], catalog[39]]), 1);
        assert_eq!(read_u32_le(catalog, 40), layout.bios_boot_image_lba);
        assert_eq!(catalog[64], 0x91);
        assert_eq!(catalog[65], 0xef);
        assert_eq!(u16::from_le_bytes([catalog[66], catalog[67]]), 1);
        assert_eq!(catalog[96], 0x88);
        assert_eq!(catalog[97], 0);
        assert_eq!(
            u16::from_le_bytes([catalog[102], catalog[103]]),
            EFI_SYSTEM_PARTITION_SECTORS as u16
        );
        assert_eq!(read_u32_le(catalog, 104), layout.efi_boot_image_lba);

        let bios_start = layout.bios_boot_image_lba as usize * ISO_BLOCK_SIZE;
        let embedded_bios = &iso[bios_start..bios_start + layout.bios_boot_image_bytes as usize];
        let manifest = validate_bios_boot_image(embedded_bios).unwrap();
        assert_eq!(
            &embedded_bios[crate::DISK_SECTOR_SIZE..crate::DISK_SECTOR_SIZE + 8],
            b"XENITHIM"
        );
        assert_eq!(manifest.entries[1].byte_len, kernel.len() as u64);
        assert_eq!(&embedded_bios[..446], &bios_disk[..446]);
        assert_eq!(&embedded_bios[510..bios_disk.len()], &bios_disk[510..]);
        assert!(embedded_bios[bios_disk.len()..]
            .iter()
            .all(|byte| *byte == 0));
        let partition = &embedded_bios
            [MBR_PARTITION_TABLE_OFFSET..MBR_PARTITION_TABLE_OFFSET + MBR_PARTITION_ENTRY_SIZE];
        assert_eq!(partition[0], 0x80);
        assert_eq!(&partition[1..4], &lba_to_chs(1));
        assert_eq!(partition[4], XENITH_PARTITION_TYPE);
        assert_eq!(
            &partition[5..8],
            &lba_to_chs((embedded_bios.len() / crate::DISK_SECTOR_SIZE - 1) as u64)
        );
        assert_eq!(read_u32_le(partition, 8), 1);
        assert_eq!(
            read_u32_le(partition, 12),
            (embedded_bios.len() / crate::DISK_SECTOR_SIZE) as u32 - 1
        );
        assert_eq!(embedded_bios.len() / crate::DISK_SECTOR_SIZE, 1_008);

        let efi_start = layout.efi_boot_image_lba as usize * ISO_BLOCK_SIZE;
        let embedded_efi = &iso[efi_start..efi_start + layout.efi_boot_image_bytes as usize];
        crate::validate_efi_system_partition(embedded_efi, &bootx64, &kernel, &initrd).unwrap();
        assert_extent(&iso, layout.kernel_lba, &kernel);
        assert_extent(&iso, layout.initrd_lba, &initrd);
    }

    #[test]
    fn root_directory_exposes_catalog_boot_kernel_and_initrd() {
        let kernel = [0x7f; 2_100];
        let initrd = [0xc0; 300];
        let disk = crate::build_disk_image(&[0; 512], &[0xea; 700], &kernel, &initrd).unwrap();
        let (iso, layout) =
            build_iso_image_with_layout(&disk, b"MZefi", &kernel, &initrd, &IsoConfig::default())
                .unwrap();
        let records = parse_directory(block(&iso, ROOT_DIRECTORY_LBA));

        assert_eq!(records.len(), 7);
        assert_eq!(records[0].name, [0]);
        assert_eq!(records[1].name, [1]);
        assert_eq!(records[0].flags, 2);
        assert_eq!(records[1].flags, 2);
        assert_eq!(
            find_record(&records, BOOT_CATALOG_NAME).lba,
            layout.boot_catalog_lba
        );
        assert_eq!(
            find_record(&records, BIOS_IMAGE_NAME).lba,
            layout.bios_boot_image_lba
        );
        assert_eq!(
            find_record(&records, EFI_IMAGE_NAME).lba,
            layout.efi_boot_image_lba
        );
        assert_eq!(find_record(&records, KERNEL_NAME).byte_len, 2_100);
        assert_eq!(find_record(&records, INITRD_NAME).byte_len, 300);
    }

    #[test]
    fn invalid_inputs_are_rejected_before_allocation() {
        assert!(matches!(
            build_iso_image(&[], b"MZ", &[1], &[1], &IsoConfig::default()),
            Err(ImageError::InvalidInput(_))
        ));
        let disk = crate::build_disk_image(&[0; 512], &[1], &[1], &[1]).unwrap();
        let config = IsoConfig {
            volume_id: "lowercase".to_owned(),
        };
        assert!(matches!(
            build_iso_image(&disk, b"MZ", &[1], &[1], &config),
            Err(ImageError::InvalidVolumeId(_))
        ));
    }

    #[test]
    fn extractor_rejects_corrupt_bios_catalog_and_partition_metadata() {
        let disk = crate::build_disk_image(&[0; 512], &[0xea; 700], &[1], &[2]).unwrap();
        let (iso, layout) =
            build_iso_image_with_layout(&disk, b"MZefi", &[1], &[2], &IsoConfig::default())
                .unwrap();

        let catalog_offset = layout.boot_catalog_lba as usize * ISO_BLOCK_SIZE;
        let mut corrupt_catalog = iso.clone();
        corrupt_catalog[catalog_offset + 36] = 0;
        assert!(matches!(
            extract_el_torito_boot_images(&corrupt_catalog),
            Err(ImageError::InvalidInput(
                "El Torito BIOS hard-disk entry is invalid"
            ))
        ));

        let bios_offset = layout.bios_boot_image_lba as usize * ISO_BLOCK_SIZE;
        let mut corrupt_partition = iso.clone();
        corrupt_partition[bios_offset + MBR_PARTITION_TABLE_OFFSET] = 0;
        assert!(matches!(
            extract_el_torito_boot_images(&corrupt_partition),
            Err(ImageError::InvalidInput(
                "El Torito BIOS partition table is invalid"
            ))
        ));

        let mut corrupt_padding = iso;
        let padding_offset = bios_offset + layout.bios_boot_image_bytes as usize - 1;
        corrupt_padding[padding_offset] = 1;
        assert!(matches!(
            extract_el_torito_boot_images(&corrupt_padding),
            Err(ImageError::InvalidInput(
                "El Torito BIOS cylinder padding is not zero"
            ))
        ));
    }

    fn block(image: &[u8], lba: u32) -> &[u8] {
        let start = lba as usize * ISO_BLOCK_SIZE;
        &image[start..start + ISO_BLOCK_SIZE]
    }

    fn assert_extent(image: &[u8], lba: u32, expected: &[u8]) {
        let start = lba as usize * ISO_BLOCK_SIZE;
        assert_eq!(&image[start..start + expected.len()], expected);
        let allocated_end = start + expected.len().div_ceil(ISO_BLOCK_SIZE) * ISO_BLOCK_SIZE;
        assert!(image[start + expected.len()..allocated_end]
            .iter()
            .all(|byte| *byte == 0));
    }

    fn parse_directory(directory: &[u8]) -> Vec<ParsedRecord> {
        let mut records = Vec::new();
        let mut cursor = 0;
        while directory[cursor] != 0 {
            let length = usize::from(directory[cursor]);
            let record = &directory[cursor..cursor + length];
            let name_length = usize::from(record[32]);
            records.push(ParsedRecord {
                name: record[33..33 + name_length].to_vec(),
                lba: read_u32_le(record, 2),
                byte_len: read_u32_le(record, 10),
                flags: record[25],
            });
            cursor += length;
        }
        records
    }

    fn find_record<'a>(records: &'a [ParsedRecord], name: &[u8]) -> &'a ParsedRecord {
        records.iter().find(|record| record.name == name).unwrap()
    }

    fn assert_both_u16(bytes: &[u8], offset: usize, expected: u16) {
        assert_eq!(
            u16::from_le_bytes([bytes[offset], bytes[offset + 1]]),
            expected
        );
        assert_eq!(
            u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]),
            expected
        );
    }

    fn assert_both_u32(bytes: &[u8], offset: usize, expected: u32) {
        assert_eq!(read_u32_le(bytes, offset), expected);
        assert_eq!(read_u32_be(bytes, offset + 4), expected);
    }

    fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    fn read_u32_be(bytes: &[u8], offset: usize) -> u32 {
        u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }
}
