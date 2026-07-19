//! Deterministic FAT16 EFI System Partition image construction.
//!
//! El Torito UEFI boot entries point at a FAT filesystem image rather than an
//! ISO9660 file tree.  This module emits the removable-media path required by
//! UEFI and keeps the kernel and initramfs beside the loader at the paths the
//! Xenith UEFI application opens.

use crate::ImageError;

pub const EFI_SECTOR_SIZE: usize = 512;
pub const EFI_SYSTEM_PARTITION_SECTORS: u32 = 32_768;

const RESERVED_SECTORS: u16 = 1;
const FAT_COUNT: u8 = 2;
const FAT_SECTORS: u16 = 128;
const ROOT_ENTRY_COUNT: u16 = 512;
const ROOT_DIRECTORY_SECTORS: u32 = 32;
const FIRST_DATA_SECTOR: u32 =
    RESERVED_SECTORS as u32 + FAT_COUNT as u32 * FAT_SECTORS as u32 + ROOT_DIRECTORY_SECTORS;
const DATA_CLUSTER_COUNT: u32 = EFI_SYSTEM_PARTITION_SECTORS - FIRST_DATA_SECTOR;
const FAT16_EOC: u16 = 0xffff;

const EFI_DIRECTORY_CLUSTER: u16 = 2;
const BOOT_DIRECTORY_CLUSTER: u16 = 3;
const XENITH_DIRECTORY_CLUSTER: u16 = 4;
const FIRST_FILE_CLUSTER: u16 = 5;

const EFI_NAME: [u8; 11] = *b"EFI        ";
const BOOT_NAME: [u8; 11] = *b"BOOT       ";
const XENITH_NAME: [u8; 11] = *b"XENITH     ";
const BOOTX64_NAME: [u8; 11] = *b"BOOTX64 EFI";
const KERNEL_NAME: [u8; 11] = *b"KERNEL  ELF";
const INITRD_SHORT_NAME: [u8; 11] = *b"INITRD~1CPI";
const INITRD_LONG_NAME: &str = "initrd.cpio";

/// Cluster positions assigned to files in a generated EFI System Partition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EfiSystemPartitionLayout {
    pub total_sectors: u32,
    pub fat_sectors: u16,
    pub first_data_sector: u32,
    pub bootx64_cluster: u16,
    pub kernel_cluster: u16,
    pub initrd_cluster: u16,
}

/// Owned files selected through the exact removable-media paths in one ESP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EfiSystemPartitionFiles {
    pub bootx64: Vec<u8>,
    pub kernel: Vec<u8>,
    pub initrd: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct Allocation {
    first_cluster: u16,
    cluster_count: u16,
    byte_len: u32,
}

/// Builds a FAT16 image containing the Xenith removable-media UEFI tree.
pub fn build_efi_system_partition(
    bootx64: &[u8],
    kernel: &[u8],
    initrd: &[u8],
) -> Result<Vec<u8>, ImageError> {
    build_efi_system_partition_with_layout(bootx64, kernel, initrd).map(|(image, _)| image)
}

/// Builds the FAT16 image and returns the allocated file clusters.
pub fn build_efi_system_partition_with_layout(
    bootx64: &[u8],
    kernel: &[u8],
    initrd: &[u8],
) -> Result<(Vec<u8>, EfiSystemPartitionLayout), ImageError> {
    validate_payloads(bootx64, kernel, initrd)?;

    let bootx64_allocation = allocation(FIRST_FILE_CLUSTER, bootx64)?;
    let kernel_first = next_cluster(bootx64_allocation)?;
    let kernel_allocation = allocation(kernel_first, kernel)?;
    let initrd_first = next_cluster(kernel_allocation)?;
    let initrd_allocation = allocation(initrd_first, initrd)?;
    let allocation_end = u32::from(initrd_allocation.first_cluster)
        .checked_add(u32::from(initrd_allocation.cluster_count))
        .ok_or(ImageError::ImageTooLarge("EFI system partition"))?;
    let first_unavailable_cluster = DATA_CLUSTER_COUNT + 2;
    if allocation_end > first_unavailable_cluster {
        return Err(ImageError::ImageTooLarge("EFI system partition payloads"));
    }

    let byte_len = usize::try_from(EFI_SYSTEM_PARTITION_SECTORS)
        .ok()
        .and_then(|sectors| sectors.checked_mul(EFI_SECTOR_SIZE))
        .ok_or(ImageError::ImageTooLarge("EFI system partition"))?;
    let mut image = vec![0_u8; byte_len];
    write_boot_sector(&mut image);
    initialize_fats(&mut image);
    mark_directory_clusters(&mut image);
    write_chain(&mut image, bootx64_allocation)?;
    write_chain(&mut image, kernel_allocation)?;
    write_chain(&mut image, initrd_allocation)?;
    write_directories(
        &mut image,
        bootx64_allocation,
        kernel_allocation,
        initrd_allocation,
    )?;
    write_allocation(&mut image, bootx64_allocation, bootx64)?;
    write_allocation(&mut image, kernel_allocation, kernel)?;
    write_allocation(&mut image, initrd_allocation, initrd)?;

    let layout = EfiSystemPartitionLayout {
        total_sectors: EFI_SYSTEM_PARTITION_SECTORS,
        fat_sectors: FAT_SECTORS,
        first_data_sector: FIRST_DATA_SECTOR,
        bootx64_cluster: bootx64_allocation.first_cluster,
        kernel_cluster: kernel_allocation.first_cluster,
        initrd_cluster: initrd_allocation.first_cluster,
    };
    validate_efi_system_partition(&image, bootx64, kernel, initrd)?;
    Ok((image, layout))
}

/// Parses the generated FAT16 tree and verifies its required paths and bytes.
pub fn validate_efi_system_partition(
    image: &[u8],
    bootx64: &[u8],
    kernel: &[u8],
    initrd: &[u8],
) -> Result<(), ImageError> {
    let geometry = parse_geometry(image)?;
    let efi = find_entry(root_directory(image, geometry)?, &EFI_NAME)?;
    require_directory(efi)?;
    let efi_directory = cluster_bytes(image, geometry, entry_cluster(efi))?;
    let boot = find_entry(efi_directory, &BOOT_NAME)?;
    let xenith = find_entry(efi_directory, &XENITH_NAME)?;
    require_directory(boot)?;
    require_directory(xenith)?;

    let boot_directory = cluster_bytes(image, geometry, entry_cluster(boot))?;
    let bootx64_entry = find_entry(boot_directory, &BOOTX64_NAME)?;
    let xenith_directory = cluster_bytes(image, geometry, entry_cluster(xenith))?;
    let kernel_entry = find_entry(xenith_directory, &KERNEL_NAME)?;
    let initrd_entry = find_long_entry(xenith_directory, INITRD_LONG_NAME, &INITRD_SHORT_NAME)?;

    compare_file(image, geometry, bootx64_entry, bootx64)?;
    compare_file(image, geometry, kernel_entry, kernel)?;
    compare_file(image, geometry, initrd_entry, initrd)?;
    Ok(())
}

/// Parses a FAT16 ESP and returns the exact files consumed by Xenith's UEFI
/// loader. Directory types, long-name metadata, FAT chains, and terminal EOC
/// markers are all validated before any bytes are returned.
pub fn extract_efi_system_partition_files(
    image: &[u8],
) -> Result<EfiSystemPartitionFiles, ImageError> {
    let geometry = parse_geometry(image)?;
    let efi = find_entry(root_directory(image, geometry)?, &EFI_NAME)?;
    require_directory(efi)?;
    let efi_directory = cluster_bytes(image, geometry, entry_cluster(efi))?;
    let boot = find_entry(efi_directory, &BOOT_NAME)?;
    let xenith = find_entry(efi_directory, &XENITH_NAME)?;
    require_directory(boot)?;
    require_directory(xenith)?;

    let boot_directory = cluster_bytes(image, geometry, entry_cluster(boot))?;
    let bootx64_entry = find_entry(boot_directory, &BOOTX64_NAME)?;
    let xenith_directory = cluster_bytes(image, geometry, entry_cluster(xenith))?;
    let kernel_entry = find_entry(xenith_directory, &KERNEL_NAME)?;
    let initrd_entry = find_long_entry(xenith_directory, INITRD_LONG_NAME, &INITRD_SHORT_NAME)?;

    let files = EfiSystemPartitionFiles {
        bootx64: read_file(image, geometry, bootx64_entry)?,
        kernel: read_file(image, geometry, kernel_entry)?,
        initrd: read_file(image, geometry, initrd_entry)?,
    };
    validate_payloads(&files.bootx64, &files.kernel, &files.initrd)?;
    Ok(files)
}

fn validate_payloads(bootx64: &[u8], kernel: &[u8], initrd: &[u8]) -> Result<(), ImageError> {
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
    Ok(())
}

fn allocation(first_cluster: u16, payload: &[u8]) -> Result<Allocation, ImageError> {
    let clusters = payload.len().div_ceil(EFI_SECTOR_SIZE);
    let cluster_count = u16::try_from(clusters)
        .map_err(|_| ImageError::ImageTooLarge("EFI system partition payload"))?;
    let byte_len = u32::try_from(payload.len())
        .map_err(|_| ImageError::ImageTooLarge("EFI system partition payload"))?;
    Ok(Allocation {
        first_cluster,
        cluster_count,
        byte_len,
    })
}

fn next_cluster(allocation: Allocation) -> Result<u16, ImageError> {
    allocation
        .first_cluster
        .checked_add(allocation.cluster_count)
        .ok_or(ImageError::ImageTooLarge("EFI system partition payload"))
}

fn write_boot_sector(image: &mut [u8]) {
    let sector = &mut image[..EFI_SECTOR_SIZE];
    sector[..3].copy_from_slice(&[0xeb, 0x3c, 0x90]);
    sector[3..11].copy_from_slice(b"XENITH  ");
    write_u16(sector, 11, EFI_SECTOR_SIZE as u16);
    sector[13] = 1;
    write_u16(sector, 14, RESERVED_SECTORS);
    sector[16] = FAT_COUNT;
    write_u16(sector, 17, ROOT_ENTRY_COUNT);
    write_u16(sector, 19, EFI_SYSTEM_PARTITION_SECTORS as u16);
    sector[21] = 0xf8;
    write_u16(sector, 22, FAT_SECTORS);
    write_u16(sector, 24, 32);
    write_u16(sector, 26, 64);
    write_u32(sector, 28, 0);
    write_u32(sector, 32, 0);
    sector[36] = 0x80;
    sector[38] = 0x29;
    write_u32(sector, 39, 0x5845_4e49);
    sector[43..54].copy_from_slice(b"XENITH ESP ");
    sector[54..62].copy_from_slice(b"FAT16   ");
    sector[510..512].copy_from_slice(&[0x55, 0xaa]);
}

fn initialize_fats(image: &mut [u8]) {
    for fat_index in 0..FAT_COUNT {
        set_fat_entry(image, fat_index, 0, 0xfff8);
        set_fat_entry(image, fat_index, 1, FAT16_EOC);
    }
}

fn mark_directory_clusters(image: &mut [u8]) {
    for cluster in [
        EFI_DIRECTORY_CLUSTER,
        BOOT_DIRECTORY_CLUSTER,
        XENITH_DIRECTORY_CLUSTER,
    ] {
        for fat_index in 0..FAT_COUNT {
            set_fat_entry(image, fat_index, cluster, FAT16_EOC);
        }
    }
}

fn write_chain(image: &mut [u8], allocation: Allocation) -> Result<(), ImageError> {
    if allocation.cluster_count == 0 {
        return Err(ImageError::InvalidInput(
            "EFI system partition files must not be empty",
        ));
    }
    for index in 0..allocation.cluster_count {
        let cluster = allocation
            .first_cluster
            .checked_add(index)
            .ok_or(ImageError::ImageTooLarge("EFI FAT chain"))?;
        let value = if index + 1 == allocation.cluster_count {
            FAT16_EOC
        } else {
            cluster + 1
        };
        for fat_index in 0..FAT_COUNT {
            set_fat_entry(image, fat_index, cluster, value);
        }
    }
    Ok(())
}

fn set_fat_entry(image: &mut [u8], fat_index: u8, cluster: u16, value: u16) {
    let fat_sector = u32::from(RESERVED_SECTORS) + u32::from(fat_index) * u32::from(FAT_SECTORS);
    let offset = fat_sector as usize * EFI_SECTOR_SIZE + usize::from(cluster) * 2;
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_directories(
    image: &mut [u8],
    bootx64: Allocation,
    kernel: Allocation,
    initrd: Allocation,
) -> Result<(), ImageError> {
    let root_offset = (u32::from(RESERVED_SECTORS) + u32::from(FAT_COUNT) * u32::from(FAT_SECTORS))
        as usize
        * EFI_SECTOR_SIZE;
    write_entry(
        &mut image[root_offset..root_offset + 32],
        *b"XENITH ESP ",
        0x08,
        0,
        0,
    );
    write_entry(
        &mut image[root_offset + 32..root_offset + 64],
        EFI_NAME,
        0x10,
        EFI_DIRECTORY_CLUSTER,
        0,
    );

    let efi = cluster_bytes_mut(image, EFI_DIRECTORY_CLUSTER)?;
    write_dot_entries(efi, EFI_DIRECTORY_CLUSTER, 0);
    write_entry(&mut efi[64..96], BOOT_NAME, 0x10, BOOT_DIRECTORY_CLUSTER, 0);
    write_entry(
        &mut efi[96..128],
        XENITH_NAME,
        0x10,
        XENITH_DIRECTORY_CLUSTER,
        0,
    );

    let boot = cluster_bytes_mut(image, BOOT_DIRECTORY_CLUSTER)?;
    write_dot_entries(boot, BOOT_DIRECTORY_CLUSTER, EFI_DIRECTORY_CLUSTER);
    write_entry(
        &mut boot[64..96],
        BOOTX64_NAME,
        0x20,
        bootx64.first_cluster,
        bootx64.byte_len,
    );

    let xenith = cluster_bytes_mut(image, XENITH_DIRECTORY_CLUSTER)?;
    write_dot_entries(xenith, XENITH_DIRECTORY_CLUSTER, EFI_DIRECTORY_CLUSTER);
    write_entry(
        &mut xenith[64..96],
        KERNEL_NAME,
        0x20,
        kernel.first_cluster,
        kernel.byte_len,
    );
    write_lfn_entry(
        &mut xenith[96..128],
        INITRD_LONG_NAME,
        lfn_checksum(&INITRD_SHORT_NAME),
    );
    write_entry(
        &mut xenith[128..160],
        INITRD_SHORT_NAME,
        0x20,
        initrd.first_cluster,
        initrd.byte_len,
    );
    Ok(())
}

fn write_dot_entries(directory: &mut [u8], current: u16, parent: u16) {
    write_entry(&mut directory[..32], *b".          ", 0x10, current, 0);
    write_entry(&mut directory[32..64], *b"..         ", 0x10, parent, 0);
}

fn write_entry(entry: &mut [u8], name: [u8; 11], attributes: u8, cluster: u16, size: u32) {
    entry.fill(0);
    entry[..11].copy_from_slice(&name);
    entry[11] = attributes;
    write_u16(entry, 14, 0);
    write_u16(entry, 16, 0x0021);
    write_u16(entry, 22, 0);
    write_u16(entry, 24, 0x0021);
    write_u16(entry, 26, cluster);
    write_u32(entry, 28, size);
}

fn write_lfn_entry(entry: &mut [u8], name: &str, checksum: u8) {
    entry.fill(0xff);
    entry[0] = 0x41;
    entry[11] = 0x0f;
    entry[12] = 0;
    entry[13] = checksum;
    entry[26..28].fill(0);
    let mut units = [0xffff_u16; 13];
    let encoded: Vec<u16> = name.encode_utf16().collect();
    units[..encoded.len()].copy_from_slice(&encoded);
    units[encoded.len()] = 0;
    for (unit, offset) in units
        .iter()
        .zip([1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30])
    {
        entry[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
}

fn lfn_checksum(short_name: &[u8; 11]) -> u8 {
    short_name
        .iter()
        .fold(0_u8, |sum, byte| sum.rotate_right(1).wrapping_add(*byte))
}

fn write_allocation(
    image: &mut [u8],
    allocation: Allocation,
    payload: &[u8],
) -> Result<(), ImageError> {
    let start = cluster_offset(allocation.first_cluster)?;
    let end = start
        .checked_add(payload.len())
        .ok_or(ImageError::ImageTooLarge("EFI payload"))?;
    image[start..end].copy_from_slice(payload);
    Ok(())
}

fn cluster_bytes_mut(image: &mut [u8], cluster: u16) -> Result<&mut [u8], ImageError> {
    let start = cluster_offset(cluster)?;
    image
        .get_mut(start..start + EFI_SECTOR_SIZE)
        .ok_or(ImageError::ImageTooLarge("EFI directory"))
}

fn cluster_offset(cluster: u16) -> Result<usize, ImageError> {
    if cluster < 2 {
        return Err(ImageError::InvalidInput("invalid EFI FAT cluster"));
    }
    let sector = FIRST_DATA_SECTOR
        .checked_add(u32::from(cluster) - 2)
        .ok_or(ImageError::ImageTooLarge("EFI FAT cluster"))?;
    usize::try_from(sector)
        .ok()
        .and_then(|value| value.checked_mul(EFI_SECTOR_SIZE))
        .ok_or(ImageError::ImageTooLarge("EFI FAT cluster"))
}

#[derive(Clone, Copy)]
struct Geometry {
    reserved_sectors: u16,
    fat_count: u8,
    fat_sectors: u16,
    root_entry_count: u16,
    first_data_sector: u32,
}

fn parse_geometry(image: &[u8]) -> Result<Geometry, ImageError> {
    if image.len() < EFI_SECTOR_SIZE || image[510..512] != [0x55, 0xaa] {
        return Err(ImageError::InvalidInput("EFI FAT boot sector is invalid"));
    }
    if read_u16(image, 11) != EFI_SECTOR_SIZE as u16 || image[13] != 1 {
        return Err(ImageError::InvalidInput("EFI FAT geometry is unsupported"));
    }
    let reserved_sectors = read_u16(image, 14);
    let fat_count = image[16];
    let root_entry_count = read_u16(image, 17);
    let total_sectors = u32::from(read_u16(image, 19));
    let fat_sectors = read_u16(image, 22);
    let expected_len = usize::try_from(total_sectors)
        .ok()
        .and_then(|sectors| sectors.checked_mul(EFI_SECTOR_SIZE))
        .ok_or(ImageError::ImageTooLarge("EFI system partition"))?;
    if expected_len != image.len()
        || reserved_sectors == 0
        || fat_count == 0
        || fat_sectors == 0
        || root_entry_count == 0
    {
        return Err(ImageError::InvalidInput("EFI FAT geometry is invalid"));
    }
    let root_sectors = u32::from(root_entry_count)
        .checked_mul(32)
        .and_then(|bytes| bytes.checked_add(EFI_SECTOR_SIZE as u32 - 1))
        .map(|bytes| bytes / EFI_SECTOR_SIZE as u32)
        .ok_or(ImageError::ImageTooLarge("EFI root directory"))?;
    let first_data_sector = u32::from(reserved_sectors)
        .checked_add(u32::from(fat_count) * u32::from(fat_sectors))
        .and_then(|value| value.checked_add(root_sectors))
        .ok_or(ImageError::ImageTooLarge("EFI FAT geometry"))?;
    let cluster_count = total_sectors
        .checked_sub(first_data_sector)
        .ok_or(ImageError::InvalidInput("EFI FAT data area is invalid"))?;
    if !(4_085..65_525).contains(&cluster_count) {
        return Err(ImageError::InvalidInput("EFI image is not FAT16"));
    }
    Ok(Geometry {
        reserved_sectors,
        fat_count,
        fat_sectors,
        root_entry_count,
        first_data_sector,
    })
}

fn root_directory(image: &[u8], geometry: Geometry) -> Result<&[u8], ImageError> {
    let start_sector = u32::from(geometry.reserved_sectors)
        + u32::from(geometry.fat_count) * u32::from(geometry.fat_sectors);
    let start = start_sector as usize * EFI_SECTOR_SIZE;
    let length = usize::from(geometry.root_entry_count) * 32;
    image
        .get(start..start + length)
        .ok_or(ImageError::InvalidInput("EFI root directory is truncated"))
}

fn cluster_bytes(image: &[u8], geometry: Geometry, cluster: u16) -> Result<&[u8], ImageError> {
    if cluster < 2 {
        return Err(ImageError::InvalidInput("EFI directory cluster is invalid"));
    }
    let sector = geometry.first_data_sector + u32::from(cluster) - 2;
    let start = sector as usize * EFI_SECTOR_SIZE;
    image
        .get(start..start + EFI_SECTOR_SIZE)
        .ok_or(ImageError::InvalidInput(
            "EFI directory cluster is truncated",
        ))
}

fn find_entry<'a>(directory: &'a [u8], name: &[u8; 11]) -> Result<&'a [u8], ImageError> {
    for entry in directory.as_chunks::<32>().0 {
        if entry[0] == 0 {
            break;
        }
        if entry[0] != 0xe5 && entry[11] != 0x0f && &entry[..11] == name {
            return Ok(entry);
        }
    }
    Err(ImageError::InvalidInput(
        "required EFI system partition path is missing",
    ))
}

fn find_long_entry<'a>(
    directory: &'a [u8],
    long_name: &str,
    short_name: &[u8; 11],
) -> Result<&'a [u8], ImageError> {
    let entries = directory.as_chunks::<32>().0;
    for (index, entry) in entries.iter().enumerate() {
        if entry[0] == 0 {
            break;
        }
        if entry[11] != 0x0f && &entry[..11] == short_name {
            let lfn = index
                .checked_sub(1)
                .and_then(|previous| entries.get(previous))
                .ok_or(ImageError::InvalidInput("EFI long file name is missing"))?;
            if lfn[11] != 0x0f || lfn[13] != lfn_checksum(short_name) {
                return Err(ImageError::InvalidInput(
                    "EFI long file name metadata is invalid",
                ));
            }
            let decoded = decode_lfn(lfn)?;
            if !decoded.eq_ignore_ascii_case(long_name) {
                return Err(ImageError::InvalidInput("EFI long file name is invalid"));
            }
            return Ok(entry);
        }
    }
    Err(ImageError::InvalidInput(
        "required EFI system partition path is missing",
    ))
}

fn decode_lfn(entry: &[u8]) -> Result<String, ImageError> {
    let mut units = Vec::new();
    for offset in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30] {
        let unit = read_u16(entry, offset);
        if unit == 0 || unit == 0xffff {
            break;
        }
        units.push(unit);
    }
    String::from_utf16(&units)
        .map_err(|_| ImageError::InvalidInput("EFI long file name is not UTF-16"))
}

fn require_directory(entry: &[u8]) -> Result<(), ImageError> {
    if entry[11] & 0x10 == 0 {
        return Err(ImageError::InvalidInput(
            "EFI system partition path component is not a directory",
        ));
    }
    Ok(())
}

fn compare_file(
    image: &[u8],
    geometry: Geometry,
    entry: &[u8],
    expected: &[u8],
) -> Result<(), ImageError> {
    if entry[11] & 0x10 != 0 || read_u32(entry, 28) as usize != expected.len() {
        return Err(ImageError::InvalidInput("EFI file metadata is invalid"));
    }
    let mut cluster = entry_cluster(entry);
    let mut compared = 0_usize;
    let mut visits = 0_u32;
    while compared < expected.len() {
        visits += 1;
        if visits > DATA_CLUSTER_COUNT {
            return Err(ImageError::InvalidInput("EFI FAT chain loops"));
        }
        let data = cluster_bytes(image, geometry, cluster)?;
        let count = (expected.len() - compared).min(EFI_SECTOR_SIZE);
        if data[..count] != expected[compared..compared + count] {
            return Err(ImageError::InvalidInput("EFI file contents mismatch"));
        }
        compared += count;
        let next = fat_entry(image, geometry, cluster)?;
        if compared == expected.len() {
            if next < 0xfff8 {
                return Err(ImageError::InvalidInput("EFI FAT chain is too long"));
            }
        } else if !(2..0xfff8).contains(&next) {
            return Err(ImageError::InvalidInput("EFI FAT chain is truncated"));
        } else {
            cluster = next;
        }
    }
    Ok(())
}

fn read_file(image: &[u8], geometry: Geometry, entry: &[u8]) -> Result<Vec<u8>, ImageError> {
    if entry[11] & 0x10 != 0 {
        return Err(ImageError::InvalidInput("EFI file metadata is invalid"));
    }
    let byte_len = read_u32(entry, 28) as usize;
    if byte_len == 0 {
        return Err(ImageError::InvalidInput("EFI file is empty"));
    }
    let mut bytes = Vec::with_capacity(byte_len);
    let mut cluster = entry_cluster(entry);
    let mut visits = 0_u32;
    while bytes.len() < byte_len {
        visits += 1;
        if visits > DATA_CLUSTER_COUNT {
            return Err(ImageError::InvalidInput("EFI FAT chain loops"));
        }
        let data = cluster_bytes(image, geometry, cluster)?;
        let count = (byte_len - bytes.len()).min(EFI_SECTOR_SIZE);
        bytes.extend_from_slice(&data[..count]);
        let next = fat_entry(image, geometry, cluster)?;
        if bytes.len() == byte_len {
            if next < 0xfff8 {
                return Err(ImageError::InvalidInput("EFI FAT chain is too long"));
            }
        } else if !(2..0xfff8).contains(&next) {
            return Err(ImageError::InvalidInput("EFI FAT chain is truncated"));
        } else {
            cluster = next;
        }
    }
    Ok(bytes)
}

fn fat_entry(image: &[u8], geometry: Geometry, cluster: u16) -> Result<u16, ImageError> {
    let offset =
        usize::from(geometry.reserved_sectors) * EFI_SECTOR_SIZE + usize::from(cluster) * 2;
    image
        .get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .ok_or(ImageError::InvalidInput("EFI FAT is truncated"))
}

fn entry_cluster(entry: &[u8]) -> u16 {
    read_u16(entry, 26)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fat16_tree_contains_exact_uefi_paths_and_payloads() {
        let bootx64 = [b'M', b'Z', 1, 2, 3, 4];
        let kernel = vec![0x4b; 1_301];
        let initrd = vec![0x49; 777];
        let (image, layout) =
            build_efi_system_partition_with_layout(&bootx64, &kernel, &initrd).unwrap();

        assert_eq!(image.len(), 16 * 1024 * 1024);
        assert_eq!(layout.total_sectors, 32_768);
        assert_eq!(&image[510..512], &[0x55, 0xaa]);
        assert_eq!(read_u16(&image, 11), 512);
        assert_eq!(&image[54..62], b"FAT16   ");
        validate_efi_system_partition(&image, &bootx64, &kernel, &initrd).unwrap();

        let geometry = parse_geometry(&image).unwrap();
        let efi = find_entry(root_directory(&image, geometry).unwrap(), &EFI_NAME).unwrap();
        let efi_directory = cluster_bytes(&image, geometry, entry_cluster(efi)).unwrap();
        assert!(find_entry(efi_directory, &BOOT_NAME).is_ok());
        assert!(find_entry(efi_directory, &XENITH_NAME).is_ok());
    }

    #[test]
    fn validator_detects_file_corruption() {
        let bootx64 = [b'M', b'Z', 1];
        let kernel = [0x4b; 600];
        let initrd = [0x49; 300];
        let (mut image, layout) =
            build_efi_system_partition_with_layout(&bootx64, &kernel, &initrd).unwrap();
        let offset = cluster_offset(layout.kernel_cluster).unwrap();
        image[offset] ^= 1;
        assert!(validate_efi_system_partition(&image, &bootx64, &kernel, &initrd).is_err());
    }

    #[test]
    fn uefi_loader_must_be_a_pe_image() {
        assert!(matches!(
            build_efi_system_partition(b"ELF", b"kernel", b"initrd"),
            Err(ImageError::InvalidInput(
                "BOOTX64.EFI must be a non-empty PE image"
            ))
        ));
    }
}
