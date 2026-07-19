//! Read-only consistency checking for XenithFS and FAT32 images.

use std::fmt;

use xenith_fs_format::{
    crc32, parse_directory, DiskInode, InodeKind, JournalError, JournalHeader, Superblock,
    SuperblockError, BLOCK_SIZE, INODE_SIZE, MAX_DIRECTORY_SIZE,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub filesystem: &'static str,
    pub blocks: u64,
    pub allocated_blocks: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckError {
    Truncated,
    UnknownFilesystem,
    BadChecksum,
    Invalid(&'static str),
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("filesystem image is truncated"),
            Self::UnknownFilesystem => f.write_str("unknown filesystem signature"),
            Self::BadChecksum => f.write_str("superblock checksum mismatch"),
            Self::Invalid(reason) => write!(f, "invalid filesystem: {reason}"),
        }
    }
}

impl std::error::Error for CheckError {}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, CheckError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(CheckError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, CheckError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(CheckError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

pub fn check(image: &[u8]) -> Result<Report, CheckError> {
    if image.starts_with(xenith_fs_format::MAGIC) {
        check_xenithfs(image)
    } else if image.get(82..90) == Some(b"FAT32   ") {
        check_fat32(image)
    } else {
        Err(CheckError::UnknownFilesystem)
    }
}

pub fn check_xenithfs(image: &[u8]) -> Result<Report, CheckError> {
    let superblock = Superblock::parse(image).map_err(map_superblock_error)?;
    let image_len = image_bytes(superblock.total_blocks)?;
    let source = image.get(..image_len).ok_or(CheckError::Truncated)?;
    let journal_offset = block_offset(superblock.journal_start)?;
    let header = JournalHeader::parse(
        source
            .get(journal_offset..journal_offset + BLOCK_SIZE)
            .ok_or(CheckError::Truncated)?,
    )
    .map_err(map_journal_error)?;
    header
        .validate_for(&superblock)
        .map_err(map_journal_error)?;

    let replayed;
    let effective = if header.prepared {
        replayed = replay_to_memory(source, &superblock, &header)?;
        replayed.as_slice()
    } else {
        source
    };

    let bitmap_offset = block_offset(superblock.bitmap_start)?;
    let bitmap_len = usize::try_from(superblock.bitmap_blocks)
        .ok()
        .and_then(|blocks| blocks.checked_mul(BLOCK_SIZE))
        .ok_or(CheckError::Invalid("bitmap geometry overflow"))?;
    let bitmap = effective
        .get(bitmap_offset..bitmap_offset + bitmap_len)
        .ok_or(CheckError::Truncated)?;

    let block_count = usize::try_from(superblock.total_blocks)
        .map_err(|_| CheckError::Invalid("block count exceeds host limits"))?;
    let inode_count = usize::try_from(superblock.inode_count)
        .map_err(|_| CheckError::Invalid("inode count exceeds host limits"))?;
    let mut expected_blocks = vec![false; block_count];
    expected_blocks[..superblock.data_start as usize].fill(true);
    for block in 0..superblock.data_start {
        if !bitmap_get(bitmap, block)? {
            return Err(CheckError::Invalid("reserved block is free in bitmap"));
        }
    }

    let mut inodes = Vec::with_capacity(inode_count);
    for index in 0..inode_count {
        let number = index as u64 + 1;
        let offset = inode_offset(&superblock, number)?;
        let record = effective
            .get(offset..offset + INODE_SIZE)
            .ok_or(CheckError::Truncated)?;
        let inode = DiskInode::parse(
            record,
            number,
            superblock.data_start,
            superblock.total_blocks,
        )
        .map_err(|error| match error {
            xenith_fs_format::InodeError::BadChecksum => {
                CheckError::Invalid("inode checksum mismatch")
            },
            _ => CheckError::Invalid("corrupt inode record"),
        })?;
        if let Some(inode) = &inode {
            for extent in &inode.extents {
                for delta in 0..u64::from(extent.block_count) {
                    let block = extent
                        .physical_block
                        .checked_add(delta)
                        .ok_or(CheckError::Invalid("extent overflow"))?;
                    let index = usize::try_from(block)
                        .map_err(|_| CheckError::Invalid("extent exceeds host limits"))?;
                    if expected_blocks[index] {
                        return Err(CheckError::Invalid("multiply allocated data block"));
                    }
                    if !bitmap_get(bitmap, block)? {
                        return Err(CheckError::Invalid("inode extent is free in bitmap"));
                    }
                    expected_blocks[index] = true;
                }
            }
        }
        inodes.push(inode);
    }

    let root_index = usize::try_from(superblock.root_inode - 1)
        .map_err(|_| CheckError::Invalid("root inode exceeds host limits"))?;
    let root = inodes
        .get(root_index)
        .and_then(Option::as_ref)
        .ok_or(CheckError::Invalid("root inode is unallocated"))?;
    if root.kind != InodeKind::Directory {
        return Err(CheckError::Invalid("root inode is not a directory"));
    }

    for inode in inodes.iter().flatten() {
        if inode.kind != InodeKind::Directory {
            continue;
        }
        let bytes = read_inode_contents(effective, inode, MAX_DIRECTORY_SIZE)?;
        for record in
            parse_directory(&bytes).map_err(|_| CheckError::Invalid("corrupt directory records"))?
        {
            let child_index = usize::try_from(record.inode - 1)
                .map_err(|_| CheckError::Invalid("directory inode exceeds host limits"))?;
            let child =
                inodes
                    .get(child_index)
                    .and_then(Option::as_ref)
                    .ok_or(CheckError::Invalid(
                        "directory references an unallocated inode",
                    ))?;
            if child.kind != record.kind {
                return Err(CheckError::Invalid("directory entry type mismatch"));
            }
        }
    }

    let mut allocated_blocks = 0u64;
    for (block, expected) in expected_blocks.into_iter().enumerate() {
        let allocated = bitmap_get(bitmap, block as u64)?;
        if allocated {
            allocated_blocks += 1;
        }
        if allocated != expected {
            return Err(CheckError::Invalid("unreferenced allocated data block"));
        }
    }

    Ok(Report {
        filesystem: "xenithfs",
        blocks: superblock.total_blocks,
        allocated_blocks,
        warnings: if image.len() > image_len {
            vec!["trailing bytes after XenithFS volume".to_owned()]
        } else {
            Vec::new()
        },
    })
}

fn replay_to_memory(
    image: &[u8],
    superblock: &Superblock,
    header: &JournalHeader,
) -> Result<Vec<u8>, CheckError> {
    let mut replayed = image.to_vec();
    for (index, descriptor) in header.descriptors.iter().enumerate() {
        let payload_block = superblock
            .journal_start
            .checked_add(1 + index as u64)
            .ok_or(CheckError::Invalid("journal payload overflow"))?;
        let payload_offset = block_offset(payload_block)?;
        let payload = image
            .get(payload_offset..payload_offset + BLOCK_SIZE)
            .ok_or(CheckError::Truncated)?;
        if crc32(payload) != descriptor.checksum {
            return Err(CheckError::Invalid("journal payload checksum mismatch"));
        }
        let target = block_offset(descriptor.target_block)?;
        replayed[target..target + BLOCK_SIZE].copy_from_slice(payload);
    }
    Ok(replayed)
}

fn read_inode_contents(
    image: &[u8],
    inode: &DiskInode,
    limit: usize,
) -> Result<Vec<u8>, CheckError> {
    let size = usize::try_from(inode.size)
        .map_err(|_| CheckError::Invalid("inode size exceeds host limits"))?;
    if size > limit {
        return Err(CheckError::Invalid("directory exceeds format limit"));
    }
    if !inode.inline_symlink.is_empty() {
        return Ok(inode.inline_symlink.clone());
    }
    let mut output = vec![0u8; size];
    for extent in &inode.extents {
        if extent.flags & xenith_fs_format::Extent::UNWRITTEN != 0 {
            continue;
        }
        for delta in 0..u64::from(extent.block_count) {
            let logical = extent.logical_block + delta;
            let destination_u64 = logical
                .checked_mul(BLOCK_SIZE as u64)
                .ok_or(CheckError::Invalid("logical extent overflow"))?;
            if destination_u64 >= inode.size {
                break;
            }
            let destination = usize::try_from(destination_u64)
                .map_err(|_| CheckError::Invalid("logical extent exceeds host limits"))?;
            let physical = extent.physical_block + delta;
            let source = block_offset(physical)?;
            let count = (size - destination).min(BLOCK_SIZE);
            output[destination..destination + count]
                .copy_from_slice(&image[source..source + count]);
        }
    }
    Ok(output)
}

fn map_superblock_error(error: SuperblockError) -> CheckError {
    match error {
        SuperblockError::TooShort => CheckError::Truncated,
        SuperblockError::BadChecksum => CheckError::BadChecksum,
        SuperblockError::BadMagic
        | SuperblockError::UnsupportedVersion(_)
        | SuperblockError::UnsupportedBlockSize(_)
        | SuperblockError::InvalidGeometry
        | SuperblockError::UnsupportedFeatures(_) => {
            CheckError::Invalid("invalid XenithFS superblock")
        },
    }
}

fn map_journal_error(error: JournalError) -> CheckError {
    match error {
        JournalError::BadChecksum => CheckError::Invalid("journal checksum mismatch"),
        JournalError::TooShort => CheckError::Truncated,
        JournalError::BadMagic
        | JournalError::BadState
        | JournalError::TooManyDescriptors
        | JournalError::InvalidTarget => CheckError::Invalid("invalid journal header"),
    }
}

fn bitmap_get(bitmap: &[u8], block: u64) -> Result<bool, CheckError> {
    let index = usize::try_from(block / 8)
        .map_err(|_| CheckError::Invalid("bitmap index exceeds host limits"))?;
    let byte = *bitmap
        .get(index)
        .ok_or(CheckError::Invalid("bitmap is too short"))?;
    Ok(byte & (1 << (block % 8)) != 0)
}

fn inode_offset(superblock: &Superblock, number: u64) -> Result<usize, CheckError> {
    let table = block_offset(superblock.inode_table_start)?;
    let index = usize::try_from(number - 1)
        .map_err(|_| CheckError::Invalid("inode number exceeds host limits"))?;
    table
        .checked_add(
            index
                .checked_mul(INODE_SIZE)
                .ok_or(CheckError::Invalid("inode offset overflow"))?,
        )
        .ok_or(CheckError::Invalid("inode offset overflow"))
}

fn image_bytes(blocks: u64) -> Result<usize, CheckError> {
    blocks
        .checked_mul(BLOCK_SIZE as u64)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or(CheckError::Invalid("image size exceeds host limits"))
}

fn block_offset(block: u64) -> Result<usize, CheckError> {
    block
        .checked_mul(BLOCK_SIZE as u64)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or(CheckError::Invalid("block offset exceeds host limits"))
}

pub fn check_fat32(image: &[u8]) -> Result<Report, CheckError> {
    if image.len() < 512 || image.get(510..512) != Some(&[0x55, 0xaa]) {
        return Err(CheckError::Truncated);
    }
    let bytes_per_sector = u16_at(image, 11)?;
    let sectors_per_cluster = image[13];
    let sectors = u32_at(image, 32)?;
    let fat_sectors = u32_at(image, 36)?;
    let root_cluster = u32_at(image, 44)?;
    if bytes_per_sector != 512 || !sectors_per_cluster.is_power_of_two() {
        return Err(CheckError::Invalid("invalid FAT32 geometry"));
    }
    if fat_sectors == 0 || root_cluster < 2 || sectors as usize * 512 > image.len() {
        return Err(CheckError::Invalid("invalid FAT32 extents"));
    }
    let reserved = u16_at(image, 14)? as usize;
    if u32_at(image, reserved * 512 + 8)? & 0x0fff_ffff < 0x0fff_fff8 {
        return Err(CheckError::Invalid("root cluster is not allocated"));
    }
    Ok(Report {
        filesystem: "fat32",
        blocks: u64::from(sectors),
        allocated_blocks: 1,
        warnings: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use xenith_fs_format::{
        encode_directory, DirectoryRecord, Extent, InodeKind, JournalDescriptor,
    };

    use super::*;

    const IMAGE_SIZE: u64 = 8 * 1024 * 1024;

    fn fresh() -> (Vec<u8>, xenith_mkfs::Geometry) {
        xenith_mkfs::format_xenithfs(IMAGE_SIZE, "TEST").unwrap()
    }

    fn set_bitmap(image: &mut [u8], geometry: xenith_mkfs::Geometry, block: u64, set: bool) {
        let offset = geometry.bitmap_start as usize * BLOCK_SIZE + (block / 8) as usize;
        let mask = 1 << (block % 8);
        if set {
            image[offset] |= mask;
        } else {
            image[offset] &= !mask;
        }
    }

    fn install_one_file(image: &mut [u8], geometry: xenith_mkfs::Geometry) -> usize {
        let directory = encode_directory(&[DirectoryRecord {
            inode: 2,
            kind: InodeKind::Regular,
            name: "hello".to_owned(),
        }])
        .unwrap();
        let data_block = geometry.data_start;
        let data_offset = data_block as usize * BLOCK_SIZE;
        image[data_offset..data_offset + directory.len()].copy_from_slice(&directory);
        set_bitmap(image, geometry, data_block, true);

        let mut root = DiskInode::empty(1, InodeKind::Directory, 0o755);
        root.size = directory.len() as u64;
        root.extents.push(Extent {
            logical_block: 0,
            physical_block: data_block,
            block_count: 1,
            flags: 0,
        });
        let inode_table = geometry.inode_start as usize * BLOCK_SIZE;
        image[inode_table..inode_table + INODE_SIZE].copy_from_slice(&root.encode().unwrap());
        let child = DiskInode::empty(2, InodeKind::Regular, 0o644);
        image[inode_table + INODE_SIZE..inode_table + 2 * INODE_SIZE]
            .copy_from_slice(&child.encode().unwrap());
        data_offset
    }

    #[test]
    fn fsck_accepts_mkfs_output() {
        let (image, geometry) = fresh();
        let report = check(&image).unwrap();
        assert_eq!(report.filesystem, "xenithfs");
        assert_eq!(report.blocks, geometry.blocks);
        assert_eq!(report.allocated_blocks, geometry.data_start);
    }

    #[test]
    fn mkfs_output_is_readable_by_kernel_format_explorer() {
        let (image, _) = fresh();
        let explorer = xenith_mount::Explorer::parse(&image).unwrap();
        assert_eq!(
            explorer.inspect().filesystem,
            xenith_mount::FilesystemKind::XenithFs
        );
        assert!(explorer.list("/").unwrap().is_empty());
    }

    #[test]
    fn validates_directory_inode_and_extent_graph() {
        let (mut image, geometry) = fresh();
        install_one_file(&mut image, geometry);
        assert!(check_xenithfs(&image).is_ok());
    }

    #[test]
    fn detects_superblock_corruption() {
        let (mut image, _) = fresh();
        image[64] ^= 1;
        assert_eq!(check(&image), Err(CheckError::BadChecksum));
    }

    #[test]
    fn detects_journal_corruption() {
        let (mut image, geometry) = fresh();
        let offset = geometry.journal_start as usize * BLOCK_SIZE + 24;
        image[offset] ^= 1;
        assert_eq!(
            check(&image),
            Err(CheckError::Invalid("journal checksum mismatch"))
        );
    }

    #[test]
    fn detects_reserved_bitmap_corruption() {
        let (mut image, geometry) = fresh();
        set_bitmap(&mut image, geometry, geometry.journal_start, false);
        assert_eq!(
            check(&image),
            Err(CheckError::Invalid("reserved block is free in bitmap"))
        );
    }

    #[test]
    fn detects_inode_checksum_corruption() {
        let (mut image, geometry) = fresh();
        let offset = geometry.inode_start as usize * BLOCK_SIZE + 252;
        image[offset] ^= 1;
        assert_eq!(
            check(&image),
            Err(CheckError::Invalid("inode checksum mismatch"))
        );
    }

    #[test]
    fn detects_directory_checksum_corruption() {
        let (mut image, geometry) = fresh();
        let directory = install_one_file(&mut image, geometry);
        image[directory + 12] ^= 1;
        assert_eq!(
            check(&image),
            Err(CheckError::Invalid("corrupt directory records"))
        );
    }

    #[test]
    fn validates_prepared_journal_payload_before_replay() {
        let (mut image, geometry) = fresh();
        let target = geometry.inode_start;
        let target_offset = target as usize * BLOCK_SIZE;
        let payload_offset = (geometry.journal_start + 1) as usize * BLOCK_SIZE;
        let payload = image[target_offset..target_offset + BLOCK_SIZE].to_vec();
        image[payload_offset..payload_offset + BLOCK_SIZE].copy_from_slice(&payload);
        let header = JournalHeader {
            prepared: true,
            sequence: 1,
            descriptors: vec![JournalDescriptor {
                target_block: target,
                checksum: crc32(&payload),
            }],
        }
        .encode()
        .unwrap();
        let journal_offset = geometry.journal_start as usize * BLOCK_SIZE;
        image[journal_offset..journal_offset + BLOCK_SIZE].copy_from_slice(&header);
        assert!(check(&image).is_ok());

        image[payload_offset] ^= 1;
        assert_eq!(
            check(&image),
            Err(CheckError::Invalid("journal payload checksum mismatch"))
        );
    }
}
