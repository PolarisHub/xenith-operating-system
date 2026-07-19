//! On-disk XenithFS and FAT32 image construction.

use std::fmt;

pub use xenith_fs_format::{crc32, BLOCK_SIZE, INODE_SIZE, VERSION};

pub const SUPER_MAGIC: [u8; 8] = *xenith_fs_format::MAGIC;
pub const ROOT_INODE: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    TooSmall,
    TooLarge,
    InvalidLabel,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => f.write_str("image is too small"),
            Self::TooLarge => f.write_str("image geometry exceeds the format"),
            Self::InvalidLabel => f.write_str("label must be non-empty ASCII and at most 31 bytes"),
        }
    }
}

impl std::error::Error for FormatError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub blocks: u64,
    pub bitmap_start: u64,
    pub bitmap_blocks: u32,
    pub inode_start: u64,
    pub inode_blocks: u64,
    pub journal_start: u64,
    pub journal_blocks: u32,
    pub data_start: u64,
    pub inode_count: u64,
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub fn geometry(size: u64) -> Result<Geometry, FormatError> {
    if size < 8 * 1024 * 1024 {
        return Err(FormatError::TooSmall);
    }
    let blocks = size / BLOCK_SIZE as u64;
    let bitmap_blocks = u32::try_from(blocks.div_ceil((BLOCK_SIZE * 8) as u64))
        .map_err(|_| FormatError::TooLarge)?;
    let inode_count = (blocks / 8).clamp(128, 65_536);
    let inode_blocks = (inode_count * INODE_SIZE as u64).div_ceil(BLOCK_SIZE as u64);
    let inode_start = 1u64;
    let bitmap_start = inode_start
        .checked_add(inode_blocks)
        .ok_or(FormatError::TooLarge)?;
    let journal_start = bitmap_start
        .checked_add(u64::from(bitmap_blocks))
        .ok_or(FormatError::TooLarge)?;
    let journal_blocks =
        u32::try_from((blocks / 64).clamp(8, 256)).map_err(|_| FormatError::TooLarge)?;
    let data_start = journal_start
        .checked_add(u64::from(journal_blocks))
        .ok_or(FormatError::TooLarge)?;
    if data_start >= blocks {
        return Err(FormatError::TooSmall);
    }
    Ok(Geometry {
        blocks,
        bitmap_start,
        bitmap_blocks,
        inode_start,
        inode_blocks,
        journal_start,
        journal_blocks,
        data_start,
        inode_count,
    })
}

fn mark_block(image: &mut [u8], geometry: Geometry, block: u64) {
    let byte = usize::try_from(block / 8).expect("bitmap index");
    let bit = (block % 8) as u8;
    let offset = geometry.bitmap_start as usize * BLOCK_SIZE + byte;
    image[offset] |= 1 << bit;
}

pub fn format_xenithfs(size: u64, label: &str) -> Result<(Vec<u8>, Geometry), FormatError> {
    if label.is_empty() || label.len() > 31 || !label.is_ascii() {
        return Err(FormatError::InvalidLabel);
    }
    let geometry = geometry(size)?;
    let image_len =
        usize::try_from(geometry.blocks * BLOCK_SIZE as u64).map_err(|_| FormatError::TooLarge)?;
    let mut image = vec![0u8; image_len];

    for block in 0..geometry.data_start {
        mark_block(&mut image, geometry, block);
    }

    let inode_offset = geometry.inode_start as usize * BLOCK_SIZE;
    let root = xenith_fs_format::DiskInode::empty(
        ROOT_INODE,
        xenith_fs_format::InodeKind::Directory,
        0o755,
    )
    .encode()
    .map_err(|_| FormatError::TooLarge)?;
    image[inode_offset..inode_offset + INODE_SIZE].copy_from_slice(&root);

    let superblock = xenith_fs_format::Superblock {
        total_blocks: geometry.blocks,
        inode_table_start: geometry.inode_start,
        inode_count: geometry.inode_count,
        bitmap_start: geometry.bitmap_start,
        bitmap_blocks: geometry.bitmap_blocks,
        data_start: geometry.data_start,
        root_inode: ROOT_INODE,
        journal_start: geometry.journal_start,
        journal_blocks: geometry.journal_blocks,
        features: 0,
        sequence: 0,
    }
    .encode()
    .map_err(|_| FormatError::TooLarge)?;
    image[..superblock.len()].copy_from_slice(&superblock);

    let journal = xenith_fs_format::JournalHeader::clean(0)
        .encode()
        .map_err(|_| FormatError::TooLarge)?;
    let journal_offset = geometry.journal_start as usize * BLOCK_SIZE;
    image[journal_offset..journal_offset + BLOCK_SIZE].copy_from_slice(&journal);
    Ok((image, geometry))
}

pub fn format_fat32(size: u64, label: &str) -> Result<Vec<u8>, FormatError> {
    const SECTOR: usize = 512;
    if size < 33 * 1024 * 1024 {
        return Err(FormatError::TooSmall);
    }
    if label.is_empty() || label.len() > 11 || !label.is_ascii() {
        return Err(FormatError::InvalidLabel);
    }
    let sectors = size / SECTOR as u64;
    let image_len = usize::try_from(sectors * SECTOR as u64).map_err(|_| FormatError::TooLarge)?;
    let mut image = vec![0u8; image_len];
    let reserved = 32u32;
    let sectors_per_cluster = 8u8;
    let fat_sectors =
        ((sectors * 4).div_ceil(SECTOR as u64 * sectors_per_cluster as u64 - 8)) as u32;
    let boot = &mut image[..SECTOR];
    boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    boot[3..11].copy_from_slice(b"XENITH  ");
    put_u16(boot, 11, SECTOR as u16);
    boot[13] = sectors_per_cluster;
    put_u16(boot, 14, reserved as u16);
    boot[16] = 2;
    put_u32(boot, 32, sectors as u32);
    put_u32(boot, 36, fat_sectors);
    put_u32(boot, 44, 2);
    put_u16(boot, 48, 1);
    put_u16(boot, 50, 6);
    boot[64] = 0x80;
    boot[66] = 0x29;
    put_u32(boot, 67, 0x5846_5331);
    let mut padded = [b' '; 11];
    padded[..label.len()].copy_from_slice(label.as_bytes());
    boot[71..82].copy_from_slice(&padded);
    boot[82..90].copy_from_slice(b"FAT32   ");
    boot[510..512].copy_from_slice(&[0x55, 0xaa]);

    let fsinfo = &mut image[SECTOR..SECTOR * 2];
    put_u32(fsinfo, 0, 0x4161_5252);
    put_u32(fsinfo, 484, 0x6141_7272);
    put_u32(fsinfo, 488, 0xffff_ffff);
    put_u32(fsinfo, 492, 0xffff_ffff);
    put_u32(fsinfo, 508, 0xaa55_0000);
    let backup_boot = image[..SECTOR].to_vec();
    image[6 * SECTOR..7 * SECTOR].copy_from_slice(&backup_boot);

    for fat_index in 0..2u32 {
        let offset = (reserved + fat_index * fat_sectors) as usize * SECTOR;
        put_u32(&mut image, offset, 0x0fff_fff8);
        put_u32(&mut image, offset + 4, 0x0fff_ffff);
        put_u32(&mut image, offset + 8, 0x0fff_ffff);
    }
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xenithfs_has_root_and_valid_checksum() {
        let (image, geometry) = format_xenithfs(8 * 1024 * 1024, "ROOT").unwrap();
        assert_eq!(&image[..8], &SUPER_MAGIC);
        let superblock = xenith_fs_format::Superblock::parse(&image).unwrap();
        assert_eq!(superblock.root_inode, ROOT_INODE);
        let inode = &image[geometry.inode_start as usize * BLOCK_SIZE..];
        let root = xenith_fs_format::DiskInode::parse(
            inode,
            ROOT_INODE,
            geometry.data_start,
            geometry.blocks,
        )
        .unwrap()
        .unwrap();
        assert_eq!(root.kind, xenith_fs_format::InodeKind::Directory);
        assert!(root.extents.is_empty());
        assert!(xenith_fs_format::JournalHeader::parse(
            &image[geometry.journal_start as usize * BLOCK_SIZE..]
        )
        .is_ok());
    }

    #[test]
    fn fat32_has_bpb_and_signatures() {
        let image = format_fat32(33 * 1024 * 1024, "XENITH").unwrap();
        assert_eq!(&image[82..90], b"FAT32   ");
        assert_eq!(&image[510..512], &[0x55, 0xaa]);
    }
}
