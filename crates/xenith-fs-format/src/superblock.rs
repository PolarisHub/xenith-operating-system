//! XenithFS superblock parser, encoder, geometry checks, and checksum.

use core::fmt;

pub const MAGIC: &[u8; 8] = b"XENITHFS";
pub const VERSION: u32 = 1;
pub const BLOCK_SIZE: usize = 4096;
pub const SUPERBLOCK_BYTES: usize = 512;
const CHECKSUM_OFFSET: usize = 96;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Superblock {
    pub total_blocks: u64,
    pub inode_table_start: u64,
    pub inode_count: u64,
    pub bitmap_start: u64,
    pub bitmap_blocks: u32,
    pub data_start: u64,
    pub root_inode: u64,
    pub journal_start: u64,
    pub journal_blocks: u32,
    pub features: u64,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuperblockError {
    TooShort,
    BadMagic,
    UnsupportedVersion(u32),
    UnsupportedBlockSize(u32),
    BadChecksum,
    InvalidGeometry,
    UnsupportedFeatures(u64),
}

impl fmt::Display for SuperblockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("short XenithFS superblock"),
            Self::BadMagic => f.write_str("bad XenithFS magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported XenithFS version {version}")
            },
            Self::UnsupportedBlockSize(size) => {
                write!(f, "unsupported XenithFS block size {size}")
            },
            Self::BadChecksum => f.write_str("XenithFS superblock checksum mismatch"),
            Self::InvalidGeometry => f.write_str("invalid XenithFS geometry"),
            Self::UnsupportedFeatures(features) => {
                write!(f, "unsupported XenithFS features 0x{features:x}")
            },
        }
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

impl Superblock {
    pub fn parse(bytes: &[u8]) -> Result<Self, SuperblockError> {
        let bytes = bytes
            .get(..SUPERBLOCK_BYTES)
            .ok_or(SuperblockError::TooShort)?;
        if &bytes[..8] != MAGIC {
            return Err(SuperblockError::BadMagic);
        }
        let version = read_u32(bytes, 8);
        if version != VERSION {
            return Err(SuperblockError::UnsupportedVersion(version));
        }
        let block_size = read_u32(bytes, 12);
        if block_size as usize != BLOCK_SIZE {
            return Err(SuperblockError::UnsupportedBlockSize(block_size));
        }
        let expected = read_u32(bytes, CHECKSUM_OFFSET);
        let mut checked = [0u8; SUPERBLOCK_BYTES];
        checked.copy_from_slice(bytes);
        checked[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].fill(0);
        if crc32(&checked) != expected {
            return Err(SuperblockError::BadChecksum);
        }
        let superblock = Self {
            total_blocks: read_u64(bytes, 16),
            inode_table_start: read_u64(bytes, 24),
            inode_count: read_u64(bytes, 32),
            bitmap_start: read_u64(bytes, 40),
            bitmap_blocks: read_u32(bytes, 48),
            data_start: read_u64(bytes, 52),
            root_inode: read_u64(bytes, 60),
            journal_start: read_u64(bytes, 68),
            journal_blocks: read_u32(bytes, 76),
            features: read_u64(bytes, 80),
            sequence: read_u64(bytes, 88),
        };
        superblock.validate()?;
        Ok(superblock)
    }

    pub fn encode(self) -> Result<[u8; SUPERBLOCK_BYTES], SuperblockError> {
        self.validate()?;
        let mut bytes = [0u8; SUPERBLOCK_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..12].copy_from_slice(&VERSION.to_le_bytes());
        bytes[12..16].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
        bytes[16..24].copy_from_slice(&self.total_blocks.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.inode_table_start.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.inode_count.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.bitmap_start.to_le_bytes());
        bytes[48..52].copy_from_slice(&self.bitmap_blocks.to_le_bytes());
        bytes[52..60].copy_from_slice(&self.data_start.to_le_bytes());
        bytes[60..68].copy_from_slice(&self.root_inode.to_le_bytes());
        bytes[68..76].copy_from_slice(&self.journal_start.to_le_bytes());
        bytes[76..80].copy_from_slice(&self.journal_blocks.to_le_bytes());
        bytes[80..88].copy_from_slice(&self.features.to_le_bytes());
        bytes[88..96].copy_from_slice(&self.sequence.to_le_bytes());
        let checksum = crc32(&bytes);
        bytes[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), SuperblockError> {
        if self.features != 0 {
            return Err(SuperblockError::UnsupportedFeatures(self.features));
        }
        if self.total_blocks < 8
            || self.inode_count == 0
            || self.root_inode == 0
            || self.root_inode > self.inode_count
            || self.bitmap_blocks == 0
            || self.journal_blocks < 2
            || self.data_start >= self.total_blocks
        {
            return Err(SuperblockError::InvalidGeometry);
        }
        let ranges = [
            (0, 1),
            checked_range(self.inode_table_start, self.inode_table_blocks()?),
            checked_range(self.bitmap_start, u64::from(self.bitmap_blocks)),
            checked_range(self.journal_start, u64::from(self.journal_blocks)),
        ];
        for &(start, end) in &ranges {
            if start >= end || end > self.total_blocks || end > self.data_start {
                return Err(SuperblockError::InvalidGeometry);
            }
        }
        for left in 0..ranges.len() {
            for right in left + 1..ranges.len() {
                if ranges[left].0 < ranges[right].1 && ranges[right].0 < ranges[left].1 {
                    return Err(SuperblockError::InvalidGeometry);
                }
            }
        }
        let bitmap_capacity = u64::from(self.bitmap_blocks)
            .checked_mul(BLOCK_SIZE as u64 * 8)
            .ok_or(SuperblockError::InvalidGeometry)?;
        if bitmap_capacity < self.total_blocks {
            return Err(SuperblockError::InvalidGeometry);
        }
        Ok(())
    }

    pub fn inode_table_blocks(&self) -> Result<u64, SuperblockError> {
        self.inode_count
            .checked_mul(super::INODE_SIZE as u64)
            .and_then(|bytes| bytes.checked_add(BLOCK_SIZE as u64 - 1))
            .map(|bytes| bytes / BLOCK_SIZE as u64)
            .ok_or(SuperblockError::InvalidGeometry)
    }

    pub fn contains_journal_block(&self, block: u64) -> bool {
        block >= self.journal_start && block < self.journal_start + u64::from(self.journal_blocks)
    }
}

fn checked_range(start: u64, length: u64) -> (u64, u64) {
    (start, start.saturating_add(length))
}

/// Small dependency-free IEEE CRC-32 used for every XenithFS metadata object.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Superblock {
        Superblock {
            total_blocks: 64,
            inode_table_start: 1,
            inode_count: 16,
            bitmap_start: 2,
            bitmap_blocks: 1,
            data_start: 11,
            root_inode: 1,
            journal_start: 3,
            journal_blocks: 8,
            features: 0,
            sequence: 0,
        }
    }

    #[test]
    fn round_trip() {
        let superblock = example();
        assert_eq!(
            Superblock::parse(&superblock.encode().unwrap()).unwrap(),
            superblock
        );
    }

    #[test]
    fn standard_crc_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
