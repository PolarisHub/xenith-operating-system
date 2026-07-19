//! Fixed-size, checksummed XenithFS inode records.

use alloc::vec::Vec;

use super::{crc32, validate_extents, Extent, ExtentError};

pub const INODE_SIZE: usize = 256;
pub const MAX_EXTENTS: usize = 6;
pub const INLINE_SYMLINK_BYTES: usize = 28;
const MAGIC: u32 = 0x4f4e_4958; // XINO
const VERSION: u16 = 1;
const CHECKSUM_OFFSET: usize = 252;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InodeKind {
    Regular = 1,
    Directory = 2,
    Symlink = 3,
}

impl InodeKind {
    pub fn from_disk(value: u8) -> Result<Self, InodeError> {
        match value {
            1 => Ok(Self::Regular),
            2 => Ok(Self::Directory),
            3 => Ok(Self::Symlink),
            _ => Err(InodeError::InvalidKind),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskInode {
    pub number: u64,
    pub generation: u64,
    pub kind: InodeKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub links: u32,
    pub size: u64,
    pub accessed: u64,
    pub modified: u64,
    pub changed: u64,
    pub extents: Vec<Extent>,
    pub inline_symlink: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InodeError {
    TooShort,
    BadHeader,
    BadChecksum,
    WrongNumber,
    InvalidKind,
    InvalidMetadata,
    TooManyExtents,
    InlineSymlinkTooLong,
    Extent(ExtentError),
}

impl From<ExtentError> for InodeError {
    fn from(error: ExtentError) -> Self {
        Self::Extent(error)
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

impl DiskInode {
    pub fn empty(number: u64, kind: InodeKind, mode: u32) -> Self {
        Self {
            number,
            generation: 1,
            kind,
            mode: mode & 0o7777,
            uid: 0,
            gid: 0,
            links: if kind == InodeKind::Directory { 2 } else { 1 },
            size: 0,
            accessed: 0,
            modified: 0,
            changed: 0,
            extents: Vec::new(),
            inline_symlink: Vec::new(),
        }
    }

    pub fn parse(
        bytes: &[u8],
        expected_number: u64,
        data_start: u64,
        total_blocks: u64,
    ) -> Result<Option<Self>, InodeError> {
        let bytes = bytes.get(..INODE_SIZE).ok_or(InodeError::TooShort)?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Ok(None);
        }
        if read_u32(bytes, 0) != MAGIC || read_u16(bytes, 4) != VERSION {
            return Err(InodeError::BadHeader);
        }
        let mut checked = [0u8; INODE_SIZE];
        checked.copy_from_slice(bytes);
        let expected_crc = read_u32(bytes, CHECKSUM_OFFSET);
        checked[CHECKSUM_OFFSET..].fill(0);
        if crc32(&checked) != expected_crc {
            return Err(InodeError::BadChecksum);
        }
        let number = read_u64(bytes, 8);
        if number != expected_number {
            return Err(InodeError::WrongNumber);
        }
        let extent_count = usize::from(read_u16(bytes, 72));
        let symlink_len = usize::from(read_u16(bytes, 74));
        if extent_count > MAX_EXTENTS {
            return Err(InodeError::TooManyExtents);
        }
        if symlink_len > INLINE_SYMLINK_BYTES {
            return Err(InodeError::InlineSymlinkTooLong);
        }
        let mut extents = Vec::with_capacity(extent_count);
        for index in 0..extent_count {
            let offset = 80 + index * 24;
            extents.push(Extent {
                logical_block: read_u64(bytes, offset),
                physical_block: read_u64(bytes, offset + 8),
                block_count: read_u32(bytes, offset + 16),
                flags: read_u32(bytes, offset + 20),
            });
        }
        validate_extents(&extents, data_start, total_blocks)?;
        let inline_symlink = bytes[224..224 + symlink_len].to_vec();
        let kind = InodeKind::from_disk(bytes[6])?;
        let inode = Self {
            number,
            generation: read_u64(bytes, 16),
            kind,
            mode: read_u32(bytes, 24) & 0o7777,
            uid: read_u32(bytes, 28),
            gid: read_u32(bytes, 32),
            links: read_u32(bytes, 36),
            size: read_u64(bytes, 40),
            accessed: read_u64(bytes, 48),
            modified: read_u64(bytes, 56),
            changed: read_u64(bytes, 64),
            extents,
            inline_symlink,
        };
        if inode.links == 0
            || (inode.kind != InodeKind::Symlink && !inode.inline_symlink.is_empty())
            || (inode.kind == InodeKind::Symlink
                && !inode.inline_symlink.is_empty()
                && inode.size as usize != inode.inline_symlink.len())
        {
            return Err(InodeError::InvalidMetadata);
        }
        Ok(Some(inode))
    }

    pub fn encode(&self) -> Result<[u8; INODE_SIZE], InodeError> {
        if self.extents.len() > MAX_EXTENTS {
            return Err(InodeError::TooManyExtents);
        }
        if self.inline_symlink.len() > INLINE_SYMLINK_BYTES {
            return Err(InodeError::InlineSymlinkTooLong);
        }
        if self.links == 0
            || (self.kind != InodeKind::Symlink && !self.inline_symlink.is_empty())
            || (self.kind == InodeKind::Symlink
                && !self.inline_symlink.is_empty()
                && self.size as usize != self.inline_symlink.len())
        {
            return Err(InodeError::InvalidMetadata);
        }
        let mut bytes = [0u8; INODE_SIZE];
        bytes[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
        bytes[6] = self.kind as u8;
        bytes[8..16].copy_from_slice(&self.number.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.generation.to_le_bytes());
        bytes[24..28].copy_from_slice(&(self.mode & 0o7777).to_le_bytes());
        bytes[28..32].copy_from_slice(&self.uid.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.gid.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.links.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.size.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.accessed.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.modified.to_le_bytes());
        bytes[64..72].copy_from_slice(&self.changed.to_le_bytes());
        bytes[72..74].copy_from_slice(&(self.extents.len() as u16).to_le_bytes());
        bytes[74..76].copy_from_slice(&(self.inline_symlink.len() as u16).to_le_bytes());
        for (index, extent) in self.extents.iter().enumerate() {
            let offset = 80 + index * 24;
            bytes[offset..offset + 8].copy_from_slice(&extent.logical_block.to_le_bytes());
            bytes[offset + 8..offset + 16].copy_from_slice(&extent.physical_block.to_le_bytes());
            bytes[offset + 16..offset + 20].copy_from_slice(&extent.block_count.to_le_bytes());
            bytes[offset + 20..offset + 24].copy_from_slice(&extent.flags.to_le_bytes());
        }
        bytes[224..224 + self.inline_symlink.len()].copy_from_slice(&self.inline_symlink);
        let checksum = crc32(&bytes);
        bytes[CHECKSUM_OFFSET..].copy_from_slice(&checksum.to_le_bytes());
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_directory_round_trip() {
        let inode = DiskInode::empty(1, InodeKind::Directory, 0o755);
        assert_eq!(
            DiskInode::parse(&inode.encode().unwrap(), 1, 10, 64).unwrap(),
            Some(inode)
        );
    }
}
