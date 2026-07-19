//! Fixed-size XenithFS inode records.

extern crate alloc;

use alloc::vec::Vec;

use xenith_fs_format::{DiskInode as FormatInode, InodeError, InodeKind};

use super::extent::Extent;
use super::XenithFsError;
use crate::fs::inode::FileType;

pub const INODE_SIZE: usize = 256;
pub const MAX_EXTENTS: usize = 6;
pub const INLINE_SYMLINK_BYTES: usize = 28;

#[derive(Clone, Debug)]
pub struct DiskInode {
    pub number: u64,
    pub generation: u64,
    pub kind: FileType,
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

fn kind_to_format(value: FileType) -> Result<InodeKind, XenithFsError> {
    match value {
        FileType::Regular => Ok(InodeKind::Regular),
        FileType::Directory => Ok(InodeKind::Directory),
        FileType::Symlink => Ok(InodeKind::Symlink),
        FileType::CharacterDevice | FileType::BlockDevice => Err(XenithFsError::Unsupported),
    }
}

fn kind_from_format(value: InodeKind) -> FileType {
    match value {
        InodeKind::Regular => FileType::Regular,
        InodeKind::Directory => FileType::Directory,
        InodeKind::Symlink => FileType::Symlink,
    }
}

fn map_inode_error(error: InodeError) -> XenithFsError {
    match error {
        InodeError::BadChecksum => XenithFsError::Checksum,
        InodeError::Extent(error) => error.into(),
        InodeError::TooManyExtents | InodeError::InlineSymlinkTooLong => XenithFsError::NoSpace,
        InodeError::TooShort
        | InodeError::BadHeader
        | InodeError::WrongNumber
        | InodeError::InvalidKind
        | InodeError::InvalidMetadata => XenithFsError::CorruptInode,
    }
}

impl DiskInode {
    pub fn empty(number: u64, kind: FileType, mode: u32) -> Self {
        Self {
            number,
            generation: 1,
            kind,
            mode: mode & 0o7777,
            uid: 0,
            gid: 0,
            links: if kind == FileType::Directory { 2 } else { 1 },
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
    ) -> Result<Option<Self>, XenithFsError> {
        FormatInode::parse(bytes, expected_number, data_start, total_blocks)
            .map_err(map_inode_error)
            .map(|inode| {
                inode.map(|inode| Self {
                    number: inode.number,
                    generation: inode.generation,
                    kind: kind_from_format(inode.kind),
                    mode: inode.mode,
                    uid: inode.uid,
                    gid: inode.gid,
                    links: inode.links,
                    size: inode.size,
                    accessed: inode.accessed,
                    modified: inode.modified,
                    changed: inode.changed,
                    extents: inode.extents,
                    inline_symlink: inode.inline_symlink,
                })
            })
    }

    pub fn encode(&self) -> Result<[u8; INODE_SIZE], XenithFsError> {
        FormatInode {
            number: self.number,
            generation: self.generation,
            kind: kind_to_format(self.kind)?,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            links: self.links,
            size: self.size,
            accessed: self.accessed,
            modified: self.modified,
            changed: self.changed,
            extents: self.extents.clone(),
            inline_symlink: self.inline_symlink.clone(),
        }
        .encode()
        .map_err(map_inode_error)
    }
}
