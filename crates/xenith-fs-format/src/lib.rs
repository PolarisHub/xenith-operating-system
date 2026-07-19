//! Canonical on-disk structures for the journaled XenithFS format.
//!
//! This crate is deliberately `no_std`: the kernel, image builder, checker,
//! and read-only explorer all use the same byte layouts, checksum code, and
//! structural bounds.

#![no_std]

extern crate alloc;

mod directory;
mod extent;
mod inode;
mod journal;
mod superblock;

pub use directory::{
    encode_directory, parse_directory, DirectoryError, DirectoryRecord, DIRECTORY_HEADER_SIZE,
    MAX_DIRECTORY_SIZE,
};
pub use extent::{mapped_block, validate_extents, Extent, ExtentError};
pub use inode::{DiskInode, InodeError, InodeKind, INLINE_SYMLINK_BYTES, INODE_SIZE, MAX_EXTENTS};
pub use journal::{
    JournalDescriptor, JournalError, JournalHeader, JOURNAL_DESCRIPTOR_BYTES, JOURNAL_HEADER_BYTES,
    JOURNAL_MAGIC,
};
pub use superblock::{
    crc32, Superblock, SuperblockError, BLOCK_SIZE, MAGIC, SUPERBLOCK_BYTES, VERSION,
};
