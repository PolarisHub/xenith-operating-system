//! Canonical XenithFS superblock primitives shared with host tools.

pub use xenith_fs_format::{
    crc32, Superblock, SuperblockError, BLOCK_SIZE, MAGIC, SUPERBLOCK_BYTES, VERSION,
};
