//! Bounded, read-only exploration of XenithFS and FAT32 disk images.
//!
//! This crate deliberately operates on image bytes. It does not attach a live
//! mount point and never mutates the source image.

mod error;
mod fat32;
mod path;
mod xenithfs;

pub use error::Error;

/// Largest image accepted by the command-line frontend (8 GiB).
pub const MAX_IMAGE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Largest file materialized by one read or extraction (512 MiB).
pub const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesystemKind {
    XenithFs,
    XenithFsLegacy,
    Fat32,
}

impl FilesystemKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XenithFs => "xenithfs",
            Self::XenithFsLegacy => "xenithfs-legacy",
            Self::Fat32 => "fat32",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

impl EntryKind {
    pub const fn marker(self) -> char {
        match self {
            Self::File => 'f',
            Self::Directory => 'd',
            Self::Symlink => 'l',
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    pub identifier: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection {
    pub filesystem: FilesystemKind,
    pub label: Option<String>,
    pub logical_block_size: u32,
    pub total_bytes: u64,
    pub root_identifier: u64,
}

pub struct Explorer<'a> {
    inner: Inner<'a>,
}

enum Inner<'a> {
    Xenith(xenithfs::XenithFs<'a>),
    Fat32(fat32::Fat32<'a>),
}

impl<'a> Explorer<'a> {
    pub fn parse(image: &'a [u8]) -> Result<Self, Error> {
        if image.starts_with(b"XENITHFS") {
            Ok(Self {
                inner: Inner::Xenith(xenithfs::XenithFs::parse(image)?),
            })
        } else if fat32::Fat32::has_signature(image) {
            Ok(Self {
                inner: Inner::Fat32(fat32::Fat32::parse(image)?),
            })
        } else {
            Err(Error::UnknownFilesystem)
        }
    }

    pub fn inspect(&self) -> Inspection {
        match &self.inner {
            Inner::Xenith(filesystem) => filesystem.inspect(),
            Inner::Fat32(filesystem) => filesystem.inspect(),
        }
    }

    pub fn list(&self, path: &str) -> Result<Vec<Entry>, Error> {
        let path = path::ImagePath::parse(path)?;
        match &self.inner {
            Inner::Xenith(filesystem) => filesystem.list(&path),
            Inner::Fat32(filesystem) => filesystem.list(&path),
        }
    }

    /// Reads a regular file, or the stored bytes of a XenithFS symlink.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, Error> {
        let path = path::ImagePath::parse(path)?;
        match &self.inner {
            Inner::Xenith(filesystem) => filesystem.read_file(&path),
            Inner::Fat32(filesystem) => filesystem.read_file(&path),
        }
    }
}
