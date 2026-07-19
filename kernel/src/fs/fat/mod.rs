//! Read-only FAT32 filesystem mounted over the kernel block-device contract.

#![allow(clippy::module_inception)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::inode::{
    allocate_inode_id, cache_insert, DirEntry, FileType, Inode, InodeMetadata, InodeOps,
};
use super::vfs::{FileSystem, FsError, NodeRef, VfsNode};
use crate::devices::ahci::BlockDevice;

pub mod boot_sector;
pub mod dir;
pub mod fat;
pub mod file;

pub use boot_sector::{BootSector, BootSectorError};
pub use dir::FatDirEntry;
pub use fat::{ClusterLink, FatError, FatVolume};

fn map_fat_error(error: FatError) -> FsError {
    match error {
        FatError::Io => FsError::Io,
        FatError::InvalidBootSector(_)
        | FatError::InvalidCluster(_)
        | FatError::BadCluster(_)
        | FatError::ClusterLoop
        | FatError::CorruptDirectory => FsError::Corrupt,
        FatError::UnsupportedSectorSize => FsError::Unsupported,
        FatError::Overflow => FsError::Overflow,
    }
}

struct FatShared<D: BlockDevice> {
    volume: FatVolume<D>,
}

struct FatNode<D: BlockDevice> {
    inode: Inode,
    shared: Arc<FatShared<D>>,
    entry: Option<FatDirEntry>,
}

impl<D> FatNode<D>
where
    D: BlockDevice + Send + 'static,
{
    fn root(shared: Arc<FatShared<D>>) -> NodeRef {
        let mut metadata = InodeMetadata::new(allocate_inode_id(), FileType::Directory, 0o555);
        metadata.links = 2;
        let node: NodeRef = Arc::new(Self {
            inode: Inode::new(metadata),
            shared,
            entry: None,
        });
        cache_insert(&node);
        node
    }

    fn from_entry(shared: Arc<FatShared<D>>, entry: FatDirEntry) -> NodeRef {
        let kind = if entry.is_directory() {
            FileType::Directory
        } else {
            FileType::Regular
        };
        let mode = if kind == FileType::Directory {
            0o555
        } else {
            0o444
        };
        let mut metadata = InodeMetadata::new(allocate_inode_id(), kind, mode);
        metadata.size = u64::from(entry.size);
        metadata.links = if kind == FileType::Directory { 2 } else { 1 };
        let node: NodeRef = Arc::new(Self {
            inode: Inode::new(metadata),
            shared,
            entry: Some(entry),
        });
        cache_insert(&node);
        node
    }

    fn directory_cluster(&self) -> Result<u32, FsError> {
        match &self.entry {
            Some(entry) if entry.is_directory() && entry.first_cluster >= 2 => {
                Ok(entry.first_cluster)
            },
            Some(entry) if !entry.is_directory() => Err(FsError::NotDirectory),
            Some(_) => Err(FsError::Corrupt),
            None => Ok(self.shared.volume.boot_sector().root_cluster),
        }
    }

    fn entries(&self) -> Result<Vec<FatDirEntry>, FsError> {
        dir::read_directory(&self.shared.volume, self.directory_cluster()?).map_err(map_fat_error)
    }
}

impl<D> VfsNode for FatNode<D>
where
    D: BlockDevice + Send + 'static,
{
    fn inode(&self) -> &Inode {
        &self.inode
    }
}

impl<D> InodeOps for FatNode<D>
where
    D: BlockDevice + Send + 'static,
{
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize, FsError> {
        let entry = self.entry.as_ref().ok_or(FsError::IsDirectory)?;
        if entry.is_directory() {
            return Err(FsError::IsDirectory);
        }
        file::read_file(&self.shared.volume, entry, offset, buffer).map_err(map_fat_error)
    }

    fn lookup(&self, name: &str) -> Result<NodeRef, FsError> {
        self.entries()?
            .into_iter()
            .find(|entry| {
                entry.name != "." && entry.name != ".." && entry.name.eq_ignore_ascii_case(name)
            })
            .map(|entry| Self::from_entry(Arc::clone(&self.shared), entry))
            .ok_or(FsError::NotFound)
    }

    fn read_dir(&self) -> Result<Vec<DirEntry>, FsError> {
        let mut output = Vec::new();
        for entry in self.entries()? {
            if entry.name == "." || entry.name == ".." {
                continue;
            }
            let node = Self::from_entry(Arc::clone(&self.shared), entry.clone());
            let metadata = node.metadata();
            output.push(DirEntry {
                name: entry.name,
                inode: metadata.id,
                kind: metadata.kind,
            });
        }
        Ok(output)
    }
}

/// Mounted FAT32 filesystem. FAT mutation is intentionally disabled until
/// allocation and mirror-update transactions can be made crash-consistent.
pub struct FatFileSystem<D: BlockDevice + Send + 'static> {
    shared: Arc<FatShared<D>>,
    root: NodeRef,
}

impl<D> FatFileSystem<D>
where
    D: BlockDevice + Send + 'static,
{
    pub fn mount(device: D) -> Result<Self, FatError> {
        let shared = Arc::new(FatShared {
            volume: FatVolume::mount(device)?,
        });
        let root = FatNode::root(Arc::clone(&shared));
        Ok(Self { shared, root })
    }

    pub fn boot_sector(&self) -> BootSector {
        self.shared.volume.boot_sector()
    }
}

impl<D> FileSystem for FatFileSystem<D>
where
    D: BlockDevice + Send + 'static,
{
    fn name(&self) -> &'static str {
        "fat32"
    }

    fn root(&self) -> NodeRef {
        Arc::clone(&self.root)
    }

    fn is_read_only(&self) -> bool {
        true
    }
}
