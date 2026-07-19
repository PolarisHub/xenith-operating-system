//! Inode metadata, operation dispatch, and the kernel inode cache.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Weak;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use super::vfs::{FsError, NodeRef, VfsNode};
use crate::sync::SpinLock;

/// Stable identifier for an inode during the lifetime of a mounted filesystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct InodeId(u64);

impl InodeId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

static NEXT_INODE: AtomicU64 = AtomicU64::new(1);

/// Allocate an identifier from the kernel-wide namespace.
pub fn allocate_inode_id() -> InodeId {
    InodeId(NEXT_INODE.fetch_add(1, Ordering::Relaxed))
}

/// The object represented by an inode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    CharacterDevice,
    BlockDevice,
}

/// Filesystem-independent inode metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InodeMetadata {
    pub id: InodeId,
    pub kind: FileType,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub links: u32,
    pub size: u64,
    pub accessed: u64,
    pub modified: u64,
    pub changed: u64,
}

impl InodeMetadata {
    pub const fn new(id: InodeId, kind: FileType, mode: u32) -> Self {
        Self {
            id,
            kind,
            mode,
            uid: 0,
            gid: 0,
            links: 1,
            size: 0,
            accessed: 0,
            modified: 0,
            changed: 0,
        }
    }
}

/// A directory entry returned without exposing a filesystem's private node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub inode: InodeId,
    pub kind: FileType,
}

/// The common metadata portion embedded in every VFS node.
pub struct Inode {
    metadata: SpinLock<InodeMetadata>,
}

impl Inode {
    pub const fn new(metadata: InodeMetadata) -> Self {
        Self {
            metadata: SpinLock::new(metadata),
        }
    }

    pub fn snapshot(&self) -> InodeMetadata {
        *self.metadata.lock()
    }

    pub fn id(&self) -> InodeId {
        self.metadata.lock().id
    }

    pub fn kind(&self) -> FileType {
        self.metadata.lock().kind
    }

    pub fn set_size(&self, size: u64) {
        self.metadata.lock().size = size;
    }

    pub fn update_metadata(&self, update: impl FnOnce(&mut InodeMetadata)) {
        update(&mut self.metadata.lock());
    }
}

impl fmt::Debug for Inode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.snapshot().fmt(f)
    }
}

/// Operations supplied by a concrete filesystem node.
pub trait InodeOps: Send + Sync {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize, FsError> {
        Err(FsError::Unsupported)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize, FsError> {
        Err(FsError::ReadOnly)
    }

    fn truncate(&self, _size: u64) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    fn lookup(&self, _name: &str) -> Result<NodeRef, FsError> {
        Err(FsError::NotDirectory)
    }

    fn create(&self, _name: &str, _kind: FileType, _mode: u32) -> Result<NodeRef, FsError> {
        Err(FsError::ReadOnly)
    }

    fn remove(&self, _name: &str) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    fn read_dir(&self) -> Result<Vec<DirEntry>, FsError> {
        Err(FsError::NotDirectory)
    }

    fn read_link(&self) -> Result<String, FsError> {
        Err(FsError::InvalidInput)
    }

    fn set_link_target(&self, _target: &str) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    fn set_mode(&self, _mode: u32) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    fn set_owner(&self, _uid: u32, _gid: u32) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    fn set_times(&self, _accessed: u64, _modified: u64) -> Result<(), FsError> {
        Err(FsError::ReadOnly)
    }

    fn sync(&self) -> Result<(), FsError> {
        Ok(())
    }
}

/// Weak inode cache: it accelerates repeated lookups without owning nodes.
static INODE_CACHE: SpinLock<Vec<(InodeId, Weak<dyn VfsNode>)>> = SpinLock::new(Vec::new());

pub fn cache_insert(node: &NodeRef) {
    let id = node.inode().id();
    let mut cache = INODE_CACHE.lock();
    cache.retain(|(cached, weak)| *cached != id && weak.strong_count() != 0);
    cache.push((id, alloc::sync::Arc::downgrade(node)));
}

pub fn cache_get(id: InodeId) -> Option<NodeRef> {
    let mut cache = INODE_CACHE.lock();
    let mut found = None;
    cache.retain(|(cached, weak)| {
        if let Some(node) = weak.upgrade() {
            if *cached == id {
                found = Some(node);
            }
            true
        } else {
            false
        }
    });
    found
}

pub fn cache_prune() {
    INODE_CACHE
        .lock()
        .retain(|(_, weak)| weak.strong_count() != 0);
}

pub fn cache_clear() {
    INODE_CACHE.lock().clear();
}
