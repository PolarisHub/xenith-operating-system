//! Writable in-memory filesystem used for the initial root mount.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::inode::{
    allocate_inode_id, cache_insert, DirEntry, FileType, Inode, InodeMetadata, InodeOps,
};
use super::path::{validate_name, Component, Path, PathBuf, MAX_NAME};
use super::vfs::{FileSystem, FsError, NodeRef, VfsNode};
use crate::sync::SpinLock;

enum RamNodeData {
    File(Vec<u8>),
    Directory(BTreeMap<String, RamDirectoryEntry>),
    Symlink(String),
}

#[derive(Clone, Copy)]
enum NamePolicy {
    CaseSensitive,
    AsciiCaseInsensitive,
}

struct RamDirectoryEntry {
    /// `None` means the map key already is the display spelling. The
    /// case-insensitive policy stores the original spelling separately from
    /// its canonical lowercase key.
    display_name: Option<String>,
    node: NodeRef,
}

struct FoldedLookupName {
    bytes: [u8; MAX_NAME],
    len: usize,
}

impl FoldedLookupName {
    fn new(name: &str) -> Self {
        debug_assert!(name.len() <= MAX_NAME);
        let mut folded = Self {
            bytes: [0; MAX_NAME],
            len: name.len(),
        };
        for (output, input) in folded.bytes.iter_mut().zip(name.bytes()) {
            *output = input.to_ascii_lowercase();
        }
        folded
    }

    fn as_str(&self) -> &str {
        match core::str::from_utf8(&self.bytes[..self.len]) {
            Ok(name) => name,
            Err(_) => unreachable!("ASCII folding preserves valid UTF-8"),
        }
    }
}

impl NamePolicy {
    fn lookup<'a>(
        self,
        entries: &'a BTreeMap<String, RamDirectoryEntry>,
        requested: &str,
    ) -> Option<&'a RamDirectoryEntry> {
        match self {
            Self::CaseSensitive => entries.get(requested),
            Self::AsciiCaseInsensitive => {
                let folded = FoldedLookupName::new(requested);
                entries.get(folded.as_str())
            },
        }
    }

    fn insertion_key(self, name: &str) -> String {
        match self {
            Self::CaseSensitive => name.to_string(),
            Self::AsciiCaseInsensitive => name.to_ascii_lowercase(),
        }
    }

    fn display_name(self, name: &str) -> Option<String> {
        match self {
            Self::CaseSensitive => None,
            Self::AsciiCaseInsensitive => Some(name.to_string()),
        }
    }

    fn remove(
        self,
        entries: &mut BTreeMap<String, RamDirectoryEntry>,
        requested: &str,
    ) -> Option<RamDirectoryEntry> {
        match self {
            Self::CaseSensitive => entries.remove(requested),
            Self::AsciiCaseInsensitive => {
                let folded = FoldedLookupName::new(requested);
                entries.remove(folded.as_str())
            },
        }
    }
}

struct RamFsInner {
    bytes: AtomicU64,
    name_policy: NamePolicy,
}

impl RamFsInner {
    const fn new(name_policy: NamePolicy) -> Self {
        Self {
            bytes: AtomicU64::new(0),
            name_policy,
        }
    }
}

struct RamNode {
    inode: Inode,
    filesystem: Weak<RamFsInner>,
    name_policy: NamePolicy,
    data: SpinLock<RamNodeData>,
}

impl RamNode {
    fn allocate(filesystem: &Arc<RamFsInner>, kind: FileType, mode: u32) -> NodeRef {
        let data = match kind {
            FileType::Regular => RamNodeData::File(Vec::new()),
            FileType::Directory => RamNodeData::Directory(BTreeMap::new()),
            FileType::Symlink => RamNodeData::Symlink(String::new()),
            FileType::CharacterDevice | FileType::BlockDevice => RamNodeData::File(Vec::new()),
        };
        let metadata = InodeMetadata::new(allocate_inode_id(), kind, mode & 0o7777);
        let node: NodeRef = Arc::new(Self {
            inode: Inode::new(metadata),
            filesystem: Arc::downgrade(filesystem),
            name_policy: filesystem.name_policy,
            data: SpinLock::new(data),
        });
        cache_insert(&node);
        node
    }
}

impl VfsNode for RamNode {
    fn inode(&self) -> &Inode {
        &self.inode
    }
}

impl InodeOps for RamNode {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let offset = usize::try_from(offset).map_err(|_| FsError::Overflow)?;
        let data = self.data.lock();
        let bytes = match &*data {
            RamNodeData::File(bytes) => bytes.as_slice(),
            RamNodeData::Directory(_) => return Err(FsError::IsDirectory),
            RamNodeData::Symlink(target) => target.as_bytes(),
        };
        if offset >= bytes.len() {
            return Ok(0);
        }
        let count = buf.len().min(bytes.len() - offset);
        buf[..count].copy_from_slice(&bytes[offset..offset + count]);
        Ok(count)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        let offset = usize::try_from(offset).map_err(|_| FsError::Overflow)?;
        let end = offset.checked_add(buf.len()).ok_or(FsError::Overflow)?;
        let mut data = self.data.lock();
        let bytes = match &mut *data {
            RamNodeData::File(bytes) => bytes,
            RamNodeData::Directory(_) => return Err(FsError::IsDirectory),
            RamNodeData::Symlink(_) => return Err(FsError::InvalidInput),
        };
        let old_len = bytes.len();
        if end > old_len {
            bytes.resize(end, 0);
        }
        bytes[offset..end].copy_from_slice(buf);
        self.inode.set_size(bytes.len() as u64);
        if let Some(filesystem) = self.filesystem.upgrade() {
            if bytes.len() >= old_len {
                filesystem
                    .bytes
                    .fetch_add((bytes.len() - old_len) as u64, Ordering::Relaxed);
            }
        }
        Ok(buf.len())
    }

    fn truncate(&self, size: u64) -> Result<(), FsError> {
        let size = usize::try_from(size).map_err(|_| FsError::Overflow)?;
        let mut data = self.data.lock();
        let bytes = match &mut *data {
            RamNodeData::File(bytes) => bytes,
            RamNodeData::Directory(_) => return Err(FsError::IsDirectory),
            RamNodeData::Symlink(_) => return Err(FsError::InvalidInput),
        };
        let old_len = bytes.len();
        bytes.resize(size, 0);
        self.inode.set_size(size as u64);
        if let Some(filesystem) = self.filesystem.upgrade() {
            if size >= old_len {
                filesystem
                    .bytes
                    .fetch_add((size - old_len) as u64, Ordering::Relaxed);
            } else {
                filesystem
                    .bytes
                    .fetch_sub((old_len - size) as u64, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    fn lookup(&self, name: &str) -> Result<NodeRef, FsError> {
        validate_name(name)?;
        let data = self.data.lock();
        match &*data {
            RamNodeData::Directory(entries) => self
                .name_policy
                .lookup(entries, name)
                .map(|entry| Arc::clone(&entry.node))
                .ok_or(FsError::NotFound),
            _ => Err(FsError::NotDirectory),
        }
    }

    fn create(&self, name: &str, kind: FileType, mode: u32) -> Result<NodeRef, FsError> {
        validate_name(name)?;
        let filesystem = self.filesystem.upgrade().ok_or(FsError::Io)?;
        let mut data = self.data.lock();
        let entries = match &mut *data {
            RamNodeData::Directory(entries) => entries,
            _ => return Err(FsError::NotDirectory),
        };
        if self.name_policy.lookup(entries, name).is_some() {
            return Err(FsError::AlreadyExists);
        }
        let node = Self::allocate(&filesystem, kind, mode);
        entries.insert(self.name_policy.insertion_key(name), RamDirectoryEntry {
            display_name: self.name_policy.display_name(name),
            node: Arc::clone(&node),
        });
        Ok(node)
    }

    fn remove(&self, name: &str) -> Result<(), FsError> {
        validate_name(name)?;
        let mut data = self.data.lock();
        let entries = match &mut *data {
            RamNodeData::Directory(entries) => entries,
            _ => return Err(FsError::NotDirectory),
        };
        let child = self
            .name_policy
            .lookup(entries, name)
            .map(|entry| Arc::clone(&entry.node))
            .ok_or(FsError::NotFound)?;
        if child.metadata().kind == FileType::Directory && !child.read_dir()?.is_empty() {
            return Err(FsError::NotEmpty);
        }
        let released = child.metadata().size;
        self.name_policy
            .remove(entries, name)
            .ok_or(FsError::NotFound)?;
        if released != 0 {
            if let Some(filesystem) = self.filesystem.upgrade() {
                filesystem.bytes.fetch_sub(released, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    fn read_dir(&self) -> Result<Vec<DirEntry>, FsError> {
        let data = self.data.lock();
        let entries = match &*data {
            RamNodeData::Directory(entries) => entries,
            _ => return Err(FsError::NotDirectory),
        };
        Ok(entries
            .iter()
            .map(|(key, entry)| {
                let metadata = entry.node.metadata();
                DirEntry {
                    name: entry.display_name.clone().unwrap_or_else(|| key.clone()),
                    inode: metadata.id,
                    kind: metadata.kind,
                }
            })
            .collect())
    }

    fn read_link(&self) -> Result<String, FsError> {
        let data = self.data.lock();
        match &*data {
            RamNodeData::Symlink(target) => Ok(target.clone()),
            _ => Err(FsError::InvalidInput),
        }
    }

    fn set_link_target(&self, target: &str) -> Result<(), FsError> {
        let mut data = self.data.lock();
        match &mut *data {
            RamNodeData::Symlink(current) => {
                let old_len = current.len();
                *current = target.to_string();
                self.inode.set_size(target.len() as u64);
                if let Some(filesystem) = self.filesystem.upgrade() {
                    if target.len() >= old_len {
                        filesystem
                            .bytes
                            .fetch_add((target.len() - old_len) as u64, Ordering::Relaxed);
                    } else {
                        filesystem
                            .bytes
                            .fetch_sub((old_len - target.len()) as u64, Ordering::Relaxed);
                    }
                }
                Ok(())
            },
            _ => Err(FsError::InvalidInput),
        }
    }

    fn set_mode(&self, mode: u32) -> Result<(), FsError> {
        self.inode
            .update_metadata(|metadata| metadata.mode = mode & 0o7777);
        Ok(())
    }

    fn set_owner(&self, uid: u32, gid: u32) -> Result<(), FsError> {
        self.inode.update_metadata(|metadata| {
            metadata.uid = uid;
            metadata.gid = gid;
        });
        Ok(())
    }

    fn set_times(&self, accessed: u64, modified: u64) -> Result<(), FsError> {
        self.inode.update_metadata(|metadata| {
            metadata.accessed = accessed;
            metadata.modified = modified;
            metadata.changed = modified;
        });
        Ok(())
    }
}

/// A ramfs instance. Cloning it shares every node and byte counter.
#[derive(Clone)]
pub struct RamFs {
    inner: Arc<RamFsInner>,
    root: NodeRef,
}

impl RamFs {
    pub fn new() -> Self {
        Self::with_name_policy(NamePolicy::CaseSensitive)
    }

    /// Create a filesystem whose directory lookups fold ASCII case while
    /// retaining the spelling supplied when each entry was created.
    pub fn new_ascii_case_insensitive() -> Self {
        Self::with_name_policy(NamePolicy::AsciiCaseInsensitive)
    }

    fn with_name_policy(name_policy: NamePolicy) -> Self {
        let inner = Arc::new(RamFsInner::new(name_policy));
        let root = RamNode::allocate(&inner, FileType::Directory, 0o755);
        Self { inner, root }
    }

    pub fn bytes_used(&self) -> u64 {
        self.inner.bytes.load(Ordering::Relaxed)
    }

    fn resolve_internal(&self, path: &PathBuf) -> Result<NodeRef, FsError> {
        let mut current = Arc::clone(&self.root);
        for component in Path::new(path.as_str()).components() {
            if let Component::Normal(name) = component {
                current = current.lookup(name)?;
            }
        }
        Ok(current)
    }

    pub fn mkdir_all(&self, path: &str, mode: u32) -> Result<NodeRef, FsError> {
        let path = PathBuf::normalize(path)?;
        let mut current = Arc::clone(&self.root);
        for component in Path::new(path.as_str()).components() {
            let Component::Normal(name) = component else {
                continue;
            };
            current = match current.lookup(name) {
                Ok(node) if node.metadata().kind == FileType::Directory => node,
                Ok(_) => return Err(FsError::NotDirectory),
                Err(FsError::NotFound) => current.create(name, FileType::Directory, mode)?,
                Err(error) => return Err(error),
            };
        }
        Ok(current)
    }

    pub fn write_file(&self, path: &str, data: &[u8], mode: u32) -> Result<NodeRef, FsError> {
        let path = PathBuf::normalize(path)?;
        let parent_path = path.parent().ok_or(FsError::InvalidInput)?;
        let parent = self.mkdir_all(parent_path.as_str(), 0o755)?;
        let name = path.file_name().ok_or(FsError::InvalidInput)?;
        let file = match parent.lookup(name) {
            Ok(node) if node.metadata().kind == FileType::Regular => node,
            Ok(_) => return Err(FsError::AlreadyExists),
            Err(FsError::NotFound) => parent.create(name, FileType::Regular, mode)?,
            Err(error) => return Err(error),
        };
        file.truncate(0)?;
        file.write_at(0, data)?;
        Ok(file)
    }

    pub fn symlink(&self, path: &str, target: &str, mode: u32) -> Result<NodeRef, FsError> {
        let path = PathBuf::normalize(path)?;
        let parent_path = path.parent().ok_or(FsError::InvalidInput)?;
        let parent = self.mkdir_all(parent_path.as_str(), 0o755)?;
        let name = path.file_name().ok_or(FsError::InvalidInput)?;
        let node = parent.create(name, FileType::Symlink, mode)?;
        node.set_link_target(target)?;
        Ok(node)
    }

    pub fn node(&self, path: &str) -> Result<NodeRef, FsError> {
        self.resolve_internal(&PathBuf::normalize(path)?)
    }
}

impl Default for RamFs {
    fn default() -> Self {
        Self::new()
    }
}

impl FileSystem for RamFs {
    fn name(&self) -> &'static str {
        "ramfs"
    }

    fn root(&self) -> NodeRef {
        Arc::clone(&self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_sparse_files_and_directories() {
        let fs = RamFs::new();
        let file = fs.write_file("/etc/xenith.conf", b"ok", 0o640).unwrap();
        file.write_at(4, b"!").unwrap();
        let mut bytes = [0xff; 5];
        assert_eq!(file.read_at(0, &mut bytes).unwrap(), 5);
        assert_eq!(&bytes, b"ok\0\0!");
        assert_eq!(fs.node("/etc").unwrap().read_dir().unwrap().len(), 1);
    }

    #[test]
    fn symlink_target_is_retained() {
        let fs = RamFs::new();
        fs.write_file("/bin/init", b"elf", 0o755).unwrap();
        let link = fs.symlink("/init", "/bin/init", 0o777).unwrap();
        assert_eq!(link.read_link().unwrap(), "/bin/init");
    }

    #[test]
    fn metadata_mutations_are_visible_without_changing_file_kind() {
        let fs = RamFs::new();
        let file = fs.write_file("/note", b"x", 0o644).unwrap();
        file.set_mode(0o6750).unwrap();
        file.set_owner(1000, 100).unwrap();
        file.set_times(11, 22).unwrap();
        let metadata = file.metadata();
        assert_eq!(metadata.kind, FileType::Regular);
        assert_eq!(metadata.mode, 0o6750);
        assert_eq!((metadata.uid, metadata.gid), (1000, 100));
        assert_eq!(
            (metadata.accessed, metadata.modified, metadata.changed),
            (11, 22, 22)
        );
    }

    #[test]
    fn ascii_case_insensitive_instance_preserves_original_spelling() {
        let fs = RamFs::new_ascii_case_insensitive();
        fs.write_file("/Users/Xenith/Music/Track.WAV", b"audio", 0o644)
            .unwrap();

        let mut bytes = [0u8; 5];
        let file = fs.node("/users/xENITH/music/track.wav").unwrap();
        assert_eq!(file.read_at(0, &mut bytes).unwrap(), bytes.len());
        assert_eq!(&bytes, b"audio");

        let entries = fs.node("/USERS/XENITH/MUSIC").unwrap().read_dir().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Track.WAV");
    }

    #[test]
    fn ascii_case_insensitive_instance_rejects_duplicates_and_removes_by_folded_name() {
        let fs = RamFs::new_ascii_case_insensitive();
        let directory = fs.mkdir_all("/ProgramData", 0o755).unwrap();
        directory
            .create("Settings.ini", FileType::Regular, 0o644)
            .unwrap();
        assert!(matches!(
            directory.create("SETTINGS.INI", FileType::Regular, 0o644),
            Err(FsError::AlreadyExists)
        ));

        directory.remove("settings.INI").unwrap();
        assert_eq!(
            directory.lookup("Settings.ini").err(),
            Some(FsError::NotFound)
        );
        assert!(directory.read_dir().unwrap().is_empty());
    }

    #[test]
    fn default_instance_remains_case_sensitive() {
        let fs = RamFs::new();
        fs.write_file("/Case", b"upper", 0o644).unwrap();
        fs.write_file("/case", b"lower", 0o644).unwrap();
        assert!(fs.node("/CASE").is_err());
        assert_eq!(fs.root().read_dir().unwrap().len(), 2);
    }
}
