//! Filesystem-independent nodes, mounts, lookup, and open/create operations.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use super::fd::{FileObject, FileRef, OpenFlags};
use super::inode::{DirEntry, FileType, Inode, InodeMetadata, InodeOps};
use super::path::{absolutize, validate_name, Path, PathBuf};
use crate::sync::SpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    Io,
    NotFound,
    AlreadyExists,
    NotDirectory,
    IsDirectory,
    NotEmpty,
    InvalidInput,
    NameTooLong,
    BadFileDescriptor,
    Interrupted,
    WouldBlock,
    BrokenPipe,
    NotSeekable,
    TooManyOpenFiles,
    PermissionDenied,
    ReadOnly,
    NoSpace,
    Unsupported,
    Loop,
    Overflow,
    Corrupt,
    Busy,
    NotMounted,
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Io => "filesystem I/O error",
            Self::NotFound => "path not found",
            Self::AlreadyExists => "path already exists",
            Self::NotDirectory => "not a directory",
            Self::IsDirectory => "is a directory",
            Self::NotEmpty => "directory not empty",
            Self::InvalidInput => "invalid filesystem argument",
            Self::NameTooLong => "path component too long",
            Self::BadFileDescriptor => "bad file descriptor",
            Self::Interrupted => "filesystem operation interrupted",
            Self::WouldBlock => "operation would block",
            Self::BrokenPipe => "broken pipe",
            Self::NotSeekable => "file is not seekable",
            Self::TooManyOpenFiles => "too many open files",
            Self::PermissionDenied => "permission denied",
            Self::ReadOnly => "read-only filesystem",
            Self::NoSpace => "no space left on filesystem",
            Self::Unsupported => "filesystem operation not supported",
            Self::Loop => "too many symbolic links",
            Self::Overflow => "filesystem value overflow",
            Self::Corrupt => "corrupt filesystem data",
            Self::Busy => "filesystem object is busy",
            Self::NotMounted => "no root filesystem is mounted",
        };
        f.write_str(message)
    }
}

/// Shared handle used throughout the VFS.
pub type NodeRef = Arc<dyn VfsNode>;

/// Object-safe node surface implemented by ramfs and disk filesystems.
pub trait VfsNode: InodeOps {
    fn inode(&self) -> &Inode;

    /// Open a dynamic PTY slave represented by this node.  Ordinary nodes use
    /// the default `None`; devpts overrides it so the returned descriptor is
    /// terminal-aware instead of an offset-based character-file placeholder.
    fn open_pty(&self) -> Result<Option<super::pty::PtyEndpoint>, FsError> {
        Ok(None)
    }

    fn metadata(&self) -> InodeMetadata {
        self.inode().snapshot()
    }
}

/// A mountable filesystem instance.
pub trait FileSystem: Send + Sync {
    fn name(&self) -> &'static str;
    fn root(&self) -> NodeRef;

    fn is_read_only(&self) -> bool {
        false
    }

    fn sync(&self) -> Result<(), FsError> {
        self.root().sync()
    }
}

#[derive(Clone)]
pub struct VfsMount {
    pub path: PathBuf,
    pub filesystem: Arc<dyn FileSystem>,
}

impl fmt::Debug for VfsMount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VfsMount")
            .field("path", &self.path)
            .field("filesystem", &self.filesystem.name())
            .finish()
    }
}

/// Root node, published only after a complete filesystem instance exists.
pub static ROOT: SpinLock<Option<NodeRef>> = SpinLock::new(None);
static MOUNTS: SpinLock<Vec<VfsMount>> = SpinLock::new(Vec::new());

pub fn mount_root(filesystem: Arc<dyn FileSystem>) -> Result<(), FsError> {
    let root = filesystem.root();
    if root.metadata().kind != FileType::Directory {
        return Err(FsError::NotDirectory);
    }

    *ROOT.lock() = Some(root);
    let mut mounts = MOUNTS.lock();
    mounts.clear();
    mounts.push(VfsMount {
        path: PathBuf::root(),
        filesystem,
    });
    Ok(())
}

pub fn mount(path: &Path<'_>, filesystem: Arc<dyn FileSystem>) -> Result<(), FsError> {
    let absolute = absolutize(path)?;
    let target = resolve_absolute(&absolute)?;
    if target.metadata().kind != FileType::Directory
        || filesystem.root().metadata().kind != FileType::Directory
    {
        return Err(FsError::NotDirectory);
    }

    let mut mounts = MOUNTS.lock();
    if mounts.iter().any(|entry| entry.path == absolute) {
        return Err(FsError::Busy);
    }
    mounts.push(VfsMount {
        path: absolute,
        filesystem,
    });
    mounts.sort_by_key(|mount| core::cmp::Reverse(mount.path.as_str().len()));
    Ok(())
}

pub fn unmount(path: &Path<'_>) -> Result<(), FsError> {
    let absolute = absolutize(path)?;
    if absolute.is_root() {
        return Err(FsError::Busy);
    }
    let mut mounts = MOUNTS.lock();
    if mounts.iter().any(|entry| {
        entry.path != absolute && path_has_prefix(entry.path.as_str(), absolute.as_str())
    }) {
        return Err(FsError::Busy);
    }
    let old_len = mounts.len();
    mounts.retain(|entry| entry.path != absolute);
    if mounts.len() == old_len {
        Err(FsError::NotMounted)
    } else {
        Ok(())
    }
}

pub fn mounts() -> Vec<VfsMount> {
    MOUNTS.lock().clone()
}

fn path_has_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    path == prefix
        || (path.starts_with(prefix) && path.as_bytes().get(prefix.len()).copied() == Some(b'/'))
}

fn selected_mount(path: &PathBuf) -> Result<VfsMount, FsError> {
    let mounts = MOUNTS.lock();
    mounts
        .iter()
        .filter(|entry| path_has_prefix(path.as_str(), entry.path.as_str()))
        .max_by_key(|entry| entry.path.as_str().len())
        .cloned()
        .ok_or(FsError::NotMounted)
}

fn relative_to_mount<'a>(path: &'a str, mount: &str) -> &'a str {
    if mount == "/" {
        path.trim_start_matches('/')
    } else {
        path[mount.len()..].trim_start_matches('/')
    }
}

pub fn resolve(path: &Path<'_>) -> Result<NodeRef, FsError> {
    let absolute = absolutize(path)?;
    resolve_absolute(&absolute)
}

pub fn resolve_absolute(path: &PathBuf) -> Result<NodeRef, FsError> {
    resolve_absolute_inner(path, 0)
}

fn resolve_absolute_inner(path: &PathBuf, symlink_depth: usize) -> Result<NodeRef, FsError> {
    const MAX_SYMLINKS: usize = 40;
    if symlink_depth > MAX_SYMLINKS {
        return Err(FsError::Loop);
    }
    let mount = selected_mount(path)?;
    let mut current = mount.filesystem.root();
    let relative = relative_to_mount(path.as_str(), mount.path.as_str());
    let components: Vec<&str> = relative
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect();
    let mut traversed = mount.path.clone();
    for (index, name) in components.iter().copied().enumerate() {
        if current.metadata().kind != FileType::Directory {
            return Err(FsError::NotDirectory);
        }
        let next = current.lookup(name)?;
        if next.metadata().kind == FileType::Symlink {
            let target = next.read_link()?;
            let mut redirected = if target.starts_with('/') {
                PathBuf::from_absolute(&target)?
            } else {
                traversed.join(&target)?
            };
            for remaining in &components[index + 1..] {
                redirected = redirected.join(remaining)?;
            }
            return resolve_absolute_inner(&redirected, symlink_depth + 1);
        }
        traversed = traversed.join(name)?;
        current = next;
    }
    Ok(current)
}

pub fn lookup_parent(path: &Path<'_>) -> Result<(NodeRef, String), FsError> {
    let absolute = absolutize(path)?;
    if absolute.is_root() {
        return Err(FsError::InvalidInput);
    }
    let name = absolute.file_name().ok_or(FsError::InvalidInput)?;
    validate_name(name)?;
    let parent_path = absolute.parent().ok_or(FsError::InvalidInput)?;
    let parent = resolve_absolute(&parent_path)?;
    if parent.metadata().kind != FileType::Directory {
        return Err(FsError::NotDirectory);
    }
    Ok((parent, String::from(name)))
}

pub fn mkdir(path: &Path<'_>, mode: u32) -> Result<NodeRef, FsError> {
    let (parent, name) = lookup_parent(path)?;
    parent.create(&name, FileType::Directory, mode)
}

pub fn create_file(path: &Path<'_>, mode: u32) -> Result<NodeRef, FsError> {
    let (parent, name) = lookup_parent(path)?;
    parent.create(&name, FileType::Regular, mode)
}

pub fn unlink(path: &Path<'_>) -> Result<(), FsError> {
    let absolute = absolutize(path)?;
    if MOUNTS.lock().iter().any(|mount| mount.path == absolute) {
        return Err(FsError::Busy);
    }
    let (parent, name) = lookup_parent(path)?;
    if parent.lookup(&name)?.metadata().kind == FileType::Directory {
        return Err(FsError::IsDirectory);
    }
    parent.remove(&name)
}

pub fn rmdir(path: &Path<'_>) -> Result<(), FsError> {
    let absolute = absolutize(path)?;
    if MOUNTS.lock().iter().any(|mount| mount.path == absolute) {
        return Err(FsError::Busy);
    }
    let (parent, name) = lookup_parent(path)?;
    if parent.lookup(&name)?.metadata().kind != FileType::Directory {
        return Err(FsError::NotDirectory);
    }
    parent.remove(&name)
}

pub fn symlink(target: &str, link: &Path<'_>) -> Result<NodeRef, FsError> {
    if target.is_empty() || target.len() > 4096 || target.as_bytes().contains(&0) {
        return Err(FsError::InvalidInput);
    }
    let (parent, name) = lookup_parent(link)?;
    let node = parent.create(&name, FileType::Symlink, 0o777)?;
    if let Err(error) = node.set_link_target(target) {
        let _ = parent.remove(&name);
        return Err(error);
    }
    Ok(node)
}

pub fn chmod(path: &Path<'_>, mode: u32) -> Result<(), FsError> {
    resolve(path)?.set_mode(mode)
}

pub fn chown(path: &Path<'_>, uid: u32, gid: u32) -> Result<(), FsError> {
    resolve(path)?.set_owner(uid, gid)
}

pub fn set_times(path: &Path<'_>, accessed: u64, modified: u64) -> Result<(), FsError> {
    resolve(path)?.set_times(accessed, modified)
}

pub fn read_dir(path: &Path<'_>) -> Result<Vec<DirEntry>, FsError> {
    resolve(path)?.read_dir()
}

pub fn open(path: &Path<'_>, flags: OpenFlags, mode: u32) -> Result<FileRef, FsError> {
    flags.validate()?;
    let node = match resolve(path) {
        Ok(existing) => {
            if flags.contains(OpenFlags::CREATE) && flags.contains(OpenFlags::EXCLUSIVE) {
                return Err(FsError::AlreadyExists);
            }
            existing
        },
        Err(FsError::NotFound) if flags.contains(OpenFlags::CREATE) => create_file(path, mode)?,
        Err(error) => return Err(error),
    };

    let metadata = node.metadata();
    if flags.contains(OpenFlags::DIRECTORY) && metadata.kind != FileType::Directory {
        return Err(FsError::NotDirectory);
    }
    if metadata.kind == FileType::Directory && flags.can_write() {
        return Err(FsError::IsDirectory);
    }
    if let Some(endpoint) = node.open_pty()? {
        if flags.contains(OpenFlags::TRUNCATE) {
            return Err(FsError::InvalidInput);
        }
        return Ok(Arc::new(FileObject::new_pty(endpoint, flags)));
    }
    if flags.contains(OpenFlags::TRUNCATE) {
        if !flags.can_write() {
            return Err(FsError::PermissionDenied);
        }
        node.truncate(0)?;
    }
    Ok(Arc::new(FileObject::new(node, flags)))
}

pub fn sync_all() -> Result<(), FsError> {
    let mounts = MOUNTS.lock().clone();
    for mount in mounts {
        mount.filesystem.sync()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::ramfs::RamFs;

    #[test]
    fn mountpoints_cannot_be_removed_or_unmounted_below_live_children() {
        let root = RamFs::new();
        root.mkdir_all("/mnt", 0o755).unwrap();
        root.mkdir_all("/target", 0o755).unwrap();
        root.symlink("/link", "/target", 0o777).unwrap();
        mount_root(Arc::new(root)).unwrap();

        let mounted = RamFs::new();
        mounted.mkdir_all("/nested", 0o755).unwrap();
        mount(&Path::new("/mnt"), Arc::new(mounted)).unwrap();
        mount(&Path::new("/mnt/nested"), Arc::new(RamFs::new())).unwrap();

        assert_eq!(rmdir(&Path::new("/mnt")), Err(FsError::Busy));
        assert_eq!(unlink(&Path::new("/mnt")), Err(FsError::Busy));
        assert_eq!(unmount(&Path::new("/mnt")), Err(FsError::Busy));
        unmount(&Path::new("/mnt/nested")).unwrap();
        unmount(&Path::new("/mnt")).unwrap();
        rmdir(&Path::new("/mnt")).unwrap();
        assert_eq!(rmdir(&Path::new("/link")), Err(FsError::NotDirectory));
        unlink(&Path::new("/link")).unwrap();
        rmdir(&Path::new("/target")).unwrap();
    }
}
