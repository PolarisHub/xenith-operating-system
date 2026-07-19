//! Xenith virtual filesystem, in-memory root, initramfs, and FAT32 support.

extern crate alloc;

use alloc::sync::Arc;

pub mod fat;
pub mod fd;
pub mod initramfs;
pub mod inode;
pub mod path;
pub mod pipe;
pub mod pty;
pub mod ramfs;
pub mod syscalls;
pub mod vfs;
pub mod xenithfs;

pub use fd::{FdTable, FileObject, FileRef, OpenFlags, SeekWhence};
pub use inode::{DirEntry, FileType, Inode, InodeId, InodeMetadata, InodeOps};
pub use path::{Path, PathBuf};
pub use vfs::{FileSystem, FsError, NodeRef, VfsMount, VfsNode};

/// Mount a fresh ramfs root and populate the first valid CPIO boot module.
pub fn init(boot_info: &'static limine::BootInfo) {
    let ramfs = ramfs::RamFs::new();
    let filesystem: Arc<dyn FileSystem> = Arc::new(ramfs.clone());
    if let Err(error) = vfs::mount_root(filesystem) {
        panic!("fs: failed to mount ramfs root: {error}");
    }

    match initramfs::load_from_boot(boot_info, &ramfs) {
        Ok(entries) => ::log::info!(
            "fs: mounted ramfs root with {} initramfs entries ({} bytes)",
            entries,
            ramfs.bytes_used()
        ),
        Err(initramfs::InitramfsError::NoArchive) => {
            ::log::warn!("fs: no CPIO initramfs module; mounted an empty ramfs root")
        },
        Err(error) => {
            ::log::error!("fs: initramfs rejected: {}", error);
            panic!("fs: cannot continue with a corrupt initramfs");
        },
    }

    if let Err(error) = ramfs.mkdir_all("/dev/pts", 0o755).and_then(|_| {
        let filesystem: Arc<dyn FileSystem> = Arc::new(pty::DevPtsFs::new());
        vfs::mount(&Path::new("/dev/pts"), filesystem)
    }) {
        panic!("fs: failed to mount devpts: {error}");
    }
}
