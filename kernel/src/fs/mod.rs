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

/// Mount fresh native and Windows ramfs namespaces, then populate the first
/// valid CPIO boot module.
pub fn init(boot_info: &'static limine::BootInfo) {
    let native = ramfs::RamFs::new();
    let filesystem: Arc<dyn FileSystem> = Arc::new(native.clone());
    if let Err(error) = vfs::mount_root(filesystem) {
        panic!("fs: failed to mount ramfs root: {error}");
    }

    if let Err(error) = native.mkdir_all(xenith_abi::WINDOWS_NATIVE_ROOT, 0o755) {
        panic!("fs: failed to create Windows namespace mountpoint: {error}");
    }
    let windows = ramfs::RamFs::new_ascii_case_insensitive();
    let windows_filesystem: Arc<dyn FileSystem> = Arc::new(windows.clone());
    if let Err(error) = vfs::mount(
        &Path::new(xenith_abi::WINDOWS_NATIVE_ROOT),
        windows_filesystem,
    ) {
        panic!("fs: failed to mount Windows namespace: {error}");
    }
    if let Err(error) = windows.mkdir_all("/c", 0o755) {
        panic!("fs: failed to create Windows system drive: {error}");
    }

    match initramfs::load_split_from_boot(boot_info, &native, &windows) {
        Ok(stats) => ::log::info!(
            "fs: mounted ramfs namespaces with {} initramfs entries (native={} entries/{} bytes, windows={} entries/{} bytes)",
            stats.total(),
            stats.native_entries,
            native.bytes_used(),
            stats.windows_entries,
            windows.bytes_used()
        ),
        Err(initramfs::InitramfsError::NoArchive) => {
            ::log::warn!("fs: no CPIO initramfs module; mounted namespace roots only")
        },
        Err(error) => {
            ::log::error!("fs: initramfs rejected: {}", error);
            panic!("fs: cannot continue with a corrupt initramfs");
        },
    }
    ::log::info!(
        "XENITH_WINDOWS_NAMESPACE_READY native={} drive={}",
        xenith_abi::WINDOWS_NATIVE_ROOT,
        xenith_abi::WINDOWS_SYSTEM_DRIVE
    );

    if let Err(error) = native.mkdir_all("/dev/pts", 0o755).and_then(|_| {
        let filesystem: Arc<dyn FileSystem> = Arc::new(pty::DevPtsFs::new());
        vfs::mount(&Path::new("/dev/pts"), filesystem)
    }) {
        panic!("fs: failed to mount devpts: {error}");
    }
}
