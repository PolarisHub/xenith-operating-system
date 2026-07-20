//! Safe VFS syscall operations used after architecture-specific user copies.

extern crate alloc;

use alloc::sync::Arc;

use xenith_abi::ipc::IpcSendTransfer;

pub use super::fd::InstalledTransferBatch;
use super::fd::{FdTable, FileObject, FileRef, OpenFlags, RetiredFiles, SeekWhence};
use super::inode::{FileType, InodeMetadata};
use super::path::{self, Path, PathBuf};
use super::vfs::{self, FsError};
use crate::ipc::channel::{ChannelEndpoint, ChannelTransfers, CHANNEL_TRANSFER_CAPACITY};
use crate::ipc::shared_memory::SharedMemoryRef;
use crate::sync::SpinLock;

static FD_TABLE: SpinLock<Option<FdTable>> = SpinLock::new(None);

/// Run one descriptor-table operation against the current process. Kernel
/// callers outside a registered userspace task retain the bootstrap table so
/// early VFS tests and bring-up helpers continue to work.
fn with_fd_table<R>(operation: impl FnOnce(&mut FdTable) -> R) -> R {
    if crate::user::process::try_current_pid().is_some() {
        return crate::user::process::with_current_process_mut(|process| {
            operation(&mut process.fd_table)
        })
        .expect("current PID disappeared during descriptor operation");
    }
    let mut bootstrap = FD_TABLE.lock();
    operation(bootstrap.get_or_insert_with(FdTable::new_process))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_mtime: i64,
    pub st_ctime: i64,
}

impl From<InodeMetadata> for Stat {
    fn from(metadata: InodeMetadata) -> Self {
        let kind = match metadata.kind {
            FileType::Regular => 0o100000,
            FileType::Directory => 0o040000,
            FileType::Symlink => 0o120000,
            FileType::CharacterDevice => 0o020000,
            FileType::BlockDevice => 0o060000,
        };
        Self {
            st_dev: 0,
            st_ino: metadata.id.get(),
            st_mode: kind | (metadata.mode & 0o7777),
            st_nlink: metadata.links,
            st_uid: metadata.uid,
            st_gid: metadata.gid,
            st_rdev: 0,
            st_size: metadata.size.min(i64::MAX as u64) as i64,
            st_blksize: 4096,
            st_blocks: (metadata.size.saturating_add(511) / 512).min(i64::MAX as u64) as i64,
            st_atime: metadata.accessed.min(i64::MAX as u64) as i64,
            st_mtime: metadata.modified.min(i64::MAX as u64) as i64,
            st_ctime: metadata.changed.min(i64::MAX as u64) as i64,
        }
    }
}

pub fn sys_open(path: &str, raw_flags: u32, mode: u32) -> Result<i32, FsError> {
    let flags = OpenFlags::from_raw(raw_flags)?;
    let file = vfs::open(&Path::new(path), flags, mode)?;
    let result = with_fd_table(|table| table.alloc_fd(Arc::clone(&file)));
    drop(file);
    result
}

pub fn sys_close(fd: i32) -> Result<(), FsError> {
    let removed = with_fd_table(|table| table.close(fd))?;
    drop(removed);
    Ok(())
}

pub fn sys_read(fd: i32, buffer: &mut [u8]) -> Result<usize, FsError> {
    let file = get_file_with_rights(fd, xenith_abi::ipc::IPC_TRANSFER_RIGHT_READ)?;
    file.read(buffer)
}

pub fn sys_write(fd: i32, buffer: &[u8]) -> Result<usize, FsError> {
    let file = get_file_with_rights(fd, xenith_abi::ipc::IPC_TRANSFER_RIGHT_WRITE)?;
    file.write(buffer)
}

pub fn sys_lseek(fd: i32, offset: i64, raw_whence: i32) -> Result<u64, FsError> {
    let whence = SeekWhence::from_raw(raw_whence)?;
    let file = with_fd_table(|table| {
        table.get_with_any_right(
            fd,
            xenith_abi::ipc::IPC_TRANSFER_RIGHT_READ | xenith_abi::ipc::IPC_TRANSFER_RIGHT_WRITE,
        )
    })?;
    file.seek(offset, whence)
}

pub fn sys_stat(path: &str) -> Result<Stat, FsError> {
    Ok(vfs::resolve(&Path::new(path))?.metadata().into())
}

pub fn sys_fstat(fd: i32) -> Result<Stat, FsError> {
    let file = with_fd_table(|table| table.get(fd))?;
    Ok(file.node()?.metadata().into())
}

pub fn sys_mkdir(path: &str, mode: u32) -> Result<(), FsError> {
    vfs::mkdir(&Path::new(path), mode).map(|_| ())
}

pub fn sys_unlink(path: &str) -> Result<(), FsError> {
    vfs::unlink(&Path::new(path))
}

pub fn sys_rmdir(path: &str) -> Result<(), FsError> {
    vfs::rmdir(&Path::new(path))
}

pub fn sys_mount_ramfs(path: &str) -> Result<(), FsError> {
    let filesystem: Arc<dyn super::vfs::FileSystem> = Arc::new(super::ramfs::RamFs::new());
    vfs::mount(&Path::new(path), filesystem)
}

pub fn sys_unmount(path: &str) -> Result<(), FsError> {
    vfs::unmount(&Path::new(path))
}

pub fn sys_symlink(target: &str, link: &str) -> Result<(), FsError> {
    vfs::symlink(target, &Path::new(link)).map(|_| ())
}

pub fn sys_chmod(path: &str, mode: u32) -> Result<(), FsError> {
    vfs::chmod(&Path::new(path), mode)
}

pub fn sys_chown(path: &str, uid: u32, gid: u32) -> Result<(), FsError> {
    vfs::chown(&Path::new(path), uid, gid)
}

pub fn sys_utimens(path: &str, accessed: u64, modified: u64) -> Result<(), FsError> {
    vfs::set_times(&Path::new(path), accessed, modified)
}

pub fn sys_chdir(new_directory: &str) -> Result<(), FsError> {
    let absolute = path::absolutize(&Path::new(new_directory))?;
    let node = vfs::resolve_absolute(&absolute)?;
    if node.metadata().kind != FileType::Directory {
        return Err(FsError::NotDirectory);
    }
    path::set_current_dir(absolute);
    Ok(())
}

pub fn sys_getcwd(buffer: &mut [u8]) -> Result<usize, FsError> {
    let cwd = path::current_dir();
    let required = cwd.as_str().len().checked_add(1).ok_or(FsError::Overflow)?;
    if buffer.len() < required {
        return Err(FsError::InvalidInput);
    }
    buffer[..required - 1].copy_from_slice(cwd.as_str().as_bytes());
    buffer[required - 1] = 0;
    Ok(required)
}

pub fn sys_dup(fd: i32) -> Result<i32, FsError> {
    with_fd_table(|table| table.dup(fd))
}

pub fn sys_dup2(old_fd: i32, new_fd: i32) -> Result<i32, FsError> {
    let (duplicated, displaced) = with_fd_table(|table| table.dup2(old_fd, new_fd))?;
    drop(displaced);
    Ok(duplicated)
}

pub fn get_file(fd: i32) -> Result<FileRef, FsError> {
    with_fd_table(|table| table.get(fd))
}

pub fn get_file_with_rights(fd: i32, required_rights: u32) -> Result<FileRef, FsError> {
    with_fd_table(|table| table.get_with_rights(fd, required_rights))
}

pub fn get_file_with_any_right(fd: i32, accepted_rights: u32) -> Result<FileRef, FsError> {
    with_fd_table(|table| table.get_with_any_right(fd, accepted_rights))
}

pub fn descriptor_rights(fd: i32) -> Result<u32, FsError> {
    with_fd_table(|table| table.rights(fd))
}

pub fn get_channel(fd: i32, required_rights: u32) -> Result<FileRef, FsError> {
    let file = get_file_with_rights(fd, required_rights)?;
    if file.channel_endpoint().is_none() {
        return Err(FsError::BadFileDescriptor);
    }
    Ok(file)
}

pub fn get_shared_memory(fd: i32, required_rights: u32) -> Result<SharedMemoryRef, FsError> {
    let file = get_file_with_rights(fd, required_rights)?;
    file.shared_memory()
        .map(Arc::clone)
        .ok_or(FsError::BadFileDescriptor)
}

/// Resolve one shared-memory descriptor and return the exact rights attached
/// to that descriptor in the same descriptor-table transaction.
///
/// Mapping code retains the returned rights as the maximum permissions of
/// the mapping, so a later `mprotect` cannot recover authority that was
/// removed while the descriptor was transferred.
pub fn get_shared_memory_with_rights(
    fd: i32,
    required_rights: u32,
) -> Result<(SharedMemoryRef, u32), FsError> {
    let resolved: Result<(FileRef, u32), FsError> = with_fd_table(|table| {
        let file = table.get_with_rights(fd, required_rights)?;
        let rights = table.rights(fd)?;
        Ok((file, rights))
    });
    let (file, rights) = resolved?;
    let object = file
        .shared_memory()
        .map(Arc::clone)
        .ok_or(FsError::BadFileDescriptor)?;
    drop(file);
    Ok((object, rights))
}

pub fn install_channel_pair(
    first: ChannelEndpoint,
    second: ChannelEndpoint,
) -> Result<(i32, i32), FsError> {
    let first = Arc::new(FileObject::new_channel(first));
    let second = Arc::new(FileObject::new_channel(second));
    let result = with_fd_table(|table| table.alloc_pair(Arc::clone(&first), Arc::clone(&second)));
    drop(first);
    drop(second);
    result
}

pub fn install_shared_memory(object: SharedMemoryRef) -> Result<i32, FsError> {
    let file = Arc::new(FileObject::new_shared_memory(object));
    let result = with_fd_table(|table| table.alloc_fd(Arc::clone(&file)));
    drop(file);
    result
}

pub fn snapshot_channel_transfers(
    requests: &[IpcSendTransfer; CHANNEL_TRANSFER_CAPACITY],
    count: usize,
) -> Result<ChannelTransfers, FsError> {
    with_fd_table(|table| table.snapshot_channel_transfers(requests, count))
}

pub fn install_channel_transfers(
    transfers: &ChannelTransfers,
) -> Result<InstalledTransferBatch, FsError> {
    with_fd_table(|table| table.install_channel_transfers(transfers))
}

#[must_use = "drop rolled-back files after this function releases PROCESS_TABLE"]
pub fn rollback_channel_transfers(installed: InstalledTransferBatch) -> RetiredFiles {
    with_fd_table(|table| table.rollback_channel_transfers(installed))
}

pub fn sys_pipe() -> Result<(i32, i32), FsError> {
    let (reader, writer) = super::pipe::create();
    let reader = Arc::new(FileObject::new_pipe(reader, OpenFlags::READ_ONLY));
    let writer = Arc::new(FileObject::new_pipe(writer, OpenFlags::WRITE_ONLY));
    let result = with_fd_table(|table| table.alloc_pair(Arc::clone(&reader), Arc::clone(&writer)));
    drop(reader);
    drop(writer);
    result
}

pub fn sys_open_pty() -> Result<(i32, i32), FsError> {
    let (master, slave) = super::pty::create()?;
    let master = Arc::new(FileObject::new_pty(master, OpenFlags::READ_WRITE));
    let slave = Arc::new(FileObject::new_pty(slave, OpenFlags::READ_WRITE));
    let result = with_fd_table(|table| table.alloc_pair(Arc::clone(&master), Arc::clone(&slave)));
    drop(master);
    drop(slave);
    result
}

pub fn reset_process_state() {
    let replacement = FdTable::new_process();
    let previous = with_fd_table(|table| core::mem::replace(table, replacement));
    drop(previous);
    path::set_current_dir(PathBuf::root());
}

impl From<FsError> for crate::syscall::Errno {
    fn from(value: FsError) -> Self {
        use crate::syscall::Errno;
        match value {
            FsError::Io | FsError::Corrupt => Errno::Eio,
            FsError::NotFound => Errno::Enoent,
            FsError::AlreadyExists => Errno::Eexist,
            FsError::NotDirectory => Errno::Enotdir,
            FsError::IsDirectory => Errno::Eisdir,
            FsError::NotEmpty => Errno::Enotempty,
            FsError::InvalidInput | FsError::Overflow => Errno::Einval,
            FsError::NameTooLong => Errno::Enametoolong,
            FsError::BadFileDescriptor => Errno::Ebadf,
            FsError::Interrupted => Errno::Eintr,
            FsError::WouldBlock => Errno::Eagain,
            FsError::BrokenPipe => Errno::Epipe,
            FsError::NotSeekable => Errno::Espipe,
            FsError::TooManyOpenFiles => Errno::Emfile,
            FsError::PermissionDenied => Errno::Eacces,
            FsError::ReadOnly => Errno::Erofs,
            FsError::NoSpace => Errno::Enospc,
            FsError::Unsupported => Errno::Enosys,
            FsError::Loop => Errno::Eloop,
            FsError::Busy => Errno::Ebusy,
            FsError::NotMounted => Errno::Enodev,
        }
    }
}

pub use sys_chdir as chdir;
pub use sys_close as close;
pub use sys_dup as dup;
pub use sys_dup2 as dup2;
pub use sys_fstat as fstat;
pub use sys_getcwd as getcwd;
pub use sys_lseek as lseek;
pub use sys_mkdir as mkdir;
pub use sys_open as open;
pub use sys_open_pty as open_pty;
pub use sys_pipe as pipe;
pub use sys_read as read;
pub use sys_rmdir as rmdir;
pub use sys_stat as stat;
pub use sys_unlink as unlink;
pub use sys_write as write;
