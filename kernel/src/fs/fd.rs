//! Open-file descriptions and per-process descriptor tables.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::{array, fmt};

use xenith_abi::ipc::{
    IpcReceiveTransfer, IpcSendTransfer, IPC_MAX_TRANSFERS, IPC_TRANSFER_RIGHTS_ALL,
    IPC_TRANSFER_RIGHT_MAP, IPC_TRANSFER_RIGHT_READ, IPC_TRANSFER_RIGHT_TRANSFER,
    IPC_TRANSFER_RIGHT_WRITE,
};
use xenith_abi::spawn::{SpawnFileAction, SPAWN_RESTRICTED_MAX_FILE_ACTIONS};
use xenith_bitflags::bitflags;

use super::inode::FileType;
use super::pipe::{PipeDirection, PipeEndpoint};
use super::pty::{PtyEndpoint, PtySide};
use super::vfs::{FsError, NodeRef};
use crate::ipc::channel::{
    ChannelEndpoint, ChannelTransfer, ChannelTransfers, CHANNEL_TRANSFER_CAPACITY,
};
use crate::ipc::shared_memory::SharedMemoryRef;
use crate::sync::SpinLock;

const _: [(); CHANNEL_TRANSFER_CAPACITY] = [(); IPC_MAX_TRANSFERS as usize];

/// Initial rights for message-channel descriptors. `TRANSFER` is withheld to
/// prevent queued channel references from forming ownership cycles.
pub const CHANNEL_DESCRIPTOR_RIGHTS: u32 = IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_WRITE;
/// Initial rights for shared-memory descriptors.
pub const SHARED_MEMORY_DESCRIPTOR_RIGHTS: u32 = IPC_TRANSFER_RIGHT_READ
    | IPC_TRANSFER_RIGHT_WRITE
    | IPC_TRANSFER_RIGHT_MAP
    | IPC_TRANSFER_RIGHT_TRANSFER;

bitflags! {
    /// POSIX-compatible open flag bits accepted by the VFS.
    pub struct OpenFlags: u32 {
        pub const WRITE_ONLY = 0x0001;
        pub const READ_WRITE = 0x0002;
        pub const ACCESS_MODE = 0x0003;
        pub const CREATE = 0x0040;
        pub const EXCLUSIVE = 0x0080;
        pub const TRUNCATE = 0x0200;
        pub const APPEND = 0x0400;
        pub const NONBLOCK = 0x0800;
        pub const DIRECTORY = 0x1_0000;
        pub const CLOSE_ON_EXEC = 0x8_0000;
    }
}

impl OpenFlags {
    pub const READ_ONLY: Self = Self::empty();

    pub fn from_raw(bits: u32) -> Result<Self, FsError> {
        Self::from_bits(bits).ok_or(FsError::InvalidInput)
    }

    pub fn validate(self) -> Result<(), FsError> {
        if self.bits() & Self::ACCESS_MODE.bits() == Self::ACCESS_MODE.bits() {
            return Err(FsError::InvalidInput);
        }
        if self.contains(Self::TRUNCATE) && !self.can_write() {
            return Err(FsError::PermissionDenied);
        }
        Ok(())
    }

    pub const fn can_read(self) -> bool {
        self.bits() & Self::ACCESS_MODE.bits() != Self::WRITE_ONLY.bits()
    }

    pub const fn can_write(self) -> bool {
        let access = self.bits() & Self::ACCESS_MODE.bits();
        access == Self::WRITE_ONLY.bits() || access == Self::READ_WRITE.bits()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeekWhence {
    Start,
    Current,
    End,
}

impl SeekWhence {
    pub fn from_raw(value: i32) -> Result<Self, FsError> {
        match value {
            0 => Ok(Self::Start),
            1 => Ok(Self::Current),
            2 => Ok(Self::End),
            _ => Err(FsError::InvalidInput),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleStream {
    Stdin,
    Stdout,
    Stderr,
}

enum FileBackend {
    Vfs(NodeRef),
    Console(ConsoleStream),
    Pipe(PipeEndpoint),
    Pty(PtyEndpoint),
    Channel(ChannelEndpoint),
    SharedMemory(SharedMemoryRef),
}

/// Shared open-file description. `dup` and `fork` share this object's offset
/// and, for pipes, the lifetime of its endpoint.
pub struct FileObject {
    backend: FileBackend,
    offset: SpinLock<u64>,
    flags: OpenFlags,
}

pub type FileRef = Arc<FileObject>;

impl FileObject {
    pub fn new(node: NodeRef, flags: OpenFlags) -> Self {
        Self {
            backend: FileBackend::Vfs(node),
            offset: SpinLock::new(0),
            flags,
        }
    }

    pub fn new_console(stream: ConsoleStream) -> Self {
        let flags = match stream {
            ConsoleStream::Stdin => OpenFlags::READ_ONLY,
            ConsoleStream::Stdout | ConsoleStream::Stderr => OpenFlags::WRITE_ONLY,
        };
        Self {
            backend: FileBackend::Console(stream),
            offset: SpinLock::new(0),
            flags,
        }
    }

    pub fn new_pipe(endpoint: PipeEndpoint, flags: OpenFlags) -> Self {
        Self {
            backend: FileBackend::Pipe(endpoint),
            offset: SpinLock::new(0),
            flags,
        }
    }

    pub fn new_pty(endpoint: PtyEndpoint, flags: OpenFlags) -> Self {
        Self {
            backend: FileBackend::Pty(endpoint),
            offset: SpinLock::new(0),
            flags,
        }
    }

    pub fn new_channel(endpoint: ChannelEndpoint) -> Self {
        Self {
            backend: FileBackend::Channel(endpoint),
            offset: SpinLock::new(0),
            flags: OpenFlags::READ_WRITE,
        }
    }

    pub fn new_shared_memory(object: SharedMemoryRef) -> Self {
        Self {
            backend: FileBackend::SharedMemory(object),
            offset: SpinLock::new(0),
            flags: OpenFlags::READ_WRITE,
        }
    }

    #[must_use]
    pub fn channel_endpoint(&self) -> Option<&ChannelEndpoint> {
        match &self.backend {
            FileBackend::Channel(endpoint) => Some(endpoint),
            FileBackend::Vfs(_)
            | FileBackend::Console(_)
            | FileBackend::Pipe(_)
            | FileBackend::Pty(_)
            | FileBackend::SharedMemory(_) => None,
        }
    }

    #[must_use]
    pub fn shared_memory(&self) -> Option<&SharedMemoryRef> {
        match &self.backend {
            FileBackend::SharedMemory(object) => Some(object),
            FileBackend::Vfs(_)
            | FileBackend::Console(_)
            | FileBackend::Pipe(_)
            | FileBackend::Pty(_)
            | FileBackend::Channel(_) => None,
        }
    }

    fn initial_descriptor_rights(&self) -> u32 {
        match &self.backend {
            // Channel transfer is intentionally withheld: a queued channel
            // FileRef could otherwise form an Arc cycle back to its pair.
            FileBackend::Channel(_) => CHANNEL_DESCRIPTOR_RIGHTS,
            FileBackend::SharedMemory(_) => SHARED_MEMORY_DESCRIPTOR_RIGHTS,
            FileBackend::Vfs(_)
            | FileBackend::Console(_)
            | FileBackend::Pipe(_)
            | FileBackend::Pty(_) => {
                let mut rights = IPC_TRANSFER_RIGHT_TRANSFER;
                if self.flags.can_read() {
                    rights |= IPC_TRANSFER_RIGHT_READ;
                }
                if self.flags.can_write() {
                    rights |= IPC_TRANSFER_RIGHT_WRITE;
                }
                rights
            },
        }
    }

    pub fn node(&self) -> Result<NodeRef, FsError> {
        match &self.backend {
            FileBackend::Vfs(node) => Ok(Arc::clone(node)),
            FileBackend::Pty(endpoint) => Ok(endpoint.node()),
            FileBackend::Console(_)
            | FileBackend::Pipe(_)
            | FileBackend::Channel(_)
            | FileBackend::SharedMemory(_) => Err(FsError::InvalidInput),
        }
    }

    pub const fn flags(&self) -> OpenFlags {
        self.flags
    }

    pub fn offset(&self) -> u64 {
        *self.offset.lock()
    }

    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match &self.backend {
            FileBackend::Console(_) => true,
            FileBackend::Pty(endpoint) => endpoint.side() == PtySide::Slave,
            FileBackend::Vfs(_)
            | FileBackend::Pipe(_)
            | FileBackend::Channel(_)
            | FileBackend::SharedMemory(_) => false,
        }
    }

    #[must_use]
    pub fn pipe_direction(&self) -> Option<PipeDirection> {
        match &self.backend {
            FileBackend::Pipe(endpoint) => Some(endpoint.direction()),
            FileBackend::Vfs(_)
            | FileBackend::Console(_)
            | FileBackend::Pty(_)
            | FileBackend::Channel(_)
            | FileBackend::SharedMemory(_) => None,
        }
    }

    /// Devpts number exposed by `TIOCGPTN` on a PTY master.
    #[must_use]
    pub fn pty_number(&self) -> Option<usize> {
        match &self.backend {
            FileBackend::Pty(endpoint) if endpoint.side() == PtySide::Master => {
                Some(endpoint.number())
            },
            FileBackend::Vfs(_)
            | FileBackend::Console(_)
            | FileBackend::Pipe(_)
            | FileBackend::Pty(_)
            | FileBackend::Channel(_)
            | FileBackend::SharedMemory(_) => None,
        }
    }

    #[must_use]
    pub fn terminal_attributes(&self) -> Option<xenith_abi::TerminalAttributes> {
        match &self.backend {
            FileBackend::Console(_) => Some(crate::tty::attributes()),
            FileBackend::Pty(endpoint) => endpoint.attributes(),
            FileBackend::Vfs(_)
            | FileBackend::Pipe(_)
            | FileBackend::Channel(_)
            | FileBackend::SharedMemory(_) => None,
        }
    }

    pub fn set_terminal_attributes(
        &self,
        attributes: xenith_abi::TerminalAttributes,
        flush: bool,
    ) -> bool {
        match &self.backend {
            FileBackend::Console(_) => {
                crate::tty::set_attributes(attributes, flush);
                true
            },
            FileBackend::Pty(endpoint) => endpoint.set_attributes(attributes, flush),
            FileBackend::Vfs(_)
            | FileBackend::Pipe(_)
            | FileBackend::Channel(_)
            | FileBackend::SharedMemory(_) => false,
        }
    }

    #[must_use]
    pub fn terminal_window_size(&self) -> Option<xenith_abi::WindowSize> {
        match &self.backend {
            FileBackend::Console(_) => Some(crate::tty::window_size()),
            FileBackend::Pty(endpoint) => endpoint.window_size(),
            FileBackend::Vfs(_)
            | FileBackend::Pipe(_)
            | FileBackend::Channel(_)
            | FileBackend::SharedMemory(_) => None,
        }
    }

    pub fn set_terminal_window_size(&self, window_size: xenith_abi::WindowSize) -> bool {
        match &self.backend {
            FileBackend::Console(_) => {
                crate::tty::set_window_size(window_size);
                true
            },
            FileBackend::Pty(endpoint) => endpoint.set_window_size(window_size),
            FileBackend::Vfs(_)
            | FileBackend::Pipe(_)
            | FileBackend::Channel(_)
            | FileBackend::SharedMemory(_) => false,
        }
    }

    #[must_use]
    pub fn terminal_pending_input(&self) -> Option<usize> {
        match &self.backend {
            FileBackend::Console(_) => Some(crate::tty::pending_input()),
            FileBackend::Pty(endpoint) if endpoint.side() == PtySide::Slave => {
                Some(endpoint.pending_input())
            },
            FileBackend::Vfs(_)
            | FileBackend::Pipe(_)
            | FileBackend::Pty(_)
            | FileBackend::Channel(_)
            | FileBackend::SharedMemory(_) => None,
        }
    }

    #[must_use]
    pub fn terminal_foreground_group(&self) -> Option<u64> {
        match &self.backend {
            FileBackend::Console(_) => Some(crate::tty::foreground_group()),
            FileBackend::Pty(endpoint) => endpoint.foreground_group(),
            FileBackend::Vfs(_)
            | FileBackend::Pipe(_)
            | FileBackend::Channel(_)
            | FileBackend::SharedMemory(_) => None,
        }
    }

    pub fn set_terminal_foreground_group(&self, process_group: u64) -> bool {
        match &self.backend {
            FileBackend::Console(_) => {
                crate::tty::set_foreground_group(process_group);
                true
            },
            FileBackend::Pty(endpoint) => endpoint.set_foreground_group(process_group),
            FileBackend::Vfs(_)
            | FileBackend::Pipe(_)
            | FileBackend::Channel(_)
            | FileBackend::SharedMemory(_) => false,
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, FsError> {
        if !self.flags.can_read() {
            return Err(FsError::BadFileDescriptor);
        }
        match &self.backend {
            FileBackend::Vfs(node) => {
                if node.metadata().kind == FileType::Directory {
                    return Err(FsError::IsDirectory);
                }
                let mut offset = self.offset.lock();
                let read = node.read_at(*offset, buf)?;
                *offset = offset.checked_add(read as u64).ok_or(FsError::Overflow)?;
                Ok(read)
            },
            FileBackend::Console(ConsoleStream::Stdin) => loop {
                match crate::tty::read(buf) {
                    Ok(read) => break Ok(read),
                    Err(
                        signal @ (crate::user::signal::Signal::Tstp
                        | crate::user::signal::Signal::Ttin
                        | crate::user::signal::Signal::Ttou),
                    ) => {
                        crate::tty::signal_foreground(signal);
                        crate::user::process::enforce_current_state();
                    },
                    Err(signal) => {
                        crate::tty::signal_foreground(signal);
                        break Err(FsError::Interrupted);
                    },
                }
            },
            FileBackend::Console(ConsoleStream::Stdout | ConsoleStream::Stderr) => {
                Err(FsError::BadFileDescriptor)
            },
            FileBackend::Pipe(endpoint) => {
                endpoint.read(buf, self.flags.contains(OpenFlags::NONBLOCK))
            },
            FileBackend::Pty(endpoint) => {
                if endpoint.side() == PtySide::Slave {
                    wait_for_foreground(|| endpoint.foreground_group())?;
                }
                endpoint.read(buf, self.flags.contains(OpenFlags::NONBLOCK))
            },
            FileBackend::Channel(_) | FileBackend::SharedMemory(_) => Err(FsError::Unsupported),
        }
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, FsError> {
        if !self.flags.can_write() {
            return Err(FsError::BadFileDescriptor);
        }
        match &self.backend {
            FileBackend::Vfs(node) => {
                if node.metadata().kind == FileType::Directory {
                    return Err(FsError::IsDirectory);
                }
                let mut offset = self.offset.lock();
                if self.flags.contains(OpenFlags::APPEND) {
                    *offset = node.metadata().size;
                }
                let written = node.write_at(*offset, buf)?;
                *offset = offset
                    .checked_add(written as u64)
                    .ok_or(FsError::Overflow)?;
                Ok(written)
            },
            FileBackend::Console(ConsoleStream::Stdout | ConsoleStream::Stderr) => {
                Ok(crate::tty::write_output(buf))
            },
            FileBackend::Console(ConsoleStream::Stdin) => Err(FsError::BadFileDescriptor),
            FileBackend::Pipe(endpoint) => {
                endpoint.write(buf, self.flags.contains(OpenFlags::NONBLOCK))
            },
            FileBackend::Pty(endpoint) => {
                endpoint.write(buf, self.flags.contains(OpenFlags::NONBLOCK))
            },
            FileBackend::Channel(_) | FileBackend::SharedMemory(_) => Err(FsError::Unsupported),
        }
    }

    pub fn seek(&self, displacement: i64, whence: SeekWhence) -> Result<u64, FsError> {
        let FileBackend::Vfs(node) = &self.backend else {
            return Err(FsError::NotSeekable);
        };
        let mut offset = self.offset.lock();
        let base = match whence {
            SeekWhence::Start => 0,
            SeekWhence::Current => *offset,
            SeekWhence::End => node.metadata().size,
        };
        let next = if displacement < 0 {
            base.checked_sub(displacement.unsigned_abs())
        } else {
            base.checked_add(displacement as u64)
        }
        .ok_or(FsError::InvalidInput)?;
        *offset = next;
        Ok(next)
    }
}

fn wait_for_foreground(mut foreground: impl FnMut() -> Option<u64>) -> Result<(), FsError> {
    loop {
        let process_group = crate::user::process::current_process_group();
        let foreground_group = foreground().unwrap_or(0);
        if process_group.is_kernel()
            || foreground_group == 0
            || foreground_group == process_group.as_u64()
        {
            return Ok(());
        }
        let _ =
            crate::user::process::signal_group(process_group, crate::user::signal::Signal::Ttin);
        if !crate::user::process::current_is_stopped() {
            return Err(FsError::Interrupted);
        }
        crate::user::process::enforce_current_state();
    }
}

impl fmt::Debug for FileObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match &self.backend {
            FileBackend::Vfs(_) => "vfs",
            FileBackend::Console(_) => "terminal",
            FileBackend::Pipe(_) => "pipe",
            FileBackend::Pty(endpoint) => match endpoint.side() {
                PtySide::Master => "pty-master",
                PtySide::Slave => "pty-slave",
            },
            FileBackend::Channel(_) => "channel",
            FileBackend::SharedMemory(_) => "shared-memory",
        };
        f.debug_struct("FileObject")
            .field("kind", &kind)
            .field("offset", &self.offset())
            .field("flags", &self.flags)
            .finish()
    }
}

pub const MAX_FDS: usize = 256;

#[derive(Clone)]
struct FdEntry {
    file: FileRef,
    close_on_exec: bool,
    rights: u32,
}

impl FdEntry {
    fn from_file(file: FileRef) -> Self {
        let rights = file.initial_descriptor_rights();
        let close_on_exec = file.flags().contains(OpenFlags::CLOSE_ON_EXEC);
        Self {
            file,
            close_on_exec,
            rights,
        }
    }
}

fn valid_descriptor_rights(rights: u32) -> bool {
    rights != 0 && rights & !IPC_TRANSFER_RIGHTS_ALL == 0
}

/// Metadata and rollback authority for one atomic received-transfer install.
///
/// This type is intentionally neither `Copy` nor `Clone`: passing it to
/// rollback consumes the sole authority to remove the newly installed FDs.
#[derive(Debug)]
#[must_use]
pub struct InstalledTransferBatch {
    records: [IpcReceiveTransfer; CHANNEL_TRANSFER_CAPACITY],
    count: usize,
}

impl InstalledTransferBatch {
    fn new() -> Self {
        Self {
            records: [IpcReceiveTransfer {
                installed_fd: 0,
                rights: 0,
                tag: 0,
            }; CHANNEL_TRANSFER_CAPACITY],
            count: 0,
        }
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    #[must_use]
    pub const fn records(&self) -> &[IpcReceiveTransfer; CHANNEL_TRANSFER_CAPACITY] {
        &self.records
    }
}

/// Fixed-capacity carrier for file references removed under an outer lock.
///
/// `Option<Arc<_>>` uses the pointer niche on supported targets, so this is
/// approximately 2 KiB at `MAX_FDS == 256`. Keeping it inline makes process
/// exit and exec descriptor retirement allocation-free. Dropping the batch
/// after releasing `PROCESS_TABLE` performs any final backend destruction.
#[must_use = "drop retired files only after releasing outer ownership locks"]
pub struct RetiredFiles {
    files: [Option<FileRef>; MAX_FDS],
    len: usize,
}

impl RetiredFiles {
    pub const fn new() -> Self {
        Self {
            files: [const { None }; MAX_FDS],
            len: 0,
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn try_push(&mut self, entry: FdEntry) -> Result<(), FdEntry> {
        let Some(slot) = self.files.get_mut(self.len) else {
            return Err(entry);
        };
        *slot = Some(entry.file);
        self.len += 1;
        Ok(())
    }
}

impl Default for RetiredFiles {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FdTable {
    slots: Vec<Option<FdEntry>>,
    first_dynamic: usize,
}

impl Clone for FdTable {
    fn clone(&self) -> Self {
        Self {
            slots: self.slots.clone(),
            first_dynamic: self.first_dynamic,
        }
    }
}

impl FdTable {
    pub fn new() -> Self {
        Self {
            slots: alloc::vec![None; MAX_FDS],
            first_dynamic: 0,
        }
    }

    /// Create a process table with real terminal-backed standard descriptors.
    pub fn new_process() -> Self {
        let mut table = Self::new();
        table.slots[0] = Some(FdEntry::from_file(Arc::new(FileObject::new_console(
            ConsoleStream::Stdin,
        ))));
        table.slots[1] = Some(FdEntry::from_file(Arc::new(FileObject::new_console(
            ConsoleStream::Stdout,
        ))));
        table.slots[2] = Some(FdEntry::from_file(Arc::new(FileObject::new_console(
            ConsoleStream::Stderr,
        ))));
        table
    }

    pub fn alloc_fd(&mut self, file: FileRef) -> Result<i32, FsError> {
        self.alloc_fd_from(file, self.first_dynamic)
    }

    pub fn alloc_fd_from(&mut self, file: FileRef, minimum: usize) -> Result<i32, FsError> {
        let start = minimum.max(self.first_dynamic);
        for index in start..MAX_FDS {
            if self.slots[index].is_none() {
                self.slots[index] = Some(FdEntry::from_file(file));
                return Ok(index as i32);
            }
        }
        Err(FsError::TooManyOpenFiles)
    }

    pub fn get(&self, fd: i32) -> Result<FileRef, FsError> {
        let index = usize::try_from(fd).map_err(|_| FsError::BadFileDescriptor)?;
        self.slots
            .get(index)
            .and_then(Option::as_ref)
            .map(|entry| Arc::clone(&entry.file))
            .ok_or(FsError::BadFileDescriptor)
    }

    pub fn get_with_rights(&self, fd: i32, required: u32) -> Result<FileRef, FsError> {
        if !valid_descriptor_rights(required) {
            return Err(FsError::InvalidInput);
        }
        let index = usize::try_from(fd).map_err(|_| FsError::BadFileDescriptor)?;
        let entry = self
            .slots
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(FsError::BadFileDescriptor)?;
        if entry.rights & required != required {
            return Err(FsError::PermissionDenied);
        }
        Ok(Arc::clone(&entry.file))
    }

    pub fn get_with_any_right(&self, fd: i32, accepted: u32) -> Result<FileRef, FsError> {
        if !valid_descriptor_rights(accepted) {
            return Err(FsError::InvalidInput);
        }
        let index = usize::try_from(fd).map_err(|_| FsError::BadFileDescriptor)?;
        let entry = self
            .slots
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(FsError::BadFileDescriptor)?;
        if entry.rights & accepted == 0 {
            return Err(FsError::PermissionDenied);
        }
        Ok(Arc::clone(&entry.file))
    }

    pub fn rights(&self, fd: i32) -> Result<u32, FsError> {
        let index = usize::try_from(fd).map_err(|_| FsError::BadFileDescriptor)?;
        self.slots
            .get(index)
            .and_then(Option::as_ref)
            .map(|entry| entry.rights)
            .ok_or(FsError::BadFileDescriptor)
    }

    /// Remove a descriptor without dropping its open-file reference.
    ///
    /// Callers that hold an outer ownership lock (notably `PROCESS_TABLE`)
    /// must release that lock before dropping the returned reference. Backend
    /// destruction may wake blocked readers or writers.
    #[must_use = "drop the removed file only after releasing outer ownership locks"]
    pub fn close(&mut self, fd: i32) -> Result<FileRef, FsError> {
        let index = usize::try_from(fd).map_err(|_| FsError::BadFileDescriptor)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(FsError::BadFileDescriptor)?;
        slot.take()
            .map(|entry| entry.file)
            .ok_or(FsError::BadFileDescriptor)
    }

    pub fn dup(&mut self, fd: i32) -> Result<i32, FsError> {
        let source = usize::try_from(fd).map_err(|_| FsError::BadFileDescriptor)?;
        let source = self
            .slots
            .get(source)
            .and_then(Option::as_ref)
            .ok_or(FsError::BadFileDescriptor)?;
        let file = Arc::clone(&source.file);
        let rights = source.rights;
        let target = self
            .slots
            .iter()
            .enumerate()
            .skip(self.first_dynamic)
            .find_map(|(index, slot)| slot.is_none().then_some(index))
            .ok_or(FsError::TooManyOpenFiles)?;
        self.slots[target] = Some(FdEntry {
            file,
            close_on_exec: false,
            rights,
        });
        Ok(target as i32)
    }

    /// Duplicate `old_fd` onto `new_fd`, returning any displaced reference.
    ///
    /// The displaced file must be dropped after releasing outer ownership
    /// locks for the same reason as [`Self::close`].
    #[must_use = "drop the displaced file only after releasing outer ownership locks"]
    pub fn dup2(&mut self, old_fd: i32, new_fd: i32) -> Result<(i32, Option<FileRef>), FsError> {
        let source = usize::try_from(old_fd).map_err(|_| FsError::BadFileDescriptor)?;
        let source = self
            .slots
            .get(source)
            .and_then(Option::as_ref)
            .ok_or(FsError::BadFileDescriptor)?;
        let file = Arc::clone(&source.file);
        let rights = source.rights;
        let target = usize::try_from(new_fd).map_err(|_| FsError::BadFileDescriptor)?;
        if target >= MAX_FDS {
            return Err(FsError::BadFileDescriptor);
        }
        if old_fd == new_fd {
            return Ok((new_fd, None));
        }
        let displaced = self
            .slots
            .get_mut(target)
            .ok_or(FsError::BadFileDescriptor)?
            .replace(FdEntry {
                file,
                close_on_exec: false,
                rights,
            });
        Ok((new_fd, displaced.map(|entry| entry.file)))
    }

    /// Build an empty child table populated only by an explicit attenuated
    /// source-to-target mapping set.
    ///
    /// The complete fixed batch is validated before the first `FileRef` is
    /// cloned or the child table is changed. Ordinary descriptors require the
    /// source's `TRANSFER` right. A channel endpoint is the sole exception:
    /// restricted spawn may hand that non-transferable endpoint directly to
    /// its immediate child, but can grant only a nonempty subset of the
    /// source's existing read/write rights.
    pub fn clone_restricted(
        &self,
        actions: &[SpawnFileAction; SPAWN_RESTRICTED_MAX_FILE_ACTIONS],
        count: usize,
    ) -> Result<Self, FsError> {
        if count > SPAWN_RESTRICTED_MAX_FILE_ACTIONS
            || actions[..count].iter().any(|action| !action.is_valid())
            || actions[count..].iter().any(|action| !action.is_zero())
        {
            return Err(FsError::InvalidInput);
        }

        let mut sources = [0usize; SPAWN_RESTRICTED_MAX_FILE_ACTIONS];
        let mut targets = [0usize; SPAWN_RESTRICTED_MAX_FILE_ACTIONS];
        for (index, action) in actions[..count].iter().enumerate() {
            let source =
                usize::try_from(action.source_fd).map_err(|_| FsError::BadFileDescriptor)?;
            let target =
                usize::try_from(action.target_fd).map_err(|_| FsError::BadFileDescriptor)?;
            if target >= MAX_FDS || targets[..index].contains(&target) {
                return Err(if target >= MAX_FDS {
                    FsError::BadFileDescriptor
                } else {
                    FsError::InvalidInput
                });
            }
            let entry = self
                .slots
                .get(source)
                .and_then(Option::as_ref)
                .ok_or(FsError::BadFileDescriptor)?;
            if action.rights & !entry.rights != 0
                || (entry.rights & IPC_TRANSFER_RIGHT_TRANSFER == 0
                    && entry.file.channel_endpoint().is_none())
            {
                return Err(FsError::PermissionDenied);
            }
            sources[index] = source;
            targets[index] = target;
        }

        let mut child = Self::new();
        for index in 0..count {
            // Every index and source slot was validated above while `self` is
            // immutably borrowed, so neither can change in this phase.
            let entry = self.slots[sources[index]]
                .as_ref()
                .expect("validated restricted-spawn source disappeared");
            child.slots[targets[index]] = Some(FdEntry {
                file: Arc::clone(&entry.file),
                close_on_exec: false,
                rights: actions[index].rights,
            });
        }
        Ok(child)
    }

    /// Atomically reserve two descriptors, used by `pipe(2)` so callers never
    /// observe a half-created pipe when the table has only one free slot.
    pub fn alloc_pair(&mut self, first: FileRef, second: FileRef) -> Result<(i32, i32), FsError> {
        let mut free = self
            .slots
            .iter()
            .enumerate()
            .skip(self.first_dynamic)
            .filter_map(|(index, slot)| slot.is_none().then_some(index));
        let first_fd = free.next().ok_or(FsError::TooManyOpenFiles)?;
        let second_fd = free.next().ok_or(FsError::TooManyOpenFiles)?;
        self.slots[first_fd] = Some(FdEntry::from_file(first));
        self.slots[second_fd] = Some(FdEntry::from_file(second));
        Ok((first_fd as i32, second_fd as i32))
    }

    /// Snapshot a canonical fixed transfer request without consuming FDs.
    ///
    /// Validation completes before any `FileRef` is cloned. Every source must
    /// carry `TRANSFER`, and requested rights may only attenuate its current
    /// descriptor rights.
    pub fn snapshot_channel_transfers(
        &self,
        requests: &[IpcSendTransfer; CHANNEL_TRANSFER_CAPACITY],
        count: usize,
    ) -> Result<ChannelTransfers, FsError> {
        if count > CHANNEL_TRANSFER_CAPACITY
            || requests[..count].iter().any(|request| !request.is_valid())
            || requests[count..].iter().any(|request| !request.is_zero())
        {
            return Err(FsError::InvalidInput);
        }

        let mut source_indices = [0usize; CHANNEL_TRANSFER_CAPACITY];
        for (index, request) in requests[..count].iter().enumerate() {
            let source =
                usize::try_from(request.source_fd).map_err(|_| FsError::BadFileDescriptor)?;
            let entry = self
                .slots
                .get(source)
                .and_then(Option::as_ref)
                .ok_or(FsError::BadFileDescriptor)?;
            if entry.rights & IPC_TRANSFER_RIGHT_TRANSFER == 0
                || request.rights & !entry.rights != 0
            {
                return Err(FsError::PermissionDenied);
            }
            source_indices[index] = source;
        }

        let mut transfers: ChannelTransfers = array::from_fn(|_| None);
        for index in 0..count {
            let Some(entry) = self.slots[source_indices[index]].as_ref() else {
                return Err(FsError::Corrupt);
            };
            let request = requests[index];
            transfers[index] = Some(ChannelTransfer {
                file: Arc::clone(&entry.file),
                rights: request.rights,
                tag: request.tag,
            });
        }
        Ok(transfers)
    }

    /// Atomically install a canonical fixed transfer batch.
    ///
    /// All rights and descriptor capacity are validated before the first slot
    /// is changed, so every error leaves the table untouched.
    pub fn install_channel_transfers(
        &mut self,
        transfers: &ChannelTransfers,
    ) -> Result<InstalledTransferBatch, FsError> {
        let mut count = 0usize;
        let mut saw_empty = false;
        for transfer in transfers {
            match transfer {
                Some(transfer) if saw_empty => return Err(FsError::InvalidInput),
                Some(transfer) => {
                    if !valid_descriptor_rights(transfer.rights)
                        || transfer.rights & !transfer.file.initial_descriptor_rights() != 0
                    {
                        return Err(FsError::PermissionDenied);
                    }
                    count += 1;
                },
                None => saw_empty = true,
            }
        }

        let mut free = [0usize; CHANNEL_TRANSFER_CAPACITY];
        let mut free_count = 0usize;
        for (index, slot) in self.slots.iter().enumerate().skip(self.first_dynamic) {
            if slot.is_none() && free_count < count {
                free[free_count] = index;
                free_count += 1;
            }
        }
        if free_count != count {
            return Err(FsError::TooManyOpenFiles);
        }

        let mut installed = InstalledTransferBatch::new();
        for (index, transfer) in transfers[..count].iter().flatten().enumerate() {
            let fd = free[index];
            self.slots[fd] = Some(FdEntry {
                file: Arc::clone(&transfer.file),
                close_on_exec: false,
                rights: transfer.rights,
            });
            installed.records[index] = IpcReceiveTransfer {
                installed_fd: fd as i32,
                rights: transfer.rights,
                tag: transfer.tag,
            };
            installed.count += 1;
        }
        Ok(installed)
    }

    /// Remove a previously installed transfer batch without dropping files.
    #[must_use = "drop rolled-back files only after releasing outer ownership locks"]
    pub fn rollback_channel_transfers(
        &mut self,
        installed: InstalledTransferBatch,
    ) -> RetiredFiles {
        let mut retired = RetiredFiles::new();
        for record in &installed.records[..installed.count] {
            let Ok(index) = usize::try_from(record.installed_fd) else {
                continue;
            };
            let Some(slot) = self.slots.get_mut(index) else {
                continue;
            };
            let Some(entry) = slot.take() else {
                continue;
            };
            if let Err(entry) = retired.try_push(entry) {
                *slot = Some(entry);
                break;
            }
        }
        retired
    }

    /// Remove every descriptor and return the references for deferred drop.
    #[must_use = "drop removed files only after releasing outer ownership locks"]
    pub fn close_all(&mut self) -> RetiredFiles {
        let mut removed = RetiredFiles::new();
        for slot in &mut self.slots {
            let Some(entry) = slot.take() else {
                continue;
            };
            if let Err(entry) = removed.try_push(entry) {
                // Capacity equals the descriptor-table bound, but restore the
                // entry rather than dropping or panicking if that invariant
                // is ever violated.
                *slot = Some(entry);
                break;
            }
        }
        removed
    }

    /// Close descriptors whose open description carries `CLOSE_ON_EXEC`.
    /// Xenith currently stores this bit on the shared open description; the
    /// operation still provides the required exec boundary for every file
    /// opened through the present VFS API.
    #[must_use = "drop removed files only after releasing outer ownership locks"]
    pub fn close_on_exec(&mut self) -> RetiredFiles {
        let mut removed = RetiredFiles::new();
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|entry| entry.close_on_exec) {
                let Some(entry) = slot.take() else {
                    continue;
                };
                if let Err(entry) = removed.try_push(entry) {
                    *slot = Some(entry);
                    break;
                }
            }
        }
        removed
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FdTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let open = self.slots.iter().filter(|slot| slot.is_some()).count();
        f.debug_struct("FdTable")
            .field("open", &open)
            .field("capacity", &MAX_FDS)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::ramfs::RamFs;
    use super::*;

    fn spawn_actions() -> [SpawnFileAction; SPAWN_RESTRICTED_MAX_FILE_ACTIONS] {
        [SpawnFileAction::default(); SPAWN_RESTRICTED_MAX_FILE_ACTIONS]
    }

    #[test]
    fn duplicated_descriptors_share_the_open_offset() {
        let fs = RamFs::new();
        let node = fs.write_file("/data", b"abcdef", 0o644).unwrap();
        let file = Arc::new(FileObject::new(node, OpenFlags::READ_ONLY));
        let mut table = FdTable::new();
        let first = table.alloc_fd(Arc::clone(&file)).unwrap();
        let second = table.dup(first).unwrap();
        let mut bytes = [0u8; 2];
        assert_eq!(table.get(first).unwrap().read(&mut bytes).unwrap(), 2);
        assert_eq!(&bytes, b"ab");
        assert_eq!(table.get(second).unwrap().read(&mut bytes).unwrap(), 2);
        assert_eq!(&bytes, b"cd");
    }

    #[test]
    fn descriptor_rights_are_minimal_and_checked_per_entry() {
        let fs = RamFs::new();
        let mut table = FdTable::new();
        let read_only = Arc::new(FileObject::new(
            fs.write_file("/rights-ro", b"r", 0o644).unwrap(),
            OpenFlags::READ_ONLY,
        ));
        let write_only = Arc::new(FileObject::new(
            fs.write_file("/rights-wo", b"w", 0o644).unwrap(),
            OpenFlags::WRITE_ONLY,
        ));
        let read_write = Arc::new(FileObject::new(
            fs.write_file("/rights-rw", b"rw", 0o644).unwrap(),
            OpenFlags::READ_WRITE,
        ));
        let read_fd = table.alloc_fd(read_only).unwrap();
        let write_fd = table.alloc_fd(write_only).unwrap();
        let both_fd = table.alloc_fd(read_write).unwrap();

        assert_eq!(
            table.rights(read_fd).unwrap(),
            IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_TRANSFER
        );
        assert_eq!(
            table.rights(write_fd).unwrap(),
            IPC_TRANSFER_RIGHT_WRITE | IPC_TRANSFER_RIGHT_TRANSFER
        );
        assert_eq!(
            table.rights(both_fd).unwrap(),
            IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_WRITE | IPC_TRANSFER_RIGHT_TRANSFER
        );
        assert!(table
            .get_with_rights(read_fd, IPC_TRANSFER_RIGHT_READ)
            .is_ok());
        assert_eq!(
            table
                .get_with_rights(read_fd, IPC_TRANSFER_RIGHT_WRITE)
                .unwrap_err(),
            FsError::PermissionDenied
        );
        assert_eq!(
            table.get_with_rights(read_fd, 0).unwrap_err(),
            FsError::InvalidInput
        );
        assert_eq!(
            table.get_with_rights(read_fd, 1 << 31).unwrap_err(),
            FsError::InvalidInput
        );
        assert!(table
            .get_with_any_right(read_fd, IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_WRITE)
            .is_ok());
        assert_eq!(
            table
                .get_with_any_right(read_fd, IPC_TRANSFER_RIGHT_WRITE)
                .unwrap_err(),
            FsError::PermissionDenied
        );
    }

    #[test]
    fn terminal_control_lookup_accepts_read_only_standard_input() {
        let table = FdTable::new_process();
        let either_data_right = IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_WRITE;

        assert_eq!(
            table.rights(0).unwrap(),
            IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_TRANSFER
        );
        assert!(table.get_with_any_right(0, either_data_right).is_ok());
        assert_eq!(
            table
                .get_with_rights(0, IPC_TRANSFER_RIGHT_WRITE)
                .unwrap_err(),
            FsError::PermissionDenied
        );
    }

    #[test]
    fn channel_descriptors_are_read_write_but_never_transferable() {
        let (endpoint, peer) = crate::ipc::channel::create().unwrap();
        let channel = Arc::new(FileObject::new_channel(endpoint));
        let mut table = FdTable::new();
        let fd = table.alloc_fd(Arc::clone(&channel)).unwrap();

        assert!(channel.channel_endpoint().is_some());
        assert!(channel.shared_memory().is_none());
        assert_eq!(CHANNEL_DESCRIPTOR_RIGHTS, 3);
        assert_eq!(table.rights(fd).unwrap(), CHANNEL_DESCRIPTOR_RIGHTS);
        assert!(table
            .get_with_rights(fd, IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_WRITE)
            .is_ok());
        assert_eq!(
            table
                .get_with_rights(fd, IPC_TRANSFER_RIGHT_TRANSFER)
                .unwrap_err(),
            FsError::PermissionDenied
        );

        let mut requests = [IpcSendTransfer::default(); CHANNEL_TRANSFER_CAPACITY];
        requests[0] = IpcSendTransfer {
            source_fd: fd,
            rights: IPC_TRANSFER_RIGHT_READ,
            tag: 7,
        };
        assert_eq!(
            table.snapshot_channel_transfers(&requests, 1).unwrap_err(),
            FsError::PermissionDenied
        );
        drop(peer);
    }

    #[test]
    fn transfer_snapshot_is_canonical_and_strictly_attenuating() {
        let fs = RamFs::new();
        let file = Arc::new(FileObject::new(
            fs.write_file("/snapshot", b"payload", 0o644).unwrap(),
            OpenFlags::READ_WRITE,
        ));
        let mut table = FdTable::new();
        let fd = table.alloc_fd(Arc::clone(&file)).unwrap();
        let mut requests = [IpcSendTransfer::default(); CHANNEL_TRANSFER_CAPACITY];
        requests[0] = IpcSendTransfer {
            source_fd: fd,
            rights: IPC_TRANSFER_RIGHT_READ,
            tag: 0xA1,
        };
        requests[1] = IpcSendTransfer {
            source_fd: fd,
            rights: IPC_TRANSFER_RIGHT_WRITE | IPC_TRANSFER_RIGHT_TRANSFER,
            tag: 0xB2,
        };

        let transfers = table.snapshot_channel_transfers(&requests, 2).unwrap();
        let first = transfers[0].as_ref().unwrap();
        let second = transfers[1].as_ref().unwrap();
        assert!(Arc::ptr_eq(&first.file, &file));
        assert!(Arc::ptr_eq(&second.file, &file));
        assert_eq!((first.rights, first.tag), (IPC_TRANSFER_RIGHT_READ, 0xA1));
        assert_eq!(
            (second.rights, second.tag),
            (IPC_TRANSFER_RIGHT_WRITE | IPC_TRANSFER_RIGHT_TRANSFER, 0xB2)
        );
        assert!(transfers[2..].iter().all(Option::is_none));

        requests[0].rights = IPC_TRANSFER_RIGHT_MAP;
        requests[1] = IpcSendTransfer::default();
        assert_eq!(
            table.snapshot_channel_transfers(&requests, 1).unwrap_err(),
            FsError::PermissionDenied
        );
        requests[0].rights = 1 << 31;
        assert_eq!(
            table.snapshot_channel_transfers(&requests, 1).unwrap_err(),
            FsError::InvalidInput
        );
        requests[0] = IpcSendTransfer::default();
        requests[1] = IpcSendTransfer {
            source_fd: fd,
            rights: IPC_TRANSFER_RIGHT_READ,
            tag: 1,
        };
        assert_eq!(
            table.snapshot_channel_transfers(&requests, 0).unwrap_err(),
            FsError::InvalidInput
        );
        assert_eq!(
            table
                .snapshot_channel_transfers(&requests, CHANNEL_TRANSFER_CAPACITY + 1)
                .unwrap_err(),
            FsError::InvalidInput
        );
    }

    #[test]
    fn attenuated_rights_survive_dup_dup2_and_fork_clone() {
        let fs = RamFs::new();
        let source = Arc::new(FileObject::new(
            fs.write_file("/attenuated", b"data", 0o644).unwrap(),
            OpenFlags::READ_WRITE,
        ));
        let displaced = Arc::new(FileObject::new_console(ConsoleStream::Stdout));
        let mut transfers: ChannelTransfers = array::from_fn(|_| None);
        transfers[0] = Some(ChannelTransfer {
            file: source,
            rights: IPC_TRANSFER_RIGHT_READ,
            tag: 9,
        });
        let mut table = FdTable::new();
        let installed = table.install_channel_transfers(&transfers).unwrap();
        let installed_fd = installed.records()[0].installed_fd;
        let duplicate = table.dup(installed_fd).unwrap();
        let target = table.alloc_fd(displaced).unwrap();
        let (_, retired) = table.dup2(installed_fd, target).unwrap();
        drop(retired);
        let child = table.clone();

        for fd in [installed_fd, duplicate, target] {
            assert_eq!(table.rights(fd).unwrap(), IPC_TRANSFER_RIGHT_READ);
            assert_eq!(
                table
                    .get_with_rights(fd, IPC_TRANSFER_RIGHT_WRITE)
                    .unwrap_err(),
                FsError::PermissionDenied
            );
            assert_eq!(child.rights(fd).unwrap(), IPC_TRANSFER_RIGHT_READ);
        }
    }

    #[test]
    fn restricted_clone_installs_only_exact_attenuated_targets() {
        let fs = RamFs::new();
        let file = Arc::new(FileObject::new(
            fs.write_file("/restricted", b"data", 0o644).unwrap(),
            OpenFlags::READ_WRITE,
        ));
        let mut parent = FdTable::new_process();
        let source = parent.alloc_fd(Arc::clone(&file)).unwrap();
        let mut actions = spawn_actions();
        actions[0] = SpawnFileAction {
            source_fd: source,
            target_fd: 9,
            rights: IPC_TRANSFER_RIGHT_READ,
            flags: 0,
        };

        let child = parent.clone_restricted(&actions, 1).unwrap();
        assert_eq!(child.rights(9), Ok(IPC_TRANSFER_RIGHT_READ));
        assert!(Arc::ptr_eq(&child.get(9).unwrap(), &file));
        assert_eq!(child.get(0).unwrap_err(), FsError::BadFileDescriptor);
        assert_eq!(child.get(source).unwrap_err(), FsError::BadFileDescriptor);
        assert_eq!(
            child
                .get_with_rights(9, IPC_TRANSFER_RIGHT_WRITE)
                .unwrap_err(),
            FsError::PermissionDenied
        );
        assert!(parent.get(source).is_ok());
    }

    #[test]
    fn restricted_clone_validation_is_atomic_and_rejects_escalation() {
        let fs = RamFs::new();
        let file = Arc::new(FileObject::new(
            fs.write_file("/restricted-invalid", b"x", 0o644).unwrap(),
            OpenFlags::READ_ONLY,
        ));
        let mut parent = FdTable::new();
        let source = parent.alloc_fd(Arc::clone(&file)).unwrap();
        let baseline_refs = Arc::strong_count(&file);
        let mut actions = spawn_actions();
        actions[0] = SpawnFileAction {
            source_fd: source,
            target_fd: 3,
            rights: IPC_TRANSFER_RIGHT_READ,
            flags: 0,
        };
        actions[1] = SpawnFileAction {
            source_fd: source,
            target_fd: 3,
            rights: IPC_TRANSFER_RIGHT_READ,
            flags: 0,
        };
        assert!(matches!(
            parent.clone_restricted(&actions, 2),
            Err(FsError::InvalidInput)
        ));
        assert_eq!(Arc::strong_count(&file), baseline_refs);

        actions[1] = SpawnFileAction::default();
        actions[0].rights = IPC_TRANSFER_RIGHT_WRITE;
        assert!(matches!(
            parent.clone_restricted(&actions, 1),
            Err(FsError::PermissionDenied)
        ));
        assert_eq!(Arc::strong_count(&file), baseline_refs);

        actions[0].rights = IPC_TRANSFER_RIGHT_READ;
        actions[0].source_fd = MAX_FDS as i32;
        assert!(matches!(
            parent.clone_restricted(&actions, 1),
            Err(FsError::BadFileDescriptor)
        ));
        assert_eq!(Arc::strong_count(&file), baseline_refs);

        actions[0].source_fd = source;
        actions[0].flags = 1;
        assert!(matches!(
            parent.clone_restricted(&actions, 1),
            Err(FsError::InvalidInput)
        ));
        assert_eq!(Arc::strong_count(&file), baseline_refs);

        actions[0].flags = 0;
        actions[0].target_fd = MAX_FDS as i32;
        assert!(matches!(
            parent.clone_restricted(&actions, 1),
            Err(FsError::BadFileDescriptor)
        ));
        actions[0].target_fd = 3;
        actions[0].rights = 0;
        assert!(matches!(
            parent.clone_restricted(&actions, 1),
            Err(FsError::InvalidInput)
        ));
        actions[0].rights = 1 << 31;
        assert!(matches!(
            parent.clone_restricted(&actions, 1),
            Err(FsError::InvalidInput)
        ));
        assert_eq!(Arc::strong_count(&file), baseline_refs);

        actions[0] = SpawnFileAction::default();
        actions[1] = SpawnFileAction {
            source_fd: source,
            target_fd: 4,
            rights: IPC_TRANSFER_RIGHT_READ,
            flags: 0,
        };
        assert!(matches!(
            parent.clone_restricted(&actions, 0),
            Err(FsError::InvalidInput)
        ));
        assert!(matches!(
            parent.clone_restricted(&actions, SPAWN_RESTRICTED_MAX_FILE_ACTIONS + 1),
            Err(FsError::InvalidInput)
        ));
        assert_eq!(Arc::strong_count(&file), baseline_refs);
    }

    #[test]
    fn restricted_clone_requires_transfer_for_non_channel_sources() {
        let fs = RamFs::new();
        let file = Arc::new(FileObject::new(
            fs.write_file("/restricted-no-transfer", b"x", 0o644)
                .unwrap(),
            OpenFlags::READ_ONLY,
        ));
        let mut transfers: ChannelTransfers = array::from_fn(|_| None);
        transfers[0] = Some(ChannelTransfer {
            file,
            rights: IPC_TRANSFER_RIGHT_READ,
            tag: 0,
        });
        let mut parent = FdTable::new();
        let installed = parent.install_channel_transfers(&transfers).unwrap();
        let source = installed.records()[0].installed_fd;
        let mut actions = spawn_actions();
        actions[0] = SpawnFileAction {
            source_fd: source,
            target_fd: 5,
            rights: IPC_TRANSFER_RIGHT_READ,
            flags: 0,
        };

        assert!(matches!(
            parent.clone_restricted(&actions, 1),
            Err(FsError::PermissionDenied)
        ));
        assert_eq!(parent.rights(source), Ok(IPC_TRANSFER_RIGHT_READ));
    }

    #[test]
    fn restricted_clone_accepts_the_exact_sixteen_action_bound() {
        let fs = RamFs::new();
        let file = Arc::new(FileObject::new(
            fs.write_file("/restricted-bound", b"x", 0o644).unwrap(),
            OpenFlags::READ_ONLY,
        ));
        let mut parent = FdTable::new();
        let source = parent.alloc_fd(file).unwrap();
        let mut actions = spawn_actions();
        for (target, action) in actions.iter_mut().enumerate() {
            *action = SpawnFileAction {
                source_fd: source,
                target_fd: target as i32,
                rights: IPC_TRANSFER_RIGHT_READ,
                flags: 0,
            };
        }

        let child = parent
            .clone_restricted(&actions, SPAWN_RESTRICTED_MAX_FILE_ACTIONS)
            .unwrap();
        for target in 0..SPAWN_RESTRICTED_MAX_FILE_ACTIONS {
            assert_eq!(child.rights(target as i32), Ok(IPC_TRANSFER_RIGHT_READ));
        }
    }

    #[test]
    fn restricted_clone_allows_direct_nontransfer_channel_inheritance() {
        let (endpoint, peer) = crate::ipc::channel::create().unwrap();
        let channel = Arc::new(FileObject::new_channel(endpoint));
        let mut parent = FdTable::new();
        let source = parent.alloc_fd(Arc::clone(&channel)).unwrap();
        assert_eq!(parent.rights(source).unwrap(), CHANNEL_DESCRIPTOR_RIGHTS);

        let mut actions = spawn_actions();
        actions[0] = SpawnFileAction {
            source_fd: source,
            target_fd: 6,
            rights: IPC_TRANSFER_RIGHT_WRITE,
            flags: 0,
        };
        let child = parent.clone_restricted(&actions, 1).unwrap();
        assert_eq!(child.rights(6), Ok(IPC_TRANSFER_RIGHT_WRITE));
        assert_eq!(
            child
                .get_with_rights(6, IPC_TRANSFER_RIGHT_TRANSFER)
                .unwrap_err(),
            FsError::PermissionDenied
        );
        drop(peer);
    }

    #[test]
    fn received_transfer_install_is_atomic_when_capacity_is_short() {
        let filler = Arc::new(FileObject::new_console(ConsoleStream::Stdout));
        let mut table = FdTable::new();
        for _ in 0..MAX_FDS - 1 {
            table.alloc_fd(Arc::clone(&filler)).unwrap();
        }
        let mut transfers: ChannelTransfers = array::from_fn(|_| None);
        for (index, slot) in transfers.iter_mut().take(2).enumerate() {
            *slot = Some(ChannelTransfer {
                file: Arc::clone(&filler),
                rights: IPC_TRANSFER_RIGHT_WRITE,
                tag: index as u64,
            });
        }
        let before = table.slots.iter().filter(|slot| slot.is_some()).count();

        assert!(matches!(
            table.install_channel_transfers(&transfers),
            Err(FsError::TooManyOpenFiles)
        ));
        assert_eq!(
            table.slots.iter().filter(|slot| slot.is_some()).count(),
            before
        );
        assert!(table.slots[MAX_FDS - 1].is_none());
    }

    #[test]
    fn received_transfer_install_rejects_noncanonical_or_excess_rights_atomically() {
        let filler = Arc::new(FileObject::new_console(ConsoleStream::Stdout));
        let mut table = FdTable::new();
        let mut transfers: ChannelTransfers = array::from_fn(|_| None);
        transfers[1] = Some(ChannelTransfer {
            file: Arc::clone(&filler),
            rights: IPC_TRANSFER_RIGHT_WRITE,
            tag: 1,
        });

        assert_eq!(
            table.install_channel_transfers(&transfers).unwrap_err(),
            FsError::InvalidInput
        );
        assert!(table.slots.iter().all(Option::is_none));

        transfers[0] = transfers[1].take();
        transfers[0].as_mut().unwrap().rights = IPC_TRANSFER_RIGHT_READ;
        assert_eq!(
            table.install_channel_transfers(&transfers).unwrap_err(),
            FsError::PermissionDenied
        );
        assert!(table.slots.iter().all(Option::is_none));
    }

    #[test]
    fn received_transfer_metadata_and_rollback_are_transactional() {
        assert!(core::mem::size_of::<InstalledTransferBatch>() <= 80);
        assert_eq!(SHARED_MEMORY_DESCRIPTOR_RIGHTS, IPC_TRANSFER_RIGHTS_ALL);
        let fs = RamFs::new();
        let file = Arc::new(FileObject::new(
            fs.write_file("/rollback-transfer", b"x", 0o644).unwrap(),
            OpenFlags::READ_WRITE,
        ));
        let weak = Arc::downgrade(&file);
        let mut transfers: ChannelTransfers = array::from_fn(|_| None);
        transfers[0] = Some(ChannelTransfer {
            file,
            rights: IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_TRANSFER,
            tag: 0xFEED,
        });
        let mut table = FdTable::new();
        let installed = table.install_channel_transfers(&transfers).unwrap();
        assert_eq!(installed.count(), 1);
        let record = installed.records()[0];
        assert_eq!(record, IpcReceiveTransfer {
            installed_fd: 0,
            rights: IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_TRANSFER,
            tag: 0xFEED,
        });
        assert!(installed.records()[1..]
            .iter()
            .all(IpcReceiveTransfer::is_zero));
        assert_eq!(table.rights(record.installed_fd).unwrap(), record.rights);
        drop(transfers);

        let retired = table.rollback_channel_transfers(installed);
        assert_eq!(
            table.get(record.installed_fd).unwrap_err(),
            FsError::BadFileDescriptor
        );
        assert!(weak.upgrade().is_some());
        drop(retired);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn channel_pair_install_reserves_both_slots_before_publication() {
        let filler = Arc::new(FileObject::new_console(ConsoleStream::Stdout));
        let mut full = FdTable::new();
        for _ in 0..MAX_FDS - 1 {
            full.alloc_fd(Arc::clone(&filler)).unwrap();
        }
        let (first_endpoint, second_endpoint) = crate::ipc::channel::create().unwrap();
        let first = Arc::new(FileObject::new_channel(first_endpoint));
        let second = Arc::new(FileObject::new_channel(second_endpoint));
        let before = full.slots.iter().filter(|slot| slot.is_some()).count();
        assert_eq!(
            full.alloc_pair(Arc::clone(&first), Arc::clone(&second))
                .unwrap_err(),
            FsError::TooManyOpenFiles
        );
        assert_eq!(
            full.slots.iter().filter(|slot| slot.is_some()).count(),
            before
        );

        let mut available = FdTable::new();
        let (first_fd, second_fd) = available.alloc_pair(first, second).unwrap();
        assert_ne!(first_fd, second_fd);
        assert_eq!(
            available.rights(first_fd).unwrap(),
            CHANNEL_DESCRIPTOR_RIGHTS
        );
        assert_eq!(
            available.rights(second_fd).unwrap(),
            CHANNEL_DESCRIPTOR_RIGHTS
        );
    }

    #[test]
    fn close_returns_last_reference_for_deferred_backend_drop() {
        let (reader, writer) = crate::fs::pipe::create();
        let reader = FileObject::new_pipe(reader, OpenFlags::READ_ONLY | OpenFlags::NONBLOCK);
        let mut table = FdTable::new();
        let writer_fd = table
            .alloc_fd(Arc::new(FileObject::new_pipe(
                writer,
                OpenFlags::WRITE_ONLY,
            )))
            .unwrap();

        let removed = table.close(writer_fd).unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(reader.read(&mut byte), Err(FsError::WouldBlock));
        drop(removed);
        assert_eq!(reader.read(&mut byte), Ok(0));
    }

    #[test]
    fn dup2_returns_the_displaced_reference_for_deferred_drop() {
        let fs = RamFs::new();
        let source = Arc::new(FileObject::new(
            fs.write_file("/source", b"source", 0o644).unwrap(),
            OpenFlags::READ_ONLY,
        ));
        let displaced = Arc::new(FileObject::new(
            fs.write_file("/displaced", b"target", 0o644).unwrap(),
            OpenFlags::READ_ONLY,
        ));
        let displaced_weak = Arc::downgrade(&displaced);
        let mut table = FdTable::new();
        let source_fd = table.alloc_fd(Arc::clone(&source)).unwrap();
        let target_fd = table.alloc_fd(displaced).unwrap();

        let (result, retired) = table.dup2(source_fd, target_fd).unwrap();
        assert_eq!(result, target_fd);
        assert!(Arc::ptr_eq(&table.get(target_fd).unwrap(), &source));
        assert!(displaced_weak.upgrade().is_some());
        drop(retired);
        assert!(displaced_weak.upgrade().is_none());
    }

    #[test]
    fn bulk_close_operations_return_every_removed_reference() {
        let fs = RamFs::new();
        let plain = Arc::new(FileObject::new(
            fs.write_file("/plain-bulk", b"x", 0o644).unwrap(),
            OpenFlags::READ_ONLY,
        ));
        let cloexec = Arc::new(FileObject::new(
            fs.write_file("/cloexec-bulk", b"y", 0o644).unwrap(),
            OpenFlags::READ_ONLY | OpenFlags::CLOSE_ON_EXEC,
        ));
        let plain_weak = Arc::downgrade(&plain);
        let cloexec_weak = Arc::downgrade(&cloexec);
        let mut table = FdTable::new();
        let plain_fd = table.alloc_fd(plain).unwrap();
        let cloexec_fd = table.alloc_fd(cloexec).unwrap();

        let exec_removed = table.close_on_exec();
        assert_eq!(exec_removed.len(), 1);
        assert!(table.get(plain_fd).is_ok());
        assert_eq!(
            table.get(cloexec_fd).unwrap_err(),
            FsError::BadFileDescriptor
        );
        assert!(cloexec_weak.upgrade().is_some());
        drop(exec_removed);
        assert!(cloexec_weak.upgrade().is_none());

        let all_removed = table.close_all();
        assert_eq!(all_removed.len(), 1);
        assert_eq!(table.get(plain_fd).unwrap_err(), FsError::BadFileDescriptor);
        assert!(plain_weak.upgrade().is_some());
        drop(all_removed);
        assert!(plain_weak.upgrade().is_none());
    }

    #[test]
    fn retired_file_batch_covers_the_full_descriptor_bound_inline() {
        assert!(core::mem::size_of::<RetiredFiles>() <= 3 * 1024);
        let file = Arc::new(FileObject::new_console(ConsoleStream::Stdout));
        let file_weak = Arc::downgrade(&file);
        let mut table = FdTable::new();
        for _ in 0..MAX_FDS {
            table.alloc_fd(Arc::clone(&file)).unwrap();
        }
        drop(file);

        let retired = table.close_all();
        assert_eq!(retired.len(), MAX_FDS);
        assert!(file_weak.upgrade().is_some());
        drop(retired);
        assert!(file_weak.upgrade().is_none());
    }

    #[test]
    fn fork_clone_shares_files_and_exec_closes_marked_descriptors() {
        let fs = RamFs::new();
        let plain = Arc::new(FileObject::new(
            fs.write_file("/plain", b"x", 0o644).unwrap(),
            OpenFlags::READ_ONLY,
        ));
        let cloexec = Arc::new(FileObject::new(
            fs.write_file("/secret", b"y", 0o644).unwrap(),
            OpenFlags::READ_ONLY | OpenFlags::CLOSE_ON_EXEC,
        ));
        let mut parent = FdTable::new();
        let plain_fd = parent.alloc_fd(plain).unwrap();
        let cloexec_fd = parent.alloc_fd(cloexec).unwrap();
        let mut child = parent.clone();
        let duplicated = child.dup(cloexec_fd).unwrap();
        assert!(child.get(plain_fd).is_ok());
        assert!(child.get(cloexec_fd).is_ok());
        drop(child.close_on_exec());
        assert!(child.get(plain_fd).is_ok());
        // POSIX dup clears FD_CLOEXEC on the new descriptor.
        assert!(child.get(duplicated).is_ok());
        assert_eq!(
            child.get(cloexec_fd).unwrap_err(),
            FsError::BadFileDescriptor
        );
        assert!(parent.get(cloexec_fd).is_ok());
    }

    #[test]
    fn process_table_has_real_stdio_and_reuses_a_closed_standard_slot() {
        let mut table = FdTable::new_process();
        assert!(table.get(0).unwrap().is_terminal());
        assert!(table.get(1).unwrap().is_terminal());
        assert!(table.get(2).unwrap().is_terminal());
        table.close(1).unwrap();
        let replacement = Arc::new(FileObject::new_console(ConsoleStream::Stdout));
        assert_eq!(table.alloc_fd(replacement).unwrap(), 1);
    }

    #[test]
    fn cloned_tables_keep_pipe_endpoints_alive_until_the_last_close() {
        let (reader, writer) = crate::fs::pipe::create();
        let reader = Arc::new(FileObject::new_pipe(reader, OpenFlags::READ_ONLY));
        let writer = Arc::new(FileObject::new_pipe(writer, OpenFlags::WRITE_ONLY));
        let mut parent = FdTable::new_process();
        let (read_fd, write_fd) = parent.alloc_pair(reader, writer).unwrap();
        let mut child = parent.clone();

        parent.close(write_fd).unwrap();
        child.close(write_fd).unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(parent.get(read_fd).unwrap().read(&mut byte).unwrap(), 0);

        parent.close(read_fd).unwrap();
        child.close(read_fd).unwrap();
    }

    #[test]
    fn cloned_tables_keep_pty_sides_alive_until_the_last_close() {
        let (master, slave) = crate::fs::pty::create().unwrap();
        let number = master.number();
        let master = Arc::new(FileObject::new_pty(master, OpenFlags::READ_WRITE));
        let slave = Arc::new(FileObject::new_pty(slave, OpenFlags::READ_WRITE));
        assert_eq!(master.pty_number(), Some(number));
        assert_eq!(slave.pty_number(), None);
        assert_eq!(
            master.node().unwrap().metadata().kind,
            FileType::CharacterDevice
        );
        let mut parent = FdTable::new();
        let (master_fd, slave_fd) = parent.alloc_pair(master, slave).unwrap();
        let mut child = parent.clone();

        parent.close(slave_fd).unwrap();
        assert_eq!(parent.get(master_fd).unwrap().write(b"x\n").unwrap(), 2);
        let mut bytes = [0u8; 2];
        assert_eq!(child.get(slave_fd).unwrap().read(&mut bytes).unwrap(), 2);
        assert_eq!(bytes, *b"x\n");

        child.close(slave_fd).unwrap();
        assert_eq!(
            parent.get(master_fd).unwrap().write(b"x"),
            Err(FsError::BrokenPipe)
        );
        parent.close(master_fd).unwrap();
        child.close(master_fd).unwrap();
    }
}
