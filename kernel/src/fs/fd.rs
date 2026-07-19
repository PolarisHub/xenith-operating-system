//! Open-file descriptions and per-process descriptor tables.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use xenith_bitflags::bitflags;

use super::inode::FileType;
use super::pipe::{PipeDirection, PipeEndpoint};
use super::pty::{PtyEndpoint, PtySide};
use super::vfs::{FsError, NodeRef};
use crate::sync::SpinLock;

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

    pub fn node(&self) -> Result<NodeRef, FsError> {
        match &self.backend {
            FileBackend::Vfs(node) => Ok(Arc::clone(node)),
            FileBackend::Pty(endpoint) => Ok(endpoint.node()),
            FileBackend::Console(_) | FileBackend::Pipe(_) => Err(FsError::InvalidInput),
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
            FileBackend::Vfs(_) | FileBackend::Pipe(_) => false,
        }
    }

    #[must_use]
    pub fn pipe_direction(&self) -> Option<PipeDirection> {
        match &self.backend {
            FileBackend::Pipe(endpoint) => Some(endpoint.direction()),
            FileBackend::Vfs(_) | FileBackend::Console(_) | FileBackend::Pty(_) => None,
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
            | FileBackend::Pty(_) => None,
        }
    }

    #[must_use]
    pub fn terminal_attributes(&self) -> Option<xenith_abi::TerminalAttributes> {
        match &self.backend {
            FileBackend::Console(_) => Some(crate::tty::attributes()),
            FileBackend::Pty(endpoint) => endpoint.attributes(),
            FileBackend::Vfs(_) | FileBackend::Pipe(_) => None,
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
            FileBackend::Vfs(_) | FileBackend::Pipe(_) => false,
        }
    }

    #[must_use]
    pub fn terminal_window_size(&self) -> Option<xenith_abi::WindowSize> {
        match &self.backend {
            FileBackend::Console(_) => Some(crate::tty::window_size()),
            FileBackend::Pty(endpoint) => endpoint.window_size(),
            FileBackend::Vfs(_) | FileBackend::Pipe(_) => None,
        }
    }

    pub fn set_terminal_window_size(&self, window_size: xenith_abi::WindowSize) -> bool {
        match &self.backend {
            FileBackend::Console(_) => {
                crate::tty::set_window_size(window_size);
                true
            },
            FileBackend::Pty(endpoint) => endpoint.set_window_size(window_size),
            FileBackend::Vfs(_) | FileBackend::Pipe(_) => false,
        }
    }

    #[must_use]
    pub fn terminal_pending_input(&self) -> Option<usize> {
        match &self.backend {
            FileBackend::Console(_) => Some(crate::tty::pending_input()),
            FileBackend::Pty(endpoint) if endpoint.side() == PtySide::Slave => {
                Some(endpoint.pending_input())
            },
            FileBackend::Vfs(_) | FileBackend::Pipe(_) | FileBackend::Pty(_) => None,
        }
    }

    #[must_use]
    pub fn terminal_foreground_group(&self) -> Option<u64> {
        match &self.backend {
            FileBackend::Console(_) => Some(crate::tty::foreground_group()),
            FileBackend::Pty(endpoint) => endpoint.foreground_group(),
            FileBackend::Vfs(_) | FileBackend::Pipe(_) => None,
        }
    }

    pub fn set_terminal_foreground_group(&self, process_group: u64) -> bool {
        match &self.backend {
            FileBackend::Console(_) => {
                crate::tty::set_foreground_group(process_group);
                true
            },
            FileBackend::Pty(endpoint) => endpoint.set_foreground_group(process_group),
            FileBackend::Vfs(_) | FileBackend::Pipe(_) => false,
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
        table.slots[0] = Some(FdEntry {
            file: Arc::new(FileObject::new_console(ConsoleStream::Stdin)),
            close_on_exec: false,
        });
        table.slots[1] = Some(FdEntry {
            file: Arc::new(FileObject::new_console(ConsoleStream::Stdout)),
            close_on_exec: false,
        });
        table.slots[2] = Some(FdEntry {
            file: Arc::new(FileObject::new_console(ConsoleStream::Stderr)),
            close_on_exec: false,
        });
        table
    }

    pub fn alloc_fd(&mut self, file: FileRef) -> Result<i32, FsError> {
        self.alloc_fd_from(file, self.first_dynamic)
    }

    pub fn alloc_fd_from(&mut self, file: FileRef, minimum: usize) -> Result<i32, FsError> {
        let start = minimum.max(self.first_dynamic);
        for index in start..MAX_FDS {
            if self.slots[index].is_none() {
                let close_on_exec = file.flags().contains(OpenFlags::CLOSE_ON_EXEC);
                self.slots[index] = Some(FdEntry {
                    file,
                    close_on_exec,
                });
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

    pub fn close(&mut self, fd: i32) -> Result<(), FsError> {
        let index = usize::try_from(fd).map_err(|_| FsError::BadFileDescriptor)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(FsError::BadFileDescriptor)?;
        if slot.take().is_none() {
            return Err(FsError::BadFileDescriptor);
        }
        Ok(())
    }

    pub fn dup(&mut self, fd: i32) -> Result<i32, FsError> {
        let file = self.get(fd)?;
        let target = self.alloc_fd(file)?;
        self.slots[target as usize]
            .as_mut()
            .expect("allocated descriptor disappeared")
            .close_on_exec = false;
        Ok(target)
    }

    pub fn dup2(&mut self, old_fd: i32, new_fd: i32) -> Result<i32, FsError> {
        let file = self.get(old_fd)?;
        let target = usize::try_from(new_fd).map_err(|_| FsError::BadFileDescriptor)?;
        if target >= MAX_FDS {
            return Err(FsError::BadFileDescriptor);
        }
        if old_fd == new_fd {
            return Ok(new_fd);
        }
        self.slots[target] = Some(FdEntry {
            file,
            close_on_exec: false,
        });
        Ok(new_fd)
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
        self.slots[first_fd] = Some(FdEntry {
            close_on_exec: first.flags().contains(OpenFlags::CLOSE_ON_EXEC),
            file: first,
        });
        self.slots[second_fd] = Some(FdEntry {
            close_on_exec: second.flags().contains(OpenFlags::CLOSE_ON_EXEC),
            file: second,
        });
        Ok((first_fd as i32, second_fd as i32))
    }

    pub fn close_all(&mut self) {
        for slot in &mut self.slots {
            *slot = None;
        }
    }

    /// Close descriptors whose open description carries `CLOSE_ON_EXEC`.
    /// Xenith currently stores this bit on the shared open description; the
    /// operation still provides the required exec boundary for every file
    /// opened through the present VFS API.
    pub fn close_on_exec(&mut self) {
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|entry| entry.close_on_exec) {
                *slot = None;
            }
        }
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
        child.close_on_exec();
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
