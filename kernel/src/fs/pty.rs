//! Bounded pseudo-terminal pairs and the synthetic `/dev/pts` filesystem.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use xenith_abi::{TerminalAttributes, WindowSize, ONLCR, OPOST};

use super::inode::{
    allocate_inode_id, DirEntry, FileType, Inode, InodeId, InodeMetadata, InodeOps,
};
use super::vfs::{FileSystem, FsError, NodeRef, VfsNode};
use crate::sync::SpinLock;
use crate::tty::{LineDiscipline, RawReadTimer};
use crate::user::signal::Signal;

/// Maximum simultaneously named PTY pairs.  Descriptor limits independently
/// bound the number of open descriptions; this cap bounds `/dev/pts` metadata.
pub const MAX_PTYS: usize = 64;

struct PtyState {
    line: LineDiscipline,
    master_refs: usize,
    slave_refs: usize,
}

impl PtyState {
    const fn new() -> Self {
        Self {
            line: LineDiscipline::new(),
            master_refs: 1,
            slave_refs: 1,
        }
    }
}

struct RegistryEntry {
    state: Weak<SpinLock<PtyState>>,
    inode: InodeId,
}

static REGISTRY: SpinLock<Vec<Option<RegistryEntry>>> = SpinLock::new(Vec::new());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PtySide {
    Master,
    Slave,
}

/// One shared open description for a PTY side.  `dup` and `fork` share the
/// enclosing `Arc<FileObject>`.  Named slave opens create additional endpoint
/// references, so a side is closed only after its last open description dies.
pub struct PtyEndpoint {
    state: Arc<SpinLock<PtyState>>,
    side: PtySide,
    number: usize,
    inode: InodeId,
}

impl PtyEndpoint {
    fn new(state: Arc<SpinLock<PtyState>>, side: PtySide, number: usize, inode: InodeId) -> Self {
        Self {
            state,
            side,
            number,
            inode,
        }
    }

    fn reopen_slave(
        state: Arc<SpinLock<PtyState>>,
        number: usize,
        inode: InodeId,
    ) -> Result<Self, FsError> {
        {
            let mut shared = state.lock();
            if shared.master_refs == 0 {
                return Err(FsError::NotFound);
            }
            shared.slave_refs = shared
                .slave_refs
                .checked_add(1)
                .ok_or(FsError::TooManyOpenFiles)?;
        }
        Ok(Self::new(state, PtySide::Slave, number, inode))
    }

    #[must_use]
    pub const fn side(&self) -> PtySide {
        self.side
    }

    #[must_use]
    pub const fn number(&self) -> usize {
        self.number
    }

    #[must_use]
    pub fn path(&self) -> String {
        alloc::format!("/dev/pts/{}", self.number)
    }

    pub fn node(&self) -> NodeRef {
        Arc::new(DevPtsSlaveNode::new(
            self.number,
            self.inode,
            Arc::downgrade(&self.state),
        ))
    }

    pub fn read(&self, destination: &mut [u8], nonblocking: bool) -> Result<usize, FsError> {
        if destination.is_empty() {
            return Ok(0);
        }
        let mut timer = RawReadTimer::default();
        loop {
            let mut state = self.state.lock();
            match self.side {
                PtySide::Master => {
                    let read = state.line.drain_output(destination);
                    if read != 0 {
                        return Ok(read);
                    }
                    if state.slave_refs == 0 {
                        return Ok(0);
                    }
                },
                PtySide::Slave => {
                    match state.line.read_once(
                        destination,
                        nonblocking,
                        crate::time::uptime_ns(),
                        &mut timer,
                    ) {
                        Ok(Some(read)) => return Ok(read),
                        Err(_) => return Err(FsError::Interrupted),
                        Ok(None) => {},
                    }
                    if state.master_refs == 0 {
                        return Ok(0);
                    }
                },
            }
            if nonblocking {
                return Err(FsError::WouldBlock);
            }
            drop(state);
            crate::sched::yield_now();
        }
    }

    pub fn write(&self, source: &[u8], nonblocking: bool) -> Result<usize, FsError> {
        if source.is_empty() {
            return Ok(0);
        }
        match self.side {
            PtySide::Master => self.write_master(source),
            PtySide::Slave => self.write_slave(source, nonblocking),
        }
    }

    fn write_master(&self, source: &[u8]) -> Result<usize, FsError> {
        let mut written = 0usize;
        for &byte in source {
            let (signal, foreground_group) = {
                let mut state = self.state.lock();
                if state.slave_refs == 0 {
                    return if written == 0 {
                        Err(FsError::BrokenPipe)
                    } else {
                        Ok(written)
                    };
                }
                let signal = state.line.feed_input_byte(byte);
                (signal, state.line.foreground_group())
            };
            if let Some(signal) = signal {
                signal_group(foreground_group, signal);
            }
            written += 1;
        }
        Ok(written)
    }

    fn write_slave(&self, source: &[u8], nonblocking: bool) -> Result<usize, FsError> {
        let mut written = 0usize;
        while written < source.len() {
            let mut state = self.state.lock();
            if state.master_refs == 0 {
                return if written == 0 {
                    Err(FsError::BrokenPipe)
                } else {
                    Ok(written)
                };
            }
            let attributes = state.line.attributes();
            let byte = source[written];
            let translate_newline =
                attributes.output_flags & (OPOST | ONLCR) == (OPOST | ONLCR) && byte == b'\n';
            let needed = if translate_newline { 2 } else { 1 };
            if state.line.output_available() < needed {
                if nonblocking {
                    return if written == 0 {
                        Err(FsError::WouldBlock)
                    } else {
                        Ok(written)
                    };
                }
                drop(state);
                crate::sched::yield_now();
                continue;
            }
            if translate_newline {
                let _ = state.line.push_output(b'\r');
            }
            let _ = state.line.push_output(byte);
            written += 1;
        }
        Ok(written)
    }

    #[must_use]
    pub fn attributes(&self) -> Option<TerminalAttributes> {
        (self.side == PtySide::Slave).then(|| self.state.lock().line.attributes())
    }

    pub fn set_attributes(&self, attributes: TerminalAttributes, flush: bool) -> bool {
        if self.side != PtySide::Slave {
            return false;
        }
        self.state.lock().line.set_attributes(attributes, flush);
        true
    }

    #[must_use]
    pub fn window_size(&self) -> Option<WindowSize> {
        (self.side == PtySide::Slave).then(|| self.state.lock().line.window_size())
    }

    pub fn set_window_size(&self, window_size: WindowSize) -> bool {
        if self.side != PtySide::Slave {
            return false;
        }
        self.state.lock().line.set_window_size(window_size);
        true
    }

    #[must_use]
    pub fn pending_input(&self) -> usize {
        let state = self.state.lock();
        match self.side {
            PtySide::Master => state.line.output_pending(),
            PtySide::Slave => state.line.pending_input(),
        }
    }

    #[must_use]
    pub fn foreground_group(&self) -> Option<u64> {
        (self.side == PtySide::Slave).then(|| self.state.lock().line.foreground_group())
    }

    pub fn set_foreground_group(&self, process_group: u64) -> bool {
        if self.side != PtySide::Slave {
            return false;
        }
        self.state.lock().line.set_foreground_group(process_group);
        true
    }
}

impl Drop for PtyEndpoint {
    fn drop(&mut self) {
        let release_name = {
            let mut state = self.state.lock();
            match self.side {
                PtySide::Master => {
                    state.master_refs = state.master_refs.saturating_sub(1);
                    state.master_refs == 0
                },
                PtySide::Slave => {
                    state.slave_refs = state.slave_refs.saturating_sub(1);
                    false
                },
            }
        };
        if release_name {
            release_number(self.number, &self.state);
        }
    }
}

fn signal_group(foreground_group: u64, signal: Signal) {
    if foreground_group != 0 {
        let _ =
            crate::user::process::signal_group(crate::user::ProcessId(foreground_group), signal);
    }
}

fn register(state: &Arc<SpinLock<PtyState>>) -> Result<(usize, InodeId), FsError> {
    let mut registry = REGISTRY.lock();
    for entry in registry.iter_mut() {
        if entry
            .as_ref()
            .is_some_and(|entry| entry.state.strong_count() == 0)
        {
            *entry = None;
        }
    }
    let number = if let Some(index) = registry.iter().position(Option::is_none) {
        index
    } else if registry.len() < MAX_PTYS {
        registry.push(None);
        registry.len() - 1
    } else {
        return Err(FsError::NoSpace);
    };
    let inode = allocate_inode_id();
    registry[number] = Some(RegistryEntry {
        state: Arc::downgrade(state),
        inode,
    });
    Ok((number, inode))
}

fn release_number(number: usize, state: &Arc<SpinLock<PtyState>>) {
    let mut registry = REGISTRY.lock();
    let Some(slot) = registry.get_mut(number) else {
        return;
    };
    if slot.as_ref().is_some_and(|entry| {
        entry
            .state
            .upgrade()
            .is_some_and(|registered| Arc::ptr_eq(&registered, state))
    }) {
        *slot = None;
    }
}

fn lookup_entry(number: usize) -> Result<(Arc<SpinLock<PtyState>>, InodeId), FsError> {
    let mut registry = REGISTRY.lock();
    let Some(slot) = registry.get_mut(number) else {
        return Err(FsError::NotFound);
    };
    let Some(entry) = slot else {
        return Err(FsError::NotFound);
    };
    let Some(state) = entry.state.upgrade() else {
        *slot = None;
        return Err(FsError::NotFound);
    };
    Ok((state, entry.inode))
}

fn parse_number(name: &str) -> Result<usize, FsError> {
    if name.is_empty() || name.len() > 1 && name.starts_with('0') {
        return Err(FsError::NotFound);
    }
    let number = name.parse::<usize>().map_err(|_| FsError::NotFound)?;
    if number >= MAX_PTYS {
        return Err(FsError::NotFound);
    }
    Ok(number)
}

/// Create one named PTY pair, returned in master/slave order.  The descriptor
/// ABI remains identical to anonymous `openpty`; its slave is additionally
/// reachable at `/dev/pts/<number>` until the last master closes.
pub fn create() -> Result<(PtyEndpoint, PtyEndpoint), FsError> {
    let state = Arc::new(SpinLock::new(PtyState::new()));
    let (number, inode) = register(&state)?;
    Ok((
        PtyEndpoint::new(Arc::clone(&state), PtySide::Master, number, inode),
        PtyEndpoint::new(state, PtySide::Slave, number, inode),
    ))
}

struct DevPtsRoot {
    inode: Inode,
}

impl DevPtsRoot {
    fn new() -> Self {
        Self {
            inode: Inode::new(InodeMetadata::new(
                allocate_inode_id(),
                FileType::Directory,
                0o555,
            )),
        }
    }
}

impl VfsNode for DevPtsRoot {
    fn inode(&self) -> &Inode {
        &self.inode
    }
}

impl InodeOps for DevPtsRoot {
    fn lookup(&self, name: &str) -> Result<NodeRef, FsError> {
        let number = parse_number(name)?;
        let (state, inode) = lookup_entry(number)?;
        Ok(Arc::new(DevPtsSlaveNode::new(
            number,
            inode,
            Arc::downgrade(&state),
        )))
    }

    fn read_dir(&self) -> Result<Vec<DirEntry>, FsError> {
        let mut registry = REGISTRY.lock();
        let mut entries = Vec::new();
        entries
            .try_reserve(registry.len().min(MAX_PTYS))
            .map_err(|_| FsError::NoSpace)?;
        for (number, slot) in registry.iter_mut().enumerate() {
            let Some(entry) = slot else {
                continue;
            };
            if entry.state.strong_count() == 0 {
                *slot = None;
                continue;
            }
            entries.push(DirEntry {
                name: number.to_string(),
                inode: entry.inode,
                kind: FileType::CharacterDevice,
            });
        }
        Ok(entries)
    }
}

struct DevPtsSlaveNode {
    inode: Inode,
    number: usize,
    state: Weak<SpinLock<PtyState>>,
}

impl DevPtsSlaveNode {
    fn new(number: usize, inode: InodeId, state: Weak<SpinLock<PtyState>>) -> Self {
        Self {
            inode: Inode::new(InodeMetadata::new(inode, FileType::CharacterDevice, 0o620)),
            number,
            state,
        }
    }
}

impl VfsNode for DevPtsSlaveNode {
    fn inode(&self) -> &Inode {
        &self.inode
    }

    fn open_pty(&self) -> Result<Option<PtyEndpoint>, FsError> {
        let state = self.state.upgrade().ok_or(FsError::NotFound)?;
        PtyEndpoint::reopen_slave(state, self.number, self.inode.id()).map(Some)
    }
}

impl InodeOps for DevPtsSlaveNode {}

pub struct DevPtsFs {
    root: Arc<DevPtsRoot>,
}

impl DevPtsFs {
    pub fn new() -> Self {
        Self {
            root: Arc::new(DevPtsRoot::new()),
        }
    }
}

impl Default for DevPtsFs {
    fn default() -> Self {
        Self::new()
    }
}

impl FileSystem for DevPtsFs {
    fn name(&self) -> &'static str {
        "devpts"
    }

    fn root(&self) -> NodeRef {
        self.root.clone()
    }

    fn is_read_only(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use xenith_abi::{ICANON, VMIN, VTIME};

    use super::*;

    #[test]
    fn canonical_editing_echo_and_output_cross_the_pair() {
        let (master, slave) = create().unwrap();
        assert_eq!(master.write(b"ab\x7fc\n", false).unwrap(), 5);
        let mut input = [0u8; 8];
        assert_eq!(slave.read(&mut input, false).unwrap(), 3);
        assert_eq!(&input[..3], b"ac\n");

        let mut echo = [0u8; 32];
        let echoed = master.read(&mut echo, false).unwrap();
        assert!(echoed >= 5);

        assert_eq!(slave.write(b"output\n", false).unwrap(), 7);
        let read = master.read(&mut echo, false).unwrap();
        assert_eq!(&echo[..read], b"output\r\n");
    }

    #[test]
    fn raw_vmin_and_nonblocking_semantics_share_the_console_discipline() {
        let (master, slave) = create().unwrap();
        let mut attributes = slave.attributes().unwrap();
        attributes.local_flags &= !ICANON;
        attributes.control_characters[VMIN] = 2;
        attributes.control_characters[VTIME] = 0;
        assert!(slave.set_attributes(attributes, true));

        master.write(b"x", false).unwrap();
        let mut input = [0u8; 4];
        assert_eq!(slave.read(&mut input, true).unwrap(), 1);
        assert_eq!(input[0], b'x');
        assert_eq!(slave.read(&mut input, true), Err(FsError::WouldBlock));

        master.write(b"yz", false).unwrap();
        assert_eq!(slave.read(&mut input, false).unwrap(), 2);
        assert_eq!(&input[..2], b"yz");
    }

    #[test]
    fn devpts_names_reopen_slave_and_disappear_with_master() {
        let filesystem = DevPtsFs::new();
        let root = filesystem.root();
        let (master, slave) = create().unwrap();
        let number = master.number();
        assert_eq!(master.path(), alloc::format!("/dev/pts/{number}"));
        assert!(root
            .read_dir()
            .unwrap()
            .iter()
            .any(|entry| entry.name == number.to_string()));

        let node = root.lookup(&number.to_string()).unwrap();
        let reopened = node.open_pty().unwrap().unwrap();
        master.write(b"line\n", false).unwrap();
        let mut input = [0u8; 8];
        assert_eq!(reopened.read(&mut input, false).unwrap(), 5);
        assert_eq!(&input[..5], b"line\n");

        drop(master);
        assert!(matches!(
            root.lookup(&number.to_string()),
            Err(FsError::NotFound)
        ));
        drop(reopened);
        drop(slave);
    }

    #[test]
    fn control_char_interrupts_slave_input() {
        let (master, slave) = create().unwrap();
        let interrupt = slave.attributes().unwrap().control_characters[xenith_abi::VINTR];
        master.write(&[interrupt], false).unwrap();
        let mut input = [0u8; 1];
        assert_eq!(slave.read(&mut input, false), Err(FsError::Interrupted));
    }

    #[test]
    fn close_and_nonblocking_semantics_are_bounded() {
        let (master, slave) = create().unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(master.read(&mut byte, true), Err(FsError::WouldBlock));
        drop(slave);
        assert_eq!(master.read(&mut byte, false).unwrap(), 0);
        assert_eq!(master.write(b"x", false), Err(FsError::BrokenPipe));
    }
}
