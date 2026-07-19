//! XenithFS: extent-based writable filesystem with a bounded redo journal.

#![allow(clippy::module_inception)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::devices::ahci::BlockDevice;
use crate::fs::inode::{cache_insert, DirEntry, FileType, Inode, InodeId, InodeMetadata, InodeOps};
use crate::fs::path::validate_name;
use crate::fs::vfs::{FileSystem, FsError, NodeRef, VfsNode};
use crate::sync::SpinLock;

pub mod dir;
pub mod extent;
pub mod inode;
pub mod journal;
pub mod sb;

use dir::{encode_directory, parse_directory, DirectoryRecord, MAX_DIRECTORY_SIZE};
use extent::mapped_block;
pub use extent::Extent;
use inode::{DiskInode, INLINE_SYMLINK_BYTES, INODE_SIZE, MAX_EXTENTS};
use journal::{JournalDescriptor, JournalHeader};
use sb::crc32;
pub use sb::{Superblock, SuperblockError, BLOCK_SIZE};

const DEVICE_SECTOR_SIZE: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XenithFsError {
    Io,
    BadSuperblock(SuperblockError),
    BadJournal,
    Checksum,
    CorruptInode,
    CorruptExtent,
    CorruptDirectory,
    InvalidInode(u64),
    NoSpace,
    TransactionTooLarge,
    Overflow,
    Unsupported,
}

impl fmt::Display for XenithFsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io => f.write_str("XenithFS block I/O failed"),
            Self::BadSuperblock(error) => write!(f, "invalid XenithFS superblock: {error}"),
            Self::BadJournal => f.write_str("invalid XenithFS journal"),
            Self::Checksum => f.write_str("XenithFS metadata checksum mismatch"),
            Self::CorruptInode => f.write_str("corrupt XenithFS inode"),
            Self::CorruptExtent => f.write_str("corrupt XenithFS extent map"),
            Self::CorruptDirectory => f.write_str("corrupt XenithFS directory"),
            Self::InvalidInode(number) => write!(f, "invalid XenithFS inode {number}"),
            Self::NoSpace => f.write_str("XenithFS has no allocatable space"),
            Self::TransactionTooLarge => f.write_str("XenithFS transaction exceeds journal"),
            Self::Overflow => f.write_str("XenithFS arithmetic overflow"),
            Self::Unsupported => f.write_str("unsupported XenithFS feature"),
        }
    }
}

impl From<SuperblockError> for XenithFsError {
    fn from(error: SuperblockError) -> Self {
        Self::BadSuperblock(error)
    }
}

impl From<xenith_fs_format::JournalError> for XenithFsError {
    fn from(error: xenith_fs_format::JournalError) -> Self {
        match error {
            xenith_fs_format::JournalError::BadChecksum => Self::Checksum,
            xenith_fs_format::JournalError::TooManyDescriptors => Self::TransactionTooLarge,
            xenith_fs_format::JournalError::TooShort
            | xenith_fs_format::JournalError::BadMagic
            | xenith_fs_format::JournalError::BadState
            | xenith_fs_format::JournalError::InvalidTarget => Self::BadJournal,
        }
    }
}

impl From<xenith_fs_format::ExtentError> for XenithFsError {
    fn from(error: xenith_fs_format::ExtentError) -> Self {
        match error {
            xenith_fs_format::ExtentError::Overflow => Self::Overflow,
            xenith_fs_format::ExtentError::ZeroLength
            | xenith_fs_format::ExtentError::UnsupportedFlags
            | xenith_fs_format::ExtentError::LogicalOverlap
            | xenith_fs_format::ExtentError::PhysicalOutOfBounds
            | xenith_fs_format::ExtentError::PhysicalOverlap => Self::CorruptExtent,
        }
    }
}

fn map_error(error: XenithFsError) -> FsError {
    match error {
        XenithFsError::Io => FsError::Io,
        XenithFsError::NoSpace | XenithFsError::TransactionTooLarge => FsError::NoSpace,
        XenithFsError::Overflow => FsError::Overflow,
        XenithFsError::Unsupported => FsError::Unsupported,
        XenithFsError::BadSuperblock(_)
        | XenithFsError::BadJournal
        | XenithFsError::Checksum
        | XenithFsError::CorruptInode
        | XenithFsError::CorruptExtent
        | XenithFsError::CorruptDirectory
        | XenithFsError::InvalidInode(_) => FsError::Corrupt,
    }
}

struct BlockStore<D: BlockDevice> {
    device: SpinLock<D>,
}

impl<D: BlockDevice> BlockStore<D> {
    fn new(device: D) -> Self {
        Self {
            device: SpinLock::new(device),
        }
    }

    fn read_block(&self, block: u64) -> Result<Vec<u8>, XenithFsError> {
        let sectors = BLOCK_SIZE / D::SECTOR_SIZE;
        let lba = block
            .checked_mul(sectors as u64)
            .ok_or(XenithFsError::Overflow)?;
        let mut bytes = vec![0; BLOCK_SIZE];
        let transferred = self
            .device
            .lock()
            .read_blocks(lba, &mut bytes)
            .map_err(|_| XenithFsError::Io)?;
        if transferred != BLOCK_SIZE {
            return Err(XenithFsError::Io);
        }
        Ok(bytes)
    }

    fn write_block(&self, block: u64, bytes: &[u8]) -> Result<(), XenithFsError> {
        if bytes.len() != BLOCK_SIZE {
            return Err(XenithFsError::Io);
        }
        let sectors = BLOCK_SIZE / D::SECTOR_SIZE;
        let lba = block
            .checked_mul(sectors as u64)
            .ok_or(XenithFsError::Overflow)?;
        let transferred = self
            .device
            .lock()
            .write_blocks(lba, bytes)
            .map_err(|_| XenithFsError::Io)?;
        if transferred != BLOCK_SIZE {
            return Err(XenithFsError::Io);
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), XenithFsError> {
        self.device.lock().flush().map_err(|_| XenithFsError::Io)
    }
}

#[derive(Clone)]
struct BlockUpdate {
    target: u64,
    data: Vec<u8>,
}

#[derive(Clone)]
struct MutableState {
    bitmap: Vec<u8>,
    sequence: u64,
}

struct XenithShared<D: BlockDevice> {
    store: BlockStore<D>,
    superblock: Superblock,
    state: SpinLock<MutableState>,
    inode_namespace: u64,
}

static NEXT_INODE_NAMESPACE: AtomicU64 = AtomicU64::new(1);

fn bitmap_get(bitmap: &[u8], block: u64) -> Result<bool, XenithFsError> {
    let index = usize::try_from(block / 8).map_err(|_| XenithFsError::Overflow)?;
    let bit = (block % 8) as u8;
    Ok(bitmap.get(index).is_some_and(|byte| byte & (1 << bit) != 0))
}

fn bitmap_set(bitmap: &mut [u8], block: u64, allocated: bool) -> Result<usize, XenithFsError> {
    let index = usize::try_from(block / 8).map_err(|_| XenithFsError::Overflow)?;
    let bit = (block % 8) as u8;
    let byte = bitmap.get_mut(index).ok_or(XenithFsError::CorruptExtent)?;
    if allocated {
        *byte |= 1 << bit;
    } else {
        *byte &= !(1 << bit);
    }
    Ok(index / BLOCK_SIZE)
}

fn stage_block<'a, D: BlockDevice>(
    shared: &XenithShared<D>,
    updates: &'a mut Vec<BlockUpdate>,
    target: u64,
) -> Result<&'a mut Vec<u8>, XenithFsError> {
    if let Some(index) = updates.iter().position(|update| update.target == target) {
        return Ok(&mut updates[index].data);
    }
    let data = shared.store.read_block(target)?;
    updates.push(BlockUpdate { target, data });
    Ok(&mut updates.last_mut().expect("just pushed update").data)
}

fn commit_updates<D: BlockDevice>(
    shared: &XenithShared<D>,
    state: &mut MutableState,
    updates: &[BlockUpdate],
) -> Result<(), XenithFsError> {
    if updates.is_empty() {
        return Ok(());
    }
    if updates.len() >= shared.superblock.journal_blocks as usize {
        return Err(XenithFsError::TransactionTooLarge);
    }
    for update in updates {
        let in_journal = update.target >= shared.superblock.journal_start
            && update.target
                < shared.superblock.journal_start + u64::from(shared.superblock.journal_blocks);
        if update.target == 0 || update.target >= shared.superblock.total_blocks || in_journal {
            return Err(XenithFsError::BadJournal);
        }
    }
    let sequence = state.sequence.wrapping_add(1);
    let mut descriptors = Vec::with_capacity(updates.len());
    for (index, update) in updates.iter().enumerate() {
        shared.store.write_block(
            shared.superblock.journal_start + 1 + index as u64,
            &update.data,
        )?;
        descriptors.push(JournalDescriptor {
            target_block: update.target,
            checksum: crc32(&update.data),
        });
    }
    // Journal payload must be durable before its prepared commit marker.
    shared.store.flush()?;
    let prepared = JournalHeader {
        prepared: true,
        sequence,
        descriptors,
    }
    .encode()?;
    shared
        .store
        .write_block(shared.superblock.journal_start, &prepared)?;
    shared.store.flush()?;
    for update in updates {
        shared.store.write_block(update.target, &update.data)?;
    }
    // Home blocks must reach media before the transaction is marked clean.
    shared.store.flush()?;
    let clean = JournalHeader::clean(sequence).encode()?;
    shared
        .store
        .write_block(shared.superblock.journal_start, &clean)?;
    shared.store.flush()?;
    state.sequence = sequence;
    Ok(())
}

fn replay_journal<D: BlockDevice>(
    store: &BlockStore<D>,
    superblock: &Superblock,
) -> Result<u64, XenithFsError> {
    let block = store.read_block(superblock.journal_start)?;
    let header = JournalHeader::parse(&block)?;
    if header.descriptors.len() >= superblock.journal_blocks as usize {
        return Err(XenithFsError::BadJournal);
    }
    if header.prepared {
        for (index, descriptor) in header.descriptors.iter().enumerate() {
            let in_journal = descriptor.target_block >= superblock.journal_start
                && descriptor.target_block
                    < superblock.journal_start + u64::from(superblock.journal_blocks);
            if descriptor.target_block == 0
                || descriptor.target_block >= superblock.total_blocks
                || in_journal
            {
                return Err(XenithFsError::BadJournal);
            }
            let payload = store.read_block(superblock.journal_start + 1 + index as u64)?;
            if crc32(&payload) != descriptor.checksum {
                return Err(XenithFsError::Checksum);
            }
            store.write_block(descriptor.target_block, &payload)?;
        }
        store.flush()?;
        store.write_block(
            superblock.journal_start,
            &JournalHeader::clean(header.sequence).encode()?,
        )?;
        store.flush()?;
    }
    Ok(header.sequence.max(superblock.sequence))
}

fn read_inode<D: BlockDevice>(
    shared: &XenithShared<D>,
    number: u64,
) -> Result<Option<DiskInode>, XenithFsError> {
    if number == 0 || number > shared.superblock.inode_count {
        return Err(XenithFsError::InvalidInode(number));
    }
    let byte_offset = (number - 1)
        .checked_mul(INODE_SIZE as u64)
        .ok_or(XenithFsError::Overflow)?;
    let block_number = shared
        .superblock
        .inode_table_start
        .checked_add(byte_offset / BLOCK_SIZE as u64)
        .ok_or(XenithFsError::Overflow)?;
    let within = (byte_offset % BLOCK_SIZE as u64) as usize;
    let block = shared.store.read_block(block_number)?;
    DiskInode::parse(
        &block[within..within + INODE_SIZE],
        number,
        shared.superblock.data_start,
        shared.superblock.total_blocks,
    )
}

fn stage_inode<D: BlockDevice>(
    shared: &XenithShared<D>,
    updates: &mut Vec<BlockUpdate>,
    number: u64,
    inode: Option<&DiskInode>,
) -> Result<(), XenithFsError> {
    if number == 0 || number > shared.superblock.inode_count {
        return Err(XenithFsError::InvalidInode(number));
    }
    let byte_offset = (number - 1)
        .checked_mul(INODE_SIZE as u64)
        .ok_or(XenithFsError::Overflow)?;
    let block_number = shared.superblock.inode_table_start + byte_offset / BLOCK_SIZE as u64;
    let within = (byte_offset % BLOCK_SIZE as u64) as usize;
    let block = stage_block(shared, updates, block_number)?;
    if let Some(inode) = inode {
        block[within..within + INODE_SIZE].copy_from_slice(&inode.encode()?);
    } else {
        block[within..within + INODE_SIZE].fill(0);
    }
    Ok(())
}

fn allocate_inode<D: BlockDevice>(shared: &XenithShared<D>) -> Result<u64, XenithFsError> {
    for number in 1..=shared.superblock.inode_count {
        if read_inode(shared, number)?.is_none() {
            return Ok(number);
        }
    }
    Err(XenithFsError::NoSpace)
}

fn allocate_block(
    superblock: &Superblock,
    state: &mut MutableState,
    bitmap_dirty: &mut Vec<usize>,
) -> Result<u64, XenithFsError> {
    for block in superblock.data_start..superblock.total_blocks {
        if !bitmap_get(&state.bitmap, block)? {
            let bitmap_block = bitmap_set(&mut state.bitmap, block, true)?;
            if !bitmap_dirty.contains(&bitmap_block) {
                bitmap_dirty.push(bitmap_block);
            }
            return Ok(block);
        }
    }
    Err(XenithFsError::NoSpace)
}

fn free_block(
    state: &mut MutableState,
    bitmap_dirty: &mut Vec<usize>,
    block: u64,
) -> Result<(), XenithFsError> {
    if !bitmap_get(&state.bitmap, block)? {
        return Err(XenithFsError::CorruptExtent);
    }
    let bitmap_block = bitmap_set(&mut state.bitmap, block, false)?;
    if !bitmap_dirty.contains(&bitmap_block) {
        bitmap_dirty.push(bitmap_block);
    }
    Ok(())
}

fn stage_bitmaps<D: BlockDevice>(
    shared: &XenithShared<D>,
    state: &MutableState,
    updates: &mut Vec<BlockUpdate>,
    bitmap_dirty: &[usize],
) -> Result<(), XenithFsError> {
    for &index in bitmap_dirty {
        if index >= shared.superblock.bitmap_blocks as usize {
            return Err(XenithFsError::CorruptExtent);
        }
        let start = index * BLOCK_SIZE;
        let target = shared.superblock.bitmap_start + index as u64;
        let block = stage_block(shared, updates, target)?;
        block.copy_from_slice(&state.bitmap[start..start + BLOCK_SIZE]);
    }
    Ok(())
}

fn insert_extent(inode: &mut DiskInode, logical: u64, physical: u64) -> Result<(), XenithFsError> {
    let position = inode
        .extents
        .iter()
        .position(|extent| extent.logical_block > logical)
        .unwrap_or(inode.extents.len());
    inode.extents.insert(position, Extent {
        logical_block: logical,
        physical_block: physical,
        block_count: 1,
        flags: 0,
    });
    if position > 0 {
        let previous = inode.extents[position - 1];
        if previous.logical_end() == Some(logical)
            && previous.physical_end() == Some(physical)
            && previous.flags == 0
        {
            inode.extents[position - 1].block_count = previous
                .block_count
                .checked_add(1)
                .ok_or(XenithFsError::Overflow)?;
            inode.extents.remove(position);
        }
    }
    let index = position
        .saturating_sub(1)
        .min(inode.extents.len().saturating_sub(1));
    if index + 1 < inode.extents.len() {
        let left = inode.extents[index];
        let right = inode.extents[index + 1];
        if left.logical_end() == Some(right.logical_block)
            && left.physical_end() == Some(right.physical_block)
            && left.flags == right.flags
        {
            inode.extents[index].block_count = left
                .block_count
                .checked_add(right.block_count)
                .ok_or(XenithFsError::Overflow)?;
            inode.extents.remove(index + 1);
        }
    }
    if inode.extents.len() > MAX_EXTENTS {
        return Err(XenithFsError::NoSpace);
    }
    Ok(())
}

fn ensure_data_block<D: BlockDevice>(
    shared: &XenithShared<D>,
    state: &mut MutableState,
    inode: &mut DiskInode,
    logical: u64,
    updates: &mut Vec<BlockUpdate>,
    bitmap_dirty: &mut Vec<usize>,
) -> Result<u64, XenithFsError> {
    if let Some(block) = mapped_block(&inode.extents, logical) {
        return Ok(block);
    }
    let physical = allocate_block(&shared.superblock, state, bitmap_dirty)?;
    if let Err(error) = insert_extent(inode, logical, physical) {
        free_block(state, bitmap_dirty, physical)?;
        return Err(error);
    }
    stage_block(shared, updates, physical)?.fill(0);
    Ok(physical)
}

fn read_data<D: BlockDevice>(
    shared: &XenithShared<D>,
    inode: &DiskInode,
    offset: u64,
    output: &mut [u8],
) -> Result<usize, XenithFsError> {
    if offset >= inode.size || output.is_empty() {
        return Ok(0);
    }
    let available = usize::try_from((inode.size - offset).min(output.len() as u64))
        .map_err(|_| XenithFsError::Overflow)?;
    let mut done = 0usize;
    while done < available {
        let position = offset + done as u64;
        let logical = position / BLOCK_SIZE as u64;
        let within = (position % BLOCK_SIZE as u64) as usize;
        let count = (available - done).min(BLOCK_SIZE - within);
        if let Some(physical) = mapped_block(&inode.extents, logical) {
            let block = shared.store.read_block(physical)?;
            output[done..done + count].copy_from_slice(&block[within..within + count]);
        } else {
            output[done..done + count].fill(0);
        }
        done += count;
    }
    Ok(done)
}

fn stage_write_data<D: BlockDevice>(
    shared: &XenithShared<D>,
    state: &mut MutableState,
    inode: &mut DiskInode,
    offset: u64,
    input: &[u8],
    updates: &mut Vec<BlockUpdate>,
    bitmap_dirty: &mut Vec<usize>,
) -> Result<usize, XenithFsError> {
    let end = offset
        .checked_add(input.len() as u64)
        .ok_or(XenithFsError::Overflow)?;
    let mut done = 0usize;
    while done < input.len() {
        let position = offset + done as u64;
        let logical = position / BLOCK_SIZE as u64;
        let within = (position % BLOCK_SIZE as u64) as usize;
        let count = (input.len() - done).min(BLOCK_SIZE - within);
        let physical = ensure_data_block(shared, state, inode, logical, updates, bitmap_dirty)?;
        let block = stage_block(shared, updates, physical)?;
        block[within..within + count].copy_from_slice(&input[done..done + count]);
        done += count;
    }
    inode.size = inode.size.max(end);
    Ok(done)
}

fn stage_truncate<D: BlockDevice>(
    shared: &XenithShared<D>,
    state: &mut MutableState,
    inode: &mut DiskInode,
    size: u64,
    updates: &mut Vec<BlockUpdate>,
    bitmap_dirty: &mut Vec<usize>,
) -> Result<(), XenithFsError> {
    if size >= inode.size {
        inode.size = size;
        return Ok(());
    }
    let keep_blocks = size.div_ceil(BLOCK_SIZE as u64);
    let mut retained = Vec::new();
    for extent in &inode.extents {
        let logical_end = extent.logical_end().ok_or(XenithFsError::Overflow)?;
        if extent.logical_block >= keep_blocks {
            for delta in 0..u64::from(extent.block_count) {
                free_block(state, bitmap_dirty, extent.physical_block + delta)?;
            }
        } else if logical_end > keep_blocks {
            let keep = keep_blocks - extent.logical_block;
            for delta in keep..u64::from(extent.block_count) {
                free_block(state, bitmap_dirty, extent.physical_block + delta)?;
            }
            let mut shortened = *extent;
            shortened.block_count = u32::try_from(keep).map_err(|_| XenithFsError::Overflow)?;
            retained.push(shortened);
        } else {
            retained.push(*extent);
        }
    }
    inode.extents = retained;
    if !size.is_multiple_of(BLOCK_SIZE as u64) && keep_blocks != 0 {
        let logical = keep_blocks - 1;
        if let Some(physical) = mapped_block(&inode.extents, logical) {
            let block = stage_block(shared, updates, physical)?;
            block[(size % BLOCK_SIZE as u64) as usize..].fill(0);
        }
    }
    inode.size = size;
    Ok(())
}

fn read_all<D: BlockDevice>(
    shared: &XenithShared<D>,
    inode: &DiskInode,
    limit: usize,
) -> Result<Vec<u8>, XenithFsError> {
    let size = usize::try_from(inode.size).map_err(|_| XenithFsError::Overflow)?;
    if size > limit {
        return Err(XenithFsError::CorruptDirectory);
    }
    let mut bytes = vec![0; size];
    let read = read_data(shared, inode, 0, &mut bytes)?;
    if read != size {
        return Err(XenithFsError::Io);
    }
    Ok(bytes)
}

fn vfs_inode_id<D: BlockDevice>(shared: &XenithShared<D>, number: u64) -> InodeId {
    InodeId::new(shared.inode_namespace | number)
}

fn metadata<D: BlockDevice>(shared: &XenithShared<D>, inode: &DiskInode) -> InodeMetadata {
    InodeMetadata {
        id: vfs_inode_id(shared, inode.number),
        kind: inode.kind,
        mode: inode.mode,
        uid: inode.uid,
        gid: inode.gid,
        links: inode.links,
        size: inode.size,
        accessed: inode.accessed,
        modified: inode.modified,
        changed: inode.changed,
    }
}

struct XenithNode<D: BlockDevice + Send + 'static> {
    inode: Inode,
    number: u64,
    shared: Arc<XenithShared<D>>,
}

impl<D: BlockDevice + Send + 'static> XenithNode<D> {
    fn from_disk(shared: Arc<XenithShared<D>>, disk: DiskInode) -> NodeRef {
        let node: NodeRef = Arc::new(Self {
            inode: Inode::new(metadata(&shared, &disk)),
            number: disk.number,
            shared,
        });
        cache_insert(&node);
        node
    }

    fn disk_inode(&self) -> Result<DiskInode, FsError> {
        read_inode(&self.shared, self.number)
            .map_err(map_error)?
            .ok_or(FsError::NotFound)
    }

    fn directory_records(&self, inode: &DiskInode) -> Result<Vec<DirectoryRecord>, FsError> {
        if inode.kind != FileType::Directory {
            return Err(FsError::NotDirectory);
        }
        parse_directory(&read_all(&self.shared, inode, MAX_DIRECTORY_SIZE).map_err(map_error)?)
            .map_err(map_error)
    }

    fn commit_mutation(
        &self,
        state: &mut MutableState,
        mut working: MutableState,
        mut updates: Vec<BlockUpdate>,
        bitmap_dirty: Vec<usize>,
    ) -> Result<(), FsError> {
        stage_bitmaps(&self.shared, &working, &mut updates, &bitmap_dirty)
            .and_then(|_| commit_updates(&self.shared, &mut working, &updates))
            .map_err(map_error)?;
        *state = working;
        Ok(())
    }
}

impl<D: BlockDevice + Send + 'static> VfsNode for XenithNode<D> {
    fn inode(&self) -> &Inode {
        &self.inode
    }
}

impl<D: BlockDevice + Send + 'static> InodeOps for XenithNode<D> {
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize, FsError> {
        let _state = self.shared.state.lock();
        let inode = self.disk_inode()?;
        if inode.kind == FileType::Directory {
            return Err(FsError::IsDirectory);
        }
        if inode.kind == FileType::Symlink && !inode.inline_symlink.is_empty() {
            let offset = usize::try_from(offset).map_err(|_| FsError::Overflow)?;
            if offset >= inode.inline_symlink.len() {
                return Ok(0);
            }
            let count = buffer.len().min(inode.inline_symlink.len() - offset);
            buffer[..count].copy_from_slice(&inode.inline_symlink[offset..offset + count]);
            return Ok(count);
        }
        read_data(&self.shared, &inode, offset, buffer).map_err(map_error)
    }

    fn write_at(&self, offset: u64, buffer: &[u8]) -> Result<usize, FsError> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let mut state = self.shared.state.lock();
        let mut working = state.clone();
        let mut inode = self.disk_inode()?;
        if inode.kind != FileType::Regular {
            return Err(if inode.kind == FileType::Directory {
                FsError::IsDirectory
            } else {
                FsError::InvalidInput
            });
        }
        let mut updates = Vec::new();
        let mut bitmap_dirty = Vec::new();
        let written = stage_write_data(
            &self.shared,
            &mut working,
            &mut inode,
            offset,
            buffer,
            &mut updates,
            &mut bitmap_dirty,
        )
        .map_err(map_error)?;
        stage_inode(&self.shared, &mut updates, inode.number, Some(&inode)).map_err(map_error)?;
        self.commit_mutation(&mut state, working, updates, bitmap_dirty)?;
        self.inode
            .update_metadata(|meta| *meta = metadata(&self.shared, &inode));
        Ok(written)
    }

    fn truncate(&self, size: u64) -> Result<(), FsError> {
        let mut state = self.shared.state.lock();
        let mut working = state.clone();
        let mut inode = self.disk_inode()?;
        if inode.kind != FileType::Regular {
            return Err(FsError::InvalidInput);
        }
        let mut updates = Vec::new();
        let mut bitmap_dirty = Vec::new();
        stage_truncate(
            &self.shared,
            &mut working,
            &mut inode,
            size,
            &mut updates,
            &mut bitmap_dirty,
        )
        .map_err(map_error)?;
        stage_inode(&self.shared, &mut updates, inode.number, Some(&inode)).map_err(map_error)?;
        self.commit_mutation(&mut state, working, updates, bitmap_dirty)?;
        self.inode
            .update_metadata(|meta| *meta = metadata(&self.shared, &inode));
        Ok(())
    }

    fn lookup(&self, name: &str) -> Result<NodeRef, FsError> {
        validate_name(name)?;
        let _state = self.shared.state.lock();
        let inode = self.disk_inode()?;
        let entry = self
            .directory_records(&inode)?
            .into_iter()
            .find(|entry| entry.name == name)
            .ok_or(FsError::NotFound)?;
        let child = read_inode(&self.shared, entry.inode)
            .map_err(map_error)?
            .ok_or(FsError::NotFound)?;
        if child.kind != entry.kind {
            return Err(FsError::Corrupt);
        }
        Ok(Self::from_disk(Arc::clone(&self.shared), child))
    }

    fn create(&self, name: &str, kind: FileType, mode: u32) -> Result<NodeRef, FsError> {
        validate_name(name)?;
        if matches!(kind, FileType::CharacterDevice | FileType::BlockDevice) {
            return Err(FsError::Unsupported);
        }
        let mut state = self.shared.state.lock();
        let mut working = state.clone();
        let mut parent = self.disk_inode()?;
        let mut records = self.directory_records(&parent)?;
        if records.iter().any(|entry| entry.name == name) {
            return Err(FsError::AlreadyExists);
        }
        let number = allocate_inode(&self.shared).map_err(map_error)?;
        let child = DiskInode::empty(number, kind, mode);
        records.push(DirectoryRecord {
            inode: number,
            kind,
            name: name.to_string(),
        });
        let directory = encode_directory(&records).map_err(map_error)?;
        let mut updates = Vec::new();
        let mut bitmap_dirty = Vec::new();
        stage_truncate(
            &self.shared,
            &mut working,
            &mut parent,
            0,
            &mut updates,
            &mut bitmap_dirty,
        )
        .map_err(map_error)?;
        stage_write_data(
            &self.shared,
            &mut working,
            &mut parent,
            0,
            &directory,
            &mut updates,
            &mut bitmap_dirty,
        )
        .map_err(map_error)?;
        stage_inode(&self.shared, &mut updates, parent.number, Some(&parent)).map_err(map_error)?;
        stage_inode(&self.shared, &mut updates, child.number, Some(&child)).map_err(map_error)?;
        self.commit_mutation(&mut state, working, updates, bitmap_dirty)?;
        self.inode
            .update_metadata(|meta| *meta = metadata(&self.shared, &parent));
        Ok(Self::from_disk(Arc::clone(&self.shared), child))
    }

    fn remove(&self, name: &str) -> Result<(), FsError> {
        validate_name(name)?;
        let mut state = self.shared.state.lock();
        let mut working = state.clone();
        let mut parent = self.disk_inode()?;
        let mut records = self.directory_records(&parent)?;
        let index = records
            .iter()
            .position(|entry| entry.name == name)
            .ok_or(FsError::NotFound)?;
        let entry = records.remove(index);
        let mut child = read_inode(&self.shared, entry.inode)
            .map_err(map_error)?
            .ok_or(FsError::NotFound)?;
        if child.kind == FileType::Directory && !self.directory_records(&child)?.is_empty() {
            return Err(FsError::NotEmpty);
        }
        let directory = encode_directory(&records).map_err(map_error)?;
        let mut updates = Vec::new();
        let mut bitmap_dirty = Vec::new();
        stage_truncate(
            &self.shared,
            &mut working,
            &mut parent,
            0,
            &mut updates,
            &mut bitmap_dirty,
        )
        .map_err(map_error)?;
        stage_write_data(
            &self.shared,
            &mut working,
            &mut parent,
            0,
            &directory,
            &mut updates,
            &mut bitmap_dirty,
        )
        .map_err(map_error)?;
        stage_truncate(
            &self.shared,
            &mut working,
            &mut child,
            0,
            &mut updates,
            &mut bitmap_dirty,
        )
        .map_err(map_error)?;
        stage_inode(&self.shared, &mut updates, parent.number, Some(&parent)).map_err(map_error)?;
        stage_inode(&self.shared, &mut updates, child.number, None).map_err(map_error)?;
        self.commit_mutation(&mut state, working, updates, bitmap_dirty)?;
        self.inode
            .update_metadata(|meta| *meta = metadata(&self.shared, &parent));
        Ok(())
    }

    fn read_dir(&self) -> Result<Vec<DirEntry>, FsError> {
        let _state = self.shared.state.lock();
        let inode = self.disk_inode()?;
        Ok(self
            .directory_records(&inode)?
            .into_iter()
            .map(|entry| DirEntry {
                name: entry.name,
                inode: vfs_inode_id(&self.shared, entry.inode),
                kind: entry.kind,
            })
            .collect())
    }

    fn read_link(&self) -> Result<String, FsError> {
        let _state = self.shared.state.lock();
        let inode = self.disk_inode()?;
        if inode.kind != FileType::Symlink {
            return Err(FsError::InvalidInput);
        }
        let bytes = if inode.inline_symlink.is_empty() && inode.size != 0 {
            read_all(&self.shared, &inode, 4096).map_err(map_error)?
        } else {
            inode.inline_symlink
        };
        String::from_utf8(bytes).map_err(|_| FsError::Corrupt)
    }

    fn set_link_target(&self, target: &str) -> Result<(), FsError> {
        if target.is_empty() || target.len() > 4096 || target.as_bytes().contains(&0) {
            return Err(FsError::InvalidInput);
        }
        let mut state = self.shared.state.lock();
        let mut working = state.clone();
        let mut inode = self.disk_inode()?;
        if inode.kind != FileType::Symlink {
            return Err(FsError::InvalidInput);
        }
        let mut updates = Vec::new();
        let mut bitmap_dirty = Vec::new();
        stage_truncate(
            &self.shared,
            &mut working,
            &mut inode,
            0,
            &mut updates,
            &mut bitmap_dirty,
        )
        .map_err(map_error)?;
        if target.len() <= INLINE_SYMLINK_BYTES {
            inode.inline_symlink = target.as_bytes().to_vec();
            inode.size = target.len() as u64;
        } else {
            inode.inline_symlink.clear();
            stage_write_data(
                &self.shared,
                &mut working,
                &mut inode,
                0,
                target.as_bytes(),
                &mut updates,
                &mut bitmap_dirty,
            )
            .map_err(map_error)?;
        }
        stage_inode(&self.shared, &mut updates, inode.number, Some(&inode)).map_err(map_error)?;
        self.commit_mutation(&mut state, working, updates, bitmap_dirty)?;
        self.inode
            .update_metadata(|meta| *meta = metadata(&self.shared, &inode));
        Ok(())
    }

    fn set_mode(&self, mode: u32) -> Result<(), FsError> {
        let mut state = self.shared.state.lock();
        let working = state.clone();
        let mut inode = self.disk_inode()?;
        inode.mode = mode & 0o7777;
        let mut updates = Vec::new();
        stage_inode(&self.shared, &mut updates, inode.number, Some(&inode)).map_err(map_error)?;
        self.commit_mutation(&mut state, working, updates, Vec::new())?;
        self.inode
            .update_metadata(|meta| *meta = metadata(&self.shared, &inode));
        Ok(())
    }

    fn set_owner(&self, uid: u32, gid: u32) -> Result<(), FsError> {
        let mut state = self.shared.state.lock();
        let working = state.clone();
        let mut inode = self.disk_inode()?;
        inode.uid = uid;
        inode.gid = gid;
        let mut updates = Vec::new();
        stage_inode(&self.shared, &mut updates, inode.number, Some(&inode)).map_err(map_error)?;
        self.commit_mutation(&mut state, working, updates, Vec::new())?;
        self.inode
            .update_metadata(|meta| *meta = metadata(&self.shared, &inode));
        Ok(())
    }

    fn set_times(&self, accessed: u64, modified: u64) -> Result<(), FsError> {
        let mut state = self.shared.state.lock();
        let working = state.clone();
        let mut inode = self.disk_inode()?;
        inode.accessed = accessed;
        inode.modified = modified;
        inode.changed = modified;
        let mut updates = Vec::new();
        stage_inode(&self.shared, &mut updates, inode.number, Some(&inode)).map_err(map_error)?;
        self.commit_mutation(&mut state, working, updates, Vec::new())?;
        self.inode
            .update_metadata(|meta| *meta = metadata(&self.shared, &inode));
        Ok(())
    }

    fn sync(&self) -> Result<(), FsError> {
        self.shared.store.flush().map_err(map_error)
    }
}

/// Mounted XenithFS volume. Mutations are journaled before target blocks are
/// written; mount replays a fully prepared transaction exactly once.
pub struct XenithFileSystem<D: BlockDevice + Send + 'static> {
    shared: Arc<XenithShared<D>>,
    root: NodeRef,
}

impl<D: BlockDevice + Send + 'static> XenithFileSystem<D> {
    pub fn mount(mut device: D) -> Result<Self, XenithFsError> {
        if D::SECTOR_SIZE != DEVICE_SECTOR_SIZE || !BLOCK_SIZE.is_multiple_of(D::SECTOR_SIZE) {
            return Err(XenithFsError::Unsupported);
        }
        let mut sector = [0u8; DEVICE_SECTOR_SIZE];
        let transferred = device
            .read_blocks(0, &mut sector)
            .map_err(|_| XenithFsError::Io)?;
        if transferred != sector.len() {
            return Err(XenithFsError::Io);
        }
        let superblock = Superblock::parse(&sector)?;
        if superblock.inode_count > 0x0000_ffff_ffff_ffff {
            return Err(XenithFsError::Unsupported);
        }
        let store = BlockStore::new(device);
        let sequence = replay_journal(&store, &superblock)?;
        let bitmap_len = superblock.bitmap_blocks as usize * BLOCK_SIZE;
        let mut bitmap = vec![0; bitmap_len];
        for index in 0..superblock.bitmap_blocks as usize {
            let block = store.read_block(superblock.bitmap_start + index as u64)?;
            bitmap[index * BLOCK_SIZE..(index + 1) * BLOCK_SIZE].copy_from_slice(&block);
        }
        for reserved in 0..superblock.data_start {
            if !bitmap_get(&bitmap, reserved)? {
                return Err(XenithFsError::CorruptExtent);
            }
        }
        let namespace = NEXT_INODE_NAMESPACE.fetch_add(1, Ordering::Relaxed);
        if namespace > u64::from(u16::MAX) {
            return Err(XenithFsError::NoSpace);
        }
        let shared = Arc::new(XenithShared {
            store,
            superblock,
            state: SpinLock::new(MutableState { bitmap, sequence }),
            inode_namespace: namespace << 48,
        });
        let root_disk = read_inode(&shared, superblock.root_inode)?
            .ok_or(XenithFsError::InvalidInode(superblock.root_inode))?;
        if root_disk.kind != FileType::Directory {
            return Err(XenithFsError::CorruptInode);
        }
        parse_directory(&read_all(&shared, &root_disk, MAX_DIRECTORY_SIZE)?)?;
        let root = XenithNode::from_disk(Arc::clone(&shared), root_disk);
        Ok(Self { shared, root })
    }

    pub fn superblock(&self) -> Superblock {
        self.shared.superblock
    }
}

impl<D: BlockDevice + Send + 'static> FileSystem for XenithFileSystem<D> {
    fn name(&self) -> &'static str {
        "xenithfs"
    }

    fn root(&self) -> NodeRef {
        Arc::clone(&self.root)
    }

    fn sync(&self) -> Result<(), FsError> {
        self.root.sync()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::ahci::HbaError;

    #[derive(Clone)]
    struct MemoryDisk {
        bytes: Arc<SpinLock<Vec<u8>>>,
        flushes: Arc<AtomicU64>,
    }

    impl BlockDevice for MemoryDisk {
        fn read_blocks(&mut self, lba: u64, output: &mut [u8]) -> Result<usize, HbaError> {
            if output.is_empty() || !output.len().is_multiple_of(Self::SECTOR_SIZE) {
                return Err(HbaError::InvalidBuffer);
            }
            let start = usize::try_from(lba)
                .ok()
                .and_then(|value| value.checked_mul(Self::SECTOR_SIZE))
                .ok_or(HbaError::InvalidLba)?;
            let end = start
                .checked_add(output.len())
                .ok_or(HbaError::InvalidLba)?;
            let bytes = self.bytes.lock();
            let source = bytes.get(start..end).ok_or(HbaError::InvalidLba)?;
            output.copy_from_slice(source);
            Ok(output.len())
        }

        fn write_blocks(&mut self, lba: u64, input: &[u8]) -> Result<usize, HbaError> {
            if input.is_empty() || !input.len().is_multiple_of(Self::SECTOR_SIZE) {
                return Err(HbaError::InvalidBuffer);
            }
            let start = usize::try_from(lba)
                .ok()
                .and_then(|value| value.checked_mul(Self::SECTOR_SIZE))
                .ok_or(HbaError::InvalidLba)?;
            let end = start.checked_add(input.len()).ok_or(HbaError::InvalidLba)?;
            let mut bytes = self.bytes.lock();
            let target = bytes.get_mut(start..end).ok_or(HbaError::InvalidLba)?;
            target.copy_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> Result<(), HbaError> {
            self.flushes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn formatted_disk() -> MemoryDisk {
        const BLOCKS: usize = 64;
        let mut bytes = vec![0u8; BLOCKS * BLOCK_SIZE];
        bytes[..8].copy_from_slice(sb::MAGIC);
        bytes[8..12].copy_from_slice(&sb::VERSION.to_le_bytes());
        bytes[12..16].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
        bytes[16..24].copy_from_slice(&(BLOCKS as u64).to_le_bytes());
        bytes[24..32].copy_from_slice(&1u64.to_le_bytes()); // inode table
        bytes[32..40].copy_from_slice(&16u64.to_le_bytes()); // inode count
        bytes[40..48].copy_from_slice(&2u64.to_le_bytes()); // bitmap
        bytes[48..52].copy_from_slice(&1u32.to_le_bytes());
        bytes[52..60].copy_from_slice(&11u64.to_le_bytes()); // data start
        bytes[60..68].copy_from_slice(&1u64.to_le_bytes()); // root inode
        bytes[68..76].copy_from_slice(&3u64.to_le_bytes()); // journal
        bytes[76..80].copy_from_slice(&8u32.to_le_bytes());
        let checksum = crc32(&bytes[..sb::SUPERBLOCK_BYTES]);
        bytes[96..100].copy_from_slice(&checksum.to_le_bytes());

        let root = DiskInode::empty(1, FileType::Directory, 0o755)
            .encode()
            .unwrap();
        bytes[BLOCK_SIZE..BLOCK_SIZE + INODE_SIZE].copy_from_slice(&root);
        // Blocks 0..10 contain the superblock, inode table, bitmap, and journal.
        for block in 0..11u64 {
            let byte = 2 * BLOCK_SIZE + (block / 8) as usize;
            bytes[byte] |= 1 << (block % 8);
        }
        MemoryDisk {
            bytes: Arc::new(SpinLock::new(bytes)),
            flushes: Arc::new(AtomicU64::new(0)),
        }
    }

    #[test]
    fn writes_and_replays_persistent_tree() {
        let disk = formatted_disk();
        let fs = XenithFileSystem::mount(disk.clone()).unwrap();
        let root = fs.root();
        let file = root.create("hello", FileType::Regular, 0o640).unwrap();
        assert_eq!(file.write_at(0, b"persistent").unwrap(), 10);
        file.set_mode(0o6750).unwrap();
        file.set_owner(1000, 100).unwrap();
        file.set_times(11, 22).unwrap();
        drop(fs);

        let remounted = XenithFileSystem::mount(disk).unwrap();
        let file = remounted.root().lookup("hello").unwrap();
        let mut output = [0u8; 10];
        assert_eq!(file.read_at(0, &mut output).unwrap(), output.len());
        assert_eq!(&output, b"persistent");
        let metadata = file.metadata();
        assert_eq!(metadata.mode, 0o6750);
        assert_eq!((metadata.uid, metadata.gid), (1000, 100));
        assert_eq!(
            (metadata.accessed, metadata.modified, metadata.changed),
            (11, 22, 22)
        );
    }

    #[test]
    fn journal_commit_and_sync_issue_flush_barriers() {
        let disk = formatted_disk();
        let flushes = Arc::clone(&disk.flushes);
        let fs = XenithFileSystem::mount(disk).unwrap();
        let file = fs
            .root()
            .create("barrier", FileType::Regular, 0o600)
            .unwrap();
        file.write_at(0, b"durable").unwrap();
        assert!(flushes.load(Ordering::Relaxed) >= 8);
        let before_sync = flushes.load(Ordering::Relaxed);
        fs.sync().unwrap();
        assert_eq!(flushes.load(Ordering::Relaxed), before_sync + 1);
    }
}
