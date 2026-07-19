use std::collections::HashSet;

use crate::path::{child_path, ImagePath};
use crate::{Entry, EntryKind, Error, FilesystemKind, Inspection, MAX_FILE_BYTES};

const BLOCK_SIZE: usize = 4096;
const INODE_SIZE: usize = 256;
const MODERN_SUPERBLOCK_SIZE: usize = 512;
const MODERN_INODE_MAGIC: u32 = 0x4f4e_4958;
const MAX_EXTENTS: usize = 14;
const MODERN_MAX_EXTENTS: usize = 6;
const MAX_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;
const MODERN_MAX_DIRECTORY_BYTES: u64 = 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 65_536;

pub(crate) struct XenithFs<'a> {
    image: &'a [u8],
    layout: Layout,
}

enum Layout {
    Modern(ModernSuper),
    Legacy(LegacySuper),
}

#[derive(Clone, Copy)]
struct ModernSuper {
    total_blocks: u64,
    inode_table_start: u64,
    inode_count: u64,
    data_start: u64,
    root_inode: u64,
}

struct LegacySuper {
    total_blocks: u64,
    inode_table_start: u64,
    inode_count: u64,
    data_start: u64,
    root_inode: u64,
    label: String,
}

#[derive(Clone, Copy)]
struct Extent {
    logical_block: u64,
    physical_block: u64,
    block_count: u32,
    flags: u32,
}

struct Inode {
    number: u64,
    kind: EntryKind,
    size: u64,
    extents: Vec<Extent>,
    inline_symlink: Vec<u8>,
}

struct DirectoryRecord {
    inode: u64,
    kind: EntryKind,
    name: String,
}

impl<'a> XenithFs<'a> {
    pub(crate) fn parse(image: &'a [u8]) -> Result<Self, Error> {
        if image.len() < MODERN_SUPERBLOCK_SIZE {
            return Err(Error::Truncated("XenithFS superblock"));
        }
        if image.get(..8) != Some(b"XENITHFS") {
            return Err(Error::Corrupt("XenithFS magic"));
        }
        if read_u32(image, 8)? != 1 {
            return Err(Error::Unsupported("XenithFS version"));
        }
        if read_u32(image, 12)? as usize != BLOCK_SIZE {
            return Err(Error::Unsupported("XenithFS block size"));
        }

        let layout = if modern_checksum_matches(image)? {
            Layout::Modern(parse_modern_super(image)?)
        } else {
            Layout::Legacy(parse_legacy_super(image)?)
        };
        Ok(Self { image, layout })
    }

    pub(crate) fn inspect(&self) -> Inspection {
        match &self.layout {
            Layout::Modern(superblock) => Inspection {
                filesystem: FilesystemKind::XenithFs,
                label: None,
                logical_block_size: BLOCK_SIZE as u32,
                total_bytes: superblock.total_blocks * BLOCK_SIZE as u64,
                root_identifier: superblock.root_inode,
            },
            Layout::Legacy(superblock) => Inspection {
                filesystem: FilesystemKind::XenithFsLegacy,
                label: Some(superblock.label.clone()),
                logical_block_size: BLOCK_SIZE as u32,
                total_bytes: superblock.total_blocks * BLOCK_SIZE as u64,
                root_identifier: superblock.root_inode,
            },
        }
    }

    pub(crate) fn list(&self, path: &ImagePath) -> Result<Vec<Entry>, Error> {
        let directory = self.resolve(path)?;
        if directory.kind != EntryKind::Directory {
            return Err(Error::NotDirectory(path.display().to_owned()));
        }
        let records = self.read_directory(&directory)?;
        records
            .into_iter()
            .map(|record| {
                let inode = self.read_inode(record.inode)?;
                if inode.kind != record.kind {
                    return Err(Error::Corrupt("XenithFS directory entry type"));
                }
                Ok(Entry {
                    path: child_path(path.display(), &record.name),
                    name: record.name,
                    kind: inode.kind,
                    size: inode.size,
                    identifier: inode.number,
                })
            })
            .collect()
    }

    pub(crate) fn read_file(&self, path: &ImagePath) -> Result<Vec<u8>, Error> {
        let inode = self.resolve(path)?;
        if inode.kind == EntryKind::Directory {
            return Err(Error::IsDirectory(path.display().to_owned()));
        }
        self.read_contents(&inode, MAX_FILE_BYTES)
    }

    fn root_inode(&self) -> u64 {
        match self.layout {
            Layout::Modern(superblock) => superblock.root_inode,
            Layout::Legacy(ref superblock) => superblock.root_inode,
        }
    }

    fn resolve(&self, path: &ImagePath) -> Result<Inode, Error> {
        let mut inode = self.read_inode(self.root_inode())?;
        for component in path.components() {
            if inode.kind != EntryKind::Directory {
                return Err(Error::NotDirectory(path.display().to_owned()));
            }
            let record = self
                .read_directory(&inode)?
                .into_iter()
                .find(|record| record.name == *component)
                .ok_or_else(|| Error::NotFound(path.display().to_owned()))?;
            inode = self.read_inode(record.inode)?;
            if inode.kind != record.kind {
                return Err(Error::Corrupt("XenithFS directory entry type"));
            }
        }
        Ok(inode)
    }

    fn read_inode(&self, number: u64) -> Result<Inode, Error> {
        match self.layout {
            Layout::Modern(superblock) => self.read_modern_inode(superblock, number),
            Layout::Legacy(ref superblock) => self.read_legacy_inode(superblock, number),
        }
    }

    fn read_modern_inode(&self, superblock: ModernSuper, number: u64) -> Result<Inode, Error> {
        if number == 0 || number > superblock.inode_count {
            return Err(Error::Corrupt("XenithFS inode number"));
        }
        let table_offset = block_offset(superblock.inode_table_start)?;
        let index =
            usize::try_from(number - 1).map_err(|_| Error::Corrupt("XenithFS inode number"))?;
        let offset = table_offset
            .checked_add(
                index
                    .checked_mul(INODE_SIZE)
                    .ok_or(Error::Corrupt("XenithFS inode offset"))?,
            )
            .ok_or(Error::Corrupt("XenithFS inode offset"))?;
        let bytes = slice(self.image, offset, INODE_SIZE, "XenithFS inode")?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(Error::Corrupt("unallocated XenithFS inode reference"));
        }
        if read_u32(bytes, 0)? != MODERN_INODE_MAGIC || read_u16(bytes, 4)? != 1 {
            return Err(Error::Corrupt("XenithFS inode header"));
        }
        let mut checked = [0u8; INODE_SIZE];
        checked.copy_from_slice(bytes);
        let expected = read_u32(bytes, 252)?;
        checked[252..256].fill(0);
        if crc32(&checked) != expected {
            return Err(Error::Corrupt("XenithFS inode checksum"));
        }
        if read_u64(bytes, 8)? != number || read_u32(bytes, 36)? == 0 {
            return Err(Error::Corrupt("XenithFS inode metadata"));
        }
        let kind = disk_kind(bytes[6])?;
        let extent_count = usize::from(read_u16(bytes, 72)?);
        let symlink_len = usize::from(read_u16(bytes, 74)?);
        if extent_count > MODERN_MAX_EXTENTS || symlink_len > 28 {
            return Err(Error::Corrupt("XenithFS inode bounds"));
        }
        let mut extents = Vec::with_capacity(extent_count);
        for index in 0..extent_count {
            let extent_offset = 80 + index * 24;
            extents.push(Extent {
                logical_block: read_u64(bytes, extent_offset)?,
                physical_block: read_u64(bytes, extent_offset + 8)?,
                block_count: read_u32(bytes, extent_offset + 16)?,
                flags: read_u32(bytes, extent_offset + 20)?,
            });
        }
        validate_extents(
            &extents,
            superblock.data_start,
            superblock.total_blocks,
            true,
        )?;
        let inline_symlink = bytes[224..224 + symlink_len].to_vec();
        let size = read_u64(bytes, 40)?;
        if (kind != EntryKind::Symlink && !inline_symlink.is_empty())
            || (kind == EntryKind::Symlink
                && !inline_symlink.is_empty()
                && size != inline_symlink.len() as u64)
        {
            return Err(Error::Corrupt("XenithFS inline symlink"));
        }
        Ok(Inode {
            number,
            kind,
            size,
            extents,
            inline_symlink,
        })
    }

    fn read_legacy_inode(&self, superblock: &LegacySuper, number: u64) -> Result<Inode, Error> {
        if number == 0 || number > superblock.inode_count {
            return Err(Error::Corrupt("legacy XenithFS inode number"));
        }
        let table_offset = block_offset(superblock.inode_table_start)?;
        let index = usize::try_from(number - 1)
            .map_err(|_| Error::Corrupt("legacy XenithFS inode number"))?;
        let offset = table_offset
            .checked_add(
                index
                    .checked_mul(INODE_SIZE)
                    .ok_or(Error::Corrupt("legacy XenithFS inode offset"))?,
            )
            .ok_or(Error::Corrupt("legacy XenithFS inode offset"))?;
        let bytes = slice(self.image, offset, INODE_SIZE, "legacy XenithFS inode")?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(Error::Corrupt(
                "unallocated legacy XenithFS inode reference",
            ));
        }
        if read_u16(bytes, 2)? == 0 {
            return Err(Error::Corrupt("legacy XenithFS inode link count"));
        }
        let kind = mode_kind(read_u16(bytes, 0)?)?;
        let count = usize::try_from(read_u64(bytes, 24)?)
            .map_err(|_| Error::Corrupt("legacy XenithFS extent count"))?;
        if count > MAX_EXTENTS {
            return Err(Error::Corrupt("legacy XenithFS extent count"));
        }
        let mut logical_block = 0u64;
        let mut extents = Vec::with_capacity(count);
        for index in 0..count {
            let extent_offset = 32 + index * 16;
            let block_count = read_u32(bytes, extent_offset + 8)?;
            extents.push(Extent {
                logical_block,
                physical_block: read_u64(bytes, extent_offset)?,
                block_count,
                flags: 0,
            });
            logical_block = logical_block
                .checked_add(u64::from(block_count))
                .ok_or(Error::Corrupt("legacy XenithFS extent"))?;
        }
        validate_extents(
            &extents,
            superblock.data_start,
            superblock.total_blocks,
            false,
        )?;
        Ok(Inode {
            number,
            kind,
            size: read_u64(bytes, 16)?,
            extents,
            inline_symlink: Vec::new(),
        })
    }

    fn read_contents(&self, inode: &Inode, limit: u64) -> Result<Vec<u8>, Error> {
        if inode.size > limit {
            return Err(Error::LimitExceeded("file or directory size"));
        }
        if !inode.inline_symlink.is_empty() {
            return Ok(inode.inline_symlink.clone());
        }
        let size = usize::try_from(inode.size)
            .map_err(|_| Error::LimitExceeded("file or directory size"))?;
        let mut output = vec![0u8; size];
        for extent in &inode.extents {
            if extent.flags & 1 != 0 {
                continue;
            }
            for block_index in 0..u64::from(extent.block_count) {
                let logical = extent
                    .logical_block
                    .checked_add(block_index)
                    .ok_or(Error::Corrupt("XenithFS logical extent"))?;
                let destination = logical
                    .checked_mul(BLOCK_SIZE as u64)
                    .ok_or(Error::Corrupt("XenithFS logical extent"))?;
                if destination >= inode.size {
                    break;
                }
                let physical = extent
                    .physical_block
                    .checked_add(block_index)
                    .ok_or(Error::Corrupt("XenithFS physical extent"))?;
                let source = block_offset(physical)?;
                let copy_len = usize::try_from((inode.size - destination).min(BLOCK_SIZE as u64))
                    .map_err(|_| Error::Corrupt("XenithFS extent length"))?;
                let destination = usize::try_from(destination)
                    .map_err(|_| Error::Corrupt("XenithFS logical extent"))?;
                output[destination..destination + copy_len].copy_from_slice(slice(
                    self.image,
                    source,
                    copy_len,
                    "XenithFS extent",
                )?);
            }
        }
        Ok(output)
    }

    fn read_directory(&self, inode: &Inode) -> Result<Vec<DirectoryRecord>, Error> {
        match self.layout {
            Layout::Modern(_) => {
                let bytes = self.read_contents(inode, MODERN_MAX_DIRECTORY_BYTES)?;
                parse_modern_directory(&bytes, self.inode_count())
            },
            Layout::Legacy(_) => {
                let bytes = self.read_contents(inode, MAX_DIRECTORY_BYTES)?;
                parse_legacy_directory(&bytes, self.inode_count())
            },
        }
    }

    fn inode_count(&self) -> u64 {
        match self.layout {
            Layout::Modern(superblock) => superblock.inode_count,
            Layout::Legacy(ref superblock) => superblock.inode_count,
        }
    }
}

fn modern_checksum_matches(image: &[u8]) -> Result<bool, Error> {
    let bytes = slice(image, 0, MODERN_SUPERBLOCK_SIZE, "XenithFS superblock")?;
    let expected = read_u32(bytes, 96)?;
    let mut checked = [0u8; MODERN_SUPERBLOCK_SIZE];
    checked.copy_from_slice(bytes);
    checked[96..100].fill(0);
    Ok(crc32(&checked) == expected)
}

fn parse_modern_super(image: &[u8]) -> Result<ModernSuper, Error> {
    let superblock = ModernSuper {
        total_blocks: read_u64(image, 16)?,
        inode_table_start: read_u64(image, 24)?,
        inode_count: read_u64(image, 32)?,
        data_start: read_u64(image, 52)?,
        root_inode: read_u64(image, 60)?,
    };
    let bitmap_start = read_u64(image, 40)?;
    let bitmap_blocks = u64::from(read_u32(image, 48)?);
    let journal_start = read_u64(image, 68)?;
    let journal_blocks = u64::from(read_u32(image, 76)?);
    let features = read_u64(image, 80)?;
    if features != 0 {
        return Err(Error::Unsupported("XenithFS feature flags"));
    }
    if superblock.total_blocks < 8
        || superblock.inode_count == 0
        || superblock.root_inode == 0
        || superblock.root_inode > superblock.inode_count
        || bitmap_blocks == 0
        || journal_blocks < 2
        || superblock.data_start >= superblock.total_blocks
    {
        return Err(Error::Corrupt("XenithFS geometry"));
    }
    ensure_image_blocks(image, superblock.total_blocks)?;
    let inode_blocks = superblock
        .inode_count
        .checked_mul(INODE_SIZE as u64)
        .and_then(|bytes| bytes.checked_add(BLOCK_SIZE as u64 - 1))
        .map(|bytes| bytes / BLOCK_SIZE as u64)
        .ok_or(Error::Corrupt("XenithFS inode geometry"))?;
    let ranges = [
        (0, 1),
        checked_range(superblock.inode_table_start, inode_blocks)?,
        checked_range(bitmap_start, bitmap_blocks)?,
        checked_range(journal_start, journal_blocks)?,
    ];
    for &(start, end) in &ranges {
        if start >= end || end > superblock.data_start {
            return Err(Error::Corrupt("XenithFS metadata geometry"));
        }
    }
    for left in 0..ranges.len() {
        for right in left + 1..ranges.len() {
            if ranges[left].0 < ranges[right].1 && ranges[right].0 < ranges[left].1 {
                return Err(Error::Corrupt("overlapping XenithFS metadata"));
            }
        }
    }
    let bitmap_capacity = bitmap_blocks
        .checked_mul(BLOCK_SIZE as u64 * 8)
        .ok_or(Error::Corrupt("XenithFS bitmap geometry"))?;
    if bitmap_capacity < superblock.total_blocks {
        return Err(Error::Corrupt("XenithFS bitmap capacity"));
    }
    Ok(superblock)
}

fn parse_legacy_super(image: &[u8]) -> Result<LegacySuper, Error> {
    if image.len() < BLOCK_SIZE {
        return Err(Error::Truncated("legacy XenithFS superblock"));
    }
    let expected = read_u32(image, BLOCK_SIZE - 4)?;
    if crc32(&image[..BLOCK_SIZE - 4]) != expected {
        return Err(Error::Corrupt("XenithFS superblock checksum"));
    }
    let superblock = LegacySuper {
        total_blocks: read_u64(image, 16)?,
        inode_table_start: read_u64(image, 40)?,
        inode_count: read_u64(image, 64)?,
        data_start: read_u64(image, 56)?,
        root_inode: read_u64(image, 72)?,
        label: parse_legacy_label(image)?,
    };
    let bitmap_start = read_u64(image, 24)?;
    let bitmap_blocks = read_u64(image, 32)?;
    let inode_blocks = read_u64(image, 48)?;
    if superblock.total_blocks < 2
        || bitmap_start != 1
        || bitmap_blocks == 0
        || superblock.inode_count == 0
        || superblock.root_inode == 0
        || superblock.root_inode > superblock.inode_count
        || checked_add(bitmap_start, bitmap_blocks)? > superblock.inode_table_start
        || checked_add(superblock.inode_table_start, inode_blocks)? > superblock.data_start
        || superblock.data_start >= superblock.total_blocks
    {
        return Err(Error::Corrupt("legacy XenithFS geometry"));
    }
    let required_inode_blocks = superblock
        .inode_count
        .checked_mul(INODE_SIZE as u64)
        .and_then(|bytes| bytes.checked_add(BLOCK_SIZE as u64 - 1))
        .map(|bytes| bytes / BLOCK_SIZE as u64)
        .ok_or(Error::Corrupt("legacy XenithFS inode geometry"))?;
    if required_inode_blocks > inode_blocks
        || bitmap_blocks
            .checked_mul(BLOCK_SIZE as u64 * 8)
            .is_none_or(|capacity| capacity < superblock.total_blocks)
    {
        return Err(Error::Corrupt("legacy XenithFS metadata capacity"));
    }
    ensure_image_blocks(image, superblock.total_blocks)?;
    Ok(superblock)
}

fn parse_legacy_label(image: &[u8]) -> Result<String, Error> {
    let length = usize::from(*image.get(80).ok_or(Error::Truncated("XenithFS label"))?);
    if length == 0 || length > 31 {
        return Err(Error::Corrupt("legacy XenithFS label"));
    }
    let label = slice(image, 81, length, "XenithFS label")?;
    if !label.is_ascii() {
        return Err(Error::Corrupt("legacy XenithFS label"));
    }
    String::from_utf8(label.to_vec()).map_err(|_| Error::Corrupt("legacy XenithFS label"))
}

fn parse_modern_directory(bytes: &[u8], inode_count: u64) -> Result<Vec<DirectoryRecord>, Error> {
    let mut output = Vec::new();
    let mut names = HashSet::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if output.len() >= MAX_DIRECTORY_ENTRIES {
            return Err(Error::LimitExceeded("directory entries"));
        }
        let header = slice(bytes, offset, 16, "XenithFS directory record")?;
        let inode = read_u64(header, 0)?;
        let record_len = usize::from(read_u16(header, 8)?);
        let name_len = usize::from(header[10]);
        if record_len < 16 + name_len || record_len % 8 != 0 {
            return Err(Error::Corrupt("XenithFS directory record length"));
        }
        let record = slice(bytes, offset, record_len, "XenithFS directory record")?;
        let expected = read_u32(record, 12)?;
        let mut checked = record.to_vec();
        checked[12..16].fill(0);
        if crc32(&checked) != expected {
            return Err(Error::Corrupt("XenithFS directory checksum"));
        }
        if inode == 0 || inode > inode_count {
            return Err(Error::Corrupt("XenithFS directory inode"));
        }
        let name = std::str::from_utf8(&record[16..16 + name_len])
            .map_err(|_| Error::Corrupt("XenithFS directory name"))?;
        validate_name(name, false)?;
        if !names.insert(name.to_owned()) {
            return Err(Error::Corrupt("duplicate XenithFS directory name"));
        }
        output.push(DirectoryRecord {
            inode,
            kind: disk_kind(header[11])?,
            name: name.to_owned(),
        });
        offset = offset
            .checked_add(record_len)
            .ok_or(Error::Corrupt("XenithFS directory offset"))?;
    }
    Ok(output)
}

fn parse_legacy_directory(bytes: &[u8], inode_count: u64) -> Result<Vec<DirectoryRecord>, Error> {
    if !bytes.len().is_multiple_of(256) {
        return Err(Error::Corrupt("legacy XenithFS directory size"));
    }
    let mut output = Vec::new();
    let mut names = HashSet::new();
    for slot in bytes.as_chunks::<256>().0 {
        let inode = read_u64(slot, 0)?;
        if inode == 0 {
            continue;
        }
        if inode > inode_count {
            return Err(Error::Corrupt("legacy XenithFS directory inode"));
        }
        let name_len = usize::from(slot[9]);
        if name_len == 0 || name_len > 240 {
            return Err(Error::Corrupt("legacy XenithFS directory name length"));
        }
        let name = std::str::from_utf8(&slot[16..16 + name_len])
            .map_err(|_| Error::Corrupt("legacy XenithFS directory name"))?;
        validate_name(name, true)?;
        if name == "." || name == ".." {
            continue;
        }
        if output.len() >= MAX_DIRECTORY_ENTRIES {
            return Err(Error::LimitExceeded("directory entries"));
        }
        if !names.insert(name.to_owned()) {
            return Err(Error::Corrupt("duplicate legacy XenithFS directory name"));
        }
        output.push(DirectoryRecord {
            inode,
            kind: disk_kind(slot[8])?,
            name: name.to_owned(),
        });
    }
    Ok(output)
}

fn validate_extents(
    extents: &[Extent],
    data_start: u64,
    total_blocks: u64,
    allow_unwritten: bool,
) -> Result<(), Error> {
    let mut logical_end = 0u64;
    for extent in extents {
        let physical_end = extent
            .physical_block
            .checked_add(u64::from(extent.block_count))
            .ok_or(Error::Corrupt("XenithFS extent"))?;
        let next_logical = extent
            .logical_block
            .checked_add(u64::from(extent.block_count))
            .ok_or(Error::Corrupt("XenithFS extent"))?;
        if extent.block_count == 0
            || (!allow_unwritten && extent.flags != 0)
            || (allow_unwritten && extent.flags & !1 != 0)
            || extent.logical_block < logical_end
            || extent.physical_block < data_start
            || physical_end > total_blocks
        {
            return Err(Error::Corrupt("XenithFS extent"));
        }
        logical_end = next_logical;
    }
    for (index, left) in extents.iter().enumerate() {
        let left_end = left.physical_block + u64::from(left.block_count);
        for right in &extents[index + 1..] {
            let right_end = right.physical_block + u64::from(right.block_count);
            if left.physical_block < right_end && right.physical_block < left_end {
                return Err(Error::Corrupt("overlapping XenithFS extents"));
            }
        }
    }
    Ok(())
}

fn validate_name(name: &str, allow_dots: bool) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > 255
        || name.contains('/')
        || name.contains('\0')
        || (!allow_dots && (name == "." || name == ".."))
    {
        return Err(Error::Corrupt("XenithFS directory name"));
    }
    Ok(())
}

fn disk_kind(value: u8) -> Result<EntryKind, Error> {
    match value {
        1 => Ok(EntryKind::File),
        2 => Ok(EntryKind::Directory),
        3 => Ok(EntryKind::Symlink),
        _ => Err(Error::Corrupt("XenithFS inode type")),
    }
}

fn mode_kind(mode: u16) -> Result<EntryKind, Error> {
    match mode & 0o170000 {
        0o100000 => Ok(EntryKind::File),
        0o040000 => Ok(EntryKind::Directory),
        0o120000 => Ok(EntryKind::Symlink),
        _ => Err(Error::Unsupported("legacy XenithFS inode type")),
    }
}

fn ensure_image_blocks(image: &[u8], blocks: u64) -> Result<(), Error> {
    let required = blocks
        .checked_mul(BLOCK_SIZE as u64)
        .ok_or(Error::Corrupt("XenithFS image size"))?;
    if required > image.len() as u64 {
        return Err(Error::Truncated("XenithFS image"));
    }
    Ok(())
}

fn checked_range(start: u64, length: u64) -> Result<(u64, u64), Error> {
    Ok((start, checked_add(start, length)?))
}

fn checked_add(left: u64, right: u64) -> Result<u64, Error> {
    left.checked_add(right)
        .ok_or(Error::Corrupt("XenithFS geometry overflow"))
}

fn block_offset(block: u64) -> Result<usize, Error> {
    block
        .checked_mul(BLOCK_SIZE as u64)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(Error::Corrupt("XenithFS block offset"))
}

fn slice<'a>(
    bytes: &'a [u8],
    offset: usize,
    length: usize,
    item: &'static str,
) -> Result<&'a [u8], Error> {
    let end = offset.checked_add(length).ok_or(Error::Corrupt(item))?;
    bytes.get(offset..end).ok_or(Error::Truncated(item))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let value = slice(bytes, offset, 2, "XenithFS integer")?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let value = slice(bytes, offset, 4, "XenithFS integer")?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let value = slice(bytes, offset, 8, "XenithFS integer")?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
