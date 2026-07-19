//! FAT short/long directory-entry decoding.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::fat::{FatError, FatVolume};
use crate::devices::ahci::BlockDevice;

pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME_ID: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LONG_NAME: u8 = 0x0f;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FatDirEntry {
    pub name: String,
    pub attributes: u8,
    pub first_cluster: u32,
    pub size: u32,
    pub created_time: u16,
    pub created_date: u16,
    pub accessed_date: u16,
    pub modified_time: u16,
    pub modified_date: u16,
    pub entry_offset: u32,
}

impl FatDirEntry {
    pub const fn is_directory(&self) -> bool {
        self.attributes & ATTR_DIRECTORY != 0
    }

    pub const fn is_read_only(&self) -> bool {
        self.attributes & ATTR_READ_ONLY != 0
    }

    pub const fn is_volume_label(&self) -> bool {
        self.attributes & ATTR_VOLUME_ID != 0
    }
}

#[derive(Clone)]
struct LongFragment {
    order: u8,
    checksum: u8,
    units: [u16; 13],
}

fn le16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn short_checksum(name: &[u8]) -> u8 {
    name.iter()
        .fold(0u8, |sum, byte| sum.rotate_right(1).wrapping_add(*byte))
}

fn long_fragment(entry: &[u8]) -> LongFragment {
    let mut units = [0u16; 13];
    let offsets = [1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    for (index, offset) in offsets.into_iter().enumerate() {
        units[index] = le16(entry, offset);
    }
    LongFragment {
        order: entry[0] & 0x1f,
        checksum: entry[13],
        units,
    }
}

fn long_name(fragments: &mut Vec<LongFragment>, checksum: u8) -> Option<String> {
    if fragments.is_empty() || fragments.iter().any(|part| part.checksum != checksum) {
        fragments.clear();
        return None;
    }
    fragments.sort_by_key(|part| part.order);
    for (index, fragment) in fragments.iter().enumerate() {
        if fragment.order as usize != index + 1 {
            fragments.clear();
            return None;
        }
    }
    let mut units = Vec::with_capacity(fragments.len() * 13);
    for fragment in fragments.iter() {
        for unit in fragment.units {
            if unit == 0 || unit == 0xffff {
                break;
            }
            units.push(unit);
        }
    }
    fragments.clear();
    if units.is_empty() {
        None
    } else {
        Some(String::from_utf16_lossy(&units))
    }
}

fn short_name(entry: &[u8]) -> String {
    let mut base = entry[..8].to_vec();
    if base.first().copied() == Some(0x05) {
        base[0] = 0xe5;
    }
    while base.last().copied() == Some(b' ') {
        base.pop();
    }
    let mut extension = entry[8..11].to_vec();
    while extension.last().copied() == Some(b' ') {
        extension.pop();
    }
    if entry[12] & 0x08 != 0 {
        base.make_ascii_lowercase();
    }
    if entry[12] & 0x10 != 0 {
        extension.make_ascii_lowercase();
    }
    let mut name = String::from_utf8_lossy(&base).into_owned();
    if !extension.is_empty() {
        name.push('.');
        name.push_str(&String::from_utf8_lossy(&extension));
    }
    name
}

pub fn parse_directory(bytes: &[u8]) -> Result<Vec<FatDirEntry>, FatError> {
    if !bytes.len().is_multiple_of(32) {
        return Err(FatError::CorruptDirectory);
    }
    let mut result = Vec::new();
    let mut fragments = Vec::new();
    for (index, entry) in bytes.as_chunks::<32>().0.iter().enumerate() {
        match entry[0] {
            0x00 => break,
            0xe5 => {
                fragments.clear();
                continue;
            },
            _ => {},
        }
        let attributes = entry[11];
        if attributes == ATTR_LONG_NAME {
            if entry[12] != 0 || le16(entry, 26) != 0 || entry[0] & 0x1f == 0 {
                fragments.clear();
                continue;
            }
            fragments.push(long_fragment(entry));
            continue;
        }

        let checksum = short_checksum(&entry[..11]);
        let name = long_name(&mut fragments, checksum).unwrap_or_else(|| short_name(entry));
        if name.is_empty() {
            continue;
        }
        let first_cluster = (u32::from(le16(entry, 20)) << 16) | u32::from(le16(entry, 26));
        let record = FatDirEntry {
            name,
            attributes,
            first_cluster,
            size: le32(entry, 28),
            created_time: le16(entry, 14),
            created_date: le16(entry, 16),
            accessed_date: le16(entry, 18),
            modified_time: le16(entry, 22),
            modified_date: le16(entry, 24),
            entry_offset: u32::try_from(index * 32).map_err(|_| FatError::Overflow)?,
        };
        if !record.is_volume_label() {
            result.push(record);
        }
    }
    Ok(result)
}

pub fn read_directory<D: BlockDevice>(
    volume: &FatVolume<D>,
    first_cluster: u32,
) -> Result<Vec<FatDirEntry>, FatError> {
    parse_directory(&volume.read_chain(first_cluster)?)
}

pub fn find_entry<D: BlockDevice>(
    volume: &FatVolume<D>,
    directory_cluster: u32,
    name: &str,
) -> Result<Option<FatDirEntry>, FatError> {
    Ok(read_directory(volume, directory_cluster)?
        .into_iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_short_file_name() {
        let mut bytes = [0u8; 64];
        bytes[..11].copy_from_slice(b"README  TXT");
        bytes[11] = ATTR_ARCHIVE;
        bytes[28..32].copy_from_slice(&12u32.to_le_bytes());
        let entries = parse_directory(&bytes).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "README.TXT");
        assert_eq!(entries[0].size, 12);
    }

    #[test]
    fn skips_deleted_entries() {
        let mut bytes = [0u8; 64];
        bytes[0] = 0xe5;
        assert!(parse_directory(&bytes).unwrap().is_empty());
    }
}
