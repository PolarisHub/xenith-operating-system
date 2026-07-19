//! Checksummed variable-length XenithFS directory records.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{crc32, InodeKind};

pub const DIRECTORY_HEADER_SIZE: usize = 16;
pub const MAX_DIRECTORY_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryRecord {
    pub inode: u64,
    pub kind: InodeKind,
    pub name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryError {
    TooLarge,
    Truncated,
    InvalidRecordLength,
    BadChecksum,
    InvalidInode,
    InvalidKind,
    InvalidName,
    DuplicateName,
    TooManyEntries,
}

pub fn parse_directory(bytes: &[u8]) -> Result<Vec<DirectoryRecord>, DirectoryError> {
    if bytes.len() > MAX_DIRECTORY_SIZE {
        return Err(DirectoryError::TooLarge);
    }
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if records.len() >= u16::MAX as usize {
            return Err(DirectoryError::TooManyEntries);
        }
        let header = bytes
            .get(offset..offset + DIRECTORY_HEADER_SIZE)
            .ok_or(DirectoryError::Truncated)?;
        let inode = u64::from_le_bytes(header[0..8].try_into().unwrap());
        let record_len = usize::from(u16::from_le_bytes(header[8..10].try_into().unwrap()));
        let name_len = usize::from(header[10]);
        if record_len < DIRECTORY_HEADER_SIZE + name_len || !record_len.is_multiple_of(8) {
            return Err(DirectoryError::InvalidRecordLength);
        }
        let record = bytes
            .get(offset..offset + record_len)
            .ok_or(DirectoryError::Truncated)?;
        let expected = u32::from_le_bytes(record[12..16].try_into().unwrap());
        let mut checked = record.to_vec();
        checked[12..16].fill(0);
        if crc32(&checked) != expected {
            return Err(DirectoryError::BadChecksum);
        }
        if inode == 0 {
            return Err(DirectoryError::InvalidInode);
        }
        let name = core::str::from_utf8(&record[16..16 + name_len])
            .map_err(|_| DirectoryError::InvalidName)?;
        validate_name(name)?;
        if records
            .iter()
            .any(|entry: &DirectoryRecord| entry.name == name)
        {
            return Err(DirectoryError::DuplicateName);
        }
        records.push(DirectoryRecord {
            inode,
            kind: InodeKind::from_disk(header[11]).map_err(|_| DirectoryError::InvalidKind)?,
            name: name.to_string(),
        });
        offset = offset
            .checked_add(record_len)
            .ok_or(DirectoryError::TooLarge)?;
    }
    Ok(records)
}

pub fn encode_directory(records: &[DirectoryRecord]) -> Result<Vec<u8>, DirectoryError> {
    let mut bytes = Vec::new();
    for (index, record) in records.iter().enumerate() {
        if index >= u16::MAX as usize {
            return Err(DirectoryError::TooManyEntries);
        }
        if record.inode == 0 {
            return Err(DirectoryError::InvalidInode);
        }
        validate_name(&record.name)?;
        if records[..index]
            .iter()
            .any(|entry| entry.name == record.name)
        {
            return Err(DirectoryError::DuplicateName);
        }
        let record_len = (DIRECTORY_HEADER_SIZE + record.name.len()).next_multiple_of(8);
        if bytes.len().saturating_add(record_len) > MAX_DIRECTORY_SIZE
            || record_len > usize::from(u16::MAX)
        {
            return Err(DirectoryError::TooLarge);
        }
        let start = bytes.len();
        bytes.resize(start + record_len, 0);
        bytes[start..start + 8].copy_from_slice(&record.inode.to_le_bytes());
        bytes[start + 8..start + 10].copy_from_slice(&(record_len as u16).to_le_bytes());
        bytes[start + 10] = record.name.len() as u8;
        bytes[start + 11] = record.kind as u8;
        bytes[start + 16..start + 16 + record.name.len()].copy_from_slice(record.name.as_bytes());
        let checksum = crc32(&bytes[start..start + record_len]);
        bytes[start + 12..start + 16].copy_from_slice(&checksum.to_le_bytes());
    }
    Ok(bytes)
}

fn validate_name(name: &str) -> Result<(), DirectoryError> {
    if name.is_empty()
        || name.len() > 255
        || name.contains('/')
        || name.contains('\0')
        || name == "."
        || name == ".."
    {
        return Err(DirectoryError::InvalidName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn round_trip() {
        let records = vec![DirectoryRecord {
            inode: 7,
            kind: InodeKind::Regular,
            name: "hello".to_string(),
        }];
        let bytes = encode_directory(&records).unwrap();
        assert_eq!(parse_directory(&bytes).unwrap(), records);
    }
}
