//! Checksummed variable-length directories using the shared XenithFS format.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub use xenith_fs_format::MAX_DIRECTORY_SIZE;
use xenith_fs_format::{DirectoryError, InodeKind};

use super::XenithFsError;
use crate::fs::inode::FileType;

#[derive(Clone, Debug)]
pub struct DirectoryRecord {
    pub inode: u64,
    pub kind: FileType,
    pub name: String,
}

fn kind_to_format(kind: FileType) -> Result<InodeKind, XenithFsError> {
    match kind {
        FileType::Regular => Ok(InodeKind::Regular),
        FileType::Directory => Ok(InodeKind::Directory),
        FileType::Symlink => Ok(InodeKind::Symlink),
        FileType::CharacterDevice | FileType::BlockDevice => Err(XenithFsError::Unsupported),
    }
}

fn kind_from_format(kind: InodeKind) -> FileType {
    match kind {
        InodeKind::Regular => FileType::Regular,
        InodeKind::Directory => FileType::Directory,
        InodeKind::Symlink => FileType::Symlink,
    }
}

fn map_parse_error(error: DirectoryError) -> XenithFsError {
    if error == DirectoryError::BadChecksum {
        XenithFsError::Checksum
    } else {
        XenithFsError::CorruptDirectory
    }
}

fn map_encode_error(error: DirectoryError) -> XenithFsError {
    match error {
        DirectoryError::TooLarge | DirectoryError::TooManyEntries => XenithFsError::NoSpace,
        DirectoryError::BadChecksum
        | DirectoryError::Truncated
        | DirectoryError::InvalidRecordLength
        | DirectoryError::InvalidInode
        | DirectoryError::InvalidKind
        | DirectoryError::InvalidName
        | DirectoryError::DuplicateName => XenithFsError::CorruptDirectory,
    }
}

pub fn parse_directory(bytes: &[u8]) -> Result<Vec<DirectoryRecord>, XenithFsError> {
    xenith_fs_format::parse_directory(bytes)
        .map_err(map_parse_error)
        .map(|records| {
            records
                .into_iter()
                .map(|record| DirectoryRecord {
                    inode: record.inode,
                    kind: kind_from_format(record.kind),
                    name: record.name,
                })
                .collect()
        })
}

pub fn encode_directory(records: &[DirectoryRecord]) -> Result<Vec<u8>, XenithFsError> {
    let records = records
        .iter()
        .map(|record| {
            Ok(xenith_fs_format::DirectoryRecord {
                inode: record.inode,
                kind: kind_to_format(record.kind)?,
                name: record.name.clone(),
            })
        })
        .collect::<Result<Vec<_>, XenithFsError>>()?;
    xenith_fs_format::encode_directory(&records).map_err(map_encode_error)
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;

    #[test]
    fn directory_round_trip() {
        let records = vec![DirectoryRecord {
            inode: 7,
            kind: FileType::Regular,
            name: "hello".to_string(),
        }];
        let bytes = encode_directory(&records).unwrap();
        let decoded = parse_directory(&bytes).unwrap();
        assert_eq!(decoded[0].inode, 7);
        assert_eq!(decoded[0].name, "hello");
    }
}
