//! `newc` CPIO parser and ramfs population from boot modules.

extern crate alloc;

use core::{fmt, slice};

use xenith_boot::BootInfo;

use super::ramfs::RamFs;
use super::vfs::FsError;

const HEADER_LEN: usize = 110;
const NEWC_MAGIC: &[u8; 6] = b"070701";
const CRC_MAGIC: &[u8; 6] = b"070702";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitramfsError {
    Truncated { offset: usize },
    BadMagic { offset: usize },
    InvalidHex { offset: usize },
    InvalidName { offset: usize },
    ChecksumMismatch { offset: usize },
    SizeOverflow,
    NoArchive,
    Filesystem(FsError),
}

impl fmt::Display for InitramfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { offset } => write!(f, "truncated CPIO entry at {offset}"),
            Self::BadMagic { offset } => write!(f, "bad CPIO magic at {offset}"),
            Self::InvalidHex { offset } => write!(f, "invalid CPIO hex field at {offset}"),
            Self::InvalidName { offset } => write!(f, "invalid CPIO name at {offset}"),
            Self::ChecksumMismatch { offset } => {
                write!(f, "CPIO CRC checksum mismatch at {offset}")
            },
            Self::SizeOverflow => f.write_str("CPIO size overflows address space"),
            Self::NoArchive => f.write_str("no initramfs CPIO module was supplied"),
            Self::Filesystem(error) => write!(f, "initramfs population failed: {error}"),
        }
    }
}

impl From<FsError> for InitramfsError {
    fn from(value: FsError) -> Self {
        Self::Filesystem(value)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CpioEntry<'a> {
    pub name: &'a str,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub modified: u32,
    pub data: &'a [u8],
}

/// Counts of archive entries installed into each initramfs namespace.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PopulationStats {
    pub native_entries: usize,
    pub windows_entries: usize,
}

impl PopulationStats {
    pub const fn total(self) -> usize {
        self.native_entries + self.windows_entries
    }
}

impl CpioEntry<'_> {
    pub const fn file_type(&self) -> u32 {
        self.mode & 0o170000
    }

    pub const fn permissions(&self) -> u32 {
        self.mode & 0o7777
    }
}

pub struct CpioNewc<'a> {
    image: &'a [u8],
    offset: usize,
    finished: bool,
}

impl<'a> CpioNewc<'a> {
    pub const fn new(image: &'a [u8]) -> Self {
        Self {
            image,
            offset: 0,
            finished: false,
        }
    }
}

fn parse_hex(field: &[u8], offset: usize) -> Result<u32, InitramfsError> {
    let mut value = 0u32;
    for (index, byte) in field.iter().copied().enumerate() {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'f' => u32::from(byte - b'a') + 10,
            b'A'..=b'F' => u32::from(byte - b'A') + 10,
            _ => {
                return Err(InitramfsError::InvalidHex {
                    offset: offset + index,
                })
            },
        };
        value = value
            .checked_mul(16)
            .and_then(|number| number.checked_add(digit))
            .ok_or(InitramfsError::SizeOverflow)?;
    }
    Ok(value)
}

fn align_four(value: usize) -> Result<usize, InitramfsError> {
    value
        .checked_add(3)
        .map(|number| number & !3)
        .ok_or(InitramfsError::SizeOverflow)
}

impl<'a> Iterator for CpioNewc<'a> {
    type Item = Result<CpioEntry<'a>, InitramfsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished || self.offset == self.image.len() {
            return None;
        }
        let start = self.offset;
        let header_end = match start.checked_add(HEADER_LEN) {
            Some(end) if end <= self.image.len() => end,
            _ => {
                self.finished = true;
                return Some(Err(InitramfsError::Truncated { offset: start }));
            },
        };
        let header = &self.image[start..header_end];
        if &header[..6] != NEWC_MAGIC && &header[..6] != CRC_MAGIC {
            self.finished = true;
            return Some(Err(InitramfsError::BadMagic { offset: start }));
        }

        let mode = match parse_hex(&header[14..22], start + 14) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        let uid = match parse_hex(&header[22..30], start + 22) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        let gid = match parse_hex(&header[30..38], start + 30) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        let modified = match parse_hex(&header[46..54], start + 46) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        let checksum = match parse_hex(&header[102..110], start + 102) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        let file_size = match parse_hex(&header[54..62], start + 54) {
            Ok(value) => value as usize,
            Err(error) => return Some(Err(error)),
        };
        let name_size = match parse_hex(&header[94..102], start + 94) {
            Ok(0) => {
                self.finished = true;
                return Some(Err(InitramfsError::InvalidName { offset: start }));
            },
            Ok(value) => value as usize,
            Err(error) => return Some(Err(error)),
        };

        let name_end = match header_end.checked_add(name_size) {
            Some(end) if end <= self.image.len() => end,
            _ => {
                self.finished = true;
                return Some(Err(InitramfsError::Truncated { offset: start }));
            },
        };
        let name_bytes = &self.image[header_end..name_end];
        if name_bytes.last().copied() != Some(0) {
            self.finished = true;
            return Some(Err(InitramfsError::InvalidName { offset: header_end }));
        }
        let name = match core::str::from_utf8(&name_bytes[..name_size - 1]) {
            Ok(name) if !name.contains('\0') => name,
            _ => {
                self.finished = true;
                return Some(Err(InitramfsError::InvalidName { offset: header_end }));
            },
        };
        if name == "TRAILER!!!" {
            self.finished = true;
            return None;
        }

        let data_start = match align_four(name_end) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        let data_end = match data_start.checked_add(file_size) {
            Some(end) if end <= self.image.len() => end,
            _ => {
                self.finished = true;
                return Some(Err(InitramfsError::Truncated { offset: start }));
            },
        };
        if &header[..6] == CRC_MAGIC {
            let actual = self.image[data_start..data_end]
                .iter()
                .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)));
            if actual != checksum {
                self.finished = true;
                return Some(Err(InitramfsError::ChecksumMismatch { offset: start }));
            }
        }
        self.offset = match align_four(data_end) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        Some(Ok(CpioEntry {
            name,
            mode,
            uid,
            gid,
            modified,
            data: &self.image[data_start..data_end],
        }))
    }
}

fn safe_archive_path(name: &str) -> Result<&str, InitramfsError> {
    let name = name.trim_start_matches("./").trim_start_matches('/');
    if name.is_empty()
        || name
            .split('/')
            .any(|part| part == ".." || part.contains('\0'))
    {
        return Err(InitramfsError::InvalidName { offset: 0 });
    }
    Ok(name)
}

fn populate_namespaces(
    image: &[u8],
    native: &RamFs,
    windows: Option<&RamFs>,
) -> Result<PopulationStats, InitramfsError> {
    let mut stats = PopulationStats::default();
    for entry in CpioNewc::new(image) {
        let entry = entry?;
        let name = safe_archive_path(entry.name)?;
        if name == "." {
            continue;
        }

        let (ramfs, relative_name, windows_entry) = match windows {
            Some(windows) if name == xenith_abi::WINDOWS_INITRAMFS_ROOT => (windows, ".", true),
            Some(windows)
                if name
                    .strip_prefix(xenith_abi::WINDOWS_INITRAMFS_ROOT)
                    .is_some_and(|suffix| suffix.starts_with('/')) =>
            {
                let relative = name
                    .strip_prefix(xenith_abi::WINDOWS_INITRAMFS_ROOT)
                    .and_then(|suffix| suffix.strip_prefix('/'))
                    .ok_or(InitramfsError::InvalidName { offset: 0 })?;
                if relative.is_empty() {
                    return Err(InitramfsError::InvalidName { offset: 0 });
                }
                (windows, relative, true)
            },
            _ => (native, name, false),
        };

        let path = if relative_name == "." {
            alloc::string::String::from("/")
        } else {
            alloc::format!("/{relative_name}")
        };
        let node = match entry.file_type() {
            0o040000 => ramfs.mkdir_all(&path, entry.permissions())?,
            0o100000 | 0 => ramfs.write_file(&path, entry.data, entry.permissions())?,
            0o120000 => {
                let target = core::str::from_utf8(entry.data)
                    .map_err(|_| InitramfsError::InvalidName { offset: 0 })?;
                ramfs.symlink(&path, target, entry.permissions())?
            },
            // Device nodes require a device registry binding; retaining a
            // fabricated byte file would be more misleading than skipping it.
            0o020000 | 0o060000 | 0o010000 => continue,
            _ => continue,
        };
        node.inode().update_metadata(|metadata| {
            metadata.mode = entry.permissions();
            metadata.uid = entry.uid;
            metadata.gid = entry.gid;
            metadata.modified = u64::from(entry.modified);
            metadata.changed = u64::from(entry.modified);
        });
        let count = if windows_entry {
            &mut stats.windows_entries
        } else {
            &mut stats.native_entries
        };
        *count = count.checked_add(1).ok_or(InitramfsError::SizeOverflow)?;
    }
    Ok(stats)
}

/// Populate one filesystem without applying namespace routing.
pub fn populate(image: &[u8], ramfs: &RamFs) -> Result<usize, InitramfsError> {
    Ok(populate_namespaces(image, ramfs, None)?.native_entries)
}

/// Populate native and Windows filesystems from one archive.
///
/// Entries named by [`xenith_abi::WINDOWS_INITRAMFS_ROOT`] or beginning with
/// that component plus `/` are installed into
/// `windows`, with that prefix removed. Every other entry is installed into
/// `native`.
pub fn populate_split(
    image: &[u8],
    native: &RamFs,
    windows: &RamFs,
) -> Result<PopulationStats, InitramfsError> {
    populate_namespaces(image, native, Some(windows))
}

fn archive_from_boot(
    raw_boot_info: &'static limine::BootInfo,
) -> Result<&'static [u8], InitramfsError> {
    let boot_info = BootInfo::new(raw_boot_info);
    for module in boot_info.modules() {
        if module.len < NEWC_MAGIC.len() as u64 {
            continue;
        }
        let len = usize::try_from(module.len).map_err(|_| InitramfsError::SizeOverflow)?;
        let address = boot_info.phys_to_virt(module.start).as_u64() as *const u8;
        // SAFETY: Limine promises each module is a contiguous `len`-byte
        // physical allocation retained for the kernel lifetime. `phys_to_virt`
        // maps its first byte through the HHDM, so this read-only slice covers
        // exactly that allocation.
        let image = unsafe { slice::from_raw_parts(address, len) };
        if image.starts_with(NEWC_MAGIC) || image.starts_with(CRC_MAGIC) {
            return Ok(image);
        }
    }
    Err(InitramfsError::NoArchive)
}

pub fn load_from_boot(
    raw_boot_info: &'static limine::BootInfo,
    ramfs: &RamFs,
) -> Result<usize, InitramfsError> {
    populate(archive_from_boot(raw_boot_info)?, ramfs)
}

pub fn load_split_from_boot(
    raw_boot_info: &'static limine::BootInfo,
    native: &RamFs,
    windows: &RamFs,
) -> Result<PopulationStats, InitramfsError> {
    populate_split(archive_from_boot(raw_boot_info)?, native, windows)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    fn field(value: u32) -> [u8; 8] {
        let mut out = [b'0'; 8];
        let digits = b"0123456789abcdef";
        for index in 0..8 {
            out[7 - index] = digits[((value >> (index * 4)) & 0xf) as usize];
        }
        out
    }

    fn append_entry(image: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
        let mut header = [b'0'; HEADER_LEN];
        header[..6].copy_from_slice(NEWC_MAGIC);
        header[14..22].copy_from_slice(&field(mode));
        header[38..46].copy_from_slice(&field(1));
        header[54..62].copy_from_slice(&field(data.len() as u32));
        header[94..102].copy_from_slice(&field((name.len() + 1) as u32));
        image.extend_from_slice(&header);
        image.extend_from_slice(name.as_bytes());
        image.push(0);
        while !image.len().is_multiple_of(4) {
            image.push(0);
        }
        image.extend_from_slice(data);
        while !image.len().is_multiple_of(4) {
            image.push(0);
        }
    }

    #[test]
    fn rejects_truncated_header() {
        assert!(matches!(
            CpioNewc::new(b"070701").next().unwrap(),
            Err(InitramfsError::Truncated { .. })
        ));
    }

    #[test]
    fn hex_parser_accepts_both_cases() {
        assert_eq!(parse_hex(b"0000aBcD", 0).unwrap(), 0xabcd);
        assert_eq!(field(0x1234), *b"00001234");
    }

    #[test]
    fn populates_ramfs_from_newc_archive() {
        let mut image = Vec::new();
        append_entry(&mut image, "bin", 0o040755, &[]);
        append_entry(&mut image, "bin/init", 0o100755, b"ELF");
        append_entry(&mut image, "TRAILER!!!", 0, &[]);
        let fs = RamFs::new();
        assert_eq!(populate(&image, &fs).unwrap(), 2);
        let mut bytes = [0u8; 3];
        assert_eq!(
            fs.node("/bin/init")
                .unwrap()
                .read_at(0, &mut bytes)
                .unwrap(),
            3
        );
        assert_eq!(&bytes, b"ELF");
    }

    #[test]
    fn routes_windows_entries_into_separate_case_insensitive_ramfs() {
        let mut image = Vec::new();
        append_entry(&mut image, "etc", 0o040755, &[]);
        append_entry(&mut image, "etc/native.conf", 0o100644, b"native");
        append_entry(&mut image, "win", 0o040755, &[]);
        append_entry(&mut image, "win/C/Users/Xenith", 0o040755, &[]);
        append_entry(
            &mut image,
            "win/C/Users/Xenith/Payload.TXT",
            0o100644,
            b"windows",
        );
        append_entry(
            &mut image,
            "win/C/Users/Xenith/payload-link",
            0o120777,
            b"Payload.TXT",
        );
        append_entry(&mut image, "TRAILER!!!", 0, &[]);

        let native = RamFs::new();
        let windows = RamFs::new_ascii_case_insensitive();
        let stats = populate_split(&image, &native, &windows).unwrap();

        assert_eq!(stats, PopulationStats {
            native_entries: 2,
            windows_entries: 4,
        });
        assert_eq!(stats.total(), 6);
        assert_eq!(native.node("/win").err(), Some(FsError::NotFound));
        assert!(native.node("/etc/native.conf").is_ok());

        let mut bytes = [0u8; 7];
        let file = windows
            .node("/c/users/xENITH/payload.txt")
            .expect("Windows path should use ASCII-insensitive lookup");
        assert_eq!(file.read_at(0, &mut bytes).unwrap(), bytes.len());
        assert_eq!(&bytes, b"windows");
        assert_eq!(
            windows
                .node("/C/Users/Xenith/payload-link")
                .unwrap()
                .read_link()
                .unwrap(),
            "Payload.TXT"
        );
    }
}
