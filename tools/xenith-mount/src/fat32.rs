use std::collections::HashSet;

use crate::path::{child_path, ImagePath};
use crate::{Entry, EntryKind, Error, FilesystemKind, Inspection, MAX_FILE_BYTES};

const MAX_DIRECTORY_BYTES: usize = 16 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 65_536;
const MAX_LFN_SLOTS: usize = 20;
const FAT32_MASK: u32 = 0x0fff_ffff;
const FAT32_BAD_CLUSTER: u32 = 0x0fff_fff7;
const FAT32_END_OF_CHAIN: u32 = 0x0fff_fff8;

pub(crate) struct Fat32<'a> {
    image: &'a [u8],
    bytes_per_sector: usize,
    cluster_size: usize,
    total_bytes: usize,
    fat_offset: usize,
    fat_bytes: usize,
    data_offset: usize,
    cluster_count: u32,
    max_cluster: u32,
    root_cluster: u32,
    label: Option<String>,
}

#[derive(Clone)]
struct DirectoryEntry {
    name: String,
    kind: EntryKind,
    cluster: u32,
    size: u32,
}

impl<'a> Fat32<'a> {
    pub(crate) fn has_signature(image: &[u8]) -> bool {
        image.get(82..90) == Some(b"FAT32   ")
    }

    pub(crate) fn parse(image: &'a [u8]) -> Result<Self, Error> {
        if image.len() < 512 {
            return Err(Error::Truncated("FAT32 boot sector"));
        }
        if image.get(510..512) != Some(&[0x55, 0xaa]) {
            return Err(Error::Corrupt("FAT32 boot signature"));
        }
        if !Self::has_signature(image) {
            return Err(Error::Corrupt("FAT32 type signature"));
        }
        let bytes_per_sector = usize::from(read_u16(image, 11)?);
        if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
            return Err(Error::Unsupported("FAT32 sector size"));
        }
        let sectors_per_cluster = usize::from(image[13]);
        if sectors_per_cluster == 0
            || !sectors_per_cluster.is_power_of_two()
            || sectors_per_cluster > 128
        {
            return Err(Error::Corrupt("FAT32 sectors per cluster"));
        }
        let reserved_sectors = usize::from(read_u16(image, 14)?);
        let fat_count = usize::from(image[16]);
        let root_entries = read_u16(image, 17)?;
        let fat16_sectors = read_u16(image, 22)?;
        let fat_sectors =
            usize::try_from(read_u32(image, 36)?).map_err(|_| Error::Corrupt("FAT32 FAT size"))?;
        if reserved_sectors == 0
            || fat_count == 0
            || fat_count > 2
            || root_entries != 0
            || fat16_sectors != 0
            || fat_sectors == 0
            || read_u16(image, 42)? != 0
        {
            return Err(Error::Corrupt("FAT32 geometry"));
        }

        let short_total = u64::from(read_u16(image, 19)?);
        let total_sectors = if short_total == 0 {
            u64::from(read_u32(image, 32)?)
        } else {
            short_total
        };
        if total_sectors == 0 {
            return Err(Error::Corrupt("FAT32 total sectors"));
        }
        let total_bytes_u64 = total_sectors
            .checked_mul(bytes_per_sector as u64)
            .ok_or(Error::Corrupt("FAT32 image size"))?;
        if total_bytes_u64 > image.len() as u64 {
            return Err(Error::Truncated("FAT32 image"));
        }
        let total_bytes =
            usize::try_from(total_bytes_u64).map_err(|_| Error::Unsupported("FAT32 image size"))?;

        let all_fat_sectors = fat_count
            .checked_mul(fat_sectors)
            .ok_or(Error::Corrupt("FAT32 FAT geometry"))?;
        let first_data_sector = reserved_sectors
            .checked_add(all_fat_sectors)
            .ok_or(Error::Corrupt("FAT32 data geometry"))?;
        let total_sectors_usize =
            usize::try_from(total_sectors).map_err(|_| Error::Unsupported("FAT32 sector count"))?;
        if first_data_sector >= total_sectors_usize {
            return Err(Error::Corrupt("FAT32 data geometry"));
        }
        let data_sectors = total_sectors_usize - first_data_sector;
        let cluster_count_usize = data_sectors / sectors_per_cluster;
        if cluster_count_usize == 0 || cluster_count_usize > 0x0fff_ffed {
            return Err(Error::Corrupt("FAT32 cluster count"));
        }
        let cluster_count = u32::try_from(cluster_count_usize)
            .map_err(|_| Error::Corrupt("FAT32 cluster count"))?;
        let max_cluster = cluster_count
            .checked_add(1)
            .ok_or(Error::Corrupt("FAT32 cluster count"))?;
        let cluster_size = bytes_per_sector
            .checked_mul(sectors_per_cluster)
            .ok_or(Error::Corrupt("FAT32 cluster size"))?;

        let extended_flags = read_u16(image, 40)?;
        let active_fat = if extended_flags & 0x0080 != 0 {
            usize::from(extended_flags & 0x000f)
        } else {
            0
        };
        if active_fat >= fat_count {
            return Err(Error::Corrupt("FAT32 active FAT"));
        }
        let active_fat_sector = reserved_sectors
            .checked_add(
                active_fat
                    .checked_mul(fat_sectors)
                    .ok_or(Error::Corrupt("FAT32 FAT offset"))?,
            )
            .ok_or(Error::Corrupt("FAT32 FAT offset"))?;
        let fat_offset = active_fat_sector
            .checked_mul(bytes_per_sector)
            .ok_or(Error::Corrupt("FAT32 FAT offset"))?;
        let fat_bytes = fat_sectors
            .checked_mul(bytes_per_sector)
            .ok_or(Error::Corrupt("FAT32 FAT size"))?;
        let required_fat_bytes = usize::try_from(u64::from(max_cluster) + 1)
            .ok()
            .and_then(|entries| entries.checked_mul(4))
            .ok_or(Error::Corrupt("FAT32 FAT capacity"))?;
        if required_fat_bytes > fat_bytes
            || fat_offset
                .checked_add(fat_bytes)
                .is_none_or(|end| end > total_bytes)
        {
            return Err(Error::Corrupt("FAT32 FAT capacity"));
        }
        let data_offset = first_data_sector
            .checked_mul(bytes_per_sector)
            .ok_or(Error::Corrupt("FAT32 data offset"))?;
        let root_cluster = read_u32(image, 44)? & FAT32_MASK;
        if root_cluster < 2 || root_cluster > max_cluster {
            return Err(Error::Corrupt("FAT32 root cluster"));
        }

        let label = parse_label(&image[71..82])?;
        let filesystem = Self {
            image,
            bytes_per_sector,
            cluster_size,
            total_bytes,
            fat_offset,
            fat_bytes,
            data_offset,
            cluster_count,
            max_cluster,
            root_cluster,
            label,
        };
        // Validate that the root starts on an allocated chain.
        filesystem.next_cluster(root_cluster)?;
        Ok(filesystem)
    }

    pub(crate) fn inspect(&self) -> Inspection {
        Inspection {
            filesystem: FilesystemKind::Fat32,
            label: self.label.clone(),
            logical_block_size: self.bytes_per_sector as u32,
            total_bytes: self.total_bytes as u64,
            root_identifier: u64::from(self.root_cluster),
        }
    }

    pub(crate) fn list(&self, path: &ImagePath) -> Result<Vec<Entry>, Error> {
        let cluster = self.resolve_directory(path)?;
        self.read_directory(cluster)?
            .into_iter()
            .map(|entry| {
                Ok(Entry {
                    path: child_path(path.display(), &entry.name),
                    name: entry.name,
                    kind: entry.kind,
                    size: u64::from(entry.size),
                    identifier: u64::from(entry.cluster),
                })
            })
            .collect()
    }

    pub(crate) fn read_file(&self, path: &ImagePath) -> Result<Vec<u8>, Error> {
        if path.components().is_empty() {
            return Err(Error::IsDirectory(path.display().to_owned()));
        }
        let mut cluster = self.root_cluster;
        let mut result = None;
        for (index, component) in path.components().iter().enumerate() {
            let entry = find_entry(self.read_directory(cluster)?, component)
                .ok_or_else(|| Error::NotFound(path.display().to_owned()))?;
            if index + 1 == path.components().len() {
                result = Some(entry);
                break;
            }
            if entry.kind != EntryKind::Directory {
                return Err(Error::NotDirectory(path.display().to_owned()));
            }
            cluster = entry.cluster;
        }
        let entry = result.ok_or_else(|| Error::NotFound(path.display().to_owned()))?;
        if entry.kind == EntryKind::Directory {
            return Err(Error::IsDirectory(path.display().to_owned()));
        }
        self.read_file_chain(entry.cluster, u64::from(entry.size))
    }

    fn resolve_directory(&self, path: &ImagePath) -> Result<u32, Error> {
        let mut cluster = self.root_cluster;
        for component in path.components() {
            let entry = find_entry(self.read_directory(cluster)?, component)
                .ok_or_else(|| Error::NotFound(path.display().to_owned()))?;
            if entry.kind != EntryKind::Directory {
                return Err(Error::NotDirectory(path.display().to_owned()));
            }
            cluster = entry.cluster;
        }
        Ok(cluster)
    }

    fn read_directory(&self, start_cluster: u32) -> Result<Vec<DirectoryEntry>, Error> {
        let bytes = self.read_directory_chain(start_cluster)?;
        let mut output = Vec::new();
        let mut names = HashSet::new();
        let mut lfn_slots = Vec::<[u8; 32]>::new();

        for raw in bytes.as_chunks::<32>().0 {
            if raw[0] == 0x00 {
                break;
            }
            if raw[0] == 0xe5 {
                lfn_slots.clear();
                continue;
            }
            if raw[11] == 0x0f {
                if lfn_slots.len() >= MAX_LFN_SLOTS {
                    return Err(Error::LimitExceeded("FAT32 long filename slots"));
                }
                let mut slot = [0u8; 32];
                slot.copy_from_slice(raw);
                lfn_slots.push(slot);
                continue;
            }

            let attributes = raw[11];
            if attributes & 0xc0 != 0 {
                return Err(Error::Corrupt("FAT32 directory attributes"));
            }
            if attributes & 0x08 != 0 {
                lfn_slots.clear();
                continue;
            }
            let short_name = decode_short_name(raw)?;
            let name = decode_lfn(&lfn_slots, raw).unwrap_or(short_name);
            lfn_slots.clear();
            if name == "." || name == ".." {
                continue;
            }
            validate_name(&name)?;
            if output.len() >= MAX_DIRECTORY_ENTRIES {
                return Err(Error::LimitExceeded("FAT32 directory entries"));
            }
            if !names.insert(name.to_ascii_uppercase()) {
                return Err(Error::Corrupt("duplicate FAT32 directory name"));
            }
            let cluster = (u32::from(read_u16(raw, 20)?) << 16) | u32::from(read_u16(raw, 26)?);
            let cluster = cluster & FAT32_MASK;
            let size = read_u32(raw, 28)?;
            let kind = if attributes & 0x10 != 0 {
                EntryKind::Directory
            } else {
                EntryKind::File
            };
            if (kind == EntryKind::Directory || size != 0)
                && (cluster < 2 || cluster > self.max_cluster)
            {
                return Err(Error::Corrupt("FAT32 directory entry cluster"));
            }
            output.push(DirectoryEntry {
                name,
                kind,
                cluster,
                size,
            });
        }
        Ok(output)
    }

    fn read_directory_chain(&self, start_cluster: u32) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        let mut visited = HashSet::new();
        let mut cluster = start_cluster;
        loop {
            if !visited.insert(cluster) {
                return Err(Error::Corrupt("cyclic FAT32 directory chain"));
            }
            if visited.len() > self.cluster_count as usize {
                return Err(Error::Corrupt("FAT32 directory chain length"));
            }
            if output
                .len()
                .checked_add(self.cluster_size)
                .is_none_or(|length| length > MAX_DIRECTORY_BYTES)
            {
                return Err(Error::LimitExceeded("FAT32 directory bytes"));
            }
            let bytes = self.cluster_bytes(cluster)?;
            output.extend_from_slice(bytes);
            if bytes.as_chunks::<32>().0.iter().any(|entry| entry[0] == 0) {
                return Ok(output);
            }
            match self.next_cluster(cluster)? {
                Some(next) => cluster = next,
                None => return Ok(output),
            }
        }
    }

    fn read_file_chain(&self, start_cluster: u32, size: u64) -> Result<Vec<u8>, Error> {
        if size > MAX_FILE_BYTES {
            return Err(Error::LimitExceeded("file size"));
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        if start_cluster < 2 || start_cluster > self.max_cluster {
            return Err(Error::Corrupt("FAT32 file cluster"));
        }
        let output_len = usize::try_from(size).map_err(|_| Error::LimitExceeded("file size"))?;
        let needed_clusters = output_len.div_ceil(self.cluster_size);
        if needed_clusters > self.cluster_count as usize {
            return Err(Error::Corrupt("FAT32 file chain length"));
        }
        let mut output = Vec::with_capacity(output_len);
        let mut visited = HashSet::new();
        let mut cluster = start_cluster;
        for index in 0..needed_clusters {
            if !visited.insert(cluster) {
                return Err(Error::Corrupt("cyclic FAT32 file chain"));
            }
            let remaining = output_len - output.len();
            let bytes = self.cluster_bytes(cluster)?;
            output.extend_from_slice(&bytes[..remaining.min(bytes.len())]);
            if index + 1 != needed_clusters {
                cluster = self
                    .next_cluster(cluster)?
                    .ok_or(Error::Truncated("FAT32 file chain"))?;
            }
        }
        Ok(output)
    }

    fn next_cluster(&self, cluster: u32) -> Result<Option<u32>, Error> {
        if cluster < 2 || cluster > self.max_cluster {
            return Err(Error::Corrupt("FAT32 cluster number"));
        }
        let entry_offset = usize::try_from(cluster)
            .ok()
            .and_then(|value| value.checked_mul(4))
            .ok_or(Error::Corrupt("FAT32 FAT entry offset"))?;
        if entry_offset
            .checked_add(4)
            .is_none_or(|end| end > self.fat_bytes)
        {
            return Err(Error::Corrupt("FAT32 FAT entry"));
        }
        let value = read_u32(self.image, self.fat_offset + entry_offset)? & FAT32_MASK;
        if value >= FAT32_END_OF_CHAIN {
            return Ok(None);
        }
        if value == FAT32_BAD_CLUSTER
            || value < 2
            || value > self.max_cluster
            || value >= 0x0fff_fff0
        {
            return Err(Error::Corrupt("FAT32 cluster chain"));
        }
        Ok(Some(value))
    }

    fn cluster_bytes(&self, cluster: u32) -> Result<&'a [u8], Error> {
        if cluster < 2 || cluster > self.max_cluster {
            return Err(Error::Corrupt("FAT32 cluster number"));
        }
        let index =
            usize::try_from(cluster - 2).map_err(|_| Error::Corrupt("FAT32 cluster offset"))?;
        let offset = index
            .checked_mul(self.cluster_size)
            .and_then(|relative| self.data_offset.checked_add(relative))
            .ok_or(Error::Corrupt("FAT32 cluster offset"))?;
        let end = offset
            .checked_add(self.cluster_size)
            .ok_or(Error::Corrupt("FAT32 cluster offset"))?;
        if end > self.total_bytes {
            return Err(Error::Truncated("FAT32 cluster"));
        }
        self.image
            .get(offset..end)
            .ok_or(Error::Truncated("FAT32 cluster"))
    }
}

fn find_entry(entries: Vec<DirectoryEntry>, name: &str) -> Option<DirectoryEntry> {
    entries
        .into_iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(name))
}

fn parse_label(bytes: &[u8]) -> Result<Option<String>, Error> {
    if !bytes.is_ascii() {
        return Err(Error::Corrupt("FAT32 volume label"));
    }
    let label = std::str::from_utf8(bytes)
        .map_err(|_| Error::Corrupt("FAT32 volume label"))?
        .trim_end_matches(' ');
    if label.is_empty() || label == "NO NAME" {
        Ok(None)
    } else {
        Ok(Some(label.to_owned()))
    }
}

fn decode_short_name(entry: &[u8]) -> Result<String, Error> {
    let mut name = entry
        .get(..11)
        .ok_or(Error::Truncated("FAT32 directory entry"))?
        .to_vec();
    if name[0] == 0x05 {
        name[0] = 0xe5;
    }
    let base_end = name[..8]
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(0, |index| index + 1);
    let extension_end = name[8..11]
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(0, |index| index + 1);
    if base_end == 0 {
        return Err(Error::Corrupt("FAT32 short filename"));
    }
    let lowercase_flags = entry[12];
    let mut base = decode_oem(&name[..base_end]);
    let mut extension = decode_oem(&name[8..8 + extension_end]);
    if lowercase_flags & 0x08 != 0 {
        base.make_ascii_lowercase();
    }
    if lowercase_flags & 0x10 != 0 {
        extension.make_ascii_lowercase();
    }
    if extension.is_empty() {
        Ok(base)
    } else {
        Ok(format!("{base}.{extension}"))
    }
}

fn decode_oem(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

fn decode_lfn(slots: &[[u8; 32]], short: &[u8]) -> Option<String> {
    if slots.is_empty() || slots.len() > MAX_LFN_SLOTS {
        return None;
    }
    let checksum = short_name_checksum(short.get(..11)?);
    for (index, slot) in slots.iter().enumerate() {
        let ordinal = usize::from(slot[0] & 0x1f);
        let expected = slots.len().checked_sub(index)?;
        let last_flag_valid = if index == 0 {
            slot[0] & 0x40 != 0
        } else {
            slot[0] & 0x40 == 0
        };
        if ordinal != expected
            || !last_flag_valid
            || slot[11] != 0x0f
            || slot[12] != 0
            || slot[13] != checksum
            || slot[26] != 0
            || slot[27] != 0
        {
            return None;
        }
    }

    let offsets = [1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    let mut units = Vec::with_capacity(slots.len() * offsets.len());
    let mut terminated = false;
    for slot in slots.iter().rev() {
        for offset in offsets {
            let unit = u16::from_le_bytes([slot[offset], slot[offset + 1]]);
            match unit {
                0x0000 => terminated = true,
                0xffff if terminated => {},
                _ if terminated => return None,
                _ => units.push(unit),
            }
        }
    }
    if units.is_empty() || units.len() > 255 {
        return None;
    }
    String::from_utf16(&units).ok()
}

fn short_name_checksum(name: &[u8]) -> u8 {
    name.iter()
        .fold(0u8, |sum, byte| sum.rotate_right(1).wrapping_add(*byte))
}

fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\0')
        || name.encode_utf16().count() > 255
    {
        return Err(Error::Corrupt("FAT32 filename"));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(Error::Truncated("FAT32 integer"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(Error::Truncated("FAT32 integer"))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}
