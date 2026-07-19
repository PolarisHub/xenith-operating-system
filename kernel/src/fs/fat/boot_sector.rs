//! FAT32 BIOS parameter block parsing and geometry validation.

use core::fmt;

pub const BOOT_SECTOR_SIZE: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootSectorError {
    Truncated,
    BadSignature,
    InvalidBytesPerSector,
    InvalidSectorsPerCluster,
    InvalidReservedSectors,
    InvalidFatCount,
    InvalidFatSize,
    InvalidTotalSectors,
    InvalidRootCluster,
    UnsupportedVersion,
    NotFat32,
    GeometryOverflow,
}

impl fmt::Display for BootSectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Truncated => "truncated FAT boot sector",
            Self::BadSignature => "missing FAT boot signature",
            Self::InvalidBytesPerSector => "invalid FAT bytes-per-sector value",
            Self::InvalidSectorsPerCluster => "invalid FAT sectors-per-cluster value",
            Self::InvalidReservedSectors => "invalid FAT reserved-sector count",
            Self::InvalidFatCount => "invalid FAT table count",
            Self::InvalidFatSize => "invalid FAT size",
            Self::InvalidTotalSectors => "invalid FAT total-sector count",
            Self::InvalidRootCluster => "invalid FAT32 root cluster",
            Self::UnsupportedVersion => "unsupported FAT32 version",
            Self::NotFat32 => "volume geometry is not FAT32",
            Self::GeometryOverflow => "FAT geometry overflows",
        };
        f.write_str(message)
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootSector {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fat_count: u8,
    pub total_sectors: u32,
    pub sectors_per_fat: u32,
    pub flags: u16,
    pub version: u16,
    pub root_cluster: u32,
    pub fs_info_sector: u16,
    pub backup_boot_sector: u16,
    pub volume_id: u32,
    pub volume_label: [u8; 11],
}

impl BootSector {
    pub fn parse(bytes: &[u8]) -> Result<Self, BootSectorError> {
        if bytes.len() < BOOT_SECTOR_SIZE {
            return Err(BootSectorError::Truncated);
        }
        if bytes[510] != 0x55 || bytes[511] != 0xaa {
            return Err(BootSectorError::BadSignature);
        }

        let bytes_per_sector = le16(bytes, 11);
        if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
            return Err(BootSectorError::InvalidBytesPerSector);
        }
        let sectors_per_cluster = bytes[13];
        if sectors_per_cluster == 0
            || !sectors_per_cluster.is_power_of_two()
            || sectors_per_cluster > 128
        {
            return Err(BootSectorError::InvalidSectorsPerCluster);
        }
        let reserved_sectors = le16(bytes, 14);
        if reserved_sectors == 0 {
            return Err(BootSectorError::InvalidReservedSectors);
        }
        let fat_count = bytes[16];
        if fat_count == 0 || fat_count > 2 {
            return Err(BootSectorError::InvalidFatCount);
        }
        // A FAT32 volume has no fixed root directory and does not use BPB_FATSz16.
        if le16(bytes, 17) != 0 || le16(bytes, 22) != 0 {
            return Err(BootSectorError::NotFat32);
        }
        let total_sectors = match le16(bytes, 19) {
            0 => le32(bytes, 32),
            value => u32::from(value),
        };
        if total_sectors == 0 {
            return Err(BootSectorError::InvalidTotalSectors);
        }
        let sectors_per_fat = le32(bytes, 36);
        if sectors_per_fat == 0 {
            return Err(BootSectorError::InvalidFatSize);
        }
        let version = le16(bytes, 42);
        if version != 0 {
            return Err(BootSectorError::UnsupportedVersion);
        }
        let root_cluster = le32(bytes, 44);
        if !(2..0x0fff_fff7).contains(&root_cluster) {
            return Err(BootSectorError::InvalidRootCluster);
        }

        let mut volume_label = [0u8; 11];
        volume_label.copy_from_slice(&bytes[71..82]);
        let boot = Self {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            fat_count,
            total_sectors,
            sectors_per_fat,
            flags: le16(bytes, 40),
            version,
            root_cluster,
            fs_info_sector: le16(bytes, 48),
            backup_boot_sector: le16(bytes, 50),
            volume_id: le32(bytes, 67),
            volume_label,
        };
        if boot.active_fat() >= boot.fat_count {
            return Err(BootSectorError::InvalidFatCount);
        }
        // The data area must contain enough clusters to be classified as FAT32.
        // Small synthetic images used by unit tests may opt into parsing the BPB
        // directly, but mounting rejects a FAT12/FAT16 geometry here.
        if boot.cluster_count()? < 65_525 {
            return Err(BootSectorError::NotFat32);
        }
        Ok(boot)
    }

    pub fn fat_start_sector(self) -> u64 {
        u64::from(self.reserved_sectors)
    }

    pub fn data_start_sector(self) -> Result<u64, BootSectorError> {
        u64::from(self.reserved_sectors)
            .checked_add(u64::from(self.fat_count) * u64::from(self.sectors_per_fat))
            .ok_or(BootSectorError::GeometryOverflow)
    }

    pub fn cluster_count(self) -> Result<u32, BootSectorError> {
        let data_start = self.data_start_sector()?;
        let data_sectors = u64::from(self.total_sectors)
            .checked_sub(data_start)
            .ok_or(BootSectorError::InvalidTotalSectors)?;
        u32::try_from(data_sectors / u64::from(self.sectors_per_cluster))
            .map_err(|_| BootSectorError::GeometryOverflow)
    }

    pub fn cluster_size(self) -> usize {
        usize::from(self.bytes_per_sector) * usize::from(self.sectors_per_cluster)
    }

    pub fn active_fat(self) -> u8 {
        if self.flags & 0x0080 == 0 {
            0
        } else {
            (self.flags & 0x000f) as u8
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_signature() {
        assert_eq!(
            BootSector::parse(&[0u8; BOOT_SECTOR_SIZE]),
            Err(BootSectorError::BadSignature)
        );
    }
}
