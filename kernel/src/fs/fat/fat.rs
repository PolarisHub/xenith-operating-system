//! FAT table traversal and sector/cluster access over a block device.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use super::boot_sector::{BootSector, BootSectorError, BOOT_SECTOR_SIZE};
use crate::devices::ahci::BlockDevice;
use crate::sync::SpinLock;

pub const BAD_CLUSTER: u32 = 0x0fff_fff7;
pub const END_OF_CHAIN: u32 = 0x0fff_fff8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatError {
    Io,
    InvalidBootSector(BootSectorError),
    UnsupportedSectorSize,
    InvalidCluster(u32),
    BadCluster(u32),
    ClusterLoop,
    CorruptDirectory,
    Overflow,
}

impl fmt::Display for FatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io => f.write_str("FAT block I/O failed"),
            Self::InvalidBootSector(error) => write!(f, "invalid FAT boot sector: {error}"),
            Self::UnsupportedSectorSize => f.write_str("block and FAT sector sizes differ"),
            Self::InvalidCluster(cluster) => write!(f, "invalid FAT cluster {cluster}"),
            Self::BadCluster(cluster) => write!(f, "bad FAT cluster {cluster}"),
            Self::ClusterLoop => f.write_str("FAT cluster chain loops"),
            Self::CorruptDirectory => f.write_str("corrupt FAT directory entry"),
            Self::Overflow => f.write_str("FAT geometry overflow"),
        }
    }
}

impl From<BootSectorError> for FatError {
    fn from(value: BootSectorError) -> Self {
        Self::InvalidBootSector(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterLink {
    Free,
    Next(u32),
    End,
    Bad,
}

pub struct FatVolume<D: BlockDevice> {
    device: SpinLock<D>,
    boot: BootSector,
}

impl<D: BlockDevice> FatVolume<D> {
    pub fn mount(mut device: D) -> Result<Self, FatError> {
        if D::SECTOR_SIZE != BOOT_SECTOR_SIZE {
            return Err(FatError::UnsupportedSectorSize);
        }
        let mut sector = [0u8; BOOT_SECTOR_SIZE];
        let transferred = device
            .read_blocks(0, &mut sector)
            .map_err(|_| FatError::Io)?;
        if transferred != sector.len() {
            return Err(FatError::Io);
        }
        let boot = BootSector::parse(&sector)?;
        if usize::from(boot.bytes_per_sector) != D::SECTOR_SIZE {
            return Err(FatError::UnsupportedSectorSize);
        }
        Ok(Self {
            device: SpinLock::new(device),
            boot,
        })
    }

    pub const fn boot_sector(&self) -> BootSector {
        self.boot
    }

    pub fn cluster_size(&self) -> usize {
        self.boot.cluster_size()
    }

    pub fn cluster_sector(&self, cluster: u32) -> Result<u64, FatError> {
        self.validate_cluster(cluster)?;
        self.boot
            .data_start_sector()?
            .checked_add(u64::from(cluster - 2) * u64::from(self.boot.sectors_per_cluster))
            .ok_or(FatError::Overflow)
    }

    fn validate_cluster(&self, cluster: u32) -> Result<(), FatError> {
        let maximum = self
            .boot
            .cluster_count()?
            .checked_add(2)
            .ok_or(FatError::Overflow)?;
        if cluster < 2 || cluster >= maximum {
            Err(FatError::InvalidCluster(cluster))
        } else {
            Ok(())
        }
    }

    pub fn read_cluster(&self, cluster: u32, buffer: &mut [u8]) -> Result<(), FatError> {
        if buffer.len() != self.cluster_size() {
            return Err(FatError::Overflow);
        }
        let lba = self.cluster_sector(cluster)?;
        let transferred = self
            .device
            .lock()
            .read_blocks(lba, buffer)
            .map_err(|_| FatError::Io)?;
        if transferred == buffer.len() {
            Ok(())
        } else {
            Err(FatError::Io)
        }
    }

    pub fn next_cluster(&self, cluster: u32) -> Result<ClusterLink, FatError> {
        self.validate_cluster(cluster)?;
        let fat_offset = u64::from(cluster) * 4;
        let sector = self
            .boot
            .fat_start_sector()
            .checked_add(u64::from(self.boot.active_fat()) * u64::from(self.boot.sectors_per_fat))
            .and_then(|start| start.checked_add(fat_offset / u64::from(self.boot.bytes_per_sector)))
            .ok_or(FatError::Overflow)?;
        let offset = (fat_offset % u64::from(self.boot.bytes_per_sector)) as usize;
        let mut bytes = vec![0u8; usize::from(self.boot.bytes_per_sector)];
        let transferred = self
            .device
            .lock()
            .read_blocks(sector, &mut bytes)
            .map_err(|_| FatError::Io)?;
        if transferred != bytes.len() || offset + 4 > bytes.len() {
            return Err(FatError::Io);
        }
        let value = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) & 0x0fff_ffff;
        match value {
            0 => Ok(ClusterLink::Free),
            BAD_CLUSTER => Ok(ClusterLink::Bad),
            END_OF_CHAIN..=0x0fff_ffff => Ok(ClusterLink::End),
            2..=0x0fff_fff6 => Ok(ClusterLink::Next(value)),
            _ => Err(FatError::InvalidCluster(value)),
        }
    }

    pub fn cluster_chain(&self, first: u32) -> Result<Vec<u32>, FatError> {
        self.validate_cluster(first)?;
        let maximum = self.boot.cluster_count()? as usize;
        let mut chain = Vec::new();
        let mut current = first;
        for _ in 0..maximum {
            chain.push(current);
            match self.next_cluster(current)? {
                ClusterLink::Next(next) => current = next,
                ClusterLink::End => return Ok(chain),
                ClusterLink::Bad => return Err(FatError::BadCluster(current)),
                ClusterLink::Free => return Err(FatError::InvalidCluster(current)),
            }
        }
        Err(FatError::ClusterLoop)
    }

    pub fn read_chain(&self, first: u32) -> Result<Vec<u8>, FatError> {
        let chain = self.cluster_chain(first)?;
        let total = chain
            .len()
            .checked_mul(self.cluster_size())
            .ok_or(FatError::Overflow)?;
        let mut bytes = vec![0u8; total];
        let cluster_size = self.cluster_size();
        for (index, cluster) in chain.into_iter().enumerate() {
            let start = index * cluster_size;
            self.read_cluster(cluster, &mut bytes[start..start + cluster_size])?;
        }
        Ok(bytes)
    }
}
