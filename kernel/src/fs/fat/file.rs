//! Reads from FAT cluster chains with ordinary byte offsets.

extern crate alloc;

use alloc::vec;

use super::dir::FatDirEntry;
use super::fat::{ClusterLink, FatError, FatVolume};
use crate::devices::ahci::BlockDevice;

pub fn read_file<D: BlockDevice>(
    volume: &FatVolume<D>,
    entry: &FatDirEntry,
    offset: u64,
    output: &mut [u8],
) -> Result<usize, FatError> {
    if entry.is_directory() {
        return Err(FatError::CorruptDirectory);
    }
    let file_size = u64::from(entry.size);
    if offset >= file_size || output.is_empty() {
        return Ok(0);
    }
    if entry.first_cluster < 2 {
        return if entry.size == 0 {
            Ok(0)
        } else {
            Err(FatError::InvalidCluster(entry.first_cluster))
        };
    }

    let cluster_size = volume.cluster_size();
    let mut skip = usize::try_from(offset / cluster_size as u64).map_err(|_| FatError::Overflow)?;
    let mut intra = (offset % cluster_size as u64) as usize;
    let wanted = output
        .len()
        .min(usize::try_from(file_size - offset).map_err(|_| FatError::Overflow)?);
    let mut cluster = entry.first_cluster;
    let maximum = volume.boot_sector().cluster_count()? as usize;

    for _ in 0..maximum {
        if skip == 0 {
            break;
        }
        cluster = match volume.next_cluster(cluster)? {
            ClusterLink::Next(next) => next,
            ClusterLink::End => return Err(FatError::CorruptDirectory),
            ClusterLink::Bad => return Err(FatError::BadCluster(cluster)),
            ClusterLink::Free => return Err(FatError::InvalidCluster(cluster)),
        };
        skip -= 1;
    }
    if skip != 0 {
        return Err(FatError::ClusterLoop);
    }

    let mut scratch = vec![0u8; cluster_size];
    let mut copied = 0usize;
    for _ in 0..maximum {
        volume.read_cluster(cluster, &mut scratch)?;
        let available = cluster_size - intra;
        let count = available.min(wanted - copied);
        output[copied..copied + count].copy_from_slice(&scratch[intra..intra + count]);
        copied += count;
        if copied == wanted {
            return Ok(copied);
        }
        intra = 0;
        cluster = match volume.next_cluster(cluster)? {
            ClusterLink::Next(next) => next,
            ClusterLink::End => return Ok(copied),
            ClusterLink::Bad => return Err(FatError::BadCluster(cluster)),
            ClusterLink::Free => return Err(FatError::InvalidCluster(cluster)),
        };
    }
    Err(FatError::ClusterLoop)
}
