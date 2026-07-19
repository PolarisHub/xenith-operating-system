//! Testable bounds used by the freestanding BIOS loader and its packer.

#![no_std]

pub const BIOS_SECTOR_SIZE: u64 = 512;
pub const BIOS_MAX_TRANSFER_SECTORS: u64 = 127;
pub const STAGE2_LOAD_ADDRESS: u64 = 0x8000;
pub const KERNEL_STAGING_ADDRESS: u64 = 0x0200_0000;
pub const KERNEL_STAGING_CAPACITY: u64 = 32 * 1024 * 1024;
pub const INITRD_LOAD_ADDRESS: u64 = 0x0600_0000;
pub const INITRD_CAPACITY: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundsError {
    Empty,
    Overflow,
    TooLarge,
}

pub fn sector_count(byte_len: u64) -> Result<u64, BoundsError> {
    if byte_len == 0 {
        return Err(BoundsError::Empty);
    }
    byte_len
        .checked_add(BIOS_SECTOR_SIZE - 1)
        .map(|value| value / BIOS_SECTOR_SIZE)
        .ok_or(BoundsError::Overflow)
}

pub fn checked_buffer(byte_len: u64, capacity: u64) -> Result<usize, BoundsError> {
    if byte_len == 0 {
        return Err(BoundsError::Empty);
    }
    if byte_len > capacity {
        return Err(BoundsError::TooLarge);
    }
    usize::try_from(byte_len).map_err(|_| BoundsError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_payloads_to_disk_sectors() {
        assert_eq!(sector_count(1), Ok(1));
        assert_eq!(sector_count(512), Ok(1));
        assert_eq!(sector_count(513), Ok(2));
    }

    #[test]
    fn rejects_buffers_beyond_the_documented_bound() {
        assert_eq!(checked_buffer(1025, 1024), Err(BoundsError::TooLarge));
    }
}
