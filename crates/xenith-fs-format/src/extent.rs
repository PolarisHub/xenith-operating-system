//! Extent mapping and validation.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub logical_block: u64,
    pub physical_block: u64,
    pub block_count: u32,
    pub flags: u32,
}

impl Extent {
    pub const UNWRITTEN: u32 = 1;

    pub fn logical_end(self) -> Option<u64> {
        self.logical_block.checked_add(u64::from(self.block_count))
    }

    pub fn physical_end(self) -> Option<u64> {
        self.physical_block.checked_add(u64::from(self.block_count))
    }

    pub fn map(self, logical: u64) -> Option<u64> {
        if logical < self.logical_block || logical >= self.logical_end()? {
            return None;
        }
        self.physical_block
            .checked_add(logical - self.logical_block)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtentError {
    ZeroLength,
    UnsupportedFlags,
    LogicalOverlap,
    PhysicalOutOfBounds,
    PhysicalOverlap,
    Overflow,
}

pub fn validate_extents(
    extents: &[Extent],
    data_start: u64,
    total_blocks: u64,
) -> Result<(), ExtentError> {
    let mut logical_end = 0u64;
    for extent in extents {
        if extent.block_count == 0 {
            return Err(ExtentError::ZeroLength);
        }
        if extent.flags & !Extent::UNWRITTEN != 0 {
            return Err(ExtentError::UnsupportedFlags);
        }
        if extent.logical_block < logical_end {
            return Err(ExtentError::LogicalOverlap);
        }
        if extent.physical_block < data_start
            || extent.physical_end().is_none_or(|end| end > total_blocks)
        {
            return Err(ExtentError::PhysicalOutOfBounds);
        }
        logical_end = extent.logical_end().ok_or(ExtentError::Overflow)?;
    }
    for (index, left) in extents.iter().enumerate() {
        let left_end = left.physical_end().ok_or(ExtentError::Overflow)?;
        for right in &extents[index + 1..] {
            let right_end = right.physical_end().ok_or(ExtentError::Overflow)?;
            if left.physical_block < right_end && right.physical_block < left_end {
                return Err(ExtentError::PhysicalOverlap);
            }
        }
    }
    Ok(())
}

pub fn mapped_block(extents: &[Extent], logical: u64) -> Option<u64> {
    extents.iter().find_map(|extent| extent.map(logical))
}
