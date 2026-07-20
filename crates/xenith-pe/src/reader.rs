use crate::PeError;

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub(crate) fn bytes(&self, offset: usize, size: usize) -> Result<&'a [u8], PeError> {
        let end = offset
            .checked_add(size)
            .ok_or(PeError::ArithmeticOverflow {
                field: "file range",
            })?;
        self.bytes
            .get(offset..end)
            .ok_or(PeError::Truncated { offset, size })
    }

    pub(crate) fn u8(&self, offset: usize) -> Result<u8, PeError> {
        Ok(self.bytes(offset, 1)?[0])
    }

    pub(crate) fn u16(&self, offset: usize) -> Result<u16, PeError> {
        let bytes = self.bytes(offset, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn u32(&self, offset: usize) -> Result<u32, PeError> {
        let bytes = self.bytes(offset, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn u64(&self, offset: usize) -> Result<u64, PeError> {
        let bytes = self.bytes(offset, 8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
}

pub(crate) fn checked_add(
    left: usize,
    right: usize,
    field: &'static str,
) -> Result<usize, PeError> {
    left.checked_add(right)
        .ok_or(PeError::ArithmeticOverflow { field })
}

pub(crate) fn checked_mul(
    left: usize,
    right: usize,
    field: &'static str,
) -> Result<usize, PeError> {
    left.checked_mul(right)
        .ok_or(PeError::ArithmeticOverflow { field })
}

pub(crate) fn align_up(value: u32, alignment: u32, field: &'static str) -> Result<u32, PeError> {
    debug_assert!(alignment.is_power_of_two());
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|rounded| rounded & !mask)
        .ok_or(PeError::ArithmeticOverflow { field })
}
