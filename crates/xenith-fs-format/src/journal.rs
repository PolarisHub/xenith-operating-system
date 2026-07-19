//! Single-transaction XenithFS redo-journal header.

use alloc::vec::Vec;

use super::{crc32, Superblock, BLOCK_SIZE};

pub const JOURNAL_MAGIC: &[u8; 8] = b"XNJRNL01";
pub const JOURNAL_HEADER_BYTES: usize = 32;
pub const JOURNAL_DESCRIPTOR_BYTES: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalDescriptor {
    pub target_block: u64,
    pub checksum: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalHeader {
    pub prepared: bool,
    pub sequence: u64,
    pub descriptors: Vec<JournalDescriptor>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalError {
    TooShort,
    BadMagic,
    BadState,
    TooManyDescriptors,
    BadChecksum,
    InvalidTarget,
}

impl JournalHeader {
    pub fn clean(sequence: u64) -> Self {
        Self {
            prepared: false,
            sequence,
            descriptors: Vec::new(),
        }
    }

    pub fn parse(block: &[u8]) -> Result<Self, JournalError> {
        let block = block.get(..BLOCK_SIZE).ok_or(JournalError::TooShort)?;
        if block.iter().all(|byte| *byte == 0) {
            return Ok(Self::clean(0));
        }
        if &block[..8] != JOURNAL_MAGIC {
            return Err(JournalError::BadMagic);
        }
        if block[8] > 1 {
            return Err(JournalError::BadState);
        }
        let count = usize::from(u16::from_le_bytes(block[10..12].try_into().unwrap()));
        if count > (BLOCK_SIZE - JOURNAL_HEADER_BYTES) / JOURNAL_DESCRIPTOR_BYTES {
            return Err(JournalError::TooManyDescriptors);
        }
        let expected = u32::from_le_bytes(block[24..28].try_into().unwrap());
        let mut checked = block.to_vec();
        checked[24..28].fill(0);
        if crc32(&checked) != expected {
            return Err(JournalError::BadChecksum);
        }
        let mut descriptors = Vec::with_capacity(count);
        for index in 0..count {
            let offset = JOURNAL_HEADER_BYTES + index * JOURNAL_DESCRIPTOR_BYTES;
            descriptors.push(JournalDescriptor {
                target_block: u64::from_le_bytes(block[offset..offset + 8].try_into().unwrap()),
                checksum: u32::from_le_bytes(block[offset + 8..offset + 12].try_into().unwrap()),
            });
        }
        if block[8] == 0 && !descriptors.is_empty() {
            return Err(JournalError::BadState);
        }
        Ok(Self {
            prepared: block[8] == 1,
            sequence: u64::from_le_bytes(block[16..24].try_into().unwrap()),
            descriptors,
        })
    }

    pub fn encode(&self) -> Result<[u8; BLOCK_SIZE], JournalError> {
        if self.descriptors.len() > (BLOCK_SIZE - JOURNAL_HEADER_BYTES) / JOURNAL_DESCRIPTOR_BYTES {
            return Err(JournalError::TooManyDescriptors);
        }
        if !self.prepared && !self.descriptors.is_empty() {
            return Err(JournalError::BadState);
        }
        let mut block = [0u8; BLOCK_SIZE];
        block[..8].copy_from_slice(JOURNAL_MAGIC);
        block[8] = u8::from(self.prepared);
        block[10..12].copy_from_slice(&(self.descriptors.len() as u16).to_le_bytes());
        block[16..24].copy_from_slice(&self.sequence.to_le_bytes());
        for (index, descriptor) in self.descriptors.iter().enumerate() {
            let offset = JOURNAL_HEADER_BYTES + index * JOURNAL_DESCRIPTOR_BYTES;
            block[offset..offset + 8].copy_from_slice(&descriptor.target_block.to_le_bytes());
            block[offset + 8..offset + 12].copy_from_slice(&descriptor.checksum.to_le_bytes());
        }
        let checksum = crc32(&block);
        block[24..28].copy_from_slice(&checksum.to_le_bytes());
        Ok(block)
    }

    pub fn validate_for(&self, superblock: &Superblock) -> Result<(), JournalError> {
        if self.descriptors.len() >= superblock.journal_blocks as usize {
            return Err(JournalError::TooManyDescriptors);
        }
        for descriptor in &self.descriptors {
            if descriptor.target_block == 0
                || descriptor.target_block >= superblock.total_blocks
                || superblock.contains_journal_block(descriptor.target_block)
            {
                return Err(JournalError::InvalidTarget);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_header_round_trip() {
        let header = JournalHeader::clean(7);
        assert_eq!(
            JournalHeader::parse(&header.encode().unwrap()).unwrap(),
            header
        );
    }
}
