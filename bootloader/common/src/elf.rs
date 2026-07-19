//! Allocation-free ELF64 validation and load-segment iteration.

use crate::{align_down, align_up, PAGE_SIZE};

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const PT_LOAD: u32 = 1;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfError {
    TooShort,
    BadMagic,
    UnsupportedClass,
    UnsupportedEndian,
    UnsupportedVersion,
    UnsupportedType,
    UnsupportedMachine,
    BadHeaderSize,
    BadProgramHeaderSize,
    ProgramHeadersOutsideImage,
    SegmentOutsideImage,
    SegmentFileLargerThanMemory,
    SegmentAddressOverflow,
    SegmentAddressUnaligned,
    NoLoadSegments,
    EntryOutsideLoadSegment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSegment {
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub flags: u32,
    pub alignment: u64,
}

impl LoadSegment {
    #[must_use]
    pub const fn is_executable(self) -> bool {
        self.flags & 1 != 0
    }

    pub fn file_bytes<'a>(&self, image: &'a [u8]) -> Result<&'a [u8], ElfError> {
        let start = usize::try_from(self.file_offset).map_err(|_| ElfError::SegmentOutsideImage)?;
        let len = usize::try_from(self.file_size).map_err(|_| ElfError::SegmentOutsideImage)?;
        image
            .get(
                start
                    ..start
                        .checked_add(len)
                        .ok_or(ElfError::SegmentOutsideImage)?,
            )
            .ok_or(ElfError::SegmentOutsideImage)
    }
}

#[derive(Clone, Copy)]
pub struct Elf64<'a> {
    image: &'a [u8],
    entry: u64,
    ph_offset: usize,
    ph_count: usize,
}

impl<'a> Elf64<'a> {
    pub fn parse(image: &'a [u8]) -> Result<Self, ElfError> {
        if image.len() < ELF_HEADER_SIZE {
            return Err(ElfError::TooShort);
        }
        if image.get(0..4) != Some(b"\x7fELF".as_slice()) {
            return Err(ElfError::BadMagic);
        }
        if image[4] != 2 {
            return Err(ElfError::UnsupportedClass);
        }
        if image[5] != 1 {
            return Err(ElfError::UnsupportedEndian);
        }
        if image[6] != 1 || read_u32(image, 20)? != 1 {
            return Err(ElfError::UnsupportedVersion);
        }
        if read_u16(image, 16)? != ET_EXEC {
            return Err(ElfError::UnsupportedType);
        }
        if read_u16(image, 18)? != EM_X86_64 {
            return Err(ElfError::UnsupportedMachine);
        }
        if usize::from(read_u16(image, 52)?) != ELF_HEADER_SIZE {
            return Err(ElfError::BadHeaderSize);
        }
        if usize::from(read_u16(image, 54)?) != PROGRAM_HEADER_SIZE {
            return Err(ElfError::BadProgramHeaderSize);
        }
        let ph_offset = usize::try_from(read_u64(image, 32)?)
            .map_err(|_| ElfError::ProgramHeadersOutsideImage)?;
        let ph_count = usize::from(read_u16(image, 56)?);
        let table_len = ph_count
            .checked_mul(PROGRAM_HEADER_SIZE)
            .ok_or(ElfError::ProgramHeadersOutsideImage)?;
        if image
            .get(
                ph_offset
                    ..ph_offset
                        .checked_add(table_len)
                        .ok_or(ElfError::ProgramHeadersOutsideImage)?,
            )
            .is_none()
        {
            return Err(ElfError::ProgramHeadersOutsideImage);
        }
        let elf = Self {
            image,
            entry: read_u64(image, 24)?,
            ph_offset,
            ph_count,
        };
        elf.validate_load_segments()?;
        Ok(elf)
    }

    #[must_use]
    pub const fn entry(&self) -> u64 {
        self.entry
    }

    #[must_use]
    pub fn load_segments(&self) -> ProgramHeaderIter<'a> {
        ProgramHeaderIter {
            image: self.image,
            offset: self.ph_offset,
            remaining: self.ph_count,
        }
    }

    pub fn physical_span(&self) -> Result<(u64, u64), ElfError> {
        let mut start = u64::MAX;
        let mut end = 0_u64;
        for segment in self.load_segments() {
            let segment = segment?;
            start = start.min(align_down(segment.physical_address, PAGE_SIZE));
            let segment_end = segment
                .physical_address
                .checked_add(segment.memory_size)
                .and_then(|value| align_up(value, PAGE_SIZE))
                .ok_or(ElfError::SegmentAddressOverflow)?;
            end = end.max(segment_end);
        }
        if start == u64::MAX {
            Err(ElfError::NoLoadSegments)
        } else {
            Ok((start, end))
        }
    }

    pub fn virtual_span(&self) -> Result<(u64, u64), ElfError> {
        let mut start = u64::MAX;
        let mut end = 0_u64;
        for segment in self.load_segments() {
            let segment = segment?;
            start = start.min(align_down(segment.virtual_address, PAGE_SIZE));
            let segment_end = segment
                .virtual_address
                .checked_add(segment.memory_size)
                .and_then(|value| align_up(value, PAGE_SIZE))
                .ok_or(ElfError::SegmentAddressOverflow)?;
            end = end.max(segment_end);
        }
        if start == u64::MAX {
            Err(ElfError::NoLoadSegments)
        } else {
            Ok((start, end))
        }
    }

    fn validate_load_segments(&self) -> Result<(), ElfError> {
        let mut load_count = 0;
        let mut entry_covered = false;
        for segment in self.load_segments() {
            let segment = segment?;
            load_count += 1;
            if segment.file_size > segment.memory_size {
                return Err(ElfError::SegmentFileLargerThanMemory);
            }
            segment.file_bytes(self.image)?;
            segment
                .physical_address
                .checked_add(segment.memory_size)
                .ok_or(ElfError::SegmentAddressOverflow)?;
            let virtual_end = segment
                .virtual_address
                .checked_add(segment.memory_size)
                .ok_or(ElfError::SegmentAddressOverflow)?;
            if segment.alignment > 1
                && (!segment.alignment.is_power_of_two()
                    || segment.virtual_address % segment.alignment
                        != segment.file_offset % segment.alignment)
            {
                return Err(ElfError::SegmentAddressUnaligned);
            }
            if segment.is_executable()
                && self.entry >= segment.virtual_address
                && self.entry < virtual_end
            {
                entry_covered = true;
            }
        }
        if load_count == 0 {
            return Err(ElfError::NoLoadSegments);
        }
        if !entry_covered {
            return Err(ElfError::EntryOutsideLoadSegment);
        }
        Ok(())
    }
}

pub struct ProgramHeaderIter<'a> {
    image: &'a [u8],
    offset: usize,
    remaining: usize,
}

impl Iterator for ProgramHeaderIter<'_> {
    type Item = Result<LoadSegment, ElfError>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining != 0 {
            let start = self.offset;
            self.offset += PROGRAM_HEADER_SIZE;
            self.remaining -= 1;
            let raw = match self.image.get(start..start + PROGRAM_HEADER_SIZE) {
                Some(raw) => raw,
                None => return Some(Err(ElfError::ProgramHeadersOutsideImage)),
            };
            let kind = match read_u32(raw, 0) {
                Ok(kind) => kind,
                Err(error) => return Some(Err(error)),
            };
            if kind != PT_LOAD {
                continue;
            }
            return Some(parse_load_segment(raw));
        }
        None
    }
}

fn parse_load_segment(raw: &[u8]) -> Result<LoadSegment, ElfError> {
    Ok(LoadSegment {
        flags: read_u32(raw, 4)?,
        file_offset: read_u64(raw, 8)?,
        virtual_address: read_u64(raw, 16)?,
        physical_address: read_u64(raw, 24)?,
        file_size: read_u64(raw, 32)?,
        memory_size: read_u64(raw, 40)?,
        alignment: read_u64(raw, 48)?,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ElfError> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or(ElfError::TooShort)?
        .try_into()
        .map_err(|_| ElfError::TooShort)?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ElfError> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(ElfError::TooShort)?
        .try_into()
        .map_err(|_| ElfError::TooShort)?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ElfError> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or(ElfError::TooShort)?
        .try_into()
        .map_err(|_| ElfError::TooShort)?;
    Ok(u64::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executable() -> [u8; 0x120] {
        let mut image = [0_u8; 0x120];
        image[0..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        image[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        image[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        image[20..24].copy_from_slice(&1_u32.to_le_bytes());
        image[24..32].copy_from_slice(&0xffff_ffff_8000_0100_u64.to_le_bytes());
        image[32..40].copy_from_slice(&64_u64.to_le_bytes());
        image[52..54].copy_from_slice(&64_u16.to_le_bytes());
        image[54..56].copy_from_slice(&56_u16.to_le_bytes());
        image[56..58].copy_from_slice(&1_u16.to_le_bytes());
        let ph = &mut image[64..120];
        ph[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
        ph[4..8].copy_from_slice(&5_u32.to_le_bytes());
        ph[8..16].copy_from_slice(&0x100_u64.to_le_bytes());
        ph[16..24].copy_from_slice(&0xffff_ffff_8000_0100_u64.to_le_bytes());
        ph[24..32].copy_from_slice(&0x10_0100_u64.to_le_bytes());
        ph[32..40].copy_from_slice(&0x20_u64.to_le_bytes());
        ph[40..48].copy_from_slice(&0x80_u64.to_le_bytes());
        ph[48..56].copy_from_slice(&0x100_u64.to_le_bytes());
        image
    }

    #[test]
    fn validates_and_iterates_a_kernel_image() {
        let image = executable();
        let elf = Elf64::parse(&image).unwrap();
        let segment = elf.load_segments().next().unwrap().unwrap();
        assert_eq!(segment.file_bytes(&image).unwrap().len(), 0x20);
        assert_eq!(elf.physical_span().unwrap(), (0x10_0000, 0x10_1000));
        assert_eq!(elf.entry(), 0xffff_ffff_8000_0100);
    }

    #[test]
    fn rejects_an_entry_in_non_executable_memory() {
        let mut image = executable();
        image[68..72].copy_from_slice(&4_u32.to_le_bytes());
        assert_eq!(
            Elf64::parse(&image).err(),
            Some(ElfError::EntryOutsideLoadSegment)
        );
    }
}
