//! Strict ELF64 parser used by the machine loader.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfError {
    Truncated,
    BadMagic,
    UnsupportedClass,
    UnsupportedEndian,
    UnsupportedMachine,
    InvalidHeader,
    SegmentOutOfBounds,
}

#[derive(Clone, Copy, Debug)]
pub struct ProgramHeader {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub align: u64,
}

impl ProgramHeader {
    pub const LOAD: u32 = 1;
    pub const EXECUTE: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const READ: u32 = 4;
}

pub struct ElfImage<'a> {
    bytes: &'a [u8],
    entry: u64,
    program_offset: usize,
    program_size: usize,
    program_count: usize,
}

impl<'a> ElfImage<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ElfError> {
        if bytes.len() < 64 {
            return Err(ElfError::Truncated);
        }
        if &bytes[..4] != b"\x7FELF" {
            return Err(ElfError::BadMagic);
        }
        if bytes[4] != 2 {
            return Err(ElfError::UnsupportedClass);
        }
        if bytes[5] != 1 {
            return Err(ElfError::UnsupportedEndian);
        }
        if read_u16(bytes, 18)? != 62 {
            return Err(ElfError::UnsupportedMachine);
        }
        let header_size = usize::from(read_u16(bytes, 52)?);
        let program_size = usize::from(read_u16(bytes, 54)?);
        let program_count = usize::from(read_u16(bytes, 56)?);
        let program_offset =
            usize::try_from(read_u64(bytes, 32)?).map_err(|_| ElfError::InvalidHeader)?;
        if header_size < 64 || program_size < 56 {
            return Err(ElfError::InvalidHeader);
        }
        let end = program_offset
            .checked_add(
                program_size
                    .checked_mul(program_count)
                    .ok_or(ElfError::InvalidHeader)?,
            )
            .ok_or(ElfError::InvalidHeader)?;
        if end > bytes.len() {
            return Err(ElfError::Truncated);
        }
        Ok(Self {
            bytes,
            entry: read_u64(bytes, 24)?,
            program_offset,
            program_size,
            program_count,
        })
    }

    #[must_use]
    pub const fn entry(&self) -> u64 {
        self.entry
    }

    pub fn program_headers(&self) -> ProgramHeaders<'_> {
        ProgramHeaders {
            image: self,
            index: 0,
        }
    }

    pub fn segment_data(&self, header: ProgramHeader) -> Result<&'a [u8], ElfError> {
        let start = usize::try_from(header.offset).map_err(|_| ElfError::SegmentOutOfBounds)?;
        let size = usize::try_from(header.file_size).map_err(|_| ElfError::SegmentOutOfBounds)?;
        self.bytes
            .get(
                start
                    ..start
                        .checked_add(size)
                        .ok_or(ElfError::SegmentOutOfBounds)?,
            )
            .ok_or(ElfError::SegmentOutOfBounds)
    }
}

pub struct ProgramHeaders<'a> {
    image: &'a ElfImage<'a>,
    index: usize,
}

impl Iterator for ProgramHeaders<'_> {
    type Item = Result<ProgramHeader, ElfError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.image.program_count {
            return None;
        }
        let offset = self.image.program_offset + self.index * self.image.program_size;
        self.index += 1;
        Some((|| {
            Ok(ProgramHeader {
                kind: read_u32(self.image.bytes, offset)?,
                flags: read_u32(self.image.bytes, offset + 4)?,
                offset: read_u64(self.image.bytes, offset + 8)?,
                virtual_address: read_u64(self.image.bytes, offset + 16)?,
                physical_address: read_u64(self.image.bytes, offset + 24)?,
                file_size: read_u64(self.image.bytes, offset + 32)?,
                memory_size: read_u64(self.image.bytes, offset + 40)?,
                align: read_u64(self.image.bytes, offset + 48)?,
            })
        })())
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ElfError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(ElfError::Truncated)?
            .try_into()
            .expect("two bytes"),
    ))
}
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ElfError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(ElfError::Truncated)?
            .try_into()
            .expect("four bytes"),
    ))
}
fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ElfError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(ElfError::Truncated)?
            .try_into()
            .expect("eight bytes"),
    ))
}
