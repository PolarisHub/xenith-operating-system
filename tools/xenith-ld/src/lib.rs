//! Dependency-free ELF64 static image writer for Xenith userspace.

use std::fmt;

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const PAYLOAD_OFFSET: usize = 0x1000;
const PAGE_SIZE: u64 = 0x1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentFlags(u32);

impl SegmentFlags {
    pub const EXECUTE: Self = Self(1);
    pub const WRITE: Self = Self(2);
    pub const READ: Self = Self(4);

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for SegmentFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// One input section promoted to its own page-aligned PT_LOAD segment.
#[derive(Clone, Copy, Debug)]
pub struct StaticSection<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
    /// In-memory size, allowing a zero-filled tail for `.bss`.
    pub memory_size: u64,
    pub flags: SegmentFlags,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationKind {
    Absolute64,
    PcRelative32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Relocation {
    pub section: usize,
    pub offset: u64,
    pub target_section: usize,
    pub target_offset: u64,
    pub addend: i64,
    pub kind: RelocationKind,
}

#[derive(Clone, Copy, Debug)]
pub struct StaticLinkOptions {
    pub base_address: u64,
    pub entry_section: usize,
    pub entry_offset: u64,
}

impl Default for StaticLinkOptions {
    fn default() -> Self {
        Self {
            base_address: 0x0040_0000,
            entry_section: 0,
            entry_offset: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkedSection {
    pub file_offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticImage {
    pub bytes: Vec<u8>,
    pub sections: Vec<LinkedSection>,
    pub entry: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct LinkOptions {
    pub base_address: u64,
    pub entry_offset: u64,
    pub writable: bool,
}

impl Default for LinkOptions {
    fn default() -> Self {
        Self {
            base_address: 0x0040_0000,
            entry_offset: 0,
            writable: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkError {
    EmptyInput,
    UnalignedBase,
    EntryOutsideImage,
    ImageTooLarge,
    InvalidSection,
    DuplicateSection,
    WritableExecutableSection,
    InvalidRelocation,
    RelocationOverflow,
}

impl fmt::Display for LinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyInput => "no linkable input",
            Self::UnalignedBase => "base address is not page aligned",
            Self::EntryOutsideImage => "entry is outside an executable input section",
            Self::ImageTooLarge => "linked image exceeds representable ELF/file bounds",
            Self::InvalidSection => "invalid section name, data size, or memory size",
            Self::DuplicateSection => "duplicate section name",
            Self::WritableExecutableSection => "writable-executable sections are forbidden",
            Self::InvalidRelocation => "relocation references an invalid section or offset",
            Self::RelocationOverflow => "relocation result does not fit its encoding",
        })
    }
}

impl std::error::Error for LinkError {}

/// Link page-separated text/rodata/data/bss segments into a static ELF64.
///
/// The output uses one PT_LOAD per input section, enforces W^X, validates an
/// executable entry section, and applies absolute-64 or PC-relative-32
/// relocations after final virtual addresses are known.
pub fn link_static(
    sections: &[StaticSection<'_>],
    relocations: &[Relocation],
    options: StaticLinkOptions,
) -> Result<StaticImage, LinkError> {
    if sections.is_empty() {
        return Err(LinkError::EmptyInput);
    }
    if sections.len() > usize::from(u16::MAX) {
        return Err(LinkError::ImageTooLarge);
    }
    if !options.base_address.is_multiple_of(PAGE_SIZE) {
        return Err(LinkError::UnalignedBase);
    }
    if options.entry_section >= sections.len() {
        return Err(LinkError::EntryOutsideImage);
    }
    for (index, section) in sections.iter().enumerate() {
        if section.name.is_empty()
            || section.memory_size < section.data.len() as u64
            || (section.data.is_empty() && section.memory_size == 0)
        {
            return Err(LinkError::InvalidSection);
        }
        if sections[..index]
            .iter()
            .any(|previous| previous.name == section.name)
        {
            return Err(LinkError::DuplicateSection);
        }
        if section.flags.contains(SegmentFlags::WRITE)
            && section.flags.contains(SegmentFlags::EXECUTE)
        {
            return Err(LinkError::WritableExecutableSection);
        }
    }
    let entry_section = sections[options.entry_section];
    if !entry_section.flags.contains(SegmentFlags::EXECUTE)
        || options.entry_offset >= entry_section.memory_size
    {
        return Err(LinkError::EntryOutsideImage);
    }

    let header_bytes = ELF_HEADER_SIZE
        .checked_add(
            PROGRAM_HEADER_SIZE
                .checked_mul(sections.len())
                .ok_or(LinkError::ImageTooLarge)?,
        )
        .ok_or(LinkError::ImageTooLarge)?;
    let first_payload = align_up(header_bytes as u64, PAGE_SIZE)?;
    let mut next_file = first_payload;
    let mut next_virtual = options.base_address;
    let mut layouts = Vec::with_capacity(sections.len());
    for section in sections {
        next_file = align_up(next_file, PAGE_SIZE)?;
        next_virtual = align_up(next_virtual, PAGE_SIZE)?;
        layouts.push(LinkedSection {
            file_offset: next_file,
            virtual_address: next_virtual,
            file_size: section.data.len() as u64,
            memory_size: section.memory_size,
        });
        next_file = next_file
            .checked_add(section.data.len() as u64)
            .ok_or(LinkError::ImageTooLarge)?;
        next_virtual = next_virtual
            .checked_add(section.memory_size)
            .ok_or(LinkError::ImageTooLarge)?;
    }
    let file_size = usize::try_from(next_file).map_err(|_| LinkError::ImageTooLarge)?;
    let mut image = vec![0_u8; file_size];
    write_elf_header(
        &mut image,
        layouts[options.entry_section].virtual_address + options.entry_offset,
        sections.len(),
    );
    for (index, (section, layout)) in sections.iter().zip(&layouts).enumerate() {
        let header = ELF_HEADER_SIZE + index * PROGRAM_HEADER_SIZE;
        write_program_header(
            &mut image,
            header,
            section.flags.bits(),
            layout.file_offset,
            layout.virtual_address,
            layout.file_size,
            layout.memory_size,
        );
        let start = usize::try_from(layout.file_offset).map_err(|_| LinkError::ImageTooLarge)?;
        image[start..start + section.data.len()].copy_from_slice(section.data);
    }
    apply_relocations(&mut image, &layouts, relocations)?;
    let entry = layouts[options.entry_section].virtual_address + options.entry_offset;
    Ok(StaticImage {
        bytes: image,
        sections: layouts,
        entry,
    })
}

fn align_up(value: u64, alignment: u64) -> Result<u64, LinkError> {
    value
        .checked_add(alignment - 1)
        .map(|adjusted| adjusted & !(alignment - 1))
        .ok_or(LinkError::ImageTooLarge)
}

fn apply_relocations(
    image: &mut [u8],
    layouts: &[LinkedSection],
    relocations: &[Relocation],
) -> Result<(), LinkError> {
    for relocation in relocations {
        let source = *layouts
            .get(relocation.section)
            .ok_or(LinkError::InvalidRelocation)?;
        let target = *layouts
            .get(relocation.target_section)
            .ok_or(LinkError::InvalidRelocation)?;
        let width = match relocation.kind {
            RelocationKind::Absolute64 => 8,
            RelocationKind::PcRelative32 => 4,
        };
        if relocation
            .offset
            .checked_add(width)
            .is_none_or(|end| end > source.file_size)
            || relocation.target_offset > target.memory_size
        {
            return Err(LinkError::InvalidRelocation);
        }
        let patch = source
            .file_offset
            .checked_add(relocation.offset)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(LinkError::InvalidRelocation)?;
        let target_address = i128::from(target.virtual_address)
            + i128::from(relocation.target_offset)
            + i128::from(relocation.addend);
        match relocation.kind {
            RelocationKind::Absolute64 => {
                let value =
                    u64::try_from(target_address).map_err(|_| LinkError::RelocationOverflow)?;
                image[patch..patch + 8].copy_from_slice(&value.to_le_bytes());
            },
            RelocationKind::PcRelative32 => {
                let place_after =
                    i128::from(source.virtual_address) + i128::from(relocation.offset) + 4;
                let value = i32::try_from(target_address - place_after)
                    .map_err(|_| LinkError::RelocationOverflow)?;
                image[patch..patch + 4].copy_from_slice(&value.to_le_bytes());
            },
        }
    }
    Ok(())
}

fn write_elf_header(image: &mut [u8], entry: u64, program_count: usize) {
    image[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put_u16(image, 16, 2);
    put_u16(image, 18, 0x3e);
    put_u32(image, 20, 1);
    put_u64(image, 24, entry);
    put_u64(image, 32, ELF_HEADER_SIZE as u64);
    put_u16(image, 52, ELF_HEADER_SIZE as u16);
    put_u16(image, 54, PROGRAM_HEADER_SIZE as u16);
    put_u16(image, 56, program_count as u16);
}

fn write_program_header(
    image: &mut [u8],
    header: usize,
    flags: u32,
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
) {
    put_u32(image, header, 1);
    put_u32(image, header + 4, flags);
    put_u64(image, header + 8, file_offset);
    put_u64(image, header + 16, virtual_address);
    put_u64(image, header + 24, virtual_address);
    put_u64(image, header + 32, file_size);
    put_u64(image, header + 40, memory_size);
    put_u64(image, header + 48, PAGE_SIZE);
}

/// Wrap a flat x86-64 payload in a static ELF64 executable with one PT_LOAD.
pub fn link_flat(code: &[u8], options: LinkOptions) -> Result<Vec<u8>, LinkError> {
    if code.is_empty() {
        return Err(LinkError::EmptyInput);
    }
    if !options.base_address.is_multiple_of(0x1000) {
        return Err(LinkError::UnalignedBase);
    }
    if options.entry_offset >= code.len() as u64 {
        return Err(LinkError::EntryOutsideImage);
    }
    let file_size = PAYLOAD_OFFSET
        .checked_add(code.len())
        .ok_or(LinkError::ImageTooLarge)?;
    let mut image = vec![0u8; file_size];
    image[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put_u16(&mut image, 16, 2);
    put_u16(&mut image, 18, 0x3e);
    put_u32(&mut image, 20, 1);
    put_u64(&mut image, 24, options.base_address + options.entry_offset);
    put_u64(&mut image, 32, ELF_HEADER_SIZE as u64);
    put_u64(&mut image, 40, 0);
    put_u32(&mut image, 48, 0);
    put_u16(&mut image, 52, ELF_HEADER_SIZE as u16);
    put_u16(&mut image, 54, PROGRAM_HEADER_SIZE as u16);
    put_u16(&mut image, 56, 1);
    put_u16(&mut image, 58, 0);
    put_u16(&mut image, 60, 0);
    put_u16(&mut image, 62, 0);

    let header = ELF_HEADER_SIZE;
    put_u32(&mut image, header, 1);
    put_u32(&mut image, header + 4, if options.writable { 7 } else { 5 });
    put_u64(&mut image, header + 8, PAYLOAD_OFFSET as u64);
    put_u64(&mut image, header + 16, options.base_address);
    put_u64(&mut image, header + 24, options.base_address);
    put_u64(&mut image, header + 32, code.len() as u64);
    put_u64(&mut image, header + 40, code.len() as u64);
    put_u64(&mut image, header + 48, 0x1000);
    image[PAYLOAD_OFFSET..].copy_from_slice(code);
    Ok(image)
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_loadable_elf64() {
        let image = link_flat(&[0x90, 0xc3], LinkOptions::default()).unwrap();
        assert_eq!(&image[..4], b"\x7fELF");
        assert_eq!(u16::from_le_bytes(image[18..20].try_into().unwrap()), 0x3e);
        assert_eq!(
            u64::from_le_bytes(image[24..32].try_into().unwrap()),
            0x0040_0000
        );
        assert_eq!(&image[PAYLOAD_OFFSET..], &[0x90, 0xc3]);
    }

    #[test]
    fn rejects_entry_past_payload() {
        let error = link_flat(&[0x90], LinkOptions {
            entry_offset: 1,
            ..LinkOptions::default()
        })
        .unwrap_err();
        assert_eq!(error, LinkError::EntryOutsideImage);
    }

    #[test]
    fn links_wx_separated_segments_and_applies_absolute_relocation() {
        let text = [0x48, 0xBE, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3];
        let rodata = *b"hello\0";
        let linked = link_static(
            &[
                StaticSection {
                    name: ".text",
                    data: &text,
                    memory_size: text.len() as u64,
                    flags: SegmentFlags::READ | SegmentFlags::EXECUTE,
                },
                StaticSection {
                    name: ".rodata",
                    data: &rodata,
                    memory_size: rodata.len() as u64,
                    flags: SegmentFlags::READ,
                },
                StaticSection {
                    name: ".bss",
                    data: &[],
                    memory_size: 4096,
                    flags: SegmentFlags::READ | SegmentFlags::WRITE,
                },
            ],
            &[Relocation {
                section: 0,
                offset: 2,
                target_section: 1,
                target_offset: 0,
                addend: 0,
                kind: RelocationKind::Absolute64,
            }],
            StaticLinkOptions::default(),
        )
        .unwrap();
        assert_eq!(linked.entry, 0x0040_0000);
        assert_eq!(linked.sections.len(), 3);
        assert_eq!(linked.sections[2].file_size, 0);
        assert_eq!(linked.sections[2].memory_size, 4096);
        let text_file = linked.sections[0].file_offset as usize;
        let pointer = u64::from_le_bytes(
            linked.bytes[text_file + 2..text_file + 10]
                .try_into()
                .unwrap(),
        );
        assert_eq!(pointer, linked.sections[1].virtual_address);
        assert_eq!(
            &linked.bytes[linked.sections[1].file_offset as usize..][..rodata.len()],
            &rodata
        );
    }

    #[test]
    fn production_linker_rejects_writable_executable_segments() {
        assert_eq!(
            link_static(
                &[StaticSection {
                    name: ".text",
                    data: &[0xC3],
                    memory_size: 1,
                    flags: SegmentFlags::READ | SegmentFlags::WRITE | SegmentFlags::EXECUTE,
                }],
                &[],
                StaticLinkOptions::default(),
            )
            .unwrap_err(),
            LinkError::WritableExecutableSection
        );
    }
}
