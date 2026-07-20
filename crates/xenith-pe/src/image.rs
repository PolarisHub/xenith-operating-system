use crate::headers::{
    CoffHeader, DataDirectory, DosHeader, FileRange, OptionalHeader64, PeHeaders, SectionHeader,
    IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_FILE_MACHINE_AMD64, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, MAX_DATA_DIRECTORIES, MAX_IMAGE_SIZE, MAX_SECTIONS,
};
use crate::reader::{align_up, checked_add, checked_mul, Reader};
use crate::{LoaderPlan, PeError};

const DOS_HEADER_SIZE: usize = 64;
const PE_SIGNATURE: u32 = 0x0000_4550;
const PE_SIGNATURE_SIZE: usize = 4;
const COFF_HEADER_SIZE: usize = 20;
const OPTIONAL_HEADER64_FIXED_SIZE: usize = 112;
const DATA_DIRECTORY_SIZE: usize = 8;
const SECTION_HEADER_SIZE: usize = 40;
const MIN_FILE_ALIGNMENT: u32 = 0x200;
const MAX_FILE_ALIGNMENT: u32 = 0x1_0000;
const PAGE_SIZE: u32 = 0x1000;
const IMAGE_BASE_ALIGNMENT: u64 = 0x1_0000;

/// Fully validated view of an AMD64 PE32+ file.
///
/// The view borrows the source bytes and stores section and directory metadata
/// in fixed arrays, so parsing requires neither allocation nor unsafe code.
#[derive(Clone, Debug)]
pub struct PeImage<'a> {
    bytes: &'a [u8],
    headers: PeHeaders,
    directories: [DataDirectory; MAX_DATA_DIRECTORIES],
    directory_count: usize,
    sections: [SectionHeader; MAX_SECTIONS],
    section_count: usize,
}

impl<'a> PeImage<'a> {
    /// Parses and structurally validates one AMD64 PE32+ image.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PeError> {
        let reader = Reader::new(bytes);
        let dos_magic = reader.u16(0)?;
        if dos_magic != 0x5a4d {
            return Err(PeError::BadDosMagic { found: dos_magic });
        }

        let pe_offset = reader.u32(0x3c)?;
        if pe_offset < DOS_HEADER_SIZE as u32 {
            return Err(PeError::PeHeaderOverlapsDosHeader { offset: pe_offset });
        }
        let pe_offset_usize =
            usize::try_from(pe_offset).map_err(|_| PeError::ArithmeticOverflow {
                field: "PE header offset",
            })?;
        let signature = reader.u32(pe_offset_usize)?;
        if signature != PE_SIGNATURE {
            return Err(PeError::BadPeSignature { found: signature });
        }

        let coff_offset = checked_add(pe_offset_usize, PE_SIGNATURE_SIZE, "COFF header offset")?;
        let coff = parse_coff_header(&reader, coff_offset)?;
        if coff.machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(PeError::UnsupportedMachine {
                found: coff.machine,
            });
        }
        if coff.number_of_sections == 0 {
            return Err(PeError::NoSections);
        }
        if usize::from(coff.number_of_sections) > MAX_SECTIONS {
            return Err(PeError::TooManySections {
                count: coff.number_of_sections,
            });
        }
        if usize::from(coff.size_of_optional_header) < OPTIONAL_HEADER64_FIXED_SIZE {
            return Err(PeError::OptionalHeaderTooSmall {
                size: coff.size_of_optional_header,
            });
        }

        let optional_offset = checked_add(coff_offset, COFF_HEADER_SIZE, "optional header offset")?;
        reader.bytes(optional_offset, usize::from(coff.size_of_optional_header))?;
        let optional = parse_optional_header(&reader, optional_offset)?;
        validate_optional_header(optional)?;

        if optional.number_of_rva_and_sizes > MAX_DATA_DIRECTORIES as u32 {
            return Err(PeError::TooManyDataDirectories {
                count: optional.number_of_rva_and_sizes,
            });
        }
        let directory_bytes = checked_mul(
            usize::try_from(optional.number_of_rva_and_sizes).map_err(|_| {
                PeError::ArithmeticOverflow {
                    field: "data-directory count",
                }
            })?,
            DATA_DIRECTORY_SIZE,
            "data-directory table size",
        )?;
        let required_optional_size = checked_add(
            OPTIONAL_HEADER64_FIXED_SIZE,
            directory_bytes,
            "required optional-header size",
        )?;
        if required_optional_size > usize::from(coff.size_of_optional_header) {
            return Err(PeError::DataDirectoriesTruncated {
                count: optional.number_of_rva_and_sizes,
                optional_header_size: coff.size_of_optional_header,
            });
        }

        let section_table_offset = checked_add(
            optional_offset,
            usize::from(coff.size_of_optional_header),
            "section-table offset",
        )?;
        let section_table_size = checked_mul(
            usize::from(coff.number_of_sections),
            SECTION_HEADER_SIZE,
            "section-table size",
        )?;
        let section_table_end = checked_add(
            section_table_offset,
            section_table_size,
            "section-table end",
        )?;
        reader.bytes(section_table_offset, section_table_size)?;

        let size_of_headers_usize =
            usize::try_from(optional.size_of_headers).map_err(|_| PeError::ArithmeticOverflow {
                field: "SizeOfHeaders",
            })?;
        if section_table_end > size_of_headers_usize {
            return Err(PeError::SectionTableOutsideHeaders {
                section_table_end,
                size_of_headers: optional.size_of_headers,
            });
        }
        reader.bytes(0, size_of_headers_usize)?;

        let mut directories = [DataDirectory::EMPTY; MAX_DATA_DIRECTORIES];
        let directory_count = usize::try_from(optional.number_of_rva_and_sizes).map_err(|_| {
            PeError::ArithmeticOverflow {
                field: "data-directory count",
            }
        })?;
        for (index, directory) in directories[..directory_count].iter_mut().enumerate() {
            let offset = checked_add(
                optional_offset + OPTIONAL_HEADER64_FIXED_SIZE,
                index * DATA_DIRECTORY_SIZE,
                "data-directory offset",
            )?;
            *directory = DataDirectory {
                address: reader.u32(offset)?,
                size: reader.u32(offset + 4)?,
            };
        }

        let header_mapped_size = align_up(
            optional.size_of_headers,
            optional.section_alignment,
            "mapped header size",
        )?;
        let mut sections = [SectionHeader::EMPTY; MAX_SECTIONS];
        let section_count = usize::from(coff.number_of_sections);
        let mut required_image_size = header_mapped_size;
        for (index, section) in sections[..section_count].iter_mut().enumerate() {
            let offset = checked_add(
                section_table_offset,
                index * SECTION_HEADER_SIZE,
                "section-header offset",
            )?;
            *section = parse_section_header(&reader, offset)?;
            validate_section(bytes.len(), index, section, optional, header_mapped_size)?;
            let end = section
                .virtual_address
                .checked_add(section.mapped_size)
                .ok_or(PeError::ArithmeticOverflow {
                    field: "section virtual end",
                })?;
            required_image_size = required_image_size.max(end);
        }

        validate_section_overlaps(&sections[..section_count])?;
        validate_entry_point(optional, &sections[..section_count])?;
        if optional.size_of_image != required_image_size {
            return Err(PeError::SizeOfImageMismatch {
                declared: optional.size_of_image,
                required: required_image_size,
            });
        }

        let image = Self {
            bytes,
            headers: PeHeaders {
                dos: DosHeader { pe_offset },
                coff,
                optional,
            },
            directories,
            directory_count,
            sections,
            section_count,
        };
        image.validate_directories()?;
        Ok(image)
    }

    /// Returns all parsed top-level headers.
    #[must_use]
    pub const fn headers(&self) -> PeHeaders {
        self.headers
    }

    /// Returns advertised data directories in table order.
    #[must_use]
    pub fn directories(&self) -> &[DataDirectory] {
        &self.directories[..self.directory_count]
    }

    /// Returns one advertised data directory, if that index exists.
    #[must_use]
    pub fn directory(&self, index: usize) -> Option<DataDirectory> {
        self.directories().get(index).copied()
    }

    /// Returns validated section headers in original table order.
    #[must_use]
    pub fn sections(&self) -> &[SectionHeader] {
        &self.sections[..self.section_count]
    }

    /// Returns the original immutable image bytes.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Resolves a wholly file-backed image RVA range to a checked file range.
    ///
    /// The range must fit entirely within the headers or one section's initialized
    /// bytes; this function never joins discontiguous ranges or returns zero-fill.
    pub fn rva_to_file_range(&self, rva: u32, size: u32) -> Result<FileRange, PeError> {
        let end = rva
            .checked_add(size)
            .ok_or(PeError::RvaOutsideImage { rva, size })?;
        if end > self.headers.optional.size_of_image {
            return Err(PeError::RvaOutsideImage { rva, size });
        }

        if rva < self.headers.optional.size_of_headers
            && end <= self.headers.optional.size_of_headers
        {
            return Ok(FileRange { offset: rva, size });
        }

        for section in self.sections() {
            let raw_end_rva = section
                .virtual_address
                .checked_add(section.size_of_raw_data)
                .ok_or(PeError::RvaNotFileBacked { rva, size })?;
            if rva >= section.virtual_address && end <= raw_end_rva {
                let delta = rva - section.virtual_address;
                let offset = section
                    .pointer_to_raw_data
                    .checked_add(delta)
                    .ok_or(PeError::RvaNotFileBacked { rva, size })?;
                let file_end = offset
                    .checked_add(size)
                    .ok_or(PeError::RvaNotFileBacked { rva, size })?;
                if usize::try_from(file_end).map_or(true, |value| value > self.bytes.len()) {
                    return Err(PeError::RvaNotFileBacked { rva, size });
                }
                return Ok(FileRange { offset, size });
            }
        }

        Err(PeError::RvaNotFileBacked { rva, size })
    }

    /// Resolves a range wholly backed by initialized bytes of one section.
    ///
    /// Unlike [`Self::rva_to_file_range`], this rejects header RVAs and
    /// distinguishes a section's mapped zero-fill tail from an unmapped RVA.
    /// Format metadata that must exist in the file should use this operation.
    pub fn section_file_range(&self, rva: u32, size: u32) -> Result<FileRange, PeError> {
        let end = rva
            .checked_add(size)
            .ok_or(PeError::RvaOutsideImage { rva, size })?;
        if end > self.headers.optional.size_of_image {
            return Err(PeError::RvaOutsideImage { rva, size });
        }

        for (index, section) in self.sections().iter().copied().enumerate() {
            let mapped_end = section
                .virtual_address
                .checked_add(section.mapped_size)
                .ok_or(PeError::RvaNotSectionBacked { rva, size })?;
            let starts_in_section = if size == 0 {
                rva >= section.virtual_address && rva <= mapped_end
            } else {
                rva >= section.virtual_address && rva < mapped_end
            };
            if !starts_in_section {
                continue;
            }

            let raw_end = section
                .virtual_address
                .checked_add(section.size_of_raw_data)
                .ok_or(PeError::RvaNotSectionBacked { rva, size })?;
            if end <= raw_end {
                let delta = rva - section.virtual_address;
                let offset = section
                    .pointer_to_raw_data
                    .checked_add(delta)
                    .ok_or(PeError::RvaNotSectionBacked { rva, size })?;
                return Ok(FileRange { offset, size });
            }
            if end <= mapped_end {
                return Err(PeError::RvaTouchesVirtualZeroFill {
                    section: index,
                    rva,
                    size,
                });
            }
            return Err(PeError::RvaNotSectionBacked { rva, size });
        }

        Err(PeError::RvaNotSectionBacked { rva, size })
    }

    /// Borrows initialized section bytes for a checked RVA range.
    ///
    /// Header bytes, gaps, cross-section ranges, and virtual zero-fill are
    /// rejected rather than synthesized.
    pub fn section_bytes(&self, rva: u32, size: u32) -> Result<&'a [u8], PeError> {
        self.file_bytes(self.section_file_range(rva, size)?)
    }

    /// Borrows bytes described by a previously validated file range.
    pub fn file_bytes(&self, range: FileRange) -> Result<&'a [u8], PeError> {
        let offset = usize::try_from(range.offset).map_err(|_| PeError::ArithmeticOverflow {
            field: "file-range offset",
        })?;
        let size = usize::try_from(range.size).map_err(|_| PeError::ArithmeticOverflow {
            field: "file-range size",
        })?;
        Reader::new(self.bytes).bytes(offset, size)
    }

    /// Creates an allocation-free, declarative load plan for this image.
    pub fn loader_plan(&self) -> Result<LoaderPlan, PeError> {
        LoaderPlan::from_image(self)
    }

    fn validate_directories(&self) -> Result<(), PeError> {
        for (index, directory) in self.directories().iter().copied().enumerate() {
            if directory.is_empty() {
                continue;
            }
            if directory.address == 0 || directory.size == 0 {
                return Err(PeError::IncompleteDataDirectory {
                    directory: index,
                    address: directory.address,
                    size: directory.size,
                });
            }

            if index == IMAGE_DIRECTORY_ENTRY_SECURITY {
                if directory.address & 7 != 0 {
                    return Err(PeError::CertificateTableMisaligned {
                        offset: directory.address,
                    });
                }
                let end = directory.address.checked_add(directory.size).ok_or(
                    PeError::CertificateTableOutsideFile {
                        offset: directory.address,
                        size: directory.size,
                    },
                )?;
                if usize::try_from(end).map_or(true, |value| value > self.bytes.len()) {
                    return Err(PeError::CertificateTableOutsideFile {
                        offset: directory.address,
                        size: directory.size,
                    });
                }
                continue;
            }

            let end = directory.address.checked_add(directory.size).ok_or(
                PeError::DataDirectoryOutsideImage {
                    directory: index,
                    rva: directory.address,
                    size: directory.size,
                },
            )?;
            if end > self.headers.optional.size_of_image {
                return Err(PeError::DataDirectoryOutsideImage {
                    directory: index,
                    rva: directory.address,
                    size: directory.size,
                });
            }
            if self
                .rva_to_file_range(directory.address, directory.size)
                .is_err()
            {
                return Err(PeError::DataDirectoryNotFileBacked {
                    directory: index,
                    rva: directory.address,
                    size: directory.size,
                });
            }
        }
        Ok(())
    }
}

fn parse_coff_header(reader: &Reader<'_>, offset: usize) -> Result<CoffHeader, PeError> {
    reader.bytes(offset, COFF_HEADER_SIZE)?;
    Ok(CoffHeader {
        machine: reader.u16(offset)?,
        number_of_sections: reader.u16(offset + 2)?,
        time_date_stamp: reader.u32(offset + 4)?,
        pointer_to_symbol_table: reader.u32(offset + 8)?,
        number_of_symbols: reader.u32(offset + 12)?,
        size_of_optional_header: reader.u16(offset + 16)?,
        characteristics: reader.u16(offset + 18)?,
    })
}

fn parse_optional_header(reader: &Reader<'_>, offset: usize) -> Result<OptionalHeader64, PeError> {
    let magic = reader.u16(offset)?;
    if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        return Err(PeError::BadOptionalMagic { found: magic });
    }
    Ok(OptionalHeader64 {
        major_linker_version: reader.u8(offset + 2)?,
        minor_linker_version: reader.u8(offset + 3)?,
        size_of_code: reader.u32(offset + 4)?,
        size_of_initialized_data: reader.u32(offset + 8)?,
        size_of_uninitialized_data: reader.u32(offset + 12)?,
        address_of_entry_point: reader.u32(offset + 16)?,
        base_of_code: reader.u32(offset + 20)?,
        image_base: reader.u64(offset + 24)?,
        section_alignment: reader.u32(offset + 32)?,
        file_alignment: reader.u32(offset + 36)?,
        major_operating_system_version: reader.u16(offset + 40)?,
        minor_operating_system_version: reader.u16(offset + 42)?,
        major_image_version: reader.u16(offset + 44)?,
        minor_image_version: reader.u16(offset + 46)?,
        major_subsystem_version: reader.u16(offset + 48)?,
        minor_subsystem_version: reader.u16(offset + 50)?,
        win32_version_value: reader.u32(offset + 52)?,
        size_of_image: reader.u32(offset + 56)?,
        size_of_headers: reader.u32(offset + 60)?,
        checksum: reader.u32(offset + 64)?,
        subsystem: reader.u16(offset + 68)?,
        dll_characteristics: reader.u16(offset + 70)?,
        size_of_stack_reserve: reader.u64(offset + 72)?,
        size_of_stack_commit: reader.u64(offset + 80)?,
        size_of_heap_reserve: reader.u64(offset + 88)?,
        size_of_heap_commit: reader.u64(offset + 96)?,
        loader_flags: reader.u32(offset + 104)?,
        number_of_rva_and_sizes: reader.u32(offset + 108)?,
    })
}

fn validate_optional_header(optional: OptionalHeader64) -> Result<(), PeError> {
    if !optional.section_alignment.is_power_of_two() {
        return Err(PeError::InvalidSectionAlignment {
            value: optional.section_alignment,
        });
    }
    if !optional.file_alignment.is_power_of_two() {
        return Err(PeError::InvalidFileAlignment {
            value: optional.file_alignment,
        });
    }
    let conventional_file_alignment =
        (MIN_FILE_ALIGNMENT..=MAX_FILE_ALIGNMENT).contains(&optional.file_alignment);
    let low_alignment_image = optional.section_alignment < PAGE_SIZE
        && optional.file_alignment == optional.section_alignment;
    if !conventional_file_alignment && !low_alignment_image {
        return Err(PeError::InvalidFileAlignment {
            value: optional.file_alignment,
        });
    }
    if optional.section_alignment < optional.file_alignment
        || (optional.section_alignment < PAGE_SIZE
            && optional.section_alignment != optional.file_alignment)
    {
        return Err(PeError::InvalidAlignmentRelationship {
            section_alignment: optional.section_alignment,
            file_alignment: optional.file_alignment,
        });
    }
    if optional.image_base & (IMAGE_BASE_ALIGNMENT - 1) != 0 {
        return Err(PeError::InvalidImageBase {
            value: optional.image_base,
        });
    }
    if optional
        .image_base
        .checked_add(u64::from(optional.size_of_image))
        .is_none()
    {
        return Err(PeError::ImageAddressOverflow);
    }
    if optional.size_of_image == 0 || optional.size_of_image & (optional.section_alignment - 1) != 0
    {
        return Err(PeError::InvalidSizeOfImage {
            value: optional.size_of_image,
        });
    }
    if optional.size_of_image > MAX_IMAGE_SIZE {
        return Err(PeError::ImageTooLarge {
            value: optional.size_of_image,
            maximum: MAX_IMAGE_SIZE,
        });
    }
    if optional.size_of_headers == 0
        || optional.size_of_headers & (optional.file_alignment - 1) != 0
        || optional.size_of_headers > optional.size_of_image
    {
        return Err(PeError::InvalidSizeOfHeaders {
            value: optional.size_of_headers,
        });
    }
    if optional.address_of_entry_point >= optional.size_of_image
        && optional.address_of_entry_point != 0
    {
        return Err(PeError::EntryPointOutsideImage {
            rva: optional.address_of_entry_point,
        });
    }
    if optional.size_of_stack_commit > optional.size_of_stack_reserve {
        return Err(PeError::InvalidStackSizes {
            reserve: optional.size_of_stack_reserve,
            commit: optional.size_of_stack_commit,
        });
    }
    if optional.size_of_heap_commit > optional.size_of_heap_reserve {
        return Err(PeError::InvalidHeapSizes {
            reserve: optional.size_of_heap_reserve,
            commit: optional.size_of_heap_commit,
        });
    }
    Ok(())
}

fn parse_section_header(reader: &Reader<'_>, offset: usize) -> Result<SectionHeader, PeError> {
    let mut name = [0_u8; 8];
    name.copy_from_slice(reader.bytes(offset, 8)?);
    Ok(SectionHeader {
        name,
        virtual_size: reader.u32(offset + 8)?,
        virtual_address: reader.u32(offset + 12)?,
        size_of_raw_data: reader.u32(offset + 16)?,
        pointer_to_raw_data: reader.u32(offset + 20)?,
        pointer_to_relocations: reader.u32(offset + 24)?,
        pointer_to_line_numbers: reader.u32(offset + 28)?,
        number_of_relocations: reader.u16(offset + 32)?,
        number_of_line_numbers: reader.u16(offset + 34)?,
        characteristics: reader.u32(offset + 36)?,
        mapped_size: 0,
    })
}

fn validate_section(
    file_size: usize,
    index: usize,
    section: &mut SectionHeader,
    optional: OptionalHeader64,
    header_mapped_size: u32,
) -> Result<(), PeError> {
    if section.virtual_address & (optional.section_alignment - 1) != 0 {
        return Err(PeError::SectionVirtualAddressMisaligned {
            section: index,
            value: section.virtual_address,
        });
    }
    if section.size_of_raw_data & (optional.file_alignment - 1) != 0 {
        return Err(PeError::SectionRawSizeMisaligned {
            section: index,
            value: section.size_of_raw_data,
        });
    }
    if section.size_of_raw_data != 0 {
        if optional.section_alignment < PAGE_SIZE
            && section.pointer_to_raw_data != section.virtual_address
        {
            return Err(PeError::LowAlignmentSectionOffsetMismatch {
                section: index,
                virtual_address: section.virtual_address,
                pointer_to_raw_data: section.pointer_to_raw_data,
            });
        }
        if section.pointer_to_raw_data & (optional.file_alignment - 1) != 0 {
            return Err(PeError::SectionRawPointerMisaligned {
                section: index,
                value: section.pointer_to_raw_data,
            });
        }
        if section.pointer_to_raw_data < optional.size_of_headers {
            return Err(PeError::SectionRawDataOverlapsHeaders {
                section: index,
                offset: section.pointer_to_raw_data,
            });
        }
        let raw_end = section
            .pointer_to_raw_data
            .checked_add(section.size_of_raw_data)
            .ok_or(PeError::SectionRawDataOutsideFile {
                section: index,
                offset: section.pointer_to_raw_data,
                size: section.size_of_raw_data,
            })?;
        if usize::try_from(raw_end).map_or(true, |value| value > file_size) {
            return Err(PeError::SectionRawDataOutsideFile {
                section: index,
                offset: section.pointer_to_raw_data,
                size: section.size_of_raw_data,
            });
        }
    }

    let content_size = section.virtual_size.max(section.size_of_raw_data);
    section.mapped_size = align_up(
        content_size,
        optional.section_alignment,
        "section load size",
    )?;
    if section.mapped_size == 0 {
        return Ok(());
    }
    if section.virtual_address < header_mapped_size {
        return Err(PeError::SectionVirtualRangeOverlapsHeaders {
            section: index,
            virtual_address: section.virtual_address,
        });
    }
    let virtual_end = section
        .virtual_address
        .checked_add(section.mapped_size)
        .ok_or(PeError::SectionVirtualRangeOutsideImage {
            section: index,
            virtual_address: section.virtual_address,
            mapped_size: section.mapped_size,
        })?;
    if virtual_end > optional.size_of_image {
        return Err(PeError::SectionVirtualRangeOutsideImage {
            section: index,
            virtual_address: section.virtual_address,
            mapped_size: section.mapped_size,
        });
    }
    if section.characteristics & IMAGE_SCN_MEM_WRITE != 0
        && section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    {
        return Err(PeError::WriteExecuteSection { section: index });
    }
    Ok(())
}

fn validate_section_overlaps(sections: &[SectionHeader]) -> Result<(), PeError> {
    for first in 0..sections.len() {
        for second in (first + 1)..sections.len() {
            if ranges_overlap(
                sections[first].virtual_address,
                sections[first].mapped_size,
                sections[second].virtual_address,
                sections[second].mapped_size,
            ) {
                return Err(PeError::VirtualSectionsOverlap { first, second });
            }
            if ranges_overlap(
                sections[first].pointer_to_raw_data,
                sections[first].size_of_raw_data,
                sections[second].pointer_to_raw_data,
                sections[second].size_of_raw_data,
            ) {
                return Err(PeError::RawSectionsOverlap { first, second });
            }
        }
    }
    Ok(())
}

fn validate_entry_point(
    optional: OptionalHeader64,
    sections: &[SectionHeader],
) -> Result<(), PeError> {
    let entry = optional.address_of_entry_point;
    if entry == 0 {
        return Ok(());
    }
    let executable = sections.iter().any(|section| {
        let Some(end) = section.virtual_address.checked_add(section.mapped_size) else {
            return false;
        };
        entry >= section.virtual_address
            && entry < end
            && section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    });
    if !executable {
        return Err(PeError::EntryPointNotExecutable { rva: entry });
    }
    Ok(())
}

fn ranges_overlap(first_start: u32, first_size: u32, second_start: u32, second_size: u32) -> bool {
    if first_size == 0 || second_size == 0 {
        return false;
    }
    let Some(first_end) = first_start.checked_add(first_size) else {
        return true;
    };
    let Some(second_end) = second_start.checked_add(second_size) else {
        return true;
    };
    first_start < second_end && second_start < first_end
}
