use xenith_pe::{
    FileRange, PeError, PeImage, IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, MAX_DATA_DIRECTORIES, MAX_IMAGE_SIZE, MAX_SECTIONS,
};

const PE_OFFSET: usize = 0x80;
const COFF_OFFSET: usize = PE_OFFSET + 4;
const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
const OPTIONAL_SIZE: usize = 240;
const SECTION_TABLE_OFFSET: usize = OPTIONAL_OFFSET + OPTIONAL_SIZE;
const SECTION_SIZE: usize = 40;

const OPT_MAGIC: usize = OPTIONAL_OFFSET;
const OPT_ENTRY: usize = OPTIONAL_OFFSET + 16;
const OPT_IMAGE_BASE: usize = OPTIONAL_OFFSET + 24;
const OPT_SECTION_ALIGNMENT: usize = OPTIONAL_OFFSET + 32;
const OPT_FILE_ALIGNMENT: usize = OPTIONAL_OFFSET + 36;
const OPT_SIZE_IMAGE: usize = OPTIONAL_OFFSET + 56;
const OPT_SIZE_HEADERS: usize = OPTIONAL_OFFSET + 60;
const OPT_STACK_RESERVE: usize = OPTIONAL_OFFSET + 72;
const OPT_STACK_COMMIT: usize = OPTIONAL_OFFSET + 80;
const OPT_HEAP_RESERVE: usize = OPTIONAL_OFFSET + 88;
const OPT_HEAP_COMMIT: usize = OPTIONAL_OFFSET + 96;
const OPT_DIRECTORY_COUNT: usize = OPTIONAL_OFFSET + 108;
const DIRECTORY_TABLE: usize = OPTIONAL_OFFSET + 112;

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn section(
    bytes: &mut [u8],
    index: usize,
    name: &[u8],
    virtual_layout: (u32, u32),
    file_layout: (u32, u32),
    characteristics: u32,
) {
    let offset = SECTION_TABLE_OFFSET + index * SECTION_SIZE;
    bytes[offset..offset + name.len()].copy_from_slice(name);
    put_u32(bytes, offset + 8, virtual_layout.0);
    put_u32(bytes, offset + 12, virtual_layout.1);
    put_u32(bytes, offset + 16, file_layout.0);
    put_u32(bytes, offset + 20, file_layout.1);
    put_u32(bytes, offset + 36, characteristics);
}

fn directory(bytes: &mut [u8], index: usize, address: u32, size: u32) {
    let offset = DIRECTORY_TABLE + index * 8;
    put_u32(bytes, offset, address);
    put_u32(bytes, offset + 4, size);
}

fn valid_image() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x600];
    put_u16(&mut bytes, 0, 0x5a4d);
    put_u32(&mut bytes, 0x3c, PE_OFFSET as u32);
    put_u32(&mut bytes, PE_OFFSET, 0x0000_4550);

    put_u16(&mut bytes, COFF_OFFSET, 0x8664);
    put_u16(&mut bytes, COFF_OFFSET + 2, 2);
    put_u32(&mut bytes, COFF_OFFSET + 4, 0x1234_5678);
    put_u16(&mut bytes, COFF_OFFSET + 16, OPTIONAL_SIZE as u16);
    put_u16(&mut bytes, COFF_OFFSET + 18, 0x0022);

    put_u16(&mut bytes, OPT_MAGIC, 0x020b);
    bytes[OPTIONAL_OFFSET + 2] = 1;
    bytes[OPTIONAL_OFFSET + 3] = 2;
    put_u32(&mut bytes, OPTIONAL_OFFSET + 4, 0x200);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 8, 0x200);
    put_u32(&mut bytes, OPT_ENTRY, 0x1000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 20, 0x1000);
    put_u64(&mut bytes, OPT_IMAGE_BASE, 0x0000_0001_4000_0000);
    put_u32(&mut bytes, OPT_SECTION_ALIGNMENT, 0x1000);
    put_u32(&mut bytes, OPT_FILE_ALIGNMENT, 0x200);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 40, 6);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 48, 6);
    put_u32(&mut bytes, OPT_SIZE_IMAGE, 0x3000);
    put_u32(&mut bytes, OPT_SIZE_HEADERS, 0x200);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 68, 3);
    put_u64(&mut bytes, OPT_STACK_RESERVE, 0x10_0000);
    put_u64(&mut bytes, OPT_STACK_COMMIT, 0x1000);
    put_u64(&mut bytes, OPT_HEAP_RESERVE, 0x10_0000);
    put_u64(&mut bytes, OPT_HEAP_COMMIT, 0x1000);
    put_u32(&mut bytes, OPT_DIRECTORY_COUNT, MAX_DATA_DIRECTORIES as u32);

    section(
        &mut bytes,
        0,
        b".text",
        (0x180, 0x1000),
        (0x200, 0x200),
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | 0x20,
    );
    section(
        &mut bytes,
        1,
        b".data",
        (0x80, 0x2000),
        (0x200, 0x400),
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x40,
    );
    bytes
}

#[test]
fn parses_valid_amd64_pe32_plus_and_builds_plan() {
    let bytes = valid_image();
    let image = PeImage::parse(&bytes).unwrap();
    let headers = image.headers();

    assert_eq!(headers.dos.pe_offset, PE_OFFSET as u32);
    assert_eq!(headers.coff.machine, 0x8664);
    assert_eq!(headers.coff.number_of_sections, 2);
    assert_eq!(headers.optional.image_base, 0x0000_0001_4000_0000);
    assert_eq!(headers.optional.size_of_image, 0x3000);
    assert_eq!(image.sections()[0].name, *b".text\0\0\0");
    assert_eq!(image.sections()[0].mapped_size, 0x1000);
    assert_eq!(image.directories().len(), 16);

    let plan = image.loader_plan().unwrap();
    assert_eq!(plan.headers.file, FileRange {
        offset: 0,
        size: 0x200
    });
    assert_eq!(plan.headers.virtual_range.size, 0x1000);
    assert_eq!(plan.sections().len(), 2);
    assert!(plan.sections()[0].permissions.execute);
    assert!(!plan.sections()[0].permissions.write);
    assert!(plan.sections()[1].permissions.write);
    assert_eq!(plan.preferred_entry(), Some(0x0000_0001_4000_1000));
}

#[test]
fn resolves_only_contiguous_file_backed_rvas() {
    let bytes = valid_image();
    let image = PeImage::parse(&bytes).unwrap();

    assert_eq!(image.rva_to_file_range(0x40, 8).unwrap(), FileRange {
        offset: 0x40,
        size: 8
    });
    assert_eq!(image.rva_to_file_range(0x1080, 0x20).unwrap(), FileRange {
        offset: 0x280,
        size: 0x20
    });
    assert!(matches!(
        image.rva_to_file_range(0x2200, 1),
        Err(PeError::RvaNotFileBacked { .. })
    ));
    assert!(matches!(
        image.rva_to_file_range(0x2fff, 2),
        Err(PeError::RvaOutsideImage { .. })
    ));
}

#[test]
fn accepts_mapped_and_security_directories_with_distinct_address_rules() {
    let mut bytes = valid_image();
    directory(&mut bytes, 1, 0x2000, 0x20);
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_SECURITY, 0x580, 0x20);

    let image = PeImage::parse(&bytes).unwrap();
    assert_eq!(image.directory(1).unwrap().address, 0x2000);
    assert_eq!(
        image
            .file_bytes(image.rva_to_file_range(0x2000, 0x20).unwrap())
            .unwrap()
            .len(),
        0x20
    );
}

#[test]
fn rejects_every_truncation_boundary_without_panicking() {
    let bytes = valid_image();
    for length in 0..bytes.len() {
        let result = PeImage::parse(&bytes[..length]);
        if length < 0x600 {
            assert!(result.is_err(), "unexpected success at length {length:#x}");
        }
    }
}

#[test]
fn rejects_bad_dos_magic() {
    let mut bytes = valid_image();
    put_u16(&mut bytes, 0, 0x1234);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::BadDosMagic { found: 0x1234 })
    ));
}

#[test]
fn rejects_pe_header_inside_dos_header() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, 0x3c, 0x20);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::PeHeaderOverlapsDosHeader { offset: 0x20 })
    ));
}

#[test]
fn rejects_bad_pe_signature() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, PE_OFFSET, 0xdead_beef);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::BadPeSignature { found: 0xdead_beef })
    ));
}

#[test]
fn rejects_non_amd64_machine() {
    let mut bytes = valid_image();
    put_u16(&mut bytes, COFF_OFFSET, 0x014c);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::UnsupportedMachine { found: 0x014c })
    ));
}

#[test]
fn rejects_zero_or_excessive_sections() {
    let mut bytes = valid_image();
    put_u16(&mut bytes, COFF_OFFSET + 2, 0);
    assert_eq!(PeImage::parse(&bytes).unwrap_err(), PeError::NoSections);

    let mut bytes = valid_image();
    put_u16(&mut bytes, COFF_OFFSET + 2, (MAX_SECTIONS + 1) as u16);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::TooManySections { .. })
    ));
}

#[test]
fn rejects_short_optional_header_and_pe32_magic() {
    let mut bytes = valid_image();
    put_u16(&mut bytes, COFF_OFFSET + 16, 111);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::OptionalHeaderTooSmall { size: 111 })
    ));

    let mut bytes = valid_image();
    put_u16(&mut bytes, OPT_MAGIC, 0x010b);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::BadOptionalMagic { found: 0x010b })
    ));
}

#[test]
fn rejects_excessive_or_truncated_directory_table() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, OPT_DIRECTORY_COUNT, 17);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::TooManyDataDirectories { count: 17 })
    ));

    let mut bytes = valid_image();
    put_u16(&mut bytes, COFF_OFFSET + 16, 112);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::DataDirectoriesTruncated { .. })
    ));
}

#[test]
fn rejects_invalid_alignment_values_and_relationships() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, OPT_FILE_ALIGNMENT, 0x300);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::InvalidFileAlignment { value: 0x300 })
    ));

    let mut bytes = valid_image();
    put_u32(&mut bytes, OPT_SECTION_ALIGNMENT, 0x1800);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::InvalidSectionAlignment { value: 0x1800 })
    ));

    let mut bytes = valid_image();
    put_u32(&mut bytes, OPT_SECTION_ALIGNMENT, 0x100);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::InvalidAlignmentRelationship { .. })
    ));
}

#[test]
fn rejects_low_alignment_sections_whose_file_offsets_differ_from_rvas() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, OPT_SECTION_ALIGNMENT, 0x200);
    put_u32(&mut bytes, OPT_SIZE_IMAGE, 0x2200);
    assert_eq!(
        PeImage::parse(&bytes).unwrap_err(),
        PeError::LowAlignmentSectionOffsetMismatch {
            section: 0,
            virtual_address: 0x1000,
            pointer_to_raw_data: 0x200,
        }
    );
}

#[test]
fn accepts_low_alignment_sections_when_file_offsets_equal_rvas() {
    let mut bytes = valid_image();
    bytes.resize(0x2200, 0);
    put_u32(&mut bytes, OPT_SECTION_ALIGNMENT, 0x200);
    put_u32(&mut bytes, OPT_SIZE_IMAGE, 0x2200);
    put_u32(&mut bytes, SECTION_TABLE_OFFSET + 20, 0x1000);
    put_u32(&mut bytes, SECTION_TABLE_OFFSET + SECTION_SIZE + 20, 0x2000);
    assert!(PeImage::parse(&bytes).is_ok());
}

#[test]
fn rejects_misaligned_image_base_and_address_overflow() {
    let mut bytes = valid_image();
    put_u64(&mut bytes, OPT_IMAGE_BASE, 0x1400_1000);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::InvalidImageBase { .. })
    ));

    let mut bytes = valid_image();
    put_u64(&mut bytes, OPT_IMAGE_BASE, !0xffff_u64);
    put_u32(&mut bytes, OPT_SIZE_IMAGE, 0x2_0000);
    assert_eq!(
        PeImage::parse(&bytes).unwrap_err(),
        PeError::ImageAddressOverflow
    );
}

#[test]
fn rejects_invalid_or_excessive_image_size() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, OPT_SIZE_IMAGE, 0x2800);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::InvalidSizeOfImage { .. })
    ));

    let mut bytes = valid_image();
    put_u32(&mut bytes, OPT_SIZE_IMAGE, MAX_IMAGE_SIZE + 0x1000);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::ImageTooLarge { .. })
    ));
}

#[test]
fn rejects_bad_header_size_or_section_table_boundary() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, OPT_SIZE_HEADERS, 0x100);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::InvalidSizeOfHeaders { .. })
    ));

    let mut bytes = valid_image();
    put_u16(&mut bytes, COFF_OFFSET + 16, 0x200);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::SectionTableOutsideHeaders { .. })
    ));
}

#[test]
fn rejects_entry_point_outside_image() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, OPT_ENTRY, 0x3000);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::EntryPointOutsideImage { rva: 0x3000 })
    ));
}

#[test]
fn rejects_entry_point_outside_executable_section() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, OPT_ENTRY, 0x2000);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::EntryPointNotExecutable { rva: 0x2000 })
    ));
}

#[test]
fn accepts_an_absent_entry_point() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, OPT_ENTRY, 0);
    let image = PeImage::parse(&bytes).unwrap();
    assert_eq!(image.loader_plan().unwrap().preferred_entry(), None);
}

#[test]
fn rejects_commit_larger_than_reserve() {
    let mut bytes = valid_image();
    put_u64(&mut bytes, OPT_STACK_COMMIT, 0x20_0000);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::InvalidStackSizes { .. })
    ));

    let mut bytes = valid_image();
    put_u64(&mut bytes, OPT_HEAP_COMMIT, 0x20_0000);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::InvalidHeapSizes { .. })
    ));
}

#[test]
fn rejects_section_alignment_and_raw_alignment_errors() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, SECTION_TABLE_OFFSET + 12, 0x1100);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::SectionVirtualAddressMisaligned { .. })
    ));

    let mut bytes = valid_image();
    put_u32(&mut bytes, SECTION_TABLE_OFFSET + 16, 0x180);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::SectionRawSizeMisaligned { .. })
    ));

    let mut bytes = valid_image();
    put_u32(&mut bytes, SECTION_TABLE_OFFSET + 20, 0x300);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::SectionRawPointerMisaligned { .. })
    ));
}

#[test]
fn rejects_raw_range_overflow_and_truncation() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, SECTION_TABLE_OFFSET + 20, 0xffff_fe00);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::SectionRawDataOutsideFile { .. })
    ));

    let mut bytes = valid_image();
    bytes.truncate(0x5ff);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::Truncated { .. }) | Err(PeError::SectionRawDataOutsideFile { .. })
    ));
}

#[test]
fn rejects_section_ranges_overlapping_headers() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, SECTION_TABLE_OFFSET + 12, 0);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::SectionVirtualRangeOverlapsHeaders { .. })
    ));

    let mut bytes = valid_image();
    put_u32(&mut bytes, SECTION_TABLE_OFFSET + 20, 0);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::SectionRawDataOverlapsHeaders { .. })
    ));
}

#[test]
fn rejects_virtual_range_overflow_or_image_escape() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, SECTION_TABLE_OFFSET + 12, 0xffff_f000);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::SectionVirtualRangeOutsideImage { .. })
    ));

    let mut bytes = valid_image();
    put_u32(&mut bytes, SECTION_TABLE_OFFSET + 8, 0x3000);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::SectionVirtualRangeOutsideImage { .. })
    ));
}

#[test]
fn rejects_overlapping_virtual_sections() {
    let mut bytes = valid_image();
    let second = SECTION_TABLE_OFFSET + SECTION_SIZE;
    put_u32(&mut bytes, second + 12, 0x1000);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::VirtualSectionsOverlap {
            first: 0,
            second: 1
        })
    ));
}

#[test]
fn rejects_overlapping_raw_sections() {
    let mut bytes = valid_image();
    let second = SECTION_TABLE_OFFSET + SECTION_SIZE;
    put_u32(&mut bytes, second + 20, 0x200);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::RawSectionsOverlap {
            first: 0,
            second: 1
        })
    ));
}

#[test]
fn rejects_write_execute_section() {
    let mut bytes = valid_image();
    put_u32(
        &mut bytes,
        SECTION_TABLE_OFFSET + 36,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
    );
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::WriteExecuteSection { section: 0 })
    ));
}

#[test]
fn rejects_size_of_image_that_does_not_match_load_ranges() {
    let mut bytes = valid_image();
    put_u32(&mut bytes, OPT_SIZE_IMAGE, 0x4000);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::SizeOfImageMismatch {
            declared: 0x4000,
            required: 0x3000
        })
    ));
}

#[test]
fn rejects_incomplete_or_unbacked_mapped_directory() {
    let mut bytes = valid_image();
    directory(&mut bytes, 1, 0x2000, 0);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::IncompleteDataDirectory { directory: 1, .. })
    ));

    let mut bytes = valid_image();
    directory(&mut bytes, 1, 0x2200, 0x20);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::DataDirectoryNotFileBacked { directory: 1, .. })
    ));
}

#[test]
fn rejects_directory_rva_overflow_and_image_escape() {
    let mut bytes = valid_image();
    directory(&mut bytes, 1, 0xffff_fff0, 0x20);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::DataDirectoryOutsideImage { directory: 1, .. })
    ));

    let mut bytes = valid_image();
    directory(&mut bytes, 1, 0x2ff0, 0x20);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::DataDirectoryOutsideImage { directory: 1, .. })
    ));
}

#[test]
fn rejects_bad_certificate_file_range() {
    let mut bytes = valid_image();
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_SECURITY, 0x582, 0x10);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::CertificateTableMisaligned { .. })
    ));

    let mut bytes = valid_image();
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_SECURITY, 0x5f8, 0x20);
    assert!(matches!(
        PeImage::parse(&bytes),
        Err(PeError::CertificateTableOutsideFile { .. })
    ));
}
