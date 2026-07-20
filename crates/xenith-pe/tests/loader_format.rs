use xenith_pe::{
    DirectorySupport, ImportTarget, PeError, PeImage, IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, MAX_IMPORTS_PER_MODULE,
    MAX_IMPORT_DIRECTORY_BYTES, RELOCATION_TYPE_DIR64,
};

const IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
const PE_OFFSET: usize = 0x80;
const COFF_OFFSET: usize = PE_OFFSET + 4;
const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
const OPTIONAL_SIZE: usize = 240;
const SECTION_TABLE_OFFSET: usize = OPTIONAL_OFFSET + OPTIONAL_SIZE;
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
    let offset = SECTION_TABLE_OFFSET + index * 40;
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

#[allow(clippy::panic)] // An invalid RVA is a test-fixture construction bug.
fn file_offset(rva: u32) -> usize {
    match rva {
        0x0000..=0x01ff => rva as usize,
        0x1000..=0x11ff => 0x200 + (rva - 0x1000) as usize,
        0x2000..=0x25ff => 0x400 + (rva - 0x2000) as usize,
        0x3000..=0x31ff => 0xa00 + (rva - 0x3000) as usize,
        _ => panic!("fixture RVA is not file-backed: {rva:#x}"),
    }
}

fn put_rva_u16(bytes: &mut [u8], rva: u32, value: u16) {
    put_u16(bytes, file_offset(rva), value);
}

fn put_rva_u32(bytes: &mut [u8], rva: u32, value: u32) {
    put_u32(bytes, file_offset(rva), value);
}

fn put_rva_u64(bytes: &mut [u8], rva: u32, value: u64) {
    put_u64(bytes, file_offset(rva), value);
}

fn put_rva_bytes(bytes: &mut [u8], rva: u32, value: &[u8]) {
    let offset = file_offset(rva);
    bytes[offset..offset + value.len()].copy_from_slice(value);
}

fn loader_image() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0xc00];
    put_u16(&mut bytes, 0, 0x5a4d);
    put_u32(&mut bytes, 0x3c, PE_OFFSET as u32);
    put_u32(&mut bytes, PE_OFFSET, 0x0000_4550);

    put_u16(&mut bytes, COFF_OFFSET, 0x8664);
    put_u16(&mut bytes, COFF_OFFSET + 2, 3);
    put_u16(&mut bytes, COFF_OFFSET + 16, OPTIONAL_SIZE as u16);
    put_u16(&mut bytes, COFF_OFFSET + 18, 0x0022);

    put_u16(&mut bytes, OPTIONAL_OFFSET, 0x020b);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 4, 0x200);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 8, 0x800);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 16, 0x1000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 20, 0x1000);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 24, IMAGE_BASE);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 32, 0x1000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 36, 0x200);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 40, 6);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 48, 6);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x4000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 60, 0x200);
    put_u16(&mut bytes, OPTIONAL_OFFSET + 68, 3);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 72, 0x10_0000);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 80, 0x1000);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 88, 0x10_0000);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 96, 0x1000);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 108, 16);

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
        b".rdata",
        (0x800, 0x2000),
        (0x600, 0x400),
        IMAGE_SCN_MEM_READ | 0x40,
    );
    section(
        &mut bytes,
        2,
        b".data",
        (0x200, 0x3000),
        (0x200, 0xa00),
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | 0x40,
    );

    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x2000, 40);
    put_rva_u32(&mut bytes, 0x2000, 0x2100);
    put_rva_u32(&mut bytes, 0x200c, 0x2080);
    put_rva_u32(&mut bytes, 0x2010, 0x2180);
    put_rva_bytes(&mut bytes, 0x2080, b"KERNEL32.dll\0");
    put_rva_u64(&mut bytes, 0x2100, 0x2200);
    put_rva_u64(&mut bytes, 0x2108, 0x8000_0000_0000_0007);
    put_rva_u64(&mut bytes, 0x2110, 0);
    put_rva_u64(&mut bytes, 0x2180, 0x2200);
    put_rva_u64(&mut bytes, 0x2188, 0x8000_0000_0000_0007);
    put_rva_u64(&mut bytes, 0x2190, 0);
    put_rva_u16(&mut bytes, 0x2200, 0x12);
    put_rva_bytes(&mut bytes, 0x2202, b"WriteFile\0");

    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0x2300, 12);
    put_rva_u32(&mut bytes, 0x2300, 0x3000);
    put_rva_u32(&mut bytes, 0x2304, 12);
    put_rva_u16(
        &mut bytes,
        0x2308,
        (u16::from(RELOCATION_TYPE_DIR64) << 12) | 0x10,
    );
    put_rva_u16(&mut bytes, 0x230a, 0);
    put_rva_u64(&mut bytes, 0x3010, IMAGE_BASE + 0x1234);
    bytes
}

fn maximum_import_table_image() -> Vec<u8> {
    const THUNK_RVA: u32 = 0x2200;
    const THUNK_FILE_OFFSET: usize = 0x600;

    let mut bytes = loader_image();
    bytes.resize(0x8a00, 0);
    let rdata = SECTION_TABLE_OFFSET + 40;
    let data = SECTION_TABLE_OFFSET + 80;
    put_u32(&mut bytes, rdata + 8, 0x8400);
    put_u32(&mut bytes, rdata + 16, 0x8400);
    put_u32(&mut bytes, data + 12, 0xb000);
    put_u32(&mut bytes, data + 20, 0x8800);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0xc000);
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0, 0);
    put_rva_u32(&mut bytes, 0x2000, 0);
    put_rva_u32(&mut bytes, 0x2010, THUNK_RVA);
    for index in 0..MAX_IMPORTS_PER_MODULE {
        put_u64(
            &mut bytes,
            THUNK_FILE_OFFSET + index * 8,
            0x8000_0000_0000_0001,
        );
    }
    put_u64(
        &mut bytes,
        THUNK_FILE_OFFSET + MAX_IMPORTS_PER_MODULE * 8,
        0,
    );
    bytes
}

#[test]
fn section_reads_require_initialized_section_bytes() {
    let bytes = loader_image();
    let image = PeImage::parse(&bytes).unwrap();

    assert_eq!(image.section_bytes(0x2080, 8).unwrap(), b"KERNEL32");
    assert!(matches!(
        image.section_bytes(0x100, 8),
        Err(PeError::RvaNotSectionBacked { .. })
    ));
    assert!(matches!(
        image.section_bytes(0x2600, 1),
        Err(PeError::RvaTouchesVirtualZeroFill { section: 1, .. })
    ));
    assert!(matches!(
        image.section_bytes(0x25ff, 2),
        Err(PeError::RvaTouchesVirtualZeroFill { section: 1, .. })
    ));
    assert!(matches!(
        image.section_bytes(0x4000, 1),
        Err(PeError::RvaOutsideImage { .. })
    ));
}

#[test]
fn plans_dir64_relocation_and_ignores_absolute_padding() {
    let bytes = loader_image();
    let image = PeImage::parse(&bytes).unwrap();
    let actual_base = IMAGE_BASE + 0x1_0000;
    let mut patches = Vec::new();
    let plan = image
        .visit_base_relocations(actual_base, |patch| patches.push(patch))
        .unwrap();

    assert_eq!(plan.patch_count, 1);
    assert_eq!(plan.image_delta, 0x1_0000);
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0].target_rva, 0x3010);
    assert_eq!(patches[0].original_value, IMAGE_BASE + 0x1234);
    assert_eq!(patches[0].relocated_value, actual_base + 0x1234);
}

#[test]
fn requires_relocations_only_when_the_base_changes() {
    let mut bytes = loader_image();
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0, 0);
    let image = PeImage::parse(&bytes).unwrap();

    assert_eq!(
        image.base_relocation_plan(IMAGE_BASE).unwrap().patch_count,
        0
    );
    assert!(matches!(
        image.base_relocation_plan(IMAGE_BASE + 0x1_0000),
        Err(PeError::RelocationsRequiredButMissing { .. })
    ));
}

#[test]
fn rejects_unaligned_actual_image_base_before_planning() {
    let bytes = loader_image();
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.base_relocation_plan(IMAGE_BASE + 1),
        Err(PeError::InvalidActualImageBase { .. })
    ));
}

#[test]
fn rejects_truncated_and_invalid_relocation_blocks() {
    let mut bytes = loader_image();
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0x2300, 6);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.base_relocation_plan(IMAGE_BASE),
        Err(PeError::RelocationBlockHeaderTruncated { .. })
    ));

    let mut bytes = loader_image();
    put_rva_u32(&mut bytes, 0x2304, 10);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.base_relocation_plan(IMAGE_BASE),
        Err(PeError::InvalidRelocationBlockSize { block_size: 10, .. })
    ));

    let mut bytes = loader_image();
    put_rva_u32(&mut bytes, 0x2304, 16);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.base_relocation_plan(IMAGE_BASE),
        Err(PeError::InvalidRelocationBlockSize { block_size: 16, .. })
    ));
}

#[test]
fn rejects_misaligned_relocation_page() {
    let mut bytes = loader_image();
    put_rva_u32(&mut bytes, 0x2300, 0x3001);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.base_relocation_plan(IMAGE_BASE),
        Err(PeError::RelocationPageMisaligned { page_rva: 0x3001 })
    ));
}

#[test]
fn rejects_relocation_page_outside_image() {
    let mut bytes = loader_image();
    put_rva_u32(&mut bytes, 0x2300, 0x4000);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.base_relocation_plan(IMAGE_BASE),
        Err(PeError::RelocationPageOutsideImage { page_rva: 0x4000 })
    ));
}

#[test]
fn rejects_relocation_blocks_out_of_page_order() {
    let mut bytes = loader_image();
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0x2300, 24);
    put_rva_u32(&mut bytes, 0x230c, 0x2000);
    put_rva_u32(&mut bytes, 0x2310, 12);
    put_rva_u16(&mut bytes, 0x2314, 0);
    put_rva_u16(&mut bytes, 0x2316, 0);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.base_relocation_plan(IMAGE_BASE),
        Err(PeError::RelocationPagesNotIncreasing {
            previous_page_rva: 0x3000,
            page_rva: 0x2000
        })
    ));
}

#[test]
fn rejects_unsupported_relocation_without_visiting_partial_plan() {
    let mut bytes = loader_image();
    put_rva_u16(&mut bytes, 0x2308, (3 << 12) | 0x10);
    let image = PeImage::parse(&bytes).unwrap();
    let mut visited = 0;
    let error = image
        .visit_base_relocations(IMAGE_BASE, |_| visited += 1)
        .unwrap_err();

    assert_eq!(visited, 0);
    assert!(matches!(error, PeError::UnsupportedRelocationType {
        relocation_type: 3,
        ..
    }));
}

#[test]
fn rejects_relocation_target_in_virtual_zero_fill() {
    let mut bytes = loader_image();
    put_rva_u32(&mut bytes, 0x2300, 0x2000);
    put_rva_u16(
        &mut bytes,
        0x2308,
        (u16::from(RELOCATION_TYPE_DIR64) << 12) | 0x600,
    );
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.base_relocation_plan(IMAGE_BASE),
        Err(PeError::RvaTouchesVirtualZeroFill { section: 1, .. })
    ));
}

#[test]
fn rejects_relocated_pointer_overflow_and_underflow() {
    let mut bytes = loader_image();
    put_rva_u64(&mut bytes, 0x3010, u64::MAX);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.base_relocation_plan(IMAGE_BASE + 0x1_0000),
        Err(PeError::RelocatedValueOverflow {
            target_rva: 0x3010,
            ..
        })
    ));

    let mut bytes = loader_image();
    put_rva_u64(&mut bytes, 0x3010, 1);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.base_relocation_plan(IMAGE_BASE - 0x1_0000),
        Err(PeError::RelocatedValueOverflow {
            target_rva: 0x3010,
            ..
        })
    ));
}

#[test]
fn parses_named_and_ordinal_imports() {
    let bytes = loader_image();
    let image = PeImage::parse(&bytes).unwrap();
    let mut imports = Vec::new();
    let summary = image.visit_imports(|record| imports.push(record)).unwrap();

    assert_eq!(summary.module_count, 1);
    assert_eq!(summary.import_count, 2);
    assert_eq!(imports[0].module_name, b"KERNEL32.dll");
    assert_eq!(imports[0].lookup_rva, 0x2100);
    assert_eq!(imports[0].iat_rva, 0x2180);
    assert_eq!(imports[0].target, ImportTarget::Name {
        hint: 0x12,
        name: b"WriteFile"
    });
    assert_eq!(imports[1].target, ImportTarget::Ordinal(7));
}

#[test]
fn per_module_import_bound_reserves_the_final_scanned_slot_for_termination() {
    assert_eq!(MAX_IMPORTS_PER_MODULE, 4_095);
    let mut bytes = maximum_import_table_image();
    let image = PeImage::parse(&bytes).unwrap();
    let summary = image.import_summary().unwrap();
    assert_eq!(summary.module_count, 1);
    assert_eq!(summary.import_count, MAX_IMPORTS_PER_MODULE);

    const THUNK_FILE_OFFSET: usize = 0x600;
    put_u64(
        &mut bytes,
        THUNK_FILE_OFFSET + MAX_IMPORTS_PER_MODULE * 8,
        0x8000_0000_0000_0001,
    );
    let image = PeImage::parse(&bytes).unwrap();
    assert_eq!(
        image.import_summary(),
        Err(PeError::UnterminatedImportThunkTable {
            descriptor: 0,
            maximum: MAX_IMPORTS_PER_MODULE,
        })
    );
}

#[test]
fn empty_regular_import_directory_has_zero_summary() {
    let mut bytes = loader_image();
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_IMPORT, 0, 0);
    let image = PeImage::parse(&bytes).unwrap();
    let summary = image.import_summary().unwrap();
    assert_eq!(summary.module_count, 0);
    assert_eq!(summary.import_count, 0);
}

#[test]
fn rejects_bad_import_directory_shape_and_missing_terminator() {
    let mut bytes = loader_image();
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x2000, 21);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::InvalidImportDirectorySize { size: 21 })
    ));

    let mut bytes = loader_image();
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x2000, 20);
    let image = PeImage::parse(&bytes).unwrap();
    assert_eq!(
        image.import_summary().unwrap_err(),
        PeError::UnterminatedImportDirectory
    );
}

#[test]
fn rejects_import_directory_above_explicit_work_bound() {
    let mut bytes = loader_image();
    bytes.resize(0x1c00, 0);
    let rdata = SECTION_TABLE_OFFSET + 40;
    let data = SECTION_TABLE_OFFSET + 80;
    put_u32(&mut bytes, rdata + 8, 0x1600);
    put_u32(&mut bytes, rdata + 16, 0x1600);
    put_u32(&mut bytes, data + 12, 0x4000);
    put_u32(&mut bytes, data + 20, 0x1a00);
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x5000);
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0, 0);
    directory(
        &mut bytes,
        IMAGE_DIRECTORY_ENTRY_IMPORT,
        0x2000,
        MAX_IMPORT_DIRECTORY_BYTES + 20,
    );
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::ImportDirectoryTooLarge {
            size,
            maximum: MAX_IMPORT_DIRECTORY_BYTES
        }) if size == MAX_IMPORT_DIRECTORY_BYTES + 20
    ));
}

#[test]
fn rejects_nonzero_bytes_after_null_import_descriptor() {
    let mut bytes = loader_image();
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x2000, 60);
    put_rva_u32(&mut bytes, 0x2028, 1);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::NonZeroImportDirectoryTail {
            directory_offset: 40
        })
    ));
}

#[test]
fn rejects_missing_import_descriptor_fields() {
    let mut bytes = loader_image();
    put_rva_u32(&mut bytes, 0x200c, 0);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::MissingImportModuleName { descriptor: 0 })
    ));

    let mut bytes = loader_image();
    put_rva_u32(&mut bytes, 0x2010, 0);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::MissingImportAddressTable { descriptor: 0 })
    ));
}

#[test]
fn rejects_misaligned_or_empty_import_thunk_table() {
    let mut bytes = loader_image();
    put_rva_u32(&mut bytes, 0x2000, 0x2104);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::ImportThunkTableMisaligned { rva: 0x2104, .. })
    ));

    let mut bytes = loader_image();
    put_rva_u64(&mut bytes, 0x2100, 0);
    put_rva_u64(&mut bytes, 0x2180, 0);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::EmptyImportThunkTable { descriptor: 0 })
    ));
}

#[test]
fn rejects_invalid_ordinal_encodings() {
    let mut bytes = loader_image();
    put_rva_u64(&mut bytes, 0x2108, 0x8000_0000_0001_0007);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::InvalidOrdinalImportEncoding { thunk: 1, .. })
    ));

    let mut bytes = loader_image();
    put_rva_u64(&mut bytes, 0x2108, 0x8000_0000_0000_0000);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::InvalidImportOrdinal { thunk: 1, .. })
    ));
}

#[test]
fn rejects_named_import_rva_wider_than_pe32_plus_rva() {
    let mut bytes = loader_image();
    put_rva_u64(&mut bytes, 0x2100, 0x0000_0001_0000_2200);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::ImportNameRvaTooWide { thunk: 0, .. })
    ));
}

#[test]
fn rejects_import_name_in_virtual_zero_fill() {
    let mut bytes = loader_image();
    put_rva_u32(&mut bytes, 0x200c, 0x2600);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::RvaTouchesVirtualZeroFill { section: 1, .. })
    ));
}

#[test]
fn rejects_invalid_empty_and_overlong_import_names() {
    let mut bytes = loader_image();
    put_rva_bytes(&mut bytes, 0x2080, b"BAD\x1fNAME\0");
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::InvalidImportNameByte { byte: 0x1f, .. })
    ));

    let mut bytes = loader_image();
    put_rva_bytes(&mut bytes, 0x2080, b"\0");
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::EmptyImportName { rva: 0x2080 })
    ));

    let mut bytes = loader_image();
    put_rva_u32(&mut bytes, 0x200c, 0x2400);
    put_rva_bytes(&mut bytes, 0x2400, &[b'A'; 257]);
    put_rva_bytes(&mut bytes, 0x2501, b"\0");
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::ImportNameTooLong { rva: 0x2400, .. })
    ));
}

#[test]
fn rejects_nonzero_iat_terminator() {
    let mut bytes = loader_image();
    put_rva_u64(&mut bytes, 0x2190, 1);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::NonZeroImportAddressTerminator { rva: 0x2190, .. })
    ));
}

#[test]
fn validates_entire_import_table_before_visiting() {
    let mut bytes = loader_image();
    put_rva_u32(&mut bytes, 0x2000, 0x25f8);
    put_rva_u64(&mut bytes, 0x25f8, 0x2200);
    let image = PeImage::parse(&bytes).unwrap();
    let mut visited = 0;
    let error = image.visit_imports(|_| visited += 1).unwrap_err();

    assert_eq!(visited, 0);
    assert!(matches!(error, PeError::RvaTouchesVirtualZeroFill {
        section: 1,
        ..
    }));
}

#[test]
fn regular_import_directory_must_be_section_backed() {
    let mut bytes = loader_image();
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x100, 20);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.import_summary(),
        Err(PeError::RvaNotSectionBacked {
            rva: 0x100,
            size: 20
        })
    ));
}

#[test]
fn reports_tls_and_delay_import_policy_explicitly() {
    let mut bytes = loader_image();
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_TLS, 0x2400, 16);
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2420, 32);
    let image = PeImage::parse(&bytes).unwrap();
    let policy = image.loader_format_policy();

    assert_eq!(policy.regular_imports, DirectorySupport::Supported);
    assert_eq!(policy.base_relocations, DirectorySupport::Supported);
    assert_eq!(policy.tls, DirectorySupport::Unsupported);
    assert_eq!(policy.delay_imports, DirectorySupport::Unsupported);
    assert!(matches!(
        image.require_initial_loader_policy(),
        Err(PeError::UnsupportedTlsDirectory {
            rva: 0x2400,
            size: 16
        })
    ));
}

#[test]
fn reports_delay_import_error_when_tls_is_absent() {
    let mut bytes = loader_image();
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2420, 32);
    let image = PeImage::parse(&bytes).unwrap();
    assert!(matches!(
        image.require_initial_loader_policy(),
        Err(PeError::UnsupportedDelayImportDirectory {
            rva: 0x2420,
            size: 32
        })
    ));
}
