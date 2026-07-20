use xenith_pe::{PeImage, IMAGE_DIRECTORY_ENTRY_BASERELOC};
use xenith_winhost::fixture::{console_fixture, CONSOLE_FIXTURE_MESSAGE};
use xenith_winhost::{
    apply_relocation_plan, build_loaded_image, materialize_image, plan_bootstrap_imports,
    plan_runtime_relocations, validate_runtime_subset, visit_final_section_protections,
    BootstrapAddresses, FinalProtection, LoaderError, MAX_HEAP_RESERVE_BYTES,
    MAX_STACK_RESERVE_BYTES, RUNTIME_PAGE_SIZE, UNSUPPORTED_COFF_CHARACTERISTICS_MASK,
    UNSUPPORTED_DLL_CHARACTERISTICS_MASK,
};
use xenith_winhost_core::NtStatus;

const IMAGE_BASE: u64 = 0x0000_0000_0020_0000;
const ACTUAL_BASE: u64 = IMAGE_BASE + 0x1_0000;
const PE_OFFSET: usize = 0x80;
const COFF_OFFSET: usize = PE_OFFSET + 4;
const OPTIONAL_OFFSET: usize = COFF_OFFSET + 20;
const OPTIONAL_SIZE: usize = 240;
const SECTION_TABLE_OFFSET: usize = OPTIONAL_OFFSET + OPTIONAL_SIZE;
const DIRECTORY_TABLE: usize = OPTIONAL_OFFSET + 112;
const IMAGE_SIZE: usize = 0x4000;
const IAT_GET_STD_HANDLE: u32 = 0x2180;
const IAT_WRITE_FILE: u32 = 0x2188;
const IAT_EXIT_PROCESS: u32 = 0x2190;
const RELOCATION_TARGET: u32 = 0x3010;
const MESSAGE_RVA: u32 = 0x2250;

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn directory(bytes: &mut [u8], index: usize, address: u32, size: u32) {
    let offset = DIRECTORY_TABLE + index * 8;
    put_u32(bytes, offset, address);
    put_u32(bytes, offset + 4, size);
}

#[allow(clippy::panic)] // An invalid RVA is a test-fixture mutation bug.
fn file_offset(rva: u32) -> usize {
    match rva {
        0x0000..=0x01ff => rva as usize,
        0x1000..=0x11ff => 0x200 + (rva - 0x1000) as usize,
        0x2000..=0x25ff => 0x400 + (rva - 0x2000) as usize,
        0x3000..=0x31ff => 0xa00 + (rva - 0x3000) as usize,
        _ => panic!("fixture RVA is not file-backed: {rva:#x}"),
    }
}

fn put_rva_u64(bytes: &mut [u8], rva: u32, value: u64) {
    put_u64(bytes, file_offset(rva), value);
}

fn addresses() -> BootstrapAddresses {
    BootstrapAddresses {
        get_std_handle: 0x1111_1111_1111_1111,
        write_file: 0x2222_2222_2222_2222,
        exit_process: 0x3333_3333_3333_3333,
        rtl_exit_user_process: Some(0x4444_4444_4444_4444),
        nt_close: Some(0x5555_5555_5555_5555),
    }
}

fn read_u64(bytes: &[u8], rva: u32) -> u64 {
    let start = rva as usize;
    u64::from_le_bytes(bytes[start..start + 8].try_into().unwrap())
}

fn read_i32(bytes: &[u8], rva: u32) -> i32 {
    let start = rva as usize;
    i32::from_le_bytes(bytes[start..start + 4].try_into().unwrap())
}

#[test]
fn deterministic_console_fixture_has_exact_mapping_iat_and_relocation_plan() {
    let bytes = console_fixture();
    let image = PeImage::parse(&bytes).unwrap();
    let loader = validate_runtime_subset(&image).unwrap();
    assert_eq!(loader.image_base, IMAGE_BASE);
    assert_eq!(loader.size_of_image as usize, IMAGE_SIZE);
    assert_eq!(loader.entry_rva, 0x1000);

    let imports = plan_bootstrap_imports(&image, addresses()).unwrap();
    assert_eq!(imports.len(), 3);
    assert_eq!(imports.patches()[0].rva(), IAT_GET_STD_HANDLE);
    assert_eq!(imports.patches()[0].address(), addresses().get_std_handle);
    assert_eq!(imports.patches()[1].rva(), IAT_WRITE_FILE);
    assert_eq!(imports.patches()[1].address(), addresses().write_file);
    assert_eq!(imports.patches()[2].rva(), IAT_EXIT_PROCESS);
    assert_eq!(imports.patches()[2].address(), addresses().exit_process);

    let relocations = plan_runtime_relocations(&image, ACTUAL_BASE).unwrap();
    assert_eq!(relocations.actual_base(), ACTUAL_BASE);
    assert_eq!(relocations.len(), 1);
    assert_eq!(relocations.patches()[0].target_rva, RELOCATION_TARGET);
    assert_eq!(
        relocations.patches()[0].original_value,
        IMAGE_BASE + u64::from(MESSAGE_RVA)
    );
    assert_eq!(
        relocations.patches()[0].relocated_value,
        ACTUAL_BASE + u64::from(MESSAGE_RVA)
    );

    let mut output = vec![0u8; IMAGE_SIZE];
    let loaded = build_loaded_image(&image, ACTUAL_BASE, addresses(), &mut output).unwrap();
    assert_eq!(loaded.entry_address, ACTUAL_BASE + 0x1000);
    assert_eq!(loaded.import_count, 3);
    assert_eq!(loaded.relocation_count, 1);
    assert_eq!(
        read_u64(&output, IAT_GET_STD_HANDLE),
        addresses().get_std_handle
    );
    assert_eq!(read_u64(&output, IAT_WRITE_FILE), addresses().write_file);
    assert_eq!(
        read_u64(&output, IAT_EXIT_PROCESS),
        addresses().exit_process
    );
    assert_eq!(
        read_u64(&output, RELOCATION_TARGET),
        ACTUAL_BASE + u64::from(MESSAGE_RVA)
    );
    assert_eq!(
        &output[MESSAGE_RVA as usize..MESSAGE_RVA as usize + CONSOLE_FIXTURE_MESSAGE.len()],
        CONSOLE_FIXTURE_MESSAGE
    );
    assert_eq!(output[0x1000], 0x48);
    assert_eq!(&output[0x1004..0x1007], &[0x48, 0x8b, 0x05]);
    assert_eq!(
        0x100b_i64 + i64::from(read_i32(&output, 0x1007)),
        i64::from(RELOCATION_TARGET)
    );
    assert_eq!(&output[0x1017..0x101c], &[0xb9, 0xf5, 0xff, 0xff, 0xff]);
    assert_eq!(&output[0x101c..0x101e], &[0xff, 0x15]);
    assert_eq!(
        0x1022_i64 + i64::from(read_i32(&output, 0x101e)),
        i64::from(IAT_GET_STD_HANDLE)
    );
}

#[test]
fn fixture_protection_plan_is_read_execute_read_and_read_write() {
    let bytes = console_fixture();
    let image = PeImage::parse(&bytes).unwrap();
    let mut protections = Vec::new();
    visit_final_section_protections(&image, |range| protections.push(range)).unwrap();
    assert_eq!(protections.len(), 3);
    assert_eq!(protections[0].rva, 0x1000);
    assert_eq!(protections[0].protection, FinalProtection::ReadExecute);
    assert_eq!(protections[1].rva, 0x2000);
    assert_eq!(protections[1].protection, FinalProtection::Read);
    assert_eq!(protections[2].rva, 0x3000);
    assert_eq!(protections[2].protection, FinalProtection::ReadWrite);
}

#[test]
fn contradictory_coff_and_dll_characteristics_are_rejected_by_exact_masks() {
    assert_eq!(UNSUPPORTED_COFF_CHARACTERISTICS_MASK, 0x5100);
    for found in [0x0100, 0x1000, 0x4000, 0x5100] {
        let mut bytes = console_fixture();
        put_u16(&mut bytes, COFF_OFFSET + 18, 0x0022 | found);
        let image = PeImage::parse(&bytes).unwrap();
        let error = validate_runtime_subset(&image).unwrap_err();
        assert_eq!(error, LoaderError::UnsupportedCoffCharacteristics { found });
        assert_eq!(error.nt_status(), NtStatus::NOT_SUPPORTED);
    }

    assert_eq!(UNSUPPORTED_DLL_CHARACTERISTICS_MASK, 0x7080);
    for found in [0x0080, 0x1000, 0x2000, 0x4000, 0x7080] {
        let mut bytes = console_fixture();
        put_u16(&mut bytes, OPTIONAL_OFFSET + 70, found);
        let image = PeImage::parse(&bytes).unwrap();
        let error = validate_runtime_subset(&image).unwrap_err();
        assert_eq!(error, LoaderError::UnsupportedDllCharacteristics { found });
        assert_eq!(error.nt_status(), NtStatus::NOT_SUPPORTED);
    }
}

#[test]
fn relocation_stripped_metadata_is_consistent_and_preferred_base_only() {
    let mut contradictory = console_fixture();
    put_u16(&mut contradictory, COFF_OFFSET + 18, 0x0023);
    let image = PeImage::parse(&contradictory).unwrap();
    let error = validate_runtime_subset(&image).unwrap_err();
    assert_eq!(error, LoaderError::RelocationsStrippedWithDirectory);
    assert_eq!(error.nt_status(), NtStatus::INVALID_IMAGE_FORMAT);

    let mut preferred_only = console_fixture();
    put_u16(&mut preferred_only, COFF_OFFSET + 18, 0x0023);
    directory(&mut preferred_only, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0, 0);
    let image = PeImage::parse(&preferred_only).unwrap();
    validate_runtime_subset(&image).unwrap();
    assert!(plan_runtime_relocations(&image, IMAGE_BASE)
        .unwrap()
        .is_empty());
    let error = plan_runtime_relocations(&image, ACTUAL_BASE).unwrap_err();
    assert_eq!(error, LoaderError::PreferredImageBaseRequired {
        preferred_image_base: IMAGE_BASE,
        actual_image_base: ACTUAL_BASE,
    });
    assert_eq!(error.nt_status(), NtStatus::CONFLICTING_ADDRESSES);
}

#[test]
fn stack_and_heap_metadata_follow_bounded_page_multiple_policy() {
    assert_eq!(RUNTIME_PAGE_SIZE, 0x1000);
    assert_eq!(MAX_STACK_RESERVE_BYTES, 8 * 1024 * 1024);
    assert_eq!(MAX_HEAP_RESERVE_BYTES, 64 * 1024 * 1024);

    let mut bytes = console_fixture();
    put_u64(&mut bytes, OPTIONAL_OFFSET + 72, 0);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 80, 0);
    let image = PeImage::parse(&bytes).unwrap();
    assert_eq!(
        validate_runtime_subset(&image),
        Err(LoaderError::InvalidStackReserve { value: 0 })
    );

    let mut bytes = console_fixture();
    put_u64(&mut bytes, OPTIONAL_OFFSET + 72, 0x1001);
    let image = PeImage::parse(&bytes).unwrap();
    assert_eq!(
        validate_runtime_subset(&image),
        Err(LoaderError::InvalidStackReserve { value: 0x1001 })
    );

    let mut bytes = console_fixture();
    put_u64(
        &mut bytes,
        OPTIONAL_OFFSET + 72,
        MAX_STACK_RESERVE_BYTES + RUNTIME_PAGE_SIZE as u64,
    );
    let image = PeImage::parse(&bytes).unwrap();
    assert_eq!(
        validate_runtime_subset(&image),
        Err(LoaderError::StackReserveTooLarge {
            value: MAX_STACK_RESERVE_BYTES + RUNTIME_PAGE_SIZE as u64,
        })
    );

    for value in [0, 0x1001] {
        let mut bytes = console_fixture();
        put_u64(&mut bytes, OPTIONAL_OFFSET + 80, value);
        let image = PeImage::parse(&bytes).unwrap();
        assert_eq!(
            validate_runtime_subset(&image),
            Err(LoaderError::InvalidStackCommit { value })
        );
    }

    let mut bytes = console_fixture();
    put_u64(&mut bytes, OPTIONAL_OFFSET + 88, 0);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 96, 0);
    let image = PeImage::parse(&bytes).unwrap();
    assert_eq!(
        validate_runtime_subset(&image),
        Err(LoaderError::InvalidHeapReserve { value: 0 })
    );

    let mut bytes = console_fixture();
    put_u64(&mut bytes, OPTIONAL_OFFSET + 88, 0x1001);
    let image = PeImage::parse(&bytes).unwrap();
    assert_eq!(
        validate_runtime_subset(&image),
        Err(LoaderError::InvalidHeapReserve { value: 0x1001 })
    );

    let mut bytes = console_fixture();
    put_u64(
        &mut bytes,
        OPTIONAL_OFFSET + 88,
        MAX_HEAP_RESERVE_BYTES + RUNTIME_PAGE_SIZE as u64,
    );
    let image = PeImage::parse(&bytes).unwrap();
    assert_eq!(
        validate_runtime_subset(&image),
        Err(LoaderError::HeapReserveTooLarge {
            value: MAX_HEAP_RESERVE_BYTES + RUNTIME_PAGE_SIZE as u64,
        })
    );

    for value in [0, 0x1001] {
        let mut bytes = console_fixture();
        put_u64(&mut bytes, OPTIONAL_OFFSET + 96, value);
        let image = PeImage::parse(&bytes).unwrap();
        assert_eq!(
            validate_runtime_subset(&image),
            Err(LoaderError::InvalidHeapCommit { value })
        );
    }

    let mut bytes = console_fixture();
    put_u64(&mut bytes, OPTIONAL_OFFSET + 72, MAX_STACK_RESERVE_BYTES);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 80, MAX_STACK_RESERVE_BYTES);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 88, MAX_HEAP_RESERVE_BYTES);
    put_u64(&mut bytes, OPTIONAL_OFFSET + 96, MAX_HEAP_RESERVE_BYTES);
    let image = PeImage::parse(&bytes).unwrap();
    validate_runtime_subset(&image).unwrap();
}

#[test]
fn materialization_failure_does_not_change_destination() {
    let bytes = console_fixture();
    let image = PeImage::parse(&bytes).unwrap();
    let mut short = vec![0xa5; IMAGE_SIZE - 1];
    let before = short.clone();
    assert_eq!(
        materialize_image(&image, &mut short),
        Err(LoaderError::InvalidImageBuffer)
    );
    assert_eq!(short, before);
}

#[test]
fn relocation_source_mismatch_is_detected_before_any_patch() {
    let bytes = console_fixture();
    let image = PeImage::parse(&bytes).unwrap();
    let plan = plan_runtime_relocations(&image, ACTUAL_BASE).unwrap();
    let mut output = vec![0u8; IMAGE_SIZE];
    materialize_image(&image, &mut output).unwrap();
    output[RELOCATION_TARGET as usize] ^= 1;
    let before = output.clone();
    assert_eq!(
        apply_relocation_plan(&plan, &mut output),
        Err(LoaderError::RelocationSourceMismatch {
            rva: RELOCATION_TARGET
        })
    );
    assert_eq!(output, before);
}

#[test]
fn overflowing_actual_image_range_does_not_change_destination() {
    let mut bytes = console_fixture();
    // Extend the final zero-fill section past one 64-KiB allocation unit so
    // the highest aligned base cannot contain the complete image.
    put_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x1_4000);
    put_u32(&mut bytes, SECTION_TABLE_OFFSET + 2 * 40 + 8, 0x1_1000);
    let image = PeImage::parse(&bytes).unwrap();
    let mut output = vec![0x5a; 0x1_4000];
    let before = output.clone();
    let overflowing_base = !0xffff_u64;
    assert!(build_loaded_image(&image, overflowing_base, addresses(), &mut output).is_err());
    assert_eq!(output, before);
}

#[test]
fn api_sets_ordinals_exceptions_and_unknown_exports_are_rejected() {
    let mut api_set = console_fixture();
    let module = file_offset(0x2080);
    api_set[module..module + 17].copy_from_slice(b"API-MS-WIN-X.DLL\0");
    let image = PeImage::parse(&api_set).unwrap();
    assert_eq!(
        plan_bootstrap_imports(&image, addresses()),
        Err(LoaderError::UnsupportedApiSet)
    );

    let mut ordinal = console_fixture();
    put_rva_u64(&mut ordinal, 0x2100, 0x8000_0000_0000_0001);
    let image = PeImage::parse(&ordinal).unwrap();
    assert_eq!(
        plan_bootstrap_imports(&image, addresses()),
        Err(LoaderError::OrdinalImport)
    );

    let mut exception = console_fixture();
    directory(&mut exception, 3, 0x2300, 12);
    let image = PeImage::parse(&exception).unwrap();
    assert_eq!(
        validate_runtime_subset(&image),
        Err(LoaderError::ExceptionDirectory)
    );

    let mut unknown = console_fixture();
    let symbol = file_offset(0x2202);
    unknown[symbol..symbol + 11].copy_from_slice(b"CreateFile\0");
    let image = PeImage::parse(&unknown).unwrap();
    assert_eq!(
        plan_bootstrap_imports(&image, addresses()),
        Err(LoaderError::SymbolNotAllowed)
    );
}

#[test]
fn zero_optional_nt_shim_addresses_are_rejected_before_iat_planning() {
    let bytes = console_fixture();
    let image = PeImage::parse(&bytes).unwrap();

    let mut invalid = addresses();
    invalid.nt_close = Some(0);
    assert_eq!(
        plan_bootstrap_imports(&image, invalid),
        Err(LoaderError::InvalidShimAddress)
    );

    invalid = addresses();
    invalid.rtl_exit_user_process = Some(0);
    assert_eq!(
        plan_bootstrap_imports(&image, invalid),
        Err(LoaderError::InvalidShimAddress)
    );
}

#[test]
fn nt_close_is_the_only_new_guest_import_wired_by_this_runtime_pass() {
    let mut bytes = console_fixture();
    let module = file_offset(0x2080);
    bytes[module..module + 13].copy_from_slice(b"NTDLL.dll\0\0\0\0");
    put_rva_u64(&mut bytes, 0x2108, 0);
    put_rva_u64(&mut bytes, IAT_WRITE_FILE, 0);
    let symbol = file_offset(0x2202);
    bytes[symbol..symbol + 8].copy_from_slice(b"NtClose\0");

    let image = PeImage::parse(&bytes).unwrap();
    let imports = plan_bootstrap_imports(&image, addresses()).unwrap();
    assert_eq!(imports.len(), 1);
    assert_eq!(imports.patches()[0].rva(), IAT_GET_STD_HANDLE);
    assert_eq!(
        imports.patches()[0].address(),
        addresses().nt_close.unwrap()
    );

    let mut unavailable = addresses();
    unavailable.nt_close = None;
    assert_eq!(
        plan_bootstrap_imports(&image, unavailable),
        Err(LoaderError::SymbolNotAllowed)
    );
}
