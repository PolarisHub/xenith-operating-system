use xenith_pe::{
    PeError, PeImage, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, RELOCATION_TYPE_DIR64,
};
use xenith_winhost_core::{
    AddressError, ExportQuery, ExportTargetRegistration, ImagePlacement, ImportPlanError,
    ImportResolution, ImportSymbol, ModuleRegistry, ReservationKind, VirtualAddressPlanner,
    VmProtection,
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

#[allow(clippy::panic)]
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

fn loader_image(module_name: &[u8]) -> Vec<u8> {
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
    put_rva_bytes(&mut bytes, 0x2080, module_name);
    put_rva_bytes(&mut bytes, 0x2080 + module_name.len() as u32, &[0]);
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

#[test]
fn import_plan_consumes_named_and_ordinal_xenith_pe_records() {
    let bytes = loader_image(b"KERNEL32.dll");
    let image = PeImage::parse(&bytes).unwrap();
    let mut registry = ModuleRegistry::<2, 4>::try_new().unwrap();
    let module = registry
        .register_module(b"kernel32.dll", 0x1800_0000, 0x20_000)
        .unwrap();
    registry
        .register_export(
            module,
            ExportQuery::Name(b"WriteFile"),
            ExportTargetRegistration::ImageRva(0x1110),
        )
        .unwrap();
    registry
        .register_export(
            module,
            ExportQuery::Ordinal(7),
            ExportTargetRegistration::ImageRva(0x2220),
        )
        .unwrap();

    let plan = registry.plan_imports::<2>(&image).unwrap();
    assert_eq!(plan.len(), 2);
    assert!(!plan.is_empty());
    assert!(plan.is_fully_resolved());
    assert_eq!(plan.unresolved_count(), 0);
    assert_eq!(plan.bindings()[0].iat_rva, 0x2180);
    assert_eq!(plan.bindings()[0].module.as_bytes(), b"KERNEL32.DLL");
    assert!(matches!(
        plan.bindings()[0].symbol,
        ImportSymbol::Name { hint: 0x12, name } if name.as_bytes() == b"WriteFile"
    ));
    assert_eq!(plan.bindings()[0].resolution, ImportResolution::Resolved {
        module,
        address: 0x1800_1110,
    });
    assert_eq!(plan.bindings()[1].symbol, ImportSymbol::Ordinal(7));
    assert_eq!(plan.bindings()[1].resolution, ImportResolution::Resolved {
        module,
        address: 0x1800_2220,
    });
}

#[test]
fn import_plan_reports_capacity_before_emitting_a_partial_plan() {
    let bytes = loader_image(b"KERNEL32.dll");
    let image = PeImage::parse(&bytes).unwrap();
    let registry = ModuleRegistry::<1, 1>::try_new().unwrap();
    assert_eq!(
        registry.plan_imports::<1>(&image),
        Err(ImportPlanError::PlanFull {
            required: 2,
            capacity: 1,
        })
    );
}

#[test]
fn import_plan_preserves_missing_forwarder_and_api_set_outcomes() {
    let bytes = loader_image(b"KERNEL32.dll");
    let image = PeImage::parse(&bytes).unwrap();
    let mut registry = ModuleRegistry::<1, 2>::try_new().unwrap();
    let module = registry
        .register_module(b"kernel32.dll", 0x1800_0000, 0x20_000)
        .unwrap();
    registry
        .register_export(
            module,
            ExportQuery::Name(b"WriteFile"),
            ExportTargetRegistration::Forwarder(b"KERNELBASE.WriteFile"),
        )
        .unwrap();
    let plan = registry.plan_imports::<2>(&image).unwrap();
    assert!(matches!(
        plan.bindings()[0].resolution,
        ImportResolution::UnsupportedForwarder { module: found, forwarder }
            if found == module && forwarder.as_bytes() == b"KERNELBASE.WriteFile"
    ));
    assert_eq!(
        plan.bindings()[1].resolution,
        ImportResolution::SymbolNotFound { module }
    );
    assert_eq!(plan.unresolved_count(), 2);

    let api_bytes = loader_image(b"api-ms-win-core-file-l1-1-0.dll");
    let api_image = PeImage::parse(&api_bytes).unwrap();
    let api_plan = registry.plan_imports::<2>(&api_image).unwrap();
    assert!(api_plan
        .bindings()
        .iter()
        .all(|binding| binding.resolution == ImportResolution::UnsupportedApiSet));
}

#[test]
fn import_plan_rejects_module_paths_instead_of_treating_them_as_basenames() {
    let bytes = loader_image(b"bad/path.dll");
    let image = PeImage::parse(&bytes).unwrap();
    let registry = ModuleRegistry::<1, 1>::try_new().unwrap();
    assert_eq!(
        registry.plan_imports::<2>(&image),
        Err(ImportPlanError::InvalidModuleName {
            descriptor_index: 0,
        })
    );
}

#[test]
fn malformed_imports_remain_xenith_pe_errors() {
    let mut bytes = loader_image(b"KERNEL32.dll");
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x2000, 21);
    let image = PeImage::parse(&bytes).unwrap();
    let registry = ModuleRegistry::<1, 1>::try_new().unwrap();
    assert!(matches!(
        registry.plan_imports::<2>(&image),
        Err(ImportPlanError::Pe(PeError::InvalidImportDirectorySize {
            size: 21
        }))
    ));
}

#[test]
fn preferred_pe_layout_has_exact_section_protections() {
    let bytes = loader_image(b"KERNEL32.dll");
    let image = PeImage::parse(&bytes).unwrap();
    let mut planner =
        VirtualAddressPlanner::<2>::try_new(IMAGE_BASE, IMAGE_BASE + 0x20_000).unwrap();
    let layout = planner
        .reserve_pe_image(&image, ImagePlacement::PreferredOnly)
        .unwrap();

    assert_eq!(layout.preferred_base, IMAGE_BASE);
    assert_eq!(layout.actual_base, IMAGE_BASE);
    assert!(!layout.relocated);
    assert_eq!(layout.entry_address, Some(IMAGE_BASE + 0x1000));
    assert_eq!(layout.reservation.kind, ReservationKind::PeImage);
    assert_eq!(layout.reservation.protection, VmProtection::NONE);
    assert_eq!(layout.headers.address, IMAGE_BASE);
    assert_eq!(layout.headers.protection, VmProtection::READ);
    assert_eq!(layout.sections().len(), 3);
    assert_eq!(layout.sections()[0].protection, VmProtection::READ_EXECUTE);
    assert_eq!(layout.sections()[1].protection, VmProtection::READ);
    assert_eq!(layout.sections()[2].protection, VmProtection::READ_WRITE);
    assert!(layout
        .sections()
        .iter()
        .all(|section| !(section.protection.is_writable() && section.protection.is_executable())));
}

#[test]
fn occupied_preferred_base_rebases_to_lowest_64k_gap() {
    let bytes = loader_image(b"KERNEL32.dll");
    let image = PeImage::parse(&bytes).unwrap();
    let mut planner =
        VirtualAddressPlanner::<3>::try_new(IMAGE_BASE, IMAGE_BASE + 0x30_000).unwrap();
    planner
        .reserve_exact(
            IMAGE_BASE,
            0x4000,
            VmProtection::NONE,
            ReservationKind::Guard,
        )
        .unwrap();
    let layout = planner
        .reserve_pe_image(&image, ImagePlacement::PreferredOrFirstFit)
        .unwrap();
    assert_eq!(layout.actual_base, IMAGE_BASE + 0x1_0000);
    assert!(layout.relocated);
    assert_eq!(layout.entry_address, Some(IMAGE_BASE + 0x1_1000));
    assert_eq!(planner.reservations().len(), 2);
}

#[test]
fn preferred_only_failure_does_not_mutate_the_planner() {
    let bytes = loader_image(b"KERNEL32.dll");
    let image = PeImage::parse(&bytes).unwrap();
    let mut planner =
        VirtualAddressPlanner::<3>::try_new(IMAGE_BASE, IMAGE_BASE + 0x30_000).unwrap();
    planner
        .reserve_exact(
            IMAGE_BASE,
            0x4000,
            VmProtection::NONE,
            ReservationKind::Guard,
        )
        .unwrap();
    assert_eq!(
        planner.reserve_pe_image(&image, ImagePlacement::PreferredOnly),
        Err(AddressError::PreferredAddressUnavailable)
    );
    assert_eq!(planner.len(), 1);
}

#[test]
fn fallback_requires_valid_relocations_before_reserving() {
    let mut bytes = loader_image(b"KERNEL32.dll");
    directory(&mut bytes, IMAGE_DIRECTORY_ENTRY_BASERELOC, 0, 0);
    let image = PeImage::parse(&bytes).unwrap();
    let mut planner =
        VirtualAddressPlanner::<3>::try_new(IMAGE_BASE, IMAGE_BASE + 0x30_000).unwrap();
    planner
        .reserve_exact(
            IMAGE_BASE,
            0x4000,
            VmProtection::NONE,
            ReservationKind::Guard,
        )
        .unwrap();
    assert!(matches!(
        planner.reserve_pe_image(&image, ImagePlacement::PreferredOrFirstFit),
        Err(AddressError::Pe(
            PeError::RelocationsRequiredButMissing { .. }
        ))
    ));
    assert_eq!(planner.len(), 1);
}
