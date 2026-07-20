use xenith_winhost_core::{
    AddressError, ExportQuery, ExportTargetRegistration, ImportResolution, ModuleError, ModuleName,
    ModuleRegistry, ReservationKind, VirtualAddressPlanner, VmProtection, MAX_ADDRESS_RESERVATIONS,
    MAX_REGISTERED_EXPORTS, MAX_REGISTERED_MODULES,
};

#[test]
fn module_registry_capacities_are_explicit() {
    assert!(matches!(
        ModuleRegistry::<0, 1>::try_new(),
        Err(ModuleError::InvalidCapacity { .. })
    ));
    assert!(matches!(
        ModuleRegistry::<1, 0>::try_new(),
        Err(ModuleError::InvalidCapacity { .. })
    ));
    // Avoid constructing deliberately enormous values on the test-thread stack.
    assert_eq!(MAX_REGISTERED_MODULES, 256);
    assert_eq!(MAX_REGISTERED_EXPORTS, 4_096);
}

#[test]
fn module_names_have_a_narrow_explicit_bootstrap_grammar() {
    let name = ModuleName::parse(b"Kernel32.DlL").unwrap();
    assert_eq!(name.as_bytes(), b"KERNEL32.DLL");
    assert!(!name.is_api_set());
    assert!(ModuleName::parse(b"").is_err());
    assert!(ModuleName::parse(b"C:\\Windows\\kernel32.dll").is_err());
    assert!(ModuleName::parse(b"bad name.dll").is_err());
    assert!(ModuleName::parse(&vec![b'a'; 257]).is_err());
}

#[test]
fn module_registration_is_case_insensitive_and_range_checked() {
    let mut registry = ModuleRegistry::<3, 4>::try_new().unwrap();
    let first = registry
        .register_module(b"kernel32.dll", 0x1000_0000, 0x20_000)
        .unwrap();
    assert_eq!(first.slot(), 0);
    assert_eq!(first.generation(), 1);
    assert_eq!(registry.len(), 1);
    assert!(!registry.is_empty());
    assert_eq!(
        registry.register_module(b"KERNEL32.DLL", 0x2000_0000, 0x10_000),
        Err(ModuleError::DuplicateModule)
    );
    assert_eq!(
        registry.register_module(b"user32.dll", 0x1001_0000, 0x20_000),
        Err(ModuleError::OverlappingImage)
    );
    assert_eq!(
        registry.register_module(b"user32.dll", u64::MAX, 1),
        Err(ModuleError::InvalidImageRange)
    );
}

#[test]
fn direct_exports_resolve_by_exact_name_or_ordinal() {
    let mut registry = ModuleRegistry::<2, 4>::try_new().unwrap();
    let module = registry
        .register_module(b"kernel32.dll", 0x1800_0000, 0x10_000)
        .unwrap();
    registry
        .register_export(
            module,
            ExportQuery::Name(b"WriteFile"),
            ExportTargetRegistration::ImageRva(0x1234),
        )
        .unwrap();
    registry
        .register_export(
            module,
            ExportQuery::Ordinal(7),
            ExportTargetRegistration::ImageRva(0x4321),
        )
        .unwrap();

    assert_eq!(
        registry.resolve(b"KeRnEl32.DlL", ExportQuery::Name(b"WriteFile")),
        ImportResolution::Resolved {
            module,
            address: 0x1800_1234,
        }
    );
    assert_eq!(
        registry.resolve(b"kernel32.dll", ExportQuery::Ordinal(7)),
        ImportResolution::Resolved {
            module,
            address: 0x1800_4321,
        }
    );
    assert_eq!(
        registry.resolve(b"kernel32.dll", ExportQuery::Name(b"writefile")),
        ImportResolution::SymbolNotFound { module }
    );
}

#[test]
fn missing_invalid_and_api_set_results_are_distinct() {
    let registry = ModuleRegistry::<1, 1>::try_new().unwrap();
    assert_eq!(
        registry.resolve(b"missing.dll", ExportQuery::Name(b"Fn")),
        ImportResolution::ModuleNotFound
    );
    assert_eq!(
        registry.resolve(b"bad/path.dll", ExportQuery::Name(b"Fn")),
        ImportResolution::InvalidModuleName
    );
    assert_eq!(
        registry.resolve(b"api-ms-win-core-file-l1-1-0.dll", ExportQuery::Name(b"Fn")),
        ImportResolution::UnsupportedApiSet
    );
    assert_eq!(
        registry.resolve(
            b"EXT-MS-WIN-NTUSER-WINDOW-L1-1-0.DLL",
            ExportQuery::Name(b"Fn")
        ),
        ImportResolution::UnsupportedApiSet
    );
    assert_eq!(
        registry.resolve(b"missing.dll", ExportQuery::Ordinal(0)),
        ImportResolution::InvalidSymbol
    );
}

#[test]
#[allow(clippy::panic)]
fn forwarders_are_retained_but_never_followed_implicitly() {
    let mut registry = ModuleRegistry::<1, 2>::try_new().unwrap();
    let module = registry
        .register_module(b"kernel32.dll", 0x1800_0000, 0x10_000)
        .unwrap();
    registry
        .register_export(
            module,
            ExportQuery::Name(b"Sleep"),
            ExportTargetRegistration::Forwarder(b"KERNELBASE.Sleep"),
        )
        .unwrap();
    let outcome = registry.resolve(b"kernel32.dll", ExportQuery::Name(b"Sleep"));
    match outcome {
        ImportResolution::UnsupportedForwarder {
            module: found,
            forwarder,
        } => {
            assert_eq!(found, module);
            assert_eq!(forwarder.as_bytes(), b"KERNELBASE.Sleep");
        },
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn export_registration_rejects_duplicates_bad_targets_and_full_tables() {
    let mut registry = ModuleRegistry::<1, 1>::try_new().unwrap();
    let module = registry
        .register_module(b"one.dll", 0x1000_0000, 0x1000)
        .unwrap();
    assert_eq!(
        registry.register_export(
            module,
            ExportQuery::Ordinal(0),
            ExportTargetRegistration::ImageRva(0),
        ),
        Err(ModuleError::InvalidOrdinal)
    );
    assert_eq!(
        registry.register_export(
            module,
            ExportQuery::Name(b"Outside"),
            ExportTargetRegistration::ImageRva(0x1000),
        ),
        Err(ModuleError::ExportOutsideImage)
    );
    assert_eq!(
        registry.register_export(
            module,
            ExportQuery::Name(b"Forward"),
            ExportTargetRegistration::Forwarder(b"nodot"),
        ),
        Err(ModuleError::InvalidForwarder)
    );
    registry
        .register_export(
            module,
            ExportQuery::Name(b"Only"),
            ExportTargetRegistration::ImageRva(0x100),
        )
        .unwrap();
    assert_eq!(
        registry.register_export(
            module,
            ExportQuery::Name(b"Only"),
            ExportTargetRegistration::ImageRva(0x200),
        ),
        Err(ModuleError::DuplicateExport)
    );
    assert_eq!(
        registry.register_export(
            module,
            ExportQuery::Name(b"Second"),
            ExportTargetRegistration::ImageRva(0x200),
        ),
        Err(ModuleError::ExportTableFull)
    );
}

#[test]
fn unregister_invalidates_module_ids_and_reuses_with_a_new_generation() {
    let mut registry = ModuleRegistry::<1, 1>::try_new().unwrap();
    let old = registry
        .register_module(b"old.dll", 0x1000_0000, 0x1000)
        .unwrap();
    assert_eq!(
        registry.unregister_module(old).unwrap(),
        (0x1000_0000, 0x1000)
    );
    let current = registry
        .register_module(b"new.dll", 0x2000_0000, 0x1000)
        .unwrap();
    assert_eq!(current.slot(), old.slot());
    assert_ne!(current.generation(), old.generation());
    assert_eq!(
        registry.unregister_module(old),
        Err(ModuleError::InvalidModuleId)
    );
}

#[test]
fn export_capacity_is_global_and_unregister_releases_owned_entries() {
    let mut registry = ModuleRegistry::<2, 2>::try_new().unwrap();
    let first = registry
        .register_module(b"first.dll", 0x1000_0000, 0x1000)
        .unwrap();
    let second = registry
        .register_module(b"second.dll", 0x2000_0000, 0x1000)
        .unwrap();
    registry
        .register_export(
            first,
            ExportQuery::Name(b"First"),
            ExportTargetRegistration::ImageRva(0x100),
        )
        .unwrap();
    registry
        .register_export(
            second,
            ExportQuery::Name(b"Second"),
            ExportTargetRegistration::ImageRva(0x200),
        )
        .unwrap();
    assert_eq!(registry.export_count(), 2);
    assert_eq!(
        registry.register_export(
            second,
            ExportQuery::Name(b"Full"),
            ExportTargetRegistration::ImageRva(0x300),
        ),
        Err(ModuleError::ExportTableFull)
    );

    registry.unregister_module(first).unwrap();
    assert_eq!(registry.export_count(), 1);
    registry
        .register_export(
            second,
            ExportQuery::Name(b"NowFits"),
            ExportTargetRegistration::ImageRva(0x300),
        )
        .unwrap();
    assert_eq!(registry.export_count(), 2);
    assert_eq!(
        registry.resolve(b"second.dll", ExportQuery::Name(b"Second")),
        ImportResolution::Resolved {
            module: second,
            address: 0x2000_0200,
        }
    );
}

#[test]
fn address_planner_validates_bounds_capacity_and_wx() {
    assert!(matches!(
        VirtualAddressPlanner::<0>::try_new(0x1000, 0x2000),
        Err(AddressError::InvalidCapacity { .. })
    ));
    assert!(matches!(
        VirtualAddressPlanner::<{ MAX_ADDRESS_RESERVATIONS + 1 }>::try_new(0x1000, 0x2000),
        Err(AddressError::InvalidCapacity { .. })
    ));
    assert_eq!(
        VirtualAddressPlanner::<2>::try_new(0x1001, 0x3000).err(),
        Some(AddressError::InvalidBounds)
    );
    assert_eq!(
        VmProtection::try_new(true, true, true),
        Err(AddressError::WritableExecutable)
    );
    assert!(VmProtection::READ_EXECUTE.is_readable());
    assert!(VmProtection::READ_EXECUTE.is_executable());
    assert!(!VmProtection::READ_EXECUTE.is_writable());
}

#[test]
fn exact_reservations_are_sorted_and_overlap_is_rejected() {
    let mut planner = VirtualAddressPlanner::<4>::try_new(0x1000, 0x10_000).unwrap();
    planner
        .reserve_exact(
            0x8000,
            0x1000,
            VmProtection::READ_WRITE,
            ReservationKind::Heap,
        )
        .unwrap();
    planner
        .reserve_exact(
            0x2000,
            0x2000,
            VmProtection::READ_EXECUTE,
            ReservationKind::HostRuntime,
        )
        .unwrap();
    assert_eq!(planner.reservations()[0].start, 0x2000);
    assert_eq!(planner.reservations()[1].start, 0x8000);
    assert_eq!(
        planner.reserve_exact(
            0x3000,
            0x1000,
            VmProtection::READ,
            ReservationKind::Other(1),
        ),
        Err(AddressError::Overlap)
    );
    assert_eq!(
        planner.reserve_exact(
            0x2800,
            0x1000,
            VmProtection::READ,
            ReservationKind::Other(1),
        ),
        Err(AddressError::MisalignedAddress)
    );
}

#[test]
fn first_fit_is_lowest_address_and_honors_alignment() {
    let mut planner = VirtualAddressPlanner::<5>::try_new(0x1000, 0x20_000).unwrap();
    planner
        .reserve_exact(0x1000, 0x3000, VmProtection::READ, ReservationKind::Guard)
        .unwrap();
    planner
        .reserve_exact(0x8000, 0x2000, VmProtection::READ, ReservationKind::Guard)
        .unwrap();
    let page = planner
        .reserve_first_fit(
            0x1000,
            0x1000,
            VmProtection::READ_WRITE,
            ReservationKind::Stack,
        )
        .unwrap();
    assert_eq!(page.start, 0x4000);
    let aligned = planner
        .reserve_first_fit(
            0x1000,
            0x4000,
            VmProtection::READ_WRITE,
            ReservationKind::Shared,
        )
        .unwrap();
    assert_eq!(aligned.start, 0x_0000_c000);
}

#[test]
fn invalid_sizes_alignments_space_and_table_full_are_reported() {
    let mut planner = VirtualAddressPlanner::<1>::try_new(0x1000, 0x4000).unwrap();
    assert_eq!(
        planner.reserve_first_fit(1, 0x1000, VmProtection::READ, ReservationKind::Other(0),),
        Err(AddressError::InvalidSize)
    );
    assert_eq!(
        planner.reserve_first_fit(
            0x1000,
            0x1800,
            VmProtection::READ,
            ReservationKind::Other(0),
        ),
        Err(AddressError::InvalidAlignment)
    );
    planner
        .reserve_exact(0x1000, 0x1000, VmProtection::NONE, ReservationKind::Guard)
        .unwrap();
    assert_eq!(
        planner.reserve_exact(
            0x3000,
            0x1000,
            VmProtection::READ,
            ReservationKind::Other(1),
        ),
        Err(AddressError::ReservationTableFull)
    );

    let mut small = VirtualAddressPlanner::<2>::try_new(0x1000, 0x3000).unwrap();
    small
        .reserve_exact(0x1000, 0x2000, VmProtection::NONE, ReservationKind::Guard)
        .unwrap();
    assert_eq!(
        small.reserve_first_fit(
            0x1000,
            0x1000,
            VmProtection::READ,
            ReservationKind::Other(2),
        ),
        Err(AddressError::OutOfAddressSpace)
    );
}
