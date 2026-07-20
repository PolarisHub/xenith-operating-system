use core::mem::size_of;

use xenith_winhost_core::{
    ntstatus_to_dos_error, AccessMask, DosError, GuestHandle, HandleEntry, HandleError,
    HandleTable, NtSeverity, NtStatus, ObjectType, MAX_HANDLE_ENTRIES,
};

fn entry(id: u64, object_type: ObjectType, access: u32) -> HandleEntry {
    HandleEntry {
        object_id: id,
        object_type,
        access: AccessMask::from_bits(access),
        inheritable: false,
    }
}

#[test]
fn status_and_dos_types_are_exactly_32_bits() {
    assert_eq!(size_of::<NtStatus>(), 4);
    assert_eq!(size_of::<DosError>(), 4);
    assert_eq!(size_of::<GuestHandle>(), 4);
    assert_eq!(size_of::<AccessMask>(), 4);
}

#[test]
fn status_bit_patterns_and_signed_success_rule_are_preserved() {
    assert_eq!(NtStatus::SUCCESS.as_u32(), 0);
    assert_eq!(NtStatus::ACCESS_DENIED.as_u32(), 0xc000_0022);
    assert_eq!(NtStatus::ACCESS_DENIED.as_i32(), -1_073_741_790);
    assert!(NtStatus::SUCCESS.is_success());
    assert!(NtStatus::PENDING.is_success());
    assert!(NtStatus::from_u32(0x4000_1234).is_success());
    assert!(!NtStatus::BUFFER_OVERFLOW.is_success());
    assert!(!NtStatus::ACCESS_DENIED.is_success());
}

#[test]
fn bootstrap_status_constants_match_their_documented_bit_patterns() {
    let cases = [
        (NtStatus::SUCCESS, 0x0000_0000),
        (NtStatus::ABANDONED, 0x0000_0080),
        (NtStatus::TIMEOUT, 0x0000_0102),
        (NtStatus::PENDING, 0x0000_0103),
        (NtStatus::BUFFER_OVERFLOW, 0x8000_0005),
        (NtStatus::NO_MORE_FILES, 0x8000_0006),
        (NtStatus::UNSUCCESSFUL, 0xc000_0001),
        (NtStatus::NOT_IMPLEMENTED, 0xc000_0002),
        (NtStatus::INVALID_INFO_CLASS, 0xc000_0003),
        (NtStatus::ACCESS_VIOLATION, 0xc000_0005),
        (NtStatus::INVALID_HANDLE, 0xc000_0008),
        (NtStatus::INVALID_PARAMETER, 0xc000_000d),
        (NtStatus::NO_SUCH_FILE, 0xc000_000f),
        (NtStatus::END_OF_FILE, 0xc000_0011),
        (NtStatus::NO_MEMORY, 0xc000_0017),
        (NtStatus::CONFLICTING_ADDRESSES, 0xc000_0018),
        (NtStatus::ACCESS_DENIED, 0xc000_0022),
        (NtStatus::BUFFER_TOO_SMALL, 0xc000_0023),
        (NtStatus::OBJECT_TYPE_MISMATCH, 0xc000_0024),
        (NtStatus::OBJECT_NAME_INVALID, 0xc000_0033),
        (NtStatus::OBJECT_NAME_NOT_FOUND, 0xc000_0034),
        (NtStatus::OBJECT_NAME_COLLISION, 0xc000_0035),
        (NtStatus::OBJECT_PATH_INVALID, 0xc000_0039),
        (NtStatus::OBJECT_PATH_NOT_FOUND, 0xc000_003a),
        (NtStatus::SHARING_VIOLATION, 0xc000_0043),
        (NtStatus::MUTANT_NOT_OWNED, 0xc000_0046),
        (NtStatus::SEMAPHORE_LIMIT_EXCEEDED, 0xc000_0047),
        (NtStatus::INVALID_IMAGE_FORMAT, 0xc000_007b),
        (NtStatus::INTEGER_OVERFLOW, 0xc000_0095),
        (NtStatus::INSUFFICIENT_RESOURCES, 0xc000_009a),
        (NtStatus::FILE_IS_A_DIRECTORY, 0xc000_00ba),
        (NtStatus::NOT_SUPPORTED, 0xc000_00bb),
        (NtStatus::DIRECTORY_NOT_EMPTY, 0xc000_0101),
        (NtStatus::NAME_TOO_LONG, 0xc000_0106),
        (NtStatus::DLL_NOT_FOUND, 0xc000_0135),
        (NtStatus::ENTRYPOINT_NOT_FOUND, 0xc000_0139),
        (NtStatus::MUTANT_LIMIT_EXCEEDED, 0xc000_0191),
    ];
    for (status, raw) in cases {
        assert_eq!(status.as_u32(), raw);
        assert_eq!(NtStatus::from_u32(raw), status);
    }
}

#[test]
fn bootstrap_dos_error_constants_match_exact_error_numbers() {
    let cases = [
        (DosError::SUCCESS, 0),
        (DosError::INVALID_FUNCTION, 1),
        (DosError::FILE_NOT_FOUND, 2),
        (DosError::PATH_NOT_FOUND, 3),
        (DosError::ACCESS_DENIED, 5),
        (DosError::INVALID_HANDLE, 6),
        (DosError::NOT_ENOUGH_MEMORY, 8),
        (DosError::NO_MORE_FILES, 18),
        (DosError::GEN_FAILURE, 31),
        (DosError::SHARING_VIOLATION, 32),
        (DosError::HANDLE_EOF, 38),
        (DosError::NOT_SUPPORTED, 50),
        (DosError::INVALID_PARAMETER, 87),
        (DosError::INSUFFICIENT_BUFFER, 122),
        (DosError::INVALID_NAME, 123),
        (DosError::MOD_NOT_FOUND, 126),
        (DosError::PROC_NOT_FOUND, 127),
        (DosError::DIR_NOT_EMPTY, 145),
        (DosError::BAD_PATHNAME, 161),
        (DosError::ALREADY_EXISTS, 183),
        (DosError::BAD_EXE_FORMAT, 193),
        (DosError::FILENAME_EXCED_RANGE, 206),
        (DosError::MORE_DATA, 234),
        (DosError::MR_MID_NOT_FOUND, 317),
        (DosError::INVALID_ADDRESS, 487),
        (DosError::IO_PENDING, 997),
        (DosError::NOACCESS, 998),
        (DosError::NO_SYSTEM_RESOURCES, 1450),
    ];
    for (error, raw) in cases {
        assert_eq!(error.as_u32(), raw);
        assert_eq!(DosError::from_u32(raw), error);
    }
}

#[test]
fn status_severity_uses_the_top_two_bits() {
    assert_eq!(NtStatus::SUCCESS.severity(), NtSeverity::Success);
    assert_eq!(
        NtStatus::from_u32(0x4000_0001).severity(),
        NtSeverity::Informational
    );
    assert_eq!(NtStatus::BUFFER_OVERFLOW.severity(), NtSeverity::Warning);
    assert_eq!(NtStatus::UNSUCCESSFUL.severity(), NtSeverity::Error);
}

#[test]
fn documented_status_subset_has_stable_dos_mappings() {
    let cases = [
        (NtStatus::SUCCESS, DosError::SUCCESS),
        (NtStatus::PENDING, DosError::IO_PENDING),
        (NtStatus::BUFFER_OVERFLOW, DosError::MORE_DATA),
        (NtStatus::BUFFER_TOO_SMALL, DosError::INSUFFICIENT_BUFFER),
        (NtStatus::NO_MORE_FILES, DosError::NO_MORE_FILES),
        (NtStatus::UNSUCCESSFUL, DosError::GEN_FAILURE),
        (NtStatus::NOT_IMPLEMENTED, DosError::INVALID_FUNCTION),
        (NtStatus::NOT_SUPPORTED, DosError::NOT_SUPPORTED),
        (NtStatus::ACCESS_VIOLATION, DosError::NOACCESS),
        (NtStatus::INVALID_HANDLE, DosError::INVALID_HANDLE),
        (NtStatus::NO_SUCH_FILE, DosError::FILE_NOT_FOUND),
        (NtStatus::OBJECT_NAME_NOT_FOUND, DosError::FILE_NOT_FOUND),
        (NtStatus::END_OF_FILE, DosError::HANDLE_EOF),
        (NtStatus::OBJECT_PATH_NOT_FOUND, DosError::PATH_NOT_FOUND),
        (NtStatus::OBJECT_PATH_INVALID, DosError::BAD_PATHNAME),
        (NtStatus::ACCESS_DENIED, DosError::ACCESS_DENIED),
        (NtStatus::OBJECT_NAME_COLLISION, DosError::ALREADY_EXISTS),
        (NtStatus::SHARING_VIOLATION, DosError::SHARING_VIOLATION),
        (NtStatus::NO_MEMORY, DosError::NOT_ENOUGH_MEMORY),
        (NtStatus::CONFLICTING_ADDRESSES, DosError::INVALID_ADDRESS),
        (
            NtStatus::INSUFFICIENT_RESOURCES,
            DosError::NO_SYSTEM_RESOURCES,
        ),
        (NtStatus::INVALID_IMAGE_FORMAT, DosError::BAD_EXE_FORMAT),
        (NtStatus::FILE_IS_A_DIRECTORY, DosError::ACCESS_DENIED),
        (NtStatus::DIRECTORY_NOT_EMPTY, DosError::DIR_NOT_EMPTY),
        (NtStatus::NAME_TOO_LONG, DosError::FILENAME_EXCED_RANGE),
        (NtStatus::DLL_NOT_FOUND, DosError::MOD_NOT_FOUND),
        (NtStatus::ENTRYPOINT_NOT_FOUND, DosError::PROC_NOT_FOUND),
    ];
    for (status, expected) in cases {
        assert_eq!(ntstatus_to_dos_error(status), expected);
    }
}

#[test]
fn unknown_status_is_not_guessed() {
    assert_eq!(
        ntstatus_to_dos_error(NtStatus::from_u32(0xdead_beef)),
        DosError::MR_MID_NOT_FOUND
    );
    assert_eq!(DosError::MR_MID_NOT_FOUND.as_u32(), 317);
}

#[test]
fn handle_capacity_is_explicitly_bounded() {
    assert!(matches!(
        HandleTable::<0>::try_new(),
        Err(HandleError::InvalidCapacity { capacity: 0, .. })
    ));
    assert!(matches!(
        HandleTable::<{ MAX_HANDLE_ENTRIES + 1 }>::try_new(),
        Err(HandleError::InvalidCapacity { .. })
    ));
    assert!(HandleTable::<MAX_HANDLE_ENTRIES>::try_new().is_ok());
}

#[test]
fn insertion_is_deterministic_and_null_is_never_issued() {
    let mut table = HandleTable::<3>::try_new().unwrap();
    let first = table
        .insert(entry(10, ObjectType::File, AccessMask::GENERIC_READ.bits()))
        .unwrap();
    let second = table
        .insert(entry(11, ObjectType::Event, AccessMask::SYNCHRONIZE.bits()))
        .unwrap();
    assert_eq!(first.raw(), 0x1001);
    assert_eq!(second.raw(), 0x1002);
    assert!(!first.is_null());
    assert!(GuestHandle::NULL.is_null());
    assert_eq!(table.len(), 2);
    assert_eq!(table.capacity(), 3);
}

#[test]
fn close_rejects_stale_handles_after_slot_reuse() {
    let mut table = HandleTable::<1>::try_new().unwrap();
    let old = table
        .insert(entry(10, ObjectType::File, AccessMask::GENERIC_READ.bits()))
        .unwrap();
    assert_eq!(table.close(old).unwrap().object_id, 10);
    assert!(table.is_empty());

    let current = table
        .insert(entry(11, ObjectType::File, AccessMask::GENERIC_READ.bits()))
        .unwrap();
    assert_ne!(current, old);
    assert_eq!(
        table.reference(old, None, AccessMask::NONE),
        Err(HandleError::InvalidHandle)
    );
    assert_eq!(table.close(old), Err(HandleError::InvalidHandle));
    assert_eq!(
        table
            .reference(current, None, AccessMask::NONE)
            .unwrap()
            .object_id,
        11
    );
}

#[test]
fn reference_checks_type_and_access_without_changing_the_table() {
    let granted =
        AccessMask::from_bits(AccessMask::GENERIC_READ.bits() | AccessMask::READ_CONTROL.bits());
    let mut table = HandleTable::<2>::try_new().unwrap();
    let handle = table
        .insert(HandleEntry {
            object_id: 44,
            object_type: ObjectType::File,
            access: granted,
            inheritable: true,
        })
        .unwrap();

    assert_eq!(
        table.reference(handle, Some(ObjectType::Event), AccessMask::NONE),
        Err(HandleError::TypeMismatch {
            expected: ObjectType::Event,
            actual: ObjectType::File,
        })
    );
    assert_eq!(
        table.reference(handle, Some(ObjectType::File), AccessMask::GENERIC_WRITE),
        Err(HandleError::AccessDenied {
            requested: AccessMask::GENERIC_WRITE,
            granted,
        })
    );
    assert_eq!(table.len(), 1);
}

#[test]
fn duplicate_can_narrow_but_never_escalate_access() {
    let granted =
        AccessMask::from_bits(AccessMask::GENERIC_READ.bits() | AccessMask::GENERIC_WRITE.bits());
    let mut table = HandleTable::<3>::try_new().unwrap();
    let source = table
        .insert(HandleEntry {
            object_id: 77,
            object_type: ObjectType::Section,
            access: granted,
            inheritable: false,
        })
        .unwrap();
    let duplicate = table
        .duplicate(source, Some(AccessMask::GENERIC_READ), Some(true))
        .unwrap();
    let copied = table
        .reference(
            duplicate,
            Some(ObjectType::Section),
            AccessMask::GENERIC_READ,
        )
        .unwrap();
    assert_eq!(copied.object_id, 77);
    assert_eq!(copied.access, AccessMask::GENERIC_READ);
    assert!(copied.inheritable);
    assert_eq!(
        table.duplicate(source, Some(AccessMask::GENERIC_ALL), None),
        Err(HandleError::AccessDenied {
            requested: AccessMask::GENERIC_ALL,
            granted,
        })
    );
}

#[test]
fn full_table_and_malformed_values_are_rejected() {
    let mut table = HandleTable::<1>::try_new().unwrap();
    table
        .insert(entry(1, ObjectType::Thread, AccessMask::SYNCHRONIZE.bits()))
        .unwrap();
    assert_eq!(
        table.insert(entry(2, ObjectType::Thread, 0)),
        Err(HandleError::TableFull)
    );
    assert_eq!(
        table.reference(GuestHandle::NULL, None, AccessMask::NONE),
        Err(HandleError::InvalidHandle)
    );
    assert_eq!(
        table.reference(GuestHandle::from_raw(1), None, AccessMask::NONE),
        Err(HandleError::InvalidHandle)
    );
    assert_eq!(
        table.reference(GuestHandle::from_raw(u32::MAX), None, AccessMask::NONE),
        Err(HandleError::InvalidHandle)
    );
    assert_eq!(
        table.insert(entry(2, ObjectType::Invalid, 0)),
        Err(HandleError::InvalidObjectType)
    );
    assert_eq!(
        table.insert(entry(0, ObjectType::Thread, 0)),
        Err(HandleError::InvalidObjectId)
    );
}

#[test]
fn handle_errors_have_stable_bootstrap_statuses() {
    assert_eq!(
        HandleError::InvalidHandle.status(),
        NtStatus::INVALID_HANDLE
    );
    assert_eq!(
        HandleError::TableFull.status(),
        NtStatus::INSUFFICIENT_RESOURCES
    );
    assert_eq!(
        HandleError::AccessDenied {
            requested: AccessMask::GENERIC_ALL,
            granted: AccessMask::NONE,
        }
        .status(),
        NtStatus::ACCESS_DENIED
    );
    assert_eq!(
        HandleError::TypeMismatch {
            expected: ObjectType::Event,
            actual: ObjectType::File,
        }
        .status(),
        NtStatus::OBJECT_TYPE_MISMATCH
    );
    assert_eq!(
        HandleError::InvalidObjectId.status(),
        NtStatus::INVALID_PARAMETER
    );
}
