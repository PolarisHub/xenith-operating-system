use core::mem::{align_of, size_of};

use xenith_winhost_core::{
    plan_runtime_environment, LayoutError, NtBoolean, NtClientId64, NtLargeInteger, NtStatus,
    NtThreadId, NtTypeError, NtUnicodeString64, RuntimeLayoutRequest, MAX_ENVIRONMENT_BYTES,
    PEB64_PROCESS_PARAMETERS_OFFSET, PROCESS_PARAMETERS64_COMMAND_LINE_OFFSET,
    PROCESS_PARAMETERS64_ENVIRONMENT_OFFSET, PROCESS_PARAMETERS64_IMAGE_PATH_OFFSET,
    RUNTIME_LAYOUT_PAGE_SIZE, RUNTIME_USER_ADDRESS_LIMIT, TEB64_PEB_OFFSET, TEB64_SELF_OFFSET,
};

fn request() -> RuntimeLayoutRequest {
    RuntimeLayoutRequest {
        arena_base: 0x10_0000,
        arena_size: 0x8_000,
        image_path_bytes: 10,
        command_line_bytes: 14,
        environment_bytes: 8,
        stack_bytes: 0x4_000,
    }
}

#[test]
fn exact_width_nt_types_validate_canonical_boundary_values() {
    assert_eq!(size_of::<NtBoolean>(), 1);
    assert_eq!(size_of::<NtLargeInteger>(), 8);
    assert_eq!(size_of::<NtThreadId>(), 8);
    assert_eq!(size_of::<NtUnicodeString64>(), 16);
    assert_eq!(align_of::<NtUnicodeString64>(), 8);
    assert_eq!(size_of::<NtClientId64>(), 16);

    assert_eq!(NtBoolean::try_from_raw(0), Ok(NtBoolean::FALSE));
    assert_eq!(NtBoolean::try_from_raw(1), Ok(NtBoolean::TRUE));
    assert_eq!(
        NtBoolean::try_from_raw(2),
        Err(NtTypeError::InvalidBoolean { raw: 2 })
    );
    assert_eq!(NtThreadId::try_from_raw(0), Err(NtTypeError::NullThreadId));
    assert_eq!(NtLargeInteger::from_i64(i64::MIN).as_i64(), i64::MIN);

    let empty = NtUnicodeString64::try_new(0, 0, 0).unwrap();
    assert!(empty.is_canonical());
    let value = NtUnicodeString64::try_new(0x1234, 4, 6).unwrap();
    assert!(value.is_canonical());
    assert_eq!(
        NtUnicodeString64::try_new(0x1234, 3, 4),
        Err(NtTypeError::OddUtf16ByteLength)
    );
    assert_eq!(
        NtUnicodeString64::try_new(0x1234, 6, 4),
        Err(NtTypeError::LengthExceedsMaximum)
    );
    assert_eq!(
        NtUnicodeString64::try_new(0, 0, 2),
        Err(NtTypeError::NullBuffer)
    );
    let noncanonical = NtUnicodeString64 {
        length_bytes: 0,
        maximum_length_bytes: 0,
        padding: 1,
        buffer: 0,
    };
    assert!(!noncanonical.is_canonical());
    assert_eq!(
        NtTypeError::NullBuffer.status(),
        NtStatus::INVALID_PARAMETER
    );
}

#[test]
fn runtime_environment_plan_has_exact_offsets_and_nonoverlapping_ranges() {
    let plan = plan_runtime_environment(request()).unwrap();
    assert_eq!(plan.peb.base(), 0x10_0000);
    assert_eq!(plan.peb.end(), 0x10_1000);
    assert_eq!(plan.teb.base(), 0x10_1000);
    assert_eq!(plan.teb.end(), 0x10_2000);
    assert_eq!(plan.process_parameters.base(), 0x10_2000);
    assert_eq!(plan.process_parameters.end(), 0x10_3000);
    assert_eq!(plan.stack_guard.base(), 0x10_3000);
    assert_eq!(plan.stack.base(), 0x10_4000);
    assert_eq!(plan.stack_top(), 0x10_8000);

    assert_eq!(plan.image_path.base(), 0x10_2088);
    assert_eq!(plan.image_path.size(), 12);
    assert_eq!(plan.command_line.base(), 0x10_2098);
    assert_eq!(plan.command_line.size(), 16);
    assert_eq!(plan.environment.base(), 0x10_20a8);
    assert_eq!(plan.environment.size(), 12);
    assert!(plan.process_parameters.contains(plan.image_path.base()));
    assert!(plan.process_parameters.contains(plan.command_line.base()));
    assert!(plan.process_parameters.contains(plan.environment.base()));

    assert_eq!(
        plan.peb_process_parameters_field(),
        plan.peb.base() + PEB64_PROCESS_PARAMETERS_OFFSET
    );
    assert_eq!(plan.teb_self_field(), plan.teb.base() + TEB64_SELF_OFFSET);
    assert_eq!(plan.teb_peb_field(), plan.teb.base() + TEB64_PEB_OFFSET);
    assert_eq!(
        plan.image_path_field(),
        plan.process_parameters.base() + PROCESS_PARAMETERS64_IMAGE_PATH_OFFSET
    );
    assert_eq!(
        plan.command_line_field(),
        plan.process_parameters.base() + PROCESS_PARAMETERS64_COMMAND_LINE_OFFSET
    );
    assert_eq!(
        plan.environment_field(),
        plan.process_parameters.base() + PROCESS_PARAMETERS64_ENVIRONMENT_OFFSET
    );
    assert_eq!(
        plan.image_path_string(),
        NtUnicodeString64::try_new(plan.image_path.base(), 10, 12).unwrap()
    );
    assert_eq!(
        plan.command_line_string(),
        NtUnicodeString64::try_new(plan.command_line.base(), 14, 16).unwrap()
    );

    let ordered = [
        plan.peb,
        plan.teb,
        plan.process_parameters,
        plan.stack_guard,
        plan.stack,
    ];
    for pair in ordered.windows(2) {
        assert!(pair[0].end() <= pair[1].base());
    }
}

#[test]
fn layout_rejects_alignment_bounds_overflow_and_insufficient_arenas() {
    let mut invalid = request();
    invalid.arena_base = 0;
    assert_eq!(
        plan_runtime_environment(invalid),
        Err(LayoutError::NullArenaBase)
    );

    invalid = request();
    invalid.arena_base += 1;
    assert_eq!(
        plan_runtime_environment(invalid),
        Err(LayoutError::InvalidAlignment)
    );

    invalid = request();
    invalid.stack_bytes = RUNTIME_LAYOUT_PAGE_SIZE - 1;
    assert_eq!(
        plan_runtime_environment(invalid),
        Err(LayoutError::InvalidAlignment)
    );

    invalid = request();
    invalid.image_path_bytes = 3;
    assert_eq!(
        plan_runtime_environment(invalid),
        Err(LayoutError::InvalidStringLength)
    );

    invalid = request();
    invalid.command_line_bytes = u16::MAX as usize - 1;
    assert_eq!(
        plan_runtime_environment(invalid),
        Err(LayoutError::InvalidStringLength)
    );

    invalid = request();
    invalid.environment_bytes = MAX_ENVIRONMENT_BYTES + 2;
    assert_eq!(
        plan_runtime_environment(invalid),
        Err(LayoutError::InvalidEnvironmentLength)
    );
    invalid.environment_bytes = 3;
    assert_eq!(
        plan_runtime_environment(invalid),
        Err(LayoutError::InvalidEnvironmentLength)
    );

    invalid = request();
    invalid.arena_size -= RUNTIME_LAYOUT_PAGE_SIZE;
    assert_eq!(
        plan_runtime_environment(invalid),
        Err(LayoutError::ArenaTooSmall)
    );

    invalid = request();
    invalid.arena_base = RUNTIME_USER_ADDRESS_LIMIT - RUNTIME_LAYOUT_PAGE_SIZE;
    assert_eq!(
        plan_runtime_environment(invalid),
        Err(LayoutError::OutsideUserAddressSpace)
    );
    assert_eq!(
        LayoutError::OutsideUserAddressSpace.status(),
        NtStatus::CONFLICTING_ADDRESSES
    );

    invalid = request();
    invalid.arena_base = u64::MAX - (RUNTIME_LAYOUT_PAGE_SIZE - 1);
    assert_eq!(
        plan_runtime_environment(invalid),
        Err(LayoutError::IntegerOverflow)
    );
    assert_eq!(LayoutError::ArenaTooSmall.status(), NtStatus::NO_MEMORY);
    assert_eq!(
        LayoutError::IntegerOverflow.status(),
        NtStatus::INTEGER_OVERFLOW
    );
}
