use xenith_winhost::runtime::{
    decode_guest_handle, validate_console_write, BootstrapRuntime, STD_ERROR_SELECTOR,
    STD_INPUT_SELECTOR, STD_OUTPUT_SELECTOR,
};
use xenith_winhost::MAX_CONSOLE_WRITE_BYTES;
use xenith_winhost_core::{
    GuestHandle, NtServiceCall, NtServiceReply, NtStatus, RUNTIME_USER_ADDRESS_LIMIT,
};

#[test]
fn bootstrap_console_handles_are_typed_distinct_and_generation_safe() {
    let mut runtime = BootstrapRuntime::<8, 8>::try_new().unwrap();
    let input = runtime.get_std_handle(STD_INPUT_SELECTOR).unwrap();
    let output = runtime.get_std_handle(STD_OUTPUT_SELECTOR).unwrap();
    let error = runtime.get_std_handle(STD_ERROR_SELECTOR).unwrap();
    assert_eq!(input.raw(), 0x1001);
    assert_eq!(output.raw(), 0x1002);
    assert_eq!(error.raw(), 0x1003);
    assert_eq!(runtime.handle_count(), 3);
    assert_eq!(runtime.object_count(), 3);

    assert_eq!(runtime.read_descriptor(input), Ok(0));
    assert_eq!(
        runtime.write_descriptor(input),
        Err(NtStatus::ACCESS_DENIED)
    );
    assert_eq!(runtime.write_descriptor(output), Ok(1));
    assert_eq!(
        runtime.read_descriptor(output),
        Err(NtStatus::ACCESS_DENIED)
    );
    assert_eq!(runtime.write_descriptor(error), Ok(2));
    assert_eq!(runtime.get_std_handle(0), Err(NtStatus::INVALID_PARAMETER));

    assert_eq!(runtime.close(output), NtStatus::SUCCESS);
    assert_eq!(runtime.handle_count(), 2);
    assert_eq!(runtime.object_count(), 2);
    assert_eq!(
        runtime.write_descriptor(output),
        Err(NtStatus::INVALID_HANDLE)
    );
    assert_eq!(runtime.close(output), NtStatus::INVALID_HANDLE);
    assert_eq!(runtime.get_std_handle(STD_OUTPUT_SELECTOR), Ok(output));
}

#[test]
fn host_symbol_adapter_returns_not_implemented_for_unknown_services() {
    let mut runtime = BootstrapRuntime::<8, 8>::try_new().unwrap();
    let input = runtime.get_std_handle(STD_INPUT_SELECTOR).unwrap();
    assert_eq!(
        runtime.dispatch_symbol(
            b"NTDLL.DLL",
            b"NtUnsupportedFutureCall",
            NtServiceCall::Close { handle: input },
        ),
        NtServiceReply::status(NtStatus::NOT_IMPLEMENTED)
    );
    assert_eq!(runtime.handle_count(), 3);
    assert_eq!(runtime.read_descriptor(input), Ok(0));
}

#[test]
fn guest_handle_decode_rejects_null_negative_and_wide_values() {
    assert_eq!(decode_guest_handle(0), Err(NtStatus::INVALID_HANDLE));
    assert_eq!(decode_guest_handle(-1), Err(NtStatus::INVALID_HANDLE));
    if usize::BITS > u32::BITS {
        assert_eq!(
            decode_guest_handle((u64::from(u32::MAX) + 1) as isize),
            Err(NtStatus::INVALID_HANDLE)
        );
    }
    assert_eq!(
        decode_guest_handle(0x1001),
        Ok(GuestHandle::from_raw(0x1001))
    );
}

#[test]
fn console_write_scalar_validation_is_bounded_and_deterministic() {
    let valid = validate_console_write(0x1001, 0x2000, 4, 0x3000, 0).unwrap();
    assert_eq!(valid.handle, GuestHandle::from_raw(0x1001));
    assert_eq!(valid.buffer, 0x2000);
    assert_eq!(valid.length, 4);
    assert_eq!(valid.written, 0x3000);

    assert_eq!(
        validate_console_write(0, 0x2000, 4, 0x3000, 0),
        Err(NtStatus::INVALID_HANDLE)
    );
    assert_eq!(
        validate_console_write(0x1001, 0, 4, 0x3000, 0),
        Err(NtStatus::ACCESS_VIOLATION)
    );
    assert_eq!(
        validate_console_write(0x1001, 0x2000, 4, 0, 0),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        validate_console_write(0x1001, 0x2000, 4, 0x3000, 1),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        validate_console_write(
            0x1001,
            0x2000,
            (MAX_CONSOLE_WRITE_BYTES + 1) as u32,
            0x3000,
            0,
        ),
        Err(NtStatus::INVALID_PARAMETER)
    );

    assert!(validate_console_write(
        0x1001,
        RUNTIME_USER_ADDRESS_LIMIT - 1,
        1,
        RUNTIME_USER_ADDRESS_LIMIT - 4,
        0,
    )
    .is_ok());
    assert_eq!(
        validate_console_write(0x1001, RUNTIME_USER_ADDRESS_LIMIT - 1, 2, 0x3000, 0,),
        Err(NtStatus::ACCESS_VIOLATION)
    );
    assert_eq!(
        validate_console_write(0x1001, 0x2000, 1, RUNTIME_USER_ADDRESS_LIMIT - 3, 0,),
        Err(NtStatus::ACCESS_VIOLATION)
    );
    assert_eq!(
        validate_console_write(0x1001, u64::MAX, 1, 0x3000, 0),
        Err(NtStatus::ACCESS_VIOLATION)
    );

    assert!(validate_console_write(0x1001, 0, 0, 0x3000, 0).is_ok());
    assert_eq!(
        validate_console_write(0x1001, RUNTIME_USER_ADDRESS_LIMIT, 0, 0x3000, 0),
        Err(NtStatus::ACCESS_VIOLATION)
    );
}

#[test]
fn runtime_capacity_smaller_than_three_console_objects_fails_closed() {
    assert!(matches!(
        BootstrapRuntime::<2, 3>::try_new(),
        Err(NtStatus::INSUFFICIENT_RESOURCES)
    ));
    assert!(matches!(
        BootstrapRuntime::<3, 2>::try_new(),
        Err(NtStatus::INSUFFICIENT_RESOURCES)
    ));
}
