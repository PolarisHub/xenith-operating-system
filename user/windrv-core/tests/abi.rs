use xenith_windrv_core::{
    IoAccess, IoControlCode, IoMethod, MajorFunction, IRP_MJ_MAXIMUM_FUNCTION, MAJOR_FUNCTION_COUNT,
};

#[test]
fn all_public_major_function_codes_round_trip() {
    assert_eq!(IRP_MJ_MAXIMUM_FUNCTION, 0x1b);
    assert_eq!(MAJOR_FUNCTION_COUNT, 28);
    for raw in 0..=IRP_MJ_MAXIMUM_FUNCTION {
        let major = MajorFunction::from_raw(raw).expect("defined WDM major code");
        assert_eq!(major as u8, raw);
        assert_eq!(major.index(), raw as usize);
    }
    assert_eq!(MajorFunction::from_raw(0x1c), None);
    assert_eq!(MajorFunction::from_raw(u8::MAX), None);
}

#[test]
fn ctl_code_layout_matches_wdm_bit_fields() {
    let code = IoControlCode::new(0x22, 0x801, IoMethod::OutDirect, IoAccess::ReadWrite).unwrap();
    assert_eq!(code.raw(), (0x22 << 16) | (3 << 14) | (0x801 << 2) | 2);
    assert_eq!(code.device_type(), 0x22);
    assert_eq!(code.function(), 0x801);
    assert_eq!(code.method(), IoMethod::OutDirect);
    assert_eq!(code.access(), IoAccess::ReadWrite);
}

#[test]
fn ctl_code_rejects_function_truncation() {
    assert_eq!(
        IoControlCode::new(1, 0x1000, IoMethod::Buffered, IoAccess::Any),
        None
    );
}

#[test]
fn arbitrary_control_codes_decode_without_panicking() {
    for raw in [0, 1, 2, 3, 0x222003, u32::MAX] {
        let code = IoControlCode::from_raw(raw);
        assert_eq!(code.raw(), raw);
        assert_eq!(code.function(), ((raw >> 2) & 0x0fff) as u16);
    }
}

#[test]
fn exhaustive_low_sixteen_bits_round_trip_without_truncation() {
    for device_type in [0_u16, 1, 0x22, 0x8000, u16::MAX] {
        for low in u16::MIN..=u16::MAX {
            let raw = (u32::from(device_type) << 16) | u32::from(low);
            let decoded = IoControlCode::from_raw(raw);
            let rebuilt = IoControlCode::new(
                decoded.device_type(),
                decoded.function(),
                decoded.method(),
                decoded.access(),
            )
            .unwrap();
            assert_eq!(rebuilt.raw(), raw);
        }
    }
}
