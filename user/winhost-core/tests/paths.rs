use xenith_winhost_core::{normalize_nt_path, NtPathKind, PathError};

fn utf16(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn normalized<const N: usize>(value: &str) -> Vec<u16> {
    normalize_nt_path::<N>(&utf16(value))
        .unwrap()
        .as_units()
        .to_vec()
}

#[test]
fn dos_device_paths_are_folded_and_canonicalized() {
    let path = normalize_nt_path::<64>(&utf16(r"\??\c:\Temp\\.\file.txt\")).unwrap();
    assert_eq!(path.kind(), NtPathKind::DosDevices);
    assert_eq!(path.as_units(), utf16(r"\??\C:\TEMP\FILE.TXT"));
    assert_eq!(path.len(), 20);
    assert!(!path.is_empty());
}

#[test]
fn device_prefix_is_case_insensitive() {
    let path = normalize_nt_path::<64>(&utf16(r"\dEvIcE\HarddiskVolume1\Windows")).unwrap();
    assert_eq!(path.kind(), NtPathKind::Device);
    assert_eq!(path.as_units(), utf16(r"\DEVICE\HARDDISKVOLUME1\WINDOWS"));
}

#[test]
fn relative_object_names_are_supported_without_adding_a_root() {
    let path = normalize_nt_path::<64>(&utf16(r"BaseNamedObjects\ready-event")).unwrap();
    assert_eq!(path.kind(), NtPathKind::Relative);
    assert_eq!(path.as_units(), utf16(r"BASENAMEDOBJECTS\READY-EVENT"));
}

#[test]
fn parent_components_rewind_only_inside_the_namespace() {
    assert_eq!(
        normalized::<64>(r"\Device\Disk0\Part1\..\Part2"),
        utf16(r"\DEVICE\DISK0\PART2")
    );
    assert_eq!(normalized::<16>(r"a\b\..\..\c"), utf16("C"));
    assert_eq!(
        normalize_nt_path::<32>(&utf16(r"\??\C:\..\..")),
        Err(PathError::ParentEscapesRoot)
    );
    assert_eq!(
        normalize_nt_path::<8>(&utf16(r"..\name")),
        Err(PathError::ParentEscapesRoot)
    );
}

#[test]
fn rewound_storage_does_not_change_canonical_equality() {
    let rewound = normalize_nt_path::<32>(&utf16(r"alpha\very-long-name\..\beta")).unwrap();
    let direct = normalize_nt_path::<32>(&utf16(r"ALPHA\BETA")).unwrap();
    assert_eq!(rewound, direct);
}

#[test]
fn namespace_roots_without_an_object_are_rejected() {
    assert_eq!(
        normalize_nt_path::<8>(&utf16(r"\??\")),
        Err(PathError::MissingObjectName)
    );
    assert_eq!(
        normalize_nt_path::<16>(&utf16(r"\Device\\.\")),
        Err(PathError::MissingObjectName)
    );
    assert_eq!(normalize_nt_path::<8>(&[]), Err(PathError::Empty));
}

#[test]
fn unsupported_absolute_namespaces_are_not_aliased() {
    assert_eq!(
        normalize_nt_path::<64>(&utf16(r"\BaseNamedObjects\Event")),
        Err(PathError::UnsupportedAbsoluteNamespace)
    );
    assert_eq!(
        normalize_nt_path::<64>(&utf16(r"\GLOBAL??\C:")),
        Err(PathError::UnsupportedAbsoluteNamespace)
    );
}

#[test]
fn malformed_utf16_and_embedded_nul_are_rejected_with_indices() {
    assert_eq!(
        normalize_nt_path::<8>(&[b'a' as u16, 0xd800]),
        Err(PathError::InvalidUtf16 { index: 1 })
    );
    assert_eq!(
        normalize_nt_path::<8>(&[0xdc00]),
        Err(PathError::InvalidUtf16 { index: 0 })
    );
    assert_eq!(
        normalize_nt_path::<8>(&[b'a' as u16, 0, b'b' as u16]),
        Err(PathError::EmbeddedNul { index: 1 })
    );
}

#[test]
fn valid_non_ascii_utf16_is_retained_ordinally() {
    let input = utf16("Résumé\\😀");
    let path = normalize_nt_path::<32>(&input).unwrap();
    assert_eq!(path.as_units(), utf16("RéSUMé\\😀"));
}

#[test]
fn controls_and_forward_slashes_are_rejected() {
    assert_eq!(
        normalize_nt_path::<16>(&utf16("alpha/beta")),
        Err(PathError::InvalidCharacter {
            index: 5,
            unit: b'/' as u16,
        })
    );
    assert_eq!(
        normalize_nt_path::<16>(&[b'a' as u16, 0x1f]),
        Err(PathError::InvalidCharacter {
            index: 1,
            unit: 0x1f,
        })
    );
}

#[test]
fn output_capacity_is_a_hard_bound() {
    assert_eq!(normalized::<3>("abc"), utf16("ABC"));
    assert_eq!(
        normalize_nt_path::<2>(&utf16("abc")),
        Err(PathError::BufferTooSmall { capacity: 2 })
    );
    assert_eq!(
        normalize_nt_path::<3>(&utf16(r"\??\x")),
        Err(PathError::BufferTooSmall { capacity: 3 })
    );
}
