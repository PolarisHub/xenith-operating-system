use xenith_winhost::path_runtime::{resolve_executable_path, ExecutablePath, ExecutablePathError};
use xenith_winhost_core::WindowsPathError;

#[test]
fn native_paths_pass_through_without_copy_or_rewrite() {
    for path in [b"/tests/win64-console.exe".as_slice(), b"tests/tool.exe"] {
        let resolved = resolve_executable_path::<128>(path).unwrap();
        assert_eq!(resolved.as_bytes(), path);
        assert!(!resolved.is_windows());
        assert!(matches!(resolved, ExecutablePath::Native(_)));
    }
}

#[test]
fn c_drive_paths_map_below_the_dedicated_mount() {
    let resolved =
        resolve_executable_path::<128>(br"C:\Users\Xenith\Downloads\win64-console.exe").unwrap();
    assert!(resolved.is_windows());
    assert_eq!(
        resolved.as_bytes(),
        b"/win/c/Users/Xenith/Downloads/win64-console.exe"
    );

    let slash_form = resolve_executable_path::<64>(b"c:/windows/SYSTEM32").unwrap();
    assert_eq!(slash_form.as_bytes(), b"/win/c/windows/SYSTEM32");
}

#[test]
fn unsupported_windows_namespaces_and_drives_fail_closed() {
    assert!(matches!(
        resolve_executable_path::<64>(br"C:relative.exe"),
        Err(ExecutablePathError::Windows(
            WindowsPathError::DriveRelative
        ))
    ));
    assert!(matches!(
        resolve_executable_path::<64>(br"\\server\share\tool.exe"),
        Err(ExecutablePathError::Windows(
            WindowsPathError::UnsupportedNamespace
        ))
    ));
    assert!(matches!(
        resolve_executable_path::<64>(b"//server/share/tool.exe"),
        Err(ExecutablePathError::Windows(
            WindowsPathError::UnsupportedNamespace
        ))
    ));
    assert!(matches!(
        resolve_executable_path::<64>(br"/\server\share\tool.exe"),
        Err(ExecutablePathError::Windows(
            WindowsPathError::UnsupportedNamespace
        ))
    ));
    assert_eq!(
        resolve_executable_path::<64>(br"D:\tool.exe"),
        Err(ExecutablePathError::Windows(
            WindowsPathError::UnmappedDrive { drive: b'D' }
        ))
    );
}

#[test]
fn windows_looking_invalid_utf8_is_not_passed_to_native_open() {
    assert_eq!(
        resolve_executable_path::<32>(&[b'C', b':', b'\\', 0xff]),
        Err(ExecutablePathError::InvalidUtf8)
    );
}

#[test]
fn translated_output_capacity_is_enforced() {
    assert_eq!(
        resolve_executable_path::<8>(br"C:\tool.exe"),
        Err(ExecutablePathError::Windows(
            WindowsPathError::BufferTooSmall { capacity: 8 }
        ))
    );
}
