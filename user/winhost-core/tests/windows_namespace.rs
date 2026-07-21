use std::collections::{BTreeMap, BTreeSet};

use xenith_winhost_core::{
    build_windows_environment_block, dos_path_to_native, normalize_dos_path, resolve_known_folder,
    KnownFolder, KnownFolderRedirect, ProfileContext, WindowsEnvironmentError, WindowsPathError,
    DEFAULT_PROFILE_PATH, DEFAULT_PROFILE_USERNAME, WINDOWS_ENVIRONMENT_VARIABLE_COUNT,
    WINDOWS_INITRAMFS_ROOT, WINDOWS_NAMESPACE_DIRECTORIES, WINDOWS_NATIVE_ROOT,
    WINDOWS_SYSTEM_DRIVE,
};

#[test]
fn drive_absolute_paths_normalize_without_losing_component_case() {
    let dos = normalize_dos_path::<256>(r"c:/Users//Xenith/./Music/../Downloads/")
        .expect("valid DOS path");
    assert_eq!(dos.as_str(), r"C:\Users\Xenith\Downloads");
    assert_eq!(dos.len(), dos.as_bytes().len());
    assert!(!dos.is_empty());

    let native =
        dos_path_to_native::<256>(r"C:\Users\MiXeD\Résumé.txt").expect("valid native translation");
    assert_eq!(native.as_str(), "/win/c/Users/MiXeD/Résumé.txt");
    assert_eq!(native.len(), native.as_bytes().len());
    assert!(!native.is_empty());

    assert_eq!(
        normalize_dos_path::<32>(r"\??\c:\Windows")
            .expect("native DOS prefix")
            .as_str(),
        r"C:\Windows"
    );
    assert_eq!(
        normalize_dos_path::<3>(r"C:\")
            .expect("drive root")
            .as_str(),
        r"C:\"
    );
    assert_eq!(
        dos_path_to_native::<6>(r"Z:\"),
        Err(WindowsPathError::UnmappedDrive { drive: b'Z' })
    );
}

#[test]
fn relative_unc_device_and_verbatim_namespaces_fail_closed() {
    assert_eq!(normalize_dos_path::<64>(""), Err(WindowsPathError::Empty));
    assert_eq!(
        normalize_dos_path::<64>(r"Users\Xenith"),
        Err(WindowsPathError::NotDriveAbsolute)
    );
    assert_eq!(
        normalize_dos_path::<64>(r"C:Users\Xenith"),
        Err(WindowsPathError::DriveRelative)
    );
    assert_eq!(
        normalize_dos_path::<64>("C:"),
        Err(WindowsPathError::DriveRelative)
    );
    for path in [
        r"\\server\share\file",
        r"//server/share/file",
        r"\\?\C:\Windows",
        r"\\.\PhysicalDrive0",
        r"\Device\HarddiskVolume1",
        r"\??\UNC\server\share",
    ] {
        assert_eq!(
            normalize_dos_path::<128>(path),
            Err(WindowsPathError::UnsupportedNamespace),
            "{path}"
        );
    }
}

#[test]
fn invalid_win32_components_ads_and_reserved_devices_are_rejected() {
    for invalid in ['<', '>', ':', '"', '|', '?', '*'] {
        let path = format!(r"C:\Users\bad{invalid}name");
        assert!(matches!(
            normalize_dos_path::<128>(&path),
            Err(WindowsPathError::InvalidCharacter {
                character,
                ..
            }) if character == invalid
        ));
    }
    assert!(matches!(
        normalize_dos_path::<128>(r"C:\file.txt:stream"),
        Err(WindowsPathError::InvalidCharacter { character: ':', .. })
    ));
    assert!(matches!(
        normalize_dos_path::<128>("C:\\bad\u{0001}name"),
        Err(WindowsPathError::InvalidControl { .. })
    ));
    for path in [r"C:\trailing.", r"C:\trailing "] {
        assert!(matches!(
            normalize_dos_path::<128>(path),
            Err(WindowsPathError::TrailingDotOrSpace { .. })
        ));
    }
    for device in [
        "CON",
        "prn.txt",
        "AuX",
        "NUL.log",
        "CON .txt",
        "COM1",
        "com9.bin",
        "COM¹.log",
        "LPT1",
        "lPt9.cfg",
        "LPT³.txt",
    ] {
        let path = format!(r"C:\Users\{device}");
        assert!(matches!(
            normalize_dos_path::<128>(&path),
            Err(WindowsPathError::ReservedDeviceName { .. })
        ));
    }
    assert_eq!(
        normalize_dos_path::<32>(r"C:\COM0.txt")
            .expect("COM0 is not a reserved DOS basename")
            .as_str(),
        r"C:\COM0.txt"
    );
}

#[test]
fn parent_resolution_is_root_bounded_and_capacity_is_exact() {
    assert_eq!(
        normalize_dos_path::<64>(r"C:\..\Windows"),
        Err(WindowsPathError::ParentEscapesRoot)
    );
    assert_eq!(
        normalize_dos_path::<64>(r"C:\Users\..\..\Windows"),
        Err(WindowsPathError::ParentEscapesRoot)
    );
    assert_eq!(
        normalize_dos_path::<9>(r"C:\Windows"),
        Err(WindowsPathError::BufferTooSmall { capacity: 9 })
    );
    assert_eq!(
        normalize_dos_path::<10>(r"C:\Windows")
            .expect("exact capacity")
            .as_str(),
        r"C:\Windows"
    );
    assert_eq!(
        dos_path_to_native::<14>(r"C:\Windows")
            .expect("exact native capacity")
            .as_str(),
        "/win/c/Windows"
    );
}

#[test]
fn packaged_directory_manifest_is_canonical_unique_and_bounded() {
    assert_eq!(WINDOWS_NATIVE_ROOT, "/win");
    assert_eq!(WINDOWS_INITRAMFS_ROOT, "win");
    assert_eq!(
        WINDOWS_NATIVE_ROOT.strip_prefix('/'),
        Some(WINDOWS_INITRAMFS_ROOT)
    );
    assert_eq!(WINDOWS_SYSTEM_DRIVE, "C:");
    assert_eq!(DEFAULT_PROFILE_USERNAME, "Xenith");
    assert_eq!(DEFAULT_PROFILE_PATH, r"C:\Users\Xenith");
    let mut folded = BTreeSet::new();
    for directory in WINDOWS_NAMESPACE_DIRECTORIES {
        assert!(directory == &"c" || directory.starts_with("c/"));
        assert!(!directory.starts_with('/'));
        assert!(!directory.ends_with('/'));
        assert!(!directory.contains('\\'));
        assert!(folded.insert(directory.to_ascii_lowercase()), "{directory}");
    }
    for required in [
        "c/Windows/System32",
        "c/Program Files/Common Files",
        "c/ProgramData",
        "c/Users/Default",
        "c/Users/Public/Music",
        "c/Users/Xenith/AppData/Local/Temp",
        "c/Users/Xenith/Documents",
        "c/Users/Xenith/Downloads",
        "c/Users/Xenith/Music",
        "c/Users/Xenith/Pictures",
        "c/Users/Xenith/Videos",
    ] {
        assert!(
            WINDOWS_NAMESPACE_DIRECTORIES.contains(&required),
            "{required}"
        );
    }
    assert!(WINDOWS_NAMESPACE_DIRECTORIES
        .iter()
        .all(|path| !path.contains("SysWOW64")
            && !path.contains("Sysnative")
            && !path.contains("Documents and Settings")));
}

#[test]
fn known_folder_defaults_match_the_packaged_modern_layout() {
    let context = ProfileContext::xenith();
    let expected = [
        (KnownFolder::Windows, r"C:\Windows"),
        (KnownFolder::System, r"C:\Windows\System32"),
        (KnownFolder::ProgramFiles, r"C:\Program Files"),
        (KnownFolder::ProgramFilesX86, r"C:\Program Files (x86)"),
        (
            KnownFolder::CommonProgramFiles,
            r"C:\Program Files\Common Files",
        ),
        (
            KnownFolder::CommonProgramFilesX86,
            r"C:\Program Files (x86)\Common Files",
        ),
        (KnownFolder::ProgramData, r"C:\ProgramData"),
        (KnownFolder::UserProfiles, r"C:\Users"),
        (KnownFolder::DefaultProfile, r"C:\Users\Default"),
        (KnownFolder::Public, r"C:\Users\Public"),
        (KnownFolder::Profile, r"C:\Users\Xenith"),
        (KnownFolder::Desktop, r"C:\Users\Xenith\Desktop"),
        (KnownFolder::Documents, r"C:\Users\Xenith\Documents"),
        (KnownFolder::Downloads, r"C:\Users\Xenith\Downloads"),
        (KnownFolder::Music, r"C:\Users\Xenith\Music"),
        (KnownFolder::Pictures, r"C:\Users\Xenith\Pictures"),
        (KnownFolder::Videos, r"C:\Users\Xenith\Videos"),
        (
            KnownFolder::RoamingAppData,
            r"C:\Users\Xenith\AppData\Roaming",
        ),
        (KnownFolder::LocalAppData, r"C:\Users\Xenith\AppData\Local"),
        (
            KnownFolder::LocalAppDataLow,
            r"C:\Users\Xenith\AppData\LocalLow",
        ),
        (
            KnownFolder::UserProgramFiles,
            r"C:\Users\Xenith\AppData\Local\Programs",
        ),
        (
            KnownFolder::StartMenu,
            r"C:\Users\Xenith\AppData\Roaming\Microsoft\Windows\Start Menu",
        ),
        (
            KnownFolder::Programs,
            r"C:\Users\Xenith\AppData\Roaming\Microsoft\Windows\Start Menu\Programs",
        ),
        (
            KnownFolder::Startup,
            r"C:\Users\Xenith\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        ),
        (KnownFolder::Temp, r"C:\Users\Xenith\AppData\Local\Temp"),
        (KnownFolder::PublicDesktop, r"C:\Users\Public\Desktop"),
        (KnownFolder::PublicDocuments, r"C:\Users\Public\Documents"),
        (
            KnownFolder::CommonStartup,
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        ),
        (KnownFolder::Fonts, r"C:\Windows\Fonts"),
    ];
    for (folder, path) in expected {
        let resolved = resolve_known_folder::<512>(folder, &context).expect("known folder");
        assert_eq!(resolved.as_str(), path, "{folder:?}");
        assert!(!resolved.as_str().ends_with('\\'));
    }
}

#[test]
fn known_folder_redirects_are_normalized_and_inherited_by_children() {
    let redirects = [
        KnownFolderRedirect::new(KnownFolder::Profile, r"C:\Profiles\Valentino\"),
        KnownFolderRedirect::new(KnownFolder::LocalAppData, r"C:/Fast//Local"),
        KnownFolderRedirect::new(KnownFolder::Desktop, r"C:\Direct\Desk"),
    ];
    let context = ProfileContext::new("Valentino", r"C:\ignored", &redirects);
    assert_eq!(context.username(), "Valentino");
    assert_eq!(context.profile_path(), r"C:\ignored");
    assert_eq!(context.redirects(), &redirects);
    assert_eq!(redirects[0].folder(), KnownFolder::Profile);
    assert_eq!(redirects[0].path(), r"C:\Profiles\Valentino\");
    assert_eq!(
        resolve_known_folder::<256>(KnownFolder::Documents, &context)
            .expect("profile child")
            .as_str(),
        r"C:\Profiles\Valentino\Documents"
    );
    assert_eq!(
        resolve_known_folder::<256>(KnownFolder::Temp, &context)
            .expect("local child")
            .as_str(),
        r"C:\Fast\Local\Temp"
    );
    assert_eq!(
        resolve_known_folder::<256>(KnownFolder::Desktop, &context)
            .expect("direct child")
            .as_str(),
        r"C:\Direct\Desk"
    );
}

#[test]
fn environment_block_is_sorted_exact_and_double_nul_terminated() {
    let block = build_windows_environment_block::<4096>(&ProfileContext::xenith())
        .expect("default environment policy");
    assert_eq!(block.variable_count(), WINDOWS_ENVIRONMENT_VARIABLE_COUNT);
    assert!(!block.is_empty());
    assert_eq!(block.len(), block.as_units().len());
    assert_eq!(&block.as_units()[block.len() - 2..], &[0, 0]);

    let entries = decode_environment(block.as_units());
    assert_eq!(entries.len(), WINDOWS_ENVIRONMENT_VARIABLE_COUNT);
    let mut sorted = entries.clone();
    sorted.sort_by_key(|entry| {
        entry
            .split_once('=')
            .expect("name=value")
            .0
            .to_ascii_uppercase()
    });
    assert_eq!(entries, sorted);
    let variables: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| entry.split_once('=').expect("name=value"))
        .collect();
    assert_eq!(variables["SystemDrive"], "C:");
    assert_eq!(variables["SystemRoot"], r"C:\Windows");
    assert_eq!(variables["windir"], r"C:\Windows");
    assert_eq!(variables["ProgramFiles"], r"C:\Program Files");
    assert_eq!(variables["ProgramFiles(x86)"], r"C:\Program Files (x86)");
    assert_eq!(variables["ProgramW6432"], r"C:\Program Files");
    assert_eq!(
        variables["CommonProgramFiles"],
        r"C:\Program Files\Common Files"
    );
    assert_eq!(
        variables["CommonProgramFiles(x86)"],
        r"C:\Program Files (x86)\Common Files"
    );
    assert_eq!(variables["ProgramData"], r"C:\ProgramData");
    assert_eq!(variables["ALLUSERSPROFILE"], r"C:\ProgramData");
    assert_eq!(variables["PUBLIC"], r"C:\Users\Public");
    assert_eq!(variables["USERPROFILE"], r"C:\Users\Xenith");
    assert_eq!(variables["USERNAME"], "Xenith");
    assert_eq!(variables["HOMEDRIVE"], "C:");
    assert_eq!(variables["HOMEPATH"], r"\Users\Xenith");
    assert_eq!(variables["APPDATA"], r"C:\Users\Xenith\AppData\Roaming");
    assert_eq!(variables["LOCALAPPDATA"], r"C:\Users\Xenith\AppData\Local");
    assert_eq!(variables["TEMP"], r"C:\Users\Xenith\AppData\Local\Temp");
    assert_eq!(variables["TMP"], variables["TEMP"]);
    assert_eq!(variables["OS"], "Windows_NT");
    assert_eq!(variables["PROCESSOR_ARCHITECTURE"], "AMD64");
    assert_eq!(
        variables["PATH"],
        r"C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem"
    );
    assert!(!variables.contains_key("ComSpec"));
    assert!(!variables.contains_key("PROCESSOR_ARCHITEW6432"));
}

#[test]
fn environment_uses_profile_policy_and_reports_invalid_or_small_inputs() {
    let redirects = [KnownFolderRedirect::new(
        KnownFolder::LocalAppData,
        r"C:\Cache\Local",
    )];
    let context = ProfileContext::new("Ada", r"C:\Profiles\Ada", &redirects);
    let block = build_windows_environment_block::<4096>(&context).expect("custom environment");
    let entries = decode_environment(block.as_units());
    let variables: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| entry.split_once('=').expect("name=value"))
        .collect();
    assert_eq!(variables["SystemDrive"], "C:");
    assert_eq!(variables["HOMEDRIVE"], "C:");
    assert_eq!(variables["HOMEPATH"], r"\Profiles\Ada");
    assert_eq!(variables["LOCALAPPDATA"], r"C:\Cache\Local");
    assert_eq!(variables["TEMP"], r"C:\Cache\Local\Temp");
    assert_eq!(variables["USERNAME"], "Ada");

    let invalid = ProfileContext::new("bad=name", r"C:\Users\bad", &[]);
    assert_eq!(
        build_windows_environment_block::<4096>(&invalid),
        Err(WindowsEnvironmentError::InvalidUsername { index: 3 })
    );
    assert_eq!(
        build_windows_environment_block::<16>(&ProfileContext::xenith()),
        Err(WindowsEnvironmentError::BufferTooSmall { capacity: 16 })
    );
}

#[test]
fn environment_search_path_follows_windows_and_system_redirects() {
    let redirects = [KnownFolderRedirect::new(
        KnownFolder::Windows,
        r"C:\SystemRoot",
    )];
    let context = ProfileContext::new("Ada", r"C:\Users\Ada", &redirects);
    let block = build_windows_environment_block::<4096>(&context).expect("redirected environment");
    let entries = decode_environment(block.as_units());
    let variables: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| entry.split_once('=').expect("name=value"))
        .collect();
    assert_eq!(variables["SystemRoot"], r"C:\SystemRoot");
    assert_eq!(variables["windir"], r"C:\SystemRoot");
    assert_eq!(
        variables["PATH"],
        r"C:\SystemRoot\System32;C:\SystemRoot;C:\SystemRoot\System32\Wbem"
    );
    assert_eq!(
        resolve_known_folder::<128>(KnownFolder::System, &context)
            .expect("redirected system")
            .as_str(),
        r"C:\SystemRoot\System32"
    );
}

fn decode_environment(units: &[u16]) -> Vec<String> {
    assert!(units.ends_with(&[0, 0]));
    units[..units.len() - 1]
        .split(|unit| *unit == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf16(entry).expect("valid UTF-16"))
        .collect()
}
