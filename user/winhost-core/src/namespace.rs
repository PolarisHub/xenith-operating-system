//! Bounded Windows drive, profile, known-folder, and environment policy.
//!
//! This module describes the namespace presented to a future Windows guest.
//! It does not install a PEB, create a process environment, implement NTFS, or
//! provide Win32 APIs.

use core::fmt;

pub use xenith_abi::{WINDOWS_INITRAMFS_ROOT, WINDOWS_NATIVE_ROOT, WINDOWS_SYSTEM_DRIVE};

/// Username used by the packaged bootstrap profile.
pub const DEFAULT_PROFILE_USERNAME: &str = "Xenith";

/// Guest-visible path of the packaged bootstrap profile.
pub const DEFAULT_PROFILE_PATH: &str = r"C:\Users\Xenith";

/// Maximum UTF-8 byte length accepted by the built-in profile policy.
pub const MAX_WINDOWS_POLICY_PATH_BYTES: usize = 1_024;

/// Number of variables emitted by [`build_windows_environment_block`].
pub const WINDOWS_ENVIRONMENT_VARIABLE_COUNT: usize = 23;

/// Standard directory entries packaged beneath [`WINDOWS_NATIVE_ROOT`].
///
/// Entries use native separators and are relative to `/win`. The drive name
/// is lowercase so an image has one canonical spelling; the mounted Windows
/// filesystem remains responsible for case-insensitive lookup.
pub const WINDOWS_NAMESPACE_DIRECTORIES: &[&str] = &[
    "c",
    "c/PerfLogs",
    "c/Program Files",
    "c/Program Files/Common Files",
    "c/Program Files (x86)",
    "c/Program Files (x86)/Common Files",
    "c/ProgramData",
    "c/ProgramData/Microsoft",
    "c/ProgramData/Microsoft/Windows",
    "c/ProgramData/Microsoft/Windows/Start Menu",
    "c/ProgramData/Microsoft/Windows/Start Menu/Programs",
    "c/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup",
    "c/ProgramData/Microsoft/Windows/Templates",
    "c/Users",
    "c/Users/Default",
    "c/Users/Default/AppData",
    "c/Users/Default/AppData/Local",
    "c/Users/Default/AppData/Local/Programs",
    "c/Users/Default/AppData/Local/Programs/Common",
    "c/Users/Default/AppData/Local/Temp",
    "c/Users/Default/AppData/LocalLow",
    "c/Users/Default/AppData/Roaming",
    "c/Users/Default/AppData/Roaming/Microsoft",
    "c/Users/Default/AppData/Roaming/Microsoft/Windows",
    "c/Users/Default/AppData/Roaming/Microsoft/Windows/Recent",
    "c/Users/Default/AppData/Roaming/Microsoft/Windows/SendTo",
    "c/Users/Default/AppData/Roaming/Microsoft/Windows/Start Menu",
    "c/Users/Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs",
    "c/Users/Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
    "c/Users/Default/AppData/Roaming/Microsoft/Windows/Templates",
    "c/Users/Default/Desktop",
    "c/Users/Default/Documents",
    "c/Users/Default/Downloads",
    "c/Users/Default/Favorites",
    "c/Users/Default/Links",
    "c/Users/Default/Music",
    "c/Users/Default/Pictures",
    "c/Users/Default/Saved Games",
    "c/Users/Default/Searches",
    "c/Users/Default/Videos",
    "c/Users/Public",
    "c/Users/Public/Desktop",
    "c/Users/Public/Documents",
    "c/Users/Public/Downloads",
    "c/Users/Public/Music",
    "c/Users/Public/Pictures",
    "c/Users/Public/Videos",
    "c/Users/Xenith",
    "c/Users/Xenith/AppData",
    "c/Users/Xenith/AppData/Local",
    "c/Users/Xenith/AppData/Local/Programs",
    "c/Users/Xenith/AppData/Local/Programs/Common",
    "c/Users/Xenith/AppData/Local/Temp",
    "c/Users/Xenith/AppData/LocalLow",
    "c/Users/Xenith/AppData/Roaming",
    "c/Users/Xenith/AppData/Roaming/Microsoft",
    "c/Users/Xenith/AppData/Roaming/Microsoft/Windows",
    "c/Users/Xenith/AppData/Roaming/Microsoft/Windows/Recent",
    "c/Users/Xenith/AppData/Roaming/Microsoft/Windows/SendTo",
    "c/Users/Xenith/AppData/Roaming/Microsoft/Windows/Start Menu",
    "c/Users/Xenith/AppData/Roaming/Microsoft/Windows/Start Menu/Programs",
    "c/Users/Xenith/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
    "c/Users/Xenith/AppData/Roaming/Microsoft/Windows/Templates",
    "c/Users/Xenith/Desktop",
    "c/Users/Xenith/Documents",
    "c/Users/Xenith/Downloads",
    "c/Users/Xenith/Favorites",
    "c/Users/Xenith/Links",
    "c/Users/Xenith/Music",
    "c/Users/Xenith/Pictures",
    "c/Users/Xenith/Saved Games",
    "c/Users/Xenith/Searches",
    "c/Users/Xenith/Videos",
    "c/Windows",
    "c/Windows/Fonts",
    "c/Windows/INF",
    "c/Windows/Logs",
    "c/Windows/Resources",
    "c/Windows/System32",
    "c/Windows/System32/DriverStore",
    "c/Windows/System32/DriverStore/FileRepository",
    "c/Windows/System32/Wbem",
    "c/Windows/System32/config",
    "c/Windows/System32/drivers",
    "c/Windows/System32/drivers/etc",
    "c/Windows/System32/spool",
    "c/Windows/SystemTemp",
    "c/Windows/Temp",
    "c/Windows/WinSxS",
];

/// Failure while parsing or normalizing a guest-visible DOS path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPathError {
    /// The input was empty.
    Empty,
    /// The input did not begin with a drive designator.
    NotDriveAbsolute,
    /// A drive-relative form such as `C:folder` was supplied.
    DriveRelative,
    /// The requested drive has no configured native mount.
    UnmappedDrive {
        /// Uppercase ASCII drive letter.
        drive: u8,
    },
    /// A UNC, device, verbatim, or other unsupported namespace was supplied.
    UnsupportedNamespace,
    /// A parent component would escape the drive root.
    ParentEscapesRoot,
    /// A NUL or control character was found.
    InvalidControl {
        /// UTF-8 byte index in the input.
        index: usize,
    },
    /// A Win32-invalid filename character or alternate-data-stream colon was found.
    InvalidCharacter {
        /// UTF-8 byte index in the input.
        index: usize,
        /// Rejected character.
        character: char,
    },
    /// A component ended in a space or dot.
    TrailingDotOrSpace {
        /// UTF-8 byte index at which the component began.
        component_start: usize,
    },
    /// A component used a reserved DOS device basename.
    ReservedDeviceName {
        /// UTF-8 byte index at which the component began.
        component_start: usize,
    },
    /// The normalized result did not fit in the requested capacity.
    BufferTooSmall {
        /// Output capacity in UTF-8 bytes.
        capacity: usize,
    },
}

/// A canonical, fixed-capacity guest-visible DOS path.
///
/// The drive letter is uppercase, separators are backslashes, redundant
/// separators and dot components are removed, and component spelling is
/// otherwise preserved.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NormalizedDosPath<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> NormalizedDosPath<N> {
    /// Returns the normalized UTF-8 path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        valid_utf8(&self.bytes[..self.len])
    }

    /// Returns the normalized UTF-8 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Returns the byte length without a trailing NUL.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the result is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<const N: usize> fmt::Debug for NormalizedDosPath<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("NormalizedDosPath")
            .field(&self.as_str())
            .finish()
    }
}

/// A canonical, fixed-capacity native VFS path for a Windows drive path.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NativeWindowsPath<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> NativeWindowsPath<N> {
    /// Returns the absolute native UTF-8 path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        valid_utf8(&self.bytes[..self.len])
    }

    /// Returns the absolute native UTF-8 path bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Returns the byte length without a trailing NUL.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the result is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<const N: usize> fmt::Debug for NativeWindowsPath<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("NativeWindowsPath")
            .field(&self.as_str())
            .finish()
    }
}

/// Normalizes a drive-absolute DOS path without allocating.
///
/// Direct `C:\...`, slash-separated `c:/...`, and native-DOS
/// `\??\C:\...` forms are accepted. UNC, Win32 verbatim (`\\?\`), device,
/// and drive-relative forms are rejected. This function intentionally does
/// not change the separate NT object-path normalizer.
pub fn normalize_dos_path<const N: usize>(
    input: &str,
) -> Result<NormalizedDosPath<N>, WindowsPathError> {
    let normalized = normalize_windows_path::<N>(input, PathOutput::Dos)?;
    Ok(NormalizedDosPath {
        bytes: normalized.bytes,
        len: normalized.len,
    })
}

/// Maps a supported drive-absolute DOS path into the native `/win/<drive>` tree.
pub fn dos_path_to_native<const N: usize>(
    input: &str,
) -> Result<NativeWindowsPath<N>, WindowsPathError> {
    let normalized = normalize_windows_path::<N>(input, PathOutput::Native)?;
    Ok(NativeWindowsPath {
        bytes: normalized.bytes,
        len: normalized.len,
    })
}

#[derive(Clone, Copy)]
enum PathOutput {
    Dos,
    Native,
}

struct FixedPath<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

fn normalize_windows_path<const N: usize>(
    input: &str,
    output_kind: PathOutput,
) -> Result<FixedPath<N>, WindowsPathError> {
    if input.is_empty() {
        return Err(WindowsPathError::Empty);
    }
    let bytes = input.as_bytes();
    let mut cursor = 0_usize;
    let has_native_dos_prefix = bytes.starts_with(b"\\??\\");
    if has_native_dos_prefix {
        cursor = 4;
    } else if is_separator(bytes[0]) {
        return Err(WindowsPathError::UnsupportedNamespace);
    }
    if bytes.len().saturating_sub(cursor) < 2
        || !bytes[cursor].is_ascii_alphabetic()
        || bytes[cursor + 1] != b':'
    {
        return Err(if has_native_dos_prefix {
            WindowsPathError::UnsupportedNamespace
        } else {
            WindowsPathError::NotDriveAbsolute
        });
    }
    let drive = bytes[cursor];
    cursor += 2;
    if cursor == bytes.len() || !is_separator(bytes[cursor]) {
        return Err(WindowsPathError::DriveRelative);
    }
    if !drive.eq_ignore_ascii_case(&b'C') {
        return Err(WindowsPathError::UnmappedDrive {
            drive: drive.to_ascii_uppercase(),
        });
    }
    while cursor < bytes.len() && is_separator(bytes[cursor]) {
        cursor += 1;
    }

    let mut result = FixedPath {
        bytes: [0; N],
        len: 0,
    };
    match output_kind {
        PathOutput::Dos => {
            push_byte(&mut result, drive.to_ascii_uppercase())?;
            push_byte(&mut result, b':')?;
            push_byte(&mut result, b'\\')?;
        },
        PathOutput::Native => {
            push_bytes(&mut result, WINDOWS_NATIVE_ROOT.as_bytes())?;
            push_byte(&mut result, b'/')?;
            push_byte(&mut result, drive.to_ascii_lowercase())?;
        },
    }
    let root_len = result.len;
    let mut component_rewinds = [0_usize; N];
    let mut component_count = 0_usize;

    while cursor < bytes.len() {
        let component_start = cursor;
        while cursor < bytes.len() && !is_separator(bytes[cursor]) {
            cursor += 1;
        }
        let component = &input[component_start..cursor];
        while cursor < bytes.len() && is_separator(bytes[cursor]) {
            cursor += 1;
        }

        if component == "." {
            continue;
        }
        if component == ".." {
            if component_count == 0 {
                return Err(WindowsPathError::ParentEscapesRoot);
            }
            component_count -= 1;
            result.len = component_rewinds[component_count];
            continue;
        }
        validate_windows_component(component, component_start)?;
        if component_count == component_rewinds.len() {
            return Err(WindowsPathError::BufferTooSmall { capacity: N });
        }
        component_rewinds[component_count] = result.len;
        if result.len != root_len || matches!(output_kind, PathOutput::Native) {
            push_byte(&mut result, match output_kind {
                PathOutput::Dos => b'\\',
                PathOutput::Native => b'/',
            })?;
        }
        push_bytes(&mut result, component.as_bytes())?;
        component_count += 1;
    }
    Ok(result)
}

fn push_byte<const N: usize>(output: &mut FixedPath<N>, byte: u8) -> Result<(), WindowsPathError> {
    if output.len == N {
        return Err(WindowsPathError::BufferTooSmall { capacity: N });
    }
    output.bytes[output.len] = byte;
    output.len += 1;
    Ok(())
}

fn push_bytes<const N: usize>(
    output: &mut FixedPath<N>,
    bytes: &[u8],
) -> Result<(), WindowsPathError> {
    for byte in bytes.iter().copied() {
        push_byte(output, byte)?;
    }
    Ok(())
}

const fn is_separator(byte: u8) -> bool {
    byte == b'\\' || byte == b'/'
}

fn validate_windows_component(
    component: &str,
    component_start: usize,
) -> Result<(), WindowsPathError> {
    if component.ends_with('.') || component.ends_with(' ') {
        return Err(WindowsPathError::TrailingDotOrSpace { component_start });
    }
    for (offset, character) in component.char_indices() {
        if character == '\0' || character.is_control() {
            return Err(WindowsPathError::InvalidControl {
                index: component_start + offset,
            });
        }
        if matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
            return Err(WindowsPathError::InvalidCharacter {
                index: component_start + offset,
                character,
            });
        }
    }
    if is_reserved_dos_basename(component) {
        return Err(WindowsPathError::ReservedDeviceName { component_start });
    }
    Ok(())
}

fn is_reserved_dos_basename(component: &str) -> bool {
    let basename = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches([' ', '.']);
    if basename.eq_ignore_ascii_case("CON")
        || basename.eq_ignore_ascii_case("PRN")
        || basename.eq_ignore_ascii_case("AUX")
        || basename.eq_ignore_ascii_case("NUL")
    {
        return true;
    }
    let bytes = basename.as_bytes();
    let serial_prefix = bytes.len() >= 3
        && (bytes[..3].eq_ignore_ascii_case(b"COM") || bytes[..3].eq_ignore_ascii_case(b"LPT"));
    (bytes.len() == 4 && serial_prefix && matches!(bytes[3], b'1'..=b'9'))
        || (bytes.len() == 5
            && serial_prefix
            && (&bytes[3..] == "¹".as_bytes()
                || &bytes[3..] == "²".as_bytes()
                || &bytes[3..] == "³".as_bytes()))
}

fn valid_utf8(bytes: &[u8]) -> &str {
    match core::str::from_utf8(bytes) {
        Ok(value) => value,
        Err(_) => unreachable!("namespace paths are copied only from UTF-8 input"),
    }
}

/// Guest-visible folders supported by the bootstrap profile policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownFolder {
    /// Windows installation directory.
    Windows,
    /// Native system directory.
    System,
    /// Native-architecture Program Files directory.
    ProgramFiles,
    /// 32-bit Program Files directory present in the x64 namespace.
    ProgramFilesX86,
    /// Native-architecture shared program files.
    CommonProgramFiles,
    /// 32-bit shared program files.
    CommonProgramFilesX86,
    /// Machine-wide application data.
    ProgramData,
    /// Root containing user profiles.
    UserProfiles,
    /// Default profile template.
    DefaultProfile,
    /// Public shared profile.
    Public,
    /// Current user profile root.
    Profile,
    /// Current user's desktop.
    Desktop,
    /// Current user's documents.
    Documents,
    /// Current user's downloads.
    Downloads,
    /// Current user's music.
    Music,
    /// Current user's pictures.
    Pictures,
    /// Current user's videos.
    Videos,
    /// Current user's favorites.
    Favorites,
    /// Current user's links.
    Links,
    /// Current user's saved games.
    SavedGames,
    /// Current user's searches.
    Searches,
    /// Current user's roaming application data.
    RoamingAppData,
    /// Current user's local application data.
    LocalAppData,
    /// Current user's low-integrity-oriented local data path.
    LocalAppDataLow,
    /// Current user's local program installation directory.
    UserProgramFiles,
    /// Shared subdirectory of the user program installation directory.
    UserProgramFilesCommon,
    /// Current user's Start menu.
    StartMenu,
    /// Current user's Start menu Programs directory.
    Programs,
    /// Current user's startup directory.
    Startup,
    /// Current user's templates.
    Templates,
    /// Current user's recent-items directory.
    Recent,
    /// Current user's SendTo directory.
    SendTo,
    /// Current user's temporary directory.
    Temp,
    /// Public desktop.
    PublicDesktop,
    /// Public documents.
    PublicDocuments,
    /// Public downloads.
    PublicDownloads,
    /// Public music.
    PublicMusic,
    /// Public pictures.
    PublicPictures,
    /// Public videos.
    PublicVideos,
    /// Machine-wide Start menu.
    CommonStartMenu,
    /// Machine-wide Start menu Programs directory.
    CommonPrograms,
    /// Machine-wide startup directory.
    CommonStartup,
    /// Machine-wide templates.
    CommonTemplates,
    /// Windows fonts directory.
    Fonts,
}

/// A caller-selected known-folder redirection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KnownFolderRedirect<'a> {
    folder: KnownFolder,
    path: &'a str,
}

impl<'a> KnownFolderRedirect<'a> {
    /// Creates a direct redirection for one known folder.
    #[must_use]
    pub const fn new(folder: KnownFolder, path: &'a str) -> Self {
        Self { folder, path }
    }

    /// Returns the redirected folder.
    #[must_use]
    pub const fn folder(self) -> KnownFolder {
        self.folder
    }

    /// Returns the requested guest-visible path.
    #[must_use]
    pub const fn path(self) -> &'a str {
        self.path
    }
}

/// Profile inputs used by known-folder and environment policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileContext<'a> {
    username: &'a str,
    profile_path: &'a str,
    redirects: &'a [KnownFolderRedirect<'a>],
}

impl<'a> ProfileContext<'a> {
    /// Creates a profile context with an explicit profile root and redirects.
    #[must_use]
    pub const fn new(
        username: &'a str,
        profile_path: &'a str,
        redirects: &'a [KnownFolderRedirect<'a>],
    ) -> Self {
        Self {
            username,
            profile_path,
            redirects,
        }
    }

    /// Returns the packaged bootstrap profile context.
    #[must_use]
    pub const fn xenith() -> ProfileContext<'static> {
        ProfileContext::new(DEFAULT_PROFILE_USERNAME, DEFAULT_PROFILE_PATH, &[])
    }

    /// Returns the username placed in the environment policy.
    #[must_use]
    pub const fn username(self) -> &'a str {
        self.username
    }

    /// Returns the unnormalized configured profile path.
    #[must_use]
    pub const fn profile_path(self) -> &'a str {
        self.profile_path
    }

    /// Returns the direct known-folder redirections in precedence order.
    #[must_use]
    pub const fn redirects(self) -> &'a [KnownFolderRedirect<'a>] {
        self.redirects
    }
}

impl Default for ProfileContext<'static> {
    fn default() -> Self {
        Self::xenith()
    }
}

/// Failure while resolving a known folder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownFolderError {
    /// A configured path was not a valid bounded drive-absolute path.
    Path(WindowsPathError),
}

impl From<WindowsPathError> for KnownFolderError {
    fn from(error: WindowsPathError) -> Self {
        Self::Path(error)
    }
}

/// Resolves a known folder to a normalized guest-visible path.
///
/// A direct redirection wins. Defaults derived from another known folder also
/// inherit that parent's redirection, such as `Temp` following redirected
/// `LocalAppData`. The first duplicate redirect wins deterministically.
pub fn resolve_known_folder<const N: usize>(
    folder: KnownFolder,
    context: &ProfileContext<'_>,
) -> Result<NormalizedDosPath<N>, KnownFolderError> {
    if let Some(path) = redirected_path(folder, context.redirects) {
        return normalize_dos_path(path).map_err(Into::into);
    }
    let direct = match folder {
        KnownFolder::Windows => Some(r"C:\Windows"),
        KnownFolder::ProgramFiles => Some(r"C:\Program Files"),
        KnownFolder::ProgramFilesX86 => Some(r"C:\Program Files (x86)"),
        KnownFolder::ProgramData => Some(r"C:\ProgramData"),
        KnownFolder::UserProfiles => Some(r"C:\Users"),
        KnownFolder::DefaultProfile => Some(r"C:\Users\Default"),
        KnownFolder::Public => Some(r"C:\Users\Public"),
        KnownFolder::Profile => Some(context.profile_path),
        _ => None,
    };
    if let Some(path) = direct {
        return normalize_dos_path(path).map_err(Into::into);
    }

    let (parent, suffix) = match folder {
        KnownFolder::System => (KnownFolder::Windows, "System32"),
        KnownFolder::CommonProgramFiles => (KnownFolder::ProgramFiles, "Common Files"),
        KnownFolder::CommonProgramFilesX86 => (KnownFolder::ProgramFilesX86, "Common Files"),
        KnownFolder::Desktop => (KnownFolder::Profile, "Desktop"),
        KnownFolder::Documents => (KnownFolder::Profile, "Documents"),
        KnownFolder::Downloads => (KnownFolder::Profile, "Downloads"),
        KnownFolder::Music => (KnownFolder::Profile, "Music"),
        KnownFolder::Pictures => (KnownFolder::Profile, "Pictures"),
        KnownFolder::Videos => (KnownFolder::Profile, "Videos"),
        KnownFolder::Favorites => (KnownFolder::Profile, "Favorites"),
        KnownFolder::Links => (KnownFolder::Profile, "Links"),
        KnownFolder::SavedGames => (KnownFolder::Profile, "Saved Games"),
        KnownFolder::Searches => (KnownFolder::Profile, "Searches"),
        KnownFolder::RoamingAppData => (KnownFolder::Profile, r"AppData\Roaming"),
        KnownFolder::LocalAppData => (KnownFolder::Profile, r"AppData\Local"),
        KnownFolder::LocalAppDataLow => (KnownFolder::Profile, r"AppData\LocalLow"),
        KnownFolder::UserProgramFiles => (KnownFolder::LocalAppData, "Programs"),
        KnownFolder::UserProgramFilesCommon => (KnownFolder::UserProgramFiles, "Common"),
        KnownFolder::StartMenu => (KnownFolder::RoamingAppData, r"Microsoft\Windows\Start Menu"),
        KnownFolder::Programs => (KnownFolder::StartMenu, "Programs"),
        KnownFolder::Startup => (KnownFolder::Programs, "Startup"),
        KnownFolder::Templates => (KnownFolder::RoamingAppData, r"Microsoft\Windows\Templates"),
        KnownFolder::Recent => (KnownFolder::RoamingAppData, r"Microsoft\Windows\Recent"),
        KnownFolder::SendTo => (KnownFolder::RoamingAppData, r"Microsoft\Windows\SendTo"),
        KnownFolder::Temp => (KnownFolder::LocalAppData, "Temp"),
        KnownFolder::PublicDesktop => (KnownFolder::Public, "Desktop"),
        KnownFolder::PublicDocuments => (KnownFolder::Public, "Documents"),
        KnownFolder::PublicDownloads => (KnownFolder::Public, "Downloads"),
        KnownFolder::PublicMusic => (KnownFolder::Public, "Music"),
        KnownFolder::PublicPictures => (KnownFolder::Public, "Pictures"),
        KnownFolder::PublicVideos => (KnownFolder::Public, "Videos"),
        KnownFolder::CommonStartMenu => (KnownFolder::ProgramData, r"Microsoft\Windows\Start Menu"),
        KnownFolder::CommonPrograms => (KnownFolder::CommonStartMenu, "Programs"),
        KnownFolder::CommonStartup => (KnownFolder::CommonPrograms, "Startup"),
        KnownFolder::CommonTemplates => (KnownFolder::ProgramData, r"Microsoft\Windows\Templates"),
        KnownFolder::Fonts => (KnownFolder::Windows, "Fonts"),
        KnownFolder::Windows
        | KnownFolder::ProgramFiles
        | KnownFolder::ProgramFilesX86
        | KnownFolder::ProgramData
        | KnownFolder::UserProfiles
        | KnownFolder::DefaultProfile
        | KnownFolder::Public
        | KnownFolder::Profile => unreachable!("direct known folders returned above"),
    };
    let parent_path = resolve_known_folder::<N>(parent, context)?;
    append_known_folder(parent_path.as_str(), suffix).map_err(Into::into)
}

fn redirected_path<'a>(
    folder: KnownFolder,
    redirects: &'a [KnownFolderRedirect<'a>],
) -> Option<&'a str> {
    redirects
        .iter()
        .find(|redirect| redirect.folder == folder)
        .map(|redirect| redirect.path)
}

fn append_known_folder<const N: usize>(
    parent: &str,
    suffix: &str,
) -> Result<NormalizedDosPath<N>, WindowsPathError> {
    let mut joined = FixedPath {
        bytes: [0; N],
        len: 0,
    };
    push_bytes(&mut joined, parent.as_bytes())?;
    push_byte(&mut joined, b'\\')?;
    push_bytes(&mut joined, suffix.as_bytes())?;
    normalize_dos_path(valid_utf8(&joined.bytes[..joined.len]))
}

/// Failure while building a guest environment block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsEnvironmentError {
    /// Profile or known-folder path policy failed.
    KnownFolder(KnownFolderError),
    /// The username contained a NUL, control character, or equals sign.
    InvalidUsername {
        /// UTF-8 byte index in the username.
        index: usize,
    },
    /// The UTF-16 block did not fit in the requested capacity.
    BufferTooSmall {
        /// Output capacity in UTF-16 code units.
        capacity: usize,
    },
}

impl From<KnownFolderError> for WindowsEnvironmentError {
    fn from(error: KnownFolderError) -> Self {
        Self::KnownFolder(error)
    }
}

/// A fixed-capacity, sorted UTF-16 Windows environment block.
///
/// Each entry is `name=value\0`; a final extra NUL terminates the block. The
/// block is policy output only and is not installed into guest process memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsEnvironmentBlock<const N: usize> {
    units: [u16; N],
    len: usize,
}

impl<const N: usize> WindowsEnvironmentBlock<N> {
    /// Returns the used UTF-16 units including the final double-NUL terminator.
    #[must_use]
    pub fn as_units(&self) -> &[u16] {
        &self.units[..self.len]
    }

    /// Returns the used UTF-16 length including both final NUL units.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the block contains no variable entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len <= 2
    }

    /// Returns the fixed number of variables emitted by the policy.
    #[must_use]
    pub const fn variable_count(&self) -> usize {
        WINDOWS_ENVIRONMENT_VARIABLE_COUNT
    }
}

/// Builds the bootstrap environment policy as a sorted UTF-16 double-NUL block.
///
/// The default context advertises paths represented by
/// [`WINDOWS_NAMESPACE_DIRECTORIES`]. A caller supplying a custom profile or
/// redirection remains responsible for provisioning it. No `ComSpec` is
/// fabricated, and the x86 directory variables do not imply a WoW64 runtime.
pub fn build_windows_environment_block<const N: usize>(
    context: &ProfileContext<'_>,
) -> Result<WindowsEnvironmentBlock<N>, WindowsEnvironmentError> {
    validate_username(context.username)?;
    let profile = resolve_policy_path(KnownFolder::Profile, context)?;
    let roaming = resolve_policy_path(KnownFolder::RoamingAppData, context)?;
    let local = resolve_policy_path(KnownFolder::LocalAppData, context)?;
    let temp = resolve_policy_path(KnownFolder::Temp, context)?;
    let public = resolve_policy_path(KnownFolder::Public, context)?;
    let program_data = resolve_policy_path(KnownFolder::ProgramData, context)?;
    let program_files = resolve_policy_path(KnownFolder::ProgramFiles, context)?;
    let program_files_x86 = resolve_policy_path(KnownFolder::ProgramFilesX86, context)?;
    let common_program_files = resolve_policy_path(KnownFolder::CommonProgramFiles, context)?;
    let common_program_files_x86 =
        resolve_policy_path(KnownFolder::CommonProgramFilesX86, context)?;
    let windows = resolve_policy_path(KnownFolder::Windows, context)?;
    let system = resolve_policy_path(KnownFolder::System, context)?;
    let search_path = environment_search_path(system.as_str(), windows.as_str())?;

    let profile_string = profile.as_str();
    let home_drive = &profile_string[..2];
    let home_path = &profile_string[2..];
    let mut block = EnvironmentWriter {
        units: [0; N],
        len: 0,
    };
    // This explicit order is ASCII case-insensitive lexical order.
    block.entry("ALLUSERSPROFILE", program_data.as_str())?;
    block.entry("APPDATA", roaming.as_str())?;
    block.entry("CommonProgramFiles", common_program_files.as_str())?;
    block.entry("CommonProgramFiles(x86)", common_program_files_x86.as_str())?;
    block.entry("CommonProgramW6432", common_program_files.as_str())?;
    block.entry("HOMEDRIVE", home_drive)?;
    block.entry("HOMEPATH", home_path)?;
    block.entry("LOCALAPPDATA", local.as_str())?;
    block.entry("OS", "Windows_NT")?;
    block.entry("PATH", valid_utf8(&search_path.bytes[..search_path.len]))?;
    block.entry("PROCESSOR_ARCHITECTURE", "AMD64")?;
    block.entry("ProgramData", program_data.as_str())?;
    block.entry("ProgramFiles", program_files.as_str())?;
    block.entry("ProgramFiles(x86)", program_files_x86.as_str())?;
    block.entry("ProgramW6432", program_files.as_str())?;
    block.entry("PUBLIC", public.as_str())?;
    block.entry("SystemDrive", WINDOWS_SYSTEM_DRIVE)?;
    block.entry("SystemRoot", windows.as_str())?;
    block.entry("TEMP", temp.as_str())?;
    block.entry("TMP", temp.as_str())?;
    block.entry("USERNAME", context.username)?;
    block.entry("USERPROFILE", profile.as_str())?;
    block.entry("windir", windows.as_str())?;
    block.finish()?;
    Ok(WindowsEnvironmentBlock {
        units: block.units,
        len: block.len,
    })
}

fn environment_search_path(
    system: &str,
    windows: &str,
) -> Result<FixedPath<MAX_WINDOWS_POLICY_PATH_BYTES>, WindowsEnvironmentError> {
    let mut path = FixedPath {
        bytes: [0; MAX_WINDOWS_POLICY_PATH_BYTES],
        len: 0,
    };
    for (index, part) in [system, windows, system].iter().enumerate() {
        if index != 0 {
            push_byte(&mut path, b';').map_err(KnownFolderError::from)?;
        }
        push_bytes(&mut path, part.as_bytes()).map_err(KnownFolderError::from)?;
        if index == 2 {
            push_bytes(&mut path, br"\Wbem").map_err(KnownFolderError::from)?;
        }
    }
    Ok(path)
}

fn resolve_policy_path(
    folder: KnownFolder,
    context: &ProfileContext<'_>,
) -> Result<NormalizedDosPath<MAX_WINDOWS_POLICY_PATH_BYTES>, KnownFolderError> {
    resolve_known_folder(folder, context)
}

fn validate_username(username: &str) -> Result<(), WindowsEnvironmentError> {
    for (index, character) in username.char_indices() {
        if character == '\0' || character.is_control() || character == '=' {
            return Err(WindowsEnvironmentError::InvalidUsername { index });
        }
    }
    Ok(())
}

struct EnvironmentWriter<const N: usize> {
    units: [u16; N],
    len: usize,
}

impl<const N: usize> EnvironmentWriter<N> {
    fn entry(&mut self, name: &str, value: &str) -> Result<(), WindowsEnvironmentError> {
        self.text(name)?;
        self.unit(b'=' as u16)?;
        self.text(value)?;
        self.unit(0)
    }

    fn text(&mut self, text: &str) -> Result<(), WindowsEnvironmentError> {
        for unit in text.encode_utf16() {
            self.unit(unit)?;
        }
        Ok(())
    }

    fn unit(&mut self, unit: u16) -> Result<(), WindowsEnvironmentError> {
        if self.len == N {
            return Err(WindowsEnvironmentError::BufferTooSmall { capacity: N });
        }
        self.units[self.len] = unit;
        self.len += 1;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), WindowsEnvironmentError> {
        self.unit(0)
    }
}
