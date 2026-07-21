//! Executable-path routing shared by the Win64 host and its tests.

use xenith_winhost_core::{dos_path_to_native, NativeWindowsPath, WindowsPathError};

/// Failure while selecting a native executable path for the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutablePathError {
    /// A Windows-looking argument was not valid UTF-8.
    InvalidUtf8,
    /// Windows drive-path policy rejected the argument.
    Windows(WindowsPathError),
}

impl From<WindowsPathError> for ExecutablePathError {
    fn from(error: WindowsPathError) -> Self {
        Self::Windows(error)
    }
}

/// Native path selected for one executable argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutablePath<'a, const N: usize> {
    /// Existing native Xenith path, borrowed without modification.
    Native(&'a [u8]),
    /// Validated Windows drive path translated below `/win`.
    Windows(NativeWindowsPath<N>),
}

impl<const N: usize> ExecutablePath<'_, N> {
    /// Returns the absolute or caller-supplied native bytes passed to `open`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Native(path) => path,
            Self::Windows(path) => path.as_bytes(),
        }
    }

    /// Returns whether drive-path translation was applied.
    #[must_use]
    pub const fn is_windows(&self) -> bool {
        matches!(self, Self::Windows(_))
    }
}

/// Resolve a host executable argument without changing native Xenith paths.
///
/// Drive-designator and leading-backslash forms are treated as Windows paths
/// and fail closed through the bounded DOS-path policy. Native absolute and
/// relative paths continue to pass through byte-for-byte.
pub fn resolve_executable_path<const N: usize>(
    input: &[u8],
) -> Result<ExecutablePath<'_, N>, ExecutablePathError> {
    if !looks_like_windows_path(input) {
        return Ok(ExecutablePath::Native(input));
    }
    let input = core::str::from_utf8(input).map_err(|_| ExecutablePathError::InvalidUtf8)?;
    Ok(ExecutablePath::Windows(dos_path_to_native(input)?))
}

fn looks_like_windows_path(input: &[u8]) -> bool {
    input.first() == Some(&b'\\')
        || (input.len() >= 2 && input[0] == b'/' && matches!(input[1], b'/' | b'\\'))
        || (input.len() >= 2 && input[0].is_ascii_alphabetic() && input[1] == b':')
}
