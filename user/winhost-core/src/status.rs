//! Exact-width status values used by the bootstrap host boundary.

/// A 32-bit NT status value.
///
/// The constants here are a deliberately small bootstrap subset. This type is
/// not an exhaustive replacement for the Windows status catalog.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NtStatus(i32);

impl NtStatus {
    /// The operation completed successfully.
    pub const SUCCESS: Self = Self::from_u32(0x0000_0000);
    /// The operation is pending.
    pub const PENDING: Self = Self::from_u32(0x0000_0103);
    /// A wait operation reached its explicit zero-timeout boundary.
    pub const TIMEOUT: Self = Self::from_u32(0x0000_0102);
    /// A mutant was acquired after its previous owner terminated.
    pub const ABANDONED: Self = Self::from_u32(0x0000_0080);
    /// The caller's buffer was too small, with partial information available.
    pub const BUFFER_OVERFLOW: Self = Self::from_u32(0x8000_0005);
    /// Enumeration has no more entries.
    pub const NO_MORE_FILES: Self = Self::from_u32(0x8000_0006);
    /// An unspecified failure occurred.
    pub const UNSUCCESSFUL: Self = Self::from_u32(0xc000_0001);
    /// The operation is not implemented.
    pub const NOT_IMPLEMENTED: Self = Self::from_u32(0xc000_0002);
    /// The information class is invalid.
    pub const INVALID_INFO_CLASS: Self = Self::from_u32(0xc000_0003);
    /// Guest memory could not be accessed.
    pub const ACCESS_VIOLATION: Self = Self::from_u32(0xc000_0005);
    /// A handle failed validation.
    pub const INVALID_HANDLE: Self = Self::from_u32(0xc000_0008);
    /// An argument is invalid.
    pub const INVALID_PARAMETER: Self = Self::from_u32(0xc000_000d);
    /// The requested file does not exist.
    pub const NO_SUCH_FILE: Self = Self::from_u32(0xc000_000f);
    /// The end of a file was reached.
    pub const END_OF_FILE: Self = Self::from_u32(0xc000_0011);
    /// No suitable virtual memory is available.
    pub const NO_MEMORY: Self = Self::from_u32(0xc000_0017);
    /// A requested virtual address conflicts with an existing mapping.
    pub const CONFLICTING_ADDRESSES: Self = Self::from_u32(0xc000_0018);
    /// Access checks rejected the operation.
    pub const ACCESS_DENIED: Self = Self::from_u32(0xc000_0022);
    /// A handle named an object of the wrong runtime type.
    pub const OBJECT_TYPE_MISMATCH: Self = Self::from_u32(0xc000_0024);
    /// A supplied buffer is too small.
    pub const BUFFER_TOO_SMALL: Self = Self::from_u32(0xc000_0023);
    /// An object name is syntactically invalid.
    pub const OBJECT_NAME_INVALID: Self = Self::from_u32(0xc000_0033);
    /// An object name was not found.
    pub const OBJECT_NAME_NOT_FOUND: Self = Self::from_u32(0xc000_0034);
    /// An object with the requested name already exists.
    pub const OBJECT_NAME_COLLISION: Self = Self::from_u32(0xc000_0035);
    /// An object path is syntactically invalid.
    pub const OBJECT_PATH_INVALID: Self = Self::from_u32(0xc000_0039);
    /// A component of an object path was not found.
    pub const OBJECT_PATH_NOT_FOUND: Self = Self::from_u32(0xc000_003a);
    /// An incompatible sharing mode is already active.
    pub const SHARING_VIOLATION: Self = Self::from_u32(0xc000_0043);
    /// A mutant release was attempted by a thread that does not own it.
    pub const MUTANT_NOT_OWNED: Self = Self::from_u32(0xc000_0046);
    /// A semaphore release would exceed its configured limit.
    pub const SEMAPHORE_LIMIT_EXCEEDED: Self = Self::from_u32(0xc000_0047);
    /// A file is not a valid image for this loader.
    pub const INVALID_IMAGE_FORMAT: Self = Self::from_u32(0xc000_007b);
    /// Required resources could not be allocated.
    pub const INSUFFICIENT_RESOURCES: Self = Self::from_u32(0xc000_009a);
    /// A checked integer operation overflowed.
    pub const INTEGER_OVERFLOW: Self = Self::from_u32(0xc000_0095);
    /// The operation is outside the supported bootstrap contract.
    pub const NOT_SUPPORTED: Self = Self::from_u32(0xc000_00bb);
    /// The target is a directory, not a regular file.
    pub const FILE_IS_A_DIRECTORY: Self = Self::from_u32(0xc000_00ba);
    /// A directory is not empty.
    pub const DIRECTORY_NOT_EMPTY: Self = Self::from_u32(0xc000_0101);
    /// An object name exceeds the supported bound.
    pub const NAME_TOO_LONG: Self = Self::from_u32(0xc000_0106);
    /// A required module was not found.
    pub const DLL_NOT_FOUND: Self = Self::from_u32(0xc000_0135);
    /// A required exported symbol was not found.
    pub const ENTRYPOINT_NOT_FOUND: Self = Self::from_u32(0xc000_0139);
    /// Recursive mutant acquisition exceeded the supported count.
    pub const MUTANT_LIMIT_EXCEEDED: Self = Self::from_u32(0xc000_0191);

    /// Constructs a status from its exact unsigned bit pattern.
    #[must_use]
    pub const fn from_u32(raw: u32) -> Self {
        Self(raw as i32)
    }

    /// Returns the exact unsigned bit pattern.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0 as u32
    }

    /// Returns the signed representation used by the `NT_SUCCESS` rule.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self.0
    }

    /// Returns the two-bit severity encoded in bits 31 through 30.
    #[must_use]
    pub const fn severity(self) -> NtSeverity {
        match self.as_u32() >> 30 {
            0 => NtSeverity::Success,
            1 => NtSeverity::Informational,
            2 => NtSeverity::Warning,
            _ => NtSeverity::Error,
        }
    }

    /// Implements the signed `NT_SUCCESS(status)` predicate.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 >= 0
    }
}

/// Severity encoded in an NT status value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtSeverity {
    /// Successful completion.
    Success,
    /// Successful completion carrying information.
    Informational,
    /// Warning or partial completion.
    Warning,
    /// Failure.
    Error,
}

/// A 32-bit DOS/Win32 error number.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DosError(u32);

impl DosError {
    /// No error.
    pub const SUCCESS: Self = Self(0);
    /// The function is invalid.
    pub const INVALID_FUNCTION: Self = Self(1);
    /// A file was not found.
    pub const FILE_NOT_FOUND: Self = Self(2);
    /// A path was not found.
    pub const PATH_NOT_FOUND: Self = Self(3);
    /// Access was denied.
    pub const ACCESS_DENIED: Self = Self(5);
    /// A handle is invalid.
    pub const INVALID_HANDLE: Self = Self(6);
    /// Memory is exhausted.
    pub const NOT_ENOUGH_MEMORY: Self = Self(8);
    /// Enumeration has no more files.
    pub const NO_MORE_FILES: Self = Self(18);
    /// An unspecified device or service failure occurred.
    pub const GEN_FAILURE: Self = Self(31);
    /// A file sharing mode conflicts.
    pub const SHARING_VIOLATION: Self = Self(32);
    /// The end of a file was reached.
    pub const HANDLE_EOF: Self = Self(38);
    /// The operation is not supported.
    pub const NOT_SUPPORTED: Self = Self(50);
    /// A parameter is invalid.
    pub const INVALID_PARAMETER: Self = Self(87);
    /// A caller buffer is insufficient.
    pub const INSUFFICIENT_BUFFER: Self = Self(122);
    /// A module was not found.
    pub const MOD_NOT_FOUND: Self = Self(126);
    /// A procedure was not found.
    pub const PROC_NOT_FOUND: Self = Self(127);
    /// A name is invalid.
    pub const INVALID_NAME: Self = Self(123);
    /// A directory is not empty.
    pub const DIR_NOT_EMPTY: Self = Self(145);
    /// The object already exists.
    pub const ALREADY_EXISTS: Self = Self(183);
    /// A path has invalid syntax.
    pub const BAD_PATHNAME: Self = Self(161);
    /// An executable image has an invalid format.
    pub const BAD_EXE_FORMAT: Self = Self(193);
    /// A filename is beyond the supported range.
    pub const FILENAME_EXCED_RANGE: Self = Self(206);
    /// More data is available than fit in the supplied buffer.
    pub const MORE_DATA: Self = Self(234);
    /// No DOS mapping exists in this bootstrap subset.
    pub const MR_MID_NOT_FOUND: Self = Self(317);
    /// A virtual address conflicts with an existing range.
    pub const INVALID_ADDRESS: Self = Self(487);
    /// An asynchronous operation is pending.
    pub const IO_PENDING: Self = Self(997);
    /// Memory cannot be accessed at the supplied address.
    pub const NOACCESS: Self = Self(998);
    /// The system cannot provide the requested resource.
    pub const NO_SYSTEM_RESOURCES: Self = Self(1450);

    /// Constructs an error from its exact number.
    #[must_use]
    pub const fn from_u32(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the exact error number.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Maps the documented bootstrap NT-status subset to DOS errors.
///
/// Unknown status values deliberately map to `MR_MID_NOT_FOUND`; this function
/// never guesses from status facility or severity fields.
#[must_use]
pub const fn ntstatus_to_dos_error(status: NtStatus) -> DosError {
    match status.as_u32() {
        0x0000_0000 => DosError::SUCCESS,
        0x0000_0103 => DosError::IO_PENDING,
        0x8000_0005 => DosError::MORE_DATA,
        0x8000_0006 => DosError::NO_MORE_FILES,
        0xc000_0001 => DosError::GEN_FAILURE,
        0xc000_0002 => DosError::INVALID_FUNCTION,
        0xc000_0003 | 0xc000_000d => DosError::INVALID_PARAMETER,
        0xc000_0005 => DosError::NOACCESS,
        0xc000_0008 => DosError::INVALID_HANDLE,
        0xc000_000f | 0xc000_0034 => DosError::FILE_NOT_FOUND,
        0xc000_0011 => DosError::HANDLE_EOF,
        0xc000_0017 => DosError::NOT_ENOUGH_MEMORY,
        0xc000_0018 => DosError::INVALID_ADDRESS,
        0xc000_0022 => DosError::ACCESS_DENIED,
        0xc000_0023 => DosError::INSUFFICIENT_BUFFER,
        0xc000_0033 => DosError::INVALID_NAME,
        0xc000_0035 => DosError::ALREADY_EXISTS,
        0xc000_0039 => DosError::BAD_PATHNAME,
        0xc000_003a => DosError::PATH_NOT_FOUND,
        0xc000_0043 => DosError::SHARING_VIOLATION,
        0xc000_007b => DosError::BAD_EXE_FORMAT,
        0xc000_009a => DosError::NO_SYSTEM_RESOURCES,
        0xc000_00ba => DosError::ACCESS_DENIED,
        0xc000_00bb => DosError::NOT_SUPPORTED,
        0xc000_0101 => DosError::DIR_NOT_EMPTY,
        0xc000_0106 => DosError::FILENAME_EXCED_RANGE,
        0xc000_0135 => DosError::MOD_NOT_FOUND,
        0xc000_0139 => DosError::PROC_NOT_FOUND,
        _ => DosError::MR_MID_NOT_FOUND,
    }
}
