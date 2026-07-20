//! Exact-width WDM request and control-code vocabulary.

/// Highest defined WDM major-function value.
pub const IRP_MJ_MAXIMUM_FUNCTION: u8 = 0x1b;

/// Number of entries in `DRIVER_OBJECT::MajorFunction`.
pub const MAJOR_FUNCTION_COUNT: usize = IRP_MJ_MAXIMUM_FUNCTION as usize + 1;

/// WDM IRP major-function code.
///
/// The explicit values match the public `IRP_MJ_*` contract. Unsupported
/// functions remain absent from a driver's dispatch table; they are never
/// silently reported as successful.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MajorFunction {
    /// Open/create a file object for a device.
    Create = 0x00,
    /// Create a named pipe.
    CreateNamedPipe = 0x01,
    /// Close a file object.
    Close = 0x02,
    /// Read data.
    Read = 0x03,
    /// Write data.
    Write = 0x04,
    /// Query file information.
    QueryInformation = 0x05,
    /// Set file information.
    SetInformation = 0x06,
    /// Query extended attributes.
    QueryEa = 0x07,
    /// Set extended attributes.
    SetEa = 0x08,
    /// Flush buffered data.
    FlushBuffers = 0x09,
    /// Query volume information.
    QueryVolumeInformation = 0x0a,
    /// Set volume information.
    SetVolumeInformation = 0x0b,
    /// Directory control.
    DirectoryControl = 0x0c,
    /// File-system control.
    FileSystemControl = 0x0d,
    /// User-visible device control.
    DeviceControl = 0x0e,
    /// Kernel-internal device control.
    InternalDeviceControl = 0x0f,
    /// Shutdown notification.
    Shutdown = 0x10,
    /// Acquire a byte-range lock.
    LockControl = 0x11,
    /// Clean up one file-object context.
    Cleanup = 0x12,
    /// Create a mailslot.
    CreateMailslot = 0x13,
    /// Query security metadata.
    QuerySecurity = 0x14,
    /// Set security metadata.
    SetSecurity = 0x15,
    /// Power-management request.
    Power = 0x16,
    /// System-control/WMI request.
    SystemControl = 0x17,
    /// Device-change notification.
    DeviceChange = 0x18,
    /// Query or set quota information.
    QueryQuota = 0x19,
    /// Set quota information.
    SetQuota = 0x1a,
    /// Plug-and-play request.
    Pnp = 0x1b,
}

impl MajorFunction {
    /// Parses one public WDM major-function byte.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            0x00 => Self::Create,
            0x01 => Self::CreateNamedPipe,
            0x02 => Self::Close,
            0x03 => Self::Read,
            0x04 => Self::Write,
            0x05 => Self::QueryInformation,
            0x06 => Self::SetInformation,
            0x07 => Self::QueryEa,
            0x08 => Self::SetEa,
            0x09 => Self::FlushBuffers,
            0x0a => Self::QueryVolumeInformation,
            0x0b => Self::SetVolumeInformation,
            0x0c => Self::DirectoryControl,
            0x0d => Self::FileSystemControl,
            0x0e => Self::DeviceControl,
            0x0f => Self::InternalDeviceControl,
            0x10 => Self::Shutdown,
            0x11 => Self::LockControl,
            0x12 => Self::Cleanup,
            0x13 => Self::CreateMailslot,
            0x14 => Self::QuerySecurity,
            0x15 => Self::SetSecurity,
            0x16 => Self::Power,
            0x17 => Self::SystemControl,
            0x18 => Self::DeviceChange,
            0x19 => Self::QueryQuota,
            0x1a => Self::SetQuota,
            0x1b => Self::Pnp,
            _ => return None,
        })
    }

    /// Returns the exact dispatch-table index.
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// Transfer method encoded in the low two IOCTL bits.
///
/// These values decode the public bit contract only. This crate does not build
/// Windows system buffers, MDLs, or validate `METHOD_NEITHER` pointers.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IoMethod {
    /// Windows buffered-I/O encoding.
    Buffered = 0,
    /// Windows input-direct encoding.
    InDirect = 1,
    /// Windows output-direct encoding.
    OutDirect = 2,
    /// Windows neither-buffered-nor-direct encoding.
    Neither = 3,
}

impl IoMethod {
    const fn from_bits(bits: u32) -> Self {
        match bits & 3 {
            0 => Self::Buffered,
            1 => Self::InDirect,
            2 => Self::OutDirect,
            _ => Self::Neither,
        }
    }
}

/// Access requirement encoded in an IOCTL.
///
/// Decoding does not enforce file-handle access; a future host boundary must
/// compare this value with independently validated open-handle rights.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IoAccess {
    /// A handle with any access may submit the request.
    Any = 0,
    /// Read access is required.
    Read = 1,
    /// Write access is required.
    Write = 2,
    /// Read and write access are required.
    ReadWrite = 3,
}

impl IoAccess {
    const fn from_bits(bits: u32) -> Self {
        match bits & 3 {
            0 => Self::Any,
            1 => Self::Read,
            2 => Self::Write,
            _ => Self::ReadWrite,
        }
    }
}

/// Exact 32-bit Windows device-control code.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IoControlCode(u32);

impl IoControlCode {
    /// Constructs the public `CTL_CODE` bit layout.
    ///
    /// The function field is twelve bits. Values outside that range are
    /// rejected instead of being silently truncated.
    pub const fn new(
        device_type: u16,
        function: u16,
        method: IoMethod,
        access: IoAccess,
    ) -> Option<Self> {
        if function > 0x0fff {
            return None;
        }
        Some(Self(
            ((device_type as u32) << 16)
                | ((access as u32) << 14)
                | ((function as u32) << 2)
                | method as u32,
        ))
    }

    /// Wraps a caller-provided control code for decoding.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the exact encoded value.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns the 16-bit device type.
    #[must_use]
    pub const fn device_type(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// Returns the two-bit access requirement.
    #[must_use]
    pub const fn access(self) -> IoAccess {
        IoAccess::from_bits(self.0 >> 14)
    }

    /// Returns the twelve-bit function identifier.
    #[must_use]
    pub const fn function(self) -> u16 {
        ((self.0 >> 2) & 0x0fff) as u16
    }

    /// Returns the transfer method.
    #[must_use]
    pub const fn method(self) -> IoMethod {
        IoMethod::from_bits(self.0)
    }
}
