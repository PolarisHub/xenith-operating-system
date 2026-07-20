//! Exact-width scalar and boundary records for the clean-room NT runtime.

use crate::NtStatus;

/// A strict one-byte NT boolean.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtBoolean(u8);

impl NtBoolean {
    /// False value accepted at the guest boundary.
    pub const FALSE: Self = Self(0);
    /// True value accepted at the guest boundary.
    pub const TRUE: Self = Self(1);

    /// Validates a raw boolean without treating arbitrary nonzero values as true.
    pub const fn try_from_raw(raw: u8) -> Result<Self, NtTypeError> {
        match raw {
            0 => Ok(Self::FALSE),
            1 => Ok(Self::TRUE),
            _ => Err(NtTypeError::InvalidBoolean { raw }),
        }
    }

    /// Returns the exact guest representation.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Returns the validated Rust boolean.
    #[must_use]
    pub const fn get(self) -> bool {
        self.0 == 1
    }
}

/// Signed 64-bit integer used for time and size values at NT boundaries.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NtLargeInteger(i64);

impl NtLargeInteger {
    /// Creates an exact signed value.
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        Self(value)
    }

    /// Returns the exact signed value.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0
    }
}

/// Nonzero runtime thread identity used by mutant ownership checks.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NtThreadId(u64);

impl NtThreadId {
    /// Validates a nonzero thread identity.
    pub const fn try_from_raw(raw: u64) -> Result<Self, NtTypeError> {
        if raw == 0 {
            Err(NtTypeError::NullThreadId)
        } else {
            Ok(Self(raw))
        }
    }

    /// Returns the exact internal identity.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Exact x64 `UNICODE_STRING` boundary record.
///
/// This record only describes an already validated guest buffer. It never
/// dereferences `buffer` and does not imply ownership of the pointed-to bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtUnicodeString64 {
    /// Number of meaningful UTF-16 bytes, excluding any terminator.
    pub length_bytes: u16,
    /// Total byte capacity of the pointed-to buffer.
    pub maximum_length_bytes: u16,
    /// Required x64 alignment padding; canonical records keep it zero.
    pub padding: u32,
    /// Guest virtual address of the UTF-16 buffer.
    pub buffer: u64,
}

impl NtUnicodeString64 {
    /// Builds a canonical descriptor after validating length and pointer rules.
    pub const fn try_new(
        buffer: u64,
        length_bytes: u16,
        maximum_length_bytes: u16,
    ) -> Result<Self, NtTypeError> {
        if length_bytes & 1 != 0 || maximum_length_bytes & 1 != 0 {
            return Err(NtTypeError::OddUtf16ByteLength);
        }
        if length_bytes > maximum_length_bytes {
            return Err(NtTypeError::LengthExceedsMaximum);
        }
        if maximum_length_bytes != 0 && buffer == 0 {
            return Err(NtTypeError::NullBuffer);
        }
        Ok(Self {
            length_bytes,
            maximum_length_bytes,
            padding: 0,
            buffer,
        })
    }

    /// Returns whether reserved padding and all length rules are canonical.
    #[must_use]
    pub const fn is_canonical(self) -> bool {
        self.padding == 0
            && self.length_bytes & 1 == 0
            && self.maximum_length_bytes & 1 == 0
            && self.length_bytes <= self.maximum_length_bytes
            && (self.maximum_length_bytes == 0 || self.buffer != 0)
    }
}

/// Exact-width process/thread identity pair used by x64 NT interfaces.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtClientId64 {
    /// Process identity or zero when deliberately absent.
    pub process: u64,
    /// Thread identity or zero when deliberately absent.
    pub thread: u64,
}

/// Validation failure for an exact-width NT boundary type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtTypeError {
    /// A BOOLEAN value was neither zero nor one.
    InvalidBoolean {
        /// Rejected byte.
        raw: u8,
    },
    /// A runtime thread identity was zero.
    NullThreadId,
    /// A UTF-16 byte count was odd.
    OddUtf16ByteLength,
    /// String length exceeded the buffer's declared maximum.
    LengthExceedsMaximum,
    /// A nonempty string descriptor used a null buffer address.
    NullBuffer,
}

impl NtTypeError {
    /// Converts a type-validation failure to an NT status.
    #[must_use]
    pub const fn status(self) -> NtStatus {
        NtStatus::INVALID_PARAMETER
    }
}
