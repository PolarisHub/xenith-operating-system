//! Generation-safe guest handle slots.

use crate::NtStatus;

const INDEX_BITS: u32 = 12;
const INDEX_MASK: u32 = (1 << INDEX_BITS) - 1;
const GENERATION_MASK: u32 = (1 << (32 - INDEX_BITS)) - 1;
const MAX_ISSUED_GENERATION: u32 = GENERATION_MASK - 1;

/// Maximum number of entries representable by the guest handle encoding.
pub const MAX_HANDLE_ENTRIES: usize = INDEX_MASK as usize;

/// An opaque, nonzero 32-bit guest handle.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GuestHandle(u32);

impl GuestHandle {
    /// Invalid/null handle value.
    pub const NULL: Self = Self(0);

    /// Constructs a handle from a raw guest value for boundary validation.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw guest-visible value.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns whether this is the null handle.
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

/// Runtime object type carried by a handle table entry.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectType {
    /// Internal sentinel; insertion rejects it.
    Invalid = 0,
    /// File object.
    File = 1,
    /// Directory object.
    Directory = 2,
    /// Event object.
    Event = 3,
    /// Semaphore object.
    Semaphore = 4,
    /// Mutant/mutex object.
    Mutant = 5,
    /// Shared section object.
    Section = 6,
    /// Process object.
    Process = 7,
    /// Thread object.
    Thread = 8,
    /// Console object.
    Console = 9,
    /// Registry-key object.
    RegistryKey = 10,
    /// Access-token object.
    Token = 11,
    /// Waitable timer object.
    Timer = 12,
}

/// Exact 32-bit access mask attached to one guest handle.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AccessMask(u32);

impl AccessMask {
    /// No granted access bits.
    pub const NONE: Self = Self(0);
    /// Delete right.
    pub const DELETE: Self = Self(0x0001_0000);
    /// Read-control right.
    pub const READ_CONTROL: Self = Self(0x0002_0000);
    /// Write-DACL right.
    pub const WRITE_DAC: Self = Self(0x0004_0000);
    /// Write-owner right.
    pub const WRITE_OWNER: Self = Self(0x0008_0000);
    /// Synchronize right.
    pub const SYNCHRONIZE: Self = Self(0x0010_0000);
    /// Generic-all request bit.
    pub const GENERIC_ALL: Self = Self(0x1000_0000);
    /// Generic-execute request bit.
    pub const GENERIC_EXECUTE: Self = Self(0x2000_0000);
    /// Generic-write request bit.
    pub const GENERIC_WRITE: Self = Self(0x4000_0000);
    /// Generic-read request bit.
    pub const GENERIC_READ: Self = Self(0x8000_0000);

    /// Event query-state right.
    pub const EVENT_QUERY_STATE: Self = Self(0x0000_0001);
    /// Event modify-state right.
    pub const EVENT_MODIFY_STATE: Self = Self(0x0000_0002);
    /// Mutant query-state right.
    pub const MUTANT_QUERY_STATE: Self = Self(0x0000_0001);
    /// Semaphore query-state right.
    pub const SEMAPHORE_QUERY_STATE: Self = Self(0x0000_0001);
    /// Semaphore modify-state right.
    pub const SEMAPHORE_MODIFY_STATE: Self = Self(0x0000_0002);
    /// Timer query-state right.
    pub const TIMER_QUERY_STATE: Self = Self(0x0000_0001);
    /// Timer modify-state right.
    pub const TIMER_MODIFY_STATE: Self = Self(0x0000_0002);

    /// Constructs a mask from exact access bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the exact access bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns whether every requested bit is granted.
    #[must_use]
    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }

    /// Returns the union of two exact masks.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns whether the mask has no set bits.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// One caller-owned object reference stored in the handle table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleEntry {
    /// Stable identifier in the caller's object store.
    pub object_id: u64,
    /// Runtime type used for checked references.
    pub object_type: ObjectType,
    /// Rights granted to this handle, not necessarily to the object globally.
    pub access: AccessMask,
    /// Whether a later process-creation layer may inherit this handle.
    pub inheritable: bool,
}

impl HandleEntry {
    const EMPTY: Self = Self {
        object_id: 0,
        object_type: ObjectType::Invalid,
        access: AccessMask::NONE,
        inheritable: false,
    };
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u32,
    occupied: bool,
    retired: bool,
    entry: HandleEntry,
}

impl Slot {
    const EMPTY: Self = Self {
        generation: 1,
        occupied: false,
        retired: false,
        entry: HandleEntry::EMPTY,
    };
}

/// Handle-table operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleError {
    /// The const-generic capacity is zero or exceeds the encoding limit.
    InvalidCapacity {
        /// Supplied capacity.
        capacity: usize,
        /// Largest supported capacity.
        maximum: usize,
    },
    /// All reusable table slots are occupied or permanently retired.
    TableFull,
    /// The entry used the internal invalid object type.
    InvalidObjectType,
    /// The entry used the reserved null object identity.
    InvalidObjectId,
    /// The handle was null, malformed, closed, retired, or stale.
    InvalidHandle,
    /// The entry did not have the expected runtime type.
    TypeMismatch {
        /// Type required by the operation.
        expected: ObjectType,
        /// Type stored in the referenced entry.
        actual: ObjectType,
    },
    /// The handle did not grant all requested access bits.
    AccessDenied {
        /// Requested access bits.
        requested: AccessMask,
        /// Access bits held by the source handle.
        granted: AccessMask,
    },
}

impl HandleError {
    /// Converts a table error to the bootstrap NT status boundary.
    #[must_use]
    pub const fn status(self) -> NtStatus {
        match self {
            Self::InvalidCapacity { .. } | Self::InvalidObjectType | Self::InvalidObjectId => {
                NtStatus::INVALID_PARAMETER
            },
            Self::TableFull => NtStatus::INSUFFICIENT_RESOURCES,
            Self::InvalidHandle => NtStatus::INVALID_HANDLE,
            Self::TypeMismatch { .. } => NtStatus::OBJECT_TYPE_MISMATCH,
            Self::AccessDenied { .. } => NtStatus::ACCESS_DENIED,
        }
    }
}

/// Fixed-capacity guest handle table.
///
/// The low 12 bits encode `slot + 1`; the upper 20 bits encode a nonzero
/// generation. The all-ones generation is never issued, keeping common negative
/// pseudo-handle values outside this table. A slot is retired instead of wrapping
/// its generation, so an old handle can never become valid again during the
/// table's lifetime. Closing returns the entry so the caller can release its
/// separate object-store ref.
pub struct HandleTable<const N: usize> {
    slots: [Slot; N],
    len: usize,
}

impl<const N: usize> HandleTable<N> {
    /// Creates an empty table after validating its representable capacity.
    pub const fn try_new() -> Result<Self, HandleError> {
        if N == 0 || N > MAX_HANDLE_ENTRIES {
            return Err(HandleError::InvalidCapacity {
                capacity: N,
                maximum: MAX_HANDLE_ENTRIES,
            });
        }
        Ok(Self {
            slots: [Slot::EMPTY; N],
            len: 0,
        })
    }

    /// Returns the number of live handles.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the table has no live handles.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the const-generic slot capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Inserts one caller-owned object reference into the lowest reusable slot.
    pub fn insert(&mut self, entry: HandleEntry) -> Result<GuestHandle, HandleError> {
        if entry.object_type == ObjectType::Invalid {
            return Err(HandleError::InvalidObjectType);
        }
        if entry.object_id == 0 {
            return Err(HandleError::InvalidObjectId);
        }
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if !slot.occupied && !slot.retired {
                slot.occupied = true;
                slot.entry = entry;
                self.len += 1;
                return Ok(encode(index, slot.generation));
            }
        }
        Err(HandleError::TableFull)
    }

    /// References an entry after validating generation, type, and access.
    pub fn reference(
        &self,
        handle: GuestHandle,
        expected_type: Option<ObjectType>,
        requested_access: AccessMask,
    ) -> Result<HandleEntry, HandleError> {
        let (index, generation) = decode(handle).ok_or(HandleError::InvalidHandle)?;
        let slot = self.slots.get(index).ok_or(HandleError::InvalidHandle)?;
        if !slot.occupied || slot.retired || slot.generation != generation {
            return Err(HandleError::InvalidHandle);
        }
        if let Some(expected) = expected_type {
            if slot.entry.object_type != expected {
                return Err(HandleError::TypeMismatch {
                    expected,
                    actual: slot.entry.object_type,
                });
            }
        }
        if !slot.entry.access.contains(requested_access) {
            return Err(HandleError::AccessDenied {
                requested: requested_access,
                granted: slot.entry.access,
            });
        }
        Ok(slot.entry)
    }

    /// Closes a live handle and returns its object-store reference to the caller.
    pub fn close(&mut self, handle: GuestHandle) -> Result<HandleEntry, HandleError> {
        let (index, generation) = decode(handle).ok_or(HandleError::InvalidHandle)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(HandleError::InvalidHandle)?;
        if !slot.occupied || slot.retired || slot.generation != generation {
            return Err(HandleError::InvalidHandle);
        }
        let entry = slot.entry;
        slot.occupied = false;
        slot.entry = HandleEntry::EMPTY;
        if slot.generation == MAX_ISSUED_GENERATION {
            slot.retired = true;
        } else {
            slot.generation += 1;
        }
        self.len -= 1;
        Ok(entry)
    }

    /// Duplicates a handle, optionally narrowing access and changing inheritance.
    ///
    /// The returned slot is another reference to the same `object_id`. The
    /// caller must account for that reference in its object store.
    pub fn duplicate(
        &mut self,
        source: GuestHandle,
        desired_access: Option<AccessMask>,
        inheritable: Option<bool>,
    ) -> Result<GuestHandle, HandleError> {
        let mut entry = self.reference(source, None, AccessMask::NONE)?;
        if let Some(desired) = desired_access {
            if !entry.access.contains(desired) {
                return Err(HandleError::AccessDenied {
                    requested: desired,
                    granted: entry.access,
                });
            }
            entry.access = desired;
        }
        if let Some(value) = inheritable {
            entry.inheritable = value;
        }
        self.insert(entry)
    }
}

fn encode(index: usize, generation: u32) -> GuestHandle {
    debug_assert!(index < MAX_HANDLE_ENTRIES);
    debug_assert!((1..=MAX_ISSUED_GENERATION).contains(&generation));
    GuestHandle((generation << INDEX_BITS) | (index as u32 + 1))
}

fn decode(handle: GuestHandle) -> Option<(usize, u32)> {
    let slot = handle.0 & INDEX_MASK;
    let generation = handle.0 >> INDEX_BITS;
    if slot == 0 || generation == 0 {
        return None;
    }
    Some(((slot - 1) as usize, generation))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> HandleEntry {
        HandleEntry {
            object_id: 1,
            object_type: ObjectType::Event,
            access: AccessMask::NONE,
            inheritable: false,
        }
    }

    #[test]
    fn exhausted_handle_generation_retires_instead_of_wrapping() {
        let mut table = HandleTable::<1>::try_new().unwrap();
        table.slots[0].generation = MAX_ISSUED_GENERATION;
        let last = table.insert(entry()).unwrap();

        assert_eq!(table.close(last), Ok(entry()));
        assert_eq!(
            table.reference(last, None, AccessMask::NONE),
            Err(HandleError::InvalidHandle)
        );
        assert_eq!(table.insert(entry()), Err(HandleError::TableFull));
    }
}
