//! Generation-safe, reference-counted runtime object storage.

use crate::{
    EventState, MutantState, NtStatus, NtThreadId, ObjectType, SemaphoreState, TimerState,
};

const OBJECT_INDEX_BITS: u32 = 16;
const OBJECT_INDEX_MASK: u64 = (1u64 << OBJECT_INDEX_BITS) - 1;
const OBJECT_GENERATION_MASK: u64 = (1u64 << (64 - OBJECT_INDEX_BITS)) - 1;
const MAX_ISSUED_OBJECT_GENERATION: u64 = OBJECT_GENERATION_MASK - 1;

/// Maximum fixed object-store capacity supported by the identifier encoding.
pub const MAX_OBJECT_ENTRIES: usize = OBJECT_INDEX_MASK as usize;

/// Opaque nonzero identity for one runtime object slot generation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectId(u64);

impl ObjectId {
    /// Reserved null identity.
    pub const NULL: Self = Self(0);

    /// Constructs an identity from untrusted bits for later table validation.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the exact encoded identity.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Returns whether the identity is null.
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

/// Host console endpoint retained as a typed runtime object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleObject {
    descriptor: i32,
    readable: bool,
    writable: bool,
}

impl ConsoleObject {
    /// Creates a borrowed console endpoint after validating its capabilities.
    pub const fn try_new(
        descriptor: i32,
        readable: bool,
        writable: bool,
    ) -> Result<Self, ObjectError> {
        if descriptor < 0 || (!readable && !writable) {
            return Err(ObjectError::InvalidObject);
        }
        Ok(Self {
            descriptor,
            readable,
            writable,
        })
    }

    /// Returns the borrowed Xenith descriptor number.
    #[must_use]
    pub const fn descriptor(self) -> i32 {
        self.descriptor
    }

    /// Returns whether reads are allowed by this object.
    #[must_use]
    pub const fn is_readable(self) -> bool {
        self.readable
    }

    /// Returns whether writes are allowed by this object.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        self.writable
    }
}

/// Inline payload for every supported runtime object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeObject {
    /// Internal empty-slot sentinel; insertion rejects it.
    Invalid,
    /// Event object.
    Event(EventState),
    /// Recursive mutant object.
    Mutant(MutantState),
    /// Counting semaphore object.
    Semaphore(SemaphoreState),
    /// Waitable timer object.
    Timer(TimerState),
    /// Borrowed console endpoint.
    Console(ConsoleObject),
}

impl RuntimeObject {
    /// Returns the handle-table type corresponding to this payload.
    #[must_use]
    pub const fn object_type(self) -> ObjectType {
        match self {
            Self::Invalid => ObjectType::Invalid,
            Self::Event(_) => ObjectType::Event,
            Self::Mutant(_) => ObjectType::Mutant,
            Self::Semaphore(_) => ObjectType::Semaphore,
            Self::Timer(_) => ObjectType::Timer,
            Self::Console(_) => ObjectType::Console,
        }
    }
}

#[derive(Clone, Copy)]
struct ObjectSlot {
    generation: u64,
    references: u32,
    occupied: bool,
    retired: bool,
    object: RuntimeObject,
}

impl ObjectSlot {
    const EMPTY: Self = Self {
        generation: 1,
        references: 0,
        occupied: false,
        retired: false,
        object: RuntimeObject::Invalid,
    };
}

/// Object-store operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectError {
    /// The const-generic capacity is zero or exceeds the identifier encoding.
    InvalidCapacity {
        /// Supplied capacity.
        capacity: usize,
        /// Largest supported capacity.
        maximum: usize,
    },
    /// All non-retired slots are occupied.
    TableFull,
    /// The caller supplied the internal invalid object sentinel.
    InvalidObject,
    /// The object identity was null, malformed, stale, or already released.
    InvalidObjectId,
    /// The object did not have the expected runtime type.
    TypeMismatch {
        /// Required type.
        expected: ObjectType,
        /// Stored type.
        actual: ObjectType,
    },
    /// The reference count could not be increased without wrapping.
    ReferenceOverflow,
}

impl ObjectError {
    /// Converts an object-store failure to a stable NT status.
    #[must_use]
    pub const fn status(self) -> NtStatus {
        match self {
            Self::InvalidCapacity { .. } | Self::InvalidObject => NtStatus::INVALID_PARAMETER,
            Self::TableFull | Self::ReferenceOverflow => NtStatus::INSUFFICIENT_RESOURCES,
            Self::InvalidObjectId => NtStatus::INVALID_HANDLE,
            Self::TypeMismatch { .. } => NtStatus::OBJECT_TYPE_MISMATCH,
        }
    }
}

/// Fixed-capacity object store with non-wrapping generations and refcounts.
///
/// Each inserted object starts with one caller-owned reference. Handle
/// duplication must retain the object before publishing the new handle, and
/// handle close must release exactly one reference. The last release returns
/// the payload so a host can retire external resources outside this table.
pub struct ObjectTable<const N: usize> {
    slots: [ObjectSlot; N],
    len: usize,
}

impl<const N: usize> ObjectTable<N> {
    /// Creates an empty table after validating capacity.
    pub const fn try_new() -> Result<Self, ObjectError> {
        if N == 0 || N > MAX_OBJECT_ENTRIES {
            return Err(ObjectError::InvalidCapacity {
                capacity: N,
                maximum: MAX_OBJECT_ENTRIES,
            });
        }
        Ok(Self {
            slots: [ObjectSlot::EMPTY; N],
            len: 0,
        })
    }

    /// Returns the number of live objects, independent of reference counts.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether no object is live.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Inserts an object and gives the caller its first reference.
    pub fn insert(&mut self, object: RuntimeObject) -> Result<ObjectId, ObjectError> {
        if object.object_type() == ObjectType::Invalid {
            return Err(ObjectError::InvalidObject);
        }
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if !slot.occupied && !slot.retired {
                slot.occupied = true;
                slot.references = 1;
                slot.object = object;
                self.len += 1;
                return Ok(encode_object(index, slot.generation));
            }
        }
        Err(ObjectError::TableFull)
    }

    /// Copies an object after validating identity and optional type.
    pub fn reference(
        &self,
        id: ObjectId,
        expected: Option<ObjectType>,
    ) -> Result<RuntimeObject, ObjectError> {
        let slot = self.live_slot(id)?;
        validate_type(slot.object, expected)?;
        Ok(slot.object)
    }

    /// Borrows an object mutably after validating identity and optional type.
    pub fn reference_mut(
        &mut self,
        id: ObjectId,
        expected: Option<ObjectType>,
    ) -> Result<&mut RuntimeObject, ObjectError> {
        let slot = self.live_slot_mut(id)?;
        validate_type(slot.object, expected)?;
        Ok(&mut slot.object)
    }

    /// Adds one reference without allowing the counter to wrap.
    pub fn retain(&mut self, id: ObjectId) -> Result<u32, ObjectError> {
        let slot = self.live_slot_mut(id)?;
        let next = slot
            .references
            .checked_add(1)
            .ok_or(ObjectError::ReferenceOverflow)?;
        slot.references = next;
        Ok(next)
    }

    /// Releases one reference and returns the payload after the last release.
    pub fn release(&mut self, id: ObjectId) -> Result<Option<RuntimeObject>, ObjectError> {
        let (index, generation) = decode_object(id).ok_or(ObjectError::InvalidObjectId)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ObjectError::InvalidObjectId)?;
        if !slot.occupied || slot.retired || slot.generation != generation || slot.references == 0 {
            return Err(ObjectError::InvalidObjectId);
        }
        slot.references -= 1;
        if slot.references != 0 {
            return Ok(None);
        }

        let retired = slot.object;
        slot.object = RuntimeObject::Invalid;
        slot.occupied = false;
        if slot.generation == MAX_ISSUED_OBJECT_GENERATION {
            slot.retired = true;
        } else {
            slot.generation += 1;
        }
        self.len -= 1;
        Ok(Some(retired))
    }

    /// Returns the live reference count for diagnostics and invariant tests.
    pub fn reference_count(&self, id: ObjectId) -> Result<u32, ObjectError> {
        Ok(self.live_slot(id)?.references)
    }

    /// Abandons every mutant currently owned by `thread`.
    ///
    /// Returns the number of objects whose ownership changed.
    pub fn abandon_mutants(&mut self, thread: NtThreadId) -> usize {
        let mut changed = 0;
        for slot in &mut self.slots {
            if !slot.occupied {
                continue;
            }
            if let RuntimeObject::Mutant(mutant) = &mut slot.object {
                changed += usize::from(mutant.abandon_if_owned(thread));
            }
        }
        changed
    }

    fn live_slot(&self, id: ObjectId) -> Result<&ObjectSlot, ObjectError> {
        let (index, generation) = decode_object(id).ok_or(ObjectError::InvalidObjectId)?;
        let slot = self.slots.get(index).ok_or(ObjectError::InvalidObjectId)?;
        if !slot.occupied || slot.retired || slot.generation != generation || slot.references == 0 {
            return Err(ObjectError::InvalidObjectId);
        }
        Ok(slot)
    }

    fn live_slot_mut(&mut self, id: ObjectId) -> Result<&mut ObjectSlot, ObjectError> {
        let (index, generation) = decode_object(id).ok_or(ObjectError::InvalidObjectId)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ObjectError::InvalidObjectId)?;
        if !slot.occupied || slot.retired || slot.generation != generation || slot.references == 0 {
            return Err(ObjectError::InvalidObjectId);
        }
        Ok(slot)
    }
}

fn validate_type(object: RuntimeObject, expected: Option<ObjectType>) -> Result<(), ObjectError> {
    if let Some(expected) = expected {
        let actual = object.object_type();
        if actual != expected {
            return Err(ObjectError::TypeMismatch { expected, actual });
        }
    }
    Ok(())
}

fn encode_object(index: usize, generation: u64) -> ObjectId {
    debug_assert!(index < MAX_OBJECT_ENTRIES);
    debug_assert!((1..=MAX_ISSUED_OBJECT_GENERATION).contains(&generation));
    ObjectId((generation << OBJECT_INDEX_BITS) | (index as u64 + 1))
}

fn decode_object(id: ObjectId) -> Option<(usize, u64)> {
    let slot = id.0 & OBJECT_INDEX_MASK;
    let generation = id.0 >> OBJECT_INDEX_BITS;
    if slot == 0 || generation == 0 || generation > MAX_ISSUED_OBJECT_GENERATION {
        return None;
    }
    Some(((slot - 1) as usize, generation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventKind, EventState};

    fn event() -> RuntimeObject {
        RuntimeObject::Event(EventState::new(EventKind::Notification, false))
    }

    #[test]
    fn reference_overflow_is_transactional() {
        let mut table = ObjectTable::<1>::try_new().unwrap();
        let id = table.insert(event()).unwrap();
        table.slots[0].references = u32::MAX;

        assert_eq!(table.retain(id), Err(ObjectError::ReferenceOverflow));
        assert_eq!(table.reference_count(id), Ok(u32::MAX));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn exhausted_object_generation_retires_instead_of_wrapping() {
        let mut table = ObjectTable::<1>::try_new().unwrap();
        table.slots[0].generation = MAX_ISSUED_OBJECT_GENERATION;
        let last = table.insert(event()).unwrap();

        assert!(matches!(
            table.release(last),
            Ok(Some(RuntimeObject::Event(_)))
        ));
        assert_eq!(
            table.reference(last, None),
            Err(ObjectError::InvalidObjectId)
        );
        assert_eq!(table.insert(event()), Err(ObjectError::TableFull));
    }
}
