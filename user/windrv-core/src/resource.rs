//! Capability-scoped hardware-resource descriptions for an isolated host.

use xenith_winhost_core::NtStatus;

const INDEX_BITS: u32 = 8;
const INDEX_MASK: u32 = (1 << INDEX_BITS) - 1;
const GENERATION_MASK: u32 = (1 << (32 - INDEX_BITS)) - 1;
const MAX_ISSUED_GENERATION: u32 = GENERATION_MASK - 1;
const PAGE_SIZE: u64 = 4096;
const ALL_RESOURCE_RIGHTS: ResourceRights = ResourceRights::READ
    .union(ResourceRights::WRITE)
    .union(ResourceRights::MAP)
    .union(ResourceRights::ACK_INTERRUPT)
    .union(ResourceRights::DMA);

/// Maximum hardware grants in one isolated driver host.
pub const MAX_HARDWARE_GRANTS: usize = INDEX_MASK as usize;

/// Maximum MMIO span described by one grant.
pub const MAX_MMIO_GRANT_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum DMA transfer advertised by one domain grant.
pub const MAX_DMA_TRANSFER_BYTES: u32 = 16 * 1024 * 1024;

/// Opaque generation-safe hardware capability identifier.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceId(u32);

impl ResourceId {
    /// Null/invalid identifier.
    pub const NULL: Self = Self(0);

    /// Constructs an ID from an untrusted boundary value.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the exact boundary value.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// Rights attached to one hardware grant.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ResourceRights(u8);

impl ResourceRights {
    /// No rights; grant creation rejects this value.
    pub const NONE: Self = Self(0);
    /// Read from an I/O-port or MMIO range.
    pub const READ: Self = Self(1 << 0);
    /// Write to an I/O-port or MMIO range.
    pub const WRITE: Self = Self(1 << 1);
    /// Map an MMIO range into the isolated host.
    pub const MAP: Self = Self(1 << 2);
    /// Acknowledge a delivered interrupt.
    pub const ACK_INTERRUPT: Self = Self(1 << 3);
    /// Submit DMA mappings through the host's bounded DMA service.
    pub const DMA: Self = Self(1 << 4);

    /// Constructs a rights word for boundary validation.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Returns the exact rights bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Returns the union of two rights sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns whether every requested bit is granted.
    #[must_use]
    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }
}

/// Hardware resource described by trusted enumeration, never by the guest
/// driver itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareResource {
    /// Inclusive-start I/O-port range.
    IoPort {
        /// First x86 I/O port.
        start: u16,
        /// Nonzero port count.
        length: u32,
    },
    /// Page-aligned physical MMIO span.
    Mmio {
        /// Page-aligned physical base.
        physical_base: u64,
        /// Page-multiple byte length.
        length: u64,
    },
    /// One interrupt route delivered through the host.
    Interrupt {
        /// Architectural interrupt vector, excluding CPU exceptions.
        vector: u8,
        /// `true` for level-triggered, `false` for edge-triggered.
        level_triggered: bool,
        /// Polarity supplied by firmware/routing tables.
        active_low: bool,
    },
    /// DMA domain policy; no physical address is directly exposed.
    DmaDomain {
        /// Highest device-visible bus address.
        maximum_address: u64,
        /// Maximum bytes in one submitted mapping.
        maximum_transfer: u32,
        /// Whether the device is cache coherent with CPUs.
        coherent: bool,
    },
}

/// One validated resource and its attenuated rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareGrant {
    /// Resource discovered and assigned by trusted host policy.
    pub resource: HardwareResource,
    /// Operations the driver host may request.
    pub rights: ResourceRights,
}

impl HardwareGrant {
    const EMPTY: Self = Self {
        resource: HardwareResource::IoPort {
            start: 0,
            length: 1,
        },
        rights: ResourceRights::NONE,
    };

    /// Validates range arithmetic and kind-specific rights.
    pub const fn validate(self) -> Result<Self, ResourceError> {
        if self.rights.bits() == 0 {
            return Err(ResourceError::InvalidRights);
        }
        match self.resource {
            HardwareResource::IoPort { start, length } => {
                let Some(end) = (start as u32).checked_add(length) else {
                    return Err(ResourceError::InvalidRange);
                };
                if length == 0 || end > 0x1_0000 {
                    return Err(ResourceError::InvalidRange);
                }
                let allowed = ResourceRights::READ.union(ResourceRights::WRITE);
                if !allowed.contains(self.rights) {
                    return Err(ResourceError::InvalidRights);
                }
            },
            HardwareResource::Mmio {
                physical_base,
                length,
            } => {
                if physical_base & (PAGE_SIZE - 1) != 0
                    || length == 0
                    || length & (PAGE_SIZE - 1) != 0
                    || length > MAX_MMIO_GRANT_BYTES
                    || physical_base.checked_add(length).is_none()
                {
                    return Err(ResourceError::InvalidRange);
                }
                let allowed = ResourceRights::READ
                    .union(ResourceRights::WRITE)
                    .union(ResourceRights::MAP);
                let data_access = ResourceRights::READ.union(ResourceRights::WRITE);
                if !allowed.contains(self.rights)
                    || !self.rights.contains(ResourceRights::MAP)
                    || self.rights.bits() & data_access.bits() == 0
                {
                    return Err(ResourceError::InvalidRights);
                }
            },
            HardwareResource::Interrupt { vector, .. } => {
                if vector < 32 {
                    return Err(ResourceError::InvalidRange);
                }
                if self.rights.bits() != ResourceRights::ACK_INTERRUPT.bits() {
                    return Err(ResourceError::InvalidRights);
                }
            },
            HardwareResource::DmaDomain {
                maximum_address,
                maximum_transfer,
                ..
            } => {
                if maximum_address == 0
                    || maximum_transfer == 0
                    || maximum_transfer > MAX_DMA_TRANSFER_BYTES
                {
                    return Err(ResourceError::InvalidRange);
                }
                if self.rights.bits() != ResourceRights::DMA.bits() {
                    return Err(ResourceError::InvalidRights);
                }
            },
        }
        Ok(self)
    }
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u32,
    occupied: bool,
    retired: bool,
    grant: HardwareGrant,
}

impl Slot {
    const EMPTY: Self = Self {
        generation: 1,
        occupied: false,
        retired: false,
        grant: HardwareGrant::EMPTY,
    };
}

/// Hardware grant-table failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceError {
    /// Capacity is zero or cannot be represented.
    InvalidCapacity {
        /// Requested capacity.
        capacity: usize,
        /// Encoding maximum.
        maximum: usize,
    },
    /// Every reusable grant slot is occupied.
    TableFull,
    /// Resource identifier is null, malformed, revoked, or stale.
    InvalidResource,
    /// Address, length, vector, or DMA bound is invalid.
    InvalidRange,
    /// Rights are empty, unknown, or invalid for this resource kind.
    InvalidRights,
    /// The requested operation exceeds the grant.
    AccessDenied {
        /// Requested rights.
        requested: ResourceRights,
        /// Granted rights.
        granted: ResourceRights,
    },
}

impl ResourceError {
    /// Converts a resource-policy failure to an NT status value.
    #[must_use]
    pub const fn status(self) -> NtStatus {
        match self {
            Self::InvalidCapacity { .. } | Self::InvalidRange | Self::InvalidRights => {
                NtStatus::INVALID_PARAMETER
            },
            Self::TableFull => NtStatus::INSUFFICIENT_RESOURCES,
            Self::InvalidResource => NtStatus::INVALID_HANDLE,
            Self::AccessDenied { .. } => NtStatus::ACCESS_DENIED,
        }
    }
}

/// Fixed-capacity table owned by one isolated driver-host process.
pub struct HardwareGrantTable<const N: usize> {
    slots: [Slot; N],
    len: usize,
}

impl<const N: usize> HardwareGrantTable<N> {
    /// Creates an empty table after validating the identifier encoding.
    pub const fn try_new() -> Result<Self, ResourceError> {
        if N == 0 || N > MAX_HARDWARE_GRANTS {
            return Err(ResourceError::InvalidCapacity {
                capacity: N,
                maximum: MAX_HARDWARE_GRANTS,
            });
        }
        Ok(Self {
            slots: [Slot::EMPTY; N],
            len: 0,
        })
    }

    /// Number of live grants.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether no grant is live.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Publishes one fully validated trusted-host grant.
    pub fn grant(&mut self, grant: HardwareGrant) -> Result<ResourceId, ResourceError> {
        let grant = grant.validate()?;
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if !slot.occupied && !slot.retired {
                slot.grant = grant;
                slot.occupied = true;
                self.len += 1;
                return Ok(ResourceId(encode(index, slot.generation)));
            }
        }
        Err(ResourceError::TableFull)
    }

    /// Returns one exactly attenuated grant after generation and rights checks.
    pub fn reference(
        &self,
        id: ResourceId,
        requested: ResourceRights,
    ) -> Result<HardwareGrant, ResourceError> {
        if requested.bits() == 0 || !ALL_RESOURCE_RIGHTS.contains(requested) {
            return Err(ResourceError::InvalidRights);
        }
        let (index, generation) = decode(id.0).ok_or(ResourceError::InvalidResource)?;
        let slot = self
            .slots
            .get(index)
            .ok_or(ResourceError::InvalidResource)?;
        if !slot.occupied || slot.retired || slot.generation != generation {
            return Err(ResourceError::InvalidResource);
        }
        if !slot.grant.rights.contains(requested) {
            return Err(ResourceError::AccessDenied {
                requested,
                granted: slot.grant.rights,
            });
        }
        HardwareGrant {
            resource: slot.grant.resource,
            rights: requested,
        }
        .validate()
    }

    /// Revokes a grant and invalidates every stale copy of its ID.
    pub fn revoke(&mut self, id: ResourceId) -> Result<HardwareGrant, ResourceError> {
        let (index, generation) = decode(id.0).ok_or(ResourceError::InvalidResource)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ResourceError::InvalidResource)?;
        if !slot.occupied || slot.retired || slot.generation != generation {
            return Err(ResourceError::InvalidResource);
        }
        let grant = slot.grant;
        slot.occupied = false;
        slot.grant = HardwareGrant::EMPTY;
        if slot.generation == MAX_ISSUED_GENERATION {
            slot.retired = true;
        } else {
            slot.generation += 1;
        }
        self.len -= 1;
        Ok(grant)
    }
}

fn encode(index: usize, generation: u32) -> u32 {
    debug_assert!(index < MAX_HARDWARE_GRANTS);
    debug_assert!((1..=MAX_ISSUED_GENERATION).contains(&generation));
    (generation << INDEX_BITS) | (index as u32 + 1)
}

fn decode(raw: u32) -> Option<(usize, u32)> {
    let slot = raw & INDEX_MASK;
    let generation = raw >> INDEX_BITS;
    if slot == 0 || generation == 0 || generation > MAX_ISSUED_GENERATION {
        return None;
    }
    Some(((slot - 1) as usize, generation))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> HardwareGrant {
        HardwareGrant {
            resource: HardwareResource::IoPort {
                start: 0x3f8,
                length: 8,
            },
            rights: ResourceRights::READ,
        }
    }

    #[test]
    fn final_resource_generation_retires_without_wrapping() {
        let mut table = HardwareGrantTable::<1>::try_new().unwrap();
        table.slots[0].generation = MAX_ISSUED_GENERATION;
        let id = table.grant(grant()).unwrap();
        table.revoke(id).unwrap();

        assert_eq!(
            table.reference(id, ResourceRights::READ),
            Err(ResourceError::InvalidResource)
        );
        assert_eq!(table.grant(grant()), Err(ResourceError::TableFull));
    }
}
