//! Generation-safe driver/device objects and bounded device stacks.

use xenith_winhost_core::{NtStatus, RUNTIME_USER_ADDRESS_LIMIT};

use crate::{MajorFunction, MAJOR_FUNCTION_COUNT};

const INDEX_BITS: u32 = 8;
const INDEX_MASK: u32 = (1 << INDEX_BITS) - 1;
const GENERATION_MASK: u32 = (1 << (32 - INDEX_BITS)) - 1;
const MAX_ISSUED_GENERATION: u32 = GENERATION_MASK - 1;

const MAX_ENCODED_OBJECTS: usize = INDEX_MASK as usize;

/// Operational limit for inline driver records.
///
/// Driver records contain a complete major-function table, so this is kept
/// below the ID encoding limit to bound const-generic object size.
pub const MAX_DRIVER_OBJECTS: usize = 64;

/// Maximum inline device records accepted by one registry.
pub const MAX_DEVICE_OBJECTS: usize = MAX_ENCODED_OBJECTS;

/// Maximum attached devices traversed for one request.
pub const MAX_DEVICE_STACK_DEPTH: usize = 8;

/// Largest driver image accepted by the policy record.
pub const MAX_DRIVER_IMAGE_BYTES: u64 = 64 * 1024 * 1024;

/// Opaque generation-safe driver identifier.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DriverId(u32);

impl DriverId {
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

/// Opaque generation-safe device identifier.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceId(u32);

impl DeviceId {
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

    pub(crate) const fn is_well_formed(self) -> bool {
        decode(self.0).is_some()
    }
}

/// Checked guest addresses supplied by one loaded driver image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverObject {
    image_base: u64,
    image_size: u64,
    driver_entry: u64,
    add_device: u64,
    unload: u64,
    major_functions: [u64; MAJOR_FUNCTION_COUNT],
}

impl DriverObject {
    const EMPTY: Self = Self {
        image_base: 0,
        image_size: 0,
        driver_entry: 0,
        add_device: 0,
        unload: 0,
        major_functions: [0; MAJOR_FUNCTION_COUNT],
    };

    /// Creates an object after validating that its entry lies in the image.
    pub fn new(image_base: u64, image_size: u64, driver_entry: u64) -> Result<Self, RegistryError> {
        let object = Self {
            image_base,
            image_size,
            driver_entry,
            ..Self::EMPTY
        };
        object.validate_address(driver_entry, false)?;
        Ok(object)
    }

    /// Returns the mapped image base.
    #[must_use]
    pub const fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Returns the mapped image length.
    #[must_use]
    pub const fn image_size(&self) -> u64 {
        self.image_size
    }

    /// Returns the validated `DriverEntry` address.
    #[must_use]
    pub const fn driver_entry(&self) -> u64 {
        self.driver_entry
    }

    /// Installs the optional `AddDevice` callback. Zero means absent.
    pub fn set_add_device(&mut self, address: u64) -> Result<(), RegistryError> {
        self.validate_address(address, true)?;
        self.add_device = address;
        Ok(())
    }

    /// Installs the optional unload callback. Zero means absent.
    pub fn set_unload(&mut self, address: u64) -> Result<(), RegistryError> {
        self.validate_address(address, true)?;
        self.unload = address;
        Ok(())
    }

    /// Installs one major-function dispatch address. Zero removes it.
    pub fn set_dispatch(
        &mut self,
        major: MajorFunction,
        address: u64,
    ) -> Result<(), RegistryError> {
        self.validate_address(address, true)?;
        self.major_functions[major.index()] = address;
        Ok(())
    }

    /// Returns the `AddDevice` callback, if supplied.
    #[must_use]
    pub const fn add_device(&self) -> Option<u64> {
        if self.add_device == 0 {
            None
        } else {
            Some(self.add_device)
        }
    }

    /// Returns the unload callback, if supplied.
    #[must_use]
    pub const fn unload(&self) -> Option<u64> {
        if self.unload == 0 {
            None
        } else {
            Some(self.unload)
        }
    }

    /// Returns one registered dispatch address.
    #[must_use]
    pub const fn dispatch(&self, major: MajorFunction) -> Option<u64> {
        let address = self.major_functions[major.index()];
        if address == 0 {
            None
        } else {
            Some(address)
        }
    }

    fn validate_address(&self, address: u64, optional: bool) -> Result<(), RegistryError> {
        if optional && address == 0 {
            return Ok(());
        }
        if self.image_base == 0
            || self.image_base >= RUNTIME_USER_ADDRESS_LIMIT
            || self.image_size == 0
            || self.image_size > MAX_DRIVER_IMAGE_BYTES
        {
            return Err(RegistryError::InvalidImageRange);
        }
        let end = self
            .image_base
            .checked_add(self.image_size)
            .ok_or(RegistryError::InvalidImageRange)?;
        if end > RUNTIME_USER_ADDRESS_LIMIT {
            return Err(RegistryError::InvalidImageRange);
        }
        if address < self.image_base || address >= end {
            return Err(RegistryError::AddressOutsideImage { address });
        }
        Ok(())
    }
}

/// One device object owned by a registered driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceObject {
    /// Driver which owns this device object.
    pub owner: DriverId,
    /// Next lower device in the attachment stack.
    pub lower_device: Option<DeviceId>,
    /// Public Windows device-type value.
    pub device_type: u16,
    /// Driver-defined device characteristics.
    pub characteristics: u32,
}

impl DeviceObject {
    const EMPTY: Self = Self {
        owner: DriverId::NULL,
        lower_device: None,
        device_type: 0,
        characteristics: 0,
    };
}

/// Immutable top-to-bottom snapshot of a validated device stack.
///
/// IDs remain generation checked by [`DriverRegistry`] when each dispatch is
/// resolved, so removing a device after planning turns later lookup into an
/// explicit stale-device error rather than a dangling reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceStack {
    devices: [DeviceId; MAX_DEVICE_STACK_DEPTH],
    len: u8,
}

impl DeviceStack {
    const EMPTY: Self = Self {
        devices: [DeviceId::NULL; MAX_DEVICE_STACK_DEPTH],
        len: 0,
    };

    /// Number of devices from top to bottom.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns whether the snapshot has no devices.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the device at a zero-based stack location.
    #[must_use]
    pub fn get(&self, location: usize) -> Option<DeviceId> {
        self.devices
            .get(location)
            .copied()
            .filter(|_| location < self.len())
    }

    /// Returns the validated top device.
    #[must_use]
    pub fn top(&self) -> Option<DeviceId> {
        self.get(0)
    }
}

#[derive(Clone, Copy)]
struct DriverSlot {
    generation: u32,
    occupied: bool,
    retired: bool,
    object: DriverObject,
}

impl DriverSlot {
    const EMPTY: Self = Self {
        generation: 1,
        occupied: false,
        retired: false,
        object: DriverObject::EMPTY,
    };
}

#[derive(Clone, Copy)]
struct DeviceSlot {
    generation: u32,
    occupied: bool,
    retired: bool,
    object: DeviceObject,
}

impl DeviceSlot {
    const EMPTY: Self = Self {
        generation: 1,
        occupied: false,
        retired: false,
        object: DeviceObject::EMPTY,
    };
}

/// Driver/device registry failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    /// A const-generic capacity is zero or exceeds its operational bound.
    InvalidCapacity {
        /// Requested capacity.
        capacity: usize,
        /// Operational maximum for the selected object kind.
        maximum: usize,
    },
    /// All reusable slots are occupied.
    TableFull,
    /// Driver ID is null, malformed, closed, or stale.
    InvalidDriver,
    /// Device ID is null, malformed, removed, or stale.
    InvalidDevice,
    /// The image base/size is empty, overflowing, or exceeds the bound.
    InvalidImageRange,
    /// A guest callback is outside its owning image.
    AddressOutsideImage {
        /// Rejected guest address.
        address: u64,
    },
    /// A driver still owns device objects.
    DriverBusy,
    /// Another object is still attached above the device.
    DeviceBusy,
    /// The upper device already has a lower attachment.
    AlreadyAttached,
    /// The requested attachment would create a cycle.
    AttachmentCycle,
    /// The bounded device-stack depth would be exceeded.
    StackTooDeep,
    /// The driver did not register this major function.
    NoDispatch,
}

impl RegistryError {
    /// Converts the policy error to an NT status value.
    #[must_use]
    pub const fn status(self) -> NtStatus {
        match self {
            Self::InvalidCapacity { .. }
            | Self::InvalidImageRange
            | Self::AddressOutsideImage { .. }
            | Self::AlreadyAttached
            | Self::AttachmentCycle => NtStatus::INVALID_PARAMETER,
            Self::TableFull => NtStatus::INSUFFICIENT_RESOURCES,
            Self::InvalidDriver | Self::InvalidDevice => NtStatus::INVALID_HANDLE,
            Self::DriverBusy | Self::DeviceBusy => NtStatus::SHARING_VIOLATION,
            Self::StackTooDeep | Self::NoDispatch => NtStatus::NOT_SUPPORTED,
        }
    }
}

/// Fixed-capacity registry used by an isolated driver-host process.
pub struct DriverRegistry<const DRIVERS: usize, const DEVICES: usize> {
    drivers: [DriverSlot; DRIVERS],
    devices: [DeviceSlot; DEVICES],
    driver_count: usize,
    device_count: usize,
}

impl<const DRIVERS: usize, const DEVICES: usize> DriverRegistry<DRIVERS, DEVICES> {
    /// Creates an empty registry after checking both encodings.
    pub const fn try_new() -> Result<Self, RegistryError> {
        if DRIVERS == 0 || DRIVERS > MAX_DRIVER_OBJECTS {
            return Err(RegistryError::InvalidCapacity {
                capacity: DRIVERS,
                maximum: MAX_DRIVER_OBJECTS,
            });
        }
        if DEVICES == 0 || DEVICES > MAX_DEVICE_OBJECTS {
            return Err(RegistryError::InvalidCapacity {
                capacity: DEVICES,
                maximum: MAX_DEVICE_OBJECTS,
            });
        }
        Ok(Self {
            drivers: [DriverSlot::EMPTY; DRIVERS],
            devices: [DeviceSlot::EMPTY; DEVICES],
            driver_count: 0,
            device_count: 0,
        })
    }

    /// Number of live driver objects.
    #[must_use]
    pub const fn driver_count(&self) -> usize {
        self.driver_count
    }

    /// Number of live device objects.
    #[must_use]
    pub const fn device_count(&self) -> usize {
        self.device_count
    }

    /// Publishes a fully validated driver object transactionally.
    pub fn register_driver(&mut self, object: DriverObject) -> Result<DriverId, RegistryError> {
        object.validate_address(object.driver_entry, false)?;
        for (index, slot) in self.drivers.iter_mut().enumerate() {
            if !slot.occupied && !slot.retired {
                slot.object = object;
                slot.occupied = true;
                self.driver_count += 1;
                return Ok(DriverId(encode(index, slot.generation)));
            }
        }
        Err(RegistryError::TableFull)
    }

    /// Returns a copy of one validated driver record.
    pub fn driver(&self, id: DriverId) -> Result<DriverObject, RegistryError> {
        let (index, generation) = decode(id.0).ok_or(RegistryError::InvalidDriver)?;
        let slot = self
            .drivers
            .get(index)
            .ok_or(RegistryError::InvalidDriver)?;
        if !slot.occupied || slot.retired || slot.generation != generation {
            return Err(RegistryError::InvalidDriver);
        }
        Ok(slot.object)
    }

    /// Removes a driver only after all of its devices are gone.
    pub fn unregister_driver(&mut self, id: DriverId) -> Result<DriverObject, RegistryError> {
        self.driver(id)?;
        if self
            .devices
            .iter()
            .any(|slot| slot.occupied && slot.object.owner == id)
        {
            return Err(RegistryError::DriverBusy);
        }
        let (index, generation) = decode(id.0).ok_or(RegistryError::InvalidDriver)?;
        let slot = &mut self.drivers[index];
        if slot.generation != generation {
            return Err(RegistryError::InvalidDriver);
        }
        let object = slot.object;
        retire_slot(&mut slot.generation, &mut slot.occupied, &mut slot.retired);
        slot.object = DriverObject::EMPTY;
        self.driver_count -= 1;
        Ok(object)
    }

    /// Creates a device and optionally attaches it above an existing device.
    pub fn create_device(
        &mut self,
        owner: DriverId,
        lower_device: Option<DeviceId>,
        device_type: u16,
        characteristics: u32,
    ) -> Result<DeviceId, RegistryError> {
        self.driver(owner)?;
        if let Some(lower) = lower_device {
            self.device(lower)?;
            if self.has_upper_attachment(lower) {
                return Err(RegistryError::DeviceBusy);
            }
            if self.stack_depth(lower)? >= MAX_DEVICE_STACK_DEPTH {
                return Err(RegistryError::StackTooDeep);
            }
        }
        for (index, slot) in self.devices.iter_mut().enumerate() {
            if !slot.occupied && !slot.retired {
                slot.object = DeviceObject {
                    owner,
                    lower_device,
                    device_type,
                    characteristics,
                };
                slot.occupied = true;
                self.device_count += 1;
                return Ok(DeviceId(encode(index, slot.generation)));
            }
        }
        Err(RegistryError::TableFull)
    }

    /// Returns a copy of one validated device record.
    pub fn device(&self, id: DeviceId) -> Result<DeviceObject, RegistryError> {
        let (index, generation) = decode(id.0).ok_or(RegistryError::InvalidDevice)?;
        let slot = self
            .devices
            .get(index)
            .ok_or(RegistryError::InvalidDevice)?;
        if !slot.occupied || slot.retired || slot.generation != generation {
            return Err(RegistryError::InvalidDevice);
        }
        Ok(slot.object)
    }

    /// Attaches an existing upper device to a lower stack transactionally.
    pub fn attach_device(&mut self, upper: DeviceId, lower: DeviceId) -> Result<(), RegistryError> {
        let upper_object = self.device(upper)?;
        self.device(lower)?;
        if upper_object.lower_device.is_some() {
            return Err(RegistryError::AlreadyAttached);
        }
        if self.has_upper_attachment(lower) {
            return Err(RegistryError::DeviceBusy);
        }
        let mut cursor = Some(lower);
        let mut depth = 1usize;
        let mut visited = [DeviceId::NULL; MAX_DEVICE_STACK_DEPTH];
        while let Some(current) = cursor {
            if current == upper {
                return Err(RegistryError::AttachmentCycle);
            }
            if visited[..depth - 1].contains(&current) {
                return Err(RegistryError::AttachmentCycle);
            }
            if depth >= MAX_DEVICE_STACK_DEPTH {
                return Err(RegistryError::StackTooDeep);
            }
            visited[depth - 1] = current;
            cursor = self.device(current)?.lower_device;
            depth += 1;
        }
        let (index, _) = decode(upper.0).ok_or(RegistryError::InvalidDevice)?;
        self.devices[index].object.lower_device = Some(lower);
        Ok(())
    }

    /// Detaches and returns the previous lower device, if any.
    pub fn detach_device(&mut self, upper: DeviceId) -> Result<Option<DeviceId>, RegistryError> {
        self.device(upper)?;
        let (index, _) = decode(upper.0).ok_or(RegistryError::InvalidDevice)?;
        Ok(self.devices[index].object.lower_device.take())
    }

    /// Removes a device after every upper attachment has been removed.
    pub fn remove_device(&mut self, id: DeviceId) -> Result<DeviceObject, RegistryError> {
        self.device(id)?;
        if self
            .devices
            .iter()
            .any(|slot| slot.occupied && slot.object.lower_device == Some(id))
        {
            return Err(RegistryError::DeviceBusy);
        }
        let (index, generation) = decode(id.0).ok_or(RegistryError::InvalidDevice)?;
        let slot = &mut self.devices[index];
        if slot.generation != generation {
            return Err(RegistryError::InvalidDevice);
        }
        let object = slot.object;
        retire_slot(&mut slot.generation, &mut slot.occupied, &mut slot.retired);
        slot.object = DeviceObject::EMPTY;
        self.device_count -= 1;
        Ok(object)
    }

    /// Resolves the dispatch address for a request sent to one device.
    pub fn dispatch_address(
        &self,
        device: DeviceId,
        major: MajorFunction,
    ) -> Result<u64, RegistryError> {
        let device = self.device(device)?;
        self.driver(device.owner)?
            .dispatch(major)
            .ok_or(RegistryError::NoDispatch)
    }

    /// Returns the number of devices from `top` through the bottom.
    pub fn stack_depth(&self, top: DeviceId) -> Result<usize, RegistryError> {
        let mut cursor = Some(top);
        let mut depth = 0usize;
        let mut visited = [DeviceId::NULL; MAX_DEVICE_STACK_DEPTH];
        while let Some(current) = cursor {
            if visited[..depth].contains(&current) {
                return Err(RegistryError::AttachmentCycle);
            }
            if depth >= MAX_DEVICE_STACK_DEPTH {
                return Err(RegistryError::StackTooDeep);
            }
            visited[depth] = current;
            cursor = self.device(current)?.lower_device;
            depth += 1;
        }
        Ok(depth)
    }

    /// Captures a bounded top-to-bottom dispatch route.
    pub fn plan_stack(&self, top: DeviceId) -> Result<DeviceStack, RegistryError> {
        let mut result = DeviceStack::EMPTY;
        let mut cursor = Some(top);
        while let Some(current) = cursor {
            let index = result.len();
            if result.devices[..index].contains(&current) {
                return Err(RegistryError::AttachmentCycle);
            }
            if index >= MAX_DEVICE_STACK_DEPTH {
                return Err(RegistryError::StackTooDeep);
            }
            let object = self.device(current)?;
            result.devices[index] = current;
            result.len += 1;
            cursor = object.lower_device;
        }
        Ok(result)
    }

    fn has_upper_attachment(&self, lower: DeviceId) -> bool {
        self.devices
            .iter()
            .any(|slot| slot.occupied && slot.object.lower_device == Some(lower))
    }
}

fn encode(index: usize, generation: u32) -> u32 {
    debug_assert!(index < MAX_ENCODED_OBJECTS);
    debug_assert!((1..=MAX_ISSUED_GENERATION).contains(&generation));
    (generation << INDEX_BITS) | (index as u32 + 1)
}

const fn decode(raw: u32) -> Option<(usize, u32)> {
    let slot = raw & INDEX_MASK;
    let generation = raw >> INDEX_BITS;
    if slot == 0 || generation == 0 || generation > MAX_ISSUED_GENERATION {
        return None;
    }
    Some(((slot - 1) as usize, generation))
}

fn retire_slot(generation: &mut u32, occupied: &mut bool, retired: &mut bool) {
    *occupied = false;
    if *generation == MAX_ISSUED_GENERATION {
        *retired = true;
    } else {
        *generation += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn driver() -> DriverObject {
        DriverObject::new(0x10_0000, 0x2000, 0x10_0100).unwrap()
    }

    #[test]
    fn final_driver_and_device_generations_retire_without_wrapping() {
        let mut registry = DriverRegistry::<1, 1>::try_new().unwrap();
        registry.drivers[0].generation = MAX_ISSUED_GENERATION;
        let owner = registry.register_driver(driver()).unwrap();
        registry.devices[0].generation = MAX_ISSUED_GENERATION;
        let device = registry.create_device(owner, None, 1, 0).unwrap();

        registry.remove_device(device).unwrap();
        assert_eq!(
            registry.create_device(owner, None, 1, 0),
            Err(RegistryError::TableFull)
        );
        registry.unregister_driver(owner).unwrap();
        assert_eq!(
            registry.register_driver(driver()),
            Err(RegistryError::TableFull)
        );
        assert_eq!(registry.driver(owner), Err(RegistryError::InvalidDriver));
        assert_eq!(registry.device(device), Err(RegistryError::InvalidDevice));
    }

    #[test]
    fn traversal_detects_a_corrupted_preexisting_cycle() {
        let mut registry = DriverRegistry::<1, 2>::try_new().unwrap();
        let owner = registry.register_driver(driver()).unwrap();
        let first = registry.create_device(owner, None, 1, 0).unwrap();
        let second = registry.create_device(owner, None, 1, 0).unwrap();
        let (first_index, _) = decode(first.raw()).unwrap();
        let (second_index, _) = decode(second.raw()).unwrap();
        registry.devices[first_index].object.lower_device = Some(second);
        registry.devices[second_index].object.lower_device = Some(first);

        assert_eq!(
            registry.stack_depth(first),
            Err(RegistryError::AttachmentCycle)
        );
        assert_eq!(
            registry.plan_stack(first),
            Err(RegistryError::AttachmentCycle)
        );
    }
}
