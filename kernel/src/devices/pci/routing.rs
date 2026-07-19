//! ACPI `_PRT`-backed PCI INTx routing with bounded bridge swizzling.

use alloc::string::String;

use super::enumerate::{PciDevice, PciHeaderKind};
use super::PciAddress;
use crate::acpi::aml::{AmlError, AmlValue, PciRoute, Resource};
use crate::mm::KVec;
use crate::sync::SpinLock;

const MAX_SWIZZLE_HOPS: usize = 32;
const PCI_BRIDGE_CLASS: u8 = 0x06;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FirmwareRoute {
    bus: u8,
    device: u8,
    function: Option<u8>,
    pin: u8,
    gsi: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ParentBridge {
    parent_bus: u8,
    device: u8,
    function: u8,
}

#[derive(Debug)]
struct RoutingDatabase {
    routes: KVec<FirmwareRoute>,
    parents: [Option<ParentBridge>; 256],
}

impl RoutingDatabase {
    const fn new() -> Self {
        Self {
            routes: KVec::new(),
            parents: [None; 256],
        }
    }

    fn clear(&mut self) {
        self.routes.clear();
        self.parents.fill(None);
    }

    fn lookup(&self, bus: u8, device: u8, function: u8, pin: u8) -> Option<u32> {
        let mut resolved = None;
        for route in &self.routes {
            if route.bus != bus
                || route.device != device
                || route.pin != pin
                || route.function.is_some_and(|expected| expected != function)
            {
                continue;
            }
            match resolved {
                Some(existing) if existing != route.gsi => return None,
                _ => resolved = Some(route.gsi),
            }
        }
        resolved
    }

    fn resolve(&self, device: &PciDevice) -> Option<u32> {
        let mut bus = device.address.bus();
        let mut slot = device.address.device();
        let mut function = device.address.function();
        let mut pin = device.interrupt_pin.checked_sub(1)?;
        if pin > 3 {
            return None;
        }
        let mut visited = [false; 256];
        for _ in 0..MAX_SWIZZLE_HOPS {
            if visited[usize::from(bus)] {
                return None;
            }
            visited[usize::from(bus)] = true;
            if let Some(gsi) = self.lookup(bus, slot, function, pin) {
                return Some(gsi);
            }
            let parent = self.parents[usize::from(bus)]?;
            // PCI-to-PCI bridge swizzle: a function at device D rotates its
            // INTA-D pin by D before appearing on the upstream bridge pin.
            pin = (pin + slot) & 3;
            bus = parent.parent_bus;
            slot = parent.device;
            function = parent.function;
        }
        None
    }
}

static ROUTING: SpinLock<RoutingDatabase> = SpinLock::new(RoutingDatabase::new());

/// Build the immutable-at-runtime routing database after PCI enumeration.
pub fn init(devices: &[PciDevice]) -> usize {
    let mut database = ROUTING.lock();
    database.clear();
    discover_parent_bridges(&mut database, devices);

    let paths = match crate::acpi::aml::pci_route_table_paths() {
        Ok(paths) => paths,
        Err(_) => return 0,
    };
    for path in paths {
        let bus = match table_bus(&path, devices) {
            Ok(Some(bus)) => bus,
            Ok(None) => continue,
            Err(error) => {
                ::log::debug!("pci.routing: skipped {path}: {error:?}");
                continue;
            },
        };
        let routes = match crate::acpi::aml::pci_routes(&path) {
            Ok(routes) => routes,
            Err(error) => {
                ::log::debug!("pci.routing: _PRT evaluation failed for {path}: {error}");
                continue;
            },
        };
        for route in routes {
            if let Some(route) = decode_route(bus, route) {
                database.routes.push(route);
            }
        }
    }
    let count = database.routes.len();
    if count != 0 {
        ::log::info!("pci.routing: loaded {count} validated ACPI _PRT route(s)");
    }
    count
}

/// Resolve one enumerated function's zero-based INT pin through ACPI and any
/// intervening PCI-to-PCI bridges.
#[must_use]
pub fn resolve_intx(device: &PciDevice) -> Option<u32> {
    ROUTING.lock().resolve(device)
}

fn discover_parent_bridges(database: &mut RoutingDatabase, devices: &[PciDevice]) {
    for device in devices {
        let Some(secondary) = secondary_bus(device) else {
            continue;
        };
        if secondary == 0 || secondary == device.address.bus() {
            continue;
        }
        let parent = ParentBridge {
            parent_bus: device.address.bus(),
            device: device.address.device(),
            function: device.address.function(),
        };
        let slot = &mut database.parents[usize::from(secondary)];
        match *slot {
            None => *slot = Some(parent),
            Some(existing) if existing == parent => {},
            Some(_) => {
                // Ambiguous firmware topology is unsafe to swizzle through.
                *slot = None;
            },
        }
    }
}

fn secondary_bus(device: &PciDevice) -> Option<u8> {
    if device.base_class != PCI_BRIDGE_CLASS
        || !matches!(device.header_kind, PciHeaderKind::Bridge)
        || !matches!(device.subclass, 0x04 | 0x07 | 0x09)
    {
        return None;
    }
    let address = canonical_address(device)?;
    Some((address.read32(0x18) >> 8) as u8)
}

fn canonical_address(device: &PciDevice) -> Option<PciAddress> {
    PciAddress::new(
        device.address.bus(),
        device.address.device(),
        device.address.function(),
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TableError {
    Aml(AmlError),
    InvalidInteger(&'static str),
    MissingBridge { bus: u8, address: u32 },
}

fn table_bus(path: &str, devices: &[PciDevice]) -> Result<Option<u8>, TableError> {
    let prefixes = path_prefixes(path);
    let mut first_addressed = None;
    let mut addresses = KVec::new();
    for (index, prefix) in prefixes.iter().enumerate() {
        if let Some(address) = optional_integer(prefix, "_ADR")? {
            first_addressed.get_or_insert(index);
            addresses.push((
                index,
                u32::try_from(address).map_err(|_| TableError::InvalidInteger("_ADR"))?,
            ));
        }
    }
    let anchor_end = first_addressed.unwrap_or(prefixes.len());
    let mut segment = 0u16;
    let mut bus = 0u8;
    for prefix in &prefixes[..anchor_end] {
        if let Some(value) = optional_integer(prefix, "_SEG")? {
            segment = u16::try_from(value).map_err(|_| TableError::InvalidInteger("_SEG"))?;
        }
        if let Some(value) = optional_integer(prefix, "_BBN")? {
            bus = u8::try_from(value).map_err(|_| TableError::InvalidInteger("_BBN"))?;
        }
    }
    if segment != 0 {
        return Ok(None);
    }
    for (_, address) in addresses {
        let device_number = (address >> 16) as u16;
        let function = address as u16;
        if device_number >= 32 || function >= 8 {
            return Err(TableError::InvalidInteger("_ADR"));
        }
        let bridge = devices.iter().find(|device| {
            device.address.bus() == bus
                && u16::from(device.address.device()) == device_number
                && u16::from(device.address.function()) == function
        });
        let Some(secondary) = bridge.and_then(secondary_bus) else {
            return Err(TableError::MissingBridge { bus, address });
        };
        bus = secondary;
    }
    Ok(Some(bus))
}

fn path_prefixes(path: &str) -> KVec<String> {
    let mut prefixes = KVec::new();
    let mut current = String::from("\\");
    for segment in path.trim_start_matches('\\').split('.') {
        if segment.is_empty() {
            continue;
        }
        if current.len() > 1 {
            current.push('.');
        }
        current.push_str(segment);
        prefixes.push(current.clone());
    }
    prefixes
}

fn optional_integer(prefix: &str, name: &'static str) -> Result<Option<u64>, TableError> {
    let path = alloc::format!("{prefix}.{name}");
    match crate::acpi::aml::evaluate(&path, &[]) {
        Ok(AmlValue::Integer(value)) => Ok(Some(value)),
        Ok(_) => Err(TableError::InvalidInteger(name)),
        Err(AmlError::NotFound(_)) => Ok(None),
        Err(error) => Err(TableError::Aml(error)),
    }
}

fn decode_route(bus: u8, route: PciRoute) -> Option<FirmwareRoute> {
    let device = u16::try_from((route.address >> 16) & 0xffff).ok()?;
    let raw_function = u16::try_from(route.address & 0xffff).ok()?;
    if device >= 32 || route.pin > 3 {
        return None;
    }
    let function = match raw_function {
        0xffff => None,
        value if value < 8 => Some(value as u8),
        _ => return None,
    };
    let gsi = match route.source {
        None => route.source_index,
        Some(source) => resolve_link_gsi(&source, route.source_index)?,
    };
    Some(FirmwareRoute {
        bus,
        device: device as u8,
        function,
        pin: route.pin,
        gsi,
    })
}

fn resolve_link_gsi(path: &str, source_index: u32) -> Option<u32> {
    let resources = crate::acpi::aml::current_resources(path).ok()?;
    if let Some(resource) = usize::try_from(source_index)
        .ok()
        .and_then(|index| resources.get(index))
    {
        if let Some(gsi) = resource_gsi(resource) {
            return Some(gsi);
        }
    }
    // Link-device _CRS buffers commonly wrap their one IRQ in dependent
    // descriptors while `_PRT.SourceIndex` remains zero. Accept exactly one
    // unambiguous IRQ across the full template, never guess among choices.
    let mut resolved = None;
    for resource in &resources {
        let Some(gsi) = resource_gsi(resource) else {
            continue;
        };
        match resolved {
            Some(existing) if existing != gsi => return None,
            _ => resolved = Some(gsi),
        }
    }
    resolved
}

fn resource_gsi(resource: &Resource) -> Option<u32> {
    match resource {
        Resource::Irq { mask, .. } if mask.count_ones() == 1 => Some(mask.trailing_zeros()),
        Resource::ExtendedIrq { interrupts, .. } if interrupts.len() == 1 => {
            interrupts.first().copied()
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(bus: u8, device: u8, function: Option<u8>, pin: u8, gsi: u32) -> FirmwareRoute {
        FirmwareRoute {
            bus,
            device,
            function,
            pin,
            gsi,
        }
    }

    #[test]
    fn lookup_prefers_no_route_over_conflicting_firmware_entries() {
        let mut database = RoutingDatabase::new();
        database.routes.push(route(0, 2, None, 0, 16));
        assert_eq!(database.lookup(0, 2, 3, 0), Some(16));
        database.routes.push(route(0, 2, Some(3), 0, 17));
        assert_eq!(database.lookup(0, 2, 3, 0), None);
    }

    #[test]
    fn bridge_swizzling_rotates_each_downstream_slot() {
        let mut database = RoutingDatabase::new();
        database.parents[2] = Some(ParentBridge {
            parent_bus: 1,
            device: 5,
            function: 0,
        });
        database.parents[1] = Some(ParentBridge {
            parent_bus: 0,
            device: 1,
            function: 0,
        });
        // Bus-2 device 3 INTA -> pin D on bus 1; bridge device 5 rotates D
        // back to pin A at root device 1.
        database.routes.push(route(0, 1, None, 0, 19));
        let mut device = test_device(2, 3, 0, 1);
        assert_eq!(database.resolve(&device), Some(19));
        device.interrupt_pin = 0;
        assert_eq!(database.resolve(&device), None);
    }

    #[test]
    fn path_prefixes_are_canonical_and_ordered() {
        assert_eq!(path_prefixes("\\_SB_.PCI0.RP01"), [
            "\\_SB_",
            "\\_SB_.PCI0",
            "\\_SB_.PCI0.RP01"
        ]);
    }

    #[test]
    fn irq_resources_must_be_unambiguous() {
        assert_eq!(
            resource_gsi(&Resource::Irq {
                mask: 1 << 11,
                flags: 0
            }),
            Some(11)
        );
        assert_eq!(
            resource_gsi(&Resource::Irq {
                mask: (1 << 10) | (1 << 11),
                flags: 0
            }),
            None
        );
    }

    fn test_device(bus: u8, device: u8, function: u8, pin: u8) -> PciDevice {
        PciDevice {
            address: super::super::enumerate::PciAddress::new_unchecked(bus, device, function),
            vendor_id: 0x1234,
            device_id: 0x5678,
            revision: 0,
            prog_if: 0,
            subclass: 0,
            base_class: 2,
            header_kind: PciHeaderKind::Device,
            multifunction: false,
            bars: [0; 6],
            interrupt_line: 11,
            interrupt_pin: pin,
        }
    }
}
