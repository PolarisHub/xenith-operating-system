//! Canonical device-driver registration surface.
//!
//! PCI enumeration and binding are implemented together in
//! [`super::pci::enumerate`]. Keeping this compatibility namespace as pure
//! re-exports gives kernel drivers one discoverable import path without a
//! second device record, registry, or bind lifecycle that boot never calls.
//!
//! Non-PCI named devices use [`super::registry`]; PCI drivers implement
//! [`PciDriver`], register before the bus scan, and receive the same
//! [`PciDevice`] record produced by enumeration.

pub use super::pci::enumerate::{
    enumerate_and_bind, enumerate_bus, probe_devices, register_driver, PciBarInfo, PciBarKind,
    PciClassCode, PciDevice, PciDriver, PciDriverError, PciHeaderKind,
};
