//! Operation-region access abstraction.
//!
//! AML itself is not allowed to issue arbitrary port or MMIO operations.
//! Platform code supplies a handler and can enforce an address whitelist.

extern crate alloc;

use alloc::sync::Arc;

use super::AmlError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionSpace {
    SystemMemory,
    SystemIo,
    PciConfig,
    EmbeddedControl,
    SmBus,
    Cmos,
    PciBarTarget,
    Ipmi,
    GeneralPurposeIo,
    GenericSerialBus,
    PlatformCommunicationsChannel,
    FunctionalFixedHardware,
    Oem(u8),
}

impl From<u8> for RegionSpace {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::SystemMemory,
            0x01 => Self::SystemIo,
            0x02 => Self::PciConfig,
            0x03 => Self::EmbeddedControl,
            0x04 => Self::SmBus,
            0x05 => Self::Cmos,
            0x06 => Self::PciBarTarget,
            0x07 => Self::Ipmi,
            0x08 => Self::GeneralPurposeIo,
            0x09 => Self::GenericSerialBus,
            0x0a => Self::PlatformCommunicationsChannel,
            0x7f => Self::FunctionalFixedHardware,
            value => Self::Oem(value),
        }
    }
}

pub trait RegionHandler: Send + Sync {
    /// Read one naturally addressed 8/16/32/64-bit region unit.
    fn read(&self, space: RegionSpace, address: u64, width: u8) -> Result<u64, AmlError>;

    /// Write one naturally addressed 8/16/32/64-bit region unit.
    fn write(
        &self,
        space: RegionSpace,
        address: u64,
        width: u8,
        value: u64,
    ) -> Result<(), AmlError>;
}

/// Default handler used during discovery. It makes region access fail closed
/// until platform code installs a policy-bearing backend.
pub struct DenyRegionHandler;

impl RegionHandler for DenyRegionHandler {
    fn read(&self, _: RegionSpace, _: u64, _: u8) -> Result<u64, AmlError> {
        Err(AmlError::RegionAccessDenied)
    }

    fn write(&self, _: RegionSpace, _: u64, _: u8, _: u64) -> Result<(), AmlError> {
        Err(AmlError::RegionAccessDenied)
    }
}

pub(crate) fn deny_handler() -> Arc<dyn RegionHandler> {
    Arc::new(DenyRegionHandler)
}
