//! Values exchanged by the AML namespace and evaluator.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Runtime AML value. The interpreter deliberately keeps references as
/// canonical namespace paths instead of exposing pointers into its map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AmlValue {
    Uninitialized,
    Integer(u64),
    String(String),
    Buffer(Vec<u8>),
    Package(Vec<AmlValue>),
    Reference(String),
}

impl AmlValue {
    pub fn as_integer(&self) -> Option<u64> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    pub fn truthy(&self) -> bool {
        match self {
            Self::Uninitialized => false,
            Self::Integer(value) => *value != 0,
            Self::String(value) => !value.is_empty(),
            Self::Buffer(value) => value.iter().any(|byte| *byte != 0),
            Self::Package(value) => !value.is_empty(),
            Self::Reference(_) => true,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::Uninitialized | Self::Integer(_) | Self::Reference(_) => 0,
            Self::String(value) => value.len(),
            Self::Buffer(value) => value.len(),
            Self::Package(value) => value.len(),
        }
    }
}

/// Decoded ACPI `_STA` bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceStatus {
    pub raw: u64,
    pub present: bool,
    pub enabled: bool,
    pub visible: bool,
    pub functioning: bool,
    pub battery_present: bool,
}

impl DeviceStatus {
    pub const DEFAULT: Self = Self::from_raw(0x0f);

    pub const fn from_raw(raw: u64) -> Self {
        Self {
            raw,
            present: raw & 1 != 0,
            enabled: raw & 2 != 0,
            visible: raw & 4 != 0,
            functioning: raw & 8 != 0,
            battery_present: raw & 16 != 0,
        }
    }
}

/// A decoded `_CRS` resource descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resource {
    Irq {
        mask: u16,
        flags: u8,
    },
    ExtendedIrq {
        flags: u8,
        interrupts: Vec<u32>,
    },
    Dma {
        channels: u8,
        flags: u8,
    },
    IoPort {
        decode_16: bool,
        minimum: u16,
        maximum: u16,
        alignment: u8,
        length: u8,
    },
    FixedIoPort {
        base: u16,
        length: u8,
    },
    Memory {
        writable: bool,
        minimum: u64,
        maximum: u64,
        alignment: u64,
        length: u64,
    },
    AddressSpace {
        resource_type: u8,
        flags: u8,
        type_flags: u8,
        granularity: u64,
        minimum: u64,
        maximum: u64,
        translation: u64,
        length: u64,
    },
    GenericRegister {
        address_space: u8,
        bit_width: u8,
        bit_offset: u8,
        access_size: u8,
        address: u64,
    },
    StartDependent {
        priority: Option<u8>,
    },
    EndDependent,
    Vendor(Vec<u8>),
}

/// One routing entry returned by a PCI root bridge's `_PRT` method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciRoute {
    pub address: u64,
    pub pin: u8,
    /// Canonical link-device path, or `None` for a hard-wired GSI.
    pub source: Option<String>,
    pub source_index: u32,
}
