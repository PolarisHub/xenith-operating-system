//! Bounded conventional PCI capability-list parsing and MSI metadata.

use super::{PciAddress, PciHeaderType};

pub const CAP_ID_MSI: u8 = 0x05;
pub const CAP_ID_MSIX: u8 = 0x11;
pub const MAX_CAPABILITIES: usize = 48;

const STATUS_CAPABILITIES_LIST: u16 = 1 << 4;
const TYPE0_CAP_POINTER: u8 = 0x34;
const CARDBUS_CAP_POINTER: u8 = 0x14;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PciCapability {
    pub id: u8,
    pub offset: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityError {
    InvalidPointer(u8),
    Loop(u8),
    TooMany,
    WrongCapability,
    Truncated,
    InvalidBir(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityList {
    entries: [PciCapability; MAX_CAPABILITIES],
    len: usize,
}

impl CapabilityList {
    const fn new() -> Self {
        Self {
            entries: [PciCapability { id: 0, offset: 0 }; MAX_CAPABILITIES],
            len: 0,
        }
    }

    #[must_use]
    pub fn iter(&self) -> impl Iterator<Item = PciCapability> + '_ {
        self.entries[..self.len].iter().copied()
    }

    #[must_use]
    pub fn find(&self, id: u8) -> Option<PciCapability> {
        self.iter().find(|capability| capability.id == id)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Walk the conventional 256-byte capability list with loop and range checks.
pub fn walk(address: PciAddress) -> Result<CapabilityList, CapabilityError> {
    if address.read_status() & STATUS_CAPABILITIES_LIST == 0 {
        return Ok(CapabilityList::new());
    }
    let pointer_register = match address.read_header_type() {
        PciHeaderType::CardbusBridge => CARDBUS_CAP_POINTER,
        _ => TYPE0_CAP_POINTER,
    };
    walk_from(address.read8(pointer_register), |offset| {
        address.read8(offset)
    })
}

fn valid_pointer(pointer: u8) -> bool {
    (0x40..=0xfc).contains(&pointer) && pointer & 3 == 0
}

fn walk_from(
    mut pointer: u8,
    mut read8: impl FnMut(u8) -> u8,
) -> Result<CapabilityList, CapabilityError> {
    let mut list = CapabilityList::new();
    let mut visited = [false; 256];
    while pointer != 0 {
        if !valid_pointer(pointer) {
            return Err(CapabilityError::InvalidPointer(pointer));
        }
        if visited[usize::from(pointer)] {
            return Err(CapabilityError::Loop(pointer));
        }
        if list.len == MAX_CAPABILITIES {
            return Err(CapabilityError::TooMany);
        }
        visited[usize::from(pointer)] = true;
        list.entries[list.len] = PciCapability {
            id: read8(pointer),
            offset: pointer,
        };
        list.len += 1;
        pointer = read8(pointer + 1);
    }
    Ok(list)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsiCapability {
    pub offset: u8,
    pub control: u16,
    pub address_low: u8,
    pub address_high: Option<u8>,
    pub message_data: u8,
    pub mask_bits: Option<u8>,
}

impl MsiCapability {
    pub fn read(address: PciAddress, capability: PciCapability) -> Result<Self, CapabilityError> {
        if capability.id != CAP_ID_MSI {
            return Err(CapabilityError::WrongCapability);
        }
        let control_offset = capability
            .offset
            .checked_add(2)
            .ok_or(CapabilityError::Truncated)?;
        let control = address.read16(control_offset);
        Self::from_control(capability.offset, control)
    }

    fn from_control(offset: u8, control: u16) -> Result<Self, CapabilityError> {
        let address_low = offset
            .checked_add(4)
            .filter(|value| *value <= 0xfc)
            .ok_or(CapabilityError::Truncated)?;
        let is_64_bit = control & (1 << 7) != 0;
        let address_high = if is_64_bit {
            Some(
                offset
                    .checked_add(8)
                    .filter(|value| *value <= 0xfc)
                    .ok_or(CapabilityError::Truncated)?,
            )
        } else {
            None
        };
        let message_data = offset
            .checked_add(if is_64_bit { 12 } else { 8 })
            .filter(|value| *value <= 0xfe)
            .ok_or(CapabilityError::Truncated)?;
        let mask_bits = if control & (1 << 8) != 0 {
            Some(
                offset
                    .checked_add(if is_64_bit { 16 } else { 12 })
                    .filter(|value| *value <= 0xfc)
                    .ok_or(CapabilityError::Truncated)?,
            )
        } else {
            None
        };
        Ok(Self {
            offset,
            control,
            address_low,
            address_high,
            message_data,
            mask_bits,
        })
    }

    pub fn disable(self, address: PciAddress) {
        address.write16(self.offset + 2, self.control & !1);
    }

    /// Program one fixed, edge-triggered message and enable exactly one vector.
    pub fn program_single(self, address: PciAddress, destination: u8, vector: u8) {
        self.disable(address);
        address.write32(
            self.address_low,
            0xfee0_0000 | (u32::from(destination) << 12),
        );
        if let Some(high) = self.address_high {
            address.write32(high, 0);
        }
        address.write16(self.message_data, u16::from(vector));
        if let Some(mask) = self.mask_bits {
            address.write32(mask, address.read32(mask) & !1);
        }
        // Clear Multiple Message Enable and set MSI Enable last, after every
        // message field and the driver's hard-IRQ binding are published.
        address.write16(self.offset + 2, (self.control & !(0b111 << 4)) | 1);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsixCapability {
    pub offset: u8,
    pub table_size: u16,
    pub enabled: bool,
    pub function_masked: bool,
    pub table_bir: u8,
    pub table_offset: u32,
    pub pba_bir: u8,
    pub pba_offset: u32,
}

impl MsixCapability {
    pub fn read(address: PciAddress, capability: PciCapability) -> Result<Self, CapabilityError> {
        if capability.id != CAP_ID_MSIX || capability.offset > 0xf4 {
            return Err(if capability.id == CAP_ID_MSIX {
                CapabilityError::Truncated
            } else {
                CapabilityError::WrongCapability
            });
        }
        Self::from_registers(
            capability.offset,
            address.read16(capability.offset + 2),
            address.read32(capability.offset + 4),
            address.read32(capability.offset + 8),
        )
    }

    fn from_registers(
        offset: u8,
        control: u16,
        table: u32,
        pba: u32,
    ) -> Result<Self, CapabilityError> {
        let table_bir = table as u8 & 7;
        let pba_bir = pba as u8 & 7;
        if table_bir >= 6 {
            return Err(CapabilityError::InvalidBir(table_bir));
        }
        if pba_bir >= 6 {
            return Err(CapabilityError::InvalidBir(pba_bir));
        }
        Ok(Self {
            offset,
            table_size: (control & 0x7ff) + 1,
            enabled: control & (1 << 15) != 0,
            function_masked: control & (1 << 14) != 0,
            table_bir,
            table_offset: table & !7,
            pba_bir,
            pba_offset: pba & !7,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walker_is_bounded_and_detects_cycles() {
        let mut config = [0u8; 256];
        config[0x40] = CAP_ID_MSI;
        config[0x41] = 0x48;
        config[0x48] = CAP_ID_MSIX;
        let list = walk_from(0x40, |offset| config[usize::from(offset)]).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list.find(CAP_ID_MSIX).unwrap().offset, 0x48);
        config[0x49] = 0x40;
        assert_eq!(
            walk_from(0x40, |offset| config[usize::from(offset)]),
            Err(CapabilityError::Loop(0x40))
        );
    }

    #[test]
    fn walker_rejects_unaligned_and_header_space_pointers() {
        assert_eq!(
            walk_from(0x3c, |_| 0),
            Err(CapabilityError::InvalidPointer(0x3c))
        );
        assert_eq!(
            walk_from(0x42, |_| 0),
            Err(CapabilityError::InvalidPointer(0x42))
        );
    }

    #[test]
    fn msi_layout_handles_32_and_64_bit_forms() {
        let msi32 = MsiCapability::from_control(0x50, 0).unwrap();
        assert_eq!(msi32.address_high, None);
        assert_eq!(msi32.message_data, 0x58);
        let msi64 = MsiCapability::from_control(0x60, (1 << 7) | (1 << 8)).unwrap();
        assert_eq!(msi64.address_high, Some(0x68));
        assert_eq!(msi64.message_data, 0x6c);
        assert_eq!(msi64.mask_bits, Some(0x70));
    }

    #[test]
    fn msix_metadata_validates_bars_and_masks_offsets() {
        let decoded =
            MsixCapability::from_registers(0x70, (1 << 15) | 3, 0x1234_5002, 0x2001).unwrap();
        assert_eq!(decoded.table_size, 4);
        assert!(decoded.enabled);
        assert_eq!(decoded.table_bir, 2);
        assert_eq!(decoded.table_offset, 0x1234_5000);
        assert_eq!(decoded.pba_bir, 1);
        assert_eq!(decoded.pba_offset, 0x2000);
        assert_eq!(
            MsixCapability::from_registers(0x70, 0, 6, 0),
            Err(CapabilityError::InvalidBir(6))
        );
    }
}
