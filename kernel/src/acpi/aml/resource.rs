//! Decoders for `_CRS` resource templates and PCI `_PRT` packages.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::value::{AmlValue, PciRoute, Resource};
use super::AmlError;

fn le16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn le64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn address_descriptor(data: &[u8], width: usize) -> Result<Resource, AmlError> {
    let required = 3 + width * 5;
    if data.len() < required {
        return Err(AmlError::MalformedResource);
    }
    let read = |offset: usize| -> u64 {
        match width {
            2 => u64::from(le16(&data[offset..offset + 2])),
            4 => u64::from(le32(&data[offset..offset + 4])),
            8 => le64(&data[offset..offset + 8]),
            _ => 0,
        }
    };
    Ok(Resource::AddressSpace {
        resource_type: data[0],
        flags: data[1],
        type_flags: data[2],
        granularity: read(3),
        minimum: read(3 + width),
        maximum: read(3 + width * 2),
        translation: read(3 + width * 3),
        length: read(3 + width * 4),
    })
}

pub fn decode_resources(bytes: &[u8]) -> Result<Vec<Resource>, AmlError> {
    const MAX_DESCRIPTORS: usize = 256;
    const MAX_VENDOR_BYTES: usize = 4096;

    let mut resources = Vec::new();
    let mut offset = 0usize;
    let mut ended = false;
    while offset < bytes.len() {
        if resources.len() >= MAX_DESCRIPTORS {
            return Err(AmlError::LimitExceeded("resource descriptors"));
        }
        let tag = bytes[offset];
        offset += 1;
        if tag & 0x80 == 0 {
            let kind = (tag >> 3) & 0x0f;
            let length = usize::from(tag & 0x07);
            let end = offset
                .checked_add(length)
                .ok_or(AmlError::MalformedResource)?;
            let data = bytes.get(offset..end).ok_or(AmlError::MalformedResource)?;
            offset = end;
            match kind {
                0x04 if data.len() == 2 || data.len() == 3 => resources.push(Resource::Irq {
                    mask: le16(data),
                    flags: data.get(2).copied().unwrap_or(0),
                }),
                0x05 if data.len() == 2 => resources.push(Resource::Dma {
                    channels: data[0],
                    flags: data[1],
                }),
                0x06 if data.len() <= 1 => resources.push(Resource::StartDependent {
                    priority: data.first().copied(),
                }),
                0x07 if data.is_empty() => resources.push(Resource::EndDependent),
                0x08 if data.len() == 7 => resources.push(Resource::IoPort {
                    decode_16: data[0] & 1 != 0,
                    minimum: le16(&data[1..3]),
                    maximum: le16(&data[3..5]),
                    alignment: data[5],
                    length: data[6],
                }),
                0x09 if data.len() == 3 => resources.push(Resource::FixedIoPort {
                    base: le16(&data[..2]),
                    length: data[2],
                }),
                0x0e if data.len() <= MAX_VENDOR_BYTES => {
                    resources.push(Resource::Vendor(data.to_vec()));
                },
                0x0f if data.len() == 1 => {
                    ended = true;
                    break;
                },
                _ => return Err(AmlError::MalformedResource),
            }
        } else {
            let kind = tag & 0x7f;
            let length_bytes = bytes
                .get(offset..offset + 2)
                .ok_or(AmlError::MalformedResource)?;
            let length = usize::from(le16(length_bytes));
            offset += 2;
            let end = offset
                .checked_add(length)
                .ok_or(AmlError::MalformedResource)?;
            let data = bytes.get(offset..end).ok_or(AmlError::MalformedResource)?;
            offset = end;
            match kind {
                0x01 if data.len() >= 9 => resources.push(Resource::Memory {
                    writable: data[0] & 1 != 0,
                    minimum: u64::from(le16(&data[1..3])) << 8,
                    maximum: u64::from(le16(&data[3..5])) << 8,
                    alignment: u64::from(le16(&data[5..7])),
                    length: u64::from(le16(&data[7..9])) << 8,
                }),
                0x02 if data.len() >= 12 => resources.push(Resource::GenericRegister {
                    address_space: data[0],
                    bit_width: data[1],
                    bit_offset: data[2],
                    access_size: data[3],
                    address: le64(&data[4..12]),
                }),
                0x04 if data.len() <= MAX_VENDOR_BYTES => {
                    resources.push(Resource::Vendor(data.to_vec()));
                },
                0x05 if data.len() >= 17 => resources.push(Resource::Memory {
                    writable: data[0] & 1 != 0,
                    minimum: u64::from(le32(&data[1..5])),
                    maximum: u64::from(le32(&data[5..9])),
                    alignment: u64::from(le32(&data[9..13])),
                    length: u64::from(le32(&data[13..17])),
                }),
                0x06 if data.len() >= 9 => {
                    let base = u64::from(le32(&data[1..5]));
                    let length = u64::from(le32(&data[5..9]));
                    resources.push(Resource::Memory {
                        writable: data[0] & 1 != 0,
                        minimum: base,
                        maximum: base.saturating_add(length.saturating_sub(1)),
                        alignment: 0,
                        length,
                    });
                },
                0x07 => resources.push(address_descriptor(data, 4)?),
                0x08 => resources.push(address_descriptor(data, 2)?),
                0x09 if data.len() >= 2 => {
                    let count = usize::from(data[1]);
                    let needed = 2usize
                        .checked_add(count.checked_mul(4).ok_or(AmlError::MalformedResource)?)
                        .ok_or(AmlError::MalformedResource)?;
                    if data.len() < needed || count > 64 {
                        return Err(AmlError::MalformedResource);
                    }
                    let mut interrupts = Vec::with_capacity(count);
                    for index in 0..count {
                        let start = 2 + index * 4;
                        interrupts.push(le32(&data[start..start + 4]));
                    }
                    resources.push(Resource::ExtendedIrq {
                        flags: data[0],
                        interrupts,
                    });
                },
                0x0a => resources.push(address_descriptor(data, 8)?),
                _ => return Err(AmlError::MalformedResource),
            }
        }
    }
    if !ended {
        return Err(AmlError::MalformedResource);
    }
    Ok(resources)
}

pub fn decode_prt(value: AmlValue) -> Result<Vec<PciRoute>, AmlError> {
    let AmlValue::Package(entries) = value else {
        return Err(AmlError::TypeMismatch("_PRT package"));
    };
    if entries.len() > 256 {
        return Err(AmlError::LimitExceeded("PCI routes"));
    }
    let mut routes = Vec::with_capacity(entries.len());
    for entry in entries {
        let AmlValue::Package(fields) = entry else {
            return Err(AmlError::InvalidRoute);
        };
        if fields.len() != 4 {
            return Err(AmlError::InvalidRoute);
        }
        let address = fields[0].as_integer().ok_or(AmlError::InvalidRoute)?;
        let pin = u8::try_from(fields[1].as_integer().ok_or(AmlError::InvalidRoute)?)
            .map_err(|_| AmlError::InvalidRoute)?;
        if pin > 3 {
            return Err(AmlError::InvalidRoute);
        }
        let source = match &fields[2] {
            AmlValue::Integer(0) => None,
            AmlValue::Reference(path) | AmlValue::String(path) => Some(String::from(path)),
            _ => return Err(AmlError::InvalidRoute),
        };
        let source_index = u32::try_from(fields[3].as_integer().ok_or(AmlError::InvalidRoute)?)
            .map_err(|_| AmlError::InvalidRoute)?;
        routes.push(PciRoute {
            address,
            pin,
            source,
            source_index,
        });
    }
    Ok(routes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_irq_io_and_end_tag() {
        let bytes = [
            0x22, 0x20, 0x00, // IRQ 5
            0x47, 0x01, 0xf8, 0x03, 0xf8, 0x03, 0x01, 0x08, // IO 0x3f8
            0x79, 0x00, // end tag
        ];
        let resources = decode_resources(&bytes).unwrap();
        assert_eq!(resources.len(), 2);
        assert!(matches!(resources[0], Resource::Irq { mask: 0x20, .. }));
    }

    #[test]
    fn rejects_missing_end_tag() {
        assert_eq!(
            decode_resources(&[0x22, 1, 0]),
            Err(AmlError::MalformedResource)
        );
    }
}
