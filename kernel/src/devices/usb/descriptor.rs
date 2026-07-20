//! Allocation-free parsing for the USB descriptors needed by boot HID.
//!
//! The parser deliberately accepts only configuration descriptor streams and
//! extracts alternate-setting-zero HID interfaces that advertise the USB HID
//! boot subclass.  It does not pretend to be a general USB class framework:
//! hubs, isochronous endpoints, report-descriptor interpretation, and vendor
//! protocols remain outside this layer.

/// USB descriptor type for a device descriptor.
pub const DESCRIPTOR_DEVICE: u8 = 1;
/// USB descriptor type for a configuration descriptor.
pub const DESCRIPTOR_CONFIGURATION: u8 = 2;
/// USB descriptor type for an interface descriptor.
pub const DESCRIPTOR_INTERFACE: u8 = 4;
/// USB descriptor type for an endpoint descriptor.
pub const DESCRIPTOR_ENDPOINT: u8 = 5;

const CLASS_HID: u8 = 3;
const HID_BOOT_SUBCLASS: u8 = 1;
const HID_BOOT_KEYBOARD: u8 = 1;
const HID_BOOT_MOUSE: u8 = 2;
const TRANSFER_INTERRUPT: u8 = 3;

/// Maximum number of boot-HID interfaces accepted from one configuration.
///
/// Four covers composite keyboard/mouse/media devices while keeping endpoint
/// and decoder storage statically bounded.
pub const MAX_BOOT_INTERFACES: usize = 4;

/// Boot protocol selected by an interface descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootProtocol {
    /// Eight-byte HID boot keyboard reports.
    Keyboard,
    /// Three-byte HID boot mouse reports (optional trailing wheel/buttons are
    /// consumed when a device supplies them).
    Mouse,
}

/// One interrupt-IN boot-HID function extracted from a configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootInterface {
    /// Interface number used by SET_PROTOCOL and SET_IDLE.
    pub interface_number: u8,
    /// HID boot protocol advertised by `bInterfaceProtocol`.
    pub protocol: BootProtocol,
    /// Full endpoint address, including the IN direction bit.
    pub endpoint_address: u8,
    /// Maximum payload bytes per service opportunity.
    pub max_packet_size: u16,
    /// Additional high-speed transactions encoded by wMaxPacketSize.
    pub transactions_per_microframe: u8,
    /// Raw USB bInterval value; the xHCI layer converts it by device speed.
    pub interval: u8,
}

/// Bounded result of parsing one configuration descriptor stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootConfiguration {
    /// Value supplied to the standard SET_CONFIGURATION request.
    pub configuration_value: u8,
    interfaces: [Option<BootInterface>; MAX_BOOT_INTERFACES],
    len: usize,
}

impl BootConfiguration {
    /// Boot-HID interfaces in descriptor order.
    pub fn interfaces(&self) -> impl Iterator<Item = BootInterface> + '_ {
        self.interfaces[..self.len].iter().flatten().copied()
    }

    /// Number of accepted boot-HID interfaces.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the configuration contains no supported boot-HID interface.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Descriptor validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    /// The supplied byte slice cannot contain the descriptor header.
    Truncated,
    /// A descriptor has an invalid length or a configuration header is wrong.
    Malformed,
    /// A supported interface advertises an invalid interrupt endpoint.
    InvalidEndpoint,
    /// More supported HID interfaces were present than the fixed bound.
    TooManyBootInterfaces,
}

/// Validate a USB device descriptor and return its EP0 maximum-packet byte.
pub fn device_ep0_packet_byte(bytes: &[u8]) -> Result<u8, DescriptorError> {
    if bytes.len() < 8 {
        return Err(DescriptorError::Truncated);
    }
    if bytes[0] < 8 || bytes[1] != DESCRIPTOR_DEVICE {
        return Err(DescriptorError::Malformed);
    }
    Ok(bytes[7])
}

/// Read `wTotalLength` from a configuration descriptor header.
pub fn configuration_total_length(bytes: &[u8]) -> Result<usize, DescriptorError> {
    if bytes.len() < 9 {
        return Err(DescriptorError::Truncated);
    }
    if bytes[0] < 9 || bytes[1] != DESCRIPTOR_CONFIGURATION {
        return Err(DescriptorError::Malformed);
    }
    let total = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    if total < 9 {
        return Err(DescriptorError::Malformed);
    }
    Ok(total)
}

/// Parse the boot-HID interfaces and interrupt-IN endpoints in a complete
/// configuration descriptor stream.
///
/// Unknown descriptors are skipped using their declared `bLength`.  A HID
/// interface is committed only after a valid interrupt-IN endpoint is seen,
/// so malformed or output-only interfaces never reach xHCI configuration.
pub fn parse_boot_configuration(bytes: &[u8]) -> Result<BootConfiguration, DescriptorError> {
    let total = configuration_total_length(bytes)?;
    if total > bytes.len() {
        return Err(DescriptorError::Truncated);
    }

    let mut result = BootConfiguration {
        configuration_value: bytes[5],
        interfaces: [None; MAX_BOOT_INTERFACES],
        len: 0,
    };
    if result.configuration_value == 0 {
        return Err(DescriptorError::Malformed);
    }

    #[derive(Clone, Copy)]
    struct Candidate {
        interface_number: u8,
        protocol: BootProtocol,
    }

    let mut candidate: Option<Candidate> = None;
    let mut offset = 0usize;
    while offset < total {
        if total - offset < 2 {
            return Err(DescriptorError::Truncated);
        }
        let length = usize::from(bytes[offset]);
        let descriptor_type = bytes[offset + 1];
        if length < 2 {
            return Err(DescriptorError::Malformed);
        }
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= total)
            .ok_or(DescriptorError::Truncated)?;
        let descriptor = &bytes[offset..end];

        match descriptor_type {
            DESCRIPTOR_INTERFACE => {
                if descriptor.len() < 9 {
                    return Err(DescriptorError::Malformed);
                }
                candidate = if descriptor[3] == 0
                    && descriptor[5] == CLASS_HID
                    && descriptor[6] == HID_BOOT_SUBCLASS
                {
                    let protocol = match descriptor[7] {
                        HID_BOOT_KEYBOARD => Some(BootProtocol::Keyboard),
                        HID_BOOT_MOUSE => Some(BootProtocol::Mouse),
                        _ => None,
                    };
                    protocol.map(|protocol| Candidate {
                        interface_number: descriptor[2],
                        protocol,
                    })
                } else {
                    None
                };
            },
            DESCRIPTOR_ENDPOINT => {
                let Some(interface) = candidate else {
                    offset = end;
                    continue;
                };
                if descriptor.len() < 7 {
                    return Err(DescriptorError::Malformed);
                }
                let address = descriptor[2];
                let attributes = descriptor[3];
                if address & 0x80 == 0
                    || address & 0x0f == 0
                    || attributes & 0x03 != TRANSFER_INTERRUPT
                {
                    offset = end;
                    continue;
                }
                let raw_packet = u16::from_le_bytes([descriptor[4], descriptor[5]]);
                let max_packet_size = raw_packet & 0x07ff;
                let additional_transactions = ((raw_packet >> 11) & 0x03) as u8;
                if max_packet_size == 0 || additional_transactions == 3 || descriptor[6] == 0 {
                    return Err(DescriptorError::InvalidEndpoint);
                }
                if result.len == MAX_BOOT_INTERFACES {
                    return Err(DescriptorError::TooManyBootInterfaces);
                }
                result.interfaces[result.len] = Some(BootInterface {
                    interface_number: interface.interface_number,
                    protocol: interface.protocol,
                    endpoint_address: address,
                    max_packet_size,
                    transactions_per_microframe: additional_transactions + 1,
                    interval: descriptor[6],
                });
                result.len += 1;
                // A boot interface needs only one interrupt-IN endpoint. Do
                // not accidentally configure a second vendor endpoint from
                // the same interface as another keyboard/mouse function.
                candidate = None;
            },
            _ => {},
        }

        offset = end;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYBOARD_CONFIG: [u8; 34] = [
        9, 2, 34, 0, 1, 7, 0, 0x80, 50, // configuration
        9, 4, 2, 0, 1, 3, 1, 1, 0, // boot-keyboard interface
        9, 0x21, 0x11, 0x01, 0, 1, 0x22, 63, 0, // HID descriptor
        7, 5, 0x81, 3, 8, 0, 10, // interrupt IN
    ];

    #[test]
    fn parses_boot_keyboard_through_unknown_hid_descriptor() {
        let parsed = parse_boot_configuration(&KEYBOARD_CONFIG).unwrap();
        assert_eq!(parsed.configuration_value, 7);
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed.interfaces().next(),
            Some(BootInterface {
                interface_number: 2,
                protocol: BootProtocol::Keyboard,
                endpoint_address: 0x81,
                max_packet_size: 8,
                transactions_per_microframe: 1,
                interval: 10,
            })
        );
    }

    #[test]
    fn ignores_non_boot_and_output_endpoints() {
        let mut bytes = KEYBOARD_CONFIG;
        bytes[15] = 0; // interface subclass is not boot
        let parsed = parse_boot_configuration(&bytes).unwrap();
        assert!(parsed.is_empty());

        let mut bytes = KEYBOARD_CONFIG;
        bytes[29] = 0x01; // endpoint is OUT
        let parsed = parse_boot_configuration(&bytes).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn rejects_truncation_zero_lengths_and_invalid_endpoint_payloads() {
        assert_eq!(
            parse_boot_configuration(&KEYBOARD_CONFIG[..20]),
            Err(DescriptorError::Truncated)
        );
        let mut zero_length = KEYBOARD_CONFIG;
        zero_length[9] = 0;
        assert_eq!(
            parse_boot_configuration(&zero_length),
            Err(DescriptorError::Malformed)
        );
        let mut zero_packet = KEYBOARD_CONFIG;
        zero_packet[31] = 0;
        assert_eq!(
            parse_boot_configuration(&zero_packet),
            Err(DescriptorError::InvalidEndpoint)
        );
    }

    #[test]
    fn validates_device_and_configuration_headers() {
        assert_eq!(device_ep0_packet_byte(&[18, 1, 0, 2, 0, 0, 0, 64]), Ok(64));
        assert_eq!(
            device_ep0_packet_byte(&[7, 1, 0, 0, 0, 0, 0, 8]),
            Err(DescriptorError::Malformed)
        );
        assert_eq!(configuration_total_length(&KEYBOARD_CONFIG), Ok(34));
    }
}
