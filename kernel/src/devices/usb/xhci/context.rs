//! xHCI input/device context construction.
//!
//! Context fields follow xHCI 1.2 sections 6.2.2-6.2.5.  The controller may
//! select 32- or 64-byte contexts through HCCPARAMS1.CSZ; this writer handles
//! both without relying on Rust struct padding or unaligned references.

/// The xHCI Device Context Index for endpoint zero.
pub const EP0_DCI: u8 = 1;

/// Hardware-selected context stride.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextSize {
    Bytes32,
    Bytes64,
}

impl ContextSize {
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Bytes32 => 32,
            Self::Bytes64 => 64,
        }
    }

    /// Output device context contains one slot plus 31 endpoint contexts.
    #[must_use]
    pub const fn output_bytes(self) -> usize {
        self.bytes() * 32
    }

    /// Input context adds one Input Control Context before the device context.
    #[must_use]
    pub const fn input_bytes(self) -> usize {
        self.bytes() * 33
    }
}

/// Endpoint type encoding from xHCI table 6-8.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointType {
    Control = 4,
    InterruptIn = 7,
}

/// Fields used to create one endpoint context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointContext {
    pub endpoint_type: EndpointType,
    pub dequeue_pointer: u64,
    pub max_packet_size: u16,
    pub max_burst_size: u8,
    pub mult: u8,
    pub interval: u8,
    pub average_trb_length: u16,
    pub max_esit_payload: u32,
}

/// Validated mutable writer over one xHCI input context.
pub struct InputContext<'a> {
    bytes: &'a mut [u8],
    size: ContextSize,
}

impl<'a> InputContext<'a> {
    /// Clear and wrap a buffer of exactly the size required by `size`.
    pub fn new(bytes: &'a mut [u8], size: ContextSize) -> Option<Self> {
        if bytes.len() < size.input_bytes() {
            return None;
        }
        bytes[..size.input_bytes()].fill(0);
        Some(Self { bytes, size })
    }

    /// Set Drop Context and Add Context flags in the input-control context.
    pub fn set_control_flags(&mut self, drop_flags: u32, add_flags: u32) {
        self.write_context_dword(0, 0, drop_flags);
        self.write_context_dword(0, 1, add_flags);
    }

    /// Populate the input Slot Context for a directly attached root-port
    /// device. Route String and TT fields remain zero because hubs are not
    /// supported by this bounded layer.
    pub fn set_slot(&mut self, speed: u8, root_port: u8, context_entries: u8) {
        let entries = u32::from(context_entries.clamp(1, 31));
        self.write_context_dword(1, 0, (u32::from(speed & 0x0f) << 20) | (entries << 27));
        self.write_context_dword(1, 1, u32::from(root_port) << 16);
    }

    /// Populate an endpoint context at a valid DCI (1..=31).
    pub fn set_endpoint(&mut self, dci: u8, endpoint: EndpointContext) -> Option<()> {
        if !(1..=31).contains(&dci)
            || endpoint.dequeue_pointer & 0x0f != 0
            || endpoint.max_packet_size == 0
            || endpoint.mult > 2
        {
            return None;
        }
        // Input context index 0 is the ICC, index 1 the slot, and endpoint
        // DCI n occupies input-context index n+1.
        let index = usize::from(dci) + 1;
        let esit = endpoint.max_esit_payload.min(0x00ff_ffff);
        self.write_context_dword(
            index,
            0,
            (u32::from(endpoint.mult) << 8)
                | (u32::from(endpoint.interval & 0x0f) << 16)
                | ((esit >> 16) << 24),
        );
        self.write_context_dword(
            index,
            1,
            (3 << 1)
                | ((endpoint.endpoint_type as u32) << 3)
                | (u32::from(endpoint.max_burst_size) << 8)
                | (u32::from(endpoint.max_packet_size) << 16),
        );
        let dequeue = endpoint.dequeue_pointer | 1; // DCS = producer cycle 1
        self.write_context_dword(index, 2, dequeue as u32);
        self.write_context_dword(index, 3, (dequeue >> 32) as u32);
        self.write_context_dword(
            index,
            4,
            u32::from(endpoint.average_trb_length) | ((esit & 0xffff) << 16),
        );
        Some(())
    }

    fn write_context_dword(&mut self, context_index: usize, dword: usize, value: u32) {
        let offset = context_index * self.size.bytes() + dword * 4;
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}

/// Translate a USB endpoint address into xHCI's Device Context Index.
#[must_use]
pub const fn endpoint_dci(endpoint_address: u8) -> Option<u8> {
    let number = endpoint_address & 0x0f;
    if number == 0 {
        return None;
    }
    let direction_in = (endpoint_address >> 7) & 1;
    Some(number * 2 + direction_in)
}

/// Convert USB bInterval into xHCI's exponent encoding.
///
/// Speed IDs are xHCI defaults: 1=full, 2=low, 3=high, 4/5=SuperSpeed.
#[must_use]
pub fn interval_for_speed(speed: u8, interval: u8) -> Option<u8> {
    if interval == 0 {
        return None;
    }
    match speed {
        1 | 2 => Some(ceil_log2(interval).saturating_add(3).min(15)),
        3..=5 => Some(interval.clamp(1, 16) - 1),
        _ => None,
    }
}

fn ceil_log2(value: u8) -> u8 {
    let mut exponent = 0u8;
    let mut power = 1u16;
    while power < value as u16 {
        power <<= 1;
        exponent += 1;
    }
    exponent
}

/// EP0 packet size used before the first device-descriptor read.
#[must_use]
pub const fn initial_ep0_packet_size(speed: u8) -> Option<u16> {
    match speed {
        1 | 2 => Some(8),
        3 => Some(64),
        4 | 5 => Some(512),
        _ => None,
    }
}

/// Decode bMaxPacketSize0 for the enumerated speed.
#[must_use]
pub const fn descriptor_ep0_packet_size(speed: u8, encoded: u8) -> Option<u16> {
    match speed {
        1 => match encoded {
            8 | 16 | 32 | 64 => Some(encoded as u16),
            _ => None,
        },
        2 => match encoded {
            8 => Some(8),
            _ => None,
        },
        3 => match encoded {
            64 => Some(64),
            _ => None,
        },
        4 | 5 if encoded >= 3 && encoded <= 10 => Some(1u16 << encoded),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dword(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn writes_32_and_64_byte_context_layouts() {
        for size in [ContextSize::Bytes32, ContextSize::Bytes64] {
            let mut bytes = [0xa5; 33 * 64];
            let mut input = InputContext::new(&mut bytes, size).unwrap();
            input.set_control_flags(0, 0b11);
            input.set_slot(3, 4, 3);
            input
                .set_endpoint(3, EndpointContext {
                    endpoint_type: EndpointType::InterruptIn,
                    dequeue_pointer: 0x1234_5000,
                    max_packet_size: 8,
                    max_burst_size: 0,
                    mult: 0,
                    interval: 7,
                    average_trb_length: 8,
                    max_esit_payload: 8,
                })
                .unwrap();
            let stride = size.bytes();
            assert_eq!(dword(&bytes, 4), 3);
            assert_eq!((dword(&bytes, stride) >> 20) & 0xf, 3);
            assert_eq!((dword(&bytes, stride) >> 27) & 0x1f, 3);
            assert_eq!((dword(&bytes, stride + 4) >> 16) & 0xff, 4);
            let endpoint = 4 * stride;
            assert_eq!((dword(&bytes, endpoint + 4) >> 3) & 7, 7);
            assert_eq!(dword(&bytes, endpoint + 8), 0x1234_5001);
        }
    }

    #[test]
    fn converts_endpoint_indices_and_intervals() {
        assert_eq!(endpoint_dci(0x81), Some(3));
        assert_eq!(endpoint_dci(0x02), Some(4));
        assert_eq!(endpoint_dci(0), None);
        assert_eq!(interval_for_speed(1, 10), Some(7));
        assert_eq!(interval_for_speed(3, 4), Some(3));
        assert_eq!(interval_for_speed(4, 255), Some(15));
        assert_eq!(interval_for_speed(3, 0), None);
    }

    #[test]
    fn validates_ep0_packet_sizes_by_speed() {
        assert_eq!(initial_ep0_packet_size(1), Some(8));
        assert_eq!(initial_ep0_packet_size(4), Some(512));
        assert_eq!(descriptor_ep0_packet_size(1, 32), Some(32));
        assert_eq!(descriptor_ep0_packet_size(2, 64), None);
        assert_eq!(descriptor_ep0_packet_size(4, 9), Some(512));
    }
}
