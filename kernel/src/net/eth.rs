//! Ethernet-II frame parsing and construction.

use core::fmt;

use super::PacketError;

pub const HEADER_LEN: usize = 14;
pub const MIN_FRAME_LEN: usize = 60;
pub const MAX_PAYLOAD_LEN: usize = 1500;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const ZERO: Self = Self([0; 6]);
    pub const BROADCAST: Self = Self([0xff; 6]);

    #[must_use]
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0; 6]
    }

    #[must_use]
    pub fn is_broadcast(self) -> bool {
        self.0 == [0xff; 6]
    }

    #[must_use]
    pub const fn is_multicast(self) -> bool {
        self.0[0] & 1 != 0
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Ipv6 = 0x86dd,
    Vlan = 0x8100,
    Other(u16),
}

impl EtherType {
    #[must_use]
    pub const fn from_raw(value: u16) -> Self {
        match value {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86dd => Self::Ipv6,
            0x8100 => Self::Vlan,
            other => Self::Other(other),
        }
    }

    #[must_use]
    pub const fn raw(self) -> u16 {
        match self {
            Self::Ipv4 => 0x0800,
            Self::Arp => 0x0806,
            Self::Ipv6 => 0x86dd,
            Self::Vlan => 0x8100,
            Self::Other(value) => value,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EthernetFrame<'a> {
    pub destination: MacAddress,
    pub source: MacAddress,
    pub ethertype: EtherType,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < HEADER_LEN {
            return Err(PacketError::Truncated);
        }
        let destination = MacAddress(bytes[0..6].try_into().expect("six-byte slice"));
        let source = MacAddress(bytes[6..12].try_into().expect("six-byte slice"));
        let ethertype = EtherType::from_raw(u16::from_be_bytes([bytes[12], bytes[13]]));
        Ok(Self {
            destination,
            source,
            ethertype,
            payload: &bytes[HEADER_LEN..],
        })
    }

    pub fn write(
        output: &mut [u8],
        destination: MacAddress,
        source: MacAddress,
        ethertype: EtherType,
        payload: &[u8],
    ) -> Result<usize, PacketError> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(PacketError::Oversized);
        }
        let required = HEADER_LEN + payload.len();
        if output.len() < required {
            return Err(PacketError::BufferTooSmall);
        }
        output[..6].copy_from_slice(&destination.0);
        output[6..12].copy_from_slice(&source.0);
        output[12..14].copy_from_slice(&ethertype.raw().to_be_bytes());
        output[HEADER_LEN..required].copy_from_slice(payload);
        Ok(required)
    }
}
