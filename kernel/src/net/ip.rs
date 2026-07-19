//! IPv4 addresses, headers, prefix matching, and Internet checksums.

use core::fmt;

use super::PacketError;

pub const MIN_HEADER_LEN: usize = 20;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    pub const UNSPECIFIED: Self = Self([0, 0, 0, 0]);
    pub const BROADCAST: Self = Self([255, 255, 255, 255]);
    pub const LOOPBACK: Self = Self([127, 0, 0, 1]);

    #[must_use]
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self([a, b, c, d])
    }

    #[must_use]
    pub const fn octets(self) -> [u8; 4] {
        self.0
    }

    #[must_use]
    pub const fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self(value.to_be_bytes())
    }

    #[must_use]
    pub fn is_unspecified(self) -> bool {
        self.0 == [0; 4]
    }

    #[must_use]
    pub const fn is_loopback(self) -> bool {
        self.0[0] == 127
    }

    #[must_use]
    pub const fn is_multicast(self) -> bool {
        self.0[0] >= 224 && self.0[0] <= 239
    }

    #[must_use]
    pub const fn matches_prefix(self, network: Self, prefix_len: u8) -> bool {
        if prefix_len > 32 {
            return false;
        }
        let full_bytes = (prefix_len / 8) as usize;
        let remaining = prefix_len % 8;
        let mut index = 0;
        while index < full_bytes {
            if self.0[index] != network.0[index] {
                return false;
            }
            index += 1;
        }
        if remaining != 0 {
            let mask = u8::MAX << (8 - remaining);
            return self.0[full_bytes] & mask == network.0[full_bytes] & mask;
        }
        true
    }

    #[must_use]
    pub const fn masked(self, prefix_len: u8) -> Self {
        if prefix_len > 32 {
            return Self::UNSPECIFIED;
        }
        let mut bytes = self.0;
        let full_bytes = (prefix_len / 8) as usize;
        let remaining = prefix_len % 8;
        let mut index = full_bytes;
        if remaining != 0 {
            bytes[index] &= u8::MAX << (8 - remaining);
            index += 1;
        }
        while index < 4 {
            bytes[index] = 0;
            index += 1;
        }
        Self(bytes)
    }

    #[must_use]
    pub const fn subnet_broadcast(self, prefix_len: u8) -> Self {
        if prefix_len > 32 {
            return Self::BROADCAST;
        }
        let mut bytes = self.masked(prefix_len).0;
        let full_bytes = (prefix_len / 8) as usize;
        let remaining = prefix_len % 8;
        let mut index = full_bytes;
        if remaining != 0 {
            bytes[index] |= u8::MAX >> remaining;
            index += 1;
        }
        while index < 4 {
            bytes[index] = u8::MAX;
            index += 1;
        }
        Self(bytes)
    }
}

impl fmt::Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IpProtocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Other(u8),
}

impl IpProtocol {
    #[must_use]
    pub const fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            other => Self::Other(other),
        }
    }

    #[must_use]
    pub const fn raw(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Other(value) => value,
        }
    }
}

/// Incremental one's-complement checksum accumulator.
pub struct Checksum {
    sum: u32,
    odd: Option<u8>,
}

impl Checksum {
    #[must_use]
    pub const fn new() -> Self {
        Self { sum: 0, odd: None }
    }

    pub fn add(&mut self, mut bytes: &[u8]) {
        if let Some(high) = self.odd.take() {
            if let Some((&low, rest)) = bytes.split_first() {
                self.sum += u16::from_be_bytes([high, low]) as u32;
                bytes = rest;
            } else {
                self.odd = Some(high);
                return;
            }
        }
        let (pairs, remainder) = bytes.as_chunks::<2>();
        for pair in pairs {
            self.sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
        }
        if let Some(&last) = remainder.first() {
            self.odd = Some(last);
        }
    }

    #[must_use]
    pub fn finish(mut self) -> u16 {
        if let Some(high) = self.odd.take() {
            self.sum += (high as u32) << 8;
        }
        while self.sum >> 16 != 0 {
            self.sum = (self.sum & 0xffff) + (self.sum >> 16);
        }
        !(self.sum as u16)
    }
}

impl Default for Checksum {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut checksum = Checksum::new();
    checksum.add(bytes);
    checksum.finish()
}

pub fn add_ipv4_pseudo_header(
    checksum: &mut Checksum,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: IpProtocol,
    length: u16,
) {
    checksum.add(&source.0);
    checksum.add(&destination.0);
    checksum.add(&[0, protocol.raw()]);
    checksum.add(&length.to_be_bytes());
}

#[derive(Clone, Copy, Debug)]
pub struct Ipv4Packet<'a> {
    pub dscp_ecn: u8,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub header: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < MIN_HEADER_LEN {
            return Err(PacketError::Truncated);
        }
        if bytes[0] >> 4 != 4 {
            return Err(PacketError::UnsupportedVersion);
        }
        let header_len = usize::from(bytes[0] & 0x0f) * 4;
        if header_len < MIN_HEADER_LEN || header_len > bytes.len() {
            return Err(PacketError::Malformed);
        }
        let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if total_len < header_len || total_len > bytes.len() {
            return Err(PacketError::Truncated);
        }
        if internet_checksum(&bytes[..header_len]) != 0 {
            return Err(PacketError::BadChecksum);
        }
        Ok(Self {
            dscp_ecn: bytes[1],
            identification: u16::from_be_bytes([bytes[4], bytes[5]]),
            flags_fragment: u16::from_be_bytes([bytes[6], bytes[7]]),
            ttl: bytes[8],
            protocol: IpProtocol::from_raw(bytes[9]),
            source: Ipv4Addr(bytes[12..16].try_into().expect("four-byte slice")),
            destination: Ipv4Addr(bytes[16..20].try_into().expect("four-byte slice")),
            header: &bytes[..header_len],
            payload: &bytes[header_len..total_len],
        })
    }

    #[must_use]
    pub const fn more_fragments(&self) -> bool {
        self.flags_fragment & 0x2000 != 0
    }

    #[must_use]
    pub const fn fragment_offset(&self) -> u16 {
        self.flags_fragment & 0x1fff
    }

    #[must_use]
    pub const fn is_fragmented(&self) -> bool {
        self.more_fragments() || self.fragment_offset() != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Ipv4Header {
    pub dscp_ecn: u8,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
}

impl Ipv4Header {
    pub fn write(self, output: &mut [u8], payload_len: usize) -> Result<usize, PacketError> {
        let total_len = MIN_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(PacketError::Oversized)?;
        let total_len = u16::try_from(total_len).map_err(|_| PacketError::Oversized)?;
        if output.len() < MIN_HEADER_LEN {
            return Err(PacketError::BufferTooSmall);
        }
        output[..MIN_HEADER_LEN].fill(0);
        output[0] = 0x45;
        output[1] = self.dscp_ecn;
        output[2..4].copy_from_slice(&total_len.to_be_bytes());
        output[4..6].copy_from_slice(&self.identification.to_be_bytes());
        output[6..8].copy_from_slice(&self.flags_fragment.to_be_bytes());
        output[8] = self.ttl;
        output[9] = self.protocol.raw();
        output[12..16].copy_from_slice(&self.source.0);
        output[16..20].copy_from_slice(&self.destination.0);
        let checksum = internet_checksum(&output[..MIN_HEADER_LEN]);
        output[10..12].copy_from_slice(&checksum.to_be_bytes());
        Ok(MIN_HEADER_LEN)
    }
}
