//! UDP datagram validation and construction over IPv4.

use super::ip::{add_ipv4_pseudo_header, Checksum, IpProtocol, Ipv4Addr};
use super::PacketError;

pub const HEADER_LEN: usize = 8;

#[derive(Clone, Copy, Debug)]
pub struct UdpDatagram<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < HEADER_LEN {
            return Err(PacketError::Truncated);
        }
        let length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
        if length < HEADER_LEN || length > bytes.len() {
            return Err(PacketError::Truncated);
        }
        Ok(Self {
            source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            checksum: u16::from_be_bytes([bytes[6], bytes[7]]),
            payload: &bytes[HEADER_LEN..length],
        })
    }

    pub fn parse_ipv4(
        bytes: &'a [u8],
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> Result<Self, PacketError> {
        let datagram = Self::parse(bytes)?;
        let length = u16::from_be_bytes([bytes[4], bytes[5]]);
        if datagram.checksum != 0 {
            let mut checksum = Checksum::new();
            add_ipv4_pseudo_header(&mut checksum, source, destination, IpProtocol::Udp, length);
            checksum.add(&bytes[..usize::from(length)]);
            if checksum.finish() != 0 {
                return Err(PacketError::BadChecksum);
            }
        }
        Ok(datagram)
    }
}

pub fn write_ipv4(
    output: &mut [u8],
    source: (Ipv4Addr, u16),
    destination: (Ipv4Addr, u16),
    payload: &[u8],
) -> Result<usize, PacketError> {
    let length = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(PacketError::Oversized)?;
    let length_u16 = u16::try_from(length).map_err(|_| PacketError::Oversized)?;
    if output.len() < length {
        return Err(PacketError::BufferTooSmall);
    }
    output[..length].fill(0);
    output[0..2].copy_from_slice(&source.1.to_be_bytes());
    output[2..4].copy_from_slice(&destination.1.to_be_bytes());
    output[4..6].copy_from_slice(&length_u16.to_be_bytes());
    output[8..length].copy_from_slice(payload);
    let mut checksum = Checksum::new();
    add_ipv4_pseudo_header(
        &mut checksum,
        source.0,
        destination.0,
        IpProtocol::Udp,
        length_u16,
    );
    checksum.add(&output[..length]);
    let mut value = checksum.finish();
    if value == 0 {
        value = 0xffff;
    }
    output[6..8].copy_from_slice(&value.to_be_bytes());
    Ok(length)
}
