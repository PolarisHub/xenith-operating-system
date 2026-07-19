//! ICMPv4 parsing and echo reply construction.

use super::ip::internet_checksum;
use super::PacketError;

pub const HEADER_LEN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpKind {
    EchoReply,
    DestinationUnreachable,
    EchoRequest,
    TimeExceeded,
    Other(u8),
}

impl IcmpKind {
    #[must_use]
    pub const fn from_raw(value: u8) -> Self {
        match value {
            0 => Self::EchoReply,
            3 => Self::DestinationUnreachable,
            8 => Self::EchoRequest,
            11 => Self::TimeExceeded,
            other => Self::Other(other),
        }
    }

    #[must_use]
    pub const fn raw(self) -> u8 {
        match self {
            Self::EchoReply => 0,
            Self::DestinationUnreachable => 3,
            Self::EchoRequest => 8,
            Self::TimeExceeded => 11,
            Self::Other(value) => value,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IcmpPacket<'a> {
    pub kind: IcmpKind,
    pub code: u8,
    pub rest_of_header: [u8; 4],
    pub payload: &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < HEADER_LEN {
            return Err(PacketError::Truncated);
        }
        if internet_checksum(bytes) != 0 {
            return Err(PacketError::BadChecksum);
        }
        Ok(Self {
            kind: IcmpKind::from_raw(bytes[0]),
            code: bytes[1],
            rest_of_header: bytes[4..8].try_into().expect("four-byte slice"),
            payload: &bytes[8..],
        })
    }

    #[must_use]
    pub fn echo_id_sequence(&self) -> Option<(u16, u16)> {
        if matches!(self.kind, IcmpKind::EchoRequest | IcmpKind::EchoReply) && self.code == 0 {
            Some((
                u16::from_be_bytes([self.rest_of_header[0], self.rest_of_header[1]]),
                u16::from_be_bytes([self.rest_of_header[2], self.rest_of_header[3]]),
            ))
        } else {
            None
        }
    }
}

pub fn write_echo(
    output: &mut [u8],
    reply: bool,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<usize, PacketError> {
    let length = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(PacketError::Oversized)?;
    if output.len() < length {
        return Err(PacketError::BufferTooSmall);
    }
    output[..length].fill(0);
    output[0] = if reply { 0 } else { 8 };
    output[4..6].copy_from_slice(&identifier.to_be_bytes());
    output[6..8].copy_from_slice(&sequence.to_be_bytes());
    output[8..length].copy_from_slice(payload);
    let checksum = internet_checksum(&output[..length]);
    output[2..4].copy_from_slice(&checksum.to_be_bytes());
    Ok(length)
}

pub fn write_echo_reply(output: &mut [u8], request: IcmpPacket<'_>) -> Result<usize, PacketError> {
    let (identifier, sequence) = request
        .echo_id_sequence()
        .filter(|_| matches!(request.kind, IcmpKind::EchoRequest))
        .ok_or(PacketError::Malformed)?;
    write_echo(output, true, identifier, sequence, request.payload)
}
