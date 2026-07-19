//! Bounded DNS query/response codec used by the kernel network service and
//! mirrored by the small userspace `nslookup` utility.

use super::ip::Ipv4Addr;
use super::PacketError;

pub const PORT: u16 = 53;
pub const MAX_NAME_LEN: usize = 253;
pub const MAX_PACKET_LEN: usize = 512;
const HEADER_LEN: usize = 12;
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;
const MAX_POINTER_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Other(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    pub address: Ipv4Addr,
    pub ttl_seconds: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response {
    pub code: ResponseCode,
    pub truncated: bool,
    pub answer: Option<Answer>,
}

pub fn write_query(
    output: &mut [u8],
    transaction_id: u16,
    name: &str,
) -> Result<usize, PacketError> {
    if output.len() < HEADER_LEN || name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(PacketError::Malformed);
    }
    output.fill(0);
    output[0..2].copy_from_slice(&transaction_id.to_be_bytes());
    output[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    output[4..6].copy_from_slice(&1u16.to_be_bytes());
    let mut offset = HEADER_LEN;
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 || !label.as_bytes().iter().all(valid_name_byte) {
            return Err(PacketError::Malformed);
        }
        let end = offset
            .checked_add(1 + label.len())
            .ok_or(PacketError::Oversized)?;
        if end + 5 > output.len() {
            return Err(PacketError::BufferTooSmall);
        }
        output[offset] = label.len() as u8;
        output[offset + 1..end].copy_from_slice(label.as_bytes());
        offset = end;
    }
    output[offset] = 0;
    offset += 1;
    output[offset..offset + 2].copy_from_slice(&TYPE_A.to_be_bytes());
    output[offset + 2..offset + 4].copy_from_slice(&CLASS_IN.to_be_bytes());
    Ok(offset + 4)
}

pub fn parse_response(bytes: &[u8], transaction_id: u16) -> Result<Response, PacketError> {
    if bytes.len() < HEADER_LEN || bytes.len() > u16::MAX as usize {
        return Err(PacketError::Truncated);
    }
    if u16::from_be_bytes([bytes[0], bytes[1]]) != transaction_id {
        return Err(PacketError::Malformed);
    }
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 {
        return Err(PacketError::Malformed);
    }
    let code = match (flags & 0x000f) as u8 {
        0 => ResponseCode::NoError,
        1 => ResponseCode::FormatError,
        2 => ResponseCode::ServerFailure,
        3 => ResponseCode::NameError,
        4 => ResponseCode::NotImplemented,
        5 => ResponseCode::Refused,
        value => ResponseCode::Other(value),
    };
    let questions = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    let answers = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
    if questions > 16 || answers > 128 {
        return Err(PacketError::Malformed);
    }
    let mut offset = HEADER_LEN;
    for _ in 0..questions {
        offset = skip_name(bytes, offset)?;
        offset = offset.checked_add(4).ok_or(PacketError::Oversized)?;
        if offset > bytes.len() {
            return Err(PacketError::Truncated);
        }
    }
    let mut answer = None;
    for _ in 0..answers {
        offset = skip_name(bytes, offset)?;
        let fixed_end = offset.checked_add(10).ok_or(PacketError::Oversized)?;
        let fixed = bytes.get(offset..fixed_end).ok_or(PacketError::Truncated)?;
        let record_type = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let ttl_seconds = u32::from_be_bytes(fixed[4..8].try_into().expect("TTL is four bytes"));
        let length = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let data_end = fixed_end
            .checked_add(length)
            .ok_or(PacketError::Oversized)?;
        let data = bytes
            .get(fixed_end..data_end)
            .ok_or(PacketError::Truncated)?;
        if answer.is_none() && record_type == TYPE_A && class == CLASS_IN && data.len() == 4 {
            answer = Some(Answer {
                address: Ipv4Addr(data.try_into().expect("A record is four bytes")),
                ttl_seconds,
            });
        }
        offset = data_end;
    }
    Ok(Response {
        code,
        truncated: flags & 0x0200 != 0,
        answer,
    })
}

fn skip_name(bytes: &[u8], mut offset: usize) -> Result<usize, PacketError> {
    let original = offset;
    let mut consumed = 0usize;
    let mut jumped = false;
    let mut depth = 0usize;
    loop {
        let length = *bytes.get(offset).ok_or(PacketError::Truncated)?;
        if length & 0xc0 == 0xc0 {
            let low = *bytes.get(offset + 1).ok_or(PacketError::Truncated)?;
            let pointer = usize::from(u16::from_be_bytes([length & 0x3f, low]));
            if pointer >= bytes.len() || pointer >= offset || depth >= MAX_POINTER_DEPTH {
                return Err(PacketError::Malformed);
            }
            if !jumped {
                consumed = offset + 2 - original;
            }
            offset = pointer;
            jumped = true;
            depth += 1;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(PacketError::Malformed);
        }
        offset += 1;
        if length == 0 {
            return Ok(if jumped { original + consumed } else { offset });
        }
        offset = offset
            .checked_add(usize::from(length))
            .ok_or(PacketError::Oversized)?;
        if offset > bytes.len() {
            return Err(PacketError::Truncated);
        }
    }
}

fn valid_name_byte(byte: &u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_encodes_labels_and_question() {
        let mut bytes = [0u8; MAX_PACKET_LEN];
        let length = write_query(&mut bytes, 0x1234, "www.example.com").unwrap();
        assert_eq!(&bytes[..2], &[0x12, 0x34]);
        assert_eq!(&bytes[12..16], &[3, b'w', b'w', b'w']);
        assert_eq!(&bytes[length - 4..length], &[0, 1, 0, 1]);
    }

    #[test]
    fn compressed_a_answer_is_parsed() {
        let mut query = [0u8; MAX_PACKET_LEN];
        let question_end = write_query(&mut query, 0xbeef, "xenith.test").unwrap();
        query[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        query[6..8].copy_from_slice(&1u16.to_be_bytes());
        let mut offset = question_end;
        query[offset..offset + 2].copy_from_slice(&[0xc0, 0x0c]);
        offset += 2;
        query[offset..offset + 2].copy_from_slice(&TYPE_A.to_be_bytes());
        query[offset + 2..offset + 4].copy_from_slice(&CLASS_IN.to_be_bytes());
        query[offset + 4..offset + 8].copy_from_slice(&300u32.to_be_bytes());
        query[offset + 8..offset + 10].copy_from_slice(&4u16.to_be_bytes());
        query[offset + 10..offset + 14].copy_from_slice(&[192, 0, 2, 9]);
        let response = parse_response(&query[..offset + 14], 0xbeef).unwrap();
        assert_eq!(response.code, ResponseCode::NoError);
        assert_eq!(
            response.answer,
            Some(Answer {
                address: Ipv4Addr::new(192, 0, 2, 9),
                ttl_seconds: 300,
            })
        );
    }

    #[test]
    fn compression_loops_and_wrong_ids_are_rejected() {
        let mut bytes = [0u8; 18];
        bytes[0..2].copy_from_slice(&1u16.to_be_bytes());
        bytes[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
        bytes[12..14].copy_from_slice(&[0xc0, 0x0c]);
        assert_eq!(parse_response(&bytes, 1), Err(PacketError::Malformed));
        assert_eq!(parse_response(&bytes, 2), Err(PacketError::Malformed));
    }
}
