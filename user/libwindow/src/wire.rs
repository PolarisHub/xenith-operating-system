use xenith_abi::compositor::{
    CompositorBufferReleaseEvent, CompositorCloseEvent, CompositorConfigureEvent,
    CompositorFocusEvent, CompositorFrameDoneEvent, CompositorHandle, CompositorHeader,
    CompositorKeyEvent, CompositorPointerEvent, CompositorTextEvent,
    COMPOSITOR_EVENT_BUFFER_RELEASE, COMPOSITOR_EVENT_CLOSE, COMPOSITOR_EVENT_CONFIGURE,
    COMPOSITOR_EVENT_FOCUS, COMPOSITOR_EVENT_FRAME_DONE, COMPOSITOR_EVENT_KEY,
    COMPOSITOR_EVENT_POINTER, COMPOSITOR_EVENT_TEXT, COMPOSITOR_HEADER_SIZE, COMPOSITOR_KIND_EVENT,
    COMPOSITOR_KIND_REPLY, COMPOSITOR_MAGIC, COMPOSITOR_REPLY_STATUS, COMPOSITOR_VERSION,
};

use crate::client::EventKind;

pub(crate) const HEADER_SIZE: usize = COMPOSITOR_HEADER_SIZE as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WireError {
    Truncated,
    InvalidHeader,
    InvalidPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecodedMessage {
    Reply {
        serial: u64,
        status: i32,
        value: CompositorHandle,
    },
    Event {
        serial: u64,
        surface: CompositorHandle,
        kind: EventKind,
    },
}

pub(crate) fn encode_header(
    output: &mut [u8],
    kind: u16,
    opcode: u16,
    payload_size: usize,
    serial: u64,
    object: CompositorHandle,
) -> Result<usize, WireError> {
    let message_size = HEADER_SIZE
        .checked_add(payload_size)
        .ok_or(WireError::InvalidPayload)?;
    if output.len() < message_size || message_size > u32::MAX as usize {
        return Err(WireError::Truncated);
    }
    put_u32(output, 0, COMPOSITOR_MAGIC)?;
    put_u16(output, 4, COMPOSITOR_VERSION)?;
    put_u16(output, 6, COMPOSITOR_HEADER_SIZE)?;
    put_u32(output, 8, message_size as u32)?;
    put_u16(output, 12, kind)?;
    put_u16(output, 14, opcode)?;
    put_u32(output, 16, 0)?;
    put_u32(output, 20, 0)?;
    put_u64(output, 24, serial)?;
    put_u64(output, 32, object.0)?;
    Ok(message_size)
}

pub(crate) fn decode_message(input: &[u8]) -> Result<DecodedMessage, WireError> {
    let header = decode_header(input)?;
    if !header.is_valid_message(
        xenith_abi::compositor::CompositorMessageDirection::ServerToClient,
        input.len() as u32,
    ) {
        return Err(WireError::InvalidHeader);
    }
    let payload = &input[HEADER_SIZE..];
    match (header.kind, header.opcode) {
        (COMPOSITOR_KIND_REPLY, COMPOSITOR_REPLY_STATUS) => {
            let status = get_i32(payload, 0)?;
            let reserved = get_u32(payload, 4)?;
            let value = CompositorHandle(get_u64(payload, 8)?);
            let reserved2 = [get_u64(payload, 16)?, get_u64(payload, 24)?];
            let decoded = xenith_abi::compositor::CompositorStatusReply {
                status,
                reserved,
                value,
                reserved2,
            };
            if !decoded.is_valid() {
                return Err(WireError::InvalidPayload);
            }
            Ok(DecodedMessage::Reply {
                serial: header.serial,
                status,
                value,
            })
        },
        (COMPOSITOR_KIND_EVENT, opcode) => Ok(DecodedMessage::Event {
            serial: header.serial,
            surface: header.object,
            kind: decode_event(opcode, payload)?,
        }),
        _ => Err(WireError::InvalidHeader),
    }
}

fn decode_header(input: &[u8]) -> Result<CompositorHeader, WireError> {
    if input.len() < HEADER_SIZE || input.len() > u32::MAX as usize {
        return Err(WireError::Truncated);
    }
    Ok(CompositorHeader {
        magic: get_u32(input, 0)?,
        version: get_u16(input, 4)?,
        header_size: get_u16(input, 6)?,
        message_size: get_u32(input, 8)?,
        kind: get_u16(input, 12)?,
        opcode: get_u16(input, 14)?,
        flags: get_u32(input, 16)?,
        reserved: get_u32(input, 20)?,
        serial: get_u64(input, 24)?,
        object: CompositorHandle(get_u64(input, 32)?),
    })
}

fn decode_event(opcode: u16, payload: &[u8]) -> Result<EventKind, WireError> {
    let kind = match opcode {
        COMPOSITOR_EVENT_CONFIGURE => {
            let event = CompositorConfigureEvent {
                width: get_u32(payload, 0)?,
                height: get_u32(payload, 4)?,
                state: get_u32(payload, 8)?,
                scale_milli: get_u32(payload, 12)?,
                reserved: [get_u64(payload, 16)?, get_u64(payload, 24)?],
            };
            if !event.is_valid() {
                return Err(WireError::InvalidPayload);
            }
            EventKind::Configure(event)
        },
        COMPOSITOR_EVENT_CLOSE => {
            let event = CompositorCloseEvent {
                reason: get_u32(payload, 0)?,
                reserved: get_u32(payload, 4)?,
                reserved2: [get_u64(payload, 8)?, get_u64(payload, 16)?],
            };
            if !event.is_valid() {
                return Err(WireError::InvalidPayload);
            }
            EventKind::Close(event)
        },
        COMPOSITOR_EVENT_FOCUS => {
            let event = CompositorFocusEvent {
                focused: get_u32(payload, 0)?,
                seat: get_u32(payload, 4)?,
                reserved: [get_u64(payload, 8)?, get_u64(payload, 16)?],
            };
            if !event.is_valid() {
                return Err(WireError::InvalidPayload);
            }
            EventKind::Focus(event)
        },
        COMPOSITOR_EVENT_POINTER => {
            let event = CompositorPointerEvent {
                timestamp_ns: get_u64(payload, 0)?,
                x: get_i32(payload, 8)?,
                y: get_i32(payload, 12)?,
                delta_x: get_i32(payload, 16)?,
                delta_y: get_i32(payload, 20)?,
                buttons: get_u32(payload, 24)?,
                changed_button: get_u16(payload, 28)?,
                action: get_u16(payload, 30)?,
                modifiers: get_u32(payload, 32)?,
                axis_x: get_i32(payload, 36)?,
                axis_y: get_i32(payload, 40)?,
                reserved: get_u32(payload, 44)?,
                reserved2: [get_u64(payload, 48)?, get_u64(payload, 56)?],
            };
            if !event.is_valid() {
                return Err(WireError::InvalidPayload);
            }
            EventKind::Pointer(event)
        },
        COMPOSITOR_EVENT_KEY => {
            let event = CompositorKeyEvent {
                timestamp_ns: get_u64(payload, 0)?,
                key_code: get_u32(payload, 8)?,
                scan_code: get_u32(payload, 12)?,
                modifiers: get_u32(payload, 16)?,
                state: get_u16(payload, 20)?,
                repeat_count: get_u16(payload, 22)?,
                reserved: [get_u32(payload, 24)?, get_u32(payload, 28)?],
                reserved2: [get_u64(payload, 32)?, get_u64(payload, 40)?],
            };
            if !event.is_valid() {
                return Err(WireError::InvalidPayload);
            }
            EventKind::Key(event)
        },
        COMPOSITOR_EVENT_TEXT => {
            let byte_length = get_u16(payload, 0)?;
            let flags = get_u16(payload, 2)?;
            let reserved = get_u32(payload, 4)?;
            let mut bytes = [0; xenith_abi::compositor::COMPOSITOR_MAX_TEXT_BYTES as usize];
            copy_exact(payload, 8, &mut bytes)?;
            let event = CompositorTextEvent {
                byte_length,
                flags,
                reserved,
                bytes,
                reserved2: [get_u64(payload, 72)?, get_u64(payload, 80)?],
            };
            if !event.is_valid() {
                return Err(WireError::InvalidPayload);
            }
            EventKind::Text(event)
        },
        COMPOSITOR_EVENT_FRAME_DONE => {
            let event = CompositorFrameDoneEvent {
                frame_token: get_u64(payload, 0)?,
                presentation_time_ns: get_u64(payload, 8)?,
                refresh_interval_ns: get_u64(payload, 16)?,
                flags: get_u32(payload, 24)?,
                reserved: get_u32(payload, 28)?,
                reserved2: [get_u64(payload, 32)?, get_u64(payload, 40)?],
            };
            if !event.is_valid() {
                return Err(WireError::InvalidPayload);
            }
            EventKind::FrameDone(event)
        },
        COMPOSITOR_EVENT_BUFFER_RELEASE => {
            let event = CompositorBufferReleaseEvent {
                buffer_token: get_u64(payload, 0)?,
                flags: get_u32(payload, 8)?,
                reserved: get_u32(payload, 12)?,
                reserved2: [get_u64(payload, 16)?, get_u64(payload, 24)?],
            };
            if !event.is_valid() {
                return Err(WireError::InvalidPayload);
            }
            EventKind::BufferRelease(event)
        },
        _ => return Err(WireError::InvalidHeader),
    };
    Ok(kind)
}

pub(crate) fn put_u16(output: &mut [u8], offset: usize, value: u16) -> Result<(), WireError> {
    put(output, offset, &value.to_le_bytes())
}

pub(crate) fn put_u32(output: &mut [u8], offset: usize, value: u32) -> Result<(), WireError> {
    put(output, offset, &value.to_le_bytes())
}

pub(crate) fn put_u64(output: &mut [u8], offset: usize, value: u64) -> Result<(), WireError> {
    put(output, offset, &value.to_le_bytes())
}

pub(crate) fn put(output: &mut [u8], offset: usize, value: &[u8]) -> Result<(), WireError> {
    let end = offset
        .checked_add(value.len())
        .ok_or(WireError::Truncated)?;
    let target = output.get_mut(offset..end).ok_or(WireError::Truncated)?;
    target.copy_from_slice(value);
    Ok(())
}

fn get_u16(input: &[u8], offset: usize) -> Result<u16, WireError> {
    let mut bytes = [0; 2];
    copy_exact(input, offset, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn get_u32(input: &[u8], offset: usize) -> Result<u32, WireError> {
    let mut bytes = [0; 4];
    copy_exact(input, offset, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn get_i32(input: &[u8], offset: usize) -> Result<i32, WireError> {
    let mut bytes = [0; 4];
    copy_exact(input, offset, &mut bytes)?;
    Ok(i32::from_le_bytes(bytes))
}

fn get_u64(input: &[u8], offset: usize) -> Result<u64, WireError> {
    let mut bytes = [0; 8];
    copy_exact(input, offset, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn copy_exact(input: &[u8], offset: usize, output: &mut [u8]) -> Result<(), WireError> {
    let end = offset
        .checked_add(output.len())
        .ok_or(WireError::Truncated)?;
    let source = input.get(offset..end).ok_or(WireError::Truncated)?;
    output.copy_from_slice(source);
    Ok(())
}
