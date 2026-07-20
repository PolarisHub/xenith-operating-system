//! Transport-neutral wire records for Xenith's userspace compositor.
//!
//! The transport carries a [`CompositorHeader`] followed by exactly one of the
//! fixed-size payloads below. Integers are little-endian on the wire. Handles
//! are opaque outside the compositor; their upper 32 bits are a generation and
//! their lower 32 bits are a slot, preventing stale-slot reuse.

use core::mem::{align_of, size_of};

pub const COMPOSITOR_MAGIC: u32 = 0x504D_4358; // `XCMP` in little-endian memory.
pub const COMPOSITOR_VERSION: u16 = 1;
pub const COMPOSITOR_MAX_MESSAGE_SIZE: u32 = 4096;
pub const COMPOSITOR_MAX_SURFACE_DIMENSION: u32 = 16_384;
pub const COMPOSITOR_MAX_SURFACE_BYTES: u64 = 512 * 1024 * 1024;
pub const COMPOSITOR_MAX_DAMAGE_RECTS: u32 = 64;
pub const COMPOSITOR_MAX_TITLE_BYTES: u32 = 256;
pub const COMPOSITOR_MAX_TEXT_BYTES: u32 = 64;

pub const COMPOSITOR_KIND_REQUEST: u16 = 1;
pub const COMPOSITOR_KIND_REPLY: u16 = 2;
pub const COMPOSITOR_KIND_EVENT: u16 = 3;

pub const COMPOSITOR_REQUEST_CREATE_SURFACE: u16 = 1;
pub const COMPOSITOR_REQUEST_DESTROY_SURFACE: u16 = 2;
pub const COMPOSITOR_REQUEST_ATTACH_BUFFER: u16 = 3;
pub const COMPOSITOR_REQUEST_COMMIT: u16 = 4;
pub const COMPOSITOR_REQUEST_SET_ROLE: u16 = 5;
pub const COMPOSITOR_REQUEST_SET_TITLE: u16 = 6;
pub const COMPOSITOR_REQUEST_SET_STATE: u16 = 7;
pub const COMPOSITOR_REQUEST_ACK_CONFIGURE: u16 = 8;

pub const COMPOSITOR_REPLY_STATUS: u16 = 1;

pub const COMPOSITOR_EVENT_CONFIGURE: u16 = 1;
pub const COMPOSITOR_EVENT_CLOSE: u16 = 2;
pub const COMPOSITOR_EVENT_FOCUS: u16 = 3;
pub const COMPOSITOR_EVENT_POINTER: u16 = 4;
pub const COMPOSITOR_EVENT_KEY: u16 = 5;
pub const COMPOSITOR_EVENT_TEXT: u16 = 6;
pub const COMPOSITOR_EVENT_FRAME_DONE: u16 = 7;

pub const COMPOSITOR_FORMAT_BGRX8888: u32 = 1;
pub const COMPOSITOR_FORMAT_BGRA8888: u32 = 2;

pub const COMPOSITOR_ROLE_NONE: u16 = 0;
pub const COMPOSITOR_ROLE_TOPLEVEL: u16 = 1;
pub const COMPOSITOR_ROLE_POPUP: u16 = 2;
pub const COMPOSITOR_ROLE_CURSOR: u16 = 3;

pub const COMPOSITOR_STATE_MAXIMIZED: u32 = 1 << 0;
pub const COMPOSITOR_STATE_FULLSCREEN: u32 = 1 << 1;
pub const COMPOSITOR_STATE_MINIMIZED: u32 = 1 << 2;
pub const COMPOSITOR_STATE_ACTIVATED: u32 = 1 << 3;
pub const COMPOSITOR_STATE_ALL: u32 = COMPOSITOR_STATE_MAXIMIZED
    | COMPOSITOR_STATE_FULLSCREEN
    | COMPOSITOR_STATE_MINIMIZED
    | COMPOSITOR_STATE_ACTIVATED;

pub const COMPOSITOR_COMMIT_REQUEST_FRAME_DONE: u32 = 1 << 0;

pub const COMPOSITOR_POINTER_ACTION_MOTION: u16 = 1;
pub const COMPOSITOR_POINTER_ACTION_BUTTON: u16 = 2;
pub const COMPOSITOR_POINTER_ACTION_AXIS: u16 = 3;

pub const COMPOSITOR_KEY_RELEASED: u16 = 0;
pub const COMPOSITOR_KEY_PRESSED: u16 = 1;
pub const COMPOSITOR_KEY_REPEATED: u16 = 2;

pub const COMPOSITOR_FOCUS_OUT: u32 = 0;
pub const COMPOSITOR_FOCUS_IN: u32 = 1;

/// Opaque object identifier. Both the slot and generation must be nonzero.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct CompositorHandle(pub u64);

impl CompositorHandle {
    pub const INVALID: Self = Self(0);

    #[must_use]
    pub const fn from_parts(slot: u32, generation: u32) -> Self {
        Self(((generation as u64) << 32) | slot as u64)
    }

    #[must_use]
    pub const fn slot(self) -> u32 {
        self.0 as u32
    }

    #[must_use]
    pub const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.slot() != 0 && self.generation() != 0
    }
}

pub const COMPOSITOR_HEADER_SIZE: u16 = size_of::<CompositorHeader>() as u16;

/// Common prefix for every compositor message.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorHeader {
    pub magic: u32,
    pub version: u16,
    pub header_size: u16,
    pub message_size: u32,
    pub kind: u16,
    pub opcode: u16,
    pub flags: u32,
    /// Must be zero.
    pub reserved: u32,
    pub serial: u64,
    /// Target surface for surface requests/events, otherwise invalid.
    pub object: CompositorHandle,
}

impl CompositorHeader {
    #[must_use]
    pub const fn new(
        kind: u16,
        opcode: u16,
        payload_size: u32,
        serial: u64,
        object: CompositorHandle,
    ) -> Self {
        let message_size =
            if payload_size <= COMPOSITOR_MAX_MESSAGE_SIZE - COMPOSITOR_HEADER_SIZE as u32 {
                COMPOSITOR_HEADER_SIZE as u32 + payload_size
            } else {
                0
            };
        Self {
            magic: COMPOSITOR_MAGIC,
            version: COMPOSITOR_VERSION,
            header_size: COMPOSITOR_HEADER_SIZE,
            message_size,
            kind,
            opcode,
            flags: 0,
            reserved: 0,
            serial,
            object,
        }
    }

    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.magic == COMPOSITOR_MAGIC
            && self.version == COMPOSITOR_VERSION
            && self.header_size == COMPOSITOR_HEADER_SIZE
            && self.message_size >= COMPOSITOR_HEADER_SIZE as u32
            && self.message_size <= COMPOSITOR_MAX_MESSAGE_SIZE
            && self.flags == 0
            && self.reserved == 0
            && is_known_opcode(self.kind, self.opcode)
    }

    #[must_use]
    pub const fn is_valid_for_payload(&self, payload_size: u32) -> bool {
        self.is_valid()
            && payload_size <= COMPOSITOR_MAX_MESSAGE_SIZE - COMPOSITOR_HEADER_SIZE as u32
            && self.message_size == COMPOSITOR_HEADER_SIZE as u32 + payload_size
    }

    #[must_use]
    pub const fn is_complete_in(&self, available_bytes: u32) -> bool {
        self.is_valid() && available_bytes >= self.message_size
    }
}

#[must_use]
pub const fn is_known_opcode(kind: u16, opcode: u16) -> bool {
    match kind {
        COMPOSITOR_KIND_REQUEST => matches!(
            opcode,
            COMPOSITOR_REQUEST_CREATE_SURFACE
                | COMPOSITOR_REQUEST_DESTROY_SURFACE
                | COMPOSITOR_REQUEST_ATTACH_BUFFER
                | COMPOSITOR_REQUEST_COMMIT
                | COMPOSITOR_REQUEST_SET_ROLE
                | COMPOSITOR_REQUEST_SET_TITLE
                | COMPOSITOR_REQUEST_SET_STATE
                | COMPOSITOR_REQUEST_ACK_CONFIGURE
        ),
        COMPOSITOR_KIND_REPLY => opcode == COMPOSITOR_REPLY_STATUS,
        COMPOSITOR_KIND_EVENT => matches!(
            opcode,
            COMPOSITOR_EVENT_CONFIGURE
                | COMPOSITOR_EVENT_CLOSE
                | COMPOSITOR_EVENT_FOCUS
                | COMPOSITOR_EVENT_POINTER
                | COMPOSITOR_EVENT_KEY
                | COMPOSITOR_EVENT_TEXT
                | COMPOSITOR_EVENT_FRAME_DONE
        ),
        _ => false,
    }
}

/// Shared-memory surface description. `buffer_token` is transport-defined.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorSurfaceMetadata {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
    pub buffer_token: u64,
    pub offset: u64,
    pub length: u64,
    /// Must be zero.
    pub reserved: [u64; 2],
}

impl CompositorSurfaceMetadata {
    #[must_use]
    pub const fn bytes_per_pixel(&self) -> u32 {
        match self.format {
            COMPOSITOR_FORMAT_BGRX8888 | COMPOSITOR_FORMAT_BGRA8888 => 4,
            _ => 0,
        }
    }

    /// Minimum bytes read while copying the visible pixels, excluding final-row padding.
    #[must_use]
    pub const fn required_bytes(&self) -> Option<u64> {
        let bytes_per_pixel = self.bytes_per_pixel() as u64;
        if self.width == 0 || self.height == 0 || bytes_per_pixel == 0 {
            return None;
        }
        let row_bytes = match (self.width as u64).checked_mul(bytes_per_pixel) {
            Some(value) => value,
            None => return None,
        };
        let prior_rows = match (self.height as u64 - 1).checked_mul(self.stride as u64) {
            Some(value) => value,
            None => return None,
        };
        prior_rows.checked_add(row_bytes)
    }

    /// Validate geometry and that the described slice fits its backing buffer.
    #[must_use]
    pub const fn is_valid(&self, backing_length: u64) -> bool {
        if self.reserved[0] != 0
            || self.reserved[1] != 0
            || self.buffer_token == 0
            || self.width == 0
            || self.height == 0
            || self.width > COMPOSITOR_MAX_SURFACE_DIMENSION
            || self.height > COMPOSITOR_MAX_SURFACE_DIMENSION
            || self.length == 0
            || self.length > COMPOSITOR_MAX_SURFACE_BYTES
        {
            return false;
        }
        let bytes_per_pixel = self.bytes_per_pixel();
        let row_bytes = match self.width.checked_mul(bytes_per_pixel) {
            Some(value) if bytes_per_pixel != 0 => value,
            _ => return false,
        };
        if self.stride < row_bytes || !self.stride.is_multiple_of(bytes_per_pixel) {
            return false;
        }
        let required = match self.required_bytes() {
            Some(value) => value,
            None => return false,
        };
        let end = match self.offset.checked_add(self.length) {
            Some(value) => value,
            None => return false,
        };
        required <= self.length && end <= backing_length
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorDamageRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl CompositorDamageRect {
    #[must_use]
    pub const fn is_valid_for(&self, surface_width: u32, surface_height: u32) -> bool {
        if self.width == 0 || self.height == 0 {
            return false;
        }
        match (
            self.x.checked_add(self.width),
            self.y.checked_add(self.height),
        ) {
            (Some(right), Some(bottom)) => right <= surface_width && bottom <= surface_height,
            _ => false,
        }
    }

    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.x == 0 && self.y == 0 && self.width == 0 && self.height == 0
    }
}

#[must_use]
pub fn validate_damage_rects(
    rects: &[CompositorDamageRect],
    surface_width: u32,
    surface_height: u32,
) -> bool {
    rects.len() <= COMPOSITOR_MAX_DAMAGE_RECTS as usize
        && rects
            .iter()
            .all(|rect| rect.is_valid_for(surface_width, surface_height))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorCreateSurfaceRequest {
    /// Must be zero.
    pub reserved: [u64; 2],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorDestroySurfaceRequest {
    /// Must be zero.
    pub reserved: [u64; 2],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorAttachBufferRequest {
    pub surface: CompositorSurfaceMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorCommitRequest {
    /// Client-selected token echoed by [`CompositorFrameDoneEvent`].
    pub frame_token: u64,
    pub damage_count: u32,
    pub flags: u32,
    pub damage: [CompositorDamageRect; COMPOSITOR_MAX_DAMAGE_RECTS as usize],
    /// Must be zero.
    pub reserved: [u64; 2],
}

impl Default for CompositorCommitRequest {
    fn default() -> Self {
        Self {
            frame_token: 0,
            damage_count: 0,
            flags: 0,
            damage: [CompositorDamageRect::default(); COMPOSITOR_MAX_DAMAGE_RECTS as usize],
            reserved: [0; 2],
        }
    }
}

impl CompositorCommitRequest {
    #[must_use]
    pub fn is_valid(&self, surface_width: u32, surface_height: u32) -> bool {
        if self.damage_count > COMPOSITOR_MAX_DAMAGE_RECTS
            || self.flags & !COMPOSITOR_COMMIT_REQUEST_FRAME_DONE != 0
            || self.reserved != [0; 2]
            || (self.flags & COMPOSITOR_COMMIT_REQUEST_FRAME_DONE != 0) != (self.frame_token != 0)
        {
            return false;
        }
        let count = self.damage_count as usize;
        validate_damage_rects(&self.damage[..count], surface_width, surface_height)
            && self.damage[count..]
                .iter()
                .all(CompositorDamageRect::is_zero)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorSetRoleRequest {
    pub role: u16,
    pub flags: u16,
    /// Must be zero.
    pub reserved: u32,
    /// Required for popup roles; invalid for other roles.
    pub parent: CompositorHandle,
    /// Must be zero.
    pub reserved2: [u64; 2],
}

impl CompositorSetRoleRequest {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        let role_valid = matches!(
            self.role,
            COMPOSITOR_ROLE_NONE
                | COMPOSITOR_ROLE_TOPLEVEL
                | COMPOSITOR_ROLE_POPUP
                | COMPOSITOR_ROLE_CURSOR
        );
        role_valid
            && self.flags == 0
            && self.reserved == 0
            && self.reserved2[0] == 0
            && self.reserved2[1] == 0
            && if self.role == COMPOSITOR_ROLE_POPUP {
                self.parent.is_valid()
            } else {
                self.parent.0 == CompositorHandle::INVALID.0
            }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorSetTitleRequest {
    pub byte_length: u16,
    pub flags: u16,
    /// Must be zero.
    pub reserved: u32,
    pub bytes: [u8; COMPOSITOR_MAX_TITLE_BYTES as usize],
    /// Must be zero.
    pub reserved2: [u64; 2],
}

impl Default for CompositorSetTitleRequest {
    fn default() -> Self {
        Self {
            byte_length: 0,
            flags: 0,
            reserved: 0,
            bytes: [0; COMPOSITOR_MAX_TITLE_BYTES as usize],
            reserved2: [0; 2],
        }
    }
}

impl CompositorSetTitleRequest {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let length = self.byte_length as usize;
        self.flags == 0
            && self.reserved == 0
            && self.reserved2 == [0; 2]
            && length <= COMPOSITOR_MAX_TITLE_BYTES as usize
            && core::str::from_utf8(&self.bytes[..length]).is_ok()
            && self.bytes[length..].iter().all(|byte| *byte == 0)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorSetStateRequest {
    pub state: u32,
    pub mask: u32,
    /// Must be zero.
    pub reserved: [u64; 2],
}

/// Accept the compositor configuration whose serial was carried by the
/// corresponding [`CompositorHeader`]. A client must acknowledge before
/// committing a buffer sized for that configuration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorAckConfigureRequest {
    pub configure_serial: u64,
    /// Must be zero.
    pub reserved: [u64; 2],
}

impl CompositorAckConfigureRequest {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.configure_serial != 0 && self.reserved[0] == 0 && self.reserved[1] == 0
    }
}

impl CompositorSetStateRequest {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.state & !self.mask == 0
            && self.state & !COMPOSITOR_STATE_ALL == 0
            && self.mask & !COMPOSITOR_STATE_ALL == 0
            && self.reserved[0] == 0
            && self.reserved[1] == 0
    }
}

/// Reply to any request. Create returns the new surface in `value`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorStatusReply {
    /// Zero on success; otherwise a negative transport-independent error code.
    pub status: i32,
    /// Must be zero.
    pub reserved: u32,
    pub value: CompositorHandle,
    /// Must be zero.
    pub reserved2: [u64; 2],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorConfigureEvent {
    pub width: u32,
    pub height: u32,
    pub state: u32,
    /// Logical scale in thousandths; `1000` means 1x.
    pub scale_milli: u32,
    /// Must be zero.
    pub reserved: [u64; 2],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorCloseEvent {
    pub reason: u32,
    /// Must be zero.
    pub reserved: u32,
    /// Must be zero.
    pub reserved2: [u64; 2],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorFocusEvent {
    /// [`COMPOSITOR_FOCUS_OUT`] or [`COMPOSITOR_FOCUS_IN`].
    pub focused: u32,
    pub seat: u32,
    /// Must be zero.
    pub reserved: [u64; 2],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorPointerEvent {
    pub timestamp_ns: u64,
    pub x: i32,
    pub y: i32,
    pub delta_x: i32,
    pub delta_y: i32,
    pub buttons: u32,
    pub changed_button: u16,
    pub action: u16,
    pub modifiers: u32,
    pub axis_x: i32,
    pub axis_y: i32,
    /// Must be zero.
    pub reserved: u32,
    /// Must be zero.
    pub reserved2: [u64; 2],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorKeyEvent {
    pub timestamp_ns: u64,
    pub key_code: u32,
    pub scan_code: u32,
    pub modifiers: u32,
    /// Released, pressed, or repeated; never a Rust `bool`.
    pub state: u16,
    pub repeat_count: u16,
    /// Must be zero.
    pub reserved: [u32; 2],
    /// Must be zero.
    pub reserved2: [u64; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorTextEvent {
    pub byte_length: u16,
    pub flags: u16,
    /// Must be zero.
    pub reserved: u32,
    pub bytes: [u8; COMPOSITOR_MAX_TEXT_BYTES as usize],
    /// Must be zero.
    pub reserved2: [u64; 2],
}

impl Default for CompositorTextEvent {
    fn default() -> Self {
        Self {
            byte_length: 0,
            flags: 0,
            reserved: 0,
            bytes: [0; COMPOSITOR_MAX_TEXT_BYTES as usize],
            reserved2: [0; 2],
        }
    }
}

impl CompositorTextEvent {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let length = self.byte_length as usize;
        self.flags == 0
            && self.reserved == 0
            && self.reserved2 == [0; 2]
            && length <= COMPOSITOR_MAX_TEXT_BYTES as usize
            && core::str::from_utf8(&self.bytes[..length]).is_ok()
            && self.bytes[length..].iter().all(|byte| *byte == 0)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorFrameDoneEvent {
    pub frame_token: u64,
    pub presentation_time_ns: u64,
    pub refresh_interval_ns: u64,
    pub flags: u32,
    /// Must be zero.
    pub reserved: u32,
    /// Must be zero.
    pub reserved2: [u64; 2],
}

macro_rules! assert_layout {
    ($ty:ty, $size:expr, $align:expr) => {
        const _: [(); $size] = [(); size_of::<$ty>()];
        const _: [(); $align] = [(); align_of::<$ty>()];
    };
}

assert_layout!(CompositorHandle, 8, 8);
assert_layout!(CompositorHeader, 40, 8);
assert_layout!(CompositorSurfaceMetadata, 56, 8);
assert_layout!(CompositorDamageRect, 16, 4);
assert_layout!(CompositorCreateSurfaceRequest, 16, 8);
assert_layout!(CompositorDestroySurfaceRequest, 16, 8);
assert_layout!(CompositorAttachBufferRequest, 56, 8);
assert_layout!(CompositorCommitRequest, 1056, 8);
assert_layout!(CompositorSetRoleRequest, 32, 8);
assert_layout!(CompositorSetTitleRequest, 280, 8);
assert_layout!(CompositorSetStateRequest, 24, 8);
assert_layout!(CompositorAckConfigureRequest, 24, 8);
assert_layout!(CompositorStatusReply, 32, 8);
assert_layout!(CompositorConfigureEvent, 32, 8);
assert_layout!(CompositorCloseEvent, 24, 8);
assert_layout!(CompositorFocusEvent, 24, 8);
assert_layout!(CompositorPointerEvent, 64, 8);
assert_layout!(CompositorKeyEvent, 48, 8);
assert_layout!(CompositorTextEvent, 88, 8);
assert_layout!(CompositorFrameDoneEvent, 48, 8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_contains_slot_and_generation() {
        let handle = CompositorHandle::from_parts(7, 11);
        assert!(handle.is_valid());
        assert_eq!(handle.slot(), 7);
        assert_eq!(handle.generation(), 11);
        assert!(!CompositorHandle::INVALID.is_valid());
        assert!(!CompositorHandle::from_parts(7, 0).is_valid());
        assert!(!CompositorHandle::from_parts(0, 11).is_valid());
    }

    #[test]
    fn header_rejects_unknown_or_noncanonical_messages() {
        let header = CompositorHeader::new(
            COMPOSITOR_KIND_REQUEST,
            COMPOSITOR_REQUEST_COMMIT,
            size_of::<CompositorCommitRequest>() as u32,
            9,
            CompositorHandle::from_parts(2, 4),
        );
        assert!(header.is_valid());
        assert!(header.is_valid_for_payload(size_of::<CompositorCommitRequest>() as u32));
        assert!(header.is_complete_in(header.message_size));
        assert!(!header.is_complete_in(header.message_size - 1));

        let mut corrupt = header;
        corrupt.reserved = 1;
        assert!(!corrupt.is_valid());
        corrupt = header;
        corrupt.opcode = u16::MAX;
        assert!(!corrupt.is_valid());
        corrupt = header;
        corrupt.message_size = COMPOSITOR_MAX_MESSAGE_SIZE + 1;
        assert!(!corrupt.is_valid());
    }

    #[test]
    fn surface_validation_checks_stride_arithmetic_and_backing_bounds() {
        let surface = CompositorSurfaceMetadata {
            width: 800,
            height: 600,
            stride: 800 * 4,
            format: COMPOSITOR_FORMAT_BGRA8888,
            buffer_token: 3,
            offset: 4096,
            length: (800 * 600 * 4) as u64,
            reserved: [0; 2],
        };
        assert!(surface.is_valid(4096 + surface.length));
        assert!(!surface.is_valid(4095 + surface.length));

        let mut invalid = surface;
        invalid.stride -= 4;
        assert!(!invalid.is_valid(4096 + invalid.length));
        invalid = surface;
        invalid.offset = u64::MAX - 4;
        assert!(!invalid.is_valid(u64::MAX));
        invalid = surface;
        invalid.reserved[0] = 1;
        assert!(!invalid.is_valid(4096 + invalid.length));
    }

    #[test]
    fn damage_is_bounded_and_inactive_entries_must_be_zero() {
        let mut commit = CompositorCommitRequest {
            damage_count: 1,
            ..CompositorCommitRequest::default()
        };
        commit.damage[0] = CompositorDamageRect {
            x: 10,
            y: 20,
            width: 30,
            height: 40,
        };
        assert!(commit.is_valid(100, 100));

        commit.damage[0].width = 100;
        assert!(!commit.is_valid(100, 100));
        commit.damage[0].width = 30;
        commit.damage[1].width = 1;
        assert!(!commit.is_valid(100, 100));
        commit.damage[1] = CompositorDamageRect::default();
        commit.damage_count = COMPOSITOR_MAX_DAMAGE_RECTS + 1;
        assert!(!commit.is_valid(100, 100));
    }

    #[test]
    fn bounded_strings_require_utf8_and_zero_tail() {
        let mut title = CompositorSetTitleRequest {
            byte_length: 6,
            ..CompositorSetTitleRequest::default()
        };
        title.bytes[..6].copy_from_slice(b"Xenith");
        assert!(title.is_valid());
        title.bytes[7] = 1;
        assert!(!title.is_valid());

        let mut text = CompositorTextEvent {
            byte_length: 2,
            ..CompositorTextEvent::default()
        };
        text.bytes[..2].copy_from_slice(&[0xC3, 0xA9]);
        assert!(text.is_valid());
        text.bytes[1] = 0;
        assert!(!text.is_valid());
    }

    #[test]
    fn configure_ack_requires_a_nonzero_serial_and_canonical_tail() {
        let mut ack = CompositorAckConfigureRequest {
            configure_serial: 41,
            reserved: [0; 2],
        };
        assert!(ack.is_valid());
        ack.configure_serial = 0;
        assert!(!ack.is_valid());
        ack.configure_serial = 41;
        ack.reserved[1] = 1;
        assert!(!ack.is_valid());
    }
}
