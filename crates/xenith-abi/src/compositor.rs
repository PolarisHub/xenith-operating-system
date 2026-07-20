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
/// The compositor has stopped reading the named attached buffer.
pub const COMPOSITOR_EVENT_BUFFER_RELEASE: u16 = 8;

/// Request completed successfully.
pub const COMPOSITOR_STATUS_OK: i32 = 0;
pub const COMPOSITOR_STATUS_INVALID_ARGUMENT: i32 = -1;
pub const COMPOSITOR_STATUS_NOT_FOUND: i32 = -2;
pub const COMPOSITOR_STATUS_ALREADY_EXISTS: i32 = -3;
pub const COMPOSITOR_STATUS_ACCESS_DENIED: i32 = -4;
pub const COMPOSITOR_STATUS_NO_MEMORY: i32 = -5;
pub const COMPOSITOR_STATUS_RESOURCE_EXHAUSTED: i32 = -6;
pub const COMPOSITOR_STATUS_UNSUPPORTED: i32 = -7;
pub const COMPOSITOR_STATUS_INVALID_STATE: i32 = -8;

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

/// Local validation context; this enum is not part of any wire record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositorMessageDirection {
    ClientToServer,
    ServerToClient,
}

/// Whether an opcode targets a surface in [`CompositorHeader::object`].
/// This enum is descriptive metadata and is not carried on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositorObjectRule {
    Invalid,
    Valid,
}

/// Exact schema associated with one `(kind, opcode)` pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositorOpcodeSchema {
    pub kind: u16,
    pub opcode: u16,
    pub payload_size: u32,
    pub direction: CompositorMessageDirection,
    pub object_rule: CompositorObjectRule,
}

impl CompositorOpcodeSchema {
    #[must_use]
    pub const fn accepts_direction(&self, direction: CompositorMessageDirection) -> bool {
        matches!(
            (self.direction, direction),
            (
                CompositorMessageDirection::ClientToServer,
                CompositorMessageDirection::ClientToServer
            ) | (
                CompositorMessageDirection::ServerToClient,
                CompositorMessageDirection::ServerToClient
            )
        )
    }

    #[must_use]
    pub const fn accepts_object(&self, object: CompositorHandle) -> bool {
        match self.object_rule {
            CompositorObjectRule::Invalid => object.0 == CompositorHandle::INVALID.0,
            CompositorObjectRule::Valid => object.is_valid(),
        }
    }
}

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
    /// Nonzero request/reply correlation or server event serial.
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
        if self.magic != COMPOSITOR_MAGIC
            || self.version != COMPOSITOR_VERSION
            || self.header_size != COMPOSITOR_HEADER_SIZE
            || self.message_size < COMPOSITOR_HEADER_SIZE as u32
            || self.message_size > COMPOSITOR_MAX_MESSAGE_SIZE
            || self.flags != 0
            || self.reserved != 0
            || self.serial == 0
        {
            return false;
        }
        match compositor_opcode_schema(self.kind, self.opcode) {
            Some(schema) => {
                self.message_size == COMPOSITOR_HEADER_SIZE as u32 + schema.payload_size
                    && schema.accepts_object(self.object)
            },
            None => false,
        }
    }

    #[must_use]
    pub const fn is_valid_for_payload(&self, payload_size: u32) -> bool {
        self.is_valid()
            && payload_size <= COMPOSITOR_MAX_MESSAGE_SIZE - COMPOSITOR_HEADER_SIZE as u32
            && self.message_size == COMPOSITOR_HEADER_SIZE as u32 + payload_size
    }

    #[must_use]
    pub const fn is_valid_for_direction(&self, direction: CompositorMessageDirection) -> bool {
        if !self.is_valid() {
            return false;
        }
        match compositor_opcode_schema(self.kind, self.opcode) {
            Some(schema) => schema.accepts_direction(direction),
            None => false,
        }
    }

    /// Validate one complete datagram. Trailing bytes are noncanonical.
    #[must_use]
    pub const fn is_complete_in(&self, available_bytes: u32) -> bool {
        self.is_valid() && available_bytes == self.message_size
    }

    /// Validate schema, direction, object rule, payload size, and exact datagram length.
    #[must_use]
    pub const fn is_valid_message(
        &self,
        direction: CompositorMessageDirection,
        available_bytes: u32,
    ) -> bool {
        self.is_valid_for_direction(direction) && available_bytes == self.message_size
    }
}

#[must_use]
pub const fn is_known_opcode(kind: u16, opcode: u16) -> bool {
    compositor_opcode_schema(kind, opcode).is_some()
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

impl CompositorCreateSurfaceRequest {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.reserved[0] == 0 && self.reserved[1] == 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorDestroySurfaceRequest {
    /// Must be zero.
    pub reserved: [u64; 2],
}

impl CompositorDestroySurfaceRequest {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.reserved[0] == 0 && self.reserved[1] == 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorAttachBufferRequest {
    pub surface: CompositorSurfaceMetadata,
}

impl CompositorAttachBufferRequest {
    #[must_use]
    pub const fn is_valid(&self, backing_length: u64) -> bool {
        self.surface.is_valid(backing_length)
    }
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
    /// [`COMPOSITOR_STATUS_OK`] or a known negative compositor status.
    pub status: i32,
    /// Must be zero.
    pub reserved: u32,
    pub value: CompositorHandle,
    /// Must be zero.
    pub reserved2: [u64; 2],
}

#[must_use]
pub const fn is_known_status(status: i32) -> bool {
    matches!(
        status,
        COMPOSITOR_STATUS_OK
            | COMPOSITOR_STATUS_INVALID_ARGUMENT
            | COMPOSITOR_STATUS_NOT_FOUND
            | COMPOSITOR_STATUS_ALREADY_EXISTS
            | COMPOSITOR_STATUS_ACCESS_DENIED
            | COMPOSITOR_STATUS_NO_MEMORY
            | COMPOSITOR_STATUS_RESOURCE_EXHAUSTED
            | COMPOSITOR_STATUS_UNSUPPORTED
            | COMPOSITOR_STATUS_INVALID_STATE
    )
}

impl CompositorStatusReply {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        let value_is_invalid = self.value.0 == CompositorHandle::INVALID.0;
        is_known_status(self.status)
            && self.reserved == 0
            && self.reserved2[0] == 0
            && self.reserved2[1] == 0
            && (value_is_invalid || self.value.is_valid())
            && (self.status == COMPOSITOR_STATUS_OK || value_is_invalid)
    }
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

impl CompositorConfigureEvent {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.width != 0
            && self.height != 0
            && self.width <= COMPOSITOR_MAX_SURFACE_DIMENSION
            && self.height <= COMPOSITOR_MAX_SURFACE_DIMENSION
            && self.state & !COMPOSITOR_STATE_ALL == 0
            && self.scale_milli != 0
            && self.reserved[0] == 0
            && self.reserved[1] == 0
    }
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

impl CompositorCloseEvent {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.reserved == 0 && self.reserved2[0] == 0 && self.reserved2[1] == 0
    }
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

impl CompositorFocusEvent {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self.focused, COMPOSITOR_FOCUS_OUT | COMPOSITOR_FOCUS_IN)
            && self.reserved[0] == 0
            && self.reserved[1] == 0
    }
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

impl CompositorPointerEvent {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        if self.reserved != 0 || self.reserved2[0] != 0 || self.reserved2[1] != 0 {
            return false;
        }
        match self.action {
            COMPOSITOR_POINTER_ACTION_MOTION => {
                self.changed_button == 0 && self.axis_x == 0 && self.axis_y == 0
            },
            COMPOSITOR_POINTER_ACTION_BUTTON => {
                self.changed_button != 0
                    && self.changed_button & (self.changed_button - 1) == 0
                    && self.axis_x == 0
                    && self.axis_y == 0
            },
            COMPOSITOR_POINTER_ACTION_AXIS => {
                self.changed_button == 0 && (self.axis_x != 0 || self.axis_y != 0)
            },
            _ => false,
        }
    }
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

impl CompositorKeyEvent {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        let repeat_is_valid = match self.state {
            COMPOSITOR_KEY_RELEASED | COMPOSITOR_KEY_PRESSED => self.repeat_count == 0,
            COMPOSITOR_KEY_REPEATED => self.repeat_count != 0,
            _ => false,
        };
        repeat_is_valid
            && self.reserved[0] == 0
            && self.reserved[1] == 0
            && self.reserved2[0] == 0
            && self.reserved2[1] == 0
    }
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

impl CompositorFrameDoneEvent {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.frame_token != 0
            && self.flags == 0
            && self.reserved == 0
            && self.reserved2[0] == 0
            && self.reserved2[1] == 0
    }
}

/// Signals that the compositor will no longer read the attached buffer token.
/// The client may reuse, replace, unmap, or close that buffer after this event.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct CompositorBufferReleaseEvent {
    pub buffer_token: u64,
    pub flags: u32,
    /// Must be zero.
    pub reserved: u32,
    /// Must be zero.
    pub reserved2: [u64; 2],
}

impl CompositorBufferReleaseEvent {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.buffer_token != 0
            && self.flags == 0
            && self.reserved == 0
            && self.reserved2[0] == 0
            && self.reserved2[1] == 0
    }
}

/// Return the exact schema for a known compositor `(kind, opcode)` pair.
#[must_use]
pub const fn compositor_opcode_schema(kind: u16, opcode: u16) -> Option<CompositorOpcodeSchema> {
    let (payload_size, direction, object_rule) = match (kind, opcode) {
        (COMPOSITOR_KIND_REQUEST, COMPOSITOR_REQUEST_CREATE_SURFACE) => (
            size_of::<CompositorCreateSurfaceRequest>() as u32,
            CompositorMessageDirection::ClientToServer,
            CompositorObjectRule::Invalid,
        ),
        (COMPOSITOR_KIND_REQUEST, COMPOSITOR_REQUEST_DESTROY_SURFACE) => (
            size_of::<CompositorDestroySurfaceRequest>() as u32,
            CompositorMessageDirection::ClientToServer,
            CompositorObjectRule::Valid,
        ),
        (COMPOSITOR_KIND_REQUEST, COMPOSITOR_REQUEST_ATTACH_BUFFER) => (
            size_of::<CompositorAttachBufferRequest>() as u32,
            CompositorMessageDirection::ClientToServer,
            CompositorObjectRule::Valid,
        ),
        (COMPOSITOR_KIND_REQUEST, COMPOSITOR_REQUEST_COMMIT) => (
            size_of::<CompositorCommitRequest>() as u32,
            CompositorMessageDirection::ClientToServer,
            CompositorObjectRule::Valid,
        ),
        (COMPOSITOR_KIND_REQUEST, COMPOSITOR_REQUEST_SET_ROLE) => (
            size_of::<CompositorSetRoleRequest>() as u32,
            CompositorMessageDirection::ClientToServer,
            CompositorObjectRule::Valid,
        ),
        (COMPOSITOR_KIND_REQUEST, COMPOSITOR_REQUEST_SET_TITLE) => (
            size_of::<CompositorSetTitleRequest>() as u32,
            CompositorMessageDirection::ClientToServer,
            CompositorObjectRule::Valid,
        ),
        (COMPOSITOR_KIND_REQUEST, COMPOSITOR_REQUEST_SET_STATE) => (
            size_of::<CompositorSetStateRequest>() as u32,
            CompositorMessageDirection::ClientToServer,
            CompositorObjectRule::Valid,
        ),
        (COMPOSITOR_KIND_REQUEST, COMPOSITOR_REQUEST_ACK_CONFIGURE) => (
            size_of::<CompositorAckConfigureRequest>() as u32,
            CompositorMessageDirection::ClientToServer,
            CompositorObjectRule::Valid,
        ),
        (COMPOSITOR_KIND_REPLY, COMPOSITOR_REPLY_STATUS) => (
            size_of::<CompositorStatusReply>() as u32,
            CompositorMessageDirection::ServerToClient,
            CompositorObjectRule::Invalid,
        ),
        (COMPOSITOR_KIND_EVENT, COMPOSITOR_EVENT_CONFIGURE) => (
            size_of::<CompositorConfigureEvent>() as u32,
            CompositorMessageDirection::ServerToClient,
            CompositorObjectRule::Valid,
        ),
        (COMPOSITOR_KIND_EVENT, COMPOSITOR_EVENT_CLOSE) => (
            size_of::<CompositorCloseEvent>() as u32,
            CompositorMessageDirection::ServerToClient,
            CompositorObjectRule::Valid,
        ),
        (COMPOSITOR_KIND_EVENT, COMPOSITOR_EVENT_FOCUS) => (
            size_of::<CompositorFocusEvent>() as u32,
            CompositorMessageDirection::ServerToClient,
            CompositorObjectRule::Valid,
        ),
        (COMPOSITOR_KIND_EVENT, COMPOSITOR_EVENT_POINTER) => (
            size_of::<CompositorPointerEvent>() as u32,
            CompositorMessageDirection::ServerToClient,
            CompositorObjectRule::Valid,
        ),
        (COMPOSITOR_KIND_EVENT, COMPOSITOR_EVENT_KEY) => (
            size_of::<CompositorKeyEvent>() as u32,
            CompositorMessageDirection::ServerToClient,
            CompositorObjectRule::Valid,
        ),
        (COMPOSITOR_KIND_EVENT, COMPOSITOR_EVENT_TEXT) => (
            size_of::<CompositorTextEvent>() as u32,
            CompositorMessageDirection::ServerToClient,
            CompositorObjectRule::Valid,
        ),
        (COMPOSITOR_KIND_EVENT, COMPOSITOR_EVENT_FRAME_DONE) => (
            size_of::<CompositorFrameDoneEvent>() as u32,
            CompositorMessageDirection::ServerToClient,
            CompositorObjectRule::Valid,
        ),
        (COMPOSITOR_KIND_EVENT, COMPOSITOR_EVENT_BUFFER_RELEASE) => (
            size_of::<CompositorBufferReleaseEvent>() as u32,
            CompositorMessageDirection::ServerToClient,
            CompositorObjectRule::Valid,
        ),
        _ => return None,
    };
    Some(CompositorOpcodeSchema {
        kind,
        opcode,
        payload_size,
        direction,
        object_rule,
    })
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
assert_layout!(CompositorBufferReleaseEvent, 32, 8);

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
    fn opcode_schema_is_exact_and_complete() {
        let cases = [
            (
                COMPOSITOR_KIND_REQUEST,
                COMPOSITOR_REQUEST_CREATE_SURFACE,
                size_of::<CompositorCreateSurfaceRequest>() as u32,
                CompositorMessageDirection::ClientToServer,
                CompositorObjectRule::Invalid,
            ),
            (
                COMPOSITOR_KIND_REQUEST,
                COMPOSITOR_REQUEST_DESTROY_SURFACE,
                size_of::<CompositorDestroySurfaceRequest>() as u32,
                CompositorMessageDirection::ClientToServer,
                CompositorObjectRule::Valid,
            ),
            (
                COMPOSITOR_KIND_REQUEST,
                COMPOSITOR_REQUEST_ATTACH_BUFFER,
                size_of::<CompositorAttachBufferRequest>() as u32,
                CompositorMessageDirection::ClientToServer,
                CompositorObjectRule::Valid,
            ),
            (
                COMPOSITOR_KIND_REQUEST,
                COMPOSITOR_REQUEST_COMMIT,
                size_of::<CompositorCommitRequest>() as u32,
                CompositorMessageDirection::ClientToServer,
                CompositorObjectRule::Valid,
            ),
            (
                COMPOSITOR_KIND_REQUEST,
                COMPOSITOR_REQUEST_SET_ROLE,
                size_of::<CompositorSetRoleRequest>() as u32,
                CompositorMessageDirection::ClientToServer,
                CompositorObjectRule::Valid,
            ),
            (
                COMPOSITOR_KIND_REQUEST,
                COMPOSITOR_REQUEST_SET_TITLE,
                size_of::<CompositorSetTitleRequest>() as u32,
                CompositorMessageDirection::ClientToServer,
                CompositorObjectRule::Valid,
            ),
            (
                COMPOSITOR_KIND_REQUEST,
                COMPOSITOR_REQUEST_SET_STATE,
                size_of::<CompositorSetStateRequest>() as u32,
                CompositorMessageDirection::ClientToServer,
                CompositorObjectRule::Valid,
            ),
            (
                COMPOSITOR_KIND_REQUEST,
                COMPOSITOR_REQUEST_ACK_CONFIGURE,
                size_of::<CompositorAckConfigureRequest>() as u32,
                CompositorMessageDirection::ClientToServer,
                CompositorObjectRule::Valid,
            ),
            (
                COMPOSITOR_KIND_REPLY,
                COMPOSITOR_REPLY_STATUS,
                size_of::<CompositorStatusReply>() as u32,
                CompositorMessageDirection::ServerToClient,
                CompositorObjectRule::Invalid,
            ),
            (
                COMPOSITOR_KIND_EVENT,
                COMPOSITOR_EVENT_CONFIGURE,
                size_of::<CompositorConfigureEvent>() as u32,
                CompositorMessageDirection::ServerToClient,
                CompositorObjectRule::Valid,
            ),
            (
                COMPOSITOR_KIND_EVENT,
                COMPOSITOR_EVENT_CLOSE,
                size_of::<CompositorCloseEvent>() as u32,
                CompositorMessageDirection::ServerToClient,
                CompositorObjectRule::Valid,
            ),
            (
                COMPOSITOR_KIND_EVENT,
                COMPOSITOR_EVENT_FOCUS,
                size_of::<CompositorFocusEvent>() as u32,
                CompositorMessageDirection::ServerToClient,
                CompositorObjectRule::Valid,
            ),
            (
                COMPOSITOR_KIND_EVENT,
                COMPOSITOR_EVENT_POINTER,
                size_of::<CompositorPointerEvent>() as u32,
                CompositorMessageDirection::ServerToClient,
                CompositorObjectRule::Valid,
            ),
            (
                COMPOSITOR_KIND_EVENT,
                COMPOSITOR_EVENT_KEY,
                size_of::<CompositorKeyEvent>() as u32,
                CompositorMessageDirection::ServerToClient,
                CompositorObjectRule::Valid,
            ),
            (
                COMPOSITOR_KIND_EVENT,
                COMPOSITOR_EVENT_TEXT,
                size_of::<CompositorTextEvent>() as u32,
                CompositorMessageDirection::ServerToClient,
                CompositorObjectRule::Valid,
            ),
            (
                COMPOSITOR_KIND_EVENT,
                COMPOSITOR_EVENT_FRAME_DONE,
                size_of::<CompositorFrameDoneEvent>() as u32,
                CompositorMessageDirection::ServerToClient,
                CompositorObjectRule::Valid,
            ),
            (
                COMPOSITOR_KIND_EVENT,
                COMPOSITOR_EVENT_BUFFER_RELEASE,
                size_of::<CompositorBufferReleaseEvent>() as u32,
                CompositorMessageDirection::ServerToClient,
                CompositorObjectRule::Valid,
            ),
        ];
        assert_eq!(cases.len(), 17);

        for (kind, opcode, payload_size, direction, object_rule) in cases {
            let schema = compositor_opcode_schema(kind, opcode).expect("known schema");
            assert_eq!(schema.kind, kind);
            assert_eq!(schema.opcode, opcode);
            assert_eq!(schema.payload_size, payload_size);
            assert_eq!(schema.direction, direction);
            assert_eq!(schema.object_rule, object_rule);
            assert!(is_known_opcode(kind, opcode));

            let object = match object_rule {
                CompositorObjectRule::Invalid => CompositorHandle::INVALID,
                CompositorObjectRule::Valid => CompositorHandle::from_parts(2, 4),
            };
            let header = CompositorHeader::new(kind, opcode, payload_size, 1, object);
            assert!(header.is_valid_message(direction, header.message_size));
            let opposite = match direction {
                CompositorMessageDirection::ClientToServer => {
                    CompositorMessageDirection::ServerToClient
                },
                CompositorMessageDirection::ServerToClient => {
                    CompositorMessageDirection::ClientToServer
                },
            };
            assert!(!header.is_valid_for_direction(opposite));
        }

        assert!(compositor_opcode_schema(0, 0).is_none());
        assert!(compositor_opcode_schema(COMPOSITOR_KIND_EVENT, u16::MAX).is_none());
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
        assert!(!header.is_valid_for_payload(size_of::<CompositorCommitRequest>() as u32 - 1));
        assert!(header.is_complete_in(header.message_size));
        assert!(!header.is_complete_in(header.message_size - 1));
        assert!(!header.is_complete_in(header.message_size + 1));
        assert!(header.is_valid_message(
            CompositorMessageDirection::ClientToServer,
            header.message_size
        ));
        assert!(!header.is_valid_for_direction(CompositorMessageDirection::ServerToClient));

        let mut corrupt = header;
        corrupt.magic ^= 1;
        assert!(!corrupt.is_valid());
        corrupt = header;
        corrupt.version += 1;
        assert!(!corrupt.is_valid());
        corrupt = header;
        corrupt.header_size -= 1;
        assert!(!corrupt.is_valid());
        corrupt = header;
        corrupt.flags = 1;
        assert!(!corrupt.is_valid());
        corrupt = header;
        corrupt.reserved = 1;
        assert!(!corrupt.is_valid());
        corrupt = header;
        corrupt.serial = 0;
        assert!(!corrupt.is_valid());
        corrupt = header;
        corrupt.object = CompositorHandle::INVALID;
        assert!(!corrupt.is_valid());
        corrupt = header;
        corrupt.opcode = u16::MAX;
        assert!(!corrupt.is_valid());
        corrupt = header;
        corrupt.message_size -= 1;
        assert!(!corrupt.is_valid());
        corrupt = header;
        corrupt.message_size = COMPOSITOR_MAX_MESSAGE_SIZE + 1;
        assert!(!corrupt.is_valid());

        let create = CompositorHeader::new(
            COMPOSITOR_KIND_REQUEST,
            COMPOSITOR_REQUEST_CREATE_SURFACE,
            size_of::<CompositorCreateSurfaceRequest>() as u32,
            10,
            CompositorHandle::INVALID,
        );
        assert!(create.is_valid());
        let mut corrupt_create = create;
        corrupt_create.object = CompositorHandle::from_parts(1, 1);
        assert!(!corrupt_create.is_valid());
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

    #[test]
    fn request_payloads_require_canonical_reserved_fields() {
        let mut create = CompositorCreateSurfaceRequest::default();
        assert!(create.is_valid());
        create.reserved[0] = 1;
        assert!(!create.is_valid());

        let mut destroy = CompositorDestroySurfaceRequest::default();
        assert!(destroy.is_valid());
        destroy.reserved[1] = 1;
        assert!(!destroy.is_valid());

        let surface = CompositorSurfaceMetadata {
            width: 64,
            height: 64,
            stride: 256,
            format: COMPOSITOR_FORMAT_BGRX8888,
            buffer_token: 7,
            offset: 0,
            length: 64 * 64 * 4,
            reserved: [0; 2],
        };
        let attach = CompositorAttachBufferRequest { surface };
        assert!(attach.is_valid(surface.length));
        assert!(!attach.is_valid(surface.length - 1));

        let mut role = CompositorSetRoleRequest {
            role: COMPOSITOR_ROLE_POPUP,
            parent: CompositorHandle::from_parts(1, 1),
            ..CompositorSetRoleRequest::default()
        };
        assert!(role.is_valid());
        role.flags = 1;
        assert!(!role.is_valid());

        let mut state = CompositorSetStateRequest {
            state: COMPOSITOR_STATE_MAXIMIZED,
            mask: COMPOSITOR_STATE_MAXIMIZED,
            reserved: [0; 2],
        };
        assert!(state.is_valid());
        state.state |= COMPOSITOR_STATE_FULLSCREEN;
        assert!(!state.is_valid());
    }

    #[test]
    fn status_codes_and_status_payload_are_canonical() {
        let statuses = [
            COMPOSITOR_STATUS_OK,
            COMPOSITOR_STATUS_INVALID_ARGUMENT,
            COMPOSITOR_STATUS_NOT_FOUND,
            COMPOSITOR_STATUS_ALREADY_EXISTS,
            COMPOSITOR_STATUS_ACCESS_DENIED,
            COMPOSITOR_STATUS_NO_MEMORY,
            COMPOSITOR_STATUS_RESOURCE_EXHAUSTED,
            COMPOSITOR_STATUS_UNSUPPORTED,
            COMPOSITOR_STATUS_INVALID_STATE,
        ];
        for (index, status) in statuses.iter().copied().enumerate() {
            assert!(is_known_status(status));
            if index != 0 {
                assert!(status < 0);
            }
            assert!(!statuses[..index].contains(&status));
        }
        assert!(!is_known_status(1));
        assert!(!is_known_status(-9));

        let mut reply = CompositorStatusReply::default();
        assert!(reply.is_valid());
        reply.value = CompositorHandle::from_parts(4, 2);
        assert!(reply.is_valid());
        reply.status = COMPOSITOR_STATUS_INVALID_ARGUMENT;
        assert!(!reply.is_valid());
        reply.value = CompositorHandle::INVALID;
        assert!(reply.is_valid());
        reply.status = -9;
        assert!(!reply.is_valid());
        reply.status = COMPOSITOR_STATUS_OK;
        reply.value = CompositorHandle::from_parts(4, 0);
        assert!(!reply.is_valid());
        reply.value = CompositorHandle::INVALID;
        reply.reserved2[0] = 1;
        assert!(!reply.is_valid());
    }

    #[test]
    fn server_event_payloads_reject_noncanonical_values() {
        let mut configure = CompositorConfigureEvent {
            width: 800,
            height: 600,
            state: COMPOSITOR_STATE_ACTIVATED,
            scale_milli: 1000,
            reserved: [0; 2],
        };
        assert!(configure.is_valid());
        configure.scale_milli = 0;
        assert!(!configure.is_valid());
        configure.scale_milli = 1000;
        configure.state = 1 << 31;
        assert!(!configure.is_valid());

        let mut close = CompositorCloseEvent::default();
        assert!(close.is_valid());
        close.reserved = 1;
        assert!(!close.is_valid());

        let mut focus = CompositorFocusEvent::default();
        assert!(focus.is_valid());
        focus.focused = 2;
        assert!(!focus.is_valid());

        let mut pointer = CompositorPointerEvent {
            action: COMPOSITOR_POINTER_ACTION_MOTION,
            ..CompositorPointerEvent::default()
        };
        assert!(pointer.is_valid());
        pointer.changed_button = 1;
        assert!(!pointer.is_valid());
        pointer.action = COMPOSITOR_POINTER_ACTION_BUTTON;
        assert!(pointer.is_valid());
        pointer.changed_button = 3;
        assert!(!pointer.is_valid());
        pointer.action = COMPOSITOR_POINTER_ACTION_AXIS;
        pointer.changed_button = 0;
        pointer.axis_y = -1;
        assert!(pointer.is_valid());
        pointer.reserved2[1] = 1;
        assert!(!pointer.is_valid());

        let mut key = CompositorKeyEvent {
            state: COMPOSITOR_KEY_PRESSED,
            ..CompositorKeyEvent::default()
        };
        assert!(key.is_valid());
        key.state = COMPOSITOR_KEY_REPEATED;
        assert!(!key.is_valid());
        key.repeat_count = 1;
        assert!(key.is_valid());
        key.state = u16::MAX;
        assert!(!key.is_valid());

        let mut frame = CompositorFrameDoneEvent {
            frame_token: 1,
            ..CompositorFrameDoneEvent::default()
        };
        assert!(frame.is_valid());
        frame.frame_token = 0;
        assert!(!frame.is_valid());
        frame.frame_token = 1;
        frame.flags = 1;
        assert!(!frame.is_valid());

        assert_eq!(size_of::<CompositorBufferReleaseEvent>(), 32);
        assert_eq!(align_of::<CompositorBufferReleaseEvent>(), 8);
        assert_eq!(
            core::mem::offset_of!(CompositorBufferReleaseEvent, buffer_token),
            0
        );
        assert_eq!(
            core::mem::offset_of!(CompositorBufferReleaseEvent, reserved2),
            16
        );
        let mut release = CompositorBufferReleaseEvent {
            buffer_token: 9,
            ..CompositorBufferReleaseEvent::default()
        };
        assert!(release.is_valid());
        release.buffer_token = 0;
        assert!(!release.is_valid());
        release.buffer_token = 9;
        release.reserved2[0] = 1;
        assert!(!release.is_valid());
    }
}
