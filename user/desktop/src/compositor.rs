//! Allocation-free compositor protocol and bounded multi-client scene state.
//!
//! This module deliberately contains no syscalls and touches no framebuffer.
//! [`CompositorState`] is the transaction engine for one connection.
//! [`MultiClientCompositor`] isolates a fixed number of those engines and owns
//! global resource policy, scene ordering, focus routing, and damage merging.
//! The caller executes returned actions and performs mappings; idle operation
//! therefore needs only channel/UI readiness waits, never periodic polling.

use core::str;

use xenith_abi::ipc::{IpcReceiveMessage, IPC_TRANSFER_RIGHT_MAP, IPC_TRANSFER_RIGHT_READ};
use xenith_abi::{
    compositor as wire, UiInputEvent, UI_EVENT_FLAG_OVERFLOW, UI_EVENT_FLAG_PRESSED,
    UI_EVENT_FLAG_REPEAT, UI_EVENT_KEY, UI_EVENT_POINTER, UI_MODIFIER_CAPS_LOCK,
    UI_MODIFIER_LEFT_ALT, UI_MODIFIER_LEFT_CTRL, UI_MODIFIER_LEFT_SHIFT, UI_MODIFIER_LEFT_SUPER,
    UI_MODIFIER_NUM_LOCK, UI_MODIFIER_RIGHT_ALT, UI_MODIFIER_RIGHT_CTRL, UI_MODIFIER_RIGHT_SHIFT,
    UI_MODIFIER_RIGHT_SUPER, UI_MODIFIER_SCROLL_LOCK, UI_POINTER_BUTTON_BACK,
    UI_POINTER_BUTTON_FORWARD, UI_POINTER_BUTTON_LEFT, UI_POINTER_BUTTON_MIDDLE,
    UI_POINTER_BUTTON_RIGHT,
};

/// One client may own at most this many live surfaces.
pub const MAX_CLIENT_SURFACES: usize = 8;
/// Maximum simultaneous compositor connections.
pub const MAX_COMPOSITOR_CLIENTS: usize = 8;
/// Maximum number of scene entries across all clients.
pub const MAX_SCENE_SURFACES: usize = MAX_COMPOSITOR_CLIENTS * MAX_CLIENT_SURFACES;
/// One current and one pending mapping per surface, plus transactional scratch.
pub const MAX_CLIENT_BUFFER_MAPPINGS: usize = MAX_CLIENT_SURFACES * 2 + 1;
/// Hard per-client resident shared-buffer budget.
pub const MAX_CLIENT_MAPPED_BYTES: u64 = 64 * 1024 * 1024;
/// Hard compositor-wide resident shared-buffer budget.
pub const MAX_COMPOSITOR_MAPPED_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum normalized display-damage rectangles retained between submissions.
pub const MAX_SCENE_DAMAGE_RECTS: usize = 12;
/// Focus transition plus every possible button/motion/axis event in one input sample.
pub const MAX_ROUTED_MESSAGES: usize = 12;
/// Maximum externally visible actions produced by one committed request.
pub const MAX_COMPOSITOR_ACTIONS: usize = 6;
/// Largest server record emitted here: header plus frame-done payload.
pub const MAX_ENCODED_MESSAGE_BYTES: usize = 128;

const UI_MODIFIER_ALL: u16 = UI_MODIFIER_LEFT_SHIFT
    | UI_MODIFIER_RIGHT_SHIFT
    | UI_MODIFIER_LEFT_CTRL
    | UI_MODIFIER_RIGHT_CTRL
    | UI_MODIFIER_LEFT_ALT
    | UI_MODIFIER_RIGHT_ALT
    | UI_MODIFIER_LEFT_SUPER
    | UI_MODIFIER_RIGHT_SUPER
    | UI_MODIFIER_CAPS_LOCK
    | UI_MODIFIER_NUM_LOCK
    | UI_MODIFIER_SCROLL_LOCK;
const UI_POINTER_BUTTON_ALL: u16 = UI_POINTER_BUTTON_LEFT
    | UI_POINTER_BUTTON_RIGHT
    | UI_POINTER_BUTTON_MIDDLE
    | UI_POINTER_BUTTON_BACK
    | UI_POINTER_BUTTON_FORWARD;

const PAGE_SIZE: u64 = 4096;
const REQUIRED_ATTACH_RIGHTS: u32 = IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_MAP;

/// A complete server-to-client compositor record, ready to place in an IPC
/// message payload. The inactive tail is always zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedMessage {
    bytes: [u8; MAX_ENCODED_MESSAGE_BYTES],
    length: u16,
}

impl EncodedMessage {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.length as usize
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

/// Mapping request the runtime must complete before committing an attach.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapBufferAction {
    pub descriptor: i32,
    pub buffer_token: u64,
    pub mapping_offset: u64,
    pub mapping_length: u64,
    /// Byte offset from the returned page-aligned mapping to surface byte 0.
    pub data_offset: u64,
    pub data_length: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
}

/// Successful result of the runtime's `MapBufferAction`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappedBuffer {
    /// Page-aligned userspace address returned by `mmap`.
    pub mapping_address: u64,
}

/// Mapping retained by the compositor for a pending or current buffer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BufferSnapshot {
    pub mapping_address: u64,
    pub mapping_length: u64,
    pub data_offset: u64,
    pub data_length: u64,
    pub buffer_token: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
}

impl BufferSnapshot {
    /// Exact byte span containing visible pixels. Row padding after the final
    /// row is deliberately excluded, matching `CompositorSurfaceMetadata`.
    #[must_use]
    pub const fn required_data_bytes(self) -> Option<u64> {
        if self.width == 0 || self.height == 0 {
            return None;
        }
        let row_bytes = match (self.width as u64).checked_mul(4) {
            Some(bytes) => bytes,
            None => return None,
        };
        if (self.stride as u64) < row_bytes {
            return None;
        }
        let prior_rows = match (self.height as u64 - 1).checked_mul(self.stride as u64) {
            Some(bytes) => bytes,
            None => return None,
        };
        prior_rows.checked_add(row_bytes)
    }
}

/// The runtime must stop using and unmap this retired buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnmapBufferAction {
    pub mapping_address: u64,
    pub mapping_length: u64,
    pub buffer_token: u64,
}

/// Render/copy decision for one accepted commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PresentAction {
    pub surface: wire::CompositorHandle,
    pub request_serial: u64,
    pub buffer: BufferSnapshot,
    pub damage_count: u8,
    pub damage: [wire::CompositorDamageRect; wire::COMPOSITOR_MAX_DAMAGE_RECTS as usize],
}

/// Deferred frame acknowledgement. After presentation, pass this ticket to
/// [`CompositorState::complete_frame`] with real timing information.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameDoneDecision {
    pub surface: wire::CompositorHandle,
    pub frame_token: u64,
}

/// External work emitted by a committed transaction, in execution order.
// The large Present variant is the allocation-free ownership boundary for a
// protocol-bounded 64-rectangle commit. Boxing it would violate this module's
// no-allocator contract.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositorAction {
    Present(PresentAction),
    UnmapBuffer(UnmapBufferAction),
    Event(EncodedMessage),
    Reply(EncodedMessage),
    FrameDone(FrameDoneDecision),
}

/// Fixed-capacity action batch. No request can exceed the public bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionBatch {
    actions: [Option<CompositorAction>; MAX_COMPOSITOR_ACTIONS],
    length: u8,
}

impl ActionBatch {
    const fn new() -> Self {
        Self {
            actions: [None; MAX_COMPOSITOR_ACTIONS],
            length: 0,
        }
    }

    fn push(&mut self, action: CompositorAction) -> Result<(), TransactionError> {
        let index = self.length as usize;
        let Some(slot) = self.actions.get_mut(index) else {
            return Err(TransactionError::ActionCapacityInvariant);
        };
        *slot = Some(action);
        self.length += 1;
        Ok(())
    }

    #[must_use]
    pub fn as_slice(&self) -> &[Option<CompositorAction>] {
        &self.actions[..self.length as usize]
    }

    pub fn iter(&self) -> impl Iterator<Item = &CompositorAction> {
        self.as_slice().iter().filter_map(Option::as_ref)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.length as usize
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

/// Read-only state exposed for diagnostics and policy integration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceSnapshot {
    pub handle: wire::CompositorHandle,
    pub role: u16,
    pub parent: wire::CompositorHandle,
    pub state: u32,
    pub configure_serial: u64,
    pub acknowledged_configure_serial: u64,
    pub configured_width: u32,
    pub configured_height: u32,
    pub scale_milli: u32,
    pub title_length: u16,
    pub title: [u8; wire::COMPOSITOR_MAX_TITLE_BYTES as usize],
    pub pending_buffer: Option<BufferSnapshot>,
    pub current_buffer: Option<BufferSnapshot>,
    pub last_commit_serial: u64,
    pub outstanding_frame_token: u64,
}

/// Generation-protected connection identifier. It is never placed on the
/// client wire; surface handles remain connection-local by design.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct ClientHandle(pub u64);

impl ClientHandle {
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

/// Globally unambiguous reference used only by compositor policy and runtime.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct SurfaceId {
    pub client: ClientHandle,
    pub surface: wire::CompositorHandle,
}

impl SurfaceId {
    #[must_use]
    pub const fn new(client: ClientHandle, surface: wire::CompositorHandle) -> Self {
        Self { client, surface }
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.client.is_valid() && self.surface.is_valid()
    }
}

/// Signed display-space surface rectangle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SceneRect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl SceneRect {
    #[must_use]
    pub const fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.width == 0 || self.height == 0
    }

    fn clipped_to(self, clip: Self) -> Option<Self> {
        let left = (self.x as i64).max(clip.x as i64);
        let top = (self.y as i64).max(clip.y as i64);
        let right = (self.x as i64 + self.width as i64).min(clip.x as i64 + clip.width as i64);
        let bottom = (self.y as i64 + self.height as i64).min(clip.y as i64 + clip.height as i64);
        if right <= left || bottom <= top {
            return None;
        }
        Some(Self::new(
            left as i32,
            top as i32,
            (right - left) as u32,
            (bottom - top) as u32,
        ))
    }

    fn touches(self, other: Self) -> bool {
        let self_right = self.x as i64 + self.width as i64;
        let self_bottom = self.y as i64 + self.height as i64;
        let other_right = other.x as i64 + other.width as i64;
        let other_bottom = other.y as i64 + other.height as i64;
        self.x as i64 <= other_right
            && other.x as i64 <= self_right
            && self.y as i64 <= other_bottom
            && other.y as i64 <= self_bottom
    }

    fn union(self, other: Self) -> Self {
        let left = (self.x as i64).min(other.x as i64);
        let top = (self.y as i64).min(other.y as i64);
        let right = (self.x as i64 + self.width as i64).max(other.x as i64 + other.width as i64);
        let bottom = (self.y as i64 + self.height as i64).max(other.y as i64 + other.height as i64);
        Self::new(
            left as i32,
            top as i32,
            (right - left) as u32,
            (bottom - top) as u32,
        )
    }

    #[must_use]
    pub fn contains(self, x: i32, y: i32) -> bool {
        !self.is_empty()
            && (x as i64) >= self.x as i64
            && (y as i64) >= self.y as i64
            && (x as i64) < self.x as i64 + self.width as i64
            && (y as i64) < self.y as i64 + self.height as i64
    }
}

/// One bottom-to-top scene entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SceneEntry {
    pub id: SurfaceId,
    pub bounds: SceneRect,
}

/// Normalized damage drained atomically from the multi-client scene.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SceneDamageBatch {
    rects: [SceneRect; MAX_SCENE_DAMAGE_RECTS],
    length: u8,
    full: bool,
}

impl SceneDamageBatch {
    #[must_use]
    pub fn as_slice(&self) -> &[SceneRect] {
        &self.rects[..self.length as usize]
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.full
    }
}

/// Invalid wire data. These errors never mutate state and normally terminate
/// the offending one-client connection after its received descriptors close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidIpcEnvelope,
    InvalidHeader,
    WrongDirection,
    UnknownOpcode,
    InvalidMessageLength,
    UnexpectedTransfers,
    InvalidPayload,
    RequestSerialOutOfOrder,
}

/// Invalid server construction parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateError {
    InvalidConfiguration,
}

/// A prepared transaction could not be committed. State remains unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionError {
    StaleTransaction,
    MappingRequired,
    UnexpectedMapping,
    InvalidMapping,
    InvalidAbortStatus,
    EventSerialExhausted,
    ActionCapacityInvariant,
    StateInvariant,
}

/// Multi-client admission or lookup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultiClientError {
    ClientCapacity,
    InvalidClient,
    ClientFaulted,
    InvalidSurface,
    InvalidGeometry,
    SceneCapacity,
    MappingQuota,
    InvalidInput,
    Transaction(TransactionError),
}

impl From<TransactionError> for MultiClientError {
    fn from(error: TransactionError) -> Self {
        Self::Transaction(error)
    }
}

/// A malformed request faults only the named connection. The caller should
/// close that endpoint and invoke [`MultiClientCompositor::disconnect`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientProtocolFault {
    pub client: ClientHandle,
    pub error: ProtocolError,
}

/// Failure from multi-client request preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultiPrepareError {
    Client(MultiClientError),
    Protocol(ClientProtocolFault),
}

/// Prepared request tied to one generation-protected connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiPreparedRequest {
    client: ClientHandle,
    request: PreparedRequest,
}

impl MultiPreparedRequest {
    #[must_use]
    pub const fn client(&self) -> ClientHandle {
        self.client
    }

    #[must_use]
    pub const fn request_serial(&self) -> u64 {
        self.request.request_serial()
    }

    #[must_use]
    pub const fn map_action(&self) -> Option<MapBufferAction> {
        self.request.map_action()
    }
}

/// A normal per-client action batch plus any policy events routed to other
/// connections (currently focus transitions).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchBatch {
    pub client: ClientHandle,
    pub actions: ActionBatch,
    pub routed: RoutedMessageBatch,
}

/// One encoded server event and its destination connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutedMessage {
    pub client: ClientHandle,
    pub message: EncodedMessage,
}

/// Bounded routed server events produced by one policy or input operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutedMessageBatch {
    messages: [Option<RoutedMessage>; MAX_ROUTED_MESSAGES],
    length: u8,
}

impl RoutedMessageBatch {
    const fn new() -> Self {
        Self {
            messages: [None; MAX_ROUTED_MESSAGES],
            length: 0,
        }
    }

    fn push(&mut self, message: RoutedMessage) -> Result<(), MultiClientError> {
        let Some(slot) = self.messages.get_mut(self.length as usize) else {
            return Err(MultiClientError::Transaction(
                TransactionError::ActionCapacityInvariant,
            ));
        };
        *slot = Some(message);
        self.length += 1;
        Ok(())
    }

    fn append(&mut self, other: Self) -> Result<(), MultiClientError> {
        for message in other.iter().copied() {
            self.push(message)?;
        }
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &RoutedMessage> {
        self.messages[..self.length as usize]
            .iter()
            .filter_map(Option::as_ref)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.length as usize
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

/// Mapping retirement emitted when one client disconnects. No release events
/// are sent because that transport is already unusable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisconnectCleanup {
    pub client: ClientHandle,
    unmaps: [Option<UnmapBufferAction>; MAX_CLIENT_SURFACES * 2],
    unmap_count: u8,
    pub routed: RoutedMessageBatch,
}

impl DisconnectCleanup {
    fn new(client: ClientHandle) -> Self {
        Self {
            client,
            unmaps: [None; MAX_CLIENT_SURFACES * 2],
            unmap_count: 0,
            routed: RoutedMessageBatch::new(),
        }
    }

    fn push_unmap(&mut self, action: UnmapBufferAction) -> Result<(), MultiClientError> {
        let Some(slot) = self.unmaps.get_mut(self.unmap_count as usize) else {
            return Err(MultiClientError::Transaction(
                TransactionError::ActionCapacityInvariant,
            ));
        };
        *slot = Some(action);
        self.unmap_count += 1;
        Ok(())
    }

    pub fn unmaps(&self) -> impl Iterator<Item = &UnmapBufferAction> {
        self.unmaps[..self.unmap_count as usize]
            .iter()
            .filter_map(Option::as_ref)
    }

    #[must_use]
    pub const fn unmap_count(&self) -> usize {
        self.unmap_count as usize
    }
}

/// Completion supplied to [`CompositorState::commit`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalCompletion {
    None,
    BufferMapped(MappedBuffer),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Surface {
    role: u16,
    parent: wire::CompositorHandle,
    state: u32,
    configure_serial: u64,
    acknowledged_configure_serial: u64,
    configured_width: u32,
    configured_height: u32,
    scale_milli: u32,
    title_length: u16,
    title: [u8; wire::COMPOSITOR_MAX_TITLE_BYTES as usize],
    pending_buffer: Option<BufferSnapshot>,
    current_buffer: Option<BufferSnapshot>,
    last_commit_serial: u64,
    outstanding_frame_token: u64,
}

impl Surface {
    const fn new() -> Self {
        Self {
            role: wire::COMPOSITOR_ROLE_NONE,
            parent: wire::CompositorHandle::INVALID,
            state: 0,
            configure_serial: 0,
            acknowledged_configure_serial: 0,
            configured_width: 0,
            configured_height: 0,
            scale_milli: 0,
            title_length: 0,
            title: [0; wire::COMPOSITOR_MAX_TITLE_BYTES as usize],
            pending_buffer: None,
            current_buffer: None,
            last_commit_serial: 0,
            outstanding_frame_token: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SurfaceSlot {
    generation: u32,
    surface: Option<Surface>,
}

impl SurfaceSlot {
    const EMPTY: Self = Self {
        generation: 1,
        surface: None,
    };
}

// Prepared commits retain their bounded damage list by value so a caller can
// complete mapping work without borrowing the receive buffer.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreparedOperation {
    ReplyOnly {
        status: i32,
    },
    Create {
        slot: usize,
        handle: wire::CompositorHandle,
    },
    Destroy {
        slot: usize,
        handle: wire::CompositorHandle,
    },
    Attach {
        slot: usize,
        handle: wire::CompositorHandle,
        map: MapBufferAction,
    },
    Commit {
        slot: usize,
        handle: wire::CompositorHandle,
        frame_token: u64,
        request_frame_done: bool,
        damage_count: u8,
        damage: [wire::CompositorDamageRect; wire::COMPOSITOR_MAX_DAMAGE_RECTS as usize],
    },
    SetRole {
        slot: usize,
        handle: wire::CompositorHandle,
        role: u16,
        parent: wire::CompositorHandle,
    },
    SetTitle {
        slot: usize,
        title_length: u16,
        title: [u8; wire::COMPOSITOR_MAX_TITLE_BYTES as usize],
    },
    SetState {
        slot: usize,
        handle: wire::CompositorHandle,
        state: u32,
    },
    AckConfigure {
        slot: usize,
        configure_serial: u64,
    },
}

/// Non-forgeable request plan. Preparing never changes compositor state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedRequest {
    epoch: u64,
    request_serial: u64,
    operation: PreparedOperation,
}

impl PreparedRequest {
    /// Mapping work required before commit, if any.
    #[must_use]
    pub const fn map_action(&self) -> Option<MapBufferAction> {
        match self.operation {
            PreparedOperation::Attach { map, .. } => Some(map),
            _ => None,
        }
    }

    #[must_use]
    pub const fn request_serial(&self) -> u64 {
        self.request_serial
    }
}

/// Fixed one-client compositor state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositorState {
    surfaces: [SurfaceSlot; MAX_CLIENT_SURFACES],
    default_width: u32,
    default_height: u32,
    scale_milli: u32,
    last_request_serial: u64,
    next_event_serial: u64,
    epoch: u64,
}

impl CompositorState {
    pub fn new(
        default_width: u32,
        default_height: u32,
        scale_milli: u32,
    ) -> Result<Self, StateError> {
        if default_width == 0
            || default_height == 0
            || default_width > wire::COMPOSITOR_MAX_SURFACE_DIMENSION
            || default_height > wire::COMPOSITOR_MAX_SURFACE_DIMENSION
            || scale_milli == 0
        {
            return Err(StateError::InvalidConfiguration);
        }
        Ok(Self {
            surfaces: [SurfaceSlot::EMPTY; MAX_CLIENT_SURFACES],
            default_width,
            default_height,
            scale_milli,
            last_request_serial: 0,
            next_event_serial: 1,
            epoch: 1,
        })
    }

    #[must_use]
    pub const fn last_request_serial(&self) -> u64 {
        self.last_request_serial
    }

    #[must_use]
    pub fn live_surface_count(&self) -> usize {
        self.surfaces
            .iter()
            .filter(|slot| slot.surface.is_some())
            .count()
    }

    #[must_use]
    pub fn surface(&self, handle: wire::CompositorHandle) -> Option<SurfaceSnapshot> {
        let index = self.surface_index(handle)?;
        let surface = self.surfaces[index].surface?;
        Some(SurfaceSnapshot {
            handle,
            role: surface.role,
            parent: surface.parent,
            state: surface.state,
            configure_serial: surface.configure_serial,
            acknowledged_configure_serial: surface.acknowledged_configure_serial,
            configured_width: surface.configured_width,
            configured_height: surface.configured_height,
            scale_milli: surface.scale_milli,
            title_length: surface.title_length,
            title: surface.title,
            pending_buffer: surface.pending_buffer,
            current_buffer: surface.current_buffer,
            last_commit_serial: surface.last_commit_serial,
            outstanding_frame_token: surface.outstanding_frame_token,
        })
    }

    /// Decode and validate one complete client request without mutating state.
    pub fn prepare(&self, message: &IpcReceiveMessage) -> Result<PreparedRequest, ProtocolError> {
        let decoded = decode_request(message, self.last_request_serial)?;
        let request_serial = decoded.header.serial;
        let object = decoded.header.object;
        let operation = match decoded.payload {
            DecodedPayload::Create => match self
                .surfaces
                .iter()
                .enumerate()
                .find(|(_, slot)| slot.surface.is_none())
            {
                Some((slot, entry)) => PreparedOperation::Create {
                    slot,
                    handle: wire::CompositorHandle::from_parts(slot as u32 + 1, entry.generation),
                },
                None => PreparedOperation::ReplyOnly {
                    status: wire::COMPOSITOR_STATUS_RESOURCE_EXHAUSTED,
                },
            },
            DecodedPayload::Destroy => {
                let Some(slot) = self.surface_index(object) else {
                    return Ok(self.reply_plan(request_serial, wire::COMPOSITOR_STATUS_NOT_FOUND));
                };
                let has_child = self.surfaces.iter().any(|entry| {
                    entry
                        .surface
                        .is_some_and(|surface| surface.parent == object)
                });
                if has_child {
                    PreparedOperation::ReplyOnly {
                        status: wire::COMPOSITOR_STATUS_INVALID_STATE,
                    }
                } else {
                    PreparedOperation::Destroy {
                        slot,
                        handle: object,
                    }
                }
            },
            DecodedPayload::Attach { surface, transfer } => {
                let Some(slot) = self.surface_index(object) else {
                    return Ok(self.reply_plan(request_serial, wire::COMPOSITOR_STATUS_NOT_FOUND));
                };
                if self.buffer_token_in_use(surface.buffer_token) {
                    PreparedOperation::ReplyOnly {
                        status: wire::COMPOSITOR_STATUS_ALREADY_EXISTS,
                    }
                } else {
                    let Some(map) = map_action(transfer.installed_fd, surface) else {
                        return Err(ProtocolError::InvalidPayload);
                    };
                    PreparedOperation::Attach {
                        slot,
                        handle: object,
                        map,
                    }
                }
            },
            DecodedPayload::Commit {
                frame_token,
                flags,
                damage_count,
                damage,
            } => {
                let Some(slot) = self.surface_index(object) else {
                    return Ok(self.reply_plan(request_serial, wire::COMPOSITOR_STATUS_NOT_FOUND));
                };
                let surface = self.surfaces[slot]
                    .surface
                    .ok_or(ProtocolError::InvalidPayload)?;
                let Some(buffer) = surface.pending_buffer.or(surface.current_buffer) else {
                    return Ok(
                        self.reply_plan(request_serial, wire::COMPOSITOR_STATUS_INVALID_STATE)
                    );
                };
                if surface.role != wire::COMPOSITOR_ROLE_NONE
                    && (surface.configure_serial == 0
                        || surface.acknowledged_configure_serial != surface.configure_serial
                        || buffer.width != surface.configured_width
                        || buffer.height != surface.configured_height)
                {
                    return Ok(
                        self.reply_plan(request_serial, wire::COMPOSITOR_STATUS_INVALID_STATE)
                    );
                }
                if damage[..damage_count as usize]
                    .iter()
                    .any(|rect| !rect.is_valid_for(buffer.width, buffer.height))
                {
                    return Ok(
                        self.reply_plan(request_serial, wire::COMPOSITOR_STATUS_INVALID_ARGUMENT)
                    );
                }
                let request_frame_done = flags & wire::COMPOSITOR_COMMIT_REQUEST_FRAME_DONE != 0;
                if request_frame_done && surface.outstanding_frame_token != 0 {
                    return Ok(
                        self.reply_plan(request_serial, wire::COMPOSITOR_STATUS_RESOURCE_EXHAUSTED)
                    );
                }
                PreparedOperation::Commit {
                    slot,
                    handle: object,
                    frame_token,
                    request_frame_done,
                    damage_count,
                    damage,
                }
            },
            DecodedPayload::SetRole { role, parent } => {
                let Some(slot) = self.surface_index(object) else {
                    return Ok(self.reply_plan(request_serial, wire::COMPOSITOR_STATUS_NOT_FOUND));
                };
                let surface = self.surfaces[slot]
                    .surface
                    .ok_or(ProtocolError::InvalidPayload)?;
                if surface.role != wire::COMPOSITOR_ROLE_NONE {
                    PreparedOperation::ReplyOnly {
                        status: wire::COMPOSITOR_STATUS_ALREADY_EXISTS,
                    }
                } else if role == wire::COMPOSITOR_ROLE_CURSOR {
                    // The current software scene has no hardware/software
                    // cursor-surface contract. Do not claim support by
                    // treating a cursor as a normal window.
                    PreparedOperation::ReplyOnly {
                        status: wire::COMPOSITOR_STATUS_UNSUPPORTED,
                    }
                } else if role == wire::COMPOSITOR_ROLE_POPUP
                    && (parent == object || self.surface_index(parent).is_none())
                {
                    PreparedOperation::ReplyOnly {
                        status: wire::COMPOSITOR_STATUS_NOT_FOUND,
                    }
                } else {
                    PreparedOperation::SetRole {
                        slot,
                        handle: object,
                        role,
                        parent,
                    }
                }
            },
            DecodedPayload::SetTitle {
                title_length,
                title,
            } => match self.surface_index(object) {
                Some(slot) => PreparedOperation::SetTitle {
                    slot,
                    title_length,
                    title,
                },
                None => PreparedOperation::ReplyOnly {
                    status: wire::COMPOSITOR_STATUS_NOT_FOUND,
                },
            },
            DecodedPayload::SetState { state, mask } => {
                let Some(slot) = self.surface_index(object) else {
                    return Ok(self.reply_plan(request_serial, wire::COMPOSITOR_STATUS_NOT_FOUND));
                };
                let surface = self.surfaces[slot]
                    .surface
                    .ok_or(ProtocolError::InvalidPayload)?;
                if mask & wire::COMPOSITOR_STATE_ACTIVATED != 0 {
                    // Activation is compositor-owned focus policy. A client
                    // must never be able to mark itself active.
                    PreparedOperation::ReplyOnly {
                        status: wire::COMPOSITOR_STATUS_ACCESS_DENIED,
                    }
                } else if mask != 0 {
                    // Maximize/fullscreen/minimize need policy-owned geometry
                    // and visibility transitions. Until those exist, return a
                    // truthful capability result instead of a no-op success.
                    PreparedOperation::ReplyOnly {
                        status: wire::COMPOSITOR_STATUS_UNSUPPORTED,
                    }
                } else if surface.role != wire::COMPOSITOR_ROLE_TOPLEVEL {
                    PreparedOperation::ReplyOnly {
                        status: wire::COMPOSITOR_STATUS_INVALID_STATE,
                    }
                } else {
                    PreparedOperation::SetState {
                        slot,
                        handle: object,
                        state: (surface.state & !mask) | state,
                    }
                }
            },
            DecodedPayload::AckConfigure { configure_serial } => {
                let Some(slot) = self.surface_index(object) else {
                    return Ok(self.reply_plan(request_serial, wire::COMPOSITOR_STATUS_NOT_FOUND));
                };
                let surface = self.surfaces[slot]
                    .surface
                    .ok_or(ProtocolError::InvalidPayload)?;
                if surface.configure_serial == 0 || configure_serial != surface.configure_serial {
                    PreparedOperation::ReplyOnly {
                        status: wire::COMPOSITOR_STATUS_INVALID_STATE,
                    }
                } else {
                    PreparedOperation::AckConfigure {
                        slot,
                        configure_serial,
                    }
                }
            },
        };
        Ok(PreparedRequest {
            epoch: self.epoch,
            request_serial,
            operation,
        })
    }

    /// Commit a prepared request. All actions are built against a private
    /// fixed-size state copy; `self` changes only after the complete batch is
    /// known to fit and encode successfully.
    pub fn commit(
        &mut self,
        prepared: PreparedRequest,
        completion: ExternalCompletion,
    ) -> Result<ActionBatch, TransactionError> {
        if prepared.epoch != self.epoch {
            return Err(TransactionError::StaleTransaction);
        }
        if prepared.request_serial <= self.last_request_serial {
            return Err(TransactionError::StaleTransaction);
        }
        let expected_map = match prepared.operation {
            PreparedOperation::Attach { map, .. } => Some(map),
            _ => None,
        };
        let mapped = match (expected_map, completion) {
            (Some(map), ExternalCompletion::BufferMapped(mapped)) => {
                if mapped.mapping_address == 0
                    || mapped.mapping_address & (PAGE_SIZE - 1) != 0
                    || mapped
                        .mapping_address
                        .checked_add(map.mapping_length)
                        .is_none()
                {
                    return Err(TransactionError::InvalidMapping);
                }
                Some(mapped)
            },
            (Some(_), ExternalCompletion::None) => return Err(TransactionError::MappingRequired),
            (None, ExternalCompletion::BufferMapped(_)) => {
                return Err(TransactionError::UnexpectedMapping);
            },
            (None, ExternalCompletion::None) => None,
        };

        let mut next = *self;
        let mut actions = ActionBatch::new();
        next.apply(prepared, mapped, &mut actions)?;
        next.last_request_serial = prepared.request_serial;
        next.epoch = next.epoch.wrapping_add(1).max(1);
        *self = next;
        Ok(actions)
    }

    /// Finish a failed attach mapping without installing any buffer. This
    /// consumes the request serial and emits exactly one error reply.
    pub fn abort_mapping(
        &mut self,
        prepared: PreparedRequest,
        status: i32,
    ) -> Result<ActionBatch, TransactionError> {
        if prepared.epoch != self.epoch
            || prepared.request_serial <= self.last_request_serial
            || !matches!(prepared.operation, PreparedOperation::Attach { .. })
        {
            return Err(TransactionError::StaleTransaction);
        }
        if !matches!(
            status,
            wire::COMPOSITOR_STATUS_INVALID_ARGUMENT
                | wire::COMPOSITOR_STATUS_ACCESS_DENIED
                | wire::COMPOSITOR_STATUS_NO_MEMORY
                | wire::COMPOSITOR_STATUS_RESOURCE_EXHAUSTED
        ) {
            return Err(TransactionError::InvalidAbortStatus);
        }
        let mut next = *self;
        let mut actions = ActionBatch::new();
        actions.push(CompositorAction::Reply(encode_status_reply(
            prepared.request_serial,
            status,
            wire::CompositorHandle::INVALID,
        )))?;
        next.last_request_serial = prepared.request_serial;
        next.epoch = next.epoch.wrapping_add(1).max(1);
        *self = next;
        Ok(actions)
    }

    /// Encode a real frame-done event after the runtime has presented the
    /// corresponding [`FrameDoneDecision`].
    pub fn complete_frame(
        &mut self,
        decision: FrameDoneDecision,
        presentation_time_ns: u64,
        refresh_interval_ns: u64,
    ) -> Result<EncodedMessage, TransactionError> {
        let Some(slot) = self.surface_index(decision.surface) else {
            return Err(TransactionError::StateInvariant);
        };
        let outstanding_frame_token = self.surfaces[slot]
            .surface
            .ok_or(TransactionError::StateInvariant)?
            .outstanding_frame_token;
        if decision.frame_token == 0
            || decision.frame_token != outstanding_frame_token
            || refresh_interval_ns == 0
        {
            return Err(TransactionError::StateInvariant);
        }
        let mut next = *self;
        let serial = next.allocate_event_serial()?;
        next.surfaces[slot]
            .surface
            .as_mut()
            .ok_or(TransactionError::StateInvariant)?
            .outstanding_frame_token = 0;
        next.epoch = next.epoch.wrapping_add(1).max(1);
        let message =
            encode_frame_done(serial, decision, presentation_time_ns, refresh_interval_ns);
        *self = next;
        Ok(message)
    }

    fn set_server_focus(
        &mut self,
        surface: wire::CompositorHandle,
        focused: bool,
        seat: u32,
    ) -> Result<EncodedMessage, TransactionError> {
        let Some(slot) = self.surface_index(surface) else {
            return Err(TransactionError::StateInvariant);
        };
        let mut next = *self;
        let serial = next.allocate_event_serial()?;
        let target = next.surfaces[slot]
            .surface
            .as_mut()
            .ok_or(TransactionError::StateInvariant)?;
        if focused {
            target.state |= wire::COMPOSITOR_STATE_ACTIVATED;
        } else {
            target.state &= !wire::COMPOSITOR_STATE_ACTIVATED;
        }
        next.epoch = next.epoch.wrapping_add(1).max(1);
        let message = encode_focus(serial, surface, focused, seat);
        *self = next;
        Ok(message)
    }

    fn can_allocate_event_serials(&self, count: usize) -> bool {
        u64::try_from(count)
            .ok()
            .and_then(|count| self.next_event_serial.checked_add(count))
            .is_some()
    }

    fn pointer_event(
        &mut self,
        surface: wire::CompositorHandle,
        event: wire::CompositorPointerEvent,
    ) -> Result<EncodedMessage, TransactionError> {
        if self.surface_index(surface).is_none() || !event.is_valid() {
            return Err(TransactionError::StateInvariant);
        }
        let mut next = *self;
        let serial = next.allocate_event_serial()?;
        next.epoch = next.epoch.wrapping_add(1).max(1);
        let message = encode_pointer(serial, surface, event);
        *self = next;
        Ok(message)
    }

    fn key_event(
        &mut self,
        surface: wire::CompositorHandle,
        event: wire::CompositorKeyEvent,
    ) -> Result<EncodedMessage, TransactionError> {
        if self.surface_index(surface).is_none() || !event.is_valid() {
            return Err(TransactionError::StateInvariant);
        }
        let mut next = *self;
        let serial = next.allocate_event_serial()?;
        next.epoch = next.epoch.wrapping_add(1).max(1);
        let message = encode_key(serial, surface, event);
        *self = next;
        Ok(message)
    }

    fn text_event(
        &mut self,
        surface: wire::CompositorHandle,
        event: wire::CompositorTextEvent,
    ) -> Result<EncodedMessage, TransactionError> {
        if self.surface_index(surface).is_none() || !event.is_valid() {
            return Err(TransactionError::StateInvariant);
        }
        let mut next = *self;
        let serial = next.allocate_event_serial()?;
        next.epoch = next.epoch.wrapping_add(1).max(1);
        let message = encode_text(serial, surface, &event);
        *self = next;
        Ok(message)
    }

    const fn reply_plan(&self, request_serial: u64, status: i32) -> PreparedRequest {
        PreparedRequest {
            epoch: self.epoch,
            request_serial,
            operation: PreparedOperation::ReplyOnly { status },
        }
    }

    fn surface_index(&self, handle: wire::CompositorHandle) -> Option<usize> {
        if !handle.is_valid() {
            return None;
        }
        let index = handle.slot().checked_sub(1)? as usize;
        let slot = self.surfaces.get(index)?;
        (slot.generation == handle.generation() && slot.surface.is_some()).then_some(index)
    }

    fn buffer_token_in_use(&self, token: u64) -> bool {
        self.surfaces.iter().any(|slot| {
            slot.surface.is_some_and(|surface| {
                surface
                    .pending_buffer
                    .is_some_and(|buffer| buffer.buffer_token == token)
                    || surface
                        .current_buffer
                        .is_some_and(|buffer| buffer.buffer_token == token)
            })
        })
    }

    fn allocate_event_serial(&mut self) -> Result<u64, TransactionError> {
        let serial = self.next_event_serial;
        let next = serial
            .checked_add(1)
            .ok_or(TransactionError::EventSerialExhausted)?;
        self.next_event_serial = next;
        Ok(serial)
    }

    fn apply(
        &mut self,
        prepared: PreparedRequest,
        mapped: Option<MappedBuffer>,
        actions: &mut ActionBatch,
    ) -> Result<(), TransactionError> {
        let serial = prepared.request_serial;
        match prepared.operation {
            PreparedOperation::ReplyOnly { status } => {
                actions.push(CompositorAction::Reply(encode_status_reply(
                    serial,
                    status,
                    wire::CompositorHandle::INVALID,
                )))?;
            },
            PreparedOperation::Create { slot, handle } => {
                let entry = self
                    .surfaces
                    .get_mut(slot)
                    .ok_or(TransactionError::StateInvariant)?;
                if entry.surface.is_some()
                    || entry.generation != handle.generation()
                    || handle.slot() != slot as u32 + 1
                {
                    return Err(TransactionError::StateInvariant);
                }
                entry.surface = Some(Surface::new());
                actions.push(CompositorAction::Reply(encode_status_reply(
                    serial,
                    wire::COMPOSITOR_STATUS_OK,
                    handle,
                )))?;
            },
            PreparedOperation::Destroy { slot, handle } => {
                if self.surface_index(handle) != Some(slot) {
                    return Err(TransactionError::StateInvariant);
                }
                let surface = self.surfaces[slot]
                    .surface
                    .take()
                    .ok_or(TransactionError::StateInvariant)?;
                self.surfaces[slot].generation = next_generation(self.surfaces[slot].generation);
                if let Some(buffer) = surface.pending_buffer {
                    self.retire_buffer(handle, buffer, actions)?;
                }
                if let Some(buffer) = surface.current_buffer {
                    self.retire_buffer(handle, buffer, actions)?;
                }
                actions.push(CompositorAction::Reply(encode_status_reply(
                    serial,
                    wire::COMPOSITOR_STATUS_OK,
                    wire::CompositorHandle::INVALID,
                )))?;
            },
            PreparedOperation::Attach { slot, handle, map } => {
                if self.surface_index(handle) != Some(slot) {
                    return Err(TransactionError::StateInvariant);
                }
                let mapped = mapped.ok_or(TransactionError::MappingRequired)?;
                let buffer = BufferSnapshot {
                    mapping_address: mapped.mapping_address,
                    mapping_length: map.mapping_length,
                    data_offset: map.data_offset,
                    data_length: map.data_length,
                    buffer_token: map.buffer_token,
                    width: map.width,
                    height: map.height,
                    stride: map.stride,
                    format: map.format,
                };
                let replaced = self.surfaces[slot]
                    .surface
                    .as_mut()
                    .ok_or(TransactionError::StateInvariant)?
                    .pending_buffer
                    .replace(buffer);
                if let Some(old) = replaced {
                    self.retire_buffer(handle, old, actions)?;
                }
                actions.push(CompositorAction::Reply(encode_status_reply(
                    serial,
                    wire::COMPOSITOR_STATUS_OK,
                    wire::CompositorHandle::INVALID,
                )))?;
            },
            PreparedOperation::Commit {
                slot,
                handle,
                frame_token,
                request_frame_done,
                damage_count,
                damage,
            } => {
                if self.surface_index(handle) != Some(slot) {
                    return Err(TransactionError::StateInvariant);
                }
                let surface = self.surfaces[slot]
                    .surface
                    .as_mut()
                    .ok_or(TransactionError::StateInvariant)?;
                let replacement = surface.pending_buffer.take();
                let retired = replacement.and_then(|buffer| surface.current_buffer.replace(buffer));
                let buffer = surface
                    .current_buffer
                    .ok_or(TransactionError::StateInvariant)?;
                surface.last_commit_serial = serial;
                if request_frame_done {
                    surface.outstanding_frame_token = frame_token;
                }

                actions.push(CompositorAction::Present(PresentAction {
                    surface: handle,
                    request_serial: serial,
                    buffer,
                    damage_count,
                    damage,
                }))?;
                if let Some(old) = retired {
                    self.retire_buffer(handle, old, actions)?;
                }
                if request_frame_done {
                    actions.push(CompositorAction::FrameDone(FrameDoneDecision {
                        surface: handle,
                        frame_token,
                    }))?;
                }
                actions.push(CompositorAction::Reply(encode_status_reply(
                    serial,
                    wire::COMPOSITOR_STATUS_OK,
                    wire::CompositorHandle::INVALID,
                )))?;
            },
            PreparedOperation::SetRole {
                slot,
                handle,
                role,
                parent,
            } => {
                if self.surface_index(handle) != Some(slot) {
                    return Err(TransactionError::StateInvariant);
                }
                let configure_serial = if role == wire::COMPOSITOR_ROLE_NONE {
                    0
                } else {
                    self.allocate_event_serial()?
                };
                let surface = self.surfaces[slot]
                    .surface
                    .as_mut()
                    .ok_or(TransactionError::StateInvariant)?;
                surface.role = role;
                surface.parent = parent;
                if configure_serial != 0 {
                    configure_surface(
                        surface,
                        configure_serial,
                        self.default_width,
                        self.default_height,
                        self.scale_milli,
                    );
                    actions.push(CompositorAction::Event(encode_configure(
                        configure_serial,
                        handle,
                        surface,
                    )))?;
                }
                actions.push(CompositorAction::Reply(encode_status_reply(
                    serial,
                    wire::COMPOSITOR_STATUS_OK,
                    wire::CompositorHandle::INVALID,
                )))?;
            },
            PreparedOperation::SetTitle {
                slot,
                title_length,
                title,
            } => {
                let surface = self
                    .surfaces
                    .get_mut(slot)
                    .and_then(|entry| entry.surface.as_mut())
                    .ok_or(TransactionError::StateInvariant)?;
                surface.title_length = title_length;
                surface.title = title;
                actions.push(CompositorAction::Reply(encode_status_reply(
                    serial,
                    wire::COMPOSITOR_STATUS_OK,
                    wire::CompositorHandle::INVALID,
                )))?;
            },
            PreparedOperation::SetState {
                slot,
                handle,
                state,
            } => {
                if self.surface_index(handle) != Some(slot) {
                    return Err(TransactionError::StateInvariant);
                }
                let configure_serial = self.allocate_event_serial()?;
                let surface = self.surfaces[slot]
                    .surface
                    .as_mut()
                    .ok_or(TransactionError::StateInvariant)?;
                surface.state = state;
                configure_surface(
                    surface,
                    configure_serial,
                    self.default_width,
                    self.default_height,
                    self.scale_milli,
                );
                actions.push(CompositorAction::Event(encode_configure(
                    configure_serial,
                    handle,
                    surface,
                )))?;
                actions.push(CompositorAction::Reply(encode_status_reply(
                    serial,
                    wire::COMPOSITOR_STATUS_OK,
                    wire::CompositorHandle::INVALID,
                )))?;
            },
            PreparedOperation::AckConfigure {
                slot,
                configure_serial,
            } => {
                let surface = self
                    .surfaces
                    .get_mut(slot)
                    .and_then(|entry| entry.surface.as_mut())
                    .ok_or(TransactionError::StateInvariant)?;
                if surface.configure_serial != configure_serial {
                    return Err(TransactionError::StateInvariant);
                }
                surface.acknowledged_configure_serial = configure_serial;
                actions.push(CompositorAction::Reply(encode_status_reply(
                    serial,
                    wire::COMPOSITOR_STATUS_OK,
                    wire::CompositorHandle::INVALID,
                )))?;
            },
        }
        Ok(())
    }

    fn retire_buffer(
        &mut self,
        surface: wire::CompositorHandle,
        buffer: BufferSnapshot,
        actions: &mut ActionBatch,
    ) -> Result<(), TransactionError> {
        actions.push(CompositorAction::UnmapBuffer(UnmapBufferAction {
            mapping_address: buffer.mapping_address,
            mapping_length: buffer.mapping_length,
            buffer_token: buffer.buffer_token,
        }))?;
        let serial = self.allocate_event_serial()?;
        actions.push(CompositorAction::Event(encode_buffer_release(
            serial,
            surface,
            buffer.buffer_token,
        )))?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClientSlot {
    generation: u32,
    faulted: bool,
    state: Option<CompositorState>,
}

impl ClientSlot {
    const EMPTY: Self = Self {
        generation: 1,
        faulted: false,
        state: None,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SceneDamage {
    bounds: SceneRect,
    rects: [SceneRect; MAX_SCENE_DAMAGE_RECTS],
    length: u8,
    full: bool,
}

impl SceneDamage {
    const fn new(bounds: SceneRect) -> Self {
        Self {
            bounds,
            rects: [SceneRect::new(0, 0, 0, 0); MAX_SCENE_DAMAGE_RECTS],
            length: 0,
            full: false,
        }
    }

    fn add(&mut self, rect: SceneRect) {
        if self.full {
            return;
        }
        let Some(mut candidate) = rect.clipped_to(self.bounds) else {
            return;
        };
        let mut index = 0usize;
        while index < self.length as usize {
            if candidate.touches(self.rects[index]) {
                candidate = candidate.union(self.rects[index]);
                self.length -= 1;
                self.rects[index] = self.rects[self.length as usize];
                index = 0;
            } else {
                index += 1;
            }
        }
        let Some(slot) = self.rects.get_mut(self.length as usize) else {
            self.mark_full();
            return;
        };
        *slot = candidate;
        self.length += 1;
    }

    fn mark_full(&mut self) {
        self.rects.fill(SceneRect::new(0, 0, 0, 0));
        self.rects[0] = self.bounds;
        self.length = 1;
        self.full = true;
    }

    fn take(&mut self) -> SceneDamageBatch {
        let batch = SceneDamageBatch {
            rects: self.rects,
            length: self.length,
            full: self.full,
        };
        self.rects.fill(SceneRect::new(0, 0, 0, 0));
        self.length = 0;
        self.full = false;
        batch
    }
}

/// Fixed-capacity compositor hub. Each connection owns an independent
/// protocol state, while this type owns global scene and resource policy.
pub struct MultiClientCompositor {
    clients: [ClientSlot; MAX_COMPOSITOR_CLIENTS],
    default_width: u32,
    default_height: u32,
    scale_milli: u32,
    scene: [Option<SceneEntry>; MAX_SCENE_SURFACES],
    scene_length: u8,
    focused: Option<SurfaceId>,
    pointer_capture: Option<SurfaceId>,
    pointer_buttons: u16,
    pointer_resync: bool,
    damage: SceneDamage,
}

impl MultiClientCompositor {
    pub fn new(
        display_width: u32,
        display_height: u32,
        default_width: u32,
        default_height: u32,
        scale_milli: u32,
    ) -> Result<Self, StateError> {
        if display_width == 0
            || display_height == 0
            || display_width > wire::COMPOSITOR_MAX_SURFACE_DIMENSION
            || display_height > wire::COMPOSITOR_MAX_SURFACE_DIMENSION
        {
            return Err(StateError::InvalidConfiguration);
        }
        // Reuse the per-client validation contract before publishing policy.
        let _ = CompositorState::new(default_width, default_height, scale_milli)?;
        Ok(Self {
            clients: [ClientSlot::EMPTY; MAX_COMPOSITOR_CLIENTS],
            default_width,
            default_height,
            scale_milli,
            scene: [None; MAX_SCENE_SURFACES],
            scene_length: 0,
            focused: None,
            pointer_capture: None,
            pointer_buttons: 0,
            pointer_resync: false,
            damage: SceneDamage::new(SceneRect::new(0, 0, display_width, display_height)),
        })
    }

    /// Admit one connection or reject it without disturbing existing clients.
    pub fn connect(&mut self) -> Result<ClientHandle, MultiClientError> {
        let Some((index, slot)) = self
            .clients
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.state.is_none())
        else {
            return Err(MultiClientError::ClientCapacity);
        };
        let state = CompositorState::new(self.default_width, self.default_height, self.scale_milli)
            .map_err(|_| MultiClientError::InvalidGeometry)?;
        slot.state = Some(state);
        slot.faulted = false;
        Ok(ClientHandle::from_parts(index as u32 + 1, slot.generation))
    }

    #[must_use]
    pub fn client_count(&self) -> usize {
        self.clients
            .iter()
            .filter(|slot| slot.state.is_some())
            .count()
    }

    #[must_use]
    pub fn scene_surface_count(&self) -> usize {
        self.scene_length as usize
    }

    #[must_use]
    pub fn is_client_faulted(&self, client: ClientHandle) -> bool {
        self.client_index(client)
            .is_some_and(|index| self.clients[index].faulted)
    }

    #[must_use]
    pub const fn focused_surface(&self) -> Option<SurfaceId> {
        self.focused
    }

    #[must_use]
    pub const fn pointer_capture(&self) -> Option<SurfaceId> {
        self.pointer_capture
    }

    pub fn scene_entries(&self) -> impl DoubleEndedIterator<Item = &SceneEntry> {
        self.scene[..self.scene_length as usize]
            .iter()
            .filter_map(Option::as_ref)
    }

    #[must_use]
    pub fn surface(&self, id: SurfaceId) -> Option<SurfaceSnapshot> {
        let index = self.client_index(id.client)?;
        self.clients[index].state.as_ref()?.surface(id.surface)
    }

    /// Decode one request. Malformed wire data faults only this client; valid
    /// semantic errors remain ordinary status replies from `CompositorState`.
    pub fn prepare(
        &mut self,
        client: ClientHandle,
        message: &IpcReceiveMessage,
    ) -> Result<MultiPreparedRequest, MultiPrepareError> {
        let index = self
            .client_index(client)
            .ok_or(MultiPrepareError::Client(MultiClientError::InvalidClient))?;
        if self.clients[index].faulted {
            return Err(MultiPrepareError::Client(MultiClientError::ClientFaulted));
        }
        let result = self.clients[index]
            .state
            .as_ref()
            .ok_or(MultiPrepareError::Client(MultiClientError::InvalidClient))?
            .prepare(message);
        match result {
            Ok(request) => Ok(MultiPreparedRequest { client, request }),
            Err(error) => {
                self.clients[index].faulted = true;
                Err(MultiPrepareError::Protocol(ClientProtocolFault {
                    client,
                    error,
                }))
            },
        }
    }

    /// Check peak retained-plus-scratch mapping usage before calling `mmap`.
    pub fn mapping_permitted(
        &self,
        prepared: &MultiPreparedRequest,
    ) -> Result<(), MultiClientError> {
        let Some(map) = prepared.map_action() else {
            return Ok(());
        };
        let index = self
            .client_index(prepared.client)
            .ok_or(MultiClientError::InvalidClient)?;
        if self.clients[index].faulted {
            return Err(MultiClientError::ClientFaulted);
        }
        let state = self.clients[index]
            .state
            .as_ref()
            .ok_or(MultiClientError::InvalidClient)?;
        let (client_mappings, client_bytes) = mapping_usage(state);
        let global_bytes = self
            .clients
            .iter()
            .filter_map(|slot| slot.state.as_ref())
            .try_fold(0u64, |total, state| {
                total.checked_add(mapping_usage(state).1)
            })
            .ok_or(MultiClientError::MappingQuota)?;
        if client_mappings >= MAX_CLIENT_BUFFER_MAPPINGS
            || client_bytes
                .checked_add(map.mapping_length)
                .is_none_or(|bytes| bytes > MAX_CLIENT_MAPPED_BYTES)
            || global_bytes
                .checked_add(map.mapping_length)
                .is_none_or(|bytes| bytes > MAX_COMPOSITOR_MAPPED_BYTES)
        {
            return Err(MultiClientError::MappingQuota);
        }
        Ok(())
    }

    pub fn commit(
        &mut self,
        prepared: MultiPreparedRequest,
        completion: ExternalCompletion,
    ) -> Result<DispatchBatch, MultiClientError> {
        if matches!(completion, ExternalCompletion::BufferMapped(_)) {
            self.mapping_permitted(&prepared)?;
        }
        let index = self
            .client_index(prepared.client)
            .ok_or(MultiClientError::InvalidClient)?;
        if self.clients[index].faulted {
            return Err(MultiClientError::ClientFaulted);
        }
        let destroyed = match prepared.request.operation {
            PreparedOperation::Destroy { handle, .. } => {
                Some(SurfaceId::new(prepared.client, handle))
            },
            _ => None,
        };
        let actions = self.clients[index]
            .state
            .as_mut()
            .ok_or(MultiClientError::InvalidClient)?
            .commit(prepared.request, completion)?;
        if let Some(id) = destroyed {
            self.remove_scene_surface(id);
            if self.focused == Some(id) {
                self.focused = None;
            }
            if self.pointer_capture == Some(id) {
                self.pointer_capture = None;
                self.pointer_resync = self.pointer_buttons != 0;
            }
        }
        Ok(DispatchBatch {
            client: prepared.client,
            actions,
            routed: RoutedMessageBatch::new(),
        })
    }

    pub fn abort_mapping(
        &mut self,
        prepared: MultiPreparedRequest,
        status: i32,
    ) -> Result<DispatchBatch, MultiClientError> {
        let index = self
            .client_index(prepared.client)
            .ok_or(MultiClientError::InvalidClient)?;
        if self.clients[index].faulted {
            return Err(MultiClientError::ClientFaulted);
        }
        let actions = self.clients[index]
            .state
            .as_mut()
            .ok_or(MultiClientError::InvalidClient)?
            .abort_mapping(prepared.request, status)?;
        Ok(DispatchBatch {
            client: prepared.client,
            actions,
            routed: RoutedMessageBatch::new(),
        })
    }

    pub fn complete_frame(
        &mut self,
        client: ClientHandle,
        decision: FrameDoneDecision,
        presentation_time_ns: u64,
        refresh_interval_ns: u64,
    ) -> Result<EncodedMessage, MultiClientError> {
        let index = self
            .client_index(client)
            .ok_or(MultiClientError::InvalidClient)?;
        if self.clients[index].faulted {
            return Err(MultiClientError::ClientFaulted);
        }
        self.clients[index]
            .state
            .as_mut()
            .ok_or(MultiClientError::InvalidClient)?
            .complete_frame(decision, presentation_time_ns, refresh_interval_ns)
            .map_err(Into::into)
    }

    /// Install or move a committed surface in display space. New entries are
    /// placed on top; moving an entry preserves its relative z-order.
    pub fn place_surface(
        &mut self,
        id: SurfaceId,
        bounds: SceneRect,
    ) -> Result<(), MultiClientError> {
        self.require_operational_client(id.client)?;
        let surface = self.surface(id).ok_or(MultiClientError::InvalidSurface)?;
        let buffer = surface
            .current_buffer
            .ok_or(MultiClientError::InvalidSurface)?;
        if bounds.is_empty()
            || bounds.width != buffer.width
            || bounds.height != buffer.height
            || bounds.clipped_to(self.damage.bounds).is_none()
        {
            return Err(MultiClientError::InvalidGeometry);
        }
        if let Some(index) = self.scene_index(id) {
            let old = self.scene[index]
                .ok_or(MultiClientError::InvalidSurface)?
                .bounds;
            if old != bounds {
                self.damage.add(old);
                self.damage.add(bounds);
                self.scene[index] = Some(SceneEntry { id, bounds });
            }
            return Ok(());
        }
        let index = self.scene_length as usize;
        let Some(slot) = self.scene.get_mut(index) else {
            return Err(MultiClientError::SceneCapacity);
        };
        *slot = Some(SceneEntry { id, bounds });
        self.scene_length += 1;
        self.damage.add(bounds);
        Ok(())
    }

    /// Raise one live surface to the top of the scene.
    pub fn raise_surface(&mut self, id: SurfaceId) -> Result<(), MultiClientError> {
        self.require_operational_client(id.client)?;
        let index = self
            .scene_index(id)
            .ok_or(MultiClientError::InvalidSurface)?;
        let last = self.scene_length as usize - 1;
        if index == last {
            return Ok(());
        }
        let entry = self.scene[index].ok_or(MultiClientError::InvalidSurface)?;
        self.damage.add(entry.bounds);
        self.scene.copy_within(index + 1..=last, index);
        self.scene[last] = Some(entry);
        Ok(())
    }

    /// Add validated surface-local damage to the global normalized batch.
    pub fn damage_surface(
        &mut self,
        id: SurfaceId,
        rectangles: &[wire::CompositorDamageRect],
    ) -> Result<(), MultiClientError> {
        self.require_operational_client(id.client)?;
        let index = self
            .scene_index(id)
            .ok_or(MultiClientError::InvalidSurface)?;
        let entry = self.scene[index].ok_or(MultiClientError::InvalidSurface)?;
        for rectangle in rectangles {
            if !rectangle.is_valid_for(entry.bounds.width, entry.bounds.height) {
                return Err(MultiClientError::InvalidGeometry);
            }
            let x = (entry.bounds.x as i64)
                .checked_add(rectangle.x as i64)
                .and_then(|value| i32::try_from(value).ok())
                .ok_or(MultiClientError::InvalidGeometry)?;
            let y = (entry.bounds.y as i64)
                .checked_add(rectangle.y as i64)
                .and_then(|value| i32::try_from(value).ok())
                .ok_or(MultiClientError::InvalidGeometry)?;
            self.damage
                .add(SceneRect::new(x, y, rectangle.width, rectangle.height));
        }
        Ok(())
    }

    #[must_use]
    pub fn take_damage(&mut self) -> SceneDamageBatch {
        self.damage.take()
    }

    /// Topmost focusable surface containing this display-space point.
    #[must_use]
    pub fn pointer_target(&self, x: i32, y: i32) -> Option<SurfaceId> {
        self.scene_entries()
            .rev()
            .find(|entry| entry.bounds.contains(x, y) && self.is_focusable(entry.id))
            .map(|entry| entry.id)
    }

    /// Current keyboard target, if it remains live and focusable.
    #[must_use]
    pub fn keyboard_target(&self) -> Option<SurfaceId> {
        self.focused.filter(|id| self.is_focusable(*id))
    }

    #[must_use]
    pub fn is_surface_focusable(&self, id: SurfaceId) -> bool {
        self.is_focusable(id)
    }

    /// Transactionally route a focus transition and update activated state.
    pub fn focus_surface(
        &mut self,
        target: SurfaceId,
        seat: u32,
    ) -> Result<RoutedMessageBatch, MultiClientError> {
        self.require_operational_client(target.client)?;
        if self.scene_index(target).is_none() || !self.is_focusable(target) {
            return Err(MultiClientError::InvalidSurface);
        }
        let previous = self.focused;
        if previous == Some(target) {
            return Ok(RoutedMessageBatch::new());
        }
        if let Some(old) = previous {
            self.require_operational_client(old.client)?;
        }

        let mut routed = RoutedMessageBatch::new();
        match previous {
            Some(old) if old.client == target.client => {
                let index = self
                    .client_index(target.client)
                    .ok_or(MultiClientError::InvalidClient)?;
                let mut staged = *self.clients[index]
                    .state
                    .as_ref()
                    .ok_or(MultiClientError::InvalidClient)?;
                let out = staged.set_server_focus(old.surface, false, seat)?;
                let input = staged.set_server_focus(target.surface, true, seat)?;
                routed.push(RoutedMessage {
                    client: old.client,
                    message: out,
                })?;
                routed.push(RoutedMessage {
                    client: target.client,
                    message: input,
                })?;
                self.clients[index].state = Some(staged);
            },
            Some(old) => {
                let old_index = self
                    .client_index(old.client)
                    .ok_or(MultiClientError::InvalidClient)?;
                let target_index = self
                    .client_index(target.client)
                    .ok_or(MultiClientError::InvalidClient)?;
                let mut old_state = *self.clients[old_index]
                    .state
                    .as_ref()
                    .ok_or(MultiClientError::InvalidClient)?;
                let mut target_state = *self.clients[target_index]
                    .state
                    .as_ref()
                    .ok_or(MultiClientError::InvalidClient)?;
                let out = old_state.set_server_focus(old.surface, false, seat)?;
                let input = target_state.set_server_focus(target.surface, true, seat)?;
                routed.push(RoutedMessage {
                    client: old.client,
                    message: out,
                })?;
                routed.push(RoutedMessage {
                    client: target.client,
                    message: input,
                })?;
                self.clients[old_index].state = Some(old_state);
                self.clients[target_index].state = Some(target_state);
            },
            None => {
                let index = self
                    .client_index(target.client)
                    .ok_or(MultiClientError::InvalidClient)?;
                let mut staged = *self.clients[index]
                    .state
                    .as_ref()
                    .ok_or(MultiClientError::InvalidClient)?;
                let input = staged.set_server_focus(target.surface, true, seat)?;
                routed.push(RoutedMessage {
                    client: target.client,
                    message: input,
                })?;
                self.clients[index].state = Some(staged);
            },
        }
        self.focused = Some(target);
        Ok(routed)
    }

    pub fn clear_focus(&mut self, seat: u32) -> Result<RoutedMessageBatch, MultiClientError> {
        let Some(old) = self.focused else {
            return Ok(RoutedMessageBatch::new());
        };
        let index = self.require_operational_client(old.client)?;
        let mut staged = *self.clients[index]
            .state
            .as_ref()
            .ok_or(MultiClientError::InvalidClient)?;
        let message = staged.set_server_focus(old.surface, false, seat)?;
        let mut routed = RoutedMessageBatch::new();
        routed.push(RoutedMessage {
            client: old.client,
            message,
        })?;
        self.clients[index].state = Some(staged);
        self.focused = None;
        Ok(routed)
    }

    /// Route one canonical pointer sample. Button presses focus and raise the
    /// hit-tested surface, then capture it until the final release. Motion and
    /// wheel samples without capture go only to the topmost hit-tested client.
    pub fn route_pointer(
        &mut self,
        event: UiInputEvent,
        display_x: i32,
        display_y: i32,
        delta_x: i32,
        delta_y: i32,
    ) -> Result<RoutedMessageBatch, MultiClientError> {
        if !valid_pointer_input(event) {
            return Err(MultiClientError::InvalidInput);
        }
        if self.pointer_resync {
            self.pointer_buttons = event.buttons;
            if event.buttons == 0 {
                self.pointer_resync = false;
            }
            return Ok(RoutedMessageBatch::new());
        }
        if event.flags & UI_EVENT_FLAG_OVERFLOW != 0 {
            return self.route_pointer_overflow(event, display_x, display_y);
        }

        let old_buttons = self.pointer_buttons;
        let new_buttons = event.buttons;
        let changed = old_buttons ^ new_buttons;
        let newly_pressed = changed & new_buttons;
        let target = if old_buttons == 0 {
            self.pointer_target(display_x, display_y)
        } else {
            self.pointer_capture
                .filter(|id| self.scene_index(*id).is_some() && self.is_focusable(*id))
        };
        let Some(target) = target else {
            self.pointer_buttons = new_buttons;
            if new_buttons == 0 {
                self.pointer_capture = None;
            }
            return Ok(RoutedMessageBatch::new());
        };

        let motion = delta_x != 0 || delta_y != 0;
        let axis = event.value3 != 0;
        let input_count = changed.count_ones() as usize + usize::from(motion) + usize::from(axis);
        let focus_on_press = newly_pressed != 0;
        self.ensure_focus_and_input_capacity(target, input_count, focus_on_press)?;

        let mut routed = RoutedMessageBatch::new();
        if focus_on_press {
            self.raise_surface(target)?;
            routed.append(self.focus_surface(target, 0)?)?;
        }
        let (local_x, local_y) = self.surface_local_position(target, display_x, display_y)?;
        let index = self.require_operational_client(target.client)?;
        let mut staged = *self.clients[index]
            .state
            .as_ref()
            .ok_or(MultiClientError::InvalidClient)?;
        let mut progressive_buttons = old_buttons;
        for button in pointer_button_bits() {
            if changed & button == 0 {
                continue;
            }
            progressive_buttons ^= button;
            let message = staged.pointer_event(target.surface, wire::CompositorPointerEvent {
                timestamp_ns: event.timestamp_ns,
                x: local_x,
                y: local_y,
                buttons: u32::from(progressive_buttons),
                changed_button: button,
                action: wire::COMPOSITOR_POINTER_ACTION_BUTTON,
                modifiers: u32::from(event.modifiers),
                ..wire::CompositorPointerEvent::default()
            })?;
            routed.push(RoutedMessage {
                client: target.client,
                message,
            })?;
        }
        if motion {
            let message = staged.pointer_event(target.surface, wire::CompositorPointerEvent {
                timestamp_ns: event.timestamp_ns,
                x: local_x,
                y: local_y,
                delta_x,
                delta_y,
                buttons: u32::from(new_buttons),
                action: wire::COMPOSITOR_POINTER_ACTION_MOTION,
                modifiers: u32::from(event.modifiers),
                ..wire::CompositorPointerEvent::default()
            })?;
            routed.push(RoutedMessage {
                client: target.client,
                message,
            })?;
        }
        if axis {
            let message = staged.pointer_event(target.surface, wire::CompositorPointerEvent {
                timestamp_ns: event.timestamp_ns,
                x: local_x,
                y: local_y,
                buttons: u32::from(new_buttons),
                action: wire::COMPOSITOR_POINTER_ACTION_AXIS,
                modifiers: u32::from(event.modifiers),
                axis_y: event.value3,
                ..wire::CompositorPointerEvent::default()
            })?;
            routed.push(RoutedMessage {
                client: target.client,
                message,
            })?;
        }
        self.clients[index].state = Some(staged);
        self.pointer_buttons = new_buttons;
        if old_buttons == 0 && new_buttons != 0 {
            self.pointer_capture = Some(target);
        } else if new_buttons == 0 {
            self.pointer_capture = None;
        }
        Ok(routed)
    }

    /// Route one canonical key sample to the focused surface. Printable press
    /// and repeat samples emit a following UTF-8 text event.
    pub fn route_key(
        &mut self,
        event: UiInputEvent,
    ) -> Result<RoutedMessageBatch, MultiClientError> {
        if !valid_key_input(event) {
            return Err(MultiClientError::InvalidInput);
        }
        let Some(target) = self.keyboard_target() else {
            return Ok(RoutedMessageBatch::new());
        };
        let state = if event.flags & UI_EVENT_FLAG_REPEAT != 0 {
            wire::COMPOSITOR_KEY_REPEATED
        } else if event.flags & UI_EVENT_FLAG_PRESSED != 0 {
            wire::COMPOSITOR_KEY_PRESSED
        } else {
            wire::COMPOSITOR_KEY_RELEASED
        };
        let character = if state == wire::COMPOSITOR_KEY_RELEASED || event.value1 == 0 {
            None
        } else {
            u32::try_from(event.value1).ok().and_then(char::from_u32)
        };
        let event_count = 1 + usize::from(character.is_some());
        self.ensure_event_capacity(target.client, event_count)?;
        let index = self.require_operational_client(target.client)?;
        let mut staged = *self.clients[index]
            .state
            .as_ref()
            .ok_or(MultiClientError::InvalidClient)?;
        let key = wire::CompositorKeyEvent {
            timestamp_ns: event.timestamp_ns,
            key_code: event.code,
            scan_code: event.code,
            modifiers: u32::from(event.modifiers),
            state,
            repeat_count: u16::from(state == wire::COMPOSITOR_KEY_REPEATED),
            ..wire::CompositorKeyEvent::default()
        };
        let mut routed = RoutedMessageBatch::new();
        routed.push(RoutedMessage {
            client: target.client,
            message: staged.key_event(target.surface, key)?,
        })?;
        if let Some(character) = character {
            let mut text = wire::CompositorTextEvent::default();
            let mut encoded = [0u8; 4];
            let bytes = character.encode_utf8(&mut encoded).as_bytes();
            text.byte_length = bytes.len() as u16;
            text.bytes[..bytes.len()].copy_from_slice(bytes);
            routed.push(RoutedMessage {
                client: target.client,
                message: staged.text_event(target.surface, text)?,
            })?;
        }
        self.clients[index].state = Some(staged);
        Ok(routed)
    }

    fn route_pointer_overflow(
        &mut self,
        event: UiInputEvent,
        display_x: i32,
        display_y: i32,
    ) -> Result<RoutedMessageBatch, MultiClientError> {
        let old_buttons = self.pointer_buttons;
        let target = self
            .pointer_capture
            .filter(|id| self.scene_index(*id).is_some() && self.is_focusable(*id));
        let mut routed = RoutedMessageBatch::new();
        if let Some(target) = target {
            self.ensure_event_capacity(target.client, old_buttons.count_ones() as usize)?;
            let (local_x, local_y) = self.surface_local_position(target, display_x, display_y)?;
            let index = self.require_operational_client(target.client)?;
            let mut staged = *self.clients[index]
                .state
                .as_ref()
                .ok_or(MultiClientError::InvalidClient)?;
            let mut progressive = old_buttons;
            for button in pointer_button_bits() {
                if progressive & button == 0 {
                    continue;
                }
                progressive &= !button;
                let message =
                    staged.pointer_event(target.surface, wire::CompositorPointerEvent {
                        timestamp_ns: event.timestamp_ns,
                        x: local_x,
                        y: local_y,
                        buttons: u32::from(progressive),
                        changed_button: button,
                        action: wire::COMPOSITOR_POINTER_ACTION_BUTTON,
                        modifiers: u32::from(event.modifiers),
                        ..wire::CompositorPointerEvent::default()
                    })?;
                routed.push(RoutedMessage {
                    client: target.client,
                    message,
                })?;
            }
            self.clients[index].state = Some(staged);
        }
        self.pointer_capture = None;
        self.pointer_buttons = 0;
        self.pointer_resync = event.buttons != 0;
        Ok(routed)
    }

    /// Remove one connection, advance its generation, retire every mapping,
    /// and damage every visible surface it owned.
    pub fn disconnect(
        &mut self,
        client: ClientHandle,
    ) -> Result<DisconnectCleanup, MultiClientError> {
        let index = self
            .client_index(client)
            .ok_or(MultiClientError::InvalidClient)?;
        let state = self.clients[index]
            .state
            .take()
            .ok_or(MultiClientError::InvalidClient)?;
        let mut cleanup = DisconnectCleanup::new(client);
        for slot in &state.surfaces {
            let Some(surface) = slot.surface else {
                continue;
            };
            for buffer in [surface.pending_buffer, surface.current_buffer]
                .into_iter()
                .flatten()
            {
                cleanup.push_unmap(UnmapBufferAction {
                    mapping_address: buffer.mapping_address,
                    mapping_length: buffer.mapping_length,
                    buffer_token: buffer.buffer_token,
                })?;
            }
        }
        self.remove_client_scene(client);
        if self.focused.is_some_and(|id| id.client == client) {
            self.focused = None;
        }
        if self.pointer_capture.is_some_and(|id| id.client == client) {
            self.pointer_capture = None;
            self.pointer_resync = self.pointer_buttons != 0;
        }
        self.clients[index].faulted = false;
        self.clients[index].generation = next_generation(self.clients[index].generation);
        Ok(cleanup)
    }

    fn ensure_event_capacity(
        &self,
        client: ClientHandle,
        count: usize,
    ) -> Result<(), MultiClientError> {
        let index = self.require_operational_client(client)?;
        let state = self.clients[index]
            .state
            .as_ref()
            .ok_or(MultiClientError::InvalidClient)?;
        if state.can_allocate_event_serials(count) {
            Ok(())
        } else {
            Err(MultiClientError::Transaction(
                TransactionError::EventSerialExhausted,
            ))
        }
    }

    fn ensure_focus_and_input_capacity(
        &self,
        target: SurfaceId,
        input_count: usize,
        focus: bool,
    ) -> Result<(), MultiClientError> {
        if !focus || self.focused == Some(target) {
            return self.ensure_event_capacity(target.client, input_count);
        }
        match self.focused {
            Some(old) if old.client == target.client => {
                self.ensure_event_capacity(target.client, input_count + 2)
            },
            Some(old) => {
                self.ensure_event_capacity(old.client, 1)?;
                self.ensure_event_capacity(target.client, input_count + 1)
            },
            None => self.ensure_event_capacity(target.client, input_count + 1),
        }
    }

    fn surface_local_position(
        &self,
        id: SurfaceId,
        display_x: i32,
        display_y: i32,
    ) -> Result<(i32, i32), MultiClientError> {
        let index = self
            .scene_index(id)
            .ok_or(MultiClientError::InvalidSurface)?;
        let bounds = self.scene[index]
            .ok_or(MultiClientError::InvalidSurface)?
            .bounds;
        let x = (display_x as i64)
            .checked_sub(bounds.x as i64)
            .and_then(|value| i32::try_from(value).ok())
            .ok_or(MultiClientError::InvalidInput)?;
        let y = (display_y as i64)
            .checked_sub(bounds.y as i64)
            .and_then(|value| i32::try_from(value).ok())
            .ok_or(MultiClientError::InvalidInput)?;
        Ok((x, y))
    }

    fn client_index(&self, handle: ClientHandle) -> Option<usize> {
        if !handle.is_valid() {
            return None;
        }
        let index = handle.slot().checked_sub(1)? as usize;
        let slot = self.clients.get(index)?;
        (slot.generation == handle.generation() && slot.state.is_some()).then_some(index)
    }

    fn require_operational_client(&self, client: ClientHandle) -> Result<usize, MultiClientError> {
        let index = self
            .client_index(client)
            .ok_or(MultiClientError::InvalidClient)?;
        if self.clients[index].faulted {
            Err(MultiClientError::ClientFaulted)
        } else {
            Ok(index)
        }
    }

    fn scene_index(&self, id: SurfaceId) -> Option<usize> {
        self.scene[..self.scene_length as usize]
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.id == id))
    }

    fn is_focusable(&self, id: SurfaceId) -> bool {
        self.require_operational_client(id.client).is_ok()
            && self.surface(id).is_some_and(|surface| {
                matches!(
                    surface.role,
                    wire::COMPOSITOR_ROLE_TOPLEVEL | wire::COMPOSITOR_ROLE_POPUP
                ) && surface.state & wire::COMPOSITOR_STATE_MINIMIZED == 0
            })
    }

    fn remove_scene_surface(&mut self, id: SurfaceId) {
        let Some(index) = self.scene_index(id) else {
            return;
        };
        if let Some(entry) = self.scene[index] {
            self.damage.add(entry.bounds);
        }
        let last = self.scene_length as usize - 1;
        self.scene.copy_within(index + 1..=last, index);
        self.scene[last] = None;
        self.scene_length -= 1;
    }

    fn remove_client_scene(&mut self, client: ClientHandle) {
        let mut index = 0usize;
        while index < self.scene_length as usize {
            let Some(entry) = self.scene[index] else {
                break;
            };
            if entry.id.client == client {
                self.remove_scene_surface(entry.id);
            } else {
                index += 1;
            }
        }
    }
}

const fn pointer_button_bits() -> [u16; 5] {
    [
        UI_POINTER_BUTTON_LEFT,
        UI_POINTER_BUTTON_RIGHT,
        UI_POINTER_BUTTON_MIDDLE,
        UI_POINTER_BUTTON_BACK,
        UI_POINTER_BUTTON_FORWARD,
    ]
}

fn valid_pointer_input(event: UiInputEvent) -> bool {
    event.kind == UI_EVENT_POINTER
        && event.flags & !UI_EVENT_FLAG_OVERFLOW == 0
        && event.modifiers & !UI_MODIFIER_ALL == 0
        && event.buttons & !UI_POINTER_BUTTON_ALL == 0
        && event.code == 0
        && event.reserved == [0; 2]
}

fn valid_key_input(event: UiInputEvent) -> bool {
    let pressed = event.flags & UI_EVENT_FLAG_PRESSED != 0;
    let repeat = event.flags & UI_EVENT_FLAG_REPEAT != 0;
    let character_valid = event.value1 == 0
        || u32::try_from(event.value1)
            .ok()
            .and_then(char::from_u32)
            .is_some();
    event.kind == UI_EVENT_KEY
        && event.flags & !(UI_EVENT_FLAG_PRESSED | UI_EVENT_FLAG_REPEAT | UI_EVENT_FLAG_OVERFLOW)
            == 0
        && (!repeat || pressed)
        && (pressed || event.value1 == 0)
        && event.modifiers & !UI_MODIFIER_ALL == 0
        && event.buttons == 0
        && event.code != 0
        && event.value2 == 0
        && event.value3 == 0
        && event.reserved == [0; 2]
        && character_valid
}

fn mapping_usage(state: &CompositorState) -> (usize, u64) {
    let mut count = 0usize;
    let mut bytes = 0u64;
    for slot in &state.surfaces {
        let Some(surface) = slot.surface else {
            continue;
        };
        for buffer in [surface.pending_buffer, surface.current_buffer]
            .into_iter()
            .flatten()
        {
            count += 1;
            bytes = bytes.saturating_add(buffer.mapping_length);
        }
    }
    (count, bytes)
}

fn configure_surface(
    surface: &mut Surface,
    configure_serial: u64,
    width: u32,
    height: u32,
    scale_milli: u32,
) {
    surface.configure_serial = configure_serial;
    surface.acknowledged_configure_serial = 0;
    surface.configured_width = width;
    surface.configured_height = height;
    surface.scale_milli = scale_milli;
}

const fn next_generation(generation: u32) -> u32 {
    let next = generation.wrapping_add(1);
    if next == 0 {
        1
    } else {
        next
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedHeader {
    serial: u64,
    object: wire::CompositorHandle,
}

// Decoding is deliberately self-contained and allocation-free; the largest
// request therefore owns the ABI-bounded damage array until preparation.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodedPayload {
    Create,
    Destroy,
    Attach {
        surface: wire::CompositorSurfaceMetadata,
        transfer: xenith_abi::ipc::IpcReceiveTransfer,
    },
    Commit {
        frame_token: u64,
        flags: u32,
        damage_count: u8,
        damage: [wire::CompositorDamageRect; wire::COMPOSITOR_MAX_DAMAGE_RECTS as usize],
    },
    SetRole {
        role: u16,
        parent: wire::CompositorHandle,
    },
    SetTitle {
        title_length: u16,
        title: [u8; wire::COMPOSITOR_MAX_TITLE_BYTES as usize],
    },
    SetState {
        state: u32,
        mask: u32,
    },
    AckConfigure {
        configure_serial: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedRequest {
    header: DecodedHeader,
    payload: DecodedPayload,
}

fn decode_request(
    message: &IpcReceiveMessage,
    last_request_serial: u64,
) -> Result<DecodedRequest, ProtocolError> {
    if !message.is_valid() {
        return Err(ProtocolError::InvalidIpcEnvelope);
    }
    let available = message.payload_length as usize;
    if available < wire::COMPOSITOR_HEADER_SIZE as usize {
        return Err(ProtocolError::InvalidMessageLength);
    }
    let bytes = &message.payload[..available];
    let magic = read_u32(bytes, 0).ok_or(ProtocolError::InvalidHeader)?;
    let version = read_u16(bytes, 4).ok_or(ProtocolError::InvalidHeader)?;
    let header_size = read_u16(bytes, 6).ok_or(ProtocolError::InvalidHeader)?;
    let message_size = read_u32(bytes, 8).ok_or(ProtocolError::InvalidHeader)?;
    let kind = read_u16(bytes, 12).ok_or(ProtocolError::InvalidHeader)?;
    let opcode = read_u16(bytes, 14).ok_or(ProtocolError::InvalidHeader)?;
    let flags = read_u32(bytes, 16).ok_or(ProtocolError::InvalidHeader)?;
    let reserved = read_u32(bytes, 20).ok_or(ProtocolError::InvalidHeader)?;
    let serial = read_u64(bytes, 24).ok_or(ProtocolError::InvalidHeader)?;
    let object = wire::CompositorHandle(read_u64(bytes, 32).ok_or(ProtocolError::InvalidHeader)?);

    if magic != wire::COMPOSITOR_MAGIC
        || version != wire::COMPOSITOR_VERSION
        || header_size != wire::COMPOSITOR_HEADER_SIZE
        || flags != 0
        || reserved != 0
        || serial == 0
    {
        return Err(ProtocolError::InvalidHeader);
    }
    if serial <= last_request_serial {
        return Err(ProtocolError::RequestSerialOutOfOrder);
    }
    let Some(schema) = wire::compositor_opcode_schema(kind, opcode) else {
        return Err(ProtocolError::UnknownOpcode);
    };
    if !schema.accepts_direction(wire::CompositorMessageDirection::ClientToServer)
        || kind != wire::COMPOSITOR_KIND_REQUEST
    {
        return Err(ProtocolError::WrongDirection);
    }
    if !schema.accepts_object(object) {
        return Err(ProtocolError::InvalidHeader);
    }
    let expected_length = (wire::COMPOSITOR_HEADER_SIZE as u32)
        .checked_add(schema.payload_size)
        .ok_or(ProtocolError::InvalidMessageLength)?;
    if message_size != expected_length || available != expected_length as usize {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let attach = opcode == wire::COMPOSITOR_REQUEST_ATTACH_BUFFER;
    if attach {
        if message.transfer_count != 1 {
            return Err(ProtocolError::UnexpectedTransfers);
        }
        let transfer = message.transfers[0];
        if transfer.rights & REQUIRED_ATTACH_RIGHTS != REQUIRED_ATTACH_RIGHTS {
            return Err(ProtocolError::UnexpectedTransfers);
        }
    } else if message.transfer_count != 0 {
        return Err(ProtocolError::UnexpectedTransfers);
    }

    let payload = &bytes[wire::COMPOSITOR_HEADER_SIZE as usize..];
    let payload = match opcode {
        wire::COMPOSITOR_REQUEST_CREATE_SURFACE => {
            if payload.len() != 16 || !all_zero(payload) {
                return Err(ProtocolError::InvalidPayload);
            }
            DecodedPayload::Create
        },
        wire::COMPOSITOR_REQUEST_DESTROY_SURFACE => {
            if payload.len() != 16 || !all_zero(payload) {
                return Err(ProtocolError::InvalidPayload);
            }
            DecodedPayload::Destroy
        },
        wire::COMPOSITOR_REQUEST_ATTACH_BUFFER => {
            let surface = decode_surface_metadata(payload)?;
            let transfer = message.transfers[0];
            if transfer.tag != surface.buffer_token {
                return Err(ProtocolError::UnexpectedTransfers);
            }
            DecodedPayload::Attach { surface, transfer }
        },
        wire::COMPOSITOR_REQUEST_COMMIT => decode_commit(payload)?,
        wire::COMPOSITOR_REQUEST_SET_ROLE => decode_role(payload)?,
        wire::COMPOSITOR_REQUEST_SET_TITLE => decode_title(payload)?,
        wire::COMPOSITOR_REQUEST_SET_STATE => decode_state(payload)?,
        wire::COMPOSITOR_REQUEST_ACK_CONFIGURE => decode_ack_configure(payload)?,
        _ => return Err(ProtocolError::UnknownOpcode),
    };
    Ok(DecodedRequest {
        header: DecodedHeader { serial, object },
        payload,
    })
}

fn decode_surface_metadata(
    payload: &[u8],
) -> Result<wire::CompositorSurfaceMetadata, ProtocolError> {
    if payload.len() != 56 {
        return Err(ProtocolError::InvalidMessageLength);
    }
    let surface = wire::CompositorSurfaceMetadata {
        width: read_u32(payload, 0).ok_or(ProtocolError::InvalidPayload)?,
        height: read_u32(payload, 4).ok_or(ProtocolError::InvalidPayload)?,
        stride: read_u32(payload, 8).ok_or(ProtocolError::InvalidPayload)?,
        format: read_u32(payload, 12).ok_or(ProtocolError::InvalidPayload)?,
        buffer_token: read_u64(payload, 16).ok_or(ProtocolError::InvalidPayload)?,
        offset: read_u64(payload, 24).ok_or(ProtocolError::InvalidPayload)?,
        length: read_u64(payload, 32).ok_or(ProtocolError::InvalidPayload)?,
        reserved: [
            read_u64(payload, 40).ok_or(ProtocolError::InvalidPayload)?,
            read_u64(payload, 48).ok_or(ProtocolError::InvalidPayload)?,
        ],
    };
    let backing_end = surface
        .offset
        .checked_add(surface.length)
        .ok_or(ProtocolError::InvalidPayload)?;
    if !surface.is_valid(backing_end) {
        return Err(ProtocolError::InvalidPayload);
    }
    Ok(surface)
}

fn decode_commit(payload: &[u8]) -> Result<DecodedPayload, ProtocolError> {
    if payload.len() != 1056 {
        return Err(ProtocolError::InvalidMessageLength);
    }
    let frame_token = read_u64(payload, 0).ok_or(ProtocolError::InvalidPayload)?;
    let count = read_u32(payload, 8).ok_or(ProtocolError::InvalidPayload)?;
    let flags = read_u32(payload, 12).ok_or(ProtocolError::InvalidPayload)?;
    if count > wire::COMPOSITOR_MAX_DAMAGE_RECTS
        || flags & !wire::COMPOSITOR_COMMIT_REQUEST_FRAME_DONE != 0
        || (flags & wire::COMPOSITOR_COMMIT_REQUEST_FRAME_DONE != 0) != (frame_token != 0)
        || !all_zero(&payload[1040..1056])
    {
        return Err(ProtocolError::InvalidPayload);
    }
    let mut damage =
        [wire::CompositorDamageRect::default(); wire::COMPOSITOR_MAX_DAMAGE_RECTS as usize];
    let mut index = 0usize;
    while index < damage.len() {
        let offset = 16 + index * 16;
        let rect = wire::CompositorDamageRect {
            x: read_u32(payload, offset).ok_or(ProtocolError::InvalidPayload)?,
            y: read_u32(payload, offset + 4).ok_or(ProtocolError::InvalidPayload)?,
            width: read_u32(payload, offset + 8).ok_or(ProtocolError::InvalidPayload)?,
            height: read_u32(payload, offset + 12).ok_or(ProtocolError::InvalidPayload)?,
        };
        if index >= count as usize && !rect.is_zero() {
            return Err(ProtocolError::InvalidPayload);
        }
        damage[index] = rect;
        index += 1;
    }
    Ok(DecodedPayload::Commit {
        frame_token,
        flags,
        damage_count: count as u8,
        damage,
    })
}

fn decode_role(payload: &[u8]) -> Result<DecodedPayload, ProtocolError> {
    if payload.len() != 32 {
        return Err(ProtocolError::InvalidMessageLength);
    }
    let role = read_u16(payload, 0).ok_or(ProtocolError::InvalidPayload)?;
    let flags = read_u16(payload, 2).ok_or(ProtocolError::InvalidPayload)?;
    let reserved = read_u32(payload, 4).ok_or(ProtocolError::InvalidPayload)?;
    let parent = wire::CompositorHandle(read_u64(payload, 8).ok_or(ProtocolError::InvalidPayload)?);
    if !matches!(
        role,
        wire::COMPOSITOR_ROLE_NONE
            | wire::COMPOSITOR_ROLE_TOPLEVEL
            | wire::COMPOSITOR_ROLE_POPUP
            | wire::COMPOSITOR_ROLE_CURSOR
    ) || flags != 0
        || reserved != 0
        || !all_zero(&payload[16..32])
        || if role == wire::COMPOSITOR_ROLE_POPUP {
            !parent.is_valid()
        } else {
            parent != wire::CompositorHandle::INVALID
        }
    {
        return Err(ProtocolError::InvalidPayload);
    }
    Ok(DecodedPayload::SetRole { role, parent })
}

fn decode_title(payload: &[u8]) -> Result<DecodedPayload, ProtocolError> {
    if payload.len() != 280 {
        return Err(ProtocolError::InvalidMessageLength);
    }
    let title_length = read_u16(payload, 0).ok_or(ProtocolError::InvalidPayload)?;
    let flags = read_u16(payload, 2).ok_or(ProtocolError::InvalidPayload)?;
    let reserved = read_u32(payload, 4).ok_or(ProtocolError::InvalidPayload)?;
    let length = title_length as usize;
    if length > wire::COMPOSITOR_MAX_TITLE_BYTES as usize
        || flags != 0
        || reserved != 0
        || str::from_utf8(&payload[8..8 + length]).is_err()
        || !all_zero(&payload[8 + length..264])
        || !all_zero(&payload[264..280])
    {
        return Err(ProtocolError::InvalidPayload);
    }
    let mut title = [0; wire::COMPOSITOR_MAX_TITLE_BYTES as usize];
    title[..length].copy_from_slice(&payload[8..8 + length]);
    Ok(DecodedPayload::SetTitle {
        title_length,
        title,
    })
}

fn decode_state(payload: &[u8]) -> Result<DecodedPayload, ProtocolError> {
    if payload.len() != 24 {
        return Err(ProtocolError::InvalidMessageLength);
    }
    let state = read_u32(payload, 0).ok_or(ProtocolError::InvalidPayload)?;
    let mask = read_u32(payload, 4).ok_or(ProtocolError::InvalidPayload)?;
    if state & !mask != 0
        || state & !wire::COMPOSITOR_STATE_ALL != 0
        || mask & !wire::COMPOSITOR_STATE_ALL != 0
        || !all_zero(&payload[8..24])
    {
        return Err(ProtocolError::InvalidPayload);
    }
    Ok(DecodedPayload::SetState { state, mask })
}

fn decode_ack_configure(payload: &[u8]) -> Result<DecodedPayload, ProtocolError> {
    if payload.len() != 24 {
        return Err(ProtocolError::InvalidMessageLength);
    }
    let configure_serial = read_u64(payload, 0).ok_or(ProtocolError::InvalidPayload)?;
    if configure_serial == 0 || !all_zero(&payload[8..24]) {
        return Err(ProtocolError::InvalidPayload);
    }
    Ok(DecodedPayload::AckConfigure { configure_serial })
}

fn map_action(
    descriptor: i32,
    surface: wire::CompositorSurfaceMetadata,
) -> Option<MapBufferAction> {
    let mapping_offset = surface.offset & !(PAGE_SIZE - 1);
    let data_offset = surface.offset.checked_sub(mapping_offset)?;
    let span = data_offset.checked_add(surface.length)?;
    let mapping_length = align_page_up(span)?;
    Some(MapBufferAction {
        descriptor,
        buffer_token: surface.buffer_token,
        mapping_offset,
        mapping_length,
        data_offset,
        data_length: surface.length,
        width: surface.width,
        height: surface.height,
        stride: surface.stride,
        format: surface.format,
    })
}

const fn align_page_up(value: u64) -> Option<u64> {
    match value.checked_add(PAGE_SIZE - 1) {
        Some(value) => Some(value & !(PAGE_SIZE - 1)),
        None => None,
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset.checked_add(1)?)?,
    ]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset.checked_add(1)?)?,
        *bytes.get(offset.checked_add(2)?)?,
        *bytes.get(offset.checked_add(3)?)?,
    ]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset.checked_add(1)?)?,
        *bytes.get(offset.checked_add(2)?)?,
        *bytes.get(offset.checked_add(3)?)?,
        *bytes.get(offset.checked_add(4)?)?,
        *bytes.get(offset.checked_add(5)?)?,
        *bytes.get(offset.checked_add(6)?)?,
        *bytes.get(offset.checked_add(7)?)?,
    ]))
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn encoded_message(
    kind: u16,
    opcode: u16,
    serial: u64,
    object: wire::CompositorHandle,
    payload_length: usize,
) -> EncodedMessage {
    let length = wire::COMPOSITOR_HEADER_SIZE as usize + payload_length;
    debug_assert!(length <= MAX_ENCODED_MESSAGE_BYTES);
    let mut message = EncodedMessage {
        bytes: [0; MAX_ENCODED_MESSAGE_BYTES],
        length: length as u16,
    };
    write_u32(&mut message.bytes, 0, wire::COMPOSITOR_MAGIC);
    write_u16(&mut message.bytes, 4, wire::COMPOSITOR_VERSION);
    write_u16(&mut message.bytes, 6, wire::COMPOSITOR_HEADER_SIZE);
    write_u32(&mut message.bytes, 8, length as u32);
    write_u16(&mut message.bytes, 12, kind);
    write_u16(&mut message.bytes, 14, opcode);
    write_u64(&mut message.bytes, 24, serial);
    write_u64(&mut message.bytes, 32, object.0);
    message
}

fn encode_status_reply(serial: u64, status: i32, value: wire::CompositorHandle) -> EncodedMessage {
    let mut message = encoded_message(
        wire::COMPOSITOR_KIND_REPLY,
        wire::COMPOSITOR_REPLY_STATUS,
        serial,
        wire::CompositorHandle::INVALID,
        32,
    );
    write_u32(&mut message.bytes, 40, status as u32);
    write_u64(&mut message.bytes, 48, value.0);
    message
}

fn encode_configure(
    serial: u64,
    handle: wire::CompositorHandle,
    surface: &Surface,
) -> EncodedMessage {
    let mut message = encoded_message(
        wire::COMPOSITOR_KIND_EVENT,
        wire::COMPOSITOR_EVENT_CONFIGURE,
        serial,
        handle,
        32,
    );
    write_u32(&mut message.bytes, 40, surface.configured_width);
    write_u32(&mut message.bytes, 44, surface.configured_height);
    write_u32(&mut message.bytes, 48, surface.state);
    write_u32(&mut message.bytes, 52, surface.scale_milli);
    message
}

fn encode_buffer_release(
    serial: u64,
    handle: wire::CompositorHandle,
    buffer_token: u64,
) -> EncodedMessage {
    let mut message = encoded_message(
        wire::COMPOSITOR_KIND_EVENT,
        wire::COMPOSITOR_EVENT_BUFFER_RELEASE,
        serial,
        handle,
        32,
    );
    write_u64(&mut message.bytes, 40, buffer_token);
    message
}

fn encode_focus(
    serial: u64,
    handle: wire::CompositorHandle,
    focused: bool,
    seat: u32,
) -> EncodedMessage {
    let mut message = encoded_message(
        wire::COMPOSITOR_KIND_EVENT,
        wire::COMPOSITOR_EVENT_FOCUS,
        serial,
        handle,
        24,
    );
    write_u32(
        &mut message.bytes,
        40,
        if focused {
            wire::COMPOSITOR_FOCUS_IN
        } else {
            wire::COMPOSITOR_FOCUS_OUT
        },
    );
    write_u32(&mut message.bytes, 44, seat);
    message
}

fn encode_pointer(
    serial: u64,
    handle: wire::CompositorHandle,
    event: wire::CompositorPointerEvent,
) -> EncodedMessage {
    let mut message = encoded_message(
        wire::COMPOSITOR_KIND_EVENT,
        wire::COMPOSITOR_EVENT_POINTER,
        serial,
        handle,
        64,
    );
    write_u64(&mut message.bytes, 40, event.timestamp_ns);
    write_u32(&mut message.bytes, 48, event.x as u32);
    write_u32(&mut message.bytes, 52, event.y as u32);
    write_u32(&mut message.bytes, 56, event.delta_x as u32);
    write_u32(&mut message.bytes, 60, event.delta_y as u32);
    write_u32(&mut message.bytes, 64, event.buttons);
    write_u16(&mut message.bytes, 68, event.changed_button);
    write_u16(&mut message.bytes, 70, event.action);
    write_u32(&mut message.bytes, 72, event.modifiers);
    write_u32(&mut message.bytes, 76, event.axis_x as u32);
    write_u32(&mut message.bytes, 80, event.axis_y as u32);
    message
}

fn encode_key(
    serial: u64,
    handle: wire::CompositorHandle,
    event: wire::CompositorKeyEvent,
) -> EncodedMessage {
    let mut message = encoded_message(
        wire::COMPOSITOR_KIND_EVENT,
        wire::COMPOSITOR_EVENT_KEY,
        serial,
        handle,
        48,
    );
    write_u64(&mut message.bytes, 40, event.timestamp_ns);
    write_u32(&mut message.bytes, 48, event.key_code);
    write_u32(&mut message.bytes, 52, event.scan_code);
    write_u32(&mut message.bytes, 56, event.modifiers);
    write_u16(&mut message.bytes, 60, event.state);
    write_u16(&mut message.bytes, 62, event.repeat_count);
    message
}

fn encode_text(
    serial: u64,
    handle: wire::CompositorHandle,
    event: &wire::CompositorTextEvent,
) -> EncodedMessage {
    let mut message = encoded_message(
        wire::COMPOSITOR_KIND_EVENT,
        wire::COMPOSITOR_EVENT_TEXT,
        serial,
        handle,
        88,
    );
    write_u16(&mut message.bytes, 40, event.byte_length);
    message.bytes[48..112].copy_from_slice(&event.bytes);
    message
}

fn encode_frame_done(
    serial: u64,
    decision: FrameDoneDecision,
    presentation_time_ns: u64,
    refresh_interval_ns: u64,
) -> EncodedMessage {
    let mut message = encoded_message(
        wire::COMPOSITOR_KIND_EVENT,
        wire::COMPOSITOR_EVENT_FRAME_DONE,
        serial,
        decision.surface,
        48,
    );
    write_u64(&mut message.bytes, 40, decision.frame_token);
    write_u64(&mut message.bytes, 48, presentation_time_ns);
    write_u64(&mut message.bytes, 56, refresh_interval_ns);
    message
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use xenith_abi::ipc::{
        IpcReceiveTransfer, IPC_TRANSFER_RIGHT_TRANSFER, IPC_TRANSFER_RIGHT_WRITE,
    };

    use super::*;

    const WIDTH: u32 = 64;
    const HEIGHT: u32 = 48;
    const STRIDE: u32 = WIDTH * 4;
    const BUFFER_LENGTH: u64 = STRIDE as u64 * HEIGHT as u64;

    #[test]
    fn buffer_snapshot_required_span_excludes_final_row_padding() {
        let snapshot = BufferSnapshot {
            width: 3,
            height: 2,
            stride: 16,
            data_length: 28,
            ..BufferSnapshot::default()
        };

        assert_eq!(snapshot.required_data_bytes(), Some(28));
        assert_eq!(
            snapshot.data_length,
            snapshot.required_data_bytes().unwrap()
        );
    }

    fn state() -> CompositorState {
        CompositorState::new(WIDTH, HEIGHT, 1000).unwrap()
    }

    fn request(opcode: u16, serial: u64, object: wire::CompositorHandle) -> IpcReceiveMessage {
        let schema = wire::compositor_opcode_schema(wire::COMPOSITOR_KIND_REQUEST, opcode).unwrap();
        let length = wire::COMPOSITOR_HEADER_SIZE as usize + schema.payload_size as usize;
        let mut message = IpcReceiveMessage::empty();
        message.payload_length = length as u32;
        write_u32(&mut message.payload, 0, wire::COMPOSITOR_MAGIC);
        write_u16(&mut message.payload, 4, wire::COMPOSITOR_VERSION);
        write_u16(&mut message.payload, 6, wire::COMPOSITOR_HEADER_SIZE);
        write_u32(&mut message.payload, 8, length as u32);
        write_u16(&mut message.payload, 12, wire::COMPOSITOR_KIND_REQUEST);
        write_u16(&mut message.payload, 14, opcode);
        write_u64(&mut message.payload, 24, serial);
        write_u64(&mut message.payload, 32, object.0);
        message
    }

    fn unknown_request(serial: u64) -> IpcReceiveMessage {
        let mut message = IpcReceiveMessage::empty();
        message.payload_length = wire::COMPOSITOR_HEADER_SIZE as u32;
        write_u32(&mut message.payload, 0, wire::COMPOSITOR_MAGIC);
        write_u16(&mut message.payload, 4, wire::COMPOSITOR_VERSION);
        write_u16(&mut message.payload, 6, wire::COMPOSITOR_HEADER_SIZE);
        write_u32(&mut message.payload, 8, wire::COMPOSITOR_HEADER_SIZE as u32);
        write_u16(&mut message.payload, 12, wire::COMPOSITOR_KIND_REQUEST);
        write_u16(&mut message.payload, 14, u16::MAX);
        write_u64(&mut message.payload, 24, serial);
        message
    }

    fn finish(state: &mut CompositorState, message: &IpcReceiveMessage) -> ActionBatch {
        let prepared = state.prepare(message).unwrap();
        assert_eq!(prepared.map_action(), None);
        state.commit(prepared, ExternalCompletion::None).unwrap()
    }

    fn reply(batch: &ActionBatch) -> EncodedMessage {
        batch
            .iter()
            .find_map(|action| match action {
                CompositorAction::Reply(message) => Some(*message),
                _ => None,
            })
            .expect("request emitted a reply")
    }

    fn reply_status(batch: &ActionBatch) -> i32 {
        read_u32(reply(batch).as_bytes(), 40).unwrap() as i32
    }

    fn reply_value(batch: &ActionBatch) -> wire::CompositorHandle {
        wire::CompositorHandle(read_u64(reply(batch).as_bytes(), 48).unwrap())
    }

    fn create(state: &mut CompositorState, serial: u64) -> wire::CompositorHandle {
        let batch = finish(
            state,
            &request(
                wire::COMPOSITOR_REQUEST_CREATE_SURFACE,
                serial,
                wire::CompositorHandle::INVALID,
            ),
        );
        assert_eq!(reply_status(&batch), wire::COMPOSITOR_STATUS_OK);
        reply_value(&batch)
    }

    fn destroy_request(serial: u64, handle: wire::CompositorHandle) -> IpcReceiveMessage {
        request(wire::COMPOSITOR_REQUEST_DESTROY_SURFACE, serial, handle)
    }

    fn role_request(
        serial: u64,
        handle: wire::CompositorHandle,
        role: u16,
        parent: wire::CompositorHandle,
    ) -> IpcReceiveMessage {
        let mut message = request(wire::COMPOSITOR_REQUEST_SET_ROLE, serial, handle);
        write_u16(&mut message.payload, 40, role);
        write_u64(&mut message.payload, 48, parent.0);
        message
    }

    fn ack_request(
        serial: u64,
        handle: wire::CompositorHandle,
        configure_serial: u64,
    ) -> IpcReceiveMessage {
        let mut message = request(wire::COMPOSITOR_REQUEST_ACK_CONFIGURE, serial, handle);
        write_u64(&mut message.payload, 40, configure_serial);
        message
    }

    fn attach_request(
        serial: u64,
        handle: wire::CompositorHandle,
        token: u64,
        offset: u64,
    ) -> IpcReceiveMessage {
        let mut message = request(wire::COMPOSITOR_REQUEST_ATTACH_BUFFER, serial, handle);
        write_u32(&mut message.payload, 40, WIDTH);
        write_u32(&mut message.payload, 44, HEIGHT);
        write_u32(&mut message.payload, 48, STRIDE);
        write_u32(&mut message.payload, 52, wire::COMPOSITOR_FORMAT_BGRX8888);
        write_u64(&mut message.payload, 56, token);
        write_u64(&mut message.payload, 64, offset);
        write_u64(&mut message.payload, 72, BUFFER_LENGTH);
        message.transfer_count = 1;
        message.transfers[0] = IpcReceiveTransfer {
            installed_fd: 7,
            rights: REQUIRED_ATTACH_RIGHTS,
            tag: token,
        };
        message
    }

    fn commit_request(
        serial: u64,
        handle: wire::CompositorHandle,
        frame_token: u64,
        damage: Option<wire::CompositorDamageRect>,
    ) -> IpcReceiveMessage {
        let mut message = request(wire::COMPOSITOR_REQUEST_COMMIT, serial, handle);
        if frame_token != 0 {
            write_u64(&mut message.payload, 40, frame_token);
            write_u32(
                &mut message.payload,
                52,
                wire::COMPOSITOR_COMMIT_REQUEST_FRAME_DONE,
            );
        }
        if let Some(rect) = damage {
            write_u32(&mut message.payload, 48, 1);
            write_u32(&mut message.payload, 56, rect.x);
            write_u32(&mut message.payload, 60, rect.y);
            write_u32(&mut message.payload, 64, rect.width);
            write_u32(&mut message.payload, 68, rect.height);
        }
        message
    }

    fn attach(
        state: &mut CompositorState,
        serial: u64,
        handle: wire::CompositorHandle,
        token: u64,
        address: u64,
    ) -> ActionBatch {
        let prepared = state
            .prepare(&attach_request(serial, handle, token, 0))
            .unwrap();
        assert_eq!(prepared.map_action().unwrap().buffer_token, token);
        state
            .commit(
                prepared,
                ExternalCompletion::BufferMapped(MappedBuffer {
                    mapping_address: address,
                }),
            )
            .unwrap()
    }

    fn event(batch: &ActionBatch, opcode: u16) -> Option<EncodedMessage> {
        batch.iter().find_map(|action| match action {
            CompositorAction::Event(message)
                if read_u16(message.as_bytes(), 14) == Some(opcode) =>
            {
                Some(*message)
            },
            _ => None,
        })
    }

    #[test]
    fn malformed_headers_payloads_and_envelopes_are_rejected_transactionally() {
        let state = state();
        let original = state;

        let mut bad_magic = request(
            wire::COMPOSITOR_REQUEST_CREATE_SURFACE,
            1,
            wire::CompositorHandle::INVALID,
        );
        write_u32(&mut bad_magic.payload, 0, 0);
        assert_eq!(state.prepare(&bad_magic), Err(ProtocolError::InvalidHeader));

        let mut trailing = request(
            wire::COMPOSITOR_REQUEST_CREATE_SURFACE,
            1,
            wire::CompositorHandle::INVALID,
        );
        trailing.payload_length += 1;
        assert_eq!(
            state.prepare(&trailing),
            Err(ProtocolError::InvalidMessageLength)
        );

        let mut reserved = request(
            wire::COMPOSITOR_REQUEST_CREATE_SURFACE,
            1,
            wire::CompositorHandle::INVALID,
        );
        reserved.payload[40] = 1;
        assert_eq!(state.prepare(&reserved), Err(ProtocolError::InvalidPayload));

        let mut noncanonical = request(
            wire::COMPOSITOR_REQUEST_CREATE_SURFACE,
            1,
            wire::CompositorHandle::INVALID,
        );
        noncanonical.payload[noncanonical.payload_length as usize] = 1;
        assert_eq!(
            state.prepare(&noncanonical),
            Err(ProtocolError::InvalidIpcEnvelope)
        );
        assert_eq!(
            state.prepare(&unknown_request(1)),
            Err(ProtocolError::UnknownOpcode)
        );
        assert_eq!(state, original);
    }

    #[test]
    fn transfers_are_opcode_scoped_rights_checked_and_token_bound() {
        let mut state = state();
        let handle = create(&mut state, 1);

        let mut unexpected = request(wire::COMPOSITOR_REQUEST_COMMIT, 2, handle);
        unexpected.transfer_count = 1;
        unexpected.transfers[0] = IpcReceiveTransfer {
            installed_fd: 9,
            rights: REQUIRED_ATTACH_RIGHTS,
            tag: 8,
        };
        assert_eq!(
            state.prepare(&unexpected),
            Err(ProtocolError::UnexpectedTransfers)
        );

        let mut missing_map = attach_request(2, handle, 10, 0);
        missing_map.transfers[0].rights = IPC_TRANSFER_RIGHT_READ;
        assert_eq!(
            state.prepare(&missing_map),
            Err(ProtocolError::UnexpectedTransfers)
        );

        let mut wrong_tag = attach_request(2, handle, 10, 0);
        wrong_tag.transfers[0].tag = 11;
        assert_eq!(
            state.prepare(&wrong_tag),
            Err(ProtocolError::UnexpectedTransfers)
        );

        let mut extra_rights = attach_request(2, handle, 10, 0);
        extra_rights.transfers[0].rights |= IPC_TRANSFER_RIGHT_WRITE | IPC_TRANSFER_RIGHT_TRANSFER;
        assert!(state.prepare(&extra_rights).is_ok());
    }

    #[test]
    fn stale_handles_never_alias_reused_slots() {
        let mut state = state();
        let old = create(&mut state, 1);
        assert_eq!(
            reply_status(&finish(&mut state, &destroy_request(2, old))),
            wire::COMPOSITOR_STATUS_OK
        );
        let new = create(&mut state, 3);
        assert_eq!(old.slot(), new.slot());
        assert_ne!(old.generation(), new.generation());

        let stale = finish(&mut state, &destroy_request(4, old));
        assert_eq!(reply_status(&stale), wire::COMPOSITOR_STATUS_NOT_FOUND);
        assert!(state.surface(new).is_some());
    }

    #[test]
    fn role_configure_must_be_acked_before_a_sized_commit() {
        let mut state = state();
        let handle = create(&mut state, 1);
        let role = finish(
            &mut state,
            &role_request(
                2,
                handle,
                wire::COMPOSITOR_ROLE_TOPLEVEL,
                wire::CompositorHandle::INVALID,
            ),
        );
        let configure = event(&role, wire::COMPOSITOR_EVENT_CONFIGURE).unwrap();
        let configure_serial = read_u64(configure.as_bytes(), 24).unwrap();
        assert_ne!(configure_serial, 0);
        assert_eq!(
            state.surface(handle).unwrap().configure_serial,
            configure_serial
        );

        attach(&mut state, 3, handle, 100, 0x10_000);
        let gated = finish(&mut state, &commit_request(4, handle, 0, None));
        assert_eq!(reply_status(&gated), wire::COMPOSITOR_STATUS_INVALID_STATE);
        assert!(state.surface(handle).unwrap().pending_buffer.is_some());

        let bad_ack = finish(&mut state, &ack_request(5, handle, configure_serial + 1));
        assert_eq!(
            reply_status(&bad_ack),
            wire::COMPOSITOR_STATUS_INVALID_STATE
        );
        let ack = finish(&mut state, &ack_request(6, handle, configure_serial));
        assert_eq!(reply_status(&ack), wire::COMPOSITOR_STATUS_OK);
        let committed = finish(
            &mut state,
            &commit_request(
                7,
                handle,
                77,
                Some(wire::CompositorDamageRect {
                    x: 0,
                    y: 0,
                    width: WIDTH,
                    height: HEIGHT,
                }),
            ),
        );
        assert!(committed
            .iter()
            .any(|action| matches!(action, CompositorAction::Present(_))));
        assert!(committed
            .iter()
            .any(|action| matches!(action, CompositorAction::FrameDone(_))));
    }

    #[test]
    fn attach_is_two_phase_and_mapping_failure_leaves_surface_unchanged() {
        let mut state = state();
        let handle = create(&mut state, 1);
        let prepared = state.prepare(&attach_request(2, handle, 20, 128)).unwrap();
        let map = prepared.map_action().unwrap();
        assert_eq!(map.mapping_offset, 0);
        assert_eq!(map.data_offset, 128);
        assert_eq!(map.mapping_length, 16 * 1024);
        assert!(state.surface(handle).unwrap().pending_buffer.is_none());

        assert_eq!(
            state.commit(
                prepared,
                ExternalCompletion::BufferMapped(MappedBuffer { mapping_address: 1 }),
            ),
            Err(TransactionError::InvalidMapping)
        );
        assert!(state.surface(handle).unwrap().pending_buffer.is_none());

        let aborted = state
            .abort_mapping(prepared, wire::COMPOSITOR_STATUS_NO_MEMORY)
            .unwrap();
        assert_eq!(reply_status(&aborted), wire::COMPOSITOR_STATUS_NO_MEMORY);
        assert!(state.surface(handle).unwrap().pending_buffer.is_none());
        assert_eq!(state.last_request_serial(), 2);
    }

    #[test]
    fn attach_commit_frame_done_and_safe_encoding_complete_the_lifecycle() {
        let mut state = state();
        let handle = create(&mut state, 1);
        assert_eq!(
            reply_status(&attach(&mut state, 2, handle, 30, 0x20_000)),
            wire::COMPOSITOR_STATUS_OK
        );
        let committed = finish(
            &mut state,
            &commit_request(
                3,
                handle,
                300,
                Some(wire::CompositorDamageRect {
                    x: 1,
                    y: 2,
                    width: 10,
                    height: 11,
                }),
            ),
        );
        let present = committed
            .iter()
            .find_map(|action| match action {
                CompositorAction::Present(present) => Some(*present),
                _ => None,
            })
            .unwrap();
        assert_eq!(present.buffer.buffer_token, 30);
        assert_eq!(present.damage_count, 1);
        let decision = committed
            .iter()
            .find_map(|action| match action {
                CompositorAction::FrameDone(decision) => Some(*decision),
                _ => None,
            })
            .unwrap();
        assert_eq!(state.surface(handle).unwrap().outstanding_frame_token, 300);
        assert_eq!(
            state.complete_frame(
                FrameDoneDecision {
                    surface: handle,
                    frame_token: 301,
                },
                9_000_000,
                16_666_667,
            ),
            Err(TransactionError::StateInvariant)
        );
        let done = state
            .complete_frame(decision, 9_000_000, 16_666_667)
            .unwrap();
        assert_eq!(read_u32(done.as_bytes(), 0), Some(wire::COMPOSITOR_MAGIC));
        assert_eq!(
            read_u16(done.as_bytes(), 14),
            Some(wire::COMPOSITOR_EVENT_FRAME_DONE)
        );
        assert_eq!(read_u64(done.as_bytes(), 40), Some(300));
        assert!(done.bytes[done.len()..].iter().all(|byte| *byte == 0));
        assert_eq!(
            state.complete_frame(decision, 9_000_000, 16_666_667),
            Err(TransactionError::StateInvariant)
        );
        let surface = state.surface(handle).unwrap();
        assert!(surface.pending_buffer.is_none());
        assert_eq!(surface.current_buffer.unwrap().buffer_token, 30);
        assert_eq!(surface.outstanding_frame_token, 0);
    }

    #[test]
    fn only_one_frame_completion_may_be_outstanding_per_surface() {
        let mut state = state();
        let handle = create(&mut state, 1);
        attach(&mut state, 2, handle, 31, 0x20_000);
        let first = finish(&mut state, &commit_request(3, handle, 300, None));
        let decision = first
            .iter()
            .find_map(|action| match action {
                CompositorAction::FrameDone(decision) => Some(*decision),
                _ => None,
            })
            .unwrap();

        let rejected = finish(&mut state, &commit_request(4, handle, 301, None));
        assert_eq!(
            reply_status(&rejected),
            wire::COMPOSITOR_STATUS_RESOURCE_EXHAUSTED
        );
        assert!(!rejected
            .iter()
            .any(|action| matches!(action, CompositorAction::Present(_))));
        assert_eq!(state.surface(handle).unwrap().outstanding_frame_token, 300);

        state
            .complete_frame(decision, 9_000_000, 16_666_667)
            .unwrap();
        let accepted = finish(&mut state, &commit_request(5, handle, 302, None));
        assert_eq!(reply_status(&accepted), wire::COMPOSITOR_STATUS_OK);
        assert_eq!(state.surface(handle).unwrap().outstanding_frame_token, 302);
    }

    #[test]
    fn pending_and_current_buffer_replacements_are_released_once() {
        let mut state = state();
        let handle = create(&mut state, 1);
        attach(&mut state, 2, handle, 40, 0x10_000);
        finish(&mut state, &commit_request(3, handle, 0, None));

        attach(&mut state, 4, handle, 41, 0x20_000);
        let replace_pending = attach(&mut state, 5, handle, 42, 0x30_000);
        assert!(replace_pending.iter().any(|action| matches!(
            action,
            CompositorAction::UnmapBuffer(UnmapBufferAction {
                buffer_token: 41,
                ..
            })
        )));
        let pending_release =
            event(&replace_pending, wire::COMPOSITOR_EVENT_BUFFER_RELEASE).unwrap();
        assert_eq!(read_u64(pending_release.as_bytes(), 40), Some(41));

        let replace_current = finish(&mut state, &commit_request(6, handle, 0, None));
        assert!(replace_current.iter().any(|action| matches!(
            action,
            CompositorAction::UnmapBuffer(UnmapBufferAction {
                buffer_token: 40,
                ..
            })
        )));
        assert_eq!(
            state
                .surface(handle)
                .unwrap()
                .current_buffer
                .unwrap()
                .buffer_token,
            42
        );
    }

    #[test]
    fn capacity_is_bounded_and_destroy_advances_generation() {
        let mut state = state();
        let mut handles = [wire::CompositorHandle::INVALID; MAX_CLIENT_SURFACES];
        for (index, handle) in handles.iter_mut().enumerate() {
            *handle = create(&mut state, index as u64 + 1);
        }
        assert_eq!(state.live_surface_count(), MAX_CLIENT_SURFACES);
        let exhausted = finish(
            &mut state,
            &request(
                wire::COMPOSITOR_REQUEST_CREATE_SURFACE,
                MAX_CLIENT_SURFACES as u64 + 1,
                wire::CompositorHandle::INVALID,
            ),
        );
        assert_eq!(
            reply_status(&exhausted),
            wire::COMPOSITOR_STATUS_RESOURCE_EXHAUSTED
        );
        let serial = MAX_CLIENT_SURFACES as u64 + 2;
        finish(&mut state, &destroy_request(serial, handles[0]));
        let reused = create(&mut state, serial + 1);
        assert_eq!(reused.slot(), handles[0].slot());
        assert_eq!(reused.generation(), handles[0].generation() + 1);
    }

    #[test]
    fn title_is_tracked_and_unimplemented_window_states_are_truthfully_rejected() {
        let mut state = state();
        let handle = create(&mut state, 1);
        finish(
            &mut state,
            &role_request(
                2,
                handle,
                wire::COMPOSITOR_ROLE_TOPLEVEL,
                wire::CompositorHandle::INVALID,
            ),
        );

        let mut title = request(wire::COMPOSITOR_REQUEST_SET_TITLE, 3, handle);
        write_u16(&mut title.payload, 40, 6);
        title.payload[48..54].copy_from_slice(b"Xenith");
        assert_eq!(reply_status(&finish(&mut state, &title)), 0);
        let surface = state.surface(handle).unwrap();
        assert_eq!(&surface.title[..surface.title_length as usize], b"Xenith");

        let old_configure = surface.configure_serial;
        let mut set_state = request(wire::COMPOSITOR_REQUEST_SET_STATE, 4, handle);
        write_u32(&mut set_state.payload, 40, wire::COMPOSITOR_STATE_MAXIMIZED);
        write_u32(&mut set_state.payload, 44, wire::COMPOSITOR_STATE_MAXIMIZED);
        let changed = finish(&mut state, &set_state);
        assert_eq!(reply_status(&changed), wire::COMPOSITOR_STATUS_UNSUPPORTED);
        assert!(event(&changed, wire::COMPOSITOR_EVENT_CONFIGURE).is_none());
        let surface = state.surface(handle).unwrap();
        assert_eq!(surface.configure_serial, old_configure);
        assert_eq!(surface.acknowledged_configure_serial, 0);
        assert_eq!(surface.state, 0);

        let mut bad_utf8 = request(wire::COMPOSITOR_REQUEST_SET_TITLE, 5, handle);
        write_u16(&mut bad_utf8.payload, 40, 1);
        bad_utf8.payload[48] = 0xff;
        assert_eq!(state.prepare(&bad_utf8), Err(ProtocolError::InvalidPayload));
        assert_eq!(&state.surface(handle).unwrap().title[..6], b"Xenith");
    }

    #[test]
    fn damage_bounds_and_prepared_epoch_prevent_partial_state_changes() {
        let mut state = state();
        let first = create(&mut state, 1);
        attach(&mut state, 2, first, 50, 0x10_000);

        let invalid_damage = finish(
            &mut state,
            &commit_request(
                3,
                first,
                0,
                Some(wire::CompositorDamageRect {
                    x: WIDTH,
                    y: 0,
                    width: 1,
                    height: 1,
                }),
            ),
        );
        assert_eq!(
            reply_status(&invalid_damage),
            wire::COMPOSITOR_STATUS_INVALID_ARGUMENT
        );
        assert!(state.surface(first).unwrap().current_buffer.is_none());

        let stale = state.prepare(&commit_request(4, first, 0, None)).unwrap();
        let _second = create(&mut state, 5);
        assert_eq!(
            state.commit(stale, ExternalCompletion::None),
            Err(TransactionError::StaleTransaction)
        );
        assert!(state.surface(first).unwrap().current_buffer.is_none());
    }

    #[test]
    fn request_serials_are_strictly_monotonic() {
        let mut state = state();
        let _ = create(&mut state, 10);
        assert_eq!(
            state.prepare(&request(
                wire::COMPOSITOR_REQUEST_CREATE_SURFACE,
                10,
                wire::CompositorHandle::INVALID,
            )),
            Err(ProtocolError::RequestSerialOutOfOrder)
        );
        assert_eq!(
            state.prepare(&request(
                wire::COMPOSITOR_REQUEST_CREATE_SURFACE,
                9,
                wire::CompositorHandle::INVALID,
            )),
            Err(ProtocolError::RequestSerialOutOfOrder)
        );
    }

    fn multi_state() -> MultiClientCompositor {
        MultiClientCompositor::new(640, 480, WIDTH, HEIGHT, 1000).unwrap()
    }

    fn multi_finish(
        compositor: &mut MultiClientCompositor,
        client: ClientHandle,
        message: &IpcReceiveMessage,
    ) -> DispatchBatch {
        let prepared = compositor.prepare(client, message).unwrap();
        assert_eq!(prepared.map_action(), None);
        compositor
            .commit(prepared, ExternalCompletion::None)
            .unwrap()
    }

    fn multi_create(
        compositor: &mut MultiClientCompositor,
        client: ClientHandle,
        serial: u64,
    ) -> wire::CompositorHandle {
        let batch = multi_finish(
            compositor,
            client,
            &request(
                wire::COMPOSITOR_REQUEST_CREATE_SURFACE,
                serial,
                wire::CompositorHandle::INVALID,
            ),
        );
        assert_eq!(reply_status(&batch.actions), wire::COMPOSITOR_STATUS_OK);
        reply_value(&batch.actions)
    }

    fn multi_attach(
        compositor: &mut MultiClientCompositor,
        client: ClientHandle,
        serial: u64,
        surface: wire::CompositorHandle,
        token: u64,
        address: u64,
    ) -> DispatchBatch {
        let prepared = compositor
            .prepare(client, &attach_request(serial, surface, token, 0))
            .unwrap();
        compositor.mapping_permitted(&prepared).unwrap();
        compositor
            .commit(
                prepared,
                ExternalCompletion::BufferMapped(MappedBuffer {
                    mapping_address: address,
                }),
            )
            .unwrap()
    }

    fn multi_configure_surface(
        compositor: &mut MultiClientCompositor,
        client: ClientHandle,
        token: u64,
        address: u64,
    ) -> SurfaceId {
        let surface = multi_create(compositor, client, 1);
        let role = multi_finish(
            compositor,
            client,
            &role_request(
                2,
                surface,
                wire::COMPOSITOR_ROLE_TOPLEVEL,
                wire::CompositorHandle::INVALID,
            ),
        );
        assert!(event(&role.actions, wire::COMPOSITOR_EVENT_CONFIGURE).is_some());
        let configure_serial = compositor
            .surface(SurfaceId::new(client, surface))
            .unwrap()
            .configure_serial;
        assert_eq!(
            reply_status(
                &multi_finish(
                    compositor,
                    client,
                    &ack_request(3, surface, configure_serial),
                )
                .actions,
            ),
            wire::COMPOSITOR_STATUS_OK
        );
        multi_attach(compositor, client, 4, surface, token, address);
        let committed = multi_finish(
            compositor,
            client,
            &commit_request(
                5,
                surface,
                0,
                Some(wire::CompositorDamageRect {
                    x: 0,
                    y: 0,
                    width: WIDTH,
                    height: HEIGHT,
                }),
            ),
        );
        assert!(committed
            .actions
            .iter()
            .any(|action| matches!(action, CompositorAction::Present(_))));
        SurfaceId::new(client, surface)
    }

    #[test]
    fn multi_client_capacity_generation_and_surface_ownership_are_isolated() {
        let mut compositor = multi_state();
        let mut clients = [ClientHandle::INVALID; MAX_COMPOSITOR_CLIENTS];
        for client in &mut clients {
            *client = compositor.connect().unwrap();
        }
        assert_eq!(compositor.client_count(), MAX_COMPOSITOR_CLIENTS);
        assert_eq!(compositor.connect(), Err(MultiClientError::ClientCapacity));

        let first_surface = multi_create(&mut compositor, clients[0], 1);
        let second_surface = multi_create(&mut compositor, clients[1], 1);
        // Wire handles are connection scoped and may be numerically equal.
        assert_eq!(first_surface, second_surface);
        assert!(compositor
            .surface(SurfaceId::new(clients[0], first_surface))
            .is_some());
        assert!(compositor
            .surface(SurfaceId::new(clients[1], second_surface))
            .is_some());

        let old = clients[0];
        let cleanup = compositor.disconnect(old).unwrap();
        assert_eq!(cleanup.unmap_count(), 0);
        assert!(compositor
            .surface(SurfaceId::new(clients[1], second_surface))
            .is_some());
        let replacement = compositor.connect().unwrap();
        assert_eq!(replacement.slot(), old.slot());
        assert_ne!(replacement.generation(), old.generation());
        assert!(matches!(
            compositor.prepare(
                old,
                &request(
                    wire::COMPOSITOR_REQUEST_CREATE_SURFACE,
                    2,
                    wire::CompositorHandle::INVALID,
                ),
            ),
            Err(MultiPrepareError::Client(MultiClientError::InvalidClient))
        ));
    }

    #[test]
    fn malformed_protocol_faults_only_the_offending_client() {
        let mut compositor = multi_state();
        let bad_client = compositor.connect().unwrap();
        let healthy_client = compositor.connect().unwrap();
        let mut malformed = request(
            wire::COMPOSITOR_REQUEST_CREATE_SURFACE,
            1,
            wire::CompositorHandle::INVALID,
        );
        write_u32(&mut malformed.payload, 0, 0);
        assert_eq!(
            compositor.prepare(bad_client, &malformed),
            Err(MultiPrepareError::Protocol(ClientProtocolFault {
                client: bad_client,
                error: ProtocolError::InvalidHeader,
            }))
        );
        assert!(compositor.is_client_faulted(bad_client));
        assert!(!compositor.is_client_faulted(healthy_client));
        assert!(matches!(
            compositor.prepare(
                bad_client,
                &request(
                    wire::COMPOSITOR_REQUEST_CREATE_SURFACE,
                    1,
                    wire::CompositorHandle::INVALID,
                ),
            ),
            Err(MultiPrepareError::Client(MultiClientError::ClientFaulted))
        ));
        assert!(multi_create(&mut compositor, healthy_client, 1).is_valid());
    }

    #[test]
    fn mapping_quotas_are_checked_before_external_mapping_and_at_commit() {
        let mut compositor = multi_state();
        let client = compositor.connect().unwrap();
        let surface = multi_create(&mut compositor, client, 1);
        let mut oversized = attach_request(2, surface, 91, 0);
        write_u64(
            &mut oversized.payload,
            72,
            MAX_CLIENT_MAPPED_BYTES + PAGE_SIZE,
        );
        let prepared = compositor.prepare(client, &oversized).unwrap();
        assert_eq!(
            compositor.mapping_permitted(&prepared),
            Err(MultiClientError::MappingQuota)
        );
        assert_eq!(
            compositor.commit(
                prepared,
                ExternalCompletion::BufferMapped(MappedBuffer {
                    mapping_address: 0x10_000,
                }),
            ),
            Err(MultiClientError::MappingQuota)
        );
        let rejected = compositor
            .abort_mapping(prepared, wire::COMPOSITOR_STATUS_RESOURCE_EXHAUSTED)
            .unwrap();
        assert_eq!(
            reply_status(&rejected.actions),
            wire::COMPOSITOR_STATUS_RESOURCE_EXHAUSTED
        );
        assert!(compositor
            .surface(SurfaceId::new(client, surface))
            .unwrap()
            .pending_buffer
            .is_none());
    }

    #[test]
    fn scene_z_order_hit_testing_focus_and_damage_are_client_aware() {
        let mut compositor = multi_state();
        let first_client = compositor.connect().unwrap();
        let second_client = compositor.connect().unwrap();
        let first = multi_configure_surface(&mut compositor, first_client, 101, 0x10_000);
        let second = multi_configure_surface(&mut compositor, second_client, 201, 0x20_000);
        compositor
            .place_surface(first, SceneRect::new(10, 10, WIDTH, HEIGHT))
            .unwrap();
        compositor
            .place_surface(second, SceneRect::new(20, 20, WIDTH, HEIGHT))
            .unwrap();
        assert_eq!(compositor.pointer_target(25, 25), Some(second));
        compositor.raise_surface(first).unwrap();
        assert_eq!(compositor.pointer_target(25, 25), Some(first));

        let first_focus = compositor.focus_surface(first, 0).unwrap();
        assert_eq!(first_focus.len(), 1);
        let message = first_focus.iter().next().unwrap();
        assert_eq!(message.client, first_client);
        assert_eq!(
            read_u16(message.message.as_bytes(), 14),
            Some(wire::COMPOSITOR_EVENT_FOCUS)
        );
        assert_eq!(
            read_u32(message.message.as_bytes(), 40),
            Some(wire::COMPOSITOR_FOCUS_IN)
        );
        assert_eq!(compositor.keyboard_target(), Some(first));
        assert_ne!(
            compositor.surface(first).unwrap().state & wire::COMPOSITOR_STATE_ACTIVATED,
            0
        );

        let transition = compositor.focus_surface(second, 7).unwrap();
        assert_eq!(transition.len(), 2);
        let mut routed = transition.iter();
        let out = routed.next().unwrap();
        let input = routed.next().unwrap();
        assert_eq!(out.client, first_client);
        assert_eq!(
            read_u32(out.message.as_bytes(), 40),
            Some(wire::COMPOSITOR_FOCUS_OUT)
        );
        assert_eq!(input.client, second_client);
        assert_eq!(
            read_u32(input.message.as_bytes(), 40),
            Some(wire::COMPOSITOR_FOCUS_IN)
        );
        assert_eq!(read_u32(input.message.as_bytes(), 44), Some(7));
        assert_eq!(
            compositor.surface(first).unwrap().state & wire::COMPOSITOR_STATE_ACTIVATED,
            0
        );
        assert_ne!(
            compositor.surface(second).unwrap().state & wire::COMPOSITOR_STATE_ACTIVATED,
            0
        );

        let _ = compositor.take_damage();
        compositor
            .damage_surface(first, &[
                wire::CompositorDamageRect {
                    x: 0,
                    y: 0,
                    width: 4,
                    height: 4,
                },
                wire::CompositorDamageRect {
                    x: 4,
                    y: 0,
                    width: 4,
                    height: 4,
                },
            ])
            .unwrap();
        let damage = compositor.take_damage();
        assert_eq!(damage.as_slice(), &[SceneRect::new(10, 10, 8, 4)]);
        assert!(!damage.is_full());
    }

    #[test]
    fn disconnect_retires_all_buffers_removes_scene_and_damages_exposure() {
        let mut compositor = multi_state();
        let client = compositor.connect().unwrap();
        let id = multi_configure_surface(&mut compositor, client, 301, 0x30_000);
        compositor
            .place_surface(id, SceneRect::new(30, 40, WIDTH, HEIGHT))
            .unwrap();
        compositor.focus_surface(id, 0).unwrap();
        multi_attach(&mut compositor, client, 6, id.surface, 302, 0x40_000);
        let _ = compositor.take_damage();

        let cleanup = compositor.disconnect(client).unwrap();
        assert_eq!(cleanup.unmap_count(), 2);
        let mut tokens = cleanup
            .unmaps()
            .map(|action| action.buffer_token)
            .collect::<std::vec::Vec<_>>();
        tokens.sort_unstable();
        assert_eq!(tokens, std::vec![301, 302]);
        assert_eq!(compositor.scene_surface_count(), 0);
        assert_eq!(compositor.focused_surface(), None);
        assert_eq!(compositor.keyboard_target(), None);
        assert_eq!(compositor.take_damage().as_slice(), &[SceneRect::new(
            30, 40, WIDTH, HEIGHT
        )]);
    }

    #[test]
    fn clients_cannot_self_assign_activated_focus_state() {
        let mut state = state();
        let surface = create(&mut state, 1);
        finish(
            &mut state,
            &role_request(
                2,
                surface,
                wire::COMPOSITOR_ROLE_TOPLEVEL,
                wire::CompositorHandle::INVALID,
            ),
        );
        let mut request = request(wire::COMPOSITOR_REQUEST_SET_STATE, 3, surface);
        write_u32(&mut request.payload, 40, wire::COMPOSITOR_STATE_ACTIVATED);
        write_u32(&mut request.payload, 44, wire::COMPOSITOR_STATE_ACTIVATED);
        let rejected = finish(&mut state, &request);
        assert_eq!(
            reply_status(&rejected),
            wire::COMPOSITOR_STATUS_ACCESS_DENIED
        );
        assert_eq!(
            state.surface(surface).unwrap().state & wire::COMPOSITOR_STATE_ACTIVATED,
            0
        );
    }

    #[test]
    fn unsupported_cursor_role_returns_unsupported_without_claiming_success() {
        let mut state = state();
        let surface = create(&mut state, 1);
        let rejected = finish(
            &mut state,
            &role_request(
                2,
                surface,
                wire::COMPOSITOR_ROLE_CURSOR,
                wire::CompositorHandle::INVALID,
            ),
        );
        assert_eq!(reply_status(&rejected), wire::COMPOSITOR_STATUS_UNSUPPORTED);
        assert_eq!(
            state.surface(surface).unwrap().role,
            wire::COMPOSITOR_ROLE_NONE
        );
    }

    #[test]
    fn simultaneous_two_client_coordinator_lifecycle_is_deterministic() {
        let mut compositor = multi_state();
        let first_client = compositor.connect().unwrap();
        let second_client = compositor.connect().unwrap();
        let first = multi_configure_surface(&mut compositor, first_client, 501, 0x50_000);
        let second = multi_configure_surface(&mut compositor, second_client, 601, 0x60_000);
        assert_eq!(first.surface, second.surface);
        assert_ne!(first, second);

        compositor
            .place_surface(first, SceneRect::new(12, 12, WIDTH, HEIGHT))
            .unwrap();
        compositor
            .place_surface(second, SceneRect::new(18, 18, WIDTH, HEIGHT))
            .unwrap();
        assert_eq!(compositor.pointer_target(24, 24), Some(second));
        assert_eq!(compositor.focus_surface(first, 0).unwrap().len(), 1);
        let transfer = compositor.focus_surface(second, 0).unwrap();
        assert_eq!(transfer.len(), 2);
        assert_eq!(compositor.keyboard_target(), Some(second));

        let mut malformed = request(wire::COMPOSITOR_REQUEST_SET_TITLE, 6, first.surface);
        write_u16(&mut malformed.payload, 40, 1);
        malformed.payload[48] = 0xff;
        assert!(matches!(
            compositor.prepare(first_client, &malformed),
            Err(MultiPrepareError::Protocol(ClientProtocolFault {
                client,
                error: ProtocolError::InvalidPayload,
            })) if client == first_client
        ));
        assert!(compositor.is_client_faulted(first_client));
        assert!(!compositor.is_client_faulted(second_client));

        compositor.raise_surface(second).unwrap();
        compositor
            .damage_surface(second, &[wire::CompositorDamageRect {
                x: 1,
                y: 1,
                width: 3,
                height: 3,
            }])
            .unwrap();
        let cleanup = compositor.disconnect(first_client).unwrap();
        assert_eq!(cleanup.unmap_count(), 1);
        assert_eq!(cleanup.unmaps().next().unwrap().buffer_token, 501);
        assert_eq!(compositor.client_count(), 1);
        assert_eq!(compositor.scene_surface_count(), 1);
        assert_eq!(compositor.pointer_target(24, 24), Some(second));
        assert_eq!(compositor.keyboard_target(), Some(second));
        assert!(compositor.surface(second).is_some());
    }

    #[test]
    fn global_mapping_quota_is_shared_without_cross_client_token_collisions() {
        let mut compositor = multi_state();
        let mut clients = [ClientHandle::INVALID; 5];
        for client in &mut clients {
            *client = compositor.connect().unwrap();
        }
        for (index, client) in clients.iter().copied().take(4).enumerate() {
            let surface = multi_create(&mut compositor, client, 1);
            let mut request = attach_request(2, surface, 700, 0);
            write_u64(&mut request.payload, 72, MAX_CLIENT_MAPPED_BYTES);
            let prepared = compositor.prepare(client, &request).unwrap();
            compositor.mapping_permitted(&prepared).unwrap();
            compositor
                .commit(
                    prepared,
                    ExternalCompletion::BufferMapped(MappedBuffer {
                        mapping_address: 0x1000_0000 + index as u64 * 0x1000_0000,
                    }),
                )
                .unwrap();
        }

        let last = clients[4];
        let surface = multi_create(&mut compositor, last, 1);
        let mut request = attach_request(2, surface, 700, 0);
        write_u64(&mut request.payload, 72, MAX_CLIENT_MAPPED_BYTES);
        let prepared = compositor.prepare(last, &request).unwrap();
        assert_eq!(
            compositor.mapping_permitted(&prepared),
            Err(MultiClientError::MappingQuota)
        );
    }

    #[test]
    fn fragmented_scene_damage_collapses_to_a_bounded_full_redraw() {
        let mut compositor = multi_state();
        let client = compositor.connect().unwrap();
        let id = multi_configure_surface(&mut compositor, client, 801, 0x80_000);
        compositor
            .place_surface(id, SceneRect::new(0, 0, WIDTH, HEIGHT))
            .unwrap();
        let _ = compositor.take_damage();
        let mut rectangles = [wire::CompositorDamageRect::default(); MAX_SCENE_DAMAGE_RECTS + 1];
        for (index, rectangle) in rectangles.iter_mut().enumerate() {
            *rectangle = wire::CompositorDamageRect {
                x: index as u32 * 2,
                y: 0,
                width: 1,
                height: 1,
            };
        }
        compositor.damage_surface(id, &rectangles).unwrap();
        let damage = compositor.take_damage();
        assert!(damage.is_full());
        assert_eq!(damage.as_slice(), &[SceneRect::new(0, 0, 640, 480)]);
    }

    fn pointer_input(sequence: u64, timestamp_ns: u64, buttons: u16, wheel: i32) -> UiInputEvent {
        UiInputEvent {
            sequence,
            timestamp_ns,
            kind: UI_EVENT_POINTER,
            buttons,
            value3: wheel,
            ..UiInputEvent::default()
        }
    }

    fn key_input(
        sequence: u64,
        timestamp_ns: u64,
        code: u32,
        flags: u16,
        character: Option<char>,
    ) -> UiInputEvent {
        UiInputEvent {
            sequence,
            timestamp_ns,
            kind: UI_EVENT_KEY,
            flags,
            code,
            value1: character.map_or(0, |character| character as i32),
            ..UiInputEvent::default()
        }
    }

    #[test]
    fn simultaneous_two_client_input_routes_focus_capture_text_and_disconnect() {
        let mut compositor = multi_state();
        let first_client = compositor.connect().unwrap();
        let second_client = compositor.connect().unwrap();
        let first = multi_configure_surface(&mut compositor, first_client, 901, 0x90_000);
        let second = multi_configure_surface(&mut compositor, second_client, 902, 0xa0_000);
        compositor
            .place_surface(first, SceneRect::new(10, 10, WIDTH, HEIGHT))
            .unwrap();
        compositor
            .place_surface(second, SceneRect::new(100, 10, WIDTH, HEIGHT))
            .unwrap();
        let _ = compositor.take_damage();

        let press = compositor
            .route_pointer(
                pointer_input(1, 100, UI_POINTER_BUTTON_LEFT, 0),
                20,
                20,
                0,
                0,
            )
            .unwrap();
        assert_eq!(press.len(), 2);
        let mut press_messages = press.iter();
        let focus = press_messages.next().unwrap();
        let button = press_messages.next().unwrap();
        assert_eq!(focus.client, first_client);
        assert_eq!(
            read_u16(focus.message.as_bytes(), 14),
            Some(wire::COMPOSITOR_EVENT_FOCUS)
        );
        assert_eq!(button.client, first_client);
        assert_eq!(
            read_u16(button.message.as_bytes(), 14),
            Some(wire::COMPOSITOR_EVENT_POINTER)
        );
        assert_eq!(read_u32(button.message.as_bytes(), 48), Some(10));
        assert_eq!(read_u32(button.message.as_bytes(), 52), Some(10));
        assert_eq!(
            read_u16(button.message.as_bytes(), 68),
            Some(UI_POINTER_BUTTON_LEFT)
        );
        assert_eq!(compositor.pointer_capture(), Some(first));
        assert_eq!(compositor.keyboard_target(), Some(first));

        let captured_motion = compositor
            .route_pointer(
                pointer_input(2, 110, UI_POINTER_BUTTON_LEFT, 0),
                110,
                20,
                90,
                0,
            )
            .unwrap();
        assert_eq!(captured_motion.len(), 1);
        let motion = captured_motion.iter().next().unwrap();
        assert_eq!(motion.client, first_client);
        assert_eq!(read_u32(motion.message.as_bytes(), 48), Some(100));
        assert_eq!(read_u32(motion.message.as_bytes(), 56), Some(90));

        let typed = compositor
            .route_key(key_input(3, 120, 0x1e, UI_EVENT_FLAG_PRESSED, Some('é')))
            .unwrap();
        assert_eq!(typed.len(), 2);
        let mut typed_messages = typed.iter();
        let key = typed_messages.next().unwrap();
        let text = typed_messages.next().unwrap();
        assert_eq!(key.client, first_client);
        assert_eq!(
            read_u16(key.message.as_bytes(), 14),
            Some(wire::COMPOSITOR_EVENT_KEY)
        );
        assert_eq!(read_u32(key.message.as_bytes(), 48), Some(0x1e));
        assert_eq!(text.client, first_client);
        assert_eq!(
            read_u16(text.message.as_bytes(), 14),
            Some(wire::COMPOSITOR_EVENT_TEXT)
        );
        assert_eq!(read_u16(text.message.as_bytes(), 40), Some(2));
        assert_eq!(&text.message.as_bytes()[48..50], "é".as_bytes());

        let release = compositor
            .route_pointer(pointer_input(4, 130, 0, 0), 110, 20, 0, 0)
            .unwrap();
        assert_eq!(release.len(), 1);
        assert_eq!(release.iter().next().unwrap().client, first_client);
        assert_eq!(compositor.pointer_capture(), None);

        let hover = compositor
            .route_pointer(pointer_input(5, 140, 0, 0), 110, 20, 1, 0)
            .unwrap();
        assert_eq!(hover.len(), 1);
        assert_eq!(hover.iter().next().unwrap().client, second_client);
        assert_eq!(compositor.keyboard_target(), Some(first));

        let second_press = compositor
            .route_pointer(
                pointer_input(6, 150, UI_POINTER_BUTTON_LEFT, 0),
                110,
                20,
                0,
                0,
            )
            .unwrap();
        assert_eq!(second_press.len(), 3);
        let destinations = second_press
            .iter()
            .map(|message| message.client)
            .collect::<std::vec::Vec<_>>();
        assert_eq!(destinations, std::vec![
            first_client,
            second_client,
            second_client
        ]);
        assert_eq!(compositor.keyboard_target(), Some(second));
        assert_eq!(compositor.pointer_capture(), Some(second));

        let cleanup = compositor.disconnect(second_client).unwrap();
        assert_eq!(cleanup.unmap_count(), 1);
        assert_eq!(compositor.pointer_capture(), None);
        assert_eq!(compositor.keyboard_target(), None);
        assert!(compositor
            .route_pointer(pointer_input(7, 160, 0, 0), 20, 20, 0, 0)
            .unwrap()
            .is_empty());
        let refocused = compositor
            .route_pointer(
                pointer_input(8, 170, UI_POINTER_BUTTON_LEFT, 0),
                20,
                20,
                0,
                0,
            )
            .unwrap();
        assert_eq!(refocused.len(), 2);
        assert!(refocused
            .iter()
            .all(|message| message.client == first_client));
    }

    #[test]
    fn pointer_overflow_synthesizes_releases_and_resynchronizes_capture() {
        let mut compositor = multi_state();
        let client = compositor.connect().unwrap();
        let surface = multi_configure_surface(&mut compositor, client, 903, 0xb0_000);
        compositor
            .place_surface(surface, SceneRect::new(10, 10, WIDTH, HEIGHT))
            .unwrap();
        compositor
            .route_pointer(
                pointer_input(1, 100, UI_POINTER_BUTTON_LEFT | UI_POINTER_BUTTON_RIGHT, 0),
                20,
                20,
                0,
                0,
            )
            .unwrap();
        assert_eq!(compositor.pointer_capture(), Some(surface));

        let mut overflow = pointer_input(2, 110, UI_POINTER_BUTTON_LEFT, 0);
        overflow.flags = UI_EVENT_FLAG_OVERFLOW;
        let releases = compositor.route_pointer(overflow, 20, 20, 0, 0).unwrap();
        assert_eq!(releases.len(), 2);
        assert!(releases.iter().all(|message| {
            read_u16(message.message.as_bytes(), 70) == Some(wire::COMPOSITOR_POINTER_ACTION_BUTTON)
        }));
        assert_eq!(compositor.pointer_capture(), None);
        assert!(compositor
            .route_pointer(
                pointer_input(3, 120, UI_POINTER_BUTTON_LEFT, 0),
                20,
                20,
                0,
                0,
            )
            .unwrap()
            .is_empty());
        assert!(compositor
            .route_pointer(pointer_input(4, 130, 0, 0), 20, 20, 0, 0)
            .unwrap()
            .is_empty());
        assert_eq!(compositor.pointer_capture(), None);
    }

    #[test]
    fn invalid_input_is_rejected_without_changing_focus_or_capture() {
        let mut compositor = multi_state();
        let client = compositor.connect().unwrap();
        let surface = multi_configure_surface(&mut compositor, client, 904, 0xc0_000);
        compositor
            .place_surface(surface, SceneRect::new(10, 10, WIDTH, HEIGHT))
            .unwrap();
        let mut invalid = pointer_input(1, 100, 1 << 15, 0);
        assert_eq!(
            compositor.route_pointer(invalid, 20, 20, 0, 0),
            Err(MultiClientError::InvalidInput)
        );
        assert_eq!(compositor.pointer_capture(), None);
        assert_eq!(compositor.focused_surface(), None);

        invalid = key_input(2, 110, 0x1e, UI_EVENT_FLAG_REPEAT, Some('a'));
        assert_eq!(
            compositor.route_key(invalid),
            Err(MultiClientError::InvalidInput)
        );
        assert_eq!(compositor.focused_surface(), None);
    }
}
