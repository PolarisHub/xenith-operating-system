use core::mem::size_of;

use xenith_abi::compositor::{
    validate_damage_rects, CompositorAckConfigureRequest, CompositorAttachBufferRequest,
    CompositorBufferReleaseEvent, CompositorCloseEvent, CompositorCommitRequest,
    CompositorConfigureEvent, CompositorCreateSurfaceRequest, CompositorDamageRect,
    CompositorDestroySurfaceRequest, CompositorFocusEvent, CompositorFrameDoneEvent,
    CompositorHandle, CompositorKeyEvent, CompositorPointerEvent, CompositorSetRoleRequest,
    CompositorSetStateRequest, CompositorSetTitleRequest, CompositorSurfaceMetadata,
    CompositorTextEvent, COMPOSITOR_COMMIT_REQUEST_FRAME_DONE, COMPOSITOR_KIND_REQUEST,
    COMPOSITOR_MAX_DAMAGE_RECTS, COMPOSITOR_MAX_TITLE_BYTES, COMPOSITOR_REQUEST_ACK_CONFIGURE,
    COMPOSITOR_REQUEST_ATTACH_BUFFER, COMPOSITOR_REQUEST_COMMIT, COMPOSITOR_REQUEST_CREATE_SURFACE,
    COMPOSITOR_REQUEST_DESTROY_SURFACE, COMPOSITOR_REQUEST_SET_ROLE, COMPOSITOR_REQUEST_SET_STATE,
    COMPOSITOR_REQUEST_SET_TITLE, COMPOSITOR_ROLE_NONE, COMPOSITOR_STATUS_OK,
};
use xenith_abi::{
    IpcReceiveMessage, IpcReceiveTransfer, IpcSendMessage, IpcSendTransfer, IPC_ABI_VERSION,
    IPC_MESSAGE_HEADER_SIZE, IPC_TRANSFER_RIGHT_MAP, IPC_TRANSFER_RIGHT_READ,
};

use crate::transport::Transport;
use crate::wire::{self, DecodedMessage, WireError, HEADER_SIZE};

pub const MAX_TRACKED_SURFACES: usize = 32;
pub const MAX_TRACKED_BUFFERS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestKind {
    CreateSurface,
    DestroySurface,
    AttachBuffer,
    Commit,
    SetRole,
    SetTitle,
    SetState,
    AckConfigure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reply {
    pub serial: u64,
    pub request: RequestKind,
    pub status: i32,
    pub value: CompositorHandle,
}

impl Reply {
    #[must_use]
    pub const fn succeeded(self) -> bool {
        self.status == COMPOSITOR_STATUS_OK
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    Configure(CompositorConfigureEvent),
    Close(CompositorCloseEvent),
    Focus(CompositorFocusEvent),
    Pointer(CompositorPointerEvent),
    Key(CompositorKeyEvent),
    Text(CompositorTextEvent),
    FrameDone(CompositorFrameDoneEvent),
    BufferRelease(CompositorBufferReleaseEvent),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Event {
    pub serial: u64,
    pub surface: CompositorHandle,
    pub kind: EventKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Incoming {
    Reply(Reply),
    Event(Event),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceInfo {
    pub handle: CompositorHandle,
    pub role: u16,
    pub state: u32,
    pub width: u32,
    pub height: u32,
    pub active_buffer_token: u64,
    pub pending_configure_serial: u64,
    pub configured_width: u32,
    pub configured_height: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgumentError {
    InvalidSurface,
    InvalidMetadata,
    InvalidRole,
    TitleTooLong,
    InvalidState,
    TooManyDamageRects,
    InvalidDamage,
    InvalidFrameToken,
    InvalidConfigureSerial,
    InvalidDescriptor,
    DuplicateBufferToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateError {
    RequestPending,
    SerialExhausted,
    SurfaceCapacity,
    BufferCapacity,
    UnknownSurface,
    NoBufferAttached,
    ConfigureNotPending,
    ConfigureUnacknowledged,
    BufferDoesNotMatchConfigure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidIpcRecord,
    UnexpectedTransfer,
    InvalidHeader,
    InvalidPayload,
    TransportLength { expected: usize, actual: usize },
    ReplyWithoutRequest,
    ReplySerialMismatch { expected: u64, actual: u64 },
    InvalidCreateReply,
    UnexpectedReplyValue,
    UnknownEventSurface,
    DuplicateSurface,
    UnexpectedBufferToken,
    LocalStateCapacity,
    InvalidOutgoingRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error<E> {
    Transport(E),
    Argument(ArgumentError),
    State(StateError),
    Protocol(ProtocolError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingRequest {
    Create,
    Destroy {
        surface: CompositorHandle,
    },
    Attach {
        surface: CompositorHandle,
        width: u32,
        height: u32,
        buffer_token: u64,
    },
    Commit,
    SetRole {
        surface: CompositorHandle,
        role: u16,
    },
    SetTitle,
    SetState {
        surface: CompositorHandle,
        state: u32,
        mask: u32,
    },
    AckConfigure {
        surface: CompositorHandle,
        configure_serial: u64,
    },
}

impl PendingRequest {
    const fn kind(self) -> RequestKind {
        match self {
            Self::Create => RequestKind::CreateSurface,
            Self::Destroy { .. } => RequestKind::DestroySurface,
            Self::Attach { .. } => RequestKind::AttachBuffer,
            Self::Commit => RequestKind::Commit,
            Self::SetRole { .. } => RequestKind::SetRole,
            Self::SetTitle => RequestKind::SetTitle,
            Self::SetState { .. } => RequestKind::SetState,
            Self::AckConfigure { .. } => RequestKind::AckConfigure,
        }
    }
}

#[derive(Clone, Copy)]
struct Pending {
    serial: u64,
    request: PendingRequest,
}

#[derive(Clone, Copy)]
struct SurfaceSlot {
    handle: CompositorHandle,
    role: u16,
    state: u32,
    width: u32,
    height: u32,
    active_buffer_token: u64,
    pending_configure_serial: u64,
    configured_width: u32,
    configured_height: u32,
}

impl SurfaceSlot {
    const EMPTY: Self = Self {
        handle: CompositorHandle::INVALID,
        role: COMPOSITOR_ROLE_NONE,
        state: 0,
        width: 0,
        height: 0,
        active_buffer_token: 0,
        pending_configure_serial: 0,
        configured_width: 0,
        configured_height: 0,
    };

    const fn is_used(self) -> bool {
        self.handle.0 != 0
    }

    const fn info(self) -> SurfaceInfo {
        SurfaceInfo {
            handle: self.handle,
            role: self.role,
            state: self.state,
            width: self.width,
            height: self.height,
            active_buffer_token: self.active_buffer_token,
            pending_configure_serial: self.pending_configure_serial,
            configured_width: self.configured_width,
            configured_height: self.configured_height,
        }
    }
}

#[derive(Clone, Copy)]
struct BufferSlot {
    surface: CompositorHandle,
    token: u64,
}

impl BufferSlot {
    const EMPTY: Self = Self {
        surface: CompositorHandle::INVALID,
        token: 0,
    };
}

/// Allocation-free compositor connection with bounded protocol state.
pub struct Client<T> {
    transport: T,
    send_record: IpcSendMessage,
    receive_record: IpcReceiveMessage,
    next_serial: u64,
    pending: Option<Pending>,
    surfaces: [SurfaceSlot; MAX_TRACKED_SURFACES],
    buffers: [BufferSlot; MAX_TRACKED_BUFFERS],
}

impl<T> Client<T> {
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            send_record: IpcSendMessage::empty(),
            receive_record: IpcReceiveMessage::empty(),
            next_serial: 1,
            pending: None,
            surfaces: [SurfaceSlot::EMPTY; MAX_TRACKED_SURFACES],
            buffers: [BufferSlot::EMPTY; MAX_TRACKED_BUFFERS],
        }
    }

    /// Construct a client whose first request uses `next_serial`.
    ///
    /// This supports restoring a connection-local serial sequence without ever
    /// emitting zero or silently wrapping the sequence.
    pub fn with_next_serial(transport: T, next_serial: u64) -> Result<Self, StateError> {
        if next_serial == 0 {
            return Err(StateError::SerialExhausted);
        }
        let mut client = Self::new(transport);
        client.next_serial = next_serial;
        Ok(client)
    }

    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn into_transport(self) -> T {
        self.transport
    }

    #[must_use]
    pub const fn has_pending_request(&self) -> bool {
        self.pending.is_some()
    }

    #[must_use]
    pub const fn pending_request(&self) -> Option<(u64, RequestKind)> {
        match self.pending {
            Some(pending) => Some((pending.serial, pending.request.kind())),
            None => None,
        }
    }

    #[must_use]
    pub fn surface_info(&self, surface: CompositorHandle) -> Option<SurfaceInfo> {
        self.surface_index(surface)
            .map(|index| self.surfaces[index].info())
    }

    #[must_use]
    pub fn tracked_surface_count(&self) -> usize {
        self.surfaces.iter().filter(|slot| slot.is_used()).count()
    }

    #[must_use]
    pub fn tracked_buffer_count(&self) -> usize {
        self.buffers.iter().filter(|slot| slot.token != 0).count()
    }

    fn surface_index(&self, surface: CompositorHandle) -> Option<usize> {
        self.surfaces
            .iter()
            .position(|slot| slot.handle == surface && slot.is_used())
    }

    fn require_surface<E>(&self, surface: CompositorHandle) -> Result<usize, Error<E>> {
        if !surface.is_valid() {
            return Err(Error::Argument(ArgumentError::InvalidSurface));
        }
        self.surface_index(surface)
            .ok_or(Error::State(StateError::UnknownSurface))
    }

    fn require_idle<E>(&self) -> Result<(), Error<E>> {
        if self.pending.is_some() {
            Err(Error::State(StateError::RequestPending))
        } else {
            Ok(())
        }
    }

    fn allocate_serial<E>(&mut self) -> Result<u64, Error<E>> {
        let serial = self.next_serial;
        if serial == 0 {
            return Err(Error::State(StateError::SerialExhausted));
        }
        self.next_serial = serial.checked_add(1).unwrap_or(0);
        Ok(serial)
    }
}

impl<T: Transport> Client<T> {
    pub fn create_surface(&mut self, timeout_ns: u64) -> Result<u64, Error<T::Error>> {
        self.require_idle()?;
        if !self.surfaces.iter().any(|slot| !slot.is_used()) {
            return Err(Error::State(StateError::SurfaceCapacity));
        }
        let serial = self.begin_request(
            COMPOSITOR_REQUEST_CREATE_SURFACE,
            CompositorHandle::INVALID,
            size_of::<CompositorCreateSurfaceRequest>(),
        )?;
        self.finish_request(serial, PendingRequest::Create, timeout_ns, None)
    }

    pub fn destroy_surface(
        &mut self,
        surface: CompositorHandle,
        timeout_ns: u64,
    ) -> Result<u64, Error<T::Error>> {
        self.require_idle()?;
        self.require_surface(surface)?;
        let serial = self.begin_request(
            COMPOSITOR_REQUEST_DESTROY_SURFACE,
            surface,
            size_of::<CompositorDestroySurfaceRequest>(),
        )?;
        self.finish_request(
            serial,
            PendingRequest::Destroy { surface },
            timeout_ns,
            None,
        )
    }

    pub fn attach_buffer(
        &mut self,
        surface: CompositorHandle,
        shared_memory_fd: i32,
        backing_length: u64,
        metadata: CompositorSurfaceMetadata,
        timeout_ns: u64,
    ) -> Result<u64, Error<T::Error>> {
        self.require_idle()?;
        self.require_surface(surface)?;
        if shared_memory_fd < 0 {
            return Err(Error::Argument(ArgumentError::InvalidDescriptor));
        }
        let request = CompositorAttachBufferRequest { surface: metadata };
        if !request.is_valid(backing_length) {
            return Err(Error::Argument(ArgumentError::InvalidMetadata));
        }
        if self
            .buffers
            .iter()
            .any(|buffer| buffer.token == metadata.buffer_token)
        {
            return Err(Error::Argument(ArgumentError::DuplicateBufferToken));
        }
        if !self.buffers.iter().any(|buffer| buffer.token == 0) {
            return Err(Error::State(StateError::BufferCapacity));
        }

        let serial = self.begin_request(
            COMPOSITOR_REQUEST_ATTACH_BUFFER,
            surface,
            size_of::<CompositorAttachBufferRequest>(),
        )?;
        let payload = &mut self.send_record.payload;
        let base = HEADER_SIZE;
        put_u32(payload, base, metadata.width)?;
        put_u32(payload, base + 4, metadata.height)?;
        put_u32(payload, base + 8, metadata.stride)?;
        put_u32(payload, base + 12, metadata.format)?;
        put_u64(payload, base + 16, metadata.buffer_token)?;
        put_u64(payload, base + 24, metadata.offset)?;
        put_u64(payload, base + 32, metadata.length)?;
        self.finish_request(
            serial,
            PendingRequest::Attach {
                surface,
                width: metadata.width,
                height: metadata.height,
                buffer_token: metadata.buffer_token,
            },
            timeout_ns,
            Some(IpcSendTransfer {
                source_fd: shared_memory_fd,
                rights: IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_MAP,
                tag: metadata.buffer_token,
            }),
        )
    }

    pub fn set_role(
        &mut self,
        surface: CompositorHandle,
        role: u16,
        parent: CompositorHandle,
        timeout_ns: u64,
    ) -> Result<u64, Error<T::Error>> {
        self.require_idle()?;
        self.require_surface(surface)?;
        let request = CompositorSetRoleRequest {
            role,
            flags: 0,
            reserved: 0,
            parent,
            reserved2: [0; 2],
        };
        if !request.is_valid() {
            return Err(Error::Argument(ArgumentError::InvalidRole));
        }
        let serial = self.begin_request(
            COMPOSITOR_REQUEST_SET_ROLE,
            surface,
            size_of::<CompositorSetRoleRequest>(),
        )?;
        let payload = &mut self.send_record.payload;
        let base = HEADER_SIZE;
        put_u16(payload, base, role)?;
        put_u64(payload, base + 8, parent.0)?;
        self.finish_request(
            serial,
            PendingRequest::SetRole { surface, role },
            timeout_ns,
            None,
        )
    }

    pub fn set_title(
        &mut self,
        surface: CompositorHandle,
        title: &str,
        timeout_ns: u64,
    ) -> Result<u64, Error<T::Error>> {
        self.require_idle()?;
        self.require_surface(surface)?;
        if title.len() > COMPOSITOR_MAX_TITLE_BYTES as usize {
            return Err(Error::Argument(ArgumentError::TitleTooLong));
        }
        let serial = self.begin_request(
            COMPOSITOR_REQUEST_SET_TITLE,
            surface,
            size_of::<CompositorSetTitleRequest>(),
        )?;
        let payload = &mut self.send_record.payload;
        let base = HEADER_SIZE;
        put_u16(payload, base, title.len() as u16)?;
        wire::put(payload, base + 8, title.as_bytes()).map_err(outgoing_error)?;
        self.finish_request(serial, PendingRequest::SetTitle, timeout_ns, None)
    }

    pub fn set_state(
        &mut self,
        surface: CompositorHandle,
        state: u32,
        mask: u32,
        timeout_ns: u64,
    ) -> Result<u64, Error<T::Error>> {
        self.require_idle()?;
        self.require_surface(surface)?;
        let request = CompositorSetStateRequest {
            state,
            mask,
            reserved: [0; 2],
        };
        if !request.is_valid() {
            return Err(Error::Argument(ArgumentError::InvalidState));
        }
        let serial = self.begin_request(
            COMPOSITOR_REQUEST_SET_STATE,
            surface,
            size_of::<CompositorSetStateRequest>(),
        )?;
        let payload = &mut self.send_record.payload;
        let base = HEADER_SIZE;
        put_u32(payload, base, state)?;
        put_u32(payload, base + 4, mask)?;
        self.finish_request(
            serial,
            PendingRequest::SetState {
                surface,
                state,
                mask,
            },
            timeout_ns,
            None,
        )
    }

    pub fn ack_configure(
        &mut self,
        surface: CompositorHandle,
        configure_serial: u64,
        timeout_ns: u64,
    ) -> Result<u64, Error<T::Error>> {
        self.require_idle()?;
        let index = self.require_surface(surface)?;
        if configure_serial == 0 {
            return Err(Error::Argument(ArgumentError::InvalidConfigureSerial));
        }
        if self.surfaces[index].pending_configure_serial == 0
            || self.surfaces[index].pending_configure_serial != configure_serial
        {
            return Err(Error::State(StateError::ConfigureNotPending));
        }
        let serial = self.begin_request(
            COMPOSITOR_REQUEST_ACK_CONFIGURE,
            surface,
            size_of::<CompositorAckConfigureRequest>(),
        )?;
        put_u64(&mut self.send_record.payload, HEADER_SIZE, configure_serial)?;
        self.finish_request(
            serial,
            PendingRequest::AckConfigure {
                surface,
                configure_serial,
            },
            timeout_ns,
            None,
        )
    }

    pub fn commit(
        &mut self,
        surface: CompositorHandle,
        damage: &[CompositorDamageRect],
        frame_token: Option<u64>,
        timeout_ns: u64,
    ) -> Result<u64, Error<T::Error>> {
        self.require_idle()?;
        let index = self.require_surface(surface)?;
        let slot = self.surfaces[index];
        if slot.width == 0 || slot.height == 0 || slot.active_buffer_token == 0 {
            return Err(Error::State(StateError::NoBufferAttached));
        }
        if slot.pending_configure_serial != 0 {
            return Err(Error::State(StateError::ConfigureUnacknowledged));
        }
        if slot.configured_width != 0
            && (slot.width != slot.configured_width || slot.height != slot.configured_height)
        {
            return Err(Error::State(StateError::BufferDoesNotMatchConfigure));
        }
        if damage.len() > COMPOSITOR_MAX_DAMAGE_RECTS as usize {
            return Err(Error::Argument(ArgumentError::TooManyDamageRects));
        }
        if !validate_damage_rects(damage, slot.width, slot.height) {
            return Err(Error::Argument(ArgumentError::InvalidDamage));
        }
        if matches!(frame_token, Some(0)) {
            return Err(Error::Argument(ArgumentError::InvalidFrameToken));
        }
        let serial = self.begin_request(
            COMPOSITOR_REQUEST_COMMIT,
            surface,
            size_of::<CompositorCommitRequest>(),
        )?;
        let payload = &mut self.send_record.payload;
        let base = HEADER_SIZE;
        put_u64(payload, base, frame_token.unwrap_or(0))?;
        put_u32(payload, base + 8, damage.len() as u32)?;
        put_u32(
            payload,
            base + 12,
            if frame_token.is_some() {
                COMPOSITOR_COMMIT_REQUEST_FRAME_DONE
            } else {
                0
            },
        )?;
        for (index, rectangle) in damage.iter().enumerate() {
            let offset = base + 16 + index * size_of::<CompositorDamageRect>();
            put_u32(payload, offset, rectangle.x)?;
            put_u32(payload, offset + 4, rectangle.y)?;
            put_u32(payload, offset + 8, rectangle.width)?;
            put_u32(payload, offset + 12, rectangle.height)?;
        }
        self.finish_request(serial, PendingRequest::Commit, timeout_ns, None)
    }

    /// Block for one complete reply or asynchronous compositor event.
    pub fn receive(&mut self, timeout_ns: u64) -> Result<Incoming, Error<T::Error>> {
        reset_receive_record(&mut self.receive_record);
        let actual = self
            .transport
            .receive(&mut self.receive_record, timeout_ns)
            .map_err(Error::Transport)?;
        let record_is_valid = self.receive_record.is_valid();
        let has_unexpected_transfers = self.receive_record.transfer_count != 0;
        self.close_received_descriptors();
        if !record_is_valid {
            return Err(Error::Protocol(ProtocolError::InvalidIpcRecord));
        }
        if has_unexpected_transfers {
            return Err(Error::Protocol(ProtocolError::UnexpectedTransfer));
        }
        let expected = self.receive_record.payload_length as usize;
        if actual != expected {
            return Err(Error::Protocol(ProtocolError::TransportLength {
                expected,
                actual,
            }));
        }
        let decoded = wire::decode_message(&self.receive_record.payload[..expected])
            .map_err(|error| Error::Protocol(protocol_error(error)))?;
        match decoded {
            DecodedMessage::Reply {
                serial,
                status,
                value,
            } => self.complete_reply(serial, status, value),
            DecodedMessage::Event {
                serial,
                surface,
                kind,
            } => self.accept_event(serial, surface, kind),
        }
    }

    /// Consume and close every canonical descriptor still owned by the receive
    /// record. Taking each entry before closing makes this safe to reuse when a
    /// future protocol message claims selected transfers first.
    fn close_received_descriptors(&mut self) {
        let mut closed = [-1; xenith_abi::IPC_MAX_TRANSFERS as usize];
        let mut closed_count = 0;

        for index in 0..self.receive_record.transfers.len() {
            let transfer = core::mem::take(&mut self.receive_record.transfers[index]);
            if !transfer.is_valid() || closed[..closed_count].contains(&transfer.installed_fd) {
                continue;
            }
            closed[closed_count] = transfer.installed_fd;
            closed_count += 1;
            self.transport.close_descriptor(transfer.installed_fd);
        }
    }

    fn begin_request(
        &mut self,
        opcode: u16,
        object: CompositorHandle,
        payload_size: usize,
    ) -> Result<u64, Error<T::Error>> {
        let serial = self.allocate_serial()?;
        reset_send_record(&mut self.send_record);
        let message_size = wire::encode_header(
            &mut self.send_record.payload,
            COMPOSITOR_KIND_REQUEST,
            opcode,
            payload_size,
            serial,
            object,
        )
        .map_err(outgoing_error)?;
        self.send_record.payload_length = message_size as u32;
        Ok(serial)
    }

    fn finish_request(
        &mut self,
        serial: u64,
        request: PendingRequest,
        timeout_ns: u64,
        transfer: Option<IpcSendTransfer>,
    ) -> Result<u64, Error<T::Error>> {
        if let Some(transfer) = transfer {
            self.send_record.transfer_count = 1;
            self.send_record.transfers[0] = transfer;
        }
        if !self.send_record.is_valid() {
            return Err(Error::Protocol(ProtocolError::InvalidOutgoingRecord));
        }
        let expected = self.send_record.payload_length as usize;
        let actual = self
            .transport
            .send(&self.send_record, timeout_ns)
            .map_err(Error::Transport)?;
        if actual != expected {
            return Err(Error::Protocol(ProtocolError::TransportLength {
                expected,
                actual,
            }));
        }
        self.pending = Some(Pending { serial, request });
        Ok(serial)
    }

    fn complete_reply(
        &mut self,
        serial: u64,
        status: i32,
        value: CompositorHandle,
    ) -> Result<Incoming, Error<T::Error>> {
        let pending = self
            .pending
            .ok_or(Error::Protocol(ProtocolError::ReplyWithoutRequest))?;
        if serial != pending.serial {
            return Err(Error::Protocol(ProtocolError::ReplySerialMismatch {
                expected: pending.serial,
                actual: serial,
            }));
        }
        match pending.request {
            PendingRequest::Create if status == COMPOSITOR_STATUS_OK => {
                if !value.is_valid() {
                    return Err(Error::Protocol(ProtocolError::InvalidCreateReply));
                }
                if self.surface_index(value).is_some() {
                    return Err(Error::Protocol(ProtocolError::DuplicateSurface));
                }
            },
            PendingRequest::Create => {
                if value != CompositorHandle::INVALID {
                    return Err(Error::Protocol(ProtocolError::InvalidCreateReply));
                }
            },
            _ if value != CompositorHandle::INVALID => {
                return Err(Error::Protocol(ProtocolError::UnexpectedReplyValue));
            },
            _ => {},
        }

        self.pending = None;
        if status == COMPOSITOR_STATUS_OK {
            self.apply_success(pending.request, value)?;
        }
        Ok(Incoming::Reply(Reply {
            serial,
            request: pending.request.kind(),
            status,
            value,
        }))
    }

    fn apply_success(
        &mut self,
        request: PendingRequest,
        value: CompositorHandle,
    ) -> Result<(), Error<T::Error>> {
        match request {
            PendingRequest::Create => {
                let slot = self
                    .surfaces
                    .iter_mut()
                    .find(|slot| !slot.is_used())
                    .ok_or(Error::Protocol(ProtocolError::LocalStateCapacity))?;
                *slot = SurfaceSlot {
                    handle: value,
                    ..SurfaceSlot::EMPTY
                };
            },
            PendingRequest::Destroy { surface } => {
                let index = self
                    .surface_index(surface)
                    .ok_or(Error::Protocol(ProtocolError::UnknownEventSurface))?;
                self.surfaces[index] = SurfaceSlot::EMPTY;
                for buffer in &mut self.buffers {
                    if buffer.surface == surface {
                        *buffer = BufferSlot::EMPTY;
                    }
                }
            },
            PendingRequest::Attach {
                surface,
                width,
                height,
                buffer_token,
            } => {
                let buffer = self
                    .buffers
                    .iter_mut()
                    .find(|buffer| buffer.token == 0)
                    .ok_or(Error::Protocol(ProtocolError::LocalStateCapacity))?;
                *buffer = BufferSlot {
                    surface,
                    token: buffer_token,
                };
                let index = self
                    .surface_index(surface)
                    .ok_or(Error::Protocol(ProtocolError::UnknownEventSurface))?;
                self.surfaces[index].width = width;
                self.surfaces[index].height = height;
                self.surfaces[index].active_buffer_token = buffer_token;
            },
            PendingRequest::SetRole { surface, role } => {
                let index = self
                    .surface_index(surface)
                    .ok_or(Error::Protocol(ProtocolError::UnknownEventSurface))?;
                self.surfaces[index].role = role;
            },
            PendingRequest::SetState {
                surface,
                state,
                mask,
            } => {
                let index = self
                    .surface_index(surface)
                    .ok_or(Error::Protocol(ProtocolError::UnknownEventSurface))?;
                let old = self.surfaces[index].state;
                self.surfaces[index].state = (old & !mask) | state;
            },
            PendingRequest::AckConfigure {
                surface,
                configure_serial,
            } => {
                let index = self
                    .surface_index(surface)
                    .ok_or(Error::Protocol(ProtocolError::UnknownEventSurface))?;
                if self.surfaces[index].pending_configure_serial == configure_serial {
                    self.surfaces[index].pending_configure_serial = 0;
                }
            },
            PendingRequest::Commit | PendingRequest::SetTitle => {},
        }
        Ok(())
    }

    fn accept_event(
        &mut self,
        serial: u64,
        surface: CompositorHandle,
        kind: EventKind,
    ) -> Result<Incoming, Error<T::Error>> {
        let surface_index = self
            .surface_index(surface)
            .ok_or(Error::Protocol(ProtocolError::UnknownEventSurface))?;
        match kind {
            EventKind::Configure(configure) => {
                let slot = &mut self.surfaces[surface_index];
                slot.pending_configure_serial = serial;
                slot.configured_width = configure.width;
                slot.configured_height = configure.height;
            },
            EventKind::BufferRelease(release) => {
                let index = self
                    .buffers
                    .iter()
                    .position(|buffer| {
                        buffer.surface == surface && buffer.token == release.buffer_token
                    })
                    .ok_or(Error::Protocol(ProtocolError::UnexpectedBufferToken))?;
                self.buffers[index] = BufferSlot::EMPTY;
                if self.surfaces[surface_index].active_buffer_token == release.buffer_token {
                    self.surfaces[surface_index].active_buffer_token = 0;
                }
            },
            _ => {},
        }
        Ok(Incoming::Event(Event {
            serial,
            surface,
            kind,
        }))
    }
}

fn protocol_error(error: WireError) -> ProtocolError {
    match error {
        WireError::Truncated | WireError::InvalidHeader => ProtocolError::InvalidHeader,
        WireError::InvalidPayload => ProtocolError::InvalidPayload,
    }
}

fn outgoing_error<E>(_: WireError) -> Error<E> {
    Error::Protocol(ProtocolError::InvalidOutgoingRecord)
}

fn put_u16<E>(output: &mut [u8], offset: usize, value: u16) -> Result<(), Error<E>> {
    wire::put_u16(output, offset, value).map_err(outgoing_error)
}

fn put_u32<E>(output: &mut [u8], offset: usize, value: u32) -> Result<(), Error<E>> {
    wire::put_u32(output, offset, value).map_err(outgoing_error)
}

fn put_u64<E>(output: &mut [u8], offset: usize, value: u64) -> Result<(), Error<E>> {
    wire::put_u64(output, offset, value).map_err(outgoing_error)
}

fn reset_send_record(record: &mut IpcSendMessage) {
    record.version = IPC_ABI_VERSION;
    record.header_size = IPC_MESSAGE_HEADER_SIZE;
    record.payload_length = 0;
    record.transfer_count = 0;
    record.flags = 0;
    record.reserved = 0;
    record.transfers.fill(IpcSendTransfer::default());
    record.payload.fill(0);
}

fn reset_receive_record(record: &mut IpcReceiveMessage) {
    record.version = IPC_ABI_VERSION;
    record.header_size = IPC_MESSAGE_HEADER_SIZE;
    record.payload_length = 0;
    record.transfer_count = 0;
    record.flags = 0;
    record.reserved = 0;
    record.transfers.fill(IpcReceiveTransfer::default());
    record.payload.fill(0);
}
