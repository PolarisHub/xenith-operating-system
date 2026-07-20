use std::collections::VecDeque;

use libwindow::{
    ArgumentError, Client, Error, EventKind, Incoming, ProtocolError, RequestKind, StateError,
    Transport,
};
use xenith_abi::compositor::{
    CompositorDamageRect, CompositorHandle, CompositorSurfaceMetadata,
    COMPOSITOR_COMMIT_REQUEST_FRAME_DONE, COMPOSITOR_EVENT_BUFFER_RELEASE, COMPOSITOR_EVENT_CLOSE,
    COMPOSITOR_EVENT_CONFIGURE, COMPOSITOR_EVENT_FOCUS, COMPOSITOR_EVENT_FRAME_DONE,
    COMPOSITOR_EVENT_KEY, COMPOSITOR_EVENT_POINTER, COMPOSITOR_EVENT_TEXT, COMPOSITOR_FOCUS_IN,
    COMPOSITOR_FORMAT_BGRA8888, COMPOSITOR_HEADER_SIZE, COMPOSITOR_KEY_PRESSED,
    COMPOSITOR_KIND_EVENT, COMPOSITOR_KIND_REPLY, COMPOSITOR_MAGIC,
    COMPOSITOR_POINTER_ACTION_MOTION, COMPOSITOR_REPLY_STATUS, COMPOSITOR_REQUEST_ACK_CONFIGURE,
    COMPOSITOR_REQUEST_ATTACH_BUFFER, COMPOSITOR_REQUEST_COMMIT, COMPOSITOR_REQUEST_CREATE_SURFACE,
    COMPOSITOR_REQUEST_DESTROY_SURFACE, COMPOSITOR_REQUEST_SET_ROLE, COMPOSITOR_REQUEST_SET_STATE,
    COMPOSITOR_REQUEST_SET_TITLE, COMPOSITOR_ROLE_TOPLEVEL, COMPOSITOR_STATE_ACTIVATED,
    COMPOSITOR_STATE_MAXIMIZED, COMPOSITOR_STATUS_INVALID_STATE, COMPOSITOR_STATUS_OK,
    COMPOSITOR_VERSION,
};
use xenith_abi::{
    IpcReceiveMessage, IpcReceiveTransfer, IpcSendMessage, IPC_TRANSFER_RIGHT_MAP,
    IPC_TRANSFER_RIGHT_READ,
};

const TIMEOUT: u64 = 50_000_000;
const SURFACE: CompositorHandle = CompositorHandle::from_parts(7, 3);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FakeError;

#[derive(Default)]
struct FakeTransport {
    sent: Vec<IpcSendMessage>,
    incoming: VecDeque<IpcReceiveMessage>,
    closed: Vec<i32>,
    fail_send: bool,
    fail_receive: bool,
}

impl FakeTransport {
    fn push(&mut self, message: IpcReceiveMessage) {
        self.incoming.push_back(message);
    }
}

impl Transport for FakeTransport {
    type Error = FakeError;

    fn send(&mut self, message: &IpcSendMessage, _timeout_ns: u64) -> Result<usize, Self::Error> {
        if self.fail_send {
            return Err(FakeError);
        }
        self.sent.push(*message);
        Ok(message.payload_length as usize)
    }

    fn receive(
        &mut self,
        message: &mut IpcReceiveMessage,
        _timeout_ns: u64,
    ) -> Result<usize, Self::Error> {
        if self.fail_receive {
            return Err(FakeError);
        }
        let next = self.incoming.pop_front().ok_or(FakeError)?;
        let length = next.payload_length as usize;
        *message = next;
        Ok(length)
    }

    fn close_descriptor(&mut self, descriptor: i32) {
        self.closed.push(descriptor);
    }
}

#[test]
fn create_request_is_canonical_golden_bytes_and_busy_until_reply() {
    let mut client = Client::new(FakeTransport::default());
    assert_eq!(client.create_surface(TIMEOUT), Ok(1));
    assert_eq!(
        client.create_surface(TIMEOUT),
        Err(Error::State(StateError::RequestPending))
    );

    let message = &client.transport().sent[0];
    assert!(message.is_valid());
    assert_eq!(message.transfer_count, 0);
    assert_eq!(message.payload_length, 56);
    assert_header(
        message,
        COMPOSITOR_REQUEST_CREATE_SURFACE,
        1,
        CompositorHandle::INVALID,
        16,
    );
    assert!(message.payload[40..56].iter().all(|byte| *byte == 0));
    assert!(message.payload[56..].iter().all(|byte| *byte == 0));

    client
        .transport_mut()
        .push(status_reply(1, COMPOSITOR_STATUS_OK, SURFACE));
    assert_eq!(
        client.receive(TIMEOUT),
        Ok(Incoming::Reply(libwindow::Reply {
            serial: 1,
            request: RequestKind::CreateSurface,
            status: COMPOSITOR_STATUS_OK,
            value: SURFACE,
        }))
    );
    assert_eq!(client.tracked_surface_count(), 1);
    assert_eq!(client.surface_info(SURFACE).unwrap().handle, SURFACE);
}

#[test]
fn every_request_has_exact_little_endian_payload_and_monotonic_serial() {
    let mut client = connected_client();

    assert_eq!(
        client.set_role(
            SURFACE,
            COMPOSITOR_ROLE_TOPLEVEL,
            CompositorHandle::INVALID,
            TIMEOUT
        ),
        Ok(2)
    );
    let message = last_sent(&client);
    assert_header(message, COMPOSITOR_REQUEST_SET_ROLE, 2, SURFACE, 32);
    assert_eq!(
        &message.payload[40..42],
        &COMPOSITOR_ROLE_TOPLEVEL.to_le_bytes()
    );
    assert!(message.payload[42..72].iter().all(|byte| *byte == 0));
    complete_ok(&mut client, 2, RequestKind::SetRole);

    assert_eq!(client.set_title(SURFACE, "Xenith ✦", TIMEOUT), Ok(3));
    let message = last_sent(&client);
    assert_header(message, COMPOSITOR_REQUEST_SET_TITLE, 3, SURFACE, 280);
    let title = "Xenith ✦".as_bytes();
    assert_eq!(
        &message.payload[40..42],
        &(title.len() as u16).to_le_bytes()
    );
    assert_eq!(&message.payload[48..48 + title.len()], title);
    assert!(message.payload[48 + title.len()..320]
        .iter()
        .all(|byte| *byte == 0));
    complete_ok(&mut client, 3, RequestKind::SetTitle);

    let state = COMPOSITOR_STATE_ACTIVATED | COMPOSITOR_STATE_MAXIMIZED;
    assert_eq!(client.set_state(SURFACE, state, state, TIMEOUT), Ok(4));
    let message = last_sent(&client);
    assert_header(message, COMPOSITOR_REQUEST_SET_STATE, 4, SURFACE, 24);
    assert_eq!(&message.payload[40..44], &state.to_le_bytes());
    assert_eq!(&message.payload[44..48], &state.to_le_bytes());
    assert!(message.payload[48..64].iter().all(|byte| *byte == 0));
    complete_ok(&mut client, 4, RequestKind::SetState);
    assert_eq!(client.surface_info(SURFACE).unwrap().state, state);

    let metadata = surface_metadata(0x1122_3344_5566_7788);
    assert_eq!(
        client.attach_buffer(SURFACE, 9, 0x80_000, metadata, TIMEOUT),
        Ok(5)
    );
    let message = last_sent(&client);
    assert_header(message, COMPOSITOR_REQUEST_ATTACH_BUFFER, 5, SURFACE, 56);
    assert_eq!(message.transfer_count, 1);
    assert_eq!(message.transfers[0].source_fd, 9);
    assert_eq!(
        message.transfers[0].rights,
        IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_MAP
    );
    assert_eq!(message.transfers[0].tag, metadata.buffer_token);
    assert!(message.transfers[1..]
        .iter()
        .all(|transfer| transfer.is_zero()));
    assert_eq!(&message.payload[40..44], &metadata.width.to_le_bytes());
    assert_eq!(&message.payload[44..48], &metadata.height.to_le_bytes());
    assert_eq!(&message.payload[48..52], &metadata.stride.to_le_bytes());
    assert_eq!(&message.payload[52..56], &metadata.format.to_le_bytes());
    assert_eq!(
        &message.payload[56..64],
        &metadata.buffer_token.to_le_bytes()
    );
    assert_eq!(&message.payload[64..72], &metadata.offset.to_le_bytes());
    assert_eq!(&message.payload[72..80], &metadata.length.to_le_bytes());
    assert!(message.payload[80..96].iter().all(|byte| *byte == 0));
    complete_ok(&mut client, 5, RequestKind::AttachBuffer);

    client
        .transport_mut()
        .push(configure_event(77, SURFACE, 320, 200));
    assert!(matches!(
        client.receive(TIMEOUT),
        Ok(Incoming::Event(libwindow::Event {
            serial: 77,
            kind: EventKind::Configure(_),
            ..
        }))
    ));
    assert_eq!(client.ack_configure(SURFACE, 77, TIMEOUT), Ok(6));
    let message = last_sent(&client);
    assert_header(message, COMPOSITOR_REQUEST_ACK_CONFIGURE, 6, SURFACE, 24);
    assert_eq!(&message.payload[40..48], &77_u64.to_le_bytes());
    assert!(message.payload[48..64].iter().all(|byte| *byte == 0));
    complete_ok(&mut client, 6, RequestKind::AckConfigure);

    let damage = [
        CompositorDamageRect {
            x: 1,
            y: 2,
            width: 30,
            height: 40,
        },
        CompositorDamageRect {
            x: 100,
            y: 80,
            width: 10,
            height: 20,
        },
    ];
    assert_eq!(client.commit(SURFACE, &damage, Some(99), TIMEOUT), Ok(7));
    let message = last_sent(&client);
    assert_header(message, COMPOSITOR_REQUEST_COMMIT, 7, SURFACE, 1056);
    assert_eq!(&message.payload[40..48], &99_u64.to_le_bytes());
    assert_eq!(&message.payload[48..52], &2_u32.to_le_bytes());
    assert_eq!(
        &message.payload[52..56],
        &COMPOSITOR_COMMIT_REQUEST_FRAME_DONE.to_le_bytes()
    );
    assert_eq!(&message.payload[56..60], &1_u32.to_le_bytes());
    assert_eq!(&message.payload[60..64], &2_u32.to_le_bytes());
    assert_eq!(&message.payload[64..68], &30_u32.to_le_bytes());
    assert_eq!(&message.payload[68..72], &40_u32.to_le_bytes());
    assert!(message.payload[88..1096].iter().all(|byte| *byte == 0));
    complete_ok(&mut client, 7, RequestKind::Commit);

    assert_eq!(client.destroy_surface(SURFACE, TIMEOUT), Ok(8));
    let message = last_sent(&client);
    assert_header(message, COMPOSITOR_REQUEST_DESTROY_SURFACE, 8, SURFACE, 16);
    assert!(message.payload[40..56].iter().all(|byte| *byte == 0));
    complete_ok(&mut client, 8, RequestKind::DestroySurface);
    assert_eq!(client.tracked_surface_count(), 0);
    assert_eq!(client.tracked_buffer_count(), 0);
}

#[test]
fn event_state_transitions_gate_ack_commit_and_buffer_reuse() {
    let mut client = connected_client();
    let metadata = surface_metadata(44);
    client
        .attach_buffer(SURFACE, 6, 0x80_000, metadata, TIMEOUT)
        .unwrap();
    complete_ok(&mut client, 2, RequestKind::AttachBuffer);
    assert_eq!(client.tracked_buffer_count(), 1);

    client
        .transport_mut()
        .push(configure_event(900, SURFACE, 800, 600));
    client.receive(TIMEOUT).unwrap();
    assert_eq!(
        client.commit(SURFACE, &[], None, TIMEOUT),
        Err(Error::State(StateError::ConfigureUnacknowledged))
    );
    assert_eq!(
        client.ack_configure(SURFACE, 899, TIMEOUT),
        Err(Error::State(StateError::ConfigureNotPending))
    );
    client.ack_configure(SURFACE, 900, TIMEOUT).unwrap();

    // A newer configuration may arrive before the old acknowledgement reply.
    client
        .transport_mut()
        .push(configure_event(901, SURFACE, 1024, 768));
    client.receive(TIMEOUT).unwrap();
    complete_ok(&mut client, 3, RequestKind::AckConfigure);
    assert_eq!(
        client
            .surface_info(SURFACE)
            .unwrap()
            .pending_configure_serial,
        901
    );

    client.ack_configure(SURFACE, 901, TIMEOUT).unwrap();
    complete_ok(&mut client, 4, RequestKind::AckConfigure);
    assert_eq!(
        client
            .surface_info(SURFACE)
            .unwrap()
            .pending_configure_serial,
        0
    );
    assert_eq!(
        client.commit(SURFACE, &[], None, TIMEOUT),
        Err(Error::State(StateError::BufferDoesNotMatchConfigure))
    );

    let replacement = CompositorSurfaceMetadata {
        width: 1024,
        height: 768,
        stride: 4096,
        format: COMPOSITOR_FORMAT_BGRA8888,
        buffer_token: 45,
        offset: 4096,
        length: 3_145_728,
        reserved: [0; 2],
    };
    client
        .attach_buffer(SURFACE, 7, 0x40_0000, replacement, TIMEOUT)
        .unwrap();
    complete_ok(&mut client, 5, RequestKind::AttachBuffer);
    client.commit(SURFACE, &[], None, TIMEOUT).unwrap();
    complete_ok(&mut client, 6, RequestKind::Commit);

    client
        .transport_mut()
        .push(buffer_release_event(77, SURFACE, metadata.buffer_token));
    client.receive(TIMEOUT).unwrap();
    assert_eq!(client.tracked_buffer_count(), 1);
    assert_eq!(
        client.surface_info(SURFACE).unwrap().active_buffer_token,
        replacement.buffer_token
    );
    client
        .transport_mut()
        .push(buffer_release_event(78, SURFACE, replacement.buffer_token));
    client.receive(TIMEOUT).unwrap();
    assert_eq!(client.tracked_buffer_count(), 0);
    assert_eq!(client.surface_info(SURFACE).unwrap().active_buffer_token, 0);
    assert_eq!(
        client.commit(SURFACE, &[], None, TIMEOUT),
        Err(Error::State(StateError::NoBufferAttached))
    );
}

#[test]
fn malformed_records_replies_events_and_object_references_are_rejected() {
    let mut client = connected_client();
    client.set_title(SURFACE, "pending", TIMEOUT).unwrap();

    let mut bad_tail = status_reply(2, COMPOSITOR_STATUS_OK, CompositorHandle::INVALID);
    bad_tail.payload[bad_tail.payload_length as usize] = 1;
    client.transport_mut().push(bad_tail);
    assert_eq!(
        client.receive(TIMEOUT),
        Err(Error::Protocol(ProtocolError::InvalidIpcRecord))
    );

    let mut transferred = status_reply(2, COMPOSITOR_STATUS_OK, CompositorHandle::INVALID);
    transferred.transfer_count = 1;
    transferred.transfers[0] = IpcReceiveTransfer {
        installed_fd: 4,
        rights: IPC_TRANSFER_RIGHT_READ,
        tag: 1,
    };
    client.transport_mut().push(transferred);
    assert_eq!(
        client.receive(TIMEOUT),
        Err(Error::Protocol(ProtocolError::UnexpectedTransfer))
    );
    assert_eq!(client.transport().closed, [4]);

    let mut bad_magic = status_reply(2, COMPOSITOR_STATUS_OK, CompositorHandle::INVALID);
    put_u32(&mut bad_magic.payload, 0, 0);
    client.transport_mut().push(bad_magic);
    assert_eq!(
        client.receive(TIMEOUT),
        Err(Error::Protocol(ProtocolError::InvalidHeader))
    );

    let mut bad_status = status_reply(2, COMPOSITOR_STATUS_OK, CompositorHandle::INVALID);
    put_i32(&mut bad_status.payload, 40, -999);
    client.transport_mut().push(bad_status);
    assert_eq!(
        client.receive(TIMEOUT),
        Err(Error::Protocol(ProtocolError::InvalidPayload))
    );

    client.transport_mut().push(status_reply(
        99,
        COMPOSITOR_STATUS_OK,
        CompositorHandle::INVALID,
    ));
    assert_eq!(
        client.receive(TIMEOUT),
        Err(Error::Protocol(ProtocolError::ReplySerialMismatch {
            expected: 2,
            actual: 99,
        }))
    );

    client.transport_mut().push(configure_event(
        8,
        CompositorHandle::from_parts(99, 1),
        20,
        20,
    ));
    assert_eq!(
        client.receive(TIMEOUT),
        Err(Error::Protocol(ProtocolError::UnknownEventSurface))
    );

    let mut bad_pointer = server_message(
        COMPOSITOR_KIND_EVENT,
        COMPOSITOR_EVENT_POINTER,
        10,
        SURFACE,
        64,
    );
    // Unknown action and a noncanonical reserved word.
    put_u16(&mut bad_pointer.payload, 40 + 30, 99);
    put_u32(&mut bad_pointer.payload, 40 + 44, 1);
    client.transport_mut().push(bad_pointer);
    assert_eq!(
        client.receive(TIMEOUT),
        Err(Error::Protocol(ProtocolError::InvalidPayload))
    );

    let mut bad_text = server_message(
        COMPOSITOR_KIND_EVENT,
        COMPOSITOR_EVENT_TEXT,
        11,
        SURFACE,
        88,
    );
    put_u16(&mut bad_text.payload, 40, 2);
    bad_text.payload[48] = 0xC0;
    bad_text.payload[49] = 0xAF;
    client.transport_mut().push(bad_text);
    assert_eq!(
        client.receive(TIMEOUT),
        Err(Error::Protocol(ProtocolError::InvalidPayload))
    );

    // The outstanding request remains correlated after malformed traffic.
    client.transport_mut().push(status_reply(
        2,
        COMPOSITOR_STATUS_INVALID_STATE,
        CompositorHandle::INVALID,
    ));
    assert!(matches!(
        client.receive(TIMEOUT),
        Ok(Incoming::Reply(libwindow::Reply {
            request: RequestKind::SetTitle,
            status: COMPOSITOR_STATUS_INVALID_STATE,
            ..
        }))
    ));
}

#[test]
fn hostile_server_transfers_are_closed_before_any_protocol_error() {
    let mut client = connected_client();
    client.set_title(SURFACE, "pending", TIMEOUT).unwrap();

    let mut transferred = status_reply(2, COMPOSITOR_STATUS_OK, CompositorHandle::INVALID);
    transferred.transfer_count = 4;
    for (index, descriptor) in [0, 17, 17, 29].into_iter().enumerate() {
        transferred.transfers[index] = IpcReceiveTransfer {
            installed_fd: descriptor,
            rights: IPC_TRANSFER_RIGHT_READ,
            tag: index as u64,
        };
    }
    client.transport_mut().push(transferred);
    assert_eq!(
        client.receive(TIMEOUT),
        Err(Error::Protocol(ProtocolError::UnexpectedTransfer))
    );
    assert_eq!(client.transport().closed, [0, 17, 29]);

    let mut malformed = status_reply(2, COMPOSITOR_STATUS_OK, CompositorHandle::INVALID);
    malformed.transfer_count = 1;
    malformed.transfers[0] = IpcReceiveTransfer {
        installed_fd: 31,
        rights: IPC_TRANSFER_RIGHT_READ | IPC_TRANSFER_RIGHT_MAP,
        tag: 7,
    };
    malformed.transfers[3] = IpcReceiveTransfer {
        installed_fd: 37,
        rights: IPC_TRANSFER_RIGHT_READ,
        tag: 8,
    };
    client.transport_mut().push(malformed);
    assert_eq!(
        client.receive(TIMEOUT),
        Err(Error::Protocol(ProtocolError::InvalidIpcRecord))
    );
    assert_eq!(client.transport().closed, [0, 17, 29, 31, 37]);
}

#[test]
fn every_server_event_variant_decodes_from_exact_wire_offsets() {
    let mut client = connected_client();
    let metadata = surface_metadata(123);
    client
        .attach_buffer(SURFACE, 6, 0x80_000, metadata, TIMEOUT)
        .unwrap();
    complete_ok(&mut client, 2, RequestKind::AttachBuffer);

    client
        .transport_mut()
        .push(configure_event(100, SURFACE, 320, 200));
    assert!(matches!(
        client.receive(TIMEOUT),
        Ok(Incoming::Event(libwindow::Event {
            kind: EventKind::Configure(_),
            ..
        }))
    ));

    let mut close = server_message(
        COMPOSITOR_KIND_EVENT,
        COMPOSITOR_EVENT_CLOSE,
        101,
        SURFACE,
        24,
    );
    put_u32(&mut close.payload, 40, 9);
    client.transport_mut().push(close);
    assert!(matches!(
        client.receive(TIMEOUT),
        Ok(Incoming::Event(libwindow::Event {
            kind: EventKind::Close(event),
            ..
        })) if event.reason == 9
    ));

    let mut focus = server_message(
        COMPOSITOR_KIND_EVENT,
        COMPOSITOR_EVENT_FOCUS,
        102,
        SURFACE,
        24,
    );
    put_u32(&mut focus.payload, 40, COMPOSITOR_FOCUS_IN);
    put_u32(&mut focus.payload, 44, 4);
    client.transport_mut().push(focus);
    assert!(matches!(
        client.receive(TIMEOUT),
        Ok(Incoming::Event(libwindow::Event {
            kind: EventKind::Focus(event),
            ..
        })) if event.focused == COMPOSITOR_FOCUS_IN && event.seat == 4
    ));

    let mut pointer = server_message(
        COMPOSITOR_KIND_EVENT,
        COMPOSITOR_EVENT_POINTER,
        103,
        SURFACE,
        64,
    );
    put_u64(&mut pointer.payload, 40, 123_456);
    put_i32(&mut pointer.payload, 48, -10);
    put_i32(&mut pointer.payload, 52, 20);
    put_i32(&mut pointer.payload, 56, -2);
    put_i32(&mut pointer.payload, 60, 3);
    put_u16(
        &mut pointer.payload,
        40 + 30,
        COMPOSITOR_POINTER_ACTION_MOTION,
    );
    client.transport_mut().push(pointer);
    assert!(matches!(
        client.receive(TIMEOUT),
        Ok(Incoming::Event(libwindow::Event {
            kind: EventKind::Pointer(event),
            ..
        })) if event.timestamp_ns == 123_456 && event.x == -10 && event.delta_y == 3
    ));

    let mut key = server_message(
        COMPOSITOR_KIND_EVENT,
        COMPOSITOR_EVENT_KEY,
        104,
        SURFACE,
        48,
    );
    put_u64(&mut key.payload, 40, 444);
    put_u32(&mut key.payload, 48, 30);
    put_u32(&mut key.payload, 52, 0x1E);
    put_u32(&mut key.payload, 56, 8);
    put_u16(&mut key.payload, 60, COMPOSITOR_KEY_PRESSED);
    client.transport_mut().push(key);
    assert!(matches!(
        client.receive(TIMEOUT),
        Ok(Incoming::Event(libwindow::Event {
            kind: EventKind::Key(event),
            ..
        })) if event.key_code == 30 && event.scan_code == 0x1E && event.modifiers == 8
    ));

    let mut text = server_message(
        COMPOSITOR_KIND_EVENT,
        COMPOSITOR_EVENT_TEXT,
        105,
        SURFACE,
        88,
    );
    put_u16(&mut text.payload, 40, 5);
    text.payload[48..53].copy_from_slice(b"hello");
    client.transport_mut().push(text);
    assert!(matches!(
        client.receive(TIMEOUT),
        Ok(Incoming::Event(libwindow::Event {
            kind: EventKind::Text(event),
            ..
        })) if event.byte_length == 5 && &event.bytes[..5] == b"hello"
    ));

    let mut frame = server_message(
        COMPOSITOR_KIND_EVENT,
        COMPOSITOR_EVENT_FRAME_DONE,
        106,
        SURFACE,
        48,
    );
    put_u64(&mut frame.payload, 40, 88);
    put_u64(&mut frame.payload, 48, 5_000);
    put_u64(&mut frame.payload, 56, 16_666_667);
    client.transport_mut().push(frame);
    assert!(matches!(
        client.receive(TIMEOUT),
        Ok(Incoming::Event(libwindow::Event {
            kind: EventKind::FrameDone(event),
            ..
        })) if event.frame_token == 88 && event.presentation_time_ns == 5_000
    ));

    client
        .transport_mut()
        .push(buffer_release_event(107, SURFACE, metadata.buffer_token));
    assert!(matches!(
        client.receive(TIMEOUT),
        Ok(Incoming::Event(libwindow::Event {
            kind: EventKind::BufferRelease(event),
            ..
        })) if event.buffer_token == metadata.buffer_token
    ));
}

#[test]
fn request_arguments_and_transport_failures_do_not_corrupt_state() {
    let mut client = connected_client();
    assert_eq!(
        client.set_title(SURFACE, &"x".repeat(257), TIMEOUT),
        Err(Error::Argument(ArgumentError::TitleTooLong))
    );
    assert_eq!(
        client.set_state(SURFACE, 2, 1, TIMEOUT),
        Err(Error::Argument(ArgumentError::InvalidState))
    );
    assert_eq!(
        client.attach_buffer(SURFACE, -1, 4096, surface_metadata(3), TIMEOUT),
        Err(Error::Argument(ArgumentError::InvalidDescriptor))
    );
    assert_eq!(
        client.commit(
            SURFACE,
            &[CompositorDamageRect {
                x: 0,
                y: 0,
                width: 9999,
                height: 1,
            }],
            None,
            TIMEOUT
        ),
        Err(Error::State(StateError::NoBufferAttached))
    );

    client.transport_mut().fail_send = true;
    assert_eq!(
        client.set_title(SURFACE, "valid", TIMEOUT),
        Err(Error::Transport(FakeError))
    );
    assert!(!client.has_pending_request());
    client.transport_mut().fail_send = false;
    // Failed sends still consume a serial; serials are never reused.
    assert_eq!(client.set_title(SURFACE, "valid", TIMEOUT), Ok(3));
}

#[test]
fn serial_maximum_is_emitted_once_then_exhausted_without_wrap() {
    let mut client = Client::with_next_serial(FakeTransport::default(), u64::MAX).unwrap();
    assert_eq!(client.create_surface(TIMEOUT), Ok(u64::MAX));
    client
        .transport_mut()
        .push(status_reply(u64::MAX, COMPOSITOR_STATUS_OK, SURFACE));
    client.receive(TIMEOUT).unwrap();
    assert_eq!(
        client.set_title(SURFACE, "never sent", TIMEOUT),
        Err(Error::State(StateError::SerialExhausted))
    );
    assert_eq!(client.transport().sent.len(), 1);
    assert!(matches!(
        Client::with_next_serial(FakeTransport::default(), 0),
        Err(StateError::SerialExhausted)
    ));
}

fn connected_client() -> Client<FakeTransport> {
    let mut client = Client::new(FakeTransport::default());
    client.create_surface(TIMEOUT).unwrap();
    client
        .transport_mut()
        .push(status_reply(1, COMPOSITOR_STATUS_OK, SURFACE));
    client.receive(TIMEOUT).unwrap();
    client
}

fn complete_ok(client: &mut Client<FakeTransport>, serial: u64, kind: RequestKind) {
    client.transport_mut().push(status_reply(
        serial,
        COMPOSITOR_STATUS_OK,
        CompositorHandle::INVALID,
    ));
    assert!(matches!(
        client.receive(TIMEOUT),
        Ok(Incoming::Reply(libwindow::Reply {
            request,
            status: COMPOSITOR_STATUS_OK,
            ..
        })) if request == kind
    ));
}

fn last_sent(client: &Client<FakeTransport>) -> &IpcSendMessage {
    client.transport().sent.last().unwrap()
}

fn surface_metadata(buffer_token: u64) -> CompositorSurfaceMetadata {
    CompositorSurfaceMetadata {
        width: 320,
        height: 200,
        stride: 1280,
        format: COMPOSITOR_FORMAT_BGRA8888,
        buffer_token,
        offset: 4096,
        length: 256_000,
        reserved: [0; 2],
    }
}

fn status_reply(serial: u64, status: i32, value: CompositorHandle) -> IpcReceiveMessage {
    let mut message = server_message(
        COMPOSITOR_KIND_REPLY,
        COMPOSITOR_REPLY_STATUS,
        serial,
        CompositorHandle::INVALID,
        32,
    );
    put_i32(&mut message.payload, 40, status);
    put_u64(&mut message.payload, 48, value.0);
    message
}

fn configure_event(
    serial: u64,
    surface: CompositorHandle,
    width: u32,
    height: u32,
) -> IpcReceiveMessage {
    let mut message = server_message(
        COMPOSITOR_KIND_EVENT,
        COMPOSITOR_EVENT_CONFIGURE,
        serial,
        surface,
        32,
    );
    put_u32(&mut message.payload, 40, width);
    put_u32(&mut message.payload, 44, height);
    put_u32(&mut message.payload, 52, 1000);
    message
}

fn buffer_release_event(serial: u64, surface: CompositorHandle, token: u64) -> IpcReceiveMessage {
    let mut message = server_message(
        COMPOSITOR_KIND_EVENT,
        COMPOSITOR_EVENT_BUFFER_RELEASE,
        serial,
        surface,
        32,
    );
    put_u64(&mut message.payload, 40, token);
    message
}

fn server_message(
    kind: u16,
    opcode: u16,
    serial: u64,
    object: CompositorHandle,
    payload_size: usize,
) -> IpcReceiveMessage {
    let mut message = IpcReceiveMessage::empty();
    let size = COMPOSITOR_HEADER_SIZE as usize + payload_size;
    message.payload_length = size as u32;
    put_u32(&mut message.payload, 0, COMPOSITOR_MAGIC);
    put_u16(&mut message.payload, 4, COMPOSITOR_VERSION);
    put_u16(&mut message.payload, 6, COMPOSITOR_HEADER_SIZE);
    put_u32(&mut message.payload, 8, size as u32);
    put_u16(&mut message.payload, 12, kind);
    put_u16(&mut message.payload, 14, opcode);
    put_u64(&mut message.payload, 24, serial);
    put_u64(&mut message.payload, 32, object.0);
    message
}

fn assert_header(
    message: &IpcSendMessage,
    opcode: u16,
    serial: u64,
    object: CompositorHandle,
    payload_size: usize,
) {
    assert_eq!(&message.payload[0..4], &COMPOSITOR_MAGIC.to_le_bytes());
    assert_eq!(&message.payload[4..6], &COMPOSITOR_VERSION.to_le_bytes());
    assert_eq!(
        &message.payload[6..8],
        &COMPOSITOR_HEADER_SIZE.to_le_bytes()
    );
    assert_eq!(
        &message.payload[8..12],
        &((COMPOSITOR_HEADER_SIZE as usize + payload_size) as u32).to_le_bytes()
    );
    assert_eq!(&message.payload[12..14], &1_u16.to_le_bytes());
    assert_eq!(&message.payload[14..16], &opcode.to_le_bytes());
    assert!(message.payload[16..24].iter().all(|byte| *byte == 0));
    assert_eq!(&message.payload[24..32], &serial.to_le_bytes());
    assert_eq!(&message.payload[32..40], &object.0.to_le_bytes());
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_i32(output: &mut [u8], offset: usize, value: i32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
