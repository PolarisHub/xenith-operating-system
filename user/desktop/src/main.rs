#![no_std]
#![no_main]

use core::panic::PanicInfo;

use libuser::args::Startup;
use xenith_abi::compositor::{
    CompositorHandle, COMPOSITOR_FORMAT_BGRA8888, COMPOSITOR_FORMAT_BGRX8888,
    COMPOSITOR_STATUS_ACCESS_DENIED, COMPOSITOR_STATUS_INVALID_ARGUMENT,
    COMPOSITOR_STATUS_NO_MEMORY, COMPOSITOR_STATUS_RESOURCE_EXHAUSTED,
};
use xenith_abi::{
    Errno, IpcReceiveMessage, IpcSendMessage, Timespec, UiDisplayInfo, UiInputEvent, UiRect,
    WaitItem, MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, PROT_READ, PROT_WRITE, SIGKILL,
    UI_ABI_VERSION, UI_DISPLAY_NATIVE_PIXEL_FORMAT, UI_EVENT_FLAG_OVERFLOW, UI_EVENT_KEY,
    UI_EVENT_POINTER, WAIT_INTEREST_READABLE, WAIT_READY_HANGUP, WAIT_READY_READABLE,
    WAIT_READY_UI_INPUT, WAIT_TIMEOUT_INFINITE,
};
use xenith_desktop::compositor::{
    BufferSnapshot, ClientHandle, CompositorAction, DispatchBatch, EncodedMessage,
    ExternalCompletion, MappedBuffer, MultiClientCompositor, PresentAction, RoutedMessageBatch,
    SceneRect, SurfaceId, UnmapBufferAction, MAX_CLIENT_BUFFER_MAPPINGS, MAX_CLIENT_SURFACES,
    MAX_COMPOSITOR_CLIENTS, MAX_SCENE_SURFACES,
};
use xenith_desktop::{
    DamageTracker, DesktopState, EventAction, PixelFormat, Point, Rect, Renderer, Size, Surface,
    MAX_DAMAGE_RECTS,
};

const SMOKE_WAIT_NS: u64 = 50_000_000;
const CLIENT_SEND_TIMEOUT_NS: u64 = 50_000_000;
const SMOKE_REAP_POLL_NS: i64 = 5_000_000;
const SMOKE_REAP_ATTEMPTS: usize = 20;
const REFRESH_INTERVAL_NS: u64 = 16_666_667;
// Each surface can retain a current and pending buffer. One extra slot is the
// transactional scratch mapping needed to replace a pending buffer while all
// steady-state slots are occupied; the retired mapping is released on commit.
const MAX_BUFFER_MAPPINGS: usize = MAX_COMPOSITOR_CLIENTS * MAX_CLIENT_BUFFER_MAPPINGS;
const MAX_CHANNEL_BATCH: usize = 8;
const MAX_EVENT_WAIT_ITEMS: usize = MAX_COMPOSITOR_CLIENTS + 1;
const WINDOW_SMOKE_PATH: &[u8] = b"/bin/xenith-window-smoke";
const WINDOW_SMOKE_ARGV0: &[u8] = b"/bin/xenith-window-smoke\0";
const EXPLORER_PATH: &[u8] = b"/bin/xenith-explorer";
const EXPLORER_ARGV0: &[u8] = b"/bin/xenith-explorer\0";
const WINDOW_CLIENT_CHANNEL_FD: i32 = 3;

#[derive(Clone, Copy)]
enum LoopExit {
    RecoveryChord,
    SmokeComplete,
}

#[derive(Clone, Copy)]
enum WindowClientKind {
    Smoke,
    Explorer,
}

#[derive(Clone, Copy)]
struct Failure {
    stage: &'static str,
    errno: i32,
}

#[derive(Clone, Copy, Default)]
struct StartupOptions {
    smoke_exit: bool,
    window_smoke: bool,
}

#[derive(Clone, Copy)]
struct NativePixelFormat {
    red_shift: u8,
    red_size: u8,
    green_shift: u8,
    green_size: u8,
    blue_shift: u8,
    blue_size: u8,
}

impl NativePixelFormat {
    const fn from_display(display: UiDisplayInfo) -> Self {
        Self {
            red_shift: display.red_shift,
            red_size: display.red_size,
            green_shift: display.green_shift,
            green_size: display.green_size,
            blue_shift: display.blue_shift,
            blue_size: display.blue_size,
        }
    }

    fn pack(self, red: u8, green: u8, blue: u8) -> u32 {
        pack_channel(red, self.red_shift, self.red_size)
            | pack_channel(green, self.green_shift, self.green_size)
            | pack_channel(blue, self.blue_shift, self.blue_size)
    }

    fn unpack(self, pixel: u32) -> (u8, u8, u8) {
        (
            unpack_channel(pixel, self.red_shift, self.red_size),
            unpack_channel(pixel, self.green_shift, self.green_size),
            unpack_channel(pixel, self.blue_shift, self.blue_size),
        )
    }
}

#[derive(Clone, Copy)]
struct MappingSlot {
    client: ClientHandle,
    address: u64,
    length: u64,
    token: u64,
}

impl MappingSlot {
    const EMPTY: Self = Self {
        client: ClientHandle::INVALID,
        address: 0,
        length: 0,
        token: 0,
    };

    const fn is_used(self) -> bool {
        self.address != 0
    }
}

#[derive(Clone, Copy)]
struct WindowLayer {
    id: SurfaceId,
    buffer: BufferSnapshot,
    x: i32,
    y: i32,
}

impl WindowLayer {
    const EMPTY: Self = Self {
        id: SurfaceId::new(ClientHandle::INVALID, CompositorHandle::INVALID),
        buffer: BufferSnapshot {
            mapping_address: 0,
            mapping_length: 0,
            data_offset: 0,
            data_length: 0,
            buffer_token: 0,
            width: 0,
            height: 0,
            stride: 0,
            format: 0,
        },
        x: 0,
        y: 0,
    };

    const fn is_used(self) -> bool {
        self.id.is_valid()
    }

    const fn bounds(self) -> Rect {
        Rect::new(self.x, self.y, self.buffer.width, self.buffer.height)
    }
}

#[derive(Clone, Copy)]
struct ClientConnection {
    client: ClientHandle,
    server_fd: i32,
    peer_fd: i32,
}

impl ClientConnection {
    const EMPTY: Self = Self {
        client: ClientHandle::INVALID,
        server_fd: -1,
        peer_fd: -1,
    };

    const fn is_used(self) -> bool {
        self.client.is_valid() && self.server_fd >= 0
    }
}

struct FrameContext<'a> {
    mapping: *mut u8,
    length: usize,
    stride: usize,
    render_format: PixelFormat,
    native_format: NativePixelFormat,
    renderer: &'a Renderer,
    state: &'a mut DesktopState,
}

enum SendError {
    Disconnected(ClientHandle),
    Fatal(Failure),
}

enum MessageOutcome {
    Continue,
    Disconnect,
}

struct CompositorRuntime {
    compositor: MultiClientCompositor,
    connections: [ClientConnection; MAX_COMPOSITOR_CLIENTS],
    smoke_client: ClientHandle,
    smoke_pid: i64,
    explorer_client: ClientHandle,
    explorer_pid: i64,
    mappings: [MappingSlot; MAX_BUFFER_MAPPINGS],
    layers: [WindowLayer; MAX_SCENE_SURFACES],
}

impl CompositorRuntime {
    fn new(size: Size) -> Result<Self, Failure> {
        let (window_width, window_height) = default_window_size(size);
        let compositor =
            MultiClientCompositor::new(size.width, size.height, window_width, window_height, 1000)
                .map_err(|_| Failure {
                    stage: "compositor-state",
                    errno: 0,
                })?;
        Ok(Self {
            compositor,
            // Idle desktop sessions pay no channel-queue allocation. Files
            // and the protocol smoke each provision a private pair only when
            // explicitly launched.
            connections: [ClientConnection::EMPTY; MAX_COMPOSITOR_CLIENTS],
            smoke_client: ClientHandle::INVALID,
            smoke_pid: -1,
            explorer_client: ClientHandle::INVALID,
            explorer_pid: -1,
            mappings: [MappingSlot::EMPTY; MAX_BUFFER_MAPPINGS],
            layers: [WindowLayer::EMPTY; MAX_SCENE_SURFACES],
        })
    }

    fn launch_window_smoke(&mut self) -> Result<(), Failure> {
        if self.smoke_client.is_valid() {
            return Err(Failure {
                stage: "smoke-channel",
                errno: 0,
            });
        }
        let pid = match self.launch_window_client(
            WINDOW_SMOKE_PATH,
            WINDOW_SMOKE_ARGV0,
            "spawn-window-smoke-restricted",
            WindowClientKind::Smoke,
        ) {
            Ok(pid) => pid,
            Err(failure) => {
                return Err(self
                    .abort_window_client(WindowClientKind::Smoke)
                    .unwrap_or(failure));
            },
        };
        libuser::println!("XENITH_COMPOSITOR_SMOKE_SPAWN pid={}", pid);
        Ok(())
    }

    fn launch_explorer(&mut self) -> Result<(), Failure> {
        if self.connection(self.explorer_client).is_some() {
            libuser::println!("XENITH_EXPLORER_ALREADY_OPEN");
            return Ok(());
        }
        self.explorer_client = ClientHandle::INVALID;
        if self.explorer_pid > 0 {
            let mut status = 0;
            match libuser::syscall::waitpid(self.explorer_pid, &mut status, xenith_abi::WNOHANG) {
                Ok(reaped) if reaped == self.explorer_pid => self.explorer_pid = -1,
                Ok(0) => {
                    libuser::println!("XENITH_EXPLORER_ALREADY_OPEN");
                    return Ok(());
                },
                Err(libuser::Error(errno)) if errno == Errno::Eintr as i32 => {
                    libuser::println!("XENITH_EXPLORER_ALREADY_OPEN");
                    return Ok(());
                },
                Err(libuser::Error(errno)) if errno == Errno::Echild as i32 => {
                    self.explorer_pid = -1;
                },
                Ok(_) => {
                    return Err(Failure {
                        stage: "reap-explorer-result",
                        errno: 0,
                    });
                },
                Err(libuser::Error(errno)) => {
                    return Err(Failure {
                        stage: "reap-explorer",
                        errno,
                    });
                },
            }
        }
        let pid = match self.launch_window_client(
            EXPLORER_PATH,
            EXPLORER_ARGV0,
            "spawn-explorer-restricted",
            WindowClientKind::Explorer,
        ) {
            Ok(pid) => pid,
            Err(failure) => {
                return Err(self
                    .abort_window_client(WindowClientKind::Explorer)
                    .unwrap_or(failure));
            },
        };
        libuser::println!("XENITH_EXPLORER_SPAWN pid={}", pid);
        Ok(())
    }

    fn launch_window_client(
        &mut self,
        path: &[u8],
        argv0: &[u8],
        spawn_stage: &'static str,
        kind: WindowClientKind,
    ) -> Result<i64, Failure> {
        let pair = libuser::channel_create().map_err(|libuser::Error(errno)| Failure {
            stage: "channel-create",
            errno,
        })?;
        if !pair.is_valid() {
            if pair.endpoint0 >= 0 {
                let _ = libuser::syscall::close(pair.endpoint0);
            }
            if pair.endpoint1 >= 0 && pair.endpoint1 != pair.endpoint0 {
                let _ = libuser::syscall::close(pair.endpoint1);
            }
            return Err(Failure {
                stage: "channel-pair",
                errno: 0,
            });
        }
        let client = match self.compositor.connect() {
            Ok(client) => client,
            Err(_) => {
                let _ = libuser::syscall::close(pair.endpoint0);
                let _ = libuser::syscall::close(pair.endpoint1);
                return Err(Failure {
                    stage: "compositor-connect",
                    errno: 0,
                });
            },
        };
        let Some(connection) = self
            .connections
            .iter_mut()
            .find(|connection| !connection.is_used())
        else {
            let _ = self.compositor.disconnect(client);
            let _ = libuser::syscall::close(pair.endpoint0);
            let _ = libuser::syscall::close(pair.endpoint1);
            return Err(Failure {
                stage: "connection-capacity",
                errno: 0,
            });
        };
        *connection = ClientConnection {
            client,
            server_fd: pair.endpoint0,
            peer_fd: pair.endpoint1,
        };
        let mut child_channel = [0u8; 12];
        if !write_decimal_fd(WINDOW_CLIENT_CHANNEL_FD, &mut child_channel) {
            *connection = ClientConnection::EMPTY;
            let _ = self.compositor.disconnect(client);
            let _ = libuser::syscall::close(pair.endpoint0);
            let _ = libuser::syscall::close(pair.endpoint1);
            return Err(Failure {
                stage: "window-client-argv",
                errno: 0,
            });
        }
        let argv = [argv0.as_ptr(), child_channel.as_ptr(), core::ptr::null()];
        let mut request = libuser::SpawnRestrictedRequest {
            file_action_count: 3,
            ..libuser::SpawnRestrictedRequest::default()
        };
        request.file_actions[0] = libuser::SpawnFileAction {
            source_fd: 1,
            target_fd: 1,
            rights: libuser::IPC_TRANSFER_RIGHT_WRITE,
            flags: 0,
        };
        request.file_actions[1] = libuser::SpawnFileAction {
            source_fd: 2,
            target_fd: 2,
            rights: libuser::IPC_TRANSFER_RIGHT_WRITE,
            flags: 0,
        };
        request.file_actions[2] = libuser::SpawnFileAction {
            source_fd: pair.endpoint1,
            target_fd: WINDOW_CLIENT_CHANNEL_FD,
            rights: libuser::IPC_TRANSFER_RIGHT_READ | libuser::IPC_TRANSFER_RIGHT_WRITE,
            flags: 0,
        };
        let pid = match libuser::spawn_restricted(path, argv.as_ptr(), core::ptr::null(), &request)
        {
            Ok(pid) => pid,
            Err(libuser::Error(errno)) => {
                *connection = ClientConnection::EMPTY;
                let _ = self.compositor.disconnect(client);
                let _ = libuser::syscall::close(pair.endpoint0);
                let _ = libuser::syscall::close(pair.endpoint1);
                return Err(Failure {
                    stage: spawn_stage,
                    errno,
                });
            },
        };
        match kind {
            WindowClientKind::Smoke => {
                self.smoke_client = client;
                self.smoke_pid = pid;
            },
            WindowClientKind::Explorer => {
                self.explorer_client = client;
                self.explorer_pid = pid;
            },
        }
        libuser::syscall::close(pair.endpoint1).map_err(|libuser::Error(errno)| Failure {
            stage: "close-client-endpoint",
            errno,
        })?;
        self.connection_mut(client)
            .ok_or(Failure {
                stage: "connection-lost",
                errno: 0,
            })?
            .peer_fd = -1;
        Ok(pid)
    }

    fn abort_window_client(&mut self, kind: WindowClientKind) -> Option<Failure> {
        let client = match kind {
            WindowClientKind::Smoke => self.smoke_client,
            WindowClientKind::Explorer => self.explorer_client,
        };
        let mut first = None;
        if client.is_valid() {
            if let Some(index) = self
                .connections
                .iter()
                .position(|connection| connection.is_used() && connection.client == client)
            {
                let connection = self.connections[index];
                self.connections[index] = ClientConnection::EMPTY;
                for descriptor in [connection.server_fd, connection.peer_fd] {
                    if descriptor < 0 {
                        continue;
                    }
                    if let Err(libuser::Error(errno)) = libuser::syscall::close(descriptor) {
                        if errno != Errno::Ebadf as i32 && first.is_none() {
                            first = Some(Failure {
                                stage: "abort-window-client-channel",
                                errno,
                            });
                        }
                    }
                }
            }
            if self.compositor.disconnect(client).is_err() && first.is_none() {
                first = Some(Failure {
                    stage: "abort-window-client-compositor",
                    errno: 0,
                });
            }
        }
        let reap = match kind {
            WindowClientKind::Smoke => {
                self.smoke_client = ClientHandle::INVALID;
                Self::reap_child_bounded(&mut self.smoke_pid)
            },
            WindowClientKind::Explorer => {
                self.explorer_client = ClientHandle::INVALID;
                Self::reap_child_bounded(&mut self.explorer_pid)
            },
        };
        first.or(reap)
    }

    fn smoke_pending(&self) -> bool {
        self.smoke_pid > 0 && self.connection(self.smoke_client).is_some()
    }

    fn connection(&self, client: ClientHandle) -> Option<&ClientConnection> {
        self.connections
            .iter()
            .find(|connection| connection.is_used() && connection.client == client)
    }

    fn connection_mut(&mut self, client: ClientHandle) -> Option<&mut ClientConnection> {
        self.connections
            .iter_mut()
            .find(|connection| connection.is_used() && connection.client == client)
    }

    fn populate_wait_items(&self, items: &mut [WaitItem; MAX_EVENT_WAIT_ITEMS]) -> usize {
        items.fill(WaitItem::default());
        items[0] = WaitItem::ui_input(1);
        let mut count = 1usize;
        for connection in self
            .connections
            .iter()
            .filter(|connection| connection.is_used())
        {
            items[count] = WaitItem::channel(
                connection.server_fd,
                WAIT_INTEREST_READABLE,
                connection.client.0,
            );
            count += 1;
        }
        count
    }

    fn drain_channel(
        &mut self,
        client: ClientHandle,
        frame: &mut FrameContext<'_>,
    ) -> Result<(), Failure> {
        for _ in 0..MAX_CHANNEL_BATCH {
            let server_fd = self
                .connection(client)
                .ok_or(Failure {
                    stage: "drain-missing-client",
                    errno: 0,
                })?
                .server_fd;
            let mut message = IpcReceiveMessage::empty();
            let received = match libuser::channel_recv(server_fd, &mut message, 0) {
                Ok(received) => received,
                Err(libuser::Error(errno)) if errno == Errno::Eagain as i32 => return Ok(()),
                Err(libuser::Error(errno)) if errno == Errno::Epipe as i32 => {
                    self.disconnect_client(client, frame, "XENITH_COMPOSITOR_CLIENT_CLOSED")?;
                    return Ok(());
                },
                Err(libuser::Error(errno)) => {
                    return Err(Failure {
                        stage: "channel-recv",
                        errno,
                    });
                },
            };
            if received != message.payload_length as usize {
                close_received_descriptors(&message, None)?;
                self.disconnect_client(client, frame, "XENITH_COMPOSITOR_CLIENT_REJECTED")?;
                return Ok(());
            }
            match self.process_message(client, message, frame)? {
                MessageOutcome::Continue => {},
                MessageOutcome::Disconnect => {
                    self.disconnect_client(client, frame, "XENITH_COMPOSITOR_CLIENT_REJECTED")?;
                    return Ok(());
                },
            }
        }
        Ok(())
    }

    fn process_message(
        &mut self,
        client: ClientHandle,
        message: IpcReceiveMessage,
        frame: &mut FrameContext<'_>,
    ) -> Result<MessageOutcome, Failure> {
        let prepared = match self.compositor.prepare(client, &message) {
            Ok(prepared) => prepared,
            Err(_) => {
                close_received_descriptors(&message, None)?;
                return Ok(MessageOutcome::Disconnect);
            },
        };

        let batch = if let Some(map) = prepared.map_action() {
            if self.compositor.mapping_permitted(&prepared).is_err() {
                close_received_descriptors(&message, None)?;
                let batch = self
                    .compositor
                    .abort_mapping(prepared, COMPOSITOR_STATUS_RESOURCE_EXHAUSTED)
                    .map_err(|_| Failure {
                        stage: "abort-map-quota",
                        errno: 0,
                    })?;
                return self.execute_or_disconnect(batch, frame);
            }
            let map_length = match usize::try_from(map.mapping_length) {
                Ok(length) if length != 0 => length,
                _ => {
                    close_received_descriptors(&message, None)?;
                    let batch = self
                        .compositor
                        .abort_mapping(prepared, COMPOSITOR_STATUS_INVALID_ARGUMENT)
                        .map_err(|_| Failure {
                            stage: "abort-invalid-map",
                            errno: 0,
                        })?;
                    return self.execute_or_disconnect(batch, frame);
                },
            };
            let map_offset = match isize::try_from(map.mapping_offset) {
                Ok(offset) => offset,
                Err(_) => {
                    close_received_descriptors(&message, None)?;
                    let batch = self
                        .compositor
                        .abort_mapping(prepared, COMPOSITOR_STATUS_INVALID_ARGUMENT)
                        .map_err(|_| Failure {
                            stage: "abort-map-offset",
                            errno: 0,
                        })?;
                    return self.execute_or_disconnect(batch, frame);
                },
            };
            let mapped = libuser::syscall::mmap(
                core::ptr::null_mut(),
                map_length,
                PROT_READ,
                MAP_SHARED,
                map.descriptor,
                map_offset,
            );
            if let Err(close_failure) = close_received_descriptors(&message, None) {
                if let Ok(address) = mapped {
                    libuser::syscall::munmap(address, map_length).map_err(
                        |libuser::Error(errno)| Failure {
                            stage: "rollback-map-close",
                            errno,
                        },
                    )?;
                }
                return Err(close_failure);
            }
            let address = match mapped {
                Ok(address) => address,
                Err(libuser::Error(errno)) => {
                    let batch = self
                        .compositor
                        .abort_mapping(prepared, mapping_status(errno))
                        .map_err(|_| Failure {
                            stage: "abort-map",
                            errno: 0,
                        })?;
                    return self.execute_or_disconnect(batch, frame);
                },
            };
            if !self.add_mapping(client, address as u64, map.mapping_length, map.buffer_token) {
                libuser::syscall::munmap(address, map_length).map_err(
                    |libuser::Error(errno)| Failure {
                        stage: "rollback-map-capacity",
                        errno,
                    },
                )?;
                let batch = self
                    .compositor
                    .abort_mapping(prepared, COMPOSITOR_STATUS_RESOURCE_EXHAUSTED)
                    .map_err(|_| Failure {
                        stage: "abort-map-capacity",
                        errno: 0,
                    })?;
                return self.execute_or_disconnect(batch, frame);
            }
            match self.compositor.commit(
                prepared,
                ExternalCompletion::BufferMapped(MappedBuffer {
                    mapping_address: address as u64,
                }),
            ) {
                Ok(batch) => batch,
                Err(_) => {
                    libuser::syscall::munmap(address, map_length).map_err(
                        |libuser::Error(errno)| Failure {
                            stage: "rollback-map-commit",
                            errno,
                        },
                    )?;
                    self.remove_mapping(client, address as u64, map.buffer_token);
                    return Err(Failure {
                        stage: "commit-mapped-request",
                        errno: 0,
                    });
                },
            }
        } else {
            close_received_descriptors(&message, None)?;
            self.compositor
                .commit(prepared, ExternalCompletion::None)
                .map_err(|_| Failure {
                    stage: "commit-request",
                    errno: 0,
                })?
        };

        self.execute_or_disconnect(batch, frame)
    }

    fn execute_or_disconnect(
        &mut self,
        batch: DispatchBatch,
        frame: &mut FrameContext<'_>,
    ) -> Result<MessageOutcome, Failure> {
        let request_client = batch.client;
        match self.execute_dispatch(batch, frame) {
            Ok(()) => Ok(MessageOutcome::Continue),
            Err(SendError::Disconnected(client)) if client == request_client => {
                Ok(MessageOutcome::Disconnect)
            },
            Err(SendError::Disconnected(client)) => {
                self.disconnect_client(client, frame, "XENITH_COMPOSITOR_CLIENT_CLOSED")?;
                Ok(MessageOutcome::Continue)
            },
            Err(SendError::Fatal(failure)) => Err(failure),
        }
    }

    fn execute_dispatch(
        &mut self,
        batch: DispatchBatch,
        frame: &mut FrameContext<'_>,
    ) -> Result<(), SendError> {
        let client = batch.client;
        for action in batch.actions.iter() {
            match *action {
                CompositorAction::Present(present_action) => {
                    self.present_client(client, frame, present_action)
                        .map_err(SendError::Fatal)?;
                    let id = SurfaceId::new(client, present_action.surface);
                    if self.compositor.focused_surface().is_none()
                        && self.compositor.is_surface_focusable(id)
                    {
                        let routed = self.compositor.focus_surface(id, 0).map_err(|_| {
                            SendError::Fatal(Failure {
                                stage: "focus-presented-surface",
                                errno: 0,
                            })
                        })?;
                        for message in routed.iter() {
                            self.send_encoded(message.client, message.message)?;
                        }
                    }
                },
                CompositorAction::UnmapBuffer(unmap_action) => self
                    .unmap_buffer(client, frame, unmap_action)
                    .map_err(SendError::Fatal)?,
                CompositorAction::Event(message) | CompositorAction::Reply(message) => {
                    self.send_encoded(client, message)?;
                },
                CompositorAction::FrameDone(decision) => {
                    let presentation_time_ns = monotonic_time_ns().map_err(SendError::Fatal)?;
                    let message = self
                        .compositor
                        .complete_frame(client, decision, presentation_time_ns, REFRESH_INTERVAL_NS)
                        .map_err(|_| {
                            SendError::Fatal(Failure {
                                stage: "complete-frame",
                                errno: 0,
                            })
                        })?;
                    self.send_encoded(client, message)?;
                },
            }
        }
        for routed in batch.routed.iter() {
            self.send_encoded(routed.client, routed.message)?;
        }
        Ok(())
    }

    fn send_encoded(&self, client: ClientHandle, encoded: EncodedMessage) -> Result<(), SendError> {
        let server_fd = self
            .connection(client)
            .ok_or(SendError::Disconnected(client))?
            .server_fd;
        let mut message = IpcSendMessage::empty();
        if !message.set_payload(encoded.as_bytes()) {
            return Err(SendError::Fatal(Failure {
                stage: "encode-server-message",
                errno: 0,
            }));
        }
        // A short bounded wait lets a runnable client drain its eight-slot
        // queue during legitimate key/text/repaint bursts. A client that
        // remains full for the complete deadline is still isolated below.
        match libuser::channel_send(server_fd, &message, CLIENT_SEND_TIMEOUT_NS) {
            Ok(length) if length == encoded.len() => Ok(()),
            Ok(_) => Err(SendError::Fatal(Failure {
                stage: "short-channel-send",
                errno: 0,
            })),
            Err(libuser::Error(errno))
                if errno == Errno::Epipe as i32 || errno == Errno::Eagain as i32 =>
            {
                Err(SendError::Disconnected(client))
            },
            Err(libuser::Error(errno)) => Err(SendError::Fatal(Failure {
                stage: "channel-send",
                errno,
            })),
        }
    }

    fn route_input_event(
        &mut self,
        event: UiInputEvent,
        old_cursor: Point,
        new_cursor: Point,
        frame: &mut FrameContext<'_>,
    ) -> Result<(), Failure> {
        let routed = match event.kind {
            UI_EVENT_POINTER => self
                .compositor
                .route_pointer(
                    event,
                    new_cursor.x,
                    new_cursor.y,
                    new_cursor.x.saturating_sub(old_cursor.x),
                    new_cursor.y.saturating_sub(old_cursor.y),
                )
                .map_err(|_| Failure {
                    stage: "route-pointer-input",
                    errno: 0,
                })?,
            UI_EVENT_KEY => self.compositor.route_key(event).map_err(|_| Failure {
                stage: "route-key-input",
                errno: 0,
            })?,
            _ => return Ok(()),
        };
        self.dispatch_input_messages(routed, frame)
    }

    fn dispatch_input_messages(
        &mut self,
        routed: RoutedMessageBatch,
        frame: &mut FrameContext<'_>,
    ) -> Result<(), Failure> {
        for routed in routed.iter().copied() {
            if self.connection(routed.client).is_none() {
                continue;
            }
            match self.send_encoded(routed.client, routed.message) {
                Ok(()) => {},
                Err(SendError::Disconnected(client)) => {
                    self.disconnect_client(client, frame, "XENITH_COMPOSITOR_CLIENT_INPUT_CLOSED")?;
                },
                Err(SendError::Fatal(failure)) => return Err(failure),
            }
        }
        Ok(())
    }

    fn present_client(
        &mut self,
        client: ClientHandle,
        frame: &mut FrameContext<'_>,
        action: PresentAction,
    ) -> Result<(), Failure> {
        if !self.mapping_exists(
            client,
            action.buffer.mapping_address,
            action.buffer.mapping_length,
            action.buffer.buffer_token,
        ) {
            return Err(Failure {
                stage: "present-unowned-buffer",
                errno: 0,
            });
        }
        let id = SurfaceId::new(client, action.surface);
        let (x, y) = layer_origin(frame.state.size(), action.buffer, id);
        let layer = WindowLayer {
            id,
            buffer: action.buffer,
            x,
            y,
        };
        let existing_index = self.layers.iter().position(|candidate| candidate.id == id);
        let layer_index = existing_index
            .or_else(|| {
                self.layers
                    .iter()
                    .position(|candidate| !candidate.is_used())
            })
            .ok_or(Failure {
                stage: "layer-capacity",
                errno: 0,
            })?;
        self.compositor
            .place_surface(
                id,
                SceneRect::new(x, y, action.buffer.width, action.buffer.height),
            )
            .map_err(|_| Failure {
                stage: "place-client-surface",
                errno: 0,
            })?;
        self.layers[layer_index] = layer;
        self.compositor
            .damage_surface(id, &action.damage[..action.damage_count as usize])
            .map_err(|_| Failure {
                stage: "damage-client-surface",
                errno: 0,
            })?;
        let damage = self.compositor.take_damage();
        if damage.is_empty() {
            return Ok(());
        }
        let mut wire_damage = [UiRect::default(); xenith_abi::UI_MAX_DAMAGE_RECTS];
        let mut regions = [Rect::default(); MAX_DAMAGE_RECTS];
        for (destination, source) in regions.iter_mut().zip(damage.as_slice()) {
            *destination = Rect::new(source.x, source.y, source.width, source.height);
        }
        let regions = &regions[..damage.as_slice().len()];
        render_background_damage(frame, regions)?;
        self.redraw_layers(frame, regions)?;
        render_overlay_damage(frame, regions)?;
        if damage.is_full() {
            present(frame.mapping, frame.length, frame.stride, &[])?;
        } else {
            for (destination, source) in wire_damage.iter_mut().zip(regions) {
                *destination = (*source).into();
            }
            present(
                frame.mapping,
                frame.length,
                frame.stride,
                &wire_damage[..regions.len()],
            )?;
        }
        Ok(())
    }

    fn unmap_buffer(
        &mut self,
        client: ClientHandle,
        frame: &mut FrameContext<'_>,
        action: UnmapBufferAction,
    ) -> Result<(), Failure> {
        let layer_bounds = self.layers.iter_mut().find_map(|layer| {
            (layer.is_used()
                && layer.id.client == client
                && layer.buffer.mapping_address == action.mapping_address
                && layer.buffer.buffer_token == action.buffer_token)
                .then(|| {
                    let bounds = layer.bounds();
                    *layer = WindowLayer::EMPTY;
                    bounds
                })
        });
        if !self.mapping_exists(
            client,
            action.mapping_address,
            action.mapping_length,
            action.buffer_token,
        ) {
            return Err(Failure {
                stage: "unmap-unowned-buffer",
                errno: 0,
            });
        }
        let address = action.mapping_address as *mut u8;
        let length = usize::try_from(action.mapping_length).map_err(|_| Failure {
            stage: "unmap-length",
            errno: 0,
        })?;
        libuser::syscall::munmap(address, length).map_err(|libuser::Error(errno)| Failure {
            stage: "unmap-client-buffer",
            errno,
        })?;
        self.remove_mapping(client, action.mapping_address, action.buffer_token);

        if layer_bounds.is_some() {
            self.present_scene_damage(frame)?;
        }
        Ok(())
    }

    fn redraw_layers(&self, frame: &mut FrameContext<'_>, damage: &[Rect]) -> Result<(), Failure> {
        for entry in self.compositor.scene_entries() {
            let layer = self
                .layers
                .iter()
                .copied()
                .find(|layer| layer.id == entry.id)
                .ok_or(Failure {
                    stage: "scene-layer-missing",
                    errno: 0,
                })?;
            let Some(layer_bounds) = layer.bounds().intersect(frame.state.size().bounds()) else {
                continue;
            };
            for &damaged in damage {
                let Some(destination) = layer_bounds.intersect(damaged) else {
                    continue;
                };
                let source_x = (destination.x - layer.x) as u32;
                let source_y = (destination.y - layer.y) as u32;
                composite_buffer_rect(
                    frame,
                    layer.buffer,
                    source_x,
                    source_y,
                    UiRect::from(destination),
                )?;
            }
        }
        Ok(())
    }

    fn present_scene_damage(&mut self, frame: &mut FrameContext<'_>) -> Result<(), Failure> {
        let damage = self.compositor.take_damage();
        if damage.is_empty() {
            return Ok(());
        }
        let mut regions = [Rect::default(); MAX_DAMAGE_RECTS];
        for (destination, source) in regions.iter_mut().zip(damage.as_slice()) {
            *destination = Rect::new(source.x, source.y, source.width, source.height);
        }
        let regions = &regions[..damage.as_slice().len()];
        render_background_damage(frame, regions)?;
        self.redraw_layers(frame, regions)?;
        render_overlay_damage(frame, regions)?;
        if damage.is_full() {
            present(frame.mapping, frame.length, frame.stride, &[])
        } else {
            let mut wire = [UiRect::default(); MAX_DAMAGE_RECTS];
            for (destination, source) in wire.iter_mut().zip(regions) {
                *destination = (*source).into();
            }
            present(
                frame.mapping,
                frame.length,
                frame.stride,
                &wire[..regions.len()],
            )
        }
    }

    fn add_mapping(&mut self, client: ClientHandle, address: u64, length: u64, token: u64) -> bool {
        if address == 0
            || length == 0
            || token == 0
            || self.mappings.iter().any(|slot| {
                slot.is_used()
                    && (slot.address == address || (slot.client == client && slot.token == token))
            })
        {
            return false;
        }
        let Some(slot) = self.mappings.iter_mut().find(|slot| !slot.is_used()) else {
            return false;
        };
        *slot = MappingSlot {
            client,
            address,
            length,
            token,
        };
        true
    }

    fn mapping_exists(&self, client: ClientHandle, address: u64, length: u64, token: u64) -> bool {
        self.mappings.iter().any(|slot| {
            slot.client == client
                && slot.address == address
                && slot.length == length
                && slot.token == token
        })
    }

    fn remove_mapping(&mut self, client: ClientHandle, address: u64, token: u64) -> bool {
        let Some(slot) = self
            .mappings
            .iter_mut()
            .find(|slot| slot.client == client && slot.address == address && slot.token == token)
        else {
            return false;
        };
        *slot = MappingSlot::EMPTY;
        true
    }

    fn disconnect_client(
        &mut self,
        client: ClientHandle,
        frame: &mut FrameContext<'_>,
        marker: &'static str,
    ) -> Result<(), Failure> {
        let cleanup = self.compositor.disconnect(client).map_err(|_| Failure {
            stage: "disconnect-state",
            errno: 0,
        })?;
        let mut first = None;
        for action in cleanup.unmaps().copied() {
            if !self.mapping_exists(
                client,
                action.mapping_address,
                action.mapping_length,
                action.buffer_token,
            ) {
                if first.is_none() {
                    first = Some(Failure {
                        stage: "disconnect-unowned-map",
                        errno: 0,
                    });
                }
                continue;
            }
            let length = usize::try_from(action.mapping_length).unwrap_or(0);
            if length == 0 {
                if first.is_none() {
                    first = Some(Failure {
                        stage: "disconnect-map-length",
                        errno: 0,
                    });
                }
            } else if let Err(libuser::Error(errno)) =
                libuser::syscall::munmap(action.mapping_address as *mut u8, length)
            {
                if first.is_none() {
                    first = Some(Failure {
                        stage: "disconnect-unmap",
                        errno,
                    });
                }
            }
            self.remove_mapping(client, action.mapping_address, action.buffer_token);
        }
        for layer in &mut self.layers {
            if layer.id.client == client {
                *layer = WindowLayer::EMPTY;
            }
        }
        if let Some(connection) = self.connection(client).copied() {
            for descriptor in [connection.server_fd, connection.peer_fd] {
                if descriptor < 0 {
                    continue;
                }
                if let Err(libuser::Error(errno)) = libuser::syscall::close(descriptor) {
                    if first.is_none() {
                        first = Some(Failure {
                            stage: "disconnect-channel",
                            errno,
                        });
                    }
                }
            }
            if let Some(slot) = self.connection_mut(client) {
                *slot = ClientConnection::EMPTY;
            }
        }
        if self.smoke_client == client {
            self.smoke_client = ClientHandle::INVALID;
        }
        if self.explorer_client == client {
            self.explorer_client = ClientHandle::INVALID;
            if let Some(failure) = Self::reap_child_bounded(&mut self.explorer_pid) {
                if first.is_none() {
                    first = Some(failure);
                }
            }
        }
        let render_failure = self.present_scene_damage(frame).err();
        libuser::println!("{}", marker);
        first.or(render_failure).map_or(Ok(()), Err)
    }

    fn shutdown(&mut self) -> Option<Failure> {
        let mut first = None;
        self.layers.fill(WindowLayer::EMPTY);
        let mut clients = [ClientHandle::INVALID; MAX_COMPOSITOR_CLIENTS];
        let mut client_count = 0usize;
        for connection in self
            .connections
            .iter()
            .filter(|connection| connection.is_used())
        {
            clients[client_count] = connection.client;
            client_count += 1;
        }
        for &client in &clients[..client_count] {
            if self.compositor.disconnect(client).is_err() && first.is_none() {
                first = Some(Failure {
                    stage: "shutdown-client-state",
                    errno: 0,
                });
            }
        }
        for slot in &mut self.mappings {
            if !slot.is_used() {
                continue;
            }
            let address = slot.address as *mut u8;
            let length = usize::try_from(slot.length).unwrap_or(0);
            if length == 0 {
                if first.is_none() {
                    first = Some(Failure {
                        stage: "shutdown-map-length",
                        errno: 0,
                    });
                }
            } else if let Err(libuser::Error(errno)) = libuser::syscall::munmap(address, length) {
                if first.is_none() {
                    first = Some(Failure {
                        stage: "shutdown-unmap",
                        errno,
                    });
                }
            }
            *slot = MappingSlot::EMPTY;
        }
        for connection in &mut self.connections {
            for descriptor in [connection.server_fd, connection.peer_fd] {
                if descriptor < 0 {
                    continue;
                }
                if let Err(libuser::Error(errno)) = libuser::syscall::close(descriptor) {
                    if first.is_none() {
                        first = Some(Failure {
                            stage: "shutdown-channel",
                            errno,
                        });
                    }
                }
            }
            *connection = ClientConnection::EMPTY;
        }
        self.smoke_client = ClientHandle::INVALID;
        self.explorer_client = ClientHandle::INVALID;
        let smoke_reap = Self::reap_child_bounded(&mut self.smoke_pid);
        let explorer_reap = Self::reap_child_bounded(&mut self.explorer_pid);
        first.or(smoke_reap).or(explorer_reap)
    }

    fn reap_child_bounded(pid_slot: &mut i64) -> Option<Failure> {
        let pid = *pid_slot;
        if pid <= 0 {
            return None;
        }
        let mut status = 0;
        for _ in 0..SMOKE_REAP_ATTEMPTS {
            match libuser::syscall::waitpid(pid, &mut status, xenith_abi::WNOHANG) {
                Ok(reaped) if reaped == pid => {
                    *pid_slot = -1;
                    return None;
                },
                Ok(0) => {},
                Ok(_) => {
                    return Some(Failure {
                        stage: "reap-window-client-result",
                        errno: 0,
                    });
                },
                Err(libuser::Error(errno)) if errno == Errno::Eintr as i32 => continue,
                Err(libuser::Error(errno)) if errno == Errno::Echild as i32 => {
                    *pid_slot = -1;
                    return None;
                },
                Err(libuser::Error(errno)) => {
                    return Some(Failure {
                        stage: "reap-window-client",
                        errno,
                    });
                },
            }
            match libuser::syscall::nanosleep(Timespec {
                seconds: 0,
                nanoseconds: SMOKE_REAP_POLL_NS,
            }) {
                Ok(()) => {},
                Err(libuser::Error(errno)) if errno == Errno::Eintr as i32 => {},
                Err(libuser::Error(errno)) => {
                    return Some(Failure {
                        stage: "reap-window-client-sleep",
                        errno,
                    });
                },
            }
        }

        if let Err(libuser::Error(errno)) = libuser::syscall::kill(pid, SIGKILL) {
            if errno != Errno::Esrch as i32 {
                return Some(Failure {
                    stage: "terminate-window-client",
                    errno,
                });
            }
        }
        loop {
            match libuser::syscall::waitpid(pid, &mut status, 0) {
                Ok(reaped) if reaped == pid => {
                    *pid_slot = -1;
                    return None;
                },
                Err(libuser::Error(errno)) if errno == Errno::Eintr as i32 => {},
                Err(libuser::Error(errno)) if errno == Errno::Echild as i32 => {
                    *pid_slot = -1;
                    return None;
                },
                Ok(_) => {
                    return Some(Failure {
                        stage: "reap-terminated-window-client-result",
                        errno: 0,
                    });
                },
                Err(libuser::Error(errno)) => {
                    return Some(Failure {
                        stage: "reap-terminated-window-client",
                        errno,
                    });
                },
            }
        }
    }
}

#[no_mangle]
/// # Safety
/// `startup` must point to the loader-created, read-only startup block.
pub unsafe extern "C" fn _start(startup: *const Startup) -> ! {
    // SAFETY: the kernel validates and pins the startup block before entry.
    let options = unsafe { startup.as_ref() }
        .map(read_options)
        .unwrap_or_default();
    let code = desktop_main(options);
    libuser::syscall::exit(code)
}

fn read_options(startup: &Startup) -> StartupOptions {
    let mut options = StartupOptions::default();
    for index in 1..startup.argc {
        // SAFETY: Startup's loader contract covers all entries through argc.
        match unsafe { startup.argument(index) } {
            Some(b"--smoke-exit") => options.smoke_exit = true,
            Some(b"--window-smoke") => options.window_smoke = true,
            _ => {},
        }
    }
    options
}

fn desktop_main(options: StartupOptions) -> i32 {
    let mut display = UiDisplayInfo::default();
    if let Err(libuser::Error(errno)) = libuser::ui_acquire(&mut display) {
        report_failure(Failure {
            stage: "acquire",
            errno,
        });
        return 1;
    }

    let geometry = match validate_display(display) {
        Ok(geometry) => geometry,
        Err(failure) => {
            let cleanup_failure = release_only();
            report_failure(cleanup_failure.unwrap_or(failure));
            return 1;
        },
    };
    let (size, stride, backbuffer_len, format, native_format) = geometry;
    let mapping = match libuser::syscall::mmap(
        core::ptr::null_mut(),
        backbuffer_len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    ) {
        Ok(mapping) => mapping,
        Err(libuser::Error(errno)) => {
            let failure = Failure {
                stage: "mmap",
                errno,
            };
            let cleanup_failure = release_only();
            report_failure(cleanup_failure.unwrap_or(failure));
            return 1;
        },
    };

    let mut runtime = match CompositorRuntime::new(size) {
        Ok(runtime) => runtime,
        Err(failure) => {
            let cleanup_failure = cleanup(mapping, backbuffer_len);
            report_failure(cleanup_failure.unwrap_or(failure));
            return 1;
        },
    };
    let mut state = DesktopState::new(size);
    let renderer = Renderer::new();
    let result =
        render_full(mapping, backbuffer_len, stride, format, &renderer, &state).and_then(|()| {
            libuser::println!("XENITH_DESKTOP_READY");
            if options.window_smoke {
                runtime.launch_window_smoke()?;
            }
            run_event_loop(
                mapping,
                backbuffer_len,
                stride,
                format,
                native_format,
                &renderer,
                &mut state,
                &mut runtime,
                options.smoke_exit,
            )
        });

    if matches!(result, Ok(LoopExit::RecoveryChord)) {
        libuser::println!("XENITH_DESKTOP_EXIT");
    }
    let runtime_failure = runtime.shutdown();
    let cleanup_failure = cleanup(mapping, backbuffer_len);
    match (result, runtime_failure.or(cleanup_failure)) {
        (Ok(_), None) => {
            libuser::println!("XENITH_DESKTOP_CLEAN_EXIT");
            0
        },
        (_, Some(failure)) | (Err(failure), None) => {
            report_failure(failure);
            1
        },
    }
}

fn validate_display(
    display: UiDisplayInfo,
) -> Result<(Size, usize, usize, PixelFormat, NativePixelFormat), Failure> {
    let size = Size::new(display.width, display.height);
    let stride = display.stride as usize;
    let visible = (display.width as usize).checked_mul(4).ok_or(Failure {
        stage: "geometry-width",
        errno: 0,
    })?;
    if display.version != UI_ABI_VERSION
        || display.width == 0
        || display.height == 0
        || display.bits_per_pixel != 32
        || display.flags & UI_DISPLAY_NATIVE_PIXEL_FORMAT == 0
        || display.reserved != 0
        || stride < visible
        || !stride.is_multiple_of(4)
    {
        return Err(Failure {
            stage: "display-info",
            errno: 0,
        });
    }
    let backbuffer_len = stride.checked_mul(display.height as usize).ok_or(Failure {
        stage: "geometry-size",
        errno: 0,
    })?;
    let format = PixelFormat::new(
        display.red_shift,
        display.red_size,
        display.green_shift,
        display.green_size,
        display.blue_shift,
        display.blue_size,
    )
    .map_err(|_| Failure {
        stage: "pixel-format",
        errno: 0,
    })?;
    Ok((
        size,
        stride,
        backbuffer_len,
        format,
        NativePixelFormat::from_display(display),
    ))
}

fn render_full(
    mapping: *mut u8,
    length: usize,
    stride: usize,
    format: PixelFormat,
    renderer: &Renderer,
    state: &DesktopState,
) -> Result<(), Failure> {
    render_damage(mapping, length, stride, format, renderer, state, &[state
        .size()
        .bounds()])?;
    present(mapping, length, stride, &[])
}

fn render_damage(
    mapping: *mut u8,
    length: usize,
    stride: usize,
    format: PixelFormat,
    renderer: &Renderer,
    state: &DesktopState,
    damage: &[Rect],
) -> Result<(), Failure> {
    // SAFETY: `mapping` is the live anonymous mapping owned by this process,
    // and every caller retains it through this render operation.
    let bytes = unsafe { core::slice::from_raw_parts_mut(mapping, length) };
    let mut surface = Surface::new(bytes, state.size(), stride, format).map_err(|_| Failure {
        stage: "surface",
        errno: 0,
    })?;
    renderer.render(&mut surface, state, damage);
    Ok(())
}

fn render_background_damage(frame: &mut FrameContext<'_>, damage: &[Rect]) -> Result<(), Failure> {
    // SAFETY: FrameContext retains the live desktop mapping for this call.
    let bytes = unsafe { core::slice::from_raw_parts_mut(frame.mapping, frame.length) };
    let mut surface = Surface::new(bytes, frame.state.size(), frame.stride, frame.render_format)
        .map_err(|_| Failure {
            stage: "background-surface",
            errno: 0,
        })?;
    frame
        .renderer
        .render_background(&mut surface, frame.state, damage);
    Ok(())
}

fn render_overlay_damage(frame: &mut FrameContext<'_>, damage: &[Rect]) -> Result<(), Failure> {
    // SAFETY: FrameContext retains the live desktop mapping for this call.
    let bytes = unsafe { core::slice::from_raw_parts_mut(frame.mapping, frame.length) };
    let mut surface = Surface::new(bytes, frame.state.size(), frame.stride, frame.render_format)
        .map_err(|_| Failure {
            stage: "overlay-surface",
            errno: 0,
        })?;
    frame
        .renderer
        .render_overlay(&mut surface, frame.state, damage);
    Ok(())
}

fn present(
    mapping: *mut u8,
    length: usize,
    stride: usize,
    damage: &[UiRect],
) -> Result<(), Failure> {
    // SAFETY: the anonymous mapping remains readable until final cleanup.
    let bytes = unsafe { core::slice::from_raw_parts(mapping, length) };
    libuser::ui_present(bytes, stride, damage).map_err(|libuser::Error(errno)| Failure {
        stage: "present",
        errno,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_event_loop(
    mapping: *mut u8,
    length: usize,
    stride: usize,
    render_format: PixelFormat,
    native_format: NativePixelFormat,
    renderer: &Renderer,
    state: &mut DesktopState,
    runtime: &mut CompositorRuntime,
    smoke_exit: bool,
) -> Result<LoopExit, Failure> {
    let mut events = [UiInputEvent::default(); 32];
    let mut damage = DamageTracker::new(state.layout().screen);
    let mut frame = FrameContext {
        mapping,
        length,
        stride,
        render_format,
        native_format,
        renderer,
        state,
    };
    loop {
        let timeout = if smoke_exit && !runtime.smoke_pending() {
            SMOKE_WAIT_NS
        } else {
            WAIT_TIMEOUT_INFINITE
        };
        let mut wait_items = [WaitItem::default(); MAX_EVENT_WAIT_ITEMS];
        let wait_count = runtime.populate_wait_items(&mut wait_items);
        let ready_count = match libuser::wait(&mut wait_items[..wait_count], timeout) {
            Ok(count) => count,
            Err(libuser::Error(errno)) if errno == Errno::Eintr as i32 => continue,
            Err(libuser::Error(errno)) => {
                return Err(Failure {
                    stage: "wait",
                    errno,
                });
            },
        };

        if wait_items[0].ready & WAIT_READY_UI_INPUT != 0 {
            let event_count = match libuser::ui_read_events(&mut events, 0) {
                Ok(count) => count,
                Err(libuser::Error(errno)) if errno == Errno::Eintr as i32 => continue,
                Err(libuser::Error(errno)) => {
                    return Err(Failure {
                        stage: "read-events",
                        errno,
                    });
                },
            };
            damage.clear();
            let launcher_was_open = frame.state.launcher_open();
            for &event in &events[..event_count] {
                let old_cursor = frame.state.cursor();
                let action = frame.state.handle_event(event, &mut damage);
                let new_cursor = frame.state.cursor();
                match action {
                    EventAction::Exit => return Ok(LoopExit::RecoveryChord),
                    EventAction::LaunchExplorer => {
                        if let Err(failure) = runtime.launch_explorer() {
                            libuser::println!(
                                "XENITH_EXPLORER_LAUNCH_FAIL stage={} errno={}",
                                failure.stage,
                                failure.errno
                            );
                        }
                    },
                    EventAction::Continue => {
                        runtime.route_input_event(event, old_cursor, new_cursor, &mut frame)?;
                    },
                    EventAction::Consumed
                        if event.kind == UI_EVENT_POINTER
                            && event.flags & UI_EVENT_FLAG_OVERFLOW != 0 =>
                    {
                        runtime.route_input_event(event, old_cursor, new_cursor, &mut frame)?;
                    },
                    EventAction::Consumed => {},
                }
            }
            if !damage.is_empty() {
                let regions = damage.rects();
                render_background_damage(&mut frame, regions)?;
                runtime.redraw_layers(&mut frame, regions)?;
                render_overlay_damage(&mut frame, regions)?;
                if damage.is_full() {
                    present(frame.mapping, frame.length, frame.stride, &[])?;
                } else {
                    let mut wire = [UiRect::default(); MAX_DAMAGE_RECTS];
                    for (destination, source) in wire.iter_mut().zip(regions) {
                        *destination = (*source).into();
                    }
                    present(
                        frame.mapping,
                        frame.length,
                        frame.stride,
                        &wire[..regions.len()],
                    )?;
                }
                if frame.state.launcher_open() != launcher_was_open {
                    libuser::println!(
                        "XENITH_DESKTOP_LAUNCHER_{}",
                        if frame.state.launcher_open() {
                            "OPEN"
                        } else {
                            "CLOSED"
                        }
                    );
                }
            }
            runtime.present_scene_damage(&mut frame)?;
        }

        for item in wait_items[1..wait_count].iter().copied() {
            let client = ClientHandle(item.token);
            if item.ready & WAIT_READY_READABLE != 0 {
                runtime.drain_channel(client, &mut frame)?;
            }
            if runtime.connection(client).is_some()
                && item.ready & WAIT_READY_HANGUP != 0
                && item.ready & WAIT_READY_READABLE == 0
            {
                runtime.disconnect_client(client, &mut frame, "XENITH_COMPOSITOR_CLIENT_CLOSED")?;
            }
        }
        if smoke_exit && ready_count == 0 && !runtime.smoke_pending() {
            return Ok(LoopExit::SmokeComplete);
        }
    }
}

fn composite_buffer_rect(
    frame: &mut FrameContext<'_>,
    buffer: BufferSnapshot,
    source_x: u32,
    source_y: u32,
    destination: UiRect,
) -> Result<(), Failure> {
    let data_address = buffer
        .mapping_address
        .checked_add(buffer.data_offset)
        .ok_or(Failure {
            stage: "client-buffer-address",
            errno: 0,
        })?;
    let mapping_end = buffer
        .mapping_address
        .checked_add(buffer.mapping_length)
        .ok_or(Failure {
            stage: "client-mapping-overflow",
            errno: 0,
        })?;
    let data_end = data_address
        .checked_add(buffer.data_length)
        .ok_or(Failure {
            stage: "client-buffer-overflow",
            errno: 0,
        })?;
    let stride = buffer.stride as usize;
    let required = buffer.required_data_bytes().ok_or(Failure {
        stage: "client-buffer-geometry",
        errno: 0,
    })?;
    if data_address == 0
        || buffer.data_length < required
        || data_end > mapping_end
        || destination.width == 0
        || destination.height == 0
        || source_x
            .checked_add(destination.width)
            .is_none_or(|right| right > buffer.width)
        || source_y
            .checked_add(destination.height)
            .is_none_or(|bottom| bottom > buffer.height)
    {
        return Err(Failure {
            stage: "client-buffer-bounds",
            errno: 0,
        });
    }
    let source = data_address as *const u8;
    let has_alpha = match buffer.format {
        COMPOSITOR_FORMAT_BGRX8888 => false,
        COMPOSITOR_FORMAT_BGRA8888 => true,
        _ => {
            return Err(Failure {
                stage: "client-buffer-format",
                errno: 0,
            });
        },
    };
    // SAFETY: the desktop owns this live read-write backbuffer for the loop lifetime.
    let output = unsafe { core::slice::from_raw_parts_mut(frame.mapping, frame.length) };
    for row in 0..destination.height as usize {
        for column in 0..destination.width as usize {
            let source_offset =
                (source_y as usize + row) * stride + (source_x as usize + column) * 4;
            let destination_offset = (destination.y as usize + row) * frame.stride
                + (destination.x as usize + column) * 4;
            // SAFETY: the checked buffer geometry above keeps all four byte
            // offsets inside the live shared mapping. The client can mutate
            // MAP_SHARED storage concurrently, so source pixels are read
            // through raw volatile loads and never exposed as Rust references.
            let blue = unsafe { core::ptr::read_volatile(source.add(source_offset)) };
            let green = unsafe { core::ptr::read_volatile(source.add(source_offset + 1)) };
            let red = unsafe { core::ptr::read_volatile(source.add(source_offset + 2)) };
            let alpha = if has_alpha {
                // SAFETY: identical bounds and shared-memory reasoning as the
                // three component loads immediately above.
                unsafe { core::ptr::read_volatile(source.add(source_offset + 3)) }
            } else {
                255
            };
            let pixel = if alpha == 255 {
                frame.native_format.pack(red, green, blue)
            } else {
                let existing = u32::from_ne_bytes(
                    output[destination_offset..destination_offset + 4]
                        .try_into()
                        .map_err(|_| Failure {
                            stage: "native-pixel-read",
                            errno: 0,
                        })?,
                );
                let (background_red, background_green, background_blue) =
                    frame.native_format.unpack(existing);
                frame.native_format.pack(
                    blend_channel(background_red, red, alpha),
                    blend_channel(background_green, green, alpha),
                    blend_channel(background_blue, blue, alpha),
                )
            };
            output[destination_offset..destination_offset + 4]
                .copy_from_slice(&pixel.to_ne_bytes());
        }
    }
    Ok(())
}

fn layer_origin(size: Size, buffer: BufferSnapshot, id: SurfaceId) -> (i32, i32) {
    let base_x = size.width.saturating_sub(buffer.width) / 2;
    let base_y = size.height.saturating_sub(buffer.height) / 2;
    let ordinal = id
        .client
        .slot()
        .saturating_sub(1)
        .saturating_mul(MAX_CLIENT_SURFACES as u32)
        .saturating_add(id.surface.slot().saturating_sub(1));
    let cascade = ordinal.min(5).saturating_mul(18);
    let x = base_x
        .saturating_add(cascade)
        .min(size.width.saturating_sub(buffer.width));
    let y = base_y
        .saturating_add(cascade)
        .min(size.height.saturating_sub(buffer.height));
    (x as i32, y as i32)
}

fn default_window_size(size: Size) -> (u32, u32) {
    let horizontal_margin = if size.width > 200 { 64 } else { 0 };
    let vertical_margin = if size.height > 180 { 100 } else { 0 };
    (
        size.width.saturating_sub(horizontal_margin).clamp(1, 720),
        size.height.saturating_sub(vertical_margin).clamp(1, 460),
    )
}

fn close_received_descriptors(
    message: &IpcReceiveMessage,
    except: Option<i32>,
) -> Result<(), Failure> {
    let count = (message.transfer_count as usize).min(message.transfers.len());
    let mut first = None;
    for transfer in &message.transfers[..count] {
        if transfer.installed_fd < 0 || except == Some(transfer.installed_fd) {
            continue;
        }
        if let Err(libuser::Error(errno)) = libuser::syscall::close(transfer.installed_fd) {
            if first.is_none() {
                first = Some(Failure {
                    stage: "close-received-fd",
                    errno,
                });
            }
        }
    }
    first.map_or(Ok(()), Err)
}

fn mapping_status(errno: i32) -> i32 {
    if errno == Errno::Eacces as i32 || errno == Errno::Eperm as i32 {
        COMPOSITOR_STATUS_ACCESS_DENIED
    } else if errno == Errno::Enomem as i32 {
        COMPOSITOR_STATUS_NO_MEMORY
    } else if errno == Errno::Emfile as i32 || errno == Errno::Eagain as i32 {
        COMPOSITOR_STATUS_RESOURCE_EXHAUSTED
    } else {
        COMPOSITOR_STATUS_INVALID_ARGUMENT
    }
}

fn monotonic_time_ns() -> Result<u64, Failure> {
    let time = libuser::syscall::clock_gettime().map_err(|libuser::Error(errno)| Failure {
        stage: "frame-clock",
        errno,
    })?;
    let seconds = u64::try_from(time.seconds).map_err(|_| Failure {
        stage: "frame-clock-value",
        errno: 0,
    })?;
    let nanoseconds = u64::try_from(time.nanoseconds).map_err(|_| Failure {
        stage: "frame-clock-value",
        errno: 0,
    })?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .map(|value| value.max(1))
        .ok_or(Failure {
            stage: "frame-clock-overflow",
            errno: 0,
        })
}

fn write_decimal_fd(value: i32, output: &mut [u8; 12]) -> bool {
    output.fill(0);
    if value < 0 {
        return false;
    }
    let mut digits = [0u8; 10];
    let mut count = 0usize;
    let mut remaining = value as u32;
    loop {
        digits[count] = b'0' + (remaining % 10) as u8;
        count += 1;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    for index in 0..count {
        output[index] = digits[count - index - 1];
    }
    true
}

fn pack_channel(value: u8, shift: u8, size: u8) -> u32 {
    let maximum = if size == 32 {
        u64::from(u32::MAX)
    } else {
        (1u64 << size) - 1
    };
    ((((u64::from(value) * maximum) + 127) / 255) << shift) as u32
}

fn unpack_channel(value: u32, shift: u8, size: u8) -> u8 {
    let maximum = if size == 32 {
        u64::from(u32::MAX)
    } else {
        (1u64 << size) - 1
    };
    let mask = if size == 32 {
        u32::MAX
    } else {
        ((1u64 << size) - 1) as u32
    };
    let raw = u64::from((value >> shift) & mask);
    ((raw * 255 + maximum / 2) / maximum) as u8
}

fn blend_channel(background: u8, foreground: u8, alpha: u8) -> u8 {
    let alpha = u32::from(alpha);
    ((u32::from(foreground) * alpha + u32::from(background) * (255 - alpha) + 127) / 255) as u8
}

fn release_only() -> Option<Failure> {
    libuser::ui_release()
        .err()
        .map(|libuser::Error(errno)| Failure {
            stage: "release",
            errno,
        })
}

fn cleanup(mapping: *mut u8, length: usize) -> Option<Failure> {
    let release_failure = release_only();
    let unmap_failure =
        libuser::syscall::munmap(mapping, length)
            .err()
            .map(|libuser::Error(errno)| Failure {
                stage: "munmap",
                errno,
            });
    release_failure.or(unmap_failure)
}

fn report_failure(failure: Failure) {
    libuser::println!(
        "XENITH_DESKTOP_FAIL stage={} errno={}",
        failure.stage,
        failure.errno
    );
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = libuser::ui_release();
    libuser::println!("XENITH_DESKTOP_FAIL stage=panic errno=0");
    libuser::syscall::exit(127)
}
