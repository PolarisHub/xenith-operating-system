#![no_std]
#![no_main]

use core::panic::PanicInfo;

use libuser::args::Startup;
use libwindow::{Client, Event, EventKind, Incoming, LibuserTransport};
use xenith_abi::compositor::{
    CompositorDamageRect, CompositorHandle, CompositorSurfaceMetadata, COMPOSITOR_FORMAT_BGRA8888,
    COMPOSITOR_ROLE_TOPLEVEL,
};
use xenith_abi::{
    DirectoryEntry, Errno, Stat, MAP_SHARED, PROT_READ, PROT_WRITE, WAIT_TIMEOUT_INFINITE,
};
use xenith_explorer::{
    render, Command, EntryMetadata, ExplorerModel, FixedPath, HistoryMode, Interaction, Layout,
    PathError, ENTRY_KIND_DIRECTORY, MAX_DIRECTORY_ENTRIES,
};

const FRAME_TOKEN_BASE: u64 = 0x5845_4e49_5446_0000;
const BUFFER_TOKENS: [u64; 2] = [0x5846_494c_4553_0001, 0x5846_494c_4553_0002];

#[derive(Clone, Copy)]
struct Failure {
    stage: &'static str,
    errno: i32,
}

enum AppError {
    Closed,
    Failed(Failure),
}

type AppResult<T> = core::result::Result<T, AppError>;

#[derive(Clone, Copy)]
struct SharedBuffer {
    fd: i32,
    mapping: *mut u8,
    length: usize,
    token: u64,
    retained: bool,
}

impl SharedBuffer {
    const EMPTY: Self = Self {
        fd: -1,
        mapping: core::ptr::null_mut(),
        length: 0,
        token: 0,
        retained: false,
    };

    const fn is_allocated(self) -> bool {
        self.fd >= 0 && !self.mapping.is_null() && self.length != 0 && self.token != 0
    }
}

struct Runtime {
    client: Client<LibuserTransport>,
    endpoint: i32,
    surface: CompositorHandle,
    width: u32,
    height: u32,
    stride: usize,
    buffers: [SharedBuffer; 2],
    current_buffer: Option<usize>,
    next_frame: u64,
    last_frame_done: u64,
    model: ExplorerModel,
    layout: Layout,
    pending_command: Command,
    dirty: bool,
    exit_requested: bool,
    ready_emitted: bool,
}

impl Runtime {
    fn new(endpoint: i32) -> Self {
        Self {
            client: Client::new(LibuserTransport::new(endpoint)),
            endpoint,
            surface: CompositorHandle::INVALID,
            width: 1,
            height: 1,
            stride: 4,
            buffers: [SharedBuffer::EMPTY; 2],
            current_buffer: None,
            next_frame: 1,
            last_frame_done: 0,
            model: ExplorerModel::new(),
            layout: Layout::new(1, 1),
            pending_command: Command::None,
            dirty: false,
            exit_requested: false,
            ready_emitted: false,
        }
    }

    fn run(&mut self, initial_path: Option<&[u8]>) -> AppResult<()> {
        self.initialize_surface()?;
        self.allocate_buffers()?;
        let initial = initial_path
            .map(FixedPath::normalize_absolute)
            .transpose()
            .map_err(|_| failed("initial-path", 0))?
            .unwrap_or_else(|| self.model.current_path());
        self.load_directory(initial, HistoryMode::Preserve)
            .map_err(|libuser::Error(errno)| failed("initial-directory", errno))?;
        self.dirty = true;

        while !self.exit_requested {
            if self.dirty {
                self.dirty = false;
                self.present()?;
                if !self.ready_emitted {
                    libuser::println!("XENITH_EXPLORER_READY");
                    self.ready_emitted = true;
                }
                continue;
            }
            if self.pending_command != Command::None {
                let command = core::mem::replace(&mut self.pending_command, Command::None);
                self.execute_command(command);
                continue;
            }
            match self
                .client
                .receive(WAIT_TIMEOUT_INFINITE)
                .map_err(|error| window_error("receive-event", error))?
            {
                Incoming::Event(event) => self.handle_event(event),
                Incoming::Reply(_) => return Err(failed("unsolicited-reply", 0)),
            }
        }
        Ok(())
    }

    fn initialize_surface(&mut self) -> AppResult<()> {
        let serial = self
            .client
            .create_surface(WAIT_TIMEOUT_INFINITE)
            .map_err(|error| window_error("create-surface", error))?;
        let reply = self.wait_reply(serial)?;
        if !reply.succeeded() || !reply.value.is_valid() {
            return Err(failed("create-reply", reply.status));
        }
        self.surface = reply.value;

        let serial = self
            .client
            .set_role(
                self.surface,
                COMPOSITOR_ROLE_TOPLEVEL,
                CompositorHandle::INVALID,
                WAIT_TIMEOUT_INFINITE,
            )
            .map_err(|error| window_error("set-role", error))?;
        Self::require_success(self.wait_reply(serial)?, "role-reply")?;
        let configured = self
            .client
            .surface_info(self.surface)
            .ok_or_else(|| failed("configure-state", 0))?;
        if configured.pending_configure_serial == 0
            || configured.configured_width == 0
            || configured.configured_height == 0
        {
            return Err(failed("configure-event", 0));
        }
        self.width = configured.configured_width;
        self.height = configured.configured_height;
        self.stride = (self.width as usize)
            .checked_mul(4)
            .ok_or_else(|| failed("surface-stride", 0))?;
        self.layout = Layout::new(self.width, self.height);

        let serial = self
            .client
            .ack_configure(
                self.surface,
                configured.pending_configure_serial,
                WAIT_TIMEOUT_INFINITE,
            )
            .map_err(|error| window_error("ack-configure", error))?;
        Self::require_success(self.wait_reply(serial)?, "ack-reply")?;

        let serial = self
            .client
            .set_title(self.surface, "Files", WAIT_TIMEOUT_INFINITE)
            .map_err(|error| window_error("set-title", error))?;
        Self::require_success(self.wait_reply(serial)?, "title-reply")
    }

    fn allocate_buffers(&mut self) -> AppResult<()> {
        let length = self
            .stride
            .checked_mul(self.height as usize)
            .ok_or_else(|| failed("surface-length", 0))?;
        for (index, token) in BUFFER_TOKENS.iter().copied().enumerate() {
            let fd = libuser::shm_create(length)
                .map_err(|libuser::Error(errno)| failed("shm-create", errno))?;
            let mapping = match libuser::syscall::mmap(
                core::ptr::null_mut(),
                length,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fd,
                0,
            ) {
                Ok(mapping) => mapping,
                Err(libuser::Error(errno)) => {
                    let _ = libuser::syscall::close(fd);
                    return Err(failed("shm-map", errno));
                },
            };
            self.buffers[index] = SharedBuffer {
                fd,
                mapping,
                length,
                token,
                retained: false,
            };
        }
        Ok(())
    }

    fn present(&mut self) -> AppResult<()> {
        let index = self
            .buffers
            .iter()
            .enumerate()
            .find(|(index, buffer)| Some(*index) != self.current_buffer && !buffer.retained)
            .map(|(index, _)| index)
            .ok_or_else(|| failed("no-free-buffer", 0))?;
        let buffer = self.buffers[index];
        if !buffer.is_allocated() {
            return Err(failed("invalid-buffer", 0));
        }
        // SAFETY: this process exclusively writes a live read-write mapping
        // until the attach below transfers read-only compositor access.
        let pixels = unsafe { core::slice::from_raw_parts_mut(buffer.mapping, buffer.length) };
        render(pixels, self.width, self.height, self.stride, &self.model)
            .map_err(|_| failed("render", 0))?;

        let metadata = CompositorSurfaceMetadata {
            width: self.width,
            height: self.height,
            stride: self.stride as u32,
            format: COMPOSITOR_FORMAT_BGRA8888,
            buffer_token: buffer.token,
            offset: 0,
            length: buffer.length as u64,
            reserved: [0; 2],
        };
        let serial = self
            .client
            .attach_buffer(
                self.surface,
                buffer.fd,
                buffer.length as u64,
                metadata,
                WAIT_TIMEOUT_INFINITE,
            )
            .map_err(|error| window_error("attach-buffer", error))?;
        Self::require_success(self.wait_reply(serial)?, "attach-reply")?;
        self.buffers[index].retained = true;

        let token = FRAME_TOKEN_BASE | self.next_frame;
        self.next_frame = self.next_frame.checked_add(1).unwrap_or(1);
        self.last_frame_done = 0;
        let damage = [CompositorDamageRect {
            x: 0,
            y: 0,
            width: self.width,
            height: self.height,
        }];
        let serial = self
            .client
            .commit(self.surface, &damage, Some(token), WAIT_TIMEOUT_INFINITE)
            .map_err(|error| window_error("commit", error))?;
        Self::require_success(self.wait_reply(serial)?, "commit-reply")?;
        if self.last_frame_done != token {
            return Err(failed("frame-done", 0));
        }
        self.current_buffer = Some(index);
        Ok(())
    }

    fn wait_reply(&mut self, expected: u64) -> AppResult<libwindow::Reply> {
        loop {
            match self
                .client
                .receive(WAIT_TIMEOUT_INFINITE)
                .map_err(|error| window_error("receive-reply", error))?
            {
                Incoming::Reply(reply) => {
                    if reply.serial != expected {
                        return Err(failed("reply-serial", 0));
                    }
                    return Ok(reply);
                },
                Incoming::Event(event) => self.handle_event(event),
            }
        }
    }

    fn require_success(reply: libwindow::Reply, stage: &'static str) -> AppResult<()> {
        if reply.succeeded() {
            Ok(())
        } else {
            Err(failed(stage, reply.status))
        }
    }

    fn handle_event(&mut self, event: Event) {
        match event.kind {
            EventKind::Configure(configure) => {
                if self.surface.is_valid()
                    && (configure.width != self.width || configure.height != self.height)
                    && self.buffers.iter().any(|buffer| buffer.is_allocated())
                {
                    self.model
                        .set_status(b"Window resizing is not available yet");
                    self.dirty = true;
                }
            },
            EventKind::Close(_) => self.exit_requested = true,
            EventKind::Focus(focus) => {
                if self.model.set_focused(focus.focused != 0) {
                    self.dirty = true;
                }
            },
            EventKind::Pointer(pointer) => {
                let interaction = self.model.handle_pointer(self.layout, pointer);
                self.queue_interaction(interaction);
            },
            EventKind::Key(key) => {
                let interaction = self.model.handle_key(self.layout, key);
                self.queue_interaction(interaction);
            },
            EventKind::Text(text) => {
                let interaction = self.model.handle_text(text);
                self.queue_interaction(interaction);
            },
            EventKind::FrameDone(frame) => self.last_frame_done = frame.frame_token,
            EventKind::BufferRelease(release) => {
                if let Some(buffer) = self
                    .buffers
                    .iter_mut()
                    .find(|buffer| buffer.token == release.buffer_token)
                {
                    buffer.retained = false;
                }
            },
        }
    }

    fn queue_interaction(&mut self, interaction: Interaction) {
        self.dirty |= interaction.repaint;
        if interaction.command == Command::Exit {
            self.pending_command = Command::Exit;
        } else if self.pending_command == Command::None && interaction.command != Command::None {
            self.pending_command = interaction.command;
        }
    }

    fn execute_command(&mut self, command: Command) {
        match command {
            Command::None => {},
            Command::Exit => self.exit_requested = true,
            Command::Back => {
                if let Some(path) = self.model.back_target() {
                    self.navigate(path, HistoryMode::Back);
                }
            },
            Command::Up => {
                if let Some(path) = self.model.up_target() {
                    self.navigate(path, HistoryMode::Push);
                }
            },
            Command::Refresh => {
                self.navigate(self.model.current_path(), HistoryMode::Preserve);
            },
            Command::NewFolder => self.create_folder(),
            Command::OpenSelected => self.open_selected(),
            Command::SubmitAddress => self.submit_address(),
            Command::NavigatePlace(place) => {
                self.navigate(place.path(), HistoryMode::Push);
            },
            Command::DeleteSelected => self.delete_selected(),
        }
    }

    fn navigate(&mut self, path: FixedPath, mode: HistoryMode) -> bool {
        match self.load_directory(path, mode) {
            Ok(()) => {
                self.dirty = true;
                true
            },
            Err(libuser::Error(errno)) => {
                self.model.set_status(b"Unable to open this folder");
                libuser::println!(
                    "XENITH_EXPLORER_DIRECTORY_FAIL path={} errno={}",
                    path.as_str(),
                    errno
                );
                self.dirty = true;
                false
            },
        }
    }

    fn load_directory(&mut self, path: FixedPath, mode: HistoryMode) -> libuser::Result<()> {
        let selected = if mode == HistoryMode::Preserve {
            self.model.selected_entry().copied()
        } else {
            None
        };
        let mut wire = [DirectoryEntry::default(); MAX_DIRECTORY_ENTRIES];
        let count = libuser::syscall::read_dir(path.as_bytes(), &mut wire)?;
        let mut metadata = [EntryMetadata::default(); MAX_DIRECTORY_ENTRIES];
        for index in 0..count {
            let length = usize::from(wire[index].name_len).min(wire[index].name.len());
            let Ok(child) = path.join_component(&wire[index].name[..length]) else {
                continue;
            };
            let mut stat = Stat::default();
            if libuser::syscall::stat(child.as_bytes(), &mut stat).is_ok() {
                metadata[index] = EntryMetadata {
                    size: stat.size,
                    modified_ns: stat.modified_ns,
                };
            }
        }
        self.model
            .commit_directory(path, &wire[..count], &metadata[..count], mode);
        if let Some(entry) = selected {
            self.model
                .select_name(entry.name(), self.layout.visible_row_count());
        }
        libuser::println!(
            "XENITH_EXPLORER_DIRECTORY path={} entries={}",
            path.as_str(),
            count
        );
        if count == MAX_DIRECTORY_ENTRIES {
            libuser::println!(
                "XENITH_EXPLORER_DIRECTORY_TRUNCATED path={} limit={}",
                path.as_str(),
                MAX_DIRECTORY_ENTRIES
            );
        }
        Ok(())
    }

    fn open_selected(&mut self) {
        let Some(entry) = self.model.selected_entry().copied() else {
            return;
        };
        if entry.kind != ENTRY_KIND_DIRECTORY {
            self.model
                .set_status(b"No application is registered for this file yet");
            libuser::println!(
                "XENITH_EXPLORER_OPEN_UNSUPPORTED path={} name={}",
                self.model.current_path().as_str(),
                core::str::from_utf8(entry.name()).unwrap_or("?")
            );
            self.dirty = true;
            return;
        }
        match self.model.current_path().join_component(entry.name()) {
            Ok(path) => {
                self.navigate(path, HistoryMode::Push);
            },
            Err(_) => {
                self.model.set_status(b"This folder name is not valid");
                self.dirty = true;
            },
        }
    }

    fn submit_address(&mut self) {
        let path = FixedPath::normalize_absolute(self.model.address_bytes());
        match path {
            Ok(path) => {
                let success = self.navigate(path, HistoryMode::Push);
                self.model.finish_address_edit(success);
            },
            Err(error) => {
                self.model.set_status(address_error(error));
                self.dirty = true;
            },
        }
    }

    fn create_folder(&mut self) {
        let parent = self.model.current_path();
        let mut name = [0u8; 32];
        for ordinal in 1..=99u32 {
            let length = new_folder_name(ordinal, &mut name);
            let Ok(path) = parent.join_component(&name[..length]) else {
                break;
            };
            let mut stat = Stat::default();
            match libuser::syscall::stat(path.as_bytes(), &mut stat) {
                Ok(()) => continue,
                Err(libuser::Error(errno)) if errno == Errno::Enoent as i32 => {},
                Err(libuser::Error(errno)) => {
                    self.model.set_status(b"Unable to check a new folder name");
                    libuser::println!("XENITH_EXPLORER_CREATE_FAIL errno={}", errno);
                    self.dirty = true;
                    return;
                },
            }
            match libuser::syscall::mkdir(path.as_bytes(), 0o755) {
                Ok(()) => {
                    libuser::println!("XENITH_EXPLORER_CREATED path={}", path.as_str());
                    if self.load_directory(parent, HistoryMode::Preserve).is_ok() {
                        self.model
                            .select_name(&name[..length], self.layout.visible_row_count());
                    }
                    self.dirty = true;
                    return;
                },
                Err(libuser::Error(errno)) => {
                    self.model.set_status(b"Unable to create a folder");
                    libuser::println!("XENITH_EXPLORER_CREATE_FAIL errno={}", errno);
                    self.dirty = true;
                    return;
                },
            }
        }
        self.model
            .set_status(b"No unused New folder name was available");
        self.dirty = true;
    }

    fn delete_selected(&mut self) {
        let Some(entry) = self.model.selected_entry().copied() else {
            return;
        };
        let parent = self.model.current_path();
        let Ok(path) = parent.join_component(entry.name()) else {
            self.model.set_status(b"This item name is not valid");
            self.dirty = true;
            return;
        };
        let result = if entry.kind == ENTRY_KIND_DIRECTORY {
            libuser::syscall::rmdir(path.as_bytes())
        } else {
            libuser::syscall::unlink(path.as_bytes())
        };
        match result {
            Ok(()) => {
                libuser::println!("XENITH_EXPLORER_DELETED path={}", path.as_str());
                let _ = self.load_directory(parent, HistoryMode::Preserve);
            },
            Err(libuser::Error(errno)) => {
                self.model.cancel_delete();
                self.model
                    .set_status(if entry.kind == ENTRY_KIND_DIRECTORY {
                        b"Folder deletion failed; only empty folders can be removed"
                    } else {
                        b"Unable to delete this file"
                    });
                libuser::println!(
                    "XENITH_EXPLORER_DELETE_FAIL path={} errno={}",
                    path.as_str(),
                    errno
                );
            },
        }
        self.dirty = true;
    }

    fn cleanup(&mut self, server_alive: bool) -> Option<Failure> {
        let mut first = None;
        if server_alive && self.surface.is_valid() {
            match self
                .client
                .destroy_surface(self.surface, WAIT_TIMEOUT_INFINITE)
            {
                Ok(serial) => match self.wait_reply(serial) {
                    Ok(reply) if reply.succeeded() => {},
                    Err(AppError::Closed) => {},
                    Ok(reply) => {
                        first = Some(Failure {
                            stage: "destroy-reply",
                            errno: reply.status,
                        })
                    },
                    Err(AppError::Failed(failure)) => first = Some(failure),
                },
                Err(error) => match window_error("destroy-surface", error) {
                    AppError::Closed => {},
                    AppError::Failed(failure) => first = Some(failure),
                },
            }
            self.surface = CompositorHandle::INVALID;
        }
        for buffer in &mut self.buffers {
            if !buffer.mapping.is_null() && buffer.length != 0 {
                if let Err(libuser::Error(errno)) =
                    libuser::syscall::munmap(buffer.mapping, buffer.length)
                {
                    if first.is_none() {
                        first = Some(Failure {
                            stage: "cleanup-munmap",
                            errno,
                        });
                    }
                }
            }
            if buffer.fd >= 0 {
                if let Err(libuser::Error(errno)) = libuser::syscall::close(buffer.fd) {
                    if first.is_none() {
                        first = Some(Failure {
                            stage: "cleanup-shm",
                            errno,
                        });
                    }
                }
            }
            *buffer = SharedBuffer::EMPTY;
        }
        if self.endpoint >= 0 {
            if let Err(libuser::Error(errno)) = libuser::syscall::close(self.endpoint) {
                if first.is_none() {
                    first = Some(Failure {
                        stage: "cleanup-channel",
                        errno,
                    });
                }
            }
            self.endpoint = -1;
        }
        first
    }
}

#[no_mangle]
/// # Safety
/// `startup` must point to the immutable loader-created startup block.
pub unsafe extern "C" fn _start(startup: *const Startup) -> ! {
    // SAFETY: guaranteed by the process entry contract above.
    let startup = unsafe { startup.as_ref() };
    let Some(startup) = startup else {
        report_failure(Failure {
            stage: "startup",
            errno: 0,
        });
        libuser::syscall::exit(1)
    };
    // SAFETY: loader-owned argument vectors remain valid for process lifetime.
    let endpoint = unsafe { startup.argument(1) }.and_then(parse_fd);
    let Some(endpoint) = endpoint else {
        report_failure(Failure {
            stage: "client-fd",
            errno: 0,
        });
        libuser::syscall::exit(1)
    };
    // SAFETY: same immutable startup-vector contract.
    let initial_path = unsafe { startup.argument(2) };

    let mut runtime = Runtime::new(endpoint);
    let result = runtime.run(initial_path);
    let server_alive = !matches!(result, Err(AppError::Closed));
    let cleanup = runtime.cleanup(server_alive);
    match (result, cleanup) {
        (Ok(()) | Err(AppError::Closed), None) => {
            libuser::println!("XENITH_EXPLORER_CLEAN_EXIT");
            libuser::syscall::exit(0)
        },
        (Ok(()) | Err(AppError::Closed), Some(failure)) | (Err(AppError::Failed(failure)), _) => {
            report_failure(failure);
            libuser::syscall::exit(1)
        },
    }
}

fn parse_fd(bytes: &[u8]) -> Option<i32> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0i32;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(i32::from(byte - b'0'))?;
    }
    Some(value)
}

fn new_folder_name(ordinal: u32, output: &mut [u8; 32]) -> usize {
    output.fill(0);
    let base = b"New folder";
    output[..base.len()].copy_from_slice(base);
    if ordinal <= 1 {
        return base.len();
    }
    let mut used = base.len();
    output[used] = b' ';
    output[used + 1] = b'(';
    used += 2;
    let mut reverse = [0u8; 10];
    let mut value = ordinal;
    let mut digits = 0;
    while value != 0 {
        reverse[digits] = b'0' + (value % 10) as u8;
        digits += 1;
        value /= 10;
    }
    for index in 0..digits {
        output[used + index] = reverse[digits - index - 1];
    }
    used += digits;
    output[used] = b')';
    used + 1
}

const fn address_error(error: PathError) -> &'static [u8] {
    match error {
        PathError::NotAbsolute | PathError::Empty => b"Enter an absolute C:\\ or / path",
        PathError::TooLong => b"That path is too long",
        PathError::UnsupportedWindowsPath => b"Only the C: Windows drive is available",
        PathError::InvalidUtf8 | PathError::InvalidCharacter | PathError::InvalidComponent => {
            b"That path is not valid"
        },
    }
}

fn window_error(stage: &'static str, error: libwindow::Error<libuser::Error>) -> AppError {
    match error {
        libwindow::Error::Transport(libuser::Error(errno)) if errno == Errno::Epipe as i32 => {
            AppError::Closed
        },
        libwindow::Error::Transport(libuser::Error(errno)) => {
            AppError::Failed(Failure { stage, errno })
        },
        libwindow::Error::Argument(_)
        | libwindow::Error::State(_)
        | libwindow::Error::Protocol(_) => AppError::Failed(Failure { stage, errno: 0 }),
    }
}

const fn failed(stage: &'static str, errno: i32) -> AppError {
    AppError::Failed(Failure { stage, errno })
}

fn report_failure(failure: Failure) {
    libuser::println!(
        "XENITH_EXPLORER_FAIL stage={} errno={}",
        failure.stage,
        failure.errno
    );
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libuser::println!("XENITH_EXPLORER_FAIL stage=panic errno=0");
    libuser::syscall::exit(127)
}
