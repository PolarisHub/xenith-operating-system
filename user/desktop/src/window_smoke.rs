#![no_std]
#![no_main]

use core::panic::PanicInfo;

use libuser::args::Startup;
use libwindow::{Client, EventKind, Incoming, LibuserTransport};
use xenith_abi::compositor::{
    CompositorDamageRect, CompositorHandle, CompositorSurfaceMetadata, COMPOSITOR_FORMAT_BGRX8888,
    COMPOSITOR_ROLE_TOPLEVEL,
};
use xenith_abi::{Timespec, MAP_SHARED, PROT_READ, PROT_WRITE, WAIT_TIMEOUT_INFINITE};

#[path = "window_smoke_render.rs"]
mod window_smoke_render;

const FRAME_TOKEN: u64 = 0x5845_4e49_5448_0001;

struct Failure {
    stage: &'static str,
    errno: i32,
}

struct Resources {
    endpoint: i32,
    shared_memory: i32,
    mapping: *mut u8,
    mapping_length: usize,
}

impl Resources {
    const fn new(endpoint: i32) -> Self {
        Self {
            endpoint,
            shared_memory: -1,
            mapping: core::ptr::null_mut(),
            mapping_length: 0,
        }
    }

    fn cleanup(&mut self) -> Option<Failure> {
        let mut first = None;
        if !self.mapping.is_null() && self.mapping_length != 0 {
            if let Err(libuser::Error(errno)) =
                libuser::syscall::munmap(self.mapping, self.mapping_length)
            {
                first = Some(Failure {
                    stage: "munmap",
                    errno,
                });
            }
            self.mapping = core::ptr::null_mut();
            self.mapping_length = 0;
        }
        if self.shared_memory >= 0 {
            if let Err(libuser::Error(errno)) = libuser::syscall::close(self.shared_memory) {
                if first.is_none() {
                    first = Some(Failure {
                        stage: "close-shm",
                        errno,
                    });
                }
            }
            self.shared_memory = -1;
        }
        if self.endpoint >= 0 {
            if let Err(libuser::Error(errno)) = libuser::syscall::close(self.endpoint) {
                if first.is_none() {
                    first = Some(Failure {
                        stage: "close-channel",
                        errno,
                    });
                }
            }
            self.endpoint = -1;
        }
        first
    }
}

#[derive(Default)]
struct Observed {
    frame_done: bool,
    buffer_released: bool,
}

#[no_mangle]
/// # Safety
/// `startup` must name the loader-created startup block and vectors.
pub unsafe extern "C" fn _start(startup: *const Startup) -> ! {
    // SAFETY: the kernel loader owns and validates this immutable block.
    let startup = unsafe { startup.as_ref() };
    let result = startup
        .ok_or(Failure {
            stage: "startup",
            errno: 0,
        })
        .and_then(start_smoke);

    match result {
        Ok(()) => {
            libuser::println!("XENITH_WINDOW_SMOKE_PASS");
            libuser::syscall::exit(0)
        },
        Err(failure) => {
            report_failure(failure);
            libuser::syscall::exit(1)
        },
    }
}

fn start_smoke(startup: &Startup) -> Result<(), Failure> {
    // SAFETY: the loader contract for Startup applies for the process lifetime.
    let endpoint = unsafe { startup.argument(1) }
        .and_then(parse_fd)
        .ok_or(Failure {
            stage: "client-fd",
            errno: 0,
        })?;
    match libuser::syscall::close(0) {
        Err(libuser::Error(errno)) if errno == xenith_abi::Errno::Ebadf as i32 => {},
        Err(libuser::Error(errno)) => {
            return Err(Failure {
                stage: "restricted-fd-table",
                errno,
            });
        },
        Ok(()) => {
            return Err(Failure {
                stage: "inherited-stdin",
                errno: 0,
            });
        },
    }

    let mut resources = Resources::new(endpoint);
    libuser::println!("XENITH_WINDOW_SMOKE_START");
    let run_result = run_protocol(&mut resources);
    let cleanup_result = resources.cleanup();
    match (run_result, cleanup_result) {
        (Err(failure), _) => Err(failure),
        (Ok(()), Some(failure)) => Err(failure),
        (Ok(()), None) => Ok(()),
    }
}

fn run_protocol(resources: &mut Resources) -> Result<(), Failure> {
    let mut client = Client::new(LibuserTransport::new(resources.endpoint));
    let mut observed = Observed::default();

    let serial = client
        .create_surface(WAIT_TIMEOUT_INFINITE)
        .map_err(|_| failure("create-send"))?;
    let create = wait_for_reply(&mut client, serial, &mut observed, "create-reply")?;
    let surface = create.value;
    if !surface.is_valid() {
        return Err(failure("create-handle"));
    }

    let serial = client
        .set_role(
            surface,
            COMPOSITOR_ROLE_TOPLEVEL,
            CompositorHandle::INVALID,
            WAIT_TIMEOUT_INFINITE,
        )
        .map_err(|_| failure("role-send"))?;
    wait_for_reply(&mut client, serial, &mut observed, "role-reply")?;
    let configured = client
        .surface_info(surface)
        .ok_or(failure("configure-state"))?;
    if configured.pending_configure_serial == 0
        || configured.configured_width == 0
        || configured.configured_height == 0
    {
        return Err(failure("configure-event"));
    }

    let serial = client
        .ack_configure(
            surface,
            configured.pending_configure_serial,
            WAIT_TIMEOUT_INFINITE,
        )
        .map_err(|_| failure("ack-send"))?;
    wait_for_reply(&mut client, serial, &mut observed, "ack-reply")?;

    let serial = client
        .set_title(surface, "Xenith compositor", WAIT_TIMEOUT_INFINITE)
        .map_err(|_| failure("title-send"))?;
    wait_for_reply(&mut client, serial, &mut observed, "title-reply")?;

    let width = configured.configured_width;
    let height = configured.configured_height;
    let stride = (width as usize)
        .checked_mul(4)
        .ok_or(failure("buffer-stride"))?;
    let length = stride
        .checked_mul(height as usize)
        .ok_or(failure("buffer-length"))?;
    resources.shared_memory =
        libuser::shm_create(length).map_err(|libuser::Error(errno)| Failure {
            stage: "shm-create",
            errno,
        })?;
    resources.mapping = libuser::syscall::mmap(
        core::ptr::null_mut(),
        length,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        resources.shared_memory,
        0,
    )
    .map_err(|libuser::Error(errno)| Failure {
        stage: "mmap",
        errno,
    })?;
    resources.mapping_length = length;
    // SAFETY: the process exclusively owns this live read-write mapping.
    let pixels = unsafe { core::slice::from_raw_parts_mut(resources.mapping, length) };
    if !window_smoke_render::draw_window(pixels, width, height, stride) {
        return Err(failure("draw"));
    }

    let metadata = CompositorSurfaceMetadata {
        width,
        height,
        stride: stride as u32,
        format: COMPOSITOR_FORMAT_BGRX8888,
        buffer_token: 1,
        offset: 0,
        length: length as u64,
        reserved: [0; 2],
    };
    let serial = client
        .attach_buffer(
            surface,
            resources.shared_memory,
            length as u64,
            metadata,
            WAIT_TIMEOUT_INFINITE,
        )
        .map_err(|_| failure("attach-send"))?;
    wait_for_reply(&mut client, serial, &mut observed, "attach-reply")?;

    let damage = [CompositorDamageRect {
        x: 0,
        y: 0,
        width,
        height,
    }];
    let serial = client
        .commit(surface, &damage, Some(FRAME_TOKEN), WAIT_TIMEOUT_INFINITE)
        .map_err(|_| failure("commit-send"))?;
    wait_for_reply(&mut client, serial, &mut observed, "commit-reply")?;
    if !observed.frame_done {
        return Err(failure("frame-done"));
    }
    libuser::println!("XENITH_WINDOW_SMOKE_PRESENTED");

    libuser::syscall::nanosleep(Timespec {
        seconds: 0,
        nanoseconds: 50_000_000,
    })
    .map_err(|libuser::Error(errno)| Failure {
        stage: "display-delay",
        errno,
    })?;

    let serial = client
        .destroy_surface(surface, WAIT_TIMEOUT_INFINITE)
        .map_err(|_| failure("destroy-send"))?;
    wait_for_reply(&mut client, serial, &mut observed, "destroy-reply")?;
    if !observed.buffer_released {
        return Err(failure("buffer-release"));
    }
    Ok(())
}

fn wait_for_reply(
    client: &mut Client<LibuserTransport>,
    expected_serial: u64,
    observed: &mut Observed,
    stage: &'static str,
) -> Result<libwindow::Reply, Failure> {
    loop {
        match client
            .receive(WAIT_TIMEOUT_INFINITE)
            .map_err(|_| failure(stage))?
        {
            Incoming::Reply(reply) => {
                if reply.serial != expected_serial || !reply.succeeded() {
                    return Err(failure(stage));
                }
                return Ok(reply);
            },
            Incoming::Event(event) => match event.kind {
                EventKind::FrameDone(frame) => {
                    if frame.frame_token != FRAME_TOKEN
                        || frame.presentation_time_ns == 0
                        || frame.refresh_interval_ns == 0
                    {
                        return Err(failure("invalid-frame-done"));
                    }
                    observed.frame_done = true;
                },
                EventKind::BufferRelease(release) => {
                    if release.buffer_token != 1 {
                        return Err(failure("invalid-buffer-release"));
                    }
                    observed.buffer_released = true;
                },
                _ => {},
            },
        }
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

const fn failure(stage: &'static str) -> Failure {
    Failure { stage, errno: 0 }
}

fn report_failure(failure: Failure) {
    libuser::println!(
        "XENITH_WINDOW_SMOKE_FAIL stage={} errno={}",
        failure.stage,
        failure.errno
    );
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libuser::println!("XENITH_WINDOW_SMOKE_FAIL stage=panic errno=0");
    libuser::syscall::exit(127)
}
