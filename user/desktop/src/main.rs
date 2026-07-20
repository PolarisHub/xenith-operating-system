#![no_std]
#![no_main]

use core::panic::PanicInfo;

use libuser::args::Startup;
use xenith_abi::{
    Errno, UiDisplayInfo, UiInputEvent, UiRect, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE,
    UI_ABI_VERSION, UI_DISPLAY_NATIVE_PIXEL_FORMAT, UI_TIMEOUT_INFINITE,
};
use xenith_desktop::{
    DamageTracker, DesktopState, EventAction, PixelFormat, Renderer, Size, Surface,
    MAX_DAMAGE_RECTS,
};

const SMOKE_WAIT_NS: u64 = 50_000_000;

#[derive(Clone, Copy)]
enum LoopExit {
    RecoveryChord,
    SmokeComplete,
}

struct Failure {
    stage: &'static str,
    errno: i32,
}

#[no_mangle]
/// # Safety
/// `startup` must point to the loader-created, read-only startup block.
pub unsafe extern "C" fn _start(startup: *const Startup) -> ! {
    // SAFETY: the kernel validates and pins the startup block before entry.
    let smoke_exit = unsafe { startup.as_ref() }.and_then(|args| unsafe { args.argument(1) })
        == Some(b"--smoke-exit");
    let code = desktop_main(smoke_exit);
    libuser::syscall::exit(code)
}

fn desktop_main(smoke_exit: bool) -> i32 {
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
    let (size, stride, backbuffer_len, format) = geometry;
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

    let mut state = DesktopState::new(size);
    let renderer = Renderer::new();
    let result =
        render_full(mapping, backbuffer_len, stride, format, &renderer, &state).and_then(|()| {
            libuser::println!("XENITH_DESKTOP_READY");
            run_event_loop(
                mapping,
                backbuffer_len,
                stride,
                format,
                &renderer,
                &mut state,
                smoke_exit,
            )
        });

    if matches!(result, Ok(LoopExit::RecoveryChord)) {
        libuser::println!("XENITH_DESKTOP_EXIT");
    }
    let cleanup_failure = cleanup(mapping, backbuffer_len);
    match (result, cleanup_failure) {
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

fn validate_display(display: UiDisplayInfo) -> Result<(Size, usize, usize, PixelFormat), Failure> {
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
    Ok((size, stride, backbuffer_len, format))
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
    damage: &[xenith_desktop::Rect],
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
    format: PixelFormat,
    renderer: &Renderer,
    state: &mut DesktopState,
    smoke_exit: bool,
) -> Result<LoopExit, Failure> {
    let mut events = [UiInputEvent::default(); 32];
    let mut damage = DamageTracker::new(state.layout().screen);
    loop {
        let timeout = if smoke_exit {
            SMOKE_WAIT_NS
        } else {
            UI_TIMEOUT_INFINITE
        };
        let event_count = match libuser::ui_read_events(&mut events, timeout) {
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
        let launcher_was_open = state.launcher_open();
        for &event in &events[..event_count] {
            if state.handle_event(event, &mut damage) == EventAction::Exit {
                return Ok(LoopExit::RecoveryChord);
            }
        }
        if !damage.is_empty() {
            let regions = damage.rects();
            render_damage(mapping, length, stride, format, renderer, state, regions)?;
            if damage.is_full() {
                present(mapping, length, stride, &[])?;
            } else {
                let mut wire = [UiRect::default(); MAX_DAMAGE_RECTS];
                for (destination, source) in wire.iter_mut().zip(regions) {
                    *destination = (*source).into();
                }
                present(mapping, length, stride, &wire[..regions.len()])?;
            }
            if state.launcher_open() != launcher_was_open {
                libuser::println!(
                    "XENITH_DESKTOP_LAUNCHER_{}",
                    if state.launcher_open() {
                        "OPEN"
                    } else {
                        "CLOSED"
                    }
                );
            }
        }
        if smoke_exit {
            return Ok(LoopExit::SmokeComplete);
        }
    }
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
