#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use xenith_abi::{
    SigAction, SigAltStack, SigInfo, SigSet, SignalFrame, UiDisplayInfo, UiInputEvent, UiRect,
    GRND_NONBLOCK, MAP_ANONYMOUS, MAP_PRIVATE, MINSIGSTKSZ, PROT_READ, PROT_WRITE, SA_ONSTACK,
    SA_SIGINFO, SIGNAL_FRAME_ALTSTACK, SIGNAL_FRAME_XSTATE, SIGNAL_XSTATE_MAX, SIGUSR1, SIGUSR2,
    SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK, SI_USER, SS_DISABLE, UI_ABI_VERSION,
    UI_DISPLAY_NATIVE_PIXEL_FORMAT,
};

const PAGE_SIZE: usize = 4096;
const ALT_STACK_SIZE: usize = MINSIGSTKSZ as usize;

static SIGNAL_COUNT: AtomicUsize = AtomicUsize::new(0);
static SIGNAL_FAILURES: AtomicU64 = AtomicU64::new(0);
static EXPECTED_PID: AtomicU64 = AtomicU64::new(0);
static ALT_STACK_START: AtomicU64 = AtomicU64::new(0);
static ALT_STACK_END: AtomicU64 = AtomicU64::new(0);
static LAST_SIGNAL: AtomicU32 = AtomicU32::new(0);

const BAD_POINTER: u64 = 1 << 0;
const BAD_SEQUENCE: u64 = 1 << 1;
const BAD_SIGINFO_SIGNO: u64 = 1 << 2;
const BAD_SIGINFO_CODE: u64 = 1 << 3;
const BAD_SENDER: u64 = 1 << 4;
const BAD_HANDLER_STACK: u64 = 1 << 5;
const BAD_FRAME_POINTERS: u64 = 1 << 6;
const BAD_FRAME_SIGNO: u64 = 1 << 7;
const BAD_FRAME_FLAGS: u64 = 1 << 8;
const BAD_XSTATE_METADATA: u64 = 1 << 9;

enum UiSmokeOutcome {
    Ok,
    SkipNoFramebuffer,
    Failed {
        stage: &'static str,
        errno: i32,
        cleanup_failures: u8,
    },
}

fn ui_failed(stage: &'static str, errno: i32, mapping: Option<(*mut u8, usize)>) -> UiSmokeOutcome {
    let mut cleanup_failures = 0;
    if libuser::ui_release().is_err() {
        cleanup_failures |= 1;
    }
    if let Some((address, length)) = mapping {
        if libuser::syscall::munmap(address, length).is_err() {
            cleanup_failures |= 2;
        }
    }
    UiSmokeOutcome::Failed {
        stage,
        errno,
        cleanup_failures,
    }
}

fn channel_mask(shift: u8, size: u8) -> Option<u32> {
    let end = u16::from(shift).checked_add(u16::from(size))?;
    if size == 0 || end > 32 {
        return None;
    }
    let low_mask = if size == 32 {
        u32::MAX
    } else {
        (1u32 << size) - 1
    };
    low_mask.checked_shl(u32::from(shift))
}

fn pack_channel(value: u8, shift: u8, size: u8) -> u32 {
    let maximum = if size == 32 {
        u64::from(u32::MAX)
    } else {
        (1u64 << size) - 1
    };
    ((((u64::from(value) * maximum) + 127) / 255) << shift) as u32
}

fn pack_pixel(display: &UiDisplayInfo, red: u8, green: u8, blue: u8) -> u32 {
    pack_channel(red, display.red_shift, display.red_size)
        | pack_channel(green, display.green_shift, display.green_size)
        | pack_channel(blue, display.blue_shift, display.blue_size)
}

fn paint_rect(mapping: *mut u8, stride: usize, rect: UiRect, color: impl Fn(usize, usize) -> u32) {
    for y in rect.y as usize..(rect.y + rect.height) as usize {
        // SAFETY: the caller bounds `rect` to the mapped display and validates
        // that every stride-wide row is present in the mapping.
        let row = unsafe { mapping.add(y * stride).cast::<u32>() };
        for x in rect.x as usize..(rect.x + rect.width) as usize {
            // SAFETY: x is inside the visible width and the stride covers all
            // visible pixels. Anonymous mappings are writable and aligned.
            unsafe { row.add(x).write(color(x, y)) };
        }
    }
}

fn ui_runtime_smoke() -> UiSmokeOutcome {
    let mut display = UiDisplayInfo::default();
    if let Err(libuser::Error(errno)) = libuser::ui_acquire(&mut display) {
        if errno == xenith_abi::Errno::Enodev as i32 {
            return UiSmokeOutcome::SkipNoFramebuffer;
        }
        return UiSmokeOutcome::Failed {
            stage: "acquire",
            errno,
            cleanup_failures: 0,
        };
    }

    let Some(red_mask) = channel_mask(display.red_shift, display.red_size) else {
        return ui_failed("format-red", 0, None);
    };
    let Some(green_mask) = channel_mask(display.green_shift, display.green_size) else {
        return ui_failed("format-green", 0, None);
    };
    let Some(blue_mask) = channel_mask(display.blue_shift, display.blue_size) else {
        return ui_failed("format-blue", 0, None);
    };
    let Some(visible_row_bytes) = (display.width as usize).checked_mul(4) else {
        return ui_failed("geometry-width", 0, None);
    };
    let stride = display.stride as usize;
    let height = display.height as usize;
    if display.version != UI_ABI_VERSION
        || display.width == 0
        || display.height == 0
        || display.bits_per_pixel != 32
        || display.flags & UI_DISPLAY_NATIVE_PIXEL_FORMAT == 0
        || display.reserved != 0
        || stride < visible_row_bytes
        || !stride.is_multiple_of(4)
        || red_mask & green_mask != 0
        || red_mask & blue_mask != 0
        || green_mask & blue_mask != 0
    {
        return ui_failed("display-info", 0, None);
    }
    let Some(backbuffer_len) = stride.checked_mul(height) else {
        return ui_failed("geometry-size", 0, None);
    };
    let mapping = match libuser::syscall::mmap(
        core::ptr::null_mut(),
        backbuffer_len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    ) {
        Ok(mapping) => mapping,
        Err(libuser::Error(errno)) => return ui_failed("mmap", errno, None),
    };

    let colors = [
        pack_pixel(&display, 0x12, 0x1a, 0x31),
        pack_pixel(&display, 0x1d, 0x4e, 0x68),
        pack_pixel(&display, 0x25, 0xb9, 0x9a),
        pack_pixel(&display, 0xa8, 0xed, 0xd8),
    ];
    let full = UiRect {
        x: 0,
        y: 0,
        width: display.width,
        height: display.height,
    };
    paint_rect(mapping, stride, full, |x, y| {
        colors[((x >> 4) ^ (y >> 4)) & 3]
    });
    // SAFETY: mmap returned a readable range of exactly this byte length, and
    // it remains mapped until the cleanup below.
    let full_present = libuser::ui_present(
        unsafe { core::slice::from_raw_parts(mapping, backbuffer_len) },
        stride,
        &[],
    );
    if let Err(libuser::Error(errno)) = full_present {
        return ui_failed("present-full", errno, Some((mapping, backbuffer_len)));
    }

    let mut events = [UiInputEvent::default(); 1];
    if let Err(libuser::Error(errno)) = libuser::ui_read_events(&mut events, 0) {
        return ui_failed("events-zero-time", errno, Some((mapping, backbuffer_len)));
    }

    let damage_width = display.width.min(16);
    let damage_height = display.height.min(16);
    let damage = UiRect {
        x: (display.width - damage_width) / 2,
        y: (display.height - damage_height) / 2,
        width: damage_width,
        height: damage_height,
    };
    let accent = pack_pixel(&display, 0xf5, 0x7f, 0x50);
    paint_rect(mapping, stride, damage, |_, _| accent);
    // SAFETY: the mapping remains readable and live for this presentation.
    let damage_present = libuser::ui_present(
        unsafe { core::slice::from_raw_parts(mapping, backbuffer_len) },
        stride,
        &[damage],
    );
    if let Err(libuser::Error(errno)) = damage_present {
        return ui_failed("present-damage", errno, Some((mapping, backbuffer_len)));
    }

    if let Err(libuser::Error(errno)) = libuser::ui_release() {
        let cleanup_failures =
            u8::from(libuser::syscall::munmap(mapping, backbuffer_len).is_err()) << 1;
        return UiSmokeOutcome::Failed {
            stage: "release",
            errno,
            cleanup_failures,
        };
    }
    if let Err(libuser::Error(errno)) = libuser::syscall::munmap(mapping, backbuffer_len) {
        return UiSmokeOutcome::Failed {
            stage: "munmap",
            errno,
            cleanup_failures: 2,
        };
    }
    UiSmokeOutcome::Ok
}

extern "C" fn signal_handler(signo: u32, info: *const SigInfo, frame: *const SignalFrame) {
    let invocation = SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    let mut failures = 0u64;
    if info.is_null() || frame.is_null() {
        SIGNAL_FAILURES.fetch_or(BAD_POINTER, Ordering::SeqCst);
        return;
    }
    let expected_signal = match invocation {
        1 => SIGUSR1,
        2 => SIGUSR2,
        _ => {
            failures |= BAD_SEQUENCE;
            0
        },
    };
    if signo != expected_signal {
        failures |= BAD_SEQUENCE;
    }

    // SAFETY: the kernel supplies both pointers for an SA_SIGINFO handler;
    // null was rejected above and the records remain live until sigreturn.
    let (info, frame) = unsafe { (&*info, &*frame) };
    if info.signo != signo {
        failures |= BAD_SIGINFO_SIGNO;
    }
    if info.code != SI_USER {
        failures |= BAD_SIGINFO_CODE;
    }
    if info.sender_pid != EXPECTED_PID.load(Ordering::SeqCst) {
        failures |= BAD_SENDER;
    }

    let stack_probe = 0u8;
    let stack_address = core::ptr::from_ref(&stack_probe) as u64;
    let stack_start = ALT_STACK_START.load(Ordering::SeqCst);
    let stack_end = ALT_STACK_END.load(Ordering::SeqCst);
    if !(stack_start..stack_end).contains(&stack_address) {
        failures |= BAD_HANDLER_STACK;
    }
    if !core::ptr::eq(info, core::ptr::from_ref(&frame.info)) {
        failures |= BAD_FRAME_POINTERS;
    }
    if frame.signo != u64::from(signo) || frame.info.signo != signo {
        failures |= BAD_FRAME_SIGNO;
    }
    if frame.frame_flags & (SIGNAL_FRAME_ALTSTACK | SIGNAL_FRAME_XSTATE)
        != SIGNAL_FRAME_ALTSTACK | SIGNAL_FRAME_XSTATE
    {
        failures |= BAD_FRAME_FLAGS;
    }
    let xstate_end = frame.xstate_ptr.checked_add(frame.xstate_size);
    if frame.xstate_ptr & 63 != 0
        || frame.xstate_size == 0
        || frame.xstate_size > SIGNAL_XSTATE_MAX as u64
        || frame.xstate_features == 0
        || frame.xstate_ptr < stack_start
        || xstate_end.is_none_or(|end| end > stack_end)
    {
        failures |= BAD_XSTATE_METADATA;
    }
    LAST_SIGNAL.store(signo, Ordering::SeqCst);
    SIGNAL_FAILURES.fetch_or(failures, Ordering::SeqCst);
}

fn signal_runtime_smoke() -> Result<(), u32> {
    SIGNAL_COUNT.store(0, Ordering::SeqCst);
    SIGNAL_FAILURES.store(0, Ordering::SeqCst);
    LAST_SIGNAL.store(0, Ordering::SeqCst);

    let stack = libuser::syscall::mmap(
        core::ptr::null_mut(),
        ALT_STACK_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    )
    .map_err(|_| 1u32)?;
    let stack_start = stack as u64;
    let Some(stack_end) = stack_start.checked_add(ALT_STACK_SIZE as u64) else {
        return Err(2);
    };
    ALT_STACK_START.store(stack_start, Ordering::SeqCst);
    ALT_STACK_END.store(stack_end, Ordering::SeqCst);

    let alternate = SigAltStack {
        sp: stack_start,
        size: ALT_STACK_SIZE as u64,
        flags: 0,
        reserved: 0,
    };
    if libuser::syscall::sigaltstack(Some(&alternate), None).is_err() {
        return Err(3);
    }
    let mut queried = SigAltStack::default();
    if libuser::syscall::sigaltstack(None, Some(&mut queried)).is_err()
        || queried.sp != alternate.sp
        || queried.size != alternate.size
        || queried.flags != 0
    {
        return Err(4);
    }

    let action = SigAction {
        handler: signal_handler as *const () as usize as u64,
        mask: SigSet(0),
        flags: SA_ONSTACK | SA_SIGINFO,
    };
    if libuser::syscall::sigaction(SIGUSR1, Some(&action), None).is_err()
        || libuser::syscall::sigaction(SIGUSR2, Some(&action), None).is_err()
    {
        return Err(5);
    }
    let pid = libuser::syscall::getpid().map_err(|_| 6u32)?;
    let pid_argument = i64::try_from(pid).map_err(|_| 7u32)?;
    EXPECTED_PID.store(pid, Ordering::SeqCst);
    if libuser::syscall::kill(pid_argument, SIGUSR1).is_err() {
        return Err(8);
    }
    if SIGNAL_COUNT.load(Ordering::SeqCst) != 1
        || LAST_SIGNAL.load(Ordering::SeqCst) != SIGUSR1
        || SIGNAL_FAILURES.load(Ordering::SeqCst) != 0
    {
        return Err(9);
    }

    let usr2 = SigSet(1u64 << SIGUSR2);
    let mut original_mask = SigSet::default();
    if libuser::syscall::sigprocmask(SIG_BLOCK, Some(&usr2), Some(&mut original_mask)).is_err() {
        return Err(10);
    }
    if libuser::syscall::kill(pid_argument, SIGUSR2).is_err() {
        return Err(11);
    }
    if SIGNAL_COUNT.load(Ordering::SeqCst) != 1 {
        return Err(12);
    }
    if libuser::syscall::sigprocmask(SIG_UNBLOCK, Some(&usr2), None).is_err() {
        return Err(13);
    }
    if SIGNAL_COUNT.load(Ordering::SeqCst) != 2
        || LAST_SIGNAL.load(Ordering::SeqCst) != SIGUSR2
        || SIGNAL_FAILURES.load(Ordering::SeqCst) != 0
    {
        return Err(14);
    }
    if libuser::syscall::sigprocmask(SIG_SETMASK, Some(&original_mask), None).is_err() {
        return Err(15);
    }

    let disabled = SigAltStack {
        sp: 0,
        size: 0,
        flags: SS_DISABLE,
        reserved: 0,
    };
    if libuser::syscall::sigaltstack(Some(&disabled), None).is_err()
        || libuser::syscall::munmap(stack, ALT_STACK_SIZE).is_err()
    {
        return Err(16);
    }
    Ok(())
}

fn memory_and_random_smoke() -> bool {
    let Ok(base) = libuser::syscall::brk(0) else {
        return false;
    };
    let Some(grown) = base.checked_add(PAGE_SIZE * 2) else {
        return false;
    };
    if libuser::syscall::brk(grown) != Ok(grown) {
        return false;
    }
    // SAFETY: the successful brk growth mapped this byte writable.
    unsafe { core::ptr::write_volatile(base as *mut u8, 0x5a) };
    // SAFETY: the same mapping remains live until the shrink below.
    if unsafe { core::ptr::read_volatile(base as *const u8) } != 0x5a {
        return false;
    }
    if libuser::syscall::brk(base) != Ok(base) {
        return false;
    }

    let Ok(mapping) = libuser::syscall::mmap(
        core::ptr::null_mut(),
        PAGE_SIZE * 3,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    ) else {
        return false;
    };
    // SAFETY: mmap returned three writable pages.
    unsafe {
        core::ptr::write_volatile(mapping, 0x11);
        core::ptr::write_volatile(mapping.add(PAGE_SIZE * 2), 0x33);
    }
    // Splitting a region exercises the middle-unmap metadata path while the
    // retained prefix and suffix stay accessible.
    // SAFETY: the offsets remain within the three-page mapping.
    let middle = unsafe { mapping.add(PAGE_SIZE) };
    if libuser::syscall::munmap(middle, PAGE_SIZE).is_err() {
        return false;
    }
    // SAFETY: only the middle page was removed.
    let retained = unsafe {
        core::ptr::read_volatile(mapping) == 0x11
            && core::ptr::read_volatile(mapping.add(PAGE_SIZE * 2)) == 0x33
    };
    // SAFETY: the suffix address is still inside the original allocation.
    let suffix = unsafe { mapping.add(PAGE_SIZE * 2) };
    if !retained
        || libuser::syscall::munmap(mapping, PAGE_SIZE).is_err()
        || libuser::syscall::munmap(suffix, PAGE_SIZE).is_err()
    {
        return false;
    }

    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    if libuser::syscall::getrandom(&mut first, 0) != Ok(first.len())
        || libuser::syscall::getrandom(&mut second, GRND_NONBLOCK) != Ok(second.len())
        || first == second
        || !first.iter().chain(second.iter()).any(|byte| *byte != 0)
    {
        return false;
    }
    matches!(
        libuser::syscall::getrandom(&mut [], 2),
        Err(libuser::syscall::Error(22))
    )
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    libuser::println!("hello from Xenith ring 3");
    if !memory_and_random_smoke() {
        libuser::println!("XENITH_VM_RANDOM_FAIL");
        libuser::syscall::exit(1)
    }
    libuser::println!("XENITH_VM_RANDOM_OK");
    match signal_runtime_smoke() {
        Ok(()) => {
            libuser::println!("XENITH_RING3_SIGNAL_OK");
        },
        Err(stage) => {
            libuser::println!(
                "XENITH_RING3_SIGNAL_FAIL stage={} flags={:#x} count={}",
                stage,
                SIGNAL_FAILURES.load(Ordering::SeqCst),
                SIGNAL_COUNT.load(Ordering::SeqCst)
            );
            libuser::syscall::exit(2)
        },
    }
    match ui_runtime_smoke() {
        UiSmokeOutcome::Ok => {
            libuser::println!("XENITH_RING3_UI_OK");
            libuser::syscall::exit(0)
        },
        UiSmokeOutcome::SkipNoFramebuffer => {
            libuser::println!("XENITH_RING3_UI_SKIP_NO_FRAMEBUFFER");
            libuser::syscall::exit(0)
        },
        UiSmokeOutcome::Failed {
            stage,
            errno,
            cleanup_failures,
        } => {
            libuser::println!(
                "XENITH_RING3_UI_FAIL stage={} errno={} cleanup={:#x}",
                stage,
                errno,
                cleanup_failures
            );
            libuser::syscall::exit(3)
        },
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libuser::syscall::exit(127)
}
