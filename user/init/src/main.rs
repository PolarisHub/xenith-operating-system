#![no_std]
#![no_main]

use core::panic::PanicInfo;

use xenith_abi::Errno;

const DESKTOP_PATH: &[u8] = b"/bin/xenith-desktop";
const SHELL_PATH: &[u8] = b"/bin/sh";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    libuser::println!("Xenith userspace init");

    if display_session_available() {
        run_desktop_session();
    } else {
        libuser::println!("init: no framebuffer session; using terminal shell");
    }

    exec_shell()
}

fn display_session_available() -> bool {
    let mut display = libuser::UiDisplayInfo::default();
    if libuser::ui_acquire(&mut display).is_err() {
        // A text-only boot is a supported session mode, not a syscall
        // failure. The caller emits the single useful fallback message.
        return false;
    }

    if let Err(error) = libuser::ui_release() {
        libuser::println!("init: framebuffer release failed: errno {}", error.0);
        return false;
    }
    true
}

fn run_desktop_session() {
    let argv0 = b"/bin/xenith-desktop\0";
    let argv = [argv0.as_ptr(), core::ptr::null()];
    libuser::println!("XENITH_DESKTOP_START");
    let pid = match libuser::syscall::spawn(DESKTOP_PATH, argv.as_ptr(), core::ptr::null()) {
        Ok(pid) => pid,
        Err(error) => {
            libuser::println!("init: desktop spawn failed: errno {}", error.0);
            libuser::println!("XENITH_DESKTOP_FALLBACK");
            return;
        },
    };

    let mut status = 0i32;
    loop {
        match libuser::syscall::waitpid(pid, &mut status, 0) {
            Ok(_) => {
                libuser::println!("init: desktop exited: status {status:#x}");
                break;
            },
            Err(error) if error.0 == Errno::Eintr as i32 => continue,
            Err(error) => {
                libuser::println!("init: desktop wait failed: errno {}", error.0);
                break;
            },
        }
    }
    libuser::println!("XENITH_DESKTOP_FALLBACK");
}

fn exec_shell() -> ! {
    let argv0 = b"/bin/sh\0";
    let argv = [argv0.as_ptr(), core::ptr::null()];
    if let Err(error) = libuser::syscall::exec(SHELL_PATH, argv.as_ptr(), core::ptr::null()) {
        libuser::println!("init: exec /bin/sh failed: errno {}", error.0);
    }
    libuser::syscall::exit(127)
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libuser::println!("init: panic");
    libuser::syscall::exit(127)
}
