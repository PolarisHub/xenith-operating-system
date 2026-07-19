#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    libuser::println!("Xenith userspace init");
    let path = b"/bin/sh";
    let argv0 = b"/bin/sh\0";
    let argv = [argv0.as_ptr(), core::ptr::null()];
    if let Err(error) = libuser::syscall::exec(path, argv.as_ptr(), core::ptr::null()) {
        libuser::println!("init: exec /bin/sh failed: errno {}", error.0);
    }
    libuser::syscall::exit(127)
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libuser::println!("init: panic");
    libuser::syscall::exit(127)
}
