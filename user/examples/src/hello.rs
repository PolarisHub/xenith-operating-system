#![no_std]
#![no_main]

use core::panic::PanicInfo;

use xenith_abi::{
    GRND_NONBLOCK, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE,
};

const PAGE_SIZE: usize = 4096;

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
    if memory_and_random_smoke() {
        libuser::println!("XENITH_VM_RANDOM_OK");
        libuser::syscall::exit(0)
    }
    libuser::println!("XENITH_VM_RANDOM_FAIL");
    libuser::syscall::exit(1)
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libuser::syscall::exit(127)
}
