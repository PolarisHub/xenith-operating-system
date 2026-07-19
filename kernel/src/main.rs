//! Xenith kernel binary entry point.
//!
//! A supported loader transfers control to [`_start`] in ring 0 with a
//! higher-half direct map and its boot-info pointer in `rdi` (System V AMD64
//! ABI). The entry wrapper detects either the legacy Limine-compatible record
//! or Xenith's physical-pointer protocol, normalizes it, and then forwards the
//! compatibility surface to [`xenith_kernel::init`].

#![no_std]
#![no_main]

use core::arch::asm;
#[cfg(not(test))]
use core::panic::PanicInfo;

/// Xenith kernel entry point.
///
/// The function never returns: once [`xenith_kernel::init`] has brought every
/// subsystem up, the BSP halts and waits for interrupts.
///
/// # Safety
///
/// `raw_boot_info` must satisfy [`xenith_kernel::boot::normalize_raw`]'s loader
/// handoff contract. Supported loaders call this symbol exactly once on the
/// BSP with interrupts disabled.
#[no_mangle]
pub unsafe extern "C" fn _start(raw_boot_info: *const u8) -> ! {
    // SAFETY: this is the sole ABI boundary. The BIOS, UEFI, and legacy
    // emulator loaders establish the mappings and lifetime documented above.
    let boot_info = unsafe { xenith_kernel::boot::normalize_raw(raw_boot_info) }
        .unwrap_or_else(|error| panic!("xenith: boot handoff rejected: {error}"));
    xenith_kernel::init(boot_info);

    // init() returns once the kernel has reached a quiescent idle state.
    // Park indefinitely; interrupts may still wake the core (e.g. the timer
    // tick), so `hlt` is both lower-power and safer than a busy spin.
    loop {
        // SAFETY: `hlt` halts the CPU until the next interrupt. It performs
        // no memory access and touches no register state beyond the
        // instruction pointer, so the `nostack` and `nomem` options are
        // correct and no kernel invariant is disturbed.
        unsafe {
            asm!("hlt", options(nostack, nomem));
        }
    }
}

/// Top-level panic handler.
///
/// Kept in the final binary crate (where the linker expects the single
/// `#[panic_handler]`) and delegated to [`xenith_kernel::panic::handle`],
/// which logs the fault and parks the core.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    xenith_kernel::panic::handle(info)
}
