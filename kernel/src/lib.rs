//! Xenith kernel library.
//!
//! The bulk of the kernel lives in this crate. The binary (`main.rs`) owns
//! only the raw loader entry symbol and the `#[panic_handler]`; everything
//! else is driven from [`init`].
//!
//! # Subsystem layering
//!
//! Modules are layered top-to-bottom: a module only depends on modules listed
//! beneath it. The shared `xenith-types`, `xenith-bitflags`, and
//! `xenith-boot` crates sit underneath everything and are elided here.
//!
//! ```text
//!   user, syscall, fs, sched    <- process model + interfaces
//!   devices, time, acpi         <- drivers + platform discovery
//!   mm, sync                    <- memory + concurrency
//!   arch                        <- CPU tables, interrupts, context switch
//!   console, log, util          <- leaf services
//! ```
//!
//! The subsystem modules expose the production kernel surface used by the
//! boot sequence, architecture entry paths, and userspace ABI.

#![no_std]

extern crate alloc;

// --- Subsystem modules -----------------------------------------------------

pub mod acpi;
pub mod arch;
pub mod boot;
pub mod console;
pub mod devices;
pub mod fs;
pub mod ipc;
pub mod log;
pub mod mm;
pub mod net;
pub mod power;
pub mod sched;
pub mod sync;
pub mod syscall;
pub mod time;
pub mod tty;
pub mod ui;
pub mod user;
pub mod util;

// --- Bootstrap and fault handling ------------------------------------------

pub mod init;
pub mod panic;
#[cfg(test_kernel)]
pub mod test;

/// Kernel bring-up entry point.
///
/// Called exactly once by the binary's `_start` after [`boot`] has normalized
/// either supported loader protocol. Delegates to [`init::init`], which runs
/// every subsystem initialiser in dependency order, then returns so the caller
/// can park the BSP in a `hlt` loop.
///
/// The `init` module and this function intentionally share a name: the module
/// owns the implementation, this function is the stable public entry point.
/// Rust places modules (type namespace) and functions (value namespace) in
/// separate namespaces, so both coexist and `init::init(boot_info)` resolves
/// through the module while a bare `init(...)` call would resolve to this
/// function.
pub fn init(boot_info: &'static limine::BootInfo) {
    init::init(boot_info)
}
