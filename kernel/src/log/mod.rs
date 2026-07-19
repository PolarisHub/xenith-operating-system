//! Logging backend for the `log` facade.
//!
//! This module owns the kernel's `log::Log` implementation. The facade
//! macros (`::log::info!`, `::log::warn!`, ...) are the public interface used
//! across every subsystem; [`init`] installs the backend and sets the maximum
//! level, and [`logger::register_console`] later plugs in the framebuffer
//! console once the `console` subsystem is up.
//!
//! Note: because this crate also declares `pub mod log`, the external `log`
//! crate is reached via the leading-`::` path (`::log::info!`). Inside this
//! module the `logger` submodule aliases the external crate to `log_facade`
//! for the same reason.
//!
//! Submodules:
//! * [`logger`] — the [`KernelLogger`](`logger::KernelLogger`) type, the
//!   static instance, the serial + console sink plumbing, and the optional
//!   [`ConsoleSink`](`logger::ConsoleSink`) trait.

pub mod logger;

use ::log as log_facade;
use log_facade::LevelFilter;
pub use logger::{register_console, write_str_raw, ConsoleSink, KernelLogger, KERNEL_LOGGER};

/// Install the kernel logger and set the maximum log level.
///
/// Call exactly once during bring-up, after the early console is usable and
/// before any subsystem that relies on `log::` output. Records at or below
/// `level` are emitted to the serial port (and to the framebuffer console
/// once [`register_console`] has been called); finer records are dropped.
///
/// The facade's global filter and the logger's own `AtomicU8` filter are both
/// set so that `log_enabled!` short-circuits cheaply and the backend agrees.
pub fn init(level: LevelFilter) {
    // `set_logger` fails only if called twice; bring-up calls us once, so the
    // error is ignored. If it ever does fire, the existing logger stays in
    // place and the new level still takes effect below.
    let _ = log_facade::set_logger(&KERNEL_LOGGER);
    log_facade::set_max_level(level);
    KERNEL_LOGGER.set_max_level(level);
}
