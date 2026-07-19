//! Concrete `log::Log` implementation for the kernel.
//!
//! [`KernelLogger`] is installed once by [`super::init`] as the process-wide
//! backend for the `log` facade. Every `::log::info!` / `::log::error!` /
//! ... call in the kernel ends up here. The logger formats each record as
//!
//! ```text
//! [<colored LEVEL> <target>: <message>]
//! ```
//!
//! and fans the bytes out to two sinks:
//!
//! * the 16550-compatible UART at COM1 (`0x3F8`), always; and
//! * an optional framebuffer console registered later by the `console`
//!   subsystem via [`register_console`].
//!
//! The UART writer here is deliberately small and permanently independent of
//! higher-level device registration: its polled COM1 path remains available
//! during early boot, interrupts-disabled sections, and panic handling. The
//! public sink trait adds the framebuffer console without replacing that
//! emergency serial path.
//!
//! Disambiguation: this crate declares `pub mod log`, so the external `log`
//! crate is reached through the `log_facade` alias (`use ::log as
//! log_facade`). The leading `::` forces resolution through the extern-crate
//! prelude instead of the local module of the same name.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU8, Ordering};

use ::log as log_facade;
use log_facade::{Level, LevelFilter, Log, Metadata, Record};
use spin::Mutex;

// --- Public sink trait -----------------------------------------------------

/// Optional text sink for the framebuffer console.
///
/// The `console` subsystem implements this and calls [`register_console`]
/// once its framebuffer writer is up, so log lines are mirrored to the screen
/// in addition to the serial port. Until then the logger writes to serial
/// only, which is enough for early bring-up.
///
/// Implementations must be safe to call from any context, including interrupt
/// handlers and the panic path: the logger holds the writer lock while it
/// dispatches to [`ConsoleSink::write_str`], so a blocking or slow sink will
/// stall every other core trying to log. Keep it bounded.
pub trait ConsoleSink: Send + Sync {
    /// Append a raw byte slice to the console output.
    fn write_str(&self, s: &str);

    /// Append formatted output. The default builds on [`write_str`] so
    /// implementors only need to override the byte path. The `Self: Sized`
    /// bound keeps the trait object-safe: the method is excluded from the
    /// vtable for `dyn ConsoleSink`, which is fine because the logger only
    /// ever calls [`write_str`] and [`flush`] through the trait object.
    fn write_fmt(&self, args: fmt::Arguments<'_>)
    where
        Self: Sized,
    {
        let mut adapter = SinkFmtAdapter(self);
        let _ = fmt::write(&mut adapter, args);
    }

    /// Flush any buffered output. The default is a no-op; framebuffer drivers
    /// that batch updates can implement this to push the cursor.
    fn flush(&self) {}
}

impl<'a> fmt::Write for SinkFmtAdapter<'a> {
    #[inline]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        (self.0).write_str(s);
        Ok(())
    }
}

/// `fmt::Write` glue that forwards to a [`ConsoleSink`]. Used only by the
/// default `ConsoleSink::write_fmt` implementation above.
struct SinkFmtAdapter<'a>(&'a dyn ConsoleSink);

// --- Serial port (16550 UART) ----------------------------------------------

/// Base I/O port of the first 16550-compatible serial port (COM1).
const COM1: u16 = 0x3F8;

/// A minimal 16550 UART writer.
///
/// Kept as the logger's independent polled sink even after device
/// initialization. The port is configured for 115200 baud, 8 data bits, no
/// parity, one stop bit (8N1) with the FIFO enabled.
#[derive(Clone, Copy)]
struct SerialPort {
    base: u16,
}

impl SerialPort {
    const fn new(base: u16) -> Self {
        SerialPort { base }
    }

    /// Program the UART for 115200 8N1 with the FIFO on. Idempotent.
    fn init(&mut self) {
        let b = self.base;
        // SAFETY: each `outb` writes a single byte to a fixed I/O port. Port
        // I/O has no memory-safety implications; the only effect is device
        // configuration. The ordering is preserved because `outb` is not
        // marked `nomem`, so the compiler treats each call as a side effect
        // that cannot be reordered relative to the others.
        outb(b + 1, 0x00); // disable interrupts
        outb(b + 3, 0x80); // enable DLAB to set the baud divisor
        outb(b, 0x01); // divisor low byte: 1 -> 115200 baud
        outb(b + 1, 0x00); // divisor high byte
        outb(b + 3, 0x03); // 8 bits, no parity, one stop; clear DLAB
        outb(b + 2, 0xC7); // enable FIFO, clear it, 14-byte threshold
        outb(b + 4, 0x0B); // drive RTS/DSR, enable OUT2
    }

    /// Block until the transmit holding register is empty, then write one byte.
    fn write_byte(&mut self, byte: u8) {
        let b = self.base;
        // SAFETY: `inb` reads the line status register; `outb` writes the
        // data byte to the transmit holding register. Neither accesses
        // memory, and the spin loop only waits for a device status bit.
        while inb(b + 5) & 0x20 == 0 {
            core::hint::spin_loop();
        }
        outb(b, byte);
    }

    /// Write a string, translating bare `\n` into `\r\n` so a raw serial
    /// terminal moves to the start of the next line.
    fn write_str(&mut self, s: &str) {
        for &byte in s.as_bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }
}

/// Write `val` to the 8-bit I/O port `port`.
///
/// Safe wrapper: port I/O cannot cause memory unsafety; the only effect is
/// external device state.
#[inline]
fn outb(port: u16, val: u8) {
    // SAFETY: `out dx, al` writes AL to the I/O port named by DX. It touches
    // no general-purpose memory and no stack; flags are unchanged. The
    // `preserves_flags` option reflects that. `nomem` is intentionally
    // omitted so the call is an ordered side effect the compiler cannot
    // reorder across other I/O or memory accesses.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nostack, preserves_flags),
        );
    }
}

/// Read one byte from the 8-bit I/O port `port`.
///
/// Safe wrapper: port I/O cannot cause memory unsafety.
#[inline]
fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: `in al, dx` reads one byte from the I/O port named by DX into
    // AL. No memory or stack access; flags are unchanged.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") val,
            in("dx") port,
            options(nostack, preserves_flags),
        );
    }
    val
}

// --- Colour helpers --------------------------------------------------------

/// ANSI escape that colours the level tag on a serial terminal. The
/// framebuffer console ignores these unless its renderer strips them.
fn level_colour(level: Level) -> &'static str {
    match level {
        Level::Error => "\x1b[1;31m", // bold red
        Level::Warn => "\x1b[1;33m",  // bold yellow
        Level::Info => "\x1b[1;36m",  // bold cyan
        Level::Debug => "\x1b[1;34m", // bold blue
        Level::Trace => "\x1b[0;90m", // bright black / grey
    }
}

/// ANSI reset, written after the closing bracket to leave the terminal clean.
const COLOUR_RESET: &str = "\x1b[0m";

// --- Writer and logger -----------------------------------------------------

/// Mutable output state guarded by the logger's spin lock.
struct Writer {
    serial: SerialPort,
    /// Lazily set on first use so log calls work even if `init` has not run
    /// yet (e.g. an early `log::error!` before `log::init`).
    serial_ready: bool,
    /// Optional framebuffer console, plugged in by `register_console`.
    console: Option<&'static dyn ConsoleSink>,
}

/// The kernel's `log::Log` backend.
///
/// One static instance, [`KERNEL_LOGGER`], is installed by [`super::init`].
/// The max level is kept in an `AtomicU8` so it can be changed at runtime
/// without taking the writer lock; the writer itself is serialised by a
/// `spin::Mutex` so interleaved multi-core output stays line-coherent.
pub struct KernelLogger {
    /// `LevelFilter` discriminant (Off=0 .. Trace=5), read by `enabled`.
    max_level: AtomicU8,
    /// Guards the serial port and the optional console reference.
    writer: Mutex<Writer>,
}

impl KernelLogger {
    /// Construct an idle logger: serial uninitialised, no console, level Off.
    const fn new() -> Self {
        KernelLogger {
            max_level: AtomicU8::new(LevelFilter::Off as u8),
            writer: Mutex::new(Writer {
                serial: SerialPort::new(COM1),
                serial_ready: false,
                console: None,
            }),
        }
    }

    /// Update the runtime level filter. Applies to subsequent records.
    pub fn set_max_level(&self, level: LevelFilter) {
        self.max_level.store(level as u8, Ordering::Release);
    }
}

impl Log for KernelLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // Acquire pairs with the Release store in `set_max_level`; a torn
        // read is impossible on x86_64 (naturally aligned u8 load is atomic)
        // but the ordering keeps the intent honest across architectures.
        let max = self.max_level.load(Ordering::Acquire);
        // `Level` discriminants run 1..=5; `LevelFilter::Off` is 0, so the
        // comparison filters everything when the filter is Off.
        metadata.level() as u8 <= max
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let level = record.level();
        let colour = level_colour(level);
        let level_str = level.as_str();
        let target = record.target();

        // Hold the writer lock for the whole line so two cores logging
        // concurrently cannot interleave their bytes mid-record.
        let mut w = self.writer.lock();
        if !w.serial_ready {
            w.serial.init();
            w.serial_ready = true;
        }

        // Copy the console reference out before mutably borrowing `serial`:
        // both fields are reached through `DerefMut` on the guard, so taking
        // `&mut w.serial` while still holding a shared borrow of `w.console`
        // would conflict. The copy ends the shared borrow first.
        let console = w.console;
        let mut fan = Fanout {
            serial: &mut w.serial,
            console,
        };
        // `<5` left-justifies the level tag to a fixed width so the colons
        // line up across ERROR/WARN/INFO/DEBUG/TRACE.
        let _ = write!(fan, "{colour}[{level_str:<5} {target}: ");
        let _ = fan.write_fmt(*record.args());
        // `COLOUR_RESET` is a `const`, so it is passed positionally rather than
        // relying on named capture in the format string.
        let _ = writeln!(fan, "]{}", COLOUR_RESET);
    }

    fn flush(&self) {
        // The serial path is unbuffered (each byte waits for the holding
        // register), so only the optional console might need flushing.
        let w = self.writer.lock();
        if let Some(console) = w.console {
            console.flush();
        }
    }
}

/// `fmt::Write` adapter that copies every chunk to both the serial port and
/// the optional framebuffer console. Lives only for the duration of one
/// `log` call, under the writer lock.
struct Fanout<'a> {
    serial: &'a mut SerialPort,
    console: Option<&'static dyn ConsoleSink>,
}

impl fmt::Write for Fanout<'_> {
    #[inline]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.serial.write_str(s);
        if let Some(console) = self.console {
            console.write_str(s);
        }
        Ok(())
    }
}

// --- Static instance and free functions ------------------------------------

/// The single kernel logger instance, installed by [`super::init`].
pub static KERNEL_LOGGER: KernelLogger = KernelLogger::new();

/// Register a framebuffer console sink.
///
/// Called by the `console` subsystem once its framebuffer writer is ready.
/// After this call every log record is mirrored to the screen in addition to
/// the serial port.
pub fn register_console(sink: &'static dyn ConsoleSink) {
    let mut w = KERNEL_LOGGER.writer.lock();
    w.console = Some(sink);
}

/// Write a raw string to every sink, bypassing the level filter and the
/// `log` facade.
///
/// Used by paths that need unconditional output (e.g. an emergency banner
/// before the facade is wired). Takes the writer lock, so it must not be
/// called from a context that already holds it — the panic handler uses its
/// own lock-free emergency writer instead, precisely to avoid that.
pub fn write_str_raw(s: &str) {
    let mut w = KERNEL_LOGGER.writer.lock();
    if !w.serial_ready {
        w.serial.init();
        w.serial_ready = true;
    }
    w.serial.write_str(s);
    if let Some(console) = w.console {
        console.write_str(s);
    }
}
