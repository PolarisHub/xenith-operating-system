//! Kernel console abstraction and global printk sink.
//!
//! [`Console`] is the trait every text output backend implements. The kernel
//! keeps a single global console in [`CONSOLE`]; [`write_str`] and friends
//! route to whatever backend was installed by [`init`]. The `log` module's
//! backend and the panic handler both sink through here, so every byte of
//! kernel output funnels through one typed surface.
//!
//! # Backends
//!
//! [`devices::framebuffer::FramebufferConsole`] drives a 32 bpp Limine
//! linear framebuffer with an 8x16 font; [`devices::vga::VgaTextConsole`]
//! drives the legacy 0xB8000 VGA text plane. [`init`] picks the framebuffer
//! when the bootloader reported one and falls back to VGA otherwise.
//!
//! # Why `&'static dyn Console`, not `Box<dyn Console>`
//!
//! The console is the *first* subsystem brought up — before the page
//! allocator and the heap exist (see [`init`](crate::init)). A `Box`
//! allocation is therefore impossible at install time, so the global holds a
//! `&'static dyn Console` borrowed from a statically-allocated backend
//! singleton instead. Each backend lives in a `static` and is initialised in
//! place by [`init`] before its reference is handed to [`set_console`]; the
//! backends use interior mutability (`spin::Mutex` for cursor/state) so the
//! shared `&'static` reference is all the trait ever needs.
//!
//! The `spin::Mutex` is used directly (rather than [`crate::sync::SpinLock`])
//! to match the sibling `devices::serial` driver and stay self-contained
//! until the `sync` module re-exports its own wrapper; the swap is a
//! one-line type change here.

use core::fmt;

use crate::devices::{framebuffer, vga};

// ---------------------------------------------------------------------------
// Color
// ---------------------------------------------------------------------------

/// A console colour drawn from the classic 16-entry VGA palette.
///
/// The same enum feeds both backends: [`Color::rgb`] yields the 8-8-8 triple
/// the framebuffer writes into a 32 bpp pixel, and [`Color::vga`] yields the
/// 4-bit attribute nibble the VGA text plane packs beside each character
/// code. Keeping one type means callers (and the `log` level colours) name a
/// colour once and let each backend translate it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Color {
    /// VGA 0.
    Black = 0,
    /// VGA 1.
    Blue = 1,
    /// VGA 2.
    Green = 2,
    /// VGA 3.
    Cyan = 3,
    /// VGA 4.
    Red = 4,
    /// VGA 5.
    Magenta = 5,
    /// VGA 6.
    Brown = 6,
    /// VGA 7.
    LightGray = 7,
    /// VGA 8.
    DarkGray = 8,
    /// VGA 9.
    LightBlue = 9,
    /// VGA 10.
    LightGreen = 10,
    /// VGA 11.
    LightCyan = 11,
    /// VGA 12.
    LightRed = 12,
    /// VGA 13.
    LightMagenta = 13,
    /// VGA 14.
    Yellow = 14,
    /// VGA 15.
    White = 15,
}

impl Color {
    /// Returns the 8-8-8 RGB triple used to fill a 32 bpp framebuffer pixel.
    ///
    /// The values are the standard VGA palette in 0-255 sRGB space (the
    /// "170/85/255" IBM encoding), so on-screen colours match what a VGA
    /// text mode would show for the same attribute nibble.
    #[must_use]
    pub const fn rgb(self) -> (u8, u8, u8) {
        match self {
            Self::Black => (0, 0, 0),
            Self::Blue => (0, 0, 170),
            Self::Green => (0, 170, 0),
            Self::Cyan => (0, 170, 170),
            Self::Red => (170, 0, 0),
            Self::Magenta => (170, 0, 170),
            Self::Brown => (170, 85, 0),
            Self::LightGray => (170, 170, 170),
            Self::DarkGray => (85, 85, 85),
            Self::LightBlue => (85, 85, 255),
            Self::LightGreen => (85, 255, 85),
            Self::LightCyan => (85, 255, 255),
            Self::LightRed => (255, 85, 85),
            Self::LightMagenta => (255, 85, 255),
            Self::Yellow => (255, 255, 85),
            Self::White => (255, 255, 255),
        }
    }

    /// Returns the 4-bit VGA attribute nibble for this colour (0..=15).
    ///
    /// Because [`Color`] is `#[repr(u8)]` and the discriminants are assigned
    /// in VGA order, the nibble is just the discriminant value.
    #[must_use]
    pub const fn vga(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Console trait
// ---------------------------------------------------------------------------

/// A text output backend.
///
/// All methods take `&self`: backends own their mutable state behind a lock
/// so a single `&'static dyn Console` can be shared kernel-wide without
/// needing an exclusive borrow at the call site. [`write_str`] has a default
/// that forwards to [`write_char`] character by character, so backends only
/// have to implement the per-character path.
///
/// Implementations must be `Send + Sync` so a `&'static dyn Console` can be
/// stored in the global [`CONSOLE`] (which is itself `Sync`).
pub trait Console: Send + Sync {
    /// Write a single character, honouring `\n`, `\r`, and `\t`.
    fn write_char(&self, ch: char);

    /// Write a string. The default iterates [`write_char`]; backends may
    /// override this with a faster bulk path.
    fn write_str(&self, s: &str) {
        for ch in s.chars() {
            self.write_char(ch);
        }
    }

    /// Clear the entire screen and home the cursor.
    fn clear(&self);

    /// Set the foreground and background colours for subsequent output.
    fn set_color(&self, fg: Color, bg: Color);
}

// ---------------------------------------------------------------------------
// Global console slot
// ---------------------------------------------------------------------------

/// The active kernel console.
///
/// `None` until [`init`] installs a backend. All of [`write_str`],
/// [`write_char`], [`clear`], and [`set_color`] silently no-op while it is
/// `None`, so early code that runs before the console exists (and code on a
/// machine with no usable output device) can call them without faulting.
static CONSOLE: spin::Mutex<Option<&'static dyn Console>> = spin::Mutex::new(None);

/// Install `console` as the active kernel console, replacing any prior one.
///
/// Takes a `&'static` reference so the backend can live in a `static`
/// singleton without needing the heap (see the [module docs](self)).
pub fn set_console(console: &'static dyn Console) {
    *CONSOLE.lock() = Some(console);
}

/// Write `s` to the active console, if any.
pub fn write_str(s: &str) {
    if let Some(c) = *CONSOLE.lock() {
        c.write_str(s);
    }
}

/// Write a single character to the active console, if any.
pub fn write_char(ch: char) {
    if let Some(c) = *CONSOLE.lock() {
        c.write_char(ch);
    }
}

/// Clear the active console, if any.
pub fn clear() {
    if let Some(c) = *CONSOLE.lock() {
        c.clear();
    }
}

/// Set the active console's colours, if any.
pub fn set_color(fg: Color, bg: Color) {
    if let Some(c) = *CONSOLE.lock() {
        c.set_color(fg, bg);
    }
}

// ---------------------------------------------------------------------------
// printk-style formatting
// ---------------------------------------------------------------------------

/// [`fmt::Write`] adapter that funnels formatted output through [`write_str`].
///
/// Used by the [`kprint!`]/[`kprintln!`] macros and by the `log` backend so
/// `core::fmt` formatting reaches the screen with no allocation. It holds no
/// state of its own — every `write_str` call locks the global console, so
/// output is line-wise atomic with respect to other `kprint!` callers only
/// when a single `write_fmt` invocation emits one `write_str`; for true
/// atomicity across multiple `write_str` calls, callers should build one
/// `format_args!` and emit it in a single `write_fmt`.
pub struct KernelWriter;

impl fmt::Write for KernelWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        crate::console::write_str(s);
        Ok(())
    }
}

/// Print formatted text to the kernel console with no trailing newline.
///
/// Backs onto [`KernelWriter`] / [`write_str`], so it needs no allocator and
/// is safe to call from the panic handler and any ring-0 context where the
/// console is installed.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = $crate::console::KernelWriter.write_fmt(format_args!($($arg)*));
    }};
}

/// Print formatted text to the kernel console followed by a newline.
#[macro_export]
macro_rules! kprintln {
    () => { $crate::kprint!("\n") };
    ($($arg:tt)*) => { $crate::kprint!("{}\n", format_args!($($arg)*)) };
}

// ---------------------------------------------------------------------------
// Bring-up
// ---------------------------------------------------------------------------

/// Console bring-up.
///
/// Runs before every other subsystem so the rest of boot can report progress.
/// Selects the framebuffer backend when Limine handed us a 32 bpp linear
/// framebuffer, otherwise falls back to the VGA text plane at 0xB8000
/// (reached through the higher-half direct map). After a backend is installed
/// it is announced on itself, which is the first real output of boot.
pub fn init(boot_info: &'static limine::BootInfo) {
    let bi = xenith_boot::BootInfo::new(boot_info);

    if try_framebuffer(&bi) {
        kprintln!("xenith: framebuffer console ready");
        return;
    }

    if try_vga(&bi) {
        kprintln!("xenith: vga text console ready");
    }

    // Neither backend was available. There is nothing to print to, so we do
    // not panic — the serial console (brought up later by `devices::init`)
    // may still carry output, and headless boots are legitimate.
}

/// Initialise the framebuffer backend from the first Limine framebuffer.
///
/// Returns `true` on success (a 32 bpp framebuffer was found, initialised,
/// and installed), `false` if there is no framebuffer or it is not 32 bpp.
fn try_framebuffer(bi: &xenith_boot::BootInfo) -> bool {
    let Some(fb) = bi.framebuffer() else {
        return false;
    };
    if fb.bpp != 32 {
        return false;
    }
    let vaddr = bi.phys_to_virt(fb.phys_addr);
    // SAFETY: `FramebufferConsole::init_in_place` writes the geometry fields
    // of a `static mut` singleton. This runs on the BSP before any other CPU
    // or interrupt handler can observe it, so the write is race-free.
    unsafe {
        framebuffer::init_in_place(vaddr.as_u64() as *mut u8, fb.pitch, fb.width, fb.height);
        set_console(framebuffer::static_ref());
    }
    true
}

/// Initialise the VGA text backend, mapping 0xB8000 through the HHDM.
///
/// Returns `true` on success. VGA text mode is a fixed PC platform device, so
/// this only fails if the HHDM offset is somehow absent — in which case the
/// framebuffer path was already tried and failed too, and boot continues
/// with no console.
fn try_vga(bi: &xenith_boot::BootInfo) -> bool {
    // 0xB8000 is the legacy VGA colour text buffer; mono is 0xB0000. Every
    // PC Limine boots has the colour buffer, and the HHDM direct map covers
    // it, so phys_to_virt never fails here.
    let phys = xenith_types::PhysAddr::new_truncate(0xB8000);
    let vaddr = bi.phys_to_virt(phys);
    // SAFETY: same single-threaded-BSP rationale as `try_framebuffer`: the
    // VGA singleton's geometry is written once before any reference escapes.
    unsafe {
        vga::init_in_place(vaddr.as_u64() as *mut u16);
        set_console(vga::static_ref());
    }
    true
}
