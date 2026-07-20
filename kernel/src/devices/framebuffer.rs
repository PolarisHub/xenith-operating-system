//! Linear framebuffer console: 32 bpp, 8x16 cell, software cursor.
//!
//! [`FramebufferConsole`] renders text into a Limine-provided linear
//! framebuffer by drawing each glyph from an 8x16 font one pixel at a time.
//! It supports `\n`, `\r`, `\t`, line wrap, and scrolling by copying pixel
//! rows upward in video memory. The cursor is a steady block drawn in the
//! current foreground colour at the next write position.
//!
//! # Layout
//!
//! The backend is a `static` singleton (`FB_CONSOLE`) initialised in place
//! by [`init_in_place`] before [`static_ref`] hands out the `&'static` borrow
//! that [`console::set_console`] stores. Mutable state (cursor position and
//! colours) lives behind a `spin::Mutex` so the shared reference is enough
//! for the [`Console`](crate::console::Console) impl.
//!
//! # Font
//!
//! Printable ASCII uses Xenith's complete IBM VGA 8x16 bitmap table. Bytes
//! outside the table render as an outlined replacement cell.

use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::console::{Color, Console};
use crate::devices::fb_font::{self, GLYPH_HEIGHT, GLYPH_WIDTH};
use crate::devices::gfx::{Framebuffer as GfxFramebuffer, PixelFormat};
use crate::devices::term::{FramebufferRenderer, Terminal};

// --- Geometry --------------------------------------------------------------

/// Cell dimensions in pixels. The font is 8 pixels wide and 16 tall, so each
/// character occupies an 8x16 block of the framebuffer.
const CHAR_W: usize = GLYPH_WIDTH;
const CHAR_H: usize = GLYPH_HEIGHT;

/// Immutable framebuffer geometry, written once by [`init_in_place`].
///
/// All fields are set before any `&'static` reference escapes, so they are
/// read-only for the lifetime of the console and need no synchronisation.
#[derive(Clone, Copy)]
struct FramebufferGeom {
    /// Base of the pixel buffer, already translated through the HHDM.
    buffer: *mut u8,
    /// Bytes per scanline.
    pitch: usize,
    /// Visible width in pixels.
    width: u16,
    /// Visible height in pixels.
    height: u16,
    /// Native channel layout of each 32-bit scanout pixel.
    format: PixelFormat,
    /// Text columns that fit in `width`.
    cols: usize,
    /// Text rows that fit in `height`.
    rows: usize,
}

/// Mutable per-cursor state, guarded by `state`.
struct FbState {
    col: usize,
    row: usize,
    fg: Color,
    bg: Color,
}

/// 32 bpp linear framebuffer text console.
///
/// Holds the geometry by value and the mutable cursor state behind a lock.
/// The raw buffer pointer makes this `!Send`/`!Sync` by default; the unsafe
/// impls below assert the access discipline (single BSP init, then
/// lock-serialised mutation of state and write-only pixel stores).
pub struct FramebufferConsole {
    geom: FramebufferGeom,
    state: spin::Mutex<FbState>,
    terminal: spin::Mutex<Option<Terminal<FramebufferRenderer>>>,
    splash_active: AtomicBool,
}

/// Borrowed hardware scanout descriptor handed to the userspace display layer.
///
/// The raw pointer is valid for the kernel lifetime, but callers may write it
/// only while [`userspace_suspended`] is true after a successful
/// [`suspend_for_userspace`] call. [`resume_from_userspace`] ends that lease.
#[derive(Clone, Copy)]
pub(crate) struct Scanout {
    pub(crate) buffer: *mut u8,
    pub(crate) pitch: usize,
    pub(crate) width: u16,
    pub(crate) height: u16,
    pub(crate) format: PixelFormat,
}

// SAFETY: the descriptor is only a movable capability. Actual access remains
// governed by the synchronized suspend/resume ownership protocol.
unsafe impl Send for Scanout {}

/// True while the framebuffer terminal has yielded scanout ownership.
static RENDERING_SUSPENDED: AtomicBool = AtomicBool::new(false);

/// A release from exception context cannot safely repaint every terminal
/// cell with interrupts disabled. Console writers complete this redraw before
/// applying an update and retry once after dropping the terminal lock, closing
/// the handoff window where an interrupted writer already made its final check.
static REDRAW_PENDING: AtomicBool = AtomicBool::new(false);

// SAFETY: geometry is initialized once before publication. Every kernel VRAM
// write holds `terminal`, while `state` separately serializes cursor and color
// state. A successful userspace suspension is established while `terminal` is
// held and makes the renderer a no-op until resume reacquires the same lock,
// so the scanout has exactly one active writer under the documented lease.
unsafe impl Send for FramebufferConsole {}
unsafe impl Sync for FramebufferConsole {}

impl FramebufferConsole {
    /// Const constructor for the `static` singleton.
    ///
    /// Produces a console with a null buffer and zero geometry; [`init_in_place`]
    /// fills the real values before the first use. The default colours match
    /// the conventional light-gray-on-black text console.
    const fn uninit() -> Self {
        Self {
            geom: FramebufferGeom {
                buffer: ptr::null_mut(),
                pitch: 0,
                width: 0,
                height: 0,
                format: PixelFormat::XRGB8888,
                cols: 0,
                rows: 0,
            },
            state: spin::Mutex::new(FbState {
                col: 0,
                row: 0,
                fg: Color::LightGray,
                bg: Color::Black,
            }),
            terminal: spin::Mutex::new(None),
            splash_active: AtomicBool::new(false),
        }
    }
}

// The singleton. `static mut` because the geometry is written once in place
// at init; thereafter only shared `&'static` references are handed out and
// all mutation goes through the interior `spin::Mutex`.
static mut FB_CONSOLE: FramebufferConsole = FramebufferConsole::uninit();

/// Initialise the singleton's geometry from the Limine framebuffer.
///
/// # Safety
///
/// Must be called exactly once, on the BSP, before [`static_ref`] returns a
/// reference and before any `Console` method is invoked. The caller guarantees
/// `buffer` points at a writable 32 bpp framebuffer of `width`x`height`
/// pixels with `pitch` bytes per row, mapped writable for the kernel's
/// lifetime.
pub unsafe fn init_in_place(
    buffer: *mut u8,
    pitch: u16,
    width: u16,
    height: u16,
    format: PixelFormat,
    preserve_splash: bool,
) {
    let pitch = pitch as usize;
    let cols = (width as usize) / CHAR_W;
    let rows = (height as usize) / CHAR_H;

    // SAFETY: `FB_CONSOLE` is a `static mut` whose geometry we write exactly
    // once here, on the BSP, before any other code observes it. No reference
    // has escaped yet (the console is not installed until `static_ref` is
    // called, which happens after this returns), so the write is race-free.
    unsafe {
        let g = &raw mut FB_CONSOLE;
        (*g).geom = FramebufferGeom {
            buffer,
            pitch,
            width,
            height,
            format,
            cols,
            rows,
        };
        (*g).splash_active.store(preserve_splash, Ordering::Release);
        RENDERING_SUSPENDED.store(false, Ordering::Release);
        REDRAW_PENDING.store(false, Ordering::Release);
    }

    // Keep the UEFI artwork intact until the first real console write. Other
    // boot paths retain the original clean-screen startup behaviour.
    // SAFETY: `static_ref` only requires that `init_in_place` has run, which
    // is exactly the invariant this function establishes above.
    let console = unsafe { static_ref() };
    if !preserve_splash {
        console.clear();
    }
}

/// Borrow the singleton as a `&'static dyn Console`.
///
/// # Safety
///
/// The caller must have first invoked [`init_in_place`]. After init the
/// reference is valid for the kernel's lifetime.
pub unsafe fn static_ref() -> &'static dyn Console {
    // SAFETY: `init_in_place` has run, so the geometry is populated. We only
    // ever hand out shared references; all mutation is through the interior
    // `spin::Mutex` on `state` or was the one-time geometry write in init.
    unsafe { &*core::ptr::addr_of!(FB_CONSOLE) }
}

/// Replace the allocation-free early console with Xenith's stateful VT100
/// renderer after the kernel heap is online.
///
/// Early boot deliberately uses the inline text grid because console setup
/// precedes memory allocation. The init path calls this once after filesystem
/// setup and before starting userspace, at which point the terminal can own
/// primary and alternate screen buffers and interpret CSI/SGR sequences.
#[must_use]
pub fn upgrade_terminal() -> bool {
    // SAFETY: the console singleton was initialized by `console::init` before
    // memory bring-up. A null/zero geometry below detects the VGA path where
    // no framebuffer console was installed.
    let console = unsafe { &*core::ptr::addr_of!(FB_CONSOLE) };
    let geom = &console.geom;
    if geom.buffer.is_null() || geom.cols == 0 || geom.rows == 0 {
        return false;
    }
    let mut terminal_slot = console.terminal.lock();
    let surface = GfxFramebuffer::with_format(
        geom.buffer,
        geom.pitch,
        geom.width,
        geom.height,
        geom.format,
    );
    let renderer = FramebufferRenderer::new(surface);
    let preserving = console.splash_active.load(Ordering::Acquire);
    let terminal = if preserving {
        Terminal::new_preserving(renderer)
    } else {
        Terminal::new(renderer)
    };
    let Ok(terminal) = terminal else {
        if preserving {
            console.splash_active.store(false, Ordering::Release);
            console.clear_early_surface();
        }
        return false;
    };
    *terminal_slot = Some(terminal);
    true
}

/// Return whether the firmware splash is still the active display surface.
#[must_use]
pub fn splash_active() -> bool {
    // SAFETY: callers reach this only after console initialization. A zeroed
    // pre-init singleton also reports false, so an unusually early query is
    // harmless.
    let console = unsafe { &*core::ptr::addr_of!(FB_CONSOLE) };
    console.splash_active.load(Ordering::Acquire)
}

/// Yield the framebuffer scanout to the userspace display/session layer.
///
/// Taking the terminal lock establishes a clean ownership boundary with every
/// console writer. The stateful terminal remains live and continues updating
/// its cell model, but its renderer becomes a no-op until
/// [`resume_from_userspace`] is called. A second acquisition, the VGA path, or
/// acquisition before the stateful terminal exists returns `None`.
pub(crate) fn suspend_for_userspace() -> Option<Scanout> {
    // SAFETY: the singleton is either initialized or still has null geometry;
    // the latter is rejected below.
    let console = unsafe { &*core::ptr::addr_of!(FB_CONSOLE) };
    let terminal = console.terminal.lock();
    let geom = console.geom;
    if geom.buffer.is_null()
        || geom.cols == 0
        || geom.rows == 0
        || terminal.is_none()
        || RENDERING_SUSPENDED.swap(true, Ordering::AcqRel)
    {
        return None;
    }
    REDRAW_PENDING.store(false, Ordering::Release);
    console.splash_active.store(false, Ordering::Release);
    Some(Scanout {
        buffer: geom.buffer,
        pitch: geom.pitch,
        width: geom.width,
        height: geom.height,
        format: geom.format,
    })
}

/// Return userspace-owned scanout to the framebuffer terminal and repaint it.
pub(crate) fn resume_from_userspace() {
    // SAFETY: see [`suspend_for_userspace`].
    let console = unsafe { &*core::ptr::addr_of!(FB_CONSOLE) };
    if !RENDERING_SUSPENDED.load(Ordering::Acquire) {
        return;
    }
    // Publish pending before making rendering live. A concurrent console
    // writer can then never paint a partial update over the userspace image
    // without first restoring the complete terminal model.
    REDRAW_PENDING.store(true, Ordering::Release);
    if !RENDERING_SUSPENDED.swap(false, Ordering::AcqRel) {
        return;
    }
    if !crate::arch::x86_64::interrupts_enabled() {
        // Never block an exception path behind a terminal writer that may be
        // preempted on this CPU. If uncontended, restore immediately. If a
        // writer owns the lock, its mandatory post-unlock retry completes the
        // redraw; any intervening writer inherits the same obligation.
        console.service_pending_redraw();
        return;
    }
    let mut terminal = console.terminal.lock();
    console.finish_pending_redraw(&mut terminal);
}

/// Whether userspace currently owns the hardware scanout.
#[must_use]
pub(crate) fn userspace_suspended() -> bool {
    RENDERING_SUSPENDED.load(Ordering::Acquire)
}

/// Update the progress indicator painted by the UEFI loader.
///
/// The logical grayscale shades are packed through the scanout's validated
/// native channel layout before being written.
pub fn splash_progress(percent: u8) {
    // SAFETY: `console::init` has populated the singleton before init stages
    // call this function.
    let console = unsafe { &*core::ptr::addr_of!(FB_CONSOLE) };
    let _terminal_guard = console.terminal.lock();
    if !console.splash_active.load(Ordering::Acquire) {
        return;
    }
    let geom = &console.geom;
    if geom.buffer.is_null() || geom.width < 640 || geom.height < 480 {
        return;
    }

    let x = (usize::from(geom.width) - 640) / 2 + 58;
    let y = (usize::from(geom.height) - 480) / 2 + 378;
    let filled = 218 * usize::from(percent.min(100)) / 100;
    fill_rect(geom, x, y, 220, 10, geom.format.pack_rgb(0x9a, 0x9a, 0x9a));
    fill_rect(
        geom,
        x + 1,
        y + 1,
        218,
        8,
        geom.format.pack_rgb(0x1a, 0x1a, 0x1a),
    );
    if filled != 0 {
        fill_rect(
            geom,
            x + 1,
            y + 1,
            filled,
            8,
            geom.format.pack_rgb(0xee, 0xee, 0xee),
        );
    }
}

/// Remove a still-visible splash and expose a clean terminal immediately.
pub fn dismiss_splash() {
    // SAFETY: see [`splash_progress`].
    let console = unsafe { &*core::ptr::addr_of!(FB_CONSOLE) };
    let mut terminal = console.terminal.lock();
    if console.splash_active.swap(false, Ordering::AcqRel) {
        if let Some(active) = terminal.as_mut() {
            active.reset();
        } else {
            console.clear_early_surface();
        }
    }
}

// --- Pixel drawing ---------------------------------------------------------

impl FramebufferConsole {
    /// Clear and home the allocation-free renderer while the terminal lock is
    /// held by the caller and no stateful terminal is installed.
    fn clear_early_surface(&self) {
        let geom = &self.geom;
        if geom.cols == 0 || geom.buffer.is_null() {
            return;
        }
        let bg = self.state.lock().bg;
        let bg_rgb = rgb_of(geom.format, bg);
        for y in 0..usize::from(geom.height) {
            for x in 0..usize::from(geom.width) {
                // SAFETY: bounded by the framebuffer's visible geometry.
                unsafe { Self::put_pixel(geom, x, y, bg_rgb) };
            }
        }
        let mut state = self.state.lock();
        state.col = 0;
        state.row = 0;
        draw_cursor(geom, &state);
    }

    /// Write a 32 bpp pixel at column `x`, row `y` (pixel coordinates).
    ///
    /// # Safety
    ///
    /// Caller ensures `(x, y)` is within the visible geometry and `buffer` is
    /// a valid writable 32 bpp framebuffer base. All callers are inside this
    /// module and pass coordinates derived from the text grid, so this is
    /// always satisfied.
    #[inline]
    unsafe fn put_pixel(geom: &FramebufferGeom, x: usize, y: usize, rgb: u32) {
        let off = y * geom.pitch + x * 4;
        // SAFETY: `off` is within `pitch * height` (callers bound x/y to the
        // visible area), the buffer is 32 bpp and writable, and the store is
        // naturally aligned (pitch and x are such that off is 4-aligned).
        unsafe {
            ptr::write_volatile(geom.buffer.add(off) as *mut u32, rgb);
        }
    }

    /// Fill the cell at text column `col`, row `row` with `rgb`.
    #[inline]
    fn fill_cell(geom: &FramebufferGeom, col: usize, row: usize, rgb: u32) {
        let x0 = col * CHAR_W;
        let y0 = row * CHAR_H;
        // Bounds-check against the visible geometry: cells that fall outside
        // the framebuffer (e.g. a partial last column) are skipped silently
        // rather than writing off the end of video memory.
        if x0 + CHAR_W > geom.width as usize || y0 + CHAR_H > geom.height as usize {
            return;
        }
        for dy in 0..CHAR_H {
            for dx in 0..CHAR_W {
                // SAFETY: bounded above against width/height.
                unsafe { Self::put_pixel(geom, x0 + dx, y0 + dy, rgb) };
            }
        }
    }

    /// Draw `byte`'s glyph at text column `col`, row `row` using `fg`/`bg`.
    fn draw_glyph(geom: &FramebufferGeom, col: usize, row: usize, byte: u8, fg: Color, bg: Color) {
        let x0 = col * CHAR_W;
        let y0 = row * CHAR_H;
        if x0 + CHAR_W > geom.width as usize || y0 + CHAR_H > geom.height as usize {
            return;
        }
        let fg_rgb = rgb_of(geom.format, fg);
        let bg_rgb = rgb_of(geom.format, bg);
        let glyph = fb_font::glyph(byte);
        for (gy, bits) in glyph.into_iter().enumerate() {
            for gx in 0..CHAR_W {
                let on = (bits >> (7 - gx)) & 1 == 1;
                let rgb = if on { fg_rgb } else { bg_rgb };
                // SAFETY: bounded above against width/height.
                unsafe { Self::put_pixel(geom, x0 + gx, y0 + gy, rgb) };
            }
        }
    }

    /// Scroll the text grid up by one row, clearing the last row with `bg`.
    ///
    /// `bg` is the caller's current background colour; passing it in keeps
    /// scroll self-contained instead of re-locking `state` to read it.
    fn scroll_up(geom: &FramebufferGeom, bg: Color) {
        // Copy each pixel row from row y into row y-1. Rows are disjoint
        // `pitch`-sized spans and destination < source, so a forward copy is
        // safe; `ptr::copy` (memmove) is used for robustness regardless of
        // overlap direction.
        let row_bytes = geom.cols * CHAR_W * 4;
        for y in 1..geom.rows {
            let dst = y0_pixel(geom, y - 1);
            let src = y0_pixel(geom, y);
            // SAFETY: both pointers are within the framebuffer for
            // `row_bytes` bytes; dst < src so the forward copy never clobbers
            // source data before it is read. `row_bytes` is `cols*CHAR_W*4`,
            // which is `<= width*4 <= pitch`, so each span stays in-bounds.
            unsafe {
                ptr::copy(src, dst, row_bytes);
            }
        }
        clear_row_pixels(geom, geom.rows - 1, rgb_of(geom.format, bg));
    }
}

fn fill_rect(geom: &FramebufferGeom, x: usize, y: usize, width: usize, height: usize, rgb: u32) {
    let end_x = x.saturating_add(width).min(usize::from(geom.width));
    let end_y = y.saturating_add(height).min(usize::from(geom.height));
    for py in y.min(end_y)..end_y {
        for px in x.min(end_x)..end_x {
            // SAFETY: both coordinates are clipped to the visible geometry.
            unsafe { FramebufferConsole::put_pixel(geom, px, py, rgb) };
        }
    }
}

/// Pixel pointer at the start of text `row`'s first column.
#[inline]
fn y0_pixel(geom: &FramebufferGeom, row: usize) -> *mut u8 {
    let y0 = row * CHAR_H;
    // SAFETY: caller (scroll_up) bounds row against geom.rows; the pointer
    // arithmetic is within the framebuffer.
    unsafe { geom.buffer.add(y0 * geom.pitch) }
}

/// Fill a text row's pixels with a solid `rgb` colour.
fn clear_row_pixels(geom: &FramebufferGeom, row: usize, rgb: u32) {
    let y0 = row * CHAR_H;
    if y0 + CHAR_H > geom.height as usize {
        return;
    }
    for dy in 0..CHAR_H {
        let y = y0 + dy;
        for dx in 0..(geom.cols * CHAR_W) {
            if dx >= geom.width as usize {
                break;
            }
            // SAFETY: bounded against width/height above.
            unsafe { FramebufferConsole::put_pixel(geom, dx, y, rgb) };
        }
    }
}

// --- Console impl ----------------------------------------------------------

impl Console for FramebufferConsole {
    fn write_str(&self, text: &str) {
        {
            let mut terminal = self.terminal.lock();
            self.finish_pending_redraw(&mut terminal);
            if let Some(active) = terminal.as_mut() {
                if self.splash_active.swap(false, Ordering::AcqRel) {
                    active.reset();
                }
                active.write(text.as_bytes());
            } else if !self.splash_active.load(Ordering::Acquire) {
                for character in text.chars() {
                    self.write_char_early(character);
                }
            }
            self.finish_pending_redraw(&mut terminal);
        }
        self.service_pending_redraw();
    }

    fn write_char(&self, ch: char) {
        let byte = if ch.is_ascii() { ch as u8 } else { b'?' };
        {
            let mut terminal = self.terminal.lock();
            self.finish_pending_redraw(&mut terminal);
            if let Some(active) = terminal.as_mut() {
                if self.splash_active.swap(false, Ordering::AcqRel) {
                    active.reset();
                }
                active.write(core::slice::from_ref(&byte));
            } else if !self.splash_active.load(Ordering::Acquire) {
                self.write_char_early(ch);
            }
            self.finish_pending_redraw(&mut terminal);
        }
        self.service_pending_redraw();
    }

    fn clear(&self) {
        {
            let mut terminal = self.terminal.lock();
            self.finish_pending_redraw(&mut terminal);
            if !self.splash_active.load(Ordering::Acquire) {
                if let Some(active) = terminal.as_mut() {
                    active.reset();
                } else {
                    self.clear_early_surface();
                }
            }
            self.finish_pending_redraw(&mut terminal);
        }
        self.service_pending_redraw();
    }

    fn set_color(&self, fg: Color, bg: Color) {
        let mut st = self.state.lock();
        st.fg = fg;
        st.bg = bg;
    }
}

impl FramebufferConsole {
    /// Try to service a deferred redraw without waiting for the terminal lock.
    ///
    /// Every normal console writer invokes this after releasing its guard.
    /// Therefore, if an interrupt-disabled release loses the initial try-lock
    /// race, the current lock owner (or a writer that overtakes it) performs a
    /// guaranteed retry after unlocking.
    fn service_pending_redraw(&self) {
        if !REDRAW_PENDING.load(Ordering::Acquire) {
            return;
        }
        if let Some(mut terminal) = self.terminal.try_lock() {
            self.finish_pending_redraw(&mut terminal);
        }
    }

    /// Complete a deferred full redraw while the caller owns `terminal`.
    fn finish_pending_redraw(&self, terminal: &mut Option<Terminal<FramebufferRenderer>>) {
        if !REDRAW_PENDING.swap(false, Ordering::AcqRel) {
            return;
        }
        if let Some(active) = terminal.as_mut() {
            active.redraw_all();
        } else {
            self.clear_early_surface();
        }
    }

    /// Render one character through the allocation-free path.
    ///
    /// The caller holds `terminal`, which serializes every early VRAM write.
    fn write_char_early(&self, ch: char) {
        let geom = &self.geom;
        // A degenerate (uninitialised) console would have cols == 0; bail out
        // rather than dividing by zero or writing to a null buffer.
        if geom.cols == 0 || geom.buffer.is_null() {
            return;
        }

        // Hold the state lock across the whole write so the cursor position
        // and colours cannot change mid-character (e.g. from another CPU).
        let mut st = self.state.lock();
        match ch {
            '\n' => {
                // Clear the cursor block at the current cell (it sits on the
                // empty next-write position), then advance to the next row.
                let bg = st.bg;
                Self::fill_cell(geom, st.col, st.row, rgb_of(geom.format, bg));
                st.col = 0;
                st.row += 1;
                if st.row >= geom.rows {
                    st.row = geom.rows - 1;
                    let bg = st.bg;
                    Self::scroll_up(geom, bg);
                }
                draw_cursor(geom, &st);
            },
            '\r' => {
                let bg = st.bg;
                Self::fill_cell(geom, st.col, st.row, rgb_of(geom.format, bg));
                st.col = 0;
                draw_cursor(geom, &st);
            },
            '\t' => {
                // Advance to the next 8-column tab stop.
                let bg = st.bg;
                Self::fill_cell(geom, st.col, st.row, rgb_of(geom.format, bg));
                let next = (st.col + 8) & !7;
                st.col = if next >= geom.cols {
                    geom.cols - 1
                } else {
                    next
                };
                draw_cursor(geom, &st);
            },
            c => {
                let byte = if c.is_ascii() { c as u8 } else { b'?' };
                Self::draw_glyph(geom, st.col, st.row, byte, st.fg, st.bg);
                st.col += 1;
                if st.col >= geom.cols {
                    st.col = 0;
                    st.row += 1;
                    if st.row >= geom.rows {
                        st.row = geom.rows - 1;
                        let bg = st.bg;
                        Self::scroll_up(geom, bg);
                    }
                }
                draw_cursor(geom, &st);
            },
        }
    }
}

/// Pack a logical console colour into the scanout's native channel layout.
#[inline]
fn rgb_of(format: PixelFormat, c: Color) -> u32 {
    let (r, g, b) = c.rgb();
    format.pack_rgb(r, g, b)
}

/// Draw the steady block cursor at the current position in the foreground
/// colour. The cell under the cursor is the next write position, so it is
/// empty (background) and the block does not hide any typed character.
fn draw_cursor(geom: &FramebufferGeom, st: &FbState) {
    let fg_rgb = rgb_of(geom.format, st.fg);
    FramebufferConsole::fill_cell(geom, st.col, st.row, fg_rgb);
}
