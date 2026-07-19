//! VGA colour text console over the 0xB8000 plane.
//!
//! [`VgaTextConsole`] drives the legacy PC VGA text buffer: 80x25 cells of
//! two bytes each (character code + attribute nibbles). It handles `\n`,
//! `\r`, `\t`, line wrap, scrolling by `memcpy`-ing rows upward, and a
//! hardware cursor driven through the 6845 CRTC index/data ports at
//! 0x3D4/0x3D5.
//!
//! # Singletons and access
//!
//! Like the framebuffer backend, the console is a `static` singleton
//! (`VGA_CONSOLE`) initialised in place by [`init_in_place`] before
//! [`static_ref`] hands out the `&'static` borrow. Mutable cursor state is
//! behind a `spin::Mutex`; the 0xB8000 buffer is reached through the HHDM
//! direct map, so the raw pointer is just a `*mut u16` into the direct map.
//!
//! # Port I/O
//!
//! The CRTC ports are reached with a private [`outb`] helper that wraps
//! `out dx, al`. It moves to `crate::arch::Port8` once the `port` submodule
//! lands; the inline asm is identical to the one in `devices::serial` and is
//! duplicated only to keep this driver self-contained during bring-up.

use core::arch::asm;
use core::ptr;

use crate::console::{Color, Console};

// --- CRTC port I/O ---------------------------------------------------------

/// VGA CRTC index register (selects the register the next 0x3D5 access hits).
const CRTC_INDEX: u16 = 0x3D4;
/// VGA CRTC data register (read/writes the selected register).
const CRTC_DATA: u16 = 0x3D5;

/// CRTC cursor start register index. Bit 5 disables the cursor.
const CURSOR_START: u8 = 0x0A;
/// CRTC cursor end register index.
const CURSOR_END: u8 = 0x0B;
/// CRTC cursor location high byte register index.
const CURSOR_LOC_HIGH: u8 = 0x0E;
/// CRTC cursor location low byte register index.
const CURSOR_LOC_LOW: u8 = 0x0F;

/// Write one byte to an I/O port.
///
/// SAFETY: the caller must ensure `port` selects a device I/O port the
/// kernel may write. The CRTC ports 0x3D4/0x3D5 satisfy this by construction.
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: `out dx, al` writes al to the port in dx, performs no memory
    // access, and does not touch EFLAGS, so `nomem`, `preserves_flags`, and
    // `nostack` are correct.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// --- Geometry --------------------------------------------------------------

/// 80x25 VGA colour text mode.
const COLS: usize = 80;
const ROWS: usize = 25;

/// Mutable cursor/colour state, guarded by `state`.
struct VgaState {
    col: usize,
    row: usize,
    fg: Color,
    bg: Color,
}

/// VGA colour text console over the 0xB8000 plane.
///
/// `buffer` is the HHDM-translated base of the 0xB8000 plane as `*mut u16`
/// (one `u16` per cell: low byte = character, high byte = attribute). The
/// raw pointer makes this `!Send`/`!Sync` by default; the unsafe impls
/// assert the same access discipline as the framebuffer backend.
pub struct VgaTextConsole {
    buffer: *mut u16,
    state: spin::Mutex<VgaState>,
}

// SAFETY: `buffer` is the VGA text plane, mapped writable for the kernel's
// lifetime and only ever written under `state`'s lock. The geometry is fixed
// (80x25) and the pointer is set once by `init_in_place` before any
// reference escapes, so shared access after init is sound.
unsafe impl Send for VgaTextConsole {}
unsafe impl Sync for VgaTextConsole {}

impl VgaTextConsole {
    /// Const constructor for the `static` singleton.
    const fn uninit() -> Self {
        Self {
            buffer: ptr::null_mut(),
            state: spin::Mutex::new(VgaState {
                col: 0,
                row: 0,
                fg: Color::LightGray,
                bg: Color::Black,
            }),
        }
    }
}

// The singleton, initialised in place by `init_in_place`.
static mut VGA_CONSOLE: VgaTextConsole = VgaTextConsole::uninit();

/// Initialise the singleton with the HHDM-translated 0xB8000 base.
///
/// # Safety
///
/// Must be called exactly once, on the BSP, before [`static_ref`] returns a
/// reference. `buffer` must point at a writable `u16` array of at least
/// `COLS * ROWS` cells, valid for the kernel's lifetime.
pub unsafe fn init_in_place(buffer: *mut u16) {
    // SAFETY: one-time BSP write to the singleton's buffer field before any
    // reference escapes; no other CPU or handler can observe it yet.
    unsafe {
        let g = &raw mut VGA_CONSOLE;
        (*g).buffer = buffer;
    }
    // SAFETY: `static_ref` only requires that `init_in_place` has run, which
    // the write above just established.
    let console = unsafe { static_ref() };
    console.clear();
    enable_cursor();
}

/// Borrow the singleton as a `&'static dyn Console`.
///
/// # Safety
///
/// The caller must have first invoked [`init_in_place`].
pub unsafe fn static_ref() -> &'static dyn Console {
    // SAFETY: `init_in_place` has run; only shared references are handed out
    // and all mutation is through the interior `spin::Mutex` on `state`.
    unsafe { &*core::ptr::addr_of!(VGA_CONSOLE) }
}

// --- Cell helpers ----------------------------------------------------------

impl VgaTextConsole {
    /// Build a VGA attribute byte from foreground and background colours.
    #[inline]
    fn attr(fg: Color, bg: Color) -> u8 {
        (bg.vga() & 0x0F) << 4 | (fg.vga() & 0x0F)
    }

    /// Write a cell (character + attribute) at text column `col`, row `row`.
    ///
    /// # Safety
    ///
    /// Caller ensures `buffer` is valid and `(col, row)` is within `COLS` x
    /// `ROWS`. All callers in this module satisfy that.
    #[inline]
    unsafe fn write_cell(buffer: *mut u16, col: usize, row: usize, ch: u8, attr: u8) {
        let idx = row * COLS + col;
        // SAFETY: `idx` is within the 80x25 plane (callers bound col/row),
        // and the store is naturally aligned (u16 at an even byte offset).
        unsafe {
            ptr::write_volatile(buffer.add(idx), u16::from(ch) | (u16::from(attr) << 8));
        }
    }

    /// Clear a text row by filling it with spaces in the given colours.
    fn clear_row(buffer: *mut u16, row: usize, fg: Color, bg: Color) {
        let attr = Self::attr(fg, bg);
        for col in 0..COLS {
            // SAFETY: col < COLS, row < ROWS (callers bound row).
            unsafe { Self::write_cell(buffer, col, row, b' ', attr) };
        }
    }

    /// Scroll the text grid up by one row, clearing the last row.
    fn scroll_up(buffer: *mut u16, fg: Color, bg: Color) {
        // Copy row 1..ROWS into row 0..ROWS-1. Rows are disjoint `COLS`-cell
        // spans; a forward copy is safe because destination < source.
        for row in 1..ROWS {
            // SAFETY: row is 1..ROWS and each computed cell offset remains
            // within the 80x25 text plane.
            let dst = unsafe { buffer.add((row - 1) * COLS) };
            let src = unsafe { buffer.add(row * COLS) };
            // SAFETY: both pointers are within the plane for `COLS` u16s and
            // dst < src, so the forward copy is race-free.
            unsafe {
                ptr::copy(src, dst, COLS);
            }
        }
        Self::clear_row(buffer, ROWS - 1, fg, bg);
    }

    /// Update the hardware cursor to the given linear cell index.
    fn set_cursor_hw(idx: usize) {
        let idx = idx as u16;
        // SAFETY: writing the CRTC index then data register is the standard
        // 6845 programming sequence; the ports are fixed PC platform I/O.
        unsafe {
            outb(CRTC_INDEX, CURSOR_LOC_HIGH);
            outb(CRTC_DATA, (idx >> 8) as u8);
            outb(CRTC_INDEX, CURSOR_LOC_LOW);
            outb(CRTC_DATA, idx as u8);
        }
    }
}

/// Enable the hardware cursor with a default underline shape.
///
/// Writes the cursor start (0x0A) and end (0x0B) registers to an underline
/// scanline range. The cursor start register's bit 5 clears the "cursor
/// disable" flag, so this also turns the cursor on after a mode set.
fn enable_cursor() {
    // SAFETY: fixed CRTC port writes; see `set_cursor_hw`.
    unsafe {
        // Cursor start = scanline 13, cursor end = scanline 14: a thin
        // underline near the bottom of the 16-scanline cell.
        outb(CRTC_INDEX, CURSOR_START);
        outb(CRTC_DATA, 13);
        outb(CRTC_INDEX, CURSOR_END);
        outb(CRTC_DATA, 14);
    }
}

// --- Console impl ----------------------------------------------------------

impl Console for VgaTextConsole {
    fn write_char(&self, ch: char) {
        let buffer = self.buffer;
        if buffer.is_null() {
            return;
        }
        let mut st = self.state.lock();
        let attr = Self::attr(st.fg, st.bg);
        match ch {
            '\n' => {
                st.col = 0;
                st.row += 1;
                if st.row >= ROWS {
                    st.row = ROWS - 1;
                    let (fg, bg) = (st.fg, st.bg);
                    drop(st);
                    Self::scroll_up(buffer, fg, bg);
                    st = self.state.lock();
                }
                Self::set_cursor_hw(st.row * COLS + st.col);
            },
            '\r' => {
                st.col = 0;
                Self::set_cursor_hw(st.row * COLS + st.col);
            },
            '\t' => {
                let next = (st.col + 8) & !7;
                st.col = if next >= COLS { COLS - 1 } else { next };
                Self::set_cursor_hw(st.row * COLS + st.col);
            },
            c => {
                let byte = if c.is_ascii() { c as u8 } else { b'?' };
                // SAFETY: st.col < COLS and st.row < ROWS (clamped above),
                // and buffer is the valid 80x25 plane.
                unsafe { Self::write_cell(buffer, st.col, st.row, byte, attr) };
                st.col += 1;
                if st.col >= COLS {
                    st.col = 0;
                    st.row += 1;
                    if st.row >= ROWS {
                        st.row = ROWS - 1;
                        let (fg, bg) = (st.fg, st.bg);
                        drop(st);
                        Self::scroll_up(buffer, fg, bg);
                        st = self.state.lock();
                    }
                }
                Self::set_cursor_hw(st.row * COLS + st.col);
            },
        }
    }

    fn clear(&self) {
        let buffer = self.buffer;
        if buffer.is_null() {
            return;
        }
        let (fg, bg) = {
            let st = self.state.lock();
            (st.fg, st.bg)
        };
        for row in 0..ROWS {
            Self::clear_row(buffer, row, fg, bg);
        }
        let mut st = self.state.lock();
        st.col = 0;
        st.row = 0;
        Self::set_cursor_hw(0);
    }

    fn set_color(&self, fg: Color, bg: Color) {
        let mut st = self.state.lock();
        st.fg = fg;
        st.bg = bg;
    }
}
