//! Graphics primitives over a 32 bpp linear framebuffer.
//!
//! [`Framebuffer`] owns a raw pixel pointer plus immutable geometry (width,
//! height, pitch) and offers the standard set of 2D drawing primitives:
//! [`put_pixel`], [`fill_rect`], [`draw_rect`] (outline), [`draw_line`]
//! (Bresenham), [`draw_char`] using the 8x16 font in [`fb_font`], and
//! [`blit`] for rectangular pixel copies. Every primitive clips against the
//! framebuffer's visible rectangle so an out-of-bounds coordinate is a no-op
//! rather than a write off the end of video memory.
//!
//! # Layout
//!
//! This module is intentionally separate from [`framebuffer`](crate::devices::
//! framebuffer), which implements the kernel [`Console`] as a text grid. That
//! console layers *on top of* the framebuffer's raw pixel store; the primitives
//! here are the lower-level surface it could draw through once the two are
//! reconciled. For now `gfx` stands alone so the console's existing inlined
//! pixel writes keep working unchanged, and new callers (splash screens, debug
//! overlays, future UI) get a typed drawing API without touching raw pointers.
//!
//! # Pixel format
//!
//! Pixels are 32 bpp `0xRRGGBB` (the high byte is ignored / treated as padding
//! by most Limine framebuffers, which are XRGB8888). [`Color::to_u32`] packs
//! an RGB triple into that layout; the [`from_console`] constructor adapts the
//! shared [`console::Color`] VGA palette so callers can mix console and gfx
//! colours freely.
//!
//! # Safety
//!
//! [`Framebuffer`] carries a `*mut u8` to video memory, which makes it
//! `!Send`/`!Sync` by default. The unsafe impls below assert the same access
//! discipline as the framebuffer console: the pointer is set once at init and
//! every pixel store is a naturally-aligned volatile `u32` write within the
//! `pitch * height` span. All drawing methods are `&self`; they perform only
//! write-only volatile stores, so concurrent draws from multiple CPUs race
//! only at the pixel granularity (last writer wins) and never corrupt memory
//! outside the framebuffer.

use alloc::boxed::Box;
use core::ptr;

use crate::console::Color as ConsoleColor;
use crate::devices::fb_font::{self, GLYPH_HEIGHT, GLYPH_WIDTH};

// ---------------------------------------------------------------------------
// Colour
// ---------------------------------------------------------------------------

/// A 24-bit RGB colour packed as `0x00RRGGBB` for a 32 bpp framebuffer.
///
/// The high byte is zero; on an XRGB8888 framebuffer it is written as padding
/// and ignored by the scan-out hardware. Construct one with [`Color::new`]
/// from raw `r/g/b` components, or with [`Color::from_console`] from a VGA
/// palette entry so gfx and console output match on screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Color(u32);

impl Color {
    /// Build a colour from 8-bit red, green, and blue components.
    #[must_use]
    #[inline]
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self((r as u32) << 16 | (g as u32) << 8 | b as u32)
    }

    /// Build a colour from a packed `0xRRGGBB` value (the high byte is masked).
    #[must_use]
    #[inline]
    pub const fn from_rgb24(rgb: u32) -> Self {
        Self(rgb & 0x00FF_FFFF)
    }

    /// Pack into the `u32` a 32 bpp framebuffer expects.
    #[must_use]
    #[inline]
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    /// Red component, 0..=255.
    #[must_use]
    #[inline]
    pub const fn r(self) -> u8 {
        (self.0 >> 16) as u8
    }

    /// Green component, 0..=255.
    #[must_use]
    #[inline]
    pub const fn g(self) -> u8 {
        (self.0 >> 8) as u8
    }

    /// Blue component, 0..=255.
    #[must_use]
    #[inline]
    pub const fn b(self) -> u8 {
        self.0 as u8
    }

    /// Translate a VGA-palette [`ConsoleColor`] into a gfx [`Color`].
    ///
    /// Uses the same 0-255 sRGB triple [`ConsoleColor::rgb`] yields, so a gfx
    /// primitive drawing with [`Color::from_console(ConsoleColor::LightGray)`]
    /// produces the same shade as the text console's light-gray cells.
    #[must_use]
    #[inline]
    pub const fn from_console(c: ConsoleColor) -> Self {
        let (r, g, b) = c.rgb();
        Self::new(r, g, b)
    }
}

// ---------------------------------------------------------------------------
// Framebuffer geometry + clipping
// ---------------------------------------------------------------------------

/// A rectangular region, used for clipping and source/destination spans.
///
/// `x`/`y` is the top-left corner; `w`/`h` are the (exclusive) extent. A rect
/// with `w == 0` or `h == 0` is empty and contributes nothing to any draw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    /// Top-left X in pixels.
    pub x: i32,
    /// Top-left Y in pixels.
    pub y: i32,
    /// Width in pixels.
    pub w: i32,
    /// Height in pixels.
    pub h: i32,
}

impl Rect {
    /// Build a rect from its top-left corner and size.
    #[must_use]
    #[inline]
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Self { x, y, w, h }
    }

    /// Returns `true` if this rect has zero area.
    #[must_use]
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.w <= 0 || self.h <= 0
    }

    /// Right edge (exclusive): `x + w`.
    #[must_use]
    #[inline]
    pub const fn right(self) -> i32 {
        self.x + self.w
    }

    /// Bottom edge (exclusive): `y + h`.
    #[must_use]
    #[inline]
    pub const fn bottom(self) -> i32 {
        self.y + self.h
    }

    /// Returns `true` if `(px, py)` lies inside this rect.
    #[must_use]
    #[inline]
    pub const fn contains(self, px: i32, py: i32) -> bool {
        px >= self.x && px < self.right() && py >= self.y && py < self.bottom()
    }

    /// Intersect with `other`, returning the (possibly empty) overlap.
    ///
    /// Used to clip a draw region against the framebuffer's visible rect.
    /// Empty when the two rects do not overlap.
    #[must_use]
    #[inline]
    pub fn intersect(self, other: Rect) -> Rect {
        let x = self.x.max(other.x);
        let y = self.y.max(other.y);
        let right = self.right().min(other.right());
        let bottom = self.bottom().min(other.bottom());
        Rect::new(x, y, right - x, bottom - y)
    }
}

// ---------------------------------------------------------------------------
// Framebuffer surface
// ---------------------------------------------------------------------------

/// A 32 bpp linear framebuffer drawing surface.
///
/// Wraps the raw pixel pointer and immutable geometry that Limine reports for
/// a linear framebuffer. All draw methods clip against the visible rectangle
/// `{0, 0, width, height}` so no store can escape the `pitch * height` span.
///
/// The raw pointer makes this `!Send`/`!Sync` by default; see the module-level
/// safety note for the access discipline the unsafe impls assert.
pub struct Framebuffer {
    /// Base of the pixel buffer, already translated through the HHDM.
    buffer: *mut u8,
    /// Bytes per scanline (may exceed `width * 4` for alignment padding).
    pitch: usize,
    /// Visible width in pixels.
    width: i32,
    /// Visible height in pixels.
    height: i32,
}

// SAFETY: `Framebuffer` performs only write-only volatile `u32` stores into the
// `pitch * height` span of the buffer, every store bounds-checked against the
// visible rect before the pointer is formed. The pointer itself is set once at
// construction and never mutated thereafter, so a `&Framebuffer` is safe to
// share across CPUs: concurrent draws race only at pixel granularity (last
// writer wins) and never write outside the framebuffer.
unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

impl Framebuffer {
    /// Construct a drawing surface from raw framebuffer parameters.
    ///
    /// `buffer` must point at a writable 32 bpp framebuffer of `width` x
    /// `height` pixels with `pitch` bytes per row, mapped writable for the
    /// kernel's lifetime. The caller is responsible for the HHDM translation
    /// (see [`xenith_boot::BootInfo::phys_to_virt`]).
    ///
    /// `pitch` is taken as `usize` because Limine reports it as such and it is
    /// used directly in pointer arithmetic; `width`/`height` are `i32` so
    /// clipping math does not need a cast at every callsite.
    #[must_use]
    #[inline]
    pub const fn new(buffer: *mut u8, pitch: usize, width: u16, height: u16) -> Self {
        Self {
            buffer,
            pitch,
            width: width as i32,
            height: height as i32,
        }
    }

    /// Visible width in pixels.
    #[must_use]
    #[inline]
    pub const fn width(&self) -> i32 {
        self.width
    }

    /// Visible height in pixels.
    #[must_use]
    #[inline]
    pub const fn height(&self) -> i32 {
        self.height
    }

    /// Bytes per scanline.
    #[must_use]
    #[inline]
    pub const fn pitch(&self) -> usize {
        self.pitch
    }

    /// The full visible rectangle `{0, 0, width, height}`.
    #[must_use]
    #[inline]
    pub const fn view_rect(&self) -> Rect {
        Rect::new(0, 0, self.width, self.height)
    }

    /// Returns `true` if `(x, y)` is within the visible framebuffer.
    #[must_use]
    #[inline]
    pub const fn in_bounds(&self, x: i32, y: i32) -> bool {
        x >= 0 && x < self.width && y >= 0 && y < self.height
    }

    // --- raw pixel store -----------------------------------------------

    /// Write a 32 bpp pixel at `(x, y)` with no bounds check.
    ///
    /// # Safety
    ///
    /// Caller must guarantee `(x, y)` is within `[0, width) x [0, height)` and
    /// that `buffer` is a valid writable 32 bpp framebuffer base. All public
    /// drawing methods route through [`put_pixel`] (which bounds-checks) or
    /// call this after establishing bounds themselves.
    #[inline]
    unsafe fn put_pixel_raw(&self, x: i32, y: i32, c: Color) {
        let off = (y as usize) * self.pitch + (x as usize) * 4;
        // SAFETY: caller guarantees (x, y) in bounds, so `off` is within
        // `pitch * height`; the store is naturally aligned because `pitch` is
        // a multiple of 4 on any real 32 bpp framebuffer and `x*4` is too.
        unsafe {
            ptr::write_volatile(self.buffer.add(off) as *mut u32, c.to_u32());
        }
    }

    /// Write a single pixel at `(x, y)`, clipped to the visible rect.
    ///
    /// Out-of-bounds coordinates are silently dropped — this is the building
    /// block every other primitive uses, so a clipped draw never faults.
    #[inline]
    pub fn put_pixel(&self, x: i32, y: i32, c: Color) {
        if self.in_bounds(x, y) {
            // SAFETY: just verified (x, y) is within the visible rect.
            unsafe { self.put_pixel_raw(x, y, c) };
        }
    }

    // --- filled and outlined rectangles --------------------------------

    /// Fill the axis-aligned rectangle `r` with `c`.
    ///
    /// The rect is intersected with the visible framebuffer first, so a fill
    /// that extends past an edge paints only the visible portion. An empty or
    /// fully off-screen rect is a no-op.
    pub fn fill_rect(&self, r: Rect, c: Color) {
        let clip = r.intersect(self.view_rect());
        if clip.is_empty() {
            return;
        }
        let c32 = c.to_u32();
        // Iterate scanlines; for each row write the run of pixels in one
        // linear pass. A volatile u32 store per pixel keeps ordering with
        // respect to other draws on the same core and matches what the
        // framebuffer console does.
        for y in clip.y..clip.bottom() {
            let row_off = (y as usize) * self.pitch + (clip.x as usize) * 4;
            for dx in 0..clip.w {
                // SAFETY: clip is within the visible rect, so `row_off + dx*4`
                // is within `pitch * height`; the store is 4-aligned.
                unsafe {
                    ptr::write_volatile(
                        self.buffer.add(row_off + (dx as usize) * 4) as *mut u32,
                        c32,
                    );
                }
            }
        }
    }

    /// Draw the 1-pixel outline of `r` in `c`.
    ///
    /// The outline is drawn as four `fill_rect` calls (top, bottom, left,
    /// right), each clipped to the visible rect. A rect thinner or shorter
    /// than 2 pixels collapses to a single filled bar, which is the correct
    /// degenerate behaviour.
    pub fn draw_rect(&self, r: Rect, c: Color) {
        if r.is_empty() {
            return;
        }
        // Top edge.
        self.fill_rect(Rect::new(r.x, r.y, r.w, 1), c);
        // Bottom edge (skip if the rect is only 1 tall: the top already drew it).
        if r.h > 1 {
            self.fill_rect(Rect::new(r.x, r.bottom() - 1, r.w, 1), c);
        }
        // Left edge (skip the corners already drawn by top/bottom).
        if r.h > 2 {
            self.fill_rect(Rect::new(r.x, r.y + 1, 1, r.h - 2), c);
        }
        // Right edge.
        if r.h > 2 && r.w > 1 {
            self.fill_rect(Rect::new(r.right() - 1, r.y + 1, 1, r.h - 2), c);
        }
    }

    // --- Bresenham line ------------------------------------------------

    /// Draw a 1-pixel line from `(x0, y0)` to `(x1, y1)` using Bresenham's
    /// algorithm.
    ///
    /// Handles every octant (steep and shallow, in both directions) with the
    /// classic integer-error-accumulator formulation. Every plotted pixel goes
    /// through [`put_pixel`], so a line that runs off any edge is clipped
    /// rather than faulting.
    pub fn draw_line(&self, x0: i32, y0: i32, x1: i32, y1: i32, c: Color) {
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy; // 2*dx + 2*dy before scaling; we use the /2 form.
        let mut x = x0;
        let mut y = y0;
        loop {
            self.put_pixel(x, y, c);
            if x == x1 && y == y1 {
                break;
            }
            // e2 = 2 * err; the standard Bresenham update.
            let e2 = 2 * err;
            if e2 >= dy {
                // Step in x.
                err += dy;
                x += sx;
            }
            if e2 <= dx {
                // Step in y.
                err += dx;
                y += sy;
            }
        }
    }

    // --- text ----------------------------------------------------------

    /// Draw `ch` at pixel `(x, y)` (top-left of the 8x16 cell) in `fg` on `bg`.
    ///
    /// The glyph is looked up from [`fb_font::FONT`] via [`fb_font::glyph`];
    /// bytes >= 128 render as an outlined placeholder. The cell's background
    /// is filled even for blank rows, so successive characters tile cleanly
    /// without needing a separate clear pass. Both axes are clipped: a glyph
    /// that straddles the right or bottom edge draws only its visible pixels.
    pub fn draw_char(&self, x: i32, y: i32, ch: u8, fg: Color, bg: Color) {
        let glyph = fb_font::glyph(ch);
        for (gy, bits) in glyph.into_iter().enumerate() {
            let py = y + gy as i32;
            if py < 0 || py >= self.height {
                continue;
            }
            for gx in 0..GLYPH_WIDTH {
                let px = x + gx as i32;
                if px < 0 || px >= self.width {
                    continue;
                }
                let on = (bits >> (7 - gx)) & 1 == 1;
                let c = if on { fg } else { bg };
                // SAFETY: px/py checked against the visible rect above.
                unsafe { self.put_pixel_raw(px, py, c) };
            }
        }
    }

    /// Draw `s` starting at pixel `(x, y)` in `fg` on `bg`, advancing one
    /// 8-pixel cell per character.
    ///
    /// Newlines (`\n`) wrap to the next row (`y + GLYPH_HEIGHT`); carriage
    /// return (`\r`) resets the x cursor to the original `x`. Other control
    /// bytes render as their (blank) glyph. The whole string is clipped to
    /// the visible framebuffer, so text running off any edge is dropped.
    pub fn draw_str(&self, x: i32, y: i32, s: &str, fg: Color, bg: Color) {
        let mut cx = x;
        let mut cy = y;
        let cell_w = GLYPH_WIDTH as i32;
        let cell_h = GLYPH_HEIGHT as i32;
        for b in s.bytes() {
            match b {
                b'\n' => {
                    cy += cell_h;
                    cx = x;
                    continue;
                },
                b'\r' => {
                    cx = x;
                    continue;
                },
                _ => self.draw_char(cx, cy, b, fg, bg),
            }
            cx += cell_w;
        }
    }

    // --- blit ----------------------------------------------------------

    /// Copy a rectangular pixel region from `src` to `(dst_x, dst_y)`.
    ///
    /// `src_rect` selects the source region inside `self`; the destination is
    /// the same size positioned at `(dst_x, dst_y)`. Both source and
    /// destination are clipped to the visible framebuffer, so a blit that runs
    /// off either edge copies only the visible overlap. The copy direction is
    /// chosen per-scanline to be correct when source and destination overlap
    /// (forward copy when `dst_y <= src_rect.y`, backward otherwise).
    ///
    /// This is a same-surface blit (the framebuffer onto itself); it is the
    /// primitive a scrolling console or drag-rect redraw would use. A
    /// cross-surface blit would take a second `&Framebuffer`; that is left for
    /// a future compositing layer.
    pub fn blit(&self, src_rect: Rect, dst_x: i32, dst_y: i32) {
        // Clip the source to the visible rect first; this also makes empty
        // sources a no-op.
        let src = src_rect.intersect(self.view_rect());
        if src.is_empty() {
            return;
        }
        // Compute the visible destination rect by intersecting the translated
        // source rect with the view, then shift the source back by the same
        // delta so the two stay aligned pixel-for-pixel.
        let dst_full = Rect::new(dst_x, dst_y, src.w, src.h);
        let dst = dst_full.intersect(self.view_rect());
        if dst.is_empty() {
            return;
        }
        let dx = dst.x - dst_full.x;
        let dy = dst.y - dst_full.y;
        let src_x = src.x + dx;
        let src_y = src.y + dy;
        let w = dst.w;
        let h = dst.h;
        let row_bytes = (w as usize) * 4;

        // If the destination is above (or at the same y as) the source, copy
        // top-to-bottom so an upward scroll does not clobber rows it has yet
        // to read. Otherwise copy bottom-to-top.
        let forward = dst_y <= src_y;
        let row_range: Box<dyn Iterator<Item = i32>> = if forward {
            Box::new(0..h)
        } else {
            Box::new((0..h).rev())
        };
        for i in row_range {
            let sy = src_y + i;
            let dy_row = dst.y + i;
            let src_off = (sy as usize) * self.pitch + (src_x as usize) * 4;
            let dst_off = (dy_row as usize) * self.pitch + (dst.x as usize) * 4;
            // SAFETY: both spans are within `pitch * height` (src and dst were
            // clipped to the view rect) and `row_bytes <= pitch`. The copy
            // direction was chosen above to be correct for overlap.
            unsafe {
                ptr::copy(
                    self.buffer.add(src_off),
                    self.buffer.add(dst_off),
                    row_bytes,
                );
            }
        }
    }

    /// Fill the whole visible framebuffer with `c`.
    ///
    /// Cheaper than `fill_rect(view_rect())` because the geometry is fixed and
    /// the inner loop can stride by `pitch`, but the visible result is the
    /// same. Used by the console backend's `clear` and by a splash screen's
    /// background fill.
    pub fn clear(&self, c: Color) {
        self.fill_rect(self.view_rect(), c);
    }
}

// ---------------------------------------------------------------------------
// Tests (host-only; exercise the pure helpers with no framebuffer access)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_pack_unpack_roundtrips() {
        let c = Color::new(0x12, 0x34, 0x56);
        assert_eq!(c.to_u32(), 0x0012_3456);
        assert_eq!(c.r(), 0x12);
        assert_eq!(c.g(), 0x34);
        assert_eq!(c.b(), 0x56);
    }

    #[test]
    fn from_rgb24_masks_high_byte() {
        assert_eq!(Color::from_rgb24(0xFF12_3456).to_u32(), 0x0012_3456);
    }

    #[test]
    fn from_console_matches_rgb() {
        let c = Color::from_console(ConsoleColor::Red);
        assert_eq!(c, Color::new(170, 0, 0));
    }

    #[test]
    fn rect_intersect_overlap() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(5, 5, 10, 10);
        assert_eq!(a.intersect(b), Rect::new(5, 5, 5, 5));
    }

    #[test]
    fn rect_intersect_disjoint_is_empty() {
        let a = Rect::new(0, 0, 4, 4);
        let b = Rect::new(10, 10, 4, 4);
        assert!(a.intersect(b).is_empty());
    }

    #[test]
    fn rect_contains_respects_exclusive_edges() {
        let r = Rect::new(0, 0, 10, 10);
        assert!(r.contains(0, 0));
        assert!(r.contains(9, 9));
        assert!(!r.contains(10, 0));
        assert!(!r.contains(0, 10));
    }

    #[test]
    fn font_glyph_blank_for_control() {
        assert_eq!(fb_font::glyph(b'\0'), [0u8; GLYPH_HEIGHT]);
        assert_eq!(fb_font::glyph(b' '), [0u8; GLYPH_HEIGHT]);
    }

    #[test]
    fn font_glyph_ascii_has_pixels() {
        // 'A' is non-blank somewhere in its glyph.
        let a = fb_font::glyph(b'A');
        assert!(a.iter().any(|row| *row != 0));
    }

    #[test]
    fn font_glyph_high_byte_uses_placeholder() {
        // 0x80 is out of table range; glyph() returns the outlined cell whose
        // top and bottom rows are full.
        let g = fb_font::glyph(0x80);
        assert_eq!(g[0], 0xFF);
        assert_eq!(g[GLYPH_HEIGHT - 1], 0xFF);
    }

    #[test]
    fn pixel_on_tests_msb_leftmost() {
        // Row 0xFF has every column on; row 0x80 only the leftmost.
        let mut g = [0u8; GLYPH_HEIGHT];
        g[0] = 0xFF;
        g[1] = 0x80;
        assert!(fb_font::pixel_on(&g, 0, 0));
        assert!(fb_font::pixel_on(&g, 0, 7));
        assert!(fb_font::pixel_on(&g, 1, 0));
        assert!(!fb_font::pixel_on(&g, 1, 1));
    }
}
