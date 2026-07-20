use crate::{DesktopState, Point, Rect, Size};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Rgb {
    r: u8,
    g: u8,
    b: u8,
}

impl Rgb {
    const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    fn blend(self, top: Self, alpha: u8) -> Self {
        let alpha = u32::from(alpha);
        let inverse = 255 - alpha;
        Self {
            r: ((u32::from(self.r) * inverse + u32::from(top.r) * alpha + 127) / 255) as u8,
            g: ((u32::from(self.g) * inverse + u32::from(top.g) * alpha + 127) / 255) as u8,
            b: ((u32::from(self.b) * inverse + u32::from(top.b) * alpha + 127) / 255) as u8,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenderError {
    InvalidSurface,
    InvalidPixelFormat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PixelFormat {
    red_shift: u8,
    red_size: u8,
    green_shift: u8,
    green_size: u8,
    blue_shift: u8,
    blue_size: u8,
    red_mask: u32,
    green_mask: u32,
    blue_mask: u32,
}

impl PixelFormat {
    pub fn new(
        red_shift: u8,
        red_size: u8,
        green_shift: u8,
        green_size: u8,
        blue_shift: u8,
        blue_size: u8,
    ) -> Result<Self, RenderError> {
        let red_mask = channel_mask(red_shift, red_size).ok_or(RenderError::InvalidPixelFormat)?;
        let green_mask =
            channel_mask(green_shift, green_size).ok_or(RenderError::InvalidPixelFormat)?;
        let blue_mask =
            channel_mask(blue_shift, blue_size).ok_or(RenderError::InvalidPixelFormat)?;
        if red_mask & green_mask != 0 || red_mask & blue_mask != 0 || green_mask & blue_mask != 0 {
            return Err(RenderError::InvalidPixelFormat);
        }
        Ok(Self {
            red_shift,
            red_size,
            green_shift,
            green_size,
            blue_shift,
            blue_size,
            red_mask,
            green_mask,
            blue_mask,
        })
    }

    #[must_use]
    fn pack(self, color: Rgb) -> u32 {
        pack_channel(color.r, self.red_shift, self.red_size)
            | pack_channel(color.g, self.green_shift, self.green_size)
            | pack_channel(color.b, self.blue_shift, self.blue_size)
    }

    #[allow(dead_code)]
    fn unpack(self, pixel: u32) -> Rgb {
        Rgb::new(
            unpack_channel(pixel & self.red_mask, self.red_shift, self.red_size),
            unpack_channel(pixel & self.green_mask, self.green_shift, self.green_size),
            unpack_channel(pixel & self.blue_mask, self.blue_shift, self.blue_size),
        )
    }
}

fn channel_mask(shift: u8, size: u8) -> Option<u32> {
    let end = u16::from(shift).checked_add(u16::from(size))?;
    if size == 0 || size > 32 || end > 32 {
        return None;
    }
    let low = if size == 32 {
        u32::MAX
    } else {
        (1u32 << size) - 1
    };
    low.checked_shl(u32::from(shift))
}

fn pack_channel(value: u8, shift: u8, size: u8) -> u32 {
    let maximum = if size == 32 {
        u64::from(u32::MAX)
    } else {
        (1u64 << size) - 1
    };
    ((((u64::from(value) * maximum) + 127) / 255) << shift) as u32
}

fn unpack_channel(value: u32, shift: u8, size: u8) -> u8 {
    let maximum = if size == 32 {
        u64::from(u32::MAX)
    } else {
        (1u64 << size) - 1
    };
    let raw = u64::from(value >> shift);
    ((raw * 255 + maximum / 2) / maximum) as u8
}

pub struct Surface<'a> {
    bytes: &'a mut [u8],
    size: Size,
    stride: usize,
    format: PixelFormat,
}

impl<'a> Surface<'a> {
    pub fn new(
        bytes: &'a mut [u8],
        size: Size,
        stride: usize,
        format: PixelFormat,
    ) -> Result<Self, RenderError> {
        let visible = (size.width as usize)
            .checked_mul(4)
            .ok_or(RenderError::InvalidSurface)?;
        let required = (size.height as usize)
            .checked_mul(stride)
            .ok_or(RenderError::InvalidSurface)?;
        if size.width == 0
            || size.height == 0
            || stride < visible
            || !stride.is_multiple_of(4)
            || bytes.len() < required
        {
            return Err(RenderError::InvalidSurface);
        }
        Ok(Self {
            bytes,
            size,
            stride,
            format,
        })
    }

    fn put(&mut self, x: i32, y: i32, color: Rgb) {
        if x < 0 || y < 0 || x as u32 >= self.size.width || y as u32 >= self.size.height {
            return;
        }
        let offset = y as usize * self.stride + x as usize * 4;
        let bytes = self.format.pack(color).to_ne_bytes();
        self.bytes[offset..offset + 4].copy_from_slice(&bytes);
    }

    fn get(&self, x: u32, y: u32) -> Rgb {
        let offset = y as usize * self.stride + x as usize * 4;
        let pixel = u32::from_ne_bytes([
            self.bytes[offset],
            self.bytes[offset + 1],
            self.bytes[offset + 2],
            self.bytes[offset + 3],
        ]);
        self.format.unpack(pixel)
    }
}

const INK: Rgb = Rgb::new(246, 246, 244);
const MUTED: Rgb = Rgb::new(174, 174, 171);
const BAR_TINT: Rgb = Rgb::new(16, 16, 16);
const PANEL_TINT: Rgb = Rgb::new(22, 22, 21);

/// Allocation-free wallpaper source used by the software renderer.
///
/// The callback receives the destination pixel and full screen size, so an
/// embedded image can implement focal-point cover cropping without allocating
/// or resizing a frame ahead of time.
pub type WallpaperSampler = fn(x: u32, y: u32, size: Size) -> [u8; 3];

#[derive(Clone, Copy)]
enum WallpaperSource {
    Embedded,
    Custom(WallpaperSampler),
}

pub struct Renderer {
    wallpaper: WallpaperSource,
}

impl Renderer {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            wallpaper: WallpaperSource::Embedded,
        }
    }

    #[must_use]
    pub const fn with_wallpaper(wallpaper: WallpaperSampler) -> Self {
        Self {
            wallpaper: WallpaperSource::Custom(wallpaper),
        }
    }

    pub fn render(&self, surface: &mut Surface<'_>, state: &DesktopState, damage: &[Rect]) {
        self.render_background(surface, state, damage);
        self.render_overlay(surface, state, damage);
    }

    /// Rebuild the opaque wallpaper below every client surface.
    pub fn render_background(
        &self,
        surface: &mut Surface<'_>,
        state: &DesktopState,
        damage: &[Rect],
    ) {
        for &rect in damage {
            let Some(clip) = rect.intersect(state.layout().screen) else {
                continue;
            };
            self.render_wallpaper(surface, state, clip);
        }
    }

    /// Rebuild the restrained shell bar, launcher, and cursor above clients.
    pub fn render_overlay(&self, surface: &mut Surface<'_>, state: &DesktopState, damage: &[Rect]) {
        for &rect in damage {
            let Some(clip) = rect.intersect(state.layout().screen) else {
                continue;
            };
            self.render_shell(surface, state, clip);
            self.render_cursor(surface, state.cursor(), clip);
        }
    }

    fn render_wallpaper(&self, surface: &mut Surface<'_>, state: &DesktopState, clip: Rect) {
        let right = clip.right() as i32;
        let bottom = clip.bottom() as i32;
        match self.wallpaper {
            WallpaperSource::Embedded => {
                let wallpaper = crate::wallpaper::Sampler::new(state.size());
                for y in clip.y..bottom {
                    for x in clip.x..right {
                        let [r, g, b] = wallpaper.sample(x as u32, y as u32);
                        surface.put(x, y, Rgb::new(r, g, b));
                    }
                }
            },
            WallpaperSource::Custom(sample) => {
                for y in clip.y..bottom {
                    for x in clip.x..right {
                        let [r, g, b] = sample(x as u32, y as u32, state.size());
                        surface.put(x, y, Rgb::new(r, g, b));
                    }
                }
            },
        }
    }

    fn render_shell(&self, surface: &mut Surface<'_>, state: &DesktopState, clip: Rect) {
        let layout = state.layout();
        apply_tint(surface, layout.dock, BAR_TINT, 188, clip);
        fill_rect(
            surface,
            Rect::new(layout.dock.x, layout.dock.y, layout.dock.width, 1),
            Rgb::new(78, 78, 76),
            clip,
        );

        let button = layout.launcher_button;
        if state.launcher_open() {
            apply_tint_rounded(surface, button, 5, INK, 32, clip);
        }
        draw_mark(surface, button.inset((button.width / 4).max(3)), INK, clip);
        draw_text(
            surface,
            Point::new(
                button.right() as i32 + 10,
                layout.dock.y + layout.dock.height as i32 / 2 - 3,
            ),
            1,
            b"XENITH",
            INK,
            clip,
        );

        if state.launcher_open() {
            self.render_launcher(surface, layout.launcher, clip);
        }
    }

    fn render_launcher(&self, surface: &mut Surface<'_>, panel: Rect, clip: Rect) {
        apply_tint_rounded(surface, panel, 8, PANEL_TINT, 230, clip);
        draw_rounded_outline(surface, panel, 8, Rgb::new(91, 91, 88), clip);
        let padding = 16;
        let icon = Rect::new(panel.x + padding, panel.y + padding, 22, 22);
        draw_mark(surface, icon, INK, clip);
        draw_text(
            surface,
            Point::new(icon.right() as i32 + 10, panel.y + padding + 7),
            1,
            b"XENITH",
            INK,
            clip,
        );
        draw_text(
            surface,
            Point::new(panel.x + padding, panel.bottom() as i32 - padding - 7),
            1,
            b"NO APPLICATIONS INSTALLED",
            MUTED,
            clip,
        );
    }

    fn render_cursor(&self, surface: &mut Surface<'_>, cursor: Point, clip: Rect) {
        draw_cursor_shape(
            surface,
            Point::new(cursor.x + 2, cursor.y + 3),
            Rgb::new(0, 0, 0),
            clip,
        );
        draw_cursor_outline(surface, cursor, Rgb::new(7, 7, 7), clip);
        draw_cursor_shape(surface, cursor, INK, clip);
    }
}

impl Default for Renderer {
    fn default() -> Self {
        Self::new()
    }
}

fn apply_tint(surface: &mut Surface<'_>, rect: Rect, color: Rgb, alpha: u8, clip: Rect) {
    let Some(bounds) = rect.intersect(clip) else {
        return;
    };
    for y in bounds.y..bounds.bottom() as i32 {
        for x in bounds.x..bounds.right() as i32 {
            let base = surface.get(x as u32, y as u32);
            surface.put(x, y, base.blend(color, alpha));
        }
    }
}

fn apply_tint_rounded(
    surface: &mut Surface<'_>,
    rect: Rect,
    radius: u32,
    color: Rgb,
    alpha: u8,
    clip: Rect,
) {
    let Some(bounds) = rect.intersect(clip) else {
        return;
    };
    for y in bounds.y..bounds.bottom() as i32 {
        for x in bounds.x..bounds.right() as i32 {
            if rounded_contains(rect, radius, Point::new(x, y)) {
                let base = surface.get(x as u32, y as u32);
                surface.put(x, y, base.blend(color, alpha));
            }
        }
    }
}

fn rounded_contains(rect: Rect, radius: u32, point: Point) -> bool {
    if !rect.contains(point) {
        return false;
    }
    let radius = radius
        .min(rect.width.saturating_sub(1) / 2)
        .min(rect.height.saturating_sub(1) / 2) as i32;
    if radius <= 1 {
        return true;
    }
    let left_center = rect.x + radius;
    let right_center = rect.right() as i32 - radius - 1;
    let top_center = rect.y + radius;
    let bottom_center = rect.bottom() as i32 - radius - 1;
    let nearest_x = point.x.clamp(left_center, right_center);
    let nearest_y = point.y.clamp(top_center, bottom_center);
    let dx = i64::from(point.x - nearest_x);
    let dy = i64::from(point.y - nearest_y);
    dx * dx + dy * dy <= i64::from(radius) * i64::from(radius)
}

fn fill_rect(surface: &mut Surface<'_>, rect: Rect, color: Rgb, clip: Rect) {
    let Some(rect) = rect.intersect(clip) else {
        return;
    };
    for y in rect.y..rect.bottom() as i32 {
        for x in rect.x..rect.right() as i32 {
            surface.put(x, y, color);
        }
    }
}

fn draw_rounded_outline(
    surface: &mut Surface<'_>,
    rect: Rect,
    radius: u32,
    color: Rgb,
    clip: Rect,
) {
    let Some(bounds) = rect.intersect(clip) else {
        return;
    };
    let inner = rect.inset(1);
    for y in bounds.y..bounds.bottom() as i32 {
        for x in bounds.x..bounds.right() as i32 {
            let point = Point::new(x, y);
            if rounded_contains(rect, radius, point)
                && (inner.is_empty() || !rounded_contains(inner, radius.saturating_sub(1), point))
            {
                surface.put(x, y, color);
            }
        }
    }
}

fn draw_mark(surface: &mut Surface<'_>, bounds: Rect, color: Rgb, clip: Rect) {
    if bounds.is_empty() {
        return;
    }
    let gap = (bounds.width.min(bounds.height) / 7).max(1);
    let tile_width = bounds.width.saturating_sub(gap) / 2;
    let tile_height = bounds.height.saturating_sub(gap) / 2;
    let tiles = [
        Rect::new(bounds.x, bounds.y, tile_width, tile_height),
        Rect::new(
            bounds.x + tile_width as i32 + gap as i32,
            bounds.y,
            tile_width,
            tile_height,
        ),
        Rect::new(
            bounds.x,
            bounds.y + tile_height as i32 + gap as i32,
            tile_width,
            tile_height,
        ),
        Rect::new(
            bounds.x + tile_width as i32 + gap as i32,
            bounds.y + tile_height as i32 + gap as i32,
            tile_width,
            tile_height,
        ),
    ];
    for rect in tiles {
        fill_rect(surface, rect, color, clip);
    }
}

fn draw_text(
    surface: &mut Surface<'_>,
    origin: Point,
    scale: u32,
    text: &[u8],
    color: Rgb,
    clip: Rect,
) {
    let scale = scale.max(1) as i32;
    let advance = 6 * scale;
    for (index, &character) in text.iter().enumerate() {
        let glyph_origin = Point::new(origin.x + index as i32 * advance, origin.y);
        let glyph_bounds = Rect::new(
            glyph_origin.x,
            glyph_origin.y,
            (5 * scale) as u32,
            (7 * scale) as u32,
        );
        if glyph_bounds.intersect(clip).is_none() {
            continue;
        }
        let rows = glyph(character);
        for (row, bits) in rows.iter().copied().enumerate() {
            for column in 0..5 {
                if bits & (1 << (4 - column)) == 0 {
                    continue;
                }
                fill_rect(
                    surface,
                    Rect::new(
                        glyph_origin.x + column * scale,
                        glyph_origin.y + row as i32 * scale,
                        scale as u32,
                        scale as u32,
                    ),
                    color,
                    clip,
                );
            }
        }
    }
}

fn glyph(character: u8) -> [u8; 7] {
    match character.to_ascii_uppercase() {
        b'A' => [0x0e, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        b'B' => [0x1e, 0x11, 0x11, 0x1e, 0x11, 0x11, 0x1e],
        b'C' => [0x0e, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0e],
        b'D' => [0x1e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1e],
        b'E' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x1f],
        b'F' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x10],
        b'G' => [0x0e, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0f],
        b'H' => [0x11, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        b'I' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x1f],
        b'J' => [0x07, 0x02, 0x02, 0x02, 0x12, 0x12, 0x0c],
        b'K' => [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
        b'L' => [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1f],
        b'M' => [0x11, 0x1b, 0x15, 0x15, 0x11, 0x11, 0x11],
        b'N' => [0x11, 0x19, 0x19, 0x15, 0x13, 0x13, 0x11],
        b'O' => [0x0e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        b'P' => [0x1e, 0x11, 0x11, 0x1e, 0x10, 0x10, 0x10],
        b'Q' => [0x0e, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0d],
        b'R' => [0x1e, 0x11, 0x11, 0x1e, 0x14, 0x12, 0x11],
        b'S' => [0x0f, 0x10, 0x10, 0x0e, 0x01, 0x01, 0x1e],
        b'T' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        b'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        b'V' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x0a, 0x04],
        b'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x1b, 0x11],
        b'X' => [0x11, 0x11, 0x0a, 0x04, 0x0a, 0x11, 0x11],
        b'Y' => [0x11, 0x11, 0x0a, 0x04, 0x04, 0x04, 0x04],
        b'Z' => [0x1f, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1f],
        b'0' => [0x0e, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0e],
        b'1' => [0x04, 0x0c, 0x14, 0x04, 0x04, 0x04, 0x1f],
        b'2' => [0x0e, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1f],
        b'3' => [0x1e, 0x01, 0x01, 0x0e, 0x01, 0x01, 0x1e],
        b'4' => [0x02, 0x06, 0x0a, 0x12, 0x1f, 0x02, 0x02],
        b'5' => [0x1f, 0x10, 0x10, 0x1e, 0x01, 0x01, 0x1e],
        b'6' => [0x0e, 0x10, 0x10, 0x1e, 0x11, 0x11, 0x0e],
        b'7' => [0x1f, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        b'8' => [0x0e, 0x11, 0x11, 0x0e, 0x11, 0x11, 0x0e],
        b'9' => [0x0e, 0x11, 0x11, 0x0f, 0x01, 0x01, 0x0e],
        b'-' => [0, 0, 0, 0x1f, 0, 0, 0],
        b'.' => [0, 0, 0, 0, 0, 0x06, 0x06],
        b':' => [0, 0x06, 0x06, 0, 0x06, 0x06, 0],
        b' ' => [0; 7],
        _ => [0x0e, 0x11, 0x01, 0x02, 0x04, 0, 0x04],
    }
}

fn cursor_inside(local_x: i32, local_y: i32) -> bool {
    (0..=14).contains(&local_y) && local_x >= 0 && local_x <= local_y / 2
        || (10..=19).contains(&local_y) && (4..=7).contains(&local_x)
}

fn draw_cursor_shape(surface: &mut Surface<'_>, origin: Point, color: Rgb, clip: Rect) {
    for y in 0..20 {
        for x in 0..10 {
            if cursor_inside(x, y) {
                let point = Point::new(origin.x + x, origin.y + y);
                if clip.contains(point) {
                    surface.put(point.x, point.y, color);
                }
            }
        }
    }
}

fn draw_cursor_outline(surface: &mut Surface<'_>, origin: Point, color: Rgb, clip: Rect) {
    for y in -1..=20 {
        for x in -1..=10 {
            if cursor_inside(x, y) {
                continue;
            }
            let adjacent = cursor_inside(x - 1, y)
                || cursor_inside(x + 1, y)
                || cursor_inside(x, y - 1)
                || cursor_inside(x, y + 1);
            let point = Point::new(origin.x + x, origin.y + y);
            if adjacent && clip.contains(point) {
                surface.put(point.x, point.y, color);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec;

    use super::*;
    use crate::{DamageTracker, Layout};

    fn rgb_format() -> PixelFormat {
        PixelFormat::new(16, 8, 8, 8, 0, 8).unwrap()
    }

    #[test]
    fn rejects_overlapping_or_truncated_formats() {
        assert_eq!(
            PixelFormat::new(16, 8, 16, 8, 0, 8),
            Err(RenderError::InvalidPixelFormat)
        );
        assert_eq!(
            PixelFormat::new(28, 8, 8, 8, 0, 8),
            Err(RenderError::InvalidPixelFormat)
        );
    }

    #[test]
    fn full_render_is_deterministic_and_non_blank() {
        let size = Size::new(320, 200);
        let stride = size.width as usize * 4;
        let mut first = vec![0u8; stride * size.height as usize];
        let mut second = first.clone();
        let state = DesktopState::new(size);
        let renderer = Renderer::new();
        renderer.render(
            &mut Surface::new(&mut first, size, stride, rgb_format()).unwrap(),
            &state,
            &[size.bounds()],
        );
        renderer.render(
            &mut Surface::new(&mut second, size, stride, rgb_format()).unwrap(),
            &state,
            &[size.bounds()],
        );
        assert_eq!(first, second);
        assert!(first.iter().any(|byte| *byte != 0));
        let surface = Surface::new(&mut first, size, stride, rgb_format()).unwrap();
        let [r, g, b] = crate::wallpaper::Sampler::new(size).sample(0, 0);
        assert_eq!(surface.get(0, 0), Rgb::new(r, g, b));
    }

    #[test]
    fn custom_wallpaper_sampler_is_used_without_touching_pixels_outside_damage() {
        fn solid(_: u32, _: u32, _: Size) -> [u8; 3] {
            [23, 37, 41]
        }

        let size = Size::new(64, 48);
        let stride = size.width as usize * 4;
        let mut bytes = vec![0u8; stride * size.height as usize];
        let state = DesktopState::new(size);
        let renderer = Renderer::with_wallpaper(solid);
        let damage = Rect::new(2, 3, 4, 5);
        renderer.render_background(
            &mut Surface::new(&mut bytes, size, stride, rgb_format()).unwrap(),
            &state,
            &[damage],
        );
        let surface = Surface::new(&mut bytes, size, stride, rgb_format()).unwrap();
        assert_eq!(surface.get(2, 3), Rgb::new(23, 37, 41));
        assert_eq!(surface.get(5, 7), Rgb::new(23, 37, 41));
        assert_eq!(surface.get(1, 3), Rgb::default());
    }

    #[test]
    fn explicit_scene_layers_match_the_combined_renderer() {
        let size = Size::new(320, 200);
        let stride = size.width as usize * 4;
        let mut combined = vec![0u8; stride * size.height as usize];
        let mut layered = combined.clone();
        let state = DesktopState::new(size);
        let renderer = Renderer::new();
        renderer.render(
            &mut Surface::new(&mut combined, size, stride, rgb_format()).unwrap(),
            &state,
            &[size.bounds()],
        );
        let mut surface = Surface::new(&mut layered, size, stride, rgb_format()).unwrap();
        renderer.render_background(&mut surface, &state, &[size.bounds()]);
        renderer.render_overlay(&mut surface, &state, &[size.bounds()]);
        assert_eq!(combined, layered);
    }

    #[test]
    fn render_respects_the_requested_damage_clip() {
        let size = Size::new(160, 120);
        let stride = size.width as usize * 4;
        let mut bytes = vec![0u8; stride * size.height as usize];
        let state = DesktopState::new(size);
        let renderer = Renderer::new();
        let mut surface = Surface::new(&mut bytes, size, stride, rgb_format()).unwrap();
        renderer.render(&mut surface, &state, &[size.bounds()]);
        let outside_offset = 100 * 4 + 100 * stride;
        bytes[outside_offset..outside_offset + 4].copy_from_slice(&0x00ff_00ff_u32.to_ne_bytes());
        let before = bytes.clone();
        let damage = Rect::new(0, 0, 8, 8);
        renderer.render(
            &mut Surface::new(&mut bytes, size, stride, rgb_format()).unwrap(),
            &state,
            &[damage],
        );
        assert_eq!(bytes, before);
        assert_eq!(
            &bytes[outside_offset..outside_offset + 4],
            &0x00ff_00ff_u32.to_ne_bytes(),
            "rendering a small damage region touched a pixel outside its clip"
        );
    }

    #[test]
    fn launcher_visual_region_fits_small_gate_resolution() {
        let layout = Layout::new(Size::new(320, 200));
        assert!(layout.launcher.width >= 280);
        assert!(layout.launcher.height >= 70);
        assert_eq!(layout.top_bar, layout.dock);
        assert_eq!(layout.dock.x, 0);
        assert_eq!(layout.dock.right(), layout.screen.right());
        assert_eq!(layout.dock.bottom(), layout.screen.bottom());
        assert!(layout.launcher.bottom() <= i64::from(layout.dock.y));
        let mut damage = DamageTracker::new(layout.screen);
        damage.add(layout.launcher.expand(10));
        assert!(!damage.is_full());
    }
}
