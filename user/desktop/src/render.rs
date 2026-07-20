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

#[derive(Clone, Copy)]
struct Palette {
    ink: Rgb,
    muted: Rgb,
    accent: Rgb,
    accent_two: Rgb,
    success: Rgb,
}

impl Palette {
    const DEFAULT: Self = Self {
        ink: Rgb::new(239, 246, 255),
        muted: Rgb::new(157, 173, 198),
        accent: Rgb::new(77, 218, 255),
        accent_two: Rgb::new(147, 102, 255),
        success: Rgb::new(91, 232, 171),
    };
}

pub struct Renderer {
    palette: Palette,
}

impl Renderer {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            palette: Palette::DEFAULT,
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

    /// Rebuild shell-owned glass, chrome, and cursor above client surfaces.
    pub fn render_overlay(&self, surface: &mut Surface<'_>, state: &DesktopState, damage: &[Rect]) {
        for &rect in damage {
            let Some(clip) = rect.intersect(state.layout().screen) else {
                continue;
            };
            self.render_glass(surface, state, clip);
            self.render_chrome(surface, state, clip);
            self.render_cursor(surface, state.cursor(), clip);
        }
    }

    fn render_wallpaper(&self, surface: &mut Surface<'_>, state: &DesktopState, clip: Rect) {
        let right = clip.right() as i32;
        let bottom = clip.bottom() as i32;
        for y in clip.y..bottom {
            for x in clip.x..right {
                let color = wallpaper(x as u32, y as u32, state.size());
                surface.put(x, y, color);
            }
        }
    }

    fn render_glass(&self, surface: &mut Surface<'_>, state: &DesktopState, clip: Rect) {
        let layout = state.layout();
        apply_glass_panel(surface, layout.top_bar, 18, 145, clip);
        apply_glass_panel(surface, layout.dock, 22, 165, clip);
        if state.launcher_open() {
            apply_glass_panel(surface, layout.launcher, 24, 205, clip);
        }
    }

    fn render_chrome(&self, surface: &mut Surface<'_>, state: &DesktopState, clip: Rect) {
        let layout = state.layout();
        let compact = state.size().width < 520 || state.size().height < 300;
        let top_icon = Rect::new(layout.top_bar.x + 12, layout.top_bar.y + 9, 25, 25);
        draw_logo(surface, top_icon, clip, self.palette);
        draw_text(
            surface,
            Point::new(
                top_icon.x + 35,
                layout.top_bar.y + if compact { 13 } else { 11 },
            ),
            if compact { 1 } else { 2 },
            b"XENITH",
            self.palette.ink,
            clip,
        );

        let status_y = layout.top_bar.y + (layout.top_bar.height as i32 / 2) - 3;
        let status_x = layout.top_bar.right() as i32 - if compact { 18 } else { 112 };
        fill_circle(
            surface,
            Point::new(status_x, status_y + 3),
            4,
            self.palette.success,
            clip,
        );
        if !compact {
            draw_text(
                surface,
                Point::new(status_x + 12, status_y),
                1,
                b"SYSTEM READY",
                self.palette.muted,
                clip,
            );
        }

        let button = layout.launcher_button;
        fill_rounded(
            surface,
            button,
            12,
            if state.launcher_open() {
                self.palette.accent_two
            } else {
                Rgb::new(29, 52, 79)
            },
            clip,
        );
        draw_logo(
            surface,
            button.inset((button.width / 4).max(3)),
            clip,
            self.palette,
        );
        if layout.dock.width >= 180 {
            draw_text(
                surface,
                Point::new(
                    button.right() as i32 + 16,
                    layout.dock.y + layout.dock.height as i32 / 2 - 3,
                ),
                1,
                b"NO APPS RUNNING",
                self.palette.muted,
                clip,
            );
        }

        if state.launcher_open() {
            self.render_launcher(surface, layout.launcher, clip, compact);
        }
    }

    fn render_launcher(&self, surface: &mut Surface<'_>, panel: Rect, clip: Rect, compact: bool) {
        let padding = if compact { 14 } else { 22 };
        let icon_size = if compact { 26 } else { 34 };
        let icon = Rect::new(panel.x + padding, panel.y + padding, icon_size, icon_size);
        draw_logo(surface, icon, clip, self.palette);
        draw_text(
            surface,
            Point::new(icon.right() as i32 + 12, panel.y + padding + 2),
            if compact { 1 } else { 2 },
            b"XENITH",
            self.palette.ink,
            clip,
        );
        if !compact {
            draw_text(
                surface,
                Point::new(icon.right() as i32 + 13, panel.y + padding + 22),
                1,
                b"WORKSPACE",
                self.palette.muted,
                clip,
            );
        }
        let divider = Rect::new(
            panel.x + padding,
            panel.y + padding + icon_size as i32 + 16,
            panel.width.saturating_sub((padding as u32) * 2),
            1,
        );
        fill_rect(surface, divider, Rgb::new(61, 79, 108), clip);

        let center_y = panel.y + panel.height as i32 / 2;
        let empty = Rect::new(panel.x + padding, center_y - 18, 38, 38);
        draw_empty_grid(surface, empty, clip, self.palette);
        draw_text(
            surface,
            Point::new(empty.right() as i32 + 14, center_y - 10),
            1,
            b"YOUR DESKTOP IS READY",
            self.palette.ink,
            clip,
        );
        if !compact {
            draw_text(
                surface,
                Point::new(empty.right() as i32 + 14, center_y + 5),
                1,
                b"APPLICATIONS WILL APPEAR HERE",
                self.palette.muted,
                clip,
            );
        }
        if panel.height >= 170 {
            draw_text(
                surface,
                Point::new(panel.x + padding, panel.bottom() as i32 - padding - 7),
                1,
                b"SUPER OR CLICK TO CLOSE",
                self.palette.muted,
                clip,
            );
        }
    }

    fn render_cursor(&self, surface: &mut Surface<'_>, cursor: Point, clip: Rect) {
        draw_cursor_shape(
            surface,
            Point::new(cursor.x + 2, cursor.y + 3),
            Rgb::new(0, 5, 13),
            clip,
        );
        draw_cursor_outline(surface, cursor, Rgb::new(3, 12, 26), clip);
        draw_cursor_shape(surface, cursor, self.palette.ink, clip);
    }
}

impl Default for Renderer {
    fn default() -> Self {
        Self::new()
    }
}

fn wallpaper(x: u32, y: u32, size: Size) -> Rgb {
    let height = size.height.max(1);
    let t = y.saturating_mul(255) / height;
    let mut color = Rgb::new(
        (12u32.saturating_sub(t / 42)) as u8,
        (20u32.saturating_sub(t / 28)) as u8,
        (42u32.saturating_sub(t / 18)) as u8,
    );
    let cyan_center = Point::new((size.width * 4 / 5) as i32, (size.height / 5) as i32);
    let violet_center = Point::new((size.width / 7) as i32, (size.height * 4 / 5) as i32);
    color = radial_glow(
        color,
        x,
        y,
        cyan_center,
        size.width.max(size.height) / 2,
        Rgb::new(13, 173, 222),
        92,
    );
    color = radial_glow(
        color,
        x,
        y,
        violet_center,
        size.width.max(size.height) / 2,
        Rgb::new(111, 58, 210),
        78,
    );
    let grain = ((x.wrapping_mul(17) ^ y.wrapping_mul(29) ^ (x * y).wrapping_mul(3)) & 3) as u8;
    color.blend(Rgb::new(18 + grain, 25 + grain, 43 + grain), 10)
}

fn radial_glow(
    base: Rgb,
    x: u32,
    y: u32,
    center: Point,
    radius: u32,
    color: Rgb,
    maximum_alpha: u8,
) -> Rgb {
    if radius == 0 {
        return base;
    }
    let dx = i64::from(x).abs_diff(i64::from(center.x));
    let dy = i64::from(y).abs_diff(i64::from(center.y));
    let distance = dx.max(dy).saturating_add(dx.min(dy) / 2);
    if distance >= u64::from(radius) {
        return base;
    }
    let strength = u64::from(radius) - distance;
    let alpha = strength * u64::from(maximum_alpha) / u64::from(radius);
    base.blend(color, alpha as u8)
}

fn glass_panel(mut base: Rgb, point: Point, panel: Rect, radius: u32, alpha: u8) -> Rgb {
    if rounded_contains(panel.expand(8), radius + 8, point)
        && !rounded_contains(panel, radius, point)
    {
        base = base.blend(Rgb::new(0, 2, 10), 35);
    }
    if rounded_contains(panel.expand(4), radius + 4, point)
        && !rounded_contains(panel, radius, point)
    {
        base = base.blend(Rgb::new(0, 2, 10), 42);
    }
    if rounded_contains(panel, radius, point) {
        base = base.blend(Rgb::new(20, 31, 52), alpha);
        let inner = panel.inset(1);
        if !inner.is_empty() && !rounded_contains(inner, radius.saturating_sub(1), point) {
            base = base.blend(Rgb::new(151, 208, 238), 55);
        } else if point.y <= panel.y.saturating_add(2) {
            base = base.blend(Rgb::new(196, 226, 247), 24);
        }
    }
    base
}

fn apply_glass_panel(surface: &mut Surface<'_>, panel: Rect, radius: u32, alpha: u8, clip: Rect) {
    let Some(bounds) = panel.expand(8).intersect(clip) else {
        return;
    };
    for y in bounds.y..bounds.bottom() as i32 {
        for x in bounds.x..bounds.right() as i32 {
            let point = Point::new(x, y);
            let base = surface.get(x as u32, y as u32);
            surface.put(x, y, glass_panel(base, point, panel, radius, alpha));
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

fn fill_rounded(surface: &mut Surface<'_>, rect: Rect, radius: u32, color: Rgb, clip: Rect) {
    let Some(bounds) = rect.intersect(clip) else {
        return;
    };
    for y in bounds.y..bounds.bottom() as i32 {
        for x in bounds.x..bounds.right() as i32 {
            if rounded_contains(rect, radius, Point::new(x, y)) {
                surface.put(x, y, color);
            }
        }
    }
}

fn fill_circle(surface: &mut Surface<'_>, center: Point, radius: i32, color: Rgb, clip: Rect) {
    let bounds = Rect::new(
        center.x - radius,
        center.y - radius,
        (radius * 2 + 1) as u32,
        (radius * 2 + 1) as u32,
    );
    let Some(bounds) = bounds.intersect(clip) else {
        return;
    };
    for y in bounds.y..bounds.bottom() as i32 {
        for x in bounds.x..bounds.right() as i32 {
            let dx = x - center.x;
            let dy = y - center.y;
            if dx * dx + dy * dy <= radius * radius {
                surface.put(x, y, color);
            }
        }
    }
}

fn draw_logo(surface: &mut Surface<'_>, bounds: Rect, clip: Rect, palette: Palette) {
    if bounds.is_empty() {
        return;
    }
    let gap = (bounds.width / 8).max(1);
    let tile_width = bounds.width.saturating_sub(gap) / 2;
    let tile_height = bounds.height.saturating_sub(gap) / 2;
    let tiles = [
        (
            Rect::new(bounds.x, bounds.y, tile_width, tile_height),
            palette.accent,
        ),
        (
            Rect::new(
                bounds.x + tile_width as i32 + gap as i32,
                bounds.y,
                tile_width,
                tile_height,
            ),
            Rgb::new(77, 160, 255),
        ),
        (
            Rect::new(
                bounds.x,
                bounds.y + tile_height as i32 + gap as i32,
                tile_width,
                tile_height,
            ),
            Rgb::new(97, 119, 255),
        ),
        (
            Rect::new(
                bounds.x + tile_width as i32 + gap as i32,
                bounds.y + tile_height as i32 + gap as i32,
                tile_width,
                tile_height,
            ),
            palette.accent_two,
        ),
    ];
    for (rect, color) in tiles {
        fill_rounded(surface, rect, (tile_width / 3).max(1), color, clip);
    }
}

fn draw_empty_grid(surface: &mut Surface<'_>, bounds: Rect, clip: Rect, palette: Palette) {
    fill_rounded(surface, bounds, 10, Rgb::new(34, 54, 82), clip);
    let inner = bounds.inset(9);
    draw_logo(surface, inner, clip, palette);
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
        assert_eq!(surface.get(0, 0), Rgb::new(12, 20, 42));
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
        let mut damage = DamageTracker::new(layout.screen);
        damage.add(layout.launcher.expand(10));
        assert!(!damage.is_full());
    }
}
