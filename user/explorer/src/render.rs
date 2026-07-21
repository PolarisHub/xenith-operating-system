//! CPU-efficient BGRA8888 renderer for Xenith Files.

use crate::layout::{Layout, Point, Rect};
use crate::model::{
    Entry, ExplorerModel, KnownPlace, ENTRY_KIND_DIRECTORY, ENTRY_KIND_REGULAR, ENTRY_KIND_SYMLINK,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenderError {
    InvalidSurface,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Color {
    red: u8,
    green: u8,
    blue: u8,
    alpha: u8,
}

impl Color {
    const fn new(red: u8, green: u8, blue: u8, alpha: u8) -> Self {
        Self {
            red,
            green,
            blue,
            alpha,
        }
    }

    fn mix(self, top: Self, amount: u8) -> Self {
        let amount = u32::from(amount);
        let inverse = 255 - amount;
        Self::new(
            ((u32::from(self.red) * inverse + u32::from(top.red) * amount + 127) / 255) as u8,
            ((u32::from(self.green) * inverse + u32::from(top.green) * amount + 127) / 255) as u8,
            ((u32::from(self.blue) * inverse + u32::from(top.blue) * amount + 127) / 255) as u8,
            self.alpha.max(top.alpha),
        )
    }
}

const TRANSPARENT: Color = Color::new(0, 0, 0, 0);
const WINDOW: Color = Color::new(21, 25, 34, 246);
const TITLE: Color = Color::new(28, 34, 45, 242);
const TOOLBAR: Color = Color::new(25, 30, 40, 238);
const SIDEBAR: Color = Color::new(24, 29, 39, 230);
const CONTENT: Color = Color::new(30, 35, 46, 244);
const PANEL: Color = Color::new(42, 49, 63, 232);
const PANEL_BORDER: Color = Color::new(83, 94, 115, 210);
const TEXT: Color = Color::new(244, 247, 252, 255);
const MUTED: Color = Color::new(161, 171, 190, 255);
const ACCENT: Color = Color::new(91, 174, 255, 255);
const ACCENT_SOFT: Color = Color::new(53, 117, 189, 245);
const DANGER: Color = Color::new(232, 91, 104, 255);
const FOLDER: Color = Color::new(245, 188, 83, 255);

struct Canvas<'a> {
    bytes: &'a mut [u8],
    width: u32,
    height: u32,
    stride: usize,
}

impl<'a> Canvas<'a> {
    fn new(
        bytes: &'a mut [u8],
        width: u32,
        height: u32,
        stride: usize,
    ) -> Result<Self, RenderError> {
        let visible = (width as usize)
            .checked_mul(4)
            .ok_or(RenderError::InvalidSurface)?;
        let required = (height as usize)
            .checked_mul(stride)
            .ok_or(RenderError::InvalidSurface)?;
        if width == 0
            || height == 0
            || stride < visible
            || !stride.is_multiple_of(4)
            || bytes.len() < required
        {
            return Err(RenderError::InvalidSurface);
        }
        Ok(Self {
            bytes,
            width,
            height,
            stride,
        })
    }

    fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.width, self.height)
    }

    fn clear(&mut self, color: Color) {
        for y in 0..self.height {
            for x in 0..self.width {
                self.put(x as i32, y as i32, color);
            }
        }
    }

    fn put(&mut self, x: i32, y: i32, color: Color) {
        if x < 0 || y < 0 || x as u32 >= self.width || y as u32 >= self.height {
            return;
        }
        let offset = y as usize * self.stride + x as usize * 4;
        self.bytes[offset] = color.blue;
        self.bytes[offset + 1] = color.green;
        self.bytes[offset + 2] = color.red;
        self.bytes[offset + 3] = color.alpha;
    }

    fn get(&self, x: i32, y: i32) -> Color {
        if x < 0 || y < 0 || x as u32 >= self.width || y as u32 >= self.height {
            return TRANSPARENT;
        }
        let offset = y as usize * self.stride + x as usize * 4;
        Color::new(
            self.bytes[offset + 2],
            self.bytes[offset + 1],
            self.bytes[offset],
            self.bytes[offset + 3],
        )
    }
}

/// Rebuild a complete translucent Files surface in BGRA8888 format.
pub fn render(
    bytes: &mut [u8],
    width: u32,
    height: u32,
    stride: usize,
    model: &ExplorerModel,
) -> Result<(), RenderError> {
    let mut canvas = Canvas::new(bytes, width, height, stride)?;
    let layout = Layout::new(width, height);
    canvas.clear(TRANSPARENT);
    fill_rounded(&mut canvas, layout.window, 10, WINDOW, layout.window);

    fill_rounded(&mut canvas, layout.title_bar, 10, TITLE, layout.window);
    fill_rect(
        &mut canvas,
        Rect::new(
            layout.title_bar.x,
            layout.title_bar.y + layout.title_bar.height.saturating_sub(10) as i32,
            layout.title_bar.width,
            layout.title_bar.height.min(10),
        ),
        TITLE,
        layout.window,
    );
    fill_rect(&mut canvas, layout.toolbar, TOOLBAR, layout.window);
    fill_rect(&mut canvas, layout.sidebar, SIDEBAR, layout.window);
    fill_rect(&mut canvas, layout.content, CONTENT, layout.window);
    fill_rect(&mut canvas, layout.status_bar, TITLE, layout.window);

    draw_text(
        &mut canvas,
        Point::new(16, center_text_y(layout.title_bar, 2)),
        2,
        b"FILES",
        TEXT,
        layout.title_bar,
    );
    draw_text(
        &mut canvas,
        Point::new(82, center_text_y(layout.title_bar, 1)),
        1,
        b"XENITH",
        MUTED,
        layout.title_bar,
    );
    if model.focused() {
        fill_rect(
            &mut canvas,
            Rect::new(16, layout.title_bar.height.saturating_sub(3) as i32, 50, 2),
            ACCENT,
            layout.title_bar,
        );
    }
    draw_close(&mut canvas, layout.close_button, layout.title_bar);

    draw_toolbar_button(
        &mut canvas,
        layout.back_button,
        model.can_go_back(),
        ToolbarIcon::Back,
    );
    draw_toolbar_button(&mut canvas, layout.up_button, true, ToolbarIcon::Up);
    draw_toolbar_button(
        &mut canvas,
        layout.refresh_button,
        true,
        ToolbarIcon::Refresh,
    );
    draw_toolbar_button(
        &mut canvas,
        layout.new_folder_button,
        true,
        ToolbarIcon::NewFolder,
    );
    fill_rounded(
        &mut canvas,
        layout.address,
        7,
        if model.address_select_all() {
            ACCENT_SOFT
        } else {
            PANEL
        },
        layout.toolbar,
    );
    draw_rounded_outline(
        &mut canvas,
        layout.address,
        7,
        if model.address_editing() {
            ACCENT
        } else {
            PANEL_BORDER
        },
        layout.toolbar,
    );
    let mut path = [0u8; crate::model::MAX_PATH_BYTES];
    let path_length = if model.address_editing() {
        let source = model.address_bytes();
        let length = source.len().min(path.len());
        path[..length].copy_from_slice(&source[..length]);
        length
    } else {
        model.current_path().write_display(&mut path)
    };
    draw_text_tail(
        &mut canvas,
        Point::new(layout.address.x + 10, center_text_y(layout.address, 1)),
        1,
        &path[..path_length],
        TEXT,
        layout.address.inset(7),
    );

    draw_sidebar(&mut canvas, layout, model);
    draw_directory(&mut canvas, layout, model);
    draw_status(&mut canvas, layout, model);
    Ok(())
}

fn draw_sidebar(canvas: &mut Canvas<'_>, layout: Layout, model: &ExplorerModel) {
    for (index, place) in KnownPlace::ALL.iter().copied().enumerate() {
        let Some(row) = layout.sidebar_row(index) else {
            continue;
        };
        let Some(row_clip) = row.intersect(layout.sidebar) else {
            continue;
        };
        if model.current_path() == place.path() {
            fill_rounded(canvas, row.inset(2), 7, ACCENT_SOFT, row_clip);
            fill_rect(
                canvas,
                Rect::new(row.x + 1, row.y + 7, 3, row.height.saturating_sub(14)),
                ACCENT,
                row_clip,
            );
        }
        draw_place_icon(
            canvas,
            Rect::new(
                row.x + 12,
                row.y + row.height.saturating_sub(16) as i32 / 2,
                18,
                row.height.min(16),
            ),
            place,
            row_clip,
        );
        draw_text(
            canvas,
            Point::new(row.x + 40, center_text_y(row, 1)),
            1,
            place.label(),
            TEXT,
            row_clip,
        );
    }
}

fn draw_directory(canvas: &mut Canvas<'_>, layout: Layout, model: &ExplorerModel) {
    fill_rect(canvas, layout.column_header, TOOLBAR, layout.content);
    let name_x = layout.content.x + 46;
    let type_x = layout.content.x + (layout.content.width * 58 / 100) as i32;
    let size_x = layout.content.x + (layout.content.width * 84 / 100) as i32;
    draw_text(
        canvas,
        Point::new(name_x, center_text_y(layout.column_header, 1)),
        1,
        b"NAME",
        MUTED,
        layout.column_header,
    );
    if layout.content.width >= 300 {
        draw_text(
            canvas,
            Point::new(type_x, center_text_y(layout.column_header, 1)),
            1,
            b"TYPE",
            MUTED,
            layout.column_header,
        );
    }
    if layout.content.width >= 430 {
        draw_text(
            canvas,
            Point::new(size_x, center_text_y(layout.column_header, 1)),
            1,
            b"SIZE",
            MUTED,
            layout.column_header,
        );
    }
    fill_rect(
        canvas,
        Rect::new(
            layout.column_header.x,
            layout.column_header.bottom() as i32 - 1,
            layout.column_header.width,
            1,
        ),
        PANEL_BORDER,
        layout.content,
    );

    let visible = layout.visible_row_count();
    for visible_index in 0..visible {
        let entry_index = model.scroll().saturating_add(visible_index);
        let Some(entry) = model.entries().get(entry_index) else {
            break;
        };
        let Some(row) = layout.row_rect(visible_index) else {
            break;
        };
        let selected = model.selected_index() == Some(entry_index);
        if selected {
            let color = if model.delete_pending() == Some(entry_index) {
                Color::new(126, 49, 59, 244)
            } else {
                ACCENT_SOFT
            };
            fill_rounded(canvas, row.inset(3), 6, color, layout.rows);
        } else if visible_index % 2 == 1 {
            tint_rect(canvas, row, Color::new(255, 255, 255, 255), 5, layout.rows);
        }
        let icon = Rect::new(
            row.x + 14,
            row.y + row.height.saturating_sub(16) as i32 / 2,
            20,
            row.height.min(16),
        );
        draw_entry_icon(canvas, icon, entry, layout.rows);
        draw_text_tail(
            canvas,
            Point::new(name_x, center_text_y(row, 1)),
            1,
            entry.name(),
            TEXT,
            Rect::new(
                name_x,
                row.y,
                (type_x - name_x - 8).max(1) as u32,
                row.height,
            ),
        );
        if layout.content.width >= 300 {
            draw_text(
                canvas,
                Point::new(type_x, center_text_y(row, 1)),
                1,
                entry_type(entry),
                MUTED,
                Rect::new(
                    type_x,
                    row.y,
                    (size_x - type_x - 6).max(1) as u32,
                    row.height,
                ),
            );
        }
        if layout.content.width >= 430 && entry.kind == ENTRY_KIND_REGULAR {
            let mut size = [0u8; 20];
            let length = format_size(entry.size, &mut size);
            draw_text(
                canvas,
                Point::new(size_x, center_text_y(row, 1)),
                1,
                &size[..length],
                MUTED,
                row,
            );
        }
    }

    if model.entry_count() == 0 && layout.rows.height < 50 {
        draw_text(
            canvas,
            Point::new(layout.rows.x + 14, center_text_y(layout.rows, 1)),
            1,
            b"EMPTY FOLDER",
            MUTED,
            layout.rows,
        );
    } else if model.entry_count() == 0 {
        let center_x = layout.rows.x + (layout.rows.width / 2) as i32;
        let center_y = layout.rows.y + (layout.rows.height / 2) as i32;
        draw_folder(
            canvas,
            Rect::new(center_x - 20, center_y - 28, 40, 32),
            layout.rows,
        );
        draw_text(
            canvas,
            Point::new(center_x - 30, center_y + 15),
            1,
            b"THIS FOLDER IS EMPTY",
            MUTED,
            layout.rows,
        );
    }
}

fn draw_status(canvas: &mut Canvas<'_>, layout: Layout, model: &ExplorerModel) {
    fill_rect(
        canvas,
        Rect::new(
            layout.status_bar.x,
            layout.status_bar.y,
            layout.status_bar.width,
            1,
        ),
        PANEL_BORDER,
        layout.status_bar,
    );
    let status = model.status();
    if !status.is_empty() {
        draw_text(
            canvas,
            Point::new(14, center_text_y(layout.status_bar, 1)),
            1,
            status,
            if model.delete_pending().is_some() {
                DANGER
            } else {
                TEXT
            },
            layout.status_bar,
        );
        return;
    }
    let mut count = [0u8; 24];
    let mut length = write_decimal(model.entry_count() as u64, &mut count);
    for &byte in b" ITEMS" {
        if length < count.len() {
            count[length] = byte;
            length += 1;
        }
    }
    draw_text(
        canvas,
        Point::new(14, center_text_y(layout.status_bar, 1)),
        1,
        &count[..length],
        MUTED,
        layout.status_bar,
    );
}

#[derive(Clone, Copy)]
enum ToolbarIcon {
    Back,
    Up,
    Refresh,
    NewFolder,
}

fn draw_toolbar_button(canvas: &mut Canvas<'_>, rect: Rect, enabled: bool, icon: ToolbarIcon) {
    fill_rounded(canvas, rect, 7, PANEL, canvas.bounds());
    draw_rounded_outline(canvas, rect, 7, PANEL_BORDER, canvas.bounds());
    let color = if enabled { TEXT } else { MUTED };
    let center = Point::new(
        rect.x + (rect.width / 2) as i32,
        rect.y + (rect.height / 2) as i32,
    );
    match icon {
        ToolbarIcon::Back => {
            draw_line(
                canvas,
                center.x + 5,
                center.y - 7,
                center.x - 3,
                center.y,
                color,
                rect,
            );
            draw_line(
                canvas,
                center.x - 3,
                center.y,
                center.x + 5,
                center.y + 7,
                color,
                rect,
            );
        },
        ToolbarIcon::Up => {
            draw_line(
                canvas,
                center.x - 7,
                center.y + 4,
                center.x,
                center.y - 4,
                color,
                rect,
            );
            draw_line(
                canvas,
                center.x,
                center.y - 4,
                center.x + 7,
                center.y + 4,
                color,
                rect,
            );
        },
        ToolbarIcon::Refresh => {
            draw_arc(canvas, center, 8, color, rect);
            draw_line(
                canvas,
                center.x + 7,
                center.y - 7,
                center.x + 8,
                center.y,
                color,
                rect,
            );
            draw_line(
                canvas,
                center.x + 7,
                center.y - 7,
                center.x + 1,
                center.y - 6,
                color,
                rect,
            );
        },
        ToolbarIcon::NewFolder => {
            draw_folder(canvas, Rect::new(center.x - 9, center.y - 6, 18, 14), rect);
            draw_line(
                canvas,
                center.x,
                center.y - 4,
                center.x,
                center.y + 7,
                TEXT,
                rect,
            );
            draw_line(
                canvas,
                center.x - 5,
                center.y + 2,
                center.x + 5,
                center.y + 2,
                TEXT,
                rect,
            );
        },
    }
}

fn draw_close(canvas: &mut Canvas<'_>, rect: Rect, clip: Rect) {
    let center_x = rect.x + (rect.width / 2) as i32;
    let center_y = rect.y + (rect.height / 2) as i32;
    draw_line(
        canvas,
        center_x - 5,
        center_y - 5,
        center_x + 5,
        center_y + 5,
        TEXT,
        clip,
    );
    draw_line(
        canvas,
        center_x + 5,
        center_y - 5,
        center_x - 5,
        center_y + 5,
        TEXT,
        clip,
    );
}

fn draw_place_icon(canvas: &mut Canvas<'_>, rect: Rect, place: KnownPlace, clip: Rect) {
    match place {
        KnownPlace::Home => {
            let center = rect.x + (rect.width / 2) as i32;
            draw_line(canvas, rect.x + 1, rect.y + 8, center, rect.y, ACCENT, clip);
            draw_line(
                canvas,
                center,
                rect.y,
                rect.right() as i32 - 2,
                rect.y + 8,
                ACCENT,
                clip,
            );
            fill_rect(
                canvas,
                Rect::new(
                    rect.x + 4,
                    rect.y + 8,
                    rect.width.saturating_sub(8),
                    rect.height.saturating_sub(8),
                ),
                ACCENT,
                clip,
            );
        },
        _ => draw_folder(canvas, rect, clip),
    }
}

fn draw_entry_icon(canvas: &mut Canvas<'_>, rect: Rect, entry: &Entry, clip: Rect) {
    if entry.kind == ENTRY_KIND_DIRECTORY {
        draw_folder(canvas, rect, clip);
    } else {
        draw_file(canvas, rect, clip);
    }
}

fn draw_folder(canvas: &mut Canvas<'_>, rect: Rect, clip: Rect) {
    let tab_width = (rect.width / 2).max(3);
    fill_rounded(
        canvas,
        Rect::new(rect.x, rect.y, tab_width, (rect.height / 3).max(3)),
        2,
        FOLDER,
        clip,
    );
    fill_rounded(
        canvas,
        Rect::new(
            rect.x,
            rect.y + (rect.height / 4) as i32,
            rect.width,
            rect.height.saturating_sub(rect.height / 4),
        ),
        3,
        FOLDER,
        clip,
    );
}

fn draw_file(canvas: &mut Canvas<'_>, rect: Rect, clip: Rect) {
    fill_rounded(canvas, rect, 2, Color::new(174, 193, 221, 255), clip);
    let fold = (rect.width.min(rect.height) / 3).max(2);
    fill_rect(
        canvas,
        Rect::new(rect.right() as i32 - fold as i32, rect.y, fold, fold),
        CONTENT,
        clip,
    );
    fill_rect(
        canvas,
        Rect::new(
            rect.x + 4,
            rect.y + (rect.height / 2) as i32,
            rect.width.saturating_sub(8),
            1,
        ),
        PANEL_BORDER,
        clip,
    );
}

fn entry_type(entry: &Entry) -> &'static [u8] {
    match entry.kind {
        ENTRY_KIND_DIRECTORY => b"FILE FOLDER",
        ENTRY_KIND_REGULAR => b"FILE",
        ENTRY_KIND_SYMLINK => b"LINK",
        _ => b"DEVICE",
    }
}

fn format_size(size: u64, output: &mut [u8]) -> usize {
    let (value, suffix) = if size >= 1024 * 1024 * 1024 {
        (size / (1024 * 1024 * 1024), &b" GB"[..])
    } else if size >= 1024 * 1024 {
        (size / (1024 * 1024), &b" MB"[..])
    } else if size >= 1024 {
        (size / 1024, &b" KB"[..])
    } else {
        (size, &b" B"[..])
    };
    let mut length = write_decimal(value, output);
    for &byte in suffix {
        if length == output.len() {
            break;
        }
        output[length] = byte;
        length += 1;
    }
    length
}

fn write_decimal(mut value: u64, output: &mut [u8]) -> usize {
    if output.is_empty() {
        return 0;
    }
    let mut reverse = [0u8; 20];
    let mut count = 0;
    loop {
        reverse[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let length = count.min(output.len());
    for index in 0..length {
        output[index] = reverse[count - index - 1];
    }
    length
}

fn fill_rect(canvas: &mut Canvas<'_>, rect: Rect, color: Color, clip: Rect) {
    let Some(bounds) = rect
        .intersect(clip)
        .and_then(|value| value.intersect(canvas.bounds()))
    else {
        return;
    };
    for y in bounds.y..bounds.bottom() as i32 {
        for x in bounds.x..bounds.right() as i32 {
            canvas.put(x, y, color);
        }
    }
}

fn tint_rect(canvas: &mut Canvas<'_>, rect: Rect, color: Color, alpha: u8, clip: Rect) {
    let Some(bounds) = rect
        .intersect(clip)
        .and_then(|value| value.intersect(canvas.bounds()))
    else {
        return;
    };
    for y in bounds.y..bounds.bottom() as i32 {
        for x in bounds.x..bounds.right() as i32 {
            let base = canvas.get(x, y);
            canvas.put(x, y, base.mix(color, alpha));
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
    let nearest_x = point
        .x
        .clamp(rect.x + radius, rect.right() as i32 - radius - 1);
    let nearest_y = point
        .y
        .clamp(rect.y + radius, rect.bottom() as i32 - radius - 1);
    let dx = i64::from(point.x - nearest_x);
    let dy = i64::from(point.y - nearest_y);
    dx * dx + dy * dy <= i64::from(radius) * i64::from(radius)
}

fn fill_rounded(canvas: &mut Canvas<'_>, rect: Rect, radius: u32, color: Color, clip: Rect) {
    let Some(bounds) = rect
        .intersect(clip)
        .and_then(|value| value.intersect(canvas.bounds()))
    else {
        return;
    };
    for y in bounds.y..bounds.bottom() as i32 {
        for x in bounds.x..bounds.right() as i32 {
            if rounded_contains(rect, radius, Point::new(x, y)) {
                canvas.put(x, y, color);
            }
        }
    }
}

fn draw_rounded_outline(
    canvas: &mut Canvas<'_>,
    rect: Rect,
    radius: u32,
    color: Color,
    clip: Rect,
) {
    let Some(bounds) = rect
        .intersect(clip)
        .and_then(|value| value.intersect(canvas.bounds()))
    else {
        return;
    };
    let inner = rect.inset(1);
    for y in bounds.y..bounds.bottom() as i32 {
        for x in bounds.x..bounds.right() as i32 {
            let point = Point::new(x, y);
            if rounded_contains(rect, radius, point)
                && (inner.is_empty() || !rounded_contains(inner, radius.saturating_sub(1), point))
            {
                canvas.put(x, y, color);
            }
        }
    }
}

fn draw_line(
    canvas: &mut Canvas<'_>,
    mut x0: i32,
    mut y0: i32,
    x1: i32,
    y1: i32,
    color: Color,
    clip: Rect,
) {
    let dx = (x1 - x0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let dy = -(y1 - y0).abs();
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut error = dx + dy;
    loop {
        let point = Point::new(x0, y0);
        if clip.contains(point) {
            canvas.put(x0, y0, color);
        }
        if x0 == x1 && y0 == y1 {
            break;
        }
        let doubled = error.saturating_mul(2);
        if doubled >= dy {
            error += dy;
            x0 += sx;
        }
        if doubled <= dx {
            error += dx;
            y0 += sy;
        }
    }
}

fn draw_arc(canvas: &mut Canvas<'_>, center: Point, radius: i32, color: Color, clip: Rect) {
    let mut x = radius;
    let mut y = 0;
    let mut error = 1 - radius;
    while x >= y {
        for (dx, dy) in [
            (x, y),
            (y, x),
            (-y, x),
            (-x, y),
            (-x, -y),
            (-y, -x),
            (y, -x),
            (x, -y),
        ] {
            let point = Point::new(center.x + dx, center.y + dy);
            if clip.contains(point) {
                canvas.put(point.x, point.y, color);
            }
        }
        y += 1;
        if error < 0 {
            error += 2 * y + 1;
        } else {
            x -= 1;
            error += 2 * (y - x) + 1;
        }
    }
}

fn draw_text_tail(
    canvas: &mut Canvas<'_>,
    origin: Point,
    scale: u32,
    text: &[u8],
    color: Color,
    clip: Rect,
) {
    let advance = 6usize.saturating_mul(scale.max(1) as usize);
    let capacity = (clip.width as usize / advance).max(1);
    let text = if text.len() > capacity {
        &text[text.len() - capacity..]
    } else {
        text
    };
    draw_text(canvas, origin, scale, text, color, clip);
}

fn center_text_y(rect: Rect, scale: u32) -> i32 {
    let glyph_height = 7u32.saturating_mul(scale.max(1));
    rect.y + rect.height.saturating_sub(glyph_height) as i32 / 2
}

fn draw_text(
    canvas: &mut Canvas<'_>,
    origin: Point,
    scale: u32,
    text: &[u8],
    color: Color,
    clip: Rect,
) {
    let scale = scale.max(1) as i32;
    let advance = 6 * scale;
    for (index, &character) in text.iter().enumerate() {
        let x = origin.x.saturating_add(index as i32 * advance);
        let glyph_bounds = Rect::new(x, origin.y, (5 * scale) as u32, (7 * scale) as u32);
        if glyph_bounds.intersect(clip).is_none() {
            continue;
        }
        for (row, bits) in glyph(character).iter().copied().enumerate() {
            for column in 0..5 {
                if bits & (1 << (4 - column)) != 0 {
                    fill_rect(
                        canvas,
                        Rect::new(
                            x + column * scale,
                            origin.y + row as i32 * scale,
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
        b'_' => [0, 0, 0, 0, 0, 0, 0x1f],
        b'.' => [0, 0, 0, 0, 0, 0x06, 0x06],
        b':' => [0, 0x06, 0x06, 0, 0x06, 0x06, 0],
        b'/' => [0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10],
        b'\\' => [0x10, 0x08, 0x08, 0x04, 0x02, 0x02, 0x01],
        b'(' => [0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02],
        b')' => [0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08],
        b'+' => [0, 0x04, 0x04, 0x1f, 0x04, 0x04, 0],
        b' ' => [0; 7],
        _ => [0x0e, 0x11, 0x01, 0x02, 0x04, 0, 0x04],
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec;

    use super::*;

    #[test]
    fn render_is_deterministic_translucent_and_non_flat() {
        let model = ExplorerModel::new();
        let (width, height, stride) = (720, 460, 720 * 4);
        let mut first = vec![0u8; stride * height];
        let mut second = first.clone();
        render(&mut first, width as u32, height as u32, stride, &model).unwrap();
        render(&mut second, width as u32, height as u32, stride, &model).unwrap();
        assert_eq!(first, second);
        let (pixels, tail) = first.as_chunks::<4>();
        assert!(tail.is_empty());
        assert!(pixels.iter().any(|pixel| pixel[3] == 0));
        assert!(pixels.iter().any(|pixel| pixel[3] > 0));
        assert!(pixels.iter().any(|pixel| pixel != &first[..4]));
    }

    #[test]
    fn render_rejects_invalid_surfaces_and_handles_tiny_ones() {
        assert_eq!(
            render(&mut [0; 16], 4, 4, 15, &ExplorerModel::new()),
            Err(RenderError::InvalidSurface)
        );
        assert!(render(&mut [0; 4], 1, 1, 4, &ExplorerModel::new()).is_ok());
    }

    #[test]
    fn compact_integration_surface_remains_renderable_and_non_flat() {
        let (width, height, stride) = (256usize, 100usize, 256usize * 4);
        let mut pixels = vec![0u8; stride * height];
        render(
            &mut pixels,
            width as u32,
            height as u32,
            stride,
            &ExplorerModel::new(),
        )
        .unwrap();
        let first = [pixels[0], pixels[1], pixels[2], pixels[3]];
        assert!(pixels.as_chunks::<4>().0.iter().any(|pixel| pixel[3] > 0));
        assert!(pixels
            .as_chunks::<4>()
            .0
            .iter()
            .any(|pixel| pixel != &first));
    }

    #[test]
    fn size_format_is_bounded() {
        let mut output = [0; 20];
        let length = format_size(5 * 1024 * 1024, &mut output);
        assert_eq!(&output[..length], b"5 MB");
    }
}
