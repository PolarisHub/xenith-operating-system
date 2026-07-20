//! Stateful ANSI/VT100 terminal parser with a framebuffer renderer.

use crate::devices::fb_font::{GLYPH_HEIGHT, GLYPH_WIDTH};
use crate::devices::framebuffer;
use crate::devices::gfx::{Color as GfxColor, Framebuffer, Rect};
use crate::mm::KVec;

const MAX_CSI_PARAMS: usize = 16;
const TAB_WIDTH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalColor {
    Default,
    Indexed(u8),
    Rgb(u8, u8, u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Attributes {
    pub bold: bool,
    pub dim: bool,
    pub underline: bool,
    pub blink: bool,
    pub reverse: bool,
    pub hidden: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub byte: u8,
    pub foreground: TerminalColor,
    pub background: TerminalColor,
    pub attributes: Attributes,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            byte: b' ',
            foreground: TerminalColor::Default,
            background: TerminalColor::Default,
            attributes: Attributes::default(),
        }
    }
}

pub trait TerminalRenderer {
    fn dimensions(&self) -> (usize, usize);
    fn draw_cell(&mut self, column: usize, row: usize, cell: Cell);
    fn set_cursor(&mut self, _column: usize, _row: usize, _visible: bool) {}
}

pub struct FramebufferRenderer {
    framebuffer: Framebuffer,
    default_foreground: GfxColor,
    default_background: GfxColor,
}

impl FramebufferRenderer {
    #[must_use]
    pub const fn new(framebuffer: Framebuffer) -> Self {
        Self {
            framebuffer,
            default_foreground: GfxColor::new(0xd0, 0xd0, 0xd0),
            default_background: GfxColor::new(0x10, 0x10, 0x10),
        }
    }

    #[must_use]
    pub const fn with_defaults(
        framebuffer: Framebuffer,
        foreground: GfxColor,
        background: GfxColor,
    ) -> Self {
        Self {
            framebuffer,
            default_foreground: foreground,
            default_background: background,
        }
    }

    #[must_use]
    pub const fn framebuffer(&self) -> &Framebuffer {
        &self.framebuffer
    }

    fn resolve(&self, color: TerminalColor, foreground: bool, bold: bool) -> GfxColor {
        match color {
            TerminalColor::Default => {
                if foreground {
                    self.default_foreground
                } else {
                    self.default_background
                }
            },
            TerminalColor::Rgb(r, g, b) => GfxColor::new(r, g, b),
            TerminalColor::Indexed(index) => indexed_color(index, bold),
        }
    }
}

impl TerminalRenderer for FramebufferRenderer {
    fn dimensions(&self) -> (usize, usize) {
        (
            (self.framebuffer.width().max(0) as usize) / GLYPH_WIDTH,
            (self.framebuffer.height().max(0) as usize) / GLYPH_HEIGHT,
        )
    }

    fn draw_cell(&mut self, column: usize, row: usize, cell: Cell) {
        if framebuffer::userspace_suspended() {
            return;
        }
        let mut foreground = self.resolve(
            cell.foreground,
            true,
            cell.attributes.bold && !cell.attributes.dim,
        );
        let mut background = self.resolve(cell.background, false, false);
        if cell.attributes.reverse {
            core::mem::swap(&mut foreground, &mut background);
        }
        if cell.attributes.hidden {
            foreground = background;
        }
        let x = (column * GLYPH_WIDTH) as i32;
        let y = (row * GLYPH_HEIGHT) as i32;
        self.framebuffer
            .draw_char(x, y, cell.byte, foreground, background);
        if cell.attributes.underline {
            self.framebuffer.draw_line(
                x,
                y + GLYPH_HEIGHT as i32 - 2,
                x + GLYPH_WIDTH as i32 - 1,
                y + GLYPH_HEIGHT as i32 - 2,
                foreground,
            );
        }
    }

    fn set_cursor(&mut self, column: usize, row: usize, visible: bool) {
        if !visible || framebuffer::userspace_suspended() {
            return;
        }
        let x = (column * GLYPH_WIDTH) as i32;
        let y = (row * GLYPH_HEIGHT + GLYPH_HEIGHT - 2) as i32;
        self.framebuffer.fill_rect(
            Rect::new(x, y, GLYPH_WIDTH as i32, 2),
            self.default_foreground,
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalError {
    ZeroSizedRenderer,
    GeometryOverflow,
}

#[derive(Clone, Copy)]
struct Cursor {
    column: usize,
    row: usize,
}

#[derive(Clone, Copy)]
struct Style {
    foreground: TerminalColor,
    background: TerminalColor,
    attributes: Attributes,
}

impl Default for Style {
    fn default() -> Self {
        Self {
            foreground: TerminalColor::Default,
            background: TerminalColor::Default,
            attributes: Attributes::default(),
        }
    }
}

#[derive(Clone, Copy)]
struct CsiState {
    private: bool,
    params: [u16; MAX_CSI_PARAMS],
    count: usize,
    current: u16,
    has_current: bool,
}

impl CsiState {
    const fn new() -> Self {
        Self {
            private: false,
            params: [0; MAX_CSI_PARAMS],
            count: 0,
            current: 0,
            has_current: false,
        }
    }

    fn push(&mut self) {
        if self.count < MAX_CSI_PARAMS {
            self.params[self.count] = if self.has_current { self.current } else { 0 };
            self.count += 1;
        }
        self.current = 0;
        self.has_current = false;
    }

    fn finish(mut self) -> Self {
        if self.has_current || self.count == 0 {
            self.push();
        }
        self
    }
}

#[derive(Clone, Copy)]
enum ParserState {
    Ground,
    Escape,
    Csi(CsiState),
    Osc { escaped: bool },
}

pub struct Terminal<R: TerminalRenderer> {
    renderer: R,
    columns: usize,
    rows: usize,
    cells: KVec<Cell>,
    alternate_cells: KVec<Cell>,
    cursor: Cursor,
    primary_cursor: Cursor,
    alternate_cursor: Cursor,
    saved_cursor: Cursor,
    style: Style,
    parser: ParserState,
    scroll_top: usize,
    scroll_bottom: usize,
    wraparound: bool,
    pending_wrap: bool,
    cursor_visible: bool,
    alternate_active: bool,
}

impl<R: TerminalRenderer> Terminal<R> {
    pub fn new(renderer: R) -> Result<Self, TerminalError> {
        Self::new_with_initial_paint(renderer, true)
    }

    /// Construct a terminal without touching the renderer yet.
    ///
    /// The UEFI boot path uses this while its splash is still visible. The
    /// first real console write resets the terminal, which paints the normal
    /// background and cursor immediately before rendering that output.
    pub fn new_preserving(renderer: R) -> Result<Self, TerminalError> {
        Self::new_with_initial_paint(renderer, false)
    }

    fn new_with_initial_paint(mut renderer: R, paint: bool) -> Result<Self, TerminalError> {
        let (columns, rows) = renderer.dimensions();
        if columns == 0 || rows == 0 {
            return Err(TerminalError::ZeroSizedRenderer);
        }
        let count = columns
            .checked_mul(rows)
            .ok_or(TerminalError::GeometryOverflow)?;
        let cells = alloc::vec![Cell::default(); count];
        let alternate_cells = alloc::vec![Cell::default(); count];
        if paint {
            for row in 0..rows {
                for column in 0..columns {
                    renderer.draw_cell(column, row, Cell::default());
                }
            }
            renderer.set_cursor(0, 0, true);
        }
        Ok(Self {
            renderer,
            columns,
            rows,
            cells,
            alternate_cells,
            cursor: Cursor { column: 0, row: 0 },
            primary_cursor: Cursor { column: 0, row: 0 },
            alternate_cursor: Cursor { column: 0, row: 0 },
            saved_cursor: Cursor { column: 0, row: 0 },
            style: Style::default(),
            parser: ParserState::Ground,
            scroll_top: 0,
            scroll_bottom: rows - 1,
            wraparound: true,
            pending_wrap: false,
            cursor_visible: true,
            alternate_active: false,
        })
    }

    #[must_use]
    pub const fn dimensions(&self) -> (usize, usize) {
        (self.columns, self.rows)
    }

    #[must_use]
    pub const fn cursor(&self) -> (usize, usize) {
        (self.cursor.column, self.cursor.row)
    }

    #[must_use]
    pub fn cell(&self, column: usize, row: usize) -> Option<Cell> {
        self.index(column, row).map(|index| self.cells[index])
    }

    #[must_use]
    pub const fn cursor_visible(&self) -> bool {
        self.cursor_visible
    }

    pub fn write(&mut self, bytes: &[u8]) {
        let old = self.cells[self.cursor.row * self.columns + self.cursor.column];
        self.renderer
            .draw_cell(self.cursor.column, self.cursor.row, old);
        for &byte in bytes {
            self.advance_parser(byte);
        }
        self.renderer
            .set_cursor(self.cursor.column, self.cursor.row, self.cursor_visible);
    }

    pub fn reset(&mut self) {
        self.cursor = Cursor { column: 0, row: 0 };
        self.primary_cursor = self.cursor;
        self.alternate_cursor = self.cursor;
        self.saved_cursor = self.cursor;
        self.style = Style::default();
        self.parser = ParserState::Ground;
        self.scroll_top = 0;
        self.scroll_bottom = self.rows - 1;
        self.wraparound = true;
        self.pending_wrap = false;
        self.cursor_visible = true;
        if self.alternate_active {
            core::mem::swap(&mut self.cells, &mut self.alternate_cells);
            self.alternate_active = false;
        }
        self.alternate_cells.fill(Cell::default());
        self.clear_rows(0, self.rows - 1);
        self.renderer.set_cursor(0, 0, true);
    }

    /// Repaint the complete saved terminal model and its current cursor.
    ///
    /// Display ownership uses this after a userspace scanout session ends.
    /// Writes received while rendering was suspended still updated `cells`,
    /// so one bounded redraw restores the exact current terminal contents.
    pub fn redraw_all(&mut self) {
        self.redraw_rows(0, self.rows - 1);
        self.renderer
            .set_cursor(self.cursor.column, self.cursor.row, self.cursor_visible);
    }

    #[must_use]
    pub fn into_renderer(self) -> R {
        self.renderer
    }

    fn advance_parser(&mut self, byte: u8) {
        let state = core::mem::replace(&mut self.parser, ParserState::Ground);
        self.parser = match state {
            ParserState::Ground => self.ground(byte),
            ParserState::Escape => self.escape(byte),
            ParserState::Csi(mut csi) => match byte {
                b'0'..=b'9' => {
                    csi.has_current = true;
                    csi.current = csi
                        .current
                        .saturating_mul(10)
                        .saturating_add(u16::from(byte - b'0'));
                    ParserState::Csi(csi)
                },
                b';' | b':' => {
                    csi.push();
                    ParserState::Csi(csi)
                },
                b'?' if csi.count == 0 && !csi.has_current => {
                    csi.private = true;
                    ParserState::Csi(csi)
                },
                0x40..=0x7e => {
                    let csi = csi.finish();
                    self.handle_csi(byte, csi.private, &csi.params[..csi.count]);
                    ParserState::Ground
                },
                0x1b => ParserState::Escape,
                _ => ParserState::Csi(csi),
            },
            ParserState::Osc { escaped } => match (escaped, byte) {
                (_, 0x07) => ParserState::Ground,
                (true, b'\\') => ParserState::Ground,
                (_, 0x1b) => ParserState::Osc { escaped: true },
                _ => ParserState::Osc { escaped: false },
            },
        };
    }

    fn ground(&mut self, byte: u8) -> ParserState {
        match byte {
            0x1b => ParserState::Escape,
            0x00 | 0x07 => ParserState::Ground,
            0x08 => {
                self.cursor.column = self.cursor.column.saturating_sub(1);
                self.pending_wrap = false;
                ParserState::Ground
            },
            b'\t' => {
                self.cursor.column =
                    ((self.cursor.column / TAB_WIDTH + 1) * TAB_WIDTH).min(self.columns - 1);
                self.pending_wrap = false;
                ParserState::Ground
            },
            b'\n' | 0x0b | 0x0c => {
                self.line_feed();
                ParserState::Ground
            },
            b'\r' => {
                self.cursor.column = 0;
                self.pending_wrap = false;
                ParserState::Ground
            },
            0x20..=0xff => {
                self.put_byte(byte);
                ParserState::Ground
            },
            _ => ParserState::Ground,
        }
    }

    fn escape(&mut self, byte: u8) -> ParserState {
        match byte {
            b'[' => ParserState::Csi(CsiState::new()),
            b']' => ParserState::Osc { escaped: false },
            b'7' => {
                self.saved_cursor = self.cursor;
                ParserState::Ground
            },
            b'8' => {
                self.cursor = self.saved_cursor;
                self.clamp_cursor();
                ParserState::Ground
            },
            b'D' => {
                self.line_feed();
                ParserState::Ground
            },
            b'E' => {
                self.cursor.column = 0;
                self.line_feed();
                ParserState::Ground
            },
            b'M' => {
                self.reverse_index();
                ParserState::Ground
            },
            b'c' => {
                self.reset();
                ParserState::Ground
            },
            0x1b => ParserState::Escape,
            _ => ParserState::Ground,
        }
    }

    fn handle_csi(&mut self, final_byte: u8, private: bool, params: &[u16]) {
        let first = param(params, 0, 1) as usize;
        match final_byte {
            b'A' => self.cursor.row = self.cursor.row.saturating_sub(first),
            b'B' => self.cursor.row = (self.cursor.row + first).min(self.rows - 1),
            b'C' => self.cursor.column = (self.cursor.column + first).min(self.columns - 1),
            b'D' => self.cursor.column = self.cursor.column.saturating_sub(first),
            b'E' => {
                self.cursor.row = (self.cursor.row + first).min(self.rows - 1);
                self.cursor.column = 0;
            },
            b'F' => {
                self.cursor.row = self.cursor.row.saturating_sub(first);
                self.cursor.column = 0;
            },
            b'G' | b'`' => self.cursor.column = first.saturating_sub(1).min(self.columns - 1),
            b'H' | b'f' => {
                self.cursor.row = first.saturating_sub(1).min(self.rows - 1);
                self.cursor.column = (param(params, 1, 1) as usize)
                    .saturating_sub(1)
                    .min(self.columns - 1);
            },
            b'J' => self.erase_display(params.first().copied().unwrap_or(0)),
            b'K' => self.erase_line(params.first().copied().unwrap_or(0)),
            b'm' => self.set_graphics_rendition(params),
            b'r' if !private => self.set_scroll_region(params),
            b's' => self.saved_cursor = self.cursor,
            b'u' => {
                self.cursor = self.saved_cursor;
                self.clamp_cursor();
            },
            b'S' => self.scroll_up(self.scroll_top, self.scroll_bottom, first),
            b'T' => self.scroll_down(self.scroll_top, self.scroll_bottom, first),
            b'L' => {
                if (self.scroll_top..=self.scroll_bottom).contains(&self.cursor.row) {
                    self.scroll_down(self.cursor.row, self.scroll_bottom, first);
                }
            },
            b'M' => {
                if (self.scroll_top..=self.scroll_bottom).contains(&self.cursor.row) {
                    self.scroll_up(self.cursor.row, self.scroll_bottom, first);
                }
            },
            b'@' => self.insert_characters(first),
            b'P' => self.delete_characters(first),
            b'X' => self.erase_characters(first),
            b'h' if private => self.set_private_modes(params, true),
            b'l' if private => self.set_private_modes(params, false),
            _ => {},
        }
        self.pending_wrap = false;
    }

    fn put_byte(&mut self, byte: u8) {
        if self.pending_wrap {
            self.cursor.column = 0;
            self.line_feed();
            self.pending_wrap = false;
        }
        let cell = Cell {
            byte,
            foreground: self.style.foreground,
            background: self.style.background,
            attributes: self.style.attributes,
        };
        self.set_cell(self.cursor.column, self.cursor.row, cell);
        if self.cursor.column + 1 == self.columns {
            self.pending_wrap = self.wraparound;
        } else {
            self.cursor.column += 1;
        }
    }

    fn line_feed(&mut self) {
        self.pending_wrap = false;
        if self.cursor.row == self.scroll_bottom {
            self.scroll_up(self.scroll_top, self.scroll_bottom, 1);
        } else if self.cursor.row + 1 < self.rows {
            self.cursor.row += 1;
        }
    }

    fn reverse_index(&mut self) {
        self.pending_wrap = false;
        if self.cursor.row == self.scroll_top {
            self.scroll_down(self.scroll_top, self.scroll_bottom, 1);
        } else {
            self.cursor.row = self.cursor.row.saturating_sub(1);
        }
    }

    fn set_cell(&mut self, column: usize, row: usize, cell: Cell) {
        if let Some(index) = self.index(column, row) {
            self.cells[index] = cell;
            self.renderer.draw_cell(column, row, cell);
        }
    }

    fn blank_cell(&self) -> Cell {
        Cell {
            byte: b' ',
            foreground: self.style.foreground,
            background: self.style.background,
            attributes: Attributes::default(),
        }
    }

    fn index(&self, column: usize, row: usize) -> Option<usize> {
        if column < self.columns && row < self.rows {
            Some(row * self.columns + column)
        } else {
            None
        }
    }

    fn redraw_rows(&mut self, top: usize, bottom: usize) {
        for row in top..=bottom {
            for column in 0..self.columns {
                let cell = self.cells[row * self.columns + column];
                self.renderer.draw_cell(column, row, cell);
            }
        }
    }

    fn clear_rows(&mut self, top: usize, bottom: usize) {
        let blank = self.blank_cell();
        for row in top..=bottom {
            for column in 0..self.columns {
                let index = row * self.columns + column;
                self.cells[index] = blank;
                self.renderer.draw_cell(column, row, blank);
            }
        }
    }

    fn scroll_up(&mut self, top: usize, bottom: usize, count: usize) {
        if top > bottom || bottom >= self.rows {
            return;
        }
        let height = bottom - top + 1;
        let count = count.max(1).min(height);
        if count < height {
            for row in top..=bottom - count {
                let source = row + count;
                for column in 0..self.columns {
                    self.cells[row * self.columns + column] =
                        self.cells[source * self.columns + column];
                }
            }
        }
        let blank = self.blank_cell();
        for row in bottom + 1 - count..=bottom {
            self.cells[row * self.columns..(row + 1) * self.columns].fill(blank);
        }
        self.redraw_rows(top, bottom);
    }

    fn scroll_down(&mut self, top: usize, bottom: usize, count: usize) {
        if top > bottom || bottom >= self.rows {
            return;
        }
        let height = bottom - top + 1;
        let count = count.max(1).min(height);
        for row in (top + count..=bottom).rev() {
            let source = row - count;
            for column in 0..self.columns {
                self.cells[row * self.columns + column] =
                    self.cells[source * self.columns + column];
            }
        }
        let blank = self.blank_cell();
        for row in top..top + count {
            self.cells[row * self.columns..(row + 1) * self.columns].fill(blank);
        }
        self.redraw_rows(top, bottom);
    }

    fn erase_display(&mut self, mode: u16) {
        let blank = self.blank_cell();
        match mode {
            0 => {
                for row in self.cursor.row..self.rows {
                    let start = if row == self.cursor.row {
                        self.cursor.column
                    } else {
                        0
                    };
                    for column in start..self.columns {
                        self.set_cell(column, row, blank);
                    }
                }
            },
            1 => {
                for row in 0..=self.cursor.row {
                    let end = if row == self.cursor.row {
                        self.cursor.column
                    } else {
                        self.columns - 1
                    };
                    for column in 0..=end {
                        self.set_cell(column, row, blank);
                    }
                }
            },
            2 | 3 => self.clear_rows(0, self.rows - 1),
            _ => {},
        }
    }

    fn erase_line(&mut self, mode: u16) {
        let blank = self.blank_cell();
        let (start, end) = match mode {
            0 => (self.cursor.column, self.columns - 1),
            1 => (0, self.cursor.column),
            2 => (0, self.columns - 1),
            _ => return,
        };
        for column in start..=end {
            self.set_cell(column, self.cursor.row, blank);
        }
    }

    fn insert_characters(&mut self, count: usize) {
        let count = count.max(1).min(self.columns - self.cursor.column);
        let row_start = self.cursor.row * self.columns;
        for column in (self.cursor.column + count..self.columns).rev() {
            self.cells[row_start + column] = self.cells[row_start + column - count];
        }
        let blank = self.blank_cell();
        self.cells[row_start + self.cursor.column..row_start + self.cursor.column + count]
            .fill(blank);
        self.redraw_rows(self.cursor.row, self.cursor.row);
    }

    fn delete_characters(&mut self, count: usize) {
        let count = count.max(1).min(self.columns - self.cursor.column);
        let row_start = self.cursor.row * self.columns;
        for column in self.cursor.column..self.columns - count {
            self.cells[row_start + column] = self.cells[row_start + column + count];
        }
        let blank = self.blank_cell();
        self.cells[row_start + self.columns - count..row_start + self.columns].fill(blank);
        self.redraw_rows(self.cursor.row, self.cursor.row);
    }

    fn erase_characters(&mut self, count: usize) {
        let end = (self.cursor.column + count.max(1)).min(self.columns);
        let blank = self.blank_cell();
        for column in self.cursor.column..end {
            self.set_cell(column, self.cursor.row, blank);
        }
    }

    fn set_scroll_region(&mut self, params: &[u16]) {
        let top = (param(params, 0, 1) as usize).saturating_sub(1);
        let bottom = (param(params, 1, self.rows as u16) as usize).saturating_sub(1);
        if top < bottom && bottom < self.rows {
            self.scroll_top = top;
            self.scroll_bottom = bottom;
            self.cursor = Cursor { column: 0, row: 0 };
        }
    }

    fn set_private_modes(&mut self, params: &[u16], enabled: bool) {
        for &mode in params {
            match mode {
                7 => self.wraparound = enabled,
                25 => self.cursor_visible = enabled,
                47 => self.use_alternate_screen(enabled, false),
                1047 => self.use_alternate_screen(enabled, true),
                1049 => self.use_alternate_screen(enabled, true),
                _ => {},
            }
        }
    }

    fn use_alternate_screen(&mut self, enabled: bool, clear: bool) {
        if enabled == self.alternate_active {
            if enabled && clear {
                self.clear_rows(0, self.rows - 1);
                self.cursor = Cursor { column: 0, row: 0 };
            }
            return;
        }
        if enabled {
            self.primary_cursor = self.cursor;
            core::mem::swap(&mut self.cells, &mut self.alternate_cells);
            self.cursor = self.alternate_cursor;
            self.alternate_active = true;
            if clear {
                self.cells.fill(Cell::default());
                self.cursor = Cursor { column: 0, row: 0 };
            }
        } else {
            self.alternate_cursor = self.cursor;
            core::mem::swap(&mut self.cells, &mut self.alternate_cells);
            self.cursor = self.primary_cursor;
            self.alternate_active = false;
        }
        self.pending_wrap = false;
        self.redraw_rows(0, self.rows - 1);
    }

    fn set_graphics_rendition(&mut self, params: &[u16]) {
        if params.is_empty() {
            self.style = Style::default();
            return;
        }
        let mut index = 0;
        while index < params.len() {
            let code = params[index];
            match code {
                0 => self.style = Style::default(),
                1 => self.style.attributes.bold = true,
                2 => self.style.attributes.dim = true,
                4 => self.style.attributes.underline = true,
                5 | 6 => self.style.attributes.blink = true,
                7 => self.style.attributes.reverse = true,
                8 => self.style.attributes.hidden = true,
                22 => {
                    self.style.attributes.bold = false;
                    self.style.attributes.dim = false;
                },
                24 => self.style.attributes.underline = false,
                25 => self.style.attributes.blink = false,
                27 => self.style.attributes.reverse = false,
                28 => self.style.attributes.hidden = false,
                30..=37 => self.style.foreground = TerminalColor::Indexed((code - 30) as u8),
                39 => self.style.foreground = TerminalColor::Default,
                40..=47 => self.style.background = TerminalColor::Indexed((code - 40) as u8),
                49 => self.style.background = TerminalColor::Default,
                90..=97 => self.style.foreground = TerminalColor::Indexed((code - 90 + 8) as u8),
                100..=107 => self.style.background = TerminalColor::Indexed((code - 100 + 8) as u8),
                38 | 48 => {
                    let foreground = code == 38;
                    if params.get(index + 1) == Some(&5) {
                        if let Some(&color) = params.get(index + 2) {
                            let value = TerminalColor::Indexed(color.min(255) as u8);
                            if foreground {
                                self.style.foreground = value;
                            } else {
                                self.style.background = value;
                            }
                            index += 2;
                        }
                    } else if params.get(index + 1) == Some(&2) && index + 4 < params.len() {
                        let value = TerminalColor::Rgb(
                            params[index + 2].min(255) as u8,
                            params[index + 3].min(255) as u8,
                            params[index + 4].min(255) as u8,
                        );
                        if foreground {
                            self.style.foreground = value;
                        } else {
                            self.style.background = value;
                        }
                        index += 4;
                    }
                },
                _ => {},
            }
            index += 1;
        }
    }

    fn clamp_cursor(&mut self) {
        self.cursor.column = self.cursor.column.min(self.columns - 1);
        self.cursor.row = self.cursor.row.min(self.rows - 1);
    }
}

impl<R: TerminalRenderer> core::fmt::Write for Terminal<R> {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        self.write(text.as_bytes());
        Ok(())
    }
}

fn param(params: &[u16], index: usize, default: u16) -> u16 {
    match params.get(index).copied() {
        Some(0) | None => default,
        Some(value) => value,
    }
}

fn indexed_color(mut index: u8, bold: bool) -> GfxColor {
    if bold && index < 8 {
        index += 8;
    }
    const ANSI: [(u8, u8, u8); 16] = [
        (0x00, 0x00, 0x00),
        (0xaa, 0x00, 0x00),
        (0x00, 0xaa, 0x00),
        (0xaa, 0x55, 0x00),
        (0x00, 0x00, 0xaa),
        (0xaa, 0x00, 0xaa),
        (0x00, 0xaa, 0xaa),
        (0xaa, 0xaa, 0xaa),
        (0x55, 0x55, 0x55),
        (0xff, 0x55, 0x55),
        (0x55, 0xff, 0x55),
        (0xff, 0xff, 0x55),
        (0x55, 0x55, 0xff),
        (0xff, 0x55, 0xff),
        (0x55, 0xff, 0xff),
        (0xff, 0xff, 0xff),
    ];
    if index < 16 {
        let (r, g, b) = ANSI[index as usize];
        return GfxColor::new(r, g, b);
    }
    if index < 232 {
        let cube = index - 16;
        let r = cube / 36;
        let g = (cube / 6) % 6;
        let b = cube % 6;
        let scale = |value: u8| if value == 0 { 0 } else { 55 + value * 40 };
        return GfxColor::new(scale(r), scale(g), scale(b));
    }
    let gray = 8 + (index - 232) * 10;
    GfxColor::new(gray, gray, gray)
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{Cell, Terminal, TerminalRenderer};

    struct CountingRenderer {
        draws: Arc<AtomicUsize>,
        cursors: Arc<AtomicUsize>,
    }

    impl TerminalRenderer for CountingRenderer {
        fn dimensions(&self) -> (usize, usize) {
            (4, 2)
        }

        fn draw_cell(&mut self, _column: usize, _row: usize, _cell: Cell) {
            self.draws.fetch_add(1, Ordering::Relaxed);
        }

        fn set_cursor(&mut self, _column: usize, _row: usize, _visible: bool) {
            self.cursors.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn preserving_constructor_does_not_touch_the_existing_framebuffer() {
        let draws = Arc::new(AtomicUsize::new(0));
        let cursors = Arc::new(AtomicUsize::new(0));
        let renderer = CountingRenderer {
            draws: Arc::clone(&draws),
            cursors: Arc::clone(&cursors),
        };

        let mut terminal = Terminal::new_preserving(renderer).expect("valid test geometry");
        assert_eq!(draws.load(Ordering::Relaxed), 0);
        assert_eq!(cursors.load(Ordering::Relaxed), 0);

        terminal.reset();
        assert_eq!(draws.load(Ordering::Relaxed), 8);
        assert_eq!(cursors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn redraw_all_repaints_saved_cells_and_cursor() {
        let draws = Arc::new(AtomicUsize::new(0));
        let cursors = Arc::new(AtomicUsize::new(0));
        let renderer = CountingRenderer {
            draws: Arc::clone(&draws),
            cursors: Arc::clone(&cursors),
        };
        let mut terminal = Terminal::new_preserving(renderer).expect("valid test geometry");
        terminal.write(b"A");
        draws.store(0, Ordering::Relaxed);
        cursors.store(0, Ordering::Relaxed);

        terminal.redraw_all();

        assert_eq!(draws.load(Ordering::Relaxed), 8);
        assert_eq!(cursors.load(Ordering::Relaxed), 1);
    }
}
