//! Responsive, integer-only layout and hit testing for the Files window.

pub const SIDEBAR_PLACE_COUNT: usize = 7;
pub const ROW_HEIGHT: u32 = 34;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl Point {
    #[must_use]
    pub const fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    #[must_use]
    pub const fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    #[must_use]
    pub const fn right(self) -> i64 {
        self.x as i64 + self.width as i64
    }

    #[must_use]
    pub const fn bottom(self) -> i64 {
        self.y as i64 + self.height as i64
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.width == 0 || self.height == 0
    }

    #[must_use]
    pub const fn contains(self, point: Point) -> bool {
        point.x as i64 >= self.x as i64
            && point.y as i64 >= self.y as i64
            && (point.x as i64) < self.right()
            && (point.y as i64) < self.bottom()
    }

    #[must_use]
    pub fn intersect(self, other: Self) -> Option<Self> {
        let left = i64::from(self.x).max(i64::from(other.x));
        let top = i64::from(self.y).max(i64::from(other.y));
        let right = self.right().min(other.right());
        let bottom = self.bottom().min(other.bottom());
        if right <= left || bottom <= top {
            return None;
        }
        Some(Self::new(
            left as i32,
            top as i32,
            (right - left) as u32,
            (bottom - top) as u32,
        ))
    }

    #[must_use]
    pub const fn inset(self, amount: u32) -> Self {
        let horizontal = amount.saturating_mul(2);
        let vertical = amount.saturating_mul(2);
        Self::new(
            self.x.saturating_add(amount as i32),
            self.y.saturating_add(amount as i32),
            self.width.saturating_sub(horizontal),
            self.height.saturating_sub(vertical),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HitTarget {
    None,
    Close,
    Back,
    Up,
    Refresh,
    NewFolder,
    Address,
    Sidebar(usize),
    Row(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layout {
    pub window: Rect,
    pub title_bar: Rect,
    pub close_button: Rect,
    pub toolbar: Rect,
    pub back_button: Rect,
    pub up_button: Rect,
    pub refresh_button: Rect,
    pub new_folder_button: Rect,
    pub address: Rect,
    pub sidebar: Rect,
    pub content: Rect,
    pub column_header: Rect,
    pub rows: Rect,
    pub status_bar: Rect,
    sidebar_rows: [Rect; SIDEBAR_PLACE_COUNT],
    row_height: u32,
}

impl Layout {
    #[must_use]
    pub fn new(width: u32, height: u32) -> Self {
        let width = width.max(1);
        let height = height.max(1);
        let compact = height < 180;
        let title_height = height.min(if compact { 24 } else { 38 });
        let remaining_after_title = height.saturating_sub(title_height);
        let toolbar_height = remaining_after_title.min(if compact { 30 } else { 48 });
        let status_height = remaining_after_title
            .saturating_sub(toolbar_height)
            .min(if compact { 16 } else { 28 });
        let body_y = title_height.saturating_add(toolbar_height);
        let body_height = height.saturating_sub(body_y).saturating_sub(status_height);
        let sidebar_width = if width >= 480 {
            (width / 4).clamp(156, 184)
        } else {
            (width / 3).clamp(92, 132)
        }
        .min(width.saturating_sub(1));

        let title_bar = Rect::new(0, 0, width, title_height);
        let close_width = width.min(44);
        let close_button = Rect::new(
            width.saturating_sub(close_width) as i32,
            0,
            close_width,
            title_height,
        );
        let toolbar = Rect::new(0, title_height as i32, width, toolbar_height);
        let button_size = toolbar_height.saturating_sub(12).clamp(1, 34);
        let button_y = title_height.saturating_add(toolbar_height.saturating_sub(button_size) / 2);
        let mut button_x = 10u32.min(width.saturating_sub(1));
        let back_button = Rect::new(button_x as i32, button_y as i32, button_size, button_size);
        button_x = button_x.saturating_add(button_size).saturating_add(6);
        let up_button = Rect::new(button_x as i32, button_y as i32, button_size, button_size);
        button_x = button_x.saturating_add(button_size).saturating_add(6);
        let refresh_button = Rect::new(button_x as i32, button_y as i32, button_size, button_size);
        button_x = button_x.saturating_add(button_size).saturating_add(8);
        let new_folder_button =
            Rect::new(button_x as i32, button_y as i32, button_size, button_size);
        button_x = button_x.saturating_add(button_size).saturating_add(10);
        let address_right_margin = 10;
        let address = Rect::new(
            button_x as i32,
            button_y as i32,
            width
                .saturating_sub(button_x)
                .saturating_sub(address_right_margin),
            button_size,
        );

        let sidebar = Rect::new(0, body_y as i32, sidebar_width, body_height);
        let content = Rect::new(
            sidebar_width as i32,
            body_y as i32,
            width.saturating_sub(sidebar_width),
            body_height,
        );
        let header_height = body_height.min(if compact { 12 } else { 28 });
        let column_header = Rect::new(content.x, content.y, content.width, header_height);
        let rows = Rect::new(
            content.x,
            content.y.saturating_add(header_height as i32),
            content.width,
            content.height.saturating_sub(header_height),
        );
        let status_bar = Rect::new(
            0,
            height.saturating_sub(status_height) as i32,
            width,
            status_height,
        );

        let mut sidebar_rows = [Rect::default(); SIDEBAR_PLACE_COUNT];
        let first_inset = if compact { 1 } else { 8 }.min(body_height);
        let available_sidebar_height = body_height.saturating_sub(first_inset);
        let preferred_row_height = if compact { 26 } else { 36 };
        let fitted_row_height = available_sidebar_height / SIDEBAR_PLACE_COUNT as u32;
        let sidebar_row_height = if fitted_row_height >= 10 {
            preferred_row_height.min(fitted_row_height)
        } else {
            preferred_row_height.min(available_sidebar_height).max(1)
        };
        let first_y = body_y.saturating_add(first_inset);
        for (index, row) in sidebar_rows.iter_mut().enumerate() {
            let candidate = Rect::new(
                6,
                first_y.saturating_add(index as u32 * sidebar_row_height) as i32,
                sidebar_width.saturating_sub(12),
                sidebar_row_height,
            );
            *row = if candidate.intersect(sidebar) == Some(candidate) {
                candidate
            } else {
                Rect::default()
            };
        }

        let row_height = if compact { 18 } else { ROW_HEIGHT };

        Self {
            window: Rect::new(0, 0, width, height),
            title_bar,
            close_button,
            toolbar,
            back_button,
            up_button,
            refresh_button,
            new_folder_button,
            address,
            sidebar,
            content,
            column_header,
            rows,
            status_bar,
            sidebar_rows,
            row_height,
        }
    }

    #[must_use]
    pub const fn width(self) -> u32 {
        self.window.width
    }

    #[must_use]
    pub const fn height(self) -> u32 {
        self.window.height
    }

    #[must_use]
    pub const fn visible_row_count(self) -> usize {
        (self.rows.height / self.row_height) as usize
    }

    #[must_use]
    pub fn sidebar_row(self, index: usize) -> Option<Rect> {
        self.sidebar_rows.get(index).copied()
    }

    #[must_use]
    pub fn row_rect(self, visible_index: usize) -> Option<Rect> {
        let y = (visible_index as u32).checked_mul(self.row_height)?;
        if y >= self.rows.height {
            return None;
        }
        Some(Rect::new(
            self.rows.x,
            self.rows.y.saturating_add(y as i32),
            self.rows.width,
            self.row_height.min(self.rows.height - y),
        ))
    }

    #[must_use]
    pub fn hit_test(self, point: Point, scroll: usize, entry_count: usize) -> HitTarget {
        for (rect, target) in [
            (self.close_button, HitTarget::Close),
            (self.back_button, HitTarget::Back),
            (self.up_button, HitTarget::Up),
            (self.refresh_button, HitTarget::Refresh),
            (self.new_folder_button, HitTarget::NewFolder),
            (self.address, HitTarget::Address),
        ] {
            if !rect.is_empty() && rect.contains(point) {
                return target;
            }
        }
        for (index, rect) in self.sidebar_rows.iter().copied().enumerate() {
            if rect.contains(point) {
                return HitTarget::Sidebar(index);
            }
        }
        if self.rows.contains(point) {
            let visible = ((point.y - self.rows.y) as u32 / self.row_height) as usize;
            let index = scroll.saturating_add(visible);
            if index < entry_count {
                return HitTarget::Row(index);
            }
        }
        HitTarget::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_stays_bounded_at_normal_and_tiny_sizes() {
        for (width, height) in [(720, 460), (320, 200), (256, 100), (1, 1)] {
            let layout = Layout::new(width, height);
            for rect in [
                layout.title_bar,
                layout.toolbar,
                layout.sidebar,
                layout.content,
                layout.status_bar,
            ] {
                assert!(rect.x >= 0 && rect.y >= 0);
                assert!(rect.right() <= i64::from(width));
                assert!(rect.bottom() <= i64::from(height));
            }
        }
        let integration_layout = Layout::new(256, 100);
        assert_eq!(integration_layout.visible_row_count(), 1);
        assert!(integration_layout.row_rect(0).is_some());
        assert!(integration_layout.address.width > 0);
    }

    #[test]
    fn hit_testing_maps_controls_sidebar_and_scrolled_rows() {
        let layout = Layout::new(720, 460);
        assert_eq!(
            layout.hit_test(
                Point::new(layout.close_button.x + 1, layout.close_button.y + 1),
                0,
                20,
            ),
            HitTarget::Close
        );
        let sidebar = layout.sidebar_row(3).unwrap();
        assert_eq!(
            layout.hit_test(Point::new(sidebar.x + 1, sidebar.y + 1), 0, 20),
            HitTarget::Sidebar(3)
        );
        let row = layout.row_rect(1).unwrap();
        assert_eq!(
            layout.hit_test(Point::new(row.x + 1, row.y + 1), 5, 20),
            HitTarget::Row(6)
        );
    }

    #[test]
    fn compact_sidebar_never_creates_invisible_targets_outside_its_panel() {
        let layout = Layout::new(256, 100);
        for index in 0..SIDEBAR_PLACE_COUNT {
            let row = layout.sidebar_row(index).unwrap();
            assert!(row.is_empty() || row.intersect(layout.sidebar) == Some(row));
        }
        assert_eq!(
            layout.hit_test(
                Point::new(layout.sidebar.x + 1, layout.status_bar.y + 1),
                0,
                0,
            ),
            HitTarget::None
        );
        assert_eq!(
            layout.hit_test(Point::new(layout.content.x + 1, layout.content.y + 1), 0, 0,),
            HitTarget::None
        );
    }
}
