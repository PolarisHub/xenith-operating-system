//! Allocation-free desktop state, layout, damage tracking, and software rendering.
//!
//! The runtime owns one anonymous native-format backbuffer. Every input batch
//! mutates [`DesktopState`], collects a bounded set of damaged rectangles, and
//! asks [`Renderer`] to reconstruct only those pixels from the embedded photo,
//! client surfaces, one restrained shell bar, and the cursor.

#![no_std]

pub mod compositor;
mod render;
mod wallpaper;
#[cfg(test)]
mod window_smoke_render;

pub use render::{PixelFormat, RenderError, Renderer, Surface, WallpaperSampler};
use xenith_abi::{
    UiInputEvent, UiRect, UI_EVENT_FLAG_OVERFLOW, UI_EVENT_FLAG_PRESSED, UI_EVENT_FLAG_REPEAT,
    UI_EVENT_KEY, UI_EVENT_POINTER, UI_MODIFIER_LEFT_ALT, UI_MODIFIER_LEFT_CTRL,
    UI_MODIFIER_LEFT_SHIFT, UI_MODIFIER_LEFT_SUPER, UI_MODIFIER_RIGHT_ALT, UI_MODIFIER_RIGHT_CTRL,
    UI_MODIFIER_RIGHT_SHIFT, UI_MODIFIER_RIGHT_SUPER, UI_POINTER_BUTTON_LEFT,
};

pub const MAX_DAMAGE_RECTS: usize = 12;

const KEY_ESCAPE: u32 = 0x01;
const KEY_BACKSPACE: u32 = 0x0e;
const KEY_Q: u32 = 0x10;
const KEY_F1: u32 = 0x3b;
const KEY_LEFT_SUPER: u32 = 0xe05b;
const KEY_RIGHT_SUPER: u32 = 0xe05c;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

impl Size {
    #[must_use]
    pub const fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }

    #[must_use]
    pub const fn bounds(self) -> Rect {
        Rect::new(0, 0, self.width, self.height)
    }
}

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
    pub fn contains(self, point: Point) -> bool {
        i64::from(point.x) >= i64::from(self.x)
            && i64::from(point.y) >= i64::from(self.y)
            && i64::from(point.x) < self.right()
            && i64::from(point.y) < self.bottom()
    }

    #[must_use]
    pub fn intersect(self, other: Self) -> Option<Self> {
        let left = i64::from(self.x).max(i64::from(other.x));
        let top = i64::from(self.y).max(i64::from(other.y));
        let right = self.right().min(other.right());
        let bottom = self.bottom().min(other.bottom());
        if left >= right || top >= bottom {
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
    pub fn union(self, other: Self) -> Self {
        let left = i64::from(self.x).min(i64::from(other.x));
        let top = i64::from(self.y).min(i64::from(other.y));
        let right = self.right().max(other.right());
        let bottom = self.bottom().max(other.bottom());
        Self::new(
            left as i32,
            top as i32,
            (right - left) as u32,
            (bottom - top) as u32,
        )
    }

    #[must_use]
    pub fn expand(self, amount: u32) -> Self {
        let amount = amount.min(i32::MAX as u32) as i32;
        Self::new(
            self.x.saturating_sub(amount),
            self.y.saturating_sub(amount),
            self.width.saturating_add((amount as u32).saturating_mul(2)),
            self.height
                .saturating_add((amount as u32).saturating_mul(2)),
        )
    }

    #[must_use]
    pub fn inset(self, amount: u32) -> Self {
        let doubled = amount.saturating_mul(2);
        if self.width <= doubled || self.height <= doubled {
            return Self::default();
        }
        Self::new(
            self.x.saturating_add(amount as i32),
            self.y.saturating_add(amount as i32),
            self.width - doubled,
            self.height - doubled,
        )
    }

    #[must_use]
    pub fn touches(self, other: Self) -> bool {
        i64::from(self.x) <= other.right().saturating_add(1)
            && self.right().saturating_add(1) >= i64::from(other.x)
            && i64::from(self.y) <= other.bottom().saturating_add(1)
            && self.bottom().saturating_add(1) >= i64::from(other.y)
    }
}

impl From<Rect> for UiRect {
    fn from(value: Rect) -> Self {
        Self {
            x: value.x.max(0) as u32,
            y: value.y.max(0) as u32,
            width: value.width,
            height: value.height,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layout {
    pub screen: Rect,
    pub top_bar: Rect,
    pub dock: Rect,
    pub launcher_button: Rect,
    pub launcher: Rect,
}

impl Layout {
    #[must_use]
    pub fn new(size: Size) -> Self {
        let width = size.width.max(1);
        let height = size.height.max(1);
        let screen = Rect::new(0, 0, width, height);
        let bar_height = (if height >= 360 { 38 } else { 32 }).min(height).max(1);
        let bar_y = height.saturating_sub(bar_height);
        let dock = Rect::new(0, bar_y as i32, width, bar_height);
        // Keep the legacy top-bar hit region as an alias of the sole shell bar.
        // This preserves shell pointer capture without an invisible region.
        let top_bar = dock;
        let button_margin = 5.min(bar_height.saturating_sub(1) / 2);
        let button_size = bar_height.saturating_sub(button_margin * 2).max(1);
        let launcher_button = Rect::new(
            button_margin as i32,
            (bar_y + button_margin) as i32,
            button_size,
            button_size,
        );

        let panel_margin = 8.min(width.saturating_sub(1) / 2);
        let launcher_width = width.saturating_sub(panel_margin * 2).clamp(1, 300);
        let available_height = bar_y.saturating_sub(panel_margin);
        let launcher_height = available_height.clamp(1, 96);
        let launcher_x = panel_margin;
        let launcher_y = bar_y
            .saturating_sub(panel_margin)
            .saturating_sub(launcher_height);
        let launcher = Rect::new(
            launcher_x as i32,
            launcher_y as i32,
            launcher_width,
            launcher_height,
        );

        Self {
            screen,
            top_bar,
            dock,
            launcher_button,
            launcher,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventAction {
    Continue,
    Consumed,
    Exit,
}

#[derive(Debug)]
pub struct DesktopState {
    size: Size,
    layout: Layout,
    cursor: Point,
    cursor_x_q8: i64,
    cursor_y_q8: i64,
    buttons: u16,
    shell_pointer_buttons: u16,
    pointer_resync: bool,
    suppressed_key: u32,
    launcher_open: bool,
}

impl DesktopState {
    #[must_use]
    pub fn new(size: Size) -> Self {
        let layout = Layout::new(size);
        let cursor = Point::new((size.width / 2) as i32, (size.height / 2) as i32);
        Self {
            size,
            layout,
            cursor,
            cursor_x_q8: i64::from(cursor.x) << POINTER_FRACTION_BITS,
            cursor_y_q8: i64::from(cursor.y) << POINTER_FRACTION_BITS,
            buttons: 0,
            shell_pointer_buttons: 0,
            pointer_resync: false,
            suppressed_key: 0,
            launcher_open: false,
        }
    }

    #[must_use]
    pub const fn size(&self) -> Size {
        self.size
    }

    #[must_use]
    pub const fn layout(&self) -> Layout {
        self.layout
    }

    #[must_use]
    pub const fn cursor(&self) -> Point {
        self.cursor
    }

    #[must_use]
    pub const fn launcher_open(&self) -> bool {
        self.launcher_open
    }

    #[must_use]
    pub fn cursor_damage(&self) -> Rect {
        Rect::new(
            self.cursor.x.saturating_sub(3),
            self.cursor.y.saturating_sub(3),
            20,
            26,
        )
    }

    pub fn handle_event(&mut self, event: UiInputEvent, damage: &mut DamageTracker) -> EventAction {
        if event.flags & UI_EVENT_FLAG_OVERFLOW != 0 {
            damage.mark_full();
            self.buttons = 0;
            self.shell_pointer_buttons = 0;
            self.pointer_resync = true;
            self.suppressed_key = 0;
        }
        match event.kind {
            UI_EVENT_POINTER => self.handle_pointer(event, damage),
            UI_EVENT_KEY => self.handle_key(event, damage),
            _ => EventAction::Continue,
        }
    }

    fn handle_pointer(&mut self, event: UiInputEvent, damage: &mut DamageTracker) -> EventAction {
        let old_cursor = self.cursor_damage();
        let max_x = self.size.width.saturating_sub(1).min(i32::MAX as u32) as i32;
        let max_y = self.size.height.saturating_sub(1).min(i32::MAX as u32) as i32;
        self.cursor_x_q8 = move_pointer_axis(self.cursor_x_q8, event.value1, max_x);
        self.cursor_y_q8 = move_pointer_axis(self.cursor_y_q8, event.value2, max_y);
        self.cursor.x = pointer_pixel(self.cursor_x_q8, max_x);
        self.cursor.y = pointer_pixel(self.cursor_y_q8, max_y);
        let new_cursor = self.cursor_damage();
        if old_cursor != new_cursor {
            damage.add(old_cursor);
            damage.add(new_cursor);
        }

        let over_shell = self.layout.top_bar.contains(self.cursor)
            || self.layout.dock.contains(self.cursor)
            || self.launcher_open && self.layout.launcher.contains(self.cursor);
        if self.pointer_resync {
            // The queue no longer proves which transitions were dropped. Use
            // the current mask as a baseline, but never turn a surviving held
            // button into a new shell press. Normal edges resume only after a
            // release snapshot; the compositor applies the same policy.
            self.buttons = event.buttons;
            if event.buttons == 0 {
                self.pointer_resync = false;
            }
            return if over_shell {
                EventAction::Consumed
            } else {
                EventAction::Continue
            };
        }

        let old_left = self.buttons & UI_POINTER_BUTTON_LEFT != 0;
        let new_left = event.buttons & UI_POINTER_BUTTON_LEFT != 0;
        let old_buttons = self.buttons;
        let newly_pressed = (old_buttons ^ event.buttons) & event.buttons;
        let shell_had_capture = self.shell_pointer_buttons != 0;
        if shell_had_capture {
            self.shell_pointer_buttons |= newly_pressed;
        } else if old_buttons == 0 && newly_pressed != 0 && over_shell {
            self.shell_pointer_buttons = newly_pressed;
        }
        self.buttons = event.buttons;
        if new_left && !old_left && self.layout.launcher_button.contains(self.cursor) {
            self.toggle_launcher(damage);
        }
        let consumed = shell_had_capture
            || self.shell_pointer_buttons != 0
            || old_buttons == 0 && event.buttons == 0 && over_shell;
        self.shell_pointer_buttons &= event.buttons;
        if consumed {
            EventAction::Consumed
        } else {
            EventAction::Continue
        }
    }

    fn handle_key(&mut self, event: UiInputEvent, damage: &mut DamageTracker) -> EventAction {
        if self.suppressed_key == event.code {
            if event.flags & UI_EVENT_FLAG_PRESSED == 0 {
                self.suppressed_key = 0;
            }
            return EventAction::Consumed;
        }
        if matches!(event.code, KEY_LEFT_SUPER | KEY_RIGHT_SUPER) {
            if event.flags & UI_EVENT_FLAG_PRESSED != 0 && event.flags & UI_EVENT_FLAG_REPEAT == 0 {
                self.toggle_launcher(damage);
            }
            return EventAction::Consumed;
        }
        if event.flags & UI_EVENT_FLAG_PRESSED == 0 {
            return EventAction::Continue;
        }
        let control = event.modifiers & (UI_MODIFIER_LEFT_CTRL | UI_MODIFIER_RIGHT_CTRL) != 0;
        let alt = event.modifiers & (UI_MODIFIER_LEFT_ALT | UI_MODIFIER_RIGHT_ALT) != 0;
        let shift = event.modifiers & (UI_MODIFIER_LEFT_SHIFT | UI_MODIFIER_RIGHT_SHIFT) != 0;
        let super_key = event.modifiers & (UI_MODIFIER_LEFT_SUPER | UI_MODIFIER_RIGHT_SUPER) != 0;
        if (matches!(event.code, KEY_BACKSPACE | KEY_F1) && control && alt)
            || (event.code == KEY_Q && super_key && shift)
        {
            return EventAction::Exit;
        }
        if event.code == KEY_ESCAPE && self.launcher_open {
            self.suppressed_key = event.code;
            self.toggle_launcher(damage);
            return EventAction::Consumed;
        }
        EventAction::Continue
    }

    fn toggle_launcher(&mut self, damage: &mut DamageTracker) {
        self.launcher_open = !self.launcher_open;
        damage.add(self.layout.launcher.expand(10));
        damage.add(self.layout.launcher_button.expand(3));
    }
}

const POINTER_FRACTION_BITS: u32 = 8;
const POINTER_ONE: i64 = 1 << POINTER_FRACTION_BITS;

/// Apply a continuous, bounded pointer gain in Q8 fixed point.
///
/// One-count motion remains effectively one pixel, while faster packets rise
/// gradually to 2x instead of jumping between the old 1x/2x/3x tiers. Keeping
/// the fractional remainder makes slow diagonal and VMware relative motion
/// feel consistent without allocating or running a timer-driven filter.
fn accelerate_axis_q8(value: i32) -> i64 {
    let magnitude = value.unsigned_abs();
    let gain_q8 = POINTER_ONE + i64::from(magnitude.min(16)) * 16;
    i64::from(value).saturating_mul(gain_q8)
}

fn move_pointer_axis(current_q8: i64, delta: i32, maximum: i32) -> i64 {
    current_q8
        .saturating_add(accelerate_axis_q8(delta))
        .clamp(0, i64::from(maximum) << POINTER_FRACTION_BITS)
}

fn pointer_pixel(position_q8: i64, maximum: i32) -> i32 {
    ((position_q8.saturating_add(POINTER_ONE / 2)) >> POINTER_FRACTION_BITS)
        .clamp(0, i64::from(maximum)) as i32
}

#[derive(Clone, Copy, Debug)]
pub struct DamageTracker {
    screen: Rect,
    rects: [Rect; MAX_DAMAGE_RECTS],
    len: usize,
    full: bool,
}

impl DamageTracker {
    #[must_use]
    pub const fn new(screen: Rect) -> Self {
        Self {
            screen,
            rects: [Rect::new(0, 0, 0, 0); MAX_DAMAGE_RECTS],
            len: 0,
            full: false,
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
        self.full = false;
    }

    pub fn mark_full(&mut self) {
        self.len = 0;
        self.full = true;
    }

    pub fn add(&mut self, rect: Rect) {
        if self.full {
            return;
        }
        let Some(mut merged) = rect.intersect(self.screen) else {
            return;
        };

        let mut index = 0;
        while index < self.len {
            if merged.touches(self.rects[index]) {
                merged = merged.union(self.rects[index]);
                self.len -= 1;
                self.rects[index] = self.rects[self.len];
                index = 0;
            } else {
                index += 1;
            }
        }
        if self.len == self.rects.len() {
            self.mark_full();
            return;
        }
        self.rects[self.len] = merged;
        self.len += 1;
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        !self.full && self.len == 0
    }

    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.full
    }

    #[must_use]
    pub fn rects(&self) -> &[Rect] {
        if self.full {
            core::slice::from_ref(&self.screen)
        } else {
            &self.rects[..self.len]
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn pointer(dx: i32, dy: i32, buttons: u16) -> UiInputEvent {
        UiInputEvent {
            kind: UI_EVENT_POINTER,
            buttons,
            value1: dx,
            value2: dy,
            ..UiInputEvent::default()
        }
    }

    fn place_cursor(state: &mut DesktopState, point: Point) {
        state.cursor = point;
        state.cursor_x_q8 = i64::from(point.x) << POINTER_FRACTION_BITS;
        state.cursor_y_q8 = i64::from(point.y) << POINTER_FRACTION_BITS;
    }

    #[test]
    fn damage_clips_and_merges_touching_regions() {
        let mut damage = DamageTracker::new(Rect::new(0, 0, 100, 80));
        damage.add(Rect::new(-5, 3, 10, 10));
        damage.add(Rect::new(5, 3, 7, 10));
        assert_eq!(damage.rects(), &[Rect::new(0, 3, 12, 10)]);
    }

    #[test]
    fn pointer_is_accelerated_clamped_and_damages_old_and_new_bounds() {
        let mut state = DesktopState::new(Size::new(100, 80));
        let mut damage = DamageTracker::new(state.layout().screen);
        state.handle_event(pointer(i32::MAX, i32::MAX, 0), &mut damage);
        assert_eq!(state.cursor(), Point::new(99, 79));
        assert!(!damage.is_empty());
        for rect in damage.rects() {
            assert_eq!(*rect, rect.intersect(state.layout().screen).unwrap());
        }
    }

    #[test]
    fn stationary_pointer_events_never_drift() {
        let mut state = DesktopState::new(Size::new(800, 600));
        let origin = state.cursor();
        let mut damage = DamageTracker::new(state.layout().screen);
        for _ in 0..1_000 {
            assert_eq!(
                state.handle_event(pointer(0, 0, 0), &mut damage),
                EventAction::Continue
            );
        }
        assert_eq!(state.cursor(), origin);
        assert!(damage.is_empty());
    }

    #[test]
    fn fractional_gain_accumulates_symmetrically() {
        let mut state = DesktopState::new(Size::new(800, 600));
        let origin = state.cursor();
        let mut damage = DamageTracker::new(state.layout().screen);
        for _ in 0..16 {
            state.handle_event(pointer(1, 0, 0), &mut damage);
        }
        assert_eq!(state.cursor(), Point::new(origin.x + 17, origin.y));
        for _ in 0..16 {
            state.handle_event(pointer(-1, 0, 0), &mut damage);
        }
        assert_eq!(state.cursor(), origin);

        damage.clear();
        for _ in 0..64 {
            state.handle_event(pointer(0, 0, 0), &mut damage);
        }
        assert_eq!(state.cursor(), origin);
        assert!(damage.is_empty());
    }

    #[test]
    fn overflow_releases_local_pointer_button_state() {
        let mut state = DesktopState::new(Size::new(800, 600));
        let mut damage = DamageTracker::new(state.layout().screen);
        state.handle_event(pointer(0, 0, UI_POINTER_BUTTON_LEFT), &mut damage);
        assert_eq!(state.buttons, UI_POINTER_BUTTON_LEFT);
        state.handle_event(
            UiInputEvent {
                flags: UI_EVENT_FLAG_OVERFLOW,
                ..UiInputEvent::default()
            },
            &mut damage,
        );
        assert_eq!(state.buttons, 0);
        assert_eq!(state.shell_pointer_buttons, 0);
        assert!(state.pointer_resync);
        state.handle_event(pointer(0, 0, 0), &mut damage);
        assert!(!state.pointer_resync);
    }

    #[test]
    fn overflow_never_turns_a_held_button_into_a_launcher_click() {
        let mut state = DesktopState::new(Size::new(800, 600));
        let button = state.layout().launcher_button;
        place_cursor(&mut state, Point::new(button.x + 1, button.y + 1));
        let mut damage = DamageTracker::new(state.layout().screen);

        let held_overflow = UiInputEvent {
            flags: UI_EVENT_FLAG_OVERFLOW,
            ..pointer(0, 0, UI_POINTER_BUTTON_LEFT)
        };
        assert_eq!(
            state.handle_event(held_overflow, &mut damage),
            EventAction::Consumed
        );
        assert!(!state.launcher_open());
        assert!(state.pointer_resync);

        state.handle_event(pointer(0, 0, UI_POINTER_BUTTON_LEFT), &mut damage);
        assert!(!state.launcher_open());
        state.handle_event(pointer(0, 0, 0), &mut damage);
        assert!(!state.pointer_resync);
        state.handle_event(pointer(0, 0, UI_POINTER_BUTTON_LEFT), &mut damage);
        assert!(state.launcher_open());
    }

    #[test]
    fn launcher_button_uses_a_press_edge() {
        let mut state = DesktopState::new(Size::new(1024, 768));
        let button = state.layout().launcher_button;
        let target = Point::new(button.x + 2, button.y + 2);
        place_cursor(&mut state, target);
        let mut damage = DamageTracker::new(state.layout().screen);
        assert_eq!(
            state.handle_event(pointer(0, 0, UI_POINTER_BUTTON_LEFT), &mut damage),
            EventAction::Consumed
        );
        assert!(state.launcher_open());
        state.handle_event(pointer(0, 0, UI_POINTER_BUTTON_LEFT), &mut damage);
        assert!(state.launcher_open());
        state.handle_event(pointer(0, 0, 0), &mut damage);
        state.handle_event(pointer(0, 0, UI_POINTER_BUTTON_LEFT), &mut damage);
        assert!(!state.launcher_open());
    }

    #[test]
    fn emergency_chord_requests_exit() {
        let mut state = DesktopState::new(Size::new(800, 600));
        let mut damage = DamageTracker::new(state.layout().screen);
        let event = UiInputEvent {
            kind: UI_EVENT_KEY,
            flags: UI_EVENT_FLAG_PRESSED,
            modifiers: UI_MODIFIER_LEFT_CTRL | UI_MODIFIER_RIGHT_ALT,
            code: KEY_BACKSPACE,
            ..UiInputEvent::default()
        };
        assert_eq!(state.handle_event(event, &mut damage), EventAction::Exit);
    }

    #[test]
    fn left_super_make_toggles_once_and_break_is_ignored() {
        let mut state = DesktopState::new(Size::new(320, 200));
        let mut damage = DamageTracker::new(state.layout().screen);
        let make = UiInputEvent {
            kind: UI_EVENT_KEY,
            flags: UI_EVENT_FLAG_PRESSED,
            modifiers: UI_MODIFIER_LEFT_SUPER,
            code: KEY_LEFT_SUPER,
            ..UiInputEvent::default()
        };
        assert_eq!(state.handle_event(make, &mut damage), EventAction::Consumed);
        assert!(state.launcher_open());
        assert!(!damage.is_empty());

        damage.clear();
        let release = UiInputEvent {
            flags: 0,
            modifiers: 0,
            ..make
        };
        assert_eq!(
            state.handle_event(release, &mut damage),
            EventAction::Consumed
        );
        assert!(state.launcher_open());
        assert!(damage.is_empty());
    }

    #[test]
    fn shell_pointer_capture_and_escape_release_do_not_leak_to_clients() {
        let mut state = DesktopState::new(Size::new(1024, 768));
        let button = state.layout().launcher_button;
        place_cursor(&mut state, Point::new(button.x + 1, button.y + 1));
        let mut damage = DamageTracker::new(state.layout().screen);
        assert_eq!(
            state.handle_event(pointer(0, 0, UI_POINTER_BUTTON_LEFT), &mut damage),
            EventAction::Consumed
        );
        place_cursor(&mut state, Point::new(500, 300));
        assert_eq!(
            state.handle_event(pointer(0, 0, UI_POINTER_BUTTON_LEFT), &mut damage),
            EventAction::Consumed
        );
        assert_eq!(
            state.handle_event(pointer(0, 0, 0), &mut damage),
            EventAction::Consumed
        );

        let escape = UiInputEvent {
            kind: UI_EVENT_KEY,
            flags: UI_EVENT_FLAG_PRESSED,
            code: KEY_ESCAPE,
            ..UiInputEvent::default()
        };
        assert_eq!(
            state.handle_event(escape, &mut damage),
            EventAction::Consumed
        );
        assert!(!state.launcher_open());
        assert_eq!(
            state.handle_event(UiInputEvent { flags: 0, ..escape }, &mut damage,),
            EventAction::Consumed
        );
    }

    #[test]
    fn layout_stays_inside_tiny_and_normal_screens() {
        for size in [Size::new(1, 1), Size::new(320, 200), Size::new(1024, 768)] {
            let layout = Layout::new(size);
            for rect in [
                layout.top_bar,
                layout.dock,
                layout.launcher_button,
                layout.launcher,
            ] {
                assert_eq!(rect, rect.intersect(layout.screen).unwrap());
            }
        }
    }
}
