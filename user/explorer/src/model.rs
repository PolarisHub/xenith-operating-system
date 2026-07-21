//! Allocation-free filesystem model and input state for Xenith Files.

use core::cmp::Ordering;

use xenith_abi::compositor::{
    CompositorKeyEvent, CompositorPointerEvent, CompositorTextEvent, COMPOSITOR_KEY_PRESSED,
    COMPOSITOR_KEY_REPEATED, COMPOSITOR_POINTER_ACTION_AXIS, COMPOSITOR_POINTER_ACTION_BUTTON,
};
use xenith_abi::{
    DirectoryEntry, UI_MODIFIER_LEFT_ALT, UI_MODIFIER_LEFT_CTRL, UI_MODIFIER_LEFT_SHIFT,
    UI_MODIFIER_RIGHT_ALT, UI_MODIFIER_RIGHT_CTRL, UI_MODIFIER_RIGHT_SHIFT, UI_POINTER_BUTTON_LEFT,
};
use xenith_winhost_core::{dos_path_to_native, WindowsPathError};

use crate::layout::{HitTarget, Layout, Point, SIDEBAR_PLACE_COUNT};

pub const MAX_PATH_BYTES: usize = 1_024;
pub const MAX_DIRECTORY_ENTRIES: usize = 96;
pub const MAX_HISTORY_ENTRIES: usize = 12;
pub const MAX_STATUS_BYTES: usize = 192;

pub use xenith_abi::{
    DIRECTORY_ENTRY_KIND_DIRECTORY as ENTRY_KIND_DIRECTORY,
    DIRECTORY_ENTRY_KIND_REGULAR as ENTRY_KIND_REGULAR,
    DIRECTORY_ENTRY_KIND_SYMLINK as ENTRY_KIND_SYMLINK,
};

const DEFAULT_DIRECTORY: &[u8] = b"/win/c/Users/Xenith";
const DOUBLE_CLICK_NS: u64 = 500_000_000;

const KEY_ESCAPE: u32 = 0x01;
const KEY_BACKSPACE: u32 = 0x0e;
const KEY_ENTER: u32 = 0x1c;
const KEY_L: u32 = 0x26;
const KEY_N: u32 = 0x31;
const KEY_F5: u32 = 0x3f;
const KEY_HOME: u32 = 0xe047;
const KEY_UP: u32 = 0xe048;
const KEY_PAGE_UP: u32 = 0xe049;
const KEY_LEFT: u32 = 0xe04b;
const KEY_END: u32 = 0xe04f;
const KEY_DOWN: u32 = 0xe050;
const KEY_PAGE_DOWN: u32 = 0xe051;
const KEY_DELETE: u32 = 0xe053;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathError {
    Empty,
    NotAbsolute,
    InvalidUtf8,
    InvalidCharacter,
    InvalidComponent,
    TooLong,
    UnsupportedWindowsPath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedPath {
    bytes: [u8; MAX_PATH_BYTES],
    len: u16,
}

impl FixedPath {
    pub const EMPTY: Self = Self {
        bytes: [0; MAX_PATH_BYTES],
        len: 0,
    };

    #[must_use]
    pub fn default_directory() -> Self {
        Self::normalize_absolute(DEFAULT_DIRECTORY).expect("built-in Explorer path is valid")
    }

    pub fn normalize_absolute(input: &[u8]) -> Result<Self, PathError> {
        if input.is_empty() {
            return Err(PathError::Empty);
        }
        let text = core::str::from_utf8(input).map_err(|_| PathError::InvalidUtf8)?;
        let bytes = if looks_like_windows_path(input) {
            let native =
                dos_path_to_native::<MAX_PATH_BYTES>(text).map_err(map_windows_path_error)?;
            return Self::normalize_native(native.as_bytes());
        } else {
            input
        };
        Self::normalize_native(bytes)
    }

    fn normalize_native(input: &[u8]) -> Result<Self, PathError> {
        if input.first() != Some(&b'/') {
            return Err(PathError::NotAbsolute);
        }
        core::str::from_utf8(input).map_err(|_| PathError::InvalidUtf8)?;
        let mut output = Self::EMPTY;
        output.bytes[0] = b'/';
        output.len = 1;
        let mut cursor = 1usize;
        while cursor <= input.len() {
            while cursor < input.len() && input[cursor] == b'/' {
                cursor += 1;
            }
            if cursor >= input.len() {
                break;
            }
            let start = cursor;
            while cursor < input.len() && input[cursor] != b'/' {
                cursor += 1;
            }
            let component = &input[start..cursor];
            if component == b"." {
                continue;
            }
            if component == b".." {
                output.pop_component();
                continue;
            }
            validate_component(component)?;
            output.push_component(component)?;
        }
        Ok(output)
    }

    pub fn join_component(self, component: &[u8]) -> Result<Self, PathError> {
        validate_component(component)?;
        let mut output = self;
        if output.is_empty() || output.as_bytes().first() != Some(&b'/') {
            return Err(PathError::NotAbsolute);
        }
        output.push_component(component)?;
        Ok(output)
    }

    #[must_use]
    pub fn parent(self) -> Self {
        let mut output = self;
        output.pop_component();
        output
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        // `len` is written only after bounds checks in this module.
        let len = self.len as usize;
        &self.bytes[..len]
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("/")
    }

    #[must_use]
    pub const fn len(self) -> usize {
        self.len as usize
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Write a friendly DOS path for the Windows namespace and a native path
    /// everywhere else. The result is not NUL terminated.
    pub fn write_display(self, output: &mut [u8]) -> usize {
        let source = self.as_bytes();
        let windows_tail = if source == b"/win/c" {
            Some(&b""[..])
        } else {
            source.strip_prefix(b"/win/c/")
        };
        if let Some(tail) = windows_tail {
            let mut used = 0;
            for byte in b"C:\\" {
                if used == output.len() {
                    return used;
                }
                output[used] = *byte;
                used += 1;
            }
            for &byte in tail {
                if used == output.len() {
                    break;
                }
                output[used] = if byte == b'/' { b'\\' } else { byte };
                used += 1;
            }
            used
        } else {
            let length = source.len().min(output.len());
            output[..length].copy_from_slice(&source[..length]);
            length
        }
    }

    fn push_component(&mut self, component: &[u8]) -> Result<(), PathError> {
        let current = self.len();
        let separator = usize::from(current > 1);
        let required = current
            .checked_add(separator)
            .and_then(|value| value.checked_add(component.len()))
            .ok_or(PathError::TooLong)?;
        if required > self.bytes.len() {
            return Err(PathError::TooLong);
        }
        let mut offset = current;
        if separator != 0 {
            self.bytes[offset] = b'/';
            offset += 1;
        }
        self.bytes[offset..offset + component.len()].copy_from_slice(component);
        self.len = required as u16;
        Ok(())
    }

    fn pop_component(&mut self) {
        let mut length = self.len();
        while length > 1 && self.bytes[length - 1] != b'/' {
            length -= 1;
        }
        if length > 1 {
            length -= 1;
        }
        let old_length = self.len();
        self.bytes[length..old_length].fill(0);
        self.len = length as u16;
    }
}

impl Default for FixedPath {
    fn default() -> Self {
        Self::EMPTY
    }
}

fn looks_like_windows_path(input: &[u8]) -> bool {
    input.starts_with(b"\\??\\")
        || input.len() >= 3
            && input[0].is_ascii_alphabetic()
            && input[1] == b':'
            && matches!(input[2], b'/' | b'\\')
}

fn validate_component(component: &[u8]) -> Result<(), PathError> {
    if component.is_empty() || matches!(component, b"." | b"..") {
        return Err(PathError::InvalidComponent);
    }
    if component.len() > 255
        || component
            .iter()
            .any(|byte| *byte == 0 || *byte == b'/' || *byte == b'\\' || *byte < 0x20)
    {
        return Err(PathError::InvalidCharacter);
    }
    core::str::from_utf8(component).map_err(|_| PathError::InvalidUtf8)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EntryMetadata {
    pub size: u64,
    pub modified_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    pub inode: u64,
    pub kind: u8,
    name_len: u16,
    name: [u8; 256],
    pub size: u64,
    pub modified_ns: u64,
}

impl Entry {
    const EMPTY: Self = Self {
        inode: 0,
        kind: 0,
        name_len: 0,
        name: [0; 256],
        size: 0,
        modified_ns: 0,
    };

    fn from_wire(entry: DirectoryEntry, metadata: EntryMetadata) -> Self {
        let length = usize::from(entry.name_len).min(entry.name.len());
        let length = if core::str::from_utf8(&entry.name[..length]).is_ok() {
            length
        } else {
            0
        };
        let mut name = [0; 256];
        name[..length].copy_from_slice(&entry.name[..length]);
        Self {
            inode: entry.inode,
            kind: entry.kind,
            name_len: length as u16,
            name,
            size: metadata.size,
            modified_ns: metadata.modified_ns,
        }
    }

    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    #[must_use]
    pub const fn is_directory(self) -> bool {
        self.kind == ENTRY_KIND_DIRECTORY
    }
}

impl Default for Entry {
    fn default() -> Self {
        Self::EMPTY
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownPlace {
    Home,
    Desktop,
    Documents,
    Downloads,
    Music,
    Pictures,
    Videos,
}

impl KnownPlace {
    pub const ALL: [Self; SIDEBAR_PLACE_COUNT] = [
        Self::Home,
        Self::Desktop,
        Self::Documents,
        Self::Downloads,
        Self::Music,
        Self::Pictures,
        Self::Videos,
    ];

    #[must_use]
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Home => b"Home",
            Self::Desktop => b"Desktop",
            Self::Documents => b"Documents",
            Self::Downloads => b"Downloads",
            Self::Music => b"Music",
            Self::Pictures => b"Pictures",
            Self::Videos => b"Videos",
        }
    }

    #[must_use]
    pub const fn native_path(self) -> &'static [u8] {
        match self {
            Self::Home => b"/win/c/Users/Xenith",
            Self::Desktop => b"/win/c/Users/Xenith/Desktop",
            Self::Documents => b"/win/c/Users/Xenith/Documents",
            Self::Downloads => b"/win/c/Users/Xenith/Downloads",
            Self::Music => b"/win/c/Users/Xenith/Music",
            Self::Pictures => b"/win/c/Users/Xenith/Pictures",
            Self::Videos => b"/win/c/Users/Xenith/Videos",
        }
    }

    #[must_use]
    pub fn path(self) -> FixedPath {
        FixedPath::normalize_absolute(self.native_path()).expect("built-in known folder is valid")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryMode {
    Push,
    Back,
    Preserve,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    None,
    Exit,
    Back,
    Up,
    Refresh,
    NewFolder,
    OpenSelected,
    SubmitAddress,
    NavigatePlace(KnownPlace),
    DeleteSelected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interaction {
    pub command: Command,
    pub repaint: bool,
}

impl Interaction {
    pub const NONE: Self = Self {
        command: Command::None,
        repaint: false,
    };

    #[must_use]
    pub const fn repaint() -> Self {
        Self {
            command: Command::None,
            repaint: true,
        }
    }

    #[must_use]
    pub const fn command(command: Command, repaint: bool) -> Self {
        Self { command, repaint }
    }
}

pub struct ExplorerModel {
    current: FixedPath,
    entries: [Entry; MAX_DIRECTORY_ENTRIES],
    entry_count: usize,
    history: [FixedPath; MAX_HISTORY_ENTRIES],
    history_len: usize,
    selected: Option<usize>,
    scroll: usize,
    focused: bool,
    address_editing: bool,
    address_replace_on_text: bool,
    address: [u8; MAX_PATH_BYTES],
    address_len: usize,
    delete_pending: Option<usize>,
    last_click: Option<usize>,
    last_click_ns: u64,
    status: [u8; MAX_STATUS_BYTES],
    status_len: usize,
}

impl ExplorerModel {
    #[must_use]
    pub fn new() -> Self {
        Self {
            current: FixedPath::default_directory(),
            entries: [Entry::EMPTY; MAX_DIRECTORY_ENTRIES],
            entry_count: 0,
            history: [FixedPath::EMPTY; MAX_HISTORY_ENTRIES],
            history_len: 0,
            selected: None,
            scroll: 0,
            focused: false,
            address_editing: false,
            address_replace_on_text: false,
            address: [0; MAX_PATH_BYTES],
            address_len: 0,
            delete_pending: None,
            last_click: None,
            last_click_ns: 0,
            status: [0; MAX_STATUS_BYTES],
            status_len: 0,
        }
    }

    #[must_use]
    pub const fn current_path(&self) -> FixedPath {
        self.current
    }

    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries[..self.entry_count]
    }

    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    #[must_use]
    pub const fn selected_index(&self) -> Option<usize> {
        self.selected
    }

    #[must_use]
    pub fn selected_entry(&self) -> Option<&Entry> {
        self.selected.and_then(|index| self.entries().get(index))
    }

    #[must_use]
    pub const fn scroll(&self) -> usize {
        self.scroll
    }

    #[must_use]
    pub const fn focused(&self) -> bool {
        self.focused
    }

    #[must_use]
    pub const fn address_editing(&self) -> bool {
        self.address_editing
    }

    #[must_use]
    pub const fn address_select_all(&self) -> bool {
        self.address_editing && self.address_replace_on_text
    }

    #[must_use]
    pub fn address_bytes(&self) -> &[u8] {
        &self.address[..self.address_len]
    }

    #[must_use]
    pub fn status(&self) -> &[u8] {
        &self.status[..self.status_len]
    }

    #[must_use]
    pub const fn delete_pending(&self) -> Option<usize> {
        self.delete_pending
    }

    #[must_use]
    pub fn can_go_back(&self) -> bool {
        self.history_len != 0
    }

    #[must_use]
    pub fn back_target(&self) -> Option<FixedPath> {
        self.history_len
            .checked_sub(1)
            .map(|index| self.history[index])
    }

    #[must_use]
    pub fn up_target(&self) -> Option<FixedPath> {
        let parent = self.current.parent();
        (parent != self.current).then_some(parent)
    }

    pub fn commit_directory(
        &mut self,
        target: FixedPath,
        entries: &[DirectoryEntry],
        metadata: &[EntryMetadata],
        history_mode: HistoryMode,
    ) {
        match history_mode {
            HistoryMode::Push if target != self.current => self.push_history(self.current),
            HistoryMode::Back if self.back_target() == Some(target) => {
                self.history_len -= 1;
                self.history[self.history_len] = FixedPath::EMPTY;
            },
            HistoryMode::Push | HistoryMode::Back | HistoryMode::Preserve => {},
        }
        self.current = target;
        self.entries.fill(Entry::EMPTY);
        self.entry_count = entries.len().min(metadata.len()).min(self.entries.len());
        for index in 0..self.entry_count {
            self.entries[index] = Entry::from_wire(entries[index], metadata[index]);
        }
        self.sort_entries();
        self.selected = None;
        self.scroll = 0;
        self.delete_pending = None;
        self.last_click = None;
        self.address_editing = false;
        self.address_replace_on_text = false;
        self.clear_status();
    }

    pub fn select_name(&mut self, name: &[u8], visible_rows: usize) {
        self.selected = self.entries().iter().position(|entry| entry.name() == name);
        self.ensure_selection_visible(visible_rows);
    }

    pub fn set_focused(&mut self, focused: bool) -> bool {
        let changed = self.focused != focused;
        self.focused = focused;
        changed
    }

    pub fn set_status(&mut self, status: &[u8]) {
        self.status.fill(0);
        self.status_len = status.len().min(self.status.len());
        self.status[..self.status_len].copy_from_slice(&status[..self.status_len]);
    }

    pub fn clear_status(&mut self) {
        self.status.fill(0);
        self.status_len = 0;
    }

    pub fn cancel_delete(&mut self) -> bool {
        let changed = self.delete_pending.take().is_some();
        if changed {
            self.clear_status();
        }
        changed
    }

    pub fn finish_address_edit(&mut self, success: bool) {
        if success {
            self.address_editing = false;
            self.address_replace_on_text = false;
            self.address_len = 0;
            self.address.fill(0);
        }
    }

    pub fn handle_pointer(&mut self, layout: Layout, event: CompositorPointerEvent) -> Interaction {
        if event.action == COMPOSITOR_POINTER_ACTION_AXIS {
            let old = self.scroll;
            let visible = layout.visible_row_count().max(1);
            let maximum = self.entry_count.saturating_sub(visible);
            if event.axis_y > 0 {
                self.scroll = self.scroll.saturating_sub(3);
            } else if event.axis_y < 0 {
                self.scroll = self.scroll.saturating_add(3).min(maximum);
            }
            return Interaction::command(Command::None, old != self.scroll);
        }
        if event.action != COMPOSITOR_POINTER_ACTION_BUTTON
            || event.changed_button != UI_POINTER_BUTTON_LEFT
            || event.buttons & u32::from(UI_POINTER_BUTTON_LEFT) == 0
        {
            return Interaction::NONE;
        }
        let hit = layout.hit_test(Point::new(event.x, event.y), self.scroll, self.entry_count);
        match hit {
            HitTarget::Close => Interaction::command(Command::Exit, false),
            HitTarget::Back => Interaction::command(Command::Back, false),
            HitTarget::Up => Interaction::command(Command::Up, false),
            HitTarget::Refresh => Interaction::command(Command::Refresh, false),
            HitTarget::NewFolder => Interaction::command(Command::NewFolder, false),
            HitTarget::Address => {
                self.begin_address_edit(false);
                Interaction::repaint()
            },
            HitTarget::Sidebar(index) => KnownPlace::ALL
                .get(index)
                .copied()
                .map_or(Interaction::NONE, |place| {
                    Interaction::command(Command::NavigatePlace(place), false)
                }),
            HitTarget::Row(index) => {
                let double_click = self.last_click == Some(index)
                    && event.timestamp_ns.saturating_sub(self.last_click_ns) <= DOUBLE_CLICK_NS;
                let changed = self.selected != Some(index) || self.delete_pending.is_some();
                self.selected = Some(index);
                self.delete_pending = None;
                self.clear_status();
                self.last_click = Some(index);
                self.last_click_ns = event.timestamp_ns;
                if double_click {
                    Interaction::command(Command::OpenSelected, true)
                } else {
                    Interaction::command(Command::None, changed)
                }
            },
            HitTarget::None => {
                let selection_changed = self.selected.take().is_some();
                let delete_changed = self.cancel_delete();
                let changed = selection_changed || delete_changed;
                self.last_click = None;
                Interaction::command(Command::None, changed)
            },
        }
    }

    pub fn handle_key(&mut self, layout: Layout, event: CompositorKeyEvent) -> Interaction {
        if !matches!(
            event.state,
            COMPOSITOR_KEY_PRESSED | COMPOSITOR_KEY_REPEATED
        ) {
            return Interaction::NONE;
        }
        let control =
            event.modifiers & u32::from(UI_MODIFIER_LEFT_CTRL | UI_MODIFIER_RIGHT_CTRL) != 0;
        let alt = event.modifiers & u32::from(UI_MODIFIER_LEFT_ALT | UI_MODIFIER_RIGHT_ALT) != 0;
        let shift =
            event.modifiers & u32::from(UI_MODIFIER_LEFT_SHIFT | UI_MODIFIER_RIGHT_SHIFT) != 0;
        let repeated = event.state == COMPOSITOR_KEY_REPEATED;

        if control && shift && event.key_code == KEY_N {
            return if repeated {
                Interaction::NONE
            } else {
                Interaction::command(Command::NewFolder, false)
            };
        }
        if control && event.key_code == KEY_L {
            if repeated {
                return Interaction::NONE;
            }
            self.begin_address_edit(true);
            return Interaction::repaint();
        }
        if self.address_editing {
            return match event.key_code {
                KEY_ESCAPE if !repeated => {
                    self.address_editing = false;
                    self.address_replace_on_text = false;
                    self.address_len = 0;
                    self.address.fill(0);
                    Interaction::repaint()
                },
                KEY_BACKSPACE => {
                    self.pop_address_character();
                    Interaction::repaint()
                },
                KEY_ENTER if !repeated => Interaction::command(Command::SubmitAddress, false),
                _ => Interaction::NONE,
            };
        }
        match event.key_code {
            KEY_ESCAPE if !repeated => Interaction::command(Command::None, self.cancel_delete()),
            KEY_F5 if !repeated => Interaction::command(Command::Refresh, false),
            KEY_BACKSPACE if !repeated => Interaction::command(Command::Up, false),
            KEY_LEFT if alt && !repeated => Interaction::command(Command::Back, false),
            KEY_ENTER if !repeated => Interaction::command(Command::OpenSelected, false),
            KEY_DELETE if !repeated => self.request_delete(),
            KEY_UP => self.move_selection(-1, layout.visible_row_count()),
            KEY_DOWN => self.move_selection(1, layout.visible_row_count()),
            KEY_PAGE_UP => self.move_selection(
                -(layout.visible_row_count().max(1) as isize),
                layout.visible_row_count(),
            ),
            KEY_PAGE_DOWN => self.move_selection(
                layout.visible_row_count().max(1) as isize,
                layout.visible_row_count(),
            ),
            KEY_HOME if self.entry_count != 0 => {
                self.selected = Some(0);
                self.scroll = 0;
                self.delete_pending = None;
                Interaction::repaint()
            },
            KEY_END if self.entry_count != 0 => {
                self.selected = Some(self.entry_count - 1);
                self.ensure_selection_visible(layout.visible_row_count());
                self.delete_pending = None;
                Interaction::repaint()
            },
            _ => Interaction::NONE,
        }
    }

    pub fn handle_text(&mut self, event: CompositorTextEvent) -> Interaction {
        if !self.address_editing {
            return Interaction::NONE;
        }
        let length = usize::from(event.byte_length).min(event.bytes.len());
        let bytes = &event.bytes[..length];
        let insertion = if self.address_replace_on_text {
            0
        } else {
            self.address_len
        };
        if core::str::from_utf8(bytes).is_err()
            || bytes.iter().any(|byte| *byte == 0 || *byte < 0x20)
            || insertion.saturating_add(bytes.len()) > self.address.len()
        {
            return Interaction::NONE;
        }
        if self.address_replace_on_text {
            self.address.fill(0);
            self.address_len = 0;
            self.address_replace_on_text = false;
        }
        self.address[self.address_len..self.address_len + bytes.len()].copy_from_slice(bytes);
        self.address_len += bytes.len();
        Interaction::repaint()
    }

    fn begin_address_edit(&mut self, replace_on_text: bool) {
        self.address.fill(0);
        self.address_len = self.current.write_display(&mut self.address);
        self.address_editing = true;
        self.address_replace_on_text = replace_on_text;
        self.delete_pending = None;
        self.clear_status();
    }

    fn pop_address_character(&mut self) {
        if self.address_replace_on_text {
            self.address.fill(0);
            self.address_len = 0;
            self.address_replace_on_text = false;
            return;
        }
        if self.address_len == 0 {
            return;
        }
        self.address_len -= 1;
        while self.address_len != 0
            && core::str::from_utf8(&self.address[..self.address_len]).is_err()
        {
            self.address_len -= 1;
        }
        self.address[self.address_len..].fill(0);
    }

    fn request_delete(&mut self) -> Interaction {
        let Some(selected) = self.selected else {
            return Interaction::NONE;
        };
        if self.delete_pending == Some(selected) {
            Interaction::command(Command::DeleteSelected, false)
        } else {
            self.delete_pending = Some(selected);
            self.set_status(b"Press Delete again to remove this item; Esc cancels");
            Interaction::repaint()
        }
    }

    fn move_selection(&mut self, delta: isize, visible_rows: usize) -> Interaction {
        if self.entry_count == 0 {
            return Interaction::NONE;
        }
        let target = self.selected.map_or_else(
            || if delta < 0 { self.entry_count - 1 } else { 0 },
            |current| {
                current
                    .saturating_add_signed(delta)
                    .min(self.entry_count.saturating_sub(1))
            },
        );
        let changed = self.selected != Some(target) || self.delete_pending.is_some();
        self.selected = Some(target);
        self.delete_pending = None;
        self.clear_status();
        self.ensure_selection_visible(visible_rows);
        Interaction::command(Command::None, changed)
    }

    fn ensure_selection_visible(&mut self, visible_rows: usize) {
        let visible_rows = visible_rows.max(1);
        let Some(selected) = self.selected else {
            return;
        };
        if selected < self.scroll {
            self.scroll = selected;
        } else if selected >= self.scroll.saturating_add(visible_rows) {
            self.scroll = selected.saturating_add(1).saturating_sub(visible_rows);
        }
        self.scroll = self
            .scroll
            .min(self.entry_count.saturating_sub(visible_rows));
    }

    fn push_history(&mut self, path: FixedPath) {
        if self.history_len == self.history.len() {
            self.history.copy_within(1.., 0);
            self.history_len -= 1;
        }
        self.history[self.history_len] = path;
        self.history_len += 1;
    }

    fn sort_entries(&mut self) {
        for index in 1..self.entry_count {
            let mut cursor = index;
            while cursor != 0
                && compare_entries(&self.entries[cursor], &self.entries[cursor - 1])
                    == Ordering::Less
            {
                self.entries.swap(cursor, cursor - 1);
                cursor -= 1;
            }
        }
    }
}

fn map_windows_path_error(error: WindowsPathError) -> PathError {
    match error {
        WindowsPathError::Empty => PathError::Empty,
        WindowsPathError::NotDriveAbsolute | WindowsPathError::DriveRelative => {
            PathError::NotAbsolute
        },
        WindowsPathError::UnmappedDrive { .. } | WindowsPathError::UnsupportedNamespace => {
            PathError::UnsupportedWindowsPath
        },
        WindowsPathError::ParentEscapesRoot
        | WindowsPathError::TrailingDotOrSpace { .. }
        | WindowsPathError::ReservedDeviceName { .. } => PathError::InvalidComponent,
        WindowsPathError::InvalidControl { .. } | WindowsPathError::InvalidCharacter { .. } => {
            PathError::InvalidCharacter
        },
        WindowsPathError::BufferTooSmall { .. } => PathError::TooLong,
    }
}

impl Default for ExplorerModel {
    fn default() -> Self {
        Self::new()
    }
}

fn compare_entries(left: &Entry, right: &Entry) -> Ordering {
    match (left.is_directory(), right.is_directory()) {
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        _ => {},
    }
    let mut left_bytes = left
        .name()
        .iter()
        .copied()
        .map(|byte| byte.to_ascii_lowercase());
    let mut right_bytes = right
        .name()
        .iter()
        .copied()
        .map(|byte| byte.to_ascii_lowercase());
    loop {
        match (left_bytes.next(), right_bytes.next()) {
            (Some(a), Some(b)) => match a.cmp(&b) {
                Ordering::Equal => {},
                ordering => return ordering,
            },
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return left.name().cmp(right.name()),
        }
    }
}

#[cfg(test)]
mod tests {
    use xenith_abi::compositor::{COMPOSITOR_KEY_PRESSED, COMPOSITOR_POINTER_ACTION_BUTTON};

    use super::*;

    fn wire(name: &[u8], kind: u8) -> DirectoryEntry {
        let mut entry = DirectoryEntry {
            kind,
            name_len: name.len() as u16,
            ..DirectoryEntry::default()
        };
        entry.name[..name.len()].copy_from_slice(name);
        entry
    }

    fn load(model: &mut ExplorerModel) {
        let entries = [
            wire(b"zeta.txt", ENTRY_KIND_REGULAR),
            wire(b"Music", ENTRY_KIND_DIRECTORY),
            wire(b"alpha.txt", ENTRY_KIND_REGULAR),
        ];
        model.commit_directory(
            FixedPath::default_directory(),
            &entries,
            &[EntryMetadata::default(); 3],
            HistoryMode::Preserve,
        );
    }

    #[test]
    fn path_normalization_accepts_native_and_dos_absolute_paths() {
        assert_eq!(
            FixedPath::normalize_absolute(b"/win//c/Users/./Xenith/../Public")
                .unwrap()
                .as_bytes(),
            b"/win/c/Users/Public"
        );
        let dos = FixedPath::normalize_absolute(br"C:\Users\Xenith\Music").unwrap();
        assert_eq!(dos.as_bytes(), b"/win/c/Users/Xenith/Music");
        let mut display = [0; 64];
        let length = dos.write_display(&mut display);
        assert_eq!(&display[..length], br"C:\Users\Xenith\Music");
        assert_eq!(
            FixedPath::normalize_absolute(b"relative"),
            Err(PathError::NotAbsolute)
        );
        assert_eq!(
            FixedPath::normalize_absolute(br"D:\Files"),
            Err(PathError::UnsupportedWindowsPath)
        );
        assert_eq!(
            FixedPath::normalize_absolute(br"C:\Users\Xenith\bad<name"),
            Err(PathError::InvalidCharacter)
        );
        assert_eq!(
            FixedPath::normalize_absolute(br"C:\Users\Xenith\CON"),
            Err(PathError::InvalidComponent)
        );
    }

    #[test]
    fn directory_commit_sorts_folders_first_and_preserves_history() {
        let mut model = ExplorerModel::new();
        load(&mut model);
        assert_eq!(model.entries()[0].name(), b"Music");
        assert_eq!(model.entries()[1].name(), b"alpha.txt");
        let target = KnownPlace::Downloads.path();
        model.commit_directory(target, &[], &[], HistoryMode::Push);
        assert_eq!(model.back_target(), Some(FixedPath::default_directory()));
        model.commit_directory(FixedPath::default_directory(), &[], &[], HistoryMode::Back);
        assert!(!model.can_go_back());
    }

    #[test]
    fn pointer_selection_requires_a_second_bounded_click_to_open() {
        let mut model = ExplorerModel::new();
        load(&mut model);
        let layout = Layout::new(720, 460);
        let row = layout.row_rect(0).unwrap();
        let event = CompositorPointerEvent {
            timestamp_ns: 1_000,
            x: row.x + 2,
            y: row.y + 2,
            buttons: u32::from(UI_POINTER_BUTTON_LEFT),
            changed_button: UI_POINTER_BUTTON_LEFT,
            action: COMPOSITOR_POINTER_ACTION_BUTTON,
            ..CompositorPointerEvent::default()
        };
        assert_eq!(model.handle_pointer(layout, event).command, Command::None);
        assert_eq!(
            model
                .handle_pointer(layout, CompositorPointerEvent {
                    timestamp_ns: 2_000,
                    ..event
                },)
                .command,
            Command::OpenSelected
        );
    }

    #[test]
    fn delete_is_confirmed_and_escape_cancels() {
        let mut model = ExplorerModel::new();
        load(&mut model);
        model.selected = Some(0);
        let layout = Layout::new(720, 460);
        let delete = CompositorKeyEvent {
            key_code: KEY_DELETE,
            state: COMPOSITOR_KEY_PRESSED,
            ..CompositorKeyEvent::default()
        };
        assert_eq!(model.handle_key(layout, delete), Interaction::repaint());
        assert_eq!(
            model.handle_key(layout, CompositorKeyEvent {
                state: COMPOSITOR_KEY_REPEATED,
                ..delete
            },),
            Interaction::NONE
        );
        assert_eq!(model.delete_pending(), Some(0));
        assert_eq!(
            model.handle_key(layout, delete).command,
            Command::DeleteSelected
        );
        let escape = CompositorKeyEvent {
            key_code: KEY_ESCAPE,
            state: COMPOSITOR_KEY_PRESSED,
            ..CompositorKeyEvent::default()
        };
        assert!(model.handle_key(layout, escape).repaint);
        assert_eq!(model.delete_pending(), None);
    }

    #[test]
    fn ctrl_l_edits_only_absolute_address_text() {
        let mut model = ExplorerModel::new();
        let layout = Layout::new(720, 460);
        let ctrl_l = CompositorKeyEvent {
            key_code: KEY_L,
            modifiers: u32::from(UI_MODIFIER_LEFT_CTRL),
            state: COMPOSITOR_KEY_PRESSED,
            ..CompositorKeyEvent::default()
        };
        assert!(model.handle_key(layout, ctrl_l).repaint);
        assert_eq!(model.address_bytes(), br"C:\Users\Xenith");
        let text = CompositorTextEvent {
            byte_length: 1,
            bytes: {
                let mut bytes = [0; xenith_abi::compositor::COMPOSITOR_MAX_TEXT_BYTES as usize];
                bytes[0] = b'X';
                bytes
            },
            ..CompositorTextEvent::default()
        };
        assert!(model.handle_text(text).repaint);
        assert_eq!(model.address_bytes(), b"X");
        assert!(!model.address_select_all());
    }

    #[test]
    fn ctrl_shift_n_creates_once_and_ignores_repeat() {
        let mut model = ExplorerModel::new();
        let layout = Layout::new(720, 460);
        let shortcut = CompositorKeyEvent {
            key_code: KEY_N,
            modifiers: u32::from(UI_MODIFIER_LEFT_CTRL | UI_MODIFIER_LEFT_SHIFT),
            state: COMPOSITOR_KEY_PRESSED,
            ..CompositorKeyEvent::default()
        };
        assert_eq!(
            model.handle_key(layout, shortcut).command,
            Command::NewFolder
        );
        assert_eq!(
            model.handle_key(layout, CompositorKeyEvent {
                state: COMPOSITOR_KEY_REPEATED,
                ..shortcut
            },),
            Interaction::NONE
        );
    }

    #[test]
    fn keyboard_starts_at_the_nearest_edge_and_empty_click_cancels_delete() {
        let mut model = ExplorerModel::new();
        load(&mut model);
        let layout = Layout::new(720, 460);
        let down = CompositorKeyEvent {
            key_code: KEY_DOWN,
            state: COMPOSITOR_KEY_PRESSED,
            ..CompositorKeyEvent::default()
        };
        assert!(model.handle_key(layout, down).repaint);
        assert_eq!(model.selected_index(), Some(0));

        model.selected = None;
        let up = CompositorKeyEvent {
            key_code: KEY_UP,
            ..down
        };
        assert!(model.handle_key(layout, up).repaint);
        assert_eq!(model.selected_index(), Some(model.entry_count() - 1));

        assert!(model.request_delete().repaint);
        let empty_click = CompositorPointerEvent {
            timestamp_ns: 90,
            x: layout.column_header.x + 2,
            y: layout.column_header.y + 2,
            buttons: u32::from(UI_POINTER_BUTTON_LEFT),
            changed_button: UI_POINTER_BUTTON_LEFT,
            action: COMPOSITOR_POINTER_ACTION_BUTTON,
            ..CompositorPointerEvent::default()
        };
        assert!(model.handle_pointer(layout, empty_click).repaint);
        assert_eq!(model.selected_index(), None);
        assert_eq!(model.delete_pending(), None);
        assert!(model.status().is_empty());
    }
}
