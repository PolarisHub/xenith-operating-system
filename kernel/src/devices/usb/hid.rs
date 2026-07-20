//! HID boot-protocol report decoding for keyboards and relative mice.
//!
//! Boot protocol is intentionally used instead of interpreting arbitrary HID
//! report descriptors.  That gives the kernel a small, deterministic input
//! path during early desktop bring-up while still handling composite USB
//! keyboard/mouse devices through their standard class/subclass/protocol
//! interface descriptors.

use crate::devices::ps2::keyboard::{KeyCode, KeyEvent, KeyModifiers};
use crate::devices::ps2::mouse::{MouseButtons, MouseEvent};

const KEYBOARD_REPORT_LEN: usize = 8;
const KEY_SLOTS: usize = 6;

/// Delay before a newly pressed USB key begins software typematic repeat.
pub const TYPEMATIC_DELAY_NS: u64 = 250_000_000;
/// Target software typematic rate.
pub const TYPEMATIC_RATE_HZ: u64 = 30;
const TYPEMATIC_PERIOD_NS: u64 = 1_000_000_000 / TYPEMATIC_RATE_HZ;

/// Malformed or unusable boot report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HidReportError {
    /// The endpoint delivered fewer bytes than the boot report requires.
    Truncated,
    /// The keyboard reported ErrorRollOver, POSTFail, or ErrorUndefined.
    KeyboardRollover,
}

/// Stateful decoder for the eight-byte HID keyboard boot report.
///
/// USB reports contain the complete current key set rather than make/break
/// bytes.  The decoder retains the preceding six usages and modifier bitmap,
/// emits releases before presses, and suppresses duplicate usages.  Hardware
/// report repetition is not converted into duplicate key presses; typematic
/// is a scheduler policy above this transport.
#[derive(Clone, Copy, Debug)]
pub struct BootKeyboard {
    modifier_byte: u8,
    keys: [u8; KEY_SLOTS],
    modifiers: KeyModifiers,
    repeat_usage: u8,
    next_repeat_ns: u64,
}

impl BootKeyboard {
    /// Empty keyboard state with no keys or modifiers held.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            modifier_byte: 0,
            keys: [0; KEY_SLOTS],
            modifiers: KeyModifiers::empty(),
            repeat_usage: 0,
            next_repeat_ns: 0,
        }
    }

    /// Decode one complete keyboard report and emit transition events.
    ///
    /// Rollover reports are rejected without changing retained state, which
    /// prevents a transient six-key overflow from synthesizing releases for
    /// every key the user is still holding.
    pub fn decode(
        &mut self,
        report: &[u8],
        emit: impl FnMut(KeyEvent),
    ) -> Result<usize, HidReportError> {
        self.decode_inner(report, None, emit)
    }

    /// Decode a report and update the deterministic software-typematic clock.
    ///
    /// `now_ns` is supplied by the transport so this decoder remains free of
    /// hardware and global-time dependencies. A newly selected repeat key is
    /// armed for [`TYPEMATIC_DELAY_NS`]; unchanged reports do not restart it.
    pub fn decode_at(
        &mut self,
        report: &[u8],
        now_ns: u64,
        emit: impl FnMut(KeyEvent),
    ) -> Result<usize, HidReportError> {
        self.decode_inner(report, Some(now_ns), emit)
    }

    fn decode_inner(
        &mut self,
        report: &[u8],
        now_ns: Option<u64>,
        mut emit: impl FnMut(KeyEvent),
    ) -> Result<usize, HidReportError> {
        if report.len() < KEYBOARD_REPORT_LEN {
            return Err(HidReportError::Truncated);
        }
        let incoming = &report[2..KEYBOARD_REPORT_LEN];
        if incoming.iter().any(|usage| (1..=3).contains(usage)) {
            return Err(HidReportError::KeyboardRollover);
        }

        let mut emitted = 0usize;
        let next_modifiers = report[0];
        // Releases first so a simultaneous modifier/key replacement carries
        // the modifier state that is true after each individual transition.
        for bit in 0..8u8 {
            let mask = 1u8 << bit;
            if self.modifier_byte & mask != 0 && next_modifiers & mask == 0 {
                self.apply_modifier(bit, false);
                emit(self.modifier_event(bit, false));
                emitted += 1;
            }
        }
        for bit in 0..8u8 {
            let mask = 1u8 << bit;
            if self.modifier_byte & mask == 0 && next_modifiers & mask != 0 {
                self.apply_modifier(bit, true);
                emit(self.modifier_event(bit, true));
                emitted += 1;
            }
        }
        self.modifier_byte = next_modifiers;

        for usage in self.keys {
            if usage != 0 && !contains_usage(incoming, usage) {
                emit(self.key_event(usage, false));
                emitted += 1;
            }
        }
        let previous_repeat = self.repeat_usage;
        let mut selected_repeat =
            if previous_repeat != 0 && contains_usage(incoming, previous_repeat) {
                previous_repeat
            } else {
                0
            };
        let mut selected_new_repeat = false;
        for (index, usage) in incoming.iter().copied().enumerate() {
            if usage == 0 || incoming[..index].contains(&usage) || contains_usage(&self.keys, usage)
            {
                continue;
            }
            self.apply_lock_key(usage);
            emit(self.key_event(usage, true));
            emitted += 1;
            if is_repeatable_usage(usage) {
                // Descriptor order provides a deterministic tie-break when a
                // report introduces multiple keys simultaneously.
                selected_repeat = usage;
                selected_new_repeat = true;
            }
        }

        if selected_repeat == 0 {
            selected_repeat = incoming
                .iter()
                .rev()
                .copied()
                .find(|usage| is_repeatable_usage(*usage))
                .unwrap_or(0);
        }

        self.keys.fill(0);
        let mut output = 0usize;
        for (index, usage) in incoming.iter().copied().enumerate() {
            if usage != 0 && !incoming[..index].contains(&usage) {
                self.keys[output] = usage;
                output += 1;
            }
        }
        if selected_repeat != previous_repeat || selected_new_repeat {
            self.arm_repeat(selected_repeat, now_ns);
        } else if selected_repeat == 0 {
            self.cancel_repeat();
        }
        Ok(emitted)
    }

    /// Emit at most one due typematic event and return the number emitted.
    ///
    /// Missed periods are skipped arithmetically instead of being replayed in
    /// a burst, keeping task-context service work strictly bounded after a
    /// scheduler stall. The next event retains the original 30 Hz phase.
    pub fn repeat_due(&mut self, now_ns: u64, mut emit: impl FnMut(KeyEvent)) -> usize {
        if self.repeat_usage == 0
            || !contains_usage(&self.keys, self.repeat_usage)
            || now_ns < self.next_repeat_ns
        {
            if self.repeat_usage != 0 && !contains_usage(&self.keys, self.repeat_usage) {
                self.cancel_repeat();
            }
            return 0;
        }

        let usage = self.repeat_usage;
        let mut event = self.key_event(usage, true);
        event.repeat = true;
        emit(event);

        let elapsed = now_ns.saturating_sub(self.next_repeat_ns);
        let periods = elapsed / TYPEMATIC_PERIOD_NS + 1;
        self.next_repeat_ns = self
            .next_repeat_ns
            .saturating_add(periods.saturating_mul(TYPEMATIC_PERIOD_NS));
        1
    }

    /// Synthesize releases for every physically held key/modifier and reset.
    ///
    /// This is intended for task-context disconnect/re-enumeration teardown so
    /// a removed keyboard cannot leave the desktop with stuck input state.
    /// Lock toggles are not synthetic physical keys; release events retain
    /// their current lock flags, then the discarded decoder is reset fully.
    pub fn disconnect(&mut self, mut emit: impl FnMut(KeyEvent)) -> usize {
        let mut emitted = 0usize;
        for usage in self.keys {
            if usage != 0 {
                emit(self.key_event(usage, false));
                emitted += 1;
            }
        }
        for bit in 0..8u8 {
            let mask = 1u8 << bit;
            if self.modifier_byte & mask != 0 {
                self.apply_modifier(bit, false);
                emit(self.modifier_event(bit, false));
                emitted += 1;
            }
        }
        *self = Self::new();
        emitted
    }

    fn arm_repeat(&mut self, usage: u8, now_ns: Option<u64>) {
        let Some(now_ns) = now_ns.filter(|_| usage != 0) else {
            self.cancel_repeat();
            return;
        };
        self.repeat_usage = usage;
        self.next_repeat_ns = now_ns.saturating_add(TYPEMATIC_DELAY_NS);
    }

    fn cancel_repeat(&mut self) {
        self.repeat_usage = 0;
        self.next_repeat_ns = 0;
    }

    fn apply_modifier(&mut self, bit: u8, pressed: bool) {
        let flag = modifier_flag(bit);
        if pressed {
            self.modifiers.insert(flag);
        } else {
            self.modifiers.remove(flag);
        }
    }

    fn apply_lock_key(&mut self, usage: u8) {
        let lock = match usage {
            0x39 => Some(KeyModifiers::CAPS_LOCK),
            0x47 => Some(KeyModifiers::SCROLL_LOCK),
            0x53 => Some(KeyModifiers::NUM_LOCK),
            _ => None,
        };
        if let Some(lock) = lock {
            if self.modifiers.contains(lock) {
                self.modifiers.remove(lock);
            } else {
                self.modifiers.insert(lock);
            }
        }
    }

    fn modifier_event(&self, bit: u8, pressed: bool) -> KeyEvent {
        let (code, raw_scancode) = modifier_key(bit);
        KeyEvent {
            code,
            pressed,
            character: None,
            modifiers: self.modifiers,
            raw_scancode,
            repeat: false,
        }
    }

    fn key_event(&self, usage: u8, pressed: bool) -> KeyEvent {
        let mapping = key_mapping(usage);
        KeyEvent {
            code: mapping.code,
            pressed,
            character: pressed.then(|| mapping.character(self.modifiers)).flatten(),
            modifiers: self.modifiers,
            raw_scancode: mapping.raw_scancode,
            repeat: false,
        }
    }

    /// Modifier and lock state after the most recently accepted report.
    #[must_use]
    pub const fn modifiers(&self) -> KeyModifiers {
        self.modifiers
    }
}

impl Default for BootKeyboard {
    fn default() -> Self {
        Self::new()
    }
}

/// Stateful decoder for the HID mouse boot report.
///
/// Retaining the last button bitmap lets disconnect teardown synthesize the
/// all-buttons-released sample needed to prevent a held button from remaining
/// logically stuck after hot-unplug or endpoint recovery.
#[derive(Clone, Copy, Debug, Default)]
pub struct BootMouse {
    buttons: MouseButtons,
}

impl BootMouse {
    /// Empty mouse state with no buttons held.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buttons: MouseButtons::empty(),
        }
    }

    /// Decode buttons, relative X/Y, and an optional wheel byte.
    ///
    /// HID relative Y already uses screen orientation (positive is down), so
    /// unlike PS/2 packet decoding no sign inversion is applied.
    pub fn decode(&mut self, report: &[u8]) -> Result<MouseEvent, HidReportError> {
        if report.len() < 3 {
            return Err(HidReportError::Truncated);
        }
        let mut buttons = MouseButtons::empty();
        if report[0] & 0x01 != 0 {
            buttons.insert(MouseButtons::LEFT);
        }
        if report[0] & 0x02 != 0 {
            buttons.insert(MouseButtons::RIGHT);
        }
        if report[0] & 0x04 != 0 {
            buttons.insert(MouseButtons::MIDDLE);
        }
        if report[0] & 0x08 != 0 {
            buttons.insert(MouseButtons::BACK);
        }
        if report[0] & 0x10 != 0 {
            buttons.insert(MouseButtons::FORWARD);
        }
        self.buttons = buttons;
        Ok(MouseEvent {
            buttons,
            dx: i16::from(report[1] as i8),
            dy: i16::from(report[2] as i8),
            dz: report.get(3).copied().unwrap_or(0) as i8,
        })
    }

    /// Return one zero-motion, all-buttons-released sample when needed.
    ///
    /// Repeated teardown is idempotent: a mouse that had no held buttons (or
    /// has already been disconnected) produces no redundant event.
    pub fn disconnect(&mut self) -> Option<MouseEvent> {
        if self.buttons.is_empty() {
            return None;
        }
        self.buttons = MouseButtons::empty();
        Some(MouseEvent::default())
    }
}

#[derive(Clone, Copy)]
struct KeyMapping {
    code: KeyCode,
    raw_scancode: u16,
    normal: Option<char>,
    shifted: Option<char>,
}

impl KeyMapping {
    fn character(self, modifiers: KeyModifiers) -> Option<char> {
        let shift = modifiers.shift();
        if let Some(character) = self.normal {
            if character.is_ascii_alphabetic() {
                let uppercase = shift ^ modifiers.contains(KeyModifiers::CAPS_LOCK);
                return Some(if uppercase {
                    character.to_ascii_uppercase()
                } else {
                    character
                });
            }
        }
        if shift {
            self.shifted.or(self.normal)
        } else {
            self.normal
        }
    }
}

const fn map(
    code: KeyCode,
    raw_scancode: u16,
    normal: Option<char>,
    shifted: Option<char>,
) -> KeyMapping {
    KeyMapping {
        code,
        raw_scancode,
        normal,
        shifted,
    }
}

#[allow(clippy::too_many_lines)]
fn key_mapping(usage: u8) -> KeyMapping {
    use KeyCode::*;
    match usage {
        0x04 => map(A, 0x1e, Some('a'), Some('A')),
        0x05 => map(B, 0x30, Some('b'), Some('B')),
        0x06 => map(C, 0x2e, Some('c'), Some('C')),
        0x07 => map(D, 0x20, Some('d'), Some('D')),
        0x08 => map(E, 0x12, Some('e'), Some('E')),
        0x09 => map(F, 0x21, Some('f'), Some('F')),
        0x0a => map(G, 0x22, Some('g'), Some('G')),
        0x0b => map(H, 0x23, Some('h'), Some('H')),
        0x0c => map(I, 0x17, Some('i'), Some('I')),
        0x0d => map(J, 0x24, Some('j'), Some('J')),
        0x0e => map(K, 0x25, Some('k'), Some('K')),
        0x0f => map(L, 0x26, Some('l'), Some('L')),
        0x10 => map(M, 0x32, Some('m'), Some('M')),
        0x11 => map(N, 0x31, Some('n'), Some('N')),
        0x12 => map(O, 0x18, Some('o'), Some('O')),
        0x13 => map(P, 0x19, Some('p'), Some('P')),
        0x14 => map(Q, 0x10, Some('q'), Some('Q')),
        0x15 => map(R, 0x13, Some('r'), Some('R')),
        0x16 => map(S, 0x1f, Some('s'), Some('S')),
        0x17 => map(T, 0x14, Some('t'), Some('T')),
        0x18 => map(U, 0x16, Some('u'), Some('U')),
        0x19 => map(V, 0x2f, Some('v'), Some('V')),
        0x1a => map(W, 0x11, Some('w'), Some('W')),
        0x1b => map(X, 0x2d, Some('x'), Some('X')),
        0x1c => map(Y, 0x15, Some('y'), Some('Y')),
        0x1d => map(Z, 0x2c, Some('z'), Some('Z')),
        0x1e => map(Digit1, 0x02, Some('1'), Some('!')),
        0x1f => map(Digit2, 0x03, Some('2'), Some('@')),
        0x20 => map(Digit3, 0x04, Some('3'), Some('#')),
        0x21 => map(Digit4, 0x05, Some('4'), Some('$')),
        0x22 => map(Digit5, 0x06, Some('5'), Some('%')),
        0x23 => map(Digit6, 0x07, Some('6'), Some('^')),
        0x24 => map(Digit7, 0x08, Some('7'), Some('&')),
        0x25 => map(Digit8, 0x09, Some('8'), Some('*')),
        0x26 => map(Digit9, 0x0a, Some('9'), Some('(')),
        0x27 => map(Digit0, 0x0b, Some('0'), Some(')')),
        0x28 => map(Enter, 0x1c, Some('\n'), Some('\n')),
        0x29 => map(Escape, 0x01, None, None),
        0x2a => map(Backspace, 0x0e, Some('\u{8}'), Some('\u{8}')),
        0x2b => map(Tab, 0x0f, Some('\t'), Some('\t')),
        0x2c => map(Space, 0x39, Some(' '), Some(' ')),
        0x2d => map(Minus, 0x0c, Some('-'), Some('_')),
        0x2e => map(Equal, 0x0d, Some('='), Some('+')),
        0x2f => map(LeftBracket, 0x1a, Some('['), Some('{')),
        0x30 => map(RightBracket, 0x1b, Some(']'), Some('}')),
        0x31 | 0x32 => map(Backslash, 0x2b, Some('\\'), Some('|')),
        0x33 => map(Semicolon, 0x27, Some(';'), Some(':')),
        0x34 => map(Apostrophe, 0x28, Some('\''), Some('"')),
        0x35 => map(Grave, 0x29, Some('`'), Some('~')),
        0x36 => map(Comma, 0x33, Some(','), Some('<')),
        0x37 => map(Period, 0x34, Some('.'), Some('>')),
        0x38 => map(Slash, 0x35, Some('/'), Some('?')),
        0x39 => map(CapsLock, 0x3a, None, None),
        0x3a => map(F1, 0x3b, None, None),
        0x3b => map(F2, 0x3c, None, None),
        0x3c => map(F3, 0x3d, None, None),
        0x3d => map(F4, 0x3e, None, None),
        0x3e => map(F5, 0x3f, None, None),
        0x3f => map(F6, 0x40, None, None),
        0x40 => map(F7, 0x41, None, None),
        0x41 => map(F8, 0x42, None, None),
        0x42 => map(F9, 0x43, None, None),
        0x43 => map(F10, 0x44, None, None),
        0x44 => map(F11, 0x57, None, None),
        0x45 => map(F12, 0x58, None, None),
        0x46 => map(PrintScreen, 0xe037, None, None),
        0x47 => map(ScrollLock, 0x46, None, None),
        0x48 => map(Pause, 0xe11d, None, None),
        0x49 => map(Insert, 0xe052, None, None),
        0x4a => map(Home, 0xe047, None, None),
        0x4b => map(PageUp, 0xe049, None, None),
        0x4c => map(Delete, 0xe053, None, None),
        0x4d => map(End, 0xe04f, None, None),
        0x4e => map(PageDown, 0xe051, None, None),
        0x4f => map(ArrowRight, 0xe04d, None, None),
        0x50 => map(ArrowLeft, 0xe04b, None, None),
        0x51 => map(ArrowDown, 0xe050, None, None),
        0x52 => map(ArrowUp, 0xe048, None, None),
        0x53 => map(NumLock, 0x45, None, None),
        0x54 => map(NumpadDivide, 0xe035, Some('/'), Some('/')),
        0x55 => map(NumpadMultiply, 0x37, Some('*'), Some('*')),
        0x56 => map(NumpadSubtract, 0x4a, Some('-'), Some('-')),
        0x57 => map(NumpadAdd, 0x4e, Some('+'), Some('+')),
        0x58 => map(NumpadEnter, 0xe01c, Some('\n'), Some('\n')),
        0x59 => map(Numpad1, 0x4f, None, None),
        0x5a => map(Numpad2, 0x50, None, None),
        0x5b => map(Numpad3, 0x51, None, None),
        0x5c => map(Numpad4, 0x4b, None, None),
        0x5d => map(Numpad5, 0x4c, None, None),
        0x5e => map(Numpad6, 0x4d, None, None),
        0x5f => map(Numpad7, 0x47, None, None),
        0x60 => map(Numpad8, 0x48, None, None),
        0x61 => map(Numpad9, 0x49, None, None),
        0x62 => map(Numpad0, 0x52, None, None),
        0x63 => map(NumpadDecimal, 0x53, None, None),
        0x65 => map(Menu, 0xe05d, None, None),
        _ => map(
            Unknown(u16::from(usage)),
            0xf000 | u16::from(usage),
            None,
            None,
        ),
    }
}

const fn modifier_flag(bit: u8) -> KeyModifiers {
    match bit {
        0 => KeyModifiers::LEFT_CTRL,
        1 => KeyModifiers::LEFT_SHIFT,
        2 => KeyModifiers::LEFT_ALT,
        3 => KeyModifiers::LEFT_SUPER,
        4 => KeyModifiers::RIGHT_CTRL,
        5 => KeyModifiers::RIGHT_SHIFT,
        6 => KeyModifiers::RIGHT_ALT,
        _ => KeyModifiers::RIGHT_SUPER,
    }
}

const fn modifier_key(bit: u8) -> (KeyCode, u16) {
    match bit {
        0 => (KeyCode::LeftCtrl, 0x1d),
        1 => (KeyCode::LeftShift, 0x2a),
        2 => (KeyCode::LeftAlt, 0x38),
        3 => (KeyCode::LeftSuper, 0xe05b),
        4 => (KeyCode::RightCtrl, 0xe01d),
        5 => (KeyCode::RightShift, 0x36),
        6 => (KeyCode::RightAlt, 0xe038),
        _ => (KeyCode::RightSuper, 0xe05c),
    }
}

fn contains_usage(usages: &[u8], usage: u8) -> bool {
    usages.contains(&usage)
}

const fn is_repeatable_usage(usage: u8) -> bool {
    usage != 0 && !matches!(usage, 0x39 | 0x47 | 0x53)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn keyboard_diffs_reports_and_tracks_shifted_characters() {
        let mut keyboard = BootKeyboard::new();
        let mut events = Vec::new();
        keyboard
            .decode(&[0x02, 0, 0x04, 0, 0, 0, 0, 0], |event| events.push(event))
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].code, KeyCode::LeftShift);
        assert_eq!(events[1].code, KeyCode::A);
        assert_eq!(events[1].character, Some('A'));

        events.clear();
        keyboard
            .decode(&[0, 0, 0, 0, 0, 0, 0, 0], |event| events.push(event))
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].code, KeyCode::LeftShift);
        assert!(!events[0].pressed);
        assert_eq!(events[1].code, KeyCode::A);
        assert!(!events[1].pressed);
    }

    #[test]
    fn keyboard_suppresses_unchanged_and_duplicate_usages() {
        let mut keyboard = BootKeyboard::new();
        let mut count = 0;
        keyboard
            .decode(&[0, 0, 0x05, 0x05, 0, 0, 0, 0], |_| count += 1)
            .unwrap();
        assert_eq!(count, 1);
        keyboard
            .decode(&[0, 0, 0x05, 0, 0, 0, 0, 0], |_| count += 1)
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn rollover_preserves_held_state() {
        let mut keyboard = BootKeyboard::new();
        keyboard
            .decode(&[0, 0, 0x06, 0, 0, 0, 0, 0], |_| {})
            .unwrap();
        assert_eq!(
            keyboard.decode(&[0, 0, 1, 1, 1, 1, 1, 1], |_| {}),
            Err(HidReportError::KeyboardRollover)
        );
        let mut events = Vec::new();
        keyboard
            .decode(&[0, 0, 0, 0, 0, 0, 0, 0], |event| events.push(event))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].code, KeyCode::C);
        assert!(!events[0].pressed);
    }

    #[test]
    fn caps_lock_toggles_character_case() {
        let mut keyboard = BootKeyboard::new();
        keyboard
            .decode(&[0, 0, 0x39, 0, 0, 0, 0, 0], |_| {})
            .unwrap();
        keyboard.decode(&[0; 8], |_| {}).unwrap();
        let mut character = None;
        keyboard
            .decode(&[0, 0, 0x07, 0, 0, 0, 0, 0], |event| {
                character = event.character
            })
            .unwrap();
        assert_eq!(character, Some('D'));
    }

    #[test]
    fn typematic_waits_250_ms_runs_at_30_hz_and_skips_backlog() {
        let mut keyboard = BootKeyboard::new();
        let start = 1_000_000_000;
        keyboard
            .decode_at(&[0, 0, 0x04, 0, 0, 0, 0, 0], start, |_| {})
            .unwrap();

        let mut events = Vec::new();
        assert_eq!(
            keyboard.repeat_due(start + TYPEMATIC_DELAY_NS - 1, |event| events.push(event)),
            0
        );
        assert_eq!(
            keyboard.repeat_due(start + TYPEMATIC_DELAY_NS, |event| events.push(event)),
            1
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].code, KeyCode::A);
        assert!(events[0].pressed);
        assert!(events[0].repeat);
        assert_eq!(events[0].character, Some('a'));

        assert_eq!(
            keyboard.repeat_due(
                start + TYPEMATIC_DELAY_NS + TYPEMATIC_PERIOD_NS - 1,
                |event| events.push(event)
            ),
            0
        );
        assert_eq!(
            keyboard.repeat_due(start + TYPEMATIC_DELAY_NS + TYPEMATIC_PERIOD_NS, |event| {
                events.push(event)
            }),
            1
        );

        let after_stall = start + 10 * TYPEMATIC_DELAY_NS;
        assert_eq!(
            keyboard.repeat_due(after_stall, |event| events.push(event)),
            1
        );
        assert_eq!(
            keyboard.repeat_due(after_stall, |event| events.push(event)),
            0,
            "one service call never replays an unbounded repeat backlog"
        );
    }

    #[test]
    fn newest_repeatable_key_wins_and_release_rearms_previous_key() {
        let mut keyboard = BootKeyboard::new();
        keyboard
            .decode_at(&[0, 0, 0x04, 0, 0, 0, 0, 0], 0, |_| {})
            .unwrap();
        keyboard
            .decode_at(&[0, 0, 0x04, 0x05, 0, 0, 0, 0], 100_000_000, |_| {})
            .unwrap();

        let mut events = Vec::new();
        assert_eq!(keyboard.repeat_due(349_999_999, |_| {}), 0);
        assert_eq!(
            keyboard.repeat_due(350_000_000, |event| events.push(event)),
            1
        );
        assert_eq!(events.last().map(|event| event.code), Some(KeyCode::B));

        keyboard
            .decode_at(&[0, 0, 0x04, 0, 0, 0, 0, 0], 400_000_000, |_| {})
            .unwrap();
        assert_eq!(keyboard.repeat_due(649_999_999, |_| {}), 0);
        assert_eq!(
            keyboard.repeat_due(650_000_000, |event| events.push(event)),
            1
        );
        assert_eq!(events.last().map(|event| event.code), Some(KeyCode::A));
    }

    #[test]
    fn modifier_changes_affect_repeat_character_but_lock_keys_do_not_repeat() {
        let mut keyboard = BootKeyboard::new();
        keyboard
            .decode_at(&[0, 0, 0x04, 0, 0, 0, 0, 0], 0, |_| {})
            .unwrap();
        keyboard
            .decode_at(&[0x02, 0, 0x04, 0, 0, 0, 0, 0], 10, |_| {})
            .unwrap();
        let mut repeated = None;
        assert_eq!(
            keyboard.repeat_due(TYPEMATIC_DELAY_NS, |event| repeated = Some(event)),
            1
        );
        assert_eq!(repeated.and_then(|event| event.character), Some('A'));

        keyboard
            .decode_at(&[0, 0, 0x39, 0, 0, 0, 0, 0], TYPEMATIC_DELAY_NS + 1, |_| {})
            .unwrap();
        assert_eq!(keyboard.repeat_due(u64::MAX - 1, |_| {}), 0);
    }

    #[test]
    fn disconnect_releases_every_held_key_and_modifier_then_resets_state() {
        let mut keyboard = BootKeyboard::new();
        keyboard
            .decode_at(&[0x02, 0, 0x04, 0x05, 0, 0, 0, 0], 100, |_| {})
            .unwrap();

        let mut events = Vec::new();
        assert_eq!(keyboard.disconnect(|event| events.push(event)), 3);
        assert_eq!(events.iter().map(|event| event.code).collect::<Vec<_>>(), [
            KeyCode::A,
            KeyCode::B,
            KeyCode::LeftShift
        ]);
        assert!(events.iter().all(|event| !event.pressed && !event.repeat));
        assert!(keyboard.modifiers().is_empty());
        assert_eq!(keyboard.repeat_due(u64::MAX, |_| {}), 0);
        assert_eq!(keyboard.disconnect(|_| {}), 0);
    }

    #[test]
    fn mouse_sign_extends_axes_and_maps_five_buttons() {
        let mut mouse = BootMouse::new();
        let event = mouse.decode(&[0x1f, 0xff, 0x7f, 0xfe]).unwrap();
        assert_eq!(event.dx, -1);
        assert_eq!(event.dy, 127);
        assert_eq!(event.dz, -2);
        assert!(event.buttons.contains(MouseButtons::LEFT));
        assert!(event.buttons.contains(MouseButtons::FORWARD));
    }

    #[test]
    fn mouse_disconnect_releases_held_buttons_once() {
        let mut mouse = BootMouse::new();
        mouse.decode(&[0x03, 4, 0xfd]).unwrap();

        let release = mouse.disconnect().expect("held buttons need a release");
        assert_eq!(release, MouseEvent::default());
        assert_eq!(mouse.disconnect(), None);
    }

    #[test]
    fn mouse_disconnect_ignores_motion_without_held_buttons() {
        let mut mouse = BootMouse::new();
        mouse.decode(&[0, 12, 7, 1]).unwrap();
        assert_eq!(mouse.disconnect(), None);
    }

    #[test]
    fn truncated_mouse_report_preserves_disconnect_state() {
        let mut mouse = BootMouse::new();
        mouse.decode(&[MouseButtons::LEFT.bits(), 0, 0]).unwrap();
        assert_eq!(mouse.decode(&[0, 0]), Err(HidReportError::Truncated));
        assert_eq!(mouse.disconnect(), Some(MouseEvent::default()));
    }
}
