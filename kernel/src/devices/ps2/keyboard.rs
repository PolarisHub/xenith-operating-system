//! PS/2 keyboard driver: scancode-set-1 decoding, US keymap, and IRQ queue.

use xenith_bitflags::bitflags;

use super::{
    is_initialized as controller_is_initialized, read_config, read_first_port_data, send_cmd,
    try_read_first_port_byte, write_config, write_data, ControllerConfig, Ps2ControllerError,
};
use crate::sync::SpinLockIRQ;
use crate::util::ringbuffer::RingBuffer;

const CMD_ENABLE_FIRST: u8 = 0xAE;
const KBD_RESET: u8 = 0xFF;
const KBD_DISABLE_SCANNING: u8 = 0xF5;
const KBD_ENABLE_SCANNING: u8 = 0xF4;
const KBD_SET_SCANCODE_SET: u8 = 0xF0;
const KBD_SET_LEDS: u8 = 0xED;
const SCANCODE_SET_1: u8 = 0x01;
const ACK: u8 = 0xFA;
const RESEND: u8 = 0xFE;
const SELF_TEST_PASSED: u8 = 0xAA;
const COMMAND_RETRIES: usize = 3;
// Host-scripted input can arrive between keyboard initialization and the first
// userspace terminal read. Keep the queue bounded, but large enough to retain
// several complete command lines (make and break are separate events).
const EVENT_QUEUE_CAPACITY: usize = 1024;

/// Keyboard bring-up or command failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ps2KeyboardError {
    /// The shared 8042 controller is not online.
    ControllerNotInitialized,
    /// The shared controller transport failed.
    Controller(Ps2ControllerError),
    /// The keyboard repeatedly rejected a command or returned an unexpected
    /// response byte.
    BadResponse,
    /// The keyboard's power-on self-test failed after reset.
    SelfTestFailed,
}

impl From<Ps2ControllerError> for Ps2KeyboardError {
    fn from(error: Ps2ControllerError) -> Self {
        Self::Controller(error)
    }
}

bitflags! {
    /// Modifier and lock state captured with a [`KeyEvent`].
    pub struct KeyModifiers: u16 {
        pub const LEFT_SHIFT  = 1 << 0;
        pub const RIGHT_SHIFT = 1 << 1;
        pub const LEFT_CTRL   = 1 << 2;
        pub const RIGHT_CTRL  = 1 << 3;
        pub const LEFT_ALT    = 1 << 4;
        pub const RIGHT_ALT   = 1 << 5;
        pub const LEFT_SUPER  = 1 << 6;
        pub const RIGHT_SUPER = 1 << 7;
        pub const CAPS_LOCK   = 1 << 8;
        pub const NUM_LOCK    = 1 << 9;
        pub const SCROLL_LOCK = 1 << 10;
    }
}

impl KeyModifiers {
    /// Either Shift key is held.
    #[must_use]
    pub fn shift(self) -> bool {
        self.intersects(Self::LEFT_SHIFT | Self::RIGHT_SHIFT)
    }

    /// Either Control key is held.
    #[must_use]
    pub fn control(self) -> bool {
        self.intersects(Self::LEFT_CTRL | Self::RIGHT_CTRL)
    }

    /// Either Alt key is held.
    #[must_use]
    pub fn alt(self) -> bool {
        self.intersects(Self::LEFT_ALT | Self::RIGHT_ALT)
    }
}

/// Physical keys represented by the PC/AT set-1 map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum KeyCode {
    Escape,
    Digit1,
    Digit2,
    Digit3,
    Digit4,
    Digit5,
    Digit6,
    Digit7,
    Digit8,
    Digit9,
    Digit0,
    Minus,
    Equal,
    Backspace,
    Tab,
    Q,
    W,
    E,
    R,
    T,
    Y,
    U,
    I,
    O,
    P,
    LeftBracket,
    RightBracket,
    Enter,
    LeftCtrl,
    A,
    S,
    D,
    F,
    G,
    H,
    J,
    K,
    L,
    Semicolon,
    Apostrophe,
    Grave,
    LeftShift,
    Backslash,
    Z,
    X,
    C,
    V,
    B,
    N,
    M,
    Comma,
    Period,
    Slash,
    RightShift,
    NumpadMultiply,
    LeftAlt,
    Space,
    CapsLock,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    NumLock,
    ScrollLock,
    Numpad7,
    Numpad8,
    Numpad9,
    NumpadSubtract,
    Numpad4,
    Numpad5,
    Numpad6,
    NumpadAdd,
    Numpad1,
    Numpad2,
    Numpad3,
    Numpad0,
    NumpadDecimal,
    NumpadEnter,
    NumpadDivide,
    RightCtrl,
    RightAlt,
    Home,
    ArrowUp,
    PageUp,
    ArrowLeft,
    ArrowRight,
    End,
    ArrowDown,
    PageDown,
    Insert,
    Delete,
    LeftSuper,
    RightSuper,
    Menu,
    PrintScreen,
    Pause,
    Unknown(u16),
}

/// One decoded transition from the keyboard byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    /// Physical key identity.
    pub code: KeyCode,
    /// `true` for make/repeat, `false` for break.
    pub pressed: bool,
    /// US-layout character for printable press events. Releases and
    /// non-printable keys carry `None`.
    pub character: Option<char>,
    /// Modifier/lock state after applying this transition.
    pub modifiers: KeyModifiers,
    /// Raw set-1 code. Extended keys are encoded as `0xE000 | code`.
    pub raw_scancode: u16,
    /// Whether this make arrived while the key was already down.
    pub repeat: bool,
}

struct KeyboardState {
    events: RingBuffer<KeyEvent, EVENT_QUEUE_CAPACITY>,
    modifiers: KeyModifiers,
    pressed: [u64; 4],
    extended: bool,
    pause_index: u8,
    initialized: bool,
    leds_dirty: bool,
    dropped_events: u64,
    bus_errors: u64,
}

impl KeyboardState {
    const fn new() -> Self {
        Self {
            events: RingBuffer::new(),
            modifiers: KeyModifiers::empty(),
            pressed: [0; 4],
            extended: false,
            pause_index: 0,
            initialized: false,
            leds_dirty: false,
            dropped_events: 0,
            bus_errors: 0,
        }
    }

    fn is_down(&self, id: usize) -> bool {
        self.pressed[id / 64] & (1u64 << (id % 64)) != 0
    }

    fn set_down(&mut self, id: usize, down: bool) {
        let mask = 1u64 << (id % 64);
        if down {
            self.pressed[id / 64] |= mask;
        } else {
            self.pressed[id / 64] &= !mask;
        }
    }

    fn feed(&mut self, byte: u8) -> Option<KeyEvent> {
        const PAUSE_TAIL: [u8; 5] = [0x1D, 0x45, 0xE1, 0x9D, 0xC5];

        if self.pause_index != 0 {
            let expected = PAUSE_TAIL[(self.pause_index - 1) as usize];
            if byte != expected {
                self.pause_index = u8::from(byte == 0xE1);
                return None;
            }
            self.pause_index += 1;
            if self.pause_index <= PAUSE_TAIL.len() as u8 {
                return None;
            }
            self.pause_index = 0;
            return Some(KeyEvent {
                code: KeyCode::Pause,
                pressed: true,
                character: None,
                modifiers: self.modifiers,
                raw_scancode: 0xE11D,
                repeat: false,
            });
        }

        if byte == 0xE0 {
            self.extended = true;
            return None;
        }
        if byte == 0xE1 {
            self.extended = false;
            self.pause_index = 1;
            return None;
        }

        let extended = core::mem::take(&mut self.extended);
        let pressed = byte & 0x80 == 0;
        let code_byte = byte & 0x7F;
        // E0 2A/E0 36 and E0 AA/E0 B6 are fake shifts embedded in the
        // PrintScreen sequence. They must not alter the real Shift state.
        if extended && matches!(code_byte, 0x2A | 0x36) {
            return None;
        }
        let code = decode_key(code_byte, extended);
        let id = usize::from(code_byte) | if extended { 0x80 } else { 0 };
        let was_down = self.is_down(id);
        self.set_down(id, pressed);
        self.update_modifiers(code, pressed, was_down);

        let raw = if extended {
            0xE000 | u16::from(code_byte)
        } else {
            u16::from(code_byte)
        };
        Some(KeyEvent {
            code,
            pressed,
            character: pressed
                .then(|| key_character(code, self.modifiers))
                .flatten(),
            modifiers: self.modifiers,
            raw_scancode: raw,
            repeat: pressed && was_down,
        })
    }

    fn update_modifiers(&mut self, code: KeyCode, pressed: bool, was_down: bool) {
        let momentary = match code {
            KeyCode::LeftShift => Some(KeyModifiers::LEFT_SHIFT),
            KeyCode::RightShift => Some(KeyModifiers::RIGHT_SHIFT),
            KeyCode::LeftCtrl => Some(KeyModifiers::LEFT_CTRL),
            KeyCode::RightCtrl => Some(KeyModifiers::RIGHT_CTRL),
            KeyCode::LeftAlt => Some(KeyModifiers::LEFT_ALT),
            KeyCode::RightAlt => Some(KeyModifiers::RIGHT_ALT),
            KeyCode::LeftSuper => Some(KeyModifiers::LEFT_SUPER),
            KeyCode::RightSuper => Some(KeyModifiers::RIGHT_SUPER),
            _ => None,
        };
        if let Some(flag) = momentary {
            self.modifiers.set(flag, pressed);
            return;
        }
        if pressed && !was_down {
            let lock = match code {
                KeyCode::CapsLock => Some(KeyModifiers::CAPS_LOCK),
                KeyCode::NumLock => Some(KeyModifiers::NUM_LOCK),
                KeyCode::ScrollLock => Some(KeyModifiers::SCROLL_LOCK),
                _ => None,
            };
            if let Some(flag) = lock {
                self.modifiers.toggle(flag);
                self.leds_dirty = true;
            }
        }
    }

    fn enqueue(&mut self, event: KeyEvent) {
        if let Err(event) = self.events.push(event) {
            let _ = self.events.pop();
            let _ = self.events.push(event);
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
    }
}

static KEYBOARD: SpinLockIRQ<KeyboardState> = SpinLockIRQ::new(KeyboardState::new());

fn keyboard_command(command: u8) -> Result<(), Ps2KeyboardError> {
    for _ in 0..COMMAND_RETRIES {
        write_data(command)?;
        match read_first_port_data()? {
            ACK => return Ok(()),
            RESEND => continue,
            _ => return Err(Ps2KeyboardError::BadResponse),
        }
    }
    Err(Ps2KeyboardError::BadResponse)
}

fn led_bits(modifiers: KeyModifiers) -> u8 {
    u8::from(modifiers.contains(KeyModifiers::SCROLL_LOCK))
        | (u8::from(modifiers.contains(KeyModifiers::NUM_LOCK)) << 1)
        | (u8::from(modifiers.contains(KeyModifiers::CAPS_LOCK)) << 2)
}

/// Reset and configure the keyboard for raw scancode set 1, then enable IRQ 1.
pub fn init() -> Result<(), Ps2KeyboardError> {
    if !controller_is_initialized() {
        return Err(Ps2KeyboardError::ControllerNotInitialized);
    }
    if KEYBOARD.lock().initialized {
        return Ok(());
    }

    send_cmd(CMD_ENABLE_FIRST)?;
    keyboard_command(KBD_DISABLE_SCANNING)?;
    keyboard_command(KBD_RESET)?;
    if read_first_port_data()? != SELF_TEST_PASSED {
        return Err(Ps2KeyboardError::SelfTestFailed);
    }
    keyboard_command(KBD_DISABLE_SCANNING)?;
    keyboard_command(KBD_SET_SCANCODE_SET)?;
    keyboard_command(SCANCODE_SET_1)?;
    keyboard_command(KBD_SET_LEDS)?;
    keyboard_command(0)?;

    keyboard_command(KBD_ENABLE_SCANNING)?;

    let mut config = read_config()?;
    config.insert(ControllerConfig::FIRST_INT);
    config.remove(ControllerConfig::FIRST_CLK_DISABLED | ControllerConfig::TRANSLATION);
    write_config(config)?;
    {
        let mut state = KEYBOARD.lock();
        state.initialized = true;
        state.leds_dirty = false;
    }
    ::log::info!("xenith.ps2.keyboard: scancode set 1, US keymap, IRQ 1 enabled");
    Ok(())
}

/// IRQ-1 handler. Reads at most one first-port byte and never blocks.
pub fn handle_interrupt() {
    let byte = match try_read_first_port_byte() {
        Ok(Some(byte)) => byte,
        Ok(None) => return,
        Err(_) => {
            let mut state = KEYBOARD.lock();
            state.bus_errors = state.bus_errors.saturating_add(1);
            return;
        },
    };
    let (epoch, event) = {
        let mut state = KEYBOARD.lock();
        if !state.initialized {
            return;
        }
        let epoch = crate::ui::input_epoch();
        (epoch, state.feed(byte))
    };
    if let Some(event) = event {
        crate::ui::route_key_event(epoch, event);
    }
}

/// Queue a decoded event for the kernel TTY path.
///
/// The UI router calls this while holding its epoch lock so acquiring a new
/// graphical input session cannot race a late console-queue insertion.
pub(crate) fn enqueue_console_event(event: KeyEvent) {
    KEYBOARD.lock().enqueue(event);
}

/// Pop the oldest decoded key event.
pub fn pop_event() -> Option<KeyEvent> {
    KEYBOARD.lock().events.pop()
}

/// Number of queued events.
#[must_use]
pub fn pending_events() -> usize {
    KEYBOARD.lock().events.len()
}

/// Discard all decoded events while preserving pressed-key/modifier state.
///
/// Session transitions use this to prevent a keystroke queued for the text
/// console from leaking into the newly acquired graphical input epoch.
pub(crate) fn clear_events() {
    let mut state = KEYBOARD.lock();
    state.events.clear();
    state.extended = false;
    state.pause_index = 0;
}

/// Current modifier and lock state.
#[must_use]
pub fn modifiers() -> KeyModifiers {
    KEYBOARD.lock().modifiers
}

/// Whether keyboard bring-up completed.
#[must_use]
pub fn is_initialized() -> bool {
    KEYBOARD.lock().initialized
}

/// Number of oldest events discarded because the bounded queue was full.
#[must_use]
pub fn dropped_events() -> u64 {
    KEYBOARD.lock().dropped_events
}

/// Push the current software lock state to the keyboard LEDs. This is kept
/// out of the IRQ handler because device commands are synchronous and may
/// require retries.
pub fn sync_leds() -> Result<(), Ps2KeyboardError> {
    let mut state = KEYBOARD.lock();
    if !state.leds_dirty {
        return Ok(());
    }
    keyboard_command(KBD_SET_LEDS)?;
    keyboard_command(led_bits(state.modifiers))?;
    state.leds_dirty = false;
    Ok(())
}

fn decode_key(code: u8, extended: bool) -> KeyCode {
    if extended {
        return match code {
            0x1C => KeyCode::NumpadEnter,
            0x1D => KeyCode::RightCtrl,
            0x35 => KeyCode::NumpadDivide,
            0x37 => KeyCode::PrintScreen,
            0x38 => KeyCode::RightAlt,
            0x47 => KeyCode::Home,
            0x48 => KeyCode::ArrowUp,
            0x49 => KeyCode::PageUp,
            0x4B => KeyCode::ArrowLeft,
            0x4D => KeyCode::ArrowRight,
            0x4F => KeyCode::End,
            0x50 => KeyCode::ArrowDown,
            0x51 => KeyCode::PageDown,
            0x52 => KeyCode::Insert,
            0x53 => KeyCode::Delete,
            0x5B => KeyCode::LeftSuper,
            0x5C => KeyCode::RightSuper,
            0x5D => KeyCode::Menu,
            _ => KeyCode::Unknown(0xE000 | u16::from(code)),
        };
    }
    match code {
        0x01 => KeyCode::Escape,
        0x02 => KeyCode::Digit1,
        0x03 => KeyCode::Digit2,
        0x04 => KeyCode::Digit3,
        0x05 => KeyCode::Digit4,
        0x06 => KeyCode::Digit5,
        0x07 => KeyCode::Digit6,
        0x08 => KeyCode::Digit7,
        0x09 => KeyCode::Digit8,
        0x0A => KeyCode::Digit9,
        0x0B => KeyCode::Digit0,
        0x0C => KeyCode::Minus,
        0x0D => KeyCode::Equal,
        0x0E => KeyCode::Backspace,
        0x0F => KeyCode::Tab,
        0x10 => KeyCode::Q,
        0x11 => KeyCode::W,
        0x12 => KeyCode::E,
        0x13 => KeyCode::R,
        0x14 => KeyCode::T,
        0x15 => KeyCode::Y,
        0x16 => KeyCode::U,
        0x17 => KeyCode::I,
        0x18 => KeyCode::O,
        0x19 => KeyCode::P,
        0x1A => KeyCode::LeftBracket,
        0x1B => KeyCode::RightBracket,
        0x1C => KeyCode::Enter,
        0x1D => KeyCode::LeftCtrl,
        0x1E => KeyCode::A,
        0x1F => KeyCode::S,
        0x20 => KeyCode::D,
        0x21 => KeyCode::F,
        0x22 => KeyCode::G,
        0x23 => KeyCode::H,
        0x24 => KeyCode::J,
        0x25 => KeyCode::K,
        0x26 => KeyCode::L,
        0x27 => KeyCode::Semicolon,
        0x28 => KeyCode::Apostrophe,
        0x29 => KeyCode::Grave,
        0x2A => KeyCode::LeftShift,
        0x2B => KeyCode::Backslash,
        0x2C => KeyCode::Z,
        0x2D => KeyCode::X,
        0x2E => KeyCode::C,
        0x2F => KeyCode::V,
        0x30 => KeyCode::B,
        0x31 => KeyCode::N,
        0x32 => KeyCode::M,
        0x33 => KeyCode::Comma,
        0x34 => KeyCode::Period,
        0x35 => KeyCode::Slash,
        0x36 => KeyCode::RightShift,
        0x37 => KeyCode::NumpadMultiply,
        0x38 => KeyCode::LeftAlt,
        0x39 => KeyCode::Space,
        0x3A => KeyCode::CapsLock,
        0x3B => KeyCode::F1,
        0x3C => KeyCode::F2,
        0x3D => KeyCode::F3,
        0x3E => KeyCode::F4,
        0x3F => KeyCode::F5,
        0x40 => KeyCode::F6,
        0x41 => KeyCode::F7,
        0x42 => KeyCode::F8,
        0x43 => KeyCode::F9,
        0x44 => KeyCode::F10,
        0x45 => KeyCode::NumLock,
        0x46 => KeyCode::ScrollLock,
        0x47 => KeyCode::Numpad7,
        0x48 => KeyCode::Numpad8,
        0x49 => KeyCode::Numpad9,
        0x4A => KeyCode::NumpadSubtract,
        0x4B => KeyCode::Numpad4,
        0x4C => KeyCode::Numpad5,
        0x4D => KeyCode::Numpad6,
        0x4E => KeyCode::NumpadAdd,
        0x4F => KeyCode::Numpad1,
        0x50 => KeyCode::Numpad2,
        0x51 => KeyCode::Numpad3,
        0x52 => KeyCode::Numpad0,
        0x53 => KeyCode::NumpadDecimal,
        0x57 => KeyCode::F11,
        0x58 => KeyCode::F12,
        _ => KeyCode::Unknown(u16::from(code)),
    }
}

fn key_character(code: KeyCode, modifiers: KeyModifiers) -> Option<char> {
    let shift = modifiers.shift();
    let caps = modifiers.contains(KeyModifiers::CAPS_LOCK);
    let upper = shift ^ caps;
    let letter = |lower: char| {
        if upper {
            lower.to_ascii_uppercase()
        } else {
            lower
        }
    };
    Some(match code {
        KeyCode::A => letter('a'),
        KeyCode::B => letter('b'),
        KeyCode::C => letter('c'),
        KeyCode::D => letter('d'),
        KeyCode::E => letter('e'),
        KeyCode::F => letter('f'),
        KeyCode::G => letter('g'),
        KeyCode::H => letter('h'),
        KeyCode::I => letter('i'),
        KeyCode::J => letter('j'),
        KeyCode::K => letter('k'),
        KeyCode::L => letter('l'),
        KeyCode::M => letter('m'),
        KeyCode::N => letter('n'),
        KeyCode::O => letter('o'),
        KeyCode::P => letter('p'),
        KeyCode::Q => letter('q'),
        KeyCode::R => letter('r'),
        KeyCode::S => letter('s'),
        KeyCode::T => letter('t'),
        KeyCode::U => letter('u'),
        KeyCode::V => letter('v'),
        KeyCode::W => letter('w'),
        KeyCode::X => letter('x'),
        KeyCode::Y => letter('y'),
        KeyCode::Z => letter('z'),
        KeyCode::Digit1 => {
            if shift {
                '!'
            } else {
                '1'
            }
        },
        KeyCode::Digit2 => {
            if shift {
                '@'
            } else {
                '2'
            }
        },
        KeyCode::Digit3 => {
            if shift {
                '#'
            } else {
                '3'
            }
        },
        KeyCode::Digit4 => {
            if shift {
                '$'
            } else {
                '4'
            }
        },
        KeyCode::Digit5 => {
            if shift {
                '%'
            } else {
                '5'
            }
        },
        KeyCode::Digit6 => {
            if shift {
                '^'
            } else {
                '6'
            }
        },
        KeyCode::Digit7 => {
            if shift {
                '&'
            } else {
                '7'
            }
        },
        KeyCode::Digit8 => {
            if shift {
                '*'
            } else {
                '8'
            }
        },
        KeyCode::Digit9 => {
            if shift {
                '('
            } else {
                '9'
            }
        },
        KeyCode::Digit0 => {
            if shift {
                ')'
            } else {
                '0'
            }
        },
        KeyCode::Minus => {
            if shift {
                '_'
            } else {
                '-'
            }
        },
        KeyCode::Equal => {
            if shift {
                '+'
            } else {
                '='
            }
        },
        KeyCode::LeftBracket => {
            if shift {
                '{'
            } else {
                '['
            }
        },
        KeyCode::RightBracket => {
            if shift {
                '}'
            } else {
                ']'
            }
        },
        KeyCode::Backslash => {
            if shift {
                '|'
            } else {
                '\\'
            }
        },
        KeyCode::Semicolon => {
            if shift {
                ':'
            } else {
                ';'
            }
        },
        KeyCode::Apostrophe => {
            if shift {
                '"'
            } else {
                '\''
            }
        },
        KeyCode::Grave => {
            if shift {
                '~'
            } else {
                '`'
            }
        },
        KeyCode::Comma => {
            if shift {
                '<'
            } else {
                ','
            }
        },
        KeyCode::Period => {
            if shift {
                '>'
            } else {
                '.'
            }
        },
        KeyCode::Slash => {
            if shift {
                '?'
            } else {
                '/'
            }
        },
        KeyCode::Space => ' ',
        KeyCode::Tab => '\t',
        KeyCode::Enter | KeyCode::NumpadEnter => '\n',
        KeyCode::Backspace => '\u{8}',
        KeyCode::Escape => '\u{1b}',
        KeyCode::NumpadMultiply => '*',
        KeyCode::NumpadDivide => '/',
        KeyCode::NumpadSubtract => '-',
        KeyCode::NumpadAdd => '+',
        KeyCode::Numpad0 if modifiers.contains(KeyModifiers::NUM_LOCK) => '0',
        KeyCode::Numpad1 if modifiers.contains(KeyModifiers::NUM_LOCK) => '1',
        KeyCode::Numpad2 if modifiers.contains(KeyModifiers::NUM_LOCK) => '2',
        KeyCode::Numpad3 if modifiers.contains(KeyModifiers::NUM_LOCK) => '3',
        KeyCode::Numpad4 if modifiers.contains(KeyModifiers::NUM_LOCK) => '4',
        KeyCode::Numpad5 if modifiers.contains(KeyModifiers::NUM_LOCK) => '5',
        KeyCode::Numpad6 if modifiers.contains(KeyModifiers::NUM_LOCK) => '6',
        KeyCode::Numpad7 if modifiers.contains(KeyModifiers::NUM_LOCK) => '7',
        KeyCode::Numpad8 if modifiers.contains(KeyModifiers::NUM_LOCK) => '8',
        KeyCode::Numpad9 if modifiers.contains(KeyModifiers::NUM_LOCK) => '9',
        KeyCode::NumpadDecimal if modifiers.contains(KeyModifiers::NUM_LOCK) => '.',
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_follow_shift_xor_caps() {
        assert_eq!(key_character(KeyCode::A, KeyModifiers::empty()), Some('a'));
        assert_eq!(
            key_character(KeyCode::A, KeyModifiers::LEFT_SHIFT),
            Some('A')
        );
        assert_eq!(
            key_character(KeyCode::A, KeyModifiers::CAPS_LOCK),
            Some('A')
        );
        assert_eq!(
            key_character(
                KeyCode::A,
                KeyModifiers::CAPS_LOCK | KeyModifiers::LEFT_SHIFT
            ),
            Some('a')
        );
    }

    #[test]
    fn make_break_and_repeat_are_tracked() {
        let mut state = KeyboardState::new();
        let first = state.feed(0x1E).unwrap();
        assert!(first.pressed);
        assert!(!first.repeat);
        assert_eq!(first.character, Some('a'));
        assert!(state.feed(0x1E).unwrap().repeat);
        let release = state.feed(0x9E).unwrap();
        assert!(!release.pressed);
        assert_eq!(release.character, None);
    }

    #[test]
    fn extended_navigation_decodes() {
        let mut state = KeyboardState::new();
        assert!(state.feed(0xE0).is_none());
        let event = state.feed(0x48).unwrap();
        assert_eq!(event.code, KeyCode::ArrowUp);
        assert_eq!(event.raw_scancode, 0xE048);
    }

    #[test]
    fn extended_left_super_preserves_raw_code_and_modifier_edges() {
        let mut state = KeyboardState::new();
        assert!(state.feed(0xE0).is_none());
        let make = state.feed(0x5B).unwrap();
        assert_eq!(make.code, KeyCode::LeftSuper);
        assert_eq!(make.raw_scancode, 0xE05B);
        assert!(make.pressed);
        assert!(!make.repeat);
        assert!(make.modifiers.contains(KeyModifiers::LEFT_SUPER));

        assert!(state.feed(0xE0).is_none());
        let release = state.feed(0xDB).unwrap();
        assert_eq!(release.code, KeyCode::LeftSuper);
        assert_eq!(release.raw_scancode, 0xE05B);
        assert!(!release.pressed);
        assert!(!release.modifiers.contains(KeyModifiers::LEFT_SUPER));
    }

    #[test]
    fn pause_sequence_emits_one_event() {
        let mut state = KeyboardState::new();
        for byte in [0xE1, 0x1D, 0x45, 0xE1, 0x9D] {
            assert!(state.feed(byte).is_none());
        }
        assert_eq!(state.feed(0xC5).unwrap().code, KeyCode::Pause);
    }

    #[test]
    fn lock_key_does_not_toggle_on_repeat() {
        let mut state = KeyboardState::new();
        let first = state.feed(0x3A).unwrap();
        assert!(first.modifiers.contains(KeyModifiers::CAPS_LOCK));
        let repeat = state.feed(0x3A).unwrap();
        assert!(repeat.repeat);
        assert!(repeat.modifiers.contains(KeyModifiers::CAPS_LOCK));
    }
}
