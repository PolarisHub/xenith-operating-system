//! Freestanding Rust interface to the Xenith syscall ABI.

#![no_std]

pub mod args;
pub mod env;
pub mod io;
pub mod stdio;
pub mod string;
pub mod syscall;
pub mod terminal;

pub use syscall::{ui_acquire, ui_present, ui_read_events, ui_release, Error, Result};
pub use xenith_abi::{
    SigAction, SigAltStack, SigInfo, SigSet, SignalFrame, UiDisplayInfo, UiInputEvent, UiRect,
    UI_ABI_VERSION, UI_DISPLAY_NATIVE_PIXEL_FORMAT, UI_EVENT_FLAG_OVERFLOW, UI_EVENT_FLAG_PRESSED,
    UI_EVENT_FLAG_REPEAT, UI_EVENT_KEY, UI_EVENT_POINTER, UI_MAX_DAMAGE_RECTS,
    UI_MAX_EVENTS_PER_READ, UI_MODIFIER_CAPS_LOCK, UI_MODIFIER_LEFT_ALT, UI_MODIFIER_LEFT_CTRL,
    UI_MODIFIER_LEFT_SHIFT, UI_MODIFIER_LEFT_SUPER, UI_MODIFIER_NUM_LOCK, UI_MODIFIER_RIGHT_ALT,
    UI_MODIFIER_RIGHT_CTRL, UI_MODIFIER_RIGHT_SHIFT, UI_MODIFIER_RIGHT_SUPER,
    UI_MODIFIER_SCROLL_LOCK, UI_POINTER_BUTTON_BACK, UI_POINTER_BUTTON_FORWARD,
    UI_POINTER_BUTTON_LEFT, UI_POINTER_BUTTON_MIDDLE, UI_POINTER_BUTTON_RIGHT, UI_TIMEOUT_INFINITE,
};

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        let _ = $crate::stdio::_print(core::format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{
        let _ = $crate::stdio::_print(core::format_args!("{}\n", core::format_args!($($arg)*)));
    }};
}
