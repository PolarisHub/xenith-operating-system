//! Freestanding Rust interface to the Xenith syscall ABI.

#![no_std]

pub mod args;
pub mod env;
pub mod io;
pub mod stdio;
pub mod string;
pub mod syscall;
pub mod terminal;

pub use syscall::{
    channel_create, channel_recv, channel_send, gettid, mprotect, shm_create, spawn_restricted,
    spawn_thread, thread_create, thread_exit, thread_join, ui_acquire, ui_present, ui_read_events,
    ui_release, wait, Error, Result, ThreadEntry,
};
pub use xenith_abi::{
    IpcChannelPair, IpcReceiveMessage, IpcReceiveTransfer, IpcSendMessage, IpcSendTransfer,
    SigAction, SigAltStack, SigInfo, SigSet, SignalFrame, SpawnFileAction, SpawnRestrictedRequest,
    ThreadCreate, ThreadJoinResult, UiDisplayInfo, UiInputEvent, UiRect, WaitItem, IPC_ABI_VERSION,
    IPC_MAX_MESSAGE_BYTES, IPC_MAX_TRANSFERS, IPC_TIMEOUT_INFINITE, IPC_TRANSFER_RIGHT_MAP,
    IPC_TRANSFER_RIGHT_READ, IPC_TRANSFER_RIGHT_TRANSFER, IPC_TRANSFER_RIGHT_WRITE,
    SPAWN_FILE_ACTION_SIZE, SPAWN_RESTRICTED_ABI_VERSION, SPAWN_RESTRICTED_HEADER_SIZE,
    SPAWN_RESTRICTED_MAX_FILE_ACTIONS, SPAWN_RESTRICTED_REQUEST_SIZE, THREAD_ABI_VERSION,
    THREAD_MAX_PER_PROCESS, THREAD_STACK_MAX, THREAD_STACK_MIN, UI_ABI_VERSION,
    UI_DISPLAY_NATIVE_PIXEL_FORMAT, UI_EVENT_FLAG_OVERFLOW, UI_EVENT_FLAG_PRESSED,
    UI_EVENT_FLAG_REPEAT, UI_EVENT_KEY, UI_EVENT_POINTER, UI_MAX_DAMAGE_RECTS,
    UI_MAX_EVENTS_PER_READ, UI_MODIFIER_CAPS_LOCK, UI_MODIFIER_LEFT_ALT, UI_MODIFIER_LEFT_CTRL,
    UI_MODIFIER_LEFT_SHIFT, UI_MODIFIER_LEFT_SUPER, UI_MODIFIER_NUM_LOCK, UI_MODIFIER_RIGHT_ALT,
    UI_MODIFIER_RIGHT_CTRL, UI_MODIFIER_RIGHT_SHIFT, UI_MODIFIER_RIGHT_SUPER,
    UI_MODIFIER_SCROLL_LOCK, UI_POINTER_BUTTON_BACK, UI_POINTER_BUTTON_FORWARD,
    UI_POINTER_BUTTON_LEFT, UI_POINTER_BUTTON_MIDDLE, UI_POINTER_BUTTON_RIGHT, UI_TIMEOUT_INFINITE,
    WAIT_ABI_VERSION, WAIT_INTEREST_READABLE, WAIT_INTEREST_UI_INPUT, WAIT_INTEREST_WRITABLE,
    WAIT_MAX_ITEMS, WAIT_READY_HANGUP, WAIT_READY_READABLE, WAIT_READY_UI_INPUT,
    WAIT_READY_WRITABLE, WAIT_SOURCE_UI, WAIT_TIMEOUT_INFINITE,
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
