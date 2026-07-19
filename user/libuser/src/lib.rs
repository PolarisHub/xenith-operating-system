//! Freestanding Rust interface to the Xenith syscall ABI.

#![no_std]

pub mod args;
pub mod env;
pub mod io;
pub mod stdio;
pub mod string;
pub mod syscall;
pub mod terminal;

pub use syscall::{Error, Result};
pub use xenith_abi::{SigAction, SigAltStack, SigInfo, SigSet, SignalFrame};

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
