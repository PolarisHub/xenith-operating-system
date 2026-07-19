//! Minimal `core::fmt` writer backed by stdout.

use core::fmt::{self, Write};

struct Stdout;

impl Write for Stdout {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        crate::io::write_all(crate::io::STDOUT, value.as_bytes()).map_err(|_| fmt::Error)
    }
}

pub fn _print(args: fmt::Arguments<'_>) -> fmt::Result {
    Stdout.write_fmt(args)
}
