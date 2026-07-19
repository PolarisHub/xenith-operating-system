//! File-descriptor constants and exact I/O helpers.

use crate::syscall::{self, Error, Result};

pub const STDIN: i32 = 0;
pub const STDOUT: i32 = 1;
pub const STDERR: i32 = 2;

pub fn write_all(fd: i32, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        let written = syscall::write(fd, bytes)?;
        if written == 0 {
            return Err(Error(5));
        }
        bytes = &bytes[written..];
    }
    Ok(())
}
