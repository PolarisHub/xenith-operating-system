//! Typed terminal control helpers over `ioctl(2)`.

use xenith_abi::{
    TerminalAttributes, WindowSize, TCGETS, TCSETS, TCSETSF, TCSETSW, TIOCGPGRP, TIOCGPTN,
    TIOCGWINSZ, TIOCSPGRP, TIOCSWINSZ,
};

use crate::syscall::{self, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetAttributesWhen {
    Now,
    Drain,
    Flush,
}

pub fn get_attributes(fd: i32) -> Result<TerminalAttributes> {
    let mut attributes = TerminalAttributes::default();
    syscall::ioctl(
        fd,
        TCGETS,
        (&mut attributes as *mut TerminalAttributes) as usize,
    )
    .map(|_| attributes)
}

pub fn set_attributes(
    fd: i32,
    when: SetAttributesWhen,
    attributes: &TerminalAttributes,
) -> Result<()> {
    let command = match when {
        SetAttributesWhen::Now => TCSETS,
        SetAttributesWhen::Drain => TCSETSW,
        SetAttributesWhen::Flush => TCSETSF,
    };
    syscall::ioctl(
        fd,
        command,
        (attributes as *const TerminalAttributes) as usize,
    )
    .map(|_| ())
}

pub fn window_size(fd: i32) -> Result<WindowSize> {
    let mut window = WindowSize::default();
    syscall::ioctl(fd, TIOCGWINSZ, (&mut window as *mut WindowSize) as usize).map(|_| window)
}

pub fn set_window_size(fd: i32, window: &WindowSize) -> Result<()> {
    syscall::ioctl(fd, TIOCSWINSZ, (window as *const WindowSize) as usize).map(|_| ())
}

pub fn foreground_process_group(fd: i32) -> Result<i64> {
    let mut process_group = 0i64;
    syscall::ioctl(fd, TIOCGPGRP, (&mut process_group as *mut i64) as usize).map(|_| process_group)
}

pub fn set_foreground_process_group(fd: i32, process_group: i64) -> Result<()> {
    syscall::ioctl(fd, TIOCSPGRP, (&process_group as *const i64) as usize).map(|_| ())
}

/// Return the decimal component used by this master at `/dev/pts/<number>`.
pub fn pty_number(fd: i32) -> Result<u32> {
    let mut number = 0u32;
    syscall::ioctl(fd, TIOCGPTN, (&mut number as *mut u32) as usize).map(|_| number)
}
