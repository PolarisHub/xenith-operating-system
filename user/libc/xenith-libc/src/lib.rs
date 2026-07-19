//! Freestanding C ABI surface for Xenith userspace.

#![no_std]

use core::ffi::{c_char, c_int, c_void};

/// # Safety
/// `destination` and `source` must be valid for `count` non-overlapping bytes.
#[no_mangle]
pub unsafe extern "C" fn memcpy(
    destination: *mut c_void,
    source: *const c_void,
    count: usize,
) -> *mut c_void {
    // SAFETY: the caller supplies C's memcpy validity and non-overlap contract.
    unsafe { core::ptr::copy_nonoverlapping(source.cast::<u8>(), destination.cast::<u8>(), count) };
    destination
}

/// # Safety
/// `destination` and `source` must be valid for `count` bytes.
#[no_mangle]
pub unsafe extern "C" fn memmove(
    destination: *mut c_void,
    source: *const c_void,
    count: usize,
) -> *mut c_void {
    // SAFETY: `ptr::copy` provides the overlap behavior required by memmove.
    unsafe { core::ptr::copy(source.cast::<u8>(), destination.cast::<u8>(), count) };
    destination
}

/// # Safety
/// `destination` must be writable for `count` bytes.
#[no_mangle]
pub unsafe extern "C" fn memset(
    destination: *mut c_void,
    value: c_int,
    count: usize,
) -> *mut c_void {
    // SAFETY: the caller guarantees the destination range is writable.
    unsafe { core::ptr::write_bytes(destination.cast::<u8>(), value as u8, count) };
    destination
}

/// # Safety
/// Both inputs must be readable for `count` bytes.
#[no_mangle]
pub unsafe extern "C" fn memcmp(left: *const c_void, right: *const c_void, count: usize) -> c_int {
    for index in 0..count {
        // SAFETY: the caller guarantees both ranges contain `count` bytes.
        let (a, b) = unsafe {
            (
                *left.cast::<u8>().add(index),
                *right.cast::<u8>().add(index),
            )
        };
        if a != b {
            return c_int::from(a) - c_int::from(b);
        }
    }
    0
}

/// # Safety
/// `string` must point to a readable NUL-terminated byte string.
#[no_mangle]
pub unsafe extern "C" fn strlen(string: *const c_char) -> usize {
    let mut length = 0usize;
    // SAFETY: each byte before the terminator is readable under the contract.
    while unsafe { *string.add(length) } != 0 {
        length += 1;
    }
    length
}

/// Write bytes through the Xenith syscall ABI.
///
/// # Safety
/// `buffer` must be readable for `count` bytes.
#[no_mangle]
pub unsafe extern "C" fn xenith_write(fd: c_int, buffer: *const c_void, count: usize) -> isize {
    // SAFETY: the caller guarantees the input byte range.
    let bytes = unsafe { core::slice::from_raw_parts(buffer.cast::<u8>(), count) };
    libuser::syscall::write(fd, bytes).map_or_else(|error| -(error.0 as isize), |n| n as isize)
}

/// Read bytes through the Xenith syscall ABI.
///
/// # Safety
/// `buffer` must be writable for `count` bytes.
#[no_mangle]
pub unsafe extern "C" fn xenith_read(fd: c_int, buffer: *mut c_void, count: usize) -> isize {
    // SAFETY: the caller guarantees the output byte range.
    let bytes = unsafe { core::slice::from_raw_parts_mut(buffer.cast::<u8>(), count) };
    libuser::syscall::read(fd, bytes).map_or_else(|error| -(error.0 as isize), |n| n as isize)
}

#[no_mangle]
pub extern "C" fn xenith_close(fd: c_int) -> c_int {
    libuser::syscall::close(fd).map_or_else(|error| -error.0, |()| 0)
}

#[no_mangle]
pub extern "C" fn xenith_dup(fd: c_int) -> c_int {
    libuser::syscall::dup(fd).unwrap_or_else(|error| -error.0)
}

#[no_mangle]
pub extern "C" fn xenith_dup2(old_fd: c_int, new_fd: c_int) -> c_int {
    libuser::syscall::dup2(old_fd, new_fd).unwrap_or_else(|error| -error.0)
}

/// # Safety
/// `descriptors` must point to writable storage for two `int` values.
#[no_mangle]
pub unsafe extern "C" fn xenith_pipe(descriptors: *mut c_int) -> c_int {
    let Some(descriptors) = (unsafe { descriptors.cast::<[c_int; 2]>().as_mut() }) else {
        return -14;
    };
    libuser::syscall::pipe(descriptors).map_or_else(|error| -error.0, |()| 0)
}

/// # Safety
/// `descriptors` must point to writable storage for master and slave fds.
#[no_mangle]
pub unsafe extern "C" fn xenith_openpty(descriptors: *mut c_int) -> c_int {
    let Some(descriptors) = (unsafe { descriptors.cast::<[c_int; 2]>().as_mut() }) else {
        return -14;
    };
    libuser::syscall::openpty(descriptors).map_or_else(|error| -error.0, |()| 0)
}

#[no_mangle]
pub extern "C" fn xenith_setpgid(pid: i64, process_group: i64) -> c_int {
    libuser::syscall::setpgid(pid, process_group).map_or_else(|error| -error.0, |()| 0)
}

#[no_mangle]
pub extern "C" fn xenith_getpgrp() -> i64 {
    libuser::syscall::getpgrp().unwrap_or_else(|error| -i64::from(error.0))
}

#[no_mangle]
pub extern "C" fn xenith_setsid() -> i64 {
    libuser::syscall::setsid().unwrap_or_else(|error| -i64::from(error.0))
}

#[no_mangle]
pub extern "C" fn xenith_kill(pid: i64, signal: u32) -> c_int {
    libuser::syscall::kill(pid, signal).map_or_else(|error| -error.0, |()| 0)
}

#[no_mangle]
pub extern "C" fn xenith_ioctl(fd: c_int, command: u32, argument: usize) -> isize {
    libuser::syscall::ioctl(fd, command, argument)
        .map_or_else(|error| -(error.0 as isize), |value| value as isize)
}

/// Fill a C buffer from Xenith's kernel CSPRNG.
///
/// # Safety
/// `buffer` must be writable for `count` bytes.
#[no_mangle]
pub unsafe extern "C" fn xenith_getrandom(
    buffer: *mut c_void,
    count: usize,
    flags: u32,
) -> isize {
    if count == 0 {
        return libuser::syscall::getrandom(&mut [], flags)
            .map_or_else(|error| -(error.0 as isize), |value| value as isize);
    }
    if buffer.is_null() {
        return -14;
    }
    // SAFETY: the caller supplies the writable range required by the C ABI.
    let bytes = unsafe { core::slice::from_raw_parts_mut(buffer.cast::<u8>(), count) };
    libuser::syscall::getrandom(bytes, flags)
        .map_or_else(|error| -(error.0 as isize), |value| value as isize)
}

/// Terminate the calling process.
#[no_mangle]
pub extern "C" fn xenith_exit(status: c_int) -> ! {
    libuser::syscall::exit(status)
}
