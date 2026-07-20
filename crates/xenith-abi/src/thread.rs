//! Versioned userspace-thread syscall records.
//!
//! Thread identifiers are the scheduler's never-reused 64-bit task ids. A
//! caller owns the supplied stack mapping until the thread has been joined;
//! the kernel never allocates, grows, or silently aliases a user stack.

/// Wire ABI version accepted by [`ThreadCreate`].
pub const THREAD_ABI_VERSION: u32 = 1;

/// Maximum live plus unjoined threads retained by one process.
pub const THREAD_MAX_PER_PROCESS: usize = 32;

/// Minimum private stack mapping accepted by `thread_create`.
pub const THREAD_STACK_MIN: u64 = 16 * 1024;

/// Maximum private stack mapping accepted by `thread_create`.
pub const THREAD_STACK_MAX: u64 = 8 * 1024 * 1024;

/// Create one joinable execution stream in the caller's address space.
///
/// `stack_base` and `stack_size` describe a page-aligned, writable,
/// non-executable mapping owned exclusively by the new thread while it is
/// live. `entry(argument)` begins with the SysV AMD64 calling convention and
/// must not return; libuser supplies a trampoline which converts a normal
/// return into `thread_exit`.
///
/// `tls_base` is reserved for architectural TLS support and must currently be
/// zero. Every flag and reserved field must also be zero.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct ThreadCreate {
    pub version: u32,
    pub flags: u32,
    pub entry: u64,
    pub stack_base: u64,
    pub stack_size: u64,
    pub argument: u64,
    pub tls_base: u64,
    pub reserved: [u64; 2],
}

/// Result written by `thread_join` after it consumes a completed thread.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct ThreadJoinResult {
    pub exit_code: i32,
    pub reserved: u32,
}

pub const THREAD_CREATE_SIZE: usize = core::mem::size_of::<ThreadCreate>();
pub const THREAD_JOIN_RESULT_SIZE: usize = core::mem::size_of::<ThreadJoinResult>();

const _: () = assert!(THREAD_CREATE_SIZE == 64);
const _: () = assert!(THREAD_JOIN_RESULT_SIZE == 8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_wire_records_have_stable_sizes() {
        assert_eq!(THREAD_CREATE_SIZE, 64);
        assert_eq!(THREAD_JOIN_RESULT_SIZE, 8);
        assert_eq!(core::mem::offset_of!(ThreadCreate, version), 0);
        assert_eq!(core::mem::offset_of!(ThreadCreate, flags), 4);
        assert_eq!(core::mem::offset_of!(ThreadCreate, entry), 8);
        assert_eq!(core::mem::offset_of!(ThreadCreate, stack_base), 16);
        assert_eq!(core::mem::offset_of!(ThreadCreate, stack_size), 24);
        assert_eq!(core::mem::offset_of!(ThreadCreate, argument), 32);
        assert_eq!(core::mem::offset_of!(ThreadCreate, tls_base), 40);
        assert_eq!(core::mem::offset_of!(ThreadCreate, reserved), 48);
        assert_eq!(core::mem::offset_of!(ThreadJoinResult, exit_code), 0);
        assert_eq!(core::mem::offset_of!(ThreadJoinResult, reserved), 4);
    }

    #[test]
    fn default_request_is_explicitly_unversioned_and_zeroed() {
        let request = ThreadCreate::default();
        assert_eq!(request.version, 0);
        assert_eq!(request.flags, 0);
        assert_eq!(request.reserved, [0; 2]);
    }
}
