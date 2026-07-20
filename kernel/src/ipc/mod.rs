//! Bounded local inter-process communication primitives.
//!
//! IPC objects are exposed to userspace through ordinary per-process file
//! descriptors.  The objects in this module remain policy-neutral: native
//! desktop and future compatibility servers build their protocols on top of
//! message channels and shared memory rather than adding policy to the
//! kernel.

pub mod channel;
pub mod shared_memory;
pub mod syscall;
pub mod wait;
