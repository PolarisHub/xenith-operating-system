//! Environment lookup over a loader-provided start block.

use crate::args::Startup;

/// # Safety
/// `startup` must satisfy [`Startup::argument`]'s loader-memory contract.
pub unsafe fn get<'a>(startup: &'a Startup, name: &[u8]) -> Option<&'a [u8]> {
    // SAFETY: forwarded from this function's loader-memory contract.
    unsafe { startup.environment() }.get(name)
}
