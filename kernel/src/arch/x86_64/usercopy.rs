//! Fault-recoverable supervisor access to userspace memory.
//!
//! The raw copy loops live in `asm/usercopy.S` so the page-fault handler can
//! identify their exact instruction ranges and redirect a fault to a fixup.
//! Callers must still validate and pin the active address space first; this
//! module only turns a fault during the final memory access into a recoverable
//! error and opens the SMAP access window when CR4.SMAP is active.

use core::sync::atomic::{AtomicBool, Ordering};

use xenith_types::{Page, VirtAddr};

use super::instructions::InterruptGuard;
use crate::mm::r#virtual::address_space::AddressSpace;
use crate::mm::r#virtual::{Mapper, PageTableFlags, USER_MAX};

static SMAP_ENABLED: AtomicBool = AtomicBool::new(false);

// The handwritten routines use the SysV x86-64 register convention even when
// this module is host-tested on Windows, whose `extern "C"` ABI would pass
// the first four arguments in RCX/RDX/R8/R9.
extern "sysv64" {
    fn xenith_copy_from_user_asm(
        destination: *mut u8,
        source: *const u8,
        length: usize,
        smap_enabled: usize,
    ) -> i32;
    fn xenith_copy_to_user_asm(
        destination: *mut u8,
        source: *const u8,
        length: usize,
        smap_enabled: usize,
    ) -> i32;

    static xenith_copy_from_user_start: u8;
    static xenith_copy_from_user_end: u8;
    static xenith_copy_from_user_fixup: u8;
    static xenith_copy_to_user_start: u8;
    static xenith_copy_to_user_end: u8;
    static xenith_copy_to_user_fixup: u8;
}

/// Publish whether CR4.SMAP is active on the current boot CPU.
///
/// This is called during architecture bring-up before any userspace task can
/// run. AP bring-up must call it after programming that AP's CR4 as well.
pub(super) fn set_smap_enabled(enabled: bool) {
    SMAP_ENABLED.store(enabled, Ordering::Release);
}

/// Whether user-copy assembly must bracket accesses with STAC/CLAC.
#[must_use]
pub fn smap_enabled() -> bool {
    SMAP_ENABLED.load(Ordering::Acquire)
}

fn validate_user_pages(pointer: u64, length: usize, write: bool) -> bool {
    if pointer == 0 {
        return false;
    }
    if length == 0 {
        return pointer <= USER_MAX;
    }
    let Some(last) = pointer.checked_add(length as u64 - 1) else {
        return false;
    };
    if last > USER_MAX {
        return false;
    }
    let Some(start) = VirtAddr::new(pointer) else {
        return false;
    };
    let Some(end) = VirtAddr::new(last) else {
        return false;
    };
    let mut page = Page::containing_addr(start);
    let last_page = Page::containing_addr(end);
    let mapper = Mapper::active();
    // SAFETY: callers hold InterruptGuard through validation and copying, so
    // the active CR3 cannot change while this non-owning view is used.
    let active_space = write.then(|| unsafe { AddressSpace::adopt_current() });
    loop {
        let Some((_, mut flags)) = mapper.translate(page) else {
            return false;
        };
        if !flags.contains(PageTableFlags::USER) {
            return false;
        }
        if write && !flags.contains(PageTableFlags::WRITABLE) {
            if !flags.contains(PageTableFlags::COPY_ON_WRITE)
                || active_space
                    .as_ref()
                    .and_then(|space| space.resolve_cow_fault(page).ok())
                    != Some(true)
            {
                return false;
            }
            let Some((_, resolved)) = mapper.translate(page) else {
                return false;
            };
            flags = resolved;
            if !flags.contains(PageTableFlags::USER | PageTableFlags::WRITABLE) {
                return false;
            }
        }
        if page == last_page {
            break;
        }
        let Some(next) = page.next() else {
            return false;
        };
        page = next;
    }
    true
}

/// Validate and copy an entire userspace slice into a kernel buffer.
///
/// The interrupt guard pins the active CR3 between the page-table walk and
/// the fault-recoverable assembly copy.
pub fn copy_from_user_slice(destination: &mut [u8], source: u64) -> bool {
    if destination.is_empty() {
        return true;
    }
    // SAFETY: a short ring-0 critical section is required to pin CR3.
    let _interrupt_guard = unsafe { InterruptGuard::disable() };
    if !validate_user_pages(source, destination.len(), false) {
        return false;
    }
    // SAFETY: validation covered every source page and the slice is writable.
    unsafe {
        copy_from_user(
            destination.as_mut_ptr(),
            source as *const u8,
            destination.len(),
        )
    }
}

/// Validate and copy a kernel slice into userspace, splitting COW leaves
/// before the copy when the active process still shares them.
pub fn copy_to_user_slice(destination: u64, source: &[u8]) -> bool {
    if source.is_empty() {
        return true;
    }
    // SAFETY: a short ring-0 critical section is required to pin CR3.
    let _interrupt_guard = unsafe { InterruptGuard::disable() };
    if !validate_user_pages(destination, source.len(), true) {
        return false;
    }
    // SAFETY: validation covered writable destination pages and source lives.
    unsafe { copy_to_user(destination as *mut u8, source.as_ptr(), source.len()) }
}

/// Copy a validated userspace range into a kernel buffer.
///
/// # Safety
///
/// `source..source+length` must have been validated against the pinned active
/// user address space, and `destination` must be writable for `length` bytes.
pub unsafe fn copy_from_user(destination: *mut u8, source: *const u8, length: usize) -> bool {
    // SAFETY: the caller supplies both valid ranges. The assembly routine
    // preserves the SysV ABI and converts a user-page #PF into a non-zero
    // return through `fault_fixup` below.
    unsafe {
        xenith_copy_from_user_asm(destination, source, length, usize::from(smap_enabled())) == 0
    }
}

/// Copy a kernel buffer into a validated writable userspace range.
///
/// # Safety
///
/// `destination..destination+length` must have been validated writable in the
/// pinned active user address space, and `source` must be readable for
/// `length` bytes.
pub unsafe fn copy_to_user(destination: *mut u8, source: *const u8, length: usize) -> bool {
    // SAFETY: see `copy_from_user`; the operand directions are reversed.
    unsafe {
        xenith_copy_to_user_asm(destination, source, length, usize::from(smap_enabled())) == 0
    }
}

/// Return the recovery target for a kernel page fault inside a user-copy loop.
#[must_use]
pub fn fault_fixup(rip: u64, fault_address: u64) -> Option<u64> {
    if fault_address > crate::mm::r#virtual::USER_MAX {
        return None;
    }

    let from_start = core::ptr::addr_of!(xenith_copy_from_user_start) as u64;
    let from_end = core::ptr::addr_of!(xenith_copy_from_user_end) as u64;
    if (from_start..from_end).contains(&rip) {
        return Some(core::ptr::addr_of!(xenith_copy_from_user_fixup) as u64);
    }

    let to_start = core::ptr::addr_of!(xenith_copy_to_user_start) as u64;
    let to_end = core::ptr::addr_of!(xenith_copy_to_user_end) as u64;
    if (to_start..to_end).contains(&rip) {
        return Some(core::ptr::addr_of!(xenith_copy_to_user_fixup) as u64);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixup_ranges_are_nonempty_and_exact() {
        let from_start = core::ptr::addr_of!(xenith_copy_from_user_start) as u64;
        let from_end = core::ptr::addr_of!(xenith_copy_from_user_end) as u64;
        let to_start = core::ptr::addr_of!(xenith_copy_to_user_start) as u64;
        let to_end = core::ptr::addr_of!(xenith_copy_to_user_end) as u64;
        assert!(from_start < from_end);
        assert!(to_start < to_end);
        assert_eq!(
            fault_fixup(from_start, 0x1000),
            Some(core::ptr::addr_of!(xenith_copy_from_user_fixup) as u64)
        );
        assert_eq!(fault_fixup(from_end, 0x1000), None);
        assert_eq!(
            fault_fixup(to_start, 0x2000),
            Some(core::ptr::addr_of!(xenith_copy_to_user_fixup) as u64)
        );
        assert_eq!(fault_fixup(to_end, 0x2000), None);
    }

    #[test]
    fn kernel_fault_addresses_are_never_recovered() {
        let start = core::ptr::addr_of!(xenith_copy_from_user_start) as u64;
        assert_eq!(fault_fixup(start, crate::mm::r#virtual::USER_MAX + 1), None);
    }

    #[test]
    fn assembly_copies_both_directions_without_smap() {
        set_smap_enabled(false);
        let source = *b"fault-safe-copy";
        let mut kernel = [0u8; 15];
        let mut user = [0u8; 15];
        // SAFETY: all arrays are live for the exact copy length.
        assert!(unsafe { copy_from_user(kernel.as_mut_ptr(), source.as_ptr(), source.len()) });
        assert_eq!(kernel, source);
        // SAFETY: the source and destination arrays are valid and disjoint.
        assert!(unsafe { copy_to_user(user.as_mut_ptr(), kernel.as_ptr(), kernel.len()) });
        assert_eq!(user, source);
    }
}
