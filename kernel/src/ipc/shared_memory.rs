//! Fixed-size, zero-filled shared-memory objects.
//!
//! An object owns its physical frames until the last descriptor and mapping
//! reference disappears.  Page-table mappings borrow those frames; they must
//! never return them directly to the physical allocator.  Objects are always
//! non-executable and cannot be resized in the version-1 ABI.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use xenith_types::PhysFrame;

use crate::mm::physical;
use crate::mm::r#virtual::address_space;

pub const PAGE_SIZE: u64 = 4096;
pub const MAX_SHARED_MEMORY_OBJECT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_SHARED_MEMORY_GLOBAL_BYTES: u64 = 64 * 1024 * 1024;
const MIN_FREE_RESERVE_BYTES: u64 = 8 * 1024 * 1024;

static COMMITTED_SHARED_BYTES: AtomicU64 = AtomicU64::new(0);
/// Bytes promised to creators which have not yet finished allocating all of
/// their frames. Live objects are already reflected in the physical
/// allocator's free count; only in-flight promises must be subtracted from a
/// concurrent creator's snapshot.
static IN_FLIGHT_SHARED_BYTES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedMemoryError {
    InvalidLength,
    QuotaExceeded,
    OutOfMemory,
    InvalidOffset,
}

/// Kernel-owned backing for a fixed-size shared mapping.
pub struct SharedMemoryObject {
    length: u64,
    frames: Vec<PhysFrame>,
}

pub type SharedMemoryRef = Arc<SharedMemoryObject>;

impl SharedMemoryObject {
    /// Allocate and zero a complete object transactionally.
    pub fn create(requested_length: u64) -> Result<SharedMemoryRef, SharedMemoryError> {
        let length = validate_length(requested_length)?;
        let reservation = CreationReservation::acquire(length)?;

        let frame_count =
            usize::try_from(length / PAGE_SIZE).map_err(|_| SharedMemoryError::InvalidLength)?;
        let mut frames = Vec::new();
        if frames.try_reserve_exact(frame_count).is_err() {
            return Err(SharedMemoryError::OutOfMemory);
        }

        for _ in 0..frame_count {
            let Some(frame) = physical::allocate_frame() else {
                for allocated in frames.drain(..) {
                    let _ = physical::deallocate(allocated);
                }
                return Err(SharedMemoryError::OutOfMemory);
            };
            zero_frame(frame);
            frames.push(frame);
        }

        // All frames are now charged in the physical allocator's free count.
        // Transfer the global quota claim to the object and remove only the
        // temporary in-flight reservation before publishing it.
        reservation.commit_to_object();
        Ok(Arc::new(Self { length, frames }))
    }

    #[must_use]
    pub const fn len(&self) -> u64 {
        self.length
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    pub fn frame_at_offset(&self, offset: u64) -> Result<PhysFrame, SharedMemoryError> {
        if offset & (PAGE_SIZE - 1) != 0 || offset >= self.length {
            return Err(SharedMemoryError::InvalidOffset);
        }
        let index =
            usize::try_from(offset / PAGE_SIZE).map_err(|_| SharedMemoryError::InvalidOffset)?;
        self.frames
            .get(index)
            .copied()
            .ok_or(SharedMemoryError::InvalidOffset)
    }

    #[must_use]
    pub fn frames(&self) -> &[PhysFrame] {
        &self.frames
    }
}

impl Drop for SharedMemoryObject {
    fn drop(&mut self) {
        for frame in self.frames.drain(..) {
            if let Err(error) = physical::deallocate(frame) {
                ::log::error!("ipc.shm: failed to free {:?}: {}", frame, error);
            }
        }
        release_quota(self.length);
    }
}

impl core::fmt::Debug for SharedMemoryObject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedMemoryObject")
            .field("length", &self.length)
            .field("frames", &self.frames.len())
            .finish()
    }
}

fn validate_length(requested: u64) -> Result<u64, SharedMemoryError> {
    if requested == 0 {
        return Err(SharedMemoryError::InvalidLength);
    }
    let length = requested
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
        .ok_or(SharedMemoryError::InvalidLength)?;
    if length == 0 || length > MAX_SHARED_MEMORY_OBJECT_BYTES {
        return Err(SharedMemoryError::QuotaExceeded);
    }
    Ok(length)
}

fn reserve_global_quota(length: u64) -> Result<(), SharedMemoryError> {
    let mut current = COMMITTED_SHARED_BYTES.load(Ordering::Acquire);
    loop {
        let next = current
            .checked_add(length)
            .filter(|total| *total <= MAX_SHARED_MEMORY_GLOBAL_BYTES)
            .ok_or(SharedMemoryError::QuotaExceeded)?;
        match COMMITTED_SHARED_BYTES.compare_exchange_weak(
            current,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

fn reserve_physical_budget(length: u64) -> Result<(), SharedMemoryError> {
    let mut current = IN_FLIGHT_SHARED_BYTES.load(Ordering::Acquire);
    loop {
        let free_bytes = physical::free_count().saturating_mul(PAGE_SIZE);
        let next = current
            .checked_add(length)
            .ok_or(SharedMemoryError::QuotaExceeded)?;
        if !physical_budget_allows(free_bytes, next, length) {
            return Err(SharedMemoryError::QuotaExceeded);
        }
        match IN_FLIGHT_SHARED_BYTES.compare_exchange_weak(
            current,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

#[inline]
const fn physical_budget_allows(free_bytes: u64, promised_bytes: u64, length: u64) -> bool {
    free_bytes.saturating_sub(promised_bytes) >= MIN_FREE_RESERVE_BYTES && length <= free_bytes / 4
}

fn release_in_flight(length: u64) {
    let previous = IN_FLIGHT_SHARED_BYTES.fetch_sub(length, Ordering::AcqRel);
    debug_assert!(
        previous >= length,
        "shared-memory in-flight quota underflow"
    );
}

fn release_quota(length: u64) {
    let previous = COMMITTED_SHARED_BYTES.fetch_sub(length, Ordering::AcqRel);
    debug_assert!(previous >= length, "shared-memory quota underflow");
}

/// RAII rollback for both quotas held while an object is being constructed.
struct CreationReservation {
    length: u64,
    in_flight: bool,
    global: bool,
}

impl CreationReservation {
    fn acquire(length: u64) -> Result<Self, SharedMemoryError> {
        reserve_global_quota(length)?;
        if let Err(error) = reserve_physical_budget(length) {
            release_quota(length);
            return Err(error);
        }
        Ok(Self {
            length,
            in_flight: true,
            global: true,
        })
    }

    fn commit_to_object(mut self) {
        release_in_flight(self.length);
        self.in_flight = false;
        // SharedMemoryObject::drop owns this release from now on.
        self.global = false;
    }
}

impl Drop for CreationReservation {
    fn drop(&mut self) {
        if self.in_flight {
            release_in_flight(self.length);
        }
        if self.global {
            release_quota(self.length);
        }
    }
}

fn zero_frame(frame: PhysFrame) {
    let address = address_space::phys_to_virt(frame.start_address()).as_u64();
    // SAFETY: the physical allocator returned an exclusive frame and its HHDM
    // alias covers one complete frame.
    unsafe { ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE as usize) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_are_page_rounded_and_bounded() {
        assert_eq!(validate_length(1), Ok(PAGE_SIZE));
        assert_eq!(validate_length(PAGE_SIZE), Ok(PAGE_SIZE));
        assert_eq!(validate_length(PAGE_SIZE + 1), Ok(PAGE_SIZE * 2));
        assert_eq!(validate_length(0), Err(SharedMemoryError::InvalidLength));
        assert_eq!(
            validate_length(MAX_SHARED_MEMORY_OBJECT_BYTES + 1),
            Err(SharedMemoryError::QuotaExceeded)
        );
        assert_eq!(
            validate_length(u64::MAX),
            Err(SharedMemoryError::InvalidLength)
        );
    }

    #[test]
    fn concurrent_creation_promises_preserve_the_free_memory_floor() {
        const MIB: u64 = 1024 * 1024;

        assert!(physical_budget_allows(64 * MIB, 16 * MIB, 16 * MIB));
        assert!(physical_budget_allows(64 * MIB, 48 * MIB, 16 * MIB));
        assert!(!physical_budget_allows(64 * MIB, 60 * MIB, 12 * MIB));
        assert!(!physical_budget_allows(64 * MIB, 16 * MIB, 20 * MIB));
    }
}
