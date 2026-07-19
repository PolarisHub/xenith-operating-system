//! Physical frame allocation.
//!
//! The global allocator is protected by a spin lock because page-table
//! allocation can occur on any CPU. Its bitmap lives in physical memory
//! selected from the boot map, so this module requires neither the heap nor a
//! fixed maximum RAM size during early bring-up.

pub mod bitmap;
pub mod buddy;

pub use bitmap::{BitmapFrameAllocator, BitmapInitError, DeallocateError};
use xenith_boot::BootInfo;
use xenith_types::{PhysAddr, PhysFrame};

use crate::sync::SpinLock;

/// The one physical allocator used by the kernel.
pub static FRAME_ALLOCATOR: SpinLock<Option<BitmapFrameAllocator>> = SpinLock::new(None);

/// Stable trait object registered with the address-space layer.
///
/// Keeping the proxy separate from the lock makes the public allocator
/// implementation independent of either of the virtual-memory module's
/// temporary frame-allocator traits.
pub struct GlobalFrameAllocator;

pub static GLOBAL_FRAME_ALLOCATOR: GlobalFrameAllocator = GlobalFrameAllocator;

/// Initialise the global bitmap from Limine's memory map.
pub fn init(boot_info: BootInfo) {
    // Check the one-shot invariant before constructing the allocator: its
    // bitmap owns a `'static` mutable HHDM slice, so a second construction
    // over the same boot map would already be invalid before assignment.
    let mut slot = FRAME_ALLOCATOR.lock();
    assert!(slot.is_none(), "mm.physical: allocator initialised twice");
    // SAFETY: the empty global slot proves this boot map has not already
    // supplied bitmap storage, and `BitmapFrameAllocator` reserves its chosen
    // pages before exposing any allocation operation.
    let allocator = unsafe { BitmapFrameAllocator::from_boot_info(boot_info) }
        .unwrap_or_else(|error| panic!("mm.physical: {error}"));
    let capacity = allocator.capacity();
    let total = allocator.total_frames();

    *slot = Some(allocator);
    drop(slot);

    crate::mm::r#virtual::address_space::register_frame_allocator(&GLOBAL_FRAME_ALLOCATOR);
    ::log::info!(
        "mm.physical: bitmap tracks {} frames, {} allocatable ({} MiB)",
        total,
        capacity,
        capacity.saturating_mul(PhysFrame::SIZE) / (1024 * 1024),
    );
}

/// Allocate one physical frame from the global allocator.
#[inline]
#[must_use]
pub fn allocate_frame() -> Option<PhysFrame> {
    FRAME_ALLOCATOR
        .lock()
        .as_mut()
        .and_then(BitmapFrameAllocator::allocate_frame)
}

/// Allocate one physical frame below an exclusive address limit.
///
/// Used by x86 AP startup, whose SIPI trampoline must live in conventional
/// memory. The selected frame remains an ordinary allocator allocation and
/// is therefore never aliased with firmware, bitmap, or heap reservations.
#[inline]
#[must_use]
pub fn allocate_frame_below(exclusive_limit: PhysAddr) -> Option<PhysFrame> {
    FRAME_ALLOCATOR
        .lock()
        .as_mut()
        .and_then(|allocator| allocator.allocate_frame_below(exclusive_limit))
}

/// Allocate a physically contiguous run and return its first frame.
#[inline]
#[must_use]
pub fn allocate_range(count: usize) -> Option<PhysFrame> {
    FRAME_ALLOCATOR
        .lock()
        .as_mut()
        .and_then(|allocator| allocator.allocate_range(count))
}

/// Return one frame to the global allocator.
pub fn deallocate(frame: PhysFrame) -> Result<(), DeallocateError> {
    let mut slot = FRAME_ALLOCATOR.lock();
    let allocator = slot.as_mut().ok_or(DeallocateError::OutOfRange)?;
    allocator.deallocate(frame)
}

/// Return a contiguous run to the global allocator.
pub fn deallocate_range(first: PhysFrame, count: usize) -> Result<(), DeallocateError> {
    let mut slot = FRAME_ALLOCATOR.lock();
    let allocator = slot.as_mut().ok_or(DeallocateError::OutOfRange)?;
    allocator.deallocate_range(first, count)
}

/// Snapshot the number of currently free frames.
#[must_use]
pub fn free_count() -> u64 {
    FRAME_ALLOCATOR
        .lock()
        .as_ref()
        .map_or(0, BitmapFrameAllocator::free_count)
}

/// Snapshot the number of frames currently checked out.
#[must_use]
pub fn used_count() -> u64 {
    FRAME_ALLOCATOR
        .lock()
        .as_ref()
        .map_or(0, BitmapFrameAllocator::used_count)
}

impl crate::mm::r#virtual::address_space::FrameAllocator for GlobalFrameAllocator {
    fn allocate(&self) -> Option<PhysFrame> {
        allocate_frame()
    }

    fn deallocate(&self, frame: PhysFrame) {
        if let Err(error) = deallocate(frame) {
            ::log::error!("mm.physical: rejected frame free {:?}: {}", frame, error);
        }
    }
}

impl crate::mm::r#virtual::paging::FrameAllocator for GlobalFrameAllocator {
    fn allocate(&self) -> Option<PhysFrame> {
        allocate_frame()
    }

    fn deallocate(&self, frame: PhysFrame) {
        if let Err(error) = deallocate(frame) {
            ::log::error!(
                "mm.physical: rejected page-table frame free {:?}: {}",
                frame,
                error
            );
        }
    }
}
