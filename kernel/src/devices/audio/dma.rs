//! Physically contiguous storage used by the HDA bus-master engines.
//!
//! HDA's CORB, RIRB, buffer-descriptor lists, and PCM buffers are addressed
//! with physical addresses.  This owner keeps the allocation alive, exposes
//! its HHDM mapping to the CPU, and provides the ordering points used before
//! and after device DMA.  Allocation is bounded and never silently truncates
//! a physical address for controllers without 64-bit DMA support.

use core::ptr::NonNull;
use core::sync::atomic::{compiler_fence, fence, Ordering};

use xenith_types::PhysFrame;

/// Failure to create a DMA allocation with the requested addressing limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaError {
    ZeroLength,
    SizeOverflow,
    OutOfMemory,
    AddressTooHigh,
}

/// A uniquely owned, page-aligned, physically contiguous DMA allocation.
pub struct DmaRegion {
    first: PhysFrame,
    pages: usize,
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: ownership of the allocated frames moves with `DmaRegion`.  CPU
// access is serialized by the owning HDA controller lock, and CPU/device
// ordering is made explicit through `sync_for_{device,cpu}`.
unsafe impl Send for DmaRegion {}
unsafe impl Sync for DmaRegion {}

impl DmaRegion {
    /// Allocate at least `len` bytes, optionally requiring the last byte to
    /// remain at or below `max_address`.
    pub fn allocate(len: usize, max_address: Option<u64>) -> Result<Self, DmaError> {
        if len == 0 {
            return Err(DmaError::ZeroLength);
        }
        let page_size = PhysFrame::SIZE as usize;
        let pages = len
            .checked_add(page_size - 1)
            .ok_or(DmaError::SizeOverflow)?
            / page_size;
        let allocated_len = pages.checked_mul(page_size).ok_or(DmaError::SizeOverflow)?;
        let first = crate::mm::physical::allocate_range(pages).ok_or(DmaError::OutOfMemory)?;
        let physical = first.start_address().as_u64();
        let end = physical.checked_add(allocated_len as u64 - 1);
        if max_address.is_some_and(|limit| end.is_none_or(|last| last > limit)) {
            let _ = crate::mm::physical::deallocate_range(first, pages);
            return Err(DmaError::AddressTooHigh);
        }

        let virtual_address = crate::mm::phys_to_virt(first.start_address()).as_u64();
        let ptr = NonNull::new(virtual_address as *mut u8).ok_or(DmaError::OutOfMemory)?;
        // SAFETY: the allocator returned an exclusive contiguous run covering
        // `allocated_len` bytes, all writable through the HHDM.
        unsafe { ptr.as_ptr().write_bytes(0, allocated_len) };
        Ok(Self {
            first,
            pages,
            ptr,
            len: allocated_len,
        })
    }

    #[must_use]
    pub const fn physical_address(&self) -> u64 {
        self.first.start_address().as_u64()
    }

    #[must_use]
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    #[must_use]
    pub fn physical_at(&self, offset: usize) -> Option<u64> {
        (offset < self.len).then(|| self.physical_address() + offset as u64)
    }

    /// Publish CPU writes before handing descriptors or payload to HDA.
    #[inline]
    pub fn sync_for_device(&self) {
        compiler_fence(Ordering::Release);
        fence(Ordering::SeqCst);
    }

    /// Order device writes before the CPU reads a response or payload.
    #[inline]
    pub fn sync_for_cpu(&self) {
        fence(Ordering::SeqCst);
        compiler_fence(Ordering::Acquire);
    }
}

impl Drop for DmaRegion {
    fn drop(&mut self) {
        if let Err(error) = crate::mm::physical::deallocate_range(self.first, self.pages) {
            ::log::error!("hda.dma: frame release rejected: {}", error);
        }
    }
}
