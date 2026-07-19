//! Physically contiguous, HHDM-mapped DMA storage.

use core::ptr::NonNull;
use core::sync::atomic::{compiler_fence, fence, Ordering};

use xenith_types::PhysFrame;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaError {
    ZeroLength,
    OutOfMemory,
    AddressTooHigh,
}

pub struct DmaRegion {
    first: PhysFrame,
    pages: usize,
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: a DmaRegion uniquely owns its frames. Access through shared driver
// state is serialized by the adapter registry lock; the device side is
// ordered explicitly with the sync methods below.
unsafe impl Send for DmaRegion {}
unsafe impl Sync for DmaRegion {}

impl DmaRegion {
    pub fn allocate(len: usize, max_address: Option<u64>) -> Result<Self, DmaError> {
        if len == 0 {
            return Err(DmaError::ZeroLength);
        }
        let pages = len
            .checked_add(PhysFrame::SIZE as usize - 1)
            .ok_or(DmaError::OutOfMemory)?
            / PhysFrame::SIZE as usize;
        let first = crate::mm::physical::allocate_range(pages).ok_or(DmaError::OutOfMemory)?;
        let physical = first.start_address().as_u64();
        let allocated_len = pages * PhysFrame::SIZE as usize;
        if max_address.is_some_and(|maximum| {
            physical
                .checked_add(allocated_len as u64 - 1)
                .is_none_or(|end| end > maximum)
        }) {
            let _ = crate::mm::physical::deallocate_range(first, pages);
            return Err(DmaError::AddressTooHigh);
        }
        let virtual_address = crate::mm::phys_to_virt(first.start_address()).as_u64();
        let ptr = NonNull::new(virtual_address as *mut u8).ok_or(DmaError::OutOfMemory)?;
        // SAFETY: the allocated frame run is writable through the HHDM and
        // spans `allocated_len` bytes. Zeroing prevents stale kernel data from
        // becoming device-visible and establishes valid zero descriptors.
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
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
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

    pub fn slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let end = offset.checked_add(len)?;
        if end > self.len {
            return None;
        }
        // SAFETY: the bounds above constrain this shared slice to the owned
        // frame run. Device-written memory must be synchronized first.
        Some(unsafe { core::slice::from_raw_parts(self.ptr.as_ptr().add(offset), len) })
    }

    pub fn slice_mut(&mut self, offset: usize, len: usize) -> Option<&mut [u8]> {
        let end = offset.checked_add(len)?;
        if end > self.len {
            return None;
        }
        // SAFETY: `&mut self` gives unique CPU access and the checked span is
        // wholly inside this region.
        Some(unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr().add(offset), len) })
    }

    #[inline]
    pub fn sync_for_device(&self) {
        compiler_fence(Ordering::Release);
        fence(Ordering::SeqCst);
    }

    #[inline]
    pub fn sync_for_cpu(&self) {
        fence(Ordering::SeqCst);
        compiler_fence(Ordering::Acquire);
    }
}

impl Drop for DmaRegion {
    fn drop(&mut self) {
        if let Err(error) = crate::mm::physical::deallocate_range(self.first, self.pages) {
            ::log::error!("net.dma: frame release rejected: {}", error);
        }
    }
}
