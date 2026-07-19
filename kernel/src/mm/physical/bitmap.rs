//! Bitmap-backed physical frame allocation.
//!
//! The allocator tracks every physical frame below the highest memory-map
//! address. A set bit is unavailable and a clear bit is allocatable. Starting
//! with every bit set and only clearing complete frames from usable regions is
//! deliberately conservative: firmware holes and partial boundary frames can
//! never be handed to the mapper by accident.

use core::{fmt, slice};

use xenith_boot::{BootInfo, MemoryRegion};
use xenith_types::{PhysAddr, PhysFrame};

use super::buddy::FrameBacking;
use crate::util::Bitmap;

const FRAME_SIZE: u64 = PhysFrame::SIZE;
const BITS_PER_WORD: u64 = 64;

/// Memory maps are normally small (under twenty entries). Keeping the usable
/// spans inline lets the allocator validate frees without requiring the heap,
/// which is not online during physical-memory initialisation.
const MAX_USABLE_SPANS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrameSpan {
    start: u64,
    end: u64,
}

impl FrameSpan {
    const EMPTY: Self = Self { start: 0, end: 0 };

    const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    const fn contains(self, frame: u64) -> bool {
        frame >= self.start && frame < self.end
    }

    const fn len(self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// Failure while constructing the early physical allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitmapInitError {
    /// The bootloader supplied no non-empty physical memory ranges.
    EmptyMemoryMap,
    /// The highest reported address cannot be represented by this target's
    /// `usize`, so a Rust slice could not describe its bitmap.
    AddressSpaceTooLarge,
    /// No usable region is large enough to hold the bitmap itself.
    NoBitmapStorage,
    /// The boot map contains more usable fragments than the fixed early-boot
    /// span table can retain.
    TooManyUsableRegions,
}

impl fmt::Display for BitmapInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMemoryMap => f.write_str("empty physical memory map"),
            Self::AddressSpaceTooLarge => f.write_str("physical address space is too large"),
            Self::NoBitmapStorage => f.write_str("no usable region can hold the frame bitmap"),
            Self::TooManyUsableRegions => f.write_str("too many usable memory-map regions"),
        }
    }
}

/// Failure while returning frames to the allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeallocateError {
    /// The frame lies above the highest frame represented by the bitmap.
    OutOfRange,
    /// The frame belongs to firmware, the kernel image, the heap carve-out,
    /// or the bitmap backing store and was never available for allocation.
    Reserved,
    /// The frame is already free.
    DoubleFree,
    /// The requested run is empty or its end overflows the tracked range.
    InvalidRange,
}

impl fmt::Display for DeallocateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange => f.write_str("frame is outside the physical bitmap"),
            Self::Reserved => f.write_str("frame is permanently reserved"),
            Self::DoubleFree => f.write_str("frame is already free"),
            Self::InvalidRange => f.write_str("invalid frame range"),
        }
    }
}

/// A zero-allocation physical frame allocator built from the boot memory map.
pub struct BitmapFrameAllocator {
    bitmap: Bitmap<'static>,
    total_frames: u64,
    capacity_frames: u64,
    usable: [FrameSpan; MAX_USABLE_SPANS],
    usable_len: usize,
    bitmap_storage: FrameSpan,
    heap_storage: FrameSpan,
}

impl fmt::Debug for BitmapFrameAllocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitmapFrameAllocator")
            .field("total_frames", &self.total_frames)
            .field("capacity_frames", &self.capacity_frames)
            .field("free_frames", &self.free_count())
            .field("used_frames", &self.used_count())
            .field("usable_regions", &self.usable_len)
            .field("bitmap_storage", &self.bitmap_storage)
            .field("heap_storage", &self.heap_storage)
            .finish()
    }
}

impl BitmapFrameAllocator {
    /// Build the allocator and place its bitmap in a usable HHDM-mapped range.
    ///
    /// The returned bitmap borrows the selected physical pages for the kernel
    /// lifetime and records them as a permanent reservation before any
    /// allocation can occur.
    ///
    /// # Safety
    ///
    /// The caller must construct at most one allocator from a given physical
    /// memory map and must not otherwise access its selected bitmap pages.
    pub unsafe fn from_boot_info(boot: BootInfo) -> Result<Self, BitmapInitError> {
        let max_end = boot
            .memory_map()
            .filter_map(|region| region.end())
            .map(|end| end.as_u64())
            .max()
            .ok_or(BitmapInitError::EmptyMemoryMap)?;
        if max_end == 0 {
            return Err(BitmapInitError::EmptyMemoryMap);
        }

        let total_frames = max_end.div_ceil(FRAME_SIZE);
        let total_frames_usize =
            usize::try_from(total_frames).map_err(|_| BitmapInitError::AddressSpaceTooLarge)?;
        let words = total_frames.div_ceil(BITS_PER_WORD);
        let words_usize =
            usize::try_from(words).map_err(|_| BitmapInitError::AddressSpaceTooLarge)?;
        let bitmap_bytes = words
            .checked_mul(core::mem::size_of::<u64>() as u64)
            .ok_or(BitmapInitError::AddressSpaceTooLarge)?;
        let bitmap_frames = bitmap_bytes.div_ceil(FRAME_SIZE);

        let bitmap_start =
            select_bitmap_storage(&boot, bitmap_frames).ok_or(BitmapInitError::NoBitmapStorage)?;
        let bitmap_end = bitmap_start
            .checked_add(bitmap_frames)
            .ok_or(BitmapInitError::AddressSpaceTooLarge)?;
        let bitmap_span = FrameSpan::new(bitmap_start, bitmap_end);

        // Validate and retain every usable span before creating the static
        // bitmap slice. This keeps all fallible boot-map processing ahead of
        // publishing a kernel-lifetime borrow of the backing pages.
        let mut usable = [FrameSpan::EMPTY; MAX_USABLE_SPANS];
        let mut usable_len = 0usize;
        for region in boot.memory_map().filter(MemoryRegion::is_usable) {
            let Some(span) = complete_frames(region) else {
                continue;
            };
            if usable_len == usable.len() {
                return Err(BitmapInitError::TooManyUsableRegions);
            }
            usable[usable_len] = span;
            usable_len += 1;
        }

        // The heap is brought up after this allocator and carves 32 MiB from
        // the end of the largest suitable usable region. Reserve the same
        // range now; otherwise early page-table allocations could hand those
        // frames out before `allocator::heap_phys_claim()` is published.
        let heap_span = future_heap_span(&boot).unwrap_or(FrameSpan::EMPTY);

        let bitmap_phys = PhysAddr::new_truncate(bitmap_start * FRAME_SIZE);
        let bitmap_virt = boot.phys_to_virt(bitmap_phys);
        let words_ptr = bitmap_virt.as_u64() as *mut u64;

        // SAFETY: `select_bitmap_storage` chose `bitmap_frames` complete usable
        // frames, the HHDM maps them writable, and no reference to the range
        // has been published. `words_usize * 8` fits within that reservation.
        // The reservation remains allocated for the life of the kernel, so a
        // `'static` slice is valid.
        let storage: &'static mut [u64] = unsafe {
            core::ptr::write_bytes(words_ptr.cast::<u8>(), 0, words_usize * 8);
            slice::from_raw_parts_mut(words_ptr, words_usize)
        };
        let mut bitmap = Bitmap::with_len(storage, total_frames_usize);
        bitmap.set_all();

        for span in &usable[..usable_len] {
            for idx in span.start..span.end {
                bitmap.clear(idx as usize);
            }
        }

        mark_span(&mut bitmap, bitmap_span, true);
        mark_span(&mut bitmap, heap_span, true);
        // Frame zero is a useful null/sentinel value in low-level code and
        // should never become ordinary heap or page-table storage.
        if total_frames != 0 {
            bitmap.set(0);
        }

        let capacity_frames = bitmap.count_zeros() as u64;
        Ok(Self {
            bitmap,
            total_frames,
            capacity_frames,
            usable,
            usable_len,
            bitmap_storage: bitmap_span,
            heap_storage: heap_span,
        })
    }

    /// Allocate one 4 KiB frame.
    #[inline]
    #[must_use]
    pub fn allocate_frame(&mut self) -> Option<PhysFrame> {
        self.allocate_range(1)
    }

    /// Allocate one frame whose end lies at or below `exclusive_limit`.
    ///
    /// Real-mode startup vectors can address only low physical memory. This
    /// bounded allocator keeps that architectural constraint inside the
    /// frame bitmap instead of allocating arbitrary frames and leaking every
    /// unsuitable result.
    #[must_use]
    pub fn allocate_frame_below(&mut self, exclusive_limit: PhysAddr) -> Option<PhysFrame> {
        let max_frame = (exclusive_limit.as_u64() / FRAME_SIZE).min(self.total_frames);
        for idx in 1..max_frame {
            if !self.bitmap.get(idx as usize) {
                self.bitmap.set(idx as usize);
                return Some(frame_from_index(idx));
            }
        }
        None
    }

    /// Allocate `count` physically contiguous frames and return the first.
    ///
    /// No power-of-two or alignment restriction is imposed; callers needing
    /// buddy-aligned blocks should use the sibling buddy allocator.
    #[must_use]
    pub fn allocate_range(&mut self, count: usize) -> Option<PhysFrame> {
        if count == 0 {
            return None;
        }
        let start = self.bitmap.allocate_range(count)? as u64;
        Some(frame_from_index(start))
    }

    /// Return one frame, rejecting reserved and already-free frames.
    pub fn deallocate(&mut self, frame: PhysFrame) -> Result<(), DeallocateError> {
        self.deallocate_range(frame, 1)
    }

    /// Return a contiguous run previously obtained from [`allocate_range`].
    /// Validation is completed before any bit is cleared, so an invalid run
    /// cannot be partially freed.
    pub fn deallocate_range(
        &mut self,
        first: PhysFrame,
        count: usize,
    ) -> Result<(), DeallocateError> {
        if count == 0 {
            return Err(DeallocateError::InvalidRange);
        }
        let start = first.number();
        let count_u64 = count as u64;
        let end = start
            .checked_add(count_u64)
            .ok_or(DeallocateError::InvalidRange)?;
        if end > self.total_frames {
            return Err(DeallocateError::OutOfRange);
        }
        for idx in start..end {
            if !self.is_releasable(idx) {
                return Err(DeallocateError::Reserved);
            }
            if !self.bitmap.get(idx as usize) {
                return Err(DeallocateError::DoubleFree);
            }
        }
        self.bitmap.free_range(start as usize, count);
        Ok(())
    }

    /// Number of currently available frames.
    #[inline]
    #[must_use]
    pub fn free_count(&self) -> u64 {
        self.bitmap.count_zeros() as u64
    }

    /// Number of frames allocated since initialisation.
    ///
    /// Firmware holes and permanent reservations are excluded; therefore
    /// `free_count + used_count == capacity` remains true.
    #[inline]
    #[must_use]
    pub fn used_count(&self) -> u64 {
        self.capacity_frames.saturating_sub(self.free_count())
    }

    /// Number of frames this allocator can ever hand out.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        self.capacity_frames
    }

    /// Number of frame slots represented, including reserved holes.
    #[inline]
    #[must_use]
    pub const fn total_frames(&self) -> u64 {
        self.total_frames
    }

    /// Whether a frame is currently available.
    #[inline]
    #[must_use]
    pub fn is_free(&self, frame: PhysFrame) -> bool {
        let idx = frame.number();
        idx < self.total_frames && !self.bitmap.get(idx as usize)
    }

    fn is_releasable(&self, idx: u64) -> bool {
        if idx == 0 || self.bitmap_storage.contains(idx) || self.heap_storage.contains(idx) {
            return false;
        }
        self.usable[..self.usable_len]
            .iter()
            .any(|span| span.contains(idx))
    }
}

impl FrameBacking for BitmapFrameAllocator {
    fn total_frames(&self) -> u64 {
        self.total_frames
    }

    fn is_frame_free(&self, abs_idx: u64) -> bool {
        abs_idx < self.total_frames && !self.bitmap.get(abs_idx as usize)
    }

    fn mark_frame_allocated(&mut self, abs_idx: u64) {
        assert!(
            abs_idx < self.total_frames,
            "physical frame index out of range"
        );
        self.bitmap.set(abs_idx as usize);
    }

    fn mark_frame_free(&mut self, abs_idx: u64) {
        assert!(
            self.is_releasable(abs_idx),
            "attempted to free a reserved frame"
        );
        self.bitmap.clear(abs_idx as usize);
    }
}

fn complete_frames(region: MemoryRegion) -> Option<FrameSpan> {
    let start = align_up(region.start.as_u64(), FRAME_SIZE)? / FRAME_SIZE;
    let end_addr = region.start.as_u64().checked_add(region.len)?;
    let end = end_addr / FRAME_SIZE;
    (start < end).then_some(FrameSpan::new(start, end))
}

fn select_bitmap_storage(boot: &BootInfo, frames: u64) -> Option<u64> {
    boot.memory_map()
        .filter(MemoryRegion::is_usable)
        .filter_map(complete_frames)
        .find(|span| span.len() >= frames)
        .map(|span| span.start)
}

fn future_heap_span(boot: &BootInfo) -> Option<FrameSpan> {
    let heap_bytes = crate::mm::allocator::HEAP_SIZE as u64;
    let minimum = heap_bytes.checked_add(16 * 1024 * 1024)?;
    let region = boot
        .memory_map()
        .filter(MemoryRegion::is_usable)
        .filter(|region| region.len >= minimum)
        .max_by_key(|region| region.len)?;
    let end = region.end()?.as_u64();
    let start = end.checked_sub(heap_bytes)?;
    Some(FrameSpan::new(start / FRAME_SIZE, end / FRAME_SIZE))
}

fn mark_span(bitmap: &mut Bitmap<'_>, span: FrameSpan, allocated: bool) {
    for idx in span.start..span.end {
        bitmap.assign(idx as usize, allocated);
    }
}

#[inline]
fn align_up(value: u64, align: u64) -> Option<u64> {
    value.checked_add(align - 1).map(|v| v & !(align - 1))
}

#[inline]
fn frame_from_index(index: u64) -> PhysFrame {
    PhysFrame::containing_addr(PhysAddr::new_truncate(index * FRAME_SIZE))
}
