//! Bitmap-backed physical frame allocation.
//!
//! The allocator tracks every physical frame below the highest memory-map
//! address. A set bit is unavailable and a clear bit is allocatable. Starting
//! with every bit set and only clearing complete frames from usable regions is
//! deliberately conservative: firmware holes and partial boundary frames can
//! never be handed to the mapper by accident.

use core::{fmt, slice};

use xenith_boot::{BootInfo, MemoryRegion, RegionKind};
use xenith_types::{PhysAddr, PhysFrame};

use super::buddy::FrameBacking;
use crate::util::Bitmap;

const FRAME_SIZE: u64 = PhysFrame::SIZE;
const BITS_PER_WORD: u64 = 64;

/// Memory maps are normally small (under twenty entries). Keeping the usable
/// spans inline lets the allocator validate frees without requiring the heap,
/// which is not online during physical-memory initialisation.
const MAX_USABLE_SPANS: usize = 128;
const MAX_RECLAIMABLE_SPANS: usize = 128;

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

    const fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// A physical frame interval that delayed bootloader-memory reclamation must
/// preserve. Ranges are half-open and include every frame touched by the
/// original byte interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProtectedFrameRange(FrameSpan);

impl ProtectedFrameRange {
    pub(super) fn from_bytes(start: u64, len: u64) -> Option<Self> {
        let end = start.checked_add(len)?;
        if start == end {
            return None;
        }
        let first = start / FRAME_SIZE;
        let last = end.checked_add(FRAME_SIZE - 1)? / FRAME_SIZE;
        (first < last).then_some(Self(FrameSpan::new(first, last)))
    }

    pub(super) const fn from_frames(start: u64, end: u64) -> Option<Self> {
        if start < end {
            Some(Self(FrameSpan::new(start, end)))
        } else {
            None
        }
    }
}

/// Result of one delayed bootloader-memory reclamation attempt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReclaimReport {
    pub released_frames: u64,
    pub skipped_frames: u64,
    pub already_reclaimed: bool,
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
    /// The boot map contains more bootloader-owned fragments than the fixed
    /// delayed-reclamation table can retain.
    TooManyReclaimableRegions,
}

impl fmt::Display for BitmapInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMemoryMap => f.write_str("empty physical memory map"),
            Self::AddressSpaceTooLarge => f.write_str("physical address space is too large"),
            Self::NoBitmapStorage => f.write_str("no usable region can hold the frame bitmap"),
            Self::TooManyUsableRegions => f.write_str("too many usable memory-map regions"),
            Self::TooManyReclaimableRegions => {
                f.write_str("too many bootloader-reclaimable memory-map regions")
            },
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
    free_frames: u64,
    next_frame: usize,
    usable: [FrameSpan; MAX_USABLE_SPANS],
    usable_len: usize,
    bootloader: [FrameSpan; MAX_RECLAIMABLE_SPANS],
    bootloader_len: usize,
    released_bootloader: [FrameSpan; MAX_RECLAIMABLE_SPANS],
    released_bootloader_len: usize,
    bootloader_reclaimed: bool,
    bitmap_storage: FrameSpan,
    heap_storage: FrameSpan,
}

impl fmt::Debug for BitmapFrameAllocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitmapFrameAllocator")
            .field("total_frames", &self.total_frames)
            .field("capacity_frames", &self.capacity_frames)
            .field("free_frames", &self.free_frames)
            .field("used_frames", &self.used_count())
            .field("usable_regions", &self.usable_len)
            .field("bootloader_regions", &self.bootloader_len)
            .field("bootloader_reclaimed", &self.bootloader_reclaimed)
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

        // Heap initialisation publishes its exact adaptive physical claim
        // before the frame allocator starts. Exclude it while choosing the
        // bitmap backing; zeroing a bitmap placed inside the live heap would
        // otherwise silently corrupt allocator metadata.
        let heap_span = heap_claim_span().unwrap_or(FrameSpan::EMPTY);
        let bitmap_start = select_bitmap_storage(&boot, bitmap_frames, heap_span)
            .ok_or(BitmapInitError::NoBitmapStorage)?;
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

        let mut bootloader = [FrameSpan::EMPTY; MAX_RECLAIMABLE_SPANS];
        let mut bootloader_len = 0usize;
        for region in boot
            .memory_map()
            .filter(|region| region.kind == RegionKind::Bootloader)
        {
            let Some(span) = complete_frames(region) else {
                continue;
            };
            if bootloader_len == bootloader.len() {
                return Err(BitmapInitError::TooManyReclaimableRegions);
            }
            bootloader[bootloader_len] = span;
            bootloader_len += 1;
        }

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
        let next_frame = bitmap.find_zero_in(1, total_frames_usize).unwrap_or(1);
        Ok(Self {
            bitmap,
            total_frames,
            capacity_frames,
            free_frames: capacity_frames,
            next_frame,
            usable,
            usable_len,
            bootloader,
            bootloader_len,
            released_bootloader: [FrameSpan::EMPTY; MAX_RECLAIMABLE_SPANS],
            released_bootloader_len: 0,
            bootloader_reclaimed: false,
            bitmap_storage: bitmap_span,
            heap_storage: heap_span,
        })
    }

    /// Allocate one 4 KiB frame.
    #[inline]
    #[must_use]
    pub fn allocate_frame(&mut self) -> Option<PhysFrame> {
        if self.free_frames == 0 || self.bitmap.len() <= 1 {
            return None;
        }
        let start = self.next_frame.clamp(1, self.bitmap.len());
        let index = self
            .bitmap
            .find_zero_in(start, self.bitmap.len())
            .or_else(|| self.bitmap.find_zero_in(1, start))?;
        self.bitmap.set(index);
        self.free_frames -= 1;
        self.next_frame = next_search_index(index, self.bitmap.len());
        Some(frame_from_index(index as u64))
    }

    /// Allocate one frame whose end lies at or below `exclusive_limit`.
    ///
    /// Real-mode startup vectors can address only low physical memory. This
    /// bounded allocator keeps that architectural constraint inside the
    /// frame bitmap instead of allocating arbitrary frames and leaking every
    /// unsuitable result.
    #[must_use]
    pub fn allocate_frame_below(&mut self, exclusive_limit: PhysAddr) -> Option<PhysFrame> {
        let max_frame =
            usize::try_from((exclusive_limit.as_u64() / FRAME_SIZE).min(self.total_frames)).ok()?;
        let index = self.bitmap.find_zero_in(1, max_frame)?;
        self.bitmap.set(index);
        self.free_frames -= 1;
        self.next_frame = next_search_index(index, self.bitmap.len());
        Some(frame_from_index(index as u64))
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
        if count == 1 {
            return self.allocate_frame();
        }
        if count as u64 > self.free_frames {
            return None;
        }
        let start = self.bitmap.allocate_range(count)?;
        self.free_frames -= count as u64;
        let end = start.saturating_add(count - 1);
        self.next_frame = next_search_index(end, self.bitmap.len());
        Some(frame_from_index(start as u64))
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
        self.free_frames = self
            .free_frames
            .checked_add(count_u64)
            .expect("physical free-frame accounting overflow");
        Ok(())
    }

    /// Make complete bootloader-owned regions available after all boot-time
    /// references have been consumed.
    ///
    /// Reclamation is intentionally region-granular. If a live kernel object,
    /// module, stack, page-table allocation, or framebuffer touches a region,
    /// the entire normalized memory-map region remains reserved. That is more
    /// conservative than punching holes around individual pages and makes the
    /// ownership proof independent of allocator metadata stored in the region.
    pub(super) fn reclaim_bootloader(
        &mut self,
        protected: &[ProtectedFrameRange],
    ) -> ReclaimReport {
        if self.bootloader_reclaimed {
            return ReclaimReport {
                already_reclaimed: true,
                ..ReclaimReport::default()
            };
        }
        self.bootloader_reclaimed = true;

        let mut report = ReclaimReport::default();
        for index in 0..self.bootloader_len {
            let original = self.bootloader[index];
            let span = FrameSpan::new(original.start.max(1), original.end);
            if span.start >= span.end {
                continue;
            }
            let is_protected = protected.iter().any(|range| span.overlaps(range.0))
                || span.overlaps(self.bitmap_storage)
                || span.overlaps(self.heap_storage);
            let unexpectedly_available =
                (span.start..span.end).any(|frame| !self.bitmap.get(frame as usize));
            if is_protected || unexpectedly_available {
                report.skipped_frames = report.skipped_frames.saturating_add(span.len());
                continue;
            }

            mark_span(&mut self.bitmap, span, false);
            self.released_bootloader[self.released_bootloader_len] = span;
            self.released_bootloader_len += 1;
            self.capacity_frames = self
                .capacity_frames
                .checked_add(span.len())
                .expect("physical capacity accounting overflow");
            self.free_frames = self
                .free_frames
                .checked_add(span.len())
                .expect("physical free-frame accounting overflow");
            report.released_frames = report.released_frames.saturating_add(span.len());
            self.next_frame = self.next_frame.min(span.start as usize);
        }
        report
    }

    /// Number of currently available frames.
    #[inline]
    #[must_use]
    pub fn free_count(&self) -> u64 {
        self.free_frames
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
            || self.released_bootloader[..self.released_bootloader_len]
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
        assert!(
            !self.bitmap.get(abs_idx as usize),
            "attempted to allocate a claimed frame"
        );
        self.bitmap.set(abs_idx as usize);
        self.free_frames -= 1;
        self.next_frame = next_search_index(abs_idx as usize, self.bitmap.len());
    }

    fn mark_frame_free(&mut self, abs_idx: u64) {
        assert!(
            self.is_releasable(abs_idx),
            "attempted to free a reserved frame"
        );
        assert!(
            self.bitmap.get(abs_idx as usize),
            "attempted to free an available frame"
        );
        self.bitmap.clear(abs_idx as usize);
        self.free_frames = self
            .free_frames
            .checked_add(1)
            .expect("physical free-frame accounting overflow");
    }
}

fn complete_frames(region: MemoryRegion) -> Option<FrameSpan> {
    let start = align_up(region.start.as_u64(), FRAME_SIZE)? / FRAME_SIZE;
    let end_addr = region.start.as_u64().checked_add(region.len)?;
    let end = end_addr / FRAME_SIZE;
    (start < end).then_some(FrameSpan::new(start, end))
}

fn select_bitmap_storage(boot: &BootInfo, frames: u64, excluded: FrameSpan) -> Option<u64> {
    boot.memory_map()
        .filter(MemoryRegion::is_usable)
        .filter_map(complete_frames)
        .find_map(|span| select_disjoint_start(span, frames, excluded))
}

fn select_disjoint_start(span: FrameSpan, frames: u64, excluded: FrameSpan) -> Option<u64> {
    let before_end = span.end.min(excluded.start);
    if before_end.saturating_sub(span.start) >= frames {
        return Some(span.start);
    }

    let after_start = span.start.max(excluded.end);
    (span.end.saturating_sub(after_start) >= frames).then_some(after_start)
}

fn heap_claim_span() -> Option<FrameSpan> {
    let (start, len) = crate::mm::allocator::heap_phys_claim()?;
    let start = start.as_u64();
    let end = start.checked_add(len)?;
    let first = start / FRAME_SIZE;
    let last = end.checked_add(FRAME_SIZE - 1)? / FRAME_SIZE;
    (first < last).then_some(FrameSpan::new(first, last))
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

#[inline]
fn next_search_index(index: usize, len: usize) -> usize {
    let next = index.saturating_add(1);
    if next >= len {
        1
    } else {
        next.max(1)
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec;

    use super::*;

    fn test_allocator(
        total_frames: usize,
        usable_spans: &[(u64, u64)],
        bootloader_spans: &[(u64, u64)],
        bitmap_storage: FrameSpan,
        heap_storage: FrameSpan,
    ) -> BitmapFrameAllocator {
        let words = total_frames.div_ceil(BITS_PER_WORD as usize);
        let storage = Box::leak(vec![u64::MAX; words].into_boxed_slice());
        let mut bitmap = Bitmap::with_len(storage, total_frames);
        let mut usable = [FrameSpan::EMPTY; MAX_USABLE_SPANS];
        for (index, &(start, end)) in usable_spans.iter().enumerate() {
            usable[index] = FrameSpan::new(start, end);
            mark_span(&mut bitmap, usable[index], false);
        }
        mark_span(&mut bitmap, bitmap_storage, true);
        mark_span(&mut bitmap, heap_storage, true);
        if total_frames != 0 {
            bitmap.set(0);
        }

        let mut bootloader = [FrameSpan::EMPTY; MAX_RECLAIMABLE_SPANS];
        for (index, &(start, end)) in bootloader_spans.iter().enumerate() {
            bootloader[index] = FrameSpan::new(start, end);
        }
        let capacity = bitmap.count_zeros() as u64;
        let next_frame = bitmap.find_zero_in(1, total_frames).unwrap_or(1);
        BitmapFrameAllocator {
            bitmap,
            total_frames: total_frames as u64,
            capacity_frames: capacity,
            free_frames: capacity,
            next_frame,
            usable,
            usable_len: usable_spans.len(),
            bootloader,
            bootloader_len: bootloader_spans.len(),
            released_bootloader: [FrameSpan::EMPTY; MAX_RECLAIMABLE_SPANS],
            released_bootloader_len: 0,
            bootloader_reclaimed: false,
            bitmap_storage,
            heap_storage,
        }
    }

    fn frame(number: u64) -> PhysFrame {
        frame_from_index(number)
    }

    #[test]
    fn bitmap_storage_never_overlaps_the_adaptive_heap_claim() {
        let usable = FrameSpan::new(10, 100);

        assert_eq!(
            select_disjoint_start(usable, 30, FrameSpan::new(70, 100)),
            Some(10)
        );
        assert_eq!(
            select_disjoint_start(usable, 20, FrameSpan::new(10, 80)),
            Some(80)
        );
        assert_eq!(
            select_disjoint_start(usable, 15, FrameSpan::new(20, 90)),
            None
        );
        assert_eq!(
            select_disjoint_start(usable, 90, FrameSpan::EMPTY),
            Some(10)
        );
    }

    #[test]
    fn next_fit_single_frame_search_crosses_words_and_wraps() {
        let mut allocator = test_allocator(
            130,
            &[(5, 6), (64, 65), (129, 130)],
            &[],
            FrameSpan::EMPTY,
            FrameSpan::EMPTY,
        );
        allocator.next_frame = 63;

        assert_eq!(allocator.allocate_frame(), Some(frame(64)));
        assert_eq!(allocator.allocate_frame(), Some(frame(129)));
        assert_eq!(allocator.allocate_frame(), Some(frame(5)));
        assert_eq!(allocator.allocate_frame(), None);
        assert_eq!(allocator.free_count(), 0);
        assert_eq!(allocator.used_count(), allocator.capacity());
    }

    #[test]
    fn low_limit_and_permanent_reservations_are_never_crossed() {
        let mut allocator = test_allocator(
            20,
            &[(1, 20)],
            &[],
            FrameSpan::new(2, 3),
            FrameSpan::new(10, 12),
        );
        let capacity = allocator.capacity();

        assert_eq!(
            allocator.allocate_frame_below(PhysAddr::new_truncate(2 * FRAME_SIZE)),
            Some(frame(1))
        );
        assert_eq!(
            allocator.allocate_frame_below(PhysAddr::new_truncate(2 * FRAME_SIZE)),
            None
        );
        assert_eq!(
            allocator.deallocate(frame(2)),
            Err(DeallocateError::Reserved)
        );
        assert_eq!(
            allocator.deallocate(frame(10)),
            Err(DeallocateError::Reserved)
        );

        while allocator.allocate_frame().is_some() {}
        assert!(!allocator.is_free(frame(0)));
        assert!(!allocator.is_free(frame(2)));
        assert!(!allocator.is_free(frame(10)));
        assert!(!allocator.is_free(frame(11)));
        assert_eq!(allocator.used_count(), capacity);
    }

    #[test]
    fn deallocation_is_transactional_and_capacity_accounting_is_constant() {
        let mut allocator = test_allocator(32, &[(1, 32)], &[], FrameSpan::EMPTY, FrameSpan::EMPTY);
        let capacity = allocator.capacity();
        let first = allocator.allocate_range(3).expect("three-frame run");
        assert_eq!(allocator.free_count() + allocator.used_count(), capacity);
        assert_eq!(allocator.used_count(), 3);

        allocator.deallocate_range(first, 3).expect("valid free");
        assert_eq!(allocator.free_count(), capacity);
        assert_eq!(allocator.used_count(), 0);
        assert_eq!(
            allocator.deallocate_range(first, 3),
            Err(DeallocateError::DoubleFree)
        );
        assert_eq!(allocator.free_count(), capacity);
        assert_eq!(allocator.used_count(), 0);
    }

    #[test]
    fn reclaim_is_region_safe_idempotent_and_updates_capacity_once() {
        let mut allocator = test_allocator(
            96,
            &[(1, 4)],
            &[(64, 68), (80, 84)],
            FrameSpan::EMPTY,
            FrameSpan::EMPTY,
        );
        let initial_capacity = allocator.capacity();
        let protected = [ProtectedFrameRange::from_frames(65, 66).unwrap()];

        let report = allocator.reclaim_bootloader(&protected);
        assert_eq!(report.released_frames, 4);
        assert_eq!(report.skipped_frames, 4);
        assert!(!report.already_reclaimed);
        assert_eq!(allocator.capacity(), initial_capacity + 4);
        assert_eq!(allocator.free_count(), initial_capacity + 4);
        assert!(!allocator.is_free(frame(64)));
        assert!(allocator.is_free(frame(80)));

        let second = allocator.reclaim_bootloader(&[]);
        assert!(second.already_reclaimed);
        assert_eq!(second.released_frames, 0);
        assert_eq!(allocator.capacity(), initial_capacity + 4);
        assert_eq!(allocator.free_count(), initial_capacity + 4);

        let reclaimed = allocator.allocate_range(4).expect("reclaimed run");
        assert_eq!(reclaimed, frame(80));
        allocator
            .deallocate_range(reclaimed, 4)
            .expect("reclaimed frames are releasable");
        assert_eq!(allocator.free_count(), allocator.capacity());
        assert_eq!(
            allocator.deallocate(reclaimed),
            Err(DeallocateError::DoubleFree)
        );
    }

    #[test]
    fn reclaim_keeps_allocator_owned_spans_reserved() {
        let mut allocator = test_allocator(
            64,
            &[(1, 8)],
            &[(16, 20), (24, 28)],
            FrameSpan::new(16, 17),
            FrameSpan::new(24, 26),
        );
        let capacity = allocator.capacity();
        let report = allocator.reclaim_bootloader(&[]);

        assert_eq!(report.released_frames, 0);
        assert_eq!(report.skipped_frames, 8);
        assert_eq!(allocator.capacity(), capacity);
        assert!(!allocator.is_free(frame(16)));
        assert!(!allocator.is_free(frame(24)));
    }

    #[test]
    fn protected_byte_ranges_cover_partial_boundary_frames() {
        assert_eq!(
            ProtectedFrameRange::from_bytes(FRAME_SIZE - 1, 2),
            ProtectedFrameRange::from_frames(0, 2)
        );
        assert_eq!(ProtectedFrameRange::from_bytes(0, 0), None);
        assert_eq!(ProtectedFrameRange::from_bytes(u64::MAX, 2), None);
    }
}
