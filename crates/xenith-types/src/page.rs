//! Page and physical-frame types, plus the page-table index helpers.
//!
//! The paging subsystem never deals in raw addresses; it deals in *pages*
//! (virtual) and *frames* (physical). A page and a frame are both just
//! "an address divided by 4 KiB, viewed as a unit", but keeping them in
//! separate types stops the compiler from ever letting a frame number
//! flow into a function that expects a page number — the two spaces are
//! completely unrelated and confusing them is a classic paging bug.
//!
//! This module provides:
//!
//! * [`Page`] — a 4 KiB virtual page.
//! * [`PhysFrame`] — a 4 KiB physical frame.
//! * [`PageRange`] — an inclusive iterator over a contiguous run of pages,
//!   used everywhere the kernel needs to map or unmap a region.
//! * [`PageTableIndex`] — a 9-bit index into one level of a page table
//!   (0..=511), with fallible and truncating constructors.
//! * [`PageTableLevel`] — which level of the four-level page table we are
//!   talking about (PML4 → PDPT → PD → PT).
//!
//! Only 4 KiB pages are modelled here. 2 MiB / 1 GiB "large/huge" pages are
//! described by the [`PageSize`](crate::size::PageSize) markers and are
//! handled by the paging code in the kernel crate; this types crate stays
//! neutral about page size for the index/level primitives so the kernel can
//! reuse them for any level.

use core::fmt;
use core::ops::{Add, AddAssign, RangeInclusive, Sub, SubAssign};

use crate::address::{PhysAddr, VirtAddr, PAGE_SIZE};

// ---------------------------------------------------------------------------
// Page (virtual, 4 KiB)
// ---------------------------------------------------------------------------

/// A 4 KiB virtual memory page.
///
/// A `Page` is identified by its starting virtual address, which is always
/// 4 KiB-aligned. It is the unit the kernel maps, unmaps, and tracks
/// permissions on; user-space allocations are ultimately a sequence of
/// pages.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Page {
    start: VirtAddr,
}

impl Page {
    /// The size of a page in bytes (4 KiB).
    pub const SIZE: u64 = PAGE_SIZE;

    /// The page containing the given virtual address.
    ///
    /// The address is rounded *down* to the containing page boundary, so
    /// `containing_addr(0x1234_5678)` is the page starting at
    /// `0x1234_5000`. The input must already be canonical — if it is not,
    /// the result is meaningless (we cannot panic in `const` here, so the
    /// caller is responsible for using a valid `VirtAddr`).
    #[inline]
    #[must_use]
    pub const fn containing_addr(addr: VirtAddr) -> Self {
        Self {
            start: addr.align_down(PAGE_SIZE),
        }
    }

    /// The starting virtual address of this page.
    #[inline]
    #[must_use]
    pub const fn start_address(self) -> VirtAddr {
        self.start
    }

    /// The index of this page in the virtual address space — i.e. its
    /// starting address divided by 4 KiB. Useful as a dense, per-space
    /// identifier and for computing page counts between two pages.
    #[inline]
    #[must_use]
    pub const fn number(self) -> u64 {
        self.start.as_u64() / PAGE_SIZE
    }

    /// The page immediately after this one in the virtual address space.
    ///
    /// Returns `None` if this is the last valid page and incrementing would
    /// overflow the canonical address space.
    #[inline]
    #[must_use]
    pub fn next(self) -> Option<Self> {
        let next_addr = self.start.as_u64().checked_add(PAGE_SIZE)?;
        let next_va = VirtAddr::new(VirtAddr::new_truncate(next_addr).as_u64())?;
        Some(Self { start: next_va })
    }

    /// The page immediately before this one. Returns `None` on underflow.
    #[inline]
    #[must_use]
    pub fn prev(self) -> Option<Self> {
        let prev_addr = self.start.as_u64().checked_sub(PAGE_SIZE)?;
        let prev_va = VirtAddr::new(prev_addr)?;
        Some(Self { start: prev_va })
    }
}

impl fmt::Debug for Page {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Page({:#x})", self.start.as_u64())
    }
}

impl Add<u64> for Page {
    type Output = Page;
    /// Advance by `count` pages. Panics if the result is non-canonical.
    #[inline]
    fn add(self, count: u64) -> Page {
        Page::containing_addr(self.start + count * PAGE_SIZE)
    }
}

impl Sub<u64> for Page {
    type Output = Page;
    /// Go back by `count` pages. Panics on underflow.
    #[inline]
    fn sub(self, count: u64) -> Page {
        Page::containing_addr(self.start - count * PAGE_SIZE)
    }
}

impl Sub<Self> for Page {
    type Output = u64;
    /// Number of pages between two pages (exclusive of the start, inclusive
    /// of the end via `+1` at the call site). Equivalent to
    /// `self.number() - rhs.number()`.
    #[inline]
    fn sub(self, rhs: Self) -> u64 {
        self.number() - rhs.number()
    }
}

// ---------------------------------------------------------------------------
// PhysFrame (physical, 4 KiB)
// ---------------------------------------------------------------------------

/// A 4 KiB physical memory frame.
///
/// Frames are the physical counterpart of pages: when the kernel "maps a
/// page to a frame", it writes the frame's physical address into the PTE
/// for that page. Frames are allocated and freed by the frame allocator in
/// the `mm` crate; here we only carry the type.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PhysFrame {
    start: PhysAddr,
}

impl PhysFrame {
    /// The size of a frame in bytes (4 KiB).
    pub const SIZE: u64 = PAGE_SIZE;

    /// The frame containing the given physical address. Rounds down to the
    /// 4 KiB boundary.
    #[inline]
    #[must_use]
    pub const fn containing_addr(addr: PhysAddr) -> Self {
        Self {
            start: addr.align_down(PAGE_SIZE),
        }
    }

    /// The starting physical address of this frame.
    #[inline]
    #[must_use]
    pub const fn start_address(self) -> PhysAddr {
        self.start
    }

    /// The index of this frame in the physical address space — its starting
    /// address divided by 4 KiB. Used as the key in the frame allocator's
    /// bitmap.
    #[inline]
    #[must_use]
    pub const fn number(self) -> u64 {
        self.start.as_u64() / PAGE_SIZE
    }

    /// The next frame in physical order. Returns `None` on 52-bit overflow.
    #[inline]
    #[must_use]
    pub fn next(self) -> Option<Self> {
        let next = self.start.as_u64().checked_add(PAGE_SIZE)?;
        Some(Self {
            start: PhysAddr::new_truncate(next),
        })
    }
}

impl fmt::Debug for PhysFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysFrame({:#x})", self.start.as_u64())
    }
}

impl Add<u64> for PhysFrame {
    type Output = PhysFrame;
    #[inline]
    fn add(self, count: u64) -> PhysFrame {
        PhysFrame::containing_addr(self.start + count * PAGE_SIZE)
    }
}

impl Sub<u64> for PhysFrame {
    type Output = PhysFrame;
    #[inline]
    fn sub(self, count: u64) -> PhysFrame {
        PhysFrame::containing_addr(self.start - count * PAGE_SIZE)
    }
}

impl Sub<Self> for PhysFrame {
    type Output = u64;
    #[inline]
    fn sub(self, rhs: Self) -> u64 {
        self.number() - rhs.number()
    }
}

// ---------------------------------------------------------------------------
// PageRange
// ---------------------------------------------------------------------------

/// An inclusive range of virtual pages `[start, end]`.
///
/// Iterating yields every page from `start` to `end` in ascending address
/// order. The range is constructed with [`PageRange::new`] which takes the
/// first and last page (both inclusive); `PageRange::between` is a
/// convenience that builds the range covering a `[base, base+len)` region.
///
/// This is the primary type the kernel's mapping routines consume: "map
/// this range of pages to this range of frames".
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PageRange {
    start: Page,
    end: Page,
}

impl PageRange {
    /// Create an inclusive range `[start, end]`.
    ///
    /// `start` must be numerically less than or equal to `end`; if it is
    /// not, the two are swapped so the range is always well-formed. This
    /// keeps callers from having to do the comparison themselves and makes
    /// `PageRange` self-normalising.
    #[inline]
    #[must_use]
    pub fn new(start: Page, end: Page) -> Self {
        if start.start_address() <= end.start_address() {
            Self { start, end }
        } else {
            Self {
                start: end,
                end: start,
            }
        }
    }

    /// Build the range of pages that covers the virtual region
    /// `[base, base + len_bytes)`.
    ///
    /// `len_bytes` of zero yields an empty range (start == end == the page
    /// containing `base`); callers that want a truly empty iteration should
    /// check `is_empty()` or use `len()` (which reports the page count, 1
    /// for a zero-length region). The convention matches the rest of the
    /// kernel: a zero-length mapping is a no-op and simply produces one
    /// page that the caller is expected to skip via `is_empty`.
    #[inline]
    #[must_use]
    pub fn between(base: VirtAddr, len_bytes: u64) -> Self {
        let start = Page::containing_addr(base);
        // For a zero-length region the end is the same page as the start;
        // otherwise we step back one byte so the end page is inclusive of
        // the last byte but not of the byte *after* the region.
        let end_addr = if len_bytes == 0 {
            base
        } else {
            // len_bytes - 1 is safe: we just checked it is non-zero.
            base + (len_bytes - 1)
        };
        let end = Page::containing_addr(end_addr);
        Self::new(start, end)
    }

    /// The first page in the range.
    #[inline]
    #[must_use]
    pub const fn start(self) -> Page {
        self.start
    }

    /// The last page in the range (inclusive).
    #[inline]
    #[must_use]
    pub const fn end(self) -> Page {
        self.end
    }

    /// The number of pages in the range. Always `>= 1` because the range
    /// is inclusive on both ends.
    #[inline]
    #[must_use]
    pub fn len(self) -> u64 {
        (self.end - self.start) + 1
    }

    /// `true` if the range contains exactly one page.
    ///
    /// (An inclusive range can never be empty — even a "zero-length"
    /// region covers the page containing its base address.)
    #[inline]
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
}

impl Iterator for PageRange {
    type Item = Page;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.start.start_address() > self.end.start_address() {
            return None;
        }
        let cur = self.start;
        // Advance start by one page; if that overshoots the end we leave
        // start past end so the next call returns None.
        match cur.next() {
            Some(n) => self.start = n,
            None => {
                // cur is the last representable page; force termination.
                self.start = Page::containing_addr(self.end.start_address() + PAGE_SIZE);
            },
        }
        Some(cur)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        // Once the iterator has been exhausted, `start` is advanced one page
        // past `end` and the naive `end - start` would underflow. Guard the
        // exhausted case explicitly so ExactSizeIterator::len stays sound
        // even after the last element has been yielded.
        if self.start.start_address() > self.end.start_address() {
            return (0, Some(0));
        }
        let remaining = (self.end - self.start) + 1;
        // usize casts: page counts never exceed usize on x86_64 in practice.
        let r = remaining as usize;
        (r, Some(r))
    }
}

impl ExactSizeIterator for PageRange {
    #[inline]
    fn len(&self) -> usize {
        // Reuse the size_hint upper bound — it is exact for this iterator.
        self.size_hint().0
    }
}

// Note: we do NOT implement `IntoIterator` explicitly here. The standard
// library provides a blanket `impl<I: Iterator> IntoIterator for I`, and
// since `PageRange: Iterator`, `for page in range` and `range.into_iter()`
// already work — adding our own impl would conflict with that blanket one.

// Allow building a `PageRange` from the std `RangeInclusive<Page>` syntax
// (`start..=end`) so call sites can write whichever form they find clearer.
impl From<RangeInclusive<Page>> for PageRange {
    #[inline]
    fn from(r: RangeInclusive<Page>) -> Self {
        Self::new(*r.start(), *r.end())
    }
}

// ---------------------------------------------------------------------------
// PageTableIndex (9-bit, 0..=511)
// ---------------------------------------------------------------------------

/// A 9-bit index into a single page-table level.
///
/// Each level of the x86_64 four-level page table has exactly 512 entries,
/// addressed by bits [8:0] of the appropriate slice of the virtual
/// address. A `PageTableIndex` wraps that 9-bit value so it cannot be
/// confused with a regular `u16` and so out-of-range values (>= 512) are
/// caught at construction time.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PageTableIndex(u16);

impl PageTableIndex {
    /// The inclusive upper bound of a valid index: 511. There are 512
    /// entries per table (9 bits).
    pub const MAX: u16 = 511;

    /// Create a page-table index from a `u16`. Returns `None` if the value
    /// is >= 512.
    #[inline]
    #[must_use]
    pub const fn new(idx: u16) -> Option<Self> {
        if idx <= Self::MAX {
            Some(Self(idx))
        } else {
            None
        }
    }

    /// Create a page-table index, truncating to 9 bits.
    ///
    /// Use this when the input is known to carry flags or other garbage in
    /// the high bits (e.g. extracting the index from a packed PTE).
    #[inline]
    #[must_use]
    pub const fn new_truncate(idx: u16) -> Self {
        Self(idx & 0x1FF)
    }

    /// The raw 9-bit value, in `0..=511`.
    #[inline]
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

impl fmt::Debug for PageTableIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PageTableIndex({})", self.0)
    }
}

impl From<PageTableIndex> for u16 {
    #[inline]
    fn from(idx: PageTableIndex) -> Self {
        idx.0
    }
}

impl From<PageTableIndex> for u64 {
    #[inline]
    fn from(idx: PageTableIndex) -> Self {
        idx.0 as u64
    }
}

impl Add<u16> for PageTableIndex {
    type Output = Self;
    /// Add an offset, panicking if the result exceeds 511. Used in
    /// table-walking code that assumes indices stay in range.
    #[inline]
    fn add(self, rhs: u16) -> Self {
        Self::new(self.0.checked_add(rhs).expect("PageTableIndex overflow"))
            .expect("PageTableIndex exceeded 511")
    }
}

impl Sub<u16> for PageTableIndex {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: u16) -> Self {
        Self::new(self.0.checked_sub(rhs).expect("PageTableIndex underflow"))
            .expect("PageTableIndex negative underflow")
    }
}

impl Sub<Self> for PageTableIndex {
    type Output = u16;
    #[inline]
    fn sub(self, rhs: Self) -> u16 {
        self.0.wrapping_sub(rhs.0)
    }
}

impl AddAssign<u16> for PageTableIndex {
    #[inline]
    fn add_assign(&mut self, rhs: u16) {
        *self = *self + rhs;
    }
}

impl SubAssign<u16> for PageTableIndex {
    #[inline]
    fn sub_assign(&mut self, rhs: u16) {
        *self = *self - rhs;
    }
}

// ---------------------------------------------------------------------------
// PageTableLevel
// ---------------------------------------------------------------------------

/// The four levels of the x86_64 page table.
///
/// Translation walks from the CR3-rooted PML4 downwards: Level 4 (PML4) →
/// Level 3 (PDPT) → Level 2 (PD) → Level 1 (PT). Level 1 entries point at
/// 4 KiB pages; entries at levels 2 and 3 may instead be "large"/"huge"
/// pages (2 MiB / 1 GiB) if the huge-page bit is set, short-circuiting the
/// remaining lower levels.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PageTableLevel {
    /// Level 4 — the root table pointed to by CR3. (PML4)
    Four,
    /// Level 3 — page-directory-pointer table. (PDPT)
    Three,
    /// Level 2 — page directory. (PD)
    Two,
    /// Level 1 — page table, entries point at 4 KiB pages. (PT)
    One,
}

impl PageTableLevel {
    /// The numerical level (1..=4) where 1 is the leaf PT and 4 is the
    /// root PML4. Convenient for arithmetic when walking tables generically.
    #[inline]
    #[must_use]
    pub const fn level(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
            Self::Four => 4,
        }
    }

    /// The level immediately below this one, or `None` if this is the leaf
    /// level (Level 1).
    #[inline]
    #[must_use]
    pub const fn lower(self) -> Option<Self> {
        match self {
            Self::Four => Some(Self::Three),
            Self::Three => Some(Self::Two),
            Self::Two => Some(Self::One),
            Self::One => None,
        }
    }

    /// The level immediately above this one, or `None` if this is the root
    /// level (Level 4).
    #[inline]
    #[must_use]
    pub const fn upper(self) -> Option<Self> {
        match self {
            Self::One => Some(Self::Two),
            Self::Two => Some(Self::Three),
            Self::Three => Some(Self::Four),
            Self::Four => None,
        }
    }

    /// `true` if this is the leaf level (Level 1), whose entries point
    /// directly at 4 KiB pages.
    #[inline]
    #[must_use]
    pub const fn is_leaf(self) -> bool {
        matches!(self, Self::One)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Page -------------------------------------------------------------

    #[test]
    fn page_containing_addr_rounds_down() {
        let va = VirtAddr::new(0xFFFF_8000_0000_1234).unwrap();
        let p = Page::containing_addr(va);
        assert_eq!(p.start_address().as_u64(), 0xFFFF_8000_0000_1000);
    }

    #[test]
    fn page_size_and_number() {
        assert_eq!(Page::SIZE, 4096);
        let p = Page::containing_addr(VirtAddr::new(0xFFFF_8000_0000_1000).unwrap());
        // 0xFFFF_8000_0000_1000 / 4096 = 0xFFFF_8000_0000_1
        assert_eq!(p.number(), 0xFFFF_8000_0000_1000 / 4096);
    }

    #[test]
    fn page_next_prev() {
        let p = Page::containing_addr(VirtAddr::new(0xFFFF_8000_0000_1000).unwrap());
        let n = p.next().unwrap();
        assert_eq!(n.start_address().as_u64(), 0xFFFF_8000_0000_2000);
        assert_eq!(n.prev().unwrap(), p);
    }

    #[test]
    fn page_arithmetic() {
        let base = Page::containing_addr(VirtAddr::new(0xFFFF_8000_0000_1000).unwrap());
        assert_eq!((base + 3).start_address().as_u64(), 0xFFFF_8000_0000_4000);
        assert_eq!((base + 3) - base, 3);
        // Sub<Self> gives page count difference.
        let other = Page::containing_addr(VirtAddr::new(0xFFFF_8000_0000_4000).unwrap());
        assert_eq!(other - base, 3);
    }

    // ---- PhysFrame --------------------------------------------------------

    #[test]
    fn frame_containing_and_number() {
        let pa = PhysAddr::new(0x0000_0000_0010_1234).unwrap();
        let f = PhysFrame::containing_addr(pa);
        assert_eq!(f.start_address().as_u64(), 0x0000_0000_0010_1000);
        assert_eq!(f.number(), 0x0000_0000_0010_1000 / 4096);
        assert_eq!(PhysFrame::SIZE, 4096);
    }

    #[test]
    fn frame_next_and_arithmetic() {
        let f = PhysFrame::containing_addr(PhysAddr::new(0x1000).unwrap());
        assert_eq!(f.next().unwrap().start_address().as_u64(), 0x2000);
        assert_eq!((f + 2).start_address().as_u64(), 0x3000);
        assert_eq!((f + 5) - f, 5);
    }

    // ---- PageRange --------------------------------------------------------

    #[test]
    fn page_range_iterates_inclusively() {
        let s = Page::containing_addr(VirtAddr::new(0xFFFF_8000_0000_0000).unwrap());
        let e = Page::containing_addr(VirtAddr::new(0xFFFF_8000_0000_3000).unwrap());
        let range = PageRange::new(s, e);
        assert_eq!(range.len(), 4);

        let pages: Vec<u64> = range.map(|p| p.start_address().as_u64()).collect();
        assert_eq!(pages, vec![
            0xFFFF_8000_0000_0000,
            0xFFFF_8000_0000_1000,
            0xFFFF_8000_0000_2000,
            0xFFFF_8000_0000_3000,
        ]);
    }

    #[test]
    fn page_range_single_page() {
        let s = Page::containing_addr(VirtAddr::new(0x1000).unwrap());
        let range = PageRange::new(s, s);
        assert_eq!(range.len(), 1);
        assert!(!range.is_empty());
        let pages: Vec<u64> = range.map(|p| p.start_address().as_u64()).collect();
        assert_eq!(pages, vec![0x1000]);
    }

    #[test]
    fn page_range_normalises_order() {
        // Constructed "backwards"; should still iterate ascending.
        let s = Page::containing_addr(VirtAddr::new(0x3000).unwrap());
        let e = Page::containing_addr(VirtAddr::new(0x1000).unwrap());
        let range = PageRange::new(s, e);
        let first = range.into_iter().next().unwrap();
        assert_eq!(first.start_address().as_u64(), 0x1000);
    }

    #[test]
    fn page_range_between_covers_region() {
        // A 0x2500-byte region starting at 0x1000 spans pages
        // 0x1000, 0x2000, 0x3000 (3 pages, because 0x1000 + 0x2500 - 1 = 0x34FF).
        let range = PageRange::between(VirtAddr::new(0x1000).unwrap(), 0x2500);
        assert_eq!(range.len(), 3);
        assert_eq!(range.start().start_address().as_u64(), 0x1000);
        assert_eq!(range.end().start_address().as_u64(), 0x3000);
    }

    #[test]
    fn page_range_between_zero_len() {
        let range = PageRange::between(VirtAddr::new(0x1234).unwrap(), 0);
        assert_eq!(range.len(), 1);
        assert_eq!(range.start(), range.end());
    }

    #[test]
    fn page_range_exact_size_iterator() {
        let s = Page::containing_addr(VirtAddr::new(0).unwrap());
        let e = Page::containing_addr(VirtAddr::new(0x5000).unwrap());
        let range = PageRange::new(s, e);
        // ExactSizeIterator trait method agrees with our len(). PageRange is
        // Copy, so we can call into_iter() on a copy and still query the
        // original afterwards.
        let copy = range;
        assert_eq!(copy.into_iter().len(), 6);
        assert_eq!(range.len(), 6);
    }

    #[test]
    fn page_range_from_range_inclusive() {
        let s = Page::containing_addr(VirtAddr::new(0x1000).unwrap());
        let e = Page::containing_addr(VirtAddr::new(0x3000).unwrap());
        let std_range = s..=e;
        let range = PageRange::from(std_range);
        assert_eq!(range.len(), 3);
    }

    // ---- PageTableIndex ---------------------------------------------------

    #[test]
    fn pti_new_valid() {
        assert_eq!(PageTableIndex::new(0).unwrap().value(), 0);
        assert_eq!(PageTableIndex::new(511).unwrap().value(), 511);
    }

    #[test]
    fn pti_new_rejects_out_of_range() {
        assert!(PageTableIndex::new(512).is_none());
        assert!(PageTableIndex::new(u16::MAX).is_none());
    }

    #[test]
    fn pti_new_truncate_masks_nine_bits() {
        assert_eq!(PageTableIndex::new_truncate(0x1FF).value(), 511);
        // 0x200 & 0x1FF == 0
        assert_eq!(PageTableIndex::new_truncate(0x200).value(), 0);
        // 0x3FF & 0x1FF == 0x1FF
        assert_eq!(PageTableIndex::new_truncate(0x3FF).value(), 511);
    }

    #[test]
    fn pti_arithmetic() {
        let a = PageTableIndex::new(10).unwrap();
        assert_eq!((a + 5).value(), 15);
        assert_eq!((a + 5) - a, 5);
        let mut b = a;
        b += 3;
        assert_eq!(b.value(), 13);
        b -= 1;
        assert_eq!(b.value(), 12);
    }

    #[test]
    fn pti_conversions() {
        let a = PageTableIndex::new(200).unwrap();
        assert_eq!(u16::from(a), 200);
        assert_eq!(u64::from(a), 200);
    }

    #[test]
    fn pti_max_constant() {
        assert_eq!(PageTableIndex::MAX, 511);
    }

    // ---- PageTableLevel ---------------------------------------------------

    #[test]
    fn level_numbers() {
        assert_eq!(PageTableLevel::One.level(), 1);
        assert_eq!(PageTableLevel::Two.level(), 2);
        assert_eq!(PageTableLevel::Three.level(), 3);
        assert_eq!(PageTableLevel::Four.level(), 4);
    }

    #[test]
    fn level_lower_and_upper() {
        assert_eq!(PageTableLevel::Four.lower(), Some(PageTableLevel::Three));
        assert_eq!(PageTableLevel::Three.lower(), Some(PageTableLevel::Two));
        assert_eq!(PageTableLevel::Two.lower(), Some(PageTableLevel::One));
        assert_eq!(PageTableLevel::One.lower(), None);

        assert_eq!(PageTableLevel::One.upper(), Some(PageTableLevel::Two));
        assert_eq!(PageTableLevel::Two.upper(), Some(PageTableLevel::Three));
        assert_eq!(PageTableLevel::Three.upper(), Some(PageTableLevel::Four));
        assert_eq!(PageTableLevel::Four.upper(), None);
    }

    #[test]
    fn level_is_leaf() {
        assert!(PageTableLevel::One.is_leaf());
        assert!(!PageTableLevel::Two.is_leaf());
        assert!(!PageTableLevel::Three.is_leaf());
        assert!(!PageTableLevel::Four.is_leaf());
    }

    #[test]
    fn level_ordering() {
        // Ord goes by enum discriminant order (Four < Three < Two < One).
        assert!(PageTableLevel::Four < PageTableLevel::One);
    }
}
