//! The active-table mapper: map, unmap, and translate against a PML4 root.
//!
//! [`Mapper`] is the low-level virtual-memory primitive. It holds the physical
//! frame of a PML4 (level-4) table and provides the four operations everything
//! else in the kernel builds on:
//!
//! * [`Mapper::map`] — install a 4 KiB page → frame mapping, creating any
//!   missing intermediate page tables (PDPT, PD, PT) on the way down.
//! * [`Mapper::map_range`] — map a contiguous run of pages to a contiguous run
//!   of frames with one call.
//! * [`Mapper::unmap`] — remove a mapping, clearing the leaf PTE and
//!   invalidating the TLB entry; returns the frame the page was mapped to.
//! * [`Mapper::translate`] — walk the live tables read-only and report which
//!   frame (and flags) a page resolves to, with huge-page support.
//!
//! # How tables are reached: the HHDM direct map
//!
//! The mapper never allocates kernel *virtual* address space to reach page
//! tables. Instead it relies on the higher-half direct map (HHDM) that Limine
//! installed: for any physical address `p`, `crate::mm::phys_to_virt(p)` is a
//! writable, kernel-only virtual address that hits the same byte. So when the
//! mapper needs to edit a PML4/PDPT/PD/PT frame, it converts the frame's
//! physical address to its HHDM virtual address, overlays a `&mut PageTable`
//! onto it, and writes through that pointer. No kernel heap, no per-table
//! virtual mapping — just arithmetic plus a cast.
//!
//! This is what the task brief means by "uses the HHDM offset to edit tables
//! without allocating": the table *memory* already exists in physical frames
//! (either Limine's initial PML4 tree, or frames handed out by the physical
//! allocator for new sub-tables); the mapper reaches it through the direct map
//! rather than by allocating anything new in the virtual address space.
//!
//! # Frame allocation for new sub-tables
//!
//! `map` and `map_range` may need to materialise intermediate tables that do
//! not yet exist. They cannot invent physical frames out of thin air, so they
//! take a [`FrameAllocator`] argument. The trait is deliberately minimal —
//! "give me a 4 KiB frame" / "take this one back" — because that is the entire
//! contract the walker needs. A real implementation lives in `mm::physical`;
//! until that module lands, callers pass a concrete allocator (e.g. a stub that
//! returns frames from a static reserved pool during early boot).
//!
//! # Safety
//!
//! Every table mutation goes through one of two paths:
//!
//! 1. A `&mut PageTable` obtained by overlaying the HHDM-mapped frame with
//!    [`frame_as_table_mut`], then writing via [`PageTableEntry::set_frame`] /
//!    [`PageTableEntry::set_unused`] through the `&mut` from
//!    [`PageTable::entry_mut`].
//! 2. A volatile zeroing loop in [`zero_frame`] for freshly allocated frames.
//!
//! Both paths carry a `SAFETY` comment on the unsafe block that produces the
//! reference, stating the aliasing and alignment invariants. The writes
//! themselves are plain `&mut` stores; on x86's TSO memory model they are
//! visible to the MMU in program order, and every mapping change is followed by
//! [`invlpg`](crate::arch::x86_64::instructions::invlpg) so no stale TLB entry
//! survives. Callers must hold the address-space lock (the per-process lock in
//! `sched`/`user`) to prevent two CPUs from mutating the same table tree at
//! once; the mapper itself is single-threaded by convention.

use core::ptr;

use xenith_types::{Page, PageRange, PageTableLevel, PhysAddr, PhysFrame, PAGE_SIZE};

use super::page_table::{
    p1_index, p2_index, p3_index, p4_index, PageTable, PageTableEntry, PageTableFlags,
};
use crate::arch::x86_64::instructions::read_cr3;
use crate::mm::phys_to_virt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Mask covering the physical-address field of a PTE: bits 12..=51.
///
/// This is the same mask used in [`super::page_table`] and
/// [`super::address_space`]; repeated here so the mapper does not reach into
/// either module's private constants. The three copies are identical by
/// architecture (the x86_64 PTE address field is fixed at bits 12..=51) and
/// cannot drift.
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Flag set for an intermediate (non-leaf) table entry that sits on the path to
/// a *kernel* mapping: present + writable, no USER (kernel-only), no GLOBAL
/// (global is leaf-only). Built from raw bits because `BitOr` on the bitflags
/// type is not `const fn`.
const INTERMEDIATE_KERNEL: PageTableFlags = PageTableFlags::from_bits_truncate(
    PageTableFlags::PRESENT.bits() | PageTableFlags::WRITABLE.bits(),
);

/// Flag set for an intermediate table entry on the path to a *user* mapping:
/// present + writable + USER. The CPU checks the USER bit at *every* level of
/// the walk, not just the leaf, so every intermediate entry above a user page
/// must carry USER or ring 3 cannot reach the leaf.
const INTERMEDIATE_USER: PageTableFlags = PageTableFlags::from_bits_truncate(
    PageTableFlags::PRESENT.bits() | PageTableFlags::WRITABLE.bits() | PageTableFlags::USER.bits(),
);

// ---------------------------------------------------------------------------
// Frame allocator trait
// ---------------------------------------------------------------------------

/// The contract the mapper needs from the physical frame allocator.
///
/// `map` / `map_range` call [`allocate`](Self::allocate) to obtain 4 KiB
/// frames for any intermediate page tables (PDPT/PD/PT) that do not yet exist
/// along the path to the target page. `unmap` does *not* call
/// [`deallocate`](Self::deallocate): intermediate tables are left in place
/// even when they become empty, because scanning 512 entries to detect
/// emptiness on every unmap is too costly. Reclaiming empty sub-tables is the
/// job of a full address-space teardown, not of `unmap`.
///
/// This is a thin local trait rather than a re-export of
/// `super::address_space::FrameAllocator` so that `paging` (the lower layer)
/// does not depend on `address_space` (the higher layer). When the canonical
/// `mm::physical` frame allocator lands, it will implement this trait and the
/// global pointer registered by `mm::init` will be passed to the mapper.
pub trait FrameAllocator {
    /// Return one unused 4 KiB physical frame, or `None` if the allocator is
    /// exhausted. The caller zeroes the frame (via [`zero_frame`]) before
    /// linking it into a page table.
    fn allocate(&self) -> Option<PhysFrame>;
    /// Return a frame to the pool. The frame must have come from
    /// [`allocate`](Self::allocate) and must not still be mapped as a page
    /// table anywhere.
    fn deallocate(&self, frame: PhysFrame);
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a mapping operation failed.
///
/// Hand-rolled (per Xenith convention) rather than using `thiserror`: the
/// kernel is `no_std` with no error infrastructure beyond `Debug` + `Result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// No physical frame could be allocated for a new intermediate page table.
    /// The mapping itself was not installed; retrying after freeing frames may
    /// succeed.
    OutOfMemory,
    /// The leaf PTE for this page is already present. Callers must
    /// [`unmap`](Mapper::unmap) first if they intend to remap.
    AlreadyMapped,
    /// A huge-page entry (2 MiB or 1 GiB) already covers the target page, so a
    /// 4 KiB mapping cannot be installed without splitting the large page.
    /// Xenith does not yet split huge pages; the caller must unmap the huge
    /// mapping first.
    HugeConflict,
}

/// Why an unmap operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmapError {
    /// The page is not mapped (some intermediate level is not present, or the
    /// leaf PTE is clear). There is nothing to remove.
    NotMapped,
    /// The page is covered by a huge-page entry. Unmapping a single 4 KiB page
    /// from a 2 MiB / 1 GiB mapping is not supported; the caller must unmap the
    /// whole large page.
    HugeConflict,
}

// ---------------------------------------------------------------------------
// active_p4_phys — read the current CR3 root
// ---------------------------------------------------------------------------

/// Read the physical address of the currently-active PML4 table from CR3.
///
/// CR3 bits 12..=51 hold the PML4 physical address; the low bits (PWT/PCD) and
/// high bits are mask-features and reserved. This is the canonical way to
/// discover the kernel's (or the current process's) page-table root: Limine
/// built the initial PML4 and left it in CR3 before jumping to `_start`, so at
/// boot the active PML4 *is* the kernel address space.
///
/// This is safe to call from any kernel context because `read_cr3` is
/// privileged (CPL 0) and the kernel always runs in ring 0; the read has no
/// side effects beyond returning the current CR3 image.
#[inline]
#[must_use]
pub fn active_p4_phys() -> PhysAddr {
    // SAFETY: ring-0 read of CR3; the kernel is always in CPL 0. The read has
    // no side effects and returns the raw CR3 image, from which we mask the
    // address field.
    let raw = unsafe { read_cr3() };
    PhysAddr::new_truncate(raw & ADDR_MASK)
}

// ---------------------------------------------------------------------------
// Mapper
// ---------------------------------------------------------------------------

/// A handle to a four-level x86_64 page table, identified by its PML4 frame.
///
/// `Mapper` is just a `PhysFrame` — the physical frame holding the PML4 root.
/// All the actual table memory lives in physical frames reached through the
/// HHDM; the mapper fabricates `&mut PageTable` references to them on demand
/// via [`phys_to_virt`] + a cast. Because it is a single frame handle, `Mapper`
/// is `Copy` and can be passed by value without indirection.
///
/// Construct one with [`Mapper::from_p4`] when you already know the PML4 frame,
/// or [`Mapper::active`] / [`Mapper::from_cr3`] to adopt the running address
/// space. The kernel's own mapper is established once during
/// [`super::init`] and reused for the lifetime of the boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mapper {
    /// The 4 KiB physical frame holding the PML4 (level-4) table. Writing this
    /// frame's address into CR3 activates the address space this mapper
    /// describes.
    p4_frame: PhysFrame,
}

impl Mapper {
    // -- construction ------------------------------------------------------

    /// Wrap a known PML4 frame.
    ///
    /// # Safety
    ///
    /// The caller must guarantee `p4_frame` points at a valid, present PML4
    /// table that is mapped writable through the HHDM. The mapper will write
    /// through the HHDM alias of this frame, so a frame that is not actually a
    /// PML4 (or is not HHDM-reachable) will corrupt memory.
    #[inline]
    #[must_use]
    pub const unsafe fn from_p4(p4_frame: PhysFrame) -> Self {
        Self { p4_frame }
    }

    /// Adopt the currently-active address space by reading CR3.
    ///
    /// This is how the kernel obtains its own mapper at boot: Limine built the
    /// initial PML4 (with the HHDM, kernel image, and framebuffer mapped) and
    /// left it in CR3, so [`Mapper::active`] wraps that root without rebuilding
    /// it. The returned mapper edits the *live* tables the CPU is currently
    /// walking, so changes are visible immediately after `invlpg`.
    ///
    /// Safe to call from any kernel context: `read_cr3` is privileged (CPL 0)
    /// and the kernel always runs in ring 0, and the active CR3 always points
    /// at a valid PML4 (that is the CPU's invariant for the running address
    /// space).
    #[inline]
    #[must_use]
    pub fn active() -> Self {
        let addr = active_p4_phys();
        // SAFETY: the active CR3 points at a valid, present, HHDM-mapped PML4
        // — that is the CPU's invariant for the running address space.
        unsafe { Self::from_p4(PhysFrame::containing_addr(addr)) }
    }

    /// Build a mapper from a raw CR3 image.
    ///
    /// `raw` is the full CR3 value (address bits plus PWT/PCD flags); the
    /// address field is masked out. Useful when the caller has saved a CR3
    /// image (e.g. the scheduler stashing the outgoing address space) and wants
    /// a mapper for it without re-reading the register.
    ///
    /// # Safety
    ///
    /// The caller must guarantee `raw`'s address field points at a valid,
    /// present, HHDM-mapped PML4 frame.
    #[inline]
    #[must_use]
    pub unsafe fn from_cr3(raw: u64) -> Self {
        let addr = PhysAddr::new_truncate(raw & ADDR_MASK);
        // SAFETY: caller vouches for the CR3 image's address field.
        unsafe { Self::from_p4(PhysFrame::containing_addr(addr)) }
    }

    /// The PML4 physical frame this mapper is rooted at.
    #[inline]
    #[must_use]
    pub const fn p4_frame(&self) -> PhysFrame {
        self.p4_frame
    }

    /// The raw CR3 value that would activate this address space (address bits
    /// only; PWT/PCD left clear for write-back caching).
    #[inline]
    #[must_use]
    pub fn cr3(&self) -> u64 {
        self.p4_frame.start_address().as_u64() & ADDR_MASK
    }

    // -- mapping -----------------------------------------------------------

    /// Map a single 4 KiB `page` to `frame` with the given leaf `flags`.
    ///
    /// Intermediate page tables (PDPT, PD, PT) along the path are allocated and
    /// zeroed on demand from `alloc`. Each intermediate entry is installed with
    /// `PRESENT | WRITABLE` plus `USER` if the leaf flags request `USER` — the
    /// CPU checks USER at every walk level, so a user leaf needs USER all the
    /// way up or ring 3 cannot reach it.
    ///
    /// Returns [`MapError::AlreadyMapped`] if the leaf PTE is already present,
    /// [`MapError::HugeConflict`] if a huge page already covers `page`, and
    /// [`MapError::OutOfMemory`] if `alloc` cannot provide a frame for a new
    /// sub-table.
    pub fn map(
        &self,
        page: Page,
        frame: PhysFrame,
        flags: PageTableFlags,
        alloc: &dyn FrameAllocator,
    ) -> Result<(), MapError> {
        let intermediate = if flags.contains(PageTableFlags::USER) {
            INTERMEDIATE_USER
        } else {
            INTERMEDIATE_KERNEL
        };

        let leaf = self.walk_or_create(page, intermediate, alloc)?;
        if leaf.is_present() {
            return Err(MapError::AlreadyMapped);
        }
        // Install the leaf PTE. `set_frame` ORs the frame address into the
        // flag bits; we force PRESENT on so the caller cannot accidentally
        // install a not-present mapping via `map` (use `unmap` to remove).
        leaf.set_frame(frame, flags | PageTableFlags::PRESENT);
        // SAFETY: `page.start_address()` is a canonical virtual address (every
        // `Page` is built from a canonical `VirtAddr`), and `invlpg` is a
        // privileged instruction executed in ring 0. The invalidate ensures
        // the MMU does not cache a stale not-present translation from before
        // the mapping was installed.
        if flags.contains(PageTableFlags::USER) {
            crate::arch::x86_64::smp::shootdown_page(self.cr3(), page.start_address().as_u64());
        } else {
            crate::arch::x86_64::smp::shootdown_kernel_page(page.start_address().as_u64());
        }
        ::log::trace!(
            "xenith.mm.virtual.paging: mapped {:?} -> {:?} flags={:#x}",
            page,
            frame,
            flags.bits()
        );
        Ok(())
    }

    /// Map a contiguous run of pages to a contiguous run of frames.
    ///
    /// `pages` is the inclusive [`PageRange`] to map; `start_frame` is the
    /// first physical frame, and each subsequent page maps to the next frame.
    /// All leaves receive the same `flags`. Intermediate tables are created on
    /// demand exactly as in [`map`](Self::map).
    ///
    /// On success returns the frame that *follows* the last mapped frame, so a
    /// caller mapping several adjacent ranges can chain the result into the
    /// next call without recomputing the offset. On error the mapping is
    /// rolled back: every page that was installed is unmapped before returning,
    /// so the address space is left as if the call never happened (though any
    /// intermediate tables the call materialised remain — they are harmless
    /// empty tables and will be reused or reclaimed later).
    pub fn map_range(
        &self,
        pages: PageRange,
        start_frame: PhysFrame,
        flags: PageTableFlags,
        alloc: &dyn FrameAllocator,
    ) -> Result<PhysFrame, MapError> {
        let mut current_frame = start_frame;
        // Remember where the run starts so we can roll it back on failure.
        // `PageRange` is `Copy`, so reading `pages.start()` before the loop
        // snapshots the start even though the loop below consumes the iterator.
        let range_start = pages.start();
        let mut installed: u64 = 0;
        for page in pages {
            match self.map(page, current_frame, flags, alloc) {
                Ok(()) => {
                    installed += 1;
                    // Advance to the next physical frame. `PhysFrame + u64`
                    // panics on 52-bit overflow; that would indicate the
                    // caller handed in a frame range that runs off the end of
                    // physical memory, which is a caller bug.
                    current_frame = current_frame + 1;
                },
                Err(e) => {
                    // Roll back every page we installed so the address space
                    // is not left half-mapped. `unmap` clears the leaf PTE and
                    // invalidates the TLB; its `NotMapped` error cannot happen
                    // here because we just mapped these pages, so the result
                    // is intentionally discarded.
                    if installed > 0 {
                        ::log::warn!(
                            "xenith.mm.virtual.paging: map_range failed after {} pages ({:?}); rolling back",
                            installed,
                            e
                        );
                        // The installed pages are [range_start, range_start +
                        // installed - 1]. Build an inclusive PageRange over
                        // them and unmap each. `Page + u64` panics on a
                        // non-canonical result, which cannot happen here
                        // because the range was valid to begin with.
                        let rollback_end = range_start + (installed - 1);
                        for rb in PageRange::new(range_start, rollback_end) {
                            let _ = self.unmap(rb);
                        }
                    }
                    return Err(e);
                },
            }
        }
        Ok(current_frame)
    }

    // -- unmapping ---------------------------------------------------------

    /// Unmap a single page, clearing its leaf PTE and invalidating the TLB.
    ///
    /// Returns the physical frame the page was mapped to, or
    /// [`UnmapError::NotMapped`] if no leaf entry was present, or
    /// [`UnmapError::HugeConflict`] if a huge page covers `page`.
    ///
    /// The leaf PTE is cleared and `invlpg` issued; the frame is *not* freed
    /// (the caller owns it and may remap or return it to the allocator).
    /// Intermediate tables are left in place even if they become empty —
    /// freeing them would require a 512-entry scan on every unmap, which is
    /// too costly. Empty sub-tables are reclaimed during address-space
    /// teardown.
    pub fn unmap(&self, page: Page) -> Result<PhysFrame, UnmapError> {
        // The walk helper is a safe fn whose internal unsafe blocks carry
        // their own SAFETY comments; the caller is expected to hold the
        // address-space lock, which is the invariant those comments rely on.
        let leaf = self.walk_to_leaf_mut(page).ok_or(UnmapError::NotMapped)?;
        if !leaf.is_present() {
            return Err(UnmapError::NotMapped);
        }
        let old_flags = leaf.flags();
        let frame = leaf
            .frame()
            .unwrap_or_else(|| PhysFrame::containing_addr(PhysAddr::zero()));
        leaf.set_unused();
        // SAFETY: `page.start_address()` is a canonical virtual address (every
        // `Page` is built from a canonical `VirtAddr`), and `invlpg` is a
        // privileged instruction executed in ring 0. The invalidate is
        // essential: without it the CPU could keep using the now-cleared
        // translation until the next CR3 write.
        if old_flags.contains(PageTableFlags::USER) {
            crate::arch::x86_64::smp::shootdown_page(self.cr3(), page.start_address().as_u64());
        } else {
            crate::arch::x86_64::smp::shootdown_kernel_page(page.start_address().as_u64());
        }
        ::log::trace!(
            "xenith.mm.virtual.paging: unmapped {:?} (was {:?})",
            page,
            frame
        );
        Ok(frame)
    }

    // -- translation -------------------------------------------------------

    /// Translate a virtual page to the physical frame it maps to, with the
    /// leaf entry's flags.
    ///
    /// Walks the four-level table without allocating. Returns `None` if any
    /// level is not present. Huge pages are handled: a `HUGE` entry at PDE
    /// (level 2) or PDPTE (level 3) resolves immediately to the physical frame
    /// that covers `page` within the large page (the entry's address field
    /// points at the base of the 2 MiB / 1 GiB region; the frame for `page` is
    /// the base plus the intra-large-page offset).
    ///
    /// The walk reads through HHDM-mapped `&PageTable` references. These reads
    /// are non-volatile, so hardware-maintained bits (ACCESSED, DIRTY) may be
    /// stale; this is fine for `translate`, which only needs the address and
    /// the kernel-controlled flag bits.
    pub fn translate(&self, page: Page) -> Option<(PhysFrame, PageTableFlags)> {
        // `walk_and_resolve` is a safe fn with internal unsafe blocks; no
        // `&mut` is fabricated, so a concurrent mutator (prevented by the
        // address-space lock in practice) can at worst produce a torn read.
        self.walk_and_resolve(page)
    }

    /// The leaf flags for `page`, without the frame.
    ///
    /// Convenience wrapper around [`translate`](Self::translate) for callers
    /// (e.g. a future `mprotect`) that only need the permission bits.
    #[inline]
    #[must_use]
    pub fn flags(&self, page: Page) -> Option<PageTableFlags> {
        self.translate(page).map(|(_, f)| f)
    }

    // -- private walk helpers ----------------------------------------------

    /// Walk to the leaf PTE for `page`, creating missing intermediate tables
    /// on the way down, and return a `&mut` to the leaf entry.
    ///
    /// `intermediate` is the flag set used for any PML4/PDPT/PD entry the
    /// walker has to materialise. The leaf entry itself is left untouched (the
    /// caller sets it); only the path to it is ensured to exist.
    ///
    /// The caller must hold the address-space lock so no other CPU is mutating
    /// this table path concurrently. The returned `&mut` borrows from the
    /// HHDM-mapped table frames and is valid for the duration of the caller's
    /// critical section.
    #[allow(clippy::mut_from_ref)]
    fn walk_or_create(
        &self,
        page: Page,
        intermediate: PageTableFlags,
        alloc: &dyn FrameAllocator,
    ) -> Result<&mut PageTableEntry, MapError> {
        // SAFETY: the caller (a public method like `map`) holds the
        // address-space lock, guaranteeing exclusive access to this address
        // space's table tree for the duration of the walk.
        let p4 = unsafe { self.p4_mut() };
        let p3 =
            Self::next_level_or_create(p4, p4_index(page.start_address()), intermediate, alloc)?;
        let p2 =
            Self::next_level_or_create(p3, p3_index(page.start_address()), intermediate, alloc)?;
        let p1 =
            Self::next_level_or_create(p2, p2_index(page.start_address()), intermediate, alloc)?;
        Ok(p1.entry_mut(p1_index(page.start_address())))
    }

    /// Given a parent table and an index into it, return a `&mut` to the child
    /// table, allocating and linking a fresh frame if the entry is not present.
    ///
    /// If the entry is already a huge-page entry, the caller's `page` is
    /// already covered by a large mapping and we refuse to split it
    /// ([`MapError::HugeConflict`]).
    ///
    /// The caller must hold the address-space lock; the returned `&mut` is
    /// valid for the duration of that critical section.
    fn next_level_or_create<'a>(
        parent: &'a mut PageTable,
        index: xenith_types::PageTableIndex,
        intermediate: PageTableFlags,
        alloc: &dyn FrameAllocator,
    ) -> Result<&'a mut PageTable, MapError> {
        let entry = parent.entry(index);
        if entry.is_huge() {
            return Err(MapError::HugeConflict);
        }
        if !entry.is_present() {
            let frame = alloc.allocate().ok_or(MapError::OutOfMemory)?;
            // SAFETY: `frame` was just handed out by the allocator exclusively
            // to this caller, so no other reference to it exists. We zero it
            // through the HHDM alias before linking it so the MMU never sees
            // stale garbage entries.
            unsafe { zero_frame(&frame) };
            parent.entry_mut(index).set_frame(frame, intermediate);
            // SAFETY: we just linked `frame` into `parent` and zeroed it; the
            // new child table is HHDM-reachable and has no aliasing `&mut`
            // because the frame was freshly allocated.
            return Ok(unsafe { frame_as_table_mut(frame) });
        }
        let frame = entry.frame().ok_or(MapError::OutOfMemory)?;
        // SAFETY: the entry is present and points at a valid child table; the
        // caller holds the address-space lock, so the `&mut` chain down from
        // the PML4 is exclusive.
        Ok(unsafe { frame_as_table_mut(frame) })
    }

    /// Walk to the leaf PTE for `page` without allocating, returning a `&mut`
    /// to it, or `None` if any intermediate level is not present or a huge
    /// page is encountered (the caller cannot unmap a 4 KiB page from under a
    /// huge mapping).
    ///
    /// The caller must hold the address-space lock and ensure no conflicting
    /// `&mut` to the table chain is live.
    #[inline]
    #[allow(clippy::mut_from_ref)]
    fn walk_to_leaf_mut(&self, page: Page) -> Option<&mut PageTableEntry> {
        // SAFETY: the caller holds the address-space lock; same aliasing
        // contract as `walk_or_create`.
        let p4 = unsafe { self.p4_mut() };
        let p4e = p4.entry(p4_index(page.start_address()));
        if !p4e.is_present() {
            return None;
        }
        // SAFETY: `p4e` is present and points at a valid PDPT frame; the lock
        // makes our `&mut` chain exclusive.
        let p3 = unsafe { frame_as_table_mut(p4e.frame()?) };
        let p3e = p3.entry(p3_index(page.start_address()));
        if !p3e.is_present() || p3e.is_huge() {
            return None;
        }
        // SAFETY: `p3e` is present, non-huge, points at a valid PD frame.
        let p2 = unsafe { frame_as_table_mut(p3e.frame()?) };
        let p2e = p2.entry(p2_index(page.start_address()));
        if !p2e.is_present() || p2e.is_huge() {
            return None;
        }
        // SAFETY: `p2e` is present, non-huge, points at a valid PT frame.
        let p1 = unsafe { frame_as_table_mut(p2e.frame()?) };
        Some(p1.entry_mut(p1_index(page.start_address())))
    }

    /// Walk the table read-only and resolve `page` to its frame and flags,
    /// handling huge pages at levels 2 and 3.
    ///
    /// No `&mut` is fabricated; a concurrent mutator (if any, which the
    /// address-space lock prevents) can at worst produce a torn read.
    fn walk_and_resolve(&self, page: Page) -> Option<(PhysFrame, PageTableFlags)> {
        // SAFETY: read-only shared references only; no mutation occurs.
        let p4 = unsafe { self.p4() };
        let p4e = p4.entry(p4_index(page.start_address()));
        if !p4e.is_present() {
            return None;
        }
        // SAFETY: `p4e` is present and points at a valid PDPT frame; a shared
        // reference is safe even under a concurrent mutator (torn read at
        // worst).
        let p3 = unsafe { frame_as_table(p4e.frame()?) };
        let p3e = p3.entry(p3_index(page.start_address()));
        if !p3e.is_present() {
            return None;
        }
        if p3e.is_huge() {
            return Some((huge_frame(*p3e, page, PageTableLevel::Three), p3e.flags()));
        }
        let p2 = unsafe { frame_as_table(p3e.frame()?) };
        let p2e = p2.entry(p2_index(page.start_address()));
        if !p2e.is_present() {
            return None;
        }
        if p2e.is_huge() {
            return Some((huge_frame(*p2e, page, PageTableLevel::Two), p2e.flags()));
        }
        let p1 = unsafe { frame_as_table(p2e.frame()?) };
        let p1e = p1.entry(p1_index(page.start_address()));
        if !p1e.is_present() {
            return None;
        }
        p1e.frame().map(|f| (f, p1e.flags()))
    }

    /// A mutable reference to the PML4 table, reached through the HHDM.
    ///
    /// # Safety
    ///
    /// The caller must ensure no other `&mut` to the PML4 (or any of its
    /// descendants) is live. In practice the paging code holds a single
    /// `&mut` chain down the walk; the address-space lock prevents concurrent
    /// mutators.
    #[inline]
    unsafe fn p4_mut(&self) -> &'static mut PageTable {
        let va = phys_to_virt(self.p4_frame.start_address());
        // SAFETY: `va` is the HHDM virtual address of the PML4 frame, which
        // Limine mapped writable. `PageTable` is `repr(C, align(4096))` and
        // exactly 4096 bytes, matching the frame. The caller guarantees no
        // aliasing `&mut` is live.
        unsafe { &mut *(va.as_u64() as *mut PageTable) }
    }

    /// A shared reference to the PML4 table, reached through the HHDM.
    ///
    /// # Safety
    ///
    /// Same as `p4_mut` but for reads; a concurrent `&mut` may exist, which is
    /// benign for a read-only walk (torn read at worst).
    #[inline]
    unsafe fn p4(&self) -> &'static PageTable {
        let va = phys_to_virt(self.p4_frame.start_address());
        // SAFETY: see `p4_mut`; the cast is sound for the same layout reasons.
        unsafe { &*(va.as_u64() as *const PageTable) }
    }
}

// ---------------------------------------------------------------------------
// Free functions: frame <-> table casts, huge-page decode, zeroing
// ---------------------------------------------------------------------------

/// Overlay a `&PageTable` onto a physical frame reached through the HHDM.
///
/// # Safety
///
/// `frame` must point at a present page-table frame (a PML4/PDPT/PD/PT) that
/// is mapped through the HHDM, and the caller must ensure no conflicting
/// `&mut` to the same frame is live.
#[inline]
unsafe fn frame_as_table(frame: PhysFrame) -> &'static PageTable {
    let va = phys_to_virt(frame.start_address());
    // SAFETY: `phys_to_virt` yields the HHDM virtual address of the frame,
    // which Limine mapped writable. `PageTable` is `repr(C, align(4096))` and
    // exactly 4096 bytes, matching a frame. The caller guarantees no
    // conflicting mutable aliasing.
    unsafe { &*(va.as_u64() as *const PageTable) }
}

/// Overlay a `&mut PageTable` onto a physical frame reached through the HHDM.
///
/// # Safety
///
/// Same as [`frame_as_table`] but the caller must additionally guarantee no
/// other reference (shared or mutable) to the frame is live.
#[inline]
unsafe fn frame_as_table_mut(frame: PhysFrame) -> &'static mut PageTable {
    let va = phys_to_virt(frame.start_address());
    // SAFETY: see `frame_as_table`; the mutable variant additionally requires
    // exclusive access, which the caller guarantees via the address-space
    // lock and the single-walker convention.
    unsafe { &mut *(va.as_u64() as *mut PageTable) }
}

/// Decode the physical frame for a huge-page entry that covers `page`.
///
/// A huge PTE's address field points at the *base* of the large page (2 MiB
/// for level 2, 1 GiB for level 3), not at the 4 KiB frame for `page`. The
/// frame that `page` maps to is the base frame plus the offset of `page`
/// within the large page, in 4 KiB units. We compute that by aligning the
/// huge entry's address down to the large-page boundary and adding the
/// page-aligned intra-large-page offset.
fn huge_frame(entry: PageTableEntry, page: Page, level: PageTableLevel) -> PhysFrame {
    let base = entry.bits() & ADDR_MASK;
    // The size of the large page in bytes: 1 GiB at level 3, 2 MiB at level 2.
    // Level 1 cannot be huge (bit 7 is PAT there), but we fall back to
    // PAGE_SIZE defensively so the arithmetic stays well-defined.
    let large_size: u64 = match level {
        PageTableLevel::Three => 1 << 30,
        PageTableLevel::Two => 1 << 21,
        _ => PAGE_SIZE,
    };
    // Mask off the intra-large-page offset bits to get the base address, then
    // add back the page-aligned intra-large-page offset of `page`.
    let base_aligned = base & !(large_size - 1);
    let intra = page.start_address().as_u64() & (large_size - 1);
    PhysFrame::containing_addr(PhysAddr::new_truncate(base_aligned + intra))
}

/// Zero a freshly allocated page-table frame through the HHDM.
///
/// A page-table frame must be entirely zero (every entry not-present) before
/// it is linked into a parent entry, otherwise the MMU would treat stale bytes
/// as mappings. We zero via volatile writes so the stores are not elided or
/// reordered away from the hardware's perspective.
///
/// # Safety
///
/// `frame` must point at a writable 4 KiB physical frame that is HHDM-mapped
/// and not aliased by any other live reference (the allocator hands frames out
/// exclusively, so this holds for a freshly allocated frame).
unsafe fn zero_frame(frame: &PhysFrame) {
    let va = phys_to_virt(frame.start_address());
    // SAFETY: `va` is the HHDM address of a freshly allocated, writable 4 KiB
    // frame. We write exactly `PAGE_SIZE / 8` u64s (4096 bytes), filling the
    // frame exactly. The frame is not aliased — the allocator handed it out
    // exclusively — so the volatile writes are sound.
    let ptr = va.as_u64() as *mut u64;
    for i in 0..(PAGE_SIZE / 8) {
        unsafe { ptr::write_volatile(ptr.add(i as usize), 0) };
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // `index_for` is only exercised by tests, so it is imported here rather
    // than in the parent module to avoid an unused-import warning in
    // non-test builds. The path climbs two `super` levels: `tests` -> `paging`
    // -> `virtual`, then into the sibling `page_table` module.
    use xenith_types::VirtAddr;

    use super::super::page_table::index_for;
    use super::*;

    /// A trivial frame allocator that hands out frames from a static counter.
    /// Used only to exercise the walker logic in isolation; the real allocator
    /// lives in `mm::physical`.
    struct BumpAllocator {
        next: core::sync::atomic::AtomicU64,
    }

    impl BumpAllocator {
        const fn new(start: u64) -> Self {
            Self {
                next: core::sync::atomic::AtomicU64::new(start),
            }
        }
    }

    impl FrameAllocator for BumpAllocator {
        fn allocate(&self) -> Option<PhysFrame> {
            let n = self
                .next
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            // Stop before we run off the end of the test's fake physical
            // space; 64 frames is plenty for any single map_range test.
            if n >= 64 {
                return None;
            }
            Some(PhysFrame::containing_addr(PhysAddr::new_truncate(
                0x10_0000 + n * PAGE_SIZE,
            )))
        }
        fn deallocate(&self, _frame: PhysFrame) {
            // No-op: the bump allocator does not reclaim.
        }
    }

    #[test]
    fn active_p4_phys_masks_flags() {
        // CR3's address field is bits 12..=51; the low PWT/PCD bits and high
        // reserved bits must be stripped. We cannot read the real CR3 from a
        // host test (it is privileged), so we verify the mask logic directly:
        // any value ANDed with ADDR_MASK keeps only bits 12..=51.
        let raw = 0x0000_0000_00AB_C003u64; // frame 0xAB_C00, PWT=1, PCD=1
        let masked = raw & ADDR_MASK;
        assert_eq!(masked, 0x0000_0000_00AB_C000);
        // Bits 0..11 (flags) are stripped.
        assert_eq!(masked & 0xFFF, 0);
        // Bits 52..63 are stripped.
        assert_eq!(masked >> 52, 0);
    }

    #[test]
    fn intermediate_flag_sets_are_sane() {
        // Kernel intermediates: present + writable, no USER.
        assert!(INTERMEDIATE_KERNEL.contains(PageTableFlags::PRESENT));
        assert!(INTERMEDIATE_KERNEL.contains(PageTableFlags::WRITABLE));
        assert!(!INTERMEDIATE_KERNEL.contains(PageTableFlags::USER));
        assert!(!INTERMEDIATE_KERNEL.contains(PageTableFlags::GLOBAL));
        // User intermediates: present + writable + USER.
        assert!(INTERMEDIATE_USER.contains(PageTableFlags::PRESENT));
        assert!(INTERMEDIATE_USER.contains(PageTableFlags::WRITABLE));
        assert!(INTERMEDIATE_USER.contains(PageTableFlags::USER));
    }

    #[test]
    fn map_error_variants_distinct() {
        use MapError as E;
        assert_ne!(E::OutOfMemory, E::AlreadyMapped);
        assert_ne!(E::OutOfMemory, E::HugeConflict);
        assert_ne!(E::AlreadyMapped, E::HugeConflict);
    }

    #[test]
    fn unmap_error_variants_distinct() {
        use UnmapError as E;
        assert_ne!(E::NotMapped, E::HugeConflict);
    }

    #[test]
    fn huge_frame_decodes_2m_base_plus_offset() {
        // A 2 MiB huge entry at level 2 pointing at base 0x4000_0000.
        let base = 0x4000_0000u64;
        let entry = PageTableEntry::new_pointing(
            PhysFrame::containing_addr(PhysAddr::new_truncate(base)),
            PageTableFlags::PRESENT | PageTableFlags::HUGE,
        );
        // A page 0x4000_5000 is 5 * 4 KiB into the 2 MiB large page.
        let page = Page::containing_addr(VirtAddr::new(0x4000_5000).unwrap());
        let frame = huge_frame(entry, page, PageTableLevel::Two);
        assert_eq!(frame.start_address().as_u64(), 0x4000_5000);
    }

    #[test]
    fn huge_frame_decodes_1g_base_plus_offset() {
        // A 1 GiB huge entry at level 3 pointing at base 0x4_0000_0000.
        let base = 0x4_0000_0000u64;
        let entry = PageTableEntry::new_pointing(
            PhysFrame::containing_addr(PhysAddr::new_truncate(base)),
            PageTableFlags::PRESENT | PageTableFlags::HUGE,
        );
        // A page 0x4_0020_5000 is (0x205000 / 4096) = 0x205 frames into the 1
        // GiB region.
        let page = Page::containing_addr(VirtAddr::new(0x4_0020_5000).unwrap());
        let frame = huge_frame(entry, page, PageTableLevel::Three);
        assert_eq!(frame.start_address().as_u64(), 0x4_0020_5000);
    }

    #[test]
    fn huge_frame_level_one_falls_back_to_page_size() {
        // Level 1 cannot be huge; the function falls back to PAGE_SIZE so the
        // arithmetic returns the entry's own base (no intra offset).
        let entry = PageTableEntry::new_pointing(
            PhysFrame::containing_addr(PhysAddr::new_truncate(0x8000)),
            PageTableFlags::PRESENT,
        );
        let page = Page::containing_addr(VirtAddr::new(0x8000).unwrap());
        let frame = huge_frame(entry, page, PageTableLevel::One);
        assert_eq!(frame.start_address().as_u64(), 0x8000);
    }

    #[test]
    fn mapper_from_cr3_masks_address() {
        // from_cr3 should keep only bits 12..=51 of the raw value.
        let raw = 0x0000_0000_0010_0003u64; // frame 0x10_000, PWT=1, PCD=1
                                            // SAFETY: this is a host test; the "PML4 frame" is a fiction. We are
                                            // only checking the masking arithmetic, not dereferencing anything.
        let mapper = unsafe { Mapper::from_cr3(raw) };
        assert_eq!(
            mapper.p4_frame().start_address().as_u64(),
            0x0000_0000_0010_0000
        );
        // cr3() round-trips the address with flags stripped.
        assert_eq!(mapper.cr3(), 0x0000_0000_0010_0000);
    }

    #[test]
    fn mapper_cr3_round_trips_p4_frame() {
        let frame = PhysFrame::containing_addr(PhysAddr::new_truncate(0x1_0000));
        // SAFETY: host test; we only inspect the stored frame, never deref.
        let mapper = unsafe { Mapper::from_p4(frame) };
        assert_eq!(mapper.p4_frame(), frame);
        assert_eq!(mapper.cr3(), 0x1_0000);
    }

    #[test]
    fn bump_allocator_yields_distinct_aligned_frames() {
        let alloc = BumpAllocator::new(0);
        let f0 = alloc.allocate().unwrap();
        let f1 = alloc.allocate().unwrap();
        assert_ne!(f0, f1);
        // Every frame is 4 KiB-aligned.
        assert!(f0.start_address().is_page_aligned());
        assert!(f1.start_address().is_page_aligned());
    }

    #[test]
    fn bump_allocator_exhausts_after_capacity() {
        let alloc = BumpAllocator::new(60);
        // The allocator caps at 64 frames total; starting at 60 leaves 4.
        let _ = alloc.allocate();
        let _ = alloc.allocate();
        let _ = alloc.allocate();
        let _ = alloc.allocate();
        assert!(alloc.allocate().is_none());
    }

    #[test]
    fn index_for_dispatch_matches_named_functions() {
        let addr = VirtAddr::new(0x0000_0123_4567_789A).unwrap();
        assert_eq!(index_for(addr, PageTableLevel::Four), p4_index(addr));
        assert_eq!(index_for(addr, PageTableLevel::Three), p3_index(addr));
        assert_eq!(index_for(addr, PageTableLevel::Two), p2_index(addr));
        assert_eq!(index_for(addr, PageTableLevel::One), p1_index(addr));
    }

    #[test]
    fn addr_mask_is_bits_12_through_51() {
        // The address field is exactly bits 12..=51: 40 bits, 4 KiB-aligned.
        assert_eq!(ADDR_MASK, 0x000F_FFFF_FFFF_F000);
        // A frame address ANDed with the mask is unchanged (already aligned).
        let frame = 0x0000_0000_0010_0000u64;
        assert_eq!(frame & ADDR_MASK, frame);
        // Flag bits (0..11) are stripped.
        assert_eq!((frame | 0x7) & ADDR_MASK, frame);
    }
}
