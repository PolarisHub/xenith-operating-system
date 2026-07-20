//! Hardware page-table data structures for x86_64 long mode.
//!
//! The x86_64 MMU walks a four-level page table rooted in CR3:
//!
//! ```text
//!   CR3 -> PML4 (level 4)
//!            v  PML4e -> PDPT (level 3)
//!                       v  PDPTe -> PD (level 2)
//!                                  v  PDE -> PT (level 1)
//!                                            v  PTE -> 4 KiB page
//! ```
//!
//! Every level is a 4 KiB-aligned array of 512 8-byte entries — exactly the
//! same shape — so a single [`PageTable`] type and a single [`PageTableEntry`]
//! type describe all four levels. The *interpretation* of an entry (does it
//! point to a sub-table, or to a mapped page, and at what size?) depends on
//! which level it sits at and whether the huge-page bit is set; that logic
//! lives in the [`super::paging`] walker, not here.
//!
//! This module is intentionally pure data: it defines the in-memory layout of
//! one table and one entry, the flag bit set, and the index arithmetic that
//! turns a [`VirtAddr`] into the four 9-bit indices the walker needs. It
//! performs no pointer dereference and no HHDM translation — callers reach the
//! actual table memory through the [`super::paging::Mapper`], which knows the
//! higher-half direct-map offset. Keeping the layout here and the access there
//! is what lets the same types be reused for both the live kernel tables and
//! any future per-process user tables.
//!
//! # `#[repr(transparent)]` and `#[repr(C, align(4096))]`
//!
//! [`PageTableEntry`] is `#[repr(transparent)]` over `u64`, so it is exactly
//! 8 bytes with no padding and the same layout as the hardware PTE. The
//! [`PageTable`] wrapper is `#[repr(C, align(4096))]` so the 512-entry array
//! is 4096 bytes, 4 KiB-aligned — the two requirements the MMU imposes on a
//! page table. Getting either wrong silently corrupts translation, so the
//! reprs are load-bearing and not stylistic.

use core::fmt;

use xenith_bitflags::bitflags;
use xenith_types::{PageTableIndex, PageTableLevel, PhysAddr, PhysFrame, VirtAddr};

// ---------------------------------------------------------------------------
// Page-table entry flags
// ---------------------------------------------------------------------------

bitflags! {
    /// The flag bits of an x86_64 page-table entry.
    ///
    /// These are the architecturally-defined bits in the low 12 bytes and bit
    /// 63 of a PTE. The physical address occupies bits 12..=51 and is handled
    /// separately by [`PageTableEntry::frame`] / [`PageTableEntry::set_frame`];
    /// this flag set deliberately names *only* the flag bits so that
    /// `from_bits_truncate` strips the address field out cleanly when reading
    /// flags back.
    ///
    /// Bits 9..=11 and 52..=62 are "available for software" on x86_64. Xenith
    /// owns bit 9 as its copy-on-write marker; the remaining software bits are
    /// unnamed and dropped by the truncating constructor.
    pub struct PageTableFlags: u64 {
        /// Bit 0 — Present. When clear, the entry is not used and any access
        /// to the covered range page-faults. Almost every entry the kernel
        /// installs sets this.
        const PRESENT      = 1 << 0;

        /// Bit 1 — Writable. When clear, writes to the covered range fault
        /// (even from ring 0 if CR0.WP is set, which Xenith enables). Read-only
        /// kernel data and copy-on-write pages clear this.
        const WRITABLE     = 1 << 1;

        /// Bit 2 — User-accessible. When set, ring 3 may access the covered
        /// range (subject to the ring's permission checks); when clear, only
        /// ring 0 may. Kernel entries leave this clear; user entries set it.
        const USER         = 1 << 2;

        /// Bit 3 — Page-level Write-Through. Sets the PWT caching policy for
        /// the table or page. Xenith leaves this clear (write-back) for normal
        /// memory; memory-mapped IO may set it.
        const WRITE_THROUGH = 1 << 3;

        /// Bit 4 — Page-level Cache Disable. Sets the PCD bit, making accesses
        /// to the covered range uncached. Used for MMIO and framebuffer ranges
        /// where the CPU must not reorder or buffer writes.
        const CACHE_DISABLE = 1 << 4;

        /// Bit 5 — Accessed. Set by the CPU on a read or execute to the covered
        /// range; the kernel may clear it and inspect it later to implement
        /// page-replacement. The MMU only ever sets this, never clears it.
        const ACCESSED     = 1 << 5;

        /// Bit 6 — Dirty. Set by the CPU on a write to the covered range. Like
        /// ACCESSED, the MMU only sets it; the kernel clears it to track which
        /// pages have been written since the last sweep.
        const DIRTY        = 1 << 6;

        /// Bit 7 — Huge page (PS). At level 2 this marks a 2 MiB page; at
        /// level 3 it marks a 1 GiB page (requires PDPE1GB). At level 1 it is
        /// the PAT bit and is not a "huge" indicator. The walker inspects this
        /// to decide whether to descend another level or stop.
        const HUGE         = 1 << 7;

        /// Bit 8 — Global. When set (and CR4.PGE is enabled), the translation
        /// is tagged global and survives a CR3 write. The kernel marks the
        /// HHDM and kernel-text entries global so address-space switches do not
        /// flush them.
        const GLOBAL       = 1 << 8;

        /// Bit 9 — Xenith software copy-on-write marker. Hardware ignores this
        /// bit. A present user page with COW set and WRITABLE clear shares its
        /// backing frame until the first write creates a private copy.
        const COPY_ON_WRITE = 1 << 9;

        /// Bit 63 — No-Execute. When set, the covered range cannot be executed
        /// (fetches fault with U=0 on the page fault). Requires EFER.NXE;
        /// Xenith enables NXE in `early_init`-adjacent code. Kernel data and
        /// user data pages set this; code pages leave it clear.
        const NO_EXECUTE   = 1 << 63;
    }
}

impl PageTableFlags {
    /// Bit 7 when used by a 4 KiB leaf PTE: the high PAT selector bit.
    ///
    /// Hardware reuses the same bit as `HUGE` in level-2/3 entries. The
    /// mapper always knows the current level, so this alias lets leaf cache
    /// policy code state its intent without changing the binary encoding.
    pub const PAT_4K: Self = Self::HUGE;

    /// The "default kernel page" flag set: present, writable, global, no-execute.
    ///
    /// This is the combination used for most kernel data mappings (the HHDM,
    /// kernel heap, allocator metadata). It is not writable-executable —
    /// kernel code mappings drop `NO_EXECUTE` and add nothing else, since
    /// executable kernel pages should not be writable (W^X).
    ///
    /// Built with `from_bits_truncate` over `.bits()` because the `BitOr`
    /// operator on the flag struct is not `const fn` (it is a trait method),
    /// so a `const` flag set cannot use `Self::PRESENT | Self::WRITABLE`. The
    /// underlying `u64` `|` is const-evaluable, and `from_bits_truncate` /
    /// `bits` are `const fn`, so this form compiles in const context.
    pub const KERNEL_DATA: Self = Self::from_bits_truncate(
        Self::PRESENT.bits()
            | Self::WRITABLE.bits()
            | Self::GLOBAL.bits()
            | Self::NO_EXECUTE.bits(),
    );

    /// The flag set for kernel code: present, readable, executable, global.
    /// `WRITABLE` is intentionally omitted so the kernel text is not
    /// writable while CR0.WP is set.
    pub const KERNEL_CODE: Self =
        Self::from_bits_truncate(Self::PRESENT.bits() | Self::GLOBAL.bits());

    /// The flag set for a user data page: present, writable, user,
    /// no-execute. `GLOBAL` is omitted — user pages are per-address-space and
    /// must be flushed on context switch.
    pub const USER_DATA: Self = Self::from_bits_truncate(
        Self::PRESENT.bits() | Self::WRITABLE.bits() | Self::USER.bits() | Self::NO_EXECUTE.bits(),
    );

    /// The flag set for a user code page: present, readable, executable, user.
    pub const USER_CODE: Self = Self::from_bits_truncate(Self::PRESENT.bits() | Self::USER.bits());
}

// ---------------------------------------------------------------------------
// Address-field mask and helpers
// ---------------------------------------------------------------------------

/// Mask covering the physical-address bits of a PTE (bits 12..=51).
///
/// The address field is 40 bits wide, always aligned to at least 4 KiB, so
/// bits 0..=11 carry flags and bits 52..=63 carry the available field plus
/// the NX bit. ANDing a raw PTE with this extracts the destination physical
/// address; ORing a masked address back with the flag bits reconstructs a
/// valid entry.
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ---------------------------------------------------------------------------
// PageTableEntry
// ---------------------------------------------------------------------------

/// A single x86_64 page-table entry.
///
/// This is a transparent `u64` wrapper: it has the exact same memory layout as
/// the hardware PTE, so a `[PageTableEntry; 512]` is bit-identical to the
/// table the MMU walks. The type exposes the flag bits via [`PageTableFlags`]
/// and the address field via [`PhysFrame`], so callers never have to spell out
/// the hardware bit layout.
///
/// An entry is "unused" when it is entirely zero — no present bit, no address.
/// [`PageTableEntry::is_unused`] lets a walker detect a hole without decoding
/// the full entry, and [`PageTableEntry::set_unused`] is how `unmap` clears a
/// mapping (a zeroed entry is universally interpreted as "not present").
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// Create an entry that points nowhere — the all-zero entry.
    ///
    /// A zero PTE has the present bit clear, so the MMU treats the covered
    /// range as unmapped. This is the correct initial state for every entry in
    /// a freshly-allocated table.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self(0)
    }

    /// Construct an entry pointing at `frame` with the given `flags`.
    ///
    /// The frame's physical address is masked into bits 12..=51 and ORed with
    /// the flag bits. The frame must be 4 KiB-aligned (which every [`PhysFrame`]
    /// is by construction), so no information is lost in the mask.
    #[inline]
    #[must_use]
    pub const fn new_pointing(frame: PhysFrame, flags: PageTableFlags) -> Self {
        let addr = frame.start_address().as_u64() & ADDR_MASK;
        Self(addr | flags.bits())
    }

    /// `true` if the entry is entirely zero (no present bit, no address).
    ///
    /// Cheaper than decoding flags and is the test the walker uses to detect a
    /// missing sub-table without allocating.
    #[inline]
    #[must_use]
    pub const fn is_unused(self) -> bool {
        self.0 == 0
    }

    /// Clear the entry to the all-zero state.
    ///
    /// After this the MMU treats the covered range as unmapped. The caller is
    /// responsible for invalidating any cached TLB entry (via `invlpg` or a
    /// CR3 reload) so the stale translation is not still used.
    #[inline]
    pub fn set_unused(&mut self) {
        self.0 = 0;
    }

    /// The raw `u64` bits of the entry, including both address and flags.
    ///
    /// Useful for logging or for round-tripping an entry through a value the
    /// bitflag helpers cannot represent (e.g. preserving software-available
    /// bits). For decoded access prefer [`flags`](Self::flags) and
    /// [`frame`](Self::frame).
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Decode the flag bits of this entry.
    ///
    /// `from_bits_truncate` drops the address field (bits 12..=51) and any
    /// software-available bits, returning only the named flags. An unused
    /// entry yields an empty flag set.
    #[inline]
    #[must_use]
    pub const fn flags(self) -> PageTableFlags {
        PageTableFlags::from_bits_truncate(self.0)
    }

    /// Overwrite the flag bits without changing the address.
    ///
    /// Keeps the address field intact and replaces the flag portion. This is
    /// how `mprotect`-style permission changes are expressed: read the entry,
    /// adjust flags, write them back without touching the mapped frame.
    #[inline]
    pub fn set_flags(&mut self, flags: PageTableFlags) {
        // Preserve the address bits, replace everything else with the new
        // flag set. The flag set's own bits never overlap the address field
        // (flags live in bits 0..=8 and 63; address lives in 12..=51), so a
        // plain OR is exact.
        self.0 = (self.0 & ADDR_MASK) | flags.bits();
    }

    /// Decode the destination physical address as a [`PhysFrame`].
    ///
    /// Returns the 4 KiB frame the entry points at. For intermediate-level
    /// entries (PML4e, PDPTE, PDE without huge) this is the frame holding the
    /// next-level table; for a leaf PTE it is the mapped page; for a huge PDE
    /// / PDPTE it is the start of the 2 MiB / 1 GiB region (still a valid
    /// [`PhysFrame`], just larger-aligned). The caller's level context
    /// disambiguates the interpretation.
    ///
    /// Returns `None` only if the entry is unused (all zero), since decoding a
    /// frame from a non-present entry is meaningless. A present entry with an
    /// all-zero address is a valid mapping of physical frame 0 and is returned
    /// as `Some`.
    #[inline]
    #[must_use]
    pub fn frame(self) -> Option<PhysFrame> {
        if self.is_unused() {
            return None;
        }
        Some(PhysFrame::containing_addr(PhysAddr::new_truncate(
            self.0 & ADDR_MASK,
        )))
    }

    /// The raw destination physical address, without the [`PhysFrame`] wrap.
    ///
    /// Like [`frame`](Self::frame) but returns the [`PhysAddr`] directly;
    /// useful for huge pages where the caller wants the larger-aligned base
    /// address without implying a 4 KiB frame.
    #[inline]
    #[must_use]
    pub fn addr(self) -> PhysAddr {
        PhysAddr::new_truncate(self.0 & ADDR_MASK)
    }

    /// Re-target the entry at `frame`, preserving its current flags.
    ///
    /// Equivalent to `self.set_frame(frame, self.flags())` but slightly
    /// cheaper because it does not recompute the flag set. Used by code that
    /// remaps a page to a different physical frame without changing
    /// permissions (e.g. copy-on-write resolution).
    #[inline]
    pub fn set_frame(&mut self, frame: PhysFrame, flags: PageTableFlags) {
        let addr = frame.start_address().as_u64() & ADDR_MASK;
        self.0 = addr | flags.bits();
    }

    /// `true` if the present bit is set.
    #[inline]
    #[must_use]
    pub const fn is_present(self) -> bool {
        self.flags().contains(PageTableFlags::PRESENT)
    }

    /// `true` if the huge-page bit is set.
    ///
    /// Meaningful only at levels 2 and 3; at level 1 the same bit is the PAT
    /// attribute, not a huge indicator. The walker checks this to decide
    /// whether to descend.
    #[inline]
    #[must_use]
    pub const fn is_huge(self) -> bool {
        self.flags().contains(PageTableFlags::HUGE)
    }

    /// `true` if the entry permits user-space access (the USER bit is set).
    #[inline]
    #[must_use]
    pub const fn is_user(self) -> bool {
        self.flags().contains(PageTableFlags::USER)
    }

    /// `true` if the entry is writable.
    #[inline]
    #[must_use]
    pub const fn is_writable(self) -> bool {
        self.flags().contains(PageTableFlags::WRITABLE)
    }
}

impl fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Render the raw bits plus the decoded flags so a crash dump shows
        // both the exact hardware value and the human-readable flag set.
        f.debug_struct("PageTableEntry")
            .field("raw", &format_args!("{:#018x}", self.0))
            .field("flags", &self.flags())
            .field("addr", &format_args!("{:#018x}", (self.0 & ADDR_MASK)))
            .finish()
    }
}

impl Default for PageTableEntry {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PageTable
// ---------------------------------------------------------------------------

/// A single level of an x86_64 page table: 512 entries, 4 KiB total.
///
/// The same type describes all four levels (PML4, PDPT, PD, PT) because the
/// hardware layout is identical at every level — only the *meaning* of an
/// entry's destination differs, and that is the walker's concern. The
/// `#[repr(C, align(4096))]` guarantees the array is 4096 bytes and starts at
/// a 4 KiB boundary, which are the two requirements the MMU imposes.
///
/// A `PageTable` is plain data: it holds 512 [`PageTableEntry`] values and
/// nothing else. Construction does not zero the table in memory — [`new`]
/// produces an all-zero value on the stack, which is fine for a freshly
/// allocated table that the caller will write into physical memory through the
/// HHDM. To zero a table already living at a physical frame, use
/// [`PageTable::zero`] through a reference obtained from the mapper.
///
/// [`new`]: PageTable::new
#[repr(C, align(4096))]
#[derive(Clone)]
pub struct PageTable {
    /// The 512 entries, in index order. `#[repr(C)]` makes this a contiguous
    /// array with no leading padding, so `&table as *const _ as *const u8`
    /// points at entry 0.
    entries: [PageTableEntry; 512],
}

impl PageTable {
    /// The number of entries in one page table, on every level.
    pub const ENTRY_COUNT: usize = 512;

    /// Create an all-zero page table.
    ///
    /// Every entry is [`PageTableEntry::new`], so the table as a whole maps
    /// nothing until entries are written. This is the correct initial value
    /// for a freshly allocated table frame.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        // `PageTableEntry` is a `Copy` type with a `const fn new`, so a
        // const-array initializer works in stable const eval. This avoids any
        // runtime memset and lets a `PageTable::new()` live in a `static`.
        Self {
            entries: [PageTableEntry::new(); 512],
        }
    }

    /// The entry at `index`, by shared reference.
    #[inline]
    #[must_use]
    pub fn entry(&self, index: PageTableIndex) -> &PageTableEntry {
        // PageTableIndex is guaranteed 0..=511 by its constructor, so the
        // usize cast is always in range. We index directly; no bounds check
        // is needed beyond the one the constructor already enforced.
        &self.entries[index.value() as usize]
    }

    /// The entry at `index`, by mutable reference.
    #[inline]
    #[must_use]
    pub fn entry_mut(&mut self, index: PageTableIndex) -> &mut PageTableEntry {
        &mut self.entries[index.value() as usize]
    }

    /// The whole entry array, by shared slice.
    ///
    /// Useful for scanning a table (e.g. to find the first unused slot, or to
    /// count present entries when tearing down an address space).
    #[inline]
    #[must_use]
    pub fn entries(&self) -> &[PageTableEntry; 512] {
        &self.entries
    }

    /// The whole entry array, by mutable slice.
    #[inline]
    #[must_use]
    pub fn entries_mut(&mut self) -> &mut [PageTableEntry; 512] {
        &mut self.entries
    }

    /// `true` if every entry in the table is unused (all zero).
    ///
    /// A fully-empty table can be freed and its frame returned to the
    /// allocator when it is no longer referenced by its parent. The walker
    /// uses this during `unmap` to decide whether to collapse a now-empty
    /// sub-table.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(|e| e.is_unused())
    }

    /// Zero every entry in the table.
    ///
    /// After this the table maps nothing. The caller must still invalidate any
    /// TLB entries that pointed through this table; clearing the entries in
    /// memory does not by itself evict cached translations.
    ///
    /// This is the routine the mapper calls on a freshly allocated table frame
    /// before installing it into a parent entry: a new table must be all-zero
    /// so that its present bits are clear and the MMU does not follow stale
    /// garbage pointers.
    #[inline]
    pub fn zero(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.set_unused();
        }
    }
}

impl Default for PageTable {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PageTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Count present entries rather than dumping 512 PTEs, which would be
        // useless noise in a log. A table with 0 present entries is almost
        // always a freshly-allocated one; a table with 512 is fully populated.
        let present = self.entries.iter().filter(|e| e.is_present()).count();
        f.debug_struct("PageTable")
            .field("present_entries", &present)
            .field("total", &Self::ENTRY_COUNT)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Index arithmetic: VirtAddr -> four 9-bit indices
// ---------------------------------------------------------------------------

/// The shift for the level-4 (PML4) index: bits 39..=47 of the virtual address.
const P4_SHIFT: u64 = 39;
/// The shift for the level-3 (PDPT) index: bits 30..=38.
const P3_SHIFT: u64 = 30;
/// The shift for the level-2 (PD) index: bits 21..=29.
const P2_SHIFT: u64 = 21;
/// The shift for the level-1 (PT) index: bits 12..=20.
const P1_SHIFT: u64 = 12;

/// The 9-bit index mask (each level selects one of 512 entries).
const INDEX_MASK: u64 = 0x1FF;

/// Extract the PML4 (level-4) index from a virtual address.
///
/// Bits 39..=47 of the canonical address select one of the 512 entries in the
/// root table pointed to by CR3. The result is always in `0..=511`.
#[inline]
#[must_use]
pub const fn p4_index(addr: VirtAddr) -> PageTableIndex {
    PageTableIndex::new_truncate(((addr.as_u64() >> P4_SHIFT) & INDEX_MASK) as u16)
}

/// Extract the PDPT (level-3) index from a virtual address (bits 30..=38).
#[inline]
#[must_use]
pub const fn p3_index(addr: VirtAddr) -> PageTableIndex {
    PageTableIndex::new_truncate(((addr.as_u64() >> P3_SHIFT) & INDEX_MASK) as u16)
}

/// Extract the PD (level-2) index from a virtual address (bits 21..=29).
#[inline]
#[must_use]
pub const fn p2_index(addr: VirtAddr) -> PageTableIndex {
    PageTableIndex::new_truncate(((addr.as_u64() >> P2_SHIFT) & INDEX_MASK) as u16)
}

/// Extract the PT (level-1) index from a virtual address (bits 12..=20).
#[inline]
#[must_use]
pub const fn p1_index(addr: VirtAddr) -> PageTableIndex {
    PageTableIndex::new_truncate(((addr.as_u64() >> P1_SHIFT) & INDEX_MASK) as u16)
}

/// The index for `addr` at the given [`PageTableLevel`].
///
/// Convenience for generic walking code that parameterises over the level: it
/// collapses the four dedicated `pN_index` functions into one dispatch. For
/// non-generic callers the named functions are clearer and slightly cheaper
/// (no match).
#[inline]
#[must_use]
pub fn index_for(addr: VirtAddr, level: PageTableLevel) -> PageTableIndex {
    match level {
        PageTableLevel::Four => p4_index(addr),
        PageTableLevel::Three => p3_index(addr),
        PageTableLevel::Two => p2_index(addr),
        PageTableLevel::One => p1_index(addr),
    }
}

/// The four indices for `addr`, from the root (PML4) down to the leaf (PT).
///
/// Returns `(p4, p3, p2, p1)` in walk order. A walker that needs all four at
/// once (e.g. to build or tear down a mapping) calls this once instead of
/// four separate `pN_index` calls, and the tuple layout makes the descent
/// direction obvious at the call site.
#[inline]
#[must_use]
pub fn indices(
    addr: VirtAddr,
) -> (
    PageTableIndex,
    PageTableIndex,
    PageTableIndex,
    PageTableIndex,
) {
    (
        p4_index(addr),
        p3_index(addr),
        p2_index(addr),
        p1_index(addr),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn va(n: u64) -> VirtAddr {
        VirtAddr::new_truncate(n)
    }

    #[test]
    fn flags_or_and_contains() {
        let f = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::COPY_ON_WRITE
            | PageTableFlags::NO_EXECUTE;
        assert!(f.contains(PageTableFlags::PRESENT));
        assert!(f.contains(PageTableFlags::WRITABLE));
        assert!(f.contains(PageTableFlags::NO_EXECUTE));
        assert!(f.contains(PageTableFlags::COPY_ON_WRITE));
        assert!(!f.contains(PageTableFlags::USER));
        // The NX bit survives the round trip through bits().
        assert_eq!(f.bits() >> 63, 1);
        assert_eq!(f.bits() & (1 << 9), 1 << 9);
    }

    #[test]
    fn leaf_pat_alias_uses_architectural_bit_seven() {
        assert_eq!(PageTableFlags::PAT_4K.bits(), 1 << 7);
        assert_eq!(PageTableFlags::PAT_4K.bits(), PageTableFlags::HUGE.bits());
    }

    #[test]
    fn entry_preserves_copy_on_write_software_bit() {
        let frame = PhysFrame::containing_addr(PhysAddr::new(0x8000).unwrap());
        let entry = PageTableEntry::new_pointing(
            frame,
            PageTableFlags::PRESENT | PageTableFlags::USER | PageTableFlags::COPY_ON_WRITE,
        );
        assert!(entry.flags().contains(PageTableFlags::COPY_ON_WRITE));
        assert!(!entry.is_writable());
    }

    #[test]
    fn preset_flag_sets_are_sane() {
        // KERNEL_DATA must be writable + present + global + NX, but not user.
        let kd = PageTableFlags::KERNEL_DATA;
        assert!(kd.contains(
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::GLOBAL
                | PageTableFlags::NO_EXECUTE
        ));
        assert!(!kd.contains(PageTableFlags::USER));
        // KERNEL_CODE must be executable (no NX) and not writable (W^X).
        let kc = PageTableFlags::KERNEL_CODE;
        assert!(kc.contains(PageTableFlags::PRESENT | PageTableFlags::GLOBAL));
        assert!(!kc.contains(PageTableFlags::NO_EXECUTE));
        assert!(!kc.contains(PageTableFlags::WRITABLE));
        // USER_DATA must be user + writable + NX, not global.
        let ud = PageTableFlags::USER_DATA;
        assert!(ud.contains(
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::USER
                | PageTableFlags::NO_EXECUTE
        ));
        assert!(!ud.contains(PageTableFlags::GLOBAL));
    }

    #[test]
    fn entry_new_is_unused() {
        let e = PageTableEntry::new();
        assert!(e.is_unused());
        assert!(!e.is_present());
        assert!(e.frame().is_none());
        assert_eq!(e.bits(), 0);
    }

    #[test]
    fn entry_round_trips_frame_and_flags() {
        let frame = PhysFrame::containing_addr(PhysAddr::new(0x8000_0000).unwrap());
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        let e = PageTableEntry::new_pointing(frame, flags);
        assert!(e.is_present());
        assert!(e.is_writable());
        assert!(!e.is_user());
        // The frame comes back as the 4 KiB-aligned address we put in.
        assert_eq!(e.frame().unwrap().start_address().as_u64(), 0x8000_0000);
        // The address field occupies bits 12..51; the flag bits are separate.
        assert_eq!(e.bits() & ADDR_MASK, 0x8000_0000);
    }

    #[test]
    fn entry_frame_zero_is_present_mapping() {
        // A present entry targeting physical frame 0 is a valid mapping, not
        // "unused" — frame() must return Some(frame 0), not None.
        let e = PageTableEntry::new_pointing(
            PhysFrame::containing_addr(PhysAddr::zero()),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
        assert!(!e.is_unused());
        assert!(e.is_present());
        assert_eq!(e.frame().unwrap().start_address().as_u64(), 0);
    }

    #[test]
    fn entry_set_flags_preserves_address() {
        let frame = PhysFrame::containing_addr(PhysAddr::new(0x1_0000).unwrap());
        let mut e =
            PageTableEntry::new_pointing(frame, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
        // Flip to read-only by removing WRITABLE; the mapped frame must stay.
        let mut f = e.flags();
        f.remove(PageTableFlags::WRITABLE);
        e.set_flags(f);
        assert!(!e.is_writable());
        assert!(e.is_present());
        assert_eq!(e.frame().unwrap().start_address().as_u64(), 0x1_0000);
    }

    #[test]
    fn entry_set_unused_clears_everything() {
        let frame = PhysFrame::containing_addr(PhysAddr::new(0x2_0000).unwrap());
        let mut e =
            PageTableEntry::new_pointing(frame, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
        e.set_unused();
        assert!(e.is_unused());
        assert!(!e.is_present());
        assert_eq!(e.bits(), 0);
    }

    #[test]
    fn page_table_new_is_all_unused_and_empty() {
        let t = PageTable::new();
        assert!(t.is_empty());
        // Every slot is unused and indexing stays in range.
        for i in 0..=511u16 {
            let idx = PageTableIndex::new(i).unwrap();
            assert!(t.entry(idx).is_unused());
        }
    }

    #[test]
    fn page_table_zero_clears_entries() {
        let mut t = PageTable::new();
        let idx = PageTableIndex::new(7).unwrap();
        *t.entry_mut(idx) = PageTableEntry::new_pointing(
            PhysFrame::containing_addr(PhysAddr::new(0x10_0000).unwrap()),
            PageTableFlags::PRESENT,
        );
        assert!(!t.is_empty());
        t.zero();
        assert!(t.is_empty());
        assert!(t.entry(idx).is_unused());
    }

    #[test]
    fn index_extraction_for_a_known_address() {
        // 0xFFFF_8000_0000_0000 is the HHDM base. Its four indices are all 0
        // except p4, which is 256 (bit 39 set from the sign-extension of
        // 0xFFFF_8000...). Concretely:
        //   p4 = (0xFFFF_8000_0000_0000 >> 39) & 0x1FF
        let addr = va(0xFFFF_8000_0000_0000);
        let expected_p4 = ((0xFFFF_8000_0000_0000u64 >> 39) & 0x1FF) as u16;
        assert_eq!(p4_index(addr).value(), expected_p4);
        assert_eq!(
            p3_index(addr).value(),
            ((0xFFFF_8000_0000_0000u64 >> 30) & 0x1FF) as u16
        );
        assert_eq!(
            p2_index(addr).value(),
            ((0xFFFF_8000_0000_0000u64 >> 21) & 0x1FF) as u16
        );
        assert_eq!(
            p1_index(addr).value(),
            ((0xFFFF_8000_0000_0000u64 >> 12) & 0x1FF) as u16
        );
    }

    #[test]
    fn index_for_dispatch_matches_named_functions() {
        let addr = va(0x0000_7FFF_DEAD_BEEF);
        assert_eq!(index_for(addr, PageTableLevel::Four), p4_index(addr));
        assert_eq!(index_for(addr, PageTableLevel::Three), p3_index(addr));
        assert_eq!(index_for(addr, PageTableLevel::Two), p2_index(addr));
        assert_eq!(index_for(addr, PageTableLevel::One), p1_index(addr));
    }

    #[test]
    fn indices_returns_walk_order() {
        let addr = va(0xDEAD_BEEF_0000);
        let (p4, p3, p2, p1) = indices(addr);
        assert_eq!(p4, p4_index(addr));
        assert_eq!(p3, p3_index(addr));
        assert_eq!(p2, p2_index(addr));
        assert_eq!(p1, p1_index(addr));
    }

    #[test]
    fn entry_layout_is_eight_bytes() {
        // The hardware PTE is exactly 8 bytes; the transparent wrapper must
        // not add padding. If this ever breaks, every page table in the system
        // is mis-sized and the MMU walks garbage.
        assert_eq!(core::mem::size_of::<PageTableEntry>(), 8);
        assert_eq!(
            core::mem::align_of::<PageTableEntry>(),
            core::mem::align_of::<u64>()
        );
    }

    #[test]
    fn page_table_layout_is_4kib_aligned() {
        // A page table must be exactly 4096 bytes and 4 KiB-aligned, or the
        // MMU cannot use it. Both are enforced by repr(C, align(4096)).
        assert_eq!(core::mem::size_of::<PageTable>(), 4096);
        assert_eq!(core::mem::align_of::<PageTable>(), 4096);
        assert_eq!(PageTable::ENTRY_COUNT, 512);
    }
}
