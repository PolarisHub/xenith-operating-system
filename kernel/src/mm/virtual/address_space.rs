//! Virtual address spaces and the higher-half direct map.
//!
//! An [`AddressSpace`] is the kernel's handle to a single x86_64 four-level
//! page table hierarchy rooted at a PML4 frame. Every userspace process owns
//! one; the kernel itself owns a singleton — the "kernel address space" —
//! whose PML4 Limine built for us at boot and which we *adopt* by reading
//! CR3 rather than reconstructing from scratch.
//!
//! # The higher-half direct map (HHDM)
//!
//! Limine direct-maps *all* physical RAM at a fixed virtual offset in the
//! canonical upper half. On Xenith that offset is
//! [`HIGHER_HALF`] (`0xFFFF_8000_0000_0000`): for any physical address `p`,
//! `HIGHER_HALF + p` is a writable, kernel-only virtual address that hits the
//! same byte. This is what lets the kernel touch page tables, frame buffers,
//! and the memory-map array without first allocating page-table entries to
//! reach them — the translations already exist.
//!
//! [`init_hhdm`] records the offset Limine chose (read from the boot info's
//! HHDM tag) into a module-global so that [`phys_to_virt`] can do the
//! arithmetic anywhere in `mm`. The offset is in practice always
//! [`HIGHER_HALF`], but we store the Limine value verbatim rather than
//! hard-coding it so a future 5-level-paging build that uses a different
//! offset keeps working.
//!
//! # Kernel vs. user mappings
//!
//! User pages live in the low canonical half (below [`USER_MAX`]) and carry
//! the `USER` bit so ring 3 can reach them. Kernel pages live in the high
//! half and never set `USER`; with SMEP/SMAP enabled, ring 0 touching a
//! user page or ring 3 executing a kernel page both fault. [`map_user`]
//! enforces the low-half constraint and sets `USER`; [`map_kernel`] maps a
//! physical range into the HHDM with kernel-only, global, executable flags.
//!
//! [`map_user`]: AddressSpace::map_user
//! [`map_kernel`]: AddressSpace::map_kernel
//! [`translate`]: AddressSpace::translate
//! [`unmap`]: AddressSpace::unmap
//! [`fork`]: AddressSpace::fork
//! [`destroy`]: AddressSpace::destroy

extern crate alloc;

use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use xenith_bitflags::bitflags;
use xenith_types::{
    Page, PageTableIndex, PageTableLevel, PhysAddr, PhysFrame, VirtAddr, PAGE_SIZE,
};

use crate::arch::x86_64::instructions::{read_cr3, write_cr3};
use crate::sync::SpinLock;

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/// The base of the kernel's higher-half direct map.
///
/// Every physical address `p` is reachable at `HIGHER_HALF + p`. This is the
/// canonical upper-half boundary (bit 47 set, bits 48..=63 sign-extended) and
/// matches the offset Limine reports via its HHDM tag on every PC we target.
/// Keeping it as a named constant rather than spelling the literal means the
/// page-walk code never has to wonder which "0xFFFF_..." it is looking at.
pub const HIGHER_HALF: u64 = 0xFFFF_8000_0000_0000;

/// The highest virtual address a user-space mapping may use.
///
/// This is the top of the canonical low half — bit 47 clear and every bit
/// above it clear. Addresses in `0x0000_7FFF_FFFF_FFFF + 1 ..= HIGHER_HALF - 1`
/// are non-canonical and would `#GP` on access, so the user region is
/// `[0, USER_MAX]` inclusive. [`AddressSpace::map_user`] rejects any page
/// whose start address exceeds this.
pub const USER_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;

/// The number of entries in one page-table level: 512 (9 bits).
///
/// Each level of the x86_64 four-level walk indexes 512 8-byte entries, which
/// fills exactly one 4 KiB frame. Every `PageTable` is this many entries.
pub const ENTRIES_PER_TABLE: usize = 512;

/// The bit mask covering the physical-address field of a PTE: bits 12..=51.
///
/// Page-table entries store a 4 KiB-aligned physical address in bits 12..=51
/// (40 bits, enough for up to 1 TiB of physical memory at frame granularity).
/// Bits 52..=62 are software-available and bit 63 is NX; the low 12 bits are
/// flags. This mask isolates the address so [`PageTableEntry::frame`] can
/// pull it out without disturbing the flag bits.
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ---------------------------------------------------------------------------
// Page-table entry flags
// ---------------------------------------------------------------------------

bitflags! {
    /// The flag bits of an x86_64 page-table entry.
    ///
    /// These are the architecturally-defined bits in the low 12 bytes and bit
    /// 63 (NX) of a PTE. The address field (bits 12..=51) is *not* part of
    /// this flag set — it lives in [`PageTableEntry`] alongside the flags and
    /// is manipulated through [`PageTableEntry::frame`] /
    /// [`PageTableEntry::set`].
    ///
    /// Not every bit is meaningful at every level: `HUGE_PAGE` is only
    /// interpreted at PDPTE/PDE levels, `GLOBAL` is only honored at leaf
    /// entries, and `DIRTY`/`ACCESSED` are only set by the MMU on leaf
    /// entries. The type carries all of them so a single flag set can be
    /// passed to any mapping routine; the caller is responsible for setting
    /// only the bits that make sense at the target level.
    pub struct PageTableFlags: u64 {
        /// Present. The entry maps something; clear means a fault on access.
        /// Every usable mapping sets this; clearing it without first writing
        /// back the entry (or invalidating) leaves a stale TLB entry.
        const PRESENT     = 1 << 0;
        /// Writable. If clear, writes fault (#PF). Read-only pages clear this.
        const WRITABLE    = 1 << 1;
        /// User/supervisor. If set, ring 3 may access; if clear, only ring 0.
        /// Every user page sets this; kernel pages leave it clear so SMEP
        /// and SMAP can do their job.
        const USER        = 1 << 2;
        /// Page-level write-through. The CPU uses write-through caching for
        /// this page's translations. Xenith leaves it clear (write-back).
        const WRITE_THROUGH = 1 << 3;
        /// Page-level cache disable. The CPU does not cache this page's
        /// translations. Used for MMIO regions mapped into the HHDM.
        const CACHE_DISABLE = 1 << 4;
        /// Accessed. Set by the MMU when the page is read/written. The kernel
        /// reads it for eviction policy and never sets it manually.
        const ACCESSED    = 1 << 5;
        /// Dirty. Set by the MMU when the page is written. Same as ACCESSED:
        /// a hardware-maintained bit the kernel only reads.
        const DIRTY       = 1 << 6;
        /// Huge/large page. At PDE level => 2 MiB pages; at PDPTE level =>
        /// 1 GiB pages (requires PDPE1GB). Leaf-only; ignored at PML4.
        const HUGE_PAGE   = 1 << 7;
        /// Global. The translation survives CR3 writes (does not flush from
        /// the TLB). Reserved for kernel mappings; requires CR4.PGE, which
        /// `early_init` sets. User pages must never set this.
        const GLOBAL      = 1 << 8;
        /// Software-owned marker for a shared user page that was writable
        /// before `fork`. Hardware ignores this available PTE bit; Xenith
        /// clears WRITABLE while it is set and splits the frame on a write
        /// fault.
        const COPY_ON_WRITE = 1 << 9;
        /// No-execute. The page cannot be fetched as an instruction; a fetch
        /// faults (#PF with the I/D bit set). Requires EFER.NXE, which the
        /// kernel enables during arch bring-up. Code pages clear this.
        const NO_EXECUTE  = 1 << 63;
    }
}

impl PageTableFlags {
    /// The flag set for a typical user-space data page: present, writable,
    /// user-accessible, no-execute. This is what [`AddressSpace::map_user`]
    /// ORs in by default for anonymous user memory unless the caller asks
    /// for executable or read-only.
    ///
    /// Built with `from_bits_truncate` because the `BitOr` operator is not
    /// `const`-evaluable (trait methods cannot be `const`), so a `const`
    /// flag set has to be assembled from its raw bits. The value is
    /// `PRESENT | WRITABLE | USER | NO_EXECUTE` = `0x8000_0000_0000_0007`.
    pub const USER_DATA: Self = Self::from_bits_truncate(
        Self::PRESENT.bits() | Self::WRITABLE.bits() | Self::USER.bits() | Self::NO_EXECUTE.bits(),
    );

    /// The flag set for a kernel HHDM direct-map entry: present, writable,
    /// global, executable (the HHDM covers kernel code/data, so NX is left
    /// off — the kernel needs to execute from the higher half). Global so
    /// the mapping survives context switches.
    ///
    /// `PRESENT | WRITABLE | GLOBAL` = `0x0000_0000_0000_0103`.
    pub const KERNEL_HHDM: Self = Self::from_bits_truncate(
        Self::PRESENT.bits() | Self::WRITABLE.bits() | Self::GLOBAL.bits(),
    );
}

// ---------------------------------------------------------------------------
// PageTableEntry
// ---------------------------------------------------------------------------

/// A single 64-bit page-table entry.
///
/// A PTE packs a 4 KiB-aligned physical address (bits 12..=51) together with
/// flag bits (0..=8 and 63) and software-available bits (9..=11, 52..=62).
/// This newtype keeps the raw `u64` so it is `#[repr(transparent)]` and
/// exactly the size the hardware expects in a page-table frame; the accessors
/// extract the two logical fields (address and flags) without letting them
/// leak into each other.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// A completely empty entry: not present, no address, no flags.
    ///
    /// Page-table frames allocated by [`AddressSpace::new_empty`] are filled
    /// with this value so any walk through an unpopulated slot sees "not
    /// present" rather than stale bootloader data.
    #[inline]
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Construct an entry pointing at `frame` with the given `flags`.
    ///
    /// The frame's low 12 bits are masked off (a PTE address is always
    /// 4 KiB-aligned) and OR'd with the flag bits. The frame address must
    /// fit in 52 bits; frames handed out by the allocator always do.
    #[inline]
    #[must_use]
    pub const fn new(frame: PhysFrame, flags: PageTableFlags) -> Self {
        Self((frame.start_address().as_u64() & ADDR_MASK) | flags.bits())
    }

    /// The raw 64-bit PTE value, as the hardware sees it.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Is the entry present? (PTE bit 0.)
    #[inline]
    #[must_use]
    pub const fn is_present(self) -> bool {
        self.0 & PageTableFlags::PRESENT.bits() != 0
    }

    /// Is this a huge/large-page entry? (PTE bit 7.)
    ///
    /// Only meaningful at PDPTE and PDE levels; a leaf PTE with this bit set
    /// is architecturally reserved and would fault, so the walker treats a
    /// set `HUGE_PAGE` at any non-leaf level as "stop walking here".
    #[inline]
    #[must_use]
    pub const fn is_huge(self) -> bool {
        self.0 & PageTableFlags::HUGE_PAGE.bits() != 0
    }

    /// The flag bits of this entry, with the address field stripped.
    #[inline]
    #[must_use]
    pub const fn flags(self) -> PageTableFlags {
        // from_bits_truncate drops any bit outside the defined flag set —
        // notably the address field, which is not a flag. This is the only
        // sound way to recover the flags since the address and flags share
        // the same u64.
        PageTableFlags::from_bits_truncate(self.0)
    }

    /// The physical frame this entry points at, or `None` if the address
    /// field is zero.
    ///
    /// Returns `None` for an empty entry so callers can distinguish "not
    /// present" from "present but pointing at frame 0" (the latter is a
    /// legitimate mapping of the first physical page, e.g. for the real-mode
    /// IVT or trampoline code).
    #[inline]
    #[must_use]
    pub fn frame(self) -> Option<PhysFrame> {
        let addr = self.0 & ADDR_MASK;
        if addr == 0 && !self.is_present() {
            return None;
        }
        Some(PhysFrame::containing_addr(PhysAddr::new_truncate(addr)))
    }

    /// Overwrite both the frame and the flags in one store.
    ///
    /// Use this when mapping a page: it is a single volatile write that
    /// publishes the entry atomically with respect to the MMU's walker (the
    /// walker observes a consistent present/not-present transition rather
    /// than a torn address-with-old-flags state).
    #[inline]
    pub fn set(&mut self, frame: PhysFrame, flags: PageTableFlags) {
        // SAFETY: `self` is `repr(transparent)` over a `u64`, so taking a
        // raw mutable pointer to it yields a valid `*mut u64` with no
        // padding. The volatile store publishes the new PTE to any concurrent
        // hardware page-table walk. `self` is guaranteed dereferenceable
        // because the caller holds the `&mut`.
        let value = (frame.start_address().as_u64() & ADDR_MASK) | flags.bits();
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(*self).cast::<u64>(), value) };
    }

    /// Clear the entry to not-present, returning the frame it pointed at.
    ///
    /// Used by [`AddressSpace::unmap`]. The cleared entry is a single
    /// volatile write of zero, which the MMU treats as "not present".
    #[inline]
    pub fn clear(&mut self) -> Option<PhysFrame> {
        let prev = self.frame();
        // SAFETY: same repr/aliasing rationale as `set`; a zero store marks
        // the entry not-present.
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(*self).cast::<u64>(), 0) };
        prev
    }
}

impl core::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PageTableEntry")
            .field("raw", &format_args!("0x{:016x}", self.0))
            .field("present", &self.is_present())
            .field("frame", &self.frame().map(|fr| fr.start_address()))
            .field("flags", &self.flags().bits())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// PageTable
// ---------------------------------------------------------------------------

/// A single 4 KiB page table: 512 entries.
///
/// `PageTable` is `#[repr(C, align(4096))]` so it exactly fills one physical
/// frame and can be overlaid onto a frame reached through the HHDM by a
/// plain pointer cast. Only the kernel ever instantiates a `PageTable`
/// directly (when zeroing a freshly allocated frame); the walker always
/// reads them through [`phys_to_virt`] + a cast, never by value.
#[repr(C, align(4096))]
pub struct PageTable {
    /// The 512 entries, indexed by [`PageTableIndex`] (0..=511).
    entries: [PageTableEntry; ENTRIES_PER_TABLE],
}

impl PageTable {
    /// An all-zero (all-not-present) table, suitable for overlaying onto a
    /// freshly allocated frame before it is linked into a parent entry.
    ///
    /// This is `const` so a new table can be initialised without an allocator
    /// in the (rare) case where the kernel has a static frame to spare.
    #[inline]
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            entries: [PageTableEntry::empty(); ENTRIES_PER_TABLE],
        }
    }

    /// Read the entry at `index`.
    ///
    /// The read is volatile so the compiler cannot hoist it out of a walk
    /// loop or assume a stale value — the MMU may have set ACCESSED/DIRTY
    /// between reads.
    #[inline]
    #[must_use]
    pub fn entry(&self, index: PageTableIndex) -> PageTableEntry {
        // SAFETY: `index.value()` is 0..=511 by construction, and `entries`
        // has exactly 512 slots, so the index is in bounds. The volatile
        // read returns the current PTE value as the hardware sees it.
        let idx = index.value() as usize;
        unsafe { ptr::read_volatile(ptr::addr_of!(self.entries[idx])) }
    }

    /// A mutable reference to the entry at `index`.
    ///
    /// Returns a `&mut` so callers can use [`PageTableEntry::set`] /
    /// [`PageTableEntry::clear`], which themselves do volatile writes. The
    /// borrow is unique so there is no torn-write risk from aliasing.
    #[inline]
    pub fn entry_mut(&mut self, index: PageTableIndex) -> &mut PageTableEntry {
        let idx = index.value() as usize;
        &mut self.entries[idx]
    }

    /// Iterate over all entries, yielding `(index, entry)` pairs. Used by
    /// [`AddressSpace::destroy`] to find and free lower-level tables.
    pub fn iter(&self) -> impl Iterator<Item = (PageTableIndex, PageTableEntry)> + '_ {
        (0..ENTRIES_PER_TABLE).map(move |i| {
            // SAFETY: i is in 0..512 and PageTableIndex::new accepts that.
            let idx = PageTableIndex::new(i as u16).expect("i < 512");
            (idx, self.entry(idx))
        })
    }
}

// ---------------------------------------------------------------------------
// HHDM offset storage
// ---------------------------------------------------------------------------

/// The HHDM offset Limine reported, or 0 before [`init_hhdm`] has run.
///
/// Stored in an `AtomicU64` rather than a `spin::Once` so reads from
/// [`phys_to_virt`] — which happen on every page-table walk and every
/// physical-to-virtual conversion in the kernel — stay lock-free and
/// interrupt-safe. Once set it never changes, so `Relaxed` ordering is
/// sufficient: we only need eventual visibility, not synchronisation with
/// any other variable.
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Record the HHDM offset from the Limine boot info.
///
/// Called once from `mm::init` after the boot info is available. The value
/// is in practice always [`HIGHER_HALF`], but we take it as a parameter so
/// this module does not depend on the `xenith-boot` wrapper — the caller
/// reads `boot_info.hhdm_offset()` and passes the `u64` here.
///
/// Panics if called twice, since a changing HHDM base would silently
/// mis-translate every physical address in the kernel.
pub fn init_hhdm(offset: u64) {
    let prev = HHDM_OFFSET.compare_exchange(0, offset, Ordering::SeqCst, Ordering::SeqCst);
    assert!(
        prev.is_ok(),
        "xenith.mm.virtual: init_hhdm called twice (offset was 0x{:016x})",
        offset
    );
    ::log::debug!(
        "xenith.mm.virtual: HHDM offset = 0x{:016x} (HIGHER_HALF = 0x{:016x})",
        offset,
        HIGHER_HALF
    );
}

/// The HHDM offset previously recorded by [`init_hhdm`].
///
/// Returns [`HIGHER_HALF`] as a fallback if [`init_hhdm`] has not run yet.
/// The fallback keeps very-early boot code (before `mm::init`) working when
/// it touches a physical address through the HHDM; the value is the same
/// one Limine uses on every target, so it is correct in practice even
/// before the boot-info tag is read.
#[inline]
#[must_use]
pub fn hhdm_offset() -> u64 {
    let v = HHDM_OFFSET.load(Ordering::Relaxed);
    if v != 0 {
        v
    } else {
        HIGHER_HALF
    }
}

/// Translate a physical address to its HHDM direct-map virtual address.
///
/// Pure arithmetic (`hhdm_offset() + phys`); never allocates page tables.
/// The result is always in the kernel half, so it is safe to dereference
/// from ring 0 but must never be handed to ring 3.
#[inline]
#[must_use]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new_truncate(hhdm_offset() + phys.as_u64())
}

/// The inverse of [`phys_to_virt`]: recover the physical address from an
/// HHDM-mapped virtual address. Returns `None` if `virt` is not in the
/// HHDM region (i.e. below `hhdm_offset()`).
#[inline]
#[must_use]
pub fn virt_to_phys(virt: VirtAddr) -> Option<PhysAddr> {
    let off = hhdm_offset();
    let v = virt.as_u64();
    if v >= off {
        Some(PhysAddr::new_truncate(v - off))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Frame allocator bridge
// ---------------------------------------------------------------------------

/// The contract the page-table code needs from the physical frame allocator.
///
/// This thin local trait keeps page-table ownership independent of the
/// concrete physical allocator. `mm::init` registers the live adapter once the
/// bitmap/buddy allocator is ready, and [`alloc_frame`] / [`free_frame`]
/// delegate through it. The contract stays minimal: one 4 KiB frame in or out,
/// because that is all the paging code requires.
pub trait FrameAllocator: Send + Sync {
    /// Return one unused 4 KiB physical frame, or `None` if the allocator is
    /// exhausted. The returned frame is zeroed by the caller as needed.
    fn allocate(&self) -> Option<PhysFrame>;
    /// Return a frame to the pool. The frame must have come from
    /// [`allocate`](Self::allocate) and must not still be mapped anywhere.
    fn deallocate(&self, frame: PhysFrame);
}

/// Global frame-allocator pointer, registered once by `mm::init` once the
/// real allocator is up. Before that, [`alloc_frame`] returns `None`.
///
/// The `AtomicU64` holds the pointer as a raw `usize`, stored with `Release`
/// and loaded with `Acquire` so the allocator object is published before the
/// pointer to it becomes visible. A null value means "not registered yet".
static FRAME_ALLOC: SpinLock<Option<&'static dyn FrameAllocator>> = SpinLock::new(None);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SharedUserFrame {
    frame: PhysFrame,
    references: usize,
}

/// Only multiply-mapped user frames are recorded. Once a release leaves one
/// owner, the entry is removed and that final owner follows the normal frame
/// lifecycle without permanent per-page metadata.
static SHARED_USER_FRAMES: SpinLock<Vec<SharedUserFrame>> = SpinLock::new(Vec::new());

/// Serializes a write-fault split with the corresponding reference update.
/// This remains necessary after AP bring-up because two children may fault on
/// the same inherited frame concurrently.
static COW_FAULT_LOCK: SpinLock<()> = SpinLock::new(());

/// Register the global frame allocator. Called once from `mm::init`.
///
/// Panics on double registration to catch a wiring mistake early — there is
/// only ever one physical frame allocator in the kernel.
pub fn register_frame_allocator(alloc: &'static dyn FrameAllocator) {
    let mut slot = FRAME_ALLOC.lock();
    assert!(
        slot.is_none(),
        "xenith.mm.virtual: frame allocator registered twice"
    );
    *slot = Some(alloc);
}

/// Allocate a single 4 KiB frame from the global allocator.
///
/// Returns `None` if no allocator has been registered yet (early boot) or if
/// the allocator is exhausted. Callers that cannot handle `None` should
/// propagate the error rather than panicking — exhausting physical memory is
/// a recoverable condition for most callers (e.g. `fork` failing with
/// `OutOfMemory`).
fn alloc_frame() -> Option<PhysFrame> {
    FRAME_ALLOC
        .lock()
        .as_ref()
        .and_then(|alloc| alloc.allocate())
}

/// Free a frame back to the global allocator. No-op if none is registered.
fn free_frame(frame: PhysFrame) {
    if let Some(alloc) = *FRAME_ALLOC.lock() {
        alloc.deallocate(frame);
    }
}

// ---------------------------------------------------------------------------
// Mapping errors
// ---------------------------------------------------------------------------

/// Why a mapping operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// The virtual address is outside the region allowed for this kind of
    /// mapping (e.g. a user page above [`USER_MAX`] or a kernel page in the
    /// low half).
    OutOfRange,
    /// No physical frame could be allocated for a new page table.
    OutOfMemory,
    /// The page is already mapped. Callers must [`unmap`](AddressSpace::unmap)
    /// first if they intend to remap.
    AlreadyMapped,
    /// A present paging-structure entry did not contain a usable frame.
    CorruptPageTable,
    /// Eager fork only duplicates the 4 KiB user mappings Xenith creates.
    HugePageUnsupported,
}

/// Why an unmap operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmapError {
    /// The page is not mapped, so there is nothing to remove.
    NotMapped,
}

// ---------------------------------------------------------------------------
// AddressSpace
// ---------------------------------------------------------------------------

/// A virtual address space: the physical frame holding its PML4 root plus
/// the operations to map, unmap, and translate pages within it.
///
/// Every userspace process owns one `AddressSpace`; the kernel owns a
/// singleton adopted from CR3 at boot. The struct is a single `PhysFrame`
/// (8 bytes) so it can be embedded by value in a process control block
/// without indirection. All the actual page-table memory lives in physical
/// frames reached through the HHDM; the `AddressSpace` is just the root
/// handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressSpace {
    /// The 4 KiB physical frame holding the PML4 (level-4) table. Writing
    /// this frame's address into CR3 activates the address space.
    p4_frame: PhysFrame,
}

impl AddressSpace {
    // -- construction ------------------------------------------------------

    /// Adopt the currently-active address space as a kernel handle.
    ///
    /// Reads CR3 and wraps the PML4 frame it points at. This is how the
    /// kernel "builds its identity via the Limine HHDM tag at init": Limine
    /// constructed the initial PML4 (with the HHDM direct map, the kernel
    /// image, and the framebuffer mapped) before jumping to `_start`, so at
    /// boot the running CR3 *is* the kernel address space. We adopt it
    /// rather than rebuilding so we never lose the translations the
    /// bootloader set up.
    ///
    /// # Safety
    ///
    /// The caller must be in ring 0 (CR3 is privileged) and the current CR3
    /// must point at a valid, present PML4 — always true once Limine has
    /// handed control to the kernel.
    #[inline]
    #[must_use]
    pub unsafe fn adopt_current() -> Self {
        // SAFETY: ring-0 read of CR3; delegated to the instruction wrapper.
        // The frame address is extracted with the CR3 address mask via Cr3.
        let raw = unsafe { read_cr3() };
        let addr = PhysAddr::new_truncate(raw & ADDR_MASK);
        Self {
            p4_frame: PhysFrame::containing_addr(addr),
        }
    }

    /// Allocate a fresh, empty address space with a zeroed PML4.
    ///
    /// Used by [`fork`](Self::fork) (eventually) and by the user-space
    /// loader to build a process's first address space. The new PML4 has no
    /// entries; the caller is responsible for either mapping the kernel
    /// higher half into it (so syscall entry works) or arranging for the
    /// process to share the kernel half of an existing space.
    ///
    /// Returns `Err(OutOfMemory)` if the frame allocator is not yet up or is
    /// exhausted.
    pub fn new_empty() -> Result<Self, MapError> {
        let frame = alloc_frame().ok_or(MapError::OutOfMemory)?;
        // Zero the new PML4 frame through the HHDM so every entry starts
        // not-present. A page-table frame must be zeroed before it is
        // linked into a parent entry, otherwise stale garbage would be
        // interpreted as mappings.
        zero_frame(&frame);
        Ok(Self { p4_frame: frame })
    }

    /// The physical frame holding this space's PML4 root.
    #[inline]
    #[must_use]
    pub const fn p4_frame(&self) -> PhysFrame {
        self.p4_frame
    }

    /// The raw CR3 value to load in order to activate this address space.
    ///
    /// Bits 12..=51 carry the PML4 physical address; the low flag bits
    /// (PWT/PCD) are left clear for write-back caching, matching the kernel
    /// default. The result is suitable for [`load`](Self::load).
    #[inline]
    #[must_use]
    pub fn cr3(&self) -> u64 {
        self.p4_frame.start_address().as_u64() & ADDR_MASK
    }

    /// Activate this address space by writing CR3.
    ///
    /// Writing CR3 switches the active PML4 and flushes non-global TLB
    /// entries on the local core. Kernel-global mappings (the HHDM, kernel
    /// code) survive because they were tagged `GLOBAL`.
    ///
    /// # Safety
    ///
    /// The caller must ensure `self` points at a valid, present PML4 and
    /// that switching address spaces does not pull the rug out from under
    /// any in-flight memory access depending on the old translations.
    #[inline]
    pub unsafe fn load(&self) {
        // SAFETY: forwarded to `write_cr3`; the caller vouches for the CR3
        // image (constructed from a real PML4 frame by `cr3()`).
        unsafe { write_cr3(self.cr3()) };
    }

    // -- table access ------------------------------------------------------

    /// The virtual address of the PML4 table, reached through the HHDM.
    #[inline]
    fn p4_addr(&self) -> VirtAddr {
        phys_to_virt(self.p4_frame.start_address())
    }

    /// A mutable reference to the PML4 table, reached through the HHDM.
    ///
    /// # Safety
    ///
    /// The caller must ensure no other `&mut` to this table is live. In
    /// practice the paging code holds a single `&mut` chain down the walk,
    /// so this is straightforward; the `unsafe` is here because the
    /// reference is fabricated from a raw pointer rather than borrowed from
    /// an owning Rust value.
    #[inline]
    #[allow(clippy::mut_from_ref)]
    unsafe fn p4_mut(&self) -> &mut PageTable {
        // SAFETY: `p4_addr()` is the HHDM virtual address of the PML4 frame,
        // which is mapped writable by Limine. The frame is 4 KiB-aligned
        // and `PageTable` is `repr(C, align(4096))` with exactly 4096 bytes,
        // so the cast is layout-compatible. The caller guarantees no aliasing.
        unsafe { &mut *(self.p4_addr().as_u64() as *mut PageTable) }
    }

    /// A shared reference to the PML4 table, reached through the HHDM.
    ///
    /// # Safety
    ///
    /// Same aliasing contract as [`p4_mut`](Self::p4_mut), but for reads.
    #[inline]
    unsafe fn p4(&self) -> &PageTable {
        // SAFETY: see `p4_mut`; the cast is sound for the same reasons and
        // the caller guarantees no conflicting `&mut` is live.
        unsafe { &*(self.p4_addr().as_u64() as *const PageTable) }
    }

    // -- mapping -----------------------------------------------------------

    /// Map a single 4 KiB user page to a physical frame.
    ///
    /// `page` must be in the low canonical half (`page.start_address() <=
    /// USER_MAX`); `flags` must include [`PageTableFlags::USER`] for the
    /// mapping to be reachable from ring 3. Intermediate page tables
    /// (PDPT/PD/PT) are allocated and zeroed on demand; each is linked into
    /// its parent with `PRESENT | WRITABLE | USER` so the user mapping is
    /// walkable all the way down.
    ///
    /// Returns `Err(AlreadyMapped)` if the leaf PTE is already present, so
    /// the caller does not silently overwrite an existing mapping.
    pub fn map_user(
        &self,
        page: Page,
        frame: PhysFrame,
        flags: PageTableFlags,
    ) -> Result<(), MapError> {
        let start = page.start_address().as_u64();
        if start > USER_MAX {
            ::log::trace!(
                "xenith.mm.virtual: map_user rejected page {:?} above USER_MAX",
                page
            );
            return Err(MapError::OutOfRange);
        }

        // Intermediate entries need USER so a ring-3 access can walk through
        // them; the CPU checks USER at every level, not just the leaf. Built
        // from raw bits because `BitOr` is not `const` (see `USER_DATA`).
        // PRESENT | WRITABLE | USER = 0x7.
        const INTERMEDIATE: PageTableFlags = PageTableFlags::from_bits_truncate(
            PageTableFlags::PRESENT.bits()
                | PageTableFlags::WRITABLE.bits()
                | PageTableFlags::USER.bits(),
        );

        let leaf = self.walk_or_create(page, INTERMEDIATE)?;
        if leaf.is_present() {
            return Err(MapError::AlreadyMapped);
        }
        leaf.set(frame, flags | PageTableFlags::PRESENT);
        // Flush any stale TLB entry for this page. A prior not-present walk
        // may have cached the absence; without invlpg the new mapping might
        // not take effect until the next CR3 write.
        // SAFETY: `start` is a canonical user address; invlpg is privileged
        // and we are in ring 0.
        crate::arch::x86_64::smp::shootdown_page(self.cr3(), start);
        Ok(())
    }

    /// Map a contiguous physical range into the HHDM direct map.
    ///
    /// This is [`map_kernel`]: it establishes the kernel's higher-half
    /// identity for a physical region `[phys, phys + count*4096)` at virtual
    /// addresses `[HIGHER_HALF + phys, ...)`. Each leaf entry is
    /// [`PageTableFlags::KERNEL_HHDM`] (present, writable, global,
    /// executable) so the mapping survives context switches and is writable
    /// from ring 0. Intermediate tables are allocated with `PRESENT |
    /// WRITABLE` (no `USER`, no `GLOBAL` — those are leaf-only).
    ///
    /// Limine has already mapped the HHDM for the boot-time physical memory;
    /// this method is used later to extend it (for hot-added memory, MMIO
    /// apertures, or dynamically discovered regions) without rebuilding CR3.
    ///
    /// [`map_kernel`]: AddressSpace::map_kernel
    pub fn map_kernel(&self, phys_start: PhysAddr, count: u64) -> Result<(), MapError> {
        if count == 0 {
            return Ok(());
        }
        // Intermediate kernel tables: present + writable, no USER (kernel
        // only), no GLOBAL (global is leaf-only). PRESENT | WRITABLE = 0x3.
        const INTERMEDIATE: PageTableFlags = PageTableFlags::from_bits_truncate(
            PageTableFlags::PRESENT.bits() | PageTableFlags::WRITABLE.bits(),
        );

        let mut phys = phys_start.align_down(PAGE_SIZE);
        for _ in 0..count {
            let frame = PhysFrame::containing_addr(phys);
            // The HHDM virtual address for this frame: HIGHER_HALF + phys.
            // We use `phys_to_virt` so the offset stays consistent with
            // whatever Limine reported (in practice HIGHER_HALF).
            let virt = phys_to_virt(phys);
            let page = Page::containing_addr(virt);
            let leaf = self.walk_or_create(page, INTERMEDIATE)?;
            // If the HHDM already covers this frame (Limine mapped it), the
            // entry will be present. Remapping it identically is a no-op,
            // so we overwrite rather than erroring — extending the HHDM
            // must be idempotent.
            leaf.set(frame, PageTableFlags::KERNEL_HHDM);
            crate::arch::x86_64::smp::shootdown_kernel_page(page.start_address().as_u64());
            phys = match phys.as_u64().checked_add(PAGE_SIZE) {
                Some(next) => PhysAddr::new_truncate(next),
                None => break,
            };
        }
        Ok(())
    }

    /// Walk the four-level table for `page`, creating missing intermediate
    /// tables on the way down, and return a `&mut` to the leaf PTE.
    ///
    /// `intermediate` is the flag set used for any PML4/PDPT/PD entry the
    /// walker has to materialise. The leaf entry is left untouched (the
    /// caller sets it); only the path to it is ensured to exist.
    #[allow(clippy::mut_from_ref)]
    fn walk_or_create(
        &self,
        page: Page,
        intermediate: PageTableFlags,
    ) -> Result<&mut PageTableEntry, MapError> {
        // SAFETY: we hold the only `&mut` chain into this address space for
        // the duration of the walk. No other code mutates the kernel's PML4
        // concurrently here; the paging subsystem serialises topology
        // changes at a higher layer (the process's address-space lock).
        let p4 = unsafe { self.p4_mut() };
        let p3 = Self::next_level_or_create(p4, p4_index(page), intermediate)?;
        let p2 = Self::next_level_or_create(p3, p3_index(page), intermediate)?;
        let p1 = Self::next_level_or_create(p2, p2_index(page), intermediate)?;
        Ok(p1.entry_mut(p1_index(page)))
    }

    /// Given a parent table and an index into it, return a `&mut` to the
    /// child table, allocating and linking a fresh frame if the entry is
    /// not present.
    ///
    /// If the entry is already a huge-page entry (`HUGE_PAGE` set), the
    /// caller's `page` is already covered by a large mapping and we refuse
    /// to split it — returning `AlreadyMapped` so the caller does not
    /// silently clobber a 2 MiB / 1 GiB mapping with a 4 KiB one.
    fn next_level_or_create(
        parent: &mut PageTable,
        index: PageTableIndex,
        intermediate: PageTableFlags,
    ) -> Result<&mut PageTable, MapError> {
        let entry = parent.entry(index);
        if entry.is_huge() {
            // A huge page already covers this range; do not split it.
            return Err(MapError::AlreadyMapped);
        }
        if !entry.is_present() {
            let frame = alloc_frame().ok_or(MapError::OutOfMemory)?;
            zero_frame(&frame);
            parent.entry_mut(index).set(frame, intermediate);
            // SAFETY: we just linked `frame` into `parent` and zeroed it via
            // the HHDM; the new child table is reachable and has no aliasing
            // `&mut` because we created it fresh this call.
            return Ok(unsafe { frame_as_table_mut(frame) });
        }
        let frame = entry.frame().ok_or(MapError::OutOfMemory)?; // present but no frame: corrupt PTE
                                                                 // SAFETY: the entry is present and points at a valid child table; we
                                                                 // hold the unique `&mut` chain down from the PML4 so no aliasing.
        Ok(unsafe { frame_as_table_mut(frame) })
    }

    // -- unmapping ---------------------------------------------------------

    /// Unmap a single page, clearing its leaf PTE.
    ///
    /// Returns the physical frame the page was mapped to, or
    /// `Err(NotMapped)` if no leaf entry was present. The leaf PTE is
    /// cleared with a volatile write and the TLB entry invalidated; the
    /// frame is *not* freed (the caller owns it and may remap or return it
    /// to the allocator). Intermediate tables are left in place even if
    /// they become empty — freeing them is [`destroy`](Self::destroy)'s job,
    /// not `unmap`'s, because checking "is this table now empty?" on every
    /// unmap would cost a 512-entry scan.
    pub fn unmap(&self, page: Page) -> Result<PhysFrame, UnmapError> {
        // SAFETY: read-only walk; we take a `&mut` only at the leaf for the
        // clear(). No concurrent mutator of this address space is expected
        // (the caller holds the space lock).
        let leaf = unsafe { self.walk_mut(page) }.ok_or(UnmapError::NotMapped)?;
        if !leaf.is_present() {
            return Err(UnmapError::NotMapped);
        }
        let old_flags = leaf.flags();
        let frame = leaf.clear();
        if old_flags.contains(PageTableFlags::USER) {
            crate::arch::x86_64::smp::shootdown_page(self.cr3(), page.start_address().as_u64());
        } else {
            crate::arch::x86_64::smp::shootdown_kernel_page(page.start_address().as_u64());
        }
        // `clear()` always returns Some when the entry was present and had a
        // non-zero address; frame() returns None only for an empty entry,
        // which we just ruled out. Fall back to frame 0 defensively.
        Ok(frame.unwrap_or_else(|| PhysFrame::containing_addr(PhysAddr::zero())))
    }

    // -- translation -------------------------------------------------------

    /// Translate a virtual page to the physical frame it maps to, together
    /// with the leaf entry's flags.
    ///
    /// Walks the four-level table without allocating. Returns `None` if any
    /// level is not present. Huge pages are handled: a `HUGE_PAGE` entry at
    /// PDE or PDPTE level resolves immediately with the physical frame that
    /// covers `page` (the address bits in a huge entry point at the base of
    /// the large page, which contains `page`).
    pub fn translate(&self, page: Page) -> Option<(PhysFrame, PageTableFlags)> {
        // SAFETY: read-only walk; no `&mut` is fabricated, so aliasing with
        // a concurrent mutator is benign (a torn read at worst, which the
        // caller can retry).
        let p4 = unsafe { self.p4() };
        let p4e = p4.entry(p4_index(page));
        if !p4e.is_present() {
            return None;
        }
        let p3 = unsafe { frame_as_table(p4e.frame()?) };
        let p3e = p3.entry(p3_index(page));
        if !p3e.is_present() {
            return None;
        }
        if p3e.is_huge() {
            return Some((huge_frame(p3e, page, PageTableLevel::Three), p3e.flags()));
        }
        let p2 = unsafe { frame_as_table(p3e.frame()?) };
        let p2e = p2.entry(p2_index(page));
        if !p2e.is_present() {
            return None;
        }
        if p2e.is_huge() {
            return Some((huge_frame(p2e, page, PageTableLevel::Two), p2e.flags()));
        }
        let p1 = unsafe { frame_as_table(p2e.frame()?) };
        let p1e = p1.entry(p1_index(page));
        if !p1e.is_present() {
            return None;
        }
        p1e.frame().map(|f| (f, p1e.flags()))
    }

    // -- fork / destroy ----------------------------------------------------

    /// Copy-on-write duplicate this address space for `fork(2)`.
    ///
    /// Present 4 KiB user mappings initially point at the same physical
    /// frames. Read-only pages stay read-only; writable pages have WRITABLE
    /// replaced with COPY_ON_WRITE in both spaces. The first writer receives
    /// a private copied frame from [`resolve_current_cow_fault`]. Kernel-half
    /// PML4 entries are shared verbatim, as for a freshly loaded ELF image.
    ///
    /// The operation is transactional.  If allocation or page-table creation
    /// fails, child mappings and reference increments are rolled back and all
    /// parent permissions are restored before the error is reported.
    pub fn fork(&self) -> Result<Self, MapError> {
        let _cow_guard = COW_FAULT_LOCK.lock();
        let child = Self::new_empty()?;
        copy_kernel_half(self, &child);

        let mut mapped = Vec::<ForkMapping>::new();
        let result = self.clone_user_mappings(&child, &mut mapped);
        if let Err(error) = result {
            rollback_fork(self, &child, &mapped);
            return Err(error);
        }

        ::log::debug!(
            "xenith.mm.virtual: COW-forked {} user pages into PML4 {:?}",
            mapped.len(),
            child.p4_frame()
        );
        Ok(child)
    }

    fn clone_user_mappings(
        &self,
        child: &Self,
        mapped: &mut Vec<ForkMapping>,
    ) -> Result<(), MapError> {
        // SAFETY: this is a read-only walk of the parent's live hierarchy.
        let p4 = unsafe { self.p4() };
        for (p4_index, p4e) in p4.iter().take(ENTRIES_PER_TABLE / 2) {
            if !p4e.is_present() {
                continue;
            }
            if p4e.is_huge() {
                return Err(MapError::HugePageUnsupported);
            }
            // SAFETY: a present, non-huge PML4 entry points to a PDPT.
            let p3 = unsafe { frame_as_table(p4e.frame().ok_or(MapError::CorruptPageTable)?) };
            for (p3_index, p3e) in p3.iter() {
                if !p3e.is_present() {
                    continue;
                }
                if p3e.is_huge() {
                    return Err(MapError::HugePageUnsupported);
                }
                // SAFETY: a present, non-huge PDPT entry points to a PD.
                let p2 = unsafe { frame_as_table(p3e.frame().ok_or(MapError::CorruptPageTable)?) };
                for (p2_index, p2e) in p2.iter() {
                    if !p2e.is_present() {
                        continue;
                    }
                    if p2e.is_huge() {
                        return Err(MapError::HugePageUnsupported);
                    }
                    // SAFETY: a present, non-huge PD entry points to a PT.
                    let p1 = unsafe {
                        frame_as_table_mut(p2e.frame().ok_or(MapError::CorruptPageTable)?)
                    };
                    for raw_p1 in 0..ENTRIES_PER_TABLE {
                        let p1_index = PageTableIndex::new(raw_p1 as u16)
                            .expect("leaf page-table index is in range");
                        let p1e = p1.entry(p1_index);
                        if !p1e.is_present() {
                            continue;
                        }
                        if !p1e.flags().contains(PageTableFlags::USER) {
                            return Err(MapError::CorruptPageTable);
                        }
                        mapped.try_reserve(1).map_err(|_| MapError::OutOfMemory)?;
                        let source = p1e.frame().ok_or(MapError::CorruptPageTable)?;
                        let page = page_from_indices(p4_index, p3_index, p2_index, p1_index);
                        let original_flags = p1e.flags();
                        let shared_flags = cow_shared_flags(original_flags);
                        retain_shared_user_frame(source)?;
                        if let Err(error) = child.map_user(page, source, shared_flags) {
                            let _ = release_user_frame(source);
                            return Err(error);
                        }
                        let parent_flags =
                            (shared_flags != original_flags).then_some(original_flags);
                        if parent_flags.is_some() {
                            p1.entry_mut(p1_index).set(source, shared_flags);
                            // SAFETY: `page` is canonical and currently mapped;
                            // invalidating an unrelated active CR3 is harmless,
                            // while the normal fork path flushes the parent now.
                            crate::arch::x86_64::smp::shootdown_page(
                                self.cr3(),
                                page.start_address().as_u64(),
                            );
                        }
                        mapped.push(ForkMapping {
                            page,
                            frame: source,
                            parent_flags,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Resolve a write fault against a COPY_ON_WRITE leaf in this address
    /// space. Returns `Ok(false)` when the mapping is not a COW candidate.
    pub fn resolve_cow_fault(&self, page: Page) -> Result<bool, MapError> {
        let _fault_guard = COW_FAULT_LOCK.lock();
        // SAFETY: the faulting CPU is the only mutator of its current leaf;
        // COW_FAULT_LOCK excludes simultaneous shared-frame splits.
        let Some(leaf) = (unsafe { self.walk_mut(page) }) else {
            return Ok(false);
        };
        let flags = leaf.flags();
        if !flags.contains(PageTableFlags::PRESENT | PageTableFlags::USER)
            || !flags.contains(PageTableFlags::COPY_ON_WRITE)
            || flags.contains(PageTableFlags::WRITABLE)
        {
            return Ok(false);
        }
        let source = leaf.frame().ok_or(MapError::CorruptPageTable)?;
        let mut writable = flags;
        writable.remove(PageTableFlags::COPY_ON_WRITE);
        writable.insert(PageTableFlags::WRITABLE);

        if shared_user_frame(source) {
            let destination = alloc_frame().ok_or(MapError::OutOfMemory)?;
            copy_frame(source, destination);
            leaf.set(destination, writable);
            if release_user_frame(source) {
                // A recorded shared frame cannot become wholly unowned while
                // this PTE has just moved from it.
                leaf.set(source, flags);
                free_frame(destination);
                return Err(MapError::CorruptPageTable);
            }
        } else {
            // Another process already split or exited, leaving this mapping
            // as the sole owner; permission restoration needs no copy.
            leaf.set(source, writable);
        }
        // SAFETY: the leaf has changed and `page` is a canonical page start.
        crate::arch::x86_64::smp::shootdown_page(self.cr3(), page.start_address().as_u64());
        Ok(true)
    }

    /// Tear down the address space, freeing every page-table frame below
    /// the PML4 and then the PML4 itself.
    ///
    /// Walks the PML4, PDPT, and PD levels freeing any present, non-huge
    /// child tables. Leaf PT frames are freed when their parent PD entry is
    /// freed (the PT is the child of the PD). The frame each entry points
    /// at is returned to the allocator via [`free_frame`].
    ///
    /// **Does not** unmap or free the pages the leaf entries point at —
    /// those are owned frames whose lifecycle is the user allocator's
    /// responsibility, not the page-table allocator's. Only the table
    /// *structure* (PML4/PDPT/PD/PT frames) is reclaimed here.
    ///
    /// # Safety
    ///
    /// The caller must guarantee `self` is not the currently-loaded address
    /// space (switch away first) and that no CPU is concurrently walking
    /// these tables. After this returns, `self` must not be used.
    pub unsafe fn destroy(&self) {
        // SAFETY: caller guarantees no concurrent walker and that `self` is
        // not loaded on any CPU. We hold the unique path down the tables.
        let p4 = unsafe { self.p4() };
        for (_, p4e) in p4.iter() {
            if !p4e.is_present() || p4e.is_huge() {
                continue;
            }
            let p4_child = p4e
                .frame()
                .unwrap_or_else(|| PhysFrame::containing_addr(PhysAddr::zero()));
            // SAFETY: p4_child is a present, non-huge PML4 entry, so it
            // points at a valid PDPT frame reachable through the HHDM.
            let p3 = unsafe { frame_as_table(p4_child) };
            for (_, p3e) in p3.iter() {
                if !p3e.is_present() || p3e.is_huge() {
                    continue;
                }
                let p3_child = p3e
                    .frame()
                    .unwrap_or_else(|| PhysFrame::containing_addr(PhysAddr::zero()));
                // SAFETY: present, non-huge PDPT entry -> valid PD frame.
                let p2 = unsafe { frame_as_table(p3_child) };
                for (_, p2e) in p2.iter() {
                    if !p2e.is_present() || p2e.is_huge() {
                        continue;
                    }
                    // The PD entry points at a leaf PT frame; free it.
                    let pt = p2e
                        .frame()
                        .unwrap_or_else(|| PhysFrame::containing_addr(PhysAddr::zero()));
                    free_frame(pt);
                }
                // All PTs under this PDPT entry are freed; free the PD.
                free_frame(p3_child);
            }
            // All PDs/PDPTs under this PML4 entry are freed; free the PDPT.
            free_frame(p4_child);
        }
        // Every sub-table freed; free the PML4 root last.
        free_frame(self.p4_frame);
        ::log::trace!(
            "xenith.mm.virtual: destroyed address space {:?}",
            self.p4_frame
        );
    }

    // -- walk helpers ------------------------------------------------------

    /// Walk to the leaf PTE for `page` without allocating, returning a
    /// `&mut` to it, or `None` if any intermediate level is not present.
    ///
    /// # Safety
    ///
    /// Caller must ensure no conflicting `&mut` to the table chain is live.
    #[inline]
    #[allow(clippy::mut_from_ref)]
    unsafe fn walk_mut(&self, page: Page) -> Option<&mut PageTableEntry> {
        // SAFETY: same aliasing contract as the other walk helpers; the
        // caller guarantees uniqueness.
        let p4 = unsafe { self.p4_mut() };
        let p4e = p4.entry(p4_index(page));
        if !p4e.is_present() {
            return None;
        }
        let p3 = unsafe { frame_as_table_mut(p4e.frame()?) };
        let p3e = p3.entry(p3_index(page));
        if !p3e.is_present() || p3e.is_huge() {
            return None;
        }
        let p2 = unsafe { frame_as_table_mut(p3e.frame()?) };
        let p2e = p2.entry(p2_index(page));
        if !p2e.is_present() || p2e.is_huge() {
            return None;
        }
        let p1 = unsafe { frame_as_table_mut(p2e.frame()?) };
        Some(p1.entry_mut(p1_index(page)))
    }
}

// ---------------------------------------------------------------------------
// Free functions: index extraction, frame<->table casts, huge-page decode
// ---------------------------------------------------------------------------

/// Extract the PML4 (level-4) index from a page's virtual address.
///
/// Bits 39..=47 of the virtual address select the PML4 entry. We shift right
/// 39 and mask to 9 bits, then wrap in the [`PageTableIndex`] newtype so the
/// index cannot be confused with a raw integer.
#[inline]
fn p4_index(page: Page) -> PageTableIndex {
    PageTableIndex::new_truncate(((page.start_address().as_u64() >> 39) & 0x1FF) as u16)
}

/// Extract the PDPT (level-3) index: bits 30..=38.
#[inline]
fn p3_index(page: Page) -> PageTableIndex {
    PageTableIndex::new_truncate(((page.start_address().as_u64() >> 30) & 0x1FF) as u16)
}

/// Extract the PD (level-2) index: bits 21..=29.
#[inline]
fn p2_index(page: Page) -> PageTableIndex {
    PageTableIndex::new_truncate(((page.start_address().as_u64() >> 21) & 0x1FF) as u16)
}

/// Extract the PT (level-1) index: bits 12..=20.
#[inline]
fn p1_index(page: Page) -> PageTableIndex {
    PageTableIndex::new_truncate(((page.start_address().as_u64() >> 12) & 0x1FF) as u16)
}

/// Overlay a `&PageTable` onto a physical frame reached through the HHDM.
///
/// # Safety
///
/// `frame` must point at a present page-table frame (a PML4/PDPT/PD/PT) that
/// is mapped writable through the HHDM, and the caller must ensure no
/// conflicting `&mut` to the same frame is live.
#[inline]
unsafe fn frame_as_table(frame: PhysFrame) -> &'static PageTable {
    // SAFETY: `phys_to_virt` yields the HHDM virtual address of the frame,
    // which Limine mapped writable. `PageTable` is `repr(C, align(4096))`
    // and exactly 4096 bytes, matching a frame. The caller guarantees no
    // conflicting mutable aliasing.
    let va = phys_to_virt(frame.start_address());
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
    // SAFETY: see `frame_as_table`; the mutable variant additionally
    // requires exclusive access, which the caller guarantees.
    let va = phys_to_virt(frame.start_address());
    unsafe { &mut *(va.as_u64() as *mut PageTable) }
}

/// Decode the physical frame for a huge-page entry that covers `page`.
///
/// A huge PTE's address field points at the *base* of the large page (2 MiB
/// for level 2, 1 GiB for level 3), not at the 4 KiB frame for `page`. The
/// frame that `page` maps to is the base frame plus the offset of `page`
/// within the large page, in 4 KiB units. We compute that by aligning the
/// huge entry's address down to the large-page boundary and adding the
/// page's intra-large-page frame offset.
fn huge_frame(entry: PageTableEntry, page: Page, level: PageTableLevel) -> PhysFrame {
    let base = entry.bits() & ADDR_MASK;
    // The size of the large page in bytes: 1 GiB at level 3, 2 MiB at level 2.
    let large_size: u64 = match level {
        PageTableLevel::Three => 1 << 30,
        PageTableLevel::Two => 1 << 21,
        _ => PAGE_SIZE,
    };
    // Mask off the intra-large-page offset bits to get the base address,
    // then add back the page-aligned intra-large-page offset.
    let base_aligned = base & !(large_size - 1);
    let intra = page.start_address().as_u64() & (large_size - 1);
    PhysFrame::containing_addr(PhysAddr::new_truncate(base_aligned + intra))
}

/// Copy the shared kernel half of `parent` into a fresh child PML4.
fn copy_kernel_half(parent: &AddressSpace, child: &AddressSpace) {
    // SAFETY: both handles name live PML4 frames.  The child is fresh and
    // uniquely owned by the in-progress fork, while the parent is read-only.
    let source = unsafe { parent.p4() };
    let destination = unsafe { child.p4_mut() };
    for raw in (ENTRIES_PER_TABLE / 2)..ENTRIES_PER_TABLE {
        let index = PageTableIndex::new(raw as u16).expect("PML4 index is in range");
        *destination.entry_mut(index) = source.entry(index);
    }
}

fn clear_kernel_half(space: &AddressSpace) {
    // SAFETY: used only while rolling back an unpublished child hierarchy.
    let table = unsafe { space.p4_mut() };
    for raw in (ENTRIES_PER_TABLE / 2)..ENTRIES_PER_TABLE {
        let index = PageTableIndex::new(raw as u16).expect("PML4 index is in range");
        *table.entry_mut(index) = PageTableEntry::empty();
    }
}

fn copy_frame(source: PhysFrame, destination: PhysFrame) {
    let source = phys_to_virt(source.start_address()).as_u64() as *const u8;
    let destination = phys_to_virt(destination.start_address()).as_u64() as *mut u8;
    // SAFETY: fork allocated `destination` exclusively and both HHDM aliases
    // cover exactly one complete physical frame.
    unsafe { ptr::copy_nonoverlapping(source, destination, PAGE_SIZE as usize) };
}

fn cow_shared_flags(mut flags: PageTableFlags) -> PageTableFlags {
    if flags.contains(PageTableFlags::WRITABLE) {
        flags.remove(PageTableFlags::WRITABLE);
        flags.insert(PageTableFlags::COPY_ON_WRITE);
    }
    flags
}

fn retain_shared_user_frame(frame: PhysFrame) -> Result<(), MapError> {
    let mut frames = SHARED_USER_FRAMES.lock();
    if let Some(shared) = frames.iter_mut().find(|shared| shared.frame == frame) {
        shared.references = shared
            .references
            .checked_add(1)
            .ok_or(MapError::CorruptPageTable)?;
        return Ok(());
    }
    frames.try_reserve(1).map_err(|_| MapError::OutOfMemory)?;
    frames.push(SharedUserFrame {
        frame,
        references: 2,
    });
    Ok(())
}

fn shared_user_frame(frame: PhysFrame) -> bool {
    SHARED_USER_FRAMES
        .lock()
        .iter()
        .any(|shared| shared.frame == frame)
}

/// Release one user mapping and report whether its frame is now wholly
/// unreferenced and should be returned to the physical allocator.
#[must_use]
pub fn release_user_frame(frame: PhysFrame) -> bool {
    let mut frames = SHARED_USER_FRAMES.lock();
    let Some(index) = frames.iter().position(|shared| shared.frame == frame) else {
        return true;
    };
    if frames[index].references > 2 {
        frames[index].references -= 1;
    } else {
        frames.swap_remove(index);
    }
    false
}

fn page_from_indices(
    p4: PageTableIndex,
    p3: PageTableIndex,
    p2: PageTableIndex,
    p1: PageTableIndex,
) -> Page {
    let address = (u64::from(p4.value()) << 39)
        | (u64::from(p3.value()) << 30)
        | (u64::from(p2.value()) << 21)
        | (u64::from(p1.value()) << 12);
    Page::containing_addr(VirtAddr::new_truncate(address))
}

#[derive(Clone, Copy)]
struct ForkMapping {
    page: Page,
    frame: PhysFrame,
    parent_flags: Option<PageTableFlags>,
}

fn rollback_fork(parent: &AddressSpace, child: &AddressSpace, mapped: &[ForkMapping]) {
    for mapping in mapped.iter().rev().copied() {
        let _ = child.unmap(mapping.page);
        let _ = release_user_frame(mapping.frame);
        if let Some(flags) = mapping.parent_flags {
            // SAFETY: the unpublished rollback owns the mutation path and the
            // parent mapping remains present throughout the failed fork.
            if let Some(leaf) = unsafe { parent.walk_mut(mapping.page) } {
                leaf.set(mapping.frame, flags);
                // SAFETY: restore the active parent's cached permission.
                crate::arch::x86_64::smp::shootdown_page(
                    parent.cr3(),
                    mapping.page.start_address().as_u64(),
                );
            }
        }
    }
    clear_kernel_half(child);
    // SAFETY: the child was never published or activated and all owned leaf
    // references have already been detached and released.
    unsafe { child.destroy() };
}

/// Zero a freshly allocated page-table frame through the HHDM.
///
/// A page-table frame must be entirely zero (every entry not-present) before
/// it is linked into a parent entry, otherwise the MMU would treat stale
/// bytes as mappings. We zero via volatile writes so the stores are not
/// elided or reordered away from the hardware's perspective.
fn zero_frame(frame: &PhysFrame) {
    let va = phys_to_virt(frame.start_address());
    // SAFETY: `va` is the HHDM address of a freshly allocated, writable 4
    // KiB frame. We write exactly PAGE_SIZE u64s (4096 bytes), which fills
    // the frame exactly. The frame is not aliased — the allocator handed it
    // out exclusively — so the volatile writes are sound.
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
    use super::*;

    #[test]
    fn constants_are_canonical_boundaries() {
        // HIGHER_HALF is the canonical upper-half boundary: bit 47 set, all
        // higher bits sign-extended to 1.
        assert_eq!(HIGHER_HALF, 0xFFFF_8000_0000_0000);
        assert!(VirtAddr::is_canonical(HIGHER_HALF));
        // USER_MAX is the top of the low canonical half.
        assert_eq!(USER_MAX, 0x0000_7FFF_FFFF_FFFF);
        assert!(VirtAddr::is_canonical(USER_MAX));
        // The two are adjacent with the non-canonical hole between them.
        assert!(!VirtAddr::is_canonical(USER_MAX + 1));
    }

    #[test]
    fn hhdm_offset_defaults_to_higher_half() {
        // Before init_hhdm runs, phys_to_virt falls back to HIGHER_HALF.
        // We cannot call init_hhdm here because it is global and other tests
        // might run first; instead check the fallback directly. The atomic
        // may have been set by another test in the same process, so only
        // assert the fallback semantics when it is still zero.
        if HHDM_OFFSET.load(Ordering::Relaxed) == 0 {
            assert_eq!(hhdm_offset(), HIGHER_HALF);
        }
    }

    #[test]
    fn phys_to_virt_round_trips() {
        // Only valid if the HHDM has been set; otherwise virt_to_phys uses
        // the HIGHER_HALF fallback, which still round-trips for addresses
        // in the HHDM region.
        let off = hhdm_offset();
        let phys = PhysAddr::new_truncate(0x1234_5000);
        let virt = phys_to_virt(phys);
        assert_eq!(virt.as_u64(), off + 0x1234_5000);
        assert_eq!(virt_to_phys(virt), Some(phys));
        // A low-half address is not in the HHDM region.
        let low = VirtAddr::new(0x1000).unwrap();
        assert_eq!(virt_to_phys(low), None);
    }

    #[test]
    fn pte_empty_is_not_present() {
        let e = PageTableEntry::empty();
        assert!(!e.is_present());
        assert!(!e.is_huge());
        assert!(e.frame().is_none());
        assert_eq!(e.bits(), 0);
    }

    #[test]
    fn pte_new_packs_address_and_flags() {
        let frame = PhysFrame::containing_addr(PhysAddr::new_truncate(0x4000_5000));
        let e = PageTableEntry::new(frame, PageTableFlags::USER_DATA);
        assert!(e.is_present());
        assert!(e.flags().contains(PageTableFlags::USER));
        assert!(e.flags().contains(PageTableFlags::NO_EXECUTE));
        // The address field is the frame base, 4 KiB aligned.
        assert_eq!(e.frame().unwrap().start_address().as_u64(), 0x4000_5000);
    }

    #[test]
    fn pte_set_and_clear() {
        let mut e = PageTableEntry::empty();
        let frame = PhysFrame::containing_addr(PhysAddr::new_truncate(0x8000));
        e.set(frame, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
        assert!(e.is_present());
        assert_eq!(e.frame().unwrap().start_address().as_u64(), 0x8000);
        let prev = e.clear();
        assert!(!e.is_present());
        assert_eq!(prev.unwrap().start_address().as_u64(), 0x8000);
    }

    #[test]
    fn index_extraction_splits_a_virtual_address() {
        // A user address with all index fields non-zero so every extractor
        // returns something distinguishable: 0x0000_0123_4567_789A.
        let va = VirtAddr::new(0x0000_0123_4567_789A).unwrap();
        let page = Page::containing_addr(va);
        // P4 = bits 39..47 = 0x024 (0x0000_0123_4567_789A >> 39 = 0x24).
        assert_eq!(
            p4_index(page).value(),
            u16::try_from((0x0000_0123_4567_789Au64 >> 39) & 0x1FF).unwrap()
        );
        assert_eq!(
            p3_index(page).value(),
            u16::try_from((0x0000_0123_4567_789Au64 >> 30) & 0x1FF).unwrap()
        );
        assert_eq!(
            p2_index(page).value(),
            u16::try_from((0x0000_0123_4567_789Au64 >> 21) & 0x1FF).unwrap()
        );
        assert_eq!(
            p1_index(page).value(),
            u16::try_from((0x0000_0123_4567_789Au64 >> 12) & 0x1FF).unwrap()
        );
        // Every index is in 0..=511.
        for v in [
            p4_index(page).value(),
            p3_index(page).value(),
            p2_index(page).value(),
            p1_index(page).value(),
        ] {
            assert!(v <= 511);
        }
    }

    #[test]
    fn page_table_zeroed_is_all_empty() {
        let t = PageTable::zeroed();
        for i in 0..ENTRIES_PER_TABLE {
            let idx = PageTableIndex::new(i as u16).unwrap();
            assert!(!t.entry(idx).is_present());
        }
    }

    #[test]
    fn user_data_flags_have_expected_bits() {
        let f = PageTableFlags::USER_DATA;
        assert!(f.contains(PageTableFlags::PRESENT));
        assert!(f.contains(PageTableFlags::WRITABLE));
        assert!(f.contains(PageTableFlags::USER));
        assert!(f.contains(PageTableFlags::NO_EXECUTE));
        // Kernel pages must not carry USER.
        assert!(!PageTableFlags::KERNEL_HHDM.contains(PageTableFlags::USER));
        assert!(PageTableFlags::KERNEL_HHDM.contains(PageTableFlags::GLOBAL));
    }

    #[test]
    fn cow_flags_and_reference_lifecycle_preserve_the_last_owner() {
        let writable = cow_shared_flags(PageTableFlags::USER_DATA);
        assert!(writable.contains(PageTableFlags::COPY_ON_WRITE));
        assert!(!writable.contains(PageTableFlags::WRITABLE));
        let read_only = PageTableFlags::PRESENT | PageTableFlags::USER;
        assert_eq!(cow_shared_flags(read_only), read_only);

        let frame = PhysFrame::containing_addr(PhysAddr::new_truncate(0x7FFE_0000));
        assert!(release_user_frame(frame));
        retain_shared_user_frame(frame).expect("first shared reference");
        retain_shared_user_frame(frame).expect("third shared reference");
        assert!(shared_user_frame(frame));
        assert!(!release_user_frame(frame));
        assert!(shared_user_frame(frame));
        assert!(!release_user_frame(frame));
        assert!(!shared_user_frame(frame));
        assert!(release_user_frame(frame));
    }

    #[test]
    fn huge_frame_decodes_2m_base_plus_offset() {
        // A 2 MiB huge entry at level 2 pointing at base 0x4000_0000.
        let base = 0x4000_0000u64;
        let entry = PageTableEntry::new(
            PhysFrame::containing_addr(PhysAddr::new_truncate(base)),
            PageTableFlags::PRESENT | PageTableFlags::HUGE_PAGE,
        );
        // A page 0x4000_5000 is 5 * 4 KiB into the 2 MiB large page.
        let page = Page::containing_addr(VirtAddr::new(0x4000_5000).unwrap());
        let frame = huge_frame(entry, page, PageTableLevel::Two);
        assert_eq!(frame.start_address().as_u64(), 0x4000_5000);
    }

    #[test]
    fn map_error_variants_are_distinct() {
        // The three variants are pairwise unequal so callers can match
        // exhaustively without two failures collapsing into the same arm.
        use MapError as E;
        assert_ne!(E::OutOfRange, E::OutOfMemory);
        assert_ne!(E::OutOfRange, E::AlreadyMapped);
        assert_ne!(E::OutOfMemory, E::AlreadyMapped);
    }
}
