//! Memory region descriptors derived from the Limine memory map.
//!
//! The bootloader hands the kernel a memory map describing every physical
//! memory range it knows about and how that range may be used. The raw
//! Limine entries use small integer `kind` tags; this module wraps them in a
//! safe, strongly-typed [`RegionKind`] enum paired with a [`MemoryRegion`]
//! record carrying a physical start address and a byte length.
//!
//! The kernel page allocator consumes `MemoryRegion`s filtered to
//! [`RegionKind::Usable`] only; everything else is reserved and must not be
//! handed out for general allocation.

use core::fmt;

use xenith_types::PhysAddr;

/// The kind of a physical memory range, as reported by Limine.
///
/// The discriminant values match the integer tags the Limine protocol uses in
/// its memory map entries so that the conversion in
/// [`MemoryRegion::from_limine`](super::BootInfo) is a direct, lossless
/// mapping. Keeping them stable also lets code that needs to log the raw tag
/// round-trip through `as u32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum RegionKind {
    /// Memory the kernel and bootloader may freely use for allocation.
    ///
    /// Limine tag value `0`. This is the only kind the page allocator hands
    /// out; all other kinds are treated as unavailable.
    Usable = 0,

    /// Memory that must not be touched. This includes hardware-reserved
    /// ranges, non-RAM regions, and anything the firmware asked the OS to
    /// avoid.
    ///
    /// Limine tag value `1`.
    Reserved = 1,

    /// ACPI tables that can be reclaimed after the kernel has read and
    /// mapped them elsewhere. Safe to use for general allocation once the
    /// relevant tables have been copied out.
    ///
    /// Limine tag value `2`.
    AcpiReclaim = 2,

    /// ACPI non-volatile storage. Must be preserved across reboots; never
    /// reclaim for general allocation.
    ///
    /// Limine tag value `3`.
    AcpiNvs = 3,

    /// Memory that the firmware reported as defective. Never use.
    ///
    /// Limine tag value `4`.
    Bad = 4,

    /// Memory used by the bootloader itself that becomes reclaimable once the
    /// kernel is done with boot-time structures (e.g. the boot info, the
    /// memory map, modules). Reclaim it only after the boot info has been
    /// fully consumed.
    ///
    /// Limine tag value `5`.
    Bootloader = 5,

    /// Memory holding the kernel image and its modules. Reserved for the
    /// kernel's own use; not available to the general allocator.
    ///
    /// Limine tag value `6`.
    Kernel = 6,
}

impl RegionKind {
    /// Map a raw Limine memory-map `kind` tag to a [`RegionKind`].
    ///
    /// Unknown tag values — which should not occur with a conforming
    /// bootloader but are defensive against future revisions — collapse to
    /// [`RegionKind::Reserved`]. Treating an unknown range as reserved is the
    /// safe default: the allocator will never hand it out, so we never
    /// accidentally clobber a range the firmware cares about.
    pub const fn from_raw(kind: u32) -> Self {
        match kind {
            0 => Self::Usable,
            1 => Self::Reserved,
            2 => Self::AcpiReclaim,
            3 => Self::AcpiNvs,
            4 => Self::Bad,
            5 => Self::Bootloader,
            6 => Self::Kernel,
            // Defensive: any tag we do not recognize is treated as reserved
            // so the allocator skips it rather than handing out memory whose
            // purpose we do not understand.
            _ => Self::Reserved,
        }
    }

    /// Returns `true` if this region may be used for general page allocation.
    ///
    /// Only [`RegionKind::Usable`] qualifies. Bootloader-reclaimable memory
    /// is intentionally excluded here because it must not be freed until the
    /// boot info has been fully consumed; the page allocator can opt into
    /// reclaiming those ranges separately once it is safe to do so.
    #[inline]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Usable)
    }

    /// Returns `true` if this region must be preserved and never overwritten.
    ///
    /// NVS and bad memory fall into this category, as do reserved ranges.
    #[inline]
    pub const fn is_preserved(self) -> bool {
        matches!(self, Self::Reserved | Self::AcpiNvs | Self::Bad)
    }

    /// Returns the raw Limine tag value for this kind.
    #[inline]
    pub const fn as_raw(self) -> u32 {
        self as u32
    }
}

impl fmt::Display for RegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Usable => "usable",
            Self::Reserved => "reserved",
            Self::AcpiReclaim => "acpi-reclaimable",
            Self::AcpiNvs => "acpi-nvs",
            Self::Bad => "bad",
            Self::Bootloader => "bootloader-reclaimable",
            Self::Kernel => "kernel+modules",
        };
        f.write_str(name)
    }
}

/// A physical memory range described by a start address and a byte length.
///
/// This is the safe, owned-data counterpart to a raw `limine::MemmapEntry`.
/// It copies the base and length out of the boot info and resolves the kind
/// tag into a [`RegionKind`]. Copying is deliberate: the boot info memory map
/// lives in bootloader-reclaimable memory, so the kernel wants stable copies
/// it can hold onto after the boot structures are reclaimed.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryRegion {
    /// Physical address of the first byte of the region. Always
    /// page-aligned for regions reported by Limine.
    pub start: PhysAddr,
    /// Length of the region in bytes.
    pub len: u64,
    /// The role of this memory range.
    pub kind: RegionKind,
}

impl MemoryRegion {
    /// Construct a new memory region from a physical start address, a byte
    /// length, and a kind.
    ///
    /// `start` is stored as-is; callers are expected to pass an address that
    /// is already page-aligned (Limine guarantees this for its entries).
    #[inline]
    pub const fn new(start: PhysAddr, len: u64, kind: RegionKind) -> Self {
        Self { start, len, kind }
    }

    /// The physical address one past the last byte of this region.
    ///
    /// Returns `None` if the end address would overflow the 52-bit physical
    /// address space. For well-formed boot memory maps this never happens,
    /// but the checked API keeps callers honest if they synthesize regions.
    #[inline]
    pub fn end(&self) -> Option<PhysAddr> {
        // PhysAddr + u64 is supported via Add<u64>; the saturating check is
        // expressed through Option so a caller cannot silently wrap.
        let end = self.start.as_u64().checked_add(self.len)?;
        PhysAddr::new(end)
    }

    /// Returns `true` if `addr` lies within `[start, start + len)`.
    #[inline]
    pub fn contains(&self, addr: PhysAddr) -> bool {
        let start = self.start.as_u64();
        let a = addr.as_u64();
        a >= start && a.wrapping_sub(start) < self.len
    }

    /// Returns `true` if this region is usable for general allocation.
    #[inline]
    pub const fn is_usable(&self) -> bool {
        self.kind.is_usable()
    }

    /// Number of 4 KiB frames fully contained in this region.
    ///
    /// Partial trailing frames are not counted. Useful for sizing the page
    /// allocator against the usable memory map.
    #[inline]
    pub fn frame_count(&self) -> u64 {
        // Page size is 4096; align the base up and the end down to count only
        // whole frames. We operate on raw u64 to avoid needing the Page type
        // from xenith-types here, keeping this module leaf-like.
        const FRAME: u64 = 4096;
        let base = self.start.as_u64();
        let aligned_base = base.checked_add(FRAME - 1).map(|v| v & !(FRAME - 1));
        let Some(aligned_base) = aligned_base else {
            return 0;
        };
        let end = base.checked_add(self.len).unwrap_or(base);
        if aligned_base >= end {
            return 0;
        }
        let usable = end - aligned_base;
        usable / FRAME
    }
}

impl fmt::Debug for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryRegion")
            .field("start", &format_args!("0x{:016x}", self.start.as_u64()))
            .field("len", &format_args!("0x{:x}", self.len))
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[0x{:016x}+0x{:x}, {})",
            self.start.as_u64(),
            self.len,
            self.kind
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pa(n: u64) -> PhysAddr {
        PhysAddr::new_truncate(n)
    }

    #[test]
    fn kind_round_trip() {
        for raw in 0..=6u32 {
            let kind = RegionKind::from_raw(raw);
            assert_eq!(kind.as_raw(), raw);
        }
        // Unknown tags collapse to Reserved and stay safe.
        assert_eq!(RegionKind::from_raw(42), RegionKind::Reserved);
        assert!(!RegionKind::from_raw(42).is_usable());
    }

    #[test]
    fn usable_classification() {
        assert!(RegionKind::Usable.is_usable());
        assert!(!RegionKind::Bootloader.is_usable());
        assert!(!RegionKind::Kernel.is_usable());
        assert!(RegionKind::AcpiNvs.is_preserved());
        assert!(RegionKind::Bad.is_preserved());
        assert!(RegionKind::Reserved.is_preserved());
        assert!(!RegionKind::Usable.is_preserved());
    }

    #[test]
    fn region_contains() {
        let r = MemoryRegion::new(pa(0x1000), 0x3000, RegionKind::Usable);
        assert!(r.contains(pa(0x1000)));
        assert!(r.contains(pa(0x2500)));
        assert!(!r.contains(pa(0x4000)));
        assert!(!r.contains(pa(0)));
    }

    #[test]
    fn frame_count_counts_whole_frames() {
        // 0x1000..0x4000 = 0x3000 bytes = 3 frames
        let r = MemoryRegion::new(pa(0x1000), 0x3000, RegionKind::Usable);
        assert_eq!(r.frame_count(), 3);
        // Misaligned start: 0x1800..0x4000 aligns base up to 0x2000, giving
        // 0x2000 bytes = 2 frames.
        let r2 = MemoryRegion::new(pa(0x1800), 0x2800, RegionKind::Usable);
        assert_eq!(r2.frame_count(), 2);
        // Sub-frame region yields zero.
        let r3 = MemoryRegion::new(pa(0x1000), 0x100, RegionKind::Usable);
        assert_eq!(r3.frame_count(), 0);
    }

    #[test]
    fn end_address_check() {
        let r = MemoryRegion::new(pa(0x1000), 0x1000, RegionKind::Usable);
        assert_eq!(r.end().map(|a| a.as_u64()), Some(0x2000));
    }
}
