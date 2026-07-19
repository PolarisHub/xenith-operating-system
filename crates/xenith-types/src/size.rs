//! Page-size marker types for the Xenith memory subsystem.
//!
//! The kernel deals with three hardware-supported page sizes on x86_64:
//!
//! * 4 KiB pages (the default, used for all leaf page-table entries).
//! * 2 MiB "large" pages (PDE-level, huge-page bit set).
//! * 1 GiB "huge" pages (PDPTE-level, requires PDPE1GB CPUID bit).
//!
//! Rather than passing a `u64` byte count around and hoping nobody confuses
//! it with a frame number, we encode the page size in the *type* of a marker
//! struct. Generic paging code is parameterised over `S: PageSize`, which
//! lets the compiler prove at compile time that a 4 KiB frame is never
//! accidentally mapped with a 2 MiB entry.
//!
//! The [`PageSize`] trait exposes the size as a `const` so it can be used in
//! `const` contexts (array sizes, compile-time constants, alignment math).

/// A page-size marker: a type whose only purpose is to carry a compile-time
/// `SIZE` constant describing how large a page of that kind is.
///
/// All implementors are zero-sized unit structs, so they cost nothing at
/// runtime. The trait is sealed in practice because it is only implemented
/// here, on [`Size4KiB`], [`Size2MiB`], and [`Size1GiB`].
///
/// # Safety contract for implementors
///
/// `SIZE` must be a power of two and must correspond to a page size the
/// hardware actually supports in the page-table level the implementor is
/// used for. The constants below satisfy this by construction.
pub trait PageSize: Copy + Clone + Eq + PartialEq + Ord + PartialOrd {
    /// The page size in bytes. Always a power of two.
    const SIZE: u64;

    /// The number of bits to shift a byte address right to obtain the
    /// page/frame number. Equivalent to `SIZE.trailing_zeros()` but precomputed
    /// for use in `const` contexts without intrinsics.
    const SIZE_BITS: u32;

    /// A short human-readable name, useful in log output and panic messages.
    const NAME: &'static str;
}

/// Marker for a 4 KiB page — the standard leaf page size on x86_64.
///
/// 4 KiB pages are mapped by PTEs at page-table level 1 and are the only
/// size the MMU will ever produce a page-fault for at that level. All
/// user-space allocations are ultimately backed by 4 KiB pages.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Size4KiB;

impl PageSize for Size4KiB {
    const SIZE: u64 = 4096;
    // log2(4096) = 12.
    const SIZE_BITS: u32 = 12;
    const NAME: &'static str = "4KiB";
}

/// Marker for a 2 MiB "large" page. Mapped by a PDE with the huge-page bit
/// set; the CPU skips the level-1 table entirely for these entries.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Size2MiB;

impl PageSize for Size2MiB {
    const SIZE: u64 = 2 * 1024 * 1024;
    // log2(2 MiB) = 21.
    const SIZE_BITS: u32 = 21;
    const NAME: &'static str = "2MiB";
}

/// Marker for a 1 GiB "huge" page. Requires the PDPE1GB CPUID feature.
/// Mapped by a PDPTE with the huge-page bit set; the CPU skips both the
/// level-2 and level-1 tables.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Size1GiB;

impl PageSize for Size1GiB {
    const SIZE: u64 = 1024 * 1024 * 1024;
    // log2(1 GiB) = 30.
    const SIZE_BITS: u32 = 30;
    const NAME: &'static str = "1GiB";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size4kib_constants() {
        assert_eq!(Size4KiB::SIZE, 4096);
        assert_eq!(Size4KiB::SIZE_BITS, 12);
        assert_eq!(Size4KiB::NAME, "4KiB");
        // SIZE must be a power of two.
        assert_eq!(Size4KiB::SIZE.count_ones(), 1);
    }

    #[test]
    fn size2mib_constants() {
        assert_eq!(Size2MiB::SIZE, 2 * 1024 * 1024);
        assert_eq!(Size2MiB::SIZE_BITS, 21);
        assert_eq!(Size2MiB::NAME, "2MiB");
        assert_eq!(Size2MiB::SIZE.count_ones(), 1);
        // 2 MiB is exactly 512 4 KiB pages.
        assert_eq!(Size2MiB::SIZE / Size4KiB::SIZE, 512);
    }

    #[test]
    fn size1gib_constants() {
        assert_eq!(Size1GiB::SIZE, 1024 * 1024 * 1024);
        assert_eq!(Size1GiB::SIZE_BITS, 30);
        assert_eq!(Size1GiB::NAME, "1GiB");
        assert_eq!(Size1GiB::SIZE.count_ones(), 1);
        // 1 GiB is exactly 512 2 MiB pages and 262144 4 KiB pages.
        assert_eq!(Size1GiB::SIZE / Size2MiB::SIZE, 512);
        assert_eq!(Size1GiB::SIZE / Size4KiB::SIZE, 262_144);
    }

    #[test]
    fn size_bits_agrees_with_size() {
        // For every page size, shifting 1u64 by SIZE_BITS must yield SIZE.
        assert_eq!(1u64 << Size4KiB::SIZE_BITS, Size4KiB::SIZE);
        assert_eq!(1u64 << Size2MiB::SIZE_BITS, Size2MiB::SIZE);
        assert_eq!(1u64 << Size1GiB::SIZE_BITS, Size1GiB::SIZE);
    }

    #[test]
    fn markers_are_zero_sized() {
        // The marker structs must be unit types — they carry no data.
        assert_eq!(core::mem::size_of::<Size4KiB>(), 0);
        assert_eq!(core::mem::size_of::<Size2MiB>(), 0);
        assert_eq!(core::mem::size_of::<Size1GiB>(), 0);
    }
}
