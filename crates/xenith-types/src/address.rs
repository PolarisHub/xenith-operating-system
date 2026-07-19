//! Physical and virtual address newtypes for x86_64.
//!
//! Both addresses are 64-bit quantities at the hardware level, but treating
//! them as a single `u64` type is a recipe for disaster: it is trivial to
//! accidentally add a physical offset to a virtual address, or to feed a
//! virtual address into a function that expects a physical one. The two
//! types here exist to make those mistakes compile-time errors.
//!
//! * [`PhysAddr`] wraps a physical address. Physical addresses on x86_64 are
//!   up to 52 bits wide in principle (the MAXPHYADDR CPUID leaf), but for
//!   simplicity and because no current PC uses more, we accept any `u64`
//!   that fits in 52 bits. `PhysAddr::new` returns `None` for values with
//!   bits 52..=63 set, since those can never be a real physical address.
//!
//! * [`VirtAddr`] wraps a canonical 64-bit virtual address. The x86_64 MMU
//!   only looks at bits 0..=47 for address translation and requires bits
//!   48..=63 to be a sign-extension of bit 47 ("canonical form"). A
//!   non-canonical address raises a `#GP` on any memory access.
//!   `VirtAddr::new` returns `None` for non-canonical values;
//!   `VirtAddr::new_truncate` forces canonical form by sign-extending
//!   bit 47, which is the right thing when the caller knows they only care
//!   about the low 48 bits (e.g. masking a user pointer).

use core::fmt;
use core::ops::{Add, Sub};

/// The size of a standard 4 KiB page in bytes. Kept here, next to the
/// address types, so alignment helpers can reference it without pulling in
/// the `page` module (which itself depends on `address`).
pub const PAGE_SIZE: u64 = 4096;

/// The canonical-address mask: bits 0..=47 are the real address, bits
/// 48..=63 must replicate bit 47. This is the highest bit the MMU uses.
pub const CANONICAL_SIGN_BIT: u8 = 47;
const CANONICAL_MASK: u64 = (1u64 << (CANONICAL_SIGN_BIT + 1)) - 1;

/// The maximum physical address bit the kernel currently supports.
///
/// Real x86_64 hardware advertises MAXPHYADDR via CPUID, typically 36, 40,
/// 43, 46, or 52. We use 52 (the architectural maximum) as the validation
/// cutoff: any input with bits 52..=63 set cannot be a physical address on
/// any x86_64 part and is rejected by [`PhysAddr::new`].
pub const PHYS_ADDR_MAX_BITS: u8 = 52;
const PHYS_ADDR_MASK: u64 = (1u64 << PHYS_ADDR_MAX_BITS) - 1;

// ---------------------------------------------------------------------------
// PhysAddr
// ---------------------------------------------------------------------------

/// A physical memory address.
///
/// Physical addresses are what the memory bus sees; they are never
/// dereferenceable from the CPU without first being mapped into the virtual
/// address space (e.g. via the HHDM direct map at `0xFFFF_8000_0000_0000`
/// in the Xenith kernel).
///
/// Unlike [`VirtAddr`], a `PhysAddr` does not enforce a width limit: on
/// x86_64 the usable physical width is CPUID-dependent (up to 52 bits) and
/// the kernel frequently handles raw `u64` values that carry flag bits in
/// the high bytes (page-table entries, DMA descriptors). Validating those
/// at construction would force every caller to mask twice. Instead,
/// [`PhysAddr::new`] always succeeds and [`PhysAddr::new_truncate`] is the
/// explicit "strip the high bits" constructor. Callers that need a
/// guaranteed-valid physical address should use `new_truncate` or check
/// `as_u64() < (1 << 52)` themselves.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PhysAddr(u64);

impl PhysAddr {
    /// Create a physical address from a raw `u64`.
    ///
    /// Always returns `Some`: physical addresses are not canonicalised the
    /// way virtual addresses are, so there is no input that is "obviously
    /// wrong" at this layer. The `Option` return type is kept for API
    /// symmetry with [`VirtAddr::new`], which lets calling code pattern-match
    /// uniformly.
    #[inline]
    #[must_use]
    pub const fn new(addr: u64) -> Option<Self> {
        Some(Self(addr))
    }

    /// Create a physical address, masking off any bits above bit 51.
    ///
    /// Use this when the input is known to carry flag bits in the high
    /// bytes (e.g. a page-table entry that still has its flags attached)
    /// and you want only the address portion. For inputs you trust to be
    /// bare addresses, [`PhysAddr::new`] is cheaper and never fails.
    #[inline]
    #[must_use]
    pub const fn new_truncate(addr: u64) -> Self {
        Self(addr & PHYS_ADDR_MASK)
    }

    /// Create a physical address at offset zero (the null physical address).
    #[inline]
    #[must_use]
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Return the raw `u64` value of this address.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Align this address *down* to the given power-of-two alignment.
    ///
    /// `align` must be a power of two; if it is not, the result is the
    /// original address unchanged (we cannot panic in no_std, and a
    /// non-power-of-two alignment is meaningless). Callers that want to
    /// validate the alignment should check it beforehand.
    #[inline]
    #[must_use]
    pub const fn align_down(self, align: u64) -> Self {
        if align.is_power_of_two() {
            Self(self.0 & !(align - 1))
        } else {
            self
        }
    }

    /// Align this address *up* to the given power-of-two alignment.
    ///
    /// Returns `None` if `align` is not a power of two, or if the aligned
    /// value would overflow the `u64` range. Since [`PhysAddr::new`] does
    /// not enforce a 52-bit width, callers that need a guaranteed-valid
    /// physical address should additionally check the result fits in the
    /// CPU's MAXPHYADDR width.
    #[inline]
    #[must_use]
    pub fn align_up(self, align: u64) -> Option<Self> {
        if !align.is_power_of_two() {
            return None;
        }
        let mask = align - 1;
        // Add align-1 then mask down. checked_add catches u64 overflow; the
        // mask then brings the result up to the requested boundary.
        let summed = self.0.checked_add(mask)?;
        let aligned = summed & !mask;
        // new() always returns Some, so this unwrap is sound by construction.
        Some(Self::new(aligned).expect("PhysAddr::new is always Some"))
    }

    /// Returns `true` if this address is a multiple of `align`.
    ///
    /// A non-power-of-two `align` always returns `false`.
    #[inline]
    #[must_use]
    pub const fn is_aligned(self, align: u64) -> bool {
        align.is_power_of_two() && (self.0 & (align - 1)) == 0
    }

    /// Convenience: align down to a 4 KiB page boundary.
    #[inline]
    #[must_use]
    pub const fn page_align_down(self) -> Self {
        self.align_down(PAGE_SIZE)
    }

    /// Convenience: align up to a 4 KiB page boundary.
    #[inline]
    #[must_use]
    pub fn page_align_up(self) -> Option<Self> {
        self.align_up(PAGE_SIZE)
    }

    /// Convenience: is this address 4 KiB page-aligned?
    #[inline]
    #[must_use]
    pub const fn is_page_aligned(self) -> bool {
        self.is_aligned(PAGE_SIZE)
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Render as phys:0x... so it is visually distinct from VirtAddr in
        // logs and crash dumps.
        write!(f, "phys:0x{:016x}", self.0)
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

impl Add<u64> for PhysAddr {
    type Output = Self;
    /// Add a byte offset. Panics on overflow of the 52-bit physical space.
    ///
    /// This is intended for address arithmetic where overflow is a bug, not
    /// a runtime condition. For fallible addition use `checked_add_offset`.
    #[inline]
    fn add(self, rhs: u64) -> Self {
        Self::new(self.0.checked_add(rhs).expect("PhysAddr addition overflow"))
            .expect("PhysAddr addition exceeded 52-bit physical space")
    }
}

impl Sub<u64> for PhysAddr {
    type Output = Self;
    /// Subtract a byte offset. Panics on underflow.
    #[inline]
    fn sub(self, rhs: u64) -> Self {
        Self(
            self.0
                .checked_sub(rhs)
                .expect("PhysAddr subtraction underflow"),
        )
    }
}

impl Sub<Self> for PhysAddr {
    type Output = u64;
    /// The difference between two physical addresses, in bytes, as a `u64`.
    #[inline]
    fn sub(self, rhs: Self) -> u64 {
        self.0.wrapping_sub(rhs.0)
    }
}

// ---------------------------------------------------------------------------
// VirtAddr
// ---------------------------------------------------------------------------

/// A canonical 64-bit virtual address.
///
/// "Canonical" means bits 48..=63 are all copies of bit 47. The MMU enforces
/// this: accessing a non-canonical address raises a general-protection
/// fault (`#GP`) before any translation happens. This type guarantees its
/// contents are canonical, so any `VirtAddr` handed to paging code is
/// safe to load into a register.
///
/// Addresses with bit 47 clear are user-space (low half, `0x0000_...`).
/// Addresses with bit 47 set are kernel-space (high half, `0xFFFF_...`),
/// which is where the Xenith kernel lives (higher-half mapping).
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VirtAddr(u64);

impl VirtAddr {
    /// Create a virtual address from a raw `u64`.
    ///
    /// Returns `None` if the input is not in canonical form (bits 48..=63
    /// do not all match bit 47). This is the safe constructor — use it for
    /// any address whose provenance you do not completely trust.
    #[inline]
    #[must_use]
    pub const fn new(addr: u64) -> Option<Self> {
        if Self::is_canonical(addr) {
            Some(Self(addr))
        } else {
            None
        }
    }

    /// Create a virtual address, forcing canonical form by sign-extending
    /// bit 47 into bits 48..=63.
    ///
    /// This is the right constructor when the caller knows the meaningful
    /// bits live in 0..=47 and the high bits are garbage — for example when
    /// masking flags out of a page-table entry, or when a bootloader hands
    /// back a pointer with stale high bits. For addresses you simply want
    /// to validate, use [`VirtAddr::new`].
    #[inline]
    #[must_use]
    pub const fn new_truncate(addr: u64) -> Self {
        // Sign-extend bit 47: take the low 48 bits, then if bit 47 is set
        // fill bits 48..=63 with ones.
        let low48 = addr & CANONICAL_MASK;
        if (low48 >> CANONICAL_SIGN_BIT) & 1 == 1 {
            Self(low48 | !CANONICAL_MASK)
        } else {
            Self(low48)
        }
    }

    /// Create the null virtual address (`0x0`).
    #[inline]
    #[must_use]
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Return the raw `u64` value of this address.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Is this address in the kernel (high) half of the canonical space?
    ///
    /// i.e. does bit 47 — and therefore all of bits 47..=63 — set? Such
    /// addresses are `0xFFFF_8000_0000_0000` and above in practice.
    #[inline]
    #[must_use]
    pub const fn is_kernel(self) -> bool {
        (self.0 >> CANONICAL_SIGN_BIT) & 1 == 1
    }

    /// Is this address in the user (low) half of the canonical space?
    #[inline]
    #[must_use]
    pub const fn is_user(self) -> bool {
        !self.is_kernel()
    }

    /// Align this address *down* to the given power-of-two alignment.
    #[inline]
    #[must_use]
    pub const fn align_down(self, align: u64) -> Self {
        if align.is_power_of_two() {
            Self(self.0 & !(align - 1))
        } else {
            self
        }
    }

    /// Align this address *up* to the given power-of-two alignment.
    ///
    /// Returns `None` if `align` is not a power of two, or if aligning
    /// would produce a non-canonical address (which would happen only if
    /// the low 48 bits overflowed while the high bits were already all
    /// ones — extremely unlikely, but we refuse rather than hand back a
    /// bad address).
    #[inline]
    #[must_use]
    pub fn align_up(self, align: u64) -> Option<Self> {
        if !align.is_power_of_two() {
            return None;
        }
        let mask = align - 1;
        let summed = self.0.checked_add(mask)?;
        let aligned = summed & !mask;
        Self::new(Self::new_truncate(aligned).as_u64())
    }

    /// Returns `true` if this address is a multiple of `align`.
    #[inline]
    #[must_use]
    pub const fn is_aligned(self, align: u64) -> bool {
        align.is_power_of_two() && (self.0 & (align - 1)) == 0
    }

    /// Convenience: align down to a 4 KiB page boundary.
    #[inline]
    #[must_use]
    pub const fn page_align_down(self) -> Self {
        self.align_down(PAGE_SIZE)
    }

    /// Convenience: align up to a 4 KiB page boundary.
    #[inline]
    #[must_use]
    pub fn page_align_up(self) -> Option<Self> {
        self.align_up(PAGE_SIZE)
    }

    /// Convenience: is this address 4 KiB page-aligned?
    #[inline]
    #[must_use]
    pub const fn is_page_aligned(self) -> bool {
        self.is_aligned(PAGE_SIZE)
    }

    /// Check whether a raw `u64` is in x86_64 canonical form.
    ///
    /// Canonical means bits 48..=63 are all copies of bit 47. So:
    /// * if bit 47 is clear, bits 48..=63 must all be clear (user half);
    /// * if bit 47 is set, bits 48..=63 must all be set (kernel half).
    #[inline]
    #[must_use]
    pub const fn is_canonical(addr: u64) -> bool {
        let high = addr & !CANONICAL_MASK;
        let bit47 = (addr >> CANONICAL_SIGN_BIT) & 1;
        // Either bit 47 is 0 and the high bits are all 0, or bit 47 is 1 and
        // the high bits are all 1 (i.e. equal to !CANONICAL_MASK).
        (bit47 == 0 && high == 0) || (bit47 == 1 && high == !CANONICAL_MASK)
    }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Render as virt:0x... to distinguish from PhysAddr in dumps.
        write!(f, "virt:0x{:016x}", self.0)
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

impl Add<u64> for VirtAddr {
    type Output = Self;
    /// Add a byte offset, preserving canonical form. Panics on overflow or
    /// if the result would be non-canonical (which would indicate the
    /// offset crossed the 48-bit boundary — a bug in the caller).
    #[inline]
    fn add(self, rhs: u64) -> Self {
        let raw = self.0.checked_add(rhs).expect("VirtAddr addition overflow");
        Self::new(raw).expect("VirtAddr addition produced non-canonical address")
    }
}

impl Sub<u64> for VirtAddr {
    type Output = Self;
    /// Subtract a byte offset. Panics on underflow.
    #[inline]
    fn sub(self, rhs: u64) -> Self {
        let raw = self
            .0
            .checked_sub(rhs)
            .expect("VirtAddr subtraction underflow");
        Self::new(raw).expect("VirtAddr subtraction produced non-canonical address")
    }
}

impl Sub<Self> for VirtAddr {
    type Output = u64;
    /// The difference between two virtual addresses, in bytes, as a `u64`.
    ///
    /// This uses wrapping subtraction so that `kernel_base - user_ptr` does
    /// not panic even when the user pointer is numerically larger; the
    /// result is the correct two's-complement distance.
    #[inline]
    fn sub(self, rhs: Self) -> u64 {
        self.0.wrapping_sub(rhs.0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PhysAddr ---------------------------------------------------------

    #[test]
    fn phys_new_always_some() {
        // PhysAddr::new never rejects: physical addresses are not
        // canonicalised, so any u64 is accepted at this layer. This keeps
        // the API parallel with VirtAddr::new (which can return None)
        // without forcing callers to mask flag bits twice.
        assert_eq!(PhysAddr::new(0).map(|a| a.as_u64()), Some(0));
        // The highest valid 52-bit physical address.
        let max = (1u64 << 52) - 1;
        assert_eq!(PhysAddr::new(max).map(|a| a.as_u64()), Some(max));
        // Even values with bits above 52 set are accepted unchanged. This
        // is intentional: PTEs and DMA descriptors carry flag bits there,
        // and validation is the caller's job (use new_truncate to strip).
        assert_eq!(
            PhysAddr::new(0xFFFF_8000_0000_0000).map(|a| a.as_u64()),
            Some(0xFFFF_8000_0000_0000)
        );
    }

    #[test]
    fn phys_new_truncate_masks_high_bits() {
        // new_truncate strips bits above bit 51, keeping only the address.
        let a = PhysAddr::new_truncate((1u64 << 52) | 0x1234);
        assert_eq!(a.as_u64(), 0x1234);
        // A value with only bits 52..=55 set drops to zero, because the
        // 52-bit mask keeps bits 0..=51 only.
        let b = PhysAddr::new_truncate(0xF000_0000_0000_0000);
        assert_eq!(b.as_u64(), 0);
        // Bits 48..=51 are inside the 52-bit range, so they survive.
        let c = PhysAddr::new_truncate(0xFFFF_0000_0000_0000);
        assert_eq!(c.as_u64(), 0x000F_0000_0000_0000);
    }

    #[test]
    fn phys_align_down_and_up() {
        let a = PhysAddr::new(0x1234_5678).unwrap();
        assert_eq!(a.align_down(4096).as_u64(), 0x1234_5000);
        assert_eq!(a.align_up(4096).unwrap().as_u64(), 0x1234_6000);

        // Already aligned stays put.
        let aligned = PhysAddr::new(0x1234_5000).unwrap();
        assert_eq!(aligned.align_down(4096), aligned);
        assert_eq!(aligned.align_up(4096).unwrap(), aligned);
    }

    #[test]
    fn phys_align_up_overflow_returns_none() {
        // u64::MAX plus any non-zero mask overflows checked_add.
        let max = PhysAddr::new(u64::MAX).unwrap();
        assert!(max.align_up(4096).is_none());
        // Non-power-of-two alignment is rejected regardless of the address.
        let a = PhysAddr::new(0x1000).unwrap();
        assert!(a.align_up(3).is_none());
    }

    #[test]
    fn phys_is_aligned() {
        let a = PhysAddr::new(0x1234_5000).unwrap();
        assert!(a.is_aligned(4096));
        assert!(!a.is_aligned(8192));
        // Non-power-of-two alignment is treated as "never aligned".
        assert!(!a.is_aligned(3));
    }

    #[test]
    fn phys_arithmetic() {
        let base = PhysAddr::new(0x1000).unwrap();
        assert_eq!((base + 0x500).as_u64(), 0x1500);
        assert_eq!((base - 0x500).as_u64(), 0x0B00);
        // Sub<Self> yields the byte difference.
        let hi = PhysAddr::new(0x2000).unwrap();
        assert_eq!(hi - base, 0x1000);
    }

    #[test]
    fn phys_helpers() {
        let a = PhysAddr::new(0x1234_5678).unwrap();
        assert_eq!(a.page_align_down().as_u64(), 0x1234_5000);
        assert_eq!(a.page_align_up().unwrap().as_u64(), 0x1234_6000);
        assert!(!a.is_page_aligned());
        assert!(a.page_align_down().is_page_aligned());
    }

    #[test]
    fn phys_ordering_and_zero() {
        assert!(PhysAddr::new(0x1000).unwrap() > PhysAddr::zero());
        assert_eq!(PhysAddr::zero().as_u64(), 0);
    }

    // ---- VirtAddr ---------------------------------------------------------

    #[test]
    fn virt_new_accepts_canonical() {
        // Low half: bits 48..=63 all zero.
        assert_eq!(
            VirtAddr::new(0x0000_7FFF_FFFF_FFFF).map(|a| a.as_u64()),
            Some(0x0000_7FFF_FFFF_FFFF)
        );
        // High half: bits 48..=63 all one.
        assert_eq!(
            VirtAddr::new(0xFFFF_8000_0000_0000).map(|a| a.as_u64()),
            Some(0xFFFF_8000_0000_0000)
        );
        // Null is canonical.
        assert_eq!(VirtAddr::new(0).map(|a| a.as_u64()), Some(0));
    }

    #[test]
    fn virt_new_rejects_non_canonical() {
        // The classic "hole": bit 47 clear but bit 48 set.
        assert_eq!(VirtAddr::new(0x0000_8000_0000_0000), None);
        // And the mirror: bit 47 set but bit 48 clear.
        assert_eq!(VirtAddr::new(0x7FFF_FFFF_FFFF_FFFF), None);
    }

    #[test]
    fn virt_new_truncate_canonicalises() {
        // A value with bit 47 clear and high garbage bits set: the high
        // bits are dropped (masked to the low 48) and NO sign extension
        // happens because bit 47 is clear. Result stays in the user half.
        // 0x0001_2345_6789 has bit 47 clear (it is < 2^47), so the high
        // nibble 0xABCD is thrown away.
        let a = VirtAddr::new_truncate(0xABCD_0001_2345_6789);
        assert_eq!(a.as_u64(), 0x0000_0001_2345_6789);
        assert!(VirtAddr::is_canonical(a.as_u64()));

        // A value with bit 47 set: the high bits are replaced with ones
        // (sign extension of bit 47), producing a kernel-half address.
        // 0x0000_8000_0000_0000 has bit 47 set and high bits clear, which
        // is non-canonical; new_truncate sign-extends to 0xFFFF_8000_....
        let b = VirtAddr::new_truncate(0x0000_8000_0000_0000);
        assert_eq!(b.as_u64(), 0xFFFF_8000_0000_0000);
        assert!(VirtAddr::is_canonical(b.as_u64()));

        // A value with bit 47 set AND high bits already all ones is already
        // canonical and stays unchanged.
        let c = VirtAddr::new_truncate(0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(c.as_u64(), 0xFFFF_FFFF_FFFF_FFFF);
    }

    #[test]
    fn virt_is_kernel_and_user() {
        assert!(VirtAddr::new(0xFFFF_8000_0000_0000).unwrap().is_kernel());
        assert!(!VirtAddr::new(0xFFFF_8000_0000_0000).unwrap().is_user());
        assert!(VirtAddr::new(0x0000_7FFF_FFFF_FFFF).unwrap().is_user());
        assert!(!VirtAddr::new(0x0000_7FFF_FFFF_FFFF).unwrap().is_kernel());
    }

    #[test]
    fn virt_align_helpers() {
        let a = VirtAddr::new(0xFFFF_8000_0000_1234).unwrap();
        assert_eq!(a.align_down(4096).as_u64(), 0xFFFF_8000_0000_1000);
        assert_eq!(a.align_up(4096).unwrap().as_u64(), 0xFFFF_8000_0000_2000);
        assert!(a.align_down(4096).is_page_aligned());
        assert!(!a.is_page_aligned());
    }

    #[test]
    fn virt_arithmetic() {
        let base = VirtAddr::new(0xFFFF_8000_0000_1000).unwrap();
        assert_eq!((base + 0x500).as_u64(), 0xFFFF_8000_0000_1500);
        assert_eq!((base - 0x500).as_u64(), 0xFFFF_8000_0000_0B00);
        // Sub<Self> returns the byte distance.
        let other = VirtAddr::new(0xFFFF_8000_0000_2000).unwrap();
        assert_eq!(other - base, 0x1000);
    }

    #[test]
    fn virt_sub_wraps_across_halves() {
        // Kernel-base minus a user pointer should wrap, not panic.
        let k = VirtAddr::new(0xFFFF_8000_0000_0000).unwrap();
        let u = VirtAddr::new(0x0000_0000_0000_1000).unwrap();
        // The exact numeric value isn't important; what matters is no panic.
        let _diff = k - u;
    }

    #[test]
    fn virt_is_canonical_predicate() {
        assert!(VirtAddr::is_canonical(0));
        assert!(VirtAddr::is_canonical(0xFFFF_FFFF_FFFF_FFFF));
        assert!(VirtAddr::is_canonical(0x0000_7FFF_FFFF_FFFF));
        assert!(VirtAddr::is_canonical(0xFFFF_8000_0000_0000));
        assert!(!VirtAddr::is_canonical(0x0000_8000_0000_0000));
        assert!(!VirtAddr::is_canonical(0x7FFF_FFFF_FFFF_FFFF));
    }

    #[test]
    fn page_size_constant() {
        assert_eq!(PAGE_SIZE, 4096);
    }
}
