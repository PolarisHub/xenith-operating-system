//! # xenith-bitflags
//!
//! A tiny, `no_std` bitflags macro for the Xenith kernel.
//!
//! The [`bitflags!`] macro generates a `#[repr(transparent)]` struct wrapping
//! an integer backing storage type (by default `u64`, but any of `u8`, `u16`,
//! `u32`, `u64`, `u128`, `usize`, or the signed variants is accepted). The
//! generated type carries a set of associated `const` flag constants and a
//! suite of operator and helper method impls so flags can be combined,
//! inspected, toggled, and cleared ergonomically.
//!
//! ## Example
//!
//! ```
//! use xenith_bitflags::bitflags;
//!
//! bitflags! {
//!     pub struct Permissions: u32 {
//!         const READ  = 1 << 0;
//!         const WRITE = 1 << 1;
//!         const EXEC  = 1 << 2;
//!     }
//! }
//!
//! let rw = Permissions::READ | Permissions::WRITE;
//! assert!(rw.contains(Permissions::READ));
//! assert!(!rw.contains(Permissions::EXEC));
//! ```
//!
//! ## Why not the `bitflags` crate?
//!
//! The upstream `bitflags` crate is excellent and feature-rich, but Xenith
//! keeps a deliberately small dependency tree at the foundation layer. This
//! macro covers the subset of functionality the kernel actually uses, is fully
//! `no_std` with zero allocations, and compiles in a few thousand bytes.

#![no_std]
#![allow(clippy::needless_doctest_main)]

#[cfg(test)]
extern crate std;

use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

/// Sealed trait describing the integer types that can back a bitflags struct.
///
/// This is the primitive integer contract the macro relies on: a zero value, a
/// bitwise OR/AND/XXOR/NOT, and an `is_empty` check via `==`. All standard
/// unsigned and signed integer types implement it. The trait is sealed against
/// downstream impls via the private [`private::Sealed`] marker so only the
/// types enumerated here can be used as backing storage — this keeps the
/// macro's generated code sound.
pub trait Bits:
    Copy
    + Clone
    + PartialEq
    + Eq
    + BitOr<Output = Self>
    + BitAnd<Output = Self>
    + BitXor<Output = Self>
    + BitOrAssign
    + BitAndAssign
    + BitXor<Output = Self>
    + BitXorAssign
    + Not<Output = Self>
    + private::Sealed
{
    /// The additive identity (`0`). Used to construct an empty flag set.
    const ZERO: Self;

    /// Returns `true` if this value has no bits set.
    #[inline]
    fn is_zero(self) -> bool {
        self == Self::ZERO
    }
}

mod private {
    /// Sealing marker. Implementing this trait outside this crate is
    /// impossible, which prevents downstream code from supplying exotic
    /// backing types to the macro.
    pub trait Sealed {}
}

macro_rules! impl_bits {
    ($($t:ty),* $(,)?) => {
        $(
            impl private::Sealed for $t {}
            impl Bits for $t {
                const ZERO: Self = 0;
            }
        )*
    };
}

impl_bits! {
    u8, u16, u32, u64, u128, usize,
    i8, i16, i32, i64, i128, isize,
}

/// The bitflags generator.
///
/// See the crate-level documentation for a usage example and the list of
/// generated methods.
#[macro_export]
macro_rules! bitflags {
    (
        $(#[$outer:meta])*
        $vis:vis struct $name:ident : $bits:ty {
            $(
                $(#[$inner:meta])*
                $const_vis:vis const $flag:ident = $value:expr;
            )*
        }
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        $vis struct $name($bits);

        impl $name {
            $(
                $(#[$inner])*
                // Flag values are part of the generated type's public API.
                // Several kernel modules intentionally declare the flags
                // without repeating `pub` on every line, matching the
                // upstream bitflags convention.
                pub const $flag: Self = Self($value);
            )*

            /// Construct a flag set from raw bits.
            ///
            /// Returns `None` if any bit is set that is not covered by the
            /// defined flags — this is the safe, checked constructor. Use
            /// [`from_bits_truncate`](Self::from_bits_truncate) to silently
            /// discard unknown bits instead.
            #[inline]
            pub const fn from_bits(bits: $bits) -> Option<Self> {
                let masked = bits & Self::ALL.0;
                if masked == bits {
                    Some(Self(bits))
                } else {
                    None
                }
            }

            /// Construct a flag set from raw bits, silently discarding any
            /// bits not covered by the defined flags.
            #[inline]
            pub const fn from_bits_truncate(bits: $bits) -> Self {
                Self(bits & Self::ALL.0)
            }

            /// Return the raw underlying bits.
            #[inline]
            pub const fn bits(self) -> $bits {
                self.0
            }

            /// Returns `true` if all of the bits in `other` are set.
            ///
            /// This is the subset relation: `self` contains `other` iff
            /// every bit set in `other` is also set in `self`. The empty
            /// flag set is contained by every set (vacuously), matching the
            /// upstream `bitflags` crate.
            #[inline]
            pub const fn contains(self, other: Self) -> bool {
                (self.0 & other.0) == other.0
            }

            /// Returns `true` if any bit in `other` is set within `self`.
            ///
            /// This is the "intersects" relation: `self & other != 0`. Unlike
            /// [`contains`](Self::contains), `other` need not be a subset of
            /// `self`, only share at least one bit.
            #[inline]
            pub const fn intersects(self, other: Self) -> bool {
                (self.0 & other.0) != <$bits as $crate::Bits>::ZERO
            }

            /// Insert the bits of `other` into `self`.
            #[inline]
            pub fn insert(&mut self, other: Self) {
                self.0 |= other.0;
            }

            /// Remove the bits of `other` from `self`.
            #[inline]
            pub fn remove(&mut self, other: Self) {
                self.0 &= !other.0;
            }

            /// Toggle the bits of `other` in `self`.
            #[inline]
            pub fn toggle(&mut self, other: Self) {
                self.0 ^= other.0;
            }

            /// Set or clear the bits of `other` depending on `value`.
            #[inline]
            pub fn set(&mut self, other: Self, value: bool) {
                if value {
                    self.insert(other);
                } else {
                    self.remove(other);
                }
            }

            /// Returns `true` if no bits are set.
            #[inline]
            pub const fn is_empty(self) -> bool {
                // Compare directly to the zero constant rather than calling
                // `Bits::is_zero`, which is not a `const fn` and so cannot be
                // used inside this `const fn`. Integer `==` is const-evaluable.
                self.0 == <$bits as $crate::Bits>::ZERO
            }

            /// Returns `true` if all defined flags are set.
            #[inline]
            pub const fn is_all(self) -> bool {
                Self::ALL.0 != <$bits as $crate::Bits>::ZERO && (self.0 & Self::ALL.0) == Self::ALL.0
            }

            /// Returns a flag set with no bits set.
            #[inline]
            pub const fn empty() -> Self {
                Self(<$bits as $crate::Bits>::ZERO)
            }

            /// Returns a flag set with every defined bit set.
            #[inline]
            pub const fn all() -> Self {
                Self(Self::ALL_BITS)
            }

            /// The combined bits of every defined flag. Computed once here so
            /// the checked constructors and `is_all` do not have to recompute
            /// it on every call.
            const ALL_BITS: $bits = {
                let mut acc: $bits = <$bits as $crate::Bits>::ZERO;
                $( acc |= $value; )*
                acc
            };

            /// A named constant equal to the union of all defined flags.
            pub const ALL: Self = Self(Self::ALL_BITS);
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self::empty()
            }
        }

        impl From<$bits> for $name {
            /// Convert from raw bits using
            /// [`from_bits_truncate`](Self::from_bits_truncate). Unknown bits
            /// are discarded. If you need a checked conversion, call
            /// [`from_bits`](Self::from_bits) explicitly.
            #[inline]
            fn from(bits: $bits) -> Self {
                Self::from_bits_truncate(bits)
            }
        }

        impl From<$name> for $bits {
            #[inline]
            fn from(flags: $name) -> Self {
                flags.0
            }
        }

        impl core::fmt::Binary for $name {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Binary::fmt(&self.0, f)
            }
        }

        impl core::fmt::Octal for $name {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Octal::fmt(&self.0, f)
            }
        }

        impl core::fmt::LowerHex for $name {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl core::fmt::UpperHex for $name {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::UpperHex::fmt(&self.0, f)
            }
        }

        impl core::ops::BitOr for $name {
            type Output = Self;
            #[inline]
            fn bitor(self, rhs: Self) -> Self {
                Self(self.0 | rhs.0)
            }
        }

        impl core::ops::BitOrAssign for $name {
            #[inline]
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }

        impl core::ops::BitAnd for $name {
            type Output = Self;
            #[inline]
            fn bitand(self, rhs: Self) -> Self {
                Self(self.0 & rhs.0)
            }
        }

        impl core::ops::BitAndAssign for $name {
            #[inline]
            fn bitand_assign(&mut self, rhs: Self) {
                self.0 &= rhs.0;
            }
        }

        impl core::ops::BitXor for $name {
            type Output = Self;
            #[inline]
            fn bitxor(self, rhs: Self) -> Self {
                Self(self.0 ^ rhs.0)
            }
        }

        impl core::ops::BitXorAssign for $name {
            #[inline]
            fn bitxor_assign(&mut self, rhs: Self) {
                self.0 ^= rhs.0;
            }
        }

        impl core::ops::Not for $name {
            type Output = Self;
            /// The complement is taken within the set of defined bits so that
            /// `!flags` never introduces unknown bits. This matches the
            /// behavior of the upstream `bitflags` crate.
            #[inline]
            fn not(self) -> Self {
                Self(Self::ALL.0 & !self.0)
            }
        }

        impl core::ops::Sub for $name {
            type Output = Self;
            /// `self - other` clears the bits in `other` from `self`. This is
            /// the operator form of [`remove`](Self::remove).
            #[inline]
            fn sub(self, rhs: Self) -> Self {
                Self(self.0 & !rhs.0)
            }
        }

        impl core::ops::SubAssign for $name {
            #[inline]
            fn sub_assign(&mut self, rhs: Self) {
                self.0 &= !rhs.0;
            }
        }

        impl core::ops::BitOr<$bits> for $name {
            type Output = Self;
            #[inline]
            fn bitor(self, rhs: $bits) -> Self {
                Self(self.0 | rhs)
            }
        }

        impl core::ops::BitAnd<$bits> for $name {
            type Output = Self;
            #[inline]
            fn bitand(self, rhs: $bits) -> Self {
                Self(self.0 & rhs)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use std::format;

    bitflags! {
        pub struct Permissions: u32 {
            const READ    = 0b001;
            const WRITE   = 0b010;
            const EXECUTE = 0b100;
        }
    }

    bitflags! {
        pub struct PageFlags: u64 {
            const PRESENT  = 1 << 0;
            const WRITABLE = 1 << 1;
            const USER     = 1 << 2;
            const GLOBAL   = 1 << 63;
        }
    }

    bitflags! {
        pub struct TinyFlags: u8 {
            const A = 1 << 0;
            const B = 1 << 1;
            const C = 1 << 2;
        }
    }

    #[test]
    fn empty_and_all() {
        assert!(Permissions::empty().is_empty());
        assert!(Permissions::empty().bits() == 0);
        assert!(Permissions::all().is_all());
        assert_eq!(
            Permissions::all().bits(),
            Permissions::READ.bits() | Permissions::WRITE.bits() | Permissions::EXECUTE.bits()
        );
    }

    #[test]
    fn or_combines() {
        let rw = Permissions::READ | Permissions::WRITE;
        assert_eq!(rw.bits(), 0b011);
        assert!(rw.contains(Permissions::READ));
        assert!(rw.contains(Permissions::WRITE));
        assert!(!rw.contains(Permissions::EXECUTE));
    }

    #[test]
    fn intersects_shares_any_bit() {
        let rw = Permissions::READ | Permissions::WRITE;
        let wx = Permissions::WRITE | Permissions::EXECUTE;
        assert!(rw.intersects(wx));
        assert!(!rw.intersects(Permissions::EXECUTE));
    }

    #[test]
    fn insert_remove_toggle() {
        let mut f = Permissions::empty();
        f.insert(Permissions::READ);
        assert!(f.contains(Permissions::READ));
        f.insert(Permissions::WRITE);
        assert_eq!(f.bits(), 0b011);
        f.remove(Permissions::READ);
        assert!(!f.contains(Permissions::READ));
        assert!(f.contains(Permissions::WRITE));
        f.toggle(Permissions::WRITE);
        assert!(f.is_empty());
        f.toggle(Permissions::EXECUTE);
        assert!(f.contains(Permissions::EXECUTE));
    }

    #[test]
    fn set_helper() {
        let mut f = Permissions::empty();
        f.set(Permissions::READ, true);
        assert!(f.contains(Permissions::READ));
        f.set(Permissions::READ, false);
        assert!(!f.contains(Permissions::READ));
    }

    #[test]
    fn from_bits_checked() {
        assert!(Permissions::from_bits(0b011).is_some());
        // The high bit (0b1000) is not a defined flag — the checked ctor
        // must reject it.
        assert!(Permissions::from_bits(0b1000).is_none());
    }

    #[test]
    fn from_bits_truncate_drops_unknown() {
        let f = Permissions::from_bits_truncate(0b1111);
        assert_eq!(f.bits(), 0b111);
        assert!(f.is_all());
    }

    #[test]
    fn not_is_bounded_to_defined_bits() {
        let r = Permissions::READ;
        let not_r = !r;
        assert!(!not_r.contains(Permissions::READ));
        assert!(not_r.contains(Permissions::WRITE));
        assert!(not_r.contains(Permissions::EXECUTE));
    }

    #[test]
    fn sub_clears_bits() {
        let rw = Permissions::READ | Permissions::WRITE;
        let r = rw - Permissions::WRITE;
        assert!(r.contains(Permissions::READ));
        assert!(!r.contains(Permissions::WRITE));
    }

    #[test]
    fn u64_backing_with_high_bit() {
        let g = PageFlags::PRESENT | PageFlags::GLOBAL;
        assert!(g.contains(PageFlags::GLOBAL));
        assert!(g.contains(PageFlags::PRESENT));
        assert!(!g.contains(PageFlags::USER));
        assert_eq!(g.bits() >> 63, 1);
    }

    #[test]
    fn u8_backing_works() {
        let ab = TinyFlags::A | TinyFlags::B;
        assert_eq!(ab.bits(), 0b011);
        assert!(ab.contains(TinyFlags::A));
        assert!(ab.intersects(TinyFlags::B));
        assert!(!ab.contains(TinyFlags::C));
    }

    #[test]
    fn formatting_delegates_to_inner() {
        let f = Permissions::READ | Permissions::WRITE;
        assert_eq!(format!("{f:b}"), "11");
        assert_eq!(format!("{f:o}"), "3");
        assert_eq!(format!("{f:x}"), "3");
        assert_eq!(format!("{f:X}"), "3");
    }

    #[test]
    fn default_is_empty() {
        assert_eq!(Permissions::default(), Permissions::empty());
    }

    #[test]
    fn from_and_into_bits() {
        let f: Permissions = 0b011.into();
        assert!(f.contains(Permissions::READ));
        let raw: u32 = f.into();
        assert_eq!(raw, 0b011);
    }

    #[test]
    fn contains_empty_is_vacuously_true() {
        // Standard bitflags semantics: every set contains the empty set
        // (all zero of the empty flag's bits are set — vacuously true).
        assert!(Permissions::empty().contains(Permissions::empty()));
        assert!(Permissions::READ.contains(Permissions::empty()));
        assert!((Permissions::READ | Permissions::WRITE).contains(Permissions::empty()));
    }
}
