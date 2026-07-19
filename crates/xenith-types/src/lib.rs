//! `xenith-types` — shared address, page, and memory-size types for the
//! Xenith kernel.
//!
//! This is the bottom layer of the Xenith workspace: a tiny, dependency-free
//! `no_std` crate that every other crate (kernel, boot, bitflags, user
//! libraries) can depend on without pulling in anything else. It contains no
//! I/O, no unsafe code, and no hardware access — just the newtypes the rest
//! of the kernel uses to keep physical and virtual addresses, pages, and
//! frames from being confused with each other.
//!
//! # Layout
//!
//! * [`address`] — [`PhysAddr`] and [`VirtAddr`]: u64 newtypes for physical
//!   and canonical virtual addresses, with alignment helpers and arithmetic.
//! * [`page`] — [`Page`] and [`PhysFrame`] (4 KiB virtual page / physical
//!   frame), [`PageRange`] for iterating runs of pages, and the
//!   [`PageTableIndex`] / [`PageTableLevel`] primitives for table walking.
//! * [`size`] — the [`PageSize`] trait and the [`Size4KiB`] / [`Size2MiB`]
//!   / [`Size1GiB`] marker types used to parameterise generic paging code.
//!
//! # Why a separate crate?
//!
//! Putting these types in their own crate, with no dependencies, means the
//! bitflags macro crate and the boot-info crate can both use them without
//! depending on the kernel (which would be a circular dependency). It also
//! keeps the type surface small and well-documented: every type here is one
//! a Xenith developer will touch daily, so the bar for clarity is high.
//!
//! # `no_std`
//!
//! The crate is `#![no_std]` in all real (non-test) builds. The `cfg(test)`
//! gate only exists so the host test harness can link `std` for
//! `assert_eq!` formatting and `Vec` collection in unit tests; kernel
//! consumers never see `std`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]
// We use no unsafe code in this crate at all — every operation on these
// newtypes is plain integer arithmetic. Deny unsafe code outright so a
// future contributor cannot sneak an `unsafe` block in without justifying
// it against this crate's "pure integer types" contract.
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::missing_const_for_fn)]
// Allow the test module to pull in std for the host test harness. This
// `extern crate` is only linked under cfg(test) and never appears in a
// kernel build.

pub mod address;
pub mod page;
pub mod size;

// Flat re-exports so downstream code can write `use xenith_types::PhysAddr`
// instead of drilling into submodules. The submodule paths remain available
// for callers that want to scope imports explicitly.
pub use address::{PhysAddr, VirtAddr, PAGE_SIZE};
pub use page::{Page, PageRange, PageTableIndex, PageTableLevel, PhysFrame};
pub use size::{PageSize, Size1GiB, Size2MiB, Size4KiB};
