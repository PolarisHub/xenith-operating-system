//! Kernel heap allocation facade: `kmalloc` / `kfree`, the `Kbox` / `KVec` /
//! `KString` type aliases, and a [`HeapStats`] accessor.
//!
//! This module is the safe, idiomatic surface over the kernel heap. It has
//! two jobs:
//!
//! 1. Provide raw byte-level allocation helpers ([`kmalloc`], [`kfree`],
//!    [`kmalloc_zeroed`], [`krealloc`]) that wrap `alloc::alloc` and keep
//!    usage statistics. These are for C-style call sites and for code that
//!    needs a `NonNull<u8>` rather than a Rust collection.
//!
//! 2. Re-export the standard `alloc` collection types under Xenith-specific
//!    names — [`Kbox`], [`KVec`], [`KString`] — so kernel code has a single,
//!    greppable convention for heap-backed storage and never accidentally
//!    reaches for `std` counterparts. These use the `#[global_allocator]`
//!    registered by the [`super::allocator`] module, which routes to the
//!    heap backed by [`super::heap`].
//!
//! # Statistics
//!
//! Every byte-level helper updates the atomics in [`HEAP_STATS`]. The
//! `#[global_allocator]` in [`super::allocator`] is expected to update the
//! same counters for `Box` / `Vec` / `String` traffic, so [`heap_stats`]
//! reflects all kernel allocation regardless of which entry point was used.
//! The counters are monotonic (total allocations, total frees, total bytes
//! allocated, total bytes freed) so [`heap_stats`] computes `bytes_in_use` as
//! a saturating difference and never underflows.
//!
//! # When is this usable?
//!
//! Only after [`super::heap::init`] has run (i.e. after [`super::init`]).
//! Before that, the global allocator is not registered and `alloc::alloc`
//! has nowhere to allocate from; a call will return `OutOfMemory`. Use
//! [`super::is_initialized`] to guard early paths.

use alloc::alloc::{alloc, alloc_zeroed, dealloc, realloc, Layout};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// A failure from one of the `kmalloc*` helpers.
///
/// Hand-rolled per the Xenith convention (no `thiserror`, no `std`); the two
/// variants cover the only two failure modes the raw allocator can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmallocError {
    /// The requested layout was invalid: zero size, or a non-power-of-two
    /// alignment. These are caller bugs, so they surface as a distinct
    /// variant rather than being silently coerced.
    InvalidLayout,
    /// The underlying allocator could not satisfy the request. The heap is
    /// either uninitialised, full, or fragmented past the requested
    /// alignment.
    OutOfMemory,
}

// ---------------------------------------------------------------------------
// Statistics counters and snapshot
// ---------------------------------------------------------------------------

/// Atomic counters tracking kernel heap usage, updated by every `kmalloc*`
/// helper and by the global allocator.
///
/// The fields are `pub` so that [`super::allocator`]'s `GlobalAlloc` impl can
/// increment them directly (it sees the same allocation traffic as the raw
/// helpers). All fields are monotonic: they only ever increase, which lets
/// [`heap_stats`] compute `bytes_in_use` as a saturating difference without
/// any underflow risk.
///
/// The four counters are read independently in [`heap_stats`], so the
/// snapshot is not atomically consistent — two reads may straddle an
/// allocation. This is acceptable for diagnostics; precise accounting would
/// require a lock, which is not worth it for stats that are only ever read
/// for logging or a future `/proc/meminfo`-style debug surface.
#[derive(Debug)]
pub struct HeapStatsCounters {
    /// Total number of successful allocation calls (kmalloc / krealloc-grow
    /// / Box / Vec / String allocations).
    pub allocations: AtomicU64,
    /// Total number of successful free calls (kfree / krealloc-shrink-to-zero
    /// / dropping a Box / Vec / String).
    pub frees: AtomicU64,
    /// Total bytes ever handed out (cumulative across all allocations).
    pub bytes_allocated: AtomicU64,
    /// Total bytes ever returned (cumulative across all frees).
    pub bytes_freed: AtomicU64,
}

impl HeapStatsCounters {
    /// Create a zeroed counter set. Used by the [`HEAP_STATS`] static.
    pub const fn new() -> Self {
        Self {
            allocations: AtomicU64::new(0),
            frees: AtomicU64::new(0),
            bytes_allocated: AtomicU64::new(0),
            bytes_freed: AtomicU64::new(0),
        }
    }
}

impl Default for HeapStatsCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// The global heap-usage counter set.
///
/// Every `kmalloc*` helper in this module updates this static, and the
/// `#[global_allocator]` in [`super::allocator`] is expected to do the same
/// for `Box` / `Vec` / `String` traffic so [`heap_stats`] reflects all
/// kernel allocation.
pub static HEAP_STATS: HeapStatsCounters = HeapStatsCounters::new();

/// A point-in-time snapshot of kernel heap usage.
///
/// Built by [`heap_stats`] from a read of [`HEAP_STATS`]. All fields are
/// plain `u64` values; the snapshot is not atomically consistent with respect
/// to concurrent allocation, which is fine for diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeapStats {
    /// Total successful allocation calls since boot.
    pub allocations: u64,
    /// Total successful free calls since boot.
    pub frees: u64,
    /// Total bytes ever allocated (cumulative).
    pub bytes_allocated: u64,
    /// Total bytes ever freed (cumulative).
    pub bytes_freed: u64,
    /// Bytes currently in use: `bytes_allocated.saturating_sub(bytes_freed)`.
    pub bytes_in_use: u64,
}

/// Read a snapshot of the kernel heap usage counters.
///
/// The snapshot is built from four independent atomic reads, so it may be
/// slightly inconsistent under concurrent allocation. This is deliberate:
/// taking a lock for stats would serialise every allocator call, which is not
/// worth it for a diagnostic surface.
#[must_use]
pub fn heap_stats() -> HeapStats {
    // Acquire on each read pairs with the Release the allocator would use if
    // it ever needed one; Relaxed would also be fine here since we only need
    // eventual visibility, but Acquire is cheap and conservative.
    let allocations = HEAP_STATS.allocations.load(Ordering::Acquire);
    let frees = HEAP_STATS.frees.load(Ordering::Acquire);
    let bytes_allocated = HEAP_STATS.bytes_allocated.load(Ordering::Acquire);
    let bytes_freed = HEAP_STATS.bytes_freed.load(Ordering::Acquire);
    HeapStats {
        allocations,
        frees,
        bytes_allocated,
        bytes_freed,
        bytes_in_use: bytes_allocated.saturating_sub(bytes_freed),
    }
}

// ---------------------------------------------------------------------------
// Raw byte-level allocation helpers
// ---------------------------------------------------------------------------

/// Allocate `layout.size()` bytes with `layout.align()` alignment.
///
/// Returns a [`NonNull`] pointer to the allocated block, or
/// [`KmallocError::InvalidLayout`] if the layout is malformed (zero size or
/// non-power-of-two alignment), or [`KmallocError::OutOfMemory`] if the
/// underlying allocator cannot satisfy the request.
///
/// The caller must eventually return the block with [`kfree`], passing the
/// same `layout`. The memory is **not** zeroed; use [`kmalloc_zeroed`] when
/// the contents must start clean (e.g. page tables, security-sensitive
/// buffers).
///
/// Zero-size allocations are rejected as `InvalidLayout` rather than returning
/// a dangling pointer. Rust's own `Box` handles ZSTs at the type level, so a
/// raw `kmalloc(0)` is almost always a caller bug.
pub fn kmalloc(layout: Layout) -> Result<NonNull<u8>, KmallocError> {
    // The alloc crate requires the layout to have non-zero size and a
    // power-of-two alignment. Layout::from_size_align already enforces the
    // power-of-two invariant, but callers can build a layout with size 0
    // through Layout::new::<()> etc.; reject that explicitly.
    if layout.size() == 0 {
        return Err(KmallocError::InvalidLayout);
    }

    // SAFETY: `alloc` requires a valid, non-zero-size Layout. We validated
    // size above and Layout's constructors guarantee power-of-two alignment,
    // so the precondition holds.
    let ptr = unsafe { alloc(layout) };
    let nn = NonNull::new(ptr).ok_or(KmallocError::OutOfMemory)?;

    // Monotonic counters: Relaxed is sufficient because these are diagnostic
    // counters with no synchronisation role — we only need eventual
    // visibility for a stats reader.
    HEAP_STATS.allocations.fetch_add(1, Ordering::Relaxed);
    HEAP_STATS
        .bytes_allocated
        .fetch_add(layout.size() as u64, Ordering::Relaxed);
    Ok(nn)
}

/// Allocate a zeroed block with the given layout.
///
/// Like [`kmalloc`] but the returned bytes are guaranteed zero. Use this for
/// page tables, descriptor blocks, and any buffer that must not leak stale
/// heap contents to a reader.
///
/// Returns the same error variants as [`kmalloc`] for the same reasons.
pub fn kmalloc_zeroed(layout: Layout) -> Result<NonNull<u8>, KmallocError> {
    if layout.size() == 0 {
        return Err(KmallocError::InvalidLayout);
    }

    // SAFETY: same precondition as `alloc`: valid, non-zero-size Layout.
    let ptr = unsafe { alloc_zeroed(layout) };
    let nn = NonNull::new(ptr).ok_or(KmallocError::OutOfMemory)?;

    HEAP_STATS.allocations.fetch_add(1, Ordering::Relaxed);
    HEAP_STATS
        .bytes_allocated
        .fetch_add(layout.size() as u64, Ordering::Relaxed);
    Ok(nn)
}

/// Free a block previously returned by [`kmalloc`] / [`kmalloc_zeroed`] /
/// [`krealloc`].
///
/// `ptr` must be a pointer returned by one of the allocation helpers in this
/// module (or by `krealloc`), and `layout` must be the layout the block was
/// allocated with. Mismatching the layout, freeing a pointer twice, or
/// freeing a pointer from a different allocator is undefined behaviour.
///
/// # Safety
///
/// The caller guarantees that `ptr` was returned by a prior successful
/// `kmalloc*` call with exactly this `layout`, and that `ptr` has not
/// already been freed.
///
/// # Panics
///
/// Panics if `layout.size()` is zero, since a zero-size block can never have
/// been handed out by [`kmalloc`] (it rejects zero size). A free with a
/// zero-size layout is therefore always a caller bug.
pub unsafe fn kfree(ptr: NonNull<u8>, layout: Layout) {
    assert!(
        layout.size() != 0,
        "kfree: zero-size layout (no valid kmalloc produces one)"
    );

    // SAFETY: caller guarantees `ptr` came from a kmalloc* call with this
    // exact layout and has not been freed yet. `dealloc` requires exactly
    // that precondition.
    unsafe { dealloc(ptr.as_ptr(), layout) };

    HEAP_STATS.frees.fetch_add(1, Ordering::Relaxed);
    HEAP_STATS
        .bytes_freed
        .fetch_add(layout.size() as u64, Ordering::Relaxed);
}

/// Resize a previously allocated block in place (or by moving).
///
/// Grows or shrinks the allocation at `ptr` (which was allocated with
/// `layout`) to `new_size` bytes, preserving the alignment and as much of the
/// original contents as fit. The returned pointer may be different from
/// `ptr`; if so, the old block has been freed and the caller must not use
/// `ptr` again.
///
/// A `new_size` of zero frees the block and returns [`NonNull::dangling`]:
/// the canonical "empty allocation" pointer. The caller should not pass it to
/// [`kfree`] (that would double-free); treating a zero-size realloc as a
/// free is the standard Rust alloc convention.
///
/// # Safety
///
/// The caller guarantees that `ptr` was returned by a prior successful
/// `kmalloc*` call with exactly this `layout`, and that `ptr` has not
/// already been freed.
pub unsafe fn krealloc(
    ptr: NonNull<u8>,
    layout: Layout,
    new_size: usize,
) -> Result<NonNull<u8>, KmallocError> {
    // The original layout must be non-zero (kmalloc rejects zero size), so a
    // zero-size original is a contract violation.
    if layout.size() == 0 {
        return Err(KmallocError::InvalidLayout);
    }

    if new_size == 0 {
        // Realloc-to-zero is a free. We do the dealloc ourselves (realloc
        // with new_size 0 is undefined in the alloc crate) and return the
        // canonical dangling pointer per the Rust convention.
        // SAFETY: caller guarantees ptr was allocated with `layout`.
        unsafe { dealloc(ptr.as_ptr(), layout) };
        // Count the free for stats. The original bytes are returned.
        HEAP_STATS.frees.fetch_add(1, Ordering::Relaxed);
        HEAP_STATS
            .bytes_freed
            .fetch_add(layout.size() as u64, Ordering::Relaxed);
        return Ok(NonNull::dangling());
    }

    // SAFETY: caller guarantees `ptr` was allocated with `layout` and not
    // freed; `realloc` requires exactly that, plus a non-zero `new_size`
    // (checked above).
    let new_ptr = unsafe { realloc(ptr.as_ptr(), layout, new_size) };
    let nn = NonNull::new(new_ptr).ok_or(KmallocError::OutOfMemory)?;

    // For stats, treat a realloc as one free of the old size and one
    // allocation of the new size. This keeps bytes_in_use consistent
    // (bytes_allocated - bytes_freed) and double-counts the call in both
    // allocations and frees, which is the honest representation: the
    // allocator did both pieces of work.
    let old_size = layout.size() as u64;
    let new_size64 = new_size as u64;
    HEAP_STATS.allocations.fetch_add(1, Ordering::Relaxed);
    HEAP_STATS.frees.fetch_add(1, Ordering::Relaxed);
    HEAP_STATS
        .bytes_allocated
        .fetch_add(new_size64, Ordering::Relaxed);
    HEAP_STATS
        .bytes_freed
        .fetch_add(old_size, Ordering::Relaxed);
    Ok(nn)
}

/// Convenience wrapper: allocate `size` bytes with `align` alignment.
///
/// Builds a [`Layout`] from `(size, align)` and delegates to [`kmalloc`].
/// Use this when a caller has the size and alignment as separate integers
/// (e.g. coming from a foreign struct descriptor) rather than a pre-built
/// `Layout`.
pub fn kmalloc_size(size: usize, align: usize) -> Result<NonNull<u8>, KmallocError> {
    let layout = Layout::from_size_align(size, align).map_err(|_| KmallocError::InvalidLayout)?;
    kmalloc(layout)
}

// ---------------------------------------------------------------------------
// Idiomatic collection aliases
// ---------------------------------------------------------------------------

/// A heap-owned box, aliasing [`alloc::boxed::Box`].
///
/// Use `Kbox<T>` for any single heap allocation that owns its content. It
/// routes through the kernel's `#[global_allocator]` (registered in
/// [`super::allocator`]); no `std` is involved.
pub type Kbox<T> = alloc::boxed::Box<T>;

/// A heap-owned growable vector, aliasing [`alloc::vec::Vec`].
///
/// Use `KVec<T>` for dynamic arrays. Like [`Kbox`], it uses the kernel global
/// allocator.
pub type KVec<T> = alloc::vec::Vec<T>;

/// A heap-owned UTF-8 string, aliasing [`alloc::string::String`].
///
/// Use `KString` for owned text (log message construction, path buffers,
/// userspace-supplied strings that must outlive the borrow). For `&str`
/// borrowed from static data, use the plain `&str` — `KString` is only for
/// heap-backed ownership.
pub type KString = alloc::string::String;
