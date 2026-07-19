//! Kernel heap bootstrap and the `Kmalloc` surface.
//!
//! This module is the bridge between the boot memory map and the heap
//! implementation in [`super::heap`]. It owns three things:
//!
//! * [`init_heap`] — called once from `mm::init` after the Limine memory map
//!   is available. It picks a large usable physical range, exposes it through
//!   the Limine HHDM direct map (so no page-table work is needed to make the
//!   heap reachable), and hands the resulting virtual range to the global
//!   [`LockedHeap`].
//! * [`HeapStats`] / [`heap_stats`] — a lock-free running counter of
//!   allocation activity, updated by the heap on every `alloc`/`dealloc` and
//!   readable from any context for diagnostics.
//! * [`Kmalloc`] plus the [`Box`] / [`Vec`] / [`String`] re-exports — the
//!   typed allocation API the rest of the kernel uses, and the single
//!   import site for the `alloc` collection types.
//!
//! `extern crate alloc` lives here (rather than at the crate root) so the
//! whole memory-management subtree is self-contained: every `alloc` type the
//! kernel touches is re-exported from this module, and [`super::heap`] pulls
//! [`GlobalAlloc`] back through the re-export below instead of reaching for a
//! second extern-crate declaration.

// Bring the `alloc` crate into scope for this module and its descendants. In
// the 2018 edition `extern crate` is still required for `alloc` because it is
// not part of the prelude; declaring it here makes `alloc::` paths resolve in
// `mm::allocator` and its submodules, and the re-exports below make the types
// available crate-wide via `crate::mm::allocator::Box` etc.
extern crate alloc;

// Re-export the `alloc` collection types so the rest of the kernel imports
// them from one place (`crate::mm::allocator::{Box, Vec, String}`) rather than
// each pulling in `extern crate alloc` themselves. This is the canonical
// kernel pattern: a single module owns the allocator surface. The `string`
// and `vec` module re-exports also bring the `format!`/`vec!` macro paths into
// scope for callers that `use crate::mm::allocator::*`.
pub use alloc::boxed::Box;
pub use alloc::string::{self, String};
pub use alloc::vec::{self, Vec};
// Re-export `GlobalAlloc` so `super::heap` can name the trait without its own
// `extern crate alloc` — the whole `mm` subtree shares this one declaration.
pub use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use xenith_boot::{BootInfo, MemoryRegion};
use xenith_types::PhysAddr;

// ---------------------------------------------------------------------------
// Allocation error
// ---------------------------------------------------------------------------

/// The error returned by [`Kmalloc::kmalloc`] and [`Kmalloc::krealloc`] when an
/// allocation cannot be satisfied.
///
/// This is a hand-rolled enum rather than `core::alloc::AllocError` because the
/// latter is gated behind the unstable `allocator_api` feature and the Xenith
/// convention is to use own error types. The two variants cover every failure
/// mode the heap can produce: the backing region is exhausted, or the heap has
/// not been initialised yet (allocations before `mm::init` finishes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    /// The heap's reserved region does not have enough contiguous free space to
    /// satisfy the request. Returned by every tier (slab refill failure,
    /// coarse carve failure) once the heap is running.
    OutOfMemory,
    /// The heap has not been initialised yet — [`init_heap`] has not run, so
    /// there is no backing region to allocate from. Early-boot code that
    /// accidentally allocates hits this rather than faulting.
    NotInitialised,
}

impl core::fmt::Display for AllocError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfMemory => f.write_str("kernel heap out of memory"),
            Self::NotInitialised => f.write_str("kernel heap not yet initialised"),
        }
    }
}

// Re-export the `LockedHeap` and the global allocator static so callers can
// reach them as `crate::mm::allocator::ALLOCATOR` / `LockedHeap`.
pub use super::heap::LockedHeap;

// ---------------------------------------------------------------------------
// The global allocator static
// ---------------------------------------------------------------------------

/// The single kernel heap, registered with the `alloc` crate as the
/// `#[global_allocator]`.
///
/// Every `Box`/`Vec`/`String` in the kernel ultimately calls
/// [`GlobalAlloc::alloc`] on this static. It starts uninitialised (allocations
/// return `null` until [`init_heap`] has run) and is bound to the reserved
/// HHDM-backed region during `mm::init`.
///
/// Declared here rather than in `heap.rs` so that the `extern crate alloc`
/// declaration, the `#[global_allocator]` registration, and the `Kmalloc`
/// impl all live in one module — the `alloc`-facing surface of the kernel.
#[cfg_attr(not(test), global_allocator)]
static ALLOCATOR: LockedHeap = LockedHeap::new();

/// A handle to the global allocator for callers that want the `Kmalloc` API
/// without naming the static directly. `&ALLOCATOR` implements [`Kmalloc`].
pub fn global_allocator() -> &'static LockedHeap {
    &ALLOCATOR
}

// ---------------------------------------------------------------------------
// Heap statistics (lock-free)
// ---------------------------------------------------------------------------

/// A snapshot of kernel heap activity.
///
/// Every field is an atomic counter updated by the heap on each `alloc`/
/// `dealloc`, so a snapshot can be read from any context — including an
/// interrupt handler or a panic handler — without taking the heap lock.
/// The values are best-effort: two counters updated a few instructions apart
/// are not atomically consistent with each other, so `bytes_in_use` may be
/// momentarily off by one allocation. This is fine for diagnostics.
#[derive(Debug, Default)]
pub struct HeapStats {
    /// Total bytes handed out by `alloc` over the kernel's lifetime. Never
    /// decreases; the counterpart of `bytes_deallocated`.
    pub bytes_allocated: usize,
    /// Total bytes returned by `dealloc` over the kernel's lifetime.
    pub bytes_deallocated: usize,
    /// Number of `alloc` calls (including `alloc_zeroed` and the alloc half
    /// of `realloc`).
    pub alloc_count: usize,
    /// Number of `dealloc` calls (including the free half of `realloc`).
    pub dealloc_count: usize,
    /// High-water mark of bytes simultaneously outstanding. Tracked by
    /// comparing a running `current_bytes` against this on every alloc.
    pub peak_bytes: usize,
    /// Bytes currently outstanding (`bytes_allocated - bytes_deallocated` at
    /// the instant of the snapshot).
    pub current_bytes: usize,
    /// The configured capacity of the heap region in bytes, or `0` before
    /// [`init_heap`] has run. Useful for `used / capacity` gauges.
    pub capacity: usize,
}

// The live counters are kept in a separate `static` (not inside `HeapStats`)
// because `HeapStats` is a plain snapshot returned by value, while the live
// state must be `static` atomics. The `LiveStats` struct groups them so the
// record helpers touch one named global.
struct LiveStats {
    bytes_allocated: AtomicUsize,
    bytes_deallocated: AtomicUsize,
    alloc_count: AtomicUsize,
    dealloc_count: AtomicUsize,
    current_bytes: AtomicUsize,
    peak_bytes: AtomicUsize,
    capacity: AtomicUsize,
}

// SAFETY: `LiveStats` contains only `AtomicUsize`, which is `Sync`. The
// composite is therefore `Sync` without an unsafe impl, but we spell out the
// const constructor because atomics do not yet implement `const Default`.
impl LiveStats {
    const fn new() -> Self {
        Self {
            bytes_allocated: AtomicUsize::new(0),
            bytes_deallocated: AtomicUsize::new(0),
            alloc_count: AtomicUsize::new(0),
            dealloc_count: AtomicUsize::new(0),
            current_bytes: AtomicUsize::new(0),
            peak_bytes: AtomicUsize::new(0),
            capacity: AtomicUsize::new(0),
        }
    }
}

/// The live heap statistics counters. Updated by [`record_alloc`] and
/// [`record_dealloc`] under the heap lock; read by [`heap_stats`].
static STATS: LiveStats = LiveStats::new();

/// Record an `alloc` of `bytes` for statistics. Called by `LockedHeap::alloc`
/// while the heap lock is held, so the `Relaxed` orderings are sufficient —
/// the lock provides the cross-field ordering and the atomics only need to be
/// individually coherent for lock-free `heap_stats` reads.
pub(crate) fn record_alloc(bytes: usize) {
    STATS.alloc_count.fetch_add(1, Ordering::Relaxed);
    STATS.bytes_allocated.fetch_add(bytes, Ordering::Relaxed);
    // Track the outstanding-bytes high-water mark. The compare-exchange loop is
    // safe against concurrent updates because we hold the heap lock; even
    // without it the loop would converge, just with a possibly-stale peak.
    let now = STATS.current_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
    let mut peak = STATS.peak_bytes.load(Ordering::Relaxed);
    while now > peak {
        match STATS.peak_bytes.compare_exchange_weak(
            peak,
            now,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => peak = actual,
        }
    }
}

/// Record a `dealloc` of `bytes` for statistics. Counterpart of
/// [`record_alloc`].
pub(crate) fn record_dealloc(bytes: usize) {
    STATS.dealloc_count.fetch_add(1, Ordering::Relaxed);
    STATS.bytes_deallocated.fetch_add(bytes, Ordering::Relaxed);
    STATS.current_bytes.fetch_sub(bytes, Ordering::Relaxed);
}

/// Take a coherent-ish snapshot of the heap statistics.
///
/// Each counter is loaded with `Relaxed`, so the returned struct is not an
/// atomic snapshot of all fields at one instant — but each field is
/// individually accurate. This is the right trade-off for a diagnostics read
/// that must never block on the heap lock.
pub fn heap_stats() -> HeapStats {
    let bytes_allocated = STATS.bytes_allocated.load(Ordering::Relaxed);
    let bytes_deallocated = STATS.bytes_deallocated.load(Ordering::Relaxed);
    HeapStats {
        bytes_allocated,
        bytes_deallocated,
        alloc_count: STATS.alloc_count.load(Ordering::Relaxed),
        dealloc_count: STATS.dealloc_count.load(Ordering::Relaxed),
        current_bytes: bytes_allocated.saturating_sub(bytes_deallocated),
        peak_bytes: STATS.peak_bytes.load(Ordering::Relaxed),
        capacity: STATS.capacity.load(Ordering::Relaxed),
    }
}

// ---------------------------------------------------------------------------
// Kmalloc trait
// ---------------------------------------------------------------------------

/// A kernel-style typed allocation API layered on top of [`GlobalAlloc`].
///
/// `GlobalAlloc` is the low-level trait the `alloc` crate calls; `Kmalloc` is
/// the ergonomic surface kernel code reaches for when it wants a `Result`-
/// returning allocation (rather than a nullable raw pointer) or a typed
/// resize. It is implemented for [`LockedHeap`] by forwarding to the same
/// `GlobalAlloc` methods, so there is exactly one allocator implementation
/// behind both surfaces.
///
/// All methods take `&self` because the allocator is a single global static;
/// callers obtain it via [`global_allocator`] or `&ALLOCATOR`.
pub trait Kmalloc {
    /// Allocate `layout.size()` bytes at `layout.align()`.
    ///
    /// Returns a non-null pointer on success, or [`AllocError`] if the heap
    /// is exhausted or not yet initialised. The returned pointer is valid
    /// until passed to [`Kmalloc::kfree`].
    fn kmalloc(&self, layout: Layout) -> Result<NonNull<u8>, AllocError>;

    /// Free a pointer returned by [`kmalloc`](Self::kmalloc).
    ///
    /// # Safety
    ///
    /// `ptr` must be a live allocation returned by `kmalloc` with exactly
    /// `layout`, and must not be used after this call.
    unsafe fn kfree(&self, ptr: NonNull<u8>, layout: Layout);

    /// Resize an allocation in place if possible, else allocate a new block,
    /// copy the preserved prefix, and free the old block.
    ///
    /// # Safety
    ///
    /// `ptr` must be a live allocation of `old_layout`. The first
    /// `min(old_layout.size(), new_size)` bytes are preserved.
    unsafe fn krealloc(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_size: usize,
    ) -> Result<NonNull<u8>, AllocError>;

    /// Convenience: the current heap statistics snapshot.
    fn stats(&self) -> HeapStats {
        heap_stats()
    }
}

impl Kmalloc for LockedHeap {
    fn kmalloc(&self, layout: Layout) -> Result<NonNull<u8>, AllocError> {
        // SAFETY: `GlobalAlloc::alloc` is safe to call — it returns a null
        // pointer on failure rather than a dangling one, so the NonNull
        // construction below is the only unsafe step and it is guarded by the
        // null check.
        let p = unsafe { <Self as GlobalAlloc>::alloc(self, layout) };
        NonNull::new(p).ok_or(AllocError::OutOfMemory)
    }

    unsafe fn kfree(&self, ptr: NonNull<u8>, layout: Layout) {
        // SAFETY: forwarded to `GlobalAlloc::dealloc` with the caller's
        // guarantee that `ptr`/`layout` came from a matching `alloc`.
        unsafe {
            <Self as GlobalAlloc>::dealloc(self, ptr.as_ptr(), layout);
        }
    }

    unsafe fn krealloc(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_size: usize,
    ) -> Result<NonNull<u8>, AllocError> {
        // SAFETY: caller guarantees `ptr` is a live allocation of `old_layout`.
        let p = unsafe { <Self as GlobalAlloc>::realloc(self, ptr.as_ptr(), old_layout, new_size) };
        NonNull::new(p).ok_or(AllocError::OutOfMemory)
    }
}

// ---------------------------------------------------------------------------
// Heap bootstrap: claim a physical range and map it via the HHDM
// ---------------------------------------------------------------------------

/// The default heap size: 32 MiB. Large enough for the kernel's working set
/// during early bring-up (VFS caches, scheduler structures, driver state) and
/// small enough that it fits in the smallest RAM configuration Xenith targets
/// (256 MiB VMs). Tunable by editing this constant; no runtime knob exists
/// because the heap is carved before the frame allocator exists.
pub const HEAP_SIZE: usize = 32 * 1024 * 1024;

/// The minimum usable region size we will claim the heap from. We require some
/// headroom above [`HEAP_SIZE`] so the frame allocator still gets frames from
/// the same region after we carve our chunk.
const HEAP_REGION_MIN: u64 = (HEAP_SIZE as u64) + 16 * 1024 * 1024;

/// The physical range claimed for the kernel heap, set by [`init_heap`].
///
/// `None` before `init_heap` runs; `Some((phys_start, byte_len))` once the
/// heap has been carved out of the memory map. The frame allocator reads this
/// via [`heap_phys_claim`] to skip the range and avoid double-allocating the
/// heap's backing frames.
static HEAP_PHYS_CLAIM: spin::once::Once<(PhysAddr, u64)> = spin::once::Once::new();

/// Returns the physical `[start, len)` range claimed for the kernel heap, or
/// `None` before [`init_heap`] has run.
///
/// The frame allocator must not hand out frames in this range: they back the
/// heap's virtual region through the HHDM direct map and would be corrupted by
/// any other mapping. Reading is lock-free (the value is written exactly once
/// during boot and never changes afterwards).
pub fn heap_phys_claim() -> Option<(PhysAddr, u64)> {
    HEAP_PHYS_CLAIM.get().copied()
}

/// Pick the best usable memory region for the heap.
///
/// "Best" is the largest usable region, because a larger region leaves more
/// leftover frames for the frame allocator after the heap carves its chunk.
/// Returns `None` if no usable region is at least [`HEAP_REGION_MIN`] bytes.
fn pick_heap_region(boot: &BootInfo) -> Option<MemoryRegion> {
    boot.memory_map()
        .filter(|r| r.is_usable())
        .filter(|r| r.len >= HEAP_REGION_MIN)
        .max_by_key(|r| r.len)
}

/// Bring up the kernel heap.
///
/// Called once from `mm::init` after the Limine memory map is available. It:
///
/// 1. Finds the largest usable physical region (at least [`HEAP_REGION_MIN`]).
/// 2. Carves [`HEAP_SIZE`] bytes off the *end* of that region for the heap —
///    carving from the end leaves the low frames of the region for the frame
///    allocator, which is the more natural allocation direction.
/// 3. Records the claim in [`HEAP_PHYS_CLAIM`] so the frame allocator can
///    skip it.
/// 4. Computes the HHDM virtual address of the carved range and binds the
///    global [`LockedHeap`] to it.
///
/// The HHDM direct map Limine set up makes step 4 pure arithmetic: every
/// physical byte is already mapped at `hhdm_offset + phys`, so the heap is
/// reachable the instant we know its physical base. No page tables are
/// allocated here, which is why the heap can come up before the page-table
/// allocator.
///
/// # Panics
///
/// Panics if no usable region is large enough to hold the heap. A kernel
/// without 32 MiB of contiguous usable RAM cannot boot — there is no
/// fallback.
pub fn init_heap(boot_info: &'static limine::BootInfo) {
    let boot = BootInfo::new(boot_info);

    let region = pick_heap_region(&boot).unwrap_or_else(|| {
        panic!(
            "xenith.mm.heap: no usable memory region >= {} bytes for the heap",
            HEAP_REGION_MIN
        );
    });

    // Carve from the end of the region: claim_phys = region.end - HEAP_SIZE.
    // Carving from the end leaves the lower frames of the region for the frame
    // allocator, which is the more natural allocation direction.
    let region_end = region
        .end()
        .unwrap_or_else(|| panic!("xenith.mm.heap: usable region end overflows PhysAddr"));
    // `region_end - HEAP_SIZE` is a bare physical address with no flag bits, so
    // `PhysAddr::new` always returns `Some`; the expect documents that invariant.
    let claim_phys = PhysAddr::new(region_end.as_u64() - HEAP_SIZE as u64)
        .expect("heap claim physical address is within 52-bit space");
    let claim_len = HEAP_SIZE as u64;

    // Publish the claim so the frame allocator (initialised after the heap) can
    // skip this physical range. `Once` is written exactly once during boot and
    // read by `heap_phys_claim` thereafter; `call_once` is the spin crate's
    // one-shot initialiser and a second call would simply return the stored
    // value, which is what we want.
    HEAP_PHYS_CLAIM.call_once(|| (claim_phys, claim_len));

    // Translate the carved physical range through the HHDM direct map. Limine
    // guarantees the entire physical address space is direct-mapped at this
    // offset, so the resulting virtual range is writable and kernel-accessible
    // with no further setup.
    let heap_virt = boot.phys_to_virt(claim_phys);
    let heap_base = heap_virt.as_u64() as *mut u8;

    // Bind the global heap. SAFETY: `[heap_base, heap_base + HEAP_SIZE)` is
    // the HHDM mapping of the carved physical range, which Limine guarantees
    // is valid, writable, mapped kernel memory for the program's lifetime and
    // is not referenced by anything else (we just carved it out of the free
    // pool and the frame allocator will respect `heap_phys_claim`).
    unsafe {
        ALLOCATOR.init(heap_base, HEAP_SIZE);
    }
    STATS.capacity.store(HEAP_SIZE, Ordering::Relaxed);

    ::log::info!(
        "xenith.mm.heap: {} KiB heap at virt:{:#x} (phys:{:#x})",
        HEAP_SIZE / 1024,
        heap_virt.as_u64(),
        claim_phys.as_u64()
    );
}
