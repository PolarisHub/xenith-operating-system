//! Memory management subsystem root: physical frames, virtual paging, heap.
//!
//! This module is the top of the Xenith memory subsystem. It owns the boot
//! sequence that brings physical, virtual, and heap allocation online, and it
//! exposes the kernel-wide [`phys_to_virt`] / [`virt_to_phys`] helpers that
//! every other subsystem uses to translate between physical addresses and the
//! higher-half direct map (HHDM) Limine set up.
//!
//! # Submodules
//!
//! * [`physical`] — physical frame allocator. Consumes the Limine memory map
//!   and hands out 4 KiB frames.
//! * [`r#virtual`] — kernel page tables and virtual-memory management. Adopts
//!   the Limine-provided PML4 and provides map/unmap primitives. (The module
//!   is named `virtual` on disk but `virtual` is a Rust reserved keyword, so
//!   it is declared and referenced as `r#virtual`.)
//! * [`heap`] — the kernel heap. Backed by frames from [`physical`]; after
//!   [`heap::init`] the `alloc` crate (`Box`, `Vec`, `String`) is usable.
//! * [`allocator`] — the `#[global_allocator]` registration that routes
//!   `alloc::alloc` calls to the heap.
//! * [`kmalloc`] — safe facade: [`kmalloc::Kbox`], [`kmalloc::KVec`],
//!   [`kmalloc::KString`] aliases, raw [`kmalloc::kmalloc`] /
//!   [`kmalloc::kfree`] helpers, and the [`kmalloc::HeapStats`] accessor.
//!
//! # Layering
//!
//! `mm` sits above `arch` (for CR3 / page-table instructions) and `sync`
//! (for the locks that protect the frame bitmap and page tables) and below
//! every subsystem that allocates. The `alloc` crate is linked here, in this
//! module, so the kernel only gains heap access after [`init`] runs — every
//! earlier boot step is `no_alloc`.
//!
//! # Boot sequence
//!
//! [`init`] runs the three submodule initialisers in order — physical, then
//! virtual, then heap — and logs at each step. The order is load-bearing:
//!
//! 1. **physical** must come first: both the virtual mapper and the heap need
//!    free frames before they can build page tables or heap backing store.
//! 2. **virtual** adopts the kernel page tables and prepares map/unmap; it
//!    needs the frame allocator to allocate any new page-table pages it must
//!    create.
//! 3. **heap** carves a heap region out of mapped kernel virtual space, backs
//!    it with frames from [`physical`], and registers the global allocator.
//!    Only after this can `Box` / `Vec` / `String` be used.
//!
//! # HHDM direct map
//!
//! Limine maps all physical memory at a fixed offset (`0xFFFF_8000_0000_0000`
//! on typical configs) so the kernel can reach any physical byte without
//! allocating page tables. [`init`] captures that offset once; afterwards
//! [`phys_to_virt`] is a single add. The offset is stored in an atomic so the
//! helper is lock-free and safe to call from any context, including interrupt
//! handlers and the panic path.

// Link the `alloc` crate here, at the mm root, so the kernel gains heap
// access exactly when this subsystem comes online. The declaration is visible
// to every descendant module (physical, heap, allocator, kmalloc, ...), so
// they can all name `alloc::boxed::Box` etc. without their own `extern crate`.
extern crate alloc;

pub mod allocator;
pub mod heap;
pub mod kmalloc;
pub mod physical;
// `virtual` is a Rust reserved keyword (reserved for future use), so the
// module must be declared and referenced through the raw-identifier escape
// `r#virtual`. The on-disk directory is still `mm/virtual/` — file paths do
// not care about Rust keywords; only the identifier in source does.
pub mod r#virtual;

// Re-export the common heap-backed collection aliases and the stats accessor
// at the mm root so the rest of the kernel can write `use crate::mm::Kbox`
// without drilling into the kmalloc submodule.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub use kmalloc::{heap_stats, HeapStats, KString, KVec, Kbox};
use xenith_boot::BootInfo;
use xenith_types::{PhysAddr, VirtAddr};

/// The HHDM direct-map offset, captured once during [`init`].
///
/// Stored as a raw `u64` so [`phys_to_virt`] / [`virt_to_phys`] are lock-free.
/// Before [`init`] runs this is `0`; since the real HHDM base is always in
/// the kernel upper half (`0xFFFF_8000_0000_0000` and above), `0` is a
/// reliable "not yet initialised" sentinel.
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// `true` once [`init`] has completed all three submodule bring-up steps.
///
/// Used by [`is_initialized`] so callers that need the heap can assert it is
/// ready rather than silently allocating into an uninitialised allocator.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Translate a physical address to a virtual address through the HHDM.
///
/// This is pure arithmetic — `virt = hhdm_offset + phys` — and does not
/// allocate page tables. It presumes the HHDM direct map covers the full
/// physical address space, which Limine guarantees for the regions the kernel
/// touches.
///
/// # Panics
///
/// Panics if [`init`] has not yet run (the HHDM offset is still `0`). Every
/// physical address the kernel holds was either handed to it by Limine (after
/// the HHDM is up) or allocated by [`physical`] (after [`init`]), so a call
/// before `init` is a logic bug and should fail loudly rather than silently
/// produce a garbage direct-map address.
#[inline]
#[must_use]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    let off = HHDM_OFFSET.load(Ordering::Acquire);
    if off == 0 {
        panic!("mm::phys_to_virt called before mm::init");
    }
    // wrapping_add is sound: the HHDM base is a canonical upper-half address
    // and the physical offset is below 2^52, so the sum cannot overflow u64.
    // new_truncate canonicalises the result (already canonical, but the call
    // is cheap and keeps the invariant explicit).
    VirtAddr::new_truncate(off.wrapping_add(phys.as_u64()))
}

/// Translate an HHDM-mapped virtual address back to a physical address.
///
/// The inverse of [`phys_to_virt`]: `phys = virt - hhdm_offset`. The caller
/// must ensure `virt` actually lies in the HHDM range; an address outside the
/// direct map will underflow and produce a bogus physical address. This is
/// the caller's responsibility because a correct check requires knowing the
/// physical memory size, which is not stored here.
///
/// # Panics
///
/// Panics if [`init`] has not yet run, for the same reason as [`phys_to_virt`].
#[inline]
#[must_use]
pub fn virt_to_phys(virt: VirtAddr) -> PhysAddr {
    let off = HHDM_OFFSET.load(Ordering::Acquire);
    if off == 0 {
        panic!("mm::virt_to_phys called before mm::init");
    }
    // wrapping_sub: a virt below the HHDM base would underflow, but callers
    // are expected to only pass HHDM-mapped addresses; the wrapping result is
    // then masked into the 52-bit physical space by new_truncate.
    PhysAddr::new_truncate(virt.as_u64().wrapping_sub(off))
}

/// The HHDM direct-map offset, as captured during [`init`].
///
/// Returns [`VirtAddr::zero`] if [`init`] has not run; callers that need a
/// valid offset should check [`is_initialized`] first.
#[inline]
#[must_use]
pub fn hhdm_offset() -> VirtAddr {
    VirtAddr::new_truncate(HHDM_OFFSET.load(Ordering::Acquire))
}

/// Returns `true` once [`init`] has brought all three mm submodules online.
///
/// Use this to guard code that requires the heap (e.g. asserting before a
/// `Kbox::new` in a path that could theoretically run early). Before [`init`]
/// returns, this is `false` and `alloc` is not usable.
#[inline]
#[must_use]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

/// Bring the memory subsystem online.
///
/// Runs the three submodule initialisers in dependency order — physical frame
/// allocator, virtual memory / kernel page tables, kernel heap — and logs at
/// each step so a boot that hangs prints a trail up to the hang point. After
/// this returns, `alloc::boxed::Box`, `alloc::vec::Vec`, and
/// `alloc::string::String` are usable.
///
/// Each submodule receives the safe [`BootInfo`] wrapper (which is `Copy`: it
/// is just a `&'static limine::BootInfo`), so the submodules do not have to
/// re-wrap the raw Limine pointer.
///
/// This function is called exactly once from [`crate::init`] and must not be
/// re-entered. It panics if any submodule initialiser fails, since a kernel
/// without working memory management cannot continue.
pub fn init(boot_info: &'static limine::BootInfo) {
    let bi = BootInfo::new(boot_info);

    // Capture the HHDM offset first so phys_to_virt is usable by the heap and
    // virtual initialisers below (they may need to translate frame addresses
    // back into the direct map to seed their own bookkeeping). The Release
    // store pairs with the Acquire load in phys_to_virt.
    let hhdm = bi.hhdm_offset();
    HHDM_OFFSET.store(hhdm.as_u64(), Ordering::Release);
    ::log::info!("mm: HHDM direct map @ {:#018x}", hhdm.as_u64());

    // 1. Reserve and bind the HHDM-backed kernel heap. Publishing the
    // physical claim before constructing the frame bitmap prevents those
    // frames from ever entering the free pool.
    ::log::info!("mm.heap: reserving HHDM-backed kernel heap");
    allocator::init_heap(boot_info);
    ::log::info!("mm.heap: kernel heap online (Box/Vec/String available)");

    // 2. Physical frame allocator.
    // Consumes the Limine memory map and builds the frame bitmap. Until this
    // runs there is no way to obtain a free physical frame, so both the
    // virtual mapper and the heap (which need page tables and backing frames
    // respectively) must wait for it.
    ::log::info!("mm.physical: initialising frame allocator from memory map");
    physical::init(bi);
    ::log::info!("mm.physical: frame allocator online");

    // 3. Virtual memory / kernel page tables.
    // Adopts the Limine-provided PML4 as the kernel address space and
    // prepares the map/unmap primitives. Needs the frame allocator to
    // allocate any new page-table pages it must create.
    ::log::info!("mm.virtual: adopting kernel page tables");
    r#virtual::init(bi);
    ::log::info!("mm.virtual: kernel page tables ready");

    INITIALIZED.store(true, Ordering::Release);
    ::log::info!("mm: subsystem online");
}
