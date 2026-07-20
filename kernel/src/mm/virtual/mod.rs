//! Virtual memory: page tables, the active mapper, and address spaces.
//!
//! This is the `mm::virtual` submodule (spelled `r#virtual` at the call site
//! because `virtual` is a reserved Rust keyword). It owns the three pieces of
//! Xenith's paging layer:
//!
//! * [`page_table`] — the hardware data structures: [`PageTableEntry`],
//!   [`PageTable`], the [`PageTableFlags`] bit set, and the
//!   `VirtAddr -> four 9-bit indices` arithmetic. Pure data, no pointer
//!   dereference.
//! * [`paging`] — the active-table [`Mapper`]: `map`, `unmap`, `map_range`,
//!   `translate`, and [`active_p4_phys`]. Holds a PML4 frame and reaches table
//!   memory through the HHDM direct map, so it edits tables without allocating
//!   kernel virtual address space.
//! * [`address_space`] — the per-process [`AddressSpace`] type and the
//!   higher-half direct-map helpers (`phys_to_virt` / `virt_to_phys` with an
//!   early-boot fallback, the `HIGHER_HALF` / `USER_MAX` layout constants, and
//!   the global frame-allocator registry). This is the layer `sched` and
//!   `user` build on; `paging` is the lower-level primitive beneath it.
//!
//! # Initialisation
//!
//! [`init`] runs once from [`crate::mm::init`] after the HHDM offset has been
//! captured at the `mm` root. It records the HHDM offset into the
//! `address_space` submodule (which keeps its own copy so its `phys_to_virt`
//! fallback works even before `mm::init` finishes), adopts the running CR3 as
//! the kernel mapper, and logs. After [`init`] returns, the kernel can
//! [`Mapper::map`] / [`Mapper::unmap`] against the live tables.
//!
//! # Layering note
//!
//! `page_table` and `paging` are the lower layer; `address_space` is the
//! higher layer. `paging` depends on `page_table` (for the entry/table types
//! and index arithmetic) and on `crate::mm::phys_to_virt` (for the HHDM). It
//! deliberately does *not* depend on `address_space`, so the lower layer stays
//! free of process-model concerns. `address_space` keeps its own parallel
//! `PageTableEntry` / `PageTable` types and HHDM storage so it can be developed
//! and tested independently; a future consolidation pass will unify the two
//! representations behind the `page_table` definitions.

pub mod address_space;
pub mod page_table;
pub mod paging;

// Flat re-exports so callers can write
// `use crate::mm::r#virtual::{Mapper, PageTableFlags, PageTableEntry};`
// without drilling into submodules. The submodule paths stay available.
pub use address_space::{
    init_hhdm, phys_to_virt as hhdm_phys_to_virt, virt_to_phys as hhdm_virt_to_phys, AddressSpace,
    HIGHER_HALF, USER_MAX,
};
pub use page_table::{
    index_for, indices, p1_index, p2_index, p3_index, p4_index, PageTable, PageTableEntry,
    PageTableFlags,
};
pub use paging::{active_p4_phys, CachePolicyError, FrameAllocator, MapError, Mapper, UnmapError};
use xenith_boot::BootInfo;

/// Bring the virtual-memory subsystem online.
///
/// Called once from [`crate::mm::init`] *after* the `mm` root has captured the
/// HHDM offset (so [`crate::mm::phys_to_virt`] is usable). The steps are:
///
/// 1. Record the HHDM offset into [`address_space`] via [`init_hhdm`]. The
///    `address_space` submodule keeps its own copy of the offset so its
///    `phys_to_virt` fallback (`HIGHER_HALF`) works even before this call, but
///    the real value must be installed for correctness once the boot info is
///    available.
/// 2. Adopt the running CR3 as the kernel [`Mapper`]. This does not mutate any
///    tables — it merely reads CR3 and wraps the PML4 frame — but it confirms
///    that the active root is reachable through the HHDM and logs it for boot
///    diagnostics.
///
/// After this returns, the kernel may call [`Mapper::map`] / [`Mapper::unmap`]
/// on the active mapper to extend or modify the live kernel address space.
pub fn init(bi: BootInfo) {
    // 1. Install the HHDM offset into the address_space submodule. The value
    // is the same one `mm::init` already stored at the mm root; we pass it
    // verbatim so the two stores agree. `init_hhdm` panics on a second call,
    // which catches a double-init wiring bug at the first boot.
    let hhdm = bi.hhdm_offset().as_u64();
    init_hhdm(hhdm);
    ::log::debug!(
        "xenith.mm.virtual: address_space HHDM offset installed = {:#018x}",
        hhdm
    );

    // 2. Adopt the running CR3 as the kernel mapper. This is a read-only
    // probe: we read CR3, wrap the PML4 frame, and log it. The mapper edits
    // the *live* tables the CPU is walking, so any later `map`/`unmap` is
    // effective immediately (after `invlpg`). We do not switch address spaces
    // here — Limine's initial PML4 is the kernel address space and stays
    // active.
    let mapper = Mapper::active();
    ::log::info!(
        "xenith.mm.virtual: kernel mapper adopted, PML4 @ {:?}",
        mapper.p4_frame()
    );

    // Linear scanout is a write-mostly MMIO workload. On PAT-capable CPUs,
    // split only the direct-map pages covering the boot framebuffer and mark
    // their 4 KiB leaves write-combining. This avoids uncached/WB store stalls
    // without changing the cache policy of ordinary RAM. The operation runs
    // before AP startup, so the active table has a single mutator.
    if let Some(framebuffer) = bi.framebuffer() {
        if crate::arch::x86_64::framebuffer_write_combining_available() {
            let virtual_start = bi.phys_to_virt(framebuffer.phys_addr);
            match mapper.set_write_combining_range(
                virtual_start,
                framebuffer.phys_addr,
                framebuffer.size,
                &crate::mm::physical::GLOBAL_FRAME_ALLOCATOR,
            ) {
                Ok(pages) => ::log::info!(
                    "xenith.mm.virtual: framebuffer write-combining enabled ({} pages)",
                    pages
                ),
                Err(error) => ::log::warn!(
                    "xenith.mm.virtual: framebuffer WC unavailable ({:?}); retaining loader cache policy",
                    error
                ),
            }
        } else {
            ::log::warn!(
                "xenith.mm.virtual: CPU has no PAT; retaining loader framebuffer cache policy"
            );
        }
    }
}
