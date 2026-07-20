//! Physical frame allocation.
//!
//! The global allocator is protected by a spin lock because page-table
//! allocation can occur on any CPU. Its bitmap lives in physical memory
//! selected from the boot map, so this module requires neither the heap nor a
//! fixed maximum RAM size during early bring-up.

pub mod bitmap;
pub mod buddy;

use alloc::vec::Vec;
use core::arch::asm;

use bitmap::ProtectedFrameRange;
pub use bitmap::{BitmapFrameAllocator, BitmapInitError, DeallocateError, ReclaimReport};
use xenith_boot::BootInfo;
use xenith_types::{Page, PhysAddr, PhysFrame, VirtAddr};

use crate::sync::SpinLock;

/// The one physical allocator used by the kernel.
pub static FRAME_ALLOCATOR: SpinLock<Option<BitmapFrameAllocator>> = SpinLock::new(None);

/// Stable trait object registered with the address-space layer.
///
/// Keeping the proxy separate from the lock makes the public allocator
/// implementation independent of either of the virtual-memory module's
/// temporary frame-allocator traits.
pub struct GlobalFrameAllocator;

pub static GLOBAL_FRAME_ALLOCATOR: GlobalFrameAllocator = GlobalFrameAllocator;

struct ProtectedRanges {
    entries: Vec<ProtectedFrameRange>,
}

impl ProtectedRanges {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn push(&mut self, range: ProtectedFrameRange) -> Option<()> {
        self.entries.try_reserve(1).ok()?;
        self.entries.push(range);
        Some(())
    }

    fn as_slice(&self) -> &[ProtectedFrameRange] {
        &self.entries
    }
}

unsafe extern "C" {
    static __kernel_start: u8;
    static __kernel_end: u8;
}

/// Initialise the global bitmap from Limine's memory map.
pub fn init(boot_info: BootInfo) {
    // Check the one-shot invariant before constructing the allocator: its
    // bitmap owns a `'static` mutable HHDM slice, so a second construction
    // over the same boot map would already be invalid before assignment.
    let mut slot = FRAME_ALLOCATOR.lock();
    assert!(slot.is_none(), "mm.physical: allocator initialised twice");
    // SAFETY: the empty global slot proves this boot map has not already
    // supplied bitmap storage, and `BitmapFrameAllocator` reserves its chosen
    // pages before exposing any allocation operation.
    let allocator = unsafe { BitmapFrameAllocator::from_boot_info(boot_info) }
        .unwrap_or_else(|error| panic!("mm.physical: {error}"));
    let capacity = allocator.capacity();
    let total = allocator.total_frames();

    *slot = Some(allocator);
    drop(slot);

    crate::mm::r#virtual::address_space::register_frame_allocator(&GLOBAL_FRAME_ALLOCATOR);
    ::log::info!(
        "mm.physical: bitmap tracks {} frames, {} allocatable ({} MiB)",
        total,
        capacity,
        capacity.saturating_mul(PhysFrame::SIZE) / (1024 * 1024),
    );
}

/// Allocate one physical frame from the global allocator.
#[inline]
#[must_use]
pub fn allocate_frame() -> Option<PhysFrame> {
    FRAME_ALLOCATOR
        .lock()
        .as_mut()
        .and_then(BitmapFrameAllocator::allocate_frame)
}

/// Allocate one physical frame below an exclusive address limit.
///
/// Used by x86 AP startup, whose SIPI trampoline must live in conventional
/// memory. The selected frame remains an ordinary allocator allocation and
/// is therefore never aliased with firmware, bitmap, or heap reservations.
#[inline]
#[must_use]
pub fn allocate_frame_below(exclusive_limit: PhysAddr) -> Option<PhysFrame> {
    FRAME_ALLOCATOR
        .lock()
        .as_mut()
        .and_then(|allocator| allocator.allocate_frame_below(exclusive_limit))
}

/// Allocate a physically contiguous run and return its first frame.
#[inline]
#[must_use]
pub fn allocate_range(count: usize) -> Option<PhysFrame> {
    FRAME_ALLOCATOR
        .lock()
        .as_mut()
        .and_then(|allocator| allocator.allocate_range(count))
}

/// Return one frame to the global allocator.
pub fn deallocate(frame: PhysFrame) -> Result<(), DeallocateError> {
    let mut slot = FRAME_ALLOCATOR.lock();
    let allocator = slot.as_mut().ok_or(DeallocateError::OutOfRange)?;
    allocator.deallocate(frame)
}

/// Return a contiguous run to the global allocator.
pub fn deallocate_range(first: PhysFrame, count: usize) -> Result<(), DeallocateError> {
    let mut slot = FRAME_ALLOCATOR.lock();
    let allocator = slot.as_mut().ok_or(DeallocateError::OutOfRange)?;
    allocator.deallocate_range(first, count)
}

/// Snapshot the number of currently free frames.
#[must_use]
pub fn free_count() -> u64 {
    FRAME_ALLOCATOR
        .lock()
        .as_ref()
        .map_or(0, BitmapFrameAllocator::free_count)
}

/// Snapshot the number of frames currently checked out.
#[must_use]
pub fn used_count() -> u64 {
    FRAME_ALLOCATOR
        .lock()
        .as_ref()
        .map_or(0, BitmapFrameAllocator::used_count)
}

/// Reclaim loader-owned RAM after the VFS has copied the initramfs and no
/// subsystem retains boot-info metadata.
///
/// Legacy Limine handoffs are deliberately excluded: Xenith does not control
/// where those loaders place the active page tables and boot stack. For the
/// native protocol, the kernel protects its mapped image, the complete
/// normalized regions containing CR3 and the current stack, every module, and
/// the framebuffer before releasing any disjoint bootloader region.
pub fn reclaim_bootloader_memory(boot_info: BootInfo) -> ReclaimReport {
    if !crate::boot::has_native_handoff() {
        ::log::info!("mm.physical: retaining bootloader memory for legacy handoff provenance");
        return ReclaimReport::default();
    }
    let Some(protected) = build_reclaim_protection(boot_info) else {
        ::log::warn!("mm.physical: bootloader-memory ownership proof incomplete; retaining it");
        return ReclaimReport::default();
    };

    let mut slot = FRAME_ALLOCATOR.lock();
    let Some(allocator) = slot.as_mut() else {
        return ReclaimReport::default();
    };
    let report = allocator.reclaim_bootloader(protected.as_slice());
    if report.already_reclaimed {
        ::log::debug!("mm.physical: bootloader memory was already reclaimed");
    } else {
        ::log::info!(
            "mm.physical: reclaimed {} bootloader frames ({} KiB), retained {} protected frames",
            report.released_frames,
            report.released_frames.saturating_mul(PhysFrame::SIZE) / 1024,
            report.skipped_frames,
        );
    }
    report
}

fn build_reclaim_protection(boot_info: BootInfo) -> Option<ProtectedRanges> {
    let mapper = crate::mm::r#virtual::Mapper::active();
    let mut protected = ProtectedRanges::new();

    protected.push(kernel_image_frames(&mapper)?)?;
    for frame in active_page_table_frames(mapper.p4_frame())? {
        let start = frame.number();
        protected.push(ProtectedFrameRange::from_frames(
            start,
            start.checked_add(1)?,
        )?)?;
    }

    let stack_page = Page::containing_addr(VirtAddr::new_truncate(current_stack_pointer()));
    let stack_frame = mapper.translate(stack_page)?.0.number();
    protected.push(ProtectedFrameRange::from_frames(
        stack_frame,
        stack_frame.checked_add(1)?,
    )?)?;

    for module in boot_info.modules() {
        protected.push(ProtectedFrameRange::from_bytes(
            module.start.as_u64(),
            module.len,
        )?)?;
    }
    for framebuffer in boot_info.framebuffers() {
        protected.push(ProtectedFrameRange::from_bytes(
            framebuffer.phys_addr.as_u64(),
            framebuffer.size as u64,
        )?)?;
    }
    Some(protected)
}

fn active_page_table_frames(root: PhysFrame) -> Option<Vec<PhysFrame>> {
    const PRESENT: u64 = 1;
    const HUGE: u64 = 1 << 7;
    const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
    const ENTRIES: usize = 512;

    let mut discovered = Vec::new();
    let mut pending = Vec::new();
    pending.try_reserve(1).ok()?;
    pending.push((root, 4u8));

    while let Some((frame, level)) = pending.pop() {
        if discovered.contains(&frame) {
            continue;
        }
        discovered.try_reserve(1).ok()?;
        discovered.push(frame);
        if level == 1 {
            continue;
        }

        let table = crate::mm::phys_to_virt(frame.start_address()).as_u64() as *const u64;
        for index in 0..ENTRIES {
            // SAFETY: every pending frame came from a present non-leaf entry
            // in the active CR3 tree and the HHDM maps all physical RAM.
            let entry = unsafe { core::ptr::read_volatile(table.add(index)) };
            if entry & PRESENT == 0 || (level == 3 || level == 2) && entry & HUGE != 0 {
                continue;
            }
            let child = entry & ADDRESS_MASK;
            if child == 0 {
                return None;
            }
            pending.try_reserve(1).ok()?;
            pending.push((
                PhysFrame::containing_addr(PhysAddr::new_truncate(child)),
                level - 1,
            ));
        }
    }
    Some(discovered)
}

fn kernel_image_frames(mapper: &crate::mm::r#virtual::Mapper) -> Option<ProtectedFrameRange> {
    let start = core::ptr::addr_of!(__kernel_start) as u64;
    let end = core::ptr::addr_of!(__kernel_end) as u64;
    if start >= end {
        return None;
    }
    let first_page = Page::containing_addr(VirtAddr::new_truncate(start));
    let page_count = end
        .checked_add(Page::SIZE - 1)?
        .checked_sub(first_page.start_address().as_u64())?
        / Page::SIZE;
    let first_frame = mapper.translate(first_page)?.0.number();
    for offset in 0..page_count {
        let page = first_page + offset;
        if mapper.translate(page)?.0.number() != first_frame.checked_add(offset)? {
            return None;
        }
    }
    ProtectedFrameRange::from_frames(first_frame, first_frame.checked_add(page_count)?)
}

#[inline]
fn current_stack_pointer() -> u64 {
    let pointer: u64;
    // SAFETY: reading RSP is side-effect free and does not dereference it.
    unsafe {
        asm!(
            "mov {}, rsp",
            out(reg) pointer,
            options(nomem, nostack, preserves_flags)
        );
    }
    pointer
}

impl crate::mm::r#virtual::address_space::FrameAllocator for GlobalFrameAllocator {
    fn allocate(&self) -> Option<PhysFrame> {
        allocate_frame()
    }

    fn deallocate(&self, frame: PhysFrame) {
        if let Err(error) = deallocate(frame) {
            ::log::error!("mm.physical: rejected frame free {:?}: {}", frame, error);
        }
    }
}

impl crate::mm::r#virtual::paging::FrameAllocator for GlobalFrameAllocator {
    fn allocate(&self) -> Option<PhysFrame> {
        allocate_frame()
    }

    fn deallocate(&self, frame: PhysFrame) {
        if let Err(error) = deallocate(frame) {
            ::log::error!(
                "mm.physical: rejected page-table frame free {:?}: {}",
                frame,
                error
            );
        }
    }
}
