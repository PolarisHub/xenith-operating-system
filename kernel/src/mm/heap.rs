//! Kernel heap allocator: a fixed-size slab + coarse freelist over a reserved
//! virtual region.
//!
//! The heap owns a single contiguous byte range `[base, base + size)` of
//! already-mapped virtual memory and satisfies `GlobalAlloc` requests from it
//! with a two-tier allocator:
//!
//! * **Slab tier** — small allocations (up to [`MAX_SLAB_SIZE`]) are served
//!   from per-size-class segregated free lists. Each class is a power of two
//!   starting at 16 bytes; a free block carries its `next` pointer inline, so
//!   no external metadata is needed. When a class runs dry it is refilled by
//!   carving one slab run from the coarse tier and slicing it into
//!   class-sized blocks. Because blocks within a class are all the same size,
//!   no coalescing is needed or possible — a freed block simply goes back on
//!   the class list.
//!
//! * **Coarse tier** — allocations larger than [`MAX_SLAB_SIZE`] and all slab
//!   refills are carved from an address-ordered free list of variable-sized
//!   blocks. Each free block begins with an in-band [`FreeHeader`] carrying
//!   its size and `next` pointer; allocated blocks carry an [`AllocHeader`]
//!   immediately before the returned user pointer recording the block's full
//!   `[start, end)` extent, which is what makes `dealloc` able to coalesce the
//!   block back with its address-neighbours.
//!
//! # Alignment
//!
//! Every class size is a power of two and every slab run is carved from the
//! coarse tier with alignment equal to the class size, so slab-returned
//! pointers are naturally class-aligned — which is `>= layout.align()` by
//! construction (the class is chosen as `next_pow2(max(size, align))`).
//! Coarse allocations place the user pointer at an aligned offset inside the
//! carved block and record the block start in the header, so the alignment
//! slack before the user pointer is recovered on `dealloc`.
//!
//! # Locking
//!
//! The whole [`Heap`] is guarded by a [`SpinLockIRQ`](crate::sync::SpinLockIRQ)
//! so an interrupt handler that allocates cannot self-deadlock against a
//! half-held lock on the same CPU. The `GlobalAlloc` methods lock internally
//! and drop the guard before returning, so the `!Send` guard never escapes.
//!
//! # Safety
//!
//! All pointer arithmetic stays within `[base, end)` by construction: the
//! coarse free list only ever hands out sub-ranges of the initial region, and
//! slab runs are sub-allocations of coarse blocks. The `unsafe` blocks below
//! document which invariant each dereference relies on.

use core::alloc::Layout;
use core::mem::size_of;
use core::ptr::{self, NonNull};

use xenith_types::VirtAddr;

// `GlobalAlloc` and `Layout` live in `core::alloc`, so this file does not need
// `extern crate alloc` on its own. We pull `GlobalAlloc` through the
// `allocator` re-export so there is a single named source for the trait across
// the `mm` subtree, and reach the stat counters via the same sibling module.
use super::allocator::{record_alloc, record_dealloc, GlobalAlloc};
use crate::sync::SpinLockIRQ;

// ---------------------------------------------------------------------------
// Sizing constants
// ---------------------------------------------------------------------------

/// The smallest slab class. Must be at least `size_of::<FreeNode>()` (8 bytes
/// on 64-bit) so a free block can hold its own `next` pointer. We round up to
/// 16 to leave room for the allocator to store a small back-pointer or magic
/// if a future phase wants double-free detection, and because 16 is the
/// natural minimum alignment for most kernel structures.
pub const MIN_SLAB_SIZE: usize = 16;

/// The largest allocation served from the slab tier. Allocations whose class
/// exceeds this fall through to the coarse freelist. 16 KiB keeps the slab
/// tier covering the overwhelming majority of kernel allocations (Box<u64>,
/// Vec nodes, small Strings) while bounding the number of class freelists.
pub const MAX_SLAB_SIZE: usize = 16 * 1024;

/// How many blocks a slab refill carves at once. Refilling in batches amortises
/// the coarse-tier carving cost across many small allocations of the same size.
/// Eight is a modest batch: a 16-byte class refill costs 128 bytes of coarse
/// space, a 16 KiB class refill costs 128 KiB — both comfortable inside the
/// 32 MiB default heap.
const SLAB_REFILL_COUNT: usize = 8;

/// The slab size classes, ascending powers of two from [`MIN_SLAB_SIZE`] to
/// [`MAX_SLAB_SIZE`]. Stored as a `const` slice so `class_index` can binary-
/// search it; the array length is the number of class freelists in [`Heap`].
const SLAB_CLASSES: [usize; 11] = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16_384];

/// The number of slab classes, derived from [`SLAB_CLASSES`] so the array in
/// [`Heap`] is sized consistently without repeating the literal.
const NUM_CLASSES: usize = SLAB_CLASSES.len();

// ---------------------------------------------------------------------------
// Inline block headers
// ---------------------------------------------------------------------------

/// A node in a slab class free list.
///
/// Slab free blocks are all exactly `class_size` bytes, so the only metadata
/// they need is a single `next` pointer threaded through the first word of the
/// block. `FreeNode` is a `#[repr(C)]` overlay on those first bytes; it is
/// only ever read/written while the heap lock is held, so the shared mutation
/// is covered by the [`SpinLockIRQ`] critical section.
#[repr(C)]
struct FreeNode {
    next: Option<NonNull<FreeNode>>,
}

/// Header at the start of a free block in the coarse tier.
///
/// `size` is the total size of the free block in bytes, *including* this
/// header. `next` threads the coarse free list in ascending address order so
/// `dealloc` can find the address-neighbours of a freed block in one walk for
/// coalescing.
#[repr(C)]
struct FreeHeader {
    size: usize,
    next: Option<NonNull<FreeHeader>>,
}

/// Header immediately preceding a coarse-tier allocation's user pointer.
///
/// `block_start` is the absolute start of the carved coarse block (which may
/// be below the user pointer because of alignment padding) and `size` is the
/// block's total byte extent. On `dealloc` the allocator recovers both from
/// this header so it can return the full `[block_start, block_start + size)`
/// range to the coarse free list and coalesce it with its neighbours.
///
/// Laying the header *immediately before* the user pointer (rather than at the
/// block start) means `dealloc` can find it from the user pointer alone, with
/// no alignment arithmetic — the common case for `GlobalAlloc::dealloc`.
#[repr(C)]
struct AllocHeader {
    /// Absolute start of the coarse block this allocation was carved from.
    block_start: *mut u8,
    /// Total size of the coarse block, including this header and any
    /// alignment slack between `block_start` and the user pointer.
    size: usize,
}

// ---------------------------------------------------------------------------
// Slab class free list
// ---------------------------------------------------------------------------

/// The free list for a single slab size class.
///
/// `head` points to the first free block; each free block's first word holds
/// the `next` pointer (see [`FreeNode`]). All operations are O(1) push/pop.
/// The list is empty when `head` is `None`.
#[derive(Copy, Clone)]
struct SlabClass {
    head: Option<NonNull<FreeNode>>,
}

impl SlabClass {
    /// An empty slab class free list.
    const fn empty() -> Self {
        Self { head: None }
    }

    /// Pop a free block off this class, returning a pointer to its first byte.
    ///
    /// Returns `None` when the class is empty (the caller must then refill).
    /// The returned pointer is class-aligned by construction.
    #[inline]
    fn pop(&mut self) -> Option<NonNull<u8>> {
        let node = self.head?;
        // SAFETY: `node` points to a free block in this class's list. We hold
        // the heap lock, so no other accessor can race. We read the `next`
        // field to advance the head, then forget the node (its memory is now
        // handed to the caller).
        let next = unsafe { node.as_ref().next };
        self.head = next;
        // The block's first byte is the same address as the FreeNode overlay.
        // SAFETY: `node` is a non-null pointer we just read from the head; the
        // block it points to is live and remains valid until handed out.
        let user = unsafe { NonNull::new_unchecked(node.as_ptr() as *mut u8) };
        Some(user)
    }

    /// Push a freed block back onto this class's free list.
    ///
    /// `ptr` must point to a block of exactly this class's size that was
    /// previously handed out by [`SlabClass::pop`] (or a freshly sliced refill
    /// block). The block's first word is overwritten with the current head.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a live, class-sized block inside the heap region
    /// and no other reference to it may exist.
    #[inline]
    unsafe fn push(&mut self, ptr: NonNull<u8>) {
        let node = ptr.as_ptr() as *mut FreeNode;
        // SAFETY: caller guarantees `ptr` is a valid class-sized block; we
        // hold the heap lock so the write is unaliased.
        unsafe {
            (*node).next = self.head;
        }
        // SAFETY: `node` derives from the non-null `ptr`; the block is live.
        self.head = Some(unsafe { NonNull::new_unchecked(node) });
    }
}

// ---------------------------------------------------------------------------
// The heap
// ---------------------------------------------------------------------------

/// The unlocked heap state.
///
/// All fields are only touched while the [`SpinLockIRQ`] in [`LockedHeap`] is
/// held, so they are plain (non-atomic) values. `base`/`end` pin the reserved
/// region; `coarse` is the address-ordered free list of large variable blocks;
/// `slabs` holds the per-class free lists; `inited` gates use before
/// [`Heap::init`] has run.
pub struct Heap {
    /// Inclusive start of the reserved heap region. `null` until `init`.
    base: *mut u8,
    /// Exclusive end of the reserved heap region (`base + size`).
    end: *mut u8,
    /// Head of the coarse-tier free list, address-ordered. `None` when the
    /// coarse tier is exhausted.
    coarse: Option<NonNull<FreeHeader>>,
    /// Per-size-class free lists, indexed by [`class_index`].
    slabs: [SlabClass; NUM_CLASSES],
    /// `false` until [`Heap::init`] has been called. Allocations attempted
    /// before init return `null` (a `GlobalAlloc` alloc failure) rather than
    /// panicking, so early-boot code that accidentally allocates logs a
    /// clean out-of-memory instead of faulting.
    inited: bool,
}

// SAFETY: `Heap` holds raw pointers into the kernel heap region, which is
// private to this CPU's allocator. The `SpinLockIRQ` wrapper is the sole
// synchronisation boundary; moving a `Heap` across CPUs is meaningless (there
// is exactly one global heap) but not intrinsically unsafe because the raw
// pointers are to globally-mapped kernel memory, not thread-local storage.
// The auto traits are refused only because of the raw pointers; spell them
// out so `LockedHeap: Sync` can derive from `Heap: Send`.
unsafe impl Send for Heap {}
unsafe impl Sync for Heap {}

impl Heap {
    /// A heap with no backing region. All allocations fail until [`init`]
    /// wires up a real range.
    ///
    /// `const`-constructible so the [`LockedHeap`] can live in a `static`.
    const fn empty() -> Self {
        Self {
            base: core::ptr::null_mut(),
            end: core::ptr::null_mut(),
            coarse: None,
            slabs: [
                SlabClass::empty(),
                SlabClass::empty(),
                SlabClass::empty(),
                SlabClass::empty(),
                SlabClass::empty(),
                SlabClass::empty(),
                SlabClass::empty(),
                SlabClass::empty(),
                SlabClass::empty(),
                SlabClass::empty(),
                SlabClass::empty(),
            ],
            inited: false,
        }
    }

    /// Claim `[base, base + size)` as the heap region and seed the coarse free
    /// list with one giant free block covering the whole range.
    ///
    /// `base` must be writable kernel-mapped virtual memory of `size` bytes,
    /// `size` must be large enough to hold at least one [`FreeHeader`], and
    /// `base` must be aligned to at least `size_of::<FreeHeader>()`. Calling
    /// `init` twice is allowed: the second call discards the prior state and
    /// re-seeds from the new range (used only by hypothetical re-init paths,
    /// not the normal boot flow).
    ///
    /// # Safety
    ///
    /// The caller guarantees `[base, base + size)` is valid, writable, mapped
    /// kernel memory for the lifetime of the program and is not concurrently
    /// referenced by anything else. In practice this is the HHDM-mapped
    /// physical chunk [`allocator::init_heap`](super::allocator::init_heap)
    /// carves out of the Limine memory map.
    unsafe fn init(&mut self, base: *mut u8, size: usize) {
        self.base = base;
        self.end = base.wrapping_add(size);
        // Lay down a single free block covering the entire region. Its header
        // lives at `base`; the remainder is available to carve from.
        // SAFETY: `base` is valid for `size` bytes per the caller; writing a
        // `FreeHeader` at the start touches only `size_of::<FreeHeader>()`
        // bytes, which fits because the caller sized the region to hold one.
        unsafe {
            let hdr = base as *mut FreeHeader;
            (*hdr).size = size;
            (*hdr).next = None;
            self.coarse = Some(NonNull::new_unchecked(hdr));
        }
        self.inited = true;
    }

    /// Align a raw pointer up to `align` (power of two). Returns `None` on
    /// overflow or if the aligned address would pass `end`.
    #[inline]
    fn align_up_ptr(addr: *mut u8, align: usize, end: *mut u8) -> Option<*mut u8> {
        debug_assert!(align.is_power_of_two());
        let mask = align - 1;
        let raw = addr as usize;
        let aligned = raw.checked_add(mask)? & !mask;
        let p = aligned as *mut u8;
        if p > end {
            None
        } else {
            Some(p)
        }
    }

    // --- Slab tier --------------------------------------------------------

    /// Allocate `layout.size()` bytes with `layout.align()` from the slab tier.
    ///
    /// Returns `None` if the layout does not fit a slab class (caller should
    /// fall through to the coarse tier) or if the class is empty and the
    /// coarse tier cannot refill it.
    ///
    /// The returned pointer is class-aligned, which is `>= layout.align()`.
    fn slab_alloc(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let (idx, class) = class_index(&layout)?;
        loop {
            if let Some(p) = self.slabs[idx].pop() {
                return Some(p);
            }
            // Class is dry: carve a fresh slab run from the coarse tier and
            // slice it into class-sized blocks. If the coarse tier is
            // exhausted we cannot satisfy this allocation from the slab tier.
            // We request `class` alignment so the run starts on a class
            // boundary, which makes every sliced sub-block class-aligned.
            let (run, run_size) = self.coarse_alloc_raw(SLAB_REFILL_COUNT * class, class)?;
            // Slice the run into SLAB_REFILL_COUNT blocks and push them onto
            // the class free list. The first block will be popped on the next
            // iteration; the rest queue up for subsequent allocations. If the
            // carver returned a larger block (absorbed tail), the trailing
            // bytes are simply not sliced into blocks — they stay attached to
            // the last block as internal slack, which is reclaimed when the
            // run's blocks are freed back to the slab class.
            let _ = run_size;
            // SAFETY: `run` points to at least `SLAB_REFILL_COUNT * class`
            // bytes of fresh heap memory we just carved; each sub-block is
            // `class` bytes and class-aligned because `run` is class-aligned.
            unsafe {
                for i in 0..SLAB_REFILL_COUNT {
                    let block = run.as_ptr().add(i * class);
                    self.slabs[idx].push(NonNull::new_unchecked(block));
                }
            }
            // Loop: the pop at the top now succeeds.
        }
    }

    /// Return a slab-tier block to its class free list.
    ///
    /// `ptr` must have been returned by [`slab_alloc`](Self::slab_alloc) with
    /// the same `layout`. The block's first word is overwritten with the
    /// current class head.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a live slab allocation matching `layout` and must
    /// not be used after this call.
    unsafe fn slab_dealloc(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let (idx, _) = class_index(&layout)
            .expect("slab_dealloc on a layout that does not map to a slab class");
        // SAFETY: caller guarantees `ptr` is a slab block of this class.
        unsafe {
            self.slabs[idx].push(ptr);
        }
    }

    // --- Coarse tier ------------------------------------------------------

    /// Carve `size` bytes at `align` from the coarse free list and write an
    /// [`AllocHeader`] immediately before the aligned user pointer.
    ///
    /// Returns the user pointer (aligned to `align` and valid for `size`
    /// bytes), or `None` if no coarse block is large enough.
    ///
    /// The request to [`coarse_alloc_raw`] reserves room for the header plus
    /// alignment slack so the user pointer can be `align`-aligned even when
    /// `align` is larger than the header. The header records the true carved
    /// block `[start, start + block_size)` so [`coarse_dealloc`] can return
    /// the full range (including any tail absorbed by the raw carver) to the
    /// free list.
    fn coarse_alloc(&mut self, size: usize, align: usize) -> Option<NonNull<u8>> {
        // Reserve header + alignment slack. The carve start returned by
        // `coarse_alloc_raw` is `align`-aligned, so the user pointer is
        // `start + user_off` where `user_off` is the smallest multiple of
        // `align` that is >= `hdr_sz`. That is `max(align, hdr_sz)` because
        // `hdr_sz` (16) is already a multiple of every `align <= 16`.
        let hdr_sz = size_of::<AllocHeader>();
        let user_off = if align > hdr_sz { align } else { hdr_sz };
        let need = size + user_off;
        let (start, block_size) = self.coarse_alloc_raw(need, align)?;

        // `start` is `align`-aligned and `user_off` is a multiple of `align`,
        // so `user` is `align`-aligned by construction. The AllocHeader sits
        // in the `user_off - hdr_sz` bytes between `start` and `user`.
        // SAFETY: `user_off <= need <= block_size`, so `start + user_off` and
        // `start + user_off - hdr_sz` both lie within the carved block.
        let (user, hdr) = unsafe {
            let user = start.as_ptr().add(user_off);
            let hdr = user.sub(hdr_sz) as *mut AllocHeader;
            (user, hdr)
        };
        // SAFETY: `user` lies within `[start, start + block_size)` and `hdr`
        // lies within `[start, user)`. We hold the heap lock, so the writes
        // are unaliased.
        unsafe {
            (*hdr).block_start = start.as_ptr();
            (*hdr).size = block_size;
        }
        NonNull::new(user)
    }

    /// Carve `size` bytes at `align` from the coarse free list, returning the
    /// raw block start and its true size (no [`AllocHeader`] is written).
    ///
    /// This is the low-level carver used by both [`coarse_alloc`] (for user
    /// allocations, which then add a header) and [`slab_alloc`] (for refill
    /// runs, which slice the run themselves). The returned start is
    /// `align`-aligned and the block is at least `size` bytes; `block_size`
    /// may be larger when a too-small tail was absorbed to avoid fragmentation.
    ///
    /// Both the prefix before the aligned carve and the tail after the
    /// requested size are split back onto the free list when they are large
    /// enough to hold a [`FreeHeader`]; a too-small tail is absorbed into the
    /// returned block. Because the heap region is page-aligned and every
    /// split happens at a 16-byte boundary, the prefix is either zero or at
    /// least 16 bytes — so it is always splittable and never wasted.
    fn coarse_alloc_raw(&mut self, size: usize, align: usize) -> Option<(NonNull<u8>, usize)> {
        debug_assert!(align.is_power_of_two());
        let mut prev: Option<NonNull<FreeHeader>> = None;
        let mut cur = self.coarse;
        while let Some(block) = cur {
            // SAFETY: `block` is a live free header in the coarse list. We
            // hold the heap lock, so the list is stable while we walk it.
            let b_ptr = block.as_ptr();
            let (b_addr, b_size, b_next) =
                unsafe { (b_ptr as *mut u8, (*b_ptr).size, (*b_ptr).next) };

            // Fit an `align`-aligned carve of `size` bytes inside this block.
            let carve = Self::align_up_ptr(b_addr, align, self.end)?;
            let carve_end = carve.wrapping_add(size);
            if carve_end > b_addr.wrapping_add(b_size) {
                // Too small; try the next block.
                prev = Some(block);
                cur = b_next;
                continue;
            }

            let prefix = (carve as usize) - (b_addr as usize);
            let used = (carve_end as usize) - (b_addr as usize);
            let tail = b_size - used;

            // Split the prefix back as a free block. It is either zero (carve
            // == b_addr) or >= 16 because both ends are 16-aligned boundaries.
            if prefix >= size_of::<FreeHeader>() {
                // SAFETY: `[b_addr, carve)` is a valid 16-byte+ sub-block.
                let phdr = b_addr as *mut FreeHeader;
                unsafe {
                    (*phdr).size = prefix;
                    // `next` is overwritten by `link_after` below when the tail
                    // is spliced in (or set to `b_next` when the tail is
                    // absorbed); the placeholder keeps the node well-formed in
                    // the meantime.
                    (*phdr).next = Some(block);
                }
                // The prefix replaces `block` in the list position; `block`
                // is then removed (the tail, if any, is linked after it).
                // SAFETY: `phdr` derives from the non-null `b_addr` and points
                // at a sub-block we just validated.
                let pnode = unsafe { NonNull::new_unchecked(phdr) };
                Self::link_after(self, prev, Some(pnode));
                // From the prefix's perspective, its successor is the tail (or
                // the rest of the list). Fix that up below.
                prev = Some(pnode);
            }

            // Determine the returned block size: if the tail is too small to
            // hold a free header, absorb it into the allocation (round the
            // block size up); otherwise split the tail back onto the list.
            // `link_after` handles the `prev.is_none()` case by setting
            // `self.coarse`, so the head pointer stays consistent whether or
            // not a prefix was split.
            let mut block_size = size;
            if tail >= size_of::<FreeHeader>() + MIN_SLAB_SIZE {
                // SAFETY: `[carve_end, carve_end + tail)` is a valid sub-block.
                let thdr = carve_end as *mut FreeHeader;
                unsafe {
                    (*thdr).size = tail;
                    (*thdr).next = b_next;
                }
                // SAFETY: `thdr` is non-null (carve_end is within the region).
                let tnode = unsafe { NonNull::new_unchecked(thdr) };
                Self::link_after(self, prev, Some(tnode));
            } else {
                // Absorb the tail: the returned block extends to the end of
                // the original free block.
                block_size = size + tail;
                Self::link_after(self, prev, b_next);
            }

            return NonNull::new(carve).map(|p| (p, block_size));
        }
        None
    }

    /// Splice `node` into the coarse list after `prev` (or as the new head
    /// when `prev` is `None`). This is the write-side counterpart of the walk
    /// in [`coarse_alloc_raw`] and [`coarse_dealloc`].
    #[inline]
    fn link_after(&mut self, prev: Option<NonNull<FreeHeader>>, node: Option<NonNull<FreeHeader>>) {
        match prev {
            Some(p) => {
                // SAFETY: `p` is a live free header; we hold the heap lock.
                unsafe {
                    (*p.as_ptr()).next = node;
                }
            },
            None => self.coarse = node,
        }
    }

    /// Return a coarse-tier block to the free list, coalescing with its
    /// address-neighbours.
    ///
    /// The free list is address-ordered; this walks it once to find the
    /// insertion point (the last node whose start is below `block_start`),
    /// then coalesces with the successor and/or predecessor if adjacent. The
    /// successor is merged first (growing the to-be-inserted block), then the
    /// predecessor absorbs the grown block if adjacent — so a block that
    /// bridges both neighbours becomes a single coalesced block in one pass.
    ///
    /// # Safety
    ///
    /// `block_start`/`size` must describe a live coarse allocation previously
    /// carved by [`coarse_alloc`] (i.e. the values read from its
    /// [`AllocHeader`]), and the block must not be used after this call.
    unsafe fn coarse_dealloc(&mut self, block_start: *mut u8, size: usize) {
        let block_end = block_start.wrapping_add(size);

        // Walk to the insertion point: `prev` is the last node with start <
        // block_start; `cur` is the first node with start > block_start (the
        // successor), or None.
        let mut prev: Option<NonNull<FreeHeader>> = None;
        let mut cur = self.coarse;
        while let Some(node) = cur {
            // SAFETY: read-only walk under the heap lock.
            let n_ptr = node.as_ptr();
            if (n_ptr as *mut u8) as usize > block_start as usize {
                break;
            }
            prev = Some(node);
            cur = unsafe { (*n_ptr).next };
        }

        // Coalesce with the successor if it immediately follows the freed
        // block. `new_start`/`new_size` describe the (possibly grown) block we
        // are about to insert; `new_next` is what it should point at.
        let new_start = block_start;
        let mut new_size = size;
        let mut new_next = cur;
        if let Some(succ) = cur {
            let s_ptr = succ.as_ptr();
            let s_start = s_ptr as *mut u8;
            // SAFETY: `succ` is live; lock held.
            let s_size = unsafe { (*s_ptr).size };
            if s_start == block_end {
                // Absorb the successor into the freed block.
                new_size += s_size;
                new_next = unsafe { (*s_ptr).next };
            }
        }

        // Coalesce with the predecessor if it immediately precedes the freed
        // block. If so, the predecessor grows to cover the whole merged range
        // and we are done (no new header is inserted).
        if let Some(pred) = prev {
            let p_ptr = pred.as_ptr();
            let p_start = p_ptr as *mut u8;
            // SAFETY: `pred` is live; lock held.
            let p_size = unsafe { (*p_ptr).size };
            if p_start.wrapping_add(p_size) == block_start {
                // Absorb the freed block (plus any successor merge) into the
                // predecessor in place.
                unsafe {
                    (*p_ptr).size = p_size + new_size;
                    (*p_ptr).next = new_next;
                }
                return;
            }
        }

        // No predecessor merge: insert a fresh free header at `new_start`.
        // SAFETY: `new_start` is the start of the freed allocation (or the
        // start of the successor-merged region, which is the same address);
        // it holds at least `size_of::<FreeHeader>()` bytes because every
        // coarse allocation is >= MIN_SLAB_SIZE.
        let hdr = new_start as *mut FreeHeader;
        unsafe {
            (*hdr).size = new_size;
            (*hdr).next = new_next;
        }
        // SAFETY: `hdr` derives from `new_start`, which is a non-null pointer
        // into the heap region; the block is large enough for a FreeHeader.
        let node = unsafe { NonNull::new_unchecked(hdr) };
        Self::link_after(self, prev, Some(node));
    }

    // --- Top-level dispatch ----------------------------------------------

    /// Allocate `layout` from whichever tier fits.
    ///
    /// Returns a pointer valid for `layout.size()` bytes at `layout.align()`,
    /// or `None` if the heap is exhausted (or not yet initialised).
    fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        if !self.inited {
            return None;
        }
        if class_index(&layout).is_some() {
            self.slab_alloc(layout)
        } else {
            self.coarse_alloc(layout.size(), layout.align())
        }
    }

    /// Release a pointer previously returned by [`allocate`].
    ///
    /// # Safety
    ///
    /// `ptr` must be a live allocation returned by [`allocate`] with exactly
    /// `layout`, and must not be used after this call.
    unsafe fn deallocate(&mut self, ptr: NonNull<u8>, layout: Layout) {
        if class_index(&layout).is_some() {
            unsafe {
                self.slab_dealloc(ptr, layout);
            }
            return;
        }
        // Coarse: recover the block extent from the AllocHeader immediately
        // before the user pointer, then coalesce-insert it.
        // SAFETY: `ptr` came from coarse_alloc, which placed an AllocHeader
        // immediately before it; subtracting the header size lands inside the
        // carved block, and reading the header fields is sound under the heap
        // lock.
        let (block_start, size) = unsafe {
            let hdr = ptr.as_ptr().sub(size_of::<AllocHeader>()) as *const AllocHeader;
            ((*hdr).block_start, (*hdr).size)
        };
        unsafe {
            self.coarse_dealloc(block_start, size);
        }
    }

    /// Grow/shrink an allocation in place when possible, else alloc-copy-free.
    ///
    /// # Safety
    ///
    /// Same contract as [`GlobalAlloc::realloc`]: `ptr` must be a live
    /// allocation of `old_layout`, and the first `min(old_layout.size(),
    /// new_layout.size())` bytes must be preserved.
    unsafe fn reallocate(
        &mut self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_size: usize,
    ) -> Option<NonNull<u8>> {
        // If the new size still fits the same slab class (or the same coarse
        // block), we can return the pointer unchanged. For slab blocks this
        // is the common case (e.g. Vec growing within its class). For coarse
        // blocks we grow in place only if the new size fits the existing
        // block; otherwise we fall back to alloc-copy-free.
        let new_layout = match Layout::from_size_align(new_size, old_layout.align()) {
            Ok(l) => l,
            Err(_) => return None,
        };
        if let Some((_, old_class)) = class_index(&old_layout) {
            if let Some((_, new_class)) = class_index(&new_layout) {
                if old_class == new_class {
                    return Some(ptr);
                }
            }
            // Slab -> different class: fall through to copy.
        } else if let Some((_, new_class)) = class_index(&new_layout) {
            // Coarse -> slab: must copy.
            let _ = new_class;
        } else {
            // Coarse -> coarse: grow in place if the existing block still has
            // room for `new_size` user bytes. The usable region is
            // `[user, block_start + block_size)`, so the available byte count
            // is `(block_start + block_size) - user`. Conservatively require
            // the new size to fit without overwriting the AllocHeader or
            // spilling past the block end.
            // SAFETY: `ptr` is a live coarse allocation, so the AllocHeader
            // immediately before it is valid to read.
            let (block_start, block_size) = unsafe {
                let hdr = ptr.as_ptr().sub(size_of::<AllocHeader>()) as *const AllocHeader;
                ((*hdr).block_start, (*hdr).size)
            };
            let block_end = block_start.wrapping_add(block_size);
            let usable = (block_end as usize).saturating_sub(ptr.as_ptr() as usize);
            if new_size <= usable {
                return Some(ptr);
            }
        }

        // Fall back: allocate a fresh block, copy the preserved prefix, free
        // the old block. The copy length is the smaller of the old and new
        // user sizes so we never read past the old allocation or write past
        // the new one.
        let new_ptr = self.allocate(new_layout)?;
        let copy = core::cmp::min(old_layout.size(), new_size);
        // SAFETY: both pointers are valid for at least `copy` bytes within
        // their respective allocations; they do not alias (fresh alloc).
        unsafe {
            ptr::copy_nonoverlapping(ptr.as_ptr(), new_ptr.as_ptr(), copy);
            self.deallocate(ptr, old_layout);
        }
        Some(new_ptr)
    }
}

// ---------------------------------------------------------------------------
// Size-class mapping
// ---------------------------------------------------------------------------

/// Round `n` up to the next power of two, or `None` if it overflows.
fn round_up_pow2(n: usize) -> Option<usize> {
    if n <= 1 {
        return Some(1);
    }
    let bits = usize::BITS - (n - 1).leading_zeros();
    1usize.checked_shl(bits)
}

/// Map a [`Layout`] to its slab class index and class size.
///
/// The class is the smallest power-of-two slab size that is `>=` both
/// `layout.size()` and `layout.align()`. Returns `None` if that size exceeds
/// [`MAX_SLAB_SIZE`] (the allocation must go to the coarse tier). Returns the
/// index into [`SLAB_CLASSES`] and the class size for the caller's use.
fn class_index(layout: &Layout) -> Option<(usize, usize)> {
    let need = core::cmp::max(layout.size(), layout.align());
    let class = round_up_pow2(need)?;
    if class < MIN_SLAB_SIZE {
        // Sizes below the smallest class round up to MIN_SLAB_SIZE so tiny
        // allocations (e.g. a single u8) share the 16-byte class.
        return Some((0, MIN_SLAB_SIZE));
    }
    if class > MAX_SLAB_SIZE {
        return None;
    }
    let idx = SLAB_CLASSES.iter().position(|&c| c == class)?;
    Some((idx, class))
}

// ---------------------------------------------------------------------------
// LockedHeap: the GlobalAlloc wrapper
// ---------------------------------------------------------------------------

/// The kernel's global heap, wrapped in an IRQ-safe spinlock.
///
/// This is the type registered with `#[global_allocator]`; the `alloc` crate
/// routes every `Box`/`Vec`/`String` allocation through [`GlobalAlloc`] on
/// this static. The inner [`Heap`] is only touched while the lock is held, and
/// the lock disables interrupts so an interrupt-handler allocation cannot
/// self-deadlock against a process-context allocation on the same CPU.
pub struct LockedHeap(SpinLockIRQ<Heap>);

impl LockedHeap {
    /// Create a heap that is not yet backed by any region.
    ///
    /// Allocations against an un-initialised heap return `null` (a clean
    /// out-of-memory) rather than faulting. [`init`](Self::init) wires up the
    /// real range once the boot memory map is available.
    #[must_use]
    pub const fn new() -> Self {
        Self(SpinLockIRQ::new(Heap::empty()))
    }

    /// Bind the heap to the reserved `[base, base + size)` region.
    ///
    /// Called exactly once from
    /// [`allocator::init_heap`](super::allocator::init_heap) after the boot
    /// memory map has been consulted and the backing physical range mapped
    /// (via the Limine HHDM direct map). See [`Heap::init`] for the safety
    /// contract.
    ///
    /// # Safety
    ///
    /// The caller guarantees `[base, base + size)` is valid, writable, mapped
    /// kernel memory for the lifetime of the program and not concurrently
    /// referenced.
    pub unsafe fn init(&self, base: *mut u8, size: usize) {
        let mut h = self.0.lock();
        // SAFETY: forwarded to `Heap::init` with the caller's guarantee.
        unsafe {
            h.init(base, size);
        }
    }

    /// The virtual address of the heap's first byte, or `None` before init.
    ///
    /// Exposed for diagnostics so the boot log can report where the heap lives
    /// without poking at the lock-protected state by hand.
    pub fn base(&self) -> Option<VirtAddr> {
        let h = self.0.lock();
        if h.base.is_null() {
            None
        } else {
            VirtAddr::new(h.base as u64)
        }
    }

    /// Total capacity of the heap region in bytes, or `0` before init.
    pub fn capacity(&self) -> usize {
        let h = self.0.lock();
        if h.base.is_null() {
            0
        } else {
            (h.end as usize).saturating_sub(h.base as usize)
        }
    }
}

impl Default for LockedHeap {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: every `GlobalAlloc` method locks the inner `Heap`, performs the
// allocation under the lock, and drops the guard before returning. The
// returned pointers point into the globally-mapped heap region, which is valid
// for the program's lifetime. The `unsafe` blocks inside forward to `Heap`'s
// methods, each of which documents its own invariants.
unsafe impl GlobalAlloc for LockedHeap {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut h = self.0.lock();
        match h.allocate(layout) {
            Some(p) => {
                // Counters are updated outside the heap state but inside the
                // lock; use Relaxed since the atomics are only for stat reads
                // and there is no cross-variable ordering requirement.
                record_alloc(layout.size());
                p.as_ptr()
            },
            None => core::ptr::null_mut(),
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let Some(ptr) = NonNull::new(ptr) else {
            return;
        };
        let mut h = self.0.lock();
        // SAFETY: caller of `dealloc` guarantees `ptr`/`layout` came from
        // `alloc` and the block is live.
        unsafe {
            h.deallocate(ptr, layout);
        }
        record_dealloc(layout.size());
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { self.alloc(layout) };
        if !p.is_null() {
            // SAFETY: `alloc` returned a valid pointer for `layout.size()`
            // bytes; zeroing it touches exactly that range.
            unsafe {
                ptr::write_bytes(p, 0, layout.size());
            }
        }
        p
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Some(ptr) = NonNull::new(ptr) else {
            return core::ptr::null_mut();
        };
        let mut h = self.0.lock();
        // SAFETY: caller guarantees `ptr` is a live allocation of `layout`.
        match unsafe { h.reallocate(ptr, layout, new_size) } {
            Some(new) => {
                // For the copy-fallback path the old block was freed inside
                // `reallocate`; account for the size change best-effort.
                if new.as_ptr() != ptr.as_ptr() {
                    record_dealloc(layout.size());
                    record_alloc(new_size);
                }
                new.as_ptr()
            },
            None => core::ptr::null_mut(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (host build; the slab/coarse math is pure pointer arithmetic over a
// fake region, so these run under cfg(test) with a stack-backed buffer)
// ---------------------------------------------------------------------------

/// Internal capacity accessor used only by host tests.
#[cfg(test)]
impl Heap {
    #[inline]
    fn capacity_intern(&self) -> usize {
        (self.end as usize).saturating_sub(self.base as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-up-to-power-of-two is the size-class foundation; pin its edges.
    #[test]
    fn round_up_pow2_edges() {
        assert_eq!(round_up_pow2(0), Some(1));
        assert_eq!(round_up_pow2(1), Some(1));
        assert_eq!(round_up_pow2(2), Some(2));
        assert_eq!(round_up_pow2(3), Some(4));
        assert_eq!(round_up_pow2(16), Some(16));
        assert_eq!(round_up_pow2(17), Some(32));
        assert_eq!(round_up_pow2(4096), Some(4096));
        assert_eq!(round_up_pow2(4097), Some(8192));
    }

    /// A layout that fits the smallest class maps to index 0 / 16 bytes.
    #[test]
    fn class_index_small() {
        let l = Layout::from_size_align(1, 1).unwrap();
        assert_eq!(class_index(&l), Some((0, 16)));
        let l = Layout::from_size_align(16, 16).unwrap();
        assert_eq!(class_index(&l), Some((0, 16)));
    }

    /// A layout larger than the largest slab class falls through to None.
    #[test]
    fn class_index_overflow_to_coarse() {
        let l = Layout::from_size_align(MAX_SLAB_SIZE + 1, 16).unwrap();
        assert_eq!(class_index(&l), None);
        let l = Layout::from_size_align(1 << 20, 16).unwrap();
        assert_eq!(class_index(&l), None);
    }

    /// Alignment drives the class: a 1-byte allocation with 256-align lands in
    /// the 256 class.
    #[test]
    fn class_index_respects_alignment() {
        let l = Layout::from_size_align(1, 256).unwrap();
        assert_eq!(class_index(&l), Some((4, 256)));
    }

    /// A 64 KiB buffer aligned to a page boundary, so the coarse free blocks
    /// carved from it satisfy the "all blocks are 16-aligned" invariant the
    /// allocator relies on (page alignment is a multiple of every slab class).
    /// Allocated on each test's stack so the parallel host test harness can run
    /// these tests concurrently without sharing a buffer.
    #[repr(C, align(4096))]
    struct Aligned64K([u8; 64 * 1024]);

    /// A freshly-seeded heap reports the requested capacity.
    #[test]
    fn heap_init_seeds_coarse_region() {
        let mut buf = Aligned64K([0u8; 64 * 1024]);
        let base = buf.0.as_mut_ptr();
        let mut heap = Heap::empty();
        // SAFETY: `buf` is a 64 KiB writable buffer we own for the test.
        unsafe {
            heap.init(base, buf.0.len());
        }
        assert!(heap.inited);
        assert_eq!(heap.capacity_intern(), 64 * 1024);
    }

    /// Slab-class push/pop round-trips a block.
    #[test]
    fn slab_class_push_pop() {
        let mut class = SlabClass::empty();
        // A fake 16-byte block on the stack.
        let mut block = [0u8; 16];
        let p = NonNull::new(block.as_mut_ptr()).unwrap();
        // SAFETY: `p` is a valid 16-byte block we own for the test.
        unsafe {
            class.push(p);
        }
        let out = class.pop().expect("just-pushed block is present");
        assert_eq!(out.as_ptr(), block.as_mut_ptr());
        assert!(class.pop().is_none());
    }

    /// End-to-end: a small allocation goes through the slab tier and comes
    /// back aligned and non-null; deallocating it does not corrupt state.
    #[test]
    fn slab_alloc_round_trip() {
        let mut buf = Aligned64K([0u8; 64 * 1024]);
        let base = buf.0.as_mut_ptr();
        let mut heap = Heap::empty();
        unsafe {
            heap.init(base, buf.0.len());
        }
        let layout = Layout::from_size_align(48, 8).unwrap();
        let p = heap.allocate(layout).expect("48-byte slab alloc");
        assert_eq!(p.as_ptr() as usize % 8, 0, "slab alloc must be aligned");
        // Write a sentinel through the pointer to confirm it is writable and
        // unique. SAFETY: `p` is valid for `layout.size()` bytes.
        unsafe {
            p.as_ptr().write_volatile(0xAB);
        }
        // SAFETY: `p` was allocated with `layout`.
        unsafe {
            heap.deallocate(p, layout);
        }
    }

    /// A page-aligned large allocation goes through the coarse tier and is
    /// returned on a 4 KiB boundary.
    #[test]
    fn coarse_alloc_page_aligned() {
        let mut buf = Aligned64K([0u8; 64 * 1024]);
        let base = buf.0.as_mut_ptr();
        let mut heap = Heap::empty();
        unsafe {
            heap.init(base, buf.0.len());
        }
        // 32 KiB is above MAX_SLAB_SIZE (16 KiB), so this routes to the coarse
        // tier. Request 4 KiB alignment.
        let layout = Layout::from_size_align(32 * 1024, 4096).unwrap();
        let p = heap.allocate(layout).expect("32 KiB coarse alloc");
        assert_eq!(
            p.as_ptr() as usize % 4096,
            0,
            "coarse alloc must honour page alignment"
        );
        // SAFETY: `p` is valid for `layout.size()` bytes.
        unsafe {
            p.as_ptr().write_bytes(0xCD, layout.size());
        }
        // SAFETY: free the coarse allocation.
        unsafe {
            heap.deallocate(p, layout);
        }
    }

    /// Allocating then freeing a coarse block and re-allocating the same size
    /// exercises coalescing: after the free the whole region should be one
    /// block again, so the second alloc must succeed at the same address.
    #[test]
    fn coarse_dealloc_coalesces() {
        let mut buf = Aligned64K([0u8; 64 * 1024]);
        let base = buf.0.as_mut_ptr();
        let mut heap = Heap::empty();
        unsafe {
            heap.init(base, buf.0.len());
        }
        let layout = Layout::from_size_align(20 * 1024, 16).unwrap();
        let p1 = heap.allocate(layout).expect("first coarse alloc");
        // SAFETY: free p1; coalescing should restore the full region.
        unsafe {
            heap.deallocate(p1, layout);
        }
        // The whole 64 KiB region should be available again as one block.
        let p2 = heap
            .allocate(layout)
            .expect("second coarse alloc after free");
        assert_eq!(
            p2.as_ptr(),
            p1.as_ptr(),
            "coalesced block reuses the low address"
        );
        // SAFETY: free p2.
        unsafe {
            heap.deallocate(p2, layout);
        }
    }
}
