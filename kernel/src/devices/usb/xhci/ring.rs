//! Physically contiguous xHCI DMA arena and cycle-bit ring state machines.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, Ordering};

use super::trb::{Trb, TRB_SIZE};
use crate::devices::net::dma::{DmaError, DmaRegion};

/// One page / 256 TRBs per ring. A producer ring reserves its final TRB for
/// the Link TRB, leaving 255 outstanding commands/transfers before wrapping.
pub const RING_ENTRIES: usize = 256;
pub const RING_BYTES: usize = RING_ENTRIES * TRB_SIZE;

/// Failure to allocate or address a bounded DMA object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingError {
    Dma(DmaError),
    ArenaExhausted,
    InvalidAlignment,
    InvalidRing,
}

impl From<DmaError> for RingError {
    fn from(error: DmaError) -> Self {
        Self::Dma(error)
    }
}

/// Offset/length/physical tuple for an allocation within the DMA arena.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaSlice {
    pub offset: usize,
    pub len: usize,
    pub physical: u64,
}

/// One contiguous, zeroed DMA allocation carved into aligned controller
/// objects. Long-lived controller objects are bump allocated here; reusable
/// per-slot windows below keep hotplug from consuming this cursor forever.
pub struct DmaArena {
    region: DmaRegion,
    next: usize,
}

impl DmaArena {
    pub fn new(bytes: usize, max_address: Option<u64>) -> Result<Self, RingError> {
        Ok(Self {
            region: DmaRegion::allocate(bytes, max_address)?,
            next: 0,
        })
    }

    pub fn allocate(&mut self, bytes: usize, alignment: usize) -> Result<DmaSlice, RingError> {
        if bytes == 0 || alignment == 0 || !alignment.is_power_of_two() {
            return Err(RingError::InvalidAlignment);
        }
        let offset = align_up(self.next, alignment).ok_or(RingError::ArenaExhausted)?;
        let end = offset
            .checked_add(bytes)
            .filter(|end| *end <= self.region.len())
            .ok_or(RingError::ArenaExhausted)?;
        let physical = self
            .region
            .physical_at(offset)
            .ok_or(RingError::ArenaExhausted)?;
        self.next = end;
        Ok(DmaSlice {
            offset,
            len: bytes,
            physical,
        })
    }

    pub fn bytes(&self, slice: DmaSlice) -> Option<&[u8]> {
        self.region.slice(slice.offset, slice.len)
    }

    pub fn bytes_mut(&mut self, slice: DmaSlice) -> Option<&mut [u8]> {
        self.region.slice_mut(slice.offset, slice.len)
    }

    pub fn copy_out(&self, slice: DmaSlice, length: usize, output: &mut [u8]) -> Option<usize> {
        let count = length.min(slice.len).min(output.len());
        output[..count].copy_from_slice(self.region.slice(slice.offset, count)?);
        Some(count)
    }

    pub fn write_u64(&mut self, slice: DmaSlice, index: usize, value: u64) -> Option<()> {
        let byte_offset = index.checked_mul(8)?;
        if byte_offset.checked_add(8)? > slice.len {
            return None;
        }
        let address = self.region.as_mut_ptr() as usize + slice.offset + byte_offset;
        if address & 7 != 0 {
            return None;
        }
        // SAFETY: slice bounds and 8-byte alignment were checked above.
        unsafe { write_volatile(address as *mut u64, value) };
        Some(())
    }

    pub fn write_u32(&mut self, slice: DmaSlice, index: usize, value: u32) -> Option<()> {
        let byte_offset = index.checked_mul(4)?;
        if byte_offset.checked_add(4)? > slice.len {
            return None;
        }
        let address = self.region.as_mut_ptr() as usize + slice.offset + byte_offset;
        if address & 3 != 0 {
            return None;
        }
        // SAFETY: slice bounds and 4-byte alignment were checked above.
        unsafe { write_volatile(address as *mut u32, value) };
        Some(())
    }

    /// Clear a previously carved span before its ownership is recycled.
    pub fn clear(&mut self, slice: DmaSlice) -> Option<()> {
        self.region.slice_mut(slice.offset, slice.len)?.fill(0);
        Some(())
    }

    fn write_producer_trb(&mut self, ring: DmaSlice, index: usize, trb: Trb) -> Option<()> {
        let offset = index.checked_mul(TRB_SIZE)?;
        if offset.checked_add(TRB_SIZE)? > ring.len {
            return None;
        }
        let address = self.region.as_mut_ptr() as usize + ring.offset + offset;
        if address & 0x0f != 0 {
            return None;
        }
        // The cycle bit is the ownership handoff. First publish a control
        // dword carrying the opposite cycle, then parameter/status, and only
        // after a release fence publish the final control dword.
        let hidden_control = trb.control ^ 1;
        // SAFETY: address is a validated aligned 16-byte slot in the arena.
        unsafe {
            write_volatile(address as *mut u32, trb.parameter_low);
            write_volatile((address + 4) as *mut u32, trb.parameter_high);
            write_volatile((address + 8) as *mut u32, trb.status);
            write_volatile((address + 12) as *mut u32, hidden_control);
        }
        compiler_fence(Ordering::Release);
        // SAFETY: same validated control dword; this store transfers ownership.
        unsafe { write_volatile((address + 12) as *mut u32, trb.control) };
        Some(())
    }

    fn read_event_trb(&self, ring: DmaSlice, index: usize, expected_cycle: bool) -> Option<Trb> {
        let offset = index.checked_mul(TRB_SIZE)?;
        if offset.checked_add(TRB_SIZE)? > ring.len {
            return None;
        }
        let address = self.region.as_ptr() as usize + ring.offset + offset;
        if address & 0x0f != 0 {
            return None;
        }
        // The controller writes the cycle bit last. Observe it first, acquire,
        // then read the remaining dwords only for a software-owned event.
        // SAFETY: address is a validated event-ring slot.
        let control = unsafe { read_volatile((address + 12) as *const u32) };
        if (control & 1 != 0) != expected_cycle {
            return None;
        }
        compiler_fence(Ordering::Acquire);
        // SAFETY: cycle ownership guarantees the controller completed writes.
        Some(unsafe {
            Trb {
                parameter_low: read_volatile(address as *const u32),
                parameter_high: read_volatile((address + 4) as *const u32),
                status: read_volatile((address + 8) as *const u32),
                control,
            }
        })
    }

    pub fn sync_for_device(&self) {
        self.region.sync_for_device();
    }

    pub fn sync_for_cpu(&self) {
        self.region.sync_for_cpu();
    }
}

/// Resettable bump allocator over a fixed slice of [`DmaArena`].
///
/// A controller reserves one window for each hardware slot. Disable Slot
/// completes before that window is cleared and rewound, so disconnects and
/// failed enumeration reuse exactly the same bounded DMA addresses without
/// leaving stale cycle bits visible to the controller.
#[derive(Clone, Copy, Debug)]
pub struct DmaSubArena {
    memory: DmaSlice,
    next: usize,
}

impl DmaSubArena {
    #[must_use]
    pub const fn new(memory: DmaSlice) -> Self {
        Self { memory, next: 0 }
    }

    pub fn allocate(&mut self, bytes: usize, alignment: usize) -> Result<DmaSlice, RingError> {
        if bytes == 0 || alignment == 0 || !alignment.is_power_of_two() {
            return Err(RingError::InvalidAlignment);
        }
        let absolute = self
            .memory
            .offset
            .checked_add(self.next)
            .ok_or(RingError::ArenaExhausted)?;
        let aligned = align_up(absolute, alignment).ok_or(RingError::ArenaExhausted)?;
        let offset = aligned
            .checked_sub(self.memory.offset)
            .ok_or(RingError::InvalidAlignment)?;
        let end = offset
            .checked_add(bytes)
            .filter(|end| *end <= self.memory.len)
            .ok_or(RingError::ArenaExhausted)?;
        let physical = self
            .memory
            .physical
            .checked_add(offset as u64)
            .filter(|physical| *physical & (alignment as u64 - 1) == 0)
            .ok_or(RingError::InvalidAlignment)?;
        self.next = end;
        Ok(DmaSlice {
            offset: aligned,
            len: bytes,
            physical,
        })
    }

    /// Zero all old contexts/TRBs and return the slot window to its start.
    pub fn reset(&mut self, arena: &mut DmaArena) -> Result<(), RingError> {
        arena.clear(self.memory).ok_or(RingError::InvalidRing)?;
        self.next = 0;
        arena.sync_for_device();
        Ok(())
    }
}

/// Producer ring with an automatically maintained Link TRB and cycle state.
#[derive(Clone, Copy, Debug)]
pub struct ProducerRing {
    memory: DmaSlice,
    cursor: ProducerCursor,
}

impl ProducerRing {
    pub fn allocate(arena: &mut DmaArena) -> Result<Self, RingError> {
        let memory = arena.allocate(RING_BYTES, 64)?;
        Self::initialize(arena, memory)
    }

    /// Allocate a producer ring from a resettable per-slot DMA window.
    pub fn allocate_in(
        arena: &mut DmaArena,
        subarena: &mut DmaSubArena,
    ) -> Result<Self, RingError> {
        let memory = subarena.allocate(RING_BYTES, 64)?;
        Self::initialize(arena, memory)
    }

    fn initialize(arena: &mut DmaArena, memory: DmaSlice) -> Result<Self, RingError> {
        let mut ring = Self {
            memory,
            cursor: ProducerCursor::new(RING_ENTRIES),
        };
        // Keep the Link TRB controller-owned bit clear until the producer has
        // actually filled every preceding data slot in the first traversal.
        ring.publish_link(arena, LinkOwnership {
            cycle: false,
            chain: false,
        })?;
        Ok(ring)
    }

    /// Enqueue one TRB and return its physical address for completion matching.
    ///
    /// The caller owns fullness accounting. Xenith's command ring has exactly
    /// one synchronous command outstanding, each control ring has one TD (at
    /// most three TRBs) outstanding, and each HID interrupt ring has one
    /// Normal TRB outstanding. Consequently a 255-entry producer ring cannot
    /// lap its hardware consumer in the supported runtime paths.
    pub fn push(&mut self, arena: &mut DmaArena, trb: Trb) -> Result<u64, RingError> {
        let index = self.cursor.index;
        let physical = self
            .memory
            .physical
            .checked_add((index * TRB_SIZE) as u64)
            .ok_or(RingError::InvalidRing)?;
        let chained = trb.chained();
        let trb = trb.with_cycle(self.cursor.cycle);
        arena
            .write_producer_trb(self.memory, index, trb)
            .ok_or(RingError::InvalidRing)?;
        if let Some(link) = self.cursor.advance(chained) {
            self.publish_link(arena, link)?;
        }
        arena.sync_for_device();
        Ok(physical)
    }

    #[must_use]
    pub const fn physical(self) -> u64 {
        self.memory.physical
    }

    fn publish_link(
        &mut self,
        arena: &mut DmaArena,
        ownership: LinkOwnership,
    ) -> Result<(), RingError> {
        let link_index = self.cursor.entries - 1;
        let link = Trb::link(self.memory.physical, ownership.chain).with_cycle(ownership.cycle);
        // The Link TRB belongs to the cycle of the data TRB immediately before
        // it. If the preceding TRB chains the next stage of a TD, the Link TRB
        // must carry CH as well. `ProducerCursor::advance` returns that old
        // ownership while moving software to index zero and toggling PCS.
        // Publishing the *next* cycle here would hide the link from hardware
        // and stall the ring after exactly 255 submissions.
        arena
            .write_producer_trb(self.memory, link_index, link)
            .ok_or(RingError::InvalidRing)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProducerCursor {
    entries: usize,
    index: usize,
    cycle: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinkOwnership {
    cycle: bool,
    chain: bool,
}

impl ProducerCursor {
    const fn new(entries: usize) -> Self {
        Self {
            entries,
            index: 0,
            cycle: true,
        }
    }

    /// Advance past one data TRB. At wrap, return the cycle that the Link TRB
    /// must retain while the next data TRB uses the toggled producer cycle.
    fn advance(&mut self, chained: bool) -> Option<LinkOwnership> {
        self.index += 1;
        if self.index == self.entries - 1 {
            let ownership = LinkOwnership {
                cycle: self.cycle,
                chain: chained,
            };
            self.index = 0;
            self.cycle = !self.cycle;
            Some(ownership)
        } else {
            None
        }
    }
}

/// Single-segment Event Ring consumer.
#[derive(Clone, Copy, Debug)]
pub struct EventRing {
    memory: DmaSlice,
    index: usize,
    cycle: bool,
}

impl EventRing {
    pub fn allocate(arena: &mut DmaArena) -> Result<Self, RingError> {
        Ok(Self {
            memory: arena.allocate(RING_BYTES, 64)?,
            index: 0,
            cycle: true,
        })
    }

    pub fn pop(&mut self, arena: &DmaArena) -> Option<Trb> {
        arena.sync_for_cpu();
        let trb = arena.read_event_trb(self.memory, self.index, self.cycle)?;
        self.index += 1;
        if self.index == RING_ENTRIES {
            self.index = 0;
            self.cycle = !self.cycle;
        }
        Some(trb)
    }

    #[must_use]
    pub const fn physical(self) -> u64 {
        self.memory.physical
    }

    #[must_use]
    pub fn dequeue_physical(self) -> u64 {
        self.memory.physical + (self.index * TRB_SIZE) as u64
    }

    #[must_use]
    pub const fn segment_size(self) -> u16 {
        RING_ENTRIES as u16
    }
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|sum| sum & !(alignment - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn producer_cursor_reserves_link_and_toggles_on_wrap() {
        let mut cursor = ProducerCursor::new(4); // three data TRBs + link
        assert_eq!(cursor.advance(false), None);
        assert_eq!(cursor.advance(false), None);
        assert_eq!(
            cursor.advance(false),
            Some(LinkOwnership {
                cycle: true,
                chain: false
            })
        );
        assert_eq!(cursor.index, 0);
        assert!(!cursor.cycle);
        assert_eq!(cursor.advance(false), None);
        assert_eq!(cursor.advance(false), None);
        assert_eq!(
            cursor.advance(false),
            Some(LinkOwnership {
                cycle: false,
                chain: false
            })
        );
        assert!(cursor.cycle);
    }

    #[test]
    fn wrap_link_uses_old_cycle_while_next_data_uses_new_cycle() {
        let mut cursor = ProducerCursor::new(3); // two data slots + one link
        assert_eq!(cursor.advance(false), None);
        let ownership = cursor.advance(false).expect("second data reaches link");
        let published_link = Trb::link(0x1000, ownership.chain).with_cycle(ownership.cycle);
        assert!(ownership.cycle, "first traversal link remains cycle one");
        assert!(published_link.cycle());
        assert!(!cursor.cycle, "next data traversal toggles to cycle zero");

        assert_eq!(cursor.advance(false), None);
        let ownership = cursor
            .advance(false)
            .expect("second traversal reaches link");
        let published_link = Trb::link(0x1000, ownership.chain).with_cycle(ownership.cycle);
        assert!(!ownership.cycle, "second traversal link is cycle zero");
        assert!(!published_link.cycle());
        assert!(cursor.cycle, "third data traversal returns to cycle one");
    }

    #[test]
    fn td_crossing_link_preserves_chain_only_for_chained_predecessor() {
        let mut cursor = ProducerCursor::new(3);
        assert_eq!(cursor.advance(false), None);
        let ownership = cursor.advance(true).expect("chained stage reaches link");
        let link = Trb::link(0x2000, ownership.chain).with_cycle(ownership.cycle);
        assert!(link.chained(), "Setup/Data TD continues across Link TRB");
        assert!(link.cycle());

        assert_eq!(cursor.advance(false), None);
        let ownership = cursor
            .advance(false)
            .expect("unchained status reaches link");
        let link = Trb::link(0x2000, ownership.chain).with_cycle(ownership.cycle);
        assert!(!link.chained(), "new TD must not inherit prior chain state");
        assert!(!link.cycle());
    }

    #[test]
    fn alignment_is_checked_and_overflow_safe() {
        assert_eq!(align_up(1, 64), Some(64));
        assert_eq!(align_up(64, 64), Some(64));
        assert_eq!(align_up(usize::MAX, 64), None);
    }

    #[test]
    fn subarena_rewinds_to_identical_dma_layout() {
        let memory = DmaSlice {
            offset: 0x2000,
            len: 0x4000,
            physical: 0x8000,
        };
        let mut subarena = DmaSubArena::new(memory);
        let first = subarena.allocate(0x321, 64).unwrap();
        let second = subarena.allocate(0x1000, 4096).unwrap();
        assert_eq!(first.offset, 0x2000);
        assert_eq!(first.physical, 0x8000);
        assert_eq!(second.offset, 0x3000);
        assert_eq!(second.physical, 0x9000);

        // `reset` additionally zeroes through the owning arena; rewinding the
        // pure cursor here proves a slot receives the exact same addresses.
        subarena.next = 0;
        assert_eq!(subarena.allocate(0x321, 64).unwrap(), first);
        assert_eq!(subarena.allocate(0x1000, 4096).unwrap(), second);
    }

    #[test]
    fn trb_and_ring_layout_match_hardware_contract() {
        assert_eq!(core::mem::size_of::<Trb>(), TRB_SIZE);
        assert_eq!(core::mem::align_of::<Trb>(), TRB_SIZE);
        assert_eq!(RING_BYTES, 4096);
    }
}
