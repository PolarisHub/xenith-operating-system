//! Page-table construction for identity, HHDM, and relocated kernel mappings.

use xenith_boot_common::{align_down, align_up, HHDM_OFFSET, PAGE_SIZE};

use crate::LoaderError;

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const LARGE: u64 = 1 << 7;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

pub struct PageTables {
    base: u64,
    capacity: usize,
    used: usize,
}

impl PageTables {
    /// The caller provides zeroed, page-aligned, identity-accessible physical memory.
    pub unsafe fn new(base: u64, capacity: usize) -> Result<Self, LoaderError> {
        if !base.is_multiple_of(PAGE_SIZE) || capacity < 7 {
            return Err(LoaderError::PageTables);
        }
        // SAFETY: caller allocated all `capacity` pages exclusively to this builder.
        unsafe { core::ptr::write_bytes(base as *mut u8, 0, capacity * PAGE_SIZE as usize) };
        Ok(Self {
            base,
            capacity,
            used: 1,
        })
    }

    #[must_use]
    pub const fn cr3(&self) -> u64 {
        self.base
    }

    pub fn map_transition_windows(&mut self) -> Result<(), LoaderError> {
        let pdpt = self.allocate_table()?;
        self.write_entry(self.base, 0, pdpt | PRESENT | WRITABLE);
        self.write_entry(self.base, 256, pdpt | PRESENT | WRITABLE);
        for gib in 0..4_usize {
            let pd = self.allocate_table()?;
            self.write_entry(pdpt, gib, pd | PRESENT | WRITABLE);
            for entry in 0..512_usize {
                let physical = ((gib * 512 + entry) as u64) * 0x20_0000;
                self.write_entry(pd, entry, physical | PRESENT | WRITABLE | LARGE);
            }
        }
        Ok(())
    }

    pub fn map_kernel(
        &mut self,
        virtual_start: u64,
        physical_start: u64,
        length: u64,
        writable: bool,
    ) -> Result<(), LoaderError> {
        if virtual_start & (PAGE_SIZE - 1) != physical_start & (PAGE_SIZE - 1) {
            return Err(LoaderError::KernelLayout);
        }
        let virtual_page = align_down(virtual_start, PAGE_SIZE);
        let physical_page = align_down(physical_start, PAGE_SIZE);
        let end = align_up(
            virtual_start
                .checked_add(length)
                .ok_or(LoaderError::KernelLayout)?,
            PAGE_SIZE,
        )
        .ok_or(LoaderError::KernelLayout)?;
        let mut offset = 0;
        while virtual_page + offset < end {
            self.map_4k(virtual_page + offset, physical_page + offset, writable)?;
            offset += PAGE_SIZE;
        }
        Ok(())
    }

    pub fn map_hhdm_physical(&mut self, physical: u64, length: u64) -> Result<(), LoaderError> {
        self.map_kernel(
            HHDM_OFFSET
                .checked_add(physical)
                .ok_or(LoaderError::PageTables)?,
            physical,
            length,
            true,
        )
    }

    fn map_4k(
        &mut self,
        virtual_address: u64,
        physical: u64,
        writable: bool,
    ) -> Result<(), LoaderError> {
        let indexes = [
            ((virtual_address >> 39) & 0x1ff) as usize,
            ((virtual_address >> 30) & 0x1ff) as usize,
            ((virtual_address >> 21) & 0x1ff) as usize,
            ((virtual_address >> 12) & 0x1ff) as usize,
        ];
        let mut table = self.base;
        for &index in &indexes[..3] {
            let current = self.read_entry(table, index);
            if current & LARGE != 0 {
                let mapped = current & 0x000f_ffff_ffe0_0000;
                let within = virtual_address & 0x1f_ffff;
                if mapped + within == physical {
                    return Ok(());
                }
                return Err(LoaderError::PageTables);
            }
            table = if current & PRESENT != 0 {
                current & ADDRESS_MASK
            } else {
                let allocated = self.allocate_table()?;
                self.write_entry(table, index, allocated | PRESENT | WRITABLE);
                allocated
            };
        }
        let mut flags = PRESENT;
        if writable {
            flags |= WRITABLE;
        }
        self.write_entry(table, indexes[3], align_down(physical, PAGE_SIZE) | flags);
        Ok(())
    }

    fn allocate_table(&mut self) -> Result<u64, LoaderError> {
        if self.used >= self.capacity {
            return Err(LoaderError::PageTables);
        }
        let address = self.base + self.used as u64 * PAGE_SIZE;
        self.used += 1;
        Ok(address)
    }

    fn read_entry(&self, table: u64, index: usize) -> u64 {
        // SAFETY: all traversed tables were allocated and initialized by this builder.
        unsafe { core::ptr::read((table as *const u64).add(index)) }
    }

    fn write_entry(&self, table: u64, index: usize, value: u64) {
        // SAFETY: all target tables are exclusively owned until ExitBootServices.
        unsafe { core::ptr::write((table as *mut u64).add(index), value) };
    }
}
