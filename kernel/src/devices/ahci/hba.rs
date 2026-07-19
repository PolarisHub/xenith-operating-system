//! AHCI port engine and ATA DMA command path.
//!
//! A port owns one permanently allocated, physically contiguous DMA arena:
//! the command list, received-FIS area, one command table, and a 64 KiB
//! bounce buffer. Xenith's boot heap is carved from the HHDM direct map, so
//! heap virtual addresses translate back to stable physical addresses. The
//! bounce buffer keeps callers' stack or non-HHDM buffers out of the DMA
//! contract and bounds every command to 128 logical sectors.

use core::alloc::Layout;
use core::mem::size_of;
use core::sync::atomic::{compiler_fence, Ordering};
use core::{fmt, ptr};

use xenith_types::VirtAddr;

use crate::mm::kmalloc::{kmalloc_zeroed, KmallocError};
use crate::mm::{virt_to_phys, Kbox};

/// ATA logical-sector size used by READ/WRITE DMA EXT.
pub const SECTOR_SIZE: usize = 512;
/// Number of sectors that fit in the per-port bounce buffer.
pub const MAX_SECTORS_PER_COMMAND: usize = 128;
const DMA_BUFFER_SIZE: usize = SECTOR_SIZE * MAX_SECTORS_PER_COMMAND;

const PX_CLB: usize = 0x00;
const PX_CLBU: usize = 0x04;
const PX_FB: usize = 0x08;
const PX_FBU: usize = 0x0C;
const PX_IS: usize = 0x10;
const PX_IE: usize = 0x14;
const PX_CMD: usize = 0x18;
const PX_TFD: usize = 0x20;
const PX_SIG: usize = 0x24;
const PX_SSTS: usize = 0x28;
const PX_SERR: usize = 0x30;
const PX_SACT: usize = 0x34;
const PX_CI: usize = 0x38;

const CMD_ST: u32 = 1 << 0;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;

const TFD_ERR: u32 = 1 << 0;
const TFD_DRQ: u32 = 1 << 3;
const TFD_BSY: u32 = 1 << 7;
const IS_TFES: u32 = 1 << 30;

const SSTS_DET_MASK: u32 = 0x0F;
const SSTS_DET_PRESENT: u32 = 0x03;
const SSTS_IPM_MASK: u32 = 0x0F00;
const SSTS_IPM_ACTIVE: u32 = 0x0100;

const FIS_TYPE_REG_H2D: u8 = 0x27;
const FIS_COMMAND: u8 = 1 << 7;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_FLUSH_CACHE_EXT: u8 = 0xea;

const COMMAND_FIS_DWORDS: u16 = 5;
const COMMAND_HEADER_WRITE: u16 = 1 << 6;
const PRDT_INTERRUPT_ON_COMPLETION: u32 = 1 << 31;
const PRDT_BYTE_COUNT_MASK: u32 = 0x003F_FFFF;
const MAX_LBA48: u64 = (1u64 << 48) - 1;

/// Bounded poll count for command-engine state transitions.
const ENGINE_POLL_LIMIT: u32 = 2_000_000;
/// Bounded poll count for one ATA command. The loop uses `spin_loop`, so this
/// is deliberately generous while still guaranteeing a wedged disk cannot
/// hang the kernel forever.
const COMMAND_POLL_LIMIT: u32 = 50_000_000;

/// Errors reported by AHCI discovery, port setup, and block transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HbaError {
    /// The supplied PCI function does not advertise the AHCI class triple.
    NotAhci,
    /// BAR5 is absent.
    NoAbar,
    /// BAR5 is an I/O BAR rather than the required memory BAR.
    AbarIsIo,
    /// The kernel could not allocate the aligned DMA arena.
    OutOfMemory,
    /// A 32-bit-only HBA cannot address the allocated DMA arena.
    DmaAddressTooHigh,
    /// The command or FIS engine failed to stop/start within the poll bound.
    EngineTimeout,
    /// No active SATA device is connected to this port.
    PortUnavailable,
    /// The buffer length is zero or not a multiple of 512 bytes.
    InvalidBuffer,
    /// The transfer would exceed the 48-bit ATA LBA range.
    InvalidLba,
    /// The device never left BSY/DRQ before a command was issued.
    DeviceBusy,
    /// PxCI did not clear within the bounded completion poll.
    CommandTimeout,
    /// PxIS/PxTFD reported an ATA task-file error.
    TaskFileError,
}

impl fmt::Display for HbaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotAhci => "not an AHCI controller",
            Self::NoAbar => "AHCI BAR5 is absent",
            Self::AbarIsIo => "AHCI BAR5 is not memory mapped",
            Self::OutOfMemory => "AHCI DMA allocation failed",
            Self::DmaAddressTooHigh => "AHCI DMA address exceeds controller width",
            Self::EngineTimeout => "AHCI command engine timed out",
            Self::PortUnavailable => "AHCI port has no active SATA device",
            Self::InvalidBuffer => "AHCI buffer must contain whole sectors",
            Self::InvalidLba => "AHCI LBA exceeds ATA-48 range",
            Self::DeviceBusy => "AHCI device remained busy",
            Self::CommandTimeout => "AHCI command completion timed out",
            Self::TaskFileError => "AHCI task-file error",
        })
    }
}

impl From<KmallocError> for HbaError {
    fn from(_: KmallocError) -> Self {
        Self::OutOfMemory
    }
}

/// One 32-byte AHCI command-list entry.
#[repr(C)]
#[derive(Clone, Copy)]
struct CommandHeader {
    flags: u16,
    prdt_length: u16,
    bytes_transferred: u32,
    table_base: u32,
    table_base_upper: u32,
    reserved: [u32; 4],
}

/// One physical-region descriptor. A PRDT entry can describe up to 4 MiB;
/// Xenith uses at most 64 KiB here.
#[repr(C)]
#[derive(Clone, Copy)]
struct PrdtEntry {
    data_base: u32,
    data_base_upper: u32,
    reserved: u32,
    byte_count_and_interrupt: u32,
}

/// Command table for slot zero: command FIS, ATAPI area, reserved bytes, and
/// one PRDT entry.
#[repr(C, align(128))]
struct CommandTable {
    command_fis: [u8; 64],
    atapi_command: [u8; 16],
    reserved: [u8; 48],
    prdt: [PrdtEntry; 1],
}

#[repr(C, align(1024))]
struct CommandList([CommandHeader; 32]);

#[repr(C, align(256))]
struct ReceivedFis([u8; 256]);

#[repr(C, align(4096))]
struct DmaBuffer([u8; DMA_BUFFER_SIZE]);

/// All port-owned DMA objects in one aligned allocation. Zero is a valid
/// initial representation for every member.
#[repr(C, align(4096))]
struct PortDma {
    command_list: CommandList,
    received_fis: ReceivedFis,
    command_table: CommandTable,
    data: DmaBuffer,
}

fn allocate_dma() -> Result<Kbox<PortDma>, HbaError> {
    let raw = kmalloc_zeroed(Layout::new::<PortDma>())?;
    let typed = raw.cast::<PortDma>().as_ptr();
    // SAFETY: `kmalloc_zeroed` returned a uniquely owned allocation with
    // exactly `Layout::new::<PortDma>()`. Every field accepts an all-zero
    // representation, and Box will later deallocate it with the same layout.
    Ok(unsafe { Kbox::from_raw(typed) })
}

#[inline]
fn physical_address<T>(ptr: *const T) -> u64 {
    virt_to_phys(VirtAddr::new_truncate(ptr as u64)).as_u64()
}

#[inline]
const fn split_address(address: u64) -> (u32, u32) {
    (address as u32, (address >> 32) as u32)
}

/// MMIO handle and DMA state for one AHCI port.
pub struct HbaPort {
    base: u64,
    index: u8,
    command_slots: u8,
    supports_64bit: bool,
    dma: Kbox<PortDma>,
}

impl HbaPort {
    /// Allocate and program a port's command/FIS memory, then start its engine.
    pub fn new(
        base: u64,
        index: u8,
        command_slots: u8,
        supports_64bit: bool,
    ) -> Result<Self, HbaError> {
        let dma = allocate_dma()?;
        let mut port = Self {
            base,
            index,
            command_slots: command_slots.clamp(1, 32),
            supports_64bit,
            dma,
        };
        port.configure_dma()?;
        Ok(port)
    }

    #[inline]
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: `base` points at this implemented port's 0x80-byte MMIO
        // register block and all constants are aligned 32-bit offsets in it.
        unsafe { ptr::read_volatile((self.base + offset as u64) as *const u32) }
    }

    #[inline]
    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: same MMIO invariant as `read32`; volatile preserves the
        // device-visible store.
        unsafe { ptr::write_volatile((self.base + offset as u64) as *mut u32, value) }
    }

    /// Port number within the HBA (0..31).
    #[must_use]
    pub const fn index(&self) -> u8 {
        self.index
    }

    /// Number of hardware command slots advertised by CAP.NCS.
    #[must_use]
    pub const fn command_slots(&self) -> u8 {
        self.command_slots
    }

    /// Raw ATA/ATAPI device signature (PxSIG).
    #[must_use]
    pub fn signature(&self) -> u32 {
        self.read32(PX_SIG)
    }

    /// Raw SATA link status (PxSSTS).
    #[must_use]
    pub fn sata_status(&self) -> u32 {
        self.read32(PX_SSTS)
    }

    /// Whether device detection is complete and the link is in active power
    /// state. A non-zero signature alone is insufficient on unplugged ports.
    #[must_use]
    pub fn device_present(&self) -> bool {
        let status = self.sata_status();
        status & SSTS_DET_MASK == SSTS_DET_PRESENT && status & SSTS_IPM_MASK == SSTS_IPM_ACTIVE
    }

    fn dma_addresses_fit(&self) -> bool {
        if self.supports_64bit {
            return true;
        }
        let start = physical_address((&*self.dma) as *const PortDma);
        start
            .checked_add(size_of::<PortDma>() as u64 - 1)
            .is_some_and(|end| end <= u64::from(u32::MAX))
    }

    fn configure_dma(&mut self) -> Result<(), HbaError> {
        if !self.dma_addresses_fit() {
            return Err(HbaError::DmaAddressTooHigh);
        }
        self.stop_engine()?;

        let list = physical_address(&self.dma.command_list as *const CommandList);
        let fis = physical_address(&self.dma.received_fis as *const ReceivedFis);
        let table = physical_address(&self.dma.command_table as *const CommandTable);
        let (list_lo, list_hi) = split_address(list);
        let (fis_lo, fis_hi) = split_address(fis);
        let (table_lo, table_hi) = split_address(table);

        self.write32(PX_CLB, list_lo);
        self.write32(PX_CLBU, list_hi);
        self.write32(PX_FB, fis_lo);
        self.write32(PX_FBU, fis_hi);

        let header = &mut self.dma.command_list.0[0];
        header.table_base = table_lo;
        header.table_base_upper = table_hi;
        header.prdt_length = 1;

        // Polling is the completion mechanism for now; keep port interrupts
        // masked while still clearing stale status/error bits from firmware.
        self.write32(PX_IE, 0);
        self.write32(PX_IS, u32::MAX);
        self.write32(PX_SERR, u32::MAX);
        self.start_engine()
    }

    fn stop_engine(&self) -> Result<(), HbaError> {
        let mut cmd = self.read32(PX_CMD);
        cmd &= !CMD_ST;
        self.write32(PX_CMD, cmd);
        if !self.wait_cmd_clear(CMD_CR) {
            return Err(HbaError::EngineTimeout);
        }
        cmd = self.read32(PX_CMD) & !CMD_FRE;
        self.write32(PX_CMD, cmd);
        if !self.wait_cmd_clear(CMD_FR) {
            return Err(HbaError::EngineTimeout);
        }
        Ok(())
    }

    fn start_engine(&self) -> Result<(), HbaError> {
        if !self.wait_cmd_clear(CMD_CR) {
            return Err(HbaError::EngineTimeout);
        }
        let cmd = self.read32(PX_CMD) | CMD_FRE | CMD_ST;
        self.write32(PX_CMD, cmd);
        Ok(())
    }

    fn wait_cmd_clear(&self, mask: u32) -> bool {
        for _ in 0..ENGINE_POLL_LIMIT {
            if self.read32(PX_CMD) & mask == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    fn wait_device_ready(&self) -> Result<(), HbaError> {
        for _ in 0..ENGINE_POLL_LIMIT {
            let task_file = self.read32(PX_TFD);
            if task_file & TFD_ERR != 0 {
                return Err(HbaError::TaskFileError);
            }
            if task_file & (TFD_BSY | TFD_DRQ) == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(HbaError::DeviceBusy)
    }

    fn prepare_command(&mut self, lba: u64, sectors: u16, write: bool) {
        let byte_count = usize::from(sectors) * SECTOR_SIZE;
        let data_phys = physical_address(self.dma.data.0.as_ptr());
        let (data_lo, data_hi) = split_address(data_phys);

        let header = &mut self.dma.command_list.0[0];
        header.flags = COMMAND_FIS_DWORDS | if write { COMMAND_HEADER_WRITE } else { 0 };
        header.prdt_length = 1;
        header.bytes_transferred = 0;

        let table = &mut self.dma.command_table;
        table.command_fis.fill(0);
        table.atapi_command.fill(0);
        table.reserved.fill(0);
        table.prdt[0] = PrdtEntry {
            data_base: data_lo,
            data_base_upper: data_hi,
            reserved: 0,
            byte_count_and_interrupt: ((byte_count as u32 - 1) & PRDT_BYTE_COUNT_MASK)
                | PRDT_INTERRUPT_ON_COMPLETION,
        };

        let fis = &mut table.command_fis;
        fis[0] = FIS_TYPE_REG_H2D;
        fis[1] = FIS_COMMAND;
        fis[2] = if write {
            ATA_WRITE_DMA_EXT
        } else {
            ATA_READ_DMA_EXT
        };
        fis[4] = lba as u8;
        fis[5] = (lba >> 8) as u8;
        fis[6] = (lba >> 16) as u8;
        fis[7] = 1 << 6; // LBA mode
        fis[8] = (lba >> 24) as u8;
        fis[9] = (lba >> 32) as u8;
        fis[10] = (lba >> 40) as u8;
        fis[12] = sectors as u8;
        fis[13] = (sectors >> 8) as u8;
    }

    fn prepare_non_data_command(&mut self, command: u8) {
        let header = &mut self.dma.command_list.0[0];
        header.flags = COMMAND_FIS_DWORDS;
        header.prdt_length = 0;
        header.bytes_transferred = 0;

        let table = &mut self.dma.command_table;
        table.command_fis.fill(0);
        table.atapi_command.fill(0);
        table.reserved.fill(0);
        table.prdt[0] = PrdtEntry {
            data_base: 0,
            data_base_upper: 0,
            reserved: 0,
            byte_count_and_interrupt: 0,
        };
        table.command_fis[0] = FIS_TYPE_REG_H2D;
        table.command_fis[1] = FIS_COMMAND;
        table.command_fis[2] = command;
    }

    fn wait_slot_zero_available(&self) -> Result<(), HbaError> {
        for _ in 0..ENGINE_POLL_LIMIT {
            if (self.read32(PX_CI) | self.read32(PX_SACT)) & 1 == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(HbaError::DeviceBusy)
    }

    fn submit_slot_zero(&self) -> Result<(), HbaError> {
        self.write32(PX_IS, u32::MAX);
        compiler_fence(Ordering::Release);
        self.write32(PX_CI, 1);

        for _ in 0..COMMAND_POLL_LIMIT {
            let interrupt_status = self.read32(PX_IS);
            if interrupt_status & IS_TFES != 0 || self.read32(PX_TFD) & TFD_ERR != 0 {
                self.write32(PX_IS, interrupt_status);
                return Err(HbaError::TaskFileError);
            }
            if self.read32(PX_CI) & 1 == 0 {
                compiler_fence(Ordering::Acquire);
                self.write32(PX_IS, interrupt_status);
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(HbaError::CommandTimeout)
    }

    fn issue(&mut self, lba: u64, sectors: u16, write: bool) -> Result<(), HbaError> {
        if !self.device_present() {
            return Err(HbaError::PortUnavailable);
        }
        if lba > MAX_LBA48
            || lba
                .checked_add(u64::from(sectors).saturating_sub(1))
                .is_none_or(|last| last > MAX_LBA48)
        {
            return Err(HbaError::InvalidLba);
        }
        self.wait_device_ready()?;

        // This implementation owns one command table and therefore uses slot
        // zero serially. A mutable HbaPort borrow prevents two callers from
        // preparing the slot concurrently.
        self.wait_slot_zero_available()?;

        self.prepare_command(lba, sectors, write);
        self.submit_slot_zero()
    }

    /// Read exactly one 512-byte sector.
    pub fn read_sector(
        &mut self,
        lba: u64,
        sector: &mut [u8; SECTOR_SIZE],
    ) -> Result<(), HbaError> {
        self.issue(lba, 1, false)?;
        sector.copy_from_slice(&self.dma.data.0[..SECTOR_SIZE]);
        Ok(())
    }

    /// Read one or more whole sectors, chunking through the bounded DMA arena.
    pub fn read_blocks(&mut self, lba: u64, buffer: &mut [u8]) -> Result<usize, HbaError> {
        if buffer.is_empty() || !buffer.len().is_multiple_of(SECTOR_SIZE) {
            return Err(HbaError::InvalidBuffer);
        }
        let mut done = 0usize;
        while done < buffer.len() {
            let bytes = (buffer.len() - done).min(DMA_BUFFER_SIZE);
            let sectors = (bytes / SECTOR_SIZE) as u16;
            let command_lba = lba
                .checked_add((done / SECTOR_SIZE) as u64)
                .ok_or(HbaError::InvalidLba)?;
            self.issue(command_lba, sectors, false)?;
            buffer[done..done + bytes].copy_from_slice(&self.dma.data.0[..bytes]);
            done += bytes;
        }
        Ok(done)
    }

    /// Write one or more whole sectors, chunking through the bounded DMA arena.
    pub fn write_blocks(&mut self, lba: u64, buffer: &[u8]) -> Result<usize, HbaError> {
        if buffer.is_empty() || !buffer.len().is_multiple_of(SECTOR_SIZE) {
            return Err(HbaError::InvalidBuffer);
        }
        let mut done = 0usize;
        while done < buffer.len() {
            let bytes = (buffer.len() - done).min(DMA_BUFFER_SIZE);
            self.dma.data.0[..bytes].copy_from_slice(&buffer[done..done + bytes]);
            let sectors = (bytes / SECTOR_SIZE) as u16;
            let command_lba = lba
                .checked_add((done / SECTOR_SIZE) as u64)
                .ok_or(HbaError::InvalidLba)?;
            self.issue(command_lba, sectors, true)?;
            done += bytes;
        }
        Ok(done)
    }

    /// Force all previously completed writes from the drive cache to media.
    pub fn flush_cache(&mut self) -> Result<(), HbaError> {
        if !self.device_present() {
            return Err(HbaError::PortUnavailable);
        }
        self.wait_device_ready()?;
        self.wait_slot_zero_available()?;
        self.prepare_non_data_command(ATA_FLUSH_CACHE_EXT);
        self.submit_slot_zero()
    }
}

impl Drop for HbaPort {
    fn drop(&mut self) {
        let _ = self.stop_engine();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dma_layout_obeys_ahci_alignment() {
        assert_eq!(core::mem::align_of::<CommandList>(), 1024);
        assert_eq!(core::mem::align_of::<ReceivedFis>(), 256);
        assert_eq!(core::mem::align_of::<CommandTable>(), 128);
        assert_eq!(size_of::<CommandHeader>(), 32);
        assert_eq!(size_of::<PrdtEntry>(), 16);
    }

    #[test]
    fn split_address_keeps_both_halves() {
        assert_eq!(
            split_address(0x1122_3344_AABB_CCDD),
            (0xAABB_CCDD, 0x1122_3344)
        );
    }

    #[test]
    fn transfer_bound_is_whole_sectors() {
        assert_eq!(DMA_BUFFER_SIZE, 64 * 1024);
        assert_eq!(DMA_BUFFER_SIZE / SECTOR_SIZE, MAX_SECTORS_PER_COMMAND);
    }
}
