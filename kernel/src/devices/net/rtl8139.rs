//! Realtek RTL8139 PCI Fast Ethernet driver (polling RX/TX).

use core::hint::spin_loop;
use core::ptr;

use xenith_types::PhysAddr;

use super::dma::DmaRegion;
use super::{Adapter, DriverError, NetworkAdapter};
use crate::arch::{Port16, Port32, Port8};
use crate::devices::pci::enumerate::{self, PciBarKind, PciDevice, PciDriver, PciDriverError};
use crate::devices::pci::{PciAddress, PciCommand};
use crate::net::eth::{MacAddress, MIN_FRAME_LEN};

const VENDOR_REALTEK: u16 = 0x10ec;
const DEVICE_RTL8139: u16 = 0x8139;
const DEVICE_RTL8138: u16 = 0x8138;

const IDR0: u16 = 0x00;
const TSD0: u16 = 0x10;
const TSAD0: u16 = 0x20;
const RBSTART: u16 = 0x30;
const COMMAND: u16 = 0x37;
const CAPR: u16 = 0x38;
const IMR: u16 = 0x3c;
const ISR: u16 = 0x3e;
const TCR: u16 = 0x40;
const RCR: u16 = 0x44;
const CONFIG1: u16 = 0x52;
const MEDIA_STATUS: u16 = 0x58;

const COMMAND_RESET: u8 = 1 << 4;
const COMMAND_RX_ENABLE: u8 = 1 << 3;
const COMMAND_TX_ENABLE: u8 = 1 << 2;
const COMMAND_RX_EMPTY: u8 = 1;

const RX_OK: u16 = 1;
const RX_ERROR: u16 = 1 << 1;
const TX_OK: u16 = 1 << 2;
const TX_ERROR: u16 = 1 << 3;
const RX_OVERFLOW: u16 = 1 << 4;
const LINK_CHANGE: u16 = 1 << 5;
const RX_FIFO_OVERFLOW: u16 = 1 << 6;
const SYSTEM_ERROR: u16 = 1 << 15;
const INTERRUPT_MASK: u16 = RX_OK
    | RX_ERROR
    | TX_OK
    | TX_ERROR
    | RX_OVERFLOW
    | LINK_CHANGE
    | RX_FIFO_OVERFLOW
    | SYSTEM_ERROR;
const TX_OWN: u32 = 1 << 13;
const MEDIA_LINK_BAD: u8 = 1 << 2;

const RX_RING_LEN: usize = 8192;
const RX_DMA_LEN: usize = RX_RING_LEN + 16 + 1536;
const TX_SLOTS: usize = 4;
const TX_BUFFER_LEN: usize = 2048;
const RESET_POLL_LIMIT: usize = 1_000_000;

#[derive(Clone, Copy)]
enum RegisterIo {
    Port(u16),
    Mmio(u64),
}

/// Copyable, allocation-free register handle used by the shared NIC ISR.
#[derive(Clone, Copy)]
pub(in crate::devices::net) struct InterruptHandle {
    registers: RegisterIo,
}

impl InterruptHandle {
    /// Mask further causes and acknowledge this device's currently-pending
    /// RX/TX/link/error causes. Returns zero when the shared INTx line was
    /// asserted by another function.
    pub(super) fn acknowledge_and_mask(self) -> u32 {
        let status = self.registers.read16(ISR);
        if status == u16::MAX {
            return 0;
        }
        let causes = status & INTERRUPT_MASK;
        if causes != 0 {
            self.registers.write16(IMR, 0);
            self.registers.write16(ISR, causes);
        }
        u32::from(causes)
    }

    /// Enable the bounded set of causes serviced by the network worker.
    pub(super) fn enable(self) {
        self.registers.write16(IMR, INTERRUPT_MASK);
    }
}

impl RegisterIo {
    fn read8(self, offset: u16) -> u8 {
        match self {
            Self::Port(base) => Port8::new(base.wrapping_add(offset)).read(),
            Self::Mmio(base) => {
                // SAFETY: the PCI BAR is enabled and `offset` names an RTL8139
                // byte register within its 256-byte register file.
                unsafe { ptr::read_volatile((base + u64::from(offset)) as *const u8) }
            },
        }
    }

    fn read32(self, offset: u16) -> u32 {
        match self {
            Self::Port(base) => Port32::new(base.wrapping_add(offset)).read(),
            Self::Mmio(base) => unsafe {
                ptr::read_volatile((base + u64::from(offset)) as *const u32)
            },
        }
    }

    fn read16(self, offset: u16) -> u16 {
        match self {
            Self::Port(base) => Port16::new(base.wrapping_add(offset)).read(),
            Self::Mmio(base) => unsafe {
                ptr::read_volatile((base + u64::from(offset)) as *const u16)
            },
        }
    }

    fn write8(self, offset: u16, value: u8) {
        match self {
            Self::Port(base) => Port8::new(base.wrapping_add(offset)).write(value),
            Self::Mmio(base) => unsafe {
                ptr::write_volatile((base + u64::from(offset)) as *mut u8, value)
            },
        }
    }

    fn write16(self, offset: u16, value: u16) {
        match self {
            Self::Port(base) => Port16::new(base.wrapping_add(offset)).write(value),
            Self::Mmio(base) => unsafe {
                ptr::write_volatile((base + u64::from(offset)) as *mut u16, value)
            },
        }
    }

    fn write32(self, offset: u16, value: u32) {
        match self {
            Self::Port(base) => Port32::new(base.wrapping_add(offset)).write(value),
            Self::Mmio(base) => unsafe {
                ptr::write_volatile((base + u64::from(offset)) as *mut u32, value)
            },
        }
    }
}

pub struct Rtl8139 {
    bdf: (u8, u8, u8),
    registers: RegisterIo,
    mac: MacAddress,
    rx: DmaRegion,
    tx: DmaRegion,
    rx_offset: usize,
    tx_slot: usize,
}

impl Rtl8139 {
    fn new(device: &PciDevice) -> Result<Self, DriverError> {
        let (registers, is_io) = select_bar(device)?;
        let pci_address = PciAddress::new(
            device.address.bus(),
            device.address.device(),
            device.address.function(),
        )
        .ok_or(DriverError::UnsupportedBar)?;
        let mut command = PciCommand::from_bits_truncate(pci_address.read_command());
        command |= PciCommand::BUS_MASTER;
        command |= if is_io {
            PciCommand::IO_SPACE
        } else {
            PciCommand::MEMORY_SPACE
        };
        pci_address.write_command(command.bits());

        registers.write8(CONFIG1, 0);
        registers.write8(COMMAND, COMMAND_RESET);
        let mut reset = false;
        for _ in 0..RESET_POLL_LIMIT {
            if registers.read8(COMMAND) & COMMAND_RESET == 0 {
                reset = true;
                break;
            }
            spin_loop();
        }
        if !reset {
            return Err(DriverError::ResetTimeout);
        }

        let rx = DmaRegion::allocate(RX_DMA_LEN, Some(u64::from(u32::MAX)))?;
        let tx = DmaRegion::allocate(TX_SLOTS * TX_BUFFER_LEN, Some(u64::from(u32::MAX)))?;
        let mut mac_bytes = [0u8; 6];
        for (index, byte) in mac_bytes.iter_mut().enumerate() {
            *byte = registers.read8(IDR0 + index as u16);
        }
        let mac = MacAddress(mac_bytes);
        if mac.is_zero() || mac.is_broadcast() || mac.is_multicast() {
            return Err(DriverError::InvalidMac);
        }

        registers.write16(IMR, 0);
        registers.write16(ISR, u16::MAX);
        registers.write32(RBSTART, rx.physical_address() as u32);
        for slot in 0..TX_SLOTS {
            registers.write32(
                TSAD0 + (slot as u16) * 4,
                tx.physical_at(slot * TX_BUFFER_LEN)
                    .ok_or(DriverError::DmaUnavailable)? as u32,
            );
        }
        // 1024-byte DMA bursts, IFG=96 bits, no loopback.
        registers.write32(TCR, (6 << 8) | (3 << 24));
        // Accept physical-match, multicast, broadcast, and all-multicast
        // frames; WRAP lets the device use the documented overrun tail.
        registers.write32(RCR, (7 << 8) | (1 << 7) | 0x0e);
        registers.write16(CAPR, 0xfff0);
        registers.write8(COMMAND, COMMAND_RX_ENABLE | COMMAND_TX_ENABLE);

        Ok(Self {
            bdf: (
                device.address.bus(),
                device.address.device(),
                device.address.function(),
            ),
            registers,
            mac,
            rx,
            tx,
            rx_offset: 0,
            tx_slot: 0,
        })
    }

    #[must_use]
    pub const fn bdf(&self) -> (u8, u8, u8) {
        self.bdf
    }

    pub(super) const fn interrupt_handle(&self) -> InterruptHandle {
        InterruptHandle {
            registers: self.registers,
        }
    }

    fn ring_byte(&self, offset: usize) -> u8 {
        self.rx
            .slice(offset % RX_RING_LEN, 1)
            .expect("ring offset is in DMA region")[0]
    }

    fn ring_u16(&self, offset: usize) -> u16 {
        u16::from_le_bytes([self.ring_byte(offset), self.ring_byte(offset + 1)])
    }

    fn copy_from_ring(&self, offset: usize, output: &mut [u8]) {
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = self.ring_byte(offset + index);
        }
    }

    fn recover_receiver(&mut self) {
        let command = self.registers.read8(COMMAND);
        self.registers.write8(COMMAND, command & !COMMAND_RX_ENABLE);
        self.rx_offset = 0;
        self.registers
            .write32(RBSTART, self.rx.physical_address() as u32);
        self.registers.write16(CAPR, 0xfff0);
        self.registers
            .write8(COMMAND, command | COMMAND_RX_ENABLE | COMMAND_TX_ENABLE);
    }
}

impl NetworkAdapter for Rtl8139 {
    fn driver_name(&self) -> &'static str {
        "rtl8139"
    }

    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn link_up(&self) -> bool {
        self.registers.read8(MEDIA_STATUS) & MEDIA_LINK_BAD == 0
    }

    fn mtu(&self) -> usize {
        1500
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), DriverError> {
        if frame.len() > 1514 {
            return Err(DriverError::FrameTooLarge);
        }
        let status_offset = TSD0 + (self.tx_slot as u16) * 4;
        if self.registers.read32(status_offset) & TX_OWN == 0 {
            return Err(DriverError::WouldBlock);
        }
        let length = frame.len().max(MIN_FRAME_LEN);
        let buffer = self
            .tx
            .slice_mut(self.tx_slot * TX_BUFFER_LEN, length)
            .ok_or(DriverError::DmaUnavailable)?;
        buffer.fill(0);
        buffer[..frame.len()].copy_from_slice(frame);
        self.tx.sync_for_device();
        self.registers.write32(status_offset, length as u32);
        self.tx_slot = (self.tx_slot + 1) % TX_SLOTS;
        Ok(())
    }

    fn poll_receive(&mut self, output: &mut [u8]) -> Result<usize, DriverError> {
        if self.registers.read8(COMMAND) & COMMAND_RX_EMPTY != 0 {
            return Err(DriverError::NoPacket);
        }
        self.rx.sync_for_cpu();
        let status = self.ring_u16(self.rx_offset);
        let dma_length = usize::from(self.ring_u16(self.rx_offset + 2));
        if status & RX_OK == 0 || !(4..=1518).contains(&dma_length) {
            self.recover_receiver();
            return Err(DriverError::DeviceFault);
        }
        let frame_length = dma_length - 4;
        if output.len() < frame_length {
            return Err(DriverError::BufferTooSmall);
        }
        self.copy_from_ring(self.rx_offset + 4, &mut output[..frame_length]);
        self.rx_offset = (self.rx_offset + 4 + dma_length + 3) & !3;
        self.rx_offset %= RX_RING_LEN;
        self.registers
            .write16(CAPR, self.rx_offset.wrapping_sub(16) as u16);
        self.registers.write16(ISR, u16::MAX);
        Ok(frame_length)
    }
}

fn select_bar(device: &PciDevice) -> Result<(RegisterIo, bool), DriverError> {
    let mut io = None;
    let mut mmio = None;
    for index in 0u8..6 {
        if device.bar_is_high_half(index) {
            continue;
        }
        let Some(bar) = device.bar(index) else {
            continue;
        };
        if bar.address == 0 {
            continue;
        }
        match bar.kind {
            PciBarKind::Io if bar.address <= u64::from(u16::MAX) => {
                io.get_or_insert(RegisterIo::Port(bar.address as u16));
            },
            PciBarKind::Mem32 | PciBarKind::Mem64 => {
                let virtual_address =
                    crate::mm::phys_to_virt(PhysAddr::new_truncate(bar.address)).as_u64();
                mmio.get_or_insert(RegisterIo::Mmio(virtual_address));
            },
            _ => {},
        }
    }
    mmio.map(|registers| (registers, false))
        .or_else(|| io.map(|registers| (registers, true)))
        .ok_or(DriverError::UnsupportedBar)
}

struct Rtl8139PciDriver;
static RTL8139_PCI_DRIVER: Rtl8139PciDriver = Rtl8139PciDriver;

impl PciDriver for Rtl8139PciDriver {
    fn name(&self) -> &'static str {
        "rtl8139"
    }

    fn matches(&self, device: &PciDevice) -> bool {
        device.vendor_id == VENDOR_REALTEK
            && matches!(device.device_id, DEVICE_RTL8139 | DEVICE_RTL8138)
            && device.base_class == 0x02
    }

    fn probe(&self, device: &PciDevice) -> Result<(), PciDriverError> {
        let adapter = Rtl8139::new(device).map_err(|error| {
            ::log::warn!("rtl8139: {} setup failed: {:?}", device.address, error);
            match error {
                DriverError::UnsupportedBar => PciDriverError::BarUnreadable,
                _ => PciDriverError::ProbeFailed("RTL8139 initialization failed"),
            }
        })?;
        let mac = adapter.mac_address();
        let link = adapter.link_up();
        let interrupt = adapter.interrupt_handle();
        if let Some(index) = super::attach(Adapter::Rtl8139(adapter)) {
            let interrupt_mode =
                super::configure_intx(device, index, super::IrqDevice::Rtl8139(interrupt));
            ::log::info!(
                "rtl8139: {} attached, MAC {}, link={}, service={}",
                device.address,
                mac,
                if link { "up" } else { "down" },
                if interrupt_mode { "INTx" } else { "poll" }
            );
        }
        Ok(())
    }
}

pub fn register_pci_driver() {
    enumerate::register_driver(&RTL8139_PCI_DRIVER);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupt_mask_covers_rx_tx_link_and_fault_causes() {
        assert_ne!(INTERRUPT_MASK & RX_OK, 0);
        assert_ne!(INTERRUPT_MASK & TX_OK, 0);
        assert_ne!(INTERRUPT_MASK & LINK_CHANGE, 0);
        assert_ne!(INTERRUPT_MASK & SYSTEM_ERROR, 0);
        assert_eq!(INTERRUPT_MASK & (1 << 14), 0);
    }
}
