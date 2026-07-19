//! Intel 8254x/e1000 PCI Ethernet driver with DMA descriptor rings.

use core::hint::spin_loop;
use core::mem::size_of;
use core::ptr;

use xenith_types::PhysAddr;

use super::dma::DmaRegion;
use super::{Adapter, DriverError, NetworkAdapter};
use crate::devices::pci::enumerate::{self, PciBarKind, PciDevice, PciDriver, PciDriverError};
use crate::devices::pci::{PciAddress, PciCommand};
use crate::net::eth::{MacAddress, MIN_FRAME_LEN};

const VENDOR_INTEL: u16 = 0x8086;
const SUPPORTED_IDS: &[u16] = &[
    0x100e, // 82540EM (QEMU default)
    0x100f, // 82545EM
    0x1010, // 82546EB
    0x107c, // 82541PI
    0x10d3, // 82574L
    0x153a, // I217-LM
];

const CTRL: usize = 0x0000;
const STATUS: usize = 0x0008;
const EERD: usize = 0x0014;
const ICR: usize = 0x00c0;
const IMS: usize = 0x00d0;
const IMC: usize = 0x00d8;
const RCTL: usize = 0x0100;
const TCTL: usize = 0x0400;
const TIPG: usize = 0x0410;
const RDBAL: usize = 0x2800;
const RDBAH: usize = 0x2804;
const RDLEN: usize = 0x2808;
const RDH: usize = 0x2810;
const RDT: usize = 0x2818;
const TDBAL: usize = 0x3800;
const TDBAH: usize = 0x3804;
const TDLEN: usize = 0x3808;
const TDH: usize = 0x3810;
const TDT: usize = 0x3818;
const RAL0: usize = 0x5400;
const RAH0: usize = 0x5404;

const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;
const STATUS_LU: u32 = 1 << 1;
const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;

const RX_STATUS_DD: u8 = 1;
const RX_STATUS_EOP: u8 = 1 << 1;
const TX_STATUS_DD: u8 = 1;
const TX_CMD_EOP: u8 = 1;
const TX_CMD_IFCS: u8 = 1 << 1;
const TX_CMD_RS: u8 = 1 << 3;

const INTERRUPT_TX_DESCRIPTOR_WRITTEN: u32 = 1 << 0;
const INTERRUPT_LINK_STATUS_CHANGE: u32 = 1 << 2;
const INTERRUPT_RX_SEQUENCE_ERROR: u32 = 1 << 3;
const INTERRUPT_RX_DESCRIPTOR_MINIMUM: u32 = 1 << 4;
const INTERRUPT_RX_OVERRUN: u32 = 1 << 6;
const INTERRUPT_RX_TIMER: u32 = 1 << 7;
const INTERRUPT_MASK: u32 = INTERRUPT_TX_DESCRIPTOR_WRITTEN
    | INTERRUPT_LINK_STATUS_CHANGE
    | INTERRUPT_RX_SEQUENCE_ERROR
    | INTERRUPT_RX_DESCRIPTOR_MINIMUM
    | INTERRUPT_RX_OVERRUN
    | INTERRUPT_RX_TIMER;

const RING_COUNT: usize = 32;
const BUFFER_LEN: usize = 2048;
const RESET_POLL_LIMIT: usize = 2_000_000;
const EEPROM_POLL_LIMIT: usize = 100_000;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RxDescriptor {
    address: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TxDescriptor {
    address: u64,
    length: u16,
    checksum_offset: u8,
    command: u8,
    status: u8,
    checksum_start: u8,
    special: u16,
}

#[derive(Clone, Copy)]
struct Mmio {
    base: u64,
}

/// Copyable MMIO handle used by the shared, allocation-free NIC ISR.
#[derive(Clone, Copy)]
pub(in crate::devices::net) struct InterruptHandle {
    registers: Mmio,
}

impl InterruptHandle {
    /// Read-to-clear the e1000 cause register, mask the service causes when
    /// this function asserted the shared line, and return the claimed bits.
    pub(super) fn acknowledge_and_mask(self) -> u32 {
        let status = self.registers.read32(ICR);
        if status == u32::MAX {
            return 0;
        }
        let causes = status & INTERRUPT_MASK;
        if causes != 0 {
            self.registers.write32(IMC, INTERRUPT_MASK);
        }
        causes
    }

    /// Re-arm only the RX/TX/link/error causes handled by the worker.
    pub(super) fn enable(self) {
        self.registers.write32(IMS, INTERRUPT_MASK);
    }
}

impl Mmio {
    fn read32(self, offset: usize) -> u32 {
        // SAFETY: `base` is the HHDM mapping of BAR0 and every offset used by
        // this module is an aligned e1000 32-bit register.
        unsafe { ptr::read_volatile((self.base + offset as u64) as *const u32) }
    }

    fn write32(self, offset: usize, value: u32) {
        // SAFETY: same BAR/register invariant as read32.
        unsafe { ptr::write_volatile((self.base + offset as u64) as *mut u32, value) }
    }
}

pub struct E1000 {
    bdf: (u8, u8, u8),
    registers: Mmio,
    mac: MacAddress,
    rx_descriptors: DmaRegion,
    tx_descriptors: DmaRegion,
    rx_buffers: DmaRegion,
    tx_buffers: DmaRegion,
    rx_index: usize,
    tx_index: usize,
}

impl E1000 {
    fn new(device: &PciDevice) -> Result<Self, DriverError> {
        let registers = select_bar(device)?;
        let pci_address = PciAddress::new(
            device.address.bus(),
            device.address.device(),
            device.address.function(),
        )
        .ok_or(DriverError::UnsupportedBar)?;
        let command = PciCommand::from_bits_truncate(pci_address.read_command())
            | PciCommand::MEMORY_SPACE
            | PciCommand::BUS_MASTER;
        pci_address.write_command(command.bits());

        registers.write32(IMC, u32::MAX);
        registers.write32(CTRL, registers.read32(CTRL) | CTRL_RST);
        let mut reset = false;
        for _ in 0..RESET_POLL_LIMIT {
            if registers.read32(CTRL) & CTRL_RST == 0 {
                reset = true;
                break;
            }
            spin_loop();
        }
        if !reset {
            return Err(DriverError::ResetTimeout);
        }
        registers.write32(IMC, u32::MAX);
        let _ = registers.read32(ICR);
        registers.write32(CTRL, registers.read32(CTRL) | CTRL_SLU);

        let mac = read_mac(registers)?;
        let mut rx_descriptors = DmaRegion::allocate(RING_COUNT * size_of::<RxDescriptor>(), None)?;
        let mut tx_descriptors = DmaRegion::allocate(RING_COUNT * size_of::<TxDescriptor>(), None)?;
        let rx_buffers = DmaRegion::allocate(RING_COUNT * BUFFER_LEN, None)?;
        let tx_buffers = DmaRegion::allocate(RING_COUNT * BUFFER_LEN, None)?;

        for index in 0..RING_COUNT {
            let rx = RxDescriptor {
                address: rx_buffers
                    .physical_at(index * BUFFER_LEN)
                    .ok_or(DriverError::DmaUnavailable)?,
                ..RxDescriptor::default()
            };
            let tx = TxDescriptor {
                address: tx_buffers
                    .physical_at(index * BUFFER_LEN)
                    .ok_or(DriverError::DmaUnavailable)?,
                status: TX_STATUS_DD,
                ..TxDescriptor::default()
            };
            // SAFETY: descriptor regions are page-aligned, large enough for
            // RING_COUNT entries, and uniquely borrowed during setup.
            unsafe {
                (rx_descriptors.as_mut_ptr() as *mut RxDescriptor)
                    .add(index)
                    .write(rx);
                (tx_descriptors.as_mut_ptr() as *mut TxDescriptor)
                    .add(index)
                    .write(tx);
            }
        }
        rx_descriptors.sync_for_device();
        tx_descriptors.sync_for_device();

        program_ring(
            registers,
            RDBAL,
            RDBAH,
            RDLEN,
            rx_descriptors.physical_address(),
            RING_COUNT * size_of::<RxDescriptor>(),
        );
        registers.write32(RDH, 0);
        registers.write32(RDT, (RING_COUNT - 1) as u32);
        program_ring(
            registers,
            TDBAL,
            TDBAH,
            TDLEN,
            tx_descriptors.physical_address(),
            RING_COUNT * size_of::<TxDescriptor>(),
        );
        registers.write32(TDH, 0);
        registers.write32(TDT, 0);

        // Receive physical-address matches plus broadcast, strip Ethernet CRC.
        registers.write32(RCTL, RCTL_EN | RCTL_BAM | RCTL_SECRC);
        // Pad short frames, collision threshold 16, collision distance 64.
        registers.write32(TCTL, TCTL_EN | TCTL_PSP | (0x10 << 4) | (0x40 << 12));
        registers.write32(TIPG, 10 | (8 << 10) | (6 << 20));

        Ok(Self {
            bdf: (
                device.address.bus(),
                device.address.device(),
                device.address.function(),
            ),
            registers,
            mac,
            rx_descriptors,
            tx_descriptors,
            rx_buffers,
            tx_buffers,
            rx_index: 0,
            tx_index: 0,
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

    fn rx_descriptor(&self, index: usize) -> RxDescriptor {
        // SAFETY: index is always modulo RING_COUNT and the DMA ring contains
        // exactly that many aligned descriptors. Volatile observes DMA writes.
        unsafe {
            ptr::read_volatile((self.rx_descriptors.as_ptr() as *const RxDescriptor).add(index))
        }
    }

    fn write_rx_descriptor(&mut self, index: usize, descriptor: RxDescriptor) {
        unsafe {
            ptr::write_volatile(
                (self.rx_descriptors.as_mut_ptr() as *mut RxDescriptor).add(index),
                descriptor,
            )
        }
    }

    fn tx_descriptor(&self, index: usize) -> TxDescriptor {
        unsafe {
            ptr::read_volatile((self.tx_descriptors.as_ptr() as *const TxDescriptor).add(index))
        }
    }

    fn write_tx_descriptor(&mut self, index: usize, descriptor: TxDescriptor) {
        unsafe {
            ptr::write_volatile(
                (self.tx_descriptors.as_mut_ptr() as *mut TxDescriptor).add(index),
                descriptor,
            )
        }
    }
}

impl NetworkAdapter for E1000 {
    fn driver_name(&self) -> &'static str {
        "e1000"
    }

    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn link_up(&self) -> bool {
        self.registers.read32(STATUS) & STATUS_LU != 0
    }

    fn mtu(&self) -> usize {
        1500
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), DriverError> {
        if frame.len() > 1514 {
            return Err(DriverError::FrameTooLarge);
        }
        self.tx_descriptors.sync_for_cpu();
        let mut descriptor = self.tx_descriptor(self.tx_index);
        if descriptor.status & TX_STATUS_DD == 0 {
            return Err(DriverError::WouldBlock);
        }
        let length = frame.len().max(MIN_FRAME_LEN);
        let buffer = self
            .tx_buffers
            .slice_mut(self.tx_index * BUFFER_LEN, length)
            .ok_or(DriverError::DmaUnavailable)?;
        buffer.fill(0);
        buffer[..frame.len()].copy_from_slice(frame);
        self.tx_buffers.sync_for_device();
        descriptor.length = length as u16;
        descriptor.command = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
        descriptor.status = 0;
        self.write_tx_descriptor(self.tx_index, descriptor);
        self.tx_descriptors.sync_for_device();
        self.tx_index = (self.tx_index + 1) % RING_COUNT;
        self.registers.write32(TDT, self.tx_index as u32);
        Ok(())
    }

    fn poll_receive(&mut self, output: &mut [u8]) -> Result<usize, DriverError> {
        self.rx_descriptors.sync_for_cpu();
        let mut descriptor = self.rx_descriptor(self.rx_index);
        if descriptor.status & RX_STATUS_DD == 0 {
            return Err(DriverError::NoPacket);
        }
        if descriptor.status & RX_STATUS_EOP == 0 || descriptor.errors != 0 {
            descriptor.status = 0;
            self.write_rx_descriptor(self.rx_index, descriptor);
            self.rx_descriptors.sync_for_device();
            self.registers.write32(RDT, self.rx_index as u32);
            self.rx_index = (self.rx_index + 1) % RING_COUNT;
            return Err(DriverError::DeviceFault);
        }
        let length = usize::from(descriptor.length);
        if length > 1514 {
            descriptor.status = 0;
            descriptor.length = 0;
            self.write_rx_descriptor(self.rx_index, descriptor);
            self.rx_descriptors.sync_for_device();
            let completed = self.rx_index;
            self.rx_index = (self.rx_index + 1) % RING_COUNT;
            self.registers.write32(RDT, completed as u32);
            return Err(DriverError::DeviceFault);
        }
        if output.len() < length {
            return Err(DriverError::BufferTooSmall);
        }
        self.rx_buffers.sync_for_cpu();
        let buffer = self
            .rx_buffers
            .slice(self.rx_index * BUFFER_LEN, length)
            .ok_or(DriverError::DmaUnavailable)?;
        output[..length].copy_from_slice(buffer);
        descriptor.status = 0;
        descriptor.length = 0;
        self.write_rx_descriptor(self.rx_index, descriptor);
        self.rx_descriptors.sync_for_device();
        let completed = self.rx_index;
        self.rx_index = (self.rx_index + 1) % RING_COUNT;
        self.registers.write32(RDT, completed as u32);
        Ok(length)
    }
}

fn select_bar(device: &PciDevice) -> Result<Mmio, DriverError> {
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
        if matches!(bar.kind, PciBarKind::Mem32 | PciBarKind::Mem64) {
            return Ok(Mmio {
                base: crate::mm::phys_to_virt(PhysAddr::new_truncate(bar.address)).as_u64(),
            });
        }
    }
    Err(DriverError::UnsupportedBar)
}

fn read_mac(registers: Mmio) -> Result<MacAddress, DriverError> {
    let low = registers.read32(RAL0);
    let high = registers.read32(RAH0);
    let mut bytes = [
        low as u8,
        (low >> 8) as u8,
        (low >> 16) as u8,
        (low >> 24) as u8,
        high as u8,
        (high >> 8) as u8,
    ];
    let mut mac = MacAddress(bytes);
    if mac.is_zero() || mac.is_broadcast() || mac.is_multicast() {
        for word in 0..3u16 {
            let value = read_eeprom_word(registers, word)?;
            bytes[usize::from(word) * 2] = value as u8;
            bytes[usize::from(word) * 2 + 1] = (value >> 8) as u8;
        }
        mac = MacAddress(bytes);
    }
    if mac.is_zero() || mac.is_broadcast() || mac.is_multicast() {
        return Err(DriverError::InvalidMac);
    }
    // Ensure receive address zero is programmed and marked valid after reset.
    registers.write32(
        RAL0,
        u32::from_le_bytes(bytes[..4].try_into().expect("four bytes")),
    );
    registers.write32(
        RAH0,
        u32::from(u16::from_le_bytes([bytes[4], bytes[5]])) | (1 << 31),
    );
    Ok(mac)
}

fn read_eeprom_word(registers: Mmio, address: u16) -> Result<u16, DriverError> {
    registers.write32(EERD, (u32::from(address) << 8) | 1);
    for _ in 0..EEPROM_POLL_LIMIT {
        let value = registers.read32(EERD);
        if value & (1 << 4) != 0 {
            return Ok((value >> 16) as u16);
        }
        spin_loop();
    }
    Err(DriverError::DeviceFault)
}

fn program_ring(
    registers: Mmio,
    low_register: usize,
    high_register: usize,
    length_register: usize,
    address: u64,
    length: usize,
) {
    registers.write32(low_register, address as u32);
    registers.write32(high_register, (address >> 32) as u32);
    registers.write32(length_register, length as u32);
}

struct E1000PciDriver;
static E1000_PCI_DRIVER: E1000PciDriver = E1000PciDriver;

impl PciDriver for E1000PciDriver {
    fn name(&self) -> &'static str {
        "e1000"
    }

    fn matches(&self, device: &PciDevice) -> bool {
        device.vendor_id == VENDOR_INTEL
            && SUPPORTED_IDS.contains(&device.device_id)
            && device.base_class == 0x02
    }

    fn probe(&self, device: &PciDevice) -> Result<(), PciDriverError> {
        let adapter = E1000::new(device).map_err(|error| {
            ::log::warn!("e1000: {} setup failed: {:?}", device.address, error);
            match error {
                DriverError::UnsupportedBar => PciDriverError::BarUnreadable,
                _ => PciDriverError::ProbeFailed("e1000 initialization failed"),
            }
        })?;
        let mac = adapter.mac_address();
        let link = adapter.link_up();
        let interrupt = adapter.interrupt_handle();
        if let Some(index) = super::attach(Adapter::E1000(adapter)) {
            let interrupt_mode =
                super::configure_interrupt(device, index, super::IrqDevice::E1000(interrupt));
            ::log::info!(
                "e1000: {} attached, MAC {}, link={}, service={}",
                device.address,
                mac,
                if link { "up" } else { "down" },
                interrupt_mode.label()
            );
        }
        Ok(())
    }
}

pub fn register_pci_driver() {
    enumerate::register_driver(&E1000_PCI_DRIVER);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupt_mask_covers_rx_tx_link_and_fault_causes() {
        assert_ne!(INTERRUPT_MASK & INTERRUPT_TX_DESCRIPTOR_WRITTEN, 0);
        assert_ne!(INTERRUPT_MASK & INTERRUPT_RX_TIMER, 0);
        assert_ne!(INTERRUPT_MASK & INTERRUPT_RX_OVERRUN, 0);
        assert_ne!(INTERRUPT_MASK & INTERRUPT_LINK_STATUS_CHANGE, 0);
        assert_eq!(INTERRUPT_MASK & (1 << 5), 0);
    }
}
