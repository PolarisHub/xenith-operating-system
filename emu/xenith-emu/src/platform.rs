//! Register-level platform devices that back image-oriented emulator runs.
//!
//! These models intentionally stay deterministic: ATA media is an in-memory
//! byte vector, PCI configuration is a fixed legacy topology, and HPET time is
//! derived from interpreted CPU cycles rather than host wall-clock time.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::device::Device;

const ATA_SECTOR_SIZE: usize = 512;
const ATA_PRIMARY_BASE: u16 = 0x1F0;
const ATA_PRIMARY_CONTROL: u16 = 0x3F6;
const ATA_STATUS_ERR: u8 = 1 << 0;
const ATA_STATUS_DRQ: u8 = 1 << 3;
const ATA_STATUS_DRDY: u8 = 1 << 6;
const ATA_ERROR_ABORTED: u8 = 1 << 2;
const ATA_ERROR_ID_NOT_FOUND: u8 = 1 << 4;

/// Shareable backing bytes for one primary-master ATA disk.
#[derive(Clone)]
pub struct AtaDiskImage {
    bytes: Arc<Mutex<Vec<u8>>>,
    changed: Arc<AtomicBool>,
    read_only: bool,
}

impl AtaDiskImage {
    /// Create a sector-aligned ATA disk image.
    pub fn new(bytes: Vec<u8>, read_only: bool) -> Result<Self, AtaDiskError> {
        if bytes.is_empty() || !bytes.len().is_multiple_of(ATA_SECTOR_SIZE) {
            return Err(AtaDiskError::InvalidLength(bytes.len()));
        }
        Ok(Self {
            bytes: Arc::new(Mutex::new(bytes)),
            changed: Arc::new(AtomicBool::new(false)),
            read_only,
        })
    }

    /// Return a consistent copy suitable for an explicit CLI output image.
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        self.bytes
            .lock()
            .map_or_else(|_| Vec::new(), |bytes| bytes.clone())
    }

    #[must_use]
    pub fn changed(&self) -> bool {
        self.changed.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    fn sector_count(&self) -> u64 {
        self.bytes
            .lock()
            .map_or(0, |bytes| (bytes.len() / ATA_SECTOR_SIZE) as u64)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtaDiskError {
    InvalidLength(usize),
}

enum AtaTransfer {
    None,
    Read {
        bytes: Vec<u8>,
        cursor: usize,
    },
    Write {
        offset: usize,
        bytes: Vec<u8>,
        cursor: usize,
    },
}

/// Primary-master ATA task-file device with PIO LBA28/LBA48 transfers.
pub struct AtaPioDisk {
    image: AtaDiskImage,
    error: u8,
    features: [u8; 2],
    sector_count: [u8; 2],
    lba_low: [u8; 2],
    lba_mid: [u8; 2],
    lba_high: [u8; 2],
    device: u8,
    status: u8,
    control: u8,
    pending_irq: bool,
    transfer: AtaTransfer,
}

impl AtaPioDisk {
    #[must_use]
    pub fn new(image: AtaDiskImage) -> Self {
        Self {
            image,
            error: 0,
            features: [0; 2],
            sector_count: [0; 2],
            lba_low: [0; 2],
            lba_mid: [0; 2],
            lba_high: [0; 2],
            device: 0xE0,
            status: ATA_STATUS_DRDY,
            control: 0,
            pending_irq: false,
            transfer: AtaTransfer::None,
        }
    }

    fn reset_task_file(&mut self) {
        self.error = 1;
        self.features = [0; 2];
        self.sector_count = [0, 1];
        self.lba_low = [0, 1];
        self.lba_mid = [0, 0];
        self.lba_high = [0, 0];
        self.device = 0xE0;
        self.status = ATA_STATUS_DRDY;
        self.pending_irq = false;
        self.transfer = AtaTransfer::None;
    }

    fn record(pair: &mut [u8; 2], value: u8) {
        pair[0] = pair[1];
        pair[1] = value;
    }

    fn lba48(&self) -> u64 {
        u64::from(self.lba_low[1])
            | (u64::from(self.lba_mid[1]) << 8)
            | (u64::from(self.lba_high[1]) << 16)
            | (u64::from(self.lba_low[0]) << 24)
            | (u64::from(self.lba_mid[0]) << 32)
            | (u64::from(self.lba_high[0]) << 40)
    }

    fn lba28(&self) -> u64 {
        u64::from(self.lba_low[1])
            | (u64::from(self.lba_mid[1]) << 8)
            | (u64::from(self.lba_high[1]) << 16)
            | (u64::from(self.device & 0x0F) << 24)
    }

    fn transfer_sectors(&self, extended: bool) -> u32 {
        if extended {
            let count = u16::from(self.sector_count[1]) | (u16::from(self.sector_count[0]) << 8);
            if count == 0 {
                65_536
            } else {
                u32::from(count)
            }
        } else if self.sector_count[1] == 0 {
            256
        } else {
            u32::from(self.sector_count[1])
        }
    }

    fn byte_range(&self, lba: u64, sectors: u32) -> Option<(usize, usize)> {
        let start = lba.checked_mul(ATA_SECTOR_SIZE as u64)?;
        let length = u64::from(sectors).checked_mul(ATA_SECTOR_SIZE as u64)?;
        let end = start.checked_add(length)?;
        (end <= self.image.sector_count() * ATA_SECTOR_SIZE as u64).then(|| {
            (
                usize::try_from(start).ok().unwrap_or(usize::MAX),
                usize::try_from(end).ok().unwrap_or(usize::MAX),
            )
        })
    }

    fn fail(&mut self, error: u8) {
        self.error = error;
        self.status = ATA_STATUS_DRDY | ATA_STATUS_ERR;
        self.pending_irq = true;
        self.transfer = AtaTransfer::None;
    }

    fn identify(&mut self) {
        let sectors = self.image.sector_count();
        let mut bytes = vec![0_u8; ATA_SECTOR_SIZE];
        put_identify_word(&mut bytes, 0, 0x0040);
        put_identify_ascii(&mut bytes, 10, 20, b"XENITH00000000000001");
        put_identify_ascii(&mut bytes, 23, 8, b"0.1");
        put_identify_ascii(&mut bytes, 27, 40, b"Xenith deterministic ATA disk");
        put_identify_word(&mut bytes, 49, 1 << 9);
        put_identify_word(&mut bytes, 60, sectors.min(0x0FFF_FFFF) as u16);
        put_identify_word(&mut bytes, 61, (sectors.min(0x0FFF_FFFF) >> 16) as u16);
        put_identify_word(&mut bytes, 83, 1 << 10);
        for (index, word) in [
            sectors as u16,
            (sectors >> 16) as u16,
            (sectors >> 32) as u16,
            (sectors >> 48) as u16,
        ]
        .into_iter()
        .enumerate()
        {
            put_identify_word(&mut bytes, 100 + index, word);
        }
        self.start_read(bytes);
    }

    fn start_rw(&mut self, extended: bool, write: bool) {
        if self.device & 0x10 != 0 {
            self.fail(ATA_ERROR_ABORTED);
            return;
        }
        let lba = if extended { self.lba48() } else { self.lba28() };
        let sectors = self.transfer_sectors(extended);
        let Some((start, end)) = self.byte_range(lba, sectors) else {
            self.fail(ATA_ERROR_ID_NOT_FOUND);
            return;
        };
        if start == usize::MAX || end == usize::MAX {
            self.fail(ATA_ERROR_ID_NOT_FOUND);
            return;
        }
        if write {
            if self.image.read_only() {
                self.fail(ATA_ERROR_ABORTED);
                return;
            }
            self.error = 0;
            self.status = ATA_STATUS_DRDY | ATA_STATUS_DRQ;
            self.transfer = AtaTransfer::Write {
                offset: start,
                bytes: vec![0; end - start],
                cursor: 0,
            };
        } else {
            let bytes = self
                .image
                .bytes
                .lock()
                .ok()
                .and_then(|image| image.get(start..end).map(<[u8]>::to_vec));
            match bytes {
                Some(bytes) => self.start_read(bytes),
                None => self.fail(ATA_ERROR_ID_NOT_FOUND),
            }
        }
    }

    fn start_read(&mut self, bytes: Vec<u8>) {
        self.error = 0;
        self.status = ATA_STATUS_DRDY | ATA_STATUS_DRQ;
        self.transfer = AtaTransfer::Read { bytes, cursor: 0 };
    }

    fn command(&mut self, command: u8) {
        self.pending_irq = false;
        match command {
            0x20 => self.start_rw(false, false),
            0x24 => self.start_rw(true, false),
            0x30 => self.start_rw(false, true),
            0x34 => self.start_rw(true, true),
            0xE7 | 0xEA => {
                self.error = 0;
                self.status = ATA_STATUS_DRDY;
                self.pending_irq = true;
            },
            0xEC => self.identify(),
            _ => self.fail(ATA_ERROR_ABORTED),
        }
    }

    fn read_data(&mut self, size: u8) -> u32 {
        if !matches!(size, 1 | 2 | 4) {
            return u32::MAX;
        }
        let mut output = 0u32;
        let mut completed = false;
        if let AtaTransfer::Read { bytes, cursor } = &mut self.transfer {
            for index in 0..usize::from(size) {
                if let Some(byte) = bytes.get(*cursor).copied() {
                    output |= u32::from(byte) << (index * 8);
                    *cursor += 1;
                }
            }
            completed = *cursor >= bytes.len();
        }
        if completed {
            self.transfer = AtaTransfer::None;
            self.status = ATA_STATUS_DRDY;
            self.pending_irq = true;
        }
        output
    }

    fn write_data(&mut self, size: u8, value: u32) {
        if !matches!(size, 1 | 2 | 4) {
            return;
        }
        let mut completed = None;
        if let AtaTransfer::Write {
            offset,
            bytes,
            cursor,
        } = &mut self.transfer
        {
            for index in 0..usize::from(size) {
                if let Some(byte) = bytes.get_mut(*cursor) {
                    *byte = (value >> (index * 8)) as u8;
                    *cursor += 1;
                }
            }
            if *cursor >= bytes.len() {
                completed = Some((*offset, std::mem::take(bytes)));
            }
        }
        if let Some((offset, bytes)) = completed {
            let stored = self.image.bytes.lock().is_ok_and(|mut image| {
                image
                    .get_mut(offset..offset + bytes.len())
                    .is_some_and(|target| {
                        target.copy_from_slice(&bytes);
                        true
                    })
            });
            if stored {
                self.image.changed.store(true, Ordering::Release);
                self.transfer = AtaTransfer::None;
                self.status = ATA_STATUS_DRDY;
                self.pending_irq = true;
            } else {
                self.fail(ATA_ERROR_ID_NOT_FOUND);
            }
        }
    }
}

impl Device for AtaPioDisk {
    fn name(&self) -> &'static str {
        "primary-master ATA PIO disk"
    }

    fn read_port(&mut self, port: u16, size: u8) -> Option<u32> {
        if port == ATA_PRIMARY_CONTROL && size == 1 {
            return Some(u32::from(self.status));
        }
        if !(ATA_PRIMARY_BASE..=ATA_PRIMARY_BASE + 7).contains(&port) {
            return None;
        }
        match port - ATA_PRIMARY_BASE {
            0 => Some(self.read_data(size)),
            1 if size == 1 => Some(u32::from(self.error)),
            2 if size == 1 => Some(u32::from(self.sector_count[1])),
            3 if size == 1 => Some(u32::from(self.lba_low[1])),
            4 if size == 1 => Some(u32::from(self.lba_mid[1])),
            5 if size == 1 => Some(u32::from(self.lba_high[1])),
            6 if size == 1 => Some(u32::from(self.device)),
            7 if size == 1 => {
                self.pending_irq = false;
                Some(u32::from(self.status))
            },
            _ => Some(u32::MAX),
        }
    }

    fn write_port(&mut self, port: u16, size: u8, value: u32) -> bool {
        if port == ATA_PRIMARY_CONTROL && size == 1 {
            let previous = self.control;
            self.control = value as u8;
            if previous & 4 != 0 && self.control & 4 == 0 {
                self.reset_task_file();
            }
            return true;
        }
        if !(ATA_PRIMARY_BASE..=ATA_PRIMARY_BASE + 7).contains(&port) {
            return false;
        }
        match port - ATA_PRIMARY_BASE {
            0 => self.write_data(size, value),
            1 if size == 1 => Self::record(&mut self.features, value as u8),
            2 if size == 1 => Self::record(&mut self.sector_count, value as u8),
            3 if size == 1 => Self::record(&mut self.lba_low, value as u8),
            4 if size == 1 => Self::record(&mut self.lba_mid, value as u8),
            5 if size == 1 => Self::record(&mut self.lba_high, value as u8),
            6 if size == 1 => self.device = value as u8,
            7 if size == 1 => self.command(value as u8),
            _ => {},
        }
        true
    }

    fn interrupt(&mut self) -> Option<u8> {
        if self.pending_irq && self.control & 2 == 0 {
            self.pending_irq = false;
            Some(0x2E)
        } else {
            None
        }
    }
}

const RTL8139_IO_BASE: u16 = 0xC000;
const RTL8139_IO_LENGTH: u16 = 0x100;
const RTL_COMMAND: usize = 0x37;
const RTL_IMR: usize = 0x3C;
const RTL_ISR: usize = 0x3E;
const RTL_MEDIA_STATUS: usize = 0x58;
const RTL_COMMAND_RESET: u8 = 1 << 4;
const RTL_COMMAND_RX_EMPTY: u8 = 1;
const RTL_TX_OWN: u32 = 1 << 13;
const RTL_ISR_TX_OK: u16 = 1 << 2;

/// Deterministic RTL8139 link model with an always-up link and TX sink.
///
/// It is sufficient for the production driver to reset, discover its MAC,
/// allocate/program DMA rings, and complete transmitted frames. Receiving
/// from a host backend is deliberately absent, so the RX ring remains empty.
pub struct Rtl8139Nic {
    registers: [u8; RTL8139_IO_LENGTH as usize],
    pending_irq: bool,
}

impl Default for Rtl8139Nic {
    fn default() -> Self {
        let mut device = Self {
            registers: [0; RTL8139_IO_LENGTH as usize],
            pending_irq: false,
        };
        device.reset_registers();
        device
    }
}

impl Rtl8139Nic {
    fn reset_registers(&mut self) {
        self.registers.fill(0);
        self.registers[..6].copy_from_slice(&[0x02, 0x58, 0x45, 0x4E, 0x49, 0x54]);
        self.registers[RTL_COMMAND] = RTL_COMMAND_RX_EMPTY;
        self.registers[RTL_MEDIA_STATUS] = 0;
        for slot in 0..4 {
            let offset = 0x10 + slot * 4;
            self.registers[offset..offset + 4].copy_from_slice(&RTL_TX_OWN.to_le_bytes());
        }
        self.pending_irq = false;
    }

    fn read_register(&self, offset: usize, size: u8) -> u32 {
        if !matches!(size, 1 | 2 | 4) {
            return u32::MAX;
        }
        let mut value = 0u32;
        for byte in 0..usize::from(size) {
            value |=
                u32::from(self.registers.get(offset + byte).copied().unwrap_or(0xFF)) << (byte * 8);
        }
        value
    }

    fn write_register(&mut self, offset: usize, size: u8, value: u32) {
        if !matches!(size, 1 | 2 | 4) {
            return;
        }
        if offset == RTL_COMMAND && size == 1 {
            if value as u8 & RTL_COMMAND_RESET != 0 {
                self.reset_registers();
            } else {
                self.registers[RTL_COMMAND] = value as u8 | RTL_COMMAND_RX_EMPTY;
            }
            return;
        }
        if offset == RTL_ISR && size == 2 {
            let current = u16::from_le_bytes(
                self.registers[RTL_ISR..RTL_ISR + 2]
                    .try_into()
                    .expect("ISR register width"),
            );
            let remaining = current & !(value as u16);
            self.registers[RTL_ISR..RTL_ISR + 2].copy_from_slice(&remaining.to_le_bytes());
            self.pending_irq = remaining
                & u16::from_le_bytes(
                    self.registers[RTL_IMR..RTL_IMR + 2]
                        .try_into()
                        .expect("IMR register width"),
                )
                != 0;
            return;
        }
        if (0x10..0x20).contains(&offset) && offset.is_multiple_of(4) && size == 4 {
            let completed = (value & 0x1FFF) | RTL_TX_OWN;
            self.registers[offset..offset + 4].copy_from_slice(&completed.to_le_bytes());
            self.registers[RTL_ISR..RTL_ISR + 2].copy_from_slice(&RTL_ISR_TX_OK.to_le_bytes());
            let interrupt_mask = u16::from_le_bytes(
                self.registers[RTL_IMR..RTL_IMR + 2]
                    .try_into()
                    .expect("IMR register width"),
            );
            self.pending_irq = interrupt_mask & RTL_ISR_TX_OK != 0;
            return;
        }
        for byte in 0..usize::from(size) {
            if let Some(target) = self.registers.get_mut(offset + byte) {
                *target = (value >> (byte * 8)) as u8;
            }
        }
    }
}

impl Device for Rtl8139Nic {
    fn name(&self) -> &'static str {
        "RTL8139 Ethernet TX sink"
    }

    fn read_port(&mut self, port: u16, size: u8) -> Option<u32> {
        let offset = port.checked_sub(RTL8139_IO_BASE)?;
        (offset < RTL8139_IO_LENGTH).then(|| self.read_register(usize::from(offset), size))
    }

    fn write_port(&mut self, port: u16, size: u8, value: u32) -> bool {
        let Some(offset) = port.checked_sub(RTL8139_IO_BASE) else {
            return false;
        };
        if offset >= RTL8139_IO_LENGTH {
            return false;
        }
        self.write_register(usize::from(offset), size, value);
        true
    }

    fn interrupt(&mut self) -> Option<u8> {
        self.pending_irq.then(|| {
            self.pending_irq = false;
            0x2B
        })
    }
}

fn put_identify_word(bytes: &mut [u8], word: usize, value: u16) {
    if let Some(target) = bytes.get_mut(word * 2..word * 2 + 2) {
        target.copy_from_slice(&value.to_le_bytes());
    }
}

fn put_identify_ascii(bytes: &mut [u8], first_word: usize, words: usize, value: &[u8]) {
    let start = first_word * 2;
    let length = words * 2;
    let Some(target) = bytes.get_mut(start..start + length) else {
        return;
    };
    target.fill(b' ');
    for (index, byte) in value.iter().copied().take(length).enumerate() {
        target[index ^ 1] = byte;
    }
}

#[derive(Clone)]
struct PciFunction {
    bus: u8,
    device: u8,
    function: u8,
    config: [u8; 256],
}

impl PciFunction {
    fn new(bdf: (u8, u8, u8), id: (u16, u16), class: (u8, u8, u8), header: u8) -> Self {
        let mut config = [0_u8; 256];
        config[0..2].copy_from_slice(&id.0.to_le_bytes());
        config[2..4].copy_from_slice(&id.1.to_le_bytes());
        config[8] = 1;
        config[9] = class.2;
        config[10] = class.1;
        config[11] = class.0;
        config[0x0E] = header;
        Self {
            bus: bdf.0,
            device: bdf.1,
            function: bdf.2,
            config,
        }
    }
}

/// PCI configuration mechanism #1 with a small conventional PC topology.
pub struct LegacyPciConfig {
    address: u32,
    functions: Vec<PciFunction>,
}

impl Default for LegacyPciConfig {
    fn default() -> Self {
        let host = PciFunction::new((0, 0, 0), (0x8086, 0x1237), (0x06, 0x00, 0x00), 0);
        let isa = PciFunction::new((0, 1, 0), (0x8086, 0x7000), (0x06, 0x01, 0x00), 0x80);
        let mut ide = PciFunction::new((0, 1, 1), (0x8086, 0x7010), (0x01, 0x01, 0x80), 0);
        for (offset, value) in [
            (0x10, 0x0000_01F1_u32),
            (0x14, 0x0000_03F5),
            (0x18, 0x0000_0171),
            (0x1C, 0x0000_0375),
        ] {
            ide.config[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        let mut ethernet = PciFunction::new((0, 2, 0), (0x10EC, 0x8139), (0x02, 0x00, 0x00), 0);
        ethernet.config[0x10..0x14].copy_from_slice(&0x0000_C001_u32.to_le_bytes());
        ethernet.config[0x3C] = 11;
        ethernet.config[0x3D] = 1;
        Self {
            address: 0,
            functions: vec![host, isa, ide, ethernet],
        }
    }
}

impl LegacyPciConfig {
    fn selected(&self) -> Option<(usize, usize)> {
        if self.address & (1 << 31) == 0 {
            return None;
        }
        let bus = (self.address >> 16) as u8;
        let device = ((self.address >> 11) & 0x1F) as u8;
        let function = ((self.address >> 8) & 7) as u8;
        let offset = (self.address & 0xFC) as usize;
        let index = self.functions.iter().position(|entry| {
            (entry.bus, entry.device, entry.function) == (bus, device, function)
        })?;
        Some((index, offset))
    }

    fn read_config(&self, port: u16, size: u8) -> u32 {
        if !matches!(size, 1 | 2 | 4) {
            return u32::MAX;
        }
        let lane = usize::from(port - 0xCFC);
        let Some((index, base)) = self.selected() else {
            return u32::MAX;
        };
        let offset = base + lane;
        let config = &self.functions[index].config;
        let mut value = 0u32;
        for byte in 0..usize::from(size) {
            value |= u32::from(config.get(offset + byte).copied().unwrap_or(0xFF)) << (byte * 8);
        }
        value
    }

    fn write_config(&mut self, port: u16, size: u8, value: u32) {
        if !matches!(size, 1 | 2 | 4) {
            return;
        }
        let lane = usize::from(port - 0xCFC);
        let Some((index, base)) = self.selected() else {
            return;
        };
        let offset = base + lane;
        let config = &mut self.functions[index].config;
        for byte in 0..usize::from(size) {
            let target = offset + byte;
            // Identity, class-code, header-layout and interrupt-pin fields are
            // read-only; command/status and BAR programming remain writable.
            if target < 4 || (8..=0x0F).contains(&target) || target == 0x3D {
                continue;
            }
            if let Some(slot) = config.get_mut(target) {
                *slot = (value >> (byte * 8)) as u8;
            }
        }
    }
}

impl Device for LegacyPciConfig {
    fn name(&self) -> &'static str {
        "PCI configuration mechanism #1"
    }

    fn read_port(&mut self, port: u16, size: u8) -> Option<u32> {
        match port {
            0xCF8 if size == 4 => Some(self.address),
            0xCFC..=0xCFF if usize::from(port - 0xCFC) + usize::from(size) <= 4 => {
                Some(self.read_config(port, size))
            },
            _ => None,
        }
    }

    fn write_port(&mut self, port: u16, size: u8, value: u32) -> bool {
        match port {
            0xCF8 if size == 4 => self.address = value,
            0xCFC..=0xCFF if usize::from(port - 0xCFC) + usize::from(size) <= 4 => {
                self.write_config(port, size, value);
            },
            _ => return false,
        }
        true
    }
}

const HPET_BASE: u64 = 0xFED0_0000;
const HPET_MMIO_BYTES: u64 = 0x400;
const HPET_PERIOD_FS: u64 = 10_000_000;
const HPET_CPU_CYCLES_PER_TICK: u64 = 3;

/// One-comparator, 64-bit HPET driven by deterministic interpreter cycles.
pub struct Hpet {
    configuration: u64,
    interrupt_status: u64,
    main_counter: u64,
    timer_configuration: u64,
    comparator: u64,
    period: u64,
    cycle_remainder: u64,
    pending_vector: Option<u8>,
}

impl Default for Hpet {
    fn default() -> Self {
        Self {
            configuration: 0,
            interrupt_status: 0,
            main_counter: 0,
            // Timer 0 supports periodic mode and a 64-bit comparator.
            timer_configuration: (1 << 4) | (1 << 5),
            comparator: 0,
            period: 0,
            cycle_remainder: 0,
            pending_vector: None,
        }
    }
}

impl Hpet {
    const fn capabilities() -> u64 {
        // rev 1, one timer (encoded as zero), 64-bit counter, legacy routing,
        // Xenith vendor ID, and a 10 ns main-counter period.
        1 | (1 << 13) | (1 << 15) | (0x5858 << 16) | (HPET_PERIOD_FS << 32)
    }

    fn register(&self, offset: u64) -> Option<u64> {
        match offset & !7 {
            0x000 => Some(Self::capabilities()),
            0x010 => Some(self.configuration),
            0x020 => Some(self.interrupt_status),
            0x0F0 => Some(self.main_counter),
            0x100 => Some(self.timer_configuration),
            0x108 => Some(self.comparator),
            _ => (offset < HPET_MMIO_BYTES).then_some(0),
        }
    }

    fn read_register(&self, offset: u64, size: u8) -> Option<u64> {
        if !matches!(size, 4 | 8) || !offset.is_multiple_of(u64::from(size)) {
            return None;
        }
        let value = self.register(offset)?;
        Some(if offset & 4 != 0 { value >> 32 } else { value })
    }

    fn write_register(&mut self, offset: u64, size: u8, value: u64) -> bool {
        if !matches!(size, 4 | 8)
            || !offset.is_multiple_of(u64::from(size))
            || offset >= HPET_MMIO_BYTES
        {
            return false;
        }
        let merge = |old: u64| {
            if size == 8 {
                value
            } else if offset & 4 == 0 {
                (old & 0xFFFF_FFFF_0000_0000) | (value & 0xFFFF_FFFF)
            } else {
                (old & 0xFFFF_FFFF) | (value << 32)
            }
        };
        match offset & !7 {
            0x010 => self.configuration = merge(self.configuration) & 3,
            0x020 => {
                self.interrupt_status &= !merge(0);
                if self.interrupt_status & 1 == 0 {
                    self.pending_vector = None;
                }
            },
            0x0F0 => self.main_counter = merge(self.main_counter),
            0x100 => {
                let supported = self.timer_configuration & ((1 << 4) | (1 << 5));
                let writable = merge(self.timer_configuration)
                    & ((1 << 2) | (1 << 3) | (1 << 6) | (0x1F << 9));
                self.timer_configuration = supported | writable;
            },
            0x108 => {
                let programmed = merge(self.comparator);
                if self.timer_configuration & (1 << 3) != 0
                    && self.timer_configuration & (1 << 6) == 0
                {
                    self.period = programmed.max(1);
                } else {
                    self.comparator = programmed;
                    self.timer_configuration &= !(1 << 6);
                }
            },
            _ => {},
        }
        true
    }

    fn crossed(old: u64, new: u64, target: u64) -> bool {
        if old <= new {
            target > old && target <= new
        } else {
            target > old || target <= new
        }
    }

    fn expire(&mut self) {
        self.interrupt_status |= 1;
        if self.timer_configuration & (1 << 2) != 0 {
            self.pending_vector = Some(if self.configuration & 2 != 0 {
                0x20
            } else {
                0x20 + ((self.timer_configuration >> 9) as u8 & 0x1F)
            });
        }
        if self.timer_configuration & (1 << 3) != 0 && self.period != 0 {
            while self.comparator <= self.main_counter {
                let next = self.comparator.wrapping_add(self.period);
                if next <= self.comparator {
                    break;
                }
                self.comparator = next;
            }
        } else {
            self.comparator = u64::MAX;
        }
    }
}

impl Device for Hpet {
    fn name(&self) -> &'static str {
        "64-bit HPET"
    }

    fn read_mmio(&mut self, address: u64, size: u8) -> Option<u64> {
        let offset = address.checked_sub(HPET_BASE)?;
        self.read_register(offset, size)
    }

    fn write_mmio(&mut self, address: u64, size: u8, value: u64) -> bool {
        address
            .checked_sub(HPET_BASE)
            .is_some_and(|offset| self.write_register(offset, size, value))
    }

    fn tick(&mut self, cycles: u64) {
        if self.configuration & 1 == 0 || cycles == 0 {
            return;
        }
        let total = self.cycle_remainder.saturating_add(cycles);
        let elapsed = total / HPET_CPU_CYCLES_PER_TICK;
        self.cycle_remainder = total % HPET_CPU_CYCLES_PER_TICK;
        if elapsed == 0 {
            return;
        }
        let old = self.main_counter;
        self.main_counter = self.main_counter.wrapping_add(elapsed);
        if self.comparator != u64::MAX && Self::crossed(old, self.main_counter, self.comparator) {
            self.expire();
        }
    }

    fn interrupt(&mut self) -> Option<u8> {
        self.pending_vector.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ata_write_register(device: &mut AtaPioDisk, register: u16, value: u8) {
        assert!(device.write_port(ATA_PRIMARY_BASE + register, 1, u32::from(value)));
    }

    #[test]
    fn ata_lba48_read_write_and_identify_use_exact_sectors() {
        let mut raw = vec![0_u8; ATA_SECTOR_SIZE * 4];
        raw[ATA_SECTOR_SIZE..ATA_SECTOR_SIZE + 4].copy_from_slice(b"READ");
        let image = AtaDiskImage::new(raw, false).unwrap();
        let mut ata = AtaPioDisk::new(image.clone());

        ata_write_register(&mut ata, 2, 0);
        ata_write_register(&mut ata, 3, 0);
        ata_write_register(&mut ata, 4, 0);
        ata_write_register(&mut ata, 5, 0);
        ata_write_register(&mut ata, 2, 1);
        ata_write_register(&mut ata, 3, 1);
        ata_write_register(&mut ata, 4, 0);
        ata_write_register(&mut ata, 5, 0);
        ata_write_register(&mut ata, 7, 0x24);
        assert_eq!(
            ata.read_port(ATA_PRIMARY_BASE, 4),
            Some(u32::from_le_bytes(*b"READ"))
        );

        ata_write_register(&mut ata, 2, 0);
        ata_write_register(&mut ata, 3, 0);
        ata_write_register(&mut ata, 4, 0);
        ata_write_register(&mut ata, 5, 0);
        ata_write_register(&mut ata, 2, 1);
        ata_write_register(&mut ata, 3, 2);
        ata_write_register(&mut ata, 4, 0);
        ata_write_register(&mut ata, 5, 0);
        ata_write_register(&mut ata, 7, 0x34);
        for index in 0..128_u32 {
            assert!(ata.write_port(ATA_PRIMARY_BASE, 4, 0xA5A5_0000 | index));
        }
        assert!(image.changed());
        assert_eq!(
            &image.snapshot()[ATA_SECTOR_SIZE * 2..ATA_SECTOR_SIZE * 2 + 4],
            &[0, 0, 0xA5, 0xA5]
        );

        ata_write_register(&mut ata, 7, 0xEC);
        let identify: Vec<u16> = (0..256)
            .map(|_| ata.read_port(ATA_PRIMARY_BASE, 2).unwrap() as u16)
            .collect();
        assert_ne!(identify[83] & (1 << 10), 0);
        assert_eq!(identify[100], 4);
    }

    #[test]
    fn read_only_ata_media_aborts_writes() {
        let image = AtaDiskImage::new(vec![0; ATA_SECTOR_SIZE], true).unwrap();
        let mut ata = AtaPioDisk::new(image);
        ata_write_register(&mut ata, 2, 1);
        ata_write_register(&mut ata, 3, 0);
        ata_write_register(&mut ata, 4, 0);
        ata_write_register(&mut ata, 5, 0);
        ata_write_register(&mut ata, 7, 0x30);
        assert_eq!(
            ata.read_port(ATA_PRIMARY_BASE + 7, 1),
            Some(u32::from(ATA_STATUS_DRDY | ATA_STATUS_ERR))
        );
    }

    #[test]
    fn pci_mechanism_one_enumerates_host_bridge_and_ide() {
        let mut pci = LegacyPciConfig::default();
        assert!(pci.write_port(0xCF8, 4, 0x8000_0000));
        assert_eq!(pci.read_port(0xCFC, 4), Some(0x1237_8086));
        assert!(pci.write_port(0xCF8, 4, 0x8000_0908));
        assert_eq!(pci.read_port(0xCFC, 4), Some(0x0101_8001));
        assert!(pci.write_port(0xCF8, 4, 0x8000_F800));
        assert_eq!(pci.read_port(0xCFC, 4), Some(u32::MAX));
    }

    #[test]
    fn rtl8139_resets_reports_link_and_completes_transmit() {
        let mut nic = Rtl8139Nic::default();
        assert_eq!(nic.read_port(RTL8139_IO_BASE, 4), Some(0x4E45_5802));
        assert!(nic.write_port(RTL8139_IO_BASE + RTL_COMMAND as u16, 1, 0x10));
        assert_eq!(
            nic.read_port(RTL8139_IO_BASE + RTL_COMMAND as u16, 1),
            Some(1)
        );
        assert_eq!(
            nic.read_port(RTL8139_IO_BASE + RTL_MEDIA_STATUS as u16, 1),
            Some(0)
        );
        assert!(nic.write_port(RTL8139_IO_BASE + RTL_IMR as u16, 2, 1 << 2));
        assert!(nic.write_port(RTL8139_IO_BASE + 0x10, 4, 60));
        assert_eq!(
            nic.read_port(RTL8139_IO_BASE + 0x10, 4),
            Some(RTL_TX_OWN | 60)
        );
        assert_eq!(nic.interrupt(), Some(0x2B));
    }

    #[test]
    fn hpet_counter_and_one_shot_interrupt_are_functional() {
        let mut hpet = Hpet::default();
        assert_eq!(hpet.read_mmio(HPET_BASE, 8), Some(Hpet::capabilities()));
        assert!(hpet.write_mmio(HPET_BASE + 0x108, 8, 10));
        assert!(hpet.write_mmio(HPET_BASE + 0x100, 8, 1 << 2));
        assert!(hpet.write_mmio(HPET_BASE + 0x10, 8, 3));
        hpet.tick(29);
        assert_eq!(hpet.interrupt(), None);
        hpet.tick(1);
        assert_eq!(hpet.interrupt(), Some(0x20));
        assert_eq!(hpet.read_mmio(HPET_BASE + 0x20, 8), Some(1));
        assert!(hpet.write_mmio(HPET_BASE + 0x20, 8, 1));
        assert_eq!(hpet.read_mmio(HPET_BASE + 0x20, 8), Some(0));
    }
}
