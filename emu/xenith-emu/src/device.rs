//! Port-I/O and MMIO devices used by the emulator.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

// Deterministic virtual clock tree. One interpreted CPU cycle is the base:
// the PIT receives one input tick per 256 cycles (~1.193 MHz at a virtual
// 305.5 MHz CPU), while the LAPIC receives one per 2 cycles (~152.7 MHz)
// before its programmable divide register. These explicit ratios keep the
// kernel's PIT-relative calibration coherent and make a calibrated 100 Hz
// tick span about 3.05 million guest cycles. An older 64x PIT acceleration
// compressed that period below the timer ISR's own instruction cost.
const PIT_CPU_CYCLES_PER_INPUT_TICK: u64 = 256;
const LAPIC_CPU_CYCLES_PER_INPUT_TICK: u64 = 2;

pub trait Device: Send {
    fn name(&self) -> &'static str;
    fn read_port(&mut self, _port: u16, _size: u8) -> Option<u32> {
        None
    }
    fn write_port(&mut self, _port: u16, _size: u8, _value: u32) -> bool {
        false
    }
    fn read_mmio(&mut self, _address: u64, _size: u8) -> Option<u64> {
        None
    }
    fn write_mmio(&mut self, _address: u64, _size: u8, _value: u64) -> bool {
        false
    }
    fn tick(&mut self, _cycles: u64) {}
    fn interrupt(&mut self) -> Option<u8> {
        None
    }
    fn inject_ps2_scancodes(&mut self, _scancodes: &[u8]) -> bool {
        false
    }
    fn ps2_keyboard_ready(&self) -> Option<bool> {
        None
    }
    fn ioapic_route(&self, _irq: u8) -> Option<IoApicRoute> {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoApicRoute {
    pub destination: u8,
    pub vector: u8,
    pub masked: bool,
}

pub struct Serial16550 {
    base: u16,
    registers: [u8; 8],
    receive: VecDeque<u8>,
    output: Arc<Mutex<Vec<u8>>>,
    mirror_stdout: bool,
}

impl Serial16550 {
    #[must_use]
    pub fn new(base: u16, output: Arc<Mutex<Vec<u8>>>, mirror_stdout: bool) -> Self {
        let mut registers = [0u8; 8];
        registers[5] = 0x60;
        Self {
            base,
            registers,
            receive: VecDeque::new(),
            output,
            mirror_stdout,
        }
    }

    pub fn inject(&mut self, bytes: &[u8]) {
        self.receive.extend(bytes.iter().copied());
        if !self.receive.is_empty() {
            self.registers[5] |= 1;
        }
    }
}

impl Device for Serial16550 {
    fn name(&self) -> &'static str {
        "16550 UART"
    }

    fn read_port(&mut self, port: u16, size: u8) -> Option<u32> {
        if size != 1 || !(self.base..self.base + 8).contains(&port) {
            return None;
        }
        let index = usize::from(port - self.base);
        if index == 0 && self.registers[3] & 0x80 == 0 {
            let byte = self.receive.pop_front().unwrap_or(0);
            if self.receive.is_empty() {
                self.registers[5] &= !1;
            }
            Some(u32::from(byte))
        } else {
            Some(u32::from(self.registers[index]))
        }
    }

    fn write_port(&mut self, port: u16, size: u8, value: u32) -> bool {
        if size != 1 || !(self.base..self.base + 8).contains(&port) {
            return false;
        }
        let index = usize::from(port - self.base);
        let byte = value as u8;
        if index == 0 && self.registers[3] & 0x80 == 0 {
            if let Ok(mut output) = self.output.lock() {
                output.push(byte);
            }
            if self.mirror_stdout {
                let _ = io::stdout().write_all(&[byte]);
                let _ = io::stdout().flush();
            }
        } else {
            self.registers[index] = byte;
        }
        true
    }
}

pub struct Cmos {
    index: u8,
    bytes: [u8; 128],
}

impl Default for Cmos {
    fn default() -> Self {
        let mut bytes = [0u8; 128];
        // Deterministic valid BCD/24-hour snapshot: 2026-07-19 00:00:00.
        // The RTC does not follow host wall time, keeping emulator runs
        // reproducible while satisfying the kernel's calendar validation.
        bytes[0x07] = 0x19;
        bytes[0x08] = 0x07;
        bytes[0x09] = 0x26;
        bytes[0x0A] = 0x26;
        bytes[0x0B] = 0x02;
        bytes[0x0D] = 0x80;
        bytes[0x32] = 0x20;
        Self { index: 0, bytes }
    }
}

impl Device for Cmos {
    fn name(&self) -> &'static str {
        "CMOS RTC"
    }
    fn read_port(&mut self, port: u16, size: u8) -> Option<u32> {
        if size != 1 {
            return None;
        }
        match port {
            0x70 => Some(u32::from(self.index)),
            0x71 => Some(u32::from(self.bytes[usize::from(self.index & 0x7F)])),
            _ => None,
        }
    }
    fn write_port(&mut self, port: u16, size: u8, value: u32) -> bool {
        if size != 1 {
            return false;
        }
        match port {
            0x70 => self.index = value as u8,
            0x71 => self.bytes[usize::from(self.index & 0x7F)] = value as u8,
            _ => return false,
        }
        true
    }
}

pub struct Pit8254 {
    divider: u16,
    counter: u16,
    mode: u8,
    pending_low: Option<u8>,
    latched: u16,
    latched_valid: bool,
    read_high: bool,
    cycle_remainder: u64,
}

impl Default for Pit8254 {
    fn default() -> Self {
        Self {
            divider: u16::MAX,
            counter: u16::MAX,
            mode: 0,
            pending_low: None,
            latched: 0,
            latched_valid: false,
            read_high: false,
            cycle_remainder: 0,
        }
    }
}

impl Device for Pit8254 {
    fn name(&self) -> &'static str {
        "8254 PIT"
    }

    fn read_port(&mut self, port: u16, size: u8) -> Option<u32> {
        if port != 0x40 || size != 1 {
            return None;
        }
        let value = if self.latched_valid {
            self.latched
        } else {
            self.counter
        };
        let byte = if self.read_high {
            (value >> 8) as u8
        } else {
            value as u8
        };
        if self.read_high {
            self.latched_valid = false;
        }
        self.read_high = !self.read_high;
        Some(u32::from(byte))
    }

    fn write_port(&mut self, port: u16, size: u8, value: u32) -> bool {
        if size != 1 {
            return false;
        }
        match port {
            0x43 => {
                let command = value as u8;
                if command >> 6 != 0 {
                    return true;
                }
                if command & 0x30 == 0 {
                    self.latched = self.counter;
                    self.latched_valid = true;
                    self.read_high = false;
                } else {
                    self.mode = (command >> 1) & 7;
                    self.pending_low = None;
                    self.read_high = false;
                }
            },
            0x40 => {
                let byte = value as u8;
                if let Some(low) = self.pending_low.take() {
                    let programmed = u16::from(low) | (u16::from(byte) << 8);
                    self.divider = programmed.max(1);
                    self.counter = self.divider;
                } else {
                    self.pending_low = Some(byte);
                }
            },
            _ => return false,
        }
        true
    }

    fn tick(&mut self, cycles: u64) {
        let total = self.cycle_remainder.saturating_add(cycles);
        let elapsed = total / PIT_CPU_CYCLES_PER_INPUT_TICK;
        self.cycle_remainder = total % PIT_CPU_CYCLES_PER_INPUT_TICK;
        if elapsed == 0 {
            return;
        }
        if matches!(self.mode, 2 | 6) {
            let divider = u64::from(self.divider.max(1));
            let current = u64::from(self.counter.max(1));
            self.counter = if elapsed < current {
                (current - elapsed) as u16
            } else {
                let remainder = (elapsed - current) % divider;
                if remainder == 0 {
                    self.divider
                } else {
                    (divider - remainder) as u16
                }
            };
        } else {
            self.counter = self
                .counter
                .saturating_sub(elapsed.min(u64::from(u16::MAX)) as u16);
        }
    }
}

#[derive(Default)]
pub struct LegacyPic {
    master_mask: u8,
    slave_mask: u8,
    master_command: u8,
    slave_command: u8,
}

impl Device for LegacyPic {
    fn name(&self) -> &'static str {
        "8259 PIC"
    }
    fn read_port(&mut self, port: u16, size: u8) -> Option<u32> {
        if size != 1 {
            return None;
        }
        match port {
            0x20 => Some(u32::from(self.master_command)),
            0x21 => Some(u32::from(self.master_mask)),
            0xA0 => Some(u32::from(self.slave_command)),
            0xA1 => Some(u32::from(self.slave_mask)),
            _ => None,
        }
    }
    fn write_port(&mut self, port: u16, size: u8, value: u32) -> bool {
        if size != 1 {
            return false;
        }
        match port {
            0x20 => self.master_command = value as u8,
            0x21 => self.master_mask = value as u8,
            0xA0 => self.slave_command = value as u8,
            0xA1 => self.slave_mask = value as u8,
            _ => return false,
        }
        true
    }
}

#[derive(Default)]
pub struct Ps2Controller {
    status: u8,
    configuration: u8,
    output: VecDeque<u8>,
    awaiting_config: bool,
    first_port_enabled: bool,
    keyboard_scanning: bool,
}

impl Ps2Controller {
    fn queue(&mut self, byte: u8) {
        self.output.push_back(byte);
        self.status |= 1;
    }

    fn inject_scancodes(&mut self, scancodes: &[u8]) {
        if !self.first_port_enabled || !self.keyboard_scanning {
            return;
        }
        self.output.extend(scancodes.iter().copied());
        if !self.output.is_empty() {
            self.status |= 1;
        }
    }
}

/// Encode US-layout ASCII as PS/2 keyboard set-1 make/break scancodes.
///
/// Shifted characters include explicit left-shift make/break events. Building
/// the complete vector before it reaches the controller makes an unsupported
/// character an atomic error rather than a partially typed command.
pub(crate) fn encode_ascii_set1(input: &str) -> Result<Vec<u8>, char> {
    let mut output = Vec::with_capacity(input.len() * 2);
    for character in input.chars() {
        let (scancode, shifted) = match character {
            'a'..='z' => {
                const LETTERS: [u8; 26] = [
                    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32,
                    0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
                ];
                (LETTERS[character as usize - 'a' as usize], false)
            },
            'A'..='Z' => {
                const LETTERS: [u8; 26] = [
                    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32,
                    0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
                ];
                (LETTERS[character as usize - 'A' as usize], true)
            },
            '1' => (0x02, false),
            '2' => (0x03, false),
            '3' => (0x04, false),
            '4' => (0x05, false),
            '5' => (0x06, false),
            '6' => (0x07, false),
            '7' => (0x08, false),
            '8' => (0x09, false),
            '9' => (0x0A, false),
            '0' => (0x0B, false),
            '!' => (0x02, true),
            '@' => (0x03, true),
            '#' => (0x04, true),
            '$' => (0x05, true),
            '%' => (0x06, true),
            '^' => (0x07, true),
            '&' => (0x08, true),
            '*' => (0x09, true),
            '(' => (0x0A, true),
            ')' => (0x0B, true),
            '-' => (0x0C, false),
            '_' => (0x0C, true),
            '=' => (0x0D, false),
            '+' => (0x0D, true),
            '\u{8}' => (0x0E, false),
            '\t' => (0x0F, false),
            '[' => (0x1A, false),
            '{' => (0x1A, true),
            ']' => (0x1B, false),
            '}' => (0x1B, true),
            '\n' | '\r' => (0x1C, false),
            ';' => (0x27, false),
            ':' => (0x27, true),
            '\'' => (0x28, false),
            '"' => (0x28, true),
            '`' => (0x29, false),
            '~' => (0x29, true),
            '\\' => (0x2B, false),
            '|' => (0x2B, true),
            ',' => (0x33, false),
            '<' => (0x33, true),
            '.' => (0x34, false),
            '>' => (0x34, true),
            '/' => (0x35, false),
            '?' => (0x35, true),
            ' ' => (0x39, false),
            unsupported => return Err(unsupported),
        };

        if shifted {
            output.push(0x2A);
        }
        output.push(scancode);
        output.push(scancode | 0x80);
        if shifted {
            output.push(0xAA);
        }
    }
    Ok(output)
}

impl Device for Ps2Controller {
    fn name(&self) -> &'static str {
        "8042 PS/2"
    }
    fn read_port(&mut self, port: u16, size: u8) -> Option<u32> {
        if size != 1 {
            return None;
        }
        match port {
            0x60 => {
                let value = self.output.pop_front().unwrap_or(0);
                if self.output.is_empty() {
                    self.status &= !1;
                }
                Some(u32::from(value))
            },
            0x64 => Some(u32::from(self.status)),
            _ => None,
        }
    }
    fn write_port(&mut self, port: u16, size: u8, value: u32) -> bool {
        if size != 1 {
            return false;
        }
        match port {
            0x64 => match value as u8 {
                0x20 => self.queue(self.configuration),
                0x60 => self.awaiting_config = true,
                0xAD => self.first_port_enabled = false,
                0xAE => self.first_port_enabled = true,
                0xAA => self.queue(0x55),
                0xAB | 0xA9 => self.queue(0),
                _ => {},
            },
            0x60 if self.awaiting_config => {
                self.configuration = value as u8;
                self.awaiting_config = false;
            },
            0x60 => {
                // A keyboard reset acknowledges the command and then reports
                // its basic-assurance self-test result. The kernel consumes
                // these as two distinct protocol bytes during bring-up.
                self.queue(0xFA);
                match value as u8 {
                    0xF4 => self.keyboard_scanning = true,
                    0xF5 => self.keyboard_scanning = false,
                    0xFF => {
                        self.keyboard_scanning = false;
                        self.queue(0xAA);
                    },
                    _ => {},
                }
            },
            _ => return false,
        }
        true
    }

    fn interrupt(&mut self) -> Option<u8> {
        // Xenith programs IRQ 1 to the legacy/remapped vector 0x21. The
        // current emulator does not inspect the PIC IMR or I/O APIC
        // redirection table, so a guest that routes IRQ 1 to another vector
        // is not supported by this fixed-vector device model.
        (self.first_port_enabled && self.configuration & 1 != 0 && !self.output.is_empty())
            .then_some(0x21)
    }

    fn inject_ps2_scancodes(&mut self, scancodes: &[u8]) -> bool {
        self.inject_scancodes(scancodes);
        true
    }

    fn ps2_keyboard_ready(&self) -> Option<bool> {
        Some(self.first_port_enabled && self.keyboard_scanning && self.configuration & 1 != 0)
    }
}

pub struct LocalApic {
    base: u64,
    registers: [u32; 256],
    divider_remainder: u64,
    pending_vectors: VecDeque<u8>,
    interrupt_in_service: bool,
}

const LAPIC_REG_ID: usize = 0x020 / 16;
const LAPIC_REG_VERSION: usize = 0x030 / 16;
const LAPIC_REG_EOI: usize = 0x0B0 / 16;
const LAPIC_REG_SVR: usize = 0x0F0 / 16;
const LAPIC_REG_LVT_TIMER: usize = 0x320 / 16;
const LAPIC_REG_INITIAL_COUNT: usize = 0x380 / 16;
const LAPIC_REG_CURRENT_COUNT: usize = 0x390 / 16;
const LAPIC_REG_DIVIDE: usize = 0x3E0 / 16;

const LAPIC_SVR_SOFTWARE_ENABLE: u32 = 1 << 8;
const LAPIC_LVT_MASKED: u32 = 1 << 16;
const LAPIC_LVT_PERIODIC: u32 = 1 << 17;

impl Default for LocalApic {
    fn default() -> Self {
        Self::new(0)
    }
}

impl LocalApic {
    /// Construct one processor-local APIC with a stable physical/x2APIC id.
    #[must_use]
    pub fn new(apic_id: u32) -> Self {
        let mut registers = [0; 256];
        registers[LAPIC_REG_ID] = apic_id;
        // Integrated APIC version 0x14 with six LVT entries (max index 5).
        registers[LAPIC_REG_VERSION] = 0x14 | (5 << 16);
        Self {
            base: 0xFEE0_0000,
            registers,
            divider_remainder: 0,
            pending_vectors: VecDeque::new(),
            interrupt_in_service: false,
        }
    }

    #[must_use]
    pub fn apic_id(&self) -> u32 {
        self.registers[LAPIC_REG_ID]
    }

    /// Read one xAPIC register by its byte offset.
    #[must_use]
    pub fn read_register(&self, offset: u16) -> u64 {
        u64::from(self.registers[usize::from(offset) / 16])
    }

    /// Write one xAPIC/x2APIC register by its byte offset.
    pub fn write_register(&mut self, offset: u16, value: u64) {
        let index = usize::from(offset) / 16;
        match index {
            // ID, version, and current timer count are read-only.
            LAPIC_REG_ID | LAPIC_REG_VERSION | LAPIC_REG_CURRENT_COUNT => {},
            LAPIC_REG_EOI => self.end_of_interrupt(),
            LAPIC_REG_INITIAL_COUNT => {
                let count = value as u32;
                self.registers[LAPIC_REG_INITIAL_COUNT] = count;
                self.registers[LAPIC_REG_CURRENT_COUNT] = count;
                self.divider_remainder = 0;
            },
            _ => self.registers[index] = value as u32,
        }
    }

    /// Latch a fixed interrupt for delivery to this processor.
    pub fn queue_vector(&mut self, vector: u8) {
        if !self.pending_vectors.contains(&vector) {
            self.pending_vectors.push_back(vector);
        }
    }

    pub fn end_of_interrupt(&mut self) {
        self.interrupt_in_service = false;
    }

    pub fn reset(&mut self) {
        *self = Self::new(self.apic_id());
    }

    pub fn advance(&mut self, cycles: u64) {
        self.tick(cycles);
    }

    pub fn next_interrupt(&mut self) -> Option<u8> {
        self.interrupt()
    }

    fn timer_divisor(&self) -> u64 {
        let programmed = match self.registers[LAPIC_REG_DIVIDE] & 0x0B {
            0x0 => 2,
            0x1 => 4,
            0x2 => 8,
            0x3 => 16,
            0x8 => 32,
            0x9 => 64,
            0xA => 128,
            0xB => 1,
            _ => unreachable!("divide register is masked to valid encoding bits"),
        };
        programmed * LAPIC_CPU_CYCLES_PER_INPUT_TICK
    }

    fn timer_expired(&mut self) {
        let lvt = self.registers[LAPIC_REG_LVT_TIMER];
        if self.registers[LAPIC_REG_SVR] & LAPIC_SVR_SOFTWARE_ENABLE != 0
            && lvt & LAPIC_LVT_MASKED == 0
        {
            self.queue_vector(lvt as u8);
        }
    }
}

impl Device for LocalApic {
    fn name(&self) -> &'static str {
        "local APIC"
    }
    fn read_mmio(&mut self, address: u64, size: u8) -> Option<u64> {
        if size != 4 || !(self.base..self.base + 0x1000).contains(&address) {
            return None;
        }
        Some(u64::from(
            self.registers[((address - self.base) / 16) as usize],
        ))
    }
    fn write_mmio(&mut self, address: u64, size: u8, value: u64) -> bool {
        if size != 4 || !(self.base..self.base + 0x1000).contains(&address) {
            return false;
        }
        self.write_register((address - self.base) as u16, value);
        true
    }

    fn tick(&mut self, cycles: u64) {
        let initial = self.registers[LAPIC_REG_INITIAL_COUNT];
        let current = self.registers[LAPIC_REG_CURRENT_COUNT];
        if initial == 0 || current == 0 || cycles == 0 {
            return;
        }
        let divisor = self.timer_divisor();
        let total = self.divider_remainder.saturating_add(cycles);
        let elapsed = total / divisor;
        self.divider_remainder = total % divisor;
        if elapsed == 0 {
            return;
        }

        if elapsed < u64::from(current) {
            self.registers[LAPIC_REG_CURRENT_COUNT] = current - elapsed as u32;
            return;
        }

        self.timer_expired();
        if self.registers[LAPIC_REG_LVT_TIMER] & LAPIC_LVT_PERIODIC == 0 {
            self.registers[LAPIC_REG_CURRENT_COUNT] = 0;
            return;
        }

        let elapsed_after_expiry = elapsed - u64::from(current);
        let remainder = elapsed_after_expiry % u64::from(initial);
        self.registers[LAPIC_REG_CURRENT_COUNT] = if remainder == 0 {
            initial
        } else {
            initial - remainder as u32
        };
    }

    fn interrupt(&mut self) -> Option<u8> {
        if self.interrupt_in_service {
            return None;
        }
        let vector = self.pending_vectors.pop_front()?;
        self.interrupt_in_service = true;
        Some(vector)
    }
}

pub struct IoApic {
    base: u64,
    selector: u8,
    registers: [u32; 256],
}

impl Default for IoApic {
    fn default() -> Self {
        let mut registers = [0u32; 256];
        registers[0] = 1 << 24;
        registers[1] = 0x11 | (23 << 16);
        for register in &mut registers[0x10..=0x3f] {
            *register = 1 << 16;
        }
        Self {
            base: 0xFEC0_0000,
            selector: 0,
            registers,
        }
    }
}

impl Device for IoApic {
    fn name(&self) -> &'static str {
        "I/O APIC"
    }

    fn read_mmio(&mut self, address: u64, size: u8) -> Option<u64> {
        if size != 4 {
            return None;
        }
        match address.checked_sub(self.base)? {
            0 => Some(u64::from(self.selector)),
            0x10 => Some(u64::from(self.registers[usize::from(self.selector)])),
            _ => None,
        }
    }

    fn write_mmio(&mut self, address: u64, size: u8, value: u64) -> bool {
        if size != 4 {
            return false;
        }
        match address.checked_sub(self.base) {
            Some(0) => self.selector = value as u8,
            Some(0x10) => self.registers[usize::from(self.selector)] = value as u32,
            _ => return false,
        }
        true
    }

    fn ioapic_route(&self, irq: u8) -> Option<IoApicRoute> {
        if irq >= 24 {
            return None;
        }
        let low = self.registers[0x10 + usize::from(irq) * 2];
        let high = self.registers[0x11 + usize::from(irq) * 2];
        Some(IoApicRoute {
            destination: (high >> 24) as u8,
            vector: low as u8,
            masked: low & (1 << 16) != 0,
        })
    }
}

#[derive(Default)]
pub struct AbsentHpet;

impl Device for AbsentHpet {
    fn name(&self) -> &'static str {
        "absent HPET window"
    }

    fn read_mmio(&mut self, address: u64, size: u8) -> Option<u64> {
        if (1..=8).contains(&size) && (0xFED0_0000..0xFED0_0400).contains(&address) {
            Some(0)
        } else {
            None
        }
    }

    fn write_mmio(&mut self, address: u64, size: u8, _value: u64) -> bool {
        (1..=8).contains(&size) && (0xFED0_0000..0xFED0_0400).contains(&address)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        encode_ascii_set1, Cmos, Device, LocalApic, Ps2Controller, LAPIC_CPU_CYCLES_PER_INPUT_TICK,
    };

    const LAPIC_BASE: u64 = 0xFEE0_0000;

    fn lapic_write(apic: &mut LocalApic, offset: u64, value: u32) {
        assert!(apic.write_mmio(LAPIC_BASE + offset, 4, u64::from(value)));
    }

    fn lapic_read(apic: &mut LocalApic, offset: u64) -> u32 {
        apic.read_mmio(LAPIC_BASE + offset, 4)
            .expect("LAPIC register") as u32
    }

    #[test]
    fn ps2_keyboard_reset_returns_ack_then_self_test() {
        let mut controller = Ps2Controller::default();
        assert!(controller.write_port(0x60, 1, 0xFF));
        assert_eq!(controller.read_port(0x64, 1), Some(1));
        assert_eq!(controller.read_port(0x60, 1), Some(0xFA));
        assert_eq!(controller.read_port(0x60, 1), Some(0xAA));
        assert_eq!(controller.read_port(0x64, 1), Some(0));
    }

    #[test]
    fn cmos_default_is_a_valid_deterministic_bcd_date() {
        let mut cmos = Cmos::default();
        for (register, expected) in [(0x07, 0x19), (0x08, 0x07), (0x09, 0x26), (0x32, 0x20)] {
            assert!(cmos.write_port(0x70, 1, register));
            assert_eq!(cmos.read_port(0x71, 1), Some(expected));
        }
    }

    #[test]
    fn ascii_encoder_emits_set1_make_break_and_shift() {
        assert_eq!(encode_ascii_set1("aA_ /\n").unwrap(), [
            0x1E, 0x9E, 0x2A, 0x1E, 0x9E, 0xAA, 0x2A, 0x0C, 0x8C, 0xAA, 0x39, 0xB9, 0x35, 0xB5,
            0x1C, 0x9C,
        ]);
        assert_eq!(encode_ascii_set1("x\u{20ac}"), Err('\u{20ac}'));
    }

    #[test]
    fn ps2_irq1_requires_enabled_scanning_config_and_pending_data() {
        let mut controller = Ps2Controller::default();
        assert_eq!(controller.ps2_keyboard_ready(), Some(false));
        controller.inject_scancodes(&[0x1E]);
        assert_eq!(controller.interrupt(), None);

        assert!(controller.write_port(0x64, 1, 0xAE));
        assert!(controller.write_port(0x60, 1, 0xF4));
        assert_eq!(controller.read_port(0x60, 1), Some(0xFA));
        controller.inject_scancodes(&[0x1E]);
        assert_eq!(controller.interrupt(), None);

        assert!(controller.write_port(0x64, 1, 0x60));
        assert!(controller.write_port(0x60, 1, 1));
        assert_eq!(controller.ps2_keyboard_ready(), Some(true));
        assert_eq!(controller.interrupt(), Some(0x21));
        assert_eq!(controller.read_port(0x60, 1), Some(0x1E));
        assert_eq!(controller.interrupt(), None);
    }

    #[test]
    fn ps2_raw_extended_sequence_retains_every_byte_in_order() {
        let mut controller = Ps2Controller::default();
        assert!(controller.write_port(0x64, 1, 0xAE));
        assert!(controller.write_port(0x60, 1, 0xF4));
        assert_eq!(controller.read_port(0x60, 1), Some(0xFA));
        assert!(controller.write_port(0x64, 1, 0x60));
        assert!(controller.write_port(0x60, 1, 1));

        controller.inject_scancodes(&[0xE0, 0x5B, 0xE0, 0xDB]);
        for expected in [0xE0, 0x5B, 0xE0, 0xDB] {
            assert_eq!(controller.interrupt(), Some(0x21));
            assert_eq!(controller.read_port(0x60, 1), Some(expected));
        }
        assert_eq!(controller.interrupt(), None);
    }

    #[test]
    fn lapic_one_shot_counts_down_and_fires_once() {
        let mut apic = LocalApic::default();
        lapic_write(&mut apic, 0x0F0, 0x1FF);
        lapic_write(&mut apic, 0x3E0, 0x0B);
        lapic_write(&mut apic, 0x320, 0x40);
        lapic_write(&mut apic, 0x380, 3);

        apic.tick(2 * LAPIC_CPU_CYCLES_PER_INPUT_TICK);
        assert_eq!(lapic_read(&mut apic, 0x390), 1);
        assert_eq!(apic.interrupt(), None);
        apic.tick(LAPIC_CPU_CYCLES_PER_INPUT_TICK);
        assert_eq!(lapic_read(&mut apic, 0x390), 0);
        assert_eq!(apic.interrupt(), Some(0x40));
        lapic_write(&mut apic, 0x0B0, 0);
        apic.tick(100);
        assert_eq!(apic.interrupt(), None);
    }

    #[test]
    fn lapic_periodic_timer_waits_for_eoi_before_redelivery() {
        let mut apic = LocalApic::default();
        lapic_write(&mut apic, 0x0F0, 0x1FF);
        lapic_write(&mut apic, 0x3E0, 0x0B);
        lapic_write(&mut apic, 0x320, (1 << 17) | 0xFD);
        lapic_write(&mut apic, 0x380, 3);

        apic.tick(3 * LAPIC_CPU_CYCLES_PER_INPUT_TICK);
        assert_eq!(apic.interrupt(), Some(0xFD));
        assert_eq!(lapic_read(&mut apic, 0x390), 3);
        apic.tick(3 * LAPIC_CPU_CYCLES_PER_INPUT_TICK);
        assert_eq!(apic.interrupt(), None);
        lapic_write(&mut apic, 0x0B0, 0);
        assert_eq!(apic.interrupt(), Some(0xFD));
    }

    #[test]
    fn lapic_divide_register_scales_elapsed_cycles() {
        let mut apic = LocalApic::default();
        lapic_write(&mut apic, 0x0F0, 0x1FF);
        lapic_write(&mut apic, 0x3E0, 0x01);
        lapic_write(&mut apic, 0x320, 0x41);
        lapic_write(&mut apic, 0x380, 2);

        apic.tick(8 * LAPIC_CPU_CYCLES_PER_INPUT_TICK - 1);
        assert_eq!(lapic_read(&mut apic, 0x390), 1);
        apic.tick(1);
        assert_eq!(apic.interrupt(), Some(0x41));
    }
}
