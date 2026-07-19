//! Strict, bounded execution of Xenith's packaged 16/32-bit BIOS stages.
//!
//! This is deliberately not a general x86 emulator.  It implements the exact
//! architectural subset emitted by Xenith stage1 and the stage2 assembly
//! entry, fetches every instruction from guest RAM, and fails immediately on
//! an unsupported opcode.  The ordinary long-mode CPU takes over only after
//! this runner reaches stage2's real `call stage2_main` boundary.

use std::fmt;

use crate::memory::{MemoryBus, MemoryError};

const STAGE1_START: u64 = 0x7c00;
const STAGE2_START: u64 = 0x8000;
const BOOT_DRIVE: u8 = 0x80;
const SECTOR_SIZE: usize = 512;
const MAX_INSTRUCTIONS: u64 = 50_000;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

const EAX: usize = 0;
const ECX: usize = 1;
const EDX: usize = 2;
const EBX: usize = 3;
const ESP: usize = 4;
const EBP: usize = 5;
const ESI: usize = 6;
const EDI: usize = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Real16,
    Protected32,
    Long64,
}

impl Mode {
    const fn name(self) -> &'static str {
        match self {
            Self::Real16 => "real16",
            Self::Protected32 => "protected32",
            Self::Long64 => "long64",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Stage1,
    Stage2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchTrace {
    pub instructions: u64,
    pub bytes: u64,
    pub checksum: u64,
}

impl FetchTrace {
    const fn new() -> Self {
        Self {
            instructions: 0,
            bytes: 0,
            checksum: FNV_OFFSET,
        }
    }

    fn record(&mut self, bytes: &[u8]) {
        self.instructions += 1;
        self.bytes += bytes.len() as u64;
        for &byte in bytes {
            self.checksum ^= u64::from(byte);
            self.checksum = self.checksum.wrapping_mul(FNV_PRIME);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageExecutionTrace {
    pub stage1: FetchTrace,
    pub stage2: FetchTrace,
    pub bios_interrupts: u64,
    pub e820_entries: u32,
    pub a20_enabled: bool,
    pub protected_mode_entered: bool,
    pub long_mode_entered: bool,
    pub stage2_main_entry: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StageExecError {
    Memory(MemoryError),
    ExecutionLimit,
    Unsupported {
        stage: &'static str,
        mode: &'static str,
        address: u64,
        bytes: [u8; 8],
    },
    Bios(&'static str),
    Disk(&'static str),
    UnexpectedTransfer {
        expected: u64,
        actual: u64,
    },
}

impl From<MemoryError> for StageExecError {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}

impl fmt::Display for StageExecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for StageExecError {}

pub fn execute_packaged_stages(
    bus: &mut MemoryBus,
    image: &[u8],
) -> Result<StageExecutionTrace, StageExecError> {
    let mut runner = Runner::new(bus, image);
    runner.run()
}

struct Runner<'a> {
    bus: &'a mut MemoryBus,
    image: &'a [u8],
    registers: [u64; 8],
    cs: u16,
    ds: u16,
    es: u16,
    ss: u16,
    fs: u16,
    gs: u16,
    ip: u64,
    cr0: u64,
    cr3: u64,
    cr4: u64,
    efer: u64,
    carry: bool,
    zero: bool,
    mode: Mode,
    stage: Stage,
    direction: bool,
    interrupts: bool,
    port92: u8,
    trace: StageExecutionTrace,
}

impl<'a> Runner<'a> {
    fn new(bus: &'a mut MemoryBus, image: &'a [u8]) -> Self {
        let mut registers = [0; 8];
        registers[EDX] = u64::from(BOOT_DRIVE);
        Self {
            bus,
            image,
            registers,
            cs: 0,
            ds: 0,
            es: 0,
            ss: 0,
            fs: 0,
            gs: 0,
            ip: STAGE1_START,
            cr0: 0x6000_0010,
            cr3: 0,
            cr4: 0,
            efer: 0,
            carry: false,
            zero: false,
            mode: Mode::Real16,
            stage: Stage::Stage1,
            direction: false,
            interrupts: true,
            port92: 0,
            trace: StageExecutionTrace {
                stage1: FetchTrace::new(),
                stage2: FetchTrace::new(),
                bios_interrupts: 0,
                e820_entries: 0,
                a20_enabled: false,
                protected_mode_entered: false,
                long_mode_entered: false,
                stage2_main_entry: 0,
            },
        }
    }

    fn run(&mut self) -> Result<StageExecutionTrace, StageExecError> {
        for _ in 0..MAX_INSTRUCTIONS {
            let mut instruction = [0u8; 15];
            self.bus.read_physical(self.linear_ip(), &mut instruction)?;
            let stop = match self.mode {
                Mode::Real16 => self.step_real(&instruction)?,
                Mode::Protected32 => self.step_protected(&instruction)?,
                Mode::Long64 => self.step_long(&instruction)?,
            };
            if stop {
                return Ok(self.trace);
            }
        }
        Err(StageExecError::ExecutionLimit)
    }

    fn linear_ip(&self) -> u64 {
        if self.mode == Mode::Real16 {
            (u64::from(self.cs) << 4) + (self.ip & 0xffff)
        } else {
            self.ip
        }
    }

    fn commit(&mut self, instruction: &[u8], length: usize) {
        match self.stage {
            Stage::Stage1 => self.trace.stage1.record(&instruction[..length]),
            Stage::Stage2 => self.trace.stage2.record(&instruction[..length]),
        }
        self.ip = self.ip.wrapping_add(length as u64);
        if self.mode == Mode::Real16 {
            self.ip &= 0xffff;
        }
    }

    fn branch8(&mut self, instruction: &[u8], length: usize, taken: bool) {
        let displacement = i64::from(instruction[length - 1] as i8);
        self.commit(instruction, length);
        if taken {
            self.ip = self.ip.wrapping_add_signed(displacement);
        }
    }

    fn branch16(&mut self, instruction: &[u8], length: usize, taken: bool) {
        let displacement = i64::from(i16::from_le_bytes([
            instruction[length - 2],
            instruction[length - 1],
        ]));
        self.commit(instruction, length);
        if taken {
            self.ip = self.ip.wrapping_add_signed(displacement) & 0xffff;
        }
    }

    fn unsupported(&self, instruction: &[u8]) -> StageExecError {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&instruction[..8]);
        StageExecError::Unsupported {
            stage: match self.stage {
                Stage::Stage1 => "stage1",
                Stage::Stage2 => "stage2",
            },
            mode: self.mode.name(),
            address: self.linear_ip(),
            bytes,
        }
    }

    fn step_real(&mut self, b: &[u8; 15]) -> Result<bool, StageExecError> {
        match b[0] {
            0xfa => {
                self.interrupts = false;
                self.commit(b, 1);
            },
            0xfb => {
                self.interrupts = true;
                self.commit(b, 1);
            },
            0x31 if b[1] == 0xc0 => {
                self.set16(EAX, 0);
                self.logic_flags(0);
                self.commit(b, 2);
            },
            0x31 if b[1] == 0xff => {
                self.set16(EDI, 0);
                self.logic_flags(0);
                self.commit(b, 2);
            },
            0x8e => {
                let value = self.get16(EAX);
                match b[1] {
                    0xd8 => self.ds = value,
                    0xc0 => self.es = value,
                    0xd0 => self.ss = value,
                    _ => return Err(self.unsupported(b)),
                }
                self.commit(b, 2);
            },
            0xb8..=0xbf => {
                let register = usize::from(b[0] - 0xb8);
                self.set16(register, u16::from_le_bytes([b[1], b[2]]));
                self.commit(b, 3);
            },
            0x88 if b[1] == 0x16 => {
                let address = u16::from_le_bytes([b[2], b[3]]);
                self.write8(self.real_data(self.ds, address), self.get8(EDX))?;
                self.commit(b, 4);
            },
            0x8a if b[1] == 0x16 => {
                let address = u16::from_le_bytes([b[2], b[3]]);
                let value = self.read8(self.real_data(self.ds, address))?;
                self.set8(EDX, value);
                self.commit(b, 4);
            },
            0xb4 => {
                self.set_high8(EAX, b[1]);
                self.commit(b, 2);
            },
            0xcd => {
                self.bios_interrupt(b[1])?;
                self.commit(b, 2);
            },
            0x81 if b[1] == 0xfb => {
                let rhs = u16::from_le_bytes([b[2], b[3]]);
                self.compare(u64::from(self.get16(EBX)), u64::from(rhs), u16::MAX as u64);
                self.commit(b, 4);
            },
            0xf7 if b[1] == 0xc1 => {
                let rhs = u16::from_le_bytes([b[2], b[3]]);
                self.logic_flags(u64::from(self.get16(ECX) & rhs));
                self.commit(b, 4);
            },
            0xa1 => {
                let address = u16::from_le_bytes([b[1], b[2]]);
                let value = self.read16(self.real_data(self.ds, address))?;
                self.set16(EAX, value);
                self.commit(b, 3);
            },
            0xa3 => {
                let address = u16::from_le_bytes([b[1], b[2]]);
                self.write16(self.real_data(self.ds, address), self.get16(EAX))?;
                self.commit(b, 3);
            },
            0xc7 if b[1] == 0x06 => {
                let address = u16::from_le_bytes([b[2], b[3]]);
                let value = u16::from_le_bytes([b[4], b[5]]);
                self.write16(self.real_data(self.ds, address), value)?;
                self.commit(b, 6);
            },
            0x83 if b[1] == 0xc7 => {
                let value = self.get16(EDI).wrapping_add(u16::from(b[2]));
                self.set16(EDI, value);
                self.logic_flags(u64::from(value));
                self.commit(b, 3);
            },
            0x72 | 0x73 | 0x74 | 0x75 | 0x77 => {
                let taken = self.condition(b[0]);
                self.branch8(b, 2, taken);
            },
            0xe4 if b[1] == 0x92 => {
                self.set8(EAX, self.port92);
                self.commit(b, 2);
            },
            0x0c => {
                let value = self.get8(EAX) | b[1];
                self.set8(EAX, value);
                self.logic_flags(u64::from(value));
                self.commit(b, 2);
            },
            0x24 => {
                let value = self.get8(EAX) & b[1];
                self.set8(EAX, value);
                self.logic_flags(u64::from(value));
                self.commit(b, 2);
            },
            0xe6 if b[1] == 0x92 => {
                self.port92 = self.get8(EAX);
                self.trace.a20_enabled = self.port92 & 2 != 0;
                self.commit(b, 2);
            },
            0xea => {
                let offset = u16::from_le_bytes([b[1], b[2]]);
                let segment = u16::from_le_bytes([b[3], b[4]]);
                self.commit(b, 5);
                self.cs = segment;
                self.ip = u64::from(offset);
                if self.stage == Stage::Stage1 {
                    if segment != 0 || u64::from(offset) != STAGE2_START {
                        return Err(StageExecError::UnexpectedTransfer {
                            expected: STAGE2_START,
                            actual: (u64::from(segment) << 4) + u64::from(offset),
                        });
                    }
                    self.stage = Stage::Stage2;
                } else if self.cr0 & 1 != 0 {
                    self.mode = Mode::Protected32;
                    self.trace.protected_mode_entered = true;
                    self.ip = u64::from(offset);
                }
            },
            0x26 if b[1..5] == [0x66, 0xc7, 0x45, 0x14] => {
                let value = u32::from_le_bytes([b[5], b[6], b[7], b[8]]);
                let address = self.real_data(self.es, self.get16(EDI).wrapping_add(0x14));
                self.write32(address, value)?;
                self.commit(b, 9);
            },
            0x66 => self.step_real_66(b)?,
            0x0f => self.step_real_0f(b)?,
            _ => return Err(self.unsupported(b)),
        }
        Ok(false)
    }

    fn step_real_66(&mut self, b: &[u8; 15]) -> Result<(), StageExecError> {
        match b[1] {
            0x31 if b[2] == 0xdb => {
                self.set32(EBX, 0);
                self.logic_flags(0);
                self.commit(b, 3);
            },
            0xb8..=0xbf => {
                let register = usize::from(b[1] - 0xb8);
                self.set32(register, u32::from_le_bytes([b[2], b[3], b[4], b[5]]));
                self.commit(b, 6);
            },
            0xc7 if b[2] == 0x06 => {
                let address = u16::from_le_bytes([b[3], b[4]]);
                let value = u32::from_le_bytes([b[5], b[6], b[7], b[8]]);
                self.write32(self.real_data(self.ds, address), value)?;
                self.commit(b, 9);
            },
            0x81 if b[2] == 0x3e => {
                let address = u16::from_le_bytes([b[3], b[4]]);
                let lhs = self.read32(self.real_data(self.ds, address))?;
                let rhs = u32::from_le_bytes([b[5], b[6], b[7], b[8]]);
                self.compare(u64::from(lhs), u64::from(rhs), u32::MAX as u64);
                self.commit(b, 9);
            },
            0x83 if b[2] == 0x3e => {
                let address = u16::from_le_bytes([b[3], b[4]]);
                let lhs = self.read32(self.real_data(self.ds, address))?;
                self.compare(u64::from(lhs), u64::from(b[5]), u32::MAX as u64);
                self.commit(b, 6);
            },
            0x83 if b[2] == 0xf9 => {
                self.compare(
                    u64::from(self.get32(ECX)),
                    u64::from(b[3]),
                    u32::MAX as u64,
                );
                self.commit(b, 4);
            },
            0x83 if b[2] == 0xc8 => {
                let value = self.get32(EAX) | u32::from(b[3]);
                self.set32(EAX, value);
                self.logic_flags(u64::from(value));
                self.commit(b, 4);
            },
            0x85 if b[2] == 0xc0 || b[2] == 0xdb => {
                let register = if b[2] == 0xc0 { EAX } else { EBX };
                self.logic_flags(u64::from(self.get32(register)));
                self.commit(b, 3);
            },
            0x3d => {
                let rhs = u32::from_le_bytes([b[2], b[3], b[4], b[5]]);
                self.compare(
                    u64::from(self.get32(EAX)),
                    u64::from(rhs),
                    u32::MAX as u64,
                );
                self.commit(b, 6);
            },
            0xa1 => {
                let address = u16::from_le_bytes([b[2], b[3]]);
                let value = self.read32(self.real_data(self.ds, address))?;
                self.set32(EAX, value);
                self.commit(b, 4);
            },
            0xff if b[2] == 0x06 => {
                let address = self.real_data(self.ds, u16::from_le_bytes([b[3], b[4]]));
                let value = self.read32(address)?.wrapping_add(1);
                self.write32(address, value)?;
                self.logic_flags(u64::from(value));
                self.commit(b, 5);
            },
            _ => return Err(self.unsupported(b)),
        }
        Ok(())
    }

    fn step_real_0f(&mut self, b: &[u8; 15]) -> Result<(), StageExecError> {
        match b[1] {
            0x82 | 0x84 | 0x85 | 0x87 => {
                let taken = self.condition(b[1] - 0x10);
                self.branch16(b, 4, taken);
            },
            0x01 if b[2] == 0x16 => {
                // LGDT's descriptor bytes are consumed from actual guest RAM;
                // the bounded runner uses the known flat GDT semantics after
                // the subsequent far transfer.
                let descriptor = self.real_data(self.ds, u16::from_le_bytes([b[3], b[4]]));
                let mut bytes = [0; 6];
                self.bus.read_physical(descriptor, &mut bytes)?;
                self.commit(b, 5);
            },
            0x20 if b[2] == 0xc0 => {
                self.set32(EAX, self.cr0 as u32);
                self.commit(b, 3);
            },
            0x22 if b[2] == 0xc0 => {
                self.cr0 = u64::from(self.get32(EAX));
                self.commit(b, 3);
            },
            _ => return Err(self.unsupported(b)),
        }
        Ok(())
    }

    fn step_protected(&mut self, b: &[u8; 15]) -> Result<bool, StageExecError> {
        match b[0] {
            0x66 if b[1] == 0xb8 => {
                self.set16(EAX, u16::from_le_bytes([b[2], b[3]]));
                self.commit(b, 4);
            },
            0x66 if b[1] == 0x8e => {
                let value = self.get16(EAX);
                match b[2] {
                    0xd8 => self.ds = value,
                    0xc0 => self.es = value,
                    0xd0 => self.ss = value,
                    0xe0 => self.fs = value,
                    0xe8 => self.gs = value,
                    _ => return Err(self.unsupported(b)),
                }
                self.commit(b, 3);
            },
            0xb8..=0xbf => {
                let register = usize::from(b[0] - 0xb8);
                self.set32(register, u32::from_le_bytes([b[1], b[2], b[3], b[4]]));
                self.commit(b, 5);
            },
            0xfc => {
                self.direction = false;
                self.commit(b, 1);
            },
            0x31 if b[1] == 0xc0 => {
                self.set32(EAX, 0);
                self.logic_flags(0);
                self.commit(b, 2);
            },
            0xf3 if b[1] == 0xab => {
                if self.direction {
                    return Err(StageExecError::Bios("reverse REP STOSD is unsupported"));
                }
                let count = self.get32(ECX);
                let mut address = u64::from(self.get32(EDI));
                for _ in 0..count {
                    self.write32(address, self.get32(EAX))?;
                    address += 4;
                }
                self.set32(EDI, address as u32);
                self.set32(ECX, 0);
                self.commit(b, 2);
            },
            0xc7 if b[1] == 0x05 => {
                let address = u64::from(u32::from_le_bytes([b[2], b[3], b[4], b[5]]));
                let value = u32::from_le_bytes([b[6], b[7], b[8], b[9]]);
                self.write32(address, value)?;
                self.commit(b, 10);
            },
            0xc7 if b[1] == 0x47 && b[2] == 4 => {
                let value = u32::from_le_bytes([b[3], b[4], b[5], b[6]]);
                self.write32(u64::from(self.get32(EDI)) + 4, value)?;
                self.commit(b, 7);
            },
            0x89 if b[1] == 0x07 => {
                self.write32(u64::from(self.get32(EDI)), self.get32(EAX))?;
                self.commit(b, 2);
            },
            0x05 => {
                let rhs = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
                let value = self.get32(EAX).wrapping_add(rhs);
                self.set32(EAX, value);
                self.logic_flags(u64::from(value));
                self.commit(b, 5);
            },
            0x0d => {
                let rhs = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
                let value = self.get32(EAX) | rhs;
                self.set32(EAX, value);
                self.logic_flags(u64::from(value));
                self.commit(b, 5);
            },
            0x83 if b[1] == 0xc7 => {
                let value = self.get32(EDI).wrapping_add(u32::from(b[2]));
                self.set32(EDI, value);
                self.logic_flags(u64::from(value));
                self.commit(b, 3);
            },
            0x83 if b[1] == 0xe0 => {
                let rhs = i32::from(b[2] as i8) as u32;
                let value = self.get32(EAX) & rhs;
                self.set32(EAX, value);
                self.logic_flags(u64::from(value));
                self.commit(b, 3);
            },
            0x83 if b[1] == 0xc8 => {
                let value = self.get32(EAX) | u32::from(b[2]);
                self.set32(EAX, value);
                self.logic_flags(u64::from(value));
                self.commit(b, 3);
            },
            0xe2 => {
                let count = self.get32(ECX).wrapping_sub(1);
                self.set32(ECX, count);
                self.branch8(b, 2, count != 0);
            },
            0xea => {
                let offset = u32::from_le_bytes([b[1], b[2], b[3], b[4]]);
                let segment = u16::from_le_bytes([b[5], b[6]]);
                self.commit(b, 7);
                if self.cr0 & (1 << 31) == 0 || self.efer & (1 << 8) == 0 {
                    return Err(StageExecError::Bios("long-mode far jump before PG/LME"));
                }
                self.cs = segment;
                self.ip = u64::from(offset);
                self.mode = Mode::Long64;
                self.trace.long_mode_entered = true;
            },
            0x0f => self.step_protected_0f(b)?,
            _ => return Err(self.unsupported(b)),
        }
        Ok(false)
    }

    fn step_protected_0f(&mut self, b: &[u8; 15]) -> Result<(), StageExecError> {
        match (b[1], b[2]) {
            (0x20, 0xc0) => self.set32(EAX, self.cr0 as u32),
            (0x20, 0xe0) => self.set32(EAX, self.cr4 as u32),
            (0x22, 0xc0) => self.cr0 = u64::from(self.get32(EAX)),
            (0x22, 0xd8) => self.cr3 = u64::from(self.get32(EAX)),
            (0x22, 0xe0) => self.cr4 = u64::from(self.get32(EAX)),
            _ if b[1] == 0x32 => {
                if self.get32(ECX) != 0xc000_0080 {
                    return Err(StageExecError::Bios("unsupported RDMSR index"));
                }
                self.set32(EAX, self.efer as u32);
                self.set32(EDX, (self.efer >> 32) as u32);
                self.commit(b, 2);
                return Ok(());
            },
            _ if b[1] == 0x30 => {
                if self.get32(ECX) != 0xc000_0080 {
                    return Err(StageExecError::Bios("unsupported WRMSR index"));
                }
                self.efer = u64::from(self.get32(EAX)) | (u64::from(self.get32(EDX)) << 32);
                self.commit(b, 2);
                return Ok(());
            },
            _ => return Err(self.unsupported(b)),
        }
        self.commit(b, 3);
        Ok(())
    }

    fn step_long(&mut self, b: &[u8; 15]) -> Result<bool, StageExecError> {
        match b[0] {
            0x31 if b[1] == 0xc0 => {
                self.set32(EAX, 0);
                self.logic_flags(0);
                self.commit(b, 2);
            },
            0x66 if b[1] == 0x8e => {
                let value = self.get16(EAX);
                match b[2] {
                    0xd8 => self.ds = value,
                    0xc0 => self.es = value,
                    0xd0 => self.ss = value,
                    0xe0 => self.fs = value,
                    0xe8 => self.gs = value,
                    _ => return Err(self.unsupported(b)),
                }
                self.commit(b, 3);
            },
            0x48 if b[1..3] == [0xc7, 0xc4] => {
                let value = i64::from(i32::from_le_bytes([b[3], b[4], b[5], b[6]])) as u64;
                self.registers[ESP] = value;
                self.commit(b, 7);
            },
            0x48 if b[1..3] == [0x31, 0xed] => {
                self.registers[EBP] = 0;
                self.logic_flags(0);
                self.commit(b, 3);
            },
            0x0f if b[1..3] == [0xb6, 0x3d] => {
                let displacement = i64::from(i32::from_le_bytes([b[3], b[4], b[5], b[6]]));
                let address = self.ip.wrapping_add(7).wrapping_add_signed(displacement);
                let value = self.read8(address)?;
                self.set32(EDI, u32::from(value));
                self.commit(b, 7);
            },
            0x8b if b[1] == 0x35 => {
                let displacement = i64::from(i32::from_le_bytes([b[2], b[3], b[4], b[5]]));
                let address = self.ip.wrapping_add(6).wrapping_add_signed(displacement);
                let value = self.read32(address)?;
                self.set32(ESI, value);
                self.commit(b, 6);
            },
            0xe8 => {
                let displacement = i64::from(i32::from_le_bytes([b[1], b[2], b[3], b[4]]));
                let target = self.ip.wrapping_add(5).wrapping_add_signed(displacement);
                self.commit(b, 5);
                if self.get8(EDI) != BOOT_DRIVE
                    || self.get32(ESI) != self.trace.e820_entries
                {
                    return Err(StageExecError::Bios("stage2_main arguments differ from BIOS state"));
                }
                self.trace.stage2_main_entry = target;
                return Ok(true);
            },
            _ => return Err(self.unsupported(b)),
        }
        Ok(false)
    }

    fn bios_interrupt(&mut self, vector: u8) -> Result<(), StageExecError> {
        self.trace.bios_interrupts += 1;
        match vector {
            0x13 => match self.high8(EAX) {
                0x41 => {
                    if self.get16(EBX) != 0x55aa || self.get8(EDX) != BOOT_DRIVE {
                        return Err(StageExecError::Bios("invalid EDD probe registers"));
                    }
                    self.set16(EBX, 0xaa55);
                    self.set16(ECX, 1);
                    self.carry = false;
                },
                0x42 => self.edd_read()?,
                _ => return Err(StageExecError::Bios("unsupported INT 13h function")),
            },
            0x15 if self.get16(EAX) == 0x2401 => {
                self.trace.a20_enabled = true;
                self.carry = false;
            },
            0x15 if self.get32(EAX) == 0xe820 => self.e820()?,
            0x10 => return Err(StageExecError::Bios("stage failure reached INT 10h")),
            _ => return Err(StageExecError::Bios("unsupported BIOS interrupt")),
        }
        Ok(())
    }

    fn edd_read(&mut self) -> Result<(), StageExecError> {
        if self.get8(EDX) != BOOT_DRIVE {
            return Err(StageExecError::Bios("EDD read used unsupported drive"));
        }
        let dap = self.real_data(self.ds, self.get16(ESI));
        if self.read8(dap)? != 0x10 {
            return Err(StageExecError::Bios("invalid EDD packet size"));
        }
        let sectors = u64::from(self.read16(dap + 2)?);
        if sectors == 0 || sectors > 127 {
            return Err(StageExecError::Bios("invalid EDD sector count"));
        }
        let offset = self.read16(dap + 4)?;
        let segment = self.read16(dap + 6)?;
        let lba = self.read64(dap + 8)?;
        let start = usize::try_from(lba)
            .ok()
            .and_then(|value| value.checked_mul(SECTOR_SIZE))
            .ok_or(StageExecError::Disk("EDD LBA overflow"))?;
        let length = usize::try_from(sectors)
            .ok()
            .and_then(|value| value.checked_mul(SECTOR_SIZE))
            .ok_or(StageExecError::Disk("EDD length overflow"))?;
        let source = self
            .image
            .get(start..start.saturating_add(length))
            .ok_or(StageExecError::Disk("EDD read exceeds disk"))?;
        let destination = self.real_data(segment, offset);
        self.bus.write_physical(destination, source)?;
        self.carry = false;
        Ok(())
    }

    fn e820(&mut self) -> Result<(), StageExecError> {
        if self.get32(EDX) != 0x534d_4150 || self.get32(ECX) < 20 {
            return Err(StageExecError::Bios("invalid E820 request registers"));
        }
        let memory_end = self.bus.len() as u64;
        if memory_end <= 0x10_0000 {
            return Err(StageExecError::Bios("E820 requires memory above 1 MiB"));
        }
        let records = [
            E820Record::new(0, 0x0009_fc00, 1),
            E820Record::new(0x0009_fc00, 0x0006_0400, 2),
            E820Record::new(0x0010_0000, memory_end - 0x0010_0000, 1),
        ];
        let index = usize::try_from(self.get32(EBX))
            .map_err(|_| StageExecError::Bios("invalid E820 continuation"))?;
        let record = records
            .get(index)
            .ok_or(StageExecError::Bios("invalid E820 continuation"))?;
        let destination = self.real_data(self.es, self.get16(EDI));
        self.bus.write_physical(destination, &record.bytes())?;
        self.set32(EAX, 0x534d_4150);
        self.set32(ECX, 24);
        self.set32(EBX, if index + 1 == records.len() { 0 } else { (index + 1) as u32 });
        self.trace.e820_entries = self.trace.e820_entries.max((index + 1) as u32);
        self.carry = false;
        Ok(())
    }

    fn condition(&self, opcode: u8) -> bool {
        match opcode {
            0x72 => self.carry,
            0x73 => !self.carry,
            0x74 => self.zero,
            0x75 => !self.zero,
            0x77 => !self.carry && !self.zero,
            _ => false,
        }
    }

    fn compare(&mut self, lhs: u64, rhs: u64, mask: u64) {
        let lhs = lhs & mask;
        let rhs = rhs & mask;
        self.carry = lhs < rhs;
        self.zero = lhs.wrapping_sub(rhs) & mask == 0;
    }

    fn logic_flags(&mut self, value: u64) {
        self.carry = false;
        self.zero = value == 0;
    }

    fn real_data(&self, segment: u16, offset: u16) -> u64 {
        (u64::from(segment) << 4) + u64::from(offset)
    }

    fn get8(&self, register: usize) -> u8 {
        self.registers[register] as u8
    }

    fn set8(&mut self, register: usize, value: u8) {
        self.registers[register] = (self.registers[register] & !0xff) | u64::from(value);
    }

    fn high8(&self, register: usize) -> u8 {
        (self.registers[register] >> 8) as u8
    }

    fn set_high8(&mut self, register: usize, value: u8) {
        self.registers[register] =
            (self.registers[register] & !0xff00) | (u64::from(value) << 8);
    }

    fn get16(&self, register: usize) -> u16 {
        self.registers[register] as u16
    }

    fn set16(&mut self, register: usize, value: u16) {
        self.registers[register] = (self.registers[register] & !0xffff) | u64::from(value);
    }

    fn get32(&self, register: usize) -> u32 {
        self.registers[register] as u32
    }

    fn set32(&mut self, register: usize, value: u32) {
        self.registers[register] = u64::from(value);
    }

    fn read8(&mut self, address: u64) -> Result<u8, StageExecError> {
        let mut bytes = [0; 1];
        self.bus.read_physical(address, &mut bytes)?;
        Ok(bytes[0])
    }

    fn read16(&mut self, address: u64) -> Result<u16, StageExecError> {
        let mut bytes = [0; 2];
        self.bus.read_physical(address, &mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read32(&mut self, address: u64) -> Result<u32, StageExecError> {
        let mut bytes = [0; 4];
        self.bus.read_physical(address, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read64(&mut self, address: u64) -> Result<u64, StageExecError> {
        let mut bytes = [0; 8];
        self.bus.read_physical(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn write8(&mut self, address: u64, value: u8) -> Result<(), StageExecError> {
        self.bus.write_physical(address, &[value])?;
        Ok(())
    }

    fn write16(&mut self, address: u64, value: u16) -> Result<(), StageExecError> {
        self.bus.write_physical(address, &value.to_le_bytes())?;
        Ok(())
    }

    fn write32(&mut self, address: u64, value: u32) -> Result<(), StageExecError> {
        self.bus.write_physical(address, &value.to_le_bytes())?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct E820Record {
    base: u64,
    length: u64,
    kind: u32,
    attributes: u32,
}

impl E820Record {
    const fn new(base: u64, length: u64, kind: u32) -> Self {
        Self {
            base,
            length,
            kind,
            attributes: 1,
        }
    }

    fn bytes(self) -> [u8; 24] {
        let mut bytes = [0; 24];
        bytes[0..8].copy_from_slice(&self.base.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.length.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.kind.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.attributes.to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_trace_is_order_sensitive_and_counts_repeated_bytes() {
        let mut first = FetchTrace::new();
        first.record(&[1, 2]);
        first.record(&[3]);
        let mut second = FetchTrace::new();
        second.record(&[1, 3]);
        second.record(&[2]);
        assert_eq!(first.instructions, 2);
        assert_eq!(first.bytes, 3);
        assert_ne!(first.checksum, second.checksum);
    }

    #[test]
    fn unsupported_opcode_is_never_skipped() {
        let mut bus = MemoryBus::new(1024 * 1024);
        bus.write_physical(STAGE1_START, &[0x0f, 0x0b]).unwrap();
        let image = vec![0; 3 * SECTOR_SIZE];
        let error = execute_packaged_stages(&mut bus, &image).unwrap_err();
        assert!(matches!(
            error,
            StageExecError::Unsupported {
                stage: "stage1",
                address: STAGE1_START,
                ..
            }
        ));
    }
}
