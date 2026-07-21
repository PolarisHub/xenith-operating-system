//! Architectural CPU state and instruction interpreter.

use std::collections::BTreeMap;

use xenith_x86::{
    decode, Condition, Instruction, MemoryOperand, Mnemonic, Operand, OperandSize, Register,
};

use crate::memory::{Access, MemoryBus, MemoryError, PagingContext, Privilege};

const FLAG_CF: u64 = 1 << 0;
const FLAG_PF: u64 = 1 << 2;
const FLAG_AF: u64 = 1 << 4;
const FLAG_ZF: u64 = 1 << 6;
const FLAG_SF: u64 = 1 << 7;
const FLAG_IF: u64 = 1 << 9;
const FLAG_DF: u64 = 1 << 10;
const FLAG_OF: u64 = 1 << 11;
const CR0_EM: u64 = 1 << 2;
const CR0_TS: u64 = 1 << 3;
const CR4_OSFXSR: u64 = 1 << 9;
const FXSAVE_SIZE: usize = 512;
const FXSAVE_ALIGNMENT: u64 = 16;
const MXCSR_MASK: u32 = 0x0000_ffbf;

const IDT_ENTRY_SIZE: u64 = 16;
const GDT_ENTRY_SIZE: u64 = 8;
const TSS_RSP0_OFFSET: u64 = 4;
const TSS_IST1_OFFSET: u64 = 0x24;

const IA32_EFER: u32 = 0xC000_0080;
const IA32_APIC_BASE: u32 = 0x0000_001B;
const IA32_PAT: u32 = 0x0000_0277;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;
const IA32_FS_BASE: u32 = 0xC000_0100;
const IA32_GS_BASE: u32 = 0xC000_0101;
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

#[derive(Clone, Copy, Debug, Default)]
pub struct DescriptorTable {
    pub base: u64,
    pub limit: u16,
}

#[derive(Clone, Debug)]
pub struct CpuState {
    pub registers: [u64; 16],
    pub rip: u64,
    pub rflags: u64,
    pub cs: u16,
    pub ss: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub tr: u16,
    pub gdtr: DescriptorTable,
    pub idtr: DescriptorTable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub cycles: u64,
    pub halted: bool,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            registers: [0; 16],
            rip: 0xFFF0,
            rflags: 2,
            cs: 0xF000,
            ss: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
            tr: 0,
            gdtr: DescriptorTable::default(),
            idtr: DescriptorTable::default(),
            cr0: 0x6000_0010,
            cr2: 0,
            cr3: 0,
            cr4: 0,
            efer: 0,
            cycles: 0,
            halted: false,
        }
    }
}

impl CpuState {
    #[must_use]
    pub fn register(&self, register: Register) -> u64 {
        self.registers[usize::from(register.index())]
    }
    pub fn set_register(&mut self, register: Register, value: u64) {
        self.registers[usize::from(register.index())] = value;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CpuFault {
    Memory(MemoryError),
    Decode {
        rip: u64,
        error: xenith_x86::DecodeError,
    },
    Unsupported {
        rip: u64,
        instruction: Instruction,
    },
    InvalidOperand,
    GeneralProtection(&'static str),
    DeviceNotAvailable,
    DivideError,
    InvalidControlRegister(u8),
    InvalidInterruptGate {
        vector: u8,
        reason: &'static str,
    },
    InvalidTaskState(&'static str),
    InvalidStartupVector {
        apic_id: u32,
        vector: u8,
        reason: &'static str,
    },
}

impl From<MemoryError> for CpuFault {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExitReason {
    Halted,
    Breakpoint(u64),
    Fault(CpuFault),
    InstructionLimit,
}

pub struct Cpu {
    pub state: CpuState,
    msrs: BTreeMap<u32, u64>,
    interrupt_shadow: u8,
    interrupts_delivered: u64,
    apic_id: u32,
    processor_count: u16,
    fx_state: [u8; FXSAVE_SIZE],
}

impl Default for Cpu {
    fn default() -> Self {
        Self::new()
    }
}

impl Cpu {
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_topology(0, 1, true)
    }

    #[must_use]
    pub(crate) fn new_with_topology(apic_id: u32, processor_count: u16, bsp: bool) -> Self {
        assert!(processor_count != 0);
        let mut msrs = BTreeMap::new();
        msrs.insert(IA32_EFER, 0);
        msrs.insert(
            IA32_APIC_BASE,
            0xFEE0_0000 | (1 << 11) | if bsp { 1 << 8 } else { 0 },
        );
        // Architectural reset value: WB, WT, UC-, UC repeated twice.
        msrs.insert(IA32_PAT, 0x0007_0406_0007_0406);
        msrs.insert(IA32_STAR, 0);
        msrs.insert(IA32_LSTAR, 0);
        msrs.insert(IA32_FMASK, 0);
        msrs.insert(IA32_FS_BASE, 0);
        msrs.insert(IA32_GS_BASE, 0);
        msrs.insert(IA32_KERNEL_GS_BASE, 0);
        Self {
            state: CpuState::default(),
            msrs,
            interrupt_shadow: 0,
            interrupts_delivered: 0,
            apic_id,
            processor_count,
            fx_state: initial_fx_state(),
        }
    }

    pub(crate) fn configure_topology(&mut self, apic_id: u32, processor_count: u16, bsp: bool) {
        self.apic_id = apic_id;
        self.processor_count = processor_count;
        let base = self
            .msrs
            .get(&IA32_APIC_BASE)
            .copied()
            .unwrap_or(0xFEE0_0000);
        self.msrs.insert(
            IA32_APIC_BASE,
            (base & !(1 << 8)) | (1 << 11) | if bsp { 1 << 8 } else { 0 },
        );
    }

    #[must_use]
    pub const fn apic_id(&self) -> u32 {
        self.apic_id
    }

    #[must_use]
    pub const fn interrupts_delivered(&self) -> u64 {
        self.interrupts_delivered
    }

    pub fn run(&mut self, bus: &mut MemoryBus, limit: u64) -> ExitReason {
        for _ in 0..limit {
            if let Some(reason) = self.run_cycle(bus) {
                return reason;
            }
        }
        ExitReason::InstructionLimit
    }

    /// Execute one interpreter/device cycle with normal interrupt delivery.
    ///
    /// The debugger uses the same primitive as the free-running loop so a
    /// continue operation cannot starve timer or keyboard IRQs.
    pub(crate) fn run_cycle(&mut self, bus: &mut MemoryBus) -> Option<ExitReason> {
        let interrupts_inhibited = self.interrupt_shadow != 0;
        self.interrupt_shadow = self.interrupt_shadow.saturating_sub(1);
        if !interrupts_inhibited && self.state.rflags & FLAG_IF != 0 {
            if let Some(vector) = bus.next_interrupt() {
                if let Err(fault) = self.deliver_interrupt(bus, vector) {
                    return Some(ExitReason::Fault(fault));
                }
                bus.tick(1);
                return None;
            }
        }

        if self.state.halted {
            bus.tick(1);
            return None;
        }

        match self.step(bus) {
            Ok(Some(ExitReason::Halted)) if self.state.rflags & FLAG_IF != 0 => {},
            Ok(Some(reason)) => return Some(reason),
            Ok(None) => {},
            Err(fault) => return Some(ExitReason::Fault(fault)),
        }
        bus.tick(1);
        None
    }

    pub fn step(&mut self, bus: &mut MemoryBus) -> Result<Option<ExitReason>, CpuFault> {
        let start_rip = self.state.rip;
        let mut bytes = [0u8; 15];
        let mut loaded = 0usize;
        let instruction = loop {
            if loaded == bytes.len() {
                return Err(CpuFault::Decode {
                    rip: start_rip,
                    error: xenith_x86::DecodeError {
                        offset: 15,
                        kind: xenith_x86::DecodeErrorKind::TooLong,
                    },
                });
            }
            let physical = bus.translate(
                start_rip + loaded as u64,
                self.paging_context(),
                Access::Execute,
            )?;
            bus.read_physical(physical, &mut bytes[loaded..loaded + 1])?;
            loaded += 1;
            match decode(&bytes[..loaded]) {
                Ok(instruction) => break instruction,
                Err(error)
                    if error.kind == xenith_x86::DecodeErrorKind::Truncated
                        && loaded < bytes.len() => {},
                Err(error) => {
                    return Err(CpuFault::Decode {
                        rip: start_rip,
                        error,
                    })
                },
            }
        };
        self.state.rip = start_rip.wrapping_add(u64::from(instruction.length));
        self.state.cycles = self.state.cycles.wrapping_add(1);
        self.execute(bus, instruction, start_rip)
    }

    fn execute(
        &mut self,
        bus: &mut MemoryBus,
        instruction: Instruction,
        start_rip: u64,
    ) -> Result<Option<ExitReason>, CpuFault> {
        let first = instruction.operands[0];
        let second = instruction.operands[1];
        let third = instruction.operands[2];
        match instruction.mnemonic {
            // The interpreter has a coherent RAM model and no host cache
            // aliases, so architectural cache/TLB maintenance is a no-op.
            Mnemonic::Nop | Mnemonic::Fence | Mnemonic::Invlpg => {},
            Mnemonic::Wbinvd => self.wbinvd()?,
            Mnemonic::Hlt => {
                self.state.halted = true;
                return Ok(Some(ExitReason::Halted));
            },
            Mnemonic::Cli => self.state.rflags &= !FLAG_IF,
            Mnemonic::Sti => {
                self.state.rflags |= FLAG_IF;
                // Maskable interrupts are inhibited through the instruction
                // immediately following STI. This is what makes `sti; hlt`
                // an atomic idle transition rather than a lost-wakeup race.
                self.interrupt_shadow = 1;
            },
            Mnemonic::Cld => self.state.rflags &= !FLAG_DF,
            Mnemonic::Std => self.state.rflags |= FLAG_DF,
            Mnemonic::Int3 => return Ok(Some(ExitReason::Breakpoint(start_rip))),
            Mnemonic::Clts => self.clts()?,
            Mnemonic::Fninit => self.fninit()?,
            Mnemonic::Fxsave => {
                if self.state.cr4 & CR4_OSFXSR == 0 {
                    return Err(CpuFault::Unsupported {
                        rip: start_rip,
                        instruction,
                    });
                }
                self.fxsave(bus, first.ok_or(CpuFault::InvalidOperand)?)?;
            },
            Mnemonic::Fxrstor => {
                if self.state.cr4 & CR4_OSFXSR == 0 {
                    return Err(CpuFault::Unsupported {
                        rip: start_rip,
                        instruction,
                    });
                }
                self.fxrstor(bus, first.ok_or(CpuFault::InvalidOperand)?)?;
            },
            Mnemonic::Mov => {
                let destination = first.ok_or(CpuFault::InvalidOperand)?;
                let source = second.ok_or(CpuFault::InvalidOperand)?;
                let value = self.read_operand(bus, source)?;
                self.write_operand(
                    bus,
                    destination,
                    self.extend_for_destination(value, source, destination),
                )?;
            },
            Mnemonic::Xchg => {
                let left = first.ok_or(CpuFault::InvalidOperand)?;
                let right = second.ok_or(CpuFault::InvalidOperand)?;
                let left_value = self.read_operand(bus, left)?;
                let right_value = self.read_operand(bus, right)?;
                self.write_operand(bus, left, right_value)?;
                self.write_operand(bus, right, left_value)?;
            },
            Mnemonic::Movzx | Mnemonic::Movsx => {
                let destination = first.ok_or(CpuFault::InvalidOperand)?;
                let source = second.ok_or(CpuFault::InvalidOperand)?;
                let value = self.read_operand(bus, source)?;
                let value = if instruction.mnemonic == Mnemonic::Movsx {
                    sign_extend(value, source.size())
                } else {
                    value & source.size().mask()
                };
                self.write_operand(bus, destination, value)?;
            },
            Mnemonic::SignExtendAccumulator => {
                let destination = first.ok_or(CpuFault::InvalidOperand)?;
                let source = second.ok_or(CpuFault::InvalidOperand)?;
                let size = source.size();
                let value = self.read_operand(bus, source)?;
                let high = if value & (1u64 << (size.bits() - 1)) != 0 {
                    size.mask()
                } else {
                    0
                };
                self.write_operand(bus, destination, high)?;
            },
            Mnemonic::Lea => {
                let destination = first.ok_or(CpuFault::InvalidOperand)?;
                let Some(Operand::Memory(memory)) = second else {
                    return Err(CpuFault::InvalidOperand);
                };
                let address = self.effective_address(memory);
                self.write_operand(bus, destination, address)?;
            },
            Mnemonic::Add
            | Mnemonic::Adc
            | Mnemonic::Sub
            | Mnemonic::Sbb
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Cmp
            | Mnemonic::Test => {
                self.binary(bus, instruction.mnemonic, first, second)?;
            },
            Mnemonic::Cmpxchg => self.compare_exchange(bus, first, second)?,
            Mnemonic::Xadd => self.exchange_add(bus, first, second)?,
            Mnemonic::Bswap => {
                let operand = first.ok_or(CpuFault::InvalidOperand)?;
                let value = self.read_operand(bus, operand)?;
                let swapped = match operand.size() {
                    OperandSize::Dword => u64::from((value as u32).swap_bytes()),
                    OperandSize::Qword => value.swap_bytes(),
                    OperandSize::Byte | OperandSize::Word | OperandSize::Oword => {
                        return Err(CpuFault::InvalidOperand)
                    },
                };
                self.write_operand(bus, operand, swapped)?;
            },
            Mnemonic::Bsf | Mnemonic::Bsr => {
                self.bit_scan(bus, instruction.mnemonic, first, second)?;
            },
            Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc => {
                self.bit_test(bus, instruction.mnemonic, first, second)?;
            },
            Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Neg | Mnemonic::Not => {
                self.unary(bus, instruction.mnemonic, first)?
            },
            Mnemonic::Imul if second.is_some() => {
                self.signed_multiply(bus, first, second, third)?;
            },
            Mnemonic::Mul | Mnemonic::Imul | Mnemonic::Div | Mnemonic::Idiv => {
                self.multiply_divide(bus, instruction.mnemonic, first)?
            },
            Mnemonic::Push => {
                let operand = first.ok_or(CpuFault::InvalidOperand)?;
                let mut value = self.read_operand(bus, operand)?;
                if matches!(operand, Operand::Immediate { .. }) {
                    value = sign_extend(value, operand.size());
                }
                self.push(bus, value)?;
            },
            Mnemonic::Pop => {
                let value = self.pop(bus)?;
                self.write_operand(bus, first.ok_or(CpuFault::InvalidOperand)?, value)?;
            },
            Mnemonic::PushFlags => self.push(bus, self.state.rflags)?,
            Mnemonic::PopFlags => self.state.rflags = self.pop(bus)? | 2,
            Mnemonic::Call => {
                let target = self.branch_target(bus, first.ok_or(CpuFault::InvalidOperand)?)?;
                self.push(bus, self.state.rip)?;
                self.state.rip = target;
            },
            Mnemonic::Return => self.state.rip = self.pop(bus)?,
            Mnemonic::ReturnFar => {
                self.state.rip = self.pop(bus)?;
                self.state.cs = self.pop(bus)? as u16;
            },
            Mnemonic::Jump => {
                self.state.rip = self.branch_target(bus, first.ok_or(CpuFault::InvalidOperand)?)?
            },
            Mnemonic::JumpCondition(condition) => {
                if self.condition(condition) {
                    self.state.rip =
                        self.branch_target(bus, first.ok_or(CpuFault::InvalidOperand)?)?;
                }
            },
            Mnemonic::MoveCondition(condition) => {
                if self.condition(condition) {
                    let destination = first.ok_or(CpuFault::InvalidOperand)?;
                    let source = second.ok_or(CpuFault::InvalidOperand)?;
                    let value = self.read_operand(bus, source)?;
                    self.write_operand(bus, destination, value)?;
                }
            },
            Mnemonic::SetCondition(condition) => self.write_operand(
                bus,
                first.ok_or(CpuFault::InvalidOperand)?,
                u64::from(self.condition(condition)),
            )?,
            Mnemonic::In => {
                let destination = first.ok_or(CpuFault::InvalidOperand)?;
                let port = self.read_operand(bus, second.ok_or(CpuFault::InvalidOperand)?)? as u16;
                let value = bus.read_port(port, destination.size() as u8);
                self.write_operand(bus, destination, u64::from(value))?;
            },
            Mnemonic::Out => {
                let port = self.read_operand(bus, first.ok_or(CpuFault::InvalidOperand)?)? as u16;
                let source = second.ok_or(CpuFault::InvalidOperand)?;
                let value = self.read_operand(bus, source)?;
                bus.write_port(port, source.size() as u8, value as u32);
            },
            Mnemonic::Movs | Mnemonic::Stos => {
                self.string_operation(bus, instruction.mnemonic, instruction, first, second)?;
            },
            Mnemonic::Cpuid => self.cpuid(),
            Mnemonic::Rdmsr => self.rdmsr(bus),
            Mnemonic::Wrmsr => self.wrmsr(bus),
            Mnemonic::Rdtsc => {
                let value = self.state.cycles;
                self.state.set_register(Register::Rax, value as u32 as u64);
                self.state.set_register(Register::Rdx, value >> 32);
            },
            Mnemonic::Syscall => self.syscall(),
            Mnemonic::Sysret => self.sysret(),
            Mnemonic::Swapgs => self.swapgs(),
            Mnemonic::Lgdt | Mnemonic::Lidt => {
                self.load_descriptor_table(bus, instruction.mnemonic, first)?
            },
            Mnemonic::Ltr => {
                self.state.tr =
                    self.read_operand(bus, first.ok_or(CpuFault::InvalidOperand)?)? as u16;
            },
            Mnemonic::Iretq => self.iretq(bus)?,
            Mnemonic::Leave => {
                self.state
                    .set_register(Register::Rsp, self.state.register(Register::Rbp));
                let value = self.pop(bus)?;
                self.state.set_register(Register::Rbp, value);
            },
            Mnemonic::Shl | Mnemonic::Shr | Mnemonic::Sar | Mnemonic::Rol | Mnemonic::Ror => {
                self.shift(bus, instruction.mnemonic, first, second)?;
            },
            Mnemonic::Shld => self.shift_double_left(bus, first, second, third)?,
        }
        Ok(None)
    }

    fn read_operand(&self, bus: &mut MemoryBus, operand: Operand) -> Result<u64, CpuFault> {
        match operand {
            Operand::Register {
                register,
                size,
                high8,
            } => {
                let value = self.state.register(register);
                Ok(if high8 {
                    (value >> 8) & 0xFF
                } else {
                    value & size.mask()
                })
            },
            Operand::Memory(memory) => {
                let mut bytes = [0u8; 8];
                let count = usize::from(memory.size as u8).min(8);
                bus.read_linear(
                    self.effective_address(memory),
                    &mut bytes[..count],
                    self.paging_context(),
                    Access::Read,
                )?;
                Ok(u64::from_le_bytes(bytes))
            },
            Operand::Immediate { value, size } => Ok(value & size.mask()),
            Operand::Relative { displacement, .. } => {
                Ok(self.state.rip.wrapping_add_signed(displacement))
            },
            Operand::Control { index } => self.control(index),
            Operand::Segment { index } => self.segment(index).map(u64::from),
        }
    }

    fn write_operand(
        &mut self,
        bus: &mut MemoryBus,
        operand: Operand,
        value: u64,
    ) -> Result<(), CpuFault> {
        match operand {
            Operand::Register {
                register,
                size,
                high8,
            } => {
                let old = self.state.register(register);
                let value = value & size.mask();
                let updated = if high8 {
                    (old & !0xFF00) | ((value & 0xFF) << 8)
                } else {
                    match size {
                        OperandSize::Byte => (old & !0xFF) | value,
                        OperandSize::Word => (old & !0xFFFF) | value,
                        OperandSize::Dword => value,
                        OperandSize::Qword | OperandSize::Oword => value,
                    }
                };
                self.state.set_register(register, updated);
            },
            Operand::Memory(memory) => {
                let bytes = value.to_le_bytes();
                let count = usize::from(memory.size as u8).min(8);
                bus.write_linear(
                    self.effective_address(memory),
                    &bytes[..count],
                    self.paging_context(),
                )?;
            },
            Operand::Control { index } => self.set_control(index, value)?,
            Operand::Segment { index } => self.set_segment(index, value as u16)?,
            Operand::Immediate { .. } | Operand::Relative { .. } => {
                return Err(CpuFault::InvalidOperand)
            },
        }
        Ok(())
    }

    fn effective_address(&self, memory: MemoryOperand) -> u64 {
        let mut address = memory.displacement as u64;
        if memory.rip_relative {
            address = address.wrapping_add(self.state.rip);
        }
        if let Some(base) = memory.base {
            address = address.wrapping_add(self.state.register(base));
        }
        if let Some(index) = memory.index {
            address = address.wrapping_add(
                self.state
                    .register(index)
                    .wrapping_mul(u64::from(memory.scale)),
            );
        }
        address = address.wrapping_add(match memory.segment {
            Some(0x64) => self.msrs.get(&IA32_FS_BASE).copied().unwrap_or(0),
            Some(0x65) => self.msrs.get(&IA32_GS_BASE).copied().unwrap_or(0),
            _ => 0,
        });
        address
    }

    fn clts(&mut self) -> Result<(), CpuFault> {
        if self.state.cs & 3 != 0 {
            return Err(CpuFault::GeneralProtection("CLTS requires CPL0"));
        }
        self.state.cr0 &= !CR0_TS;
        Ok(())
    }

    fn wbinvd(&self) -> Result<(), CpuFault> {
        if self.state.cs & 3 != 0 {
            return Err(CpuFault::GeneralProtection("WBINVD requires CPL0"));
        }
        // Guest RAM is immediately coherent and has no modeled cache, so the
        // architectural write-back/invalidate operation needs no further
        // state change after its privilege check.
        Ok(())
    }

    fn require_fpu_available(&self) -> Result<(), CpuFault> {
        if self.state.cr0 & (CR0_EM | CR0_TS) != 0 {
            Err(CpuFault::DeviceNotAvailable)
        } else {
            Ok(())
        }
    }

    fn fx_address(&self, operand: Operand) -> Result<u64, CpuFault> {
        let Operand::Memory(memory) = operand else {
            return Err(CpuFault::InvalidOperand);
        };
        let address = self.effective_address(memory);
        if !address.is_multiple_of(FXSAVE_ALIGNMENT) {
            return Err(CpuFault::GeneralProtection(
                "FXSAVE/FXRSTOR area is not 16-byte aligned",
            ));
        }
        Ok(address)
    }

    fn fxsave(&mut self, bus: &mut MemoryBus, operand: Operand) -> Result<(), CpuFault> {
        self.require_fpu_available()?;
        let address = self.fx_address(operand)?;
        self.fx_state[28..32].copy_from_slice(&MXCSR_MASK.to_le_bytes());
        bus.write_linear(address, &self.fx_state, self.paging_context())?;
        Ok(())
    }

    fn fxrstor(&mut self, bus: &mut MemoryBus, operand: Operand) -> Result<(), CpuFault> {
        self.require_fpu_available()?;
        let address = self.fx_address(operand)?;
        let mut image = [0_u8; FXSAVE_SIZE];
        bus.read_linear(address, &mut image, self.paging_context(), Access::Read)?;
        let mxcsr = u32::from_le_bytes(image[24..28].try_into().expect("four-byte MXCSR"));
        if mxcsr & !MXCSR_MASK != 0 {
            return Err(CpuFault::GeneralProtection(
                "FXRSTOR image has unsupported MXCSR bits",
            ));
        }
        // MXCSR_MASK and the reserved tail are outputs of FXSAVE rather than
        // restorable register state. Preserve the emulated processor's mask
        // while loading the x87, MXCSR, ST, and XMM portions.
        self.fx_state[..28].copy_from_slice(&image[..28]);
        self.fx_state[32..416].copy_from_slice(&image[32..416]);
        self.fx_state[28..32].copy_from_slice(&MXCSR_MASK.to_le_bytes());
        Ok(())
    }

    fn fninit(&mut self) -> Result<(), CpuFault> {
        self.require_fpu_available()?;
        self.fx_state[..24].fill(0);
        self.fx_state[..2].copy_from_slice(&0x037f_u16.to_le_bytes());
        self.fx_state[32..160].fill(0);
        Ok(())
    }

    fn extend_for_destination(&self, value: u64, source: Operand, destination: Operand) -> u64 {
        if (source.size() as u8) < destination.size() as u8 {
            sign_extend(value, source.size())
        } else {
            value
        }
    }

    fn binary(
        &mut self,
        bus: &mut MemoryBus,
        mnemonic: Mnemonic,
        first: Option<Operand>,
        second: Option<Operand>,
    ) -> Result<(), CpuFault> {
        let destination = first.ok_or(CpuFault::InvalidOperand)?;
        let source = second.ok_or(CpuFault::InvalidOperand)?;
        let size = destination.size();
        let left = self.read_operand(bus, destination)? & size.mask();
        let mut right = self.read_operand(bus, source)?;
        if (source.size() as u8) < size as u8 {
            right = sign_extend(right, source.size());
        }
        right &= size.mask();
        let carry = u64::from(self.state.rflags & FLAG_CF != 0);
        let result = match mnemonic {
            Mnemonic::Add => self.add_flags(left, right, 0, size),
            Mnemonic::Adc => self.add_flags(left, right, carry, size),
            Mnemonic::Sub | Mnemonic::Cmp => self.sub_flags(left, right, 0, size),
            Mnemonic::Sbb => self.sub_flags(left, right, carry, size),
            Mnemonic::And | Mnemonic::Test => {
                let value = left & right;
                self.logical_flags(value, size);
                value
            },
            Mnemonic::Or => {
                let value = left | right;
                self.logical_flags(value, size);
                value
            },
            Mnemonic::Xor => {
                let value = left ^ right;
                self.logical_flags(value, size);
                value
            },
            _ => unreachable!(),
        } & size.mask();
        if !matches!(mnemonic, Mnemonic::Cmp | Mnemonic::Test) {
            self.write_operand(bus, destination, result)?;
        }
        Ok(())
    }

    fn unary(
        &mut self,
        bus: &mut MemoryBus,
        mnemonic: Mnemonic,
        operand: Option<Operand>,
    ) -> Result<(), CpuFault> {
        let operand = operand.ok_or(CpuFault::InvalidOperand)?;
        let size = operand.size();
        let value = self.read_operand(bus, operand)?;
        let old_cf = self.state.rflags & FLAG_CF;
        let result = match mnemonic {
            Mnemonic::Inc => {
                let result = self.add_flags(value, 1, 0, size);
                self.state.rflags = (self.state.rflags & !FLAG_CF) | old_cf;
                result
            },
            Mnemonic::Dec => {
                let result = self.sub_flags(value, 1, 0, size);
                self.state.rflags = (self.state.rflags & !FLAG_CF) | old_cf;
                result
            },
            Mnemonic::Neg => self.sub_flags(0, value, 0, size),
            Mnemonic::Not => !value,
            _ => unreachable!(),
        };
        self.write_operand(bus, operand, result & size.mask())
    }

    fn compare_exchange(
        &mut self,
        bus: &mut MemoryBus,
        destination: Option<Operand>,
        source: Option<Operand>,
    ) -> Result<(), CpuFault> {
        let destination = destination.ok_or(CpuFault::InvalidOperand)?;
        let source = source.ok_or(CpuFault::InvalidOperand)?;
        let size = destination.size();
        let accumulator = self.state.register(Register::Rax) & size.mask();
        let old = self.read_operand(bus, destination)? & size.mask();
        let _ = self.sub_flags(accumulator, old, 0, size);
        if accumulator == old {
            let replacement = self.read_operand(bus, source)?;
            self.write_operand(bus, destination, replacement)?;
        } else {
            self.write_operand(bus, Operand::register(Register::Rax, size), old)?;
        }
        Ok(())
    }

    fn exchange_add(
        &mut self,
        bus: &mut MemoryBus,
        destination: Option<Operand>,
        source: Option<Operand>,
    ) -> Result<(), CpuFault> {
        let destination = destination.ok_or(CpuFault::InvalidOperand)?;
        let source = source.ok_or(CpuFault::InvalidOperand)?;
        let size = destination.size();
        let old = self.read_operand(bus, destination)? & size.mask();
        let addend = self.read_operand(bus, source)? & size.mask();
        let result = self.add_flags(old, addend, 0, size);
        self.write_operand(bus, destination, result)?;
        self.write_operand(bus, source, old)
    }

    fn bit_scan(
        &mut self,
        bus: &mut MemoryBus,
        mnemonic: Mnemonic,
        destination: Option<Operand>,
        source: Option<Operand>,
    ) -> Result<(), CpuFault> {
        let destination = destination.ok_or(CpuFault::InvalidOperand)?;
        let source = source.ok_or(CpuFault::InvalidOperand)?;
        let value = self.read_operand(bus, source)? & source.size().mask();
        if value == 0 {
            self.state.rflags |= FLAG_ZF;
            return Ok(());
        }
        self.state.rflags &= !FLAG_ZF;
        let index = if mnemonic == Mnemonic::Bsf {
            value.trailing_zeros()
        } else {
            63 - value.leading_zeros()
        };
        self.write_operand(bus, destination, u64::from(index))
    }

    fn bit_test(
        &mut self,
        bus: &mut MemoryBus,
        mnemonic: Mnemonic,
        base: Option<Operand>,
        index: Option<Operand>,
    ) -> Result<(), CpuFault> {
        let base = base.ok_or(CpuFault::InvalidOperand)?;
        let width = u64::from(base.size().bits());
        let value = self.read_operand(bus, base)?;
        let index = self.read_operand(bus, index.ok_or(CpuFault::InvalidOperand)?)? % width;
        let bit = 1u64 << index;
        self.state.rflags &= !FLAG_CF;
        if value & bit != 0 {
            self.state.rflags |= FLAG_CF;
        }
        let updated = match mnemonic {
            Mnemonic::Bt => return Ok(()),
            Mnemonic::Bts => value | bit,
            Mnemonic::Btr => value & !bit,
            Mnemonic::Btc => value ^ bit,
            _ => return Err(CpuFault::InvalidOperand),
        };
        self.write_operand(bus, base, updated)?;
        Ok(())
    }

    fn shift(
        &mut self,
        bus: &mut MemoryBus,
        mnemonic: Mnemonic,
        destination: Option<Operand>,
        count: Option<Operand>,
    ) -> Result<(), CpuFault> {
        let destination = destination.ok_or(CpuFault::InvalidOperand)?;
        let size = destination.size();
        let width = u32::from(size.bits());
        let count_mask = if width == 64 { 0x3f } else { 0x1f };
        let mut count =
            (self.read_operand(bus, count.ok_or(CpuFault::InvalidOperand)?)? as u32) & count_mask;
        if count == 0 {
            return Ok(());
        }
        if matches!(mnemonic, Mnemonic::Rol | Mnemonic::Ror) {
            count %= width;
            if count == 0 {
                return Ok(());
            }
        }
        let value = self.read_operand(bus, destination)? & size.mask();
        let (result, carry) = match mnemonic {
            Mnemonic::Rol => {
                let result = rotate_left(value, size, count);
                (result, result & 1)
            },
            Mnemonic::Ror => {
                let result = rotate_right(value, size, count);
                (result, (result >> (width - 1)) & 1)
            },
            Mnemonic::Shl => (
                value.wrapping_shl(count) & size.mask(),
                (value >> (width - count.min(width))) & 1,
            ),
            Mnemonic::Shr => (
                value.wrapping_shr(count),
                (value >> (count.min(width) - 1)) & 1,
            ),
            Mnemonic::Sar => {
                let signed = sign_extend(value, size) as i64;
                (
                    (signed >> count.min(width - 1)) as u64 & size.mask(),
                    (value >> (count.min(width) - 1)) & 1,
                )
            },
            _ => return Err(CpuFault::InvalidOperand),
        };
        self.common_flags(result, size);
        self.state.rflags &= !(FLAG_CF | FLAG_OF);
        if carry != 0 {
            self.state.rflags |= FLAG_CF;
        }
        if count == 1 {
            match mnemonic {
                Mnemonic::Shl if ((result >> (width - 1)) & 1) ^ carry != 0 => {
                    self.state.rflags |= FLAG_OF;
                },
                Mnemonic::Shr if value & (1u64 << (width - 1)) != 0 => {
                    self.state.rflags |= FLAG_OF;
                },
                Mnemonic::Rol if ((result >> (width - 1)) & 1) ^ carry != 0 => {
                    self.state.rflags |= FLAG_OF;
                },
                Mnemonic::Ror if ((result >> (width - 1)) ^ (result >> (width - 2))) & 1 != 0 => {
                    self.state.rflags |= FLAG_OF;
                },
                _ => {},
            }
        }
        self.write_operand(bus, destination, result)
    }

    fn shift_double_left(
        &mut self,
        bus: &mut MemoryBus,
        destination: Option<Operand>,
        source: Option<Operand>,
        count: Option<Operand>,
    ) -> Result<(), CpuFault> {
        let destination = destination.ok_or(CpuFault::InvalidOperand)?;
        let source = source.ok_or(CpuFault::InvalidOperand)?;
        if destination.size() != source.size() {
            return Err(CpuFault::InvalidOperand);
        }

        let size = destination.size();
        let width = u32::from(size.bits());
        if !matches!(width, 16 | 32 | 64) {
            return Err(CpuFault::InvalidOperand);
        }
        let count_mask = if width == 64 { 0x3f } else { 0x1f };
        let count =
            (self.read_operand(bus, count.ok_or(CpuFault::InvalidOperand)?)? as u32) & count_mask;
        if count == 0 {
            return Ok(());
        }

        let mask = size.mask();
        let destination_value = self.read_operand(bus, destination)? & mask;
        let source_value = self.read_operand(bus, source)? & mask;
        let concatenated = (u128::from(destination_value) << width) | u128::from(source_value);
        let result = ((concatenated << count) >> width) as u64 & mask;
        let carry_position = width * 2 - count;
        let carry = (concatenated >> carry_position) as u64 & 1;

        self.common_flags(result, size);
        self.state.rflags &= !(FLAG_CF | FLAG_OF);
        if carry != 0 {
            self.state.rflags |= FLAG_CF;
        }
        if count == 1 && ((result >> (width - 1)) & 1) ^ carry != 0 {
            self.state.rflags |= FLAG_OF;
        }
        self.write_operand(bus, destination, result)
    }

    fn string_operation(
        &mut self,
        bus: &mut MemoryBus,
        mnemonic: Mnemonic,
        instruction: Instruction,
        first: Option<Operand>,
        second: Option<Operand>,
    ) -> Result<(), CpuFault> {
        let size = first.ok_or(CpuFault::InvalidOperand)?.size();
        let bytes = u64::from(size as u8);
        let repeated = instruction.prefixes.repeat || instruction.prefixes.repeat_not_equal;
        let count = if repeated {
            self.state.register(Register::Rcx)
        } else {
            1
        };
        let delta = if self.state.rflags & FLAG_DF != 0 {
            0u64.wrapping_sub(bytes)
        } else {
            bytes
        };
        for _ in 0..count {
            let destination = self.state.register(Register::Rdi);
            let value = if mnemonic == Mnemonic::Movs {
                let source = self.state.register(Register::Rsi);
                let mut raw = [0u8; 8];
                bus.read_linear(
                    source,
                    &mut raw[..bytes as usize],
                    self.paging_context(),
                    Access::Read,
                )?;
                self.state
                    .set_register(Register::Rsi, source.wrapping_add(delta));
                u64::from_le_bytes(raw)
            } else {
                self.read_operand(bus, second.ok_or(CpuFault::InvalidOperand)?)?
            };
            bus.write_linear(
                destination,
                &value.to_le_bytes()[..bytes as usize],
                self.paging_context(),
            )?;
            self.state
                .set_register(Register::Rdi, destination.wrapping_add(delta));
        }
        if repeated {
            self.state.set_register(Register::Rcx, 0);
        }
        Ok(())
    }

    fn multiply_divide(
        &mut self,
        bus: &mut MemoryBus,
        mnemonic: Mnemonic,
        operand: Option<Operand>,
    ) -> Result<(), CpuFault> {
        let operand = operand.ok_or(CpuFault::InvalidOperand)?;
        let size = operand.size();
        let bits = u32::from(size.bits());
        let mask = u128::from(size.mask());
        let source = u128::from(self.read_operand(bus, operand)? & size.mask());
        let accumulator = u128::from(self.state.register(Register::Rax) & size.mask());
        match mnemonic {
            Mnemonic::Mul | Mnemonic::Imul => {
                let result = accumulator.wrapping_mul(source);
                let low = (result & mask) as u64;
                let high = ((result >> bits) & mask) as u64;
                self.state.set_register(Register::Rax, low);
                self.state.set_register(Register::Rdx, high);
                self.state.rflags &= !(FLAG_CF | FLAG_OF);
                if high != 0 {
                    self.state.rflags |= FLAG_CF | FLAG_OF;
                }
            },
            Mnemonic::Div | Mnemonic::Idiv => {
                if source == 0 {
                    return Err(CpuFault::DivideError);
                }
                let dividend = (u128::from(self.state.register(Register::Rdx) & size.mask())
                    << bits)
                    | accumulator;
                let quotient = dividend / source;
                if quotient > mask {
                    return Err(CpuFault::DivideError);
                }
                self.state.set_register(Register::Rax, quotient as u64);
                self.state
                    .set_register(Register::Rdx, (dividend % source) as u64);
            },
            _ => unreachable!(),
        }
        Ok(())
    }

    fn signed_multiply(
        &mut self,
        bus: &mut MemoryBus,
        destination: Option<Operand>,
        source: Option<Operand>,
        immediate: Option<Operand>,
    ) -> Result<(), CpuFault> {
        let destination = destination.ok_or(CpuFault::InvalidOperand)?;
        let source = source.ok_or(CpuFault::InvalidOperand)?;
        let size = destination.size();
        let left_operand = if immediate.is_some() {
            source
        } else {
            destination
        };
        let right_operand = immediate.unwrap_or(source);
        let left = signed_operand(self.read_operand(bus, left_operand)?, left_operand.size());
        let right = signed_operand(self.read_operand(bus, right_operand)?, right_operand.size());
        let result = left.wrapping_mul(right);
        let bits = u32::from(size.bits());
        let (minimum, maximum) = if bits == 64 {
            (i128::from(i64::MIN), i128::from(i64::MAX))
        } else {
            (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
        };
        self.state.rflags &= !(FLAG_CF | FLAG_OF);
        if result < minimum || result > maximum {
            self.state.rflags |= FLAG_CF | FLAG_OF;
        }
        self.write_operand(bus, destination, result as u64 & size.mask())
    }

    fn add_flags(&mut self, left: u64, right: u64, carry: u64, size: OperandSize) -> u64 {
        let mask = size.mask();
        let (intermediate, carry1) = (left & mask).overflowing_add(right & mask);
        let (result, carry2) = intermediate.overflowing_add(carry);
        let result = result & mask;
        self.common_flags(result, size);
        self.state.rflags &= !(FLAG_CF | FLAG_AF | FLAG_OF);
        if carry1
            || carry2
            || u128::from(left & mask) + u128::from(right & mask) + u128::from(carry)
                > u128::from(mask)
        {
            self.state.rflags |= FLAG_CF;
        }
        if (left ^ right ^ result) & 0x10 != 0 {
            self.state.rflags |= FLAG_AF;
        }
        let sign = 1u64 << (size.bits() - 1);
        if (!(left ^ right) & (left ^ result) & sign) != 0 {
            self.state.rflags |= FLAG_OF;
        }
        result
    }

    fn sub_flags(&mut self, left: u64, right: u64, borrow: u64, size: OperandSize) -> u64 {
        let mask = size.mask();
        let result = left.wrapping_sub(right).wrapping_sub(borrow) & mask;
        self.common_flags(result, size);
        self.state.rflags &= !(FLAG_CF | FLAG_AF | FLAG_OF);
        if u128::from(left & mask) < u128::from(right & mask) + u128::from(borrow) {
            self.state.rflags |= FLAG_CF;
        }
        if (left ^ right ^ result) & 0x10 != 0 {
            self.state.rflags |= FLAG_AF;
        }
        let sign = 1u64 << (size.bits() - 1);
        if ((left ^ right) & (left ^ result) & sign) != 0 {
            self.state.rflags |= FLAG_OF;
        }
        result
    }

    fn logical_flags(&mut self, result: u64, size: OperandSize) {
        self.state.rflags &= !(FLAG_CF | FLAG_OF | FLAG_AF);
        self.common_flags(result, size);
    }

    fn common_flags(&mut self, result: u64, size: OperandSize) {
        self.state.rflags &= !(FLAG_ZF | FLAG_SF | FLAG_PF);
        let masked = result & size.mask();
        if masked == 0 {
            self.state.rflags |= FLAG_ZF;
        }
        if masked & (1u64 << (size.bits() - 1)) != 0 {
            self.state.rflags |= FLAG_SF;
        }
        if (masked as u8).count_ones().is_multiple_of(2) {
            self.state.rflags |= FLAG_PF;
        }
    }

    fn condition(&self, condition: Condition) -> bool {
        let cf = self.state.rflags & FLAG_CF != 0;
        let pf = self.state.rflags & FLAG_PF != 0;
        let zf = self.state.rflags & FLAG_ZF != 0;
        let sf = self.state.rflags & FLAG_SF != 0;
        let of = self.state.rflags & FLAG_OF != 0;
        match condition {
            Condition::Overflow => of,
            Condition::NotOverflow => !of,
            Condition::Below => cf,
            Condition::AboveOrEqual => !cf,
            Condition::Equal => zf,
            Condition::NotEqual => !zf,
            Condition::BelowOrEqual => cf || zf,
            Condition::Above => !cf && !zf,
            Condition::Sign => sf,
            Condition::NotSign => !sf,
            Condition::Parity => pf,
            Condition::NotParity => !pf,
            Condition::Less => sf != of,
            Condition::GreaterOrEqual => sf == of,
            Condition::LessOrEqual => zf || sf != of,
            Condition::Greater => !zf && sf == of,
        }
    }

    fn push(&mut self, bus: &mut MemoryBus, value: u64) -> Result<(), CpuFault> {
        let rsp = self.state.register(Register::Rsp).wrapping_sub(8);
        self.state.set_register(Register::Rsp, rsp);
        bus.write_linear(rsp, &value.to_le_bytes(), self.paging_context())?;
        Ok(())
    }

    fn pop(&mut self, bus: &mut MemoryBus) -> Result<u64, CpuFault> {
        let rsp = self.state.register(Register::Rsp);
        let mut bytes = [0u8; 8];
        bus.read_linear(rsp, &mut bytes, self.paging_context(), Access::Read)?;
        self.state.set_register(Register::Rsp, rsp.wrapping_add(8));
        Ok(u64::from_le_bytes(bytes))
    }

    fn branch_target(&self, bus: &mut MemoryBus, operand: Operand) -> Result<u64, CpuFault> {
        self.read_operand(bus, operand)
    }

    fn control(&self, index: u8) -> Result<u64, CpuFault> {
        match index {
            0 => Ok(self.state.cr0),
            2 => Ok(self.state.cr2),
            3 => Ok(self.state.cr3),
            4 => Ok(self.state.cr4),
            _ => Err(CpuFault::InvalidControlRegister(index)),
        }
    }

    fn set_control(&mut self, index: u8, value: u64) -> Result<(), CpuFault> {
        match index {
            0 => self.state.cr0 = value,
            2 => self.state.cr2 = value,
            3 => self.state.cr3 = value & 0x000F_FFFF_FFFF_FFFF,
            4 => self.state.cr4 = value,
            _ => return Err(CpuFault::InvalidControlRegister(index)),
        }
        Ok(())
    }

    fn segment(&self, index: u8) -> Result<u16, CpuFault> {
        match index {
            0 => Ok(self.state.es),
            1 => Ok(self.state.cs),
            2 => Ok(self.state.ss),
            3 => Ok(self.state.ds),
            4 => Ok(self.state.fs),
            5 => Ok(self.state.gs),
            _ => Err(CpuFault::InvalidOperand),
        }
    }

    fn set_segment(&mut self, index: u8, value: u16) -> Result<(), CpuFault> {
        match index {
            0 => self.state.es = value,
            2 => self.state.ss = value,
            3 => self.state.ds = value,
            4 => self.state.fs = value,
            5 => self.state.gs = value,
            _ => return Err(CpuFault::InvalidOperand),
        }
        Ok(())
    }

    fn cpuid(&mut self) {
        let leaf = self.state.register(Register::Rax) as u32;
        let subleaf = self.state.register(Register::Rcx) as u32;
        let (eax, ebx, ecx, edx): (u32, u32, u32, u32) = match (leaf, subleaf) {
            (0, _) => (0xD, 0x756E_6558, 0x6C65_746E, 0x6874_694E),
            (1, _) => (
                0x0006_0F01,
                (self.apic_id << 24) | (u32::from(self.processor_count.min(255)) << 16),
                (1 << 0) | (1 << 9) | (1 << 13) | (1 << 19) | (1 << 20) | (1 << 21),
                (1 << 4)
                    | (1 << 5)
                    | (1 << 6)
                    | (1 << 8)
                    | (1 << 9)
                    | (1 << 15)
                    | (1 << 16)
                    | (1 << 23)
                    | (1 << 24)
                    | (1 << 25)
                    | (1 << 26)
                    | (u32::from(self.processor_count > 1) << 28),
            ),
            (7, 0) => (0, 0, 0, 0),
            (0xB, 0) => (0, 1, 1 << 8, self.apic_id),
            (0xB, 1) => (
                u32::from(self.processor_count.next_power_of_two().trailing_zeros() as u16),
                u32::from(self.processor_count),
                (2 << 8) | 1,
                self.apic_id,
            ),
            (0xB, _) => (0, 0, subleaf, self.apic_id),
            (0xD, 0) => (0x3, 512, 512, 0),
            (0x8000_0000, _) => (0x8000_0008, 0, 0, 0),
            (0x8000_0001, _) => (0, 0, 0, (1 << 11) | (1 << 20) | (1 << 29)),
            (0x8000_0008, _) => (48 | (48 << 8), 0, 0, 0),
            _ => (0, 0, 0, 0),
        };
        self.state.set_register(Register::Rax, u64::from(eax));
        self.state.set_register(Register::Rbx, u64::from(ebx));
        self.state.set_register(Register::Rcx, u64::from(ecx));
        self.state.set_register(Register::Rdx, u64::from(edx));
    }

    fn rdmsr(&mut self, bus: &MemoryBus) {
        let index = self.state.register(Register::Rcx) as u32;
        let value = if index == IA32_EFER {
            self.state.efer
        } else if let Some(value) = bus.read_x2apic_msr(index) {
            value
        } else {
            self.msrs.get(&index).copied().unwrap_or(0)
        };
        self.state.set_register(Register::Rax, value as u32 as u64);
        self.state.set_register(Register::Rdx, value >> 32);
    }

    fn wrmsr(&mut self, bus: &mut MemoryBus) {
        let index = self.state.register(Register::Rcx) as u32;
        let value = (self.state.register(Register::Rdx) << 32)
            | (self.state.register(Register::Rax) & 0xFFFF_FFFF);
        if index == IA32_EFER {
            self.state.efer = value;
        }
        let _ = bus.write_x2apic_msr(index, value);
        self.msrs.insert(index, value);
    }

    fn syscall(&mut self) {
        self.state.set_register(Register::Rcx, self.state.rip);
        self.state.set_register(Register::R11, self.state.rflags);
        self.state.rflags &= !self.msrs.get(&IA32_FMASK).copied().unwrap_or(0);
        self.state.rip = self.msrs.get(&IA32_LSTAR).copied().unwrap_or(0);
        self.state.cs = (self.msrs.get(&IA32_STAR).copied().unwrap_or(0) >> 32) as u16 & !3;
    }

    fn sysret(&mut self) {
        self.state.rip = self.state.register(Register::Rcx);
        self.state.rflags = self.state.register(Register::R11) | 2;
        let star = self.msrs.get(&IA32_STAR).copied().unwrap_or(0);
        self.state.cs = (((star >> 48) as u16).wrapping_add(16)) | 3;
        self.state.ss = (((star >> 48) as u16).wrapping_add(8)) | 3;
    }

    fn swapgs(&mut self) {
        let user = self.msrs.get(&IA32_GS_BASE).copied().unwrap_or(0);
        let kernel = self.msrs.get(&IA32_KERNEL_GS_BASE).copied().unwrap_or(0);
        self.msrs.insert(IA32_GS_BASE, kernel);
        self.msrs.insert(IA32_KERNEL_GS_BASE, user);
    }

    fn load_descriptor_table(
        &mut self,
        bus: &mut MemoryBus,
        mnemonic: Mnemonic,
        operand: Option<Operand>,
    ) -> Result<(), CpuFault> {
        let Some(Operand::Memory(memory)) = operand else {
            return Err(CpuFault::InvalidOperand);
        };
        let mut bytes = [0u8; 10];
        bus.read_linear(
            self.effective_address(memory),
            &mut bytes,
            self.paging_context(),
            Access::Read,
        )?;
        let table = DescriptorTable {
            limit: u16::from_le_bytes(bytes[..2].try_into().expect("two bytes")),
            base: u64::from_le_bytes(bytes[2..].try_into().expect("eight bytes")),
        };
        if mnemonic == Mnemonic::Lgdt {
            self.state.gdtr = table;
        } else {
            self.state.idtr = table;
        }
        Ok(())
    }

    fn deliver_interrupt(&mut self, bus: &mut MemoryBus, vector: u8) -> Result<(), CpuFault> {
        let gate = self.read_interrupt_gate(bus, vector)?;
        let target_cpl = self.validate_interrupt_code_segment(bus, vector, gate.selector)?;
        let current_cpl = (self.state.cs & 3) as u8;
        if target_cpl > current_cpl {
            return Err(CpuFault::InvalidInterruptGate {
                vector,
                reason: "interrupt gate cannot transfer to a less privileged segment",
            });
        }
        let old_rip = self.state.rip;
        let old_cs = self.state.cs;
        let old_rflags = self.state.rflags;
        let old_rsp = self.state.register(Register::Rsp);
        let old_ss = self.state.ss;
        let changes_privilege = target_cpl < current_cpl;
        let stack_top = if gate.ist != 0 {
            self.read_tss_ist(bus, gate.ist)?
        } else if changes_privilege {
            if target_cpl != 0 {
                return Err(CpuFault::InvalidInterruptGate {
                    vector,
                    reason: "only CPL0 interrupt targets are implemented",
                });
            }
            self.read_tss_rsp0(bus)?
        } else {
            old_rsp
        } & !0x0f;

        // Long-mode interrupts always save SS:RSP, including same-CPL and IST
        // entries. The selected stack is 16-byte aligned before the five
        // eight-byte frame values are pushed.
        const FRAME_BYTES: usize = 5 * 8;
        let frame_rsp = stack_top
            .checked_sub(FRAME_BYTES as u64)
            .ok_or(CpuFault::InvalidTaskState("interrupt stack underflow"))?;
        let mut frame = [0u8; 40];
        frame[0..8].copy_from_slice(&old_rip.to_le_bytes());
        frame[8..16].copy_from_slice(&u64::from(old_cs).to_le_bytes());
        frame[16..24].copy_from_slice(&old_rflags.to_le_bytes());
        frame[24..32].copy_from_slice(&old_rsp.to_le_bytes());
        frame[32..40].copy_from_slice(&u64::from(old_ss).to_le_bytes());
        bus.write_linear(
            frame_rsp,
            &frame[..FRAME_BYTES],
            self.supervisor_paging_context(),
        )?;

        self.state.set_register(Register::Rsp, frame_rsp);
        self.state.cs = (gate.selector & !3) | u16::from(target_cpl);
        if changes_privilege {
            // IA-32e privilege-changing interrupt entry loads a null SS.
            // The prior user SS remains in the IRET frame above.
            self.state.ss = 0;
        }
        self.state.rip = gate.offset;
        if gate.gate_type == 0x0E {
            self.state.rflags &= !FLAG_IF;
        }
        self.state.halted = false;
        self.interrupts_delivered = self.interrupts_delivered.saturating_add(1);
        Ok(())
    }

    fn read_interrupt_gate(
        &self,
        bus: &mut MemoryBus,
        vector: u8,
    ) -> Result<InterruptGate, CpuFault> {
        let offset = u64::from(vector) * IDT_ENTRY_SIZE;
        if offset + IDT_ENTRY_SIZE - 1 > u64::from(self.state.idtr.limit) {
            return Err(CpuFault::InvalidInterruptGate {
                vector,
                reason: "vector exceeds the IDT limit",
            });
        }
        let mut bytes = [0u8; IDT_ENTRY_SIZE as usize];
        bus.read_linear(
            self.state.idtr.base.wrapping_add(offset),
            &mut bytes,
            self.supervisor_paging_context(),
            Access::Read,
        )?;
        let selector = u16::from_le_bytes(bytes[2..4].try_into().expect("two bytes"));
        let ist = bytes[4] & 7;
        let attributes = bytes[5];
        let gate_type = attributes & 0x0F;
        if bytes[4] & !7 != 0 || bytes[12..16] != [0; 4] {
            return Err(CpuFault::InvalidInterruptGate {
                vector,
                reason: "reserved gate bits are non-zero",
            });
        }
        if attributes & 0x80 == 0 {
            return Err(CpuFault::InvalidInterruptGate {
                vector,
                reason: "gate is not present",
            });
        }
        if attributes & 0x10 != 0 || !matches!(gate_type, 0x0E | 0x0F) {
            return Err(CpuFault::InvalidInterruptGate {
                vector,
                reason: "gate is not a 64-bit interrupt or trap gate",
            });
        }
        if selector & !3 == 0 {
            return Err(CpuFault::InvalidInterruptGate {
                vector,
                reason: "gate has a null code selector",
            });
        }
        let offset_low = u64::from(u16::from_le_bytes(
            bytes[0..2].try_into().expect("two bytes"),
        ));
        let offset_middle = u64::from(u16::from_le_bytes(
            bytes[6..8].try_into().expect("two bytes"),
        ));
        let offset_high = u64::from(u32::from_le_bytes(
            bytes[8..12].try_into().expect("four bytes"),
        ));
        let handler = offset_low | (offset_middle << 16) | (offset_high << 32);
        if !is_canonical(handler) {
            return Err(CpuFault::InvalidInterruptGate {
                vector,
                reason: "handler address is not canonical",
            });
        }
        Ok(InterruptGate {
            offset: handler,
            selector,
            ist,
            gate_type,
        })
    }

    fn validate_interrupt_code_segment(
        &self,
        bus: &mut MemoryBus,
        vector: u8,
        selector: u16,
    ) -> Result<u8, CpuFault> {
        if selector & 4 != 0 {
            return Err(CpuFault::InvalidInterruptGate {
                vector,
                reason: "LDT code selectors are not implemented",
            });
        }
        let offset = u64::from(selector & !7);
        if offset + GDT_ENTRY_SIZE - 1 > u64::from(self.state.gdtr.limit) {
            return Err(CpuFault::InvalidInterruptGate {
                vector,
                reason: "code selector exceeds the GDT limit",
            });
        }
        let mut descriptor = [0u8; GDT_ENTRY_SIZE as usize];
        bus.read_linear(
            self.state.gdtr.base.wrapping_add(offset),
            &mut descriptor,
            self.supervisor_paging_context(),
            Access::Read,
        )?;
        let access = descriptor[5];
        let flags = descriptor[6];
        if access & 0x80 == 0
            || access & 0x10 == 0
            || access & 0x08 == 0
            || flags & 0x20 == 0
            || flags & 0x40 != 0
        {
            return Err(CpuFault::InvalidInterruptGate {
                vector,
                reason: "selector does not name a present 64-bit code segment",
            });
        }
        Ok((access >> 5) & 3)
    }

    fn read_tss_rsp0(&self, bus: &mut MemoryBus) -> Result<u64, CpuFault> {
        self.read_tss_stack_pointer(
            bus,
            TSS_RSP0_OFFSET,
            "TSS limit excludes RSP0",
            "TSS RSP0 is zero or non-canonical",
        )
    }

    fn read_tss_ist(&self, bus: &mut MemoryBus, ist: u8) -> Result<u64, CpuFault> {
        debug_assert!((1..=7).contains(&ist));
        let offset = TSS_IST1_OFFSET + u64::from(ist - 1) * 8;
        self.read_tss_stack_pointer(
            bus,
            offset,
            "TSS limit excludes the selected IST pointer",
            "TSS IST pointer is zero or non-canonical",
        )
    }

    fn read_tss_stack_pointer(
        &self,
        bus: &mut MemoryBus,
        offset: u64,
        limit_reason: &'static str,
        invalid_pointer_reason: &'static str,
    ) -> Result<u64, CpuFault> {
        let selector = self.state.tr;
        if selector & !7 == 0 || selector & 4 != 0 {
            return Err(CpuFault::InvalidTaskState(
                "task register does not select a GDT TSS descriptor",
            ));
        }
        let descriptor_offset = u64::from(selector & !7);
        if descriptor_offset + 15 > u64::from(self.state.gdtr.limit) {
            return Err(CpuFault::InvalidTaskState(
                "TSS descriptor exceeds the GDT limit",
            ));
        }
        let mut descriptor = [0u8; 16];
        bus.read_linear(
            self.state.gdtr.base.wrapping_add(descriptor_offset),
            &mut descriptor,
            self.supervisor_paging_context(),
            Access::Read,
        )?;
        let access = descriptor[5];
        let descriptor_type = access & 0x0F;
        if access & 0x80 == 0 || access & 0x10 != 0 || !matches!(descriptor_type, 0x09 | 0x0B) {
            return Err(CpuFault::InvalidTaskState(
                "task register does not name a present 64-bit TSS",
            ));
        }
        let limit = u64::from(u16::from_le_bytes(
            descriptor[0..2].try_into().expect("two bytes"),
        )) | (u64::from(descriptor[6] & 0x0F) << 16);
        if limit < offset + 7 {
            return Err(CpuFault::InvalidTaskState(limit_reason));
        }
        let base = u64::from(u16::from_le_bytes(
            descriptor[2..4].try_into().expect("two bytes"),
        )) | (u64::from(descriptor[4]) << 16)
            | (u64::from(descriptor[7]) << 24)
            | (u64::from(u32::from_le_bytes(
                descriptor[8..12].try_into().expect("four bytes"),
            )) << 32);
        let mut rsp = [0u8; 8];
        bus.read_linear(
            base.wrapping_add(offset),
            &mut rsp,
            self.supervisor_paging_context(),
            Access::Read,
        )?;
        let pointer = u64::from_le_bytes(rsp);
        if pointer == 0 || !is_canonical(pointer) {
            return Err(CpuFault::InvalidTaskState(invalid_pointer_reason));
        }
        Ok(pointer)
    }

    fn iretq(&mut self, bus: &mut MemoryBus) -> Result<(), CpuFault> {
        let rip = self.pop(bus)?;
        let cs = self.pop(bus)? as u16;
        let rflags = self.pop(bus)? | 2;
        // IRETQ in 64-bit mode unconditionally restores SS:RSP because the
        // matching interrupt entry unconditionally saved them.
        let rsp = self.pop(bus)?;
        let ss = self.pop(bus)? as u16;
        self.state.rip = rip;
        self.state.cs = cs;
        self.state.rflags = rflags;
        self.state.ss = ss;
        self.state.set_register(Register::Rsp, rsp);
        Ok(())
    }

    fn privilege(&self) -> Privilege {
        if self.state.cs & 3 == 3 {
            Privilege::User
        } else {
            Privilege::Supervisor
        }
    }

    fn paging_context(&self) -> PagingContext {
        PagingContext::new(
            self.state.cr0,
            self.state.cr3,
            self.state.efer,
            self.privilege(),
        )
    }

    fn supervisor_paging_context(&self) -> PagingContext {
        PagingContext::new(
            self.state.cr0,
            self.state.cr3,
            self.state.efer,
            Privilege::Supervisor,
        )
    }
}

fn initial_fx_state() -> [u8; FXSAVE_SIZE] {
    let mut image = [0_u8; FXSAVE_SIZE];
    image[..2].copy_from_slice(&0x037f_u16.to_le_bytes());
    image[24..28].copy_from_slice(&0x1f80_u32.to_le_bytes());
    image[28..32].copy_from_slice(&MXCSR_MASK.to_le_bytes());
    image
}

#[derive(Clone, Copy, Debug)]
struct InterruptGate {
    offset: u64,
    selector: u16,
    ist: u8,
    gate_type: u8,
}

fn is_canonical(address: u64) -> bool {
    let upper = address >> 48;
    if address & (1 << 47) == 0 {
        upper == 0
    } else {
        upper == 0xFFFF
    }
}

fn sign_extend(value: u64, size: OperandSize) -> u64 {
    match size {
        OperandSize::Byte => (value as i8 as i64) as u64,
        OperandSize::Word => (value as i16 as i64) as u64,
        OperandSize::Dword => (value as i32 as i64) as u64,
        OperandSize::Qword | OperandSize::Oword => value,
    }
}

fn signed_operand(value: u64, size: OperandSize) -> i128 {
    match size {
        OperandSize::Byte => i128::from(value as i8),
        OperandSize::Word => i128::from(value as i16),
        OperandSize::Dword => i128::from(value as i32),
        OperandSize::Qword | OperandSize::Oword => i128::from(value as i64),
    }
}

fn rotate_left(value: u64, size: OperandSize, count: u32) -> u64 {
    match size {
        OperandSize::Byte => u64::from((value as u8).rotate_left(count)),
        OperandSize::Word => u64::from((value as u16).rotate_left(count)),
        OperandSize::Dword => u64::from((value as u32).rotate_left(count)),
        OperandSize::Qword | OperandSize::Oword => value.rotate_left(count),
    }
}

fn rotate_right(value: u64, size: OperandSize, count: u32) -> u64 {
    match size {
        OperandSize::Byte => u64::from((value as u8).rotate_right(count)),
        OperandSize::Word => u64::from((value as u16).rotate_right(count)),
        OperandSize::Dword => u64::from((value as u32).rotate_right(count)),
        OperandSize::Qword | OperandSize::Oword => value.rotate_right(count),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Device;

    const PRESENT: u64 = 1;
    const WRITABLE: u64 = 1 << 1;
    const USER: u64 = 1 << 2;
    const TEST_TSS_BASE: u64 = 0x2000;
    const TEST_IDT_BASE: u64 = 0x3000;

    struct DelayedInterrupt {
        remaining: u64,
        vector: u8,
        pending: bool,
    }

    #[test]
    fn cpuid_reports_per_processor_apic_identity_and_topology() {
        let mut cpu = Cpu::new_with_topology(1, 2, false);
        cpu.state.set_register(Register::Rax, 1);
        cpu.state.set_register(Register::Rcx, 0);
        cpu.cpuid();
        assert_eq!(cpu.state.register(Register::Rbx) >> 24, 1);
        assert_eq!((cpu.state.register(Register::Rbx) >> 16) & 0xff, 2);
        assert_ne!(cpu.state.register(Register::Rcx) & (1 << 21), 0);
        assert_ne!(cpu.state.register(Register::Rdx) & (1 << 9), 0);
        assert_ne!(cpu.state.register(Register::Rdx) & (1 << 16), 0);
        assert_eq!(cpu.msrs.get(&IA32_PAT), Some(&0x0007_0406_0007_0406));

        cpu.state.set_register(Register::Rax, 0xB);
        cpu.state.set_register(Register::Rcx, 1);
        cpu.cpuid();
        assert_eq!(cpu.state.register(Register::Rbx), 2);
        assert_eq!(cpu.state.register(Register::Rdx), 1);
    }

    impl Device for DelayedInterrupt {
        fn name(&self) -> &'static str {
            "test interrupt pulse"
        }

        fn tick(&mut self, cycles: u64) {
            if self.pending || self.remaining == 0 {
                return;
            }
            self.remaining = self.remaining.saturating_sub(cycles);
            if self.remaining == 0 {
                self.pending = true;
            }
        }

        fn interrupt(&mut self) -> Option<u8> {
            self.pending.then(|| {
                self.pending = false;
                self.vector
            })
        }
    }

    fn install_interrupt_tables(
        cpu: &mut Cpu,
        bus: &mut MemoryBus,
        vector: u8,
        handler: u64,
        rsp0: u64,
    ) {
        const GDT_BASE: u64 = 0x1000;
        let kernel_code = [0xff, 0xff, 0, 0, 0, 0x9b, 0xaf, 0];
        bus.write_physical(GDT_BASE + 8, &kernel_code)
            .expect("install kernel code descriptor");

        let mut tss_descriptor = [0u8; 16];
        tss_descriptor[0..2].copy_from_slice(&0x67u16.to_le_bytes());
        tss_descriptor[2..4].copy_from_slice(&(TEST_TSS_BASE as u16).to_le_bytes());
        tss_descriptor[4] = (TEST_TSS_BASE >> 16) as u8;
        tss_descriptor[5] = 0x89;
        tss_descriptor[7] = (TEST_TSS_BASE >> 24) as u8;
        tss_descriptor[8..12].copy_from_slice(&((TEST_TSS_BASE >> 32) as u32).to_le_bytes());
        bus.write_physical(GDT_BASE + 0x18, &tss_descriptor)
            .expect("install TSS descriptor");
        bus.write_physical(TEST_TSS_BASE + TSS_RSP0_OFFSET, &rsp0.to_le_bytes())
            .expect("install TSS RSP0");

        let mut gate = [0u8; 16];
        gate[0..2].copy_from_slice(&(handler as u16).to_le_bytes());
        gate[2..4].copy_from_slice(&8u16.to_le_bytes());
        gate[5] = 0x8e;
        gate[6..8].copy_from_slice(&((handler >> 16) as u16).to_le_bytes());
        gate[8..12].copy_from_slice(&((handler >> 32) as u32).to_le_bytes());
        bus.write_physical(TEST_IDT_BASE + u64::from(vector) * IDT_ENTRY_SIZE, &gate)
            .expect("install interrupt gate");

        cpu.state.gdtr = DescriptorTable {
            base: GDT_BASE,
            limit: 0x27,
        };
        cpu.state.idtr = DescriptorTable {
            base: TEST_IDT_BASE,
            limit: u16::from(vector) * IDT_ENTRY_SIZE as u16 + 15,
        };
        cpu.state.tr = 0x18;
    }

    fn user_paged_cpu(program: &[u8], user_code: bool) -> (Cpu, MemoryBus) {
        let mut bus = MemoryBus::new(0x7000);
        for (entry_address, next_table) in [(0x1000, 0x2000), (0x2000, 0x3000), (0x3000, 0x4000)] {
            bus.write_u64_physical(entry_address, next_table | PRESENT | WRITABLE | USER)
                .expect("install user page-table level");
        }
        let code_flags = PRESENT | WRITABLE | if user_code { USER } else { 0 };
        bus.write_u64_physical(0x4000, 0x5000 | code_flags)
            .expect("map code page");
        bus.write_u64_physical(0x4008, 0x6000 | PRESENT | WRITABLE)
            .expect("map supervisor data page");
        bus.write_physical(0x5000, program)
            .expect("load user test program");

        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.cs = 3;
        cpu.state.cr0 |= 1 << 31;
        cpu.state.cr3 = 0x1000;
        (cpu, bus)
    }

    #[test]
    fn cpl3_fetch_cannot_execute_a_supervisor_page() {
        let (mut cpu, mut bus) = user_paged_cpu(&[0xf4], false);

        assert_eq!(
            cpu.step(&mut bus),
            Err(CpuFault::Memory(MemoryError::PageFault {
                address: 0,
                access: Access::Execute,
                reason: "supervisor-only",
            }))
        );
    }

    #[test]
    fn cpl3_load_cannot_read_a_supervisor_page() {
        let (mut cpu, mut bus) = user_paged_cpu(
            &[
                0x48, 0xbb, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, 0x1000
                0x48, 0x8b, 0x03, // mov rax, [rbx]
                0xf4,
            ],
            true,
        );

        assert_eq!(
            cpu.run(&mut bus, 3),
            ExitReason::Fault(CpuFault::Memory(MemoryError::PageFault {
                address: 0x1000,
                access: Access::Read,
                reason: "supervisor-only",
            }))
        );
    }

    #[test]
    fn cpl3_store_cannot_write_a_supervisor_page() {
        let (mut cpu, mut bus) = user_paged_cpu(
            &[
                0x48, 0xbb, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, 0x1000
                0x48, 0x89, 0x03, // mov [rbx], rax
                0xf4,
            ],
            true,
        );

        assert_eq!(
            cpu.run(&mut bus, 3),
            ExitReason::Fault(CpuFault::Memory(MemoryError::PageFault {
                address: 0x1000,
                access: Access::Write,
                reason: "supervisor-only",
            }))
        );
    }

    #[test]
    fn bare_rex_byte_write_targets_sil() {
        let mut bus = MemoryBus::new(0x1000);
        bus.write_physical(0, &[0x40, 0xb6, 0x02, 0xf4])
            .expect("load test program");
        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.set_register(Register::Rsi, 0xabcd);

        assert_eq!(cpu.run(&mut bus, 2), ExitReason::Halted);
        assert_eq!(cpu.state.register(Register::Rsi), 0xab02);
    }

    #[test]
    fn legacy_high_byte_read_uses_rax_for_ah() {
        let mut bus = MemoryBus::new(0x1000);
        bus.write_physical(0, &[0x0f, 0xb6, 0xcc, 0xf4])
            .expect("load test program");
        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.set_register(Register::Rax, 0x1234);
        cpu.state.set_register(Register::Rsp, 0xab00);

        assert_eq!(cpu.run(&mut bus, 2), ExitReason::Halted);
        assert_eq!(cpu.state.register(Register::Rcx), 0x12);
    }

    #[test]
    fn cdqe_sign_extends_eax_into_rax() {
        let mut bus = MemoryBus::new(0x1000);
        bus.write_physical(0, &[0x48, 0x98, 0xf4])
            .expect("load test program");
        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.set_register(Register::Rax, 0x8000_0001);

        assert_eq!(cpu.run(&mut bus, 2), ExitReason::Halted);
        assert_eq!(cpu.state.register(Register::Rax), 0xffff_ffff_8000_0001);
    }

    #[test]
    fn bswap_supports_dword_zero_extension_and_rex_w_qword() {
        let mut bus = MemoryBus::new(0x1000);
        bus.write_physical(0, &[0x0f, 0xca, 0x49, 0x0f, 0xc8, 0xf4])
            .expect("load test program");
        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.set_register(Register::Rdx, 0xffff_ffff_1122_3344);
        cpu.state.set_register(Register::R8, 0x1122_3344_5566_7788);

        assert_eq!(cpu.run(&mut bus, 3), ExitReason::Halted);
        assert_eq!(cpu.state.register(Register::Rdx), 0x4433_2211);
        assert_eq!(cpu.state.register(Register::R8), 0x8877_6655_4433_2211);
    }

    #[test]
    fn register_form_btr_and_bts_update_the_bit_and_carry() {
        let mut bus = MemoryBus::new(0x1000);
        bus.write_physical(0, &[0x49, 0x0F, 0xB3, 0xCE, 0x49, 0x0F, 0xAB, 0xCE, 0xF4])
            .expect("load test program");
        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.set_register(Register::R14, 1 << 3);
        cpu.state.set_register(Register::Rcx, 3);

        assert_eq!(cpu.step(&mut bus), Ok(None));
        assert_eq!(cpu.state.register(Register::R14), 0);
        assert_ne!(cpu.state.rflags & FLAG_CF, 0);

        assert_eq!(cpu.step(&mut bus), Ok(None));
        assert_eq!(cpu.state.register(Register::R14), 1 << 3);
        assert_eq!(cpu.state.rflags & FLAG_CF, 0);
    }

    #[test]
    fn shld_qword_immediate_executes_the_explorer_faulting_sequence() {
        let mut bus = MemoryBus::new(0x1000);
        bus.write_physical(0, &[0x48, 0x0f, 0xa4, 0xfa, 0x20, 0xf4])
            .expect("load SHLD test program");
        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.set_register(Register::Rdx, 0x0123_4567_89ab_cdef);
        cpu.state.set_register(Register::Rdi, 0xfedc_ba98_7654_3210);

        assert_eq!(cpu.run(&mut bus, 2), ExitReason::Halted);
        assert_eq!(cpu.state.register(Register::Rdx), 0x89ab_cdef_fedc_ba98);
        assert_eq!(cpu.state.register(Register::Rdi), 0xfedc_ba98_7654_3210);
        assert_ne!(cpu.state.rflags & FLAG_CF, 0);
        assert_ne!(cpu.state.rflags & FLAG_SF, 0);
        assert_eq!(cpu.state.rflags & (FLAG_ZF | FLAG_PF), 0);
    }

    #[test]
    fn shld_masks_a_qword_count_to_zero_without_touching_flags() {
        let mut bus = MemoryBus::new(0x1000);
        bus.write_physical(0, &[0x48, 0x0f, 0xa4, 0xfa, 0x40])
            .expect("load zero-count SHLD test program");
        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.set_register(Register::Rdx, 0x0123_4567_89ab_cdef);
        cpu.state.set_register(Register::Rdi, u64::MAX);
        cpu.state.rflags = 2 | FLAG_CF | FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF;
        let flags = cpu.state.rflags;

        assert_eq!(cpu.step(&mut bus), Ok(None));
        assert_eq!(cpu.state.register(Register::Rdx), 0x0123_4567_89ab_cdef);
        assert_eq!(cpu.state.rflags, flags);
    }

    #[test]
    fn shld_count_one_updates_defined_flags() {
        let mut bus = MemoryBus::new(0x1000);
        bus.write_physical(0, &[0x48, 0x0f, 0xa4, 0xfa, 0x01])
            .expect("load one-bit SHLD test program");
        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.set_register(Register::Rdx, 0x4000_0000_0000_0000);
        cpu.state.set_register(Register::Rdi, 0x8000_0000_0000_0000);
        cpu.state.rflags = 2 | FLAG_CF | FLAG_PF | FLAG_AF | FLAG_ZF;

        assert_eq!(cpu.step(&mut bus), Ok(None));
        assert_eq!(cpu.state.register(Register::Rdx), 0x8000_0000_0000_0001);
        assert_eq!(cpu.state.rflags & FLAG_CF, 0);
        assert_ne!(cpu.state.rflags & FLAG_OF, 0);
        assert_ne!(cpu.state.rflags & FLAG_SF, 0);
        assert_eq!(cpu.state.rflags & (FLAG_ZF | FLAG_PF), 0);
        assert_ne!(cpu.state.rflags & FLAG_AF, 0);
    }

    #[test]
    fn shld_writes_dword_and_word_destinations_with_x86_register_rules() {
        let mut bus = MemoryBus::new(0x1000);
        bus.write_physical(0, &[
            0x0f, 0xa4, 0xfa, 0x08, // shld edx, edi, 8
            0x66, 0x0f, 0xa4, 0xfa, 0x04, // shld dx, di, 4
        ])
        .expect("load sized SHLD test program");
        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.set_register(Register::Rdx, 0xffff_ffff_8123_4567);
        cpu.state.set_register(Register::Rdi, 0x89ab_cdef);

        assert_eq!(cpu.step(&mut bus), Ok(None));
        assert_eq!(cpu.state.register(Register::Rdx), 0x2345_6789);

        cpu.state.set_register(Register::Rdx, 0xaaaa_bbbb_cccc_1234);
        cpu.state.set_register(Register::Rdi, 0xabcd);
        assert_eq!(cpu.step(&mut bus), Ok(None));
        assert_eq!(cpu.state.register(Register::Rdx), 0xaaaa_bbbb_cccc_234a);
    }

    #[test]
    fn dec_sets_zero_for_a_following_equal_branch() {
        let mut bus = MemoryBus::new(0x1000);
        bus.write_physical(0, &[
            0xbf, 1, 0, 0, 0, 0xff, 0xcf, 0x74, 2, 0xb0, 0xff, 0xf4,
        ])
        .expect("load test program");
        let mut cpu = Cpu::new();
        cpu.state.rip = 0;

        assert_eq!(cpu.run(&mut bus, 5), ExitReason::Halted);
        assert_eq!(cpu.state.register(Register::Rdi), 0);
        assert_eq!(cpu.state.register(Register::Rax), 0);
    }

    #[test]
    fn gs_override_uses_the_active_gs_base() {
        let mut bus = MemoryBus::new(0x2000);
        bus.write_physical(0, &[
            0x65, 0x48, 0x89, 0x04, 0x25, 0x88, 0, 0, 0, 0x0f, 0xae, 0xe8, 0xf4,
        ])
        .expect("load test program");
        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.set_register(Register::Rax, 0x1122_3344_5566_7788);
        cpu.msrs.insert(IA32_GS_BASE, 0x1000);

        assert_eq!(cpu.run(&mut bus, 3), ExitReason::Halted);
        assert_eq!(
            bus.read_u64_physical(0x1088).expect("GS-relative result"),
            0x1122_3344_5566_7788
        );
    }

    #[test]
    fn cpl3_interrupt_uses_tss_rsp0_and_iret_restores_user_frame() {
        const VECTOR: u8 = 0x40;
        const HANDLER: u64 = 0x4000;
        const KERNEL_RSP0: u64 = 0x7000;
        let mut bus = MemoryBus::new(0x8000);
        bus.write_physical(HANDLER, &[0x48, 0xcf])
            .expect("install IRETQ handler");
        let mut cpu = Cpu::new();
        install_interrupt_tables(&mut cpu, &mut bus, VECTOR, HANDLER, KERNEL_RSP0);
        cpu.state.rip = 0x1234;
        cpu.state.cs = 0x2b;
        cpu.state.ss = 0x33;
        cpu.state.rflags = FLAG_IF | 2;
        cpu.state.set_register(Register::Rsp, 0x6000);
        cpu.state.halted = true;

        cpu.deliver_interrupt(&mut bus, VECTOR)
            .expect("deliver CPL3 interrupt");

        assert_eq!(cpu.state.rip, HANDLER);
        assert_eq!(cpu.state.cs, 8);
        assert_eq!(cpu.state.ss, 0);
        assert_eq!(cpu.state.register(Register::Rsp), KERNEL_RSP0 - 40);
        assert_eq!(cpu.state.rflags & FLAG_IF, 0);
        assert!(!cpu.state.halted);
        assert_eq!(cpu.interrupts_delivered(), 1);
        let frame = KERNEL_RSP0 - 40;
        assert_eq!(bus.read_u64_physical(frame).expect("saved RIP"), 0x1234);
        assert_eq!(bus.read_u64_physical(frame + 8).expect("saved CS"), 0x2b);
        assert_eq!(
            bus.read_u64_physical(frame + 16).expect("saved RFLAGS"),
            FLAG_IF | 2
        );
        assert_eq!(
            bus.read_u64_physical(frame + 24).expect("saved RSP"),
            0x6000
        );
        assert_eq!(bus.read_u64_physical(frame + 32).expect("saved SS"), 0x33);

        assert_eq!(cpu.step(&mut bus), Ok(None));
        assert_eq!(cpu.state.rip, 0x1234);
        assert_eq!(cpu.state.cs, 0x2b);
        assert_eq!(cpu.state.ss, 0x33);
        assert_eq!(cpu.state.rflags, FLAG_IF | 2);
        assert_eq!(cpu.state.register(Register::Rsp), 0x6000);
    }

    #[test]
    fn same_cpl_ist_interrupt_switches_stacks_and_iret_restores_the_full_frame() {
        const VECTOR: u8 = 0x41;
        const HANDLER: u64 = 0x4000;
        const IST1: u64 = 0x8017;
        const OLD_RSP: u64 = 0x6017;
        let mut bus = MemoryBus::new(0x9000);
        bus.write_physical(HANDLER, &[0x48, 0xcf])
            .expect("install IRETQ handler");
        let mut cpu = Cpu::new();
        install_interrupt_tables(&mut cpu, &mut bus, VECTOR, HANDLER, 0x7000);
        bus.write_physical(TEST_TSS_BASE + TSS_IST1_OFFSET, &IST1.to_le_bytes())
            .expect("install TSS IST1");
        bus.write_physical(TEST_IDT_BASE + u64::from(VECTOR) * IDT_ENTRY_SIZE + 4, &[1])
            .expect("select IST1 in interrupt gate");
        cpu.state.rip = 0x1234;
        cpu.state.cs = 8;
        cpu.state.ss = 0x10;
        cpu.state.rflags = FLAG_IF | 2;
        cpu.state.set_register(Register::Rsp, OLD_RSP);

        cpu.deliver_interrupt(&mut bus, VECTOR)
            .expect("deliver IST interrupt");

        let frame = (IST1 & !0x0f) - 40;
        assert_eq!(cpu.state.rip, HANDLER);
        assert_eq!(cpu.state.cs, 8);
        assert_eq!(cpu.state.ss, 0x10);
        assert_eq!(cpu.state.register(Register::Rsp), frame);
        assert_eq!(bus.read_u64_physical(frame).expect("saved RIP"), 0x1234);
        assert_eq!(bus.read_u64_physical(frame + 8).expect("saved CS"), 8);
        assert_eq!(
            bus.read_u64_physical(frame + 16).expect("saved RFLAGS"),
            FLAG_IF | 2
        );
        assert_eq!(
            bus.read_u64_physical(frame + 24).expect("saved RSP"),
            OLD_RSP
        );
        assert_eq!(bus.read_u64_physical(frame + 32).expect("saved SS"), 0x10);

        assert_eq!(cpu.step(&mut bus), Ok(None));
        assert_eq!(cpu.state.rip, 0x1234);
        assert_eq!(cpu.state.cs, 8);
        assert_eq!(cpu.state.ss, 0x10);
        assert_eq!(cpu.state.rflags, FLAG_IF | 2);
        assert_eq!(cpu.state.register(Register::Rsp), OLD_RSP);
    }

    #[test]
    fn ist_interrupt_rejects_a_zero_tss_pointer() {
        const VECTOR: u8 = 0x41;
        let mut bus = MemoryBus::new(0x9000);
        let mut cpu = Cpu::new();
        install_interrupt_tables(&mut cpu, &mut bus, VECTOR, 0x4000, 0x7000);
        bus.write_physical(TEST_IDT_BASE + u64::from(VECTOR) * IDT_ENTRY_SIZE + 4, &[1])
            .expect("select empty IST1 in interrupt gate");
        cpu.state.rip = 0x1234;
        cpu.state.cs = 8;
        cpu.state.ss = 0x10;
        cpu.state.set_register(Register::Rsp, 0x6000);

        assert_eq!(
            cpu.deliver_interrupt(&mut bus, VECTOR),
            Err(CpuFault::InvalidTaskState(
                "TSS IST pointer is zero or non-canonical"
            ))
        );
    }

    #[test]
    fn interruptible_hlt_resumes_after_a_pending_interrupt() {
        const VECTOR: u8 = 0x40;
        const HANDLER: u64 = 0x4000;
        let mut bus = MemoryBus::new(0x8000);
        bus.write_physical(0, &[0xfb, 0xf4, 0xb8, 42, 0, 0, 0, 0xfa, 0xf4])
            .expect("install HLT test program");
        bus.write_physical(HANDLER, &[0x48, 0xcf])
            .expect("install IRETQ handler");
        bus.attach(DelayedInterrupt {
            remaining: 2,
            vector: VECTOR,
            pending: false,
        });
        let mut cpu = Cpu::new();
        install_interrupt_tables(&mut cpu, &mut bus, VECTOR, HANDLER, 0x7000);
        cpu.state.rip = 0;
        cpu.state.cs = 8;
        cpu.state.ss = 0x10;
        cpu.state.set_register(Register::Rsp, 0x7000);

        assert_eq!(cpu.run(&mut bus, 10), ExitReason::Halted);
        assert_eq!(cpu.state.register(Register::Rax), 42);
        assert_eq!(cpu.state.rip, 9);
        assert_eq!(cpu.interrupts_delivered(), 1);
    }

    #[test]
    fn clts_is_cpl0_only_and_clears_only_cr0_ts() {
        let mut bus = MemoryBus::new(0x1000);
        bus.write_physical(0, &[0x0f, 0x06]).unwrap();
        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.cs = 8;
        cpu.state.cr0 |= CR0_TS;
        let before = cpu.state.cr0;
        assert_eq!(cpu.step(&mut bus), Ok(None));
        assert_eq!(cpu.state.cr0, before & !CR0_TS);

        cpu.state.rip = 0;
        cpu.state.cs = 0x2b;
        cpu.state.cr0 |= CR0_TS;
        assert_eq!(
            cpu.step(&mut bus),
            Err(CpuFault::GeneralProtection("CLTS requires CPL0"))
        );
        assert_ne!(cpu.state.cr0 & CR0_TS, 0);
    }

    #[test]
    fn wbinvd_is_cpl0_only() {
        let mut bus = MemoryBus::new(0x1000);
        bus.write_physical(0, &[0x0f, 0x09]).unwrap();
        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.cs = 8;
        assert_eq!(cpu.step(&mut bus), Ok(None));

        cpu.state.rip = 0;
        cpu.state.cs = 0x2b;
        assert_eq!(
            cpu.step(&mut bus),
            Err(CpuFault::GeneralProtection("WBINVD requires CPL0"))
        );
    }

    #[test]
    fn fxrstor_and_fxsave_round_trip_the_legacy_state_image() {
        let mut bus = MemoryBus::new(0x6000);
        // clts; fxrstor [rsi]; fxsave [rdi]; hlt
        bus.write_physical(0, &[0x0f, 0x06, 0x0f, 0xae, 0x0e, 0x0f, 0xae, 0x07, 0xf4])
            .unwrap();
        let mut input = initial_fx_state();
        input[24..28].copy_from_slice(&0x0000_1f00_u32.to_le_bytes());
        input[32..160].fill(0x5a);
        input[160..416].fill(0xa5);
        input[28..32].copy_from_slice(&0xdead_beef_u32.to_le_bytes());
        bus.write_physical(0x2000, &input).unwrap();

        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.cs = 8;
        cpu.state.cr0 |= CR0_TS;
        cpu.state.cr4 |= CR4_OSFXSR;
        cpu.state.set_register(Register::Rsi, 0x2000);
        cpu.state.set_register(Register::Rdi, 0x3000);
        assert_eq!(cpu.run(&mut bus, 4), ExitReason::Halted);

        let mut output = [0_u8; FXSAVE_SIZE];
        bus.read_physical(0x3000, &mut output).unwrap();
        assert_eq!(&output[..28], &input[..28]);
        assert_eq!(&output[32..416], &input[32..416]);
        assert_eq!(
            u32::from_le_bytes(output[28..32].try_into().unwrap()),
            MXCSR_MASK
        );
        assert!(output[416..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn legacy_fpu_state_access_checks_ts_alignment_mxcsr_and_page_bounds() {
        let mut bus = MemoryBus::new(0x5000);
        bus.write_physical(0, &[0x0f, 0xae, 0x07]).unwrap();
        let mut cpu = Cpu::new();
        cpu.state.rip = 0;
        cpu.state.set_register(Register::Rdi, 0x2000);
        let instruction = decode(&[0x0f, 0xae, 0x07]).unwrap();
        assert_eq!(
            cpu.step(&mut bus),
            Err(CpuFault::Unsupported {
                rip: 0,
                instruction,
            })
        );

        cpu.state.rip = 0;
        cpu.state.cr4 |= CR4_OSFXSR;
        cpu.state.cr0 |= CR0_TS;
        assert_eq!(cpu.step(&mut bus), Err(CpuFault::DeviceNotAvailable));

        cpu.state.rip = 0;
        cpu.state.cr0 &= !CR0_TS;
        cpu.state.set_register(Register::Rdi, 0x2001);
        assert_eq!(
            cpu.step(&mut bus),
            Err(CpuFault::GeneralProtection(
                "FXSAVE/FXRSTOR area is not 16-byte aligned"
            ))
        );

        // fxrstor [rdi] with a reserved MXCSR bit must #GP without loading it.
        bus.write_physical(0, &[0x0f, 0xae, 0x0f]).unwrap();
        let mut invalid = initial_fx_state();
        invalid[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        bus.write_physical(0x2000, &invalid).unwrap();
        cpu.state.rip = 0;
        cpu.state.set_register(Register::Rdi, 0x2000);
        assert_eq!(
            cpu.step(&mut bus),
            Err(CpuFault::GeneralProtection(
                "FXRSTOR image has unsupported MXCSR bits"
            ))
        );

        // A 16-byte-aligned 512-byte save that crosses into a non-present
        // page reports the precise write page fault rather than truncating.
        let mut paged = MemoryBus::new(0x6000);
        for (entry, next) in [(0x1000, 0x2000), (0x2000, 0x3000), (0x3000, 0x4000)] {
            paged.write_u64_physical(entry, next | 3).unwrap();
        }
        paged.write_u64_physical(0x4000, 0x5000 | 3).unwrap();
        paged.write_physical(0x5000, &[0x0f, 0xae, 0x07]).unwrap();
        let mut paged_cpu = Cpu::new();
        paged_cpu.state.rip = 0;
        paged_cpu.state.cr3 = 0x1000;
        paged_cpu.state.cr0 |= 1 << 31;
        paged_cpu.state.cr4 |= CR4_OSFXSR;
        paged_cpu.state.set_register(Register::Rdi, 0x0ff0);
        assert_eq!(
            paged_cpu.step(&mut paged),
            Err(CpuFault::Memory(MemoryError::PageFault {
                address: 0x1000,
                access: Access::Write,
                reason: "not present",
            }))
        );
    }
}
