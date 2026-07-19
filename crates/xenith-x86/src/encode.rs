//! Encoder for the canonical subset emitted by Xenith's assembler and compiler.

use crate::{Instruction, MemoryOperand, Mnemonic, Operand, OperandSize, Register};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    BufferTooSmall,
    UnsupportedInstruction,
    InvalidOperand,
}

pub fn encode(instruction: &Instruction, output: &mut [u8]) -> Result<usize, EncodeError> {
    let mut encoder = Encoder { output, cursor: 0 };
    encoder.instruction(instruction)?;
    Ok(encoder.cursor)
}

struct Encoder<'a> {
    output: &'a mut [u8],
    cursor: usize,
}

impl Encoder<'_> {
    fn byte(&mut self, value: u8) -> Result<(), EncodeError> {
        let Some(slot) = self.output.get_mut(self.cursor) else {
            return Err(EncodeError::BufferTooSmall);
        };
        *slot = value;
        self.cursor += 1;
        Ok(())
    }

    fn immediate(&mut self, value: u64, size: OperandSize) -> Result<(), EncodeError> {
        for index in 0..size as usize {
            self.byte((value >> (index * 8)) as u8)?;
        }
        Ok(())
    }

    fn rex(&mut self, wide: bool, register: Register) -> Result<(), EncodeError> {
        let rex = 0x40 | if wide { 8 } else { 0 } | if register.index() >= 8 { 1 } else { 0 };
        if rex != 0x40 {
            self.byte(rex)?;
        }
        Ok(())
    }

    fn unary_register(&mut self, opcode: u8, operand: Operand) -> Result<(), EncodeError> {
        let Operand::Register {
            register,
            size,
            high8: false,
        } = operand
        else {
            return Err(EncodeError::InvalidOperand);
        };
        self.rex(size == OperandSize::Qword, register)?;
        self.byte(opcode + (register.index() & 7))
    }

    fn instruction(&mut self, instruction: &Instruction) -> Result<(), EncodeError> {
        let first = instruction.operands[0];
        let second = instruction.operands[1];
        match instruction.mnemonic {
            Mnemonic::Nop => self.byte(0x90),
            Mnemonic::Hlt => self.byte(0xF4),
            Mnemonic::Cli => self.byte(0xFA),
            Mnemonic::Sti => self.byte(0xFB),
            Mnemonic::Int3 => self.byte(0xCC),
            Mnemonic::Return => self.byte(0xC3),
            Mnemonic::Leave => self.byte(0xC9),
            Mnemonic::Iretq => self.byte(0xCF),
            Mnemonic::Syscall => {
                self.byte(0x0F)?;
                self.byte(0x05)
            },
            Mnemonic::Sysret => {
                self.byte(0x0F)?;
                self.byte(0x07)
            },
            Mnemonic::Cpuid => {
                self.byte(0x0F)?;
                self.byte(0xA2)
            },
            Mnemonic::Rdmsr => {
                self.byte(0x0F)?;
                self.byte(0x32)
            },
            Mnemonic::Wrmsr => {
                self.byte(0x0F)?;
                self.byte(0x30)
            },
            Mnemonic::Swapgs => {
                self.byte(0x0F)?;
                self.byte(0x01)?;
                self.byte(0xF8)
            },
            Mnemonic::Bswap => self.bswap(first, second),
            Mnemonic::Push => self.push(first.ok_or(EncodeError::InvalidOperand)?),
            Mnemonic::Pop => self.unary_register(0x58, first.ok_or(EncodeError::InvalidOperand)?),
            Mnemonic::Jump | Mnemonic::Call | Mnemonic::JumpCondition(_) => {
                let Operand::Relative { displacement, size } =
                    first.ok_or(EncodeError::InvalidOperand)?
                else {
                    return Err(EncodeError::InvalidOperand);
                };
                match (instruction.mnemonic, size) {
                    (Mnemonic::Jump, OperandSize::Byte) => self.byte(0xEB)?,
                    (Mnemonic::Jump, OperandSize::Dword) => self.byte(0xE9)?,
                    (Mnemonic::Call, OperandSize::Dword) => self.byte(0xE8)?,
                    (Mnemonic::JumpCondition(condition), OperandSize::Byte) => {
                        self.byte(0x70 + condition.code())?
                    },
                    (Mnemonic::JumpCondition(condition), OperandSize::Dword) => {
                        self.byte(0x0F)?;
                        self.byte(0x80 + condition.code())?;
                    },
                    _ => return Err(EncodeError::InvalidOperand),
                }
                self.immediate(displacement as u64, size)
            },
            Mnemonic::Mov => self.mov(first, second),
            Mnemonic::Lea => self.lea(first, second),
            Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Not | Mnemonic::Neg => {
                self.group_unary(instruction.mnemonic, first)
            },
            Mnemonic::Imul => self.imul(first, second),
            Mnemonic::Add
            | Mnemonic::Adc
            | Mnemonic::Sub
            | Mnemonic::Sbb
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Cmp
            | Mnemonic::Test => self.binary_register(instruction.mnemonic, first, second),
            _ => Err(EncodeError::UnsupportedInstruction),
        }
    }

    fn mov(&mut self, first: Option<Operand>, second: Option<Operand>) -> Result<(), EncodeError> {
        match (first, second) {
            (
                Some(Operand::Register {
                    register,
                    size,
                    high8: false,
                }),
                Some(Operand::Immediate { value, .. }),
            ) => {
                if size == OperandSize::Word {
                    self.byte(0x66)?;
                }
                self.rex(size == OperandSize::Qword, register)?;
                self.byte(
                    if size == OperandSize::Byte {
                        0xB0
                    } else {
                        0xB8
                    } + (register.index() & 7),
                )?;
                self.immediate(value, size)
            },
            (
                Some(destination @ (Operand::Register { .. } | Operand::Memory(_))),
                Some(source @ Operand::Register { register, .. }),
            ) if destination.size() == source.size() => {
                let opcode = if destination.size() == OperandSize::Byte {
                    0x88
                } else {
                    0x89
                };
                self.modrm_instruction(opcode, destination.size(), register.index(), destination)
            },
            (
                Some(destination @ Operand::Register { register, .. }),
                Some(source @ Operand::Memory(_)),
            ) if destination.size() == source.size() => {
                let opcode = if destination.size() == OperandSize::Byte {
                    0x8A
                } else {
                    0x8B
                };
                self.modrm_instruction(opcode, destination.size(), register.index(), source)
            },
            (Some(destination @ Operand::Memory(_)), Some(Operand::Immediate { value, .. })) => {
                let size = destination.size();
                self.modrm_instruction(
                    if size == OperandSize::Byte {
                        0xC6
                    } else {
                        0xC7
                    },
                    size,
                    0,
                    destination,
                )?;
                let immediate_size = if size == OperandSize::Qword {
                    if value as i64 != value as i32 as i64 {
                        return Err(EncodeError::InvalidOperand);
                    }
                    OperandSize::Dword
                } else {
                    size
                };
                self.immediate(value, immediate_size)
            },
            _ => Err(EncodeError::UnsupportedInstruction),
        }
    }

    fn push(&mut self, operand: Operand) -> Result<(), EncodeError> {
        match operand {
            Operand::Register { .. } => self.unary_register(0x50, operand),
            Operand::Immediate { value, .. } if value as i64 == value as i8 as i64 => {
                self.byte(0x6A)?;
                self.byte(value as u8)
            },
            Operand::Immediate { value, .. } if value as i64 == value as i32 as i64 => {
                self.byte(0x68)?;
                self.immediate(value, OperandSize::Dword)
            },
            _ => Err(EncodeError::InvalidOperand),
        }
    }

    fn bswap(
        &mut self,
        first: Option<Operand>,
        second: Option<Operand>,
    ) -> Result<(), EncodeError> {
        if second.is_some() {
            return Err(EncodeError::InvalidOperand);
        }
        let Some(Operand::Register {
            register,
            size: size @ (OperandSize::Dword | OperandSize::Qword),
            high8: false,
        }) = first
        else {
            return Err(EncodeError::InvalidOperand);
        };
        self.rex(size == OperandSize::Qword, register)?;
        self.byte(0x0F)?;
        self.byte(0xC8 + (register.index() & 7))
    }

    fn binary_register(
        &mut self,
        mnemonic: Mnemonic,
        first: Option<Operand>,
        second: Option<Operand>,
    ) -> Result<(), EncodeError> {
        let destination = first.ok_or(EncodeError::InvalidOperand)?;
        let source = second.ok_or(EncodeError::InvalidOperand)?;
        let size = destination.size();
        if let Operand::Immediate { value, .. } = source {
            let extension = match mnemonic {
                Mnemonic::Add => 0,
                Mnemonic::Or => 1,
                Mnemonic::Adc => 2,
                Mnemonic::Sbb => 3,
                Mnemonic::And => 4,
                Mnemonic::Sub => 5,
                Mnemonic::Xor => 6,
                Mnemonic::Cmp => 7,
                Mnemonic::Test => 0,
                _ => return Err(EncodeError::UnsupportedInstruction),
            };
            let opcode = if mnemonic == Mnemonic::Test {
                if size == OperandSize::Byte {
                    0xF6
                } else {
                    0xF7
                }
            } else if size == OperandSize::Byte {
                0x80
            } else {
                0x81
            };
            self.modrm_instruction(opcode, size, extension, destination)?;
            let immediate_size = if size == OperandSize::Qword {
                if value as i64 != value as i32 as i64 {
                    return Err(EncodeError::InvalidOperand);
                }
                OperandSize::Dword
            } else {
                size
            };
            return self.immediate(value, immediate_size);
        }
        if size != source.size() {
            return Err(EncodeError::InvalidOperand);
        }
        let base = match mnemonic {
            Mnemonic::Add => 0x00,
            Mnemonic::Or => 0x08,
            Mnemonic::Adc => 0x10,
            Mnemonic::Sbb => 0x18,
            Mnemonic::And => 0x20,
            Mnemonic::Sub => 0x28,
            Mnemonic::Xor => 0x30,
            Mnemonic::Cmp => 0x38,
            Mnemonic::Test => 0x84,
            _ => return Err(EncodeError::UnsupportedInstruction),
        };
        match (destination, source) {
            (
                rm @ (Operand::Register { .. } | Operand::Memory(_)),
                Operand::Register { register, .. },
            ) => self.modrm_instruction(
                base | u8::from(size != OperandSize::Byte),
                size,
                register.index(),
                rm,
            ),
            (Operand::Register { register, .. }, rm @ Operand::Memory(_))
                if mnemonic != Mnemonic::Test =>
            {
                self.modrm_instruction(
                    base + 2 + u8::from(size != OperandSize::Byte),
                    size,
                    register.index(),
                    rm,
                )
            },
            _ => Err(EncodeError::InvalidOperand),
        }
    }

    fn lea(&mut self, first: Option<Operand>, second: Option<Operand>) -> Result<(), EncodeError> {
        let Some(Operand::Register { register, size, .. }) = first else {
            return Err(EncodeError::InvalidOperand);
        };
        let source = second.ok_or(EncodeError::InvalidOperand)?;
        if !matches!(source, Operand::Memory(_)) || source.size() != size {
            return Err(EncodeError::InvalidOperand);
        }
        self.modrm_instruction(0x8D, size, register.index(), source)
    }

    fn imul(&mut self, first: Option<Operand>, second: Option<Operand>) -> Result<(), EncodeError> {
        let Some(Operand::Register { register, size, .. }) = first else {
            return Err(EncodeError::InvalidOperand);
        };
        let source = second.ok_or(EncodeError::InvalidOperand)?;
        if source.size() != size {
            return Err(EncodeError::InvalidOperand);
        }
        self.operand_prefixes(size, register.index(), source)?;
        self.byte(0x0F)?;
        self.byte(0xAF)?;
        self.modrm(register.index(), source)
    }

    fn group_unary(
        &mut self,
        mnemonic: Mnemonic,
        first: Option<Operand>,
    ) -> Result<(), EncodeError> {
        let operand = first.ok_or(EncodeError::InvalidOperand)?;
        let size = operand.size();
        let (extension, opcode) = match mnemonic {
            Mnemonic::Inc => (
                0,
                if size == OperandSize::Byte {
                    0xFE
                } else {
                    0xFF
                },
            ),
            Mnemonic::Dec => (
                1,
                if size == OperandSize::Byte {
                    0xFE
                } else {
                    0xFF
                },
            ),
            Mnemonic::Not => (
                2,
                if size == OperandSize::Byte {
                    0xF6
                } else {
                    0xF7
                },
            ),
            Mnemonic::Neg => (
                3,
                if size == OperandSize::Byte {
                    0xF6
                } else {
                    0xF7
                },
            ),
            _ => return Err(EncodeError::UnsupportedInstruction),
        };
        self.modrm_instruction(opcode, size, extension, operand)
    }

    fn modrm_instruction(
        &mut self,
        opcode: u8,
        size: OperandSize,
        reg_field: u8,
        rm: Operand,
    ) -> Result<(), EncodeError> {
        self.operand_prefixes(size, reg_field, rm)?;
        self.byte(opcode)?;
        self.modrm(reg_field, rm)
    }

    fn operand_prefixes(
        &mut self,
        size: OperandSize,
        reg_field: u8,
        rm: Operand,
    ) -> Result<(), EncodeError> {
        if let Operand::Memory(memory) = rm {
            if let Some(segment) = memory.segment {
                self.byte(segment)?;
            }
        }
        if size == OperandSize::Word {
            self.byte(0x66)?;
        }
        let (rex_x, rex_b, force_byte_rex) = match rm {
            Operand::Register {
                register,
                high8: false,
                ..
            } => (
                false,
                register.index() >= 8,
                size == OperandSize::Byte && (4..=7).contains(&register.index()),
            ),
            Operand::Memory(memory) => (
                memory.index.is_some_and(|register| register.index() >= 8),
                memory.base.is_some_and(|register| register.index() >= 8),
                false,
            ),
            _ => return Err(EncodeError::InvalidOperand),
        };
        let rex = 0x40
            | if size == OperandSize::Qword { 8 } else { 0 }
            | if reg_field >= 8 { 4 } else { 0 }
            | if rex_x { 2 } else { 0 }
            | if rex_b { 1 } else { 0 };
        if rex != 0x40
            || force_byte_rex
            || (size == OperandSize::Byte && (4..=7).contains(&reg_field))
        {
            self.byte(rex)?;
        }
        Ok(())
    }

    fn modrm(&mut self, reg_field: u8, rm: Operand) -> Result<(), EncodeError> {
        match rm {
            Operand::Register {
                register,
                high8: false,
                ..
            } => self.byte(0xC0 | ((reg_field & 7) << 3) | (register.index() & 7)),
            Operand::Memory(memory) => self.memory_modrm(reg_field, memory),
            _ => Err(EncodeError::InvalidOperand),
        }
    }

    fn memory_modrm(&mut self, reg_field: u8, memory: MemoryOperand) -> Result<(), EncodeError> {
        let displacement =
            i32::try_from(memory.displacement).map_err(|_| EncodeError::InvalidOperand)?;
        if memory.rip_relative {
            if memory.base.is_some() || memory.index.is_some() {
                return Err(EncodeError::InvalidOperand);
            }
            self.byte(((reg_field & 7) << 3) | 5)?;
            return self.immediate(displacement as u32 as u64, OperandSize::Dword);
        }
        if memory
            .index
            .is_some_and(|register| register.index() == Register::Rsp.index())
        {
            return Err(EncodeError::InvalidOperand);
        }
        let base_low = memory.base.map(|register| register.index() & 7);
        let needs_sib = memory.index.is_some() || base_low == Some(4) || memory.base.is_none();
        let mode = if memory.base.is_none() || (displacement == 0 && !matches!(base_low, Some(5))) {
            0
        } else if i8::try_from(displacement).is_ok() {
            1
        } else {
            2
        };
        let rm_field = if needs_sib { 4 } else { base_low.unwrap_or(5) };
        self.byte((mode << 6) | ((reg_field & 7) << 3) | rm_field)?;
        if needs_sib {
            let scale = match memory.scale {
                1 => 0,
                2 => 1,
                4 => 2,
                8 => 3,
                _ => return Err(EncodeError::InvalidOperand),
            };
            let index = memory.index.map_or(4, |register| register.index() & 7);
            let base = base_low.unwrap_or(5);
            self.byte((scale << 6) | (index << 3) | base)?;
        }
        if mode == 1 {
            self.byte(displacement as i8 as u8)
        } else if mode == 2 || memory.base.is_none() || (mode == 0 && base_low == Some(5)) {
            self.immediate(displacement as u32 as u64, OperandSize::Dword)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mov_rax_round_trips() {
        let instruction = Instruction::new(Mnemonic::Mov).with_operands(
            Operand::register(Register::Rax, OperandSize::Qword),
            Some(Operand::Immediate {
                value: 0x1122_3344_5566_7788,
                size: OperandSize::Qword,
            }),
        );
        let mut output = [0u8; 16];
        let length = encode(&instruction, &mut output).unwrap();
        assert_eq!(&output[..length], &[
            0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
        ]);
        assert_eq!(
            crate::decode(&output[..length]).unwrap().operands,
            instruction.operands
        );
    }

    #[test]
    fn bswap_extended_qword_round_trips() {
        let instruction = Instruction::new(Mnemonic::Bswap)
            .with_operands(Operand::register(Register::R10, OperandSize::Qword), None);
        let mut output = [0u8; 16];
        let length = encode(&instruction, &mut output).unwrap();
        assert_eq!(&output[..length], &[0x49, 0x0F, 0xCA]);
        let decoded = crate::decode(&output[..length]).unwrap();
        assert_eq!(decoded.mnemonic, Mnemonic::Bswap);
        assert_eq!(decoded.operands, instruction.operands);
    }
}
