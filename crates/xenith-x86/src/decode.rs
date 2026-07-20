//! Bounds-checked x86-64 decoder.

use crate::{Instruction, MemoryOperand, Mnemonic, Operand, OperandSize, Prefixes, Register};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeErrorKind {
    Truncated,
    TooLong,
    UnsupportedOpcode,
    InvalidEncoding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeError {
    pub offset: u8,
    pub kind: DecodeErrorKind,
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
    prefixes: Prefixes,
}

pub fn decode(bytes: &[u8]) -> Result<Instruction, DecodeError> {
    let mut decoder = Decoder {
        bytes,
        cursor: 0,
        prefixes: Prefixes::default(),
    };
    decoder.read_prefixes()?;
    let opcode = decoder.byte()?;
    let mut instruction = decoder.primary(opcode)?;
    if decoder.cursor > 15 {
        return Err(decoder.error(DecodeErrorKind::TooLong));
    }
    instruction.prefixes = decoder.prefixes;
    instruction.length = decoder.cursor as u8;
    Ok(instruction)
}

impl<'a> Decoder<'a> {
    fn error(&self, kind: DecodeErrorKind) -> DecodeError {
        DecodeError {
            offset: self.cursor.min(u8::MAX as usize) as u8,
            kind,
        }
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        let Some(value) = self.bytes.get(self.cursor).copied() else {
            return Err(self.error(DecodeErrorKind::Truncated));
        };
        self.cursor += 1;
        Ok(value)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.cursor).copied()
    }

    fn imm(&mut self, size: OperandSize) -> Result<u64, DecodeError> {
        let count = size as usize;
        if count > 8 || self.cursor + count > self.bytes.len() {
            return Err(self.error(DecodeErrorKind::Truncated));
        }
        let mut value = 0u64;
        for index in 0..count {
            value |= u64::from(self.byte()?) << (index * 8);
        }
        Ok(value)
    }

    fn signed(&mut self, size: OperandSize) -> Result<i64, DecodeError> {
        let value = self.imm(size)?;
        Ok(match size {
            OperandSize::Byte => (value as i8) as i64,
            OperandSize::Word => (value as i16) as i64,
            OperandSize::Dword => (value as i32) as i64,
            OperandSize::Qword | OperandSize::Oword => value as i64,
        })
    }

    fn read_prefixes(&mut self) -> Result<(), DecodeError> {
        loop {
            match self.peek() {
                Some(0xF0) => self.prefixes.lock = true,
                Some(0xF2) => self.prefixes.repeat_not_equal = true,
                Some(0xF3) => self.prefixes.repeat = true,
                Some(0x66) => self.prefixes.operand_size = true,
                Some(0x67) => self.prefixes.address_size = true,
                Some(value @ (0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65)) => {
                    self.prefixes.segment = Some(value)
                },
                Some(value @ 0x40..=0x4F) => {
                    self.prefixes.rex_present = true;
                    self.prefixes.rex = value & 0x0F;
                },
                _ => break,
            }
            self.cursor += 1;
            if self.cursor >= 15 {
                return Err(self.error(DecodeErrorKind::TooLong));
            }
        }
        Ok(())
    }

    fn operand_size(&self, byte_operation: bool) -> OperandSize {
        if byte_operation {
            OperandSize::Byte
        } else if self.prefixes.rex_w() {
            OperandSize::Qword
        } else if self.prefixes.operand_size {
            OperandSize::Word
        } else {
            OperandSize::Dword
        }
    }

    fn register_operand(&self, field: u8, extension: u8, size: OperandSize) -> Operand {
        let high8 =
            size == OperandSize::Byte && !self.prefixes.rex_present && (4..=7).contains(&field);
        // Legacy byte-register encodings 4..7 are AH/CH/DH/BH, backed by
        // RAX/RCX/RDX/RBX.  They are not byte views of RSP/RBP/RSI/RDI.
        let raw = if high8 {
            field - 4
        } else {
            field | (extension << 3)
        };
        Operand::Register {
            register: Register::from_index(raw),
            size,
            high8,
        }
    }

    fn modrm(&mut self, size: OperandSize) -> Result<(Operand, Operand, u8), DecodeError> {
        self.modrm_sized(size, size)
    }

    fn modrm_sized(
        &mut self,
        rm_size: OperandSize,
        reg_size: OperandSize,
    ) -> Result<(Operand, Operand, u8), DecodeError> {
        let byte = self.byte()?;
        let mode = byte >> 6;
        let reg_field = (byte >> 3) & 7;
        let rm_field = byte & 7;
        let reg = self.register_operand(reg_field, self.prefixes.rex_r(), reg_size);
        if mode == 3 {
            let rm = self.register_operand(rm_field, self.prefixes.rex_b(), rm_size);
            return Ok((rm, reg, reg_field));
        }

        let mut memory = MemoryOperand::new(rm_size);
        memory.segment = self.prefixes.segment;
        if rm_field == 4 {
            let sib = self.byte()?;
            memory.scale = 1 << (sib >> 6);
            let index = (sib >> 3) & 7;
            let base = sib & 7;
            if index != 4 || self.prefixes.rex_x() != 0 {
                memory.index = Some(Register::from_index(index | (self.prefixes.rex_x() << 3)));
            }
            if mode == 0 && base == 5 {
                memory.displacement = self.signed(OperandSize::Dword)?;
            } else {
                memory.base = Some(Register::from_index(base | (self.prefixes.rex_b() << 3)));
            }
        } else if mode == 0 && rm_field == 5 {
            memory.rip_relative = !self.prefixes.address_size;
            memory.displacement = self.signed(OperandSize::Dword)?;
        } else {
            memory.base = Some(Register::from_index(
                rm_field | (self.prefixes.rex_b() << 3),
            ));
        }
        match mode {
            1 => memory.displacement += self.signed(OperandSize::Byte)?,
            2 => memory.displacement += self.signed(OperandSize::Dword)?,
            _ => {},
        }
        Ok((Operand::Memory(memory), reg, reg_field))
    }

    fn binary_modrm(&mut self, mnemonic: Mnemonic, opcode: u8) -> Result<Instruction, DecodeError> {
        let size = self.operand_size(opcode & 1 == 0);
        let (rm, reg, _) = self.modrm(size)?;
        let direction = opcode & 2 != 0;
        let (destination, source) = if direction { (reg, rm) } else { (rm, reg) };
        Ok(Instruction::new(mnemonic).with_operands(destination, Some(source)))
    }

    fn primary(&mut self, opcode: u8) -> Result<Instruction, DecodeError> {
        match opcode {
            0x90 => Ok(Instruction::new(Mnemonic::Nop)),
            0x91..=0x97 => {
                let size = self.operand_size(false);
                Ok(Instruction::new(Mnemonic::Xchg).with_operands(
                    Operand::register(Register::Rax, size),
                    Some(self.register_operand(opcode & 7, self.prefixes.rex_b(), size)),
                ))
            },
            0xF4 => Ok(Instruction::new(Mnemonic::Hlt)),
            0xFA => Ok(Instruction::new(Mnemonic::Cli)),
            0xFB => Ok(Instruction::new(Mnemonic::Sti)),
            0xFC => Ok(Instruction::new(Mnemonic::Cld)),
            0xFD => Ok(Instruction::new(Mnemonic::Std)),
            0xCC => Ok(Instruction::new(Mnemonic::Int3)),
            0xDB => {
                if self.byte()? == 0xE3 {
                    Ok(Instruction::new(Mnemonic::Fninit))
                } else {
                    Err(self.error(DecodeErrorKind::UnsupportedOpcode))
                }
            },
            0x9C => Ok(Instruction::new(Mnemonic::PushFlags)),
            0x9D => Ok(Instruction::new(Mnemonic::PopFlags)),
            0x98 => {
                let destination_size = self.operand_size(false);
                let source_size = match destination_size {
                    OperandSize::Word => OperandSize::Byte,
                    OperandSize::Dword => OperandSize::Word,
                    OperandSize::Qword => OperandSize::Dword,
                    OperandSize::Byte | OperandSize::Oword => unreachable!(),
                };
                Ok(Instruction::new(Mnemonic::Movsx).with_operands(
                    Operand::register(Register::Rax, destination_size),
                    Some(Operand::register(Register::Rax, source_size)),
                ))
            },
            0x99 => {
                let size = self.operand_size(false);
                Ok(
                    Instruction::new(Mnemonic::SignExtendAccumulator).with_operands(
                        Operand::register(Register::Rdx, size),
                        Some(Operand::register(Register::Rax, size)),
                    ),
                )
            },
            0xC3 => Ok(Instruction::new(Mnemonic::Return)),
            0xCB => Ok(Instruction::new(Mnemonic::ReturnFar)),
            0xC9 => Ok(Instruction::new(Mnemonic::Leave)),
            0xCF => Ok(Instruction::new(Mnemonic::Iretq)),
            0x50..=0x57 => Ok(Instruction::new(Mnemonic::Push).with_operands(
                self.register_operand(opcode & 7, self.prefixes.rex_b(), OperandSize::Qword),
                None,
            )),
            0x58..=0x5F => Ok(Instruction::new(Mnemonic::Pop).with_operands(
                self.register_operand(opcode & 7, self.prefixes.rex_b(), OperandSize::Qword),
                None,
            )),
            0x63 => {
                let destination_size = self.operand_size(false);
                let (source, destination, _) =
                    self.modrm_sized(OperandSize::Dword, destination_size)?;
                Ok(Instruction::new(Mnemonic::Movsx).with_operands(destination, Some(source)))
            },
            0x68 => {
                let value = self.imm(OperandSize::Dword)?;
                Ok(Instruction::new(Mnemonic::Push).with_operands(
                    Operand::Immediate {
                        value,
                        size: OperandSize::Dword,
                    },
                    None,
                ))
            },
            0x69 | 0x6B => self.imul_immediate(opcode),
            0x6A => {
                let value = self.imm(OperandSize::Byte)?;
                Ok(Instruction::new(Mnemonic::Push).with_operands(
                    Operand::Immediate {
                        value,
                        size: OperandSize::Byte,
                    },
                    None,
                ))
            },
            0x70..=0x7F => self.relative(
                Mnemonic::JumpCondition(crate::Condition::from_code(opcode)),
                OperandSize::Byte,
            ),
            0xE8 => self.relative(Mnemonic::Call, OperandSize::Dword),
            0xE9 => self.relative(Mnemonic::Jump, OperandSize::Dword),
            0xEB => self.relative(Mnemonic::Jump, OperandSize::Byte),
            0xE4 | 0xE5 => self.port_immediate(Mnemonic::In, opcode & 1 != 0),
            0xE6 | 0xE7 => self.port_immediate(Mnemonic::Out, opcode & 1 != 0),
            0xEC | 0xED => self.port_dx(Mnemonic::In, opcode & 1 != 0),
            0xEE | 0xEF => self.port_dx(Mnemonic::Out, opcode & 1 != 0),
            0xA4 | 0xA5 => Ok(Instruction::new(Mnemonic::Movs).with_operands(
                Operand::register(Register::Rsi, self.operand_size(opcode == 0xA4)),
                Some(Operand::register(
                    Register::Rdi,
                    self.operand_size(opcode == 0xA4),
                )),
            )),
            0xAA | 0xAB => Ok(Instruction::new(Mnemonic::Stos).with_operands(
                Operand::register(Register::Rdi, self.operand_size(opcode == 0xAA)),
                Some(Operand::register(
                    Register::Rax,
                    self.operand_size(opcode == 0xAA),
                )),
            )),
            0xB0..=0xB7 => {
                let destination =
                    self.register_operand(opcode & 7, self.prefixes.rex_b(), OperandSize::Byte);
                let value = self.imm(OperandSize::Byte)?;
                Ok(Instruction::new(Mnemonic::Mov).with_operands(
                    destination,
                    Some(Operand::Immediate {
                        value,
                        size: OperandSize::Byte,
                    }),
                ))
            },
            0xB8..=0xBF => {
                let size = self.operand_size(false);
                let destination = self.register_operand(opcode & 7, self.prefixes.rex_b(), size);
                let value = self.imm(size)?;
                Ok(Instruction::new(Mnemonic::Mov)
                    .with_operands(destination, Some(Operand::Immediate { value, size })))
            },
            0x88..=0x8B => self.binary_modrm(Mnemonic::Mov, opcode),
            0x8C | 0x8E => self.segment_move(opcode),
            0x86 | 0x87 => self.binary_modrm(Mnemonic::Xchg, opcode - 0x86),
            0x8D => self.binary_modrm(Mnemonic::Lea, 0x8B),
            0x04 | 0x05 | 0x0C | 0x0D | 0x14 | 0x15 | 0x1C | 0x1D | 0x24 | 0x25 | 0x2C | 0x2D
            | 0x34 | 0x35 | 0x3C | 0x3D | 0xA8 | 0xA9 => self.accumulator_immediate(opcode),
            0x00..=0x03 => self.binary_modrm(Mnemonic::Add, opcode),
            0x08..=0x0B => self.binary_modrm(Mnemonic::Or, opcode),
            0x10..=0x13 => self.binary_modrm(Mnemonic::Adc, opcode),
            0x18..=0x1B => self.binary_modrm(Mnemonic::Sbb, opcode),
            0x20..=0x23 => self.binary_modrm(Mnemonic::And, opcode),
            0x28..=0x2B => self.binary_modrm(Mnemonic::Sub, opcode),
            0x30..=0x33 => self.binary_modrm(Mnemonic::Xor, opcode),
            0x38..=0x3B => self.binary_modrm(Mnemonic::Cmp, opcode),
            0x84 | 0x85 => self.binary_modrm(Mnemonic::Test, opcode - 0x84),
            0x80 | 0x81 | 0x83 => self.group_immediate(opcode),
            0xC0 | 0xC1 | 0xD0..=0xD3 => self.group_two(opcode),
            0xC6 | 0xC7 => self.mov_immediate(opcode),
            0xF6 | 0xF7 => self.group_three(opcode),
            0xFE | 0xFF => self.group_five(opcode),
            0x0F => self.secondary(),
            _ => Err(self.error(DecodeErrorKind::UnsupportedOpcode)),
        }
    }

    fn relative(
        &mut self,
        mnemonic: Mnemonic,
        size: OperandSize,
    ) -> Result<Instruction, DecodeError> {
        let displacement = self.signed(size)?;
        Ok(
            Instruction::new(mnemonic)
                .with_operands(Operand::Relative { displacement, size }, None),
        )
    }

    fn port_immediate(
        &mut self,
        mnemonic: Mnemonic,
        wide: bool,
    ) -> Result<Instruction, DecodeError> {
        let size = self.operand_size(!wide);
        let port = Operand::Immediate {
            value: self.imm(OperandSize::Byte)?,
            size: OperandSize::Byte,
        };
        let accumulator = Operand::register(Register::Rax, size);
        let (first, second) = if mnemonic == Mnemonic::In {
            (accumulator, port)
        } else {
            (port, accumulator)
        };
        Ok(Instruction::new(mnemonic).with_operands(first, Some(second)))
    }

    fn port_dx(&mut self, mnemonic: Mnemonic, wide: bool) -> Result<Instruction, DecodeError> {
        let size = self.operand_size(!wide);
        let port = Operand::register(Register::Rdx, OperandSize::Word);
        let accumulator = Operand::register(Register::Rax, size);
        let (first, second) = if mnemonic == Mnemonic::In {
            (accumulator, port)
        } else {
            (port, accumulator)
        };
        Ok(Instruction::new(mnemonic).with_operands(first, Some(second)))
    }

    fn accumulator_immediate(&mut self, opcode: u8) -> Result<Instruction, DecodeError> {
        let mnemonic = match opcode {
            0x04 | 0x05 => Mnemonic::Add,
            0x0C | 0x0D => Mnemonic::Or,
            0x14 | 0x15 => Mnemonic::Adc,
            0x1C | 0x1D => Mnemonic::Sbb,
            0x24 | 0x25 => Mnemonic::And,
            0x2C | 0x2D => Mnemonic::Sub,
            0x34 | 0x35 => Mnemonic::Xor,
            0x3C | 0x3D => Mnemonic::Cmp,
            _ => Mnemonic::Test,
        };
        let size = self.operand_size(opcode & 1 == 0);
        let immediate_size = if size == OperandSize::Qword {
            OperandSize::Dword
        } else {
            size
        };
        let immediate = Operand::Immediate {
            value: self.imm(immediate_size)?,
            size: immediate_size,
        };
        Ok(Instruction::new(mnemonic)
            .with_operands(Operand::register(Register::Rax, size), Some(immediate)))
    }

    fn segment_move(&mut self, opcode: u8) -> Result<Instruction, DecodeError> {
        let (rm, _, segment) = self.modrm(OperandSize::Word)?;
        if segment > 5 || (opcode == 0x8E && segment == 1) {
            return Err(self.error(DecodeErrorKind::InvalidEncoding));
        }
        let segment = Operand::Segment { index: segment };
        let (destination, source) = if opcode == 0x8E {
            (segment, rm)
        } else {
            (rm, segment)
        };
        Ok(Instruction::new(Mnemonic::Mov).with_operands(destination, Some(source)))
    }

    fn imul_immediate(&mut self, opcode: u8) -> Result<Instruction, DecodeError> {
        let size = self.operand_size(false);
        let (source, destination, _) = self.modrm(size)?;
        let immediate_size = if opcode == 0x6B {
            OperandSize::Byte
        } else if size == OperandSize::Qword {
            OperandSize::Dword
        } else {
            size
        };
        let immediate = Operand::Immediate {
            value: self.imm(immediate_size)?,
            size: immediate_size,
        };
        Ok(Instruction::new(Mnemonic::Imul).with_three_operands(destination, source, immediate))
    }

    fn group_immediate(&mut self, opcode: u8) -> Result<Instruction, DecodeError> {
        let size = self.operand_size(opcode == 0x80);
        let (rm, _, extension) = self.modrm(size)?;
        let mnemonic = match extension {
            0 => Mnemonic::Add,
            1 => Mnemonic::Or,
            2 => Mnemonic::Adc,
            3 => Mnemonic::Sbb,
            4 => Mnemonic::And,
            5 => Mnemonic::Sub,
            6 => Mnemonic::Xor,
            _ => Mnemonic::Cmp,
        };
        // In 64-bit mode the 81 /digit form still carries an imm32, which
        // the CPU sign-extends to the REX.W destination width.  Treating it
        // as imm64 consumes four bytes from the following instruction and
        // desynchronises the entire stream.
        let immediate_size = match (opcode, size) {
            (0x80 | 0x83, _) => OperandSize::Byte,
            (0x81, OperandSize::Qword) => OperandSize::Dword,
            _ => size,
        };
        let value = self.imm(immediate_size)?;
        Ok(Instruction::new(mnemonic).with_operands(
            rm,
            Some(Operand::Immediate {
                value,
                size: immediate_size,
            }),
        ))
    }

    fn mov_immediate(&mut self, opcode: u8) -> Result<Instruction, DecodeError> {
        let size = self.operand_size(opcode == 0xC6);
        let (rm, _, extension) = self.modrm(size)?;
        if extension != 0 {
            return Err(self.error(DecodeErrorKind::InvalidEncoding));
        }
        let encoded_size = if size == OperandSize::Qword {
            OperandSize::Dword
        } else {
            size
        };
        let value = self.imm(encoded_size)?;
        Ok(Instruction::new(Mnemonic::Mov).with_operands(
            rm,
            Some(Operand::Immediate {
                value,
                size: encoded_size,
            }),
        ))
    }

    fn group_two(&mut self, opcode: u8) -> Result<Instruction, DecodeError> {
        let byte_operation = matches!(opcode, 0xC0 | 0xD0 | 0xD2);
        let size = self.operand_size(byte_operation);
        let (destination, _, extension) = self.modrm(size)?;
        let mnemonic = match extension {
            0 => Mnemonic::Rol,
            1 => Mnemonic::Ror,
            4 | 6 => Mnemonic::Shl,
            5 => Mnemonic::Shr,
            7 => Mnemonic::Sar,
            _ => return Err(self.error(DecodeErrorKind::UnsupportedOpcode)),
        };
        let count = match opcode {
            0xC0 | 0xC1 => Operand::Immediate {
                value: self.imm(OperandSize::Byte)?,
                size: OperandSize::Byte,
            },
            0xD0 | 0xD1 => Operand::Immediate {
                value: 1,
                size: OperandSize::Byte,
            },
            _ => Operand::register(Register::Rcx, OperandSize::Byte),
        };
        Ok(Instruction::new(mnemonic).with_operands(destination, Some(count)))
    }

    fn group_three(&mut self, opcode: u8) -> Result<Instruction, DecodeError> {
        let size = self.operand_size(opcode == 0xF6);
        let (rm, _, extension) = self.modrm(size)?;
        let mnemonic = match extension {
            0 => Mnemonic::Test,
            2 => Mnemonic::Not,
            3 => Mnemonic::Neg,
            4 => Mnemonic::Mul,
            5 => Mnemonic::Imul,
            6 => Mnemonic::Div,
            7 => Mnemonic::Idiv,
            _ => return Err(self.error(DecodeErrorKind::InvalidEncoding)),
        };
        let second = if extension == 0 {
            let immediate_size = if size == OperandSize::Qword {
                OperandSize::Dword
            } else {
                size
            };
            Some(Operand::Immediate {
                value: self.imm(immediate_size)?,
                size: immediate_size,
            })
        } else {
            None
        };
        Ok(Instruction::new(mnemonic).with_operands(rm, second))
    }

    fn group_five(&mut self, opcode: u8) -> Result<Instruction, DecodeError> {
        let size = self.operand_size(opcode == 0xFE);
        let (mut rm, _, extension) = self.modrm(size)?;
        let mnemonic = match extension {
            0 => Mnemonic::Inc,
            1 => Mnemonic::Dec,
            2 => Mnemonic::Call,
            4 => Mnemonic::Jump,
            6 => Mnemonic::Push,
            _ => return Err(self.error(DecodeErrorKind::InvalidEncoding)),
        };
        // Near indirect CALL/JMP and PUSH use a 64-bit operand by default in
        // long mode even without REX.W.  INC/DEC retain the ordinary operand
        // size selected above.
        if opcode == 0xFF && matches!(extension, 2 | 4 | 6) {
            match &mut rm {
                Operand::Register { size, .. } => *size = OperandSize::Qword,
                Operand::Memory(memory) => memory.size = OperandSize::Qword,
                _ => {},
            }
        }
        Ok(Instruction::new(mnemonic).with_operands(rm, None))
    }

    fn secondary(&mut self) -> Result<Instruction, DecodeError> {
        let opcode = self.byte()?;
        match opcode {
            0x05 => Ok(Instruction::new(Mnemonic::Syscall)),
            0x06 => Ok(Instruction::new(Mnemonic::Clts)),
            0x07 => Ok(Instruction::new(Mnemonic::Sysret)),
            0x09 => Ok(Instruction::new(Mnemonic::Wbinvd)),
            0x31 => Ok(Instruction::new(Mnemonic::Rdtsc)),
            0x32 => Ok(Instruction::new(Mnemonic::Rdmsr)),
            0x30 => Ok(Instruction::new(Mnemonic::Wrmsr)),
            0xA2 => Ok(Instruction::new(Mnemonic::Cpuid)),
            0xA3 | 0xAB | 0xB3 | 0xBB => {
                let size = self.operand_size(false);
                let (base, index, _) = self.modrm(size)?;
                let mnemonic = match opcode {
                    0xA3 => Mnemonic::Bt,
                    0xAB => Mnemonic::Bts,
                    0xB3 => Mnemonic::Btr,
                    0xBB => Mnemonic::Btc,
                    _ => unreachable!("matched register-form bit-test opcode"),
                };
                Ok(Instruction::new(mnemonic).with_operands(base, Some(index)))
            },
            0xBA => {
                let size = self.operand_size(false);
                let (base, _, extension) = self.modrm(size)?;
                let mnemonic = match extension {
                    4 => Mnemonic::Bt,
                    5 => Mnemonic::Bts,
                    6 => Mnemonic::Btr,
                    7 => Mnemonic::Btc,
                    _ => return Err(self.error(DecodeErrorKind::InvalidEncoding)),
                };
                let index = Operand::Immediate {
                    value: self.imm(OperandSize::Byte)?,
                    size: OperandSize::Byte,
                };
                Ok(Instruction::new(mnemonic).with_operands(base, Some(index)))
            },
            0xAE => {
                let (operand, _, extension) = self.modrm(OperandSize::Oword)?;
                match (operand, extension) {
                    (Operand::Memory(_), 0) => {
                        Ok(Instruction::new(Mnemonic::Fxsave).with_operands(operand, None))
                    },
                    (Operand::Memory(_), 1) => {
                        Ok(Instruction::new(Mnemonic::Fxrstor).with_operands(operand, None))
                    },
                    (Operand::Register { .. }, 5..=7) => Ok(Instruction::new(Mnemonic::Fence)),
                    _ => Err(self.error(DecodeErrorKind::UnsupportedOpcode)),
                }
            },
            0x1F => {
                // Architecturally defined multi-byte NOP.  Its ModRM/SIB and
                // displacement bytes still have to be consumed even though
                // execution has no side effects.
                let _ = self.modrm(self.operand_size(false))?;
                Ok(Instruction::new(Mnemonic::Nop))
            },
            0xB0 | 0xB1 => self.binary_modrm(Mnemonic::Cmpxchg, opcode),
            0xC0 | 0xC1 => self.binary_modrm(Mnemonic::Xadd, opcode - 0xC0),
            0xC8..=0xCF => {
                let size = self.operand_size(false);
                Ok(Instruction::new(Mnemonic::Bswap).with_operands(
                    self.register_operand(opcode & 7, self.prefixes.rex_b(), size),
                    None,
                ))
            },
            0xAF => {
                let size = self.operand_size(false);
                let (source, destination, _) = self.modrm(size)?;
                Ok(Instruction::new(Mnemonic::Imul).with_operands(destination, Some(source)))
            },
            0xBC | 0xBD => {
                let size = self.operand_size(false);
                let (source, destination, _) = self.modrm(size)?;
                Ok(Instruction::new(if opcode == 0xBC {
                    Mnemonic::Bsf
                } else {
                    Mnemonic::Bsr
                })
                .with_operands(destination, Some(source)))
            },
            0x40..=0x4F => {
                let size = self.operand_size(false);
                let (source, destination, _) = self.modrm(size)?;
                Ok(
                    Instruction::new(Mnemonic::MoveCondition(crate::Condition::from_code(opcode)))
                        .with_operands(destination, Some(source)),
                )
            },
            0x80..=0x8F => self.relative(
                Mnemonic::JumpCondition(crate::Condition::from_code(opcode)),
                OperandSize::Dword,
            ),
            0x90..=0x9F => {
                let (rm, _, _) = self.modrm(OperandSize::Byte)?;
                Ok(
                    Instruction::new(Mnemonic::SetCondition(crate::Condition::from_code(opcode)))
                        .with_operands(rm, None),
                )
            },
            0xB6 | 0xB7 | 0xBE | 0xBF => {
                let source_size = if opcode & 1 == 0 {
                    OperandSize::Byte
                } else {
                    OperandSize::Word
                };
                let destination_size = self.operand_size(false);
                let (source, destination, _) = self.modrm_sized(source_size, destination_size)?;
                let mnemonic = if opcode & 8 == 0 {
                    Mnemonic::Movzx
                } else {
                    Mnemonic::Movsx
                };
                Ok(Instruction::new(mnemonic).with_operands(destination, Some(source)))
            },
            0x01 => {
                let marker = self
                    .peek()
                    .ok_or_else(|| self.error(DecodeErrorKind::Truncated))?;
                if marker == 0xF8 {
                    self.cursor += 1;
                    return Ok(Instruction::new(Mnemonic::Swapgs));
                }
                let (rm, _, extension) = self.modrm(OperandSize::Qword)?;
                let mnemonic = match extension {
                    2 => Mnemonic::Lgdt,
                    3 => Mnemonic::Lidt,
                    7 => Mnemonic::Invlpg,
                    _ => return Err(self.error(DecodeErrorKind::InvalidEncoding)),
                };
                Ok(Instruction::new(mnemonic).with_operands(rm, None))
            },
            0x00 => {
                let (rm, _, extension) = self.modrm(OperandSize::Word)?;
                if extension != 3 {
                    return Err(self.error(DecodeErrorKind::UnsupportedOpcode));
                }
                Ok(Instruction::new(Mnemonic::Ltr).with_operands(rm, None))
            },
            0x20 | 0x22 => {
                let modrm = self.byte()?;
                if modrm >> 6 != 3 {
                    return Err(self.error(DecodeErrorKind::InvalidEncoding));
                }
                let general =
                    self.register_operand(modrm & 7, self.prefixes.rex_b(), OperandSize::Qword);
                let control = Operand::Control {
                    index: ((modrm >> 3) & 7) | (self.prefixes.rex_r() << 3),
                };
                let (destination, source) = if opcode == 0x20 {
                    (general, control)
                } else {
                    (control, general)
                };
                Ok(Instruction::new(Mnemonic::Mov).with_operands(destination, Some(source)))
            },
            _ => Err(self.error(DecodeErrorKind::UnsupportedOpcode)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_rex_mov_immediate() {
        let insn = decode(&[0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::Mov);
        assert_eq!(insn.length, 10);
        assert_eq!(
            insn.operands[0],
            Some(Operand::register(Register::Rax, OperandSize::Qword))
        );
        assert_eq!(
            insn.operands[1],
            Some(Operand::Immediate {
                value: 0x0807_0605_0403_0201,
                size: OperandSize::Qword
            })
        );
    }

    #[test]
    fn decodes_dword_and_rex_w_bswap() {
        let dword = decode(&[0x0f, 0xca]).unwrap();
        assert_eq!(dword.mnemonic, Mnemonic::Bswap);
        assert_eq!(
            dword.operands[0],
            Some(Operand::register(Register::Rdx, OperandSize::Dword))
        );
        assert_eq!(dword.length, 2);

        let qword = decode(&[0x49, 0x0f, 0xc8]).unwrap();
        assert_eq!(qword.mnemonic, Mnemonic::Bswap);
        assert_eq!(
            qword.operands[0],
            Some(Operand::register(Register::R8, OperandSize::Qword))
        );
        assert_eq!(qword.length, 3);
    }

    #[test]
    fn decodes_sib_address() {
        let insn = decode(&[0x48, 0x8B, 0x44, 0x8B, 0x10]).unwrap();
        let memory = insn.operands[1]
            .and_then(|operand| match operand {
                Operand::Memory(memory) => Some(memory),
                _ => None,
            })
            .expect("expected memory operand");
        assert_eq!(memory.base, Some(Register::Rbx));
        assert_eq!(memory.index, Some(Register::Rcx));
        assert_eq!(memory.scale, 4);
        assert_eq!(memory.displacement, 0x10);
    }

    #[test]
    fn rejects_truncated_instruction() {
        assert_eq!(
            decode(&[0xE9]).unwrap_err().kind,
            DecodeErrorKind::Truncated
        );
    }

    #[test]
    fn rex_w_group_immediate_uses_imm32() {
        let insn = decode(&[0x48, 0x81, 0xec, 0xc8, 0, 0, 0, 0x48, 0x85, 0xff]).unwrap();
        assert_eq!(insn.length, 7);
        assert_eq!(insn.mnemonic, Mnemonic::Sub);
        assert_eq!(
            insn.operands[1],
            Some(Operand::Immediate {
                value: 0xc8,
                size: OperandSize::Dword,
            })
        );
    }

    #[test]
    fn consumes_multibyte_nop_and_decodes_cmpxchg() {
        let nop = decode(&[0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(nop.mnemonic, Mnemonic::Nop);
        assert_eq!(nop.length, 11);

        let cmpxchg = decode(&[0xf0, 0x0f, 0xb0, 0x0d, 1, 0, 0, 0]).unwrap();
        assert_eq!(cmpxchg.mnemonic, Mnemonic::Cmpxchg);
        assert_eq!(cmpxchg.length, 8);
    }

    #[test]
    fn indirect_call_defaults_to_qword_operand() {
        let call = decode(&[0xff, 0x50, 0x20]).unwrap();
        assert_eq!(call.mnemonic, Mnemonic::Call);
        assert_eq!(
            call.operands[0].expect("call operand").size(),
            OperandSize::Qword
        );
    }

    #[test]
    fn bare_rex_selects_sil_instead_of_dh() {
        let instruction = decode(&[0x40, 0x80, 0xfe, 0x05]).unwrap();
        assert!(instruction.prefixes.rex_present);
        assert_eq!(
            instruction.operands[0],
            Some(Operand::Register {
                register: Register::Rsi,
                size: OperandSize::Byte,
                high8: false,
            })
        );
    }

    #[test]
    fn legacy_high_byte_registers_use_accumulator_backing_registers() {
        let instruction = decode(&[0x0f, 0xb6, 0xcc]).unwrap();
        assert_eq!(
            instruction.operands[1],
            Some(Operand::Register {
                register: Register::Rax,
                size: OperandSize::Byte,
                high8: true,
            })
        );
    }

    #[test]
    fn movzx_uses_destination_width_for_the_modrm_reg_field() {
        let instruction = decode(&[0x0f, 0xb6, 0xf8]).unwrap();
        assert_eq!(instruction.operands, [
            Some(Operand::register(Register::Rdi, OperandSize::Dword)),
            Some(Operand::register(Register::Rax, OperandSize::Byte)),
            None,
        ]);
    }

    #[test]
    fn decodes_cdqe_as_accumulator_sign_extension() {
        let instruction = decode(&[0x48, 0x98]).unwrap();
        assert_eq!(instruction.mnemonic, Mnemonic::Movsx);
        assert_eq!(instruction.operands, [
            Some(Operand::register(Register::Rax, OperandSize::Qword)),
            Some(Operand::register(Register::Rax, OperandSize::Dword)),
            None,
        ]);
    }

    #[test]
    fn decodes_bt_with_immediate_bit_index() {
        let instruction = decode(&[0x48, 0x0f, 0xba, 0xe1, 0x2f]).unwrap();
        assert_eq!(instruction.mnemonic, Mnemonic::Bt);
        assert_eq!(instruction.operands, [
            Some(Operand::register(Register::Rcx, OperandSize::Qword)),
            Some(Operand::Immediate {
                value: 47,
                size: OperandSize::Byte,
            }),
            None,
        ]);
    }

    #[test]
    fn decodes_register_form_btr_with_rex_extensions() {
        let instruction = decode(&[0x49, 0x0F, 0xB3, 0xCE]).unwrap();
        assert_eq!(instruction.mnemonic, Mnemonic::Btr);
        assert_eq!(instruction.operands, [
            Some(Operand::register(Register::R14, OperandSize::Qword)),
            Some(Operand::register(Register::Rcx, OperandSize::Qword)),
            None,
        ]);
    }

    #[test]
    fn decodes_lfence_and_preserves_gs_memory_override() {
        let fence = decode(&[0x0f, 0xae, 0xe8]).unwrap();
        assert_eq!(fence.mnemonic, Mnemonic::Fence);

        let mov = decode(&[0x65, 0x48, 0x89, 0x24, 0x25, 0x88, 0, 0, 0]).unwrap();
        let memory = mov.operands[0]
            .and_then(|operand| match operand {
                Operand::Memory(memory) => Some(memory),
                _ => None,
            })
            .expect("expected memory destination");
        assert_eq!(memory.segment, Some(0x65));
        assert_eq!(memory.displacement, 0x88);
    }

    #[test]
    fn decodes_movsxd_into_a_qword_register() {
        let instruction = decode(&[0x48, 0x63, 0xc7]).unwrap();
        assert_eq!(instruction.mnemonic, Mnemonic::Movsx);
        assert_eq!(instruction.operands, [
            Some(Operand::register(Register::Rax, OperandSize::Qword)),
            Some(Operand::register(Register::Rdi, OperandSize::Dword)),
            None,
        ]);
    }

    #[test]
    fn decodes_legacy_fpu_state_instructions_and_clts() {
        assert_eq!(decode(&[0x0f, 0x06]).unwrap().mnemonic, Mnemonic::Clts);
        assert_eq!(decode(&[0x0f, 0x09]).unwrap().mnemonic, Mnemonic::Wbinvd);
        assert_eq!(decode(&[0xdb, 0xe3]).unwrap().mnemonic, Mnemonic::Fninit);

        let save = decode(&[0x0f, 0xae, 0x07]).unwrap();
        assert_eq!(save.mnemonic, Mnemonic::Fxsave);
        assert_eq!(save.length, 3);
        assert!(matches!(save.operands[0], Some(Operand::Memory(_))));

        let save64 = decode(&[0x48, 0x0f, 0xae, 0x07]).unwrap();
        assert_eq!(save64.mnemonic, Mnemonic::Fxsave);
        assert_eq!(save64.length, 4);

        let restore = decode(&[0x0f, 0xae, 0x0e]).unwrap();
        assert_eq!(restore.mnemonic, Mnemonic::Fxrstor);
        assert!(matches!(restore.operands[0], Some(Operand::Memory(_))));

        assert!(matches!(
            decode(&[0x0f, 0xae, 0xc0]),
            Err(DecodeError {
                kind: DecodeErrorKind::UnsupportedOpcode,
                ..
            })
        ));
    }
}
