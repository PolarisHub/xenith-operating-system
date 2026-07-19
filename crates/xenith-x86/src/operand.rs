//! Typed instruction operands.

use crate::Register;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OperandSize {
    Byte = 1,
    Word = 2,
    Dword = 4,
    Qword = 8,
    Oword = 16,
}

impl OperandSize {
    #[must_use]
    pub const fn bits(self) -> u8 {
        (self as u8) * 8
    }

    #[must_use]
    pub const fn mask(self) -> u64 {
        match self {
            Self::Byte => 0xFF,
            Self::Word => 0xFFFF,
            Self::Dword => 0xFFFF_FFFF,
            Self::Qword | Self::Oword => u64::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryOperand {
    pub base: Option<Register>,
    pub index: Option<Register>,
    pub scale: u8,
    pub displacement: i64,
    pub rip_relative: bool,
    /// Explicit segment-override prefix byte, when present.
    pub segment: Option<u8>,
    pub size: OperandSize,
}

impl MemoryOperand {
    #[must_use]
    pub const fn new(size: OperandSize) -> Self {
        Self {
            base: None,
            index: None,
            scale: 1,
            displacement: 0,
            rip_relative: false,
            segment: None,
            size,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operand {
    Register {
        register: Register,
        size: OperandSize,
        high8: bool,
    },
    Memory(MemoryOperand),
    Immediate {
        value: u64,
        size: OperandSize,
    },
    Relative {
        displacement: i64,
        size: OperandSize,
    },
    Control {
        index: u8,
    },
    Segment {
        index: u8,
    },
}

impl Operand {
    #[must_use]
    pub const fn register(register: Register, size: OperandSize) -> Self {
        Self::Register {
            register,
            size,
            high8: false,
        }
    }

    #[must_use]
    pub const fn size(self) -> OperandSize {
        match self {
            Self::Register { size, .. }
            | Self::Immediate { size, .. }
            | Self::Relative { size, .. } => size,
            Self::Memory(memory) => memory.size,
            Self::Control { .. } => OperandSize::Qword,
            Self::Segment { .. } => OperandSize::Word,
        }
    }
}
