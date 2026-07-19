//! Shared x86-64 instruction representation, decoder, and encoder.

#![no_std]

mod decode;
mod encode;
mod instruction;
mod operand;
mod register;

pub use decode::{decode, DecodeError, DecodeErrorKind};
pub use encode::{encode, EncodeError};
pub use instruction::{Condition, Instruction, Mnemonic, Prefixes};
pub use operand::{MemoryOperand, Operand, OperandSize};
pub use register::Register;
