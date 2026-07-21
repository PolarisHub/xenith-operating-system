//! Instruction and prefix model used by every Xenith x86 tool.

use crate::Operand;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Prefixes {
    pub lock: bool,
    pub repeat: bool,
    pub repeat_not_equal: bool,
    pub operand_size: bool,
    pub address_size: bool,
    pub segment: Option<u8>,
    /// Whether any REX prefix was present, including the bare `0x40` form.
    ///
    /// The low four REX bits alone cannot represent this distinction, but it
    /// matters for byte registers: a bare REX selects SPL/BPL/SIL/DIL instead
    /// of the legacy AH/CH/DH/BH registers.
    pub rex_present: bool,
    pub rex: u8,
}

impl Prefixes {
    #[must_use]
    pub const fn rex_w(self) -> bool {
        self.rex & 8 != 0
    }

    #[must_use]
    pub const fn rex_r(self) -> u8 {
        (self.rex >> 2) & 1
    }

    #[must_use]
    pub const fn rex_x(self) -> u8 {
        (self.rex >> 1) & 1
    }

    #[must_use]
    pub const fn rex_b(self) -> u8 {
        self.rex & 1
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Condition {
    Overflow,
    NotOverflow,
    Below,
    AboveOrEqual,
    Equal,
    NotEqual,
    BelowOrEqual,
    Above,
    Sign,
    NotSign,
    Parity,
    NotParity,
    Less,
    GreaterOrEqual,
    LessOrEqual,
    Greater,
}

impl Condition {
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code & 15 {
            0 => Self::Overflow,
            1 => Self::NotOverflow,
            2 => Self::Below,
            3 => Self::AboveOrEqual,
            4 => Self::Equal,
            5 => Self::NotEqual,
            6 => Self::BelowOrEqual,
            7 => Self::Above,
            8 => Self::Sign,
            9 => Self::NotSign,
            10 => Self::Parity,
            11 => Self::NotParity,
            12 => Self::Less,
            13 => Self::GreaterOrEqual,
            14 => Self::LessOrEqual,
            _ => Self::Greater,
        }
    }

    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mnemonic {
    Nop,
    /// LFENCE/MFENCE/SFENCE. Execution is a serialization point.
    Fence,
    Hlt,
    Cli,
    Sti,
    Cld,
    Std,
    Int3,
    /// CLTS: clear CR0.TS at CPL0.
    Clts,
    /// WBINVD: write back modified cache lines and invalidate all caches.
    Wbinvd,
    /// FNINIT: reset the architectural x87 state.
    Fninit,
    /// FXSAVE/FXSAVE64 legacy 512-byte state image.
    Fxsave,
    /// FXRSTOR/FXRSTOR64 legacy 512-byte state image.
    Fxrstor,
    Mov,
    Xchg,
    Movzx,
    Movsx,
    /// CWD/CDQ/CQO: sign-extend the accumulator into the high register.
    SignExtendAccumulator,
    Lea,
    Add,
    Adc,
    Sub,
    Sbb,
    And,
    Or,
    Xor,
    Cmp,
    Cmpxchg,
    Xadd,
    Bswap,
    Bsf,
    Bsr,
    Bt,
    Bts,
    Btr,
    Btc,
    Test,
    Inc,
    Dec,
    Not,
    Neg,
    Mul,
    Imul,
    Div,
    Idiv,
    Shl,
    Shld,
    Shr,
    Sar,
    Rol,
    Ror,
    Push,
    Pop,
    PushFlags,
    PopFlags,
    Call,
    Return,
    ReturnFar,
    Jump,
    JumpCondition(Condition),
    MoveCondition(Condition),
    SetCondition(Condition),
    In,
    Out,
    Cpuid,
    Rdmsr,
    Wrmsr,
    Rdtsc,
    Syscall,
    Sysret,
    Swapgs,
    Lgdt,
    Lidt,
    Ltr,
    Invlpg,
    Iretq,
    Leave,
    Movs,
    Stos,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Instruction {
    pub mnemonic: Mnemonic,
    pub operands: [Option<Operand>; 3],
    pub prefixes: Prefixes,
    pub length: u8,
}

impl Instruction {
    #[must_use]
    pub const fn new(mnemonic: Mnemonic) -> Self {
        Self {
            mnemonic,
            operands: [None, None, None],
            prefixes: Prefixes {
                lock: false,
                repeat: false,
                repeat_not_equal: false,
                operand_size: false,
                address_size: false,
                segment: None,
                rex_present: false,
                rex: 0,
            },
            length: 0,
        }
    }

    #[must_use]
    pub const fn with_operands(mut self, first: Operand, second: Option<Operand>) -> Self {
        self.operands[0] = Some(first);
        self.operands[1] = second;
        self
    }

    #[must_use]
    pub const fn with_three_operands(
        mut self,
        first: Operand,
        second: Operand,
        third: Operand,
    ) -> Self {
        self.operands = [Some(first), Some(second), Some(third)];
        self
    }
}
