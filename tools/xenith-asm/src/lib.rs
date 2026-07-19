//! Converging multi-pass x86 assembler used for Xenith freestanding sources.

use std::collections::BTreeMap;
use std::fmt;

use xenith_x86::{
    encode, Condition, Instruction, MemoryOperand, Mnemonic, Operand, OperandSize, Register,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssemblerError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for AssemblerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for AssemblerError {}

pub fn assemble(source: &str) -> Result<Vec<u8>, AssemblerError> {
    let mut labels = BTreeMap::new();
    let mut converged = false;
    for _ in 0..128 {
        let (_, definitions) = pass(source, &labels, true)?;
        if definitions == labels {
            converged = true;
            break;
        }
        labels = definitions;
    }
    if !converged {
        return Err(error(0, "symbol layout did not converge"));
    }
    let (output, definitions) = pass(source, &labels, false)?;
    if definitions != labels {
        return Err(error(0, "symbol layout changed during final emission"));
    }
    Ok(output)
}

fn pass(
    source: &str,
    labels: &BTreeMap<String, u64>,
    allow_unknown: bool,
) -> Result<(Vec<u8>, BTreeMap<String, u64>), AssemblerError> {
    let mut output = Vec::new();
    let mut definitions = BTreeMap::new();
    for (index, raw) in source.lines().enumerate() {
        let line_number = index + 1;
        let mut line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some((label, rest)) = split_label(line) {
            if definitions
                .insert(label.to_string(), output.len() as u64)
                .is_some()
            {
                return Err(error(line_number, format!("duplicate label {label}")));
            }
            line = rest.trim();
            if line.is_empty() {
                continue;
            }
        }
        if line.starts_with('.')
            || line.starts_with("db ")
            || line.starts_with("dw ")
            || line.starts_with("dd ")
            || line.starts_with("dq ")
        {
            directive(line, &mut output, line_number, labels, allow_unknown)?;
        } else {
            instruction(line, &mut output, line_number, labels, allow_unknown)?;
        }
    }
    Ok((output, definitions))
}

fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote.is_some() {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
        } else if quote.is_none() && matches!(character, ';' | '#') {
            return &line[..index];
        }
    }
    line
}

fn split_label(line: &str) -> Option<(&str, &str)> {
    let colon = line.find(':')?;
    let candidate = line[..colon].trim();
    if candidate.is_empty()
        || !candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'$'))
    {
        return None;
    }
    Some((candidate, &line[colon + 1..]))
}

fn directive(
    line: &str,
    output: &mut Vec<u8>,
    line_number: usize,
    labels: &BTreeMap<String, u64>,
    collect: bool,
) -> Result<(), AssemblerError> {
    let (name, arguments) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    match name.to_ascii_lowercase().as_str() {
        ".bits" => {
            if arguments.trim() == "64" {
                Ok(())
            } else {
                Err(error(
                    line_number,
                    "only 64-bit assembly mode is implemented",
                ))
            }
        },
        ".code64" | ".text" | ".data" | ".section" | ".global" | ".globl" | ".extern"
        | ".hidden" | ".type" | ".size" | ".ident" | ".intel_syntax" => Ok(()),
        ".code16" | ".code32" => Err(error(
            line_number,
            "16/32-bit encoding is not implemented; refusing to emit mislabeled 64-bit code",
        )),
        ".org" => {
            let address = value(arguments.trim(), labels, collect, line_number)? as usize;
            if address < output.len() {
                return Err(error(line_number, ".org moves backwards"));
            }
            output.resize(address, 0);
            Ok(())
        },
        ".align" | ".balign" | ".p2align" => {
            let first = split_arguments(arguments)
                .first()
                .copied()
                .ok_or_else(|| error(line_number, "missing alignment"))?;
            let raw = value(first, labels, collect, line_number)? as usize;
            let align = if name.eq_ignore_ascii_case(".p2align") {
                1usize
                    .checked_shl(raw as u32)
                    .ok_or_else(|| error(line_number, "alignment overflow"))?
            } else {
                raw
            };
            if align == 0 || !align.is_power_of_two() {
                return Err(error(line_number, "alignment must be a power of two"));
            }
            output.resize((output.len() + align - 1) & !(align - 1), 0);
            Ok(())
        },
        ".byte" | "db" => emit_values(arguments, 1, output, labels, collect, line_number),
        ".word" | ".short" | "dw" => {
            emit_values(arguments, 2, output, labels, collect, line_number)
        },
        ".long" | ".int" | "dd" => emit_values(arguments, 4, output, labels, collect, line_number),
        ".quad" | "dq" => emit_values(arguments, 8, output, labels, collect, line_number),
        ".ascii" | ".asciz" | ".string" => {
            let bytes =
                parse_string(arguments.trim()).map_err(|message| error(line_number, message))?;
            output.extend_from_slice(&bytes);
            if name.eq_ignore_ascii_case(".asciz") || name.eq_ignore_ascii_case(".string") {
                output.push(0);
            }
            Ok(())
        },
        ".zero" => {
            let count = value(arguments.trim(), labels, collect, line_number)? as usize;
            output.resize(
                output
                    .len()
                    .checked_add(count)
                    .ok_or_else(|| error(line_number, "size overflow"))?,
                0,
            );
            Ok(())
        },
        ".fill" => {
            let fields = split_arguments(arguments);
            let count = value(
                fields.first().copied().unwrap_or("0"),
                labels,
                collect,
                line_number,
            )? as usize;
            let width = value(
                fields.get(1).copied().unwrap_or("1"),
                labels,
                collect,
                line_number,
            )? as usize;
            if !matches!(width, 1 | 2 | 4 | 8) {
                return Err(error(line_number, ".fill width must be 1, 2, 4, or 8"));
            }
            let fill = value(
                fields.get(2).copied().unwrap_or("0"),
                labels,
                collect,
                line_number,
            )?;
            for _ in 0..count {
                output.extend((0..width).map(|byte| (fill >> (byte * 8)) as u8));
            }
            Ok(())
        },
        _ => Err(error(line_number, format!("unknown directive {name}"))),
    }
}

fn emit_values(
    arguments: &str,
    width: usize,
    output: &mut Vec<u8>,
    labels: &BTreeMap<String, u64>,
    collect: bool,
    line_number: usize,
) -> Result<(), AssemblerError> {
    for argument in split_arguments(arguments) {
        if width == 1 && (argument.starts_with('"') || argument.starts_with('\'')) {
            output.extend_from_slice(
                &parse_string(argument).map_err(|message| error(line_number, message))?,
            );
            continue;
        }
        let number = value(argument, labels, collect, line_number)?;
        output.extend((0..width).map(|byte| (number >> (byte * 8)) as u8));
    }
    Ok(())
}

fn instruction(
    line: &str,
    output: &mut Vec<u8>,
    line_number: usize,
    labels: &BTreeMap<String, u64>,
    collect: bool,
) -> Result<(), AssemblerError> {
    let (name, operands) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    let name = name.to_ascii_lowercase();
    let arguments = split_arguments(operands);
    let simple = match name.as_str() {
        "nop" => Some(Mnemonic::Nop),
        "hlt" => Some(Mnemonic::Hlt),
        "cli" => Some(Mnemonic::Cli),
        "sti" => Some(Mnemonic::Sti),
        "int3" => Some(Mnemonic::Int3),
        "ret" | "retq" => Some(Mnemonic::Return),
        "leave" | "leaveq" => Some(Mnemonic::Leave),
        "iretq" => Some(Mnemonic::Iretq),
        "syscall" => Some(Mnemonic::Syscall),
        "sysret" | "sysretq" => Some(Mnemonic::Sysret),
        "cpuid" => Some(Mnemonic::Cpuid),
        "rdmsr" => Some(Mnemonic::Rdmsr),
        "wrmsr" => Some(Mnemonic::Wrmsr),
        "swapgs" => Some(Mnemonic::Swapgs),
        _ => None,
    };
    let mut instruction = if let Some(mnemonic) = simple {
        if !arguments.is_empty() {
            return Err(error(line_number, "instruction takes no operands"));
        }
        Instruction::new(mnemonic)
    } else if matches!(name.as_str(), "push" | "pushq" | "pop" | "popq") {
        let argument = arguments
            .first()
            .ok_or_else(|| error(line_number, "missing operand"))?;
        let operand = if name.starts_with("pop") {
            parse_register(argument).ok_or_else(|| error(line_number, "pop expects a register"))?
        } else if let Some(register) = parse_register(argument) {
            register
        } else {
            Operand::Immediate {
                value: value(argument, labels, collect, line_number)?,
                size: OperandSize::Qword,
            }
        };
        Instruction::new(if name.starts_with("push") {
            Mnemonic::Push
        } else {
            Mnemonic::Pop
        })
        .with_operands(operand, None)
    } else if name == "mov" || name.starts_with("mov") {
        if arguments.len() != 2 {
            return Err(error(line_number, "mov needs two operands"));
        }
        let destination = parse_operand(
            arguments[0],
            declared_size(arguments[1]).unwrap_or(OperandSize::Qword),
            labels,
            collect,
            line_number,
        )?;
        let source = parse_operand(
            arguments[1],
            destination.size(),
            labels,
            collect,
            line_number,
        )?;
        if destination.size() != source.size() {
            return Err(error(line_number, "mov operand widths differ"));
        }
        Instruction::new(Mnemonic::Mov).with_operands(destination, Some(source))
    } else if name == "lea" || name == "leaq" || name == "leal" {
        if arguments.len() != 2 {
            return Err(error(line_number, "lea needs two operands"));
        }
        let destination = parse_register(arguments[0])
            .ok_or_else(|| error(line_number, "lea destination must be a register"))?;
        let source = parse_memory(
            arguments[1],
            destination.size(),
            labels,
            collect,
            line_number,
        )?;
        Instruction::new(Mnemonic::Lea).with_operands(destination, Some(source))
    } else if let Some(mnemonic) = binary_mnemonic(&name) {
        if arguments.len() != 2 {
            return Err(error(line_number, "binary instruction needs two operands"));
        }
        let destination = parse_operand(
            arguments[0],
            declared_size(arguments[1]).unwrap_or(OperandSize::Qword),
            labels,
            collect,
            line_number,
        )?;
        let source = parse_operand(
            arguments[1],
            destination.size(),
            labels,
            collect,
            line_number,
        )?;
        if destination.size() != source.size() {
            return Err(error(line_number, "operand widths differ"));
        }
        Instruction::new(mnemonic).with_operands(destination, Some(source))
    } else if name == "bswap" {
        if arguments.len() != 1 {
            return Err(error(line_number, "bswap needs one register"));
        }
        let operand = parse_register(arguments[0])
            .ok_or_else(|| error(line_number, "bswap expects a register"))?;
        Instruction::new(Mnemonic::Bswap).with_operands(operand, None)
    } else if matches!(
        name.as_str(),
        "inc" | "incq" | "dec" | "decq" | "neg" | "negq" | "not" | "notq"
    ) {
        if arguments.len() != 1 {
            return Err(error(line_number, "unary instruction needs one operand"));
        }
        let operand = parse_operand(
            arguments[0],
            suffix_size(&name).unwrap_or(OperandSize::Qword),
            labels,
            collect,
            line_number,
        )?;
        let mnemonic = if name.starts_with("inc") {
            Mnemonic::Inc
        } else if name.starts_with("dec") {
            Mnemonic::Dec
        } else if name.starts_with("neg") {
            Mnemonic::Neg
        } else {
            Mnemonic::Not
        };
        Instruction::new(mnemonic).with_operands(operand, None)
    } else if matches!(name.as_str(), "imul" | "imulq" | "imull") {
        if arguments.len() != 2 {
            return Err(error(line_number, "imul needs two operands"));
        }
        let destination = parse_register(arguments[0])
            .ok_or_else(|| error(line_number, "imul destination must be a register"))?;
        let source = parse_operand(
            arguments[1],
            destination.size(),
            labels,
            collect,
            line_number,
        )?;
        Instruction::new(Mnemonic::Imul).with_operands(destination, Some(source))
    } else if matches!(name.as_str(), "jmp" | "call") || condition(&name).is_some() {
        if arguments.len() != 1 {
            return Err(error(line_number, "branch needs one target"));
        }
        let mnemonic = if name == "jmp" {
            Mnemonic::Jump
        } else if name == "call" {
            Mnemonic::Call
        } else {
            Mnemonic::JumpCondition(condition(&name).expect("condition checked"))
        };
        let length = if matches!(mnemonic, Mnemonic::JumpCondition(_)) {
            6
        } else {
            5
        };
        let target = value(arguments[0], labels, collect, line_number)?;
        let displacement = target.wrapping_sub(output.len() as u64 + length) as i64;
        Instruction::new(mnemonic).with_operands(
            Operand::Relative {
                displacement,
                size: OperandSize::Dword,
            },
            None,
        )
    } else {
        return Err(error(line_number, format!("unknown instruction {name}")));
    };
    let mut bytes = [0u8; 16];
    let length = encode(&instruction, &mut bytes).map_err(|failure| {
        error(
            line_number,
            format!("cannot encode instruction: {failure:?}"),
        )
    })?;
    let next_ip = output
        .len()
        .checked_add(length)
        .ok_or_else(|| error(line_number, "instruction address overflow"))?;
    let mut adjusted_rip = false;
    for (index, argument) in arguments.iter().copied().enumerate() {
        let Some(Operand::Memory(mut memory)) = instruction.operands.get(index).copied().flatten()
        else {
            continue;
        };
        if !memory.rip_relative || !rip_uses_symbol(argument) {
            continue;
        }
        memory.displacement = i64::try_from(i128::from(memory.displacement) - next_ip as i128)
            .map_err(|_| error(line_number, "RIP-relative displacement overflow"))?;
        instruction.operands[index] = Some(Operand::Memory(memory));
        adjusted_rip = true;
    }
    if adjusted_rip {
        let adjusted_length = encode(&instruction, &mut bytes).map_err(|failure| {
            error(
                line_number,
                format!("cannot encode RIP-relative instruction: {failure:?}"),
            )
        })?;
        if adjusted_length != length {
            return Err(error(
                line_number,
                "RIP-relative fixup changed instruction length",
            ));
        }
    }
    output.extend_from_slice(&bytes[..length]);
    Ok(())
}

fn rip_uses_symbol(token: &str) -> bool {
    let Some(inside) = token
        .split_once('[')
        .and_then(|(_, rest)| rest.rsplit_once(']').map(|(inside, _)| inside))
    else {
        return false;
    };
    inside.replace('-', "+-").split('+').any(|raw| {
        let term = raw.trim().trim_start_matches('-').trim();
        if term.is_empty()
            || term.eq_ignore_ascii_case("rip")
            || parse_register(term).is_some()
            || term.contains('*')
        {
            return false;
        }
        term.bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'.' | b'$'))
    })
}

fn binary_mnemonic(name: &str) -> Option<Mnemonic> {
    let base = match name {
        "add" | "adc" | "sub" | "sbb" | "and" | "or" | "xor" | "cmp" | "test" => name,
        _ if suffix_size(name).is_some() => &name[..name.len() - 1],
        _ => name,
    };
    Some(match base {
        "add" => Mnemonic::Add,
        "adc" => Mnemonic::Adc,
        "sub" => Mnemonic::Sub,
        "sbb" => Mnemonic::Sbb,
        "and" => Mnemonic::And,
        "or" => Mnemonic::Or,
        "xor" => Mnemonic::Xor,
        "cmp" => Mnemonic::Cmp,
        "test" => Mnemonic::Test,
        _ => return None,
    })
}

fn suffix_size(name: &str) -> Option<OperandSize> {
    Some(match name.as_bytes().last().copied()? {
        b'b' => OperandSize::Byte,
        b'w' => OperandSize::Word,
        b'l' => OperandSize::Dword,
        b'q' => OperandSize::Qword,
        _ => return None,
    })
}

fn condition(name: &str) -> Option<Condition> {
    Some(match name {
        "jo" => Condition::Overflow,
        "jno" => Condition::NotOverflow,
        "jb" | "jc" | "jnae" => Condition::Below,
        "jae" | "jnb" | "jnc" => Condition::AboveOrEqual,
        "je" | "jz" => Condition::Equal,
        "jne" | "jnz" => Condition::NotEqual,
        "jbe" | "jna" => Condition::BelowOrEqual,
        "ja" | "jnbe" => Condition::Above,
        "js" => Condition::Sign,
        "jns" => Condition::NotSign,
        "jp" | "jpe" => Condition::Parity,
        "jnp" | "jpo" => Condition::NotParity,
        "jl" | "jnge" => Condition::Less,
        "jge" | "jnl" => Condition::GreaterOrEqual,
        "jle" | "jng" => Condition::LessOrEqual,
        "jg" | "jnle" => Condition::Greater,
        _ => return None,
    })
}

fn parse_register(token: &str) -> Option<Operand> {
    let token = token.trim().trim_start_matches('%').to_ascii_lowercase();
    let (register, size) = match token.as_str() {
        "rax" => (Register::Rax, OperandSize::Qword),
        "eax" => (Register::Rax, OperandSize::Dword),
        "ax" => (Register::Rax, OperandSize::Word),
        "al" => (Register::Rax, OperandSize::Byte),
        "rcx" => (Register::Rcx, OperandSize::Qword),
        "ecx" => (Register::Rcx, OperandSize::Dword),
        "cx" => (Register::Rcx, OperandSize::Word),
        "cl" => (Register::Rcx, OperandSize::Byte),
        "rdx" => (Register::Rdx, OperandSize::Qword),
        "edx" => (Register::Rdx, OperandSize::Dword),
        "dx" => (Register::Rdx, OperandSize::Word),
        "dl" => (Register::Rdx, OperandSize::Byte),
        "rbx" => (Register::Rbx, OperandSize::Qword),
        "ebx" => (Register::Rbx, OperandSize::Dword),
        "bx" => (Register::Rbx, OperandSize::Word),
        "bl" => (Register::Rbx, OperandSize::Byte),
        "rsp" => (Register::Rsp, OperandSize::Qword),
        "esp" => (Register::Rsp, OperandSize::Dword),
        "sp" => (Register::Rsp, OperandSize::Word),
        "spl" => (Register::Rsp, OperandSize::Byte),
        "rbp" => (Register::Rbp, OperandSize::Qword),
        "ebp" => (Register::Rbp, OperandSize::Dword),
        "bp" => (Register::Rbp, OperandSize::Word),
        "bpl" => (Register::Rbp, OperandSize::Byte),
        "rsi" => (Register::Rsi, OperandSize::Qword),
        "esi" => (Register::Rsi, OperandSize::Dword),
        "si" => (Register::Rsi, OperandSize::Word),
        "sil" => (Register::Rsi, OperandSize::Byte),
        "rdi" => (Register::Rdi, OperandSize::Qword),
        "edi" => (Register::Rdi, OperandSize::Dword),
        "di" => (Register::Rdi, OperandSize::Word),
        "dil" => (Register::Rdi, OperandSize::Byte),
        _ if token.starts_with('r') => {
            let digits = token[1..].trim_end_matches(['b', 'w', 'd']);
            let index: u8 = digits.parse().ok()?;
            if !(8..=15).contains(&index) {
                return None;
            }
            let size = if token.ends_with('b') {
                OperandSize::Byte
            } else if token.ends_with('w') {
                OperandSize::Word
            } else if token.ends_with('d') {
                OperandSize::Dword
            } else {
                OperandSize::Qword
            };
            (Register::from_index(index), size)
        },
        _ => return None,
    };
    Some(Operand::register(register, size))
}

fn declared_size(token: &str) -> Option<OperandSize> {
    if let Some(register) = parse_register(token) {
        return Some(register.size());
    }
    memory_size_prefix(token).map(|(size, _)| size)
}

fn memory_size_prefix(token: &str) -> Option<(OperandSize, &str)> {
    let token = token.trim();
    for (name, size) in [
        ("byte", OperandSize::Byte),
        ("word", OperandSize::Word),
        ("dword", OperandSize::Dword),
        ("qword", OperandSize::Qword),
    ] {
        let Some(rest) = token.strip_prefix(name) else {
            continue;
        };
        let rest = rest.trim_start();
        let rest = rest.strip_prefix("ptr").map_or(rest, str::trim_start);
        return Some((size, rest));
    }
    None
}

fn parse_operand(
    token: &str,
    default_size: OperandSize,
    labels: &BTreeMap<String, u64>,
    collect: bool,
    line: usize,
) -> Result<Operand, AssemblerError> {
    if let Some(register) = parse_register(token) {
        return Ok(register);
    }
    if token.contains('[') {
        return parse_memory(token, default_size, labels, collect, line);
    }
    Ok(Operand::Immediate {
        value: value(token, labels, collect, line)?,
        size: default_size,
    })
}

fn parse_memory(
    token: &str,
    default_size: OperandSize,
    labels: &BTreeMap<String, u64>,
    collect: bool,
    line: usize,
) -> Result<Operand, AssemblerError> {
    let (size, mut token) = memory_size_prefix(token).unwrap_or((default_size, token.trim()));
    let mut segment = None;
    if let Some(rest) = token.strip_prefix("fs:") {
        segment = Some(0x64);
        token = rest.trim_start();
    } else if let Some(rest) = token.strip_prefix("gs:") {
        segment = Some(0x65);
        token = rest.trim_start();
    }
    let inside = token
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or_else(|| error(line, "memory operand must be enclosed in []"))?;
    let normalized = inside.replace('-', "+-");
    let mut memory = MemoryOperand::new(size);
    memory.segment = segment;
    for raw_term in normalized.split('+') {
        let term = raw_term.trim();
        if term.is_empty() {
            continue;
        }
        let (negative, term) = term
            .strip_prefix('-')
            .map_or((false, term), |rest| (true, rest.trim()));
        if let Some((register_name, scale_text)) = term.split_once('*') {
            if negative || memory.index.is_some() {
                return Err(error(line, "invalid scaled-index expression"));
            }
            let Operand::Register { register, .. } = parse_register(register_name.trim())
                .ok_or_else(|| error(line, "invalid index register"))?
            else {
                unreachable!();
            };
            let scale = value(scale_text.trim(), labels, collect, line)? as u8;
            if !matches!(scale, 1 | 2 | 4 | 8) {
                return Err(error(line, "memory scale must be 1, 2, 4, or 8"));
            }
            memory.index = Some(register);
            memory.scale = scale;
            continue;
        }
        if term.eq_ignore_ascii_case("rip") {
            if negative {
                return Err(error(line, "register terms cannot be negative"));
            }
            if memory.rip_relative || memory.base.is_some() || memory.index.is_some() {
                return Err(error(line, "RIP-relative addressing cannot use base/index"));
            }
            memory.rip_relative = true;
            continue;
        }
        if let Some(Operand::Register { register, .. }) = parse_register(term) {
            if negative {
                return Err(error(line, "register terms cannot be negative"));
            }
            if memory.base.is_none() {
                memory.base = Some(register);
            } else if memory.index.is_none() {
                memory.index = Some(register);
            } else {
                return Err(error(line, "too many registers in memory operand"));
            }
            continue;
        }
        let raw = value(term, labels, collect, line)? as i64;
        memory.displacement = if negative {
            memory
                .displacement
                .checked_sub(raw)
                .ok_or_else(|| error(line, "memory displacement overflow"))?
        } else {
            memory
                .displacement
                .checked_add(raw)
                .ok_or_else(|| error(line, "memory displacement overflow"))?
        };
    }
    if memory.rip_relative && (memory.base.is_some() || memory.index.is_some()) {
        return Err(error(line, "RIP-relative addressing cannot use base/index"));
    }
    Ok(Operand::Memory(memory))
}

fn value(
    token: &str,
    labels: &BTreeMap<String, u64>,
    collect: bool,
    line: usize,
) -> Result<u64, AssemblerError> {
    let token = token.trim().trim_start_matches('$');
    if let Some(value) = labels.get(token) {
        return Ok(*value);
    }
    if collect
        && token
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'.'))
    {
        return Ok(0);
    }
    let (negative, token) = token
        .strip_prefix('-')
        .map_or((false, token), |rest| (true, rest));
    let parsed = if let Some(hex) = token.strip_prefix("0x") {
        u64::from_str_radix(hex.replace('_', "").as_str(), 16)
    } else if let Some(binary) = token.strip_prefix("0b") {
        u64::from_str_radix(binary.replace('_', "").as_str(), 2)
    } else {
        token.replace('_', "").parse()
    }
    .map_err(|_| error(line, format!("unknown value {token}")))?;
    Ok(if negative {
        0u64.wrapping_sub(parsed)
    } else {
        parsed
    })
}

fn split_arguments(arguments: &str) -> Vec<&str> {
    let mut output = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in arguments.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote.is_some() {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
        } else if character == ',' && quote.is_none() {
            output.push(arguments[start..index].trim());
            start = index + 1;
        }
    }
    let tail = arguments[start..].trim();
    if !tail.is_empty() {
        output.push(tail);
    }
    output
}

fn parse_string(token: &str) -> Result<Vec<u8>, String> {
    let quote = token.as_bytes().first().copied().ok_or("empty string")?;
    if !matches!(quote, b'\'' | b'"') || token.as_bytes().last().copied() != Some(quote) {
        return Err("unterminated string".to_string());
    }
    let mut output = Vec::new();
    let mut bytes = token.as_bytes()[1..token.len() - 1].iter().copied();
    while let Some(byte) = bytes.next() {
        if byte != b'\\' {
            output.push(byte);
            continue;
        }
        let escaped = bytes.next().ok_or("trailing escape")?;
        output.push(match escaped {
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'0' => 0,
            b'\\' => b'\\',
            b'\'' => b'\'',
            b'"' => b'"',
            _ => return Err(format!("unknown escape \\{}", escaped as char)),
        });
    }
    Ok(output)
}

fn error(line: usize, message: impl Into<String>) -> AssemblerError {
    AssemblerError {
        line,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembles_labels_data_and_code() {
        let bytes =
            assemble(".org 2\nstart: mov rax, 0x1234\nxor rbx, rbx\njne start\n.byte 0x55, 0xaa")
                .unwrap();
        assert_eq!(&bytes[..2], &[0, 0]);
        assert_eq!(&bytes[2..4], &[0x48, 0xB8]);
        assert_eq!(&bytes[bytes.len() - 2..], &[0x55, 0xAA]);
    }

    #[test]
    fn string_escapes_are_decoded() {
        assert_eq!(assemble(".ascii \"a\\n\"").unwrap(), b"a\n");
    }

    #[test]
    fn assembles_stack_memory_sib_immediates_and_unary_operations() {
        let bytes = assemble(
            ".code64\n\
             push rbp\n\
             mov rbp, rsp\n\
             sub rsp, 16\n\
             mov qword ptr [rbp-8], 42\n\
             mov rax, qword ptr [rbp-8]\n\
             lea rdx, [rdi+rcx*4+16]\n\
             imul rax, rdx\n\
             inc qword ptr [rbp-8]\n\
             leave\n\
             ret",
        )
        .unwrap();
        assert!(bytes
            .windows(7)
            .any(|window| window == [0x48, 0x81, 0xEC, 16, 0, 0, 0]));
        assert!(bytes
            .windows(8)
            .any(|window| window == [0x48, 0xC7, 0x45, 0xF8, 42, 0, 0, 0]));
        assert!(bytes
            .windows(4)
            .any(|window| window == [0x48, 0x8B, 0x45, 0xF8]));
        assert!(bytes
            .windows(5)
            .any(|window| window == [0x48, 0x8D, 0x54, 0x8F, 16]));
    }

    #[test]
    fn supports_production_alignment_fill_and_rejects_false_modes() {
        let bytes = assemble(".byte 1\n.p2align 3\n.fill 2, 2, 0x1234").unwrap();
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[8..], &[0x34, 0x12, 0x34, 0x12]);
        assert!(assemble(".code32\nret")
            .unwrap_err()
            .message
            .contains("not implemented"));
    }

    #[test]
    fn forward_symbol_memory_displacement_converges_before_emission() {
        let bytes = assemble(
            ".code64\n\
             mov rbx, qword ptr [rax+target]\n\
             .zero 200\n\
             target:\n\
             .quad 0x1122334455667788\n",
        )
        .unwrap();
        assert_eq!(&bytes[..7], &[0x48, 0x8B, 0x98, 0xCF, 0, 0, 0]);
        assert_eq!(bytes.len(), 215);
        assert_eq!(&bytes[207..], &0x1122_3344_5566_7788_u64.to_le_bytes());
    }

    #[test]
    fn resolves_symbolic_rip_relative_memory_from_the_next_instruction() {
        let bytes = assemble(
            ".code64\n\
             lea rax, [rip+message]\n\
             ret\n\
             message:\n\
             .byte 0x5a\n",
        )
        .unwrap();
        assert_eq!(&bytes[..7], &[0x48, 0x8D, 0x05, 1, 0, 0, 0]);
        assert_eq!(&bytes[7..], &[0xC3, 0x5A]);
    }

    #[test]
    fn assembles_dword_and_extended_qword_bswap() {
        assert_eq!(assemble("bswap edx\nbswap r10\n").unwrap(), [
            0x0F, 0xCA, 0x49, 0x0F, 0xCA
        ]);
    }
}
