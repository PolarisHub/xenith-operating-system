use std::process::ExitCode;
use std::{env, fs};

use xenith_x86::{decode, Instruction, MemoryOperand, Operand, OperandSize, Register};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xenith-disasm: {error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut base = 0u64;
    let mut input = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--base" => base = parse_number(&arguments.next().ok_or("--base needs a value")?)?,
            "--help" | "-h" => {
                println!("xenith-disasm [--base address] <binary>");
                return Ok(());
            },
            value if input.is_none() => input = Some(value.to_string()),
            value => return Err(format!("unexpected argument {value}").into()),
        }
    }
    let bytes = fs::read(input.ok_or("missing input file")?)?;
    let mut offset = 0;
    while offset < bytes.len() {
        match decode(&bytes[offset..]) {
            Ok(instruction) => {
                let length = usize::from(instruction.length);
                let encoded = bytes[offset..offset + length]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                println!(
                    "{:016x}  {:<31} {}",
                    base + offset as u64,
                    encoded,
                    format_instruction(&instruction)
                );
                offset += length;
            },
            Err(_) => {
                println!(
                    "{:016x}  {:02x}                              .byte 0x{:02x}",
                    base + offset as u64,
                    bytes[offset],
                    bytes[offset]
                );
                offset += 1;
            },
        }
    }
    Ok(())
}

fn format_instruction(instruction: &Instruction) -> String {
    let mnemonic = format!("{:?}", instruction.mnemonic).to_ascii_lowercase();
    let operands = instruction
        .operands
        .iter()
        .flatten()
        .copied()
        .map(format_operand)
        .collect::<Vec<_>>();
    if operands.is_empty() {
        mnemonic
    } else {
        format!("{mnemonic} {}", operands.join(", "))
    }
}

fn format_operand(operand: Operand) -> String {
    match operand {
        Operand::Register {
            register,
            size,
            high8,
        } => register_name(register, size, high8).to_string(),
        Operand::Immediate { value, .. } => format!("0x{value:x}"),
        Operand::Relative { displacement, .. } => format!("{displacement:+#x}"),
        Operand::Control { index } => format!("cr{index}"),
        Operand::Segment { index } => ["es", "cs", "ss", "ds", "fs", "gs"]
            .get(usize::from(index))
            .copied()
            .unwrap_or("?s")
            .to_string(),
        Operand::Memory(memory) => format_memory(memory),
    }
}

fn format_memory(memory: MemoryOperand) -> String {
    let mut terms = Vec::new();
    if memory.rip_relative {
        terms.push("rip".to_string());
    }
    if let Some(base) = memory.base {
        terms.push(register_name(base, OperandSize::Qword, false).to_string());
    }
    if let Some(index) = memory.index {
        terms.push(format!(
            "{}*{}",
            register_name(index, OperandSize::Qword, false),
            memory.scale
        ));
    }
    if memory.displacement != 0 || terms.is_empty() {
        terms.push(format!("{:+#x}", memory.displacement));
    }
    format!("[{}]", terms.join(" + ").replace("+ -", "- "))
}

fn register_name(register: Register, size: OperandSize, high8: bool) -> &'static str {
    if high8 {
        return match register {
            Register::Rsp => "ah",
            Register::Rbp => "ch",
            Register::Rsi => "dh",
            Register::Rdi => "bh",
            _ => "?h",
        };
    }
    const Q: [&str; 16] = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];
    const D: [&str; 16] = [
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
        "r12d", "r13d", "r14d", "r15d",
    ];
    const W: [&str; 16] = [
        "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w",
        "r13w", "r14w", "r15w",
    ];
    const B: [&str; 16] = [
        "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b",
        "r13b", "r14b", "r15b",
    ];
    [B, W, D, Q][match size {
        OperandSize::Byte => 0,
        OperandSize::Word => 1,
        OperandSize::Dword => 2,
        _ => 3,
    }][usize::from(register.index())]
}

fn parse_number(value: &str) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)?
    } else {
        value.parse()?
    })
}
