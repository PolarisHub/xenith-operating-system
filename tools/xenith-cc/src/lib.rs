//! Small freestanding C compiler used for a shipped Xenith userspace utility.
//!
//! The accepted subset deliberately has runtime semantics rather than being a
//! constant-expression wrapper: signed `long` locals, assignment, arithmetic,
//! comparisons, `if`/`else`, `while`, `return`, and the freestanding
//! `puts("literal")` builtin. The backend emits normal Intel-syntax assembly,
//! assembles it with `xenith-asm`, and asks `xenith-ld` to build W^X-separated
//! text/rodata PT_LOAD segments with real absolute relocations.

use std::collections::BTreeMap;
use std::fmt;

use xenith_ld::{
    link_static, Relocation, RelocationKind, SegmentFlags, StaticLinkOptions, StaticSection,
};

const SYS_WRITE: u64 = 1;
const SYS_EXIT: u64 = 4;
const PLACEHOLDER_BASE: u64 = 0xF0E0_D0C0_B0A0_0000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompileError {
    Lex(String),
    Parse(String),
    DuplicateLocal(String),
    UnknownLocal(String),
    TooManyLiterals,
    MissingRelocationPlaceholder,
    Assemble(xenith_asm::AssemblerError),
    Link(xenith_ld::LinkError),
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lex(message) => write!(formatter, "lex error: {message}"),
            Self::Parse(message) => write!(formatter, "parse error: {message}"),
            Self::DuplicateLocal(name) => write!(formatter, "duplicate local {name:?}"),
            Self::UnknownLocal(name) => write!(formatter, "unknown local {name:?}"),
            Self::TooManyLiterals => formatter.write_str("too many string literals"),
            Self::MissingRelocationPlaceholder => {
                formatter.write_str("assembler omitted a string relocation placeholder")
            },
            Self::Assemble(error) => write!(formatter, "assembly failed: {error}"),
            Self::Link(error) => write!(formatter, "static link failed: {error}"),
        }
    }
}

impl std::error::Error for CompileError {}

impl From<xenith_asm::AssemblerError> for CompileError {
    fn from(value: xenith_asm::AssemblerError) -> Self {
        Self::Assemble(value)
    }
}

impl From<xenith_ld::LinkError> for CompileError {
    fn from(value: xenith_ld::LinkError) -> Self {
        Self::Link(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Identifier(String),
    Number(i64),
    String(Vec<u8>),
    Symbol(String),
    End,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BinaryOp {
    Add,
    Subtract,
    Multiply,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Expr {
    Number(i64),
    Variable(String),
    Negate(Box<Self>),
    Binary(Box<Self>, BinaryOp, Box<Self>),
    Puts(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompareOp {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Condition {
    left: Expr,
    operation: CompareOp,
    right: Expr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Statement {
    Declare(String, Expr),
    Assign(String, Expr),
    Expression(Expr),
    If {
        condition: Condition,
        then_block: Vec<Self>,
        else_block: Vec<Self>,
    },
    While {
        condition: Condition,
        block: Vec<Self>,
    },
    Return(Expr),
}

/// Compile one `int main(void)` program into a static Xenith ELF64 image.
pub fn compile(source: &str) -> Result<Vec<u8>, CompileError> {
    let tokens = lex(source)?;
    let statements = Parser::new(tokens).program()?;
    let mut generator = Generator::new(&statements)?;
    generator.emit_program(&statements)?;
    generator.link()
}

fn lex(source: &str) -> Result<Vec<Token>, CompileError> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes[offset].is_ascii_whitespace() {
            offset += 1;
            continue;
        }
        if bytes[offset..].starts_with(b"//") {
            offset += 2;
            while offset < bytes.len() && bytes[offset] != b'\n' {
                offset += 1;
            }
            continue;
        }
        if bytes[offset..].starts_with(b"/*") {
            let Some(relative) = bytes[offset + 2..]
                .windows(2)
                .position(|window| window == b"*/")
            else {
                return Err(CompileError::Lex("unterminated block comment".to_owned()));
            };
            offset += relative + 4;
            continue;
        }
        if bytes[offset].is_ascii_alphabetic() || bytes[offset] == b'_' {
            let start = offset;
            offset += 1;
            while bytes
                .get(offset)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                offset += 1;
            }
            tokens.push(Token::Identifier(source[start..offset].to_owned()));
            continue;
        }
        if bytes[offset].is_ascii_digit() {
            let start = offset;
            offset += 1;
            if bytes[start] == b'0'
                && bytes
                    .get(offset)
                    .is_some_and(|byte| *byte == b'x' || *byte == b'X')
            {
                offset += 1;
                let digits = offset;
                while bytes.get(offset).is_some_and(u8::is_ascii_hexdigit) {
                    offset += 1;
                }
                if digits == offset {
                    return Err(CompileError::Lex("hex literal needs digits".to_owned()));
                }
                let value = i64::from_str_radix(&source[digits..offset], 16)
                    .map_err(|_| CompileError::Lex("integer literal overflow".to_owned()))?;
                tokens.push(Token::Number(value));
            } else {
                while bytes.get(offset).is_some_and(u8::is_ascii_digit) {
                    offset += 1;
                }
                let value = source[start..offset]
                    .parse::<i64>()
                    .map_err(|_| CompileError::Lex("integer literal overflow".to_owned()))?;
                tokens.push(Token::Number(value));
            }
            continue;
        }
        if bytes[offset] == b'"' {
            offset += 1;
            let mut value = Vec::new();
            let mut terminated = false;
            while offset < bytes.len() {
                let byte = bytes[offset];
                offset += 1;
                if byte == b'"' {
                    terminated = true;
                    break;
                }
                if byte != b'\\' {
                    value.push(byte);
                    continue;
                }
                let escaped = *bytes
                    .get(offset)
                    .ok_or_else(|| CompileError::Lex("trailing string escape".to_owned()))?;
                offset += 1;
                value.push(match escaped {
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'0' => 0,
                    b'\\' => b'\\',
                    b'"' => b'"',
                    _ => return Err(CompileError::Lex("unsupported string escape".to_owned())),
                });
            }
            if !terminated {
                return Err(CompileError::Lex("unterminated string literal".to_owned()));
            }
            tokens.push(Token::String(value));
            continue;
        }
        let two = bytes
            .get(offset..offset + 2)
            .and_then(|raw| std::str::from_utf8(raw).ok());
        if let Some(symbol @ ("==" | "!=" | "<=" | ">=")) = two {
            tokens.push(Token::Symbol(symbol.to_owned()));
            offset += 2;
            continue;
        }
        let symbol = char::from(bytes[offset]);
        if "(){};=,+-*<>".contains(symbol) {
            tokens.push(Token::Symbol(symbol.to_string()));
            offset += 1;
            continue;
        }
        return Err(CompileError::Lex(format!(
            "unexpected byte {:?}",
            char::from(bytes[offset])
        )));
    }
    tokens.push(Token::End);
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    offset: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, offset: 0 }
    }

    fn current(&self) -> &Token {
        &self.tokens[self.offset]
    }

    fn advance(&mut self) -> Token {
        let token = self.tokens[self.offset].clone();
        self.offset += 1;
        token
    }

    fn take_identifier(&mut self) -> Result<String, CompileError> {
        match self.advance() {
            Token::Identifier(value) => Ok(value),
            token => Err(CompileError::Parse(format!(
                "expected identifier, found {token:?}"
            ))),
        }
    }

    fn keyword(&mut self, expected: &str) -> Result<(), CompileError> {
        let actual = self.take_identifier()?;
        if actual == expected {
            Ok(())
        } else {
            Err(CompileError::Parse(format!(
                "expected {expected}, found {actual}"
            )))
        }
    }

    fn symbol(&mut self, expected: &str) -> Result<(), CompileError> {
        match self.advance() {
            Token::Symbol(value) if value == expected => Ok(()),
            token => Err(CompileError::Parse(format!(
                "expected {expected:?}, found {token:?}"
            ))),
        }
    }

    fn consume_symbol(&mut self, expected: &str) -> bool {
        if matches!(self.current(), Token::Symbol(value) if value == expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn consume_keyword(&mut self, expected: &str) -> bool {
        if matches!(self.current(), Token::Identifier(value) if value == expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn program(&mut self) -> Result<Vec<Statement>, CompileError> {
        self.keyword("int")?;
        self.keyword("main")?;
        self.symbol("(")?;
        let _ = self.consume_keyword("void");
        self.symbol(")")?;
        let statements = self.block()?;
        if self.current() != &Token::End {
            return Err(CompileError::Parse("trailing input".to_owned()));
        }
        Ok(statements)
    }

    fn block(&mut self) -> Result<Vec<Statement>, CompileError> {
        self.symbol("{")?;
        let mut statements = Vec::new();
        while !self.consume_symbol("}") {
            if self.current() == &Token::End {
                return Err(CompileError::Parse("unterminated block".to_owned()));
            }
            statements.push(self.statement()?);
        }
        Ok(statements)
    }

    fn statement(&mut self) -> Result<Statement, CompileError> {
        if self.consume_keyword("int") || self.consume_keyword("long") {
            let name = self.take_identifier()?;
            let value = if self.consume_symbol("=") {
                self.expression()?
            } else {
                Expr::Number(0)
            };
            self.symbol(";")?;
            return Ok(Statement::Declare(name, value));
        }
        if self.consume_keyword("return") {
            let value = self.expression()?;
            self.symbol(";")?;
            return Ok(Statement::Return(value));
        }
        if self.consume_keyword("if") {
            self.symbol("(")?;
            let condition = self.condition()?;
            self.symbol(")")?;
            let then_block = self.block()?;
            let else_block = if self.consume_keyword("else") {
                self.block()?
            } else {
                Vec::new()
            };
            return Ok(Statement::If {
                condition,
                then_block,
                else_block,
            });
        }
        if self.consume_keyword("while") {
            self.symbol("(")?;
            let condition = self.condition()?;
            self.symbol(")")?;
            return Ok(Statement::While {
                condition,
                block: self.block()?,
            });
        }
        if let Token::Identifier(name) = self.current().clone() {
            if matches!(self.tokens.get(self.offset + 1), Some(Token::Symbol(value)) if value == "=")
            {
                self.offset += 2;
                let value = self.expression()?;
                self.symbol(";")?;
                return Ok(Statement::Assign(name, value));
            }
        }
        let expression = self.expression()?;
        self.symbol(";")?;
        Ok(Statement::Expression(expression))
    }

    fn condition(&mut self) -> Result<Condition, CompileError> {
        let left = self.expression()?;
        let operation = match self.current() {
            Token::Symbol(value) if value == "==" => CompareOp::Equal,
            Token::Symbol(value) if value == "!=" => CompareOp::NotEqual,
            Token::Symbol(value) if value == "<" => CompareOp::Less,
            Token::Symbol(value) if value == "<=" => CompareOp::LessEqual,
            Token::Symbol(value) if value == ">" => CompareOp::Greater,
            Token::Symbol(value) if value == ">=" => CompareOp::GreaterEqual,
            _ => {
                return Ok(Condition {
                    left,
                    operation: CompareOp::NotEqual,
                    right: Expr::Number(0),
                })
            },
        };
        self.offset += 1;
        Ok(Condition {
            left,
            operation,
            right: self.expression()?,
        })
    }

    fn expression(&mut self) -> Result<Expr, CompileError> {
        let mut expression = self.term()?;
        loop {
            let operation = if self.consume_symbol("+") {
                BinaryOp::Add
            } else if self.consume_symbol("-") {
                BinaryOp::Subtract
            } else {
                return Ok(expression);
            };
            expression = Expr::Binary(Box::new(expression), operation, Box::new(self.term()?));
        }
    }

    fn term(&mut self) -> Result<Expr, CompileError> {
        let mut expression = self.factor()?;
        while self.consume_symbol("*") {
            expression = Expr::Binary(
                Box::new(expression),
                BinaryOp::Multiply,
                Box::new(self.factor()?),
            );
        }
        Ok(expression)
    }

    fn factor(&mut self) -> Result<Expr, CompileError> {
        if self.consume_symbol("-") {
            return Ok(Expr::Negate(Box::new(self.factor()?)));
        }
        if self.consume_symbol("(") {
            let expression = self.expression()?;
            self.symbol(")")?;
            return Ok(expression);
        }
        match self.advance() {
            Token::Number(value) => Ok(Expr::Number(value)),
            Token::Identifier(name) if name == "puts" => {
                self.symbol("(")?;
                let Token::String(value) = self.advance() else {
                    return Err(CompileError::Parse(
                        "puts expects one string literal".to_owned(),
                    ));
                };
                self.symbol(")")?;
                Ok(Expr::Puts(value))
            },
            Token::Identifier(name) => Ok(Expr::Variable(name)),
            token => Err(CompileError::Parse(format!(
                "expected expression, found {token:?}"
            ))),
        }
    }
}

struct LiteralRelocation {
    placeholder: u64,
    rodata_offset: u64,
}

struct Generator {
    assembly: String,
    locals: BTreeMap<String, u64>,
    rodata: Vec<u8>,
    literal_relocations: Vec<LiteralRelocation>,
    next_label: usize,
}

impl Generator {
    fn new(statements: &[Statement]) -> Result<Self, CompileError> {
        let mut locals = BTreeMap::new();
        collect_locals(statements, &mut locals)?;
        Ok(Self {
            assembly: String::new(),
            locals,
            rodata: Vec::new(),
            literal_relocations: Vec::new(),
            next_label: 0,
        })
    }

    fn line(&mut self, line: impl AsRef<str>) {
        self.assembly.push_str(line.as_ref());
        self.assembly.push('\n');
    }

    fn label(&mut self, prefix: &str) -> String {
        let label = format!(".L{prefix}_{}", self.next_label);
        self.next_label += 1;
        label
    }

    fn emit_program(&mut self, statements: &[Statement]) -> Result<(), CompileError> {
        self.line(".code64");
        self.line(".global _start");
        self.line("_start:");
        self.line("push rbp");
        self.line("mov rbp, rsp");
        let stack_size = (self.locals.len() as u64 * 8).next_multiple_of(16);
        if stack_size != 0 {
            self.line(format!("sub rsp, {stack_size}"));
        }
        self.emit_statements(statements)?;
        // A return nested in one conditional branch does not prove that all
        // paths return. Keep a valid fallthrough target even when it is
        // unreachable for well-formed source.
        self.emit_return(&Expr::Number(0))?;
        Ok(())
    }

    fn emit_statements(&mut self, statements: &[Statement]) -> Result<(), CompileError> {
        for statement in statements {
            match statement {
                Statement::Declare(name, value) | Statement::Assign(name, value) => {
                    self.emit_expr(value)?;
                    let offset = self.local(name)?;
                    self.line(format!("mov qword ptr [rbp-{offset}], rax"));
                },
                Statement::Expression(expression) => self.emit_expr(expression)?,
                Statement::Return(expression) => self.emit_return(expression)?,
                Statement::If {
                    condition,
                    then_block,
                    else_block,
                } => {
                    let otherwise = self.label("else");
                    let end = self.label("endif");
                    self.emit_false_branch(condition, &otherwise)?;
                    self.emit_statements(then_block)?;
                    self.line(format!("jmp {end}"));
                    self.line(format!("{otherwise}:"));
                    self.emit_statements(else_block)?;
                    self.line(format!("{end}:"));
                },
                Statement::While { condition, block } => {
                    let head = self.label("while");
                    let end = self.label("endwhile");
                    self.line(format!("{head}:"));
                    self.emit_false_branch(condition, &end)?;
                    self.emit_statements(block)?;
                    self.line(format!("jmp {head}"));
                    self.line(format!("{end}:"));
                },
            }
        }
        Ok(())
    }

    fn emit_return(&mut self, expression: &Expr) -> Result<(), CompileError> {
        self.emit_expr(expression)?;
        self.line("mov edi, eax");
        self.line(format!("mov eax, {SYS_EXIT}"));
        self.line("syscall");
        self.line("hlt");
        Ok(())
    }

    fn emit_expr(&mut self, expression: &Expr) -> Result<(), CompileError> {
        match expression {
            Expr::Number(value) => self.line(format!("mov rax, {value}")),
            Expr::Variable(name) => {
                let offset = self.local(name)?;
                self.line(format!("mov rax, qword ptr [rbp-{offset}]"));
            },
            Expr::Negate(value) => {
                self.emit_expr(value)?;
                self.line("neg rax");
            },
            Expr::Binary(left, operation, right) => {
                self.emit_expr(left)?;
                self.line("push rax");
                self.emit_expr(right)?;
                self.line("mov rcx, rax");
                self.line("pop rax");
                self.line(match operation {
                    BinaryOp::Add => "add rax, rcx",
                    BinaryOp::Subtract => "sub rax, rcx",
                    BinaryOp::Multiply => "imul rax, rcx",
                });
            },
            Expr::Puts(bytes) => self.emit_puts(bytes)?,
        }
        Ok(())
    }

    fn emit_puts(&mut self, bytes: &[u8]) -> Result<(), CompileError> {
        let index = u16::try_from(self.literal_relocations.len())
            .map_err(|_| CompileError::TooManyLiterals)?;
        let placeholder = PLACEHOLDER_BASE | u64::from(index);
        let rodata_offset = self.rodata.len() as u64;
        self.rodata.extend_from_slice(bytes);
        self.literal_relocations.push(LiteralRelocation {
            placeholder,
            rodata_offset,
        });
        self.line("mov rdi, 1");
        self.line(format!("mov rsi, {placeholder:#x}"));
        self.line(format!("mov rdx, {}", bytes.len()));
        self.line(format!("mov rax, {SYS_WRITE}"));
        self.line("syscall");
        Ok(())
    }

    fn emit_false_branch(
        &mut self,
        condition: &Condition,
        false_label: &str,
    ) -> Result<(), CompileError> {
        self.emit_expr(&condition.left)?;
        self.line("push rax");
        self.emit_expr(&condition.right)?;
        self.line("mov rcx, rax");
        self.line("pop rax");
        self.line("cmp rax, rcx");
        let branch = match condition.operation {
            CompareOp::Equal => "jne",
            CompareOp::NotEqual => "je",
            CompareOp::Less => "jge",
            CompareOp::LessEqual => "jg",
            CompareOp::Greater => "jle",
            CompareOp::GreaterEqual => "jl",
        };
        self.line(format!("{branch} {false_label}"));
        Ok(())
    }

    fn local(&self, name: &str) -> Result<u64, CompileError> {
        self.locals
            .get(name)
            .copied()
            .ok_or_else(|| CompileError::UnknownLocal(name.to_owned()))
    }

    fn link(&self) -> Result<Vec<u8>, CompileError> {
        let text = xenith_asm::assemble(&self.assembly)?;
        let mut relocations = Vec::with_capacity(self.literal_relocations.len());
        for literal in &self.literal_relocations {
            let needle = literal.placeholder.to_le_bytes();
            let offset = text
                .windows(needle.len())
                .position(|window| window == needle)
                .ok_or(CompileError::MissingRelocationPlaceholder)?;
            relocations.push(Relocation {
                section: 0,
                offset: offset as u64,
                target_section: 1,
                target_offset: literal.rodata_offset,
                addend: 0,
                kind: RelocationKind::Absolute64,
            });
        }
        let text_section = StaticSection {
            name: ".text",
            data: &text,
            memory_size: text.len() as u64,
            flags: SegmentFlags::READ | SegmentFlags::EXECUTE,
        };
        let linked = if self.rodata.is_empty() {
            link_static(&[text_section], &[], StaticLinkOptions::default())?
        } else {
            link_static(
                &[text_section, StaticSection {
                    name: ".rodata",
                    data: &self.rodata,
                    memory_size: self.rodata.len() as u64,
                    flags: SegmentFlags::READ,
                }],
                &relocations,
                StaticLinkOptions::default(),
            )?
        };
        Ok(linked.bytes)
    }
}

fn collect_locals(
    statements: &[Statement],
    locals: &mut BTreeMap<String, u64>,
) -> Result<(), CompileError> {
    for statement in statements {
        match statement {
            Statement::Declare(name, _) => {
                let offset = (locals.len() as u64 + 1) * 8;
                if locals.insert(name.clone(), offset).is_some() {
                    return Err(CompileError::DuplicateLocal(name.clone()));
                }
            },
            Statement::If {
                then_block,
                else_block,
                ..
            } => {
                collect_locals(then_block, locals)?;
                collect_locals(else_block, locals)?;
            },
            Statement::While { block, .. } => collect_locals(block, locals)?,
            Statement::Assign(_, _) | Statement::Expression(_) | Statement::Return(_) => {},
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16_at(image: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(image[offset..offset + 2].try_into().unwrap())
    }

    fn u32_at(image: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap())
    }

    fn u64_at(image: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn compiles_runtime_locals_loop_puts_and_wx_segments() {
        let elf = compile(
            "int main(void) {\n\
             long count = 2;\n\
             while (count > 0) {\n\
                 puts(\"C TOOLCHAIN OK\\n\");\n\
                 count = count - 1;\n\
             }\n\
             if (count != 0) { return 7; } else { return 0; }\n\
             }",
        )
        .unwrap();
        assert_eq!(&elf[..4], b"\x7fELF");
        assert_eq!(u16_at(&elf, 56), 2);
        let text = 64;
        let rodata = 64 + 56;
        assert_eq!(u32_at(&elf, text + 4), 5);
        assert_eq!(u32_at(&elf, rodata + 4), 4);
        let rodata_offset = u64_at(&elf, rodata + 8) as usize;
        assert_eq!(&elf[rodata_offset..][..15], b"C TOOLCHAIN OK\n");
        let rodata_address = u64_at(&elf, rodata + 16).to_le_bytes();
        assert!(elf.windows(8).any(|window| window == rodata_address));
    }

    #[test]
    fn still_compiles_a_simple_return_but_through_the_static_linker() {
        let elf = compile("int main() { return 2 + 3 * 4; }").unwrap();
        assert_eq!(u16_at(&elf, 56), 1);
        assert_eq!(u32_at(&elf, 64 + 4), 5);
    }

    #[test]
    fn rejects_duplicate_and_unknown_locals() {
        assert!(matches!(
            compile("int main(){ int x=1; int x=2; return x; }"),
            Err(CompileError::DuplicateLocal(name)) if name == "x"
        ));
        assert!(matches!(
            compile("int main(){ return missing; }"),
            Err(CompileError::UnknownLocal(name)) if name == "missing"
        ));
    }
}
