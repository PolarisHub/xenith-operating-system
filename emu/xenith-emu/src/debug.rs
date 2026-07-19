//! Deterministic execution control and the line-oriented remote-debug protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};

use xenith_x86::Register;

use crate::{Access, CpuFault, ExitReason, Machine, MemoryError, PagingContext, Privilege};

pub const PROTOCOL_VERSION: &str = "xenith-debug-v1";
pub const MAX_MEMORY_TRANSFER: usize = 4096;
pub const MAX_COMMAND_BYTES: usize = 16_384;
pub const MAX_CONTINUE_INSTRUCTIONS: u64 = 100_000_000;
pub const MAX_BACKTRACE_FRAMES: usize = 64;
pub const MAX_WATCHPOINTS: usize = 16;
pub const MAX_WATCHED_BYTES: usize = 4096;

/// Frontend callback polled immediately before each debugger execution cycle.
pub type ExecutionHook = Box<dyn FnMut(&mut Machine)>;

const GENERAL_REGISTERS: [(&str, Register); 16] = [
    ("rax", Register::Rax),
    ("rcx", Register::Rcx),
    ("rdx", Register::Rdx),
    ("rbx", Register::Rbx),
    ("rsp", Register::Rsp),
    ("rbp", Register::Rbp),
    ("rsi", Register::Rsi),
    ("rdi", Register::Rdi),
    ("r8", Register::R8),
    ("r9", Register::R9),
    ("r10", Register::R10),
    ("r11", Register::R11),
    ("r12", Register::R12),
    ("r13", Register::R13),
    ("r14", Register::R14),
    ("r15", Register::R15),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DebugStop {
    Breakpoint {
        address: u64,
    },
    Watchpoint {
        address: u64,
        length: usize,
        instruction: u64,
    },
    Step {
        address: u64,
    },
    Halted {
        address: u64,
    },
    Fault {
        address: u64,
        fault: CpuFault,
    },
    InstructionLimit {
        address: u64,
        executed: u64,
    },
}

impl DebugStop {
    #[must_use]
    pub const fn address(&self) -> u64 {
        match self {
            Self::Breakpoint { address }
            | Self::Watchpoint {
                instruction: address,
                ..
            }
            | Self::Step { address }
            | Self::Halted { address }
            | Self::Fault { address, .. }
            | Self::InstructionLimit { address, .. } => *address,
        }
    }

    #[must_use]
    pub fn protocol_line(&self) -> String {
        match self {
            Self::Breakpoint { address } => format!("stop breakpoint {address:#018x}"),
            Self::Watchpoint {
                address,
                length,
                instruction,
            } => format!("stop watchpoint {address:#018x} {length} {instruction:#018x}"),
            Self::Step { address } => format!("stop step {address:#018x}"),
            Self::Halted { address } => format!("stop halted {address:#018x}"),
            Self::Fault { address, fault } => {
                format!(
                    "stop fault {address:#018x} {}",
                    sanitize(&format!("{fault:?}"))
                )
            },
            Self::InstructionLimit { address, executed } => {
                format!("stop limit {address:#018x} {executed}")
            },
        }
    }
}

#[derive(Debug)]
pub enum DebugError {
    Memory(MemoryError),
    UnknownRegister(String),
    ReadOnlyRegister(String),
    InvalidCommand(&'static str),
    InvalidNumber(String),
    InvalidHex,
    TransferTooLarge,
    InvalidWatchpointLength,
    TooManyWatchpoints,
    WatchpointBudgetExceeded,
    InvalidBacktraceLimit,
}

impl From<MemoryError> for DebugError {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}

impl std::fmt::Display for DebugError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory(error) => write!(formatter, "memory {error:?}"),
            Self::UnknownRegister(name) => write!(formatter, "unknown register {name}"),
            Self::ReadOnlyRegister(name) => write!(formatter, "read-only register {name}"),
            Self::InvalidCommand(message) => formatter.write_str(message),
            Self::InvalidNumber(value) => write!(formatter, "invalid number {value}"),
            Self::InvalidHex => formatter.write_str("invalid hex bytes"),
            Self::TransferTooLarge => write!(
                formatter,
                "memory transfer exceeds {MAX_MEMORY_TRANSFER} bytes"
            ),
            Self::InvalidWatchpointLength => {
                formatter.write_str("watchpoint length must be between 1 and 4096 bytes")
            },
            Self::TooManyWatchpoints => {
                write!(
                    formatter,
                    "at most {MAX_WATCHPOINTS} watchpoints are supported"
                )
            },
            Self::WatchpointBudgetExceeded => write!(
                formatter,
                "total watched memory exceeds {MAX_WATCHED_BYTES} bytes"
            ),
            Self::InvalidBacktraceLimit => write!(
                formatter,
                "backtrace frame count must be between 1 and {MAX_BACKTRACE_FRAMES}"
            ),
        }
    }
}

impl std::error::Error for DebugError {}

pub struct DebugSession<'a> {
    machine: &'a mut Machine,
    breakpoints: BTreeSet<u64>,
    watchpoints: BTreeMap<u64, Watchpoint>,
    resume_breakpoint: Option<u64>,
    default_continue_limit: u64,
    execution_hook: Option<ExecutionHook>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Watchpoint {
    bytes: Vec<u8>,
}

impl<'a> DebugSession<'a> {
    pub fn new(machine: &'a mut Machine, default_continue_limit: u64) -> Self {
        Self {
            machine,
            breakpoints: BTreeSet::new(),
            watchpoints: BTreeMap::new(),
            resume_breakpoint: None,
            default_continue_limit: default_continue_limit.clamp(1, MAX_CONTINUE_INSTRUCTIONS),
            execution_hook: None,
        }
    }

    /// Install a non-blocking frontend hook for input or monitoring.
    pub fn set_execution_hook(&mut self, hook: ExecutionHook) {
        self.execution_hook = Some(hook);
    }

    #[must_use]
    pub fn machine(&self) -> &Machine {
        self.machine
    }

    pub fn machine_mut(&mut self) -> &mut Machine {
        self.machine
    }

    pub fn add_breakpoint(&mut self, address: u64) -> bool {
        self.breakpoints.insert(address)
    }

    pub fn remove_breakpoint(&mut self, address: u64) -> bool {
        if self.resume_breakpoint == Some(address) {
            self.resume_breakpoint = None;
        }
        self.breakpoints.remove(&address)
    }

    pub fn breakpoints(&self) -> impl Iterator<Item = u64> + '_ {
        self.breakpoints.iter().copied()
    }

    pub fn add_watchpoint(&mut self, address: u64, length: usize) -> Result<bool, DebugError> {
        if length == 0 || length > MAX_WATCHED_BYTES {
            return Err(DebugError::InvalidWatchpointLength);
        }
        address
            .checked_add((length - 1) as u64)
            .ok_or_else(|| DebugError::InvalidNumber(address.to_string()))?;
        let previous_length = self
            .watchpoints
            .get(&address)
            .map_or(0, |watchpoint| watchpoint.bytes.len());
        if previous_length == 0 && self.watchpoints.len() == MAX_WATCHPOINTS {
            return Err(DebugError::TooManyWatchpoints);
        }
        let watched = self
            .watchpoints
            .values()
            .map(|watchpoint| watchpoint.bytes.len())
            .sum::<usize>()
            .saturating_sub(previous_length);
        if watched.saturating_add(length) > MAX_WATCHED_BYTES {
            return Err(DebugError::WatchpointBudgetExceeded);
        }
        let bytes = self.read_memory(address, length)?;
        let inserted = self
            .watchpoints
            .insert(address, Watchpoint { bytes })
            .is_none();
        Ok(inserted)
    }

    pub fn remove_watchpoint(&mut self, address: u64) -> bool {
        self.watchpoints.remove(&address).is_some()
    }

    pub fn watchpoints(&self) -> impl Iterator<Item = (u64, usize)> + '_ {
        self.watchpoints
            .iter()
            .map(|(&address, watchpoint)| (address, watchpoint.bytes.len()))
    }

    /// Walk a conventional x86-64 frame-pointer chain. The current RIP is
    /// frame zero; remaining entries are return addresses read from `[rbp+8]`.
    pub fn backtrace(&mut self, limit: usize) -> Result<Vec<u64>, DebugError> {
        if limit == 0 || limit > MAX_BACKTRACE_FRAMES {
            return Err(DebugError::InvalidBacktraceLimit);
        }
        let mut frames = Vec::with_capacity(limit);
        frames.push(self.machine.cpu.state.rip);
        let mut frame_pointer = self.machine.cpu.state.register(Register::Rbp);
        while frames.len() < limit && frame_pointer != 0 && frame_pointer.is_multiple_of(8) {
            let Ok(record) = self.read_memory(frame_pointer, 16) else {
                break;
            };
            let mut previous_bytes = [0; 8];
            previous_bytes.copy_from_slice(&record[..8]);
            let previous = u64::from_le_bytes(previous_bytes);
            let mut return_bytes = [0; 8];
            return_bytes.copy_from_slice(&record[8..16]);
            let return_address = u64::from_le_bytes(return_bytes);
            if return_address != 0 {
                frames.push(return_address);
            }
            if previous == 0 || previous <= frame_pointer || !previous.is_multiple_of(8) {
                break;
            }
            frame_pointer = previous;
        }
        Ok(frames)
    }

    pub fn step(&mut self) -> DebugStop {
        self.resume_breakpoint = None;
        match self.execute_one() {
            None => DebugStop::Step {
                address: self.machine.cpu.state.rip,
            },
            Some(stop) => stop,
        }
    }

    pub fn continue_execution(&mut self, limit: Option<u64>) -> DebugStop {
        let limit = limit
            .unwrap_or(self.default_continue_limit)
            .clamp(1, MAX_CONTINUE_INSTRUCTIONS);
        let suppressed = self.resume_breakpoint.take();
        for executed in 0..limit {
            let rip = self.machine.cpu.state.rip;
            if self.breakpoints.contains(&rip) && !(executed == 0 && suppressed == Some(rip)) {
                self.resume_breakpoint = Some(rip);
                return DebugStop::Breakpoint { address: rip };
            }
            if let Some(stop) = self.execute_one() {
                return stop;
            }
        }
        DebugStop::InstructionLimit {
            address: self.machine.cpu.state.rip,
            executed: limit,
        }
    }

    pub fn read_memory(&mut self, address: u64, length: usize) -> Result<Vec<u8>, DebugError> {
        if length > MAX_MEMORY_TRANSFER {
            return Err(DebugError::TransferTooLarge);
        }
        let state = &self.machine.cpu.state;
        let paging = PagingContext::new(state.cr0, state.cr3, state.efer, Privilege::Supervisor);
        let mut bytes = vec![0; length];
        self.machine
            .bus
            .read_linear(address, &mut bytes, paging, Access::Read)?;
        Ok(bytes)
    }

    /// Debug writes bypass guest page write-protection but still require mapped pages.
    pub fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<(), DebugError> {
        if bytes.len() > MAX_MEMORY_TRANSFER {
            return Err(DebugError::TransferTooLarge);
        }
        let state = &self.machine.cpu.state;
        let paging = PagingContext::new(state.cr0, state.cr3, state.efer, Privilege::Supervisor);
        for (offset, byte) in bytes.iter().copied().enumerate() {
            let linear = address
                .checked_add(offset as u64)
                .ok_or_else(|| DebugError::InvalidNumber(address.to_string()))?;
            let physical = self.machine.bus.translate(linear, paging, Access::Read)?;
            self.machine
                .bus
                .write_physical(physical, core::slice::from_ref(&byte))?;
        }
        self.refresh_watchpoints();
        Ok(())
    }

    fn refresh_watchpoints(&mut self) {
        let watched: Vec<_> = self.watchpoints().collect();
        for (address, length) in watched {
            if let Ok(bytes) = self.read_memory(address, length) {
                if let Some(watchpoint) = self.watchpoints.get_mut(&address) {
                    watchpoint.bytes = bytes;
                }
            }
        }
    }

    pub fn read_register(&self, name: &str) -> Result<u64, DebugError> {
        if let Some(register) = parse_general_register(name) {
            return Ok(self.machine.cpu.state.register(register));
        }
        let state = &self.machine.cpu.state;
        match name.to_ascii_lowercase().as_str() {
            "rip" => Ok(state.rip),
            "rflags" => Ok(state.rflags),
            "cr0" => Ok(state.cr0),
            "cr2" => Ok(state.cr2),
            "cr3" => Ok(state.cr3),
            "cr4" => Ok(state.cr4),
            "efer" => Ok(state.efer),
            "cs" => Ok(u64::from(state.cs)),
            "ss" => Ok(u64::from(state.ss)),
            "ds" => Ok(u64::from(state.ds)),
            "es" => Ok(u64::from(state.es)),
            "fs" => Ok(u64::from(state.fs)),
            "gs" => Ok(u64::from(state.gs)),
            "cycles" => Ok(state.cycles),
            _ => Err(DebugError::UnknownRegister(name.to_string())),
        }
    }

    pub fn write_register(&mut self, name: &str, value: u64) -> Result<(), DebugError> {
        if let Some(register) = parse_general_register(name) {
            self.machine.cpu.state.set_register(register, value);
            return Ok(());
        }
        let state = &mut self.machine.cpu.state;
        match name.to_ascii_lowercase().as_str() {
            "rip" => state.rip = value,
            "rflags" => state.rflags = value | 2,
            "cr0" => state.cr0 = value,
            "cr2" => state.cr2 = value,
            "cr3" => state.cr3 = value & 0x000f_ffff_ffff_f000,
            "cr4" => state.cr4 = value,
            "efer" => state.efer = value,
            "cs" => state.cs = value as u16,
            "ss" => state.ss = value as u16,
            "ds" => state.ds = value as u16,
            "es" => state.es = value as u16,
            "fs" => state.fs = value as u16,
            "gs" => state.gs = value as u16,
            "cycles" => return Err(DebugError::ReadOnlyRegister(name.to_string())),
            _ => return Err(DebugError::UnknownRegister(name.to_string())),
        }
        Ok(())
    }

    #[must_use]
    pub fn registers_line(&self) -> String {
        let mut output = String::from("ok");
        for &(name, register) in &GENERAL_REGISTERS {
            let _ = write!(
                output,
                " {name}={:#018x}",
                self.machine.cpu.state.register(register)
            );
        }
        let state = &self.machine.cpu.state;
        let _ = write!(
            output,
            " rip={:#018x} rflags={:#018x} cs={:#06x} ss={:#06x} ds={:#06x} es={:#06x} fs={:#06x} gs={:#06x} cr0={:#018x} cr2={:#018x} cr3={:#018x} cr4={:#018x} efer={:#018x} cycles={}",
            state.rip,
            state.rflags,
            state.cs,
            state.ss,
            state.ds,
            state.es,
            state.fs,
            state.gs,
            state.cr0,
            state.cr2,
            state.cr3,
            state.cr4,
            state.efer,
            state.cycles
        );
        output
    }

    pub fn execute_command(&mut self, command: &str) -> CommandResult {
        let mut fields = command.split_ascii_whitespace();
        let Some(operation) = fields.next() else {
            return CommandResult::response("error empty command");
        };
        let result = match operation {
            "hello" => Ok(format!("ok {PROTOCOL_VERSION}")),
            "status" => Ok(format!(
                "ok paused rip={:#018x} cycles={}",
                self.machine.cpu.state.rip, self.machine.cpu.state.cycles
            )),
            "registers" => no_extra(fields).map(|()| self.registers_line()),
            "read-register" => one_field(fields).and_then(|name| {
                self.read_register(name)
                    .map(|value| format!("ok {name}={value:#018x}"))
            }),
            "write-register" => two_fields(fields).and_then(|(name, value)| {
                let value = parse_u64(value)?;
                self.write_register(name, value)?;
                Ok("ok".to_string())
            }),
            "read-memory" => two_fields(fields).and_then(|(address, length)| {
                let address = parse_u64(address)?;
                let length = parse_usize(length)?;
                let bytes = self.read_memory(address, length)?;
                Ok(format!("ok {}", encode_hex(&bytes)))
            }),
            "write-memory" => two_fields(fields).and_then(|(address, bytes)| {
                let address = parse_u64(address)?;
                let bytes = decode_hex(bytes)?;
                self.write_memory(address, &bytes)?;
                Ok("ok".to_string())
            }),
            "break" => one_field(fields).and_then(|address| {
                let address = parse_u64(address)?;
                let inserted = self.add_breakpoint(address);
                Ok(format!(
                    "ok {} {address:#018x}",
                    if inserted { "added" } else { "present" }
                ))
            }),
            "delete" => one_field(fields).and_then(|address| {
                let address = parse_u64(address)?;
                let removed = self.remove_breakpoint(address);
                Ok(format!(
                    "ok {} {address:#018x}",
                    if removed { "removed" } else { "absent" }
                ))
            }),
            "breakpoints" => no_extra(fields).map(|()| {
                let mut line = String::from("ok");
                for address in self.breakpoints() {
                    let _ = write!(line, " {address:#018x}");
                }
                line
            }),
            "watch" => two_fields(fields).and_then(|(address, length)| {
                let address = parse_u64(address)?;
                let length = parse_usize(length)?;
                let inserted = self.add_watchpoint(address, length)?;
                Ok(format!(
                    "ok {} {address:#018x} {length}",
                    if inserted { "added" } else { "updated" }
                ))
            }),
            "unwatch" => one_field(fields).and_then(|address| {
                let address = parse_u64(address)?;
                let removed = self.remove_watchpoint(address);
                Ok(format!(
                    "ok {} {address:#018x}",
                    if removed { "removed" } else { "absent" }
                ))
            }),
            "watchpoints" => no_extra(fields).map(|()| {
                let mut line = String::from("ok");
                for (address, length) in self.watchpoints() {
                    let _ = write!(line, " {address:#018x}:{length}");
                }
                line
            }),
            "backtrace" => optional_field(fields).and_then(|limit| {
                let limit = limit.map(parse_usize).transpose()?.unwrap_or(32);
                let frames = self.backtrace(limit)?;
                let mut line = String::from("ok backtrace");
                for address in frames {
                    let _ = write!(line, " {address:#018x}");
                }
                Ok(line)
            }),
            "step" => no_extra(fields).map(|()| self.step().protocol_line()),
            "continue" => optional_field(fields).and_then(|limit| {
                let limit = limit.map(parse_u64).transpose()?;
                Ok(self.continue_execution(limit).protocol_line())
            }),
            "quit" => match no_extra(fields) {
                Ok(()) => return CommandResult::close("ok bye"),
                Err(error) => Err(error),
            },
            _ => Err(DebugError::InvalidCommand("unknown command")),
        };
        match result {
            Ok(response) => CommandResult::response(response),
            Err(error) => {
                CommandResult::response(format!("error {}", sanitize(&error.to_string())))
            },
        }
    }

    fn execute_one(&mut self) -> Option<DebugStop> {
        if let Some(hook) = &mut self.execution_hook {
            hook(self.machine);
        }
        let before = self.machine.cpu.state.rip;
        let exit = self.machine.cpu.run_cycle(&mut self.machine.bus);
        if let Some(stop) = self.changed_watchpoint() {
            return Some(stop);
        }
        match exit {
            None => None,
            Some(ExitReason::Halted) => Some(DebugStop::Halted {
                address: self.machine.cpu.state.rip,
            }),
            Some(ExitReason::Breakpoint(address)) => Some(DebugStop::Breakpoint { address }),
            Some(ExitReason::Fault(fault)) => Some(DebugStop::Fault {
                address: before,
                fault,
            }),
            Some(ExitReason::InstructionLimit) => Some(DebugStop::InstructionLimit {
                address: self.machine.cpu.state.rip,
                executed: 1,
            }),
        }
    }

    fn changed_watchpoint(&mut self) -> Option<DebugStop> {
        let watched: Vec<_> = self.watchpoints().collect();
        for (address, length) in watched {
            let Ok(bytes) = self.read_memory(address, length) else {
                return Some(DebugStop::Watchpoint {
                    address,
                    length,
                    instruction: self.machine.cpu.state.rip,
                });
            };
            let Some(watchpoint) = self.watchpoints.get_mut(&address) else {
                continue;
            };
            if watchpoint.bytes != bytes {
                watchpoint.bytes = bytes;
                return Some(DebugStop::Watchpoint {
                    address,
                    length,
                    instruction: self.machine.cpu.state.rip,
                });
            }
        }
        None
    }
}

pub struct CommandResult {
    pub response: String,
    pub close: bool,
}

impl CommandResult {
    fn response(response: impl Into<String>) -> Self {
        Self {
            response: response.into(),
            close: false,
        }
    }

    fn close(response: impl Into<String>) -> Self {
        Self {
            response: response.into(),
            close: true,
        }
    }
}

pub fn serve_tcp<A: ToSocketAddrs>(
    machine: &mut Machine,
    address: A,
    continue_limit: u64,
) -> io::Result<()> {
    let listener = TcpListener::bind(address)?;
    eprintln!(
        "xenith-emu: debug server listening on {}",
        listener.local_addr()?
    );
    serve_listener(machine, &listener, continue_limit)
}

/// Serve the debug protocol while polling a non-blocking frontend hook during
/// step and continue execution. Waiting for a debugger command still leaves
/// the guest paused by design.
pub fn serve_tcp_with_execution_hook<A: ToSocketAddrs>(
    machine: &mut Machine,
    address: A,
    continue_limit: u64,
    execution_hook: ExecutionHook,
) -> io::Result<()> {
    let listener = TcpListener::bind(address)?;
    eprintln!(
        "xenith-emu: debug server listening on {}",
        listener.local_addr()?
    );
    let (stream, _) = listener.accept()?;
    stream.set_nodelay(true)?;
    let reader = BufReader::new(stream.try_clone()?);
    serve_stream_inner(
        machine,
        reader,
        stream,
        continue_limit,
        Some(execution_hook),
    )
}

pub fn serve_listener(
    machine: &mut Machine,
    listener: &TcpListener,
    continue_limit: u64,
) -> io::Result<()> {
    let (stream, _) = listener.accept()?;
    stream.set_nodelay(true)?;
    serve_tcp_stream(machine, stream, continue_limit)
}

pub fn serve_tcp_stream(
    machine: &mut Machine,
    stream: TcpStream,
    continue_limit: u64,
) -> io::Result<()> {
    let reader = BufReader::new(stream.try_clone()?);
    serve_stream(machine, reader, stream, continue_limit)
}

pub fn serve_stream<R: BufRead, W: Write>(
    machine: &mut Machine,
    reader: R,
    writer: W,
    continue_limit: u64,
) -> io::Result<()> {
    serve_stream_inner(machine, reader, writer, continue_limit, None)
}

fn serve_stream_inner<R: BufRead, W: Write>(
    machine: &mut Machine,
    mut reader: R,
    mut writer: W,
    continue_limit: u64,
    execution_hook: Option<ExecutionHook>,
) -> io::Result<()> {
    let mut session = DebugSession::new(machine, continue_limit);
    if let Some(hook) = execution_hook {
        session.set_execution_hook(hook);
    }
    loop {
        let mut line = String::new();
        let read = reader
            .by_ref()
            .take((MAX_COMMAND_BYTES + 1) as u64)
            .read_line(&mut line)?;
        if read == 0 {
            return Ok(());
        }
        if read > MAX_COMMAND_BYTES {
            writer.write_all(b"error command too long\n")?;
            writer.flush()?;
            if !line.ends_with('\n') {
                discard_line(&mut reader)?;
            }
            continue;
        }
        let result = session.execute_command(line.trim());
        writer.write_all(result.response.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        if result.close {
            return Ok(());
        }
    }
}

fn discard_line(reader: &mut impl BufRead) -> io::Result<()> {
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(());
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |position| position + 1);
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(());
        }
    }
}

fn parse_general_register(name: &str) -> Option<Register> {
    GENERAL_REGISTERS
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, register)| *register)
}

fn parse_u64(value: &str) -> Result<u64, DebugError> {
    let parsed = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"));
    if let Some(hex) = parsed {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
    .map_err(|_| DebugError::InvalidNumber(value.to_string()))
}

fn parse_usize(value: &str) -> Result<usize, DebugError> {
    usize::try_from(parse_u64(value)?).map_err(|_| DebugError::InvalidNumber(value.to_string()))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, DebugError> {
    if !value.len().is_multiple_of(2) || value.len() / 2 > MAX_MEMORY_TRANSFER {
        return Err(if value.len() / 2 > MAX_MEMORY_TRANSFER {
            DebugError::TransferTooLarge
        } else {
            DebugError::InvalidHex
        });
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_digit(pair[0]).ok_or(DebugError::InvalidHex)?;
            let low = hex_digit(pair[1]).ok_or(DebugError::InvalidHex)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

const fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn no_extra<'a>(mut fields: impl Iterator<Item = &'a str>) -> Result<(), DebugError> {
    if fields.next().is_none() {
        Ok(())
    } else {
        Err(DebugError::InvalidCommand("too many arguments"))
    }
}

fn one_field<'a>(mut fields: impl Iterator<Item = &'a str>) -> Result<&'a str, DebugError> {
    let first = fields
        .next()
        .ok_or(DebugError::InvalidCommand("missing argument"))?;
    no_extra(fields)?;
    Ok(first)
}

fn two_fields<'a>(
    mut fields: impl Iterator<Item = &'a str>,
) -> Result<(&'a str, &'a str), DebugError> {
    let first = fields
        .next()
        .ok_or(DebugError::InvalidCommand("missing argument"))?;
    let second = fields
        .next()
        .ok_or(DebugError::InvalidCommand("missing argument"))?;
    no_extra(fields)?;
    Ok((first, second))
}

fn optional_field<'a>(
    mut fields: impl Iterator<Item = &'a str>,
) -> Result<Option<&'a str>, DebugError> {
    let first = fields.next();
    no_extra(fields)?;
    Ok(first)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::MachineConfig;

    fn test_machine() -> Machine {
        let mut machine = Machine::new(MachineConfig {
            memory_bytes: 1024 * 1024,
            instruction_limit: 100,
            mirror_serial: false,
            ..MachineConfig::default()
        });
        machine
            .load_flat(0x1000, &[0x90, 0x90, 0xf4], 0x80000)
            .unwrap();
        machine
    }

    #[test]
    fn breakpoint_step_and_continue_do_not_patch_guest_memory() {
        let mut machine = test_machine();
        let mut session = DebugSession::new(&mut machine, 100);
        assert!(session.add_breakpoint(0x1001));
        assert_eq!(session.continue_execution(None), DebugStop::Breakpoint {
            address: 0x1001
        });
        assert_eq!(session.machine().cpu.state.cycles, 1);
        assert_eq!(session.step(), DebugStop::Step { address: 0x1002 });
        assert_eq!(session.continue_execution(None), DebugStop::Halted {
            address: 0x1003
        });
        assert_eq!(session.read_memory(0x1000, 3).unwrap(), [0x90, 0x90, 0xf4]);
    }

    #[test]
    fn execution_hook_is_polled_during_debug_continue() {
        let mut machine = test_machine();
        let polls = Arc::new(AtomicUsize::new(0));
        let hook_polls = Arc::clone(&polls);
        let mut session = DebugSession::new(&mut machine, 2);
        session.set_execution_hook(Box::new(move |_| {
            hook_polls.fetch_add(1, Ordering::Relaxed);
        }));
        assert_eq!(
            session.continue_execution(None),
            DebugStop::InstructionLimit {
                address: 0x1002,
                executed: 2,
            }
        );
        assert_eq!(polls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn software_watchpoint_stops_after_guest_memory_changes() {
        let mut machine = Machine::new(MachineConfig {
            memory_bytes: 1024 * 1024,
            instruction_limit: 100,
            mirror_serial: false,
            ..MachineConfig::default()
        });
        let mut program = vec![0x48, 0xbb];
        program.extend_from_slice(&0x2000_u64.to_le_bytes());
        program.extend_from_slice(&[0x48, 0xb8]);
        program.extend_from_slice(&0x1122_3344_5566_7788_u64.to_le_bytes());
        program.extend_from_slice(&[0x48, 0x89, 0x03, 0xf4]);
        machine.load_flat(0x1000, &program, 0x80000).unwrap();

        let mut session = DebugSession::new(&mut machine, 100);
        assert!(session.add_watchpoint(0x2000, 8).unwrap());
        assert_eq!(session.continue_execution(None), DebugStop::Watchpoint {
            address: 0x2000,
            length: 8,
            instruction: 0x1017,
        });
        assert_eq!(
            session.read_memory(0x2000, 8).unwrap(),
            0x1122_3344_5566_7788_u64.to_le_bytes()
        );
        assert_eq!(session.continue_execution(None), DebugStop::Halted {
            address: 0x1018
        });
    }

    #[test]
    fn backtrace_walks_bounded_monotonic_frame_pointer_chain() {
        let mut machine = test_machine();
        let mut session = DebugSession::new(&mut machine, 100);
        let mut records = Vec::new();
        records.extend_from_slice(&0x70010_u64.to_le_bytes());
        records.extend_from_slice(&0x2000_u64.to_le_bytes());
        records.extend_from_slice(&0_u64.to_le_bytes());
        records.extend_from_slice(&0x3000_u64.to_le_bytes());
        session.write_memory(0x70000, &records).unwrap();
        session.write_register("rbp", 0x70000).unwrap();

        assert_eq!(session.backtrace(8).unwrap(), [0x1000, 0x2000, 0x3000]);
        assert_eq!(session.backtrace(1).unwrap(), [0x1000]);
        assert!(matches!(
            session.backtrace(MAX_BACKTRACE_FRAMES + 1),
            Err(DebugError::InvalidBacktraceLimit)
        ));
    }

    #[test]
    fn watchpoint_count_and_memory_budget_are_enforced() {
        let mut machine = test_machine();
        let mut session = DebugSession::new(&mut machine, 100);
        assert!(matches!(
            session.add_watchpoint(0x2000, 0),
            Err(DebugError::InvalidWatchpointLength)
        ));
        for index in 0..MAX_WATCHPOINTS {
            assert!(session.add_watchpoint(0x2000 + index as u64, 1).unwrap());
        }
        assert!(matches!(
            session.add_watchpoint(0x3000, 1),
            Err(DebugError::TooManyWatchpoints)
        ));
        drop(session);

        let mut session = DebugSession::new(&mut machine, 100);
        assert!(session.add_watchpoint(0x2000, MAX_WATCHED_BYTES).unwrap());
        assert!(matches!(
            session.add_watchpoint(0x4000, 1),
            Err(DebugError::WatchpointBudgetExceeded)
        ));
    }

    #[test]
    fn protocol_supports_register_and_memory_mutation() {
        let mut machine = test_machine();
        let input = Cursor::new(
            b"hello\nwrite-register rax 0x2a\nread-register rax\nwrite-memory 0x1000 cc\nread-memory 0x1000 3\nquit\n",
        );
        let mut output = Vec::new();
        serve_stream(&mut machine, input, &mut output, 100).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "ok xenith-debug-v1\nok\nok rax=0x000000000000002a\nok\nok cc90f4\nok bye\n"
        );
    }

    #[test]
    fn protocol_lists_watchpoints_and_returns_raw_backtrace() {
        let mut machine = test_machine();
        let mut input = Vec::new();
        input.extend_from_slice(b"write-register rbp 0x70000\n");
        input.extend_from_slice(b"write-memory 0x70000 00000000000000000020000000000000\n");
        input
            .extend_from_slice(b"watch 0x2000 4\nwatchpoints\nbacktrace 4\nunwatch 0x2000\nquit\n");
        let mut output = Vec::new();
        serve_stream(&mut machine, Cursor::new(input), &mut output, 100).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            concat!(
                "ok\n",
                "ok\n",
                "ok added 0x0000000000002000 4\n",
                "ok 0x0000000000002000:4\n",
                "ok backtrace 0x0000000000001000 0x0000000000002000\n",
                "ok removed 0x0000000000002000\n",
                "ok bye\n"
            )
        );
    }

    #[test]
    fn configured_breakpoint_at_current_rip_resumes_once() {
        let mut machine = test_machine();
        let mut session = DebugSession::new(&mut machine, 1);
        session.add_breakpoint(0x1000);
        assert_eq!(session.continue_execution(None), DebugStop::Breakpoint {
            address: 0x1000
        });
        assert_eq!(
            session.continue_execution(None),
            DebugStop::InstructionLimit {
                address: 0x1001,
                executed: 1
            }
        );
    }

    #[test]
    fn overlong_command_does_not_consume_the_next_command() {
        let mut machine = test_machine();
        let mut input = vec![b'x'; MAX_COMMAND_BYTES + 1];
        input.extend_from_slice(b"\nstatus\nquit\n");
        let mut output = Vec::new();
        serve_stream(&mut machine, Cursor::new(input), &mut output, 100).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.starts_with("error command too long\nok paused rip=0x0000000000001000"));
        assert!(output.ends_with("\nok bye\n"));
    }
}
