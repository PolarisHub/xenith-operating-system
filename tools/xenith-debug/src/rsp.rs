//! Bounded GDB Remote Serial Protocol adapter for Xenith's native debugger.
//!
//! The native newline protocol remains the execution backend. This module
//! translates the useful single-thread x86-64 RSP subset and deliberately
//! keeps framing independent of TCP so a serial byte stream can use the same
//! parser once a hardware-side Xenith debug endpoint exists.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpListener, ToSocketAddrs};

use crate::DebugClient;

/// Maximum decoded or encoded packet payload accepted from either peer.
pub const MAX_PACKET_PAYLOAD: usize = 16_384;
/// Xenith's native debug protocol limits one memory operation to 4 KiB.
pub const MAX_MEMORY_TRANSFER: usize = 4_096;
/// Per-RSP-session bound for software breakpoints created by GDB.
pub const MAX_SOFTWARE_BREAKPOINTS: usize = 128;

const PACKET_SIZE_HEX: &str = "4000";
const DEFAULT_STOP: &str = "S05";
const ERROR_MALFORMED: &str = "E01";
const ERROR_REGISTER: &str = "E02";
const ERROR_MEMORY: &str = "E14";
const ERROR_ARGUMENT: &str = "E16";
const ERROR_LIMIT: &str = "E1c";

const TARGET_XML: &str = r#"<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  <architecture>i386:x86-64</architecture>
  <feature name="org.gnu.gdb.i386.core">
    <reg name="rax" bitsize="64" type="int64" regnum="0"/>
    <reg name="rbx" bitsize="64" type="int64" regnum="1"/>
    <reg name="rcx" bitsize="64" type="int64" regnum="2"/>
    <reg name="rdx" bitsize="64" type="int64" regnum="3"/>
    <reg name="rsi" bitsize="64" type="int64" regnum="4"/>
    <reg name="rdi" bitsize="64" type="int64" regnum="5"/>
    <reg name="rbp" bitsize="64" type="data_ptr" regnum="6"/>
    <reg name="rsp" bitsize="64" type="data_ptr" regnum="7"/>
    <reg name="r8" bitsize="64" type="int64" regnum="8"/>
    <reg name="r9" bitsize="64" type="int64" regnum="9"/>
    <reg name="r10" bitsize="64" type="int64" regnum="10"/>
    <reg name="r11" bitsize="64" type="int64" regnum="11"/>
    <reg name="r12" bitsize="64" type="int64" regnum="12"/>
    <reg name="r13" bitsize="64" type="int64" regnum="13"/>
    <reg name="r14" bitsize="64" type="int64" regnum="14"/>
    <reg name="r15" bitsize="64" type="int64" regnum="15"/>
    <reg name="rip" bitsize="64" type="code_ptr" regnum="16"/>
    <reg name="eflags" bitsize="32" type="int32" regnum="17"/>
    <reg name="cs" bitsize="32" type="int32" regnum="18"/>
    <reg name="ss" bitsize="32" type="int32" regnum="19"/>
    <reg name="ds" bitsize="32" type="int32" regnum="20"/>
    <reg name="es" bitsize="32" type="int32" regnum="21"/>
    <reg name="fs" bitsize="32" type="int32" regnum="22"/>
    <reg name="gs" bitsize="32" type="int32" regnum="23"/>
  </feature>
</target>
"#;

#[derive(Clone, Copy)]
struct RegisterDescription {
    backend_name: &'static str,
    byte_size: usize,
}

const fn register(backend_name: &'static str, byte_size: usize) -> RegisterDescription {
    RegisterDescription {
        backend_name,
        byte_size,
    }
}

const REGISTERS: [RegisterDescription; 24] = [
    register("rax", 8),
    register("rbx", 8),
    register("rcx", 8),
    register("rdx", 8),
    register("rsi", 8),
    register("rdi", 8),
    register("rbp", 8),
    register("rsp", 8),
    register("r8", 8),
    register("r9", 8),
    register("r10", 8),
    register("r11", 8),
    register("r12", 8),
    register("r13", 8),
    register("r14", 8),
    register("r15", 8),
    register("rip", 8),
    register("rflags", 4),
    register("cs", 4),
    register("ss", 4),
    register("ds", 4),
    register("es", 4),
    register("fs", 4),
    register("gs", 4),
];

/// Backend seam implemented by Xenith's native debug client and test doubles.
pub trait DebugCommandBackend {
    /// Execute exactly one native Xenith command and return its response line.
    fn command(&mut self, command: &str) -> Result<String, String>;
}

impl DebugCommandBackend for DebugClient {
    fn command(&mut self, command: &str) -> Result<String, String> {
        DebugClient::command(self, command).map_err(|error| error.to_string())
    }
}

/// Any blocking bidirectional byte stream, including TCP and serial ports.
pub trait RspTransport: Read + Write {}

impl<T: Read + Write + ?Sized> RspTransport for T {}

#[derive(Debug)]
pub enum RspError {
    Io(io::Error),
    PacketTooLarge,
}

impl From<io::Error> for RspError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl fmt::Display for RspError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "RSP I/O error: {error}"),
            Self::PacketTooLarge => write!(
                formatter,
                "RSP packet exceeds the {MAX_PACKET_PAYLOAD}-byte limit"
            ),
        }
    }
}

impl std::error::Error for RspError {}

struct CommandReply {
    payload: String,
    close: bool,
    enter_no_ack: bool,
}

impl CommandReply {
    fn packet(payload: impl Into<String>) -> Self {
        Self {
            payload: payload.into(),
            close: false,
            enter_no_ack: false,
        }
    }

    fn close(payload: impl Into<String>) -> Self {
        Self {
            payload: payload.into(),
            close: true,
            enter_no_ack: false,
        }
    }
}

struct RspSession<B> {
    backend: B,
    ack_mode: bool,
    last_stop: String,
    breakpoints: BTreeSet<u64>,
}

impl<B: DebugCommandBackend> RspSession<B> {
    fn new(backend: B) -> Self {
        Self {
            backend,
            ack_mode: true,
            last_stop: DEFAULT_STOP.to_owned(),
            breakpoints: BTreeSet::new(),
        }
    }

    fn handle(&mut self, packet: &[u8]) -> CommandReply {
        let Ok(packet) = std::str::from_utf8(packet) else {
            return CommandReply::packet(ERROR_MALFORMED);
        };
        if packet == "?" {
            return CommandReply::packet(self.last_stop.clone());
        }
        if packet.starts_with("qSupported") {
            return CommandReply::packet(format!(
                "PacketSize={PACKET_SIZE_HEX};QStartNoAckMode+;qXfer:features:read+;swbreak+;vContSupported+"
            ));
        }
        if packet == "QStartNoAckMode" {
            return CommandReply {
                payload: "OK".to_owned(),
                close: false,
                enter_no_ack: true,
            };
        }
        if let Some(request) = packet.strip_prefix("qXfer:features:read:target.xml:") {
            return CommandReply::packet(target_xml_chunk(request));
        }
        match packet {
            "qAttached" => return CommandReply::packet("1"),
            "qC" => return CommandReply::packet("QC1"),
            "qfThreadInfo" => return CommandReply::packet("m1"),
            "qsThreadInfo" => return CommandReply::packet("l"),
            "qOffsets" => return CommandReply::packet("Text=0;Data=0;Bss=0"),
            "qSymbol::" => return CommandReply::packet("OK"),
            "vCont?" => return CommandReply::packet("vCont;c;s"),
            "!" => return CommandReply::packet("OK"),
            _ => {},
        }
        if let Some(thread) = packet.strip_prefix('H') {
            return CommandReply::packet(if valid_thread_selector(thread) {
                "OK"
            } else {
                ERROR_ARGUMENT
            });
        }
        if let Some(thread) = packet.strip_prefix('T') {
            return CommandReply::packet(if matches!(thread, "1" | "01") {
                "OK"
            } else {
                ERROR_ARGUMENT
            });
        }
        if packet == "g" {
            return CommandReply::packet(self.read_all_registers());
        }
        if let Some(register) = packet.strip_prefix('p') {
            return CommandReply::packet(self.read_register(register));
        }
        if let Some(values) = packet.strip_prefix('G') {
            return CommandReply::packet(self.write_all_registers(values));
        }
        if let Some(write) = packet.strip_prefix('P') {
            return CommandReply::packet(self.write_register(write));
        }
        if let Some(read) = packet.strip_prefix('m') {
            return CommandReply::packet(self.read_memory(read));
        }
        if let Some(write) = packet.strip_prefix('M') {
            return CommandReply::packet(self.write_memory(write));
        }
        if let Some(breakpoint) = packet.strip_prefix("Z0,") {
            return CommandReply::packet(self.insert_breakpoint(breakpoint));
        }
        if let Some(breakpoint) = packet.strip_prefix("z0,") {
            return CommandReply::packet(self.remove_breakpoint(breakpoint));
        }
        if let Some(address) = packet.strip_prefix('c') {
            return CommandReply::packet(self.resume(false, address));
        }
        if let Some(address) = packet.strip_prefix('s') {
            return CommandReply::packet(self.resume(true, address));
        }
        if let Some(actions) = packet.strip_prefix("vCont;") {
            return CommandReply::packet(self.vcont(actions));
        }
        if packet == "D" || packet.strip_prefix("D;").is_some_and(valid_process_id) {
            let _ = self.backend.command("quit");
            return CommandReply::close("OK");
        }
        if packet.starts_with("D;") {
            return CommandReply::packet(ERROR_ARGUMENT);
        }
        if packet == "k" || packet.strip_prefix("vKill;").is_some_and(valid_process_id) {
            let _ = self.backend.command("quit");
            return CommandReply::close("OK");
        }
        if packet.starts_with("vKill;") {
            return CommandReply::packet(ERROR_ARGUMENT);
        }
        // RSP requires an empty response for an unsupported request.
        CommandReply::packet("")
    }

    fn backend_command(&mut self, command: &str) -> Result<String, &'static str> {
        match self.backend.command(command) {
            Ok(response) if response.starts_with("error ") => {
                eprintln!("xenith-debug: RSP backend rejected {command:?}: {response}");
                Err(ERROR_MALFORMED)
            },
            Ok(response) => Ok(response),
            Err(error) => {
                eprintln!("xenith-debug: RSP backend failed {command:?}: {error}");
                Err(ERROR_MALFORMED)
            },
        }
    }

    fn read_all_registers(&mut self) -> String {
        let response = match self.backend_command("registers") {
            Ok(response) => response,
            Err(error) => return error.to_owned(),
        };
        let Some(fields) = response.strip_prefix("ok ") else {
            return ERROR_REGISTER.to_owned();
        };
        let mut values = [None; REGISTERS.len()];
        for field in fields.split_ascii_whitespace() {
            let Some((name, value)) = field.split_once('=') else {
                continue;
            };
            let Some(index) = REGISTERS
                .iter()
                .position(|register| register.backend_name == name)
            else {
                continue;
            };
            values[index] = parse_backend_number(value).ok();
        }
        if values.iter().any(Option::is_none) {
            return ERROR_REGISTER.to_owned();
        }
        let mut output = String::with_capacity(register_packet_hex_len());
        for (register, value) in REGISTERS.iter().zip(values.into_iter().flatten()) {
            encode_register(value, register.byte_size, &mut output);
        }
        output
    }

    fn read_register(&mut self, register: &str) -> String {
        let Some(register) = parse_register_number(register) else {
            return ERROR_REGISTER.to_owned();
        };
        let command = format!("read-register {}", register.backend_name);
        let response = match self.backend_command(&command) {
            Ok(response) => response,
            Err(error) => return error.to_owned(),
        };
        let Some((prefix, value)) = response.split_once('=') else {
            return ERROR_REGISTER.to_owned();
        };
        if prefix != format!("ok {}", register.backend_name) {
            return ERROR_REGISTER.to_owned();
        }
        let Ok(value) = parse_backend_number(value) else {
            return ERROR_REGISTER.to_owned();
        };
        let mut output = String::with_capacity(register.byte_size * 2);
        encode_register(value, register.byte_size, &mut output);
        output
    }

    fn write_all_registers(&mut self, values: &str) -> String {
        if values.len() != register_packet_hex_len()
            || !values.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return ERROR_REGISTER.to_owned();
        }
        let mut decoded = Vec::with_capacity(REGISTERS.len());
        let mut offset = 0;
        for register in REGISTERS {
            let end = offset + register.byte_size * 2;
            let Some(value) = decode_register(&values.as_bytes()[offset..end], register.byte_size)
            else {
                return ERROR_REGISTER.to_owned();
            };
            decoded.push(value);
            offset = end;
        }
        for (register, value) in REGISTERS.iter().zip(decoded) {
            let command = format!("write-register {} {value:#x}", register.backend_name);
            if !self.command_succeeded(&command) {
                return ERROR_REGISTER.to_owned();
            }
        }
        "OK".to_owned()
    }

    fn write_register(&mut self, write: &str) -> String {
        let Some((number, value)) = write.split_once('=') else {
            return ERROR_MALFORMED.to_owned();
        };
        let Some(register) = parse_register_number(number) else {
            return ERROR_REGISTER.to_owned();
        };
        let Some(value) = decode_register(value.as_bytes(), register.byte_size) else {
            return ERROR_REGISTER.to_owned();
        };
        let command = format!("write-register {} {value:#x}", register.backend_name);
        if self.command_succeeded(&command) {
            "OK".to_owned()
        } else {
            ERROR_REGISTER.to_owned()
        }
    }

    fn read_memory(&mut self, read: &str) -> String {
        let Some((address, length)) = parse_address_length(read) else {
            return ERROR_ARGUMENT.to_owned();
        };
        if length > MAX_MEMORY_TRANSFER || !range_fits(address, length) {
            return ERROR_LIMIT.to_owned();
        }
        let command = format!("read-memory {address:#x} {length}");
        let response = match self.backend_command(&command) {
            Ok(response) => response,
            Err(_) => return ERROR_MEMORY.to_owned(),
        };
        let Some(bytes) = response.strip_prefix("ok ") else {
            return ERROR_MEMORY.to_owned();
        };
        if bytes.len() != length.saturating_mul(2)
            || !bytes.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return ERROR_MEMORY.to_owned();
        }
        bytes.to_ascii_lowercase()
    }

    fn write_memory(&mut self, write: &str) -> String {
        let Some((range, bytes)) = write.split_once(':') else {
            return ERROR_MALFORMED.to_owned();
        };
        let Some((address, length)) = parse_address_length(range) else {
            return ERROR_ARGUMENT.to_owned();
        };
        if length > MAX_MEMORY_TRANSFER || !range_fits(address, length) {
            return ERROR_LIMIT.to_owned();
        }
        if bytes.len() != length.saturating_mul(2)
            || !bytes.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return ERROR_MALFORMED.to_owned();
        }
        if length == 0 {
            return "OK".to_owned();
        }
        let command = format!("write-memory {address:#x} {}", bytes.to_ascii_lowercase());
        if self.command_succeeded(&command) {
            "OK".to_owned()
        } else {
            ERROR_MEMORY.to_owned()
        }
    }

    fn insert_breakpoint(&mut self, breakpoint: &str) -> String {
        let Some((address, kind)) = parse_breakpoint(breakpoint) else {
            return ERROR_ARGUMENT.to_owned();
        };
        if kind == 0 || kind > 16 {
            return ERROR_ARGUMENT.to_owned();
        }
        if self.breakpoints.contains(&address) {
            return "OK".to_owned();
        }
        if self.breakpoints.len() == MAX_SOFTWARE_BREAKPOINTS {
            return ERROR_LIMIT.to_owned();
        }
        if !self.command_succeeded(&format!("break {address:#x}")) {
            return ERROR_MEMORY.to_owned();
        }
        self.breakpoints.insert(address);
        "OK".to_owned()
    }

    fn remove_breakpoint(&mut self, breakpoint: &str) -> String {
        let Some((address, kind)) = parse_breakpoint(breakpoint) else {
            return ERROR_ARGUMENT.to_owned();
        };
        if kind == 0 || kind > 16 {
            return ERROR_ARGUMENT.to_owned();
        }
        if !self.command_succeeded(&format!("delete {address:#x}")) {
            return ERROR_MEMORY.to_owned();
        }
        self.breakpoints.remove(&address);
        "OK".to_owned()
    }

    fn resume(&mut self, step: bool, address: &str) -> String {
        if !address.is_empty() {
            let Ok(address) = u64::from_str_radix(address, 16) else {
                return ERROR_ARGUMENT.to_owned();
            };
            if !self.command_succeeded(&format!("write-register rip {address:#x}")) {
                return ERROR_REGISTER.to_owned();
            }
        }
        let command = if step { "step" } else { "continue" };
        let response = match self.backend_command(command) {
            Ok(response) => response,
            Err(error) => return error.to_owned(),
        };
        match stop_reply(&response) {
            Some(stop) => {
                self.last_stop = stop.clone();
                stop
            },
            None => ERROR_MALFORMED.to_owned(),
        }
    }

    fn vcont(&mut self, actions: &str) -> String {
        if actions.contains(';') {
            return ERROR_ARGUMENT.to_owned();
        }
        let (action, thread) = actions.split_once(':').unwrap_or((actions, "-1"));
        if !matches!(thread, "-1" | "0" | "1") {
            return ERROR_ARGUMENT.to_owned();
        }
        match action {
            "c" => self.resume(false, ""),
            "s" => self.resume(true, ""),
            _ => ERROR_ARGUMENT.to_owned(),
        }
    }

    fn command_succeeded(&mut self, command: &str) -> bool {
        self.backend_command(command)
            .is_ok_and(|response| response == "ok" || response.starts_with("ok "))
    }
}

enum WireEvent {
    Ack,
    Nack,
    Interrupt,
    Packet { payload: Vec<u8>, valid: bool },
    Noise,
}

/// Serve one RSP client over any blocking bidirectional stream.
///
/// A `serialport`-style object can implement [`Read`] + [`Write`] and be
/// passed directly; Xenith currently supplies only the emulator-side native
/// protocol backend, not an in-kernel hardware serial debug stub.
pub fn serve_stream<B: DebugCommandBackend, S: RspTransport + ?Sized>(
    backend: B,
    stream: &mut S,
) -> Result<(), RspError> {
    let mut session = RspSession::new(backend);
    let mut last_frame = Vec::new();
    loop {
        let Some(event) = read_event(stream)? else {
            return Ok(());
        };
        match event {
            WireEvent::Ack | WireEvent::Noise => {},
            WireEvent::Nack => {
                if session.ack_mode && !last_frame.is_empty() {
                    stream.write_all(&last_frame)?;
                    stream.flush()?;
                }
            },
            WireEvent::Interrupt => {
                last_frame = encode_packet(session.last_stop.as_bytes())?;
                stream.write_all(&last_frame)?;
                stream.flush()?;
            },
            WireEvent::Packet { payload, valid } => {
                if !valid {
                    if session.ack_mode {
                        stream.write_all(b"-")?;
                        stream.flush()?;
                    }
                    continue;
                }
                if session.ack_mode {
                    stream.write_all(b"+")?;
                }
                let reply = session.handle(&payload);
                last_frame = encode_packet(reply.payload.as_bytes())?;
                stream.write_all(&last_frame)?;
                stream.flush()?;
                if reply.enter_no_ack {
                    session.ack_mode = false;
                }
                if reply.close {
                    return Ok(());
                }
            },
        }
    }
}

/// Accept one GDB connection from an already-bound TCP listener.
pub fn serve_listener<B: DebugCommandBackend>(
    backend: B,
    listener: &TcpListener,
) -> Result<(), RspError> {
    let (mut stream, _) = listener.accept()?;
    stream.set_nodelay(true)?;
    serve_stream(backend, &mut stream)
}

/// Bind a TCP GDB endpoint and bridge one client to a native Xenith backend.
pub fn serve_tcp<B: DebugCommandBackend, A: ToSocketAddrs>(
    backend: B,
    address: A,
) -> Result<(), RspError> {
    let listener = TcpListener::bind(address)?;
    eprintln!(
        "xenith-debug: GDB RSP listening on {}",
        listener.local_addr()?
    );
    serve_listener(backend, &listener)
}

fn read_event(stream: &mut (impl Read + ?Sized)) -> Result<Option<WireEvent>, RspError> {
    let Some(first) = read_byte(stream)? else {
        return Ok(None);
    };
    match first {
        b'+' => Ok(Some(WireEvent::Ack)),
        b'-' => Ok(Some(WireEvent::Nack)),
        0x03 => Ok(Some(WireEvent::Interrupt)),
        b'$' => read_packet(stream).map(Some),
        _ => Ok(Some(WireEvent::Noise)),
    }
}

fn read_packet(stream: &mut (impl Read + ?Sized)) -> Result<WireEvent, RspError> {
    let mut encoded = Vec::new();
    let mut decoded = Vec::new();
    let mut escaped = false;
    loop {
        let Some(byte) = read_byte(stream)? else {
            return Ok(WireEvent::Packet {
                payload: decoded,
                valid: false,
            });
        };
        if !escaped && byte == b'#' {
            break;
        }
        if encoded.len() == MAX_PACKET_PAYLOAD || decoded.len() == MAX_PACKET_PAYLOAD {
            return Err(RspError::PacketTooLarge);
        }
        encoded.push(byte);
        if escaped {
            decoded.push(byte ^ 0x20);
            escaped = false;
        } else if byte == b'}' {
            escaped = true;
        } else {
            decoded.push(byte);
        }
    }
    if escaped {
        return Ok(WireEvent::Packet {
            payload: decoded,
            valid: false,
        });
    }
    let Some(high) = read_byte(stream)? else {
        return Ok(WireEvent::Packet {
            payload: decoded,
            valid: false,
        });
    };
    let Some(low) = read_byte(stream)? else {
        return Ok(WireEvent::Packet {
            payload: decoded,
            valid: false,
        });
    };
    let expected = hex_digit(high)
        .zip(hex_digit(low))
        .map(|(high, low)| (high << 4) | low);
    let actual = encoded
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    Ok(WireEvent::Packet {
        payload: decoded,
        valid: expected == Some(actual),
    })
}

fn read_byte(stream: &mut (impl Read + ?Sized)) -> Result<Option<u8>, io::Error> {
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(_) => return Ok(Some(byte[0])),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
            Err(error) => return Err(error),
        }
    }
}

fn encode_packet(payload: &[u8]) -> Result<Vec<u8>, RspError> {
    if payload.len() > MAX_PACKET_PAYLOAD {
        return Err(RspError::PacketTooLarge);
    }
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.push(b'$');
    let mut checksum = 0u8;
    for byte in payload {
        if matches!(*byte, b'$' | b'#' | b'}' | b'*') {
            for escaped in [b'}', *byte ^ 0x20] {
                frame.push(escaped);
                checksum = checksum.wrapping_add(escaped);
            }
        } else {
            frame.push(*byte);
            checksum = checksum.wrapping_add(*byte);
        }
    }
    frame.push(b'#');
    frame.push(hex_char(checksum >> 4));
    frame.push(hex_char(checksum & 0x0f));
    Ok(frame)
}

fn target_xml_chunk(request: &str) -> String {
    let Some((offset, length)) = request.split_once(',') else {
        return ERROR_MALFORMED.to_owned();
    };
    let (Ok(offset), Ok(length)) = (
        usize::from_str_radix(offset, 16),
        usize::from_str_radix(length, 16),
    ) else {
        return ERROR_MALFORMED.to_owned();
    };
    if offset > TARGET_XML.len() {
        return "l".to_owned();
    }
    let length = length.min(MAX_PACKET_PAYLOAD - 1);
    let end = offset.saturating_add(length).min(TARGET_XML.len());
    let marker = if end == TARGET_XML.len() { 'l' } else { 'm' };
    format!("{marker}{}", &TARGET_XML[offset..end])
}

fn valid_thread_selector(selector: &str) -> bool {
    selector.len() >= 2
        && matches!(selector.as_bytes()[0], b'c' | b'g')
        && matches!(&selector[1..], "-1" | "0" | "1")
}

fn valid_process_id(value: &str) -> bool {
    !value.is_empty() && u64::from_str_radix(value, 16).is_ok()
}

fn parse_register_number(value: &str) -> Option<RegisterDescription> {
    let index = usize::from_str_radix(value, 16).ok()?;
    REGISTERS.get(index).copied()
}

fn register_packet_hex_len() -> usize {
    REGISTERS
        .iter()
        .map(|register| register.byte_size * 2)
        .sum()
}

fn parse_address_length(value: &str) -> Option<(u64, usize)> {
    let (address, length) = value.split_once(',')?;
    let address = u64::from_str_radix(address, 16).ok()?;
    let length = usize::from_str_radix(length, 16).ok()?;
    Some((address, length))
}

fn parse_breakpoint(value: &str) -> Option<(u64, usize)> {
    parse_address_length(value)
}

fn range_fits(address: u64, length: usize) -> bool {
    length == 0 || address.checked_add((length - 1) as u64).is_some()
}

fn parse_backend_number(value: &str) -> Result<u64, std::num::ParseIntError> {
    value
        .strip_prefix("0x")
        .map_or_else(|| value.parse(), |value| u64::from_str_radix(value, 16))
}

fn encode_u64(value: u64, output: &mut String) {
    encode_register(value, 8, output);
}

fn encode_register(value: u64, byte_size: usize, output: &mut String) {
    use fmt::Write as _;
    for byte in &value.to_le_bytes()[..byte_size] {
        let _ = write!(output, "{byte:02x}");
    }
}

fn decode_register(value: &[u8], byte_size: usize) -> Option<u64> {
    if !matches!(byte_size, 4 | 8) || value.len() != byte_size * 2 {
        return None;
    }
    let mut bytes = [0u8; 8];
    for (destination, pair) in bytes[..byte_size].iter_mut().zip(value.as_chunks::<2>().0) {
        *destination = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Some(u64::from_le_bytes(bytes))
}

fn stop_reply(response: &str) -> Option<String> {
    let mut fields = response.split_ascii_whitespace();
    if fields.next()? != "stop" {
        return None;
    }
    let reason = fields.next()?;
    match reason {
        "breakpoint" => {
            let address = parse_backend_number(fields.next()?).ok()?;
            Some(format!("T05thread:1;swbreak:;{}", pc_field(address)))
        },
        "step" | "limit" => {
            let address = parse_backend_number(fields.next()?).ok()?;
            Some(format!("T05thread:1;{}", pc_field(address)))
        },
        "watchpoint" => {
            let watched = parse_backend_number(fields.next()?).ok()?;
            let _length = fields.next()?.parse::<usize>().ok()?;
            let instruction = parse_backend_number(fields.next()?).ok()?;
            Some(format!(
                "T05thread:1;watch:{watched:x};{}",
                pc_field(instruction)
            ))
        },
        "fault" => {
            let address = parse_backend_number(fields.next()?).ok()?;
            Some(format!("T0bthread:1;{}", pc_field(address)))
        },
        "halted" => Some("W00".to_owned()),
        _ => None,
    }
}

fn pc_field(address: u64) -> String {
    let mut encoded = String::with_capacity(16);
    encode_u64(address, &mut encoded);
    format!("10:{encoded};")
}

const fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

const fn hex_char(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + value - 10,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::Cursor;

    use super::*;

    struct ScriptedBackend {
        script: VecDeque<(&'static str, &'static str)>,
    }

    impl DebugCommandBackend for ScriptedBackend {
        fn command(&mut self, command: &str) -> Result<String, String> {
            let Some((expected, response)) = self.script.pop_front() else {
                return Err(format!("unexpected command {command}"));
            };
            if command != expected {
                return Err(format!("expected {expected}, got {command}"));
            }
            Ok(response.to_owned())
        }
    }

    struct MemoryTransport {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for MemoryTransport {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for MemoryTransport {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn framing_rejects_bad_checksums_and_enters_no_ack_mode() {
        let mut input = b"$?#00".to_vec();
        input.extend_from_slice(&encode_packet(b"?").unwrap());
        input.extend_from_slice(&encode_packet(b"QStartNoAckMode").unwrap());
        input.extend_from_slice(&encode_packet(b"?").unwrap());
        let mut transport = MemoryTransport {
            input: Cursor::new(input),
            output: Vec::new(),
        };
        serve_stream(
            ScriptedBackend {
                script: VecDeque::new(),
            },
            &mut transport,
        )
        .unwrap();
        let mut expected = b"-+".to_vec();
        expected.extend_from_slice(&encode_packet(DEFAULT_STOP.as_bytes()).unwrap());
        expected.push(b'+');
        expected.extend_from_slice(&encode_packet(b"OK").unwrap());
        expected.extend_from_slice(&encode_packet(DEFAULT_STOP.as_bytes()).unwrap());
        assert_eq!(transport.output, expected);
    }

    #[test]
    fn register_values_use_target_little_endian_order() {
        let mut session = RspSession::new(ScriptedBackend {
            script: VecDeque::from([
                ("read-register rax", "ok rax=0x1122334455667788"),
                ("write-register rbx 0x2a", "ok"),
                ("read-register rflags", "ok rflags=0x0000000000000202"),
                ("write-register cs 0x8", "ok"),
            ]),
        });
        assert_eq!(session.handle(b"p0").payload, "8877665544332211");
        assert_eq!(session.handle(b"P1=2a00000000000000").payload, "OK");
        assert_eq!(session.handle(b"p11").payload, "02020000");
        assert_eq!(session.handle(b"P12=08000000").payload, "OK");
    }

    #[test]
    fn full_register_snapshot_follows_advertised_sizes_and_order() {
        let mut session = RspSession::new(ScriptedBackend {
            script: VecDeque::from([(
                "registers",
                concat!(
                    "ok rax=0x1 rcx=0x3 rdx=0x4 rbx=0x2 rsp=0x8 rbp=0x7 ",
                    "rsi=0x5 rdi=0x6 r8=0x9 r9=0xa r10=0xb r11=0xc r12=0xd ",
                    "r13=0xe r14=0xf r15=0x10 rip=0x11 rflags=0x202 cs=0x8 ",
                    "ss=0x10 ds=0x10 es=0x10 fs=0 gs=0 cycles=7"
                ),
            )]),
        });
        let packet = session.handle(b"g").payload;
        assert_eq!(packet.len(), register_packet_hex_len());
        assert!(packet.starts_with("01000000000000000200000000000000"));
        assert_eq!(&packet[17 * 16..17 * 16 + 8], "02020000");
    }

    #[test]
    fn target_description_is_bounded_and_chunked() {
        let first = target_xml_chunk("0,20");
        assert!(first.starts_with("m<?xml"));
        assert_eq!(first.len(), 0x21);
        let tail = target_xml_chunk(&format!("{:x},4000", TARGET_XML.len() - 4));
        assert_eq!(tail, format!("l{}", &TARGET_XML[TARGET_XML.len() - 4..]));
        assert_eq!(target_xml_chunk("bad"), ERROR_MALFORMED);
    }

    #[test]
    fn memory_and_breakpoint_limits_fail_before_backend_access() {
        let mut session = RspSession::new(ScriptedBackend {
            script: VecDeque::new(),
        });
        assert_eq!(session.handle(b"m1000,1001").payload, ERROR_LIMIT);
        assert_eq!(session.handle(b"M1000,2:00").payload, ERROR_MALFORMED);
        assert_eq!(session.handle(b"Z0,1000,0").payload, ERROR_ARGUMENT);
    }

    #[test]
    fn stop_responses_preserve_reason_and_program_counter() {
        assert_eq!(
            stop_reply("stop breakpoint 0x0000000000001001").unwrap(),
            "T05thread:1;swbreak:;10:0110000000000000;"
        );
        assert_eq!(
            stop_reply("stop watchpoint 0x2000 8 0x1004").unwrap(),
            "T05thread:1;watch:2000;10:0410000000000000;"
        );
        assert_eq!(stop_reply("stop halted 0x1004").unwrap(), "W00");
    }
}
