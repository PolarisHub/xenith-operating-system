//! Console terminal and reusable bounded line discipline.

use xenith_abi::{
    TerminalAttributes, WindowSize, ECHO, ECHOE, ECHOK, ECHONL, ICANON, ICRNL, ISIG, ONLCR, OPOST,
    VEOF, VEOL, VERASE, VINTR, VKILL, VMIN, VQUIT, VSUSP, VTIME,
};

use crate::devices::ps2::keyboard::{KeyCode, KeyEvent};
use crate::sync::SpinLock;
use crate::user::signal::Signal;
use crate::util::ringbuffer::RingBuffer;

const EDIT_CAPACITY: usize = 1024;
const INPUT_CAPACITY: usize = 4096;
const RECORD_CAPACITY: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CanonicalRecord {
    length: usize,
    eof: bool,
}

/// Bounded terminal line discipline shared by the console and PTY slaves.
///
/// Input editing and completed records live alongside an output queue.  The
/// console drains that queue to its display/serial backends, while a PTY
/// master drains it as the slave's output stream.  Keeping the queue here
/// makes echo, canonical editing, signals, and raw `VMIN`/`VTIME` behavior
/// identical for both terminal kinds.
pub(crate) struct LineDiscipline {
    attributes: TerminalAttributes,
    window_size: WindowSize,
    ready: RingBuffer<u8, INPUT_CAPACITY>,
    records: RingBuffer<CanonicalRecord, RECORD_CAPACITY>,
    active_record: usize,
    edit: [u8; EDIT_CAPACITY],
    edit_len: usize,
    cursor: usize,
    interrupted: Option<Signal>,
    foreground_group: u64,
    output: RingBuffer<u8, INPUT_CAPACITY>,
}

impl LineDiscipline {
    pub(crate) const fn new() -> Self {
        let mut control_characters = [0u8; xenith_abi::syscall::TERMINAL_CONTROL_CHARACTERS];
        control_characters[VINTR] = 3;
        control_characters[VQUIT] = 28;
        control_characters[VERASE] = 127;
        control_characters[VKILL] = 21;
        control_characters[VEOF] = 4;
        control_characters[VEOL] = b'\n';
        control_characters[VSUSP] = 26;
        control_characters[VMIN] = 1;
        Self {
            attributes: TerminalAttributes {
                input_flags: ICRNL,
                output_flags: OPOST | ONLCR,
                control_flags: 0,
                local_flags: ISIG | ICANON | ECHO | ECHOE | ECHOK,
                control_characters,
            },
            window_size: WindowSize {
                rows: 25,
                columns: 80,
                pixel_width: 0,
                pixel_height: 0,
            },
            ready: RingBuffer::new(),
            records: RingBuffer::new(),
            active_record: 0,
            edit: [0; EDIT_CAPACITY],
            edit_len: 0,
            cursor: 0,
            interrupted: None,
            foreground_group: 0,
            output: RingBuffer::new(),
        }
    }

    fn canonical(&self) -> bool {
        self.attributes.local_flags & ICANON != 0
    }

    fn echo(&self) -> bool {
        self.attributes.local_flags & ECHO != 0
    }

    fn queue_output(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            let _ = self.output.push(byte);
        }
    }

    fn emit(&mut self, bytes: &[u8]) {
        if self.echo() {
            self.queue_output(bytes);
        }
    }

    fn insert_byte(&mut self, byte: u8, do_echo: bool) {
        if self.edit_len == EDIT_CAPACITY {
            if do_echo {
                self.queue_output(&[7]);
            }
            return;
        }
        self.edit
            .copy_within(self.cursor..self.edit_len, self.cursor + 1);
        self.edit[self.cursor] = byte;
        self.edit_len += 1;
        self.cursor += 1;
        if do_echo && self.echo() {
            for index in self.cursor - 1..self.edit_len {
                let _ = self.output.push(self.edit[index]);
            }
            for _ in self.cursor..self.edit_len {
                self.queue_output(&[8]);
            }
        }
    }

    fn erase_before_cursor(&mut self, do_echo: bool) {
        if self.cursor == 0 {
            return;
        }
        let erased = self.cursor - 1;
        self.edit.copy_within(self.cursor..self.edit_len, erased);
        self.edit_len -= 1;
        self.cursor -= 1;
        if do_echo && self.echo() && self.attributes.local_flags & ECHOE != 0 {
            self.queue_output(&[8]);
            for index in self.cursor..self.edit_len {
                let _ = self.output.push(self.edit[index]);
            }
            self.queue_output(b" ");
            for _ in self.cursor..=self.edit_len {
                self.queue_output(&[8]);
            }
        }
    }

    fn delete_at_cursor(&mut self, do_echo: bool) {
        if self.cursor >= self.edit_len {
            return;
        }
        self.edit
            .copy_within(self.cursor + 1..self.edit_len, self.cursor);
        self.edit_len -= 1;
        if do_echo && self.echo() && self.attributes.local_flags & ECHOE != 0 {
            for index in self.cursor..self.edit_len {
                let _ = self.output.push(self.edit[index]);
            }
            self.queue_output(b" ");
            for _ in self.cursor..=self.edit_len {
                self.queue_output(&[8]);
            }
        }
    }

    fn kill_line(&mut self, do_echo: bool) {
        if do_echo && self.echo() && self.attributes.local_flags & ECHOK != 0 {
            while self.cursor < self.edit_len {
                let _ = self.output.push(self.edit[self.cursor]);
                self.cursor += 1;
            }
            for _ in 0..self.edit_len {
                self.queue_output(&[8]);
            }
            for _ in 0..self.edit_len {
                self.queue_output(b" ");
            }
            for _ in 0..self.edit_len {
                self.queue_output(&[8]);
            }
        }
        self.edit_len = 0;
        self.cursor = 0;
    }

    fn commit_line(&mut self, include_newline: bool, do_echo: bool) {
        let length = self.edit_len + usize::from(include_newline);
        let has_room =
            self.ready.capacity() - self.ready.len() >= length && !self.records.is_full();
        if !has_room {
            if do_echo {
                self.queue_output(&[7]);
            }
            return;
        }
        for &byte in &self.edit[..self.edit_len] {
            let _ = self.ready.push(byte);
        }
        if include_newline {
            let _ = self.ready.push(b'\n');
        }
        let _ = self.records.push(CanonicalRecord { length, eof: false });
        self.edit_len = 0;
        self.cursor = 0;
        if do_echo && (self.echo() || self.attributes.local_flags & ECHONL != 0) && include_newline
        {
            self.queue_output(b"\n");
        }
    }

    fn commit_eof(&mut self, do_echo: bool) {
        if self.records.is_full() || self.ready.capacity() - self.ready.len() < self.edit_len {
            if do_echo {
                self.queue_output(&[7]);
            }
            return;
        }
        for &byte in &self.edit[..self.edit_len] {
            let _ = self.ready.push(byte);
        }
        let _ = self.records.push(CanonicalRecord {
            length: self.edit_len,
            eof: self.edit_len == 0,
        });
        self.edit_len = 0;
        self.cursor = 0;
    }

    fn feed_byte(&mut self, mut byte: u8, do_echo: bool) {
        if byte == b'\r' && self.attributes.input_flags & ICRNL != 0 {
            byte = b'\n';
        }
        if self.attributes.local_flags & ISIG != 0 {
            let cc = &self.attributes.control_characters;
            let signal = if byte == cc[VINTR] {
                Some(Signal::Int)
            } else if byte == cc[VQUIT] {
                Some(Signal::Quit)
            } else if byte == cc[VSUSP] {
                Some(Signal::Tstp)
            } else {
                None
            };
            if let Some(signal) = signal {
                self.kill_line(do_echo);
                if do_echo && self.echo() {
                    let display = match signal {
                        Signal::Int => b"^C\n" as &[u8],
                        Signal::Quit => b"^\\\n",
                        Signal::Tstp => b"^Z\n",
                        _ => b"\n",
                    };
                    self.queue_output(display);
                }
                self.interrupted = Some(signal);
                return;
            }
        }

        if !self.canonical() {
            if self.ready.push(byte).is_ok() && do_echo {
                self.emit(&[byte]);
            }
            return;
        }

        let cc = &self.attributes.control_characters;
        if byte == cc[VERASE] || byte == 8 {
            self.erase_before_cursor(do_echo);
        } else if byte == cc[VKILL] {
            self.kill_line(do_echo);
        } else if byte == cc[VEOF] {
            self.commit_eof(do_echo);
        } else if byte == b'\n' || (cc[VEOL] != 0 && byte == cc[VEOL]) {
            self.commit_line(true, do_echo);
        } else {
            self.insert_byte(byte, do_echo);
        }
    }

    fn feed_event(&mut self, event: KeyEvent, do_echo: bool) {
        if !event.pressed {
            return;
        }
        match event.code {
            KeyCode::ArrowLeft if self.canonical() && self.cursor > 0 => {
                self.cursor -= 1;
                if do_echo && self.echo() {
                    self.queue_output(&[8]);
                }
            },
            KeyCode::ArrowRight if self.canonical() && self.cursor < self.edit_len => {
                if do_echo && self.echo() {
                    let _ = self.output.push(self.edit[self.cursor]);
                }
                self.cursor += 1;
            },
            KeyCode::Home if self.canonical() => {
                if do_echo && self.echo() {
                    for _ in 0..self.cursor {
                        self.queue_output(&[8]);
                    }
                }
                self.cursor = 0;
            },
            KeyCode::End if self.canonical() => {
                if do_echo && self.echo() {
                    for index in self.cursor..self.edit_len {
                        let _ = self.output.push(self.edit[index]);
                    }
                }
                self.cursor = self.edit_len;
            },
            KeyCode::Delete if self.canonical() => self.delete_at_cursor(do_echo),
            _ => {
                if let Some(character) = event.character {
                    let mut encoded = [0u8; 4];
                    let bytes = character.encode_utf8(&mut encoded).as_bytes();
                    for &byte in bytes {
                        let byte = if event.modifiers.control() && byte.is_ascii() {
                            byte.to_ascii_lowercase() & 0x1f
                        } else {
                            byte
                        };
                        self.feed_byte(byte, do_echo);
                    }
                }
            },
        }
    }

    fn try_read(&mut self, destination: &mut [u8]) -> Result<Option<usize>, Signal> {
        if let Some(signal) = self.interrupted.take() {
            return Err(signal);
        }
        if self.canonical() {
            if self.active_record == 0 {
                let Some(record) = self.records.pop() else {
                    return Ok(None);
                };
                if record.eof {
                    return Ok(Some(0));
                }
                self.active_record = record.length;
            }
            let count = destination.len().min(self.active_record);
            for byte in &mut destination[..count] {
                *byte = self
                    .ready
                    .pop()
                    .expect("canonical record exceeds ready bytes");
            }
            self.active_record -= count;
            return Ok(Some(count));
        }

        let minimum = usize::from(self.attributes.control_characters[VMIN]).min(destination.len());
        if self.ready.len() < minimum {
            return Ok(None);
        }
        let count = destination.len().min(self.ready.len());
        for byte in &mut destination[..count] {
            *byte = self.ready.pop().expect("terminal ready length changed");
        }
        Ok(Some(count))
    }

    fn flush_input(&mut self) {
        self.ready.clear();
        self.records.clear();
        self.active_record = 0;
        self.edit_len = 0;
        self.cursor = 0;
        self.interrupted = None;
    }

    fn pending(&self) -> usize {
        self.ready.len()
    }

    fn drain_raw(&mut self, destination: &mut [u8]) -> usize {
        let count = destination.len().min(self.ready.len());
        for byte in &mut destination[..count] {
            *byte = self.ready.pop().expect("terminal ready length changed");
        }
        count
    }

    pub(crate) fn feed_input_byte(&mut self, byte: u8) -> Option<Signal> {
        let previous = self.interrupted;
        self.feed_byte(byte, true);
        (self.interrupted != previous)
            .then_some(self.interrupted)
            .flatten()
    }

    pub(crate) fn read_once(
        &mut self,
        destination: &mut [u8],
        nonblocking: bool,
        now_ns: u64,
        timer: &mut RawReadTimer,
    ) -> Result<Option<usize>, Signal> {
        if self.canonical() {
            return self.try_read(destination);
        }
        if let Some(signal) = self.interrupted.take() {
            return Err(signal);
        }
        if nonblocking {
            return if self.ready.is_empty() {
                Ok(None)
            } else {
                Ok(Some(self.drain_raw(destination)))
            };
        }
        let minimum = usize::from(self.attributes.control_characters[VMIN]);
        let timeout = self.attributes.control_characters[VTIME];
        if raw_read_decision(
            minimum,
            timeout,
            self.ready.len(),
            destination.len(),
            now_ns,
            timer,
        ) == RawReadDecision::Read
        {
            Ok(Some(self.drain_raw(destination)))
        } else {
            Ok(None)
        }
    }

    pub(crate) const fn attributes(&self) -> TerminalAttributes {
        self.attributes
    }

    pub(crate) fn set_attributes(&mut self, attributes: TerminalAttributes, flush: bool) {
        self.attributes = attributes;
        if flush {
            self.flush_input();
        }
    }

    pub(crate) const fn window_size(&self) -> WindowSize {
        self.window_size
    }

    pub(crate) fn set_window_size(&mut self, window_size: WindowSize) {
        self.window_size = window_size;
    }

    pub(crate) fn pending_input(&self) -> usize {
        self.pending()
    }

    pub(crate) const fn foreground_group(&self) -> u64 {
        self.foreground_group
    }

    pub(crate) fn set_foreground_group(&mut self, process_group: u64) {
        self.foreground_group = process_group;
    }

    pub(crate) fn output_pending(&self) -> usize {
        self.output.len()
    }

    pub(crate) fn output_available(&self) -> usize {
        self.output.capacity() - self.output.len()
    }

    pub(crate) fn push_output(&mut self, byte: u8) -> Result<(), u8> {
        self.output.push(byte)
    }

    pub(crate) fn drain_output(&mut self, destination: &mut [u8]) -> usize {
        let count = destination.len().min(self.output.len());
        for byte in &mut destination[..count] {
            *byte = self.output.pop().expect("terminal output length changed");
        }
        count
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RawReadTimer {
    deadline_ns: Option<u64>,
    observed_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RawReadDecision {
    Wait,
    Read,
}

fn raw_read_decision(
    minimum: usize,
    timeout_deciseconds: u8,
    available: usize,
    capacity: usize,
    now_ns: u64,
    timer: &mut RawReadTimer,
) -> RawReadDecision {
    let minimum = minimum.min(capacity);
    if timeout_deciseconds == 0 {
        return if available >= minimum {
            RawReadDecision::Read
        } else {
            RawReadDecision::Wait
        };
    }
    let timeout_ns = u64::from(timeout_deciseconds) * 100_000_000;
    if minimum == 0 {
        if available != 0 {
            return RawReadDecision::Read;
        }
        let deadline = *timer
            .deadline_ns
            .get_or_insert(now_ns.saturating_add(timeout_ns));
        return if now_ns >= deadline {
            RawReadDecision::Read
        } else {
            RawReadDecision::Wait
        };
    }
    if available >= minimum {
        return RawReadDecision::Read;
    }
    if available > timer.observed_bytes {
        timer.observed_bytes = available;
        timer.deadline_ns = Some(now_ns.saturating_add(timeout_ns));
    }
    if timer.deadline_ns.is_some_and(|deadline| now_ns >= deadline) {
        RawReadDecision::Read
    } else {
        RawReadDecision::Wait
    }
}

static TERMINAL: SpinLock<LineDiscipline> = SpinLock::new(LineDiscipline::new());

/// Read from the controlling console, blocking cooperatively until the line
/// discipline has a complete canonical record (or enough raw bytes).
pub fn read(destination: &mut [u8]) -> Result<usize, Signal> {
    if destination.is_empty() {
        return Ok(0);
    }
    let mut raw_timer = RawReadTimer::default();
    loop {
        wait_for_foreground_read();
        while let Some(event) = crate::devices::ps2::keyboard::pop_event() {
            TERMINAL.lock().feed_event(event, true);
            flush_console_echo();
        }
        let mut terminal = TERMINAL.lock();
        if let Some(read) =
            terminal.read_once(destination, false, crate::time::uptime_ns(), &mut raw_timer)?
        {
            return Ok(read);
        }
        drop(terminal);
        crate::sched::yield_now();
    }
}

#[must_use]
pub fn attributes() -> TerminalAttributes {
    TERMINAL.lock().attributes()
}

pub fn set_attributes(attributes: TerminalAttributes, flush: bool) {
    TERMINAL.lock().set_attributes(attributes, flush);
}

#[must_use]
pub fn window_size() -> WindowSize {
    TERMINAL.lock().window_size()
}

pub fn set_window_size(window_size: WindowSize) {
    TERMINAL.lock().set_window_size(window_size);
}

#[must_use]
pub fn pending_input() -> usize {
    TERMINAL.lock().pending_input()
}

#[must_use]
pub fn foreground_group() -> u64 {
    TERMINAL.lock().foreground_group()
}

pub fn set_foreground_group(process_group: u64) {
    TERMINAL.lock().set_foreground_group(process_group);
}

fn flush_console_echo() {
    let mut output = [0u8; 256];
    loop {
        let count = TERMINAL.lock().drain_output(&mut output);
        if count == 0 {
            return;
        }
        write_output(&output[..count]);
    }
}

/// Route a terminal-generated signal to the complete foreground job.
pub fn signal_foreground(signal: Signal) {
    let process_group = foreground_group();
    if process_group != 0 {
        let _ = crate::user::process::signal_group(crate::user::ProcessId(process_group), signal);
    } else if let Some(pid) = crate::user::process::try_current_pid() {
        let _ = crate::user::process::signal(pid, signal);
    }
}

fn wait_for_foreground_read() {
    loop {
        let process_group = crate::user::process::current_process_group();
        let foreground = foreground_group();
        if process_group.is_kernel() || foreground == 0 || foreground == process_group.as_u64() {
            return;
        }
        let _ = crate::user::process::signal_group(process_group, Signal::Ttin);
        if !crate::user::process::current_is_stopped() {
            return;
        }
        crate::user::process::enforce_current_state();
    }
}

/// Write bytes to the display console and COM1. Serial newlines use CRLF,
/// while the display backend receives its native newline character.
pub fn write_output(bytes: &[u8]) -> usize {
    #[cfg(not(test))]
    {
        let mut serial = crate::devices::serial::COM1.lock();
        for &byte in bytes {
            crate::console::write_char(byte as char);
            if byte == b'\n' {
                serial.send(b'\r');
            }
            serial.send(byte);
        }
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> LineDiscipline {
        LineDiscipline::new()
    }

    #[test]
    fn canonical_input_waits_for_line_and_preserves_records() {
        let mut tty = fresh();
        tty.feed_byte(b'a', false);
        tty.feed_byte(b'b', false);
        let mut out = [0u8; 8];
        assert_eq!(tty.try_read(&mut out), Ok(None));
        tty.feed_byte(b'\n', false);
        assert_eq!(tty.try_read(&mut out), Ok(Some(3)));
        assert_eq!(&out[..3], b"ab\n");
    }

    #[test]
    fn editing_supports_cursor_insert_delete_and_kill() {
        let mut tty = fresh();
        tty.feed_byte(b'a', false);
        tty.feed_byte(b'c', false);
        tty.cursor = 1;
        tty.feed_byte(b'b', false);
        assert_eq!(&tty.edit[..tty.edit_len], b"abc");
        tty.cursor = 1;
        tty.delete_at_cursor(false);
        assert_eq!(&tty.edit[..tty.edit_len], b"ac");
        tty.feed_byte(tty.attributes.control_characters[VKILL], false);
        assert_eq!(tty.edit_len, 0);
    }

    #[test]
    fn eof_delivers_partial_line_then_zero_length_record() {
        let mut tty = fresh();
        let eof = tty.attributes.control_characters[VEOF];
        tty.feed_byte(b'x', false);
        tty.feed_byte(eof, false);
        let mut out = [0u8; 4];
        assert_eq!(tty.try_read(&mut out), Ok(Some(1)));
        assert_eq!(out[0], b'x');
        tty.feed_byte(eof, false);
        assert_eq!(tty.try_read(&mut out), Ok(Some(0)));
    }

    #[test]
    fn raw_mode_obeys_vmin_and_delivers_immediately() {
        let mut tty = fresh();
        tty.attributes.local_flags &= !ICANON;
        tty.attributes.control_characters[VMIN] = 2;
        tty.feed_byte(b'a', false);
        let mut out = [0u8; 4];
        assert_eq!(tty.try_read(&mut out), Ok(None));
        tty.feed_byte(b'b', false);
        assert_eq!(tty.try_read(&mut out), Ok(Some(2)));
        assert_eq!(&out[..2], b"ab");
    }

    #[test]
    fn isig_turns_control_c_into_interrupt_not_input() {
        let mut tty = fresh();
        tty.feed_byte(tty.attributes.control_characters[VINTR], false);
        let mut out = [0u8; 1];
        assert_eq!(tty.try_read(&mut out), Err(Signal::Int));
        assert_eq!(tty.pending(), 0);
    }

    #[test]
    fn vtime_without_vmin_expires_from_read_start() {
        let mut timer = RawReadTimer::default();
        assert_eq!(
            raw_read_decision(0, 2, 0, 8, 1_000_000_000, &mut timer),
            RawReadDecision::Wait
        );
        assert_eq!(
            raw_read_decision(0, 2, 0, 8, 1_199_999_999, &mut timer),
            RawReadDecision::Wait
        );
        assert_eq!(
            raw_read_decision(0, 2, 0, 8, 1_200_000_000, &mut timer),
            RawReadDecision::Read
        );
    }

    #[test]
    fn vtime_with_vmin_is_an_interbyte_timer() {
        let mut timer = RawReadTimer::default();
        assert_eq!(
            raw_read_decision(3, 1, 0, 8, 0, &mut timer),
            RawReadDecision::Wait
        );
        assert_eq!(timer.deadline_ns, None);
        assert_eq!(
            raw_read_decision(3, 1, 1, 8, 10, &mut timer),
            RawReadDecision::Wait
        );
        assert_eq!(timer.deadline_ns, Some(100_000_010));
        assert_eq!(
            raw_read_decision(3, 1, 2, 8, 50_000_000, &mut timer),
            RawReadDecision::Wait
        );
        assert_eq!(timer.deadline_ns, Some(150_000_000));
        assert_eq!(
            raw_read_decision(3, 1, 2, 8, 150_000_000, &mut timer),
            RawReadDecision::Read
        );
    }
}
