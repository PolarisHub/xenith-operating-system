//! Non-blocking host input transport for interactive emulator frontends.

use std::io::{self, Read};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread;

/// Maximum bytes carried by one host-input message.
pub const MAX_HOST_INPUT_CHUNK: usize = 256;

/// Number of chunks buffered between a blocking reader and the emulator.
///
/// At the current chunk size this caps queued host data at 4 KiB. If the
/// guest falls behind, only the background reader blocks; CPU/device
/// execution never waits for stdin.
pub const HOST_INPUT_CHANNEL_CAPACITY: usize = 16;

/// One event produced by a host input reader.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostInputEvent {
    /// Normalized ASCII bytes ready for keyboard encoding.
    Data(Vec<u8>),
    /// The source reached a clean end-of-file.
    Eof,
    /// The source failed or contained a byte outside the supported ASCII path.
    Error(String),
}

/// Receive side of a bounded background host-input reader.
pub struct HostInput {
    receiver: Receiver<HostInputEvent>,
    finished: bool,
}

impl HostInput {
    /// Poll without waiting for the reader or terminal.
    pub fn poll(&mut self) -> Option<HostInputEvent> {
        if self.finished {
            return None;
        }
        match self.receiver.try_recv() {
            Ok(HostInputEvent::Eof) => {
                self.finished = true;
                Some(HostInputEvent::Eof)
            },
            Ok(event) => Some(event),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.finished = true;
                Some(HostInputEvent::Eof)
            },
        }
    }

    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }
}

/// Read a terminal or file on a background thread into a bounded channel.
///
/// CRLF and bare CR are normalized to LF so one host Enter key produces one
/// PS/2 Enter make/break pair on Windows and Unix. The keyboard encoder is
/// intentionally ASCII-only; non-ASCII input is reported as an event without
/// terminating the reader.
pub fn spawn_host_input<R>(reader: R, thread_name: &str) -> io::Result<HostInput>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::sync_channel(HOST_INPUT_CHANNEL_CAPACITY);
    thread::Builder::new()
        .name(thread_name.to_string())
        .spawn(move || read_input(reader, &sender))?;
    Ok(HostInput {
        receiver,
        finished: false,
    })
}

fn read_input(mut reader: impl Read, sender: &SyncSender<HostInputEvent>) {
    let mut input = [0u8; MAX_HOST_INPUT_CHUNK];
    let mut output = Vec::with_capacity(MAX_HOST_INPUT_CHUNK);
    let mut pending_cr = false;

    loop {
        match reader.read(&mut input) {
            Ok(0) => {
                if pending_cr && !push_byte(b'\n', &mut output, sender) {
                    return;
                }
                if !flush(&mut output, sender) {
                    return;
                }
                let _ = sender.send(HostInputEvent::Eof);
                return;
            },
            Ok(count) => {
                for byte in input[..count].iter().copied() {
                    if pending_cr {
                        if !push_byte(b'\n', &mut output, sender) {
                            return;
                        }
                        pending_cr = false;
                        if byte == b'\n' {
                            continue;
                        }
                    }
                    if byte == b'\r' {
                        pending_cr = true;
                    } else if byte.is_ascii() {
                        if !push_byte(byte, &mut output, sender) {
                            return;
                        }
                    } else {
                        if !flush(&mut output, sender) {
                            return;
                        }
                        if sender
                            .send(HostInputEvent::Error(format!(
                                "unsupported non-ASCII input byte {byte:#04x}"
                            )))
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                if !flush(&mut output, sender) {
                    return;
                }
            },
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
            Err(error) => {
                if !flush(&mut output, sender) {
                    return;
                }
                let _ = sender.send(HostInputEvent::Error(error.to_string()));
                return;
            },
        }
    }
}

fn push_byte(byte: u8, output: &mut Vec<u8>, sender: &SyncSender<HostInputEvent>) -> bool {
    output.push(byte);
    if output.len() == MAX_HOST_INPUT_CHUNK {
        flush(output, sender)
    } else {
        true
    }
}

fn flush(output: &mut Vec<u8>, sender: &SyncSender<HostInputEvent>) -> bool {
    if output.is_empty() {
        return true;
    }
    let bytes = std::mem::replace(output, Vec::with_capacity(MAX_HOST_INPUT_CHUNK));
    sender.send(HostInputEvent::Data(bytes)).is_ok()
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Error};
    use std::time::Duration;

    use super::*;

    fn collect(mut input: HostInput) -> Result<Vec<HostInputEvent>, String> {
        let mut events = Vec::new();
        while !input.finished {
            match input.receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(HostInputEvent::Eof) => {
                    input.finished = true;
                    events.push(HostInputEvent::Eof);
                },
                Ok(event) => events.push(event),
                Err(mpsc::RecvTimeoutError::Disconnected) => input.finished = true,
                Err(error) => return Err(format!("input reader did not finish: {error}")),
            }
        }
        Ok(events)
    }

    #[test]
    fn normalizes_windows_and_bare_carriage_returns() {
        let input = spawn_host_input(
            Cursor::new(b"echo one\r\necho two\recho three\n"),
            "test-input",
        )
        .unwrap();
        let events = collect(input).unwrap();
        let bytes: Vec<u8> = events
            .iter()
            .filter_map(|event| match event {
                HostInputEvent::Data(bytes) => Some(bytes.as_slice()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect();
        assert_eq!(bytes, b"echo one\necho two\necho three\n");
        assert_eq!(events.last(), Some(&HostInputEvent::Eof));
    }

    #[test]
    fn channel_chunks_are_bounded_and_eof_is_explicit() {
        let input = spawn_host_input(Cursor::new(vec![b'a'; 1025]), "test-input").unwrap();
        let events = collect(input).unwrap();
        let chunks: Vec<&[u8]> = events
            .iter()
            .filter_map(|event| match event {
                HostInputEvent::Data(bytes) => Some(bytes.as_slice()),
                _ => None,
            })
            .collect();
        assert_eq!(chunks.iter().map(|chunk| chunk.len()).sum::<usize>(), 1025);
        assert!(chunks
            .iter()
            .all(|chunk| !chunk.is_empty() && chunk.len() <= MAX_HOST_INPUT_CHUNK));
        assert_eq!(events.last(), Some(&HostInputEvent::Eof));
    }

    struct FailedReader;

    impl Read for FailedReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(Error::other("read failed"))
        }
    }

    #[test]
    fn reports_reader_failure_then_disconnects_cleanly() {
        let input = spawn_host_input(FailedReader, "test-input").unwrap();
        assert_eq!(collect(input).unwrap(), vec![HostInputEvent::Error(
            "read failed".to_string()
        )]);
    }

    #[test]
    fn reports_non_ascii_bytes_without_losing_surrounding_ascii() {
        let input = spawn_host_input(Cursor::new(b"a\xffb"), "test-input").unwrap();
        assert_eq!(collect(input).unwrap(), vec![
            HostInputEvent::Data(vec![b'a']),
            HostInputEvent::Error("unsupported non-ASCII input byte 0xff".to_string()),
            HostInputEvent::Data(vec![b'b']),
            HostInputEvent::Eof,
        ]);
    }
}
