//! Blocking client for the emulator's one-command/one-response TCP protocol.

use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};

use crate::PROTOCOL_VERSION;

const MAX_LINE_BYTES: usize = 16_384;

#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    Protocol(String),
    CommandTooLong,
    EmbeddedNewline,
}

impl From<io::Error> for ClientError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Protocol(message) => write!(formatter, "protocol error: {message}"),
            Self::CommandTooLong => formatter.write_str("command exceeds 16384 bytes"),
            Self::EmbeddedNewline => formatter.write_str("command contains a newline"),
        }
    }
}

impl std::error::Error for ClientError {}

pub struct DebugClient {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl DebugClient {
    pub fn connect(address: impl ToSocketAddrs) -> Result<Self, ClientError> {
        let writer = TcpStream::connect(address)?;
        writer.set_nodelay(true)?;
        let reader = BufReader::new(writer.try_clone()?);
        let mut client = Self { reader, writer };
        let response = client.command("hello")?;
        let expected = format!("ok {PROTOCOL_VERSION}");
        if response != expected {
            return Err(ClientError::Protocol(format!(
                "expected {expected:?}, received {response:?}"
            )));
        }
        Ok(client)
    }

    pub fn command(&mut self, command: &str) -> Result<String, ClientError> {
        if command.len() > MAX_LINE_BYTES {
            return Err(ClientError::CommandTooLong);
        }
        if command.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err(ClientError::EmbeddedNewline);
        }
        self.writer.write_all(command.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        let mut response = String::new();
        let read = self.reader.read_line(&mut response)?;
        if read == 0 {
            return Err(ClientError::Protocol("connection closed".to_string()));
        }
        if read > MAX_LINE_BYTES {
            return Err(ClientError::Protocol("response too long".to_string()));
        }
        while response.ends_with(['\r', '\n']) {
            response.pop();
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    #[test]
    fn handshake_and_command_are_line_deterministic() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line, "hello\n");
            stream.write_all(b"ok xenith-debug-v1\n").unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line, "read-register rip\n");
            stream.write_all(b"ok rip=0x0000000000001000\n").unwrap();
        });
        let mut client = DebugClient::connect(address).unwrap();
        assert_eq!(
            client.command("read-register rip").unwrap(),
            "ok rip=0x0000000000001000"
        );
        server.join().unwrap();
    }
}
