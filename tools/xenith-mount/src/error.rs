use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    UnknownFilesystem,
    Truncated(&'static str),
    Corrupt(&'static str),
    Unsupported(&'static str),
    InvalidPath(&'static str),
    NotFound(String),
    NotDirectory(String),
    IsDirectory(String),
    LimitExceeded(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::UnknownFilesystem => formatter.write_str("unknown filesystem image"),
            Self::Truncated(item) => write!(formatter, "truncated {item}"),
            Self::Corrupt(item) => write!(formatter, "corrupt {item}"),
            Self::Unsupported(item) => write!(formatter, "unsupported {item}"),
            Self::InvalidPath(reason) => write!(formatter, "invalid image path: {reason}"),
            Self::NotFound(path) => write!(formatter, "image path not found: {path}"),
            Self::NotDirectory(path) => write!(formatter, "image path is not a directory: {path}"),
            Self::IsDirectory(path) => write!(formatter, "image path is a directory: {path}"),
            Self::LimitExceeded(item) => write!(formatter, "parser limit exceeded: {item}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
