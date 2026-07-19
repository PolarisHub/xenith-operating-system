use std::{fmt, io};

/// Failure returned while constructing or validating an image.
#[derive(Debug)]
pub enum ImageError {
    /// A required component was empty or structurally invalid.
    InvalidInput(&'static str),
    /// The ISO volume identifier was not representable as an ISO9660 D-string.
    InvalidVolumeId(String),
    /// The requested image cannot be represented by its on-disk integer fields.
    ImageTooLarge(&'static str),
    /// A raw-disk manifest was malformed or failed validation.
    InvalidManifest(&'static str),
    /// Host filesystem I/O failed.
    Io(io::Error),
}

impl fmt::Display for ImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(formatter, "invalid input: {message}"),
            Self::InvalidVolumeId(id) => write!(
                formatter,
                "invalid ISO volume identifier {id:?}; use 1-32 uppercase A-Z, 0-9, or _ characters"
            ),
            Self::ImageTooLarge(component) => {
                write!(formatter, "{component} is too large for the image format")
            },
            Self::InvalidManifest(message) => write!(formatter, "invalid disk manifest: {message}"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
        }
    }
}

impl std::error::Error for ImageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ImageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
