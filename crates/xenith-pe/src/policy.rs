use crate::{
    PeError, PeImage, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS,
};

/// Initial Xenith loader support state for one PE data-directory feature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectorySupport {
    /// The image does not advertise the directory.
    Absent,
    /// The foundation layer has a checked parser/planner for the directory.
    Supported,
    /// The directory is present but deliberately outside the current loader policy.
    Unsupported,
}

/// Explicit feature policy derived from an image's directory table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoaderFormatPolicy {
    /// Regular import descriptors.
    pub regular_imports: DirectorySupport,
    /// AMD64 image base relocations.
    pub base_relocations: DirectorySupport,
    /// PE TLS metadata.
    pub tls: DirectorySupport,
    /// Delay-load import metadata.
    pub delay_imports: DirectorySupport,
}

impl PeImage<'_> {
    /// Reports directory support without silently accepting unsupported features.
    #[must_use]
    pub fn loader_format_policy(&self) -> LoaderFormatPolicy {
        LoaderFormatPolicy {
            regular_imports: supported_when_present(self, IMAGE_DIRECTORY_ENTRY_IMPORT),
            base_relocations: supported_when_present(self, IMAGE_DIRECTORY_ENTRY_BASERELOC),
            tls: unsupported_when_present(self, IMAGE_DIRECTORY_ENTRY_TLS),
            delay_imports: unsupported_when_present(self, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT),
        }
    }

    /// Rejects TLS and delay imports under the initial loader policy.
    ///
    /// The structural parser still accepts and reports those directories so
    /// future layers can add support without changing the core image format.
    pub fn require_initial_loader_policy(&self) -> Result<LoaderFormatPolicy, PeError> {
        let policy = self.loader_format_policy();
        if policy.tls == DirectorySupport::Unsupported {
            if let Some(directory) = self.directory(IMAGE_DIRECTORY_ENTRY_TLS) {
                return Err(PeError::UnsupportedTlsDirectory {
                    rva: directory.address,
                    size: directory.size,
                });
            }
        }
        if policy.delay_imports == DirectorySupport::Unsupported {
            if let Some(directory) = self.directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
                return Err(PeError::UnsupportedDelayImportDirectory {
                    rva: directory.address,
                    size: directory.size,
                });
            }
        }
        Ok(policy)
    }
}

fn supported_when_present(image: &PeImage<'_>, index: usize) -> DirectorySupport {
    if has_directory(image, index) {
        DirectorySupport::Supported
    } else {
        DirectorySupport::Absent
    }
}

fn unsupported_when_present(image: &PeImage<'_>, index: usize) -> DirectorySupport {
    if has_directory(image, index) {
        DirectorySupport::Unsupported
    } else {
        DirectorySupport::Absent
    }
}

fn has_directory(image: &PeImage<'_>, index: usize) -> bool {
    image
        .directory(index)
        .is_some_and(|directory| !directory.is_empty())
}
