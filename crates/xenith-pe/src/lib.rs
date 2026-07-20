//! Checked, allocation-free parsing for Xenith's initial PE32+ image subset.
//!
//! This crate recognizes AMD64 PE32+ images, validates their structural ranges,
//! and produces a declarative loader plan. It deliberately does not map memory,
//! apply relocations, resolve imports, call Windows APIs, or execute image code.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod headers;
mod image;
mod imports;
mod plan;
mod policy;
mod reader;
mod relocation;

pub use error::PeError;
pub use headers::{
    CoffHeader, DataDirectory, DosHeader, FileRange, OptionalHeader64, PeHeaders, RvaRange,
    SectionHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_FILE_MACHINE_AMD64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, MAX_DATA_DIRECTORIES, MAX_IMAGE_SIZE, MAX_SECTIONS,
};
pub use image::PeImage;
pub use imports::{
    ImportDescriptor, ImportRecord, ImportSummary, ImportTarget, MAX_IMPORTS_PER_MODULE,
    MAX_IMPORTS_TOTAL, MAX_IMPORT_DIRECTORY_BYTES, MAX_IMPORT_MODULES, MAX_IMPORT_NAME_BYTES,
};
pub use plan::{HeaderLoad, LoadPermissions, LoaderPlan, SectionLoad};
pub use policy::{DirectorySupport, LoaderFormatPolicy};
pub use relocation::{
    BaseRelocationPlan, RelocationPatch, MAX_BASE_RELOCATIONS, RELOCATION_TYPE_ABSOLUTE,
    RELOCATION_TYPE_DIR64,
};
