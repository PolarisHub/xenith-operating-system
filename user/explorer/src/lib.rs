//! Fixed-capacity state, layout, and software rendering for Xenith Files.

#![no_std]
#![forbid(unsafe_code)]

pub mod layout;
pub mod model;
pub mod render;

pub use layout::{Layout, Point, Rect};
pub use model::{
    Command, Entry, EntryMetadata, ExplorerModel, FixedPath, HistoryMode, Interaction, KnownPlace,
    PathError, ENTRY_KIND_DIRECTORY, MAX_DIRECTORY_ENTRIES, MAX_PATH_BYTES,
};
pub use render::{render, RenderError};
