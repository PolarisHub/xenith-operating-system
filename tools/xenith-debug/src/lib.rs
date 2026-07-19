//! Symbol loading, command preparation, and the Xenith emulator debug client.

pub mod client;
pub mod command;
pub mod rsp;
pub mod source;
pub mod symbols;

pub use client::{ClientError, DebugClient};
pub use command::{CommandError, CommandTranslator, PreparedCommand};
pub use source::{SourceLocation, SourceLookupError, SourceMap, SourceRange};
pub use symbols::{Symbol, SymbolError, SymbolKind, SymbolTable};

pub const PROTOCOL_VERSION: &str = "xenith-debug-v1";
