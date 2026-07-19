//! Xenith's deterministic x86-64 interpreter and PC device model.

pub mod cpu;
pub mod debug;
pub mod device;
pub mod elf;
pub mod firmware;
pub mod host_input;
pub mod machine;
pub mod memory;
pub mod platform;
pub mod uefi;

pub use cpu::{Cpu, CpuFault, CpuState, ExitReason};
pub use debug::{
    serve_listener as serve_debug_listener, serve_stream as serve_debug_stream,
    serve_tcp as serve_debug_tcp, serve_tcp_with_execution_hook as serve_debug_tcp_with_hook,
    DebugError, DebugSession, DebugStop, ExecutionHook, PROTOCOL_VERSION,
};
pub use firmware::{BiosBootTrace, FirmwareError};
pub use machine::{
    FramebufferConfig, KeyboardInputError, Machine, MachineConfig, MachineError, ManifestBoot,
    RunSummary, MAX_EMULATED_CPUS,
};
pub use memory::{Access, MemoryBus, MemoryError, PagingContext, Privilege};
pub use platform::{AtaDiskError, AtaDiskImage};
pub use uefi::{UefiError, UefiIsoBootTrace, UefiServiceCalls};
