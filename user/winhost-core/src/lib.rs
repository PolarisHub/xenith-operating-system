//! Allocation-free policy primitives for an eventual Xenith Windows host.
//!
//! This crate is plumbing, not application compatibility. It contains no
//! Windows implementation code, performs no system calls, maps no memory, and
//! executes no guest code. Callers remain responsible for object lifetimes,
//! page-table operations, IAT writes, and every supported Windows API contract.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod handle;
mod imports;
mod layout;
mod object;
mod path;
mod runtime;
mod service;
mod status;
mod sync;
mod types;
mod vm;

pub use handle::{
    AccessMask, GuestHandle, HandleEntry, HandleError, HandleTable, ObjectType, MAX_HANDLE_ENTRIES,
};
pub use imports::{
    ExportQuery, ExportTargetRegistration, ForwarderName, ImportBinding, ImportPlanError,
    ImportResolution, ImportResolutionPlan, ImportSymbol, ModuleError, ModuleId, ModuleName,
    ModuleRegistry, SymbolName, MAX_EXPORT_NAME_BYTES, MAX_FORWARDER_NAME_BYTES,
    MAX_MODULE_NAME_BYTES, MAX_REGISTERED_EXPORTS, MAX_REGISTERED_MODULES,
};
pub use layout::{
    plan_runtime_environment, LayoutError, RuntimeAddressRange, RuntimeEnvironmentPlan,
    RuntimeLayoutRequest, MAX_ENVIRONMENT_BYTES, MAX_PROCESS_PARAMETERS_BYTES,
    PEB64_BOOTSTRAP_BYTES, PEB64_PROCESS_PARAMETERS_OFFSET,
    PROCESS_PARAMETERS64_COMMAND_LINE_OFFSET, PROCESS_PARAMETERS64_ENVIRONMENT_OFFSET,
    PROCESS_PARAMETERS64_IMAGE_PATH_OFFSET, PROCESS_PARAMETERS64_PREFIX_BYTES,
    RUNTIME_LAYOUT_PAGE_SIZE, RUNTIME_USER_ADDRESS_LIMIT, TEB64_BOOTSTRAP_BYTES, TEB64_PEB_OFFSET,
    TEB64_SELF_OFFSET,
};
pub use object::{
    ConsoleObject, ObjectError, ObjectId, ObjectTable, RuntimeObject, MAX_OBJECT_ENTRIES,
};
pub use path::{normalize_nt_path, NormalizedNtPath, NtPathKind, PathError};
pub use runtime::NtRuntime;
pub use service::{
    resolve_nt_service, NtService, NtServiceCall, NtServiceReply, NtServiceValue, NtWaitMode,
};
pub use status::{ntstatus_to_dos_error, DosError, NtSeverity, NtStatus};
pub use sync::{
    EventKind, EventState, MutantState, SemaphoreState, SyncError, TimerKind, TimerState,
    WaitSatisfaction,
};
pub use types::{
    NtBoolean, NtClientId64, NtLargeInteger, NtThreadId, NtTypeError, NtUnicodeString64,
};
pub use vm::{
    AddressError, ImagePlacement, PeImageLayout, PeSectionMapping, Reservation, ReservationKind,
    VirtualAddressPlanner, VmProtection, MAX_ADDRESS_RESERVATIONS, PE_IMAGE_ALIGNMENT,
    VM_PAGE_SIZE,
};
