//! Symbol-keyed internal NT service dispatch contracts.
//!
//! Service identities are resolved from exact `NTDLL.DLL` export names. They
//! are intentionally not Windows syscall numbers: those vary by Windows build
//! and are not part of Xenith's clean-room contract.

use crate::{
    AccessMask, EventKind, GuestHandle, ModuleName, NtStatus, NtThreadId, SymbolName, TimerKind,
};

/// Stable internal service identity selected by an export symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtService {
    /// `NtClose`.
    Close,
    /// `NtDuplicateObject` reduced to same-process handle duplication.
    DuplicateObject,
    /// `NtCreateEvent`.
    CreateEvent,
    /// `NtSetEvent`.
    SetEvent,
    /// `NtResetEvent`.
    ResetEvent,
    /// `NtCreateMutant`.
    CreateMutant,
    /// `NtReleaseMutant`.
    ReleaseMutant,
    /// `NtCreateSemaphore`.
    CreateSemaphore,
    /// `NtReleaseSemaphore`.
    ReleaseSemaphore,
    /// `NtCreateTimer`.
    CreateTimer,
    /// `NtSetTimer` reduced to monotonic relative deadlines without APCs.
    SetTimer,
    /// `NtCancelTimer`.
    CancelTimer,
    /// `NtWaitForSingleObject` reduced to nonblocking polls and ready fast paths.
    WaitForSingleObject,
    /// No supported service matched the supplied symbol.
    Unknown,
}

impl NtService {
    /// Returns the exact supported NTDLL symbol, or an empty slice for unknown.
    #[must_use]
    pub const fn symbol(self) -> &'static [u8] {
        match self {
            Self::Close => b"NtClose",
            Self::DuplicateObject => b"NtDuplicateObject",
            Self::CreateEvent => b"NtCreateEvent",
            Self::SetEvent => b"NtSetEvent",
            Self::ResetEvent => b"NtResetEvent",
            Self::CreateMutant => b"NtCreateMutant",
            Self::ReleaseMutant => b"NtReleaseMutant",
            Self::CreateSemaphore => b"NtCreateSemaphore",
            Self::ReleaseSemaphore => b"NtReleaseSemaphore",
            Self::CreateTimer => b"NtCreateTimer",
            Self::SetTimer => b"NtSetTimer",
            Self::CancelTimer => b"NtCancelTimer",
            Self::WaitForSingleObject => b"NtWaitForSingleObject",
            Self::Unknown => b"",
        }
    }
}

/// Resolves one exact export name without assigning a numeric syscall ID.
#[must_use]
pub fn resolve_nt_service(module: &[u8], symbol: &[u8]) -> NtService {
    let Ok(module) = ModuleName::parse(module) else {
        return NtService::Unknown;
    };
    let Ok(symbol) = SymbolName::parse(symbol) else {
        return NtService::Unknown;
    };
    if module.as_bytes() != b"NTDLL.DLL" {
        return NtService::Unknown;
    }
    match symbol.as_bytes() {
        b"NtClose" => NtService::Close,
        b"NtDuplicateObject" => NtService::DuplicateObject,
        b"NtCreateEvent" => NtService::CreateEvent,
        b"NtSetEvent" => NtService::SetEvent,
        b"NtResetEvent" => NtService::ResetEvent,
        b"NtCreateMutant" => NtService::CreateMutant,
        b"NtReleaseMutant" => NtService::ReleaseMutant,
        b"NtCreateSemaphore" => NtService::CreateSemaphore,
        b"NtReleaseSemaphore" => NtService::ReleaseSemaphore,
        b"NtCreateTimer" => NtService::CreateTimer,
        b"NtSetTimer" => NtService::SetTimer,
        b"NtCancelTimer" => NtService::CancelTimer,
        b"NtWaitForSingleObject" => NtService::WaitForSingleObject,
        _ => NtService::Unknown,
    }
}

/// Whether a wait request may park the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtWaitMode {
    /// Inspect and consume current signal state without parking.
    Poll,
    /// Request a scheduler-backed blocking wait.
    Blocking,
}

/// Typed, pointer-free internal arguments for one supported service.
///
/// Guest pointer validation and ABI decoding belong in a future boundary
/// adapter. Keeping this layer pointer-free lets the semantic core remain safe
/// and makes unsupported blocking/APC behavior explicit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtServiceCall {
    /// Close one handle.
    Close {
        /// Handle to close.
        handle: GuestHandle,
    },
    /// Duplicate one same-process handle.
    DuplicateObject {
        /// Existing handle.
        source: GuestHandle,
        /// Optional access attenuation.
        desired_access: Option<AccessMask>,
        /// Optional replacement inheritance flag.
        inheritable: Option<bool>,
    },
    /// Create an event.
    CreateEvent {
        /// Reset policy.
        kind: EventKind,
        /// Initial signal state.
        initial_state: bool,
        /// Granted access mask.
        access: AccessMask,
        /// Inheritance policy.
        inheritable: bool,
    },
    /// Signal an event.
    SetEvent {
        /// Event handle.
        handle: GuestHandle,
    },
    /// Reset an event.
    ResetEvent {
        /// Event handle.
        handle: GuestHandle,
    },
    /// Create a recursive mutant.
    CreateMutant {
        /// Optional initial owner.
        initial_owner: Option<NtThreadId>,
        /// Granted access mask.
        access: AccessMask,
        /// Inheritance policy.
        inheritable: bool,
    },
    /// Release one mutant recursion level.
    ReleaseMutant {
        /// Mutant handle.
        handle: GuestHandle,
        /// Calling thread.
        thread: NtThreadId,
    },
    /// Create a counting semaphore.
    CreateSemaphore {
        /// Initial count.
        initial: u32,
        /// Maximum count.
        limit: u32,
        /// Granted access mask.
        access: AccessMask,
        /// Inheritance policy.
        inheritable: bool,
    },
    /// Release semaphore permits.
    ReleaseSemaphore {
        /// Semaphore handle.
        handle: GuestHandle,
        /// Positive count to add.
        release_count: u32,
    },
    /// Create an inactive timer.
    CreateTimer {
        /// Reset policy.
        kind: TimerKind,
        /// Granted access mask.
        access: AccessMask,
        /// Inheritance policy.
        inheritable: bool,
    },
    /// Set a monotonic relative timer without APC delivery.
    SetTimer {
        /// Timer handle.
        handle: GuestHandle,
        /// Current monotonic time in a caller-selected tick unit.
        now_ticks: u64,
        /// Relative delay in the same unit.
        delay_ticks: u64,
        /// Optional period; zero selects one-shot behavior.
        period_ticks: u64,
    },
    /// Cancel a timer.
    CancelTimer {
        /// Timer handle.
        handle: GuestHandle,
    },
    /// Wait on one supported synchronization object.
    WaitForSingleObject {
        /// Waitable handle.
        handle: GuestHandle,
        /// Calling thread for mutant ownership.
        thread: NtThreadId,
        /// Current monotonic time for timer refresh.
        now_ticks: u64,
        /// Poll or request unsupported blocking behavior.
        mode: NtWaitMode,
    },
}

impl NtServiceCall {
    /// Returns the service identity required by this typed call.
    #[must_use]
    pub const fn service(self) -> NtService {
        match self {
            Self::Close { .. } => NtService::Close,
            Self::DuplicateObject { .. } => NtService::DuplicateObject,
            Self::CreateEvent { .. } => NtService::CreateEvent,
            Self::SetEvent { .. } => NtService::SetEvent,
            Self::ResetEvent { .. } => NtService::ResetEvent,
            Self::CreateMutant { .. } => NtService::CreateMutant,
            Self::ReleaseMutant { .. } => NtService::ReleaseMutant,
            Self::CreateSemaphore { .. } => NtService::CreateSemaphore,
            Self::ReleaseSemaphore { .. } => NtService::ReleaseSemaphore,
            Self::CreateTimer { .. } => NtService::CreateTimer,
            Self::SetTimer { .. } => NtService::SetTimer,
            Self::CancelTimer { .. } => NtService::CancelTimer,
            Self::WaitForSingleObject { .. } => NtService::WaitForSingleObject,
        }
    }
}

/// Optional successful value returned by the internal dispatcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtServiceValue {
    /// No scalar output.
    None,
    /// Newly created or duplicated handle.
    Handle(GuestHandle),
    /// Previous boolean signal/activity state.
    Boolean(bool),
    /// Previous recursion or semaphore count.
    Count(u32),
}

/// Status plus optional value from one internal service dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtServiceReply {
    /// Exact NT completion status.
    pub status: NtStatus,
    /// Output present only when the specific successful service defines one.
    pub value: NtServiceValue,
}

impl NtServiceReply {
    /// Builds a reply with no scalar output.
    #[must_use]
    pub const fn status(status: NtStatus) -> Self {
        Self {
            status,
            value: NtServiceValue::None,
        }
    }

    /// Builds a successful handle reply.
    #[must_use]
    pub const fn handle(handle: GuestHandle) -> Self {
        Self {
            status: NtStatus::SUCCESS,
            value: NtServiceValue::Handle(handle),
        }
    }

    /// Builds a successful boolean reply.
    #[must_use]
    pub const fn boolean(previous: bool) -> Self {
        Self {
            status: NtStatus::SUCCESS,
            value: NtServiceValue::Boolean(previous),
        }
    }

    /// Builds a successful count reply.
    #[must_use]
    pub const fn count(previous: u32) -> Self {
        Self {
            status: NtStatus::SUCCESS,
            value: NtServiceValue::Count(previous),
        }
    }
}
