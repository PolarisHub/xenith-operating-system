//! Transactional fixed-capacity IRP lifecycle.

use xenith_winhost_core::NtStatus;

use crate::{DeviceId, IoControlCode, MajorFunction};

const INDEX_BITS: u32 = 12;
const INDEX_MASK: u32 = (1 << INDEX_BITS) - 1;
const GENERATION_MASK: u32 = (1 << (32 - INDEX_BITS)) - 1;
const MAX_ISSUED_GENERATION: u32 = GENERATION_MASK - 1;
const MAX_ENCODED_REQUESTS: usize = INDEX_MASK as usize;

/// Operational limit for inline request slots in one pool.
///
/// The identifier can encode more slots, but the public limit bounds the
/// const-generic pool to a practical allocation-free footprint.
pub const MAX_REQUESTS: usize = 1024;

/// Maximum aggregate input plus output bytes described by one request.
pub const MAX_IO_TRANSFER_BYTES: usize = 1024 * 1024;

/// Generation-safe I/O-request identifier.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestId(u32);

impl RequestId {
    /// Null/invalid request identifier.
    pub const NULL: Self = Self(0);

    /// Creates an ID from an untrusted boundary value.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw boundary value.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// Explicit request-lifetime state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestState {
    /// Allocated but not yet visible to a driver.
    Allocated = 1,
    /// Synchronously executing in a dispatch callback.
    Dispatched = 2,
    /// Driver retained ownership for asynchronous completion.
    Pending = 3,
    /// Cancellation was requested; completion still owns final teardown.
    CancelRequested = 4,
    /// Completion is immutable and ready for the requester to reap.
    Completed = 5,
}

/// Bounded metadata for one I/O request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoRequest {
    /// Target device.
    pub device: DeviceId,
    /// Major dispatch function.
    pub major: MajorFunction,
    /// Driver-specific minor function.
    pub minor: u8,
    /// IOCTL for device-control requests.
    pub control_code: Option<IoControlCode>,
    /// Validated input-buffer length.
    pub input_len: usize,
    /// Validated output-buffer length.
    pub output_len: usize,
    /// Current ownership state.
    pub state: RequestState,
    /// Final or pending status.
    pub status: NtStatus,
    /// Final `IoStatus.Information` value.
    pub information: usize,
    /// Whether cancellation won a serialized transition before completion.
    pub cancel_requested: bool,
}

impl IoRequest {
    const EMPTY: Self = Self {
        device: DeviceId::NULL,
        major: MajorFunction::Create,
        minor: 0,
        control_code: None,
        input_len: 0,
        output_len: 0,
        state: RequestState::Allocated,
        status: NtStatus::SUCCESS,
        information: 0,
        cancel_requested: false,
    };
}

/// Immutable result returned when a completed request is reaped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    /// Target device retained for major-specific completion handling.
    pub device: DeviceId,
    /// Major function which defines the meaning of `information`.
    pub major: MajorFunction,
    /// Minor function needed for major-specific completion validation.
    pub minor: u8,
    /// Original device-control code, when this was a control request.
    pub control_code: Option<IoControlCode>,
    /// Validated input length retained for the boundary adapter.
    pub input_len: usize,
    /// Validated output length retained for the boundary adapter.
    pub output_len: usize,
    /// Driver-supplied completion status.
    pub status: NtStatus,
    /// Driver-supplied major-specific information value after available validation.
    pub information: usize,
    /// Whether cancellation was recorded before completion.
    pub cancel_requested: bool,
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u32,
    occupied: bool,
    retired: bool,
    request: IoRequest,
}

impl Slot {
    const EMPTY: Self = Self {
        generation: 1,
        occupied: false,
        retired: false,
        request: IoRequest::EMPTY,
    };
}

/// I/O-request lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    /// Pool capacity is zero or exceeds the operational inline-storage bound.
    InvalidCapacity {
        /// Requested capacity.
        capacity: usize,
        /// Operational maximum.
        maximum: usize,
    },
    /// Every reusable request slot is occupied.
    PoolFull,
    /// Request ID is null, malformed, reaped, or stale.
    InvalidRequest,
    /// Target device ID is null or malformed; liveness remains the registry's responsibility.
    InvalidDevice,
    /// Input/output lengths overflow or exceed the per-request budget.
    TransferTooLarge,
    /// IOCTL presence does not match the major function.
    InvalidControlCode,
    /// The operation is illegal in the current lifecycle state.
    InvalidState {
        /// State observed by the operation.
        state: RequestState,
    },
    /// Completion reports more transferred bytes than the request permits.
    InvalidInformation {
        /// Driver-reported value.
        information: usize,
        /// Largest valid byte count.
        maximum: usize,
    },
    /// A completed request cannot retain `STATUS_PENDING`.
    InvalidCompletionStatus,
}

impl RequestError {
    /// Converts a request-policy failure to an NT status value.
    #[must_use]
    pub const fn status(self) -> NtStatus {
        match self {
            Self::InvalidCapacity { .. }
            | Self::InvalidControlCode
            | Self::InvalidState { .. }
            | Self::InvalidInformation { .. }
            | Self::InvalidCompletionStatus => NtStatus::INVALID_PARAMETER,
            Self::PoolFull => NtStatus::INSUFFICIENT_RESOURCES,
            Self::InvalidRequest | Self::InvalidDevice => NtStatus::INVALID_HANDLE,
            Self::TransferTooLarge => NtStatus::INVALID_PARAMETER,
        }
    }
}

/// Fixed-capacity request pool. External synchronization is required when a
/// driver host shares the pool across threads.
pub struct RequestPool<const N: usize> {
    slots: [Slot; N],
    len: usize,
}

impl<const N: usize> RequestPool<N> {
    /// Creates an empty request pool after validating its ID encoding.
    pub const fn try_new() -> Result<Self, RequestError> {
        if N == 0 || N > MAX_REQUESTS {
            return Err(RequestError::InvalidCapacity {
                capacity: N,
                maximum: MAX_REQUESTS,
            });
        }
        Ok(Self {
            slots: [Slot::EMPTY; N],
            len: 0,
        })
    }

    /// Returns the number of live requests, including completed requests that
    /// have not yet been reaped.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether no request slot is live.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Allocates a request without publishing it to a driver.
    pub fn allocate(
        &mut self,
        device: DeviceId,
        major: MajorFunction,
        minor: u8,
        control_code: Option<IoControlCode>,
        input_len: usize,
        output_len: usize,
    ) -> Result<RequestId, RequestError> {
        if !device.is_well_formed() {
            return Err(RequestError::InvalidDevice);
        }
        let is_control = matches!(
            major,
            MajorFunction::DeviceControl | MajorFunction::InternalDeviceControl
        );
        if is_control != control_code.is_some() {
            return Err(RequestError::InvalidControlCode);
        }
        let total = input_len
            .checked_add(output_len)
            .ok_or(RequestError::TransferTooLarge)?;
        if total > MAX_IO_TRANSFER_BYTES {
            return Err(RequestError::TransferTooLarge);
        }
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if !slot.occupied && !slot.retired {
                slot.request = IoRequest {
                    device,
                    major,
                    minor,
                    control_code,
                    input_len,
                    output_len,
                    state: RequestState::Allocated,
                    status: NtStatus::SUCCESS,
                    information: 0,
                    cancel_requested: false,
                };
                slot.occupied = true;
                self.len += 1;
                return Ok(RequestId(encode(index, slot.generation)));
            }
        }
        Err(RequestError::PoolFull)
    }

    /// Returns a copy of the current request metadata.
    pub fn request(&self, id: RequestId) -> Result<IoRequest, RequestError> {
        Ok(self.slot(id)?.request)
    }

    /// Publishes an allocated request as one checked serialized transition.
    pub fn mark_dispatched(&mut self, id: RequestId) -> Result<(), RequestError> {
        let request = &mut self.slot_mut(id)?.request;
        require_state(request.state, RequestState::Allocated)?;
        request.state = RequestState::Dispatched;
        Ok(())
    }

    /// Records asynchronous driver ownership, including cancel-before-pending order.
    pub fn mark_pending(&mut self, id: RequestId) -> Result<(), RequestError> {
        let request = &mut self.slot_mut(id)?.request;
        match request.state {
            RequestState::Dispatched => {
                request.state = RequestState::Pending;
                request.status = NtStatus::PENDING;
                Ok(())
            },
            RequestState::CancelRequested => {
                // Cancellation may win the serialized policy transition just
                // before dispatch reports that it retained ownership. Preserve
                // the cancellation state while recording pending ownership.
                if request.status == NtStatus::PENDING {
                    return Err(RequestError::InvalidState {
                        state: request.state,
                    });
                }
                request.status = NtStatus::PENDING;
                Ok(())
            },
            state => Err(RequestError::InvalidState { state }),
        }
    }

    /// Requests cancellation without freeing memory still owned by dispatch.
    /// Returns `true` when cancellation wins, and `false` when it was already
    /// requested or immutable completion won first.
    pub fn request_cancel(&mut self, id: RequestId) -> Result<bool, RequestError> {
        let request = &mut self.slot_mut(id)?.request;
        match request.state {
            RequestState::Dispatched | RequestState::Pending => {
                request.state = RequestState::CancelRequested;
                request.cancel_requested = true;
                Ok(true)
            },
            RequestState::CancelRequested => Ok(false),
            RequestState::Completed => Ok(false),
            state => Err(RequestError::InvalidState { state }),
        }
    }

    /// Publishes immutable non-pending completion after validating byte counts.
    pub fn complete(
        &mut self,
        id: RequestId,
        status: NtStatus,
        information: usize,
    ) -> Result<(), RequestError> {
        let request = &mut self.slot_mut(id)?.request;
        if !matches!(
            request.state,
            RequestState::Dispatched | RequestState::Pending | RequestState::CancelRequested
        ) {
            return Err(RequestError::InvalidState {
                state: request.state,
            });
        }
        if status == NtStatus::PENDING {
            return Err(RequestError::InvalidCompletionStatus);
        }
        if let Some(maximum) = information_limit(request) {
            if information > maximum {
                return Err(RequestError::InvalidInformation {
                    information,
                    maximum,
                });
            }
        }
        request.status = status;
        request.information = information;
        request.state = RequestState::Completed;
        Ok(())
    }

    /// Rolls back a request that was never published to driver code.
    pub fn release_unsubmitted(&mut self, id: RequestId) -> Result<(), RequestError> {
        let state = self.slot(id)?.request.state;
        require_state(state, RequestState::Allocated)?;
        self.release_slot(id)?;
        Ok(())
    }

    /// Reaps one completed request and invalidates its generation.
    pub fn reap(&mut self, id: RequestId) -> Result<Completion, RequestError> {
        let request = self.slot(id)?.request;
        require_state(request.state, RequestState::Completed)?;
        let completion = Completion {
            device: request.device,
            major: request.major,
            minor: request.minor,
            control_code: request.control_code,
            input_len: request.input_len,
            output_len: request.output_len,
            status: request.status,
            information: request.information,
            cancel_requested: request.cancel_requested,
        };
        self.release_slot(id)?;
        Ok(completion)
    }

    fn slot(&self, id: RequestId) -> Result<&Slot, RequestError> {
        let (index, generation) = decode(id.0).ok_or(RequestError::InvalidRequest)?;
        let slot = self.slots.get(index).ok_or(RequestError::InvalidRequest)?;
        if !slot.occupied || slot.retired || slot.generation != generation {
            return Err(RequestError::InvalidRequest);
        }
        Ok(slot)
    }

    fn slot_mut(&mut self, id: RequestId) -> Result<&mut Slot, RequestError> {
        let (index, generation) = decode(id.0).ok_or(RequestError::InvalidRequest)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(RequestError::InvalidRequest)?;
        if !slot.occupied || slot.retired || slot.generation != generation {
            return Err(RequestError::InvalidRequest);
        }
        Ok(slot)
    }

    fn release_slot(&mut self, id: RequestId) -> Result<(), RequestError> {
        let slot = self.slot_mut(id)?;
        slot.occupied = false;
        slot.request = IoRequest::EMPTY;
        if slot.generation == MAX_ISSUED_GENERATION {
            slot.retired = true;
        } else {
            slot.generation += 1;
        }
        self.len -= 1;
        Ok(())
    }
}

fn information_limit(request: &IoRequest) -> Option<usize> {
    match request.major {
        MajorFunction::Read => Some(request.output_len),
        MajorFunction::Write => Some(request.input_len),
        MajorFunction::QueryInformation
        | MajorFunction::QueryEa
        | MajorFunction::QueryVolumeInformation
        | MajorFunction::DirectoryControl
        | MajorFunction::FileSystemControl
        | MajorFunction::DeviceControl
        | MajorFunction::InternalDeviceControl
        | MajorFunction::QuerySecurity
        | MajorFunction::SystemControl
        | MajorFunction::QueryQuota => Some(request.output_len),
        MajorFunction::Create | MajorFunction::CreateNamedPipe | MajorFunction::CreateMailslot => {
            // Public FILE_* create disposition values occupy 0 through 5.
            Some(5)
        },
        MajorFunction::Close
        | MajorFunction::SetInformation
        | MajorFunction::SetEa
        | MajorFunction::FlushBuffers
        | MajorFunction::SetVolumeInformation
        | MajorFunction::Shutdown
        | MajorFunction::LockControl
        | MajorFunction::Cleanup
        | MajorFunction::SetSecurity
        | MajorFunction::Power
        | MajorFunction::DeviceChange
        | MajorFunction::SetQuota => Some(0),
        // PnP information is minor-function-specific and may be pointer-valued.
        // The completion retains its major so a future ABI adapter can apply
        // the required per-minor validation before consuming this value.
        MajorFunction::Pnp => None,
    }
}

fn require_state(actual: RequestState, expected: RequestState) -> Result<(), RequestError> {
    if actual == expected {
        Ok(())
    } else {
        Err(RequestError::InvalidState { state: actual })
    }
}

fn encode(index: usize, generation: u32) -> u32 {
    debug_assert!(index < MAX_ENCODED_REQUESTS);
    debug_assert!((1..=MAX_ISSUED_GENERATION).contains(&generation));
    (generation << INDEX_BITS) | (index as u32 + 1)
}

fn decode(raw: u32) -> Option<(usize, u32)> {
    let slot = raw & INDEX_MASK;
    let generation = raw >> INDEX_BITS;
    if slot == 0 || generation == 0 || generation > MAX_ISSUED_GENERATION {
        return None;
    }
    Some(((slot - 1) as usize, generation))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_request_generation_retires_without_wrapping() {
        let mut pool = RequestPool::<1>::try_new().unwrap();
        pool.slots[0].generation = MAX_ISSUED_GENERATION;
        let device = DeviceId::from_raw(0x101);
        let id = pool
            .allocate(device, MajorFunction::Create, 0, None, 0, 0)
            .unwrap();
        pool.mark_dispatched(id).unwrap();
        pool.complete(id, NtStatus::SUCCESS, 0).unwrap();
        pool.reap(id).unwrap();

        assert_eq!(pool.request(id), Err(RequestError::InvalidRequest));
        assert_eq!(
            pool.allocate(device, MajorFunction::Create, 0, None, 0, 0),
            Err(RequestError::PoolFull)
        );
    }
}
