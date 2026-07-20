//! Winhost adapter for the pointer-free clean-room NT runtime.

use xenith_winhost_core::{
    GuestHandle, NtRuntime, NtServiceCall, NtServiceReply, NtStatus, RUNTIME_USER_ADDRESS_LIMIT,
};

use crate::MAX_CONSOLE_WRITE_BYTES;

/// Win32 selector for standard input.
pub const STD_INPUT_SELECTOR: u32 = (-10_i32) as u32;
/// Win32 selector for standard output.
pub const STD_OUTPUT_SELECTOR: u32 = (-11_i32) as u32;
/// Win32 selector for standard error.
pub const STD_ERROR_SELECTOR: u32 = (-12_i32) as u32;

/// Fixed-capacity runtime plus generation-safe standard-console handles.
pub struct BootstrapRuntime<const H: usize, const O: usize> {
    nt: NtRuntime<H, O>,
    input: GuestHandle,
    output: GuestHandle,
    error: GuestHandle,
}

impl<const H: usize, const O: usize> BootstrapRuntime<H, O> {
    /// Creates the runtime and publishes exactly three borrowed console objects.
    pub fn try_new() -> Result<Self, NtStatus> {
        let mut nt = NtRuntime::try_new()?;
        let input = nt.insert_console(0, true, false, false)?;
        let output = nt.insert_console(1, false, true, false)?;
        let error = nt.insert_console(2, false, true, false)?;
        Ok(Self {
            nt,
            input,
            output,
            error,
        })
    }

    /// Resolves a Win32 standard-handle selector to a typed guest handle.
    pub fn get_std_handle(&self, selector: u32) -> Result<GuestHandle, NtStatus> {
        match selector {
            STD_INPUT_SELECTOR => Ok(self.input),
            STD_OUTPUT_SELECTOR => Ok(self.output),
            STD_ERROR_SELECTOR => Ok(self.error),
            _ => Err(NtStatus::INVALID_PARAMETER),
        }
    }

    /// Resolves a writable console handle to its borrowed Xenith descriptor.
    pub fn write_descriptor(&self, handle: GuestHandle) -> Result<i32, NtStatus> {
        self.nt.console_descriptor(handle, true)
    }

    /// Resolves a readable console handle to its borrowed Xenith descriptor.
    pub fn read_descriptor(&self, handle: GuestHandle) -> Result<i32, NtStatus> {
        self.nt.console_descriptor(handle, false)
    }

    /// Closes one generation-safe runtime handle.
    pub fn close(&mut self, handle: GuestHandle) -> NtStatus {
        match self.nt.close(handle) {
            Ok(_) => NtStatus::SUCCESS,
            Err(status) => status,
        }
    }

    /// Dispatches one pointer-free NT service by exact module and symbol.
    pub fn dispatch_symbol(
        &mut self,
        module: &[u8],
        symbol: &[u8],
        call: NtServiceCall,
    ) -> NtServiceReply {
        self.nt.dispatch_symbol(module, symbol, call)
    }

    /// Returns the number of live runtime handles.
    #[must_use]
    pub const fn handle_count(&self) -> usize {
        self.nt.handle_count()
    }

    /// Returns the number of live runtime objects.
    #[must_use]
    pub const fn object_count(&self) -> usize {
        self.nt.object_count()
    }
}

/// Validated scalar portion of one synchronous console `WriteFile` request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleWritePlan {
    /// Generation-safe runtime handle.
    pub handle: GuestHandle,
    /// Guest address submitted to Xenith's checked write syscall.
    pub buffer: u64,
    /// Bounded byte count.
    pub length: usize,
    /// Guest address receiving the 32-bit completed count.
    pub written: u64,
}

/// Validates null, canonical-range, length, and synchronous-overlapped rules.
///
/// This proves arithmetic and low-half range safety only. Mapping/writability of
/// `written` cannot be recovered as an NT status until Xenith exposes a
/// fault-contained guest-copy primitive to this userspace host.
pub fn validate_console_write(
    raw_handle: isize,
    buffer: u64,
    requested: u32,
    written: u64,
    overlapped: u64,
) -> Result<ConsoleWritePlan, NtStatus> {
    let handle = decode_guest_handle(raw_handle)?;
    let length = requested as usize;
    if written == 0 || overlapped != 0 || length > MAX_CONSOLE_WRITE_BYTES {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    validate_low_range(written, core::mem::size_of::<u32>())?;
    if length != 0 {
        validate_low_range(buffer, length)?;
    } else if buffer >= RUNTIME_USER_ADDRESS_LIMIT {
        return Err(NtStatus::ACCESS_VIOLATION);
    }
    Ok(ConsoleWritePlan {
        handle,
        buffer,
        length,
        written,
    })
}

/// Converts one pointer-sized ABI value into a nonzero 32-bit runtime handle.
pub fn decode_guest_handle(raw: isize) -> Result<GuestHandle, NtStatus> {
    let raw = u32::try_from(raw).map_err(|_| NtStatus::INVALID_HANDLE)?;
    let handle = GuestHandle::from_raw(raw);
    if handle.is_null() {
        Err(NtStatus::INVALID_HANDLE)
    } else {
        Ok(handle)
    }
}

fn validate_low_range(address: u64, length: usize) -> Result<(), NtStatus> {
    if address == 0 {
        return Err(NtStatus::ACCESS_VIOLATION);
    }
    let length = u64::try_from(length).map_err(|_| NtStatus::INTEGER_OVERFLOW)?;
    let end = address
        .checked_add(length)
        .filter(|end| *end <= RUNTIME_USER_ADDRESS_LIMIT)
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    if end <= address {
        return Err(NtStatus::ACCESS_VIOLATION);
    }
    Ok(())
}
