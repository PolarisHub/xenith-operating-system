//! Checked x64 PEB, TEB, process-parameter, and initial-stack layout planning.
//!
//! The planner reserves a small, explicitly documented bootstrap prefix. It
//! does not claim that the complete undocumented Windows structures are stable,
//! and it performs no mappings or guest-memory writes.

use crate::{NtStatus, NtUnicodeString64};

/// Planning granularity used by the bootstrap environment.
pub const RUNTIME_LAYOUT_PAGE_SIZE: u64 = 4_096;
/// Exclusive upper bound of the canonical x86-64 low half.
pub const RUNTIME_USER_ADDRESS_LIMIT: u64 = 0x0000_8000_0000_0000;
/// Bytes reserved for the bounded PEB bootstrap page.
pub const PEB64_BOOTSTRAP_BYTES: u64 = RUNTIME_LAYOUT_PAGE_SIZE;
/// Bytes reserved for the bounded TEB bootstrap page.
pub const TEB64_BOOTSTRAP_BYTES: u64 = RUNTIME_LAYOUT_PAGE_SIZE;
/// Offset of `ProcessParameters` in the supported x64 PEB prefix.
pub const PEB64_PROCESS_PARAMETERS_OFFSET: u64 = 0x20;
/// Offset of `NtTib.Self` in the supported x64 TEB prefix.
pub const TEB64_SELF_OFFSET: u64 = 0x30;
/// Offset of the PEB pointer in the supported x64 TEB prefix.
pub const TEB64_PEB_OFFSET: u64 = 0x60;
/// Offset of `ImagePathName` in the supported process-parameter prefix.
pub const PROCESS_PARAMETERS64_IMAGE_PATH_OFFSET: u64 = 0x60;
/// Offset of `CommandLine` in the supported process-parameter prefix.
pub const PROCESS_PARAMETERS64_COMMAND_LINE_OFFSET: u64 = 0x70;
/// Offset of the environment pointer in the supported process-parameter prefix.
pub const PROCESS_PARAMETERS64_ENVIRONMENT_OFFSET: u64 = 0x80;
/// Size retained before inline strings in the supported parameter plan.
pub const PROCESS_PARAMETERS64_PREFIX_BYTES: u64 = 0x88;
/// Maximum planned environment payload, excluding the added double terminator.
pub const MAX_ENVIRONMENT_BYTES: usize = 1024 * 1024;
/// Maximum page-rounded process-parameter reservation.
pub const MAX_PROCESS_PARAMETERS_BYTES: u64 = 2 * 1024 * 1024;

/// One checked half-open guest address range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeAddressRange {
    base: u64,
    size: u64,
}

impl RuntimeAddressRange {
    /// Returns the first byte in the range.
    #[must_use]
    pub const fn base(self) -> u64 {
        self.base
    }

    /// Returns the number of bytes in the range.
    #[must_use]
    pub const fn size(self) -> u64 {
        self.size
    }

    /// Returns the exclusive end after checked planning.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.base + self.size
    }

    /// Returns whether `address` lies inside this range.
    #[must_use]
    pub const fn contains(self, address: u64) -> bool {
        address >= self.base && address < self.end()
    }
}

/// Inputs to the deterministic bootstrap layout planner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeLayoutRequest {
    /// Nonzero page-aligned start of an otherwise unoccupied planning arena.
    pub arena_base: u64,
    /// Page-multiple size of the planning arena.
    pub arena_size: u64,
    /// Meaningful UTF-16 bytes in the image path, excluding a terminator.
    pub image_path_bytes: usize,
    /// Meaningful UTF-16 bytes in the command line, excluding a terminator.
    pub command_line_bytes: usize,
    /// UTF-16 environment bytes, excluding the final double NUL.
    pub environment_bytes: usize,
    /// Page-multiple committed initial stack size, excluding its guard page.
    pub stack_bytes: u64,
}

/// Complete non-overlapping bootstrap environment plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeEnvironmentPlan {
    /// Arena validated by the planner.
    pub arena: RuntimeAddressRange,
    /// Reserved PEB page.
    pub peb: RuntimeAddressRange,
    /// Reserved TEB page.
    pub teb: RuntimeAddressRange,
    /// Page-rounded process-parameter and inline-buffer reservation.
    pub process_parameters: RuntimeAddressRange,
    /// NUL-terminated image-path buffer inside `process_parameters`.
    pub image_path: RuntimeAddressRange,
    /// NUL-terminated command-line buffer inside `process_parameters`.
    pub command_line: RuntimeAddressRange,
    /// Double-NUL-terminated environment block inside `process_parameters`.
    pub environment: RuntimeAddressRange,
    /// Unmapped stack guard page.
    pub stack_guard: RuntimeAddressRange,
    /// Committed initial stack range.
    pub stack: RuntimeAddressRange,
    image_path_length: u16,
    command_line_length: u16,
}

impl RuntimeEnvironmentPlan {
    /// Returns the exact address at which the PEB process-parameter pointer belongs.
    #[must_use]
    pub const fn peb_process_parameters_field(self) -> u64 {
        self.peb.base + PEB64_PROCESS_PARAMETERS_OFFSET
    }

    /// Returns the exact address at which the TEB self pointer belongs.
    #[must_use]
    pub const fn teb_self_field(self) -> u64 {
        self.teb.base + TEB64_SELF_OFFSET
    }

    /// Returns the exact address at which the TEB PEB pointer belongs.
    #[must_use]
    pub const fn teb_peb_field(self) -> u64 {
        self.teb.base + TEB64_PEB_OFFSET
    }

    /// Returns the process-parameter field address for `ImagePathName`.
    #[must_use]
    pub const fn image_path_field(self) -> u64 {
        self.process_parameters.base + PROCESS_PARAMETERS64_IMAGE_PATH_OFFSET
    }

    /// Returns the process-parameter field address for `CommandLine`.
    #[must_use]
    pub const fn command_line_field(self) -> u64 {
        self.process_parameters.base + PROCESS_PARAMETERS64_COMMAND_LINE_OFFSET
    }

    /// Returns the process-parameter field address for the environment pointer.
    #[must_use]
    pub const fn environment_field(self) -> u64 {
        self.process_parameters.base + PROCESS_PARAMETERS64_ENVIRONMENT_OFFSET
    }

    /// Builds the canonical `ImagePathName` descriptor.
    #[must_use]
    pub const fn image_path_string(self) -> NtUnicodeString64 {
        NtUnicodeString64 {
            length_bytes: self.image_path_length,
            maximum_length_bytes: self.image_path_length + 2,
            padding: 0,
            buffer: self.image_path.base,
        }
    }

    /// Builds the canonical `CommandLine` descriptor.
    #[must_use]
    pub const fn command_line_string(self) -> NtUnicodeString64 {
        NtUnicodeString64 {
            length_bytes: self.command_line_length,
            maximum_length_bytes: self.command_line_length + 2,
            padding: 0,
            buffer: self.command_line.base,
        }
    }

    /// Returns the exclusive initial stack top.
    #[must_use]
    pub const fn stack_top(self) -> u64 {
        self.stack.end()
    }
}

/// Environment planning failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutError {
    /// An arena or stack constraint was invalid.
    InvalidAlignment,
    /// The planning arena began at the reserved null address.
    NullArenaBase,
    /// The planning arena extended outside the canonical low user half.
    OutsideUserAddressSpace,
    /// A UTF-16 byte length was odd or exceeded `UNICODE_STRING` capacity.
    InvalidStringLength,
    /// The environment exceeded its explicit bound or had odd byte length.
    InvalidEnvironmentLength,
    /// Address or size arithmetic overflowed.
    IntegerOverflow,
    /// The requested layout did not fit in the arena.
    ArenaTooSmall,
}

impl LayoutError {
    /// Converts a planning failure to a stable NT status.
    #[must_use]
    pub const fn status(self) -> NtStatus {
        match self {
            Self::InvalidAlignment
            | Self::NullArenaBase
            | Self::InvalidStringLength
            | Self::InvalidEnvironmentLength => NtStatus::INVALID_PARAMETER,
            Self::OutsideUserAddressSpace => NtStatus::CONFLICTING_ADDRESSES,
            Self::IntegerOverflow => NtStatus::INTEGER_OVERFLOW,
            Self::ArenaTooSmall => NtStatus::NO_MEMORY,
        }
    }
}

/// Plans a non-overlapping x64 bootstrap environment without mutating memory.
pub fn plan_runtime_environment(
    request: RuntimeLayoutRequest,
) -> Result<RuntimeEnvironmentPlan, LayoutError> {
    if request.arena_base == 0 {
        return Err(LayoutError::NullArenaBase);
    }
    if !request.arena_base.is_multiple_of(RUNTIME_LAYOUT_PAGE_SIZE)
        || request.arena_size == 0
        || !request.arena_size.is_multiple_of(RUNTIME_LAYOUT_PAGE_SIZE)
        || request.stack_bytes == 0
        || !request.stack_bytes.is_multiple_of(RUNTIME_LAYOUT_PAGE_SIZE)
    {
        return Err(LayoutError::InvalidAlignment);
    }
    let arena_end = request
        .arena_base
        .checked_add(request.arena_size)
        .ok_or(LayoutError::IntegerOverflow)?;
    if arena_end > RUNTIME_USER_ADDRESS_LIMIT {
        return Err(LayoutError::OutsideUserAddressSpace);
    }
    let image_path_length = validate_string_length(request.image_path_bytes)?;
    let command_line_length = validate_string_length(request.command_line_bytes)?;
    if request.environment_bytes & 1 != 0 || request.environment_bytes > MAX_ENVIRONMENT_BYTES {
        return Err(LayoutError::InvalidEnvironmentLength);
    }

    let arena = RuntimeAddressRange {
        base: request.arena_base,
        size: request.arena_size,
    };
    let mut cursor = request.arena_base;
    let peb = take_range(&mut cursor, PEB64_BOOTSTRAP_BYTES, arena_end)?;
    let teb = take_range(&mut cursor, TEB64_BOOTSTRAP_BYTES, arena_end)?;

    let parameter_base = cursor;
    let mut parameter_cursor = parameter_base
        .checked_add(PROCESS_PARAMETERS64_PREFIX_BYTES)
        .ok_or(LayoutError::IntegerOverflow)?;
    parameter_cursor = align_up(parameter_cursor, 8)?;
    let image_path = take_inline(
        &mut parameter_cursor,
        request
            .image_path_bytes
            .checked_add(2)
            .ok_or(LayoutError::IntegerOverflow)?,
    )?;
    parameter_cursor = align_up(parameter_cursor, 8)?;
    let command_line = take_inline(
        &mut parameter_cursor,
        request
            .command_line_bytes
            .checked_add(2)
            .ok_or(LayoutError::IntegerOverflow)?,
    )?;
    parameter_cursor = align_up(parameter_cursor, 8)?;
    let environment = take_inline(
        &mut parameter_cursor,
        request
            .environment_bytes
            .checked_add(4)
            .ok_or(LayoutError::IntegerOverflow)?,
    )?;
    let parameter_end = align_up(parameter_cursor, RUNTIME_LAYOUT_PAGE_SIZE)?;
    let parameter_size = parameter_end
        .checked_sub(parameter_base)
        .filter(|size| *size <= MAX_PROCESS_PARAMETERS_BYTES)
        .ok_or(LayoutError::ArenaTooSmall)?;
    if parameter_end > arena_end {
        return Err(LayoutError::ArenaTooSmall);
    }
    let process_parameters = RuntimeAddressRange {
        base: parameter_base,
        size: parameter_size,
    };
    cursor = parameter_end;

    let stack_guard = take_range(&mut cursor, RUNTIME_LAYOUT_PAGE_SIZE, arena_end)?;
    let stack = take_range(&mut cursor, request.stack_bytes, arena_end)?;

    Ok(RuntimeEnvironmentPlan {
        arena,
        peb,
        teb,
        process_parameters,
        image_path,
        command_line,
        environment,
        stack_guard,
        stack,
        image_path_length,
        command_line_length,
    })
}

fn validate_string_length(bytes: usize) -> Result<u16, LayoutError> {
    if bytes & 1 != 0 || bytes > (u16::MAX as usize - 2) {
        return Err(LayoutError::InvalidStringLength);
    }
    u16::try_from(bytes).map_err(|_| LayoutError::InvalidStringLength)
}

fn take_range(
    cursor: &mut u64,
    size: u64,
    arena_end: u64,
) -> Result<RuntimeAddressRange, LayoutError> {
    let end = cursor
        .checked_add(size)
        .ok_or(LayoutError::IntegerOverflow)?;
    if end > arena_end {
        return Err(LayoutError::ArenaTooSmall);
    }
    let range = RuntimeAddressRange {
        base: *cursor,
        size,
    };
    *cursor = end;
    Ok(range)
}

fn take_inline(cursor: &mut u64, size: usize) -> Result<RuntimeAddressRange, LayoutError> {
    let size = u64::try_from(size).map_err(|_| LayoutError::IntegerOverflow)?;
    let end = cursor
        .checked_add(size)
        .ok_or(LayoutError::IntegerOverflow)?;
    let range = RuntimeAddressRange {
        base: *cursor,
        size,
    };
    *cursor = end;
    Ok(range)
}

fn align_up(value: u64, alignment: u64) -> Result<u64, LayoutError> {
    value
        .checked_add(alignment - 1)
        .map(|sum| sum & !(alignment - 1))
        .ok_or(LayoutError::IntegerOverflow)
}
