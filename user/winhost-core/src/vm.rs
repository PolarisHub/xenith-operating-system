//! Deterministic virtual-address reservation and PE protection planning.

use xenith_pe::{LoadPermissions, PeError, PeImage, MAX_SECTIONS};

/// Base page size required by this address planner.
pub const VM_PAGE_SIZE: u64 = 4_096;
/// Required PE image-base and fallback-placement alignment.
pub const PE_IMAGE_ALIGNMENT: u64 = 65_536;
/// Maximum const-generic reservation capacity accepted by this planner.
pub const MAX_ADDRESS_RESERVATIONS: usize = 4_096;

/// Validated final page protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmProtection {
    read: bool,
    write: bool,
    execute: bool,
}

impl VmProtection {
    /// Inaccessible reservation/container protection.
    pub const NONE: Self = Self {
        read: false,
        write: false,
        execute: false,
    };
    /// Read-only protection.
    pub const READ: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    /// Read/write, non-executable protection.
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    /// Read/execute, non-writable protection.
    pub const READ_EXECUTE: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
    /// Execute-only protection.
    pub const EXECUTE: Self = Self {
        read: false,
        write: false,
        execute: true,
    };
    /// Write-only, non-executable protection.
    pub const WRITE: Self = Self {
        read: false,
        write: true,
        execute: false,
    };

    /// Validates an arbitrary protection tuple, rejecting writable executable pages.
    pub const fn try_new(read: bool, write: bool, execute: bool) -> Result<Self, AddressError> {
        if write && execute {
            return Err(AddressError::WritableExecutable);
        }
        Ok(Self {
            read,
            write,
            execute,
        })
    }

    /// Returns whether reads are allowed.
    #[must_use]
    pub const fn is_readable(self) -> bool {
        self.read
    }

    /// Returns whether writes are allowed.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        self.write
    }

    /// Returns whether instruction fetches are allowed.
    #[must_use]
    pub const fn is_executable(self) -> bool {
        self.execute
    }

    fn from_pe(value: LoadPermissions) -> Result<Self, AddressError> {
        Self::try_new(value.read, value.write, value.execute)
    }
}

/// Semantic owner of one reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationKind {
    /// Host runtime code or data.
    HostRuntime,
    /// Complete PE image reservation; per-range protections live in its layout.
    PeImage,
    /// Guest thread stack.
    Stack,
    /// Guest heap arena.
    Heap,
    /// Shared-memory view.
    Shared,
    /// Guard or intentionally inaccessible range.
    Guard,
    /// Caller-defined bootstrap category.
    Other(u16),
}

/// One non-overlapping virtual-address reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reservation {
    /// Inclusive start address.
    pub start: u64,
    /// Page-multiple byte size.
    pub size: u64,
    /// Final protection for ordinary mappings, or `NONE` for a PE container.
    pub protection: VmProtection,
    /// Semantic reservation category.
    pub kind: ReservationKind,
}

impl Reservation {
    const EMPTY: Self = Self {
        start: 0,
        size: 0,
        protection: VmProtection::NONE,
        kind: ReservationKind::Guard,
    };

    /// Returns the exclusive end address when representable.
    #[must_use]
    pub const fn checked_end(self) -> Option<u64> {
        self.start.checked_add(self.size)
    }
}

/// PE placement policy when its preferred base is unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImagePlacement {
    /// Fail rather than select a different address.
    PreferredOnly,
    /// Choose the lowest 64-KiB-aligned gap and require valid base relocations.
    PreferredOrFirstFit,
}

/// One header or section range with its final PE-derived protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeSectionMapping {
    /// Raw eight-byte section name; zero for the PE headers.
    pub name: [u8; 8],
    /// Relative virtual address within the image.
    pub rva: u32,
    /// Page-aligned mapped size.
    pub size: u32,
    /// Checked guest virtual start address.
    pub address: u64,
    /// Final protection to install only after copying and relocation.
    pub protection: VmProtection,
}

impl PeSectionMapping {
    const EMPTY: Self = Self {
        name: [0; 8],
        rva: 0,
        size: 0,
        address: 0,
        protection: VmProtection::NONE,
    };
}

/// Declarative placement and final-protection plan for one PE image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeImageLayout {
    /// Container reservation blocking overlap with all other mappings.
    pub reservation: Reservation,
    /// Linker-preferred image base.
    pub preferred_base: u64,
    /// Actual selected image base.
    pub actual_base: u64,
    /// Whether valid base relocations are required.
    pub relocated: bool,
    /// Checked entry address, or `None` for an image without an entry point.
    pub entry_address: Option<u64>,
    /// Read-only PE header mapping.
    pub headers: PeSectionMapping,
    sections: [PeSectionMapping; MAX_SECTIONS],
    section_count: usize,
}

impl PeImageLayout {
    /// Returns section mappings in original PE section-table order.
    #[must_use]
    pub fn sections(&self) -> &[PeSectionMapping] {
        &self.sections[..self.section_count]
    }
}

/// Virtual-address planning failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressError {
    /// The const-generic reservation capacity is zero or exceeds the bound.
    InvalidCapacity {
        /// Supplied capacity.
        capacity: usize,
        /// Largest accepted capacity.
        maximum: usize,
    },
    /// Planner bounds are empty, unaligned, or overflow-prone.
    InvalidBounds,
    /// A reservation size is zero or not a page multiple.
    InvalidSize,
    /// An alignment is smaller than one page or not a power of two.
    InvalidAlignment,
    /// A start address does not satisfy the required alignment.
    MisalignedAddress,
    /// Checked address arithmetic overflowed.
    AddressOverflow,
    /// The requested exact range is outside planner bounds.
    OutsideAddressSpace,
    /// The requested exact range overlaps an existing reservation.
    Overlap,
    /// No suitable first-fit range exists.
    OutOfAddressSpace,
    /// The fixed reservation array is full.
    ReservationTableFull,
    /// A writable and executable protection was requested.
    WritableExecutable,
    /// Preferred-only PE placement could not be honored.
    PreferredAddressUnavailable,
    /// The PE parser, loader planner, or relocation validator rejected the image.
    Pe(PeError),
}

/// Sorted, deterministic, fixed-capacity virtual-address planner.
pub struct VirtualAddressPlanner<const N: usize> {
    floor: u64,
    ceiling: u64,
    reservations: [Reservation; N],
    len: usize,
}

impl<const N: usize> VirtualAddressPlanner<N> {
    /// Creates a planner for the half-open address range `[floor, ceiling)`.
    pub const fn try_new(floor: u64, ceiling: u64) -> Result<Self, AddressError> {
        if N == 0 || N > MAX_ADDRESS_RESERVATIONS {
            return Err(AddressError::InvalidCapacity {
                capacity: N,
                maximum: MAX_ADDRESS_RESERVATIONS,
            });
        }
        if floor >= ceiling
            || !floor.is_multiple_of(VM_PAGE_SIZE)
            || !ceiling.is_multiple_of(VM_PAGE_SIZE)
        {
            return Err(AddressError::InvalidBounds);
        }
        Ok(Self {
            floor,
            ceiling,
            reservations: [Reservation::EMPTY; N],
            len: 0,
        })
    }

    /// Returns reservations sorted by ascending start address.
    #[must_use]
    pub fn reservations(&self) -> &[Reservation] {
        &self.reservations[..self.len]
    }

    /// Returns the number of reservations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether no range is reserved.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Reserves one exact page-aligned range.
    pub fn reserve_exact(
        &mut self,
        start: u64,
        size: u64,
        protection: VmProtection,
        kind: ReservationKind,
    ) -> Result<Reservation, AddressError> {
        validate_size(size)?;
        if !start.is_multiple_of(VM_PAGE_SIZE) {
            return Err(AddressError::MisalignedAddress);
        }
        self.validate_available(start, size)?;
        let reservation = Reservation {
            start,
            size,
            protection,
            kind,
        };
        self.insert_sorted(reservation)?;
        Ok(reservation)
    }

    /// Reserves the lowest suitable gap using the requested power-of-two alignment.
    pub fn reserve_first_fit(
        &mut self,
        size: u64,
        alignment: u64,
        protection: VmProtection,
        kind: ReservationKind,
    ) -> Result<Reservation, AddressError> {
        validate_size(size)?;
        validate_alignment(alignment)?;
        let start = self.find_first_fit(size, alignment)?;
        let reservation = Reservation {
            start,
            size,
            protection,
            kind,
        };
        self.insert_sorted(reservation)?;
        Ok(reservation)
    }

    /// Selects an image address and derives immutable final PE protections.
    ///
    /// A non-preferred placement succeeds only after `xenith-pe` validates the
    /// complete base-relocation graph for that actual base. The returned plan
    /// still performs no mapping, copying, relocation, or permission changes.
    pub fn reserve_pe_image(
        &mut self,
        image: &PeImage<'_>,
        placement: ImagePlacement,
    ) -> Result<PeImageLayout, AddressError> {
        let loader = image.loader_plan().map_err(AddressError::Pe)?;
        let size = u64::from(loader.size_of_image);
        validate_size(size)?;

        let preferred_available = loader.image_base.is_multiple_of(PE_IMAGE_ALIGNMENT)
            && self.validate_available(loader.image_base, size).is_ok();
        let actual_base = if preferred_available {
            loader.image_base
        } else {
            match placement {
                ImagePlacement::PreferredOnly => {
                    return Err(AddressError::PreferredAddressUnavailable)
                },
                ImagePlacement::PreferredOrFirstFit => {
                    self.find_first_fit(size, PE_IMAGE_ALIGNMENT)?
                },
            }
        };
        let relocated = actual_base != loader.image_base;
        if relocated {
            image
                .base_relocation_plan(actual_base)
                .map_err(AddressError::Pe)?;
        }

        let headers_address = actual_base
            .checked_add(u64::from(loader.headers.virtual_range.rva))
            .ok_or(AddressError::AddressOverflow)?;
        let headers = PeSectionMapping {
            name: [0; 8],
            rva: loader.headers.virtual_range.rva,
            size: loader.headers.virtual_range.size,
            address: headers_address,
            protection: VmProtection::READ,
        };
        validate_image_subrange(actual_base, size, headers.address, u64::from(headers.size))?;

        let mut sections = [PeSectionMapping::EMPTY; MAX_SECTIONS];
        for (index, section) in loader.sections().iter().copied().enumerate() {
            let address = actual_base
                .checked_add(u64::from(section.virtual_range.rva))
                .ok_or(AddressError::AddressOverflow)?;
            let protection = VmProtection::from_pe(section.permissions)?;
            validate_image_subrange(
                actual_base,
                size,
                address,
                u64::from(section.virtual_range.size),
            )?;
            sections[index] = PeSectionMapping {
                name: section.name,
                rva: section.virtual_range.rva,
                size: section.virtual_range.size,
                address,
                protection,
            };
        }
        let entry_address = if loader.entry_rva == 0 {
            None
        } else {
            Some(
                actual_base
                    .checked_add(u64::from(loader.entry_rva))
                    .ok_or(AddressError::AddressOverflow)?,
            )
        };

        let reservation = Reservation {
            start: actual_base,
            size,
            protection: VmProtection::NONE,
            kind: ReservationKind::PeImage,
        };
        self.insert_sorted(reservation)?;
        Ok(PeImageLayout {
            reservation,
            preferred_base: loader.image_base,
            actual_base,
            relocated,
            entry_address,
            headers,
            sections,
            section_count: loader.sections().len(),
        })
    }

    fn validate_available(&self, start: u64, size: u64) -> Result<(), AddressError> {
        let end = start
            .checked_add(size)
            .ok_or(AddressError::AddressOverflow)?;
        if start < self.floor || end > self.ceiling {
            return Err(AddressError::OutsideAddressSpace);
        }
        for reservation in &self.reservations[..self.len] {
            let reservation_end = reservation
                .checked_end()
                .ok_or(AddressError::AddressOverflow)?;
            if start < reservation_end && reservation.start < end {
                return Err(AddressError::Overlap);
            }
        }
        Ok(())
    }

    fn find_first_fit(&self, size: u64, alignment: u64) -> Result<u64, AddressError> {
        let mut candidate = align_up(self.floor, alignment)?;
        for reservation in &self.reservations[..self.len] {
            let reservation_end = reservation
                .checked_end()
                .ok_or(AddressError::AddressOverflow)?;
            let candidate_end = candidate
                .checked_add(size)
                .ok_or(AddressError::AddressOverflow)?;
            if candidate_end <= reservation.start {
                return Ok(candidate);
            }
            if candidate < reservation_end {
                candidate = align_up(reservation_end, alignment)?;
            }
        }
        let end = candidate
            .checked_add(size)
            .ok_or(AddressError::AddressOverflow)?;
        if candidate < self.floor || end > self.ceiling {
            return Err(AddressError::OutOfAddressSpace);
        }
        Ok(candidate)
    }

    fn insert_sorted(&mut self, reservation: Reservation) -> Result<(), AddressError> {
        if self.len == N {
            return Err(AddressError::ReservationTableFull);
        }
        let insertion = self.reservations[..self.len]
            .iter()
            .position(|existing| existing.start > reservation.start)
            .unwrap_or(self.len);
        let mut index = self.len;
        while index > insertion {
            self.reservations[index] = self.reservations[index - 1];
            index -= 1;
        }
        self.reservations[insertion] = reservation;
        self.len += 1;
        Ok(())
    }
}

const fn validate_size(size: u64) -> Result<(), AddressError> {
    if size == 0 || !size.is_multiple_of(VM_PAGE_SIZE) {
        Err(AddressError::InvalidSize)
    } else {
        Ok(())
    }
}

const fn validate_alignment(alignment: u64) -> Result<(), AddressError> {
    if alignment < VM_PAGE_SIZE || !alignment.is_power_of_two() {
        Err(AddressError::InvalidAlignment)
    } else {
        Ok(())
    }
}

const fn align_up(value: u64, alignment: u64) -> Result<u64, AddressError> {
    let mask = alignment - 1;
    match value.checked_add(mask) {
        Some(sum) => Ok(sum & !mask),
        None => Err(AddressError::AddressOverflow),
    }
}

fn validate_image_subrange(
    image_base: u64,
    image_size: u64,
    range_start: u64,
    range_size: u64,
) -> Result<(), AddressError> {
    let image_end = image_base
        .checked_add(image_size)
        .ok_or(AddressError::AddressOverflow)?;
    let range_end = range_start
        .checked_add(range_size)
        .ok_or(AddressError::AddressOverflow)?;
    if range_size == 0 || range_start < image_base || range_end > image_end {
        return Err(AddressError::OutsideAddressSpace);
    }
    Ok(())
}
