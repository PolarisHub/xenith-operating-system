//! Bounded, allocation-free PE32+ console-image materialization for Xenith.
//!
//! This is deliberately a bootstrap slice, not general Windows compatibility.
//! It accepts AMD64 console executables with regular imports and optional DIR64
//! relocations, resolves a tiny local API allowlist, and produces a W^X final
//! protection plan. It rejects every feature for which the runtime does not
//! implement exact behavior, including SEH metadata, TLS, delay imports,
//! API-set contracts, ordinal imports, and arbitrary modules or symbols.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Source-built PE32+ fixture shared by loader and booted conformance tests.
pub mod fixture;
/// Windows executable-path validation and native namespace routing.
pub mod path_runtime;
/// Pointer-free NT runtime adapter used by the console shims.
pub mod runtime;

use xenith_pe::{
    ImportTarget, LoaderPlan, PeError, PeImage, RelocationPatch, SectionLoad,
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_DIRECTORY_ENTRY_TLS,
};
use xenith_winhost_core::{ModuleName, NtStatus, SymbolName, VmProtection};

/// Largest PE file read by the bootstrap host.
pub const MAX_PE_FILE_BYTES: usize = 16 * 1024 * 1024;
/// Largest mapped image accepted by the bootstrap host.
pub const MAX_PE_IMAGE_BYTES: usize = 64 * 1024 * 1024;
/// Largest path accepted from the Xenith startup block.
pub const MAX_PE_PATH_BYTES: usize = 1_024;
/// Maximum imports retained in one bootstrap IAT plan.
pub const MAX_BOOTSTRAP_IMPORTS: usize = 64;
/// Maximum effective DIR64 writes retained in one runtime plan.
pub const MAX_BOOTSTRAP_RELOCATIONS: usize = 1_024;
/// Maximum one-call `WriteFile` payload accepted by the console shim.
pub const MAX_CONSOLE_WRITE_BYTES: usize = 1024 * 1024;
/// Page granularity required for accepted PE stack and heap metadata.
///
/// The bootstrap host deliberately rejects sub-page commit values rather than
/// rounding image metadata implicitly.
pub const RUNTIME_PAGE_SIZE: usize = 4096;
/// Largest initial-thread stack reservation accepted by the bootstrap host.
pub const MAX_STACK_RESERVE_BYTES: u64 = 8 * 1024 * 1024;
/// Largest process-heap reservation accepted by the bootstrap host.
pub const MAX_HEAP_RESERVE_BYTES: u64 = 64 * 1024 * 1024;
/// COFF characteristic bits that contradict the AMD64 user-process host.
pub const UNSUPPORTED_COFF_CHARACTERISTICS_MASK: u16 = 0x5100;
/// Optional-header DLL characteristic bits unsupported by the bootstrap host.
pub const UNSUPPORTED_DLL_CHARACTERISTICS_MASK: u16 = 0x7080;

const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
const IMAGE_FILE_SYSTEM: u16 = 0x1000;
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_FILE_UP_SYSTEM_ONLY: u16 = 0x4000;
const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;
const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: u16 = 0x2000;
const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
const _: () = assert!(MAX_BOOTSTRAP_IMPORTS < xenith_pe::MAX_IMPORTS_TOTAL);
const _: () = assert!(MAX_BOOTSTRAP_RELOCATIONS < xenith_pe::MAX_BASE_RELOCATIONS);
const _: () = assert!(
    UNSUPPORTED_COFF_CHARACTERISTICS_MASK
        == IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_SYSTEM | IMAGE_FILE_UP_SYSTEM_ONLY
);
const _: () = assert!(
    UNSUPPORTED_DLL_CHARACTERISTICS_MASK
        == IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
            | IMAGE_DLLCHARACTERISTICS_APPCONTAINER
            | IMAGE_DLLCHARACTERISTICS_WDM_DRIVER
            | IMAGE_DLLCHARACTERISTICS_GUARD_CF
);

/// Local function addresses exposed under the bootstrap Windows module names.
///
/// Addresses are direct Xenith user addresses. There is intentionally no
/// export forwarding, API-set remapping, DLL search, or ordinal table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapAddresses {
    /// Address of the local `KERNEL32.DLL!GetStdHandle` shim.
    pub get_std_handle: u64,
    /// Address of the local `KERNEL32.DLL!WriteFile` shim.
    pub write_file: u64,
    /// Address of the local `KERNEL32.DLL!ExitProcess` shim.
    pub exit_process: u64,
    /// Optional address of `NTDLL.DLL!RtlExitUserProcess`.
    pub rtl_exit_user_process: Option<u64>,
    /// Optional address of the generation-safe `NTDLL.DLL!NtClose` shim.
    pub nt_close: Option<u64>,
}

impl BootstrapAddresses {
    fn validate(self) -> Result<(), LoaderError> {
        if self.get_std_handle == 0 || self.write_file == 0 || self.exit_process == 0 {
            return Err(LoaderError::InvalidShimAddress);
        }
        if self.rtl_exit_user_process == Some(0) {
            return Err(LoaderError::InvalidShimAddress);
        }
        if self.nt_close == Some(0) {
            return Err(LoaderError::InvalidShimAddress);
        }
        Ok(())
    }

    fn resolve(self, module: &[u8], target: ImportTarget<'_>) -> Result<u64, LoaderError> {
        let module = ModuleName::parse(module).map_err(|_| LoaderError::InvalidModuleName)?;
        if module.is_api_set() {
            return Err(LoaderError::UnsupportedApiSet);
        }
        let ImportTarget::Name { name, .. } = target else {
            return Err(LoaderError::OrdinalImport);
        };
        let symbol = SymbolName::parse(name).map_err(|_| LoaderError::InvalidSymbolName)?;
        match (module.as_bytes(), symbol.as_bytes()) {
            (b"KERNEL32.DLL", b"GetStdHandle") => Ok(self.get_std_handle),
            (b"KERNEL32.DLL", b"WriteFile") => Ok(self.write_file),
            (b"KERNEL32.DLL", b"ExitProcess") => Ok(self.exit_process),
            (b"NTDLL.DLL", b"RtlExitUserProcess") => self
                .rtl_exit_user_process
                .ok_or(LoaderError::SymbolNotAllowed),
            (b"NTDLL.DLL", b"NtClose") => self.nt_close.ok_or(LoaderError::SymbolNotAllowed),
            (b"KERNEL32.DLL" | b"NTDLL.DLL", _) => Err(LoaderError::SymbolNotAllowed),
            _ => Err(LoaderError::ModuleNotAllowed),
        }
    }
}

/// Why an image cannot enter the bounded console-host runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoaderError {
    /// The checked PE parser rejected the file.
    Pe(PeError),
    /// File size is zero or exceeds [`MAX_PE_FILE_BYTES`].
    InvalidFileSize,
    /// `SizeOfImage` exceeds [`MAX_PE_IMAGE_BYTES`].
    ImageTooLarge,
    /// The stack reserve is zero or not a [`RUNTIME_PAGE_SIZE`] multiple.
    InvalidStackReserve {
        /// Rejected reserve size.
        value: u64,
    },
    /// The stack reserve exceeds [`MAX_STACK_RESERVE_BYTES`].
    StackReserveTooLarge {
        /// Rejected reserve size.
        value: u64,
    },
    /// The stack commit is zero or not a [`RUNTIME_PAGE_SIZE`] multiple.
    InvalidStackCommit {
        /// Rejected commit size.
        value: u64,
    },
    /// The heap reserve is zero or not a [`RUNTIME_PAGE_SIZE`] multiple.
    InvalidHeapReserve {
        /// Rejected reserve size.
        value: u64,
    },
    /// The heap reserve exceeds [`MAX_HEAP_RESERVE_BYTES`].
    HeapReserveTooLarge {
        /// Rejected reserve size.
        value: u64,
    },
    /// The heap commit is zero or not a [`RUNTIME_PAGE_SIZE`] multiple.
    InvalidHeapCommit {
        /// Rejected commit size.
        value: u64,
    },
    /// The COFF executable-image bit is absent.
    NotExecutable,
    /// DLL images are outside the initial process-host path.
    DynamicLibrary,
    /// COFF flags require an image type or processor model the host lacks.
    UnsupportedCoffCharacteristics {
        /// Unsupported bits selected by [`UNSUPPORTED_COFF_CHARACTERISTICS_MASK`].
        found: u16,
    },
    /// Optional-header DLL flags require loader behavior the host lacks.
    UnsupportedDllCharacteristics {
        /// Unsupported bits selected by [`UNSUPPORTED_DLL_CHARACTERISTICS_MASK`].
        found: u16,
    },
    /// `RELOCS_STRIPPED` contradicts a nonempty base-relocation directory.
    RelocationsStrippedWithDirectory,
    /// A relocation-stripped image was not mapped at its preferred base.
    PreferredImageBaseRequired {
        /// Preferred base declared by the image.
        preferred_image_base: u64,
        /// Different actual base requested by the runtime.
        actual_image_base: u64,
    },
    /// Only the PE Windows console subsystem is accepted.
    UnsupportedSubsystem {
        /// Subsystem value from the PE optional header.
        found: u16,
    },
    /// A process image must have an executable entry point.
    MissingEntryPoint,
    /// A nonempty data directory is outside the explicit bootstrap policy.
    UnsupportedDirectory {
        /// Standard PE data-directory index.
        index: usize,
    },
    /// AMD64 exception metadata would require SEH/unwind integration.
    ExceptionDirectory,
    /// Authenticode certificate processing is not implemented.
    SecurityDirectory,
    /// PE TLS callbacks and per-thread storage are not implemented.
    TlsDirectory,
    /// Delay-loaded imports are not implemented.
    DelayImportDirectory,
    /// The image has more than [`MAX_BOOTSTRAP_IMPORTS`] imports.
    TooManyImports {
        /// Validated import count.
        count: usize,
    },
    /// The image has more than [`MAX_BOOTSTRAP_RELOCATIONS`] DIR64 writes.
    TooManyRelocations {
        /// Validated effective relocation count.
        count: usize,
    },
    /// An import module name is outside the clean-room grammar.
    InvalidModuleName,
    /// An import symbol name is outside the clean-room grammar.
    InvalidSymbolName,
    /// API-set contract resolution is not guessed.
    UnsupportedApiSet,
    /// Imports by ordinal are outside the bootstrap contract.
    OrdinalImport,
    /// The requested DLL is not on the local bootstrap allowlist.
    ModuleNotAllowed,
    /// The requested export is not on the local bootstrap allowlist.
    SymbolNotAllowed,
    /// One required local shim address was null.
    InvalidShimAddress,
    /// Multiple patch records overlap the same loaded bytes.
    OverlappingPatches,
    /// The output image slice does not exactly match `SizeOfImage`.
    InvalidImageBuffer,
    /// A checked file or mapped-image range was unexpectedly unavailable.
    RangeMismatch,
    /// A mapped relocation source differs from the parser-validated file value.
    RelocationSourceMismatch {
        /// RVA of the unexpected eight-byte value.
        rva: u32,
    },
    /// A section requests a protection other than R, RW, or RX.
    UnsupportedProtection {
        /// Section-table index.
        section: usize,
    },
    /// Checked address arithmetic failed.
    AddressOverflow,
}

impl From<PeError> for LoaderError {
    fn from(value: PeError) -> Self {
        Self::Pe(value)
    }
}

impl LoaderError {
    /// Stable NT status used when reporting this failure at a Windows boundary.
    #[must_use]
    pub const fn nt_status(self) -> NtStatus {
        match self {
            Self::InvalidFileSize
            | Self::ImageTooLarge
            | Self::StackReserveTooLarge { .. }
            | Self::HeapReserveTooLarge { .. }
            | Self::TooManyImports { .. }
            | Self::TooManyRelocations { .. } => NtStatus::INSUFFICIENT_RESOURCES,
            Self::InvalidImageBuffer | Self::RangeMismatch | Self::AddressOverflow => {
                NtStatus::ACCESS_VIOLATION
            },
            Self::InvalidShimAddress | Self::RelocationSourceMismatch { .. } => {
                NtStatus::UNSUCCESSFUL
            },
            Self::PreferredImageBaseRequired { .. } => NtStatus::CONFLICTING_ADDRESSES,
            Self::Pe(_)
            | Self::InvalidStackReserve { .. }
            | Self::InvalidStackCommit { .. }
            | Self::InvalidHeapReserve { .. }
            | Self::InvalidHeapCommit { .. }
            | Self::NotExecutable
            | Self::DynamicLibrary
            | Self::RelocationsStrippedWithDirectory
            | Self::UnsupportedSubsystem { .. }
            | Self::MissingEntryPoint
            | Self::OverlappingPatches => NtStatus::INVALID_IMAGE_FORMAT,
            Self::UnsupportedCoffCharacteristics { .. }
            | Self::UnsupportedDllCharacteristics { .. }
            | Self::UnsupportedDirectory { .. }
            | Self::ExceptionDirectory
            | Self::SecurityDirectory
            | Self::TlsDirectory
            | Self::DelayImportDirectory
            | Self::InvalidModuleName
            | Self::InvalidSymbolName
            | Self::UnsupportedApiSet
            | Self::OrdinalImport
            | Self::ModuleNotAllowed
            | Self::SymbolNotAllowed
            | Self::UnsupportedProtection { .. } => NtStatus::NOT_SUPPORTED,
        }
    }
}

/// One direct address to write into an image's import address table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IatPatch {
    rva: u32,
    address: u64,
}

impl IatPatch {
    const EMPTY: Self = Self { rva: 0, address: 0 };

    /// RVA of the eight-byte IAT slot.
    #[must_use]
    pub const fn rva(self) -> u32 {
        self.rva
    }

    /// Direct local shim address written to the IAT slot.
    #[must_use]
    pub const fn address(self) -> u64 {
        self.address
    }
}

/// Complete fixed-capacity IAT plan for the bootstrap allowlist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapImportPlan {
    image_size: usize,
    patches: [IatPatch; MAX_BOOTSTRAP_IMPORTS],
    len: usize,
}

impl BootstrapImportPlan {
    /// Ordered IAT writes, preserving PE descriptor/thunk order.
    #[must_use]
    pub fn patches(&self) -> &[IatPatch] {
        &self.patches[..self.len]
    }

    /// Number of direct IAT writes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the image imports no bootstrap functions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Complete fixed-capacity DIR64 patch plan for one actual image base.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeRelocationPlan {
    image_size: usize,
    actual_base: u64,
    patches: [RelocationPatch; MAX_BOOTSTRAP_RELOCATIONS],
    len: usize,
}

impl RuntimeRelocationPlan {
    /// Ordered checked DIR64 writes.
    #[must_use]
    pub fn patches(&self) -> &[RelocationPatch] {
        &self.patches[..self.len]
    }

    /// Actual mapped image base used to calculate the patches.
    #[must_use]
    pub const fn actual_base(&self) -> u64 {
        self.actual_base
    }

    /// Number of effective DIR64 writes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether rebasing requires no writes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Final protection supported by Xenith's W^X userspace mapping API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalProtection {
    /// Read-only, non-executable.
    Read,
    /// Read/write, non-executable.
    ReadWrite,
    /// Read/execute, non-writable.
    ReadExecute,
}

/// One page-aligned final section-protection operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionRange {
    /// RVA at which the operation begins.
    pub rva: u32,
    /// Page-multiple range size.
    pub size: u32,
    /// Final W^X protection.
    pub protection: FinalProtection,
}

/// Summary returned only after a complete image was materialized and patched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadedImage {
    /// Actual mapped image base.
    pub actual_base: u64,
    /// Checked Win64 entry address.
    pub entry_address: u64,
    /// Number of installed IAT entries.
    pub import_count: usize,
    /// Number of applied DIR64 relocations.
    pub relocation_count: usize,
}

/// Validate the complete runtime policy before mapping or mutating an image.
pub fn validate_runtime_subset(image: &PeImage<'_>) -> Result<LoaderPlan, LoaderError> {
    let headers = image.headers();
    let coff_characteristics = headers.coff.characteristics;
    if coff_characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
        return Err(LoaderError::NotExecutable);
    }
    if coff_characteristics & IMAGE_FILE_DLL != 0 {
        return Err(LoaderError::DynamicLibrary);
    }
    let unsupported_coff = coff_characteristics & UNSUPPORTED_COFF_CHARACTERISTICS_MASK;
    if unsupported_coff != 0 {
        return Err(LoaderError::UnsupportedCoffCharacteristics {
            found: unsupported_coff,
        });
    }
    let unsupported_dll =
        headers.optional.dll_characteristics & UNSUPPORTED_DLL_CHARACTERISTICS_MASK;
    if unsupported_dll != 0 {
        return Err(LoaderError::UnsupportedDllCharacteristics {
            found: unsupported_dll,
        });
    }
    if headers.optional.subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI {
        return Err(LoaderError::UnsupportedSubsystem {
            found: headers.optional.subsystem,
        });
    }
    if headers.optional.address_of_entry_point == 0 {
        return Err(LoaderError::MissingEntryPoint);
    }
    if usize::try_from(headers.optional.size_of_image)
        .map_or(true, |size| size > MAX_PE_IMAGE_BYTES)
    {
        return Err(LoaderError::ImageTooLarge);
    }
    validate_resource_metadata(image)?;
    if coff_characteristics & IMAGE_FILE_RELOCS_STRIPPED != 0
        && image
            .directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
            .is_some_and(|directory| !directory.is_empty())
    {
        return Err(LoaderError::RelocationsStrippedWithDirectory);
    }
    validate_directory_policy(image)?;
    // These calls fully validate both bounded metadata graphs even when the
    // image lands at its preferred address and has no imports.
    let imports = image.import_summary()?;
    if imports.import_count > MAX_BOOTSTRAP_IMPORTS {
        return Err(LoaderError::TooManyImports {
            count: imports.import_count,
        });
    }
    let preferred = headers.optional.image_base;
    let relocations = image.base_relocation_plan(preferred)?;
    if relocations.patch_count > MAX_BOOTSTRAP_RELOCATIONS {
        return Err(LoaderError::TooManyRelocations {
            count: relocations.patch_count,
        });
    }
    let loader = image.loader_plan()?;
    validate_protections(&loader)?;
    Ok(loader)
}

fn validate_resource_metadata(image: &PeImage<'_>) -> Result<(), LoaderError> {
    let optional = image.headers().optional;
    if !is_nonzero_page_multiple(optional.size_of_stack_reserve) {
        return Err(LoaderError::InvalidStackReserve {
            value: optional.size_of_stack_reserve,
        });
    }
    if optional.size_of_stack_reserve > MAX_STACK_RESERVE_BYTES {
        return Err(LoaderError::StackReserveTooLarge {
            value: optional.size_of_stack_reserve,
        });
    }
    if !is_nonzero_page_multiple(optional.size_of_stack_commit) {
        return Err(LoaderError::InvalidStackCommit {
            value: optional.size_of_stack_commit,
        });
    }
    if !is_nonzero_page_multiple(optional.size_of_heap_reserve) {
        return Err(LoaderError::InvalidHeapReserve {
            value: optional.size_of_heap_reserve,
        });
    }
    if optional.size_of_heap_reserve > MAX_HEAP_RESERVE_BYTES {
        return Err(LoaderError::HeapReserveTooLarge {
            value: optional.size_of_heap_reserve,
        });
    }
    if !is_nonzero_page_multiple(optional.size_of_heap_commit) {
        return Err(LoaderError::InvalidHeapCommit {
            value: optional.size_of_heap_commit,
        });
    }
    Ok(())
}

fn is_nonzero_page_multiple(value: u64) -> bool {
    value != 0 && value.is_multiple_of(RUNTIME_PAGE_SIZE as u64)
}

fn validate_directory_policy(image: &PeImage<'_>) -> Result<(), LoaderError> {
    for (index, directory) in image.directories().iter().copied().enumerate() {
        if directory.is_empty() {
            continue;
        }
        match index {
            IMAGE_DIRECTORY_ENTRY_IMPORT
            | IMAGE_DIRECTORY_ENTRY_BASERELOC
            | IMAGE_DIRECTORY_ENTRY_IAT => {},
            IMAGE_DIRECTORY_ENTRY_EXCEPTION => return Err(LoaderError::ExceptionDirectory),
            IMAGE_DIRECTORY_ENTRY_SECURITY => return Err(LoaderError::SecurityDirectory),
            IMAGE_DIRECTORY_ENTRY_TLS => return Err(LoaderError::TlsDirectory),
            IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT => return Err(LoaderError::DelayImportDirectory),
            _ => return Err(LoaderError::UnsupportedDirectory { index }),
        }
    }
    Ok(())
}

fn validate_protections(loader: &LoaderPlan) -> Result<(), LoaderError> {
    for section in loader.sections() {
        let permissions = section.permissions;
        let vm = VmProtection::try_new(permissions.read, permissions.write, permissions.execute)
            .map_err(|_| LoaderError::UnsupportedProtection {
                section: section.index,
            })?;
        if section.virtual_range.size != 0
            && (!vm.is_readable()
                || (vm.is_writable() && vm.is_executable())
                || !(section.virtual_range.rva as usize).is_multiple_of(RUNTIME_PAGE_SIZE)
                || !(section.virtual_range.size as usize).is_multiple_of(RUNTIME_PAGE_SIZE))
        {
            return Err(LoaderError::UnsupportedProtection {
                section: section.index,
            });
        }
    }
    Ok(())
}

/// Build a complete allowlisted IAT plan without changing mapped memory.
pub fn plan_bootstrap_imports(
    image: &PeImage<'_>,
    addresses: BootstrapAddresses,
) -> Result<BootstrapImportPlan, LoaderError> {
    addresses.validate()?;
    let loader = validate_runtime_subset(image)?;
    let summary = image.import_summary()?;
    let mut plan = BootstrapImportPlan {
        image_size: loader.size_of_image as usize,
        patches: [IatPatch::EMPTY; MAX_BOOTSTRAP_IMPORTS],
        len: 0,
    };
    let mut error = None;
    image.visit_imports(|record| {
        if error.is_some() {
            return;
        }
        let address = match addresses.resolve(record.module_name, record.target) {
            Ok(value) => value,
            Err(cause) => {
                error = Some(cause);
                return;
            },
        };
        let end = match record.iat_rva.checked_add(8) {
            Some(value) => value,
            None => {
                error = Some(LoaderError::RangeMismatch);
                return;
            },
        };
        if end as usize > plan.image_size
            || plan
                .patches()
                .iter()
                .any(|patch| ranges_overlap(patch.rva, 8, record.iat_rva, 8))
        {
            error = Some(if end as usize > plan.image_size {
                LoaderError::RangeMismatch
            } else {
                LoaderError::OverlappingPatches
            });
            return;
        }
        plan.patches[plan.len] = IatPatch {
            rva: record.iat_rva,
            address,
        };
        plan.len += 1;
    })?;
    if let Some(cause) = error {
        return Err(cause);
    }
    debug_assert_eq!(plan.len, summary.import_count);
    Ok(plan)
}

/// Build a complete bounded DIR64 plan for the actual mapped base.
pub fn plan_runtime_relocations(
    image: &PeImage<'_>,
    actual_base: u64,
) -> Result<RuntimeRelocationPlan, LoaderError> {
    let loader = validate_runtime_subset(image)?;
    if image.headers().coff.characteristics & IMAGE_FILE_RELOCS_STRIPPED != 0
        && actual_base != loader.image_base
    {
        return Err(LoaderError::PreferredImageBaseRequired {
            preferred_image_base: loader.image_base,
            actual_image_base: actual_base,
        });
    }
    let summary = image.base_relocation_plan(actual_base)?;
    if summary.patch_count > MAX_BOOTSTRAP_RELOCATIONS {
        return Err(LoaderError::TooManyRelocations {
            count: summary.patch_count,
        });
    }
    let empty = RelocationPatch {
        target_rva: 0,
        original_value: 0,
        relocated_value: 0,
    };
    let mut plan = RuntimeRelocationPlan {
        image_size: loader.size_of_image as usize,
        actual_base,
        patches: [empty; MAX_BOOTSTRAP_RELOCATIONS],
        len: 0,
    };
    let mut error = None;
    image.visit_base_relocations(actual_base, |patch| {
        if error.is_some() {
            return;
        }
        let Some(end) = patch.target_rva.checked_add(8) else {
            error = Some(LoaderError::RangeMismatch);
            return;
        };
        if end as usize > plan.image_size {
            error = Some(LoaderError::RangeMismatch);
            return;
        }
        if plan
            .patches()
            .iter()
            .any(|prior| ranges_overlap(prior.target_rva, 8, patch.target_rva, 8))
        {
            error = Some(LoaderError::OverlappingPatches);
            return;
        }
        plan.patches[plan.len] = patch;
        plan.len += 1;
    })?;
    if let Some(cause) = error {
        return Err(cause);
    }
    debug_assert_eq!(plan.len, summary.patch_count);
    Ok(plan)
}

/// Reject any overlap between relocation targets and IAT destinations.
pub fn validate_patch_separation(
    relocations: &RuntimeRelocationPlan,
    imports: &BootstrapImportPlan,
) -> Result<(), LoaderError> {
    if relocations.image_size != imports.image_size {
        return Err(LoaderError::InvalidImageBuffer);
    }
    for relocation in relocations.patches() {
        if imports
            .patches()
            .iter()
            .any(|iat| ranges_overlap(relocation.target_rva, 8, iat.rva, 8))
        {
            return Err(LoaderError::OverlappingPatches);
        }
    }
    Ok(())
}

/// Zero and copy a validated image, with all ranges preflighted before mutation.
pub fn materialize_image(image: &PeImage<'_>, output: &mut [u8]) -> Result<(), LoaderError> {
    let loader = validate_runtime_subset(image)?;
    if output.len() != loader.size_of_image as usize {
        return Err(LoaderError::InvalidImageBuffer);
    }
    preflight_copy(image, output.len(), &loader)?;
    output.fill(0);
    copy_file_range(
        image.bytes(),
        output,
        loader.headers.file.offset,
        loader.headers.virtual_range.rva,
        loader.headers.file.size,
    );
    for section in loader.sections() {
        if let Some(file) = section.file {
            copy_file_range(
                image.bytes(),
                output,
                file.offset,
                section.virtual_range.rva,
                file.size,
            );
        }
    }
    Ok(())
}

fn preflight_copy(
    image: &PeImage<'_>,
    output_len: usize,
    loader: &LoaderPlan,
) -> Result<(), LoaderError> {
    preflight_range(
        image.bytes().len(),
        output_len,
        loader.headers.file.offset,
        loader.headers.virtual_range.rva,
        loader.headers.file.size,
    )?;
    for section in loader.sections() {
        if let Some(file) = section.file {
            preflight_range(
                image.bytes().len(),
                output_len,
                file.offset,
                section.virtual_range.rva,
                file.size,
            )?;
        }
    }
    Ok(())
}

fn preflight_range(
    source_len: usize,
    destination_len: usize,
    source: u32,
    destination: u32,
    size: u32,
) -> Result<(), LoaderError> {
    let source_end = source.checked_add(size).ok_or(LoaderError::RangeMismatch)? as usize;
    let destination_end = destination
        .checked_add(size)
        .ok_or(LoaderError::RangeMismatch)? as usize;
    if source_end > source_len || destination_end > destination_len {
        return Err(LoaderError::RangeMismatch);
    }
    Ok(())
}

fn copy_file_range(
    source: &[u8],
    destination: &mut [u8],
    source_offset: u32,
    destination_offset: u32,
    size: u32,
) {
    let source_start = source_offset as usize;
    let destination_start = destination_offset as usize;
    let count = size as usize;
    destination[destination_start..destination_start + count]
        .copy_from_slice(&source[source_start..source_start + count]);
}

/// Apply a prevalidated DIR64 plan after verifying every source before writes.
pub fn apply_relocation_plan(
    plan: &RuntimeRelocationPlan,
    output: &mut [u8],
) -> Result<(), LoaderError> {
    if output.len() != plan.image_size {
        return Err(LoaderError::InvalidImageBuffer);
    }
    for patch in plan.patches() {
        let slot = output
            .get(patch.target_rva as usize..patch.target_rva as usize + 8)
            .ok_or(LoaderError::RangeMismatch)?;
        if read_u64(slot) != patch.original_value {
            return Err(LoaderError::RelocationSourceMismatch {
                rva: patch.target_rva,
            });
        }
    }
    for patch in plan.patches() {
        write_u64(output, patch.target_rva, patch.relocated_value);
    }
    Ok(())
}

/// Apply a complete prevalidated direct-IAT plan.
pub fn apply_import_plan(plan: &BootstrapImportPlan, output: &mut [u8]) -> Result<(), LoaderError> {
    if output.len() != plan.image_size
        || plan
            .patches()
            .iter()
            .any(|patch| patch.rva as usize + 8 > output.len())
    {
        return Err(LoaderError::InvalidImageBuffer);
    }
    for patch in plan.patches() {
        write_u64(output, patch.rva, patch.address);
    }
    Ok(())
}

/// Materialize, relocate, and bind one image as one all-or-error operation.
///
/// Every fallible structural and patch-overlap check runs before the first
/// output write. The destination must be a fresh zeroed RW anonymous mapping;
/// callers install final protections only after this returns successfully.
pub fn build_loaded_image(
    image: &PeImage<'_>,
    actual_base: u64,
    addresses: BootstrapAddresses,
    output: &mut [u8],
) -> Result<LoadedImage, LoaderError> {
    let loader = validate_runtime_subset(image)?;
    if output.len() != loader.size_of_image as usize {
        return Err(LoaderError::InvalidImageBuffer);
    }
    let imports = plan_bootstrap_imports(image, addresses)?;
    let relocations = plan_runtime_relocations(image, actual_base)?;
    validate_patch_separation(&relocations, &imports)?;
    preflight_copy(image, output.len(), &loader)?;
    let entry_address = actual_base
        .checked_add(u64::from(loader.entry_rva))
        .ok_or(LoaderError::AddressOverflow)?;

    // No operation below can fail after the complete preflight above unless
    // mapped memory changed behind this single-threaded loader.
    materialize_image(image, output)?;
    apply_relocation_plan(&relocations, output)?;
    apply_import_plan(&imports, output)?;
    Ok(LoadedImage {
        actual_base,
        entry_address,
        import_count: imports.len(),
        relocation_count: relocations.len(),
    })
}

/// Visit section overrides for the caller's initial whole-image read-only map.
///
/// The caller first protects the entire image read-only, then applies each
/// returned section range. This leaves headers and virtual gaps read-only.
pub fn visit_final_section_protections<F>(
    image: &PeImage<'_>,
    mut visitor: F,
) -> Result<(), LoaderError>
where
    F: FnMut(ProtectionRange),
{
    let loader = validate_runtime_subset(image)?;
    for section in loader.sections() {
        if section.virtual_range.size == 0 {
            continue;
        }
        visitor(ProtectionRange {
            rva: section.virtual_range.rva,
            size: section.virtual_range.size,
            protection: section_protection(section)?,
        });
    }
    Ok(())
}

fn section_protection(section: &SectionLoad) -> Result<FinalProtection, LoaderError> {
    match (
        section.permissions.read,
        section.permissions.write,
        section.permissions.execute,
    ) {
        (true, false, false) => Ok(FinalProtection::Read),
        (true, true, false) => Ok(FinalProtection::ReadWrite),
        (true, false, true) => Ok(FinalProtection::ReadExecute),
        _ => Err(LoaderError::UnsupportedProtection {
            section: section.index,
        }),
    }
}

const fn ranges_overlap(first: u32, first_size: u32, second: u32, second_size: u32) -> bool {
    let Some(first_end) = first.checked_add(first_size) else {
        return true;
    };
    let Some(second_end) = second.checked_add(second_size) else {
        return true;
    };
    first < second_end && second < first_end
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn write_u64(output: &mut [u8], rva: u32, value: u64) {
    let start = rva as usize;
    output[start..start + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_and_runtime_caps_are_deliberately_narrow() {
        assert_eq!(MAX_PE_FILE_BYTES, 16 * 1024 * 1024);
        assert_eq!(MAX_PE_IMAGE_BYTES, 64 * 1024 * 1024);
        assert_eq!(RUNTIME_PAGE_SIZE, 4096);
        assert_eq!(MAX_STACK_RESERVE_BYTES, 8 * 1024 * 1024);
        assert_eq!(MAX_HEAP_RESERVE_BYTES, 64 * 1024 * 1024);
        assert_eq!(UNSUPPORTED_COFF_CHARACTERISTICS_MASK, 0x5100);
        assert_eq!(UNSUPPORTED_DLL_CHARACTERISTICS_MASK, 0x7080);
    }

    #[test]
    fn loader_errors_have_stable_boundary_statuses() {
        assert_eq!(
            LoaderError::OrdinalImport.nt_status(),
            NtStatus::NOT_SUPPORTED
        );
        assert_eq!(
            LoaderError::NotExecutable.nt_status(),
            NtStatus::INVALID_IMAGE_FORMAT
        );
        assert_eq!(
            LoaderError::ImageTooLarge.nt_status(),
            NtStatus::INSUFFICIENT_RESOURCES
        );
        assert_eq!(
            LoaderError::InvalidStackReserve { value: 0 }.nt_status(),
            NtStatus::INVALID_IMAGE_FORMAT
        );
        assert_eq!(
            LoaderError::HeapReserveTooLarge {
                value: MAX_HEAP_RESERVE_BYTES + RUNTIME_PAGE_SIZE as u64,
            }
            .nt_status(),
            NtStatus::INSUFFICIENT_RESOURCES
        );
        assert_eq!(
            LoaderError::UnsupportedCoffCharacteristics { found: 0x0100 }.nt_status(),
            NtStatus::NOT_SUPPORTED
        );
        assert_eq!(
            LoaderError::RelocationsStrippedWithDirectory.nt_status(),
            NtStatus::INVALID_IMAGE_FORMAT
        );
        assert_eq!(
            LoaderError::PreferredImageBaseRequired {
                preferred_image_base: 0x1_4000_0000,
                actual_image_base: 0x1_4001_0000,
            }
            .nt_status(),
            NtStatus::CONFLICTING_ADDRESSES
        );
    }
}
