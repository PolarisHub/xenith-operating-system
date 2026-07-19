//! Early boot-protocol detection and normalization.
//!
//! The kernel's subsystems still consume the compact `limine::BootInfo`
//! compatibility surface. Legacy emulator boots already provide that surface,
//! while Xenith's BIOS and UEFI loaders pass a [`XenithBootInfo`] whose nested
//! pointers are physical. This module detects the handoff and, for Xenith
//! boots, copies bounded metadata through the HHDM into kernel-owned static
//! storage before memory management can reclaim loader pages.

use core::cell::UnsafeCell;
use core::ffi::c_char;
use core::mem::{align_of, size_of};
use core::sync::atomic::{AtomicU8, Ordering};
use core::{fmt, ptr};

use xenith_abi::{XenithBootInfo, XenithFramebuffer, XenithModule, XENITH_BOOT_MAGIC};

/// HHDM base installed by both Xenith loaders and assumed by kernel MMIO code.
pub const XENITH_HHDM_OFFSET: u64 = 0xffff_8000_0000_0000;
/// Physical bytes covered by the loaders' transition identity/HHDM mappings.
pub const TRANSITION_PHYSICAL_LIMIT: u64 = 1_u64 << 32;
/// Maximum number of Xenith memory-map records copied during early boot.
pub const MAX_MEMORY_MAP_ENTRIES: usize = 512;
/// Maximum number of Xenith modules copied during early boot.
pub const MAX_MODULES: usize = 16;
/// Maximum module-path payload, excluding the synthetic trailing NUL.
pub const MAX_MODULE_PATH_BYTES: usize = 255;
/// Maximum command-line payload, excluding the synthetic trailing NUL.
pub const MAX_COMMAND_LINE_BYTES: usize = 4095;

const MODULE_PATH_STORAGE_BYTES: usize = MAX_MODULE_PATH_BYTES + 1;
const COMMAND_LINE_STORAGE_BYTES: usize = MAX_COMMAND_LINE_BYTES + 1;
const BOOT_STATE_EMPTY: u8 = 0;
const BOOT_STATE_WRITING: u8 = 1;
const BOOT_STATE_READY: u8 = 2;

const LIMINE_USABLE: u32 = 0;
const LIMINE_RESERVED: u32 = 1;
const LIMINE_ACPI_RECLAIMABLE: u32 = 2;
const LIMINE_ACPI_NVS: u32 = 3;
const LIMINE_BAD_MEMORY: u32 = 4;
const LIMINE_BOOTLOADER_RECLAIMABLE: u32 = 5;
const LIMINE_KERNEL_AND_MODULES: u32 = 6;

/// The wire protocol detected at the raw kernel entry point.
#[derive(Clone, Copy, Debug)]
pub enum BootSource {
    /// Legacy Limine-compatible handoff; no conversion is performed.
    Limine(&'static limine::BootInfo),
    /// Xenith handoff copied out of the possibly unaligned entry record.
    Xenith(XenithBootInfo),
}

/// A rejected early-boot handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootError {
    NullHandoff,
    MisalignedLimineHandoff,
    WrongMagic,
    UnsupportedVersion(u32),
    HeaderTooSmall(u32),
    InvalidHhdm(u64),
    NonZeroHeaderReserved,
    InvalidMemoryMapEntrySize(u32),
    InvalidMemoryMapCount(u32),
    InvalidModuleCount(u32),
    CommandLineTooLong(u32),
    NullMetadata(&'static str),
    MisalignedMetadata(&'static str),
    MetadataSizeOverflow(&'static str),
    MetadataOutsideTransitionMap(&'static str),
    InvalidMemoryKind { index: usize, kind: u32 },
    NonZeroMemoryRegionReserved(usize),
    EmptyMemoryRegion(usize),
    MemoryRegionOverflow(usize),
    OverlappingMemoryRegion(usize),
    NoTransitionMemory,
    NonZeroModuleReserved(usize),
    EmptyModule(usize),
    ModuleRangeOverflow(usize),
    ModuleOutsideTransitionMap(usize),
    ModulePathTooLong { index: usize, length: u32 },
    ModuleOverlapsUsableMemory(usize),
    InvalidUtf8(&'static str, usize),
    EmbeddedNul(&'static str, usize),
    InvalidFramebuffer(&'static str),
    RsdpOutsideTransitionMap,
    AdapterAlreadyUsed,
}

impl fmt::Display for BootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NullHandoff => f.write_str("null boot-info pointer"),
            Self::MisalignedLimineHandoff => {
                f.write_str("misaligned legacy Limine-compatible boot info")
            },
            Self::WrongMagic => f.write_str("invalid Xenith boot magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported Xenith boot version {version}")
            },
            Self::HeaderTooSmall(size) => write!(f, "Xenith boot header is only {size} bytes"),
            Self::InvalidHhdm(offset) => write!(f, "unsupported HHDM offset {offset:#018x}"),
            Self::NonZeroHeaderReserved => {
                f.write_str("Xenith boot header reserved field is nonzero")
            },
            Self::InvalidMemoryMapEntrySize(size) => {
                write!(f, "unsupported memory-map entry size {size}")
            },
            Self::InvalidMemoryMapCount(count) => write!(
                f,
                "memory-map count {count} is outside 1..={MAX_MEMORY_MAP_ENTRIES}"
            ),
            Self::InvalidModuleCount(count) => {
                write!(f, "module count {count} exceeds {MAX_MODULES}")
            },
            Self::CommandLineTooLong(length) => write!(
                f,
                "command line is {length} bytes; maximum is {MAX_COMMAND_LINE_BYTES}"
            ),
            Self::NullMetadata(field) => write!(f, "{field} physical pointer is null"),
            Self::MisalignedMetadata(field) => {
                write!(f, "{field} physical pointer is misaligned")
            },
            Self::MetadataSizeOverflow(field) => write!(f, "{field} byte range overflows"),
            Self::MetadataOutsideTransitionMap(field) => write!(
                f,
                "{field} lies outside the loader's first-4-GiB transition map"
            ),
            Self::InvalidMemoryKind { index, kind } => {
                write!(f, "memory-map entry {index} has unknown kind {kind}")
            },
            Self::NonZeroMemoryRegionReserved(index) => {
                write!(f, "memory-map entry {index} has a nonzero reserved field")
            },
            Self::EmptyMemoryRegion(index) => {
                write!(f, "memory-map entry {index} has zero length")
            },
            Self::MemoryRegionOverflow(index) => {
                write!(f, "memory-map entry {index} address range overflows")
            },
            Self::OverlappingMemoryRegion(index) => {
                write!(f, "memory-map entry {index} is unsorted or overlapping")
            },
            Self::NoTransitionMemory => {
                f.write_str("memory map contains no region below the 4-GiB transition limit")
            },
            Self::NonZeroModuleReserved(index) => {
                write!(f, "module {index} has a nonzero reserved field")
            },
            Self::EmptyModule(index) => write!(f, "module {index} has an empty range"),
            Self::ModuleRangeOverflow(index) => {
                write!(f, "module {index} address range overflows")
            },
            Self::ModuleOutsideTransitionMap(index) => {
                write!(f, "module {index} lies outside the first 4 GiB")
            },
            Self::ModulePathTooLong { index, length } => write!(
                f,
                "module {index} path is {length} bytes; maximum is {MAX_MODULE_PATH_BYTES}"
            ),
            Self::ModuleOverlapsUsableMemory(index) => {
                write!(f, "module {index} overlaps allocator-usable memory")
            },
            Self::InvalidUtf8(field, index) => {
                write!(f, "{field} {index} is not valid UTF-8")
            },
            Self::EmbeddedNul(field, index) => {
                write!(f, "{field} {index} contains an embedded NUL")
            },
            Self::InvalidFramebuffer(reason) => write!(f, "invalid framebuffer: {reason}"),
            Self::RsdpOutsideTransitionMap => {
                f.write_str("RSDP lies outside the first-4-GiB transition map")
            },
            Self::AdapterAlreadyUsed => {
                f.write_str("Xenith boot adapter was entered more than once")
            },
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct RawMemoryRegion {
    base: u64,
    length: u64,
    kind: u32,
    reserved: u32,
}

const _: [(); size_of::<xenith_abi::XenithMemoryRegion>()] = [(); size_of::<RawMemoryRegion>()];
const _: [(); align_of::<xenith_abi::XenithMemoryRegion>()] = [(); align_of::<RawMemoryRegion>()];

const EMPTY_MEMORY_REGION: limine::MemmapEntry = limine::MemmapEntry {
    base: 0,
    length: 0,
    kind: LIMINE_RESERVED,
    reserved: 0,
};

const EMPTY_MODULE: limine::Module = limine::Module {
    base: ptr::null(),
    length: 0,
    path: ptr::null(),
    cmdline: ptr::null(),
};

const EMPTY_FRAMEBUFFER: limine::Framebuffer = limine::Framebuffer {
    address: ptr::null_mut(),
    width: 0,
    height: 0,
    pitch: 0,
    bpp: 0,
};

struct CompatStorage {
    boot_info: limine::BootInfo,
    memory_map: [limine::MemmapEntry; MAX_MEMORY_MAP_ENTRIES],
    modules: [limine::Module; MAX_MODULES],
    module_paths: [[u8; MODULE_PATH_STORAGE_BYTES]; MAX_MODULES],
    command_line: [u8; COMMAND_LINE_STORAGE_BYTES],
    framebuffer: limine::Framebuffer,
    framebuffer_pointer: [*const limine::Framebuffer; 1],
}

impl CompatStorage {
    const fn empty() -> Self {
        Self {
            boot_info: limine::BootInfo::empty(),
            memory_map: [EMPTY_MEMORY_REGION; MAX_MEMORY_MAP_ENTRIES],
            modules: [EMPTY_MODULE; MAX_MODULES],
            module_paths: [[0; MODULE_PATH_STORAGE_BYTES]; MAX_MODULES],
            command_line: [0; COMMAND_LINE_STORAGE_BYTES],
            framebuffer: EMPTY_FRAMEBUFFER,
            framebuffer_pointer: [ptr::null()],
        }
    }
}

struct CompatStorageCell(UnsafeCell<CompatStorage>);

// SAFETY: BOOT_STATE grants the BSP exclusive access while the cell is
// populated. After publication the storage is immutable for the kernel's
// lifetime.
unsafe impl Sync for CompatStorageCell {}

static COMPAT_STORAGE: CompatStorageCell =
    CompatStorageCell(UnsafeCell::new(CompatStorage::empty()));
static BOOT_STATE: AtomicU8 = AtomicU8::new(BOOT_STATE_EMPTY);

/// Detect the entry-point handoff without following nested pointers.
///
/// # Safety
///
/// `raw` must be null or point to an identity-accessible entry record supplied
/// by a supported loader. A non-null record must contain at least a complete
/// `XenithBootInfo` or `limine::BootInfo`. Xenith records need only remain
/// readable for this call and may be unaligned. A legacy Limine-compatible
/// record must be aligned, immutable, and mapped for the kernel's lifetime.
pub unsafe fn detect(raw: *const u8) -> Result<BootSource, BootError> {
    if raw.is_null() {
        return Err(BootError::NullHandoff);
    }

    // SAFETY: the entry contract guarantees at least eight readable bytes;
    // unaligned access permits packed loader storage.
    let magic = unsafe { ptr::read_unaligned(raw.cast::<u64>()) };
    if magic == XENITH_BOOT_MAGIC {
        // SAFETY: Xenith loaders supply a complete record. This type contains
        // only integers, raw pointers, and a plain framebuffer descriptor, so
        // every bit pattern is valid and the copy cannot create an invalid enum.
        let info = unsafe { ptr::read_unaligned(raw.cast::<XenithBootInfo>()) };
        Ok(BootSource::Xenith(info))
    } else {
        if !(raw as usize).is_multiple_of(align_of::<limine::BootInfo>()) {
            return Err(BootError::MisalignedLimineHandoff);
        }
        // SAFETY: the caller's legacy branch contract guarantees this aligned
        // pointer names a static Limine-compatible record.
        Ok(BootSource::Limine(unsafe {
            &*raw.cast::<limine::BootInfo>()
        }))
    }
}

/// Normalize either supported handoff into the kernel's existing boot surface.
///
/// The legacy branch is returned unchanged. The Xenith branch is validated and
/// copied exactly once into static kernel storage.
///
/// # Safety
///
/// For [`BootSource::Xenith`], every non-null physical pointer and declared
/// byte range must name readable loader-owned memory mapped at
/// `XENITH_HHDM_OFFSET + physical`. Module and framebuffer payload ranges must
/// match the mappings established by the loader. [`detect`] documents the
/// additional requirements for constructing a source from the entry pointer.
pub unsafe fn normalize(source: BootSource) -> Result<&'static limine::BootInfo, BootError> {
    match source {
        BootSource::Limine(info) => Ok(info),
        BootSource::Xenith(info) => {
            // SAFETY: the caller upholds the Xenith physical-memory contract.
            unsafe { normalize_xenith(info) }
        },
    }
}

/// Detect and normalize the raw entry-point handoff.
///
/// # Safety
///
/// The requirements of [`detect`] and [`normalize`] both apply.
pub unsafe fn normalize_raw(raw: *const u8) -> Result<&'static limine::BootInfo, BootError> {
    // SAFETY: forwarded from this function's caller.
    let source = unsafe { detect(raw)? };
    // SAFETY: forwarded from this function's caller.
    unsafe { normalize(source) }
}

unsafe fn normalize_xenith(info: XenithBootInfo) -> Result<&'static limine::BootInfo, BootError> {
    validate_header(&info)?;
    BOOT_STATE
        .compare_exchange(
            BOOT_STATE_EMPTY,
            BOOT_STATE_WRITING,
            Ordering::Acquire,
            Ordering::Relaxed,
        )
        .map_err(|_| BootError::AdapterAlreadyUsed)?;

    // SAFETY: the successful state transition gives this BSP the only mutable
    // access to the static cell. No reference has been published yet.
    let storage = unsafe { &mut *COMPAT_STORAGE.0.get() };
    // SAFETY: the caller guarantees that validated physical metadata ranges are
    // readable through the declared HHDM.
    let result = unsafe { populate_compat(&info, storage) };
    if let Err(error) = result {
        BOOT_STATE.store(BOOT_STATE_EMPTY, Ordering::Release);
        return Err(error);
    }

    let boot_info = ptr::addr_of!(storage.boot_info);
    BOOT_STATE.store(BOOT_STATE_READY, Ordering::Release);
    // SAFETY: the pointer belongs to static storage, initialization completed
    // before the Release publication, and no later mutation is permitted.
    Ok(unsafe { &*boot_info })
}

fn validate_header(info: &XenithBootInfo) -> Result<(), BootError> {
    if info.magic != XENITH_BOOT_MAGIC {
        return Err(BootError::WrongMagic);
    }
    if info.version != xenith_abi::XENITH_BOOT_VERSION {
        return Err(BootError::UnsupportedVersion(info.version));
    }
    if (info.size as usize) < size_of::<XenithBootInfo>() {
        return Err(BootError::HeaderTooSmall(info.size));
    }
    if info.hhdm_offset != XENITH_HHDM_OFFSET {
        return Err(BootError::InvalidHhdm(info.hhdm_offset));
    }
    if info.reserved != 0 {
        return Err(BootError::NonZeroHeaderReserved);
    }
    if info.memory_map_entry_size as usize != size_of::<RawMemoryRegion>() {
        return Err(BootError::InvalidMemoryMapEntrySize(
            info.memory_map_entry_size,
        ));
    }
    if info.memory_map_count == 0 || info.memory_map_count as usize > MAX_MEMORY_MAP_ENTRIES {
        return Err(BootError::InvalidMemoryMapCount(info.memory_map_count));
    }
    if info.module_count as usize > MAX_MODULES {
        return Err(BootError::InvalidModuleCount(info.module_count));
    }
    if info.command_line_length as usize > MAX_COMMAND_LINE_BYTES {
        return Err(BootError::CommandLineTooLong(info.command_line_length));
    }
    Ok(())
}

unsafe fn populate_compat(
    info: &XenithBootInfo,
    storage: &mut CompatStorage,
) -> Result<(), BootError> {
    // SAFETY: caller upholds physical metadata readability.
    let memory_count = unsafe { copy_memory_map(info, storage)? };
    // SAFETY: caller upholds physical metadata readability.
    let module_count = unsafe { copy_modules(info, storage, memory_count)? };
    // SAFETY: caller upholds physical metadata readability.
    let command_line = unsafe { copy_command_line(info, storage)? };
    let framebuffer_count = copy_framebuffer(info.framebuffer, storage)?;
    validate_rsdp(info.rsdp)?;

    let framebuffer = if framebuffer_count == 0 {
        ptr::null()
    } else {
        storage.framebuffer_pointer[0] = ptr::addr_of!(storage.framebuffer);
        storage.framebuffer_pointer.as_ptr()
    };
    let modules = if module_count == 0 {
        ptr::null()
    } else {
        storage.modules.as_ptr()
    };

    storage.boot_info = limine::BootInfo {
        hhdm_offset: info.hhdm_offset,
        framebuffer,
        framebuffer_count,
        memmap: storage.memory_map.as_ptr(),
        memmap_count: memory_count as u64,
        modules,
        modules_count: module_count as u64,
        rsdp: info.rsdp,
        kernel_cmdline: command_line,
    };
    Ok(())
}

unsafe fn copy_memory_map(
    info: &XenithBootInfo,
    storage: &mut CompatStorage,
) -> Result<usize, BootError> {
    let input_count = info.memory_map_count as usize;
    let source = metadata_pointer(
        info.memory_map as u64,
        input_count,
        size_of::<RawMemoryRegion>(),
        align_of::<RawMemoryRegion>(),
        "memory map",
    )?;
    let mut output_count = 0;
    let mut previous_end = 0;

    for index in 0..input_count {
        // SAFETY: metadata_pointer validated the complete source array. The
        // raw mirror uses u32 for `kind`, avoiding invalid-enum UB.
        let entry = unsafe {
            ptr::read_unaligned(
                source
                    .add(index * size_of::<RawMemoryRegion>())
                    .cast::<RawMemoryRegion>(),
            )
        };
        if entry.reserved != 0 {
            return Err(BootError::NonZeroMemoryRegionReserved(index));
        }
        if entry.length == 0 {
            return Err(BootError::EmptyMemoryRegion(index));
        }
        let end = entry
            .base
            .checked_add(entry.length)
            .ok_or(BootError::MemoryRegionOverflow(index))?;
        if index != 0 && entry.base < previous_end {
            return Err(BootError::OverlappingMemoryRegion(index));
        }
        previous_end = end;
        let kind = limine_memory_kind(entry.kind).ok_or(BootError::InvalidMemoryKind {
            index,
            kind: entry.kind,
        })?;

        // Xenith's current loader page tables map the first 4 GiB. Hide high
        // physical regions from the allocator until a future loader extends
        // the initial HHDM, and clip a region that crosses the boundary.
        if entry.base >= TRANSITION_PHYSICAL_LIMIT {
            continue;
        }
        let mapped_end = end.min(TRANSITION_PHYSICAL_LIMIT);
        storage.memory_map[output_count] = limine::MemmapEntry {
            base: entry.base,
            length: mapped_end - entry.base,
            kind,
            reserved: 0,
        };
        output_count += 1;
    }

    if output_count == 0 {
        Err(BootError::NoTransitionMemory)
    } else {
        Ok(output_count)
    }
}

unsafe fn copy_modules(
    info: &XenithBootInfo,
    storage: &mut CompatStorage,
    memory_count: usize,
) -> Result<usize, BootError> {
    let count = info.module_count as usize;
    if count == 0 {
        return Ok(0);
    }
    let source = metadata_pointer(
        info.modules as u64,
        count,
        size_of::<XenithModule>(),
        align_of::<XenithModule>(),
        "module table",
    )?;

    for index in 0..count {
        // SAFETY: metadata_pointer validated the complete module table.
        let module = unsafe {
            ptr::read_unaligned(
                source
                    .add(index * size_of::<XenithModule>())
                    .cast::<XenithModule>(),
            )
        };
        if module.reserved != 0 {
            return Err(BootError::NonZeroModuleReserved(index));
        }
        if module.address == 0 || module.length == 0 {
            return Err(BootError::EmptyModule(index));
        }
        let end = module
            .address
            .checked_add(module.length)
            .ok_or(BootError::ModuleRangeOverflow(index))?;
        if end > TRANSITION_PHYSICAL_LIMIT {
            return Err(BootError::ModuleOutsideTransitionMap(index));
        }
        if overlaps_usable(module.address, end, &storage.memory_map[..memory_count]) {
            return Err(BootError::ModuleOverlapsUsableMemory(index));
        }

        let path_length = module.path_length as usize;
        if path_length > MAX_MODULE_PATH_BYTES {
            return Err(BootError::ModulePathTooLong {
                index,
                length: module.path_length,
            });
        }
        let path = &mut storage.module_paths[index];
        path[..=path_length].fill(0);
        if path_length != 0 {
            // SAFETY: caller upholds the physical path range; destination is a
            // distinct kernel-static buffer sized above the validated bound.
            unsafe {
                copy_metadata_bytes(module.path as u64, &mut path[..path_length], "module path")?
            };
            validate_text(&path[..path_length], "module path", index)?;
        }

        storage.modules[index] = limine::Module {
            base: module.address as *const u8,
            length: module.length,
            path: path.as_ptr().cast::<c_char>(),
            cmdline: ptr::null(),
        };
    }
    Ok(count)
}

unsafe fn copy_command_line(
    info: &XenithBootInfo,
    storage: &mut CompatStorage,
) -> Result<*const c_char, BootError> {
    let length = info.command_line_length as usize;
    if length == 0 {
        return Ok(ptr::null());
    }
    storage.command_line[..=length].fill(0);
    // SAFETY: caller upholds the physical command-line range; destination is
    // bounded kernel-static storage.
    unsafe {
        copy_metadata_bytes(
            info.command_line as u64,
            &mut storage.command_line[..length],
            "command line",
        )?
    };
    validate_text(&storage.command_line[..length], "command line", 0)?;
    Ok(storage.command_line.as_ptr().cast::<c_char>())
}

fn copy_framebuffer(
    framebuffer: XenithFramebuffer,
    storage: &mut CompatStorage,
) -> Result<u64, BootError> {
    if framebuffer.address == 0 {
        storage.framebuffer = EMPTY_FRAMEBUFFER;
        return Ok(0);
    }
    if framebuffer.width == 0
        || framebuffer.height == 0
        || framebuffer.pitch == 0
        || framebuffer.bpp == 0
    {
        return Err(BootError::InvalidFramebuffer("zero geometry"));
    }
    let width = u16::try_from(framebuffer.width)
        .map_err(|_| BootError::InvalidFramebuffer("width exceeds u16"))?;
    let height = u16::try_from(framebuffer.height)
        .map_err(|_| BootError::InvalidFramebuffer("height exceeds u16"))?;
    let pitch = u16::try_from(framebuffer.pitch)
        .map_err(|_| BootError::InvalidFramebuffer("pitch exceeds u16"))?;
    let row_bits = u64::from(framebuffer.width)
        .checked_mul(u64::from(framebuffer.bpp))
        .ok_or(BootError::InvalidFramebuffer("row size overflows"))?;
    let row_bytes = row_bits
        .checked_add(7)
        .ok_or(BootError::InvalidFramebuffer("row size overflows"))?
        / 8;
    if u64::from(framebuffer.pitch) < row_bytes {
        return Err(BootError::InvalidFramebuffer(
            "pitch is shorter than one row",
        ));
    }
    let byte_length = u64::from(framebuffer.pitch)
        .checked_mul(u64::from(framebuffer.height))
        .ok_or(BootError::InvalidFramebuffer("byte size overflows"))?;
    let byte_end = framebuffer
        .address
        .checked_add(byte_length)
        .ok_or(BootError::InvalidFramebuffer("byte range overflows"))?;
    if framebuffer.address < TRANSITION_PHYSICAL_LIMIT && byte_end > TRANSITION_PHYSICAL_LIMIT {
        return Err(BootError::InvalidFramebuffer(
            "range crosses the 4-GiB transition boundary",
        ));
    }
    validate_hhdm_payload(framebuffer.address, byte_length)
        .map_err(|_| BootError::InvalidFramebuffer("range exceeds the HHDM window"))?;

    storage.framebuffer = limine::Framebuffer {
        address: framebuffer.address as *mut u8,
        width,
        height,
        pitch,
        bpp: framebuffer.bpp,
    };
    Ok(1)
}

fn validate_rsdp(rsdp: u64) -> Result<(), BootError> {
    if rsdp == 0 {
        return Ok(());
    }
    let end = rsdp
        .checked_add(36)
        .ok_or(BootError::RsdpOutsideTransitionMap)?;
    if end > TRANSITION_PHYSICAL_LIMIT {
        Err(BootError::RsdpOutsideTransitionMap)
    } else {
        Ok(())
    }
}

fn metadata_pointer(
    physical: u64,
    count: usize,
    entry_size: usize,
    alignment: usize,
    field: &'static str,
) -> Result<*const u8, BootError> {
    if physical == 0 {
        return Err(BootError::NullMetadata(field));
    }
    if !(physical as usize).is_multiple_of(alignment) {
        return Err(BootError::MisalignedMetadata(field));
    }
    let byte_length = count
        .checked_mul(entry_size)
        .ok_or(BootError::MetadataSizeOverflow(field))?;
    let byte_length =
        u64::try_from(byte_length).map_err(|_| BootError::MetadataSizeOverflow(field))?;
    let end = physical
        .checked_add(byte_length)
        .ok_or(BootError::MetadataSizeOverflow(field))?;
    if end > TRANSITION_PHYSICAL_LIMIT {
        return Err(BootError::MetadataOutsideTransitionMap(field));
    }
    let virtual_address = XENITH_HHDM_OFFSET
        .checked_add(physical)
        .ok_or(BootError::MetadataOutsideTransitionMap(field))?;
    Ok(virtual_address as *const u8)
}

unsafe fn copy_metadata_bytes(
    physical: u64,
    destination: &mut [u8],
    field: &'static str,
) -> Result<(), BootError> {
    let source = metadata_pointer(physical, destination.len(), 1, 1, field)?;
    // SAFETY: metadata_pointer checked the mapped range; the caller guarantees
    // it is readable, and the kernel-static destination cannot overlap low
    // loader physical metadata.
    unsafe { ptr::copy_nonoverlapping(source, destination.as_mut_ptr(), destination.len()) };
    Ok(())
}

fn validate_hhdm_payload(physical: u64, length: u64) -> Result<(), ()> {
    if physical == 0 || length == 0 {
        return Err(());
    }
    let last = physical.checked_add(length - 1).ok_or(())?;
    XENITH_HHDM_OFFSET.checked_add(last).ok_or(())?;
    Ok(())
}

fn validate_text(bytes: &[u8], field: &'static str, index: usize) -> Result<(), BootError> {
    if bytes.contains(&0) {
        return Err(BootError::EmbeddedNul(field, index));
    }
    core::str::from_utf8(bytes)
        .map(|_| ())
        .map_err(|_| BootError::InvalidUtf8(field, index))
}

fn overlaps_usable(start: u64, end: u64, memory_map: &[limine::MemmapEntry]) -> bool {
    memory_map.iter().any(|region| {
        if region.kind != LIMINE_USABLE {
            return false;
        }
        let region_end = region.base + region.length;
        start < region_end && region.base < end
    })
}

const fn limine_memory_kind(kind: u32) -> Option<u32> {
    match kind {
        0 => Some(LIMINE_USABLE),
        1 => Some(LIMINE_RESERVED),
        2 => Some(LIMINE_ACPI_RECLAIMABLE),
        3 => Some(LIMINE_ACPI_NVS),
        4 => Some(LIMINE_BOOTLOADER_RECLAIMABLE),
        5 => Some(LIMINE_KERNEL_AND_MODULES),
        6 => Some(LIMINE_RESERVED),
        7 => Some(LIMINE_BAD_MEMORY),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> XenithBootInfo {
        let mut info = XenithBootInfo::empty();
        info.hhdm_offset = XENITH_HHDM_OFFSET;
        info.memory_map = 0x1000 as *const xenith_abi::XenithMemoryRegion;
        info.memory_map_count = 1;
        info
    }

    #[test]
    fn maps_every_xenith_memory_kind_without_reinterpreting_enum_bits() {
        assert_eq!(limine_memory_kind(0), Some(LIMINE_USABLE));
        assert_eq!(limine_memory_kind(1), Some(LIMINE_RESERVED));
        assert_eq!(limine_memory_kind(2), Some(LIMINE_ACPI_RECLAIMABLE));
        assert_eq!(limine_memory_kind(3), Some(LIMINE_ACPI_NVS));
        assert_eq!(limine_memory_kind(4), Some(LIMINE_BOOTLOADER_RECLAIMABLE));
        assert_eq!(limine_memory_kind(5), Some(LIMINE_KERNEL_AND_MODULES));
        assert_eq!(limine_memory_kind(6), Some(LIMINE_RESERVED));
        assert_eq!(limine_memory_kind(7), Some(LIMINE_BAD_MEMORY));
        assert_eq!(limine_memory_kind(8), None);
    }

    #[test]
    fn validates_versioned_header_and_fixed_hhdm() {
        let info = valid_header();
        assert_eq!(validate_header(&info), Ok(()));

        let mut wrong_version = info;
        wrong_version.version += 1;
        assert_eq!(
            validate_header(&wrong_version),
            Err(BootError::UnsupportedVersion(wrong_version.version))
        );

        let mut wrong_hhdm = info;
        wrong_hhdm.hhdm_offset = 0;
        assert_eq!(validate_header(&wrong_hhdm), Err(BootError::InvalidHhdm(0)));
    }

    #[test]
    fn bounds_metadata_to_transition_mapping() {
        assert_eq!(
            metadata_pointer(0x1000, 2, 24, 8, "test").map(|pointer| pointer as u64),
            Ok(XENITH_HHDM_OFFSET + 0x1000)
        );
        assert_eq!(
            metadata_pointer(0, 1, 24, 8, "test"),
            Err(BootError::NullMetadata("test"))
        );
        assert_eq!(
            metadata_pointer(0x1001, 1, 24, 8, "test"),
            Err(BootError::MisalignedMetadata("test"))
        );
        assert_eq!(
            metadata_pointer(TRANSITION_PHYSICAL_LIMIT - 8, 1, 24, 8, "test"),
            Err(BootError::MetadataOutsideTransitionMap("test"))
        );
    }

    #[test]
    fn framebuffer_conversion_rejects_lossy_geometry() {
        let mut storage = CompatStorage::empty();
        let valid = XenithFramebuffer {
            address: 0xe000_0000,
            pitch: 4096,
            width: 1024,
            height: 768,
            bpp: 32,
            red_shift: 16,
            red_size: 8,
            green_shift: 8,
            green_size: 8,
            blue_shift: 0,
            blue_size: 8,
        };
        assert_eq!(copy_framebuffer(valid, &mut storage), Ok(1));
        assert_eq!(storage.framebuffer.width, 1024);

        let mut too_wide = valid;
        too_wide.width = u32::from(u16::MAX) + 1;
        assert_eq!(
            copy_framebuffer(too_wide, &mut storage),
            Err(BootError::InvalidFramebuffer("width exceeds u16"))
        );
    }

    #[test]
    fn text_must_be_utf8_and_nul_free_before_c_string_conversion() {
        assert_eq!(validate_text(b"xenith.boot=uefi", "cmd", 0), Ok(()));
        assert_eq!(
            validate_text(b"bad\0tail", "cmd", 0),
            Err(BootError::EmbeddedNul("cmd", 0))
        );
        assert_eq!(
            validate_text(&[0xff], "cmd", 0),
            Err(BootError::InvalidUtf8("cmd", 0))
        );
    }
}
