//! Deterministic legacy-PC firmware shim for the packaged BIOS image.
//!
//! The main interpreter intentionally remains an x86-64 execution engine.  This
//! module models the small firmware boundary that precedes long mode: reset,
//! the BIOS boot-sector transfer, Xenith's INT 13h EDD reads, stage2 payload
//! preloading, E820/A20/VBE services, and the protected/long-mode transition.
//! It consumes and validates the actual stage1 and stage2 bytes from the disk;
//! it does not substitute a second host-side image format.

#[path = "firmware_exec.rs"]
pub(crate) mod firmware_exec;

use core::mem::size_of;
use std::fmt;

use xenith_boot_common::{
    append_region_with_reservations, fnv1a64, BootMemoryKind, DiskEntry, DiskEntryKind,
    DiskManifest, Elf64, ElfError as BootElfError, ManifestError, Reservation, XenithBootInfo,
    XenithMemoryRegion, XenithModule, HHDM_OFFSET, KERNEL_VIRTUAL_BASE,
};
use xenith_x86::Register;

use crate::cpu::Cpu;
use crate::firmware::firmware_exec::{execute_packaged_stages, StageExecError};
use crate::machine::ManifestBoot;
use crate::memory::{MemoryBus, MemoryError};

const SECTOR_SIZE: usize = 512;
const RESET_VECTOR: u64 = 0x000f_fff0;
const BIOS_ROM_BASE: u64 = 0x000f_0000;
const STAGE1_LOAD_ADDRESS: u64 = 0x0000_7c00;
const STAGE2_LOAD_ADDRESS: u64 = 0x0000_8000;
const PAGE_PML4: u64 = 0x1000;
const PAGE_PDPT_LOW: u64 = 0x2000;
const PAGE_PD0: u64 = 0x3000;
const PAGE_PD1: u64 = 0x4000;
const PAGE_PD3: u64 = 0x6000;
const PAGE_PDPT_HIGH: u64 = 0x7000;
const STACK_TOP: u64 = 0x0004_f000;
const KERNEL_ENTRY_STACK: u64 = STACK_TOP - 8;
const KERNEL_STAGING_ADDRESS: u64 = 0x0200_0000;
const KERNEL_STAGING_CAPACITY: u64 = 32 * 1024 * 1024;
const INITRD_LOAD_ADDRESS: u64 = 0x0600_0000;
const INITRD_CAPACITY: u64 = 64 * 1024 * 1024;
// Keep the semantic handoff in loader-reserved memory, clear of stage2's
// 0x50000 E820 array and its retired 0x70000 INT 13h bounce buffer.
const HANDOFF_INFO: u64 = 0x0005_1000;
const HANDOFF_MODULE: u64 = 0x0005_1100;
const HANDOFF_MODULE_PATH: u64 = 0x0005_1200;
const HANDOFF_COMMAND_LINE: u64 = 0x0005_1300;
const HANDOFF_MEMORY_MAP: u64 = 0x0005_2000;
const KERNEL_PHYSICAL_MIN: u64 = 0x0010_0000;
const KERNEL_PHYSICAL_LIMIT: u64 = KERNEL_STAGING_ADDRESS;
const BOOT_DRIVE: u8 = 0x80;

const RESET_STUB: [u8; 16] = [
    0xea, 0x00, 0x00, 0x00, 0xf0, // far jump f000:0000
    b'X', b'E', b'N', b'I', b'T', b'H', b'B', b'I', b'O', b'S', 0,
];

const EMPTY_REGION: XenithMemoryRegion = XenithMemoryRegion {
    base: 0,
    length: 0,
    kind: BootMemoryKind::Reserved,
    reserved: 0,
};

/// Structured failure from the deterministic BIOS shim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FirmwareError {
    Image(&'static str),
    Stage1(&'static str),
    Stage2(&'static str),
    Manifest(ManifestError),
    KernelElf(BootElfError),
    Memory(MemoryError),
    InsufficientMemory,
    KernelLayout,
    MemoryMapCapacity,
    StageExecution(StageExecError),
}

impl From<ManifestError> for FirmwareError {
    fn from(value: ManifestError) -> Self {
        Self::Manifest(value)
    }
}

impl From<BootElfError> for FirmwareError {
    fn from(value: BootElfError) -> Self {
        Self::KernelElf(value)
    }
}

impl From<MemoryError> for FirmwareError {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}

impl From<StageExecError> for FirmwareError {
    fn from(value: StageExecError) -> Self {
        Self::StageExecution(value)
    }
}

impl fmt::Display for FirmwareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for FirmwareError {}

/// Evidence retained from one complete reset-to-kernel BIOS-shim boot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BiosBootTrace {
    pub reset_vector: u64,
    pub boot_drive: u8,
    pub stage1_load_address: u64,
    pub stage1_checksum: u64,
    pub manifest_lba: u64,
    pub stage2_lba: u64,
    pub stage2_sectors: u64,
    pub stage2_load_address: u64,
    pub stage2_checksum: u64,
    pub stage1_instructions: u64,
    pub stage1_fetched_bytes: u64,
    pub stage1_execution_checksum: u64,
    pub stage2_instructions: u64,
    pub stage2_fetched_bytes: u64,
    pub stage2_execution_checksum: u64,
    pub bios_interrupts: u64,
    pub stage2_main_entry: u64,
    pub semantic_stage2_loader_fallback: bool,
    pub e820_entries: u32,
    pub a20_enabled: bool,
    pub protected_mode_entered: bool,
    pub long_mode_entered: bool,
    pub kernel_entry: u64,
    pub handoff_address: u64,
}

pub(crate) struct FirmwareBoot {
    pub manifest: ManifestBoot,
    pub trace: BiosBootTrace,
}

/// Execute Xenith's legacy boot contract up to the long-mode kernel entry.
pub(crate) fn boot_bios_image(
    bus: &mut MemoryBus,
    cpu: &mut Cpu,
    image: &[u8],
) -> Result<FirmwareBoot, FirmwareError> {
    if image.len() < 3 * SECTOR_SIZE || !image.len().is_multiple_of(SECTOR_SIZE) {
        return Err(FirmwareError::Image(
            "BIOS disk must contain sector-aligned stage1, manifest, and payloads",
        ));
    }

    install_reset_firmware(bus, cpu)?;
    let stage1 = image
        .get(..SECTOR_SIZE)
        .ok_or(FirmwareError::Image("missing MBR"))?;
    validate_stage1(stage1)?;
    bios_read(bus, image, 0, 1, STAGE1_LOAD_ADDRESS)?;
    let manifest_sector = image
        .get(SECTOR_SIZE..2 * SECTOR_SIZE)
        .ok_or(FirmwareError::Image("missing LBA1 manifest"))?;
    let manifest = DiskManifest::parse(manifest_sector)?;
    let expected_bytes = usize::try_from(manifest.image_sectors())
        .ok()
        .and_then(|sectors| sectors.checked_mul(SECTOR_SIZE))
        .ok_or(FirmwareError::Image("declared disk size overflow"))?;
    if expected_bytes != image.len() {
        return Err(FirmwareError::Image(
            "file length differs from manifest disk size",
        ));
    }

    let stage2_entry = manifest.find(DiskEntryKind::Stage2)?;
    let kernel_entry = manifest.find(DiskEntryKind::Kernel)?;
    let initrd_entry = manifest.find(DiskEntryKind::Initrd)?;
    let stage2 = payload(image, stage2_entry)?;
    let kernel = payload(image, kernel_entry)?;
    let initrd = payload(image, initrd_entry)?;
    stage2_entry.verify_payload(stage2)?;
    kernel_entry.verify_payload(kernel)?;
    initrd_entry.verify_payload(initrd)?;

    validate_stage2(stage2)?;

    // Fetch and execute the packaged boot instructions from guest RAM. Stage1
    // performs both EDD reads; stage2 performs E820/A20, constructs page
    // tables, and enters long mode. Unsupported instructions fail rather than
    // being skipped or inferred from a signature scan.
    let execution = execute_packaged_stages(bus, image)?;
    validate_executed_transition(bus, stage2, execution.stage2_main_entry)?;

    // The general x86-64 engine does not yet run arbitrary freestanding Rust
    // loaders before a Machine owns its ATA device. Keep the remaining
    // stage2_main payload/ELF work as an explicit semantic fallback; the exact
    // assembly entry and mode transition above are still executed bytewise.
    let (entry, handoff) =
        semantic_stage2_loader_fallback(bus, image, kernel, kernel_entry, initrd_entry)?;

    *cpu = Cpu::new();
    cpu.state.rip = entry;
    // The real stage2 calls the `extern "sysv64"` kernel entry. Preserve the
    // ABI-visible post-call stack shape even though this bounded semantic
    // handoff does not execute the final Rust indirect call itself.
    cpu.state.set_register(Register::Rsp, KERNEL_ENTRY_STACK);
    cpu.state.set_register(Register::Rbp, 0);
    cpu.state.set_register(Register::Rdi, handoff);
    cpu.state.cr3 = PAGE_PML4;
    cpu.state.cr4 = (1 << 5) | (1 << 7) | (1 << 9) | (1 << 10);
    cpu.state.cr0 = (1 << 31) | (1 << 4) | (1 << 1) | 1;
    cpu.state.efer = (1 << 10) | (1 << 8);
    cpu.state.cs = 0x18;
    cpu.state.ss = 0;
    cpu.state.ds = 0;
    cpu.state.es = 0;
    cpu.state.fs = 0;
    cpu.state.gs = 0;

    Ok(FirmwareBoot {
        manifest: ManifestBoot {
            kernel_lba: kernel_entry.start_lba,
            kernel_bytes: kernel_entry.byte_len,
            initrd_lba: initrd_entry.start_lba,
            initrd_bytes: initrd_entry.byte_len,
            disk_sectors: manifest.image_sectors(),
        },
        trace: BiosBootTrace {
            reset_vector: RESET_VECTOR,
            boot_drive: BOOT_DRIVE,
            stage1_load_address: STAGE1_LOAD_ADDRESS,
            stage1_checksum: fnv1a64(stage1),
            manifest_lba: 1,
            stage2_lba: stage2_entry.start_lba,
            stage2_sectors: stage2_entry.sector_count,
            stage2_load_address: STAGE2_LOAD_ADDRESS,
            stage2_checksum: fnv1a64(stage2),
            stage1_instructions: execution.stage1.instructions,
            stage1_fetched_bytes: execution.stage1.bytes,
            stage1_execution_checksum: execution.stage1.checksum,
            stage2_instructions: execution.stage2.instructions,
            stage2_fetched_bytes: execution.stage2.bytes,
            stage2_execution_checksum: execution.stage2.checksum,
            bios_interrupts: execution.bios_interrupts,
            stage2_main_entry: execution.stage2_main_entry,
            semantic_stage2_loader_fallback: true,
            e820_entries: execution.e820_entries,
            a20_enabled: execution.a20_enabled,
            protected_mode_entered: execution.protected_mode_entered,
            long_mode_entered: execution.long_mode_entered,
            kernel_entry: entry,
            handoff_address: handoff,
        },
    })
}

fn validate_executed_transition(
    bus: &mut MemoryBus,
    stage2: &[u8],
    stage2_main_entry: u64,
) -> Result<(), FirmwareError> {
    let stage2_end = STAGE2_LOAD_ADDRESS
        .checked_add(stage2.len() as u64)
        .ok_or(FirmwareError::Stage2("stage2 range overflow"))?;
    if !(STAGE2_LOAD_ADDRESS..stage2_end).contains(&stage2_main_entry) {
        return Err(FirmwareError::Stage2(
            "executed call target is outside packaged stage2",
        ));
    }
    for (address, expected) in [
        (PAGE_PML4, PAGE_PDPT_LOW | 3),
        (PAGE_PML4 + 256 * 8, PAGE_PDPT_LOW | 3),
        (PAGE_PML4 + 511 * 8, PAGE_PDPT_HIGH | 3),
        (PAGE_PDPT_LOW, PAGE_PD0 | 3),
        (PAGE_PDPT_HIGH + 511 * 8, PAGE_PD1 | 3),
        (PAGE_PD3 + 511 * 8, (2047 * 0x20_0000) | 0x83),
    ] {
        if bus.read_u64_physical(address)? != expected {
            return Err(FirmwareError::Stage2(
                "executed stage2 produced invalid page tables",
            ));
        }
    }
    Ok(())
}

fn semantic_stage2_loader_fallback(
    bus: &mut MemoryBus,
    image: &[u8],
    kernel: &[u8],
    kernel_entry: DiskEntry,
    initrd_entry: DiskEntry,
) -> Result<(u64, u64), FirmwareError> {
    load_stage2_payloads(bus, image, kernel_entry, initrd_entry)?;
    let (entry, kernel_span) = load_kernel_segments(bus, kernel)?;
    let handoff = install_handoff(bus, kernel_span, initrd_entry.byte_len)?;
    Ok((entry, handoff))
}

fn install_reset_firmware(bus: &mut MemoryBus, cpu: &mut Cpu) -> Result<(), FirmwareError> {
    bus.write_physical(RESET_VECTOR, &RESET_STUB)?;
    // A visible ROM marker makes reset state inspectable without silently
    // treating zero-filled RAM as firmware.
    bus.write_physical(BIOS_ROM_BASE, b"Xenith deterministic BIOS shim\0")?;
    *cpu = Cpu::new();
    cpu.state.cs = 0xf000;
    cpu.state.rip = 0xfff0;
    Ok(())
}

fn validate_stage1(stage1: &[u8]) -> Result<(), FirmwareError> {
    if stage1.len() != SECTOR_SIZE || stage1[510..512] != [0x55, 0xaa] {
        return Err(FirmwareError::Stage1("missing 0x55aa boot signature"));
    }
    for (needle, reason) in [
        (
            &[
                0xfa, 0x31, 0xc0, 0x8e, 0xd8, 0x8e, 0xc0, 0x8e, 0xd0, 0xbc, 0x00, 0x7c, 0xfc, 0xfb,
            ][..],
            "missing real-mode entry sequence",
        ),
        (
            &[0xbb, 0xaa, 0x55, 0xb4, 0x41, 0xcd, 0x13],
            "missing EDD probe",
        ),
        (
            &[0x58, 0x45, 0x4e, 0x49],
            "missing XENI manifest comparison",
        ),
        (
            &[0x54, 0x48, 0x49, 0x4d],
            "missing THIM manifest comparison",
        ),
        (&[0xea, 0x00, 0x80, 0x00, 0x00], "missing stage2 far jump"),
    ] {
        require_sequence(stage1, needle).map_err(|_| FirmwareError::Stage1(reason))?;
    }
    if occurrences(stage1, &[0xb4, 0x42, 0xcd, 0x13]) < 2 {
        return Err(FirmwareError::Stage1(
            "stage1 must issue manifest and stage2 EDD reads",
        ));
    }
    Ok(())
}

fn validate_stage2(stage2: &[u8]) -> Result<(), FirmwareError> {
    for (needle, reason) in [
        (
            &[
                0xfa, 0x31, 0xc0, 0x8e, 0xd8, 0x8e, 0xc0, 0x8e, 0xd0, 0x66, 0xbc, 0x00, 0x7c, 0x00,
                0x00,
            ][..],
            "missing real-mode entry sequence",
        ),
        (
            &[
                0x66, 0xb8, 0x20, 0xe8, 0x00, 0x00, 0x66, 0xba, 0x50, 0x41, 0x4d, 0x53,
            ],
            "missing E820 request",
        ),
        (
            &[
                0xb8, 0x01, 0x24, 0xcd, 0x15, 0xe4, 0x92, 0x0c, 0x02, 0x24, 0xfe, 0xe6, 0x92,
            ],
            "missing A20 activation",
        ),
        (
            &[
                0xbf, 0x00, 0x10, 0x00, 0x00, 0xb9, 0x00, 0x1c, 0x00, 0x00, 0xf3, 0xab,
            ],
            "missing page-table initialization",
        ),
        (
            &[0xb9, 0x80, 0x00, 0x00, 0xc0, 0x0f, 0x32],
            "missing EFER transition",
        ),
        (
            &[
                0x0f, 0x22, 0xd8, 0x0f, 0x20, 0xc0, 0x0d, 0x00, 0x00, 0x00, 0x80, 0x0f, 0x22, 0xc0,
            ],
            "missing paging enable",
        ),
    ] {
        require_sequence(stage2, needle).map_err(|_| FirmwareError::Stage2(reason))?;
    }
    Ok(())
}

fn require_sequence(haystack: &[u8], needle: &[u8]) -> Result<(), ()> {
    if !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
    {
        Ok(())
    } else {
        Err(())
    }
}

fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn bios_read(
    bus: &mut MemoryBus,
    image: &[u8],
    lba: u64,
    sectors: u64,
    destination: u64,
) -> Result<(), FirmwareError> {
    let start = usize::try_from(lba)
        .ok()
        .and_then(|value| value.checked_mul(SECTOR_SIZE))
        .ok_or(FirmwareError::Image("EDD LBA offset overflow"))?;
    let length = usize::try_from(sectors)
        .ok()
        .and_then(|value| value.checked_mul(SECTOR_SIZE))
        .ok_or(FirmwareError::Image("EDD transfer length overflow"))?;
    let bytes = image
        .get(start..start.saturating_add(length))
        .ok_or(FirmwareError::Image("EDD transfer exceeds disk"))?;
    bus.write_physical(destination, bytes)?;
    Ok(())
}

fn payload(image: &[u8], entry: DiskEntry) -> Result<&[u8], FirmwareError> {
    let start = usize::try_from(entry.start_lba)
        .ok()
        .and_then(|value| value.checked_mul(SECTOR_SIZE))
        .ok_or(FirmwareError::Image("manifest payload offset overflow"))?;
    let length = usize::try_from(entry.byte_len)
        .map_err(|_| FirmwareError::Image("manifest payload length overflow"))?;
    image
        .get(start..start.saturating_add(length))
        .ok_or(FirmwareError::Image("manifest payload exceeds disk"))
}

fn load_stage2_payloads(
    bus: &mut MemoryBus,
    image: &[u8],
    kernel_entry: DiskEntry,
    initrd_entry: DiskEntry,
) -> Result<(), FirmwareError> {
    if kernel_entry.byte_len > KERNEL_STAGING_CAPACITY || initrd_entry.byte_len > INITRD_CAPACITY {
        return Err(FirmwareError::InsufficientMemory);
    }
    let kernel_sector_bytes = sector_extent(kernel_entry)?;
    let initrd_sector_bytes = sector_extent(initrd_entry)?;
    if KERNEL_STAGING_ADDRESS
        .checked_add(kernel_sector_bytes)
        .is_none_or(|end| end > bus.len() as u64)
        || INITRD_LOAD_ADDRESS
            .checked_add(initrd_sector_bytes)
            .is_none_or(|end| end > bus.len() as u64)
    {
        return Err(FirmwareError::InsufficientMemory);
    }
    let kernel_extent = payload_extent(image, kernel_entry)?;
    let initrd_extent = payload_extent(image, initrd_entry)?;
    bus.write_physical(KERNEL_STAGING_ADDRESS, kernel_extent)?;
    bus.write_physical(INITRD_LOAD_ADDRESS, initrd_extent)?;
    Ok(())
}

fn payload_extent(image: &[u8], entry: DiskEntry) -> Result<&[u8], FirmwareError> {
    let start = usize::try_from(entry.start_lba)
        .ok()
        .and_then(|value| value.checked_mul(SECTOR_SIZE))
        .ok_or(FirmwareError::Image("payload extent offset overflow"))?;
    let length = usize::try_from(sector_extent(entry)?)
        .map_err(|_| FirmwareError::Image("payload extent length overflow"))?;
    image
        .get(start..start.saturating_add(length))
        .ok_or(FirmwareError::Image("payload extent exceeds disk"))
}

fn sector_extent(entry: DiskEntry) -> Result<u64, FirmwareError> {
    entry
        .sector_count
        .checked_mul(SECTOR_SIZE as u64)
        .ok_or(FirmwareError::Image("payload sector extent overflow"))
}

fn load_kernel_segments(
    bus: &mut MemoryBus,
    kernel: &[u8],
) -> Result<(u64, (u64, u64)), FirmwareError> {
    let elf = Elf64::parse(kernel)?;
    let span = elf.physical_span()?;
    if span.0 < KERNEL_PHYSICAL_MIN || span.1 > KERNEL_PHYSICAL_LIMIT {
        return Err(FirmwareError::KernelLayout);
    }
    for segment in elf.load_segments() {
        let segment = segment?;
        let conventional_high = segment.virtual_address.checked_sub(KERNEL_VIRTUAL_BASE)
            == Some(segment.physical_address);
        if segment.virtual_address != segment.physical_address && !conventional_high {
            return Err(FirmwareError::KernelLayout);
        }
        let source = segment.file_bytes(kernel)?;
        let memory_size =
            usize::try_from(segment.memory_size).map_err(|_| FirmwareError::KernelLayout)?;
        bus.write_physical(segment.physical_address, source)?;
        let zero_count = memory_size
            .checked_sub(source.len())
            .ok_or(FirmwareError::KernelLayout)?;
        if zero_count != 0 {
            let zero_start = segment
                .physical_address
                .checked_add(source.len() as u64)
                .ok_or(FirmwareError::KernelLayout)?;
            write_zeroes(bus, zero_start, zero_count)?;
        }
    }
    Ok((elf.entry(), span))
}

fn install_handoff(
    bus: &mut MemoryBus,
    kernel_span: (u64, u64),
    initrd_length: u64,
) -> Result<u64, FirmwareError> {
    let memory_end = bus.len() as u64;
    let reservations = [
        // Match native stage2: the entire first MiB stays loader-reserved.
        // In particular, the retired 0x70000 bounce page is never allocator
        // owned and is available only through the BIOS startup contract.
        Reservation::new(0, 0x0010_0000, BootMemoryKind::Reserved),
        Reservation::new(
            kernel_span.0,
            kernel_span.1 - kernel_span.0,
            BootMemoryKind::KernelAndModules,
        ),
        Reservation::new(
            KERNEL_STAGING_ADDRESS,
            KERNEL_STAGING_CAPACITY,
            BootMemoryKind::BootloaderReclaimable,
        ),
        Reservation::new(
            INITRD_LOAD_ADDRESS,
            initrd_length,
            BootMemoryKind::KernelAndModules,
        ),
    ];
    let mut map = [EMPTY_REGION; 32];
    let mut used = 0;
    append_region_with_reservations(
        &mut map,
        &mut used,
        0,
        0x0010_0000,
        BootMemoryKind::Usable,
        &reservations,
    )
    .map_err(|_| FirmwareError::MemoryMapCapacity)?;
    append_region_with_reservations(
        &mut map,
        &mut used,
        0x0010_0000,
        memory_end - 0x0010_0000,
        BootMemoryKind::Usable,
        &reservations,
    )
    .map_err(|_| FirmwareError::MemoryMapCapacity)?;

    let path = b"/initrd.cpio";
    let command_line = b"xenith.boot=bios";
    bus.write_physical(HANDOFF_MODULE_PATH, path)?;
    bus.write_physical(HANDOFF_COMMAND_LINE, command_line)?;
    write_slice(bus, HANDOFF_MEMORY_MAP, &map[..used])?;
    let module = XenithModule {
        address: INITRD_LOAD_ADDRESS,
        length: initrd_length,
        path: HANDOFF_MODULE_PATH as *const u8,
        path_length: path.len() as u32,
        reserved: 0,
    };
    write_value(bus, HANDOFF_MODULE, &module)?;
    let mut boot_info = XenithBootInfo::empty();
    boot_info.hhdm_offset = HHDM_OFFSET;
    boot_info.memory_map = HANDOFF_MEMORY_MAP as *const XenithMemoryRegion;
    boot_info.memory_map_count = used as u32;
    boot_info.modules = HANDOFF_MODULE as *const XenithModule;
    boot_info.module_count = 1;
    boot_info.command_line = HANDOFF_COMMAND_LINE as *const u8;
    boot_info.command_line_length = command_line.len() as u32;
    write_value(bus, HANDOFF_INFO, &boot_info)?;
    Ok(HANDOFF_INFO)
}

fn write_zeroes(
    bus: &mut MemoryBus,
    mut address: u64,
    mut length: usize,
) -> Result<(), FirmwareError> {
    let zeroes = [0_u8; 4096];
    while length != 0 {
        let count = length.min(zeroes.len());
        bus.write_physical(address, &zeroes[..count])?;
        address = address
            .checked_add(count as u64)
            .ok_or(FirmwareError::KernelLayout)?;
        length -= count;
    }
    Ok(())
}

fn write_value<T: Copy>(bus: &mut MemoryBus, address: u64, value: &T) -> Result<(), FirmwareError> {
    // SAFETY: `value` is readable for its complete object representation.
    let bytes = unsafe {
        core::slice::from_raw_parts(core::ptr::from_ref(value).cast::<u8>(), size_of::<T>())
    };
    bus.write_physical(address, bytes)?;
    Ok(())
}

fn write_slice<T: Copy>(
    bus: &mut MemoryBus,
    address: u64,
    values: &[T],
) -> Result<(), FirmwareError> {
    // SAFETY: a slice is contiguous for exactly `size_of_val(values)` bytes.
    let bytes = unsafe {
        core::slice::from_raw_parts(values.as_ptr().cast::<u8>(), core::mem::size_of_val(values))
    };
    bus.write_physical(address, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_stub_lands_at_the_architectural_vector() {
        let mut bus = MemoryBus::new(2 * 1024 * 1024);
        let mut cpu = Cpu::new();
        install_reset_firmware(&mut bus, &mut cpu).unwrap();
        let mut bytes = [0_u8; 16];
        bus.read_physical(RESET_VECTOR, &mut bytes).unwrap();
        assert_eq!(bytes, RESET_STUB);
        assert_eq!(cpu.state.cs, 0xf000);
        assert_eq!(cpu.state.rip, 0xfff0);
    }

    #[test]
    fn stage_contract_search_is_bounded_and_exact() {
        assert_eq!(require_sequence(b"abc123", b"c12"), Ok(()));
        assert_eq!(require_sequence(b"abc123", b"c13"), Err(()));
        assert_eq!(occurrences(b"ababab", b"ab"), 3);
        assert_eq!(occurrences(b"abc", b""), 0);
    }

    #[test]
    fn stage1_rejects_a_signature_only_sector() {
        let mut sector = [0_u8; 512];
        sector[510..].copy_from_slice(&[0x55, 0xaa]);
        assert_eq!(
            validate_stage1(&sector),
            Err(FirmwareError::Stage1("missing real-mode entry sequence"))
        );
    }
}
