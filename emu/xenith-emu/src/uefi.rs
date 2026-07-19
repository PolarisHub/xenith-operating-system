//! Deterministic execution environment for Xenith's packaged UEFI application.
//!
//! This is not arbitrary UEFI firmware. It selects the platform-0xEF El
//! Torito entry from the actual ISO, parses its FAT16 ESP, loads the real
//! `BOOTX64.EFI` PE image, and executes that image through the ordinary
//! long-mode interpreter. Only the services and protocols reached by Xenith's
//! loader are implemented. Every other service address and every unsupported
//! instruction fails closed.

use std::collections::BTreeMap;
use std::fmt;

use xenith_boot_common::{fnv1a64, Elf64, ElfError as BootElfError, XENITH_BOOT_MAGIC};
use xenith_iso::{
    extract_efi_system_partition_files, extract_el_torito_boot_images, EfiSystemPartitionFiles,
    ImageError,
};
use xenith_x86::{decode, DecodeErrorKind, Register};

use crate::cpu::{Cpu, CpuFault, ExitReason};
use crate::firmware::firmware_exec::{
    execute_packaged_stages, StageExecError, StageExecutionTrace,
};
use crate::memory::{Access, MemoryBus, MemoryError, PagingContext, Privilege};

const PAGE_SIZE: u64 = 4096;
const INITIAL_PML4: u64 = 0x1000;
const INITIAL_PDPT: u64 = 0x2000;
const INITIAL_PD: u64 = 0x3000;
const FIRMWARE_BASE: u64 = 0x0010_0000;
const FIRMWARE_END: u64 = 0x0012_0000;
const STUB_BASE: u64 = FIRMWARE_BASE + 0x1000;
const SYSTEM_TABLE: u64 = FIRMWARE_BASE + 0x3000;
const BOOT_SERVICES: u64 = FIRMWARE_BASE + 0x3100;
const CONFIGURATION_TABLE: u64 = FIRMWARE_BASE + 0x3300;
const LOADED_IMAGE: u64 = FIRMWARE_BASE + 0x3400;
const SIMPLE_FILE_SYSTEM: u64 = FIRMWARE_BASE + 0x3500;
const ROOT_FILE: u64 = FIRMWARE_BASE + 0x3600;
const GOP: u64 = FIRMWARE_BASE + 0x3700;
const GOP_MODE: u64 = FIRMWARE_BASE + 0x3740;
const GOP_MODE_INFO: u64 = FIRMWARE_BASE + 0x3780;
const TEXT_OUTPUT: u64 = FIRMWARE_BASE + 0x3800;
const FILE_HANDLE_BASE: u64 = FIRMWARE_BASE + 0x4000;
const FILE_HANDLE_STRIDE: u64 = 0x100;
const PE_LOAD_BASE: u64 = 0x0100_0000;
const UEFI_STACK_BASE: u64 = 0x0180_0000;
const UEFI_STACK_SIZE: u64 = 0x0010_0000;
const ALLOCATION_FLOOR: u64 = 0x0200_0000;
const RETURN_SENTINEL: u64 = FIRMWARE_BASE + 0x20;
const IMAGE_HANDLE: u64 = 0x5845_4e49_5448_0001;
const DEVICE_HANDLE: u64 = 0x5845_4e49_5448_0002;
const RSDP_ADDRESS: u64 = 0x000e_0000;
const MAX_PE_IMAGE_SIZE: u64 = 4 * 1024 * 1024;
const MAX_UEFI_INSTRUCTIONS: u64 = 20_000_000;
const BIOS_SCRATCH_MEMORY: usize = 128 * 1024 * 1024;
const MEMORY_DESCRIPTOR_SIZE: usize = 40;
const FILE_INFO_SIZE: usize = 80;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

const SUCCESS: u64 = 0;
const ERROR_BIT: u64 = 1 << 63;
const INVALID_PARAMETER: u64 = ERROR_BIT | 2;
const BUFFER_TOO_SMALL: u64 = ERROR_BIT | 5;
const ALLOCATE_MAX_ADDRESS: u64 = 1;
const LOADER_DATA: u64 = 2;
const FILE_MODE_READ: u64 = 1;

const LOADED_IMAGE_GUID: [u8; 16] = [
    0xa1, 0x31, 0x1b, 0x5b, 0x62, 0x95, 0xd2, 0x11, 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
];
const SIMPLE_FILE_SYSTEM_GUID: [u8; 16] = [
    0x22, 0x5b, 0x4e, 0x96, 0x59, 0x64, 0xd2, 0x11, 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
];
const FILE_INFO_GUID: [u8; 16] = [
    0x92, 0x6e, 0x57, 0x09, 0x3f, 0x6d, 0xd2, 0x11, 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
];
const GOP_GUID: [u8; 16] = [
    0xde, 0xa9, 0x42, 0x90, 0xdc, 0x23, 0x38, 0x4a, 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a,
];
const ACPI_20_GUID: [u8; 16] = [
    0x71, 0xe8, 0x68, 0x88, 0xf1, 0xe4, 0xd3, 0x11, 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81,
];

/// Exact service-call counts retained from execution of `BOOTX64.EFI`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UefiServiceCalls {
    pub allocate_pages: u64,
    pub free_pages: u64,
    pub get_memory_map: u64,
    pub handle_protocol: u64,
    pub locate_protocol: u64,
    pub open_volume: u64,
    pub file_open: u64,
    pub file_close: u64,
    pub file_read: u64,
    pub file_get_info: u64,
    pub output_string: u64,
    pub exit_boot_services: u64,
}

/// Evidence from ISO catalog selection, PE execution, service dispatch, and
/// the resulting native Xenith handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UefiIsoBootTrace {
    pub boot_catalog_lba: u32,
    pub bios_image_lba: u32,
    pub efi_image_lba: u32,
    pub efi_load_sectors: u16,
    pub esp_checksum: u64,
    pub bootx64_checksum: u64,
    pub kernel_checksum: u64,
    pub initrd_checksum: u64,
    pub preferred_image_base: u64,
    pub image_load_base: u64,
    pub image_entry: u64,
    pub pe_instructions: u64,
    pub pe_fetched_bytes: u64,
    pub pe_execution_checksum: u64,
    pub services: UefiServiceCalls,
    pub bios_stage1_instructions: u64,
    pub bios_stage1_execution_checksum: u64,
    pub bios_stage2_instructions: u64,
    pub bios_stage2_execution_checksum: u64,
    pub bios_catalog_exact_stage_execution: bool,
    pub boot_services_exited: bool,
    pub semantic_loader_fallback: bool,
    pub gop_framebuffer: u64,
    pub gop_width: u16,
    pub gop_height: u16,
    pub gop_pitch: u16,
    pub rsdp: u64,
    pub kernel_entry: u64,
    pub handoff_address: u64,
    pub final_cr3: u64,
}

#[derive(Debug)]
pub enum UefiError {
    Iso(ImageError),
    Pe(&'static str),
    KernelElf(BootElfError),
    Memory(MemoryError),
    Cpu(CpuFault),
    BiosStage(StageExecError),
    InsufficientMemory,
    ExecutionLimit,
    UnsupportedService(u64),
    InvalidServiceCall(&'static str),
    LoaderReturned { status: u64, output: String },
    InvalidHandoff(&'static str),
}

impl From<ImageError> for UefiError {
    fn from(value: ImageError) -> Self {
        Self::Iso(value)
    }
}

impl From<BootElfError> for UefiError {
    fn from(value: BootElfError) -> Self {
        Self::KernelElf(value)
    }
}

impl From<MemoryError> for UefiError {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}

impl From<CpuFault> for UefiError {
    fn from(value: CpuFault) -> Self {
        Self::Cpu(value)
    }
}

impl From<StageExecError> for UefiError {
    fn from(value: StageExecError) -> Self {
        Self::BiosStage(value)
    }
}

impl fmt::Display for UefiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for UefiError {}

pub(crate) struct UefiBoot {
    pub trace: UefiIsoBootTrace,
    pub framebuffer: UefiFramebuffer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UefiFramebuffer {
    pub physical: u64,
    pub width: u16,
    pub height: u16,
    pub pitch: u16,
}

/// Boots the platform-0xEF entry of one packaged Xenith ISO to the first
/// kernel instruction. The caller then continues with the normal Machine
/// execution loop.
pub(crate) fn boot_uefi_iso(
    bus: &mut MemoryBus,
    cpu: &mut Cpu,
    iso: &[u8],
    framebuffer_width: u16,
    framebuffer_height: u16,
) -> Result<UefiBoot, UefiError> {
    let images = extract_el_torito_boot_images(iso)?;
    let files = extract_efi_system_partition_files(images.efi_system_partition)?;
    let bios_execution = execute_bios_catalog_entry(images.bios_disk)?;
    let kernel_entry = Elf64::parse(&files.kernel)?.entry();
    let pe = PeImage::parse(&files.bootx64)?;
    pe.load(bus)?;
    install_initial_page_tables(bus)?;

    let mut environment = UefiEnvironment::new(
        files,
        bus.len() as u64,
        framebuffer_width,
        framebuffer_height,
    )?;
    environment.install(bus, &pe)?;
    prepare_cpu(cpu, bus, pe.entry())?;

    let mut fetch = FetchEvidence::new();
    for _ in 0..MAX_UEFI_INSTRUCTIONS {
        if environment.exited && cpu.state.rip == kernel_entry {
            let handoff = cpu.state.register(Register::Rdi);
            validate_handoff(bus, cpu, handoff)?;
            let framebuffer = environment.framebuffer;
            return Ok(UefiBoot {
                trace: UefiIsoBootTrace {
                    boot_catalog_lba: images.boot_catalog_lba,
                    bios_image_lba: images.bios_image_lba,
                    efi_image_lba: images.efi_image_lba,
                    efi_load_sectors: images.efi_load_sectors,
                    esp_checksum: fnv1a64(images.efi_system_partition),
                    bootx64_checksum: fnv1a64(&environment.files.bootx64),
                    kernel_checksum: fnv1a64(&environment.files.kernel),
                    initrd_checksum: fnv1a64(&environment.files.initrd),
                    preferred_image_base: pe.preferred_base,
                    image_load_base: PE_LOAD_BASE,
                    image_entry: pe.entry(),
                    pe_instructions: fetch.instructions,
                    pe_fetched_bytes: fetch.bytes,
                    pe_execution_checksum: fetch.checksum,
                    services: environment.calls,
                    bios_stage1_instructions: bios_execution.stage1.instructions,
                    bios_stage1_execution_checksum: bios_execution.stage1.checksum,
                    bios_stage2_instructions: bios_execution.stage2.instructions,
                    bios_stage2_execution_checksum: bios_execution.stage2.checksum,
                    bios_catalog_exact_stage_execution: true,
                    boot_services_exited: true,
                    semantic_loader_fallback: false,
                    gop_framebuffer: framebuffer.physical,
                    gop_width: framebuffer.width,
                    gop_height: framebuffer.height,
                    gop_pitch: framebuffer.pitch,
                    rsdp: RSDP_ADDRESS,
                    kernel_entry,
                    handoff_address: handoff,
                    final_cr3: cpu.state.cr3,
                },
                framebuffer,
            });
        }
        if cpu.state.rip == RETURN_SENTINEL {
            return Err(UefiError::LoaderReturned {
                status: cpu.state.register(Register::Rax),
                output: environment.output.clone(),
            });
        }

        let fetched = if pe.contains(cpu.state.rip) {
            Some(fetch_instruction(bus, cpu)?)
        } else {
            None
        };
        let reason = cpu.step(bus)?;
        if let Some(bytes) = fetched {
            fetch.record(&bytes);
        }
        match reason {
            None => {},
            Some(ExitReason::Breakpoint(address)) => {
                environment.dispatch(address, cpu, bus)?;
            },
            Some(ExitReason::Halted) => {
                return Err(UefiError::InvalidHandoff(
                    "UEFI loader halted before kernel entry",
                ));
            },
            Some(ExitReason::Fault(fault)) => return Err(UefiError::Cpu(fault)),
            Some(ExitReason::InstructionLimit) => unreachable!("Cpu::step has no limit"),
        }
    }
    Err(UefiError::ExecutionLimit)
}

fn execute_bios_catalog_entry(image: &[u8]) -> Result<StageExecutionTrace, UefiError> {
    let stage1 = image
        .get(..512)
        .ok_or(UefiError::InvalidHandoff("BIOS catalog image has no MBR"))?;
    let mut bus = MemoryBus::new(BIOS_SCRATCH_MEMORY);
    bus.write_physical(0x7c00, stage1)?;
    execute_packaged_stages(&mut bus, image).map_err(UefiError::from)
}

fn prepare_cpu(cpu: &mut Cpu, bus: &mut MemoryBus, entry: u64) -> Result<(), UefiError> {
    cpu.state.rip = entry;
    cpu.state.set_register(Register::Rcx, IMAGE_HANDLE);
    cpu.state.set_register(Register::Rdx, SYSTEM_TABLE);
    cpu.state.set_register(Register::R8, 0);
    cpu.state.set_register(Register::R9, 0);
    cpu.state.cr3 = INITIAL_PML4;
    cpu.state.cr4 = 1 << 5;
    cpu.state.cr0 = (1 << 31) | (1 << 16) | (1 << 5) | 1;
    cpu.state.efer = (1 << 11) | (1 << 10) | (1 << 8);
    cpu.state.cs = 0x08;
    cpu.state.ss = 0x10;
    cpu.state.ds = 0x10;
    cpu.state.es = 0x10;
    cpu.state.fs = 0;
    cpu.state.gs = 0;
    cpu.state.rflags = 2;
    cpu.state.halted = false;
    let stack = UEFI_STACK_BASE + UEFI_STACK_SIZE - 8;
    bus.write_u64_physical(stack, RETURN_SENTINEL)?;
    cpu.state.set_register(Register::Rsp, stack);
    Ok(())
}

fn install_initial_page_tables(bus: &mut MemoryBus) -> Result<(), UefiError> {
    write_zeroes(bus, INITIAL_PML4, 0x4000)?;
    bus.write_u64_physical(INITIAL_PML4, INITIAL_PDPT | 3)?;
    bus.write_u64_physical(INITIAL_PML4 + 256 * 8, INITIAL_PDPT | 3)?;
    bus.write_u64_physical(INITIAL_PDPT, INITIAL_PD | 3)?;
    for index in 0..512_u64 {
        bus.write_u64_physical(INITIAL_PD + index * 8, (index * 0x20_0000) | 0x83)?;
    }
    Ok(())
}

fn validate_handoff(bus: &mut MemoryBus, cpu: &Cpu, address: u64) -> Result<(), UefiError> {
    if address == 0 {
        return Err(UefiError::InvalidHandoff(
            "BOOTX64.EFI produced a null handoff",
        ));
    }
    let mut magic = [0_u8; 8];
    bus.read_linear(address, &mut magic, paging_context(cpu), Access::Read)?;
    if u64::from_le_bytes(magic) != XENITH_BOOT_MAGIC {
        return Err(UefiError::InvalidHandoff(
            "BOOTX64.EFI produced a non-Xenith handoff",
        ));
    }
    Ok(())
}

fn paging_context(cpu: &Cpu) -> PagingContext {
    PagingContext::new(
        cpu.state.cr0,
        cpu.state.cr3,
        cpu.state.efer,
        Privilege::Supervisor,
    )
}

fn fetch_instruction(bus: &mut MemoryBus, cpu: &Cpu) -> Result<Vec<u8>, UefiError> {
    let mut bytes = [0_u8; 15];
    for loaded in 1..=bytes.len() {
        bus.read_linear(
            cpu.state.rip + (loaded - 1) as u64,
            &mut bytes[loaded - 1..loaded],
            paging_context(cpu),
            Access::Execute,
        )?;
        match decode(&bytes[..loaded]) {
            Ok(instruction) => return Ok(bytes[..usize::from(instruction.length)].to_vec()),
            Err(error) if error.kind == DecodeErrorKind::Truncated && loaded < bytes.len() => {},
            Err(error) => {
                return Err(UefiError::Cpu(CpuFault::Decode {
                    rip: cpu.state.rip,
                    error,
                }));
            },
        }
    }
    unreachable!("15-byte decode loop always returns")
}

struct FetchEvidence {
    instructions: u64,
    bytes: u64,
    checksum: u64,
}

impl FetchEvidence {
    const fn new() -> Self {
        Self {
            instructions: 0,
            bytes: 0,
            checksum: FNV_OFFSET,
        }
    }

    fn record(&mut self, bytes: &[u8]) {
        self.instructions += 1;
        self.bytes += bytes.len() as u64;
        for byte in bytes {
            self.checksum ^= u64::from(*byte);
            self.checksum = self.checksum.wrapping_mul(FNV_PRIME);
        }
    }
}

struct PeImage {
    preferred_base: u64,
    entry_rva: u32,
    image_size: u32,
    headers_size: u32,
    sections: Vec<PeSection>,
    bytes: Vec<u8>,
}

struct PeSection {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
}

impl PeImage {
    fn parse(bytes: &[u8]) -> Result<Self, UefiError> {
        if bytes.len() < 0x100 || &bytes[..2] != b"MZ" {
            return Err(UefiError::Pe("BOOTX64.EFI has no DOS header"));
        }
        let pe_offset = read_u32_slice(bytes, 0x3c)? as usize;
        if bytes.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
            return Err(UefiError::Pe("BOOTX64.EFI has no PE signature"));
        }
        let coff = pe_offset + 4;
        if read_u16_slice(bytes, coff)? != 0x8664 {
            return Err(UefiError::Pe("BOOTX64.EFI is not AMD64"));
        }
        let section_count = usize::from(read_u16_slice(bytes, coff + 2)?);
        if !(1..=16).contains(&section_count) {
            return Err(UefiError::Pe("BOOTX64.EFI section count is unsupported"));
        }
        let optional_size = usize::from(read_u16_slice(bytes, coff + 16)?);
        if optional_size < 240 {
            return Err(UefiError::Pe("BOOTX64.EFI optional header is truncated"));
        }
        let optional = coff + 20;
        checked_slice(bytes, optional, optional_size)?;
        if read_u16_slice(bytes, optional)? != 0x20b {
            return Err(UefiError::Pe("BOOTX64.EFI is not PE32+"));
        }
        if read_u16_slice(bytes, optional + 68)? != 10 {
            return Err(UefiError::Pe("BOOTX64.EFI is not an EFI application"));
        }
        if read_u32_slice(bytes, optional + 32)? != 4096
            || read_u32_slice(bytes, optional + 36)? != 512
        {
            return Err(UefiError::Pe("BOOTX64.EFI alignment is unsupported"));
        }
        let entry_rva = read_u32_slice(bytes, optional + 16)?;
        let preferred_base = read_u64_slice(bytes, optional + 24)?;
        let image_size = read_u32_slice(bytes, optional + 56)?;
        let headers_size = read_u32_slice(bytes, optional + 60)?;
        if image_size == 0
            || u64::from(image_size) > MAX_PE_IMAGE_SIZE
            || entry_rva >= image_size
            || headers_size > image_size
            || headers_size as usize > bytes.len()
        {
            return Err(UefiError::Pe("BOOTX64.EFI image bounds are invalid"));
        }
        if read_u32_slice(bytes, optional + 108)? < 16 {
            return Err(UefiError::Pe("BOOTX64.EFI data directories are incomplete"));
        }
        let import_rva = read_u32_slice(bytes, optional + 120)?;
        let import_size = read_u32_slice(bytes, optional + 124)?;
        let reloc_rva = read_u32_slice(bytes, optional + 152)?;
        let reloc_size = read_u32_slice(bytes, optional + 156)?;
        if import_rva != 0 || import_size != 0 {
            return Err(UefiError::Pe("BOOTX64.EFI imports are unsupported"));
        }
        if reloc_rva != 0 || reloc_size != 0 {
            return Err(UefiError::Pe("BOOTX64.EFI relocations are unsupported"));
        }

        let section_table = optional + optional_size;
        checked_slice(bytes, section_table, section_count * 40)?;
        let mut sections = Vec::with_capacity(section_count);
        let mut entry_executable = false;
        for index in 0..section_count {
            let offset = section_table + index * 40;
            let section = PeSection {
                virtual_size: read_u32_slice(bytes, offset + 8)?,
                virtual_address: read_u32_slice(bytes, offset + 12)?,
                raw_size: read_u32_slice(bytes, offset + 16)?,
                raw_offset: read_u32_slice(bytes, offset + 20)?,
                characteristics: read_u32_slice(bytes, offset + 36)?,
            };
            let mapped_size = section.virtual_size.max(section.raw_size);
            let virtual_end = section
                .virtual_address
                .checked_add(mapped_size)
                .ok_or(UefiError::Pe("BOOTX64.EFI section range overflows"))?;
            if virtual_end > image_size {
                return Err(UefiError::Pe("BOOTX64.EFI section exceeds image"));
            }
            let raw_end = section
                .raw_offset
                .checked_add(section.raw_size)
                .ok_or(UefiError::Pe("BOOTX64.EFI raw section overflows"))?;
            if raw_end as usize > bytes.len() {
                return Err(UefiError::Pe("BOOTX64.EFI raw section is truncated"));
            }
            if (section.virtual_address..virtual_end).contains(&entry_rva)
                && section.characteristics & 0x2000_0000 != 0
            {
                entry_executable = true;
            }
            sections.push(section);
        }
        if !entry_executable {
            return Err(UefiError::Pe("BOOTX64.EFI entry is not executable"));
        }
        for (index, section) in sections.iter().enumerate() {
            let start = section.virtual_address;
            let end = start + section.virtual_size.max(section.raw_size);
            if sections[index + 1..].iter().any(|other| {
                let other_start = other.virtual_address;
                let other_end = other_start + other.virtual_size.max(other.raw_size);
                start < other_end && other_start < end
            }) {
                return Err(UefiError::Pe("BOOTX64.EFI sections overlap"));
            }
        }
        Ok(Self {
            preferred_base,
            entry_rva,
            image_size,
            headers_size,
            sections,
            bytes: bytes.to_vec(),
        })
    }

    fn load(&self, bus: &mut MemoryBus) -> Result<(), UefiError> {
        let end = PE_LOAD_BASE
            .checked_add(u64::from(self.image_size))
            .ok_or(UefiError::Pe("BOOTX64.EFI load range overflows"))?;
        if end > bus.len() as u64 || end > UEFI_STACK_BASE {
            return Err(UefiError::InsufficientMemory);
        }
        write_zeroes(bus, PE_LOAD_BASE, u64::from(self.image_size))?;
        bus.write_physical(PE_LOAD_BASE, &self.bytes[..self.headers_size as usize])?;
        for section in &self.sections {
            let source = checked_slice(
                &self.bytes,
                section.raw_offset as usize,
                section.raw_size as usize,
            )?;
            bus.write_physical(PE_LOAD_BASE + u64::from(section.virtual_address), source)?;
        }
        Ok(())
    }

    const fn entry(&self) -> u64 {
        PE_LOAD_BASE + self.entry_rva as u64
    }

    fn contains(&self, address: u64) -> bool {
        (PE_LOAD_BASE..PE_LOAD_BASE + u64::from(self.image_size)).contains(&address)
    }
}

fn checked_slice(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], UefiError> {
    bytes
        .get(offset..offset.saturating_add(length))
        .ok_or(UefiError::Pe("BOOTX64.EFI structure is truncated"))
}

fn read_u16_slice(bytes: &[u8], offset: usize) -> Result<u16, UefiError> {
    let bytes = checked_slice(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_slice(bytes: &[u8], offset: usize) -> Result<u32, UefiError> {
    let bytes = checked_slice(bytes, offset, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("four bytes")))
}

fn read_u64_slice(bytes: &[u8], offset: usize) -> Result<u64, UefiError> {
    let bytes = checked_slice(bytes, offset, 8)?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Service {
    Unsupported,
    AllocatePages,
    FreePages,
    GetMemoryMap,
    HandleProtocol,
    LocateProtocol,
    ExitBootServices,
    OpenVolume,
    FileOpen,
    FileClose,
    FileRead,
    FileGetInfo,
    OutputString,
}

struct UefiEnvironment {
    files: EfiSystemPartitionFiles,
    allocator: PageAllocator,
    services: BTreeMap<u64, Service>,
    calls: UefiServiceCalls,
    open_files: BTreeMap<u64, OpenFile>,
    next_file_handle: u64,
    framebuffer: UefiFramebuffer,
    output: String,
    exited: bool,
}

#[derive(Clone, Copy)]
enum FileKind {
    Kernel,
    Initrd,
}

struct OpenFile {
    kind: FileKind,
    position: usize,
}

impl UefiEnvironment {
    fn new(
        files: EfiSystemPartitionFiles,
        memory_bytes: u64,
        width: u16,
        height: u16,
    ) -> Result<Self, UefiError> {
        if width < 8 || height < 16 {
            return Err(UefiError::InvalidServiceCall("GOP geometry is too small"));
        }
        let pitch = width
            .checked_mul(4)
            .ok_or(UefiError::InvalidServiceCall("GOP pitch overflows"))?;
        let framebuffer_bytes = u64::from(pitch)
            .checked_mul(u64::from(height))
            .and_then(|bytes| align_up(bytes, PAGE_SIZE))
            .ok_or(UefiError::InsufficientMemory)?;
        let framebuffer_base = align_down(
            memory_bytes
                .checked_sub(framebuffer_bytes)
                .ok_or(UefiError::InsufficientMemory)?,
            PAGE_SIZE,
        );
        if framebuffer_base < ALLOCATION_FLOOR + 16 * 1024 * 1024
            || UEFI_STACK_BASE + UEFI_STACK_SIZE > ALLOCATION_FLOOR
        {
            return Err(UefiError::InsufficientMemory);
        }
        Ok(Self {
            files,
            allocator: PageAllocator::new(ALLOCATION_FLOOR, framebuffer_base, memory_bytes),
            services: BTreeMap::new(),
            calls: UefiServiceCalls::default(),
            open_files: BTreeMap::new(),
            next_file_handle: FILE_HANDLE_BASE,
            framebuffer: UefiFramebuffer {
                physical: framebuffer_base,
                width,
                height,
                pitch,
            },
            output: String::new(),
            exited: false,
        })
    }

    fn install(&mut self, bus: &mut MemoryBus, pe: &PeImage) -> Result<(), UefiError> {
        write_zeroes(bus, FIRMWARE_BASE, FIRMWARE_END - FIRMWARE_BASE)?;
        bus.write_physical(RETURN_SENTINEL, &[0xcc])?;
        self.install_stubs(bus)?;
        self.install_system_table(bus, pe)?;
        self.install_filesystem(bus)?;
        self.install_gop(bus)?;
        Ok(())
    }

    fn install_stubs(&mut self, bus: &mut MemoryBus) -> Result<(), UefiError> {
        for (index, service) in [
            Service::Unsupported,
            Service::AllocatePages,
            Service::FreePages,
            Service::GetMemoryMap,
            Service::HandleProtocol,
            Service::LocateProtocol,
            Service::ExitBootServices,
            Service::OpenVolume,
            Service::FileOpen,
            Service::FileClose,
            Service::FileRead,
            Service::FileGetInfo,
            Service::OutputString,
        ]
        .into_iter()
        .enumerate()
        {
            let address = STUB_BASE + index as u64 * 0x10;
            bus.write_physical(address, &[0xcc, 0xf4])?;
            self.services.insert(address, service);
        }
        Ok(())
    }

    fn stub(&self, service: Service) -> u64 {
        self.services
            .iter()
            .find_map(|(address, candidate)| (*candidate == service).then_some(*address))
            .expect("all service stubs are installed")
    }

    fn install_system_table(&self, bus: &mut MemoryBus, pe: &PeImage) -> Result<(), UefiError> {
        // EFI_SYSTEM_TABLE fields consumed by the packaged application.
        write_u64(bus, SYSTEM_TABLE, 0x5453_5953_2049_4249)?;
        write_u64(bus, SYSTEM_TABLE + 64, TEXT_OUTPUT)?;
        write_u64(bus, SYSTEM_TABLE + 80, TEXT_OUTPUT)?;
        write_u64(bus, SYSTEM_TABLE + 96, BOOT_SERVICES)?;
        write_u64(bus, SYSTEM_TABLE + 104, 1)?;
        write_u64(bus, SYSTEM_TABLE + 112, CONFIGURATION_TABLE)?;

        bus.write_physical(CONFIGURATION_TABLE, &ACPI_20_GUID)?;
        write_u64(bus, CONFIGURATION_TABLE + 16, RSDP_ADDRESS)?;

        // Point every unimplemented boot-service slot at an explicit failing
        // stub, then replace only the functions reached by Xenith.
        for offset in (24..=368).step_by(8) {
            write_u64(bus, BOOT_SERVICES + offset, self.stub(Service::Unsupported))?;
        }
        write_u64(bus, BOOT_SERVICES + 40, self.stub(Service::AllocatePages))?;
        write_u64(bus, BOOT_SERVICES + 48, self.stub(Service::FreePages))?;
        write_u64(bus, BOOT_SERVICES + 56, self.stub(Service::GetMemoryMap))?;
        write_u64(bus, BOOT_SERVICES + 152, self.stub(Service::HandleProtocol))?;
        write_u64(
            bus,
            BOOT_SERVICES + 232,
            self.stub(Service::ExitBootServices),
        )?;
        write_u64(bus, BOOT_SERVICES + 320, self.stub(Service::LocateProtocol))?;

        // Loaded image protocol used to discover the ESP device handle.
        write_u64(bus, LOADED_IMAGE + 16, SYSTEM_TABLE)?;
        write_u64(bus, LOADED_IMAGE + 24, DEVICE_HANDLE)?;
        write_u64(bus, LOADED_IMAGE + 64, PE_LOAD_BASE)?;
        write_u64(bus, LOADED_IMAGE + 72, u64::from(pe.image_size))?;

        // Error-only text console. Its unused methods also fail explicitly.
        for offset in (0..72).step_by(8) {
            write_u64(bus, TEXT_OUTPUT + offset, self.stub(Service::Unsupported))?;
        }
        write_u64(bus, TEXT_OUTPUT + 8, self.stub(Service::OutputString))?;
        Ok(())
    }

    fn install_filesystem(&self, bus: &mut MemoryBus) -> Result<(), UefiError> {
        write_u64(bus, SIMPLE_FILE_SYSTEM, 0x0001_0000)?;
        write_u64(bus, SIMPLE_FILE_SYSTEM + 8, self.stub(Service::OpenVolume))?;
        self.write_file_protocol(bus, ROOT_FILE, true)
    }

    fn write_file_protocol(
        &self,
        bus: &mut MemoryBus,
        address: u64,
        directory: bool,
    ) -> Result<(), UefiError> {
        for offset in (0..120).step_by(8) {
            write_u64(bus, address + offset, self.stub(Service::Unsupported))?;
        }
        write_u64(
            bus,
            address,
            if directory { 0x0002_0000 } else { 0x0001_0000 },
        )?;
        if directory {
            write_u64(bus, address + 8, self.stub(Service::FileOpen))?;
        }
        write_u64(bus, address + 16, self.stub(Service::FileClose))?;
        write_u64(bus, address + 32, self.stub(Service::FileRead))?;
        write_u64(bus, address + 64, self.stub(Service::FileGetInfo))?;
        Ok(())
    }

    fn install_gop(&self, bus: &mut MemoryBus) -> Result<(), UefiError> {
        write_u64(bus, GOP, self.stub(Service::Unsupported))?;
        write_u64(bus, GOP + 8, self.stub(Service::Unsupported))?;
        write_u64(bus, GOP + 16, self.stub(Service::Unsupported))?;
        write_u64(bus, GOP + 24, GOP_MODE)?;
        write_u32(bus, GOP_MODE, 1)?;
        write_u32(bus, GOP_MODE + 4, 0)?;
        write_u64(bus, GOP_MODE + 8, GOP_MODE_INFO)?;
        write_u64(bus, GOP_MODE + 16, 36)?;
        write_u64(bus, GOP_MODE + 24, self.framebuffer.physical)?;
        write_u64(
            bus,
            GOP_MODE + 32,
            u64::from(self.framebuffer.pitch) * u64::from(self.framebuffer.height),
        )?;
        write_u32(bus, GOP_MODE_INFO + 4, u32::from(self.framebuffer.width))?;
        write_u32(bus, GOP_MODE_INFO + 8, u32::from(self.framebuffer.height))?;
        write_u32(bus, GOP_MODE_INFO + 12, 1)?; // PixelBlueGreenRedReserved8BitPerColor.
        write_u32(bus, GOP_MODE_INFO + 32, u32::from(self.framebuffer.width))?;
        Ok(())
    }

    fn dispatch(
        &mut self,
        address: u64,
        cpu: &mut Cpu,
        bus: &mut MemoryBus,
    ) -> Result<(), UefiError> {
        let service = self
            .services
            .get(&address)
            .copied()
            .ok_or(UefiError::UnsupportedService(address))?;
        let status = match service {
            Service::Unsupported => return Err(UefiError::UnsupportedService(address)),
            Service::AllocatePages => self.allocate_pages(cpu, bus)?,
            Service::FreePages => self.free_pages(cpu)?,
            Service::GetMemoryMap => self.get_memory_map(cpu, bus)?,
            Service::HandleProtocol => self.handle_protocol(cpu, bus)?,
            Service::LocateProtocol => self.locate_protocol(cpu, bus)?,
            Service::ExitBootServices => self.exit_boot_services(cpu)?,
            Service::OpenVolume => self.open_volume(cpu, bus)?,
            Service::FileOpen => self.file_open(cpu, bus)?,
            Service::FileClose => self.file_close(cpu)?,
            Service::FileRead => self.file_read(cpu, bus)?,
            Service::FileGetInfo => self.file_get_info(cpu, bus)?,
            Service::OutputString => self.output_string(cpu, bus)?,
        };
        return_from_service(cpu, bus, status)
    }

    fn allocate_pages(&mut self, cpu: &Cpu, bus: &mut MemoryBus) -> Result<u64, UefiError> {
        self.calls.allocate_pages += 1;
        if reg(cpu, Register::Rcx) != ALLOCATE_MAX_ADDRESS
            || reg(cpu, Register::Rdx) != LOADER_DATA
            || reg(cpu, Register::R8) == 0
            || reg(cpu, Register::R9) == 0
        {
            return Err(UefiError::InvalidServiceCall("AllocatePages arguments"));
        }
        let pages = reg(cpu, Register::R8);
        let result_pointer = reg(cpu, Register::R9);
        let maximum = read_u64(bus, result_pointer)?;
        let address = self
            .allocator
            .allocate(pages, LOADER_DATA as u32, maximum)
            .ok_or(UefiError::InsufficientMemory)?;
        write_zeroes(bus, address, pages * PAGE_SIZE)?;
        write_u64(bus, result_pointer, address)?;
        Ok(SUCCESS)
    }

    fn free_pages(&mut self, cpu: &Cpu) -> Result<u64, UefiError> {
        self.calls.free_pages += 1;
        let address = reg(cpu, Register::Rcx);
        let pages = reg(cpu, Register::Rdx);
        if !self.allocator.free(address, pages) {
            return Err(UefiError::InvalidServiceCall("FreePages allocation"));
        }
        Ok(SUCCESS)
    }

    fn get_memory_map(&mut self, cpu: &Cpu, bus: &mut MemoryBus) -> Result<u64, UefiError> {
        self.calls.get_memory_map += 1;
        let size_pointer = reg(cpu, Register::Rcx);
        let map_pointer = reg(cpu, Register::Rdx);
        let key_pointer = reg(cpu, Register::R8);
        let descriptor_size_pointer = reg(cpu, Register::R9);
        let descriptor_version_pointer = stack_argument(bus, cpu, 0)?;
        if size_pointer == 0
            || key_pointer == 0
            || descriptor_size_pointer == 0
            || descriptor_version_pointer == 0
        {
            return Err(UefiError::InvalidServiceCall("GetMemoryMap pointers"));
        }
        let descriptors = self.allocator.descriptors();
        let required = descriptors
            .len()
            .checked_mul(MEMORY_DESCRIPTOR_SIZE)
            .ok_or(UefiError::InsufficientMemory)?;
        let capacity = usize::try_from(read_u64(bus, size_pointer)?)
            .map_err(|_| UefiError::InvalidServiceCall("GetMemoryMap capacity"))?;
        write_u64(bus, size_pointer, required as u64)?;
        write_u64(bus, descriptor_size_pointer, MEMORY_DESCRIPTOR_SIZE as u64)?;
        write_u32(bus, descriptor_version_pointer, 1)?;
        if map_pointer == 0 || capacity < required {
            return Ok(BUFFER_TOO_SMALL);
        }
        for (index, descriptor) in descriptors.iter().enumerate() {
            let address = map_pointer + (index * MEMORY_DESCRIPTOR_SIZE) as u64;
            write_u32(bus, address, descriptor.memory_type)?;
            write_u32(bus, address + 4, 0)?;
            write_u64(bus, address + 8, descriptor.physical_start)?;
            write_u64(bus, address + 16, 0)?;
            write_u64(bus, address + 24, descriptor.pages)?;
            write_u64(bus, address + 32, 0)?;
        }
        write_u64(bus, key_pointer, self.allocator.map_key)?;
        Ok(SUCCESS)
    }

    fn handle_protocol(&mut self, cpu: &Cpu, bus: &mut MemoryBus) -> Result<u64, UefiError> {
        self.calls.handle_protocol += 1;
        let handle = reg(cpu, Register::Rcx);
        let guid = read_guid(bus, reg(cpu, Register::Rdx))?;
        let output = reg(cpu, Register::R8);
        let interface = match (handle, guid) {
            (IMAGE_HANDLE, LOADED_IMAGE_GUID) => LOADED_IMAGE,
            (DEVICE_HANDLE, SIMPLE_FILE_SYSTEM_GUID) => SIMPLE_FILE_SYSTEM,
            _ => return Err(UefiError::InvalidServiceCall("HandleProtocol request")),
        };
        write_u64(bus, output, interface)?;
        Ok(SUCCESS)
    }

    fn locate_protocol(&mut self, cpu: &Cpu, bus: &mut MemoryBus) -> Result<u64, UefiError> {
        self.calls.locate_protocol += 1;
        if read_guid(bus, reg(cpu, Register::Rcx))? != GOP_GUID
            || reg(cpu, Register::Rdx) != 0
            || reg(cpu, Register::R8) == 0
        {
            return Err(UefiError::InvalidServiceCall("LocateProtocol request"));
        }
        write_u64(bus, reg(cpu, Register::R8), GOP)?;
        Ok(SUCCESS)
    }

    fn exit_boot_services(&mut self, cpu: &Cpu) -> Result<u64, UefiError> {
        self.calls.exit_boot_services += 1;
        if reg(cpu, Register::Rcx) != IMAGE_HANDLE
            || reg(cpu, Register::Rdx) != self.allocator.map_key
        {
            return Ok(INVALID_PARAMETER);
        }
        self.exited = true;
        Ok(SUCCESS)
    }

    fn open_volume(&mut self, cpu: &Cpu, bus: &mut MemoryBus) -> Result<u64, UefiError> {
        self.calls.open_volume += 1;
        if reg(cpu, Register::Rcx) != SIMPLE_FILE_SYSTEM || reg(cpu, Register::Rdx) == 0 {
            return Err(UefiError::InvalidServiceCall("OpenVolume request"));
        }
        write_u64(bus, reg(cpu, Register::Rdx), ROOT_FILE)?;
        Ok(SUCCESS)
    }

    fn file_open(&mut self, cpu: &Cpu, bus: &mut MemoryBus) -> Result<u64, UefiError> {
        self.calls.file_open += 1;
        if reg(cpu, Register::Rcx) != ROOT_FILE
            || reg(cpu, Register::Rdx) == 0
            || reg(cpu, Register::R9) != FILE_MODE_READ
            || stack_argument(bus, cpu, 0)? != 0
        {
            return Err(UefiError::InvalidServiceCall("File.Open arguments"));
        }
        let path = read_utf16_ascii(bus, reg(cpu, Register::R8), 96)?;
        let kind = match path.as_str() {
            "\\EFI\\XENITH\\kernel.elf" => FileKind::Kernel,
            "\\EFI\\XENITH\\initrd.cpio" => FileKind::Initrd,
            _ => return Err(UefiError::InvalidServiceCall("File.Open path")),
        };
        let handle = self.next_file_handle;
        self.next_file_handle = self
            .next_file_handle
            .checked_add(FILE_HANDLE_STRIDE)
            .ok_or(UefiError::InsufficientMemory)?;
        if self.next_file_handle >= FIRMWARE_END {
            return Err(UefiError::InsufficientMemory);
        }
        self.write_file_protocol(bus, handle, false)?;
        self.open_files
            .insert(handle, OpenFile { kind, position: 0 });
        write_u64(bus, reg(cpu, Register::Rdx), handle)?;
        Ok(SUCCESS)
    }

    fn file_close(&mut self, cpu: &Cpu) -> Result<u64, UefiError> {
        self.calls.file_close += 1;
        let handle = reg(cpu, Register::Rcx);
        if self.open_files.remove(&handle).is_none() {
            return Err(UefiError::InvalidServiceCall("File.Close handle"));
        }
        Ok(SUCCESS)
    }

    fn file_read(&mut self, cpu: &Cpu, bus: &mut MemoryBus) -> Result<u64, UefiError> {
        self.calls.file_read += 1;
        let handle = reg(cpu, Register::Rcx);
        let size_pointer = reg(cpu, Register::Rdx);
        let destination = reg(cpu, Register::R8);
        let (kind, position) = self
            .open_files
            .get(&handle)
            .map(|file| (file.kind, file.position))
            .ok_or(UefiError::InvalidServiceCall("File.Read handle"))?;
        let requested = usize::try_from(read_u64(bus, size_pointer)?)
            .map_err(|_| UefiError::InvalidServiceCall("File.Read size"))?;
        let contents = self.file_contents(kind);
        let count = requested.min(contents.len().saturating_sub(position));
        bus.write_physical(destination, &contents[position..position + count])?;
        write_u64(bus, size_pointer, count as u64)?;
        self.open_files
            .get_mut(&handle)
            .expect("validated file remains open")
            .position += count;
        Ok(SUCCESS)
    }

    fn file_get_info(&mut self, cpu: &Cpu, bus: &mut MemoryBus) -> Result<u64, UefiError> {
        self.calls.file_get_info += 1;
        let handle = reg(cpu, Register::Rcx);
        if read_guid(bus, reg(cpu, Register::Rdx))? != FILE_INFO_GUID {
            return Err(UefiError::InvalidServiceCall("File.GetInfo GUID"));
        }
        let size_pointer = reg(cpu, Register::R8);
        let output = reg(cpu, Register::R9);
        let kind = self
            .open_files
            .get(&handle)
            .map(|file| file.kind)
            .ok_or(UefiError::InvalidServiceCall("File.GetInfo handle"))?;
        let capacity = usize::try_from(read_u64(bus, size_pointer)?)
            .map_err(|_| UefiError::InvalidServiceCall("File.GetInfo size"))?;
        write_u64(bus, size_pointer, FILE_INFO_SIZE as u64)?;
        if output == 0 || capacity < FILE_INFO_SIZE {
            return Ok(BUFFER_TOO_SMALL);
        }
        write_zeroes(bus, output, FILE_INFO_SIZE as u64)?;
        let length = self.file_contents(kind).len() as u64;
        write_u64(bus, output, FILE_INFO_SIZE as u64)?;
        write_u64(bus, output + 8, length)?;
        write_u64(
            bus,
            output + 16,
            align_up(length, PAGE_SIZE).unwrap_or(length),
        )?;
        Ok(SUCCESS)
    }

    fn output_string(&mut self, cpu: &Cpu, bus: &mut MemoryBus) -> Result<u64, UefiError> {
        self.calls.output_string += 1;
        if reg(cpu, Register::Rcx) != TEXT_OUTPUT {
            return Err(UefiError::InvalidServiceCall("OutputString console"));
        }
        self.output
            .push_str(&read_utf16_ascii(bus, reg(cpu, Register::Rdx), 512)?);
        Ok(SUCCESS)
    }

    fn file_contents(&self, kind: FileKind) -> &[u8] {
        match kind {
            FileKind::Kernel => &self.files.kernel,
            FileKind::Initrd => &self.files.initrd,
        }
    }
}

#[derive(Clone, Copy)]
struct Allocation {
    address: u64,
    pages: u64,
    memory_type: u32,
}

struct MemoryDescriptor {
    memory_type: u32,
    physical_start: u64,
    pages: u64,
}

struct PageAllocator {
    floor: u64,
    ceiling: u64,
    memory_end: u64,
    allocations: Vec<Allocation>,
    map_key: u64,
}

impl PageAllocator {
    const fn new(floor: u64, ceiling: u64, memory_end: u64) -> Self {
        Self {
            floor,
            ceiling,
            memory_end,
            allocations: Vec::new(),
            map_key: 1,
        }
    }

    fn allocate(&mut self, pages: u64, memory_type: u32, maximum: u64) -> Option<u64> {
        let byte_len = pages.checked_mul(PAGE_SIZE)?;
        let maximum_end = maximum.saturating_add(1);
        let mut occupied = self.allocations.clone();
        occupied.sort_by_key(|allocation| allocation.address);
        let mut gaps = Vec::new();
        let mut cursor = self.floor;
        for allocation in &occupied {
            if cursor < allocation.address {
                gaps.push((cursor, allocation.address));
            }
            cursor = allocation.address + allocation.pages * PAGE_SIZE;
        }
        if cursor < self.ceiling {
            gaps.push((cursor, self.ceiling));
        }
        for (start, end) in gaps.into_iter().rev() {
            let allowed_end = align_down(end.min(maximum_end), PAGE_SIZE);
            let Some(address) = allowed_end.checked_sub(byte_len) else {
                continue;
            };
            if address >= start {
                self.allocations.push(Allocation {
                    address,
                    pages,
                    memory_type,
                });
                self.map_key = self.map_key.wrapping_add(1).max(1);
                return Some(address);
            }
        }
        None
    }

    fn free(&mut self, address: u64, pages: u64) -> bool {
        let Some(index) = self
            .allocations
            .iter()
            .position(|allocation| allocation.address == address && allocation.pages == pages)
        else {
            return false;
        };
        self.allocations.remove(index);
        self.map_key = self.map_key.wrapping_add(1).max(1);
        true
    }

    fn descriptors(&self) -> Vec<MemoryDescriptor> {
        let mut allocations = self.allocations.clone();
        allocations.sort_by_key(|allocation| allocation.address);
        let mut descriptors = vec![MemoryDescriptor {
            memory_type: 0,
            physical_start: 0,
            pages: self.floor / PAGE_SIZE,
        }];
        let mut cursor = self.floor;
        for allocation in allocations {
            if cursor < allocation.address {
                descriptors.push(MemoryDescriptor {
                    memory_type: 7,
                    physical_start: cursor,
                    pages: (allocation.address - cursor) / PAGE_SIZE,
                });
            }
            descriptors.push(MemoryDescriptor {
                memory_type: allocation.memory_type,
                physical_start: allocation.address,
                pages: allocation.pages,
            });
            cursor = allocation.address + allocation.pages * PAGE_SIZE;
        }
        if cursor < self.ceiling {
            descriptors.push(MemoryDescriptor {
                memory_type: 7,
                physical_start: cursor,
                pages: (self.ceiling - cursor) / PAGE_SIZE,
            });
        }
        descriptors.push(MemoryDescriptor {
            memory_type: 0,
            physical_start: self.ceiling,
            pages: (self.memory_end - self.ceiling) / PAGE_SIZE,
        });
        descriptors
    }
}

fn return_from_service(cpu: &mut Cpu, bus: &mut MemoryBus, status: u64) -> Result<(), UefiError> {
    let stack = reg(cpu, Register::Rsp);
    let return_address = read_u64(bus, stack)?;
    cpu.state.set_register(Register::Rsp, stack + 8);
    cpu.state.set_register(Register::Rax, status);
    cpu.state.rip = return_address;
    Ok(())
}

fn stack_argument(bus: &mut MemoryBus, cpu: &Cpu, index: u64) -> Result<u64, UefiError> {
    read_u64(
        bus,
        reg(cpu, Register::Rsp) + 0x28 + index.saturating_mul(8),
    )
}

fn reg(cpu: &Cpu, register: Register) -> u64 {
    cpu.state.register(register)
}

fn read_guid(bus: &mut MemoryBus, address: u64) -> Result<[u8; 16], UefiError> {
    if address == 0 {
        return Err(UefiError::InvalidServiceCall("null GUID"));
    }
    let mut guid = [0_u8; 16];
    bus.read_physical(address, &mut guid)?;
    Ok(guid)
}

fn read_utf16_ascii(bus: &mut MemoryBus, address: u64, limit: usize) -> Result<String, UefiError> {
    if address == 0 {
        return Err(UefiError::InvalidServiceCall("null UTF-16 string"));
    }
    let mut output = String::new();
    for index in 0..limit {
        let mut bytes = [0_u8; 2];
        bus.read_physical(address + (index * 2) as u64, &mut bytes)?;
        let unit = u16::from_le_bytes(bytes);
        if unit == 0 {
            return Ok(output);
        }
        let byte = u8::try_from(unit)
            .ok()
            .filter(u8::is_ascii)
            .ok_or(UefiError::InvalidServiceCall("non-ASCII UTF-16 string"))?;
        output.push(char::from(byte));
    }
    Err(UefiError::InvalidServiceCall("unterminated UTF-16 string"))
}

fn read_u64(bus: &mut MemoryBus, address: u64) -> Result<u64, UefiError> {
    Ok(bus.read_u64_physical(address)?)
}

fn write_u32(bus: &mut MemoryBus, address: u64, value: u32) -> Result<(), UefiError> {
    bus.write_physical(address, &value.to_le_bytes())?;
    Ok(())
}

fn write_u64(bus: &mut MemoryBus, address: u64, value: u64) -> Result<(), UefiError> {
    bus.write_u64_physical(address, value)?;
    Ok(())
}

fn write_zeroes(bus: &mut MemoryBus, mut address: u64, mut length: u64) -> Result<(), UefiError> {
    const ZEROES: [u8; 4096] = [0; 4096];
    while length != 0 {
        let count = usize::try_from(length.min(ZEROES.len() as u64)).expect("bounded chunk");
        bus.write_physical(address, &ZEROES[..count])?;
        address += count as u64;
        length -= count as u64;
    }
    Ok(())
}

const fn align_down(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}

const fn align_up(value: u64, alignment: u64) -> Option<u64> {
    match value.checked_add(alignment - 1) {
        Some(value) => Some(value / alignment * alignment),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_allocator_is_top_down_bounded_and_map_keyed() {
        let mut allocator = PageAllocator::new(0x20_0000, 0x30_0000, 0x31_0000);
        let first = allocator.allocate(2, 2, u64::MAX).unwrap();
        let second = allocator.allocate(1, 2, first - 1).unwrap();
        assert_eq!(first, 0x2f_e000);
        assert_eq!(second, 0x2f_d000);
        assert_eq!(allocator.map_key, 3);
        assert!(allocator.free(first, 2));
        assert_eq!(allocator.map_key, 4);
        assert!(!allocator.free(first, 2));
        let descriptors = allocator.descriptors();
        assert!(descriptors.iter().any(|entry| entry.memory_type == 7));
        assert!(descriptors.iter().any(|entry| entry.memory_type == 2));
    }

    #[test]
    fn pe_parser_rejects_signature_only_payload() {
        assert!(matches!(PeImage::parse(b"MZ"), Err(UefiError::Pe(_))));
    }
}
