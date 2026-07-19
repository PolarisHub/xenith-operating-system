//! PC machine assembly, ELF loading, boot handoff, and execution control.

use std::fmt;
use std::sync::{Arc, Mutex};

use limine::{BootInfo, Framebuffer, MemmapEntry, Module};
use xenith_boot_common::{
    DiskEntry, DiskEntryKind, DiskManifest, ManifestError, XenithBootInfo, DISK_MANIFEST_LBA,
    DISK_MANIFEST_SIZE,
};
use xenith_x86::Register;

use crate::cpu::{Cpu, CpuFault, ExitReason};
use crate::device::{
    encode_ascii_set1, Cmos, IoApic, LegacyPic, Pit8254, Ps2Controller, Serial16550,
};
use crate::elf::{ElfError, ElfImage, ProgramHeader};
use crate::firmware::{boot_bios_image, BiosBootTrace, FirmwareError};
use crate::memory::{ApicEventKind, MemoryBus, MemoryError, PagingContext, Privilege};
use crate::platform::{AtaDiskError, AtaDiskImage, AtaPioDisk, Hpet, LegacyPciConfig, Rtl8139Nic};
use crate::uefi::{boot_uefi_iso, UefiError, UefiIsoBootTrace};

const PAGE_SIZE: u64 = 4096;
const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
const HHDM_BASE: u64 = 0xFFFF_8000_0000_0000;
const BOOT_INFO_PHYS: u64 = 0x0040_0000;
const MEMORY_MAP_PHYS: u64 = 0x0040_1000;
const MODULE_INFO_PHYS: u64 = 0x0040_2000;
const MODULE_PATH_PHYS: u64 = 0x0040_3000;
const FRAMEBUFFER_INFO_PHYS: u64 = 0x0040_4000;
const FRAMEBUFFER_POINTER_PHYS: u64 = 0x0040_5000;
const FIRST_PAYLOAD_PHYS: u64 = 0x0100_0000;
const KERNEL_STACK_TOP: u64 = 0xFFFF_FF7F_FFFF_F000;
const KERNEL_STACK_PAGES: u64 = 32;
const IOAPIC_PHYS: u64 = 0xFEC0_0000;
const HPET_PHYS: u64 = 0xFED0_0000;
const LAPIC_PHYS: u64 = 0xFEE0_0000;
const ACPI_RSDP_PHYS: u64 = 0x000E_0000;
const ACPI_XSDT_PHYS: u64 = 0x000E_0100;
const ACPI_MADT_PHYS: u64 = 0x000E_0200;
const ACPI_HPET_PHYS: u64 = 0x000E_0800;
const LOW_TRAMPOLINE_START: u64 = 0x0008_0000;
const LOW_TRAMPOLINE_END: u64 = 0x000A_0000;

/// Bounded topology capacity shared with the kernel's static CPU masks.
pub const MAX_EMULATED_CPUS: usize = 64;

/// Optional direct-loader linear framebuffer geometry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramebufferConfig {
    pub width: u16,
    pub height: u16,
}

impl FramebufferConfig {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let (width, height) = value
            .split_once(['x', 'X'])
            .ok_or("framebuffer geometry must be WIDTHxHEIGHT")?;
        let width = width
            .parse::<u16>()
            .map_err(|_| "invalid framebuffer width")?;
        let height = height
            .parse::<u16>()
            .map_err(|_| "invalid framebuffer height")?;
        if width < 8 || height < 16 || u32::from(width) * 4 > u32::from(u16::MAX) {
            return Err("framebuffer must be at least 8x16 with a 16-bit pitch");
        }
        Ok(Self { width, height })
    }
}

#[derive(Clone, Debug)]
pub struct MachineConfig {
    pub memory_bytes: usize,
    pub cpu_count: usize,
    pub instruction_limit: u64,
    pub mirror_serial: bool,
    pub framebuffer: Option<FramebufferConfig>,
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self {
            memory_bytes: 128 * 1024 * 1024,
            cpu_count: 1,
            instruction_limit: 100_000_000,
            mirror_serial: true,
            framebuffer: None,
        }
    }
}

#[derive(Debug)]
pub enum MachineError {
    Elf(ElfError),
    Memory(MemoryError),
    InsufficientMemory,
    InvalidSegment,
    InvalidDiskImage(&'static str),
    Manifest(ManifestError),
    Ata(AtaDiskError),
    DiskAlreadyAttached,
    Firmware(FirmwareError),
    Uefi(UefiError),
}

impl From<ElfError> for MachineError {
    fn from(value: ElfError) -> Self {
        Self::Elf(value)
    }
}
impl From<MemoryError> for MachineError {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}

impl From<ManifestError> for MachineError {
    fn from(value: ManifestError) -> Self {
        Self::Manifest(value)
    }
}

impl From<AtaDiskError> for MachineError {
    fn from(value: AtaDiskError) -> Self {
        Self::Ata(value)
    }
}

impl From<FirmwareError> for MachineError {
    fn from(value: FirmwareError) -> Self {
        Self::Firmware(value)
    }
}

impl From<UefiError> for MachineError {
    fn from(value: UefiError) -> Self {
        Self::Uefi(value)
    }
}

impl fmt::Display for MachineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for MachineError {}

/// Rejection from the deterministic host-to-PS/2 keyboard input path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyboardInputError {
    /// The US set-1 encoder intentionally accepts ASCII only.
    UnsupportedCharacter(char),
    /// The machine was assembled without a PS/2-capable controller.
    ControllerUnavailable,
}

impl fmt::Display for KeyboardInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCharacter(character) => {
                write!(formatter, "unsupported keyboard character {character:?}")
            },
            Self::ControllerUnavailable => formatter.write_str("PS/2 controller unavailable"),
        }
    }
}

impl std::error::Error for KeyboardInputError {}

#[derive(Clone, Debug)]
pub struct RunSummary {
    pub reason: ExitReason,
    pub instructions: u64,
    pub interrupts: u64,
    pub serial: Vec<u8>,
}

/// Exact manifest extents selected by [`Machine::load_manifest_image`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestBoot {
    pub kernel_lba: u64,
    pub kernel_bytes: u64,
    pub initrd_lba: u64,
    pub initrd_bytes: u64,
    pub disk_sectors: u64,
}

#[derive(Clone, Copy, Debug)]
struct FramebufferSurface {
    physical: u64,
    width: u16,
    height: u16,
    pitch: u16,
}

pub struct Machine {
    pub cpu: Cpu,
    pub bus: MemoryBus,
    application_processors: Vec<ApplicationProcessor>,
    scheduler_cursor: usize,
    config: MachineConfig,
    serial: Arc<Mutex<Vec<u8>>>,
    disk: Option<AtaDiskImage>,
    framebuffer: Option<FramebufferSurface>,
    bios_trace: Option<BiosBootTrace>,
    uefi_trace: Option<UefiIsoBootTrace>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessorLifecycle {
    WaitForSipi,
    Running,
}

struct ApplicationProcessor {
    cpu: Cpu,
    lifecycle: ProcessorLifecycle,
}

impl Machine {
    #[must_use]
    pub fn new(config: MachineConfig) -> Self {
        assert!(
            (1..=MAX_EMULATED_CPUS).contains(&config.cpu_count),
            "cpu_count must be in 1..={MAX_EMULATED_CPUS}"
        );
        let processor_count = config.cpu_count as u16;
        let serial = Arc::new(Mutex::new(Vec::new()));
        let mut bus = MemoryBus::new(config.memory_bytes);
        bus.configure_processors(config.cpu_count);
        bus.attach(Serial16550::new(
            0x3F8,
            Arc::clone(&serial),
            config.mirror_serial,
        ));
        bus.attach(Cmos::default());
        bus.attach(Pit8254::default());
        bus.attach(LegacyPic::default());
        bus.attach(Ps2Controller::default());
        bus.attach(IoApic::default());
        bus.attach(Hpet::default());
        bus.attach(LegacyPciConfig::default());
        bus.attach(Rtl8139Nic::default());
        let application_processors = (1..config.cpu_count)
            .map(|processor| ApplicationProcessor {
                cpu: Cpu::new_with_topology(processor as u32, processor_count, false),
                lifecycle: ProcessorLifecycle::WaitForSipi,
            })
            .collect();
        Self {
            cpu: Cpu::new_with_topology(0, processor_count, true),
            bus,
            application_processors,
            scheduler_cursor: 0,
            config,
            serial,
            disk: None,
            framebuffer: None,
            bios_trace: None,
            uefi_trace: None,
        }
    }

    #[must_use]
    pub fn cpu_count(&self) -> usize {
        1 + self.application_processors.len()
    }

    #[must_use]
    pub fn cpu_state(&self, processor: usize) -> Option<&crate::cpu::CpuState> {
        if processor == 0 {
            Some(&self.cpu.state)
        } else {
            self.application_processors
                .get(processor - 1)
                .map(|ap| &ap.cpu.state)
        }
    }

    fn reset_application_processors(&mut self) {
        let count = self.cpu_count() as u16;
        for (index, ap) in self.application_processors.iter_mut().enumerate() {
            ap.cpu = Cpu::new_with_topology((index + 1) as u32, count, false);
            ap.lifecycle = ProcessorLifecycle::WaitForSipi;
        }
        self.scheduler_cursor = 0;
        self.bus.configure_processors(usize::from(count));
    }

    pub fn load_flat(
        &mut self,
        address: u64,
        program: &[u8],
        stack_top: u64,
    ) -> Result<(), MachineError> {
        self.bios_trace = None;
        self.uefi_trace = None;
        self.bus.write_physical(address, program)?;
        self.reset_application_processors();
        self.cpu = Cpu::new_with_topology(0, self.cpu_count() as u16, true);
        self.cpu.state.rip = address;
        self.cpu.state.set_register(Register::Rsp, stack_top);
        self.cpu.state.cr0 &= !(1 << 31);
        Ok(())
    }

    pub fn load_kernel(
        &mut self,
        kernel: &[u8],
        initrd: Option<&[u8]>,
    ) -> Result<(), MachineError> {
        self.framebuffer = None;
        self.bios_trace = None;
        self.uefi_trace = None;
        let image = ElfImage::parse(kernel)?;
        let root = 0x1000;
        let mut tables = TableAllocator::new(0x2000, BOOT_INFO_PHYS);
        self.bus.write_physical(root, &[0; PAGE_SIZE as usize])?;

        let memory_end = self.bus.len() as u64;
        for physical in (0..align_up(memory_end, HUGE_PAGE_SIZE)).step_by(HUGE_PAGE_SIZE as usize) {
            map_huge(&mut self.bus, root, physical, physical, &mut tables)?;
            map_huge(
                &mut self.bus,
                root,
                HHDM_BASE.wrapping_add(physical),
                physical,
                &mut tables,
            )?;
        }
        for physical in [IOAPIC_PHYS, HPET_PHYS, LAPIC_PHYS] {
            map_page(
                &mut self.bus,
                root,
                HHDM_BASE + physical,
                physical,
                3 | (1 << 63),
                &mut tables,
            )?;
        }

        let mut payload = FIRST_PAYLOAD_PHYS;
        for header in image.program_headers() {
            let header = header?;
            if header.kind != ProgramHeader::LOAD || header.memory_size == 0 {
                continue;
            }
            if header.file_size > header.memory_size {
                return Err(MachineError::InvalidSegment);
            }
            let page_offset = header.virtual_address & (PAGE_SIZE - 1);
            payload = align_up(payload, PAGE_SIZE);
            let physical_base = payload;
            let total = align_up(page_offset + header.memory_size, PAGE_SIZE);
            if physical_base
                .checked_add(total)
                .is_none_or(|end| end > memory_end)
            {
                return Err(MachineError::InsufficientMemory);
            }
            let page_count = total / PAGE_SIZE;
            for page in 0..page_count {
                let virtual_address =
                    (header.virtual_address & !(PAGE_SIZE - 1)) + page * PAGE_SIZE;
                let physical_address = physical_base + page * PAGE_SIZE;
                let mut flags = 1u64;
                if header.flags & ProgramHeader::WRITE != 0 {
                    flags |= 2;
                }
                if header.flags & ProgramHeader::EXECUTE == 0 {
                    flags |= 1 << 63;
                }
                map_page(
                    &mut self.bus,
                    root,
                    virtual_address,
                    physical_address,
                    flags,
                    &mut tables,
                )?;
            }
            self.bus
                .write_physical(physical_base + page_offset, image.segment_data(header)?)?;
            payload += total;
        }

        let module = if let Some(bytes) = initrd {
            payload = align_up(payload, PAGE_SIZE);
            let module_phys = payload;
            self.bus.write_physical(module_phys, bytes)?;
            payload = align_up(payload + bytes.len() as u64, PAGE_SIZE);
            self.bus
                .write_physical(MODULE_PATH_PHYS, b"/boot/initramfs.cpio\0")?;
            let module = Module {
                base: module_phys as *const u8,
                length: bytes.len() as u64,
                path: (HHDM_BASE + MODULE_PATH_PHYS) as *const core::ffi::c_char,
                cmdline: core::ptr::null(),
            };
            write_struct(&mut self.bus, MODULE_INFO_PHYS, &module)?;
            Some(module)
        } else {
            None
        };

        let stack_phys = payload;
        let stack_bytes = KERNEL_STACK_PAGES * PAGE_SIZE;
        if stack_phys + stack_bytes > memory_end {
            return Err(MachineError::InsufficientMemory);
        }
        for page in 0..KERNEL_STACK_PAGES {
            map_page(
                &mut self.bus,
                root,
                KERNEL_STACK_TOP - stack_bytes + page * PAGE_SIZE,
                stack_phys + page * PAGE_SIZE,
                3 | (1 << 63),
                &mut tables,
            )?;
        }
        payload += stack_bytes;

        let framebuffer = if let Some(geometry) = self.config.framebuffer {
            payload = align_up(payload, PAGE_SIZE);
            let pitch = geometry
                .width
                .checked_mul(4)
                .ok_or(MachineError::InsufficientMemory)?;
            let byte_length = u64::from(pitch)
                .checked_mul(u64::from(geometry.height))
                .ok_or(MachineError::InsufficientMemory)?;
            if payload
                .checked_add(byte_length)
                .is_none_or(|end| end > memory_end)
            {
                return Err(MachineError::InsufficientMemory);
            }
            let surface = FramebufferSurface {
                physical: payload,
                width: geometry.width,
                height: geometry.height,
                pitch,
            };
            let descriptor = Framebuffer {
                address: payload as *mut u8,
                width: geometry.width,
                height: geometry.height,
                pitch,
                bpp: 32,
            };
            write_struct(&mut self.bus, FRAMEBUFFER_INFO_PHYS, &descriptor)?;
            self.bus
                .write_u64_physical(FRAMEBUFFER_POINTER_PHYS, HHDM_BASE + FRAMEBUFFER_INFO_PHYS)?;
            payload = align_up(payload + byte_length, PAGE_SIZE);
            Some(surface)
        } else {
            None
        };

        let reserved_end = align_up(payload, PAGE_SIZE);
        let cpu_count = self.cpu_count();
        install_acpi_tables(&mut self.bus, cpu_count)?;
        let memory_map = [
            MemmapEntry {
                base: 0,
                length: LOW_TRAMPOLINE_START,
                kind: 6,
                reserved: 0,
            },
            // INIT/SIPI startup needs ordinary allocator-owned conventional
            // memory. This window does not overlap loader tables or VGA RAM.
            MemmapEntry {
                base: LOW_TRAMPOLINE_START,
                length: LOW_TRAMPOLINE_END - LOW_TRAMPOLINE_START,
                kind: 0,
                reserved: 0,
            },
            MemmapEntry {
                base: LOW_TRAMPOLINE_END,
                length: reserved_end.saturating_sub(LOW_TRAMPOLINE_END),
                kind: 6,
                reserved: 0,
            },
            MemmapEntry {
                base: reserved_end,
                length: memory_end.saturating_sub(reserved_end),
                kind: 0,
                reserved: 0,
            },
        ];
        write_slice(&mut self.bus, MEMORY_MAP_PHYS, &memory_map)?;
        let boot_info = BootInfo {
            hhdm_offset: HHDM_BASE,
            framebuffer: if framebuffer.is_some() {
                (HHDM_BASE + FRAMEBUFFER_POINTER_PHYS) as *const *const Framebuffer
            } else {
                core::ptr::null()
            },
            framebuffer_count: u64::from(framebuffer.is_some()),
            memmap: (HHDM_BASE + MEMORY_MAP_PHYS) as *const MemmapEntry,
            memmap_count: memory_map.len() as u64,
            modules: if module.is_some() {
                (HHDM_BASE + MODULE_INFO_PHYS) as *const Module
            } else {
                core::ptr::null()
            },
            modules_count: u64::from(module.is_some()),
            rsdp: ACPI_RSDP_PHYS,
            kernel_cmdline: core::ptr::null(),
        };
        write_struct(&mut self.bus, BOOT_INFO_PHYS, &boot_info)?;

        self.reset_application_processors();
        self.cpu = Cpu::new_with_topology(0, self.cpu_count() as u16, true);
        self.cpu.state.rip = image.entry();
        self.cpu
            .state
            .set_register(Register::Rsp, KERNEL_STACK_TOP - 16);
        self.cpu
            .state
            .set_register(Register::Rdi, HHDM_BASE + BOOT_INFO_PHYS);
        self.cpu.state.cr3 = root;
        self.cpu.state.cr4 = 1 << 5;
        self.cpu.state.cr0 = (1 << 31) | 1 | (1 << 16);
        self.cpu.state.efer = (1 << 8) | (1 << 10) | (1 << 11);
        self.cpu.state.cs = 0x08;
        self.cpu.state.ss = 0x10;
        self.framebuffer = framebuffer;
        Ok(())
    }

    /// Validate a complete `XENITHIM` raw disk, boot its exact kernel/initrd
    /// payloads through the direct long-mode handoff, and attach the same
    /// bytes as a primary-master ATA disk.
    ///
    /// Stage1/stage2 are checksum-verified but not executed: the interpreter
    /// remains a 64-bit execution engine and does not pretend to be BIOS
    /// firmware or a real-mode CPU.
    pub fn load_manifest_image(
        &mut self,
        image: Vec<u8>,
        read_only: bool,
    ) -> Result<ManifestBoot, MachineError> {
        if self.disk.is_some() {
            return Err(MachineError::DiskAlreadyAttached);
        }
        let manifest_start = usize::try_from(DISK_MANIFEST_LBA)
            .ok()
            .and_then(|lba| lba.checked_mul(DISK_MANIFEST_SIZE))
            .ok_or(MachineError::InvalidDiskImage("manifest offset overflow"))?;
        let manifest_sector = image
            .get(manifest_start..manifest_start + DISK_MANIFEST_SIZE)
            .ok_or(MachineError::InvalidDiskImage("missing LBA1 manifest"))?;
        let manifest = DiskManifest::parse(manifest_sector)?;
        let expected_bytes = usize::try_from(manifest.image_sectors())
            .ok()
            .and_then(|sectors| sectors.checked_mul(DISK_MANIFEST_SIZE))
            .ok_or(MachineError::InvalidDiskImage(
                "declared disk size overflow",
            ))?;
        if image.len() != expected_bytes {
            return Err(MachineError::InvalidDiskImage(
                "file length differs from manifest disk size",
            ));
        }

        let stage2 = manifest.find(DiskEntryKind::Stage2)?;
        let kernel = manifest.find(DiskEntryKind::Kernel)?;
        let initrd = manifest.find(DiskEntryKind::Initrd)?;
        let stage2_payload = manifest_payload(&image, stage2)?;
        let kernel_payload = manifest_payload(&image, kernel)?;
        let initrd_payload = manifest_payload(&image, initrd)?;
        stage2.verify_payload(stage2_payload)?;
        kernel.verify_payload(kernel_payload)?;
        initrd.verify_payload(initrd_payload)?;
        self.load_kernel(kernel_payload, Some(initrd_payload))?;

        let result = ManifestBoot {
            kernel_lba: kernel.start_lba,
            kernel_bytes: kernel.byte_len,
            initrd_lba: initrd.start_lba,
            initrd_bytes: initrd.byte_len,
            disk_sectors: manifest.image_sectors(),
        };
        self.attach_ata_disk(image, read_only)?;
        Ok(result)
    }

    /// Boot a complete `XENITHIM` disk through the deterministic legacy-PC
    /// firmware shim, Xenith stage1/stage2 contracts, and the native Xenith
    /// long-mode handoff. Unlike [`load_manifest_image`](Self::load_manifest_image),
    /// this preserves the packaged BIOS stages and uses their physical layout.
    pub fn load_bios_image(
        &mut self,
        image: Vec<u8>,
        read_only: bool,
    ) -> Result<ManifestBoot, MachineError> {
        if self.disk.is_some() {
            return Err(MachineError::DiskAlreadyAttached);
        }
        self.framebuffer = None;
        self.uefi_trace = None;
        self.reset_application_processors();
        let boot = boot_bios_image(&mut self.bus, &mut self.cpu, &image)?;
        self.cpu
            .configure_topology(0, self.cpu_count() as u16, true);
        let cpu_count = self.cpu_count();
        install_acpi_tables(&mut self.bus, cpu_count)?;
        self.bus.write_u64_physical(
            boot.trace.handoff_address + core::mem::offset_of!(XenithBootInfo, rsdp) as u64,
            ACPI_RSDP_PHYS,
        )?;
        let manifest = boot.manifest;
        self.bios_trace = Some(boot.trace);
        self.attach_ata_disk(image, read_only)?;
        Ok(manifest)
    }

    /// Recorded reset/stage transition evidence for the most recent BIOS-shim
    /// boot. Direct kernel and manifest loaders return `None`.
    #[must_use]
    pub fn bios_boot_trace(&self) -> Option<&BiosBootTrace> {
        self.bios_trace.as_ref()
    }

    /// Boot the actual platform-0xEF El Torito entry in a packaged Xenith ISO.
    /// The selected `BOOTX64.EFI` PE instructions execute through the ordinary
    /// long-mode interpreter and may call only Xenith's validated UEFI subset.
    pub fn load_uefi_iso(&mut self, iso: &[u8]) -> Result<(), MachineError> {
        if self.disk.is_some() {
            return Err(MachineError::DiskAlreadyAttached);
        }
        self.framebuffer = None;
        self.bios_trace = None;
        self.uefi_trace = None;
        self.reset_application_processors();
        let processor_count = self.cpu_count() as u16;
        self.cpu = Cpu::new_with_topology(0, processor_count, true);
        install_acpi_tables(&mut self.bus, usize::from(processor_count))?;
        let geometry = self.config.framebuffer.unwrap_or(FramebufferConfig {
            width: 800,
            height: 600,
        });
        let boot = boot_uefi_iso(
            &mut self.bus,
            &mut self.cpu,
            iso,
            geometry.width,
            geometry.height,
        )?;
        self.framebuffer = Some(FramebufferSurface {
            physical: boot.framebuffer.physical,
            width: boot.framebuffer.width,
            height: boot.framebuffer.height,
            pitch: boot.framebuffer.pitch,
        });
        self.uefi_trace = Some(boot.trace);
        Ok(())
    }

    /// PE instruction and UEFI service evidence from the latest ISO boot.
    #[must_use]
    pub fn uefi_boot_trace(&self) -> Option<&UefiIsoBootTrace> {
        self.uefi_trace.as_ref()
    }

    /// Attach sector-aligned bytes as the legacy primary-master ATA disk.
    pub fn attach_ata_disk(&mut self, bytes: Vec<u8>, read_only: bool) -> Result<(), MachineError> {
        if self.disk.is_some() {
            return Err(MachineError::DiskAlreadyAttached);
        }
        let image = AtaDiskImage::new(bytes, read_only)?;
        self.bus.attach(AtaPioDisk::new(image.clone()));
        self.disk = Some(image);
        Ok(())
    }

    #[must_use]
    pub fn disk_image(&self) -> Option<&AtaDiskImage> {
        self.disk.as_ref()
    }

    /// Render the configured 32-bpp linear framebuffer as binary PPM.
    pub fn framebuffer_ppm(&mut self) -> Result<Option<Vec<u8>>, MachineError> {
        let Some(surface) = self.framebuffer else {
            return Ok(None);
        };
        let byte_length = usize::from(surface.pitch)
            .checked_mul(usize::from(surface.height))
            .ok_or(MachineError::InsufficientMemory)?;
        let mut pixels = vec![0_u8; byte_length];
        self.bus.read_physical(surface.physical, &mut pixels)?;
        let mut ppm = format!("P6\n{} {}\n255\n", surface.width, surface.height).into_bytes();
        ppm.reserve(
            usize::from(surface.width)
                .saturating_mul(usize::from(surface.height))
                .saturating_mul(3),
        );
        for y in 0..usize::from(surface.height) {
            let row = y * usize::from(surface.pitch);
            for x in 0..usize::from(surface.width) {
                let offset = row + x * 4;
                ppm.extend_from_slice(&[pixels[offset + 2], pixels[offset + 1], pixels[offset]]);
            }
        }
        Ok(Some(ppm))
    }

    /// Decode the legacy 80x25 colour text plane into a host string.
    pub fn vga_text(&mut self) -> Result<String, MachineError> {
        const VGA_TEXT_PHYS: u64 = 0xB8000;
        const VGA_COLUMNS: usize = 80;
        const VGA_ROWS: usize = 25;
        let mut plane = [0_u8; VGA_COLUMNS * VGA_ROWS * 2];
        self.bus.read_physical(VGA_TEXT_PHYS, &mut plane)?;
        let mut rows = Vec::with_capacity(VGA_ROWS);
        for row_index in 0..VGA_ROWS {
            let row_start = row_index * VGA_COLUMNS * 2;
            let row = &plane[row_start..row_start + VGA_COLUMNS * 2];
            let mut text = String::with_capacity(VGA_COLUMNS);
            for column in 0..VGA_COLUMNS {
                let byte = row[column * 2];
                text.push(if byte == 0 {
                    ' '
                } else if byte.is_ascii_graphic() || byte == b' ' {
                    char::from(byte)
                } else {
                    '\u{fffd}'
                });
            }
            rows.push(text.trim_end().to_owned());
        }
        while rows.last().is_some_and(String::is_empty) {
            rows.pop();
        }
        Ok(rows.join("\n"))
    }

    #[must_use]
    pub fn run(&mut self) -> RunSummary {
        self.run_for(self.config.instruction_limit)
    }

    /// Execute at most `instruction_limit` additional interpreted cycles.
    ///
    /// This leaves [`run`](Self::run)'s configured-limit behavior unchanged
    /// while allowing an interactive host to advance the same machine after
    /// injecting keyboard input.
    #[must_use]
    pub fn run_for(&mut self, instruction_limit: u64) -> RunSummary {
        if self.application_processors.is_empty() {
            return self.run_for_uniprocessor(instruction_limit);
        }
        self.run_for_multiprocessor(instruction_limit)
    }

    fn run_for_uniprocessor(&mut self, instruction_limit: u64) -> RunSummary {
        self.bus.select_processor(0);
        let start = self.cpu.state.cycles;
        let interrupt_start = self.cpu.interrupts_delivered();
        let reason = self.cpu.run(&mut self.bus, instruction_limit);
        self.summary(
            reason,
            self.cpu.state.cycles - start,
            self.cpu.interrupts_delivered() - interrupt_start,
        )
    }

    fn run_for_multiprocessor(&mut self, instruction_limit: u64) -> RunSummary {
        let start_cycles = self.total_cycles();
        let start_interrupts = self.total_interrupts();
        let processor_count = self.cpu_count();
        let mut reason = ExitReason::InstructionLimit;

        for _ in 0..instruction_limit {
            let mut processor = self.scheduler_cursor % processor_count;
            self.scheduler_cursor = (self.scheduler_cursor + 1) % processor_count;
            if processor != 0
                && self.application_processors[processor - 1].lifecycle
                    != ProcessorLifecycle::Running
            {
                // Waiting APs consume no virtual CPU time; keep the BSP at
                // full speed until a SIPI makes another processor runnable.
                processor = 0;
            }

            self.bus.select_processor(processor);
            let exit = if processor == 0 {
                self.cpu.run_cycle(&mut self.bus)
            } else {
                self.application_processors[processor - 1]
                    .cpu
                    .run_cycle(&mut self.bus)
            };
            if let Some(exit) = exit {
                match exit {
                    ExitReason::Halted if processor != 0 => {},
                    other => {
                        reason = other;
                        break;
                    },
                }
            }
            if let Err(fault) = self.apply_apic_events() {
                reason = ExitReason::Fault(fault);
                break;
            }
        }
        self.bus.select_processor(0);
        self.summary(
            reason,
            self.total_cycles().saturating_sub(start_cycles),
            self.total_interrupts().saturating_sub(start_interrupts),
        )
    }

    fn summary(&self, reason: ExitReason, instructions: u64, interrupts: u64) -> RunSummary {
        let serial = self
            .serial
            .lock()
            .map_or_else(|_| Vec::new(), |bytes| bytes.clone());
        RunSummary {
            reason,
            instructions,
            interrupts,
            serial,
        }
    }

    fn total_cycles(&self) -> u64 {
        self.application_processors
            .iter()
            .fold(self.cpu.state.cycles, |total, ap| {
                total.saturating_add(ap.cpu.state.cycles)
            })
    }

    fn total_interrupts(&self) -> u64 {
        self.application_processors
            .iter()
            .fold(self.cpu.interrupts_delivered(), |total, ap| {
                total.saturating_add(ap.cpu.interrupts_delivered())
            })
    }

    fn apply_apic_events(&mut self) -> Result<(), CpuFault> {
        let processor_count = self.cpu_count() as u16;
        while let Some(event) = self.bus.take_apic_event() {
            if event.processor == 0 {
                continue;
            }
            let Some(ap) = self.application_processors.get_mut(event.processor - 1) else {
                continue;
            };
            match event.kind {
                ApicEventKind::Init => {
                    ap.cpu = Cpu::new_with_topology(event.processor as u32, processor_count, false);
                    ap.lifecycle = ProcessorLifecycle::WaitForSipi;
                },
                ApicEventKind::Startup(vector)
                    if ap.lifecycle == ProcessorLifecycle::WaitForSipi =>
                {
                    self.start_application_processor(event.processor, vector)?;
                },
                // The second SIPI in INIT-SIPI-SIPI is ignored after the AP
                // has left wait-for-SIPI, as real local APICs require.
                ApicEventKind::Startup(_) => {},
            }
        }
        Ok(())
    }

    fn start_application_processor(
        &mut self,
        processor: usize,
        vector: u8,
    ) -> Result<(), CpuFault> {
        let apic_id = processor as u32;
        let physical = u64::from(vector) << 12;
        if vector >= 0xA0 {
            return Err(CpuFault::InvalidStartupVector {
                apic_id,
                vector,
                reason: "SIPI vector is outside conventional memory",
            });
        }
        let mut page = [0_u8; PAGE_SIZE as usize];
        self.bus
            .read_physical(physical, &mut page)
            .map_err(CpuFault::Memory)?;
        let gdt_signature: [u8; 24] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0x9a, 0xaf, 0, 0xff, 0xff, 0, 0, 0, 0x92,
            0xcf, 0,
        ];
        let Some(gdt) = page
            .windows(gdt_signature.len())
            .position(|window| window == gdt_signature)
        else {
            return Err(CpuFault::InvalidStartupVector {
                apic_id,
                vector,
                reason: "startup page is not a Xenith AP trampoline",
            });
        };
        let gdtr = gdt + gdt_signature.len();
        let cr3_offset = align_up((gdtr + 12) as u64, 8) as usize;
        let record_end = cr3_offset + 32;
        if record_end > page.len()
            || read_u16(&page, gdtr) != Some(23)
            || read_u32(&page, gdtr + 2) != Some((physical + gdt as u64) as u32)
            || read_u16(&page, gdtr + 10) != Some(0x08)
        {
            return Err(CpuFault::InvalidStartupVector {
                apic_id,
                vector,
                reason: "startup trampoline descriptor record is malformed",
            });
        }
        let cr3 = read_u64(&page, cr3_offset).unwrap_or(0);
        let stack = read_u64(&page, cr3_offset + 8).unwrap_or(0);
        let entry = read_u64(&page, cr3_offset + 16).unwrap_or(0);
        let logical_id = read_u32(&page, cr3_offset + 24).unwrap_or(u32::MAX);
        let expected_apic_id = read_u32(&page, cr3_offset + 28).unwrap_or(u32::MAX);
        if cr3 & (PAGE_SIZE - 1) != 0
            || cr3 > u64::from(u32::MAX)
            || stack == 0
            || entry == 0
            || logical_id as usize != processor
            || expected_apic_id != apic_id
        {
            return Err(CpuFault::InvalidStartupVector {
                apic_id,
                vector,
                reason: "startup trampoline patch values are invalid",
            });
        }

        let rsp = (stack & !0xf)
            .checked_sub(8)
            .ok_or(CpuFault::InvalidStartupVector {
                apic_id,
                vector,
                reason: "startup stack underflow",
            })?;
        let mut cpu = Cpu::new_with_topology(apic_id, self.cpu_count() as u16, false);
        cpu.state.rip = entry;
        cpu.state.set_register(Register::Rsp, rsp);
        cpu.state.set_register(Register::Rbp, 0);
        cpu.state.set_register(Register::Rdi, u64::from(logical_id));
        cpu.state
            .set_register(Register::Rsi, u64::from(expected_apic_id));
        cpu.state.cr3 = cr3;
        cpu.state.cr4 = 1 << 5;
        cpu.state.cr0 = 0x8001_0023;
        cpu.state.efer = (1 << 8) | (1 << 10) | (1 << 11);
        cpu.state.cs = 0x08;
        cpu.state.ss = 0x10;
        cpu.state.ds = 0x10;
        cpu.state.es = 0x10;
        cpu.state.fs = 0x10;
        cpu.state.gs = 0x10;
        cpu.state.gdtr.base = physical + gdt as u64;
        cpu.state.gdtr.limit = 23;
        self.bus.select_processor(processor);
        self.bus
            .write_linear(
                rsp,
                &0_u64.to_le_bytes(),
                PagingContext::new(cpu.state.cr0, cr3, cpu.state.efer, Privilege::Supervisor),
            )
            .map_err(CpuFault::Memory)?;
        let ap = &mut self.application_processors[processor - 1];
        ap.cpu = cpu;
        ap.lifecycle = ProcessorLifecycle::Running;
        Ok(())
    }

    /// Type US-layout ASCII through the emulated 8042 keyboard port.
    ///
    /// Every character becomes keyboard set-1 make/break scancodes. IRQ 1 is
    /// then raised by the controller only when guest initialization enabled
    /// its first port, scanning, and the controller's keyboard-interrupt bit.
    pub fn inject_keyboard_ascii(&mut self, input: &str) -> Result<(), KeyboardInputError> {
        let scancodes =
            encode_ascii_set1(input).map_err(KeyboardInputError::UnsupportedCharacter)?;
        self.inject_keyboard_scancodes(&scancodes)
    }

    /// Queue already encoded keyboard set-1 scancodes.
    pub fn inject_keyboard_scancodes(
        &mut self,
        scancodes: &[u8],
    ) -> Result<(), KeyboardInputError> {
        if self.bus.inject_ps2_scancodes(scancodes) {
            Ok(())
        } else {
            Err(KeyboardInputError::ControllerUnavailable)
        }
    }

    /// Whether the guest has enabled interrupt-driven PS/2 keyboard input.
    ///
    /// CLI frontends use this to retain bounded host input until the kernel
    /// has enabled the controller instead of silently dropping early typing.
    #[must_use]
    pub fn keyboard_input_ready(&self) -> bool {
        self.bus.ps2_keyboard_ready()
    }

    #[must_use]
    pub fn serial_output(&self) -> Vec<u8> {
        self.serial
            .lock()
            .map_or_else(|_| Vec::new(), |bytes| bytes.clone())
    }
}

fn install_acpi_tables(bus: &mut MemoryBus, processor_count: usize) -> Result<(), MemoryError> {
    debug_assert!((1..=MAX_EMULATED_CPUS).contains(&processor_count));

    let mut madt = sdt(b"APIC", 44 + processor_count * 8 + 12, 5);
    madt[36..40].copy_from_slice(&(LAPIC_PHYS as u32).to_le_bytes());
    madt[40..44].copy_from_slice(&1_u32.to_le_bytes());
    for processor in 0..processor_count {
        let offset = 44 + processor * 8;
        madt[offset] = 0;
        madt[offset + 1] = 8;
        madt[offset + 2] = processor as u8;
        madt[offset + 3] = processor as u8;
        madt[offset + 4..offset + 8].copy_from_slice(&1_u32.to_le_bytes());
    }
    let ioapic = 44 + processor_count * 8;
    madt[ioapic] = 1;
    madt[ioapic + 1] = 12;
    madt[ioapic + 2] = 1;
    madt[ioapic + 4..ioapic + 8].copy_from_slice(&(IOAPIC_PHYS as u32).to_le_bytes());
    madt[ioapic + 8..ioapic + 12].copy_from_slice(&0_u32.to_le_bytes());
    finish_sdt_checksum(&mut madt);
    bus.write_physical(ACPI_MADT_PHYS, &madt)?;

    let mut hpet = sdt(b"HPET", 56, 1);
    hpet[40] = 0; // Generic Address Structure: system memory.
    hpet[41] = 64;
    hpet[44..52].copy_from_slice(&HPET_PHYS.to_le_bytes());
    finish_sdt_checksum(&mut hpet);
    bus.write_physical(ACPI_HPET_PHYS, &hpet)?;

    let mut xsdt = sdt(b"XSDT", 52, 1);
    xsdt[36..44].copy_from_slice(&ACPI_MADT_PHYS.to_le_bytes());
    xsdt[44..52].copy_from_slice(&ACPI_HPET_PHYS.to_le_bytes());
    finish_sdt_checksum(&mut xsdt);
    bus.write_physical(ACPI_XSDT_PHYS, &xsdt)?;

    let mut rsdp = [0_u8; 36];
    rsdp[..8].copy_from_slice(b"RSD PTR ");
    rsdp[9..15].copy_from_slice(b"XENITH");
    rsdp[15] = 2;
    rsdp[20..24].copy_from_slice(&36_u32.to_le_bytes());
    rsdp[24..32].copy_from_slice(&ACPI_XSDT_PHYS.to_le_bytes());
    rsdp[8] = checksum_byte(&rsdp[..20]);
    rsdp[32] = checksum_byte(&rsdp);
    bus.write_physical(ACPI_RSDP_PHYS, &rsdp)
}

fn sdt(signature: &[u8; 4], length: usize, revision: u8) -> Vec<u8> {
    let mut table = vec![0_u8; length];
    table[..4].copy_from_slice(signature);
    table[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    table[8] = revision;
    table[10..16].copy_from_slice(b"XENITH");
    table[16..24].copy_from_slice(b"XENITHOS");
    table[24..28].copy_from_slice(&1_u32.to_le_bytes());
    table[28..32].copy_from_slice(b"XENI");
    table[32..36].copy_from_slice(&1_u32.to_le_bytes());
    table
}

fn finish_sdt_checksum(table: &mut [u8]) {
    table[9] = 0;
    table[9] = checksum_byte(table);
}

fn checksum_byte(bytes: &[u8]) -> u8 {
    0_u8.wrapping_sub(bytes.iter().copied().fold(0_u8, u8::wrapping_add))
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn manifest_payload(image: &[u8], entry: DiskEntry) -> Result<&[u8], ManifestError> {
    let start = usize::try_from(entry.start_lba)
        .ok()
        .and_then(|lba| lba.checked_mul(DISK_MANIFEST_SIZE))
        .ok_or(ManifestError::PayloadOutsideImage)?;
    let length = usize::try_from(entry.byte_len).map_err(|_| ManifestError::PayloadOutsideImage)?;
    let end = start
        .checked_add(length)
        .ok_or(ManifestError::PayloadOutsideImage)?;
    image
        .get(start..end)
        .ok_or(ManifestError::PayloadOutsideImage)
}

struct TableAllocator {
    next: u64,
    limit: u64,
}
impl TableAllocator {
    const fn new(next: u64, limit: u64) -> Self {
        Self { next, limit }
    }
    fn allocate(&mut self, bus: &mut MemoryBus) -> Result<u64, MachineError> {
        if self.next + PAGE_SIZE > self.limit {
            return Err(MachineError::InsufficientMemory);
        }
        let frame = self.next;
        self.next += PAGE_SIZE;
        bus.write_physical(frame, &[0; PAGE_SIZE as usize])?;
        Ok(frame)
    }
}

fn map_huge(
    bus: &mut MemoryBus,
    root: u64,
    virtual_address: u64,
    physical_address: u64,
    tables: &mut TableAllocator,
) -> Result<(), MachineError> {
    let indices = [
        (virtual_address >> 39) & 0x1FF,
        (virtual_address >> 30) & 0x1FF,
        (virtual_address >> 21) & 0x1FF,
    ];
    let mut table = root;
    for index in indices[..2].iter().copied() {
        table = next_table(bus, table, index, tables)?;
    }
    bus.write_u64_physical(
        table + indices[2] * 8,
        (physical_address & !(HUGE_PAGE_SIZE - 1)) | 0x83,
    )?;
    Ok(())
}

fn map_page(
    bus: &mut MemoryBus,
    root: u64,
    virtual_address: u64,
    physical_address: u64,
    flags: u64,
    tables: &mut TableAllocator,
) -> Result<(), MachineError> {
    let indices = [
        (virtual_address >> 39) & 0x1FF,
        (virtual_address >> 30) & 0x1FF,
        (virtual_address >> 21) & 0x1FF,
        (virtual_address >> 12) & 0x1FF,
    ];
    let mut table = root;
    for index in indices[..3].iter().copied() {
        table = next_table(bus, table, index, tables)?;
    }
    bus.write_u64_physical(
        table + indices[3] * 8,
        (physical_address & !(PAGE_SIZE - 1)) | flags,
    )?;
    Ok(())
}

fn next_table(
    bus: &mut MemoryBus,
    parent: u64,
    index: u64,
    tables: &mut TableAllocator,
) -> Result<u64, MachineError> {
    let address = parent + index * 8;
    let entry = bus.read_u64_physical(address)?;
    if entry & 1 != 0 {
        if entry & (1 << 7) != 0 {
            return Err(MachineError::InvalidSegment);
        }
        return Ok(entry & 0x000F_FFFF_FFFF_F000);
    }
    let child = tables.allocate(bus)?;
    bus.write_u64_physical(address, child | 3)?;
    Ok(child)
}

fn align_up(value: u64, align: u64) -> u64 {
    value.saturating_add(align - 1) & !(align - 1)
}

fn write_struct<T: Copy>(bus: &mut MemoryBus, address: u64, value: &T) -> Result<(), MachineError> {
    // SAFETY: a shared reference is a valid byte sequence for exactly `size_of::<T>()` bytes.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            core::ptr::from_ref(value).cast::<u8>(),
            core::mem::size_of::<T>(),
        )
    };
    bus.write_physical(address, bytes)?;
    Ok(())
}

fn write_slice<T: Copy>(
    bus: &mut MemoryBus,
    address: u64,
    value: &[T],
) -> Result<(), MachineError> {
    // SAFETY: the slice is contiguous and the byte length is its element count times element size.
    let bytes = unsafe {
        core::slice::from_raw_parts(value.as_ptr().cast::<u8>(), core::mem::size_of_val(value))
    };
    bus.write_physical(address, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_program_writes_serial() {
        let mut machine = Machine::new(MachineConfig {
            memory_bytes: 1024 * 1024,
            instruction_limit: 100,
            mirror_serial: false,
            ..MachineConfig::default()
        });
        machine
            .load_flat(
                0x1000,
                &[0xBA, 0xF8, 0x03, 0, 0, 0xB0, b'X', 0xEE, 0xF4],
                0x80000,
            )
            .unwrap();
        let summary = machine.run();
        assert_eq!(summary.reason, ExitReason::Halted);
        assert_eq!(summary.serial, b"X");
    }

    #[test]
    fn framebuffer_renderer_converts_xrgb_pixels_to_ppm() {
        let mut machine = Machine::new(MachineConfig {
            memory_bytes: 1024 * 1024,
            mirror_serial: false,
            ..MachineConfig::default()
        });
        machine.framebuffer = Some(FramebufferSurface {
            physical: 0x1000,
            width: 2,
            height: 1,
            pitch: 8,
        });
        machine
            .bus
            .write_physical(0x1000, &[0x33, 0x22, 0x11, 0, 0xCC, 0xBB, 0xAA, 0])
            .unwrap();
        assert_eq!(
            machine.framebuffer_ppm().unwrap().unwrap(),
            b"P6\n2 1\n255\n\x11\x22\x33\xAA\xBB\xCC"
        );
    }

    #[test]
    fn vga_renderer_decodes_text_cells_and_trims_blank_rows() {
        let mut machine = Machine::new(MachineConfig {
            memory_bytes: 1024 * 1024,
            mirror_serial: false,
            ..MachineConfig::default()
        });
        machine
            .bus
            .write_physical(0xB8000, &[b'X', 0x07, b'Y', 0x07])
            .unwrap();
        assert_eq!(machine.vga_text().unwrap(), "XY");
    }

    #[test]
    fn framebuffer_geometry_parser_enforces_loader_abi_bounds() {
        assert_eq!(
            FramebufferConfig::parse("800x600"),
            Ok(FramebufferConfig {
                width: 800,
                height: 600,
            })
        );
        assert!(FramebufferConfig::parse("7x600").is_err());
        assert!(FramebufferConfig::parse("20000x600").is_err());
    }

    #[test]
    fn generated_acpi_madt_describes_every_emulated_processor() {
        let mut bus = MemoryBus::new(2 * 1024 * 1024);
        install_acpi_tables(&mut bus, 2).unwrap();
        let mut rsdp = [0_u8; 36];
        bus.read_physical(ACPI_RSDP_PHYS, &mut rsdp).unwrap();
        assert_eq!(&rsdp[..8], b"RSD PTR ");
        assert_eq!(rsdp.iter().copied().fold(0_u8, u8::wrapping_add), 0);

        let mut madt = vec![0_u8; 44 + 2 * 8 + 12];
        bus.read_physical(ACPI_MADT_PHYS, &mut madt).unwrap();
        assert_eq!(&madt[..4], b"APIC");
        assert_eq!(madt.iter().copied().fold(0_u8, u8::wrapping_add), 0);
        assert_eq!(&madt[44..52], &[0, 8, 0, 0, 1, 0, 0, 0]);
        assert_eq!(&madt[52..60], &[0, 8, 1, 1, 1, 0, 0, 0]);
    }

    #[test]
    fn sipi_validates_guest_trampoline_and_starts_target_ap() {
        let mut machine = Machine::new(MachineConfig {
            memory_bytes: 2 * 1024 * 1024,
            cpu_count: 2,
            mirror_serial: false,
            ..MachineConfig::default()
        });
        for (address, value) in [
            (0x1000, 0x2000 | 3),
            (0x2000, 0x3000 | 3),
            (0x3000, 0x4000 | 3),
            (0x4000 + 9 * 8, 0x9000 | 3),
        ] {
            machine.bus.write_u64_physical(address, value).unwrap();
        }
        let mut page = [0_u8; PAGE_SIZE as usize];
        let gdt = 0x100;
        page[gdt..gdt + 24].copy_from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0x9a, 0xaf, 0, 0xff, 0xff, 0, 0, 0, 0x92,
            0xcf, 0,
        ]);
        let gdtr = gdt + 24;
        page[gdtr..gdtr + 2].copy_from_slice(&23_u16.to_le_bytes());
        page[gdtr + 2..gdtr + 6].copy_from_slice(&(0x80000_u32 + gdt as u32).to_le_bytes());
        page[gdtr + 10..gdtr + 12].copy_from_slice(&8_u16.to_le_bytes());
        let record = align_up((gdtr + 12) as u64, 8) as usize;
        page[record..record + 8].copy_from_slice(&0x1000_u64.to_le_bytes());
        page[record + 8..record + 16].copy_from_slice(&0xA000_u64.to_le_bytes());
        page[record + 16..record + 24].copy_from_slice(&0x2000_u64.to_le_bytes());
        page[record + 24..record + 28].copy_from_slice(&1_u32.to_le_bytes());
        page[record + 28..record + 32].copy_from_slice(&1_u32.to_le_bytes());
        machine.bus.write_physical(0x80000, &page).unwrap();

        machine.start_application_processor(1, 0x80).unwrap();
        let ap = &machine.application_processors[0];
        assert_eq!(ap.lifecycle, ProcessorLifecycle::Running);
        assert_eq!(ap.cpu.state.rip, 0x2000);
        assert_eq!(ap.cpu.state.register(Register::Rsp), 0x9ff8);
        assert_eq!(machine.bus.read_u64_physical(0x9ff8), Ok(0));
    }
}
