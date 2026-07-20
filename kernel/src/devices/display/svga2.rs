//! VMware SVGA II PCI driver and legacy 2D FIFO submission path.
//!
//! The driver keeps Xenith's bootloader-provided linear framebuffer as the
//! scanout allocation. It does not allocate a replacement surface. Attaching
//! negotiates SVGA protocol version 2, validates the fixed SVGA II BAR layout,
//! initializes the shared FIFO, and exposes real `UPDATE`, `RECT_COPY`, fence,
//! and synchronization primitives. Mode-setting remains private until it can
//! update the kernel UI scanout transactionally.
//!
//! PCI MMIO is reached through Xenith's Limine HHDM, matching the existing
//! e1000/AHCI driver architecture. Consequently, successful attachment relies
//! on the kernel-wide invariant that the HHDM covers the validated PCI BAR1
//! and BAR2 physical ranges with suitable device-memory semantics.

use core::hint::spin_loop;
use core::sync::atomic::{fence, Ordering};
use core::{fmt, ptr};

use xenith_types::PhysAddr;

use super::protocol::{
    self, CopyRect, DeviceCapabilities, FenceCommand, FenceSequence, FifoCapabilities, FifoLayout,
    Mode, ModeLimits, ProtocolError, Rect, RectCopyCommand, UpdateCommand,
};
use crate::arch::Port32;
use crate::devices::pci::enumerate::{self, PciBarKind, PciDevice, PciDriver, PciDriverError};
use crate::devices::pci::PciCommand;
use crate::sync::SpinLock;

const DEFAULT_SYNC_POLL_LIMIT: usize = 1_000_000;
const MAX_IO_PORT_BASE: u64 = u16::MAX as u64 - protocol::VALUE_PORT_OFFSET as u64;
const PAGE_MASK: u64 = 4095;
const PHYSICAL_ADDRESS_LIMIT: u64 = 1_u64 << 52;

/// Runtime SVGA failure. Every wait and FIFO submission path is bounded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SvgaError {
    UnsupportedDevice,
    MissingResource,
    InvalidIoBar,
    InvalidMemoryBar,
    ResourceMismatch,
    AddressOutOfRange,
    MemoryManagerUnavailable,
    UnsupportedVersion(u32),
    DeviceDisabled,
    InvalidFifoSize,
    InvalidVramSize,
    Protocol(ProtocolError),
    UnsupportedCapability,
    TooManyRectangles,
    SyncTimeout,
    FenceTimeout,
    AlreadyAttached,
    NotAttached,
}

impl From<ProtocolError> for SvgaError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl fmt::Display for SvgaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedDevice => formatter.write_str("not a VMware SVGA II PCI function"),
            Self::MissingResource => formatter.write_str("required SVGA BAR is absent"),
            Self::InvalidIoBar => formatter.write_str("SVGA BAR0 is not a usable I/O BAR"),
            Self::InvalidMemoryBar => {
                formatter.write_str("SVGA BAR1/BAR2 is not aligned 32-bit memory")
            },
            Self::ResourceMismatch => {
                formatter.write_str("SVGA register-reported address does not match PCI BAR")
            },
            Self::AddressOutOfRange => formatter.write_str("SVGA physical range is invalid"),
            Self::MemoryManagerUnavailable => formatter.write_str("HHDM is not initialized"),
            Self::UnsupportedVersion(id) => write!(formatter, "unsupported SVGA ID {id:#010x}"),
            Self::DeviceDisabled => formatter.write_str("SVGA scanout is not enabled"),
            Self::InvalidFifoSize => formatter.write_str("SVGA FIFO size/header is invalid"),
            Self::InvalidVramSize => formatter.write_str("SVGA VRAM size is invalid"),
            Self::Protocol(error) => {
                write!(formatter, "SVGA protocol validation failed: {error:?}")
            },
            Self::UnsupportedCapability => formatter.write_str("SVGA capability is unavailable"),
            Self::TooManyRectangles => formatter.write_str("too many SVGA update rectangles"),
            Self::SyncTimeout => formatter.write_str("SVGA busy register did not clear"),
            Self::FenceTimeout => formatter.write_str("SVGA fence did not complete"),
            Self::AlreadyAttached => formatter.write_str("an SVGA II adapter is already attached"),
            Self::NotAttached => formatter.write_str("no SVGA II adapter is attached"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Resources {
    io_base: u16,
    framebuffer_physical: u64,
    fifo_physical: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResourceApertures {
    io_bytes: u64,
    framebuffer_bytes: u64,
    fifo_bytes: u64,
}

/// Immutable information about the attached adapter and its current scanout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceInfo {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub svga_id: u32,
    pub capabilities: DeviceCapabilities,
    pub fifo_capabilities: FifoCapabilities,
    pub mode_limits: ModeLimits,
    pub mode: Mode,
    pub framebuffer_physical: u64,
    pub framebuffer_virtual: u64,
    pub framebuffer_aperture_bytes: u64,
    pub fifo_physical: u64,
    pub fifo_bytes: u32,
    pub fifo_aperture_bytes: u64,
}

impl DeviceInfo {
    /// Physical start of the currently visible frontbuffer, including the
    /// device-reported frontbuffer offset inside BAR1.
    #[must_use]
    pub const fn visible_framebuffer_physical(self) -> u64 {
        self.framebuffer_physical + self.mode.framebuffer_offset as u64
    }

    #[must_use]
    pub const fn visible_framebuffer_virtual(self) -> u64 {
        self.framebuffer_virtual + self.mode.framebuffer_offset as u64
    }

    /// Verify that a boot framebuffer descriptor names this exact SVGA
    /// frontbuffer. Root wiring should establish this before forwarding
    /// Xenith UI damage to [`present`].
    #[must_use]
    pub const fn matches_boot_framebuffer(
        self,
        physical_start: u64,
        width: u32,
        height: u32,
        pitch: u32,
        bits_per_pixel: u32,
    ) -> bool {
        physical_start == self.visible_framebuffer_physical()
            && width == self.mode.width
            && height == self.mode.height
            && pitch == self.mode.pitch
            && bits_per_pixel == self.mode.bits_per_pixel
    }
}

#[derive(Clone, Copy)]
struct Registers {
    index: Port32,
    value: Port32,
}

impl Registers {
    const fn new(io_base: u16) -> Self {
        Self {
            index: Port32::new(io_base + protocol::INDEX_PORT_OFFSET),
            value: Port32::new(io_base + protocol::VALUE_PORT_OFFSET),
        }
    }

    #[inline]
    fn read(self, register: u32) -> u32 {
        self.index.write(register);
        self.value.read()
    }

    #[inline]
    fn write(self, register: u32, value: u32) {
        self.index.write(register);
        self.value.write(value);
    }
}

struct Fifo {
    virtual_base: u64,
    mapped_bytes: u32,
    layout: FifoLayout,
    capabilities: FifoCapabilities,
    fences: FenceSequence,
}

impl Fifo {
    /// Initialize only after every BAR/register range has been validated.
    fn initialize(
        registers: Registers,
        virtual_base: u64,
        mapped_bytes: u32,
        minimum: u32,
    ) -> Result<Self, SvgaError> {
        let layout = FifoLayout::new(minimum, mapped_bytes, mapped_bytes)?;
        let mut fifo = Self {
            virtual_base,
            mapped_bytes,
            layout,
            capabilities: FifoCapabilities::default(),
            fences: FenceSequence::new(),
        };

        registers.write(protocol::register::CONFIG_DONE, 0);
        fifo.write_cell(protocol::fifo::MIN, layout.min());
        fifo.write_cell(protocol::fifo::MAX, layout.max());
        fence(Ordering::Release);
        fifo.write_cell(protocol::fifo::NEXT_CMD, layout.min());
        fifo.write_cell(protocol::fifo::STOP, layout.min());
        if fifo.header_contains(protocol::fifo::BUSY) {
            fifo.write_cell(protocol::fifo::BUSY, 0);
        }
        fence(Ordering::SeqCst);
        registers.write(protocol::register::CONFIG_DONE, 1);

        if registers.read(protocol::register::CONFIG_DONE) != 1
            || fifo.read_cell(protocol::fifo::MIN) != layout.min()
            || fifo.read_cell(protocol::fifo::MAX) != layout.max()
        {
            registers.write(protocol::register::CONFIG_DONE, 0);
            return Err(SvgaError::InvalidFifoSize);
        }
        if fifo.header_contains(protocol::fifo::CAPABILITIES) {
            fifo.capabilities =
                FifoCapabilities::from_bits(fifo.read_cell(protocol::fifo::CAPABILITIES));
        }
        Ok(fifo)
    }

    #[inline]
    fn header_contains(&self, index: u32) -> bool {
        index
            .checked_add(1)
            .and_then(|cells| cells.checked_mul(4))
            .is_some_and(|end| end <= self.layout.min() && end <= self.mapped_bytes)
    }

    #[inline]
    fn read_cell(&self, index: u32) -> u32 {
        debug_assert!(index.saturating_mul(4) < self.mapped_bytes);
        // SAFETY: attach validated the complete BAR2 range before translating
        // it through the HHDM. Every caller checks that the cell lies inside
        // either the FIFO header or the validated command ring.
        unsafe { ptr::read_volatile((self.virtual_base + u64::from(index) * 4) as *const u32) }
    }

    #[inline]
    fn write_cell(&mut self, index: u32, value: u32) {
        debug_assert!(index.saturating_mul(4) < self.mapped_bytes);
        // SAFETY: same validated BAR2/HHDM invariant as `read_cell`; mutable
        // access is serialized by the global adapter lock.
        unsafe {
            ptr::write_volatile(
                (self.virtual_base + u64::from(index) * 4) as *mut u32,
                value,
            );
        }
    }

    fn enqueue(&mut self, words: &[u32]) -> Result<(), SvgaError> {
        let bytes = u32::try_from(words.len())
            .ok()
            .and_then(|count| count.checked_mul(4))
            .ok_or(ProtocolError::InvalidCommand)?;
        if words.is_empty() {
            return Err(ProtocolError::InvalidCommand.into());
        }
        if self.read_cell(protocol::fifo::MIN) != self.layout.min()
            || self.read_cell(protocol::fifo::MAX) != self.layout.max()
        {
            return Err(ProtocolError::InvalidFifoLayout.into());
        }
        let mut cursor = self.read_cell(protocol::fifo::NEXT_CMD);
        let stop = self.read_cell(protocol::fifo::STOP);
        let final_cursor = self.layout.reserve(cursor, stop, bytes)?;
        let reserve = self.capabilities.reserve() && self.header_contains(protocol::fifo::RESERVED);

        if reserve {
            self.write_cell(protocol::fifo::RESERVED, bytes);
            fence(Ordering::SeqCst);
        }
        for &word in words {
            let index = cursor / 4;
            self.write_cell(index, word);
            cursor = self.layout.advance(cursor, 4)?;
            if !reserve {
                // VMware's legacy no-RESERVE path publishes one complete
                // dword at a time, matching vmwgfx's slow FIFO commit path.
                fence(Ordering::SeqCst);
                self.write_cell(protocol::fifo::NEXT_CMD, cursor);
                fence(Ordering::SeqCst);
            }
        }
        if reserve {
            fence(Ordering::Release);
            self.write_cell(protocol::fifo::NEXT_CMD, final_cursor);
            fence(Ordering::SeqCst);
            self.write_cell(protocol::fifo::RESERVED, 0);
            fence(Ordering::SeqCst);
        }
        debug_assert_eq!(cursor, final_cursor);
        Ok(())
    }

    fn allocate_fence(&mut self) -> Result<u32, SvgaError> {
        if !self.capabilities.fence() || !self.header_contains(protocol::fifo::FENCE) {
            return Err(SvgaError::UnsupportedCapability);
        }
        Ok(self.fences.allocate())
    }

    fn completed_fence(&self) -> Result<u32, SvgaError> {
        if !self.capabilities.fence() || !self.header_contains(protocol::fifo::FENCE) {
            return Err(SvgaError::UnsupportedCapability);
        }
        Ok(self.read_cell(protocol::fifo::FENCE))
    }
}

struct Svga2 {
    registers: Registers,
    fifo: Fifo,
    info: DeviceInfo,
}

impl Svga2 {
    fn attach(device: &PciDevice) -> Result<Self, SvgaError> {
        if device.vendor_id != protocol::PCI_VENDOR_VMWARE
            || device.device_id != protocol::PCI_DEVICE_SVGA2
            || device.base_class != 0x03
        {
            return Err(SvgaError::UnsupportedDevice);
        }
        let resources = decode_resources(device)?;
        let apertures = probe_resource_apertures(device)?;

        let command = PciCommand::from_bits_truncate(device.address.read_command())
            | PciCommand::IO_SPACE
            | PciCommand::MEMORY_SPACE;
        device.address.write_command(command.bits());

        let registers = Registers::new(resources.io_base);
        registers.write(protocol::register::ID, protocol::SVGA_ID_2);
        let svga_id = registers.read(protocol::register::ID);
        if svga_id != protocol::SVGA_ID_2 {
            return Err(SvgaError::UnsupportedVersion(svga_id));
        }

        let capabilities =
            DeviceCapabilities::from_bits(registers.read(protocol::register::CAPABILITIES));
        let limits = ModeLimits {
            max_width: registers.read(protocol::register::MAX_WIDTH),
            max_height: registers.read(protocol::register::MAX_HEIGHT),
            vram_bytes: registers.read(protocol::register::VRAM_SIZE),
            framebuffer_bytes: registers.read(protocol::register::FB_SIZE),
        }
        .validate()
        .map_err(|_| SvgaError::InvalidVramSize)?;
        let fifo_bytes = registers.read(protocol::register::MEM_SIZE);
        validate_memory_resources(registers, resources, apertures, limits, fifo_bytes)?;

        if registers.read(protocol::register::ENABLE) & protocol::ENABLE_ENABLE == 0 {
            return Err(SvgaError::DeviceDisabled);
        }
        let mode = read_mode(registers, limits)?;
        validate_physical_range(resources.framebuffer_physical, apertures.framebuffer_bytes)?;
        validate_physical_range(resources.fifo_physical, apertures.fifo_bytes)?;
        if !crate::mm::is_initialized() {
            return Err(SvgaError::MemoryManagerUnavailable);
        }

        // No BAR memory is dereferenced before every kind/address/size/range
        // check above succeeds. Xenith's established HHDM mapping contract is
        // then used exactly as by its existing PCI MMIO drivers.
        let framebuffer_virtual =
            crate::mm::phys_to_virt(PhysAddr::new_truncate(resources.framebuffer_physical))
                .as_u64();
        let fifo_virtual =
            crate::mm::phys_to_virt(PhysAddr::new_truncate(resources.fifo_physical)).as_u64();
        let minimum = fifo_minimum(registers, capabilities, fifo_bytes)?;
        let fifo = Fifo::initialize(registers, fifo_virtual, fifo_bytes, minimum)?;

        Ok(Self {
            registers,
            info: DeviceInfo {
                bus: device.address.bus(),
                device: device.address.device(),
                function: device.address.function(),
                svga_id,
                capabilities,
                fifo_capabilities: fifo.capabilities,
                mode_limits: limits,
                mode,
                framebuffer_physical: resources.framebuffer_physical,
                framebuffer_virtual,
                framebuffer_aperture_bytes: apertures.framebuffer_bytes,
                fifo_physical: resources.fifo_physical,
                fifo_bytes,
                fifo_aperture_bytes: apertures.fifo_bytes,
            },
            fifo,
        })
    }

    fn enqueue_with_progress(&mut self, words: &[u32]) -> Result<(), SvgaError> {
        match self.fifo.enqueue(words) {
            Ok(()) => Ok(()),
            Err(SvgaError::Protocol(ProtocolError::FifoFull)) => {
                self.sync(DEFAULT_SYNC_POLL_LIMIT)?;
                self.fifo.enqueue(words)
            },
            Err(error) => Err(error),
        }
    }

    fn present(&mut self, rectangles: &[Rect], wait: bool) -> Result<(), SvgaError> {
        if rectangles.len() > protocol::MAX_PRESENT_RECTS {
            return Err(SvgaError::TooManyRectangles);
        }
        if rectangles.is_empty() {
            Rect::full(self.info.mode).validate(self.info.mode)?;
        } else {
            for &rectangle in rectangles {
                rectangle.validate(self.info.mode)?;
            }
        }

        // Drain Xenith's write-combining framebuffer stores before publishing
        // an UPDATE that allows the host to consume those pixels.
        crate::arch::x86_64::sfence();
        if rectangles.is_empty() {
            let command = UpdateCommand::new(Rect::full(self.info.mode), self.info.mode)?;
            self.enqueue_with_progress(command.words())?;
        } else {
            for &rectangle in rectangles {
                let command = UpdateCommand::new(rectangle, self.info.mode)?;
                self.enqueue_with_progress(command.words())?;
            }
        }
        self.kick();
        if wait {
            self.sync(DEFAULT_SYNC_POLL_LIMIT)?;
        }
        Ok(())
    }

    fn rectangle_copy(&mut self, copy: CopyRect, wait: bool) -> Result<(), SvgaError> {
        if !self.info.capabilities.rect_copy() {
            return Err(SvgaError::UnsupportedCapability);
        }
        let command = RectCopyCommand::new(copy, self.info.mode)?;
        crate::arch::x86_64::sfence();
        self.enqueue_with_progress(command.words())?;
        self.kick();
        if wait {
            self.sync(DEFAULT_SYNC_POLL_LIMIT)?;
        }
        Ok(())
    }

    fn insert_fence(&mut self) -> Result<u32, SvgaError> {
        let sequence = self.fifo.allocate_fence()?;
        let command = FenceCommand::new(sequence)?;
        self.enqueue_with_progress(command.words())?;
        self.kick();
        Ok(sequence)
    }

    fn wait_fence(&mut self, sequence: u32, poll_limit: usize) -> Result<(), SvgaError> {
        if sequence == 0 {
            return Err(ProtocolError::InvalidCommand.into());
        }
        self.kick();
        for _ in 0..poll_limit {
            if FenceSequence::passed(self.fifo.completed_fence()?, sequence) {
                return Ok(());
            }
            spin_loop();
        }
        Err(SvgaError::FenceTimeout)
    }

    #[inline]
    fn kick(&self) {
        fence(Ordering::SeqCst);
        self.registers
            .write(protocol::register::SYNC, protocol::SYNC_GENERIC);
    }

    fn sync(&mut self, poll_limit: usize) -> Result<(), SvgaError> {
        self.kick();
        for _ in 0..poll_limit {
            if self.registers.read(protocol::register::BUSY) == 0 {
                return Ok(());
            }
            spin_loop();
        }
        Err(SvgaError::SyncTimeout)
    }
}

fn decode_resources(device: &PciDevice) -> Result<Resources, SvgaError> {
    let io = device.bar(0).ok_or(SvgaError::MissingResource)?;
    if io.kind != PciBarKind::Io || io.address == 0 || io.address > MAX_IO_PORT_BASE {
        return Err(SvgaError::InvalidIoBar);
    }
    let framebuffer = device.bar(1).ok_or(SvgaError::MissingResource)?;
    let fifo = device.bar(2).ok_or(SvgaError::MissingResource)?;
    if device.bar_is_high_half(1)
        || device.bar_is_high_half(2)
        || framebuffer.kind != PciBarKind::Mem32
        || fifo.kind != PciBarKind::Mem32
        || framebuffer.address == 0
        || fifo.address == 0
        || framebuffer.address & PAGE_MASK != 0
        || fifo.address & PAGE_MASK != 0
        || framebuffer.address == fifo.address
    {
        return Err(SvgaError::InvalidMemoryBar);
    }
    Ok(Resources {
        io_base: io.address as u16,
        framebuffer_physical: framebuffer.address,
        fifo_physical: fifo.address,
    })
}

/// Size the three fixed SVGA II BARs while address decoding is disabled, then
/// restore every BAR and the original command register before returning. This
/// standard PCI all-ones probe runs before any BAR-backed dereference.
fn probe_resource_apertures(device: &PciDevice) -> Result<ResourceApertures, SvgaError> {
    let original_command = device.address.read_command();
    device.address.write_command(original_command & !0x0003);
    let result = (|| {
        Ok(ResourceApertures {
            io_bytes: probe_bar_aperture(device, 0, PciBarKind::Io)?,
            framebuffer_bytes: probe_bar_aperture(device, 1, PciBarKind::Mem32)?,
            fifo_bytes: probe_bar_aperture(device, 2, PciBarKind::Mem32)?,
        })
    })();
    device.address.write_command(original_command);
    result
}

fn probe_bar_aperture(
    device: &PciDevice,
    index: u8,
    expected_kind: PciBarKind,
) -> Result<u64, SvgaError> {
    let original = *device
        .bars
        .get(index as usize)
        .ok_or(SvgaError::MissingResource)?;
    let offset = 0x10_u8 + index * 4;
    device.address.write32(offset, u32::MAX);
    let mask = device.address.read32(offset);
    device.address.write32(offset, original);
    decode_aperture_size(expected_kind, mask)
}

fn decode_aperture_size(kind: PciBarKind, probe_mask: u32) -> Result<u64, SvgaError> {
    let address_mask = match kind {
        PciBarKind::Io => probe_mask & 0xffff_fffc,
        PciBarKind::Mem32 => probe_mask & 0xffff_fff0,
        _ => return Err(SvgaError::InvalidMemoryBar),
    };
    if address_mask == 0 {
        return Err(SvgaError::MissingResource);
    }
    let size = (!address_mask).wrapping_add(1);
    if size == 0 || !size.is_power_of_two() {
        return Err(SvgaError::InvalidMemoryBar);
    }
    Ok(u64::from(size))
}

fn validate_memory_resources(
    registers: Registers,
    resources: Resources,
    apertures: ResourceApertures,
    limits: ModeLimits,
    fifo_bytes: u32,
) -> Result<(), SvgaError> {
    if u64::from(registers.read(protocol::register::FB_START)) != resources.framebuffer_physical
        || u64::from(registers.read(protocol::register::MEM_START)) != resources.fifo_physical
    {
        return Err(SvgaError::ResourceMismatch);
    }
    if limits.vram_bytes == 0 || limits.vram_bytes > protocol::MAX_VRAM_BYTES {
        return Err(SvgaError::InvalidVramSize);
    }
    if apertures.io_bytes < 2
        || apertures.framebuffer_bytes < u64::from(limits.vram_bytes)
        || apertures.fifo_bytes < u64::from(fifo_bytes)
    {
        return Err(SvgaError::ResourceMismatch);
    }
    if !(protocol::MIN_FIFO_BYTES..=protocol::MAX_FIFO_BYTES).contains(&fifo_bytes)
        || !fifo_bytes.is_multiple_of(4)
    {
        return Err(SvgaError::InvalidFifoSize);
    }
    Ok(())
}

fn validate_physical_range(start: u64, length: u64) -> Result<(), SvgaError> {
    if start == 0 || length == 0 {
        return Err(SvgaError::AddressOutOfRange);
    }
    let last = start
        .checked_add(length - 1)
        .ok_or(SvgaError::AddressOutOfRange)?;
    if start >= PHYSICAL_ADDRESS_LIMIT || last >= PHYSICAL_ADDRESS_LIMIT {
        return Err(SvgaError::AddressOutOfRange);
    }
    Ok(())
}

fn fifo_minimum(
    registers: Registers,
    capabilities: DeviceCapabilities,
    fifo_bytes: u32,
) -> Result<u32, SvgaError> {
    let register_bytes = if capabilities.extended_fifo() {
        registers
            .read(protocol::register::MEM_REGS)
            .checked_mul(4)
            .ok_or(SvgaError::InvalidFifoSize)?
    } else {
        4 * (protocol::fifo::STOP + 1)
    };
    let minimum = register_bytes.max(protocol::FIFO_PAGE_BYTES);
    if minimum % 4 != 0
        || minimum
            .checked_add(2 * protocol::FIFO_GUARD_BYTES)
            .is_none_or(|needed| needed > fifo_bytes)
    {
        return Err(SvgaError::InvalidFifoSize);
    }
    Ok(minimum)
}

fn read_mode(registers: Registers, limits: ModeLimits) -> Result<Mode, SvgaError> {
    let mode = Mode {
        width: registers.read(protocol::register::WIDTH),
        height: registers.read(protocol::register::HEIGHT),
        bits_per_pixel: registers.read(protocol::register::BITS_PER_PIXEL),
        depth: registers.read(protocol::register::DEPTH),
        pitch: registers.read(protocol::register::BYTES_PER_LINE),
        framebuffer_offset: registers.read(protocol::register::FB_OFFSET),
        framebuffer_bytes: registers.read(protocol::register::FB_SIZE),
        red_mask: registers.read(protocol::register::RED_MASK),
        green_mask: registers.read(protocol::register::GREEN_MASK),
        blue_mask: registers.read(protocol::register::BLUE_MASK),
    };
    mode.validate(limits).map_err(SvgaError::from)
}

struct Svga2PciDriver;

static PCI_DRIVER: Svga2PciDriver = Svga2PciDriver;
static ACTIVE: SpinLock<Option<Svga2>> = SpinLock::new(None);

impl PciDriver for Svga2PciDriver {
    fn name(&self) -> &'static str {
        "vmware-svga2"
    }

    fn matches(&self, device: &PciDevice) -> bool {
        device.vendor_id == protocol::PCI_VENDOR_VMWARE
            && device.device_id == protocol::PCI_DEVICE_SVGA2
            && device.base_class == 0x03
    }

    fn probe(&self, device: &PciDevice) -> Result<(), PciDriverError> {
        let mut active = ACTIVE.lock();
        if active.is_some() {
            return Err(PciDriverError::ProbeFailed(
                "an SVGA II adapter is already attached",
            ));
        }
        let adapter = Svga2::attach(device).map_err(|error| {
            ::log::warn!("svga2: {} attach failed: {}", device.address, error);
            match error {
                SvgaError::MissingResource
                | SvgaError::InvalidIoBar
                | SvgaError::InvalidMemoryBar
                | SvgaError::ResourceMismatch => PciDriverError::BarUnreadable,
                _ => PciDriverError::ProbeFailed("SVGA II initialization failed"),
            }
        })?;
        let info = adapter.info;
        ::log::info!(
            "svga2: {} attached {}x{}x{} pitch={} FIFO={} KiB caps={:#010x}/{:#010x}",
            device.address,
            info.mode.width,
            info.mode.height,
            info.mode.bits_per_pixel,
            info.mode.pitch,
            info.fifo_bytes / 1024,
            info.capabilities.bits(),
            info.fifo_capabilities.bits(),
        );
        *active = Some(adapter);
        Ok(())
    }
}

/// Register the SVGA II driver before `pci::enumerate_and_bind()` runs.
pub fn register_pci_driver() {
    enumerate::register_driver(&PCI_DRIVER);
}

#[must_use]
pub fn is_attached() -> bool {
    ACTIVE.lock().is_some()
}

#[must_use]
pub fn device_info() -> Option<DeviceInfo> {
    ACTIVE.lock().as_ref().map(|adapter| adapter.info)
}

/// Publish damaged frontbuffer rectangles through real `SVGA_CMD_UPDATE`
/// FIFO commands and return after queueing them. An empty slice updates the
/// complete current scanout. CPU framebuffer stores are fenced first.
pub fn present(rectangles: &[Rect]) -> Result<(), SvgaError> {
    let mut active = ACTIVE.lock();
    active
        .as_mut()
        .ok_or(SvgaError::NotAttached)?
        .present(rectangles, false)
}

/// Same as [`present`], but wait for the legacy BUSY register to clear.
pub fn present_and_wait(rectangles: &[Rect]) -> Result<(), SvgaError> {
    let mut active = ACTIVE.lock();
    active
        .as_mut()
        .ok_or(SvgaError::NotAttached)?
        .present(rectangles, true)
}

/// Submit a capability-gated hardware frontbuffer-to-frontbuffer copy.
pub fn rectangle_copy(copy: CopyRect) -> Result<(), SvgaError> {
    let mut active = ACTIVE.lock();
    active
        .as_mut()
        .ok_or(SvgaError::NotAttached)?
        .rectangle_copy(copy, false)
}

/// Submit a rectangle copy and wait for the legacy engine to become idle.
pub fn rectangle_copy_and_wait(copy: CopyRect) -> Result<(), SvgaError> {
    let mut active = ACTIVE.lock();
    active
        .as_mut()
        .ok_or(SvgaError::NotAttached)?
        .rectangle_copy(copy, true)
}

/// Insert a real FIFO fence when the host advertises `SVGA_FIFO_CAP_FENCE`.
pub fn insert_fence() -> Result<u32, SvgaError> {
    let mut active = ACTIVE.lock();
    active
        .as_mut()
        .ok_or(SvgaError::NotAttached)?
        .insert_fence()
}

/// Poll a FIFO fence with an explicit finite budget.
pub fn wait_fence(sequence: u32, poll_limit: usize) -> Result<(), SvgaError> {
    let mut active = ACTIVE.lock();
    active
        .as_mut()
        .ok_or(SvgaError::NotAttached)?
        .wait_fence(sequence, poll_limit)
}

/// Force FIFO processing and wait with an explicit finite poll budget.
pub fn synchronize(poll_limit: usize) -> Result<(), SvgaError> {
    let mut active = ACTIVE.lock();
    active
        .as_mut()
        .ok_or(SvgaError::NotAttached)?
        .sync(poll_limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::pci::config::PciAddress;

    fn device(bars: [u32; 6]) -> PciDevice {
        PciDevice {
            address: PciAddress::new(0, 15, 0).unwrap(),
            vendor_id: protocol::PCI_VENDOR_VMWARE,
            device_id: protocol::PCI_DEVICE_SVGA2,
            revision: 0,
            prog_if: 0,
            subclass: 0,
            base_class: 3,
            header_kind: enumerate::PciHeaderKind::Device,
            multifunction: false,
            bars,
            interrupt_line: 0,
            interrupt_pin: 0,
        }
    }

    #[test]
    fn fixed_svga2_bar_layout_is_decoded_exactly() {
        let resources =
            decode_resources(&device([0x1001, 0xe000_0008, 0xe800_0000, 0, 0, 0])).unwrap();
        assert_eq!(resources.io_base, 0x1000);
        assert_eq!(resources.framebuffer_physical, 0xe000_0000);
        assert_eq!(resources.fifo_physical, 0xe800_0000);
    }

    #[test]
    fn memory_bar_kind_alignment_and_aliasing_are_rejected() {
        for bars in [
            [0x1001, 0x0000_2001, 0xe800_0000, 0, 0, 0],
            [0x1001, 0xe000_0004, 0xe800_0000, 0, 0, 0],
            [0x1001, 0xe000_0000, 0xe000_0000, 0, 0, 0],
        ] {
            assert_eq!(
                decode_resources(&device(bars)),
                Err(SvgaError::InvalidMemoryBar)
            );
        }
    }

    #[test]
    fn port_bar_must_fit_x86_port_space() {
        assert_eq!(
            decode_resources(&device([0xffff_0001, 0xe000_0000, 0xe800_0000, 0, 0, 0,])),
            Err(SvgaError::InvalidIoBar)
        );
    }

    #[test]
    fn pci_aperture_masks_decode_to_exact_power_of_two_sizes() {
        assert_eq!(decode_aperture_size(PciBarKind::Io, 0xffff_fff1), Ok(16));
        assert_eq!(
            decode_aperture_size(PciBarKind::Mem32, 0xf000_0008),
            Ok(256 * 1024 * 1024)
        );
        assert_eq!(
            decode_aperture_size(PciBarKind::Mem32, 0xffe0_0000),
            Ok(2 * 1024 * 1024)
        );
    }

    #[test]
    fn malformed_pci_aperture_masks_are_rejected() {
        assert_eq!(
            decode_aperture_size(PciBarKind::Mem32, 0),
            Err(SvgaError::MissingResource)
        );
        assert_eq!(
            decode_aperture_size(PciBarKind::Mem32, 0xff00_1000),
            Err(SvgaError::InvalidMemoryBar)
        );
        assert_eq!(
            decode_aperture_size(PciBarKind::Mem64, 0xffff_f000),
            Err(SvgaError::InvalidMemoryBar)
        );
    }

    #[test]
    fn physical_ranges_reject_zero_overflow_and_noncanonical_addresses() {
        assert_eq!(
            validate_physical_range(0, 4096),
            Err(SvgaError::AddressOutOfRange)
        );
        assert_eq!(
            validate_physical_range(u64::MAX - 8, 16),
            Err(SvgaError::AddressOutOfRange)
        );
        assert_eq!(
            validate_physical_range(1_u64 << 52, 4096),
            Err(SvgaError::AddressOutOfRange)
        );
        assert_eq!(validate_physical_range(0xe000_0000, 4096), Ok(()));
    }
}
