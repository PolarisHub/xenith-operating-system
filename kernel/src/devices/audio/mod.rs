//! Intel High Definition Audio controller foundation.
//!
//! This is a real hardware bring-up path, not a playback stub. It binds PCI
//! multimedia/audio functions, validates BAR0, enables memory and bus-master
//! transactions, resets the controller and link with the required settling
//! periods, starts bounded CORB/RIRB DMA transport, and queries each codec's
//! identity and function groups. It also exposes validated stream/BDL types
//! for the next layer.
//!
//! Audible PCM is intentionally **not** claimed here. Generic HDA playback
//! requires parsing each codec's widget graph and connection lists, selecting
//! an output path, powering and unmuting every widget, assigning a converter
//! stream/channel, handling EAPD and vendor quirks, and then scheduling PCM
//! buffers. Starting DMA without that topology work is silent at best and can
//! pop or drive the wrong pin at worst.
//!
//! # MMIO mapping invariant
//!
//! Xenith's current PCI drivers access BARs through the boot HHDM. This module
//! validates that BAR0 is non-zero memory space, 128-byte aligned, entirely
//! inside x86-64's 52-bit physical-address width for the register window used,
//! and converts it through [`crate::mm::phys_to_virt`]. The platform/loader
//! must map PCI MMIO through that direct map, matching the existing AHCI and
//! NIC invariant. A future `ioremap` facility should replace this assumption.
//!
//! Register offsets, reset timing, ring layouts, and stream formats follow
//! the Intel High Definition Audio Specification revision 1.0a, principally
//! sections 3.3, 3.6, 4.4, and 5.5.

mod codec;
mod dma;
mod registers;
mod ring;
mod stream;
mod wait;

use core::fmt;

use codec::{
    function_group, subordinate_nodes, PARAM_FUNCTION_GROUP_TYPE, PARAM_REVISION_ID,
    PARAM_SUBORDINATE_NODE_COUNT, PARAM_VENDOR_ID,
};
pub use codec::{CodecInfo, FunctionGroupInfo, Verb};
pub use registers::{
    Capabilities, Version, DPLBASE, DPUBASE, GLOBAL_REGISTER_BYTES, INTCTL_CIE, INTCTL_GIE, INTSTS,
    SSYNC, WAKEEN, WALCLK,
};
use registers::{
    Mmio, CORBCTL, CORBCTL_RUN, GCTL, GCTL_CRST, GCTL_UNSOL, INTCTL, MAX_STREAMS, RIRBCTL,
    RIRBCTL_DMA_ENABLE, STATESTS,
};
use ring::CommandRings;
pub use ring::{Response, RingError, RingSize};
pub use stream::{
    BufferDescriptor, PcmFormat, SampleBits, StreamConfig, StreamDescriptor, StreamError,
};
use xenith_types::PhysAddr;

use crate::devices::pci::enumerate::{self, PciBarKind, PciDevice, PciDriver, PciDriverError};
use crate::devices::pci::{capability, PciAddress, PciCommand};
use crate::mm::KVec;
use crate::sync::SpinLock;

const PCI_CLASS_MULTIMEDIA: u8 = 0x04;
const PCI_SUBCLASS_HDA: u8 = 0x03;
const PCI_PROG_IF_HDA: u8 = 0x00;
const PCI_CAP_ID_POWER_MANAGEMENT: u8 = 0x01;
const HDA_BAR_INDEX: u8 = 0;
/// Covers all global registers and all 30 stream descriptors Xenith can
/// address through INTCTL. The 0x2030 alias registers are not used.
const MMIO_WINDOW_USED: u64 = 0x440;
const MAX_PHYSICAL_EXCLUSIVE: u64 = 1u64 << 52;

/// Ordered controller bring-up phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerPhase {
    Discovered,
    PciEnabled,
    ResetComplete,
    RingsRunning,
    CodecsEnumerated,
    Online,
}

impl ControllerPhase {
    #[must_use]
    const fn can_advance_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Discovered, Self::PciEnabled)
                | (Self::PciEnabled, Self::ResetComplete)
                | (Self::ResetComplete, Self::RingsRunning)
                | (Self::RingsRunning, Self::CodecsEnumerated)
                | (Self::CodecsEnumerated, Self::Online)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BringUpState {
    phase: ControllerPhase,
}

impl BringUpState {
    const fn new() -> Self {
        Self {
            phase: ControllerPhase::Discovered,
        }
    }

    fn advance(&mut self, next: ControllerPhase) -> Result<(), HdaError> {
        if !self.phase.can_advance_to(next) {
            return Err(HdaError::InvalidStateTransition);
        }
        self.phase = next;
        Ok(())
    }
}

/// Controller bring-up failure. All waits and allocations are bounded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HdaError {
    NotHda,
    MissingBar,
    IoBar,
    UnsupportedBar,
    MisalignedBar,
    BarWindowOutsidePhysicalAddressSpace,
    CapabilityListMalformed,
    PowerStateTimeout,
    UnsupportedControllerVersion,
    InvalidStreamCount,
    InvalidStateTransition,
    StreamStopTimeout,
    EngineStopTimeout,
    EnterResetTimeout,
    ExitResetTimeout,
    InvalidVerb,
    Ring(RingError),
}

impl From<RingError> for HdaError {
    fn from(value: RingError) -> Self {
        Self::Ring(value)
    }
}

impl fmt::Display for HdaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotHda => formatter.write_str("not an HDA PCI function"),
            Self::MissingBar => formatter.write_str("BAR0 is unimplemented"),
            Self::IoBar => formatter.write_str("BAR0 is I/O space"),
            Self::UnsupportedBar => formatter.write_str("BAR0 has a reserved memory type"),
            Self::MisalignedBar => formatter.write_str("BAR0 is not 128-byte aligned"),
            Self::BarWindowOutsidePhysicalAddressSpace => {
                formatter.write_str("BAR0 window exceeds 52-bit physical space")
            },
            Self::CapabilityListMalformed => formatter.write_str("malformed PCI capability list"),
            Self::PowerStateTimeout => formatter.write_str("PCI function did not enter D0"),
            Self::UnsupportedControllerVersion => {
                formatter.write_str("controller reports pre-1.0 HDA version")
            },
            Self::InvalidStreamCount => formatter.write_str("GCAP stream count exceeds INTCTL"),
            Self::InvalidStateTransition => formatter.write_str("invalid HDA bring-up transition"),
            Self::StreamStopTimeout => formatter.write_str("stream DMA did not stop"),
            Self::EngineStopTimeout => formatter.write_str("CORB/RIRB DMA did not stop"),
            Self::EnterResetTimeout => formatter.write_str("controller did not enter reset"),
            Self::ExitResetTimeout => formatter.write_str("controller did not leave reset"),
            Self::InvalidVerb => formatter.write_str("codec verb fields are invalid"),
            Self::Ring(error) => write!(formatter, "ring transport error: {error:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MmioBar {
    physical: u64,
}

fn validate_bar(device: &PciDevice) -> Result<MmioBar, HdaError> {
    let bar = device.bar(HDA_BAR_INDEX).ok_or(HdaError::MissingBar)?;
    if bar.address == 0 {
        return Err(HdaError::MissingBar);
    }
    let physical = match bar.kind {
        PciBarKind::Mem32 | PciBarKind::Mem64 => bar.address,
        PciBarKind::Io => return Err(HdaError::IoBar),
        PciBarKind::Mem16 | PciBarKind::Reserved => return Err(HdaError::UnsupportedBar),
    };
    if physical & 0x7f != 0 {
        return Err(HdaError::MisalignedBar);
    }
    let end = physical
        .checked_add(MMIO_WINDOW_USED - 1)
        .ok_or(HdaError::BarWindowOutsidePhysicalAddressSpace)?;
    if end >= MAX_PHYSICAL_EXCLUSIVE {
        return Err(HdaError::BarWindowOutsidePhysicalAddressSpace);
    }
    Ok(MmioBar { physical })
}

/// Runtime snapshot safe to return without exposing controller ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerInfo {
    pub pci_address: PciAddress,
    pub phase: ControllerPhase,
    pub version: Version,
    pub capabilities: Capabilities,
    pub reported_codec_mask: u16,
    pub discovered_codecs: u8,
    pub codec_probe_failures: u8,
    pub corb_size: RingSize,
    pub rirb_size: RingSize,
    pub unsolicited_responses_dropped: u64,
}

/// One initialized HDA controller and its live command transport.
pub struct HdaController {
    pci_address: PciAddress,
    registers: Mmio,
    phase: ControllerPhase,
    version: Version,
    capabilities: Capabilities,
    reported_codec_mask: u16,
    codecs: [Option<CodecInfo>; codec::DISCOVERABLE_CODECS],
    codec_count: u8,
    codec_probe_failures: u8,
    rings: CommandRings,
}

impl HdaController {
    fn initialize(device: &PciDevice) -> Result<Self, HdaError> {
        if !is_hda_controller(device) {
            return Err(HdaError::NotHda);
        }
        let bar = validate_bar(device)?;
        let mut state = BringUpState::new();

        let pci_address = device.address;
        enter_pci_d0(pci_address)?;
        let command_guard = PciEnableGuard::enable(pci_address);
        state.advance(ControllerPhase::PciEnabled)?;

        // SAFETY: `validate_bar` checked the decoded memory BAR and the HHDM
        // invariant is documented at module scope.
        let registers = unsafe {
            Mmio::new(crate::mm::phys_to_virt(PhysAddr::new_truncate(bar.physical)).as_u64())
        };
        let version = registers.version();
        if version.major == 0 {
            return Err(HdaError::UnsupportedControllerVersion);
        }
        let capabilities = registers.capabilities();
        if capabilities.total_streams() > MAX_STREAMS {
            return Err(HdaError::InvalidStreamCount);
        }
        reset_controller(registers, capabilities)?;
        state.advance(ControllerPhase::ResetComplete)?;

        let reported_codec_mask = registers.read16(STATESTS) & 0x7fff;
        // STATESTS is write-one-to-clear. Capture it first, then clear only
        // the codec-presence changes that were observed after reset.
        registers.write16(STATESTS, reported_codec_mask);
        let mut rings = CommandRings::initialize(registers, capabilities.supports_64bit_dma)?;
        state.advance(ControllerPhase::RingsRunning)?;

        let mut codecs: [Option<CodecInfo>; codec::DISCOVERABLE_CODECS] =
            [const { None }; codec::DISCOVERABLE_CODECS];
        let mut codec_count = 0u8;
        let mut codec_probe_failures = 0u8;
        for address in 0..codec::DISCOVERABLE_CODECS as u8 {
            if reported_codec_mask & (1u16 << address) == 0 {
                continue;
            }
            match discover_codec(registers, &mut rings, address) {
                Ok(info) => {
                    ::log::info!(
                        "hda: codec {} vendor/device={:08x}, {} function group(s){}",
                        address,
                        info.vendor_device_id,
                        info.function_groups().len(),
                        if info.groups_truncated {
                            " (truncated)"
                        } else {
                            ""
                        }
                    );
                    codecs[address as usize] = Some(info);
                    codec_count = codec_count.saturating_add(1);
                },
                Err(HdaError::Ring(RingError::ResponseTimeout)) => {
                    codec_probe_failures = codec_probe_failures.saturating_add(1);
                    ::log::warn!("hda: codec {} did not respond to discovery", address);
                },
                Err(error) => {
                    ::log::warn!("hda: codec {} discovery failed: {}", address, error);
                    return Err(error);
                },
            }
        }
        state.advance(ControllerPhase::CodecsEnumerated)?;
        state.advance(ControllerPhase::Online)?;

        ::log::info!(
            "hda: {} version {}.{}, streams in/out/bidir={}/{}/{}, codecs={}/{}, CORB/RIRB={}/{}",
            pci_address,
            version.major,
            version.minor,
            capabilities.input_streams,
            capabilities.output_streams,
            capabilities.bidirectional_streams,
            codec_count,
            reported_codec_mask.count_ones(),
            rings.corb_size().entries(),
            rings.rirb_size().entries(),
        );

        let controller = Self {
            pci_address,
            registers,
            phase: state.phase,
            version,
            capabilities,
            reported_codec_mask,
            codecs,
            codec_count,
            codec_probe_failures,
            rings,
        };
        command_guard.commit();
        Ok(controller)
    }

    #[must_use]
    pub fn info(&self) -> ControllerInfo {
        ControllerInfo {
            pci_address: self.pci_address,
            phase: self.phase,
            version: self.version,
            capabilities: self.capabilities,
            reported_codec_mask: self.reported_codec_mask,
            discovered_codecs: self.codec_count,
            codec_probe_failures: self.codec_probe_failures,
            corb_size: self.rings.corb_size(),
            rirb_size: self.rings.rirb_size(),
            unsolicited_responses_dropped: self.rings.unsolicited_dropped(),
        }
    }

    #[must_use]
    pub fn codec(&self, address: u8) -> Option<&CodecInfo> {
        self.codecs.get(address as usize)?.as_ref()
    }

    pub fn command(&mut self, verb: Verb) -> Result<Response, HdaError> {
        self.rings.command(self.registers, verb).map_err(Into::into)
    }

    #[must_use]
    fn output_stream(&self, ordinal: usize) -> Option<StreamDescriptor> {
        let index = self.capabilities.output_stream_index(ordinal)?;
        Some(StreamDescriptor::new(
            self.registers.stream(index)?,
            self.capabilities.supports_64bit_dma,
        ))
    }
}

fn reset_controller(registers: Mmio, capabilities: Capabilities) -> Result<(), HdaError> {
    // Keep every interrupt source disabled until a shared IRQ/MSI route and
    // worker are installed. Polling the command transport is deterministic.
    registers.write32(INTCTL, 0);
    registers.write16(WAKEEN, 0);
    registers.write32(GCTL, registers.read32(GCTL) & !GCTL_UNSOL);
    registers.write8(CORBCTL, registers.read8(CORBCTL) & !CORBCTL_RUN);
    registers.write8(RIRBCTL, registers.read8(RIRBCTL) & !RIRBCTL_DMA_ENABLE);

    for index in 0..capabilities.total_streams() {
        let stream = registers
            .stream(index)
            .ok_or(HdaError::InvalidStreamCount)?;
        stream.write_control(stream.control() & !(1 << 1));
    }
    let stopped = wait::until(wait::HARDWARE_TIMEOUT_MS, || {
        (0..capabilities.total_streams()).all(|index| {
            registers
                .stream(index)
                .is_some_and(|stream| stream.control() & (1 << 1) == 0)
        }) && registers.read8(CORBCTL) & CORBCTL_RUN == 0
            && registers.read8(RIRBCTL) & RIRBCTL_DMA_ENABLE == 0
    });
    if (0..capabilities.total_streams()).any(|index| {
        registers
            .stream(index)
            .is_some_and(|stream| stream.control() & (1 << 1) != 0)
    }) {
        return Err(HdaError::StreamStopTimeout);
    }
    if !stopped
        && (registers.read8(CORBCTL) & CORBCTL_RUN != 0
            || registers.read8(RIRBCTL) & RIRBCTL_DMA_ENABLE != 0)
    {
        return Err(HdaError::EngineStopTimeout);
    }

    registers.write32(GCTL, registers.read32(GCTL) & !GCTL_CRST);
    if !wait_gctl(registers, false) {
        return Err(HdaError::EnterResetTimeout);
    }
    // One millisecond exceeds the 100 us minimum reset/link-clock settling
    // interval. The wait helper selects PIT before STI and monotonic time at
    // runtime so it never reprograms the global PIT from an active SMP system.
    wait::delay(1);
    registers.write32(GCTL, registers.read32(GCTL) | GCTL_CRST);
    if !wait_gctl(registers, true) {
        return Err(HdaError::ExitResetTimeout);
    }
    // The specification requires at least 521 us (25 frames) after CRST
    // reads back as one before codec discovery. A bounded 1 ms delay safely
    // exceeds it.
    wait::delay(1);
    Ok(())
}

fn wait_gctl(registers: Mmio, expected_set: bool) -> bool {
    wait::until(wait::HARDWARE_TIMEOUT_MS, || {
        (registers.read32(GCTL) & GCTL_CRST != 0) == expected_set
    })
}

fn discover_codec(
    registers: Mmio,
    rings: &mut CommandRings,
    address: u8,
) -> Result<CodecInfo, HdaError> {
    let vendor_device_id = parameter(registers, rings, address, 0, PARAM_VENDOR_ID)?;
    let revision_id = parameter(registers, rings, address, 0, PARAM_REVISION_ID)?;
    let nodes = parameter(registers, rings, address, 0, PARAM_SUBORDINATE_NODE_COUNT)?;
    let (start_node, advertised_count) = subordinate_nodes(nodes);
    let mut info = CodecInfo::new(address, vendor_device_id, revision_id);
    if advertised_count as usize > codec::MAX_FUNCTION_GROUPS {
        info.groups_truncated = true;
    }
    for offset in 0..advertised_count.min(codec::MAX_FUNCTION_GROUPS as u8) {
        let Some(node) = start_node.checked_add(offset) else {
            info.groups_truncated = true;
            break;
        };
        let response = parameter(registers, rings, address, node, PARAM_FUNCTION_GROUP_TYPE)?;
        info.push_group(function_group(node, response));
    }
    Ok(info)
}

fn parameter(
    registers: Mmio,
    rings: &mut CommandRings,
    codec: u8,
    node: u8,
    parameter: u8,
) -> Result<u32, HdaError> {
    let verb = Verb::get_parameter(codec, node, parameter).ok_or(HdaError::InvalidVerb)?;
    Ok(rings.command(registers, verb)?.data)
}

#[must_use]
pub fn is_hda_controller(device: &PciDevice) -> bool {
    device.base_class == PCI_CLASS_MULTIMEDIA
        && device.subclass == PCI_SUBCLASS_HDA
        && device.prog_if == PCI_PROG_IF_HDA
}

struct PciEnableGuard {
    address: PciAddress,
    original_command: u16,
    restore: bool,
}

impl PciEnableGuard {
    fn enable(address: PciAddress) -> Self {
        let original_command = address.read_command();
        let enabled = PciCommand::from_bits_truncate(original_command)
            | PciCommand::MEMORY_SPACE
            | PciCommand::BUS_MASTER;
        address.write_command(enabled.bits());
        Self {
            address,
            original_command,
            restore: true,
        }
    }

    fn commit(mut self) {
        self.restore = false;
    }
}

impl Drop for PciEnableGuard {
    fn drop(&mut self) {
        if self.restore {
            self.address.write_command(self.original_command);
        }
    }
}

fn enter_pci_d0(address: PciAddress) -> Result<(), HdaError> {
    let capabilities = capability::walk(address).map_err(|_| HdaError::CapabilityListMalformed)?;
    let Some(power) = capabilities.find(PCI_CAP_ID_POWER_MANAGEMENT) else {
        return Ok(());
    };
    let pmcsr_offset = power
        .offset
        .checked_add(4)
        .filter(|offset| *offset <= 0xfe)
        .ok_or(HdaError::CapabilityListMalformed)?;
    let original = address.read16(pmcsr_offset);
    if original & 0x03 == 0 {
        return Ok(());
    }
    // PME Status is RW1C; write zero there while changing only Power State.
    address.write16(pmcsr_offset, original & !0x8003);
    // PCI functions leaving D3hot may require up to 10 ms before MMIO is
    // usable. The wait is PIT-backed before STI and monotonic at runtime.
    wait::delay(10);
    if address.read16(pmcsr_offset) & 0x03 != 0 {
        address.write16(pmcsr_offset, original & !0x8000);
        return Err(HdaError::PowerStateTimeout);
    }
    Ok(())
}

static CONTROLLERS: SpinLock<KVec<HdaController>> = SpinLock::new(KVec::new());

struct HdaPciDriver;
static HDA_PCI_DRIVER: HdaPciDriver = HdaPciDriver;

impl PciDriver for HdaPciDriver {
    fn name(&self) -> &'static str {
        "hda"
    }

    fn matches(&self, device: &PciDevice) -> bool {
        is_hda_controller(device)
    }

    fn probe(&self, device: &PciDevice) -> Result<(), PciDriverError> {
        if CONTROLLERS
            .lock()
            .iter()
            .any(|controller| controller.pci_address == device.address)
        {
            return Ok(());
        }
        let controller = HdaController::initialize(device).map_err(|error| {
            ::log::warn!("hda: {} setup failed: {}", device.describe_id(), error);
            match error {
                HdaError::MissingBar
                | HdaError::IoBar
                | HdaError::UnsupportedBar
                | HdaError::MisalignedBar
                | HdaError::BarWindowOutsidePhysicalAddressSpace => PciDriverError::BarUnreadable,
                _ => PciDriverError::ProbeFailed("HDA controller setup failed"),
            }
        })?;
        CONTROLLERS.lock().push(controller);
        Ok(())
    }
}

/// Register the class driver before `pci::enumerate_and_bind` runs.
pub fn register_pci_driver() {
    enumerate::register_driver(&HDA_PCI_DRIVER);
}

#[must_use]
pub fn controller_count() -> usize {
    CONTROLLERS.lock().len()
}

#[must_use]
pub fn controller_info(index: usize) -> Option<ControllerInfo> {
    CONTROLLERS.lock().get(index).map(HdaController::info)
}

#[must_use]
pub fn codec_info(controller: usize, address: u8) -> Option<CodecInfo> {
    CONTROLLERS.lock().get(controller)?.codec(address).copied()
}

/// Execute a validated verb through one controller's serialized transport.
pub fn command(controller: usize, verb: Verb) -> Result<Response, HdaError> {
    CONTROLLERS
        .lock()
        .get_mut(controller)
        .ok_or(HdaError::NotHda)?
        .command(verb)
}

/// Borrow a non-cloneable controller output-stream handle while the registry
/// is locked. The handle cannot be returned or copied out of this closure.
pub fn with_output_stream<R>(
    controller: usize,
    ordinal: usize,
    action: impl FnOnce(&mut StreamDescriptor) -> R,
) -> Option<R> {
    let controllers = CONTROLLERS.lock();
    let mut stream = controllers.get(controller)?.output_stream(ordinal)?;
    Some(action(&mut stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::pci::enumerate::PciHeaderKind;

    fn device(bar0: u32, bar1: u32) -> PciDevice {
        PciDevice {
            address: PciAddress::new(0, 0x1f, 3).unwrap(),
            vendor_id: 0x8086,
            device_id: 0x2668,
            revision: 1,
            prog_if: 0,
            subclass: PCI_SUBCLASS_HDA,
            base_class: PCI_CLASS_MULTIMEDIA,
            header_kind: PciHeaderKind::Device,
            multifunction: false,
            bars: [bar0, bar1, 0, 0, 0, 0],
            interrupt_line: 11,
            interrupt_pin: 1,
        }
    }

    #[test]
    fn class_match_is_vendor_independent_and_exact() {
        let mut hda = device(0xf000_0000, 0);
        assert!(is_hda_controller(&hda));
        hda.vendor_id = 0x10de;
        assert!(is_hda_controller(&hda));
        hda.subclass = 0x01;
        assert!(!is_hda_controller(&hda));
        hda.subclass = PCI_SUBCLASS_HDA;
        hda.prog_if = 1;
        assert!(!is_hda_controller(&hda));
    }

    #[test]
    fn bar_validation_accepts_memory_and_decodes_64bit_address() {
        assert_eq!(
            validate_bar(&device(0xf000_0000, 0)).unwrap().physical,
            0xf000_0000
        );
        // PCI type bits 10b denote a 64-bit memory BAR.
        assert_eq!(
            validate_bar(&device(0x0000_0004, 0x0000_0001))
                .unwrap()
                .physical,
            0x1_0000_0000
        );
    }

    #[test]
    fn bar_validation_rejects_missing_io_misaligned_and_width_overflow() {
        assert_eq!(validate_bar(&device(0, 0)), Err(HdaError::MissingBar));
        assert_eq!(validate_bar(&device(0x1001, 0)), Err(HdaError::IoBar));
        assert_eq!(validate_bar(&device(0x1080, 0)).unwrap().physical, 0x1080);
        // BAR flag masking normally enforces 16-byte alignment; the stronger
        // 128-byte controller-window requirement rejects this base.
        assert_eq!(
            validate_bar(&device(0x1010, 0)),
            Err(HdaError::MisalignedBar)
        );
        let high = (MAX_PHYSICAL_EXCLUSIVE >> 32) as u32;
        assert_eq!(
            validate_bar(&device(0x0000_0004, high)),
            Err(HdaError::BarWindowOutsidePhysicalAddressSpace)
        );
    }

    #[test]
    fn bring_up_state_allows_only_forward_adjacent_transitions() {
        let mut state = BringUpState::new();
        assert_eq!(
            state.advance(ControllerPhase::ResetComplete),
            Err(HdaError::InvalidStateTransition)
        );
        for phase in [
            ControllerPhase::PciEnabled,
            ControllerPhase::ResetComplete,
            ControllerPhase::RingsRunning,
            ControllerPhase::CodecsEnumerated,
            ControllerPhase::Online,
        ] {
            state.advance(phase).unwrap();
        }
        assert_eq!(state.phase, ControllerPhase::Online);
        assert_eq!(
            state.advance(ControllerPhase::Online),
            Err(HdaError::InvalidStateTransition)
        );
    }
}
