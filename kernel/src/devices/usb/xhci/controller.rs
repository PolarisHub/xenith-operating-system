//! Bounded root-port xHCI enumeration and HID interrupt-report transport.
//!
//! This is a real polling/interrupt-capable vertical slice, not a descriptor
//! mock: it resets the controller, owns command/event rings, addresses root
//! devices, executes EP0 control transfers, configures boot-HID interrupt-IN
//! endpoints, and continuously requeues Normal TRBs after reports complete.
//! The deliberately narrow boundary is direct root-port devices only. USB
//! hubs, non-HID classes, arbitrary report descriptors, streams, and
//! isochronous transfers are not claimed here.

use core::hint::spin_loop;

use xenith_types::PhysAddr;

use super::context::{
    descriptor_ep0_packet_size, endpoint_dci, initial_ep0_packet_size, interval_for_speed,
    ContextSize, EndpointContext, EndpointType, InputContext, EP0_DCI,
};
use super::registers::{
    Capabilities, PortProtocols, RegisterError, Registers, ResolvedPortSpeed, PORT_CHANGE_BITS,
    PORT_CONNECT_CHANGE, PORT_CURRENT_CONNECT_STATUS, PORT_ENABLED, PORT_POWER, PORT_RESET,
    PORT_RESET_CHANGE, PORT_WARM_RESET, PORT_WARM_RESET_CHANGE,
};
use super::ring::{DmaArena, DmaSlice, DmaSubArena, EventRing, ProducerRing, RingError};
use super::trb::{CompletionCode, Event, SetupDirection, Trb};
use crate::devices::pci::enumerate::{PciBarKind, PciDevice};
use crate::devices::pci::{PciCommand, PciDevice as CompactPciDevice};
use crate::devices::usb::descriptor::{
    configuration_total_length, device_ep0_packet_byte, parse_boot_configuration, BootInterface,
    BootProtocol, DescriptorError, DESCRIPTOR_CONFIGURATION, DESCRIPTOR_DEVICE,
    MAX_BOOT_INTERFACES,
};
use crate::devices::usb::hid::{BootKeyboard, BootMouse};

const PCI_CLASS_SERIAL_BUS: u8 = 0x0c;
const PCI_SUBCLASS_USB: u8 = 0x03;
const PCI_PROG_IF_XHCI: u8 = 0x30;

/// Xenith intentionally enables at most sixteen xHCI slots. This bounds DMA
/// memory and hotplug work while covering the directly attached ports of the
/// VM and ordinary desktops. Hubs are not enumerated by this layer.
pub const MAX_DEVICES: usize = 16;
const MAX_SCRATCHPADS: usize = 32;
const MAX_CONFIGURATION_BYTES: usize = 2048;
const MAX_INTERRUPT_PAYLOAD: usize = 3072;
const MAX_EVENTS_PER_DRAIN: usize = 128;
const COMMAND_TIMEOUT_MS: u16 = 1_000;
const CONTROL_TIMEOUT_MS: u16 = 1_000;
const TRANSFER_ERROR_LOG_INTERVAL_NS: u64 = 1_000_000_000;
const PORT_RESET_TIMEOUT_MS: u16 = 1_000;
const HOTPLUG_RETRY_BASE_NS: u64 = 100_000_000;
const HOTPLUG_RETRY_LIMIT: u8 = 5;
const BASE_ARENA_BYTES: usize = 32 * 1024;
// Worst-case 64-byte input/output contexts, EP0 storage, four transfer rings,
// and four maximum-sized interrupt buffers fit without spilling into another
// slot. Each window is reset only after Disable Slot completes.
const DEVICE_ARENA_BYTES: usize = 48 * 1024;

const REQUEST_GET_DESCRIPTOR: u8 = 6;
const REQUEST_SET_CONFIGURATION: u8 = 9;
const HID_REQUEST_SET_IDLE: u8 = 10;
const HID_REQUEST_SET_PROTOCOL: u8 = 11;

/// Controller/enumeration failure. Errors are value-only and allocation-free
/// so they are safe to retain in boot diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerError {
    NotXhci,
    InvalidBar,
    InvalidMmioAddress,
    Register(RegisterError),
    Ring(RingError),
    TooManyScratchpads,
    DmaLayout,
    CommandTimeout,
    TransferTimeout,
    CommandFailed(CompletionCode),
    TransferFailed(CompletionCode),
    PortResetTimeout,
    PortDisconnected,
    UnsupportedSpeed(u8),
    NoSlot,
    SlotOutOfRange(u8),
    Descriptor(DescriptorError),
    DescriptorTooLarge,
    NoBootHid,
    InvalidEndpoint,
    ControllerFailed,
}

impl From<RegisterError> for ControllerError {
    fn from(error: RegisterError) -> Self {
        Self::Register(error)
    }
}

impl From<RingError> for ControllerError {
    fn from(error: RingError) -> Self {
        Self::Ring(error)
    }
}

impl From<DescriptorError> for ControllerError {
    fn from(error: DescriptorError) -> Self {
        Self::Descriptor(error)
    }
}

impl ControllerError {
    /// Failures that may disappear after a device settles or a slot becomes
    /// available. Protocol/layout failures are deterministic and are never
    /// retried in the background.
    const fn hotplug_retryable(self) -> bool {
        matches!(
            self,
            Self::CommandTimeout
                | Self::TransferTimeout
                | Self::CommandFailed(_)
                | Self::TransferFailed(_)
                | Self::PortResetTimeout
                | Self::NoSlot
        )
    }
}

#[derive(Clone, Copy, Debug)]
enum Decoder {
    Keyboard(BootKeyboard),
    Mouse(BootMouse),
}

#[derive(Clone, Copy, Debug)]
struct HidFunction {
    interface_number: u8,
    dci: u8,
    max_packet: u16,
    report_length: u16,
    interval: u8,
    max_burst: u8,
    report_buffer: DmaSlice,
    transfer_ring: ProducerRing,
    pending_trb: u64,
    decoder: Decoder,
}

#[derive(Debug)]
struct Device {
    slot_id: u8,
    root_port: u8,
    raw_speed_id: u8,
    semantic_speed: u8,
    vendor_id: u16,
    product_id: u16,
    input_context: DmaSlice,
    control_buffer: DmaSlice,
    control_ring: ProducerRing,
    ep0_max_packet: u16,
    functions: [Option<HidFunction>; MAX_BOOT_INTERFACES],
    function_count: usize,
}

impl Device {
    fn empty(
        slot_id: u8,
        root_port: u8,
        speed: ResolvedPortSpeed,
        input_context: DmaSlice,
        control_buffer: DmaSlice,
        control_ring: ProducerRing,
        ep0_max_packet: u16,
    ) -> Self {
        Self {
            slot_id,
            root_port,
            raw_speed_id: speed.raw_speed_id,
            semantic_speed: speed.semantic.canonical_id(),
            vendor_id: 0,
            product_id: 0,
            input_context,
            control_buffer,
            control_ring,
            ep0_max_packet,
            functions: [None; MAX_BOOT_INTERFACES],
            function_count: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TransferFault {
    slot_id: u8,
    endpoint_id: u8,
    code: CompletionCode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PortRetry {
    port_id: u8,
    attempt: u8,
    deadline_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PortServiceAction {
    None,
    Disconnect,
    Enumerate,
    Reconnect,
}

const fn port_service_action(
    connected: bool,
    has_device: bool,
    connection_changed: bool,
) -> PortServiceAction {
    match (connected, has_device, connection_changed) {
        (false, true, _) => PortServiceAction::Disconnect,
        (true, false, _) => PortServiceAction::Enumerate,
        // If CCS toggled off and on before the 4 ms worker ran, the final CCS
        // alone looks unchanged. CSC is the ownership fence telling us that
        // the existing slot belongs to the previous physical connection.
        (true, true, true) => PortServiceAction::Reconnect,
        _ => PortServiceAction::None,
    }
}

const fn hotplug_retry_delay_ns(attempt: u8) -> Option<u64> {
    if attempt == 0 || attempt > HOTPLUG_RETRY_LIMIT {
        return None;
    }
    Some(HOTPLUG_RETRY_BASE_NS << (attempt - 1))
}

/// One initialized xHCI host controller and its directly attached HID slots.
pub struct XhciController {
    registers: Registers,
    pci: crate::devices::pci::PciAddress,
    capabilities: Capabilities,
    port_protocols: PortProtocols,
    context_size: ContextSize,
    enabled_slots: u8,
    arena: DmaArena,
    dcbaa: DmaSlice,
    command_ring: ProducerRing,
    event_ring: EventRing,
    device_dma: [DmaSubArena; MAX_DEVICES],
    devices: [Option<Device>; MAX_DEVICES],
    pending_ports: [u64; 4],
    port_retries: [Option<PortRetry>; MAX_DEVICES],
    recovery_slots: u16,
    events_since_publish: usize,
    event_ack_pending: bool,
    transfer_error_total: u64,
    transfer_errors_pending: u64,
    last_transfer_fault: Option<TransferFault>,
    last_transfer_error_log: Option<crate::time::Instant>,
    fatal_status_pending: bool,
    failed: bool,
}

impl XhciController {
    /// Validate BAR0 and bring a class-matched xHCI function online.
    pub fn new(device: &PciDevice) -> Result<Self, ControllerError> {
        if !is_xhci(device) {
            return Err(ControllerError::NotXhci);
        }
        let bar = device.bar(0).ok_or(ControllerError::InvalidBar)?;
        if device.bar_is_high_half(0)
            || !matches!(bar.kind, PciBarKind::Mem32 | PciBarKind::Mem64)
            || bar.address == 0
            || bar.address & 0x0f != 0
        {
            return Err(ControllerError::InvalidBar);
        }
        let physical = PhysAddr::new(bar.address).ok_or(ControllerError::InvalidMmioAddress)?;
        let virtual_address = crate::mm::phys_to_virt(physical).as_u64();

        let compact = CompactPciDevice {
            bus: device.address.bus(),
            dev: device.address.device(),
            func: device.address.function(),
            vendor: device.vendor_id,
            device: device.device_id,
            class: (u32::from(device.base_class) << 16)
                | (u32::from(device.subclass) << 8)
                | u32::from(device.prog_if),
            bars: device.bars,
            irq: device.interrupt_line,
        };
        let pci = compact.address();
        let mut command = PciCommand::from_bits_truncate(pci.read_command());
        command.insert(PciCommand::MEMORY_SPACE);
        // Do not permit DMA until every controller-owned pointer is valid.
        // This also makes all construction failures before `start` harmless.
        command.remove(PciCommand::BUS_MASTER);
        // Keep legacy INTx disabled throughout setup. The owner chooses MSI
        // after this controller has been published in the global registry.
        command.insert(PciCommand::INTERRUPT_DISABLE);
        pci.write_command(command.bits());

        // SAFETY: BAR validation above rejects zero/I/O/misaligned addresses;
        // Xenith's boot contract maps physical PCI MMIO through the HHDM for
        // the kernel lifetime, matching the AHCI/IOAPIC mapping invariant.
        let registers = unsafe { Registers::new(virtual_address) }?;
        let capabilities = registers.capabilities();
        if usize::from(capabilities.max_scratchpad_buffers) > MAX_SCRATCHPADS {
            return Err(ControllerError::TooManyScratchpads);
        }
        registers.take_ownership()?;
        let port_protocols = registers.port_protocols()?;
        if !port_protocols.capability_present() {
            ::log::warn!(
                "xhci: {:02x}:{:02x}.{} has no Supported Protocol capability; using legacy slot type/speed IDs",
                pci.bus(),
                pci.device(),
                pci.function()
            );
        }
        registers.reset()?;

        let enabled_slots = capabilities.max_slots.min(MAX_DEVICES as u8);
        let context_size = if capabilities.context_size_64 {
            ContextSize::Bytes64
        } else {
            ContextSize::Bytes32
        };
        let scratch_bytes = usize::from(capabilities.max_scratchpad_buffers)
            .checked_mul(4096)
            .ok_or(ControllerError::DmaLayout)?;
        let arena_bytes = BASE_ARENA_BYTES
            .checked_add(MAX_DEVICES * DEVICE_ARENA_BYTES)
            .and_then(|bytes| bytes.checked_add(scratch_bytes))
            .ok_or(ControllerError::DmaLayout)?;
        let max_address = (!capabilities.supports_64bit_addresses).then_some(u64::from(u32::MAX));
        let mut arena = DmaArena::new(arena_bytes, max_address)?;

        let dcbaa = arena.allocate(256 * 8, 64)?;
        Self::initialize_scratchpads(&mut arena, dcbaa, capabilities.max_scratchpad_buffers)?;
        let command_ring = ProducerRing::allocate(&mut arena)?;
        let event_ring = EventRing::allocate(&mut arena)?;
        let erst = arena.allocate(64, 64)?;
        arena
            .write_u64(erst, 0, event_ring.physical())
            .ok_or(ControllerError::DmaLayout)?;
        arena
            .write_u32(erst, 2, u32::from(event_ring.segment_size()))
            .ok_or(ControllerError::DmaLayout)?;
        let device_region = arena.allocate(MAX_DEVICES * DEVICE_ARENA_BYTES, 4096)?;
        let device_dma = core::array::from_fn(|index| {
            let offset = index * DEVICE_ARENA_BYTES;
            DmaSubArena::new(DmaSlice {
                offset: device_region.offset + offset,
                len: DEVICE_ARENA_BYTES,
                physical: device_region.physical + offset as u64,
            })
        });
        arena.sync_for_device();

        // Some xHC implementations fetch ERST immediately when ERSTBA/ERDP
        // are programmed, even while halted. All DMA objects are complete and
        // published now, so enable PCI bus mastering before exposing those
        // addresses (and still before Run/Stop is set).
        let mut command = PciCommand::from_bits_truncate(pci.read_command());
        command.insert(PciCommand::BUS_MASTER | PciCommand::INTERRUPT_DISABLE);
        pci.write_command(command.bits());
        registers.program_dcbaa(dcbaa.physical);
        registers.program_command_ring(command_ring.physical(), true);
        registers.program_event_ring(erst.physical, event_ring.physical());
        registers.set_max_slots(enabled_slots);
        if let Err(error) = registers.start() {
            let _ = registers.stop();
            // A failed stop wait must not leave a running xHC able to reach
            // arena pages that this constructor is about to release.
            let mut command = PciCommand::from_bits_truncate(pci.read_command());
            command.remove(PciCommand::BUS_MASTER);
            command.insert(PciCommand::INTERRUPT_DISABLE);
            pci.write_command(command.bits());
            return Err(error.into());
        }

        ::log::info!(
            "xhci: {:02x}:{:02x}.{} v{}.{:02x}, {} ports, {} slots, {}-byte contexts, {} scratchpads",
            pci.bus(),
            pci.device(),
            pci.function(),
            capabilities.interface_version >> 8,
            capabilities.interface_version & 0xff,
            capabilities.max_ports,
            enabled_slots,
            context_size.bytes(),
            capabilities.max_scratchpad_buffers
        );

        let mut controller = Self {
            registers,
            pci,
            capabilities,
            port_protocols,
            context_size,
            enabled_slots,
            arena,
            dcbaa,
            command_ring,
            event_ring,
            device_dma,
            devices: [const { None }; MAX_DEVICES],
            pending_ports: [0; 4],
            port_retries: [const { None }; MAX_DEVICES],
            recovery_slots: 0,
            events_since_publish: 0,
            event_ack_pending: false,
            transfer_error_total: 0,
            transfer_errors_pending: 0,
            last_transfer_fault: None,
            last_transfer_error_log: None,
            fatal_status_pending: false,
            failed: false,
        };
        controller.enumerate_initial_ports();
        if controller.failed {
            return Err(ControllerError::ControllerFailed);
        }
        Ok(controller)
    }

    fn initialize_scratchpads(
        arena: &mut DmaArena,
        dcbaa: DmaSlice,
        count: u16,
    ) -> Result<(), ControllerError> {
        if count == 0 {
            return Ok(());
        }
        let pointers = arena.allocate(usize::from(count) * 8, 64)?;
        for index in 0..usize::from(count) {
            let buffer = arena.allocate(4096, 4096)?;
            arena
                .write_u64(pointers, index, buffer.physical)
                .ok_or(ControllerError::DmaLayout)?;
        }
        arena
            .write_u64(dcbaa, 0, pointers.physical)
            .ok_or(ControllerError::DmaLayout)
    }

    fn enumerate_initial_ports(&mut self) {
        for port in 1..=self.capabilities.max_ports {
            if self.registers.port_status(port) & PORT_CURRENT_CONNECT_STATUS == 0 {
                continue;
            }
            match self.enumerate_port(port) {
                Ok(()) => {},
                Err(ControllerError::NoBootHid) => {
                    ::log::debug!("xhci: port {} has no HID boot interface", port);
                },
                Err(error) if !self.failed && error.hotplug_retryable() => {
                    self.schedule_port_retry(port, error);
                },
                Err(error) => {
                    ::log::warn!("xhci: port {} enumeration failed: {:?}", port, error);
                },
            }
        }
    }

    fn enumerate_port(&mut self, port: u8) -> Result<(), ControllerError> {
        let speed = self.reset_port(port)?;
        let slot_id = self.enable_slot(speed.slot_type)?;
        if slot_id == 0 || slot_id > self.enabled_slots || usize::from(slot_id) > MAX_DEVICES {
            if slot_id != 0 && self.disable_slot(slot_id).is_err() && !self.failed {
                self.fail_stop("Disable Slot failed after invalid slot allocation");
            }
            return Err(ControllerError::SlotOutOfRange(slot_id));
        }
        let result = self.enumerate_slot(slot_id, port, speed);
        if let Err(error) = result {
            // A completed Disable Slot command is the ownership fence that
            // makes every context/ring in this slot's fixed window reusable.
            match self.disable_slot(slot_id) {
                Ok(()) => {
                    let _ = self.arena.write_u64(self.dcbaa, usize::from(slot_id), 0);
                    if let Err(reset_error) = self.reset_slot_dma(slot_id) {
                        ::log::warn!(
                            "xhci: slot {} DMA recycle failed after enumeration error: {:?}",
                            slot_id,
                            reset_error
                        );
                    }
                },
                Err(_) if !self.failed => {
                    self.fail_stop("Disable Slot failed during enumeration cleanup");
                },
                Err(_) => {},
            }
            return Err(error);
        }
        Ok(())
    }

    fn reset_port(&self, port: u8) -> Result<ResolvedPortSpeed, ControllerError> {
        if self.registers.port_status(port) & PORT_CURRENT_CONNECT_STATUS == 0 {
            return Err(ControllerError::PortDisconnected);
        }
        self.registers
            .write_port_status(port, PORT_POWER, PORT_CHANGE_BITS);
        self.registers
            .write_port_status(port, PORT_POWER | PORT_RESET, 0);
        let reset = super::wait::until(PORT_RESET_TIMEOUT_MS, || {
            let status = self.registers.port_status(port);
            status & PORT_CURRENT_CONNECT_STATUS == 0 || status & PORT_RESET == 0
        });
        if !reset {
            return Err(ControllerError::PortResetTimeout);
        }
        let status = self.registers.port_status(port);
        if status & PORT_CURRENT_CONNECT_STATUS == 0 {
            return Err(ControllerError::PortDisconnected);
        }
        if status & PORT_ENABLED == 0 {
            // SuperSpeed links can require a Warm Port Reset rather than PR.
            self.registers
                .write_port_status(port, PORT_POWER | PORT_WARM_RESET, PORT_RESET_CHANGE);
            if !super::wait::until(PORT_RESET_TIMEOUT_MS, || {
                let status = self.registers.port_status(port);
                status & PORT_CURRENT_CONNECT_STATUS == 0
                    || (status & PORT_WARM_RESET == 0 && status & PORT_ENABLED != 0)
            }) {
                return Err(ControllerError::PortResetTimeout);
            }
            if self.registers.port_status(port) & PORT_CURRENT_CONNECT_STATUS == 0 {
                return Err(ControllerError::PortDisconnected);
            }
        }
        self.registers.write_port_status(
            port,
            PORT_POWER,
            PORT_RESET_CHANGE | PORT_WARM_RESET_CHANGE,
        );
        let raw_speed_id = self.registers.port_speed(port);
        let speed = self
            .port_protocols
            .resolve(port, raw_speed_id)
            .ok_or(ControllerError::UnsupportedSpeed(raw_speed_id))?;
        initial_ep0_packet_size(speed.semantic.canonical_id())
            .ok_or(ControllerError::UnsupportedSpeed(raw_speed_id))?;
        Ok(speed)
    }

    fn enumerate_slot(
        &mut self,
        slot_id: u8,
        root_port: u8,
        speed: ResolvedPortSpeed,
    ) -> Result<(), ControllerError> {
        let slot_index = usize::from(slot_id - 1);
        self.reset_slot_dma(slot_id)?;
        let output_context =
            self.device_dma[slot_index].allocate(self.context_size.output_bytes(), 64)?;
        let input_context =
            self.device_dma[slot_index].allocate(self.context_size.input_bytes(), 64)?;
        let control_buffer = self.device_dma[slot_index].allocate(MAX_CONFIGURATION_BYTES, 64)?;
        let control_ring =
            ProducerRing::allocate_in(&mut self.arena, &mut self.device_dma[slot_index])?;
        let semantic_speed = speed.semantic.canonical_id();
        let ep0_max_packet = initial_ep0_packet_size(semantic_speed)
            .ok_or(ControllerError::UnsupportedSpeed(speed.raw_speed_id))?;
        let mut device = Device::empty(
            slot_id,
            root_port,
            speed,
            input_context,
            control_buffer,
            control_ring,
            ep0_max_packet,
        );
        self.arena
            .write_u64(self.dcbaa, usize::from(slot_id), output_context.physical)
            .ok_or(ControllerError::DmaLayout)?;
        self.prepare_address_context(&device)?;
        self.submit_command(Trb::address_device(input_context.physical, slot_id, false))?;

        let first_length = self.get_descriptor(&mut device, DESCRIPTOR_DEVICE, 0, 8)?;
        if first_length < 8 {
            return Err(ControllerError::Descriptor(DescriptorError::Truncated));
        }
        let mut first = [0u8; 8];
        self.arena
            .copy_out(device.control_buffer, first_length, &mut first)
            .ok_or(ControllerError::DmaLayout)?;
        let encoded_packet = device_ep0_packet_byte(&first)?;
        let described_packet = descriptor_ep0_packet_size(device.semantic_speed, encoded_packet)
            .ok_or(ControllerError::InvalidEndpoint)?;
        if described_packet != device.ep0_max_packet {
            device.ep0_max_packet = described_packet;
            self.prepare_evaluate_ep0_context(&device)?;
            self.submit_command(Trb::evaluate_context(input_context.physical, slot_id))?;
        }

        let device_length = self.get_descriptor(&mut device, DESCRIPTOR_DEVICE, 0, 18)?;
        if device_length < 18 {
            return Err(ControllerError::Descriptor(DescriptorError::Truncated));
        }
        let mut device_descriptor = [0u8; 18];
        self.arena
            .copy_out(device.control_buffer, device_length, &mut device_descriptor)
            .ok_or(ControllerError::DmaLayout)?;
        device.vendor_id = u16::from_le_bytes([device_descriptor[8], device_descriptor[9]]);
        device.product_id = u16::from_le_bytes([device_descriptor[10], device_descriptor[11]]);

        let header_length = self.get_descriptor(&mut device, DESCRIPTOR_CONFIGURATION, 0, 9)?;
        if header_length < 9 {
            return Err(ControllerError::Descriptor(DescriptorError::Truncated));
        }
        let mut header = [0u8; 9];
        self.arena
            .copy_out(device.control_buffer, header_length, &mut header)
            .ok_or(ControllerError::DmaLayout)?;
        let total = configuration_total_length(&header)?;
        if total > MAX_CONFIGURATION_BYTES {
            return Err(ControllerError::DescriptorTooLarge);
        }
        let actual = self.get_descriptor(
            &mut device,
            DESCRIPTOR_CONFIGURATION,
            0,
            u16::try_from(total).map_err(|_| ControllerError::DescriptorTooLarge)?,
        )?;
        if actual < total {
            return Err(ControllerError::Descriptor(DescriptorError::Truncated));
        }
        let mut configuration_bytes = [0u8; MAX_CONFIGURATION_BYTES];
        self.arena
            .copy_out(device.control_buffer, total, &mut configuration_bytes)
            .ok_or(ControllerError::DmaLayout)?;
        let configuration = parse_boot_configuration(&configuration_bytes[..total])?;
        if configuration.is_empty() {
            return Err(ControllerError::NoBootHid);
        }

        self.control_no_data(
            &mut device,
            setup_packet(
                0x00,
                REQUEST_SET_CONFIGURATION,
                u16::from(configuration.configuration_value),
                0,
                0,
            ),
        )?;

        let mut add_flags = 1u32; // Slot Context
        let mut highest_dci = EP0_DCI;
        for interface in configuration.interfaces() {
            let function =
                self.allocate_hid_function(slot_index, device.semantic_speed, interface)?;
            let bit = 1u32
                .checked_shl(u32::from(function.dci))
                .ok_or(ControllerError::InvalidEndpoint)?;
            if add_flags & bit != 0 {
                return Err(ControllerError::InvalidEndpoint);
            }
            add_flags |= bit;
            highest_dci = highest_dci.max(function.dci);
            device.functions[device.function_count] = Some(function);
            device.function_count += 1;
        }
        self.prepare_configure_context(&device, add_flags, highest_dci)?;
        self.submit_command(Trb::configure_endpoint(input_context.physical, slot_id))?;

        for index in 0..device.function_count {
            let interface = device.functions[index]
                .as_ref()
                .expect("HID function prefix is dense")
                .interface_number;
            self.control_no_data(
                &mut device,
                setup_packet(
                    0x21,
                    HID_REQUEST_SET_PROTOCOL,
                    0, // boot protocol
                    u16::from(interface),
                    0,
                ),
            )?;
            // Infinite idle duration: reports are sent on changes; software
            // owns repeat policy rather than receiving redundant USB reports.
            self.control_no_data(
                &mut device,
                setup_packet(0x21, HID_REQUEST_SET_IDLE, 0, u16::from(interface), 0),
            )?;
        }

        for index in 0..device.function_count {
            self.queue_interrupt_report(&mut device, index)?;
        }
        ::log::info!(
            "xhci: port {} slot {} {:04x}:{:04x} online with {} boot-HID interface(s)",
            root_port,
            slot_id,
            device.vendor_id,
            device.product_id,
            device.function_count
        );
        self.devices[usize::from(slot_id - 1)] = Some(device);
        Ok(())
    }

    fn prepare_address_context(&mut self, device: &Device) -> Result<(), ControllerError> {
        let bytes = self
            .arena
            .bytes_mut(device.input_context)
            .ok_or(ControllerError::DmaLayout)?;
        let mut input =
            InputContext::new(bytes, self.context_size).ok_or(ControllerError::DmaLayout)?;
        input.set_control_flags(0, (1 << 0) | (1 << EP0_DCI));
        input.set_slot(device.raw_speed_id, device.root_port, EP0_DCI);
        input
            .set_endpoint(
                EP0_DCI,
                ep0_context(device.control_ring.physical(), device.ep0_max_packet),
            )
            .ok_or(ControllerError::InvalidEndpoint)?;
        self.arena.sync_for_device();
        Ok(())
    }

    fn prepare_evaluate_ep0_context(&mut self, device: &Device) -> Result<(), ControllerError> {
        let bytes = self
            .arena
            .bytes_mut(device.input_context)
            .ok_or(ControllerError::DmaLayout)?;
        let mut input =
            InputContext::new(bytes, self.context_size).ok_or(ControllerError::DmaLayout)?;
        input.set_control_flags(0, 1 << EP0_DCI);
        input
            .set_endpoint(
                EP0_DCI,
                ep0_context(device.control_ring.physical(), device.ep0_max_packet),
            )
            .ok_or(ControllerError::InvalidEndpoint)?;
        self.arena.sync_for_device();
        Ok(())
    }

    fn prepare_configure_context(
        &mut self,
        device: &Device,
        add_flags: u32,
        highest_dci: u8,
    ) -> Result<(), ControllerError> {
        let bytes = self
            .arena
            .bytes_mut(device.input_context)
            .ok_or(ControllerError::DmaLayout)?;
        let mut input =
            InputContext::new(bytes, self.context_size).ok_or(ControllerError::DmaLayout)?;
        input.set_control_flags(0, add_flags);
        input.set_slot(device.raw_speed_id, device.root_port, highest_dci);
        for function in device.functions.iter().flatten() {
            let payload = u32::from(function.report_length);
            input
                .set_endpoint(function.dci, EndpointContext {
                    endpoint_type: EndpointType::InterruptIn,
                    dequeue_pointer: function.transfer_ring.physical(),
                    max_packet_size: function.max_packet,
                    max_burst_size: function.max_burst,
                    mult: 0,
                    interval: function.interval,
                    average_trb_length: function.report_length,
                    max_esit_payload: payload,
                })
                .ok_or(ControllerError::InvalidEndpoint)?;
        }
        self.arena.sync_for_device();
        Ok(())
    }

    fn allocate_hid_function(
        &mut self,
        slot_index: usize,
        speed: u8,
        interface: BootInterface,
    ) -> Result<HidFunction, ControllerError> {
        let dci = endpoint_dci(interface.endpoint_address)
            .filter(|dci| *dci > EP0_DCI)
            .ok_or(ControllerError::InvalidEndpoint)?;
        let payload = usize::from(interface.max_packet_size)
            .checked_mul(usize::from(interface.transactions_per_microframe))
            .filter(|payload| *payload <= MAX_INTERRUPT_PAYLOAD)
            .ok_or(ControllerError::InvalidEndpoint)?;
        let interval = interval_for_speed(speed, interface.interval)
            .ok_or(ControllerError::InvalidEndpoint)?;
        let transfer_ring =
            ProducerRing::allocate_in(&mut self.arena, &mut self.device_dma[slot_index])?;
        let report_buffer = self.device_dma[slot_index].allocate(payload, 64)?;
        let decoder = match interface.protocol {
            BootProtocol::Keyboard => Decoder::Keyboard(BootKeyboard::new()),
            BootProtocol::Mouse => Decoder::Mouse(BootMouse::new()),
        };
        Ok(HidFunction {
            interface_number: interface.interface_number,
            dci,
            max_packet: interface.max_packet_size,
            report_length: u16::try_from(payload).map_err(|_| ControllerError::InvalidEndpoint)?,
            interval,
            max_burst: if speed == 3 {
                interface.transactions_per_microframe - 1
            } else {
                0
            },
            report_buffer,
            transfer_ring,
            pending_trb: 0,
            decoder,
        })
    }

    fn get_descriptor(
        &mut self,
        device: &mut Device,
        descriptor_type: u8,
        descriptor_index: u8,
        length: u16,
    ) -> Result<usize, ControllerError> {
        self.control_in(
            device,
            setup_packet(
                0x80,
                REQUEST_GET_DESCRIPTOR,
                (u16::from(descriptor_type) << 8) | u16::from(descriptor_index),
                0,
                length,
            ),
            length,
        )
    }

    fn control_in(
        &mut self,
        device: &mut Device,
        setup: [u8; 8],
        length: u16,
    ) -> Result<usize, ControllerError> {
        if usize::from(length) > device.control_buffer.len {
            return Err(ControllerError::DescriptorTooLarge);
        }
        self.arena
            .bytes_mut(device.control_buffer)
            .ok_or(ControllerError::DmaLayout)?
            .fill(0);
        let setup_pointer = device
            .control_ring
            .push(&mut self.arena, Trb::setup(setup, SetupDirection::In))?;
        let data_pointer = device.control_ring.push(
            &mut self.arena,
            Trb::data(device.control_buffer.physical, u32::from(length), true),
        )?;
        let status_pointer = device
            .control_ring
            .push(&mut self.arena, Trb::status(false))?;
        self.registers.ring_doorbell(device.slot_id, EP0_DCI);
        self.wait_control_transfer(
            device.slot_id,
            setup_pointer,
            data_pointer,
            status_pointer,
            usize::from(length),
        )
    }

    fn control_no_data(
        &mut self,
        device: &mut Device,
        setup: [u8; 8],
    ) -> Result<(), ControllerError> {
        let setup_pointer = device
            .control_ring
            .push(&mut self.arena, Trb::setup(setup, SetupDirection::NoData))?;
        let status_pointer = device
            .control_ring
            .push(&mut self.arena, Trb::status(true))?;
        self.registers.ring_doorbell(device.slot_id, EP0_DCI);
        let _ = self.wait_control_transfer(device.slot_id, setup_pointer, 0, status_pointer, 0)?;
        Ok(())
    }

    fn wait_control_transfer(
        &mut self,
        slot_id: u8,
        setup_pointer: u64,
        data_pointer: u64,
        status_pointer: u64,
        requested: usize,
    ) -> Result<usize, ControllerError> {
        let mut transferred = requested;
        let mut budget = super::wait::PollingBudget::new(CONTROL_TIMEOUT_MS);
        while budget.poll_again() {
            if self.registers.fatal_status() {
                self.fatal_status_pending = true;
                self.fail_stop("fatal USBSTS during control transfer");
                return Err(ControllerError::ControllerFailed);
            }
            let Some(event) = self.next_event() else {
                spin_loop();
                continue;
            };
            match event {
                Event::Transfer {
                    trb_pointer,
                    residual,
                    code,
                    endpoint_id: EP0_DCI,
                    slot_id: event_slot,
                } if event_slot == slot_id && trb_pointer == data_pointer => {
                    if !code.transfer_succeeded() {
                        self.finish_event_dispatch();
                        self.flush_event_acknowledgement();
                        return Err(ControllerError::TransferFailed(code));
                    }
                    transferred = requested.saturating_sub(residual as usize);
                    // Status Stage has IOC and completes the TD after a valid
                    // short data packet; keep draining until that event.
                    self.finish_event_dispatch();
                },
                Event::Transfer {
                    trb_pointer,
                    code,
                    endpoint_id: EP0_DCI,
                    slot_id: event_slot,
                    ..
                } if event_slot == slot_id && trb_pointer == status_pointer => {
                    self.finish_event_dispatch();
                    self.flush_event_acknowledgement();
                    if code.transfer_succeeded() {
                        return Ok(transferred);
                    }
                    return Err(ControllerError::TransferFailed(code));
                },
                Event::Transfer {
                    trb_pointer,
                    code,
                    endpoint_id: EP0_DCI,
                    slot_id: event_slot,
                    ..
                } if event_slot == slot_id
                    && (trb_pointer == setup_pointer
                        || trb_pointer == data_pointer
                        || trb_pointer == status_pointer)
                    && !code.transfer_succeeded() =>
                {
                    self.finish_event_dispatch();
                    self.flush_event_acknowledgement();
                    return Err(ControllerError::TransferFailed(code));
                },
                other => {
                    self.handle_async_event(other);
                    self.finish_event_dispatch();
                },
            }
        }
        self.flush_event_acknowledgement();
        self.fail_stop("control transfer completion timeout");
        Err(ControllerError::TransferTimeout)
    }

    fn enable_slot(&mut self, slot_type: u8) -> Result<u8, ControllerError> {
        let (_, slot) = self.submit_command(Trb::enable_slot(slot_type))?;
        (slot != 0).then_some(slot).ok_or(ControllerError::NoSlot)
    }

    fn disable_slot(&mut self, slot_id: u8) -> Result<(), ControllerError> {
        let _ = self.submit_command(Trb::disable_slot(slot_id))?;
        Ok(())
    }

    fn submit_command(&mut self, command: Trb) -> Result<(CompletionCode, u8), ControllerError> {
        if self.failed {
            return Err(ControllerError::ControllerFailed);
        }
        if self.registers.fatal_status() {
            self.fatal_status_pending = true;
            self.fail_stop("fatal USBSTS before command submission");
            return Err(ControllerError::ControllerFailed);
        }
        let pointer = self.command_ring.push(&mut self.arena, command)?;
        self.registers.ring_doorbell(0, 0);
        let mut budget = super::wait::PollingBudget::new(COMMAND_TIMEOUT_MS);
        while budget.poll_again() {
            if self.registers.fatal_status() {
                self.fatal_status_pending = true;
                self.fail_stop("fatal USBSTS during command completion wait");
                return Err(ControllerError::ControllerFailed);
            }
            let Some(event) = self.next_event() else {
                spin_loop();
                continue;
            };
            match event {
                Event::CommandCompletion {
                    command_pointer,
                    code,
                    slot_id,
                } if command_pointer == pointer => {
                    self.finish_event_dispatch();
                    self.flush_event_acknowledgement();
                    if code.command_succeeded() {
                        return Ok((code, slot_id));
                    }
                    return Err(ControllerError::CommandFailed(code));
                },
                other => {
                    self.handle_async_event(other);
                    self.finish_event_dispatch();
                },
            }
        }
        self.flush_event_acknowledgement();
        self.fail_stop("command completion timeout");
        Err(ControllerError::CommandTimeout)
    }

    fn next_event(&mut self) -> Option<Event> {
        let trb = self.event_ring.pop(&self.arena)?;
        Some(Event::decode(trb))
    }

    /// Mark an event only after its software dispatch has completed. Long
    /// synchronous waits publish bounded ERDP sub-batches without clearing
    /// EHB; the caller's final flush performs the interrupt acknowledgement.
    fn finish_event_dispatch(&mut self) {
        self.event_ack_pending = true;
        self.events_since_publish = self.events_since_publish.saturating_add(1);
        if self.events_since_publish >= MAX_EVENTS_PER_DRAIN {
            self.registers
                .publish_event_dequeue(self.event_ring.dequeue_physical());
            self.events_since_publish = 0;
        }
    }

    fn flush_event_acknowledgement(&mut self) {
        if self.event_ack_pending || self.registers.interrupt_pending() {
            self.registers
                .acknowledge_interrupter(self.event_ring.dequeue_physical());
            self.events_since_publish = 0;
            self.event_ack_pending = false;
        }
    }

    fn handle_async_event(&mut self, event: Event) {
        match event {
            Event::Transfer {
                trb_pointer,
                residual,
                code,
                endpoint_id,
                slot_id,
            } => self.handle_interrupt_report(slot_id, endpoint_id, trb_pointer, code, residual),
            Event::PortStatusChange { port_id, .. } => self.mark_port_pending(port_id),
            Event::CommandCompletion { .. } | Event::Unknown(_) => {},
        }
    }

    fn handle_interrupt_report(
        &mut self,
        slot_id: u8,
        endpoint_id: u8,
        trb_pointer: u64,
        code: CompletionCode,
        residual: u32,
    ) {
        let Some(index) = slot_id.checked_sub(1).map(usize::from) else {
            return;
        };
        let Some(device) = self.devices.get_mut(index).and_then(Option::as_mut) else {
            return;
        };
        let Some(function_index) = device.functions[..device.function_count]
            .iter()
            .position(|function| function.is_some_and(|function| function.dci == endpoint_id))
        else {
            return;
        };
        let function = device.functions[function_index]
            .as_mut()
            .expect("located HID function exists");
        // A late event from a disabled/reused slot must not consume or requeue
        // the new endpoint's one outstanding report TRB.
        if function.pending_trb != trb_pointer {
            return;
        }
        if !code.transfer_succeeded() {
            self.defer_transfer_recovery(slot_id, endpoint_id, code);
            return;
        }
        let actual = usize::from(function.report_length).saturating_sub(residual as usize);
        let mut report = [0u8; 64];
        let copied = self
            .arena
            .copy_out(function.report_buffer, actual, &mut report)
            .unwrap_or(0);
        let epoch = crate::ui::input_epoch();
        match &mut function.decoder {
            Decoder::Keyboard(keyboard) => {
                let _ = keyboard.decode_at(&report[..copied], crate::time::uptime_ns(), |event| {
                    crate::ui::route_key_event(epoch, event);
                });
            },
            Decoder::Mouse(mouse) => {
                if let Ok(event) = mouse.decode(&report[..copied]) {
                    crate::ui::route_mouse_event(epoch, event);
                }
            },
        }
        let queued = function.transfer_ring.push(
            &mut self.arena,
            Trb::normal(
                function.report_buffer.physical,
                u32::from(function.report_length),
            ),
        );
        match queued {
            Ok(pointer) => {
                function.pending_trb = pointer;
                self.registers.ring_doorbell(slot_id, endpoint_id);
            },
            Err(_) => {
                self.defer_transfer_recovery(slot_id, endpoint_id, CompletionCode::TRB_ERROR);
            },
        }
    }

    fn defer_transfer_recovery(&mut self, slot_id: u8, endpoint_id: u8, code: CompletionCode) {
        let Some(index) = slot_id.checked_sub(1).map(usize::from) else {
            return;
        };
        if index >= MAX_DEVICES {
            return;
        }
        self.recovery_slots |= 1u16 << index;
        self.transfer_error_total = self.transfer_error_total.saturating_add(1);
        self.transfer_errors_pending = self.transfer_errors_pending.saturating_add(1);
        self.last_transfer_fault = Some(TransferFault {
            slot_id,
            endpoint_id,
            code,
        });
    }

    fn queue_interrupt_report(
        &mut self,
        device: &mut Device,
        function_index: usize,
    ) -> Result<(), ControllerError> {
        let function = device.functions[function_index]
            .as_mut()
            .ok_or(ControllerError::InvalidEndpoint)?;
        let pointer = function.transfer_ring.push(
            &mut self.arena,
            Trb::normal(
                function.report_buffer.physical,
                u32::from(function.report_length),
            ),
        )?;
        function.pending_trb = pointer;
        self.registers.ring_doorbell(device.slot_id, function.dci);
        Ok(())
    }

    fn mark_port_pending(&mut self, port_id: u8) {
        if port_id == 0 {
            return;
        }
        let zero_based = usize::from(port_id - 1);
        self.pending_ports[zero_based / 64] |= 1u64 << (zero_based % 64);
    }

    fn cancel_port_retry(&mut self, port_id: u8) {
        if let Some(index) = self
            .port_retries
            .iter()
            .position(|retry| retry.is_some_and(|retry| retry.port_id == port_id))
        {
            self.port_retries[index] = None;
        }
    }

    fn schedule_port_retry(&mut self, port_id: u8, error: ControllerError) {
        if self.failed
            || !error.hotplug_retryable()
            || self.registers.port_status(port_id) & PORT_CURRENT_CONNECT_STATUS == 0
        {
            self.cancel_port_retry(port_id);
            return;
        }
        let existing = self
            .port_retries
            .iter()
            .position(|retry| retry.is_some_and(|retry| retry.port_id == port_id));
        let Some(index) = existing.or_else(|| self.port_retries.iter().position(Option::is_none))
        else {
            ::log::warn!(
                "xhci: no retry slot for transient hotplug failure on port {}: {:?}",
                port_id,
                error
            );
            return;
        };
        let attempt = self.port_retries[index].map_or(1, |retry| retry.attempt.saturating_add(1));
        let Some(delay_ns) = hotplug_retry_delay_ns(attempt) else {
            self.port_retries[index] = None;
            ::log::warn!(
                "xhci: hotplug port {} exhausted {} retries: {:?}",
                port_id,
                HOTPLUG_RETRY_LIMIT,
                error
            );
            return;
        };
        self.port_retries[index] = Some(PortRetry {
            port_id,
            attempt,
            deadline_ns: crate::time::uptime_ns().saturating_add(delay_ns),
        });
        ::log::warn!(
            "xhci: hotplug port {} transient failure {:?}; retry {}/{} in {} ms",
            port_id,
            error,
            attempt,
            HOTPLUG_RETRY_LIMIT,
            delay_ns / 1_000_000
        );
    }

    fn activate_due_port_retries(&mut self) {
        let now_ns = crate::time::uptime_ns();
        for index in 0..self.port_retries.len() {
            let Some(retry) = self.port_retries[index] else {
                continue;
            };
            if now_ns < retry.deadline_ns {
                continue;
            }
            // Preserve the attempt counter until service_port records success
            // or schedules the next backoff. The sentinel prevents duplicate
            // activation if another pending port fail-stops this service pass.
            self.port_retries[index] = Some(PortRetry {
                deadline_ns: u64::MAX,
                ..retry
            });
            self.mark_port_pending(retry.port_id);
        }
    }

    fn attempt_port_enumeration(&mut self, port_id: u8) {
        if self.registers.port_status(port_id) & PORT_CURRENT_CONNECT_STATUS == 0 {
            self.cancel_port_retry(port_id);
            return;
        }
        match self.enumerate_port(port_id) {
            Ok(()) => self.cancel_port_retry(port_id),
            Err(ControllerError::NoBootHid) => {
                self.cancel_port_retry(port_id);
                ::log::debug!("xhci: hotplug port {} has no HID boot interface", port_id);
            },
            Err(error) if !self.failed && error.hotplug_retryable() => {
                self.schedule_port_retry(port_id, error);
            },
            Err(error) if !self.failed => {
                self.cancel_port_retry(port_id);
                ::log::warn!("xhci: hotplug port {} failed: {:?}", port_id, error);
            },
            Err(_) => {},
        }
    }

    fn remove_port_device(&mut self, index: usize, port_id: u8, disposition: &'static str) -> bool {
        let slot = self.devices[index]
            .as_ref()
            .expect("located USB slot exists")
            .slot_id;
        match self.disable_slot(slot) {
            Ok(()) => {
                self.recovery_slots &= !(1u16 << index);
                self.release_device_input(index);
                self.devices[index] = None;
                let _ = self.arena.write_u64(self.dcbaa, usize::from(slot), 0);
                if let Err(error) = self.reset_slot_dma(slot) {
                    ::log::warn!("xhci: slot {} DMA recycle failed: {:?}", slot, error);
                }
                ::log::info!("xhci: root port {} {}", port_id, disposition);
                true
            },
            Err(_) if !self.failed => {
                self.fail_stop("Disable Slot failed during disconnect/reconnect");
                false
            },
            Err(_) => false,
        }
    }

    /// Drain a bounded event batch. Safe in hard-IRQ context: it allocates no
    /// memory and defers port enumeration/hotplug commands to [`Self::service`].
    pub fn handle_interrupt(&mut self) -> usize {
        if self.failed {
            return 0;
        }
        // HCE/HSE means controller DMA/event state is no longer trustworthy.
        // Hard IRQ context records the observation and returns without
        // touching the event ring; the 4 ms task worker performs fail-stop.
        if self.registers.fatal_status() {
            self.fatal_status_pending = true;
            return 0;
        }
        let mut handled = 0;
        while handled < MAX_EVENTS_PER_DRAIN {
            if self.registers.fatal_status() {
                self.fatal_status_pending = true;
                return handled;
            }
            let Some(event) = self.next_event() else {
                break;
            };
            self.handle_async_event(event);
            self.finish_event_dispatch();
            handled += 1;
        }
        self.flush_event_acknowledgement();
        handled
    }

    /// Process events and deferred root-port connect/disconnect work from task
    /// context. Call periodically when MSI is unavailable and after an IRQ
    /// wake when hotplug support is desired.
    pub fn service(&mut self) -> usize {
        if self.failed {
            return 0;
        }
        if self.fatal_status_pending || self.registers.fatal_status() {
            self.fatal_status_pending = true;
            self.fail_stop("fatal USBSTS observed by service worker");
            return 0;
        }
        let handled = self.handle_interrupt();
        if self.fatal_status_pending || self.registers.fatal_status() {
            self.fatal_status_pending = true;
            self.fail_stop("fatal USBSTS observed while draining events");
            return handled;
        }
        if self.failed {
            return handled;
        }
        self.activate_due_port_retries();
        for word_index in 0..self.pending_ports.len() {
            let mut pending = core::mem::take(&mut self.pending_ports[word_index]);
            while pending != 0 {
                let bit = pending.trailing_zeros() as usize;
                pending &= pending - 1;
                let port_index = word_index * 64 + bit;
                if port_index >= usize::from(self.capabilities.max_ports) {
                    continue;
                }
                let port_id = (port_index + 1) as u8;
                self.service_port(port_id);
                if self.failed {
                    return handled;
                }
            }
        }
        self.service_recovery_slots();
        if !self.failed {
            self.service_typematic();
            self.log_deferred_transfer_errors();
        }
        handled
    }

    fn service_port(&mut self, port_id: u8) {
        let status = self.registers.port_status(port_id);
        let connected = status & PORT_CURRENT_CONNECT_STATUS != 0;
        let connection_changed = status & PORT_CONNECT_CHANGE != 0;
        let existing = self.devices.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|device| device.root_port == port_id)
        });
        if connection_changed {
            // A fresh physical connection starts a fresh bounded retry series.
            self.cancel_port_retry(port_id);
        }
        match port_service_action(connected, existing.is_some(), connection_changed) {
            PortServiceAction::Disconnect => {
                self.cancel_port_retry(port_id);
                if let Some(index) = existing {
                    let _ = self.remove_port_device(index, port_id, "disconnected");
                }
            },
            PortServiceAction::Enumerate => self.attempt_port_enumeration(port_id),
            PortServiceAction::Reconnect => {
                let index = existing.expect("reconnect action requires an existing slot");
                if self.remove_port_device(index, port_id, "reconnected") && !self.failed {
                    self.attempt_port_enumeration(port_id);
                }
            },
            PortServiceAction::None => {
                if connected && existing.is_some() {
                    self.cancel_port_retry(port_id);
                }
            },
        }
        if !self.failed {
            self.registers
                .write_port_status(port_id, PORT_POWER, PORT_CHANGE_BITS);
        }
    }

    fn service_recovery_slots(&mut self) {
        let mut recovery = core::mem::take(&mut self.recovery_slots);
        while recovery != 0 && !self.failed {
            let index = recovery.trailing_zeros() as usize;
            recovery &= recovery - 1;
            let Some(device) = self.devices.get(index).and_then(Option::as_ref) else {
                continue;
            };
            let slot_id = device.slot_id;
            let port_id = device.root_port;
            if self.disable_slot(slot_id).is_err() {
                if !self.failed {
                    self.fail_stop("Disable Slot failed during endpoint recovery");
                }
                return;
            }
            self.recovery_slots &= !(1u16 << index);
            self.release_device_input(index);
            self.devices[index] = None;
            let _ = self.arena.write_u64(self.dcbaa, usize::from(slot_id), 0);
            if let Err(error) = self.reset_slot_dma(slot_id) {
                ::log::warn!("xhci: slot {} DMA recovery failed: {:?}", slot_id, error);
                continue;
            }
            if self.registers.port_status(port_id) & PORT_CURRENT_CONNECT_STATUS != 0 {
                match self.enumerate_port(port_id) {
                    Ok(()) => {
                        self.cancel_port_retry(port_id);
                        ::log::info!(
                            "xhci: root port {} recovered after HID endpoint fault",
                            port_id
                        );
                    },
                    Err(error) if !self.failed && error.hotplug_retryable() => {
                        self.schedule_port_retry(port_id, error);
                    },
                    Err(error) if !self.failed => {
                        self.cancel_port_retry(port_id);
                        ::log::warn!(
                            "xhci: root port {} re-enumeration failed: {:?}",
                            port_id,
                            error
                        );
                    },
                    Err(_) => {},
                }
            } else {
                self.cancel_port_retry(port_id);
            }
        }
    }

    fn release_device_input(&mut self, index: usize) {
        let Some(device) = self.devices.get_mut(index).and_then(Option::as_mut) else {
            return;
        };
        let epoch = crate::ui::input_epoch();
        for function in device.functions[..device.function_count]
            .iter_mut()
            .flatten()
        {
            match &mut function.decoder {
                Decoder::Keyboard(keyboard) => {
                    let _ = keyboard.disconnect(|event| {
                        crate::ui::route_key_event(epoch, event);
                    });
                },
                Decoder::Mouse(mouse) => {
                    if let Some(event) = mouse.disconnect() {
                        crate::ui::route_mouse_event(epoch, event);
                    }
                },
            }
        }
    }

    fn service_typematic(&mut self) {
        let now_ns = crate::time::uptime_ns();
        let epoch = crate::ui::input_epoch();
        for device in self.devices.iter_mut().flatten() {
            for function in device.functions[..device.function_count]
                .iter_mut()
                .flatten()
            {
                if let Decoder::Keyboard(keyboard) = &mut function.decoder {
                    let _ = keyboard.repeat_due(now_ns, |event| {
                        crate::ui::route_key_event(epoch, event);
                    });
                }
            }
        }
    }

    fn log_deferred_transfer_errors(&mut self) {
        if self.transfer_errors_pending == 0 {
            return;
        }
        let now = crate::time::Instant::now();
        if self.last_transfer_error_log.is_some_and(|last| {
            now.duration_since(last).as_nanos() < TRANSFER_ERROR_LOG_INTERVAL_NS
        }) {
            return;
        }
        if let Some(fault) = self.last_transfer_fault {
            ::log::warn!(
                "xhci: {} deferred HID transfer error(s), {} total; latest slot {} endpoint {} {:?}",
                self.transfer_errors_pending,
                self.transfer_error_total,
                fault.slot_id,
                fault.endpoint_id,
                fault.code
            );
        }
        self.transfer_errors_pending = 0;
        self.last_transfer_error_log = Some(now);
    }

    fn fail_stop(&mut self, reason: &'static str) {
        if self.failed {
            return;
        }
        self.failed = true;
        let stop_error = self.registers.stop().err();
        let mut command = PciCommand::from_bits_truncate(self.pci.read_command());
        command.remove(PciCommand::BUS_MASTER);
        command.insert(PciCommand::INTERRUPT_DISABLE);
        self.pci.write_command(command.bits());
        for index in 0..self.devices.len() {
            self.release_device_input(index);
        }
        ::log::error!(
            "xhci: controller fail-stopped ({}){}",
            reason,
            if stop_error.is_some() {
                "; halt acknowledgement timed out, PCI bus mastering disabled"
            } else {
                ""
            }
        );
    }

    #[must_use]
    pub fn hid_device_count(&self) -> usize {
        if self.failed {
            return 0;
        }
        self.devices
            .iter()
            .flatten()
            .map(|device| device.function_count)
            .sum()
    }

    #[must_use]
    pub const fn pci_address(&self) -> crate::devices::pci::PciAddress {
        self.pci
    }

    fn reset_slot_dma(&mut self, slot_id: u8) -> Result<(), ControllerError> {
        let index = usize::from(
            slot_id
                .checked_sub(1)
                .ok_or(ControllerError::SlotOutOfRange(slot_id))?,
        );
        let window = self
            .device_dma
            .get_mut(index)
            .ok_or(ControllerError::SlotOutOfRange(slot_id))?;
        window.reset(&mut self.arena)?;
        Ok(())
    }
}

impl Drop for XhciController {
    fn drop(&mut self) {
        // `arena` is still alive throughout Drop. Halt the xHC first; clearing
        // PCI BME afterwards is the fail-safe even if the bounded halt fails.
        if let Err(error) = self.registers.stop() {
            ::log::error!("xhci: controller stop during teardown failed: {:?}", error);
        }
        let mut command = PciCommand::from_bits_truncate(self.pci.read_command());
        command.remove(PciCommand::BUS_MASTER);
        command.insert(PciCommand::INTERRUPT_DISABLE);
        self.pci.write_command(command.bits());
    }
}

fn ep0_context(ring: u64, max_packet_size: u16) -> EndpointContext {
    EndpointContext {
        endpoint_type: EndpointType::Control,
        dequeue_pointer: ring,
        max_packet_size,
        max_burst_size: 0,
        mult: 0,
        interval: 0,
        average_trb_length: 8,
        max_esit_payload: 0,
    }
}

/// Exact class triple for an xHCI USB host controller.
#[must_use]
pub const fn is_xhci(device: &PciDevice) -> bool {
    device.base_class == PCI_CLASS_SERIAL_BUS
        && device.subclass == PCI_SUBCLASS_USB
        && device.prog_if == PCI_PROG_IF_XHCI
}

const fn setup_packet(
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    length: u16,
) -> [u8; 8] {
    let value = value.to_le_bytes();
    let index = index.to_le_bytes();
    let length = length.to_le_bytes();
    [
        request_type,
        request,
        value[0],
        value[1],
        index[0],
        index[1],
        length[0],
        length[1],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::pci::enumerate::PciHeaderKind;
    use crate::devices::pci::PciAddress;

    fn test_device(prog_if: u8) -> PciDevice {
        PciDevice {
            address: PciAddress::new(0, 20, 0).unwrap(),
            vendor_id: 0x8086,
            device_id: 0x1e31,
            revision: 4,
            prog_if,
            subclass: PCI_SUBCLASS_USB,
            base_class: PCI_CLASS_SERIAL_BUS,
            header_kind: PciHeaderKind::Device,
            multifunction: false,
            bars: [0xfebf_0004, 0, 0, 0, 0, 0],
            interrupt_line: 11,
            interrupt_pin: 1,
        }
    }

    #[test]
    fn class_match_requires_xhci_programming_interface() {
        assert!(is_xhci(&test_device(0x30)));
        assert!(!is_xhci(&test_device(0x20))); // EHCI
        assert!(!is_xhci(&test_device(0x10))); // OHCI
    }

    #[test]
    fn setup_packets_are_little_endian_and_exactly_eight_bytes() {
        assert_eq!(setup_packet(0x80, 6, 0x0201, 0x0409, 0x1234), [
            0x80, 6, 1, 2, 9, 4, 0x34, 0x12
        ]);
    }

    #[test]
    fn connection_change_replaces_a_stale_slot_after_coalesced_reconnect() {
        assert_eq!(
            port_service_action(true, true, true),
            PortServiceAction::Reconnect
        );
        assert_eq!(
            port_service_action(true, true, false),
            PortServiceAction::None
        );
        assert_eq!(
            port_service_action(false, true, true),
            PortServiceAction::Disconnect
        );
        assert_eq!(
            port_service_action(true, false, true),
            PortServiceAction::Enumerate
        );
    }

    #[test]
    fn transient_hotplug_retries_are_bounded_and_exponentially_debounced() {
        assert_eq!(hotplug_retry_delay_ns(0), None);
        assert_eq!(hotplug_retry_delay_ns(1), Some(100_000_000));
        assert_eq!(hotplug_retry_delay_ns(2), Some(200_000_000));
        assert_eq!(hotplug_retry_delay_ns(5), Some(1_600_000_000));
        assert_eq!(hotplug_retry_delay_ns(6), None);

        assert!(ControllerError::PortResetTimeout.hotplug_retryable());
        assert!(ControllerError::NoSlot.hotplug_retryable());
        assert!(ControllerError::TransferFailed(CompletionCode::TRB_ERROR).hotplug_retryable());
        assert!(!ControllerError::NoBootHid.hotplug_retryable());
        assert!(!ControllerError::DescriptorTooLarge.hotplug_retryable());
    }
}
