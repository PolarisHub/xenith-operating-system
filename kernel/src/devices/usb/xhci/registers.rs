//! Volatile xHCI capability, operational, runtime, port, and doorbell access.
//!
//! The constructor receives an HHDM virtual address only after PCI BAR0 has
//! been validated by the controller layer.  Like Xenith's AHCI and IOAPIC
//! drivers, this relies on the boot-time invariant that physical PCI MMIO is
//! reachable through the higher-half direct map; it does not silently treat a
//! zero or I/O BAR as memory.

use core::ptr::{read_volatile, write_volatile};

const HCSPARAMS1: u64 = 0x04;
const HCSPARAMS2: u64 = 0x08;
const HCCPARAMS1: u64 = 0x10;
const DBOFF: u64 = 0x14;
const RTSOFF: u64 = 0x18;

const USBCMD: u64 = 0x00;
const USBSTS: u64 = 0x04;
const PAGESIZE: u64 = 0x08;
const CRCR: u64 = 0x18;
const DCBAAP: u64 = 0x30;
const CONFIG: u64 = 0x38;
const PORT_REGS: u64 = 0x400;
const PORT_STRIDE: u64 = 0x10;

const RUNTIME_INTERRUPTER0: u64 = 0x20;
const IMAN: u64 = 0x00;
const IMOD: u64 = 0x04;
const ERSTSZ: u64 = 0x08;
const ERSTBA: u64 = 0x10;
const ERDP: u64 = 0x18;

const CMD_RUN_STOP: u32 = 1 << 0;
const CMD_HOST_CONTROLLER_RESET: u32 = 1 << 1;
const CMD_INTERRUPTER_ENABLE: u32 = 1 << 2;
const STATUS_HALTED: u32 = 1 << 0;
const STATUS_HOST_SYSTEM_ERROR: u32 = 1 << 2;
const STATUS_EVENT_INTERRUPT: u32 = 1 << 3;
const STATUS_CONTROLLER_NOT_READY: u32 = 1 << 11;
const STATUS_HOST_CONTROLLER_ERROR: u32 = 1 << 12;
const STATUS_FATAL: u32 = STATUS_HOST_SYSTEM_ERROR | STATUS_HOST_CONTROLLER_ERROR;

pub const PORT_CURRENT_CONNECT_STATUS: u32 = 1 << 0;
pub const PORT_ENABLED: u32 = 1 << 1;
pub const PORT_RESET: u32 = 1 << 4;
pub const PORT_POWER: u32 = 1 << 9;
pub const PORT_SPEED_SHIFT: u32 = 10;
pub const PORT_CONNECT_CHANGE: u32 = 1 << 17;
pub const PORT_ENABLE_CHANGE: u32 = 1 << 18;
pub const PORT_WARM_RESET_CHANGE: u32 = 1 << 19;
pub const PORT_OVERCURRENT_CHANGE: u32 = 1 << 20;
pub const PORT_RESET_CHANGE: u32 = 1 << 21;
pub const PORT_LINK_STATE_CHANGE: u32 = 1 << 22;
pub const PORT_CONFIG_ERROR_CHANGE: u32 = 1 << 23;
pub const PORT_WARM_RESET: u32 = 1 << 31;
pub const PORT_CHANGE_BITS: u32 = PORT_CONNECT_CHANGE
    | PORT_ENABLE_CHANGE
    | PORT_WARM_RESET_CHANGE
    | PORT_OVERCURRENT_CHANGE
    | PORT_RESET_CHANGE
    | PORT_LINK_STATE_CHANGE
    | PORT_CONFIG_ERROR_CHANGE;

const HCC_AC64: u32 = 1 << 0;
const HCC_CSZ: u32 = 1 << 2;
const EXT_CAP_ID_LEGACY_SUPPORT: u8 = 1;
const EXT_CAP_ID_SUPPORTED_PROTOCOL: u8 = 2;
const LEGACY_BIOS_OWNED: u32 = 1 << 16;
const LEGACY_OS_OWNED: u32 = 1 << 24;

const EXT_CAPABILITY_LIMIT: usize = 64;
const PORT_PROTOCOL_ENTRIES: usize = 256;
const BIOS_OWNERSHIP_TIMEOUT_MS: u16 = 1_000;
const CONTROLLER_TRANSITION_TIMEOUT_MS: u16 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InterrupterAckWrite {
    PublishEventDequeue,
    ClearEventInterrupt,
    ClearInterrupterPending,
}

// xHCI 1.2 section 4.17.2: publish ERDP/EHB first, clear USBSTS.EINT,
// then clear IMAN.IP. Keeping the sequence data-driven also makes a future
// refactor unable to silently invert the two RW1C acknowledgements.
const INTERRUPTER_ACK_ORDER: [InterrupterAckWrite; 3] = [
    InterrupterAckWrite::PublishEventDequeue,
    InterrupterAckWrite::ClearEventInterrupt,
    InterrupterAckWrite::ClearInterrupterPending,
];

/// Decoded immutable host-controller capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub interface_version: u16,
    pub max_slots: u8,
    pub max_interrupters: u16,
    pub max_ports: u8,
    pub max_scratchpad_buffers: u16,
    pub supports_64bit_addresses: bool,
    pub context_size_64: bool,
    pub extended_capabilities_offset: u32,
}

/// Semantic USB speed used for descriptor, EP0, and scheduling rules. The
/// raw Protocol Speed ID remains separate because custom PSIV values must be
/// copied unchanged into the xHCI Slot Context.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsbSpeed {
    Full = 1,
    Low = 2,
    High = 3,
    Super = 4,
}

impl UsbSpeed {
    #[must_use]
    pub const fn canonical_id(self) -> u8 {
        self as u8
    }
}

/// Per-connection speed and Slot Type resolved from a Supported Protocol
/// capability and the raw PORTSC Protocol Speed ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedPortSpeed {
    pub raw_speed_id: u8,
    pub semantic: UsbSpeed,
    pub slot_type: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PortProtocol {
    claimed: bool,
    custom_speed_ids: bool,
    slot_type: u8,
    semantic_by_psiv: [u8; 16],
}

const EMPTY_PORT_PROTOCOL: PortProtocol = PortProtocol {
    claimed: false,
    custom_speed_ids: false,
    slot_type: 0,
    semantic_by_psiv: [0; 16],
};

/// Fixed, allocation-free Supported Protocol routing for every possible
/// one-based xHCI root-port ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortProtocols {
    ports: [PortProtocol; PORT_PROTOCOL_ENTRIES],
    capability_present: bool,
}

impl PortProtocols {
    const fn new() -> Self {
        Self {
            ports: [EMPTY_PORT_PROTOCOL; PORT_PROTOCOL_ENTRIES],
            capability_present: false,
        }
    }

    #[must_use]
    pub const fn capability_present(&self) -> bool {
        self.capability_present
    }

    /// Resolve a raw PORTSC speed. Defaults are allowed only when the
    /// controller exposes no Supported Protocol capability at all.
    #[must_use]
    pub fn resolve(&self, port_id: u8, raw_speed_id: u8) -> Option<ResolvedPortSpeed> {
        let protocol = self.ports.get(usize::from(port_id))?;
        if self.capability_present && !protocol.claimed {
            return None;
        }
        let semantic = if protocol.claimed && protocol.custom_speed_ids {
            semantic_from_id(protocol.semantic_by_psiv[usize::from(raw_speed_id & 0x0f)])?
        } else {
            default_semantic_speed(raw_speed_id)?
        };
        Some(ResolvedPortSpeed {
            raw_speed_id,
            semantic,
            slot_type: if protocol.claimed {
                protocol.slot_type
            } else {
                0
            },
        })
    }
}

impl Capabilities {
    fn decode(version: u16, hcs1: u32, hcs2: u32, hcc1: u32) -> Self {
        // HCSPARAMS2 splits the ten-bit field unusually: bits 31:27 are
        // result bits 4:0 (Lo), while bits 25:21 are result bits 9:5 (Hi).
        let scratchpad_low = ((hcs2 >> 27) & 0x1f) as u16;
        let scratchpad_high = ((hcs2 >> 21) & 0x1f) as u16;
        Self {
            interface_version: version,
            max_slots: hcs1 as u8,
            max_interrupters: ((hcs1 >> 8) & 0x7ff) as u16,
            max_ports: (hcs1 >> 24) as u8,
            max_scratchpad_buffers: (scratchpad_high << 5) | scratchpad_low,
            supports_64bit_addresses: hcc1 & HCC_AC64 != 0,
            context_size_64: hcc1 & HCC_CSZ != 0,
            extended_capabilities_offset: ((hcc1 >> 16) & 0xffff) * 4,
        }
    }
}

/// Invalid controller register layout or bounded wait failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterError {
    InvalidCapabilityLength,
    InvalidCapabilities,
    AddressOverflow,
    BiosOwnershipTimeout,
    HaltTimeout,
    ResetTimeout,
    StartTimeout,
    FatalControllerStatus,
    UnsupportedPageSize,
}

/// Register-file handle. Raw addresses are stored as integers so the value is
/// Send/Sync without giving safe Rust a dereferenceable MMIO reference.
#[derive(Clone, Copy, Debug)]
pub struct Registers {
    capability: u64,
    operational: u64,
    runtime: u64,
    doorbells: u64,
    capabilities: Capabilities,
}

impl Registers {
    /// Construct from an already mapped, nonzero, aligned BAR address.
    ///
    /// # Safety
    ///
    /// `capability_base` must address the complete xHCI MMIO register window
    /// and remain mapped for the controller lifetime. No other driver may
    /// concurrently program the same function.
    pub unsafe fn new(capability_base: u64) -> Result<Self, RegisterError> {
        // SAFETY: caller establishes the MMIO mapping and lifetime.
        let first = unsafe { mmio_read32(capability_base) };
        let capability_length = u64::from(first & 0xff);
        if capability_length < 0x20 || capability_length & 3 != 0 {
            return Err(RegisterError::InvalidCapabilityLength);
        }
        // SAFETY: fixed capability offsets are inside every xHCI register set.
        let hcs1 = unsafe { mmio_read32(capability_base + HCSPARAMS1) };
        let hcs2 = unsafe { mmio_read32(capability_base + HCSPARAMS2) };
        let hcc1 = unsafe { mmio_read32(capability_base + HCCPARAMS1) };
        let version = (first >> 16) as u16;
        let capabilities = Capabilities::decode(version, hcs1, hcs2, hcc1);
        if capabilities.max_slots == 0
            || capabilities.max_ports == 0
            || capabilities.max_interrupters == 0
        {
            return Err(RegisterError::InvalidCapabilities);
        }
        // SAFETY: DBOFF and RTSOFF are fixed capability registers.
        let doorbell_offset = u64::from(unsafe { mmio_read32(capability_base + DBOFF) } & !3);
        // SAFETY: same invariant; low five RTSOFF bits are reserved.
        let runtime_offset = u64::from(unsafe { mmio_read32(capability_base + RTSOFF) } & !0x1f);
        let operational = capability_base
            .checked_add(capability_length)
            .ok_or(RegisterError::AddressOverflow)?;
        let runtime = capability_base
            .checked_add(runtime_offset)
            .ok_or(RegisterError::AddressOverflow)?;
        let doorbells = capability_base
            .checked_add(doorbell_offset)
            .ok_or(RegisterError::AddressOverflow)?;
        Ok(Self {
            capability: capability_base,
            operational,
            runtime,
            doorbells,
            capabilities,
        })
    }

    #[must_use]
    pub const fn capabilities(self) -> Capabilities {
        self.capabilities
    }

    /// Request xHCI ownership from legacy firmware and disable xHCI SMIs.
    pub fn take_ownership(self) -> Result<(), RegisterError> {
        let mut offset = self.capabilities.extended_capabilities_offset;
        for _ in 0..EXT_CAPABILITY_LIMIT {
            if offset == 0 || offset > 0x10_000 || offset & 3 != 0 {
                return Ok(());
            }
            let address = self
                .capability
                .checked_add(u64::from(offset))
                .ok_or(RegisterError::AddressOverflow)?;
            // SAFETY: extended-capability pointer was read from this BAR and
            // is bounded/aligned before dereference.
            let header = unsafe { mmio_read32(address) };
            let id = header as u8;
            let next = ((header >> 8) & 0xff) * 4;
            if id == EXT_CAP_ID_LEGACY_SUPPORT {
                if header & LEGACY_BIOS_OWNED != 0 {
                    // SAFETY: OS-owned is the writable semaphore in USBLEGSUP.
                    unsafe { mmio_write32(address, header | LEGACY_OS_OWNED) };
                    let released = super::wait::until(BIOS_OWNERSHIP_TIMEOUT_MS, || {
                        // SAFETY: same validated legacy-support register.
                        (unsafe { mmio_read32(address) }) & LEGACY_BIOS_OWNED == 0
                    });
                    if !released {
                        return Err(RegisterError::BiosOwnershipTimeout);
                    }
                }
                // Disable the SMI-enable low half and acknowledge any status
                // bits already set in the RW1C high half of USBLEGCTLSTS.
                // SAFETY: USBLEGCTLSTS immediately follows USBLEGSUP.
                let control = unsafe { mmio_read32(address + 4) };
                // SAFETY: zero low-half controls; writing back asserted status
                // bits clears them according to xHCI legacy-support semantics.
                unsafe { mmio_write32(address + 4, control & 0xffff_0000) };
            }
            if next == 0 {
                return Ok(());
            }
            offset = offset
                .checked_add(next)
                .ok_or(RegisterError::AddressOverflow)?;
        }
        Ok(())
    }

    /// Parse Supported Protocol extended capabilities (ID 2) into a fixed
    /// per-port Slot Type and custom-PSIV translation table.
    pub fn port_protocols(self) -> Result<PortProtocols, RegisterError> {
        let mut result = PortProtocols::new();
        let mut offset = self.capabilities.extended_capabilities_offset;
        for _ in 0..EXT_CAPABILITY_LIMIT {
            if offset == 0 {
                return Ok(result);
            }
            if offset > 0x10_000 || offset & 3 != 0 {
                return Err(RegisterError::InvalidCapabilities);
            }
            let address = self
                .capability
                .checked_add(u64::from(offset))
                .ok_or(RegisterError::AddressOverflow)?;
            // SAFETY: the extended-capability offset is bounded/aligned.
            let header = unsafe { mmio_read32(address) };
            let next = ((header >> 8) & 0xff) * 4;
            if header as u8 == EXT_CAP_ID_SUPPORTED_PROTOCOL {
                // SAFETY: DWORD2/3 are the fixed Supported Protocol prefix.
                let ports = unsafe { mmio_read32(address + 8) };
                // SAFETY: same capability prefix.
                let slot = unsafe { mmio_read32(address + 12) };
                let first_port = ports as u8;
                let port_count = (ports >> 8) as u8;
                let speed_count = ((ports >> 28) & 0x0f) as usize;
                let required_bytes = 0x10 + (speed_count as u32) * 4;
                if next != 0 && next < required_bytes {
                    return Err(RegisterError::InvalidCapabilities);
                }
                let final_port = first_port
                    .checked_add(port_count.saturating_sub(1))
                    .filter(|_| first_port != 0 && port_count != 0)
                    .filter(|port| *port <= self.capabilities.max_ports)
                    .ok_or(RegisterError::InvalidCapabilities)?;
                let mut semantic_by_psiv = [0u8; 16];
                if speed_count != 0 {
                    for index in 0..speed_count {
                        let psi_offset = offset
                            .checked_add(0x10 + (index as u32) * 4)
                            .filter(|offset| *offset <= 0x10_000)
                            .ok_or(RegisterError::InvalidCapabilities)?;
                        let psi_address = self
                            .capability
                            .checked_add(u64::from(psi_offset))
                            .ok_or(RegisterError::AddressOverflow)?;
                        // SAFETY: PSIC bounds the contiguous PSI dwords and
                        // the computed offset is checked above.
                        let psi = unsafe { mmio_read32(psi_address) };
                        let psiv = (psi & 0x0f) as usize;
                        if psiv == 0 {
                            return Err(RegisterError::InvalidCapabilities);
                        }
                        // Only symmetric PSI entries define one usable speed
                        // for both directions in this boot-HID slice.
                        if (psi >> 6) & 0x03 != 0 {
                            continue;
                        }
                        let Some(semantic) = semantic_speed_from_psi(psi) else {
                            continue;
                        };
                        let encoded = semantic.canonical_id();
                        if semantic_by_psiv[psiv] != 0 && semantic_by_psiv[psiv] != encoded {
                            return Err(RegisterError::InvalidCapabilities);
                        }
                        semantic_by_psiv[psiv] = encoded;
                    }
                }
                let protocol = PortProtocol {
                    claimed: true,
                    custom_speed_ids: speed_count != 0,
                    slot_type: (slot & 0x1f) as u8,
                    semantic_by_psiv,
                };
                for port_id in first_port..=final_port {
                    let entry = &mut result.ports[usize::from(port_id)];
                    if entry.claimed {
                        return Err(RegisterError::InvalidCapabilities);
                    }
                    *entry = protocol;
                }
                result.capability_present = true;
            }
            if next == 0 {
                return Ok(result);
            }
            offset = offset
                .checked_add(next)
                .ok_or(RegisterError::AddressOverflow)?;
        }
        Err(RegisterError::InvalidCapabilities)
    }

    /// Stop the controller, perform HCRST, and require native 4 KiB pages.
    pub fn reset(self) -> Result<(), RegisterError> {
        let command = self.op_read(USBCMD);
        self.op_write(USBCMD, command & !(CMD_RUN_STOP | CMD_INTERRUPTER_ENABLE));
        if !super::wait::until(CONTROLLER_TRANSITION_TIMEOUT_MS, || {
            self.op_read(USBSTS) & STATUS_HALTED != 0
        }) {
            return Err(RegisterError::HaltTimeout);
        }
        self.op_write(USBCMD, self.op_read(USBCMD) | CMD_HOST_CONTROLLER_RESET);
        // Intel xHC implementations require one millisecond immediately
        // after asserting HCRST before any further host-controller register
        // access; even the first reset-status poll must wait.
        crate::time::pit::pit_sleep(1);
        if !super::wait::until(CONTROLLER_TRANSITION_TIMEOUT_MS, || {
            self.op_read(USBCMD) & CMD_HOST_CONTROLLER_RESET == 0
        }) {
            return Err(RegisterError::ResetTimeout);
        }
        if !super::wait::until(CONTROLLER_TRANSITION_TIMEOUT_MS, || {
            self.op_read(USBSTS) & STATUS_CONTROLLER_NOT_READY == 0
        }) {
            return Err(RegisterError::ResetTimeout);
        }
        if self.op_read(PAGESIZE) & 1 == 0 {
            return Err(RegisterError::UnsupportedPageSize);
        }
        Ok(())
    }

    pub fn program_dcbaa(self, physical: u64) {
        self.op_write64(DCBAAP, physical & !0x3f);
    }

    pub fn program_command_ring(self, physical: u64, cycle: bool) {
        self.op_write64(CRCR, (physical & !0x3f) | u64::from(cycle));
    }

    pub fn set_max_slots(self, slots: u8) {
        self.op_write(CONFIG, u32::from(slots));
    }

    /// Program interrupter zero for a single event-ring segment.
    pub fn program_event_ring(self, erst: u64, dequeue: u64) {
        self.runtime_write(ERSTSZ, 1);
        self.runtime_write64(ERSTBA, erst & !0x3f);
        self.runtime_write64(ERDP, dequeue & !0x0f);
        // 1000 * 250 ns = 250 us moderation: bounded latency without an IRQ
        // for every individual keyboard/mouse packet during bursts.
        self.runtime_write(IMOD, 1000);
    }

    pub fn enable_interrupter(self, enabled: bool) {
        let current = self.runtime_read(IMAN);
        let value = if enabled {
            (current & !1) | (1 << 1)
        } else {
            current & !(1 << 1)
        };
        self.runtime_write(IMAN, value);
    }

    /// Publish consumed Event Ring space without ending the current Event
    /// Handler Busy interval. Synchronous waits use this bounded sub-batch
    /// update so an async burst cannot fill the ring ahead of its completion.
    pub fn publish_event_dequeue(self, next_dequeue: u64) {
        self.runtime_write64(ERDP, next_dequeue & !0x0f);
    }

    #[must_use]
    pub fn interrupt_pending(self) -> bool {
        self.runtime_read(IMAN) & 1 != 0 || self.op_read(USBSTS) & STATUS_EVENT_INTERRUPT != 0
    }

    /// Whether USBSTS reports a fatal host-system or host-controller error.
    /// The caller performs policy (including task-context fail-stop); this
    /// accessor only observes MMIO and is therefore safe in a hard IRQ.
    #[must_use]
    pub fn fatal_status(self) -> bool {
        status_is_fatal(self.op_read(USBSTS))
    }

    pub fn acknowledge_interrupter(self, next_dequeue: u64) {
        for write in INTERRUPTER_ACK_ORDER {
            match write {
                InterrupterAckWrite::PublishEventDequeue => {
                    // EHB (bit 3) is RW1C. Writing it with the new dequeue
                    // pointer clears Event Handler Busy only after software
                    // has consumed and published every preceding event.
                    self.runtime_write64(ERDP, (next_dequeue & !0x0f) | (1 << 3));
                },
                InterrupterAckWrite::ClearEventInterrupt => {
                    if self.op_read(USBSTS) & STATUS_EVENT_INTERRUPT != 0 {
                        self.op_write(USBSTS, STATUS_EVENT_INTERRUPT);
                    }
                },
                InterrupterAckWrite::ClearInterrupterPending => {
                    let iman = self.runtime_read(IMAN);
                    self.runtime_write(IMAN, (iman & (1 << 1)) | 1);
                },
            }
        }
    }

    /// Start command/event processing and enable the primary interrupter.
    pub fn start(self) -> Result<(), RegisterError> {
        self.enable_interrupter(true);
        let command = self.op_read(USBCMD) | CMD_RUN_STOP | CMD_INTERRUPTER_ENABLE;
        self.op_write(USBCMD, command);
        if !super::wait::until(CONTROLLER_TRANSITION_TIMEOUT_MS, || {
            let status = self.op_read(USBSTS);
            status_is_fatal(status) || status & STATUS_HALTED == 0
        }) {
            return Err(RegisterError::StartTimeout);
        }
        if self.fatal_status() {
            return Err(RegisterError::FatalControllerStatus);
        }
        Ok(())
    }

    /// Stop event generation and DMA before controller-owned storage is
    /// released. The caller still clears PCI Bus Master Enable even when the
    /// bounded halted wait fails, which is the final DMA safety fence.
    pub fn stop(self) -> Result<(), RegisterError> {
        self.enable_interrupter(false);
        let command = self.op_read(USBCMD) & !(CMD_RUN_STOP | CMD_INTERRUPTER_ENABLE);
        self.op_write(USBCMD, command);
        if !super::wait::until(CONTROLLER_TRANSITION_TIMEOUT_MS, || {
            self.op_read(USBSTS) & STATUS_HALTED != 0
        }) {
            return Err(RegisterError::HaltTimeout);
        }
        Ok(())
    }

    #[must_use]
    pub fn port_status(self, port_id: u8) -> u32 {
        self.op_read(port_offset(port_id))
    }

    /// Write PORTSC while preserving only software-controlled persistent bits.
    /// RW1C change bits are supplied explicitly by the caller; PED is never
    /// copied because writing a one would disable the port.
    pub fn write_port_status(self, port_id: u8, set: u32, acknowledge_changes: u32) {
        let current = self.port_status(port_id);
        let persistent = current & (PORT_POWER | (0b11 << 14) | (0b111 << 25));
        self.op_write(
            port_offset(port_id),
            persistent | set | (acknowledge_changes & PORT_CHANGE_BITS),
        );
    }

    #[must_use]
    pub fn port_speed(self, port_id: u8) -> u8 {
        ((self.port_status(port_id) >> PORT_SPEED_SHIFT) & 0x0f) as u8
    }

    /// Ring command doorbell zero or a device endpoint doorbell.
    pub fn ring_doorbell(self, slot_id: u8, target: u8) {
        let offset = u64::from(slot_id) * 4;
        // SAFETY: DBOFF names a 32-bit doorbell array and slot/target values
        // are bounded by controller capabilities/context indices.
        unsafe { mmio_write32(self.doorbells + offset, u32::from(target & 0x1f)) };
    }

    fn op_read(self, offset: u64) -> u32 {
        // SAFETY: fixed operational-register offset in the validated BAR.
        unsafe { mmio_read32(self.operational + offset) }
    }

    fn op_write(self, offset: u64, value: u32) {
        // SAFETY: fixed operational-register offset in the validated BAR.
        unsafe { mmio_write32(self.operational + offset, value) };
    }

    fn op_write64(self, offset: u64, value: u64) {
        // SAFETY: CRCR/DCBAAP are naturally aligned 64-bit operational regs.
        unsafe { mmio_write64(self.operational + offset, value) };
    }

    fn runtime_read(self, offset: u64) -> u32 {
        // SAFETY: interrupter-zero register offset in validated runtime space.
        unsafe { mmio_read32(self.runtime + RUNTIME_INTERRUPTER0 + offset) }
    }

    fn runtime_write(self, offset: u64, value: u32) {
        // SAFETY: same runtime-space invariant.
        unsafe { mmio_write32(self.runtime + RUNTIME_INTERRUPTER0 + offset, value) };
    }

    fn runtime_write64(self, offset: u64, value: u64) {
        // SAFETY: ERSTBA/ERDP are naturally aligned 64-bit runtime registers.
        unsafe { mmio_write64(self.runtime + RUNTIME_INTERRUPTER0 + offset, value) };
    }
}

const fn default_semantic_speed(raw_speed_id: u8) -> Option<UsbSpeed> {
    match raw_speed_id {
        1 => Some(UsbSpeed::Full),
        2 => Some(UsbSpeed::Low),
        3 => Some(UsbSpeed::High),
        4 => Some(UsbSpeed::Super),
        _ => None,
    }
}

const fn status_is_fatal(status: u32) -> bool {
    status & STATUS_FATAL != 0
}

const fn semantic_from_id(encoded: u8) -> Option<UsbSpeed> {
    match encoded {
        1 => Some(UsbSpeed::Full),
        2 => Some(UsbSpeed::Low),
        3 => Some(UsbSpeed::High),
        4 => Some(UsbSpeed::Super),
        _ => None,
    }
}

fn semantic_speed_from_psi(psi: u32) -> Option<UsbSpeed> {
    let exponent = (psi >> 4) & 0x03;
    let scale = match exponent {
        0 => 1u64,
        1 => 1_000,
        2 => 1_000_000,
        3 => 1_000_000_000,
        _ => unreachable!(),
    };
    let bits_per_second = u64::from(psi >> 16).checked_mul(scale)?;
    match bits_per_second {
        1_500_000 => Some(UsbSpeed::Low),
        12_000_000 => Some(UsbSpeed::Full),
        480_000_000 => Some(UsbSpeed::High),
        5_000_000_000.. => Some(UsbSpeed::Super),
        _ => None,
    }
}

const fn port_offset(port_id: u8) -> u64 {
    // Port IDs are one-based. Controller callers validate against MaxPorts.
    PORT_REGS + (port_id.saturating_sub(1) as u64) * PORT_STRIDE
}

unsafe fn mmio_read32(address: u64) -> u32 {
    // SAFETY: every caller documents the live aligned MMIO register.
    unsafe { read_volatile(address as *const u32) }
}

unsafe fn mmio_write32(address: u64, value: u32) {
    // SAFETY: every caller documents the live aligned MMIO register.
    unsafe { write_volatile(address as *mut u32, value) };
}

unsafe fn mmio_write64(address: u64, value: u64) {
    // SAFETY: xHCI's 64-bit registers are naturally aligned; x86_64 emits a
    // single aligned volatile store, as required when AC64 is in use.
    unsafe { write_volatile(address as *mut u64, value) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_fields_decode_including_split_scratchpad_count() {
        let hcs1 = 32 | (8 << 8) | (12 << 24);
        let hcs2 = (3 << 27) | (17 << 21);
        let hcc1 = HCC_AC64 | HCC_CSZ | (0x40 << 16);
        let decoded = Capabilities::decode(0x0110, hcs1, hcs2, hcc1);
        assert_eq!(decoded.max_slots, 32);
        assert_eq!(decoded.max_interrupters, 8);
        assert_eq!(decoded.max_ports, 12);
        assert_eq!(decoded.max_scratchpad_buffers, 547);
        assert_eq!(decoded.extended_capabilities_offset, 0x100);
        assert!(decoded.supports_64bit_addresses);
        assert!(decoded.context_size_64);
    }

    #[test]
    fn port_offsets_are_one_based_and_strided() {
        assert_eq!(port_offset(1), 0x400);
        assert_eq!(port_offset(2), 0x410);
        assert_eq!(port_offset(255), 0x13e0);
    }

    #[test]
    fn interrupt_acknowledgement_order_matches_xhci_contract() {
        assert_eq!(INTERRUPTER_ACK_ORDER, [
            InterrupterAckWrite::PublishEventDequeue,
            InterrupterAckWrite::ClearEventInterrupt,
            InterrupterAckWrite::ClearInterrupterPending,
        ]);
    }

    #[test]
    fn fatal_status_detects_host_system_and_controller_errors_only() {
        assert!(status_is_fatal(STATUS_HOST_SYSTEM_ERROR));
        assert!(status_is_fatal(STATUS_HOST_CONTROLLER_ERROR));
        assert!(status_is_fatal(
            STATUS_HOST_SYSTEM_ERROR | STATUS_HOST_CONTROLLER_ERROR
        ));
        assert!(!status_is_fatal(0));
        assert!(!status_is_fatal(
            STATUS_HALTED | STATUS_EVENT_INTERRUPT | STATUS_CONTROLLER_NOT_READY
        ));
    }

    #[test]
    fn psi_rates_translate_custom_ids_without_rewriting_raw_speed() {
        let low = 7 | (1 << 4) | (1500 << 16);
        let full = 9 | (2 << 4) | (12 << 16);
        let high = 11 | (2 << 4) | (480 << 16);
        let super_speed = 13 | (3 << 4) | (5 << 16);
        assert_eq!(semantic_speed_from_psi(low), Some(UsbSpeed::Low));
        assert_eq!(semantic_speed_from_psi(full), Some(UsbSpeed::Full));
        assert_eq!(semantic_speed_from_psi(high), Some(UsbSpeed::High));
        assert_eq!(semantic_speed_from_psi(super_speed), Some(UsbSpeed::Super));

        let mut protocols = PortProtocols::new();
        let mut speed_ids = [0; 16];
        speed_ids[13] = UsbSpeed::Super.canonical_id();
        protocols.capability_present = true;
        protocols.ports[4] = PortProtocol {
            claimed: true,
            custom_speed_ids: true,
            slot_type: 6,
            semantic_by_psiv: speed_ids,
        };
        assert_eq!(
            protocols.resolve(4, 13),
            Some(ResolvedPortSpeed {
                raw_speed_id: 13,
                semantic: UsbSpeed::Super,
                slot_type: 6,
            })
        );
        assert_eq!(protocols.resolve(4, 4), None);
    }

    #[test]
    fn absent_supported_protocol_uses_legacy_default_mapping_only() {
        let protocols = PortProtocols::new();
        assert_eq!(
            protocols.resolve(2, 3),
            Some(ResolvedPortSpeed {
                raw_speed_id: 3,
                semantic: UsbSpeed::High,
                slot_type: 0,
            })
        );
        assert_eq!(protocols.resolve(2, 9), None);
    }
}
