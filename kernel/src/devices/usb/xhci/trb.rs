//! xHCI Transfer Request Block construction and event decoding.
//!
//! Layout and bit positions follow xHCI 1.2 section 6.4.  Keeping TRBs as a
//! transparent four-dword value makes DMA writes explicit and allows tests to
//! verify every field without touching controller memory.

/// Bytes in every xHCI TRB.
pub const TRB_SIZE: usize = 16;

const CYCLE: u32 = 1;
const TOGGLE_CYCLE: u32 = 1 << 1;
const INTERRUPT_ON_SHORT_PACKET: u32 = 1 << 2;
const CHAIN: u32 = 1 << 4;
const INTERRUPT_ON_COMPLETION: u32 = 1 << 5;
const IMMEDIATE_DATA: u32 = 1 << 6;
const DIRECTION_IN: u32 = 1 << 16;
const BLOCK_SET_ADDRESS_REQUEST: u32 = 1 << 9;
const TYPE_SHIFT: u32 = 10;

pub const TYPE_NORMAL: u8 = 1;
pub const TYPE_SETUP_STAGE: u8 = 2;
pub const TYPE_DATA_STAGE: u8 = 3;
pub const TYPE_STATUS_STAGE: u8 = 4;
pub const TYPE_LINK: u8 = 6;
pub const TYPE_ENABLE_SLOT_COMMAND: u8 = 9;
pub const TYPE_DISABLE_SLOT_COMMAND: u8 = 10;
pub const TYPE_ADDRESS_DEVICE_COMMAND: u8 = 11;
pub const TYPE_CONFIGURE_ENDPOINT_COMMAND: u8 = 12;
pub const TYPE_EVALUATE_CONTEXT_COMMAND: u8 = 13;
pub const TYPE_TRANSFER_EVENT: u8 = 32;
pub const TYPE_COMMAND_COMPLETION_EVENT: u8 = 33;
pub const TYPE_PORT_STATUS_CHANGE_EVENT: u8 = 34;

/// One little-endian 16-byte TRB as observed by the controller.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Trb {
    pub parameter_low: u32,
    pub parameter_high: u32,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    /// Construct a zeroed TRB with only the requested type encoded.
    #[must_use]
    pub const fn typed(trb_type: u8) -> Self {
        Self {
            parameter_low: 0,
            parameter_high: 0,
            status: 0,
            control: (trb_type as u32) << TYPE_SHIFT,
        }
    }

    /// 64-bit parameter field.
    #[must_use]
    pub const fn parameter(self) -> u64 {
        (self.parameter_low as u64) | ((self.parameter_high as u64) << 32)
    }

    /// Set the 64-bit parameter field.
    #[must_use]
    pub const fn with_parameter(mut self, parameter: u64) -> Self {
        self.parameter_low = parameter as u32;
        self.parameter_high = (parameter >> 32) as u32;
        self
    }

    /// TRB type from control bits 15:10.
    #[must_use]
    pub const fn trb_type(self) -> u8 {
        ((self.control >> TYPE_SHIFT) & 0x3f) as u8
    }

    /// Producer/consumer cycle bit.
    #[must_use]
    pub const fn cycle(self) -> bool {
        self.control & CYCLE != 0
    }

    /// Install the producer cycle bit last before a TRB is made visible.
    #[must_use]
    pub const fn with_cycle(mut self, cycle: bool) -> Self {
        self.control &= !CYCLE;
        if cycle {
            self.control |= CYCLE;
        }
        self
    }

    /// Link TRB that wraps a producer ring and toggles its cycle state.
    #[must_use]
    pub const fn link(target: u64, chain: bool) -> Self {
        let mut trb = Self::typed(TYPE_LINK)
            .with_parameter(target)
            .with_control_bits(TOGGLE_CYCLE);
        if chain {
            trb.control |= CHAIN;
        }
        trb
    }

    /// Whether this TRB chains the following TRB into the same Transfer
    /// Descriptor. Producer rings mirror this bit onto a Link TRB when a TD
    /// crosses the physical end of the ring.
    #[must_use]
    pub const fn chained(self) -> bool {
        self.control & CHAIN != 0
    }

    /// Enable Slot command carrying the Supported Protocol Slot Type.
    #[must_use]
    pub const fn enable_slot(slot_type: u8) -> Self {
        let mut trb = Self::typed(TYPE_ENABLE_SLOT_COMMAND);
        trb.control |= ((slot_type & 0x1f) as u32) << 16;
        trb
    }

    /// Disable Slot command.
    #[must_use]
    pub const fn disable_slot(slot_id: u8) -> Self {
        let mut trb = Self::typed(TYPE_DISABLE_SLOT_COMMAND);
        trb.control |= (slot_id as u32) << 24;
        trb
    }

    /// Address Device command using the supplied input-context pointer.
    #[must_use]
    pub const fn address_device(input_context: u64, slot_id: u8, block_set_address: bool) -> Self {
        let mut trb = Self::typed(TYPE_ADDRESS_DEVICE_COMMAND).with_parameter(input_context);
        trb.control |= (slot_id as u32) << 24;
        if block_set_address {
            trb.control |= BLOCK_SET_ADDRESS_REQUEST;
        }
        trb
    }

    /// Configure Endpoint command.
    #[must_use]
    pub const fn configure_endpoint(input_context: u64, slot_id: u8) -> Self {
        let mut trb = Self::typed(TYPE_CONFIGURE_ENDPOINT_COMMAND).with_parameter(input_context);
        trb.control |= (slot_id as u32) << 24;
        trb
    }

    /// Evaluate Context command, used to update full-speed EP0 max packet.
    #[must_use]
    pub const fn evaluate_context(input_context: u64, slot_id: u8) -> Self {
        let mut trb = Self::typed(TYPE_EVALUATE_CONTEXT_COMMAND).with_parameter(input_context);
        trb.control |= (slot_id as u32) << 24;
        trb
    }

    /// Setup Stage TRB with the eight-byte USB setup packet as immediate data.
    #[must_use]
    pub const fn setup(setup: [u8; 8], direction: SetupDirection) -> Self {
        let mut trb = Self::typed(TYPE_SETUP_STAGE);
        trb.parameter_low = u32::from_le_bytes([setup[0], setup[1], setup[2], setup[3]]);
        trb.parameter_high = u32::from_le_bytes([setup[4], setup[5], setup[6], setup[7]]);
        trb.status = 8;
        trb.control |= IMMEDIATE_DATA | CHAIN | ((direction as u32) << 16);
        trb
    }

    /// Data Stage TRB for a control transfer.
    #[must_use]
    pub const fn data(buffer: u64, length: u32, direction_in: bool) -> Self {
        let mut trb = Self::typed(TYPE_DATA_STAGE).with_parameter(buffer);
        trb.status = length & 0x1ffff;
        trb.control |= CHAIN | INTERRUPT_ON_SHORT_PACKET;
        if direction_in {
            trb.control |= DIRECTION_IN;
        }
        trb
    }

    /// Status Stage TRB, completing a control-transfer TD.
    #[must_use]
    pub const fn status(direction_in: bool) -> Self {
        let mut trb = Self::typed(TYPE_STATUS_STAGE);
        trb.control |= INTERRUPT_ON_COMPLETION;
        if direction_in {
            trb.control |= DIRECTION_IN;
        }
        trb
    }

    /// Interrupt-IN Normal TRB. Short reports are successful and produce an
    /// event so variable-length mouse reports are not delayed.
    #[must_use]
    pub const fn normal(buffer: u64, length: u32) -> Self {
        let mut trb = Self::typed(TYPE_NORMAL).with_parameter(buffer);
        trb.status = length & 0x1ffff;
        trb.control |= INTERRUPT_ON_SHORT_PACKET | INTERRUPT_ON_COMPLETION;
        trb
    }

    const fn with_control_bits(mut self, bits: u32) -> Self {
        self.control |= bits;
        self
    }
}

/// Transfer type field of a Setup Stage TRB.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupDirection {
    NoData = 0,
    Out = 2,
    In = 3,
}

/// Completion codes consumed by the bounded command/transfer state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionCode(pub u8);

impl CompletionCode {
    pub const INVALID: Self = Self(0);
    pub const SUCCESS: Self = Self(1);
    pub const DATA_BUFFER_ERROR: Self = Self(2);
    pub const BABBLE_DETECTED: Self = Self(3);
    pub const USB_TRANSACTION_ERROR: Self = Self(4);
    pub const TRB_ERROR: Self = Self(5);
    pub const STALL_ERROR: Self = Self(6);
    pub const RESOURCE_ERROR: Self = Self(7);
    pub const BANDWIDTH_ERROR: Self = Self(8);
    pub const NO_SLOTS_AVAILABLE: Self = Self(9);
    pub const SHORT_PACKET: Self = Self(13);

    /// Success for a command TRB (short packets are transfer-only success).
    #[must_use]
    pub const fn command_succeeded(self) -> bool {
        self.0 == Self::SUCCESS.0
    }

    /// Successful transfer, including a valid short input report/descriptor.
    #[must_use]
    pub const fn transfer_succeeded(self) -> bool {
        self.0 == Self::SUCCESS.0 || self.0 == Self::SHORT_PACKET.0
    }
}

/// Event types relevant to command completion, transfers, and root-port
/// changes. Unknown event TRBs are surfaced rather than mis-decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    CommandCompletion {
        command_pointer: u64,
        code: CompletionCode,
        slot_id: u8,
    },
    Transfer {
        trb_pointer: u64,
        residual: u32,
        code: CompletionCode,
        endpoint_id: u8,
        slot_id: u8,
    },
    PortStatusChange {
        port_id: u8,
        code: CompletionCode,
    },
    Unknown(Trb),
}

impl Event {
    /// Decode a consumer-owned event TRB.
    #[must_use]
    pub const fn decode(trb: Trb) -> Self {
        let code = CompletionCode((trb.status >> 24) as u8);
        match trb.trb_type() {
            TYPE_COMMAND_COMPLETION_EVENT => Self::CommandCompletion {
                command_pointer: trb.parameter() & !0x0f,
                code,
                slot_id: (trb.control >> 24) as u8,
            },
            TYPE_TRANSFER_EVENT => Self::Transfer {
                trb_pointer: trb.parameter() & !0x0f,
                residual: trb.status & 0x00ff_ffff,
                code,
                endpoint_id: ((trb.control >> 16) & 0x1f) as u8,
                slot_id: (trb.control >> 24) as u8,
            },
            TYPE_PORT_STATUS_CHANGE_EVENT => Self::PortStatusChange {
                port_id: (trb.parameter_low >> 24) as u8,
                code,
            },
            _ => Self::Unknown(trb),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_stage_packs_request_little_endian_and_trt() {
        let setup = Trb::setup([0x80, 6, 0, 1, 0, 0, 18, 0], SetupDirection::In);
        assert_eq!(setup.parameter_low, 0x0100_0680);
        assert_eq!(setup.parameter_high, 0x0012_0000);
        assert_eq!(setup.status, 8);
        assert_eq!(setup.trb_type(), TYPE_SETUP_STAGE);
        assert_eq!((setup.control >> 16) & 3, 3);
    }

    #[test]
    fn link_and_normal_trbs_carry_required_control_bits() {
        let link = Trb::link(0x1234_5000, false).with_cycle(true);
        assert_eq!(link.parameter(), 0x1234_5000);
        assert!(link.cycle());
        assert_ne!(link.control & TOGGLE_CYCLE, 0);

        let chained = Trb::link(0x1234_5000, true);
        assert!(chained.chained());

        let normal = Trb::normal(0x2000, 64);
        assert_eq!(normal.status & 0x1ffff, 64);
        assert_ne!(normal.control & INTERRUPT_ON_COMPLETION, 0);
        assert_ne!(normal.control & INTERRUPT_ON_SHORT_PACKET, 0);
    }

    #[test]
    fn enable_slot_carries_supported_protocol_slot_type() {
        let command = Trb::enable_slot(0x15);
        assert_eq!(command.trb_type(), TYPE_ENABLE_SLOT_COMMAND);
        assert_eq!((command.control >> 16) & 0x1f, 0x15);
    }

    #[test]
    fn decodes_command_transfer_and_port_events() {
        let command = Trb {
            parameter_low: 0x1234_5678,
            parameter_high: 1,
            status: 1 << 24,
            control: (33 << 10) | (7 << 24),
        };
        assert_eq!(Event::decode(command), Event::CommandCompletion {
            command_pointer: 0x0000_0001_1234_5670,
            code: CompletionCode::SUCCESS,
            slot_id: 7,
        });

        let transfer = Trb {
            parameter_low: 0x2000,
            parameter_high: 0,
            status: (13 << 24) | 3,
            control: (32 << 10) | (3 << 16) | (2 << 24),
        };
        assert_eq!(Event::decode(transfer), Event::Transfer {
            trb_pointer: 0x2000,
            residual: 3,
            code: CompletionCode::SHORT_PACKET,
            endpoint_id: 3,
            slot_id: 2,
        });

        let port = Trb {
            parameter_low: 4 << 24,
            parameter_high: 0,
            status: 1 << 24,
            control: 34 << 10,
        };
        assert!(matches!(Event::decode(port), Event::PortStatusChange {
            port_id: 4,
            ..
        }));
    }
}
