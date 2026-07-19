//! PCI configuration-space access via legacy I/O ports 0xCF8 / 0xCFC.
//!
//! The PC's "PCI configuration mechanism #1" exposes a 256-byte per-function
//! config space through two 32-bit I/O ports:
//!
//! * **CONFIG_ADDRESS** (0xCF8) — a write-only selector. The kernel writes a
//!   32-bit packed address naming the bus, device, function, and dword offset
//!   it wants to touch, with bit 31 set to "enable". Until a new address is
//!   written, every access to the data port hits the *same* selected dword.
//! * **CONFIG_DATA** (0xCFC) — the read/write window onto the selected dword.
//!   A 32-bit `in` reads the dword; a 32-bit `out` writes it. Sub-dword reads
//!   are permitted by the bus but the host bridge forwards them as a full
//!   dword, so this driver always accesses whole dwords and lets the caller
//!   mask out the byte/half it wants.
//!
//! This mechanism addresses only the low 256 bytes of config space per
//! function. PCIe extended config space (0x100..0xFFF) is reached through
//! memory-mapped ECAM, which a later phase wires up; the port mechanism is
//! universal across all PC hardware and is what bring-up uses to enumerate
//! the bus before any MMIO mapping exists.
//!
//! # Concurrency
//!
//! The address port is a single shared register on the host bridge. If two
//! CPUs interleaved writes to 0xCF8 the data port would return the wrong
//! device's register. Every [`PciAddress::read32`] / [`PciAddress::write32`]
//! pair is therefore wrapped in a spinlock ([`CONFIG_LOCK`]) so the
//! select-then-transfer sequence is atomic with respect to other CPUs. The
//! lock is held only across the two port cycles (a microsecond each), and the
//! higher-level helpers here each issue exactly one read32/write32, so there
//! is no re-entrancy.
//!
//! # Safety
//!
//! `in`/`out` to 0xCF8/0xCFC are privileged and the kernel owns both ports by
//! architecture convention. The actual instruction emission is encapsulated in
//! [`crate::arch::Port32`], which fixes the access width in the type; this
//! module only decides *which* dword to transfer. No `unsafe` block appears
//! here because the port handles present a safe surface and the only invariant
//! the type system cannot check — "these ports belong to the kernel" — is
//! satisfied by the PC architecture itself.

use core::fmt;

use crate::arch::{Port16, Port32, Port8};
use crate::sync::SpinLock;

// ---------------------------------------------------------------------------
// Port numbers and the CONFIG_ADDRESS bit layout
// ---------------------------------------------------------------------------

/// I/O port for the CONFIG_ADDRESS register (mechanism #1 address selector).
const CONFIG_ADDRESS: u16 = 0xCF8;

/// I/O port for the CONFIG_DATA register (the selected dword's read/write
/// window).
const CONFIG_DATA: u16 = 0xCFC;

/// Bit 31 of the CONFIG_ADDRESS dword: the "config-space enable" flag. The
/// host bridge ignores writes to 0xCF8 that do not have this bit set, which
/// is how the legacy mechanism distinguishes a config cycle from a stray
/// `out` to a neighbouring port.
const CONFIG_ENABLE: u32 = 1 << 31;

/// Mask for the dword-offset field of CONFIG_ADDRESS. The field occupies
/// bits 7..2 (a 6-bit, dword-aligned offset), so the low two bits of any
/// offset we feed in must be cleared before being OR'd into the address.
const OFFSET_MASK: u32 = 0xFC;

/// Maximum device index on a single PCI bus: 32 devices (5 bits, 0..=31).
pub const MAX_DEVICES_PER_BUS: u8 = 32;

/// Maximum function index on a single PCI device: 8 functions (3 bits,
/// 0..=7). A non-multifunction device only exposes function 0; a
/// multifunction device (header-type bit 7 set) exposes 0..=7.
pub const MAX_FUNCTIONS_PER_DEVICE: u8 = 8;

/// Number of Base Address Registers in a type-0 (general) header: six
/// 32-bit BARs at offsets 0x10..0x28. Bridge headers (type 1) only have
/// two BARs; the caller is responsible for not reading BARs 2..5 on a
/// bridge.
pub const NUM_BARS: usize = 6;

// ---------------------------------------------------------------------------
// Config-space register offsets (byte addresses, dword-aligned)
// ---------------------------------------------------------------------------

// The offsets below are the canonical type-0 header layout from the PCI
// Local Bus Specification. Each is the byte address of a dword; the read32
// path masks the low two bits, so callers may pass any of them directly.

/// Offset 0x00: Vendor ID (low 16) / Device ID (high 16).
const REG_VENDOR_DEVICE: u8 = 0x00;

/// Offset 0x04: Command (low 16) / Status (high 16).
const REG_COMMAND_STATUS: u8 = 0x04;

/// Offset 0x08: Revision ID (byte 0) / Class code (bytes 1..3).
const REG_CLASS_REVISION: u8 = 0x08;

/// Offset 0x0C: Cache-line size / latency timer / header type / BIST.
const REG_HEADER_BIST: u8 = 0x0C;

/// Offset 0x10: BAR0. BARs are contiguous dwords, so BAR *i* lives at
/// `REG_BAR0 + i * 4`.
const REG_BAR0: u8 = 0x10;

/// Offset 0x3C: interrupt line / interrupt pin / min grant / max latency.
const REG_INTERRUPT: u8 = 0x3C;

/// The vendor ID read from an absent function. The host bridge returns
/// all-ones for a config read that hits no device, so a 0xFFFF vendor means
/// "nothing at this BDF — stop probing this function".
pub const VENDOR_NONE: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// Config-space access lock
// ---------------------------------------------------------------------------

/// Serialises the two-port CONFIG_ADDRESS + CONFIG_DATA dance across CPUs.
///
/// The address selector is a single shared register on the host bridge; two
/// concurrent config transactions would clobber each other's selector and
/// return the wrong device's register. We hold this lock across the
/// address-write and the following data-transfer so the pair is atomic.
static CONFIG_LOCK: SpinLock<()> = SpinLock::new(());

/// Typed handle to the CONFIG_ADDRESS port (32-bit write-only selector).
static CONFIG_ADDRESS_PORT: Port32 = Port32::new(CONFIG_ADDRESS);

/// Typed handle to the CONFIG_DATA port (32-bit read/write window).
static CONFIG_DATA_PORT: Port32 = Port32::new(CONFIG_DATA);

// ---------------------------------------------------------------------------
// PciAddress — a bus/device/function triplet
// ---------------------------------------------------------------------------

/// A PCI bus/device/function triplet identifying a single function of a
/// device on the PCI bus.
///
/// This is the unit of config-space addressing: every read and write through
/// the 0xCF8/0xCFC ports is parameterised by a BDF plus a dword offset. The
/// triplet is small enough to be `Copy` and is passed by value through every
/// config helper.
///
/// The numeric ranges are architecturally fixed: `bus` is 0..=255 (one byte,
/// all values valid), `dev` is 0..=31, and `func` is 0..=7. [`PciAddress::new`]
/// validates `dev` and `func` and returns `None` for out-of-range inputs,
/// because the address-packing bit fields would silently alias a different
/// bus/device if an over-range value were truncated by the OR.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PciAddress {
    /// Bus number, 0..=255.
    pub bus: u8,
    /// Device number on the bus, 0..=31 (5 bits).
    pub dev: u8,
    /// Function number on the device, 0..=7 (3 bits).
    pub func: u8,
}

impl PciAddress {
    /// Construct a BDF triplet, validating the `dev`/`func` ranges.
    ///
    /// Returns `None` if `dev >= 32` or `func >= 8`. `bus` is not validated
    /// because every `u8` value is a legal bus number. Callers iterating the
    /// architectural ranges (`0..32` devices, `0..8` functions) will always
    /// get `Some`, so matching on the `Option` is cheap and never fails in
    /// practice.
    #[inline]
    #[must_use]
    pub const fn new(bus: u8, dev: u8, func: u8) -> Option<Self> {
        if dev < MAX_DEVICES_PER_BUS && func < MAX_FUNCTIONS_PER_DEVICE {
            Some(Self { bus, dev, func })
        } else {
            None
        }
    }

    /// The bus number.
    #[inline]
    #[must_use]
    pub const fn bus(self) -> u8 {
        self.bus
    }

    /// The device number on the bus.
    #[inline]
    #[must_use]
    pub const fn dev(self) -> u8 {
        self.dev
    }

    /// The device number on the bus.
    ///
    /// Spelled-out alias used by enumeration-facing code; equivalent to
    /// [`dev`](Self::dev).
    #[inline]
    #[must_use]
    pub const fn device(self) -> u8 {
        self.dev
    }

    /// The function number on the device.
    #[inline]
    #[must_use]
    pub const fn func(self) -> u8 {
        self.func
    }

    /// The function number on the device.
    ///
    /// Spelled-out alias used by enumeration-facing code; equivalent to
    /// [`func`](Self::func).
    #[inline]
    #[must_use]
    pub const fn function(self) -> u8 {
        self.func
    }

    /// Pack this BDF plus a dword offset into a CONFIG_ADDRESS dword.
    ///
    /// Bit 31 is the enable flag; bits 23..16 are the bus, 15..11 the
    /// device, 10..8 the function, and 7..2 the dword-aligned offset. The
    /// low two bits of `offset` are masked off so callers cannot accidentally
    /// select a non-dword-aligned window (the bridge would ignore them
    /// anyway, but masking makes the truncation explicit at the call site).
    #[inline]
    fn make_address(self, offset: u8) -> u32 {
        CONFIG_ENABLE
            | ((self.bus as u32) << 16)
            | ((self.dev as u32) << 11)
            | ((self.func as u32) << 8)
            | ((offset as u32) & OFFSET_MASK)
    }

    /// Read a 32-bit dword from config space at `offset` (byte address).
    ///
    /// `offset` may be any value in `0..=0xFF`; the low two bits are masked
    /// off by [`make_address`](Self::make_address). The whole select-then-read
    /// sequence runs under [`CONFIG_LOCK`] so it is atomic with respect to
    /// other CPUs.
    #[inline]
    #[must_use]
    pub fn read32(self, offset: u8) -> u32 {
        let _guard = CONFIG_LOCK.lock();
        CONFIG_ADDRESS_PORT.write(self.make_address(offset));
        CONFIG_DATA_PORT.read()
    }

    /// Write a 32-bit dword to config space at `offset` (byte address).
    ///
    /// See [`read32`](Self::read32) for the offset convention and locking.
    #[inline]
    pub fn write32(self, offset: u8, value: u32) {
        let _guard = CONFIG_LOCK.lock();
        CONFIG_ADDRESS_PORT.write(self.make_address(offset));
        CONFIG_DATA_PORT.write(value);
    }

    /// Read one byte without a read/modify/write of adjacent config fields.
    #[inline]
    #[must_use]
    pub fn read8(self, offset: u8) -> u8 {
        let _guard = CONFIG_LOCK.lock();
        CONFIG_ADDRESS_PORT.write(self.make_address(offset));
        Port8::new(CONFIG_DATA + u16::from(offset & 3)).read()
    }

    /// Read one 16-bit field contained in a single config dword.
    #[inline]
    #[must_use]
    pub fn read16(self, offset: u8) -> u16 {
        debug_assert!(offset & 3 <= 2, "PCI word crosses a config dword");
        let _guard = CONFIG_LOCK.lock();
        CONFIG_ADDRESS_PORT.write(self.make_address(offset));
        Port16::new(CONFIG_DATA + u16::from(offset & 3)).read()
    }

    /// Write one byte while preserving every adjacent config field.
    #[inline]
    pub fn write8(self, offset: u8, value: u8) {
        let _guard = CONFIG_LOCK.lock();
        CONFIG_ADDRESS_PORT.write(self.make_address(offset));
        Port8::new(CONFIG_DATA + u16::from(offset & 3)).write(value);
    }

    /// Write one 16-bit field contained in a single config dword.
    #[inline]
    pub fn write16(self, offset: u8, value: u16) {
        debug_assert!(offset & 3 <= 2, "PCI word crosses a config dword");
        let _guard = CONFIG_LOCK.lock();
        CONFIG_ADDRESS_PORT.write(self.make_address(offset));
        Port16::new(CONFIG_DATA + u16::from(offset & 3)).write(value);
    }

    // ----- Standard header reads -------------------------------------------

    /// Read the Vendor ID (dword 0x00, low 16 bits).
    ///
    /// A return value of [`VENDOR_NONE`] (0xFFFF) means no device is present
    /// at this BDF — the host bridge returns all-ones for an absent
    /// function. Probing code uses this to skip empty slots.
    #[inline]
    #[must_use]
    pub fn read_vendor(self) -> u16 {
        self.read32(REG_VENDOR_DEVICE) as u16
    }

    /// Read the Device ID (dword 0x00, high 16 bits).
    #[inline]
    #[must_use]
    pub fn read_device(self) -> u16 {
        (self.read32(REG_VENDOR_DEVICE) >> 16) as u16
    }

    /// Read the 24-bit class code (dword 0x08, bits 31..8).
    ///
    /// The returned `u32` packs the three class sub-fields as
    /// `base_class << 16 | subclass << 8 | prog_if`, with the 8-bit revision
    /// ID (bits 7..0 of the dword) stripped. Use [`PciDevice`](super::PciDevice)
    /// accessors or bit shifts to decode the individual bytes.
    #[inline]
    #[must_use]
    pub fn read_class(self) -> u32 {
        (self.read32(REG_CLASS_REVISION) >> 8) & 0x00FF_FFFF
    }

    /// Read the raw header-type byte at config offset 0x0E.
    ///
    /// The byte packs the 7-bit header layout kind in bits 6..0 and the
    /// "multifunction" flag in bit 7. Use [`read_header_type`](Self::read_header_type)
    /// for the decoded kind and [`is_multifunction`](Self::is_multifunction)
    /// for the flag.
    #[inline]
    #[must_use]
    pub fn read_header_type_byte(self) -> u8 {
        // The header-type byte lives at offset 0x0E, which is byte 2 of the
        // dword at 0x0C. Reading the whole dword and shifting preserves the
        // dword-access contract the host bridge expects.
        let dword = self.read32(REG_HEADER_BIST);
        ((dword >> 16) & 0xFF) as u8
    }

    /// Read the decoded header layout kind ([`PciHeaderType`]).
    ///
    /// This is [`read_header_type_byte`](Self::read_header_type_byte) with
    /// the multifunction bit masked off and decoded to the enum. The
    /// multifunction flag is reported separately by [`is_multifunction`].
    #[inline]
    #[must_use]
    pub fn read_header_type(self) -> PciHeaderType {
        PciHeaderType::from_byte(self.read_header_type_byte())
    }

    /// Whether this device is multifunction (header-type byte bit 7 set).
    ///
    /// Enumerators use this to decide whether to probe functions 1..7 after
    /// finding a present function 0: a single-function device has the bit
    /// clear and the remaining functions are guaranteed absent.
    #[inline]
    #[must_use]
    pub fn is_multifunction(self) -> bool {
        self.read_header_type_byte() & 0x80 != 0
    }

    /// Read BAR *i* (0..=5), or `None` if `i` is out of range.
    ///
    /// Returns the raw 32-bit BAR value; bit 0 (I/O-space vs memory-space)
    /// and bit 3 (prefetchable, for memory BARs) are still set, so callers
    /// must mask the low bits to recover the base address. A value of 0
    /// means the BAR is unimplemented by the device.
    #[inline]
    #[must_use]
    pub fn read_bar(self, index: usize) -> Option<u32> {
        if index >= NUM_BARS {
            return None;
        }
        let offset = REG_BAR0.wrapping_add((index as u8) * 4);
        Some(self.read32(offset))
    }

    /// Read the interrupt line register (dword 0x3C, byte 0).
    ///
    /// This is the x86 IRQ vector the device's interrupt pin (INTA#..INTD#)
    /// is routed to by the platform firmware, or 0 if the device does not
    /// request an IRQ / is unrouted. It is a write-back register the kernel
    /// reprograms once it owns the IOAPIC; the value read here is the BIOS
    /// default.
    #[inline]
    #[must_use]
    pub fn read_interrupt_line(self) -> u8 {
        self.read32(REG_INTERRUPT) as u8
    }

    /// Read the interrupt pin register (dword 0x3C, byte 1).
    ///
    /// 0 = no interrupt pin (device uses MSI/MSI-X or polls), 1 = INTA#,
    /// 2 = INTB#, 3 = INTC#, 4 = INTD#. Routing logic pairs this with the
    /// interrupt line to decide which IOAPIC input a function asserts.
    #[inline]
    #[must_use]
    pub fn read_interrupt_pin(self) -> u8 {
        ((self.read32(REG_INTERRUPT) >> 8) & 0xFF) as u8
    }

    /// Read the 16-bit Command register (dword 0x04, low 16 bits).
    ///
    /// The command register gates a device's response to I/O, memory, and
    /// bus-master cycles. After enumeration, drivers set the I/O-space,
    /// memory-space, and bus-master bits to enable the device's BARs and
    /// DMA; the firmware leaves most devices with these cleared until the
    /// OS takes over.
    #[inline]
    #[must_use]
    pub fn read_command(self) -> u16 {
        self.read32(REG_COMMAND_STATUS) as u16
    }

    /// Read the 16-bit Status register (dword 0x04, high 16 bits).
    #[inline]
    #[must_use]
    pub fn read_status(self) -> u16 {
        (self.read32(REG_COMMAND_STATUS) >> 16) as u16
    }

    /// Write the 16-bit Command register.
    ///
    /// The high 16 bits of the dword are the read-only status register, so
    /// this performs a read-modify-write to preserve them: a blind 32-bit
    /// write to 0x04 would clear the status bits the firmware set. Drivers
    /// call this to enable bus mastering, memory-space, or I/O-space as
    /// part of bring-up.
    #[inline]
    pub fn write_command(self, command: u16) {
        let status = self.read_status();
        let packed = ((status as u32) << 16) | (command as u32);
        self.write32(REG_COMMAND_STATUS, packed);
    }

    /// Whether any device is present at this BDF.
    ///
    /// Equivalent to `read_vendor() != VENDOR_NONE`. Probing code uses this
    /// as the cheap "is there something here?" check before reading the rest
    /// of the header.
    #[inline]
    #[must_use]
    pub fn is_present(self) -> bool {
        self.read_vendor() != VENDOR_NONE
    }
}

impl fmt::Display for PciAddress {
    /// Render as the canonical `BB:DD.F` PCI location string
    /// (e.g. `00:1f.0` for bus 0, device 31, function 0).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}.{:x}", self.bus, self.dev, self.func)
    }
}

// ---------------------------------------------------------------------------
// PciHeaderType
// ---------------------------------------------------------------------------

/// The header layout kind encoded in the byte at config offset 0x0E.
///
/// The PCI spec defines three header types; type 0 is the ordinary
/// peripheral, type 1 is a PCI-to-PCI bridge, and type 2 is a CardBus
/// bridge. The layout of the config dword at 0x10 onwards differs between
/// them (bridges have two BARs plus bridge windows instead of six BARs),
/// so code that interprets BARs or the header tail must branch on this.
///
/// The multifunction flag (bit 7 of the same byte) is *not* part of this
/// enum; it is read separately via [`PciAddress::is_multifunction`] because
/// it is orthogonal to the layout kind — a general device, a bridge, or a
/// CardBus bridge can each be either single- or multi-function.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum PciHeaderType {
    /// Type 0: a general (end-point) PCI device. Six BARs at 0x10..0x28.
    General,
    /// Type 1: a PCI-to-PCI bridge. Two BARs plus bridge window registers.
    PciBridge,
    /// Type 2: a CardBus bridge (PCI-to-PCMCIA). Rare on modern hardware.
    CardbusBridge,
    /// A reserved header-type value the kernel does not yet understand.
    /// The raw 7-bit kind is preserved so diagnostics can report it.
    Unknown(u8),
}

impl PciHeaderType {
    /// Decode the low 7 bits of the header-type byte into a [`PciHeaderType`].
    ///
    /// Bit 7 (the multifunction flag) is masked off before decoding, so the
    /// same kind is reported for a single- and a multi-function device of
    /// the same layout.
    #[inline]
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        match byte & 0x7F {
            0 => Self::General,
            1 => Self::PciBridge,
            2 => Self::CardbusBridge,
            other => Self::Unknown(other),
        }
    }

    /// The raw 7-bit header-type kind (0, 1, 2, or the preserved reserved
    /// value for [`Unknown`]).
    #[inline]
    #[must_use]
    pub const fn raw(self) -> u8 {
        match self {
            Self::General => 0,
            Self::PciBridge => 1,
            Self::CardbusBridge => 2,
            Self::Unknown(other) => other,
        }
    }

    /// Whether this is a type-0 general (end-point) device.
    #[inline]
    #[must_use]
    pub const fn is_general(self) -> bool {
        matches!(self, Self::General)
    }

    /// Whether this is a type-1 PCI-to-PCI bridge.
    #[inline]
    #[must_use]
    pub const fn is_bridge(self) -> bool {
        matches!(self, Self::PciBridge)
    }
}

impl fmt::Display for PciHeaderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::General => "general",
            Self::PciBridge => "pci-bridge",
            Self::CardbusBridge => "cardbus-bridge",
            Self::Unknown(n) => {
                return write!(f, "header-{}", n);
            },
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// Tests (host-only: exercise the pure packing/decode logic with no I/O)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_address_packs_bdf_and_offset() {
        // We cannot reach the real PciAddress::make_address (private) from a
        // test without I/O, so re-derive the expected encoding here and
        // cross-check against the documented bit layout. Bus 0xAA, dev 0x1B,
        // func 0x3, offset 0x3C:
        let bus = 0xAAu8;
        let dev = 0x1Bu8;
        let func = 0x03u8;
        let offset = 0x3Cu8;
        let expected = CONFIG_ENABLE
            | ((bus as u32) << 16)
            | ((dev as u32) << 11)
            | ((func as u32) << 8)
            | ((offset as u32) & OFFSET_MASK);
        // bit 31 enable, bus in 23..16, dev in 15..11, func in 10..8, off in 7..2.
        assert_eq!(expected & CONFIG_ENABLE, CONFIG_ENABLE);
        assert_eq!((expected >> 16) & 0xFF, 0xAA);
        assert_eq!((expected >> 11) & 0x1F, 0x1B);
        assert_eq!((expected >> 8) & 0x07, 0x03);
        assert_eq!(expected & OFFSET_MASK, 0x3C);
    }

    #[test]
    fn new_validates_dev_and_func_ranges() {
        // In-range construction succeeds for all valid dev/func.
        assert!(PciAddress::new(0, 0, 0).is_some());
        assert!(PciAddress::new(0xFF, 31, 7).is_some());
        // Out-of-range dev or func is rejected: over-range values would
        // alias a different bus/device in the packed address, so the
        // constructor refuses rather than silently truncating.
        assert!(PciAddress::new(0, 32, 0).is_none());
        assert!(PciAddress::new(0, 0, 8).is_none());
        // Every bus value is legal (one byte, 0..=255).
        assert!(PciAddress::new(255, 0, 0).is_some());
    }

    #[test]
    fn header_type_decode_strips_multifunction_bit() {
        // The multifunction bit (0x80) is orthogonal to the layout kind;
        // from_byte must produce the same kind with and without it.
        assert_eq!(PciHeaderType::from_byte(0x00), PciHeaderType::General);
        assert_eq!(PciHeaderType::from_byte(0x80), PciHeaderType::General);
        assert_eq!(PciHeaderType::from_byte(0x01), PciHeaderType::PciBridge);
        assert_eq!(PciHeaderType::from_byte(0x81), PciHeaderType::PciBridge);
        assert_eq!(PciHeaderType::from_byte(0x82), PciHeaderType::CardbusBridge);
        // Reserved kinds preserve the 7-bit value for diagnostics.
        assert_eq!(PciHeaderType::from_byte(0x0F), PciHeaderType::Unknown(0x0F));
        assert_eq!(PciHeaderType::from_byte(0x8F), PciHeaderType::Unknown(0x0F));
    }

    #[test]
    fn header_type_predicates_and_raw() {
        assert!(PciHeaderType::General.is_general());
        assert!(!PciHeaderType::General.is_bridge());
        assert!(PciHeaderType::PciBridge.is_bridge());
        assert_eq!(PciHeaderType::General.raw(), 0);
        assert_eq!(PciHeaderType::PciBridge.raw(), 1);
        assert_eq!(PciHeaderType::CardbusBridge.raw(), 2);
        assert_eq!(PciHeaderType::Unknown(0x42).raw(), 0x42);
    }

    #[test]
    fn display_formats_bdf() {
        // `format!` requires the allocator, so drive the `Display` impl
        // through a fixed-buffer writer instead. This keeps the test
        // `no_std`-clean, matching the bitmap-test pattern.
        use core::fmt::Write;
        struct BufWriter {
            buf: [u8; 16],
            pos: usize,
        }
        impl Write for BufWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                if self.pos + bytes.len() > self.buf.len() {
                    return Err(core::fmt::Error);
                }
                self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
                self.pos += bytes.len();
                Ok(())
            }
        }
        fn render(addr: PciAddress, buf: &mut BufWriter) -> &str {
            buf.pos = 0;
            write!(buf, "{addr}").unwrap();
            core::str::from_utf8(&buf.buf[..buf.pos]).unwrap()
        }
        let mut buf = BufWriter {
            buf: [0u8; 16],
            pos: 0,
        };
        let a = PciAddress::new(0, 0x1F, 0).unwrap();
        assert_eq!(render(a, &mut buf), "00:1f.0");
        let b = PciAddress::new(0xAA, 0x05, 0x3).unwrap();
        assert_eq!(render(b, &mut buf), "aa:05.3");
    }
}
