//! PCI bus core: device descriptor, config-space types, and enumeration hub.
//!
//! This module is the root of the kernel's PCI support. It owns the compact
//! [`PciDevice`] config snapshot used by low-level controller code and
//! re-exports the config-space access primitives from [`config`]. The actual
//! recursive bus walk and richer discovery record live in [`enumerate`]; all
//! config transactions share [`config::PciAddress`] and its global selector
//! lock.
//!
//! # Layering
//!
//! `pci` sits under the device drivers (NIC, AHCI, NVMe, USB host) and above
//! [`crate::arch`] (for port I/O) and [`crate::sync`] (for the config-space
//! lock). It is initialised after the console and log facade are up so
//! enumeration progress can be reported, and before any PCI device driver
//! that needs a BAR or an IRQ vector.
//!
//! # The PCI address model
//!
//! A PCI function is identified by a 24-bit bus/device/function (BDF) triplet:
//! up to 256 buses, 32 devices per bus, 8 functions per device. Each function
//! exposes a 256-byte config space reached through [`config::PciAddress`].
//! [`PciDevice`] is a compact decoded-header view: vendor and device IDs, the
//! class code, six BARs, and the interrupt line. Enumeration retains
//! additional topology fields in [`enumerate::PciDevice`] and converts only
//! when a low-level driver needs this compact form.

pub mod capability;
pub mod config;
pub mod enumerate;
pub mod routing;

// Re-export the config-space primitives so callers write
// `crate::devices::pci::PciAddress` rather than drilling into `config`. The
// `enumerate` module and every PCI device driver reach the bus through these.
use core::fmt;

pub use config::{PciAddress, PciHeaderType};
use xenith_bitflags::bitflags;

use crate::devices::pci::config::{NUM_BARS, VENDOR_NONE};

// ---------------------------------------------------------------------------
// PciCommand — typed bits of the config-space Command register (offset 0x04)
// ---------------------------------------------------------------------------

bitflags! {
    /// The 16-bit PCI Command register at config offset 0x04, low half.
    ///
    /// The command register gates a device's response to bus cycles. After
    /// enumeration the firmware has typically left I/O-space, memory-space,
    /// and bus-master all *disabled*; a driver brings its device online by
    /// reading the current command value, OR-ing in the capabilities it
    /// needs, and writing it back through [`PciAddress::write_command`].
    ///
    /// Use [`PciCommand::from_bits_truncate`] on the value returned by
    /// [`PciAddress::read_command`] to ignore unknown/reserved bits a future
    /// PCI revision might define, and `.bits()` to feed the result back to
    /// [`PciAddress::write_command`].
    pub struct PciCommand: u16 {
        /// Bit 0: respond to I/O-space transactions. Required for any device
        /// whose BARs include an I/O-port BAR.
        pub const IO_SPACE                = 1 << 0;
        /// Bit 1: respond to memory-space transactions. Required for any
        /// device with a memory-mapped BAR (the common case on modern PCIe).
        pub const MEMORY_SPACE            = 1 << 1;
        /// Bit 2: enable bus mastering. The device may initiate memory
        /// reads/writes (DMA); without this, DMA engines are inert.
        pub const BUS_MASTER              = 1 << 2;
        /// Bit 3: enable monitoring of special cycles. Rarely used by
        /// end-point drivers.
        pub const SPECIAL_CYCLES          = 1 << 3;
        /// Bit 4: enable memory-write-and-invalidate. Allows the device to
        /// issue the MWI transaction, which the host bridge may optimise.
        pub const MEMORY_WRITE_INVALIDATE = 1 << 4;
        /// Bit 5: VGA palette snooping. Only relevant for VGA-compatible
        /// devices; harmless to leave clear otherwise.
        pub const VGA_PALETTE_SNOOP       = 1 << 5;
        /// Bit 6: enable parity error response. When set, the device asserts
        /// SERR# / reports a parity error instead of silently ignoring it.
        pub const PARITY_ERROR_RESPONSE   = 1 << 6;
        /// Bit 7: address/data stepping. Used by devices that cannot drive
        /// the full address in one cycle; almost always left clear.
        pub const ADDRESS_DATA_STEPPING   = 1 << 7;
        /// Bit 8: enable asserting SERR# on system errors.
        pub const SERR_ENABLE             = 1 << 8;
        /// Bit 9: enable fast back-to-back transactions to different agents.
        pub const FAST_BACK_TO_BACK       = 1 << 9;
        /// Bit 10 (PCI 2.3+): disable assertion of the legacy INTx interrupt
        /// line. Set by drivers that use MSI/MSI-X so the device does not
        /// also toggle the legacy pin.
        pub const INTERRUPT_DISABLE       = 1 << 10;
    }
}

// ---------------------------------------------------------------------------
// PciDevice — the decoded config-space snapshot of one function
// ---------------------------------------------------------------------------

/// A compact snapshot of a PCI function's standard header.
///
/// `PciDevice` holds the fields a driver consults at bring-up: the vendor and
/// device IDs for matching, the class code for generic-class drivers, the six
/// Base Address Registers for mapping the device's register file, and the
/// interrupt line the firmware routed the function's INTx pin to. It is a
/// pure-data `Copy` record; reading it never touches the bus, so any number
/// of CPUs can inspect a device simultaneously without contention.
///
/// The header *type* is intentionally not stored here: it is a one-byte value
/// cheap to re-read through [`PciAddress::read_header_type`] when a driver
/// needs to branch on it, and keeping it out of the struct means the field
/// list stays exactly the set enumeration fills in. Use [`PciDevice::address`]
/// to recover the [`PciAddress`] for any on-demand config read.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct PciDevice {
    /// Bus number, 0..=255.
    pub bus: u8,
    /// Device number on the bus, 0..=31.
    pub dev: u8,
    /// Function number on the device, 0..=7.
    pub func: u8,
    /// Vendor ID. `0xFFFF` ([`VENDOR_NONE`]) would mean "absent", but a
    /// `PciDevice` only exists for present functions, so this is always a
    /// real vendor code (e.g. `0x8086` for Intel, `0x10DE` for NVIDIA).
    pub vendor: u16,
    /// Device ID, scoped to the vendor.
    pub device: u16,
    /// 24-bit class code: `base_class << 16 | subclass << 8 | prog_if`.
    /// Use [`base_class`](Self::base_class), [`subclass`](Self::subclass),
    /// and [`prog_if`](Self::prog_if) to decode the individual bytes.
    pub class: u32,
    /// The six Base Address Registers (type-0 header). A value of `0` means
    /// the BAR is unimplemented by the device; the low bits carry the
    /// type/prefetchable flags that [`PciAddress::read_bar`] documents.
    pub bars: [u32; NUM_BARS],
    /// The interrupt line register: the x86 IRQ vector the firmware routed
    /// the function's INTx pin to, or `0` if unrouted. Drivers that switch
    /// to MSI/MSI-X ignore this; legacy-IRQ drivers feed it to the IOAPIC
    /// router once the kernel owns interrupt delivery.
    pub irq: u8,
}

impl PciDevice {
    /// Probe a PCI function and snapshot its standard header.
    ///
    /// Reads the vendor ID first; if the function is absent
    /// ([`VENDOR_NONE`]) this returns `None` so the caller can skip the BDF
    /// without paying for the remaining reads. For a present function the
    /// device ID, class code, all six BARs, and the interrupt line are read
    /// in the documented order and packed into a [`PciDevice`].
    ///
    /// Each read is a separate locked config transaction (see
    /// [`config::PciAddress::read32`]); the seven reads therefore cost seven
    /// lock acquisitions. This is fine for one-time enumeration but drivers
    /// that re-read a register in a hot path should cache the value.
    #[must_use]
    pub fn probe(addr: PciAddress) -> Option<Self> {
        let vendor = addr.read_vendor();
        if vendor == VENDOR_NONE {
            return None;
        }
        // Read the six BARs. `read_bar` returns `Option` only to bound the
        // index; for 0..NUM_BARS it is always `Some`, so `unwrap_or(0)`
        // never falls back but documents the "unimplemented -> 0" intent.
        let mut bars = [0u32; NUM_BARS];
        for (i, slot) in bars.iter_mut().enumerate() {
            *slot = addr.read_bar(i).unwrap_or(0);
        }
        Some(Self {
            bus: addr.bus(),
            dev: addr.dev(),
            func: addr.func(),
            vendor,
            device: addr.read_device(),
            class: addr.read_class(),
            bars,
            irq: addr.read_interrupt_line(),
        })
    }

    /// The [`PciAddress`] identifying this function on the bus.
    ///
    /// Reconstruction is infallible because `probe` only constructs a
    /// `PciDevice` from an in-range address; `bus`/`dev`/`func` are stored
    /// verbatim, so [`PciAddress::new`] always returns `Some` here.
    #[inline]
    #[must_use]
    pub fn address(self) -> PciAddress {
        // unwrap_or is unreachable for a valid PciDevice but avoids panicking
        // if a caller hand-constructed an out-of-range record.
        PciAddress::new(self.bus, self.dev, self.func).unwrap_or(PciAddress {
            bus: self.bus,
            dev: self.dev & (config::MAX_DEVICES_PER_BUS - 1),
            func: self.func & (config::MAX_FUNCTIONS_PER_DEVICE - 1),
        })
    }

    /// Whether this record describes a present device.
    ///
    /// Always `true` for a `PciDevice` produced by [`probe`], since `probe`
    /// returns `None` for an absent function. This exists for callers that
    /// receive a `PciDevice` from another source and want a cheap sanity
    /// check without re-reading the bus.
    #[inline]
    #[must_use]
    pub fn is_present(self) -> bool {
        self.vendor != VENDOR_NONE
    }

    /// Re-read the header layout kind from the bus.
    ///
    /// Not stored in the struct (see the type docs); computed on demand so
    /// the field list stays exactly what enumeration fills in. A driver that
    /// needs to branch on bridge-vs-end-point calls this once at bring-up.
    #[inline]
    #[must_use]
    pub fn header_type(self) -> PciHeaderType {
        self.address().read_header_type()
    }

    /// Whether this device is multifunction (header-type byte bit 7 set).
    #[inline]
    #[must_use]
    pub fn is_multifunction(self) -> bool {
        self.address().is_multifunction()
    }

    /// Base class byte (bits 23..16 of the class code).
    ///
    /// This is the coarse device category — mass storage, network, display,
    /// bridge, etc. — and the key generic-class drivers match on. See
    /// [`base_class_name`] for a human-readable label.
    #[inline]
    #[must_use]
    pub const fn base_class(self) -> u8 {
        (self.class >> 16) as u8
    }

    /// Sub-class byte (bits 15..8 of the class code).
    #[inline]
    #[must_use]
    pub const fn subclass(self) -> u8 {
        (self.class >> 8) as u8
    }

    /// Programming interface byte (bits 7..0 of the class code).
    #[inline]
    #[must_use]
    pub const fn prog_if(self) -> u8 {
        self.class as u8
    }

    /// BAR *i* (0..=5), or `0` if `i` is out of range.
    ///
    /// The stored value is the raw 32-bit BAR; bit 0 distinguishes I/O
    /// (`1`) from memory (`0`) space and, for memory BARs, bit 3 marks
    /// prefetchability. Mask the low 4 bits (memory) or low 2 bits (I/O) to
    /// recover the base address. `0` means the BAR is unimplemented.
    #[inline]
    #[must_use]
    pub fn bar(self, index: usize) -> u32 {
        if index < self.bars.len() {
            self.bars[index]
        } else {
            0
        }
    }

    /// The first memory-space BAR, or `None` if every BAR is I/O or
    /// unimplemented.
    ///
    /// Convenience for the common case where a driver wants "the" MMIO
    /// register file of an end-point. Bit 0 clear and a non-zero base
    /// identify a memory BAR.
    #[must_use]
    pub fn first_memory_bar(self) -> Option<u32> {
        self.bars
            .iter()
            .copied()
            .find(|&bar| bar != 0 && bar & 0x1 == 0)
    }

    /// The first I/O-space BAR, or `None` if every BAR is memory or
    /// unimplemented. Bit 0 set identifies an I/O BAR.
    #[must_use]
    pub fn first_io_bar(self) -> Option<u32> {
        self.bars
            .iter()
            .copied()
            .find(|&bar| bar != 0 && bar & 0x1 == 1)
    }
}

impl fmt::Display for PciDevice {
    /// Render as `BB:DD.F vendor:device <class-name>` for log lines.
    ///
    /// Picked deliberately compact so a bus scan can print one device per
    /// line without overflowing the serial console, e.g.
    /// `00:1f.0 8086:2918 isa-bridge`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}.{:x} {:04x}:{:04x} {}",
            self.bus,
            self.dev,
            self.func,
            self.vendor,
            self.device,
            base_class_name(self.base_class()),
        )
    }
}

// ---------------------------------------------------------------------------
// Class-code label
// ---------------------------------------------------------------------------

/// Human-readable name for a PCI base-class byte.
///
/// The base-class byte is the coarse device category defined by the PCI
/// Local Bus Specification; this returns a short, lower-case label for the
/// values the kernel is likely to encounter, and `"other"` for reserved or
/// vendor-defined classes. The labels are deliberately terse so they fit
/// on a serial-console log line during enumeration.
///
/// This is a flat lookup rather than a full subclass/prog_if table because
/// the fine-grained names would dwarf the rest of the module; drivers that
/// need exact subclass matching read [`PciDevice::subclass`] and
/// [`PciDevice::prog_if`] directly.
#[must_use]
pub const fn base_class_name(base: u8) -> &'static str {
    match base {
        0x00 => "legacy",
        0x01 => "mass-storage",
        0x02 => "network",
        0x03 => "display",
        0x04 => "multimedia",
        0x05 => "memory",
        0x06 => "bridge",
        0x07 => "simple-comm",
        0x08 => "base-peripheral",
        0x09 => "input",
        0x0A => "docking-station",
        0x0B => "processor",
        0x0C => "serial-bus",
        0x0D => "wireless",
        0x0E => "intelligent-io",
        0x0F => "satellite-comm",
        0x10 => "encryption",
        0x11 => "signal-processing",
        0x12 => "processing-accelerator",
        0x13 => "non-essential-instrumentation",
        _ => "other",
    }
}

// `NUM_BARS` (re-exported from `config`) is the single source of truth for
// "six BARs in a type-0 header". `PciDevice::bars` is sized by it and
// `PciDevice::probe` reads exactly that many BARs, so a future change to the
// count updates both sites through the one constant.

// ---------------------------------------------------------------------------
// Tests (host-only: exercise the pure snapshot/decode logic with no I/O)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_class_decoders_split_the_24bit_field() {
        // Class code packs base<<16 | subclass<<8 | prog_if. Pick a value
        // with distinct bytes so each decoder returns a different one.
        let dev = PciDevice {
            bus: 0,
            dev: 0x1F,
            func: 0,
            vendor: 0x8086,
            device: 0x2918,
            class: 0x0006_0100, // base 0x06 (bridge), subclass 0x01 (ISA), prog_if 0
            bars: [0; NUM_BARS],
            irq: 0,
        };
        assert_eq!(dev.base_class(), 0x06);
        assert_eq!(dev.subclass(), 0x01);
        assert_eq!(dev.prog_if(), 0x00);
    }

    #[test]
    fn base_class_name_covers_common_categories() {
        assert_eq!(base_class_name(0x01), "mass-storage");
        assert_eq!(base_class_name(0x02), "network");
        assert_eq!(base_class_name(0x03), "display");
        assert_eq!(base_class_name(0x06), "bridge");
        // Reserved / vendor-defined classes fall back to "other".
        assert_eq!(base_class_name(0xFF), "other");
    }

    #[test]
    fn bar_helpers_pick_first_memory_and_io() {
        let mut bars = [0u32; NUM_BARS];
        // BAR0: I/O space (bit 0 set), base 0x1000 (low bit cleared after mask).
        bars[0] = 0x1000 | 0x1;
        // BAR1: memory space (bit 0 clear), base 0xF000_0000.
        bars[1] = 0xF000_0000;
        let dev = PciDevice {
            bus: 0,
            dev: 0,
            func: 0,
            vendor: 0x1234,
            device: 0x5678,
            class: 0x0002_0000,
            bars,
            irq: 11,
        };
        assert_eq!(dev.first_io_bar(), Some(0x1001));
        assert_eq!(dev.first_memory_bar(), Some(0xF000_0000));
        // Out-of-range bar index returns 0 rather than panicking.
        assert_eq!(dev.bar(NUM_BARS), 0);
        assert_eq!(dev.bar(0), 0x1001);
    }

    #[test]
    fn address_round_trips_through_stored_fields() {
        let dev = PciDevice {
            bus: 0xAB,
            dev: 0x1D,
            func: 0x3,
            vendor: 0x10EC,
            device: 0x8168,
            class: 0x0002_0000,
            bars: [0; NUM_BARS],
            irq: 0,
        };
        let addr = dev.address();
        assert_eq!(addr.bus(), 0xAB);
        assert_eq!(addr.dev(), 0x1D);
        assert_eq!(addr.func(), 0x3);
    }

    #[test]
    fn is_present_rejects_vendor_none() {
        let absent = PciDevice {
            bus: 0,
            dev: 0,
            func: 0,
            vendor: VENDOR_NONE,
            device: 0xFFFF,
            class: 0,
            bars: [0; NUM_BARS],
            irq: 0,
        };
        assert!(!absent.is_present());
        let present = PciDevice {
            bus: 0,
            dev: 0,
            func: 0,
            vendor: 0x8086,
            device: 0x1234,
            class: 0,
            bars: [0; NUM_BARS],
            irq: 0,
        };
        assert!(present.is_present());
    }

    #[test]
    fn pci_command_bitflags_combine_and_inspect() {
        // The canonical driver bring-up combination: enable I/O + memory +
        // bus master so the device can respond to its BARs and issue DMA.
        let enable = PciCommand::IO_SPACE | PciCommand::MEMORY_SPACE | PciCommand::BUS_MASTER;
        assert!(enable.contains(PciCommand::BUS_MASTER));
        assert!(enable.contains(PciCommand::MEMORY_SPACE));
        assert!(!enable.contains(PciCommand::SERR_ENABLE));
        // The three enable bits are 0x07.
        assert_eq!(enable.bits(), 0x0007);
        // from_bits_truncate ignores unknown bits a future PCI revision
        // might define in the high half of the command register.
        let truncated = PciCommand::from_bits_truncate(0xFFFF);
        assert_eq!(truncated.bits(), 0x07FF);
    }
}
