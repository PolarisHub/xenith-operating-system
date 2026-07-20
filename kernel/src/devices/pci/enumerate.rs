//! PCI bus enumeration and driver binding.
//!
//! Walks PCI config space starting at bus 0, recursively descending through
//! PCI-to-PCI bridges, and collects every present function into a heap-
//! allocated [`KVec`] of [`PciDevice`] records. Each device is classified
//! through a base-class lookup table so the boot log can name what the kernel
//! found (display, network, storage, bridge, ...) before any driver is bound.
//! A trait-object registry ([`PciDriver`] / [`register_driver`]) is the hook
//! later phases use to attach concrete drivers by vendor/device ID or class.
//!
//! # Why bus 0 is the entry point
//!
//! On a legacy PC the host bridge at bus 0 is the only bus reachable through
//! 0xCF8/0xCFC port config cycles, so every other bus is discovered by
//! recursively reading the secondary-bus register (offset `0x19`) of type-1
//! PCI-to-PCI bridges found below bus 0. A shared per-bus visited bitmap
//! guards against cycles in a mis-programmed bridge tree.
//!
//! # Config-space access
//!
//! Every read goes through [`super::config::PciAddress`]. Its shared lock
//! serialises the host bridge's `0xCF8/0xCFC` selector/data pair across CPUs,
//! so enumeration, capability probing, and live drivers cannot select each
//! other's config dwords.

use core::fmt;

use super::config::{PciAddress, VENDOR_NONE};
use crate::mm::KVec;
use crate::sync::SpinLock;

/// Vendor ID at offset 0x00; `0xFFFF` means no function present.
#[inline]
fn read_vendor_id(addr: PciAddress) -> u16 {
    addr.read_vendor()
}

/// Device ID at offset 0x02.
#[inline]
fn read_device_id(addr: PciAddress) -> u16 {
    addr.read_device()
}

/// Revision / prog-if / subclass / base-class packed at offset 0x08.
#[inline]
fn read_class_code(addr: PciAddress) -> (u8, u8, u8, u8) {
    let d = addr.read32(0x08);
    // little-endian dword: rev(0x08) | progif(0x09)<<8 | sub(0x0A)<<16 | base(0x0B)<<24
    (
        (d & 0xFF) as u8,         // revision
        ((d >> 8) & 0xFF) as u8,  // prog-if
        ((d >> 16) & 0xFF) as u8, // subclass
        ((d >> 24) & 0xFF) as u8, // base class
    )
}

/// Header type at offset 0x0E. Bit 7 set => multi-function device.
#[inline]
fn read_header_type(addr: PciAddress) -> u8 {
    addr.read_header_type_byte()
}

/// Raw BAR `i` (0..6) at offset `0x10 + 4*i`.
#[inline]
fn read_bar_raw(addr: PciAddress, index: u8) -> u32 {
    debug_assert!(index < 6);
    addr.read_bar(index as usize).unwrap_or(0)
}

/// Interrupt line (0x3C) and interrupt pin (0x3D).
#[inline]
fn read_interrupt(addr: PciAddress) -> (u8, u8) {
    let d = addr.read32(0x3C);
    ((d & 0xFF) as u8, ((d >> 8) & 0xFF) as u8)
}

/// Secondary bus number behind a type-1 bridge (offset 0x19).
#[inline]
fn read_secondary_bus(addr: PciAddress) -> u8 {
    addr.read8(0x19)
}

// --- Header-type and base-class taxonomy ------------------------------------

/// Bit 7 of the header-type byte marks a multi-function device; scanning it
/// decides whether to probe functions 1..7 after a hit on function 0.
const HEADER_TYPE_MULTIFUNCTION: u8 = 0x80;
/// Low 7 bits select the header layout: 0 = normal device, 1 = PCI-PCI bridge,
/// 2 = CardBus. Only type 1 carries a secondary bus to recurse into.
const HEADER_TYPE_MASK: u8 = 0x7F;
/// PCI base class for bridge devices — the recursion trigger.
const BASE_CLASS_BRIDGE: u8 = 0x06;
/// Decoded config-header layout. Only the shapes the enumerator acts on are
/// distinguished; anything else is surfaced as [`Self::Other`] so a log line
/// still names it and a driver can inspect the raw byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciHeaderKind {
    /// Type 0: an endpoint or multi-function leaf device.
    Device,
    /// Type 1: a PCI-to-PCI bridge; carries a secondary bus to recurse into.
    Bridge,
    /// Type 2: a CardBus bridge (PCMCIA); rare on modern machines.
    CardBus,
    /// Any other header type. The raw byte is retained for diagnostics.
    Other(u8),
}

impl PciHeaderKind {
    /// Decode a raw header-type byte (the full byte, including the
    /// multi-function bit) into a layout tag.
    pub fn from_raw(raw: u8) -> Self {
        match raw & HEADER_TYPE_MASK {
            0 => Self::Device,
            1 => Self::Bridge,
            2 => Self::CardBus,
            other => Self::Other(other),
        }
    }

    /// Whether the raw header-type byte advertises a multi-function device.
    pub fn is_multifunction(raw: u8) -> bool {
        raw & HEADER_TYPE_MULTIFUNCTION != 0
    }
}

/// PCI base-class taxonomy. The variants cover every base class the PCI spec
/// assigns a stable 0xNN code; [`Self::from_base_class`] maps the byte and
/// [`Self::name`] yields a short human label for the boot log. This is the
/// "class-code lookup table" the enumerator reports against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciClassCode {
    Unclassified,
    MassStorageController,
    NetworkController,
    DisplayController,
    MultimediaController,
    MemoryController,
    BridgeDevice,
    CommunicationController,
    GenericSystemPeripheral,
    InputDeviceController,
    DockingStation,
    Processor,
    SerialBusController,
    WirelessController,
    IntelligentController,
    SatelliteCommunicationController,
    EncryptionController,
    SignalProcessingController,
    ProcessingAccelerator,
    /// A base class outside the tabled range (0x13+ or vendor-defined 0x40+).
    Other(u8),
}

impl PciClassCode {
    /// Map a raw base-class byte to its taxonomy entry.
    pub fn from_base_class(base: u8) -> Self {
        match base {
            0x00 => Self::Unclassified,
            0x01 => Self::MassStorageController,
            0x02 => Self::NetworkController,
            0x03 => Self::DisplayController,
            0x04 => Self::MultimediaController,
            0x05 => Self::MemoryController,
            0x06 => Self::BridgeDevice,
            0x07 => Self::CommunicationController,
            0x08 => Self::GenericSystemPeripheral,
            0x09 => Self::InputDeviceController,
            0x0A => Self::DockingStation,
            0x0B => Self::Processor,
            0x0C => Self::SerialBusController,
            0x0D => Self::WirelessController,
            0x0E => Self::IntelligentController,
            0x0F => Self::SatelliteCommunicationController,
            0x10 => Self::EncryptionController,
            0x11 => Self::SignalProcessingController,
            0x12 => Self::ProcessingAccelerator,
            other => Self::Other(other),
        }
    }

    /// Short human label used in the enumeration log. Keeping these as
    /// `&'static str` means logging never allocates.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unclassified => "unclassified",
            Self::MassStorageController => "mass storage controller",
            Self::NetworkController => "network controller",
            Self::DisplayController => "display controller",
            Self::MultimediaController => "multimedia controller",
            Self::MemoryController => "memory controller",
            Self::BridgeDevice => "bridge",
            Self::CommunicationController => "communication controller",
            Self::GenericSystemPeripheral => "generic system peripheral",
            Self::InputDeviceController => "input device controller",
            Self::DockingStation => "docking station",
            Self::Processor => "processor",
            Self::SerialBusController => "serial bus controller",
            Self::WirelessController => "wireless controller",
            Self::IntelligentController => "intelligent controller",
            Self::SatelliteCommunicationController => "satellite comm controller",
            Self::EncryptionController => "encryption controller",
            Self::SignalProcessingController => "signal processing controller",
            Self::ProcessingAccelerator => "processing accelerator",
            Self::Other(_) => "other",
        }
    }
}

/// Subclass label for the categories the boot log most wants to name
/// precisely: storage (IDE/SCSI/RAID/NVMe/...), network (Ethernet/InfiniBand),
/// display (VGA/3D), and bridge (host/PCI-PCI/CardBus). Other categories fall
/// back to the base-class name; this keeps the table focused on what an OS
/// bring-up actually greps for.
pub fn subclass_name(base: u8, sub: u8) -> &'static str {
    match (base, sub) {
        // Mass storage — the controller behind the boot disk matters most.
        (0x01, 0x00) => "SCSI storage",
        (0x01, 0x01) => "IDE storage",
        (0x01, 0x02) => "floppy controller",
        (0x01, 0x04) => "RAID controller",
        (0x01, 0x05) => "ATA controller",
        (0x01, 0x06) => "SATA controller",
        (0x01, 0x07) => "SAS controller",
        (0x01, 0x08) => "NVMe controller",
        // Network.
        (0x02, 0x00) => "ethernet controller",
        (0x02, 0x01) => "token-ring controller",
        (0x02, 0x07) => "infiniband controller",
        // Display.
        (0x03, 0x00) => "VGA display",
        (0x03, 0x01) => "XGA display",
        (0x03, 0x02) => "3D controller",
        // Bridges — the recursion targets.
        (0x06, 0x00) => "host bridge",
        (0x06, 0x01) => "ISA bridge",
        (0x06, 0x04) => "PCI-to-PCI bridge",
        (0x06, 0x07) => "CardBus bridge",
        (0x06, 0x09) => "PCI-to-PCI bridge (semi-transparent)",
        // Serial bus — USB lives here.
        (0x0C, 0x03) => "USB controller",
        _ => "other",
    }
}

// --- BAR decoding -----------------------------------------------------------

/// Kind of a decoded Base Address Register. PCI BARs come in I/O and
/// memory-mapped flavours, and memory BARs are 32- or 64-bit wide; a 64-bit
/// BAR consumes the next BAR slot for its high dword, which the enumerator
/// must skip so it does not treat the high half as a separate BAR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciBarKind {
    /// I/O port BAR (bit 0 set), decoded at a 32-bit port address.
    Io,
    /// 32-bit memory BAR.
    Mem32,
    /// 64-bit memory BAR; occupies two consecutive config slots.
    Mem64,
    /// 32-bit memory BAR restricted to the low 1 MiB (legacy type 2).
    Mem16,
    /// Reserved or vendor-specific type; not decoded.
    Reserved,
}

/// A decoded BAR: its kind, whether it is prefetchable, and the base address.
#[derive(Clone, Copy, Debug)]
pub struct PciBarInfo {
    /// BAR slot index (0..6). A 64-bit BAR returns its low slot here.
    pub index: u8,
    pub kind: PciBarKind,
    pub prefetchable: bool,
    /// Decoded base address. Zero if the BAR is unimplemented (read back 0).
    pub address: u64,
}

// --- Device record ----------------------------------------------------------

/// A fully-read PCI function: its address, identification, classification,
/// header layout, raw BARs, and interrupt routing.
///
/// Built by [`enumerate_bus`] for every present function and consumed by the
/// driver registry during [`probe_devices`]. All fields are read at enumerate
/// time so a driver's `matches`/`probe` callbacks never need to issue config
/// cycles themselves for the common identification fields.
#[derive(Clone, Copy, Debug)]
pub struct PciDevice {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision: u8,
    pub prog_if: u8,
    pub subclass: u8,
    pub base_class: u8,
    pub header_kind: PciHeaderKind,
    pub multifunction: bool,
    /// Six raw BAR dwords as read from config offsets 0x10..0x27. Drivers
    /// decode them via [`PciDevice::bar`] so 64-bit BAR spanning is handled
    /// in one place.
    pub bars: [u32; 6],
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
}

impl PciDevice {
    /// Read a function's full header from config space.
    ///
    /// Returns `None` if no function is present at `addr` (vendor ID 0xFFFF).
    /// Absent functions are not errors — the enumerator expects most
    /// bus/device/function triples to be empty — so they are silently skipped.
    fn probe(addr: PciAddress) -> Option<Self> {
        let vendor_id = read_vendor_id(addr);
        if vendor_id == VENDOR_NONE {
            return None;
        }
        let device_id = read_device_id(addr);
        let (revision, prog_if, subclass, base_class) = read_class_code(addr);
        let header_raw = read_header_type(addr);
        let mut bars = [0u32; 6];
        for i in 0..6 {
            bars[i as usize] = read_bar_raw(addr, i);
        }
        let (interrupt_line, interrupt_pin) = read_interrupt(addr);
        Some(Self {
            address: addr,
            vendor_id,
            device_id,
            revision,
            prog_if,
            subclass,
            base_class,
            header_kind: PciHeaderKind::from_raw(header_raw),
            multifunction: PciHeaderKind::is_multifunction(header_raw),
            bars,
            interrupt_line,
            interrupt_pin,
        })
    }

    /// Taxonomy entry for this device's base class.
    pub fn class_code(&self) -> PciClassCode {
        PciClassCode::from_base_class(self.base_class)
    }

    /// Short "vendor:device @ b:d.f" identifier for log lines.
    pub fn describe_id(&self) -> impl fmt::Display + '_ {
        // A private display view avoids allocating a String for every log
        // line; the formatter writes straight into the log backend's buffer.
        struct IdView<'a>(&'a PciDevice);
        impl<'a> fmt::Display for IdView<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "{:04x}:{:04x} @ {}",
                    self.0.vendor_id, self.0.device_id, self.0.address
                )
            }
        }
        IdView(self)
    }

    /// One-line human description combining address, IDs, and class name.
    pub fn describe(&self) -> impl fmt::Display + '_ {
        struct DescView<'a>(&'a PciDevice);
        impl<'a> fmt::Display for DescView<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Prefer the specific subclass label (e.g. "NVMe controller")
                // over the broad base-class name when the subclass is tabled.
                let class = self.0.class_code().name();
                let sub = subclass_name(self.0.base_class, self.0.subclass);
                let label = if sub != "other" { sub } else { class };
                write!(
                    f,
                    "{} [{} rev {:02x}]",
                    self.0.describe_id(),
                    label,
                    self.0.revision
                )
            }
        }
        DescView(self)
    }

    /// Decode BAR `index` (0..6). For a 64-bit memory BAR the high dword is
    /// taken from `index + 1`; calling this on a slot occupied by a 64-bit
    /// BAR's high half returns a `Reserved` info with a zero address.
    ///
    /// Returns `None` only if `index >= 6`. An unimplemented BAR (raw value
    /// 0) yields a `Mem32`/`Io` info with `address == 0`, which the caller
    /// can treat as "not present".
    pub fn bar(&self, index: u8) -> Option<PciBarInfo> {
        if index >= 6 {
            return None;
        }
        if self.bar_is_high_half(index) {
            return Some(PciBarInfo {
                index,
                kind: PciBarKind::Reserved,
                prefetchable: false,
                address: 0,
            });
        }
        let raw = self.bars[index as usize];
        // An unimplemented BAR reads back 0; surface it as a zero-address
        // 32-bit mem BAR so callers reading kind/prefetchable unconditionally
        // never see garbage.
        if raw == 0 {
            return Some(PciBarInfo {
                index,
                kind: PciBarKind::Mem32,
                prefetchable: false,
                address: 0,
            });
        }
        // Bit 0 selects I/O vs memory. I/O BARs use a 32-bit port address
        // masked by 0xFFFFFFFC; memory BARs decode type from bits [2:1] and
        // prefetchable from bit 3, with a 0xFFFF_FFF0 address mask.
        let (kind, prefetchable, address) = if raw & 0x1 != 0 {
            (PciBarKind::Io, false, (raw & 0xFFFF_FFFC) as u64)
        } else {
            let kind = match (raw >> 1) & 0b11 {
                0b00 => PciBarKind::Mem32,
                // PCI type 01b is the obsolete memory BAR restricted below
                // 1 MiB. Type 10b, not 01b, consumes the following dword as
                // the high half of a 64-bit address.
                0b01 => PciBarKind::Mem16,
                0b10 if (index as usize) < 5 => PciBarKind::Mem64,
                // A 64-bit BAR in the final slot has no high dword and is a
                // malformed header. Surface it as reserved instead of
                // silently truncating the device address to 32 bits.
                0b10 => PciBarKind::Reserved,
                _ => PciBarKind::Reserved,
            };
            let prefetchable = raw & 0x8 != 0;
            // A validated 64-bit BAR consumes the next slot for its high
            // dword. A final-slot 64-bit encoding was classified Reserved
            // above and therefore cannot be truncated here.
            let address = match kind {
                PciBarKind::Mem64 if (index as usize) < 5 => {
                    let high = self.bars[(index + 1) as usize] as u64;
                    ((raw & 0xFFFF_FFF0) as u64) | (high << 32)
                },
                _ => (raw & 0xFFFF_FFF0) as u64,
            };
            (kind, prefetchable, address)
        };
        Some(PciBarInfo {
            index,
            kind,
            prefetchable,
            address,
        })
    }

    /// Whether BAR `index` is the high dword of a preceding 64-bit BAR, and
    /// therefore not an independent BAR. Used by drivers that walk the BAR
    /// array so they skip the occupied slot.
    pub fn bar_is_high_half(&self, index: u8) -> bool {
        if index == 0 || index >= 6 {
            return false;
        }
        // Walk from BAR0 so incidental type bits in a 64-bit BAR's high
        // address dword can never consume another slot.
        let mut slot = 0u8;
        while slot < 6 {
            let raw = self.bars[slot as usize];
            let consumes_next = raw & 0x1 == 0 && (raw >> 1) & 0b11 == 0b10 && slot < 5;
            if consumes_next {
                if slot + 1 == index {
                    return true;
                }
                slot += 2;
            } else {
                if slot >= index {
                    return false;
                }
                slot += 1;
            }
        }
        false
    }
}

// --- Enumeration ------------------------------------------------------------

/// Walk PCI bus 0 recursively and collect every present function.
///
/// Starts at bus 0 because the host bridge there is the only bus reachable
/// through the 0xCF8/0xCFC port mechanism; PCI-to-PCI bridges found along
/// the way are descended into via their secondary-bus register. A 256-bit
/// visited bitmap guards against malformed bridge tables that point back to
/// an ancestor bus, which would otherwise loop the kernel at boot.
pub fn enumerate_bus() -> KVec<PciDevice> {
    let mut found = KVec::new();
    let mut visited = [false; 256];
    scan_bus(0, &mut found, &mut visited);
    found
}

/// Recursive bus scan. `visited` is shared across the entire recursive walk
/// so a cycle in the bridge topology (broken firmware programming a bridge's
/// secondary bus to an ancestor) terminates instead of recursing forever.
/// Each bus is marked visited on entry; a bridge pointing at an already-
/// visited bus is simply not descended into.
fn scan_bus(bus: u8, out: &mut KVec<PciDevice>, visited: &mut [bool; 256]) {
    if visited[bus as usize] {
        return;
    }
    visited[bus as usize] = true;

    for device in 0u8..32 {
        let base = PciAddress::new(bus, device, 0)
            .expect("enumerator device/function indices are architecturally bounded");
        // Function 0 must be present for any function on this device to exist.
        let Some(first) = PciDevice::probe(base) else {
            continue;
        };
        let multifunction = first.multifunction;
        emit_function(first, out, visited);

        // If the header advertises multiple functions, scan 1..7. Single-
        // function devices must not be probed on higher functions per the
        // PCI spec: some legacy hardware aliases function 0 onto higher
        // functions, producing phantom duplicates.
        if multifunction {
            for function in 1u8..8 {
                let addr = PciAddress::new(bus, device, function)
                    .expect("enumerator device/function indices are architecturally bounded");
                if let Some(dev) = PciDevice::probe(addr) {
                    emit_function(dev, out, visited);
                }
            }
        }
    }
}

/// Record a discovered function and, if it is a bridge that exposes a
/// secondary bus, descend into that bus. The record is appended first so the
/// tree is reported in discovery order (parent bridge before its children).
fn emit_function(dev: PciDevice, out: &mut KVec<PciDevice>, visited: &mut [bool; 256]) {
    out.push(dev);
    if let Some(secondary) = bridge_secondary_bus(&dev) {
        // A secondary bus equal to this bridge's own bus means firmware never
        // programmed the bridge; the shared `visited` guard would catch the
        // cycle anyway, but skipping it explicitly avoids a redundant probe
        // pass over the current bus.
        if secondary != dev.address.bus() {
            scan_bus(secondary, out, visited);
        }
    }
}

/// The downstream bus to recurse into, if `dev` is a bridge that carries one.
///
/// Only PCI-to-PCI bridges (subclass 0x04), CardBus bridges (0x07), and
/// semi-transparent PCI-to-PCI bridges (0x09) expose a secondary-bus register
/// at config offset 0x19. Host bridges (0x06/0x00) are bus 0 itself and have
/// no downstream bus to walk; ISA/EISA bridges are leaf devices on the host
/// side. Restricting recursion to the bridge subclasses that actually define
/// a secondary bus avoids mis-reading an unrelated register as a bus number.
fn bridge_secondary_bus(dev: &PciDevice) -> Option<u8> {
    if dev.base_class != BASE_CLASS_BRIDGE {
        return None;
    }
    match dev.subclass {
        0x04 | 0x07 | 0x09 => Some(read_secondary_bus(dev.address)),
        _ => None,
    }
}

// --- Driver registry --------------------------------------------------------

/// Errors a driver's [`PciDriver::probe`] can report. Hand-rolled rather than
/// deriving so the `&'static str` context stays a fixed message (no alloc)
/// and the variants map cleanly to log levels.
#[derive(Debug)]
pub enum PciDriverError {
    /// A BAR needed for MMIO could not be decoded or was absent.
    BarUnreadable,
    /// The device has no routable interrupt (interrupt pin 0).
    NoInterrupt,
    /// The driver accepted the device but failed its own init step.
    ProbeFailed(&'static str),
}

impl fmt::Display for PciDriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BarUnreadable => f.write_str("BAR unreadable"),
            Self::NoInterrupt => f.write_str("no interrupt pin"),
            Self::ProbeFailed(msg) => write!(f, "probe failed: {msg}"),
        }
    }
}

/// Trait implemented by a concrete PCI driver and registered with
/// [`register_driver`]. `matches` is the cheap predicate run against every
/// enumerated device; `probe` performs the real bring-up (BAR mapping, IRQ
/// routing, device reset) and is called only when `matches` returns `true`.
///
/// Drivers are stored as `&'static dyn PciDriver` trait objects so they can
/// live in `static` storage owned by their owning module and be registered
/// from `init` code without heap allocation.
pub trait PciDriver: Send + Sync {
    /// Stable, short driver name for log lines (e.g. `"nvme"`, `"e1000"`).
    fn name(&self) -> &'static str;

    /// Whether this driver claims `dev`. Typically a vendor/device ID match
    /// or a class-code match for class-generic drivers.
    fn matches(&self, dev: &PciDevice) -> bool;

    /// Bring the device online. Called once per matching device; returning
    /// `Err` logs a warning and leaves the device unbound but does not stop
    /// the rest of the probe pass.
    fn probe(&self, dev: &PciDevice) -> Result<(), PciDriverError>;
}

/// The global driver registry. A spinlock guards the `KVec` because
/// registration happens at boot from the single-threaded `init` path today,
/// but later hot-plug or module-load paths may register drivers from other
/// CPUs. The lock is short-held: [`probe_devices`] snapshots the matching
/// drivers and releases the lock before calling `probe`, so a driver's
/// bring-up can safely take its own locks without re-entering this one.
static DRIVERS: SpinLock<KVec<&'static dyn PciDriver>> = SpinLock::new(KVec::new());

/// Register a PCI driver with the global registry.
///
/// Drivers register from their owning module's `init` before
/// [`probe_devices`] runs. Re-registering the same pointer is a no-op so
/// module re-init cannot duplicate an entry and double-probe a device.
pub fn register_driver(driver: &'static dyn PciDriver) {
    let mut registry = DRIVERS.lock();
    // De-duplicate by trait-object pointer identity.
    let already = registry.iter().any(|d| {
        core::ptr::eq(
            *d as *const dyn PciDriver as *const (),
            driver as *const dyn PciDriver as *const (),
        )
    });
    if !already {
        registry.push(driver);
    }
}

/// Walk `devices` and call `probe` on every registered driver whose `matches`
/// returns `true`. The registry lock is held only to snapshot the matching
/// driver pointers; `probe` itself runs lock-free so drivers may take their
/// own locks during bring-up.
pub fn probe_devices(devices: &[PciDevice]) {
    // Stack-bound snapshot of the drivers claiming a given device. 8 slots is
    // generous: a real machine rarely has more than two or three drivers
    // competing for one device (e.g. a generic NVMe class driver and a
    // vendor-specific one). Overflow is logged and the rest are skipped.
    let mut snapshot: [Option<&'static dyn PciDriver>; 8] = [None; 8];

    for dev in devices {
        // Snapshot phase: hold the registry lock just long enough to collect
        // matching driver pointers, then drop it before any probe runs.
        {
            let registry = DRIVERS.lock();
            let mut count = 0;
            for d in registry.iter() {
                if count >= snapshot.len() {
                    ::log::warn!(
                        "pci: >{} drivers matched {}; extra drivers skipped",
                        snapshot.len(),
                        dev.describe_id()
                    );
                    break;
                }
                if d.matches(dev) {
                    snapshot[count] = Some(*d);
                    count += 1;
                }
            }
        }

        // Probe phase: lock-free. A failure is logged but does not abort the
        // pass, so one buggy driver cannot mask another that would claim the
        // same device.
        for slot in snapshot.iter().copied() {
            let Some(driver) = slot else { break };
            match driver.probe(dev) {
                Ok(()) => ::log::info!(
                    "pci: bound {} to driver '{}'",
                    dev.describe_id(),
                    driver.name()
                ),
                Err(err) => ::log::warn!(
                    "pci: driver '{}' declined {} ({err})",
                    driver.name(),
                    dev.describe_id()
                ),
            }
        }
        // Reset the snapshot so the next device starts from an empty set.
        snapshot.fill(None);
    }
}

// --- Top-level entry --------------------------------------------------------

/// Enumerate the PCI tree, log every discovered device, and run the driver
/// probe pass. Returns the number of devices found so the caller can report
/// a summary or gate later subsystem bring-up on having found, say, a boot
/// storage controller.
///
/// This is the function `devices::init` calls once the heap and port-I/O
/// paths are available. It allocates the result vector via the kernel heap
/// (`KVec`), so it must run after [`crate::mm`] is up.
pub fn enumerate_and_bind() -> usize {
    let devices = enumerate_bus();
    let count = devices.len();

    // Resolve AML `_PRT` tables against the complete bridge topology before
    // any driver chooses an INTx route. Firmware's Interrupt Line byte stays
    // available as a validated fallback when AML is absent or unsupported.
    super::routing::init(&devices);

    ::log::info!(
        "pci: enumerated {} device{}",
        count,
        if count == 1 { "" } else { "s" }
    );
    for dev in devices.iter() {
        ::log::info!("pci:   {}", dev.describe());
    }

    if count != 0 {
        probe_devices(&devices);
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device_with_bars(bars: [u32; 6]) -> PciDevice {
        PciDevice {
            address: PciAddress::new(0, 1, 0).expect("bounded test BDF"),
            vendor_id: 0x1234,
            device_id: 0x5678,
            revision: 0,
            prog_if: 0,
            subclass: 0,
            base_class: 0,
            header_kind: PciHeaderKind::Device,
            multifunction: false,
            bars,
            interrupt_line: 0,
            interrupt_pin: 0,
        }
    }

    #[test]
    fn memory_bar_type_bits_follow_pci_encoding() {
        let device = device_with_bars([
            0x3456_7004, // type 10b: 64-bit memory BAR
            0x0000_0012,
            0x000f_f002, // type 01b: below-1-MiB memory BAR
            0x8765_4006, // type 11b: reserved
            0,
            0,
        ]);

        let wide = device.bar(0).expect("BAR0 exists");
        assert_eq!(wide.kind, PciBarKind::Mem64);
        assert_eq!(wide.address, 0x0000_0012_3456_7000);
        assert!(device.bar_is_high_half(1));
        let wide_high = device.bar(1).expect("BAR1 exists");
        assert_eq!(wide_high.kind, PciBarKind::Reserved);
        assert_eq!(wide_high.address, 0);

        let legacy = device.bar(2).expect("BAR2 exists");
        assert_eq!(legacy.kind, PciBarKind::Mem16);
        assert_eq!(legacy.address, 0x000f_f000);
        assert!(!device.bar_is_high_half(3));

        assert_eq!(
            device.bar(3).expect("BAR3 exists").kind,
            PciBarKind::Reserved
        );
    }

    #[test]
    fn final_slot_cannot_truncate_a_64_bit_bar() {
        let device = device_with_bars([0, 0, 0, 0, 0, 0x1234_5004]);
        let final_bar = device.bar(5).expect("BAR5 exists");
        assert_eq!(final_bar.kind, PciBarKind::Reserved);
        assert_eq!(final_bar.address, 0x1234_5000);
        assert!(!device.bar_is_high_half(5));
    }

    #[test]
    fn high_dword_type_bits_cannot_consume_the_following_bar() {
        let device = device_with_bars([0x3456_7004, 0x0000_0004, 0x0000_c001, 0, 0, 0]);

        assert!(device.bar_is_high_half(1));
        assert!(!device.bar_is_high_half(2));
        let bar2 = device.bar(2).expect("BAR2 exists");
        assert_eq!(bar2.kind, PciBarKind::Io);
        assert_eq!(bar2.address, 0x0000_c000);
    }
}
