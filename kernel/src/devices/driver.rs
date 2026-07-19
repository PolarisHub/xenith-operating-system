//! Device and driver abstraction: the registry that matches PCI hardware
//! to the kernel code that drives it.
//!
//! Xenith separates *what a piece of hardware is* from *how the kernel talks
//! to it*. [`Device`] is the hardware-facing identity: a name and a probe
//! that decides whether a given PCI function is this device. [`Driver`] is
//! the software-facing lifecycle: bind to a probed device, initialise it,
//! and shut it down. A [`DriverDescriptor`] bridges the two — it carries the
//! static match criteria (vendor/device IDs or class code) plus a factory
//! that constructs a concrete [`Driver`] for a matched [`PciDevice`].
//!
//! The [`DriverRegistry`] owns the descriptor table and the list of bound
//! drivers. PCI enumeration walks the bus and, for each function, asks the
//! registry for a willing driver; the first descriptor whose match criteria
//! and probe both accept the device wins, mirroring the Linux/PCI ordering
//! of `id_table` then `probe`.
//!
//! `devices::init` runs after the heap is online, so the registry heap-
//! allocates its vectors. The global [`DRIVER_REGISTRY`] is `const`-
//! constructed empty and filled during bring-up; the
//! [`SpinLock`](crate::sync::SpinLock) serialises registration against
//! concurrent probing on SMP boots.
//!
//! # The `PciDevice` stub
//!
//! The canonical PCI descriptor lives in `crate::devices::pci::PciDevice`,
//! written by the parallel PCI phase. Until it lands, [`PciDevice`] below is
//! a thin local stand-in carrying exactly the fields the matcher needs. The
//! swap at integration time is a type alias plus a field-rename pass.

use core::fmt;

use crate::mm::{KVec, Kbox};
use crate::sync::SpinLock;

// ---------------------------------------------------------------------------
// PCI function descriptor (local stub — see module docs)
// ---------------------------------------------------------------------------

/// A PCI function as seen by the driver matcher.
///
/// This is a minimal local stand-in for `crate::devices::pci::PciDevice`
/// (landed by the parallel PCI phase) carrying just the fields the matcher
/// and probe functions consult. It is replaced by a type alias to the
/// canonical struct once `devices::pci` is integrated.
#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    /// PCI location: bus (bits 16..=23), device (8..=15), function (0..=2).
    /// Packed so a single `u32` identifies a function uniquely.
    pub location: u32,
    /// Vendor ID (0xFFFF means no device / invalid function).
    pub vendor_id: u16,
    /// Device ID.
    pub device_id: u16,
    /// Class code (base class), e.g. `CLASS_DISPLAY`.
    pub class_code: u8,
    /// Subclass within `class_code`.
    pub subclass: u8,
    /// Register-level programming interface (e.g. IDE vs. SATA for mass
    /// storage). `0` when the class does not subdivide further.
    pub prog_if: u8,
    /// Silicon revision ID.
    pub revision: u8,
    /// Number of Base Address Registers the function exposes (0..=6).
    pub bar_count: u8,
}

impl PciDevice {
    /// Decompose the packed location into (bus, device, function).
    #[inline]
    pub fn bdf(&self) -> (u8, u8, u8) {
        (
            ((self.location >> 16) & 0xFF) as u8,
            ((self.location >> 8) & 0x1F) as u8,
            (self.location & 0x07) as u8,
        )
    }

    /// Format the location as the canonical `bb:dd.f` string into `f`.
    pub fn fmt_bdf(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (bus, dev, fun) = self.bdf();
        write!(f, "{bus:02x}:{dev:02x}.{fun}")
    }
}

impl fmt::Display for PciDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (bus, dev, fun) = self.bdf();
        write!(
            f,
            "{bus:02x}:{dev:02x}.{fun} {vid:04x}:{did:04x} class {cls:02x}/{sub:02x}",
            vid = self.vendor_id,
            did = self.device_id,
            cls = self.class_code,
            sub = self.subclass,
        )
    }
}

// ---------------------------------------------------------------------------
// PCI base class constants (subset — extend as drivers are added)
// ---------------------------------------------------------------------------

/// PCI base-class codes consulted by class-based matching. Values from PCI
/// Local Bus Specification rev 3.0, Appendix D. Only the classes Xenith
/// actually matches against are listed; add new ones as their drivers land.
pub mod pci_class {
    /// Unclassified / pre-1.0 device.
    pub const UNCLASSIFIED: u8 = 0x00;
    /// Mass storage controller (SATA/NVMe/IDE — see subclass + prog_if).
    pub const STORAGE: u8 = 0x01;
    /// Network controller (Ethernet, Wi-Fi).
    pub const NETWORK: u8 = 0x02;
    /// Display controller (VGA, framebuffer, 3D).
    pub const DISPLAY: u8 = 0x03;
    /// Multimedia controller (audio, video).
    pub const MULTIMEDIA: u8 = 0x04;
    /// Memory controller (RAM flash — rare on modern platforms).
    pub const MEMORY: u8 = 0x05;
    /// Bridge device (host, PCI-to-PCI, ISA).
    pub const BRIDGE: u8 = 0x06;
    /// Simple communication controller (serial, modem).
    pub const COMM: u8 = 0x07;
    /// Base system peripheral (PIC, DMA, timer, RTC).
    pub const PERIPHERAL: u8 = 0x08;
    /// Input device (keyboard, mouse).
    pub const INPUT: u8 = 0x09;
    /// Docking station.
    pub const DOCKING: u8 = 0x0A;
    /// Processor (generic — 386, 486, Pentium, ...).
    pub const PROCESSOR: u8 = 0x0B;
    /// Serial bus controller (FireWire, USB, SMBus).
    pub const SERIAL_BUS: u8 = 0x0C;
    /// Wireless controller (Bluetooth, broadband).
    pub const WIRELESS: u8 = 0x0D;
    /// Intelligent I/O controller.
    pub const INTELLIGENT_IO: u8 = 0x0E;
    /// Satellite communication controller.
    pub const SATELLITE: u8 = 0x0F;
    /// Encryption / decryption controller.
    pub const ENCRYPTION: u8 = 0x10;
    /// Signal processing controller (DSP, DPU).
    pub const SIGNAL_PROCESSING: u8 = 0x11;
    /// Processing accelerator.
    pub const PROCESSING_ACCEL: u8 = 0x12;
    /// Non-essential instrumentation.
    pub const INSTRUMENTATION: u8 = 0x13;
}

// ---------------------------------------------------------------------------
// Match criteria
// ---------------------------------------------------------------------------

/// How a descriptor decides whether a PCI function belongs to its driver.
///
/// The matcher evaluates the static [`MatchKind`] first (a cheap integer
/// compare with no closure call); only if that passes does it invoke the
/// descriptor's [`probe`](DriverDescriptor::probe) function for a final,
/// driver-specific arbiter. Splitting the two lets the registry reject the
/// overwhelming majority of functions without an indirect call.
#[derive(Debug, Clone, Copy)]
pub enum MatchKind {
    /// Match a specific vendor/device pair. The most precise match — use for
    /// devices whose programming model is unique to one part number.
    VendorDevice {
        /// PCI vendor ID (e.g. `0x8086` for Intel).
        vendor: u16,
        /// PCI device ID.
        device: u16,
    },
    /// Match a whole (class, subclass, prog_if) triple. Use for device
    /// families that share a programming model across vendors — e.g. any
    /// AHCI SATA controller or any XHCI USB host. `prog_if = None` matches
    /// any programming interface, broadening the match to a subclass.
    Class {
        /// Base class code (see [`pci_class`]).
        class: u8,
        /// Subclass within the base class.
        subclass: u8,
        /// Optional programming-interface constraint. `None` is a wildcard.
        prog_if: Option<u8>,
    },
    /// Match by class only, ignoring subclass and prog_if. The broadest
    /// static match; the probe function is expected to do the real work.
    ClassAny { class: u8 },
    /// No static criteria — always invoke the probe function. Reserved for
    /// diagnostic or catch-all drivers; placing one of these first in the
    /// registry effectively claims every unclaimed function.
    ProbeOnly,
}

impl MatchKind {
    /// Whether `dev` satisfies this static criterion.
    ///
    /// This is the cheap pre-filter; a `true` return does not bind the driver
    /// — the descriptor's probe function has the final say.
    pub fn matches(&self, dev: &PciDevice) -> bool {
        match *self {
            MatchKind::VendorDevice { vendor, device } => {
                dev.vendor_id == vendor && dev.device_id == device
            },
            MatchKind::Class {
                class,
                subclass,
                prog_if,
            } => {
                dev.class_code == class
                    && dev.subclass == subclass
                    && prog_if.is_none_or(|p| dev.prog_if == p)
            },
            MatchKind::ClassAny { class } => dev.class_code == class,
            MatchKind::ProbeOnly => true,
        }
    }

    /// A human-readable label for log lines, e.g. `vid 8086:dev 100e`.
    pub fn label(&self) -> &'static str {
        match *self {
            MatchKind::VendorDevice { .. } => "vendor/device",
            MatchKind::Class { .. } => "class/subclass/prog_if",
            MatchKind::ClassAny { .. } => "class",
            MatchKind::ProbeOnly => "probe-only",
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failures a driver or the registry can report.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DriverError {
    /// No registered descriptor matched the PCI function.
    NoMatch,
    /// A descriptor matched but its probe function rejected the device.
    ProbeRejected,
    /// The constructor/factory closure returned an error while building the
    /// driver instance (e.g. out of heap, missing BAR).
    CreateFailed,
    /// The driver's `init` hook failed (hardware did not respond, firmware
    /// refused, etc.).
    InitFailed,
    /// The registry rejected a duplicate registration for the same driver
    /// name. Keeps the descriptor table free of aliases that would shadow
    /// each other during matching.
    AlreadyRegistered,
    /// The PCI function descriptor is invalid (vendor `0xFFFF` or no BARs).
    InvalidDevice,
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            DriverError::NoMatch => "no matching driver registered",
            DriverError::ProbeRejected => "driver probe rejected the device",
            DriverError::CreateFailed => "driver constructor failed",
            DriverError::InitFailed => "driver initialisation failed",
            DriverError::AlreadyRegistered => "driver already registered",
            DriverError::InvalidDevice => "invalid PCI device descriptor",
        };
        f.write_str(msg)
    }
}

// ---------------------------------------------------------------------------
// Device trait — hardware-facing identity
// ---------------------------------------------------------------------------

/// A piece of hardware the kernel can drive.
///
/// `Device` is the *identity* half of the driver model: it answers "what is
/// this?" (`name`) and "is this PCI function me?" (`probe`). The lifecycle
/// half — bind, init, shutdown — lives on [`Driver`], which a concrete driver
/// implements alongside (or instead of) `Device`.
///
/// `probe` is a static method (`Self: Sized`) because the matcher calls it
/// before any instance exists: it must decide whether to *construct* one. A
/// driver that needs instance state to decide can stash it in the [`Driver`]
/// constructor and return [`DriverError::ProbeRejected`] from there instead.
pub trait Device {
    /// Stable, human-readable name used in log lines and `/proc`-style
    /// diagnostics. Returned by reference so it may borrow a `&'static str`
    /// without allocation.
    fn name(&self) -> &str;

    /// Whether the PCI function `pci` is this device.
    ///
    /// Called by the matcher after the static [`MatchKind`] has already
    /// accepted the function; a `true` return means "yes, construct me for
    /// this hardware". Must be side-effect-free — it runs during enumeration
    /// before the device is claimed, and a driver that touches hardware here
    /// can corrupt another driver's device.
    fn probe(pci: &PciDevice) -> bool
    where
        Self: Sized;

    /// Initialise the hardware for use.
    ///
    /// Called exactly once after construction. Implementations typically
    /// reset the chip, programme sane defaults, and register interrupt
    /// handlers. Returning `Ok(())` publishes the device as ready.
    fn init(&mut self) -> Result<(), DriverError>;
}

// ---------------------------------------------------------------------------
// Driver trait — software-facing lifecycle
// ---------------------------------------------------------------------------

/// The kernel-side lifecycle for a bound driver instance.
///
/// Where [`Device`] is "what the hardware is", `Driver` is "the code that
/// runs it". A concrete driver usually implements both: `Device::probe`
/// answers the matcher's question, and the `Driver` impl owns the runtime
/// state (MMIO pointers, command rings, cached stats) and the `init` /
/// `shutdown` transitions.
///
/// `Driver` is object-safe (`Send` + no `Self: Sized` methods) so the registry
/// can hold a `Kbox<dyn Driver>` and call into it without knowing the
/// concrete type.
pub trait Driver: Send {
    /// Stable name matching the descriptor that registered this driver.
    fn name(&self) -> &str;

    /// Bring the bound hardware online.
    ///
    /// Default delegates to nothing; concrete drivers override it to reset
    /// the chip, programme registers, and connect interrupts. The registry
    /// calls this immediately after a successful `bind`.
    fn init(&mut self) -> Result<(), DriverError> {
        Ok(())
    }

    /// Quiesce the hardware and release resources.
    ///
    /// Called on shutdown or when a driver is replaced. The default is a no-
    /// op; drivers that own interrupts, DMA rings, or MMIO mappings override
    /// it to tear those down. Must be idempotent — it may be called on a
    /// half-initialised driver if `init` failed partway through.
    fn shutdown(&mut self) -> Result<(), DriverError> {
        Ok(())
    }

    /// The PCI function this driver is bound to, if any. Drivers that back a
    /// non-PCI device (a legacy ISA card, a platform device) return `None`.
    fn pci_location(&self) -> Option<u32> {
        None
    }
}

// ---------------------------------------------------------------------------
// Driver descriptor — the registry entry
// ---------------------------------------------------------------------------

/// Constructor closure: build a concrete [`Driver`] for a matched PCI
/// function. Stored as a plain `fn` pointer (not a `Box<dyn Fn>`) so a
/// descriptor is `Copy` and needs no heap allocation itself — the registry
/// keeps its descriptor vector flat and the matcher copies entries freely.
pub type DriverCtor = fn(&PciDevice) -> Result<Kbox<dyn Driver>, DriverError>;

/// A registry entry: the static match criteria plus the constructor that
/// builds a driver instance when they are satisfied.
///
/// Descriptors are registered in priority order: the first one whose
/// [`MatchKind`] accepts a PCI function and whose [`probe`](Self::probe)
/// function returns `true` claims it. Register specific
/// (`VendorDevice`) descriptors before broad (`Class` / `ProbeOnly`) ones so
/// a vendor-specific driver wins over a generic class driver for the same
/// hardware.
#[derive(Clone, Copy)]
pub struct DriverDescriptor {
    /// Stable driver name; also returned by the constructed `Driver::name`.
    /// Used for deduplication and for log lines during matching.
    pub name: &'static str,
    /// Static match criterion (the cheap pre-filter).
    pub match_kind: MatchKind,
    /// Final arbiter: invoked after `match_kind` passes. May be `None` to
    /// accept anything the static criterion allows — common for class
    /// drivers that trust the (class, subclass, prog_if) triple.
    pub probe: Option<fn(&PciDevice) -> bool>,
    /// Constructor invoked once `match_kind` and `probe` both accept the
    /// device. The returned `Kbox<dyn Driver>` is stored in the bound-driver
    /// list.
    pub ctor: DriverCtor,
}

impl fmt::Debug for DriverDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DriverDescriptor")
            .field("name", &self.name)
            .field("match_kind", &self.match_kind.label())
            .field("has_probe", &self.probe.is_some())
            .finish()
    }
}

impl DriverDescriptor {
    /// Whether `dev` passes both the static and probe filters.
    ///
    /// The matcher's core predicate. Returns `true` only when
    /// `match_kind.matches(dev)` and (if present) `probe(dev)` both hold.
    #[inline]
    pub fn accepts(&self, dev: &PciDevice) -> bool {
        if !self.match_kind.matches(dev) {
            return false;
        }
        match self.probe {
            Some(p) => p(dev),
            None => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Bound driver — a successfully claimed PCI function
// ---------------------------------------------------------------------------

/// A driver instance bound to a PCI function, retained by the registry.
///
/// Groups the boxed trait object with the location it claimed so the
/// registry can report "who owns bb:dd.f" without a second lookup. The
/// `Driver` itself may also expose the location via [`Driver::pci_location`];
/// keeping it here is the authoritative record for ownership queries.
pub struct BoundDriver {
    /// The PCI function location this driver bound to.
    pub location: u32,
    /// The driver name (mirrors `driver.name()` but available without a
    /// virtual call for log/diagnostic loops).
    pub name: &'static str,
    /// The live driver instance.
    pub driver: Kbox<dyn Driver>,
}

impl fmt::Debug for BoundDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundDriver")
            .field("location", &format_args!("0x{:08x}", self.location))
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Driver registry
// ---------------------------------------------------------------------------

/// The table of registered driver descriptors and the drivers that have
/// successfully bound to PCI functions.
///
/// Registration and binding both take the write lock; ownership queries
/// (`find`, `count`) take the read path. The lock is a plain
/// [`SpinLock`](crate::sync::SpinLock) because device bring-up is
/// short and rare — a reader-preferred [`RwLock`](crate::sync::RwLock) would
/// add CAS traffic for no gain during the write-heavy boot window.
pub struct DriverRegistry {
    /// Registered descriptors, in registration (i.e. priority) order.
    descriptors: KVec<DriverDescriptor>,
    /// Drivers that have successfully bound and initialised.
    bound: KVec<BoundDriver>,
}

impl DriverRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            descriptors: KVec::new(),
            bound: KVec::new(),
        }
    }

    /// Register a driver descriptor.
    ///
    /// Descriptors are matched in registration order, so register specific
    /// (vendor/device) drivers before generic (class) ones. Returns
    /// [`DriverError::AlreadyRegistered`] if a descriptor with the same
    /// `name` is already present — the registry refuses shadow aliases so
    /// that the matcher's "first match wins" rule stays predictable.
    pub fn register(&mut self, desc: DriverDescriptor) -> Result<(), DriverError> {
        if self.descriptors.iter().any(|d| d.name == desc.name) {
            return Err(DriverError::AlreadyRegistered);
        }
        self.descriptors.push(desc);
        ::log::debug!(
            "driver: registered `{}` ({})",
            desc.name,
            desc.match_kind.label()
        );
        Ok(())
    }

    /// Number of registered descriptors.
    pub fn descriptor_count(&self) -> usize {
        self.descriptors.len()
    }

    /// Find the first descriptor that accepts `dev`, or `None`.
    ///
    /// Iterates in priority order and returns the index plus a borrow of the
    /// descriptor so the caller can either bind immediately or report which
    /// driver claimed the function.
    pub fn match_device(&self, dev: &PciDevice) -> Option<(usize, &DriverDescriptor)> {
        self.descriptors
            .iter()
            .enumerate()
            .find(|(_, d)| d.accepts(dev))
    }

    /// Bind a driver to `dev`: match, construct, and initialise.
    ///
    /// This is the full claim sequence run by PCI enumeration for each
    /// function. On success the live driver is stored in the bound list and
    /// returned by index; on failure the registry is left untouched and the
    /// error is reported through [`DriverError`].
    ///
    /// A PCI function with vendor `0xFFFF` is rejected up front as
    /// non-existent, matching the PCI spec's "no device at this function"
    /// sentinel.
    pub fn bind(&mut self, dev: &PciDevice) -> Result<&mut BoundDriver, DriverError> {
        if dev.vendor_id == 0xFFFF {
            return Err(DriverError::InvalidDevice);
        }

        // Match first, then copy the descriptor *by value* so the immutable
        // borrow of `self` from `match_device` ends before we mutate. The
        // descriptor is `Copy` (it is just a `&'static str` + a `fn` pointer
        // + a small enum), so this is a flat byte copy with no allocation.
        let desc = match self.match_device(dev) {
            Some((_, d)) => *d,
            None => {
                ::log::trace!("driver: no match for {dev}", dev = dev);
                return Err(DriverError::NoMatch);
            },
        };

        let mut driver = (desc.ctor)(dev).map_err(|e| {
            ::log::warn!(
                "driver: `{}` ctor failed for {dev}: {e}",
                desc.name,
                dev = dev,
                e = e
            );
            DriverError::CreateFailed
        })?;

        driver.init().map_err(|e| {
            ::log::warn!(
                "driver: `{}` init failed for {dev}: {e}",
                desc.name,
                dev = dev,
                e = e
            );
            DriverError::InitFailed
        })?;

        ::log::info!("driver: `{}` bound to {dev}", desc.name, dev = dev);

        self.bound.push(BoundDriver {
            location: dev.location,
            name: desc.name,
            driver,
        });

        // Return the freshly pushed entry. `last_mut` is infallible after the
        // push; the only way it could be None is an allocation failure in
        // `push`, which aborts the kernel via the OOM handler long before we
        // get here.
        Ok(self
            .bound
            .last_mut()
            .expect("bound entry must exist after push"))
    }

    /// Bind every PCI function in `devices` that a registered driver claims.
    ///
    /// Convenience for PCI enumeration: walk a slice of probed functions and
    /// bind each one, skipping failures. Returns the number of drivers that
    /// bound successfully. `NoMatch` and `InvalidDevice` are expected (most
    /// PCI functions have no Xenith driver yet, and absent functions report
    /// vendor `0xFFFF`); `bind` already logs those at `trace`, so this arm
    /// stays quiet. Real errors are `warn`-level by `bind`.
    pub fn bind_all(&mut self, devices: &[PciDevice]) -> usize {
        let mut bound_count = 0usize;
        for dev in devices {
            match self.bind(dev) {
                Ok(_) => bound_count += 1,
                // `bind` already logged both of these at trace level.
                Err(DriverError::NoMatch) | Err(DriverError::InvalidDevice) => {},
                Err(e) => {
                    ::log::warn!("driver: bind failed for {dev}: {e}", dev = dev, e = e);
                },
            }
        }
        bound_count
    }

    /// Number of drivers currently bound.
    pub fn bound_count(&self) -> usize {
        self.bound.len()
    }

    /// Find the driver bound to PCI `location`, if any.
    pub fn find(&self, location: u32) -> Option<&BoundDriver> {
        self.bound.iter().find(|b| b.location == location)
    }

    /// Find the bound driver for PCI `location`, mutably.
    pub fn find_mut(&mut self, location: u32) -> Option<&mut BoundDriver> {
        self.bound.iter_mut().find(|b| b.location == location)
    }

    /// Iterate over all bound drivers, mutably. Used by shutdown to quiesce
    /// every device in reverse bind order.
    pub fn bound_iter_mut(&mut self) -> core::slice::IterMut<'_, BoundDriver> {
        self.bound.iter_mut()
    }

    /// Shut down every bound driver in reverse bind order, then drop them.
    ///
    /// Reverse order matches bring-up: a bridge driver is brought down after
    /// the devices behind it, so a still-live function never finds its
    /// upstream bridge gone. Errors are logged but do not abort the loop — a
    /// failing shutdown must not strand the remaining drivers online.
    pub fn shutdown_all(&mut self) {
        while let Some(mut bound) = self.bound.pop() {
            if let Err(e) = bound.driver.shutdown() {
                ::log::warn!(
                    "driver: `{}` shutdown error for 0x{loc:08x}: {e}",
                    bound.name,
                    loc = bound.location,
                    e = e
                );
            }
            ::log::debug!(
                "driver: `{}` shut down (0x{loc:08x})",
                bound.name,
                loc = bound.location
            );
            // `bound` drops here, freeing the boxed driver.
        }
    }
}

impl fmt::Debug for DriverRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DriverRegistry")
            .field("descriptors", &self.descriptors.len())
            .field("bound", &self.bound.len())
            .finish()
    }
}

impl Default for DriverRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

/// The kernel-wide driver registry.
///
/// Const-constructed empty at link time and filled during `devices::init`.
/// The spinlock serialises registration and binding against concurrent
/// access from other CPUs during SMP bring-up; after boot the lock is
/// effectively uncontended and ownership queries are a single CAS.
pub static DRIVER_REGISTRY: SpinLock<DriverRegistry> = SpinLock::new(DriverRegistry::new());

/// Convenience: register a descriptor against the global registry.
///
/// Takes the lock, registers, and releases. Intended for driver modules'
/// `init` functions, which run single-threaded on the BSP during boot but
/// still go through the lock for uniformity with future SMP bring-up.
pub fn register(desc: DriverDescriptor) -> Result<(), DriverError> {
    DRIVER_REGISTRY.lock().register(desc)
}

/// Convenience: bind a single PCI function against the global registry.
pub fn bind(dev: &PciDevice) -> Result<(), DriverError> {
    DRIVER_REGISTRY.lock().bind(dev).map(|_| ())
}

/// Convenience: bind a slice of PCI functions against the global registry,
/// returning the number that bound successfully.
pub fn bind_all(devices: &[PciDevice]) -> usize {
    DRIVER_REGISTRY.lock().bind_all(devices)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A toy driver whose probe accepts a single vendor/device pair and
    /// whose constructor records that it was built.
    struct FakeNet {
        name: &'static str,
        loc: u32,
    }

    impl Driver for FakeNet {
        fn name(&self) -> &str {
            self.name
        }
        fn pci_location(&self) -> Option<u32> {
            Some(self.loc)
        }
    }

    fn make_fake_net() -> DriverDescriptor {
        fn probe(_d: &PciDevice) -> bool {
            true
        }
        fn ctor(d: &PciDevice) -> Result<Kbox<dyn Driver>, DriverError> {
            Ok(Kbox::new(FakeNet {
                name: "fake-net",
                loc: d.location,
            }))
        }
        DriverDescriptor {
            name: "fake-net",
            match_kind: MatchKind::VendorDevice {
                vendor: 0x10EC,
                device: 0x8168,
            },
            probe: Some(probe),
            ctor,
        }
    }

    fn rtl8168() -> PciDevice {
        PciDevice {
            location: 0x0000_3000,
            vendor_id: 0x10EC,
            device_id: 0x8168,
            class_code: pci_class::NETWORK,
            subclass: 0x00,
            prog_if: 0x00,
            revision: 0x01,
            bar_count: 3,
        }
    }

    fn unmatched() -> PciDevice {
        PciDevice {
            location: 0x0000_4000,
            vendor_id: 0x1234,
            device_id: 0x5678,
            class_code: pci_class::BRIDGE,
            subclass: 0x00,
            prog_if: 0x00,
            revision: 0x00,
            bar_count: 1,
        }
    }

    #[test]
    fn vendor_device_match_accepts_exact_pair() {
        let d = make_fake_net();
        assert!(d.accepts(&rtl8168()));
        assert!(!d.accepts(&unmatched()));
    }

    #[test]
    fn class_match_wildcards_prog_if_when_none() {
        let d = DriverDescriptor {
            name: "ahci",
            match_kind: MatchKind::Class {
                class: pci_class::STORAGE,
                subclass: 0x06,
                prog_if: None,
            },
            probe: None,
            ctor: |_| Err(DriverError::CreateFailed),
        };
        let mut dev = rtl8168();
        dev.class_code = pci_class::STORAGE;
        dev.subclass = 0x06;
        dev.prog_if = 0x01; // any prog_if is accepted when None
        assert!(d.accepts(&dev));
    }

    #[test]
    fn registry_dedups_by_name() {
        let mut reg = DriverRegistry::new();
        assert!(reg.register(make_fake_net()).is_ok());
        assert_eq!(
            reg.register(make_fake_net()).unwrap_err(),
            DriverError::AlreadyRegistered
        );
    }

    #[test]
    fn registry_bind_and_find() {
        let mut reg = DriverRegistry::new();
        reg.register(make_fake_net()).unwrap();
        let dev = rtl8168();
        reg.bind(&dev).unwrap();
        assert_eq!(reg.bound_count(), 1);
        assert!(reg.find(dev.location).is_some());
        assert_eq!(reg.find(dev.location).unwrap().name, "fake-net");
    }

    #[test]
    fn registry_rejects_invalid_device() {
        let mut reg = DriverRegistry::new();
        let bad = PciDevice {
            vendor_id: 0xFFFF,
            ..rtl8168()
        };
        assert_eq!(reg.bind(&bad).unwrap_err(), DriverError::InvalidDevice);
    }

    #[test]
    fn registry_no_match_is_not_an_error_in_bind_all() {
        let mut reg = DriverRegistry::new();
        // No descriptors registered: every function yields NoMatch, which
        // bind_all swallows at trace level and does not count.
        assert_eq!(reg.bind_all(&[rtl8168(), unmatched()]), 0);
    }
}
