//! Advanced Host Controller Interface (AHCI) SATA driver.
//!
//! This module is the root of Xenith's AHCI support. AHCI is the
//! memory-mapped register interface that Intel published in 2003 to unify
//! SATA controller programming; almost every non-NVMe SATA disk in a PC sits
//! behind an AHCI controller that presents itself on PCI as
//! class `0x01` (mass storage), subclass `0x06` (SATA), programming
//! interface `0x01` (AHCI). The controller's register file is exposed
//! through an 8 KiB memory-mapped Base Address Register called the **ABAR**
//! (AHCI Base Address Register, always BAR5 on a standard AHCI function),
//! and the bulk of the driver's work is enumerating the ports the ABAR
//! advertises and driving each one's command list.
//!
//! # Layering
//!
//! `ahci` sits below the future block layer and above
//! [`crate::devices::pci`] (for function discovery and BAR/bus-master
//! programming) and [`crate::mm`] (for translating the ABAR's physical
//! address through the HHDM direct map). Port transfers use bounded polling,
//! so storage works before the platform's PCI interrupt routing is online.
//!
//! # The ABAR and the HHDM
//!
//! The ABAR is a memory BAR: its decoded base is a *physical* address, and
//! before the CPU can touch it it must be reachable in the virtual address
//! space. Limine direct-maps all physical memory at the HHDM offset, so —
//! exactly like the IOAPIC and framebuffer MMIO windows — the AHCI driver
//! reaches the ABAR by translating its physical base through
//! [`crate::mm::phys_to_virt`] rather than by allocating its own page
//! tables. The resulting virtual address is stored as a raw `u64` (not a
//! `*mut`) so the register-handle structs stay `Send` + `Sync` without an
//! `unsafe impl`, matching the IOAPIC convention.
//!
//! # Volatility
//!
//! Every ABAR access goes through [`core::ptr::read_volatile`] /
//! [`core::ptr::write_volatile`]. AHCI registers have read side effects
//! (interrupt-status bits self-clear on read in some implementations, the
//! command-issue register advances the engine) and write side effects, so
//! the compiler must not elide or reorder them. Accesses are 32-bit
//! aligned — the AHCI spec mandates 32-bit register accesses and forbids
//! byte accesses to the ABAR.
//!
//! # Detection
//!
//! [`detect`] walks a slice of probed PCI functions looking for the
//! (class, subclass, prog_if) triple `(0x01, 0x06, 0x01)`. The prog_if is
//! the distinguishing bit: `0x01` means the controller is in AHCI mode
//! (versus a legacy IDE-compatible SATA controller at prog_if `0x00`), so
//! the driver refuses anything that is not explicitly AHCI. A controller
//! discovered this way is brought online by [`AhciController::new`], which
//! maps the ABAR, reads the implemented-ports bitmap, and constructs an
//! [`HbaPort`] handle for each implemented port that also has a device
//! signature present.

pub mod hba;

// Re-export the port and register-view types so callers can write
// `crate::devices::ahci::HbaPort` without drilling into `hba`. The
// submodule path stays available for code that wants to scope imports.
use core::ptr;

pub use hba::{HbaError, HbaPort};
use xenith_bitflags::bitflags;
use xenith_types::PhysAddr;

use crate::devices::pci::enumerate::{
    self, PciDevice as EnumeratedPciDevice, PciDriver, PciDriverError,
};
use crate::devices::pci::{PciAddress, PciCommand, PciDevice};
use crate::mm::{phys_to_virt, KVec};
use crate::sync::SpinLock;

// ---------------------------------------------------------------------------
// PCI class-code constants for AHCI discovery
// ---------------------------------------------------------------------------

/// PCI base class `0x01`: mass storage controller. AHCI controllers live
/// here, alongside IDE, RAID, and NVMe.
const PCI_CLASS_MASS_STORAGE: u8 = 0x01;
/// PCI subclass `0x06`: SATA controller. A SATA controller can be either a
/// legacy IDE-compatible part (prog_if `0x00`) or a proper AHCI part
/// (prog_if `0x01`); only the latter is driven by this module.
const PCI_SUBCLASS_SATA: u8 = 0x06;
/// PCI programming interface `0x01`: the controller is in AHCI mode and
/// exposes the AHCI register set through its ABAR. This is the bit that
/// separates an AHCI SATA controller from a legacy SATA controller, so the
/// detector requires it exactly.
const PCI_PROG_IF_AHCI: u8 = 0x01;

/// BAR index that carries the ABAR on a standard AHCI function. The AHCI
/// spec fixes the ABAR at BAR5; some vendor firmware additionally exposes
/// legacy IDE I/O ports in BAR0..BAR4, but the driver only ever talks to
/// the AHCI register file through the ABAR.
const ABAR_BAR_INDEX: usize = 5;

/// The size of the ABAR register window in bytes. The generic host
/// registers occupy the first 0x100 bytes and each of the (up to) 32 ports
/// occupies a further 0x80 bytes from 0x100 onwards, so the worst case is
/// 0x100 + 32 * 0x80 = 0x1100; a BAR covering it is at least 8 KiB.
pub const ABAR_SIZE: usize = 0x2000;

/// The per-port register block is 0x80 (128) bytes, and the port blocks
/// begin at offset 0x100 in the ABAR. Port *n*'s registers live at
/// `0x100 + n * 0x80`.
pub const PORT_REG_SIZE: usize = 0x80;
/// Offset of the first per-port register block within the ABAR.
pub const PORT_REGS_BASE: usize = 0x100;

/// The maximum number of ports an AHCI controller can implement. The PI
/// (Ports Implemented) register is a 32-bit bitmap, so at most 32 ports
/// exist; the CAP register's `NP` field (bits 0..4) further limits the
/// implemented port count to NP+1.
pub const MAX_PORTS: usize = 32;

// ---------------------------------------------------------------------------
// Global Host Control register bits (GHC, ABAR offset 0x04)
// ---------------------------------------------------------------------------

bitflags! {
    /// The 32-bit Global Host Control register at ABAR offset `0x04`.
    ///
    /// GHC is the master control for the whole HBA: the reset bit, the
    /// global interrupt-enable, and the AHCI-enable bit that switches the
    /// controller out of legacy IDE-compatibility mode. A bring-up sequence
    /// typically sets `AHCI_ENABLE` first (to lock the controller into AHCI
    /// mode), performs an `HBA_RESET` with the standard 1 ms settle, then
    /// re-asserts `AHCI_ENABLE` and finally sets `INTERRUPT_ENABLE` once
    /// port setup is done.
    pub struct Ghc: u32 {
        /// Bit 0 — HBA Reset. Writing 1 resets the whole controller; the bit
        /// self-clears when the reset completes. Must be held for at least
        /// 1 ms and followed by re-enabling `AHCI_ENABLE`.
        pub const HBA_RESET       = 1 << 0;
        /// Bit 1 — Interrupt Enable. When set, the HBA asserts its interrupt
        /// line for any port interrupt whose bit is set in PxIE. Cleared by
        /// reset, so it must be re-enabled after `HBA_RESET`.
        pub const INTERRUPT_ENABLE = 1 << 1;
        /// Bit 31 — AHCI Enable. When set, the controller is in AHCI mode
        /// and the ABAR is the programming interface; when clear, the
        /// controller may present legacy IDE registers at its BAR0..BAR3.
        /// Must be set before any port is driven.
        pub const AHCI_ENABLE     = 1 << 31;
    }
}

// ---------------------------------------------------------------------------
// Host Capabilities register (CAP, ABAR offset 0x00) — selected fields
// ---------------------------------------------------------------------------

/// Mask for the Number of Command Slots field (bits 8..=12) of the CAP
/// register. The field value is `slots - 1`, so a controller advertising
/// `0x1F` here implements 32 command slots per port.
const CAP_NCS_MASK: u32 = 0x0000_1F00;
/// Shift for the Number of Command Slots field of CAP.
const CAP_NCS_SHIFT: u32 = 8;
/// Bit 31 of CAP: Supports 64-bit Addressing. When set, command-list and PRD
/// addresses may be 64-bit; when clear, only the low 4 GiB is addressable.
/// Xenith always runs in long mode, so a clear S64A would force the driver
/// to allocate DMA buffers below the 4 GiB boundary.
const CAP_S64A: u32 = 1 << 31;
/// Bits 0..=4 of CAP: the implemented port count minus one (`NP`). A value
/// of `0x1F` means 32 ports are implemented.
const CAP_NP_MASK: u32 = 0x0000_001F;

/// PxSIG value for an ATA disk. ATAPI, enclosure-management, and port-
/// multiplier signatures need different command protocols and are not
/// exposed as block devices by this driver.
const SATA_SIGNATURE: u32 = 0x0000_0101;

// ---------------------------------------------------------------------------
// AHCI controller handle
// ---------------------------------------------------------------------------

/// An AHCI SATA controller bound to one PCI function.
///
/// `AhciController` owns the ABAR mapping (a single `u64` HHDM-virtual
/// address) and the set of [`HbaPort`] handles for the ports the controller
/// implements and that have a device signature present. It is constructed by
/// [`AhciController::new`] from a probed [`PciDevice`], which maps the ABAR,
/// enables bus mastering on the PCI function, and enumerates the ports.
///
/// The struct is `Send` + `Sync` because every field is either a `u64`, a
/// plain integer, or a [`HbaPort`] (which is itself `Send` + `Sync` by the
/// same `u64`-not-`*mut` convention). No `unsafe impl` is needed.
pub struct AhciController {
    /// The HHDM-virtual address of the ABAR's first byte. All register
    /// accesses compute `abar_virt + offset` and dereference through
    /// `read_volatile` / `write_volatile`.
    abar_virt: u64,
    /// The PCI address of the controller function, retained so the driver
    /// can re-read config-space (e.g. to toggle the interrupt-disable bit
    /// once MSI/MSI-X is wired up) without the caller passing it back in.
    pci: PciAddress,
    /// The ports that were implemented by the controller *and* reported a
    /// device signature at bring-up. Ports with no drive attached are
    /// skipped so the block layer never sees an idle port it would just
    /// time out on.
    ports: [Option<HbaPort>; MAX_PORTS],
    /// The number of command slots each port supports, read from CAP. The
    /// value is `ncs + 1` (the CAP field stores `slots - 1`); cached here so
    /// every port does not re-decode CAP on construction.
    command_slots: u8,
    /// Whether the controller advertises 64-bit DMA addressing. Cached from
    /// CAP so callers that need to allocate DMA buffers can branch without
    /// touching the ABAR.
    supports_64bit: bool,
}

impl AhciController {
    /// Bring an AHCI controller online.
    ///
    /// Maps the ABAR through the HHDM, enables PCI memory-space and bus
    /// mastering on the function (the firmware leaves these cleared on most
    /// machines), reads the implemented-ports bitmap (PI), and constructs an
    /// [`HbaPort`] for every implemented port that reports a non-zero device
    /// signature. Returns [`HbaError::NotAhci`] if the function is not an
    /// AHCI SATA controller, and [`HbaError::NoAbar`] if BAR5 is
    /// unimplemented (some virtual-machine AHCI emulations only expose the
    /// ABAR after AHCI-enable is set, but real hardware always has it).
    pub fn new(dev: &PciDevice) -> Result<Self, HbaError> {
        if !is_ahci_controller(dev) {
            return Err(HbaError::NotAhci);
        }

        let abar_raw = dev.bar(ABAR_BAR_INDEX);
        if abar_raw == 0 {
            // A zero BAR5 means the function does not implement the ABAR.
            // Every real AHCI controller exposes it, so this is fatal.
            ::log::warn!(
                "ahci: {} advertises AHCI class but BAR5 is unimplemented",
                dev.address()
            );
            return Err(HbaError::NoAbar);
        }

        if abar_raw & 1 != 0 {
            return Err(HbaError::AbarIsIo);
        }
        // BAR5 is the final BAR slot in a type-0 header and cannot legally be
        // the low half of a 64-bit BAR. Strip the memory-BAR flag nibble.
        let base = u64::from(abar_raw & 0xFFFF_FFF0);

        let pci_addr = dev.address();

        // Enable memory-space + bus-master on the function. Without
        // MEMORY_SPACE the MMIO reads below return 0xFFFFFFFF (the host
        // bridge's "no device" response); without BUS_MASTER the controller
        // cannot DMA the command list, so every issued command would hang.
        let cmd = PciCommand::from_bits_truncate(pci_addr.read_command());
        let enable = cmd | PciCommand::MEMORY_SPACE | PciCommand::BUS_MASTER;
        pci_addr.write_command(enable.bits());
        ::log::debug!(
            "ahci: {} command register {:#06x} -> {:#06x}",
            pci_addr,
            cmd.bits(),
            enable.bits()
        );

        // Translate the ABAR's physical base through the HHDM direct map.
        // Limine maps all physical memory 1:1 at the HHDM offset, so the 2
        // KiB ABAR window is reachable at `HHDM + abar_phys` without
        // allocating any page tables of our own. Routing through the typed
        // constructors validates the address (PhysAddr rejects bits above
        // 52, VirtAddr canonicalises) before we flatten to the u64 the
        // volatile accesses want.
        let phys = PhysAddr::new_truncate(base);
        let virt = phys_to_virt(phys);
        let abar_virt = virt.as_u64();

        // Read the implemented-ports bitmap and the capabilities before we
        // touch any port. The GHC.AE bit must be set for PI to be readable
        // in a defined way on some controllers, so set it first; it is
        // self-clearing only on reset, which we did not issue here.
        let regs = HbaMemory::new(abar_virt);
        regs.set_ahci_enable(true);
        regs.take_ownership()?;
        regs.reset()?;
        // Port commands complete through bounded polling until IRQ routing is
        // available. Keeping GHC.IE clear prevents an unrouted INTx storm.
        regs.set_interrupt_enable(false);
        let cap = regs.cap();
        let pi = regs.ports_implemented();
        let version = regs.version();
        let command_slots = ((cap & CAP_NCS_MASK) >> CAP_NCS_SHIFT) as u8 + 1;
        let supports_64bit = (cap & CAP_S64A) != 0;
        let np = ((cap & CAP_NP_MASK) as usize) + 1;

        ::log::info!(
            "ahci: {} ABAR @ {:#018x} (phys {:#014x}), AHCI {:x}.{:x}, {} cmd slots, {} ports max, 64-bit DMA={}",
            pci_addr,
            abar_virt,
            base,
            (version >> 16) & 0xFFFF,
            version & 0xFFFF,
            command_slots,
            np,
            supports_64bit,
        );

        // Build a port handle for every implemented port that has a device
        // present. A port is "implemented" when its bit is set in PI; the
        // device's presence is inferred from a non-zero signature, which a
        // later phase will refine into an actual IDENTIFY DEVICE command.
        let mut ports: [Option<HbaPort>; MAX_PORTS] = [const { None }; MAX_PORTS];
        let mut attached = 0usize;
        for (index, slot) in ports.iter_mut().enumerate() {
            if (pi & (1u32 << index)) == 0 {
                continue;
            }
            let port_virt = abar_virt + (PORT_REGS_BASE + index * PORT_REG_SIZE) as u64;
            let port = match HbaPort::new(port_virt, index as u8, command_slots, supports_64bit) {
                Ok(port) => port,
                Err(error) => {
                    ::log::warn!("ahci: port {} setup failed: {}", index, error);
                    continue;
                },
            };
            if !port.device_present() {
                ::log::debug!("ahci: port {} implemented but link is inactive", index);
                continue;
            }
            let sig = port.signature();
            if sig != SATA_SIGNATURE {
                ::log::info!(
                    "ahci: port {} has unsupported signature {:#010x} ({})",
                    index,
                    sig,
                    signature_name(sig)
                );
                continue;
            }
            ::log::info!(
                "ahci: port {} attached, signature {:#010x} ({})",
                index,
                sig,
                signature_name(sig)
            );
            *slot = Some(port);
            attached += 1;
        }
        ::log::info!("ahci: {} port(s) with devices attached", attached);

        Ok(Self {
            abar_virt,
            pci: pci_addr,
            ports,
            command_slots,
            supports_64bit,
        })
    }

    /// The HHDM-virtual address of the ABAR. Exposed for diagnostics and for
    /// the [`hba`] submodule's port-base computation (which callers normally
    /// go through [`Self::port_base`] for).
    #[inline]
    #[must_use]
    pub const fn abar_virt(&self) -> u64 {
        self.abar_virt
    }

    /// The PCI address of the controller function.
    #[inline]
    #[must_use]
    pub const fn pci_address(&self) -> PciAddress {
        self.pci
    }

    /// The number of command slots each port supports (`CAP.NCS + 1`).
    #[inline]
    #[must_use]
    pub const fn command_slots(&self) -> u8 {
        self.command_slots
    }

    /// Whether the controller supports 64-bit DMA addressing (`CAP.S64A`).
    #[inline]
    #[must_use]
    pub const fn supports_64bit_dma(&self) -> bool {
        self.supports_64bit
    }

    /// The HHDM-virtual address of port `index`'s register block.
    ///
    /// Port *n*'s registers live at `ABAR + 0x100 + n * 0x80`; this helper
    /// encodes that once so callers never get the stride wrong. Returns
    /// `None` for out-of-range indices.
    #[inline]
    #[must_use]
    pub fn port_base(&self, index: usize) -> Option<u64> {
        if index < MAX_PORTS {
            Some(self.abar_virt + (PORT_REGS_BASE + index * PORT_REG_SIZE) as u64)
        } else {
            None
        }
    }

    /// The attached port at `index`, if any.
    #[inline]
    #[must_use]
    pub fn port(&self, index: usize) -> Option<&HbaPort> {
        self.ports.get(index)?.as_ref()
    }

    /// A mutable handle to the attached port at `index`, if any.
    #[inline]
    #[must_use]
    pub fn port_mut(&mut self, index: usize) -> Option<&mut HbaPort> {
        self.ports.get_mut(index)?.as_mut()
    }

    /// Remove an attached port from this controller and transfer ownership to
    /// a block consumer such as FAT. The controller's ABAR remains mapped for
    /// the returned port's lifetime.
    pub fn take_port(&mut self, index: usize) -> Option<HbaPort> {
        self.ports.get_mut(index)?.take()
    }

    /// Iterate over the indices of attached ports.
    pub fn attached_port_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.ports
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.is_some().then_some(i))
    }

    /// The number of drives attached across all ports.
    #[must_use]
    pub fn attached_count(&self) -> usize {
        self.ports.iter().filter(|p| p.is_some()).count()
    }

    /// A borrow on the global host register view.
    ///
    /// Cheap to construct ([`HbaMemory`] is a thin non-owning handle over
    /// the ABAR virtual address); returned so callers can read CAP / GHC /
    /// IS / PI without reaching into the private `abar_virt` field.
    #[inline]
    #[must_use]
    pub fn host_registers(&self) -> HbaMemory {
        HbaMemory::new(self.abar_virt)
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Whether `dev` is an AHCI SATA controller.
///
/// Matches the (base class, subclass, prog_if) triple
/// `(0x01, 0x06, 0x01)` — mass storage, SATA, AHCI mode. The prog_if is the
/// distinguishing bit: a SATA controller at prog_if `0x00` is a legacy
/// IDE-compatible part that this driver does not understand, so the match
/// requires prog_if exactly `0x01`.
#[must_use]
pub fn is_ahci_controller(dev: &PciDevice) -> bool {
    dev.base_class() == PCI_CLASS_MASS_STORAGE
        && dev.subclass() == PCI_SUBCLASS_SATA
        && dev.prog_if() == PCI_PROG_IF_AHCI
}

/// Walk a slice of probed PCI functions and return the indices of the ones
/// that are AHCI SATA controllers. A machine normally has at most one AHCI
/// controller, but the function is generic so a multi-controller server
/// (e.g. a backplane with several SATAs) is handled correctly.
#[must_use]
pub fn detect(devices: &[PciDevice]) -> KVecIndices {
    // A small stack-allocated index buffer keeps this allocation-free for the
    // common one-or-zero-controller case; the reallocations only fire on
    // the rare multi-controller machine.
    let mut out: KVecIndices = KVecIndices::new();
    for (i, dev) in devices.iter().enumerate() {
        if is_ahci_controller(dev) {
            ::log::info!("ahci: detected AHCI controller at {}", dev.address());
            out.push(i);
        }
    }
    out
}

/// Convenience alias for the index vector returned by [`detect`], so the
/// signature stays readable. It is just a `KVec<usize>` of indices into the
/// caller's PCI device slice.
pub type KVecIndices = crate::mm::KVec<usize>;

// ---------------------------------------------------------------------------
// PCI binding and controller registry
// ---------------------------------------------------------------------------

/// Online controllers retained for the lifetime of the kernel. Keeping the
/// controller value alive also keeps every port's DMA arena alive.
static CONTROLLERS: SpinLock<KVec<AhciController>> = SpinLock::new(KVec::new());

struct AhciPciDriver;

static AHCI_PCI_DRIVER: AhciPciDriver = AhciPciDriver;

fn canonical_pci_device(device: &EnumeratedPciDevice) -> PciDevice {
    PciDevice {
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
    }
}

impl PciDriver for AhciPciDriver {
    fn name(&self) -> &'static str {
        "ahci"
    }

    fn matches(&self, device: &EnumeratedPciDevice) -> bool {
        device.base_class == PCI_CLASS_MASS_STORAGE
            && device.subclass == PCI_SUBCLASS_SATA
            && device.prog_if == PCI_PROG_IF_AHCI
    }

    fn probe(&self, device: &EnumeratedPciDevice) -> Result<(), PciDriverError> {
        let canonical = canonical_pci_device(device);
        // A repeated PCI bind pass must not reset an already-online HBA. In
        // particular, resetting here would invalidate commands owned by the
        // controller already retained in `CONTROLLERS` even if the duplicate
        // value were discarded below.
        if CONTROLLERS
            .lock()
            .iter()
            .any(|online| online.pci_address() == canonical.address())
        {
            return Ok(());
        }
        let controller = AhciController::new(&canonical).map_err(|error| {
            ::log::warn!("ahci: failed to bind {}: {}", device.describe_id(), error);
            match error {
                HbaError::NoAbar | HbaError::AbarIsIo => PciDriverError::BarUnreadable,
                _ => PciDriverError::ProbeFailed("AHCI controller setup failed"),
            }
        })?;

        let mut controllers = CONTROLLERS.lock();
        controllers.push(controller);
        Ok(())
    }
}

/// Register the AHCI class driver before the PCI enumeration/bind pass.
pub fn register_pci_driver() {
    enumerate::register_driver(&AHCI_PCI_DRIVER);
}

/// Number of AHCI controllers successfully brought online.
#[must_use]
pub fn controller_count() -> usize {
    CONTROLLERS.lock().len()
}

/// Run `f` with a mutable attached port. The registry lock serialises block
/// I/O until the future block scheduler introduces per-port request queues.
pub fn with_port_mut<R>(
    controller: usize,
    port: usize,
    f: impl FnOnce(&mut HbaPort) -> R,
) -> Option<R> {
    let mut controllers = CONTROLLERS.lock();
    let port = controllers.get_mut(controller)?.port_mut(port)?;
    Some(f(port))
}

/// Transfer one attached port out of the global registry so a filesystem can
/// own it as its concrete [`BlockDevice`].
pub fn take_port(controller: usize, port: usize) -> Option<HbaPort> {
    CONTROLLERS.lock().get_mut(controller)?.take_port(port)
}

// ---------------------------------------------------------------------------
// Device-signature names
// ---------------------------------------------------------------------------

/// A short label for a SATA device signature (`PxSIG`).
///
/// The signature is the value the device writes into PxSIG after a COMRESET;
/// it identifies the device type before an IDENTIFY command is issued. The
/// two values a SATA driver cares about are the SATA disk signature
/// (`0x00000101`) and the ATAPI signature (`0xEB140101`); anything else is
/// reported as `other` with the raw value logged by the caller.
#[must_use]
pub const fn signature_name(sig: u32) -> &'static str {
    match sig {
        0x0000_0101 => "sata-disk",
        0xEB14_0101 => "sata-cdrom",
        0xC33C_0101 => "enclosure-management",
        0x9669_0101 => "port-multiplier",
        0x0000_0000 => "none",
        _ => "other",
    }
}

// ---------------------------------------------------------------------------
// BlockDevice trait — the contract the future block layer will consume
// ---------------------------------------------------------------------------

/// A random-access block storage device.
///
/// `BlockDevice` is the seam the (future) block layer, VFS, and
/// filesystems use to talk to a disk without knowing whether it is an AHCI
/// SATA drive, an NVMe namespace, or a ramdisk. Every read and write is
/// expressed in 512-byte sectors at a 48-bit LBA, matching the smallest
/// sector size ATA defines; a device with 4 KiB physical sectors still
/// accepts 512-byte logical accesses.
pub trait BlockDevice {
    /// The logical sector size the device accepts. Fixed at 512 for ATA;
    /// kept as an associated constant so a caller can size buffers without
    /// an instance.
    const SECTOR_SIZE: usize = 512;

    /// Read `buf.len() / Self::SECTOR_SIZE` sectors starting at `lba` into
    /// `buf`. The buffer length must be a multiple of [`SECTOR_SIZE`](Self::SECTOR_SIZE).
    ///
    /// Returns the number of bytes transferred on success.
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<usize, HbaError>;

    /// Write `buf.len() / Self::SECTOR_SIZE` sectors starting at `lba` from
    /// `buf`. Symmetric with [`read_blocks`](Self::read_blocks).
    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<usize, HbaError>;

    /// Make all previously completed writes durable before returning.
    /// Volatile or memory-backed devices may keep the default no-op.
    fn flush(&mut self) -> Result<(), HbaError> {
        Ok(())
    }
}

impl BlockDevice for HbaPort {
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<usize, HbaError> {
        HbaPort::read_blocks(self, lba, buf)
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<usize, HbaError> {
        HbaPort::write_blocks(self, lba, buf)
    }

    fn flush(&mut self) -> Result<(), HbaError> {
        self.flush_cache()
    }
}

// ---------------------------------------------------------------------------
// Host register view (HbaMemory)
// ---------------------------------------------------------------------------

/// A non-owning view of the AHCI generic host registers (the first 0x100
/// bytes of the ABAR).
///
/// `HbaMemory` is a thin handle over the ABAR's HHDM-virtual address; it is
/// `Copy` and cheap to construct, so callers create one on demand rather
/// than caching it. All accessors go through `read_volatile` so the compiler
/// cannot elide or coalesce the side-effecting MMIO reads.
///
/// The per-port register views live in [`hba::HbaPort`]; this type covers
/// only the global registers (CAP, GHC, IS, PI, VS, CAP2, BOHC). It is the
/// natural handle for controller-wide operations like a global reset or an
/// interrupt-status scan.
#[derive(Copy, Clone)]
pub struct HbaMemory {
    /// The HHDM-virtual address of the ABAR's first byte.
    base: u64,
}

impl HbaMemory {
    /// Construct a host-register view at HHDM-virtual `base`. The caller is
    /// responsible for ensuring `base` is a valid ABAR mapping (i.e. it came
    /// from [`phys_to_virt`] applied to a PCI memory BAR); the type does not
    /// re-validate.
    #[inline]
    #[must_use]
    pub const fn new(base: u64) -> Self {
        Self { base }
    }

    /// Read a 32-bit host register at byte `offset` from the ABAR.
    ///
    /// `offset` must be 4-byte aligned and within the first 0x100 bytes of
    /// the ABAR; the caller is responsible for both, matching the AHCI
    /// spec's 32-bit-access requirement.
    #[inline]
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: `base` is a valid, HHDM-mapped ABAR; `offset` is a
        // 4-byte-aligned host-register offset within the 2 KiB window. A
        // 32-bit volatile load is the AHCI-defined access width.
        unsafe { ptr::read_volatile((self.base + offset as u64) as *const u32) }
    }

    /// Write a 32-bit host register at byte `offset` from the ABAR.
    #[inline]
    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: same invariant as `read32`; the store is volatile so the
        // compiler does not elide it.
        unsafe {
            ptr::write_volatile((self.base + offset as u64) as *mut u32, value);
        }
    }

    /// Host Capabilities (CAP, offset 0x00). Read-only.
    #[inline]
    #[must_use]
    pub fn cap(&self) -> u32 {
        self.read32(0x00)
    }

    /// Global Host Control (GHC, offset 0x04). Read/write.
    #[inline]
    #[must_use]
    pub fn ghc(&self) -> u32 {
        self.read32(0x04)
    }

    /// Write the GHC register.
    #[inline]
    pub fn write_ghc(&self, value: u32) {
        self.write32(0x04, value);
    }

    /// Set or clear the AHCI-enable bit (GHC bit 31) atomically with respect
    /// to the other GHC bits. A read-modify-write preserves whatever the
    /// firmware left in the interrupt-enable and reset bits.
    #[inline]
    pub fn set_ahci_enable(&self, enable: bool) {
        let cur = self.ghc();
        let next = if enable {
            cur | Ghc::AHCI_ENABLE.bits()
        } else {
            cur & !Ghc::AHCI_ENABLE.bits()
        };
        self.write_ghc(next);
    }

    /// Enable or disable controller-wide interrupt delivery while preserving
    /// AHCI-enable and reset state.
    pub fn set_interrupt_enable(&self, enable: bool) {
        let current = self.ghc();
        let next = if enable {
            current | Ghc::INTERRUPT_ENABLE.bits()
        } else {
            current & !Ghc::INTERRUPT_ENABLE.bits()
        };
        self.write_ghc(next);
    }

    /// Interrupt Status (IS, offset 0x08). A bit is set for any port that
    /// has a pending interrupt; the per-port PxIS register distinguishes the
    /// cause. Reading IS does *not* clear it — each PxIS bit must be cleared
    /// individually.
    #[inline]
    #[must_use]
    pub fn interrupt_status(&self) -> u32 {
        self.read32(0x08)
    }

    /// Ports Implemented (PI, offset 0x0C). Bit *n* is set if port *n* is
    /// implemented by this controller. The driver uses this to decide which
    /// `HbaPort` handles to construct.
    #[inline]
    #[must_use]
    pub fn ports_implemented(&self) -> u32 {
        self.read32(0x0C)
    }

    /// AHCI Version (VS, offset 0x10). The high 16 bits are the major
    /// version and the low 16 are the minor, e.g. `0x0001_0301` is AHCI
    /// 1.3.1.
    #[inline]
    #[must_use]
    pub fn version(&self) -> u32 {
        self.read32(0x10)
    }

    /// Host Capabilities Extended (CAP2, offset 0x24). Read-only.
    #[inline]
    #[must_use]
    pub fn cap2(&self) -> u32 {
        self.read32(0x24)
    }

    /// BIOS/OS Handoff Control and Status (BOHC, offset 0x28). Used during
    /// early bring-up to take ownership from the firmware if the controller
    /// advertises the handoff capability in CAP.SAM.
    #[inline]
    #[must_use]
    pub fn bohc(&self) -> u32 {
        self.read32(0x28)
    }

    /// Write BIOS/OS Handoff Control and Status (BOHC).
    pub fn write_bohc(&self, value: u32) {
        self.write32(0x28, value);
    }

    /// Request ownership from firmware when CAP2 advertises the AHCI 1.2+
    /// BIOS/OS handoff protocol. The wait is bounded so broken firmware does
    /// not stall boot forever.
    pub fn take_ownership(&self) -> Result<(), HbaError> {
        const CAP2_BOH: u32 = 1 << 0;
        const BOHC_BOS: u32 = 1 << 0;
        const BOHC_OOS: u32 = 1 << 1;
        const BOHC_BB: u32 = 1 << 4;
        const HANDOFF_POLL_LIMIT: u32 = 5_000_000;

        if self.cap2() & CAP2_BOH == 0 {
            return Ok(());
        }
        self.write_bohc(self.bohc() | BOHC_OOS);
        for _ in 0..HANDOFF_POLL_LIMIT {
            if self.bohc() & (BOHC_BOS | BOHC_BB) == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(HbaError::EngineTimeout)
    }

    /// Issue a global HBA reset (GHC.HR).
    ///
    /// Sets the reset bit, waits for it to self-clear, then re-asserts
    /// AHCI-enable. The wait is a bounded poll because the spec only
    /// guarantees the bit clears "within a reasonable time"; one millisecond
    /// is the conventional upper bound. Port engines are programmed after
    /// this reset by [`AhciController::new`].
    pub fn reset(&self) -> Result<(), HbaError> {
        let cur = self.ghc();
        self.write_ghc(cur | Ghc::HBA_RESET.bits());
        // Spin until HR self-clears. The bound is generous: real hardware
        // clears the bit in a handful of microseconds, so a 1 ms cap is a
        // safety net rather than an expected wait.
        let mut spins = 0u32;
        while (self.ghc() & Ghc::HBA_RESET.bits()) != 0 {
            spins += 1;
            if spins > 1_000_000 {
                return Err(HbaError::EngineTimeout);
            }
            core::hint::spin_loop();
        }
        // Reset clears GHC.AE; re-assert it so the ABAR is the programming
        // interface again.
        self.set_ahci_enable(true);
        Ok(())
    }
}

// SAFETY: `HbaMemory` holds a plain `u64` (the HHDM-virtual ABAR address)
// and performs only volatile MMIO reads/writes through it. The address is
// fixed for the controller's lifetime and the AHCI registers are
// device-side state that does not alias Rust memory, so the handle is safe
// to share between CPUs (`Sync`) and move across threads (`Send`). This
// mirrors the IOAPIC handle's safety argument.
unsafe impl Send for HbaMemory {}
unsafe impl Sync for HbaMemory {}
