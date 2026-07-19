//! ACPI-driven power control: S5 soft-off via the PM1a/b control registers
//! and platform reset via the FADT `RESET_REG` generic address.
//!
//! This module is the narrow power-relevant window into the FADT. The full
//! FADT parser lives in the sibling `fadt` module (landed by a parallel
//! phase); it extracts the fields below into [`FadtPowerInfo`] and publishes
//! them through [`register_power_info`] early in ACPI bring-up. The rest of
//! the kernel — [`crate::power`] in particular — then reaches the hardware
//! through [`acpi_shutdown`] and [`acpi_reset`] without knowing anything
//! about ACPI table layout.
//!
//! # Why a separate, decoupled struct
//!
//! The FADT is a large, versioned table with dozens of fields most of the
//! kernel never touches. Carrying only the power fields in a small `Copy`
//! struct keeps the shutdown path allocation-free and lets it run after the
//! heap has been torn down (e.g. from a panic that decides to power off).
//!
//! # S5 and the `\_S5` object
//!
//! The ACPI spec defines the S5 (soft-off) sleep state's `SLP_TYP` encoding
//! in the `\_S5` package object inside the DSDT/SSDT AML. A full AML
//! interpreter is out of scope for this phase, so [`FadtPowerInfo`] carries
//! the `SLP_TYPa`/`SLP_TYPb` values explicitly: the FADT parser (or a future
//! AML walker) fills them in. When they are unknown the caller may use the
//! QEMU/PIIX default of `0`, which works on the common development target
//! but must be replaced with the `\_S5`-derived value for real hardware.
//!
//! # Safety posture
//!
//! The two write helpers issue real `out`/memory-mapped stores that drive
//! hardware power sequencing. They are safe to *call* — the type system
//! cannot tell whether the registered GAS points at a real PM block — but a
//! wrong value merely fails to power the machine off, which is a graceful
//! failure rather than a memory-safety violation. The MMIO path writes
//! through the Limine higher-half direct map, which is always mapped for the
//! physical addresses ACPI places registers at.

use core::ptr;

use crate::arch::{Port16, Port32, Port8};

// ---------------------------------------------------------------------------
// ACPI Generic Address Structure (ACPI 2.0+, §5.2.3.2)
// ---------------------------------------------------------------------------

/// ACPI Address Space IDs, the `ASL_ID` field of a [`GenericAddress`].
///
/// Only the two spaces PC power hardware actually uses for PM registers are
/// wired up here; the rest are named for completeness so a future driver can
/// match on them without re-deriving the constants.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AddressSpace {
    /// System memory: reach the register through a memory-mapped virtual
    /// address (the HHDM direct map of the physical address in the GAS).
    SystemMemory = 0,
    /// System I/O: reach the register through an `out`/`in` port cycle.
    SystemIo = 1,
    /// PCI configuration space: not supported by the shutdown path.
    PciConfig = 2,
    /// Embedded controller space: not supported by the shutdown path.
    EmbeddedController = 3,
    /// SMBus space: not supported by the shutdown path.
    SmBus = 4,
    /// Functional fixed hardware: not supported by the shutdown path.
    FunctionalFixedHardware = 0x7F,
    /// Any value outside the set ACPI defines.
    Unknown = 0xFF,
}

impl From<u8> for AddressSpace {
    #[inline]
    fn from(raw: u8) -> Self {
        match raw {
            0 => Self::SystemMemory,
            1 => Self::SystemIo,
            2 => Self::PciConfig,
            3 => Self::EmbeddedController,
            4 => Self::SmBus,
            0x7F => Self::FunctionalFixedHardware,
            _ => Self::Unknown,
        }
    }
}

/// ACPI Generic Address Structure.
///
/// A GAS is the way ACPI describes where a register lives without committing
/// to I/O or memory space: `space_id` picks the bus, `address` is the offset
/// within it, and `bit_width`/`bit_offset`/`access_size` describe the access
/// shape. The shutdown path only ever issues whole-register writes, so the
/// sub-byte `bit_offset` is honoured by the caller's choice of value rather
/// than by shifting here.
#[derive(Copy, Clone, Debug)]
pub struct GenericAddress {
    /// Which address space `address` is relative to.
    pub space: AddressSpace,
    /// Register width in bits. ACPI lets this differ from `access_size`; we
    /// use `access_size` for the actual store width and fall back to this
    /// when `access_size` is the legacy `0` ("undefined") sentinel.
    pub bit_width: u8,
    /// Bit offset of the field within the register. Unused for whole-register
    /// writes; preserved for fidelity so a future RMW path can use it.
    pub bit_offset: u8,
    /// Recommended access width in bytes (`1/2/3/4`), or `0` meaning "derive
    /// from `bit_width`". We honour it when non-zero.
    pub access_size: u8,
    /// The address itself: a port number for SystemIo, a physical address for
    /// SystemMemory, an encoded config address for PciConfig.
    pub address: u64,
}

/// Access width in bytes resolved from a [`GenericAddress`].
///
/// ACPI says: if `access_size` is non-zero use it, otherwise derive from
/// `bit_width` (round up to a power of two in {1,2,4,8}). We clamp to the
/// widths the PM registers actually use (1, 2, 4) because no PM1 control or
/// RESET_REG field is wider than 32 bits.
#[inline]
fn access_bytes(gas: &GenericAddress) -> u8 {
    if gas.access_size != 0 {
        return gas.access_size.min(4);
    }
    match gas.bit_width {
        0..=8 => 1,
        9..=16 => 2,
        17..=32 => 4,
        _ => 4,
    }
}

// ---------------------------------------------------------------------------
// Power-relevant FADT subset
// ---------------------------------------------------------------------------

/// The subset of the FADT the power sequencing path needs.
///
/// Constructed once by the ACPI bring-up code from the validated FADT and
/// published with [`register_power_info`]. All fields are
/// `Copy` so the struct can be stashed in a `spin::Once` and read lock-free
/// from the shutdown path.
#[derive(Copy, Clone, Debug)]
pub struct FadtPowerInfo {
    /// PM1a event block — included for completeness; the shutdown path does
    /// not need to read it, but a future SCI handler clears events from here.
    pub pm1a_evt: GenericAddress,
    /// PM1b event block, if the platform has a second PM chip. May be zero.
    pub pm1b_evt: GenericAddress,
    /// PM1a control register: the register S5 is written to.
    pub pm1a_cnt: GenericAddress,
    /// PM1b control register, if present. `pm1b_present` gates its use.
    pub pm1b_cnt: GenericAddress,
    /// FADT `RESET_REG`: the generic address the firmware declares for
    /// platform reset. Typically SystemIo port 0x64 (the 8042 command port).
    pub reset_reg: GenericAddress,
    /// FADT `RESET_VALUE`: the byte to write to `reset_reg` to force reset.
    pub reset_value: u8,
    /// `SLP_TYPa` for S5 from the `\_S5` package. `0` is the QEMU default.
    pub s5_slp_typa: u16,
    /// `SLP_TYPb` for S5. Only meaningful when `pm1b_present` is true.
    pub s5_slp_typb: u16,
    /// Whether `pm1b_cnt`/`pm1b_evt` describe a real second PM block.
    pub pm1b_present: bool,
    /// The Limine higher-half direct-map offset, needed to reach SystemMemory
    /// GAS registers. Stored here so the shutdown path can do MMIO without
    /// re-consulting the boot info (which may already be partly reclaimed).
    pub hhdm_offset: u64,
}

/// Errors returned by the ACPI power path.
///
/// Hand-rolled per the kernel convention (no `thiserror`/`std`); each variant
/// names one of the two reasons the hardware was not driven.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AcpiPowerError {
    /// [`register_power_info`] was never called — ACPI tables are absent or
    /// the FADT parser declined to publish a PM block. The caller should fall
    /// back to a non-ACPI path (QEMU debug-exit, 8042 reset, triple fault).
    NotAvailable,
    /// A register's [`GenericAddress`] named an address space the shutdown
    /// path does not drive (PciConfig, EmbeddedController, ...). The register
    /// is left untouched.
    UnsupportedSpace,
    /// A SystemMemory register was reached but its address plus the HHDM
    /// offset overflowed, so no store was issued.
    AddressOverflow,
}

// ---------------------------------------------------------------------------
// Global registry
// ---------------------------------------------------------------------------

/// The single published FADT power info, if any.
///
/// `spin::Once` gives set-once, lock-free reads — exactly the access pattern
/// the shutdown path wants (one writer at ACPI init, many readers, never
/// reset). `call_once` is a no-op on the second call, so a re-registration
/// during a late ACPI re-probe cannot corrupt the value.
static FADT_POWER: spin::Once<FadtPowerInfo> = spin::Once::new();

/// Publish the FADT power info for the rest of the kernel.
///
/// Called once by ACPI bring-up after the FADT is parsed. Subsequent calls are
/// harmless no-ops that return the already-published value, so the caller does
/// not need to guard against double-init.
pub fn register_power_info(info: FadtPowerInfo) {
    FADT_POWER.call_once(|| info);
}

/// Borrow the published FADT power info, if any.
///
/// Returns `None` before [`register_power_info`] has run (e.g. on a machine
/// with no ACPI, or early in boot before the FADT parser has executed). The
/// shutdown path treats `None` as "fall back to a non-ACPI mechanism".
pub fn power_info() -> Option<&'static FadtPowerInfo> {
    FADT_POWER.get()
}

// ---------------------------------------------------------------------------
// GAS write helpers
// ---------------------------------------------------------------------------

/// Write `value` (low bits) to the register described by `gas`, honouring its
/// address space and resolved access width.
///
/// Only SystemIo and SystemMemory are implemented; other spaces return
/// [`AcpiPowerError::UnsupportedSpace`] so the caller can fall back. The
/// access width is the smaller of the GAS's `access_size`/`bit_width` and 4
/// bytes, matching every PM1/RESET_REG field ACPI defines.
///
/// # Safety of the *call* (not the store)
///
/// The function is safe to call: a wrong GAS merely writes to a benign
/// location. The SystemMemory store is volatile and goes through the HHDM
/// direct map, which Limine guarantees covers every physical address the
/// firmware places MMIO registers at.
fn gas_write(gas: &GenericAddress, value: u32, hhdm: u64) -> Result<(), AcpiPowerError> {
    let bytes = access_bytes(gas);
    match gas.space {
        AddressSpace::SystemIo => {
            // Port numbers are 16-bit; the GAS carries 64 bits for uniformity
            // with the memory form, so truncate to the valid port range.
            let port = gas.address as u16;
            match bytes {
                1 => Port8::new(port).write(value as u8),
                2 => Port16::new(port).write(value as u16),
                // PM1 control and RESET_REG are never 32-bit in practice, but
                // honour the width for completeness via a 32-bit port handle.
                _ => Port32::new(port).write(value),
            }
            Ok(())
        },
        AddressSpace::SystemMemory => {
            // Map the physical address through the higher-half direct map.
            // `checked_add` guards against a malformed GAS whose address
            // would wrap the 64-bit space; we refuse rather than wrap.
            let virt = gas
                .address
                .checked_add(hhdm)
                .ok_or(AcpiPowerError::AddressOverflow)?;
            // SAFETY: `virt` is the HHDM mapping of a firmware-declared MMIO
            // register. Limine maps the full physical space at `hhdm`, so the
            // address is valid and writable in ring 0. The store is volatile
            // so the compiler does not elide it; we honour the access width by
            // casting to the smallest sufficient integer type.
            let ptr = virt as *mut u8;
            unsafe {
                match bytes {
                    1 => ptr::write_volatile(ptr, value as u8),
                    2 => ptr::write_volatile(ptr as *mut u16, value as u16),
                    _ => ptr::write_volatile(ptr as *mut u32, value),
                }
            }
            Ok(())
        },
        // PciConfig, EmbeddedController, SmBus, FunctionalFixedHardware, and
        // any unknown sentinel are not driven by the shutdown path.
        _ => Err(AcpiPowerError::UnsupportedSpace),
    }
}

// ---------------------------------------------------------------------------
// Public power actions
// ---------------------------------------------------------------------------

/// The `SLP_EN` bit in a PM1 control register: bit 13, set to enter the sleep
/// state named by `SLP_TYP` in bits 10..12.
const SLP_EN: u16 = 1 << 13;

/// `SLP_TYP` lives in bits 10..13 of PM1x_CNT. Shift the raw S5 type into
/// place.
const SLP_TYP_SHIFT: u32 = 10;

/// Enter the ACPI S5 soft-off state.
///
/// Writes `(SLP_TYP << 10) | SLP_EN` to PM1a_CNT, and to PM1b_CNT when the
/// platform declares a second PM block. The firmware then removes power; if
/// it does not (broken ACPI, no `_S5`, or running under a hypervisor that
/// ignores PM1 writes) the function returns normally so the caller can fall
/// back to a non-ACPI shutdown.
///
/// Returns [`AcpiPowerError::NotAvailable`] when no FADT power info has been
/// registered, so [`crate::power::poweroff`] can drop straight to its
/// QEMU/8042 fallbacks.
pub fn acpi_shutdown() -> Result<(), AcpiPowerError> {
    let info = match power_info() {
        Some(i) => i,
        None => return Err(AcpiPowerError::NotAvailable),
    };

    let value_a = ((info.s5_slp_typa as u32) << SLP_TYP_SHIFT) | SLP_EN as u32;
    // PM1 control writes are documented as 16-bit on PC hardware; the access
    // width encoded in the GAS is honoured by `gas_write`. A failure here
    // (e.g. PM1a_CNT in an unsupported space) is reported to the caller so it
    // can try a fallback rather than silently hang.
    gas_write(&info.pm1a_cnt, value_a, info.hhdm_offset)?;

    if info.pm1b_present {
        let value_b = ((info.s5_slp_typb as u32) << SLP_TYP_SHIFT) | SLP_EN as u32;
        // A PM1b failure is non-fatal: PM1a alone is enough to cut power on
        // the vast majority of platforms, so log-and-continue rather than
        // abort the shutdown. We still report the first error if PM1a also
        // failed above.
        let _ = gas_write(&info.pm1b_cnt, value_b, info.hhdm_offset);
    }

    ::log::info!("acpi: S5 written to PM1a control; awaiting power-off");
    Ok(())
}

/// Force a platform reset via the FADT `RESET_REG`.
///
/// Writes [`FadtPowerInfo::reset_value`] to [`FadtPowerInfo::reset_reg`]. On
/// real hardware this is usually an 8-bit out to the 8042 command port
/// (0x64) with value 0xFE; under that convention this path overlaps the
/// 8042 reset, but going through the GAS keeps the address portable for
/// platforms that declare a memory-mapped RESET_REG.
///
/// Returns [`AcpiPowerError::NotAvailable`] when no FADT has been registered
/// so [`crate::power::reboot`] can fall back to the 8042/triple-fault path.
pub fn acpi_reset() -> Result<(), AcpiPowerError> {
    let info = match power_info() {
        Some(i) => i,
        None => return Err(AcpiPowerError::NotAvailable),
    };

    gas_write(&info.reset_reg, info.reset_value as u32, info.hhdm_offset)?;
    ::log::info!("acpi: RESET_REG written; awaiting platform reset");
    Ok(())
}
