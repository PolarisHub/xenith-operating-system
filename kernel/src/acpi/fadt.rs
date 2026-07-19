//! FADT (Fixed ACPI Description Table) — PM1 registers, reset, and DSDT ptr.
//!
//! The FADT, signature `"FACP"`, is the ACPI table that describes the
//! platform's fixed power-management hardware: the PM1a/PM1b event and
//! control register blocks (used for S5 soft-off and sleep state entry), the
//! `RESET_REG` generic address (used for platform reset), and the physical
//! address of the DSDT. Xenith parses exactly those fields; the dozens of
//! other FADT fields (SCI interrupt vector, GPE blocks, RTC century
//! register, ...) are read past but not carried, and a future PM/SCI driver
//! can extend [`Fadt`] when it needs them.
//!
//! # Legacy vs extended fields
//!
//! The FADT is a versioned table. ACPI 1.0 carried the PM1 register blocks
//! as 32-bit I/O port numbers (offsets 56–71); ACPI 2.0+ added 64-bit
//! Generic Address Structures (`X_PM1a_EVT_BLK`, `X_PM1a_CNT_BLK`, ...) that
//! can name either an I/O port or a memory-mapped register. We read the
//! legacy port fields unconditionally (they are present in every revision)
//! and the extended GAS fields only when the table length covers them. When
//! an extended GAS has a non-zero address it takes precedence over the
//! legacy port, exactly as ACPI §5.2.9 mandates; otherwise the legacy port
//! is wrapped in a SystemIo GAS so the shutdown path sees a uniform
//! [`GenericAddress`] regardless of FADT revision.
//!
//! # Safety
//!
//! Every field is read byte-by-byte through `read_volatile` from the
//! HHDM-mapped FADT body, and each extended read is guarded on the table
//! length so a short (ACPI 1.0) FADT cannot drive an out-of-bounds access.
//! The parsed [`Fadt`] is leaked into `'static` storage so [`super::Tables`]
//! can hold `&'static Fadt` and stay `Copy`.

use core::fmt;

use xenith_types::PhysAddr;

use super::shutdown::{AddressSpace, GenericAddress};
use super::xsdt::SdtHeader;
use crate::mm::allocator::Box;

// ---------------------------------------------------------------------------
// FADT field offsets (ACPI §5.2.9, FADT revision 4+ layout)
// ---------------------------------------------------------------------------

/// Legacy 32-bit physical address of the DSDT. Present in every FADT
/// revision; superseded by [`X_DSDT`] when the extended field is non-zero.
const LEGACY_DSDT: usize = 40;
/// PM1a event block I/O port (legacy 32-bit). Always present.
const PM1A_EVT_BLK: usize = 56;
/// PM1b event block I/O port (legacy 32-bit). Zero when no PM1b block.
const PM1B_EVT_BLK: usize = 60;
/// PM1a control block I/O port (legacy 32-bit). Always present.
const PM1A_CNT_BLK: usize = 64;
/// PM1b control block I/O port (legacy 32-bit). Zero when no PM1b block.
const PM1B_CNT_BLK: usize = 68;
/// `RESET_REG` Generic Address Structure (12 bytes). Present in FADT
/// revision >= 2; absent in ACPI 1.0.
const RESET_REG: usize = 116;
/// The byte to write to `RESET_REG` to force a platform reset.
const RESET_VALUE: usize = 128;
/// Extended 64-bit physical address of the DSDT. Present in revision >= 2;
/// takes precedence over [`LEGACY_DSDT`] when non-zero.
const X_DSDT: usize = 140;
/// Extended GAS for the PM1a event block.
const X_PM1A_EVT: usize = 148;
/// Extended GAS for the PM1b event block.
const X_PM1B_EVT: usize = 160;
/// Extended GAS for the PM1a control block.
const X_PM1A_CNT: usize = 172;
/// Extended GAS for the PM1b control block.
const X_PM1B_CNT: usize = 184;

/// The minimum FADT length that contains the extended PM1b control GAS:
/// `X_PM1B_CNT + 12 = 196`. Tables shorter than this are ACPI 1.0-shaped and
/// only the legacy port fields are read.
const MIN_LEN_EXTENDED: usize = 196;

/// The minimum FADT length that contains `RESET_VALUE`: `RESET_VALUE + 1 =
/// 129`. Guarding the reset read on this avoids touching the reserved bytes
/// of an ACPI 1.0 FADT that predates `RESET_REG`.
const MIN_LEN_RESET: usize = 129;

/// Errors raised by FADT parsing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FadtError {
    /// The FADT body is too short to contain the legacy PM1 port fields.
    Truncated,
}

impl fmt::Display for FadtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("FADT body truncated"),
        }
    }
}

/// The parsed Fixed ACPI Description Table.
///
/// Carries the power-relevant subset the kernel acts on: the PM1a/b event
/// and control registers as [`GenericAddress`]es (so the shutdown path can
/// drive them uniformly whether they live in I/O or memory space), the
/// `RESET_REG`/`RESET_VALUE` pair, the legacy PM1a/b control port numbers
/// (for the boot log), the DSDT physical address, and whether a second PM
/// block (PM1b) is present.
#[derive(Clone, Copy, Debug)]
pub struct Fadt {
    /// Legacy PM1a control I/O port. Logged by [`super::init`] so a
    /// developer can correlate the FADT with the hardware PM block.
    pub pm1a_ctrl_block: u16,
    /// Legacy PM1b control I/O port. Zero when no PM1b block exists.
    pub pm1b_ctrl_block: u16,
    /// PM1a event register as a GAS. Prefer the extended X_PM1a_EVT_BLK when
    /// present and non-zero, else a SystemIo GAS wrapping the legacy port.
    pub pm1a_evt_gas: GenericAddress,
    /// PM1b event register GAS, or a zero-address GAS when no PM1b block.
    pub pm1b_evt_gas: GenericAddress,
    /// PM1a control register GAS — the register S5 is written to.
    pub pm1a_cnt_gas: GenericAddress,
    /// PM1b control register GAS, or zero-address when no PM1b block.
    pub pm1b_cnt_gas: GenericAddress,
    /// `RESET_REG`: the generic address firmware declares for reset.
    pub reset_reg: GenericAddress,
    /// The byte to write to `reset_reg` to force reset.
    pub reset_value: u8,
    /// Physical address of the DSDT (extended 64-bit when present, else the
    /// legacy 32-bit field). Consumed by [`super::dsdt`].
    pub dsdt_address: PhysAddr,
    /// Whether `pm1b_*` describe a real second PM block. False when the
    /// legacy PM1b port and the extended PM1b GAS are both zero.
    pub pm1b_present: bool,
}

impl Fadt {
    /// Parse a validated FADT [`SdtHeader`] into a [`Fadt`].
    ///
    /// Reads the legacy PM1 port fields unconditionally and the extended GAS
    /// fields when the table length covers them, preferring the extended
    /// forms when their addresses are non-zero. The result is leaked into
    /// `'static` storage so [`super::Tables`] can hold a `&'static Fadt`.
    pub fn parse(hdr: &'static SdtHeader) -> Result<&'static Self, FadtError> {
        let total = hdr.length as usize;
        // The legacy PM1 port block ends at PM1B_CNT_BLK + 4 = 72; a FADT
        // shorter than that cannot describe a usable PM block.
        if total < PM1B_CNT_BLK + 4 {
            return Err(FadtError::Truncated);
        }

        let base = hdr as *const SdtHeader as *const u8;
        let has_extended = total >= MIN_LEN_EXTENDED;
        let has_reset = total >= MIN_LEN_RESET;

        // --- Legacy DSDT and PM1 port fields --------------------------------
        let legacy_dsdt = read_u32_at(base, LEGACY_DSDT);
        let pm1a_evt_port = read_u32_at(base, PM1A_EVT_BLK);
        let pm1b_evt_port = read_u32_at(base, PM1B_EVT_BLK);
        let pm1a_cnt_port = read_u32_at(base, PM1A_CNT_BLK);
        let pm1b_cnt_port = read_u32_at(base, PM1B_CNT_BLK);

        // --- Extended fields, read only when the table covers them ---------
        let x_dsdt = if has_extended {
            read_u64_at(base, X_DSDT)
        } else {
            0
        };
        let x_pm1a_evt = if has_extended {
            read_gas_at(base, X_PM1A_EVT)
        } else {
            zero_gas()
        };
        let x_pm1b_evt = if has_extended {
            read_gas_at(base, X_PM1B_EVT)
        } else {
            zero_gas()
        };
        let x_pm1a_cnt = if has_extended {
            read_gas_at(base, X_PM1A_CNT)
        } else {
            zero_gas()
        };
        let x_pm1b_cnt = if has_extended {
            read_gas_at(base, X_PM1B_CNT)
        } else {
            zero_gas()
        };
        let (reset_reg, reset_value) = if has_reset {
            (read_gas_at(base, RESET_REG), read_u8_at(base, RESET_VALUE))
        } else {
            (zero_gas(), 0)
        };

        // Prefer extended GAS addresses when non-zero; otherwise wrap the
        // legacy port in a SystemIo GAS so the shutdown path sees one type.
        let pm1a_evt_gas = pick_gas(x_pm1a_evt, pm1a_evt_port, 16);
        let pm1b_evt_gas = pick_gas(x_pm1b_evt, pm1b_evt_port, 16);
        let pm1a_cnt_gas = pick_gas(x_pm1a_cnt, pm1a_cnt_port, 16);
        let pm1b_cnt_gas = pick_gas(x_pm1b_cnt, pm1b_cnt_port, 16);

        let pm1b_present = pm1b_cnt_port != 0 || (has_extended && x_pm1b_cnt.address != 0);

        // The DSDT address: prefer the extended 64-bit pointer when present
        // and non-zero, else zero-extend the legacy 32-bit field. ACPI 1.0
        // tables only have the legacy field; ACPI 2.0+ tables have both and
        // the extended one is authoritative when non-zero.
        let dsdt_address = if x_dsdt != 0 {
            PhysAddr::new_truncate(x_dsdt)
        } else {
            PhysAddr::new_truncate(u64::from(legacy_dsdt))
        };

        let fadt = Self {
            pm1a_ctrl_block: pm1a_cnt_port as u16,
            pm1b_ctrl_block: pm1b_cnt_port as u16,
            pm1a_evt_gas,
            pm1b_evt_gas,
            pm1a_cnt_gas,
            pm1b_cnt_gas,
            reset_reg,
            reset_value,
            dsdt_address,
            pm1b_present,
        };

        // Promote the stack value to `'static`. The FADT describes the
        // platform's PM hardware for the kernel's whole lifetime, so the
        // allocation is intentionally leaked.
        Ok(Box::leak(Box::new(fadt)))
    }
}

// ---------------------------------------------------------------------------
// Raw field readers
// ---------------------------------------------------------------------------

/// Read a little-endian `u8` at `off` from the FADT body.
///
/// # Safety
/// Callers guard `off` against the table length before calling.
fn read_u8_at(base: *const u8, off: usize) -> u8 {
    // SAFETY: caller guarantees `off` is within the validated FADT body.
    unsafe { core::ptr::read_volatile(base.add(off)) }
}

/// Read a little-endian `u32` at `off` from the FADT body.
///
/// # Safety
/// Callers guard `off + 4` against the table length before calling.
fn read_u32_at(base: *const u8, off: usize) -> u32 {
    let mut buf = [0u8; 4];
    for (i, slot) in buf.iter_mut().enumerate() {
        // SAFETY: caller guaranteed `off + i` is in-bounds.
        *slot = unsafe { core::ptr::read_volatile(base.add(off + i)) };
    }
    u32::from_le_bytes(buf)
}

/// Read a little-endian `u64` at `off` from the FADT body.
///
/// # Safety
/// Callers guard `off + 8` against the table length before calling.
fn read_u64_at(base: *const u8, off: usize) -> u64 {
    let mut buf = [0u8; 8];
    for (i, slot) in buf.iter_mut().enumerate() {
        // SAFETY: caller guaranteed `off + i` is in-bounds.
        *slot = unsafe { core::ptr::read_volatile(base.add(off + i)) };
    }
    u64::from_le_bytes(buf)
}

/// Read a 12-byte ACPI Generic Address Structure at `off`.
///
/// # Safety
/// Callers guard `off + 12` against the table length before calling.
fn read_gas_at(base: *const u8, off: usize) -> GenericAddress {
    let space = AddressSpace::from(read_u8_at(base, off));
    let bit_width = read_u8_at(base, off + 1);
    let bit_offset = read_u8_at(base, off + 2);
    let access_size = read_u8_at(base, off + 3);
    let address = read_u64_at(base, off + 4);
    GenericAddress {
        space,
        bit_width,
        bit_offset,
        access_size,
        address,
    }
}

/// A zero-address GAS, used as the default for absent extended fields.
fn zero_gas() -> GenericAddress {
    GenericAddress {
        space: AddressSpace::Unknown,
        bit_width: 0,
        bit_offset: 0,
        access_size: 0,
        address: 0,
    }
}

/// Prefer the extended GAS when its address is non-zero; otherwise wrap the
/// legacy I/O port in a SystemIo GAS with the given register bit width.
///
/// `legacy_port` is the 32-bit I/O port number from the FADT's legacy PM1
/// field; when it is zero and the extended GAS is also zero, the result is a
/// zero-address GAS (meaning "this register does not exist"), which the
/// shutdown path treats as "no PM1b block".
fn pick_gas(extended: GenericAddress, legacy_port: u32, bit_width: u8) -> GenericAddress {
    if extended.address != 0 {
        return extended;
    }
    if legacy_port == 0 {
        return zero_gas();
    }
    GenericAddress {
        space: AddressSpace::SystemIo,
        bit_width,
        bit_offset: 0,
        // access_size 0 means "derive from bit_width"; the shutdown path
        // resolves a 16-bit register to a 2-byte I/O write, which matches
        // every PM1 control field ACPI defines.
        access_size: 0,
        address: u64::from(legacy_port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_gas(table: &mut [u8], offset: usize, space: u8, width: u8, address: u64) {
        table[offset] = space;
        table[offset + 1] = width;
        table[offset + 3] = 2;
        table[offset + 4..offset + 12].copy_from_slice(&address.to_le_bytes());
    }

    #[test]
    fn parses_acpi_extended_fields_at_spec_offsets() {
        let table = Box::leak(Box::new([0u8; MIN_LEN_EXTENDED]));
        table[0..4].copy_from_slice(b"FACP");
        table[4..8].copy_from_slice(&(MIN_LEN_EXTENDED as u32).to_le_bytes());
        table[LEGACY_DSDT..LEGACY_DSDT + 4].copy_from_slice(&0x0012_3000u32.to_le_bytes());
        table[PM1A_CNT_BLK..PM1A_CNT_BLK + 4].copy_from_slice(&0x404u32.to_le_bytes());
        write_gas(table, RESET_REG, 1, 8, 0x0cf9);
        table[RESET_VALUE] = 0x06;
        table[X_DSDT..X_DSDT + 8].copy_from_slice(&0x0000_0000_1234_5000u64.to_le_bytes());
        write_gas(table, X_PM1A_EVT, 1, 16, 0x0440);
        write_gas(table, X_PM1A_CNT, 1, 16, 0x0444);

        // SAFETY: the leaked byte array contains a complete packed header
        // followed by every FADT field the parser reads.
        let header = unsafe { &*(table.as_ptr() as *const SdtHeader) };
        let fadt = Fadt::parse(header).unwrap();

        assert_eq!(fadt.dsdt_address.as_u64(), 0x0000_0000_1234_5000);
        assert_eq!(fadt.reset_reg.address, 0x0cf9);
        assert_eq!(fadt.reset_value, 0x06);
        assert_eq!(fadt.pm1a_evt_gas.address, 0x0440);
        assert_eq!(fadt.pm1a_cnt_gas.address, 0x0444);
    }

    /// `pick_gas` prefers an extended GAS with a non-zero address over the
    /// legacy port, and otherwise wraps the legacy port in a SystemIo GAS.
    #[test]
    fn pick_gas_prefers_extended() {
        let ext = GenericAddress {
            space: AddressSpace::SystemMemory,
            bit_width: 32,
            bit_offset: 0,
            access_size: 4,
            address: 0xFED0_3000,
        };
        let g = pick_gas(ext, 0x604, 16);
        assert_eq!(g.address, 0xFED0_3000);
        assert_eq!(g.space, AddressSpace::SystemMemory);
    }

    /// With no extended address and a non-zero legacy port, the result is a
    /// SystemIo GAS at that port with the requested bit width.
    #[test]
    fn pick_gas_wraps_legacy_port() {
        let g = pick_gas(zero_gas(), 0x604, 16);
        assert_eq!(g.space, AddressSpace::SystemIo);
        assert_eq!(g.address, 0x604);
        assert_eq!(g.bit_width, 16);
        assert_eq!(g.access_size, 0);
    }

    /// Both extended and legacy zero yields a zero-address GAS — the sentinel
    /// the shutdown path reads as "no PM1b block".
    #[test]
    fn pick_gas_zero_when_absent() {
        let g = pick_gas(zero_gas(), 0, 16);
        assert_eq!(g.address, 0);
        assert_eq!(g.space, AddressSpace::Unknown);
    }
}
