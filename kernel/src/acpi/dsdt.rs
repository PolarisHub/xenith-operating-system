//! DSDT (Differentiated System Description Table) discovery and AML body.
//!
//! The DSDT is the largest ACPI table: a blob of AML (ACPI Machine Language)
//! bytecode that declaratively describes the platform's devices, power
//! resources, thermal zones, and sleep-state packaging. Xenith evaluates the
//! discovery-oriented subset with explicit resource and execution bounds;
//! unsupported opcodes fail deterministically without disabling static ACPI.
//!
//! This module validates and locates the DSDT, then exposes its definition
//! block through [`aml_bytes`] for the bounded [`super::aml`] interpreter.
//!
//! # Where the DSDT pointer comes from
//!
//! The DSDT is not listed in the XSDT/RSDT directly. Instead the FADT
//! carries its address: a 32-bit `DSDT` field at offset 40 (ACPI 1.0) and a
//! 64-bit `X_DSDT` field at offset 142 (ACPI 2.0+). [`Fadt::parse`] resolves
//! the two into a single [`PhysAddr`] (preferring the extended field when
//! non-zero) and stores it as [`Fadt::dsdt_address`]. This module reads that
//! field back through [`super::fadt`].
//!
//! [`Fadt::parse`]: super::fadt::Fadt::parse
//! [`Fadt::dsdt_address`]: super::fadt::Fadt::dsdt_address

use xenith_types::PhysAddr;

use super::fadt::Fadt;
use super::xsdt::SdtHeader;

/// Locate the DSDT and return its physical address, plus a validated
/// `&'static` reference to its header.
///
/// Reads the DSDT pointer from the FADT (the [`Fadt::dsdt_address`] field,
/// which already preferred the 64-bit `X_DSDT` over the legacy 32-bit
/// `DSDT`), validates the DSDT's own SDT header (signature `"DSDT"` + checksum),
/// and returns both the address and the header reference so a caller can
/// confirm the table is present and well-formed without re-parsing the FADT.
///
/// Returns `None` when ACPI init has not installed a FADT, when the FADT's
/// DSDT pointer is zero, or when the DSDT header fails validation. In every
/// `None` case the caller (today only the boot log) treats the DSDT as
/// absent; a future AML interpreter will simply not run.
pub fn dsdt_address() -> Option<(PhysAddr, &'static SdtHeader)> {
    let fadt: &Fadt = super::fadt()?;
    let phys = fadt.dsdt_address;
    if phys.as_u64() == 0 {
        return None;
    }
    // Validate the DSDT's own header before handing it out. The DSDT is
    // pointed at by the FADT rather than listed in the XSDT, so it was not
    // checksummed during the root table walk — do it here.
    let (hdr, _len) = super::xsdt::validate_table_for_sig(phys, b"DSDT").ok()?;
    Some((phys, hdr))
}

/// The DSDT's physical address alone, for callers that only need to know
/// where the table lives (e.g. a boot-time log line) and not its header.
///
/// Equivalent to `dsdt_address().map(|(p, _)| p)` but without the redundant
/// header validation when the caller does not need the header.
#[inline]
pub fn dsdt_phys() -> Option<PhysAddr> {
    super::fadt()
        .map(|f| f.dsdt_address)
        .filter(|p| p.as_u64() != 0)
}

/// Return the AML definition block that follows the validated DSDT header.
///
/// The slice borrows firmware-reserved HHDM memory and therefore remains
/// valid for the kernel lifetime. Header validation bounds the slice to the
/// table's declared length before it is constructed.
pub fn aml_bytes() -> Option<&'static [u8]> {
    let (_, header) = dsdt_address()?;
    let header_len = core::mem::size_of::<SdtHeader>();
    let total = usize::try_from(header.length).ok()?;
    if total < header_len {
        return None;
    }
    let start = (header as *const SdtHeader as *const u8).wrapping_add(header_len);
    // SAFETY: `dsdt_address` validated the full table checksum and length;
    // firmware-reserved ACPI memory remains HHDM-mapped for the whole boot.
    Some(unsafe { core::slice::from_raw_parts(start, total - header_len) })
}
