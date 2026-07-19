//! RSDT (Root System Description Table) — the ACPI 1.0 table directory.
//!
//! The RSDT is the ACPI 1.0 predecessor of the XSDT: the same 36-byte common
//! header followed by an array of *32-bit* physical entry addresses, one per
//! child table. ACPI 2.0+ systems provide an XSDT (64-bit entries) instead,
//! and the RSDP's revision field tells [`super::xsdt::Tables::from_rsdp`]
//! which one to walk. This module owns only the 32-bit-stride difference; the
//! dispatch, validation, and per-table parsing are shared with the XSDT path
//! in [`super::xsdt`].
//!
//! # Why a separate module
//!
//! The XSDT and RSDT differ only in entry width (8 vs 4 bytes) and signature
//! (`"XSDT"` vs `"RSDT"`). Splitting the 32-bit walk into its own module
//! keeps the XSDT code free of `cfg`/revision branching and gives ACPI 1.0
//! hardware (and the occasional 1.0-shaped QEMU image) a clearly-named home.
//! The two walks share [`super::xsdt::validate_table`], so the checksum and
//! length-sanity logic is not duplicated.
//!
//! # Safety
//!
//! Same contract as the XSDT walker: every entry address is validated before
//! its header is trusted, and `&'static SdtHeader` references are formed
//! from HHDM-mapped firmware memory that is stable for the kernel's lifetime.

use xenith_types::PhysAddr;

use super::phys_to_virt;
use super::xsdt::{validate_table, AcpiError, SdtHeader, SDT_HEADER_LEN};

/// Walk an RSDT's 32-bit entry array.
///
/// `phys` is the RSDT's physical address and `len` is its validated total
/// length (already confirmed `>= 36` by the caller). For each non-zero
/// 32-bit entry, the entry's table is validated and `emit` is called with
/// the resulting `&'static SdtHeader` and the entry's physical address.
/// Zero entries and entries that fail validation are skipped with a
/// `debug!` log line rather than aborting the walk — a single bad entry
/// must not prevent discovery of the FADT and MADT.
pub fn walk_entries<F>(phys: PhysAddr, len: u32, mut emit: F) -> Result<(), AcpiError>
where
    F: FnMut(&'static SdtHeader, PhysAddr),
{
    // The entry array starts after the 36-byte common header and each entry
    // is 4 bytes. Any other stride means the table is
    // corrupt; refuse rather than mis-stride.
    let header_len = SDT_HEADER_LEN as u32;
    if len < header_len || !(len - header_len).is_multiple_of(4) {
        return Err(AcpiError::BadRootLength);
    }
    let n = ((len - header_len) / 4) as usize;
    let base = phys_to_virt(phys);

    for i in 0..n {
        let mut buf = [0u8; 4];
        let p = base.wrapping_add(SDT_HEADER_LEN + i * 4);
        for (j, slot) in buf.iter_mut().enumerate() {
            // SAFETY: this entry byte is within `[0, len)`, and the
            // root table is HHDM-mapped firmware memory of `len` bytes.
            *slot = unsafe { core::ptr::read_volatile(p.wrapping_add(j)) };
        }
        let entry = u32::from_le_bytes(buf);
        if entry == 0 {
            continue;
        }
        // RSDT entries are 32-bit physical addresses. Zero-extend to 64-bit
        // for the shared validate_table path; ACPI 1.0 tables always live
        // below 4 GiB so no information is lost.
        let ep = PhysAddr::new_truncate(u64::from(entry));
        match validate_table(ep) {
            Ok((hdr, _)) => emit(hdr, ep),
            Err(e) => {
                ::log::debug!("xenith.acpi: RSDT entry {} skipped ({})", i, e);
            },
        }
    }

    Ok(())
}
