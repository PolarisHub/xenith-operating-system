//! XSDT (Extended System Description Table) — the ACPI 2.0+ table directory.
//!
//! The XSDT is the root directory of every other ACPI table on an ACPI 2.0+
//! system: a 36-byte common header followed by an array of 64-bit *physical*
//! addresses, each pointing at a System Description Table (FADT, MADT, HPET,
//! DSDT, SSDT, ...). Walking it and dispatching the tables Xenith cares about
//! is the core of ACPI bring-up.
//!
//! On ACPI 1.0 the equivalent structure is the RSDT, whose entry array is
//! 32-bit addresses. [`Tables::from_rsdp`] picks the right one based on the
//! RSDP revision and routes both through the same dispatch logic, so the
//! per-table parsers ([`super::fadt`], [`super::madt`]) do not care which
//! root table listed them.
//!
//! # The [`Tables`] value
//!
//! [`Tables`] is a small `Copy` aggregate of `&'static` references to the
//! parsed tables. The references are `'static` because the underlying
//! firmware memory is HHDM-mapped and lives for the kernel's whole lifetime,
//! and the parsed-by-value structures ([`Fadt`], [`Madt`]) are leaked into
//! `'static` storage at parse time. Storing `Copy` references keeps the
//! helpers in [`super`] lock-free after boot.
//!
//! # Safety
//!
//! Every table address is validated (signature + checksum + length sanity)
//! before its header is trusted. The `&'static SdtHeader` references are
//! formed by casting HHDM pointers: this is sound because Limine maps the
//! full physical space at the HHDM base for the kernel's entire lifetime and
//! the firmware table region is never reclaimed or moved.

use core::fmt;

use xenith_types::PhysAddr;

use super::fadt::Fadt;
use super::madt::{Madt, MadtIoApicEntry, MadtLapicEntry};
use super::phys_to_virt;
use super::rsdp::Rsdp;
use super::shutdown::FadtPowerInfo;

/// The ACPI common System Description Table header (ACPI §5.2.6).
///
/// Every ACPI table — FADT, MADT, HPET, DSDT, SSDT, MCFG, ... — begins with
/// these 36 bytes. `signature` identifies the table type ("FACP" = FADT,
/// "APIC" = MADT, "HPET" = HPET), `length` is the total table length
/// including this header, and `checksum` is the byte that makes the whole
/// table sum to zero mod 256.
///
/// The layout is `#[repr(C, packed)]` because ACPI tables have no padding:
/// every field is at its natural offset and the structure is exactly 36
/// bytes. We never take a reference to a packed field directly; field
/// access goes through the [`SdtHeader::read_*`] helpers which copy bytes
/// out through `read_volatile`.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SdtHeader {
    /// Four-byte ASCII signature, e.g. `b"FACP"`.
    pub signature: [u8; 4],
    /// Total table length in bytes, including this header.
    pub length: u32,
    /// ACPI revision of this table.
    pub revision: u8,
    /// Checksum byte: the whole table sums to zero mod 256 when valid.
    pub checksum: u8,
    /// 6-byte OEM identifier.
    pub oem_id: [u8; 6],
    /// 8-byte OEM table identifier.
    pub oem_table_id: [u8; 8],
    /// OEM-specific revision.
    pub oem_revision: u32,
    /// Vendor ID of the tool that created this table.
    pub creator_id: u32,
    /// Revision of the tool that created this table.
    pub creator_revision: u32,
}

/// Byte size of the ACPI common System Description Table header.
pub(crate) const SDT_HEADER_LEN: usize = core::mem::size_of::<SdtHeader>();

/// Maximum number of validated SSDT definition blocks retained at boot.
const MAX_SSDTS: usize = 32;

/// The validated, parsed ACPI table set installed once at boot.
///
/// `Copy` so the helpers in [`super`] can hand out copies of the reference
/// set without borrowing the [`spin::Once`] that owns the canonical copy.
/// Every field is either a `&'static` reference into HHDM-mapped firmware
/// memory or a small `Copy` value, so the whole struct is `Copy`.
#[derive(Clone, Copy)]
pub struct Tables {
    /// The FADT, if present. Leaked into `'static` storage by [`Fadt::parse`].
    fadt: Option<&'static Fadt>,
    /// The MADT, if present. Leaked into `'static` storage by [`Madt::parse`].
    madt: Option<&'static Madt>,
    /// The HPET MMIO physical base, masked to a clean address, if an HPET
    /// table is present and valid.
    hpet: Option<PhysAddr>,
    /// The parsed LAPIC entries from the MADT. Empty slice when no MADT.
    lapics: &'static [MadtLapicEntry],
    /// The parsed IOAPIC entries from the MADT. Empty slice when no MADT.
    ioapics: &'static [MadtIoApicEntry],
    /// Validated secondary AML definition blocks in firmware load order.
    ssdts: [Option<&'static SdtHeader>; MAX_SSDTS],
    ssdt_count: usize,
}

/// An empty `'static` slice usable as the pre-init default for [`Tables`]
/// fields, avoiding a `None`-vs-empty distinction the helpers do not want.
const EMPTY_LAPICS: &[MadtLapicEntry] = &[];
const EMPTY_IOAPICS: &[MadtIoApicEntry] = &[];

/// Errors raised by the table walk.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AcpiError {
    /// The root table (XSDT or RSDT) failed signature or checksum
    /// validation. Without a valid root the table tree cannot be walked.
    BadRootTable,
    /// The root table's `Length` was smaller than its header or otherwise
    /// inconsistent with the number of entries it claims.
    BadRootLength,
    /// A table address in the root array was zero or pointed outside the
    /// physical address space. Skipped rather than fatal, but reported.
    BadEntryAddress,
}

impl fmt::Display for AcpiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRootTable => f.write_str("root table validation failed"),
            Self::BadRootLength => f.write_str("root table length inconsistent"),
            Self::BadEntryAddress => f.write_str("bad table entry address"),
        }
    }
}

// ---------------------------------------------------------------------------
// SDT header access and validation
// ---------------------------------------------------------------------------

/// Read a 36-byte SDT header from `phys` into a stack value.
///
/// # Safety
/// `phys` must point at 36 bytes of HHDM-mapped physical memory. Callers
/// validate the table length before trusting fields past the header.
unsafe fn read_header(phys: PhysAddr) -> SdtHeader {
    let mut buf = [0u8; SDT_HEADER_LEN];
    let base = phys_to_virt(phys);
    for (i, slot) in buf.iter_mut().enumerate() {
        // SAFETY: caller guaranteed 36 bytes of HHDM-mapped memory at phys.
        *slot = unsafe { core::ptr::read_volatile(base.add(i)) };
    }
    decode_header(&buf)
}

fn decode_header(buf: &[u8; SDT_HEADER_LEN]) -> SdtHeader {
    SdtHeader {
        signature: buf[0..4].try_into().expect("4-byte slice"),
        length: u32::from_le_bytes(buf[4..8].try_into().expect("4-byte slice")),
        revision: buf[8],
        checksum: buf[9],
        oem_id: buf[10..16].try_into().expect("6-byte slice"),
        oem_table_id: buf[16..24].try_into().expect("8-byte slice"),
        oem_revision: u32::from_le_bytes(buf[24..28].try_into().expect("4-byte slice")),
        creator_id: u32::from_le_bytes(buf[28..32].try_into().expect("4-byte slice")),
        creator_revision: u32::from_le_bytes(buf[32..36].try_into().expect("4-byte slice")),
    }
}

/// Validate a table's checksum by summing every byte of its declared length.
///
/// Returns the validated [`SdtHeader`] and the raw physical address on
/// success. The header is read eagerly (36 bytes) and the rest of the table
/// is checksummed byte-by-byte through the HHDM pointer. We cap the length
/// at 1 MiB so a corrupt `length` field cannot drive a pathological scan;
/// every ACPI table Xenith consumes is well under that.
///
/// # Safety
/// The returned `&'static SdtHeader` borrows HHDM-mapped firmware memory
/// that is stable for the kernel's entire lifetime, so the `'static`
/// lifetime is sound.
pub(crate) fn validate_table(phys: PhysAddr) -> Result<(&'static SdtHeader, u32), AcpiError> {
    if phys.as_u64() == 0 {
        return Err(AcpiError::BadEntryAddress);
    }
    // SAFETY: `phys` is a table address from the root array; it points at
    // HHDM-mapped firmware memory with at least a 36-byte header.
    let header = unsafe { read_header(phys) };
    let len = header.length;
    if !(SDT_HEADER_LEN as u32..=0x10_0000).contains(&len) {
        return Err(AcpiError::BadRootLength);
    }

    // Sum the whole table. Reading through the HHDM pointer a byte at a time
    // keeps the access volatile and avoids materialising a large stack copy.
    let base = phys_to_virt(phys);
    let mut sum: u8 = 0;
    for i in 0..len as usize {
        // SAFETY: `i` is in `[0, len)` and the table is `len` bytes of
        // HHDM-mapped firmware memory starting at `phys`.
        sum = sum.wrapping_add(unsafe { core::ptr::read_volatile(base.add(i)) });
    }
    if sum != 0 {
        return Err(AcpiError::BadRootTable);
    }

    // SAFETY: `base` is the HHDM mapping of a firmware table that Limine
    // guarantees stays mapped and in place for the kernel's lifetime. The
    // table is never reclaimed, so the borrow is valid for `'static`.
    let header_ref: &'static SdtHeader = unsafe {
        (base as *const SdtHeader)
            .as_ref()
            .expect("non-null HHDM pointer")
    };
    Ok((header_ref, len))
}

impl SdtHeader {
    /// Compare the 4-byte leading signature (the rest is NUL padding) to
    /// `sig`. Convenience wrapper so callers write `header.is(b"FACP")`
    /// instead of slicing a packed field.
    #[inline]
    pub fn is(&self, sig: &[u8; 4]) -> bool {
        self.signature == *sig
    }

    /// Return the validated definition-block bytes following this header.
    fn aml_body(&'static self) -> Option<&'static [u8]> {
        let total = usize::try_from(self.length).ok()?;
        let body_len = total.checked_sub(SDT_HEADER_LEN)?;
        let start = (self as *const Self as *const u8).wrapping_add(SDT_HEADER_LEN);
        // SAFETY: the root-table walk validated the complete table length
        // and checksum, and firmware-reserved ACPI storage remains mapped.
        Some(unsafe { core::slice::from_raw_parts(start, body_len) })
    }
}

/// Validate a table reached outside the root-table walk and check its
/// signature.
///
/// The DSDT is reached through the FADT rather than the XSDT/RSDT, so the
/// root walk in [`Tables::from_rsdp`] never checksums it. This function is the
/// public entry point a parent-table parser uses to validate such a child:
/// it runs the same signature + checksum + length-sanity pass as
/// [`validate_table`] and additionally requires the leading signature to
/// match `sig`, so a caller cannot accidentally accept another table or a
/// corrupt blob.
pub fn validate_table_for_sig(
    phys: PhysAddr,
    sig: &[u8; 4],
) -> Result<(&'static SdtHeader, u32), AcpiError> {
    let (hdr, len) = validate_table(phys)?;
    if !hdr.is(sig) {
        return Err(AcpiError::BadRootTable);
    }
    Ok((hdr, len))
}

// ---------------------------------------------------------------------------
// Table walk
// ---------------------------------------------------------------------------

impl Tables {
    /// Build the parsed table set from a validated [`Rsdp`].
    ///
    /// Walks the XSDT (ACPI 2.0+) or RSDT (ACPI 1.0) the RSDP points at,
    /// validates each entry's header, and dispatches the tables Xenith
    /// consumes: the FADT (`"FACP"`), MADT (`"APIC"`), HPET (`"HPET"`),
    /// and up to [`MAX_SSDTS`] secondary AML tables. The FADT parser also publishes the PM1/reset power info
    /// through [`super::shutdown::register_power_info`] as a side effect, so
    /// the shutdown path is wired up the moment a valid FADT is found.
    pub fn from_rsdp(rsdp: &Rsdp) -> Result<Tables, AcpiError> {
        // Collect the (signature, physical address, length) of every
        // validated entry, then dispatch the ones we care about by
        // signature. Collecting first keeps the dispatch loop signature-
        // keyed and independent of which root table supplied the address.
        let mut fadt: Option<&'static Fadt> = None;
        let mut madt: Option<&'static Madt> = None;
        let mut hpet: Option<PhysAddr> = None;
        let mut ssdts = [None; MAX_SSDTS];
        let mut ssdt_count = 0usize;

        if rsdp.has_xsdt() {
            walk_xsdt(PhysAddr::new_truncate(rsdp.xsdt_address), |hdr, _phys| {
                dispatch(
                    hdr,
                    &mut fadt,
                    &mut madt,
                    &mut hpet,
                    &mut ssdts,
                    &mut ssdt_count,
                );
            })?;
        } else {
            walk_rsdt(
                PhysAddr::new_truncate(u64::from(rsdp.rsdt_address)),
                |hdr, _phys| {
                    dispatch(
                        hdr,
                        &mut fadt,
                        &mut madt,
                        &mut hpet,
                        &mut ssdts,
                        &mut ssdt_count,
                    );
                },
            )?;
        }

        // Materialise the LAPIC/IOAPIC slices from the parsed MADT, if any.
        // The slices are leaked into `'static` storage so [`Tables`] stays
        // `Copy` and the helpers can hand out `&'static [T]` lock-free.
        let (lapics, ioapics) = match madt {
            Some(m) => (m.lapics(), m.ioapics()),
            None => (EMPTY_LAPICS, EMPTY_IOAPICS),
        };

        Ok(Tables {
            fadt,
            madt,
            hpet,
            lapics,
            ioapics,
            ssdts,
            ssdt_count,
        })
    }

    /// The parsed FADT, if present.
    #[inline]
    pub fn fadt(&self) -> Option<&'static Fadt> {
        self.fadt
    }

    /// The parsed MADT, if present.
    #[inline]
    pub fn madt(&self) -> Option<&'static Madt> {
        self.madt
    }

    /// The HPET's physical MMIO base, low 3 bits masked.
    #[inline]
    pub fn hpet_address(&self) -> Option<PhysAddr> {
        self.hpet
    }

    /// The MADT's LAPIC entries. Empty when no MADT was found.
    #[inline]
    pub fn madt_lapics(&self) -> &'static [MadtLapicEntry] {
        self.lapics
    }

    /// The MADT's IOAPIC entries. Empty when no MADT was found.
    #[inline]
    pub fn madt_ioapics(&self) -> &'static [MadtIoApicEntry] {
        self.ioapics
    }

    /// Validated SSDT AML bodies, in firmware load order.
    pub fn ssdt_aml_blocks(&self) -> impl Iterator<Item = &'static [u8]> + '_ {
        self.ssdts[..self.ssdt_count]
            .iter()
            .filter_map(|header| header.and_then(SdtHeader::aml_body))
    }

    #[must_use]
    pub const fn ssdt_count(&self) -> usize {
        self.ssdt_count
    }
}

/// Dispatch one validated table to the right parser based on its signature.
///
/// `fadt`/`madt`/`hpet` are taken by `&mut` so this closure-style helper can
/// be shared between the XSDT and RSDT walks without a per-walk copy of the
/// dispatch logic. Unknown signatures are silently skipped — ACPI tables
/// Xenith does not consume (MCFG, BGRT, ...) remain in memory for a
/// future interpreter but are not parsed here.
fn dispatch(
    hdr: &'static SdtHeader,
    fadt: &mut Option<&'static Fadt>,
    madt: &mut Option<&'static Madt>,
    hpet: &mut Option<PhysAddr>,
    ssdts: &mut [Option<&'static SdtHeader>; MAX_SSDTS],
    ssdt_count: &mut usize,
) {
    if hdr.is(b"FACP") {
        match Fadt::parse(hdr) {
            Ok(f) => {
                // Publish the power-relevant subset to the shutdown path.
                // This side effect is what wires `acpi_shutdown`/`acpi_reset`
                // up the moment a valid FADT is found, without the root
                // [`super::init`] needing to know about PM1 registers.
                register_fadt_power(f);
                *fadt = Some(f);
            },
            Err(e) => ::log::warn!("xenith.acpi: FADT parse failed ({}); skipped", e),
        }
    } else if hdr.is(b"APIC") {
        match Madt::parse(hdr) {
            Ok(m) => *madt = Some(m),
            Err(e) => ::log::warn!("xenith.acpi: MADT parse failed ({}); skipped", e),
        }
    } else if hdr.is(b"HPET") {
        match parse_hpet_address(hdr) {
            Ok(a) => *hpet = Some(a),
            Err(e) => ::log::warn!("xenith.acpi: HPET parse failed ({}); skipped", e),
        }
    } else if hdr.is(b"SSDT") {
        if let Some(slot) = ssdts.get_mut(*ssdt_count) {
            *slot = Some(hdr);
            *ssdt_count += 1;
        } else {
            ::log::warn!(
                "xenith.acpi: more than {} SSDTs; remaining blocks skipped",
                MAX_SSDTS
            );
        }
    }
}

/// Extract the HPET MMIO base from an HPET table.
///
/// The HPET table's base address is a Generic Address Structure at offset
/// 40: a 1-byte address-space ID, three 1-byte shape fields, and an 8-byte
/// address at offset 44. On x86_64 the space is always system memory and the
/// address is page-aligned (e.g. `0xFED0_0000`); we mask the low 3 bits so a
/// sub-byte `bit_offset` never leaks into the returned physical address.
fn parse_hpet_address(hdr: &'static SdtHeader) -> Result<PhysAddr, AcpiError> {
    let len = hdr.length;
    // GAS `Address` field is at offset 44; the table must be at least
    // 44 + 8 = 52 bytes long to contain it.
    if len < 52 {
        return Err(AcpiError::BadRootLength);
    }
    // `hdr` is a reference to the table's very first bytes (the SDT header
    // IS the table prefix), so the GAS `Address` field is 44 bytes past the
    // header pointer. We read 8 volatile bytes from that offset.
    let addr_ptr = (hdr as *const SdtHeader as *const u8).wrapping_add(44);
    let mut buf = [0u8; 8];
    for (i, slot) in buf.iter_mut().enumerate() {
        // SAFETY: `addr_ptr + i` is within the validated table body (offset
        // 44..52 < `len`), HHDM-mapped firmware memory.
        *slot = unsafe { core::ptr::read_volatile(addr_ptr.add(i)) };
    }
    let raw = u64::from_le_bytes(buf) & !0b111u64;
    if raw == 0 {
        return Err(AcpiError::BadEntryAddress);
    }
    Ok(PhysAddr::new_truncate(raw))
}

/// Publish the FADT's power-relevant subset to the shutdown subsystem.
///
/// Translates the parsed [`Fadt`] into a [`FadtPowerInfo`] and registers it
/// via [`super::shutdown::register_power_info`]. The bounded AML evaluator is
/// not yet wired to publish `\_S5` package values into this record, so the
/// QEMU/PIIX default of `0` remains an explicit fallback and a benign no-op on
/// platforms that use another encoding.
fn register_fadt_power(fadt: &'static Fadt) {
    let info = FadtPowerInfo {
        pm1a_evt: fadt.pm1a_evt_gas,
        pm1b_evt: fadt.pm1b_evt_gas,
        pm1a_cnt: fadt.pm1a_cnt_gas,
        pm1b_cnt: fadt.pm1b_cnt_gas,
        reset_reg: fadt.reset_reg,
        reset_value: fadt.reset_value,
        s5_slp_typa: 0,
        s5_slp_typb: 0,
        pm1b_present: fadt.pm1b_present,
        hhdm_offset: super::HHDM_BASE,
    };
    super::shutdown::register_power_info(info);
}

// ---------------------------------------------------------------------------
// Root table walkers
// ---------------------------------------------------------------------------

/// Walk an XSDT: a 36-byte header followed by `n` 64-bit *physical* entry
/// addresses, where `n = (length - 36) / 8`. Each entry is validated and
/// handed to `emit` as a `&'static SdtHeader`.
fn walk_xsdt<F>(phys: PhysAddr, mut emit: F) -> Result<(), AcpiError>
where
    F: FnMut(&'static SdtHeader, PhysAddr),
{
    let (root, len) = validate_table(phys)?;
    if !root.is(b"XSDT") {
        ::log::warn!("xenith.acpi: root table signature != XSDT");
        return Err(AcpiError::BadRootTable);
    }
    let header_len = SDT_HEADER_LEN as u32;
    if len < header_len || !(len - header_len).is_multiple_of(8) {
        return Err(AcpiError::BadRootLength);
    }
    let n = ((len - header_len) / 8) as usize;
    let base = phys_to_virt(phys);
    for i in 0..n {
        let mut buf = [0u8; 8];
        let p = base.wrapping_add(SDT_HEADER_LEN + i * 8);
        for (j, slot) in buf.iter_mut().enumerate() {
            // SAFETY: this entry byte is within the validated root body.
            *slot = unsafe { core::ptr::read_volatile(p.wrapping_add(j)) };
        }
        let entry = u64::from_le_bytes(buf);
        if entry == 0 {
            continue;
        }
        let ep = PhysAddr::new_truncate(entry);
        match validate_table(ep) {
            Ok((hdr, _)) => emit(hdr, ep),
            Err(e) => {
                ::log::debug!("xenith.acpi: XSDT entry {} skipped ({})", i, e);
            },
        }
    }
    Ok(())
}

/// Walk an RSDT: a 36-byte header followed by `n` 32-bit *physical* entry
/// addresses, where `n = (length - 36) / 4`. Delegates the 32-bit-vs-64-bit
/// difference to [`super::rsdt`], which exists precisely to keep this
/// function from re-implementing the stride arithmetic.
fn walk_rsdt<F>(phys: PhysAddr, emit: F) -> Result<(), AcpiError>
where
    F: FnMut(&'static SdtHeader, PhysAddr),
{
    let (root, len) = validate_table(phys)?;
    if !root.is(b"RSDT") {
        ::log::warn!("xenith.acpi: root table signature != RSDT");
        return Err(AcpiError::BadRootTable);
    }
    super::rsdt::walk_entries(phys, len, emit)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{decode_header, parse_hpet_address, SdtHeader, SDT_HEADER_LEN};
    use crate::mm::allocator::Box;

    /// `SdtHeader` is exactly 36 bytes — the ACPI common header size. Any
    /// The common header is 36 bytes; another size would mis-parse every table.
    #[test]
    fn sdt_header_size() {
        assert_eq!(core::mem::size_of::<SdtHeader>(), 36);
    }

    /// `is` compares the exact four-byte ACPI signature; there is no padding.
    /// The signature field contains exactly four bytes.
    #[test]
    fn is_matches_leading_four() {
        let h = SdtHeader {
            signature: *b"FACP",
            length: 36,
            revision: 4,
            checksum: 0,
            oem_id: [0; 6],
            oem_table_id: [0; 8],
            oem_revision: 0,
            creator_id: 0,
            creator_revision: 0,
        };
        assert!(h.is(b"FACP"));
        assert!(!h.is(b"APIC"));
    }

    #[test]
    fn decodes_spec_header_offsets() {
        let mut bytes = [0u8; SDT_HEADER_LEN];
        bytes[0..4].copy_from_slice(b"SSDT");
        bytes[4..8].copy_from_slice(&0x1234u32.to_le_bytes());
        bytes[8] = 2;
        bytes[9] = 0x5a;
        bytes[10..16].copy_from_slice(b"XENITH");
        bytes[16..24].copy_from_slice(b"AMLTEST0");
        bytes[24..28].copy_from_slice(&7u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&0x5445_5354u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&9u32.to_le_bytes());
        let header = decode_header(&bytes);
        let length = header.length;
        let oem_revision = header.oem_revision;
        let creator_id = header.creator_id;
        let creator_revision = header.creator_revision;
        assert_eq!(header.signature, *b"SSDT");
        assert_eq!(length, 0x1234);
        assert_eq!(header.revision, 2);
        assert_eq!(header.checksum, 0x5a);
        assert_eq!(header.oem_id, *b"XENITH");
        assert_eq!(header.oem_table_id, *b"AMLTEST0");
        assert_eq!(oem_revision, 7);
        assert_eq!(creator_id, 0x5445_5354);
        assert_eq!(creator_revision, 9);
    }

    #[test]
    fn hpet_address_uses_spec_gas_offset() {
        let mut table = Box::new([0u8; 52]);
        table[4..8].copy_from_slice(&52u32.to_le_bytes());
        table[44..52].copy_from_slice(&0xfed0_0000u64.to_le_bytes());
        let table = Box::leak(table);
        // SAFETY: the leaked byte array is at least one packed header long.
        let header = unsafe { &*(table.as_ptr() as *const SdtHeader) };
        assert_eq!(parse_hpet_address(header).unwrap().as_u64(), 0xfed0_0000);
    }
}
