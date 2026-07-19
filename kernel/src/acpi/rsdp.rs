//! Root System Description Pointer (RSDP) — ACPI table discovery entry point.
//!
//! The RSDP is the root of the ACPI table tree: a small structure the firmware
//! leaves in low memory whose only job is to point at the RSDT or XSDT, which
//! in turn lists every other ACPI table. On a BIOS system the firmware
//! places it somewhere in the `0xE_0000`–`0xF_FFFF` ROM shadow or in the EBDA
//! (Extended BIOS Data Area); on UEFI it is handed to the OS through the EFI
//! system configuration table. Limine finds it by whichever mechanism the
//! firmware provides and reports the physical address through
//! [`xenith_boot::BootInfo::rsdp`].
//!
//! [`find_and_parse`] is the single entry point the rest of the ACPI
//! subsystem calls. It takes the RSDP physical address Limine reported (or
//! `PhysAddr::zero()` when Limine did not find one) and returns a validated,
//! parsed [`Rsdp`]. When the caller passes zero it falls back to a manual
//! BIOS-style scan of the EBDA and the ROM shadow — this is the path that
//! lets Xenith come up on a legacy BIOS image that Limine booted without an
//! RSDP tag, and it costs nothing when Limine already gave us the address.
//!
//! # Two revisions, one structure
//!
//! ACPI 1.0 RSDPs are 20 bytes: a signature, a one-byte checksum, a
//! revision (`0`), an OEM id, and a 32-bit `RsdtAddress`. ACPI 2.0+ extends
//! the structure to 36 bytes: the revision is `>= 2`, a `Length` field
//! (covering the whole structure) is added, a 64-bit `XsdtAddress` replaces
//! the 32-bit field, and an `ExtendedChecksum` covers the extra bytes. The
//! ACPI 1.0 checksum still validates the first 20 bytes; the extended
//! checksum validates the full structure. We honour both so a malformed
//! extended region on a 2.0 RSDP is caught even when the legacy checksum
//! passes.
//!
//! # Safety
//!
//! The RSDP lives in firmware-reserved memory that Limine mapped through the
//! HHDM direct map. All reads are `read_volatile` from HHDM-translated
//! pointers, the signature is checked before any field is trusted, and both
//! checksums are validated before the structure is considered parsed. The
//! returned [`Rsdp`] is a plain value copy of the validated fields, so it
//! carries no lifetime and is safe to hold across the table walk.

use core::convert::TryInto;
use core::fmt;

use xenith_types::PhysAddr;

use super::phys_to_virt;

/// The RSDP signature: 8 bytes, "RSD PTR " (note the trailing blank).
///
/// ACPI §5.2.5.3 mandates this exact byte sequence at offset 0 of every
/// RSDP. The trailing space is part of the signature — a common bug is to
/// compare against `b"RSD_PTR"` (7 bytes) and silently fail to match.
const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";

/// The ACPI 1.0 RSDP length: the first 20 bytes are covered by the legacy
/// checksum. ACPI 2.0+ structures are longer (≥ 36 bytes) and add a second
/// checksum for the extended region.
const RSDP_V1_LEN: usize = 20;

/// The minimum ACPI 2.0+ RSDP length: 36 bytes. Revision `>= 2` implies at
/// least this many bytes; the `Length` field at offset 8 carries the true
/// total.
const RSDP_V2_MIN_LEN: usize = 36;

/// Bytes through the ACPI 2.0 `Length` field (offset 20, width 4).
const RSDP_V2_PREFIX_LEN: usize = 24;

/// The parsed Root System Description Pointer.
///
/// This is a value-type copy of the fields the table walk needs. It does not
/// borrow the firmware memory: [`find_and_parse`] validates the on-disk
/// structure and copies the load-bearing fields out, so the rest of ACPI
/// init never has to touch the raw bytes again.
#[derive(Clone, Copy, Debug)]
pub struct Rsdp {
    /// ACPI revision. `0` ⇒ ACPI 1.0 (use [`Rsdp::rsdt_address`]); `>= 2` ⇒
    /// ACPI 2.0+ (use [`Rsdp::xsdt_address`]).
    pub revision: u8,
    /// The 6-byte OEM identifier. ASCII, NUL-padded. Carried for diagnostics
    /// only; the table walk never reads it.
    pub oem_id: [u8; 6],
    /// 32-bit physical address of the RSDT. Always present; on ACPI 2.0+ it
    /// is typically a copy of (or alias to) the XSDT's low 32 bits and is
    /// used only as a fallback when [`xsdt_address`](Self::xsdt_address) is
    /// zero.
    pub rsdt_address: u32,
    /// 64-bit physical address of the XSDT. Zero on ACPI 1.0 RSDPs; the
    /// table walk prefers this when non-zero because the XSDT addresses
    /// 64-bit table locations the 32-bit RSDT field cannot reach.
    pub xsdt_address: u64,
    /// The total RSDP length in bytes, as reported by the `Length` field.
    /// `20` for ACPI 1.0 (where the field is absent and we substitute the
    /// constant), the real value for ACPI 2.0+.
    pub length: usize,
}

impl Rsdp {
    /// Which root table to walk: the XSDT when its address is non-zero
    /// (ACPI 2.0+), otherwise the RSDT (ACPI 1.0 fallback).
    ///
    /// Returns `true` for XSDT, `false` for RSDT. The caller
    /// ([`super::xsdt::Tables::from_rsdp`]) dispatches on this.
    #[inline]
    #[must_use]
    pub const fn has_xsdt(self) -> bool {
        self.xsdt_address != 0
    }
}

/// Errors raised by RSDP discovery and validation.
///
/// Hand-rolled per kernel convention (no `thiserror`/`std`). Each variant
/// names one distinct failure so the boot log can say exactly why ACPI was
/// disabled rather than a generic "bad table".
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RsdpError {
    /// Limine reported no RSDP and the BIOS-style scan found no signature.
    NotFound,
    /// A candidate signature did not match `b"RSD PTR "`. The byte sequence
    /// we actually saw is not carried — it is never useful to a human
    /// reading the log, and including it would bloat the enum.
    BadSignature,
    /// The ACPI 1.0 checksum (first 20 bytes) did not sum to zero. The
    /// structure is corrupt or we are looking at non-RSDP memory.
    BadChecksum,
    /// The ACPI 2.0+ extended checksum (full structure) did not sum to
    /// zero. The legacy region is valid but the extended fields cannot be
    /// trusted; we refuse rather than fall back to a partially-valid RSDP.
    BadExtendedChecksum,
    /// The `Length` field was smaller than the minimum for the claimed
    /// revision (e.g. revision 2 with length 24). The structure is
    /// malformed.
    BadLength,
}

impl fmt::Display for RsdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("RSDP not found"),
            Self::BadSignature => f.write_str("bad RSDP signature"),
            Self::BadChecksum => f.write_str("RSDP checksum failed"),
            Self::BadExtendedChecksum => f.write_str("RSDP extended checksum failed"),
            Self::BadLength => f.write_str("RSDP length inconsistent with revision"),
        }
    }
}

// ---------------------------------------------------------------------------
// Low-level reads from HHDM-translated physical memory
// ---------------------------------------------------------------------------

/// Read `n` bytes from `phys` into `out`, returning the slice.
///
/// Every byte is `read_volatile` so the compiler cannot elide or coalesce the
/// loads — ACPI tables live in MMIO-style firmware memory where access width
/// and ordering matter, even though in practice the table region is plain RAM
/// on every PC we support.
///
/// # Safety
///
/// `phys` must point at `n` bytes of physical memory that Limine mapped
/// through the HHDM direct map. Callers validate lengths against the table
/// header before reaching here, so the region is known to be in-bounds.
unsafe fn read_bytes(phys: PhysAddr, out: &mut [u8]) {
    let base = phys_to_virt(phys);
    for (i, slot) in out.iter_mut().enumerate() {
        // SAFETY: `base` is the HHDM virtual address of a firmware-reserved
        // physical region; `i` is in bounds of `out` and the caller guaranteed
        // the physical region is at least `out.len()` bytes. The volatile
        // read prevents the compiler from assuming the memory is unobservable.
        *slot = unsafe { core::ptr::read_volatile(base.add(i)) };
    }
}

/// Read a little-endian `u64` from `phys`.
///
/// # Safety
/// Same contract as [`read_bytes`] for an 8-byte region.
#[allow(dead_code)]
unsafe fn read_u64(phys: PhysAddr) -> u64 {
    let mut buf = [0u8; 8];
    unsafe { read_bytes(phys, &mut buf) };
    u64::from_le_bytes(buf)
}

/// Sum every byte in `buf`; ACPI checksums are valid when the sum mod 256 is
/// zero. This is the single primitive both the legacy and extended
/// checksums reduce to.
#[inline]
fn checksum_zero(buf: &[u8]) -> bool {
    // Wrapping add: the ACPI checksum is defined over the low 8 bits of the
    // one's-complement sum, so u8 wraparound is exactly the intended
    // arithmetic.
    let sum: u8 = buf.iter().copied().fold(0u8, |a, b| a.wrapping_add(b));
    sum == 0
}

fn extended_length(prefix: &[u8]) -> Option<usize> {
    let bytes: [u8; 4] = prefix.get(20..24)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes) as usize)
}

// ---------------------------------------------------------------------------
// BIOS-style scan fallback
// ---------------------------------------------------------------------------

/// The physical address of the EBDA segment pointer: a 16-bit segment value
/// at `0x40E` whose value × 16 is the linear EBDA base. Scanning the EBDA
/// first is cheap (typically 1 KiB) and finds the RSDP on most BIOS boxes
/// before the wider ROM scan is needed.
const EBDA_PTR_PHYS: u64 = 0x40E;

/// Scan the EBDA and the 0xE_0000–0xF_FFFF ROM shadow for an RSDP signature.
///
/// This is the legacy BIOS discovery path, used only when Limine did not
/// report an RSDP address. It walks the EBDA (one 4 KiB page starting at the
/// segment in `0x40E`) and then the 128 KiB ROM shadow in 16-byte strides —
/// the RSDP is always 16-byte aligned. Returns the first physical address
/// whose signature matches and whose legacy checksum validates, or `None`.
fn scan_for_rsdp() -> Option<PhysAddr> {
    // EBDA base = segment at 0x40E × 16, clamped to the low 1 MiB. A zero or
    // bogus segment means there is no EBDA; skip straight to the ROM scan.
    let ebda_seg = {
        let mut buf = [0u8; 2];
        // SAFETY: 0x40E is a 2-byte field in the BIOS data area, always
        // present and mapped through the HHDM in the low 1 MiB.
        unsafe { read_bytes(PhysAddr::new(EBDA_PTR_PHYS)?, &mut buf) };
        u16::from_le_bytes(buf)
    };
    if ebda_seg != 0 {
        let ebda_base = (ebda_seg as u64) << 4;
        if ebda_base < 0x10_0000 {
            if let Some(p) = scan_region(ebda_base, 0x400) {
                return Some(p);
            }
        }
    }
    // ROM shadow: 0xE_0000 ..= 0xF_FFFF, 16-byte stride. ACPI §5.2.5.1 says
    // the RSDP is 16-byte aligned in this region.
    scan_region(0xE_0000, 0x2_0000)
}

/// Scan `len` bytes from `base` in 16-byte strides for a valid RSDP.
fn scan_region(base: u64, len: u64) -> Option<PhysAddr> {
    let mut off = 0u64;
    while off + RSDP_V1_LEN as u64 <= len {
        let p = PhysAddr::new(base + off)?;
        let mut sig = [0u8; 8];
        // SAFETY: `p` is within the low-1MiB region we are scanning; the
        // HHDM maps the full physical space so the read is in-bounds.
        unsafe { read_bytes(p, &mut sig) };
        if sig == RSDP_SIGNATURE {
            // Validate the legacy checksum before claiming a hit: a stray
            // "RSD PTR " string in the ROM is useless if the structure is
            // not actually an RSDP.
            let mut head = [0u8; RSDP_V1_LEN];
            unsafe { read_bytes(p, &mut head) };
            if checksum_zero(&head) {
                return Some(p);
            }
        }
        off += 16;
    }
    None
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Locate and parse the RSDP.
///
/// When `rsdp_phys` is non-zero it is trusted as Limine's reported RSDP
/// address and validated directly. When it is zero the function falls back
/// to a BIOS-style EBDA/ROM scan. In both cases the signature and checksum
/// (legacy, plus extended for ACPI 2.0+) are verified before any field is
/// copied out.
///
/// The returned [`Rsdp`] is a value copy of the validated fields; it borrows
/// nothing, so it can outlive the firmware memory it was read from.
pub fn find_and_parse(rsdp_phys: PhysAddr) -> Result<Rsdp, RsdpError> {
    let phys = if rsdp_phys.as_u64() != 0 {
        rsdp_phys
    } else {
        ::log::debug!("xenith.acpi.rsdp: no Limine tag, scanning BIOS regions");
        scan_for_rsdp().ok_or(RsdpError::NotFound)?
    };

    // Read the fixed 20-byte head first: signature, checksum, revision,
    // OEM id, and the 32-bit RSDT address are all in this region regardless
    // of revision.
    let mut head = [0u8; RSDP_V1_LEN];
    // SAFETY: `phys` points at a real RSDP (either Limine-reported or
    // signature-matched in the scan), which is at least 20 bytes and is
    // HHDM-mapped firmware memory.
    unsafe { read_bytes(phys, &mut head) };

    if head[0..8] != RSDP_SIGNATURE {
        return Err(RsdpError::BadSignature);
    }
    if !checksum_zero(&head) {
        return Err(RsdpError::BadChecksum);
    }

    let revision = head[15];
    let oem_id: [u8; 6] = head[9..15].try_into().expect("6-byte slice");
    let rsdt_address = u32::from_le_bytes(head[16..20].try_into().expect("4-byte slice"));

    // ACPI 1.0: the structure is exactly the 20 bytes we already read.
    if revision < 2 {
        ::log::debug!(
            "xenith.acpi.rsdp: ACPI 1.0, RSDT @ phys:0x{:08x}",
            rsdt_address
        );
        return Ok(Rsdp {
            revision,
            oem_id,
            rsdt_address,
            xsdt_address: 0,
            length: RSDP_V1_LEN,
        });
    }

    // ACPI 2.0+: read the full extended structure and validate the second
    // checksum over the whole thing.
    let mut extended_prefix = [0u8; RSDP_V2_PREFIX_LEN];
    // SAFETY: revision >= 2 guarantees the RSDP includes the 24-byte prefix
    // through its Length field.
    unsafe { read_bytes(phys, &mut extended_prefix) };
    let length = extended_length(&extended_prefix).ok_or(RsdpError::BadLength)?;
    if length < RSDP_V2_MIN_LEN {
        return Err(RsdpError::BadLength);
    }

    // Read the entire structure into a stack buffer for the extended
    // checksum. Cap at a sane maximum (256 bytes) so a wildly corrupt
    // `Length` cannot drive a huge allocation or an out-of-bounds read.
    const MAX_RSDP_LEN: usize = 256;
    let len = length.min(MAX_RSDP_LEN);
    let mut buf = [0u8; MAX_RSDP_LEN];
    // SAFETY: `phys` is a valid RSDP and `len` ≤ the structure's claimed
    // length (and ≤ MAX_RSDP_LEN), so the read stays inside the table.
    unsafe { read_bytes(phys, &mut buf[..len]) };
    if !checksum_zero(&buf[..len]) {
        return Err(RsdpError::BadExtendedChecksum);
    }

    let xsdt_address = u64::from_le_bytes(buf[24..32].try_into().expect("8-byte slice"));

    ::log::debug!(
        "xenith.acpi.rsdp: ACPI 2.0+, rev {}, XSDT @ phys:0x{:016x}",
        revision,
        xsdt_address
    );

    Ok(Rsdp {
        revision,
        oem_id,
        rsdt_address,
        xsdt_address,
        length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signature constant must be exactly "RSD PTR " with the trailing
    /// space — the most common RSDP-comparison bug is dropping it.
    #[test]
    fn signature_has_trailing_space() {
        assert_eq!(&RSDP_SIGNATURE, b"RSD PTR ");
    }

    /// A buffer that sums to zero mod 256 validates; one that does not, does
    /// not. The fold uses wrapping add so u8 overflow wraps cleanly.
    #[test]
    fn checksum_zero_predicate() {
        // An all-zero buffer sums to zero.
        assert!(checksum_zero(&[0u8; 32]));
        // A buffer whose bytes sum to a multiple of 256 validates.
        let mut buf = [0u8; 4];
        buf[0] = 1;
        buf[3] = 255; // 1 + 255 = 256 ≡ 0
        assert!(checksum_zero(&buf));
        // Any other buffer fails.
        assert!(!checksum_zero(&[1u8; 4]));
    }

    #[test]
    fn extended_length_comes_from_offset_twenty() {
        let mut prefix = [0u8; RSDP_V2_PREFIX_LEN];
        // Populate the legacy checksum/OEM bytes at offset 8 so reading the
        // old, incorrect offset cannot accidentally produce the right value.
        prefix[8..12].copy_from_slice(&[0x42, b'V', b'M', b'W']);
        prefix[20..24].copy_from_slice(&(RSDP_V2_MIN_LEN as u32).to_le_bytes());

        assert_eq!(extended_length(&prefix), Some(RSDP_V2_MIN_LEN));
        assert_eq!(extended_length(&prefix[..23]), None);
    }

    /// `has_xsdt` is exactly "the 64-bit XSDT address is non-zero". ACPI 1.0
    /// RSDPs leave it zero and route through the RSDT.
    #[test]
    fn has_xsdt_predicate() {
        let v1 = Rsdp {
            revision: 0,
            oem_id: [0; 6],
            rsdt_address: 0x1234_0000,
            xsdt_address: 0,
            length: RSDP_V1_LEN,
        };
        assert!(!v1.has_xsdt());
        let v2 = Rsdp {
            revision: 2,
            oem_id: [0; 6],
            rsdt_address: 0,
            xsdt_address: 0xFFFF_8000_0000_0000,
            length: RSDP_V2_MIN_LEN,
        };
        assert!(v2.has_xsdt());
    }
}
