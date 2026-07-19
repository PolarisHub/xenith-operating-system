//! MADT (Multiple APIC Description Table) — CPU and IOAPIC topology.
//!
//! The MADT, signature `"APIC"`, is the ACPI table that enumerates the
//! platform's interrupt controllers: every CPU's local APIC (LAPIC) and
//! every I/O APIC (IOAPIC), plus the routing overrides that map legacy IRQs
//! to Global System Interrupts. Xenith retains LAPICs ([`MadtLapicEntry`]),
//! IOAPICs ([`MadtIoApicEntry`]), and Interrupt Source Overrides
//! ([`MadtInterruptSourceOverride`]).
//!
//! # Layout
//!
//! After the 36-byte common header, the MADT carries a 4-byte `Local APIC
//! Address` (the 32-bit MMIO base of the LAPIC), a 4-byte `Flags` (bit 0 =
//! `PCAT_COMPAT`, "a dual 8259 legacy PIC is present"), and then a sequence
//! of variable-length Interrupt Controller Structures. Each structure begins
//! with a 1-byte `Type` and a 1-byte `Length`; the walk strides by `Length`
//! so unknown structure types are skipped cleanly.
//!
//! # Structure types handled
//!
//! * **Type 0 — Processor Local APIC** (8 bytes): one entry per CPU. Fields
//!   carried into [`MadtLapicEntry`]: ACPI processor UID, APIC ID, and the
//!   `Enabled` flag (bit 0 of the 32-bit flags).
//! * **Type 1 — I/O APIC** (12 bytes): one entry per IOAPIC. Fields carried
//!   into [`MadtIoApicEntry`]: IOAPIC ID, 32-bit MMIO base, GSI base.
//! * **Type 2 — Interrupt Source Override** (10 bytes): maps an ISA source
//!   IRQ to a GSI and supplies its polarity/trigger flags. Xenith resolves
//!   conforming flags to the ISA defaults (active-high, edge-triggered).
//! * **Type 5 — Local APIC Address Override** (12 bytes): a 64-bit LAPIC
//!   MMIO base that overrides the 32-bit field in the header. We honour it
//!   so the LAPIC driver reaches the right register window on systems that
//!   relocate it above 4 GiB.
//! * **Type 9 — Processor Local x2APIC** (16 bytes): the 32-bit x2APIC id,
//!   32-bit ACPI processor UID, and enabled flag used on modern systems whose
//!   processor identifiers do not fit in the legacy type-0 fields.
//!
//! Every other structure type (NMIs, SAPIC, GIC family, ...) is skipped.
//!
//! # Safety
//!
//! The MADT body is read byte-by-byte through `read_volatile` from the
//! HHDM-mapped firmware table. Each structure's `Length` is bounds-checked
//! against the table end before any field is read, so a truncated or
//! corrupt entry cannot drive an out-of-bounds access. The parsed entry
//! slices are leaked into `'static` storage so [`super::Tables`] stays
//! `Copy` and the helpers are lock-free after boot.

use core::fmt;

use xenith_types::PhysAddr;

use super::xsdt::SdtHeader;
// The kernel-wide allocation surface. The `alloc` crate is linked in
// `crate::mm::allocator`; importing `Box`/`Vec` from there is the canonical
// kernel pattern and keeps a single module owning the allocator types.
use crate::mm::allocator::{Box, Vec};

/// One Processor Local APIC entry (MADT structure type 0).
///
/// The parsed, Rust-friendly view of the 8-byte MADT entry: the type/length
/// bytes are dropped (they are fixed for this structure) and the three
/// fields the scheduler and SMP bring-up consume are kept.
#[derive(Clone, Copy, Debug)]
pub struct MadtLapicEntry {
    /// The ACPI processor UID — the handle the DSDT/SSDT uses to refer to
    /// this CPU. Distinct from [`apic_id`](Self::apic_id) on some platforms.
    pub processor_uid: u32,
    /// The CPU's local APIC id. This is the value the LAPIC hardware reports
    /// and the one used for inter-processor interrupt destination delivery.
    pub apic_id: u32,
    /// Whether the CPU is enabled at boot. Disabled entries describe CPUs
    /// that exist but cannot be brought online (e.g. a hotplug slot that is
    /// currently empty); the scheduler only enumerates enabled ones.
    pub enabled: bool,
}

/// One I/O APIC entry (MADT structure type 1).
///
/// This is the type consumed directly by the I/O APIC driver.
#[derive(Clone, Copy, Debug)]
pub struct MadtIoApicEntry {
    /// The IOAPIC's APIC id. Stored into the IOAPIC id register during
    /// bring-up so local APICs can address this IOAPIC by id.
    pub id: u8,
    /// The 32-bit physical MMIO base of this IOAPIC's register window. The
    /// standard PC value is `0xFEC0_0000`; extra IOAPICs sit higher.
    pub mmio_base: u32,
    /// The first Global System Interrupt this IOAPIC handles. The classic
    /// single-IOAPIC PC has `gsi_base = 0`; extra IOAPICs stack above.
    pub gsi_base: u32,
}

/// One Interrupt Source Override entry (MADT structure type 2).
///
/// ACPI currently defines only bus `0` (ISA). The raw bus and flags are kept
/// so malformed firmware remains inspectable; [`Madt::resolve_isa_irq`]
/// ignores non-ISA entries and safely resolves reserved electrical encodings
/// to the ISA defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MadtInterruptSourceOverride {
    /// Bus identifier. ACPI requires `0`, meaning ISA.
    pub bus: u8,
    /// Bus-relative interrupt source (legacy IRQ number).
    pub source_irq: u8,
    /// Global System Interrupt input signalled by this source.
    pub gsi: u32,
    /// Raw MPS INTI flags: polarity in bits 0..1, trigger in bits 2..3.
    pub flags: u16,
}

/// Resolved electrical polarity for an ISA interrupt route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsaIrqPolarity {
    /// The line is asserted high. This is the ISA bus default.
    ActiveHigh,
    /// The line is asserted low.
    ActiveLow,
}

/// Resolved trigger mode for an ISA interrupt route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsaIrqTriggerMode {
    /// The interrupt fires on an edge. This is the ISA bus default.
    Edge,
    /// The interrupt remains asserted as a level until acknowledged.
    Level,
}

/// Fully resolved route for one legacy ISA IRQ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsaIrqRoute {
    /// GSI to program in the I/O APIC.
    pub gsi: u32,
    /// Electrical polarity after applying ACPI's ISA conforming default.
    pub polarity: IsaIrqPolarity,
    /// Trigger mode after applying ACPI's ISA conforming default.
    pub trigger: IsaIrqTriggerMode,
}

impl IsaIrqRoute {
    /// Identity-mapped ISA route used when firmware supplies no override.
    #[inline]
    #[must_use]
    pub const fn identity(irq: u8) -> Self {
        Self {
            gsi: irq as u32,
            polarity: IsaIrqPolarity::ActiveHigh,
            trigger: IsaIrqTriggerMode::Edge,
        }
    }
}

/// Errors raised by MADT parsing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MadtError {
    /// The MADT body is shorter than the 8-byte fixed prefix (LAPIC address
    /// + flags), so no structures could be walked.
    Truncated,
    /// A structure's `Length` was smaller than its fixed minimum (2 bytes
    /// for the type/length prefix) or reached past the table end. The walk
    /// stops at the bad entry to avoid reading garbage.
    BadEntryLength,
}

impl fmt::Display for MadtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("MADT body truncated"),
            Self::BadEntryLength => f.write_str("MADT entry length out of bounds"),
        }
    }
}

/// The parsed MADT.
///
/// Carries the LAPIC MMIO base (honouring a type-5 override) and `'static`
/// slices of the LAPIC, IOAPIC, and source-override entries, leaked from heap
/// `Vec`s at parse time. The slices are `'static` so [`super::Tables`] can
/// hold the MADT by reference and stay `Copy`.
#[derive(Clone, Copy)]
pub struct Madt {
    /// The LAPIC MMIO physical base, after applying any type-5 override.
    /// Defaults to the 32-bit value from the MADT header; a type-5 entry
    /// replaces it with a 64-bit address.
    pub local_apic_address: PhysAddr,
    /// Whether a dual 8259 legacy PIC is present (`PCAT_COMPAT`, MADT flags
    /// bit 0). The PIC driver masks the legacy chips when this is set.
    pub pcat_compat: bool,
    lapics: &'static [MadtLapicEntry],
    ioapics: &'static [MadtIoApicEntry],
    interrupt_source_overrides: &'static [MadtInterruptSourceOverride],
}

impl Madt {
    /// Parse a validated MADT [`SdtHeader`] into a [`Madt`].
    ///
    /// Walks the Interrupt Controller Structures from offset 44 to the end
    /// of the table, collecting type-0 (LAPIC), type-1 (IOAPIC), and type-2
    /// (Interrupt Source Override) entries and applying any type-5 LAPIC
    /// address override. The collected `Vec`s are leaked into `'static` box
    /// slices so the result outlives the parse and can be stored in
    /// [`super::Tables`].
    pub fn parse(hdr: &'static SdtHeader) -> Result<&'static Self, MadtError> {
        let total = hdr.length as usize;
        if total < 44 {
            return Err(MadtError::Truncated);
        }

        // The MADT header reference points at the table's first byte, so the
        // fixed prefix (LAPIC address + flags) is at offsets 36..44 and the
        // structure array starts at 44.
        let base = hdr as *const SdtHeader as *const u8;
        let mut lapics: Vec<MadtLapicEntry> = Vec::new();
        let mut ioapics: Vec<MadtIoApicEntry> = Vec::new();
        let mut interrupt_source_overrides: Vec<MadtInterruptSourceOverride> = Vec::new();

        // Fixed prefix: 4-byte LAPIC address at offset 36, 4-byte flags at
        // offset 40. Read them as little-endian u32s through volatile loads.
        let mut buf4 = [0u8; 4];
        for (i, slot) in buf4.iter_mut().enumerate() {
            // SAFETY: offset 36 + i is within the validated 44+ byte body.
            *slot = unsafe { core::ptr::read_volatile(base.add(36 + i)) };
        }
        let mut local_apic_address = PhysAddr::new_truncate(u64::from(u32::from_le_bytes(buf4)));
        for (i, slot) in buf4.iter_mut().enumerate() {
            // SAFETY: offset 40 + i is within the validated 44+ byte body.
            *slot = unsafe { core::ptr::read_volatile(base.add(40 + i)) };
        }
        let pcat_compat = u32::from_le_bytes(buf4) & 1 != 0;

        // Walk the variable-length structure array. Each structure is at
        // least 2 bytes (type + length); stride by the entry's own `Length`.
        let mut off = 44usize;
        while off + 2 <= total {
            // SAFETY: off and off+1 are within `[0, total)` (loop guard).
            let entry_type = unsafe { core::ptr::read_volatile(base.add(off)) };
            let entry_len = unsafe { core::ptr::read_volatile(base.add(off + 1)) } as usize;

            // A zero or sub-2 length is malformed; stop walking rather than
            // stride by a bogus value and read past the table end.
            if entry_len < 2 || off + entry_len > total {
                return Err(MadtError::BadEntryLength);
            }

            match entry_type {
                0 => {
                    // Processor Local APIC: 8 bytes. ACPI processor UID at
                    // +2, APIC id at +3, flags (u32) at +4.
                    if entry_len < 8 {
                        return Err(MadtError::BadEntryLength);
                    }
                    // SAFETY: offsets off+2, off+3 are within the entry
                    // (entry_len >= 8) and the table.
                    let uid = unsafe { core::ptr::read_volatile(base.add(off + 2)) };
                    let apic_id = unsafe { core::ptr::read_volatile(base.add(off + 3)) };
                    let mut fbuf = [0u8; 4];
                    for (i, slot) in fbuf.iter_mut().enumerate() {
                        // SAFETY: offset off+4+i is within the 8-byte entry.
                        *slot = unsafe { core::ptr::read_volatile(base.add(off + 4 + i)) };
                    }
                    let flags = u32::from_le_bytes(fbuf);
                    lapics.push(MadtLapicEntry {
                        processor_uid: u32::from(uid),
                        apic_id: u32::from(apic_id),
                        enabled: flags & 1 != 0,
                    });
                },
                1 => {
                    // I/O APIC: 12 bytes. ID at +2, reserved +3, MMIO base
                    // (u32) at +4, GSI base (u32) at +8.
                    if entry_len < 12 {
                        return Err(MadtError::BadEntryLength);
                    }
                    // SAFETY: offset off+2 is within the 12-byte entry.
                    let id = unsafe { core::ptr::read_volatile(base.add(off + 2)) };
                    let mut mbuf = [0u8; 4];
                    for (i, slot) in mbuf.iter_mut().enumerate() {
                        // SAFETY: off+4+i within the entry.
                        *slot = unsafe { core::ptr::read_volatile(base.add(off + 4 + i)) };
                    }
                    let mmio_base = u32::from_le_bytes(mbuf);
                    for (i, slot) in mbuf.iter_mut().enumerate() {
                        // SAFETY: off+8+i within the entry.
                        *slot = unsafe { core::ptr::read_volatile(base.add(off + 8 + i)) };
                    }
                    let gsi_base = u32::from_le_bytes(mbuf);
                    ioapics.push(MadtIoApicEntry {
                        id,
                        mmio_base,
                        gsi_base,
                    });
                },
                2 => {
                    // Interrupt Source Override: 10 bytes. Bus at +2,
                    // bus-relative source IRQ at +3, GSI (u32) at +4, and
                    // MPS INTI polarity/trigger flags (u16) at +8.
                    if entry_len < 10 {
                        return Err(MadtError::BadEntryLength);
                    }
                    // SAFETY: offsets off+2 and off+3 lie in the validated
                    // ten-byte entry.
                    let bus = unsafe { core::ptr::read_volatile(base.add(off + 2)) };
                    let source_irq = unsafe { core::ptr::read_volatile(base.add(off + 3)) };
                    let mut gsi_bytes = [0u8; 4];
                    for (i, slot) in gsi_bytes.iter_mut().enumerate() {
                        // SAFETY: off+4+i lies in the validated entry.
                        *slot = unsafe { core::ptr::read_volatile(base.add(off + 4 + i)) };
                    }
                    let mut flags_bytes = [0u8; 2];
                    for (i, slot) in flags_bytes.iter_mut().enumerate() {
                        // SAFETY: off+8+i lies in the validated entry.
                        *slot = unsafe { core::ptr::read_volatile(base.add(off + 8 + i)) };
                    }
                    interrupt_source_overrides.push(MadtInterruptSourceOverride {
                        bus,
                        source_irq,
                        gsi: u32::from_le_bytes(gsi_bytes),
                        flags: u16::from_le_bytes(flags_bytes),
                    });
                },
                5 => {
                    // Local APIC Address Override: 12 bytes. A 64-bit LAPIC
                    // physical base at offset +4 replaces the 32-bit header
                    // value. Applied even when the entry appears after some
                    // LAPIC/IOAPIC entries — the override is global.
                    if entry_len < 12 {
                        return Err(MadtError::BadEntryLength);
                    }
                    let mut abuf = [0u8; 8];
                    for (i, slot) in abuf.iter_mut().enumerate() {
                        // SAFETY: off+4+i within the 12-byte entry.
                        *slot = unsafe { core::ptr::read_volatile(base.add(off + 4 + i)) };
                    }
                    local_apic_address = PhysAddr::new_truncate(u64::from_le_bytes(abuf));
                },
                9 => {
                    // Processor Local x2APIC: 16 bytes. Reserved u16 at +2,
                    // x2APIC id at +4, flags at +8, processor UID at +12.
                    if entry_len < 16 {
                        return Err(MadtError::BadEntryLength);
                    }
                    let read_u32 = |field_off: usize| {
                        let mut bytes = [0u8; 4];
                        for (i, slot) in bytes.iter_mut().enumerate() {
                            // SAFETY: each requested field lies entirely in
                            // the validated 16-byte entry.
                            *slot =
                                unsafe { core::ptr::read_volatile(base.add(off + field_off + i)) };
                        }
                        u32::from_le_bytes(bytes)
                    };
                    let apic_id = read_u32(4);
                    let flags = read_u32(8);
                    let processor_uid = read_u32(12);
                    lapics.push(MadtLapicEntry {
                        processor_uid,
                        apic_id,
                        enabled: flags & 1 != 0,
                    });
                },
                // All other structure types (NMIs, SAPIC, GIC, ...) are
                // skipped. The entry's own `Length` advances the walk past
                // them cleanly.
                _ => {},
            }

            off += entry_len;
        }

        // Freeze the collected vectors into `'static` box slices. They are
        // leaked intentionally: the MADT entries describe the platform's
        // CPU/IOAPIC topology for the kernel's entire lifetime, so freeing
        // them would be a bug. Box::leak is the idiomatic way to promote a
        // heap allocation to `'static` at boot.
        let lapics_slice: &'static [MadtLapicEntry] = Box::leak(lapics.into_boxed_slice());
        let ioapics_slice: &'static [MadtIoApicEntry] = Box::leak(ioapics.into_boxed_slice());
        let interrupt_source_overrides_slice: &'static [MadtInterruptSourceOverride] =
            Box::leak(interrupt_source_overrides.into_boxed_slice());

        Ok(Box::leak(Box::new(Self {
            local_apic_address,
            pcat_compat,
            lapics: lapics_slice,
            ioapics: ioapics_slice,
            interrupt_source_overrides: interrupt_source_overrides_slice,
        })))
    }

    /// The LAPIC entries collected from the MADT.
    #[inline]
    pub fn lapics(&self) -> &'static [MadtLapicEntry] {
        self.lapics
    }

    /// The IOAPIC entries collected from the MADT.
    #[inline]
    pub fn ioapics(&self) -> &'static [MadtIoApicEntry] {
        self.ioapics
    }

    /// The Interrupt Source Override entries collected from the MADT.
    #[inline]
    pub fn interrupt_source_overrides(&self) -> &'static [MadtInterruptSourceOverride] {
        self.interrupt_source_overrides
    }

    /// Resolve an ISA IRQ to the GSI and electrical mode firmware requires.
    ///
    /// Without a matching bus-0 override the route is identity-mapped,
    /// active-high, and edge-triggered. ACPI's `00` (conforms-to-bus) flag
    /// encodings resolve to those same ISA defaults. Reserved encodings and
    /// non-zero reserved flag bits also fall back to the ISA electrical
    /// defaults while retaining the override's unambiguous GSI mapping.
    #[inline]
    #[must_use]
    pub fn resolve_isa_irq(&self, irq: u8) -> IsaIrqRoute {
        resolve_isa_irq(self.interrupt_source_overrides, irq)
    }
}

/// Resolve an ISA IRQ against a slice of MADT Interrupt Source Overrides.
///
/// This pure helper is also the pre-ACPI fallback path and is intentionally
/// total: malformed or missing electrical flags never leak a reserved mode to
/// the I/O APIC.
#[must_use]
pub fn resolve_isa_irq(overrides: &[MadtInterruptSourceOverride], irq: u8) -> IsaIrqRoute {
    let Some(iso) = overrides
        .iter()
        .find(|entry| entry.bus == 0 && entry.source_irq == irq)
    else {
        return IsaIrqRoute::identity(irq);
    };

    // Flags above bit 3 must be zero. If firmware violates that contract,
    // keep the GSI mapping but fail closed to the ISA electrical defaults.
    if iso.flags & !0x000f != 0 {
        return IsaIrqRoute {
            gsi: iso.gsi,
            ..IsaIrqRoute::identity(irq)
        };
    }

    let polarity = match iso.flags & 0b11 {
        0b11 => IsaIrqPolarity::ActiveLow,
        // 00 conforms to ISA (active-high), 01 is explicitly active-high,
        // and 10 is reserved so it safely falls back to the bus default.
        _ => IsaIrqPolarity::ActiveHigh,
    };
    let trigger = match (iso.flags >> 2) & 0b11 {
        0b11 => IsaIrqTriggerMode::Level,
        // 00 conforms to ISA (edge), 01 is explicitly edge, and 10 is
        // reserved so it safely falls back to the bus default.
        _ => IsaIrqTriggerMode::Edge,
    };

    IsaIrqRoute {
        gsi: iso.gsi,
        polarity,
        trigger,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spec_offsets_and_controller_entries() {
        let table = Box::leak(Box::new([0u8; 64]));
        table[0..4].copy_from_slice(b"APIC");
        table[4..8].copy_from_slice(&64u32.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        table[40..44].copy_from_slice(&1u32.to_le_bytes());

        table[44..52].copy_from_slice(&[0, 8, 3, 7, 1, 0, 0, 0]);
        table[52] = 1;
        table[53] = 12;
        table[54] = 2;
        table[56..60].copy_from_slice(&0xfec0_0000u32.to_le_bytes());
        table[60..64].copy_from_slice(&24u32.to_le_bytes());

        // SAFETY: the leaked byte array contains a complete packed header.
        let header = unsafe { &*(table.as_ptr() as *const SdtHeader) };
        let madt = Madt::parse(header).unwrap();
        assert_eq!(madt.local_apic_address.as_u64(), 0xfee0_0000);
        assert!(madt.pcat_compat);
        assert_eq!(madt.lapics().len(), 1);
        assert_eq!(madt.lapics()[0].processor_uid, 3);
        assert_eq!(madt.lapics()[0].apic_id, 7);
        assert!(madt.lapics()[0].enabled);
        assert_eq!(madt.ioapics().len(), 1);
        assert_eq!(madt.ioapics()[0].id, 2);
        assert_eq!(madt.ioapics()[0].mmio_base, 0xfec0_0000);
        assert_eq!(madt.ioapics()[0].gsi_base, 24);
    }

    #[test]
    fn rejects_table_without_fixed_prefix() {
        let table = Box::leak(Box::new([0u8; 43]));
        table[4..8].copy_from_slice(&43u32.to_le_bytes());
        // SAFETY: the leaked byte array contains a complete packed header.
        let header = unsafe { &*(table.as_ptr() as *const SdtHeader) };
        assert!(matches!(Madt::parse(header), Err(MadtError::Truncated)));
    }

    #[test]
    fn parses_wide_x2apic_entry() {
        let table = Box::leak(Box::new([0u8; 60]));
        table[0..4].copy_from_slice(b"APIC");
        table[4..8].copy_from_slice(&60u32.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        table[44] = 9;
        table[45] = 16;
        table[48..52].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        table[52..56].copy_from_slice(&1u32.to_le_bytes());
        table[56..60].copy_from_slice(&0x9abc_def0u32.to_le_bytes());

        // SAFETY: the leaked byte array contains a complete packed header.
        let header = unsafe { &*(table.as_ptr() as *const SdtHeader) };
        let madt = Madt::parse(header).unwrap();
        assert_eq!(madt.lapics().len(), 1);
        assert_eq!(madt.lapics()[0].apic_id, 0x1234_5678);
        assert_eq!(madt.lapics()[0].processor_uid, 0x9abc_def0);
        assert!(madt.lapics()[0].enabled);
    }

    #[test]
    fn skips_type_four_nmi_and_applies_type_five_address_override() {
        let table = Box::leak(Box::new([0u8; 62]));
        table[0..4].copy_from_slice(b"APIC");
        table[4..8].copy_from_slice(&62u32.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());

        // Type 4 is a six-byte Local APIC NMI structure, not an address
        // override. It must be skipped without applying the type-5 minimum.
        table[44..50].copy_from_slice(&[4, 6, 0xff, 0, 1, 0]);
        table[50] = 5;
        table[51] = 12;
        table[54..62].copy_from_slice(&0x0000_0001_fee0_0000u64.to_le_bytes());

        // SAFETY: the leaked byte array contains a complete packed header.
        let header = unsafe { &*(table.as_ptr() as *const SdtHeader) };
        let madt = Madt::parse(header).unwrap();
        assert_eq!(madt.local_apic_address.as_u64(), 0x0000_0001_fee0_0000);
    }

    #[test]
    fn isa_route_without_override_uses_legacy_defaults() {
        assert_eq!(resolve_isa_irq(&[], 1), IsaIrqRoute {
            gsi: 1,
            polarity: IsaIrqPolarity::ActiveHigh,
            trigger: IsaIrqTriggerMode::Edge,
        });
    }

    #[test]
    fn parses_identity_override_and_resolves_conforming_flags() {
        let table = Box::leak(Box::new([0u8; 54]));
        table[0..4].copy_from_slice(b"APIC");
        table[4..8].copy_from_slice(&54u32.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        table[44..48].copy_from_slice(&[2, 10, 0, 1]);
        table[48..52].copy_from_slice(&1u32.to_le_bytes());
        table[52..54].copy_from_slice(&0u16.to_le_bytes());

        // SAFETY: the leaked byte array contains a complete packed header.
        let header = unsafe { &*(table.as_ptr() as *const SdtHeader) };
        let madt = Madt::parse(header).unwrap();
        assert_eq!(madt.interrupt_source_overrides(), &[
            MadtInterruptSourceOverride {
                bus: 0,
                source_irq: 1,
                gsi: 1,
                flags: 0,
            }
        ]);
        assert_eq!(madt.resolve_isa_irq(1), IsaIrqRoute::identity(1));
    }

    #[test]
    fn resolves_non_identity_active_low_level_override() {
        let table = Box::leak(Box::new([0u8; 54]));
        table[0..4].copy_from_slice(b"APIC");
        table[4..8].copy_from_slice(&54u32.to_le_bytes());
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        table[44..48].copy_from_slice(&[2, 10, 0, 12]);
        table[48..52].copy_from_slice(&20u32.to_le_bytes());
        table[52..54].copy_from_slice(&0x000fu16.to_le_bytes());

        // SAFETY: the leaked byte array contains a complete packed header.
        let header = unsafe { &*(table.as_ptr() as *const SdtHeader) };
        let route = Madt::parse(header).unwrap().resolve_isa_irq(12);
        assert_eq!(route, IsaIrqRoute {
            gsi: 20,
            polarity: IsaIrqPolarity::ActiveLow,
            trigger: IsaIrqTriggerMode::Level,
        });
    }
}
