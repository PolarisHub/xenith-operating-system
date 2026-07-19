//! ACPI subsystem — table discovery, parsing, and platform shutdown.
//!
//! This module is the kernel's entry point into the ACPI world. ACPI (Advanced
//! Configuration and Power Interface) is the firmware-provided data structure
//! that a PC OS uses to discover non-enumerable hardware: which CPUs exist and
//! how interrupts are routed (the MADT), where the HPET lives (the HPET table),
//! how to power the machine off and reboot (the FADT's PM1 control registers),
//! and the big blob of declarative device configuration in the DSDT/SSDT.
//!
//! Static tables provide topology and fixed registers. The bounded [`aml`]
//! interpreter additionally loads the DSDT namespace and evaluates device
//! discovery methods such as `_STA`, `_CRS`, and `_PRT`; operation-region I/O
//! is denied until platform code installs an explicit access policy.
//!
//! # Discovery flow
//!
//! ```text
//!   Limine BootInfo.rsdp  ──►  rsdp::find / parse  ──►  Rsdp
//!                                                            │
//!                                                            ▼
//!                                          xsdt::Tables::from_rsdp
//!                                                            │
//!                              ┌────────────────────────────┼───────────────────┐
//!                              ▼                            ▼                   ▼
//!                          madt.rs                      fadt.rs              hpet (time)
//!                       (CPU + IOAPIC)            (PM1a/b, DSDT ptr)        (MMIO base)
//! ```
//!
//! [`init`] takes the RSDP physical address that the Limine boot info wrapper
//! hands us (see `xenith_boot::BootInfo::rsdp`), validates it, walks the
//! XSDT (or RSDT on ACPI 1.0), and caches the parsed MADT/FADT/HPET tables in
//! a [`spin::Once`] so the helper accessors below are O(1) after boot.
//!
//! # Address translation
//!
//! Every ACPI table address is a *physical* address. Limine direct-maps all
//! physical memory at the HHDM base `0xFFFF_8000_0000_0000`, so converting a
//! physical table address to a dereferenceable pointer is plain additive
//! arithmetic — no page tables are allocated, no frames are consumed. The
//! [`phys_to_virt`] helper centralises this; it mirrors the constant in
//! `crate::panic`, `crate::time::hpet`, and `crate::arch::x86_64::interrupts::ioapic`.
//! A future `mm::phys_to_virt` will consolidate the duplicates.
//!
//! # Safety
//!
//! ACPI tables live in firmware-reserved memory that Limine mapped uncacheable
//! and that the kernel owns for its entire lifetime. All table reads are
//! `read_volatile` from HHDM-translated pointers; the tables are validated
//! (checksum + length sanity) before any field is trusted. The parsed results
//! are stored in `static`s guarded by [`spin::Once`], so the accessors are
//! safe to call from any context after [`init`] has run.

#![allow(clippy::module_inception)]

pub mod aml;
pub mod dsdt;
pub mod fadt;
pub mod madt;
pub mod rsdp;
pub mod rsdt;
pub mod shutdown;
pub mod xsdt;

use core::sync::atomic::{AtomicBool, Ordering};

use spin::Once;
use xenith_types::PhysAddr;

use self::fadt::Fadt;
use self::madt::{MadtIoApicEntry, MadtLapicEntry};
use self::xsdt::Tables;

/// The Limine higher-half direct-map base. Adding a physical address to this
/// yields the canonical virtual address that dereferences to that physical
/// byte. Mirrors `crate::panic::HHDM_BASE`, `crate::time::hpet::HHDM_BASE`,
/// and the IOAPIC driver's constant; a shared `mm::phys_to_virt` helper will
/// consolidate the duplicates.
pub(crate) const HHDM_BASE: u64 = 0xFFFF_8000_0000_0000;

/// The parsed ACPI table set, installed once by [`init`] and read by every
/// helper accessor below. `Once` gives us a lock-free, single-shot init that
/// panics if a second caller tries to install — exactly the contract we want
/// for boot-time platform discovery.
static TABLES: Once<Tables> = Once::new();

/// The parsed FADT, installed alongside [`TABLES`]. Kept separate because the
/// shutdown path reads the PM1 control registers from the FADT long after
/// boot, and we want [`shutdown`] to be a single `Once::get` rather than a
/// walk of the full table set.
static FADT: Once<&'static Fadt> = Once::new();

/// Guard against re-entering [`init`] on a second CPU before the BSP has
/// finished. ACPI init is strictly a BSP activity; APs come up later via the
/// LAPIC/MP protocol and never touch this path. The flag is informational —
/// [`Once`] already serialises the actual table install — but it lets the
/// helpers return `None` cleanly before init has completed rather than
/// panicking through `Once::get`.
static INIT_DONE: AtomicBool = AtomicBool::new(false);

/// Translate a physical address to a HHDM-virtual pointer.
///
/// This is the central address-translation primitive for the ACPI subsystem.
/// Every ACPI table address (RSDP, XSDT, FADT, MADT, HPET, DSDT, ...) is a
/// physical address; converting it to a virtual address that the CPU can
/// dereference is `HHDM_BASE + phys`. The result is cast to the desired raw
/// pointer type by the caller.
///
/// No page-table allocation happens here — Limine's HHDM direct map covers
/// the full physical address space for the regions the kernel touches, so the
/// returned pointer is always backed by a valid mapping as long as `phys` is
/// a real physical address the firmware placed a table at.
#[inline]
pub(crate) fn phys_to_virt(phys: PhysAddr) -> *const u8 {
    // Wrapping addition is sound: HHDM_BASE is a canonical upper-half address
    // and the physical addresses we add are below 2^52, so the sum stays
    // within the upper half. new_truncate in callers canonicalises if needed.
    (HHDM_BASE.wrapping_add(phys.as_u64())) as *const u8
}

/// Initialise the ACPI subsystem from the RSDP physical address.
///
/// `rsdp_phys` is the physical address of the Root System Description Pointer
/// that Limine located and reported via `xenith_boot::BootInfo::rsdp`. The
/// function validates the RSDP, walks the XSDT (ACPI 2.0+) or RSDT (ACPI
/// 1.0 fallback) it points at, and caches the parsed tables in the module's
/// `Once` statics so the helper accessors ([`hpet_address`],
/// [`madt_ioapics`], [`madt_lapics`]) are O(1) afterwards.
///
/// Calling this more than once panics: ACPI init is a one-shot BSP activity.
/// A missing or invalid RSDP is logged at `warn!` level and the function
/// returns without installing anything; the helper accessors then return
/// `None`/empty slices and the callers (HPET, IOAPIC, shutdown) fall back to
/// their own defaults. This keeps the kernel booting on ACPI-less platforms
/// (e.g. some sub-2 MiB legacy images) rather than aborting.
pub fn init(rsdp_phys: PhysAddr) {
    ::log::info!("xenith.acpi: init from RSDP @ {}", rsdp_phys);

    let rsdp = match rsdp::find_and_parse(rsdp_phys) {
        Ok(r) => r,
        Err(e) => {
            ::log::warn!("xenith.acpi: RSDP invalid ({}); ACPI disabled", e);
            return;
        },
    };
    ::log::info!(
        "xenith.acpi: RSDP v{} signature ok, revision {}",
        if rsdp.revision >= 2 { 2 } else { 1 },
        rsdp.revision
    );

    let tables = match Tables::from_rsdp(&rsdp) {
        Ok(t) => t,
        Err(e) => {
            ::log::warn!("xenith.acpi: table walk failed ({}); ACPI disabled", e);
            return;
        },
    };

    // Install the table set first; the FADT reference is derived from it and
    // stored separately for the shutdown path. Both Once::call sites run
    // exactly once — a second `init` would panic at the `Once::call` boundary,
    // which is the intended contract for a one-shot BSP init.
    TABLES.call_once(|| tables);

    // Publish the FADT (if present) into its own Once so [`shutdown`] and the
    // PM1 helpers can reach it without walking the table set each time. We do
    // this after TABLES is installed so a concurrent reader can never see the
    // FADT without the table set that anchors it.
    if let Some(fadt) = tables.fadt() {
        // SAFETY: the FADT was parsed out of the HHDM-mapped firmware table
        // area, which Limine maps uncacheable and which persists for the
        // kernel's lifetime. The borrow is valid for `'static` because the
        // underlying table memory is never reclaimed or moved.
        let fadt_ref: &'static Fadt = unsafe {
            // The cast extends the borrow lifetime; the table memory itself
            // is bootloader/firmware-owned and stable for the whole boot.
            core::mem::transmute::<&Fadt, &'static Fadt>(fadt)
        };
        FADT.call_once(|| fadt_ref);
        ::log::info!(
            "xenith.acpi: FADT present, PM1a=0x{:04x} PM1b=0x{:04x}",
            fadt.pm1a_ctrl_block,
            fadt.pm1b_ctrl_block
        );
    } else {
        ::log::warn!("xenith.acpi: no FADT; shutdown/reboot will be unavailable");
    }

    // Log a concise summary of what we found. The MADT entries are the most
    // load-bearing: they drive LAPIC and IOAPIC bring-up.
    let lapics = tables.madt_lapics();
    let ioapics = tables.madt_ioapics();
    ::log::info!(
        "xenith.acpi: {} LAPIC(s), {} IOAPIC(s) enumerated",
        lapics.len(),
        ioapics.len()
    );

    match aml::init_from_dsdt() {
        Ok(objects) => ::log::info!(
            "xenith.acpi: AML namespace loaded ({} objects, {} SSDT block(s))",
            objects,
            tables.ssdt_count()
        ),
        Err(aml::AmlError::NoDsdt) => {
            ::log::warn!("xenith.acpi: no DSDT; AML device discovery disabled")
        },
        Err(error) => ::log::warn!(
            "xenith.acpi: AML definition block rejected ({}); static ACPI tables remain active",
            error
        ),
    }

    INIT_DONE.store(true, Ordering::Release);
}

/// Has [`init`] completed successfully?
///
/// Returns `false` before boot finishes (or if ACPI init failed and was
/// skipped). Callers that need to know whether the helper accessors will
/// return real data can check this; the accessors themselves also handle the
/// "not yet initialised" case by returning `None`/empty.
#[inline]
#[must_use]
pub fn initialised() -> bool {
    INIT_DONE.load(Ordering::Acquire)
}

/// Borrow the parsed ACPI table set, if [`init`] has installed it.
///
/// Returns `None` before [`init`] runs or if ACPI init was skipped due to an
/// invalid RSDP. Direct callers are rare — most kernel code reaches the
/// tables through the typed helpers below — but the scheduler and device
/// probe use this to discover whether ACPI is available at all.
#[inline]
pub fn tables() -> Option<&'static Tables> {
    TABLES.get()
}

/// The HPET's physical MMIO base, parsed from the ACPI HPET table.
///
/// Returns `None` if ACPI init has not run, if no HPET table is present, or
/// if the HPET table failed validation. The time subsystem
/// (`crate::time::hpet`) calls this and falls back to the PIT on `None`, so
/// a missing HPET never aborts boot.
///
/// The returned address is the raw `Address` field of the HPET table: a
/// 64-bit value whose low 3 bits encode the address-space ID (always `0` =
/// system memory for the HPET on x86_64) and whose high bits are the physical
/// byte address. We mask off the low bits here so callers get a clean
/// page-aligned-ish physical address.
#[inline]
pub fn hpet_address() -> Option<PhysAddr> {
    let tables = TABLES.get()?;
    tables.hpet_address()
}

/// The platform's I/O APIC set, as enumerated by the ACPI MADT.
///
/// Returns an empty slice if ACPI init has not run or the MADT is absent.
/// The IOAPIC driver (`crate::arch::x86_64::interrupts::ioapic`) consumes
/// this list to program redirection entries for each GSI range; on a classic
/// PC it contains exactly one entry (MMIO `0xFEC0_0000`, GSI base 0).
#[inline]
pub fn madt_ioapics() -> &'static [MadtIoApicEntry] {
    match TABLES.get() {
        Some(t) => t.madt_ioapics(),
        None => &[],
    }
}

/// The platform's local APIC CPU set, as enumerated by the ACPI MADT.
///
/// Returns an empty slice if ACPI init has not run or the MADT is absent.
/// Each entry describes one CPU's LAPIC id, its ACPI processor id, and
/// whether it is enabled at boot. The scheduler and SMP bring-up code use
/// this to size per-CPU storage and to know which APs to wake.
#[inline]
pub fn madt_lapics() -> &'static [MadtLapicEntry] {
    match TABLES.get() {
        Some(t) => t.madt_lapics(),
        None => &[],
    }
}

/// The parsed FADT, if present.
///
/// Exposed for callers that need FADT fields beyond the PM1 control registers
/// (for example, the DSDT pointer that [`dsdt`] consumes). The shutdown path
/// uses [`FADT`] directly via [`shutdown`].
#[inline]
pub fn fadt() -> Option<&'static Fadt> {
    FADT.get().copied()
}
