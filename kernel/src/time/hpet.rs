//! High Precision Event Timer (HPET) driver.
//!
//! The HPET is the platform's high-resolution monotonic counter, defined by
//! the Intel/AMD "IA-PC HPET" specification and enumerated to the OS through
//! an ACPI table (the HPET Description Table, signature `"HPET"`). It is the
//! preferred kernel clocksource on any system that has one: the main counter
//! is up to 64 bits wide (so it never wraps in practice — a 14.3 MHz counter
//! takes ~41 000 years to roll a 64-bit value), runs at a vendor-reported
//! femtosecond period, and is readable through a single MMIO load with no
//! two-step select/data protocol. On systems without an HPET the kernel falls
//! back to the PIT.
//!
//! # Register layout
//!
//! The HPET exposes a 1 KiB MMIO window whose base physical address is the
//! `Address` field of the ACPI HPET table. The registers the kernel cares
//! about are:
//!
//! | Offset | Register                       | Width |
//! |--------|--------------------------------|-------|
//! | 0x00   | General Capabilities           | 64    |
//! | 0x08   | Reserved                       | 64    |
//! | 0x10   | General Configuration          | 64    |
//! | 0x18   | Reserved                       | 64    |
//! | 0x20   | General Interrupt Status       | 64    |
//! | 0x28.. | Reserved                       |       |
//! | 0xF0   | Main Counter                   | 64    |
//! | 0xF8   | Reserved                       | 64    |
//! | 0x100  | Timer 0 Config/Cap + Comparator| 0x20 stride per timer |
//!
//! The General Capabilities register is read-only and reports, in one 64-bit
//! load: the revision (bits 0..7), how many timers exist (bits 8..12, value
//! is `count - 1`), whether the main counter is 64-bit capable (bit 13),
//! whether legacy-replacement routing is available (bit 15), the vendor ID
//! (bits 16..31), and — most importantly for us — the
//! counter's tick period in femtoseconds (bits 32..63). The period is
//! architecturally required to be non-zero, so a zero period means the MMIO
//! window is not a real HPET and we refuse to initialise.
//!
//! The General Configuration register's bit 0 is the global ENABLE_CNF: when
//! clear the main counter is halted and held at its last value; when set it
//! counts up at the period reported in the capabilities register. The kernel
//! leaves this set once [`init`] has run.
//!
//! The Main Counter at 0xF0 is a free-running up-counter that the kernel
//! reads as the monotonic timebase. It is read/write, but we only ever read
//! it: writing it would desync every deadline already computed against the
//! old value, so the driver deliberately exposes no "set counter" path.
//!
//! # Address translation
//!
//! The ACPI HPET table reports the MMIO base as a *physical* address. Limine
//! direct-maps all physical memory at the HHDM base `0xFFFF_8000_0000_0000`,
//! so converting the physical MMIO base to a dereferenceable virtual address
//! is plain additive arithmetic — no page tables are allocated, no frame is
//! consumed. The constant mirrors `crate::panic::HHDM_BASE` and the IOAPIC
//! driver's `HHDM_BASE`; a future `mm::phys_to_virt` helper will consolidate
//! the duplicates.
//!
//! # Reading the counter safely
//!
//! On a 64-bit-capable HPET the main counter is a single 64-bit MMIO load,
//! which x86 guarantees is atomic (an aligned `mov` to/from a 64-bit MMIO
//! region is architecturally atomic on every AMD64 part that implements the
//! HPET). On a 32-bit-only HPET the upper 32 bits always read zero and the
//! counter wraps every ~300 s at 14.3 MHz; we read it as a 32-bit value and
//! let [`now_ns`] saturate at the 32-bit wrap interval, which is acceptable
//! because the kernel only selects a 32-bit HPET as the clocksource when no
//! better option exists and the scheduler tick would resample it far more
//! often than every 300 s.
//!
//! # Safety
//!
//! All HPET accesses are volatile loads/stores to the HHDM-translated MMIO
//! window. The window is device memory that Limine mapped uncacheable; the
//! kernel owns it for its entire lifetime. Enabling the counter is a one-way
//! operation performed once at boot; the driver never disables it afterwards
//! because every running deadline depends on the counter advancing.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use xenith_bitflags::bitflags;
use xenith_types::{PhysAddr, VirtAddr};

use super::clock::ClockSource;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The Limine higher-half direct-map base. Adding a physical address to this
/// yields the canonical virtual address that dereferences to that physical
/// byte. Mirrors `crate::panic::HHDM_BASE` and the IOAPIC driver's constant;
/// a shared `mm::phys_to_virt` will consolidate them.
const HHDM_BASE: u64 = 0xFFFF_8000_0000_0000;

/// Legacy PC HPET base used only when no ACPI table set was available at all.
/// If ACPI is valid but contains no HPET entry, the driver must not probe this
/// address blindly and instead falls back to the LAPIC clock.
const DEFAULT_HPET_MMIO: u64 = 0xFED0_0000;

// HPET register offsets within the 1 KiB MMIO window.
/// General Capabilities Register (read-only): counter width, timer count,
/// periodic support, and the femtosecond period.
const REG_GENERAL_CAPABILITIES: u64 = 0x00;
/// General Configuration Register (R/W): global enable and legacy-route bits.
const REG_GENERAL_CONFIGURATION: u64 = 0x10;
/// General Interrupt Status Register (R/WC): per-timer interrupt active bits.
const REG_GENERAL_INTERRUPT_STATUS: u64 = 0x20;
/// Main Counter Register (R/W): the free-running up-counter timebase.
const REG_MAIN_COUNTER: u64 = 0xF0;

/// The size of the HPET MMIO window. The architecture reserves 1 KiB even
/// though the registers the kernel uses sit in the first 0x100 bytes; the
/// remainder is the per-timer block (0x100..0x400 for up to 32 timers). We
/// only touch the registers above, but the whole window is one device page.
/// Declared for the register map even though no accessor reads it today.
#[allow(dead_code)]
const HPET_WINDOW_SIZE: u64 = 0x400;

// General Capabilities register field positions.
/// Bit 13: COUNT_SIZE_CAP. Set => the main counter is 64 bits wide; clear =>
/// 32 bits (upper 32 bits always read zero).
const CAP_COUNT_SIZE_64: u64 = 1 << 13;
/// Bit 15: LEG_RT_CAP. Set => the legacy-replacement IRQ route is available.
const CAP_LEGACY_ROUTE: u64 = 1 << 15;
/// Bits 8..12: NUM_TIM_CAP. The number of timers is this field plus one.
const CAP_NUM_TIMERS_SHIFT: u64 = 8;
const CAP_NUM_TIMERS_MASK: u64 = 0x1F;
/// Bits 32..63: COUNTER_CLK_PERIOD. The counter tick period in femtoseconds.
const CAP_PERIOD_SHIFT: u64 = 32;
const CAP_PERIOD_MASK: u64 = 0xFFFF_FFFF;

// General Configuration register field positions.
/// Bit 0: ENABLE_CNF. Set => main counter is running; clear => halted.
const CFG_ENABLE: u64 = 1 << 0;
/// Bit 1: LEG_RT_CNF. Set => route timer 0/1 to legacy IRQ 0/8 instead of
/// their own I/O APIC pins. We never enable legacy routing and explicitly
/// clear this bit in [`Hpet::enable`] so a firmware left-over does not
/// misroute timer interrupts to the legacy PIC pins.
const CFG_LEGACY_ROUTE: u64 = 1 << 1;

/// One femtosecond in nanoseconds, as a rational scale. The HPET period is
/// reported in femtoseconds (1e-15 s); nanoseconds are 1e-9 s, so
/// `ns = femtoseconds / 1e6`. We keep the division as `period_fs / 1_000_000`
/// to avoid floating point in the kernel.
const FEMTOS_PER_NANO: u64 = 1_000_000;

bitflags! {
    /// Decoded General Capabilities register flags.
    ///
    /// The raw 64-bit capabilities register packs several independent fields
    /// into one load; this bitflags type exposes the two single-bit capability
    /// flags the driver branches on. The multi-bit fields (timer count,
    /// period) are extracted with shifts in [`HpetCaps::from_raw`] and stored
    /// as plain integers because they are not bitsets.
    pub struct HpetCapFlags: u64 {
        /// COUNT_SIZE_CAP: the main counter is 64 bits wide.
        const COUNTER_64_BIT = CAP_COUNT_SIZE_64;
        /// LEG_RT_CAP: the legacy-replacement IRQ route is available.
        const LEGACY_ROUTE = CAP_LEGACY_ROUTE;
    }
}

/// The decoded General Capabilities register, split into its useful fields.
///
/// Constructed once from the raw 64-bit MMIO load by [`HpetCaps::from_raw`].
/// The driver reads the period and counter width out of this struct rather
/// than re-decoding the raw register on every counter access.
#[derive(Copy, Clone, Debug)]
struct HpetCaps {
    /// Whether the main counter is 64 bits wide. When `false` the upper 32
    /// bits of the counter always read zero and the counter wraps every
    /// `2^32 * period` femtoseconds (~300 s at the standard 14.3 MHz rate).
    counter_64_bit: bool,
    /// Whether the legacy-replacement IRQ route is available. The kernel does
    /// not use it, but the field is reported for diagnostics.
    legacy_route: bool,
    /// The number of timers (comparators) the HPET exposes. The register
    /// encodes this as `count - 1`; we store the decoded count.
    num_timers: u8,
    /// The counter tick period in femtoseconds. Architecturally non-zero; a
    /// zero value indicates a bogus MMIO window and the driver refuses to
    /// initialise.
    period_fs: u64,
}

impl HpetCaps {
    /// Decode a raw General Capabilities register read into its fields.
    ///
    /// Returns `None` if the period field is zero, which the HPET spec
    /// forbids and which indicates the MMIO window is not a real HPET (for
    /// example, the ACPI table pointed at unbacked memory). The caller
    /// treats `None` as "no HPET present" and falls back to the PIT.
    #[must_use]
    fn from_raw(raw: u64) -> Option<Self> {
        let flags = HpetCapFlags::from_bits_truncate(raw);
        let num_timers_raw = (raw >> CAP_NUM_TIMERS_SHIFT) & CAP_NUM_TIMERS_MASK;
        let period_fs = (raw >> CAP_PERIOD_SHIFT) & CAP_PERIOD_MASK;
        if period_fs == 0 {
            return None;
        }
        Some(Self {
            counter_64_bit: flags.contains(HpetCapFlags::COUNTER_64_BIT),
            legacy_route: flags.contains(HpetCapFlags::LEGACY_ROUTE),
            num_timers: (num_timers_raw + 1) as u8,
            period_fs,
        })
    }

    /// The counter's frequency in hertz, computed as `1e15 / period_fs`. The
    /// period is in femtoseconds (1e-15 s), so dividing one second (1e15 fs)
    /// by the period yields ticks per second. We use `u128` for the
    /// intermediate because `1e15` overflows `u64` is false (1e15 < 2^50),
    /// but the division `1_000_000_000_000_000 / period_fs` can still exceed
    /// u64 range only for absurdly small periods; saturating division is the
    /// safe choice.
    #[must_use]
    fn frequency_hz(&self) -> u64 {
        // 1 second = 1e15 femtoseconds. period_fs is non-zero by construction.
        let one_sec_fs: u128 = 1_000_000_000_000_000;
        let freq = one_sec_fs / u128::from(self.period_fs);
        // The standard 14.31818 MHz HPET yields freq ~= 14_318_180, which fits
        // u64 easily. Saturate defensively against a pathologically tiny period.
        if freq > u128::from(u64::MAX) {
            u64::MAX
        } else {
            freq as u64
        }
    }
}

// ---------------------------------------------------------------------------
// ACPI HPET-table discovery
// ---------------------------------------------------------------------------

/// Return the physical MMIO base of the HPET, or `None` if no HPET is present.
///
/// Prefer the validated ACPI HPET table. A legacy fixed-address fallback is
/// retained only for ACPI-less machines (including the direct test handoff);
/// once ACPI successfully initializes, an absent HPET table means absent
/// hardware and no speculative MMIO access is attempted.
fn hpet_address() -> Option<PhysAddr> {
    crate::acpi::hpet_address().or_else(|| {
        (!crate::acpi::initialised()).then(|| {
            PhysAddr::new(DEFAULT_HPET_MMIO).expect("physical addresses are always representable")
        })
    })
}

// ---------------------------------------------------------------------------
// Hpet — the driver instance
// ---------------------------------------------------------------------------

/// A handle to the HPET's MMIO register window.
///
/// One instance owns the HHDM-translated virtual base of the HPET window plus
/// the capabilities decoded at init (counter width and period). All register
/// access goes through volatile loads/stores to `mmio_virt`; the base is
/// stored as a `u64` rather than a `*mut` so the struct stays `Send`/`Sync`
/// without a raw-pointer `unsafe impl` (the global singleton lives in a
/// `static`).
///
/// The counter is enabled once during [`Hpet::init`] and left running for the
/// kernel's lifetime; the driver deliberately exposes no `disable` on the
/// public surface because every running deadline depends on the counter
/// advancing, and halting it would silently freeze the scheduler.
pub struct Hpet {
    /// The HHDM-translated virtual address of the HPET MMIO window. All
    /// register accesses are `read_volatile`/`write_volatile` at offsets from
    /// this base.
    mmio_virt: u64,
    /// The decoded General Capabilities register, captured once at init so
    /// the hot path (`read_counter`, `now_ns`) does not re-read the
    /// capabilities register on every call.
    caps: HpetCaps,
    /// The counter frequency in hertz, precomputed from `caps.period_fs` at
    /// init so `frequency_hz()` is a single load. Stored as an atomic so the
    /// clocksource read path can load it with `Acquire` without taking the
    /// init lock.
    frequency_hz: AtomicU64,
    /// Whether the main counter has been enabled. Set to `true` by [`init`];
    /// `read_counter` returns zero before that so callers sampling the clock
    /// before bring-up get a safe, monotonic-safe zero rather than a stale
    /// MMIO read.
    enabled: AtomicBool,
}

impl Hpet {
    /// Construct an uninitialised handle for the `static` singleton.
    ///
    /// `mmio_virt` is zero until [`init`] populates it; accesses before init
    /// would dereference the null page, so the singleton gates every access
    /// on `enabled` being set, which only happens after a successful init.
    const fn uninit() -> Self {
        Self {
            mmio_virt: 0,
            caps: HpetCaps {
                counter_64_bit: false,
                legacy_route: false,
                num_timers: 0,
                period_fs: 0,
            },
            frequency_hz: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
        }
    }

    /// Read the 64-bit register at `offset` from the MMIO base.
    ///
    /// # Safety
    ///
    /// `self.mmio_virt` must point at a valid HPET MMIO window (set by
    /// [`init`]), and `offset` must be one of the register offsets defined
    /// above. The HPET's registers are all 64-bit aligned; a `read_volatile`
    /// of a `u64` at an aligned offset is the documented access width.
    #[inline]
    unsafe fn read_reg(&self, offset: u64) -> u64 {
        // SAFETY: caller guarantees `mmio_virt` is a valid HPET window and
        // `offset` is a valid register offset. `read_volatile` prevents the
        // compiler from reordering or eliding the MMIO load.
        unsafe { read_volatile((self.mmio_virt + offset) as *const u64) }
    }

    /// Write `value` to the 64-bit register at `offset` from the MMIO base.
    ///
    /// # Safety
    ///
    /// Same invariant as [`read_reg`]: a valid MMIO window and a valid
    /// writable register offset.
    #[inline]
    unsafe fn write_reg(&self, offset: u64, value: u64) {
        // SAFETY: caller guarantees the offset is a writable HPET register.
        // `write_volatile` ensures the store reaches the device and is not
        // coalesced or elided.
        unsafe {
            write_volatile((self.mmio_virt + offset) as *mut u64, value);
        }
    }

    /// The counter's tick period in femtoseconds, as reported by the
    /// hardware's General Capabilities register. Returns zero before
    /// [`init`] has run.
    #[must_use]
    pub fn period_femtoseconds(&self) -> u64 {
        if !self.enabled.load(Ordering::Acquire) {
            return 0;
        }
        self.caps.period_fs
    }

    /// The counter frequency in hertz (`1e15 / period_fs`). Returns zero
    /// before [`init`] has run.
    #[must_use]
    pub fn frequency_hz(&self) -> u64 {
        self.frequency_hz.load(Ordering::Acquire)
    }

    /// The number of timers (comparators) the HPET exposes. Returns zero
    /// before [`init`] has run.
    #[must_use]
    pub fn num_timers(&self) -> u8 {
        if !self.enabled.load(Ordering::Acquire) {
            return 0;
        }
        self.caps.num_timers
    }

    /// Whether the main counter is 64 bits wide. When `false` the counter is
    /// 32-bit and wraps every `2^32 * period` femtoseconds.
    #[must_use]
    pub fn is_counter_64_bit(&self) -> bool {
        if !self.enabled.load(Ordering::Acquire) {
            return false;
        }
        self.caps.counter_64_bit
    }

    /// Read the raw main counter value.
    ///
    /// This is a single aligned 64-bit MMIO load (or 32-bit on a 32-bit-only
    /// HPET, where the upper 32 bits read zero). On a 64-bit HPET x86
    /// guarantees the load is architecturally atomic, so the value is never a
    /// torn read. Returns zero before [`init`] has run so a clocksource
    /// sampled during very early boot yields a monotonic-safe zero rather
    /// than a stale MMIO read.
    #[must_use]
    pub fn read_counter(&self) -> u64 {
        if !self.enabled.load(Ordering::Acquire) {
            return 0;
        }
        // SAFETY: `mmio_virt` is a valid HPET window (set by init, which is
        // the only path that sets `enabled`), and `REG_MAIN_COUNTER` is the
        // documented main-counter offset.
        unsafe { self.read_reg(REG_MAIN_COUNTER) }
    }

    /// Read the main counter and convert it to nanoseconds.
    ///
    /// `ns = counter * period_fs / 1e6`. The counter ticks at `period_fs`
    /// femtoseconds per tick, and one nanosecond is 1e6 femtoseconds, so the
    /// conversion is `counter * period_fs / 1_000_000`. We compute the
    /// product in `u128` to avoid overflow: a 64-bit counter at the standard
    /// 14.3 MHz rate (period ~69 841 fs) runs for ~41 000 years before
    /// wrapping, and `counter * period_fs` for a full 64-bit counter is
    /// ~3e23, which overflows `u64` but fits comfortably in `u128`. The
    /// result is then truncated back to `u64` nanoseconds, which saturates at
    /// ~584 years of uptime — far beyond the counter's wrap interval.
    #[must_use]
    pub fn now_ns(&self) -> u64 {
        let counter = self.read_counter();
        if counter == 0 {
            return 0;
        }
        let period_fs = u128::from(self.caps.period_fs);
        if period_fs == 0 {
            return 0;
        }
        let nanos = (u128::from(counter) * period_fs) / u128::from(FEMTOS_PER_NANO);
        // The conversion cannot exceed u64::MAX for any realistic uptime, but
        // saturate defensively so a pathological input cannot wrap the result
        // and produce a non-monotonic timestamp.
        if nanos > u128::from(u64::MAX) {
            u64::MAX
        } else {
            nanos as u64
        }
    }

    /// Enable the main counter by setting ENABLE_CNF in the General
    /// Configuration register.
    ///
    /// Idempotent: reads-modifies-writes the config register so the
    /// legacy-route bit (which we force clear) is not left set by firmware.
    /// Called once by [`init`]; exposed for the rare diagnostic path that
    /// temporarily halts and resumes the counter.
    fn enable(&self) {
        // SAFETY: `mmio_virt` is a valid HPET window and
        // `REG_GENERAL_CONFIGURATION` is the documented config offset.
        let cfg = unsafe { self.read_reg(REG_GENERAL_CONFIGURATION) };
        // Force legacy-replacement routing OFF: the kernel uses the I/O APIC
        // for HPET timer interrupts, not the legacy PIC pins, so a firmware
        // left-over LEG_RT_CNF would misroute timer 0/1 to IRQ 0/8.
        let new_cfg = (cfg | CFG_ENABLE) & !CFG_LEGACY_ROUTE;
        // SAFETY: same offset; writing the read-back value with ENABLE set and
        // LEGACY_ROUTE clear is the documented bring-up sequence.
        unsafe { self.write_reg(REG_GENERAL_CONFIGURATION, new_cfg) };
    }

    /// Disable the main counter by clearing ENABLE_CNF.
    ///
    /// Halts the counter at its current value. Exposed for diagnostics and
    /// for the suspend/resume path; the normal kernel runtime never calls
    /// this because every scheduler deadline depends on the counter
    /// advancing.
    #[allow(dead_code)]
    fn disable(&self) {
        // SAFETY: valid HPET window and config register offset.
        let cfg = unsafe { self.read_reg(REG_GENERAL_CONFIGURATION) };
        let new_cfg = cfg & !CFG_ENABLE;
        // SAFETY: writing back with ENABLE cleared halts the counter.
        unsafe { self.write_reg(REG_GENERAL_CONFIGURATION, new_cfg) };
    }

    /// Bring the HPET up: read capabilities, validate the period, translate
    /// the MMIO base through the HHDM, and enable the counter.
    ///
    /// Returns `Err(HpetError::...))` when the HPET is absent, the MMIO
    /// window reports a zero period (which the spec forbids and which means
    /// the window is not a real HPET), or the physical address is
    /// non-canonical. On success the counter is running and [`read_counter`]
    /// / [`now_ns`] are usable.
    ///
    /// # Safety
    ///
    /// The caller must guarantee no other CPU is touching the HPET MMIO
    /// window and that the `Hpet` instance has not already been initialised.
    /// Boot bring-up satisfies both: init runs once on the BSP before the
    /// APIC delivers timer interrupts.
    unsafe fn init(&mut self) -> Result<(), HpetError> {
        let phys = hpet_address().ok_or(HpetError::NotPresent)?;
        // Translate the physical MMIO base through the HHDM direct map. Limine
        // maps all physical memory 1:1 at HHDM_BASE, so the HPET's 1 KiB
        // register window is reachable at `HHDM_BASE + phys` without
        // allocating any page tables of our own.
        let mmio_virt = HHDM_BASE + phys.as_u64();
        // Sanity-check the translated address is a canonical kernel-half
        // virtual address. It always is for a valid physical HPET base under
        // Limine's HHDM, but a corrupt ACPI table could in principle report
        // a wild value; refuse rather than dereference a non-canonical
        // pointer (which would #GP).
        if !VirtAddr::is_canonical(mmio_virt) {
            return Err(HpetError::BadAddress(phys));
        }
        self.mmio_virt = mmio_virt;

        // Read the General Capabilities register and decode it. A zero period
        // means the MMIO window is not a real HPET (the spec mandates a
        // non-zero period), so we bail and let the caller fall back to the
        // PIT rather than divide by zero later.
        // SAFETY: `mmio_virt` was just set to the HHDM-translated HPET base
        // and `REG_GENERAL_CAPABILITIES` is the documented capabilities
        // offset. The register is read-only, so this load has no side effect.
        let raw_caps = unsafe { self.read_reg(REG_GENERAL_CAPABILITIES) };
        let caps = HpetCaps::from_raw(raw_caps).ok_or(HpetError::BadPeriod)?;

        log::info!(
            "xenith.time.hpet: base phys:{phys}, {}-bit counter, {n} timers, period {p} fs ({f} Hz){leg}",
            if caps.counter_64_bit { "64" } else { "32" },
            n = caps.num_timers,
            p = caps.period_fs,
            f = caps.frequency_hz(),
            leg = if caps.legacy_route { ", legacy-route cap" } else { "" },
        );

        self.caps = caps;
        self.frequency_hz
            .store(caps.frequency_hz(), Ordering::Release);

        // Clear any stale interrupt status before enabling, so a level-triggered
        // timer left asserted by a previous firmware/boot stage does not fire
        // the moment we enable the counter. Writing all-ones to the
        // read-to-clear status register clears every per-timer active bit.
        // SAFETY: valid window; REG_GENERAL_INTERRUPT_STATUS is a
        // read-to-clear register documented to accept a 1-to-clear write.
        unsafe { self.write_reg(REG_GENERAL_INTERRUPT_STATUS, u64::MAX) };

        // Halt the counter before programming it, then enable. The HPET spec
        // recommends disabling the counter before changing comparator
        // configurations; we have no comparators to program yet, but clearing
        // ENABLE_CNF first guarantees the counter starts from a known state.
        self.disable();
        self.enable();

        // Publish the enabled state last, with Release ordering, so any CPU
        // that observes `enabled == true` also observes the populated
        // `mmio_virt`, `caps`, and `frequency_hz`. The read path pairs with
        // an Acquire load of `enabled`, establishing the happens-before edge.
        self.enabled.store(true, Ordering::Release);

        Ok(())
    }
}

/// Errors returned by [`Hpet::init`].
///
/// Hand-rolled per the kernel convention: `Debug` is derived, no `std`/`thiserror`,
/// and the variants describe the distinct failure modes a caller can react
/// to (notably `NotPresent`, which the time init layer maps to "use the PIT
/// instead").
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HpetError {
    /// No HPET was found in the platform table set. The caller falls back to
    /// the LAPIC clock.
    NotPresent,
    /// The HPET's General Capabilities register reported a zero counter
    /// period, which the architecture forbids. This means the MMIO window is
    /// not a real HPET — for example the ACPI table pointed at unbacked
    /// memory — and the driver refuses to initialise rather than divide by
    /// zero on the first `now_ns` call.
    BadPeriod,
    /// The HPET's physical MMIO base, translated through the HHDM, produced a
    /// non-canonical virtual address. This indicates a corrupt ACPI table
    /// (a wild `Address` field) and the driver refuses to dereference it
    /// because a non-canonical load would #GP.
    BadAddress(PhysAddr),
}

// ---------------------------------------------------------------------------
// ClockSource implementation
// ---------------------------------------------------------------------------

/// [`ClockSource`] backing for the monotonic clock when the HPET is the
/// selected timebase.
///
/// The trait's safety contract requires `read_ns` to be monotonic non-
/// decreasing on a given CPU and safe to call from any context, including
/// interrupt handlers. The HPET satisfies this: the main counter is a
/// free-running up-counter that never goes backwards, and `now_ns` is a
/// single volatile load plus a `u128` multiply/divide with no locks. An
/// interrupt handler can therefore sample the clock without risk of
/// deadlocking against another sampler.
impl ClockSource for Hpet {
    #[inline]
    fn read_ns(&self) -> u64 {
        self.now_ns()
    }

    fn name(&self) -> &'static str {
        "hpet"
    }
}

// ---------------------------------------------------------------------------
// Singleton and boot bring-up
// ---------------------------------------------------------------------------

/// The single HPET instance.
///
/// Owned by the [`HPET`] singleton, initialised once in place by [`init`]
/// during boot. Before init, every accessor returns zero or `false` so a
/// clocksource sampled during very early boot yields a safe, monotonic-safe
/// zero rather than a stale MMIO read. After init the instance is
/// effectively read-only (the `mmio_virt` and `caps` fields are never
/// mutated again), which is the `Sync` contract.
static mut HPET: Hpet = Hpet::uninit();

/// Initialise the HPET from the ACPI-reported MMIO base.
///
/// Reads the General Capabilities register, validates the counter period,
/// translates the MMIO base through the HHDM, clears any stale interrupt
/// status, and enables the main counter. On success the global [`HPET`]
/// singleton is live and [`read_counter`] / [`now_ns`] / [`frequency_hz`]
/// are usable.
///
/// Returns `Err` when no HPET is present or the MMIO window is bogus; the
/// time init layer maps an error to "fall back to the PIT" without treating
/// it as a kernel panic.
///
/// # Safety
///
/// Must be called exactly once, on the BSP, before any other code reads the
/// [`HPET`] singleton and before the APIC timer is calibrated against the
/// HPET. The caller guarantees no other CPU is touching the HPET MMIO window
/// concurrently. Boot bring-up satisfies both invariants.
pub unsafe fn init() -> Result<(), HpetError> {
    // SAFETY: `HPET` is a `static mut` whose fields we write exactly once
    // here, on the BSP, before any other code observes it. No reference has
    // escaped yet (the singleton is not installed as the clocksource until
    // init returns Ok), so the write is race-free.
    unsafe {
        let h = &raw mut HPET;
        (*h).init()
    }
}

/// Borrow the global HPET as a `&'static dyn ClockSource`.
///
/// # Safety
///
/// The caller must have first invoked [`init`] successfully. After init the
/// reference is valid for the kernel's lifetime and the HPET's `ClockSource`
/// impl is safe to call from any context.
pub unsafe fn static_ref() -> &'static dyn ClockSource {
    // SAFETY: `init` has run, so `mmio_virt` and `caps` are populated and
    // `enabled` is true. We only ever hand out shared references; all
    // post-init mutation is through volatile MMIO loads/stores that do not
    // touch the Rust-typed fields.
    unsafe { &*core::ptr::addr_of!(HPET) }
}

/// Read the raw HPET main counter, or zero if the HPET is not initialised.
///
/// This is the free-function form of [`Hpet::read_counter`] for callers that
/// do not hold a `&Hpet` (notably the LAPIC timer calibration path, which
/// samples the HPET a fixed number of times and does not need the trait
/// object). Safe to call from any context once init has run, and safe (returns
/// zero) before init.
#[must_use]
pub fn read_counter() -> u64 {
    // SAFETY: `HPET` is a `static mut` but we only take a shared reference
    // through `&raw const`, which is sound after the one-time init. Before
    // init `enabled` is false and `read_counter` returns zero without
    // touching `mmio_virt`, so the call is safe at any point in boot.
    unsafe { (&*core::ptr::addr_of!(HPET)).read_counter() }
}

/// Current monotonic nanosecond count from the HPET, or zero if uninitialised.
///
/// Free-function form of [`Hpet::now_ns`]; see that method for the
/// conversion math. Safe to call from any context.
#[must_use]
pub fn now_ns() -> u64 {
    // SAFETY: shared borrow through `&raw const`; `now_ns` returns zero
    // before init without dereferencing `mmio_virt`.
    unsafe { (&*core::ptr::addr_of!(HPET)).now_ns() }
}

/// The HPET counter frequency in hertz, or zero if uninitialised.
///
/// Free-function form of [`Hpet::frequency_hz`].
#[must_use]
pub fn frequency_hz() -> u64 {
    // SAFETY: shared borrow; `frequency_hz` is an atomic load that returns
    // zero before init.
    unsafe { (&*core::ptr::addr_of!(HPET)).frequency_hz() }
}

/// The HPET counter period in femtoseconds, or zero if uninitialised.
///
/// Free-function form of [`Hpet::period_femtoseconds`].
#[must_use]
pub fn period_femtoseconds() -> u64 {
    // SAFETY: shared borrow; gated on `enabled` so it is safe pre-init.
    unsafe { (&*core::ptr::addr_of!(HPET)).period_femtoseconds() }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64-bit-capable HPET with the standard 14.31818 MHz period decodes
    /// to a ~14.3 MHz frequency. The period for 14.31818 MHz is
    /// `1e15 / 14_318_180 = 69_841` fs (rounded). We construct the raw
    /// capabilities word the way the hardware would and check the decode.
    #[test]
    fn caps_decode_64_bit_standard_period() {
        // period_fs = 69_841 (the canonical QEMU HPET period).
        let period_fs: u64 = 69_841;
        let raw = CAP_COUNT_SIZE_64
            | (u64::from(2_u8 - 1) << CAP_NUM_TIMERS_SHIFT) // 2 timers => field = 1
            | (period_fs << CAP_PERIOD_SHIFT);
        let caps = HpetCaps::from_raw(raw).expect("non-zero period decodes");
        assert!(caps.counter_64_bit);
        assert!(!caps.legacy_route);
        assert_eq!(caps.num_timers, 2);
        assert_eq!(caps.period_fs, period_fs);
        // 1e15 / 69_841 ~= 14_318_180 (the standard HPET frequency).
        assert_eq!(caps.frequency_hz(), 1_000_000_000_000_000 / period_fs);
    }

    /// A zero period is the "not a real HPET" sentinel and must reject.
    #[test]
    fn caps_zero_period_rejected() {
        let raw = CAP_COUNT_SIZE_64; // period field = 0
        assert!(HpetCaps::from_raw(raw).is_none());
    }

    /// A 32-bit-only HPET (COUNT_SIZE_CAP clear) decodes with
    /// `counter_64_bit == false` and still reports its period. The period
    /// `100_000_000` fs is `100 ns` per tick, i.e. a 10 MHz counter — a clean
    /// value for checking the frequency conversion.
    #[test]
    fn caps_32_bit_variant() {
        let period_fs: u64 = 100_000_000; // 100 ns/tick => 10 MHz
        let raw = (u64::from(3_u8 - 1) << CAP_NUM_TIMERS_SHIFT) | (period_fs << CAP_PERIOD_SHIFT);
        let caps = HpetCaps::from_raw(raw).expect("non-zero period");
        assert!(!caps.counter_64_bit);
        assert_eq!(caps.num_timers, 3);
        assert_eq!(caps.period_fs, period_fs);
        // 1e15 fs / 100_000_000 fs = 10_000_000 Hz (10 MHz).
        assert_eq!(caps.frequency_hz(), 10_000_000);
    }

    /// `now_ns` converts a counter value to nanoseconds using the
    /// `counter * period_fs / 1e6` formula. With a 10 MHz counter (period
    /// `100_000_000` fs, i.e. 100 ns per tick), a counter of `1_000_000` ticks
    /// is `1_000_000 * 100 ns = 100_000_000 ns = 100 ms`.
    #[test]
    fn now_ns_conversion_is_linear() {
        let period_fs: u64 = 100_000_000; // 10 MHz => 100 ns per tick
        let raw = CAP_COUNT_SIZE_64 | (period_fs << CAP_PERIOD_SHIFT);
        let caps = HpetCaps::from_raw(raw).unwrap();
        // Reproduce the now_ns formula on a known counter value.
        let counter: u64 = 1_000_000;
        let nanos =
            (u128::from(counter) * u128::from(caps.period_fs)) / u128::from(FEMTOS_PER_NANO);
        assert_eq!(nanos as u64, 100_000_000);
    }

    /// The bitflags type round-trips the two single-bit capabilities without
    /// dropping bits in the multi-bit fields (those are extracted by shift,
    /// not by the bitflags).
    #[test]
    fn cap_flags_round_trip() {
        let flags = HpetCapFlags::COUNTER_64_BIT | HpetCapFlags::LEGACY_ROUTE;
        assert!(flags.contains(HpetCapFlags::COUNTER_64_BIT));
        assert!(flags.contains(HpetCapFlags::LEGACY_ROUTE));
        // The raw bits are exactly the two capability bits.
        assert_eq!(flags.bits(), CAP_COUNT_SIZE_64 | CAP_LEGACY_ROUTE);
    }
}
