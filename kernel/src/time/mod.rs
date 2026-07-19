//! Kernel time subsystem: timers, the RTC wall clock, and the monotonic clock.
//!
//! This module is the single home for everything time-related in Xenith. It
//! owns four cooperating pieces:
//!
//! * [`pit`] — the 8254 Programmable Interval Timer. The oldest PC timer and
//!   the calibration reference (its 1.193182 MHz input is a hard-wired
//!   constant), plus a last-resort periodic tick and an early-boot one-shot
//!   delay.
//! * [`lapic_timer`] — the per-CPU Local APIC timer. One-shot and periodic
//!   modes, calibration hook, and the LAPIC-backed [`clock::ClockSource`].
//!   The scheduler's steady tick runs on this timer.
//! * [`rtc`] — the CMOS Real-Time Clock. The battery-backed wall clock read
//!   once at boot to seed the monotonic clock's epoch.
//! * [`clock`] — `Instant`, `Duration`, the [`clock::MonotonicClock`], and
//!   the [`clock::ClockSource`] trait. The single source of monotonic time
//!   (`uptime_ns`, `Instant::now`) and wall time (`wall_time`).
//!
//! Two helper modules factor out reusable logic:
//!
//! * [`calibration`] — the routine that measures the LAPIC timer's tick rate
//!   against the PIT. Kept separate from [`lapic_timer`] so the measurement
//!   algorithm can be reused (e.g. against an HPET reference) without
//!   touching the hardware programming.
//! * [`hpet`] — the High Precision Event Timer. When present, its 64-bit
//!   free-running main counter is the preferred monotonic clocksource (it
//!   never wraps in practice and runs at a higher frequency than the LAPIC
//!   accumulator). [`init`] brings it up when present and falls back to the
//!   LAPIC clocksource otherwise.
//!
//! # Boot-time wiring
//!
//! [`init`] runs once during kernel bring-up, after the APIC and memory
//! subsystems are up. It:
//!
//! 1. Brings up the LAPIC timer ([`lapic_timer::init`]) — chooses xAPIC vs.
//!    x2APIC, enables the APIC, and sets the divide configuration.
//! 2. Calibrates the LAPIC timer's tick rate against the PIT
//!    ([`calibration::calibrate_lapic_ticks_per_sec`]) and records it.
//! 3. Attempts to bring up the HPET. If the HPET is present and usable, its
//!    clocksource is preferred; otherwise the LAPIC clocksource is used.
//! 4. Reads the RTC once to obtain the boot wall-clock epoch.
//! 5. Installs the selected clocksource and the boot epoch into the global
//!    [`clock::MONOTONIC`] clock, after which [`clock::uptime_ns`],
//!    [`clock::Instant::now`], and [`clock::wall_time`] are live.
//!
//! The scheduler phase later arms the LAPIC timer's periodic tick
//! ([`lapic_timer::set_tick`]) and wires the timer-vector IRQ handler to
//! [`lapic_timer::on_tick`]; until then the LAPIC clocksource reads zero,
//! which is why the HPET (a free-running counter that needs no IRQ) is
//! preferred when available.
//!
//! # Layering
//!
//! `time` sits above `arch` (for port I/O, MSRs, and CPUID) and `sync`, and
//! below `sched` (which consumes the tick) and every driver that timestamps
//! events. The RTC and PIT drivers touch only port I/O; the LAPIC timer
//! touches MSRs and the HHDM-mapped MMIO window; the clock module holds only
//! atomics and a `&'static dyn ClockSource`.

pub mod calibration;
pub mod clock;
pub mod hpet;
pub mod lapic_timer;
pub mod pit;
pub mod rtc;

// Flat re-exports so callers can write `use crate::time::Instant` instead of
// drilling into submodules. The submodule paths remain available for callers
// that want to scope imports explicitly. `DateTime` lives in `rtc` (it is the
// RTC's wall-clock type) but is re-exported here so the common time imports
// resolve from the module root.
pub use clock::{uptime_ns, wall_time, ClockSource, Duration, Instant, MonotonicClock};
pub use rtc::DateTime;

// ---------------------------------------------------------------------------
// Boot-time wiring
// ---------------------------------------------------------------------------

/// Bring up the kernel time subsystem.
///
/// Runs once during `init::init`, after the APIC and memory subsystems are
/// online. Calibrates the LAPIC timer, selects the best available monotonic
/// clocksource (HPET if present, otherwise the LAPIC accumulator), reads the
/// RTC to seed the wall-clock epoch, and installs both into the global
/// [`clock::MONOTONIC`] clock.
///
/// After this returns, [`uptime_ns`] and [`wall_time`] are live (modulo the
/// LAPIC clocksource's need for a running periodic tick — see the module
/// docs). The scheduler phase arms the periodic tick separately.
///
/// This function is idempotent in the sense that re-running it would
/// re-calibrate and re-install the clock, but it is intended to be called
/// exactly once; the `MONOTONIC` install path debug-asserts against a second
/// install.
pub fn init() {
    // ---- 1. LAPIC timer hardware ----------------------------------------
    // Choose xAPIC vs. x2APIC, enable the APIC, set the divide configuration.
    // Until this runs the LAPIC register accessors are unusable, so
    // calibration must come after it.
    lapic_timer::init();

    // ---- 2. Calibrate the LAPIC tick rate against the PIT ---------------
    // Measures how many LAPIC ticks elapse in a PIT-measured window and
    // stores the per-second rate. `set_tick` and the LAPIC clocksource use
    // this to convert ticks to nanoseconds.
    let lapic_freq = calibration::calibrate_lapic_ticks_per_sec();
    lapic_timer::set_frequency(lapic_freq);

    // ---- 3. Select the monotonic clocksource ----------------------------
    // Prefer the HPET when it is available: its 64-bit main counter is
    // free-running (no IRQ accumulation needed) and never wraps in practice,
    // so `uptime_ns` is live immediately. Fall back to the LAPIC accumulator,
    // which needs the scheduler to arm a periodic tick before it produces
    // useful values.
    //
    // The HPET surface is provided by the parallel `hpet` phase. The assumed
    // API is minimal: `hpet::try_init() -> Option<&'static dyn ClockSource>`
    // brings up the HPET and returns its published clocksource, or `None` if
    // no HPET is present. If the HPET phase exposes a different surface, only
    // this one call site needs adjusting.
    let source: &'static dyn ClockSource = if unsafe { hpet::init() }.is_ok() {
        // SAFETY: `hpet::init` just succeeded and publishes immutable device
        // metadata before this shared reference escapes.
        unsafe { hpet::static_ref() }
    } else {
        &lapic_timer::LAPIC_CLOCK
    };
    ::log::info!("xenith.time: monotonic clocksource = {}", source.name(),);

    // ---- 4. Seed the wall-clock epoch from the RTC ----------------------
    // Read the CMOS RTC once. The RTC read is slow (it disables interrupts
    // and may wait for the update-in-progress bit to clear) and must not be
    // on the `wall_time` hot path, so we capture the boot epoch here and
    // advance it from the monotonic clock thereafter. A garbage RTC read
    // (e.g. month 0) degrades to a zero epoch rather than panicking, so a
    // dead CMOS battery does not block boot.
    let boot_dt = rtc::now();
    let boot_epoch_ns = boot_dt.to_unix_nanos().unwrap_or(0);
    ::log::info!(
        "xenith.time: boot wall clock {} (epoch {} ns)",
        boot_dt,
        boot_epoch_ns,
    );

    // ---- 5. Install the clock -------------------------------------------
    // Wires the selected clocksource and the RTC epoch into the global
    // `MONOTONIC` clock. After this returns, `uptime_ns`, `Instant::now`,
    // and `wall_time` are live.
    clock::MONOTONIC.install(source, boot_epoch_ns);
}
