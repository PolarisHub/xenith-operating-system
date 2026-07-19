//! LAPIC timer calibration — measuring the timer's tick rate against the PIT.
//!
//! The LAPIC timer's input clock is the APIC bus clock divided by the DCR
//! divisor. Neither quantity is knowable in advance: the bus clock varies
//! with the platform (it is often the TSC rate, or a derived frequency, but
//! never a hard-wired constant like the PIT's 1.193182 MHz), and the divisor
//! is an encoded value we pick once in [`super::lapic_timer::init`]. The only
//! way to obtain the timer's effective tick rate is to measure it against a
//! reference with a known frequency.
//!
//! # The PIT as reference
//!
//! The 8254 PIT is the one PC timer whose input frequency is a hard-wired
//! constant (the NTSC colour-burst crystal divided by three, 1.193182 MHz),
//! so it is the calibration reference for every other timer. [`super::pit`]
//! exposes [`pit::calibrate_peer_hz`], a primitive that measures a caller's
//! counter over a known interval defined by N mode-2 PIT wraps and returns
//! the counter's frequency in Hz. The interval is exact in PIT input cycles
//! (`periods * divider`), so the recovered frequency is as accurate as the
//! PIT crystal — well under the ~1% the scheduler tick needs.
//!
//! # Algorithm
//!
//! 1. Programme the PIT channel 0 in mode 2 at ~100 Hz
//!    ([`pit::start_calibration_tick`]). The counter wraps at a known rate
//!    regardless of whether IRQ 0 is delivered.
//! 2. Arm the LAPIC timer in one-shot mode with an initial count of
//!    `0xFFFF_FFFF` (the maximum) and a high dummy vector. The counter
//!    begins counting down from `0xFFFF_FFFF`. With a ~1 GHz tick rate this
//!    represents ~4.3 seconds of countdown — far longer than the
//!    calibration window — so the timer does not reach zero and no
//!    interrupt is delivered during measurement.
//! 3. Call [`pit::calibrate_peer_hz`] with a peer reader that returns the
//!    LAPIC counter as an *up*-counting value (`MAX - current_count`). The
//!    primitive reads the peer before and after the known PIT interval and
//!    returns `delta * PIT_FREQUENCY / pit_cycles` — the LAPIC tick rate in
//!    Hz.
//! 4. Mask the LAPIC timer to quiesce the counter and stop the PIT.
//!
//! Because calibration measures the *effective* tick rate (post-divisor), the
//! exact DCR encoding does not affect correctness — only granularity. The
//! DCR is programmed once in [`super::lapic_timer::init`] and left; the
//! measured rate is the runtime rate.
//!
//! # Why not HPET as the reference?
//!
//! On systems with an HPET, the HPET main counter is a higher-resolution
//! reference than the PIT (64-bit, no wrap, higher frequency). The
//! [`pit::calibrate_peer_hz`] primitive is generic over the peer reader, so
//! an HPET-relative calibration can drop in by replacing the PIT interval
//! with an HPET-relative one; the LAPIC-side measurement is identical. This
//! phase uses the PIT because it is always present and its frequency is a
//! hard-wired constant, so calibration works before the HPET is mapped.

use super::{lapic_timer, pit};

/// The number of mode-2 PIT wraps to count over. At the default ~100 Hz
/// calibration tick (divider `11_932`) one wrap is ~10 ms, so three wraps is
/// ~30 ms — long enough that PIT quantisation is negligible, short enough
/// that boot is not delayed. The LAPIC's `0xFFFF_FFFF` one-shot countdown
/// lasts ~4.3 s at 1 GHz, so 30 ms is safely inside the no-expiry window.
const PERIODS: u32 = 3;

/// A high dummy vector used while calibrating. The LAPIC timer is armed
/// one-shot with this vector; because the countdown does not reach zero in
/// the calibration window, no interrupt is delivered. The vector is kept in
/// the non-exception range (`0x20..=0xFF`) so that even an unexpected expiry
/// would route to a generic IRQ vector rather than a CPU exception.
const CAL_VECTOR: u8 = 0xFE;

/// The maximum initial count used for calibration. With a ~1 GHz LAPIC tick
/// this represents ~4.3 s of countdown, far longer than the ~30 ms
/// calibration window.
const MAX_COUNT: u64 = 0xFFFF_FFFF;

/// Conservative fallback rate if calibration fails to measure a non-zero
/// delta. This indicates broken LAPIC or PIT access; returning zero would
/// make `set_tick` divide by zero, so a coarse 10 MHz default keeps the
/// kernel able to arm a tick while the failure is logged.
const FALLBACK_HZ: u64 = 10_000_000;

/// Calibrate the LAPIC timer's tick rate against the PIT and return the
/// measured rate in ticks per second.
///
/// Programmes the PIT in mode 2, arms the LAPIC timer's one-shot countdown,
/// measures the LAPIC counter over [`PERIODS`] PIT wraps via
/// [`pit::calibrate_peer_hz`], then quiesces both timers. The caller
/// ([`super::lapic_timer::set_frequency`] via `time::init`) stores the result
/// for use by [`lapic_timer::set_tick`] and the LAPIC clocksource.
///
/// Returns [`FALLBACK_HZ`] if the measurement yields no usable delta, so a
/// broken calibration does not leave the timer uncalibrated.
///
/// # Panics
///
/// In debug builds, asserts that the LAPIC timer has been initialised (so
/// the raw arm/read primitives are safe to drive).
#[must_use]
pub fn calibrate_lapic_ticks_per_sec() -> u64 {
    debug_assert!(
        lapic_timer::is_ready(),
        "xenith.time.calibration: lapic_timer::init must run first"
    );

    // Start the PIT in mode 2 at the ~100 Hz calibration rate. The counter
    // wraps at a known rate whether or not IRQ 0 is delivered, which is what
    // calibrate_peer_hz measures.
    pit::start_calibration_tick();

    // Arm the LAPIC one-shot countdown from the maximum. Unmasked so the
    // counter runs; the countdown is large enough that no interrupt fires
    // within the window.
    lapic_timer::arm_one_shot_raw(MAX_COUNT, CAL_VECTOR);

    // Measure the LAPIC counter over a known PIT interval. The peer reader
    // returns the counter as an up-counting value (elapsed ticks since arm),
    // because calibrate_peer_hz computes `after - before` and expects the
    // peer to advance. `MAX_COUNT - current_count` grows monotonically as the
    // down-counter decrements.
    let peer_reader = || {
        let ccr = lapic_timer::read_current_count();
        // If the counter reads above MAX_COUNT (impossible on real hardware,
        // but a stale or wrapped read could), saturate to zero elapsed rather
        // than underflowing.
        MAX_COUNT.saturating_sub(ccr)
    };
    let measured = pit::calibrate_peer_hz(PERIODS, peer_reader);

    // Quiesce both timers: mask the LAPIC (which also stops its counter) and
    // silence the PIT calibration tick.
    lapic_timer::mask();
    pit::stop();

    match measured {
        Some(hz) if hz != 0 => {
            ::log::info!(
                "xenith.time.calibration: lapic tick rate ~{} Hz ({} PIT wraps)",
                hz,
                PERIODS,
            );
            hz
        },
        _ => {
            ::log::warn!(
                "xenith.time.calibration: measured no LAPIC delta over {} wraps; using fallback {} Hz",
                PERIODS,
                FALLBACK_HZ,
            );
            FALLBACK_HZ
        },
    }
}
