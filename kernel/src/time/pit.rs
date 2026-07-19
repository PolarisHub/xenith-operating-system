//! 8254 Programmable Interval Timer (PIT) driver.
//!
//! The PIT is the oldest PC timer: a 1.193182 MHz counter (the NTSC colour
//! burst frequency divided by 3) that drives three independent 16-bit
//! down-counters reachable through I/O ports `0x40`..`0x43`. Channel 0 is
//! wired to IRQ 0 on the legacy PIC and is the one the kernel uses for
//! calibration and as a last-resort tick; channels 1 (DRAM refresh, unused
//! on modern hardware) and 2 (speaker beeper) are not touched here.
//!
//! # Why the PIT still matters
//!
//! On any system with an HPET, the HPET is the preferred clocksource: it is
//! 64-bit (so it never wraps in practice) and runs at a higher frequency.
//! But the PIT is the only timer whose input frequency is a hard-wired, known
//! constant — every other timer's frequency must be measured against
//! something, and the PIT is the reference. So even on HPET systems we use
//! the PIT to calibrate the LAPIC timer's actual tick rate, and on systems
//! without an HPET the PIT is both the calibration reference and the
//! monotonic clocksource.
//!
//! # Operating modes used here
//!
//! Channel 0 is programmed in two modes depending on the call site:
//!
//! * **Mode 2 (rate generator)** — [`set_mode_2`]. The counter reloads to the
//!   divider after each terminal count and pulses IRQ 0 at
//!   `PIT_FREQUENCY / divider` Hz. Used for the periodic calibration tick and
//!   for the system tick when the PIT is the clocksource.
//! * **Mode 0 (interrupt-on-terminal-count)** — [`pit_sleep`]. The counter
//!   counts down once from the divider to zero and stops. Used for one-shot
//!   delays during early boot before the scheduler is up.
//!
//! # Reading the counter
//!
//! The 16-bit counter can be latched for reading by writing a read-latch
//! command to the control register. We use the latch so a 16-bit read is
//! atomic — otherwise the high and low bytes could be sampled across a
//! counter rollover and produce a garbage value.
//!
//! # Calibration
//!
//! [`calibrate_over_periods`] establishes a *known interval* in PIT input
//! cycles by watching the counter wrap a fixed number of times. Because the
//! PIT input frequency is the hard constant [`PIT_FREQUENCY`], that cycle
//! count is a known wall-time interval. Other timers (LAPIC, TSC) read their
//! own counter before and after this call and divide by the returned cycle
//! count to recover their frequency in Hz.
//!
//! # Safety
//!
//! All PIT accesses are 8-bit port I/O through [`Port8`]. The ports
//! `0x40`..`0x43` are kernel-owned on all PC hardware. Reprogramming
//! channel 0 changes the IRQ 0 rate, which is safe because the legacy PIC
//! is masked (or absent, when the LAPIC is in use) during calibration; the
//! kernel never leaves channel 0 armed in periodic mode once the LAPIC
//! timer takes over the system tick.

use core::sync::atomic::{AtomicU64, Ordering};

use super::clock::ClockSource;
use crate::arch::x86_64::{InterruptGuard, Port8};

// ---------------------------------------------------------------------------
// PIT port and register constants
// ---------------------------------------------------------------------------

/// Channel 0 data port (the counter read/write port for the IRQ 0 channel).
const PIT_CHANNEL_0: Port8 = Port8::new(0x40);
/// Channel 2 data port. Used by the speaker; not touched here but declared
/// for completeness so the port map is in one place.
#[allow(dead_code)]
const PIT_CHANNEL_2: Port8 = Port8::new(0x42);
/// The mode/command register. Writes select the channel, access mode, and
/// operating mode for the next counter programming.
const PIT_MODE: Port8 = Port8::new(0x43);

/// The PIT's input frequency: 1.193182 MHz. This is a hard-wired constant
/// on every PC-compatible part — the oscillator is the NTSC colour-burst
/// crystal (3.579545 MHz) divided by 3. It never varies, which is what
/// makes the PIT the calibration reference.
pub const PIT_FREQUENCY: u64 = 1_193_182;

/// The divider used for the periodic calibration tick. 11_932 yields
/// ~100.0 Hz (1.193182 MHz / 11_932 = 99.998... Hz), which is a convenient
/// rate: slow enough not to flood the PIC, fast enough that a 50 ms
/// calibration window contains ~5 ticks.
pub const PIT_CAL_DIVIDER: u16 = 11_932;

/// Command byte for channel 0, lobyte/hibyte access, mode 2 (rate
/// generator). The bit layout is `SC1 SC0 RW1 RW0 M2 M1 M0 BCD`.
///   - `00`     select channel 0
///   - `11`     lobyte then hibyte access
///   - `010`    mode 2 (rate generator)
///   - `0`      binary (not BCD)
const CMD_CHAN0_MODE2: u8 = 0b0011_0100;

/// Command byte for channel 0, lobyte/hibyte access, mode 0
/// (interrupt-on-terminal-count). Used for one-shot delays.
const CMD_CHAN0_MODE0: u8 = 0b0011_0000;

/// Command byte to latch channel 0's current counter value for reading.
/// The next two reads of `0x40` return the low then high byte of the
/// latched count. `SC1 SC0 = 00`, `RW1 RW0 = 00` (latch), rest zero.
const CMD_CHAN0_LATCH: u8 = 0b0000_0000;

// ---------------------------------------------------------------------------
// PIT state
// ---------------------------------------------------------------------------

/// The accumulated PIT tick count when the PIT is the active clocksource.
///
/// Incremented by the IRQ 0 handler (wired up by the scheduler/device phase)
/// and read by [`PitClock::read_ns`] to produce a monotonic nanosecond
/// count. Before the IRQ is wired, this stays zero and the PIT is only
/// useful for the one-shot delay path.
static PIT_TICKS: AtomicU64 = AtomicU64::new(0);

/// The divider channel 0 was last programmed with. Held in an atomic so a
/// concurrent [`read_counter`] caller can compute elapsed-in-period without
/// racing a reprogram. Stored as `u64` because Rust atomic max width is 64.
static CURRENT_DIVIDER: AtomicU64 = AtomicU64::new(PIT_CAL_DIVIDER as u64);

/// Record one PIT tick. Called by the IRQ 0 handler (future phase). Public
/// so the interrupt dispatcher can call it without this module owning the
/// vector.
pub fn on_tick() {
    PIT_TICKS.fetch_add(1, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Programming
// ---------------------------------------------------------------------------

/// Program channel 0 with `divider` in the given mode.
///
/// Writes the command byte to the mode register, then writes the low and
/// high bytes of the divider to the channel 0 data port. The two byte
/// writes must be performed in order (low then high) because the access
/// mode in the command byte selects the sequence.
///
/// Interrupts are disabled across the three writes so a context switch
/// cannot leave the counter half-programmed. The caller's complete RFLAGS
/// image is restored afterward, so a boot-time caller that entered with IF
/// clear cannot accidentally enable interrupts by programming the PIT.
fn program_channel0(divider: u16, cmd: u8) {
    {
        // SAFETY: PIT programming runs in ring 0. The guard restores the
        // caller's saved RFLAGS when the three-write transaction completes.
        let _interrupt_guard = unsafe { InterruptGuard::disable() };
        PIT_MODE.write(cmd);
        PIT_CHANNEL_0.write((divider & 0xFF) as u8);
        PIT_CHANNEL_0.write(((divider >> 8) & 0xFF) as u8);
    }
    CURRENT_DIVIDER.store(u64::from(divider), Ordering::Release);
}

/// Convert a desired tick rate in Hz to the nearest PIT divider.
///
/// The divider is `PIT_FREQUENCY / hz`, clamped to `1..=65535`. A target of
/// `0` is treated as the slowest rate (divider `0xFFFF`, ~18.2 Hz). The
/// returned tuple is `(divider, achieved_hz)` so the caller can see the
/// realised rate, which differs from the request whenever `hz` does not
/// evenly divide the input frequency.
#[must_use]
pub fn hz_to_divider(hz: u64) -> (u16, u64) {
    if hz == 0 {
        return (0xFFFF, PIT_FREQUENCY / 0xFFFF);
    }
    let divider = (PIT_FREQUENCY / hz).clamp(1, 0xFFFF);
    let achieved = PIT_FREQUENCY / divider;
    (divider as u16, achieved)
}

/// Program channel 0 for mode 2 (rate generator) at approximately `rate_hz`.
///
/// Computes the nearest divider from [`PIT_FREQUENCY`] / `rate_hz`, programs
/// the channel, and returns the achieved rate in Hz (which may differ from
/// the request because the divider is an integer). After this call channel
/// 0 pulses IRQ 0 at the achieved rate; the caller is responsible for
/// routing or masking IRQ 0.
///
/// A `rate_hz` of `0` selects the slowest possible rate (~18.2 Hz).
#[must_use]
pub fn set_mode_2(rate_hz: u64) -> u64 {
    let (divider, achieved) = hz_to_divider(rate_hz);
    program_channel0(divider, CMD_CHAN0_MODE2);
    achieved
}

/// Program channel 0 for mode 0 (one-shot, interrupt-on-terminal-count)
/// with the given `divider`. The counter counts down once from `divider`
/// to zero and stops. Used by [`pit_sleep`].
pub fn set_mode_0(divider: u16) {
    program_channel0(divider, CMD_CHAN0_MODE0);
}

/// Program channel 0 for the periodic ~100 Hz calibration tick.
///
/// After this call, channel 0 pulses IRQ 0 at `PIT_FREQUENCY /
/// PIT_CAL_DIVIDER` Hz. The caller is responsible for ensuring the legacy
/// PIC (or the LAPIC's LINT0) routes IRQ 0 somewhere useful, or for
/// leaving it masked so the pulses are ignored.
pub fn start_calibration_tick() {
    program_channel0(PIT_CAL_DIVIDER, CMD_CHAN0_MODE2);
}

/// Stop channel 0 by reprogramming it to mode 0 with a divider of `0xFFFF`
/// (the slowest possible rate, ~18.2 Hz). This effectively silences the
/// calibration tick; the kernel never fully disables the PIT because mode
/// 2 with a divider of 0 would pulse at the full 1.19 MHz.
pub fn stop() {
    program_channel0(0xFFFF, CMD_CHAN0_MODE0);
}

// ---------------------------------------------------------------------------
// Counter read
// ---------------------------------------------------------------------------

/// Latch and read channel 0's current 16-bit down-counter.
///
/// The latch command freezes the counter for reading; the next two reads of
/// `0x40` return the low and high bytes. Without latching, the two reads
/// could straddle a rollover and yield a garbage value.
///
/// Returns the *remaining* count (down-counting from the divider towards
/// zero). To get the elapsed count within the current period, subtract
/// from the divider via [`elapsed_in_period`].
///
/// Interrupts are disabled across the latch + two reads so no other code
/// reprograms the channel mid-read and corrupts the access-mode sequence.
#[must_use]
pub fn read_counter() -> u16 {
    // SAFETY: PIT reads run in ring 0. The guard keeps the latch transaction
    // atomic and restores the caller's prior interrupt state on return.
    let _interrupt_guard = unsafe { InterruptGuard::disable() };
    PIT_MODE.write(CMD_CHAN0_LATCH);
    let lo = PIT_CHANNEL_0.read();
    let hi = PIT_CHANNEL_0.read();
    u16::from(lo) | (u16::from(hi) << 8)
}

/// The elapsed count within the current period: `divider - read_counter()`.
/// Useful for measuring sub-tick intervals during calibration. Uses the
/// last-programmed divider ([`CURRENT_DIVIDER`]) so the caller does not
/// have to track it.
#[must_use]
pub fn elapsed_in_period() -> u16 {
    let divider = CURRENT_DIVIDER.load(Ordering::Acquire) as u16;
    divider.wrapping_sub(read_counter())
}

// ---------------------------------------------------------------------------
// One-shot delay (early boot)
// ---------------------------------------------------------------------------

/// Spin for approximately `ms` milliseconds using the PIT one-shot mode.
///
/// Reprograms channel 0 to mode 0 with a divider computed from `ms`, then
/// spins reading the counter until it reaches zero. This is the early-boot
/// delay primitive used before the scheduler or any interrupt-driven sleep
/// is available — a "pit sleep" in the classic sense.
///
/// The delay is approximate: the PIT's 1.19 MHz input means one tick is
/// ~838 ns, so a 1 ms delay uses a divider of ~1193 and the granularity is
/// sub-microsecond. For `ms` values that would overflow a 16-bit divider
/// (> ~55 ms), the function loops internally in ~50 ms chunks.
///
/// Interrupts need not be enabled: mode 0 counts down regardless of IF,
/// and we poll the counter rather than waiting for IRQ 0. This makes
/// `pit_sleep` safe to use before the IDT is loaded.
pub fn pit_sleep(ms: u64) {
    // Maximum delay per one-shot in ms: 65535 / 1_193_182 * 1000 ≈ 54.9 ms.
    // We use 54 to stay safely below the 16-bit divider ceiling after
    // truncation.
    const MAX_MS_PER_SHOT: u64 = 54;
    let mut remaining = ms;
    while remaining > 0 {
        let chunk = remaining.min(MAX_MS_PER_SHOT);
        let divider = ((chunk * PIT_FREQUENCY) / 1000) as u16;
        set_mode_0(divider);
        // Spin until the counter reaches zero. In mode 0 the counter loads
        // `divider` on the first clock after programming, then counts down
        // and stops at zero, so we may briefly read `divider` before the
        // load resolves — that is fine, we simply keep polling.
        while read_counter() != 0 {
            core::hint::spin_loop();
        }
        remaining -= chunk;
    }
}

// ---------------------------------------------------------------------------
// Calibration: count a known interval in PIT input cycles
// ---------------------------------------------------------------------------

/// Establish a known interval by watching channel 0's counter wrap
/// `periods` times, and return the interval expressed in PIT input cycles.
///
/// This is the calibration primitive other timers calibrate against. The
/// returned value is `periods * divider` PIT input cycles, which at the
/// hard-wired [`PIT_FREQUENCY`] is a known wall-time interval of
/// `periods * divider / PIT_FREQUENCY` seconds. A caller measuring the
/// LAPIC timer or TSC reads their counter before and after this call:
///
/// ```ignore
/// let before = read_lapic_timer();
/// let cycles = pit::calibrate_over_periods(3);
/// let after = read_lapic_timer();
/// let lapic_hz = (after - before) * pit::PIT_FREQUENCY / cycles;
/// ```
///
/// Channel 0 must already be programmed in mode 2 (via [`set_mode_2`] or
/// [`start_calibration_tick`]) before calling; this function does not
/// reprogram the channel. IRQ 0 may be masked or delivered — the counter
/// wraps in mode 2 regardless, and we detect wraps by observing the
/// counter jump *up* (it reloads to the divider after hitting zero).
///
/// # Panics
///
/// Never. A `periods` of `0` returns `0` immediately.
#[must_use]
pub fn calibrate_over_periods(periods: u32) -> u64 {
    if periods == 0 {
        return 0;
    }
    let divider = CURRENT_DIVIDER.load(Ordering::Acquire) as u16;
    if divider == 0 {
        return 0;
    }
    let mut wraps: u32 = 0;
    // Sample the counter once to establish a reference. We detect a wrap by
    // the counter increasing between samples (it counts *down*, so an
    // increase means it reloaded from zero back to the divider).
    let mut prev = read_counter();
    while wraps < periods {
        let cur = read_counter();
        // A reload shows up as cur > prev (the counter went ...1, 0,
        // reload-to-divider, ...). The exact reload value is the divider,
        // so any strictly larger reading is one wrap. Use `core::hint` to
        // keep the spin cheap.
        if cur > prev {
            wraps += 1;
        }
        prev = cur;
        // Yield the hyperthread sibling between samples so the poll does
        // not starve a peer thread. We deliberately do NOT `hlt` here:
        // calibration may run with IRQs masked, where `hlt` would never
        // wake, and the counter wraps in mode 2 regardless of interrupt
        // delivery.
        core::hint::spin_loop();
    }
    u64::from(periods) * u64::from(divider)
}

/// Convenience: calibrate a peer counter against the PIT over `periods`
/// mode-2 wraps, returning the peer's frequency in Hz.
///
/// `peer_read` is called twice, before and after the known interval. The
/// delta is multiplied by [`PIT_FREQUENCY`] and divided by the elapsed PIT
/// cycles to recover the peer's tick rate. This is the shape the LAPIC
/// timer calibration will use once its counter is readable.
///
/// Returns `None` if `periods` is zero or the peer did not advance.
pub fn calibrate_peer_hz(periods: u32, peer_read: impl Fn() -> u64) -> Option<u64> {
    let before = peer_read();
    let cycles = calibrate_over_periods(periods);
    let after = peer_read();
    if cycles == 0 {
        return None;
    }
    let delta = after.checked_sub(before)?;
    if delta == 0 {
        return None;
    }
    // peer_hz = delta_ticks * pit_freq / pit_cycles. Use checked_mul to
    // avoid overflow on absurdly large deltas; saturate otherwise.
    let scaled = delta.checked_mul(PIT_FREQUENCY)?;
    Some(scaled / cycles)
}

// ---------------------------------------------------------------------------
// PIT clocksource
// ---------------------------------------------------------------------------

/// A [`ClockSource`] backed by the PIT tick counter.
///
/// Used only when neither the HPET nor a calibrated LAPIC accumulator is
/// available — the PIT's 16-bit counter wraps every ~55 ms, so this
/// implementation relies on the IRQ 0 tick accumulator ([`PIT_TICKS`])
/// rather than the raw counter. The nanosecond count is therefore
/// `ticks * (1e9 / tick_rate_hz)`, where `tick_rate_hz` is the frequency
/// the channel was programmed to (set by [`set_tick_rate_hz`] or
/// [`PitClock::set_tick_rate_hz`]).
pub struct PitClock {
    tick_rate_hz: AtomicU64,
}

impl PitClock {
    /// Construct a PIT clocksource with the given tick rate. The rate is
    /// the frequency channel 0 was programmed to (`PIT_FREQUENCY /
    /// divider`); it is used to convert accumulated ticks to nanoseconds.
    #[must_use]
    pub const fn new(tick_rate_hz: u64) -> Self {
        Self {
            tick_rate_hz: AtomicU64::new(tick_rate_hz),
        }
    }

    /// Update the tick rate after reprogramming channel 0. Called by the
    /// scheduler phase when it changes the system tick rate.
    pub fn set_tick_rate_hz(&self, hz: u64) {
        self.tick_rate_hz.store(hz, Ordering::Release);
    }
}

impl ClockSource for PitClock {
    fn read_ns(&self) -> u64 {
        let hz = self.tick_rate_hz.load(Ordering::Acquire);
        if hz == 0 {
            return 0;
        }
        let ticks = PIT_TICKS.load(Ordering::Relaxed);
        // ticks * 1e9 / hz, done as a single 64-bit divide. The tick count
        // grows at ~100 Hz by default, so for a year of uptime (~3e9 ticks)
        // the product is ~3e18, which fits in u64.
        ticks.saturating_mul(1_000_000_000) / hz
    }

    fn name(&self) -> &'static str {
        "pit"
    }
}

/// The single PIT clocksource instance. Installed as the active
/// clocksource by `time::init` when no HPET is available.
pub static PIT_CLOCK: PitClock = PitClock::new(PIT_FREQUENCY / PIT_CAL_DIVIDER as u64);

/// Set the tick rate the PIT clocksource assumes for its ns conversion.
/// Called when the system tick rate changes.
pub fn set_tick_rate_hz(hz: u64) {
    PIT_CLOCK.set_tick_rate_hz(hz);
}

// ---------------------------------------------------------------------------
// Bring-up
// ---------------------------------------------------------------------------

/// One-line bring-up used by `time::init` when the PIT is selected as the
/// calibration reference. Programs the ~100 Hz tick, logs the realised
/// rate, and leaves channel 0 armed in mode 2. The caller is responsible
/// for unmasking IRQ 0 (or leaving it masked if only the counter is
/// needed).
pub fn init() {
    let achieved = set_mode_2(PIT_FREQUENCY / u64::from(PIT_CAL_DIVIDER));
    ::log::info!(
        "pit: channel 0 mode 2, ~{} Hz tick (divider {})",
        achieved,
        PIT_CAL_DIVIDER
    );
}
