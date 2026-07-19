//! Kernel clock primitives: `Instant`, `Duration`, wall-clock `DateTime`, and
//! the [`MonotonicClock`] that backs `uptime_ns` / `Instant::now`.
//!
//! # Why not `core::time::Duration`?
//!
//! `core::time::Duration` is available on `no_std`, but it carries an
//! inner `(secs: u64, nanos: u32)` representation whose public API is
//! oriented towards `std`-style saturating/checked arithmetic and a large
//! surface of helpers (`from_secs`, `as_secs_f64`, ...) that a kernel does
//! not need. More importantly, the hot path in Xenith is "read a free-running
//! counter, multiply by a tick period, return nanoseconds" — a single `u64`
//! nanosecond count is the natural shape, and keeping the representation
//! flat avoids a 128-bit multiply on every `Instant::now`.
//!
//! Our [`Duration`] is therefore a single `u64` count of nanoseconds. It
//! saturates at `u64::MAX` (~584 years) rather than wrapping, because a
//! wrap would silently corrupt scheduler deadlines; a saturating add can at
//! worst make a deadline "never", which is observable and debuggable.
//!
//! # Monotonic vs. wall clock
//!
//! [`MonotonicClock`] is the single source of monotonic time. It is backed
//! by whichever free-running counter the time bring-up selected: the HPET
//! main counter when the HPET is present (feature `hpet`), otherwise the
//! LAPIC timer's accumulated tick count, otherwise a PIT-derived count.
//! The backing counter is abstracted behind the [`ClockSource`] trait so
//! the clock can be wired up once during init and read cheaply afterwards.
//!
//! The wall clock ([`DateTime`]) is read from the CMOS RTC at boot and
//! advanced by the monotonic clock thereafter, so `wall_time()` does not
//! touch the RTC on every call (RTC reads are slow and require disabling
//! interrupts to avoid CMOS update-in-progress races).

use core::cmp::Ordering;
use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use spin::Once;

use super::rtc::{self, DateTime};

// ---------------------------------------------------------------------------
// Duration
// ---------------------------------------------------------------------------

/// A span of time, measured in nanoseconds.
///
/// This is a single `u64` nanosecond count rather than the `(secs, nanos)`
/// pair `core::time::Duration` uses, because the kernel's hot path computes
/// durations from a free-running counter with one multiply and the flat
/// representation keeps that path branch-free. The maximum representable
/// span is ~584.9 years; arithmetic saturates at that bound rather than
/// wrapping, so a deadline can become "never" but never silently jumps to
/// "the past".
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Duration(u64);

impl Duration {
    /// One nanosecond.
    pub const NANOS: Self = Self(1);
    /// One microsecond in nanoseconds.
    pub const MICROS: Self = Self(1_000);
    /// One millisecond in nanoseconds.
    pub const MILLIS: Self = Self(1_000_000);
    /// One second in nanoseconds.
    pub const SECS: Self = Self(1_000_000_000);

    /// Construct a `Duration` from a raw nanosecond count.
    #[inline]
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Construct a `Duration` from a number of microseconds.
    #[inline]
    #[must_use]
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros.saturating_mul(1_000))
    }

    /// Construct a `Duration` from a number of milliseconds.
    #[inline]
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis.saturating_mul(1_000_000))
    }

    /// Construct a `Duration` from a number of seconds.
    #[inline]
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1_000_000_000))
    }

    /// The raw nanosecond count.
    #[inline]
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// The whole number of microseconds in this duration (truncated).
    #[inline]
    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0 / 1_000
    }

    /// The whole number of milliseconds in this duration (truncated).
    #[inline]
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0 / 1_000_000
    }

    /// The whole number of seconds in this duration (truncated).
    #[inline]
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0 / 1_000_000_000
    }

    /// Saturating addition. A result that would overflow `u64` is clamped to
    /// `u64::MAX` rather than wrapping.
    #[inline]
    #[must_use]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Saturating subtraction. Yields zero if `rhs > self` so a deadline
    /// calculation that runs backwards degrades to "fire immediately" rather
    /// than producing a huge far-future value.
    #[inline]
    #[must_use]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    /// `true` if this duration represents zero elapsed time.
    #[inline]
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::Add for Duration {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        self.saturating_add(rhs)
    }
}

impl core::ops::Sub for Duration {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        self.saturating_sub(rhs)
    }
}

impl PartialOrd for Duration {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Duration {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

// ---------------------------------------------------------------------------
// Instant
// ---------------------------------------------------------------------------

/// A monotonic timestamp sampled from the kernel's [`MonotonicClock`].
///
/// `Instant` is a wrapper around a `u64` nanosecond count read from the
/// monotonic clock, so the difference between two `Instant`s is a
/// [`Duration`]. It is deliberately not `Copy`-constructible from a raw
/// integer: the only way to obtain one is [`Instant::now`], which reads the
/// clock, or arithmetic on an existing `Instant`. This keeps every timestamp
/// genuinely tied to a clock sample.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Instant(u64);

impl Instant {
    /// Sample the current monotonic clock.
    ///
    /// Reads the backing counter through [`MonotonicClock::now`], which
    /// dispatches to the HPET/LAPIC/PIT counter selected at boot. The call
    /// is lock-free on the read path: the backing counter's `read_ns` is a
    /// plain load + multiply.
    #[inline]
    #[must_use]
    pub fn now() -> Self {
        Self(MONOTONIC.now_ns())
    }

    /// The raw nanosecond count this instant was sampled at. Useful for
    /// logging absolute timestamps; prefer `duration_since` for intervals.
    #[inline]
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// The [`Duration`] between `earlier` and `self`. If `earlier` is
    /// actually after `self` (the clock went backwards, which a monotonic
    /// clock never does but a caller can trigger by passing the wrong
    /// instant), the result is zero rather than a wrapped huge value.
    #[inline]
    #[must_use]
    pub fn duration_since(self, earlier: Instant) -> Duration {
        Duration(self.0.saturating_sub(earlier.0))
    }

    /// Add a duration to this instant, saturating at `u64::MAX`.
    #[inline]
    #[must_use]
    pub const fn saturating_add(self, dur: Duration) -> Self {
        Self(self.0.saturating_add(dur.0))
    }

    /// Subtract a duration, saturating at zero.
    #[inline]
    #[must_use]
    pub const fn saturating_sub(self, dur: Duration) -> Self {
        Self(self.0.saturating_sub(dur.0))
    }
}

impl core::ops::Add<Duration> for Instant {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Duration) -> Self {
        self.saturating_add(rhs)
    }
}

impl core::ops::Sub<Duration> for Instant {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Duration) -> Self {
        self.saturating_sub(rhs)
    }
}

impl core::ops::Sub for Instant {
    type Output = Duration;
    #[inline]
    fn sub(self, rhs: Self) -> Duration {
        self.duration_since(rhs)
    }
}

impl PartialOrd for Instant {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Instant {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

// ---------------------------------------------------------------------------
// ClockSource trait
// ---------------------------------------------------------------------------

/// A free-running counter that can be read as a nanosecond timestamp.
///
/// The kernel's [`MonotonicClock`] holds a `&'static dyn ClockSource` chosen
/// once during boot. Implementations live in [`super::hpet`], the LAPIC
/// timer accumulator, and [`super::pit`]; the trait is the seam that lets
/// the clock switch between them without the call site caring which one is
/// active.
///
/// # Safety contract for implementors
///
/// `read_ns` must be monotonic non-decreasing on a given CPU and safe to
/// call from any context, including interrupt handlers. It must not take a
/// lock that could deadlock against an IRQ-context caller. HPET reads
/// satisfy this by reading a single MMIO counter register; the LAPIC
/// accumulator satisfies it with a `Relaxed` atomic load; the PIT
/// implementation is only used during early boot before interrupts are on.
pub trait ClockSource: Sync {
    /// Read the current counter value as a nanosecond count.
    ///
    /// Implementations must be cheap (a load and a multiply) and must not
    /// allocate. The returned value must be non-decreasing across calls on
    /// the same CPU.
    fn read_ns(&self) -> u64;

    /// A short human-readable name for diagnostics ("hpet", "lapic", "pit").
    fn name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// MonotonicClock
// ---------------------------------------------------------------------------

/// The kernel's monotonic clock.
///
/// Holds a reference to the selected [`ClockSource`] plus the boot-time
/// wall clock read from the RTC. The clock is read through [`now_ns`]
/// (raw nanoseconds) or indirectly via [`Instant::now`].
///
/// The single global instance [`MONOTONIC`] is constructed once during
/// `time::init`; before that, `now_ns` returns zero and `wall_time` returns
/// the RTC epoch, which is safe but unhelpful.
pub struct MonotonicClock {
    /// The backing counter, set once at init. `None` until `time::init`
    /// selects a source; reads before init return zero.
    source: Once<&'static dyn ClockSource>,
    /// The wall-clock reading taken at boot, in Unix nanoseconds. Added to
    /// the monotonic uptime to produce `wall_time()`.
    boot_epoch_ns: AtomicU64,
}

impl MonotonicClock {
    /// Construct an uninitialised clock. Reads return zero until
    /// [`MonotonicClock::install`] is called.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            source: Once::new(),
            boot_epoch_ns: AtomicU64::new(0),
        }
    }

    /// Install the backing counter. Called exactly once from `time::init`
    /// after the HPET/LAPIC/PIT bring-up has decided which source to use.
    /// Also snapshots the RTC wall clock as the boot epoch so `wall_time`
    /// can advance from there.
    ///
    /// # Panics
    ///
    /// Debug builds assert that `source` is not installed twice, since a
    /// second install would silently change the clock's frequency and
    /// corrupt every deadline already computed against the old source.
    pub fn install(&self, source: &'static dyn ClockSource, boot_epoch_ns: u64) {
        debug_assert!(
            self.source.get().is_none(),
            "xenith.time: monotonic clock source installed twice"
        );
        self.source.call_once(|| source);
        self.boot_epoch_ns
            .store(boot_epoch_ns, AtomicOrdering::Release);
    }

    /// Read the current monotonic nanosecond count, or zero if no source is
    /// installed yet.
    #[inline]
    #[must_use]
    pub fn now_ns(&self) -> u64 {
        self.source.get().map_or(0, |source| source.read_ns())
    }

    /// The boot epoch in Unix nanoseconds (the RTC reading taken at init).
    #[inline]
    #[must_use]
    pub fn boot_epoch_ns(&self) -> u64 {
        self.boot_epoch_ns.load(AtomicOrdering::Acquire)
    }

    /// The current wall clock as a [`DateTime`]. Computed as the boot epoch
    /// plus the monotonic uptime; does not touch the RTC.
    #[must_use]
    pub fn wall_time(&self) -> DateTime {
        let epoch = self.boot_epoch_ns();
        let uptime = self.now_ns();
        DateTime::from_unix_nanos(epoch.saturating_add(uptime))
    }

    /// The monotonic uptime in nanoseconds — equivalent to [`Instant::now`]
    /// expressed as a raw `u64`.
    #[inline]
    #[must_use]
    pub fn uptime_ns(&self) -> u64 {
        self.now_ns()
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for MonotonicClock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let installed = self.source.get().is_some();
        f.debug_struct("MonotonicClock")
            .field("installed", &installed)
            .field(
                "boot_epoch_ns",
                &self.boot_epoch_ns.load(AtomicOrdering::Relaxed),
            )
            .finish()
    }
}

/// The single global monotonic clock.
///
/// Reads through this static are the kernel's one source of monotonic time.
/// `Instant::now`, `uptime_ns`, and `wall_time` all funnel here. It is
/// constructed uninitialised and wired up by `time::init`.
pub static MONOTONIC: MonotonicClock = MonotonicClock::new();

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Current monotonic uptime in nanoseconds.
#[inline]
#[must_use]
pub fn uptime_ns() -> u64 {
    MONOTONIC.uptime_ns()
}

/// Current wall clock as a [`DateTime`]. Reads the monotonic clock and adds
/// the boot epoch; never touches the RTC hardware.
#[inline]
#[must_use]
pub fn wall_time() -> DateTime {
    MONOTONIC.wall_time()
}

/// Read the RTC once and return the wall clock at the moment of the call.
///
/// This is the slow path that actually talks to CMOS; it is used during
/// `time::init` to seed [`MonotonicClock::boot_epoch_ns`] and is available
/// for a future "resync wall clock" call. Regular wall-time reads should go
/// through [`wall_time`] instead.
#[must_use]
pub fn rtc_now() -> DateTime {
    rtc::now()
}
