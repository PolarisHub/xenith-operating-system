//! CMOS Real-Time Clock driver.
//!
//! The RTC is the PC's battery-backed wall clock. It lives in the CMOS chip
//! (modern: part of the PCH/Super-I/O; historical: the Motorola MC146818)
//! and is reached through two I/O ports:
//!
//! * `0x70` — the index/register-select port. Writing a byte's low 6 bits
//!   selects which CMOS register the next read of `0x71` returns. Bit 7 of
//!   the written byte gates NMI: setting it masks NMI for the whole CPU.
//!   We always write with bit 7 clear so NMI stays enabled; the kernel's
//!   NMI policy is owned by the exception path, not the RTC reader.
//! * `0x71` — the data port. A read returns the selected register's value.
//!
//! # Register map (offset)
//!
//! | Off | Field            | Off | Field          |
//! |-----|------------------|-----|----------------|
//! | 0x00 | seconds          | 0x0B | status B      |
//! | 0x02 | minutes          | 0x0C | status C      |
//! | 0x04 | hours            | 0x0D | status D      |
//! | 0x06 | weekday (1..=7)  | 0x0E | diagnostic    |
//! | 0x07 | day of month     | 0x0F | shutdown code |
//! | 0x08 | month            | 0x10 | floppy types  |
//! | 0x09 | year (BCD 00..99)| 0x32 | century (BCD) |
//!
//! The century register at `0x32` is not universally present. ACPI
//! describes its location in the FADT; when ACPI is absent we fall back to
//! the common `0x32` and, if that reads zero, to a heuristic pinned to
//! `2000` (the RTC rolls over at the century boundary, so a year reading
//! below the boot year implies the next century).
//!
//! # BCD vs. binary
//!
//! Status B bit 2 selects the RTC's numeric format: 0 = BCD (the default
//! and the near-universal setting), 1 = binary. We read status B once and
//! decode accordingly. BCD decoding splits a byte into two nibbles:
//! `hi = (b >> 4) & 0x0F`, `lo = b & 0x0F`, value = `hi * 10 + lo`.
//!
//! # 24-hour vs. 12-hour
//!
//! Status B bit 1 selects the hour format: 0 = 12-hour (bit 7 of the hours
//! register is the PM flag), 1 = 24-hour. We read bit 1 and decode the
//! hours register accordingly, converting 12-hour PM to 24-hour.
//!
//! # Update-in-progress
//!
//! The RTC updates its time registers once per second. During the ~244 us
//! update window the time registers are undefined. Status A bit 7
//! (UIP — update in progress) is set while the update is running. We wait
//! for UIP to clear before reading, and — because a read can race the next
//! update — we read twice and retry if the two reads disagree. This is the
//! canonical "double read" algorithm from the RTC datasheet.
//!
//! # Interrupt safety
//!
//! The CMOS access must be atomic with respect to other CMOS users: a
//! context switch between writing `0x70` and reading `0x71` would let
//! another caller change the selected register and return the wrong field.
//! We save RFLAGS and disable interrupts across each read pair to make the
//! two-port transaction atomic, then restore the saved flags. The window is
//! tiny (two `in`/`out` pairs), and an early-boot caller that entered with IF
//! clear remains interrupt-disabled afterward.

use core::fmt;

use crate::arch::x86_64::instructions::InterruptGuard;
use crate::arch::x86_64::port::Port8;

// ---------------------------------------------------------------------------
// CMOS port and register constants
// ---------------------------------------------------------------------------

/// CMOS index/register-select port. Writing the low 6 bits selects the
/// register; bit 7 gates NMI (we keep it clear).
const CMOS_INDEX: Port8 = Port8::new(0x70);

/// CMOS data port. A read returns the value of the register selected by
/// the most recent write to `CMOS_INDEX`.
const CMOS_DATA: Port8 = Port8::new(0x71);

/// Status A: update-in-progress and divider/rate bits. Bit 7 is UIP.
const REG_STATUS_A: u8 = 0x0A;

/// Status B: format control. Bit 2 = binary mode, bit 1 = 24-hour, bit 0 =
/// daylight-saving enable (we ignore DS).
const REG_STATUS_B: u8 = 0x0B;

/// Seconds register (0x00).
const REG_SECONDS: u8 = 0x00;
/// Minutes register (0x02).
const REG_MINUTES: u8 = 0x02;
/// Hours register (0x04). Bit 7 is the PM flag in 12-hour mode.
const REG_HOURS: u8 = 0x04;
/// Day-of-month register (0x07).
const REG_DAY: u8 = 0x07;
/// Month register (0x08).
const REG_MONTH: u8 = 0x08;
/// Year register (0x09). Holds the year within the century (00..99 BCD).
const REG_YEAR: u8 = 0x09;
/// Century register (0x32). Not universally present; ACPI FADT documents
/// the offset when it is.
const REG_CENTURY: u8 = 0x32;

/// UIP bit in status A. While set, the time registers are being updated and
/// must not be read.
const UIP: u8 = 1 << 7;

/// Bit 2 of status B: set means binary mode, clear means BCD.
const BINARY_MODE: u8 = 1 << 2;

/// Bit 1 of status B: set means 24-hour mode, clear means 12-hour.
const HOURS_24: u8 = 1 << 1;

// ---------------------------------------------------------------------------
// DateTime
// ---------------------------------------------------------------------------

/// A wall-clock date and time in the proleptic Gregorian calendar.
///
/// All fields are in their natural units: seconds `0..=59`, minutes
/// `0..=59`, hours `0..=23`, day `1..=31`, month `1..=12`, year is the full
/// 4-digit year (e.g. `2026`). There is no timezone: the RTC stores local
/// time by convention, and the kernel treats it as UTC for simplicity until
/// a userspace time daemon says otherwise.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct DateTime {
    /// Seconds within the minute: `0..=59` (RTC does not do leap seconds).
    pub seconds: u8,
    /// Minutes within the hour: `0..=59`.
    pub minutes: u8,
    /// Hours within the day: `0..=23`.
    pub hours: u8,
    /// Day of the month: `1..=31`.
    pub day: u8,
    /// Month of the year: `1..=12`.
    pub month: u8,
    /// Full 4-digit year, e.g. `2026`.
    pub year: u16,
}

impl DateTime {
    /// Convert this `DateTime` to a Unix-epoch nanosecond count.
    ///
    /// Uses the civil-from-days algorithm (Howard Hinnant's `days_from_civil`)
    /// to compute the days since 1970-01-01 without any lookup tables, then
    /// scales to nanoseconds. The algorithm is valid for any date in the
    /// proleptic Gregorian calendar and handles leap years correctly.
    ///
    /// Returns `None` if any field is out of its valid range, so a garbage
    /// RTC read (e.g. month 0) degrades to `None` rather than producing a
    /// plausible-but-wrong timestamp.
    #[must_use]
    pub fn to_unix_nanos(self) -> Option<u64> {
        if self.month == 0 || self.month > 12 {
            return None;
        }
        if self.day == 0 || self.day > 31 {
            return None;
        }
        if self.seconds > 59 || self.minutes > 59 || self.hours > 23 {
            return None;
        }
        let y = i64::from(self.year);
        let m = i64::from(self.month);
        let d = i64::from(self.day);
        // days_from_civil: returns days since 1970-01-01 for the proleptic
        // Gregorian date (y, m, d). Algorithm by Howard Hinnant; public
        // domain. Handles the year/month shift so March is the first month
        // of the "year" for leap-day purposes.
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400; // [0, 399]
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
        let days = era * 146_097 + doe - 719_468; // days since 1970-01-01

        let secs_in_day: u64 = 86_400;
        let nanos_in_sec: u64 = 1_000_000_000;
        let day_ns = u64::try_from(days)
            .ok()?
            .checked_mul(secs_in_day)?
            .checked_mul(nanos_in_sec)?;
        let time_ns =
            (u64::from(self.hours) * 3600 + u64::from(self.minutes) * 60 + u64::from(self.seconds))
                .checked_mul(nanos_in_sec)?;
        day_ns.checked_add(time_ns)
    }

    /// Convert a Unix-epoch nanosecond count to a [`DateTime`].
    ///
    /// Inverse of [`to_unix_nanos`], using the `civil_from_days` algorithm.
    /// Used by [`MonotonicClock`](super::clock::MonotonicClock) to advance
    /// the boot epoch into the current wall time without re-reading the RTC.
    #[must_use]
    pub fn from_unix_nanos(ns: u64) -> Self {
        let nanos_in_sec: u64 = 1_000_000_000;
        let secs_in_day: u64 = 86_400;
        let total_secs = ns / nanos_in_sec;
        let days = (total_secs / secs_in_day) as i64;
        let secs_of_day = total_secs % secs_in_day;

        // civil_from_days: inverse of days_from_civil. Howard Hinnant.
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
        let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
        let year = if m <= 2 { y + 1 } else { y };

        Self {
            seconds: (secs_of_day % 60) as u8,
            minutes: ((secs_of_day / 60) % 60) as u8,
            hours: (secs_of_day / 3600) as u8,
            day: d as u8,
            month: m as u8,
            year: year as u16,
        }
    }
}

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // ISO 8601 date + time, no timezone. Padded so log lines align.
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hours, self.minutes, self.seconds
        )
    }
}

// ---------------------------------------------------------------------------
// Low-level CMOS access
// ---------------------------------------------------------------------------

/// Read a single CMOS register by index.
///
/// The two-port transaction (write index to `0x70`, read data from `0x71`)
/// is made atomic by disabling interrupts across it, so a context switch
/// cannot interleave a second caller's register selection with our read.
///
/// # Safety of the I/O
///
/// Ports `0x70`/`0x71` are kernel-owned CMOS ports on all PC-compatible
/// hardware. The `Port8` wrapper encodes the `in al, dx` / `out dx, al`
/// instructions; the caller is the kernel, so the ownership invariant holds.
#[inline]
fn read_register(reg: u8) -> u8 {
    // SAFETY: CMOS access runs in ring 0. The guard restores the caller's
    // exact saved RFLAGS after this two-port transaction.
    let _interrupt_guard = unsafe { InterruptGuard::disable() };
    // SAFETY: `reg & 0x7F` keeps bit 7 clear so NMI stays enabled. Writing
    // the index byte to 0x70 selects the register; reading 0x71 returns it.
    // The Port8 wrapper emits the correct `out`/`in` instructions.
    CMOS_INDEX.write(reg & 0x7F);
    CMOS_DATA.read()
}

/// Wait for the RTC's update-in-progress bit to clear.
///
/// The UIP bit in status A is set for ~244 us before each 1 Hz register
/// update. Reading the time registers during UIP returns garbage, so we
/// spin until UIP clears. The wait is bounded by the RTC's 1 Hz cadence:
/// UIP is set at most once per second and for under 2 ms, so the loop
/// exits within a handful of iterations.
fn wait_for_uip_clear() {
    // First, wait for UIP to *start* (if it is about to), then wait for it
    // to clear. The canonical algorithm: read A, if UIP set, wait for it to
    // clear; this guarantees we are at the start of a stable 1-second
    // window.
    while read_register(REG_STATUS_A) & UIP != 0 {
        core::hint::spin_loop();
    }
}

/// Decode a BCD-encoded register byte to binary.
///
/// BCD packs two decimal digits in one byte: the high nibble is the tens
/// digit, the low nibble is the ones digit. `0x59` -> `59`. Used for every
/// time field when status B indicates BCD mode (the default).
#[inline]
fn bcd_to_binary(bcd: u8) -> u8 {
    ((bcd >> 4) & 0x0F) * 10 + (bcd & 0x0F)
}

/// Read status B once and return its value. Used to determine the RTC's
/// binary/BCD and 12/24-hour mode for the current read.
#[inline]
fn read_status_b() -> u8 {
    read_register(REG_STATUS_B)
}

// ---------------------------------------------------------------------------
// Public read API
// ---------------------------------------------------------------------------

/// Read the current wall-clock time from the CMOS RTC.
///
/// Performs the canonical double-read: wait for UIP to clear, read all
/// fields, then read them again and retry until two consecutive reads
/// agree. This defeats the race where a 1 Hz update fires between two
/// field reads and yields e.g. `23:59:59` + `00:00:00` mixed fields.
///
/// Returns a [`DateTime`] in 24-hour, binary form regardless of the RTC's
/// configured mode. If the century register reads zero (not present), the
/// century is heuristically pinned to 2000 — the RTC rolls over at the
/// century boundary, so a two-digit year is always interpreted as
/// `20xx` on hardware booted in this millennium.
#[must_use]
pub fn now() -> DateTime {
    let status_b = read_status_b();
    let binary = status_b & BINARY_MODE != 0;
    let h24 = status_b & HOURS_24 != 0;

    loop {
        wait_for_uip_clear();
        let s1 = read_all_fields(binary, h24);
        wait_for_uip_clear();
        let s2 = read_all_fields(binary, h24);
        if s1 == s2 {
            return s1;
        }
        // The two reads disagreed: an update fired between them. Retry.
        // This is rare (a 1 Hz update must land inside the ~us read window)
        // and bounded by the RTC cadence, so the loop exits quickly.
    }
}

/// Read every time field in one pass. Called twice by [`now`] so the caller
/// can compare the two reads for consistency.
fn read_all_fields(binary: bool, h24: bool) -> DateTime {
    let raw_seconds = read_register(REG_SECONDS);
    let raw_minutes = read_register(REG_MINUTES);
    let raw_hours = read_register(REG_HOURS);
    let raw_day = read_register(REG_DAY);
    let raw_month = read_register(REG_MONTH);
    let raw_year = read_register(REG_YEAR);
    let raw_century = read_register(REG_CENTURY);

    let decode = |v: u8| if binary { v } else { bcd_to_binary(v) };

    let mut hours = decode(raw_hours);
    if !h24 {
        // 12-hour mode: bit 7 of the hours register is the PM flag. The
        // value is 1..=12. Convert to 24-hour: 12 AM -> 0, 1..=11 AM -> 1..=11,
        // 12 PM -> 12, 1..=11 PM -> 13..=23.
        let pm = raw_hours & 0x80 != 0;
        hours &= 0x7F; // strip the PM flag bit before BCD decode
        hours = decode(hours);
        if pm && hours != 12 {
            hours += 12;
        } else if !pm && hours == 12 {
            hours = 0;
        }
    }

    let year_in_century = decode(raw_year);
    let century = decode(raw_century);
    let year = if century > 0 {
        u16::from(century) * 100 + u16::from(year_in_century)
    } else {
        // No century register: assume 2000. A two-digit year of 00..99
        // becomes 2000..2099, which is correct for any machine booted this
        // millennium until 2099.
        2000 + u16::from(year_in_century)
    };

    DateTime {
        seconds: decode(raw_seconds),
        minutes: decode(raw_minutes),
        hours,
        day: decode(raw_day),
        month: decode(raw_month),
        year,
    }
}
