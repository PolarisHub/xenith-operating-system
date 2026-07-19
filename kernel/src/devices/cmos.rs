//! CMOS/NVRAM and MC146818-compatible real-time clock access.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::x86_64::port::{io_wait, Port8};
use crate::sync::SpinLockIRQ;
pub use crate::time::DateTime;

const INDEX_PORT: Port8 = Port8::new(0x70);
const DATA_PORT: Port8 = Port8::new(0x71);
const CMOS_REGISTER_COUNT: u8 = 128;
const NMI_DISABLE: u8 = 1 << 7;

const REG_SECONDS: u8 = 0x00;
const REG_MINUTES: u8 = 0x02;
const REG_HOURS: u8 = 0x04;
const REG_DAY: u8 = 0x07;
const REG_MONTH: u8 = 0x08;
const REG_YEAR: u8 = 0x09;
const REG_STATUS_A: u8 = 0x0A;
const REG_STATUS_B: u8 = 0x0B;
const REG_CENTURY: u8 = 0x32;

const STATUS_A_UIP: u8 = 1 << 7;
const STATUS_B_24_HOUR: u8 = 1 << 1;
const STATUS_B_BINARY: u8 = 1 << 2;
const STATUS_B_SET: u8 = 1 << 7;

const UIP_POLL_LIMIT: u32 = 2_000_000;
const SNAPSHOT_ATTEMPTS: usize = 8;

static CMOS_LOCK: SpinLockIRQ<()> = SpinLockIRQ::new(());
static NMI_DISABLED: AtomicBool = AtomicBool::new(false);

/// CMOS/RTC operation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmosError {
    /// The MC146818 index port exposes only registers 0..127.
    InvalidRegister(u8),
    /// The RTC update-in-progress bit never cleared.
    UpdateTimeout,
    /// Two consecutive snapshots did not agree after bounded retries.
    UnstableClock,
    /// A register contained malformed packed BCD.
    InvalidBcd,
    /// Date/time fields are outside their calendar ranges.
    InvalidDate,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct RawRtc {
    seconds: u8,
    minutes: u8,
    hours: u8,
    day: u8,
    month: u8,
    year: u8,
    century: u8,
}

#[inline]
fn select_value(register: u8) -> u8 {
    register
        | if NMI_DISABLED.load(Ordering::Relaxed) {
            NMI_DISABLE
        } else {
            0
        }
}

#[inline]
fn read_locked(register: u8) -> u8 {
    INDEX_PORT.write(select_value(register));
    io_wait();
    DATA_PORT.read()
}

#[inline]
fn write_locked(register: u8, value: u8) {
    INDEX_PORT.write(select_value(register));
    io_wait();
    DATA_PORT.write(value);
    io_wait();
}

/// Set the NMI-mask bit used on subsequent CMOS index writes.
///
/// The state is explicit because port 0x70 is a write-only latch on common
/// chipsets; attempting to "preserve" bit 7 by reading it is not portable.
pub fn set_nmi_disabled(disabled: bool) {
    let _guard = CMOS_LOCK.lock();
    NMI_DISABLED.store(disabled, Ordering::Release);
    // Re-select status A so the new NMI policy reaches the latch immediately.
    INDEX_PORT.write(select_value(REG_STATUS_A));
}

/// Whether subsequent CMOS accesses mask NMI while selecting a register.
#[must_use]
pub fn nmi_disabled() -> bool {
    NMI_DISABLED.load(Ordering::Acquire)
}

/// Read one CMOS/NVRAM register.
pub fn get(register: u8) -> Result<u8, CmosError> {
    if register >= CMOS_REGISTER_COUNT {
        return Err(CmosError::InvalidRegister(register));
    }
    let _guard = CMOS_LOCK.lock();
    Ok(read_locked(register))
}

/// Write one CMOS/NVRAM register.
pub fn set(register: u8, value: u8) -> Result<(), CmosError> {
    if register >= CMOS_REGISTER_COUNT {
        return Err(CmosError::InvalidRegister(register));
    }
    let _guard = CMOS_LOCK.lock();
    write_locked(register, value);
    Ok(())
}

/// Explicit NVRAM spelling for [`get`].
pub fn nvram_get(register: u8) -> Result<u8, CmosError> {
    get(register)
}

/// Explicit NVRAM spelling for [`set`].
pub fn nvram_set(register: u8, value: u8) -> Result<(), CmosError> {
    set(register, value)
}

fn wait_update_complete_locked() -> Result<(), CmosError> {
    for _ in 0..UIP_POLL_LIMIT {
        if read_locked(REG_STATUS_A) & STATUS_A_UIP == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(CmosError::UpdateTimeout)
}

/// Wait until the RTC is outside its once-per-second update window.
pub fn wait_update_complete() -> Result<(), CmosError> {
    let _guard = CMOS_LOCK.lock();
    wait_update_complete_locked()
}

fn raw_snapshot_locked() -> RawRtc {
    RawRtc {
        seconds: read_locked(REG_SECONDS),
        minutes: read_locked(REG_MINUTES),
        hours: read_locked(REG_HOURS),
        day: read_locked(REG_DAY),
        month: read_locked(REG_MONTH),
        year: read_locked(REG_YEAR),
        century: read_locked(REG_CENTURY),
    }
}

fn decode_bcd(value: u8) -> Result<u8, CmosError> {
    if value & 0x0F > 9 || value >> 4 > 9 {
        return Err(CmosError::InvalidBcd);
    }
    Ok((value >> 4) * 10 + (value & 0x0F))
}

#[inline]
const fn encode_bcd(value: u8) -> u8 {
    ((value / 10) << 4) | (value % 10)
}

fn decode_field(value: u8, binary: bool) -> Result<u8, CmosError> {
    if binary {
        Ok(value)
    } else {
        decode_bcd(value)
    }
}

fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u16, month: u8) -> Option<u8> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return None,
    })
}

fn validate(datetime: DateTime) -> Result<(), CmosError> {
    if datetime.year == 0
        || datetime.year > 9999
        || datetime.seconds > 59
        || datetime.minutes > 59
        || datetime.hours > 23
    {
        return Err(CmosError::InvalidDate);
    }
    let Some(max_day) = days_in_month(datetime.year, datetime.month) else {
        return Err(CmosError::InvalidDate);
    };
    if datetime.day == 0 || datetime.day > max_day {
        return Err(CmosError::InvalidDate);
    }
    Ok(())
}

fn decode_snapshot(raw: RawRtc, status_b: u8) -> Result<DateTime, CmosError> {
    let binary = status_b & STATUS_B_BINARY != 0;
    let hours_24 = status_b & STATUS_B_24_HOUR != 0;
    let pm = !hours_24 && raw.hours & 0x80 != 0;
    let hour_value = if hours_24 {
        raw.hours
    } else {
        raw.hours & 0x7F
    };
    let mut hours = decode_field(hour_value, binary)?;
    if !hours_24 {
        if hours == 0 || hours > 12 {
            return Err(CmosError::InvalidDate);
        }
        if pm {
            if hours != 12 {
                hours += 12;
            }
        } else if hours == 12 {
            hours = 0;
        }
    }

    let year_low = decode_field(raw.year, binary)?;
    let century = if raw.century == 0 {
        20
    } else {
        decode_field(raw.century, binary)?
    };
    let datetime = DateTime {
        seconds: decode_field(raw.seconds, binary)?,
        minutes: decode_field(raw.minutes, binary)?,
        hours,
        day: decode_field(raw.day, binary)?,
        month: decode_field(raw.month, binary)?,
        year: u16::from(century) * 100 + u16::from(year_low),
    };
    validate(datetime)?;
    Ok(datetime)
}

/// Read a stable RTC snapshot, normalised to binary 24-hour fields.
pub fn rtc_now() -> Result<DateTime, CmosError> {
    let _guard = CMOS_LOCK.lock();
    for _ in 0..SNAPSHOT_ATTEMPTS {
        wait_update_complete_locked()?;
        let first = raw_snapshot_locked();
        let status_b = read_locked(REG_STATUS_B);
        wait_update_complete_locked()?;
        let second = raw_snapshot_locked();
        if first == second {
            return decode_snapshot(second, status_b);
        }
    }
    Err(CmosError::UnstableClock)
}

fn encode_field(value: u8, binary: bool) -> u8 {
    if binary {
        value
    } else {
        encode_bcd(value)
    }
}

/// Set the RTC while preserving its binary/BCD, 12/24-hour, alarm, and
/// interrupt configuration. Status-B SET freezes the update cycle across the
/// multi-register write.
pub fn rtc_set(datetime: DateTime) -> Result<(), CmosError> {
    validate(datetime)?;
    let _guard = CMOS_LOCK.lock();
    wait_update_complete_locked()?;
    let status_b = read_locked(REG_STATUS_B);
    let binary = status_b & STATUS_B_BINARY != 0;
    let hours_24 = status_b & STATUS_B_24_HOUR != 0;
    write_locked(REG_STATUS_B, status_b | STATUS_B_SET);

    let encoded_hours = if hours_24 {
        encode_field(datetime.hours, binary)
    } else {
        let pm = datetime.hours >= 12;
        let hour12 = match datetime.hours % 12 {
            0 => 12,
            hour => hour,
        };
        encode_field(hour12, binary) | if pm { 0x80 } else { 0 }
    };
    write_locked(REG_SECONDS, encode_field(datetime.seconds, binary));
    write_locked(REG_MINUTES, encode_field(datetime.minutes, binary));
    write_locked(REG_HOURS, encoded_hours);
    write_locked(REG_DAY, encode_field(datetime.day, binary));
    write_locked(REG_MONTH, encode_field(datetime.month, binary));
    write_locked(REG_YEAR, encode_field((datetime.year % 100) as u8, binary));
    write_locked(
        REG_CENTURY,
        encode_field((datetime.year / 100) as u8, binary),
    );
    write_locked(REG_STATUS_B, status_b & !STATUS_B_SET);
    Ok(())
}

/// Probe the RTC once for device-phase diagnostics.
pub fn init() -> Result<DateTime, CmosError> {
    let now = rtc_now()?;
    ::log::info!("xenith.cmos: RTC {}, 128-byte NVRAM online", now);
    Ok(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcd_conversion_rejects_invalid_digits() {
        assert_eq!(decode_bcd(0x59), Ok(59));
        assert_eq!(decode_bcd(0x6A), Err(CmosError::InvalidBcd));
    }

    #[test]
    fn twelve_hour_midnight_and_noon_decode() {
        let base = RawRtc {
            seconds: 0,
            minutes: 0,
            hours: 12,
            day: 1,
            month: 1,
            year: 26,
            century: 20,
        };
        assert_eq!(decode_snapshot(base, STATUS_B_BINARY).unwrap().hours, 0);
        assert_eq!(
            decode_snapshot(
                RawRtc {
                    hours: 0x80 | 12,
                    ..base
                },
                STATUS_B_BINARY
            )
            .unwrap()
            .hours,
            12
        );
    }

    #[test]
    fn calendar_validation_handles_leap_day() {
        let leap = DateTime {
            seconds: 0,
            minutes: 0,
            hours: 0,
            day: 29,
            month: 2,
            year: 2024,
        };
        assert_eq!(validate(leap), Ok(()));
        assert_eq!(
            validate(DateTime { year: 2023, ..leap }),
            Err(CmosError::InvalidDate)
        );
    }
}
