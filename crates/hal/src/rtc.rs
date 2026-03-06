// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CMOS Real-Time Clock (RTC) driver.
//!
//! Provides access to the MC146818-compatible CMOS RTC found on
//! x86_64 systems. Supports reading and writing date/time, BCD
//! and binary mode detection, and conversion to/from Unix
//! timestamps.

use oncrix_lib::Result;

// ── CMOS register addresses ────────────────────────────────────

/// CMOS register: seconds (0–59).
const RTC_SECONDS: u8 = 0x00;
/// CMOS register: minutes (0–59).
const RTC_MINUTES: u8 = 0x02;
/// CMOS register: hours (0–23 or 1–12 + AM/PM).
const RTC_HOURS: u8 = 0x04;
/// CMOS register: day of week (1–7, Sunday = 1).
const RTC_DAY_OF_WEEK: u8 = 0x06;
/// CMOS register: day of month (1–31).
const RTC_DAY_OF_MONTH: u8 = 0x07;
/// CMOS register: month (1–12).
const RTC_MONTH: u8 = 0x08;
/// CMOS register: year (0–99, last two digits).
const RTC_YEAR: u8 = 0x09;
/// CMOS register: century (19–20+).
const RTC_CENTURY: u8 = 0x32;
/// CMOS Status Register A.
const RTC_STATUS_A: u8 = 0x0A;
/// CMOS Status Register B.
const RTC_STATUS_B: u8 = 0x0B;

/// CMOS address port (I/O port 0x70).
const CMOS_ADDR_PORT: u16 = 0x70;
/// CMOS data port (I/O port 0x71).
const CMOS_DATA_PORT: u16 = 0x71;

// ── DateTime ───────────────────────────────────────────────────

/// Calendar date and time read from the RTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    /// Full year (e.g. 2026).
    pub year: u16,
    /// Month (1–12).
    pub month: u8,
    /// Day of month (1–31).
    pub day: u8,
    /// Hour (0–23).
    pub hour: u8,
    /// Minute (0–59).
    pub minute: u8,
    /// Second (0–59).
    pub second: u8,
    /// Day of week (1–7, Sunday = 1).
    pub day_of_week: u8,
}

// ── RtcDriver ──────────────────────────────────────────────────

/// CMOS RTC hardware driver.
///
/// All port I/O is gated behind `#[cfg(target_arch = "x86_64")]`.
pub struct RtcDriver;

impl Default for RtcDriver {
    fn default() -> Self {
        Self
    }
}

impl RtcDriver {
    /// Create a new RTC driver instance.
    pub const fn new() -> Self {
        Self
    }

    /// Read a single CMOS register.
    #[cfg(target_arch = "x86_64")]
    pub fn read_cmos(&self, reg: u8) -> u8 {
        // SAFETY: CMOS ports 0x70/0x71 are standard x86_64 I/O
        // ports accessible at Ring 0. NMI disable bit (0x80) is
        // preserved by masking the register address to 7 bits.
        unsafe {
            super::arch::x86_64::io::outb(CMOS_ADDR_PORT, reg);
            super::arch::x86_64::io::inb(CMOS_DATA_PORT)
        }
    }

    /// Write a value to a CMOS register.
    #[cfg(target_arch = "x86_64")]
    pub fn write_cmos(&self, reg: u8, val: u8) {
        // SAFETY: CMOS ports 0x70/0x71 are standard x86_64 I/O
        // ports accessible at Ring 0.
        unsafe {
            super::arch::x86_64::io::outb(CMOS_ADDR_PORT, reg);
            super::arch::x86_64::io::outb(CMOS_DATA_PORT, val);
        }
    }

    /// Check whether an RTC update is currently in progress.
    ///
    /// When bit 7 of Status Register A is set, the RTC is
    /// transferring time data from the clock divider to the
    /// readable registers and values may be inconsistent.
    #[cfg(target_arch = "x86_64")]
    pub fn is_update_in_progress(&self) -> bool {
        self.read_cmos(RTC_STATUS_A) & 0x80 != 0
    }

    /// Read the current date and time from the CMOS RTC.
    ///
    /// Performs two consecutive reads and retries until both
    /// produce identical values, guaranteeing a consistent
    /// snapshot. Automatically converts from BCD to binary
    /// when the RTC is in BCD mode (Status B bit 2 clear).
    #[cfg(target_arch = "x86_64")]
    pub fn read_datetime(&self) -> DateTime {
        // Wait for any in-progress update to finish.
        while self.is_update_in_progress() {
            core::hint::spin_loop();
        }
        let mut dt = self.read_raw_datetime();

        // Read until two consecutive snapshots match.
        loop {
            while self.is_update_in_progress() {
                core::hint::spin_loop();
            }
            let dt2 = self.read_raw_datetime();
            if dt == dt2 {
                break;
            }
            dt = dt2;
        }

        // Determine whether RTC values are in BCD format.
        let status_b = self.read_cmos(RTC_STATUS_B);
        let is_binary = status_b & 0x04 != 0;

        if !is_binary {
            dt.second = bcd_to_binary(dt.second);
            dt.minute = bcd_to_binary(dt.minute);
            dt.hour = bcd_to_binary(dt.hour);
            dt.day = bcd_to_binary(dt.day);
            dt.month = bcd_to_binary(dt.month);
            dt.year = bcd_to_binary(dt.year as u8) as u16;
            dt.day_of_week = bcd_to_binary(dt.day_of_week);
        }

        // Reconstruct full year from century register.
        let century = if !is_binary {
            bcd_to_binary(self.read_cmos(RTC_CENTURY))
        } else {
            self.read_cmos(RTC_CENTURY)
        };
        dt.year += century as u16 * 100;

        dt
    }

    /// Read raw (possibly BCD-encoded) fields from CMOS.
    #[cfg(target_arch = "x86_64")]
    fn read_raw_datetime(&self) -> DateTime {
        DateTime {
            second: self.read_cmos(RTC_SECONDS),
            minute: self.read_cmos(RTC_MINUTES),
            hour: self.read_cmos(RTC_HOURS),
            day_of_week: self.read_cmos(RTC_DAY_OF_WEEK),
            day: self.read_cmos(RTC_DAY_OF_MONTH),
            month: self.read_cmos(RTC_MONTH),
            year: self.read_cmos(RTC_YEAR) as u16,
        }
    }

    /// Write a date/time to the CMOS RTC registers.
    ///
    /// The values are written in the format (BCD or binary) that
    /// the RTC is currently configured to use.
    #[cfg(target_arch = "x86_64")]
    pub fn set_datetime(&self, dt: &DateTime) -> Result<()> {
        let status_b = self.read_cmos(RTC_STATUS_B);
        let is_binary = status_b & 0x04 != 0;

        let (sec, min, hr, dow, day, mon, yr, cen) = if is_binary {
            (
                dt.second,
                dt.minute,
                dt.hour,
                dt.day_of_week,
                dt.day,
                dt.month,
                (dt.year % 100) as u8,
                (dt.year / 100) as u8,
            )
        } else {
            (
                binary_to_bcd(dt.second),
                binary_to_bcd(dt.minute),
                binary_to_bcd(dt.hour),
                binary_to_bcd(dt.day_of_week),
                binary_to_bcd(dt.day),
                binary_to_bcd(dt.month),
                binary_to_bcd((dt.year % 100) as u8),
                binary_to_bcd((dt.year / 100) as u8),
            )
        };

        // Wait for update to complete before writing.
        while self.is_update_in_progress() {
            core::hint::spin_loop();
        }

        self.write_cmos(RTC_SECONDS, sec);
        self.write_cmos(RTC_MINUTES, min);
        self.write_cmos(RTC_HOURS, hr);
        self.write_cmos(RTC_DAY_OF_WEEK, dow);
        self.write_cmos(RTC_DAY_OF_MONTH, day);
        self.write_cmos(RTC_MONTH, mon);
        self.write_cmos(RTC_YEAR, yr);
        self.write_cmos(RTC_CENTURY, cen);

        Ok(())
    }
}

// ── BCD conversion helpers ─────────────────────────────────────

/// Convert a BCD-encoded byte to binary.
///
/// BCD stores the tens digit in the high nibble and the ones
/// digit in the low nibble (e.g. `0x59` represents 59).
pub fn bcd_to_binary(bcd: u8) -> u8 {
    (bcd & 0x0F) + ((bcd >> 4) * 10)
}

/// Convert a binary value (0–99) to BCD encoding.
pub fn binary_to_bcd(val: u8) -> u8 {
    ((val / 10) << 4) | (val % 10)
}

// ── Unix timestamp conversion ──────────────────────────────────

/// Number of days in each month for a non-leap year.
const DAYS_IN_MONTH: [u16; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Returns `true` if `year` is a leap year.
fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Convert a [`DateTime`] to a Unix timestamp (seconds since
/// 1970-01-01 00:00:00 UTC).
///
/// Handles leap years correctly. Does not account for leap
/// seconds.
pub fn unix_timestamp(dt: &DateTime) -> u64 {
    let mut days: u64 = 0;

    // Sum complete years since the epoch.
    for y in 1970..dt.year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Sum complete months in the current year.
    for (m, &d) in DAYS_IN_MONTH
        .iter()
        .enumerate()
        .take(dt.month.saturating_sub(1) as usize)
    {
        days += d as u64;
        if m == 1 && is_leap_year(dt.year) {
            days += 1; // February leap day
        }
    }

    // Add days within the current month (1-based).
    days += dt.day.saturating_sub(1) as u64;

    days * 86_400 + dt.hour as u64 * 3_600 + dt.minute as u64 * 60 + dt.second as u64
}

/// Convert a Unix timestamp back to a [`DateTime`].
///
/// The `day_of_week` field is computed (1 = Sunday, 7 = Saturday).
pub fn datetime_from_timestamp(ts: u64) -> DateTime {
    let mut remaining = ts;

    let second = (remaining % 60) as u8;
    remaining /= 60;
    let minute = (remaining % 60) as u8;
    remaining /= 60;
    let hour = (remaining % 24) as u8;
    let mut days = remaining / 24;

    // 1970-01-01 was a Thursday (day_of_week = 5).
    // 1=Sun, 2=Mon, ..., 5=Thu, 6=Fri, 7=Sat.
    let dow = ((days + 4) % 7) + 1; // +4 because Thu=4 in 0-based

    let mut year: u16 = 1970;
    loop {
        let ylen: u64 = if is_leap_year(year) { 366 } else { 365 };
        if days < ylen {
            break;
        }
        days -= ylen;
        year += 1;
    }

    let mut month: u8 = 1;
    for m in 0..12u8 {
        let mut mlen = DAYS_IN_MONTH[m as usize] as u64;
        if m == 1 && is_leap_year(year) {
            mlen += 1;
        }
        if days < mlen {
            month = m + 1;
            break;
        }
        days -= mlen;
    }

    let day = days as u8 + 1;

    DateTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        day_of_week: dow as u8,
    }
}

// ── Wallclock ──────────────────────────────────────────────────

/// Wallclock timer combining RTC boot time with a monotonic tick
/// counter for sub-second precision.
///
/// Initialised once at boot from the RTC, then uses a tick
/// source (e.g. APIC or PIT) to track elapsed time without
/// further RTC reads.
pub struct Wallclock {
    /// Unix timestamp captured at boot.
    boot_time: u64,
    /// Tick counter value captured at boot.
    boot_tick: u64,
    /// Tick source frequency (ticks per second).
    ticks_per_sec: u64,
}

impl Wallclock {
    /// Initialise the wallclock from the RTC and a tick source.
    ///
    /// `current_tick` and `tps` come from whatever timer is
    /// driving the monotonic counter (PIT, APIC timer, etc.).
    #[cfg(target_arch = "x86_64")]
    pub fn init(rtc: &RtcDriver, current_tick: u64, tps: u64) -> Self {
        let dt = rtc.read_datetime();
        Self {
            boot_time: unix_timestamp(&dt),
            boot_tick: current_tick,
            ticks_per_sec: tps,
        }
    }

    /// Return the current Unix timestamp.
    pub fn now(&self, current_tick: u64) -> u64 {
        self.boot_time + self.uptime_secs(current_tick)
    }

    /// Return the current date and time as a [`DateTime`].
    pub fn now_datetime(&self, current_tick: u64) -> DateTime {
        datetime_from_timestamp(self.now(current_tick))
    }

    /// Return the number of whole seconds since boot.
    pub fn uptime_secs(&self, current_tick: u64) -> u64 {
        if self.ticks_per_sec == 0 {
            return 0;
        }
        let elapsed = current_tick.saturating_sub(self.boot_tick);
        elapsed / self.ticks_per_sec
    }
}
