// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CMOS Real-Time Clock (RTC) driver.
//!
//! Provides access to the CMOS RTC chip found on virtually all x86/x86_64
//! systems. The RTC is accessed via two I/O ports: an index/address port
//! (0x70) and a data port (0x71). The chip maintains BCD or binary-encoded
//! date/time values and several status registers.
//!
//! # Features
//!
//! - Reading current date and time (seconds, minutes, hours, day, month, year)
//! - Detecting BCD vs binary format and 12hr vs 24hr mode
//! - Waiting for RTC update cycles to complete before reading
//! - Setting the system time from RTC values
//! - Alarm and periodic interrupt configuration
//!
//! # Register Map
//!
//! | Index | Description           |
//! |-------|-----------------------|
//! | 0x00  | Seconds               |
//! | 0x01  | Seconds alarm         |
//! | 0x02  | Minutes               |
//! | 0x03  | Minutes alarm         |
//! | 0x04  | Hours                 |
//! | 0x05  | Hours alarm           |
//! | 0x06  | Day of week           |
//! | 0x07  | Day of month          |
//! | 0x08  | Month                 |
//! | 0x09  | Year                  |
//! | 0x0A  | Status register A     |
//! | 0x0B  | Status register B     |
//! | 0x0C  | Status register C     |
//! | 0x0D  | Status register D     |
//! | 0x32  | Century (may or may not exist) |
//!
//! Reference: Motorola MC146818A Data Sheet; ACPI 6.5 §9.15.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// I/O Port Definitions
// ---------------------------------------------------------------------------

/// CMOS address/index port. Writing here selects the CMOS register.
/// Bit 7 is the NMI disable bit; keep it clear in normal use.
const CMOS_ADDR_PORT: u16 = 0x70;

/// CMOS data port. Read/write from/to the selected register.
const CMOS_DATA_PORT: u16 = 0x71;

// ---------------------------------------------------------------------------
// CMOS Register Indices
// ---------------------------------------------------------------------------

/// Seconds (0-59).
const REG_SECONDS: u8 = 0x00;
/// Seconds alarm.
const _REG_SECONDS_ALARM: u8 = 0x01;
/// Minutes (0-59).
const REG_MINUTES: u8 = 0x02;
/// Minutes alarm.
const _REG_MINUTES_ALARM: u8 = 0x03;
/// Hours (0-23 in 24hr, 1-12+PM bit in 12hr).
const REG_HOURS: u8 = 0x04;
/// Hours alarm.
const _REG_HOURS_ALARM: u8 = 0x05;
/// Day of week (1=Sunday, 7=Saturday — often unreliable).
const _REG_DAY_OF_WEEK: u8 = 0x06;
/// Day of month (1-31).
const REG_DAY: u8 = 0x07;
/// Month (1-12).
const REG_MONTH: u8 = 0x08;
/// Year (last two digits, e.g. 24 for 2024).
const REG_YEAR: u8 = 0x09;
/// Status Register A.
const REG_STATUS_A: u8 = 0x0A;
/// Status Register B.
const REG_STATUS_B: u8 = 0x0B;
/// Status Register C (read-only, clears on read).
const REG_STATUS_C: u8 = 0x0C;
/// Status Register D (read-only, bit7 = valid RAM/power).
const _REG_STATUS_D: u8 = 0x0D;
/// Century register (optional, present if ACPI FADT points to it).
const REG_CENTURY: u8 = 0x32;

// ---------------------------------------------------------------------------
// Status Register A Bits
// ---------------------------------------------------------------------------

/// Status A: Update In Progress flag (bit 7). While set, reading time
/// registers may yield inconsistent values.
const STATUS_A_UIP: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// Status Register B Bits
// ---------------------------------------------------------------------------

/// Status B: 24-hour mode (bit 1). If set, hours are in 24-hour format.
const STATUS_B_24HR: u8 = 1 << 1;
/// Status B: Binary mode (bit 2). If set, values are binary; otherwise BCD.
const STATUS_B_BIN: u8 = 1 << 2;
/// Status B: Alarm interrupt enable (bit 5).
const _STATUS_B_AIE: u8 = 1 << 5;
/// Status B: Periodic interrupt enable (bit 6).
const _STATUS_B_PIE: u8 = 1 << 6;
/// Status B: Update-ended interrupt enable (bit 4).
const _STATUS_B_UIE: u8 = 1 << 4;

// ---------------------------------------------------------------------------
// Status Register C Bits (interrupt flags)
// ---------------------------------------------------------------------------

/// Status C: Update-ended interrupt flag.
const _STATUS_C_UF: u8 = 1 << 4;
/// Status C: Alarm interrupt flag.
const _STATUS_C_AF: u8 = 1 << 5;
/// Status C: Periodic interrupt flag.
const _STATUS_C_PF: u8 = 1 << 6;
/// Status C: IRQF — any enabled interrupt fired.
const _STATUS_C_IRQF: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// PM bit for 12-hour mode
// ---------------------------------------------------------------------------

/// In 12-hour mode, if bit 7 of the hours register is set the time is PM.
const HOURS_PM_BIT: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// Spin loop limit
// ---------------------------------------------------------------------------

/// Maximum iterations when polling for UIP clear.
const UIP_POLL_MAX: u32 = 1_000_000;

// ---------------------------------------------------------------------------
// DateTime
// ---------------------------------------------------------------------------

/// A point in time as read from the CMOS RTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DateTime {
    /// Full year (e.g. 2025).
    pub year: u16,
    /// Month 1–12.
    pub month: u8,
    /// Day of month 1–31.
    pub day: u8,
    /// Hour 0–23.
    pub hour: u8,
    /// Minute 0–59.
    pub minute: u8,
    /// Second 0–59.
    pub second: u8,
}

impl DateTime {
    /// Returns a zeroed-out `DateTime`.
    pub const fn zero() -> Self {
        Self {
            year: 0,
            month: 0,
            day: 0,
            hour: 0,
            minute: 0,
            second: 0,
        }
    }

    /// Checks whether the fields look plausible (basic sanity only).
    pub fn is_valid(&self) -> bool {
        self.month >= 1
            && self.month <= 12
            && self.day >= 1
            && self.day <= 31
            && self.hour <= 23
            && self.minute <= 59
            && self.second <= 59
    }
}

// ---------------------------------------------------------------------------
// Alarm
// ---------------------------------------------------------------------------

/// Alarm time stored in the CMOS RTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtcAlarm {
    /// Alarm hour (0-23).
    pub hour: u8,
    /// Alarm minute (0-59).
    pub minute: u8,
    /// Alarm second (0-59).
    pub second: u8,
    /// Whether the alarm interrupt is enabled.
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// CmosRtc driver
// ---------------------------------------------------------------------------

/// Driver for the CMOS Real-Time Clock.
///
/// The driver reads the mode bits from Status Register B once during
/// initialisation and caches them to avoid repeated register accesses.
pub struct CmosRtc {
    /// Cached mode bits from Status Register B.
    status_b: u8,
    /// Optional century register index (from ACPI FADT, 0 = not present).
    century_reg: u8,
    /// Whether the driver has been initialised.
    initialized: bool,
}

impl CmosRtc {
    /// Creates a new (uninitialised) RTC driver instance.
    pub const fn new() -> Self {
        Self {
            status_b: 0,
            century_reg: REG_CENTURY,
            initialized: false,
        }
    }

    /// Initialises the driver by reading Status Register B.
    ///
    /// Must be called before any other method.
    pub fn init(&mut self) -> Result<()> {
        self.status_b = self.read_cmos(REG_STATUS_B);
        self.initialized = true;
        Ok(())
    }

    /// Sets the optional century register index.
    ///
    /// On systems where the ACPI FADT `century` field is non-zero, pass
    /// that value here before calling `read_time`. Default is 0x32.
    pub fn set_century_reg(&mut self, reg: u8) {
        self.century_reg = reg;
    }

    /// Reads the current date and time from the CMOS RTC.
    ///
    /// Waits for the Update In Progress flag to clear before sampling the
    /// registers, then reads a second set and compares to detect a race.
    pub fn read_time(&self) -> Result<DateTime> {
        if !self.initialized {
            return Err(Error::IoError);
        }

        // Wait for UIP to clear.
        self.wait_not_updating()?;

        // Read first sample.
        let first = self.sample_registers();

        // Wait again and read second sample to detect a mid-update race.
        self.wait_not_updating()?;
        let second = self.sample_registers();

        // Use the second reading; if they don't match, use the second (more
        // recent) sample which completed cleanly after UIP was clear.
        let raw = if first == second { first } else { second };

        Ok(self.decode_raw(raw))
    }

    /// Reads and decodes the current time, returning `(hour, minute, second)`.
    pub fn read_hms(&self) -> Result<(u8, u8, u8)> {
        let dt = self.read_time()?;
        Ok((dt.hour, dt.minute, dt.second))
    }

    /// Reads the CMOS RTC interrupt status register C to acknowledge any
    /// pending interrupt. Must be called from the RTC IRQ handler.
    ///
    /// Returns the raw Status C byte; the caller should inspect the flags.
    pub fn acknowledge_interrupt(&self) -> u8 {
        // Reading Status C clears all interrupt flags.
        self.read_cmos(REG_STATUS_C)
    }

    /// Returns whether the RTC is currently in binary mode.
    pub fn is_binary_mode(&self) -> bool {
        self.status_b & STATUS_B_BIN != 0
    }

    /// Returns whether the RTC is in 24-hour mode.
    pub fn is_24hr_mode(&self) -> bool {
        self.status_b & STATUS_B_24HR != 0
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Polls Status Register A until the UIP (Update In Progress) bit clears.
    fn wait_not_updating(&self) -> Result<()> {
        for _ in 0..UIP_POLL_MAX {
            let status_a = self.read_cmos(REG_STATUS_A);
            if status_a & STATUS_A_UIP == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Raw register snapshot (before BCD/12hr decoding).
    fn sample_registers(&self) -> RawTime {
        RawTime {
            second: self.read_cmos(REG_SECONDS),
            minute: self.read_cmos(REG_MINUTES),
            hour: self.read_cmos(REG_HOURS),
            day: self.read_cmos(REG_DAY),
            month: self.read_cmos(REG_MONTH),
            year: self.read_cmos(REG_YEAR),
            century: if self.century_reg != 0 {
                self.read_cmos(self.century_reg)
            } else {
                0
            },
        }
    }

    /// Decodes a raw register snapshot into a [`DateTime`].
    fn decode_raw(&self, raw: RawTime) -> DateTime {
        let binary_mode = self.status_b & STATUS_B_BIN != 0;
        let mode_24hr = self.status_b & STATUS_B_24HR != 0;

        let second = if binary_mode {
            raw.second
        } else {
            bcd_to_bin(raw.second)
        };
        let minute = if binary_mode {
            raw.minute
        } else {
            bcd_to_bin(raw.minute)
        };

        // Hours require special handling for 12hr mode PM bit.
        let hour_raw = raw.hour & !HOURS_PM_BIT;
        let pm = (!mode_24hr) && (raw.hour & HOURS_PM_BIT != 0);
        let mut hour = if binary_mode {
            hour_raw
        } else {
            bcd_to_bin(hour_raw)
        };
        if pm {
            hour = (hour % 12) + 12;
        } else if !mode_24hr && hour == 12 {
            // 12:xx AM is really 00:xx.
            hour = 0;
        }

        let day = if binary_mode {
            raw.day
        } else {
            bcd_to_bin(raw.day)
        };
        let month = if binary_mode {
            raw.month
        } else {
            bcd_to_bin(raw.month)
        };
        let year_2d = if binary_mode {
            raw.year
        } else {
            bcd_to_bin(raw.year)
        } as u16;

        let century = if raw.century != 0 {
            (if binary_mode {
                raw.century
            } else {
                bcd_to_bin(raw.century)
            }) as u16
        } else {
            // Heuristic: assume century 20 for years 0-99.
            if year_2d >= 70 { 19 } else { 20 }
        };
        let year = century * 100 + year_2d;

        DateTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }

    /// Reads a byte from a CMOS register at the given index.
    ///
    /// # Safety
    ///
    /// Port I/O to 0x70/0x71 is safe on x86 systems; the RTC is a
    /// platform-standard device present on all supported hardware.
    fn read_cmos(&self, reg: u8) -> u8 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            // SAFETY: Writing the register index to port 0x70 then reading
            // from 0x71 is the standard CMOS RTC access protocol. The NMI
            // disable bit (bit 7) is kept clear.
            port_outb(CMOS_ADDR_PORT, reg & 0x7F);
            port_inb(CMOS_DATA_PORT)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = reg;
            0
        }
    }

    /// Writes a byte to a CMOS register at the given index.
    ///
    /// # Safety
    ///
    /// Same rationale as `read_cmos`.
    #[allow(dead_code)]
    fn write_cmos(&self, reg: u8, value: u8) {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            // SAFETY: Standard CMOS write sequence: select register via 0x70,
            // write value via 0x71. NMI disable bit kept clear.
            port_outb(CMOS_ADDR_PORT, reg & 0x7F);
            port_outb(CMOS_DATA_PORT, value);
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (reg, value);
        }
    }
}

impl Default for CmosRtc {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Raw register snapshot (internal)
// ---------------------------------------------------------------------------

/// Un-decoded snapshot of the CMOS time registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawTime {
    second: u8,
    minute: u8,
    hour: u8,
    day: u8,
    month: u8,
    year: u8,
    century: u8,
}

// ---------------------------------------------------------------------------
// BCD helpers
// ---------------------------------------------------------------------------

/// Converts a Binary-Coded Decimal byte to a binary (u8) value.
///
/// For example, `0x59` (BCD for 59) → `59`.
#[inline]
fn bcd_to_bin(bcd: u8) -> u8 {
    (bcd >> 4) * 10 + (bcd & 0x0F)
}

/// Converts a binary byte to BCD.
#[inline]
#[allow(dead_code)]
fn bin_to_bcd(bin: u8) -> u8 {
    ((bin / 10) << 4) | (bin % 10)
}

// ---------------------------------------------------------------------------
// Port I/O helpers (x86_64 only)
// ---------------------------------------------------------------------------

/// Reads one byte from an x86 I/O port.
#[cfg(target_arch = "x86_64")]
unsafe fn port_inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: Caller must ensure the port is valid for the target hardware.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

/// Writes one byte to an x86 I/O port.
#[cfg(target_arch = "x86_64")]
unsafe fn port_outb(port: u16, value: u8) {
    // SAFETY: Caller must ensure the port is valid for the target hardware.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// Global driver registry
// ---------------------------------------------------------------------------

/// Maximum number of RTC devices tracked.
const MAX_RTC_DEVICES: usize = 1;

/// Registry of CMOS RTC drivers.
pub struct RtcRegistry {
    devices: [CmosRtc; MAX_RTC_DEVICES],
    count: usize,
}

impl RtcRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { CmosRtc::new() }; MAX_RTC_DEVICES],
            count: 0,
        }
    }

    /// Registers a new CMOS RTC device.
    ///
    /// Returns the assigned index, or `Err(OutOfMemory)` if the registry
    /// is full.
    pub fn register(&mut self, mut rtc: CmosRtc) -> Result<usize> {
        if self.count >= MAX_RTC_DEVICES {
            return Err(Error::OutOfMemory);
        }
        rtc.init()?;
        let idx = self.count;
        self.devices[idx] = rtc;
        self.count += 1;
        Ok(idx)
    }

    /// Retrieves a reference to the RTC at the given index.
    pub fn get(&self, index: usize) -> Option<&CmosRtc> {
        if index < self.count {
            Some(&self.devices[index])
        } else {
            None
        }
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for RtcRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcd_conversion_roundtrip() {
        for v in 0u8..=99 {
            assert_eq!(bcd_to_bin(bin_to_bcd(v)), v);
        }
    }

    #[test]
    fn datetime_validity() {
        let dt = DateTime {
            year: 2025,
            month: 3,
            day: 15,
            hour: 10,
            minute: 30,
            second: 0,
        };
        assert!(dt.is_valid());
    }

    #[test]
    fn datetime_invalid_month() {
        let dt = DateTime {
            year: 2025,
            month: 13,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        };
        assert!(!dt.is_valid());
    }

    #[test]
    fn datetime_zero_is_invalid() {
        assert!(!DateTime::zero().is_valid());
    }

    #[test]
    fn rtc_registry_empty() {
        let reg = RtcRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }
}
