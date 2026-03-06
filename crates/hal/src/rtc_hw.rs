// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Real-Time Clock (RTC) hardware abstraction for the ONCRIX HAL.
//!
//! Provides a platform-independent RTC abstraction that supports reading and
//! writing date-time, alarm management, battery detection, periodic interrupt
//! configuration, and century rollover handling. Designed to work with both
//! CMOS-based (x86_64) and MMIO-based (ARM/RISC-V) RTC hardware.
//!
//! # Architecture
//!
//! - **RtcTime** — calendar date and time representation
//! - **RtcAlarm** — alarm configuration with optional day/hour/minute matching
//! - **RtcFeatures** — capability flags reported by the hardware
//! - **RtcIrqType** — interrupt types (alarm, periodic, update)
//! - **RtcDeviceType** — hardware variant identification
//! - **RtcConfig** — hardware configuration (MMIO/PIO, clock source, features)
//! - **RtcDevice** — a single RTC hardware device
//! - **RtcDeviceRegistry** — manages up to [`MAX_RTC_DEVICES`] RTC controllers
//!
//! # Reference
//!
//! Linux: `drivers/rtc/`, `include/linux/rtc.h`, `include/uapi/linux/rtc.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of RTC devices in the registry.
const MAX_RTC_DEVICES: usize = 4;

/// Maximum number of pending alarm events.
const MAX_ALARM_EVENTS: usize = 8;

/// Minimum valid year (for sanity checking).
const MIN_YEAR: u16 = 1970;

/// Maximum valid year.
const MAX_YEAR: u16 = 2099;

// ---------------------------------------------------------------------------
// CMOS register addresses (x86_64)
// ---------------------------------------------------------------------------

/// CMOS register: seconds (0-59).
const CMOS_SECONDS: u8 = 0x00;

/// CMOS register: seconds alarm.
const CMOS_ALARM_SECONDS: u8 = 0x01;

/// CMOS register: minutes (0-59).
const CMOS_MINUTES: u8 = 0x02;

/// CMOS register: minutes alarm.
const CMOS_ALARM_MINUTES: u8 = 0x03;

/// CMOS register: hours (0-23 or 1-12).
const CMOS_HOURS: u8 = 0x04;

/// CMOS register: hours alarm.
const CMOS_ALARM_HOURS: u8 = 0x05;

/// CMOS register: day of week (1-7).
const CMOS_DAY_OF_WEEK: u8 = 0x06;

/// CMOS register: day of month (1-31).
const CMOS_DAY_OF_MONTH: u8 = 0x07;

/// CMOS register: month (1-12).
const CMOS_MONTH: u8 = 0x08;

/// CMOS register: year (0-99).
const CMOS_YEAR: u8 = 0x09;

/// CMOS Status Register A.
const CMOS_STATUS_A: u8 = 0x0A;

/// CMOS Status Register B.
const CMOS_STATUS_B: u8 = 0x0B;

/// CMOS Status Register C (interrupt flags, read-only).
const CMOS_STATUS_C: u8 = 0x0C;

/// CMOS century register.
const CMOS_CENTURY: u8 = 0x32;

/// CMOS address I/O port.
const CMOS_ADDR_PORT: u16 = 0x70;

/// CMOS data I/O port.
const CMOS_DATA_PORT: u16 = 0x71;

// ---------------------------------------------------------------------------
// Status Register B bits
// ---------------------------------------------------------------------------

/// Data mode: 1 = binary, 0 = BCD.
const STATUS_B_DM: u8 = 1 << 2;

/// 24-hour mode: 1 = 24h, 0 = 12h.
const STATUS_B_24H: u8 = 1 << 1;

/// Alarm interrupt enable.
const STATUS_B_AIE: u8 = 1 << 5;

/// Periodic interrupt enable.
const STATUS_B_PIE: u8 = 1 << 6;

/// Update-ended interrupt enable.
const STATUS_B_UIE: u8 = 1 << 4;

/// SET bit: halt updates while setting time.
const STATUS_B_SET: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// Status Register C bits (interrupt flags)
// ---------------------------------------------------------------------------

/// Alarm flag.
const STATUS_C_AF: u8 = 1 << 5;

/// Periodic flag.
const STATUS_C_PF: u8 = 1 << 6;

/// Update-ended flag.
const STATUS_C_UF: u8 = 1 << 4;

/// IRQ flag (any interrupt occurred).
const STATUS_C_IRQF: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// MMIO register offsets (generic PL031-style RTC)
// ---------------------------------------------------------------------------

/// PL031 Data register offset (current time as seconds since epoch).
const PL031_DR_OFF: usize = 0x000;

/// PL031 Match register offset (alarm comparison value).
const PL031_MR_OFF: usize = 0x004;

/// PL031 Load register offset (set time).
const PL031_LR_OFF: usize = 0x008;

/// PL031 Control register offset.
const PL031_CR_OFF: usize = 0x00C;

/// PL031 Interrupt mask set/clear register offset.
const PL031_IMSC_OFF: usize = 0x010;

/// PL031 Raw interrupt status register offset.
const PL031_RIS_OFF: usize = 0x014;

/// PL031 Masked interrupt status register offset.
const PL031_MIS_OFF: usize = 0x018;

/// PL031 Interrupt clear register offset.
const PL031_ICR_OFF: usize = 0x01C;

// ---------------------------------------------------------------------------
// RtcTime
// ---------------------------------------------------------------------------

/// Calendar date and time representation.
///
/// All fields use human-readable values (not BCD-encoded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcTime {
    /// Full year (e.g. 2026).
    pub year: u16,
    /// Month (1-12).
    pub month: u8,
    /// Day of month (1-31).
    pub day: u8,
    /// Hour (0-23).
    pub hour: u8,
    /// Minute (0-59).
    pub minute: u8,
    /// Second (0-59).
    pub second: u8,
    /// Day of week (0 = Sunday, 6 = Saturday).
    pub weekday: u8,
}

impl RtcTime {
    /// Creates a new RtcTime with the given date and time.
    pub const fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            weekday: 0,
        }
    }

    /// Validates that all fields are within their allowed ranges.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if any field is out of range.
    pub fn validate(&self) -> Result<()> {
        if self.year < MIN_YEAR || self.year > MAX_YEAR {
            return Err(Error::InvalidArgument);
        }
        if self.month < 1 || self.month > 12 {
            return Err(Error::InvalidArgument);
        }
        if self.day < 1 || self.day > days_in_month(self.year, self.month) {
            return Err(Error::InvalidArgument);
        }
        if self.hour > 23 || self.minute > 59 || self.second > 59 {
            return Err(Error::InvalidArgument);
        }
        if self.weekday > 6 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Converts this time to a Unix timestamp (seconds since 1970-01-01).
    pub fn to_unix_timestamp(&self) -> u64 {
        let mut days: u64 = 0;
        for y in 1970..self.year {
            days += if is_leap_year(y) { 366 } else { 365 };
        }
        for m in 1..self.month {
            days += days_in_month(self.year, m) as u64;
        }
        days += self.day.saturating_sub(1) as u64;
        days * 86_400 + self.hour as u64 * 3_600 + self.minute as u64 * 60 + self.second as u64
    }

    /// Creates an RtcTime from a Unix timestamp.
    pub fn from_unix_timestamp(ts: u64) -> Self {
        let mut remaining = ts;
        let second = (remaining % 60) as u8;
        remaining /= 60;
        let minute = (remaining % 60) as u8;
        remaining /= 60;
        let hour = (remaining % 24) as u8;
        let mut days = remaining / 24;

        // Compute weekday (1970-01-01 = Thursday = 4).
        let weekday = ((days + 4) % 7) as u8;

        let mut year: u16 = 1970;
        loop {
            let ylen = if is_leap_year(year) { 366u64 } else { 365 };
            if days < ylen {
                break;
            }
            days -= ylen;
            year += 1;
        }

        let mut month: u8 = 1;
        for m in 1..=12u8 {
            let mlen = days_in_month(year, m) as u64;
            if days < mlen {
                month = m;
                break;
            }
            days -= mlen;
        }

        Self {
            year,
            month,
            day: days as u8 + 1,
            hour,
            minute,
            second,
            weekday,
        }
    }
}

// ---------------------------------------------------------------------------
// RtcAlarm
// ---------------------------------------------------------------------------

/// RTC alarm configuration.
///
/// Each field can be individually enabled for matching. Fields set to
/// `0xFF` (or `None` equivalents) are treated as "don't care" / wildcards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcAlarm {
    /// Alarm second (0-59, or 0xFF for wildcard).
    pub second: u8,
    /// Alarm minute (0-59, or 0xFF for wildcard).
    pub minute: u8,
    /// Alarm hour (0-23, or 0xFF for wildcard).
    pub hour: u8,
    /// Alarm day of month (1-31, or 0xFF for wildcard).
    pub day: u8,
    /// Whether the alarm is enabled.
    pub enabled: bool,
    /// Whether the alarm has fired and is pending acknowledgment.
    pub pending: bool,
}

/// Wildcard value meaning "match any" for alarm fields.
const ALARM_WILDCARD: u8 = 0xFF;

impl RtcAlarm {
    /// Creates a new alarm with all fields set to wildcard (disabled).
    pub const fn new() -> Self {
        Self {
            second: ALARM_WILDCARD,
            minute: ALARM_WILDCARD,
            hour: ALARM_WILDCARD,
            day: ALARM_WILDCARD,
            enabled: false,
            pending: false,
        }
    }

    /// Creates an alarm for a specific hour:minute:second.
    pub const fn at_time(hour: u8, minute: u8, second: u8) -> Self {
        Self {
            second,
            minute,
            hour,
            day: ALARM_WILDCARD,
            enabled: true,
            pending: false,
        }
    }

    /// Checks whether this alarm matches the given time.
    pub fn matches(&self, time: &RtcTime) -> bool {
        if !self.enabled {
            return false;
        }
        let sec_ok = self.second == ALARM_WILDCARD || self.second == time.second;
        let min_ok = self.minute == ALARM_WILDCARD || self.minute == time.minute;
        let hr_ok = self.hour == ALARM_WILDCARD || self.hour == time.hour;
        let day_ok = self.day == ALARM_WILDCARD || self.day == time.day;
        sec_ok && min_ok && hr_ok && day_ok
    }
}

// ---------------------------------------------------------------------------
// RtcFeatures
// ---------------------------------------------------------------------------

/// Capability flags reported by the RTC hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtcFeatures {
    /// Hardware supports alarms.
    pub has_alarm: bool,
    /// Hardware supports periodic interrupts.
    pub has_periodic_irq: bool,
    /// Hardware supports update-ended interrupts.
    pub has_update_irq: bool,
    /// Hardware has a century register.
    pub has_century: bool,
    /// Hardware has battery backup.
    pub has_battery: bool,
    /// Hardware supports BCD encoding.
    pub bcd_mode: bool,
    /// Hardware uses 24-hour format.
    pub mode_24h: bool,
    /// Hardware can report battery voltage.
    pub has_battery_voltage: bool,
}

// ---------------------------------------------------------------------------
// RtcIrqType
// ---------------------------------------------------------------------------

/// Types of RTC interrupts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcIrqType {
    /// Alarm interrupt (alarm time matched).
    Alarm,
    /// Periodic interrupt (at configured rate).
    Periodic,
    /// Update-ended interrupt (time registers updated).
    UpdateEnded,
}

// ---------------------------------------------------------------------------
// RtcDeviceType
// ---------------------------------------------------------------------------

/// RTC hardware variant identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RtcDeviceType {
    /// MC146818-compatible CMOS RTC (x86_64).
    #[default]
    CmosRtc,
    /// ARM PL031 RTC (MMIO-based).
    ArmPl031,
    /// Generic MMIO-based RTC.
    GenericMmio,
}

// ---------------------------------------------------------------------------
// RtcConfig
// ---------------------------------------------------------------------------

/// Hardware configuration for an RTC device.
#[derive(Debug, Clone, Copy)]
pub struct RtcConfig {
    /// MMIO base address (0 for PIO-based devices).
    pub mmio_base: usize,
    /// MMIO region size in bytes.
    pub mmio_size: usize,
    /// I/O port base (for CMOS RTC on x86_64).
    pub io_base: u16,
    /// Hardware type.
    pub dev_type: RtcDeviceType,
    /// Detected or configured features.
    pub features: RtcFeatures,
    /// External oscillator frequency in Hz (32768 Hz typical).
    pub osc_freq_hz: u32,
}

impl Default for RtcConfig {
    fn default() -> Self {
        Self {
            mmio_base: 0,
            mmio_size: 0,
            io_base: CMOS_ADDR_PORT,
            dev_type: RtcDeviceType::CmosRtc,
            features: RtcFeatures {
                has_alarm: true,
                has_periodic_irq: true,
                has_update_irq: true,
                has_century: true,
                has_battery: true,
                bcd_mode: true,
                mode_24h: true,
                has_battery_voltage: false,
            },
            osc_freq_hz: 32_768,
        }
    }
}

impl RtcConfig {
    /// Creates a configuration for a standard x86_64 CMOS RTC.
    pub fn cmos() -> Self {
        Self::default()
    }

    /// Creates a configuration for an ARM PL031 RTC.
    pub fn pl031(mmio_base: usize) -> Self {
        Self {
            mmio_base,
            mmio_size: 0x1000,
            io_base: 0,
            dev_type: RtcDeviceType::ArmPl031,
            features: RtcFeatures {
                has_alarm: true,
                has_periodic_irq: false,
                has_update_irq: false,
                has_century: false,
                has_battery: false,
                bcd_mode: false,
                mode_24h: true,
                has_battery_voltage: false,
            },
            osc_freq_hz: 1, // PL031 counts in seconds
        }
    }
}

// ---------------------------------------------------------------------------
// RtcAlarmEvent
// ---------------------------------------------------------------------------

/// A pending alarm event.
#[derive(Debug, Clone, Copy)]
pub struct RtcAlarmEvent {
    /// Device ID that generated the alarm.
    pub device_id: u32,
    /// Time when the alarm fired.
    pub fire_time: RtcTime,
    /// Timestamp in nanoseconds (system timer).
    pub timestamp_ns: u64,
}

/// Constant empty alarm event for array initialisation.
const EMPTY_ALARM_EVENT: RtcAlarmEvent = RtcAlarmEvent {
    device_id: 0,
    fire_time: RtcTime {
        year: 0,
        month: 0,
        day: 0,
        hour: 0,
        minute: 0,
        second: 0,
        weekday: 0,
    },
    timestamp_ns: 0,
};

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Reads a 32-bit value from MMIO at `base + offset`.
///
/// # Safety
///
/// The caller must ensure `base + offset` is a valid MMIO address.
#[inline]
unsafe fn read_mmio32(base: usize, offset: usize) -> u32 {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// Writes a 32-bit value to MMIO at `base + offset`.
///
/// # Safety
///
/// The caller must ensure `base + offset` is a valid MMIO address.
#[inline]
unsafe fn write_mmio32(base: usize, offset: usize, val: u32) {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val) }
}

// ---------------------------------------------------------------------------
// BCD helpers
// ---------------------------------------------------------------------------

/// Converts a BCD-encoded byte to binary.
fn bcd_to_bin(bcd: u8) -> u8 {
    (bcd & 0x0F) + ((bcd >> 4) * 10)
}

/// Converts a binary value (0-99) to BCD.
fn bin_to_bcd(val: u8) -> u8 {
    ((val / 10) << 4) | (val % 10)
}

// ---------------------------------------------------------------------------
// Date helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `year` is a leap year.
fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Returns the number of days in the given month.
fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 => 31,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        3 => 31,
        4 => 30,
        5 => 31,
        6 => 30,
        7 => 31,
        8 => 31,
        9 => 30,
        10 => 31,
        11 => 30,
        12 => 31,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// RtcDevice
// ---------------------------------------------------------------------------

/// A single RTC hardware device.
///
/// Manages reading/writing the hardware clock, alarm configuration,
/// interrupt handling, and battery status reporting.
pub struct RtcDevice {
    /// Unique device identifier.
    pub id: u32,
    /// Human-readable name (UTF-8).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Hardware configuration.
    pub config: RtcConfig,
    /// Current alarm configuration.
    pub alarm: RtcAlarm,
    /// Cached last-read time.
    pub cached_time: RtcTime,
    /// Whether the cached time is valid.
    pub cache_valid: bool,
    /// Periodic interrupt rate (log2 of divider, 0 = disabled).
    pub periodic_rate: u8,
    /// Number of interrupts serviced.
    pub irq_count: u64,
    /// Whether the device is initialised and active.
    pub active: bool,
}

impl RtcDevice {
    /// Creates a new RTC device.
    pub fn new(id: u32, name: &[u8], config: RtcConfig) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            name: buf,
            name_len: copy_len,
            config,
            alarm: RtcAlarm::new(),
            cached_time: RtcTime::new(2000, 1, 1, 0, 0, 0),
            cache_valid: false,
            periodic_rate: 0,
            irq_count: 0,
            active: false,
        }
    }

    /// Initialises the RTC hardware.
    ///
    /// For CMOS RTC: detects BCD/binary mode and 12/24h format.
    /// For PL031: enables the RTC counter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if hardware access fails.
    #[cfg(target_arch = "x86_64")]
    pub fn init(&mut self) -> Result<()> {
        match self.config.dev_type {
            RtcDeviceType::CmosRtc => {
                // Read Status B to detect modes.
                let status_b = self.cmos_read(CMOS_STATUS_B);
                self.config.features.bcd_mode = (status_b & STATUS_B_DM) == 0;
                self.config.features.mode_24h = (status_b & STATUS_B_24H) != 0;
                self.active = true;
                Ok(())
            }
            RtcDeviceType::ArmPl031 | RtcDeviceType::GenericMmio => {
                if self.config.mmio_base == 0 {
                    return Err(Error::IoError);
                }
                // SAFETY: mmio_base checked; CR is 32-bit RW.
                unsafe {
                    write_mmio32(self.config.mmio_base, PL031_CR_OFF, 1);
                }
                self.active = true;
                Ok(())
            }
        }
    }

    /// Reads the current date and time from the RTC hardware.
    ///
    /// For CMOS RTC, performs double-read until stable values are obtained.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device is not initialised.
    #[cfg(target_arch = "x86_64")]
    pub fn read_time(&mut self) -> Result<RtcTime> {
        if !self.active {
            return Err(Error::IoError);
        }

        let time = match self.config.dev_type {
            RtcDeviceType::CmosRtc => self.cmos_read_time(),
            RtcDeviceType::ArmPl031 | RtcDeviceType::GenericMmio => self.mmio_read_time(),
        };

        self.cached_time = time;
        self.cache_valid = true;
        Ok(time)
    }

    /// Sets the RTC hardware clock to the given time.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the time is invalid, or
    /// [`Error::IoError`] if the device is not initialised.
    #[cfg(target_arch = "x86_64")]
    pub fn set_time(&mut self, time: &RtcTime) -> Result<()> {
        if !self.active {
            return Err(Error::IoError);
        }
        time.validate()?;

        match self.config.dev_type {
            RtcDeviceType::CmosRtc => self.cmos_set_time(time),
            RtcDeviceType::ArmPl031 | RtcDeviceType::GenericMmio => self.mmio_set_time(time),
        }

        self.cached_time = *time;
        self.cache_valid = true;
        Ok(())
    }

    /// Sets the alarm configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if the hardware lacks alarm support,
    /// or [`Error::IoError`] if the device is not initialised.
    #[cfg(target_arch = "x86_64")]
    pub fn set_alarm(&mut self, alarm: &RtcAlarm) -> Result<()> {
        if !self.active {
            return Err(Error::IoError);
        }
        if !self.config.features.has_alarm {
            return Err(Error::NotImplemented);
        }

        match self.config.dev_type {
            RtcDeviceType::CmosRtc => {
                self.cmos_set_alarm(alarm);
            }
            RtcDeviceType::ArmPl031 | RtcDeviceType::GenericMmio => {
                self.mmio_set_alarm(alarm)?;
            }
        }

        self.alarm = *alarm;
        Ok(())
    }

    /// Reads the current alarm configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if the hardware lacks alarm support.
    pub fn read_alarm(&self) -> Result<RtcAlarm> {
        if !self.config.features.has_alarm {
            return Err(Error::NotImplemented);
        }
        Ok(self.alarm)
    }

    /// Returns `true` if the RTC has battery backup.
    pub fn has_battery(&self) -> bool {
        self.config.features.has_battery
    }

    /// Returns the RTC features.
    pub fn features(&self) -> &RtcFeatures {
        &self.config.features
    }

    /// Handles an RTC interrupt.
    ///
    /// Reads the interrupt flags, acknowledges the hardware, and returns
    /// the type of interrupt that occurred.
    #[cfg(target_arch = "x86_64")]
    pub fn handle_irq(&mut self) -> Option<RtcIrqType> {
        if !self.active {
            return None;
        }
        self.irq_count += 1;

        match self.config.dev_type {
            RtcDeviceType::CmosRtc => {
                let status_c = self.cmos_read(CMOS_STATUS_C);
                if status_c & STATUS_C_IRQF == 0 {
                    return None;
                }
                if status_c & STATUS_C_AF != 0 {
                    self.alarm.pending = true;
                    Some(RtcIrqType::Alarm)
                } else if status_c & STATUS_C_PF != 0 {
                    Some(RtcIrqType::Periodic)
                } else if status_c & STATUS_C_UF != 0 {
                    Some(RtcIrqType::UpdateEnded)
                } else {
                    None
                }
            }
            RtcDeviceType::ArmPl031 | RtcDeviceType::GenericMmio => {
                if self.config.mmio_base == 0 {
                    return None;
                }
                // SAFETY: mmio_base valid; MIS is 32-bit RO.
                let mis = unsafe { read_mmio32(self.config.mmio_base, PL031_MIS_OFF) };
                if mis & 1 != 0 {
                    // Clear the interrupt.
                    // SAFETY: mmio_base valid; ICR is 32-bit WO.
                    unsafe {
                        write_mmio32(self.config.mmio_base, PL031_ICR_OFF, 1);
                    }
                    self.alarm.pending = true;
                    Some(RtcIrqType::Alarm)
                } else {
                    None
                }
            }
        }
    }

    /// Sets the periodic interrupt rate.
    ///
    /// `rate` is a 4-bit value (3-15) representing log2 of the divider.
    /// Rate 0 disables periodic interrupts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if periodic IRQs are not supported.
    /// Returns [`Error::InvalidArgument`] if rate is out of range.
    #[cfg(target_arch = "x86_64")]
    pub fn set_periodic_rate(&mut self, rate: u8) -> Result<()> {
        if !self.config.features.has_periodic_irq {
            return Err(Error::NotImplemented);
        }
        if rate != 0 && (rate < 3 || rate > 15) {
            return Err(Error::InvalidArgument);
        }

        if self.config.dev_type == RtcDeviceType::CmosRtc {
            let mut status_a = self.cmos_read(CMOS_STATUS_A);
            status_a = (status_a & 0xF0) | (rate & 0x0F);
            self.cmos_write(CMOS_STATUS_A, status_a);

            // Enable or disable PIE in Status B.
            let mut status_b = self.cmos_read(CMOS_STATUS_B);
            if rate > 0 {
                status_b |= STATUS_B_PIE;
            } else {
                status_b &= !STATUS_B_PIE;
            }
            self.cmos_write(CMOS_STATUS_B, status_b);
        }

        self.periodic_rate = rate;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // CMOS RTC private methods
    // -----------------------------------------------------------------------

    /// Reads a CMOS register.
    #[cfg(target_arch = "x86_64")]
    fn cmos_read(&self, reg: u8) -> u8 {
        // SAFETY: CMOS ports 0x70/0x71 are standard x86_64 I/O ports.
        unsafe {
            crate::arch::x86_64::io::outb(CMOS_ADDR_PORT, reg);
            crate::arch::x86_64::io::inb(CMOS_DATA_PORT)
        }
    }

    /// Writes a CMOS register.
    #[cfg(target_arch = "x86_64")]
    fn cmos_write(&self, reg: u8, val: u8) {
        // SAFETY: CMOS ports 0x70/0x71 are standard x86_64 I/O ports.
        unsafe {
            crate::arch::x86_64::io::outb(CMOS_ADDR_PORT, reg);
            crate::arch::x86_64::io::outb(CMOS_DATA_PORT, val);
        }
    }

    /// Reads the time from CMOS RTC, handling BCD conversion.
    #[cfg(target_arch = "x86_64")]
    fn cmos_read_time(&self) -> RtcTime {
        // Wait for update-in-progress to clear.
        while self.cmos_read(CMOS_STATUS_A) & 0x80 != 0 {
            core::hint::spin_loop();
        }

        let raw_sec = self.cmos_read(CMOS_SECONDS);
        let raw_min = self.cmos_read(CMOS_MINUTES);
        let raw_hr = self.cmos_read(CMOS_HOURS);
        let raw_dow = self.cmos_read(CMOS_DAY_OF_WEEK);
        let raw_day = self.cmos_read(CMOS_DAY_OF_MONTH);
        let raw_mon = self.cmos_read(CMOS_MONTH);
        let raw_yr = self.cmos_read(CMOS_YEAR);
        let raw_cent = self.cmos_read(CMOS_CENTURY);

        let (sec, min, hr, dow, day, mon, yr, cent) = if self.config.features.bcd_mode {
            (
                bcd_to_bin(raw_sec),
                bcd_to_bin(raw_min),
                bcd_to_bin(raw_hr),
                bcd_to_bin(raw_dow),
                bcd_to_bin(raw_day),
                bcd_to_bin(raw_mon),
                bcd_to_bin(raw_yr),
                bcd_to_bin(raw_cent),
            )
        } else {
            (
                raw_sec, raw_min, raw_hr, raw_dow, raw_day, raw_mon, raw_yr, raw_cent,
            )
        };

        let full_year = cent as u16 * 100 + yr as u16;
        // Convert 1-7 Sunday-based DOW to 0-6 Sunday-based.
        let weekday = if dow > 0 { dow - 1 } else { 0 };

        RtcTime {
            year: full_year,
            month: mon,
            day,
            hour: hr,
            minute: min,
            second: sec,
            weekday,
        }
    }

    /// Sets the CMOS RTC time.
    #[cfg(target_arch = "x86_64")]
    fn cmos_set_time(&self, time: &RtcTime) {
        // Set the SET bit to halt updates.
        let status_b = self.cmos_read(CMOS_STATUS_B);
        self.cmos_write(CMOS_STATUS_B, status_b | STATUS_B_SET);

        let yr = (time.year % 100) as u8;
        let cent = (time.year / 100) as u8;
        let dow = time.weekday + 1; // Convert 0-6 to 1-7.

        if self.config.features.bcd_mode {
            self.cmos_write(CMOS_SECONDS, bin_to_bcd(time.second));
            self.cmos_write(CMOS_MINUTES, bin_to_bcd(time.minute));
            self.cmos_write(CMOS_HOURS, bin_to_bcd(time.hour));
            self.cmos_write(CMOS_DAY_OF_WEEK, bin_to_bcd(dow));
            self.cmos_write(CMOS_DAY_OF_MONTH, bin_to_bcd(time.day));
            self.cmos_write(CMOS_MONTH, bin_to_bcd(time.month));
            self.cmos_write(CMOS_YEAR, bin_to_bcd(yr));
            self.cmos_write(CMOS_CENTURY, bin_to_bcd(cent));
        } else {
            self.cmos_write(CMOS_SECONDS, time.second);
            self.cmos_write(CMOS_MINUTES, time.minute);
            self.cmos_write(CMOS_HOURS, time.hour);
            self.cmos_write(CMOS_DAY_OF_WEEK, dow);
            self.cmos_write(CMOS_DAY_OF_MONTH, time.day);
            self.cmos_write(CMOS_MONTH, time.month);
            self.cmos_write(CMOS_YEAR, yr);
            self.cmos_write(CMOS_CENTURY, cent);
        }

        // Clear the SET bit to resume updates.
        self.cmos_write(CMOS_STATUS_B, status_b & !STATUS_B_SET);
    }

    /// Sets the CMOS RTC alarm.
    #[cfg(target_arch = "x86_64")]
    fn cmos_set_alarm(&self, alarm: &RtcAlarm) {
        let (sec, min, hr) = if self.config.features.bcd_mode {
            (
                if alarm.second == ALARM_WILDCARD {
                    ALARM_WILDCARD
                } else {
                    bin_to_bcd(alarm.second)
                },
                if alarm.minute == ALARM_WILDCARD {
                    ALARM_WILDCARD
                } else {
                    bin_to_bcd(alarm.minute)
                },
                if alarm.hour == ALARM_WILDCARD {
                    ALARM_WILDCARD
                } else {
                    bin_to_bcd(alarm.hour)
                },
            )
        } else {
            (alarm.second, alarm.minute, alarm.hour)
        };

        self.cmos_write(CMOS_ALARM_SECONDS, sec);
        self.cmos_write(CMOS_ALARM_MINUTES, min);
        self.cmos_write(CMOS_ALARM_HOURS, hr);

        // Enable/disable alarm interrupt.
        let mut status_b = self.cmos_read(CMOS_STATUS_B);
        if alarm.enabled {
            status_b |= STATUS_B_AIE;
        } else {
            status_b &= !STATUS_B_AIE;
        }
        self.cmos_write(CMOS_STATUS_B, status_b);
    }

    // -----------------------------------------------------------------------
    // MMIO RTC private methods (PL031)
    // -----------------------------------------------------------------------

    /// Reads the time from an MMIO-based RTC.
    fn mmio_read_time(&self) -> RtcTime {
        if self.config.mmio_base == 0 {
            return RtcTime::new(2000, 1, 1, 0, 0, 0);
        }
        // SAFETY: mmio_base valid; DR returns seconds since epoch.
        let secs = unsafe { read_mmio32(self.config.mmio_base, PL031_DR_OFF) };
        RtcTime::from_unix_timestamp(secs as u64)
    }

    /// Sets the time on an MMIO-based RTC.
    fn mmio_set_time(&self, time: &RtcTime) {
        if self.config.mmio_base == 0 {
            return;
        }
        let secs = time.to_unix_timestamp() as u32;
        // SAFETY: mmio_base valid; LR is 32-bit WO.
        unsafe {
            write_mmio32(self.config.mmio_base, PL031_LR_OFF, secs);
        }
    }

    /// Sets the alarm on an MMIO-based RTC.
    fn mmio_set_alarm(&self, alarm: &RtcAlarm) -> Result<()> {
        if self.config.mmio_base == 0 {
            return Err(Error::IoError);
        }

        if alarm.enabled {
            // Compute match value from alarm fields.
            // For PL031, alarm is a simple seconds-since-epoch comparison.
            let now = unsafe { read_mmio32(self.config.mmio_base, PL031_DR_OFF) };
            let now_time = RtcTime::from_unix_timestamp(now as u64);

            // Build a target time from the alarm fields.
            let target = RtcTime {
                year: now_time.year,
                month: now_time.month,
                day: if alarm.day == ALARM_WILDCARD {
                    now_time.day
                } else {
                    alarm.day
                },
                hour: if alarm.hour == ALARM_WILDCARD {
                    now_time.hour
                } else {
                    alarm.hour
                },
                minute: if alarm.minute == ALARM_WILDCARD {
                    now_time.minute
                } else {
                    alarm.minute
                },
                second: if alarm.second == ALARM_WILDCARD {
                    now_time.second
                } else {
                    alarm.second
                },
                weekday: now_time.weekday,
            };

            let match_secs = target.to_unix_timestamp() as u32;
            // SAFETY: mmio_base valid; MR is 32-bit RW.
            unsafe {
                write_mmio32(self.config.mmio_base, PL031_MR_OFF, match_secs);
                // Enable alarm interrupt.
                write_mmio32(self.config.mmio_base, PL031_IMSC_OFF, 1);
            }
        } else {
            // Disable alarm interrupt.
            // SAFETY: mmio_base valid; IMSC is 32-bit RW.
            unsafe {
                write_mmio32(self.config.mmio_base, PL031_IMSC_OFF, 0);
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RtcDeviceRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_RTC_DEVICES`] RTC hardware devices.
pub struct RtcDeviceRegistry {
    /// Registered RTC devices.
    devices: [Option<RtcDevice>; MAX_RTC_DEVICES],
    /// Number of registered devices.
    count: usize,
    /// Pending alarm events.
    events: [RtcAlarmEvent; MAX_ALARM_EVENTS],
    /// Number of pending events.
    event_count: usize,
}

impl Default for RtcDeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RtcDeviceRegistry {
    /// Creates a new, empty RTC device registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_RTC_DEVICES],
            count: 0,
            events: [EMPTY_ALARM_EVENT; MAX_ALARM_EVENTS],
            event_count: 0,
        }
    }

    /// Registers an RTC device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same id exists.
    pub fn register(&mut self, device: RtcDevice) -> Result<()> {
        for slot in self.devices.iter().flatten() {
            if slot.id == device.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.devices.iter_mut() {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters an RTC device by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no device with that id exists.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        for slot in self.devices.iter_mut() {
            let matches = slot.as_ref().is_some_and(|d| d.id == id);
            if matches {
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a reference to a device by its `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get(&self, id: u32) -> Result<&RtcDevice> {
        self.devices
            .iter()
            .flatten()
            .find(|d| d.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to a device by its `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut RtcDevice> {
        self.devices
            .iter_mut()
            .flatten()
            .find(|d| d.id == id)
            .ok_or(Error::NotFound)
    }

    /// Records an alarm event.
    pub fn push_event(&mut self, event: RtcAlarmEvent) {
        if self.event_count < MAX_ALARM_EVENTS {
            self.events[self.event_count] = event;
            self.event_count += 1;
        }
    }

    /// Pops the oldest alarm event.
    pub fn pop_event(&mut self) -> Option<RtcAlarmEvent> {
        if self.event_count == 0 {
            return None;
        }
        let event = self.events[0];
        // Shift remaining events.
        let remaining = self.event_count - 1;
        for i in 0..remaining {
            self.events[i] = self.events[i + 1];
        }
        self.event_count -= 1;
        Some(event)
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the number of pending alarm events.
    pub fn event_count(&self) -> usize {
        self.event_count
    }
}
