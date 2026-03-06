// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CMOS Real-Time Clock (RTC) hardware access module.
//!
//! Provides low-level access to the MC146818A-compatible CMOS RTC chip
//! found in x86 PCs via I/O ports 0x70 (index) and 0x71 (data).
//!
//! # Features
//!
//! - Read/write arbitrary CMOS registers
//! - Read the full RTC date/time (with BCD-to-binary conversion)
//! - Wait for RTC update-in-progress to settle before reading
//! - Write date/time back to the RTC
//! - Access CMOS extended RAM (bytes 0x0E–0x7F)
//!
//! # Safety
//!
//! All port I/O is wrapped in `unsafe` with appropriate `// SAFETY:` comments.
//! NMI is momentarily gated during index writes as required by the hardware spec.
//!
//! Reference: MC146818A Datasheet; IBM PC-AT Technical Reference.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// I/O Ports
// ---------------------------------------------------------------------------

/// CMOS address/index port.  Bit 7 = NMI disable while writing.
const CMOS_ADDR: u16 = 0x70;
/// CMOS data port.
const CMOS_DATA: u16 = 0x71;

/// Mask applied to address byte to suppress NMI.
const NMI_DISABLE_BIT: u8 = 0x80;

// ---------------------------------------------------------------------------
// CMOS Register Map (MC146818A)
// ---------------------------------------------------------------------------

/// RTC seconds register (0–59, BCD or binary).
pub const RTC_REG_SEC: u8 = 0x00;
/// RTC seconds alarm.
pub const RTC_REG_SEC_ALARM: u8 = 0x01;
/// RTC minutes (0–59).
pub const RTC_REG_MIN: u8 = 0x02;
/// RTC minutes alarm.
pub const RTC_REG_MIN_ALARM: u8 = 0x03;
/// RTC hours (0–23 binary, or 1–12 BCD + AM/PM).
pub const RTC_REG_HOUR: u8 = 0x04;
/// RTC hours alarm.
pub const RTC_REG_HOUR_ALARM: u8 = 0x05;
/// Day of week (1–7; 1 = Sunday).
pub const RTC_REG_WDAY: u8 = 0x06;
/// Day of month (1–31).
pub const RTC_REG_MDAY: u8 = 0x07;
/// Month (1–12).
pub const RTC_REG_MONTH: u8 = 0x08;
/// Year within century (0–99).
pub const RTC_REG_YEAR: u8 = 0x09;
/// Status register A.
pub const RTC_REG_STATUS_A: u8 = 0x0A;
/// Status register B.
pub const RTC_REG_STATUS_B: u8 = 0x0B;
/// Status register C (read-only, cleared on read).
pub const RTC_REG_STATUS_C: u8 = 0x0C;
/// Status register D (battery status, read-only).
pub const RTC_REG_STATUS_D: u8 = 0x0D;
/// POST diagnostic status byte.
pub const CMOS_REG_DIAG: u8 = 0x0E;
/// Shutdown status byte.
pub const CMOS_REG_SHUTDOWN: u8 = 0x0F;
/// Century byte (BCD; not present on all chipsets).
pub const RTC_REG_CENTURY: u8 = 0x32;

// ---------------------------------------------------------------------------
// Status Register A Bits
// ---------------------------------------------------------------------------

/// Status A bit 7: Update-in-Progress (UIP). When set, RTC is updating.
pub const STATUS_A_UIP: u8 = 0x80;

/// Status A bits 6:4: divider select (010 = 32.768 kHz crystal).
pub const STATUS_A_DV_32KHZ: u8 = 0x20;

// ---------------------------------------------------------------------------
// Status Register B Bits
// ---------------------------------------------------------------------------

/// Status B bit 7: Set — when set, updates are halted.
pub const STATUS_B_SET: u8 = 0x80;
/// Status B bit 6: Periodic interrupt enable.
pub const STATUS_B_PIE: u8 = 0x40;
/// Status B bit 5: Alarm interrupt enable.
pub const STATUS_B_AIE: u8 = 0x20;
/// Status B bit 4: Update-ended interrupt enable.
pub const STATUS_B_UIE: u8 = 0x10;
/// Status B bit 3: Square-wave output enable.
pub const STATUS_B_SQWE: u8 = 0x08;
/// Status B bit 2: Data mode — 1 = binary, 0 = BCD.
pub const STATUS_B_DM: u8 = 0x04;
/// Status B bit 1: 24-hour mode (1) vs 12-hour mode (0).
pub const STATUS_B_24H: u8 = 0x02;
/// Status B bit 0: Daylight Saving Time enable.
pub const STATUS_B_DST: u8 = 0x01;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Maximum spin iterations when waiting for UIP to clear.
const UIP_WAIT_ITERS: u32 = 100_000;

/// Read one byte from the given CMOS register.
///
/// # Safety
///
/// Caller must ensure no concurrent CMOS accesses (hardware requires
/// the index and data ports to be used atomically).
#[cfg(target_arch = "x86_64")]
unsafe fn cmos_read_raw(reg: u8) -> u8 {
    // SAFETY: Port 0x70/0x71 are CMOS index/data ports.  We write the
    // register address (with NMI gate) to 0x70, then read data from 0x71.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") CMOS_ADDR,
            in("al") reg | NMI_DISABLE_BIT,
            options(nomem, nostack, preserves_flags),
        );
        let val: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") val,
            in("dx") CMOS_DATA,
            options(nomem, nostack, preserves_flags),
        );
        val
    }
}

/// Write one byte to the given CMOS register.
///
/// # Safety
///
/// Same as [`cmos_read_raw`].
#[cfg(target_arch = "x86_64")]
unsafe fn cmos_write_raw(reg: u8, val: u8) {
    // SAFETY: Writing index then data to CMOS ports 0x70/0x71.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") CMOS_ADDR,
            in("al") reg | NMI_DISABLE_BIT,
            options(nomem, nostack, preserves_flags),
        );
        core::arch::asm!(
            "out dx, al",
            in("dx") CMOS_DATA,
            in("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Restore NMI enable after a sequence of CMOS accesses.
///
/// Writing 0x00 to port 0x70 clears the NMI-disable bit and selects
/// register 0 (safe to leave selected).
#[cfg(target_arch = "x86_64")]
pub fn cmos_nmi_enable() {
    // SAFETY: Writing 0x00 to port 0x70 re-enables NMI.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") CMOS_ADDR,
            in("al") 0u8,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// CmosRtc
// ---------------------------------------------------------------------------

/// MC146818A-compatible CMOS RTC controller.
pub struct CmosRtc {
    /// Whether the RTC is configured for 24-hour mode.
    hour_24: bool,
    /// Whether the RTC stores values in binary (true) or BCD (false).
    binary_mode: bool,
}

impl CmosRtc {
    /// Create a new [`CmosRtc`] handle.
    ///
    /// Does not touch hardware; call [`init`](CmosRtc::init) to probe
    /// status registers.
    pub const fn new() -> Self {
        Self {
            hour_24: true,
            binary_mode: false,
        }
    }

    /// Probe the RTC status registers and record the data format.
    #[cfg(target_arch = "x86_64")]
    pub fn init(&mut self) -> Result<()> {
        // SAFETY: CMOS status register read is always safe on x86.
        let status_b = unsafe { cmos_read_raw(RTC_REG_STATUS_B) };
        cmos_nmi_enable();

        self.hour_24 = (status_b & STATUS_B_24H) != 0;
        self.binary_mode = (status_b & STATUS_B_DM) != 0;
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn init(&mut self) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Read a raw CMOS byte from `reg`.
    #[cfg(target_arch = "x86_64")]
    pub fn read_reg(&self, reg: u8) -> u8 {
        // SAFETY: Standard CMOS read sequence.
        let val = unsafe { cmos_read_raw(reg) };
        cmos_nmi_enable();
        val
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn read_reg(&self, _reg: u8) -> u8 {
        0
    }

    /// Write a raw byte `val` to CMOS `reg`.
    #[cfg(target_arch = "x86_64")]
    pub fn write_reg(&self, reg: u8, val: u8) {
        // SAFETY: Standard CMOS write sequence.
        unsafe { cmos_write_raw(reg, val) };
        cmos_nmi_enable();
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn write_reg(&self, _reg: u8, _val: u8) {}

    /// Wait until the RTC is not updating (UIP bit clear).
    ///
    /// Returns `Err(Error::Busy)` if the RTC does not become ready within
    /// the spin limit.
    #[cfg(target_arch = "x86_64")]
    pub fn wait_not_updating(&self) -> Result<()> {
        for _ in 0..UIP_WAIT_ITERS {
            let a = self.read_reg(RTC_REG_STATUS_A);
            if (a & STATUS_A_UIP) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn wait_not_updating(&self) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Read the current date/time from the RTC.
    ///
    /// Waits for the update-in-progress flag to clear, then reads all
    /// time/date registers atomically (best-effort; hardware does not
    /// provide a true atomic snapshot).
    pub fn read_datetime(&self) -> Result<RtcDateTime> {
        self.wait_not_updating()?;

        let sec = self.read_reg(RTC_REG_SEC);
        let min = self.read_reg(RTC_REG_MIN);
        let hour = self.read_reg(RTC_REG_HOUR);
        let mday = self.read_reg(RTC_REG_MDAY);
        let month = self.read_reg(RTC_REG_MONTH);
        let year = self.read_reg(RTC_REG_YEAR);
        let century = self.read_reg(RTC_REG_CENTURY);

        // Convert BCD → binary if needed
        let to_bin = |v: u8| -> u8 {
            if self.binary_mode {
                v
            } else {
                (v >> 4) * 10 + (v & 0x0F)
            }
        };

        let mut hour_bin = to_bin(hour & 0x7F);
        if !self.hour_24 && (hour & 0x80) != 0 {
            // 12-hour PM: add 12 (except 12 PM stays 12)
            if hour_bin != 12 {
                hour_bin += 12;
            }
        }

        let century_bin = if century != 0 { to_bin(century) } else { 20 };
        let full_year = century_bin as u16 * 100 + to_bin(year) as u16;

        Ok(RtcDateTime {
            second: to_bin(sec),
            minute: to_bin(min),
            hour: hour_bin,
            day: to_bin(mday),
            month: to_bin(month),
            year: full_year,
        })
    }

    /// Set the RTC date/time.
    ///
    /// Halts updates (STATUS_B_SET) during the write, then re-enables.
    pub fn write_datetime(&self, dt: &RtcDateTime) -> Result<()> {
        let to_bcd = |v: u8| -> u8 {
            if self.binary_mode {
                v
            } else {
                ((v / 10) << 4) | (v % 10)
            }
        };

        // Halt updates
        let status_b = self.read_reg(RTC_REG_STATUS_B);
        self.write_reg(RTC_REG_STATUS_B, status_b | STATUS_B_SET);

        let century = (dt.year / 100) as u8;
        let year_lo = (dt.year % 100) as u8;

        self.write_reg(RTC_REG_SEC, to_bcd(dt.second));
        self.write_reg(RTC_REG_MIN, to_bcd(dt.minute));
        self.write_reg(RTC_REG_HOUR, to_bcd(dt.hour));
        self.write_reg(RTC_REG_MDAY, to_bcd(dt.day));
        self.write_reg(RTC_REG_MONTH, to_bcd(dt.month));
        self.write_reg(RTC_REG_YEAR, to_bcd(year_lo));
        self.write_reg(RTC_REG_CENTURY, to_bcd(century));

        // Re-enable updates
        self.write_reg(RTC_REG_STATUS_B, status_b & !STATUS_B_SET);
        Ok(())
    }

    /// Enable or disable the periodic interrupt.
    pub fn set_periodic_irq(&self, enable: bool) {
        let status_b = self.read_reg(RTC_REG_STATUS_B);
        let new = if enable {
            status_b | STATUS_B_PIE
        } else {
            status_b & !STATUS_B_PIE
        };
        self.write_reg(RTC_REG_STATUS_B, new);
    }

    /// Acknowledge a pending RTC interrupt by reading status register C.
    pub fn ack_irq(&self) -> u8 {
        self.read_reg(RTC_REG_STATUS_C)
    }

    /// Check that the RTC battery is good (STATUS_D bit 7).
    pub fn battery_ok(&self) -> bool {
        (self.read_reg(RTC_REG_STATUS_D) & 0x80) != 0
    }
}

// ---------------------------------------------------------------------------
// RtcDateTime
// ---------------------------------------------------------------------------

/// Date and time snapshot read from or written to the RTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtcDateTime {
    /// Seconds (0–59).
    pub second: u8,
    /// Minutes (0–59).
    pub minute: u8,
    /// Hours (0–23, 24-hour format).
    pub hour: u8,
    /// Day of month (1–31).
    pub day: u8,
    /// Month (1–12).
    pub month: u8,
    /// Full four-digit year (e.g., 2026).
    pub year: u16,
}

impl RtcDateTime {
    /// Return true if all fields are within valid calendar ranges.
    pub fn is_valid(&self) -> bool {
        self.second < 60
            && self.minute < 60
            && self.hour < 24
            && self.day >= 1
            && self.day <= 31
            && self.month >= 1
            && self.month <= 12
            && self.year >= 1970
    }
}
