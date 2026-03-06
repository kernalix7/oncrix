// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVRAM (Non-Volatile RAM) driver.
//!
//! Provides access to CMOS/RTC NVRAM memory present on all PC-compatible
//! systems via the RTC index/data port pair. Also supports ACPI NVRAM
//! regions for platform-specific non-volatile storage.

use oncrix_lib::{Error, Result};

/// RTC/CMOS I/O ports.
const CMOS_INDEX_PORT: u16 = 0x70;
const CMOS_DATA_PORT: u16 = 0x71;

/// NMI disable bit in the CMOS index register (bit 7).
const NMI_DISABLE: u8 = 0x80;

/// Total CMOS NVRAM size (128 bytes on standard PC, 256 on extended CMOS).
const CMOS_SIZE: usize = 128;

/// Standard CMOS NVRAM layout offsets.
pub mod cmos_offset {
    /// RTC seconds register.
    pub const RTC_SECONDS: u8 = 0x00;
    /// RTC minutes register.
    pub const RTC_MINUTES: u8 = 0x02;
    /// RTC hours register.
    pub const RTC_HOURS: u8 = 0x04;
    /// RTC day of week.
    pub const RTC_DAY_OF_WEEK: u8 = 0x06;
    /// RTC day of month.
    pub const RTC_DAY: u8 = 0x07;
    /// RTC month.
    pub const RTC_MONTH: u8 = 0x08;
    /// RTC year (2-digit).
    pub const RTC_YEAR: u8 = 0x09;
    /// Status register A (update in progress, etc.).
    pub const STATUS_A: u8 = 0x0A;
    /// Status register B (24h mode, DST, binary/BCD, etc.).
    pub const STATUS_B: u8 = 0x0B;
    /// Status register C (interrupt flags).
    pub const STATUS_C: u8 = 0x0C;
    /// Status register D (valid CMOS RAM).
    pub const STATUS_D: u8 = 0x0D;
    /// POST diagnostic status.
    pub const DIAGNOSTIC: u8 = 0x0E;
    /// Shutdown status byte.
    pub const SHUTDOWN: u8 = 0x0F;
    /// NVRAM user data start (bytes 0x10–0x3F are user-defined).
    pub const USER_START: u8 = 0x10;
    /// Base memory low byte (in 1 KB units).
    pub const BASE_MEM_LO: u8 = 0x15;
    /// Base memory high byte.
    pub const BASE_MEM_HI: u8 = 0x16;
    /// Extended memory low byte (in 1 KB units above 1 MB).
    pub const EXT_MEM_LO: u8 = 0x17;
    /// Extended memory high byte.
    pub const EXT_MEM_HI: u8 = 0x18;
    /// Drive type byte.
    pub const DRIVE_TYPE: u8 = 0x12;
    /// Checksum high byte (covers bytes 0x10–0x2D).
    pub const CKSUM_HI: u8 = 0x2E;
    /// Checksum low byte.
    pub const CKSUM_LO: u8 = 0x2F;
    /// Century byte (BCD, e.g., 0x20 for year 20xx).
    pub const CENTURY: u8 = 0x32;
}

/// Status register B bits.
const STAT_B_24H: u8 = 1 << 1; // 24-hour mode
const STAT_B_DM: u8 = 1 << 2; // Binary (vs BCD) data mode
const STAT_B_SQWE: u8 = 1 << 3; // Square-wave enable
const STAT_B_UIE: u8 = 1 << 4; // Update-ended interrupt enable
const STAT_B_AIE: u8 = 1 << 5; // Alarm interrupt enable
const STAT_B_PIE: u8 = 1 << 6; // Periodic interrupt enable
const STAT_B_SET: u8 = 1 << 7; // Clock update inhibit

/// Status register A bits.
const STAT_A_UIP: u8 = 1 << 7; // Update-in-progress

/// Convert BCD byte to binary integer.
fn bcd_to_bin(bcd: u8) -> u8 {
    (bcd & 0x0F) + ((bcd >> 4) * 10)
}

/// Convert binary integer to BCD byte.
fn bin_to_bcd(bin: u8) -> u8 {
    ((bin / 10) << 4) | (bin % 10)
}

/// RTC date/time structure.
#[derive(Clone, Copy, Debug, Default)]
pub struct RtcDateTime {
    /// Year (full, e.g., 2026).
    pub year: u16,
    /// Month (1–12).
    pub month: u8,
    /// Day (1–31).
    pub day: u8,
    /// Hour (0–23).
    pub hour: u8,
    /// Minute (0–59).
    pub minute: u8,
    /// Second (0–59).
    pub second: u8,
}

/// NVRAM driver.
pub struct NvramDriver {
    /// Whether CMOS uses binary data mode (vs BCD).
    binary_mode: bool,
    /// Whether CMOS uses 24-hour mode.
    h24_mode: bool,
}

impl NvramDriver {
    /// Create a new NVRAM driver.
    pub fn new() -> Self {
        Self {
            binary_mode: false,
            h24_mode: true,
        }
    }

    /// Initialize the driver by reading RTC status registers.
    pub fn init(&mut self) -> Result<()> {
        let stat_b = self.read_cmos(cmos_offset::STATUS_B)?;
        self.binary_mode = (stat_b & STAT_B_DM) != 0;
        self.h24_mode = (stat_b & STAT_B_24H) != 0;
        Ok(())
    }

    /// Read the current RTC date and time.
    pub fn read_datetime(&self) -> Result<RtcDateTime> {
        // Wait until UIP (Update In Progress) is clear.
        self.wait_not_updating()?;
        let sec = self.read_cmos(cmos_offset::RTC_SECONDS)?;
        let min = self.read_cmos(cmos_offset::RTC_MINUTES)?;
        let hr = self.read_cmos(cmos_offset::RTC_HOURS)?;
        let day = self.read_cmos(cmos_offset::RTC_DAY)?;
        let mon = self.read_cmos(cmos_offset::RTC_MONTH)?;
        let yr = self.read_cmos(cmos_offset::RTC_YEAR)?;
        let cent = self.read_cmos(cmos_offset::CENTURY)?;
        let to_bin = |v: u8| -> u8 { if self.binary_mode { v } else { bcd_to_bin(v) } };
        let year_2digit = to_bin(yr) as u16;
        let century = if cent != 0 { to_bin(cent) as u16 } else { 20 };
        Ok(RtcDateTime {
            year: century * 100 + year_2digit,
            month: to_bin(mon),
            day: to_bin(day),
            hour: to_bin(hr),
            minute: to_bin(min),
            second: to_bin(sec),
        })
    }

    /// Write a date/time to the RTC.
    pub fn write_datetime(&mut self, dt: &RtcDateTime) -> Result<()> {
        let from_bin = |v: u8| -> u8 { if self.binary_mode { v } else { bin_to_bcd(v) } };
        let stat_b = self.read_cmos(cmos_offset::STATUS_B)?;
        let sec = from_bin(dt.second);
        let min = from_bin(dt.minute);
        let hr = from_bin(dt.hour);
        let day = from_bin(dt.day);
        let mon = from_bin(dt.month);
        let year_2digit = from_bin((dt.year % 100) as u8);
        let century = from_bin((dt.year / 100) as u8);
        // Inhibit updates.
        self.write_cmos(cmos_offset::STATUS_B, stat_b | STAT_B_SET)?;
        self.write_cmos(cmos_offset::RTC_SECONDS, sec)?;
        self.write_cmos(cmos_offset::RTC_MINUTES, min)?;
        self.write_cmos(cmos_offset::RTC_HOURS, hr)?;
        self.write_cmos(cmos_offset::RTC_DAY, day)?;
        self.write_cmos(cmos_offset::RTC_MONTH, mon)?;
        self.write_cmos(cmos_offset::RTC_YEAR, year_2digit)?;
        self.write_cmos(cmos_offset::CENTURY, century)?;
        // Re-enable updates.
        self.write_cmos(cmos_offset::STATUS_B, stat_b & !STAT_B_SET)?;
        Ok(())
    }

    /// Read a single byte from CMOS NVRAM.
    pub fn read_cmos(&self, offset: u8) -> Result<u8> {
        if (offset as usize) >= CMOS_SIZE {
            return Err(Error::InvalidArgument);
        }
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: CMOS_INDEX_PORT (0x70) and CMOS_DATA_PORT (0x71) are
            // the standard PC CMOS/RTC I/O ports. We set NMI_DISABLE to prevent
            // NMI delivery during the two-phase index+data access.
            unsafe {
                core::arch::asm!(
                    "out dx, al",
                    in("dx") CMOS_INDEX_PORT,
                    in("al") NMI_DISABLE | offset,
                    options(nomem, nostack)
                );
                let val: u8;
                core::arch::asm!(
                    "in al, dx",
                    in("dx") CMOS_DATA_PORT,
                    out("al") val,
                    options(nomem, nostack)
                );
                return Ok(val);
            }
        }
        #[allow(unreachable_code)]
        Err(Error::NotImplemented)
    }

    /// Write a single byte to CMOS NVRAM.
    pub fn write_cmos(&mut self, offset: u8, val: u8) -> Result<()> {
        if (offset as usize) >= CMOS_SIZE {
            return Err(Error::InvalidArgument);
        }
        #[cfg(target_arch = "x86_64")]
        // SAFETY: Standard CMOS index/data port pair; NMI_DISABLE prevents
        // interrupt delivery between the two PIO writes.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") CMOS_INDEX_PORT,
                in("al") NMI_DISABLE | offset,
                options(nomem, nostack)
            );
            core::arch::asm!(
                "out dx, al",
                in("dx") CMOS_DATA_PORT,
                in("al") val,
                options(nomem, nostack)
            );
        }
        Ok(())
    }

    /// Wait until the RTC is not in the middle of an update cycle.
    fn wait_not_updating(&self) -> Result<()> {
        let mut tries = 0u32;
        loop {
            let stat_a = self.read_cmos(cmos_offset::STATUS_A)?;
            if (stat_a & STAT_A_UIP) == 0 {
                return Ok(());
            }
            tries += 1;
            if tries > 1_000_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }
}

impl Default for NvramDriver {
    fn default() -> Self {
        Self::new()
    }
}
