// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CMOS RAM and RTC (Real-Time Clock) driver.
//!
//! The PC-AT CMOS is a 128-byte battery-backed RAM accessed via two I/O ports:
//! - **0x70**: Index register (NMI disable flag in bit 7 + register address in bits 6:0).
//! - **0x71**: Data register.
//!
//! The first 14 bytes hold the RTC time and date in either BCD or binary format.
//! Status registers A–D control RTC oscillator, update cycle, and alarm state.
//!
//! Reference: MC146818A RTC Datasheet; IBM PC-AT Technical Reference.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// CMOS I/O Ports
// ---------------------------------------------------------------------------

/// CMOS address/index port (bit 7 = NMI disable).
const CMOS_ADDR_PORT: u16 = 0x70;
/// CMOS data port.
const CMOS_DATA_PORT: u16 = 0x71;

/// Bit 7 of the address byte: disables Non-Maskable Interrupts while set.
const NMI_DISABLE: u8 = 0x80;

// ---------------------------------------------------------------------------
// CMOS Register Addresses
// ---------------------------------------------------------------------------

/// RTC seconds (0–59).
pub const REG_SECONDS: u8 = 0x00;
/// RTC seconds alarm.
pub const REG_SECONDS_ALARM: u8 = 0x01;
/// RTC minutes (0–59).
pub const REG_MINUTES: u8 = 0x02;
/// RTC minutes alarm.
pub const REG_MINUTES_ALARM: u8 = 0x03;
/// RTC hours (0–23 or 1–12 with AM/PM).
pub const REG_HOURS: u8 = 0x04;
/// RTC hours alarm.
pub const REG_HOURS_ALARM: u8 = 0x05;
/// RTC day of week (1–7; 1 = Sunday).
pub const REG_DAY_OF_WEEK: u8 = 0x06;
/// RTC day of month (1–31).
pub const REG_DAY: u8 = 0x07;
/// RTC month (1–12).
pub const REG_MONTH: u8 = 0x08;
/// RTC year within century (0–99).
pub const REG_YEAR: u8 = 0x09;
/// Status Register A: UIP flag, oscillator control, rate select.
pub const REG_STATUS_A: u8 = 0x0A;
/// Status Register B: binary/BCD mode, 12/24 hour, alarm enable, etc.
pub const REG_STATUS_B: u8 = 0x0B;
/// Status Register C: interrupt flags (read-only, cleared on read).
pub const REG_STATUS_C: u8 = 0x0C;
/// Status Register D: Valid RAM bit (read-only; 0 = battery dead).
pub const REG_STATUS_D: u8 = 0x0D;
/// RTC century register (on systems that have it, often 0x32 in FADT).
pub const REG_CENTURY: u8 = 0x32;
/// POST diagnostic status byte.
pub const REG_DIAGNOSTIC: u8 = 0x0E;
/// Shutdown status byte.
pub const REG_SHUTDOWN: u8 = 0x0F;

// ---------------------------------------------------------------------------
// Status Register Bit Flags
// ---------------------------------------------------------------------------

/// Status A bit 7: Update In Progress. Set during a one-second tick.
pub const STA_UIP: u8 = 1 << 7;

/// Status B bit 2: 24-hour mode (1) or 12-hour mode (0).
pub const STB_24HR: u8 = 1 << 1;
/// Status B bit 2 (alternate): DMLE bit (daylight saving).
pub const _STB_DMLE: u8 = 1 << 0;
/// Status B bit 3: Enables square wave output.
pub const _STB_SQWE: u8 = 1 << 3;
/// Status B bit 4: Update Ended Interrupt Enable.
pub const STB_UIE: u8 = 1 << 4;
/// Status B bit 5: Alarm Interrupt Enable.
pub const STB_AIE: u8 = 1 << 5;
/// Status B bit 6: Periodic Interrupt Enable.
pub const _STB_PIE: u8 = 1 << 6;
/// Status B bit 7: RTC halted (set to disable oscillator).
pub const _STB_SET: u8 = 1 << 7;
/// Status B bit 2 (data mode): 1 = binary (no BCD), 0 = BCD.
pub const STB_BINARY: u8 = 1 << 2;

/// Status C bit 4: Update-ended interrupt flag.
pub const STC_UF: u8 = 1 << 4;
/// Status C bit 5: Alarm interrupt flag.
pub const STC_AF: u8 = 1 << 5;
/// Status C bit 6: Periodic interrupt flag.
pub const _STC_PF: u8 = 1 << 6;
/// Status C bit 7: IRQ Flag (any pending interrupt).
pub const _STC_IRQF: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// Port I/O
// ---------------------------------------------------------------------------

/// Writes `val` to I/O port `port`.
///
/// # Safety
/// Port I/O; caller must ensure `port` is valid.
#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Port I/O instruction; caller guarantees port correctness.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
    }
}

/// Reads a byte from I/O port `port`.
///
/// # Safety
/// See `outb`.
#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Port I/O read; caller guarantees port correctness.
    unsafe {
        core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack));
    }
    val
}

// ---------------------------------------------------------------------------
// CMOS Access
// ---------------------------------------------------------------------------

/// Reads a CMOS register at `addr`, temporarily disabling NMI.
///
/// # Safety
/// Must be called from ring 0. NMI is briefly masked; do not call from NMI
/// handlers. The CMOS address latch is global state — no concurrent access.
#[cfg(target_arch = "x86_64")]
pub unsafe fn cmos_read(addr: u8) -> u8 {
    // SAFETY: NMI disable + CMOS address write + data read per MC146818A spec.
    unsafe {
        outb(CMOS_ADDR_PORT, NMI_DISABLE | (addr & 0x7F));
        let val = inb(CMOS_DATA_PORT);
        // Re-enable NMI by writing 0 to the address port (safe reset)
        outb(CMOS_ADDR_PORT, 0x00);
        val
    }
}

/// Writes `val` to CMOS register at `addr`, temporarily disabling NMI.
///
/// # Safety
/// Same restrictions as `cmos_read`. Overwriting reserved registers or
/// RTC control registers with wrong values may corrupt the RTC.
#[cfg(target_arch = "x86_64")]
pub unsafe fn cmos_write(addr: u8, val: u8) {
    // SAFETY: NMI disable + CMOS address write + data write per spec.
    unsafe {
        outb(CMOS_ADDR_PORT, NMI_DISABLE | (addr & 0x7F));
        outb(CMOS_DATA_PORT, val);
        outb(CMOS_ADDR_PORT, 0x00);
    }
}

// ---------------------------------------------------------------------------
// BCD Conversion
// ---------------------------------------------------------------------------

/// Converts a BCD-encoded byte to binary.
pub const fn bcd_to_bin(bcd: u8) -> u8 {
    (bcd >> 4) * 10 + (bcd & 0x0F)
}

/// Converts a binary value (0–99) to BCD.
pub const fn bin_to_bcd(bin: u8) -> u8 {
    ((bin / 10) << 4) | (bin % 10)
}

// ---------------------------------------------------------------------------
// RTC Time Structure
// ---------------------------------------------------------------------------

/// Calendar time read from the RTC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CmosTime {
    /// Seconds (0–59).
    pub sec: u8,
    /// Minutes (0–59).
    pub min: u8,
    /// Hours (0–23 in 24-hr mode).
    pub hour: u8,
    /// Day of month (1–31).
    pub day: u8,
    /// Month (1–12).
    pub month: u8,
    /// Year within century (0–99).
    pub year: u8,
    /// Century (e.g., 20 for years 2000–2099). May be 0 if not available.
    pub century: u8,
}

impl CmosTime {
    /// Returns the full 4-digit year, combining `century` and `year`.
    pub fn full_year(&self) -> u32 {
        if self.century == 0 {
            // Assume 2000s if no century register
            2000 + (self.year as u32)
        } else {
            (self.century as u32) * 100 + (self.year as u32)
        }
    }
}

// ---------------------------------------------------------------------------
// RTC Read
// ---------------------------------------------------------------------------

/// Reads the current RTC time from the CMOS.
///
/// Waits for the Update-In-Progress (UIP) flag to clear before sampling,
/// then reads twice and retries if the values differ, ensuring a consistent
/// snapshot across a second boundary.
///
/// # Safety
/// Must be called from ring 0; NMI is briefly disabled during register reads.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_rtc_time() -> Result<CmosTime> {
    // SAFETY: CMOS read sequence with UIP polling.
    unsafe {
        // Wait for UIP to clear (max ~1.5 ms after update)
        let mut spin = 100_000u32;
        while cmos_read(REG_STATUS_A) & STA_UIP != 0 {
            if spin == 0 {
                return Err(Error::Busy);
            }
            spin -= 1;
            core::hint::spin_loop();
        }

        // Read once
        let mut a = read_rtc_raw();
        // Read again and retry if they differ (crossed a second boundary)
        let mut retries = 3u8;
        loop {
            let b = read_rtc_raw();
            if a == b {
                break;
            }
            a = b;
            if retries == 0 {
                return Err(Error::Busy);
            }
            retries -= 1;
        }

        // Check status B for format flags
        let status_b = cmos_read(REG_STATUS_B);
        let binary = status_b & STB_BINARY != 0;

        let convert = |v: u8| if binary { v } else { bcd_to_bin(v) };

        Ok(CmosTime {
            sec: convert(a.sec),
            min: convert(a.min),
            hour: convert(a.hour & 0x7F), // mask PM bit
            day: convert(a.day),
            month: convert(a.month),
            year: convert(a.year),
            century: if a.century != 0 {
                convert(a.century)
            } else {
                0
            },
        })
    }
}

/// Internal raw read without conversion.
///
/// # Safety
/// See `read_rtc_time`.
#[cfg(target_arch = "x86_64")]
unsafe fn read_rtc_raw() -> CmosTime {
    // SAFETY: Reading CMOS registers in sequence.
    unsafe {
        CmosTime {
            sec: cmos_read(REG_SECONDS),
            min: cmos_read(REG_MINUTES),
            hour: cmos_read(REG_HOURS),
            day: cmos_read(REG_DAY),
            month: cmos_read(REG_MONTH),
            year: cmos_read(REG_YEAR),
            century: cmos_read(REG_CENTURY),
        }
    }
}

// ---------------------------------------------------------------------------
// RTC Alarm
// ---------------------------------------------------------------------------

/// Sets an RTC alarm at the given (sec, min, hour) values.
///
/// The alarm fires when the current time matches all three fields.
/// Use 0xFF in any field to act as a "don't care" wildcard.
///
/// # Safety
/// Must be called from ring 0. Writes to CMOS alarm registers.
#[cfg(target_arch = "x86_64")]
pub unsafe fn set_rtc_alarm(sec: u8, min: u8, hour: u8) {
    // SAFETY: Writing alarm registers to program an RTC alarm.
    unsafe {
        cmos_write(REG_SECONDS_ALARM, sec);
        cmos_write(REG_MINUTES_ALARM, min);
        cmos_write(REG_HOURS_ALARM, hour);
        // Enable alarm interrupt in status B
        let status_b = cmos_read(REG_STATUS_B);
        cmos_write(REG_STATUS_B, status_b | STB_AIE);
    }
}

/// Clears the RTC alarm and disables alarm interrupts.
///
/// # Safety
/// See `set_rtc_alarm`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn clear_rtc_alarm() {
    // SAFETY: Clearing alarm enable bit in status B.
    unsafe {
        let status_b = cmos_read(REG_STATUS_B);
        cmos_write(REG_STATUS_B, status_b & !STB_AIE);
    }
}

/// Reads and clears RTC interrupt flags (Status Register C).
///
/// Must be called at the end of every RTC interrupt handler to re-arm.
///
/// # Safety
/// Must be called from ring 0; typically inside an IRQ 8 handler.
#[cfg(target_arch = "x86_64")]
pub unsafe fn ack_rtc_interrupt() -> u8 {
    // SAFETY: Reading status C clears all interrupt flags.
    unsafe { cmos_read(REG_STATUS_C) }
}

// ---------------------------------------------------------------------------
// CMOS Checksum
// ---------------------------------------------------------------------------

/// CMOS checksum area: registers 0x10–0x2D.
const CSUM_START: u8 = 0x10;
/// Checksum end register.
const CSUM_END: u8 = 0x2D;
/// Checksum high byte register.
const CSUM_HIGH: u8 = 0x2E;
/// Checksum low byte register.
const CSUM_LOW: u8 = 0x2F;

/// Computes and stores the CMOS checksum over registers 0x10–0x2D.
///
/// # Safety
/// Must be called from ring 0 after modifying CMOS configuration bytes.
#[cfg(target_arch = "x86_64")]
pub unsafe fn update_cmos_checksum() {
    // SAFETY: Reading checksum range and writing sum registers.
    unsafe {
        let mut sum: u16 = 0;
        let mut reg = CSUM_START;
        while reg <= CSUM_END {
            sum = sum.wrapping_add(cmos_read(reg) as u16);
            reg += 1;
        }
        cmos_write(CSUM_HIGH, (sum >> 8) as u8);
        cmos_write(CSUM_LOW, (sum & 0xFF) as u8);
    }
}

/// Verifies the CMOS checksum.
///
/// Returns `Ok(())` if the checksum matches, or `Err(Error::IoError)` if it
/// does not (indicating a dead CMOS battery or corrupt configuration).
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn verify_cmos_checksum() -> Result<()> {
    // SAFETY: Reading checksum range and comparing with stored value.
    unsafe {
        let mut sum: u16 = 0;
        let mut reg = CSUM_START;
        while reg <= CSUM_END {
            sum = sum.wrapping_add(cmos_read(reg) as u16);
            reg += 1;
        }
        let stored = ((cmos_read(CSUM_HIGH) as u16) << 8) | (cmos_read(CSUM_LOW) as u16);
        if sum == stored {
            Ok(())
        } else {
            Err(Error::IoError)
        }
    }
}
