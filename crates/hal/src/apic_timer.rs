// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Local APIC timer programming.
//!
//! The local APIC contains a programmable timer that generates interrupts
//! by counting down from an initial count. This module provides:
//!
//! - `ApicTimerMode`: One-shot, periodic, and TSC-deadline modes.
//! - Calibration via the PIT (Programmable Interval Timer).
//! - LVT timer register programming.
//! - Conversion helpers between nanoseconds and APIC ticks.
//!
//! # APIC timer register layout
//!
//! | Offset | Register |
//! |--------|---------|
//! | 0x320  | LVT Timer |
//! | 0x3E0  | Divide Configuration |
//! | 0x380  | Initial Count |
//! | 0x390  | Current Count (read-only) |

use oncrix_lib::{Error, Result};

// ── APIC MMIO register offsets ───────────────────────────────────────────────

/// LVT Timer register offset.
const LVT_TIMER: u64 = 0x320;

/// Divide Configuration register offset.
const DIVIDE_CONFIG: u64 = 0x3E0;

/// Initial Count register offset.
const INITIAL_COUNT: u64 = 0x380;

/// Current Count register offset (read-only).
const CURRENT_COUNT: u64 = 0x390;

// ── LVT Timer bit fields ─────────────────────────────────────────────────────

/// LVT: mask interrupt (bit 16).
const LVT_MASK: u32 = 1 << 16;

/// LVT: timer mode bits (17:18).
const LVT_TIMER_MODE_SHIFT: u32 = 17;

/// LVT timer mode: one-shot.
const LVT_MODE_ONESHOT: u32 = 0b00;

/// LVT timer mode: periodic.
const LVT_MODE_PERIODIC: u32 = 0b01;

/// LVT timer mode: TSC-Deadline.
const LVT_MODE_TSC_DEADLINE: u32 = 0b10;

/// LVT: vector bits (7:0).
const LVT_VECTOR_MASK: u32 = 0xFF;

// ── Divide Configuration ─────────────────────────────────────────────────────

/// Divide by 2.
const DIV_BY_2: u32 = 0b0000;
/// Divide by 4.
const DIV_BY_4: u32 = 0b0001;
/// Divide by 8.
const DIV_BY_8: u32 = 0b0010;
/// Divide by 16.
const DIV_BY_16: u32 = 0b0011;
/// Divide by 32.
const DIV_BY_32: u32 = 0b1000;
/// Divide by 64.
const DIV_BY_64: u32 = 0b1001;
/// Divide by 128.
const DIV_BY_128: u32 = 0b1010;
/// Divide by 1.
const DIV_BY_1: u32 = 0b1011;

// ── PIT constants for calibration ────────────────────────────────────────────

/// PIT channel 2 data port.
const PIT_CHANNEL2: u16 = 0x42;

/// PIT mode/command register port.
const PIT_MODE_CMD: u16 = 0x43;

/// PIT NMI status and control.
const PIT_PC_SPEAKER: u16 = 0x61;

/// PIT base clock: 1193182 Hz.
const PIT_FREQ_HZ: u64 = 1_193_182;

/// Calibration time: 10 ms expressed as PIT ticks.
const PIT_CAL_TICKS: u32 = (PIT_FREQ_HZ / 100) as u32; // ~11931

/// Nanoseconds per second.
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Nanoseconds per millisecond.
const NANOS_PER_MS: u64 = 1_000_000;

// ── ApicTimerMode ────────────────────────────────────────────────────────────

/// Operating mode for the local APIC timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApicTimerMode {
    /// Fire once when the counter reaches zero.
    OneShot,
    /// Reload and fire repeatedly at the programmed period.
    Periodic,
    /// Interrupt when `IA32_TSC_DEADLINE` MSR equals the TSC.
    TscDeadline,
}

// ── ApicTimer ────────────────────────────────────────────────────────────────

/// Local APIC timer driver.
pub struct ApicTimer {
    /// Virtual base address of the APIC MMIO region.
    apic_base: u64,
    /// Calibrated ticks per millisecond.
    ticks_per_ms: u32,
    /// Current timer mode.
    mode: ApicTimerMode,
    /// Current divide configuration raw value.
    divisor_raw: u32,
    /// Effective clock divisor (1, 2, 4, 8, 16, 32, 64, or 128).
    divisor: u8,
    /// Whether the timer has been calibrated.
    calibrated: bool,
}

impl ApicTimer {
    /// Create a new, uncalibrated APIC timer driver.
    pub const fn new() -> Self {
        Self {
            apic_base: 0,
            ticks_per_ms: 0,
            mode: ApicTimerMode::OneShot,
            divisor_raw: DIV_BY_1,
            divisor: 1,
            calibrated: false,
        }
    }

    /// Initialise the APIC timer with the given MMIO base address.
    ///
    /// Sets divisor to ÷16 and masks the timer interrupt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `apic_virt_base` is zero.
    pub fn init(&mut self, apic_virt_base: u64) -> Result<()> {
        if apic_virt_base == 0 {
            return Err(Error::InvalidArgument);
        }
        self.apic_base = apic_virt_base;

        // Set divisor to ÷16 by default.
        self.set_divisor(16)?;

        // Mask the timer interrupt.
        self.write_reg(LVT_TIMER, LVT_MASK);

        Ok(())
    }

    /// Calibrate the timer using the PIT channel 2.
    ///
    /// Counts APIC ticks over a 10 ms PIT window, then stores
    /// `ticks_per_ms` for use in [`set_oneshot`] / [`set_periodic`].
    ///
    /// On non-x86_64 platforms, sets a synthetic 1 MHz default.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the APIC base is not set.
    pub fn calibrate_timer(&mut self) -> Result<()> {
        if self.apic_base == 0 {
            return Err(Error::InvalidArgument);
        }

        #[cfg(target_arch = "x86_64")]
        {
            // Program PIT channel 2 for a one-shot count-down of PIT_CAL_TICKS.
            // SAFETY: PIT I/O ports are standard 8086-compatible ports.
            // Writing to 0x43/0x42/0x61 is safe at CPL 0.
            unsafe {
                // Gate off speaker, use channel 2 mode 0 (one-shot).
                let speaker = port_inb(PIT_PC_SPEAKER);
                port_outb(PIT_PC_SPEAKER, (speaker & 0xFC) | 0x01); // gate on, speaker off

                // Channel 2, lobyte/hibyte, mode 0, binary.
                port_outb(PIT_MODE_CMD, 0b10_11_000_0);
                port_outb(PIT_CHANNEL2, (PIT_CAL_TICKS & 0xFF) as u8);
                port_outb(PIT_CHANNEL2, ((PIT_CAL_TICKS >> 8) & 0xFF) as u8);
            }

            // Start APIC timer with max initial count.
            self.write_reg(INITIAL_COUNT, u32::MAX);

            // Wait for PIT to complete (OUT2 goes low then high).
            // SAFETY: reading from the PIT PC speaker port is harmless.
            unsafe {
                // Re-trigger: clear and re-set gate bit.
                let speaker = port_inb(PIT_PC_SPEAKER);
                port_outb(PIT_PC_SPEAKER, speaker & 0xFE); // gate off
                port_outb(PIT_PC_SPEAKER, speaker | 0x01); // gate on

                // Poll OUT2 bit (bit 5 of port 0x61) until the counter reaches 0.
                while port_inb(PIT_PC_SPEAKER) & 0x20 == 0 {}
            }

            // Read APIC timer remaining count.
            let remaining = self.read_reg(CURRENT_COUNT);
            let elapsed = u32::MAX.saturating_sub(remaining);

            // 10 ms window → ticks_per_ms.
            self.ticks_per_ms = elapsed / 10;
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            // Synthetic 1 GHz / divisor calibration for non-x86_64.
            self.ticks_per_ms = 1_000_000 / self.divisor as u32;
        }

        self.calibrated = true;
        Ok(())
    }

    /// Program the timer in one-shot mode to fire after `ms` milliseconds.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ms` is zero.
    /// - [`Error::Busy`] if the timer has not been calibrated.
    pub fn set_oneshot(&mut self, vector: u8, ms: u32) -> Result<()> {
        if !self.calibrated {
            return Err(Error::Busy);
        }
        if ms == 0 {
            return Err(Error::InvalidArgument);
        }
        let ticks = self.ticks_per_ms.saturating_mul(ms);
        self.program_lvt(vector, ApicTimerMode::OneShot);
        self.write_reg(INITIAL_COUNT, ticks);
        self.mode = ApicTimerMode::OneShot;
        Ok(())
    }

    /// Program the timer in periodic mode with a period of `ms` milliseconds.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ms` is zero.
    /// - [`Error::Busy`] if the timer has not been calibrated.
    pub fn set_periodic(&mut self, vector: u8, ms: u32) -> Result<()> {
        if !self.calibrated {
            return Err(Error::Busy);
        }
        if ms == 0 {
            return Err(Error::InvalidArgument);
        }
        let ticks = self.ticks_per_ms.saturating_mul(ms);
        self.program_lvt(vector, ApicTimerMode::Periodic);
        self.write_reg(INITIAL_COUNT, ticks);
        self.mode = ApicTimerMode::Periodic;
        Ok(())
    }

    /// Program the timer in TSC-Deadline mode.
    ///
    /// The timer fires when `IA32_TSC_DEADLINE` MSR (0x6E0) equals
    /// or is passed by the TSC. The caller is responsible for writing
    /// the MSR.
    pub fn set_tsc_deadline(&mut self, vector: u8) {
        self.program_lvt(vector, ApicTimerMode::TscDeadline);
        self.mode = ApicTimerMode::TscDeadline;
    }

    /// Stop the timer by writing 0 to the initial count and masking LVT.
    pub fn stop(&mut self) {
        self.write_reg(INITIAL_COUNT, 0);
        let lvt = self.read_reg(LVT_TIMER);
        self.write_reg(LVT_TIMER, lvt | LVT_MASK);
    }

    /// Return the calibrated ticks per millisecond.
    ///
    /// Returns 0 if not yet calibrated.
    pub fn ticks_per_ms(&self) -> u32 {
        self.ticks_per_ms
    }

    /// Convert nanoseconds to APIC ticks.
    ///
    /// Returns 0 if not calibrated.
    pub fn nanos_to_ticks(&self, nanos: u64) -> u64 {
        if self.ticks_per_ms == 0 {
            return 0;
        }
        (nanos * self.ticks_per_ms as u64) / NANOS_PER_MS
    }

    /// Convert APIC ticks to nanoseconds.
    ///
    /// Returns 0 if not calibrated.
    pub fn ticks_to_nanos(&self, ticks: u64) -> u64 {
        if self.ticks_per_ms == 0 {
            return 0;
        }
        (ticks * NANOS_PER_MS) / self.ticks_per_ms as u64
    }

    /// Return the current APIC timer count.
    pub fn current_count(&self) -> u32 {
        self.read_reg(CURRENT_COUNT)
    }

    /// Return the current timer mode.
    pub fn mode(&self) -> ApicTimerMode {
        self.mode
    }

    /// Return whether the timer has been calibrated.
    pub fn is_calibrated(&self) -> bool {
        self.calibrated
    }

    /// Set the timer clock divisor.
    ///
    /// Valid divisors: 1, 2, 4, 8, 16, 32, 64, 128.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unsupported divisors.
    pub fn set_divisor(&mut self, div: u8) -> Result<()> {
        let raw = match div {
            1 => DIV_BY_1,
            2 => DIV_BY_2,
            4 => DIV_BY_4,
            8 => DIV_BY_8,
            16 => DIV_BY_16,
            32 => DIV_BY_32,
            64 => DIV_BY_64,
            128 => DIV_BY_128,
            _ => return Err(Error::InvalidArgument),
        };
        self.write_reg(DIVIDE_CONFIG, raw);
        self.divisor_raw = raw;
        self.divisor = div;
        Ok(())
    }

    /// Estimate the APIC timer frequency in Hz based on calibration.
    ///
    /// Returns 0 if not calibrated.
    pub fn frequency_hz(&self) -> u64 {
        if self.ticks_per_ms == 0 {
            return 0;
        }
        self.ticks_per_ms as u64 * 1_000
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Program the LVT timer register.
    fn program_lvt(&self, vector: u8, mode: ApicTimerMode) {
        let mode_bits = match mode {
            ApicTimerMode::OneShot => LVT_MODE_ONESHOT,
            ApicTimerMode::Periodic => LVT_MODE_PERIODIC,
            ApicTimerMode::TscDeadline => LVT_MODE_TSC_DEADLINE,
        };
        let lvt = (vector as u32 & LVT_VECTOR_MASK) | (mode_bits << LVT_TIMER_MODE_SHIFT);
        self.write_reg(LVT_TIMER, lvt);
    }

    /// Read a 32-bit APIC register.
    fn read_reg(&self, offset: u64) -> u32 {
        // SAFETY: apic_base is a valid kernel MMIO mapping of the local APIC.
        // All offsets used are within the 4 KiB APIC page.
        unsafe {
            let ptr = (self.apic_base + offset) as *const u32;
            core::ptr::read_volatile(ptr)
        }
    }

    /// Write a 32-bit APIC register.
    fn write_reg(&self, offset: u64, value: u32) {
        // SAFETY: same as read_reg.
        unsafe {
            let ptr = (self.apic_base + offset) as *mut u32;
            core::ptr::write_volatile(ptr, value);
        }
    }
}

impl Default for ApicTimer {
    fn default() -> Self {
        Self::new()
    }
}

// ── PIT port I/O helpers (x86_64 only) ───────────────────────────────────────

#[cfg(target_arch = "x86_64")]
unsafe fn port_inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Caller guarantees CPL 0 access. Standard x86 I/O port instruction.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nostack, nomem, preserves_flags),
        );
    }
    val
}

#[cfg(target_arch = "x86_64")]
unsafe fn port_outb(port: u16, val: u8) {
    // SAFETY: Caller guarantees CPL 0. Standard x86 I/O port instruction.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nostack, nomem, preserves_flags),
        );
    }
}

/// Estimate the per-second tick rate for a given millisecond window.
///
/// `elapsed_ticks` is the number of APIC ticks counted during
/// `ms` milliseconds. Returns ticks per second.
pub fn ticks_to_hz(elapsed_ticks: u32, ms: u32) -> u64 {
    if ms == 0 {
        return 0;
    }
    (elapsed_ticks as u64 * NANOS_PER_SEC) / (ms as u64 * NANOS_PER_MS)
}
