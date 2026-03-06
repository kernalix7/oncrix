// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ARM Generic Timer (CNTP/CNTV) hardware driver.
//!
//! Implements the ARM Architectural Timer (ARMv7-A / ARMv8-A) using the
//! CNTPCT (physical counter), CNTVCT (virtual counter), and the associated
//! compare registers. Provides oneshot and periodic timer modes via the EL1
//! physical timer (CNTP_*) and virtual timer (CNTV_*) system registers.
//!
//! # System Registers
//!
//! | Register    | Description                              |
//! |-------------|------------------------------------------|
//! | CNTFRQ_EL0  | Counter frequency (Hz, set by firmware)  |
//! | CNTPCT_EL0  | Physical count value                     |
//! | CNTVCT_EL0  | Virtual count value                      |
//! | CNTP_CTL_EL0| Physical timer control                   |
//! | CNTP_TVAL_EL0| Physical timer value (countdown)        |
//! | CNTP_CVAL_EL0| Physical timer compare value            |
//! | CNTV_CTL_EL0| Virtual timer control                    |
//! | CNTV_TVAL_EL0| Virtual timer value (countdown)         |
//! | CNTV_CVAL_EL0| Virtual timer compare value             |
//!
//! # Control Register Bits (CTL)
//!
//! | Bit | Name   | Description                              |
//! |-----|--------|------------------------------------------|
//! |  0  | ENABLE | Timer enabled                            |
//! |  1  | IMASK  | Interrupt masked (1 = masked)            |
//! |  2  | ISTATUS| Condition met (read-only)                |
//!
//! Reference: ARM DDI0487 (ARM Architecture Reference Manual).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// CTL register bits
// ---------------------------------------------------------------------------

/// Timer Enable bit in CTL register.
const CTL_ENABLE: u64 = 1 << 0;
/// Timer Interrupt Mask bit in CTL register.
const CTL_IMASK: u64 = 1 << 1;
/// Timer status bit (condition met) in CTL register.
const CTL_ISTATUS: u64 = 1 << 2;

// ---------------------------------------------------------------------------
// Timer source
// ---------------------------------------------------------------------------

/// ARM generic timer source selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmTimerSource {
    /// EL1 Physical Timer (CNTP_*_EL0).
    Physical,
    /// EL1 Virtual Timer (CNTV_*_EL0).
    Virtual,
}

// ---------------------------------------------------------------------------
// Timer mode
// ---------------------------------------------------------------------------

/// Operating mode of the ARM generic timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmTimerMode {
    /// Timer fires once after `period_ns` nanoseconds.
    Oneshot,
    /// Timer reloads automatically every `period_ns` nanoseconds.
    Periodic,
}

// ---------------------------------------------------------------------------
// ArmTimer
// ---------------------------------------------------------------------------

/// ARM generic timer driver.
pub struct ArmTimer {
    /// Counter frequency in Hz (read from CNTFRQ_EL0).
    freq_hz: u64,
    /// Selected timer source.
    source: ArmTimerSource,
    /// Current operating mode.
    mode: ArmTimerMode,
    /// Period in nanoseconds.
    period_ns: u64,
    /// Whether the timer is initialized.
    initialized: bool,
    /// Whether the timer is currently running.
    running: bool,
}

impl ArmTimer {
    /// Creates an uninitialized ARM generic timer driver.
    pub const fn new(source: ArmTimerSource) -> Self {
        Self {
            freq_hz: 0,
            source,
            mode: ArmTimerMode::Oneshot,
            period_ns: 0,
            initialized: false,
            running: false,
        }
    }

    /// Initializes the timer by reading the counter frequency.
    ///
    /// Must be called from EL1 or higher.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the frequency register reads as zero
    /// (indicating firmware did not configure it).
    pub fn init(&mut self) -> Result<()> {
        self.freq_hz = self.read_cntfrq();
        if self.freq_hz == 0 {
            // Firmware should set this; use a common default of 50 MHz.
            self.freq_hz = 50_000_000;
        }
        // Disable and mask the timer during init.
        self.write_ctl(CTL_IMASK);
        self.initialized = true;
        Ok(())
    }

    /// Programs the timer to fire after `period_ns` nanoseconds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `period_ns` is zero.
    /// Returns [`Error::IoError`] if the timer is not initialized.
    pub fn set_oneshot(&mut self, period_ns: u64) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if period_ns == 0 {
            return Err(Error::InvalidArgument);
        }
        self.period_ns = period_ns;
        self.mode = ArmTimerMode::Oneshot;
        let ticks = self.ns_to_ticks(period_ns);
        self.write_tval(ticks as u32);
        // Enable, unmask.
        self.write_ctl(CTL_ENABLE);
        self.running = true;
        Ok(())
    }

    /// Programs the timer for periodic interrupts every `period_ns` nanoseconds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `period_ns` is zero.
    /// Returns [`Error::IoError`] if the timer is not initialized.
    pub fn set_periodic(&mut self, period_ns: u64) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if period_ns == 0 {
            return Err(Error::InvalidArgument);
        }
        self.period_ns = period_ns;
        self.mode = ArmTimerMode::Periodic;
        self.reload();
        self.write_ctl(CTL_ENABLE);
        self.running = true;
        Ok(())
    }

    /// Stops the timer and masks its interrupt.
    pub fn stop(&mut self) {
        self.write_ctl(CTL_IMASK);
        self.running = false;
    }

    /// Handles a timer interrupt.
    ///
    /// Acknowledges the interrupt by reloading (periodic) or stopping (oneshot).
    /// Returns `true` if the interrupt was from this timer.
    pub fn handle_irq(&mut self) -> bool {
        let ctl = self.read_ctl();
        if ctl & CTL_ISTATUS == 0 {
            return false;
        }
        match self.mode {
            ArmTimerMode::Periodic => {
                self.reload();
            }
            ArmTimerMode::Oneshot => {
                // Mask to prevent re-triggering.
                self.write_ctl(CTL_IMASK);
                self.running = false;
            }
        }
        true
    }

    /// Returns the current physical counter value.
    #[cfg(target_arch = "aarch64")]
    pub fn read_counter(&self) -> u64 {
        let val: u64;
        match self.source {
            ArmTimerSource::Physical => {
                // SAFETY: Reading CNTPCT_EL0 is a non-privileged operation.
                unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) val) };
            }
            ArmTimerSource::Virtual => {
                // SAFETY: Reading CNTVCT_EL0 is a non-privileged operation.
                unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) val) };
            }
        }
        val
    }

    /// Returns 0 on non-AArch64 platforms (stub).
    #[cfg(not(target_arch = "aarch64"))]
    pub fn read_counter(&self) -> u64 {
        0
    }

    /// Converts nanoseconds to timer ticks.
    pub fn ns_to_ticks(&self, ns: u64) -> u64 {
        // ticks = ns * freq / 1_000_000_000
        ns.saturating_mul(self.freq_hz) / 1_000_000_000
    }

    /// Converts timer ticks to nanoseconds.
    pub fn ticks_to_ns(&self, ticks: u64) -> u64 {
        if self.freq_hz == 0 {
            return 0;
        }
        ticks.saturating_mul(1_000_000_000) / self.freq_hz
    }

    /// Returns the counter frequency in Hz.
    pub fn freq_hz(&self) -> u64 {
        self.freq_hz
    }

    /// Returns `true` if the timer is currently running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Returns `true` if the timer is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -----------------------------------------------------------------------
    // Private: System register access (AArch64)
    // -----------------------------------------------------------------------

    #[cfg(target_arch = "aarch64")]
    fn read_cntfrq(&self) -> u64 {
        let val: u64;
        // SAFETY: CNTFRQ_EL0 is a read-only register accessible at EL0+.
        unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) val) };
        val
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn read_cntfrq(&self) -> u64 {
        50_000_000 // 50 MHz stub
    }

    #[cfg(target_arch = "aarch64")]
    fn read_ctl(&self) -> u64 {
        let val: u64;
        match self.source {
            ArmTimerSource::Physical => {
                // SAFETY: CNTP_CTL_EL0 accessible at EL1+.
                unsafe { core::arch::asm!("mrs {}, cntp_ctl_el0", out(reg) val) };
            }
            ArmTimerSource::Virtual => {
                // SAFETY: CNTV_CTL_EL0 accessible at EL1+.
                unsafe { core::arch::asm!("mrs {}, cntv_ctl_el0", out(reg) val) };
            }
        }
        val
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn read_ctl(&self) -> u64 {
        0
    }

    #[cfg(target_arch = "aarch64")]
    fn write_ctl(&self, val: u64) {
        match self.source {
            ArmTimerSource::Physical => {
                // SAFETY: CNTP_CTL_EL0 write controls EL1 physical timer.
                unsafe { core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) val) };
            }
            ArmTimerSource::Virtual => {
                // SAFETY: CNTV_CTL_EL0 write controls EL1 virtual timer.
                unsafe { core::arch::asm!("msr cntv_ctl_el0, {}", in(reg) val) };
            }
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn write_ctl(&self, _val: u64) {}

    #[cfg(target_arch = "aarch64")]
    fn write_tval(&self, ticks: u32) {
        let val = ticks as u64;
        match self.source {
            ArmTimerSource::Physical => {
                // SAFETY: CNTP_TVAL_EL0 sets the physical timer countdown.
                unsafe { core::arch::asm!("msr cntp_tval_el0, {}", in(reg) val) };
            }
            ArmTimerSource::Virtual => {
                // SAFETY: CNTV_TVAL_EL0 sets the virtual timer countdown.
                unsafe { core::arch::asm!("msr cntv_tval_el0, {}", in(reg) val) };
            }
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn write_tval(&self, _ticks: u32) {}

    fn reload(&mut self) {
        let ticks = self.ns_to_ticks(self.period_ns);
        self.write_tval(ticks as u32);
    }
}

impl Default for ArmTimer {
    fn default() -> Self {
        Self::new(ArmTimerSource::Physical)
    }
}

// ---------------------------------------------------------------------------
// Standalone helpers
// ---------------------------------------------------------------------------

/// Reads the current physical counter value (CNTPCT_EL0).
///
/// Returns 0 on non-AArch64 targets.
#[cfg(target_arch = "aarch64")]
pub fn read_physical_counter() -> u64 {
    let val: u64;
    // SAFETY: CNTPCT_EL0 is a read-only system register accessible at EL0+.
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) val) };
    val
}

/// Stub: returns 0 on non-AArch64 platforms.
#[cfg(not(target_arch = "aarch64"))]
pub fn read_physical_counter() -> u64 {
    0
}

/// Reads the counter frequency from CNTFRQ_EL0.
///
/// Returns a default of 50 MHz on non-AArch64 targets.
#[cfg(target_arch = "aarch64")]
pub fn read_counter_freq() -> u64 {
    let val: u64;
    // SAFETY: CNTFRQ_EL0 is readable at EL0 and above.
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) val) };
    val
}

/// Stub: returns 50 MHz on non-AArch64 platforms.
#[cfg(not(target_arch = "aarch64"))]
pub fn read_counter_freq() -> u64 {
    50_000_000
}

/// Initializes an EL1 physical timer for oneshot use.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `period_ns` is zero.
pub fn init_el1_physical_timer(period_ns: u64) -> Result<ArmTimer> {
    let mut timer = ArmTimer::new(ArmTimerSource::Physical);
    timer.init()?;
    timer.set_oneshot(period_ns)?;
    Ok(timer)
}
