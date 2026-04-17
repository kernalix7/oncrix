// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 generic timer driver.
//!
//! Uses the EL1 Physical Timer (CNTP_*_EL0 / CNTPCT_EL0) available
//! in the ARMv8-A Architecture Reference Manual, Section D13.
//!
//! The timer frequency is read from CNTFRQ_EL0 (set by firmware/QEMU).

use crate::timer::Timer;
use oncrix_lib::Result;

/// AArch64 generic physical timer.
pub struct AArch64Timer;

impl AArch64Timer {
    /// Create a new timer handle.
    pub const fn new() -> Self {
        Self
    }

    /// Read the current counter value from CNTPCT_EL0.
    #[cfg(target_arch = "aarch64")]
    fn counter_raw() -> u64 {
        let val: u64;
        // SAFETY: CNTPCT_EL0 is always accessible at EL1; no side effects.
        unsafe {
            core::arch::asm!(
                "mrs {val}, cntpct_el0",
                val = out(reg) val,
                options(nostack, preserves_flags),
            );
        }
        val
    }

    /// Read the timer frequency from CNTFRQ_EL0 (Hz).
    #[cfg(target_arch = "aarch64")]
    fn freq_raw() -> u64 {
        let val: u64;
        // SAFETY: CNTFRQ_EL0 is always readable at EL1.
        unsafe {
            core::arch::asm!(
                "mrs {val}, cntfrq_el0",
                val = out(reg) val,
                options(nostack, preserves_flags),
            );
        }
        val
    }

    /// Write CNTP_CTL_EL0: bit 0 = ENABLE, bit 1 = IMASK.
    #[cfg(target_arch = "aarch64")]
    fn write_ctl(val: u64) {
        // SAFETY: Writing CNTP_CTL_EL0 at EL1 to enable/disable the timer.
        unsafe {
            core::arch::asm!(
                "msr cntp_ctl_el0, {val}",
                "isb",
                val = in(reg) val,
                options(nostack, preserves_flags),
            );
        }
    }

    /// Write the comparator CNTP_CVAL_EL0.
    #[cfg(target_arch = "aarch64")]
    fn write_cval(val: u64) {
        // SAFETY: Writing CNTP_CVAL_EL0 at EL1 to set the timer deadline.
        unsafe {
            core::arch::asm!(
                "msr cntp_cval_el0, {val}",
                "isb",
                val = in(reg) val,
                options(nostack, preserves_flags),
            );
        }
    }
}

impl Default for AArch64Timer {
    fn default() -> Self {
        Self::new()
    }
}

impl Timer for AArch64Timer {
    fn frequency_hz(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            Self::freq_raw()
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            1_000_000
        }
    }

    fn current_ticks(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            Self::counter_raw()
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            0
        }
    }

    fn set_oneshot(&mut self, ticks: u64) -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            let deadline = Self::counter_raw().wrapping_add(ticks);
            // Disable timer while reconfiguring.
            Self::write_ctl(0);
            Self::write_cval(deadline);
            // Enable with IMASK=0 (interrupt unmasked).
            Self::write_ctl(1);
        }
        #[cfg(not(target_arch = "aarch64"))]
        let _ = ticks;
        Ok(())
    }

    fn set_periodic(&mut self, ticks: u64) -> Result<()> {
        // The AArch64 generic timer has no hardware periodic mode.
        // A one-shot is re-armed in the interrupt handler.
        self.set_oneshot(ticks)
    }

    fn stop(&mut self) -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            // IMASK=1 (interrupt masked), ENABLE=0.
            Self::write_ctl(0b10);
        }
        Ok(())
    }
}
