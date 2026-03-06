// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 Programmable Interval Timer (PIT) driver.
//!
//! The 8253/8254 PIT provides a simple periodic timer for early
//! boot before APIC timer calibration. Channel 0 is wired to IRQ 0.

use crate::timer::Timer;
use oncrix_lib::Result;

/// PIT oscillator frequency (Hz).
const PIT_FREQUENCY: u64 = 1_193_182;

/// PIT I/O ports.
mod port {
    /// Channel 0 data port.
    pub const CHANNEL0: u16 = 0x40;
    /// Command/mode register.
    pub const COMMAND: u16 = 0x43;
}

/// PIT command byte fields.
mod cmd {
    /// Channel 0, lo/hi byte access, rate generator (mode 2).
    pub const RATE_GEN: u8 = 0x34;
    /// Channel 0, lo/hi byte access, one-shot (mode 0).
    pub const ONESHOT: u8 = 0x30;
}

/// PIT timer driver.
pub struct Pit {
    /// Current divisor (determines frequency).
    divisor: u16,
    /// Tick counter (incremented by IRQ handler).
    ticks: u64,
}

impl Default for Pit {
    fn default() -> Self {
        Self::new()
    }
}

impl Pit {
    /// Create a new PIT instance (not yet programmed).
    pub const fn new() -> Self {
        Self {
            divisor: 0,
            ticks: 0,
        }
    }

    /// Increment the tick counter. Called from the timer IRQ handler.
    pub fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);
    }

    /// Program the PIT with a specific divisor.
    fn program(&self, mode: u8, divisor: u16) {
        // SAFETY: Writing to PIT I/O ports in Ring 0.
        unsafe {
            super::io::outb(port::COMMAND, mode);
            super::io::outb(port::CHANNEL0, (divisor & 0xFF) as u8);
            super::io::outb(port::CHANNEL0, (divisor >> 8) as u8);
        }
    }
}

impl Timer for Pit {
    fn frequency_hz(&self) -> u64 {
        if self.divisor == 0 {
            return 0;
        }
        PIT_FREQUENCY / self.divisor as u64
    }

    fn current_ticks(&self) -> u64 {
        self.ticks
    }

    fn set_oneshot(&mut self, ticks: u64) -> Result<()> {
        let divisor = ticks.min(u16::MAX as u64) as u16;
        if divisor == 0 {
            return Err(oncrix_lib::Error::InvalidArgument);
        }
        self.divisor = divisor;
        self.program(cmd::ONESHOT, divisor);
        Ok(())
    }

    fn set_periodic(&mut self, ticks: u64) -> Result<()> {
        let divisor = ticks.min(u16::MAX as u64) as u16;
        if divisor == 0 {
            return Err(oncrix_lib::Error::InvalidArgument);
        }
        self.divisor = divisor;
        self.program(cmd::RATE_GEN, divisor);
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.divisor = 0;
        Ok(())
    }
}
