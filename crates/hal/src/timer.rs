// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Timer abstraction for scheduling and timekeeping.

use oncrix_lib::Result;

/// Hardware-independent timer interface.
///
/// Implementations provide architecture-specific timer control
/// (e.g., x86_64 APIC timer / HPET, aarch64 generic timer,
/// riscv64 mtime).
pub trait Timer {
    /// Returns the timer frequency in Hz.
    fn frequency_hz(&self) -> u64;

    /// Returns the current tick count since timer initialization.
    fn current_ticks(&self) -> u64;

    /// Arm a one-shot interrupt after `ticks` timer ticks.
    fn set_oneshot(&mut self, ticks: u64) -> Result<()>;

    /// Arm a periodic interrupt every `ticks` timer ticks.
    fn set_periodic(&mut self, ticks: u64) -> Result<()>;

    /// Stop the timer (cancel any pending interrupt).
    fn stop(&mut self) -> Result<()>;

    /// Convert nanoseconds to timer ticks.
    fn nanos_to_ticks(&self, nanos: u64) -> u64 {
        let freq = self.frequency_hz();
        // Use u128 intermediate to avoid overflow
        ((nanos as u128 * freq as u128) / 1_000_000_000) as u64
    }

    /// Convert timer ticks to nanoseconds.
    fn ticks_to_nanos(&self, ticks: u64) -> u64 {
        let freq = self.frequency_hz();
        if freq == 0 {
            return 0;
        }
        ((ticks as u128 * 1_000_000_000) / freq as u128) as u64
    }
}
