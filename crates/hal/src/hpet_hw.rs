// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! HPET (High Precision Event Timer) hardware register abstraction.
//!
//! This module provides a thin, register-level interface to the HPET hardware.
//! It is distinct from `hpet.rs` which provides the higher-level timer abstraction
//! with ACPI table parsing and timer scheduling.  This module focuses on:
//!
//! - Direct MMIO register access (64-bit reads/writes)
//! - Capability and configuration register parsing
//! - Main counter read
//! - Per-comparator timer programming (one-shot and periodic)
//! - Counter-to-nanosecond conversion
//!
//! # Usage
//!
//! ```ignore
//! let hpet = HpetHw::new(0xFED00000);
//! let period_fs = hpet.counter_period_fs();
//! let count = hpet.main_counter();
//! hpet.enable();
//! ```
//!
//! Reference: IA-PC HPET (High Precision Event Timers) Specification 1.0a.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// MMIO Register Offsets
// ---------------------------------------------------------------------------

/// General Capabilities and ID Register (64-bit, read-only).
pub const REG_CAP_ID: u64 = 0x000;
/// General Configuration Register (64-bit, R/W).
pub const REG_CONFIG: u64 = 0x010;
/// General Interrupt Status Register (64-bit, R/W1C).
pub const REG_INT_STATUS: u64 = 0x020;
/// Main Counter Value Register (64-bit, R/W).
pub const REG_MAIN_COUNTER: u64 = 0x0F0;

/// Timer N Configuration and Capabilities Register base offset.
pub const REG_TIMER_CONFIG_BASE: u64 = 0x100;
/// Timer N Comparator Value Register base offset.
pub const REG_TIMER_COMP_BASE: u64 = 0x108;
/// Timer N FSB Interrupt Route Register base offset.
pub const REG_TIMER_FSB_BASE: u64 = 0x110;
/// Stride between timer register sets.
pub const TIMER_STRIDE: u64 = 0x20;

/// Compute config register offset for timer `n`.
pub const fn timer_config_offset(n: u8) -> u64 {
    REG_TIMER_CONFIG_BASE + n as u64 * TIMER_STRIDE
}

/// Compute comparator register offset for timer `n`.
pub const fn timer_comp_offset(n: u8) -> u64 {
    REG_TIMER_COMP_BASE + n as u64 * TIMER_STRIDE
}

// ---------------------------------------------------------------------------
// General Configuration Register bits
// ---------------------------------------------------------------------------

/// Config bit 0: ENABLE_CNF — overall enable; start/stop main counter.
pub const CONFIG_ENABLE: u64 = 1 << 0;
/// Config bit 1: LEG_RT_CNF — enable legacy replacement routing.
pub const CONFIG_LEGACY_RT: u64 = 1 << 1;

// ---------------------------------------------------------------------------
// General Capabilities Register fields
// ---------------------------------------------------------------------------

/// Mask for the REV_ID field (bits 7:0).
pub const CAP_REV_ID_MASK: u64 = 0xFF;
/// Mask for the NUM_TIM_CAP field (bits 12:8).
pub const CAP_NUM_TIM_MASK: u64 = 0x1F00;
/// Shift for NUM_TIM_CAP.
pub const CAP_NUM_TIM_SHIFT: u32 = 8;
/// Bit 13: COUNT_SIZE_CAP — 1 if main counter is 64-bit.
pub const CAP_64BIT: u64 = 1 << 13;
/// Bit 15: LEG_RT_CAP — legacy replacement routing capable.
pub const CAP_LEGACY_RT: u64 = 1 << 15;
/// Bits 63:32: COUNTER_CLK_PERIOD in femtoseconds.
pub const CAP_PERIOD_SHIFT: u32 = 32;
pub const CAP_PERIOD_MASK: u64 = 0xFFFF_FFFF_0000_0000;

// ---------------------------------------------------------------------------
// Timer Configuration Register bits
// ---------------------------------------------------------------------------

/// Timer config bit 1: INT_TYPE_CNF — 1 = level-triggered, 0 = edge.
pub const TIMER_INT_LEVEL: u64 = 1 << 1;
/// Timer config bit 2: INT_ENB_CNF — enable interrupt for this timer.
pub const TIMER_INT_ENABLE: u64 = 1 << 2;
/// Timer config bit 3: TYPE_CNF — 1 = periodic, 0 = one-shot.
pub const TIMER_PERIODIC: u64 = 1 << 3;
/// Timer config bit 4: PER_INT_CAP — read-only, 1 = periodic capable.
pub const TIMER_PERIODIC_CAP: u64 = 1 << 4;
/// Timer config bit 5: SIZE_CAP — 1 = 64-bit comparator.
pub const TIMER_64BIT_CAP: u64 = 1 << 5;
/// Timer config bit 6: VAL_SET_CNF — set accumulator to comparator value.
pub const TIMER_VAL_SET: u64 = 1 << 6;
/// Timer config bit 8: 32MODE_CNF — force 32-bit mode.
pub const TIMER_32MODE: u64 = 1 << 8;

// ---------------------------------------------------------------------------
// Femtoseconds / nanoseconds conversion
// ---------------------------------------------------------------------------

/// 10^6 femtoseconds per nanosecond.
const FS_PER_NS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Read a 64-bit MMIO register at `base + offset`.
///
/// # Safety
///
/// Caller must ensure `base` is a valid HPET MMIO region and `offset`
/// is a valid register offset.
unsafe fn read64(base: u64, offset: u64) -> u64 {
    // SAFETY: Volatile read from HPET MMIO.
    unsafe { core::ptr::read_volatile((base + offset) as *const u64) }
}

/// Write a 64-bit value to MMIO register at `base + offset`.
///
/// # Safety
///
/// Same as [`read64`].
unsafe fn write64(base: u64, offset: u64, val: u64) {
    // SAFETY: Volatile write to HPET MMIO.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u64, val) }
}

// ---------------------------------------------------------------------------
// HpetHw
// ---------------------------------------------------------------------------

/// HPET hardware register interface.
pub struct HpetHw {
    /// Physical/virtual base address of the HPET MMIO region.
    base: u64,
}

impl HpetHw {
    /// Create a new [`HpetHw`] for the given MMIO base address.
    pub const fn new(base: u64) -> Self {
        Self { base }
    }

    /// Read the raw General Capabilities and ID register.
    pub fn capabilities(&self) -> u64 {
        // SAFETY: `self.base` is the HPET MMIO base; REG_CAP_ID is a valid offset.
        unsafe { read64(self.base, REG_CAP_ID) }
    }

    /// Return the counter clock period in femtoseconds (bits 63:32 of CAP_ID).
    ///
    /// Minimum valid value per spec: 100 ps (100,000 fs).
    pub fn counter_period_fs(&self) -> u32 {
        (self.capabilities() >> CAP_PERIOD_SHIFT) as u32
    }

    /// Return the number of timers minus one (bits 12:8 of CAP_ID).
    pub fn num_timers(&self) -> u8 {
        ((self.capabilities() & CAP_NUM_TIM_MASK) >> CAP_NUM_TIM_SHIFT) as u8
    }

    /// Return true if the main counter is 64-bit.
    pub fn is_64bit(&self) -> bool {
        (self.capabilities() & CAP_64BIT) != 0
    }

    /// Return true if legacy replacement routing is supported.
    pub fn supports_legacy_rt(&self) -> bool {
        (self.capabilities() & CAP_LEGACY_RT) != 0
    }

    /// Enable the HPET main counter.
    pub fn enable(&self) {
        // SAFETY: Writing HPET general config register.
        let cfg = unsafe { read64(self.base, REG_CONFIG) };
        unsafe { write64(self.base, REG_CONFIG, cfg | CONFIG_ENABLE) };
    }

    /// Disable the HPET main counter.
    pub fn disable(&self) {
        // SAFETY: Writing HPET general config register.
        let cfg = unsafe { read64(self.base, REG_CONFIG) };
        unsafe { write64(self.base, REG_CONFIG, cfg & !CONFIG_ENABLE) };
    }

    /// Read the current main counter value.
    pub fn main_counter(&self) -> u64 {
        // SAFETY: Reading HPET main counter register.
        unsafe { read64(self.base, REG_MAIN_COUNTER) }
    }

    /// Write the main counter (only valid while counter is halted).
    pub fn write_counter(&self, val: u64) {
        // SAFETY: Writing HPET main counter; caller must have halted it first.
        unsafe { write64(self.base, REG_MAIN_COUNTER, val) };
    }

    /// Convert a counter delta to nanoseconds.
    pub fn ticks_to_ns(&self, ticks: u64) -> u64 {
        let period_fs = self.counter_period_fs() as u64;
        ticks.saturating_mul(period_fs) / FS_PER_NS
    }

    /// Read timer `n` configuration register.
    pub fn timer_config(&self, n: u8) -> Result<u64> {
        if n > self.num_timers() {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: n is bounds-checked; accessing a valid HPET timer config register.
        Ok(unsafe { read64(self.base, timer_config_offset(n)) })
    }

    /// Read timer `n` comparator register.
    pub fn timer_comparator(&self, n: u8) -> Result<u64> {
        if n > self.num_timers() {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: n is bounds-checked; accessing a valid HPET timer comparator.
        Ok(unsafe { read64(self.base, timer_comp_offset(n)) })
    }

    /// Program timer `n` for one-shot operation at absolute counter value `target`.
    pub fn set_oneshot(&self, n: u8, target: u64) -> Result<()> {
        if n > self.num_timers() {
            return Err(Error::InvalidArgument);
        }
        let off = timer_config_offset(n);
        // SAFETY: n is bounds-checked; writing HPET timer config and comparator.
        unsafe {
            let cfg = read64(self.base, off);
            let cfg = (cfg & !TIMER_PERIODIC) | TIMER_INT_ENABLE;
            write64(self.base, off, cfg);
            write64(self.base, timer_comp_offset(n), target);
        }
        Ok(())
    }

    /// Program timer `n` for periodic operation with `period_ticks` interval.
    pub fn set_periodic(&self, n: u8, period_ticks: u64) -> Result<()> {
        if n > self.num_timers() {
            return Err(Error::InvalidArgument);
        }
        let cfg_val = self.timer_config(n)?;
        if (cfg_val & TIMER_PERIODIC_CAP) == 0 {
            return Err(Error::NotImplemented);
        }
        let off = timer_config_offset(n);
        // SAFETY: n is bounds-checked; writing HPET periodic timer config.
        unsafe {
            let cfg = read64(self.base, off);
            let cfg = cfg | TIMER_PERIODIC | TIMER_INT_ENABLE | TIMER_VAL_SET;
            write64(self.base, off, cfg);
            let now = read64(self.base, REG_MAIN_COUNTER);
            write64(self.base, timer_comp_offset(n), now + period_ticks);
            // Writing period value (VAL_SET must be set)
            write64(self.base, timer_comp_offset(n), period_ticks);
        }
        Ok(())
    }

    /// Disable timer `n` (clear interrupt enable bit).
    pub fn disable_timer(&self, n: u8) -> Result<()> {
        if n > self.num_timers() {
            return Err(Error::InvalidArgument);
        }
        let off = timer_config_offset(n);
        // SAFETY: n is bounds-checked; clearing HPET timer interrupt enable.
        unsafe {
            let cfg = read64(self.base, off);
            write64(self.base, off, cfg & !TIMER_INT_ENABLE);
        }
        Ok(())
    }

    /// Clear the interrupt status flag for timer `n`.
    pub fn clear_interrupt(&self, n: u8) {
        // SAFETY: Writing 1 to the timer's bit in INT_STATUS to clear it (W1C).
        unsafe { write64(self.base, REG_INT_STATUS, 1u64 << n) };
    }

    /// Return the HPET MMIO base address.
    pub const fn base(&self) -> u64 {
        self.base
    }
}
