// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Clock divider hardware abstraction.
//!
//! Manages programmable clock dividers found in SoC clock trees.
//! A clock divider generates a lower-frequency output from a higher-frequency
//! parent clock by dividing by an integer or fractional ratio.
//!
//! # Divider Types
//!
//! - **Integer divider**: output = input / N
//! - **Fractional divider**: output = input * M / N (arbitrary ratio)
//! - **Power-of-two divider**: output = input >> shift

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// Clock divider type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DividerType {
    /// Divides by an integer N.
    Integer,
    /// Divides by a power of 2 (shift).
    PowerOfTwo,
    /// Fractional M/N divider.
    Fractional,
}

/// Clock divider configuration.
#[derive(Debug, Clone, Copy)]
pub struct ClkDividerConfig {
    /// Numerator M (for fractional divider; equals 1 for integer/pow2).
    pub numerator: u32,
    /// Denominator N.
    pub denominator: u32,
    /// Divider type.
    pub div_type: DividerType,
}

impl ClkDividerConfig {
    /// Creates an integer divider configuration.
    pub const fn integer(divisor: u32) -> Self {
        Self {
            numerator: 1,
            denominator: divisor,
            div_type: DividerType::Integer,
        }
    }

    /// Creates a power-of-two divider (shift by `shift` bits).
    pub const fn pow2(shift: u8) -> Self {
        Self {
            numerator: 1,
            denominator: 1 << shift,
            div_type: DividerType::PowerOfTwo,
        }
    }

    /// Creates a fractional M/N divider.
    pub const fn fractional(numerator: u32, denominator: u32) -> Self {
        Self {
            numerator,
            denominator,
            div_type: DividerType::Fractional,
        }
    }

    /// Computes the output frequency given an input frequency.
    pub fn output_freq(&self, input_hz: u64) -> Result<u64> {
        if self.denominator == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(input_hz * self.numerator as u64 / self.denominator as u64)
    }

    /// Validates that numerator <= denominator (output <= input).
    pub fn validate(&self) -> Result<()> {
        if self.denominator == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.numerator > self.denominator {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

/// MMIO-based programmable clock divider.
pub struct MmioClkDivider {
    /// MMIO base address of the divider register.
    base: usize,
    /// Register offset for the divider value.
    div_reg_offset: usize,
    /// Bit mask for the divider field in the register.
    div_mask: u32,
    /// Bit shift for the divider field.
    div_shift: u8,
    /// Parent clock frequency in Hz.
    parent_hz: u64,
    /// Current configuration.
    config: ClkDividerConfig,
}

impl MmioClkDivider {
    /// Creates a new MMIO clock divider.
    pub const fn new(
        base: usize,
        div_reg_offset: usize,
        div_mask: u32,
        div_shift: u8,
        parent_hz: u64,
    ) -> Self {
        Self {
            base,
            div_reg_offset,
            div_mask,
            div_shift,
            parent_hz,
            config: ClkDividerConfig::integer(1),
        }
    }

    /// Sets the divider to achieve the closest output frequency to `target_hz`.
    pub fn set_rate(&mut self, target_hz: u64) -> Result<u64> {
        if target_hz == 0 || target_hz > self.parent_hz {
            return Err(Error::InvalidArgument);
        }
        let divisor = (self.parent_hz + target_hz - 1) / target_hz;
        let divisor = divisor.min((self.div_mask >> self.div_shift) as u64);
        let divisor = divisor.max(1);
        self.config = ClkDividerConfig::integer(divisor as u32);
        self.write_divider(divisor as u32)?;
        Ok(self.parent_hz / divisor)
    }

    /// Reads the current divider value and computes the output frequency.
    pub fn get_rate(&self) -> u64 {
        let raw = self.read_divider();
        let divisor = raw.max(1);
        self.parent_hz / divisor as u64
    }

    /// Sets the parent clock frequency.
    pub fn set_parent_hz(&mut self, parent_hz: u64) {
        self.parent_hz = parent_hz;
    }

    fn read_divider(&self) -> u32 {
        let addr = (self.base + self.div_reg_offset) as *const u32;
        // SAFETY: base is a valid SoC clock control MMIO region. Volatile read
        // prevents caching of the register value.
        let raw = unsafe { addr.read_volatile() };
        (raw & self.div_mask) >> self.div_shift
    }

    fn write_divider(&self, divisor: u32) -> Result<()> {
        if divisor & !(self.div_mask >> self.div_shift) != 0 {
            return Err(Error::InvalidArgument);
        }
        let addr = (self.base + self.div_reg_offset) as *mut u32;
        // SAFETY: base is a valid SoC clock control MMIO region. The divider field
        // is updated within its mask to avoid corrupting adjacent register fields.
        unsafe {
            let cur = (addr as *const u32).read_volatile();
            let new_val = (cur & !self.div_mask) | ((divisor << self.div_shift) & self.div_mask);
            addr.write_volatile(new_val);
        }
        Ok(())
    }
}

impl Default for MmioClkDivider {
    fn default() -> Self {
        Self::new(0, 0, 0xFF, 0, 100_000_000)
    }
}
