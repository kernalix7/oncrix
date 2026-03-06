// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Clock provider framework.
//!
//! Implements the producer side of the clock tree. A clock provider manages
//! one or more clocks (oscillators, PLLs, dividers, muxes) and exposes them
//! to clock consumers. Consumers look up clocks by name through the clock
//! provider registry.
//!
//! This module is complementary to `clk_framework` (which provides the
//! consumer API) and `clock_gate` (which provides simple on/off gates).

use oncrix_lib::{Error, Result};

/// Maximum number of clocks a single provider can manage.
pub const CLK_PROVIDER_MAX_CLOCKS: usize = 32;
/// Maximum parent clocks for a mux or divider.
pub const CLK_MAX_PARENTS: usize = 8;
/// Maximum clock name length.
pub const CLK_NAME_LEN: usize = 32;

/// Clock type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClkType {
    /// Fixed-rate oscillator (no software control).
    Fixed,
    /// Phase-locked loop (PLL).
    Pll,
    /// Integer divider.
    Divider,
    /// Clock multiplexer.
    Mux,
    /// Simple on/off gate.
    Gate,
}

/// A single clock descriptor managed by the provider.
#[derive(Debug, Clone, Copy)]
pub struct ClkDescriptor {
    /// Human-readable clock name.
    pub name: [u8; CLK_NAME_LEN],
    /// Clock type.
    pub clk_type: ClkType,
    /// Fixed or initial frequency in Hz (0 = not fixed).
    pub rate_hz: u64,
    /// Enable count (0 = disabled).
    pub enable_count: u32,
    /// Parent clock index within this provider (u8::MAX = none).
    pub parent: u8,
    /// MMIO register offset for enable/disable (0 = N/A).
    pub enable_reg: u32,
    /// Bit within `enable_reg` that enables the clock.
    pub enable_bit: u8,
}

impl ClkDescriptor {
    /// Creates a new fixed-rate clock descriptor.
    pub const fn fixed(name_bytes: [u8; CLK_NAME_LEN], rate_hz: u64) -> Self {
        Self {
            name: name_bytes,
            clk_type: ClkType::Fixed,
            rate_hz,
            enable_count: 1,
            parent: u8::MAX,
            enable_reg: 0,
            enable_bit: 0,
        }
    }

    /// Creates a new gate clock descriptor.
    pub const fn gate(
        name_bytes: [u8; CLK_NAME_LEN],
        parent: u8,
        enable_reg: u32,
        enable_bit: u8,
    ) -> Self {
        Self {
            name: name_bytes,
            clk_type: ClkType::Gate,
            rate_hz: 0,
            enable_count: 0,
            parent,
            enable_reg,
            enable_bit,
        }
    }
}

impl Default for ClkDescriptor {
    fn default() -> Self {
        Self {
            name: [0u8; CLK_NAME_LEN],
            clk_type: ClkType::Fixed,
            rate_hz: 0,
            enable_count: 0,
            parent: u8::MAX,
            enable_reg: 0,
            enable_bit: 0,
        }
    }
}

/// Clock provider — manages a set of platform clocks.
pub struct ClkProvider {
    /// MMIO base for this provider's CCU (Clock Control Unit).
    base: usize,
    /// Number of valid clocks.
    num_clocks: usize,
    /// Clock descriptors.
    clocks: [ClkDescriptor; CLK_PROVIDER_MAX_CLOCKS],
}

impl ClkProvider {
    /// Creates a new clock provider.
    ///
    /// # Arguments
    ///
    /// * `base` — MMIO base of the CCU (must be mapped).
    pub const fn new(base: usize) -> Self {
        Self {
            base,
            num_clocks: 0,
            clocks: [const {
                ClkDescriptor {
                    name: [0u8; CLK_NAME_LEN],
                    clk_type: ClkType::Fixed,
                    rate_hz: 0,
                    enable_count: 0,
                    parent: u8::MAX,
                    enable_reg: 0,
                    enable_bit: 0,
                }
            }; CLK_PROVIDER_MAX_CLOCKS],
        }
    }

    /// Registers a clock with the provider.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the provider is full.
    pub fn register(&mut self, desc: ClkDescriptor) -> Result<usize> {
        if self.num_clocks >= CLK_PROVIDER_MAX_CLOCKS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.num_clocks;
        self.clocks[idx] = desc;
        self.num_clocks += 1;
        Ok(idx)
    }

    /// Enables clock `idx`, incrementing its reference count.
    pub fn enable(&mut self, idx: usize) -> Result<()> {
        self.check_idx(idx)?;
        let clk = &mut self.clocks[idx];
        if clk.clk_type == ClkType::Fixed {
            clk.enable_count += 1;
            return Ok(());
        }
        if clk.enable_count == 0 {
            // Enable parent first (recursive).
            let parent = clk.parent;
            if (parent as usize) < self.num_clocks {
                self.enable(parent as usize)?;
            }
            let clk = &self.clocks[idx];
            if clk.clk_type == ClkType::Gate {
                self.set_gate(clk.enable_reg, clk.enable_bit, true);
            }
        }
        self.clocks[idx].enable_count += 1;
        Ok(())
    }

    /// Disables clock `idx`, decrementing its reference count.
    pub fn disable(&mut self, idx: usize) -> Result<()> {
        self.check_idx(idx)?;
        if self.clocks[idx].clk_type == ClkType::Fixed {
            return Ok(());
        }
        if self.clocks[idx].enable_count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.clocks[idx].enable_count -= 1;
        if self.clocks[idx].enable_count == 0 {
            let clk_type = self.clocks[idx].clk_type;
            let enable_reg = self.clocks[idx].enable_reg;
            let enable_bit = self.clocks[idx].enable_bit;
            let parent = self.clocks[idx].parent;
            if clk_type == ClkType::Gate {
                self.set_gate(enable_reg, enable_bit, false);
            }
            if (parent as usize) < self.num_clocks {
                self.disable(parent as usize)?;
            }
        }
        Ok(())
    }

    /// Returns the rate of clock `idx` in Hz.
    pub fn rate(&self, idx: usize) -> Result<u64> {
        self.check_idx(idx)?;
        let clk = &self.clocks[idx];
        if clk.rate_hz > 0 {
            return Ok(clk.rate_hz);
        }
        // Propagate from parent.
        if (clk.parent as usize) < self.num_clocks {
            return self.rate(clk.parent as usize);
        }
        Err(Error::NotImplemented)
    }

    /// Looks up a clock by name, returning its index.
    pub fn find_by_name(&self, name: &[u8]) -> Option<usize> {
        for (i, clk) in self.clocks[..self.num_clocks].iter().enumerate() {
            let clk_name = &clk.name[..name.len().min(CLK_NAME_LEN)];
            if clk_name == name {
                return Some(i);
            }
        }
        None
    }

    /// Returns the number of registered clocks.
    pub fn num_clocks(&self) -> usize {
        self.num_clocks
    }

    // ---- private helpers ----

    fn check_idx(&self, idx: usize) -> Result<()> {
        if idx >= self.num_clocks {
            Err(Error::InvalidArgument)
        } else {
            Ok(())
        }
    }

    fn set_gate(&self, reg: u32, bit: u8, enable: bool) {
        let ptr = (self.base + reg as usize) as *mut u32;
        // SAFETY: base is a valid mapped MMIO region; volatile prevents caching.
        let val = unsafe { core::ptr::read_volatile(ptr) };
        let new_val = if enable {
            val | (1 << bit)
        } else {
            val & !(1 << bit)
        };
        // SAFETY: same guarantee as above.
        unsafe { core::ptr::write_volatile(ptr, new_val) };
    }
}

impl Default for ClkProvider {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Returns a string slice for the clock name stored in descriptor `d`.
pub fn clk_name(d: &ClkDescriptor) -> &str {
    let end = d.name.iter().position(|&b| b == 0).unwrap_or(CLK_NAME_LEN);
    core::str::from_utf8(&d.name[..end]).unwrap_or("<invalid>")
}
