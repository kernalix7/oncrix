// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PWM hardware abstraction layer.
//!
//! Provides register-level abstraction for Pulse Width Modulation
//! (PWM) controllers. This module manages the chip-level MMIO
//! register mappings and exposes a typed interface for configuring
//! duty cycle, period, polarity, and enable/disable for individual
//! PWM channels.
//!
//! # Features
//!
//! - **Multi-chip support** -- up to 8 PWM controllers tracked.
//! - **Per-channel configuration** -- duty cycle, period, polarity
//!   per channel (up to 8 channels per chip).
//! - **Register-level abstraction** -- maps MMIO registers for
//!   period, duty, control, and status.
//! - **State machine** -- tracks chip and channel initialization,
//!   running, and disabled states.
//! - **Duty cycle calculation** -- compute duty percentage from
//!   raw period/duty values.
//!
//! # Architecture
//!
//! - [`PwmPolarity`] -- normal or inversed output polarity
//! - [`PwmConfig`] -- period + duty + polarity configuration
//! - [`PwmState`] -- per-channel runtime state
//! - [`PwmChannel`] -- single PWM output channel
//! - [`PwmChip`] -- PWM controller with multiple channels
//! - [`PwmStats`] -- aggregate statistics
//! - [`PwmHwManager`] -- the PWM manager
//!
//! Reference: Linux `drivers/pwm/core.c`,
//! `include/linux/pwm.h`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Maximum number of PWM chips.
const MAX_CHIPS: usize = 8;

/// Maximum number of channels per chip.
const MAX_CHANNELS_PER_CHIP: usize = 8;

/// Minimum period in nanoseconds (1 microsecond).
const MIN_PERIOD_NS: u64 = 1000;

/// Maximum period in nanoseconds (1 second).
const MAX_PERIOD_NS: u64 = 1_000_000_000;

// ── Register offsets ────────────────────────────────────────────

/// Register offset: channel control (enable, polarity).
const REG_CTRL: u32 = 0x00;

/// Register offset: period value.
const REG_PERIOD: u32 = 0x04;

/// Register offset: duty cycle value.
const REG_DUTY: u32 = 0x08;

/// Register offset: status (running, fault).
const REG_STATUS: u32 = 0x0C;

/// Stride between channels in register space.
const CHANNEL_STRIDE: u32 = 0x10;

// ── Control register bits ───────────────────────────────────────

/// Channel enable bit.
const CTRL_ENABLE: u32 = 1 << 0;

/// Polarity invert bit.
const CTRL_POLARITY_INV: u32 = 1 << 1;

/// Output active bit (read-only in status).
const STATUS_RUNNING: u32 = 1 << 0;

/// Fault detected bit (read-only in status).
const _STATUS_FAULT: u32 = 1 << 1;

// ── PwmPolarity ─────────────────────────────────────────────────

/// PWM output polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PwmPolarity {
    /// Normal polarity: high during duty portion.
    Normal,
    /// Inversed polarity: low during duty portion.
    Inversed,
}

impl Default for PwmPolarity {
    fn default() -> Self {
        Self::Normal
    }
}

// ── PwmConfig ───────────────────────────────────────────────────

/// PWM channel configuration.
///
/// Describes the desired period, duty cycle, and polarity for a
/// PWM output channel.
#[derive(Debug, Clone, Copy)]
pub struct PwmConfig {
    /// Period in nanoseconds.
    pub period_ns: u64,
    /// Duty cycle in nanoseconds (must be <= period_ns).
    pub duty_ns: u64,
    /// Output polarity.
    pub polarity: PwmPolarity,
}

impl Default for PwmConfig {
    fn default() -> Self {
        Self {
            period_ns: 1_000_000, // 1 ms
            duty_ns: 500_000,     // 50%
            polarity: PwmPolarity::Normal,
        }
    }
}

impl PwmConfig {
    /// Create a new configuration with validation.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if duty > period or period
    ///   is out of bounds.
    pub fn new(period_ns: u64, duty_ns: u64, polarity: PwmPolarity) -> Result<Self> {
        if period_ns < MIN_PERIOD_NS || period_ns > MAX_PERIOD_NS {
            return Err(Error::InvalidArgument);
        }
        if duty_ns > period_ns {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            period_ns,
            duty_ns,
            polarity,
        })
    }

    /// Compute duty cycle as a percentage (0..100).
    pub fn duty_percent(&self) -> u32 {
        if self.period_ns == 0 {
            return 0;
        }
        ((self.duty_ns * 100) / self.period_ns) as u32
    }

    /// Compute duty cycle as permille (0..1000).
    pub fn duty_permille(&self) -> u32 {
        if self.period_ns == 0 {
            return 0;
        }
        ((self.duty_ns * 1000) / self.period_ns) as u32
    }
}

// ── PwmState ────────────────────────────────────────────────────

/// Runtime state of a PWM channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PwmState {
    /// Channel is not initialized.
    Uninitialized,
    /// Channel is initialized but not running.
    Disabled,
    /// Channel is actively generating output.
    Running,
    /// Channel encountered a hardware fault.
    Fault,
}

impl Default for PwmState {
    fn default() -> Self {
        Self::Uninitialized
    }
}

// ── PwmChannel ──────────────────────────────────────────────────

/// A single PWM output channel.
///
/// Represents one hardware PWM output with its configuration,
/// state, and register base.
#[derive(Debug, Clone, Copy)]
pub struct PwmChannel {
    /// Channel index within the chip (0-based).
    pub index: u32,
    /// Current configuration.
    pub config: PwmConfig,
    /// Current runtime state.
    pub state: PwmState,
    /// Register base for this channel (chip base + offset).
    pub reg_base: u64,
    /// Whether this channel is in use.
    pub active: bool,
    /// Number of configuration changes applied.
    pub config_count: u64,
    /// Label / name for this channel's consumer.
    label: [u8; 32],
    /// Length of the label.
    label_len: usize,
}

impl PwmChannel {
    /// Create an empty, inactive channel.
    const fn empty() -> Self {
        Self {
            index: 0,
            config: PwmConfig {
                period_ns: 0,
                duty_ns: 0,
                polarity: PwmPolarity::Normal,
            },
            state: PwmState::Uninitialized,
            reg_base: 0,
            active: false,
            config_count: 0,
            label: [0u8; 32],
            label_len: 0,
        }
    }

    /// Whether this channel is currently generating output.
    pub const fn is_running(&self) -> bool {
        matches!(self.state, PwmState::Running)
    }

    /// Get the channel's consumer label.
    pub fn label(&self) -> &[u8] {
        &self.label[..self.label_len]
    }

    /// Compute the control register value for this channel.
    fn control_reg_value(&self) -> u32 {
        let mut ctrl = 0u32;
        if self.state == PwmState::Running {
            ctrl |= CTRL_ENABLE;
        }
        if self.config.polarity == PwmPolarity::Inversed {
            ctrl |= CTRL_POLARITY_INV;
        }
        ctrl
    }
}

// ── PwmChip ─────────────────────────────────────────────────────

/// A PWM controller chip with multiple output channels.
///
/// Represents a hardware PWM controller mapped at a specific MMIO
/// base address. Each chip can have up to [`MAX_CHANNELS_PER_CHIP`]
/// channels.
#[derive(Debug)]
pub struct PwmChip {
    /// Chip identifier.
    pub id: u32,
    /// MMIO base address for this chip's registers.
    pub base_addr: u64,
    /// Number of channels on this chip.
    pub num_channels: u32,
    /// Channel array.
    pub channels: [PwmChannel; MAX_CHANNELS_PER_CHIP],
    /// Whether the chip is initialized and active.
    pub active: bool,
    /// Chip name.
    name: [u8; 32],
    /// Name length.
    name_len: usize,
}

impl PwmChip {
    /// Create an empty, inactive chip.
    const fn empty() -> Self {
        Self {
            id: 0,
            base_addr: 0,
            num_channels: 0,
            channels: [const { PwmChannel::empty() }; MAX_CHANNELS_PER_CHIP],
            active: false,
            name: [0u8; 32],
            name_len: 0,
        }
    }

    /// Initialize the chip and its channels.
    fn init(&mut self, id: u32, base_addr: u64, num_channels: u32, name: &[u8]) {
        self.id = id;
        self.base_addr = base_addr;
        self.num_channels = num_channels.min(MAX_CHANNELS_PER_CHIP as u32);
        self.active = true;

        let copy_len = name.len().min(32);
        self.name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.name_len = copy_len;

        // Initialize channels.
        for i in 0..self.num_channels as usize {
            let offset = (i as u32) * CHANNEL_STRIDE;
            self.channels[i] = PwmChannel {
                index: i as u32,
                config: PwmConfig::default(),
                state: PwmState::Disabled,
                reg_base: base_addr + u64::from(offset),
                active: true,
                config_count: 0,
                label: [0u8; 32],
                label_len: 0,
            };
        }
    }

    /// Register offset for a channel's control register.
    pub const fn channel_ctrl_offset(&self, channel: u32) -> u32 {
        channel * CHANNEL_STRIDE + REG_CTRL
    }

    /// Register offset for a channel's period register.
    pub const fn channel_period_offset(&self, channel: u32) -> u32 {
        channel * CHANNEL_STRIDE + REG_PERIOD
    }

    /// Register offset for a channel's duty register.
    pub const fn channel_duty_offset(&self, channel: u32) -> u32 {
        channel * CHANNEL_STRIDE + REG_DUTY
    }

    /// Register offset for a channel's status register.
    pub const fn channel_status_offset(&self, channel: u32) -> u32 {
        channel * CHANNEL_STRIDE + REG_STATUS
    }

    /// Get the chip name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ── PwmStats ────────────────────────────────────────────────────

/// Aggregate PWM statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PwmStats {
    /// Total chips registered.
    pub chips_registered: u32,
    /// Total channels available.
    pub total_channels: u32,
    /// Channels currently running.
    pub running_channels: u32,
    /// Total configuration changes.
    pub config_changes: u64,
    /// Total enable operations.
    pub enable_ops: u64,
    /// Total disable operations.
    pub disable_ops: u64,
    /// Total faults detected.
    pub faults: u64,
}

// ── PwmHwManager ────────────────────────────────────────────────

/// The PWM hardware manager.
///
/// Manages multiple PWM controller chips, providing
/// configuration, enable/disable, and status query operations
/// for individual channels.
pub struct PwmHwManager {
    /// Registered PWM chips.
    chips: [PwmChip; MAX_CHIPS],
    /// Number of active chips.
    chip_count: usize,
    /// Statistics.
    stats: PwmStats,
}

impl Default for PwmHwManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PwmHwManager {
    /// Creates a new, empty PWM manager.
    pub const fn new() -> Self {
        Self {
            chips: [const { PwmChip::empty() }; MAX_CHIPS],
            chip_count: 0,
            stats: PwmStats {
                chips_registered: 0,
                total_channels: 0,
                running_channels: 0,
                config_changes: 0,
                enable_ops: 0,
                disable_ops: 0,
                faults: 0,
            },
        }
    }

    // ── Chip management ─────────────────────────────────────────

    /// Register a new PWM chip.
    ///
    /// # Arguments
    ///
    /// - `id` -- chip identifier.
    /// - `base_addr` -- MMIO base address.
    /// - `num_channels` -- number of PWM channels on this chip.
    /// - `name` -- chip name (truncated to 32 bytes).
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if chip table is full.
    /// - [`Error::AlreadyExists`] if a chip with this ID exists.
    /// - [`Error::InvalidArgument`] if `num_channels` is zero.
    pub fn register_chip(
        &mut self,
        id: u32,
        base_addr: u64,
        num_channels: u32,
        name: &[u8],
    ) -> Result<()> {
        if num_channels == 0 {
            return Err(Error::InvalidArgument);
        }

        if self.chips.iter().any(|c| c.active && c.id == id) {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .chips
            .iter_mut()
            .find(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;

        slot.init(id, base_addr, num_channels, name);
        self.chip_count += 1;
        self.stats.chips_registered += 1;
        self.stats.total_channels += num_channels.min(MAX_CHANNELS_PER_CHIP as u32);
        Ok(())
    }

    /// Unregister a PWM chip by ID.
    ///
    /// All channels are disabled before removal.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no chip with this ID exists.
    pub fn unregister_chip(&mut self, id: u32) -> Result<()> {
        let idx = self
            .chips
            .iter()
            .position(|c| c.active && c.id == id)
            .ok_or(Error::NotFound)?;

        // Disable all running channels.
        let num_ch = self.chips[idx].num_channels as usize;
        for i in 0..num_ch {
            if self.chips[idx].channels[i].state == PwmState::Running {
                self.stats.running_channels = self.stats.running_channels.saturating_sub(1);
            }
            self.chips[idx].channels[i].state = PwmState::Disabled;
            self.chips[idx].channels[i].active = false;
        }

        self.stats.total_channels = self.stats.total_channels.saturating_sub(num_ch as u32);
        self.chips[idx].active = false;
        self.chip_count = self.chip_count.saturating_sub(1);
        Ok(())
    }

    // ── Channel configuration ───────────────────────────────────

    /// Apply a configuration to a channel.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if chip or channel not found.
    /// - [`Error::InvalidArgument`] if config is invalid.
    pub fn configure(&mut self, chip_id: u32, channel: u32, config: PwmConfig) -> Result<()> {
        let chip = self.find_chip_mut(chip_id)?;

        if channel >= chip.num_channels {
            return Err(Error::InvalidArgument);
        }

        let ch = &mut chip.channels[channel as usize];
        if !ch.active {
            return Err(Error::NotFound);
        }

        // Validate config.
        if config.duty_ns > config.period_ns {
            return Err(Error::InvalidArgument);
        }
        if config.period_ns < MIN_PERIOD_NS || config.period_ns > MAX_PERIOD_NS {
            return Err(Error::InvalidArgument);
        }

        ch.config = config;
        ch.config_count += 1;
        self.stats.config_changes += 1;

        Ok(())
    }

    /// Enable a PWM channel (start generating output).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if chip or channel not found.
    /// - [`Error::InvalidArgument`] if channel has zero period.
    pub fn enable(&mut self, chip_id: u32, channel: u32) -> Result<()> {
        let chip = self.find_chip_mut(chip_id)?;

        if channel >= chip.num_channels {
            return Err(Error::InvalidArgument);
        }

        let ch = &mut chip.channels[channel as usize];
        if !ch.active {
            return Err(Error::NotFound);
        }

        if ch.config.period_ns == 0 {
            return Err(Error::InvalidArgument);
        }

        if ch.state != PwmState::Running {
            ch.state = PwmState::Running;
            self.stats.running_channels += 1;
        }
        self.stats.enable_ops += 1;

        Ok(())
    }

    /// Disable a PWM channel (stop generating output).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if chip or channel not found.
    pub fn disable(&mut self, chip_id: u32, channel: u32) -> Result<()> {
        let ci = self
            .chips
            .iter()
            .position(|c| c.active && c.id == chip_id)
            .ok_or(Error::NotFound)?;

        if channel >= self.chips[ci].num_channels {
            return Err(Error::InvalidArgument);
        }

        let ch_idx = channel as usize;
        if !self.chips[ci].channels[ch_idx].active {
            return Err(Error::NotFound);
        }

        if self.chips[ci].channels[ch_idx].state == PwmState::Running {
            self.stats.running_channels = self.stats.running_channels.saturating_sub(1);
        }
        self.chips[ci].channels[ch_idx].state = PwmState::Disabled;
        self.stats.disable_ops += 1;

        Ok(())
    }

    /// Set a consumer label on a channel.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if chip or channel not found.
    pub fn set_label(&mut self, chip_id: u32, channel: u32, label: &[u8]) -> Result<()> {
        let chip = self.find_chip_mut(chip_id)?;

        if channel >= chip.num_channels {
            return Err(Error::InvalidArgument);
        }

        let ch = &mut chip.channels[channel as usize];
        if !ch.active {
            return Err(Error::NotFound);
        }

        let copy_len = label.len().min(32);
        ch.label[..copy_len].copy_from_slice(&label[..copy_len]);
        ch.label_len = copy_len;

        Ok(())
    }

    // ── Query ───────────────────────────────────────────────────

    /// Get the current state of a channel.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if chip or channel not found.
    pub fn channel_state(&self, chip_id: u32, channel: u32) -> Result<PwmState> {
        let chip = self.find_chip(chip_id)?;
        if channel >= chip.num_channels {
            return Err(Error::InvalidArgument);
        }
        let ch = &chip.channels[channel as usize];
        if !ch.active {
            return Err(Error::NotFound);
        }
        Ok(ch.state)
    }

    /// Get the current configuration of a channel.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if chip or channel not found.
    pub fn channel_config(&self, chip_id: u32, channel: u32) -> Result<PwmConfig> {
        let chip = self.find_chip(chip_id)?;
        if channel >= chip.num_channels {
            return Err(Error::InvalidArgument);
        }
        let ch = &chip.channels[channel as usize];
        if !ch.active {
            return Err(Error::NotFound);
        }
        Ok(ch.config)
    }

    /// Get the duty cycle percentage for a channel.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if chip or channel not found.
    pub fn duty_percent(&self, chip_id: u32, channel: u32) -> Result<u32> {
        let config = self.channel_config(chip_id, channel)?;
        Ok(config.duty_percent())
    }

    /// Compute the expected register values for a channel.
    ///
    /// Returns `(ctrl, period, duty, status)` register values.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if chip or channel not found.
    pub fn expected_registers(&self, chip_id: u32, channel: u32) -> Result<(u32, u64, u64, u32)> {
        let chip = self.find_chip(chip_id)?;
        if channel >= chip.num_channels {
            return Err(Error::InvalidArgument);
        }
        let ch = &chip.channels[channel as usize];
        if !ch.active {
            return Err(Error::NotFound);
        }

        let ctrl = ch.control_reg_value();
        let period = ch.config.period_ns;
        let duty = ch.config.duty_ns;
        let status = if ch.state == PwmState::Running {
            STATUS_RUNNING
        } else {
            0
        };

        Ok((ctrl, period, duty, status))
    }

    // ── Accessors ───────────────────────────────────────────────

    /// Returns aggregate statistics.
    pub fn stats(&self) -> &PwmStats {
        &self.stats
    }

    /// Number of active chips.
    pub fn chip_count(&self) -> usize {
        self.chip_count
    }

    // ── Internal helpers ────────────────────────────────────────

    fn find_chip(&self, id: u32) -> Result<&PwmChip> {
        self.chips
            .iter()
            .find(|c| c.active && c.id == id)
            .ok_or(Error::NotFound)
    }

    fn find_chip_mut(&mut self, id: u32) -> Result<&mut PwmChip> {
        self.chips
            .iter_mut()
            .find(|c| c.active && c.id == id)
            .ok_or(Error::NotFound)
    }
}
