// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PWM (Pulse Width Modulation) controller driver.
//!
//! Provides a PWM subsystem supporting multiple chips with
//! channel request/free, period/duty configuration, polarity
//! control, and enable/disable operations.
//!
//! # Architecture
//!
//! - **PwmPolarity** — normal or inversed output polarity.
//! - **PwmState** — disabled or enabled channel state.
//! - **PwmChannel** — state descriptor for a single PWM output.
//! - **PwmChip** — a PWM controller managing up to
//!   [`MAX_PWM_CHANNELS`] channels.
//! - **PwmRegistry** — manages up to [`MAX_PWM_CHIPS`]
//!   controllers.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of PWM chip controllers.
const MAX_PWM_CHIPS: usize = 4;

/// Maximum number of channels per PWM chip.
const MAX_PWM_CHANNELS: usize = 8;

// -------------------------------------------------------------------
// PwmPolarity
// -------------------------------------------------------------------

/// PWM output polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PwmPolarity {
    /// Normal polarity (duty cycle high at start of period).
    #[default]
    Normal,
    /// Inversed polarity (duty cycle low at start of period).
    Inversed,
}

// -------------------------------------------------------------------
// PwmState
// -------------------------------------------------------------------

/// PWM channel operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PwmState {
    /// Channel is disabled (no output).
    #[default]
    Disabled,
    /// Channel is enabled (generating PWM signal).
    Enabled,
}

// -------------------------------------------------------------------
// PwmChannel
// -------------------------------------------------------------------

/// State descriptor for a single PWM output channel.
pub struct PwmChannel {
    /// Channel index within the chip.
    pub index: u8,
    /// Period in nanoseconds.
    pub period_ns: u64,
    /// Duty cycle in nanoseconds (must not exceed `period_ns`).
    pub duty_ns: u64,
    /// Output polarity.
    pub polarity: PwmPolarity,
    /// Operational state.
    pub state: PwmState,
    /// Human-readable label (UTF-8, not NUL-terminated).
    pub label: [u8; 32],
    /// Number of valid bytes in [`label`](Self::label).
    pub label_len: usize,
    /// Whether this channel has been requested by a consumer.
    pub requested: bool,
}

/// Constant empty channel for array initialisation.
const EMPTY_CHANNEL: PwmChannel = PwmChannel {
    index: 0,
    period_ns: 0,
    duty_ns: 0,
    polarity: PwmPolarity::Normal,
    state: PwmState::Disabled,
    label: [0u8; 32],
    label_len: 0,
    requested: false,
};

// -------------------------------------------------------------------
// PwmChip
// -------------------------------------------------------------------

/// A PWM chip controller.
///
/// Manages up to [`MAX_PWM_CHANNELS`] PWM output channels and
/// provides request/free, period/duty configuration, polarity
/// control, and enable/disable operations.
pub struct PwmChip {
    /// Chip identifier.
    id: u8,
    /// Base address for memory-mapped I/O registers.
    mmio_base: u64,
    /// Channel state descriptors.
    channels: [PwmChannel; MAX_PWM_CHANNELS],
    /// Number of PWM channels provided by this chip.
    npwm: u8,
    /// Whether this chip is active (initialised).
    active: bool,
    /// Human-readable chip label (UTF-8, not NUL-terminated).
    label: [u8; 32],
    /// Number of valid bytes in [`label`](Self::label).
    label_len: usize,
}

impl PwmChip {
    /// Creates a new PWM chip with the given identifier, MMIO
    /// base address, and channel count.
    ///
    /// The channel count is clamped to [`MAX_PWM_CHANNELS`].
    pub fn new(id: u8, mmio_base: u64, npwm: u8) -> Self {
        let count = (npwm as usize).min(MAX_PWM_CHANNELS);
        let mut channels = [EMPTY_CHANNEL; MAX_PWM_CHANNELS];
        let mut i = 0;
        while i < count {
            channels[i].index = i as u8;
            i += 1;
        }
        Self {
            id,
            mmio_base,
            channels,
            npwm: count as u8,
            active: true,
            label: [0u8; 32],
            label_len: 0,
        }
    }

    /// Validates that `ch` is within this chip's range and
    /// returns the index into the `channels` array.
    fn channel_index(&self, ch: u8) -> Result<usize> {
        let idx = ch as usize;
        if idx >= self.npwm as usize {
            return Err(Error::InvalidArgument);
        }
        Ok(idx)
    }

    /// Requests a PWM channel for use with the given label.
    ///
    /// Returns [`Error::InvalidArgument`] when `ch` is out of
    /// range or `label` is empty, and [`Error::Busy`] when the
    /// channel is already requested.
    pub fn request(&mut self, ch: u8, label: &[u8]) -> Result<()> {
        if label.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let idx = self.channel_index(ch)?;
        if self.channels[idx].requested {
            return Err(Error::Busy);
        }
        let copy_len = label.len().min(32);
        let mut ch_label = [0u8; 32];
        ch_label[..copy_len].copy_from_slice(&label[..copy_len]);
        self.channels[idx].requested = true;
        self.channels[idx].label = ch_label;
        self.channels[idx].label_len = copy_len;
        Ok(())
    }

    /// Releases a previously requested PWM channel.
    ///
    /// Resets the channel to its default state: disabled, normal
    /// polarity, zero period and duty cycle.
    ///
    /// Returns [`Error::InvalidArgument`] when `ch` is out of
    /// range, and [`Error::NotFound`] when the channel is not
    /// currently requested.
    pub fn free(&mut self, ch: u8) -> Result<()> {
        let idx = self.channel_index(ch)?;
        if !self.channels[idx].requested {
            return Err(Error::NotFound);
        }
        self.channels[idx].requested = false;
        self.channels[idx].period_ns = 0;
        self.channels[idx].duty_ns = 0;
        self.channels[idx].polarity = PwmPolarity::Normal;
        self.channels[idx].state = PwmState::Disabled;
        self.channels[idx].label = [0u8; 32];
        self.channels[idx].label_len = 0;
        Ok(())
    }

    /// Configures the period and duty cycle of a requested
    /// PWM channel.
    ///
    /// `duty_ns` must not exceed `period_ns`.
    ///
    /// Returns [`Error::InvalidArgument`] when `ch` is out of
    /// range or `duty_ns > period_ns`, and [`Error::NotFound`]
    /// when the channel is not currently requested.
    pub fn config(&mut self, ch: u8, period_ns: u64, duty_ns: u64) -> Result<()> {
        if duty_ns > period_ns {
            return Err(Error::InvalidArgument);
        }
        let idx = self.channel_index(ch)?;
        if !self.channels[idx].requested {
            return Err(Error::NotFound);
        }
        self.channels[idx].period_ns = period_ns;
        self.channels[idx].duty_ns = duty_ns;
        Ok(())
    }

    /// Sets the output polarity of a requested PWM channel.
    ///
    /// Returns [`Error::InvalidArgument`] when `ch` is out of
    /// range, and [`Error::NotFound`] when the channel is not
    /// currently requested.
    pub fn set_polarity(&mut self, ch: u8, pol: PwmPolarity) -> Result<()> {
        let idx = self.channel_index(ch)?;
        if !self.channels[idx].requested {
            return Err(Error::NotFound);
        }
        self.channels[idx].polarity = pol;
        Ok(())
    }

    /// Enables a requested PWM channel, starting signal output.
    ///
    /// Returns [`Error::InvalidArgument`] when `ch` is out of
    /// range, and [`Error::NotFound`] when the channel is not
    /// currently requested.
    pub fn enable(&mut self, ch: u8) -> Result<()> {
        let idx = self.channel_index(ch)?;
        if !self.channels[idx].requested {
            return Err(Error::NotFound);
        }
        self.channels[idx].state = PwmState::Enabled;
        Ok(())
    }

    /// Disables a requested PWM channel, stopping signal output.
    ///
    /// Returns [`Error::InvalidArgument`] when `ch` is out of
    /// range, and [`Error::NotFound`] when the channel is not
    /// currently requested.
    pub fn disable(&mut self, ch: u8) -> Result<()> {
        let idx = self.channel_index(ch)?;
        if !self.channels[idx].requested {
            return Err(Error::NotFound);
        }
        self.channels[idx].state = PwmState::Disabled;
        Ok(())
    }

    /// Returns the current state of a requested PWM channel as
    /// a tuple of (period_ns, duty_ns, polarity, state).
    ///
    /// Returns [`Error::InvalidArgument`] when `ch` is out of
    /// range, and [`Error::NotFound`] when the channel is not
    /// currently requested.
    pub fn get_state(&self, ch: u8) -> Result<(u64, u64, PwmPolarity, PwmState)> {
        let idx = self.channel_index(ch)?;
        if !self.channels[idx].requested {
            return Err(Error::NotFound);
        }
        Ok((
            self.channels[idx].period_ns,
            self.channels[idx].duty_ns,
            self.channels[idx].polarity,
            self.channels[idx].state,
        ))
    }

    /// Returns the duty cycle as a percentage (0–100) for a
    /// requested PWM channel.
    ///
    /// Returns [`Error::InvalidArgument`] when `ch` is out of
    /// range or the period is zero, and [`Error::NotFound`] when
    /// the channel is not currently requested.
    pub fn duty_percent(&self, ch: u8) -> Result<u64> {
        let idx = self.channel_index(ch)?;
        if !self.channels[idx].requested {
            return Err(Error::NotFound);
        }
        let period = self.channels[idx].period_ns;
        if period == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(self.channels[idx].duty_ns * 100 / period)
    }

    /// Returns the MMIO base address of this controller.
    pub fn mmio_base(&self) -> u64 {
        self.mmio_base
    }

    /// Returns the chip label as a byte slice.
    pub fn label(&self) -> &[u8] {
        &self.label[..self.label_len]
    }

    /// Returns whether this chip is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the number of PWM channels provided by this chip.
    pub fn channel_count(&self) -> u8 {
        self.npwm
    }
}

// -------------------------------------------------------------------
// PwmRegistry
// -------------------------------------------------------------------

/// Registry of PWM chip controllers.
///
/// Manages up to [`MAX_PWM_CHIPS`] chip instances, providing
/// registration and lookup operations.
pub struct PwmRegistry {
    /// Registered chip controllers.
    chips: [Option<PwmChip>; MAX_PWM_CHIPS],
    /// Number of registered chips.
    count: usize,
}

impl Default for PwmRegistry {
    fn default() -> Self {
        const NONE: Option<PwmChip> = None;
        Self {
            chips: [NONE; MAX_PWM_CHIPS],
            count: 0,
        }
    }
}

impl PwmRegistry {
    /// Registers a chip in the first available slot.
    ///
    /// Returns [`Error::OutOfMemory`] when the registry is full
    /// or [`Error::AlreadyExists`] when a chip with the same id
    /// is already registered.
    pub fn register(&mut self, chip: PwmChip) -> Result<()> {
        for c in self.chips.iter().flatten() {
            if c.id == chip.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.chips {
            if slot.is_none() {
                *slot = Some(chip);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns an immutable reference to the chip with `id`.
    pub fn get(&self, id: u8) -> Result<&PwmChip> {
        for c in self.chips.iter().flatten() {
            if c.id == id {
                return Ok(c);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to the chip with `id`.
    pub fn get_mut(&mut self, id: u8) -> Result<&mut PwmChip> {
        for c in self.chips.iter_mut().flatten() {
            if c.id == id {
                return Ok(c);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered chips.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` when no chips are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
