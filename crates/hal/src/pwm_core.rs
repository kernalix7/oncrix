// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Pulse Width Modulation (PWM) core HAL abstraction.
//!
//! Provides a hardware-independent PWM interface for configuring duty cycle,
//! period, and polarity on PWM channels. Used by motor controllers, LED dimmers,
//! fan controllers, and audio DACs.
//!
//! # PWM Signal Parameters
//!
//! - **Period**: Total time for one on+off cycle (in nanoseconds)
//! - **Duty cycle**: Fraction of the period where the signal is active
//! - **Polarity**: Whether the active state is high or low
//!
//! # Formula
//!
//! duty_ns = period_ns * duty_percent / 100

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// PWM signal polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PwmPolarity {
    /// Normal polarity: signal is high during active phase.
    Normal,
    /// Inversed polarity: signal is low during active phase.
    Inversed,
}

/// PWM channel configuration.
#[derive(Debug, Clone, Copy)]
pub struct PwmConfig {
    /// Total period in nanoseconds.
    pub period_ns: u64,
    /// Active (duty) time in nanoseconds. Must be <= period_ns.
    pub duty_ns: u64,
    /// Signal polarity.
    pub polarity: PwmPolarity,
    /// Whether the PWM output is enabled.
    pub enabled: bool,
}

impl PwmConfig {
    /// Creates a PWM configuration from a period and duty cycle percentage (0–100).
    pub fn from_percent(period_ns: u64, duty_percent: u8) -> Result<Self> {
        if duty_percent > 100 {
            return Err(Error::InvalidArgument);
        }
        let duty_ns = period_ns * duty_percent as u64 / 100;
        Ok(Self {
            period_ns,
            duty_ns,
            polarity: PwmPolarity::Normal,
            enabled: false,
        })
    }

    /// Returns the duty cycle as a percentage (0–100), rounded.
    pub fn duty_percent(&self) -> u8 {
        if self.period_ns == 0 {
            return 0;
        }
        (self.duty_ns * 100 / self.period_ns).min(100) as u8
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.period_ns == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.duty_ns > self.period_ns {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for PwmConfig {
    fn default() -> Self {
        Self {
            period_ns: 1_000_000, // 1 ms = 1 kHz
            duty_ns: 500_000,     // 50% duty
            polarity: PwmPolarity::Normal,
            enabled: false,
        }
    }
}

/// Trait for hardware-specific PWM channel implementations.
pub trait PwmChannelOps {
    /// Applies a new configuration to the PWM channel.
    fn configure(&mut self, config: &PwmConfig) -> Result<()>;

    /// Enables the PWM output.
    fn enable(&mut self) -> Result<()>;

    /// Disables the PWM output.
    fn disable(&mut self) -> Result<()>;

    /// Reads back the current hardware configuration.
    fn get_config(&self) -> PwmConfig;

    /// Sets just the duty cycle without changing the period.
    fn set_duty(&mut self, duty_ns: u64) -> Result<()> {
        let mut cfg = self.get_config();
        cfg.duty_ns = duty_ns;
        cfg.validate()?;
        self.configure(&cfg)
    }

    /// Sets the duty cycle as a percentage.
    fn set_duty_percent(&mut self, percent: u8) -> Result<()> {
        let cfg = self.get_config();
        let duty_ns = cfg.period_ns * percent as u64 / 100;
        self.set_duty(duty_ns)
    }
}

/// Software PWM state machine (for GPIO-based bit-banged PWM).
#[derive(Debug, Clone, Copy)]
pub struct SoftPwmState {
    /// Period in timer ticks.
    pub period_ticks: u32,
    /// Active-high ticks within the period.
    pub duty_ticks: u32,
    /// Current tick counter within the period.
    pub tick: u32,
    /// Current output level.
    pub output: bool,
    /// Polarity.
    pub polarity: PwmPolarity,
}

impl SoftPwmState {
    /// Creates a new software PWM state.
    pub const fn new(period_ticks: u32, duty_ticks: u32) -> Self {
        Self {
            period_ticks,
            duty_ticks,
            tick: 0,
            output: false,
            polarity: PwmPolarity::Normal,
        }
    }

    /// Advances the state by one tick. Returns the new output level.
    pub fn tick(&mut self) -> bool {
        let active = self.tick < self.duty_ticks;
        self.output = match self.polarity {
            PwmPolarity::Normal => active,
            PwmPolarity::Inversed => !active,
        };
        self.tick += 1;
        if self.tick >= self.period_ticks {
            self.tick = 0;
        }
        self.output
    }

    /// Returns the current output level without advancing.
    pub fn current_output(&self) -> bool {
        self.output
    }

    /// Resets the phase counter.
    pub fn reset(&mut self) {
        self.tick = 0;
        self.output = false;
    }
}

impl Default for SoftPwmState {
    fn default() -> Self {
        Self::new(1000, 500)
    }
}

/// A registry of PWM channels.
pub struct PwmRegistry {
    configs: [PwmConfig; 8],
    count: usize,
}

impl PwmRegistry {
    /// Creates an empty PWM registry.
    pub const fn new() -> Self {
        Self {
            configs: [PwmConfig {
                period_ns: 0,
                duty_ns: 0,
                polarity: PwmPolarity::Normal,
                enabled: false,
            }; 8],
            count: 0,
        }
    }

    /// Registers a new PWM channel configuration.
    pub fn register(&mut self, config: PwmConfig) -> Result<usize> {
        if self.count >= 8 {
            return Err(Error::OutOfMemory);
        }
        config.validate()?;
        let idx = self.count;
        self.configs[idx] = config;
        self.count += 1;
        Ok(idx)
    }

    /// Returns the configuration for a channel.
    pub fn get(&self, index: usize) -> Option<&PwmConfig> {
        if index < self.count {
            Some(&self.configs[index])
        } else {
            None
        }
    }

    /// Returns the number of registered channels.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns whether the registry has no channels.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for PwmRegistry {
    fn default() -> Self {
        Self::new()
    }
}
