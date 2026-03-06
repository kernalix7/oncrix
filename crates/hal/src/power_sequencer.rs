// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Power sequencer for controlled power-up/power-down of hardware subsystems.
//!
//! Manages ordered power rail enable/disable sequences required by complex SoCs
//! and embedded systems. Incorrect power sequencing can damage hardware or cause
//! unstable operation.
//!
//! # Power Sequence
//!
//! Power-up and power-down sequences are ordered lists of steps, each specifying:
//! - Which power rail to assert/deassert
//! - Delay to wait before the next step
//! - Optional voltage level to configure

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// Maximum steps in a power sequence.
pub const MAX_SEQUENCE_STEPS: usize = 16;

/// Maximum number of power rails.
pub const MAX_POWER_RAILS: usize = 32;

/// A single power sequencing step.
#[derive(Debug, Clone, Copy)]
pub struct PowerStep {
    /// Index of the power rail to control.
    pub rail_index: u8,
    /// Whether to enable (true) or disable (false) the rail.
    pub enable: bool,
    /// Delay in microseconds after this step before the next.
    pub delay_us: u32,
    /// Optional target voltage in millivolts (0 = don't change).
    pub target_mv: u16,
}

impl PowerStep {
    /// Creates a rail-enable step with a delay.
    pub const fn enable(rail_index: u8, delay_us: u32) -> Self {
        Self {
            rail_index,
            enable: true,
            delay_us,
            target_mv: 0,
        }
    }

    /// Creates a rail-disable step with a delay.
    pub const fn disable(rail_index: u8, delay_us: u32) -> Self {
        Self {
            rail_index,
            enable: false,
            delay_us,
            target_mv: 0,
        }
    }
}

/// A complete power sequence (ordered list of steps).
pub struct PowerSequence {
    steps: [PowerStep; MAX_SEQUENCE_STEPS],
    num_steps: usize,
}

impl PowerSequence {
    /// Creates an empty power sequence.
    pub const fn new() -> Self {
        const EMPTY: PowerStep = PowerStep {
            rail_index: 0,
            enable: false,
            delay_us: 0,
            target_mv: 0,
        };
        Self {
            steps: [EMPTY; MAX_SEQUENCE_STEPS],
            num_steps: 0,
        }
    }

    /// Appends a step to the sequence.
    pub fn add_step(&mut self, step: PowerStep) -> Result<()> {
        if self.num_steps >= MAX_SEQUENCE_STEPS {
            return Err(Error::OutOfMemory);
        }
        self.steps[self.num_steps] = step;
        self.num_steps += 1;
        Ok(())
    }

    /// Returns the steps in this sequence.
    pub fn steps(&self) -> &[PowerStep] {
        &self.steps[..self.num_steps]
    }

    /// Returns the number of steps.
    pub fn len(&self) -> usize {
        self.num_steps
    }

    /// Returns whether the sequence is empty.
    pub fn is_empty(&self) -> bool {
        self.num_steps == 0
    }
}

impl Default for PowerSequence {
    fn default() -> Self {
        Self::new()
    }
}

/// Power rail state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RailState {
    /// Rail is powered off.
    Off,
    /// Rail is ramping up.
    RampingUp,
    /// Rail is powered on and stable.
    On,
    /// Rail is ramping down.
    RampingDown,
    /// Rail is in an error state (overcurrent, undervoltage, etc.).
    Error,
}

/// A power rail descriptor.
#[derive(Debug, Clone, Copy)]
pub struct PowerRail {
    /// Rail name.
    pub name: &'static str,
    /// Nominal voltage in millivolts.
    pub nominal_mv: u16,
    /// Current state.
    pub state: RailState,
    /// GPIO or PMIC register index to control this rail.
    pub ctrl_index: u8,
}

impl PowerRail {
    /// Creates a new power rail descriptor.
    pub const fn new(name: &'static str, nominal_mv: u16, ctrl_index: u8) -> Self {
        Self {
            name,
            nominal_mv,
            state: RailState::Off,
            ctrl_index,
        }
    }
}

/// Power sequencer that drives ordered power-up/down via a callback.
pub struct PowerSequencer {
    rails: [Option<PowerRail>; MAX_POWER_RAILS],
    num_rails: usize,
}

impl PowerSequencer {
    /// Creates a new power sequencer.
    pub const fn new() -> Self {
        const NONE: Option<PowerRail> = None;
        Self {
            rails: [NONE; MAX_POWER_RAILS],
            num_rails: 0,
        }
    }

    /// Registers a power rail.
    pub fn register_rail(&mut self, rail: PowerRail) -> Result<usize> {
        if self.num_rails >= MAX_POWER_RAILS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.num_rails;
        self.rails[idx] = Some(rail);
        self.num_rails += 1;
        Ok(idx)
    }

    /// Executes a power sequence, calling the provided rail control callback for each step.
    ///
    /// # Arguments
    ///
    /// * `seq` - Sequence to execute
    /// * `ctrl` - Callback invoked for each step: `ctrl(rail, enable, target_mv) -> Result<()>`
    pub fn execute<F>(&mut self, seq: &PowerSequence, mut ctrl: F) -> Result<()>
    where
        F: FnMut(&PowerRail, bool, u16) -> Result<()>,
    {
        for step in seq.steps() {
            let rail = self
                .rails
                .get(step.rail_index as usize)
                .and_then(|r| r.as_ref())
                .ok_or(Error::NotFound)?;
            ctrl(rail, step.enable, step.target_mv)?;
            // In a real implementation, delay_us would be waited here.
            // The HAL layer provides the delay primitive.
        }
        Ok(())
    }

    /// Returns a reference to a rail by index.
    pub fn get_rail(&self, index: usize) -> Option<&PowerRail> {
        self.rails.get(index)?.as_ref()
    }

    /// Returns the number of registered rails.
    pub fn num_rails(&self) -> usize {
        self.num_rails
    }
}

impl Default for PowerSequencer {
    fn default() -> Self {
        Self::new()
    }
}
