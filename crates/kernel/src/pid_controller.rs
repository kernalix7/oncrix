// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PID controller (proportional-integral-derivative).
//!
//! Implements a general-purpose PID controller used by kernel
//! subsystems for feedback-based control loops. Applications
//! include CPU frequency governor tuning, memory pressure
//! management, I/O bandwidth throttling, and thermal control.
//! Supports configurable gains, integral windup prevention,
//! and output clamping.

use oncrix_lib::{Error, Result};

/// Maximum number of PID controller instances.
const MAX_CONTROLLERS: usize = 64;

/// Maximum number of samples in history.
const MAX_HISTORY: usize = 64;

/// PID controller gains (scaled by 1000 for fixed-point).
#[derive(Clone, Copy)]
pub struct PidGains {
    /// Proportional gain (Kp * 1000).
    kp: i64,
    /// Integral gain (Ki * 1000).
    ki: i64,
    /// Derivative gain (Kd * 1000).
    kd: i64,
}

impl PidGains {
    /// Creates new PID gains.
    pub const fn new(kp: i64, ki: i64, kd: i64) -> Self {
        Self { kp, ki, kd }
    }

    /// Returns the proportional gain.
    pub const fn kp(&self) -> i64 {
        self.kp
    }

    /// Returns the integral gain.
    pub const fn ki(&self) -> i64 {
        self.ki
    }

    /// Returns the derivative gain.
    pub const fn kd(&self) -> i64 {
        self.kd
    }
}

impl Default for PidGains {
    fn default() -> Self {
        Self::new(1000, 100, 50)
    }
}

/// Output limits for the PID controller.
#[derive(Clone, Copy)]
pub struct OutputLimits {
    /// Minimum output value.
    min: i64,
    /// Maximum output value.
    max: i64,
    /// Integral windup limit.
    integral_max: i64,
}

impl OutputLimits {
    /// Creates new output limits.
    pub const fn new(min: i64, max: i64, integral_max: i64) -> Self {
        Self {
            min,
            max,
            integral_max,
        }
    }

    /// Returns the minimum output.
    pub const fn min(&self) -> i64 {
        self.min
    }

    /// Returns the maximum output.
    pub const fn max(&self) -> i64 {
        self.max
    }

    /// Clamps a value to the output range.
    pub const fn clamp(&self, value: i64) -> i64 {
        if value < self.min {
            self.min
        } else if value > self.max {
            self.max
        } else {
            value
        }
    }
}

impl Default for OutputLimits {
    fn default() -> Self {
        Self::new(i64::MIN / 2, i64::MAX / 2, 100_000)
    }
}

/// Historical sample for the PID controller.
#[derive(Clone, Copy)]
pub struct PidSample {
    /// Measured process variable.
    measurement: i64,
    /// Setpoint at this sample.
    setpoint: i64,
    /// Computed error.
    error: i64,
    /// Controller output.
    output: i64,
    /// Timestamp in nanoseconds.
    timestamp_ns: u64,
}

impl PidSample {
    /// Creates a new empty sample.
    pub const fn new() -> Self {
        Self {
            measurement: 0,
            setpoint: 0,
            error: 0,
            output: 0,
            timestamp_ns: 0,
        }
    }

    /// Returns the error value.
    pub const fn error(&self) -> i64 {
        self.error
    }

    /// Returns the output value.
    pub const fn output(&self) -> i64 {
        self.output
    }

    /// Returns the timestamp.
    pub const fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }
}

impl Default for PidSample {
    fn default() -> Self {
        Self::new()
    }
}

/// A PID controller instance.
#[derive(Clone, Copy)]
pub struct PidController {
    /// Controller identifier.
    id: u32,
    /// PID gains.
    gains: PidGains,
    /// Output limits.
    limits: OutputLimits,
    /// Current setpoint.
    setpoint: i64,
    /// Accumulated integral term.
    integral: i64,
    /// Previous error (for derivative).
    prev_error: i64,
    /// Previous output.
    prev_output: i64,
    /// Number of updates performed.
    update_count: u64,
    /// Whether the controller is active.
    active: bool,
    /// History buffer.
    history: [PidSample; MAX_HISTORY],
    /// Number of history entries.
    history_count: usize,
}

impl PidController {
    /// Creates a new PID controller.
    pub const fn new() -> Self {
        Self {
            id: 0,
            gains: PidGains::new(1000, 100, 50),
            limits: OutputLimits::new(i64::MIN / 2, i64::MAX / 2, 100_000),
            setpoint: 0,
            integral: 0,
            prev_error: 0,
            prev_output: 0,
            update_count: 0,
            active: false,
            history: [const { PidSample::new() }; MAX_HISTORY],
            history_count: 0,
        }
    }

    /// Returns the controller identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Returns the current setpoint.
    pub const fn setpoint(&self) -> i64 {
        self.setpoint
    }

    /// Sets the setpoint.
    pub fn set_setpoint(&mut self, sp: i64) {
        self.setpoint = sp;
    }

    /// Sets the PID gains.
    pub fn set_gains(&mut self, gains: PidGains) {
        self.gains = gains;
    }

    /// Sets the output limits.
    pub fn set_limits(&mut self, limits: OutputLimits) {
        self.limits = limits;
    }

    /// Returns whether the controller is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Activates the controller.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Computes the control output for a new measurement.
    pub fn update(&mut self, measurement: i64, now_ns: u64) -> i64 {
        let error = self.setpoint - measurement;

        // Proportional term
        let p_term = (self.gains.kp * error) / 1000;

        // Integral term with windup prevention
        self.integral += error;
        if self.integral > self.limits.integral_max {
            self.integral = self.limits.integral_max;
        } else if self.integral < -self.limits.integral_max {
            self.integral = -self.limits.integral_max;
        }
        let i_term = (self.gains.ki * self.integral) / 1000;

        // Derivative term
        let d_error = error - self.prev_error;
        let d_term = (self.gains.kd * d_error) / 1000;

        // Combined output
        let raw_output = p_term + i_term + d_term;
        let output = self.limits.clamp(raw_output);

        // Record history
        if self.history_count < MAX_HISTORY {
            self.history[self.history_count] = PidSample {
                measurement,
                setpoint: self.setpoint,
                error,
                output,
                timestamp_ns: now_ns,
            };
            self.history_count += 1;
        }

        self.prev_error = error;
        self.prev_output = output;
        self.update_count += 1;

        output
    }

    /// Resets the controller state.
    pub fn reset(&mut self) {
        self.integral = 0;
        self.prev_error = 0;
        self.prev_output = 0;
        self.history_count = 0;
    }

    /// Returns the number of updates performed.
    pub const fn update_count(&self) -> u64 {
        self.update_count
    }

    /// Returns the number of history samples.
    pub const fn history_count(&self) -> usize {
        self.history_count
    }
}

impl Default for PidController {
    fn default() -> Self {
        Self::new()
    }
}

/// PID controller manager.
pub struct PidControllerManager {
    /// Registered controllers.
    controllers: [PidController; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
    /// Next controller ID.
    next_id: u32,
}

impl PidControllerManager {
    /// Creates a new PID controller manager.
    pub const fn new() -> Self {
        Self {
            controllers: [const { PidController::new() }; MAX_CONTROLLERS],
            count: 0,
            next_id: 1,
        }
    }

    /// Creates and registers a new PID controller.
    pub fn create_controller(
        &mut self,
        gains: PidGains,
        limits: OutputLimits,
        setpoint: i64,
    ) -> Result<u32> {
        if self.count >= MAX_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.controllers[self.count] = PidController {
            id,
            gains,
            limits,
            setpoint,
            integral: 0,
            prev_error: 0,
            prev_output: 0,
            update_count: 0,
            active: true,
            history: [const { PidSample::new() }; MAX_HISTORY],
            history_count: 0,
        };
        self.count += 1;
        Ok(id)
    }

    /// Gets a controller by ID.
    pub fn get_controller(&self, id: u32) -> Result<&PidController> {
        self.controllers[..self.count]
            .iter()
            .find(|c| c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Gets a mutable controller by ID.
    pub fn get_controller_mut(&mut self, id: u32) -> Result<&mut PidController> {
        self.controllers[..self.count]
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns the number of registered controllers.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for PidControllerManager {
    fn default() -> Self {
        Self::new()
    }
}
