// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Fan controller hardware abstraction.
//!
//! Provides a unified interface for managing system cooling fans including
//! speed control via PWM, tachometer reading, and automatic fan curve
//! management based on temperature thresholds.

use oncrix_lib::{Error, Result};

/// Maximum number of fan controllers supported.
pub const MAX_FAN_CONTROLLERS: usize = 8;

/// Maximum number of fan curve points.
pub const MAX_CURVE_POINTS: usize = 8;

/// Fan control mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanMode {
    /// Fan speed is fully manual (fixed duty cycle).
    Manual,
    /// Fan speed follows a temperature-based curve.
    Automatic,
    /// Fan is fully off (zero speed).
    Off,
    /// Fan runs at maximum speed.
    FullSpeed,
}

/// A single point on a fan speed curve.
#[derive(Debug, Clone, Copy)]
pub struct FanCurvePoint {
    /// Temperature threshold in milli-Celsius.
    pub temp_mc: i32,
    /// Fan duty cycle percentage (0..=100).
    pub duty_percent: u8,
}

impl FanCurvePoint {
    /// Creates a new fan curve point.
    pub const fn new(temp_mc: i32, duty_percent: u8) -> Self {
        let duty = if duty_percent > 100 {
            100
        } else {
            duty_percent
        };
        Self {
            temp_mc,
            duty_percent: duty,
        }
    }
}

impl Default for FanCurvePoint {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// Fan speed curve mapping temperature to duty cycle.
#[derive(Debug)]
pub struct FanCurve {
    points: [FanCurvePoint; MAX_CURVE_POINTS],
    count: usize,
}

impl FanCurve {
    /// Creates a new empty fan curve.
    pub const fn new() -> Self {
        Self {
            points: [const { FanCurvePoint::new(0, 0) }; MAX_CURVE_POINTS],
            count: 0,
        }
    }

    /// Adds a point to the fan curve.
    ///
    /// Points should be added in ascending temperature order.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the curve is full.
    /// Returns `Error::InvalidArgument` if duty_percent > 100.
    pub fn add_point(&mut self, temp_mc: i32, duty_percent: u8) -> Result<()> {
        if self.count >= MAX_CURVE_POINTS {
            return Err(Error::OutOfMemory);
        }
        if duty_percent > 100 {
            return Err(Error::InvalidArgument);
        }
        self.points[self.count] = FanCurvePoint::new(temp_mc, duty_percent);
        self.count += 1;
        Ok(())
    }

    /// Interpolates the duty cycle for the given temperature.
    ///
    /// Returns the duty cycle percentage (0..=100).
    pub fn interpolate(&self, temp_mc: i32) -> u8 {
        if self.count == 0 {
            return 50; // Default 50% if no curve configured
        }
        // Below first point
        if temp_mc <= self.points[0].temp_mc {
            return self.points[0].duty_percent;
        }
        // Above last point
        if temp_mc >= self.points[self.count - 1].temp_mc {
            return self.points[self.count - 1].duty_percent;
        }
        // Find the segment
        for i in 0..self.count.saturating_sub(1) {
            let lo = &self.points[i];
            let hi = &self.points[i + 1];
            if temp_mc >= lo.temp_mc && temp_mc <= hi.temp_mc {
                let span = hi.temp_mc - lo.temp_mc;
                if span == 0 {
                    return hi.duty_percent;
                }
                let offset = temp_mc - lo.temp_mc;
                let duty_span = hi.duty_percent as i32 - lo.duty_percent as i32;
                let duty = lo.duty_percent as i32 + (duty_span * offset) / span;
                return duty.clamp(0, 100) as u8;
            }
        }
        50
    }

    /// Returns the number of curve points.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for FanCurve {
    fn default() -> Self {
        Self::new()
    }
}

/// Hardware fan controller for a single fan.
pub struct FanController {
    /// Fan index in the system.
    id: u8,
    /// MMIO base address for fan controller registers.
    base_addr: u64,
    /// Current fan mode.
    mode: FanMode,
    /// Current duty cycle percentage (0..=100).
    duty_percent: u8,
    /// Speed curve for automatic mode.
    curve: FanCurve,
    /// PWM frequency in Hz.
    pwm_freq_hz: u32,
    /// Whether the controller has been initialized.
    initialized: bool,
}

impl FanController {
    /// Creates a new fan controller.
    ///
    /// # Arguments
    /// * `id` — Fan identifier (0..MAX_FAN_CONTROLLERS).
    /// * `base_addr` — MMIO base address of fan controller registers.
    /// * `pwm_freq_hz` — PWM frequency in Hz (typically 25000 for 25kHz).
    pub const fn new(id: u8, base_addr: u64, pwm_freq_hz: u32) -> Self {
        Self {
            id,
            base_addr,
            mode: FanMode::Automatic,
            duty_percent: 50,
            curve: FanCurve::new(),
            pwm_freq_hz,
            initialized: false,
        }
    }

    /// Returns the fan ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the current fan mode.
    pub fn mode(&self) -> FanMode {
        self.mode
    }

    /// Returns the current duty cycle percentage.
    pub fn duty_percent(&self) -> u8 {
        self.duty_percent
    }

    /// Initializes the fan controller hardware.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero.
    pub fn init(&mut self) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO write to fan controller configuration register.
        // base_addr is validated to be non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            ctrl.write_volatile(0); // Reset to defaults
            // Set PWM frequency
            let freq_reg = (self.base_addr + 0x04) as *mut u32;
            freq_reg.write_volatile(self.pwm_freq_hz);
        }
        self.initialized = true;
        Ok(())
    }

    /// Sets the fan duty cycle directly (manual mode).
    ///
    /// # Arguments
    /// * `duty_percent` — Duty cycle 0..=100.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if duty_percent > 100.
    /// Returns `Error::Busy` if not initialized.
    pub fn set_duty(&mut self, duty_percent: u8) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if duty_percent > 100 {
            return Err(Error::InvalidArgument);
        }
        self.mode = FanMode::Manual;
        self.duty_percent = duty_percent;
        self.apply_duty(duty_percent)
    }

    /// Sets the fan speed mode.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn set_mode(&mut self, mode: FanMode) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        self.mode = mode;
        match mode {
            FanMode::Off => self.apply_duty(0)?,
            FanMode::FullSpeed => self.apply_duty(100)?,
            FanMode::Manual => self.apply_duty(self.duty_percent)?,
            FanMode::Automatic => {} // Updated via update_from_temp
        }
        Ok(())
    }

    /// Updates fan speed based on the current temperature (automatic mode).
    ///
    /// # Arguments
    /// * `temp_mc` — Current temperature in milli-Celsius.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn update_from_temp(&mut self, temp_mc: i32) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if self.mode != FanMode::Automatic {
            return Ok(());
        }
        let duty = self.curve.interpolate(temp_mc);
        self.duty_percent = duty;
        self.apply_duty(duty)
    }

    /// Returns a mutable reference to the fan curve.
    pub fn curve_mut(&mut self) -> &mut FanCurve {
        &mut self.curve
    }

    /// Reads the fan tachometer (RPM).
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::IoError` if the tachometer read fails.
    pub fn read_rpm(&self) -> Result<u32> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO read from fan tachometer register. base_addr is valid
        // and was checked during init().
        let tach = unsafe {
            let tach_reg = (self.base_addr + 0x08) as *const u32;
            tach_reg.read_volatile()
        };
        // Convert raw tachometer count to RPM (60s * freq / pulses_per_rev)
        let rpm = if tach == 0 {
            0
        } else {
            60 * self.pwm_freq_hz / tach.max(1)
        };
        Ok(rpm)
    }

    fn apply_duty(&self, duty_percent: u8) -> Result<()> {
        // SAFETY: MMIO write to fan PWM duty cycle register. base_addr is valid.
        unsafe {
            let duty_reg = (self.base_addr + 0x0C) as *mut u32;
            // Scale 0..100 to full register range 0..0xFFFF
            let raw = (duty_percent as u32) * 0xFFFF / 100;
            duty_reg.write_volatile(raw);
        }
        Ok(())
    }
}

impl Default for FanController {
    fn default() -> Self {
        Self::new(0, 0, 25_000)
    }
}

/// Registry of all system fan controllers.
pub struct FanControllerRegistry {
    controllers: [FanController; MAX_FAN_CONTROLLERS],
    count: usize,
}

impl FanControllerRegistry {
    /// Creates a new empty fan controller registry.
    pub fn new() -> Self {
        Self {
            controllers: [
                FanController::new(0, 0, 25_000),
                FanController::new(1, 0, 25_000),
                FanController::new(2, 0, 25_000),
                FanController::new(3, 0, 25_000),
                FanController::new(4, 0, 25_000),
                FanController::new(5, 0, 25_000),
                FanController::new(6, 0, 25_000),
                FanController::new(7, 0, 25_000),
            ],
            count: 0,
        }
    }

    /// Registers a fan controller.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, fan: FanController) -> Result<()> {
        if self.count >= MAX_FAN_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        self.controllers[self.count] = fan;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a mutable reference to the controller at the given index.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the index is out of range.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut FanController> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.controllers[index])
    }

    /// Updates all fans in automatic mode with the given temperature.
    pub fn update_all_from_temp(&mut self, temp_mc: i32) {
        for fan in self.controllers[..self.count].iter_mut() {
            let _ = fan.update_from_temp(temp_mc);
        }
    }
}

impl Default for FanControllerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Converts a duty cycle percentage to a raw PWM register value.
///
/// # Arguments
/// * `duty_percent` — Duty cycle 0..=100.
/// * `max_val` — Maximum raw register value.
pub fn duty_to_raw(duty_percent: u8, max_val: u32) -> u32 {
    let duty = duty_percent.min(100) as u32;
    duty * max_val / 100
}

/// Converts a raw PWM register value back to a duty cycle percentage.
///
/// # Arguments
/// * `raw` — Raw register value.
/// * `max_val` — Maximum raw register value.
pub fn raw_to_duty(raw: u32, max_val: u32) -> u8 {
    if max_val == 0 {
        return 0;
    }
    ((raw * 100) / max_val).min(100) as u8
}
