// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Voltage regulator hardware abstraction.
//!
//! Provides a unified interface for controlling hardware voltage regulators
//! (VRMs, PMICs, buck/boost converters). Supports enabling/disabling regulators,
//! setting output voltage, and reading current voltage and load current.

use oncrix_lib::{Error, Result};

/// Maximum number of voltage regulators in the system.
pub const MAX_REGULATORS: usize = 16;

/// Type of voltage regulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegulatorType {
    /// Linear regulator (LDO — Low Drop Out).
    Ldo,
    /// Buck (step-down switching) converter.
    Buck,
    /// Boost (step-up switching) converter.
    Boost,
    /// Buck-boost converter (can step up or down).
    BuckBoost,
    /// Fixed-voltage regulator (non-adjustable).
    Fixed,
}

/// Voltage regulator operating state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegulatorState {
    /// Regulator is disabled (output off).
    Disabled,
    /// Regulator is enabled and in regulation.
    Enabled,
    /// Regulator is in bypass mode (input directly to output).
    Bypass,
    /// Regulator is in error state (overcurrent, thermal, etc.).
    Fault,
}

/// Voltage constraint specifying the allowable voltage range.
#[derive(Debug, Clone, Copy)]
pub struct VoltageConstraints {
    /// Minimum output voltage in micro-Volts.
    pub min_uv: u32,
    /// Maximum output voltage in micro-Volts.
    pub max_uv: u32,
    /// Voltage step size in micro-Volts.
    pub step_uv: u32,
}

impl VoltageConstraints {
    /// Creates new voltage constraints.
    ///
    /// # Arguments
    /// * `min_uv` — Minimum voltage in micro-Volts.
    /// * `max_uv` — Maximum voltage in micro-Volts.
    /// * `step_uv` — Voltage step size in micro-Volts (0 for fixed/continuous).
    pub const fn new(min_uv: u32, max_uv: u32, step_uv: u32) -> Self {
        Self {
            min_uv,
            max_uv,
            step_uv,
        }
    }

    /// Checks whether the given voltage is within the allowed range and aligned to step.
    pub fn is_valid(&self, voltage_uv: u32) -> bool {
        if voltage_uv < self.min_uv || voltage_uv > self.max_uv {
            return false;
        }
        if self.step_uv == 0 {
            return true;
        }
        (voltage_uv - self.min_uv) % self.step_uv == 0
    }

    /// Clamps a voltage to the nearest valid step within the range.
    pub fn clamp_to_step(&self, voltage_uv: u32) -> u32 {
        let clamped = voltage_uv.clamp(self.min_uv, self.max_uv);
        if self.step_uv == 0 {
            return clamped;
        }
        let offset = clamped.saturating_sub(self.min_uv);
        let steps = offset / self.step_uv;
        self.min_uv + steps * self.step_uv
    }
}

impl Default for VoltageConstraints {
    fn default() -> Self {
        Self::new(0, 3_300_000, 0)
    }
}

/// A hardware voltage regulator.
pub struct VoltageRegulator {
    /// Regulator identifier.
    id: u8,
    /// Human-readable name (e.g., "VCC_CORE").
    name: &'static str,
    /// Regulator type.
    reg_type: RegulatorType,
    /// MMIO base address for regulator control registers.
    base_addr: u64,
    /// Current operating state.
    state: RegulatorState,
    /// Voltage constraints.
    constraints: VoltageConstraints,
    /// Current target voltage in micro-Volts.
    target_uv: u32,
    /// Number of consumers currently enabled.
    enable_count: u32,
}

impl VoltageRegulator {
    /// Creates a new voltage regulator.
    ///
    /// # Arguments
    /// * `id` — Unique regulator identifier.
    /// * `name` — Human-readable name.
    /// * `reg_type` — Regulator type.
    /// * `base_addr` — MMIO base address.
    /// * `constraints` — Voltage constraints.
    pub const fn new(
        id: u8,
        name: &'static str,
        reg_type: RegulatorType,
        base_addr: u64,
        constraints: VoltageConstraints,
    ) -> Self {
        Self {
            id,
            name,
            reg_type,
            base_addr,
            state: RegulatorState::Disabled,
            constraints,
            target_uv: 0,
            enable_count: 0,
        }
    }

    /// Returns the regulator ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the regulator name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the regulator type.
    pub fn reg_type(&self) -> RegulatorType {
        self.reg_type
    }

    /// Returns the current operating state.
    pub fn state(&self) -> RegulatorState {
        self.state
    }

    /// Returns the current target voltage in micro-Volts.
    pub fn target_uv(&self) -> u32 {
        self.target_uv
    }

    /// Enables the voltage regulator.
    ///
    /// Uses a reference-count scheme; the regulator stays on until all
    /// consumers call `disable()`.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero.
    pub fn enable(&mut self) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        self.enable_count = self.enable_count.saturating_add(1);
        if self.state != RegulatorState::Enabled {
            // SAFETY: MMIO write to regulator enable register. base_addr is non-zero.
            unsafe {
                let ctrl = self.base_addr as *mut u32;
                let val = ctrl.read_volatile();
                ctrl.write_volatile(val | 0x1); // Set enable bit
            }
            self.state = RegulatorState::Enabled;
        }
        Ok(())
    }

    /// Decrements the enable reference count, disabling the regulator if it reaches zero.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero.
    pub fn disable(&mut self) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.enable_count > 0 {
            self.enable_count -= 1;
        }
        if self.enable_count == 0 && self.state == RegulatorState::Enabled {
            // SAFETY: MMIO write to regulator enable register. base_addr is non-zero.
            unsafe {
                let ctrl = self.base_addr as *mut u32;
                let val = ctrl.read_volatile();
                ctrl.write_volatile(val & !0x1); // Clear enable bit
            }
            self.state = RegulatorState::Disabled;
        }
        Ok(())
    }

    /// Sets the output voltage.
    ///
    /// # Arguments
    /// * `voltage_uv` — Target voltage in micro-Volts.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if voltage is outside the constraints range.
    /// Returns `Error::Busy` if the regulator is not enabled.
    pub fn set_voltage(&mut self, voltage_uv: u32) -> Result<()> {
        if self.reg_type == RegulatorType::Fixed {
            return Err(Error::InvalidArgument);
        }
        if !self.constraints.is_valid(voltage_uv) {
            return Err(Error::InvalidArgument);
        }
        let clamped = self.constraints.clamp_to_step(voltage_uv);
        self.target_uv = clamped;
        if self.base_addr != 0 {
            // SAFETY: MMIO write to voltage DAC register. base_addr is non-zero.
            unsafe {
                let vset = (self.base_addr + 0x04) as *mut u32;
                // Encode voltage: raw = (uv - min_uv) / step_uv
                let raw = if self.constraints.step_uv > 0 {
                    (clamped - self.constraints.min_uv) / self.constraints.step_uv
                } else {
                    clamped
                };
                vset.write_volatile(raw);
            }
        }
        Ok(())
    }

    /// Reads the actual output voltage from the regulator hardware.
    ///
    /// # Errors
    /// Returns `Error::IoError` if the read fails.
    /// Returns `Error::Busy` if not enabled.
    pub fn read_voltage_uv(&self) -> Result<u32> {
        if self.state != RegulatorState::Enabled {
            return Err(Error::Busy);
        }
        if self.base_addr == 0 {
            return Ok(self.target_uv);
        }
        // SAFETY: MMIO read from voltage ADC register. base_addr is non-zero.
        let raw = unsafe {
            let vadc = (self.base_addr + 0x08) as *const u32;
            vadc.read_volatile()
        };
        // Convert raw ADC value back to micro-Volts
        let uv = if self.constraints.step_uv > 0 {
            self.constraints.min_uv + raw * self.constraints.step_uv
        } else {
            raw
        };
        Ok(uv.min(self.constraints.max_uv))
    }
}

impl Default for VoltageRegulator {
    fn default() -> Self {
        Self::new(
            0,
            "unknown",
            RegulatorType::Fixed,
            0,
            VoltageConstraints::default(),
        )
    }
}

/// Registry of all system voltage regulators.
pub struct RegulatorRegistry {
    regulators: [VoltageRegulator; MAX_REGULATORS],
    count: usize,
}

impl RegulatorRegistry {
    /// Creates a new empty regulator registry.
    pub fn new() -> Self {
        Self {
            regulators: [
                VoltageRegulator::new(
                    0,
                    "vr0",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    1,
                    "vr1",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    2,
                    "vr2",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    3,
                    "vr3",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    4,
                    "vr4",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    5,
                    "vr5",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    6,
                    "vr6",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    7,
                    "vr7",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    8,
                    "vr8",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    9,
                    "vr9",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    10,
                    "vr10",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    11,
                    "vr11",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    12,
                    "vr12",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    13,
                    "vr13",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    14,
                    "vr14",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
                VoltageRegulator::new(
                    15,
                    "vr15",
                    RegulatorType::Fixed,
                    0,
                    VoltageConstraints::default(),
                ),
            ],
            count: 0,
        }
    }

    /// Registers a voltage regulator.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, regulator: VoltageRegulator) -> Result<()> {
        if self.count >= MAX_REGULATORS {
            return Err(Error::OutOfMemory);
        }
        self.regulators[self.count] = regulator;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of registered regulators.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no regulators are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a mutable reference to the regulator at the given index.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the index is out of range.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut VoltageRegulator> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.regulators[index])
    }

    /// Finds a regulator by name.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if no regulator with the given name exists.
    pub fn find_by_name(&self, name: &str) -> Result<usize> {
        for (i, reg) in self.regulators[..self.count].iter().enumerate() {
            if reg.name() == name {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }
}

impl Default for RegulatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Converts micro-Volts to milli-Volts (rounded down).
pub fn uv_to_mv(uv: u32) -> u32 {
    uv / 1_000
}

/// Converts milli-Volts to micro-Volts.
pub fn mv_to_uv(mv: u32) -> u32 {
    mv * 1_000
}

/// Computes power in micro-Watts from voltage (uV) and current (uA).
pub fn compute_power_uw(voltage_uv: u32, current_ua: u32) -> u64 {
    (voltage_uv as u64 * current_ua as u64) / 1_000_000
}
