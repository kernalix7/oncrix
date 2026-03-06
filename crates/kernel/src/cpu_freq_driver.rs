// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU frequency driver core.
//!
//! Provides the driver interface for CPU frequency scaling hardware.
//! Manages the registration and dispatch of frequency change requests
//! to architecture-specific drivers, tracks supported frequencies,
//! and enforces transition latency constraints.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of registered frequency drivers.
const MAX_DRIVERS: usize = 8;

/// Maximum number of supported frequency steps per driver.
const MAX_FREQ_STEPS: usize = 64;

/// Maximum CPUs managed.
const MAX_CPUS: usize = 64;

/// Frequency in kHz for "unknown".
const _FREQ_UNKNOWN: u32 = 0;

// ── Types ────────────────────────────────────────────────────────────

/// Identifies a frequency driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreqDriverId(u32);

impl FreqDriverId {
    /// Creates a new driver identifier.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw identifier.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// A supported frequency step.
#[derive(Debug, Clone, Copy)]
pub struct FreqStep {
    /// Frequency in kHz.
    freq_khz: u32,
    /// Voltage in millivolts (0 if unknown).
    voltage_mv: u32,
    /// Driver-specific opaque index.
    driver_index: u16,
}

impl FreqStep {
    /// Creates a new frequency step.
    pub const fn new(freq_khz: u32, voltage_mv: u32, driver_index: u16) -> Self {
        Self {
            freq_khz,
            voltage_mv,
            driver_index,
        }
    }

    /// Returns the frequency in kHz.
    pub const fn freq_khz(&self) -> u32 {
        self.freq_khz
    }

    /// Returns the voltage in millivolts.
    pub const fn voltage_mv(&self) -> u32 {
        self.voltage_mv
    }
}

/// Per-CPU frequency state.
#[derive(Debug, Clone)]
pub struct CpuFreqState {
    /// CPU identifier.
    cpu_id: u32,
    /// Current frequency in kHz.
    current_freq_khz: u32,
    /// Minimum allowed frequency in kHz.
    min_freq_khz: u32,
    /// Maximum allowed frequency in kHz.
    max_freq_khz: u32,
    /// Driver managing this CPU.
    driver_id: FreqDriverId,
    /// Total frequency transitions.
    transition_count: u64,
    /// Total time at current frequency (nanoseconds).
    time_in_state_ns: u64,
}

impl CpuFreqState {
    /// Creates a new CPU frequency state.
    pub const fn new(cpu_id: u32, driver_id: FreqDriverId) -> Self {
        Self {
            cpu_id,
            current_freq_khz: 0,
            min_freq_khz: 0,
            max_freq_khz: 0,
            driver_id,
            transition_count: 0,
            time_in_state_ns: 0,
        }
    }

    /// Returns the current frequency in kHz.
    pub const fn current_freq_khz(&self) -> u32 {
        self.current_freq_khz
    }

    /// Returns the transition count.
    pub const fn transition_count(&self) -> u64 {
        self.transition_count
    }
}

/// Registered frequency driver.
#[derive(Debug)]
pub struct FreqDriver {
    /// Driver identifier.
    id: FreqDriverId,
    /// Driver name.
    name: [u8; 32],
    /// Name length.
    name_len: usize,
    /// Supported frequency steps.
    freq_table: [Option<FreqStep>; MAX_FREQ_STEPS],
    /// Number of frequency steps.
    step_count: usize,
    /// Transition latency in nanoseconds.
    transition_latency_ns: u64,
    /// Whether the driver supports boost frequencies.
    boost_supported: bool,
    /// Whether boost is currently enabled.
    boost_enabled: bool,
    /// Number of CPUs using this driver.
    cpu_count: u32,
}

impl FreqDriver {
    /// Creates a new frequency driver.
    pub const fn new(id: FreqDriverId, transition_latency_ns: u64) -> Self {
        Self {
            id,
            name: [0u8; 32],
            name_len: 0,
            freq_table: [None; MAX_FREQ_STEPS],
            step_count: 0,
            transition_latency_ns,
            boost_supported: false,
            boost_enabled: false,
            cpu_count: 0,
        }
    }

    /// Returns the transition latency.
    pub const fn transition_latency_ns(&self) -> u64 {
        self.transition_latency_ns
    }

    /// Returns whether boost is supported.
    pub const fn boost_supported(&self) -> bool {
        self.boost_supported
    }
}

/// Frequency transition notification.
#[derive(Debug, Clone)]
pub struct FreqTransition {
    /// CPU that changed frequency.
    pub cpu_id: u32,
    /// Old frequency in kHz.
    pub old_freq_khz: u32,
    /// New frequency in kHz.
    pub new_freq_khz: u32,
    /// Transition timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

/// CPU frequency driver statistics.
#[derive(Debug, Clone)]
pub struct CpuFreqDriverStats {
    /// Total registered drivers.
    pub total_drivers: u32,
    /// Total managed CPUs.
    pub total_cpus: u32,
    /// Total frequency transitions.
    pub total_transitions: u64,
    /// Total boost transitions.
    pub boost_transitions: u64,
}

impl Default for CpuFreqDriverStats {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuFreqDriverStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_drivers: 0,
            total_cpus: 0,
            total_transitions: 0,
            boost_transitions: 0,
        }
    }
}

/// Central CPU frequency driver manager.
#[derive(Debug)]
pub struct CpuFreqDriverManager {
    /// Registered drivers.
    drivers: [Option<FreqDriver>; MAX_DRIVERS],
    /// Per-CPU frequency states.
    cpu_states: [Option<CpuFreqState>; MAX_CPUS],
    /// Number of drivers.
    driver_count: usize,
    /// Number of managed CPUs.
    cpu_count: usize,
    /// Next driver identifier.
    next_id: u32,
    /// Total transitions.
    total_transitions: u64,
}

impl Default for CpuFreqDriverManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuFreqDriverManager {
    /// Creates a new manager.
    pub const fn new() -> Self {
        Self {
            drivers: [const { None }; MAX_DRIVERS],
            cpu_states: [const { None }; MAX_CPUS],
            driver_count: 0,
            cpu_count: 0,
            next_id: 1,
            total_transitions: 0,
        }
    }

    /// Registers a new frequency driver.
    pub fn register_driver(&mut self, transition_latency_ns: u64) -> Result<FreqDriverId> {
        if self.driver_count >= MAX_DRIVERS {
            return Err(Error::OutOfMemory);
        }
        let id = FreqDriverId::new(self.next_id);
        self.next_id += 1;
        let driver = FreqDriver::new(id, transition_latency_ns);
        if let Some(slot) = self.drivers.iter_mut().find(|s| s.is_none()) {
            *slot = Some(driver);
            self.driver_count += 1;
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Adds a frequency step to a driver's table.
    pub fn add_freq_step(
        &mut self,
        driver_id: FreqDriverId,
        freq_khz: u32,
        voltage_mv: u32,
    ) -> Result<()> {
        let driver = self
            .drivers
            .iter_mut()
            .flatten()
            .find(|d| d.id == driver_id)
            .ok_or(Error::NotFound)?;
        if driver.step_count >= MAX_FREQ_STEPS {
            return Err(Error::OutOfMemory);
        }
        let step = FreqStep::new(freq_khz, voltage_mv, driver.step_count as u16);
        driver.freq_table[driver.step_count] = Some(step);
        driver.step_count += 1;
        Ok(())
    }

    /// Registers a CPU with a frequency driver.
    pub fn register_cpu(&mut self, cpu_id: u32, driver_id: FreqDriverId) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.cpu_states[idx].is_some() {
            return Err(Error::AlreadyExists);
        }
        let state = CpuFreqState::new(cpu_id, driver_id);
        self.cpu_states[idx] = Some(state);
        self.cpu_count += 1;
        if let Some(d) = self
            .drivers
            .iter_mut()
            .flatten()
            .find(|d| d.id == driver_id)
        {
            d.cpu_count += 1;
        }
        Ok(())
    }

    /// Sets the frequency for a CPU.
    pub fn set_frequency(&mut self, cpu_id: u32, target_khz: u32) -> Result<FreqTransition> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let state = self.cpu_states[idx].as_mut().ok_or(Error::NotFound)?;
        let old = state.current_freq_khz;
        state.current_freq_khz = target_khz;
        state.transition_count += 1;
        self.total_transitions += 1;
        Ok(FreqTransition {
            cpu_id,
            old_freq_khz: old,
            new_freq_khz: target_khz,
            timestamp_ns: 0,
        })
    }

    /// Sets the min/max frequency policy for a CPU.
    pub fn set_policy(&mut self, cpu_id: u32, min_khz: u32, max_khz: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let state = self.cpu_states[idx].as_mut().ok_or(Error::NotFound)?;
        if min_khz > max_khz {
            return Err(Error::InvalidArgument);
        }
        state.min_freq_khz = min_khz;
        state.max_freq_khz = max_khz;
        Ok(())
    }

    /// Returns statistics.
    pub fn stats(&self) -> CpuFreqDriverStats {
        CpuFreqDriverStats {
            total_drivers: self.driver_count as u32,
            total_cpus: self.cpu_count as u32,
            total_transitions: self.total_transitions,
            boost_transitions: 0,
        }
    }

    /// Returns the number of registered drivers.
    pub const fn driver_count(&self) -> usize {
        self.driver_count
    }
}
