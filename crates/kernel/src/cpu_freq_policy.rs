// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU frequency policy.
//!
//! Manages CPU frequency scaling policies (cpufreq). Each CPU
//! has a policy that defines minimum/maximum frequencies and the
//! governor algorithm used to select the operating frequency.
//!
//! # Design
//!
//! ```text
//!   CpufreqPolicy
//!   +-------------------+
//!   | cpu               |  CPU number
//!   | min / max / cur   |  frequency in kHz
//!   | governor          |  performance / powersave / ...
//!   | transition_lat    |  nanoseconds
//!   +-------------------+
//!
//!   CpufreqDriver:
//!   Registered by the platform to implement actual frequency changes.
//!
//!   TransitionNotifier:
//!   PRECHANGE / POSTCHANGE callbacks.
//! ```
//!
//! # Governors
//!
//! - `Performance` — always max frequency.
//! - `Powersave` — always min frequency.
//! - `Ondemand` — scale based on load.
//! - `Conservative` — gradual scaling.
//! - `Schedutil` — scheduler-driven.
//!
//! # Reference
//!
//! Linux `drivers/cpufreq/cpufreq.c`,
//! `include/linux/cpufreq.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum CPUs.
const MAX_CPUS: usize = 256;

/// Maximum registered drivers.
const MAX_DRIVERS: usize = 8;

/// Maximum transition notifiers.
const MAX_NOTIFIERS: usize = 32;

/// Maximum name length.
const MAX_NAME_LEN: usize = 32;

// ======================================================================
// CpufreqGovernor
// ======================================================================

/// CPU frequency governor algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpufreqGovernor {
    /// Always maximum frequency.
    Performance,
    /// Always minimum frequency.
    Powersave,
    /// Dynamic scaling based on load.
    Ondemand,
    /// Gradual frequency changes.
    Conservative,
    /// Scheduler-integrated scaling.
    Schedutil,
}

impl CpufreqGovernor {
    /// Returns the governor name.
    pub fn name(&self) -> &[u8] {
        match self {
            Self::Performance => b"performance",
            Self::Powersave => b"powersave",
            Self::Ondemand => b"ondemand",
            Self::Conservative => b"conservative",
            Self::Schedutil => b"schedutil",
        }
    }
}

// ======================================================================
// TransitionType
// ======================================================================

/// Frequency transition notification type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionType {
    /// About to change frequency.
    PreChange,
    /// Frequency change completed.
    PostChange,
}

// ======================================================================
// CpufreqPolicy
// ======================================================================

/// CPU frequency policy for a single CPU.
#[derive(Debug, Clone, Copy)]
pub struct CpufreqPolicy {
    /// CPU number.
    cpu: u32,
    /// Minimum frequency (kHz).
    min_freq: u32,
    /// Maximum frequency (kHz).
    max_freq: u32,
    /// Current frequency (kHz).
    cur_freq: u32,
    /// Active governor.
    governor: CpufreqGovernor,
    /// Whether this policy is active.
    active: bool,
    /// Transition latency (ns).
    transition_latency_ns: u32,
    /// Total transitions.
    total_transitions: u64,
    /// Total time in each frequency (simplified: last freq time).
    last_freq_change_ns: u64,
}

impl CpufreqPolicy {
    /// Creates a new empty policy.
    pub const fn new() -> Self {
        Self {
            cpu: 0,
            min_freq: 0,
            max_freq: 0,
            cur_freq: 0,
            governor: CpufreqGovernor::Performance,
            active: false,
            transition_latency_ns: 0,
            total_transitions: 0,
            last_freq_change_ns: 0,
        }
    }

    /// Returns the CPU number.
    pub fn cpu(&self) -> u32 {
        self.cpu
    }

    /// Returns the minimum frequency.
    pub fn min_freq(&self) -> u32 {
        self.min_freq
    }

    /// Returns the maximum frequency.
    pub fn max_freq(&self) -> u32 {
        self.max_freq
    }

    /// Returns the current frequency.
    pub fn cur_freq(&self) -> u32 {
        self.cur_freq
    }

    /// Returns the active governor.
    pub fn governor(&self) -> CpufreqGovernor {
        self.governor
    }

    /// Returns whether active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the transition latency.
    pub fn transition_latency_ns(&self) -> u32 {
        self.transition_latency_ns
    }

    /// Returns total transitions.
    pub fn total_transitions(&self) -> u64 {
        self.total_transitions
    }
}

// ======================================================================
// CpufreqDriver
// ======================================================================

/// A cpufreq driver (platform-specific frequency changer).
#[derive(Debug, Clone, Copy)]
pub struct CpufreqDriver {
    /// Driver name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Whether registered.
    registered: bool,
    /// Supported frequency table (kHz), 0-terminated.
    freq_table: [u32; 32],
    /// Number of supported frequencies.
    freq_count: usize,
}

impl CpufreqDriver {
    /// Creates a new empty driver.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            registered: false,
            freq_table: [0u32; 32],
            freq_count: 0,
        }
    }

    /// Returns the driver name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns whether registered.
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// Returns the frequency table.
    pub fn freq_table(&self) -> &[u32] {
        &self.freq_table[..self.freq_count]
    }
}

// ======================================================================
// TransitionNotifier
// ======================================================================

/// A transition notifier entry.
#[derive(Debug, Clone, Copy)]
struct TransitionNotifier {
    /// Subscriber ID.
    subscriber_id: u32,
    /// Whether active.
    active: bool,
}

impl TransitionNotifier {
    const fn new() -> Self {
        Self {
            subscriber_id: 0,
            active: false,
        }
    }
}

// ======================================================================
// CpufreqManager
// ======================================================================

/// Manages CPU frequency policies, drivers, and notifiers.
pub struct CpufreqManager {
    /// Per-CPU policies.
    policies: [CpufreqPolicy; MAX_CPUS],
    /// Number of active policies.
    policy_count: usize,
    /// Registered drivers.
    drivers: [CpufreqDriver; MAX_DRIVERS],
    /// Number of registered drivers.
    driver_count: usize,
    /// Transition notifiers.
    notifiers: [TransitionNotifier; MAX_NOTIFIERS],
    /// Number of active notifiers.
    notifier_count: usize,
    /// Global timestamp.
    timestamp: u64,
}

impl CpufreqManager {
    /// Creates a new cpufreq manager.
    pub const fn new() -> Self {
        Self {
            policies: [const { CpufreqPolicy::new() }; MAX_CPUS],
            policy_count: 0,
            drivers: [const { CpufreqDriver::new() }; MAX_DRIVERS],
            driver_count: 0,
            notifiers: [const { TransitionNotifier::new() }; MAX_NOTIFIERS],
            notifier_count: 0,
            timestamp: 0,
        }
    }

    /// Registers a cpufreq driver.
    pub fn cpufreq_register_driver(&mut self, name: &[u8], freqs: &[u32]) -> Result<usize> {
        if self.driver_count >= MAX_DRIVERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .drivers
            .iter()
            .position(|d| !d.registered)
            .ok_or(Error::OutOfMemory)?;
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.drivers[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.drivers[idx].name_len = copy_len;
        self.drivers[idx].registered = true;
        let fc = freqs.len().min(32);
        self.drivers[idx].freq_table[..fc].copy_from_slice(&freqs[..fc]);
        self.drivers[idx].freq_count = fc;
        self.driver_count += 1;
        Ok(idx)
    }

    /// Creates a policy for a CPU.
    pub fn create_policy(
        &mut self,
        cpu: u32,
        min_freq: u32,
        max_freq: u32,
        governor: CpufreqGovernor,
    ) -> Result<()> {
        let ci = cpu as usize;
        if ci >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.policies[ci].active {
            return Err(Error::AlreadyExists);
        }
        let cur = match governor {
            CpufreqGovernor::Performance => max_freq,
            CpufreqGovernor::Powersave => min_freq,
            _ => (min_freq + max_freq) / 2,
        };
        self.policies[ci] = CpufreqPolicy {
            cpu,
            min_freq,
            max_freq,
            cur_freq: cur,
            governor,
            active: true,
            transition_latency_ns: 10_000,
            total_transitions: 0,
            last_freq_change_ns: self.timestamp,
        };
        self.policy_count += 1;
        Ok(())
    }

    /// Changes the governor for a CPU.
    pub fn set_governor(&mut self, cpu: u32, governor: CpufreqGovernor) -> Result<()> {
        let ci = cpu as usize;
        if ci >= MAX_CPUS || !self.policies[ci].active {
            return Err(Error::NotFound);
        }
        self.policies[ci].governor = governor;
        let new_freq = match governor {
            CpufreqGovernor::Performance => self.policies[ci].max_freq,
            CpufreqGovernor::Powersave => self.policies[ci].min_freq,
            _ => self.policies[ci].cur_freq,
        };
        self.transition_freq(ci, new_freq);
        Ok(())
    }

    /// Sets the target frequency for a CPU.
    pub fn set_frequency(&mut self, cpu: u32, freq: u32) -> Result<()> {
        let ci = cpu as usize;
        if ci >= MAX_CPUS || !self.policies[ci].active {
            return Err(Error::NotFound);
        }
        let clamped = freq
            .max(self.policies[ci].min_freq)
            .min(self.policies[ci].max_freq);
        self.transition_freq(ci, clamped);
        Ok(())
    }

    /// Returns a reference to a CPU's policy.
    pub fn get_policy(&self, cpu: u32) -> Result<&CpufreqPolicy> {
        let ci = cpu as usize;
        if ci >= MAX_CPUS || !self.policies[ci].active {
            return Err(Error::NotFound);
        }
        Ok(&self.policies[ci])
    }

    /// Returns a reference to a driver.
    pub fn get_driver(&self, idx: usize) -> Result<&CpufreqDriver> {
        if idx >= MAX_DRIVERS || !self.drivers[idx].registered {
            return Err(Error::NotFound);
        }
        Ok(&self.drivers[idx])
    }

    /// Returns the number of active policies.
    pub fn policy_count(&self) -> usize {
        self.policy_count
    }

    /// Returns the number of registered drivers.
    pub fn driver_count(&self) -> usize {
        self.driver_count
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Performs a frequency transition.
    fn transition_freq(&mut self, ci: usize, new_freq: u32) {
        self.timestamp += 1;
        self.policies[ci].cur_freq = new_freq;
        self.policies[ci].total_transitions += 1;
        self.policies[ci].last_freq_change_ns = self.timestamp;
    }
}
