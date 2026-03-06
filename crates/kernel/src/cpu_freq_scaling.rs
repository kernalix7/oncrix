// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU frequency scaling core subsystem.
//!
//! Implements the CPU frequency scaling framework (cpufreq) that
//! manages dynamic voltage and frequency scaling (DVFS) for power
//! and thermal management. Supports multiple scaling governors,
//! frequency tables, and per-CPU policy management.

use oncrix_lib::{Error, Result};

/// Maximum number of CPUs.
const MAX_CPUS: usize = 256;

/// Maximum number of frequency table entries.
const MAX_FREQ_TABLE: usize = 32;

/// Maximum number of scaling policies.
const MAX_POLICIES: usize = 64;

/// Frequency in kHz.
pub type FreqKhz = u64;

/// Scaling governor type.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Governor {
    /// Performance: always run at maximum frequency.
    Performance,
    /// Powersave: always run at minimum frequency.
    Powersave,
    /// Ondemand: scale based on CPU utilization.
    Ondemand,
    /// Conservative: slowly ramp up/down frequency.
    Conservative,
    /// Schedutil: scheduler-driven frequency selection.
    Schedutil,
    /// Userspace: user controls frequency directly.
    Userspace,
}

impl Governor {
    /// Returns a human-readable name.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Performance => "performance",
            Self::Powersave => "powersave",
            Self::Ondemand => "ondemand",
            Self::Conservative => "conservative",
            Self::Schedutil => "schedutil",
            Self::Userspace => "userspace",
        }
    }
}

/// Frequency table entry.
#[derive(Clone, Copy)]
pub struct FreqTableEntry {
    /// Frequency in kHz.
    frequency: FreqKhz,
    /// Associated voltage in millivolts.
    voltage_mv: u32,
    /// Whether this entry is valid.
    valid: bool,
}

impl FreqTableEntry {
    /// Creates a new frequency table entry.
    pub const fn new() -> Self {
        Self {
            frequency: 0,
            voltage_mv: 0,
            valid: false,
        }
    }

    /// Creates an entry with frequency and voltage.
    pub const fn with_freq_voltage(frequency: FreqKhz, voltage_mv: u32) -> Self {
        Self {
            frequency,
            voltage_mv,
            valid: true,
        }
    }

    /// Returns the frequency in kHz.
    pub const fn frequency(&self) -> FreqKhz {
        self.frequency
    }

    /// Returns the voltage in millivolts.
    pub const fn voltage_mv(&self) -> u32 {
        self.voltage_mv
    }
}

impl Default for FreqTableEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-CPU frequency scaling policy.
#[derive(Clone, Copy)]
pub struct CpuFreqPolicy {
    /// Policy identifier.
    id: u32,
    /// CPU this policy applies to.
    cpu_id: u32,
    /// Current frequency in kHz.
    current_freq: FreqKhz,
    /// Minimum allowed frequency.
    min_freq: FreqKhz,
    /// Maximum allowed frequency.
    max_freq: FreqKhz,
    /// Hardware minimum frequency.
    cpuinfo_min_freq: FreqKhz,
    /// Hardware maximum frequency.
    cpuinfo_max_freq: FreqKhz,
    /// Active governor.
    governor: Governor,
    /// Frequency table.
    freq_table: [FreqTableEntry; MAX_FREQ_TABLE],
    /// Number of valid table entries.
    freq_table_count: usize,
    /// Number of frequency transitions.
    transition_count: u64,
    /// Total time at current frequency in nanoseconds.
    time_in_state_ns: u64,
    /// Whether this policy is active.
    active: bool,
}

impl CpuFreqPolicy {
    /// Creates a new frequency scaling policy.
    pub const fn new() -> Self {
        Self {
            id: 0,
            cpu_id: 0,
            current_freq: 0,
            min_freq: 0,
            max_freq: 0,
            cpuinfo_min_freq: 0,
            cpuinfo_max_freq: 0,
            governor: Governor::Performance,
            freq_table: [const { FreqTableEntry::new() }; MAX_FREQ_TABLE],
            freq_table_count: 0,
            transition_count: 0,
            time_in_state_ns: 0,
            active: false,
        }
    }

    /// Returns the policy identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Returns the CPU identifier.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns the current frequency.
    pub const fn current_freq(&self) -> FreqKhz {
        self.current_freq
    }

    /// Returns the minimum allowed frequency.
    pub const fn min_freq(&self) -> FreqKhz {
        self.min_freq
    }

    /// Returns the maximum allowed frequency.
    pub const fn max_freq(&self) -> FreqKhz {
        self.max_freq
    }

    /// Returns the active governor.
    pub const fn governor(&self) -> Governor {
        self.governor
    }

    /// Sets the governor.
    pub fn set_governor(&mut self, gov: Governor) {
        self.governor = gov;
    }

    /// Sets the frequency range.
    pub fn set_freq_range(&mut self, min: FreqKhz, max: FreqKhz) -> Result<()> {
        if min > max {
            return Err(Error::InvalidArgument);
        }
        if min < self.cpuinfo_min_freq || max > self.cpuinfo_max_freq {
            return Err(Error::InvalidArgument);
        }
        self.min_freq = min;
        self.max_freq = max;
        Ok(())
    }

    /// Returns the number of frequency transitions.
    pub const fn transition_count(&self) -> u64 {
        self.transition_count
    }

    /// Returns the number of freq table entries.
    pub const fn freq_table_count(&self) -> usize {
        self.freq_table_count
    }

    /// Adds an entry to the frequency table.
    pub fn add_freq_entry(&mut self, entry: FreqTableEntry) -> Result<()> {
        if self.freq_table_count >= MAX_FREQ_TABLE {
            return Err(Error::OutOfMemory);
        }
        self.freq_table[self.freq_table_count] = entry;
        self.freq_table_count += 1;
        Ok(())
    }
}

impl Default for CpuFreqPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Frequency transition notification.
#[derive(Clone, Copy)]
pub struct FreqTransition {
    /// CPU identifier.
    cpu_id: u32,
    /// Old frequency in kHz.
    old_freq: FreqKhz,
    /// New frequency in kHz.
    new_freq: FreqKhz,
    /// Timestamp of the transition.
    timestamp_ns: u64,
}

impl FreqTransition {
    /// Creates a new frequency transition record.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            old_freq: 0,
            new_freq: 0,
            timestamp_ns: 0,
        }
    }

    /// Returns the old frequency.
    pub const fn old_freq(&self) -> FreqKhz {
        self.old_freq
    }

    /// Returns the new frequency.
    pub const fn new_freq(&self) -> FreqKhz {
        self.new_freq
    }
}

impl Default for FreqTransition {
    fn default() -> Self {
        Self::new()
    }
}

/// CPU frequency scaling manager.
pub struct CpuFreqScalingManager {
    /// Scaling policies.
    policies: [CpuFreqPolicy; MAX_POLICIES],
    /// Number of active policies.
    policy_count: usize,
    /// Next policy ID.
    next_id: u32,
    /// Default governor for new policies.
    default_governor: Governor,
    /// Total frequency transitions system-wide.
    total_transitions: u64,
}

impl CpuFreqScalingManager {
    /// Creates a new CPU frequency scaling manager.
    pub const fn new() -> Self {
        Self {
            policies: [const { CpuFreqPolicy::new() }; MAX_POLICIES],
            policy_count: 0,
            next_id: 1,
            default_governor: Governor::Schedutil,
            total_transitions: 0,
        }
    }

    /// Creates a policy for a CPU.
    pub fn create_policy(
        &mut self,
        cpu_id: u32,
        min_freq: FreqKhz,
        max_freq: FreqKhz,
    ) -> Result<u32> {
        if self.policy_count >= MAX_POLICIES {
            return Err(Error::OutOfMemory);
        }
        if min_freq > max_freq {
            return Err(Error::InvalidArgument);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.policies[self.policy_count] = CpuFreqPolicy {
            id,
            cpu_id,
            current_freq: max_freq,
            min_freq,
            max_freq,
            cpuinfo_min_freq: min_freq,
            cpuinfo_max_freq: max_freq,
            governor: self.default_governor,
            freq_table: [const { FreqTableEntry::new() }; MAX_FREQ_TABLE],
            freq_table_count: 0,
            transition_count: 0,
            time_in_state_ns: 0,
            active: true,
        };
        self.policy_count += 1;
        Ok(id)
    }

    /// Sets the frequency for a CPU.
    pub fn set_frequency(&mut self, cpu_id: u32, freq: FreqKhz) -> Result<()> {
        for i in 0..self.policy_count {
            if self.policies[i].cpu_id == cpu_id && self.policies[i].active {
                if freq < self.policies[i].min_freq || freq > self.policies[i].max_freq {
                    return Err(Error::InvalidArgument);
                }
                self.policies[i].current_freq = freq;
                self.policies[i].transition_count += 1;
                self.total_transitions += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Gets the policy for a CPU.
    pub fn get_policy(&self, cpu_id: u32) -> Result<&CpuFreqPolicy> {
        self.policies[..self.policy_count]
            .iter()
            .find(|p| p.cpu_id == cpu_id && p.active)
            .ok_or(Error::NotFound)
    }

    /// Sets the default governor.
    pub fn set_default_governor(&mut self, gov: Governor) {
        self.default_governor = gov;
    }

    /// Returns the number of active policies.
    pub const fn policy_count(&self) -> usize {
        self.policy_count
    }

    /// Returns total system-wide transitions.
    pub const fn total_transitions(&self) -> u64 {
        self.total_transitions
    }
}

impl Default for CpuFreqScalingManager {
    fn default() -> Self {
        Self::new()
    }
}
