// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU frequency governor subsystem (DVFS — Dynamic Voltage and Frequency Scaling).
//!
//! Implements a set of governors that control how the CPU frequency is adjusted
//! in response to system load. The governor logic runs on each scheduler tick and
//! selects a new operating frequency within the policy constraints.
//!
//! # Governors
//!
//! | Governor     | Strategy                                          |
//! |--------------|---------------------------------------------------|
//! | Performance  | Always pin frequency to policy maximum            |
//! | Powersave    | Always pin frequency to policy minimum            |
//! | Ondemand     | Scale up aggressively on load, scale down lazily  |
//! | Conservative | Step up/down gradually to avoid frequency thrash  |
//! | Schedutil    | Use scheduler utilization signal for target freq  |
//!
//! Reference: Linux kernel `drivers/cpufreq/` documentation.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of CPUs tracked by the subsystem.
const MAX_CPUS: usize = 8;

/// Number of discrete frequency states tracked for statistics.
const FREQ_STATES: usize = 8;

/// Default ondemand up-threshold percentage (80 %).
const ONDEMAND_DEFAULT_UP_THRESHOLD: u8 = 80;

/// Default ondemand sampling rate in microseconds (50 ms).
const ONDEMAND_DEFAULT_SAMPLING_RATE_US: u64 = 50_000;

/// Default conservative up-threshold percentage (80 %).
const CONSERVATIVE_DEFAULT_UP_THRESHOLD: u8 = 80;

/// Default conservative down-threshold percentage (20 %).
const CONSERVATIVE_DEFAULT_DOWN_THRESHOLD: u8 = 20;

/// Default conservative frequency step percentage (5 %).
const CONSERVATIVE_DEFAULT_FREQ_STEP: u8 = 5;

/// Minimum frequency step for conservative governor (1 MHz in KHz).
const MIN_FREQ_STEP_KHZ: u32 = 1_000;

// ---------------------------------------------------------------------------
// CpufreqGovernor
// ---------------------------------------------------------------------------

/// Active frequency scaling governor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpufreqGovernor {
    /// Always run at the policy maximum frequency.
    Performance,
    /// Always run at the policy minimum frequency.
    Powersave,
    /// Scale up quickly on high load; scale down gradually.
    Ondemand,
    /// Step frequency up or down conservatively.
    Conservative,
    /// Use kernel scheduler utilization hints.
    Schedutil,
}

impl Default for CpufreqGovernor {
    fn default() -> Self {
        Self::Ondemand
    }
}

// ---------------------------------------------------------------------------
// OndemandTunable
// ---------------------------------------------------------------------------

/// Tunable parameters for the Ondemand governor.
#[derive(Debug, Clone, Copy)]
pub struct OndemandTunable {
    /// Load threshold above which frequency is raised to maximum (0–100).
    pub up_threshold: u8,
    /// Sampling interval in microseconds between load evaluations.
    pub sampling_rate_us: u64,
    /// If true, discount CPU cycles spent in idle tasks when computing load.
    pub ignore_nice_load: bool,
}

impl OndemandTunable {
    /// Create an `OndemandTunable` with default values.
    pub const fn new() -> Self {
        Self {
            up_threshold: ONDEMAND_DEFAULT_UP_THRESHOLD,
            sampling_rate_us: ONDEMAND_DEFAULT_SAMPLING_RATE_US,
            ignore_nice_load: false,
        }
    }

    /// Validate that the tunable values are in range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `up_threshold` is zero or
    /// greater than 100, or if `sampling_rate_us` is zero.
    pub fn validate(&self) -> Result<()> {
        if self.up_threshold == 0 || self.up_threshold > 100 {
            return Err(Error::InvalidArgument);
        }
        if self.sampling_rate_us == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for OndemandTunable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ConservativeTunable
// ---------------------------------------------------------------------------

/// Tunable parameters for the Conservative governor.
#[derive(Debug, Clone, Copy)]
pub struct ConservativeTunable {
    /// Load threshold above which frequency is stepped up (0–100).
    pub up_threshold: u8,
    /// Load threshold below which frequency is stepped down (0–100).
    pub down_threshold: u8,
    /// Percentage of the frequency range to step per tick (1–100).
    pub freq_step: u8,
}

impl ConservativeTunable {
    /// Create a `ConservativeTunable` with default values.
    pub const fn new() -> Self {
        Self {
            up_threshold: CONSERVATIVE_DEFAULT_UP_THRESHOLD,
            down_threshold: CONSERVATIVE_DEFAULT_DOWN_THRESHOLD,
            freq_step: CONSERVATIVE_DEFAULT_FREQ_STEP,
        }
    }

    /// Validate that the tunable values are internally consistent.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if thresholds or step are
    /// out of range, or if `down_threshold >= up_threshold`.
    pub fn validate(&self) -> Result<()> {
        if self.up_threshold == 0 || self.up_threshold > 100 {
            return Err(Error::InvalidArgument);
        }
        if self.down_threshold == 0 || self.down_threshold > 100 {
            return Err(Error::InvalidArgument);
        }
        if self.down_threshold >= self.up_threshold {
            return Err(Error::InvalidArgument);
        }
        if self.freq_step == 0 || self.freq_step > 100 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for ConservativeTunable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CpufreqPolicy
// ---------------------------------------------------------------------------

/// Per-CPU frequency policy describing the operating constraints.
#[derive(Debug, Clone, Copy)]
pub struct CpufreqPolicy {
    /// Minimum allowed frequency in KHz.
    pub min_freq_khz: u32,
    /// Maximum allowed frequency in KHz.
    pub max_freq_khz: u32,
    /// Current operating frequency in KHz.
    pub cur_freq_khz: u32,
    /// Active governor for this policy.
    pub governor: CpufreqGovernor,
    /// Hardware transition latency in nanoseconds (used by governor heuristics).
    pub transition_latency_ns: u32,
    /// Whether this policy slot is in use.
    pub valid: bool,
}

impl CpufreqPolicy {
    /// Create a new policy with the given frequency bounds and governor.
    ///
    /// The current frequency is initialised to `max_freq_khz`.
    pub const fn new(
        min_freq_khz: u32,
        max_freq_khz: u32,
        governor: CpufreqGovernor,
        transition_latency_ns: u32,
    ) -> Self {
        Self {
            min_freq_khz,
            max_freq_khz,
            cur_freq_khz: max_freq_khz,
            governor,
            transition_latency_ns,
            valid: false,
        }
    }

    /// Clamp `freq` to the `[min_freq_khz, max_freq_khz]` range.
    pub fn clamp_freq(&self, freq: u32) -> u32 {
        freq.max(self.min_freq_khz).min(self.max_freq_khz)
    }

    /// Return the frequency range width in KHz (max − min).
    pub fn freq_range_khz(&self) -> u32 {
        self.max_freq_khz.saturating_sub(self.min_freq_khz)
    }
}

impl Default for CpufreqPolicy {
    fn default() -> Self {
        Self::new(1_000_000, 4_000_000, CpufreqGovernor::Ondemand, 10_000)
    }
}

// ---------------------------------------------------------------------------
// CpufreqStats
// ---------------------------------------------------------------------------

/// Cumulative statistics for a CPU frequency policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpufreqStats {
    /// Total number of frequency transitions performed.
    pub freq_transitions: u64,
    /// Approximate time spent in each of the tracked frequency states (ticks).
    pub time_in_state: [u64; FREQ_STATES],
}

impl CpufreqStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            freq_transitions: 0,
            time_in_state: [0u64; FREQ_STATES],
        }
    }

    /// Record a transition and a tick in the given state bucket.
    ///
    /// `state_idx` is silently clamped to `[0, FREQ_STATES - 1]`.
    pub fn record_transition(&mut self, state_idx: usize) {
        self.freq_transitions = self.freq_transitions.saturating_add(1);
        let idx = state_idx.min(FREQ_STATES - 1);
        self.time_in_state[idx] = self.time_in_state[idx].saturating_add(1);
    }

    /// Record a tick without a transition.
    pub fn record_tick(&mut self, state_idx: usize) {
        let idx = state_idx.min(FREQ_STATES - 1);
        self.time_in_state[idx] = self.time_in_state[idx].saturating_add(1);
    }
}

// ---------------------------------------------------------------------------
// CpufreqGovernorSubsystem
// ---------------------------------------------------------------------------

/// Per-CPU governor state managed by the subsystem.
struct CpuEntry {
    policy: CpufreqPolicy,
    ondemand: OndemandTunable,
    conservative: ConservativeTunable,
    stats: CpufreqStats,
}

impl CpuEntry {
    const fn new() -> Self {
        Self {
            policy: CpufreqPolicy::new(1_000_000, 4_000_000, CpufreqGovernor::Ondemand, 10_000),
            ondemand: OndemandTunable::new(),
            conservative: ConservativeTunable::new(),
            stats: CpufreqStats::new(),
        }
    }
}

/// CPU frequency governor subsystem managing up to [`MAX_CPUS`] CPUs.
pub struct CpufreqGovernorSubsystem {
    cpus: [CpuEntry; MAX_CPUS],
    cpu_count: usize,
}

impl CpufreqGovernorSubsystem {
    /// Create a new, uninitialised subsystem.
    pub const fn new() -> Self {
        Self {
            cpus: [const { CpuEntry::new() }; MAX_CPUS],
            cpu_count: 0,
        }
    }

    /// Register a CPU with the given initial policy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum number of CPUs
    /// has been reached, or [`Error::InvalidArgument`] if the policy
    /// frequencies are invalid (min > max, or max is zero).
    pub fn register_cpu(&mut self, policy: CpufreqPolicy) -> Result<usize> {
        if self.cpu_count >= MAX_CPUS {
            return Err(Error::OutOfMemory);
        }
        if policy.max_freq_khz == 0 || policy.min_freq_khz > policy.max_freq_khz {
            return Err(Error::InvalidArgument);
        }
        let idx = self.cpu_count;
        self.cpus[idx].policy = policy;
        self.cpus[idx].policy.valid = true;
        self.cpu_count += 1;
        Ok(idx)
    }

    /// Set the governor for a CPU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu` is out of range or
    /// the policy slot is not valid.
    pub fn set_governor(&mut self, cpu: usize, gov: CpufreqGovernor) -> Result<()> {
        let entry = self.cpu_entry_mut(cpu)?;
        entry.policy.governor = gov;
        // When switching to Performance or Powersave, snap frequency immediately.
        match gov {
            CpufreqGovernor::Performance => {
                entry.policy.cur_freq_khz = entry.policy.max_freq_khz;
            }
            CpufreqGovernor::Powersave => {
                entry.policy.cur_freq_khz = entry.policy.min_freq_khz;
            }
            _ => {}
        }
        Ok(())
    }

    /// Set the operating frequency of a CPU, clamping to policy bounds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu` is out of range.
    pub fn set_freq(&mut self, cpu: usize, freq_khz: u32) -> Result<()> {
        let entry = self.cpu_entry_mut(cpu)?;
        entry.policy.cur_freq_khz = entry.policy.clamp_freq(freq_khz);
        Ok(())
    }

    /// Read the current operating frequency for a CPU in KHz.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu` is out of range.
    pub fn get_freq(&self, cpu: usize) -> Result<u32> {
        Ok(self.cpu_entry(cpu)?.policy.cur_freq_khz)
    }

    /// Set the Ondemand tunable for a CPU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu` is out of range or
    /// the tunable values fail validation.
    pub fn set_ondemand_tunable(&mut self, cpu: usize, t: OndemandTunable) -> Result<()> {
        t.validate()?;
        self.cpu_entry_mut(cpu)?.ondemand = t;
        Ok(())
    }

    /// Set the Conservative tunable for a CPU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu` is out of range or
    /// the tunable values fail validation.
    pub fn set_conservative_tunable(&mut self, cpu: usize, t: ConservativeTunable) -> Result<()> {
        t.validate()?;
        self.cpu_entry_mut(cpu)?.conservative = t;
        Ok(())
    }

    /// Return a snapshot of the frequency statistics for a CPU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu` is out of range.
    pub fn stats(&self, cpu: usize) -> Result<CpufreqStats> {
        Ok(self.cpu_entry(cpu)?.stats)
    }

    /// Return the number of registered CPUs.
    pub fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    // -----------------------------------------------------------------------
    // Governor tick
    // -----------------------------------------------------------------------

    /// Execute a governor tick for a CPU given a current load percentage.
    ///
    /// Applies the active governor policy to compute a new target frequency
    /// and updates `cur_freq_khz` and statistics accordingly.
    ///
    /// `load_percent` is the instantaneous CPU utilisation in the range 0–100.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu` is out of range, or
    /// [`Error::InvalidArgument`] if `load_percent` exceeds 100.
    pub fn governor_tick(&mut self, cpu: usize, load_percent: u8) -> Result<()> {
        if load_percent > 100 {
            return Err(Error::InvalidArgument);
        }

        // Validate cpu index before proceeding.
        if cpu >= self.cpu_count || !self.cpus[cpu].policy.valid {
            return Err(Error::InvalidArgument);
        }

        let gov = self.cpus[cpu].policy.governor;
        let new_freq = match gov {
            CpufreqGovernor::Performance => self.cpus[cpu].policy.max_freq_khz,
            CpufreqGovernor::Powersave => self.cpus[cpu].policy.min_freq_khz,
            CpufreqGovernor::Ondemand => self.tick_ondemand(cpu, load_percent),
            CpufreqGovernor::Conservative => self.tick_conservative(cpu, load_percent),
            CpufreqGovernor::Schedutil => self.tick_schedutil(cpu, load_percent),
        };

        let old_freq = self.cpus[cpu].policy.cur_freq_khz;
        let clamped = self.cpus[cpu].policy.clamp_freq(new_freq);
        self.cpus[cpu].policy.cur_freq_khz = clamped;

        // Compute state index from current frequency position in range.
        let state_idx = self.freq_state_index(cpu, clamped);
        if clamped != old_freq {
            self.cpus[cpu].stats.record_transition(state_idx);
        } else {
            self.cpus[cpu].stats.record_tick(state_idx);
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn cpu_entry(&self, cpu: usize) -> Result<&CpuEntry> {
        if cpu >= self.cpu_count || !self.cpus[cpu].policy.valid {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.cpus[cpu])
    }

    fn cpu_entry_mut(&mut self, cpu: usize) -> Result<&mut CpuEntry> {
        if cpu >= self.cpu_count || !self.cpus[cpu].policy.valid {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.cpus[cpu])
    }

    /// Ondemand tick: jump to max on high load, drop to proportional otherwise.
    fn tick_ondemand(&self, cpu: usize, load: u8) -> u32 {
        let entry = &self.cpus[cpu];
        if load >= entry.ondemand.up_threshold {
            entry.policy.max_freq_khz
        } else {
            // Scale proportionally to load within the frequency range.
            let range = entry.policy.freq_range_khz();
            let step = (range as u64)
                .saturating_mul(load as u64)
                .saturating_div(100) as u32;
            entry.policy.min_freq_khz.saturating_add(step)
        }
    }

    /// Conservative tick: step up or down by `freq_step` % of range.
    fn tick_conservative(&self, cpu: usize, load: u8) -> u32 {
        let entry = &self.cpus[cpu];
        let range = entry.policy.freq_range_khz();
        let step_khz = ((range as u64)
            .saturating_mul(entry.conservative.freq_step as u64)
            .saturating_div(100) as u32)
            .max(MIN_FREQ_STEP_KHZ);
        let cur = entry.policy.cur_freq_khz;

        if load >= entry.conservative.up_threshold {
            cur.saturating_add(step_khz)
        } else if load < entry.conservative.down_threshold {
            cur.saturating_sub(step_khz)
        } else {
            cur
        }
    }

    /// Schedutil tick: target = min + range * (load / 100) * 1.25, capped at max.
    fn tick_schedutil(&self, cpu: usize, load: u8) -> u32 {
        let entry = &self.cpus[cpu];
        // Apply a 1.25x utilisation headroom (multiply by 5/4).
        let util_with_headroom = (load as u64).saturating_mul(5).saturating_div(4).min(100);
        let range = entry.policy.freq_range_khz();
        let step = (range as u64)
            .saturating_mul(util_with_headroom)
            .saturating_div(100) as u32;
        entry.policy.min_freq_khz.saturating_add(step)
    }

    /// Map a frequency to a state bucket index for statistics.
    fn freq_state_index(&self, cpu: usize, freq_khz: u32) -> usize {
        let entry = &self.cpus[cpu];
        let range = entry.policy.freq_range_khz();
        if range == 0 {
            return 0;
        }
        let offset = freq_khz.saturating_sub(entry.policy.min_freq_khz);
        let idx = (offset as u64)
            .saturating_mul(FREQ_STATES as u64)
            .saturating_div(range as u64 + 1) as usize;
        idx.min(FREQ_STATES - 1)
    }
}

impl Default for CpufreqGovernorSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
