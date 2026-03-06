// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU frequency scaling subsystem.
//!
//! Provides abstractions for controlling CPU operating frequency and voltage,
//! implementing a Linux-style cpufreq framework adapted for a no_std microkernel.
//!
//! # Architecture
//!
//! - [`FrequencyKhz`] — newtype wrapper around kHz frequency values.
//! - [`FreqTable`] — table of supported frequencies for a CPU (max 32 entries).
//! - [`Governor`] — frequency scaling policy algorithm.
//! - [`CpuFreqPolicy`] — per-CPU policy: frequency range, current freq, governor.
//! - [`ScalingDriver`] — trait implemented by hardware-specific frequency drivers.
//! - [`TransitionNotifier`] — pre/post transition callback hooks.
//! - [`CpuFreqRegistry`] — manages per-CPU policies (max 64 CPUs).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of frequency entries in a [`FreqTable`].
const MAX_FREQ_ENTRIES: usize = 32;

/// Maximum number of CPUs tracked in [`CpuFreqRegistry`].
const MAX_CPUS: usize = 64;

/// Utilization threshold (percent) for ondemand governor upscaling.
const ONDEMAND_UP_THRESHOLD: u32 = 80;

/// Utilization threshold (percent) for ondemand governor downscaling.
const ONDEMAND_DOWN_THRESHOLD: u32 = 20;

// -------------------------------------------------------------------
// FrequencyKhz
// -------------------------------------------------------------------

/// CPU frequency expressed in kilohertz (kHz).
///
/// This newtype prevents accidental mixing of frequency units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct FrequencyKhz(pub u32);

impl FrequencyKhz {
    /// Returns the raw kHz value.
    #[inline]
    pub const fn as_khz(self) -> u32 {
        self.0
    }

    /// Returns the frequency in MHz (truncated).
    #[inline]
    pub const fn as_mhz(self) -> u32 {
        self.0 / 1_000
    }
}

// -------------------------------------------------------------------
// FreqTable
// -------------------------------------------------------------------

/// Table of supported frequencies for a single CPU.
///
/// Entries are stored in ascending order. Holds at most
/// [`MAX_FREQ_ENTRIES`] (32) frequency values.
#[derive(Debug, Clone, Copy)]
pub struct FreqTable {
    /// Frequency entries sorted in ascending order.
    entries: [FrequencyKhz; MAX_FREQ_ENTRIES],
    /// Number of valid entries.
    count: usize,
}

impl Default for FreqTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FreqTable {
    /// Creates an empty frequency table.
    pub const fn new() -> Self {
        Self {
            entries: [FrequencyKhz(0); MAX_FREQ_ENTRIES],
            count: 0,
        }
    }

    /// Inserts a frequency into the table, maintaining ascending order.
    ///
    /// Returns [`Error::OutOfMemory`] when the table is full, or
    /// [`Error::AlreadyExists`] if the frequency is already present.
    pub fn insert(&mut self, freq: FrequencyKhz) -> Result<()> {
        if self.count >= MAX_FREQ_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        for e in &self.entries[..self.count] {
            if *e == freq {
                return Err(Error::AlreadyExists);
            }
        }
        self.entries[self.count] = freq;
        self.count += 1;
        // Insertion-sort to keep ascending order.
        let mut i = self.count - 1;
        while i > 0 && self.entries[i] < self.entries[i - 1] {
            self.entries.swap(i, i - 1);
            i -= 1;
        }
        Ok(())
    }

    /// Returns a slice of the valid frequency entries.
    pub fn as_slice(&self) -> &[FrequencyKhz] {
        &self.entries[..self.count]
    }

    /// Returns the number of entries in the table.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the minimum (lowest) frequency, or `None` if empty.
    pub fn min_freq(&self) -> Option<FrequencyKhz> {
        if self.count == 0 {
            None
        } else {
            Some(self.entries[0])
        }
    }

    /// Returns the maximum (highest) frequency, or `None` if empty.
    pub fn max_freq(&self) -> Option<FrequencyKhz> {
        if self.count == 0 {
            None
        } else {
            Some(self.entries[self.count - 1])
        }
    }

    /// Finds the nearest available frequency to `target`.
    ///
    /// Returns the closest entry in kHz distance. Returns `None` if
    /// the table is empty.
    pub fn nearest(&self, target: FrequencyKhz) -> Option<FrequencyKhz> {
        if self.count == 0 {
            return None;
        }
        let mut best = self.entries[0];
        let mut best_dist = target.0.abs_diff(best.0);
        for &e in &self.entries[1..self.count] {
            let dist = target.0.abs_diff(e.0);
            if dist < best_dist {
                best = e;
                best_dist = dist;
            }
        }
        Some(best)
    }
}

// -------------------------------------------------------------------
// Governor
// -------------------------------------------------------------------

/// CPU frequency scaling governor (policy algorithm).
///
/// Determines how the frequency is selected given system load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Governor {
    /// Always run at maximum available frequency.
    #[default]
    Performance,
    /// Always run at minimum available frequency.
    Powersave,
    /// Scale frequency dynamically based on CPU utilization.
    Ondemand,
    /// Scale conservatively — slower to increase, quicker to decrease.
    Conservative,
    /// Allow user space to manually set the frequency.
    Userspace,
}

// -------------------------------------------------------------------
// CpuFreqPolicy
// -------------------------------------------------------------------

/// CPU frequency scaling policy for a single logical CPU.
#[derive(Debug, Clone, Copy)]
pub struct CpuFreqPolicy {
    /// Logical CPU identifier.
    pub cpu_id: u32,
    /// Minimum allowed frequency (kHz).
    pub min_freq: FrequencyKhz,
    /// Maximum allowed frequency (kHz).
    pub max_freq: FrequencyKhz,
    /// Current operating frequency (kHz).
    pub cur_freq: FrequencyKhz,
    /// Active governor.
    pub governor: Governor,
    /// Available frequencies for this CPU.
    pub freq_table: FreqTable,
    /// Tracked CPU utilization percentage (0–100) for Ondemand.
    pub utilization_pct: u32,
}

impl CpuFreqPolicy {
    /// Creates a new policy for `cpu_id` with the given frequency
    /// range and governor.
    ///
    /// `cur_freq` is initialised to `min_freq`.
    pub fn new(cpu_id: u32, min_freq: FrequencyKhz, max_freq: FrequencyKhz) -> Self {
        Self {
            cpu_id,
            min_freq,
            max_freq,
            cur_freq: min_freq,
            governor: Governor::Performance,
            freq_table: FreqTable::new(),
            utilization_pct: 0,
        }
    }

    /// Clamps `freq` to the policy's [min_freq, max_freq] range.
    pub fn clamp_freq(&self, freq: FrequencyKhz) -> FrequencyKhz {
        if freq < self.min_freq {
            self.min_freq
        } else if freq > self.max_freq {
            self.max_freq
        } else {
            freq
        }
    }
}

// -------------------------------------------------------------------
// ScalingDriver
// -------------------------------------------------------------------

/// Trait implemented by hardware-specific CPU frequency drivers.
pub trait ScalingDriver {
    /// Set the operating frequency for `cpu_id` to `freq_khz`.
    ///
    /// The driver may snap to the nearest available frequency.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the frequency is out
    /// of the hardware's supported range, or [`Error::IoError`] on
    /// hardware communication failure.
    fn set_frequency(&mut self, cpu_id: u32, freq: FrequencyKhz) -> Result<FrequencyKhz>;

    /// Query the current operating frequency for `cpu_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the hardware query fails.
    fn get_frequency(&self, cpu_id: u32) -> Result<FrequencyKhz>;

    /// Populate `table` with all frequencies supported by `cpu_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the hardware query fails, or
    /// [`Error::OutOfMemory`] if the table is too small.
    fn get_available_frequencies(&self, cpu_id: u32, table: &mut FreqTable) -> Result<()>;
}

// -------------------------------------------------------------------
// TransitionNotifier
// -------------------------------------------------------------------

/// Callback hooks invoked around frequency transitions.
pub trait TransitionNotifier {
    /// Called immediately before the frequency transition begins.
    ///
    /// `old_freq` is the current frequency; `new_freq` is the
    /// target. The callback may return [`Error::InvalidArgument`]
    /// to veto the transition.
    fn pre_change(
        &mut self,
        cpu_id: u32,
        old_freq: FrequencyKhz,
        new_freq: FrequencyKhz,
    ) -> Result<()>;

    /// Called immediately after the frequency transition completes.
    ///
    /// `old_freq` is the frequency before the change; `new_freq` is
    /// the frequency now in effect.
    fn post_change(&mut self, cpu_id: u32, old_freq: FrequencyKhz, new_freq: FrequencyKhz);
}

// -------------------------------------------------------------------
// OndemandState
// -------------------------------------------------------------------

/// Per-policy state for the Ondemand governor.
#[derive(Debug, Clone, Copy, Default)]
pub struct OndemandState {
    /// Accumulated busy ticks since last frequency evaluation.
    pub busy_ticks: u64,
    /// Total ticks since last frequency evaluation.
    pub total_ticks: u64,
    /// Sampling interval counter.
    pub sample_count: u32,
}

impl OndemandState {
    /// Compute the next target frequency given the policy's current
    /// utilization percentage and frequency table.
    ///
    /// - If utilization >= [`ONDEMAND_UP_THRESHOLD`], selects max
    ///   frequency within policy limits.
    /// - If utilization <= [`ONDEMAND_DOWN_THRESHOLD`], selects min
    ///   frequency within policy limits.
    /// - Otherwise, scales linearly between min and max.
    pub fn compute_target(&self, policy: &CpuFreqPolicy) -> FrequencyKhz {
        let util = policy.utilization_pct;
        if util >= ONDEMAND_UP_THRESHOLD {
            policy.max_freq
        } else if util <= ONDEMAND_DOWN_THRESHOLD {
            policy.min_freq
        } else {
            // Linear interpolation between min and max.
            let range = policy.max_freq.0.saturating_sub(policy.min_freq.0);
            let scaled = range.saturating_mul(util) / 100;
            let raw = policy.min_freq.0.saturating_add(scaled);
            // Snap to nearest entry in the freq table if available.
            let candidate = FrequencyKhz(raw);
            policy
                .freq_table
                .nearest(candidate)
                .unwrap_or(policy.clamp_freq(candidate))
        }
    }
}

// -------------------------------------------------------------------
// CpuFreqRegistry
// -------------------------------------------------------------------

/// Registry of per-CPU frequency scaling policies.
///
/// Manages up to [`MAX_CPUS`] (64) CPU policies.
pub struct CpuFreqRegistry {
    /// Per-CPU policies; `None` when a CPU is not registered.
    policies: [Option<CpuFreqPolicy>; MAX_CPUS],
    /// Number of registered CPUs.
    count: usize,
    /// Per-policy ondemand governor state.
    ondemand: [OndemandState; MAX_CPUS],
}

impl Default for CpuFreqRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuFreqRegistry {
    /// Creates a new, empty registry.
    pub const fn new() -> Self {
        Self {
            policies: [const { None }; MAX_CPUS],
            count: 0,
            ondemand: [OndemandState {
                busy_ticks: 0,
                total_ticks: 0,
                sample_count: 0,
            }; MAX_CPUS],
        }
    }

    /// Registers a CPU policy.
    ///
    /// Returns [`Error::AlreadyExists`] if a policy for `cpu_id`
    /// is already registered, or [`Error::OutOfMemory`] if the
    /// registry is full.
    pub fn register(&mut self, policy: CpuFreqPolicy) -> Result<()> {
        let idx = policy.cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.policies[idx].is_some() {
            return Err(Error::AlreadyExists);
        }
        self.policies[idx] = Some(policy);
        self.count += 1;
        Ok(())
    }

    /// Unregisters the policy for `cpu_id`.
    ///
    /// Returns [`Error::NotFound`] if no policy for that CPU exists.
    pub fn unregister(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS || self.policies[idx].is_none() {
            return Err(Error::NotFound);
        }
        self.policies[idx] = None;
        self.count -= 1;
        Ok(())
    }

    /// Returns an immutable reference to the policy for `cpu_id`.
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_policy(&self, cpu_id: u32) -> Result<&CpuFreqPolicy> {
        let idx = cpu_id as usize;
        if idx < MAX_CPUS {
            self.policies[idx].as_ref().ok_or(Error::NotFound)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Returns a mutable reference to the policy for `cpu_id`.
    fn get_policy_mut(&mut self, cpu_id: u32) -> Result<&mut CpuFreqPolicy> {
        let idx = cpu_id as usize;
        if idx < MAX_CPUS {
            self.policies[idx].as_mut().ok_or(Error::NotFound)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Sets the governor for the given CPU.
    ///
    /// Returns [`Error::NotFound`] if the CPU is not registered.
    pub fn set_governor(&mut self, cpu_id: u32, governor: Governor) -> Result<()> {
        let policy = self.get_policy_mut(cpu_id)?;
        policy.governor = governor;
        Ok(())
    }

    /// Requests a frequency change for `cpu_id`.
    ///
    /// The target is clamped to the policy's [min, max] range and
    /// snapped to the nearest table entry. The policy's `cur_freq`
    /// is updated to the returned value.
    ///
    /// When the governor is [`Governor::Userspace`] any frequency in
    /// range is accepted; other governors ignore direct calls (use
    /// [`evaluate_governor`](Self::evaluate_governor) instead).
    ///
    /// Returns [`Error::NotFound`] if the CPU is not registered, or
    /// [`Error::PermissionDenied`] if the active governor is not
    /// Userspace.
    pub fn set_frequency(&mut self, cpu_id: u32, freq: FrequencyKhz) -> Result<FrequencyKhz> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::NotFound);
        }
        let policy = self.policies[idx].as_mut().ok_or(Error::NotFound)?;
        if policy.governor != Governor::Userspace {
            return Err(Error::PermissionDenied);
        }
        let clamped = policy.clamp_freq(freq);
        let target = policy.freq_table.nearest(clamped).unwrap_or(clamped);
        let target = policy.clamp_freq(target);
        policy.cur_freq = target;
        Ok(target)
    }

    /// Evaluates the active governor for `cpu_id` and returns the
    /// computed target frequency.
    ///
    /// For [`Governor::Ondemand`] and [`Governor::Conservative`],
    /// this uses the current `utilization_pct` from the policy.
    /// The policy's `cur_freq` is updated.
    ///
    /// Returns [`Error::NotFound`] if the CPU is not registered.
    pub fn evaluate_governor(&mut self, cpu_id: u32) -> Result<FrequencyKhz> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::NotFound);
        }
        let policy = self.policies[idx].as_ref().ok_or(Error::NotFound)?;
        let governor = policy.governor;
        let target = match governor {
            Governor::Performance => policy.max_freq,
            Governor::Powersave => policy.min_freq,
            Governor::Ondemand => {
                let od = &self.ondemand[idx];
                od.compute_target(policy)
            }
            Governor::Conservative => {
                // Conservative: step up or down by at most one table entry.
                let util = policy.utilization_pct;
                let cur = policy.cur_freq;
                let table = policy.freq_table;
                let entries = table.as_slice();
                if entries.is_empty() {
                    policy.clamp_freq(cur)
                } else if util >= ONDEMAND_UP_THRESHOLD {
                    // Move up one step.
                    let next = entries.iter().find(|&&e| e > cur).copied();
                    policy.clamp_freq(next.unwrap_or(policy.max_freq))
                } else if util <= ONDEMAND_DOWN_THRESHOLD {
                    // Move down one step.
                    let prev = entries.iter().rfind(|&&e| e < cur).copied();
                    policy.clamp_freq(prev.unwrap_or(policy.min_freq))
                } else {
                    cur
                }
            }
            Governor::Userspace => policy.cur_freq,
        };
        // Apply the computed target.
        let policy = self.policies[idx].as_mut().ok_or(Error::NotFound)?;
        let target = policy.clamp_freq(target);
        policy.cur_freq = target;
        Ok(target)
    }

    /// Updates the CPU utilization hint for Ondemand/Conservative
    /// governors.
    ///
    /// `utilization_pct` must be in the range 0–100. Values outside
    /// this range are clamped.
    ///
    /// Returns [`Error::NotFound`] if the CPU is not registered.
    pub fn update_utilization(&mut self, cpu_id: u32, utilization_pct: u32) -> Result<()> {
        let policy = self.get_policy_mut(cpu_id)?;
        policy.utilization_pct = utilization_pct.min(100);
        Ok(())
    }

    /// Returns the number of registered CPU policies.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no CPU policies are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
