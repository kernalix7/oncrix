// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup Pressure Stall Information (PSI).
//!
//! Tracks resource contention metrics per cgroup, exposing how much
//! time tasks spend waiting for CPU, memory, and I/O resources.
//! PSI provides both running averages (10s, 60s, 300s) and total
//! stall time counters.
//!
//! # Metrics
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │                  PSI per cgroup                       │
//! │                                                      │
//! │  Resource    │ "some" (partial stall) │ "full" stall │
//! │ ─────────── │ ────────────────────── │ ──────────── │
//! │  CPU         │ avg10/60/300 + total   │ (N/A)        │
//! │  Memory      │ avg10/60/300 + total   │ avg + total  │
//! │  I/O         │ avg10/60/300 + total   │ avg + total  │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! # Triggers
//!
//! Users can register threshold-based triggers: "when resource
//! pressure exceeds X% for Y microseconds, send notification."
//!
//! # Reference
//!
//! Linux `kernel/sched/psi.c`, `include/linux/psi_types.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of cgroups tracked.
const MAX_CGROUPS: usize = 128;

/// Maximum number of triggers per cgroup.
const MAX_TRIGGERS_PER_CGROUP: usize = 8;

/// Number of averaging windows.
const NUM_AVG_WINDOWS: usize = 3;

/// Averaging window durations in seconds.
const AVG_WINDOWS_SECS: [u32; NUM_AVG_WINDOWS] = [10, 60, 300];

/// Number of resource types (CPU, Memory, IO).
const NUM_RESOURCE_TYPES: usize = 3;

/// PSI polling interval in milliseconds.
const _PSI_POLL_INTERVAL_MS: u64 = 2000;

/// Exponential decay factors (fixed-point, 16-bit fraction).
/// For a window of W seconds polled every 2s: factor = e^(-2/W).
/// 10s: e^(-0.2) ≈ 0.8187 → 53674
/// 60s: e^(-1/30) ≈ 0.9672 → 63396
/// 300s: e^(-1/150) ≈ 0.9934 → 65103
const DECAY_FACTORS: [u32; NUM_AVG_WINDOWS] = [53674, 63396, 65103];

/// Fixed-point shift for decay calculations.
const _DECAY_SHIFT: u32 = 16;

// ======================================================================
// Resource type
// ======================================================================

/// PSI-tracked resource type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsiResource {
    /// CPU scheduling contention.
    Cpu = 0,
    /// Memory allocation / reclaim pressure.
    Memory = 1,
    /// Block I/O pressure.
    Io = 2,
}

impl PsiResource {
    /// Converts from an index.
    pub fn from_index(idx: usize) -> Result<Self> {
        match idx {
            0 => Ok(Self::Cpu),
            1 => Ok(Self::Memory),
            2 => Ok(Self::Io),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Returns the index.
    pub fn index(self) -> usize {
        self as usize
    }
}

/// Stall type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallType {
    /// At least one task is stalled ("some").
    Some,
    /// All non-idle tasks are stalled ("full").
    Full,
}

// ======================================================================
// PSI statistics
// ======================================================================

/// Running averages for a single resource and stall type.
#[derive(Debug, Clone, Copy)]
pub struct PsiAvg {
    /// Running averages for 10s, 60s, 300s windows (percentage *
    /// 100, so 5000 = 50.00%).
    avg: [u32; NUM_AVG_WINDOWS],
    /// Total stall time in microseconds.
    total_us: u64,
}

impl PsiAvg {
    /// Creates zeroed averages.
    pub const fn new() -> Self {
        Self {
            avg: [0; NUM_AVG_WINDOWS],
            total_us: 0,
        }
    }

    /// Returns the 10-second average (percentage * 100).
    pub fn avg10(&self) -> u32 {
        self.avg[0]
    }

    /// Returns the 60-second average.
    pub fn avg60(&self) -> u32 {
        self.avg[1]
    }

    /// Returns the 300-second average.
    pub fn avg300(&self) -> u32 {
        self.avg[2]
    }

    /// Returns the total stall time in microseconds.
    pub fn total_us(&self) -> u64 {
        self.total_us
    }

    /// Updates the averages with a new sample.
    pub fn update(&mut self, stall_pct_x100: u32, delta_us: u64) {
        self.total_us = self.total_us.saturating_add(delta_us);
        for i in 0..NUM_AVG_WINDOWS {
            let factor = DECAY_FACTORS[i] as u64;
            let old = self.avg[i] as u64;
            let new_val = stall_pct_x100 as u64;
            // Exponential moving average:
            // avg = avg * decay + sample * (1 - decay)
            let decayed = (old * factor) >> 16;
            let contrib = (new_val * (65536 - factor as u64)) >> 16;
            self.avg[i] = (decayed + contrib) as u32;
        }
    }
}

/// Full PSI statistics for a single resource.
#[derive(Debug, Clone, Copy)]
pub struct PsiResourceStats {
    /// "some" stall averages.
    some: PsiAvg,
    /// "full" stall averages (not applicable for CPU).
    full: PsiAvg,
}

impl PsiResourceStats {
    /// Creates zeroed stats.
    pub const fn new() -> Self {
        Self {
            some: PsiAvg::new(),
            full: PsiAvg::new(),
        }
    }

    /// Returns the "some" averages.
    pub fn some(&self) -> &PsiAvg {
        &self.some
    }

    /// Returns the "full" averages.
    pub fn full(&self) -> &PsiAvg {
        &self.full
    }
}

/// Complete PSI stats for a cgroup (all resource types).
#[derive(Debug, Clone, Copy)]
pub struct PsiStats {
    /// Per-resource statistics.
    resources: [PsiResourceStats; NUM_RESOURCE_TYPES],
}

impl PsiStats {
    /// Creates zeroed PSI stats.
    pub const fn new() -> Self {
        Self {
            resources: [const { PsiResourceStats::new() }; NUM_RESOURCE_TYPES],
        }
    }

    /// Returns stats for a specific resource.
    pub fn resource(&self, res: PsiResource) -> &PsiResourceStats {
        &self.resources[res.index()]
    }
}

// ======================================================================
// PSI trigger
// ======================================================================

/// A PSI threshold trigger.
#[derive(Debug, Clone, Copy)]
pub struct PsiTrigger {
    /// Resource being monitored.
    resource: PsiResource,
    /// Stall type (some or full).
    stall_type: StallType,
    /// Threshold in percentage * 100 (e.g., 1000 = 10.00%).
    threshold_pct_x100: u32,
    /// Window in microseconds over which the threshold must be
    /// exceeded.
    window_us: u64,
    /// Whether this trigger is active.
    active: bool,
    /// Accumulated stall time in the current window.
    accum_us: u64,
    /// Window start timestamp in microseconds.
    window_start_us: u64,
    /// Number of times this trigger has fired.
    fire_count: u64,
    /// Whether the trigger has fired in the current window.
    fired: bool,
}

impl PsiTrigger {
    /// Creates an inactive trigger.
    pub const fn new() -> Self {
        Self {
            resource: PsiResource::Cpu,
            stall_type: StallType::Some,
            threshold_pct_x100: 0,
            window_us: 0,
            active: false,
            accum_us: 0,
            window_start_us: 0,
            fire_count: 0,
            fired: false,
        }
    }

    /// Creates an active trigger.
    pub fn with_threshold(
        resource: PsiResource,
        stall_type: StallType,
        threshold_pct_x100: u32,
        window_us: u64,
    ) -> Result<Self> {
        if threshold_pct_x100 == 0 || threshold_pct_x100 > 10000 {
            return Err(Error::InvalidArgument);
        }
        if window_us == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            resource,
            stall_type,
            threshold_pct_x100,
            window_us,
            active: true,
            accum_us: 0,
            window_start_us: 0,
            fire_count: 0,
            fired: false,
        })
    }

    /// Returns whether the trigger is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the fire count.
    pub fn fire_count(&self) -> u64 {
        self.fire_count
    }

    /// Evaluates the trigger with new stall data.
    pub fn evaluate(&mut self, now_us: u64, stall_delta_us: u64) -> bool {
        if !self.active {
            return false;
        }
        // Reset window if we've moved past it.
        if now_us.saturating_sub(self.window_start_us) >= self.window_us {
            self.window_start_us = now_us;
            self.accum_us = 0;
            self.fired = false;
        }
        self.accum_us = self.accum_us.saturating_add(stall_delta_us);
        // Check threshold: accum / window >= threshold / 10000.
        let scaled_accum = self.accum_us * 10000;
        let exceeded = scaled_accum >= self.threshold_pct_x100 as u64 * self.window_us;
        if exceeded && !self.fired {
            self.fired = true;
            self.fire_count = self.fire_count.saturating_add(1);
            return true;
        }
        false
    }

    /// Deactivates this trigger.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

// ======================================================================
// Per-cgroup PSI tracking
// ======================================================================

/// PSI tracking state for a single cgroup.
pub struct CgroupPsi {
    /// Cgroup ID.
    cgroup_id: u64,
    /// PSI statistics.
    stats: PsiStats,
    /// Triggers.
    triggers: [PsiTrigger; MAX_TRIGGERS_PER_CGROUP],
    /// Number of active triggers.
    nr_triggers: usize,
    /// Whether this cgroup slot is in use.
    active: bool,
    /// Last update timestamp in microseconds.
    last_update_us: u64,
    /// Per-resource raw stall accumulators (some, full) in us.
    raw_some: [u64; NUM_RESOURCE_TYPES],
    raw_full: [u64; NUM_RESOURCE_TYPES],
}

impl CgroupPsi {
    /// Creates an empty cgroup PSI state.
    pub const fn new() -> Self {
        Self {
            cgroup_id: 0,
            stats: PsiStats::new(),
            triggers: [const { PsiTrigger::new() }; MAX_TRIGGERS_PER_CGROUP],
            nr_triggers: 0,
            active: false,
            last_update_us: 0,
            raw_some: [0; NUM_RESOURCE_TYPES],
            raw_full: [0; NUM_RESOURCE_TYPES],
        }
    }

    /// Returns the cgroup ID.
    pub fn cgroup_id(&self) -> u64 {
        self.cgroup_id
    }

    /// Returns a reference to the PSI stats.
    pub fn stats(&self) -> &PsiStats {
        &self.stats
    }

    /// Adds a trigger.
    pub fn add_trigger(&mut self, trigger: PsiTrigger) -> Result<usize> {
        if self.nr_triggers >= MAX_TRIGGERS_PER_CGROUP {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .triggers
            .iter()
            .position(|t| !t.is_active())
            .ok_or(Error::OutOfMemory)?;
        self.triggers[slot] = trigger;
        self.nr_triggers += 1;
        Ok(slot)
    }

    /// Removes a trigger by slot index.
    pub fn remove_trigger(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_TRIGGERS_PER_CGROUP {
            return Err(Error::InvalidArgument);
        }
        if !self.triggers[slot].is_active() {
            return Err(Error::NotFound);
        }
        self.triggers[slot].deactivate();
        self.nr_triggers = self.nr_triggers.saturating_sub(1);
        Ok(())
    }

    /// Updates PSI stats with new stall samples.
    pub fn update(
        &mut self,
        now_us: u64,
        some_deltas: &[u64; NUM_RESOURCE_TYPES],
        full_deltas: &[u64; NUM_RESOURCE_TYPES],
    ) {
        let elapsed = now_us.saturating_sub(self.last_update_us);
        if elapsed == 0 {
            return;
        }
        self.last_update_us = now_us;
        for i in 0..NUM_RESOURCE_TYPES {
            self.raw_some[i] = self.raw_some[i].saturating_add(some_deltas[i]);
            self.raw_full[i] = self.raw_full[i].saturating_add(full_deltas[i]);
            // Convert to percentage * 100.
            let some_pct = if elapsed > 0 {
                ((some_deltas[i] * 10000) / elapsed.max(1)) as u32
            } else {
                0
            };
            let full_pct = if elapsed > 0 {
                ((full_deltas[i] * 10000) / elapsed.max(1)) as u32
            } else {
                0
            };
            self.stats.resources[i]
                .some
                .update(some_pct, some_deltas[i]);
            self.stats.resources[i]
                .full
                .update(full_pct, full_deltas[i]);
        }
        // Evaluate triggers.
        for t in &mut self.triggers {
            if t.is_active() {
                let res_idx = t.resource.index();
                let delta = match t.stall_type {
                    StallType::Some => some_deltas[res_idx],
                    StallType::Full => full_deltas[res_idx],
                };
                let _fired = t.evaluate(now_us, delta);
            }
        }
    }
}

// ======================================================================
// PSI manager
// ======================================================================

/// Global PSI manager tracking all cgroups.
pub struct PsiManager {
    /// Per-cgroup tracking state.
    cgroups: [CgroupPsi; MAX_CGROUPS],
    /// Number of active cgroups.
    count: usize,
    /// Global enable flag.
    enabled: bool,
}

impl PsiManager {
    /// Creates a new PSI manager.
    pub const fn new() -> Self {
        Self {
            cgroups: [const { CgroupPsi::new() }; MAX_CGROUPS],
            count: 0,
            enabled: true,
        }
    }

    /// Returns the number of tracked cgroups.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns whether PSI tracking is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sets the global enable flag.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Registers a cgroup for PSI tracking.
    pub fn register_cgroup(&mut self, cgroup_id: u64) -> Result<usize> {
        // Check for duplicate.
        for i in 0..MAX_CGROUPS {
            if self.cgroups[i].active && self.cgroups[i].cgroup_id == cgroup_id {
                return Err(Error::AlreadyExists);
            }
        }
        let slot = self
            .cgroups
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;
        self.cgroups[slot].cgroup_id = cgroup_id;
        self.cgroups[slot].active = true;
        self.cgroups[slot].stats = PsiStats::new();
        self.cgroups[slot].nr_triggers = 0;
        self.cgroups[slot].last_update_us = 0;
        self.cgroups[slot].raw_some = [0; NUM_RESOURCE_TYPES];
        self.cgroups[slot].raw_full = [0; NUM_RESOURCE_TYPES];
        self.count += 1;
        Ok(slot)
    }

    /// Unregisters a cgroup.
    pub fn unregister_cgroup(&mut self, cgroup_id: u64) -> Result<()> {
        let slot = self.find_cgroup(cgroup_id)?;
        self.cgroups[slot].active = false;
        self.count -= 1;
        Ok(())
    }

    /// Returns a reference to a cgroup's PSI state.
    pub fn get_cgroup(&self, cgroup_id: u64) -> Result<&CgroupPsi> {
        let slot = self.find_cgroup(cgroup_id)?;
        Ok(&self.cgroups[slot])
    }

    /// Updates a cgroup's PSI state.
    pub fn update_cgroup(
        &mut self,
        cgroup_id: u64,
        now_us: u64,
        some_deltas: &[u64; NUM_RESOURCE_TYPES],
        full_deltas: &[u64; NUM_RESOURCE_TYPES],
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let slot = self.find_cgroup(cgroup_id)?;
        self.cgroups[slot].update(now_us, some_deltas, full_deltas);
        Ok(())
    }

    /// Adds a trigger to a cgroup.
    pub fn add_trigger(&mut self, cgroup_id: u64, trigger: PsiTrigger) -> Result<usize> {
        let slot = self.find_cgroup(cgroup_id)?;
        self.cgroups[slot].add_trigger(trigger)
    }

    /// Removes a trigger from a cgroup.
    pub fn remove_trigger(&mut self, cgroup_id: u64, trigger_slot: usize) -> Result<()> {
        let slot = self.find_cgroup(cgroup_id)?;
        self.cgroups[slot].remove_trigger(trigger_slot)
    }

    /// Finds a cgroup slot by ID.
    fn find_cgroup(&self, cgroup_id: u64) -> Result<usize> {
        for i in 0..MAX_CGROUPS {
            if self.cgroups[i].active && self.cgroups[i].cgroup_id == cgroup_id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }
}
