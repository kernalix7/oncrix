// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Data Access Monitoring (DAMON) core framework.
//!
//! DAMON is an access-pattern monitoring framework that samples memory
//! access patterns with adaptive region granularity. The core engine
//! drives monitoring by maintaining a list of target address regions,
//! periodically sampling their access state, and merging/splitting
//! regions to track working-set changes efficiently.
//!
//! # Design
//!
//! ```text
//! ┌─────────────┐    ┌─────────────┐    ┌────────────┐
//! │  DamonCtx    │───▶│ DamonTarget │───▶│ DamonRegion│
//! │ (context)    │    │ (process)   │    │ (addr range│
//! │              │    │             │    │  + accesses)│
//! └──────┬───────┘    └─────────────┘    └────────────┘
//!        │
//!        ▼
//! ┌─────────────┐
//! │ DamonAttrs  │   sampling_interval, aggr_interval,
//! │ (tuning)    │   min/max_nr_regions
//! └─────────────┘
//! ```
//!
//! # Key Types
//!
//! - [`DamonRegion`] — one contiguous address range with access counters
//! - [`DamonTarget`] — monitoring target (a process address space)
//! - [`DamonAttrs`] — sampling / aggregation parameters
//! - [`DamonCtx`] — monitoring context binding targets and attributes
//!
//! Reference: Linux `mm/damon/core.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Default sampling interval in microseconds.
const DEFAULT_SAMPLE_US: u64 = 5_000;

/// Default aggregation interval in microseconds.
const DEFAULT_AGGR_US: u64 = 100_000;

/// Default update interval in microseconds.
const DEFAULT_UPDATE_US: u64 = 1_000_000;

/// Minimum number of monitoring regions per target.
const MIN_NR_REGIONS: usize = 10;

/// Maximum number of monitoring regions per target.
const MAX_NR_REGIONS: usize = 1000;

/// Maximum number of targets per context.
const MAX_TARGETS: usize = 64;

/// Maximum regions per target.
const MAX_REGIONS_PER_TARGET: usize = 4096;

// -------------------------------------------------------------------
// DamonRegion
// -------------------------------------------------------------------

/// Represents a contiguous virtual address range being monitored.
///
/// Each region tracks the start/end addresses and the number of
/// accesses observed within the last aggregation interval.
#[derive(Debug, Clone, Copy)]
pub struct DamonRegion {
    /// Start address of the region (inclusive).
    start: u64,
    /// End address of the region (exclusive).
    end: u64,
    /// Number of accesses observed in the current aggregation period.
    nr_accesses: u32,
    /// Age of the region in aggregation intervals.
    age: u32,
    /// Whether the region was sampled in the last interval.
    sampled: bool,
}

impl DamonRegion {
    /// Creates a new region for the given address range.
    pub const fn new(start: u64, end: u64) -> Self {
        Self {
            start,
            end,
            nr_accesses: 0,
            age: 0,
            sampled: false,
        }
    }

    /// Returns the start address.
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Returns the end address.
    pub const fn end(&self) -> u64 {
        self.end
    }

    /// Returns the region size in bytes.
    pub const fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Returns the number of accesses in the current period.
    pub const fn nr_accesses(&self) -> u32 {
        self.nr_accesses
    }

    /// Returns the region age (aggregation intervals).
    pub const fn age(&self) -> u32 {
        self.age
    }

    /// Records a sampled access for this region.
    pub fn record_access(&mut self) {
        self.nr_accesses = self.nr_accesses.saturating_add(1);
        self.sampled = true;
    }

    /// Resets counters for a new aggregation interval.
    pub fn reset_for_aggregation(&mut self) {
        self.nr_accesses = 0;
        self.age = self.age.saturating_add(1);
        self.sampled = false;
    }
}

impl Default for DamonRegion {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// -------------------------------------------------------------------
// DamonTarget
// -------------------------------------------------------------------

/// A monitoring target — typically one process address space.
///
/// Each target holds a set of non-overlapping regions covering the
/// monitored portion of its address space.
#[derive(Debug)]
pub struct DamonTarget {
    /// Identifier for the target (e.g., PID).
    pid: u64,
    /// Monitored regions (sorted by start address).
    regions: [DamonRegion; MAX_REGIONS_PER_TARGET],
    /// Number of active regions.
    nr_regions: usize,
}

impl DamonTarget {
    /// Creates a new target for the given PID.
    pub const fn new(pid: u64) -> Self {
        Self {
            pid,
            regions: [const { DamonRegion::new(0, 0) }; MAX_REGIONS_PER_TARGET],
            nr_regions: 0,
        }
    }

    /// Returns the target PID.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Returns the number of active regions.
    pub const fn nr_regions(&self) -> usize {
        self.nr_regions
    }

    /// Adds a region to the target.
    pub fn add_region(&mut self, region: DamonRegion) -> Result<()> {
        if self.nr_regions >= MAX_REGIONS_PER_TARGET {
            return Err(Error::OutOfMemory);
        }
        self.regions[self.nr_regions] = region;
        self.nr_regions += 1;
        Ok(())
    }

    /// Returns a reference to the active regions slice.
    pub fn regions(&self) -> &[DamonRegion] {
        &self.regions[..self.nr_regions]
    }

    /// Returns a mutable reference to the active regions slice.
    pub fn regions_mut(&mut self) -> &mut [DamonRegion] {
        &mut self.regions[..self.nr_regions]
    }

    /// Merges two adjacent regions if their access counts are within
    /// the given threshold.
    pub fn merge_regions(&mut self, threshold: u32) {
        if self.nr_regions < 2 {
            return;
        }
        let mut i = 0;
        while i + 1 < self.nr_regions {
            let a_accesses = self.regions[i].nr_accesses;
            let b_accesses = self.regions[i + 1].nr_accesses;
            let diff = if a_accesses > b_accesses {
                a_accesses - b_accesses
            } else {
                b_accesses - a_accesses
            };
            if diff <= threshold {
                let b_end = self.regions[i + 1].end;
                self.regions[i].end = b_end;
                // Shift remaining regions left.
                let mut j = i + 1;
                while j + 1 < self.nr_regions {
                    self.regions[j] = self.regions[j + 1];
                    j += 1;
                }
                self.nr_regions -= 1;
            } else {
                i += 1;
            }
        }
    }
}

impl Default for DamonTarget {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// DamonAttrs
// -------------------------------------------------------------------

/// Tunable attributes for DAMON monitoring.
#[derive(Debug, Clone, Copy)]
pub struct DamonAttrs {
    /// Sampling interval in microseconds.
    pub sample_us: u64,
    /// Aggregation interval in microseconds.
    pub aggr_us: u64,
    /// Update interval in microseconds.
    pub update_us: u64,
    /// Minimum number of regions per target.
    pub min_nr_regions: usize,
    /// Maximum number of regions per target.
    pub max_nr_regions: usize,
}

impl DamonAttrs {
    /// Creates attributes with default values.
    pub const fn new() -> Self {
        Self {
            sample_us: DEFAULT_SAMPLE_US,
            aggr_us: DEFAULT_AGGR_US,
            update_us: DEFAULT_UPDATE_US,
            min_nr_regions: MIN_NR_REGIONS,
            max_nr_regions: MAX_NR_REGIONS,
        }
    }

    /// Validates the attributes for consistency.
    pub fn validate(&self) -> Result<()> {
        if self.sample_us == 0 || self.aggr_us == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.aggr_us < self.sample_us {
            return Err(Error::InvalidArgument);
        }
        if self.min_nr_regions == 0 || self.min_nr_regions > self.max_nr_regions {
            return Err(Error::InvalidArgument);
        }
        if self.max_nr_regions > MAX_REGIONS_PER_TARGET {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for DamonAttrs {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// DamonCtx
// -------------------------------------------------------------------

/// The main DAMON monitoring context.
///
/// Binds a set of monitoring targets to a set of attributes and drives
/// the sample → aggregate → merge/split loop.
#[derive(Debug)]
pub struct DamonCtx {
    /// Monitoring attributes.
    attrs: DamonAttrs,
    /// Target PIDs.
    target_pids: [u64; MAX_TARGETS],
    /// Number of active targets.
    nr_targets: usize,
    /// Whether monitoring is currently running.
    running: bool,
    /// Total number of sampling passes completed.
    sample_passes: u64,
    /// Total number of aggregation passes completed.
    aggr_passes: u64,
}

impl DamonCtx {
    /// Creates a new context with default attributes.
    pub const fn new() -> Self {
        Self {
            attrs: DamonAttrs::new(),
            target_pids: [0u64; MAX_TARGETS],
            nr_targets: 0,
            running: false,
            sample_passes: 0,
            aggr_passes: 0,
        }
    }

    /// Returns the current attributes.
    pub const fn attrs(&self) -> &DamonAttrs {
        &self.attrs
    }

    /// Updates the monitoring attributes (only when stopped).
    pub fn set_attrs(&mut self, attrs: DamonAttrs) -> Result<()> {
        if self.running {
            return Err(Error::Busy);
        }
        attrs.validate()?;
        self.attrs = attrs;
        Ok(())
    }

    /// Adds a target PID to monitor.
    pub fn add_target(&mut self, pid: u64) -> Result<()> {
        if self.nr_targets >= MAX_TARGETS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate.
        for i in 0..self.nr_targets {
            if self.target_pids[i] == pid {
                return Err(Error::AlreadyExists);
            }
        }
        self.target_pids[self.nr_targets] = pid;
        self.nr_targets += 1;
        Ok(())
    }

    /// Removes a target PID.
    pub fn remove_target(&mut self, pid: u64) -> Result<()> {
        for i in 0..self.nr_targets {
            if self.target_pids[i] == pid {
                // Shift remaining.
                let mut j = i;
                while j + 1 < self.nr_targets {
                    self.target_pids[j] = self.target_pids[j + 1];
                    j += 1;
                }
                self.nr_targets -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the active target PIDs.
    pub fn target_pids(&self) -> &[u64] {
        &self.target_pids[..self.nr_targets]
    }

    /// Starts monitoring.
    pub fn start(&mut self) -> Result<()> {
        if self.running {
            return Err(Error::Busy);
        }
        if self.nr_targets == 0 {
            return Err(Error::InvalidArgument);
        }
        self.attrs.validate()?;
        self.running = true;
        Ok(())
    }

    /// Stops monitoring.
    pub fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Err(Error::InvalidArgument);
        }
        self.running = false;
        Ok(())
    }

    /// Returns whether monitoring is active.
    pub const fn is_running(&self) -> bool {
        self.running
    }

    /// Records a completed sampling pass.
    pub fn record_sample_pass(&mut self) {
        self.sample_passes = self.sample_passes.saturating_add(1);
    }

    /// Records a completed aggregation pass.
    pub fn record_aggr_pass(&mut self) {
        self.aggr_passes = self.aggr_passes.saturating_add(1);
    }

    /// Returns the number of sampling passes.
    pub const fn sample_passes(&self) -> u64 {
        self.sample_passes
    }

    /// Returns the number of aggregation passes.
    pub const fn aggr_passes(&self) -> u64 {
        self.aggr_passes
    }
}

impl Default for DamonCtx {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a default DAMON context ready for target registration.
pub fn create_context() -> DamonCtx {
    DamonCtx::new()
}

/// Validates and applies new attributes to a stopped context.
pub fn apply_attrs(ctx: &mut DamonCtx, attrs: DamonAttrs) -> Result<()> {
    ctx.set_attrs(attrs)
}

/// Returns a summary of the monitoring state.
pub fn monitoring_summary(ctx: &DamonCtx) -> (bool, u64, u64) {
    (ctx.is_running(), ctx.sample_passes(), ctx.aggr_passes())
}
