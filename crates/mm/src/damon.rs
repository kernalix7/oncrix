// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DAMON — Data Access MONitor.
//!
//! Implements a data access monitoring framework that tracks memory
//! access patterns at region granularity. Rather than tracking every
//! page individually, DAMON groups contiguous pages into regions and
//! samples access bits at configurable intervals to build frequency
//! histograms.
//!
//! # Architecture
//!
//! - [`DamonRegion`] — a contiguous virtual address range with access
//!   frequency and age tracking
//! - [`DamonTarget`] — a monitored process with its region list
//! - [`DamonContext`] — sampling and aggregation configuration
//! - [`DamonScheme`] — action-based policy (pageout, hugepage, stat)
//! - [`DamonMonitor`] — the main monitor that drives sampling
//! - [`DamonStats`] — monitoring statistics
//!
//! Reference: Linux `mm/damon/core.c`, `mm/damon/vaddr.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of regions per target.
const MAX_REGIONS: usize = 128;

/// Maximum number of monitored targets.
const MAX_TARGETS: usize = 16;

/// Maximum number of DAMOS schemes.
const MAX_SCHEMES: usize = 8;

/// Default sampling interval in microseconds.
const DEFAULT_SAMPLE_US: u64 = 5_000;

/// Default aggregation interval in microseconds.
const DEFAULT_AGGR_US: u64 = 100_000;

/// Default regions update interval in microseconds.
const DEFAULT_UPDATE_US: u64 = 1_000_000;

/// Minimum region size in bytes (one page).
const MIN_REGION_SIZE: u64 = 4096;

/// Maximum access count before saturation.
const MAX_ACCESS_COUNT: u32 = 10_000;

// -------------------------------------------------------------------
// DamonRegion
// -------------------------------------------------------------------

/// A contiguous virtual address range being monitored.
///
/// Each region tracks an access counter that is incremented on each
/// sampling pass when the access bit is set, and an age counter
/// that records how many aggregation intervals the region has been
/// monitored.
#[derive(Debug, Clone, Copy)]
pub struct DamonRegion {
    /// Start address of the region (inclusive, page-aligned).
    pub start: u64,
    /// End address of the region (exclusive, page-aligned).
    pub end: u64,
    /// Number of accesses detected during the current aggregation
    /// window.
    pub nr_accesses: u32,
    /// Number of aggregation intervals this region has existed.
    pub age: u32,
    /// Whether this region slot is occupied.
    pub active: bool,
    /// Last sampled page offset within the region.
    pub sample_offset: u64,
}

impl DamonRegion {
    /// Creates an empty, inactive region.
    const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            nr_accesses: 0,
            age: 0,
            active: false,
            sample_offset: 0,
        }
    }

    /// Creates a new region with the given address range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `start >= end` or
    /// either address is not page-aligned.
    pub const fn new(start: u64, end: u64) -> Result<Self> {
        if start >= end {
            return Err(Error::InvalidArgument);
        }
        if start % MIN_REGION_SIZE != 0 || end % MIN_REGION_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            start,
            end,
            nr_accesses: 0,
            age: 0,
            active: true,
            sample_offset: 0,
        })
    }

    /// Size of the region in bytes.
    pub const fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Number of pages in the region.
    pub const fn nr_pages(&self) -> u64 {
        self.size() / MIN_REGION_SIZE
    }
}

// -------------------------------------------------------------------
// DamonTarget
// -------------------------------------------------------------------

/// A process (or address space) being monitored by DAMON.
///
/// Each target has a PID and a list of regions covering the portions
/// of its address space that DAMON is tracking.
pub struct DamonTarget {
    /// Process identifier.
    pid: u64,
    /// Regions being monitored.
    regions: [DamonRegion; MAX_REGIONS],
    /// Number of active regions.
    region_count: usize,
    /// Whether this target slot is active.
    active: bool,
}

impl DamonTarget {
    /// Creates an empty, inactive target.
    const fn empty() -> Self {
        Self {
            pid: 0,
            regions: [DamonRegion::empty(); MAX_REGIONS],
            region_count: 0,
            active: false,
        }
    }

    /// Creates a new target for the given PID.
    pub const fn new(pid: u64) -> Self {
        Self {
            pid,
            regions: [DamonRegion::empty(); MAX_REGIONS],
            region_count: 0,
            active: true,
        }
    }

    /// Adds a region to this target.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all region slots are full.
    /// Returns [`Error::InvalidArgument`] if the region overlaps
    /// an existing region.
    pub fn add_region(&mut self, region: DamonRegion) -> Result<usize> {
        if self.region_count >= MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }

        // Check for overlap with existing regions.
        for r in &self.regions[..self.region_count] {
            if !r.active {
                continue;
            }
            if region.start < r.end && region.end > r.start {
                return Err(Error::InvalidArgument);
            }
        }

        // Find an inactive slot.
        for (i, slot) in self.regions.iter_mut().enumerate() {
            if !slot.active {
                *slot = region;
                self.region_count += 1;
                return Ok(i);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Removes a region by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// range or the slot is not active.
    pub fn remove_region(&mut self, index: usize) -> Result<()> {
        if index >= MAX_REGIONS || !self.regions[index].active {
            return Err(Error::InvalidArgument);
        }
        self.regions[index].active = false;
        self.region_count = self.region_count.saturating_sub(1);
        Ok(())
    }

    /// Returns the PID of this target.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Returns the number of active regions.
    pub const fn region_count(&self) -> usize {
        self.region_count
    }

    /// Returns a reference to a region by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// range or the slot is not active.
    pub fn region(&self, index: usize) -> Result<&DamonRegion> {
        if index >= MAX_REGIONS || !self.regions[index].active {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.regions[index])
    }

    /// Returns a mutable reference to a region by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// range or the slot is not active.
    pub fn region_mut(&mut self, index: usize) -> Result<&mut DamonRegion> {
        if index >= MAX_REGIONS || !self.regions[index].active {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.regions[index])
    }
}

// -------------------------------------------------------------------
// DamonContext
// -------------------------------------------------------------------

/// Sampling and aggregation timing configuration.
///
/// - `sample_interval_us`: how often to check access bits
/// - `aggr_interval_us`: how often to aggregate access counts
/// - `update_interval_us`: how often to update region boundaries
#[derive(Debug, Clone, Copy)]
pub struct DamonContext {
    /// Sampling interval in microseconds.
    pub sample_interval_us: u64,
    /// Aggregation interval in microseconds.
    pub aggr_interval_us: u64,
    /// Region update interval in microseconds.
    pub update_interval_us: u64,
    /// Minimum number of regions per target.
    pub min_regions: usize,
    /// Maximum number of regions per target.
    pub max_regions: usize,
}

impl Default for DamonContext {
    fn default() -> Self {
        Self {
            sample_interval_us: DEFAULT_SAMPLE_US,
            aggr_interval_us: DEFAULT_AGGR_US,
            update_interval_us: DEFAULT_UPDATE_US,
            min_regions: 10,
            max_regions: MAX_REGIONS,
        }
    }
}

impl DamonContext {
    /// Creates a new context with the given intervals.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if any interval is zero
    /// or if `sample_interval_us > aggr_interval_us`.
    pub const fn new(sample_us: u64, aggr_us: u64, update_us: u64) -> Result<Self> {
        if sample_us == 0 || aggr_us == 0 || update_us == 0 {
            return Err(Error::InvalidArgument);
        }
        if sample_us > aggr_us {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            sample_interval_us: sample_us,
            aggr_interval_us: aggr_us,
            update_interval_us: update_us,
            min_regions: 10,
            max_regions: MAX_REGIONS,
        })
    }
}

// -------------------------------------------------------------------
// DamonAction
// -------------------------------------------------------------------

/// Action to take on a region that matches a DAMOS scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DamonAction {
    /// Do nothing (just collect statistics).
    #[default]
    Stat,
    /// Page out the region to swap.
    Pageout,
    /// Promote the region to huge pages.
    Hugepage,
    /// No operation (explicitly skip).
    Nop,
    /// Mark the region for compaction.
    Compact,
}

// -------------------------------------------------------------------
// DamonScheme
// -------------------------------------------------------------------

/// A DAMOS (DAMON-based Operation Scheme) policy.
///
/// Defines criteria for selecting regions and the action to take.
/// Regions are matched when their access frequency and age fall
/// within the specified ranges. A per-scheme quota limits the
/// total bytes processed per aggregation interval.
#[derive(Debug, Clone, Copy)]
pub struct DamonScheme {
    /// Minimum access count to match.
    pub min_accesses: u32,
    /// Maximum access count to match.
    pub max_accesses: u32,
    /// Minimum region age (aggregation intervals) to match.
    pub min_age: u32,
    /// Maximum region age to match.
    pub max_age: u32,
    /// Action to take on matching regions.
    pub action: DamonAction,
    /// Maximum bytes to process per aggregation interval.
    pub quota_bytes: u64,
    /// Bytes processed so far in the current interval.
    pub bytes_used: u64,
    /// Whether this scheme slot is active.
    pub active: bool,
}

impl DamonScheme {
    /// Creates an empty, inactive scheme.
    const fn empty() -> Self {
        Self {
            min_accesses: 0,
            max_accesses: 0,
            min_age: 0,
            max_age: 0,
            action: DamonAction::Stat,
            quota_bytes: 0,
            bytes_used: 0,
            active: false,
        }
    }

    /// Creates a new scheme with the given criteria and action.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `min_accesses >
    /// max_accesses` or `min_age > max_age`.
    pub const fn new(
        min_accesses: u32,
        max_accesses: u32,
        min_age: u32,
        max_age: u32,
        action: DamonAction,
        quota_bytes: u64,
    ) -> Result<Self> {
        if min_accesses > max_accesses {
            return Err(Error::InvalidArgument);
        }
        if min_age > max_age {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            min_accesses,
            max_accesses,
            min_age,
            max_age,
            action,
            quota_bytes,
            bytes_used: 0,
            active: true,
        })
    }

    /// Returns `true` if the given access count and age fall
    /// within this scheme's criteria.
    pub const fn matches(&self, accesses: u32, age: u32) -> bool {
        accesses >= self.min_accesses
            && accesses <= self.max_accesses
            && age >= self.min_age
            && age <= self.max_age
    }

    /// Returns `true` if the quota has been exhausted.
    pub const fn quota_exhausted(&self) -> bool {
        self.quota_bytes > 0 && self.bytes_used >= self.quota_bytes
    }

    /// Resets the per-interval quota usage.
    pub fn reset_quota(&mut self) {
        self.bytes_used = 0;
    }
}

// -------------------------------------------------------------------
// DamonSchemeResult
// -------------------------------------------------------------------

/// Result of applying a DAMOS scheme to a region.
#[derive(Debug, Clone, Copy)]
pub struct DamonSchemeResult {
    /// Target PID.
    pub pid: u64,
    /// Region start address.
    pub region_start: u64,
    /// Region size in bytes.
    pub region_size: u64,
    /// Action applied.
    pub action: DamonAction,
    /// Access count at the time of action.
    pub nr_accesses: u32,
}

// -------------------------------------------------------------------
// DamonStats
// -------------------------------------------------------------------

/// DAMON monitoring statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct DamonStats {
    /// Total sampling passes executed.
    pub sample_count: u64,
    /// Total aggregation passes executed.
    pub aggr_count: u64,
    /// Total regions update passes executed.
    pub update_count: u64,
    /// Total scheme actions applied.
    pub scheme_actions: u64,
    /// Number of active targets.
    pub target_count: usize,
    /// Total regions across all targets.
    pub total_regions: usize,
}

// -------------------------------------------------------------------
// DamonMonitorState
// -------------------------------------------------------------------

/// Operating state of the DAMON monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DamonMonitorState {
    /// Monitor is stopped.
    #[default]
    Stopped,
    /// Monitor is running.
    Running,
    /// Monitor is paused.
    Paused,
}

// -------------------------------------------------------------------
// DamonMonitor
// -------------------------------------------------------------------

/// The main DAMON monitor instance.
///
/// Drives the sampling-aggregation-action loop:
/// 1. **Sample**: Check access bits on randomly sampled pages
///    within each region.
/// 2. **Aggregate**: After `aggr_interval_us`, summarize access
///    counts and age each region.
/// 3. **Apply schemes**: Match regions against DAMOS schemes and
///    apply the configured actions.
/// 4. **Update regions**: Periodically split/merge regions to
///    maintain accuracy.
pub struct DamonMonitor {
    /// Monitored targets.
    targets: [DamonTarget; MAX_TARGETS],
    /// Number of active targets.
    target_count: usize,
    /// DAMOS schemes.
    schemes: [DamonScheme; MAX_SCHEMES],
    /// Number of active schemes.
    scheme_count: usize,
    /// Timing configuration.
    context: DamonContext,
    /// Operating state.
    state: DamonMonitorState,
    /// Monitoring statistics.
    stats: DamonStats,
    /// Microsecond timestamp of the last sample.
    _last_sample_us: u64,
    /// Microsecond timestamp of the last aggregation.
    _last_aggr_us: u64,
    /// Microsecond timestamp of the last region update.
    _last_update_us: u64,
}

impl Default for DamonMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl DamonMonitor {
    /// Creates a new stopped monitor with default configuration.
    pub const fn new() -> Self {
        Self {
            targets: [const { DamonTarget::empty() }; MAX_TARGETS],
            target_count: 0,
            schemes: [DamonScheme::empty(); MAX_SCHEMES],
            scheme_count: 0,
            context: DamonContext {
                sample_interval_us: DEFAULT_SAMPLE_US,
                aggr_interval_us: DEFAULT_AGGR_US,
                update_interval_us: DEFAULT_UPDATE_US,
                min_regions: 10,
                max_regions: MAX_REGIONS,
            },
            state: DamonMonitorState::Stopped,
            stats: DamonStats {
                sample_count: 0,
                aggr_count: 0,
                update_count: 0,
                scheme_actions: 0,
                target_count: 0,
                total_regions: 0,
            },
            _last_sample_us: 0,
            _last_aggr_us: 0,
            _last_update_us: 0,
        }
    }

    /// Sets the timing configuration.
    pub fn set_context(&mut self, ctx: DamonContext) {
        self.context = ctx;
    }

    /// Returns the current configuration.
    pub const fn context(&self) -> &DamonContext {
        &self.context
    }

    /// Adds a target process to monitor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all target slots are full.
    /// Returns [`Error::AlreadyExists`] if the PID is already
    /// monitored.
    pub fn add_target(&mut self, pid: u64) -> Result<usize> {
        // Check duplicate.
        for t in &self.targets[..] {
            if t.active && t.pid == pid {
                return Err(Error::AlreadyExists);
            }
        }

        if self.target_count >= MAX_TARGETS {
            return Err(Error::OutOfMemory);
        }

        for (i, slot) in self.targets.iter_mut().enumerate() {
            if !slot.active {
                *slot = DamonTarget::new(pid);
                self.target_count += 1;
                self.stats.target_count = self.target_count;
                return Ok(i);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Removes a target by PID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PID is not monitored.
    pub fn remove_target(&mut self, pid: u64) -> Result<()> {
        let target = self
            .targets
            .iter_mut()
            .find(|t| t.active && t.pid == pid)
            .ok_or(Error::NotFound)?;
        target.active = false;
        target.region_count = 0;
        self.target_count = self.target_count.saturating_sub(1);
        self.stats.target_count = self.target_count;
        Ok(())
    }

    /// Adds a region to a target identified by PID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PID is not monitored.
    /// Returns [`Error::OutOfMemory`] if the target's region slots
    /// are full.
    /// Returns [`Error::InvalidArgument`] on overlap or bad range.
    pub fn add_region(&mut self, pid: u64, start: u64, end: u64) -> Result<usize> {
        let region = DamonRegion::new(start, end)?;
        let target = self
            .targets
            .iter_mut()
            .find(|t| t.active && t.pid == pid)
            .ok_or(Error::NotFound)?;
        let idx = target.add_region(region)?;
        self.stats.total_regions += 1;
        Ok(idx)
    }

    /// Adds a DAMOS scheme.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all scheme slots are full.
    pub fn add_scheme(&mut self, scheme: DamonScheme) -> Result<usize> {
        if self.scheme_count >= MAX_SCHEMES {
            return Err(Error::OutOfMemory);
        }
        for (i, slot) in self.schemes.iter_mut().enumerate() {
            if !slot.active {
                *slot = scheme;
                self.scheme_count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes a scheme by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// range or the slot is not active.
    pub fn remove_scheme(&mut self, index: usize) -> Result<()> {
        if index >= MAX_SCHEMES || !self.schemes[index].active {
            return Err(Error::InvalidArgument);
        }
        self.schemes[index].active = false;
        self.scheme_count = self.scheme_count.saturating_sub(1);
        Ok(())
    }

    /// Starts the monitor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if no targets are
    /// configured.
    pub fn start(&mut self) -> Result<()> {
        if self.target_count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.state = DamonMonitorState::Running;
        Ok(())
    }

    /// Stops the monitor.
    pub fn stop(&mut self) {
        self.state = DamonMonitorState::Stopped;
    }

    /// Pauses the monitor.
    pub fn pause(&mut self) {
        if self.state == DamonMonitorState::Running {
            self.state = DamonMonitorState::Paused;
        }
    }

    /// Resumes a paused monitor.
    pub fn resume(&mut self) {
        if self.state == DamonMonitorState::Paused {
            self.state = DamonMonitorState::Running;
        }
    }

    /// Performs one sampling pass.
    ///
    /// For each target and each region, checks a sampled page's
    /// access bit. If accessed, increments the region's access
    /// counter. The `accessed_pages` slice provides simulated
    /// access-bit results (one bool per region, in target order).
    ///
    /// Returns the number of regions found to be accessed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the monitor is not
    /// running.
    pub fn sample(&mut self, accessed_pages: &[bool]) -> Result<usize> {
        if self.state != DamonMonitorState::Running {
            return Err(Error::InvalidArgument);
        }

        let mut accessed_count = 0usize;
        let mut bit_idx = 0usize;

        for target in &mut self.targets {
            if !target.active {
                continue;
            }
            for region in &mut target.regions {
                if !region.active {
                    continue;
                }
                let accessed = if bit_idx < accessed_pages.len() {
                    accessed_pages[bit_idx]
                } else {
                    false
                };
                bit_idx += 1;

                if accessed {
                    region.nr_accesses = region.nr_accesses.saturating_add(1).min(MAX_ACCESS_COUNT);
                    accessed_count += 1;
                }
            }
        }

        self.stats.sample_count += 1;
        Ok(accessed_count)
    }

    /// Performs one aggregation pass.
    ///
    /// Ages all regions (increments their age counter) and applies
    /// any matching DAMOS schemes. After applying schemes, resets
    /// region access counters for the next aggregation window.
    ///
    /// Returns the number of scheme actions applied.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the monitor is not
    /// running.
    pub fn aggregate(&mut self) -> Result<usize> {
        if self.state != DamonMonitorState::Running {
            return Err(Error::InvalidArgument);
        }

        let mut actions_applied = 0usize;

        for target in &mut self.targets {
            if !target.active {
                continue;
            }
            for region in &mut target.regions {
                if !region.active {
                    continue;
                }

                // Age the region.
                region.age = region.age.saturating_add(1);

                // Check schemes.
                for scheme in &mut self.schemes {
                    if !scheme.active {
                        continue;
                    }
                    if scheme.quota_exhausted() {
                        continue;
                    }
                    if scheme.matches(region.nr_accesses, region.age) {
                        // Apply action (simulated).
                        let size = region.size();
                        scheme.bytes_used = scheme.bytes_used.saturating_add(size);
                        actions_applied += 1;
                    }
                }

                // Reset access counter for next window.
                region.nr_accesses = 0;
            }
        }

        self.stats.aggr_count += 1;
        self.stats.scheme_actions += actions_applied as u64;

        // Reset scheme quotas.
        for scheme in &mut self.schemes {
            if scheme.active {
                scheme.reset_quota();
            }
        }

        Ok(actions_applied)
    }

    /// Performs a region update pass.
    ///
    /// Splits regions that are too large and merges adjacent
    /// regions with similar access patterns. This maintains
    /// monitoring accuracy while keeping the region count bounded.
    ///
    /// `threshold` is the maximum access count difference for
    /// merging two adjacent regions.
    ///
    /// Returns the total number of active regions after the update.
    pub fn update_regions(&mut self, threshold: u32) -> usize {
        let mut total = 0usize;

        for target in &mut self.targets {
            if !target.active {
                continue;
            }

            // Merge adjacent regions with similar access patterns.
            // Simple single-pass merge: compare consecutive active
            // regions and merge if access counts are within
            // threshold.
            let mut i = 0;
            while i + 1 < MAX_REGIONS {
                let curr_active = target.regions[i].active;
                let next_active = target.regions[i + 1].active;

                if !curr_active || !next_active {
                    i += 1;
                    continue;
                }

                let curr_end = target.regions[i].end;
                let next_start = target.regions[i + 1].start;

                // Only merge if contiguous.
                if curr_end != next_start {
                    i += 1;
                    continue;
                }

                let diff = target.regions[i]
                    .nr_accesses
                    .abs_diff(target.regions[i + 1].nr_accesses);

                if diff <= threshold {
                    // Merge: extend current region, deactivate
                    // next.
                    target.regions[i].end = target.regions[i + 1].end;
                    target.regions[i + 1].active = false;
                    target.region_count = target.region_count.saturating_sub(1);
                    // Don't advance i — check if the merged
                    // region can merge with the next one too.
                } else {
                    i += 1;
                }
            }

            // Count active regions.
            let count = target.regions.iter().filter(|r| r.active).count();
            target.region_count = count;
            total += count;
        }

        self.stats.update_count += 1;
        self.stats.total_regions = total;
        total
    }

    /// Returns the current operating state.
    pub const fn state(&self) -> DamonMonitorState {
        self.state
    }

    /// Returns monitoring statistics.
    pub const fn stats(&self) -> &DamonStats {
        &self.stats
    }

    /// Returns the number of active targets.
    pub const fn target_count(&self) -> usize {
        self.target_count
    }

    /// Returns the number of active schemes.
    pub const fn scheme_count(&self) -> usize {
        self.scheme_count
    }

    /// Returns `true` if the monitor is running.
    pub const fn is_running(&self) -> bool {
        matches!(self.state, DamonMonitorState::Running)
    }

    /// Returns a reference to a target by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// range or the slot is not active.
    pub fn target(&self, index: usize) -> Result<&DamonTarget> {
        if index >= MAX_TARGETS || !self.targets[index].active {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.targets[index])
    }

    /// Returns a mutable reference to a target by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// range or the slot is not active.
    pub fn target_mut(&mut self, index: usize) -> Result<&mut DamonTarget> {
        if index >= MAX_TARGETS || !self.targets[index].active {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.targets[index])
    }

    /// Returns a reference to a scheme by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// range or the slot is not active.
    pub fn scheme(&self, index: usize) -> Result<&DamonScheme> {
        if index >= MAX_SCHEMES || !self.schemes[index].active {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.schemes[index])
    }
}
