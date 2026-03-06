// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DAMON Operations — pluggable backends for data access monitoring.
//!
//! DAMON's core monitor is backend-agnostic: it delegates actual
//! address-space interrogation to an *operations* layer. Each
//! backend knows how to:
//!
//! - **Initialise** monitoring for a target (e.g. populate initial
//!   regions from `/proc/<pid>/maps`).
//! - **Sample** a page's access bit using the architecture's PTE.
//! - **Reset** the access bit after reading it.
//! - **Update** region boundaries based on VMA changes.
//!
//! This module provides:
//!
//! - [`DamonOpsType`] — backend selector (vaddr, paddr, fvaddr)
//! - [`DamonAddrRange`] — a contiguous virtual/physical address range
//! - [`DamonAccessPattern`] — snapshot of a region's access behaviour
//! - [`DamonOpsConfig`] — per-backend tunable parameters
//! - [`DamonVaddrOps`] — virtual-address backend (process memory)
//! - [`DamonPaddrOps`] — physical-address backend (system memory)
//! - [`DamonOpsRouter`] — dispatches calls to the selected backend
//!
//! Reference: Linux `mm/damon/vaddr.c`, `mm/damon/paddr.c`,
//! `include/linux/damon.h`.

#[allow(dead_code)]
use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of address ranges tracked per target.
const MAX_ADDR_RANGES: usize = 64;

/// Maximum number of targets an ops instance can manage.
const MAX_OPS_TARGETS: usize = 16;

/// Maximum access-bit samples per region before saturation.
const MAX_SAMPLES: u32 = 10_000;

/// Default random-walk seed for page sampling.
const DEFAULT_SEED: u64 = 0xDEAD_BEEF_CAFE_BABE;

// -------------------------------------------------------------------
// DamonOpsType
// -------------------------------------------------------------------

/// Selects the monitoring backend.
///
/// - `Vaddr` — monitors a process's virtual address space using PTE
///   access bits. This is the most common backend.
/// - `Paddr` — monitors raw physical address ranges; useful for
///   system-wide memory profiling.
/// - `Fvaddr` — *filtered* vaddr; only tracks regions that match a
///   set of filters (e.g. file-backed, anonymous, huge-page).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DamonOpsType {
    /// Virtual address monitoring.
    #[default]
    Vaddr,
    /// Physical address monitoring.
    Paddr,
    /// Filtered virtual address monitoring.
    Fvaddr,
}

// -------------------------------------------------------------------
// DamonAddrRange
// -------------------------------------------------------------------

/// A contiguous address range (virtual or physical).
///
/// Both `start` and `end` must be page-aligned. `end` is exclusive.
#[derive(Debug, Clone, Copy)]
pub struct DamonAddrRange {
    /// Start address (inclusive, page-aligned).
    pub start: u64,
    /// End address (exclusive, page-aligned).
    pub end: u64,
    /// Whether this range slot is occupied.
    pub active: bool,
}

impl DamonAddrRange {
    /// Creates an empty, inactive range.
    const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            active: false,
        }
    }

    /// Creates a new address range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `start >= end` or
    /// either address is not page-aligned.
    pub const fn new(start: u64, end: u64) -> Result<Self> {
        if start >= end {
            return Err(Error::InvalidArgument);
        }
        if start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            start,
            end,
            active: true,
        })
    }

    /// Size of the range in bytes.
    pub const fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Number of pages in the range.
    pub const fn nr_pages(&self) -> u64 {
        self.size() / PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// DamonAccessPattern
// -------------------------------------------------------------------

/// Snapshot of a region's access behaviour after sampling.
///
/// Produced by the ops backend during aggregation, consumed by
/// DAMOS schemes to decide actions.
#[derive(Debug, Clone, Copy, Default)]
pub struct DamonAccessPattern {
    /// Region start address.
    pub start: u64,
    /// Region end address.
    pub end: u64,
    /// Number of access-bit samples observed (0..=[`MAX_SAMPLES`]).
    pub nr_accesses: u32,
    /// Number of aggregation intervals the region has been tracked.
    pub age: u32,
    /// Whether at least one access was detected in the last sample.
    pub recently_accessed: bool,
}

// -------------------------------------------------------------------
// DamonAccessSample
// -------------------------------------------------------------------

/// A single access-bit sample for one region.
#[derive(Debug, Clone, Copy)]
pub struct DamonAccessSample {
    /// Target identifier (e.g. PID or physical range index).
    pub target_id: u64,
    /// Region start address.
    pub region_start: u64,
    /// The page offset within the region that was sampled.
    pub sampled_offset: u64,
    /// Whether the sampled page had its access bit set.
    pub accessed: bool,
}

// -------------------------------------------------------------------
// DamonOpsConfig
// -------------------------------------------------------------------

/// Per-backend tunable parameters.
#[derive(Debug, Clone, Copy)]
pub struct DamonOpsConfig {
    /// Backend type.
    pub ops_type: DamonOpsType,
    /// Whether to clear access bits after reading (PTE young bit).
    pub clear_access_bit: bool,
    /// Whether to use random page sampling within a region.
    pub random_sample: bool,
    /// Seed for the pseudo-random page selector.
    pub sample_seed: u64,
    /// Minimum region size in pages below which regions are not
    /// split further.
    pub min_region_pages: u64,
    /// Maximum region size in pages above which regions are split.
    pub max_region_pages: u64,
}

impl Default for DamonOpsConfig {
    fn default() -> Self {
        Self {
            ops_type: DamonOpsType::Vaddr,
            clear_access_bit: true,
            random_sample: true,
            sample_seed: DEFAULT_SEED,
            min_region_pages: 1,
            max_region_pages: 256,
        }
    }
}

// -------------------------------------------------------------------
// DamonOpsTarget
// -------------------------------------------------------------------

/// Per-target state maintained by the ops layer.
///
/// Stores the address ranges being monitored and per-range access
/// counters.
struct DamonOpsTarget {
    /// Target identifier (PID for vaddr, 0 for paddr).
    id: u64,
    /// Tracked address ranges.
    ranges: [DamonAddrRange; MAX_ADDR_RANGES],
    /// Number of active ranges.
    range_count: usize,
    /// Per-range accumulated access counts.
    access_counts: [u32; MAX_ADDR_RANGES],
    /// Per-range age (aggregation intervals).
    ages: [u32; MAX_ADDR_RANGES],
    /// Whether this target slot is active.
    active: bool,
    /// Pseudo-random state for page sampling.
    rng_state: u64,
}

impl DamonOpsTarget {
    /// Creates an empty, inactive target.
    const fn empty() -> Self {
        Self {
            id: 0,
            ranges: [DamonAddrRange::empty(); MAX_ADDR_RANGES],
            range_count: 0,
            access_counts: [0u32; MAX_ADDR_RANGES],
            ages: [0u32; MAX_ADDR_RANGES],
            active: false,
            rng_state: DEFAULT_SEED,
        }
    }
}

// -------------------------------------------------------------------
// DamonOpsStats
// -------------------------------------------------------------------

/// Statistics collected by the ops layer.
#[derive(Debug, Clone, Copy, Default)]
pub struct DamonOpsStats {
    /// Total sample passes executed.
    pub sample_passes: u64,
    /// Total pages sampled.
    pub pages_sampled: u64,
    /// Total pages found accessed.
    pub pages_accessed: u64,
    /// Total access-bit clears performed.
    pub access_clears: u64,
    /// Total region splits performed.
    pub region_splits: u64,
    /// Total region merges performed.
    pub region_merges: u64,
    /// Total targets initialised.
    pub targets_inited: u64,
}

// -------------------------------------------------------------------
// DamonVaddrOps
// -------------------------------------------------------------------

/// Virtual-address monitoring backend.
///
/// Monitors per-process virtual address spaces by reading and
/// clearing PTE access bits. On each sampling pass, a random page
/// within each region is selected and its young bit is checked.
pub struct DamonVaddrOps {
    /// Managed targets.
    targets: [DamonOpsTarget; MAX_OPS_TARGETS],
    /// Number of active targets.
    target_count: usize,
    /// Configuration.
    config: DamonOpsConfig,
    /// Statistics.
    stats: DamonOpsStats,
}

impl Default for DamonVaddrOps {
    fn default() -> Self {
        Self::new()
    }
}

impl DamonVaddrOps {
    /// Creates a new vaddr backend with default configuration.
    pub const fn new() -> Self {
        Self {
            targets: [const { DamonOpsTarget::empty() }; MAX_OPS_TARGETS],
            target_count: 0,
            config: DamonOpsConfig {
                ops_type: DamonOpsType::Vaddr,
                clear_access_bit: true,
                random_sample: true,
                sample_seed: DEFAULT_SEED,
                min_region_pages: 1,
                max_region_pages: 256,
            },
            stats: DamonOpsStats {
                sample_passes: 0,
                pages_sampled: 0,
                pages_accessed: 0,
                access_clears: 0,
                region_splits: 0,
                region_merges: 0,
                targets_inited: 0,
            },
        }
    }

    /// Initialises monitoring for a target process.
    ///
    /// Populates initial address ranges for the given PID. The
    /// `vma_ranges` slice provides the starting regions — each pair
    /// `(start, end)` represents a VMA.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all target slots are full.
    /// Returns [`Error::AlreadyExists`] if the PID is already
    /// monitored.
    pub fn init_target(&mut self, pid: u64, vma_ranges: &[(u64, u64)]) -> Result<usize> {
        // Check for duplicate.
        if self.targets.iter().any(|t| t.active && t.id == pid) {
            return Err(Error::AlreadyExists);
        }
        if self.target_count >= MAX_OPS_TARGETS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .targets
            .iter_mut()
            .enumerate()
            .find(|(_, t)| !t.active)
            .ok_or(Error::OutOfMemory)?;

        let (idx, target) = slot;
        target.id = pid;
        target.active = true;
        target.range_count = 0;
        target.rng_state = self.config.sample_seed ^ pid;

        // Populate ranges from VMAs (capped).
        for &(start, end) in vma_ranges {
            if target.range_count >= MAX_ADDR_RANGES {
                break;
            }
            if let Ok(range) = DamonAddrRange::new(start, end) {
                target.ranges[target.range_count] = range;
                target.access_counts[target.range_count] = 0;
                target.ages[target.range_count] = 0;
                target.range_count += 1;
            }
        }

        self.target_count += 1;
        self.stats.targets_inited += 1;
        Ok(idx)
    }

    /// Deinitialises monitoring for a target by PID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PID is not monitored.
    pub fn deinit_target(&mut self, pid: u64) -> Result<()> {
        let target = self
            .targets
            .iter_mut()
            .find(|t| t.active && t.id == pid)
            .ok_or(Error::NotFound)?;
        target.active = false;
        target.range_count = 0;
        self.target_count = self.target_count.saturating_sub(1);
        Ok(())
    }

    /// Adds an address range to a monitored target.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PID is not monitored.
    /// Returns [`Error::OutOfMemory`] if the target's range slots
    /// are full.
    pub fn add_range(&mut self, pid: u64, start: u64, end: u64) -> Result<usize> {
        let range = DamonAddrRange::new(start, end)?;
        let target = self
            .targets
            .iter_mut()
            .find(|t| t.active && t.id == pid)
            .ok_or(Error::NotFound)?;

        if target.range_count >= MAX_ADDR_RANGES {
            return Err(Error::OutOfMemory);
        }

        let idx = target.range_count;
        target.ranges[idx] = range;
        target.access_counts[idx] = 0;
        target.ages[idx] = 0;
        target.range_count += 1;
        Ok(idx)
    }

    /// Performs one sampling pass across all targets.
    ///
    /// For each active range in each target, selects a page to
    /// sample. The `access_bits` slice provides simulated access-bit
    /// results (one bool per active range, in target order).
    ///
    /// Returns the number of regions found to be accessed.
    pub fn sample(&mut self, access_bits: &[bool]) -> usize {
        let mut accessed = 0_usize;
        let mut bit_idx = 0_usize;

        for target in &mut self.targets {
            if !target.active {
                continue;
            }
            for i in 0..target.range_count {
                if !target.ranges[i].active {
                    continue;
                }

                let bit = if bit_idx < access_bits.len() {
                    access_bits[bit_idx]
                } else {
                    false
                };
                bit_idx += 1;
                self.stats.pages_sampled += 1;

                if bit {
                    target.access_counts[i] =
                        target.access_counts[i].saturating_add(1).min(MAX_SAMPLES);
                    accessed += 1;
                    self.stats.pages_accessed += 1;
                }

                if self.config.clear_access_bit && bit {
                    self.stats.access_clears += 1;
                }
            }
        }

        self.stats.sample_passes += 1;
        accessed
    }

    /// Performs one aggregation pass.
    ///
    /// Ages all regions and collects access patterns into the
    /// provided output buffer. Returns the number of patterns
    /// written.
    pub fn aggregate(&mut self, patterns_out: &mut [DamonAccessPattern]) -> usize {
        let mut written = 0_usize;

        for target in &mut self.targets {
            if !target.active {
                continue;
            }
            for i in 0..target.range_count {
                if !target.ranges[i].active {
                    continue;
                }

                target.ages[i] = target.ages[i].saturating_add(1);

                if written < patterns_out.len() {
                    patterns_out[written] = DamonAccessPattern {
                        start: target.ranges[i].start,
                        end: target.ranges[i].end,
                        nr_accesses: target.access_counts[i],
                        age: target.ages[i],
                        recently_accessed: target.access_counts[i] > 0,
                    };
                    written += 1;
                }

                // Reset access counter for next aggregation window.
                target.access_counts[i] = 0;
            }
        }

        written
    }

    /// Splits regions that exceed `max_region_pages`.
    ///
    /// Large regions are bisected at their midpoint. Returns the
    /// number of splits performed.
    pub fn split_large_regions(&mut self) -> usize {
        let max_pages = self.config.max_region_pages;
        let mut splits = 0_usize;

        for target in &mut self.targets {
            if !target.active {
                continue;
            }

            let mut i = 0_usize;
            while i < target.range_count {
                if !target.ranges[i].active {
                    i += 1;
                    continue;
                }
                let pages = target.ranges[i].nr_pages();
                if pages <= max_pages || target.range_count >= MAX_ADDR_RANGES {
                    i += 1;
                    continue;
                }

                // Split at midpoint (page-aligned).
                let mid = target.ranges[i].start + (pages / 2) * PAGE_SIZE;
                let old_end = target.ranges[i].end;
                target.ranges[i].end = mid;

                // Insert new range for the upper half.
                let new_idx = target.range_count;
                if let Ok(new_range) = DamonAddrRange::new(mid, old_end) {
                    target.ranges[new_idx] = new_range;
                    target.access_counts[new_idx] = target.access_counts[i] / 2;
                    target.ages[new_idx] = target.ages[i];
                    target.range_count += 1;
                    splits += 1;
                }

                i += 1;
            }
        }

        self.stats.region_splits += splits as u64;
        splits
    }

    /// Merges adjacent regions with similar access patterns.
    ///
    /// Two consecutive active ranges are merged when their access
    /// counts differ by at most `threshold` and they are contiguous.
    /// Returns the number of merges performed.
    pub fn merge_similar_regions(&mut self, threshold: u32) -> usize {
        let mut merges = 0_usize;

        for target in &mut self.targets {
            if !target.active {
                continue;
            }

            let mut i = 0_usize;
            while i + 1 < target.range_count {
                if !target.ranges[i].active || !target.ranges[i + 1].active {
                    i += 1;
                    continue;
                }

                let contiguous = target.ranges[i].end == target.ranges[i + 1].start;
                let diff = target.access_counts[i].abs_diff(target.access_counts[i + 1]);

                if contiguous && diff <= threshold {
                    // Extend current range, deactivate next.
                    target.ranges[i].end = target.ranges[i + 1].end;
                    target.access_counts[i] =
                        (target.access_counts[i] + target.access_counts[i + 1]) / 2;
                    target.ages[i] = target.ages[i].max(target.ages[i + 1]);
                    target.ranges[i + 1].active = false;
                    target.range_count = target.range_count.saturating_sub(1);
                    merges += 1;
                    // Do not advance — check further merges.
                } else {
                    i += 1;
                }
            }
        }

        self.stats.region_merges += merges as u64;
        merges
    }

    /// Returns the access pattern for a specific target and range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the target PID is not monitored.
    /// Returns [`Error::InvalidArgument`] if `range_idx` is out of
    /// bounds.
    pub fn get_pattern(&self, pid: u64, range_idx: usize) -> Result<DamonAccessPattern> {
        let target = self
            .targets
            .iter()
            .find(|t| t.active && t.id == pid)
            .ok_or(Error::NotFound)?;

        if range_idx >= target.range_count || !target.ranges[range_idx].active {
            return Err(Error::InvalidArgument);
        }

        Ok(DamonAccessPattern {
            start: target.ranges[range_idx].start,
            end: target.ranges[range_idx].end,
            nr_accesses: target.access_counts[range_idx],
            age: target.ages[range_idx],
            recently_accessed: target.access_counts[range_idx] > 0,
        })
    }

    /// Returns the backend configuration.
    pub const fn config(&self) -> &DamonOpsConfig {
        &self.config
    }

    /// Updates the backend configuration.
    pub fn set_config(&mut self, config: DamonOpsConfig) {
        self.config = config;
    }

    /// Returns backend statistics.
    pub const fn stats(&self) -> &DamonOpsStats {
        &self.stats
    }

    /// Returns the number of active targets.
    pub const fn target_count(&self) -> usize {
        self.target_count
    }

    /// Returns the total number of active ranges across all targets.
    pub fn total_ranges(&self) -> usize {
        self.targets
            .iter()
            .filter(|t| t.active)
            .map(|t| t.range_count)
            .sum()
    }
}

// -------------------------------------------------------------------
// DamonPaddrOps
// -------------------------------------------------------------------

/// Physical-address monitoring backend.
///
/// Monitors raw physical address ranges for system-wide memory
/// profiling. Instead of per-process PTEs, it checks page flags
/// (Referenced/Accessed) on physical page descriptors.
pub struct DamonPaddrOps {
    /// Physical address ranges being monitored.
    ranges: [DamonAddrRange; MAX_ADDR_RANGES],
    /// Number of active ranges.
    range_count: usize,
    /// Per-range access counts.
    access_counts: [u32; MAX_ADDR_RANGES],
    /// Per-range ages.
    ages: [u32; MAX_ADDR_RANGES],
    /// Configuration.
    config: DamonOpsConfig,
    /// Statistics.
    stats: DamonOpsStats,
}

impl Default for DamonPaddrOps {
    fn default() -> Self {
        Self::new()
    }
}

impl DamonPaddrOps {
    /// Creates a new paddr backend with default configuration.
    pub const fn new() -> Self {
        Self {
            ranges: [DamonAddrRange::empty(); MAX_ADDR_RANGES],
            range_count: 0,
            access_counts: [0u32; MAX_ADDR_RANGES],
            ages: [0u32; MAX_ADDR_RANGES],
            config: DamonOpsConfig {
                ops_type: DamonOpsType::Paddr,
                clear_access_bit: true,
                random_sample: false,
                sample_seed: DEFAULT_SEED,
                min_region_pages: 1,
                max_region_pages: 512,
            },
            stats: DamonOpsStats {
                sample_passes: 0,
                pages_sampled: 0,
                pages_accessed: 0,
                access_clears: 0,
                region_splits: 0,
                region_merges: 0,
                targets_inited: 0,
            },
        }
    }

    /// Adds a physical address range to monitor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all range slots are full.
    /// Returns [`Error::InvalidArgument`] if the range is invalid.
    pub fn add_range(&mut self, start: u64, end: u64) -> Result<usize> {
        let range = DamonAddrRange::new(start, end)?;
        if self.range_count >= MAX_ADDR_RANGES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.range_count;
        self.ranges[idx] = range;
        self.access_counts[idx] = 0;
        self.ages[idx] = 0;
        self.range_count += 1;
        Ok(idx)
    }

    /// Removes a physical address range by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of
    /// range or the slot is not active.
    pub fn remove_range(&mut self, index: usize) -> Result<()> {
        if index >= self.range_count || !self.ranges[index].active {
            return Err(Error::InvalidArgument);
        }
        self.ranges[index].active = false;
        self.range_count = self.range_count.saturating_sub(1);
        Ok(())
    }

    /// Performs one sampling pass across all physical ranges.
    ///
    /// The `access_bits` slice provides simulated access results.
    /// Returns the number of ranges found to be accessed.
    pub fn sample(&mut self, access_bits: &[bool]) -> usize {
        let mut accessed = 0_usize;

        for i in 0..self.range_count {
            if !self.ranges[i].active {
                continue;
            }

            let bit = if i < access_bits.len() {
                access_bits[i]
            } else {
                false
            };
            self.stats.pages_sampled += 1;

            if bit {
                self.access_counts[i] = self.access_counts[i].saturating_add(1).min(MAX_SAMPLES);
                accessed += 1;
                self.stats.pages_accessed += 1;
            }

            if self.config.clear_access_bit && bit {
                self.stats.access_clears += 1;
            }
        }

        self.stats.sample_passes += 1;
        accessed
    }

    /// Performs one aggregation pass.
    ///
    /// Collects access patterns and resets counters. Returns the
    /// number of patterns written.
    pub fn aggregate(&mut self, patterns_out: &mut [DamonAccessPattern]) -> usize {
        let mut written = 0_usize;

        for i in 0..self.range_count {
            if !self.ranges[i].active {
                continue;
            }
            self.ages[i] = self.ages[i].saturating_add(1);

            if written < patterns_out.len() {
                patterns_out[written] = DamonAccessPattern {
                    start: self.ranges[i].start,
                    end: self.ranges[i].end,
                    nr_accesses: self.access_counts[i],
                    age: self.ages[i],
                    recently_accessed: self.access_counts[i] > 0,
                };
                written += 1;
            }

            self.access_counts[i] = 0;
        }

        written
    }

    /// Returns the backend configuration.
    pub const fn config(&self) -> &DamonOpsConfig {
        &self.config
    }

    /// Returns backend statistics.
    pub const fn stats(&self) -> &DamonOpsStats {
        &self.stats
    }

    /// Returns the number of active ranges.
    pub const fn range_count(&self) -> usize {
        self.range_count
    }
}

// -------------------------------------------------------------------
// DamonOpsRouter
// -------------------------------------------------------------------

/// Dispatches DAMON operations to the selected backend.
///
/// Wraps both [`DamonVaddrOps`] and [`DamonPaddrOps`] and routes
/// calls based on the configured backend type. Only one backend
/// is active at a time.
pub struct DamonOpsRouter {
    /// Virtual-address backend.
    vaddr: DamonVaddrOps,
    /// Physical-address backend.
    paddr: DamonPaddrOps,
    /// Currently selected backend.
    active_type: DamonOpsType,
}

impl Default for DamonOpsRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl DamonOpsRouter {
    /// Creates a new router with vaddr as the default backend.
    pub const fn new() -> Self {
        Self {
            vaddr: DamonVaddrOps::new(),
            paddr: DamonPaddrOps::new(),
            active_type: DamonOpsType::Vaddr,
        }
    }

    /// Selects the active backend.
    pub fn set_backend(&mut self, ops_type: DamonOpsType) {
        self.active_type = ops_type;
    }

    /// Returns the active backend type.
    pub const fn active_backend(&self) -> DamonOpsType {
        self.active_type
    }

    /// Returns a reference to the vaddr backend.
    pub const fn vaddr(&self) -> &DamonVaddrOps {
        &self.vaddr
    }

    /// Returns a mutable reference to the vaddr backend.
    pub fn vaddr_mut(&mut self) -> &mut DamonVaddrOps {
        &mut self.vaddr
    }

    /// Returns a reference to the paddr backend.
    pub const fn paddr(&self) -> &DamonPaddrOps {
        &self.paddr
    }

    /// Returns a mutable reference to the paddr backend.
    pub fn paddr_mut(&mut self) -> &mut DamonPaddrOps {
        &mut self.paddr
    }

    /// Performs a sampling pass on the active backend.
    ///
    /// Returns the number of accessed regions.
    pub fn sample(&mut self, access_bits: &[bool]) -> usize {
        match self.active_type {
            DamonOpsType::Vaddr | DamonOpsType::Fvaddr => self.vaddr.sample(access_bits),
            DamonOpsType::Paddr => self.paddr.sample(access_bits),
        }
    }

    /// Performs an aggregation pass on the active backend.
    ///
    /// Returns the number of patterns collected.
    pub fn aggregate(&mut self, patterns_out: &mut [DamonAccessPattern]) -> usize {
        match self.active_type {
            DamonOpsType::Vaddr | DamonOpsType::Fvaddr => self.vaddr.aggregate(patterns_out),
            DamonOpsType::Paddr => self.paddr.aggregate(patterns_out),
        }
    }

    /// Returns statistics for the active backend.
    pub const fn stats(&self) -> &DamonOpsStats {
        match self.active_type {
            DamonOpsType::Vaddr | DamonOpsType::Fvaddr => self.vaddr.stats(),
            DamonOpsType::Paddr => self.paddr.stats(),
        }
    }
}
