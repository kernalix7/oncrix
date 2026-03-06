// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DAMON monitored region management.
//!
//! DAMON (Data Access MONitor) tracks memory access patterns by
//! dividing an address space into regions and sampling access at
//! configurable intervals. This module manages the region list:
//! splitting, merging, and updating access counters so that the
//! monitoring overhead remains bounded regardless of address-space
//! size.
//!
//! # Design
//!
//! ```text
//!  damon_start(target)
//!     │
//!     ├─ initial regions from VMA list
//!     ├─ sampling loop:
//!     │   ├─ pick random page in each region
//!     │   ├─ clear accessed bit, wait interval, re-check
//!     │   └─ update access counter for region
//!     ├─ merge adjacent regions with similar access
//!     └─ split regions that are too large
//! ```
//!
//! # Key Types
//!
//! - [`DamonRegion`] — a single monitored region
//! - [`DamonRegionList`] — list of regions for one target
//! - [`DamonRegionStats`] — region management statistics
//!
//! Reference: Linux `mm/damon/core.c`, `include/linux/damon.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum regions per target.
const MAX_REGIONS: usize = 1024;

/// Minimum region size in pages.
const MIN_REGION_PAGES: u64 = 4;

/// Maximum region size in pages before splitting.
const MAX_REGION_PAGES: u64 = 16384;

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Merge threshold: regions with access diff below this are merged.
const MERGE_THRESHOLD: u32 = 5;

// -------------------------------------------------------------------
// DamonRegion
// -------------------------------------------------------------------

/// A single DAMON monitored region.
#[derive(Debug, Clone, Copy)]
pub struct DamonRegion {
    /// Start address (page-aligned).
    start_addr: u64,
    /// End address (page-aligned, exclusive).
    end_addr: u64,
    /// Access count (number of sampling hits).
    access_count: u32,
    /// Sampling attempts for this region.
    sample_attempts: u32,
    /// Age: number of aggregation intervals since creation.
    age: u32,
    /// Whether the region is active.
    active: bool,
}

impl DamonRegion {
    /// Create a new region.
    pub const fn new(start_addr: u64, end_addr: u64) -> Self {
        Self {
            start_addr,
            end_addr,
            access_count: 0,
            sample_attempts: 0,
            age: 0,
            active: true,
        }
    }

    /// Return the start address.
    pub const fn start_addr(&self) -> u64 {
        self.start_addr
    }

    /// Return the end address.
    pub const fn end_addr(&self) -> u64 {
        self.end_addr
    }

    /// Return the access count.
    pub const fn access_count(&self) -> u32 {
        self.access_count
    }

    /// Return the sample attempts.
    pub const fn sample_attempts(&self) -> u32 {
        self.sample_attempts
    }

    /// Return the age.
    pub const fn age(&self) -> u32 {
        self.age
    }

    /// Check whether the region is active.
    pub const fn active(&self) -> bool {
        self.active
    }

    /// Return the size in pages.
    pub const fn page_count(&self) -> u64 {
        (self.end_addr - self.start_addr) / PAGE_SIZE
    }

    /// Return the size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.end_addr - self.start_addr
    }

    /// Access rate as percent.
    pub const fn access_rate_pct(&self) -> u32 {
        if self.sample_attempts == 0 {
            return 0;
        }
        self.access_count * 100 / self.sample_attempts
    }

    /// Record a sample.
    pub fn record_sample(&mut self, accessed: bool) {
        self.sample_attempts = self.sample_attempts.saturating_add(1);
        if accessed {
            self.access_count = self.access_count.saturating_add(1);
        }
    }

    /// Increment age.
    pub fn increment_age(&mut self) {
        self.age = self.age.saturating_add(1);
    }

    /// Reset access counters (for new aggregation interval).
    pub fn reset_counters(&mut self) {
        self.access_count = 0;
        self.sample_attempts = 0;
    }

    /// Deactivate the region.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Check whether this region is too large and should be split.
    pub const fn should_split(&self) -> bool {
        self.page_count() > MAX_REGION_PAGES
    }

    /// Check whether this region can be merged with an adjacent one.
    pub const fn can_merge_with(&self, other: &DamonRegion) -> bool {
        if self.end_addr != other.start_addr {
            return false;
        }
        let diff = if self.access_count > other.access_count {
            self.access_count - other.access_count
        } else {
            other.access_count - self.access_count
        };
        diff <= MERGE_THRESHOLD
    }
}

impl Default for DamonRegion {
    fn default() -> Self {
        Self {
            start_addr: 0,
            end_addr: 0,
            access_count: 0,
            sample_attempts: 0,
            age: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// DamonRegionStats
// -------------------------------------------------------------------

/// Region management statistics.
#[derive(Debug, Clone, Copy)]
pub struct DamonRegionStats {
    /// Total regions created.
    pub regions_created: u64,
    /// Total regions merged.
    pub regions_merged: u64,
    /// Total regions split.
    pub regions_split: u64,
    /// Total samples taken.
    pub total_samples: u64,
    /// Total accesses detected.
    pub total_accesses: u64,
    /// Total aggregation intervals.
    pub total_aggregations: u64,
}

impl DamonRegionStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            regions_created: 0,
            regions_merged: 0,
            regions_split: 0,
            total_samples: 0,
            total_accesses: 0,
            total_aggregations: 0,
        }
    }

    /// Overall access rate as percent.
    pub const fn access_rate_pct(&self) -> u64 {
        if self.total_samples == 0 {
            return 0;
        }
        self.total_accesses * 100 / self.total_samples
    }
}

impl Default for DamonRegionStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// DamonRegionList
// -------------------------------------------------------------------

/// List of regions for one DAMON target.
pub struct DamonRegionList {
    /// Regions.
    regions: [DamonRegion; MAX_REGIONS],
    /// Number of active regions.
    count: usize,
    /// Target PID.
    target_pid: u64,
    /// Statistics.
    stats: DamonRegionStats,
}

impl DamonRegionList {
    /// Create a new region list.
    pub const fn new(target_pid: u64) -> Self {
        Self {
            regions: [const {
                DamonRegion {
                    start_addr: 0,
                    end_addr: 0,
                    access_count: 0,
                    sample_attempts: 0,
                    age: 0,
                    active: false,
                }
            }; MAX_REGIONS],
            count: 0,
            target_pid,
            stats: DamonRegionStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &DamonRegionStats {
        &self.stats
    }

    /// Return the number of regions.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the target PID.
    pub const fn target_pid(&self) -> u64 {
        self.target_pid
    }

    /// Add a region.
    pub fn add_region(&mut self, start_addr: u64, end_addr: u64) -> Result<()> {
        if start_addr >= end_addr {
            return Err(Error::InvalidArgument);
        }
        let pages = (end_addr - start_addr) / PAGE_SIZE;
        if pages < MIN_REGION_PAGES {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }
        self.regions[self.count] = DamonRegion::new(start_addr, end_addr);
        self.count += 1;
        self.stats.regions_created += 1;
        Ok(())
    }

    /// Record a sample on a region.
    pub fn record_sample(&mut self, index: usize, accessed: bool) -> Result<()> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        self.regions[index].record_sample(accessed);
        self.stats.total_samples += 1;
        if accessed {
            self.stats.total_accesses += 1;
        }
        Ok(())
    }

    /// Aggregate: increment ages and reset counters.
    pub fn aggregate(&mut self) {
        for idx in 0..self.count {
            self.regions[idx].increment_age();
            self.regions[idx].reset_counters();
        }
        self.stats.total_aggregations += 1;
    }

    /// Get a region by index.
    pub fn get_region(&self, index: usize) -> Option<&DamonRegion> {
        if index < self.count {
            Some(&self.regions[index])
        } else {
            None
        }
    }

    /// Total monitored bytes.
    pub fn total_bytes(&self) -> u64 {
        let mut total: u64 = 0;
        for idx in 0..self.count {
            total += self.regions[idx].size_bytes();
        }
        total
    }
}

impl Default for DamonRegionList {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum regions per target.
pub const fn max_regions() -> usize {
    MAX_REGIONS
}

/// Return the merge threshold.
pub const fn merge_threshold() -> u32 {
    MERGE_THRESHOLD
}

/// Return the minimum region size in pages.
pub const fn min_region_pages() -> u64 {
    MIN_REGION_PAGES
}
