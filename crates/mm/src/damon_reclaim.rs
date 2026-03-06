// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DAMON-based proactive reclamation.
//!
//! Uses DAMON to identify cold memory regions and proactively reclaim
//! them before the system reaches memory pressure. This reduces the
//! need for direct reclaim and kswapd wakeups by continuously moving
//! cold pages to swap or freeing clean file-backed pages.
//!
//! - [`ReclaimAction`] — action taken on a cold region
//! - [`ReclaimRegion`] — a monitored region with reclaim metadata
//! - [`ReclaimQuota`] — rate limiting for reclamation
//! - [`ReclaimStats`] — aggregate reclamation statistics
//! - [`DamonReclaimCtx`] — the main reclamation context
//!
//! Reference: Linux `mm/damon/reclaim.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of monitored regions.
const MAX_REGIONS: usize = 512;

/// Default cold threshold (accesses per aggregation).
const DEFAULT_COLD_THRESHOLD: u32 = 0;

/// Default minimum age before reclaim (aggregation intervals).
const DEFAULT_MIN_AGE: u32 = 10;

/// Default quota in pages per second.
const DEFAULT_QUOTA_PAGES_PER_SEC: u64 = 1024;

/// Default wmark high (percentage × 10).
const DEFAULT_WMARK_HIGH: u32 = 950;

/// Default wmark mid.
const DEFAULT_WMARK_MID: u32 = 900;

/// Default wmark low.
const DEFAULT_WMARK_LOW: u32 = 800;

// -------------------------------------------------------------------
// ReclaimAction
// -------------------------------------------------------------------

/// Actions the reclaim engine can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReclaimAction {
    /// No action.
    #[default]
    None,
    /// Reclaim pages (pageout to swap or discard).
    Pageout,
    /// Skip — region not cold enough or quota exceeded.
    Skip,
}

// -------------------------------------------------------------------
// ReclaimRegion
// -------------------------------------------------------------------

/// A monitored region annotated with reclaim metadata.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReclaimRegion {
    /// Start address.
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Access count in last aggregation period.
    pub nr_accesses: u32,
    /// Age in aggregation intervals.
    pub age: u32,
    /// Last action taken.
    pub last_action: ReclaimAction,
    /// Whether this slot is active.
    pub active: bool,
}

impl ReclaimRegion {
    /// Creates a new region.
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            start,
            end,
            nr_accesses: 0,
            age: 0,
            last_action: ReclaimAction::None,
            active: true,
        }
    }

    /// Returns the region size in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` if the region is cold enough to reclaim.
    pub fn is_cold(&self, threshold: u32, min_age: u32) -> bool {
        self.nr_accesses <= threshold && self.age >= min_age
    }
}

// -------------------------------------------------------------------
// ReclaimQuota
// -------------------------------------------------------------------

/// Rate limiting for DAMON reclamation.
#[derive(Debug, Clone, Copy)]
pub struct ReclaimQuota {
    /// Maximum pages to reclaim per second.
    pub pages_per_sec: u64,
    /// Pages reclaimed in current window.
    pub current_pages: u64,
    /// Timestamp of current window start (nanoseconds).
    pub window_start_ns: u64,
}

impl Default for ReclaimQuota {
    fn default() -> Self {
        Self {
            pages_per_sec: DEFAULT_QUOTA_PAGES_PER_SEC,
            current_pages: 0,
            window_start_ns: 0,
        }
    }
}

impl ReclaimQuota {
    /// Checks if the quota allows reclaiming more pages.
    pub fn can_reclaim(&self, nr_pages: u64) -> bool {
        self.current_pages + nr_pages <= self.pages_per_sec
    }

    /// Records pages reclaimed.
    pub fn charge(&mut self, nr_pages: u64) {
        self.current_pages = self.current_pages.saturating_add(nr_pages);
    }

    /// Resets the quota for a new window.
    pub fn reset(&mut self, timestamp_ns: u64) {
        self.current_pages = 0;
        self.window_start_ns = timestamp_ns;
    }
}

// -------------------------------------------------------------------
// Watermarks
// -------------------------------------------------------------------

/// Watermark levels for controlling reclamation activity.
#[derive(Debug, Clone, Copy)]
pub struct ReclaimWatermarks {
    /// High watermark (per-mille). Above this, stop reclamation.
    pub high: u32,
    /// Mid watermark. Between mid and high, idle reclamation.
    pub mid: u32,
    /// Low watermark. Below this, aggressive reclamation.
    pub low: u32,
}

impl Default for ReclaimWatermarks {
    fn default() -> Self {
        Self {
            high: DEFAULT_WMARK_HIGH,
            mid: DEFAULT_WMARK_MID,
            low: DEFAULT_WMARK_LOW,
        }
    }
}

impl ReclaimWatermarks {
    /// Validates the watermark configuration.
    pub fn validate(&self) -> Result<()> {
        if self.low >= self.mid || self.mid >= self.high || self.high > 1000 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Returns the urgency level given current free ratio (per-mille).
    pub fn urgency(&self, free_ratio: u32) -> ReclaimAction {
        if free_ratio >= self.high {
            ReclaimAction::None
        } else if free_ratio < self.low {
            ReclaimAction::Pageout
        } else {
            ReclaimAction::Skip
        }
    }
}

// -------------------------------------------------------------------
// ReclaimStats
// -------------------------------------------------------------------

/// Aggregate DAMON reclaim statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReclaimStats {
    /// Total reclaim passes.
    pub passes: u64,
    /// Total regions reclaimed.
    pub regions_reclaimed: u64,
    /// Total pages reclaimed (estimated).
    pub pages_reclaimed: u64,
    /// Quota limit hits.
    pub quota_limits: u64,
    /// Regions skipped (not cold enough).
    pub regions_skipped: u64,
}

impl ReclaimStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// DamonReclaimCtx
// -------------------------------------------------------------------

/// Main DAMON reclaim context.
pub struct DamonReclaimCtx {
    /// Monitored regions.
    regions: [ReclaimRegion; MAX_REGIONS],
    /// Number of active regions.
    nr_regions: usize,
    /// Cold threshold.
    cold_threshold: u32,
    /// Minimum age before reclaim.
    min_age: u32,
    /// Quota.
    quota: ReclaimQuota,
    /// Watermarks.
    wmarks: ReclaimWatermarks,
    /// Statistics.
    stats: ReclaimStats,
    /// Whether the context is running.
    running: bool,
}

impl Default for DamonReclaimCtx {
    fn default() -> Self {
        Self {
            regions: [ReclaimRegion::default(); MAX_REGIONS],
            nr_regions: 0,
            cold_threshold: DEFAULT_COLD_THRESHOLD,
            min_age: DEFAULT_MIN_AGE,
            quota: ReclaimQuota::default(),
            wmarks: ReclaimWatermarks::default(),
            stats: ReclaimStats::default(),
            running: false,
        }
    }
}

impl DamonReclaimCtx {
    /// Creates a new reclaim context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a region to monitor.
    pub fn add_region(&mut self, start: u64, end: u64) -> Result<usize> {
        if self.nr_regions >= MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }
        if start >= end {
            return Err(Error::InvalidArgument);
        }
        let idx = self.nr_regions;
        self.regions[idx] = ReclaimRegion::new(start, end);
        self.nr_regions += 1;
        Ok(idx)
    }

    /// Updates access info for a region.
    pub fn update_region(&mut self, idx: usize, nr_accesses: u32, age: u32) -> Result<()> {
        if idx >= self.nr_regions || !self.regions[idx].active {
            return Err(Error::NotFound);
        }
        self.regions[idx].nr_accesses = nr_accesses;
        self.regions[idx].age = age;
        Ok(())
    }

    /// Runs one reclaim pass over all regions.
    pub fn reclaim_pass(&mut self) -> u64 {
        let page_size: u64 = 4096;
        let mut reclaimed = 0u64;

        for i in 0..self.nr_regions {
            if !self.regions[i].active {
                continue;
            }
            if !self.regions[i].is_cold(self.cold_threshold, self.min_age) {
                self.regions[i].last_action = ReclaimAction::Skip;
                self.stats.regions_skipped += 1;
                continue;
            }
            let pages = self.regions[i].size() / page_size;
            if !self.quota.can_reclaim(pages) {
                self.stats.quota_limits += 1;
                continue;
            }
            self.regions[i].last_action = ReclaimAction::Pageout;
            self.quota.charge(pages);
            reclaimed += pages;
            self.stats.regions_reclaimed += 1;
        }

        self.stats.pages_reclaimed += reclaimed;
        self.stats.passes += 1;
        reclaimed
    }

    /// Starts the reclaim context.
    pub fn start(&mut self) -> Result<()> {
        if self.running {
            return Err(Error::Busy);
        }
        self.running = true;
        Ok(())
    }

    /// Stops the reclaim context.
    pub fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Err(Error::InvalidArgument);
        }
        self.running = false;
        Ok(())
    }

    /// Returns whether the context is running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Returns statistics.
    pub fn stats(&self) -> &ReclaimStats {
        &self.stats
    }

    /// Returns the number of active regions.
    pub fn nr_regions(&self) -> usize {
        self.nr_regions
    }

    /// Resets the quota window.
    pub fn reset_quota(&mut self, timestamp_ns: u64) {
        self.quota.reset(timestamp_ns);
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
