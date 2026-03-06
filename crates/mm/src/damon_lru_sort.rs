// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DAMON-based LRU list sorting.
//!
//! Uses DAMON access patterns to proactively sort pages in the LRU
//! lists, promoting hot pages and demoting cold pages before the
//! reclaim path needs to scan them. This reduces reclaim latency
//! by keeping the LRU lists pre-sorted by access frequency.
//!
//! - [`LruSortAction`] — actions that can be taken on a page
//! - [`LruSortRegion`] — a monitored region with its access score
//! - [`LruSortScheme`] — sorting policy (thresholds + quotas)
//! - [`LruSortStats`] — aggregate sorting statistics
//! - [`LruSortCtx`] — the main LRU sort context
//!
//! Reference: Linux `mm/damon/lru_sort.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of monitored regions.
const MAX_REGIONS: usize = 512;

/// Default hot threshold (access count per aggregation).
const DEFAULT_HOT_THRESHOLD: u32 = 5;

/// Default cold threshold.
const DEFAULT_COLD_THRESHOLD: u32 = 0;

/// Default quota limit in pages per aggregation.
const DEFAULT_QUOTA_PAGES: u64 = 256;

/// Default quota reset interval in microseconds.
const DEFAULT_QUOTA_RESET_US: u64 = 1_000_000;

// -------------------------------------------------------------------
// LruSortAction
// -------------------------------------------------------------------

/// Actions the LRU sort engine can take on a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LruSortAction {
    /// No action needed.
    #[default]
    None,
    /// Promote pages to the active LRU list.
    Promote,
    /// Demote pages to the inactive LRU list.
    Demote,
}

// -------------------------------------------------------------------
// LruSortRegion
// -------------------------------------------------------------------

/// A monitored region annotated with LRU sort metadata.
#[derive(Debug, Clone, Copy, Default)]
pub struct LruSortRegion {
    /// Start address of the region.
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Number of accesses in the last aggregation period.
    pub nr_accesses: u32,
    /// Age in aggregation intervals.
    pub age: u32,
    /// Last action taken on this region.
    pub last_action: LruSortAction,
    /// Whether this slot is active.
    pub active: bool,
}

impl LruSortRegion {
    /// Creates a new region.
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            start,
            end,
            nr_accesses: 0,
            age: 0,
            last_action: LruSortAction::None,
            active: true,
        }
    }

    /// Returns the region size in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Classifies the region based on thresholds.
    pub fn classify(&self, hot: u32, cold: u32) -> LruSortAction {
        if self.nr_accesses >= hot {
            LruSortAction::Promote
        } else if self.nr_accesses <= cold {
            LruSortAction::Demote
        } else {
            LruSortAction::None
        }
    }
}

// -------------------------------------------------------------------
// LruSortScheme
// -------------------------------------------------------------------

/// Sorting policy configuration.
#[derive(Debug, Clone, Copy)]
pub struct LruSortScheme {
    /// Access count at or above which a region is considered hot.
    pub hot_threshold: u32,
    /// Access count at or below which a region is considered cold.
    pub cold_threshold: u32,
    /// Maximum pages to promote/demote per quota window.
    pub quota_pages: u64,
    /// Quota reset interval in microseconds.
    pub quota_reset_us: u64,
    /// Whether promotion is enabled.
    pub promote_enabled: bool,
    /// Whether demotion is enabled.
    pub demote_enabled: bool,
}

impl Default for LruSortScheme {
    fn default() -> Self {
        Self {
            hot_threshold: DEFAULT_HOT_THRESHOLD,
            cold_threshold: DEFAULT_COLD_THRESHOLD,
            quota_pages: DEFAULT_QUOTA_PAGES,
            quota_reset_us: DEFAULT_QUOTA_RESET_US,
            promote_enabled: true,
            demote_enabled: true,
        }
    }
}

impl LruSortScheme {
    /// Validates the scheme configuration.
    pub fn validate(&self) -> Result<()> {
        if self.hot_threshold <= self.cold_threshold {
            return Err(Error::InvalidArgument);
        }
        if self.quota_pages == 0 || self.quota_reset_us == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// -------------------------------------------------------------------
// LruSortStats
// -------------------------------------------------------------------

/// Aggregate LRU sort statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct LruSortStats {
    /// Total regions promoted.
    pub promoted: u64,
    /// Total regions demoted.
    pub demoted: u64,
    /// Total pages promoted (estimated).
    pub pages_promoted: u64,
    /// Total pages demoted (estimated).
    pub pages_demoted: u64,
    /// Quota limit hits (promotion).
    pub quota_promote_limit: u64,
    /// Quota limit hits (demotion).
    pub quota_demote_limit: u64,
    /// Total sorting passes.
    pub sort_passes: u64,
}

impl LruSortStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// LruSortCtx
// -------------------------------------------------------------------

/// Main DAMON LRU sort context.
pub struct LruSortCtx {
    /// Monitored regions.
    regions: [LruSortRegion; MAX_REGIONS],
    /// Number of active regions.
    nr_regions: usize,
    /// Sorting scheme.
    scheme: LruSortScheme,
    /// Statistics.
    stats: LruSortStats,
    /// Pages promoted in the current quota window.
    quota_promoted: u64,
    /// Pages demoted in the current quota window.
    quota_demoted: u64,
    /// Whether the context is running.
    running: bool,
}

impl Default for LruSortCtx {
    fn default() -> Self {
        Self {
            regions: [LruSortRegion::default(); MAX_REGIONS],
            nr_regions: 0,
            scheme: LruSortScheme::default(),
            stats: LruSortStats::default(),
            quota_promoted: 0,
            quota_demoted: 0,
            running: false,
        }
    }
}

impl LruSortCtx {
    /// Creates a new LRU sort context.
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
        self.regions[idx] = LruSortRegion::new(start, end);
        self.nr_regions += 1;
        Ok(idx)
    }

    /// Updates access count for a region.
    pub fn update_accesses(&mut self, idx: usize, nr_accesses: u32) -> Result<()> {
        if idx >= self.nr_regions || !self.regions[idx].active {
            return Err(Error::NotFound);
        }
        self.regions[idx].nr_accesses = nr_accesses;
        Ok(())
    }

    /// Runs one sorting pass over all regions.
    pub fn sort_pass(&mut self) -> Result<(u64, u64)> {
        self.scheme.validate()?;
        let page_size: u64 = 4096;
        let mut promoted = 0u64;
        let mut demoted = 0u64;

        for i in 0..self.nr_regions {
            if !self.regions[i].active {
                continue;
            }
            let action =
                self.regions[i].classify(self.scheme.hot_threshold, self.scheme.cold_threshold);
            let pages = self.regions[i].size() / page_size;

            match action {
                LruSortAction::Promote if self.scheme.promote_enabled => {
                    if self.quota_promoted + pages > self.scheme.quota_pages {
                        self.stats.quota_promote_limit += 1;
                        continue;
                    }
                    self.regions[i].last_action = LruSortAction::Promote;
                    self.quota_promoted += pages;
                    promoted += pages;
                }
                LruSortAction::Demote if self.scheme.demote_enabled => {
                    if self.quota_demoted + pages > self.scheme.quota_pages {
                        self.stats.quota_demote_limit += 1;
                        continue;
                    }
                    self.regions[i].last_action = LruSortAction::Demote;
                    self.quota_demoted += pages;
                    demoted += pages;
                }
                _ => {
                    self.regions[i].last_action = LruSortAction::None;
                }
            }
        }

        self.stats.pages_promoted += promoted;
        self.stats.pages_demoted += demoted;
        self.stats.sort_passes += 1;
        Ok((promoted, demoted))
    }

    /// Resets the quota counters for a new window.
    pub fn reset_quota(&mut self) {
        self.quota_promoted = 0;
        self.quota_demoted = 0;
    }

    /// Sets the sorting scheme.
    pub fn set_scheme(&mut self, scheme: LruSortScheme) -> Result<()> {
        scheme.validate()?;
        self.scheme = scheme;
        Ok(())
    }

    /// Starts the LRU sort context.
    pub fn start(&mut self) -> Result<()> {
        if self.running {
            return Err(Error::Busy);
        }
        self.running = true;
        Ok(())
    }

    /// Stops the LRU sort context.
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

    /// Returns the number of active regions.
    pub fn nr_regions(&self) -> usize {
        self.nr_regions
    }

    /// Returns statistics.
    pub fn stats(&self) -> &LruSortStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
