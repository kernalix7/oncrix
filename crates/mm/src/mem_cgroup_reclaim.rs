// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory cgroup reclaim control.
//!
//! Implements per-cgroup memory reclamation: tracks memory usage
//! against cgroup limits, triggers reclaim when limits are approached,
//! and implements soft/hard limit enforcement with hierarchical
//! reclaim support.
//!
//! - [`ReclaimPriority`] — reclaim urgency levels
//! - [`MemcgLimit`] — cgroup memory limits
//! - [`MemcgUsage`] — current cgroup memory usage
//! - [`MemcgReclaimStats`] — per-cgroup reclaim statistics
//! - [`MemcgReclaimCtx`] — the reclaim controller
//!
//! Reference: Linux `mm/memcontrol.c` (mem_cgroup_reclaim).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum cgroups tracked.
const MAX_CGROUPS: usize = 64;

/// Default scan batch (pages).
const DEFAULT_BATCH: u64 = 32;

/// Default low watermark (percentage of limit).
const LOW_WATERMARK_PCT: u64 = 90;

// -------------------------------------------------------------------
// ReclaimPriority
// -------------------------------------------------------------------

/// Reclaim urgency levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ReclaimPriority {
    /// No reclaim needed.
    #[default]
    None,
    /// Soft reclaim (background).
    Soft,
    /// Hard reclaim (synchronous).
    Hard,
    /// Critical — OOM may follow.
    Critical,
}

// -------------------------------------------------------------------
// MemcgLimit
// -------------------------------------------------------------------

/// Memory limits for a cgroup.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemcgLimit {
    /// Hard limit in pages.
    pub hard_limit: u64,
    /// Soft limit in pages.
    pub soft_limit: u64,
    /// High watermark in pages.
    pub high: u64,
    /// Low watermark in pages.
    pub low: u64,
    /// Minimum guarantee in pages.
    pub min_pages: u64,
}

impl MemcgLimit {
    /// Creates a new limit configuration.
    pub fn new(hard_limit: u64) -> Self {
        Self {
            hard_limit,
            soft_limit: hard_limit * LOW_WATERMARK_PCT / 100,
            high: hard_limit * 95 / 100,
            low: hard_limit * LOW_WATERMARK_PCT / 100,
            min_pages: 0,
        }
    }

    /// Validates the limit configuration.
    pub fn validate(&self) -> Result<()> {
        if self.hard_limit == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.soft_limit > self.hard_limit {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// -------------------------------------------------------------------
// MemcgUsage
// -------------------------------------------------------------------

/// Current memory usage for a cgroup.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemcgUsage {
    /// Cgroup ID.
    pub cgroup_id: u64,
    /// Current usage in pages.
    pub usage: u64,
    /// Limits.
    pub limit: MemcgLimit,
    /// Whether this cgroup is active.
    pub active: bool,
}

impl MemcgUsage {
    /// Creates a new cgroup usage tracker.
    pub fn new(cgroup_id: u64, hard_limit: u64) -> Self {
        Self {
            cgroup_id,
            usage: 0,
            limit: MemcgLimit::new(hard_limit),
            active: true,
        }
    }

    /// Returns the current reclaim priority.
    pub fn priority(&self) -> ReclaimPriority {
        if self.usage >= self.limit.hard_limit {
            ReclaimPriority::Critical
        } else if self.usage >= self.limit.high {
            ReclaimPriority::Hard
        } else if self.usage >= self.limit.soft_limit {
            ReclaimPriority::Soft
        } else {
            ReclaimPriority::None
        }
    }

    /// Returns the usage ratio (per-mille).
    pub fn usage_ratio(&self) -> u32 {
        if self.limit.hard_limit == 0 {
            return 0;
        }
        ((self.usage * 1000) / self.limit.hard_limit) as u32
    }

    /// Charges pages to this cgroup.
    pub fn charge(&mut self, nr_pages: u64) -> Result<()> {
        let new_usage = self.usage.saturating_add(nr_pages);
        if new_usage > self.limit.hard_limit {
            return Err(Error::OutOfMemory);
        }
        self.usage = new_usage;
        Ok(())
    }

    /// Uncharged pages from this cgroup.
    pub fn uncharge(&mut self, nr_pages: u64) {
        self.usage = self.usage.saturating_sub(nr_pages);
    }
}

// -------------------------------------------------------------------
// MemcgReclaimStats
// -------------------------------------------------------------------

/// Per-cgroup reclaim statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemcgReclaimStats {
    /// Total reclaim attempts.
    pub reclaim_attempts: u64,
    /// Pages reclaimed.
    pub pages_reclaimed: u64,
    /// Soft limit triggers.
    pub soft_triggers: u64,
    /// Hard limit triggers.
    pub hard_triggers: u64,
    /// Critical (OOM-risk) triggers.
    pub critical_triggers: u64,
    /// Total charges.
    pub charges: u64,
    /// Charge failures (over limit).
    pub charge_failures: u64,
}

impl MemcgReclaimStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// MemcgReclaimCtx
// -------------------------------------------------------------------

/// The memory cgroup reclaim controller.
pub struct MemcgReclaimCtx {
    /// Tracked cgroups.
    cgroups: [MemcgUsage; MAX_CGROUPS],
    /// Number of tracked cgroups.
    count: usize,
    /// Reclaim batch size.
    batch_size: u64,
    /// Statistics.
    stats: MemcgReclaimStats,
}

impl Default for MemcgReclaimCtx {
    fn default() -> Self {
        Self {
            cgroups: [MemcgUsage::default(); MAX_CGROUPS],
            count: 0,
            batch_size: DEFAULT_BATCH,
            stats: MemcgReclaimStats::default(),
        }
    }
}

impl MemcgReclaimCtx {
    /// Creates a new reclaim controller.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a cgroup.
    pub fn register(&mut self, cgroup_id: u64, hard_limit: u64) -> Result<usize> {
        if self.count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.cgroups[idx] = MemcgUsage::new(cgroup_id, hard_limit);
        self.count += 1;
        Ok(idx)
    }

    /// Charges pages to a cgroup.
    pub fn charge(&mut self, idx: usize, nr_pages: u64) -> Result<()> {
        if idx >= self.count || !self.cgroups[idx].active {
            return Err(Error::NotFound);
        }
        self.stats.charges += 1;
        self.cgroups[idx].charge(nr_pages).map_err(|e| {
            self.stats.charge_failures += 1;
            e
        })
    }

    /// Runs reclaim on cgroups that exceed their limits.
    pub fn reclaim_pass(&mut self) -> u64 {
        let mut total_reclaimed = 0u64;

        for i in 0..self.count {
            if !self.cgroups[i].active {
                continue;
            }
            let priority = self.cgroups[i].priority();
            if priority == ReclaimPriority::None {
                continue;
            }

            match priority {
                ReclaimPriority::Soft => self.stats.soft_triggers += 1,
                ReclaimPriority::Hard => self.stats.hard_triggers += 1,
                ReclaimPriority::Critical => self.stats.critical_triggers += 1,
                _ => {}
            }

            let to_reclaim = self.batch_size;
            self.cgroups[i].uncharge(to_reclaim);
            total_reclaimed += to_reclaim;
            self.stats.reclaim_attempts += 1;
        }

        self.stats.pages_reclaimed += total_reclaimed;
        total_reclaimed
    }

    /// Returns the number of tracked cgroups.
    pub fn cgroup_count(&self) -> usize {
        self.count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &MemcgReclaimStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
