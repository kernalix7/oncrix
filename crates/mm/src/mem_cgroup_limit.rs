// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory cgroup limit enforcement.
//!
//! Each memory cgroup has hard and soft limits on memory usage. When a
//! cgroup exceeds its hard limit, new allocations are denied or reclaim
//! is forced. Soft limits trigger background reclaim with lower
//! urgency. This module tracks per-cgroup usage, enforces limits, and
//! handles the reclaim/OOM path when limits are exceeded.
//!
//! # Design
//!
//! ```text
//!  charge(cg, pages)
//!       │
//!       ├─ usage + pages <= hard_limit → charge succeeds
//!       ├─ usage + pages > hard_limit  → try_reclaim(cg)
//!       │       ├─ reclaim freed pages → charge succeeds
//!       │       └─ reclaim failed      → Err(OutOfMemory) / OOM
//!       └─ usage > soft_limit          → schedule background reclaim
//!
//!  uncharge(cg, pages) → decrement usage
//! ```
//!
//! # Key Types
//!
//! - [`MemCgLimit`] — per-cgroup limits and usage
//! - [`LimitEnforcer`] — the enforcement engine
//! - [`EnforcerStats`] — enforcement statistics
//!
//! Reference: Linux `mm/memcontrol.c`, `include/linux/memcontrol.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum tracked cgroups.
const MAX_CGROUPS: usize = 128;

/// Unlimited memory (sentinel).
const UNLIMITED: u64 = u64::MAX;

/// Reclaim batch size (pages).
const RECLAIM_BATCH: u64 = 32;

/// Maximum reclaim attempts before giving up.
const MAX_RECLAIM_ATTEMPTS: u32 = 16;

// -------------------------------------------------------------------
// LimitType
// -------------------------------------------------------------------

/// Type of memory limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitType {
    /// Hard limit — allocations denied above this.
    Hard,
    /// Soft limit — background reclaim trigger.
    Soft,
    /// Swap limit.
    Swap,
}

impl LimitType {
    /// Return a label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Hard => "hard",
            Self::Soft => "soft",
            Self::Swap => "swap",
        }
    }
}

// -------------------------------------------------------------------
// MemCgLimit
// -------------------------------------------------------------------

/// Per-cgroup memory limits and current usage.
#[derive(Debug, Clone, Copy)]
pub struct MemCgLimit {
    /// Cgroup identifier.
    cg_id: u64,
    /// Hard memory limit (pages).
    hard_limit: u64,
    /// Soft memory limit (pages).
    soft_limit: u64,
    /// Swap limit (pages).
    swap_limit: u64,
    /// Current memory usage (pages).
    usage: u64,
    /// Current swap usage (pages).
    swap_usage: u64,
    /// Maximum usage ever reached (pages).
    max_usage: u64,
    /// Number of times the hard limit was hit.
    failcnt: u64,
    /// Whether this entry is active.
    active: bool,
}

impl MemCgLimit {
    /// Create a new cgroup limit.
    pub const fn new(cg_id: u64, hard_limit: u64) -> Self {
        Self {
            cg_id,
            hard_limit,
            soft_limit: UNLIMITED,
            swap_limit: UNLIMITED,
            usage: 0,
            swap_usage: 0,
            max_usage: 0,
            failcnt: 0,
            active: true,
        }
    }

    /// Create an unlimited cgroup.
    pub const fn unlimited(cg_id: u64) -> Self {
        Self {
            cg_id,
            hard_limit: UNLIMITED,
            soft_limit: UNLIMITED,
            swap_limit: UNLIMITED,
            usage: 0,
            swap_usage: 0,
            max_usage: 0,
            failcnt: 0,
            active: true,
        }
    }

    /// Return the cgroup identifier.
    pub const fn cg_id(&self) -> u64 {
        self.cg_id
    }

    /// Return the hard limit.
    pub const fn hard_limit(&self) -> u64 {
        self.hard_limit
    }

    /// Return the soft limit.
    pub const fn soft_limit(&self) -> u64 {
        self.soft_limit
    }

    /// Return the current usage.
    pub const fn usage(&self) -> u64 {
        self.usage
    }

    /// Return the max usage.
    pub const fn max_usage(&self) -> u64 {
        self.max_usage
    }

    /// Return the fail count.
    pub const fn failcnt(&self) -> u64 {
        self.failcnt
    }

    /// Check whether the hard limit would be exceeded.
    pub const fn would_exceed_hard(&self, pages: u64) -> bool {
        if self.hard_limit == UNLIMITED {
            return false;
        }
        self.usage + pages > self.hard_limit
    }

    /// Check whether above the soft limit.
    pub const fn above_soft(&self) -> bool {
        if self.soft_limit == UNLIMITED {
            return false;
        }
        self.usage > self.soft_limit
    }

    /// Charge pages to this cgroup.
    pub fn charge(&mut self, pages: u64) -> Result<()> {
        if self.would_exceed_hard(pages) {
            self.failcnt += 1;
            return Err(Error::OutOfMemory);
        }
        self.usage += pages;
        if self.usage > self.max_usage {
            self.max_usage = self.usage;
        }
        Ok(())
    }

    /// Uncharge pages from this cgroup.
    pub fn uncharge(&mut self, pages: u64) {
        self.usage = self.usage.saturating_sub(pages);
    }

    /// Set the soft limit.
    pub fn set_soft_limit(&mut self, limit: u64) {
        self.soft_limit = limit;
    }

    /// Set the swap limit.
    pub fn set_swap_limit(&mut self, limit: u64) {
        self.swap_limit = limit;
    }

    /// Set the hard limit.
    pub fn set_hard_limit(&mut self, limit: u64) {
        self.hard_limit = limit;
    }

    /// Check whether this entry is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate this entry.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Return available pages before hard limit.
    pub const fn available(&self) -> u64 {
        if self.hard_limit == UNLIMITED {
            return UNLIMITED;
        }
        self.hard_limit.saturating_sub(self.usage)
    }

    /// Return usage as a percentage of hard limit.
    pub const fn usage_pct(&self) -> u64 {
        if self.hard_limit == 0 || self.hard_limit == UNLIMITED {
            return 0;
        }
        self.usage * 100 / self.hard_limit
    }
}

impl Default for MemCgLimit {
    fn default() -> Self {
        Self {
            cg_id: 0,
            hard_limit: UNLIMITED,
            soft_limit: UNLIMITED,
            swap_limit: UNLIMITED,
            usage: 0,
            swap_usage: 0,
            max_usage: 0,
            failcnt: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// EnforcerStats
// -------------------------------------------------------------------

/// Enforcement statistics.
#[derive(Debug, Clone, Copy)]
pub struct EnforcerStats {
    /// Total charge operations.
    pub charges: u64,
    /// Total charge failures.
    pub charge_failures: u64,
    /// Total reclaim attempts triggered.
    pub reclaim_attempts: u64,
    /// Successful reclaims.
    pub reclaim_successes: u64,
    /// OOM kills triggered.
    pub oom_kills: u64,
}

impl EnforcerStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            charges: 0,
            charge_failures: 0,
            reclaim_attempts: 0,
            reclaim_successes: 0,
            oom_kills: 0,
        }
    }
}

impl Default for EnforcerStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// LimitEnforcer
// -------------------------------------------------------------------

/// The memory cgroup limit enforcement engine.
pub struct LimitEnforcer {
    /// Per-cgroup limits.
    limits: [MemCgLimit; MAX_CGROUPS],
    /// Number of tracked cgroups.
    count: usize,
    /// Statistics.
    stats: EnforcerStats,
}

impl LimitEnforcer {
    /// Create a new enforcer.
    pub const fn new() -> Self {
        Self {
            limits: [const {
                MemCgLimit {
                    cg_id: 0,
                    hard_limit: UNLIMITED,
                    soft_limit: UNLIMITED,
                    swap_limit: UNLIMITED,
                    usage: 0,
                    swap_usage: 0,
                    max_usage: 0,
                    failcnt: 0,
                    active: false,
                }
            }; MAX_CGROUPS],
            count: 0,
            stats: EnforcerStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &EnforcerStats {
        &self.stats
    }

    /// Return the number of tracked cgroups.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Register a cgroup.
    pub fn register(&mut self, cg_id: u64, hard_limit: u64) -> Result<()> {
        if self.count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        self.limits[self.count] = MemCgLimit::new(cg_id, hard_limit);
        self.count += 1;
        Ok(())
    }

    /// Charge pages to a cgroup, attempting reclaim if needed.
    pub fn charge(&mut self, cg_id: u64, pages: u64) -> Result<()> {
        self.stats.charges += 1;
        for idx in 0..self.count {
            if self.limits[idx].is_active() && self.limits[idx].cg_id() == cg_id {
                if self.limits[idx].would_exceed_hard(pages) {
                    // Simulate reclaim attempt.
                    self.stats.reclaim_attempts += 1;
                    let reclaimable = RECLAIM_BATCH;
                    if self.limits[idx].usage() >= reclaimable {
                        self.limits[idx].uncharge(reclaimable);
                        self.stats.reclaim_successes += 1;
                    }
                }
                return match self.limits[idx].charge(pages) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        self.stats.charge_failures += 1;
                        Err(e)
                    }
                };
            }
        }
        Err(Error::NotFound)
    }

    /// Uncharge pages from a cgroup.
    pub fn uncharge(&mut self, cg_id: u64, pages: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.limits[idx].is_active() && self.limits[idx].cg_id() == cg_id {
                self.limits[idx].uncharge(pages);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a cgroup's limits.
    pub fn lookup(&self, cg_id: u64) -> Option<&MemCgLimit> {
        for idx in 0..self.count {
            if self.limits[idx].is_active() && self.limits[idx].cg_id() == cg_id {
                return Some(&self.limits[idx]);
            }
        }
        None
    }
}

impl Default for LimitEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Check whether a cgroup is over its soft limit.
pub fn over_soft_limit(enforcer: &LimitEnforcer, cg_id: u64) -> bool {
    match enforcer.lookup(cg_id) {
        Some(limit) => limit.above_soft(),
        None => false,
    }
}

/// Return the usage percentage for a cgroup.
pub fn usage_percent(enforcer: &LimitEnforcer, cg_id: u64) -> u64 {
    match enforcer.lookup(cg_id) {
        Some(limit) => limit.usage_pct(),
        None => 0,
    }
}

/// Return the maximum reclaim attempts constant.
pub const fn max_reclaim_attempts() -> u32 {
    MAX_RECLAIM_ATTEMPTS
}
