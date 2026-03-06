// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Compaction deferral logic.
//!
//! Implements the deferral mechanism for memory compaction: when
//! compaction fails or yields insufficient results, further attempts
//! are deferred exponentially to avoid wasting CPU cycles. Tracks
//! per-zone deferral state and reset conditions.
//!
//! - [`DeferState`] — deferral state for a zone
//! - [`DeferPolicy`] — deferral policy configuration
//! - [`CompactionDeferStats`] — deferral statistics
//! - [`CompactionDefer`] — the deferral controller
//!
//! Reference: Linux `mm/compaction.c` (compaction_defer_shift).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum zones tracked.
const MAX_ZONES: usize = 32;

/// Maximum deferral shift (exponential backoff limit).
const MAX_DEFER_SHIFT: u32 = 6;

/// Initial deferral count.
const INITIAL_DEFER_COUNT: u32 = 1;

// -------------------------------------------------------------------
// DeferState
// -------------------------------------------------------------------

/// Deferral state for a single zone.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeferState {
    /// Zone ID.
    pub zone_id: u32,
    /// Current deferral shift (exponential backoff).
    pub defer_shift: u32,
    /// Remaining deferred compaction attempts.
    pub defer_count: u32,
    /// Total compaction attempts for this zone.
    pub attempts: u64,
    /// Total deferred (skipped) compactions.
    pub deferred: u64,
    /// Last compaction order that succeeded.
    pub last_success_order: u32,
    /// Whether this zone is active.
    pub active: bool,
}

impl DeferState {
    /// Creates a new deferral state.
    pub fn new(zone_id: u32) -> Self {
        Self {
            zone_id,
            defer_shift: 0,
            defer_count: 0,
            attempts: 0,
            deferred: 0,
            last_success_order: 0,
            active: true,
        }
    }

    /// Returns `true` if compaction should be deferred.
    pub fn should_defer(&self) -> bool {
        self.defer_count > 0
    }

    /// Records a compaction failure, increasing deferral.
    pub fn record_failure(&mut self) {
        if self.defer_shift < MAX_DEFER_SHIFT {
            self.defer_shift += 1;
        }
        self.defer_count = INITIAL_DEFER_COUNT << self.defer_shift;
    }

    /// Records a compaction success, resetting deferral.
    pub fn record_success(&mut self, order: u32) {
        self.defer_shift = 0;
        self.defer_count = 0;
        self.last_success_order = order;
    }

    /// Decrements the deferral counter (called on each scan pass).
    pub fn tick(&mut self) {
        self.attempts += 1;
        if self.defer_count > 0 {
            self.defer_count -= 1;
            self.deferred += 1;
        }
    }
}

// -------------------------------------------------------------------
// DeferPolicy
// -------------------------------------------------------------------

/// Deferral policy configuration.
#[derive(Debug, Clone, Copy)]
pub struct DeferPolicy {
    /// Maximum deferral shift.
    pub max_shift: u32,
    /// Whether to reset on allocation success at any order.
    pub reset_on_any_success: bool,
    /// Minimum order to track for deferral.
    pub min_order: u32,
}

impl Default for DeferPolicy {
    fn default() -> Self {
        Self {
            max_shift: MAX_DEFER_SHIFT,
            reset_on_any_success: false,
            min_order: 1,
        }
    }
}

// -------------------------------------------------------------------
// CompactionDeferStats
// -------------------------------------------------------------------

/// Aggregate deferral statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompactionDeferStats {
    /// Total compaction attempts across all zones.
    pub total_attempts: u64,
    /// Total deferred compactions.
    pub total_deferred: u64,
    /// Total successes.
    pub total_successes: u64,
    /// Total failures.
    pub total_failures: u64,
}

impl CompactionDeferStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// CompactionDefer
// -------------------------------------------------------------------

/// The compaction deferral controller.
pub struct CompactionDefer {
    /// Per-zone deferral state.
    zones: [DeferState; MAX_ZONES],
    /// Number of zones.
    nr_zones: usize,
    /// Policy.
    policy: DeferPolicy,
    /// Statistics.
    stats: CompactionDeferStats,
}

impl Default for CompactionDefer {
    fn default() -> Self {
        Self {
            zones: [DeferState::default(); MAX_ZONES],
            nr_zones: 0,
            policy: DeferPolicy::default(),
            stats: CompactionDeferStats::default(),
        }
    }
}

impl CompactionDefer {
    /// Creates a new deferral controller.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a zone for deferral tracking.
    pub fn add_zone(&mut self, zone_id: u32) -> Result<usize> {
        if self.nr_zones >= MAX_ZONES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.nr_zones;
        self.zones[idx] = DeferState::new(zone_id);
        self.nr_zones += 1;
        Ok(idx)
    }

    /// Checks if compaction should be deferred for a zone.
    pub fn should_defer(&self, idx: usize) -> bool {
        if idx >= self.nr_zones {
            return false;
        }
        self.zones[idx].should_defer()
    }

    /// Records a compaction failure for a zone.
    pub fn record_failure(&mut self, idx: usize) -> Result<()> {
        if idx >= self.nr_zones || !self.zones[idx].active {
            return Err(Error::NotFound);
        }
        self.zones[idx].record_failure();
        self.stats.total_failures += 1;
        Ok(())
    }

    /// Records a compaction success for a zone.
    pub fn record_success(&mut self, idx: usize, order: u32) -> Result<()> {
        if idx >= self.nr_zones || !self.zones[idx].active {
            return Err(Error::NotFound);
        }
        self.zones[idx].record_success(order);
        self.stats.total_successes += 1;
        Ok(())
    }

    /// Ticks all zones (called on each scan pass).
    pub fn tick_all(&mut self) {
        for i in 0..self.nr_zones {
            if self.zones[i].active {
                self.zones[i].tick();
                self.stats.total_attempts += 1;
                if self.zones[i].should_defer() {
                    self.stats.total_deferred += 1;
                }
            }
        }
    }

    /// Returns the number of zones.
    pub fn nr_zones(&self) -> usize {
        self.nr_zones
    }

    /// Returns statistics.
    pub fn stats(&self) -> &CompactionDeferStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
