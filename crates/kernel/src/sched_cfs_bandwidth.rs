// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CFS bandwidth control — CPU bandwidth throttling for task groups.
//!
//! Implements the CFS (Completely Fair Scheduler) bandwidth controller
//! that enforces CPU time quotas on cgroup task groups.  When a group
//! exhausts its quota within a period, its tasks are throttled until
//! the next period begins.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                CfsBandwidthSubsystem                         │
//! │                                                              │
//! │  BandwidthEntry[0..MAX_ENTRIES]                               │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  group_id: u64                                         │  │
//! │  │  quota_us: i64    (-1 = unlimited)                     │  │
//! │  │  period_us: u64                                        │  │
//! │  │  runtime_remaining_us: i64                             │  │
//! │  │  nr_throttled: u64                                     │  │
//! │  │  throttled_time_us: u64                                │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/sched/fair.c` (CFS bandwidth functions),
//! `include/linux/sched/bandwidth.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum bandwidth entries (one per cgroup task group).
const MAX_ENTRIES: usize = 256;

/// Minimum period in microseconds (1 ms).
const MIN_PERIOD_US: u64 = 1_000;

/// Maximum period in microseconds (1 second).
const MAX_PERIOD_US: u64 = 1_000_000;

/// Default period in microseconds (100 ms).
const DEFAULT_PERIOD_US: u64 = 100_000;

/// Unlimited quota sentinel.
const QUOTA_UNLIMITED: i64 = -1;

// ══════════════════════════════════════════════════════════════
// ThrottleState
// ══════════════════════════════════════════════════════════════

/// Throttle state of a bandwidth entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ThrottleState {
    /// Not throttled (has remaining quota).
    Active = 0,
    /// Throttled (quota exhausted for this period).
    Throttled = 1,
    /// Unlimited (no bandwidth limit configured).
    Unlimited = 2,
}

// ══════════════════════════════════════════════════════════════
// BandwidthEntry
// ══════════════════════════════════════════════════════════════

/// Bandwidth control entry for a single task group.
#[derive(Debug, Clone, Copy)]
pub struct BandwidthEntry {
    /// Cgroup task group identifier.
    pub group_id: u64,
    /// CPU time quota per period in microseconds (-1 = unlimited).
    pub quota_us: i64,
    /// Period length in microseconds.
    pub period_us: u64,
    /// Remaining runtime in the current period.
    pub runtime_remaining_us: i64,
    /// Number of times this group has been throttled.
    pub nr_throttled: u64,
    /// Cumulative throttled time in microseconds.
    pub throttled_time_us: u64,
    /// Current throttle state.
    pub state: ThrottleState,
    /// Number of periods elapsed.
    pub nr_periods: u64,
    /// Whether this entry is active.
    pub active: bool,
    /// Whether the entry has burst support enabled.
    pub burst_enabled: bool,
    /// Burst budget in microseconds.
    pub burst_us: u64,
}

impl BandwidthEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            group_id: 0,
            quota_us: QUOTA_UNLIMITED,
            period_us: DEFAULT_PERIOD_US,
            runtime_remaining_us: 0,
            nr_throttled: 0,
            throttled_time_us: 0,
            state: ThrottleState::Unlimited,
            nr_periods: 0,
            active: false,
            burst_enabled: false,
            burst_us: 0,
        }
    }

    /// Returns `true` if the group is currently throttled.
    pub const fn is_throttled(&self) -> bool {
        matches!(self.state, ThrottleState::Throttled)
    }

    /// Returns `true` if the group has an unlimited quota.
    pub const fn is_unlimited(&self) -> bool {
        self.quota_us == QUOTA_UNLIMITED
    }
}

// ══════════════════════════════════════════════════════════════
// CfsBandwidthStats
// ══════════════════════════════════════════════════════════════

/// Aggregated CFS bandwidth statistics.
#[derive(Debug, Clone, Copy)]
pub struct CfsBandwidthStats {
    /// Total periods elapsed across all groups.
    pub total_periods: u64,
    /// Total throttle events.
    pub total_throttled: u64,
    /// Total throttled time in microseconds.
    pub total_throttled_time_us: u64,
    /// Total runtime distributed in microseconds.
    pub total_runtime_us: u64,
    /// Total burst runtime consumed.
    pub total_burst_us: u64,
}

impl CfsBandwidthStats {
    const fn new() -> Self {
        Self {
            total_periods: 0,
            total_throttled: 0,
            total_throttled_time_us: 0,
            total_runtime_us: 0,
            total_burst_us: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// CfsBandwidthSubsystem
// ══════════════════════════════════════════════════════════════

/// Top-level CFS bandwidth control subsystem.
pub struct CfsBandwidthSubsystem {
    /// Bandwidth entries.
    entries: [BandwidthEntry; MAX_ENTRIES],
    /// Statistics.
    stats: CfsBandwidthStats,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for CfsBandwidthSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl CfsBandwidthSubsystem {
    /// Create a new CFS bandwidth subsystem.
    pub const fn new() -> Self {
        Self {
            entries: [const { BandwidthEntry::empty() }; MAX_ENTRIES],
            stats: CfsBandwidthStats::new(),
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    // ── Entry management ─────────────────────────────────────

    /// Register a bandwidth entry for a task group.
    ///
    /// Returns the entry slot index.
    pub fn register(&mut self, group_id: u64, quota_us: i64, period_us: u64) -> Result<usize> {
        if period_us < MIN_PERIOD_US || period_us > MAX_PERIOD_US {
            return Err(Error::InvalidArgument);
        }
        if quota_us != QUOTA_UNLIMITED && quota_us <= 0 {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        let state = if quota_us == QUOTA_UNLIMITED {
            ThrottleState::Unlimited
        } else {
            ThrottleState::Active
        };

        self.entries[slot] = BandwidthEntry {
            group_id,
            quota_us,
            period_us,
            runtime_remaining_us: quota_us,
            nr_throttled: 0,
            throttled_time_us: 0,
            state,
            nr_periods: 0,
            active: true,
            burst_enabled: false,
            burst_us: 0,
        };
        Ok(slot)
    }

    /// Update the quota and period for an entry.
    pub fn update_quota(&mut self, slot: usize, quota_us: i64, period_us: u64) -> Result<()> {
        if slot >= MAX_ENTRIES || !self.entries[slot].active {
            return Err(Error::NotFound);
        }
        if period_us < MIN_PERIOD_US || period_us > MAX_PERIOD_US {
            return Err(Error::InvalidArgument);
        }
        self.entries[slot].quota_us = quota_us;
        self.entries[slot].period_us = period_us;
        self.entries[slot].state = if quota_us == QUOTA_UNLIMITED {
            ThrottleState::Unlimited
        } else {
            ThrottleState::Active
        };
        Ok(())
    }

    /// Unregister an entry.
    pub fn unregister(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_ENTRIES || !self.entries[slot].active {
            return Err(Error::NotFound);
        }
        self.entries[slot] = BandwidthEntry::empty();
        Ok(())
    }

    // ── Runtime accounting ───────────────────────────────────

    /// Consume runtime for a task group.
    ///
    /// Returns `true` if the group should be throttled.
    pub fn consume_runtime(&mut self, slot: usize, runtime_us: u64) -> Result<bool> {
        if slot >= MAX_ENTRIES || !self.entries[slot].active {
            return Err(Error::NotFound);
        }

        if self.entries[slot].is_unlimited() {
            return Ok(false);
        }

        self.entries[slot].runtime_remaining_us -= runtime_us as i64;
        self.stats.total_runtime_us += runtime_us;

        if self.entries[slot].runtime_remaining_us <= 0 {
            // Try burst budget.
            if self.entries[slot].burst_enabled && self.entries[slot].burst_us > 0 {
                let needed = (-self.entries[slot].runtime_remaining_us) as u64;
                if needed <= self.entries[slot].burst_us {
                    self.entries[slot].burst_us -= needed;
                    self.entries[slot].runtime_remaining_us = 0;
                    self.stats.total_burst_us += needed;
                    return Ok(false);
                }
            }

            self.entries[slot].state = ThrottleState::Throttled;
            self.entries[slot].nr_throttled += 1;
            self.stats.total_throttled += 1;
            return Ok(true);
        }

        Ok(false)
    }

    /// Start a new period, refilling the runtime quota.
    pub fn period_tick(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_ENTRIES || !self.entries[slot].active {
            return Err(Error::NotFound);
        }

        self.entries[slot].nr_periods += 1;
        self.stats.total_periods += 1;

        if !self.entries[slot].is_unlimited() {
            if self.entries[slot].is_throttled() {
                let throttled_us = self.entries[slot].period_us;
                self.entries[slot].throttled_time_us += throttled_us;
                self.stats.total_throttled_time_us += throttled_us;
            }
            self.entries[slot].runtime_remaining_us = self.entries[slot].quota_us;
            self.entries[slot].state = ThrottleState::Active;
        }

        Ok(())
    }

    /// Enable burst support for an entry.
    pub fn set_burst(&mut self, slot: usize, burst_us: u64) -> Result<()> {
        if slot >= MAX_ENTRIES || !self.entries[slot].active {
            return Err(Error::NotFound);
        }
        self.entries[slot].burst_enabled = burst_us > 0;
        self.entries[slot].burst_us = burst_us;
        Ok(())
    }

    // ── Query ────────────────────────────────────────────────

    /// Return an entry.
    pub fn entry(&self, slot: usize) -> Result<&BandwidthEntry> {
        if slot >= MAX_ENTRIES || !self.entries[slot].active {
            return Err(Error::NotFound);
        }
        Ok(&self.entries[slot])
    }

    /// Find an entry by group ID.
    pub fn find_by_group(&self, group_id: u64) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.active && e.group_id == group_id)
    }

    /// Return statistics.
    pub fn stats(&self) -> CfsBandwidthStats {
        self.stats
    }

    /// Return the number of active entries.
    pub fn active_count(&self) -> usize {
        self.entries.iter().filter(|e| e.active).count()
    }

    /// Return the number of currently throttled entries.
    pub fn throttled_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_throttled()).count()
    }
}
