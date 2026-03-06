// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Real-time scheduling group management.
//!
//! Manages RT bandwidth allocation across task groups (cgroups).
//! Each group has a runtime quota and period, preventing any single
//! RT group from monopolising CPU time.
//!
//! # Architecture
//!
//! ```text
//! RtGroupManager
//!  ├── groups[MAX_RT_GROUPS]
//!  │    ├── id, parent_id
//!  │    ├── runtime_us / period_us (bandwidth)
//!  │    ├── runtime_remaining
//!  │    └── nr_tasks, throttled
//!  └── stats: RtGroupStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/sched/rt.c` — RT group scheduling.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum RT groups.
const MAX_RT_GROUPS: usize = 64;

/// Default RT period in microseconds (1 second).
const DEFAULT_PERIOD_US: u64 = 1_000_000;

/// Default RT runtime in microseconds (950ms = 95%).
const DEFAULT_RUNTIME_US: u64 = 950_000;

/// Unlimited runtime marker.
const RT_RUNTIME_UNLIMITED: u64 = u64::MAX;

// ══════════════════════════════════════════════════════════════
// RtGroupEntry
// ══════════════════════════════════════════════════════════════

/// A single RT scheduling group.
#[derive(Debug, Clone, Copy)]
pub struct RtGroupEntry {
    /// Group identifier.
    pub id: u32,
    /// Parent group ID (0 = root).
    pub parent_id: u32,
    /// Bandwidth period in microseconds.
    pub period_us: u64,
    /// Bandwidth runtime quota in microseconds.
    pub runtime_us: u64,
    /// Runtime remaining in the current period.
    pub runtime_remaining: u64,
    /// Number of RT tasks in this group.
    pub nr_tasks: u32,
    /// Number of runnable RT tasks.
    pub nr_runnable: u32,
    /// Whether the group is currently throttled.
    pub throttled: bool,
    /// Total throttle events.
    pub throttle_count: u64,
    /// Total runtime consumed in microseconds.
    pub total_runtime: u64,
    /// Whether this entry is active.
    pub active: bool,
}

impl RtGroupEntry {
    /// Create an inactive entry.
    const fn empty() -> Self {
        Self {
            id: 0,
            parent_id: 0,
            period_us: DEFAULT_PERIOD_US,
            runtime_us: DEFAULT_RUNTIME_US,
            runtime_remaining: DEFAULT_RUNTIME_US,
            nr_tasks: 0,
            nr_runnable: 0,
            throttled: false,
            throttle_count: 0,
            total_runtime: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// RtGroupStats
// ══════════════════════════════════════════════════════════════

/// RT group scheduling statistics.
#[derive(Debug, Clone, Copy)]
pub struct RtGroupStats {
    /// Total groups created.
    pub groups_created: u64,
    /// Total throttle events.
    pub total_throttles: u64,
    /// Total unthrottle events.
    pub total_unthrottles: u64,
    /// Total runtime consumed.
    pub total_runtime: u64,
}

impl RtGroupStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            groups_created: 0,
            total_throttles: 0,
            total_unthrottles: 0,
            total_runtime: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// RtGroupManager
// ══════════════════════════════════════════════════════════════

/// Manages RT scheduling groups and bandwidth enforcement.
pub struct RtGroupManager {
    /// Group table.
    groups: [RtGroupEntry; MAX_RT_GROUPS],
    /// Next group ID.
    next_id: u32,
    /// Statistics.
    stats: RtGroupStats,
}

impl RtGroupManager {
    /// Create a new RT group manager.
    pub const fn new() -> Self {
        Self {
            groups: [const { RtGroupEntry::empty() }; MAX_RT_GROUPS],
            next_id: 1,
            stats: RtGroupStats::new(),
        }
    }

    /// Create a new RT group.
    pub fn create_group(&mut self, parent_id: u32) -> Result<u32> {
        let slot = self
            .groups
            .iter()
            .position(|g| !g.active)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id += 1;
        self.groups[slot] = RtGroupEntry {
            id,
            parent_id,
            active: true,
            ..RtGroupEntry::empty()
        };
        self.stats.groups_created += 1;
        Ok(id)
    }

    /// Set the bandwidth parameters for a group.
    pub fn set_bandwidth(&mut self, group_id: u32, runtime_us: u64, period_us: u64) -> Result<()> {
        if period_us == 0 {
            return Err(Error::InvalidArgument);
        }
        if runtime_us != RT_RUNTIME_UNLIMITED && runtime_us > period_us {
            return Err(Error::InvalidArgument);
        }
        let slot = self.find_group(group_id)?;
        self.groups[slot].runtime_us = runtime_us;
        self.groups[slot].period_us = period_us;
        self.groups[slot].runtime_remaining = runtime_us;
        Ok(())
    }

    /// Charge runtime to a group.
    ///
    /// # Errors
    ///
    /// - `WouldBlock` if the group becomes throttled.
    pub fn charge_runtime(&mut self, group_id: u32, delta_us: u64) -> Result<()> {
        let slot = self.find_group(group_id)?;
        if self.groups[slot].throttled {
            return Err(Error::WouldBlock);
        }
        if self.groups[slot].runtime_us == RT_RUNTIME_UNLIMITED {
            self.groups[slot].total_runtime += delta_us;
            self.stats.total_runtime += delta_us;
            return Ok(());
        }
        if delta_us > self.groups[slot].runtime_remaining {
            self.groups[slot].runtime_remaining = 0;
            self.groups[slot].throttled = true;
            self.groups[slot].throttle_count += 1;
            self.stats.total_throttles += 1;
            return Err(Error::WouldBlock);
        }
        self.groups[slot].runtime_remaining -= delta_us;
        self.groups[slot].total_runtime += delta_us;
        self.stats.total_runtime += delta_us;
        Ok(())
    }

    /// Replenish runtime at the start of a new period.
    pub fn replenish(&mut self, group_id: u32) -> Result<()> {
        let slot = self.find_group(group_id)?;
        self.groups[slot].runtime_remaining = self.groups[slot].runtime_us;
        if self.groups[slot].throttled {
            self.groups[slot].throttled = false;
            self.stats.total_unthrottles += 1;
        }
        Ok(())
    }

    /// Add a task to a group.
    pub fn add_task(&mut self, group_id: u32) -> Result<()> {
        let slot = self.find_group(group_id)?;
        self.groups[slot].nr_tasks += 1;
        self.groups[slot].nr_runnable += 1;
        Ok(())
    }

    /// Remove a task from a group.
    pub fn remove_task(&mut self, group_id: u32) -> Result<()> {
        let slot = self.find_group(group_id)?;
        self.groups[slot].nr_tasks = self.groups[slot].nr_tasks.saturating_sub(1);
        self.groups[slot].nr_runnable = self.groups[slot].nr_runnable.saturating_sub(1);
        Ok(())
    }

    /// Return group info.
    pub fn get_group(&self, group_id: u32) -> Result<&RtGroupEntry> {
        let slot = self.find_group(group_id)?;
        Ok(&self.groups[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> RtGroupStats {
        self.stats
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_group(&self, id: u32) -> Result<usize> {
        self.groups
            .iter()
            .position(|g| g.active && g.id == id)
            .ok_or(Error::NotFound)
    }
}
