// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 memory controller.
//!
//! Tracks and limits the memory consumption of a group of tasks.
//! Provides hard limits, soft limits (high watermark), swap accounting,
//! and OOM handling per cgroup.
//!
//! # Architecture
//!
//! ```text
//! MemCgroupV2
//!  ├── groups[MAX_GROUPS]
//!  │    ├── id, parent_id
//!  │    ├── usage / limit / high / swap_usage / swap_limit
//!  │    ├── oom_kills, oom_group
//!  │    └── events: MemCgroupEvents
//!  └── stats: MemCgroupGlobalStats
//! ```
//!
//! # Reference
//!
//! Linux `mm/memcontrol.c`, cgroup v2 `memory` controller.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum number of memory cgroups.
const MAX_GROUPS: usize = 256;

/// Unlimited memory marker.
const MEM_UNLIMITED: u64 = u64::MAX;

// ══════════════════════════════════════════════════════════════
// MemCgroupEvents
// ══════════════════════════════════════════════════════════════

/// Counters for memory cgroup events.
#[derive(Debug, Clone, Copy)]
pub struct MemCgroupEvents {
    /// Times the memory limit was hit.
    pub max_hit: u64,
    /// Times the high watermark was exceeded.
    pub high_hit: u64,
    /// OOM killer invocations.
    pub oom: u64,
    /// OOM kills within this cgroup.
    pub oom_kill: u64,
    /// Times swap limit was hit.
    pub swap_max_hit: u64,
}

impl MemCgroupEvents {
    /// Create zeroed events.
    const fn new() -> Self {
        Self {
            max_hit: 0,
            high_hit: 0,
            oom: 0,
            oom_kill: 0,
            swap_max_hit: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// MemCgroupEntry
// ══════════════════════════════════════════════════════════════

/// A single memory cgroup entry.
#[derive(Debug, Clone, Copy)]
pub struct MemCgroupEntry {
    /// Cgroup identifier.
    pub id: u32,
    /// Parent cgroup identifier (0 = root).
    pub parent_id: u32,
    /// Current memory usage in bytes.
    pub usage: u64,
    /// Hard memory limit (memory.max).
    pub limit: u64,
    /// High watermark (memory.high) — triggers reclaim.
    pub high: u64,
    /// Minimum guaranteed memory (memory.min).
    pub min_bytes: u64,
    /// Low protection boundary (memory.low).
    pub low: u64,
    /// Current swap usage in bytes.
    pub swap_usage: u64,
    /// Swap limit (memory.swap.max).
    pub swap_limit: u64,
    /// Number of OOM kills in this cgroup.
    pub oom_kills: u64,
    /// Whether to kill all tasks on OOM (memory.oom.group).
    pub oom_group: bool,
    /// Event counters.
    pub events: MemCgroupEvents,
    /// Whether this entry is active.
    pub active: bool,
}

impl MemCgroupEntry {
    /// Create an inactive entry.
    const fn empty() -> Self {
        Self {
            id: 0,
            parent_id: 0,
            usage: 0,
            limit: MEM_UNLIMITED,
            high: MEM_UNLIMITED,
            min_bytes: 0,
            low: 0,
            swap_usage: 0,
            swap_limit: MEM_UNLIMITED,
            oom_kills: 0,
            oom_group: false,
            events: MemCgroupEvents::new(),
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// MemCgroupV2
// ══════════════════════════════════════════════════════════════

/// Cgroup v2 memory controller subsystem.
pub struct MemCgroupV2 {
    /// Cgroup entries.
    groups: [MemCgroupEntry; MAX_GROUPS],
    /// Next cgroup ID to allocate.
    next_id: u32,
    /// Total memory charged across all cgroups.
    pub total_usage: u64,
    /// Total swap charged across all cgroups.
    pub total_swap: u64,
}

impl MemCgroupV2 {
    /// Create a new memory cgroup controller.
    pub const fn new() -> Self {
        Self {
            groups: [const { MemCgroupEntry::empty() }; MAX_GROUPS],
            next_id: 1,
            total_usage: 0,
            total_swap: 0,
        }
    }

    /// Create a new memory cgroup under the given parent.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if no free slots remain.
    pub fn create_group(&mut self, parent_id: u32) -> Result<u32> {
        let slot = self
            .groups
            .iter()
            .position(|g| !g.active)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id += 1;
        self.groups[slot] = MemCgroupEntry {
            id,
            parent_id,
            active: true,
            ..MemCgroupEntry::empty()
        };
        Ok(id)
    }

    /// Remove a memory cgroup.
    pub fn remove_group(&mut self, id: u32) -> Result<()> {
        let slot = self.find_group(id)?;
        self.total_usage = self.total_usage.saturating_sub(self.groups[slot].usage);
        self.total_swap = self.total_swap.saturating_sub(self.groups[slot].swap_usage);
        self.groups[slot] = MemCgroupEntry::empty();
        Ok(())
    }

    /// Set the hard memory limit (memory.max) for a cgroup.
    pub fn set_limit(&mut self, id: u32, limit: u64) -> Result<()> {
        let slot = self.find_group(id)?;
        self.groups[slot].limit = limit;
        Ok(())
    }

    /// Set the high watermark (memory.high) for a cgroup.
    pub fn set_high(&mut self, id: u32, high: u64) -> Result<()> {
        let slot = self.find_group(id)?;
        self.groups[slot].high = high;
        Ok(())
    }

    /// Set the swap limit for a cgroup.
    pub fn set_swap_limit(&mut self, id: u32, limit: u64) -> Result<()> {
        let slot = self.find_group(id)?;
        self.groups[slot].swap_limit = limit;
        Ok(())
    }

    /// Charge memory to a cgroup.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if charging would exceed the hard limit.
    pub fn charge(&mut self, id: u32, bytes: u64) -> Result<()> {
        let slot = self.find_group(id)?;
        let new_usage = self.groups[slot].usage.saturating_add(bytes);
        if new_usage > self.groups[slot].limit {
            self.groups[slot].events.max_hit += 1;
            return Err(Error::OutOfMemory);
        }
        if new_usage > self.groups[slot].high {
            self.groups[slot].events.high_hit += 1;
        }
        self.groups[slot].usage = new_usage;
        self.total_usage = self.total_usage.saturating_add(bytes);
        Ok(())
    }

    /// Uncharge memory from a cgroup.
    pub fn uncharge(&mut self, id: u32, bytes: u64) -> Result<()> {
        let slot = self.find_group(id)?;
        self.groups[slot].usage = self.groups[slot].usage.saturating_sub(bytes);
        self.total_usage = self.total_usage.saturating_sub(bytes);
        Ok(())
    }

    /// Record an OOM kill in a cgroup.
    pub fn record_oom_kill(&mut self, id: u32) -> Result<()> {
        let slot = self.find_group(id)?;
        self.groups[slot].oom_kills += 1;
        self.groups[slot].events.oom += 1;
        self.groups[slot].events.oom_kill += 1;
        Ok(())
    }

    /// Return cgroup entry by ID.
    pub fn get_group(&self, id: u32) -> Result<&MemCgroupEntry> {
        let slot = self.find_group(id)?;
        Ok(&self.groups[slot])
    }

    /// Return the number of active cgroups.
    pub fn active_count(&self) -> usize {
        self.groups.iter().filter(|g| g.active).count()
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_group(&self, id: u32) -> Result<usize> {
        self.groups
            .iter()
            .position(|g| g.active && g.id == id)
            .ok_or(Error::NotFound)
    }
}
