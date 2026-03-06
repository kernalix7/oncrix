// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory cgroup v2 (unified hierarchy) implementation.
//!
//! Provides per-cgroup memory accounting and limits following the
//! cgroup v2 memory controller interface. Each cgroup tracks page
//! charges and enforces hierarchical limits.
//!
//! # Interface Files
//!
//! - `memory.current` — current memory usage
//! - `memory.min` — guaranteed minimum (hard protection)
//! - `memory.low` — best-effort low boundary (soft protection)
//! - `memory.high` — throttle boundary (reclaim pressure)
//! - `memory.max` — hard limit (OOM if exceeded)
//! - `memory.swap.current` — current swap usage
//! - `memory.swap.max` — swap hard limit
//! - `memory.events` — OOM/reclaim event counters
//!
//! # Subsystems
//!
//! - [`MemCgLimits`] — min/low/high/max limit tuple
//! - [`MemCgSwapLimits`] — swap current/max
//! - [`MemCgEvents`] — event counters (low, high, max, oom)
//! - [`MemCgroupV2`] — per-cgroup memory controller
//! - [`MemCgHierarchy`] — hierarchical cgroup tree
//! - [`MemCgStats`] — aggregate statistics
//!
//! Reference: Linux `mm/memcontrol.c`, `mm/page_counter.c`,
//! cgroup v2 documentation.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum cgroups in the hierarchy.
const MAX_CGROUPS: usize = 128;

/// Maximum children per cgroup.
const MAX_CHILDREN: usize = 16;

/// Unlimited limit sentinel.
const LIMIT_MAX: u64 = u64::MAX;

/// Root cgroup ID.
const ROOT_CGROUP_ID: u32 = 0;

/// Maximum hierarchy depth.
const MAX_DEPTH: usize = 8;

// -------------------------------------------------------------------
// MemCgLimits
// -------------------------------------------------------------------

/// Memory limits for a cgroup v2 memory controller.
///
/// Hierarchy: `min` <= `low` <= `high` <= `max`.
#[derive(Debug, Clone, Copy)]
pub struct MemCgLimits {
    /// Hard minimum guarantee (pages). Reclaim will not go below
    /// this unless there is no other memory to reclaim.
    pub min: u64,
    /// Soft minimum (pages). Best-effort protection — reclaim
    /// will try to keep usage above this.
    pub low: u64,
    /// High watermark (pages). Usage above this triggers
    /// throttling and aggressive reclaim.
    pub high: u64,
    /// Hard maximum (pages). OOM killer invoked if exceeded.
    pub max: u64,
}

impl MemCgLimits {
    /// Creates new limits with everything unlimited.
    pub const fn unlimited() -> Self {
        Self {
            min: 0,
            low: 0,
            high: LIMIT_MAX,
            max: LIMIT_MAX,
        }
    }

    /// Creates limits with explicit values in pages.
    pub const fn new(min: u64, low: u64, high: u64, max: u64) -> Self {
        Self {
            min,
            low,
            high,
            max,
        }
    }

    /// Validates that limits are ordered correctly.
    pub const fn is_valid(&self) -> bool {
        self.min <= self.low && self.low <= self.high && self.high <= self.max
    }
}

impl Default for MemCgLimits {
    fn default() -> Self {
        Self::unlimited()
    }
}

// -------------------------------------------------------------------
// MemCgSwapLimits
// -------------------------------------------------------------------

/// Swap limits for a cgroup.
#[derive(Debug, Clone, Copy)]
pub struct MemCgSwapLimits {
    /// Current swap usage in pages.
    pub current: u64,
    /// Maximum swap in pages (LIMIT_MAX = unlimited).
    pub max: u64,
}

impl MemCgSwapLimits {
    /// Creates new swap limits.
    pub const fn new() -> Self {
        Self {
            current: 0,
            max: LIMIT_MAX,
        }
    }
}

impl Default for MemCgSwapLimits {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MemCgEvents
// -------------------------------------------------------------------

/// Event counters for a memory cgroup.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemCgEvents {
    /// Number of times usage exceeded the `low` boundary.
    pub low: u64,
    /// Number of times usage exceeded the `high` boundary.
    pub high: u64,
    /// Number of times usage hit the `max` limit.
    pub max: u64,
    /// Number of OOM events.
    pub oom: u64,
    /// Number of OOM kills.
    pub oom_kill: u64,
    /// Number of OOM kills within the group.
    pub oom_group_kill: u64,
}

impl MemCgEvents {
    /// Creates new zeroed event counters.
    pub const fn new() -> Self {
        Self {
            low: 0,
            high: 0,
            max: 0,
            oom: 0,
            oom_kill: 0,
            oom_group_kill: 0,
        }
    }
}

// -------------------------------------------------------------------
// MemCgroupV2
// -------------------------------------------------------------------

/// Per-cgroup v2 memory controller.
///
/// Tracks memory usage, enforces limits, and records events.
#[derive(Debug)]
pub struct MemCgroupV2 {
    /// Cgroup identifier.
    id: u32,
    /// Parent cgroup ID (ROOT_CGROUP_ID for root).
    parent_id: u32,
    /// Current memory usage in pages.
    usage: u64,
    /// Memory limits.
    limits: MemCgLimits,
    /// Swap tracking.
    swap: MemCgSwapLimits,
    /// Event counters.
    events: MemCgEvents,
    /// Children cgroup IDs.
    children: [u32; MAX_CHILDREN],
    /// Number of children.
    nr_children: usize,
    /// Whether this cgroup is active.
    active: bool,
    /// Total pages charged (including children, for hierarchical
    /// accounting).
    hierarchical_usage: u64,
    /// Depth in the hierarchy (root = 0).
    depth: u8,
}

impl MemCgroupV2 {
    /// Creates a new cgroup memory controller.
    pub const fn new(id: u32, parent_id: u32) -> Self {
        Self {
            id,
            parent_id,
            usage: 0,
            limits: MemCgLimits::unlimited(),
            swap: MemCgSwapLimits::new(),
            events: MemCgEvents::new(),
            children: [0; MAX_CHILDREN],
            nr_children: 0,
            active: false,
            hierarchical_usage: 0,
            depth: 0,
        }
    }

    /// Returns the cgroup ID.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Returns the parent cgroup ID.
    pub const fn parent_id(&self) -> u32 {
        self.parent_id
    }

    /// Returns the current memory usage in pages.
    pub const fn usage(&self) -> u64 {
        self.usage
    }

    /// Returns the current memory usage in bytes.
    pub const fn usage_bytes(&self) -> u64 {
        self.usage * PAGE_SIZE
    }

    /// Returns a reference to the limits.
    pub const fn limits(&self) -> &MemCgLimits {
        &self.limits
    }

    /// Returns a reference to the swap limits.
    pub const fn swap(&self) -> &MemCgSwapLimits {
        &self.swap
    }

    /// Returns a reference to the event counters.
    pub const fn events(&self) -> &MemCgEvents {
        &self.events
    }

    /// Sets the memory limits.
    pub fn set_limits(&mut self, limits: MemCgLimits) -> Result<()> {
        if !limits.is_valid() {
            return Err(Error::InvalidArgument);
        }
        self.limits = limits;
        Ok(())
    }

    /// Sets the swap max limit.
    pub fn set_swap_max(&mut self, max_pages: u64) {
        self.swap.max = max_pages;
    }

    /// Charges a page to this cgroup.
    ///
    /// Checks against the max limit and records events.
    /// Returns `NoMemory` if the charge would exceed max.
    pub fn charge_page(&mut self, nr_pages: u64) -> Result<()> {
        let new_usage = self.usage + nr_pages;

        // Check hard max
        if self.limits.max != LIMIT_MAX && new_usage > self.limits.max {
            self.events.max += 1;
            self.events.oom += 1;
            return Err(Error::OutOfMemory);
        }

        self.usage = new_usage;
        self.hierarchical_usage += nr_pages;

        // Record high event
        if self.limits.high != LIMIT_MAX && new_usage > self.limits.high {
            self.events.high += 1;
        }

        // Record low event
        if new_usage > self.limits.low && self.limits.low > 0 {
            self.events.low += 1;
        }

        Ok(())
    }

    /// Uncharges pages from this cgroup.
    pub fn uncharge_page(&mut self, nr_pages: u64) {
        self.usage = self.usage.saturating_sub(nr_pages);
        self.hierarchical_usage = self.hierarchical_usage.saturating_sub(nr_pages);
    }

    /// Charges swap usage.
    pub fn charge_swap(&mut self, nr_pages: u64) -> Result<()> {
        let new_swap = self.swap.current + nr_pages;
        if self.swap.max != LIMIT_MAX && new_swap > self.swap.max {
            return Err(Error::OutOfMemory);
        }
        self.swap.current = new_swap;
        Ok(())
    }

    /// Uncharges swap usage.
    pub fn uncharge_swap(&mut self, nr_pages: u64) {
        self.swap.current = self.swap.current.saturating_sub(nr_pages);
    }

    /// Returns whether usage exceeds the high watermark.
    pub const fn is_above_high(&self) -> bool {
        self.limits.high != LIMIT_MAX && self.usage > self.limits.high
    }

    /// Returns whether usage is below the low protection boundary.
    pub const fn is_below_low(&self) -> bool {
        self.limits.low > 0 && self.usage <= self.limits.low
    }

    /// Returns the number of reclaimable pages (above min).
    pub const fn reclaimable_pages(&self) -> u64 {
        if self.usage > self.limits.min {
            self.usage - self.limits.min
        } else {
            0
        }
    }

    /// Adds a child cgroup.
    pub fn add_child(&mut self, child_id: u32) -> Result<()> {
        if self.nr_children >= MAX_CHILDREN {
            return Err(Error::OutOfMemory);
        }
        self.children[self.nr_children] = child_id;
        self.nr_children += 1;
        Ok(())
    }

    /// Removes a child cgroup by ID.
    pub fn remove_child(&mut self, child_id: u32) -> Result<()> {
        for i in 0..self.nr_children {
            if self.children[i] == child_id {
                if i < self.nr_children - 1 {
                    self.children[i] = self.children[self.nr_children - 1];
                }
                self.nr_children -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Records an OOM kill event.
    pub fn record_oom_kill(&mut self) {
        self.events.oom_kill += 1;
    }
}

impl Default for MemCgroupV2 {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// -------------------------------------------------------------------
// MemCgStats
// -------------------------------------------------------------------

/// Aggregate statistics for the memcg hierarchy.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemCgStats {
    /// Total pages charged across all cgroups.
    pub total_charged: u64,
    /// Total pages uncharged.
    pub total_uncharged: u64,
    /// Total OOM events.
    pub total_oom_events: u64,
    /// Total OOM kills.
    pub total_oom_kills: u64,
    /// Number of active cgroups.
    pub active_cgroups: u32,
}

impl MemCgStats {
    /// Creates new zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_charged: 0,
            total_uncharged: 0,
            total_oom_events: 0,
            total_oom_kills: 0,
            active_cgroups: 0,
        }
    }
}

// -------------------------------------------------------------------
// MemCgHierarchy
// -------------------------------------------------------------------

/// Hierarchical cgroup v2 memory controller manager.
///
/// Manages a tree of cgroups with parent-child relationships
/// and hierarchical accounting.
pub struct MemCgHierarchy {
    /// Cgroup pool.
    cgroups: [MemCgroupV2; MAX_CGROUPS],
    /// Number of active cgroups.
    active_count: usize,
    /// Next cgroup ID to assign.
    next_id: u32,
    /// Statistics.
    stats: MemCgStats,
}

impl MemCgHierarchy {
    /// Creates a new hierarchy with a root cgroup.
    pub const fn new() -> Self {
        Self {
            cgroups: [const { MemCgroupV2::new(0, 0) }; MAX_CGROUPS],
            active_count: 0,
            next_id: 1,
            stats: MemCgStats::new(),
        }
    }

    /// Initializes the hierarchy, creating the root cgroup.
    pub fn init(&mut self) -> Result<()> {
        self.cgroups[0] = MemCgroupV2::new(ROOT_CGROUP_ID, ROOT_CGROUP_ID);
        self.cgroups[0].active = true;
        self.cgroups[0].depth = 0;
        self.active_count = 1;
        self.stats.active_cgroups = 1;
        Ok(())
    }

    /// Creates a new child cgroup under the given parent.
    /// Returns the new cgroup ID.
    pub fn create_cgroup(&mut self, parent_id: u32) -> Result<u32> {
        if self.active_count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        let parent_slot = self.find_cgroup(parent_id)?;
        let parent_depth = self.cgroups[parent_slot].depth;
        if parent_depth as usize >= MAX_DEPTH {
            return Err(Error::InvalidArgument);
        }

        let new_id = self.next_id;
        self.next_id += 1;

        let slot = self.find_free_slot()?;
        self.cgroups[slot] = MemCgroupV2::new(new_id, parent_id);
        self.cgroups[slot].active = true;
        self.cgroups[slot].depth = parent_depth + 1;

        // Register as child of parent
        self.cgroups[parent_slot].add_child(new_id)?;

        self.active_count += 1;
        self.stats.active_cgroups += 1;

        Ok(new_id)
    }

    /// Destroys a cgroup. It must have no children and zero usage.
    pub fn destroy_cgroup(&mut self, id: u32) -> Result<()> {
        if id == ROOT_CGROUP_ID {
            return Err(Error::InvalidArgument);
        }
        let slot = self.find_cgroup(id)?;
        if self.cgroups[slot].nr_children > 0 {
            return Err(Error::Busy);
        }
        if self.cgroups[slot].usage > 0 {
            return Err(Error::Busy);
        }

        let parent_id = self.cgroups[slot].parent_id;
        let parent_slot = self.find_cgroup(parent_id)?;
        self.cgroups[parent_slot].remove_child(id)?;

        self.cgroups[slot].active = false;
        self.active_count -= 1;
        self.stats.active_cgroups -= 1;
        Ok(())
    }

    /// Charges pages to a cgroup (with hierarchical propagation).
    pub fn charge(&mut self, cgroup_id: u32, nr_pages: u64) -> Result<()> {
        let slot = self.find_cgroup(cgroup_id)?;

        // Check limits up the hierarchy
        let mut check_id = cgroup_id;
        loop {
            let check_slot = self.find_cgroup(check_id)?;
            let new_usage = self.cgroups[check_slot].usage + nr_pages;
            if self.cgroups[check_slot].limits.max != LIMIT_MAX
                && new_usage > self.cgroups[check_slot].limits.max
            {
                return Err(Error::OutOfMemory);
            }
            if check_id == ROOT_CGROUP_ID {
                break;
            }
            check_id = self.cgroups[check_slot].parent_id;
        }

        // Charge at the target cgroup
        self.cgroups[slot].charge_page(nr_pages)?;

        // Propagate up
        let mut prop_id = self.cgroups[slot].parent_id;
        while prop_id != cgroup_id {
            if let Ok(prop_slot) = self.find_cgroup(prop_id) {
                self.cgroups[prop_slot].hierarchical_usage += nr_pages;
                if prop_id == ROOT_CGROUP_ID {
                    break;
                }
                prop_id = self.cgroups[prop_slot].parent_id;
            } else {
                break;
            }
        }

        self.stats.total_charged += nr_pages;
        Ok(())
    }

    /// Uncharges pages from a cgroup (with hierarchical propagation).
    pub fn uncharge(&mut self, cgroup_id: u32, nr_pages: u64) -> Result<()> {
        let slot = self.find_cgroup(cgroup_id)?;
        self.cgroups[slot].uncharge_page(nr_pages);

        // Propagate up
        let mut prop_id = self.cgroups[slot].parent_id;
        loop {
            if let Ok(prop_slot) = self.find_cgroup(prop_id) {
                self.cgroups[prop_slot].hierarchical_usage = self.cgroups[prop_slot]
                    .hierarchical_usage
                    .saturating_sub(nr_pages);
                if prop_id == ROOT_CGROUP_ID {
                    break;
                }
                prop_id = self.cgroups[prop_slot].parent_id;
            } else {
                break;
            }
        }

        self.stats.total_uncharged += nr_pages;
        Ok(())
    }

    /// Sets limits for a cgroup.
    pub fn set_limits(&mut self, cgroup_id: u32, limits: MemCgLimits) -> Result<()> {
        let slot = self.find_cgroup(cgroup_id)?;
        self.cgroups[slot].set_limits(limits)
    }

    /// Returns a reference to a cgroup by ID.
    pub fn get_cgroup(&self, cgroup_id: u32) -> Result<&MemCgroupV2> {
        let slot = self.find_cgroup(cgroup_id)?;
        Ok(&self.cgroups[slot])
    }

    /// Returns a reference to the aggregate statistics.
    pub const fn stats(&self) -> &MemCgStats {
        &self.stats
    }

    /// Returns the number of active cgroups.
    pub const fn active_count(&self) -> usize {
        self.active_count
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Finds a cgroup slot by ID.
    fn find_cgroup(&self, id: u32) -> Result<usize> {
        for i in 0..MAX_CGROUPS {
            if self.cgroups[i].active && self.cgroups[i].id == id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Finds a free slot in the cgroup pool.
    fn find_free_slot(&self) -> Result<usize> {
        for i in 0..MAX_CGROUPS {
            if !self.cgroups[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }
}

impl Default for MemCgHierarchy {
    fn default() -> Self {
        Self::new()
    }
}
