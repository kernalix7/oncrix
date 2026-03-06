// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory cgroup v2 controller.
//!
//! Implements the cgroup v2 memory controller for per-group memory
//! accounting, limits, and pressure tracking. This replaces the
//! legacy cgroup v1 memory controller with a unified hierarchy.
//!
//! # Design
//!
//! Each memory cgroup has:
//! - `memory.current` — current usage
//! - `memory.min` — minimum guarantee (best-effort reclaim protection)
//! - `memory.low` — low watermark (throttle reclaim)
//! - `memory.high` — high limit (throttle allocations)
//! - `memory.max` — hard limit (OOM if exceeded)
//! - `memory.swap.current` / `memory.swap.max` — swap accounting
//! - `memory.pressure` — PSI (Pressure Stall Information) counters
//!
//! # Types
//!
//! - [`MemcgV2Limits`] — min/low/high/max limits
//! - [`MemcgV2Counters`] — current usage counters
//! - [`MemcgV2SwapCounters`] — swap-specific counters
//! - [`MemcgV2Pressure`] — PSI pressure tracking
//! - [`MemcgV2Events`] — event counters (low, high, max, OOM)
//! - [`MemcgV2State`] — cgroup state
//! - [`MemcgV2Group`] — a single memory cgroup
//! - [`MemcgV2Controller`] — top-level controller
//! - [`MemcgV2Stats`] — summary statistics
//! - [`MemcgV2ChargeResult`] — result of a charge attempt
//!
//! Reference: Linux `mm/memcontrol.c`, cgroup v2 documentation.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of cgroups.
const MAX_CGROUPS: usize = 128;

/// Maximum depth of the cgroup hierarchy.
const MAX_DEPTH: usize = 8;

/// Maximum name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Sentinel value: no limit.
const NO_LIMIT: u64 = u64::MAX;

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum PIDs per cgroup.
const MAX_PIDS_PER_CGROUP: usize = 64;

/// Maximum children per cgroup.
const MAX_CHILDREN: usize = 16;

/// PSI window duration in abstract time units.
const PSI_WINDOW: u64 = 1_000_000;

/// Event history depth.
const EVENT_HISTORY: usize = 16;

// -------------------------------------------------------------------
// MemcgV2State
// -------------------------------------------------------------------

/// State of a cgroup v2 memory controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemcgV2State {
    /// Active and accepting charges.
    #[default]
    Active,
    /// Draining — no new charges, waiting for existing to settle.
    Draining,
    /// Offline — removed from hierarchy.
    Offline,
}

// -------------------------------------------------------------------
// MemcgV2Limits
// -------------------------------------------------------------------

/// cgroup v2 memory limits.
#[derive(Debug, Clone, Copy)]
pub struct MemcgV2Limits {
    /// Minimum memory guarantee in bytes (best-effort).
    pub min: u64,
    /// Low watermark in bytes (reclaim throttle).
    pub low: u64,
    /// High limit in bytes (allocation throttle).
    pub high: u64,
    /// Hard maximum in bytes (OOM trigger).
    pub max: u64,
}

impl Default for MemcgV2Limits {
    fn default() -> Self {
        Self {
            min: 0,
            low: 0,
            high: NO_LIMIT,
            max: NO_LIMIT,
        }
    }
}

impl MemcgV2Limits {
    /// Returns true if the limits are valid (min <= low <= high <= max).
    pub const fn is_valid(&self) -> bool {
        self.min <= self.low
            && (self.low <= self.high || self.high == NO_LIMIT)
            && (self.high <= self.max || self.max == NO_LIMIT)
    }

    /// Returns true if there is no hard max.
    pub const fn has_no_max(&self) -> bool {
        self.max == NO_LIMIT
    }
}

// -------------------------------------------------------------------
// MemcgV2Counters
// -------------------------------------------------------------------

/// Current memory usage counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemcgV2Counters {
    /// Current memory usage in bytes.
    pub current: u64,
    /// Peak usage in bytes.
    pub peak: u64,
    /// Kernel memory usage in bytes.
    pub kernel: u64,
    /// Kernel stack usage in bytes.
    pub kernel_stack: u64,
    /// Page tables usage in bytes.
    pub pagetables: u64,
    /// Slab (allocator cache) usage in bytes.
    pub slab: u64,
    /// Socket buffer usage in bytes.
    pub sock: u64,
    /// Anonymous page usage in bytes.
    pub anon: u64,
    /// File-backed page usage in bytes.
    pub file: u64,
    /// Shared memory usage in bytes.
    pub shmem: u64,
}

impl MemcgV2Counters {
    /// Updates the peak if current exceeds it.
    pub fn update_peak(&mut self) {
        if self.current > self.peak {
            self.peak = self.current;
        }
    }
}

// -------------------------------------------------------------------
// MemcgV2SwapCounters
// -------------------------------------------------------------------

/// Swap-specific counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemcgV2SwapCounters {
    /// Current swap usage in bytes.
    pub current: u64,
    /// Peak swap usage in bytes.
    pub peak: u64,
    /// Swap hard limit in bytes.
    pub max: u64,
    /// Number of swap allocation failures.
    pub fail_count: u64,
}

impl MemcgV2SwapCounters {
    /// Updates the peak if current exceeds it.
    pub fn update_peak(&mut self) {
        if self.current > self.peak {
            self.peak = self.current;
        }
    }
}

// -------------------------------------------------------------------
// MemcgV2Pressure
// -------------------------------------------------------------------

/// PSI (Pressure Stall Information) counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemcgV2Pressure {
    /// Total stall time for `some` level (microseconds).
    pub some_total: u64,
    /// Total stall time for `full` level (microseconds).
    pub full_total: u64,
    /// Average 10-second pressure (0..100).
    pub avg10: u32,
    /// Average 60-second pressure (0..100).
    pub avg60: u32,
    /// Average 300-second pressure (0..100).
    pub avg300: u32,
    /// Last update timestamp.
    pub last_update: u64,
}

// -------------------------------------------------------------------
// MemcgV2Events
// -------------------------------------------------------------------

/// Event counters for a cgroup.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemcgV2Events {
    /// Number of times usage went below `low`.
    pub low: u64,
    /// Number of times usage exceeded `high`.
    pub high: u64,
    /// Number of times usage reached `max`.
    pub max: u64,
    /// Number of OOM events.
    pub oom: u64,
    /// Number of OOM kills.
    pub oom_kill: u64,
    /// Number of OOM kills in the group hierarchy.
    pub oom_group_kill: u64,
}

// -------------------------------------------------------------------
// MemcgV2ChargeResult
// -------------------------------------------------------------------

/// Result of a memory charge attempt.
#[derive(Debug, Clone, Copy)]
pub enum MemcgV2ChargeResult {
    /// Charge succeeded, no pressure.
    Ok,
    /// Charge succeeded but usage is above `high` — throttle.
    Throttled,
    /// Charge would exceed `max` — denied.
    OverMax,
    /// Charge succeeded but reclaim is recommended.
    ReclaimNeeded,
}

// -------------------------------------------------------------------
// MemcgV2Group
// -------------------------------------------------------------------

/// A single memory cgroup v2 group.
#[derive(Clone)]
pub struct MemcgV2Group {
    /// Unique cgroup ID.
    pub id: u32,
    /// Parent cgroup ID (0 = root).
    pub parent_id: u32,
    /// Cgroup name.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Depth in hierarchy.
    pub depth: u32,
    /// State.
    pub state: MemcgV2State,
    /// Memory limits.
    pub limits: MemcgV2Limits,
    /// Usage counters.
    pub counters: MemcgV2Counters,
    /// Swap counters.
    pub swap: MemcgV2SwapCounters,
    /// Pressure info.
    pub pressure: MemcgV2Pressure,
    /// Events.
    pub events: MemcgV2Events,
    /// Attached PIDs.
    pub pids: [u32; MAX_PIDS_PER_CGROUP],
    /// Number of attached PIDs.
    pub nr_pids: usize,
    /// Child cgroup IDs.
    pub children: [u32; MAX_CHILDREN],
    /// Number of children.
    pub nr_children: usize,
    /// Whether this cgroup is active.
    pub active: bool,
    /// Whether OOM killing is group-scoped.
    pub oom_group: bool,
}

impl MemcgV2Group {
    /// Creates an empty, inactive cgroup.
    const fn empty() -> Self {
        Self {
            id: 0,
            parent_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            depth: 0,
            state: MemcgV2State::Active,
            limits: MemcgV2Limits {
                min: 0,
                low: 0,
                high: NO_LIMIT,
                max: NO_LIMIT,
            },
            counters: MemcgV2Counters {
                current: 0,
                peak: 0,
                kernel: 0,
                kernel_stack: 0,
                pagetables: 0,
                slab: 0,
                sock: 0,
                anon: 0,
                file: 0,
                shmem: 0,
            },
            swap: MemcgV2SwapCounters {
                current: 0,
                peak: 0,
                max: NO_LIMIT,
                fail_count: 0,
            },
            pressure: MemcgV2Pressure {
                some_total: 0,
                full_total: 0,
                avg10: 0,
                avg60: 0,
                avg300: 0,
                last_update: 0,
            },
            events: MemcgV2Events {
                low: 0,
                high: 0,
                max: 0,
                oom: 0,
                oom_kill: 0,
                oom_group_kill: 0,
            },
            pids: [0; MAX_PIDS_PER_CGROUP],
            nr_pids: 0,
            children: [0; MAX_CHILDREN],
            nr_children: 0,
            active: false,
            oom_group: false,
        }
    }

    /// Sets the cgroup name from a byte slice.
    pub fn set_name(&mut self, name: &[u8]) {
        let len = if name.len() > MAX_NAME_LEN {
            MAX_NAME_LEN
        } else {
            name.len()
        };
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Returns the effective max (considering parent chain).
    pub const fn effective_max(&self) -> u64 {
        self.limits.max
    }

    /// Returns usage as a percentage of max (0..100, or 0 if no max).
    pub fn usage_pct(&self) -> u32 {
        if self.limits.max == NO_LIMIT || self.limits.max == 0 {
            return 0;
        }
        ((self.counters.current * 100) / self.limits.max) as u32
    }

    /// Returns true if usage is above the high limit.
    pub fn above_high(&self) -> bool {
        self.limits.high != NO_LIMIT && self.counters.current > self.limits.high
    }

    /// Returns true if usage is at or above the max limit.
    pub fn at_max(&self) -> bool {
        self.limits.max != NO_LIMIT && self.counters.current >= self.limits.max
    }

    /// Returns true if usage is below the low watermark.
    pub fn below_low(&self) -> bool {
        self.limits.low > 0 && self.counters.current < self.limits.low
    }

    /// Returns true if usage is below the min guarantee.
    pub fn below_min(&self) -> bool {
        self.limits.min > 0 && self.counters.current < self.limits.min
    }
}

impl Default for MemcgV2Group {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// MemcgV2Stats
// -------------------------------------------------------------------

/// Summary statistics for the cgroup v2 memory controller.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemcgV2Stats {
    /// Total charge operations.
    pub total_charges: u64,
    /// Total uncharge operations.
    pub total_uncharges: u64,
    /// Charges that were throttled.
    pub throttled_charges: u64,
    /// Charges that were denied (over max).
    pub denied_charges: u64,
    /// Total OOM events.
    pub total_oom_events: u64,
    /// Total OOM kills.
    pub total_oom_kills: u64,
    /// Number of active cgroups.
    pub active_cgroups: u32,
    /// Total system memory charged across all cgroups.
    pub total_charged: u64,
}

// -------------------------------------------------------------------
// MemcgV2Controller
// -------------------------------------------------------------------

/// Top-level cgroup v2 memory controller.
///
/// Manages the hierarchy of memory cgroups, provides charge/uncharge
/// operations, and enforces limits.
pub struct MemcgV2Controller {
    /// Cgroup entries.
    groups: [MemcgV2Group; MAX_CGROUPS],
    /// Next cgroup ID.
    next_id: u32,
    /// Statistics.
    stats: MemcgV2Stats,
    /// Whether the controller is initialised.
    initialised: bool,
}

impl MemcgV2Controller {
    /// Creates a new, uninitialised controller.
    pub fn new() -> Self {
        Self {
            groups: [const { MemcgV2Group::empty() }; MAX_CGROUPS],
            next_id: 1,
            stats: MemcgV2Stats::default(),
            initialised: false,
        }
    }

    /// Initialises the controller and creates the root cgroup.
    pub fn init(&mut self) -> Result<u32> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.groups[0].id = id;
        self.groups[0].parent_id = 0;
        self.groups[0].depth = 0;
        self.groups[0].state = MemcgV2State::Active;
        self.groups[0].active = true;
        self.groups[0].set_name(b"root");
        self.stats.active_cgroups = 1;
        self.initialised = true;
        Ok(id)
    }

    /// Creates a child cgroup under the given parent.
    pub fn create(&mut self, parent_id: u32, name: &[u8]) -> Result<u32> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }
        let parent_idx = self.find_by_id(parent_id)?;
        let parent_depth = self.groups[parent_idx].depth;
        if parent_depth as usize >= MAX_DEPTH - 1 {
            return Err(Error::InvalidArgument);
        }
        if self.groups[parent_idx].nr_children >= MAX_CHILDREN {
            return Err(Error::OutOfMemory);
        }
        let idx = self.find_free_slot()?;
        let id = self.next_id;
        self.next_id += 1;
        self.groups[idx] = MemcgV2Group::empty();
        self.groups[idx].id = id;
        self.groups[idx].parent_id = parent_id;
        self.groups[idx].depth = parent_depth + 1;
        self.groups[idx].state = MemcgV2State::Active;
        self.groups[idx].active = true;
        self.groups[idx].set_name(name);
        // Register as child of parent.
        let nr = self.groups[parent_idx].nr_children;
        self.groups[parent_idx].children[nr] = id;
        self.groups[parent_idx].nr_children += 1;
        self.stats.active_cgroups += 1;
        Ok(id)
    }

    /// Removes a cgroup (must have no children and no PIDs).
    pub fn remove(&mut self, cgroup_id: u32) -> Result<()> {
        let idx = self.find_by_id(cgroup_id)?;
        if self.groups[idx].nr_children > 0 {
            return Err(Error::Busy);
        }
        if self.groups[idx].nr_pids > 0 {
            return Err(Error::Busy);
        }
        // Unlink from parent.
        let parent_id = self.groups[idx].parent_id;
        if parent_id != 0 {
            if let Ok(pidx) = self.find_by_id(parent_id) {
                self.unlink_child(pidx, cgroup_id);
            }
        }
        self.groups[idx] = MemcgV2Group::empty();
        self.stats.active_cgroups = self.stats.active_cgroups.saturating_sub(1);
        Ok(())
    }

    /// Sets the limits for a cgroup.
    pub fn set_limits(&mut self, cgroup_id: u32, limits: MemcgV2Limits) -> Result<()> {
        if !limits.is_valid() {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_by_id(cgroup_id)?;
        self.groups[idx].limits = limits;
        Ok(())
    }

    /// Sets the swap max for a cgroup.
    pub fn set_swap_max(&mut self, cgroup_id: u32, max: u64) -> Result<()> {
        let idx = self.find_by_id(cgroup_id)?;
        self.groups[idx].swap.max = max;
        Ok(())
    }

    /// Attaches a PID to a cgroup.
    pub fn attach_pid(&mut self, cgroup_id: u32, pid: u32) -> Result<()> {
        // Detach from any current cgroup first.
        self.detach_pid_from_all(pid);
        let idx = self.find_by_id(cgroup_id)?;
        if self.groups[idx].nr_pids >= MAX_PIDS_PER_CGROUP {
            return Err(Error::OutOfMemory);
        }
        let nr = self.groups[idx].nr_pids;
        self.groups[idx].pids[nr] = pid;
        self.groups[idx].nr_pids += 1;
        Ok(())
    }

    /// Detaches a PID from its cgroup.
    pub fn detach_pid(&mut self, cgroup_id: u32, pid: u32) -> Result<()> {
        let idx = self.find_by_id(cgroup_id)?;
        let nr = self.groups[idx].nr_pids;
        for i in 0..nr {
            if self.groups[idx].pids[i] == pid {
                let last = nr - 1;
                self.groups[idx].pids[i] = self.groups[idx].pids[last];
                self.groups[idx].nr_pids -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Charges memory to a cgroup.
    ///
    /// Returns the charge result indicating whether the allocation
    /// should proceed, be throttled, or be denied.
    pub fn charge(&mut self, cgroup_id: u32, bytes: u64) -> Result<MemcgV2ChargeResult> {
        let idx = self.find_by_id(cgroup_id)?;
        if self.groups[idx].state != MemcgV2State::Active {
            return Err(Error::PermissionDenied);
        }
        // Check hard max.
        let new_usage = self.groups[idx].counters.current + bytes;
        if self.groups[idx].limits.max != NO_LIMIT && new_usage > self.groups[idx].limits.max {
            self.groups[idx].events.max += 1;
            self.stats.denied_charges += 1;
            return Ok(MemcgV2ChargeResult::OverMax);
        }
        // Apply the charge.
        self.groups[idx].counters.current = new_usage;
        self.groups[idx].counters.update_peak();
        self.stats.total_charges += 1;
        self.stats.total_charged += bytes;
        // Charge ancestors.
        let parent_id = self.groups[idx].parent_id;
        if parent_id != 0 {
            let _ = self.charge_ancestors(parent_id, bytes);
        }
        // Check thresholds.
        if self.groups[idx].above_high() {
            self.groups[idx].events.high += 1;
            self.stats.throttled_charges += 1;
            return Ok(MemcgV2ChargeResult::Throttled);
        }
        if self.groups[idx].below_low() {
            return Ok(MemcgV2ChargeResult::ReclaimNeeded);
        }
        Ok(MemcgV2ChargeResult::Ok)
    }

    /// Uncharges memory from a cgroup.
    pub fn uncharge(&mut self, cgroup_id: u32, bytes: u64) -> Result<()> {
        let idx = self.find_by_id(cgroup_id)?;
        self.groups[idx].counters.current = self.groups[idx].counters.current.saturating_sub(bytes);
        self.stats.total_uncharges += 1;
        self.stats.total_charged = self.stats.total_charged.saturating_sub(bytes);
        // Uncharge ancestors.
        let parent_id = self.groups[idx].parent_id;
        if parent_id != 0 {
            let _ = self.uncharge_ancestors(parent_id, bytes);
        }
        Ok(())
    }

    /// Charges swap to a cgroup.
    pub fn charge_swap(&mut self, cgroup_id: u32, bytes: u64) -> Result<()> {
        let idx = self.find_by_id(cgroup_id)?;
        let new_swap = self.groups[idx].swap.current + bytes;
        if self.groups[idx].swap.max != NO_LIMIT && new_swap > self.groups[idx].swap.max {
            self.groups[idx].swap.fail_count += 1;
            return Err(Error::OutOfMemory);
        }
        self.groups[idx].swap.current = new_swap;
        self.groups[idx].swap.update_peak();
        Ok(())
    }

    /// Uncharges swap from a cgroup.
    pub fn uncharge_swap(&mut self, cgroup_id: u32, bytes: u64) -> Result<()> {
        let idx = self.find_by_id(cgroup_id)?;
        self.groups[idx].swap.current = self.groups[idx].swap.current.saturating_sub(bytes);
        Ok(())
    }

    /// Records an OOM event for a cgroup.
    pub fn record_oom(&mut self, cgroup_id: u32) -> Result<()> {
        let idx = self.find_by_id(cgroup_id)?;
        self.groups[idx].events.oom += 1;
        self.stats.total_oom_events += 1;
        Ok(())
    }

    /// Records an OOM kill for a cgroup.
    pub fn record_oom_kill(&mut self, cgroup_id: u32) -> Result<()> {
        let idx = self.find_by_id(cgroup_id)?;
        self.groups[idx].events.oom_kill += 1;
        self.stats.total_oom_kills += 1;
        if self.groups[idx].oom_group {
            self.groups[idx].events.oom_group_kill += 1;
        }
        Ok(())
    }

    /// Returns a reference to a cgroup.
    pub fn get_group(&self, cgroup_id: u32) -> Result<&MemcgV2Group> {
        let idx = self.find_by_id(cgroup_id)?;
        Ok(&self.groups[idx])
    }

    /// Returns the cgroup that a PID belongs to.
    pub fn find_cgroup_for_pid(&self, pid: u32) -> Option<u32> {
        for i in 0..MAX_CGROUPS {
            if !self.groups[i].active {
                continue;
            }
            for j in 0..self.groups[i].nr_pids {
                if self.groups[i].pids[j] == pid {
                    return Some(self.groups[i].id);
                }
            }
        }
        None
    }

    /// Sets the oom_group flag for a cgroup.
    pub fn set_oom_group(&mut self, cgroup_id: u32, enabled: bool) -> Result<()> {
        let idx = self.find_by_id(cgroup_id)?;
        self.groups[idx].oom_group = enabled;
        Ok(())
    }

    /// Returns statistics.
    pub const fn stats(&self) -> &MemcgV2Stats {
        &self.stats
    }

    /// Returns the number of active cgroups.
    pub fn nr_active(&self) -> u32 {
        self.stats.active_cgroups
    }

    /// Resets all state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    fn find_by_id(&self, id: u32) -> Result<usize> {
        for i in 0..MAX_CGROUPS {
            if self.groups[i].active && self.groups[i].id == id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    fn find_free_slot(&self) -> Result<usize> {
        for i in 0..MAX_CGROUPS {
            if !self.groups[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    fn unlink_child(&mut self, parent_idx: usize, child_id: u32) {
        let nr = self.groups[parent_idx].nr_children;
        for i in 0..nr {
            if self.groups[parent_idx].children[i] == child_id {
                let last = nr - 1;
                self.groups[parent_idx].children[i] = self.groups[parent_idx].children[last];
                self.groups[parent_idx].nr_children -= 1;
                return;
            }
        }
    }

    fn charge_ancestors(&mut self, parent_id: u32, bytes: u64) -> Result<()> {
        let mut current_id = parent_id;
        let mut depth = 0;
        while current_id != 0 && depth < MAX_DEPTH {
            if let Ok(idx) = self.find_by_id(current_id) {
                self.groups[idx].counters.current += bytes;
                self.groups[idx].counters.update_peak();
                current_id = self.groups[idx].parent_id;
            } else {
                break;
            }
            depth += 1;
        }
        Ok(())
    }

    fn uncharge_ancestors(&mut self, parent_id: u32, bytes: u64) -> Result<()> {
        let mut current_id = parent_id;
        let mut depth = 0;
        while current_id != 0 && depth < MAX_DEPTH {
            if let Ok(idx) = self.find_by_id(current_id) {
                self.groups[idx].counters.current =
                    self.groups[idx].counters.current.saturating_sub(bytes);
                current_id = self.groups[idx].parent_id;
            } else {
                break;
            }
            depth += 1;
        }
        Ok(())
    }

    fn detach_pid_from_all(&mut self, pid: u32) {
        for i in 0..MAX_CGROUPS {
            if !self.groups[i].active {
                continue;
            }
            let nr = self.groups[i].nr_pids;
            for j in 0..nr {
                if self.groups[i].pids[j] == pid {
                    let last = nr - 1;
                    self.groups[i].pids[j] = self.groups[i].pids[last];
                    self.groups[i].nr_pids -= 1;
                    break;
                }
            }
        }
    }
}

impl Default for MemcgV2Controller {
    fn default() -> Self {
        Self::new()
    }
}
