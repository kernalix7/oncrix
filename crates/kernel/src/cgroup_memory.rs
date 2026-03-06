// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 memory controller.
//!
//! Implements the `memory` controller from Linux cgroups v2 with:
//! - Hard memory limit (`memory.max`) and high watermark
//!   (`memory.high`)
//! - Soft memory limit (`memory.low`) for reclaim protection
//! - Swap accounting (`memory.swap.max`, `memory.swap.current`)
//! - Charge/uncharge accounting for page allocations
//! - OOM handling with group-level OOM kill
//! - Detailed statistics (`memory.stat`)
//! - Hierarchical accounting (parent/child propagation)
//! - Event counters for limit hits and OOM kills
//!
//! # Architecture
//!
//! ```text
//!  Page allocation:
//!    alloc_page() → charge(cgroup, size)
//!      ├── check memory.max → OOM if exceeded
//!      ├── check memory.high → throttle / reclaim
//!      └── update counters (current, stat.rss, etc.)
//!
//!  Page free:
//!    free_page() → uncharge(cgroup, size)
//!      └── update counters, propagate to parent
//!
//!  Hierarchy:
//!    parent ← aggregates children's usage
//!    memory.low protects subtree from global reclaim
//! ```
//!
//! # Control Files (cgroup v2 interface)
//!
//! | File | Description |
//! |------|-------------|
//! | `memory.current` | Current memory usage |
//! | `memory.min` | Hard protection floor (no reclaim) |
//! | `memory.low` | Soft protection (best-effort) |
//! | `memory.high` | Throttling threshold |
//! | `memory.max` | Hard limit (OOM on exceed) |
//! | `memory.swap.current` | Current swap usage |
//! | `memory.swap.max` | Swap hard limit |
//! | `memory.stat` | Detailed statistics |
//! | `memory.events` | Event counters |
//! | `memory.oom.group` | Group OOM kill enable |
//!
//! Reference: Linux `mm/memcontrol.c`,
//! `include/linux/memcontrol.h`, cgroup v2 documentation.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of memory cgroup controllers in the system.
const MAX_MEMORY_CGROUPS: usize = 64;

/// Maximum number of PIDs attached to a single memory cgroup.
const MAX_PIDS_PER_GROUP: usize = 64;

/// Maximum name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Maximum cgroup hierarchy depth (parent chain).
const MAX_HIERARCHY_DEPTH: usize = 8;

/// Limit value meaning unlimited (no memory cap).
const LIMIT_UNLIMITED: i64 = -1;

/// Default OOM score adjustment.
const DEFAULT_OOM_SCORE_ADJ: i32 = 0;

/// Minimum OOM score adjustment.
const MIN_OOM_SCORE_ADJ: i32 = -1000;

/// Maximum OOM score adjustment.
const MAX_OOM_SCORE_ADJ: i32 = 1000;

// -------------------------------------------------------------------
// MemoryStatCounters
// -------------------------------------------------------------------

/// Detailed memory usage statistics (maps to `memory.stat`).
///
/// Each counter tracks bytes of memory in the corresponding
/// category. Counters use saturating arithmetic to prevent
/// overflow.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryStatCounters {
    /// Anonymous (non-file-backed) resident memory.
    pub anon: u64,
    /// File-backed (page cache) memory.
    pub file: u64,
    /// Kernel memory (slab, stack, page tables, etc.).
    pub kernel: u64,
    /// Kernel stack memory.
    pub kernel_stack: u64,
    /// Page table memory.
    pub pagetables: u64,
    /// Slab reclaimable memory.
    pub slab_reclaimable: u64,
    /// Slab unreclaimable memory.
    pub slab_unreclaimable: u64,
    /// Memory mapped files.
    pub file_mapped: u64,
    /// Dirty file pages.
    pub file_dirty: u64,
    /// File pages under writeback.
    pub file_writeback: u64,
    /// Anonymous pages on the inactive LRU.
    pub inactive_anon: u64,
    /// Anonymous pages on the active LRU.
    pub active_anon: u64,
    /// File pages on the inactive LRU.
    pub inactive_file: u64,
    /// File pages on the active LRU.
    pub active_file: u64,
    /// Unevictable memory (locked, mlocked).
    pub unevictable: u64,
    /// Shared memory (shmem, tmpfs).
    pub shmem: u64,
    /// Pages scanned by direct reclaim.
    pub pgfault: u64,
    /// Major page faults (required I/O).
    pub pgmajfault: u64,
    /// Total pages scanned for reclaim.
    pub pgrefill: u64,
    /// Pages reclaimed via scanning.
    pub pgscan: u64,
    /// Pages successfully stolen via reclaim.
    pub pgsteal: u64,
    /// Pages activated (promoted from inactive LRU).
    pub pgactivate: u64,
    /// Pages deactivated (demoted to inactive LRU).
    pub pgdeactivate: u64,
    /// Pages lazily freed.
    pub pglazyfree: u64,
    /// THP (Transparent Huge Page) faults.
    pub thp_fault_alloc: u64,
    /// THP collapses.
    pub thp_collapse_alloc: u64,
}

impl MemoryStatCounters {
    /// Returns total RSS (anon + file-mapped + shmem).
    pub fn rss(&self) -> u64 {
        self.anon
            .saturating_add(self.file_mapped)
            .saturating_add(self.shmem)
    }

    /// Returns total cache (file + slab reclaimable).
    pub fn cache(&self) -> u64 {
        self.file.saturating_add(self.slab_reclaimable)
    }

    /// Returns total slab (reclaimable + unreclaimable).
    pub fn slab(&self) -> u64 {
        self.slab_reclaimable
            .saturating_add(self.slab_unreclaimable)
    }
}

// -------------------------------------------------------------------
// MemoryEvents
// -------------------------------------------------------------------

/// Event counters for a memory cgroup (maps to `memory.events`).
///
/// Each counter records the number of times a particular event
/// has occurred since the cgroup was created.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryEvents {
    /// Number of times `memory.low` was breached (reclaim
    /// entered the protected region).
    pub low: u64,
    /// Number of times `memory.high` was exceeded (throttling
    /// was activated).
    pub high: u64,
    /// Number of times `memory.max` was hit (allocation
    /// failures or OOM).
    pub max: u64,
    /// Number of OOM kills performed for this cgroup.
    pub oom: u64,
    /// Number of OOM group kills.
    pub oom_group_kill: u64,
    /// Number of times the cgroup's memory.oom.group was
    /// triggered.
    pub oom_kill: u64,
}

// -------------------------------------------------------------------
// SwapAccounting
// -------------------------------------------------------------------

/// Swap usage and limits for a memory cgroup.
#[derive(Debug, Clone, Copy)]
pub struct SwapAccounting {
    /// Current swap usage in bytes.
    pub current: u64,
    /// Maximum swap allowed in bytes (`-1` = unlimited).
    pub max: i64,
    /// Number of times the swap limit was hit.
    pub fail_count: u64,
}

impl Default for SwapAccounting {
    fn default() -> Self {
        Self {
            current: 0,
            max: LIMIT_UNLIMITED,
            fail_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// OomConfig
// -------------------------------------------------------------------

/// OOM configuration for a memory cgroup.
#[derive(Debug, Clone, Copy)]
pub struct OomConfig {
    /// Whether group OOM kill is enabled. When enabled, all
    /// processes in the cgroup are killed on OOM, not just one.
    pub oom_group: bool,
    /// OOM score adjustment (-1000 to 1000). Higher values make
    /// processes in this cgroup more likely to be killed.
    pub oom_score_adj: i32,
    /// Whether OOM killer is disabled for this cgroup.
    pub oom_kill_disable: bool,
    /// Number of processes killed by OOM in this cgroup.
    pub oom_kill_count: u64,
}

impl Default for OomConfig {
    fn default() -> Self {
        Self {
            oom_group: false,
            oom_score_adj: DEFAULT_OOM_SCORE_ADJ,
            oom_kill_disable: false,
            oom_kill_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// MemoryLimits
// -------------------------------------------------------------------

/// Memory limit thresholds for a cgroup.
///
/// Corresponds to the `memory.min`, `memory.low`, `memory.high`,
/// and `memory.max` control files.
#[derive(Debug, Clone, Copy)]
pub struct MemoryLimits {
    /// Hard protection floor — memory below this is never
    /// reclaimed. `-1` means unlimited (no floor).
    pub min: i64,
    /// Soft protection — memory below this is protected from
    /// reclaim on a best-effort basis. `-1` means unlimited.
    pub low: i64,
    /// Throttling threshold — usage above this triggers
    /// reclaim and throttling. `-1` means unlimited.
    pub high: i64,
    /// Hard limit — allocations beyond this trigger OOM.
    /// `-1` means unlimited.
    pub max: i64,
}

impl Default for MemoryLimits {
    fn default() -> Self {
        Self {
            min: 0,
            low: 0,
            high: LIMIT_UNLIMITED,
            max: LIMIT_UNLIMITED,
        }
    }
}

// -------------------------------------------------------------------
// MemoryCgroup
// -------------------------------------------------------------------

/// A single memory cgroup controller instance.
///
/// Manages memory limits, usage accounting, swap tracking, OOM
/// configuration, and statistics for a set of attached processes.
#[derive(Debug, Clone, Copy)]
pub struct MemoryCgroup {
    /// Unique identifier for this cgroup.
    pub id: u64,
    /// Cgroup name (UTF-8 bytes, null-padded).
    name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    name_len: usize,
    /// Memory limit configuration.
    pub limits: MemoryLimits,
    /// Current memory usage in bytes.
    pub usage: u64,
    /// Peak (watermark) memory usage in bytes.
    pub usage_peak: u64,
    /// Swap accounting.
    pub swap: SwapAccounting,
    /// OOM configuration.
    pub oom: OomConfig,
    /// Detailed statistics.
    pub stat: MemoryStatCounters,
    /// Event counters.
    pub events: MemoryEvents,
    /// Attached process IDs.
    pids: [u64; MAX_PIDS_PER_GROUP],
    /// Number of attached PIDs.
    pid_count: usize,
    /// Parent cgroup ID (0 = root / no parent).
    pub parent_id: u64,
    /// Child cgroup IDs.
    children: [u64; MAX_HIERARCHY_DEPTH],
    /// Number of children.
    child_count: usize,
    /// Whether this controller is enabled.
    pub enabled: bool,
    /// Whether this slot is actively in use.
    in_use: bool,
    /// Failcnt — number of times memory.max was hit.
    pub failcnt: u64,
}

impl MemoryCgroup {
    /// Creates an empty (inactive) cgroup slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            limits: MemoryLimits {
                min: 0,
                low: 0,
                high: LIMIT_UNLIMITED,
                max: LIMIT_UNLIMITED,
            },
            usage: 0,
            usage_peak: 0,
            swap: SwapAccounting {
                current: 0,
                max: LIMIT_UNLIMITED,
                fail_count: 0,
            },
            oom: OomConfig {
                oom_group: false,
                oom_score_adj: DEFAULT_OOM_SCORE_ADJ,
                oom_kill_disable: false,
                oom_kill_count: 0,
            },
            stat: MemoryStatCounters {
                anon: 0,
                file: 0,
                kernel: 0,
                kernel_stack: 0,
                pagetables: 0,
                slab_reclaimable: 0,
                slab_unreclaimable: 0,
                file_mapped: 0,
                file_dirty: 0,
                file_writeback: 0,
                inactive_anon: 0,
                active_anon: 0,
                inactive_file: 0,
                active_file: 0,
                unevictable: 0,
                shmem: 0,
                pgfault: 0,
                pgmajfault: 0,
                pgrefill: 0,
                pgscan: 0,
                pgsteal: 0,
                pgactivate: 0,
                pgdeactivate: 0,
                pglazyfree: 0,
                thp_fault_alloc: 0,
                thp_collapse_alloc: 0,
            },
            events: MemoryEvents {
                low: 0,
                high: 0,
                max: 0,
                oom: 0,
                oom_group_kill: 0,
                oom_kill: 0,
            },
            pids: [0u64; MAX_PIDS_PER_GROUP],
            pid_count: 0,
            parent_id: 0,
            children: [0u64; MAX_HIERARCHY_DEPTH],
            child_count: 0,
            enabled: false,
            in_use: false,
            failcnt: 0,
        }
    }

    /// Returns the cgroup name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Sets the hard memory limit (`memory.max`).
    ///
    /// `limit` must be `-1` (unlimited) or a positive value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `limit` is zero or
    /// a negative value other than `-1`.
    pub fn set_max(&mut self, limit: i64) -> Result<()> {
        if limit != LIMIT_UNLIMITED && limit <= 0 {
            return Err(Error::InvalidArgument);
        }
        self.limits.max = limit;
        Ok(())
    }

    /// Sets the high watermark (`memory.high`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `limit` is zero or
    /// a negative value other than `-1`.
    pub fn set_high(&mut self, limit: i64) -> Result<()> {
        if limit != LIMIT_UNLIMITED && limit <= 0 {
            return Err(Error::InvalidArgument);
        }
        self.limits.high = limit;
        Ok(())
    }

    /// Sets the soft protection limit (`memory.low`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `limit` is
    /// negative.
    pub fn set_low(&mut self, limit: i64) -> Result<()> {
        if limit < 0 {
            return Err(Error::InvalidArgument);
        }
        self.limits.low = limit;
        Ok(())
    }

    /// Sets the hard protection floor (`memory.min`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `limit` is
    /// negative.
    pub fn set_min(&mut self, limit: i64) -> Result<()> {
        if limit < 0 {
            return Err(Error::InvalidArgument);
        }
        self.limits.min = limit;
        Ok(())
    }

    /// Sets the swap limit (`memory.swap.max`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `limit` is zero or
    /// a negative value other than `-1`.
    pub fn set_swap_max(&mut self, limit: i64) -> Result<()> {
        if limit != LIMIT_UNLIMITED && limit <= 0 {
            return Err(Error::InvalidArgument);
        }
        self.swap.max = limit;
        Ok(())
    }

    /// Configures OOM settings for this cgroup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `oom_score_adj` is
    /// outside the range [-1000, 1000].
    pub fn set_oom_config(
        &mut self,
        oom_group: bool,
        oom_score_adj: i32,
        oom_kill_disable: bool,
    ) -> Result<()> {
        if !(MIN_OOM_SCORE_ADJ..=MAX_OOM_SCORE_ADJ).contains(&oom_score_adj) {
            return Err(Error::InvalidArgument);
        }
        self.oom.oom_group = oom_group;
        self.oom.oom_score_adj = oom_score_adj;
        self.oom.oom_kill_disable = oom_kill_disable;
        Ok(())
    }

    /// Charges memory to this cgroup.
    ///
    /// Adds `bytes` to the current usage and updates statistics.
    /// Checks against `memory.max` and `memory.high`, recording
    /// events when thresholds are crossed.
    ///
    /// # Returns
    ///
    /// - `Ok(ChargeResult::Ok)` — charge succeeded, no action
    ///   needed.
    /// - `Ok(ChargeResult::HighExceeded)` — charge succeeded but
    ///   high watermark was crossed (caller should trigger
    ///   reclaim).
    /// - `Err(Error::OutOfMemory)` — charge failed because
    ///   `memory.max` would be exceeded.
    pub fn charge(&mut self, bytes: u64) -> Result<ChargeResult> {
        let new_usage = self.usage.saturating_add(bytes);

        // Check hard limit.
        if self.limits.max != LIMIT_UNLIMITED && new_usage > self.limits.max as u64 {
            self.events.max = self.events.max.saturating_add(1);
            self.failcnt = self.failcnt.saturating_add(1);
            return Err(Error::OutOfMemory);
        }

        self.usage = new_usage;

        // Update peak watermark.
        if self.usage > self.usage_peak {
            self.usage_peak = self.usage;
        }

        // Check high watermark.
        if self.limits.high != LIMIT_UNLIMITED && self.usage > self.limits.high as u64 {
            self.events.high = self.events.high.saturating_add(1);
            return Ok(ChargeResult::HighExceeded);
        }

        // Check low watermark breach.
        if self.limits.low > 0 && self.usage > self.limits.low as u64 {
            self.events.low = self.events.low.saturating_add(1);
        }

        Ok(ChargeResult::Ok)
    }

    /// Uncharges memory from this cgroup.
    ///
    /// Subtracts `bytes` from the current usage (clamped to 0).
    pub fn uncharge(&mut self, bytes: u64) {
        self.usage = self.usage.saturating_sub(bytes);
    }

    /// Charges swap usage to this cgroup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the swap limit would
    /// be exceeded.
    pub fn charge_swap(&mut self, bytes: u64) -> Result<()> {
        let new_swap = self.swap.current.saturating_add(bytes);
        if self.swap.max != LIMIT_UNLIMITED && new_swap > self.swap.max as u64 {
            self.swap.fail_count = self.swap.fail_count.saturating_add(1);
            return Err(Error::OutOfMemory);
        }
        self.swap.current = new_swap;
        Ok(())
    }

    /// Uncharges swap usage from this cgroup.
    pub fn uncharge_swap(&mut self, bytes: u64) {
        self.swap.current = self.swap.current.saturating_sub(bytes);
    }

    /// Charges anonymous memory (RSS) to the statistics.
    pub fn charge_anon(&mut self, bytes: u64) {
        self.stat.anon = self.stat.anon.saturating_add(bytes);
    }

    /// Uncharges anonymous memory from the statistics.
    pub fn uncharge_anon(&mut self, bytes: u64) {
        self.stat.anon = self.stat.anon.saturating_sub(bytes);
    }

    /// Charges file-backed (cache) memory to the statistics.
    pub fn charge_file(&mut self, bytes: u64) {
        self.stat.file = self.stat.file.saturating_add(bytes);
    }

    /// Uncharges file-backed memory from the statistics.
    pub fn uncharge_file(&mut self, bytes: u64) {
        self.stat.file = self.stat.file.saturating_sub(bytes);
    }

    /// Charges kernel memory to the statistics.
    pub fn charge_kernel(&mut self, bytes: u64) {
        self.stat.kernel = self.stat.kernel.saturating_add(bytes);
    }

    /// Uncharges kernel memory from the statistics.
    pub fn uncharge_kernel(&mut self, bytes: u64) {
        self.stat.kernel = self.stat.kernel.saturating_sub(bytes);
    }

    /// Records a page fault event.
    pub fn record_pgfault(&mut self, major: bool) {
        self.stat.pgfault = self.stat.pgfault.saturating_add(1);
        if major {
            self.stat.pgmajfault = self.stat.pgmajfault.saturating_add(1);
        }
    }

    /// Triggers OOM handling for this cgroup.
    ///
    /// Returns the number of processes that should be killed.
    /// If `oom_group` is enabled, all processes are killed;
    /// otherwise only one process is selected.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if OOM kill is
    /// disabled for this cgroup.
    pub fn trigger_oom(&mut self) -> Result<usize> {
        if self.oom.oom_kill_disable {
            return Err(Error::PermissionDenied);
        }
        self.events.oom = self.events.oom.saturating_add(1);

        let kill_count = if self.oom.oom_group {
            self.events.oom_group_kill = self.events.oom_group_kill.saturating_add(1);
            self.pid_count
        } else {
            // Kill one process (the one with the highest
            // effective OOM score).
            if self.pid_count > 0 {
                self.events.oom_kill = self.events.oom_kill.saturating_add(1);
                1
            } else {
                0
            }
        };

        self.oom.oom_kill_count = self.oom.oom_kill_count.saturating_add(kill_count as u64);

        Ok(kill_count)
    }

    /// Adds a PID to this cgroup.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] — PID already attached.
    /// - [`Error::OutOfMemory`] — PID array full.
    pub fn add_pid(&mut self, pid: u64) -> Result<()> {
        if self.pids[..self.pid_count].contains(&pid) {
            return Err(Error::AlreadyExists);
        }
        if self.pid_count >= MAX_PIDS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        self.pids[self.pid_count] = pid;
        self.pid_count += 1;
        Ok(())
    }

    /// Removes a PID from this cgroup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PID is not attached.
    pub fn remove_pid(&mut self, pid: u64) -> Result<()> {
        let pos = self.pids[..self.pid_count]
            .iter()
            .position(|&p| p == pid)
            .ok_or(Error::NotFound)?;

        self.pid_count -= 1;
        if pos < self.pid_count {
            self.pids[pos] = self.pids[self.pid_count];
        }
        self.pids[self.pid_count] = 0;
        Ok(())
    }

    /// Returns whether a PID is attached.
    pub fn has_pid(&self, pid: u64) -> bool {
        self.pids[..self.pid_count].contains(&pid)
    }

    /// Returns the number of attached PIDs.
    pub fn pid_count(&self) -> usize {
        self.pid_count
    }

    /// Returns a reference to the memory limits.
    pub fn limits(&self) -> &MemoryLimits {
        &self.limits
    }

    /// Returns a reference to the statistics.
    pub fn stat(&self) -> &MemoryStatCounters {
        &self.stat
    }

    /// Returns a reference to the event counters.
    pub fn events(&self) -> &MemoryEvents {
        &self.events
    }

    /// Returns a reference to the swap accounting.
    pub fn swap(&self) -> &SwapAccounting {
        &self.swap
    }

    /// Returns a reference to the OOM config.
    pub fn oom_config(&self) -> &OomConfig {
        &self.oom
    }

    /// Returns the effective memory usage including swap.
    pub fn memsw_usage(&self) -> u64 {
        self.usage.saturating_add(self.swap.current)
    }

    /// Resets peak usage watermark to current usage.
    pub fn reset_peak(&mut self) {
        self.usage_peak = self.usage;
    }

    /// Adds a child cgroup by ID.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the children array is full.
    /// - [`Error::AlreadyExists`] if the child is already
    ///   registered.
    fn add_child(&mut self, child_id: u64) -> Result<()> {
        if self.children[..self.child_count].contains(&child_id) {
            return Err(Error::AlreadyExists);
        }
        if self.child_count >= MAX_HIERARCHY_DEPTH {
            return Err(Error::OutOfMemory);
        }
        self.children[self.child_count] = child_id;
        self.child_count += 1;
        Ok(())
    }

    /// Removes a child cgroup by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the child is not found.
    fn remove_child(&mut self, child_id: u64) -> Result<()> {
        let pos = self.children[..self.child_count]
            .iter()
            .position(|&c| c == child_id)
            .ok_or(Error::NotFound)?;

        self.child_count -= 1;
        if pos < self.child_count {
            self.children[pos] = self.children[self.child_count];
        }
        self.children[self.child_count] = 0;
        Ok(())
    }

    /// Returns the number of child cgroups.
    pub fn child_count(&self) -> usize {
        self.child_count
    }
}

// -------------------------------------------------------------------
// ChargeResult
// -------------------------------------------------------------------

/// Outcome of a memory charge operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargeResult {
    /// Charge succeeded, no action needed.
    Ok,
    /// Charge succeeded but `memory.high` was exceeded;
    /// the caller should trigger reclaim or throttling.
    HighExceeded,
}

// -------------------------------------------------------------------
// MemoryCgroupRegistry
// -------------------------------------------------------------------

/// System-wide registry of memory cgroup controllers.
///
/// Manages up to [`MAX_MEMORY_CGROUPS`] controllers in a
/// fixed-size array. Each controller is identified by a unique
/// `u64` ID assigned at creation time. Supports hierarchical
/// parent/child relationships.
pub struct MemoryCgroupRegistry {
    /// Fixed-size array of cgroup slots.
    cgroups: [MemoryCgroup; MAX_MEMORY_CGROUPS],
    /// Next cgroup ID to assign.
    next_id: u64,
    /// Number of active cgroups.
    count: usize,
}

impl Default for MemoryCgroupRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryCgroupRegistry {
    /// Creates a new, empty registry.
    pub const fn new() -> Self {
        const EMPTY: MemoryCgroup = MemoryCgroup::empty();
        Self {
            cgroups: [EMPTY; MAX_MEMORY_CGROUPS],
            next_id: 1,
            count: 0,
        }
    }

    /// Returns the number of active cgroups.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no cgroups are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Creates a new memory cgroup with the given name.
    ///
    /// An optional `parent_id` establishes hierarchy — charges
    /// to the child will propagate up to the parent.
    ///
    /// Returns the new cgroup's unique ID.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — name is empty or too long.
    /// - [`Error::OutOfMemory`] — no free slots available.
    /// - [`Error::NotFound`] — parent_id specified but not found.
    pub fn create(&mut self, name: &[u8], parent_id: Option<u64>) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_MEMORY_CGROUPS {
            return Err(Error::OutOfMemory);
        }

        // Validate parent if specified.
        if let Some(pid) = parent_id {
            if self.index_of(pid).is_err() {
                return Err(Error::NotFound);
            }
        }

        let slot = self
            .cgroups
            .iter()
            .position(|c| !c.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let cg = &mut self.cgroups[slot];
        *cg = MemoryCgroup::empty();
        cg.id = id;
        cg.in_use = true;
        cg.enabled = true;
        cg.name_len = name.len();
        cg.name[..name.len()].copy_from_slice(name);

        if let Some(pid) = parent_id {
            cg.parent_id = pid;
            // Register as child of parent.
            let parent_idx = self.index_of(pid)?;
            self.cgroups[parent_idx].add_child(id)?;
        }

        self.count += 1;
        Ok(id)
    }

    /// Destroys a memory cgroup by ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — cgroup does not exist.
    /// - [`Error::Busy`] — cgroup still has attached PIDs or
    ///   children.
    pub fn destroy(&mut self, id: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        if self.cgroups[idx].pid_count > 0 {
            return Err(Error::Busy);
        }
        if self.cgroups[idx].child_count > 0 {
            return Err(Error::Busy);
        }

        // Remove from parent's children list.
        let parent_id = self.cgroups[idx].parent_id;
        if parent_id != 0 {
            if let Ok(parent_idx) = self.index_of(parent_id) {
                let _ = self.cgroups[parent_idx].remove_child(id);
            }
        }

        self.cgroups[idx].in_use = false;
        self.cgroups[idx].enabled = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Returns an immutable reference to a cgroup by ID.
    pub fn get(&self, id: u64) -> Option<&MemoryCgroup> {
        self.cgroups.iter().find(|c| c.in_use && c.id == id)
    }

    /// Returns a mutable reference to a cgroup by ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut MemoryCgroup> {
        self.cgroups.iter_mut().find(|c| c.in_use && c.id == id)
    }

    /// Sets the hard memory limit for a cgroup.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — cgroup does not exist.
    /// - [`Error::InvalidArgument`] — invalid limit.
    pub fn set_max(&mut self, id: u64, limit: i64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.cgroups[idx].set_max(limit)
    }

    /// Sets the high watermark for a cgroup.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — cgroup does not exist.
    /// - [`Error::InvalidArgument`] — invalid limit.
    pub fn set_high(&mut self, id: u64, limit: i64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.cgroups[idx].set_high(limit)
    }

    /// Sets the soft protection limit for a cgroup.
    pub fn set_low(&mut self, id: u64, limit: i64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.cgroups[idx].set_low(limit)
    }

    /// Sets the hard protection floor for a cgroup.
    pub fn set_min(&mut self, id: u64, limit: i64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.cgroups[idx].set_min(limit)
    }

    /// Sets the swap limit for a cgroup.
    pub fn set_swap_max(&mut self, id: u64, limit: i64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.cgroups[idx].set_swap_max(limit)
    }

    /// Charges memory to a cgroup with hierarchical
    /// propagation.
    ///
    /// The charge is applied to the target cgroup and all
    /// ancestors up to the root.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — cgroup does not exist.
    /// - [`Error::OutOfMemory`] — would exceed `memory.max` at
    ///   some level.
    pub fn charge(&mut self, id: u64, bytes: u64) -> Result<ChargeResult> {
        // First pass: check that no ancestor would exceed its
        // limit. Collect the chain of IDs to charge.
        let mut chain = [0u64; MAX_HIERARCHY_DEPTH];
        let mut depth = 0usize;
        let mut current_id = id;

        while current_id != 0 && depth < MAX_HIERARCHY_DEPTH {
            let idx = self.index_of(current_id)?;
            let cg = &self.cgroups[idx];
            // Check if charging would exceed max.
            if cg.limits.max != LIMIT_UNLIMITED {
                let new_usage = cg.usage.saturating_add(bytes);
                if new_usage > cg.limits.max as u64 {
                    return Err(Error::OutOfMemory);
                }
            }
            chain[depth] = current_id;
            depth += 1;
            current_id = cg.parent_id;
        }

        // Second pass: apply the charge.
        let mut result = ChargeResult::Ok;
        for i in 0..depth {
            let idx = self.index_of(chain[i])?;
            match self.cgroups[idx].charge(bytes) {
                Ok(ChargeResult::HighExceeded) => {
                    result = ChargeResult::HighExceeded;
                }
                Ok(ChargeResult::Ok) => {}
                Err(e) => return Err(e),
            }
        }

        Ok(result)
    }

    /// Uncharges memory from a cgroup with hierarchical
    /// propagation.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — cgroup does not exist.
    pub fn uncharge(&mut self, id: u64, bytes: u64) -> Result<()> {
        let mut current_id = id;
        let mut depth = 0usize;

        while current_id != 0 && depth < MAX_HIERARCHY_DEPTH {
            let idx = self.index_of(current_id)?;
            self.cgroups[idx].uncharge(bytes);
            current_id = self.cgroups[idx].parent_id;
            depth += 1;
        }

        Ok(())
    }

    /// Charges swap usage to a cgroup.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — cgroup does not exist.
    /// - [`Error::OutOfMemory`] — swap limit exceeded.
    pub fn charge_swap(&mut self, id: u64, bytes: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.cgroups[idx].charge_swap(bytes)
    }

    /// Uncharges swap usage from a cgroup.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — cgroup does not exist.
    pub fn uncharge_swap(&mut self, id: u64, bytes: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.cgroups[idx].uncharge_swap(bytes);
        Ok(())
    }

    /// Attaches a PID to a cgroup.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — cgroup does not exist.
    /// - [`Error::AlreadyExists`] — PID already attached.
    /// - [`Error::OutOfMemory`] — PID array full.
    pub fn add_pid(&mut self, id: u64, pid: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.cgroups[idx].add_pid(pid)
    }

    /// Detaches a PID from a cgroup.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — cgroup or PID not found.
    pub fn remove_pid(&mut self, id: u64, pid: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.cgroups[idx].remove_pid(pid)
    }

    /// Triggers OOM handling for a cgroup.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — cgroup does not exist.
    /// - [`Error::PermissionDenied`] — OOM kill disabled.
    pub fn trigger_oom(&mut self, id: u64) -> Result<usize> {
        let idx = self.index_of(id)?;
        self.cgroups[idx].trigger_oom()
    }

    /// Returns the total memory usage across all active cgroups
    /// (non-hierarchical sum).
    pub fn total_usage(&self) -> u64 {
        self.cgroups
            .iter()
            .filter(|c| c.in_use)
            .fold(0u64, |acc, c| acc.saturating_add(c.usage))
    }

    // ── Internal helpers ──────────────────────────────────────────

    /// Returns the index of an active cgroup by ID.
    fn index_of(&self, id: u64) -> Result<usize> {
        self.cgroups
            .iter()
            .position(|c| c.in_use && c.id == id)
            .ok_or(Error::NotFound)
    }
}

impl core::fmt::Debug for MemoryCgroupRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemoryCgroupRegistry")
            .field("count", &self.count)
            .field("capacity", &MAX_MEMORY_CGROUPS)
            .finish()
    }
}
