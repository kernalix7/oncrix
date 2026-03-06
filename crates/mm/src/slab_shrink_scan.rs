// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Slab shrinker scanning.
//!
//! Implements a shrinker framework for reclaiming reclaimable slab
//! caches. Shrinkers register a `count` callback (how many objects
//! are reclaimable) and a `scan` callback (free up to N objects).
//! The reclaim path traverses the global shrinker list, invoking
//! each shrinker's scan callback with a seek/scan ratio to spread
//! reclaim effort across multiple shrinkers. Deferred work and
//! `nr_deferred` accounting handle shrinkers that cannot complete
//! their work in a single pass.
//!
//! # Key Types
//!
//! - [`ShrinkerPriority`] — reclaim urgency level
//! - [`ShrinkControl`] — per-invocation scan parameters
//! - [`ShrinkerEntry`] — registered shrinker descriptor
//! - [`ShrinkerList`] — global list of registered shrinkers
//! - [`ShrinkResult`] — outcome of a single scan invocation
//! - [`ShrinkStats`] — aggregate shrinker statistics
//! - [`SlabShrinkerManager`] — top-level shrinker manager
//!
//! Reference: Linux `mm/shrinker.c`, `include/linux/shrinker.h`,
//! `mm/vmscan.c` (`shrink_slab`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum registered shrinkers.
const MAX_SHRINKERS: usize = 64;

/// Maximum NUMA nodes for per-node invocation.
const MAX_NUMA_NODES: usize = 4;

/// Default seek/scan ratio (scan 1 for every N countable).
const DEFAULT_SEEK_RATIO: u64 = 2;

/// Maximum scan batch per invocation.
const MAX_SCAN_BATCH: u64 = 1024;

/// Invalid shrinker ID.
const INVALID_ID: u32 = u32::MAX;

// -------------------------------------------------------------------
// ShrinkerPriority
// -------------------------------------------------------------------

/// Reclaim urgency level passed to shrinkers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShrinkerPriority {
    /// Normal background reclaim.
    #[default]
    Normal,
    /// Moderate pressure — reclaim more aggressively.
    Moderate,
    /// Severe pressure — reclaim as much as possible.
    Severe,
    /// Emergency — OOM imminent.
    Emergency,
}

impl ShrinkerPriority {
    /// Numeric priority value (higher = more urgent).
    pub const fn level(self) -> u32 {
        match self {
            Self::Normal => 0,
            Self::Moderate => 1,
            Self::Severe => 2,
            Self::Emergency => 3,
        }
    }
}

// -------------------------------------------------------------------
// ShrinkControl
// -------------------------------------------------------------------

/// Per-invocation scan parameters passed to a shrinker's scan
/// callback.
#[derive(Debug, Clone, Copy)]
pub struct ShrinkControl {
    /// Number of objects requested to scan (free).
    pub nr_to_scan: u64,
    /// NUMA node to scan (-1 for all nodes).
    pub nid: i32,
    /// Memory cgroup ID to scope the scan (-1 for global).
    pub memcg_id: i32,
    /// Reclaim priority.
    pub priority: ShrinkerPriority,
    /// GFP allocation context flags.
    pub gfp_mask: u32,
}

impl ShrinkControl {
    /// Create a default global scan control.
    pub const fn global(nr_to_scan: u64, priority: ShrinkerPriority) -> Self {
        Self {
            nr_to_scan,
            nid: -1,
            memcg_id: -1,
            priority,
            gfp_mask: 0,
        }
    }

    /// Create a per-node per-memcg scan control.
    pub const fn scoped(
        nr_to_scan: u64,
        nid: i32,
        memcg_id: i32,
        priority: ShrinkerPriority,
    ) -> Self {
        Self {
            nr_to_scan,
            nid,
            memcg_id,
            priority,
            gfp_mask: 0,
        }
    }
}

// -------------------------------------------------------------------
// ShrinkResult
// -------------------------------------------------------------------

/// Outcome of a single shrinker scan invocation.
#[derive(Debug, Clone, Copy)]
pub struct ShrinkResult {
    /// Number of objects actually freed.
    pub freed: u64,
    /// Number of objects that remain reclaimable.
    pub remaining: u64,
    /// Whether the shrinker deferred work for later.
    pub deferred: bool,
}

// -------------------------------------------------------------------
// ShrinkerEntry
// -------------------------------------------------------------------

/// A registered shrinker descriptor.
///
/// In a real kernel the `count_fn` and `scan_fn` fields would be
/// function pointers. Here we store simulated countable/scannable
/// counts and track deferred work.
pub struct ShrinkerEntry {
    /// Unique shrinker identifier.
    pub id: u32,
    /// Human-readable name (up to 32 bytes).
    pub name: [u8; 32],
    /// Length of the name.
    name_len: usize,
    /// Seek/scan ratio (scan 1 object per `seeks` countable).
    pub seeks: u64,
    /// Current number of reclaimable objects (count callback).
    pub countable: u64,
    /// Objects freed so far via scan callback.
    pub scanned: u64,
    /// Deferred count: objects not scanned in previous passes.
    pub nr_deferred: u64,
    /// Per-NUMA-node deferred counts.
    pub node_deferred: [u64; MAX_NUMA_NODES],
    /// Whether this entry is active.
    active: bool,
}

impl ShrinkerEntry {
    /// Create an empty, inactive shrinker entry.
    const fn empty() -> Self {
        Self {
            id: INVALID_ID,
            name: [0u8; 32],
            name_len: 0,
            seeks: DEFAULT_SEEK_RATIO,
            countable: 0,
            scanned: 0,
            nr_deferred: 0,
            node_deferred: [0u64; MAX_NUMA_NODES],
            active: false,
        }
    }

    /// Whether this entry is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Simulate a count callback: return number of reclaimable
    /// objects (including deferred).
    pub const fn count(&self) -> u64 {
        self.countable + self.nr_deferred
    }

    /// Simulate a scan callback: free up to `nr_to_scan` objects.
    fn scan(&mut self, ctrl: &ShrinkControl) -> ShrinkResult {
        let available = self.countable;
        let to_scan = ctrl.nr_to_scan.min(available);
        let effective = if self.seeks > 0 {
            to_scan / self.seeks
        } else {
            to_scan
        };
        let freed = effective.min(available);
        self.countable = self.countable.saturating_sub(freed);
        self.scanned += freed;

        let deferred_amount = to_scan.saturating_sub(freed);
        let deferred = deferred_amount > 0;
        self.nr_deferred += deferred_amount;

        if ctrl.nid >= 0 {
            let nid = ctrl.nid as usize;
            if nid < MAX_NUMA_NODES {
                self.node_deferred[nid] += deferred_amount;
            }
        }

        ShrinkResult {
            freed,
            remaining: self.countable,
            deferred,
        }
    }

    /// Drain deferred work by adding it back to countable.
    fn drain_deferred(&mut self) {
        self.countable += self.nr_deferred;
        self.nr_deferred = 0;
        self.node_deferred = [0u64; MAX_NUMA_NODES];
    }
}

// -------------------------------------------------------------------
// ShrinkerList
// -------------------------------------------------------------------

/// Global list of registered shrinkers.
pub struct ShrinkerList {
    /// Registered shrinkers.
    entries: [ShrinkerEntry; MAX_SHRINKERS],
    /// Number of active shrinkers.
    count: usize,
}

impl ShrinkerList {
    /// Create an empty shrinker list.
    const fn new() -> Self {
        Self {
            entries: [const { ShrinkerEntry::empty() }; MAX_SHRINKERS],
            count: 0,
        }
    }

    /// Number of registered shrinkers.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Look up a shrinker by ID.
    pub fn find(&self, id: u32) -> Option<&ShrinkerEntry> {
        self.entries[..].iter().find(|e| e.active && e.id == id)
    }

    /// Register a new shrinker. Returns its ID.
    fn register(&mut self, id: u32, name: &[u8], seeks: u64, initial_count: u64) -> Result<()> {
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        let entry = &mut self.entries[slot];
        *entry = ShrinkerEntry::empty();
        entry.id = id;
        let n = name.len().min(32);
        entry.name[..n].copy_from_slice(&name[..n]);
        entry.name_len = n;
        entry.seeks = if seeks > 0 { seeks } else { DEFAULT_SEEK_RATIO };
        entry.countable = initial_count;
        entry.active = true;
        self.count += 1;
        Ok(())
    }

    /// Unregister a shrinker by ID.
    fn unregister(&mut self, id: u32) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.id == id)
            .ok_or(Error::NotFound)?;
        entry.active = false;
        entry.id = INVALID_ID;
        self.count -= 1;
        Ok(())
    }
}

// -------------------------------------------------------------------
// ShrinkStats
// -------------------------------------------------------------------

/// Aggregate shrinker statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShrinkStats {
    /// Total scan invocations.
    pub total_scans: u64,
    /// Total objects freed across all scans.
    pub total_freed: u64,
    /// Total deferred objects across all shrinkers.
    pub total_deferred: u64,
    /// Number of shrinker registrations.
    pub registrations: u64,
    /// Number of shrinker unregistrations.
    pub unregistrations: u64,
    /// Drain-deferred calls.
    pub drain_calls: u64,
}

// -------------------------------------------------------------------
// SlabShrinkerManager
// -------------------------------------------------------------------

/// Top-level slab shrinker manager.
///
/// Coordinates shrinker registration, traversal, and per-node
/// per-memcg invocation.
pub struct SlabShrinkerManager {
    /// Global shrinker list.
    list: ShrinkerList,
    /// Next shrinker ID to assign.
    next_id: u32,
    /// Aggregate statistics.
    stats: ShrinkStats,
}

impl Default for SlabShrinkerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SlabShrinkerManager {
    /// Create a new shrinker manager.
    pub const fn new() -> Self {
        Self {
            list: ShrinkerList::new(),
            next_id: 1,
            stats: ShrinkStats {
                total_scans: 0,
                total_freed: 0,
                total_deferred: 0,
                registrations: 0,
                unregistrations: 0,
                drain_calls: 0,
            },
        }
    }

    /// Register a new shrinker. Returns the assigned ID.
    pub fn register(&mut self, name: &[u8], seeks: u64, initial_count: u64) -> Result<u32> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.list.register(id, name, seeks, initial_count)?;
        self.stats.registrations += 1;
        Ok(id)
    }

    /// Unregister a shrinker by ID.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        self.list.unregister(id)?;
        self.stats.unregistrations += 1;
        Ok(())
    }

    /// Number of registered shrinkers.
    pub const fn shrinker_count(&self) -> usize {
        self.list.count()
    }

    /// Current statistics.
    pub const fn stats(&self) -> &ShrinkStats {
        &self.stats
    }

    /// Traverse all shrinkers and invoke scan with the given
    /// control. Returns total objects freed.
    pub fn shrink_slab(&mut self, ctrl: &ShrinkControl) -> u64 {
        let mut total_freed = 0u64;
        let scan_per = if ctrl.nr_to_scan > 0 {
            ctrl.nr_to_scan.min(MAX_SCAN_BATCH)
        } else {
            MAX_SCAN_BATCH
        };

        for entry in &mut self.list.entries {
            if !entry.active {
                continue;
            }
            if entry.count() == 0 {
                continue;
            }

            let mut sub_ctrl = *ctrl;
            sub_ctrl.nr_to_scan = scan_per;

            let result = entry.scan(&sub_ctrl);
            total_freed += result.freed;
            self.stats.total_scans += 1;
        }

        self.stats.total_freed += total_freed;
        total_freed
    }

    /// Scan a specific shrinker by ID.
    pub fn shrink_one(&mut self, id: u32, ctrl: &ShrinkControl) -> Result<ShrinkResult> {
        let entry = self
            .list
            .entries
            .iter_mut()
            .find(|e| e.active && e.id == id)
            .ok_or(Error::NotFound)?;

        let result = entry.scan(ctrl);
        self.stats.total_scans += 1;
        self.stats.total_freed += result.freed;
        Ok(result)
    }

    /// Add reclaimable objects to a shrinker (simulates cache
    /// growth).
    pub fn add_countable(&mut self, id: u32, count: u64) -> Result<()> {
        let entry = self
            .list
            .entries
            .iter_mut()
            .find(|e| e.active && e.id == id)
            .ok_or(Error::NotFound)?;
        entry.countable += count;
        Ok(())
    }

    /// Drain deferred work for all shrinkers, making deferred
    /// objects reclaimable again.
    pub fn drain_all_deferred(&mut self) {
        for entry in &mut self.list.entries {
            if entry.active && entry.nr_deferred > 0 {
                entry.drain_deferred();
            }
        }
        self.stats.drain_calls += 1;
    }

    /// Total deferred objects across all shrinkers.
    pub fn total_deferred(&self) -> u64 {
        self.list
            .entries
            .iter()
            .filter(|e| e.active)
            .map(|e| e.nr_deferred)
            .sum()
    }

    /// Look up a shrinker by ID (read-only).
    pub fn find_shrinker(&self, id: u32) -> Result<&ShrinkerEntry> {
        self.list.find(id).ok_or(Error::NotFound)
    }
}
