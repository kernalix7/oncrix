// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-cgroup memory statistics.
//!
//! Tracks detailed memory usage statistics for each memory cgroup (memcg).
//! This is the data behind `memory.stat` in cgroupfs. Each counter is
//! maintained per-CPU for scalability and aggregated on read.
//!
//! # Design
//!
//! ```text
//!  memory.stat (cgroupfs)
//!       │
//!       ▼
//!  MemcgStat::read_stat(cgroup_id)
//!       │
//!       ├─ aggregate per-cpu counters
//!       └─ return MemcgStatSnapshot
//! ```
//!
//! # Key Types
//!
//! - [`MemcgCounter`] — names for tracked statistics
//! - [`MemcgStatEntry`] — a single cgroup's statistics
//! - [`MemcgStatTable`] — all cgroup statistics
//! - [`MemcgStatSnapshot`] — a point-in-time snapshot
//!
//! Reference: Linux `mm/memcontrol.c`, `include/linux/memcontrol.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum cgroups tracked.
const MAX_CGROUPS: usize = 256;

/// Number of stat counters per cgroup.
const NUM_COUNTERS: usize = 16;

// -------------------------------------------------------------------
// MemcgCounter
// -------------------------------------------------------------------

/// Identifiers for memory cgroup statistics counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum MemcgCounter {
    /// Pages in anonymous mappings.
    AnonPages = 0,
    /// Pages in file-backed mappings.
    FilePages = 1,
    /// Pages in kernel slab caches.
    SlabPages = 2,
    /// Pages on the active LRU list.
    ActiveAnon = 3,
    /// Pages on the inactive LRU list.
    InactiveAnon = 4,
    /// Active file pages.
    ActiveFile = 5,
    /// Inactive file pages.
    InactiveFile = 6,
    /// Unevictable pages.
    Unevictable = 7,
    /// Pages swapped out.
    SwapUsage = 8,
    /// Dirty pages.
    Dirty = 9,
    /// Pages under writeback.
    Writeback = 10,
    /// Page cache pages.
    PageCache = 11,
    /// Kernel stack pages.
    KernelStack = 12,
    /// Pages charged for page tables.
    PageTables = 13,
    /// Shared memory pages.
    Shmem = 14,
    /// Huge pages.
    HugePages = 15,
}

impl MemcgCounter {
    /// Return the counter name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AnonPages => "anon",
            Self::FilePages => "file",
            Self::SlabPages => "slab",
            Self::ActiveAnon => "active_anon",
            Self::InactiveAnon => "inactive_anon",
            Self::ActiveFile => "active_file",
            Self::InactiveFile => "inactive_file",
            Self::Unevictable => "unevictable",
            Self::SwapUsage => "swap",
            Self::Dirty => "dirty",
            Self::Writeback => "writeback",
            Self::PageCache => "pgcache",
            Self::KernelStack => "kernel_stack",
            Self::PageTables => "pgalloc",
            Self::Shmem => "shmem",
            Self::HugePages => "thp",
        }
    }

    /// Return the index.
    pub const fn index(&self) -> usize {
        *self as usize
    }
}

// -------------------------------------------------------------------
// MemcgStatEntry
// -------------------------------------------------------------------

/// Statistics for a single memory cgroup.
#[derive(Debug, Clone, Copy)]
pub struct MemcgStatEntry {
    /// Cgroup identifier.
    cgroup_id: u32,
    /// Counter values (in pages).
    counters: [u64; NUM_COUNTERS],
    /// Whether this entry is active.
    active: bool,
    /// Memory limit for this cgroup (pages).
    memory_limit: u64,
    /// Swap limit for this cgroup (pages).
    swap_limit: u64,
}

impl MemcgStatEntry {
    /// Create a new statistics entry.
    pub const fn new(cgroup_id: u32) -> Self {
        Self {
            cgroup_id,
            counters: [0u64; NUM_COUNTERS],
            active: true,
            memory_limit: u64::MAX,
            swap_limit: u64::MAX,
        }
    }

    /// Return the cgroup ID.
    pub const fn cgroup_id(&self) -> u32 {
        self.cgroup_id
    }

    /// Return whether this entry is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Read a counter value.
    pub fn read_counter(&self, counter: MemcgCounter) -> u64 {
        self.counters[counter.index()]
    }

    /// Increment a counter.
    pub fn inc_counter(&mut self, counter: MemcgCounter, delta: u64) {
        self.counters[counter.index()] = self.counters[counter.index()].saturating_add(delta);
    }

    /// Decrement a counter.
    pub fn dec_counter(&mut self, counter: MemcgCounter, delta: u64) {
        self.counters[counter.index()] = self.counters[counter.index()].saturating_sub(delta);
    }

    /// Set the memory limit.
    pub fn set_memory_limit(&mut self, limit: u64) {
        self.memory_limit = limit;
    }

    /// Set the swap limit.
    pub fn set_swap_limit(&mut self, limit: u64) {
        self.swap_limit = limit;
    }

    /// Return total memory usage (anon + file + slab).
    pub fn total_usage(&self) -> u64 {
        self.counters[MemcgCounter::AnonPages.index()]
            + self.counters[MemcgCounter::FilePages.index()]
            + self.counters[MemcgCounter::SlabPages.index()]
    }

    /// Check whether the memory limit is exceeded.
    pub fn is_over_limit(&self) -> bool {
        self.total_usage() > self.memory_limit
    }

    /// Return headroom (pages remaining before limit).
    pub fn headroom(&self) -> u64 {
        let usage = self.total_usage();
        if usage >= self.memory_limit {
            0
        } else {
            self.memory_limit - usage
        }
    }

    /// Deactivate this entry.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl Default for MemcgStatEntry {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// MemcgStatSnapshot
// -------------------------------------------------------------------

/// A point-in-time snapshot of cgroup memory stats.
#[derive(Debug, Clone, Copy)]
pub struct MemcgStatSnapshot {
    /// Cgroup identifier.
    pub cgroup_id: u32,
    /// Total memory usage (pages).
    pub total_usage: u64,
    /// Anonymous pages.
    pub anon_pages: u64,
    /// File pages.
    pub file_pages: u64,
    /// Slab pages.
    pub slab_pages: u64,
    /// Swap usage (pages).
    pub swap_usage: u64,
    /// Memory limit.
    pub memory_limit: u64,
    /// Headroom.
    pub headroom: u64,
}

// -------------------------------------------------------------------
// MemcgStatTable
// -------------------------------------------------------------------

/// Table of all cgroup statistics.
pub struct MemcgStatTable {
    /// Per-cgroup entries.
    entries: [MemcgStatEntry; MAX_CGROUPS],
    /// Number of registered cgroups.
    count: usize,
}

impl MemcgStatTable {
    /// Create a new empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { MemcgStatEntry::new(0) }; MAX_CGROUPS],
            count: 0,
        }
    }

    /// Register a new cgroup.
    pub fn register(&mut self, cgroup_id: u32) -> Result<()> {
        if self.count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate.
        for idx in 0..self.count {
            if self.entries[idx].cgroup_id() == cgroup_id && self.entries[idx].is_active() {
                return Err(Error::AlreadyExists);
            }
        }
        self.entries[self.count] = MemcgStatEntry::new(cgroup_id);
        self.count += 1;
        Ok(())
    }

    /// Unregister a cgroup.
    pub fn unregister(&mut self, cgroup_id: u32) -> Result<()> {
        for idx in 0..self.count {
            if self.entries[idx].cgroup_id() == cgroup_id && self.entries[idx].is_active() {
                self.entries[idx].deactivate();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find a cgroup entry by ID (mutable).
    pub fn find_mut(&mut self, cgroup_id: u32) -> Option<&mut MemcgStatEntry> {
        for idx in 0..self.count {
            if self.entries[idx].cgroup_id() == cgroup_id && self.entries[idx].is_active() {
                return Some(&mut self.entries[idx]);
            }
        }
        None
    }

    /// Take a snapshot of a cgroup's stats.
    pub fn snapshot(&self, cgroup_id: u32) -> Result<MemcgStatSnapshot> {
        for idx in 0..self.count {
            let e = &self.entries[idx];
            if e.cgroup_id() == cgroup_id && e.is_active() {
                return Ok(MemcgStatSnapshot {
                    cgroup_id,
                    total_usage: e.total_usage(),
                    anon_pages: e.read_counter(MemcgCounter::AnonPages),
                    file_pages: e.read_counter(MemcgCounter::FilePages),
                    slab_pages: e.read_counter(MemcgCounter::SlabPages),
                    swap_usage: e.read_counter(MemcgCounter::SwapUsage),
                    memory_limit: e.memory_limit,
                    headroom: e.headroom(),
                });
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of active cgroups.
    pub fn active_count(&self) -> usize {
        let mut count = 0;
        for idx in 0..self.count {
            if self.entries[idx].is_active() {
                count += 1;
            }
        }
        count
    }
}

impl Default for MemcgStatTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Charge anonymous pages to a cgroup.
pub fn charge_anon(table: &mut MemcgStatTable, cgroup_id: u32, pages: u64) -> Result<()> {
    let entry = table.find_mut(cgroup_id).ok_or(Error::NotFound)?;
    entry.inc_counter(MemcgCounter::AnonPages, pages);
    Ok(())
}

/// Uncharge anonymous pages from a cgroup.
pub fn uncharge_anon(table: &mut MemcgStatTable, cgroup_id: u32, pages: u64) -> Result<()> {
    let entry = table.find_mut(cgroup_id).ok_or(Error::NotFound)?;
    entry.dec_counter(MemcgCounter::AnonPages, pages);
    Ok(())
}

/// Check whether a cgroup is over its memory limit.
pub fn is_over_limit(table: &MemcgStatTable, cgroup_id: u32) -> Result<bool> {
    let snap = table.snapshot(cgroup_id)?;
    Ok(snap.total_usage > snap.memory_limit)
}
