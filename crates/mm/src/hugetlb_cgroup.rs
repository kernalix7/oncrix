// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! HugeTLB cgroup accounting.
//!
//! Tracks and limits huge page usage per memory cgroup. Supports both
//! 2 MiB and 1 GiB huge pages. Each cgroup can have independent limits
//! for each page size, and charges propagate up the hierarchy.
//!
//! # Design
//!
//! ```text
//!  Process requests huge page
//!       │
//!       ▼
//!  HugetlbCgroup::try_charge(cgroup, size, count)
//!       │
//!       ├─ within limit? → charge + allocate
//!       └─ over limit?   → deny (ENOMEM)
//! ```
//!
//! # Key Types
//!
//! - [`HugePageSize`] — supported huge page sizes
//! - [`HugetlbUsage`] — per-size usage tracking
//! - [`HugetlbCgroup`] — per-cgroup hugetlb accounting
//! - [`HugetlbCgroupTable`] — all cgroup hugetlb data
//!
//! Reference: Linux `mm/hugetlb_cgroup.c`, `include/linux/hugetlb_cgroup.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum cgroups tracked.
const MAX_CGROUPS: usize = 256;

/// Number of huge page sizes supported.
const NUM_SIZES: usize = 2;

// -------------------------------------------------------------------
// HugePageSize
// -------------------------------------------------------------------

/// Supported huge page sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HugePageSize {
    /// 2 MiB huge pages.
    Size2M,
    /// 1 GiB huge pages.
    Size1G,
}

impl HugePageSize {
    /// Return the size in bytes.
    pub const fn bytes(&self) -> u64 {
        match self {
            Self::Size2M => 2 * 1024 * 1024,
            Self::Size1G => 1024 * 1024 * 1024,
        }
    }

    /// Return the index for array storage.
    pub const fn index(&self) -> usize {
        match self {
            Self::Size2M => 0,
            Self::Size1G => 1,
        }
    }

    /// Return a human-readable name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Size2M => "hugepages-2048kB",
            Self::Size1G => "hugepages-1048576kB",
        }
    }
}

// -------------------------------------------------------------------
// HugetlbUsage
// -------------------------------------------------------------------

/// Usage tracking for a single huge page size.
#[derive(Debug, Clone, Copy)]
pub struct HugetlbUsage {
    /// Current number of huge pages in use.
    usage: u64,
    /// Maximum allowed huge pages.
    limit: u64,
    /// Peak usage.
    max_usage: u64,
    /// Number of allocation failures due to limit.
    failcnt: u64,
    /// Reserved pages (allocated but not yet faulted).
    reserved: u64,
}

impl HugetlbUsage {
    /// Create a new usage tracker with the given limit.
    pub const fn new(limit: u64) -> Self {
        Self {
            usage: 0,
            limit,
            max_usage: 0,
            failcnt: 0,
            reserved: 0,
        }
    }

    /// Create an unlimited tracker.
    pub const fn unlimited() -> Self {
        Self::new(u64::MAX)
    }

    /// Return current usage.
    pub const fn usage(&self) -> u64 {
        self.usage
    }

    /// Return the limit.
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    /// Return peak usage.
    pub const fn max_usage(&self) -> u64 {
        self.max_usage
    }

    /// Return failure count.
    pub const fn failcnt(&self) -> u64 {
        self.failcnt
    }

    /// Return reserved pages.
    pub const fn reserved(&self) -> u64 {
        self.reserved
    }

    /// Set a new limit.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Try to charge `count` huge pages.
    pub fn try_charge(&mut self, count: u64) -> Result<()> {
        let new_usage = self.usage.saturating_add(count);
        if new_usage > self.limit {
            self.failcnt += 1;
            return Err(Error::OutOfMemory);
        }
        self.usage = new_usage;
        if self.usage > self.max_usage {
            self.max_usage = self.usage;
        }
        Ok(())
    }

    /// Uncharge `count` huge pages.
    pub fn uncharge(&mut self, count: u64) {
        self.usage = self.usage.saturating_sub(count);
    }

    /// Reserve `count` huge pages.
    pub fn reserve(&mut self, count: u64) -> Result<()> {
        let total = self
            .usage
            .saturating_add(self.reserved)
            .saturating_add(count);
        if total > self.limit {
            return Err(Error::OutOfMemory);
        }
        self.reserved += count;
        Ok(())
    }

    /// Unreserve `count` huge pages.
    pub fn unreserve(&mut self, count: u64) {
        self.reserved = self.reserved.saturating_sub(count);
    }

    /// Return headroom.
    pub const fn headroom(&self) -> u64 {
        let committed = self.usage + self.reserved;
        if committed >= self.limit {
            0
        } else {
            self.limit - committed
        }
    }

    /// Reset peak usage.
    pub fn reset_max(&mut self) {
        self.max_usage = self.usage;
    }
}

impl Default for HugetlbUsage {
    fn default() -> Self {
        Self::unlimited()
    }
}

// -------------------------------------------------------------------
// HugetlbCgroup
// -------------------------------------------------------------------

/// Per-cgroup hugetlb accounting.
#[derive(Debug, Clone, Copy)]
pub struct HugetlbCgroup {
    /// Cgroup identifier.
    cgroup_id: u32,
    /// Per-size usage tracking.
    usage: [HugetlbUsage; NUM_SIZES],
    /// Whether this entry is active.
    active: bool,
}

impl HugetlbCgroup {
    /// Create a new entry.
    pub const fn new(cgroup_id: u32) -> Self {
        Self {
            cgroup_id,
            usage: [const { HugetlbUsage::unlimited() }; NUM_SIZES],
            active: true,
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

    /// Get usage for a page size.
    pub fn get_usage(&self, size: HugePageSize) -> &HugetlbUsage {
        &self.usage[size.index()]
    }

    /// Get mutable usage for a page size.
    pub fn get_usage_mut(&mut self, size: HugePageSize) -> &mut HugetlbUsage {
        &mut self.usage[size.index()]
    }

    /// Try to charge huge pages of the given size.
    pub fn try_charge(&mut self, size: HugePageSize, count: u64) -> Result<()> {
        self.usage[size.index()].try_charge(count)
    }

    /// Uncharge huge pages.
    pub fn uncharge(&mut self, size: HugePageSize, count: u64) {
        self.usage[size.index()].uncharge(count);
    }

    /// Set limit for a page size.
    pub fn set_limit(&mut self, size: HugePageSize, limit: u64) {
        self.usage[size.index()].set_limit(limit);
    }

    /// Deactivate this entry.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl Default for HugetlbCgroup {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// HugetlbCgroupTable
// -------------------------------------------------------------------

/// Table of all cgroup hugetlb accounting data.
pub struct HugetlbCgroupTable {
    /// Per-cgroup entries.
    entries: [HugetlbCgroup; MAX_CGROUPS],
    /// Number of registered entries.
    count: usize,
}

impl HugetlbCgroupTable {
    /// Create a new empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { HugetlbCgroup::new(0) }; MAX_CGROUPS],
            count: 0,
        }
    }

    /// Register a cgroup.
    pub fn register(&mut self, cgroup_id: u32) -> Result<()> {
        if self.count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = HugetlbCgroup::new(cgroup_id);
        self.count += 1;
        Ok(())
    }

    /// Find a cgroup entry (mutable).
    pub fn find_mut(&mut self, cgroup_id: u32) -> Option<&mut HugetlbCgroup> {
        for idx in 0..self.count {
            if self.entries[idx].cgroup_id() == cgroup_id && self.entries[idx].is_active() {
                return Some(&mut self.entries[idx]);
            }
        }
        None
    }

    /// Return the number of registered cgroups.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for HugetlbCgroupTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Charge 2M huge pages to a cgroup.
pub fn charge_2m(table: &mut HugetlbCgroupTable, cgroup_id: u32, count: u64) -> Result<()> {
    let entry = table.find_mut(cgroup_id).ok_or(Error::NotFound)?;
    entry.try_charge(HugePageSize::Size2M, count)
}

/// Charge 1G huge pages to a cgroup.
pub fn charge_1g(table: &mut HugetlbCgroupTable, cgroup_id: u32, count: u64) -> Result<()> {
    let entry = table.find_mut(cgroup_id).ok_or(Error::NotFound)?;
    entry.try_charge(HugePageSize::Size1G, count)
}

/// Return total huge page usage (in bytes) for a cgroup.
pub fn total_hugetlb_bytes(table: &HugetlbCgroupTable, cgroup_id: u32) -> u64 {
    for idx in 0..table.count {
        if table.entries[idx].cgroup_id() == cgroup_id && table.entries[idx].is_active() {
            let e = &table.entries[idx];
            let usage_2m = e.get_usage(HugePageSize::Size2M).usage() * HugePageSize::Size2M.bytes();
            let usage_1g = e.get_usage(HugePageSize::Size1G).usage() * HugePageSize::Size1G.bytes();
            return usage_2m + usage_1g;
        }
    }
    0
}
