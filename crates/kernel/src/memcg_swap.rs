// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory cgroup swap accounting and control.
//!
//! Extends the memory cgroup controller with swap usage tracking
//! and per-cgroup swap limits. When a cgroup reaches its memory
//! limit, pages may be swapped out but are still charged against
//! the cgroup's swap allowance.
//!
//! # Design
//!
//! ```text
//! MemcgSwap
//!  ├── entries: [SwapCgEntry; MAX_CGROUPS]
//!  ├── global_swap_total: u64
//!  ├── global_swap_used: u64
//!  └── stats: MemcgSwapStats
//!
//! SwapCgEntry
//!  ├── cgroup_id: u64
//!  ├── swap_limit: u64 (pages)
//!  ├── swap_usage: u64 (pages)
//!  └── swap_max_usage: u64 (high watermark)
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum cgroups with swap accounting.
const MAX_CGROUPS: usize = 256;

/// Unlimited swap sentinel value.
const SWAP_UNLIMITED: u64 = u64::MAX;

// ======================================================================
// Types
// ======================================================================

/// Per-cgroup swap accounting entry.
#[derive(Debug, Clone, Copy)]
pub struct SwapCgEntry {
    /// Cgroup identifier.
    pub cgroup_id: u64,
    /// Swap limit in pages (u64::MAX = unlimited).
    pub swap_limit: u64,
    /// Current swap usage in pages.
    pub swap_usage: u64,
    /// High watermark of swap usage.
    pub swap_max_usage: u64,
    /// Number of swap-in (page fault reclaim) events.
    pub swap_in_count: u64,
    /// Number of swap-out events.
    pub swap_out_count: u64,
    /// Number of swap charge failures (limit hit).
    pub fail_count: u64,
    /// Whether this entry is active.
    pub active: bool,
}

impl SwapCgEntry {
    /// Creates an empty swap cgroup entry.
    pub const fn new() -> Self {
        Self {
            cgroup_id: 0,
            swap_limit: SWAP_UNLIMITED,
            swap_usage: 0,
            swap_max_usage: 0,
            swap_in_count: 0,
            swap_out_count: 0,
            fail_count: 0,
            active: false,
        }
    }
}

impl Default for SwapCgEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Swap charge result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapChargeResult {
    /// Charge succeeded.
    Success,
    /// Cgroup swap limit would be exceeded.
    LimitExceeded,
    /// Global swap space exhausted.
    NoSwapSpace,
}

impl Default for SwapChargeResult {
    fn default() -> Self {
        Self::Success
    }
}

/// Global swap statistics across all cgroups.
#[derive(Debug, Clone, Copy)]
pub struct MemcgSwapStats {
    /// Total swap charges.
    pub total_charges: u64,
    /// Total swap uncharges.
    pub total_uncharges: u64,
    /// Total charge failures.
    pub total_failures: u64,
    /// Total swap-in operations.
    pub total_swap_in: u64,
    /// Total swap-out operations.
    pub total_swap_out: u64,
}

impl MemcgSwapStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_charges: 0,
            total_uncharges: 0,
            total_failures: 0,
            total_swap_in: 0,
            total_swap_out: 0,
        }
    }
}

impl Default for MemcgSwapStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory cgroup swap controller.
pub struct MemcgSwap {
    /// Per-cgroup swap entries.
    entries: [SwapCgEntry; MAX_CGROUPS],
    /// Number of active entries.
    nr_active: usize,
    /// Total system swap in pages.
    global_swap_total: u64,
    /// Currently used system swap in pages.
    global_swap_used: u64,
    /// Global statistics.
    stats: MemcgSwapStats,
}

impl MemcgSwap {
    /// Creates a new memory cgroup swap controller.
    pub const fn new() -> Self {
        Self {
            entries: [SwapCgEntry::new(); MAX_CGROUPS],
            nr_active: 0,
            global_swap_total: 0,
            global_swap_used: 0,
            stats: MemcgSwapStats::new(),
        }
    }

    /// Initialises global swap capacity.
    pub fn init(&mut self, total_pages: u64) -> Result<()> {
        if total_pages == 0 {
            return Err(Error::InvalidArgument);
        }
        self.global_swap_total = total_pages;
        self.global_swap_used = 0;
        Ok(())
    }

    /// Registers a cgroup for swap accounting.
    pub fn register_cgroup(&mut self, cgroup_id: u64, swap_limit: u64) -> Result<usize> {
        if self.nr_active >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate.
        if self.find_entry(cgroup_id).is_some() {
            return Err(Error::AlreadyExists);
        }
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if !entry.active {
                *entry = SwapCgEntry {
                    cgroup_id,
                    swap_limit,
                    swap_usage: 0,
                    swap_max_usage: 0,
                    swap_in_count: 0,
                    swap_out_count: 0,
                    fail_count: 0,
                    active: true,
                };
                self.nr_active += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a cgroup from swap accounting.
    pub fn unregister_cgroup(&mut self, cgroup_id: u64) -> Result<()> {
        let idx = self.find_entry(cgroup_id).ok_or(Error::NotFound)?;
        let usage = self.entries[idx].swap_usage;
        self.global_swap_used = self.global_swap_used.saturating_sub(usage);
        self.entries[idx] = SwapCgEntry::new();
        self.nr_active = self.nr_active.saturating_sub(1);
        Ok(())
    }

    /// Charges `nr_pages` of swap to a cgroup.
    pub fn charge(&mut self, cgroup_id: u64, nr_pages: u64) -> Result<SwapChargeResult> {
        if self.global_swap_used + nr_pages > self.global_swap_total {
            self.stats.total_failures += 1;
            return Ok(SwapChargeResult::NoSwapSpace);
        }
        let idx = self.find_entry(cgroup_id).ok_or(Error::NotFound)?;
        let entry = &mut self.entries[idx];

        if entry.swap_limit != SWAP_UNLIMITED && entry.swap_usage + nr_pages > entry.swap_limit {
            entry.fail_count += 1;
            self.stats.total_failures += 1;
            return Ok(SwapChargeResult::LimitExceeded);
        }

        entry.swap_usage += nr_pages;
        if entry.swap_usage > entry.swap_max_usage {
            entry.swap_max_usage = entry.swap_usage;
        }
        entry.swap_out_count += 1;
        self.global_swap_used += nr_pages;
        self.stats.total_charges += 1;
        self.stats.total_swap_out += 1;
        Ok(SwapChargeResult::Success)
    }

    /// Uncharges `nr_pages` of swap from a cgroup (swap-in).
    pub fn uncharge(&mut self, cgroup_id: u64, nr_pages: u64) -> Result<()> {
        let idx = self.find_entry(cgroup_id).ok_or(Error::NotFound)?;
        let entry = &mut self.entries[idx];
        entry.swap_usage = entry.swap_usage.saturating_sub(nr_pages);
        entry.swap_in_count += 1;
        self.global_swap_used = self.global_swap_used.saturating_sub(nr_pages);
        self.stats.total_uncharges += 1;
        self.stats.total_swap_in += 1;
        Ok(())
    }

    /// Sets the swap limit for a cgroup.
    pub fn set_limit(&mut self, cgroup_id: u64, limit: u64) -> Result<()> {
        let idx = self.find_entry(cgroup_id).ok_or(Error::NotFound)?;
        self.entries[idx].swap_limit = limit;
        Ok(())
    }

    /// Returns swap usage for a cgroup.
    pub fn usage(&self, cgroup_id: u64) -> Result<u64> {
        let idx = self.find_entry(cgroup_id).ok_or(Error::NotFound)?;
        Ok(self.entries[idx].swap_usage)
    }

    /// Returns global statistics.
    pub fn stats(&self) -> &MemcgSwapStats {
        &self.stats
    }

    /// Returns total global swap used.
    pub fn global_swap_used(&self) -> u64 {
        self.global_swap_used
    }

    /// Returns total global swap capacity.
    pub fn global_swap_total(&self) -> u64 {
        self.global_swap_total
    }

    /// Number of active cgroup entries.
    pub fn nr_active(&self) -> usize {
        self.nr_active
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn find_entry(&self, cgroup_id: u64) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.active && e.cgroup_id == cgroup_id)
    }
}

impl Default for MemcgSwap {
    fn default() -> Self {
        Self::new()
    }
}
