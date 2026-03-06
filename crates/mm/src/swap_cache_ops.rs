// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Swap cache operations.
//!
//! Manages the swap cache — an in-memory cache of pages that have
//! been written to swap but are still resident. Prevents redundant
//! swap reads for recently swapped-out pages and supports
//! add/delete/lookup operations on swap cache entries.
//!
//! - [`SwapCacheEntry`] — a cached swap page
//! - [`SwapCacheStats`] — cache statistics
//! - [`SwapCacheOps`] — the swap cache manager
//!
//! Reference: Linux `mm/swap_state.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum swap cache entries.
const MAX_ENTRIES: usize = 512;

// -------------------------------------------------------------------
// SwapCacheEntry
// -------------------------------------------------------------------

/// A cached swap page.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapCacheEntry {
    /// Swap entry value (type + offset).
    pub swap_entry: u64,
    /// Page frame number of the cached page.
    pub pfn: u64,
    /// Reference count.
    pub refcount: u32,
    /// Whether the page is dirty (modified since swap-in).
    pub dirty: bool,
    /// Whether this entry is active.
    pub active: bool,
}

impl SwapCacheEntry {
    /// Creates a new swap cache entry.
    pub fn new(swap_entry: u64, pfn: u64) -> Self {
        Self {
            swap_entry,
            pfn,
            refcount: 1,
            dirty: false,
            active: true,
        }
    }

    /// Increments the reference count.
    pub fn get(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    /// Decrements the reference count. Returns `true` if zero.
    pub fn put(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount == 0
    }
}

// -------------------------------------------------------------------
// SwapCacheStats
// -------------------------------------------------------------------

/// Swap cache statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapCacheStats {
    /// Total pages added to cache.
    pub adds: u64,
    /// Total pages removed from cache.
    pub deletes: u64,
    /// Cache lookup hits.
    pub hits: u64,
    /// Cache lookup misses.
    pub misses: u64,
    /// Current cached pages.
    pub cached_pages: u64,
    /// Dirty pages in cache.
    pub dirty_pages: u64,
}

impl SwapCacheStats {
    /// Returns the hit ratio (per-mille).
    pub fn hit_ratio(&self) -> u32 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0;
        }
        ((self.hits * 1000) / total) as u32
    }

    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// SwapCacheOps
// -------------------------------------------------------------------

/// The swap cache manager.
pub struct SwapCacheOps {
    /// Cache entries.
    entries: [SwapCacheEntry; MAX_ENTRIES],
    /// Number of entries.
    count: usize,
    /// Statistics.
    stats: SwapCacheStats,
}

impl Default for SwapCacheOps {
    fn default() -> Self {
        Self {
            entries: [SwapCacheEntry::default(); MAX_ENTRIES],
            count: 0,
            stats: SwapCacheStats::default(),
        }
    }
}

impl SwapCacheOps {
    /// Creates a new swap cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a page to the swap cache.
    pub fn add(&mut self, swap_entry: u64, pfn: u64) -> Result<usize> {
        // Check for duplicate.
        for i in 0..self.count {
            if self.entries[i].active && self.entries[i].swap_entry == swap_entry {
                return Err(Error::AlreadyExists);
            }
        }

        if self.count >= MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.entries[idx] = SwapCacheEntry::new(swap_entry, pfn);
        self.count += 1;
        self.stats.adds += 1;
        self.stats.cached_pages += 1;
        Ok(idx)
    }

    /// Removes a page from the swap cache by swap entry.
    pub fn delete(&mut self, swap_entry: u64) -> Result<u64> {
        for i in 0..self.count {
            if self.entries[i].active && self.entries[i].swap_entry == swap_entry {
                let pfn = self.entries[i].pfn;
                if self.entries[i].dirty {
                    self.stats.dirty_pages = self.stats.dirty_pages.saturating_sub(1);
                }
                self.entries[i].active = false;
                self.stats.deletes += 1;
                if self.stats.cached_pages > 0 {
                    self.stats.cached_pages -= 1;
                }
                return Ok(pfn);
            }
        }
        Err(Error::NotFound)
    }

    /// Looks up a page in the swap cache.
    pub fn lookup(&mut self, swap_entry: u64) -> Option<u64> {
        for i in 0..self.count {
            if self.entries[i].active && self.entries[i].swap_entry == swap_entry {
                self.entries[i].get();
                self.stats.hits += 1;
                return Some(self.entries[i].pfn);
            }
        }
        self.stats.misses += 1;
        None
    }

    /// Marks a cached page as dirty.
    pub fn mark_dirty(&mut self, swap_entry: u64) -> Result<()> {
        for i in 0..self.count {
            if self.entries[i].active && self.entries[i].swap_entry == swap_entry {
                if !self.entries[i].dirty {
                    self.entries[i].dirty = true;
                    self.stats.dirty_pages += 1;
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of cached entries.
    pub fn cached_count(&self) -> usize {
        self.entries[..self.count]
            .iter()
            .filter(|e| e.active)
            .count()
    }

    /// Returns statistics.
    pub fn stats(&self) -> &SwapCacheStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
