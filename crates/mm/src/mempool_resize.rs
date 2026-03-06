// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Mempool resize operations.
//!
//! A mempool is a pool of pre-allocated objects that guarantees
//! allocation will not fail under memory pressure. This module
//! handles dynamic resizing: growing the pool when demand increases
//! and shrinking when memory is reclaimed, while maintaining the
//! minimum-elements guarantee.
//!
//! # Design
//!
//! ```text
//!  mempool_resize(pool, new_min)
//!     │
//!     ├─ if new_min > current_min:
//!     │   ├─ pre-allocate (new_min - current_min) objects
//!     │   └─ update min_nr
//!     └─ if new_min < current_min:
//!         ├─ free excess objects
//!         └─ update min_nr
//! ```
//!
//! # Key Types
//!
//! - [`MempoolEntry`] — a single pool entry
//! - [`ResizableMempool`] — a dynamically resizable mempool
//! - [`MempoolResizeStats`] — resize statistics
//!
//! Reference: Linux `mm/mempool.c`, `include/linux/mempool.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pool entries.
const MAX_POOL_ENTRIES: usize = 4096;

/// Default minimum elements.
const DEFAULT_MIN_ELEMENTS: usize = 16;

/// Maximum minimum elements.
const MAX_MIN_ELEMENTS: usize = 2048;

// -------------------------------------------------------------------
// MempoolEntry
// -------------------------------------------------------------------

/// A single pool entry.
#[derive(Debug, Clone, Copy)]
pub struct MempoolEntry {
    /// Object identifier.
    object_id: u64,
    /// Object size in bytes.
    size: u32,
    /// Whether this entry is allocated (in use by caller).
    in_use: bool,
    /// Allocation timestamp.
    alloc_timestamp: u64,
}

impl MempoolEntry {
    /// Create a free entry.
    pub const fn new(object_id: u64, size: u32) -> Self {
        Self {
            object_id,
            size,
            in_use: false,
            alloc_timestamp: 0,
        }
    }

    /// Return the object ID.
    pub const fn object_id(&self) -> u64 {
        self.object_id
    }

    /// Return the size.
    pub const fn size(&self) -> u32 {
        self.size
    }

    /// Check whether the entry is in use.
    pub const fn in_use(&self) -> bool {
        self.in_use
    }

    /// Allocate this entry.
    pub fn allocate(&mut self, timestamp: u64) {
        self.in_use = true;
        self.alloc_timestamp = timestamp;
    }

    /// Free this entry.
    pub fn release(&mut self) {
        self.in_use = false;
        self.alloc_timestamp = 0;
    }
}

impl Default for MempoolEntry {
    fn default() -> Self {
        Self {
            object_id: 0,
            size: 0,
            in_use: false,
            alloc_timestamp: 0,
        }
    }
}

// -------------------------------------------------------------------
// MempoolResizeStats
// -------------------------------------------------------------------

/// Resize statistics.
#[derive(Debug, Clone, Copy)]
pub struct MempoolResizeStats {
    /// Total resize operations.
    pub total_resizes: u64,
    /// Grow operations.
    pub grows: u64,
    /// Shrink operations.
    pub shrinks: u64,
    /// Total allocations.
    pub total_allocs: u64,
    /// Total frees.
    pub total_frees: u64,
    /// Allocation failures (pool exhausted).
    pub alloc_failures: u64,
}

impl MempoolResizeStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_resizes: 0,
            grows: 0,
            shrinks: 0,
            total_allocs: 0,
            total_frees: 0,
            alloc_failures: 0,
        }
    }

    /// Utilization: allocs / (allocs + failures).
    pub const fn success_rate_pct(&self) -> u64 {
        let total = self.total_allocs + self.alloc_failures;
        if total == 0 {
            return 100;
        }
        self.total_allocs * 100 / total
    }
}

impl Default for MempoolResizeStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ResizableMempool
// -------------------------------------------------------------------

/// A dynamically resizable mempool.
pub struct ResizableMempool {
    /// Pool entries.
    entries: [MempoolEntry; MAX_POOL_ENTRIES],
    /// Total entries in pool.
    total: usize,
    /// Minimum elements guarantee.
    min_elements: usize,
    /// Object size.
    object_size: u32,
    /// Next object ID.
    next_id: u64,
    /// Statistics.
    stats: MempoolResizeStats,
}

impl ResizableMempool {
    /// Create a new resizable mempool.
    pub const fn new(object_size: u32) -> Self {
        Self {
            entries: [const {
                MempoolEntry {
                    object_id: 0,
                    size: 0,
                    in_use: false,
                    alloc_timestamp: 0,
                }
            }; MAX_POOL_ENTRIES],
            total: 0,
            min_elements: DEFAULT_MIN_ELEMENTS,
            object_size,
            next_id: 1,
            stats: MempoolResizeStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &MempoolResizeStats {
        &self.stats
    }

    /// Return the total entries.
    pub const fn total(&self) -> usize {
        self.total
    }

    /// Return the minimum elements.
    pub const fn min_elements(&self) -> usize {
        self.min_elements
    }

    /// Return the object size.
    pub const fn object_size(&self) -> u32 {
        self.object_size
    }

    /// Initialize the pool with min_elements entries.
    pub fn init(&mut self, min_elements: usize) -> Result<()> {
        if min_elements > MAX_MIN_ELEMENTS {
            return Err(Error::InvalidArgument);
        }
        self.min_elements = min_elements;
        for _i in 0..min_elements {
            self.add_entry()?;
        }
        Ok(())
    }

    /// Add an entry to the pool.
    fn add_entry(&mut self) -> Result<()> {
        if self.total >= MAX_POOL_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let oid = self.next_id;
        self.entries[self.total] = MempoolEntry::new(oid, self.object_size);
        self.total += 1;
        self.next_id += 1;
        Ok(())
    }

    /// Resize the pool.
    pub fn resize(&mut self, new_min: usize) -> Result<()> {
        if new_min > MAX_MIN_ELEMENTS {
            return Err(Error::InvalidArgument);
        }
        self.stats.total_resizes += 1;

        if new_min > self.min_elements {
            // Grow.
            let need = new_min.saturating_sub(self.total);
            for _i in 0..need {
                self.add_entry()?;
            }
            self.stats.grows += 1;
        } else if new_min < self.min_elements {
            // Shrink: free excess entries that are not in use.
            let mut freed = 0;
            let target = self.total.saturating_sub(self.min_elements - new_min);
            while self.total > target {
                let idx = self.total - 1;
                if self.entries[idx].in_use() {
                    break;
                }
                self.total -= 1;
                freed += 1;
            }
            if freed > 0 {
                self.stats.shrinks += 1;
            }
        }
        self.min_elements = new_min;
        Ok(())
    }

    /// Allocate an object from the pool.
    pub fn alloc(&mut self, timestamp: u64) -> Result<u64> {
        for idx in 0..self.total {
            if !self.entries[idx].in_use() {
                self.entries[idx].allocate(timestamp);
                self.stats.total_allocs += 1;
                return Ok(self.entries[idx].object_id());
            }
        }
        self.stats.alloc_failures += 1;
        Err(Error::OutOfMemory)
    }

    /// Free an object back to the pool.
    pub fn free(&mut self, object_id: u64) -> Result<()> {
        for idx in 0..self.total {
            if self.entries[idx].object_id() == object_id && self.entries[idx].in_use() {
                self.entries[idx].release();
                self.stats.total_frees += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Count free entries.
    pub fn free_count(&self) -> usize {
        let mut n = 0;
        for idx in 0..self.total {
            if !self.entries[idx].in_use() {
                n += 1;
            }
        }
        n
    }

    /// Count in-use entries.
    pub fn in_use_count(&self) -> usize {
        self.total - self.free_count()
    }
}

impl Default for ResizableMempool {
    fn default() -> Self {
        Self::new(64)
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum pool entries.
pub const fn max_pool_entries() -> usize {
    MAX_POOL_ENTRIES
}

/// Return the default minimum elements.
pub const fn default_min_elements() -> usize {
    DEFAULT_MIN_ELEMENTS
}
