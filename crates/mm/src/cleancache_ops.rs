// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cleancache backend operations.
//!
//! Cleancache provides a kernel interface for storing clean (unmodified)
//! filesystem pages in a transcendent memory backend (e.g., tmem,
//! Xen). When a clean page is evicted from the page cache, it can
//! be pushed to cleancache; if the page is needed again, it can be
//! fetched without a disk read.
//!
//! # Design
//!
//! ```text
//!  evict_clean_page(page)
//!     │
//!     └─ cleancache_put(pool, inode, index, page)
//!         └─ backend stores page data
//!
//!  page_cache_miss(inode, index)
//!     │
//!     └─ cleancache_get(pool, inode, index, page)
//!         ├─ hit → page filled, skip disk I/O
//!         └─ miss → fall through to disk read
//! ```
//!
//! # Key Types
//!
//! - [`CleancachePool`] — a cleancache pool for a filesystem
//! - [`CleancacheEntry`] — a single cached page
//! - [`CleancacheBackend`] — manages all pools
//! - [`CleancacheOpsStats`] — backend statistics
//!
//! Reference: Linux `mm/cleancache.c`, `include/linux/cleancache.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pools (filesystems).
const MAX_POOLS: usize = 32;

/// Maximum entries per pool.
const MAX_ENTRIES_PER_POOL: usize = 4096;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// CleancacheEntry
// -------------------------------------------------------------------

/// A single cached page in cleancache.
#[derive(Debug, Clone, Copy)]
pub struct CleancacheEntry {
    /// Inode number.
    inode: u64,
    /// Page index within file.
    page_index: u64,
    /// Whether the entry is valid.
    valid: bool,
    /// Timestamp of put.
    timestamp: u64,
    /// Number of get hits.
    hit_count: u32,
}

impl CleancacheEntry {
    /// Create a new entry.
    pub const fn new(inode: u64, page_index: u64, timestamp: u64) -> Self {
        Self {
            inode,
            page_index,
            valid: true,
            timestamp,
            hit_count: 0,
        }
    }

    /// Return the inode.
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Return the page index.
    pub const fn page_index(&self) -> u64 {
        self.page_index
    }

    /// Check whether valid.
    pub const fn valid(&self) -> bool {
        self.valid
    }

    /// Return the hit count.
    pub const fn hit_count(&self) -> u32 {
        self.hit_count
    }

    /// Invalidate.
    pub fn invalidate(&mut self) {
        self.valid = false;
    }

    /// Record a hit.
    pub fn record_hit(&mut self) {
        self.hit_count = self.hit_count.saturating_add(1);
    }

    /// Check whether this matches the given inode/index.
    pub const fn matches(&self, inode: u64, page_index: u64) -> bool {
        self.valid && self.inode == inode && self.page_index == page_index
    }
}

impl Default for CleancacheEntry {
    fn default() -> Self {
        Self {
            inode: 0,
            page_index: 0,
            valid: false,
            timestamp: 0,
            hit_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// CleancachePool
// -------------------------------------------------------------------

/// A cleancache pool for a filesystem.
#[derive(Debug, Clone, Copy)]
pub struct CleancachePool {
    /// Pool ID.
    pool_id: u32,
    /// Filesystem type label index.
    fs_type: u32,
    /// Number of entries.
    entry_count: u32,
    /// Whether the pool is active.
    active: bool,
}

impl CleancachePool {
    /// Create a new pool.
    pub const fn new(pool_id: u32, fs_type: u32) -> Self {
        Self {
            pool_id,
            fs_type,
            entry_count: 0,
            active: true,
        }
    }

    /// Return the pool ID.
    pub const fn pool_id(&self) -> u32 {
        self.pool_id
    }

    /// Return the fs type.
    pub const fn fs_type(&self) -> u32 {
        self.fs_type
    }

    /// Return the entry count.
    pub const fn entry_count(&self) -> u32 {
        self.entry_count
    }

    /// Check whether active.
    pub const fn active(&self) -> bool {
        self.active
    }

    /// Deactivate.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl Default for CleancachePool {
    fn default() -> Self {
        Self {
            pool_id: 0,
            fs_type: 0,
            entry_count: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// CleancacheOpsStats
// -------------------------------------------------------------------

/// Backend statistics.
#[derive(Debug, Clone, Copy)]
pub struct CleancacheOpsStats {
    /// Total puts.
    pub puts: u64,
    /// Total gets.
    pub gets: u64,
    /// Get hits.
    pub hits: u64,
    /// Get misses.
    pub misses: u64,
    /// Invalidations.
    pub invalidates: u64,
    /// Pages saved from disk I/O.
    pub disk_reads_saved: u64,
}

impl CleancacheOpsStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            puts: 0,
            gets: 0,
            hits: 0,
            misses: 0,
            invalidates: 0,
            disk_reads_saved: 0,
        }
    }

    /// Hit rate as percent.
    pub const fn hit_rate_pct(&self) -> u64 {
        if self.gets == 0 {
            return 0;
        }
        self.hits * 100 / self.gets
    }
}

impl Default for CleancacheOpsStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// CleancacheBackend
// -------------------------------------------------------------------

/// Manages all cleancache pools.
pub struct CleancacheBackend {
    /// Pools.
    pools: [CleancachePool; MAX_POOLS],
    /// Pool entries (flat array: pool_id * MAX_ENTRIES_PER_POOL + idx).
    entries: [CleancacheEntry; 1024],
    /// Number of pools.
    pool_count: usize,
    /// Total entries.
    entry_count: usize,
    /// Next pool ID.
    next_pool_id: u32,
    /// Statistics.
    stats: CleancacheOpsStats,
}

impl CleancacheBackend {
    /// Create a new backend.
    pub const fn new() -> Self {
        Self {
            pools: [const {
                CleancachePool {
                    pool_id: 0,
                    fs_type: 0,
                    entry_count: 0,
                    active: false,
                }
            }; MAX_POOLS],
            entries: [const {
                CleancacheEntry {
                    inode: 0,
                    page_index: 0,
                    valid: false,
                    timestamp: 0,
                    hit_count: 0,
                }
            }; 1024],
            pool_count: 0,
            entry_count: 0,
            next_pool_id: 1,
            stats: CleancacheOpsStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &CleancacheOpsStats {
        &self.stats
    }

    /// Return the pool count.
    pub const fn pool_count(&self) -> usize {
        self.pool_count
    }

    /// Register a pool.
    pub fn register_pool(&mut self, fs_type: u32) -> Result<u32> {
        if self.pool_count >= MAX_POOLS {
            return Err(Error::OutOfMemory);
        }
        let pid = self.next_pool_id;
        self.pools[self.pool_count] = CleancachePool::new(pid, fs_type);
        self.pool_count += 1;
        self.next_pool_id += 1;
        Ok(pid)
    }

    /// Put a page into cleancache.
    pub fn put(&mut self, inode: u64, page_index: u64, timestamp: u64) -> Result<()> {
        if self.entry_count >= 1024 {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.entry_count] = CleancacheEntry::new(inode, page_index, timestamp);
        self.entry_count += 1;
        self.stats.puts += 1;
        Ok(())
    }

    /// Get a page from cleancache.
    pub fn get(&mut self, inode: u64, page_index: u64) -> Result<bool> {
        self.stats.gets += 1;
        for idx in 0..self.entry_count {
            if self.entries[idx].matches(inode, page_index) {
                self.entries[idx].record_hit();
                self.stats.hits += 1;
                self.stats.disk_reads_saved += 1;
                return Ok(true);
            }
        }
        self.stats.misses += 1;
        Ok(false)
    }

    /// Invalidate an entry.
    pub fn invalidate(&mut self, inode: u64, page_index: u64) -> Result<()> {
        for idx in 0..self.entry_count {
            if self.entries[idx].matches(inode, page_index) {
                self.entries[idx].invalidate();
                self.stats.invalidates += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Bytes saved from disk I/O.
    pub const fn bytes_saved(&self) -> u64 {
        self.stats.disk_reads_saved * PAGE_SIZE
    }
}

impl Default for CleancacheBackend {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum pools.
pub const fn max_pools() -> usize {
    MAX_POOLS
}

/// Return the maximum entries per pool.
pub const fn max_entries_per_pool() -> usize {
    MAX_ENTRIES_PER_POOL
}
