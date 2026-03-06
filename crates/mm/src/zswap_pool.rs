// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! zswap pool management.
//!
//! zswap is a compressed swap cache that sits between page reclaim and
//! the swap device. Pages destined for swap are first compressed and
//! stored in a RAM pool. If the pool is full, the least recently used
//! compressed pages are evicted to the actual swap device.
//!
//! This module manages the pool itself: allocation, deallocation,
//! sizing, and eviction policy.
//!
//! # Design
//!
//! ```text
//!  reclaim → compress page → ZswapPool::store(pfn, data)
//!       │
//!       ├─ pool has space → store compressed entry
//!       └─ pool full      → evict LRU entry → store
//!
//!  page fault → ZswapPool::load(pfn) → decompress → map
//! ```
//!
//! # Key Types
//!
//! - [`ZswapEntry`] — a single compressed page in the pool
//! - [`ZswapPool`] — the compressed page pool
//! - [`ZswapPoolConfig`] — pool configuration
//! - [`ZswapPoolStats`] — pool statistics
//!
//! Reference: Linux `mm/zswap.c`, `include/linux/zswap.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum entries in the pool.
const MAX_ENTRIES: usize = 8192;

/// Maximum compressed data size per entry (bytes).
const MAX_COMPRESSED_SIZE: usize = 3072;

/// Default pool size limit (pages equivalent).
const DEFAULT_POOL_PAGES: u64 = 16384;

/// Compression ratio threshold — reject if worse than this.
const MAX_RATIO_PERCENT: u64 = 90; // 90% of original = poor

// -------------------------------------------------------------------
// ZswapEntry
// -------------------------------------------------------------------

/// A single compressed page stored in the zswap pool.
#[derive(Debug, Clone, Copy)]
pub struct ZswapEntry {
    /// Original page PFN.
    pfn: u64,
    /// Swap slot this entry is associated with.
    swap_slot: u64,
    /// Compressed size in bytes.
    compressed_size: u32,
    /// LRU sequence number (lower = older).
    lru_seq: u64,
    /// Whether this entry is valid.
    valid: bool,
}

impl ZswapEntry {
    /// Create a new entry.
    pub const fn new(pfn: u64, swap_slot: u64, compressed_size: u32, lru_seq: u64) -> Self {
        Self {
            pfn,
            swap_slot,
            compressed_size,
            lru_seq,
            valid: true,
        }
    }

    /// Return the original PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the swap slot.
    pub const fn swap_slot(&self) -> u64 {
        self.swap_slot
    }

    /// Return the compressed size.
    pub const fn compressed_size(&self) -> u32 {
        self.compressed_size
    }

    /// Return the LRU sequence number.
    pub const fn lru_seq(&self) -> u64 {
        self.lru_seq
    }

    /// Check whether this entry is valid.
    pub const fn is_valid(&self) -> bool {
        self.valid
    }

    /// Invalidate this entry.
    pub fn invalidate(&mut self) {
        self.valid = false;
    }

    /// Return the compression ratio (percent of original 4096).
    pub const fn compression_ratio(&self) -> u64 {
        (self.compressed_size as u64) * 100 / 4096
    }
}

impl Default for ZswapEntry {
    fn default() -> Self {
        Self {
            pfn: 0,
            swap_slot: 0,
            compressed_size: 0,
            lru_seq: 0,
            valid: false,
        }
    }
}

// -------------------------------------------------------------------
// ZswapPoolConfig
// -------------------------------------------------------------------

/// Configuration for the zswap pool.
#[derive(Debug, Clone, Copy)]
pub struct ZswapPoolConfig {
    /// Maximum pool size in pages-equivalent.
    pub max_pages: u64,
    /// Whether to accept poorly compressed pages.
    pub accept_poor_compression: bool,
    /// Maximum ratio percent to accept (0-100).
    pub max_ratio_pct: u64,
    /// Whether the pool is enabled.
    pub enabled: bool,
}

impl ZswapPoolConfig {
    /// Create a default configuration.
    pub const fn new() -> Self {
        Self {
            max_pages: DEFAULT_POOL_PAGES,
            accept_poor_compression: false,
            max_ratio_pct: MAX_RATIO_PERCENT,
            enabled: true,
        }
    }

    /// Create a disabled configuration.
    pub const fn disabled() -> Self {
        Self {
            max_pages: 0,
            accept_poor_compression: false,
            max_ratio_pct: 0,
            enabled: false,
        }
    }
}

impl Default for ZswapPoolConfig {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ZswapPoolStats
// -------------------------------------------------------------------

/// Statistics for the zswap pool.
#[derive(Debug, Clone, Copy)]
pub struct ZswapPoolStats {
    /// Total pages stored.
    pub stored: u64,
    /// Total pages loaded (decompressed).
    pub loaded: u64,
    /// Total pages evicted to swap.
    pub evicted: u64,
    /// Total pages rejected (poor compression).
    pub rejected: u64,
    /// Current pool size in compressed bytes.
    pub pool_bytes: u64,
    /// Total original bytes that would have been swapped.
    pub orig_bytes: u64,
}

impl ZswapPoolStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            stored: 0,
            loaded: 0,
            evicted: 0,
            rejected: 0,
            pool_bytes: 0,
            orig_bytes: 0,
        }
    }

    /// Return the overall compression ratio (percent).
    pub const fn compression_ratio(&self) -> u64 {
        if self.orig_bytes == 0 {
            return 0;
        }
        self.pool_bytes * 100 / self.orig_bytes
    }

    /// Return the cache hit rate (percent).
    pub const fn hit_rate(&self) -> u64 {
        let total = self.loaded + self.evicted;
        if total == 0 {
            return 0;
        }
        self.loaded * 100 / total
    }
}

impl Default for ZswapPoolStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ZswapPool
// -------------------------------------------------------------------

/// The compressed swap page pool.
pub struct ZswapPool {
    /// Stored entries.
    entries: [ZswapEntry; MAX_ENTRIES],
    /// Number of valid entries.
    count: usize,
    /// LRU sequence counter.
    lru_counter: u64,
    /// Configuration.
    config: ZswapPoolConfig,
    /// Statistics.
    stats: ZswapPoolStats,
}

impl ZswapPool {
    /// Create a new pool with default configuration.
    pub const fn new() -> Self {
        Self {
            entries: [const {
                ZswapEntry {
                    pfn: 0,
                    swap_slot: 0,
                    compressed_size: 0,
                    lru_seq: 0,
                    valid: false,
                }
            }; MAX_ENTRIES],
            count: 0,
            lru_counter: 0,
            config: ZswapPoolConfig::new(),
            stats: ZswapPoolStats::new(),
        }
    }

    /// Create a pool with custom configuration.
    pub fn with_config(config: ZswapPoolConfig) -> Self {
        Self {
            config,
            ..Self::new()
        }
    }

    /// Return the number of entries.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the configuration.
    pub const fn config(&self) -> &ZswapPoolConfig {
        &self.config
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &ZswapPoolStats {
        &self.stats
    }

    /// Check whether the pool is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Store a compressed page.
    pub fn store(&mut self, pfn: u64, swap_slot: u64, compressed_size: u32) -> Result<()> {
        if !self.config.enabled {
            return Err(Error::NotImplemented);
        }
        if (compressed_size as usize) > MAX_COMPRESSED_SIZE {
            return Err(Error::InvalidArgument);
        }

        // Check compression ratio.
        let ratio = (compressed_size as u64) * 100 / 4096;
        if !self.config.accept_poor_compression && ratio > self.config.max_ratio_pct {
            self.stats.rejected += 1;
            return Err(Error::InvalidArgument);
        }

        // Evict if pool is full.
        if self.count >= MAX_ENTRIES {
            self.evict_lru();
        }

        self.lru_counter += 1;
        let entry = ZswapEntry::new(pfn, swap_slot, compressed_size, self.lru_counter);

        // Find free slot.
        for idx in 0..MAX_ENTRIES {
            if !self.entries[idx].is_valid() {
                self.entries[idx] = entry;
                self.count += 1;
                self.stats.stored += 1;
                self.stats.pool_bytes += compressed_size as u64;
                self.stats.orig_bytes += 4096;
                return Ok(());
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Load (decompress) a page from the pool.
    pub fn load(&mut self, swap_slot: u64) -> Result<u64> {
        for idx in 0..MAX_ENTRIES {
            if self.entries[idx].is_valid() && self.entries[idx].swap_slot() == swap_slot {
                let pfn = self.entries[idx].pfn();
                let size = self.entries[idx].compressed_size() as u64;
                self.entries[idx].invalidate();
                self.count -= 1;
                self.stats.loaded += 1;
                self.stats.pool_bytes = self.stats.pool_bytes.saturating_sub(size);
                self.stats.orig_bytes = self.stats.orig_bytes.saturating_sub(4096);
                return Ok(pfn);
            }
        }
        Err(Error::NotFound)
    }

    /// Evict the LRU entry.
    fn evict_lru(&mut self) {
        let mut min_seq = u64::MAX;
        let mut min_idx = 0;
        for idx in 0..MAX_ENTRIES {
            if self.entries[idx].is_valid() && self.entries[idx].lru_seq() < min_seq {
                min_seq = self.entries[idx].lru_seq();
                min_idx = idx;
            }
        }
        if self.entries[min_idx].is_valid() {
            let size = self.entries[min_idx].compressed_size() as u64;
            self.entries[min_idx].invalidate();
            self.count -= 1;
            self.stats.evicted += 1;
            self.stats.pool_bytes = self.stats.pool_bytes.saturating_sub(size);
            self.stats.orig_bytes = self.stats.orig_bytes.saturating_sub(4096);
        }
    }

    /// Invalidate all entries for a given PFN.
    pub fn invalidate_pfn(&mut self, pfn: u64) -> usize {
        let mut removed = 0;
        for idx in 0..MAX_ENTRIES {
            if self.entries[idx].is_valid() && self.entries[idx].pfn() == pfn {
                let size = self.entries[idx].compressed_size() as u64;
                self.entries[idx].invalidate();
                self.count -= 1;
                self.stats.pool_bytes = self.stats.pool_bytes.saturating_sub(size);
                removed += 1;
            }
        }
        removed
    }
}

impl Default for ZswapPool {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Create a zswap pool with a given size limit in MiB.
pub fn create_pool_mib(size_mib: u64) -> ZswapPool {
    let config = ZswapPoolConfig {
        max_pages: size_mib * 256, // 1 MiB = 256 pages
        ..ZswapPoolConfig::new()
    };
    ZswapPool::with_config(config)
}

/// Return a summary of zswap pool state.
pub fn pool_summary(pool: &ZswapPool) -> &'static str {
    if !pool.is_enabled() {
        "zswap pool: disabled"
    } else if pool.count() == 0 {
        "zswap pool: empty"
    } else {
        "zswap pool: active"
    }
}

/// Return the effective compression ratio.
pub fn effective_ratio(pool: &ZswapPool) -> u64 {
    pool.stats().compression_ratio()
}
