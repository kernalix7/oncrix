// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Frontswap backend operations.
//!
//! Frontswap intercepts swap-out operations and stores pages in a
//! transcendent memory backend instead of (or before) writing to the
//! swap device. On swap-in, frontswap is checked first; if the page
//! is found, the disk read is avoided entirely.
//!
//! # Design
//!
//! ```text
//!  swap_writepage(page, swap_entry)
//!     │
//!     └─ frontswap_store(type, offset, page)
//!         ├─ backend accepts → page stored, skip disk write
//!         └─ backend rejects → fall through to swap device
//!
//!  swap_readpage(swap_entry)
//!     │
//!     └─ frontswap_load(type, offset, page)
//!         ├─ hit → page filled, skip disk read
//!         └─ miss → read from swap device
//! ```
//!
//! # Key Types
//!
//! - [`FrontswapEntry`] — a single frontswap-cached page
//! - [`FrontswapBackend`] — manages the frontswap cache
//! - [`FrontswapOpsStats`] — backend statistics
//!
//! Reference: Linux `mm/frontswap.c`, `include/linux/frontswap.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum cached entries.
const MAX_ENTRIES: usize = 8192;

/// Maximum swap types (partitions).
const MAX_SWAP_TYPES: usize = 32;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// FrontswapEntry
// -------------------------------------------------------------------

/// A single frontswap-cached page.
#[derive(Debug, Clone, Copy)]
pub struct FrontswapEntry {
    /// Swap type (partition index).
    swap_type: u32,
    /// Swap offset (page index within partition).
    offset: u64,
    /// Whether the entry is valid.
    valid: bool,
    /// Timestamp of store.
    timestamp: u64,
    /// Number of loads (hits).
    load_count: u32,
}

impl FrontswapEntry {
    /// Create a new entry.
    pub const fn new(swap_type: u32, offset: u64, timestamp: u64) -> Self {
        Self {
            swap_type,
            offset,
            valid: true,
            timestamp,
            load_count: 0,
        }
    }

    /// Return the swap type.
    pub const fn swap_type(&self) -> u32 {
        self.swap_type
    }

    /// Return the offset.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Check whether valid.
    pub const fn valid(&self) -> bool {
        self.valid
    }

    /// Return the load count.
    pub const fn load_count(&self) -> u32 {
        self.load_count
    }

    /// Invalidate.
    pub fn invalidate(&mut self) {
        self.valid = false;
    }

    /// Record a load hit.
    pub fn record_load(&mut self) {
        self.load_count = self.load_count.saturating_add(1);
    }

    /// Check whether this matches.
    pub const fn matches(&self, swap_type: u32, offset: u64) -> bool {
        self.valid && self.swap_type == swap_type && self.offset == offset
    }
}

impl Default for FrontswapEntry {
    fn default() -> Self {
        Self {
            swap_type: 0,
            offset: 0,
            valid: false,
            timestamp: 0,
            load_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// FrontswapOpsStats
// -------------------------------------------------------------------

/// Backend statistics.
#[derive(Debug, Clone, Copy)]
pub struct FrontswapOpsStats {
    /// Total store operations.
    pub stores: u64,
    /// Successful stores.
    pub store_successes: u64,
    /// Store failures (backend rejected).
    pub store_failures: u64,
    /// Total load operations.
    pub loads: u64,
    /// Load hits.
    pub load_hits: u64,
    /// Load misses.
    pub load_misses: u64,
    /// Invalidation operations.
    pub invalidates: u64,
    /// Disk I/O operations saved.
    pub io_saved: u64,
}

impl FrontswapOpsStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            stores: 0,
            store_successes: 0,
            store_failures: 0,
            loads: 0,
            load_hits: 0,
            load_misses: 0,
            invalidates: 0,
            io_saved: 0,
        }
    }

    /// Store success rate as percent.
    pub const fn store_success_pct(&self) -> u64 {
        if self.stores == 0 {
            return 0;
        }
        self.store_successes * 100 / self.stores
    }

    /// Load hit rate as percent.
    pub const fn load_hit_pct(&self) -> u64 {
        if self.loads == 0 {
            return 0;
        }
        self.load_hits * 100 / self.loads
    }
}

impl Default for FrontswapOpsStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// FrontswapBackend
// -------------------------------------------------------------------

/// Manages the frontswap cache.
pub struct FrontswapBackend {
    /// Entries.
    entries: [FrontswapEntry; MAX_ENTRIES],
    /// Number of entries.
    count: usize,
    /// Whether frontswap is enabled.
    enabled: bool,
    /// Per-swap-type enabled flags.
    type_enabled: [bool; MAX_SWAP_TYPES],
    /// Statistics.
    stats: FrontswapOpsStats,
}

impl FrontswapBackend {
    /// Create a new backend.
    pub const fn new() -> Self {
        Self {
            entries: [const {
                FrontswapEntry {
                    swap_type: 0,
                    offset: 0,
                    valid: false,
                    timestamp: 0,
                    load_count: 0,
                }
            }; MAX_ENTRIES],
            count: 0,
            enabled: false,
            type_enabled: [false; MAX_SWAP_TYPES],
            stats: FrontswapOpsStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &FrontswapOpsStats {
        &self.stats
    }

    /// Return the entry count.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Check whether enabled.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Enable frontswap.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Enable a swap type.
    pub fn enable_type(&mut self, swap_type: u32) -> Result<()> {
        if (swap_type as usize) >= MAX_SWAP_TYPES {
            return Err(Error::InvalidArgument);
        }
        self.type_enabled[swap_type as usize] = true;
        Ok(())
    }

    /// Store a page.
    pub fn store(&mut self, swap_type: u32, offset: u64, timestamp: u64) -> Result<()> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        self.stats.stores += 1;

        if (swap_type as usize) >= MAX_SWAP_TYPES || !self.type_enabled[swap_type as usize] {
            self.stats.store_failures += 1;
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_ENTRIES {
            self.stats.store_failures += 1;
            return Err(Error::OutOfMemory);
        }

        self.entries[self.count] = FrontswapEntry::new(swap_type, offset, timestamp);
        self.count += 1;
        self.stats.store_successes += 1;
        self.stats.io_saved += 1;
        Ok(())
    }

    /// Load a page.
    pub fn load(&mut self, swap_type: u32, offset: u64) -> Result<bool> {
        self.stats.loads += 1;
        for idx in 0..self.count {
            if self.entries[idx].matches(swap_type, offset) {
                self.entries[idx].record_load();
                self.stats.load_hits += 1;
                self.stats.io_saved += 1;
                return Ok(true);
            }
        }
        self.stats.load_misses += 1;
        Ok(false)
    }

    /// Invalidate an entry.
    pub fn invalidate(&mut self, swap_type: u32, offset: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.entries[idx].matches(swap_type, offset) {
                self.entries[idx].invalidate();
                self.stats.invalidates += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Bytes of disk I/O saved.
    pub const fn bytes_saved(&self) -> u64 {
        self.stats.io_saved * PAGE_SIZE
    }
}

impl Default for FrontswapBackend {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum entries.
pub const fn max_entries() -> usize {
    MAX_ENTRIES
}

/// Return the maximum swap types.
pub const fn max_swap_types() -> usize {
    MAX_SWAP_TYPES
}
