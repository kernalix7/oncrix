// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cleancache — transcendent memory frontend.
//!
//! Provides a filesystem-agnostic cache for clean (unmodified) pages
//! that have been evicted from the page cache. Filesystems call into
//! cleancache when evicting a clean page; if the backend has spare
//! capacity it stores the data. On a subsequent page-in, the
//! filesystem checks cleancache before going to disk.
//!
//! The design follows Linux `mm/cleancache.c` and
//! `include/linux/cleancache.h`.
//!
//! # Architecture
//!
//! - [`CleanCacheOps`] — trait defining backend operations
//! - [`CachePageKey`] — composite key (pool, inode, page index)
//! - [`CacheEntry`] — cached page data with metadata
//! - [`PoolState`] — lifecycle state of a pool
//! - [`PoolInfo`] — per-pool metadata and statistics
//! - [`CleanCacheStats`] — aggregate cleancache statistics
//! - [`CleanCacheManager`] — top-level manager handling pools and
//!   entries
//!
//! # Usage
//!
//! 1. Register a filesystem pool via
//!    [`CleanCacheManager::init_fs`].
//! 2. On page eviction, call [`CleanCacheManager::put_page`] to
//!    store the page data.
//! 3. On page-in, call [`CleanCacheManager::get_page`] to retrieve
//!    cached data (avoiding a disk read).
//! 4. Invalidate pages, inodes, or entire pools when data changes.
//!
//! Reference: Linux `mm/cleancache.c`,
//! `include/linux/cleancache.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of registered filesystem pools.
const MAX_POOLS: usize = 16;

/// Maximum number of cached pages across all pools.
const MAX_CACHED_PAGES: usize = 4096;

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum number of inodes tracked per pool.
const MAX_INODES_PER_POOL: usize = 256;

/// Invalid pool ID sentinel.
const INVALID_POOL_ID: i32 = -1;

// -------------------------------------------------------------------
// CachePageKey
// -------------------------------------------------------------------

/// Composite key identifying a cached page.
///
/// A page is uniquely identified by its pool, inode number, and
/// offset-based page index within that inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePageKey {
    /// Pool identifier (filesystem instance).
    pub pool_id: i32,
    /// Inode number within the filesystem.
    pub inode: u64,
    /// Page index within the inode (byte offset / PAGE_SIZE).
    pub index: u64,
}

impl CachePageKey {
    /// Create a new cache page key.
    pub const fn new(pool_id: i32, inode: u64, index: u64) -> Self {
        Self {
            pool_id,
            inode,
            index,
        }
    }
}

impl Default for CachePageKey {
    fn default() -> Self {
        Self {
            pool_id: INVALID_POOL_ID,
            inode: 0,
            index: 0,
        }
    }
}

// -------------------------------------------------------------------
// CacheEntry
// -------------------------------------------------------------------

/// A single cached clean page.
///
/// Stores the composite key, page data, and metadata for LRU-style
/// replacement.
pub struct CacheEntry {
    /// Composite key identifying this page.
    pub key: CachePageKey,
    /// Page data buffer (4 KiB).
    pub data: [u8; PAGE_SIZE],
    /// Whether this entry is currently in use.
    pub valid: bool,
    /// Access counter for simple LRU approximation.
    pub access_count: u64,
    /// Timestamp (monotonic counter) when the entry was stored.
    pub store_timestamp: u64,
    /// Timestamp of last retrieval.
    pub last_access_timestamp: u64,
}

impl Default for CacheEntry {
    fn default() -> Self {
        Self {
            key: CachePageKey::default(),
            data: [0u8; PAGE_SIZE],
            valid: false,
            access_count: 0,
            store_timestamp: 0,
            last_access_timestamp: 0,
        }
    }
}

// -------------------------------------------------------------------
// PoolState
// -------------------------------------------------------------------

/// Lifecycle state of a cleancache pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PoolState {
    /// Pool is not allocated.
    #[default]
    Free,
    /// Pool is active and accepting put/get operations.
    Active,
    /// Pool has been invalidated (pending cleanup).
    Invalidated,
}

// -------------------------------------------------------------------
// PoolInfo
// -------------------------------------------------------------------

/// Per-pool metadata and counters.
#[derive(Debug, Clone, Copy)]
pub struct PoolInfo {
    /// Pool identifier.
    pub pool_id: i32,
    /// Current lifecycle state.
    pub state: PoolState,
    /// Filesystem type identifier (opaque tag).
    pub fs_type: u32,
    /// Number of pages currently cached for this pool.
    pub cached_pages: usize,
    /// Total pages ever stored in this pool.
    pub total_puts: u64,
    /// Total successful get operations.
    pub total_gets: u64,
    /// Total invalidate_page calls.
    pub total_invalidates: u64,
    /// Total inodes invalidated.
    pub total_inode_invalidates: u64,
}

impl Default for PoolInfo {
    fn default() -> Self {
        Self {
            pool_id: INVALID_POOL_ID,
            state: PoolState::Free,
            fs_type: 0,
            cached_pages: 0,
            total_puts: 0,
            total_gets: 0,
            total_invalidates: 0,
            total_inode_invalidates: 0,
        }
    }
}

// -------------------------------------------------------------------
// CleanCacheStats
// -------------------------------------------------------------------

/// Aggregate cleancache statistics across all pools.
#[derive(Debug, Clone, Copy, Default)]
pub struct CleanCacheStats {
    /// Total put_page calls (attempted stores).
    pub puts: u64,
    /// Successful put_page operations.
    pub puts_ok: u64,
    /// Total get_page calls (attempted retrievals).
    pub gets: u64,
    /// Successful get_page operations (cache hits).
    pub gets_ok: u64,
    /// Total invalidate_page calls.
    pub invalidates: u64,
    /// Total invalidate_inode calls.
    pub inode_invalidates: u64,
    /// Total invalidate_fs (pool) calls.
    pub fs_invalidates: u64,
    /// Number of evictions due to cache pressure.
    pub evictions: u64,
    /// Number of active pools.
    pub active_pools: u32,
    /// Total pages currently cached.
    pub total_cached: usize,
}

// -------------------------------------------------------------------
// CleanCacheOps (trait)
// -------------------------------------------------------------------

/// Backend operations for cleancache.
///
/// A backend (e.g. zcache, RAMster, Xen tmem) implements this trait
/// to provide the actual storage.
pub trait CleanCacheOps {
    /// Initialize a new filesystem pool.
    ///
    /// Returns a pool ID (>= 0) on success.
    fn init_fs(&mut self, fs_type: u32) -> Result<i32>;

    /// Store a page in the cache.
    fn put_page(
        &mut self,
        pool_id: i32,
        inode: u64,
        index: u64,
        data: &[u8; PAGE_SIZE],
    ) -> Result<()>;

    /// Retrieve a page from the cache.
    ///
    /// On success, fills `data` and returns `Ok(())`.
    /// Returns [`Error::NotFound`] if the page is not cached.
    fn get_page(
        &mut self,
        pool_id: i32,
        inode: u64,
        index: u64,
        data: &mut [u8; PAGE_SIZE],
    ) -> Result<()>;

    /// Invalidate a single cached page.
    fn invalidate_page(&mut self, pool_id: i32, inode: u64, index: u64) -> Result<()>;

    /// Invalidate all cached pages for an inode.
    fn invalidate_inode(&mut self, pool_id: i32, inode: u64) -> Result<()>;

    /// Invalidate an entire pool (filesystem unmount).
    fn invalidate_fs(&mut self, pool_id: i32) -> Result<()>;
}

// -------------------------------------------------------------------
// CleanCacheManager
// -------------------------------------------------------------------

/// Top-level cleancache manager.
///
/// Provides a built-in in-memory backend that stores page data in a
/// fixed-size entry array with LRU eviction.
pub struct CleanCacheManager {
    /// Per-pool metadata.
    pools: [PoolInfo; MAX_POOLS],
    /// Flat cache entry array.
    entries: [CacheEntry; MAX_CACHED_PAGES],
    /// Number of entries currently in use.
    entry_count: usize,
    /// Monotonic timestamp counter.
    timestamp: u64,
    /// Aggregate statistics.
    stats: CleanCacheStats,
    /// Next pool ID to allocate.
    next_pool_id: i32,
    /// Whether the manager is enabled.
    enabled: bool,
}

impl CleanCacheManager {
    /// Create a new cleancache manager.
    pub fn new() -> Self {
        const DEFAULT_POOL: PoolInfo = PoolInfo {
            pool_id: INVALID_POOL_ID,
            state: PoolState::Free,
            fs_type: 0,
            cached_pages: 0,
            total_puts: 0,
            total_gets: 0,
            total_invalidates: 0,
            total_inode_invalidates: 0,
        };
        const DEFAULT_ENTRY: CacheEntry = CacheEntry {
            key: CachePageKey {
                pool_id: INVALID_POOL_ID,
                inode: 0,
                index: 0,
            },
            data: [0u8; PAGE_SIZE],
            valid: false,
            access_count: 0,
            store_timestamp: 0,
            last_access_timestamp: 0,
        };
        Self {
            pools: [DEFAULT_POOL; MAX_POOLS],
            entries: [DEFAULT_ENTRY; MAX_CACHED_PAGES],
            entry_count: 0,
            timestamp: 0,
            stats: CleanCacheStats::default(),
            next_pool_id: 0,
            enabled: false,
        }
    }

    /// Enable the cleancache subsystem.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the cleancache subsystem.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Return whether cleancache is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> CleanCacheStats {
        self.stats
    }

    /// Return per-pool information.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pool_id` is out of
    /// range or not active.
    pub fn pool_info(&self, pool_id: i32) -> Result<&PoolInfo> {
        let slot = self.find_pool(pool_id).ok_or(Error::InvalidArgument)?;
        Ok(&self.pools[slot])
    }

    /// Initialize a new filesystem pool.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no pool slots are
    /// available.
    pub fn init_fs(&mut self, fs_type: u32) -> Result<i32> {
        // Find a free pool slot.
        let slot = self
            .pools
            .iter()
            .position(|p| p.state == PoolState::Free)
            .ok_or(Error::OutOfMemory)?;

        let pool_id = self.next_pool_id;
        self.next_pool_id += 1;

        self.pools[slot] = PoolInfo {
            pool_id,
            state: PoolState::Active,
            fs_type,
            cached_pages: 0,
            total_puts: 0,
            total_gets: 0,
            total_invalidates: 0,
            total_inode_invalidates: 0,
        };
        self.stats.active_pools += 1;
        Ok(pool_id)
    }

    /// Store a clean page in the cache.
    ///
    /// If the cache is full, the least-recently-accessed entry is
    /// evicted to make room.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the pool is not active.
    pub fn put_page(
        &mut self,
        pool_id: i32,
        inode: u64,
        index: u64,
        data: &[u8; PAGE_SIZE],
    ) -> Result<()> {
        self.stats.puts += 1;
        if !self.enabled {
            return Err(Error::InvalidArgument);
        }
        let pool_slot = self
            .find_active_pool(pool_id)
            .ok_or(Error::InvalidArgument)?;

        self.timestamp += 1;
        let ts = self.timestamp;
        let key = CachePageKey::new(pool_id, inode, index);

        // Check if the page is already cached (update in place).
        if let Some(idx) = self.find_entry(&key) {
            self.entries[idx].data.copy_from_slice(data);
            self.entries[idx].store_timestamp = ts;
            self.entries[idx].last_access_timestamp = ts;
            self.entries[idx].access_count += 1;
            self.pools[pool_slot].total_puts += 1;
            self.stats.puts_ok += 1;
            return Ok(());
        }

        // Find a free entry or evict the LRU entry.
        let slot = if self.entry_count < MAX_CACHED_PAGES {
            let s = self.entry_count;
            self.entry_count += 1;
            s
        } else {
            let victim = self.find_lru_victim();
            self.evict_entry(victim);
            victim
        };

        self.entries[slot].key = key;
        self.entries[slot].data.copy_from_slice(data);
        self.entries[slot].valid = true;
        self.entries[slot].access_count = 1;
        self.entries[slot].store_timestamp = ts;
        self.entries[slot].last_access_timestamp = ts;

        self.pools[pool_slot].cached_pages += 1;
        self.pools[pool_slot].total_puts += 1;
        self.stats.puts_ok += 1;
        self.stats.total_cached += 1;
        Ok(())
    }

    /// Retrieve a cached page.
    ///
    /// On success, fills `data` with the cached page contents and
    /// returns `Ok(())`. The entry is **consumed** (invalidated after
    /// retrieval) following the Linux cleancache "get-and-invalidate"
    /// semantics.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the page is not in the cache.
    /// Returns [`Error::InvalidArgument`] if the pool is not active.
    pub fn get_page(
        &mut self,
        pool_id: i32,
        inode: u64,
        index: u64,
        data: &mut [u8; PAGE_SIZE],
    ) -> Result<()> {
        self.stats.gets += 1;
        if !self.enabled {
            return Err(Error::NotFound);
        }
        let pool_slot = self
            .find_active_pool(pool_id)
            .ok_or(Error::InvalidArgument)?;
        let key = CachePageKey::new(pool_id, inode, index);
        let idx = self.find_entry(&key).ok_or(Error::NotFound)?;

        data.copy_from_slice(&self.entries[idx].data);

        // Consume the entry (get-and-invalidate).
        self.entries[idx].valid = false;
        self.pools[pool_slot].cached_pages = self.pools[pool_slot].cached_pages.saturating_sub(1);
        self.pools[pool_slot].total_gets += 1;
        self.stats.gets_ok += 1;
        self.stats.total_cached = self.stats.total_cached.saturating_sub(1);
        Ok(())
    }

    /// Invalidate a single cached page.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the pool is not active.
    pub fn invalidate_page(&mut self, pool_id: i32, inode: u64, index: u64) -> Result<()> {
        self.stats.invalidates += 1;
        let pool_slot = self
            .find_active_pool(pool_id)
            .ok_or(Error::InvalidArgument)?;
        let key = CachePageKey::new(pool_id, inode, index);
        if let Some(idx) = self.find_entry(&key) {
            self.entries[idx].valid = false;
            self.pools[pool_slot].cached_pages =
                self.pools[pool_slot].cached_pages.saturating_sub(1);
            self.pools[pool_slot].total_invalidates += 1;
            self.stats.total_cached = self.stats.total_cached.saturating_sub(1);
        }
        Ok(())
    }

    /// Invalidate all cached pages for an inode.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the pool is not active.
    pub fn invalidate_inode(&mut self, pool_id: i32, inode: u64) -> Result<()> {
        self.stats.inode_invalidates += 1;
        let pool_slot = self
            .find_active_pool(pool_id)
            .ok_or(Error::InvalidArgument)?;
        let mut removed = 0usize;
        for i in 0..self.entry_count {
            if self.entries[i].valid
                && self.entries[i].key.pool_id == pool_id
                && self.entries[i].key.inode == inode
            {
                self.entries[i].valid = false;
                removed += 1;
            }
        }
        self.pools[pool_slot].cached_pages =
            self.pools[pool_slot].cached_pages.saturating_sub(removed);
        self.pools[pool_slot].total_inode_invalidates += 1;
        self.stats.total_cached = self.stats.total_cached.saturating_sub(removed);
        Ok(())
    }

    /// Invalidate an entire filesystem pool.
    ///
    /// All pages belonging to this pool are removed and the pool is
    /// freed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the pool does not exist.
    pub fn invalidate_fs(&mut self, pool_id: i32) -> Result<()> {
        self.stats.fs_invalidates += 1;
        let pool_slot = self.find_pool(pool_id).ok_or(Error::InvalidArgument)?;
        // Remove all entries for this pool.
        let mut removed = 0usize;
        for i in 0..self.entry_count {
            if self.entries[i].valid && self.entries[i].key.pool_id == pool_id {
                self.entries[i].valid = false;
                removed += 1;
            }
        }
        self.pools[pool_slot].state = PoolState::Free;
        self.pools[pool_slot].cached_pages = 0;
        self.stats.active_pools = self.stats.active_pools.saturating_sub(1);
        self.stats.total_cached = self.stats.total_cached.saturating_sub(removed);
        Ok(())
    }

    /// Return the number of pages currently cached for a pool.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the pool is not active.
    pub fn pool_cached_count(&self, pool_id: i32) -> Result<usize> {
        let slot = self
            .find_active_pool(pool_id)
            .ok_or(Error::InvalidArgument)?;
        Ok(self.pools[slot].cached_pages)
    }

    /// Return the total number of cached pages across all pools.
    pub fn total_cached(&self) -> usize {
        self.stats.total_cached
    }

    /// Reset all statistics.
    pub fn reset_stats(&mut self) {
        self.stats = CleanCacheStats {
            active_pools: self.stats.active_pools,
            total_cached: self.stats.total_cached,
            ..CleanCacheStats::default()
        };
    }

    // --- internal helpers ---

    /// Find the pool slot for a given pool_id.
    fn find_pool(&self, pool_id: i32) -> Option<usize> {
        self.pools
            .iter()
            .position(|p| p.pool_id == pool_id && p.state != PoolState::Free)
    }

    /// Find an active pool slot for a given pool_id.
    fn find_active_pool(&self, pool_id: i32) -> Option<usize> {
        self.pools
            .iter()
            .position(|p| p.pool_id == pool_id && p.state == PoolState::Active)
    }

    /// Find a cache entry by key.
    fn find_entry(&self, key: &CachePageKey) -> Option<usize> {
        for i in 0..self.entry_count {
            if self.entries[i].valid && self.entries[i].key == *key {
                return Some(i);
            }
        }
        None
    }

    /// Find the LRU victim: the valid entry with the smallest
    /// last_access_timestamp.
    fn find_lru_victim(&self) -> usize {
        let mut victim = 0;
        let mut min_ts = u64::MAX;
        for i in 0..self.entry_count {
            if self.entries[i].valid && self.entries[i].last_access_timestamp < min_ts {
                min_ts = self.entries[i].last_access_timestamp;
                victim = i;
            }
        }
        victim
    }

    /// Evict a cache entry by index.
    fn evict_entry(&mut self, idx: usize) {
        if idx < self.entry_count && self.entries[idx].valid {
            let pool_id = self.entries[idx].key.pool_id;
            self.entries[idx].valid = false;
            if let Some(ps) = self.find_pool(pool_id) {
                self.pools[ps].cached_pages = self.pools[ps].cached_pages.saturating_sub(1);
            }
            self.stats.evictions += 1;
            self.stats.total_cached = self.stats.total_cached.saturating_sub(1);
        }
    }
}

impl Default for CleanCacheManager {
    fn default() -> Self {
        Self::new()
    }
}
