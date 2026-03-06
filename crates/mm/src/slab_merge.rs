// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Slab cache merging.
//!
//! When multiple subsystems create slab caches with identical object
//! sizes and alignment, the kernel can merge them into a single cache
//! to reduce memory overhead and TLB pressure. This module detects
//! mergeable caches and manages the alias relationships.
//!
//! # Design
//!
//! ```text
//!  kmem_cache_create("foo", size=128, align=8)
//!       │
//!       ├─ find existing cache with same (size, align, flags)
//!       │   ├─ found → create alias, return existing cache
//!       │   └─ not found → create new cache
//!       │
//!  kmem_cache_destroy("foo")
//!       └─ if alias → decrement refcount on parent
//!       └─ if last ref → actually destroy cache
//! ```
//!
//! # Key Types
//!
//! - [`MergeCacheKey`] — key for matching mergeable caches
//! - [`SlabAlias`] — an alias pointing to a merged parent cache
//! - [`SlabMergeTable`] — the merge lookup table
//! - [`MergeStats`] — merge statistics
//!
//! Reference: Linux `mm/slab_common.c` (slab_merge).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum caches that can be tracked for merging.
const MAX_CACHES: usize = 256;

/// Maximum aliases per cache.
const MAX_ALIASES: usize = 512;

/// Cache flag: no merging allowed.
const CACHE_NO_MERGE: u32 = 1 << 0;

/// Cache flag: must be DMA-safe.
const CACHE_DMA: u32 = 1 << 1;

/// Cache flag: zero on free.
const CACHE_ZERO_FREE: u32 = 1 << 2;

// -------------------------------------------------------------------
// MergeCacheKey
// -------------------------------------------------------------------

/// Key used to identify mergeable slab caches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeCacheKey {
    /// Object size in bytes.
    pub obj_size: u32,
    /// Object alignment in bytes.
    pub alignment: u32,
    /// Cache flags (must match for merge).
    pub flags: u32,
}

impl MergeCacheKey {
    /// Create a new merge key.
    pub const fn new(obj_size: u32, alignment: u32, flags: u32) -> Self {
        Self {
            obj_size,
            alignment,
            flags,
        }
    }

    /// Check whether this key matches another for merge purposes.
    pub const fn matches(&self, other: &MergeCacheKey) -> bool {
        self.obj_size == other.obj_size
            && self.alignment == other.alignment
            && self.flags == other.flags
    }

    /// Check whether merging is allowed for these flags.
    pub const fn merge_allowed(&self) -> bool {
        self.flags & CACHE_NO_MERGE == 0
    }
}

impl Default for MergeCacheKey {
    fn default() -> Self {
        Self {
            obj_size: 0,
            alignment: 0,
            flags: 0,
        }
    }
}

// -------------------------------------------------------------------
// MergedCache
// -------------------------------------------------------------------

/// A parent cache entry in the merge table.
#[derive(Debug, Clone, Copy)]
pub struct MergedCache {
    /// Unique cache identifier.
    cache_id: u64,
    /// The merge key.
    key: MergeCacheKey,
    /// Reference count (parent + aliases).
    refcount: u32,
    /// Whether this cache is active.
    active: bool,
}

impl MergedCache {
    /// Create a new merged cache entry.
    pub const fn new(cache_id: u64, key: MergeCacheKey) -> Self {
        Self {
            cache_id,
            key,
            refcount: 1,
            active: true,
        }
    }

    /// Return the cache identifier.
    pub const fn cache_id(&self) -> u64 {
        self.cache_id
    }

    /// Return the merge key.
    pub const fn key(&self) -> &MergeCacheKey {
        &self.key
    }

    /// Return the reference count.
    pub const fn refcount(&self) -> u32 {
        self.refcount
    }

    /// Check whether this cache is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Increment the reference count.
    pub fn acquire(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    /// Decrement the reference count. Returns true if still referenced.
    pub fn release(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        if self.refcount == 0 {
            self.active = false;
        }
        self.refcount > 0
    }
}

impl Default for MergedCache {
    fn default() -> Self {
        Self {
            cache_id: 0,
            key: MergeCacheKey::default(),
            refcount: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// SlabAlias
// -------------------------------------------------------------------

/// An alias that maps a subsystem name to a merged parent cache.
#[derive(Debug, Clone, Copy)]
pub struct SlabAlias {
    /// Alias identifier.
    alias_id: u64,
    /// Parent cache identifier.
    parent_id: u64,
    /// Whether this alias is active.
    active: bool,
}

impl SlabAlias {
    /// Create a new alias.
    pub const fn new(alias_id: u64, parent_id: u64) -> Self {
        Self {
            alias_id,
            parent_id,
            active: true,
        }
    }

    /// Return the alias identifier.
    pub const fn alias_id(&self) -> u64 {
        self.alias_id
    }

    /// Return the parent cache identifier.
    pub const fn parent_id(&self) -> u64 {
        self.parent_id
    }

    /// Check whether this alias is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate this alias.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl Default for SlabAlias {
    fn default() -> Self {
        Self {
            alias_id: 0,
            parent_id: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// MergeStats
// -------------------------------------------------------------------

/// Statistics for slab cache merging.
#[derive(Debug, Clone, Copy)]
pub struct MergeStats {
    /// Total unique caches.
    pub unique_caches: u64,
    /// Total aliases (merged duplicates).
    pub aliases: u64,
    /// Total merge attempts.
    pub merge_attempts: u64,
    /// Successful merges.
    pub merge_successes: u64,
    /// Merge rejections (NO_MERGE flag).
    pub merge_rejections: u64,
}

impl MergeStats {
    /// Create zero statistics.
    pub const fn new() -> Self {
        Self {
            unique_caches: 0,
            aliases: 0,
            merge_attempts: 0,
            merge_successes: 0,
            merge_rejections: 0,
        }
    }

    /// Return the merge ratio as a percentage.
    pub const fn merge_ratio(&self) -> u64 {
        if self.merge_attempts == 0 {
            return 0;
        }
        self.merge_successes * 100 / self.merge_attempts
    }
}

impl Default for MergeStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// SlabMergeTable
// -------------------------------------------------------------------

/// The slab cache merge lookup table.
pub struct SlabMergeTable {
    /// Parent caches.
    caches: [MergedCache; MAX_CACHES],
    /// Aliases.
    aliases: [SlabAlias; MAX_ALIASES],
    /// Number of valid caches.
    cache_count: usize,
    /// Number of valid aliases.
    alias_count: usize,
    /// Next identifier.
    next_id: u64,
    /// Statistics.
    stats: MergeStats,
}

impl SlabMergeTable {
    /// Create a new merge table.
    pub const fn new() -> Self {
        Self {
            caches: [const {
                MergedCache {
                    cache_id: 0,
                    key: MergeCacheKey {
                        obj_size: 0,
                        alignment: 0,
                        flags: 0,
                    },
                    refcount: 0,
                    active: false,
                }
            }; MAX_CACHES],
            aliases: [const {
                SlabAlias {
                    alias_id: 0,
                    parent_id: 0,
                    active: false,
                }
            }; MAX_ALIASES],
            cache_count: 0,
            alias_count: 0,
            next_id: 1,
            stats: MergeStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &MergeStats {
        &self.stats
    }

    /// Find or create a cache for the given key.
    pub fn find_or_create(&mut self, key: MergeCacheKey) -> Result<u64> {
        self.stats.merge_attempts += 1;

        if !key.merge_allowed() {
            self.stats.merge_rejections += 1;
            return self.create_new(key);
        }

        // Try to find an existing match.
        for idx in 0..self.cache_count {
            if self.caches[idx].is_active() && self.caches[idx].key().matches(&key) {
                self.caches[idx].acquire();
                let parent_id = self.caches[idx].cache_id();
                // Create an alias.
                if self.alias_count < MAX_ALIASES {
                    let alias_id = self.next_id;
                    self.next_id += 1;
                    self.aliases[self.alias_count] = SlabAlias::new(alias_id, parent_id);
                    self.alias_count += 1;
                    self.stats.aliases += 1;
                }
                self.stats.merge_successes += 1;
                return Ok(parent_id);
            }
        }

        self.create_new(key)
    }

    /// Create a new unique cache.
    fn create_new(&mut self, key: MergeCacheKey) -> Result<u64> {
        if self.cache_count >= MAX_CACHES {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.caches[self.cache_count] = MergedCache::new(id, key);
        self.cache_count += 1;
        self.stats.unique_caches += 1;
        Ok(id)
    }

    /// Release a cache or alias by identifier.
    pub fn release(&mut self, id: u64) -> Result<()> {
        // Check aliases first.
        for idx in 0..self.alias_count {
            if self.aliases[idx].is_active() && self.aliases[idx].alias_id() == id {
                let parent_id = self.aliases[idx].parent_id();
                self.aliases[idx].deactivate();
                self.stats.aliases = self.stats.aliases.saturating_sub(1);
                return self.release_cache(parent_id);
            }
        }
        // Check direct caches.
        self.release_cache(id)
    }

    /// Decrement refcount on a parent cache.
    fn release_cache(&mut self, cache_id: u64) -> Result<()> {
        for idx in 0..self.cache_count {
            if self.caches[idx].is_active() && self.caches[idx].cache_id() == cache_id {
                if !self.caches[idx].release() {
                    self.stats.unique_caches = self.stats.unique_caches.saturating_sub(1);
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of unique caches.
    pub const fn cache_count(&self) -> usize {
        self.cache_count
    }

    /// Return the number of aliases.
    pub const fn alias_count(&self) -> usize {
        self.alias_count
    }
}

impl Default for SlabMergeTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Check whether two cache keys are mergeable.
pub const fn is_mergeable(a: &MergeCacheKey, b: &MergeCacheKey) -> bool {
    a.merge_allowed() && b.merge_allowed() && a.matches(b)
}

/// Return the memory saved by merging (estimated).
pub const fn merge_savings(table: &SlabMergeTable) -> u64 {
    // Each merged alias saves approximately one slab page (4096 bytes overhead).
    table.stats().aliases * 4096
}

/// Check whether a set of flags allows merging.
pub const fn flags_allow_merge(flags: u32) -> bool {
    flags & CACHE_NO_MERGE == 0
}

/// Return the DMA flag.
pub const fn cache_dma_flag() -> u32 {
    CACHE_DMA
}

/// Return the zero-on-free flag.
pub const fn cache_zero_free_flag() -> u32 {
    CACHE_ZERO_FREE
}
