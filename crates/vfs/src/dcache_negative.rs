// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Negative dentry cache — caching "not found" lookup results.
//!
//! When a pathname component resolves to a non-existent file, the VFS
//! can cache this negative result to avoid repeated expensive filesystem
//! lookups.  This module implements a dedicated negative dentry cache
//! with LRU eviction, TTL-based expiration, per-directory limits, and
//! statistics tracking.
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |  resolve_path("foo/bar/nonexistent")                         |
//! |       |                                                      |
//! |       v                                                      |
//! |  dcache lookup  ---> miss for "nonexistent"                  |
//! |       |                                                      |
//! |       v                                                      |
//! |  filesystem inode_ops.lookup("nonexistent") --> ENOENT       |
//! |       |                                                      |
//! |       v                                                      |
//! |  +----------------------------------------------+            |
//! |  | NegativeDentryCache                          |            |
//! |  | +------------------------------------------+ |            |
//! |  | | Hash table: hash(parent_ino, name)       | |            |
//! |  | |  -> chain of NegativeDentry entries      | |            |
//! |  | +------------------------------------------+ |            |
//! |  | +------------------------------------------+ |            |
//! |  | | LRU list: oldest entries evicted first   | |            |
//! |  | +------------------------------------------+ |            |
//! |  +----------------------------------------------+            |
//! |       |                                                      |
//! |       v                                                      |
//! |  Next lookup("nonexistent") --> cache hit, return ENOENT     |
//! +-------------------------------------------------------------+
//! ```
//!
//! # Eviction policy
//!
//! Negative dentries are evicted in the following order:
//! 1. Expired entries (TTL exceeded) are removed first.
//! 2. When the cache is full, the LRU (least recently used) entry
//!    is evicted to make room.
//! 3. Manual invalidation removes specific entries or all entries
//!    under a given parent directory.
//!
//! # Reference
//!
//! Linux `fs/dcache.c` (negative dentry handling), `fs/namei.c`.

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of cached negative dentries.
const MAX_ENTRIES: usize = 512;

/// Number of hash buckets.
const HASH_BUCKETS: usize = 128;

/// Maximum filename length (POSIX NAME_MAX).
const NAME_MAX: usize = 255;

/// Default TTL for negative dentries, in seconds.
const DEFAULT_TTL_SECS: u64 = 30;

/// Maximum negative dentries per parent directory before pruning.
const MAX_PER_PARENT: u32 = 32;

/// Sentinel for "no entry".
const NONE_IDX: u32 = u32::MAX;

/// LRU high watermark — trigger auto-prune when exceeded.
const LRU_HIGH_WATERMARK: usize = 448;

/// LRU low watermark — target size after auto-prune.
const LRU_LOW_WATERMARK: usize = 320;

// ── NegativeDentry ───────────────────────────────────────────────────────────

/// A single negative dentry cache entry.
///
/// Records that a lookup of `name` under `parent_inode` returned "not found".
#[derive(Clone)]
struct NegativeDentry {
    /// Parent directory inode number.
    parent_inode: u64,
    /// Filename bytes.
    name: [u8; NAME_MAX],
    /// Length of the filename.
    name_len: u8,
    /// Timestamp (monotonic seconds) when this entry was created.
    created_at: u64,
    /// Timestamp of the last access (for LRU ordering).
    last_access: u64,
    /// Time-to-live in seconds.
    ttl_secs: u64,
    /// Access count (number of cache hits).
    hit_count: u32,
    /// Hash chain link (index of next entry in same bucket).
    hash_next: u32,
    /// LRU forward link.
    lru_next: u32,
    /// LRU backward link.
    lru_prev: u32,
    /// Superblock/filesystem identifier (to scope invalidation).
    sb_id: u32,
    /// Whether this slot is in use.
    in_use: bool,
}

impl NegativeDentry {
    /// Create an empty, unused slot.
    const fn empty() -> Self {
        Self {
            parent_inode: 0,
            name: [0; NAME_MAX],
            name_len: 0,
            created_at: 0,
            last_access: 0,
            ttl_secs: DEFAULT_TTL_SECS,
            hit_count: 0,
            hash_next: NONE_IDX,
            lru_next: NONE_IDX,
            lru_prev: NONE_IDX,
            sb_id: 0,
            in_use: false,
        }
    }

    /// Whether this entry has expired.
    fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.created_at) >= self.ttl_secs
    }

    /// Return the filename as a byte slice.
    fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Check if this entry matches a (parent, name) pair.
    fn matches(&self, parent_inode: u64, name: &[u8]) -> bool {
        self.in_use
            && self.parent_inode == parent_inode
            && self.name_len as usize == name.len()
            && self.name[..self.name_len as usize] == *name
    }
}

// ── NegCacheStats ────────────────────────────────────────────────────────────

/// Statistics for the negative dentry cache.
#[derive(Debug, Clone, Copy, Default)]
pub struct NegCacheStats {
    /// Total lookup hits (name found in negative cache).
    pub hits: u64,
    /// Total lookup misses (name not in negative cache).
    pub misses: u64,
    /// Total entries inserted.
    pub inserts: u64,
    /// Total entries evicted by LRU.
    pub evictions_lru: u64,
    /// Total entries evicted by TTL expiration.
    pub evictions_ttl: u64,
    /// Total entries explicitly invalidated.
    pub invalidations: u64,
    /// Current number of active entries.
    pub active_entries: u32,
    /// Current number of expired (stale) entries.
    pub expired_entries: u32,
}

// ── NegDentryLimit ───────────────────────────────────────────────────────────

/// Configuration limits for the negative dentry cache.
#[derive(Debug, Clone, Copy)]
pub struct NegDentryLimit {
    /// Maximum total entries.
    pub max_entries: usize,
    /// Maximum entries per parent directory.
    pub max_per_parent: u32,
    /// Default TTL in seconds.
    pub default_ttl_secs: u64,
    /// LRU high watermark.
    pub lru_high: usize,
    /// LRU low watermark.
    pub lru_low: usize,
}

impl NegDentryLimit {
    /// Default limits.
    pub const fn default_limits() -> Self {
        Self {
            max_entries: MAX_ENTRIES,
            max_per_parent: MAX_PER_PARENT,
            default_ttl_secs: DEFAULT_TTL_SECS,
            lru_high: LRU_HIGH_WATERMARK,
            lru_low: LRU_LOW_WATERMARK,
        }
    }
}

// ── Hash function ────────────────────────────────────────────────────────────

/// FNV-1a hash of (parent_inode, name), mapped to a bucket index.
fn hash_key(parent_inode: u64, name: &[u8]) -> usize {
    let mut h: u64 = 0xcbf29ce484222325;
    // Mix parent inode.
    for &b in &parent_inode.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    // Mix name bytes.
    for &b in name {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    (h as usize) % HASH_BUCKETS
}

// ── NegativeDentryCache ──────────────────────────────────────────────────────

/// Negative dentry cache with hash-table lookup and LRU eviction.
pub struct NegativeDentryCache {
    /// Entry storage.
    entries: [NegativeDentry; MAX_ENTRIES],
    /// Hash table: bucket[i] = index of first entry in chain.
    buckets: [u32; HASH_BUCKETS],
    /// Head of the LRU list (most recently used).
    lru_head: u32,
    /// Tail of the LRU list (least recently used).
    lru_tail: u32,
    /// Number of active entries.
    active_count: usize,
    /// Current monotonic time (seconds).
    current_time: u64,
    /// Configuration limits.
    limits: NegDentryLimit,
    /// Cumulative statistics.
    stats: NegCacheStats,
}

impl NegativeDentryCache {
    /// Create a new empty negative dentry cache.
    pub const fn new() -> Self {
        Self {
            entries: [const { NegativeDentry::empty() }; MAX_ENTRIES],
            buckets: [NONE_IDX; HASH_BUCKETS],
            lru_head: NONE_IDX,
            lru_tail: NONE_IDX,
            active_count: 0,
            current_time: 0,
            limits: NegDentryLimit::default_limits(),
            stats: NegCacheStats {
                hits: 0,
                misses: 0,
                inserts: 0,
                evictions_lru: 0,
                evictions_ttl: 0,
                invalidations: 0,
                active_entries: 0,
                expired_entries: 0,
            },
        }
    }

    /// Create a cache with custom limits.
    pub fn with_limits(limits: NegDentryLimit) -> Self {
        let mut cache = Self::new();
        cache.limits = limits;
        cache
    }

    /// Update the current monotonic time.
    pub fn set_time(&mut self, now_secs: u64) {
        self.current_time = now_secs;
    }

    // ── Core operations ──────────────────────────────────────────

    /// Look up a name in the negative cache.
    ///
    /// Returns `true` if the name is cached as non-existent (negative hit).
    /// Returns `false` if the name is not in the cache (must do real lookup).
    pub fn lookup_negative(&mut self, parent_inode: u64, name: &[u8]) -> bool {
        if name.is_empty() || name.len() > NAME_MAX {
            self.stats.misses += 1;
            return false;
        }

        let bucket = hash_key(parent_inode, name);
        let mut idx = self.buckets[bucket];

        while idx != NONE_IDX {
            let i = idx as usize;
            if self.entries[i].matches(parent_inode, name) {
                // Check TTL.
                if self.entries[i].is_expired(self.current_time) {
                    // Expired: remove and report miss.
                    self.remove_entry(i);
                    self.stats.evictions_ttl += 1;
                    self.stats.misses += 1;
                    return false;
                }
                // Cache hit.
                self.entries[i].last_access = self.current_time;
                self.entries[i].hit_count += 1;
                self.lru_touch(i);
                self.stats.hits += 1;
                return true;
            }
            idx = self.entries[i].hash_next;
        }

        self.stats.misses += 1;
        false
    }

    /// Add a negative dentry to the cache.
    ///
    /// Records that `name` under `parent_inode` does not exist.
    pub fn add_negative(&mut self, parent_inode: u64, name: &[u8], sb_id: u32) -> Result<()> {
        if name.is_empty() || name.len() > NAME_MAX {
            return Err(Error::InvalidArgument);
        }

        // Check per-parent limit.
        let parent_count = self.count_for_parent(parent_inode);
        if parent_count >= self.limits.max_per_parent {
            self.prune_parent(parent_inode, 1);
        }

        // Check if already cached.
        let bucket = hash_key(parent_inode, name);
        let mut idx = self.buckets[bucket];
        while idx != NONE_IDX {
            let i = idx as usize;
            if self.entries[i].matches(parent_inode, name) {
                // Refresh existing entry.
                self.entries[i].created_at = self.current_time;
                self.entries[i].last_access = self.current_time;
                self.entries[i].ttl_secs = self.limits.default_ttl_secs;
                self.lru_touch(i);
                return Ok(());
            }
            idx = self.entries[i].hash_next;
        }

        // Auto-prune if at high watermark.
        if self.active_count >= self.limits.lru_high {
            self.prune(self.active_count - self.limits.lru_low);
        }

        // Find a free slot.
        let slot_idx = self.find_free_slot()?;
        let entry = &mut self.entries[slot_idx];
        entry.parent_inode = parent_inode;
        entry.name[..name.len()].copy_from_slice(name);
        entry.name_len = name.len() as u8;
        entry.created_at = self.current_time;
        entry.last_access = self.current_time;
        entry.ttl_secs = self.limits.default_ttl_secs;
        entry.hit_count = 0;
        entry.sb_id = sb_id;
        entry.in_use = true;

        // Insert into hash chain.
        entry.hash_next = self.buckets[bucket];
        self.buckets[bucket] = slot_idx as u32;

        // Insert at LRU head.
        self.lru_push_head(slot_idx);

        self.active_count += 1;
        self.stats.inserts += 1;
        self.stats.active_entries = self.active_count as u32;
        Ok(())
    }

    /// Invalidate a specific negative dentry.
    ///
    /// Called when a file is created at a previously non-existent name.
    pub fn invalidate(&mut self, parent_inode: u64, name: &[u8]) -> bool {
        if name.is_empty() || name.len() > NAME_MAX {
            return false;
        }

        let bucket = hash_key(parent_inode, name);
        let mut idx = self.buckets[bucket];

        while idx != NONE_IDX {
            let i = idx as usize;
            if self.entries[i].matches(parent_inode, name) {
                self.remove_entry(i);
                self.stats.invalidations += 1;
                return true;
            }
            idx = self.entries[i].hash_next;
        }

        false
    }

    /// Invalidate all negative dentries under a parent directory.
    ///
    /// Called when a directory is removed or renamed.
    pub fn invalidate_parent(&mut self, parent_inode: u64) -> usize {
        let mut removed = 0usize;
        for i in 0..MAX_ENTRIES {
            if self.entries[i].in_use && self.entries[i].parent_inode == parent_inode {
                self.remove_entry(i);
                removed += 1;
            }
        }
        self.stats.invalidations += removed as u64;
        removed
    }

    /// Invalidate all negative dentries belonging to a superblock.
    pub fn invalidate_sb(&mut self, sb_id: u32) -> usize {
        let mut removed = 0usize;
        for i in 0..MAX_ENTRIES {
            if self.entries[i].in_use && self.entries[i].sb_id == sb_id {
                self.remove_entry(i);
                removed += 1;
            }
        }
        self.stats.invalidations += removed as u64;
        removed
    }

    /// Prune up to `count` entries from the LRU tail (least recently used).
    pub fn prune(&mut self, count: usize) -> usize {
        let mut pruned = 0usize;

        // First pass: remove expired entries.
        for i in 0..MAX_ENTRIES {
            if pruned >= count {
                break;
            }
            if self.entries[i].in_use && self.entries[i].is_expired(self.current_time) {
                self.remove_entry(i);
                self.stats.evictions_ttl += 1;
                pruned += 1;
            }
        }

        // Second pass: evict from LRU tail.
        while pruned < count && self.lru_tail != NONE_IDX {
            let tail_idx = self.lru_tail as usize;
            self.remove_entry(tail_idx);
            self.stats.evictions_lru += 1;
            pruned += 1;
        }

        pruned
    }

    /// Prune expired entries only.
    pub fn prune_expired(&mut self) -> usize {
        let mut pruned = 0usize;
        for i in 0..MAX_ENTRIES {
            if self.entries[i].in_use && self.entries[i].is_expired(self.current_time) {
                self.remove_entry(i);
                self.stats.evictions_ttl += 1;
                pruned += 1;
            }
        }
        pruned
    }

    // ── Statistics ───────────────────────────────────────────────

    /// Return current cache statistics.
    pub fn get_stats(&self) -> NegCacheStats {
        let mut stats = self.stats;
        stats.active_entries = self.active_count as u32;

        // Count expired entries.
        let mut expired = 0u32;
        for i in 0..MAX_ENTRIES {
            if self.entries[i].in_use && self.entries[i].is_expired(self.current_time) {
                expired += 1;
            }
        }
        stats.expired_entries = expired;
        stats
    }

    /// Reset statistics counters (active_entries stays accurate).
    pub fn reset_stats(&mut self) {
        self.stats.hits = 0;
        self.stats.misses = 0;
        self.stats.inserts = 0;
        self.stats.evictions_lru = 0;
        self.stats.evictions_ttl = 0;
        self.stats.invalidations = 0;
    }

    /// Current number of active entries.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Hit rate as a percentage (0-100).
    pub fn hit_rate(&self) -> u32 {
        let total = self.stats.hits + self.stats.misses;
        if total == 0 {
            return 0;
        }
        ((self.stats.hits * 100) / total) as u32
    }

    // ── Internal helpers ─────────────────────────────────────────

    /// Find a free slot, evicting the LRU tail if necessary.
    fn find_free_slot(&mut self) -> Result<usize> {
        // Look for a free slot.
        for i in 0..MAX_ENTRIES {
            if !self.entries[i].in_use {
                return Ok(i);
            }
        }
        // Evict the LRU tail.
        if self.lru_tail != NONE_IDX {
            let idx = self.lru_tail as usize;
            self.remove_entry(idx);
            self.stats.evictions_lru += 1;
            return Ok(idx);
        }
        Err(Error::OutOfMemory)
    }

    /// Remove an entry from both the hash chain and LRU list.
    fn remove_entry(&mut self, idx: usize) {
        if !self.entries[idx].in_use {
            return;
        }

        // Remove from hash chain.
        let parent = self.entries[idx].parent_inode;
        let name_len = self.entries[idx].name_len as usize;
        let mut name_buf = [0u8; NAME_MAX];
        name_buf[..name_len].copy_from_slice(&self.entries[idx].name[..name_len]);
        let bucket = hash_key(parent, &name_buf[..name_len]);

        if self.buckets[bucket] == idx as u32 {
            self.buckets[bucket] = self.entries[idx].hash_next;
        } else {
            let mut prev = self.buckets[bucket];
            while prev != NONE_IDX {
                let p = prev as usize;
                if self.entries[p].hash_next == idx as u32 {
                    self.entries[p].hash_next = self.entries[idx].hash_next;
                    break;
                }
                prev = self.entries[p].hash_next;
            }
        }

        // Remove from LRU list.
        self.lru_remove(idx);

        self.entries[idx].in_use = false;
        self.entries[idx].hash_next = NONE_IDX;
        self.active_count = self.active_count.saturating_sub(1);
        self.stats.active_entries = self.active_count as u32;
    }

    /// Count active entries for a given parent inode.
    fn count_for_parent(&self, parent_inode: u64) -> u32 {
        let mut count = 0u32;
        for entry in &self.entries {
            if entry.in_use && entry.parent_inode == parent_inode {
                count += 1;
            }
        }
        count
    }

    /// Prune entries for a specific parent, evicting the oldest first.
    fn prune_parent(&mut self, parent_inode: u64, count: u32) {
        let mut pruned = 0u32;
        // Find the oldest entries for this parent.
        for _ in 0..count {
            let mut oldest_idx: Option<usize> = None;
            let mut oldest_time = u64::MAX;

            for i in 0..MAX_ENTRIES {
                if self.entries[i].in_use
                    && self.entries[i].parent_inode == parent_inode
                    && self.entries[i].last_access < oldest_time
                {
                    oldest_time = self.entries[i].last_access;
                    oldest_idx = Some(i);
                }
            }

            if let Some(idx) = oldest_idx {
                self.remove_entry(idx);
                self.stats.evictions_lru += 1;
                pruned += 1;
            } else {
                break;
            }
        }
        let _ = pruned;
    }

    // ── LRU list operations ──────────────────────────────────────

    /// Push an entry to the head of the LRU list (most recently used).
    fn lru_push_head(&mut self, idx: usize) {
        self.entries[idx].lru_prev = NONE_IDX;
        self.entries[idx].lru_next = self.lru_head;

        if self.lru_head != NONE_IDX {
            self.entries[self.lru_head as usize].lru_prev = idx as u32;
        }
        self.lru_head = idx as u32;

        if self.lru_tail == NONE_IDX {
            self.lru_tail = idx as u32;
        }
    }

    /// Remove an entry from the LRU list.
    fn lru_remove(&mut self, idx: usize) {
        let prev = self.entries[idx].lru_prev;
        let next = self.entries[idx].lru_next;

        if prev != NONE_IDX {
            self.entries[prev as usize].lru_next = next;
        } else {
            self.lru_head = next;
        }

        if next != NONE_IDX {
            self.entries[next as usize].lru_prev = prev;
        } else {
            self.lru_tail = prev;
        }

        self.entries[idx].lru_prev = NONE_IDX;
        self.entries[idx].lru_next = NONE_IDX;
    }

    /// Move an entry to the head of the LRU list (touch / mark as used).
    fn lru_touch(&mut self, idx: usize) {
        // Already at head?
        if self.lru_head == idx as u32 {
            return;
        }
        self.lru_remove(idx);
        self.lru_push_head(idx);
    }
}
