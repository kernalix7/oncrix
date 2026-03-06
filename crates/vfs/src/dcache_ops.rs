// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Dentry cache (dcache) operations.
//!
//! The dentry cache accelerates pathname lookup by caching the mapping
//! from (parent_inode, name) to child inode.  This module implements
//! the hash-table-based dcache with LRU eviction, negative dentry
//! support, and bulk shrink operations.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Path resolution (resolve_path)                            │
//! │       │                                                    │
//! │       ▼                                                    │
//! │  ┌──────────────────────────────────────────┐              │
//! │  │  Dentry cache (dcache)                   │              │
//! │  │  ┌──────────────────────────────────────┐│              │
//! │  │  │ Hash table: bucket[hash(parent,name)]││              │
//! │  │  │  → chain of DcacheEntry nodes        ││              │
//! │  │  └──────────────────────────────────────┘│              │
//! │  │  ┌──────────────────────────────────────┐│              │
//! │  │  │ LRU list (unused dentries for shrink)││              │
//! │  │  └──────────────────────────────────────┘│              │
//! │  │  ┌──────────────────────────────────────┐│              │
//! │  │  │ Negative dentries (non-existent)     ││              │
//! │  │  └──────────────────────────────────────┘│              │
//! │  └──────────────────────────────────────────┘              │
//! │       │ miss                                               │
//! │       ▼                                                    │
//! │  Filesystem inode lookup (InodeOps::lookup)                │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Hash table
//!
//! Dentries are stored in a fixed-size hash table indexed by a hash
//! of (parent_inode, name).  Each bucket is a chain of entries.
//! Lookup is O(chain_length), which is typically O(1) under uniform
//! hashing.
//!
//! ## Negative dentries
//!
//! When a name lookup returns "not found", a negative dentry is
//! cached so that repeated lookups of non-existent names do not
//! hit the filesystem.
//!
//! ## LRU and shrinking
//!
//! Dentries with zero reference count are placed on the LRU list.
//! Under memory pressure, `shrink_dcache()` evicts the least-recently
//! used entries.
//!
//! ## Reference counting
//!
//! Each dentry has a reference count.  `d_lookup` increments it,
//! `dput` decrements it.  When it reaches zero, the dentry moves
//! to the LRU list but is not freed immediately.
//!
//! # Reference
//!
//! Linux `fs/dcache.c`, `include/linux/dcache.h`.

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Number of hash buckets in the dcache hash table.
const HASH_BUCKETS: usize = 256;

/// Maximum number of cached dentries.
const MAX_DENTRIES: usize = 1024;

/// Maximum filename length (POSIX NAME_MAX).
const NAME_MAX: usize = 255;

/// Sentinel value for "no entry" in chain links.
const NONE_IDX: u32 = u32::MAX;

/// Maximum number of entries on the LRU list before auto-shrink.
const LRU_HIGH_WATERMARK: usize = 768;

/// Target LRU size after shrink.
const LRU_LOW_WATERMARK: usize = 512;

// ── Dentry flags ─────────────────────────────────────────────────────────────

/// Dentry state and behavior flags.
#[derive(Debug, Clone, Copy)]
pub struct DentryFlags {
    /// This dentry is a negative (non-existent name) cache entry.
    pub negative: bool,
    /// Dentry is on the LRU list (unreferenced).
    pub on_lru: bool,
    /// Dentry is a mount point.
    pub mounted: bool,
    /// Dentry has been invalidated and should be discarded.
    pub invalidated: bool,
    /// Dentry is an automount trigger.
    pub automount: bool,
}

impl DentryFlags {
    /// Create default (positive, active) flags.
    const fn new() -> Self {
        Self {
            negative: false,
            on_lru: false,
            mounted: false,
            invalidated: false,
            automount: false,
        }
    }
}

// ── Dentry entry ─────────────────────────────────────────────────────────────

/// A single dentry cache entry.
struct DcacheEntry {
    /// Parent inode number.
    parent_inode: u64,
    /// Name buffer.
    name: [u8; NAME_MAX],
    /// Name length.
    name_len: u16,
    /// Target inode number (0 for negative dentries).
    inode: u64,
    /// Superblock / device ID.
    device_id: u32,
    /// Reference count.
    ref_count: u32,
    /// Flags.
    flags: DentryFlags,
    /// Last access tick (for LRU ordering).
    access_tick: u64,
    /// Index of next entry in hash chain (NONE_IDX = end).
    hash_next: u32,
    /// Index of next entry in LRU list (NONE_IDX = end).
    lru_next: u32,
    /// Index of previous entry in LRU list (NONE_IDX = end).
    lru_prev: u32,
    /// Whether this slot is in use.
    in_use: bool,
}

impl DcacheEntry {
    /// Create an empty, unused entry.
    const fn empty() -> Self {
        Self {
            parent_inode: 0,
            name: [0; NAME_MAX],
            name_len: 0,
            inode: 0,
            device_id: 0,
            ref_count: 0,
            flags: DentryFlags::new(),
            access_tick: 0,
            hash_next: NONE_IDX,
            lru_next: NONE_IDX,
            lru_prev: NONE_IDX,
            in_use: false,
        }
    }

    /// Check if name matches.
    fn name_matches(&self, name: &[u8]) -> bool {
        self.name_len as usize == name.len() && self.name[..self.name_len as usize] == *name
    }
}

// ── Statistics ───────────────────────────────────────────────────────────────

/// Dcache subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct DcacheStats {
    /// Total lookups performed.
    pub lookups: u64,
    /// Positive cache hits.
    pub hits: u64,
    /// Negative cache hits (name confirmed non-existent).
    pub negative_hits: u64,
    /// Cache misses.
    pub misses: u64,
    /// Entries allocated (d_alloc calls).
    pub allocs: u64,
    /// Entries freed (evicted or invalidated).
    pub frees: u64,
    /// Entries currently cached.
    pub entries: u32,
    /// Entries on the LRU list.
    pub lru_entries: u32,
    /// Negative entries cached.
    pub negative_entries: u32,
    /// Number of shrink operations.
    pub shrinks: u64,
}

impl DcacheStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            lookups: 0,
            hits: 0,
            negative_hits: 0,
            misses: 0,
            allocs: 0,
            frees: 0,
            entries: 0,
            lru_entries: 0,
            negative_entries: 0,
            shrinks: 0,
        }
    }
}

// ── Hash function ────────────────────────────────────────────────────────────

/// Compute the hash bucket for a (parent_inode, name) pair.
///
/// Uses a simple FNV-1a-style hash.
fn dcache_hash(parent: u64, name: &[u8]) -> usize {
    let mut h: u64 = 0xcbf29ce484222325; // FNV offset basis
    // Mix in parent inode.
    let parent_bytes = parent.to_le_bytes();
    for &b in &parent_bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3); // FNV prime
    }
    // Mix in name.
    for &b in name {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    (h as usize) % HASH_BUCKETS
}

// ── Dcache lookup result ─────────────────────────────────────────────────────

/// Result of a dentry cache lookup.
#[derive(Debug, Clone, Copy)]
pub enum DcacheLookupResult {
    /// Positive hit: name maps to an inode.
    Found {
        /// Inode number.
        inode: u64,
        /// Device/superblock ID.
        device_id: u32,
    },
    /// Negative hit: name is known to not exist.
    NegativeHit,
    /// Cache miss: no information cached.
    Miss,
}

// ── Dcache manager ───────────────────────────────────────────────────────────

/// The dentry cache manager.
///
/// Provides hash-table-based caching of pathname components with
/// LRU eviction and negative dentry support.
pub struct Dcache {
    /// Dentry entry pool.
    entries: [DcacheEntry; MAX_DENTRIES],
    /// Hash table: bucket heads (index into entries, NONE_IDX = empty).
    buckets: [u32; HASH_BUCKETS],
    /// Head of the LRU list (NONE_IDX = empty).
    lru_head: u32,
    /// Tail of the LRU list (NONE_IDX = empty).
    lru_tail: u32,
    /// Current tick counter for access timestamps.
    current_tick: u64,
    /// Cumulative statistics.
    stats: DcacheStats,
}

impl Dcache {
    /// Create a new, empty dentry cache.
    pub fn new() -> Self {
        Self {
            entries: [const { DcacheEntry::empty() }; MAX_DENTRIES],
            buckets: [NONE_IDX; HASH_BUCKETS],
            lru_head: NONE_IDX,
            lru_tail: NONE_IDX,
            current_tick: 0,
            stats: DcacheStats::new(),
        }
    }

    /// Advance the tick counter (call from timer or system tick).
    pub fn tick(&mut self) {
        self.current_tick = self.current_tick.wrapping_add(1);
    }

    // ── Lookup: d_lookup ─────────────────────────────────────────────────

    /// Look up a dentry by (parent_inode, name).
    ///
    /// On a positive hit, the reference count is incremented.
    /// Returns the lookup result.
    pub fn d_lookup(&mut self, parent_inode: u64, name: &[u8]) -> DcacheLookupResult {
        self.stats.lookups += 1;

        if name.is_empty() || name.len() > NAME_MAX {
            return DcacheLookupResult::Miss;
        }

        let bucket = dcache_hash(parent_inode, name);
        let mut idx = self.buckets[bucket];

        while idx != NONE_IDX {
            let i = idx as usize;
            if i >= MAX_DENTRIES {
                break;
            }

            if self.entries[i].in_use
                && self.entries[i].parent_inode == parent_inode
                && self.entries[i].name_matches(name)
                && !self.entries[i].flags.invalidated
            {
                // Hit.
                self.entries[i].access_tick = self.current_tick;

                if self.entries[i].flags.negative {
                    self.stats.negative_hits += 1;
                    return DcacheLookupResult::NegativeHit;
                }

                self.entries[i].ref_count = self.entries[i].ref_count.saturating_add(1);
                // Remove from LRU if it was there.
                if self.entries[i].flags.on_lru {
                    self.lru_remove(i);
                }

                self.stats.hits += 1;
                return DcacheLookupResult::Found {
                    inode: self.entries[i].inode,
                    device_id: self.entries[i].device_id,
                };
            }

            idx = self.entries[i].hash_next;
        }

        self.stats.misses += 1;
        DcacheLookupResult::Miss
    }

    // ── Allocate: d_alloc ────────────────────────────────────────────────

    /// Allocate a new dentry and add it to the cache.
    ///
    /// Returns the index of the allocated entry.
    pub fn d_alloc(
        &mut self,
        parent_inode: u64,
        name: &[u8],
        inode: u64,
        device_id: u32,
    ) -> Result<usize> {
        if name.is_empty() || name.len() > NAME_MAX {
            return Err(Error::InvalidArgument);
        }

        // Auto-shrink if at high watermark.
        if self.stats.lru_entries as usize >= LRU_HIGH_WATERMARK {
            let target = self.stats.entries.saturating_sub(LRU_LOW_WATERMARK as u32);
            self.shrink_dcache(target as usize);
        }

        // Find a free slot.
        let idx = self
            .entries
            .iter()
            .position(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;

        let entry = &mut self.entries[idx];
        entry.parent_inode = parent_inode;
        entry.name[..name.len()].copy_from_slice(name);
        entry.name_len = name.len() as u16;
        entry.inode = inode;
        entry.device_id = device_id;
        entry.ref_count = 1;
        entry.flags = DentryFlags::new();
        entry.access_tick = self.current_tick;
        entry.hash_next = NONE_IDX;
        entry.lru_next = NONE_IDX;
        entry.lru_prev = NONE_IDX;
        entry.in_use = true;

        // Insert into hash chain.
        let bucket = dcache_hash(parent_inode, name);
        entry.hash_next = self.buckets[bucket];
        self.buckets[bucket] = idx as u32;

        self.stats.allocs += 1;
        self.stats.entries += 1;
        Ok(idx)
    }

    /// Allocate a negative dentry (name confirmed non-existent).
    pub fn d_alloc_negative(
        &mut self,
        parent_inode: u64,
        name: &[u8],
        device_id: u32,
    ) -> Result<usize> {
        let idx = self.d_alloc(parent_inode, name, 0, device_id)?;
        self.entries[idx].flags.negative = true;
        self.entries[idx].ref_count = 0;
        self.lru_push(idx);
        self.stats.negative_entries += 1;
        Ok(idx)
    }

    // ── Add: d_add ───────────────────────────────────────────────────────

    /// Instantiate a previously allocated dentry with an inode.
    ///
    /// This is used when a lookup discovered the inode after allocating
    /// a placeholder dentry.
    pub fn d_add(&mut self, idx: usize, inode: u64) -> Result<()> {
        if idx >= MAX_DENTRIES || !self.entries[idx].in_use {
            return Err(Error::NotFound);
        }
        if self.entries[idx].flags.negative {
            self.stats.negative_entries = self.stats.negative_entries.saturating_sub(1);
        }
        self.entries[idx].inode = inode;
        self.entries[idx].flags.negative = false;
        Ok(())
    }

    // ── Drop: d_drop ─────────────────────────────────────────────────────

    /// Remove a dentry from the hash table (unhash).
    ///
    /// The dentry remains allocated but is no longer findable via
    /// `d_lookup`.  Used when a file is deleted.
    pub fn d_drop(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_DENTRIES || !self.entries[idx].in_use {
            return Err(Error::NotFound);
        }

        let parent = self.entries[idx].parent_inode;
        let name_len = self.entries[idx].name_len as usize;
        let mut name_buf = [0u8; NAME_MAX];
        name_buf[..name_len].copy_from_slice(&self.entries[idx].name[..name_len]);
        let bucket = dcache_hash(parent, &name_buf[..name_len]);

        // Remove from hash chain.
        self.hash_remove(bucket, idx);

        // If unreferenced, free immediately.
        if self.entries[idx].ref_count == 0 {
            self.free_entry(idx);
        }
        Ok(())
    }

    // ── Reference counting: dget / dput ──────────────────────────────────

    /// Increment the reference count of a dentry.
    pub fn dget(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_DENTRIES || !self.entries[idx].in_use {
            return Err(Error::NotFound);
        }
        self.entries[idx].ref_count = self.entries[idx].ref_count.saturating_add(1);
        if self.entries[idx].flags.on_lru {
            self.lru_remove(idx);
        }
        Ok(())
    }

    /// Decrement the reference count of a dentry.
    ///
    /// When the count reaches zero, the dentry is moved to the LRU list
    /// for potential eviction.
    pub fn dput(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_DENTRIES || !self.entries[idx].in_use {
            return Err(Error::NotFound);
        }
        if self.entries[idx].ref_count == 0 {
            return Ok(());
        }
        self.entries[idx].ref_count -= 1;
        if self.entries[idx].ref_count == 0 {
            self.lru_push(idx);
        }
        Ok(())
    }

    // ── Invalidation ─────────────────────────────────────────────────────

    /// Invalidate a dentry, marking it for discard.
    pub fn d_invalidate(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_DENTRIES || !self.entries[idx].in_use {
            return Err(Error::NotFound);
        }
        self.entries[idx].flags.invalidated = true;
        if self.entries[idx].ref_count == 0 {
            self.d_drop(idx)?;
        }
        Ok(())
    }

    /// Invalidate all dentries for a given superblock/device.
    pub fn d_invalidate_sb(&mut self, device_id: u32) -> u32 {
        let mut count = 0u32;
        for i in 0..MAX_DENTRIES {
            if self.entries[i].in_use && self.entries[i].device_id == device_id {
                self.entries[i].flags.invalidated = true;
                if self.entries[i].ref_count == 0 {
                    self.free_entry(i);
                    count += 1;
                }
            }
        }
        count
    }

    // ── Splice alias ─────────────────────────────────────────────────────

    /// Splice an existing dentry to a new parent and name.
    ///
    /// Used for rename operations and cross-directory moves.
    pub fn d_splice_alias(&mut self, idx: usize, new_parent: u64, new_name: &[u8]) -> Result<()> {
        if idx >= MAX_DENTRIES || !self.entries[idx].in_use {
            return Err(Error::NotFound);
        }
        if new_name.is_empty() || new_name.len() > NAME_MAX {
            return Err(Error::InvalidArgument);
        }

        // Remove from old hash chain.
        let old_parent = self.entries[idx].parent_inode;
        let old_name_len = self.entries[idx].name_len as usize;
        let mut old_name = [0u8; NAME_MAX];
        old_name[..old_name_len].copy_from_slice(&self.entries[idx].name[..old_name_len]);
        let old_bucket = dcache_hash(old_parent, &old_name[..old_name_len]);
        self.hash_remove(old_bucket, idx);

        // Update entry.
        self.entries[idx].parent_inode = new_parent;
        self.entries[idx].name[..new_name.len()].copy_from_slice(new_name);
        self.entries[idx].name_len = new_name.len() as u16;
        // Zero out remaining name buffer.
        for b in &mut self.entries[idx].name[new_name.len()..] {
            *b = 0;
        }

        // Insert into new hash chain.
        let new_bucket = dcache_hash(new_parent, new_name);
        self.entries[idx].hash_next = self.buckets[new_bucket];
        self.buckets[new_bucket] = idx as u32;

        Ok(())
    }

    // ── Shrink ───────────────────────────────────────────────────────────

    /// Shrink the dcache by evicting up to `nr` unreferenced entries
    /// from the LRU list.
    ///
    /// Returns the number of entries actually freed.
    pub fn shrink_dcache(&mut self, nr: usize) -> usize {
        let mut freed = 0usize;
        let mut idx = self.lru_tail;

        while idx != NONE_IDX && freed < nr {
            let i = idx as usize;
            if i >= MAX_DENTRIES {
                break;
            }

            let prev = self.entries[i].lru_prev;

            if self.entries[i].in_use && self.entries[i].ref_count == 0 {
                // Remove from hash chain.
                let name_len = self.entries[i].name_len as usize;
                let parent = self.entries[i].parent_inode;
                let mut name_buf = [0u8; NAME_MAX];
                name_buf[..name_len].copy_from_slice(&self.entries[i].name[..name_len]);
                let bucket = dcache_hash(parent, &name_buf[..name_len]);
                self.hash_remove(bucket, i);

                // Remove from LRU.
                self.lru_remove(i);

                // Free the entry.
                self.free_entry_no_lru(i);
                freed += 1;
            }

            idx = prev;
        }

        self.stats.shrinks += 1;
        freed
    }

    /// Shrink all unreferenced entries for a superblock.
    pub fn shrink_dcache_sb(&mut self, device_id: u32) -> usize {
        let mut freed = 0usize;
        for i in 0..MAX_DENTRIES {
            if self.entries[i].in_use
                && self.entries[i].device_id == device_id
                && self.entries[i].ref_count == 0
            {
                let name_len = self.entries[i].name_len as usize;
                let parent = self.entries[i].parent_inode;
                let mut name_buf = [0u8; NAME_MAX];
                name_buf[..name_len].copy_from_slice(&self.entries[i].name[..name_len]);
                let bucket = dcache_hash(parent, &name_buf[..name_len]);
                self.hash_remove(bucket, i);

                if self.entries[i].flags.on_lru {
                    self.lru_remove(i);
                }
                self.free_entry_no_lru(i);
                freed += 1;
            }
        }
        freed
    }

    // ── Queries ──────────────────────────────────────────────────────────

    /// Return dcache statistics.
    pub fn stats(&self) -> DcacheStats {
        self.stats
    }

    /// Reset statistics counters.
    pub fn reset_stats(&mut self) {
        let entries = self.stats.entries;
        let lru = self.stats.lru_entries;
        let neg = self.stats.negative_entries;
        self.stats = DcacheStats::new();
        self.stats.entries = entries;
        self.stats.lru_entries = lru;
        self.stats.negative_entries = neg;
    }

    /// Return the number of cached entries.
    pub fn entry_count(&self) -> u32 {
        self.stats.entries
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Remove an entry from its hash chain.
    fn hash_remove(&mut self, bucket: usize, idx: usize) {
        if bucket >= HASH_BUCKETS {
            return;
        }

        let target = idx as u32;
        let mut prev = NONE_IDX;
        let mut cur = self.buckets[bucket];

        while cur != NONE_IDX {
            let c = cur as usize;
            if c >= MAX_DENTRIES {
                break;
            }

            if cur == target {
                // Found — unlink.
                let next = self.entries[c].hash_next;
                if prev == NONE_IDX {
                    self.buckets[bucket] = next;
                } else {
                    self.entries[prev as usize].hash_next = next;
                }
                self.entries[c].hash_next = NONE_IDX;
                return;
            }

            prev = cur;
            cur = self.entries[c].hash_next;
        }
    }

    /// Push an entry to the head of the LRU list.
    fn lru_push(&mut self, idx: usize) {
        if self.entries[idx].flags.on_lru {
            return;
        }

        self.entries[idx].flags.on_lru = true;
        self.entries[idx].lru_prev = NONE_IDX;
        self.entries[idx].lru_next = self.lru_head;

        if self.lru_head != NONE_IDX {
            self.entries[self.lru_head as usize].lru_prev = idx as u32;
        }
        self.lru_head = idx as u32;

        if self.lru_tail == NONE_IDX {
            self.lru_tail = idx as u32;
        }
        self.stats.lru_entries += 1;
    }

    /// Remove an entry from the LRU list.
    fn lru_remove(&mut self, idx: usize) {
        if !self.entries[idx].flags.on_lru {
            return;
        }

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
        self.entries[idx].flags.on_lru = false;
        self.stats.lru_entries = self.stats.lru_entries.saturating_sub(1);
    }

    /// Free an entry completely (updates stats, clears in_use).
    fn free_entry(&mut self, idx: usize) {
        if self.entries[idx].flags.on_lru {
            self.lru_remove(idx);
        }
        self.free_entry_no_lru(idx);
    }

    /// Free an entry without LRU manipulation (caller already handled).
    fn free_entry_no_lru(&mut self, idx: usize) {
        if self.entries[idx].flags.negative {
            self.stats.negative_entries = self.stats.negative_entries.saturating_sub(1);
        }
        self.entries[idx].in_use = false;
        self.stats.entries = self.stats.entries.saturating_sub(1);
        self.stats.frees += 1;
    }
}
