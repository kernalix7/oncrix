// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Inode cache (icache) — hash-based inode lifecycle management.
//!
//! Provides a fixed-size hash table for caching active inodes,
//! tracking reference counts, and managing inode eviction.

use oncrix_lib::{Error, Result};

/// Maximum number of cached inodes.
pub const ICACHE_SIZE: usize = 512;

/// Inode cache hash buckets (prime for distribution).
const ICACHE_BUCKETS: usize = 127;

/// State of a cached inode entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeCacheState {
    /// Entry is free/unused.
    Free,
    /// Inode is actively referenced.
    Active,
    /// Inode is dirty and needs writeback.
    Dirty,
    /// Inode is being evicted.
    Evicting,
}

/// A single entry in the inode cache.
#[derive(Debug, Clone, Copy)]
pub struct InodeCacheEntry {
    /// Filesystem superblock identifier.
    pub sb_id: u64,
    /// Inode number within the filesystem.
    pub ino: u64,
    /// Reference count (0 = eligible for eviction).
    pub refcount: u32,
    /// Generation counter for ABA prevention.
    pub generation: u32,
    /// Cache state.
    pub state: InodeCacheState,
    /// Inode size in bytes.
    pub size: u64,
    /// Inode mode/permissions.
    pub mode: u32,
    /// Link count.
    pub nlink: u32,
    /// User ID of owner.
    pub uid: u32,
    /// Group ID of owner.
    pub gid: u32,
    /// Last access time (seconds since epoch).
    pub atime: i64,
    /// Last modification time.
    pub mtime: i64,
    /// Last status-change time.
    pub ctime: i64,
}

impl InodeCacheEntry {
    /// Create a new free (empty) entry.
    pub const fn new_free() -> Self {
        Self {
            sb_id: 0,
            ino: 0,
            refcount: 0,
            generation: 0,
            state: InodeCacheState::Free,
            size: 0,
            mode: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
        }
    }
}

impl Default for InodeCacheEntry {
    fn default() -> Self {
        Self::new_free()
    }
}

/// Hash-table bucket for the inode cache.
#[derive(Debug, Clone, Copy)]
pub struct IcacheBucket {
    /// Index into the entry pool, or `u16::MAX` for empty.
    pub head: u16,
    /// Number of entries chained in this bucket.
    pub count: u16,
}

impl IcacheBucket {
    const fn new() -> Self {
        Self {
            head: u16::MAX,
            count: 0,
        }
    }
}

impl Default for IcacheBucket {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for the inode cache.
#[derive(Debug, Clone, Copy, Default)]
pub struct IcacheStats {
    /// Total cache hits.
    pub hits: u64,
    /// Total cache misses.
    pub misses: u64,
    /// Total evictions performed.
    pub evictions: u64,
    /// Current active entries.
    pub active: u32,
}

/// The inode cache subsystem.
pub struct InodeCache {
    entries: [InodeCacheEntry; ICACHE_SIZE],
    buckets: [IcacheBucket; ICACHE_BUCKETS],
    stats: IcacheStats,
    next_slot: usize,
}

impl InodeCache {
    /// Create a new, empty inode cache.
    pub fn new() -> Self {
        Self {
            entries: [const { InodeCacheEntry::new_free() }; ICACHE_SIZE],
            buckets: [const { IcacheBucket::new() }; ICACHE_BUCKETS],
            stats: IcacheStats::default(),
            next_slot: 0,
        }
    }

    /// Compute the bucket index for a given (sb_id, ino) pair.
    fn bucket_for(sb_id: u64, ino: u64) -> usize {
        let hash =
            sb_id.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ ino.wrapping_mul(0x6c62_272e_07bb_0142);
        (hash as usize) % ICACHE_BUCKETS
    }

    /// Look up an inode in the cache. Returns the slot index if found.
    pub fn lookup(&mut self, sb_id: u64, ino: u64) -> Option<usize> {
        let bucket = Self::bucket_for(sb_id, ino);
        // Linear scan over all entries matching bucket (simple open-address).
        for (idx, entry) in self.entries.iter_mut().enumerate() {
            if entry.state != InodeCacheState::Free && entry.sb_id == sb_id && entry.ino == ino {
                entry.refcount += 1;
                self.stats.hits += 1;
                let _ = bucket;
                return Some(idx);
            }
        }
        self.stats.misses += 1;
        None
    }

    /// Insert an inode entry into the cache. Returns the assigned slot.
    pub fn insert(&mut self, entry: InodeCacheEntry) -> Result<usize> {
        // Try to find a free slot starting from next_slot.
        for offset in 0..ICACHE_SIZE {
            let idx = (self.next_slot + offset) % ICACHE_SIZE;
            if self.entries[idx].state == InodeCacheState::Free {
                self.entries[idx] = entry;
                self.entries[idx].refcount = 1;
                self.entries[idx].state = InodeCacheState::Active;
                self.next_slot = (idx + 1) % ICACHE_SIZE;
                self.stats.active += 1;
                let bucket = Self::bucket_for(entry.sb_id, entry.ino);
                self.buckets[bucket].count += 1;
                return Ok(idx);
            }
        }
        // No free slots — try eviction.
        self.evict_one()?;
        self.insert(entry)
    }

    /// Evict one unreferenced entry from the cache.
    fn evict_one(&mut self) -> Result<()> {
        for entry in self.entries.iter_mut() {
            if entry.state == InodeCacheState::Active && entry.refcount == 0 {
                let bucket = Self::bucket_for(entry.sb_id, entry.ino);
                if self.buckets[bucket].count > 0 {
                    self.buckets[bucket].count -= 1;
                }
                *entry = InodeCacheEntry::new_free();
                self.stats.evictions += 1;
                self.stats.active = self.stats.active.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Drop a reference to the inode at `slot`. Returns true if refcount hit 0.
    pub fn put(&mut self, slot: usize) -> Result<bool> {
        if slot >= ICACHE_SIZE {
            return Err(Error::InvalidArgument);
        }
        let entry = &mut self.entries[slot];
        if entry.state == InodeCacheState::Free {
            return Err(Error::NotFound);
        }
        entry.refcount = entry.refcount.saturating_sub(1);
        Ok(entry.refcount == 0)
    }

    /// Mark an inode as dirty (needs writeback).
    pub fn mark_dirty(&mut self, slot: usize) -> Result<()> {
        if slot >= ICACHE_SIZE {
            return Err(Error::InvalidArgument);
        }
        let entry = &mut self.entries[slot];
        if entry.state == InodeCacheState::Active {
            entry.state = InodeCacheState::Dirty;
            Ok(())
        } else if entry.state == InodeCacheState::Dirty {
            Ok(())
        } else {
            Err(Error::InvalidArgument)
        }
    }

    /// Retrieve a reference to the entry at `slot`.
    pub fn get(&self, slot: usize) -> Option<&InodeCacheEntry> {
        if slot >= ICACHE_SIZE {
            return None;
        }
        let e = &self.entries[slot];
        if e.state != InodeCacheState::Free {
            Some(e)
        } else {
            None
        }
    }

    /// Return a snapshot of current cache statistics.
    pub fn stats(&self) -> IcacheStats {
        self.stats
    }

    /// Invalidate all entries belonging to `sb_id` (on unmount).
    pub fn invalidate_super(&mut self, sb_id: u64) -> u32 {
        let mut count = 0u32;
        for entry in self.entries.iter_mut() {
            if entry.sb_id == sb_id && entry.state != InodeCacheState::Free {
                *entry = InodeCacheEntry::new_free();
                count += 1;
            }
        }
        self.stats.active = self.stats.active.saturating_sub(count);
        count
    }
}

impl Default for InodeCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize the global inode cache subsystem.
///
/// Must be called once during VFS initialization before any filesystem mounts.
pub fn icache_init() -> InodeCache {
    InodeCache::new()
}

/// Shrink the cache by evicting all zero-refcount entries.
///
/// Returns the number of entries freed.
pub fn icache_shrink(cache: &mut InodeCache) -> u32 {
    let mut freed = 0u32;
    for entry in cache.entries.iter_mut() {
        if entry.state != InodeCacheState::Free && entry.refcount == 0 {
            let bucket = InodeCache::bucket_for(entry.sb_id, entry.ino);
            if cache.buckets[bucket].count > 0 {
                cache.buckets[bucket].count -= 1;
            }
            *entry = InodeCacheEntry::new_free();
            freed += 1;
        }
    }
    cache.stats.evictions += freed as u64;
    cache.stats.active = cache.stats.active.saturating_sub(freed);
    freed
}
