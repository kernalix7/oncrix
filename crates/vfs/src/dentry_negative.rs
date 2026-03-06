// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Negative dentry cache — tracking confirmed-absent names.
//!
//! A negative dentry records that a filename was looked up and found NOT to
//! exist. Caching negative lookups avoids repeated disk I/O for `open` of
//! non-existent files.

use oncrix_lib::Result;

/// Maximum number of negative dentry entries.
pub const MAX_NEG_DENTRIES: usize = 256;

/// Maximum age of a negative dentry before it is considered stale (seconds).
pub const NEG_DENTRY_TTL: u64 = 5;

/// Hash table size for the negative dentry index.
const NEG_HASH_BUCKETS: usize = 64;

/// A single negative dentry entry.
#[derive(Clone, Copy)]
pub struct NegDentry {
    /// Parent directory superblock ID.
    pub parent_sb_id: u64,
    /// Parent directory inode number.
    pub parent_ino: u64,
    /// Hash of the filename that was looked up.
    pub name_hash: u64,
    /// Wall-clock time when this entry was cached (seconds).
    pub cached_at: i64,
    /// Whether this slot is occupied.
    pub valid: bool,
}

impl NegDentry {
    const fn empty() -> Self {
        Self {
            parent_sb_id: 0,
            parent_ino: 0,
            name_hash: 0,
            cached_at: 0,
            valid: false,
        }
    }

    /// Return `true` if the entry has exceeded its TTL.
    pub fn is_stale(&self, now: i64) -> bool {
        let age = now.saturating_sub(self.cached_at);
        (age as u64) >= NEG_DENTRY_TTL
    }
}

/// Hash index bucket for the negative dentry cache.
#[derive(Clone, Copy)]
struct Bucket {
    /// Entry pool indices in this bucket (u16::MAX = empty).
    slots: [u16; 4],
    count: u8,
}

impl Bucket {
    const fn new() -> Self {
        Self {
            slots: [u16::MAX; 4],
            count: 0,
        }
    }
}

/// Statistics for the negative dentry cache.
#[derive(Debug, Clone, Copy, Default)]
pub struct NegCacheStats {
    /// Total entries currently cached.
    pub count: u32,
    /// Total cache hits.
    pub hits: u64,
    /// Total cache misses.
    pub misses: u64,
    /// Total entries evicted (TTL expiry).
    pub evictions: u64,
}

/// The negative dentry cache.
pub struct NegDentryCache {
    entries: [NegDentry; MAX_NEG_DENTRIES],
    buckets: [Bucket; NEG_HASH_BUCKETS],
    stats: NegCacheStats,
    next_slot: usize,
}

impl NegDentryCache {
    /// Create a new, empty negative dentry cache.
    pub fn new() -> Self {
        Self {
            entries: [const { NegDentry::empty() }; MAX_NEG_DENTRIES],
            buckets: [const { Bucket::new() }; NEG_HASH_BUCKETS],
            stats: NegCacheStats::default(),
            next_slot: 0,
        }
    }

    fn bucket_idx(parent_sb_id: u64, parent_ino: u64, name_hash: u64) -> usize {
        let h = parent_sb_id.wrapping_mul(0x517cc1b727220a95)
            ^ parent_ino.wrapping_mul(0x6c62272e07bb0142)
            ^ name_hash;
        (h as usize) % NEG_HASH_BUCKETS
    }

    /// Look up a negative entry. Returns `true` if the name is known-absent.
    pub fn lookup(&mut self, parent_sb_id: u64, parent_ino: u64, name_hash: u64, now: i64) -> bool {
        let bidx = Self::bucket_idx(parent_sb_id, parent_ino, name_hash);
        let bucket = &self.buckets[bidx];
        for i in 0..bucket.count as usize {
            let eidx = bucket.slots[i] as usize;
            if eidx >= MAX_NEG_DENTRIES {
                continue;
            }
            let entry = &self.entries[eidx];
            if !entry.valid {
                continue;
            }
            if entry.parent_sb_id == parent_sb_id
                && entry.parent_ino == parent_ino
                && entry.name_hash == name_hash
            {
                if entry.is_stale(now) {
                    // Evict stale entry.
                    self.entries[eidx] = NegDentry::empty();
                    self.stats.evictions += 1;
                    self.stats.count = self.stats.count.saturating_sub(1);
                    self.stats.misses += 1;
                    return false;
                }
                self.stats.hits += 1;
                return true;
            }
        }
        self.stats.misses += 1;
        false
    }

    /// Insert a negative entry for a confirmed-absent name.
    pub fn insert(
        &mut self,
        parent_sb_id: u64,
        parent_ino: u64,
        name_hash: u64,
        now: i64,
    ) -> Result<()> {
        // Find a free slot starting from next_slot.
        let mut found = None;
        for offset in 0..MAX_NEG_DENTRIES {
            let idx = (self.next_slot + offset) % MAX_NEG_DENTRIES;
            if !self.entries[idx].valid {
                found = Some(idx);
                break;
            }
        }
        let idx = match found {
            Some(i) => i,
            None => {
                // Evict oldest entry.
                self.evict_oldest();
                let idx = self.next_slot % MAX_NEG_DENTRIES;
                self.next_slot = (self.next_slot + 1) % MAX_NEG_DENTRIES;
                idx
            }
        };

        self.entries[idx] = NegDentry {
            parent_sb_id,
            parent_ino,
            name_hash,
            cached_at: now,
            valid: true,
        };
        self.next_slot = (idx + 1) % MAX_NEG_DENTRIES;
        self.stats.count += 1;

        // Register in bucket.
        let bidx = Self::bucket_idx(parent_sb_id, parent_ino, name_hash);
        let bucket = &mut self.buckets[bidx];
        // Find an empty slot in the bucket.
        for i in 0..4 {
            if bucket.slots[i] == u16::MAX {
                bucket.slots[i] = idx as u16;
                if (bucket.count as usize) < 4 {
                    bucket.count += 1;
                }
                return Ok(());
            }
        }
        // Bucket full — evict first slot.
        bucket.slots[0] = idx as u16;
        Ok(())
    }

    /// Invalidate a negative entry when the file is created.
    pub fn invalidate(&mut self, parent_sb_id: u64, parent_ino: u64, name_hash: u64) {
        for entry in self.entries.iter_mut() {
            if entry.valid
                && entry.parent_sb_id == parent_sb_id
                && entry.parent_ino == parent_ino
                && entry.name_hash == name_hash
            {
                *entry = NegDentry::empty();
                self.stats.count = self.stats.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Invalidate all negative entries for a given parent directory.
    pub fn invalidate_dir(&mut self, parent_sb_id: u64, parent_ino: u64) -> u32 {
        let mut removed = 0u32;
        for entry in self.entries.iter_mut() {
            if entry.valid && entry.parent_sb_id == parent_sb_id && entry.parent_ino == parent_ino {
                *entry = NegDentry::empty();
                removed += 1;
            }
        }
        self.stats.count = self.stats.count.saturating_sub(removed);
        removed
    }

    fn evict_oldest(&mut self) {
        let mut oldest_at = i64::MAX;
        let mut oldest_idx = 0;
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.valid && entry.cached_at < oldest_at {
                oldest_at = entry.cached_at;
                oldest_idx = i;
            }
        }
        if self.entries[oldest_idx].valid {
            self.entries[oldest_idx] = NegDentry::empty();
            self.stats.count = self.stats.count.saturating_sub(1);
            self.stats.evictions += 1;
        }
    }

    /// Return a snapshot of cache statistics.
    pub fn stats(&self) -> NegCacheStats {
        self.stats
    }
}

impl Default for NegDentryCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a simple hash of a filename for use with the negative dentry cache.
pub fn hash_filename(name: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis.
    for &b in name {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3); // FNV-1a prime.
    }
    hash
}
