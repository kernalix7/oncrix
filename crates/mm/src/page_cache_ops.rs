// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page cache insert/lookup/remove operations.
//!
//! Implements the page cache — an in-memory cache of file pages
//! indexed by (file_id, page_offset). The cache uses a simple hash
//! table as a radix tree substitute for O(1) lookup.
//!
//! - [`PageCacheFlags`] — per-entry flags (dirty, locked, uptodate…)
//! - [`PageCacheEntry`] — a single cached page
//! - [`PageCacheBucket`] — hash bucket (chain of entries)
//! - [`PageCache`] — the main page cache
//! - [`PageCacheStats`] — hit/miss/eviction statistics
//!
//! Reference: `.kernelORG/` — `mm/filemap.c`, `include/linux/pagemap.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Number of hash buckets.
const NR_BUCKETS: usize = 128;

/// Maximum entries per bucket (chain length).
const MAX_CHAIN: usize = 16;

/// Maximum total entries in the cache.
const MAX_CACHE_ENTRIES: usize = 1024;

/// FNV-1a offset basis for hashing.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a prime.
const FNV_PRIME: u64 = 0x0100_0000_01b3;

// -------------------------------------------------------------------
// PageCacheFlags
// -------------------------------------------------------------------

/// Per-entry flags for a cached page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PageCacheFlags {
    /// Raw flag bits.
    bits: u32,
}

impl PageCacheFlags {
    /// Page data is valid and up-to-date.
    pub const UPTODATE: u32 = 1 << 0;
    /// Page has been modified.
    pub const DIRTY: u32 = 1 << 1;
    /// Page is locked for I/O.
    pub const LOCKED: u32 = 1 << 2;
    /// Page is referenced (accessed).
    pub const REFERENCED: u32 = 1 << 3;
    /// Page is under writeback.
    pub const WRITEBACK: u32 = 1 << 4;
    /// Page is a readahead page.
    pub const READAHEAD: u32 = 1 << 5;

    /// Creates empty flags.
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates from raw bits.
    pub fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    /// Returns raw bits.
    pub fn bits(self) -> u32 {
        self.bits
    }

    /// Tests if a flag is set.
    pub fn contains(self, flag: u32) -> bool {
        self.bits & flag == flag
    }

    /// Sets a flag.
    pub fn set(self, flag: u32) -> Self {
        Self {
            bits: self.bits | flag,
        }
    }

    /// Clears a flag.
    pub fn clear(self, flag: u32) -> Self {
        Self {
            bits: self.bits & !flag,
        }
    }
}

// -------------------------------------------------------------------
// PageCacheEntry
// -------------------------------------------------------------------

/// A single cached page.
#[derive(Debug, Clone, Copy)]
pub struct PageCacheEntry {
    /// File identifier (inode or file descriptor).
    pub file_id: u64,
    /// Page offset within the file (in pages).
    pub index: u64,
    /// Cache flags.
    pub flags: PageCacheFlags,
    /// Page data (simplified as a fixed buffer).
    pub page_data: [u8; PAGE_SIZE],
    /// Whether this entry is in use.
    pub active: bool,
    /// Reference count.
    pub refcount: u32,
}

impl Default for PageCacheEntry {
    fn default() -> Self {
        Self {
            file_id: 0,
            index: 0,
            flags: PageCacheFlags::empty(),
            page_data: [0u8; PAGE_SIZE],
            active: false,
            refcount: 0,
        }
    }
}

impl PageCacheEntry {
    /// Creates a new cache entry.
    pub fn new(file_id: u64, index: u64) -> Self {
        Self {
            file_id,
            index,
            flags: PageCacheFlags::empty().set(PageCacheFlags::UPTODATE),
            active: true,
            refcount: 1,
            ..Self::default()
        }
    }

    /// Returns `true` if this entry matches the given key.
    fn matches(&self, file_id: u64, index: u64) -> bool {
        self.active && self.file_id == file_id && self.index == index
    }

    /// Acquires a reference.
    pub fn get_ref(&mut self) {
        self.refcount += 1;
    }

    /// Releases a reference. Returns `true` if refcount reached 0.
    pub fn put_ref(&mut self) -> bool {
        if self.refcount > 0 {
            self.refcount -= 1;
        }
        self.refcount == 0
    }
}

// -------------------------------------------------------------------
// PageCacheBucket
// -------------------------------------------------------------------

/// Hash bucket containing a chain of entries (indices into the
/// global entry array).
#[derive(Debug, Clone, Copy, Default)]
pub struct PageCacheBucket {
    /// Entry indices in the global array.
    entries: [usize; MAX_CHAIN],
    /// Number of entries in this bucket.
    count: usize,
}

impl PageCacheBucket {
    /// Adds an entry index to the bucket.
    fn add(&mut self, entry_idx: usize) -> Result<()> {
        if self.count >= MAX_CHAIN {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = entry_idx;
        self.count += 1;
        Ok(())
    }

    /// Removes an entry index from the bucket.
    fn remove(&mut self, entry_idx: usize) -> bool {
        for i in 0..self.count {
            if self.entries[i] == entry_idx {
                for j in i..self.count - 1 {
                    self.entries[j] = self.entries[j + 1];
                }
                self.count -= 1;
                return true;
            }
        }
        false
    }
}

// -------------------------------------------------------------------
// PageCacheStats
// -------------------------------------------------------------------

/// Page cache statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageCacheStats {
    /// Cache hits (find_get_page succeeded).
    pub hits: u64,
    /// Cache misses.
    pub misses: u64,
    /// Insertions.
    pub inserts: u64,
    /// Deletions.
    pub deletes: u64,
    /// Dirty pages written back.
    pub writebacks: u64,
    /// Current number of cached pages.
    pub nr_pages: u64,
}

impl PageCacheStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// PageCache
// -------------------------------------------------------------------

/// The main page cache.
///
/// Uses a hash table of buckets, each pointing to entries in a
/// flat entry array.
pub struct PageCache {
    /// Global entry storage.
    entries: [PageCacheEntry; MAX_CACHE_ENTRIES],
    /// Hash buckets.
    buckets: [PageCacheBucket; NR_BUCKETS],
    /// Number of active entries.
    count: usize,
    /// Statistics.
    stats: PageCacheStats,
    /// Free list (indices of available entry slots).
    free_list: [usize; MAX_CACHE_ENTRIES],
    /// Number of free slots.
    free_count: usize,
}

impl Default for PageCache {
    fn default() -> Self {
        let mut free_list = [0usize; MAX_CACHE_ENTRIES];
        for (i, slot) in free_list.iter_mut().enumerate() {
            *slot = i;
        }
        Self {
            entries: [const {
                PageCacheEntry {
                    file_id: 0,
                    index: 0,
                    flags: PageCacheFlags { bits: 0 },
                    page_data: [0u8; PAGE_SIZE],
                    active: false,
                    refcount: 0,
                }
            }; MAX_CACHE_ENTRIES],
            buckets: [PageCacheBucket {
                entries: [0usize; MAX_CHAIN],
                count: 0,
            }; NR_BUCKETS],
            count: 0,
            stats: PageCacheStats::default(),
            free_list,
            free_count: MAX_CACHE_ENTRIES,
        }
    }
}

impl PageCache {
    /// Creates a new empty page cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Computes the bucket index for a (file_id, page_index) key.
    fn bucket_index(file_id: u64, index: u64) -> usize {
        let mut h = FNV_OFFSET;
        let key = file_id.wrapping_mul(31).wrapping_add(index);
        for byte in key.to_le_bytes() {
            h ^= byte as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        (h as usize) % NR_BUCKETS
    }

    /// Adds a page to the cache.
    pub fn add_to_page_cache(&mut self, file_id: u64, index: u64, data: &[u8]) -> Result<usize> {
        // Check for duplicate.
        if self.find_entry(file_id, index).is_some() {
            return Err(Error::AlreadyExists);
        }

        // Allocate a slot.
        if self.free_count == 0 {
            return Err(Error::OutOfMemory);
        }
        self.free_count -= 1;
        let slot = self.free_list[self.free_count];

        // Initialise entry.
        self.entries[slot] = PageCacheEntry::new(file_id, index);
        let copy_len = data.len().min(PAGE_SIZE);
        self.entries[slot].page_data[..copy_len].copy_from_slice(&data[..copy_len]);

        // Add to hash bucket.
        let bucket = Self::bucket_index(file_id, index);
        self.buckets[bucket].add(slot)?;

        self.count += 1;
        self.stats.inserts += 1;
        self.stats.nr_pages = self.count as u64;
        Ok(slot)
    }

    /// Removes a page from the cache.
    pub fn delete_from_page_cache(&mut self, file_id: u64, index: u64) -> Result<()> {
        let slot = self.find_entry(file_id, index).ok_or(Error::NotFound)?;

        let bucket = Self::bucket_index(file_id, index);
        self.buckets[bucket].remove(slot);
        self.entries[slot].active = false;

        // Return slot to free list.
        self.free_list[self.free_count] = slot;
        self.free_count += 1;
        self.count -= 1;
        self.stats.deletes += 1;
        self.stats.nr_pages = self.count as u64;
        Ok(())
    }

    /// Finds a page and returns a copy of its data (non-locking).
    pub fn find_get_page(&mut self, file_id: u64, index: u64) -> Option<usize> {
        match self.find_entry(file_id, index) {
            Some(slot) => {
                self.entries[slot].get_ref();
                self.entries[slot].flags = self.entries[slot].flags.set(PageCacheFlags::REFERENCED);
                self.stats.hits += 1;
                Some(slot)
            }
            None => {
                self.stats.misses += 1;
                None
            }
        }
    }

    /// Finds a page and locks it (sets LOCKED flag).
    pub fn find_lock_page(&mut self, file_id: u64, index: u64) -> Result<Option<usize>> {
        match self.find_entry(file_id, index) {
            Some(slot) => {
                if self.entries[slot].flags.contains(PageCacheFlags::LOCKED) {
                    return Err(Error::Busy);
                }
                self.entries[slot].flags = self.entries[slot].flags.set(PageCacheFlags::LOCKED);
                self.entries[slot].get_ref();
                self.stats.hits += 1;
                Ok(Some(slot))
            }
            None => {
                self.stats.misses += 1;
                Ok(None)
            }
        }
    }

    /// Finds the next miss: smallest index >= `start` for the given
    /// file that is NOT in cache.
    pub fn page_cache_next_miss(&self, file_id: u64, start: u64, max_scan: u64) -> u64 {
        for offset in 0..max_scan {
            let idx = start + offset;
            if self.find_entry(file_id, idx).is_none() {
                return idx;
            }
        }
        start + max_scan
    }

    /// Returns a reference to the entry at the given slot.
    pub fn get_entry(&self, slot: usize) -> Option<&PageCacheEntry> {
        if slot < MAX_CACHE_ENTRIES && self.entries[slot].active {
            Some(&self.entries[slot])
        } else {
            None
        }
    }

    /// Returns the number of cached pages.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &PageCacheStats {
        &self.stats
    }

    /// Finds the entry slot for a (file_id, index) key.
    fn find_entry(&self, file_id: u64, index: u64) -> Option<usize> {
        let bucket = Self::bucket_index(file_id, index);
        for i in 0..self.buckets[bucket].count {
            let slot = self.buckets[bucket].entries[i];
            if self.entries[slot].matches(file_id, index) {
                return Some(slot);
            }
        }
        None
    }
}
