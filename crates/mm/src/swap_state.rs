// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Swap cache management.
//!
//! Implements the swap cache — an in-memory cache of pages that are
//! also stored in swap. When a page is swapped out, it stays in the
//! swap cache until it is either reclaimed or faulted back in. This
//! avoids redundant disk I/O for pages that are swapped out and
//! faulted back quickly.
//!
//! - [`SwapEntry`] — swap device + offset identifier
//! - [`SwapCacheEntry`] — a single cached swap page
//! - [`SwapCache`] — the main swap cache
//! - [`SwapCacheStats`] — hit/miss/eviction statistics
//!
//! Reference: `.kernelORG/` — `mm/swap_state.c`, `include/linux/swap.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum entries in the swap cache.
const MAX_SWAP_CACHE: usize = 512;

/// Number of hash buckets for swap cache lookup.
const NR_BUCKETS: usize = 64;

/// Maximum chain length per bucket.
const MAX_CHAIN: usize = 16;

/// Maximum number of swap devices.
const MAX_SWAP_DEVICES: usize = 4;

// -------------------------------------------------------------------
// SwapEntry
// -------------------------------------------------------------------

/// A swap entry identifier: (device, offset) tuple packed into a u64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SwapEntry {
    /// Swap device index.
    pub device: u16,
    /// Offset within the swap device (in pages).
    pub offset: u64,
}

impl SwapEntry {
    /// Creates a new swap entry.
    pub fn new(device: u16, offset: u64) -> Self {
        Self { device, offset }
    }

    /// Packs into a single u64.
    pub fn to_u64(self) -> u64 {
        ((self.device as u64) << 48) | self.offset
    }

    /// Unpacks from a u64.
    pub fn from_u64(val: u64) -> Self {
        Self {
            device: (val >> 48) as u16,
            offset: val & 0x0000_FFFF_FFFF_FFFF,
        }
    }

    /// Returns `true` if this is a null (invalid) swap entry.
    pub fn is_null(self) -> bool {
        self.device == 0 && self.offset == 0
    }
}

// -------------------------------------------------------------------
// SwapCacheFlags
// -------------------------------------------------------------------

/// Flags for a swap cache entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SwapCacheFlags {
    /// Raw flag bits.
    bits: u32,
}

impl SwapCacheFlags {
    /// Entry has valid data.
    pub const VALID: u32 = 1 << 0;
    /// Entry is dirty (modified since last swap-out).
    pub const DIRTY: u32 = 1 << 1;
    /// Entry is locked.
    pub const LOCKED: u32 = 1 << 2;
    /// Entry is under writeback.
    pub const WRITEBACK: u32 = 1 << 3;

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

    /// Tests a flag.
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
// SwapCacheEntry
// -------------------------------------------------------------------

/// A single cached swap page.
#[derive(Debug, Clone, Copy)]
pub struct SwapCacheEntry {
    /// Swap entry identifier.
    pub swap_entry: SwapEntry,
    /// Page data.
    pub page_data: [u8; PAGE_SIZE],
    /// Cache flags.
    pub flags: SwapCacheFlags,
    /// Reference count (number of PTEs pointing here).
    pub refcount: u32,
    /// Whether this slot is in use.
    pub active: bool,
}

impl Default for SwapCacheEntry {
    fn default() -> Self {
        Self {
            swap_entry: SwapEntry::default(),
            page_data: [0u8; PAGE_SIZE],
            flags: SwapCacheFlags::empty(),
            refcount: 0,
            active: false,
        }
    }
}

impl SwapCacheEntry {
    /// Creates a new swap cache entry.
    pub fn new(swap_entry: SwapEntry) -> Self {
        Self {
            swap_entry,
            flags: SwapCacheFlags::empty().set(SwapCacheFlags::VALID),
            refcount: 1,
            active: true,
            ..Self::default()
        }
    }

    /// Duplicates the swap entry (increments reference count).
    pub fn swap_duplicate(&mut self) {
        self.refcount += 1;
    }

    /// Releases one reference. Returns `true` if refcount reached 0.
    pub fn swap_free(&mut self) -> bool {
        if self.refcount > 0 {
            self.refcount -= 1;
        }
        self.refcount == 0
    }
}

// -------------------------------------------------------------------
// SwapCacheBucket
// -------------------------------------------------------------------

/// Hash bucket for swap cache lookup.
#[derive(Debug, Clone, Copy, Default)]
struct SwapCacheBucket {
    /// Entry indices.
    entries: [usize; MAX_CHAIN],
    /// Number of entries.
    count: usize,
}

impl SwapCacheBucket {
    /// Adds an entry index.
    fn add(&mut self, idx: usize) -> Result<()> {
        if self.count >= MAX_CHAIN {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = idx;
        self.count += 1;
        Ok(())
    }

    /// Removes an entry index.
    fn remove(&mut self, idx: usize) -> bool {
        for i in 0..self.count {
            if self.entries[i] == idx {
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
// SwapCacheStats
// -------------------------------------------------------------------

/// Swap cache statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapCacheStats {
    /// Cache hits.
    pub hits: u64,
    /// Cache misses.
    pub misses: u64,
    /// Insertions.
    pub inserts: u64,
    /// Deletions.
    pub deletes: u64,
    /// Duplicate (reference increment) operations.
    pub duplicates: u64,
    /// Free (reference decrement) operations.
    pub frees: u64,
    /// Current number of cached pages.
    pub nr_pages: u64,
}

impl SwapCacheStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// SwapCache
// -------------------------------------------------------------------

/// The main swap cache.
pub struct SwapCache {
    /// Entry storage.
    entries: [SwapCacheEntry; MAX_SWAP_CACHE],
    /// Hash buckets.
    buckets: [SwapCacheBucket; NR_BUCKETS],
    /// Free list.
    free_list: [usize; MAX_SWAP_CACHE],
    /// Free list count.
    free_count: usize,
    /// Active entry count.
    count: usize,
    /// Statistics.
    stats: SwapCacheStats,
}

impl Default for SwapCache {
    fn default() -> Self {
        let mut free_list = [0usize; MAX_SWAP_CACHE];
        for (i, slot) in free_list.iter_mut().enumerate() {
            *slot = i;
        }
        Self {
            entries: [const {
                SwapCacheEntry {
                    swap_entry: SwapEntry {
                        device: 0,
                        offset: 0,
                    },
                    page_data: [0u8; PAGE_SIZE],
                    flags: SwapCacheFlags { bits: 0 },
                    refcount: 0,
                    active: false,
                }
            }; MAX_SWAP_CACHE],
            buckets: [SwapCacheBucket {
                entries: [0usize; MAX_CHAIN],
                count: 0,
            }; NR_BUCKETS],
            free_list,
            free_count: MAX_SWAP_CACHE,
            count: 0,
            stats: SwapCacheStats::default(),
        }
    }
}

impl SwapCache {
    /// Creates a new empty swap cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Computes the bucket index for a swap entry.
    fn bucket_index(entry: SwapEntry) -> usize {
        let val = entry.to_u64();
        ((val >> 12) as usize) % NR_BUCKETS
    }

    /// Adds a page to the swap cache.
    pub fn add_to_swap_cache(&mut self, swap_entry: SwapEntry, data: &[u8]) -> Result<usize> {
        // Check duplicate.
        if self.find_slot(swap_entry).is_some() {
            return Err(Error::AlreadyExists);
        }

        if self.free_count == 0 {
            return Err(Error::OutOfMemory);
        }

        self.free_count -= 1;
        let slot = self.free_list[self.free_count];

        self.entries[slot] = SwapCacheEntry::new(swap_entry);
        let copy_len = data.len().min(PAGE_SIZE);
        self.entries[slot].page_data[..copy_len].copy_from_slice(&data[..copy_len]);

        let bucket = Self::bucket_index(swap_entry);
        self.buckets[bucket].add(slot)?;

        self.count += 1;
        self.stats.inserts += 1;
        self.stats.nr_pages = self.count as u64;
        Ok(slot)
    }

    /// Removes a page from the swap cache.
    pub fn delete_from_swap_cache(&mut self, swap_entry: SwapEntry) -> Result<()> {
        let slot = self.find_slot(swap_entry).ok_or(Error::NotFound)?;

        let bucket = Self::bucket_index(swap_entry);
        self.buckets[bucket].remove(slot);
        self.entries[slot].active = false;

        self.free_list[self.free_count] = slot;
        self.free_count += 1;
        self.count -= 1;
        self.stats.deletes += 1;
        self.stats.nr_pages = self.count as u64;
        Ok(())
    }

    /// Looks up a swap cache entry.
    pub fn lookup_swap_cache(&mut self, swap_entry: SwapEntry) -> Option<usize> {
        match self.find_slot(swap_entry) {
            Some(slot) => {
                self.entries[slot].refcount += 1;
                self.stats.hits += 1;
                Some(slot)
            }
            None => {
                self.stats.misses += 1;
                None
            }
        }
    }

    /// Increments the reference count for a swap entry.
    pub fn swap_duplicate(&mut self, swap_entry: SwapEntry) -> Result<()> {
        let slot = self.find_slot(swap_entry).ok_or(Error::NotFound)?;
        self.entries[slot].swap_duplicate();
        self.stats.duplicates += 1;
        Ok(())
    }

    /// Decrements the reference count. Removes the entry if it
    /// reaches zero.
    pub fn swap_free(&mut self, swap_entry: SwapEntry) -> Result<bool> {
        let slot = self.find_slot(swap_entry).ok_or(Error::NotFound)?;
        self.stats.frees += 1;
        if self.entries[slot].swap_free() {
            self.delete_from_swap_cache(swap_entry)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Returns the total number of pages in the swap cache.
    pub fn total_swapcache_pages(&self) -> usize {
        self.count
    }

    /// Returns a reference to the entry at the given slot.
    pub fn get_entry(&self, slot: usize) -> Option<&SwapCacheEntry> {
        if slot < MAX_SWAP_CACHE && self.entries[slot].active {
            Some(&self.entries[slot])
        } else {
            None
        }
    }

    /// Returns statistics.
    pub fn stats(&self) -> &SwapCacheStats {
        &self.stats
    }

    /// Finds the slot for a swap entry.
    fn find_slot(&self, swap_entry: SwapEntry) -> Option<usize> {
        let bucket = Self::bucket_index(swap_entry);
        for i in 0..self.buckets[bucket].count {
            let slot = self.buckets[bucket].entries[i];
            if self.entries[slot].active && self.entries[slot].swap_entry == swap_entry {
                return Some(slot);
            }
        }
        None
    }
}
