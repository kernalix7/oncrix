// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SquashFS block cache.
//!
//! SquashFS stores file data and metadata in compressed blocks.  To avoid
//! re-decompressing the same block on every access, this module maintains
//! a fixed-size LRU cache of decompressed blocks.
//!
//! Two separate cache pools are provided:
//! - **Metadata cache** — small blocks (up to 8 KiB) used for directory
//!   entries, inode tables, and fragment tables.
//! - **Data cache** — larger blocks (up to 1 MiB) used for file content.
//!
//! Each cache entry transitions through the states:
//! `Free` → `Reading` → `Ready` → (evicted back to `Free`).
//!
//! The LRU eviction policy is tracked via a generation counter: the
//! entry with the smallest `last_used` value is the least-recently-used.
//!
//! # References
//!
//! - Linux `fs/squashfs/cache.c`, `fs/squashfs/cache.h`
//! - SquashFS on-disk format v4

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of entries in the metadata block cache.
pub const META_CACHE_ENTRIES: usize = 8;

/// Number of entries in the data block cache.
pub const DATA_CACHE_ENTRIES: usize = 16;

/// Maximum size of a metadata block (8 KiB).
pub const META_BLOCK_SIZE: usize = 8192;

/// Maximum size of a data block (128 KiB compressed, 1 MiB decompressed).
pub const DATA_BLOCK_SIZE: usize = 131072;

/// Decompressed data buffer size per data cache entry.
pub const DATA_DECOMP_SIZE: usize = 1_048_576; // 1 MiB

// ── CacheState ────────────────────────────────────────────────────────────────

/// State of a single cache entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheState {
    /// The entry slot is unused and available for allocation.
    #[default]
    Free,
    /// A decompression is in progress for this block.
    Reading,
    /// The decompressed data is valid and ready to serve.
    Ready,
    /// The entry is being evicted; data must not be read.
    Stale,
}

// ── MetaCacheEntry ────────────────────────────────────────────────────────────

/// One entry in the metadata block cache.
pub struct MetaCacheEntry {
    /// Physical block offset on disk where this metadata block begins.
    pub block_offset: u64,
    /// Number of valid bytes in `data`.
    pub data_len: usize,
    /// Decompressed metadata block data.
    pub data: [u8; META_BLOCK_SIZE],
    /// Cache entry state.
    pub state: CacheState,
    /// Generation counter for LRU ordering (higher = more recently used).
    pub last_used: u64,
    /// Number of outstanding consumers (ref-count; entry is pinned while > 0).
    pub refcount: u32,
}

impl MetaCacheEntry {
    /// Create an empty, free metadata cache entry.
    pub const fn new() -> Self {
        Self {
            block_offset: 0,
            data_len: 0,
            data: [0u8; META_BLOCK_SIZE],
            state: CacheState::Free,
            last_used: 0,
            refcount: 0,
        }
    }

    /// Mark the entry as in-use (increment refcount).
    pub fn acquire(&mut self) {
        self.refcount += 1;
        self.state = CacheState::Ready;
    }

    /// Release the entry (decrement refcount; may become evictable).
    pub fn release(&mut self) {
        if self.refcount > 0 {
            self.refcount -= 1;
        }
    }

    /// Return true if the entry can be evicted (not pinned, not reading).
    pub fn is_evictable(&self) -> bool {
        self.refcount == 0 && self.state == CacheState::Ready
    }
}

// ── DataCacheEntry ────────────────────────────────────────────────────────────

/// One entry in the data block cache.
pub struct DataCacheEntry {
    /// Physical block offset on disk.
    pub block_offset: u64,
    /// Compressed length on disk.
    pub compressed_len: u32,
    /// Decompressed length.
    pub decompressed_len: u32,
    /// Decompressed data (heap-simulated fixed array).
    ///
    /// Only the first `decompressed_len` bytes are meaningful.
    pub data: [u8; DATA_BLOCK_SIZE],
    /// Cache entry state.
    pub state: CacheState,
    /// LRU generation counter.
    pub last_used: u64,
    /// Outstanding consumer count.
    pub refcount: u32,
}

impl DataCacheEntry {
    /// Create a free data cache entry.
    pub const fn new() -> Self {
        Self {
            block_offset: 0,
            compressed_len: 0,
            decompressed_len: 0,
            data: [0u8; DATA_BLOCK_SIZE],
            state: CacheState::Free,
            last_used: 0,
            refcount: 0,
        }
    }

    /// Return true if evictable.
    pub fn is_evictable(&self) -> bool {
        self.refcount == 0 && self.state == CacheState::Ready
    }
}

// ── MetaCache ─────────────────────────────────────────────────────────────────

/// Fixed-size LRU cache for SquashFS metadata blocks.
pub struct MetaCache {
    entries: [MetaCacheEntry; META_CACHE_ENTRIES],
    /// Monotonically increasing generation counter.
    generation: u64,
    /// Cache hits since initialization.
    pub hits: u64,
    /// Cache misses since initialization.
    pub misses: u64,
}

impl MetaCache {
    /// Create an empty metadata cache.
    pub const fn new() -> Self {
        Self {
            entries: [const { MetaCacheEntry::new() }; META_CACHE_ENTRIES],
            generation: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Look up a metadata block by its on-disk offset.
    ///
    /// Returns the index of the cache entry on a hit, or `None` on a miss.
    pub fn lookup(&mut self, block_offset: u64) -> Option<usize> {
        for i in 0..META_CACHE_ENTRIES {
            if self.entries[i].state == CacheState::Ready
                && self.entries[i].block_offset == block_offset
            {
                self.generation += 1;
                self.entries[i].last_used = self.generation;
                self.hits += 1;
                return Some(i);
            }
        }
        self.misses += 1;
        None
    }

    /// Evict the least-recently-used evictable entry.
    ///
    /// Returns the evicted index, or `Busy` if all entries are pinned.
    pub fn evict_lru(&mut self) -> Result<usize> {
        let mut best: Option<usize> = None;
        let mut best_gen = u64::MAX;

        for i in 0..META_CACHE_ENTRIES {
            if self.entries[i].is_evictable() && self.entries[i].last_used < best_gen {
                best_gen = self.entries[i].last_used;
                best = Some(i);
            }
        }

        let idx = best.ok_or(Error::Busy)?;
        self.entries[idx].state = CacheState::Stale;
        self.entries[idx].refcount = 0;
        self.entries[idx].state = CacheState::Free;
        Ok(idx)
    }

    /// Allocate a slot for a new metadata block, evicting LRU if necessary.
    ///
    /// Returns the slot index; state is set to `Reading`.
    pub fn allocate(&mut self, block_offset: u64) -> Result<usize> {
        // Prefer a free slot.
        if let Some(i) = self
            .entries
            .iter()
            .position(|e| e.state == CacheState::Free)
        {
            self.entries[i].block_offset = block_offset;
            self.entries[i].state = CacheState::Reading;
            self.entries[i].refcount = 0;
            self.entries[i].data_len = 0;
            return Ok(i);
        }
        // Evict LRU and reuse.
        let i = self.evict_lru()?;
        self.entries[i].block_offset = block_offset;
        self.entries[i].state = CacheState::Reading;
        self.entries[i].refcount = 0;
        self.entries[i].data_len = 0;
        Ok(i)
    }

    /// Mark a slot's decompression as complete and make it ready.
    ///
    /// `data` is the decompressed content to store.
    pub fn finish_read(&mut self, idx: usize, data: &[u8]) -> Result<()> {
        if idx >= META_CACHE_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        if self.entries[idx].state != CacheState::Reading {
            return Err(Error::InvalidArgument);
        }
        let len = data.len().min(META_BLOCK_SIZE);
        self.entries[idx].data[..len].copy_from_slice(&data[..len]);
        self.entries[idx].data_len = len;
        self.generation += 1;
        self.entries[idx].last_used = self.generation;
        self.entries[idx].state = CacheState::Ready;
        Ok(())
    }

    /// Read bytes from a cached metadata block into `dst`.
    ///
    /// `offset` is the byte offset within the decompressed block.
    pub fn read(&mut self, idx: usize, offset: usize, dst: &mut [u8]) -> Result<usize> {
        if idx >= META_CACHE_ENTRIES || self.entries[idx].state != CacheState::Ready {
            return Err(Error::NotFound);
        }
        let entry = &self.entries[idx];
        if offset >= entry.data_len {
            return Ok(0);
        }
        let available = entry.data_len - offset;
        let n = dst.len().min(available);
        dst[..n].copy_from_slice(&entry.data[offset..offset + n]);
        Ok(n)
    }
}

// ── DataCache ─────────────────────────────────────────────────────────────────

/// Fixed-size LRU cache for SquashFS data blocks.
pub struct DataCache {
    entries: [DataCacheEntry; DATA_CACHE_ENTRIES],
    generation: u64,
    pub hits: u64,
    pub misses: u64,
}

impl DataCache {
    /// Create an empty data cache.
    pub const fn new() -> Self {
        Self {
            entries: [const { DataCacheEntry::new() }; DATA_CACHE_ENTRIES],
            generation: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Look up a data block by on-disk offset.
    pub fn lookup(&mut self, block_offset: u64) -> Option<usize> {
        for i in 0..DATA_CACHE_ENTRIES {
            if self.entries[i].state == CacheState::Ready
                && self.entries[i].block_offset == block_offset
            {
                self.generation += 1;
                self.entries[i].last_used = self.generation;
                self.hits += 1;
                return Some(i);
            }
        }
        self.misses += 1;
        None
    }

    /// Evict the least-recently-used evictable data entry.
    pub fn evict_lru(&mut self) -> Result<usize> {
        let mut best: Option<usize> = None;
        let mut best_gen = u64::MAX;
        for i in 0..DATA_CACHE_ENTRIES {
            if self.entries[i].is_evictable() && self.entries[i].last_used < best_gen {
                best_gen = self.entries[i].last_used;
                best = Some(i);
            }
        }
        let idx = best.ok_or(Error::Busy)?;
        self.entries[idx].state = CacheState::Free;
        self.entries[idx].refcount = 0;
        Ok(idx)
    }

    /// Allocate a data cache slot for a new block.
    pub fn allocate(&mut self, block_offset: u64, compressed_len: u32) -> Result<usize> {
        if let Some(i) = self
            .entries
            .iter()
            .position(|e| e.state == CacheState::Free)
        {
            self.entries[i].block_offset = block_offset;
            self.entries[i].compressed_len = compressed_len;
            self.entries[i].decompressed_len = 0;
            self.entries[i].state = CacheState::Reading;
            return Ok(i);
        }
        let i = self.evict_lru()?;
        self.entries[i].block_offset = block_offset;
        self.entries[i].compressed_len = compressed_len;
        self.entries[i].decompressed_len = 0;
        self.entries[i].state = CacheState::Reading;
        Ok(i)
    }

    /// Complete a data block decompression.
    pub fn finish_read(&mut self, idx: usize, decompressed: &[u8]) -> Result<()> {
        if idx >= DATA_CACHE_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        if self.entries[idx].state != CacheState::Reading {
            return Err(Error::InvalidArgument);
        }
        let len = decompressed.len().min(DATA_BLOCK_SIZE);
        self.entries[idx].data[..len].copy_from_slice(&decompressed[..len]);
        self.entries[idx].decompressed_len = len as u32;
        self.generation += 1;
        self.entries[idx].last_used = self.generation;
        self.entries[idx].state = CacheState::Ready;
        Ok(())
    }
}

// ── SquashfsCache ─────────────────────────────────────────────────────────────

/// Combined SquashFS cache: one metadata pool and one data pool.
pub struct SquashfsCache {
    /// Metadata block cache.
    pub meta: MetaCache,
    /// Data block cache.
    pub data: DataCache,
}

impl SquashfsCache {
    /// Create a new combined cache.
    pub const fn new() -> Self {
        Self {
            meta: MetaCache::new(),
            data: DataCache::new(),
        }
    }

    /// Return combined hit rate as a percentage (0–100), or 0 if no accesses.
    pub fn hit_rate_pct(&self) -> u32 {
        let total = self.meta.hits + self.meta.misses + self.data.hits + self.data.misses;
        if total == 0 {
            return 0;
        }
        let hits = self.meta.hits + self.data.hits;
        ((hits * 100) / total) as u32
    }
}
