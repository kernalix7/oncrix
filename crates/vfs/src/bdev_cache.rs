// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Block device buffer cache for the ONCRIX VFS.
//!
//! Maintains a fixed-size LRU cache of raw block buffers read from block
//! devices. Filesystems use this layer to amortize block I/O costs and to
//! ensure coherency between cached reads and pending writes.

use oncrix_lib::{Error, Result};

/// Block size used by the buffer cache (must match filesystem block size).
pub const BDEV_BLOCK_SIZE: usize = 4096;

/// Total number of blocks held in the buffer cache.
pub const BDEV_CACHE_SLOTS: usize = 128;

/// Sentinel value for an unused LRU age counter.
pub const BDEV_UNUSED_AGE: u64 = 0;

/// State of a cached block buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BufState {
    /// Slot is empty.
    #[default]
    Empty,
    /// Block data has been read from the device and is up to date.
    Clean,
    /// Block data has been modified and must be written back.
    Dirty,
    /// Block is currently being read from or written to the device.
    Locked,
}

/// A single cached block buffer entry.
pub struct BufEntry {
    /// Block number on the device.
    pub block_no: u64,
    /// Device identifier (minor number or similar).
    pub dev_id: u32,
    /// Current state of the buffer.
    pub state: BufState,
    /// LRU age counter — higher means more recently used.
    pub lru_age: u64,
    /// Reference count (number of holders).
    pub refcount: u32,
    /// The raw block data.
    pub data: [u8; BDEV_BLOCK_SIZE],
}

impl BufEntry {
    /// Create an empty cache slot.
    pub const fn new() -> Self {
        Self {
            block_no: 0,
            dev_id: 0,
            state: BufState::Empty,
            lru_age: BDEV_UNUSED_AGE,
            refcount: 0,
            data: [0u8; BDEV_BLOCK_SIZE],
        }
    }

    /// Return `true` if this slot is in use (not Empty).
    pub fn is_used(&self) -> bool {
        self.state != BufState::Empty
    }

    /// Return `true` if this slot can be evicted (Clean and no holders).
    pub fn is_evictable(&self) -> bool {
        self.state == BufState::Clean && self.refcount == 0
    }

    /// Mark the buffer as dirty.
    pub fn mark_dirty(&mut self) {
        if self.state == BufState::Clean {
            self.state = BufState::Dirty;
        }
    }

    /// Mark the buffer as clean (after writeback).
    pub fn mark_clean(&mut self) {
        if self.state == BufState::Dirty {
            self.state = BufState::Clean;
        }
    }
}

impl Default for BufEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Fixed-size block buffer cache using an LRU eviction policy.
pub struct BdevCache {
    slots: [BufEntry; BDEV_CACHE_SLOTS],
    /// Monotonically increasing age counter.
    age_counter: u64,
    /// Number of occupied slots.
    used: usize,
    /// Total cache hits since creation.
    pub hits: u64,
    /// Total cache misses since creation.
    pub misses: u64,
}

impl BdevCache {
    /// Create an empty buffer cache.
    pub const fn new() -> Self {
        Self {
            slots: [const { BufEntry::new() }; BDEV_CACHE_SLOTS],
            age_counter: 1,
            used: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Look up a block in the cache. Returns the slot index if found.
    pub fn lookup(&mut self, dev_id: u32, block_no: u64) -> Option<usize> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_used() && slot.dev_id == dev_id && slot.block_no == block_no {
                slot.lru_age = self.age_counter;
                self.age_counter += 1;
                self.hits += 1;
                return Some(i);
            }
        }
        self.misses += 1;
        None
    }

    /// Allocate a slot for a new block, evicting the LRU clean entry if necessary.
    ///
    /// Returns `Busy` if all slots are dirty or locked and no eviction is possible.
    pub fn alloc_slot(&mut self, dev_id: u32, block_no: u64) -> Result<usize> {
        // Find an empty slot first.
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.state == BufState::Empty {
                slot.dev_id = dev_id;
                slot.block_no = block_no;
                slot.state = BufState::Locked;
                slot.lru_age = self.age_counter;
                self.age_counter += 1;
                self.used += 1;
                return Ok(i);
            }
        }

        // Evict the LRU evictable slot.
        let mut oldest_age = u64::MAX;
        let mut oldest_idx = BDEV_CACHE_SLOTS;
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.is_evictable() && slot.lru_age < oldest_age {
                oldest_age = slot.lru_age;
                oldest_idx = i;
            }
        }

        if oldest_idx == BDEV_CACHE_SLOTS {
            return Err(Error::Busy);
        }

        let slot = &mut self.slots[oldest_idx];
        slot.dev_id = dev_id;
        slot.block_no = block_no;
        slot.state = BufState::Locked;
        slot.lru_age = self.age_counter;
        self.age_counter += 1;
        slot.refcount = 0;
        Ok(oldest_idx)
    }

    /// Get an immutable reference to a slot by index.
    pub fn get(&self, idx: usize) -> Result<&BufEntry> {
        if idx >= BDEV_CACHE_SLOTS || !self.slots[idx].is_used() {
            return Err(Error::NotFound);
        }
        Ok(&self.slots[idx])
    }

    /// Get a mutable reference to a slot by index.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut BufEntry> {
        if idx >= BDEV_CACHE_SLOTS || !self.slots[idx].is_used() {
            return Err(Error::NotFound);
        }
        Ok(&mut self.slots[idx])
    }

    /// Release a reference to a slot (decrement refcount, allow eviction).
    pub fn release(&mut self, idx: usize) -> Result<()> {
        if idx >= BDEV_CACHE_SLOTS {
            return Err(Error::InvalidArgument);
        }
        let slot = &mut self.slots[idx];
        if slot.refcount > 0 {
            slot.refcount -= 1;
        }
        Ok(())
    }

    /// Flush all dirty buffers for a device (mark them available for writeback).
    pub fn flush_device(&mut self, dev_id: u32) -> usize {
        let mut count = 0usize;
        for slot in self.slots.iter_mut() {
            if slot.dev_id == dev_id && slot.state == BufState::Dirty {
                slot.state = BufState::Clean;
                count += 1;
            }
        }
        count
    }

    /// Return the number of dirty buffers in the cache.
    pub fn dirty_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state == BufState::Dirty)
            .count()
    }

    /// Return the cache hit ratio as an integer percentage (0–100).
    pub fn hit_ratio(&self) -> u8 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0;
        }
        ((self.hits * 100) / total) as u8
    }
}

impl Default for BdevCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the cache slot index for a given block number (simple hash).
pub fn cache_hash(dev_id: u32, block_no: u64) -> usize {
    let h = (dev_id as u64)
        .wrapping_mul(2654435761)
        .wrapping_add(block_no);
    (h as usize) % BDEV_CACHE_SLOTS
}
