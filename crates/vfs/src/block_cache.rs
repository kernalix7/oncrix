// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Block-level I/O cache for filesystem implementations.
//!
//! Provides a fixed-capacity block cache that maps (device, block_number)
//! pairs to cached block data. Uses a simple clock-based eviction policy.
//!
//! This is distinct from the page cache: the block cache operates at the
//! raw block device level and is used by filesystem drivers before
//! higher-level page cache integration.

use oncrix_lib::{Error, Result};

/// Block size in bytes (4 KiB).
pub const BLOCK_SIZE: usize = 4096;

/// Maximum number of cached blocks.
pub const CACHE_CAPACITY: usize = 256;

/// Identifier for a cached block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockId {
    /// Device number.
    pub dev: u32,
    /// Block number on the device.
    pub block: u64,
}

impl BlockId {
    /// Create a new block identifier.
    pub const fn new(dev: u32, block: u64) -> Self {
        BlockId { dev, block }
    }
}

/// State of a cache slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    /// Slot is free.
    Free,
    /// Slot contains valid, clean data.
    Clean,
    /// Slot contains modified data not yet written back.
    Dirty,
}

/// A single block cache slot.
pub struct CacheSlot {
    /// Block identity.
    pub id: BlockId,
    /// Current state.
    pub state: SlotState,
    /// Data buffer.
    pub data: [u8; BLOCK_SIZE],
    /// Clock bit for the clock eviction algorithm.
    pub clock_bit: bool,
    /// Reference count (pinned blocks cannot be evicted).
    pub pin_count: u16,
}

impl CacheSlot {
    /// Create a free slot.
    pub const fn free() -> Self {
        CacheSlot {
            id: BlockId::new(0, 0),
            state: SlotState::Free,
            data: [0u8; BLOCK_SIZE],
            clock_bit: false,
            pin_count: 0,
        }
    }

    /// Check if this slot is pinned.
    pub fn is_pinned(&self) -> bool {
        self.pin_count > 0
    }
}

/// Block cache with clock-based eviction.
pub struct BlockCache {
    slots: [CacheSlot; CACHE_CAPACITY],
    /// Clock hand for eviction.
    clock_hand: usize,
    /// Number of occupied slots.
    used: usize,
    /// Total cache hits.
    hits: u64,
    /// Total cache misses.
    misses: u64,
}

impl BlockCache {
    /// Create a new empty block cache.
    pub fn new() -> Self {
        BlockCache {
            slots: core::array::from_fn(|_| CacheSlot::free()),
            clock_hand: 0,
            used: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Look up a block in the cache.
    ///
    /// Returns `Some(index)` if the block is cached, `None` otherwise.
    pub fn lookup(&mut self, id: BlockId) -> Option<usize> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.state != SlotState::Free && slot.id == id {
                slot.clock_bit = true;
                self.hits += 1;
                return Some(i);
            }
        }
        self.misses += 1;
        None
    }

    /// Pin a slot so it cannot be evicted.
    pub fn pin(&mut self, index: usize) -> Result<()> {
        if index >= CACHE_CAPACITY {
            return Err(Error::InvalidArgument);
        }
        let slot = &mut self.slots[index];
        slot.pin_count = slot.pin_count.saturating_add(1);
        Ok(())
    }

    /// Unpin a slot.
    pub fn unpin(&mut self, index: usize) -> Result<()> {
        if index >= CACHE_CAPACITY {
            return Err(Error::InvalidArgument);
        }
        let slot = &mut self.slots[index];
        slot.pin_count = slot.pin_count.saturating_sub(1);
        Ok(())
    }

    /// Allocate a slot for a new block, evicting if necessary.
    ///
    /// Returns the slot index. Returns `Err(Busy)` if all slots are pinned.
    pub fn allocate(&mut self, id: BlockId) -> Result<usize> {
        // First, try to find a free slot.
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.state == SlotState::Free {
                self.slots[i].id = id;
                self.slots[i].state = SlotState::Clean;
                self.slots[i].clock_bit = true;
                self.used += 1;
                return Ok(i);
            }
        }
        // Clock eviction.
        let start = self.clock_hand;
        loop {
            let i = self.clock_hand;
            self.clock_hand = (self.clock_hand + 1) % CACHE_CAPACITY;
            let slot = &mut self.slots[i];
            if slot.is_pinned() {
                if self.clock_hand == start {
                    return Err(Error::Busy);
                }
                continue;
            }
            if slot.clock_bit {
                slot.clock_bit = false;
            } else {
                // Evict this slot.
                slot.id = id;
                slot.state = SlotState::Clean;
                slot.clock_bit = true;
                slot.data = [0u8; BLOCK_SIZE];
                return Ok(i);
            }
            if self.clock_hand == start {
                return Err(Error::Busy);
            }
        }
    }

    /// Write data into a slot and mark it dirty.
    pub fn write_slot(&mut self, index: usize, data: &[u8]) -> Result<()> {
        if index >= CACHE_CAPACITY {
            return Err(Error::InvalidArgument);
        }
        let slot = &mut self.slots[index];
        let len = data.len().min(BLOCK_SIZE);
        slot.data[..len].copy_from_slice(&data[..len]);
        slot.state = SlotState::Dirty;
        Ok(())
    }

    /// Read data from a slot.
    pub fn read_slot(&self, index: usize, buf: &mut [u8]) -> Result<usize> {
        if index >= CACHE_CAPACITY {
            return Err(Error::InvalidArgument);
        }
        let slot = &self.slots[index];
        if slot.state == SlotState::Free {
            return Err(Error::NotFound);
        }
        let len = buf.len().min(BLOCK_SIZE);
        buf[..len].copy_from_slice(&slot.data[..len]);
        Ok(len)
    }

    /// Mark a slot as clean after writeback.
    pub fn mark_clean(&mut self, index: usize) -> Result<()> {
        if index >= CACHE_CAPACITY {
            return Err(Error::InvalidArgument);
        }
        if self.slots[index].state == SlotState::Dirty {
            self.slots[index].state = SlotState::Clean;
        }
        Ok(())
    }

    /// Invalidate (free) a slot.
    pub fn invalidate(&mut self, index: usize) {
        if index < CACHE_CAPACITY && self.slots[index].state != SlotState::Free {
            self.slots[index].state = SlotState::Free;
            self.used = self.used.saturating_sub(1);
        }
    }

    /// Collect indices of all dirty slots.
    pub fn dirty_slots(&self) -> [Option<usize>; CACHE_CAPACITY] {
        let mut result = [None; CACHE_CAPACITY];
        let mut j = 0;
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.state == SlotState::Dirty && j < CACHE_CAPACITY {
                result[j] = Some(i);
                j += 1;
            }
        }
        result
    }

    /// Cache statistics.
    pub fn stats(&self) -> (u64, u64, usize) {
        (self.hits, self.misses, self.used)
    }
}

impl Default for BlockCache {
    fn default() -> Self {
        Self::new()
    }
}
