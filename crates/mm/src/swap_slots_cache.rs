// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Swap slots cache for fast slot allocation.
//!
//! Maintains a per-CPU cache of free swap slots to avoid the global
//! swap_info lock on every swap-out. Each CPU pre-allocates a batch
//! of swap slots and serves allocations from its local cache.
//!
//! - [`SwapSlot`] — a single swap slot descriptor
//! - [`SlotCache`] — per-CPU swap slot cache
//! - [`SwapSlotsCacheStats`] — aggregate statistics
//! - [`SwapSlotsManager`] — manages all per-CPU caches
//!
//! Reference: Linux `mm/swap_slots.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum slots per cache.
const CACHE_SIZE: usize = 64;

/// Maximum number of CPU caches.
const MAX_CPUS: usize = 32;

/// Default refill batch size.
const DEFAULT_BATCH: usize = 16;

// -------------------------------------------------------------------
// SwapSlot
// -------------------------------------------------------------------

/// A single swap slot descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapSlot {
    /// Swap type (swap area index).
    pub swap_type: u32,
    /// Offset within the swap area.
    pub offset: u64,
    /// Whether this slot is valid.
    pub valid: bool,
}

impl SwapSlot {
    /// Creates a new swap slot.
    pub fn new(swap_type: u32, offset: u64) -> Self {
        Self {
            swap_type,
            offset,
            valid: true,
        }
    }

    /// Creates an invalid (empty) slot.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns the swap entry value (type + offset encoded).
    pub fn entry_val(&self) -> u64 {
        ((self.swap_type as u64) << 32) | self.offset
    }
}

// -------------------------------------------------------------------
// SlotCache
// -------------------------------------------------------------------

/// Per-CPU swap slot cache.
#[derive(Debug)]
pub struct SlotCache {
    /// Cached slots.
    slots: [SwapSlot; CACHE_SIZE],
    /// Number of valid slots.
    count: usize,
    /// CPU ID.
    cpu_id: u32,
    /// Allocations served from this cache.
    alloc_count: u64,
    /// Refills from global pool.
    refill_count: u64,
}

impl SlotCache {
    /// Creates a new empty cache for the given CPU.
    pub fn new(cpu_id: u32) -> Self {
        Self {
            slots: [SwapSlot::default(); CACHE_SIZE],
            count: 0,
            cpu_id,
            alloc_count: 0,
            refill_count: 0,
        }
    }

    /// Allocates a slot from the cache.
    pub fn alloc(&mut self) -> Option<SwapSlot> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        let slot = self.slots[self.count];
        self.slots[self.count] = SwapSlot::empty();
        self.alloc_count += 1;
        Some(slot)
    }

    /// Frees a slot back to the cache.
    pub fn free(&mut self, slot: SwapSlot) -> Result<()> {
        if self.count >= CACHE_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.slots[self.count] = slot;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of cached slots.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns the CPU ID.
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns `true` if the cache needs refilling.
    pub fn needs_refill(&self) -> bool {
        self.count == 0
    }
}

impl Default for SlotCache {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// SwapSlotsCacheStats
// -------------------------------------------------------------------

/// Aggregate swap slots cache statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapSlotsCacheStats {
    /// Total allocations from caches.
    pub cache_allocs: u64,
    /// Total global fallback allocations.
    pub global_allocs: u64,
    /// Total refills.
    pub refills: u64,
    /// Total slots freed back to caches.
    pub cache_frees: u64,
    /// Cache miss rate (global allocs / total allocs × 1000).
    pub miss_rate: u32,
}

impl SwapSlotsCacheStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Recalculates the miss rate.
    pub fn update_miss_rate(&mut self) {
        let total = self.cache_allocs + self.global_allocs;
        if total == 0 {
            self.miss_rate = 0;
        } else {
            self.miss_rate = ((self.global_allocs * 1000) / total) as u32;
        }
    }
}

// -------------------------------------------------------------------
// SwapSlotsManager
// -------------------------------------------------------------------

/// Manages all per-CPU swap slot caches.
pub struct SwapSlotsManager {
    /// Per-CPU caches.
    caches: [SlotCache; MAX_CPUS],
    /// Number of active CPUs.
    nr_cpus: usize,
    /// Refill batch size.
    batch_size: usize,
    /// Global next offset for slot generation.
    next_offset: u64,
    /// Statistics.
    stats: SwapSlotsCacheStats,
}

impl Default for SwapSlotsManager {
    fn default() -> Self {
        Self {
            caches: core::array::from_fn(|i| SlotCache::new(i as u32)),
            nr_cpus: 0,
            batch_size: DEFAULT_BATCH,
            next_offset: 1,
            stats: SwapSlotsCacheStats::default(),
        }
    }
}

impl SwapSlotsManager {
    /// Creates a new manager for the given number of CPUs.
    pub fn new(nr_cpus: usize) -> Result<Self> {
        if nr_cpus == 0 || nr_cpus > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let mut mgr = Self::default();
        mgr.nr_cpus = nr_cpus;
        Ok(mgr)
    }

    /// Allocates a swap slot for the given CPU.
    pub fn alloc(&mut self, cpu: usize) -> Result<SwapSlot> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }

        // Try cache first.
        if let Some(slot) = self.caches[cpu].alloc() {
            self.stats.cache_allocs += 1;
            return Ok(slot);
        }

        // Refill cache from global pool.
        self.refill(cpu)?;

        // Try again.
        if let Some(slot) = self.caches[cpu].alloc() {
            self.stats.cache_allocs += 1;
            Ok(slot)
        } else {
            self.stats.global_allocs += 1;
            // Direct allocation from global.
            let slot = SwapSlot::new(0, self.next_offset);
            self.next_offset += 1;
            Ok(slot)
        }
    }

    /// Frees a swap slot back to the given CPU's cache.
    pub fn free(&mut self, cpu: usize, slot: SwapSlot) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        self.caches[cpu].free(slot)?;
        self.stats.cache_frees += 1;
        Ok(())
    }

    /// Refills a CPU's cache from the global pool.
    fn refill(&mut self, cpu: usize) -> Result<()> {
        let batch = self.batch_size.min(CACHE_SIZE - self.caches[cpu].count());
        for _ in 0..batch {
            let slot = SwapSlot::new(0, self.next_offset);
            self.next_offset += 1;
            if self.caches[cpu].free(slot).is_err() {
                break;
            }
        }
        self.caches[cpu].refill_count += 1;
        self.stats.refills += 1;
        Ok(())
    }

    /// Returns the number of active CPUs.
    pub fn nr_cpus(&self) -> usize {
        self.nr_cpus
    }

    /// Returns statistics.
    pub fn stats(&self) -> &SwapSlotsCacheStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
