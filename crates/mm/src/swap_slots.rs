// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Swap slot cache for batched swap slot allocation.
//!
//! Maintains per-CPU caches of pre-allocated swap slot identifiers to
//! amortise the cost of global swap-area allocation. When a process
//! needs a swap slot, it first checks its local cache. If the cache is
//! empty, a batch of slots is transferred from the global free pool.
//! Similarly, when freeing a slot, the slot is returned to the local
//! cache first; if the cache is nearly full, a batch is drained back
//! to the global pool.
//!
//! # Batch sizes
//!
//! - **Refill batch**: 32 slots from global → local cache
//! - **Drain threshold**: when local count > 48, drain 32 slots back
//!
//! # Subsystems
//!
//! - [`SwapSlotCache`] — per-CPU local cache of swap slots
//! - [`SwapSlotCacheSet`] — collection of per-CPU caches
//! - [`SwapSlotSubsystem`] — main subsystem with global pool
//! - [`SwapSlotStats`] — allocation and cache statistics
//!
//! Reference: Linux `mm/swap_slots.c`, `include/linux/swap_slots.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Number of slots per local cache.
const CACHE_CAPACITY: usize = 64;

/// Number of per-CPU caches.
const NUM_CACHES: usize = 8;

/// Size of the global free pool.
const GLOBAL_POOL_SIZE: usize = 4096;

/// Number of slots to transfer in a single refill operation.
const REFILL_BATCH: usize = 32;

/// Threshold above which a local cache drains to the global pool.
const DRAIN_THRESHOLD: usize = 48;

/// Number of slots to drain in a single drain operation.
const DRAIN_BATCH: usize = 32;

/// Invalid swap slot sentinel.
const INVALID_SLOT: u64 = u64::MAX;

// -------------------------------------------------------------------
// SwapSlotCache
// -------------------------------------------------------------------

/// Per-CPU cache of swap slot identifiers.
///
/// Holds up to [`CACHE_CAPACITY`] slots. Allocation pops from the
/// top; freeing pushes onto the top (LIFO for cache locality).
#[derive(Debug)]
pub struct SwapSlotCache {
    /// Cached swap slot values.
    slots: [u64; CACHE_CAPACITY],
    /// Number of valid slots in the cache.
    count: u16,
    /// Whether this cache is enabled.
    enabled: bool,
}

impl SwapSlotCache {
    /// Create an empty cache.
    const fn empty() -> Self {
        Self {
            slots: [INVALID_SLOT; CACHE_CAPACITY],
            count: 0,
            enabled: true,
        }
    }

    /// Number of slots currently cached.
    pub const fn count(&self) -> u16 {
        self.count
    }

    /// Whether this cache is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Capacity of the cache.
    pub const fn capacity(&self) -> usize {
        CACHE_CAPACITY
    }

    /// Enable or disable this cache.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Try to allocate a slot from this cache (LIFO pop).
    fn try_alloc(&mut self) -> Option<u64> {
        if !self.enabled || self.count == 0 {
            return None;
        }
        self.count -= 1;
        let slot = self.slots[self.count as usize];
        self.slots[self.count as usize] = INVALID_SLOT;
        Some(slot)
    }

    /// Try to return a slot to this cache (LIFO push).
    ///
    /// Returns `false` if the cache is full.
    fn try_free(&mut self, slot: u64) -> bool {
        if !self.enabled || self.count as usize >= CACHE_CAPACITY {
            return false;
        }
        self.slots[self.count as usize] = slot;
        self.count += 1;
        true
    }

    /// Check whether the cache needs draining.
    fn needs_drain(&self) -> bool {
        self.count as usize > DRAIN_THRESHOLD
    }

    /// Drain `count` slots from the cache into a destination buffer.
    ///
    /// Returns the number of slots actually drained.
    fn drain_to(&mut self, dst: &mut [u64], max_drain: usize) -> usize {
        let to_drain = max_drain.min(self.count as usize);
        for i in 0..to_drain {
            if self.count == 0 {
                return i;
            }
            self.count -= 1;
            dst[i] = self.slots[self.count as usize];
            self.slots[self.count as usize] = INVALID_SLOT;
        }
        to_drain
    }

    /// Fill the cache from a source buffer.
    ///
    /// Returns the number of slots actually added.
    fn fill_from(&mut self, src: &[u64]) -> usize {
        let available = CACHE_CAPACITY - self.count as usize;
        let to_fill = available.min(src.len());
        for i in 0..to_fill {
            self.slots[self.count as usize] = src[i];
            self.count += 1;
        }
        to_fill
    }
}

impl Default for SwapSlotCache {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// SwapSlotCacheSet
// -------------------------------------------------------------------

/// Collection of per-CPU swap slot caches.
pub struct SwapSlotCacheSet {
    /// Individual per-CPU caches.
    caches: [SwapSlotCache; NUM_CACHES],
}

impl SwapSlotCacheSet {
    /// Create a new set of empty caches.
    const fn new() -> Self {
        Self {
            caches: [const { SwapSlotCache::empty() }; NUM_CACHES],
        }
    }

    /// Get a reference to a cache by CPU index.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — `cpu_id` out of range
    pub fn get(&self, cpu_id: usize) -> Result<&SwapSlotCache> {
        if cpu_id >= NUM_CACHES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.caches[cpu_id])
    }
}

impl Default for SwapSlotCacheSet {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// GlobalPool
// -------------------------------------------------------------------

/// Global free pool of swap slot identifiers.
struct GlobalPool {
    /// Available slots.
    slots: [u64; GLOBAL_POOL_SIZE],
    /// Number of valid slots in the pool.
    count: u32,
}

impl GlobalPool {
    /// Create a new global pool pre-populated with sequential slots.
    const fn new() -> Self {
        let mut pool = Self {
            slots: [INVALID_SLOT; GLOBAL_POOL_SIZE],
            count: 0,
        };
        // Pre-populate in const context.
        let mut i = 0;
        while i < GLOBAL_POOL_SIZE {
            pool.slots[i] = i as u64;
            pool.count += 1;
            i += 1;
        }
        pool
    }

    /// Try to take a batch of slots from the global pool.
    ///
    /// Returns the number of slots actually taken.
    fn take_batch(&mut self, dst: &mut [u64], max_take: usize) -> usize {
        let to_take = max_take.min(self.count as usize);
        for i in 0..to_take {
            if self.count == 0 {
                return i;
            }
            self.count -= 1;
            dst[i] = self.slots[self.count as usize];
            self.slots[self.count as usize] = INVALID_SLOT;
        }
        to_take
    }

    /// Return a batch of slots to the global pool.
    ///
    /// Returns the number of slots actually returned.
    fn return_batch(&mut self, src: &[u64]) -> usize {
        let available = GLOBAL_POOL_SIZE - self.count as usize;
        let to_return = available.min(src.len());
        for slot in src.iter().take(to_return) {
            self.slots[self.count as usize] = *slot;
            self.count += 1;
        }
        to_return
    }

    /// Return a single slot to the global pool.
    fn return_one(&mut self, slot: u64) -> bool {
        if (self.count as usize) >= GLOBAL_POOL_SIZE {
            return false;
        }
        self.slots[self.count as usize] = slot;
        self.count += 1;
        true
    }

    /// Number of available slots.
    const fn available(&self) -> u32 {
        self.count
    }
}

// -------------------------------------------------------------------
// SwapSlotStats
// -------------------------------------------------------------------

/// Swap slot cache allocation statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapSlotStats {
    /// Allocations satisfied from local cache (fast path).
    pub cache_hits: u64,
    /// Allocations that required a global refill (slow path).
    pub cache_misses: u64,
    /// Slots allocated from the global pool total.
    pub global_allocs: u64,
    /// Slots returned to the global pool total.
    pub global_frees: u64,
    /// Number of batch refill operations.
    pub refills: u64,
    /// Number of batch drain operations.
    pub drains: u64,
}

// -------------------------------------------------------------------
// SwapSlotSubsystem
// -------------------------------------------------------------------

/// Main swap slot cache subsystem.
///
/// Coordinates per-CPU caches with the global free pool, providing
/// fast-path allocation from local caches and slow-path batch
/// refill/drain operations.
pub struct SwapSlotSubsystem {
    /// Per-CPU cache set.
    cache_set: SwapSlotCacheSet,
    /// Global free pool.
    global_pool: GlobalPool,
    /// Whether the swap slot cache is enabled.
    enabled: bool,
    /// Statistics.
    stats: SwapSlotStats,
}

impl SwapSlotSubsystem {
    /// Create a new subsystem with a pre-populated global pool.
    pub const fn new() -> Self {
        Self {
            cache_set: SwapSlotCacheSet::new(),
            global_pool: GlobalPool::new(),
            enabled: true,
            stats: SwapSlotStats {
                cache_hits: 0,
                cache_misses: 0,
                global_allocs: 0,
                global_frees: 0,
                refills: 0,
                drains: 0,
            },
        }
    }

    /// Return current statistics.
    pub const fn stats(&self) -> &SwapSlotStats {
        &self.stats
    }

    /// Whether the subsystem is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the subsystem.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Number of slots available in the global pool.
    pub const fn global_available(&self) -> u32 {
        self.global_pool.available()
    }

    /// Get a reference to the per-CPU cache set.
    pub const fn cache_set(&self) -> &SwapSlotCacheSet {
        &self.cache_set
    }

    /// Allocate a swap slot for the given CPU.
    ///
    /// Fast path: pop from the local cache.
    /// Slow path: refill from the global pool, then pop.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — `cpu_id` out of range
    /// * `OutOfMemory` — both local cache and global pool are empty
    /// * `NotImplemented` — subsystem is disabled
    pub fn alloc_swap_slot(&mut self, cpu_id: usize) -> Result<u64> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        if cpu_id >= NUM_CACHES {
            return Err(Error::InvalidArgument);
        }

        // Fast path: try local cache.
        if let Some(slot) = self.cache_set.caches[cpu_id].try_alloc() {
            self.stats.cache_hits += 1;
            return Ok(slot);
        }

        // Slow path: refill from global pool.
        self.stats.cache_misses += 1;
        self.refill_cache(cpu_id)?;

        // Try again after refill.
        self.cache_set.caches[cpu_id]
            .try_alloc()
            .ok_or(Error::OutOfMemory)
    }

    /// Free a swap slot for the given CPU.
    ///
    /// Fast path: push to the local cache.
    /// If the cache exceeds the drain threshold, batch-drain to global.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — `cpu_id` out of range or `slot` is invalid
    /// * `NotImplemented` — subsystem is disabled
    pub fn free_swap_slot(&mut self, cpu_id: usize, slot: u64) -> Result<()> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        if cpu_id >= NUM_CACHES {
            return Err(Error::InvalidArgument);
        }
        if slot == INVALID_SLOT {
            return Err(Error::InvalidArgument);
        }

        // Try local cache first.
        if !self.cache_set.caches[cpu_id].try_free(slot) {
            // Cache is full; return directly to global.
            if !self.global_pool.return_one(slot) {
                // Global pool is also full — this is extremely rare.
                return Err(Error::OutOfMemory);
            }
            self.stats.global_frees += 1;
        }

        // Check if the cache needs draining.
        if self.cache_set.caches[cpu_id].needs_drain() {
            self.drain_cache(cpu_id);
        }

        Ok(())
    }

    /// Manually refill a per-CPU cache from the global pool.
    ///
    /// # Errors
    ///
    /// * `OutOfMemory` — global pool is empty
    pub fn refill_cache(&mut self, cpu_id: usize) -> Result<()> {
        if cpu_id >= NUM_CACHES {
            return Err(Error::InvalidArgument);
        }

        let mut batch = [INVALID_SLOT; REFILL_BATCH];
        let taken = self.global_pool.take_batch(&mut batch, REFILL_BATCH);
        if taken == 0 {
            return Err(Error::OutOfMemory);
        }

        let filled = self.cache_set.caches[cpu_id].fill_from(&batch[..taken]);
        self.stats.global_allocs += filled as u64;
        self.stats.refills += 1;
        Ok(())
    }

    /// Drain a per-CPU cache back to the global pool.
    fn drain_cache(&mut self, cpu_id: usize) {
        if cpu_id >= NUM_CACHES {
            return;
        }

        let mut batch = [INVALID_SLOT; DRAIN_BATCH];
        let drained = self.cache_set.caches[cpu_id].drain_to(&mut batch, DRAIN_BATCH);
        if drained > 0 {
            let returned = self.global_pool.return_batch(&batch[..drained]);
            self.stats.global_frees += returned as u64;
            self.stats.drains += 1;
        }
    }

    /// Drain all per-CPU caches back to the global pool.
    ///
    /// Called during swap-off or system shutdown.
    pub fn drain_all_caches(&mut self) {
        for cpu in 0..NUM_CACHES {
            let mut batch = [INVALID_SLOT; CACHE_CAPACITY];
            let drained = self.cache_set.caches[cpu].drain_to(&mut batch, CACHE_CAPACITY);
            if drained > 0 {
                let returned = self.global_pool.return_batch(&batch[..drained]);
                self.stats.global_frees += returned as u64;
                self.stats.drains += 1;
            }
        }
    }

    /// Disable all per-CPU caches and drain their contents.
    pub fn disable_caches(&mut self) {
        self.drain_all_caches();
        for cpu in 0..NUM_CACHES {
            self.cache_set.caches[cpu].set_enabled(false);
        }
    }

    /// Enable all per-CPU caches.
    pub fn enable_caches(&mut self) {
        for cpu in 0..NUM_CACHES {
            self.cache_set.caches[cpu].set_enabled(true);
        }
    }

    /// Return the total number of cached slots across all CPUs.
    pub fn total_cached(&self) -> u32 {
        self.cache_set
            .caches
            .iter()
            .map(|c| u32::from(c.count))
            .sum()
    }
}

impl Default for SwapSlotSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
