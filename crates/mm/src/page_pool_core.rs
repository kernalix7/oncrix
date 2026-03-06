// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page pool management for networking and DMA.
//!
//! Provides a pre-allocated page pool with fast allocation and free
//! operations, pool growth/shrink, per-CPU caching, and recycle
//! callbacks. Designed for high-throughput packet processing where
//! the standard page allocator would be too slow.
//!
//! # Key Types
//!
//! - [`PagePoolConfig`] — pool creation parameters
//! - [`PoolPageState`] — lifecycle state of a pooled page
//! - [`PoolPageEntry`] — per-page metadata (PFN, state, napi_id)
//! - [`PerCpuPageCache`] — per-CPU cache for hot-path alloc/free
//! - [`PagePoolStats`] — statistics for monitoring
//! - [`PagePoolCore`] — the main pool engine
//! - [`PagePoolRegistry`] — system-wide registry of pools
//!
//! Reference: Linux `net/core/page_pool.c`,
//! `include/net/page_pool/types.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum pages managed by a single pool.
const MAX_POOL_PAGES: usize = 1024;

/// Maximum number of page pools in the system.
const MAX_POOLS: usize = 16;

/// Maximum CPUs for per-CPU caching.
const MAX_CPUS: usize = 8;

/// Per-CPU cache capacity (pages).
const PER_CPU_CACHE_SIZE: usize = 64;

/// Default pool fill fraction (initial allocation is 25% of max).
const DEFAULT_FILL_FRACTION: usize = 4;

/// Low watermark fraction (refill when below 1/8 of pool size).
const LOW_WATERMARK_FRAC: usize = 8;

/// High watermark fraction (shrink when above 7/8 of pool size).
const HIGH_WATERMARK_FRAC: usize = 8;

/// Maximum batch size for refill/drain operations.
const MAX_BATCH_SIZE: usize = 32;

// -------------------------------------------------------------------
// PoolPageState
// -------------------------------------------------------------------

/// Lifecycle state of a page within the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PoolPageState {
    /// Page is free and available for allocation.
    #[default]
    Free,
    /// Page is allocated to a consumer (e.g., network stack).
    InUse,
    /// Page is in a per-CPU cache awaiting reuse.
    Cached,
    /// Page is queued for recycling via the recycle callback.
    Recycling,
    /// Page has been released back to the underlying allocator.
    Released,
}

// -------------------------------------------------------------------
// PagePoolConfig
// -------------------------------------------------------------------

/// Configuration for creating a new page pool.
#[derive(Debug, Clone, Copy)]
pub struct PagePoolConfig {
    /// Maximum number of pages this pool manages.
    pub max_pages: usize,
    /// Desired page order (0 = 4K, 1 = 8K, etc.).
    pub page_order: u8,
    /// NAPI ID hint for per-CPU affinity.
    pub napi_id: u32,
    /// Whether DMA mapping is required for pool pages.
    pub dma_required: bool,
    /// DMA direction: 0 = bidirectional, 1 = to-device, 2 = from-device.
    pub dma_direction: u8,
    /// Number of pages to pre-fill at creation.
    pub prefill_count: usize,
    /// Enable per-CPU caching.
    pub per_cpu_cache: bool,
}

impl Default for PagePoolConfig {
    fn default() -> Self {
        Self {
            max_pages: MAX_POOL_PAGES,
            page_order: 0,
            napi_id: 0,
            dma_required: false,
            dma_direction: 0,
            prefill_count: MAX_POOL_PAGES / DEFAULT_FILL_FRACTION,
            per_cpu_cache: true,
        }
    }
}

// -------------------------------------------------------------------
// PoolPageEntry
// -------------------------------------------------------------------

/// Metadata for a single page managed by the pool.
#[derive(Debug, Clone, Copy)]
pub struct PoolPageEntry {
    /// Physical frame number.
    pub pfn: u64,
    /// Current lifecycle state.
    pub state: PoolPageState,
    /// Reference count (for shared usage).
    pub ref_count: u16,
    /// Page order (0 = single 4K page).
    pub order: u8,
    /// DMA address (if DMA mapping is active).
    pub dma_addr: u64,
    /// NAPI ID this page is associated with.
    pub napi_id: u32,
    /// Recycling generation counter.
    pub generation: u32,
}

impl Default for PoolPageEntry {
    fn default() -> Self {
        Self {
            pfn: 0,
            state: PoolPageState::Free,
            ref_count: 0,
            order: 0,
            dma_addr: 0,
            napi_id: 0,
            generation: 0,
        }
    }
}

// -------------------------------------------------------------------
// PerCpuPageCache
// -------------------------------------------------------------------

/// Per-CPU page cache for fast hot-path allocation.
///
/// Each CPU keeps a small ring buffer of recently freed pages to
/// avoid contending on the central pool.
pub struct PerCpuPageCache {
    /// Cached page PFNs.
    entries: [u64; PER_CPU_CACHE_SIZE],
    /// Number of valid entries.
    count: usize,
    /// CPU this cache belongs to.
    cpu_id: u32,
    /// Total allocations served from this cache.
    cache_hits: u64,
    /// Total allocations that missed this cache.
    cache_misses: u64,
}

impl PerCpuPageCache {
    /// Creates an empty cache for the given CPU.
    const fn new(cpu_id: u32) -> Self {
        Self {
            entries: [0u64; PER_CPU_CACHE_SIZE],
            count: 0,
            cpu_id,
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    /// Attempts to pop a page PFN from the cache.
    pub fn alloc(&mut self) -> Option<u64> {
        if self.count == 0 {
            self.cache_misses += 1;
            return None;
        }
        self.count -= 1;
        self.cache_hits += 1;
        Some(self.entries[self.count])
    }

    /// Pushes a page PFN into the cache. Returns false if full.
    pub fn free(&mut self, pfn: u64) -> bool {
        if self.count >= PER_CPU_CACHE_SIZE {
            return false;
        }
        self.entries[self.count] = pfn;
        self.count += 1;
        true
    }

    /// Returns the number of cached pages.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Drains up to `n` entries from the cache into the provided slice.
    /// Returns the number of entries drained.
    pub fn drain(&mut self, out: &mut [u64], n: usize) -> usize {
        let to_drain = n.min(self.count).min(out.len());
        for i in 0..to_drain {
            self.count -= 1;
            out[i] = self.entries[self.count];
        }
        to_drain
    }

    /// Returns cache hit count.
    pub fn hits(&self) -> u64 {
        self.cache_hits
    }

    /// Returns cache miss count.
    pub fn misses(&self) -> u64 {
        self.cache_misses
    }

    /// Returns the CPU ID.
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }
}

// -------------------------------------------------------------------
// PagePoolStats
// -------------------------------------------------------------------

/// Statistics for a page pool.
#[derive(Debug, Clone, Copy, Default)]
pub struct PagePoolStats {
    /// Total pages currently managed by the pool.
    pub total_pages: usize,
    /// Pages currently free in the central pool.
    pub free_pages: usize,
    /// Pages currently in use.
    pub in_use_pages: usize,
    /// Pages in per-CPU caches.
    pub cached_pages: usize,
    /// Pages undergoing recycling.
    pub recycling_pages: usize,
    /// Cumulative successful allocations.
    pub alloc_count: u64,
    /// Cumulative frees/recycles.
    pub free_count: u64,
    /// Per-CPU cache hit total.
    pub cache_hits: u64,
    /// Per-CPU cache miss total.
    pub cache_misses: u64,
    /// Number of pool grow events.
    pub grow_events: u64,
    /// Number of pool shrink events.
    pub shrink_events: u64,
    /// Number of recycle callback invocations.
    pub recycle_count: u64,
}

// -------------------------------------------------------------------
// PagePoolCore
// -------------------------------------------------------------------

/// Core page pool engine for networking and DMA subsystems.
///
/// Manages a set of pre-allocated pages with fast alloc/free,
/// per-CPU caching, automatic grow/shrink, and recycle callbacks.
pub struct PagePoolCore {
    /// Pool identifier.
    pool_id: u32,
    /// Configuration.
    config: PagePoolConfig,
    /// Per-page metadata.
    pages: [PoolPageEntry; MAX_POOL_PAGES],
    /// Number of pages currently tracked.
    total_pages: usize,
    /// Number of free pages in the central pool.
    free_count: usize,
    /// Per-CPU caches.
    cpu_caches: [PerCpuPageCache; MAX_CPUS],
    /// Number of active CPUs.
    nr_cpus: usize,
    /// Whether this pool is active.
    active: bool,
    /// Monotonic generation counter for recycling.
    generation: u32,
    /// Statistics.
    alloc_count: u64,
    free_op_count: u64,
    grow_events: u64,
    shrink_events: u64,
    recycle_count: u64,
}

impl PagePoolCore {
    /// Creates a new page pool with the given ID and configuration.
    ///
    /// Pre-fills the pool with `config.prefill_count` pages
    /// (sequential PFNs starting from `base_pfn`).
    pub fn new(pool_id: u32, config: PagePoolConfig, base_pfn: u64) -> Self {
        let max = config.max_pages.min(MAX_POOL_PAGES);
        let prefill = config.prefill_count.min(max);

        let mut pages = [PoolPageEntry::default(); MAX_POOL_PAGES];
        for i in 0..prefill {
            pages[i] = PoolPageEntry {
                pfn: base_pfn + i as u64,
                state: PoolPageState::Free,
                ref_count: 0,
                order: config.page_order,
                dma_addr: if config.dma_required {
                    (base_pfn + i as u64) * PAGE_SIZE as u64
                } else {
                    0
                },
                napi_id: config.napi_id,
                generation: 0,
            };
        }

        Self {
            pool_id,
            config,
            pages,
            total_pages: prefill,
            free_count: prefill,
            cpu_caches: [
                PerCpuPageCache::new(0),
                PerCpuPageCache::new(1),
                PerCpuPageCache::new(2),
                PerCpuPageCache::new(3),
                PerCpuPageCache::new(4),
                PerCpuPageCache::new(5),
                PerCpuPageCache::new(6),
                PerCpuPageCache::new(7),
            ],
            nr_cpus: MAX_CPUS,
            active: true,
            generation: 0,
            alloc_count: 0,
            free_op_count: 0,
            grow_events: 0,
            shrink_events: 0,
            recycle_count: 0,
        }
    }

    /// Allocates a page, preferring the per-CPU cache for `cpu`.
    ///
    /// Falls back to the central pool if the cache is empty.
    /// Returns the PFN of the allocated page.
    pub fn alloc_page(&mut self, cpu: usize) -> Result<u64> {
        if !self.active {
            return Err(Error::InvalidArgument);
        }

        // Try per-CPU cache first.
        if self.config.per_cpu_cache && cpu < self.nr_cpus {
            if let Some(pfn) = self.cpu_caches[cpu].alloc() {
                // Mark the page as in-use.
                if let Some(idx) = self.find_page(pfn) {
                    self.pages[idx].state = PoolPageState::InUse;
                    self.pages[idx].ref_count = 1;
                }
                self.alloc_count += 1;
                return Ok(pfn);
            }
        }

        // Fall back to central pool.
        let idx = self.find_free_page().ok_or(Error::OutOfMemory)?;
        self.pages[idx].state = PoolPageState::InUse;
        self.pages[idx].ref_count = 1;
        self.free_count -= 1;
        self.alloc_count += 1;
        Ok(self.pages[idx].pfn)
    }

    /// Frees a page back to the pool.
    ///
    /// If per-CPU caching is enabled, tries to place the page in the
    /// CPU's cache first. Otherwise returns it to the central pool.
    pub fn free_page(&mut self, pfn: u64, cpu: usize) -> Result<()> {
        let idx = self.find_page(pfn).ok_or(Error::NotFound)?;
        if self.pages[idx].state != PoolPageState::InUse {
            return Err(Error::InvalidArgument);
        }

        self.pages[idx].ref_count = 0;

        // Try per-CPU cache.
        if self.config.per_cpu_cache && cpu < self.nr_cpus {
            if self.cpu_caches[cpu].free(pfn) {
                self.pages[idx].state = PoolPageState::Cached;
                self.free_op_count += 1;
                return Ok(());
            }
        }

        // Return to central pool.
        self.pages[idx].state = PoolPageState::Free;
        self.free_count += 1;
        self.free_op_count += 1;
        Ok(())
    }

    /// Recycles a page (e.g., after network packet processing).
    ///
    /// Increments the generation counter and returns the page to
    /// the free pool without a full DMA unmap/remap cycle.
    pub fn recycle_page(&mut self, pfn: u64) -> Result<()> {
        let idx = self.find_page(pfn).ok_or(Error::NotFound)?;
        if self.pages[idx].state != PoolPageState::InUse {
            return Err(Error::InvalidArgument);
        }

        self.pages[idx].state = PoolPageState::Free;
        self.pages[idx].ref_count = 0;
        self.pages[idx].generation += 1;
        self.free_count += 1;
        self.recycle_count += 1;
        Ok(())
    }

    /// Grows the pool by `count` pages starting at `base_pfn`.
    ///
    /// Returns the number of pages actually added.
    pub fn grow(&mut self, base_pfn: u64, count: usize) -> Result<usize> {
        if !self.active {
            return Err(Error::InvalidArgument);
        }

        let max = self.config.max_pages.min(MAX_POOL_PAGES);
        let available = max.saturating_sub(self.total_pages);
        let to_add = count.min(available);

        if to_add == 0 {
            return Err(Error::OutOfMemory);
        }

        for i in 0..to_add {
            let slot = self.total_pages + i;
            self.pages[slot] = PoolPageEntry {
                pfn: base_pfn + i as u64,
                state: PoolPageState::Free,
                ref_count: 0,
                order: self.config.page_order,
                dma_addr: if self.config.dma_required {
                    (base_pfn + i as u64) * PAGE_SIZE as u64
                } else {
                    0
                },
                napi_id: self.config.napi_id,
                generation: self.generation,
            };
        }

        self.total_pages += to_add;
        self.free_count += to_add;
        self.grow_events += 1;
        Ok(to_add)
    }

    /// Shrinks the pool by releasing up to `count` free pages.
    ///
    /// Only releases pages in [`PoolPageState::Free`] state.
    /// Returns the number of pages released.
    pub fn shrink(&mut self, count: usize) -> usize {
        let mut released = 0usize;
        let mut i = 0;
        while i < self.total_pages && released < count {
            if self.pages[i].state == PoolPageState::Free {
                self.pages[i].state = PoolPageState::Released;
                self.free_count -= 1;
                released += 1;
            }
            i += 1;
        }
        if released > 0 {
            self.shrink_events += 1;
        }
        released
    }

    /// Drains all per-CPU caches back to the central pool.
    pub fn drain_cpu_caches(&mut self) {
        let mut buf = [0u64; PER_CPU_CACHE_SIZE];
        for cpu in 0..self.nr_cpus {
            let drained = self.cpu_caches[cpu].drain(&mut buf, PER_CPU_CACHE_SIZE);
            for j in 0..drained {
                if let Some(idx) = self.find_page(buf[j]) {
                    if self.pages[idx].state == PoolPageState::Cached {
                        self.pages[idx].state = PoolPageState::Free;
                        self.free_count += 1;
                    }
                }
            }
        }
    }

    /// Returns `true` if the pool is below its low watermark.
    pub fn needs_refill(&self) -> bool {
        self.free_count < self.total_pages / LOW_WATERMARK_FRAC
    }

    /// Returns `true` if the pool is above its high watermark.
    pub fn can_shrink(&self) -> bool {
        let threshold = self.total_pages - self.total_pages / HIGH_WATERMARK_FRAC;
        self.free_count > threshold
    }

    /// Returns the pool ID.
    pub fn pool_id(&self) -> u32 {
        self.pool_id
    }

    /// Returns the pool configuration.
    pub fn config(&self) -> &PagePoolConfig {
        &self.config
    }

    /// Returns the total number of tracked pages.
    pub fn total_pages(&self) -> usize {
        self.total_pages
    }

    /// Returns the number of free pages in the central pool.
    pub fn free_count(&self) -> usize {
        self.free_count
    }

    /// Returns `true` if the pool is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivates the pool, preventing new allocations.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Collects comprehensive statistics.
    pub fn stats(&self) -> PagePoolStats {
        let mut cached = 0usize;
        let mut in_use = 0usize;
        let mut recycling = 0usize;

        for i in 0..self.total_pages {
            match self.pages[i].state {
                PoolPageState::Cached => cached += 1,
                PoolPageState::InUse => in_use += 1,
                PoolPageState::Recycling => recycling += 1,
                _ => {}
            }
        }

        let mut cache_hits = 0u64;
        let mut cache_misses = 0u64;
        for cpu in 0..self.nr_cpus {
            cache_hits += self.cpu_caches[cpu].cache_hits;
            cache_misses += self.cpu_caches[cpu].cache_misses;
            cached += self.cpu_caches[cpu].count;
        }

        PagePoolStats {
            total_pages: self.total_pages,
            free_pages: self.free_count,
            in_use_pages: in_use,
            cached_pages: cached,
            recycling_pages: recycling,
            alloc_count: self.alloc_count,
            free_count: self.free_op_count,
            cache_hits,
            cache_misses,
            grow_events: self.grow_events,
            shrink_events: self.shrink_events,
            recycle_count: self.recycle_count,
        }
    }

    // -- internal helpers --

    /// Finds the index of a free page in the central pool.
    fn find_free_page(&self) -> Option<usize> {
        for i in 0..self.total_pages {
            if self.pages[i].state == PoolPageState::Free {
                return Some(i);
            }
        }
        None
    }

    /// Finds the index of a page by PFN.
    fn find_page(&self, pfn: u64) -> Option<usize> {
        for i in 0..self.total_pages {
            if self.pages[i].pfn == pfn {
                return Some(i);
            }
        }
        None
    }
}

// -------------------------------------------------------------------
// PagePoolCoreRegistry
// -------------------------------------------------------------------

/// System-wide registry of page pools.
pub struct PagePoolCoreRegistry {
    /// Registered pools (by slot index).
    pools: [Option<PagePoolCore>; MAX_POOLS],
    /// Number of registered pools.
    count: usize,
    /// Next pool ID to assign.
    next_id: u32,
}

impl PagePoolCoreRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<PagePoolCore> = None;
        Self {
            pools: [NONE; MAX_POOLS],
            count: 0,
            next_id: 1,
        }
    }

    /// Creates and registers a new pool with the given config.
    ///
    /// Returns the pool ID on success.
    pub fn create_pool(&mut self, config: PagePoolConfig, base_pfn: u64) -> Result<u32> {
        let slot = self.find_empty_slot().ok_or(Error::OutOfMemory)?;
        let pool_id = self.next_id;
        self.pools[slot] = Some(PagePoolCore::new(pool_id, config, base_pfn));
        self.count += 1;
        self.next_id += 1;
        Ok(pool_id)
    }

    /// Looks up a pool by ID.
    pub fn get(&self, pool_id: u32) -> Result<&PagePoolCore> {
        for i in 0..MAX_POOLS {
            if let Some(pool) = &self.pools[i] {
                if pool.pool_id == pool_id {
                    return Ok(pool);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Looks up a pool by ID (mutable).
    pub fn get_mut(&mut self, pool_id: u32) -> Result<&mut PagePoolCore> {
        let pos = (0..MAX_POOLS)
            .find(|&i| self.pools[i].as_ref().is_some_and(|p| p.pool_id == pool_id))
            .ok_or(Error::NotFound)?;
        self.pools[pos].as_mut().ok_or(Error::NotFound)
    }

    /// Destroys a pool by ID.
    pub fn destroy_pool(&mut self, pool_id: u32) -> Result<()> {
        for i in 0..MAX_POOLS {
            let matches = self.pools[i]
                .as_ref()
                .map_or(false, |p| p.pool_id == pool_id);
            if matches {
                self.pools[i] = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered pools.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns `true` if there are no registered pools.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Finds the first empty slot.
    fn find_empty_slot(&self) -> Option<usize> {
        for i in 0..MAX_POOLS {
            if self.pools[i].is_none() {
                return Some(i);
            }
        }
        None
    }
}

impl Default for PagePoolCoreRegistry {
    fn default() -> Self {
        Self::new()
    }
}
