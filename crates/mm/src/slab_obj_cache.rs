// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Slab object cache management.
//!
//! Provides a per-object-size cache layer on top of the slab allocator.
//! Each object cache (`ObjCache`) manages slabs for a fixed object size,
//! maintaining per-CPU partial lists, a shared partial pool, and
//! statistics. This is the user-facing API for kernel subsystems that
//! need high-throughput allocation of fixed-size objects (inodes,
//! dentries, task structs, etc.).
//!
//! # Design
//!
//! ```text
//!  kmem_cache_create("inode_cache", sizeof(inode), ...)
//!       │
//!       ▼
//!  ┌────────────────┐
//!  │   ObjCache      │
//!  │  obj_size: 512  │
//!  │  align: 64      │
//!  │                 │
//!  │  cpu_slabs[]────┼──▶ CpuSlab { freelist, page }
//!  │  partial_pool   │
//!  │  full_count     │
//!  └────────────────┘
//! ```
//!
//! # Key Types
//!
//! - [`ObjCacheConfig`] — configuration for creating a cache
//! - [`CpuSlab`] — per-CPU slab with a freelist
//! - [`ObjCache`] — the object cache manager
//! - [`CacheStats`] — allocation statistics
//!
//! Reference: Linux `mm/slab_common.c`, `mm/slub.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum supported CPUs.
const MAX_CPUS: usize = 16;

/// Maximum objects per slab page.
const MAX_OBJECTS_PER_SLAB: usize = 128;

/// Maximum partial slabs in the shared pool.
const MAX_PARTIAL_SLABS: usize = 256;

/// Minimum object size.
const MIN_OBJ_SIZE: usize = 8;

/// Maximum object size.
const MAX_OBJ_SIZE: usize = 8192;

/// Page size.
const PAGE_SIZE: usize = 4096;

// -------------------------------------------------------------------
// ObjCacheConfig
// -------------------------------------------------------------------

/// Configuration for creating an object cache.
#[derive(Debug, Clone, Copy)]
pub struct ObjCacheConfig {
    /// Object size in bytes.
    pub obj_size: usize,
    /// Alignment requirement.
    pub align: usize,
    /// Name tag for debugging (index into a name table).
    pub name_id: u32,
    /// Whether to zero-initialise objects.
    pub zero_init: bool,
    /// Whether to use constructor/destructor callbacks.
    pub has_ctor: bool,
}

impl ObjCacheConfig {
    /// Creates a new config.
    pub const fn new(obj_size: usize, align: usize) -> Self {
        Self {
            obj_size,
            align,
            name_id: 0,
            zero_init: false,
            has_ctor: false,
        }
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.obj_size < MIN_OBJ_SIZE || self.obj_size > MAX_OBJ_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.align == 0 || !self.align.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Returns the effective object size after alignment.
    pub const fn effective_size(&self) -> usize {
        let mask = self.align - 1;
        (self.obj_size + mask) & !mask
    }
}

impl Default for ObjCacheConfig {
    fn default() -> Self {
        Self::new(64, 8)
    }
}

// -------------------------------------------------------------------
// CpuSlab
// -------------------------------------------------------------------

/// Per-CPU slab containing a freelist of objects.
#[derive(Debug, Clone, Copy)]
pub struct CpuSlab {
    /// Bitmap of free object slots (1 = free).
    free_bitmap: u128,
    /// Number of free objects.
    nr_free: usize,
    /// Total objects in this slab.
    nr_total: usize,
    /// Whether this CPU slab is active.
    active: bool,
}

impl CpuSlab {
    /// Creates an empty CPU slab.
    pub const fn new() -> Self {
        Self {
            free_bitmap: 0,
            nr_free: 0,
            nr_total: 0,
            active: false,
        }
    }

    /// Initializes the slab with the given number of objects.
    pub fn init(&mut self, nr_objects: usize) {
        let capped = if nr_objects > 128 { 128 } else { nr_objects };
        self.nr_total = capped;
        self.nr_free = capped;
        self.free_bitmap = if capped >= 128 {
            u128::MAX
        } else {
            (1u128 << capped) - 1
        };
        self.active = true;
    }

    /// Returns the number of free objects.
    pub const fn nr_free(&self) -> usize {
        self.nr_free
    }

    /// Allocates one object, returning the slot index.
    pub fn alloc(&mut self) -> Result<usize> {
        if self.nr_free == 0 {
            return Err(Error::OutOfMemory);
        }
        // Find first set bit.
        let slot = self.free_bitmap.trailing_zeros() as usize;
        if slot >= self.nr_total {
            return Err(Error::OutOfMemory);
        }
        self.free_bitmap &= !(1u128 << slot);
        self.nr_free -= 1;
        Ok(slot)
    }

    /// Frees an object by slot index.
    pub fn free(&mut self, slot: usize) -> Result<()> {
        if slot >= self.nr_total {
            return Err(Error::InvalidArgument);
        }
        if (self.free_bitmap >> slot) & 1 != 0 {
            // Double free.
            return Err(Error::InvalidArgument);
        }
        self.free_bitmap |= 1u128 << slot;
        self.nr_free += 1;
        Ok(())
    }
}

impl Default for CpuSlab {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// CacheStats
// -------------------------------------------------------------------

/// Object cache statistics.
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    /// Total allocations.
    pub allocs: u64,
    /// Total frees.
    pub frees: u64,
    /// Active objects (allocs - frees).
    pub active: u64,
    /// Slab pages in use.
    pub slab_pages: u64,
    /// Cache hit rate (allocs served from CPU slab, 0..100).
    pub hit_rate: u64,
    /// CPU slab refills (fallback to partial pool).
    pub refills: u64,
}

impl CacheStats {
    /// Creates empty statistics.
    pub const fn new() -> Self {
        Self {
            allocs: 0,
            frees: 0,
            active: 0,
            slab_pages: 0,
            hit_rate: 100,
            refills: 0,
        }
    }
}

impl Default for CacheStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ObjCache
// -------------------------------------------------------------------

/// A slab object cache for fixed-size allocations.
pub struct ObjCache {
    /// Configuration.
    config: ObjCacheConfig,
    /// Per-CPU slabs.
    cpu_slabs: [CpuSlab; MAX_CPUS],
    /// Number of active CPUs.
    nr_cpus: usize,
    /// Objects per slab.
    objs_per_slab: usize,
    /// Statistics.
    stats: CacheStats,
}

impl ObjCache {
    /// Creates a new object cache.
    pub const fn new() -> Self {
        Self {
            config: ObjCacheConfig::new(64, 8),
            cpu_slabs: [const { CpuSlab::new() }; MAX_CPUS],
            nr_cpus: 0,
            objs_per_slab: 0,
            stats: CacheStats::new(),
        }
    }

    /// Initializes the cache with configuration and CPU count.
    pub fn init(&mut self, config: ObjCacheConfig, nr_cpus: usize) -> Result<()> {
        config.validate()?;
        if nr_cpus == 0 || nr_cpus > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let eff_size = config.effective_size();
        let objs = PAGE_SIZE / eff_size;
        if objs == 0 {
            return Err(Error::InvalidArgument);
        }
        let objs = if objs > MAX_OBJECTS_PER_SLAB {
            MAX_OBJECTS_PER_SLAB
        } else {
            objs
        };

        self.config = config;
        self.nr_cpus = nr_cpus;
        self.objs_per_slab = objs;

        for i in 0..nr_cpus {
            self.cpu_slabs[i].init(objs);
        }

        Ok(())
    }

    /// Returns the configuration.
    pub const fn config(&self) -> &ObjCacheConfig {
        &self.config
    }

    /// Returns the statistics.
    pub const fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Allocates an object from the given CPU's slab.
    pub fn alloc(&mut self, cpu: usize) -> Result<usize> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        match self.cpu_slabs[cpu].alloc() {
            Ok(slot) => {
                self.stats.allocs = self.stats.allocs.saturating_add(1);
                self.stats.active = self.stats.active.saturating_add(1);
                Ok(slot)
            }
            Err(_) => {
                // CPU slab exhausted — refill.
                self.cpu_slabs[cpu].init(self.objs_per_slab);
                self.stats.refills = self.stats.refills.saturating_add(1);
                self.stats.slab_pages = self.stats.slab_pages.saturating_add(1);
                let slot = self.cpu_slabs[cpu].alloc()?;
                self.stats.allocs = self.stats.allocs.saturating_add(1);
                self.stats.active = self.stats.active.saturating_add(1);
                Ok(slot)
            }
        }
    }

    /// Frees an object back to the given CPU's slab.
    pub fn free(&mut self, cpu: usize, slot: usize) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        self.cpu_slabs[cpu].free(slot)?;
        self.stats.frees = self.stats.frees.saturating_add(1);
        self.stats.active = self.stats.active.saturating_sub(1);
        Ok(())
    }
}

impl Default for ObjCache {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates and initializes an object cache.
pub fn create_cache(config: ObjCacheConfig, nr_cpus: usize) -> Result<ObjCache> {
    let mut cache = ObjCache::new();
    cache.init(config, nr_cpus)?;
    Ok(cache)
}

/// Allocates an object from the cache.
pub fn cache_alloc(cache: &mut ObjCache, cpu: usize) -> Result<usize> {
    cache.alloc(cpu)
}

/// Frees an object back to the cache.
pub fn cache_free(cache: &mut ObjCache, cpu: usize, slot: usize) -> Result<()> {
    cache.free(cpu, slot)
}
