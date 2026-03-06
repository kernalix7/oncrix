// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! kmalloc slab cache sizes.
//!
//! Implements the kmalloc family of allocators, which provide
//! power-of-two and intermediate-sized object caches for kernel
//! memory allocation. Sizes range from 8 bytes to 8192 bytes,
//! with intermediate caches at 96 and 192 bytes for common kernel
//! object sizes.
//!
//! - [`KmallocIndex`] — maps allocation size to cache index
//! - [`KmallocCache`] — a single size cache
//! - [`KmallocCaches`] — the full set of caches
//! - [`GfpFlags`] — allocation flags
//!
//! Reference: `.kernelORG/` — `mm/slab_common.c`, `include/linux/slab.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Number of kmalloc cache sizes.
const NR_KMALLOC_CACHES: usize = 13;

/// Maximum kmalloc size (8 KiB).
const KMALLOC_MAX_SIZE: usize = 8192;

/// Minimum kmalloc size (8 bytes).
const KMALLOC_MIN_SIZE: usize = 8;

/// Page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum objects per cache.
const MAX_OBJECTS_PER_CACHE: usize = 256;

/// Cache sizes in bytes.
const CACHE_SIZES: [usize; NR_KMALLOC_CACHES] = [
    8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192,
];

/// GFP flag: allow sleeping.
const GFP_KERNEL: u32 = 1 << 0;

/// GFP flag: atomic (no sleeping).
const GFP_ATOMIC: u32 = 1 << 1;

/// GFP flag: zero-fill allocation.
const GFP_ZERO: u32 = 1 << 2;

/// GFP flag: DMA-safe memory.
const GFP_DMA: u32 = 1 << 3;

/// GFP flag: reclaimable slab.
const GFP_RECLAIMABLE: u32 = 1 << 4;

// -------------------------------------------------------------------
// KmallocIndex
// -------------------------------------------------------------------

/// Maps an allocation size to the appropriate kmalloc cache index.
///
/// Returns the index into [`CACHE_SIZES`] for the smallest cache
/// that can satisfy the requested size.
pub fn kmalloc_index(size: usize) -> Result<usize> {
    if size == 0 {
        return Err(Error::InvalidArgument);
    }
    if size > KMALLOC_MAX_SIZE {
        return Err(Error::InvalidArgument);
    }

    for (i, &cache_size) in CACHE_SIZES.iter().enumerate() {
        if size <= cache_size {
            return Ok(i);
        }
    }

    Err(Error::InvalidArgument)
}

/// Returns the actual allocated size for a given request size.
pub fn ksize(size: usize) -> Result<usize> {
    let idx = kmalloc_index(size)?;
    Ok(CACHE_SIZES[idx])
}

// -------------------------------------------------------------------
// KmallocObject
// -------------------------------------------------------------------

/// A single allocated object in a kmalloc cache.
#[derive(Debug, Clone, Copy)]
struct KmallocObject {
    /// Address of the allocated object.
    addr: u64,
    /// Whether this slot is in use.
    in_use: bool,
    /// GFP flags used for this allocation.
    gfp_flags: u32,
    /// Caller identifier (for debugging).
    caller_id: u32,
}

impl Default for KmallocObject {
    fn default() -> Self {
        Self {
            addr: 0,
            in_use: false,
            gfp_flags: 0,
            caller_id: 0,
        }
    }
}

// -------------------------------------------------------------------
// KmallocCache
// -------------------------------------------------------------------

/// A single kmalloc size cache.
///
/// Each cache manages objects of a fixed size. Objects are pre-allocated
/// in slabs and handed out on kmalloc, returned on kfree.
pub struct KmallocCache {
    /// Object size for this cache.
    obj_size: usize,
    /// Cache index.
    index: usize,
    /// Object slots.
    objects: [KmallocObject; MAX_OBJECTS_PER_CACHE],
    /// Number of allocated objects.
    nr_allocated: usize,
    /// Number of free objects.
    nr_free: usize,
    /// Total allocations (lifetime).
    total_allocs: u64,
    /// Total frees (lifetime).
    total_frees: u64,
    /// Next address to assign.
    next_addr: u64,
}

impl KmallocCache {
    /// Creates a new cache for the given size and index.
    pub fn new(obj_size: usize, index: usize) -> Self {
        Self {
            obj_size,
            index,
            objects: [KmallocObject::default(); MAX_OBJECTS_PER_CACHE],
            nr_allocated: 0,
            nr_free: MAX_OBJECTS_PER_CACHE,
            total_allocs: 0,
            total_frees: 0,
            next_addr: (index as u64 + 1) * 0x1_0000_0000,
        }
    }

    /// Returns the object size.
    pub fn obj_size(&self) -> usize {
        self.obj_size
    }

    /// Returns the cache index.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Allocates an object from this cache.
    pub fn alloc(&mut self, gfp_flags: u32, caller_id: u32) -> Result<u64> {
        if self.nr_free == 0 {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot.
        for obj in &mut self.objects {
            if !obj.in_use {
                obj.in_use = true;
                obj.addr = self.next_addr;
                obj.gfp_flags = gfp_flags;
                obj.caller_id = caller_id;
                self.next_addr += self.obj_size as u64;
                self.nr_allocated += 1;
                self.nr_free -= 1;
                self.total_allocs += 1;
                return Ok(obj.addr);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Frees an object back to this cache.
    pub fn free(&mut self, addr: u64) -> Result<()> {
        for obj in &mut self.objects {
            if obj.in_use && obj.addr == addr {
                obj.in_use = false;
                self.nr_allocated -= 1;
                self.nr_free += 1;
                self.total_frees += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of allocated objects.
    pub fn nr_allocated(&self) -> usize {
        self.nr_allocated
    }

    /// Returns the number of free objects.
    pub fn nr_free(&self) -> usize {
        self.nr_free
    }

    /// Returns total allocations.
    pub fn total_allocs(&self) -> u64 {
        self.total_allocs
    }

    /// Returns total frees.
    pub fn total_frees(&self) -> u64 {
        self.total_frees
    }

    /// Returns memory used by allocated objects.
    pub fn memory_used(&self) -> usize {
        self.nr_allocated * self.obj_size
    }
}

// -------------------------------------------------------------------
// KmallocCaches
// -------------------------------------------------------------------

/// The full set of kmalloc caches (8..8192 bytes).
pub struct KmallocCaches {
    /// Per-size caches.
    caches: [KmallocCache; NR_KMALLOC_CACHES],
}

impl KmallocCaches {
    /// Creates and initializes all kmalloc caches.
    pub fn new() -> Self {
        let caches = [
            KmallocCache::new(8, 0),
            KmallocCache::new(16, 1),
            KmallocCache::new(32, 2),
            KmallocCache::new(64, 3),
            KmallocCache::new(96, 4),
            KmallocCache::new(128, 5),
            KmallocCache::new(192, 6),
            KmallocCache::new(256, 7),
            KmallocCache::new(512, 8),
            KmallocCache::new(1024, 9),
            KmallocCache::new(2048, 10),
            KmallocCache::new(4096, 11),
            KmallocCache::new(8192, 12),
        ];
        Self { caches }
    }

    /// Allocates memory of the requested size.
    ///
    /// Finds the smallest cache that can satisfy the request and
    /// allocates an object from it.
    pub fn kmalloc(&mut self, size: usize, gfp_flags: u32, caller_id: u32) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let idx = kmalloc_index(size)?;
        self.caches[idx].alloc(gfp_flags, caller_id)
    }

    /// Frees previously allocated memory.
    ///
    /// Searches all caches for the given address.
    pub fn kfree(&mut self, addr: u64) -> Result<()> {
        for cache in &mut self.caches {
            if cache.free(addr).is_ok() {
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Reallocates memory to a new size.
    ///
    /// If the new size fits in the same cache, returns the same address.
    /// Otherwise allocates from a larger cache and frees the old one.
    pub fn krealloc(
        &mut self,
        addr: u64,
        new_size: usize,
        gfp_flags: u32,
        caller_id: u32,
    ) -> Result<u64> {
        if new_size == 0 {
            self.kfree(addr)?;
            return Err(Error::InvalidArgument);
        }

        // Find current cache index for the address.
        let mut old_idx = None;
        for (i, cache) in self.caches.iter().enumerate() {
            for obj in &cache.objects {
                if obj.in_use && obj.addr == addr {
                    old_idx = Some(i);
                    break;
                }
            }
            if old_idx.is_some() {
                break;
            }
        }

        let old_idx = old_idx.ok_or(Error::NotFound)?;
        let new_idx = kmalloc_index(new_size)?;

        // If same cache, no need to move.
        if new_idx == old_idx {
            return Ok(addr);
        }

        // Allocate from new cache, then free old.
        let new_addr = self.caches[new_idx].alloc(gfp_flags, caller_id)?;
        let _ = self.caches[old_idx].free(addr);
        Ok(new_addr)
    }

    /// Returns a reference to a specific cache.
    pub fn cache(&self, index: usize) -> Option<&KmallocCache> {
        self.caches.get(index)
    }

    /// Returns the total memory used across all caches.
    pub fn total_memory_used(&self) -> usize {
        self.caches.iter().map(|c| c.memory_used()).sum()
    }

    /// Returns the total number of allocated objects.
    pub fn total_allocated(&self) -> usize {
        self.caches.iter().map(|c| c.nr_allocated()).sum()
    }

    /// Returns the total number of free slots.
    pub fn total_free(&self) -> usize {
        self.caches.iter().map(|c| c.nr_free()).sum()
    }
}

impl Default for KmallocCaches {
    fn default() -> Self {
        Self::new()
    }
}
