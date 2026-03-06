// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Type-safe slab freeing (SLAB_TYPESAFE_BY_RCU).
//!
//! Implements RCU-delayed slab object freeing with a generation
//! counter to detect stale object reuse. Slab caches created with
//! the `typesafe_by_rcu` flag defer object destruction until an
//! RCU grace period has elapsed, allowing lockless readers to
//! safely inspect objects that may be concurrently freed.
//!
//! # Architecture
//!
//! - [`TypesafeSlabCache`] — a slab cache with typesafe-by-RCU
//!   semantics
//! - [`TypesafeObject`] — metadata for an object in the cache
//! - [`DelayedFreeEntry`] — a pending delayed-free request
//! - [`TypesafeSlabManager`] — top-level manager owning multiple
//!   caches
//!
//! ## Object lifecycle
//!
//! 1. `alloc` — returns an object with a fresh generation counter
//! 2. `free` — object goes to the delayed-free list instead of
//!    immediately returning to the free list
//! 3. After a grace period (`drain_delayed`), the object is
//!    returned to the free list with its generation bumped
//! 4. A reader holding a stale generation can detect reuse by
//!    comparing generation counters via `validate_generation`
//!
//! Reference: Linux `mm/slab_common.c` (`SLAB_TYPESAFE_BY_RCU`).

use oncrix_lib::{Error, Result};

// -- Constants

/// Maximum number of typesafe slab caches.
const MAX_CACHES: usize = 32;

/// Maximum number of objects per cache.
const MAX_OBJECTS_PER_CACHE: usize = 128;

/// Maximum number of delayed-free entries per cache.
const MAX_DELAYED_PER_CACHE: usize = 64;

/// Maximum cache name length.
const MAX_NAME_LEN: usize = 32;

// -- TypesafeObject

/// Metadata for a single object in a typesafe slab cache.
#[derive(Debug, Clone, Copy)]
pub struct TypesafeObject {
    /// Object slot index within the cache.
    pub slot: usize,
    /// Generation counter (incremented on each free + realloc).
    pub generation: u64,
    /// Whether the object is currently allocated.
    pub allocated: bool,
    /// Whether this slot has ever been used.
    pub initialized: bool,
}

impl TypesafeObject {
    const fn empty() -> Self {
        Self {
            slot: 0,
            generation: 0,
            allocated: false,
            initialized: false,
        }
    }
}

impl Default for TypesafeObject {
    fn default() -> Self {
        Self::empty()
    }
}

// -- DelayedFreeEntry

/// A pending delayed-free request.
#[derive(Debug, Clone, Copy)]
pub struct DelayedFreeEntry {
    /// Object slot index.
    pub slot: usize,
    /// Generation at the time of free.
    pub generation: u64,
    /// Simulated RCU epoch at which this free was queued.
    pub rcu_epoch: u64,
    /// Whether this entry is pending.
    pub active: bool,
}

impl DelayedFreeEntry {
    const fn empty() -> Self {
        Self {
            slot: 0,
            generation: 0,
            rcu_epoch: 0,
            active: false,
        }
    }
}

impl Default for DelayedFreeEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -- TypesafeSlabCache

/// A slab cache with SLAB_TYPESAFE_BY_RCU semantics.
#[derive(Debug, Clone, Copy)]
pub struct TypesafeSlabCache {
    /// Cache name (fixed-length, zero-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    pub name_len: usize,
    /// Object size in bytes.
    pub object_size: usize,
    /// Object metadata slots.
    pub objects: [TypesafeObject; MAX_OBJECTS_PER_CACHE],
    /// Number of allocated objects.
    pub allocated_count: usize,
    /// Total capacity.
    pub capacity: usize,
    /// Delayed-free list.
    pub delayed: [DelayedFreeEntry; MAX_DELAYED_PER_CACHE],
    /// Number of pending delayed frees.
    pub delayed_count: usize,
    /// Whether typesafe_by_rcu is enabled.
    pub typesafe: bool,
    /// Whether this cache slot is active.
    pub active: bool,
    /// Current simulated RCU epoch.
    pub current_epoch: u64,
    /// Total allocations.
    pub total_allocs: u64,
    /// Total frees.
    pub total_frees: u64,
    /// Total delayed drains.
    pub total_drains: u64,
}

impl TypesafeSlabCache {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            object_size: 0,
            objects: [const { TypesafeObject::empty() }; MAX_OBJECTS_PER_CACHE],
            allocated_count: 0,
            capacity: 0,
            delayed: [const { DelayedFreeEntry::empty() }; MAX_DELAYED_PER_CACHE],
            delayed_count: 0,
            typesafe: false,
            active: false,
            current_epoch: 0,
            total_allocs: 0,
            total_frees: 0,
            total_drains: 0,
        }
    }

    /// Allocate an object. Returns (slot, generation).
    fn alloc(&mut self) -> Result<(usize, u64)> {
        let slot_pos = {
            let mut found = None;
            for i in 0..self.capacity {
                if !self.objects[i].allocated {
                    found = Some(i);
                    break;
                }
            }
            found.ok_or(Error::OutOfMemory)?
        };
        self.objects[slot_pos].allocated = true;
        self.objects[slot_pos].initialized = true;
        self.objects[slot_pos].slot = slot_pos;
        let cur_gen = self.objects[slot_pos].generation;
        self.allocated_count += 1;
        self.total_allocs += 1;
        Ok((slot_pos, cur_gen))
    }

    /// Free an object. If typesafe, defers to delayed list.
    fn free(&mut self, slot: usize) -> Result<()> {
        if slot >= self.capacity {
            return Err(Error::InvalidArgument);
        }
        if !self.objects[slot].allocated {
            return Err(Error::NotFound);
        }
        if self.typesafe {
            self.defer_free(slot)?;
        } else {
            self.objects[slot].allocated = false;
            self.objects[slot].generation += 1;
            self.allocated_count = self.allocated_count.saturating_sub(1);
        }
        self.total_frees += 1;
        Ok(())
    }

    /// Queue a delayed free.
    fn defer_free(&mut self, slot: usize) -> Result<()> {
        let idx = self
            .delayed
            .iter()
            .position(|d| !d.active)
            .ok_or(Error::Busy)?;
        self.delayed[idx] = DelayedFreeEntry {
            slot,
            generation: self.objects[slot].generation,
            rcu_epoch: self.current_epoch,
            active: true,
        };
        self.delayed_count += 1;
        // Mark as not allocated but keep generation.
        self.objects[slot].allocated = false;
        self.allocated_count = self.allocated_count.saturating_sub(1);
        Ok(())
    }

    /// Drain delayed entries whose RCU epoch has passed.
    ///
    /// Returns the number of entries drained.
    fn drain_delayed(&mut self, safe_epoch: u64) -> usize {
        let mut drained = 0usize;
        for entry in &mut self.delayed {
            if !entry.active {
                continue;
            }
            if entry.rcu_epoch < safe_epoch {
                let slot = entry.slot;
                if slot < self.capacity {
                    self.objects[slot].generation += 1;
                }
                entry.active = false;
                self.delayed_count = self.delayed_count.saturating_sub(1);
                drained += 1;
            }
        }
        self.total_drains += drained as u64;
        drained
    }

    /// Validate that an object's generation matches expected.
    fn validate_generation(&self, slot: usize, expected_gen: u64) -> bool {
        if slot >= self.capacity {
            return false;
        }
        self.objects[slot].generation == expected_gen
    }

    /// Advance the RCU epoch.
    fn advance_epoch(&mut self) {
        self.current_epoch += 1;
    }
}

impl Default for TypesafeSlabCache {
    fn default() -> Self {
        Self::empty()
    }
}

// -- TypesafeSlabStats

/// Aggregate statistics across all typesafe slab caches.
#[derive(Debug, Clone, Copy, Default)]
pub struct TypesafeSlabStats {
    /// Total caches created.
    pub caches_created: u64,
    /// Total caches destroyed.
    pub caches_destroyed: u64,
    /// Total allocations across all caches.
    pub total_allocs: u64,
    /// Total frees across all caches.
    pub total_frees: u64,
    /// Total delayed drains.
    pub total_drains: u64,
    /// Total generation validation checks.
    pub validation_checks: u64,
    /// Validation failures (stale generation).
    pub validation_failures: u64,
}

// -- TypesafeSlabManager

/// Top-level manager for typesafe slab caches.
pub struct TypesafeSlabManager {
    /// Registered caches.
    caches: [TypesafeSlabCache; MAX_CACHES],
    /// Number of active caches.
    cache_count: usize,
    /// Statistics.
    stats: TypesafeSlabStats,
}

impl TypesafeSlabManager {
    /// Create a new, empty manager.
    pub const fn new() -> Self {
        Self {
            caches: [const { TypesafeSlabCache::empty() }; MAX_CACHES],
            cache_count: 0,
            stats: TypesafeSlabStats {
                caches_created: 0,
                caches_destroyed: 0,
                total_allocs: 0,
                total_frees: 0,
                total_drains: 0,
                validation_checks: 0,
                validation_failures: 0,
            },
        }
    }

    /// Create a new slab cache with the typesafe flag.
    ///
    /// `name` is truncated to `MAX_NAME_LEN`. `capacity` is
    /// capped at `MAX_OBJECTS_PER_CACHE`.
    pub fn create_cache(
        &mut self,
        name: &[u8],
        object_size: usize,
        capacity: usize,
        typesafe: bool,
    ) -> Result<usize> {
        if object_size == 0 {
            return Err(Error::InvalidArgument);
        }
        let idx = self
            .caches
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;
        let cap = if capacity > MAX_OBJECTS_PER_CACHE {
            MAX_OBJECTS_PER_CACHE
        } else {
            capacity
        };
        let nlen = if name.len() > MAX_NAME_LEN {
            MAX_NAME_LEN
        } else {
            name.len()
        };
        let mut cache = TypesafeSlabCache::empty();
        cache.name[..nlen].copy_from_slice(&name[..nlen]);
        cache.name_len = nlen;
        cache.object_size = object_size;
        cache.capacity = cap;
        cache.typesafe = typesafe;
        cache.active = true;
        for i in 0..cap {
            cache.objects[i].slot = i;
        }
        self.caches[idx] = cache;
        self.cache_count += 1;
        self.stats.caches_created += 1;
        Ok(idx)
    }

    /// Destroy a cache by index.
    pub fn destroy_cache(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_CACHES {
            return Err(Error::InvalidArgument);
        }
        if !self.caches[idx].active {
            return Err(Error::NotFound);
        }
        if self.caches[idx].allocated_count > 0 {
            return Err(Error::Busy);
        }
        self.caches[idx].active = false;
        self.cache_count = self.cache_count.saturating_sub(1);
        self.stats.caches_destroyed += 1;
        Ok(())
    }

    /// Allocate an object from a cache.
    ///
    /// Returns `(slot, generation)`.
    pub fn alloc(&mut self, cache_idx: usize) -> Result<(usize, u64)> {
        if cache_idx >= MAX_CACHES || !self.caches[cache_idx].active {
            return Err(Error::InvalidArgument);
        }
        let result = self.caches[cache_idx].alloc()?;
        self.stats.total_allocs += 1;
        Ok(result)
    }

    /// Free an object from a cache.
    pub fn free(&mut self, cache_idx: usize, slot: usize) -> Result<()> {
        if cache_idx >= MAX_CACHES || !self.caches[cache_idx].active {
            return Err(Error::InvalidArgument);
        }
        self.caches[cache_idx].free(slot)?;
        self.stats.total_frees += 1;
        Ok(())
    }

    /// Advance the RCU epoch for a cache and drain delayed frees.
    ///
    /// Returns the number of objects drained.
    pub fn drain_delayed(&mut self, cache_idx: usize) -> Result<usize> {
        if cache_idx >= MAX_CACHES || !self.caches[cache_idx].active {
            return Err(Error::InvalidArgument);
        }
        self.caches[cache_idx].advance_epoch();
        let epoch = self.caches[cache_idx].current_epoch;
        let drained = self.caches[cache_idx].drain_delayed(epoch);
        self.stats.total_drains += drained as u64;
        Ok(drained)
    }

    /// Validate that a previously observed generation is still
    /// current for the given object.
    pub fn validate_generation(
        &mut self,
        cache_idx: usize,
        slot: usize,
        expected_gen: u64,
    ) -> Result<bool> {
        if cache_idx >= MAX_CACHES || !self.caches[cache_idx].active {
            return Err(Error::InvalidArgument);
        }
        self.stats.validation_checks += 1;
        let valid = self.caches[cache_idx].validate_generation(slot, expected_gen);
        if !valid {
            self.stats.validation_failures += 1;
        }
        Ok(valid)
    }

    /// Number of active caches.
    pub fn cache_count(&self) -> usize {
        self.cache_count
    }

    /// Return statistics.
    pub fn stats(&self) -> &TypesafeSlabStats {
        &self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = TypesafeSlabStats::default();
    }
}

impl Default for TypesafeSlabManager {
    fn default() -> Self {
        Self::new()
    }
}
