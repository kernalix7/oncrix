// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Slab cache management subsystem.
//!
//! Provides a named, configurable cache for fixed-size kernel objects.
//! Each [`SlabCache`] manages a pool of slabs, each containing a
//! fixed number of objects. Slabs are classified as full, partial,
//! or empty, and allocation preferentially uses partial slabs.
//!
//! Supports per-CPU partial lists (modeled as per-CPU indices),
//! cache shrinking/reaping, and detailed statistics for `/proc/slabinfo`.
//!
//! # Key Types
//!
//! - [`SlabCacheFlags`] — creation flags (RECLAIM_ACCOUNT, PANIC, etc.)
//! - [`SlabState`] — slab fullness classification
//! - [`SlabDescriptor`] — per-slab metadata with embedded freelist
//! - [`SlabCache`] — the cache itself (name, config, slab array)
//! - [`SlabCacheManager`] — system-wide collection of caches
//! - [`SlabCacheStats`] — per-cache and global statistics
//!
//! Reference: Linux `mm/slab.c`, `mm/slab_common.c`,
//! `include/linux/slab.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page / slab size (4 KiB).
const SLAB_PAGE_SIZE: usize = 4096;

/// Maximum object size a slab cache can manage.
const MAX_OBJ_SIZE: usize = 2048;

/// Minimum object size (must fit a freelist index).
const MIN_OBJ_SIZE: usize = 8;

/// Maximum length of a cache name.
const MAX_CACHE_NAME_LEN: usize = 32;

/// Maximum number of slabs per cache.
const MAX_SLABS: usize = 64;

/// Maximum number of objects per slab (limited by u16 freelist).
const MAX_OBJS_PER_SLAB: usize = 512;

/// Maximum number of caches in the system.
const MAX_CACHES: usize = 64;

/// Number of (logical) CPUs for per-CPU partial tracking.
const NR_CPUS: usize = 8;

/// Freelist sentinel: no next free object.
const FREELIST_END: u16 = 0xFFFF;

// -------------------------------------------------------------------
// SlabCacheFlags
// -------------------------------------------------------------------

/// Flags controlling slab cache behaviour.
pub struct SlabCacheFlags;

impl SlabCacheFlags {
    /// Account slab pages to memory cgroup for reclaim.
    pub const RECLAIM_ACCOUNT: u32 = 1 << 0;
    /// Panic if cache creation fails (boot-critical caches).
    pub const PANIC: u32 = 1 << 1;
    /// Align objects to hardware cache lines.
    pub const HWCACHE_ALIGN: u32 = 1 << 2;
    /// Poison freed objects to detect use-after-free.
    pub const POISON: u32 = 1 << 3;
    /// Add red zones around objects to detect overflows.
    pub const RED_ZONE: u32 = 1 << 4;
    /// Store the allocating caller address for debugging.
    pub const STORE_USER: u32 = 1 << 5;
    /// Objects are reclaimable (shrinker support).
    pub const RECLAIMABLE: u32 = 1 << 6;
}

// -------------------------------------------------------------------
// SlabState
// -------------------------------------------------------------------

/// Fullness state of a slab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlabState {
    /// No objects allocated — slab is completely free.
    #[default]
    Empty,
    /// Some objects allocated, some free.
    Partial,
    /// All objects allocated — no free slots.
    Full,
}

// -------------------------------------------------------------------
// SlabDescriptor
// -------------------------------------------------------------------

/// Per-slab metadata.
///
/// Each slab is a contiguous page-sized region divided into
/// equal-sized object slots. The freelist is an embedded array
/// of u16 indices forming a linked list of free slots.
pub struct SlabDescriptor {
    /// Base physical address of the slab page.
    base_addr: u64,
    /// Number of active (allocated) objects.
    active: u16,
    /// Total capacity (objects that fit in this slab).
    capacity: u16,
    /// Index of the first free slot (FREELIST_END if none).
    freelist_head: u16,
    /// Embedded freelist: `freelist[i]` = index of next free slot
    /// after slot `i`. FREELIST_END means end of list.
    freelist: [u16; MAX_OBJS_PER_SLAB],
    /// Whether this slab descriptor is in use.
    in_use: bool,
    /// Current state.
    state: SlabState,
}

impl SlabDescriptor {
    /// Create an empty slab descriptor.
    const fn empty() -> Self {
        Self {
            base_addr: 0,
            active: 0,
            capacity: 0,
            freelist_head: FREELIST_END,
            freelist: [FREELIST_END; MAX_OBJS_PER_SLAB],
            in_use: false,
            state: SlabState::Empty,
        }
    }

    /// Initialise a slab for the given object size.
    fn init(&mut self, base_addr: u64, obj_size: usize) {
        let cap = SLAB_PAGE_SIZE / obj_size;
        let cap = if cap > MAX_OBJS_PER_SLAB {
            MAX_OBJS_PER_SLAB
        } else {
            cap
        };
        self.base_addr = base_addr;
        self.active = 0;
        self.capacity = cap as u16;
        self.in_use = true;
        self.state = SlabState::Empty;

        // Build freelist chain: 0 -> 1 -> 2 -> ... -> (cap-1) -> END.
        for i in 0..cap {
            self.freelist[i] = if i + 1 < cap {
                (i + 1) as u16
            } else {
                FREELIST_END
            };
        }
        self.freelist_head = if cap > 0 { 0 } else { FREELIST_END };
    }

    /// Allocate an object from this slab.
    ///
    /// Returns the byte offset within the slab page of the
    /// allocated object.
    fn alloc(&mut self, obj_size: usize) -> Result<usize> {
        if self.freelist_head == FREELIST_END {
            return Err(Error::OutOfMemory);
        }
        let idx = self.freelist_head as usize;
        self.freelist_head = self.freelist[idx];
        self.freelist[idx] = FREELIST_END;
        self.active += 1;
        self.update_state();
        Ok(idx * obj_size)
    }

    /// Free an object at the given byte offset within the slab.
    fn free(&mut self, offset: usize, obj_size: usize) -> Result<()> {
        if obj_size == 0 {
            return Err(Error::InvalidArgument);
        }
        let idx = offset / obj_size;
        if idx >= self.capacity as usize {
            return Err(Error::InvalidArgument);
        }
        // Link into freelist.
        self.freelist[idx] = self.freelist_head;
        self.freelist_head = idx as u16;
        self.active = self.active.saturating_sub(1);
        self.update_state();
        Ok(())
    }

    /// Update the slab state based on active count.
    fn update_state(&mut self) {
        if self.active == 0 {
            self.state = SlabState::Empty;
        } else if self.active >= self.capacity {
            self.state = SlabState::Full;
        } else {
            self.state = SlabState::Partial;
        }
    }

    /// Return the current state.
    pub const fn state(&self) -> SlabState {
        self.state
    }

    /// Return the number of active objects.
    pub const fn active_count(&self) -> u16 {
        self.active
    }

    /// Return the capacity.
    pub const fn capacity(&self) -> u16 {
        self.capacity
    }

    /// Return the base address.
    pub const fn base_addr(&self) -> u64 {
        self.base_addr
    }
}

// -------------------------------------------------------------------
// SlabCacheStats
// -------------------------------------------------------------------

/// Per-cache statistics suitable for `/proc/slabinfo`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlabCacheStats {
    /// Number of objects currently allocated.
    pub active_objs: u32,
    /// Total number of object slots across all slabs.
    pub num_objs: u32,
    /// Number of slabs with at least one allocated object.
    pub active_slabs: u16,
    /// Total number of slabs (including empty).
    pub num_slabs: u16,
    /// Total allocation requests.
    pub alloc_count: u64,
    /// Total free requests.
    pub free_count: u64,
    /// Total allocation failures (all slabs full).
    pub alloc_failures: u64,
    /// Total reap operations (empty slabs freed).
    pub reap_count: u64,
}

// -------------------------------------------------------------------
// PerCpuPartial
// -------------------------------------------------------------------

/// Per-CPU partial slab tracking.
///
/// Each CPU preferentially allocates from its own partial slab
/// to reduce cross-CPU contention.
#[derive(Clone, Copy, Default)]
struct PerCpuPartial {
    /// Index of the preferred partial slab for this CPU (-1 = none).
    slab_index: i32,
    /// Number of free objects in the preferred slab.
    free_count: u16,
}

// -------------------------------------------------------------------
// SlabCache
// -------------------------------------------------------------------

/// A named slab cache managing fixed-size objects.
pub struct SlabCache {
    /// Human-readable cache name (e.g. "task_struct").
    name: [u8; MAX_CACHE_NAME_LEN],
    /// Length of the name string.
    name_len: usize,
    /// Object size in bytes (after alignment).
    obj_size: usize,
    /// Requested alignment.
    alignment: usize,
    /// Cache creation flags.
    flags: u32,
    /// Slab descriptor array.
    slabs: [SlabDescriptor; MAX_SLABS],
    /// Per-CPU partial slab indices.
    percpu_partial: [PerCpuPartial; NR_CPUS],
    /// Statistics.
    stats: SlabCacheStats,
    /// Whether this cache is active.
    active: bool,
    /// Next slab base address to assign (simulated).
    next_slab_addr: u64,
}

impl SlabCache {
    /// Create an inactive/empty cache.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_CACHE_NAME_LEN],
            name_len: 0,
            obj_size: 0,
            alignment: 0,
            flags: 0,
            slabs: [const { SlabDescriptor::empty() }; MAX_SLABS],
            percpu_partial: [PerCpuPartial {
                slab_index: -1,
                free_count: 0,
            }; NR_CPUS],
            stats: SlabCacheStats {
                active_objs: 0,
                num_objs: 0,
                active_slabs: 0,
                num_slabs: 0,
                alloc_count: 0,
                free_count: 0,
                alloc_failures: 0,
                reap_count: 0,
            },
            active: false,
            next_slab_addr: 0,
        }
    }

    /// Initialise a cache with the given parameters.
    fn init(&mut self, name: &[u8], obj_size: usize, alignment: usize, flags: u32, base_addr: u64) {
        let copy_len = if name.len() < MAX_CACHE_NAME_LEN {
            name.len()
        } else {
            MAX_CACHE_NAME_LEN
        };
        self.name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.name_len = copy_len;

        // Apply alignment: round obj_size up to alignment.
        let aligned_size = if alignment > 0 && obj_size % alignment != 0 {
            obj_size + (alignment - obj_size % alignment)
        } else {
            obj_size
        };
        self.obj_size = aligned_size;
        self.alignment = alignment;
        self.flags = flags;
        self.active = true;
        self.next_slab_addr = base_addr;

        // Reset per-CPU partials.
        for cpu in &mut self.percpu_partial {
            cpu.slab_index = -1;
            cpu.free_count = 0;
        }
    }

    /// Add a new slab to this cache.
    fn grow(&mut self) -> Result<usize> {
        for i in 0..MAX_SLABS {
            if !self.slabs[i].in_use {
                let addr = self.next_slab_addr;
                self.next_slab_addr += SLAB_PAGE_SIZE as u64;
                self.slabs[i].init(addr, self.obj_size);
                self.stats.num_slabs += 1;
                self.stats.num_objs += self.slabs[i].capacity as u32;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a partial slab, or grow a new one.
    fn find_partial_or_grow(&mut self) -> Result<usize> {
        // First check partials.
        for i in 0..MAX_SLABS {
            if self.slabs[i].in_use && self.slabs[i].state == SlabState::Partial {
                return Ok(i);
            }
        }
        // Then check empties.
        for i in 0..MAX_SLABS {
            if self.slabs[i].in_use && self.slabs[i].state == SlabState::Empty {
                return Ok(i);
            }
        }
        // Grow a new slab.
        self.grow()
    }

    /// Allocate an object from this cache.
    ///
    /// Tries the per-CPU partial first, then any partial slab, then
    /// grows a new slab if needed.
    ///
    /// Returns the absolute address of the allocated object.
    pub fn alloc_obj(&mut self, cpu: usize) -> Result<u64> {
        let cpu_idx = cpu % NR_CPUS;

        // Try per-CPU partial first.
        let percpu_slab = self.percpu_partial[cpu_idx].slab_index;
        if percpu_slab >= 0 {
            let si = percpu_slab as usize;
            if si < MAX_SLABS && self.slabs[si].in_use && self.slabs[si].state != SlabState::Full {
                let base = self.slabs[si].base_addr;
                let offset = self.slabs[si].alloc(self.obj_size)?;
                self.stats.active_objs += 1;
                self.stats.alloc_count += 1;
                self.update_percpu(cpu_idx, si);
                if self.slabs[si].active > 0 {
                    self.stats.active_slabs = self.count_active_slabs();
                }
                return Ok(base + offset as u64);
            }
        }

        // Find a partial or grow.
        let si = self.find_partial_or_grow()?;
        let base = self.slabs[si].base_addr;
        let offset = self.slabs[si].alloc(self.obj_size)?;

        self.percpu_partial[cpu_idx].slab_index = si as i32;
        self.update_percpu(cpu_idx, si);

        self.stats.active_objs += 1;
        self.stats.alloc_count += 1;
        self.stats.active_slabs = self.count_active_slabs();

        Ok(base + offset as u64)
    }

    /// Free an object back to this cache.
    ///
    /// # Errors
    /// - `NotFound` — address does not belong to any slab.
    pub fn free_obj(&mut self, addr: u64) -> Result<()> {
        for i in 0..MAX_SLABS {
            if !self.slabs[i].in_use {
                continue;
            }
            let base = self.slabs[i].base_addr;
            let end = base + SLAB_PAGE_SIZE as u64;
            if addr >= base && addr < end {
                let offset = (addr - base) as usize;
                self.slabs[i].free(offset, self.obj_size)?;
                self.stats.active_objs = self.stats.active_objs.saturating_sub(1);
                self.stats.free_count += 1;
                self.stats.active_slabs = self.count_active_slabs();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Shrink the cache by freeing all empty slabs.
    ///
    /// Returns the number of slabs freed.
    pub fn shrink(&mut self) -> usize {
        let mut freed = 0;
        for i in 0..MAX_SLABS {
            if self.slabs[i].in_use && self.slabs[i].state == SlabState::Empty {
                self.slabs[i].in_use = false;
                self.stats.num_slabs = self.stats.num_slabs.saturating_sub(1);
                self.stats.num_objs = self
                    .stats
                    .num_objs
                    .saturating_sub(self.slabs[i].capacity as u32);
                self.stats.reap_count += 1;
                freed += 1;

                // Invalidate any per-CPU partial pointing here.
                for cpu in &mut self.percpu_partial {
                    if cpu.slab_index == i as i32 {
                        cpu.slab_index = -1;
                        cpu.free_count = 0;
                    }
                }
            }
        }
        self.stats.active_slabs = self.count_active_slabs();
        freed
    }

    /// Reap: aggressively free all empty slabs (alias for shrink).
    ///
    /// Returns the number of slabs freed.
    pub fn reap(&mut self) -> usize {
        self.shrink()
    }

    /// Update per-CPU partial metadata for a given slab.
    fn update_percpu(&mut self, cpu: usize, slab_idx: usize) {
        self.percpu_partial[cpu].slab_index = slab_idx as i32;
        self.percpu_partial[cpu].free_count = self.slabs[slab_idx]
            .capacity
            .saturating_sub(self.slabs[slab_idx].active);
    }

    /// Count slabs with at least one active object.
    fn count_active_slabs(&self) -> u16 {
        let mut count = 0u16;
        for i in 0..MAX_SLABS {
            if self.slabs[i].in_use && self.slabs[i].active > 0 {
                count += 1;
            }
        }
        count
    }

    /// Return the object size.
    pub const fn obj_size(&self) -> usize {
        self.obj_size
    }

    /// Return the cache flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Return the cache name as bytes.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return current statistics.
    pub const fn stats(&self) -> &SlabCacheStats {
        &self.stats
    }

    /// Whether this cache is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }
}

// -------------------------------------------------------------------
// SlabInfo
// -------------------------------------------------------------------

/// Summary information for a single cache, suitable for /proc/slabinfo.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlabInfo {
    /// Cache name (ASCII bytes).
    pub name: [u8; MAX_CACHE_NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Object size.
    pub obj_size: usize,
    /// Objects per slab.
    pub objs_per_slab: u16,
    /// Active objects.
    pub active_objs: u32,
    /// Total objects.
    pub num_objs: u32,
    /// Active slabs.
    pub active_slabs: u16,
    /// Total slabs.
    pub num_slabs: u16,
}

// -------------------------------------------------------------------
// SlabCacheManager
// -------------------------------------------------------------------

/// System-wide slab cache manager.
///
/// Tracks up to [`MAX_CACHES`] slab caches and provides
/// creation, lookup, and global shrink/reap operations.
pub struct SlabCacheManager {
    /// Cache array.
    caches: [SlabCache; MAX_CACHES],
    /// Number of active caches.
    active_count: usize,
    /// Global allocation counter.
    total_allocs: u64,
    /// Global free counter.
    total_frees: u64,
}

impl SlabCacheManager {
    /// Create a new slab cache manager.
    pub const fn new() -> Self {
        Self {
            caches: [const { SlabCache::empty() }; MAX_CACHES],
            active_count: 0,
            total_allocs: 0,
            total_frees: 0,
        }
    }

    /// Create a new slab cache.
    ///
    /// # Arguments
    /// - `name` — human-readable cache name.
    /// - `obj_size` — size of each object in bytes.
    /// - `alignment` — required alignment (0 for default).
    /// - `flags` — [`SlabCacheFlags`] combination.
    ///
    /// # Errors
    /// - `InvalidArgument` — obj_size out of range.
    /// - `OutOfMemory` — no free cache slots.
    /// - `AlreadyExists` — a cache with this name exists.
    pub fn create_cache(
        &mut self,
        name: &[u8],
        obj_size: usize,
        alignment: usize,
        flags: u32,
    ) -> Result<usize> {
        if obj_size < MIN_OBJ_SIZE || obj_size > MAX_OBJ_SIZE {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate name.
        for i in 0..MAX_CACHES {
            if self.caches[i].active && self.caches[i].name_len == name.len() {
                if &self.caches[i].name[..self.caches[i].name_len] == name {
                    return Err(Error::AlreadyExists);
                }
            }
        }

        // Find free slot.
        let mut slot = None;
        for i in 0..MAX_CACHES {
            if !self.caches[i].active {
                slot = Some(i);
                break;
            }
        }
        let slot = slot.ok_or(Error::OutOfMemory)?;

        let base_addr = (slot as u64) * 0x100_0000; // 16 MiB per cache space
        self.caches[slot].init(name, obj_size, alignment, flags, base_addr);
        self.active_count += 1;
        Ok(slot)
    }

    /// Destroy a slab cache by index.
    ///
    /// All slabs must be empty (no active objects).
    ///
    /// # Errors
    /// - `InvalidArgument` — index out of range or cache inactive.
    /// - `Busy` — cache has active objects.
    pub fn destroy_cache(&mut self, index: usize) -> Result<()> {
        if index >= MAX_CACHES || !self.caches[index].active {
            return Err(Error::InvalidArgument);
        }
        if self.caches[index].stats.active_objs > 0 {
            return Err(Error::Busy);
        }
        self.caches[index] = SlabCache::empty();
        self.active_count = self.active_count.saturating_sub(1);
        Ok(())
    }

    /// Allocate an object from a cache.
    ///
    /// # Errors
    /// - `InvalidArgument` — index out of range or cache inactive.
    /// - `OutOfMemory` — no free objects and cannot grow.
    pub fn alloc(&mut self, cache_index: usize, cpu: usize) -> Result<u64> {
        if cache_index >= MAX_CACHES || !self.caches[cache_index].active {
            return Err(Error::InvalidArgument);
        }
        let addr = self.caches[cache_index].alloc_obj(cpu)?;
        self.total_allocs += 1;
        Ok(addr)
    }

    /// Free an object back to a cache.
    ///
    /// # Errors
    /// - `InvalidArgument` — index out of range or cache inactive.
    /// - `NotFound` — address not found in any slab.
    pub fn free(&mut self, cache_index: usize, addr: u64) -> Result<()> {
        if cache_index >= MAX_CACHES || !self.caches[cache_index].active {
            return Err(Error::InvalidArgument);
        }
        self.caches[cache_index].free_obj(addr)?;
        self.total_frees += 1;
        Ok(())
    }

    /// Shrink all caches (free empty slabs).
    ///
    /// Returns total number of slabs freed.
    pub fn shrink_all(&mut self) -> usize {
        let mut total = 0;
        for i in 0..MAX_CACHES {
            if self.caches[i].active {
                total += self.caches[i].shrink();
            }
        }
        total
    }

    /// Reap all caches (aggressive shrink).
    ///
    /// Returns total number of slabs freed.
    pub fn reap_all(&mut self) -> usize {
        self.shrink_all()
    }

    /// Get slab info for a cache (for /proc/slabinfo).
    ///
    /// # Errors
    /// - `InvalidArgument` — index out of range or cache inactive.
    pub fn slab_info(&self, cache_index: usize) -> Result<SlabInfo> {
        if cache_index >= MAX_CACHES || !self.caches[cache_index].active {
            return Err(Error::InvalidArgument);
        }
        let cache = &self.caches[cache_index];
        let objs_per_slab = if cache.obj_size > 0 {
            (SLAB_PAGE_SIZE / cache.obj_size) as u16
        } else {
            0
        };
        Ok(SlabInfo {
            name: cache.name,
            name_len: cache.name_len,
            obj_size: cache.obj_size,
            objs_per_slab,
            active_objs: cache.stats.active_objs,
            num_objs: cache.stats.num_objs,
            active_slabs: cache.stats.active_slabs,
            num_slabs: cache.stats.num_slabs,
        })
    }

    /// Return the number of active caches.
    pub const fn active_count(&self) -> usize {
        self.active_count
    }

    /// Return global allocation counter.
    pub const fn total_allocs(&self) -> u64 {
        self.total_allocs
    }

    /// Return global free counter.
    pub const fn total_frees(&self) -> u64 {
        self.total_frees
    }
}
