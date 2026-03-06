// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Compressed memory pool interface (zpool).
//!
//! Provides a uniform abstraction layer over compressed memory backends
//! (zbud, z3fold, zsmalloc). The zswap subsystem calls into zpool
//! rather than talking to individual compressed allocators directly,
//! allowing the backend to be switched at runtime.
//!
//! # Key components
//!
//! - [`CompressionType`] — identifies the backend allocator
//! - [`ZpoolHandle`] — opaque reference to a compressed object
//! - [`ZpoolOps`] — trait defining the backend interface
//! - [`Zpool`] — the main pool that delegates to the active backend
//! - [`ZpoolMapping`] — a temporary CPU mapping of a compressed object
//! - [`ZpoolStats`] — pool-wide usage statistics
//!
//! # Design
//!
//! The zpool does not compress or decompress data itself. It manages
//! allocation, mapping, and lifetime of compressed buffers. Callers
//! (typically zswap) are responsible for feeding pre-compressed data
//! into the pool and decompressing data retrieved from it.
//!
//! Reference: Linux `mm/zpool.c`, `include/linux/zpool.h`.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────────────────

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum number of concurrent zpool instances.
const MAX_POOLS: usize = 4;

/// Maximum number of handles tracked per pool.
const MAX_HANDLES: usize = 8192;

/// Maximum object size that zpool can store (one page minus header).
const MAX_OBJECT_SIZE: usize = PAGE_SIZE - 64;

/// Minimum object size for a zpool allocation.
const MIN_OBJECT_SIZE: usize = 32;

/// Default eviction threshold as a percentage of pool capacity.
const DEFAULT_EVICTION_THRESHOLD: u32 = 90;

/// Maximum number of mappings held simultaneously.
const MAX_MAPPINGS: usize = 32;

/// Number of size buckets for allocation statistics.
const NUM_SIZE_BUCKETS: usize = 8;

// ── CompressionType ─────────────────────────────────────────────────────────

/// Identifies the compressed memory backend allocator.
///
/// Each variant corresponds to a distinct in-kernel allocator
/// with different density / fragmentation trade-offs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    /// zbud: stores at most 2 objects per page (2:1 max ratio).
    Zbud,
    /// z3fold: stores up to 3 objects per page (3:1 max ratio).
    Z3fold,
    /// zsmalloc: size-class allocator, very dense for mixed sizes.
    Zsmalloc,
}

impl Default for CompressionType {
    fn default() -> Self {
        Self::Z3fold
    }
}

// ── ZpoolHandle ─────────────────────────────────────────────────────────────

/// Opaque handle referencing a compressed object within a zpool.
///
/// The handle encodes the pool index, slot index, and the backend
/// allocator's internal handle (backend_handle) so that free and
/// map operations can be dispatched correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZpoolHandle {
    /// Pool instance index (0..MAX_POOLS).
    pub pool_index: u8,
    /// Slot index within the pool's handle table.
    pub slot_index: u16,
    /// Backend-specific handle value.
    pub backend_handle: u64,
    /// Size of the stored object in bytes.
    pub object_size: u32,
    /// Whether this handle is valid.
    pub valid: bool,
}

impl ZpoolHandle {
    /// A sentinel handle representing "no allocation".
    pub const INVALID: Self = Self {
        pool_index: 0,
        slot_index: 0,
        backend_handle: u64::MAX,
        object_size: 0,
        valid: false,
    };

    /// Returns `true` if this handle references a live allocation.
    pub const fn is_valid(&self) -> bool {
        self.valid
    }
}

// ── ZpoolMapping ────────────────────────────────────────────────────────────

/// A temporary CPU-accessible mapping of a compressed object.
///
/// While a mapping is held, the underlying physical storage is pinned
/// and must not be moved or freed. Callers should hold mappings for
/// the shortest time possible.
#[derive(Debug, Clone, Copy)]
pub struct ZpoolMapping {
    /// Virtual address of the mapped region.
    pub virt_addr: u64,
    /// Size of the mapped region in bytes.
    pub size: u32,
    /// Handle that this mapping refers to.
    pub handle: ZpoolHandle,
    /// Whether this mapping slot is in use.
    pub active: bool,
}

impl ZpoolMapping {
    /// Creates an empty (inactive) mapping.
    const fn empty() -> Self {
        Self {
            virt_addr: 0,
            size: 0,
            handle: ZpoolHandle::INVALID,
            active: false,
        }
    }
}

// ── ZpoolOps (trait) ────────────────────────────────────────────────────────

/// Trait defining the interface every zpool backend must implement.
///
/// Backend allocators (zbud, z3fold, zsmalloc) implement this trait
/// so that [`Zpool`] can delegate operations uniformly.
pub trait ZpoolOps {
    /// Allocate `size` bytes from the backend.
    ///
    /// Returns a backend-specific handle on success.
    fn backend_alloc(&mut self, size: usize) -> Result<u64>;

    /// Free a previously allocated object identified by `handle`.
    fn backend_free(&mut self, handle: u64) -> Result<()>;

    /// Map an object for CPU access, returning a virtual address.
    fn backend_map(&mut self, handle: u64) -> Result<u64>;

    /// Unmap a previously mapped object.
    fn backend_unmap(&mut self, handle: u64) -> Result<()>;

    /// Return the total size of the backend pool in bytes.
    fn backend_total_size(&self) -> u64;

    /// Return the number of bytes currently in use.
    fn backend_used_size(&self) -> u64;
}

// ── ZpoolSlot (internal) ────────────────────────────────────────────────────

/// Internal slot tracking a single allocation within a pool.
#[derive(Debug, Clone, Copy)]
struct ZpoolSlot {
    /// Backend-specific handle value.
    backend_handle: u64,
    /// Object size in bytes.
    size: u32,
    /// Whether this slot is occupied.
    active: bool,
    /// Reference count (for shared mappings).
    refcount: u16,
    /// Timestamp of the allocation (nanoseconds since boot).
    alloc_time_ns: u64,
}

impl ZpoolSlot {
    /// Creates an empty slot.
    const fn empty() -> Self {
        Self {
            backend_handle: u64::MAX,
            size: 0,
            active: false,
            refcount: 0,
            alloc_time_ns: 0,
        }
    }
}

// ── ZpoolConfig ─────────────────────────────────────────────────────────────

/// Configuration for creating a new zpool instance.
#[derive(Debug, Clone, Copy)]
pub struct ZpoolConfig {
    /// Which backend allocator to use.
    pub backend: CompressionType,
    /// Maximum pool capacity in bytes.
    pub max_size: u64,
    /// Eviction threshold as a percentage of `max_size`.
    pub eviction_threshold: u32,
    /// Whether to allow sleeping allocations.
    pub gfp_allow_sleep: bool,
}

impl Default for ZpoolConfig {
    fn default() -> Self {
        Self {
            backend: CompressionType::default(),
            max_size: (PAGE_SIZE as u64) * 1024,
            eviction_threshold: DEFAULT_EVICTION_THRESHOLD,
            gfp_allow_sleep: false,
        }
    }
}

// ── SizeBucket ──────────────────────────────────────────────────────────────

/// Allocation size histogram bucket.
#[derive(Debug, Clone, Copy)]
struct SizeBucket {
    /// Lower bound (inclusive) of this bucket in bytes.
    min_size: u32,
    /// Upper bound (exclusive) of this bucket in bytes.
    max_size: u32,
    /// Number of allocations in this bucket.
    count: u64,
    /// Total bytes allocated in this bucket.
    total_bytes: u64,
}

impl SizeBucket {
    /// Creates an empty bucket covering the given range.
    const fn new(min_size: u32, max_size: u32) -> Self {
        Self {
            min_size,
            max_size,
            count: 0,
            total_bytes: 0,
        }
    }
}

// ── ZpoolStats ──────────────────────────────────────────────────────────────

/// Aggregate statistics for a zpool instance.
#[derive(Debug, Clone, Copy)]
pub struct ZpoolStats {
    /// Total number of successful allocations.
    pub alloc_count: u64,
    /// Total number of freed allocations.
    pub free_count: u64,
    /// Number of alloc requests that failed.
    pub alloc_fail_count: u64,
    /// Total bytes currently stored in the pool.
    pub stored_bytes: u64,
    /// Total pool capacity in bytes.
    pub pool_capacity: u64,
    /// Number of active mappings.
    pub active_mappings: u32,
    /// Peak number of simultaneous allocations.
    pub peak_alloc_count: u64,
    /// Number of evictions triggered by pressure.
    pub eviction_count: u64,
    /// Per-size-bucket histogram.
    buckets: [SizeBucket; NUM_SIZE_BUCKETS],
}

impl ZpoolStats {
    /// Creates zeroed statistics.
    const fn new() -> Self {
        Self {
            alloc_count: 0,
            free_count: 0,
            alloc_fail_count: 0,
            stored_bytes: 0,
            pool_capacity: 0,
            active_mappings: 0,
            peak_alloc_count: 0,
            eviction_count: 0,
            buckets: [const { SizeBucket::new(0, 0) }; NUM_SIZE_BUCKETS],
        }
    }

    /// Returns the utilisation ratio as a percentage (0..100).
    pub const fn utilisation_percent(&self) -> u32 {
        if self.pool_capacity == 0 {
            return 0;
        }
        (self.stored_bytes * 100 / self.pool_capacity) as u32
    }

    /// Returns the number of live (allocated but not freed) objects.
    pub const fn live_count(&self) -> u64 {
        self.alloc_count.saturating_sub(self.free_count)
    }
}

// ── Zpool ───────────────────────────────────────────────────────────────────

/// The main compressed memory pool.
///
/// Maintains a table of [`ZpoolSlot`]s and a mapping table for CPU
/// access. All backend operations are dispatched through the stored
/// [`CompressionType`]; actual backend dispatch is stubbed until real
/// allocators are wired in.
pub struct Zpool {
    /// Configuration this pool was created with.
    config: ZpoolConfig,
    /// Handle slot table.
    slots: [ZpoolSlot; MAX_HANDLES],
    /// Number of occupied slots.
    slot_count: usize,
    /// Next slot index to probe on allocation.
    next_slot_hint: usize,
    /// Active CPU mappings.
    mappings: [ZpoolMapping; MAX_MAPPINGS],
    /// Number of active mappings.
    mapping_count: usize,
    /// Pool-wide statistics.
    stats: ZpoolStats,
    /// Monotonically increasing generation counter.
    generation: u64,
    /// Whether the pool has been created (initialised).
    created: bool,
    /// Pool instance index in the global registry.
    pool_index: u8,
}

impl Zpool {
    /// Creates a new, uninitialised pool.
    ///
    /// Call [`Zpool::create`] with a [`ZpoolConfig`] to finish
    /// initialisation before allocating.
    pub const fn new() -> Self {
        Self {
            config: ZpoolConfig {
                backend: CompressionType::Z3fold,
                max_size: 0,
                eviction_threshold: DEFAULT_EVICTION_THRESHOLD,
                gfp_allow_sleep: false,
            },
            slots: [const { ZpoolSlot::empty() }; MAX_HANDLES],
            slot_count: 0,
            next_slot_hint: 0,
            mappings: [const { ZpoolMapping::empty() }; MAX_MAPPINGS],
            mapping_count: 0,
            stats: ZpoolStats::new(),
            generation: 0,
            created: false,
            pool_index: 0,
        }
    }

    /// Initialise the pool with the given configuration.
    ///
    /// Must be called exactly once before any allocation. Returns
    /// [`Error::AlreadyExists`] if the pool was already created.
    pub fn create(&mut self, config: ZpoolConfig) -> Result<()> {
        if self.created {
            return Err(Error::AlreadyExists);
        }
        if config.max_size == 0 {
            return Err(Error::InvalidArgument);
        }
        if config.eviction_threshold > 100 {
            return Err(Error::InvalidArgument);
        }
        self.config = config;
        self.stats.pool_capacity = config.max_size;

        // Initialise size histogram buckets.
        let step = MAX_OBJECT_SIZE / NUM_SIZE_BUCKETS;
        for (i, bucket) in self.stats.buckets.iter_mut().enumerate() {
            bucket.min_size = (i * step) as u32;
            bucket.max_size = ((i + 1) * step) as u32;
        }

        self.created = true;
        self.generation = 1;
        Ok(())
    }

    /// Allocate `size` bytes from the pool.
    ///
    /// Returns a [`ZpoolHandle`] on success. Fails with
    /// [`Error::OutOfMemory`] if the pool is full or the request
    /// exceeds capacity.
    pub fn alloc(&mut self, size: usize) -> Result<ZpoolHandle> {
        if !self.created {
            return Err(Error::InvalidArgument);
        }
        if size < MIN_OBJECT_SIZE || size > MAX_OBJECT_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.stats.stored_bytes + (size as u64) > self.config.max_size {
            self.stats.alloc_fail_count += 1;
            return Err(Error::OutOfMemory);
        }

        // Find a free slot (first-fit from hint).
        let slot_idx = self.find_free_slot()?;

        // Dispatch to backend (stubbed).
        let backend_handle = self.backend_alloc_stub(size)?;

        let slot = &mut self.slots[slot_idx];
        slot.backend_handle = backend_handle;
        slot.size = size as u32;
        slot.active = true;
        slot.refcount = 1;
        slot.alloc_time_ns = self.generation;

        self.slot_count += 1;
        self.generation += 1;

        // Update stats.
        self.stats.alloc_count += 1;
        self.stats.stored_bytes += size as u64;
        let live = self.stats.live_count();
        if live > self.stats.peak_alloc_count {
            self.stats.peak_alloc_count = live;
        }
        self.record_size_bucket(size);

        Ok(ZpoolHandle {
            pool_index: self.pool_index,
            slot_index: slot_idx as u16,
            backend_handle,
            object_size: size as u32,
            valid: true,
        })
    }

    /// Free a previously allocated object.
    ///
    /// Returns [`Error::NotFound`] if the handle does not refer to a
    /// live allocation.
    pub fn free(&mut self, handle: ZpoolHandle) -> Result<()> {
        if !self.created {
            return Err(Error::InvalidArgument);
        }
        let idx = handle.slot_index as usize;
        if idx >= MAX_HANDLES {
            return Err(Error::InvalidArgument);
        }
        if idx >= MAX_HANDLES || !self.slots[idx].active {
            return Err(Error::NotFound);
        }
        if self.slots[idx].backend_handle != handle.backend_handle {
            return Err(Error::InvalidArgument);
        }

        let size = self.slots[idx].size as u64;
        let bh = self.slots[idx].backend_handle;

        // Dispatch to backend (stubbed).
        self.backend_free_stub(bh)?;

        self.slots[idx].active = false;
        self.slots[idx].refcount = 0;
        self.slots[idx].backend_handle = u64::MAX;
        let freed_size = self.slots[idx].size;
        self.slots[idx].size = 0;

        self.slot_count -= 1;
        self.stats.free_count += 1;
        self.stats.stored_bytes = self.stats.stored_bytes.saturating_sub(size);

        // Update hint for faster next allocation.
        if idx < self.next_slot_hint {
            self.next_slot_hint = idx;
        }

        let _ = freed_size;
        Ok(())
    }

    /// Map a compressed object for CPU read/write access.
    ///
    /// Returns a [`ZpoolMapping`] that must be released with
    /// [`Zpool::unmap`] when done. Fails with [`Error::Busy`] if the
    /// mapping table is full.
    pub fn map(&mut self, handle: ZpoolHandle) -> Result<ZpoolMapping> {
        if !self.created {
            return Err(Error::InvalidArgument);
        }
        let idx = handle.slot_index as usize;
        if idx >= MAX_HANDLES || !self.slots[idx].active {
            return Err(Error::NotFound);
        }

        // Find a free mapping slot.
        let map_idx = self.find_free_mapping()?;

        // Dispatch to backend (stubbed).
        let virt = self.backend_map_stub(handle.backend_handle)?;

        let mapping = ZpoolMapping {
            virt_addr: virt,
            size: handle.object_size,
            handle,
            active: true,
        };
        self.mappings[map_idx] = mapping;
        self.mapping_count += 1;
        self.stats.active_mappings += 1;

        Ok(mapping)
    }

    /// Release a previously created mapping.
    pub fn unmap(&mut self, handle: ZpoolHandle) -> Result<()> {
        if !self.created {
            return Err(Error::InvalidArgument);
        }

        let pos = self
            .mappings
            .iter()
            .position(|m| m.active && m.handle == handle);
        match pos {
            Some(idx) => {
                let bh = self.mappings[idx].handle.backend_handle;
                self.backend_unmap_stub(bh)?;
                self.mappings[idx].active = false;
                self.mapping_count -= 1;
                self.stats.active_mappings = self.stats.active_mappings.saturating_sub(1);
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Returns the total capacity of the pool in bytes.
    pub const fn get_total_size(&self) -> u64 {
        self.config.max_size
    }

    /// Returns a snapshot of pool statistics.
    pub const fn stats(&self) -> &ZpoolStats {
        &self.stats
    }

    /// Returns the backend type this pool was configured with.
    pub const fn backend_type(&self) -> CompressionType {
        self.config.backend
    }

    /// Returns `true` if the pool is above the eviction threshold.
    pub fn needs_eviction(&self) -> bool {
        let pct = self.stats.utilisation_percent();
        pct >= self.config.eviction_threshold
    }

    /// Returns the number of live allocations.
    pub const fn live_count(&self) -> usize {
        self.slot_count
    }

    /// Returns `true` if the pool has been created and is ready.
    pub const fn is_created(&self) -> bool {
        self.created
    }

    /// Shrink the pool by evicting the oldest `count` objects.
    ///
    /// Returns the number of objects actually evicted.
    pub fn shrink(&mut self, count: usize) -> Result<usize> {
        if !self.created {
            return Err(Error::InvalidArgument);
        }
        let mut evicted = 0usize;

        // Repeated linear scan for simplicity (real kernel would
        // maintain an LRU list).
        for _ in 0..count {
            let mut oldest_time = u64::MAX;
            let mut oldest_idx = MAX_HANDLES; // sentinel

            for (i, slot) in self.slots.iter().enumerate() {
                if slot.active && slot.alloc_time_ns < oldest_time {
                    oldest_time = slot.alloc_time_ns;
                    oldest_idx = i;
                }
            }

            if oldest_idx >= MAX_HANDLES {
                break;
            }

            let slot = &mut self.slots[oldest_idx];
            let size = slot.size as u64;
            slot.active = false;
            slot.refcount = 0;
            slot.backend_handle = u64::MAX;
            slot.size = 0;

            self.slot_count -= 1;
            self.stats.free_count += 1;
            self.stats.stored_bytes = self.stats.stored_bytes.saturating_sub(size);
            self.stats.eviction_count += 1;
            evicted += 1;
        }

        Ok(evicted)
    }

    // ── Private helpers ─────────────────────────────────────────────

    /// Find a free slot starting from `next_slot_hint`.
    fn find_free_slot(&mut self) -> Result<usize> {
        let start = self.next_slot_hint;
        for offset in 0..MAX_HANDLES {
            let idx = (start + offset) % MAX_HANDLES;
            if !self.slots[idx].active {
                self.next_slot_hint = idx + 1;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a free mapping slot.
    fn find_free_mapping(&self) -> Result<usize> {
        for (i, m) in self.mappings.iter().enumerate() {
            if !m.active {
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }

    /// Record an allocation in the size histogram.
    fn record_size_bucket(&mut self, size: usize) {
        for bucket in &mut self.stats.buckets {
            if (size as u32) >= bucket.min_size && (size as u32) < bucket.max_size {
                bucket.count += 1;
                bucket.total_bytes += size as u64;
                return;
            }
        }
        // Falls outside all buckets — record in the last one.
        if let Some(last) = self.stats.buckets.last_mut() {
            last.count += 1;
            last.total_bytes += size as u64;
        }
    }

    // ── Backend stubs ───────────────────────────────────────────────
    //
    // These stubs return synthetic handles / addresses. They will be
    // replaced with real backend dispatch when z3fold, zbud, and
    // zsmalloc are wired in as trait objects.

    /// Stub: allocate from the backend.
    fn backend_alloc_stub(&mut self, _size: usize) -> Result<u64> {
        let handle = self.generation;
        Ok(handle)
    }

    /// Stub: free from the backend.
    fn backend_free_stub(&self, _handle: u64) -> Result<()> {
        Ok(())
    }

    /// Stub: map an object for CPU access.
    fn backend_map_stub(&self, handle: u64) -> Result<u64> {
        // Return a synthetic virtual address derived from the handle.
        Ok(0xFFFF_D000_0000_0000 + handle * PAGE_SIZE as u64)
    }

    /// Stub: unmap a previously mapped object.
    fn backend_unmap_stub(&self, _handle: u64) -> Result<()> {
        Ok(())
    }
}

// ── ZpoolRegistry ───────────────────────────────────────────────────────────

/// Global registry of zpool instances.
///
/// The kernel creates at most [`MAX_POOLS`] zpool instances (e.g. one
/// per swap device). The registry provides lookup by index.
pub struct ZpoolRegistry {
    /// Pool instances.
    pools: [Zpool; MAX_POOLS],
    /// Number of created (live) pools.
    pool_count: usize,
}

impl ZpoolRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            pools: [const { Zpool::new() }; MAX_POOLS],
            pool_count: 0,
        }
    }

    /// Create a new pool with the given configuration.
    ///
    /// Returns the pool index on success.
    pub fn create_pool(&mut self, config: ZpoolConfig) -> Result<usize> {
        if self.pool_count >= MAX_POOLS {
            return Err(Error::OutOfMemory);
        }

        for (i, pool) in self.pools.iter_mut().enumerate() {
            if !pool.created {
                pool.pool_index = i as u8;
                pool.create(config)?;
                self.pool_count += 1;
                return Ok(i);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Get a mutable reference to a pool by index.
    pub fn get_pool_mut(&mut self, index: usize) -> Result<&mut Zpool> {
        if index >= MAX_POOLS {
            return Err(Error::InvalidArgument);
        }
        if !self.pools[index].created {
            return Err(Error::NotFound);
        }
        Ok(&mut self.pools[index])
    }

    /// Get a shared reference to a pool by index.
    pub fn get_pool(&self, index: usize) -> Result<&Zpool> {
        if index >= MAX_POOLS {
            return Err(Error::InvalidArgument);
        }
        if !self.pools[index].created {
            return Err(Error::NotFound);
        }
        Ok(&self.pools[index])
    }

    /// Returns the number of live pools.
    pub const fn pool_count(&self) -> usize {
        self.pool_count
    }

    /// Destroy a pool, freeing all resources.
    pub fn destroy_pool(&mut self, index: usize) -> Result<()> {
        if index >= MAX_POOLS {
            return Err(Error::InvalidArgument);
        }
        if !self.pools[index].created {
            return Err(Error::NotFound);
        }
        self.pools[index] = Zpool::new();
        self.pool_count -= 1;
        Ok(())
    }
}
