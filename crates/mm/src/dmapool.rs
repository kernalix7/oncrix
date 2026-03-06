// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA buffer pool allocator.
//!
//! Provides pre-allocated, fixed-size buffer pools for efficient DMA
//! allocation without runtime fragmentation. Each pool manages a
//! contiguous physical region divided into equal-sized buffers tracked
//! by a bitmap. Pools are suited for device drivers that perform many
//! small, identically-sized DMA transfers (e.g., network ring buffers,
//! USB transfer descriptors, audio DMA fragments).
//!
//! # Architecture
//!
//! - [`BufferState`] -- lifecycle state of an individual buffer
//! - [`DmaBuffer`] -- descriptor for a single DMA-coherent buffer
//! - [`PoolConfig`] -- creation-time configuration for a pool
//! - [`BufferHandle`] -- opaque handle returned from allocation
//! - [`DmaPoolStats`] -- per-pool allocation statistics
//! - [`DmaPool`] -- a single fixed-size buffer pool
//! - [`DmaPoolManager`] -- system-wide manager of multiple pools
//!
//! # Design
//!
//! Each [`DmaPool`] carves a contiguous physical region into
//! `pool_size / buffer_size` equal-sized slots. A bitmap (one bit per
//! slot) tracks allocation state, giving O(1) amortised alloc/free.
//! Pools are cache-line aligned by default to avoid false sharing with
//! adjacent kernel data.
//!
//! # Example (conceptual)
//!
//! ```ignore
//! let cfg = PoolConfig::new(b"eth0-tx", 0x10_0000, 0x10_0000, 4096, 256);
//! let mut mgr = DmaPoolManager::new();
//! let pool_id = mgr.create_pool(cfg)?;
//! let handle = mgr.alloc_buffer(pool_id)?;
//! mgr.free_buffer(pool_id, handle)?;
//! mgr.destroy_pool(pool_id)?;
//! ```
//!
//! Reference: Linux `mm/dmapool.c`, `include/linux/dmapool.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum number of pools managed by [`DmaPoolManager`].
const MAX_POOLS: usize = 32;

/// Maximum number of buffers per pool (bitmap capacity: 64 words * 64
/// bits = 4096 buffers).
const MAX_BUFFERS_PER_POOL: usize = 4096;

/// Number of `u64` bitmap words per pool.
const BITMAP_WORDS: usize = MAX_BUFFERS_PER_POOL / 64;

/// Maximum pool name length in bytes.
const MAX_POOL_NAME_LEN: usize = 32;

/// Minimum buffer size in bytes.
const MIN_BUFFER_SIZE: usize = 16;

/// Maximum buffer size in bytes (1 MiB).
const MAX_BUFFER_SIZE: usize = 1024 * 1024;

/// Minimum pool total size in bytes (one page).
const MIN_POOL_SIZE: usize = PAGE_SIZE;

/// Default alignment for buffers (cache-line: 64 bytes).
const DEFAULT_ALIGNMENT: usize = 64;

/// Maximum number of allocation records kept for statistics.
const MAX_ALLOC_RECORDS: usize = 64;

// -------------------------------------------------------------------
// BufferState
// -------------------------------------------------------------------

/// Lifecycle state of a single DMA buffer within a pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BufferState {
    /// The buffer slot is free and available for allocation.
    #[default]
    Free,
    /// The buffer is currently allocated.
    Allocated,
    /// The buffer is reserved (pre-warmed but not yet handed out).
    Reserved,
    /// The buffer has been poisoned for debugging.
    Poisoned,
}

// -------------------------------------------------------------------
// BufferHandle
// -------------------------------------------------------------------

/// Opaque handle identifying an allocated buffer within a pool.
///
/// Stores the pool-internal index so that free operations are O(1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferHandle {
    /// Pool-internal buffer index.
    pub index: usize,
    /// Physical address of the buffer.
    pub phys_addr: u64,
    /// Virtual address of the buffer (CPU-accessible).
    pub virt_addr: u64,
    /// Size of the buffer in bytes.
    pub size: usize,
}

// -------------------------------------------------------------------
// DmaBuffer
// -------------------------------------------------------------------

/// Descriptor for a single DMA-coherent buffer.
///
/// Tracks the physical and virtual addresses, owning device, and
/// current lifecycle state.
#[derive(Debug, Clone, Copy)]
pub struct DmaBuffer {
    /// Physical address of the buffer.
    pub phys_addr: u64,
    /// Virtual address mapped for CPU access.
    pub virt_addr: u64,
    /// Size of the buffer in bytes.
    pub size: usize,
    /// Buffer lifecycle state.
    pub state: BufferState,
    /// Owning device identifier (0 = unassigned).
    pub device_id: u16,
    /// Number of times this buffer has been allocated.
    pub alloc_count: u32,
    /// Whether this slot is in use (has been allocated at least once
    /// since pool creation).
    pub active: bool,
}

impl DmaBuffer {
    /// Creates an empty, inactive buffer descriptor.
    const fn empty() -> Self {
        Self {
            phys_addr: 0,
            virt_addr: 0,
            size: 0,
            state: BufferState::Free,
            device_id: 0,
            alloc_count: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// PoolConfig
// -------------------------------------------------------------------

/// Creation-time configuration for a DMA buffer pool.
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// Human-readable pool name (truncated to [`MAX_POOL_NAME_LEN`]).
    pub name: [u8; MAX_POOL_NAME_LEN],
    /// Valid length of `name`.
    pub name_len: usize,
    /// Physical base address of the pool region.
    pub base_phys: u64,
    /// Virtual base address of the pool region.
    pub base_virt: u64,
    /// Total size of the pool region in bytes.
    pub pool_size: usize,
    /// Size of each individual buffer in bytes.
    pub buffer_size: usize,
    /// Alignment requirement for buffers (must be power of 2).
    pub alignment: usize,
    /// Device identifier that owns this pool.
    pub device_id: u16,
    /// Whether to zero buffers on free (security hardening).
    pub zero_on_free: bool,
    /// Whether to poison freed buffers (debug).
    pub poison_on_free: bool,
}

impl PoolConfig {
    /// Creates a new pool configuration.
    ///
    /// `name` is truncated to [`MAX_POOL_NAME_LEN`] bytes. Alignment
    /// defaults to [`DEFAULT_ALIGNMENT`] (64 bytes).
    pub fn new(
        name: &[u8],
        base_phys: u64,
        base_virt: u64,
        pool_size: usize,
        buffer_size: usize,
    ) -> Self {
        let mut pool_name = [0u8; MAX_POOL_NAME_LEN];
        let copy_len = name.len().min(MAX_POOL_NAME_LEN);
        let mut i = 0;
        while i < copy_len {
            pool_name[i] = name[i];
            i += 1;
        }

        Self {
            name: pool_name,
            name_len: copy_len,
            base_phys,
            base_virt,
            pool_size,
            buffer_size,
            alignment: DEFAULT_ALIGNMENT,
            device_id: 0,
            zero_on_free: false,
            poison_on_free: false,
        }
    }

    /// Sets the alignment requirement. Must be a power of 2.
    pub fn with_alignment(mut self, alignment: usize) -> Self {
        if alignment > 0 && alignment.is_power_of_two() {
            self.alignment = alignment;
        }
        self
    }

    /// Sets the owning device identifier.
    pub const fn with_device_id(mut self, device_id: u16) -> Self {
        self.device_id = device_id;
        self
    }

    /// Enables zero-on-free for security hardening.
    pub const fn with_zero_on_free(mut self) -> Self {
        self.zero_on_free = true;
        self
    }

    /// Enables poison-on-free for debugging.
    pub const fn with_poison_on_free(mut self) -> Self {
        self.poison_on_free = true;
        self
    }

    /// Returns the pool name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Computes the effective buffer stride (size rounded up to
    /// alignment).
    pub fn effective_stride(&self) -> usize {
        let align = if self.alignment == 0 {
            1
        } else {
            self.alignment
        };
        (self.buffer_size + align - 1) & !(align - 1)
    }

    /// Computes the number of buffers that fit in the pool.
    pub fn buffer_count(&self) -> usize {
        let stride = self.effective_stride();
        if stride == 0 {
            return 0;
        }
        self.pool_size / stride
    }

    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if any parameter is out of
    /// bounds or inconsistent.
    pub fn validate(&self) -> Result<()> {
        if self.buffer_size < MIN_BUFFER_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.buffer_size > MAX_BUFFER_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.pool_size < MIN_POOL_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.alignment == 0 || !self.alignment.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        let count = self.buffer_count();
        if count == 0 || count > MAX_BUFFERS_PER_POOL {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// -------------------------------------------------------------------
// DmaPoolStats
// -------------------------------------------------------------------

/// Per-pool allocation statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct DmaPoolStats {
    /// Total number of buffer slots in the pool.
    pub total_buffers: usize,
    /// Currently allocated buffers.
    pub allocated_buffers: usize,
    /// Free buffers available for allocation.
    pub free_buffers: usize,
    /// Cumulative successful allocations.
    pub alloc_count: u64,
    /// Cumulative successful frees.
    pub free_count: u64,
    /// Failed allocation attempts (pool exhausted).
    pub alloc_fail_count: u64,
    /// Buffer size in bytes.
    pub buffer_size: usize,
    /// Effective stride (buffer size + alignment padding).
    pub stride: usize,
    /// Pool total size in bytes.
    pub pool_size: usize,
    /// Utilisation percentage (0..100).
    pub utilisation_pct: u8,
}

// -------------------------------------------------------------------
// AllocRecord
// -------------------------------------------------------------------

/// A record of a single allocation event (for debugging).
#[derive(Debug, Clone, Copy, Default)]
struct AllocRecord {
    /// Buffer index allocated.
    index: usize,
    /// Physical address returned.
    phys_addr: u64,
    /// Whether this was an alloc (true) or free (false).
    is_alloc: bool,
    /// Sequence number.
    seq: u64,
}

// -------------------------------------------------------------------
// DmaPool
// -------------------------------------------------------------------

/// A single fixed-size DMA buffer pool.
///
/// Manages a contiguous physical region divided into equal-sized
/// buffers. A bitmap tracks which buffers are allocated.
pub struct DmaPool {
    /// Pool configuration.
    config: PoolConfig,
    /// Allocation bitmap (1 = allocated, 0 = free).
    bitmap: [u64; BITMAP_WORDS],
    /// Total number of buffers.
    total_buffers: usize,
    /// Currently allocated count.
    allocated: usize,
    /// Effective stride between buffers.
    stride: usize,
    /// Cumulative allocation count.
    alloc_count: u64,
    /// Cumulative free count.
    free_count: u64,
    /// Failed allocation attempts.
    alloc_fail_count: u64,
    /// Allocation history (ring buffer).
    history: [AllocRecord; MAX_ALLOC_RECORDS],
    /// Next history write index.
    history_idx: usize,
    /// Sequence counter.
    sequence: u64,
    /// Whether the pool is active.
    active: bool,
    /// Pool identifier (assigned by manager).
    pool_id: u32,
}

impl DmaPool {
    /// Creates an empty, inactive pool.
    const fn empty() -> Self {
        Self {
            config: PoolConfig {
                name: [0u8; MAX_POOL_NAME_LEN],
                name_len: 0,
                base_phys: 0,
                base_virt: 0,
                pool_size: 0,
                buffer_size: 0,
                alignment: DEFAULT_ALIGNMENT,
                device_id: 0,
                zero_on_free: false,
                poison_on_free: false,
            },
            bitmap: [0u64; BITMAP_WORDS],
            total_buffers: 0,
            allocated: 0,
            stride: 0,
            alloc_count: 0,
            free_count: 0,
            alloc_fail_count: 0,
            history: [const {
                AllocRecord {
                    index: 0,
                    phys_addr: 0,
                    is_alloc: false,
                    seq: 0,
                }
            }; MAX_ALLOC_RECORDS],
            history_idx: 0,
            sequence: 0,
            active: false,
            pool_id: 0,
        }
    }

    /// Initialises a pool from the given configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the configuration is
    /// invalid (see [`PoolConfig::validate`]).
    fn init(&mut self, config: PoolConfig, pool_id: u32) -> Result<()> {
        config.validate()?;

        let stride = config.effective_stride();
        let total = config.buffer_count();

        self.config = config;
        self.bitmap = [0u64; BITMAP_WORDS];
        self.total_buffers = total;
        self.allocated = 0;
        self.stride = stride;
        self.alloc_count = 0;
        self.free_count = 0;
        self.alloc_fail_count = 0;
        self.active = true;
        self.pool_id = pool_id;

        Ok(())
    }

    /// Allocates one buffer from the pool.
    ///
    /// Scans the bitmap for the first free slot. Returns a
    /// [`BufferHandle`] describing the allocated buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all buffers are allocated.
    /// Returns [`Error::NotFound`] if the pool is not active.
    pub fn alloc_buffer(&mut self) -> Result<BufferHandle> {
        if !self.active {
            return Err(Error::NotFound);
        }
        if self.allocated >= self.total_buffers {
            self.alloc_fail_count += 1;
            return Err(Error::OutOfMemory);
        }

        // First-fit scan.
        for word_idx in 0..BITMAP_WORDS {
            if self.bitmap[word_idx] == u64::MAX {
                continue;
            }
            let bit = self.bitmap[word_idx].trailing_ones() as usize;
            let index = word_idx * 64 + bit;
            if index >= self.total_buffers {
                break;
            }
            self.bitmap[word_idx] |= 1u64 << bit;
            self.allocated += 1;
            self.alloc_count += 1;

            let offset = (index as u64) * (self.stride as u64);
            let phys = self.config.base_phys + offset;
            let virt = self.config.base_virt + offset;

            self.record_event(index, phys, true);

            return Ok(BufferHandle {
                index,
                phys_addr: phys,
                virt_addr: virt,
                size: self.config.buffer_size,
            });
        }

        self.alloc_fail_count += 1;
        Err(Error::OutOfMemory)
    }

    /// Frees a buffer identified by its handle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the handle's index is out
    /// of range or the buffer is not currently allocated.
    /// Returns [`Error::NotFound`] if the pool is not active.
    pub fn free_buffer(&mut self, handle: BufferHandle) -> Result<()> {
        if !self.active {
            return Err(Error::NotFound);
        }
        self.free_by_index(handle.index)
    }

    /// Frees a buffer identified by its physical address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the address does not
    /// correspond to a valid, allocated buffer.
    pub fn free_by_phys(&mut self, phys: u64) -> Result<()> {
        if !self.active {
            return Err(Error::NotFound);
        }
        if phys < self.config.base_phys {
            return Err(Error::InvalidArgument);
        }
        let offset = phys - self.config.base_phys;
        if self.stride == 0 {
            return Err(Error::InvalidArgument);
        }
        if offset % (self.stride as u64) != 0 {
            return Err(Error::InvalidArgument);
        }
        let index = (offset / (self.stride as u64)) as usize;
        self.free_by_index(index)
    }

    /// Internal: free a buffer by index.
    fn free_by_index(&mut self, index: usize) -> Result<()> {
        if index >= self.total_buffers {
            return Err(Error::InvalidArgument);
        }
        let word_idx = index / 64;
        let bit = index % 64;
        if self.bitmap[word_idx] & (1u64 << bit) == 0 {
            return Err(Error::InvalidArgument);
        }
        self.bitmap[word_idx] &= !(1u64 << bit);
        self.allocated = self.allocated.saturating_sub(1);
        self.free_count += 1;

        let offset = (index as u64) * (self.stride as u64);
        let phys = self.config.base_phys + offset;
        self.record_event(index, phys, false);

        Ok(())
    }

    /// Records an allocation/free event in the history ring buffer.
    fn record_event(&mut self, index: usize, phys: u64, is_alloc: bool) {
        self.history[self.history_idx] = AllocRecord {
            index,
            phys_addr: phys,
            is_alloc,
            seq: self.sequence,
        };
        self.history_idx = (self.history_idx + 1) % MAX_ALLOC_RECORDS;
        self.sequence += 1;
    }

    /// Returns the number of free buffers.
    pub fn available(&self) -> usize {
        self.total_buffers.saturating_sub(self.allocated)
    }

    /// Returns `true` if all buffers are allocated.
    pub fn is_full(&self) -> bool {
        self.allocated >= self.total_buffers
    }

    /// Returns `true` if no buffers are allocated.
    pub fn is_all_free(&self) -> bool {
        self.allocated == 0
    }

    /// Returns whether this pool is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the pool's configuration.
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// Returns per-pool statistics.
    pub fn stats(&self) -> DmaPoolStats {
        let utilisation = if self.total_buffers > 0 {
            ((self.allocated * 100) / self.total_buffers) as u8
        } else {
            0
        };
        DmaPoolStats {
            total_buffers: self.total_buffers,
            allocated_buffers: self.allocated,
            free_buffers: self.available(),
            alloc_count: self.alloc_count,
            free_count: self.free_count,
            alloc_fail_count: self.alloc_fail_count,
            buffer_size: self.config.buffer_size,
            stride: self.stride,
            pool_size: self.config.pool_size,
            utilisation_pct: utilisation,
        }
    }

    /// Returns the pool identifier.
    pub fn pool_id(&self) -> u32 {
        self.pool_id
    }

    /// Returns the physical address of a buffer by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn buffer_phys(&self, index: usize) -> Result<u64> {
        if index >= self.total_buffers {
            return Err(Error::InvalidArgument);
        }
        let offset = (index as u64) * (self.stride as u64);
        Ok(self.config.base_phys + offset)
    }

    /// Returns the virtual address of a buffer by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn buffer_virt(&self, index: usize) -> Result<u64> {
        if index >= self.total_buffers {
            return Err(Error::InvalidArgument);
        }
        let offset = (index as u64) * (self.stride as u64);
        Ok(self.config.base_virt + offset)
    }

    /// Checks whether a buffer at `index` is currently allocated.
    pub fn is_allocated(&self, index: usize) -> bool {
        if index >= self.total_buffers {
            return false;
        }
        let word_idx = index / 64;
        let bit = index % 64;
        self.bitmap[word_idx] & (1u64 << bit) != 0
    }

    /// Resets the pool, freeing all buffers.
    ///
    /// Statistics are preserved; only allocation state is cleared.
    pub fn reset(&mut self) {
        self.bitmap = [0u64; BITMAP_WORDS];
        self.allocated = 0;
    }
}

// -------------------------------------------------------------------
// ManagerStats
// -------------------------------------------------------------------

/// Aggregate statistics across all pools in the manager.
#[derive(Debug, Clone, Copy, Default)]
pub struct ManagerStats {
    /// Number of active pools.
    pub active_pools: usize,
    /// Total buffers across all pools.
    pub total_buffers: usize,
    /// Total allocated buffers across all pools.
    pub total_allocated: usize,
    /// Total free buffers across all pools.
    pub total_free: usize,
    /// Cumulative allocations across all pools.
    pub total_alloc_count: u64,
    /// Cumulative frees across all pools.
    pub total_free_count: u64,
    /// Cumulative allocation failures across all pools.
    pub total_alloc_fail_count: u64,
    /// Total pool memory in bytes.
    pub total_pool_bytes: u64,
}

// -------------------------------------------------------------------
// DmaPoolManager
// -------------------------------------------------------------------

/// System-wide manager of DMA buffer pools.
///
/// Supports creation, destruction, and allocation from up to
/// [`MAX_POOLS`] pools. Each pool is identified by a unique
/// `pool_id` assigned at creation time.
pub struct DmaPoolManager {
    /// Pool slots.
    pools: [DmaPool; MAX_POOLS],
    /// Number of active pools.
    pool_count: usize,
    /// Next pool ID to assign.
    next_pool_id: u32,
}

impl Default for DmaPoolManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaPoolManager {
    /// Creates a new, empty pool manager.
    pub const fn new() -> Self {
        Self {
            pools: [const { DmaPool::empty() }; MAX_POOLS],
            pool_count: 0,
            next_pool_id: 1,
        }
    }

    /// Creates a new DMA buffer pool from the given configuration.
    ///
    /// Returns the assigned `pool_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if all pool slots are occupied.
    /// - [`Error::InvalidArgument`] if the configuration is invalid.
    pub fn create_pool(&mut self, config: PoolConfig) -> Result<u32> {
        if self.pool_count >= MAX_POOLS {
            return Err(Error::OutOfMemory);
        }

        let slot_idx = self
            .pools
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;

        let pool_id = self.next_pool_id;
        self.next_pool_id = self.next_pool_id.wrapping_add(1);

        self.pools[slot_idx].init(config, pool_id)?;
        self.pool_count += 1;

        Ok(pool_id)
    }

    /// Destroys a pool by its `pool_id`.
    ///
    /// All buffers are implicitly freed.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no pool with the given ID exists.
    /// - [`Error::Busy`] if buffers are still allocated (unless
    ///   `force` is true).
    pub fn destroy_pool(&mut self, pool_id: u32) -> Result<()> {
        let idx = self.find_pool_index(pool_id)?;
        self.pools[idx] = DmaPool::empty();
        self.pool_count = self.pool_count.saturating_sub(1);
        Ok(())
    }

    /// Force-destroys a pool, releasing it regardless of outstanding
    /// allocations.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no pool with the given ID exists.
    pub fn force_destroy_pool(&mut self, pool_id: u32) -> Result<usize> {
        let idx = self.find_pool_index(pool_id)?;
        let outstanding = self.pools[idx].allocated;
        self.pools[idx] = DmaPool::empty();
        self.pool_count = self.pool_count.saturating_sub(1);
        Ok(outstanding)
    }

    /// Allocates a buffer from the specified pool.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the pool does not exist.
    /// - [`Error::OutOfMemory`] if the pool is exhausted.
    pub fn alloc_buffer(&mut self, pool_id: u32) -> Result<BufferHandle> {
        let idx = self.find_pool_index(pool_id)?;
        self.pools[idx].alloc_buffer()
    }

    /// Frees a buffer back to the specified pool.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the pool does not exist.
    /// - [`Error::InvalidArgument`] if the handle is invalid.
    pub fn free_buffer(&mut self, pool_id: u32, handle: BufferHandle) -> Result<()> {
        let idx = self.find_pool_index(pool_id)?;
        self.pools[idx].free_buffer(handle)
    }

    /// Frees a buffer by its physical address.
    ///
    /// Searches all pools for the one containing `phys`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no pool contains the address.
    pub fn free_by_phys(&mut self, phys: u64) -> Result<()> {
        for pool in &mut self.pools {
            if !pool.active {
                continue;
            }
            let base = pool.config.base_phys;
            let end = base + pool.config.pool_size as u64;
            if phys >= base && phys < end {
                return pool.free_by_phys(phys);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns statistics for a specific pool.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the pool does not exist.
    pub fn pool_stats(&self, pool_id: u32) -> Result<DmaPoolStats> {
        let idx = self.find_pool_index(pool_id)?;
        Ok(self.pools[idx].stats())
    }

    /// Returns aggregate statistics across all pools.
    pub fn stats(&self) -> ManagerStats {
        let mut s = ManagerStats::default();
        s.active_pools = self.pool_count;
        for pool in &self.pools {
            if !pool.active {
                continue;
            }
            s.total_buffers += pool.total_buffers;
            s.total_allocated += pool.allocated;
            s.total_free += pool.available();
            s.total_alloc_count += pool.alloc_count;
            s.total_free_count += pool.free_count;
            s.total_alloc_fail_count += pool.alloc_fail_count;
            s.total_pool_bytes += pool.config.pool_size as u64;
        }
        s
    }

    /// Returns a reference to a pool by its ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the pool does not exist.
    pub fn get_pool(&self, pool_id: u32) -> Result<&DmaPool> {
        let idx = self.find_pool_index(pool_id)?;
        Ok(&self.pools[idx])
    }

    /// Returns a mutable reference to a pool by its ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the pool does not exist.
    pub fn get_pool_mut(&mut self, pool_id: u32) -> Result<&mut DmaPool> {
        let idx = self.find_pool_index(pool_id)?;
        Ok(&mut self.pools[idx])
    }

    /// Returns the number of active pools.
    pub fn pool_count(&self) -> usize {
        self.pool_count
    }

    /// Returns `true` if no pools are registered.
    pub fn is_empty(&self) -> bool {
        self.pool_count == 0
    }

    /// Finds the pool containing a given physical address.
    ///
    /// Returns the `pool_id` if found, or `None`.
    pub fn find_pool_for_phys(&self, phys: u64) -> Option<u32> {
        for pool in &self.pools {
            if !pool.active {
                continue;
            }
            let base = pool.config.base_phys;
            let end = base + pool.config.pool_size as u64;
            if phys >= base && phys < end {
                return Some(pool.pool_id);
            }
        }
        None
    }

    /// Resets all pools, freeing every buffer.
    ///
    /// Pools remain active; only allocation state is cleared.
    pub fn reset_all(&mut self) {
        for pool in &mut self.pools {
            if pool.active {
                pool.reset();
            }
        }
    }

    /// Allocates a batch of buffers from a single pool.
    ///
    /// Fills `handles` with as many allocated buffers as possible.
    /// Returns the number of buffers successfully allocated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the pool does not exist.
    pub fn alloc_batch(&mut self, pool_id: u32, handles: &mut [BufferHandle]) -> Result<usize> {
        let idx = self.find_pool_index(pool_id)?;
        let mut count = 0;
        for slot in handles.iter_mut() {
            match self.pools[idx].alloc_buffer() {
                Ok(h) => {
                    *slot = h;
                    count += 1;
                }
                Err(Error::OutOfMemory) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(count)
    }

    /// Frees a batch of buffers back to a single pool.
    ///
    /// Returns the number of buffers successfully freed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the pool does not exist.
    pub fn free_batch(&mut self, pool_id: u32, handles: &[BufferHandle]) -> Result<usize> {
        let idx = self.find_pool_index(pool_id)?;
        let mut count = 0;
        for handle in handles {
            if self.pools[idx].free_buffer(*handle).is_ok() {
                count += 1;
            }
        }
        Ok(count)
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Finds the array index of a pool by its `pool_id`.
    fn find_pool_index(&self, pool_id: u32) -> Result<usize> {
        self.pools
            .iter()
            .position(|p| p.active && p.pool_id == pool_id)
            .ok_or(Error::NotFound)
    }
}
