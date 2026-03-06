// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA-safe memory allocation for the ONCRIX kernel.
//!
//! Provides coherent and streaming DMA memory allocators
//! suitable for device drivers that perform Direct Memory
//! Access (DMA) transfers.
//!
//! - [`DmaAllocator`] — central allocator for DMA regions
//! - [`DmaPool`] — fixed-size block pool for frequent allocs
//! - [`DmaRegion`] — descriptor for a mapped DMA buffer
//! - [`DmaStats`] — summary statistics

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// ISA DMA zone limit: 16 MiB.
const _DMA_ZONE_LIMIT: u64 = 0x100_0000;

/// DMA32 zone limit: 4 GiB.
const _DMA32_ZONE_LIMIT: u64 = 0x1_0000_0000;

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of tracked DMA regions.
const MAX_DMA_REGIONS: usize = 256;

/// Maximum number of DMA pools.
const MAX_DMA_POOLS: usize = 8;

// -------------------------------------------------------------------
// DmaDirection
// -------------------------------------------------------------------

/// Direction of a DMA transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmaDirection {
    /// Data flows from CPU memory to the device.
    ToDevice,
    /// Data flows from the device to CPU memory.
    FromDevice,
    /// Data flows in both directions.
    Bidirectional,
    /// No transfer direction (e.g. control buffers).
    #[default]
    None,
}

// -------------------------------------------------------------------
// DmaCoherence
// -------------------------------------------------------------------

/// Coherence mode of a DMA mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmaCoherence {
    /// Hardware-coherent: no explicit cache management needed.
    #[default]
    Coherent,
    /// Streaming: requires explicit sync before/after access.
    Streaming,
}

// -------------------------------------------------------------------
// DmaRegion
// -------------------------------------------------------------------

/// Descriptor for a single DMA-mapped memory region.
#[derive(Debug, Clone, Copy, Default)]
pub struct DmaRegion {
    /// Physical address of the region.
    pub phys_addr: u64,
    /// Virtual address mapped for CPU access.
    pub virt_addr: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Transfer direction.
    pub direction: DmaDirection,
    /// Coherence mode.
    pub coherence: DmaCoherence,
    /// Owning device identifier.
    pub device_id: u16,
    /// Whether the region is currently in use.
    pub active: bool,
}

// -------------------------------------------------------------------
// DmaPool
// -------------------------------------------------------------------

/// Fixed-size block pool for frequent small DMA allocations.
///
/// Each pool manages a contiguous physical region divided into
/// equal-sized blocks.  A bitmap tracks which blocks are free.
/// Supports up to 4096 blocks (64 × 64 bits).
pub struct DmaPool {
    /// Pool name stored inline.
    _name: [u8; 32],
    /// Number of valid bytes in `_name`.
    _name_len: usize,
    /// Physical base address of the pool.
    base_phys: u64,
    /// Virtual base address of the pool.
    base_virt: u64,
    /// Total size of the pool in bytes.
    _pool_size: u64,
    /// Size of each block in bytes.
    block_size: u64,
    /// Allocation bitmap (1 = allocated).
    bitmap: [u64; 64],
    /// Total number of blocks in the pool.
    total_blocks: usize,
    /// Number of currently allocated blocks.
    allocated: usize,
    /// Whether the pool has been initialised.
    active: bool,
}

impl Default for DmaPool {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaPool {
    /// Creates an empty, inactive pool.
    const fn new() -> Self {
        Self {
            _name: [0u8; 32],
            _name_len: 0,
            base_phys: 0,
            base_virt: 0,
            _pool_size: 0,
            block_size: 0,
            bitmap: [0u64; 64],
            total_blocks: 0,
            allocated: 0,
            active: false,
        }
    }

    /// Allocates one block from the pool.
    ///
    /// Returns `(phys_addr, virt_addr)` of the allocated block.
    pub fn alloc(&mut self) -> Result<(u64, u64)> {
        if !self.active {
            return Err(Error::NotFound);
        }
        if self.allocated >= self.total_blocks {
            return Err(Error::OutOfMemory);
        }

        for (word_idx, word) in self.bitmap.iter_mut().enumerate() {
            if *word == u64::MAX {
                continue;
            }
            let bit = (*word).trailing_ones() as usize;
            if word_idx * 64 + bit >= self.total_blocks {
                break;
            }
            *word |= 1u64 << bit;
            self.allocated += 1;
            let offset = (word_idx * 64 + bit) as u64 * self.block_size;
            let phys = self.base_phys + offset;
            let virt = self.base_virt + offset;
            return Ok((phys, virt));
        }

        Err(Error::OutOfMemory)
    }

    /// Frees a previously allocated block by its physical
    /// address.
    pub fn free(&mut self, phys: u64) -> Result<()> {
        if !self.active {
            return Err(Error::NotFound);
        }
        if phys < self.base_phys {
            return Err(Error::InvalidArgument);
        }
        let offset = phys - self.base_phys;
        if self.block_size == 0 {
            return Err(Error::InvalidArgument);
        }
        if offset % self.block_size != 0 {
            return Err(Error::InvalidArgument);
        }
        let index = (offset / self.block_size) as usize;
        if index >= self.total_blocks {
            return Err(Error::InvalidArgument);
        }
        let word_idx = index / 64;
        let bit = index % 64;
        if self.bitmap[word_idx] & (1u64 << bit) == 0 {
            return Err(Error::InvalidArgument);
        }
        self.bitmap[word_idx] &= !(1u64 << bit);
        self.allocated = self.allocated.saturating_sub(1);
        Ok(())
    }

    /// Returns the number of available (free) blocks.
    pub fn available(&self) -> usize {
        self.total_blocks - self.allocated
    }
}

// -------------------------------------------------------------------
// DmaStats
// -------------------------------------------------------------------

/// Summary statistics for the DMA allocator.
#[derive(Debug, Clone, Copy, Default)]
pub struct DmaStats {
    /// Total number of active DMA regions.
    pub total_regions: usize,
    /// Total bytes allocated across all regions.
    pub total_allocated_bytes: u64,
    /// Number of active DMA pools.
    pub pool_count: usize,
}

// -------------------------------------------------------------------
// DmaAllocator
// -------------------------------------------------------------------

/// Central DMA memory allocator.
///
/// Manages both coherent and streaming DMA regions as well as
/// fixed-size DMA pools.
pub struct DmaAllocator {
    /// Tracked DMA regions.
    regions: [DmaRegion; MAX_DMA_REGIONS],
    /// Number of regions currently used.
    region_count: usize,
    /// DMA pools for fixed-size allocations.
    pools: [DmaPool; MAX_DMA_POOLS],
    /// Number of pools currently active.
    pool_count: usize,
    /// Total bytes allocated via coherent allocations.
    total_allocated: u64,
}

impl Default for DmaAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaAllocator {
    /// Creates a new DMA allocator with no regions or pools.
    pub const fn new() -> Self {
        const EMPTY_REGION: DmaRegion = DmaRegion {
            phys_addr: 0,
            virt_addr: 0,
            size: 0,
            direction: DmaDirection::None,
            coherence: DmaCoherence::Coherent,
            device_id: 0,
            active: false,
        };
        const EMPTY_POOL: DmaPool = DmaPool {
            _name: [0u8; 32],
            _name_len: 0,
            base_phys: 0,
            base_virt: 0,
            _pool_size: 0,
            block_size: 0,
            bitmap: [0u64; 64],
            total_blocks: 0,
            allocated: 0,
            active: false,
        };
        Self {
            regions: [EMPTY_REGION; MAX_DMA_REGIONS],
            region_count: 0,
            pools: [EMPTY_POOL; MAX_DMA_POOLS],
            pool_count: 0,
            total_allocated: 0,
        }
    }

    /// Allocates a coherent DMA region of the given size.
    ///
    /// The returned [`DmaRegion`] describes a physically
    /// contiguous, cache-coherent buffer suitable for
    /// bidirectional device access.
    ///
    /// The physical address is chosen as a simple bump from
    /// `total_allocated`, rounded up to [`PAGE_SIZE`].
    /// A real implementation would query the physical page
    /// allocator.
    pub fn alloc_coherent(&mut self, size: u64, device_id: u16) -> Result<DmaRegion> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.region_count >= MAX_DMA_REGIONS {
            return Err(Error::OutOfMemory);
        }

        let aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let phys = self.total_allocated;
        let virt = phys; // identity-mapped stub

        let region = DmaRegion {
            phys_addr: phys,
            virt_addr: virt,
            size: aligned,
            direction: DmaDirection::Bidirectional,
            coherence: DmaCoherence::Coherent,
            device_id,
            active: true,
        };

        // Find first inactive slot.
        let slot = self
            .regions
            .iter()
            .position(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        self.regions[slot] = region;
        self.region_count += 1;
        self.total_allocated += aligned;

        Ok(region)
    }

    /// Maps an existing physical buffer for streaming DMA.
    ///
    /// Returns the index of the newly created region so the
    /// caller can later call [`sync_for_device`] /
    /// [`sync_for_cpu`] and [`free`].
    pub fn alloc_streaming(
        &mut self,
        phys: u64,
        size: u64,
        dir: DmaDirection,
        device_id: u16,
    ) -> Result<usize> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.region_count >= MAX_DMA_REGIONS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .regions
            .iter()
            .position(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        self.regions[slot] = DmaRegion {
            phys_addr: phys,
            virt_addr: phys, // identity-mapped stub
            size,
            direction: dir,
            coherence: DmaCoherence::Streaming,
            device_id,
            active: true,
        };

        self.region_count += 1;
        Ok(slot)
    }

    /// Frees a DMA region by its index.
    pub fn free(&mut self, index: usize) -> Result<()> {
        if index >= MAX_DMA_REGIONS {
            return Err(Error::InvalidArgument);
        }
        if !self.regions[index].active {
            return Err(Error::NotFound);
        }
        self.regions[index].active = false;
        self.region_count = self.region_count.saturating_sub(1);
        Ok(())
    }

    /// Flushes caches so the device sees the latest CPU
    /// writes (stub).
    pub fn sync_for_device(&self, index: usize) -> Result<()> {
        if index >= MAX_DMA_REGIONS {
            return Err(Error::InvalidArgument);
        }
        if !self.regions[index].active {
            return Err(Error::NotFound);
        }
        // Stub: real implementation would issue cache-clean
        // operations for the region's address range.
        Ok(())
    }

    /// Invalidates caches so the CPU sees the latest device
    /// writes (stub).
    pub fn sync_for_cpu(&self, index: usize) -> Result<()> {
        if index >= MAX_DMA_REGIONS {
            return Err(Error::InvalidArgument);
        }
        if !self.regions[index].active {
            return Err(Error::NotFound);
        }
        // Stub: real implementation would issue
        // cache-invalidate operations for the region's
        // address range.
        Ok(())
    }

    /// Creates a new DMA pool.
    ///
    /// Returns the pool index on success.
    pub fn create_pool(
        &mut self,
        name: &[u8],
        base_phys: u64,
        base_virt: u64,
        pool_size: u64,
        block_size: u64,
    ) -> Result<usize> {
        if block_size == 0 || pool_size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.pool_count >= MAX_DMA_POOLS {
            return Err(Error::OutOfMemory);
        }

        let total_blocks = (pool_size / block_size) as usize;
        if total_blocks == 0 || total_blocks > 4096 {
            return Err(Error::InvalidArgument);
        }

        let idx = self
            .pools
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;

        let mut pool_name = [0u8; 32];
        let copy_len = name.len().min(32);
        pool_name[..copy_len].copy_from_slice(&name[..copy_len]);

        self.pools[idx] = DmaPool {
            _name: pool_name,
            _name_len: copy_len,
            base_phys,
            base_virt,
            _pool_size: pool_size,
            block_size,
            bitmap: [0u64; 64],
            total_blocks,
            allocated: 0,
            active: true,
        };

        self.pool_count += 1;
        Ok(idx)
    }

    /// Allocates a block from the given pool.
    ///
    /// Returns `(phys_addr, virt_addr)` of the block.
    pub fn pool_alloc(&mut self, pool_idx: usize) -> Result<(u64, u64)> {
        if pool_idx >= MAX_DMA_POOLS {
            return Err(Error::InvalidArgument);
        }
        self.pools[pool_idx].alloc()
    }

    /// Frees a block back to the given pool.
    pub fn pool_free(&mut self, pool_idx: usize, phys: u64) -> Result<()> {
        if pool_idx >= MAX_DMA_POOLS {
            return Err(Error::InvalidArgument);
        }
        self.pools[pool_idx].free(phys)
    }

    /// Returns summary statistics for the allocator.
    pub fn stats(&self) -> DmaStats {
        DmaStats {
            total_regions: self.region_count,
            total_allocated_bytes: self.total_allocated,
            pool_count: self.pool_count,
        }
    }

    /// Returns the number of active DMA regions.
    pub fn len(&self) -> usize {
        self.region_count
    }

    /// Returns `true` if there are no active DMA regions.
    pub fn is_empty(&self) -> bool {
        self.region_count == 0
    }
}
