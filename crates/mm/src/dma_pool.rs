// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA coherent pool allocator for the ONCRIX kernel.
//!
//! Provides fixed-size block pools for DMA-safe memory allocation,
//! optimized for device drivers that need many small DMA-coherent
//! buffers (e.g., descriptor rings, command structures).
//!
//! - [`DmaPool`] — fixed-size block pool with power-of-2 alignment
//! - [`DmaAllocation`] — a single allocation from a pool
//! - [`DmaPoolManager`] — manages multiple DMA pools
//! - [`DmaPoolStats`] — allocation statistics
//!
//! Reference: `.kernelORG/` — `mm/dmapool.c`, `include/linux/dmapool.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum number of DMA pools.
const MAX_DMA_POOLS: usize = 16;

/// Maximum number of blocks per pool.
const MAX_BLOCKS_PER_POOL: usize = 256;

/// Maximum number of pool pages (backing store).
const MAX_POOL_PAGES: usize = 32;

/// Minimum block size (must fit a free-list pointer).
const MIN_BLOCK_SIZE: usize = 8;

/// Maximum block size (one page).
const MAX_BLOCK_SIZE: usize = PAGE_SIZE;

// -------------------------------------------------------------------
// DmaAllocation
// -------------------------------------------------------------------

/// Represents a single DMA allocation from a pool.
#[derive(Debug, Clone, Copy, Default)]
pub struct DmaAllocation {
    /// Virtual address of the allocation (CPU-accessible).
    pub vaddr: u64,
    /// DMA address (device-accessible, may differ from physical).
    pub dma_addr: u64,
    /// Size of the allocation in bytes.
    pub size: usize,
    /// Index of the pool this allocation came from.
    pub pool_idx: u32,
    /// Index of the block within the pool.
    pub block_idx: u32,
    /// Whether this allocation is valid.
    pub valid: bool,
}

impl DmaAllocation {
    /// Create an empty (invalid) allocation.
    pub const fn empty() -> Self {
        Self {
            vaddr: 0,
            dma_addr: 0,
            size: 0,
            pool_idx: 0,
            block_idx: 0,
            valid: false,
        }
    }
}

// -------------------------------------------------------------------
// PoolBlock
// -------------------------------------------------------------------

/// State of a single block in a DMA pool.
#[derive(Debug, Clone, Copy, Default)]
struct PoolBlock {
    /// Virtual address of the block.
    vaddr: u64,
    /// DMA address of the block.
    dma_addr: u64,
    /// Whether the block is currently allocated.
    allocated: bool,
    /// Next free block index (for free list).
    next_free: u32,
}

impl PoolBlock {
    const fn empty() -> Self {
        Self {
            vaddr: 0,
            dma_addr: 0,
            allocated: false,
            next_free: u32::MAX,
        }
    }
}

// -------------------------------------------------------------------
// PoolPage
// -------------------------------------------------------------------

/// A backing page for a DMA pool.
#[derive(Debug, Clone, Copy, Default)]
struct PoolPage {
    /// Physical address of the page.
    phys_addr: u64,
    /// Virtual address of the page.
    virt_addr: u64,
    /// DMA address of the page.
    dma_addr: u64,
    /// Number of blocks in this page.
    block_count: u32,
    /// Index of the first block in this page.
    first_block: u32,
    /// Whether this page is active.
    active: bool,
}

impl PoolPage {
    const fn empty() -> Self {
        Self {
            phys_addr: 0,
            virt_addr: 0,
            dma_addr: 0,
            block_count: 0,
            first_block: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// DmaPoolStats
// -------------------------------------------------------------------

/// Statistics for a DMA pool.
#[derive(Debug, Clone, Copy, Default)]
pub struct DmaPoolStats {
    /// Total number of allocations performed.
    pub total_allocs: u64,
    /// Total number of frees performed.
    pub total_frees: u64,
    /// Current number of allocated blocks.
    pub current_allocs: u64,
    /// Number of allocation failures.
    pub alloc_failures: u64,
    /// Number of pool pages allocated.
    pub pages_allocated: u64,
    /// High watermark of concurrent allocations.
    pub high_watermark: u64,
}

// -------------------------------------------------------------------
// DmaPool
// -------------------------------------------------------------------

/// A fixed-size block pool for DMA-coherent memory allocation.
///
/// Each pool manages blocks of a single size with power-of-2
/// alignment, backed by one or more contiguous DMA-coherent pages.
pub struct DmaPool {
    /// Pool name (for debugging).
    name: [u8; 32],
    /// Name length.
    name_len: usize,
    /// Block size in bytes.
    block_size: usize,
    /// Block alignment (power of 2).
    alignment: usize,
    /// Allocation order (log2 of pages per backing allocation).
    allocation_order: u32,
    /// Block storage.
    blocks: [PoolBlock; MAX_BLOCKS_PER_POOL],
    /// Backing pages.
    pages: [PoolPage; MAX_POOL_PAGES],
    /// Total number of blocks.
    block_count: usize,
    /// Number of backing pages.
    page_count: usize,
    /// Head of free list (index into blocks).
    free_head: u32,
    /// Number of free blocks.
    free_count: usize,
    /// Statistics.
    stats: DmaPoolStats,
    /// Whether the pool is initialized.
    initialized: bool,
    /// Next simulated physical address for page allocation.
    next_phys: u64,
}

impl DmaPool {
    /// Create a new DMA pool.
    ///
    /// `block_size` is rounded up to the next power of 2 if necessary.
    /// `alignment` must be a power of 2 and at least `MIN_BLOCK_SIZE`.
    pub fn new(name: &[u8], block_size: usize, alignment: usize) -> Self {
        let mut name_buf = [0u8; 32];
        let copy_len = name.len().min(32);
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);

        let effective_size = block_size
            .max(MIN_BLOCK_SIZE)
            .min(MAX_BLOCK_SIZE)
            .next_power_of_two();
        let effective_align = alignment.max(MIN_BLOCK_SIZE).next_power_of_two();

        Self {
            name: name_buf,
            name_len: copy_len,
            block_size: effective_size,
            alignment: effective_align,
            allocation_order: 0,
            blocks: [PoolBlock::empty(); MAX_BLOCKS_PER_POOL],
            pages: [PoolPage::empty(); MAX_POOL_PAGES],
            block_count: 0,
            page_count: 0,
            free_head: u32::MAX,
            free_count: 0,
            stats: DmaPoolStats::default(),
            initialized: false,
            next_phys: 0x1000_0000,
        }
    }

    /// Initialize the pool with a base DMA address.
    ///
    /// Allocates the first backing page and carves it into blocks.
    pub fn init(&mut self, base_dma_addr: u64) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }

        self.next_phys = base_dma_addr;
        self.add_page()?;
        self.initialized = true;
        Ok(())
    }

    /// Allocate a block from the pool.
    ///
    /// Returns a [`DmaAllocation`] with both virtual and DMA addresses.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if no free blocks are available and no
    /// more backing pages can be allocated.
    pub fn dma_pool_alloc(&mut self) -> Result<DmaAllocation> {
        if !self.initialized {
            return Err(Error::Busy);
        }

        // Try to get a free block.
        if self.free_head == u32::MAX {
            // Try to add a new backing page.
            self.add_page()?;
        }

        if self.free_head == u32::MAX {
            self.stats.alloc_failures += 1;
            return Err(Error::OutOfMemory);
        }

        let idx = self.free_head as usize;
        let block = &mut self.blocks[idx];
        self.free_head = block.next_free;
        block.allocated = true;
        block.next_free = u32::MAX;
        self.free_count -= 1;

        self.stats.total_allocs += 1;
        self.stats.current_allocs += 1;
        if self.stats.current_allocs > self.stats.high_watermark {
            self.stats.high_watermark = self.stats.current_allocs;
        }

        Ok(DmaAllocation {
            vaddr: block.vaddr,
            dma_addr: block.dma_addr,
            size: self.block_size,
            pool_idx: 0,
            block_idx: idx as u32,
            valid: true,
        })
    }

    /// Free a block back to the pool.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the allocation is invalid or
    /// the block is not currently allocated.
    pub fn dma_pool_free(&mut self, alloc: &DmaAllocation) -> Result<()> {
        if !alloc.valid {
            return Err(Error::InvalidArgument);
        }

        let idx = alloc.block_idx as usize;
        if idx >= self.block_count {
            return Err(Error::InvalidArgument);
        }

        let block = &mut self.blocks[idx];
        if !block.allocated {
            return Err(Error::InvalidArgument);
        }

        block.allocated = false;
        block.next_free = self.free_head;
        self.free_head = idx as u32;
        self.free_count += 1;

        self.stats.total_frees += 1;
        self.stats.current_allocs = self.stats.current_allocs.saturating_sub(1);

        Ok(())
    }

    /// Add a new backing page and carve it into blocks.
    fn add_page(&mut self) -> Result<()> {
        if self.page_count >= MAX_POOL_PAGES {
            return Err(Error::OutOfMemory);
        }

        let phys = self.next_phys;
        let virt_addr = phys;
        let dma_addr = phys;
        self.next_phys += PAGE_SIZE as u64;

        let blocks_per_page = PAGE_SIZE / self.block_size;
        let first_block = self.block_count;

        if first_block + blocks_per_page > MAX_BLOCKS_PER_POOL {
            return Err(Error::OutOfMemory);
        }

        // Initialize blocks.
        for i in 0..blocks_per_page {
            let block_offset = i * self.block_size;
            let bi = first_block + i;
            self.blocks[bi] = PoolBlock {
                vaddr: virt_addr + block_offset as u64,
                dma_addr: dma_addr + block_offset as u64,
                allocated: false,
                next_free: if i + 1 < blocks_per_page {
                    (bi + 1) as u32
                } else {
                    self.free_head
                },
            };
        }

        // Link to existing free list.
        self.free_head = first_block as u32;
        self.free_count += blocks_per_page;
        self.block_count += blocks_per_page;

        // Record the page.
        self.pages[self.page_count] = PoolPage {
            phys_addr: phys,
            virt_addr,
            dma_addr,
            block_count: blocks_per_page as u32,
            first_block: first_block as u32,
            active: true,
        };
        self.page_count += 1;
        self.stats.pages_allocated += 1;

        Ok(())
    }

    /// Get the pool's block size.
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Get the pool's alignment.
    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// Get the number of free blocks.
    pub fn free_block_count(&self) -> usize {
        self.free_count
    }

    /// Get the total number of blocks.
    pub fn total_block_count(&self) -> usize {
        self.block_count
    }

    /// Get the pool name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Get pool statistics.
    pub fn statistics(&self) -> &DmaPoolStats {
        &self.stats
    }

    /// Check if the pool is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Destroy the pool, freeing all backing pages.
    pub fn destroy(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }

        // Check for leaked allocations.
        if self.stats.current_allocs > 0 {
            return Err(Error::Busy);
        }

        for i in 0..self.block_count {
            self.blocks[i] = PoolBlock::empty();
        }
        for i in 0..self.page_count {
            self.pages[i] = PoolPage::empty();
        }

        self.block_count = 0;
        self.page_count = 0;
        self.free_head = u32::MAX;
        self.free_count = 0;
        self.initialized = false;

        Ok(())
    }
}

// -------------------------------------------------------------------
// DmaPoolManager
// -------------------------------------------------------------------

/// Manages multiple DMA pools.
pub struct DmaPoolManager {
    /// Registered pools.
    pools: [Option<DmaPool>; MAX_DMA_POOLS],
    /// Number of active pools.
    pool_count: usize,
    /// Next DMA base address for new pools.
    next_base: u64,
}

impl DmaPoolManager {
    /// Create a new DMA pool manager.
    pub fn new() -> Self {
        Self {
            pools: [const { None }; MAX_DMA_POOLS],
            pool_count: 0,
            next_base: 0x2000_0000,
        }
    }

    /// Create a new DMA pool.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the maximum number of pools is reached.
    pub fn dma_pool_create(
        &mut self,
        name: &[u8],
        block_size: usize,
        alignment: usize,
    ) -> Result<u32> {
        if self.pool_count >= MAX_DMA_POOLS {
            return Err(Error::OutOfMemory);
        }

        let mut pool = DmaPool::new(name, block_size, alignment);
        let base = self.next_base;
        self.next_base += PAGE_SIZE as u64 * MAX_POOL_PAGES as u64;
        pool.init(base)?;

        let idx = self.pool_count;
        self.pools[idx] = Some(pool);
        self.pool_count += 1;

        Ok(idx as u32)
    }

    /// Get a reference to a pool by index.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the pool doesn't exist.
    pub fn get_pool(&self, idx: u32) -> Result<&DmaPool> {
        let i = idx as usize;
        if i >= MAX_DMA_POOLS {
            return Err(Error::NotFound);
        }
        self.pools[i].as_ref().ok_or(Error::NotFound)
    }

    /// Get a mutable reference to a pool by index.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the pool doesn't exist.
    pub fn get_pool_mut(&mut self, idx: u32) -> Result<&mut DmaPool> {
        let i = idx as usize;
        if i >= MAX_DMA_POOLS {
            return Err(Error::NotFound);
        }
        self.pools[i].as_mut().ok_or(Error::NotFound)
    }

    /// Destroy a pool by index.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the pool doesn't exist, or `Busy` if
    /// there are outstanding allocations.
    pub fn dma_pool_destroy(&mut self, idx: u32) -> Result<()> {
        let i = idx as usize;
        if i >= MAX_DMA_POOLS {
            return Err(Error::NotFound);
        }
        match self.pools[i].as_mut() {
            Some(pool) => {
                pool.destroy()?;
                self.pools[i] = None;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Get the number of active pools.
    pub fn active_pool_count(&self) -> usize {
        self.pools.iter().filter(|p| p.is_some()).count()
    }
}
