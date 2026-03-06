// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA coherent memory allocator.
//!
//! Provides coherent DMA memory — physically contiguous buffers that
//! are simultaneously accessible by the CPU and a DMA-capable device
//! without explicit cache flush/invalidation. On x86_64, coherent DMA
//! memory is typically allocated from the low 4 GiB (or below a
//! device's DMA mask) and mapped uncacheable or write-combining.
//!
//! # Design
//!
//! ```text
//!  dma_alloc_coherent(dev, size)
//!       │
//!       ▼
//!  ┌───────────────────┐
//!  │ CoherentAllocator  │
//!  │ find contiguous    │──▶ physical frames within DMA mask
//!  │ map uncacheable    │──▶ virtual mapping (UC/WC)
//!  └───────────────────┘
//!       │
//!       ▼
//!  (cpu_addr, dma_addr)
//! ```
//!
//! # Key Types
//!
//! - [`DmaMask`] — device DMA address mask
//! - [`CoherentRegion`] — an allocated coherent DMA region
//! - [`CoherentAllocator`] — the DMA coherent allocator
//! - [`CoherentStats`] — allocation statistics
//!
//! Reference: Linux `kernel/dma/coherent.c`, `include/linux/dma-mapping.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size.
const PAGE_SIZE: usize = 4096;

/// Maximum coherent DMA regions.
const MAX_REGIONS: usize = 256;

/// Default 32-bit DMA mask (4 GiB).
const DMA_MASK_32BIT: u64 = 0xFFFF_FFFF;

/// Full 64-bit DMA mask.
const DMA_MASK_64BIT: u64 = u64::MAX;

// -------------------------------------------------------------------
// DmaMask
// -------------------------------------------------------------------

/// Device DMA address mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaMask(u64);

impl DmaMask {
    /// 32-bit DMA mask.
    pub const BIT32: Self = Self(DMA_MASK_32BIT);

    /// 64-bit DMA mask.
    pub const BIT64: Self = Self(DMA_MASK_64BIT);

    /// Creates a mask from raw bits.
    pub const fn new(mask: u64) -> Self {
        Self(mask)
    }

    /// Returns the raw mask value.
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns `true` if the given physical address is within this mask.
    pub const fn contains(self, phys_addr: u64) -> bool {
        phys_addr <= self.0
    }

    /// Returns the maximum addressable byte.
    pub const fn max_addr(self) -> u64 {
        self.0
    }
}

impl Default for DmaMask {
    fn default() -> Self {
        Self::BIT32
    }
}

// -------------------------------------------------------------------
// CacheMode
// -------------------------------------------------------------------

/// CPU cache mode for the coherent mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    /// Uncacheable (strong ordering).
    Uncacheable,
    /// Write-combining (good for frame buffers).
    WriteCombining,
    /// Write-through.
    WriteThrough,
}

impl Default for CacheMode {
    fn default() -> Self {
        Self::Uncacheable
    }
}

// -------------------------------------------------------------------
// CoherentRegion
// -------------------------------------------------------------------

/// An allocated coherent DMA memory region.
#[derive(Debug, Clone, Copy)]
pub struct CoherentRegion {
    /// CPU virtual address.
    cpu_addr: u64,
    /// DMA (bus) address.
    dma_addr: u64,
    /// Size in bytes.
    size: usize,
    /// Cache mode.
    cache_mode: CacheMode,
    /// DMA mask used for allocation.
    mask: DmaMask,
    /// Whether this region is in use.
    in_use: bool,
}

impl CoherentRegion {
    /// Creates an empty region.
    pub const fn new() -> Self {
        Self {
            cpu_addr: 0,
            dma_addr: 0,
            size: 0,
            cache_mode: CacheMode::Uncacheable,
            mask: DmaMask::BIT32,
            in_use: false,
        }
    }

    /// Returns the CPU virtual address.
    pub const fn cpu_addr(&self) -> u64 {
        self.cpu_addr
    }

    /// Returns the DMA bus address.
    pub const fn dma_addr(&self) -> u64 {
        self.dma_addr
    }

    /// Returns the size.
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns the cache mode.
    pub const fn cache_mode(&self) -> CacheMode {
        self.cache_mode
    }

    /// Returns the number of pages.
    pub const fn nr_pages(&self) -> usize {
        (self.size + PAGE_SIZE - 1) / PAGE_SIZE
    }
}

impl Default for CoherentRegion {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// CoherentStats
// -------------------------------------------------------------------

/// Coherent DMA allocator statistics.
#[derive(Debug, Clone, Copy)]
pub struct CoherentStats {
    /// Total allocations.
    pub allocs: u64,
    /// Total frees.
    pub frees: u64,
    /// Active regions.
    pub active: usize,
    /// Total bytes currently allocated.
    pub bytes_allocated: u64,
    /// Peak bytes allocated.
    pub peak_bytes: u64,
    /// Allocation failures.
    pub failures: u64,
}

impl CoherentStats {
    /// Creates empty stats.
    pub const fn new() -> Self {
        Self {
            allocs: 0,
            frees: 0,
            active: 0,
            bytes_allocated: 0,
            peak_bytes: 0,
            failures: 0,
        }
    }
}

impl Default for CoherentStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// CoherentAllocator
// -------------------------------------------------------------------

/// DMA coherent memory allocator.
pub struct CoherentAllocator {
    /// Allocated regions.
    regions: [CoherentRegion; MAX_REGIONS],
    /// Number of active regions.
    count: usize,
    /// Statistics.
    stats: CoherentStats,
    /// Next CPU virtual address hint.
    next_cpu_addr: u64,
    /// Next DMA physical address hint.
    next_dma_addr: u64,
}

impl CoherentAllocator {
    /// Creates a new coherent allocator.
    pub const fn new() -> Self {
        Self {
            regions: [const { CoherentRegion::new() }; MAX_REGIONS],
            count: 0,
            stats: CoherentStats::new(),
            next_cpu_addr: 0xFFFF_8800_0000_0000, // Kernel direct-map region.
            next_dma_addr: 0x0010_0000,           // Above 1 MiB.
        }
    }

    /// Returns the number of active regions.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns the statistics.
    pub const fn stats(&self) -> &CoherentStats {
        &self.stats
    }

    /// Allocates coherent DMA memory.
    pub fn alloc(
        &mut self,
        size: usize,
        mask: DmaMask,
        cache_mode: CacheMode,
    ) -> Result<(u64, u64)> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        // Check if the DMA address fits within the mask.
        if !mask.contains(self.next_dma_addr + aligned as u64 - 1) {
            self.stats.failures = self.stats.failures.saturating_add(1);
            return Err(Error::OutOfMemory);
        }

        // Find a free slot.
        let mut slot = MAX_REGIONS;
        for i in 0..MAX_REGIONS {
            if !self.regions[i].in_use {
                slot = i;
                break;
            }
        }
        if slot >= MAX_REGIONS {
            self.stats.failures = self.stats.failures.saturating_add(1);
            return Err(Error::OutOfMemory);
        }

        let cpu_addr = self.next_cpu_addr;
        let dma_addr = self.next_dma_addr;

        self.regions[slot] = CoherentRegion {
            cpu_addr,
            dma_addr,
            size: aligned,
            cache_mode,
            mask,
            in_use: true,
        };

        self.next_cpu_addr += aligned as u64;
        self.next_dma_addr += aligned as u64;
        self.count += 1;

        self.stats.allocs = self.stats.allocs.saturating_add(1);
        self.stats.active = self.count;
        self.stats.bytes_allocated = self.stats.bytes_allocated.saturating_add(aligned as u64);
        if self.stats.bytes_allocated > self.stats.peak_bytes {
            self.stats.peak_bytes = self.stats.bytes_allocated;
        }

        Ok((cpu_addr, dma_addr))
    }

    /// Frees coherent DMA memory.
    pub fn free(&mut self, cpu_addr: u64) -> Result<()> {
        for i in 0..MAX_REGIONS {
            if self.regions[i].in_use && self.regions[i].cpu_addr == cpu_addr {
                let size = self.regions[i].size as u64;
                self.regions[i].in_use = false;
                self.count -= 1;
                self.stats.frees = self.stats.frees.saturating_add(1);
                self.stats.active = self.count;
                self.stats.bytes_allocated = self.stats.bytes_allocated.saturating_sub(size);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Looks up a region by its CPU address.
    pub fn lookup(&self, cpu_addr: u64) -> Result<&CoherentRegion> {
        for i in 0..MAX_REGIONS {
            if self.regions[i].in_use && self.regions[i].cpu_addr == cpu_addr {
                return Ok(&self.regions[i]);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the DMA address for a given CPU address.
    pub fn cpu_to_dma(&self, cpu_addr: u64) -> Result<u64> {
        let region = self.lookup(cpu_addr)?;
        Ok(region.dma_addr)
    }
}

impl Default for CoherentAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a new coherent DMA allocator.
pub fn create_allocator() -> CoherentAllocator {
    CoherentAllocator::new()
}

/// Allocates coherent DMA memory, returning (cpu_addr, dma_addr).
pub fn dma_alloc_coherent(
    alloc: &mut CoherentAllocator,
    size: usize,
    mask: DmaMask,
) -> Result<(u64, u64)> {
    alloc.alloc(size, mask, CacheMode::Uncacheable)
}

/// Frees coherent DMA memory by CPU address.
pub fn dma_free_coherent(alloc: &mut CoherentAllocator, cpu_addr: u64) -> Result<()> {
    alloc.free(cpu_addr)
}
