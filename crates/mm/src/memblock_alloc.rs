// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Early boot memory block allocator.
//!
//! Provides the memblock allocator used during early boot before the
//! buddy allocator is initialized. Manages memory as typed regions
//! (available, reserved, nomap) and supports aligned allocation with
//! NUMA node affinity.
//!
//! - [`MemblockType`] — region classification
//! - [`MemblockRegion`] — a contiguous physical memory region
//! - [`MemblockAllocator`] — the early boot allocator
//! - [`MemblockStats`] — allocation statistics
//!
//! Reference: Linux `mm/memblock.c`, `include/linux/memblock.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of memory regions.
const MAX_REGIONS: usize = 256;

/// Default alignment (page size).
const PAGE_SIZE: u64 = 4096;

/// NUMA node: any node.
const NUMA_NO_NODE: u32 = 0xFFFF_FFFF;

// -------------------------------------------------------------------
// MemblockType
// -------------------------------------------------------------------

/// Classification for memory regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemblockType {
    /// Available for allocation.
    #[default]
    Available,
    /// Reserved (kernel, firmware, etc.).
    Reserved,
    /// Not mappable (MMIO regions, etc.).
    Nomap,
}

// -------------------------------------------------------------------
// MemblockRegion
// -------------------------------------------------------------------

/// A contiguous physical memory region.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemblockRegion {
    /// Physical base address.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    /// Region type.
    pub region_type: MemblockType,
    /// NUMA node ID.
    pub nid: u32,
    /// Whether this slot is in use.
    pub active: bool,
}

impl MemblockRegion {
    /// Creates a new region.
    pub fn new(base: u64, size: u64, region_type: MemblockType, nid: u32) -> Self {
        Self {
            base,
            size,
            region_type,
            nid,
            active: true,
        }
    }

    /// Returns the end address (exclusive).
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }

    /// Returns `true` if this region overlaps the given range.
    pub fn overlaps(&self, base: u64, size: u64) -> bool {
        self.active && self.base < base.saturating_add(size) && base < self.end()
    }

    /// Returns `true` if this region contains the given range.
    pub fn contains(&self, base: u64, size: u64) -> bool {
        self.active && base >= self.base && base.saturating_add(size) <= self.end()
    }
}

// -------------------------------------------------------------------
// MemblockStats
// -------------------------------------------------------------------

/// Memblock allocation statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemblockStats {
    /// Total allocation requests.
    pub alloc_requests: u64,
    /// Successful allocations.
    pub alloc_success: u64,
    /// Failed allocations.
    pub alloc_failures: u64,
    /// Total bytes allocated.
    pub bytes_allocated: u64,
    /// Total bytes freed.
    pub bytes_freed: u64,
    /// Regions added.
    pub regions_added: u64,
    /// Regions reserved.
    pub regions_reserved: u64,
}

impl MemblockStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// MemblockAllocator
// -------------------------------------------------------------------

/// The early boot memory block allocator.
pub struct MemblockAllocator {
    /// Memory regions.
    regions: [MemblockRegion; MAX_REGIONS],
    /// Number of active regions.
    nr_regions: usize,
    /// Statistics.
    stats: MemblockStats,
    /// Whether bottom-up allocation is preferred.
    bottom_up: bool,
}

impl Default for MemblockAllocator {
    fn default() -> Self {
        Self {
            regions: [MemblockRegion::default(); MAX_REGIONS],
            nr_regions: 0,
            stats: MemblockStats::default(),
            bottom_up: true,
        }
    }
}

impl MemblockAllocator {
    /// Creates a new memblock allocator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an available memory region.
    pub fn add(&mut self, base: u64, size: u64, nid: u32) -> Result<usize> {
        self.add_region(base, size, MemblockType::Available, nid)
    }

    /// Reserves a memory region.
    pub fn reserve(&mut self, base: u64, size: u64) -> Result<usize> {
        self.stats.regions_reserved += 1;
        self.add_region(base, size, MemblockType::Reserved, NUMA_NO_NODE)
    }

    /// Adds a region of the given type.
    fn add_region(
        &mut self,
        base: u64,
        size: u64,
        region_type: MemblockType,
        nid: u32,
    ) -> Result<usize> {
        if self.nr_regions >= MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let idx = self.nr_regions;
        self.regions[idx] = MemblockRegion::new(base, size, region_type, nid);
        self.nr_regions += 1;
        self.stats.regions_added += 1;
        Ok(idx)
    }

    /// Allocates memory with the given size and alignment.
    pub fn alloc_aligned(&mut self, size: u64, align: u64, nid: u32) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let align = if align == 0 { PAGE_SIZE } else { align };
        self.stats.alloc_requests += 1;

        for i in 0..self.nr_regions {
            if !self.regions[i].active {
                continue;
            }
            if self.regions[i].region_type != MemblockType::Available {
                continue;
            }
            if nid != NUMA_NO_NODE && self.regions[i].nid != nid {
                continue;
            }

            let base = self.regions[i].base;
            let aligned_base = (base + align - 1) & !(align - 1);
            let offset = aligned_base - base;

            if offset + size <= self.regions[i].size {
                // Mark as reserved by shrinking the available region.
                self.regions[i].base = aligned_base + size;
                self.regions[i].size -= offset + size;
                if self.regions[i].size == 0 {
                    self.regions[i].active = false;
                }
                self.stats.alloc_success += 1;
                self.stats.bytes_allocated += size;
                return Ok(aligned_base);
            }
        }

        self.stats.alloc_failures += 1;
        Err(Error::OutOfMemory)
    }

    /// Allocates page-aligned memory.
    pub fn alloc(&mut self, size: u64) -> Result<u64> {
        self.alloc_aligned(size, PAGE_SIZE, NUMA_NO_NODE)
    }

    /// Frees a previously allocated region.
    pub fn free(&mut self, base: u64, size: u64) -> Result<()> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        // Add back as available.
        self.add_region(base, size, MemblockType::Available, NUMA_NO_NODE)?;
        self.stats.bytes_freed += size;
        Ok(())
    }

    /// Sets bottom-up allocation mode.
    pub fn set_bottom_up(&mut self, bottom_up: bool) {
        self.bottom_up = bottom_up;
    }

    /// Returns whether bottom-up mode is active.
    pub fn is_bottom_up(&self) -> bool {
        self.bottom_up
    }

    /// Returns the total available memory.
    pub fn total_available(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.nr_regions {
            if self.regions[i].active && self.regions[i].region_type == MemblockType::Available {
                total = total.saturating_add(self.regions[i].size);
            }
        }
        total
    }

    /// Returns the number of regions.
    pub fn nr_regions(&self) -> usize {
        self.nr_regions
    }

    /// Returns statistics.
    pub fn stats(&self) -> &MemblockStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
