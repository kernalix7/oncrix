// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Early memory initialization.
//!
//! Implements the boot-time memory initialization sequence. The
//! bootloader provides a memory map describing usable, reserved, and
//! ACPI memory regions. This module processes that map, sets up an
//! early bump allocator for pre-buddy allocations, and reserves
//! special regions (kernel image, initrd, ACPI tables).
//!
//! - [`MemRegionType`] — memory region classification
//! - [`MemRegion`] — a single memory region
//! - [`BootMemMap`] — the complete boot memory map
//! - [`EarlyAllocator`] — bump allocator for early boot
//! - [`MemInitStats`] — initialization statistics
//!
//! Reference: `.kernelORG/` — `mm/memblock.c`, `arch/x86/kernel/e820.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum memory regions in the boot map.
const MAX_MEM_REGIONS: usize = 128;

/// Maximum reserved regions.
const MAX_RESERVED: usize = 64;

/// Early allocator arena size (4 MiB).
const EARLY_ALLOC_ARENA_SIZE: u64 = 4 * 1024 * 1024;

/// Alignment for early allocations.
const EARLY_ALLOC_ALIGN: u64 = 16;

// -------------------------------------------------------------------
// MemRegionType
// -------------------------------------------------------------------

/// Classification of a physical memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemRegionType {
    /// Usable RAM (available for general use).
    #[default]
    Usable,
    /// Reserved by firmware/hardware.
    Reserved,
    /// ACPI reclaimable memory.
    AcpiReclaimable,
    /// ACPI NVS (Non-Volatile Storage).
    AcpiNvs,
    /// Bad memory (defective).
    BadMemory,
    /// Persistent memory (NVDIMM).
    Persistent,
    /// Used by the bootloader.
    Bootloader,
    /// Kernel image.
    Kernel,
}

impl MemRegionType {
    /// Returns true if this region is usable as general RAM.
    pub fn is_usable(self) -> bool {
        matches!(self, MemRegionType::Usable | MemRegionType::AcpiReclaimable)
    }

    /// Returns a human-readable name.
    pub fn as_str(self) -> &'static str {
        match self {
            MemRegionType::Usable => "Usable",
            MemRegionType::Reserved => "Reserved",
            MemRegionType::AcpiReclaimable => "ACPI Reclaimable",
            MemRegionType::AcpiNvs => "ACPI NVS",
            MemRegionType::BadMemory => "Bad Memory",
            MemRegionType::Persistent => "Persistent",
            MemRegionType::Bootloader => "Bootloader",
            MemRegionType::Kernel => "Kernel",
        }
    }
}

// -------------------------------------------------------------------
// MemRegion
// -------------------------------------------------------------------

/// A single physical memory region.
#[derive(Debug, Clone, Copy)]
pub struct MemRegion {
    /// Start physical address.
    pub start: u64,
    /// End physical address (exclusive).
    pub end: u64,
    /// Region type.
    pub region_type: MemRegionType,
}

impl MemRegion {
    /// Creates a new memory region.
    pub fn new(start: u64, end: u64, region_type: MemRegionType) -> Self {
        Self {
            start,
            end,
            region_type,
        }
    }

    /// Returns the size of the region in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Returns the size in pages.
    pub fn nr_pages(&self) -> u64 {
        self.size() / PAGE_SIZE
    }

    /// Checks if an address falls within this region.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Checks if two regions overlap.
    pub fn overlaps(&self, other: &MemRegion) -> bool {
        self.start < other.end && other.start < self.end
    }
}

impl Default for MemRegion {
    fn default() -> Self {
        Self {
            start: 0,
            end: 0,
            region_type: MemRegionType::Reserved,
        }
    }
}

// -------------------------------------------------------------------
// BootMemMap
// -------------------------------------------------------------------

/// The complete boot memory map.
///
/// Populated from the bootloader's E820 table or UEFI memory map.
pub struct BootMemMap {
    /// Memory regions.
    regions: [MemRegion; MAX_MEM_REGIONS],
    /// Number of valid regions.
    nr_regions: usize,
    /// Reserved regions (kernel, initrd, etc.).
    reserved: [MemRegion; MAX_RESERVED],
    /// Number of reserved regions.
    nr_reserved: usize,
}

impl BootMemMap {
    /// Creates a new empty memory map.
    pub fn new() -> Self {
        Self {
            regions: [MemRegion::default(); MAX_MEM_REGIONS],
            nr_regions: 0,
            reserved: [MemRegion::default(); MAX_RESERVED],
            nr_reserved: 0,
        }
    }

    /// Adds a region to the memory map.
    pub fn add_region(&mut self, start: u64, end: u64, region_type: MemRegionType) -> Result<()> {
        if self.nr_regions >= MAX_MEM_REGIONS {
            return Err(Error::OutOfMemory);
        }
        if start >= end {
            return Err(Error::InvalidArgument);
        }
        self.regions[self.nr_regions] = MemRegion::new(start, end, region_type);
        self.nr_regions += 1;
        Ok(())
    }

    /// Reserves a region (marks it as unavailable for allocation).
    pub fn reserve_region(
        &mut self,
        start: u64,
        end: u64,
        region_type: MemRegionType,
    ) -> Result<()> {
        if self.nr_reserved >= MAX_RESERVED {
            return Err(Error::OutOfMemory);
        }
        self.reserved[self.nr_reserved] = MemRegion::new(start, end, region_type);
        self.nr_reserved += 1;
        Ok(())
    }

    /// Returns all regions.
    pub fn regions(&self) -> &[MemRegion] {
        &self.regions[..self.nr_regions]
    }

    /// Returns reserved regions.
    pub fn reserved(&self) -> &[MemRegion] {
        &self.reserved[..self.nr_reserved]
    }

    /// Returns the number of regions.
    pub fn nr_regions(&self) -> usize {
        self.nr_regions
    }

    /// Returns total usable memory in bytes.
    pub fn total_usable(&self) -> u64 {
        self.regions[..self.nr_regions]
            .iter()
            .filter(|r| r.region_type.is_usable())
            .map(|r| r.size())
            .sum()
    }

    /// Returns total reserved memory in bytes.
    pub fn total_reserved(&self) -> u64 {
        self.reserved[..self.nr_reserved]
            .iter()
            .map(|r| r.size())
            .sum()
    }

    /// Checks if an address is reserved.
    pub fn is_reserved(&self, addr: u64) -> bool {
        self.reserved[..self.nr_reserved]
            .iter()
            .any(|r| r.contains(addr))
    }

    /// Returns the highest usable physical address.
    pub fn max_phys_addr(&self) -> u64 {
        self.regions[..self.nr_regions]
            .iter()
            .filter(|r| r.region_type.is_usable())
            .map(|r| r.end)
            .max()
            .unwrap_or(0)
    }

    /// Finds the first usable region at or above the given address.
    pub fn find_usable_above(&self, min_addr: u64) -> Option<&MemRegion> {
        self.regions[..self.nr_regions]
            .iter()
            .find(|r| r.region_type.is_usable() && r.end > min_addr)
    }

    /// Sorts regions by start address (insertion sort).
    pub fn sort_by_addr(&mut self) {
        for i in 1..self.nr_regions {
            let mut j = i;
            while j > 0 && self.regions[j].start < self.regions[j - 1].start {
                self.regions.swap(j, j - 1);
                j -= 1;
            }
        }
    }
}

impl Default for BootMemMap {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// EarlyAllocator
// -------------------------------------------------------------------

/// Bump allocator for early boot memory allocation.
///
/// Used before the buddy allocator is initialized. Allocations are
/// sequential and cannot be individually freed.
pub struct EarlyAllocator {
    /// Arena start address.
    arena_start: u64,
    /// Arena end address.
    arena_end: u64,
    /// Current allocation pointer (bump).
    cursor: u64,
    /// Number of allocations made.
    nr_allocs: u64,
    /// Total bytes allocated.
    bytes_allocated: u64,
    /// Whether the allocator is active.
    active: bool,
}

impl EarlyAllocator {
    /// Creates a new early allocator at the given address.
    pub fn new(arena_start: u64, arena_size: u64) -> Self {
        Self {
            arena_start,
            arena_end: arena_start + arena_size,
            cursor: arena_start,
            nr_allocs: 0,
            bytes_allocated: 0,
            active: true,
        }
    }

    /// Allocates memory from the bump arena.
    pub fn early_alloc(&mut self, size: u64, align: u64) -> Result<u64> {
        if !self.active {
            return Err(Error::InvalidArgument);
        }
        if size == 0 {
            return Err(Error::InvalidArgument);
        }

        let align = align.max(EARLY_ALLOC_ALIGN);
        // Align the cursor up.
        let aligned = (self.cursor + align - 1) & !(align - 1);
        let end = aligned + size;

        if end > self.arena_end {
            return Err(Error::OutOfMemory);
        }

        self.cursor = end;
        self.nr_allocs += 1;
        self.bytes_allocated += size;
        Ok(aligned)
    }

    /// Allocates a page-aligned region.
    pub fn alloc_pages(&mut self, nr_pages: u64) -> Result<u64> {
        self.early_alloc(nr_pages * PAGE_SIZE, PAGE_SIZE)
    }

    /// Returns the remaining space.
    pub fn remaining(&self) -> u64 {
        self.arena_end.saturating_sub(self.cursor)
    }

    /// Returns total bytes allocated.
    pub fn bytes_allocated(&self) -> u64 {
        self.bytes_allocated
    }

    /// Returns the number of allocations.
    pub fn nr_allocs(&self) -> u64 {
        self.nr_allocs
    }

    /// Returns the usage percentage (0-100).
    pub fn usage_pct(&self) -> u64 {
        let total = self.arena_end - self.arena_start;
        if total == 0 {
            return 0;
        }
        self.bytes_allocated * 100 / total
    }

    /// Deactivates the allocator (buddy is ready).
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Returns whether the allocator is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

// -------------------------------------------------------------------
// MemInitStats
// -------------------------------------------------------------------

/// Memory initialization statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemInitStats {
    /// Total physical memory detected (bytes).
    pub total_detected: u64,
    /// Total usable memory (bytes).
    pub total_usable: u64,
    /// Total reserved memory (bytes).
    pub total_reserved: u64,
    /// Number of memory regions.
    pub nr_regions: u32,
    /// Number of reserved regions.
    pub nr_reserved: u32,
    /// Highest physical address.
    pub max_phys_addr: u64,
    /// Early allocator bytes used.
    pub early_alloc_used: u64,
}

// -------------------------------------------------------------------
// init_memory_map
// -------------------------------------------------------------------

/// Initializes the memory map from bootloader-provided data.
///
/// Takes raw region entries (start, end, type) and builds a
/// [`BootMemMap`] with sorted, validated regions.
pub fn init_memory_map(entries: &[(u64, u64, u32)]) -> Result<BootMemMap> {
    let mut map = BootMemMap::new();

    for &(start, end, raw_type) in entries {
        let region_type = match raw_type {
            1 => MemRegionType::Usable,
            2 => MemRegionType::Reserved,
            3 => MemRegionType::AcpiReclaimable,
            4 => MemRegionType::AcpiNvs,
            5 => MemRegionType::BadMemory,
            _ => MemRegionType::Reserved,
        };
        map.add_region(start, end, region_type)?;
    }

    map.sort_by_addr();
    Ok(map)
}

/// Collects initialization statistics from a memory map.
pub fn collect_init_stats(map: &BootMemMap, early: &EarlyAllocator) -> MemInitStats {
    MemInitStats {
        total_detected: map.regions().iter().map(|r| r.size()).sum(),
        total_usable: map.total_usable(),
        total_reserved: map.total_reserved(),
        nr_regions: map.nr_regions() as u32,
        nr_reserved: map.reserved().len() as u32,
        max_phys_addr: map.max_phys_addr(),
        early_alloc_used: early.bytes_allocated(),
    }
}
