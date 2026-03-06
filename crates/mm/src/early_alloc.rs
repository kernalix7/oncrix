// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Early boot memory allocator (bump allocator).
//!
//! During early boot, before the slab allocator and buddy system are
//! initialized, the kernel needs a simple way to allocate memory for
//! page tables, per-CPU areas, and initial data structures. This
//! module provides a bump (linear) allocator that operates on regions
//! of physical memory reported by firmware (E820, UEFI memory map).
//!
//! # Design
//!
//! The early allocator manages up to 8 memory regions. Allocation is
//! a simple bump-pointer operation: the pointer advances forward by
//! the requested size (aligned). Deallocation is a no-op (bump
//! allocators cannot free individual allocations).
//!
//! Two additional operations support the memblock pattern:
//! - `memblock_add(base, size)`: register a usable memory region
//! - `memblock_reserve(base, size)`: mark a region as reserved
//!   (kernel image, initrd, ACPI tables, etc.)
//!
//! Once the slab/buddy allocator is ready, `early_alloc_done()` freezes
//! the early allocator, preventing further early allocations and
//! allowing the remaining free memory to be handed off.
//!
//! # Subsystems
//!
//! - [`EarlyAllocRegion`] — a single memory region descriptor
//! - [`EarlyReservedRegion`] — a reserved (claimed) region
//! - [`EarlyAllocator`] — the bump allocator engine
//! - [`EarlyAllocStats`] — allocation statistics
//!
//! Reference: Linux `mm/memblock.c`, `arch/x86/kernel/e820.c`,
//! early boot memory initialization.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of memory regions the early allocator can manage.
const MAX_REGIONS: usize = 8;

/// Maximum number of reserved regions.
const MAX_RESERVED: usize = 32;

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Minimum allocation alignment (8 bytes).
const MIN_ALIGN: u64 = 8;

/// Maximum allocation alignment (2 MiB — huge page).
const MAX_ALIGN: u64 = 2 * 1024 * 1024;

/// Watermark: warn when a region is this percentage full.
const DEFAULT_WATERMARK_PERCENT: u64 = 90;

// -------------------------------------------------------------------
// EarlyAllocRegion
// -------------------------------------------------------------------

/// A single usable memory region for early allocation.
///
/// Tracks a contiguous block of physical memory with a bump pointer
/// (`used` field) indicating how much has been consumed.
#[derive(Debug, Clone, Copy)]
pub struct EarlyAllocRegion {
    /// Base physical address of the region.
    pub base: u64,
    /// Total size of the region in bytes.
    pub size: u64,
    /// Number of bytes already allocated from this region.
    pub used: u64,
    /// Number of bytes wasted due to alignment padding.
    pub wasted_alignment: u64,
    /// Number of individual allocations from this region.
    pub alloc_count: u32,
    /// NUMA node this region belongs to.
    pub nid: u8,
    /// Whether this region slot is in use.
    pub active: bool,
}

impl EarlyAllocRegion {
    /// Create an empty (unused) region.
    const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            used: 0,
            wasted_alignment: 0,
            alloc_count: 0,
            nid: 0,
            active: false,
        }
    }

    /// Remaining free bytes in this region.
    pub const fn remaining(&self) -> u64 {
        if self.size > self.used {
            self.size - self.used
        } else {
            0
        }
    }

    /// Usage percentage (0..100).
    pub const fn usage_percent(&self) -> u64 {
        if self.size == 0 {
            return 0;
        }
        self.used * 100 / self.size
    }

    /// Whether the region has exceeded the watermark.
    pub const fn above_watermark(&self) -> bool {
        self.usage_percent() >= DEFAULT_WATERMARK_PERCENT
    }

    /// End address (exclusive) of the region.
    pub const fn end(&self) -> u64 {
        self.base + self.size
    }

    /// Current allocation pointer (next available address).
    pub const fn current_ptr(&self) -> u64 {
        self.base + self.used
    }

    /// Attempt to allocate `size` bytes with `align` alignment.
    ///
    /// Returns the physical address of the allocation on success.
    pub fn alloc(&mut self, alloc_size: u64, align: u64) -> Result<u64> {
        if alloc_size == 0 {
            return Err(Error::InvalidArgument);
        }

        let align = normalize_alignment(align);
        let current = self.base + self.used;

        // Align up.
        let aligned = align_up(current, align);
        let padding = aligned - current;

        // Check if the allocation fits.
        let total_needed = padding + alloc_size;
        if self.used + total_needed > self.size {
            return Err(Error::OutOfMemory);
        }

        self.used += total_needed;
        self.wasted_alignment += padding;
        self.alloc_count += 1;

        Ok(aligned)
    }

    /// Check if a given address range overlaps with this region.
    pub const fn overlaps(&self, addr: u64, len: u64) -> bool {
        let r_end = self.base + self.size;
        let a_end = addr + len;
        self.base < a_end && addr < r_end
    }
}

// -------------------------------------------------------------------
// EarlyReservedRegion
// -------------------------------------------------------------------

/// A reserved memory region (not available for allocation).
///
/// Tracks regions that are claimed by the kernel image, initrd,
/// ACPI tables, device firmware, or early allocations.
#[derive(Debug, Clone, Copy)]
pub struct EarlyReservedRegion {
    /// Base physical address.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    /// Description tag for debugging.
    pub tag: [u8; 16],
    /// Number of valid bytes in `tag`.
    pub tag_len: usize,
    /// Whether this slot is in use.
    pub active: bool,
}

impl EarlyReservedRegion {
    /// Create an empty reserved region.
    const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            tag: [0u8; 16],
            tag_len: 0,
            active: false,
        }
    }

    /// End address (exclusive).
    pub const fn end(&self) -> u64 {
        self.base + self.size
    }

    /// Whether a given address range overlaps with this reservation.
    pub const fn overlaps(&self, addr: u64, len: u64) -> bool {
        let r_end = self.base + self.size;
        let a_end = addr + len;
        self.base < a_end && addr < r_end
    }
}

// -------------------------------------------------------------------
// EarlyAllocStats
// -------------------------------------------------------------------

/// Early allocator statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct EarlyAllocStats {
    /// Total bytes allocated.
    pub total_allocated: u64,
    /// Total number of regions registered.
    pub total_regions: u32,
    /// Peak total usage across all regions.
    pub peak_usage: u64,
    /// Total bytes wasted due to alignment padding.
    pub wasted_alignment: u64,
    /// Total number of individual allocations.
    pub total_alloc_count: u64,
    /// Total number of reserved regions.
    pub total_reserved: u32,
    /// Total reserved bytes.
    pub total_reserved_bytes: u64,
    /// Total available bytes across all regions.
    pub total_available: u64,
    /// Whether the allocator has been frozen.
    pub frozen: bool,
}

impl EarlyAllocStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_allocated: 0,
            total_regions: 0,
            peak_usage: 0,
            wasted_alignment: 0,
            total_alloc_count: 0,
            total_reserved: 0,
            total_reserved_bytes: 0,
            total_available: 0,
            frozen: false,
        }
    }

    /// Allocation efficiency (allocated / (allocated + wasted)) * 100.
    pub const fn efficiency_percent(&self) -> u64 {
        let total = self.total_allocated + self.wasted_alignment;
        if total == 0 {
            return 100;
        }
        self.total_allocated * 100 / total
    }
}

// -------------------------------------------------------------------
// EarlyAllocator
// -------------------------------------------------------------------

/// Early boot bump allocator.
///
/// Manages up to 8 memory regions with simple bump-pointer allocation.
/// Once the main allocator is ready, call `early_alloc_done()` to
/// freeze this allocator.
pub struct EarlyAllocator {
    /// Usable memory regions.
    regions: [EarlyAllocRegion; MAX_REGIONS],
    /// Reserved memory regions.
    reserved: [EarlyReservedRegion; MAX_RESERVED],
    /// Index of the current (preferred) region for allocation.
    current_region: usize,
    /// Number of active regions.
    nr_regions: usize,
    /// Number of active reserved regions.
    nr_reserved: usize,
    /// Aggregate statistics.
    stats: EarlyAllocStats,
    /// Whether the allocator has been initialized.
    initialized: bool,
    /// Whether the allocator has been frozen (no more allocations).
    frozen: bool,
    /// Watermark percentage for region exhaustion warnings.
    watermark_percent: u64,
}

impl EarlyAllocator {
    /// Create a new uninitialized early allocator.
    pub fn new() -> Self {
        Self {
            regions: [const { EarlyAllocRegion::empty() }; MAX_REGIONS],
            reserved: [const { EarlyReservedRegion::empty() }; MAX_RESERVED],
            current_region: 0,
            nr_regions: 0,
            nr_reserved: 0,
            stats: EarlyAllocStats::new(),
            initialized: false,
            frozen: false,
            watermark_percent: DEFAULT_WATERMARK_PERCENT,
        }
    }

    /// Initialize the early allocator.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Whether the allocator is initialized.
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Whether the allocator has been frozen.
    pub const fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Current statistics.
    pub const fn stats(&self) -> &EarlyAllocStats {
        &self.stats
    }

    /// Number of active regions.
    pub const fn nr_regions(&self) -> usize {
        self.nr_regions
    }

    /// Number of reserved regions.
    pub const fn nr_reserved(&self) -> usize {
        self.nr_reserved
    }

    /// Add a usable memory region (`memblock_add` equivalent).
    ///
    /// Registers a region of physical memory as available for early
    /// allocation. The region must not overlap with existing regions.
    pub fn memblock_add(&mut self, base: u64, size: u64) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if self.frozen {
            return Err(Error::Busy);
        }
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.nr_regions >= MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }

        // Check for overlap with existing regions.
        for region in self.regions.iter().take(MAX_REGIONS) {
            if region.active && region.overlaps(base, size) {
                return Err(Error::AlreadyExists);
            }
        }

        // Find a free slot.
        let slot = self.regions.iter().position(|r| !r.active);
        let slot = match slot {
            Some(s) => s,
            None => return Err(Error::OutOfMemory),
        };

        self.regions[slot] = EarlyAllocRegion {
            base,
            size,
            used: 0,
            wasted_alignment: 0,
            alloc_count: 0,
            nid: 0,
            active: true,
        };

        self.nr_regions += 1;
        self.stats.total_regions = self.nr_regions as u32;
        self.stats.total_available += size;

        Ok(())
    }

    /// Mark a memory range as reserved (`memblock_reserve` equivalent).
    ///
    /// Reserved regions are excluded from allocation. This is used to
    /// protect the kernel image, initrd, ACPI tables, etc.
    pub fn memblock_reserve(&mut self, base: u64, size: u64) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.nr_reserved >= MAX_RESERVED {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot.
        let slot = self.reserved.iter().position(|r| !r.active);
        let slot = match slot {
            Some(s) => s,
            None => return Err(Error::OutOfMemory),
        };

        self.reserved[slot] = EarlyReservedRegion {
            base,
            size,
            tag: [0u8; 16],
            tag_len: 0,
            active: true,
        };

        self.nr_reserved += 1;
        self.stats.total_reserved = self.nr_reserved as u32;
        self.stats.total_reserved_bytes += size;

        Ok(())
    }

    /// Mark a memory range as reserved with a descriptive tag.
    pub fn memblock_reserve_tagged(&mut self, base: u64, size: u64, tag_str: &[u8]) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.nr_reserved >= MAX_RESERVED {
            return Err(Error::OutOfMemory);
        }

        let slot = self.reserved.iter().position(|r| !r.active);
        let slot = match slot {
            Some(s) => s,
            None => return Err(Error::OutOfMemory),
        };

        let mut tag = [0u8; 16];
        let copy_len = if tag_str.len() > 16 {
            16
        } else {
            tag_str.len()
        };
        tag[..copy_len].copy_from_slice(&tag_str[..copy_len]);

        self.reserved[slot] = EarlyReservedRegion {
            base,
            size,
            tag,
            tag_len: copy_len,
            active: true,
        };

        self.nr_reserved += 1;
        self.stats.total_reserved = self.nr_reserved as u32;
        self.stats.total_reserved_bytes += size;

        Ok(())
    }

    /// Check if an address range overlaps with any reserved region.
    fn overlaps_reserved(&self, addr: u64, size: u64) -> bool {
        for res in &self.reserved {
            if res.active && res.overlaps(addr, size) {
                return true;
            }
        }
        false
    }

    /// Allocate `size` bytes with `align` alignment from the early pool.
    ///
    /// Tries the current region first, then falls back to other regions.
    /// Returns the physical address of the allocation.
    ///
    /// Deallocation is not supported (bump allocator). Use `early_free`
    /// as a no-op for API compatibility.
    pub fn early_alloc(&mut self, size: u64, align: u64) -> Result<u64> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if self.frozen {
            return Err(Error::Busy);
        }
        if size == 0 {
            return Err(Error::InvalidArgument);
        }

        let align = normalize_alignment(align);

        // Try current region first.
        if self.current_region < MAX_REGIONS && self.regions[self.current_region].active {
            let region = &self.regions[self.current_region];
            let current_ptr = region.current_ptr();
            let aligned_ptr = align_up(current_ptr, align);
            let padding = aligned_ptr - current_ptr;
            let total = padding + size;

            if region.remaining() >= total && !self.overlaps_reserved(aligned_ptr, size) {
                let addr = self.regions[self.current_region].alloc(size, align)?;
                self.update_stats_after_alloc(size, padding);
                return Ok(addr);
            }
        }

        // Fallback: try all other regions.
        for idx in 0..MAX_REGIONS {
            if idx == self.current_region {
                continue;
            }
            if !self.regions[idx].active {
                continue;
            }

            let region = &self.regions[idx];
            let current_ptr = region.current_ptr();
            let aligned_ptr = align_up(current_ptr, align);
            let padding = aligned_ptr - current_ptr;
            let total = padding + size;

            if region.remaining() >= total && !self.overlaps_reserved(aligned_ptr, size) {
                let addr = self.regions[idx].alloc(size, align)?;
                self.current_region = idx;
                self.update_stats_after_alloc(size, padding);
                return Ok(addr);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Free memory (no-op for bump allocator).
    ///
    /// Bump allocators do not support individual deallocation.
    /// This method exists for API compatibility and is a no-op.
    pub fn early_free(&self, _addr: u64, _size: u64) {
        // No-op: bump allocators cannot free individual allocations.
    }

    /// Allocate a page-aligned, page-sized block.
    pub fn early_alloc_page(&mut self) -> Result<u64> {
        self.early_alloc(PAGE_SIZE, PAGE_SIZE)
    }

    /// Allocate `n` contiguous pages.
    pub fn early_alloc_pages(&mut self, n: u64) -> Result<u64> {
        if n == 0 {
            return Err(Error::InvalidArgument);
        }
        self.early_alloc(n * PAGE_SIZE, PAGE_SIZE)
    }

    /// Freeze the early allocator.
    ///
    /// After this call, no further allocations are permitted.
    /// The remaining free memory can be handed off to the main
    /// allocator (buddy/bitmap).
    pub fn early_alloc_done(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if self.frozen {
            return Err(Error::AlreadyExists);
        }
        self.frozen = true;
        self.stats.frozen = true;
        Ok(())
    }

    /// Total remaining free bytes across all regions.
    pub fn total_remaining(&self) -> u64 {
        let mut total: u64 = 0;
        for region in &self.regions {
            if region.active {
                total += region.remaining();
            }
        }
        total
    }

    /// Total bytes used across all regions.
    pub fn total_used(&self) -> u64 {
        let mut total: u64 = 0;
        for region in &self.regions {
            if region.active {
                total += region.used;
            }
        }
        total
    }

    /// Total bytes available across all regions (capacity).
    pub fn total_capacity(&self) -> u64 {
        let mut total: u64 = 0;
        for region in &self.regions {
            if region.active {
                total += region.size;
            }
        }
        total
    }

    /// Get a reference to a region by index.
    pub fn region(&self, idx: usize) -> Result<&EarlyAllocRegion> {
        if idx >= MAX_REGIONS {
            return Err(Error::InvalidArgument);
        }
        if !self.regions[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.regions[idx])
    }

    /// Get a reference to a reserved region by index.
    pub fn reserved_region(&self, idx: usize) -> Result<&EarlyReservedRegion> {
        if idx >= MAX_RESERVED {
            return Err(Error::InvalidArgument);
        }
        if !self.reserved[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.reserved[idx])
    }

    /// Check if any region has exceeded the watermark.
    pub fn any_above_watermark(&self) -> bool {
        for region in &self.regions {
            if region.active && region.above_watermark() {
                return true;
            }
        }
        false
    }

    /// Get the remaining free ranges (for handoff to the main allocator).
    ///
    /// Returns an array of (base, size) pairs for each region's unused
    /// portion. Inactive entries have base=0, size=0.
    pub fn get_free_ranges(&self) -> [(u64, u64); MAX_REGIONS] {
        let mut ranges = [(0u64, 0u64); MAX_REGIONS];
        for (i, region) in self.regions.iter().enumerate() {
            if region.active && region.remaining() > 0 {
                ranges[i] = (region.current_ptr(), region.remaining());
            }
        }
        ranges
    }

    /// Update statistics after a successful allocation.
    fn update_stats_after_alloc(&mut self, size: u64, padding: u64) {
        self.stats.total_allocated += size;
        self.stats.wasted_alignment += padding;
        self.stats.total_alloc_count += 1;

        let used = self.total_used();
        if used > self.stats.peak_usage {
            self.stats.peak_usage = used;
        }
    }

    /// Validate the allocator state.
    ///
    /// Checks that no region's used exceeds its size and that reserved
    /// regions do not overlap with each other.
    pub fn validate(&self) -> Result<()> {
        // Check regions.
        for region in &self.regions {
            if region.active && region.used > region.size {
                return Err(Error::InvalidArgument);
            }
        }

        // Check reserved regions for overlap.
        for i in 0..MAX_RESERVED {
            if !self.reserved[i].active {
                continue;
            }
            for j in (i + 1)..MAX_RESERVED {
                if !self.reserved[j].active {
                    continue;
                }
                if self.reserved[i].overlaps(self.reserved[j].base, self.reserved[j].size) {
                    return Err(Error::InvalidArgument);
                }
            }
        }

        Ok(())
    }

    /// Set the watermark percentage.
    pub fn set_watermark(&mut self, percent: u64) -> Result<()> {
        if percent > 100 {
            return Err(Error::InvalidArgument);
        }
        self.watermark_percent = percent;
        Ok(())
    }

    /// Current watermark percentage setting.
    pub const fn watermark_percent(&self) -> u64 {
        self.watermark_percent
    }
}

impl Default for EarlyAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------

/// Align `addr` up to the next multiple of `align`.
///
/// `align` must be a power of two.
const fn align_up(addr: u64, align: u64) -> u64 {
    let mask = align - 1;
    (addr + mask) & !mask
}

/// Normalize alignment to a valid power-of-two value.
const fn normalize_alignment(align: u64) -> u64 {
    if align < MIN_ALIGN {
        return MIN_ALIGN;
    }
    if align > MAX_ALIGN {
        return MAX_ALIGN;
    }
    // Round up to next power of two.
    if align.count_ones() == 1 {
        align
    } else {
        1u64 << (64 - (align - 1).leading_zeros())
    }
}
