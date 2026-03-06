// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Boot-time memory reservation subsystem.
//!
//! Provides a simple linear allocator used during early kernel initialization,
//! before the main page allocator and slab cache are online. Memory regions
//! are reserved with `reserve()` and allocated with `alloc()`. Once the
//! permanent allocator is ready, all bootmem allocations are handed off via
//! `convert()`.
//!
//! This is conceptually equivalent to the `bootmem` and early `memblock`
//! reservation layers in Linux.
//!
//! # Lifecycle
//!
//! ```text
//! [early boot]  BootmemAllocator::new()   — empty, uninitialized
//!                    ↓
//!               add_region()             — register physical memory regions
//!                    ↓
//!               reserve()               — mark ranges used by firmware/ACPI/initrd
//!                    ↓
//!               alloc()                 — hand out memory to early boot consumers
//!                    ↓
//! [init done]   convert()               — mark allocator as finalized; handoff complete
//! ```
//!
//! # Key types
//!
//! - [`BootmemRegion`] — a single contiguous physical memory range
//! - [`BootmemReservation`] — a reserved sub-range within a region
//! - [`BootmemAllocator`] — the top-level early allocator
//! - [`BootmemStats`] — summary statistics

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of physical memory regions the allocator tracks.
pub const BOOTMEM_MAX_REGIONS: usize = 64;

/// Maximum number of explicit reservations (firmware, ACPI, initrd, etc.).
pub const BOOTMEM_MAX_RESERVATIONS: usize = 128;

/// Default allocation alignment in bytes (16-byte).
pub const BOOTMEM_DEFAULT_ALIGN: u64 = 16;

/// Page size used for page-aligned allocations.
pub const BOOTMEM_PAGE_SIZE: u64 = 4096;

/// Poison value written to freed/converted bootmem ranges (debug mode).
pub const BOOTMEM_POISON: u8 = 0xAB;

// -------------------------------------------------------------------
// BootmemRegionFlags
// -------------------------------------------------------------------

/// Flags describing a physical memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BootmemRegionFlags(u32);

impl BootmemRegionFlags {
    /// Conventional (usable) RAM.
    pub const USABLE: Self = Self(1 << 0);
    /// Reserved by firmware; cannot be used by the OS.
    pub const RESERVED: Self = Self(1 << 1);
    /// ACPI reclaimable memory.
    pub const ACPI_RECLAIMABLE: Self = Self(1 << 2);
    /// Non-volatile/persistent memory (NVDIMM).
    pub const PERSISTENT: Self = Self(1 << 3);
    /// High memory above the 4 GiB boundary.
    pub const HIGHMEM: Self = Self(1 << 4);

    /// Test whether a flag is set.
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set a flag.
    pub fn set(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

// -------------------------------------------------------------------
// BootmemRegion
// -------------------------------------------------------------------

/// A contiguous physical memory region discovered during early boot.
#[derive(Debug, Clone, Copy, Default)]
pub struct BootmemRegion {
    /// Physical start address (inclusive).
    pub base: u64,
    /// Physical end address (exclusive).
    pub end: u64,
    /// Region classification flags.
    pub flags: BootmemRegionFlags,
}

impl BootmemRegion {
    /// Construct a new region descriptor.
    pub const fn new(base: u64, end: u64, flags: BootmemRegionFlags) -> Self {
        Self { base, end, flags }
    }

    /// Return the size of the region in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.base)
    }

    /// Return `true` if the region contains the address range `[addr, addr+size)`.
    pub fn contains_range(&self, addr: u64, size: u64) -> bool {
        addr >= self.base && addr.saturating_add(size) <= self.end
    }

    /// Return `true` if the region overlaps with `[addr, addr+size)`.
    pub fn overlaps(&self, addr: u64, size: u64) -> bool {
        addr < self.end && addr.saturating_add(size) > self.base
    }
}

// -------------------------------------------------------------------
// BootmemReservation
// -------------------------------------------------------------------

/// An explicitly reserved physical address range.
#[derive(Debug, Clone, Copy, Default)]
pub struct BootmemReservation {
    /// Physical start of the reservation (inclusive).
    pub base: u64,
    /// Physical end of the reservation (exclusive).
    pub end: u64,
    /// Human-readable label for debugging.
    pub label: &'static str,
}

impl BootmemReservation {
    /// Create a new reservation.
    pub const fn new(base: u64, end: u64, label: &'static str) -> Self {
        Self { base, end, label }
    }

    /// Return the size in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.base)
    }

    /// Return `true` if this reservation overlaps the range `[addr, addr+size)`.
    pub fn overlaps(&self, addr: u64, size: u64) -> bool {
        addr < self.end && addr.saturating_add(size) > self.base
    }
}

// -------------------------------------------------------------------
// BootmemStats
// -------------------------------------------------------------------

/// Summary statistics for the boot-time allocator.
#[derive(Debug, Clone, Copy, Default)]
pub struct BootmemStats {
    /// Total usable memory registered (bytes).
    pub total_bytes: u64,
    /// Total memory reserved (bytes).
    pub reserved_bytes: u64,
    /// Total memory allocated by `alloc()` calls (bytes).
    pub allocated_bytes: u64,
    /// Number of `alloc()` calls made.
    pub alloc_count: u64,
    /// Number of regions registered.
    pub region_count: u32,
    /// Number of explicit reservations.
    pub reservation_count: u32,
}

impl BootmemStats {
    /// Return the number of free bytes (usable minus reserved minus allocated).
    pub fn free_bytes(&self) -> u64 {
        self.total_bytes
            .saturating_sub(self.reserved_bytes)
            .saturating_sub(self.allocated_bytes)
    }
}

// -------------------------------------------------------------------
// BootmemAllocState
// -------------------------------------------------------------------

/// Lifecycle state of the boot-time allocator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BootmemAllocState {
    /// Not yet initialized; no regions have been added.
    #[default]
    Uninitialized,
    /// Regions have been registered; allocation is active.
    Active,
    /// Allocation is complete; the allocator has been handed off.
    Converted,
}

// -------------------------------------------------------------------
// BootmemAllocator
// -------------------------------------------------------------------

/// Early boot-time physical memory allocator.
///
/// Uses a simple bump-pointer strategy within the first suitable free
/// region. Once `convert()` is called, no further allocations are
/// permitted.
#[derive(Debug)]
pub struct BootmemAllocator {
    /// Registered physical memory regions.
    regions: [BootmemRegion; BOOTMEM_MAX_REGIONS],
    /// Number of valid entries in `regions`.
    region_count: usize,
    /// Explicit firmware/ACPI/initrd reservations.
    reservations: [BootmemReservation; BOOTMEM_MAX_RESERVATIONS],
    /// Number of valid entries in `reservations`.
    reservation_count: usize,
    /// Bump pointer: next physical address to allocate.
    bump: u64,
    /// Current allocator lifecycle state.
    state: BootmemAllocState,
    /// Aggregate statistics.
    stats: BootmemStats,
}

impl BootmemAllocator {
    /// Create an empty, uninitialized allocator.
    pub const fn new() -> Self {
        Self {
            regions: [BootmemRegion {
                base: 0,
                end: 0,
                flags: BootmemRegionFlags(0),
            }; BOOTMEM_MAX_REGIONS],
            region_count: 0,
            reservations: [BootmemReservation {
                base: 0,
                end: 0,
                label: "",
            }; BOOTMEM_MAX_RESERVATIONS],
            reservation_count: 0,
            bump: 0,
            state: BootmemAllocState::Uninitialized,
            stats: BootmemStats {
                total_bytes: 0,
                reserved_bytes: 0,
                allocated_bytes: 0,
                alloc_count: 0,
                region_count: 0,
                reservation_count: 0,
            },
        }
    }

    /// Register a physical memory region.
    ///
    /// Must be called before `alloc()`. Regions may be added in any order;
    /// the allocator searches from the lowest base address.
    pub fn add_region(&mut self, base: u64, end: u64, flags: BootmemRegionFlags) -> Result<()> {
        if self.state == BootmemAllocState::Converted {
            return Err(Error::PermissionDenied);
        }
        if self.region_count >= BOOTMEM_MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }
        if end <= base {
            return Err(Error::InvalidArgument);
        }
        self.regions[self.region_count] = BootmemRegion::new(base, end, flags);
        self.region_count += 1;
        if flags.contains(BootmemRegionFlags::USABLE) {
            self.stats.total_bytes += end - base;
            self.stats.region_count += 1;
        }
        if self.state == BootmemAllocState::Uninitialized {
            self.state = BootmemAllocState::Active;
            // Initialize bump pointer to the start of the first usable region.
            self.bump = base;
        }
        Ok(())
    }

    /// Mark a physical range as reserved (unavailable for allocation).
    pub fn reserve(&mut self, base: u64, end: u64, label: &'static str) -> Result<()> {
        if self.state == BootmemAllocState::Converted {
            return Err(Error::PermissionDenied);
        }
        if self.reservation_count >= BOOTMEM_MAX_RESERVATIONS {
            return Err(Error::OutOfMemory);
        }
        if end <= base {
            return Err(Error::InvalidArgument);
        }
        self.reservations[self.reservation_count] = BootmemReservation::new(base, end, label);
        self.reservation_count += 1;
        self.stats.reserved_bytes += end - base;
        self.stats.reservation_count += 1;
        Ok(())
    }

    /// Allocate `size` bytes of physical memory aligned to `align`.
    ///
    /// Returns the physical base address of the allocation, or an error
    /// if the request cannot be satisfied.
    pub fn alloc_aligned(&mut self, size: u64, align: u64) -> Result<u64> {
        if self.state != BootmemAllocState::Active {
            return Err(Error::PermissionDenied);
        }
        if size == 0 || align == 0 || (align & (align - 1)) != 0 {
            return Err(Error::InvalidArgument);
        }

        // Search each usable region for a suitable gap.
        for i in 0..self.region_count {
            let region = &self.regions[i];
            if !region.flags.contains(BootmemRegionFlags::USABLE) {
                continue;
            }
            let start = (region.base.max(self.bump) + align - 1) & !(align - 1);
            if start + size > region.end {
                continue;
            }
            // Check that this range does not overlap any reservation.
            if self.is_reserved(start, size) {
                continue;
            }
            // Allocation found.
            self.bump = start + size;
            self.stats.allocated_bytes += size;
            self.stats.alloc_count += 1;
            return Ok(start);
        }
        Err(Error::OutOfMemory)
    }

    /// Allocate `size` bytes with default alignment.
    pub fn alloc(&mut self, size: u64) -> Result<u64> {
        self.alloc_aligned(size, BOOTMEM_DEFAULT_ALIGN)
    }

    /// Allocate page-aligned physical memory.
    pub fn alloc_pages(&mut self, n_pages: u64) -> Result<u64> {
        self.alloc_aligned(n_pages * BOOTMEM_PAGE_SIZE, BOOTMEM_PAGE_SIZE)
    }

    /// Mark the allocator as converted.
    ///
    /// After this call, `alloc()` and `reserve()` will return errors.
    /// The caller is responsible for handing all allocated ranges to the
    /// permanent memory allocator.
    pub fn convert(&mut self) -> Result<()> {
        if self.state != BootmemAllocState::Active {
            return Err(Error::InvalidArgument);
        }
        self.state = BootmemAllocState::Converted;
        Ok(())
    }

    /// Return the current allocator state.
    pub fn state(&self) -> BootmemAllocState {
        self.state
    }

    /// Return a snapshot of allocator statistics.
    pub fn stats(&self) -> &BootmemStats {
        &self.stats
    }

    /// Iterate over registered regions (up to `region_count`).
    pub fn regions(&self) -> &[BootmemRegion] {
        &self.regions[..self.region_count]
    }

    /// Iterate over reservations (up to `reservation_count`).
    pub fn reservations(&self) -> &[BootmemReservation] {
        &self.reservations[..self.reservation_count]
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Returns `true` if the range `[base, base+size)` overlaps any reservation.
    fn is_reserved(&self, base: u64, size: u64) -> bool {
        self.reservations[..self.reservation_count]
            .iter()
            .any(|r| r.overlaps(base, size))
    }
}

impl Default for BootmemAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_allocator() -> BootmemAllocator {
        let mut a = BootmemAllocator::new();
        a.add_region(0x10_0000, 0x200_0000, BootmemRegionFlags::USABLE)
            .unwrap();
        a
    }

    #[test]
    fn test_basic_alloc() {
        let mut a = make_allocator();
        let addr = a.alloc(64).unwrap();
        assert!(addr >= 0x10_0000);
        assert_eq!(a.stats().alloc_count, 1);
    }

    #[test]
    fn test_alignment() {
        let mut a = make_allocator();
        let addr = a.alloc_aligned(128, 4096).unwrap();
        assert_eq!(addr % 4096, 0);
    }

    #[test]
    fn test_reserve_blocks_alloc() {
        let mut a = make_allocator();
        // Reserve the first 1 MiB of the region.
        a.reserve(0x10_0000, 0x20_0000, "test").unwrap();
        let addr = a.alloc(64).unwrap();
        // Should be allocated after the reservation.
        assert!(addr >= 0x20_0000);
    }

    #[test]
    fn test_convert_blocks_further_allocs() {
        let mut a = make_allocator();
        a.convert().unwrap();
        assert!(a.alloc(64).is_err());
    }
}
