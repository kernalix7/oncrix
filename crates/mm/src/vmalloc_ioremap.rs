// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! vmalloc-based I/O remapping.
//!
//! Manages ioremap allocations that use the vmalloc address space
//! to map device MMIO regions into kernel virtual addresses. Handles
//! caching attributes, guard pages, and resource tracking.
//!
//! - [`IoremapType`] — I/O mapping cache type
//! - [`IoremapRegion`] — a mapped I/O region
//! - [`IoremapStats`] — mapping statistics
//! - [`VmallocIoremap`] — the ioremap manager
//!
//! Reference: Linux `mm/vmalloc.c` (ioremap paths), `arch/x86/mm/ioremap.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum I/O regions.
const MAX_REGIONS: usize = 128;

/// Ioremap virtual space start.
const IOREMAP_START: u64 = 0xFFFF_F000_0000_0000;

// -------------------------------------------------------------------
// IoremapType
// -------------------------------------------------------------------

/// I/O mapping cache type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IoremapType {
    /// Uncacheable (UC).
    #[default]
    Uncacheable,
    /// Write-combining (WC).
    WriteCombining,
    /// Write-through (WT).
    WriteThrough,
    /// Write-back (WB) — rare for MMIO.
    WriteBack,
    /// Encrypted (for SEV/TDX).
    Encrypted,
}

impl IoremapType {
    /// Returns the PTE cache flags.
    pub fn pte_flags(self) -> u64 {
        match self {
            Self::Uncacheable => 0x18,    // PCD | PWT
            Self::WriteCombining => 0x10, // PCD
            Self::WriteThrough => 0x08,   // PWT
            Self::WriteBack => 0x00,
            Self::Encrypted => 0x8000_0000_0000_0018, // enc + UC
        }
    }
}

// -------------------------------------------------------------------
// IoremapRegion
// -------------------------------------------------------------------

/// A mapped I/O region.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoremapRegion {
    /// Virtual address.
    pub vaddr: u64,
    /// Physical address.
    pub paddr: u64,
    /// Size in bytes.
    pub size: u64,
    /// Cache type.
    pub cache_type: IoremapType,
    /// Whether this region is active.
    pub active: bool,
}

impl IoremapRegion {
    /// Creates a new I/O region.
    pub fn new(vaddr: u64, paddr: u64, size: u64, cache_type: IoremapType) -> Self {
        Self {
            vaddr,
            paddr,
            size,
            cache_type,
            active: true,
        }
    }

    /// Returns the virtual end address.
    pub fn vend(&self) -> u64 {
        self.vaddr.saturating_add(self.size)
    }

    /// Returns the physical end address.
    pub fn pend(&self) -> u64 {
        self.paddr.saturating_add(self.size)
    }

    /// Returns `true` if the region overlaps the given physical range.
    pub fn overlaps_phys(&self, paddr: u64, size: u64) -> bool {
        self.active && self.paddr < paddr.saturating_add(size) && paddr < self.pend()
    }
}

// -------------------------------------------------------------------
// IoremapStats
// -------------------------------------------------------------------

/// I/O remapping statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoremapStats {
    /// Total ioremap calls.
    pub maps: u64,
    /// Total iounmap calls.
    pub unmaps: u64,
    /// Total bytes mapped.
    pub bytes_mapped: u64,
    /// Total bytes unmapped.
    pub bytes_unmapped: u64,
    /// Failed ioremap attempts.
    pub map_failures: u64,
    /// Current active regions.
    pub active_regions: u64,
}

impl IoremapStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// VmallocIoremap
// -------------------------------------------------------------------

/// The vmalloc-based ioremap manager.
pub struct VmallocIoremap {
    /// Tracked I/O regions.
    regions: [IoremapRegion; MAX_REGIONS],
    /// Number of regions.
    count: usize,
    /// Next virtual address.
    next_vaddr: u64,
    /// Statistics.
    stats: IoremapStats,
}

impl Default for VmallocIoremap {
    fn default() -> Self {
        Self {
            regions: [IoremapRegion::default(); MAX_REGIONS],
            count: 0,
            next_vaddr: IOREMAP_START,
            stats: IoremapStats::default(),
        }
    }
}

impl VmallocIoremap {
    /// Creates a new ioremap manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Maps a physical I/O region into virtual address space.
    pub fn ioremap(&mut self, paddr: u64, size: u64, cache_type: IoremapType) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_REGIONS {
            self.stats.map_failures += 1;
            return Err(Error::OutOfMemory);
        }

        // Check for overlapping physical regions.
        for i in 0..self.count {
            if self.regions[i].overlaps_phys(paddr, size) {
                return Err(Error::AlreadyExists);
            }
        }

        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let vaddr = self.next_vaddr;
        self.next_vaddr = self
            .next_vaddr
            .saturating_add(aligned_size)
            .saturating_add(PAGE_SIZE); // guard page

        let idx = self.count;
        self.regions[idx] = IoremapRegion::new(vaddr, paddr, aligned_size, cache_type);
        self.count += 1;

        self.stats.maps += 1;
        self.stats.bytes_mapped += aligned_size;
        self.stats.active_regions += 1;
        Ok(vaddr)
    }

    /// Unmaps an I/O region by virtual address.
    pub fn iounmap(&mut self, vaddr: u64) -> Result<()> {
        for i in 0..self.count {
            if self.regions[i].active && self.regions[i].vaddr == vaddr {
                self.stats.bytes_unmapped += self.regions[i].size;
                self.regions[i].active = false;
                self.stats.unmaps += 1;
                if self.stats.active_regions > 0 {
                    self.stats.active_regions -= 1;
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Looks up a region by virtual address.
    pub fn find_by_vaddr(&self, vaddr: u64) -> Option<&IoremapRegion> {
        for i in 0..self.count {
            if self.regions[i].active
                && vaddr >= self.regions[i].vaddr
                && vaddr < self.regions[i].vend()
            {
                return Some(&self.regions[i]);
            }
        }
        None
    }

    /// Looks up a region by physical address.
    pub fn find_by_paddr(&self, paddr: u64) -> Option<&IoremapRegion> {
        for i in 0..self.count {
            if self.regions[i].active
                && paddr >= self.regions[i].paddr
                && paddr < self.regions[i].pend()
            {
                return Some(&self.regions[i]);
            }
        }
        None
    }

    /// Returns the number of regions.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &IoremapStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
