// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! vmalloc virtual area management.
//!
//! Manages virtually contiguous but physically non-contiguous memory
//! regions in the kernel address space. Each vmalloc area is backed
//! by individual page frames that may be scattered in physical
//! memory.
//!
//! # Types
//!
//! - [`VmallocAreaType`] — type of vmalloc region
//! - [`VmallocAreaFlags`] — area permission/attribute flags
//! - [`VmallocRegion`] — descriptor for one vmalloc region
//! - [`VmallocFreeHole`] — free hole in the virtual address space
//! - [`VmallocAreaManager`] — manages the vmalloc address space
//! - [`VmallocAreaStats`] — summary statistics
//! - [`VmallocLookupResult`] — result of an address lookup
//! - [`VmallocAreaSnapshot`] — point-in-time snapshot
//!
//! # Virtual Address Space Layout
//!
//! The vmalloc address range spans a large chunk of the kernel's
//! virtual address space. Each allocation occupies a contiguous
//! virtual range with a guard page appended for overflow detection.
//! Free holes between allocations are tracked for reuse.
//!
//! Reference: Linux `mm/vmalloc.c`, `include/linux/vmalloc.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Start of the vmalloc virtual address range.
const VMALLOC_START: u64 = 0xFFFF_C900_0000_0000;

/// End of the vmalloc virtual address range (exclusive).
const VMALLOC_END: u64 = 0xFFFF_E900_0000_0000;

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Guard page size after each vmalloc area.
const GUARD_SIZE: u64 = PAGE_SIZE;

/// Maximum number of vmalloc regions.
const MAX_REGIONS: usize = 512;

/// Maximum physical pages per region.
const MAX_PAGES_PER_REGION: usize = 128;

/// Maximum number of free holes tracked.
const MAX_FREE_HOLES: usize = 256;

/// Maximum number of page table entries per region.
const MAX_PTE_ENTRIES: usize = 128;

/// Maximum length of a caller tag.
const MAX_CALLER_TAG: usize = 32;

// -------------------------------------------------------------------
// VmallocAreaType
// -------------------------------------------------------------------

/// Type of vmalloc area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmallocAreaType {
    /// Standard vmalloc allocation.
    #[default]
    Vmalloc,
    /// IO remapping (ioremap).
    Ioremap,
    /// User-mappable vmalloc area.
    UserMap,
    /// Allocated by vmap (mapping existing pages).
    Vmap,
    /// Percpu vmalloc area.
    Percpu,
    /// Allocated for modules.
    Module,
}

// -------------------------------------------------------------------
// VmallocAreaFlags
// -------------------------------------------------------------------

/// Flags controlling vmalloc area properties.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmallocAreaFlags {
    /// Area is executable.
    pub executable: bool,
    /// Area is read-only.
    pub read_only: bool,
    /// Area uses uncacheable memory.
    pub uncacheable: bool,
    /// Area uses write-combining.
    pub write_combining: bool,
    /// Area should not be freed (permanent mapping).
    pub permanent: bool,
    /// Area has been lazily freed but not yet purged.
    pub lazy_freed: bool,
}

// -------------------------------------------------------------------
// VmallocRegion
// -------------------------------------------------------------------

/// Descriptor for a single vmalloc region.
#[derive(Clone)]
pub struct VmallocRegion {
    /// Unique region ID.
    pub id: u32,
    /// Virtual base address of this region.
    pub virt_base: u64,
    /// Total virtual size in bytes (excluding guard page).
    pub size: u64,
    /// Number of physical pages backing this region.
    pub nr_pages: usize,
    /// Physical page addresses (frame numbers).
    pub phys_pages: [u64; MAX_PAGES_PER_REGION],
    /// Region type.
    pub area_type: VmallocAreaType,
    /// Area flags.
    pub flags: VmallocAreaFlags,
    /// Whether this region is active.
    pub active: bool,
    /// Caller tag for debugging.
    pub caller_tag: [u8; MAX_CALLER_TAG],
    /// Length of the caller tag.
    pub caller_tag_len: usize,
}

impl VmallocRegion {
    /// Creates an empty, inactive region.
    const fn empty() -> Self {
        Self {
            id: 0,
            virt_base: 0,
            size: 0,
            nr_pages: 0,
            phys_pages: [0; MAX_PAGES_PER_REGION],
            area_type: VmallocAreaType::Vmalloc,
            flags: VmallocAreaFlags {
                executable: false,
                read_only: false,
                uncacheable: false,
                write_combining: false,
                permanent: false,
                lazy_freed: false,
            },
            active: false,
            caller_tag: [0; MAX_CALLER_TAG],
            caller_tag_len: 0,
        }
    }

    /// Returns the virtual end address (exclusive, without guard).
    pub const fn virt_end(&self) -> u64 {
        self.virt_base + self.size
    }

    /// Returns the total virtual span including guard page.
    pub const fn total_span(&self) -> u64 {
        self.size + GUARD_SIZE
    }

    /// Returns whether `addr` falls within this region.
    pub const fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.virt_base && addr < self.virt_base + self.size
    }

    /// Returns the physical address for an offset within this region.
    pub fn phys_at_offset(&self, offset: u64) -> Result<u64> {
        let page_idx = (offset / PAGE_SIZE) as usize;
        if page_idx >= self.nr_pages {
            return Err(Error::InvalidArgument);
        }
        let page_offset = offset % PAGE_SIZE;
        Ok(self.phys_pages[page_idx] * PAGE_SIZE + page_offset)
    }

    /// Returns the physical address for a virtual address.
    pub fn virt_to_phys(&self, vaddr: u64) -> Result<u64> {
        if !self.contains_addr(vaddr) {
            return Err(Error::InvalidArgument);
        }
        self.phys_at_offset(vaddr - self.virt_base)
    }

    /// Sets the caller tag from a byte slice.
    pub fn set_caller_tag(&mut self, tag: &[u8]) {
        let len = if tag.len() > MAX_CALLER_TAG {
            MAX_CALLER_TAG
        } else {
            tag.len()
        };
        self.caller_tag[..len].copy_from_slice(&tag[..len]);
        self.caller_tag_len = len;
    }
}

impl Default for VmallocRegion {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// VmallocFreeHole
// -------------------------------------------------------------------

/// A free hole in the vmalloc virtual address space.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmallocFreeHole {
    /// Virtual base of the hole.
    pub base: u64,
    /// Size of the hole in bytes.
    pub size: u64,
    /// Whether this entry is active.
    pub active: bool,
}

impl VmallocFreeHole {
    /// Creates an empty hole.
    const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            active: false,
        }
    }

    /// Returns the end address (exclusive).
    pub const fn end(&self) -> u64 {
        self.base + self.size
    }
}

// -------------------------------------------------------------------
// VmallocLookupResult
// -------------------------------------------------------------------

/// Result of looking up a virtual address in the vmalloc space.
#[derive(Debug, Clone, Copy)]
pub struct VmallocLookupResult {
    /// Region ID.
    pub region_id: u32,
    /// Region index.
    pub region_idx: usize,
    /// Offset within the region.
    pub offset: u64,
    /// Physical address (if page is mapped).
    pub phys_addr: Option<u64>,
    /// Region type.
    pub area_type: VmallocAreaType,
}

// -------------------------------------------------------------------
// VmallocAreaSnapshot
// -------------------------------------------------------------------

/// Point-in-time snapshot of the vmalloc area state.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmallocAreaSnapshot {
    /// Number of active regions.
    pub active_regions: usize,
    /// Total virtual bytes allocated.
    pub total_virt_bytes: u64,
    /// Total physical pages mapped.
    pub total_phys_pages: u64,
    /// Number of free holes.
    pub free_holes: usize,
    /// Total free virtual bytes.
    pub total_free_bytes: u64,
    /// Largest free hole size.
    pub largest_free: u64,
}

// -------------------------------------------------------------------
// VmallocAreaStats
// -------------------------------------------------------------------

/// Summary statistics for the vmalloc area manager.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmallocAreaStats {
    /// Total allocations performed.
    pub total_allocs: u64,
    /// Total frees performed.
    pub total_frees: u64,
    /// Total lazy frees.
    pub total_lazy_frees: u64,
    /// Total purges of lazy-freed areas.
    pub total_purges: u64,
    /// Total pages mapped.
    pub total_pages_mapped: u64,
    /// Total pages unmapped.
    pub total_pages_unmapped: u64,
    /// Failed allocations (no virtual space).
    pub failed_no_vspace: u64,
    /// Failed allocations (no physical pages).
    pub failed_no_pages: u64,
}

// -------------------------------------------------------------------
// VmallocAreaManager
// -------------------------------------------------------------------

/// Manages the vmalloc virtual address space.
///
/// Tracks allocated regions and free holes within the vmalloc range.
/// Provides allocation, freeing, lazy-free/purge, and address lookup.
pub struct VmallocAreaManager {
    /// Allocated regions.
    regions: [VmallocRegion; MAX_REGIONS],
    /// Number of active regions.
    nr_regions: usize,
    /// Free holes.
    free_holes: [VmallocFreeHole; MAX_FREE_HOLES],
    /// Number of active free holes.
    nr_free_holes: usize,
    /// Next region ID.
    next_id: u32,
    /// Statistics.
    stats: VmallocAreaStats,
    /// Whether the manager is initialised.
    initialised: bool,
}

impl VmallocAreaManager {
    /// Creates a new, uninitialised manager.
    pub fn new() -> Self {
        Self {
            regions: [const { VmallocRegion::empty() }; MAX_REGIONS],
            nr_regions: 0,
            free_holes: [VmallocFreeHole::empty(); MAX_FREE_HOLES],
            nr_free_holes: 0,
            next_id: 1,
            stats: VmallocAreaStats::default(),
            initialised: false,
        }
    }

    /// Initialises the manager, creating a single free hole spanning
    /// the entire vmalloc range.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.free_holes[0] = VmallocFreeHole {
            base: VMALLOC_START,
            size: VMALLOC_END - VMALLOC_START,
            active: true,
        };
        self.nr_free_holes = 1;
        self.initialised = true;
        Ok(())
    }

    /// Allocates a vmalloc region of the given size.
    ///
    /// Finds a suitable free hole (first-fit), carves out the
    /// requested size plus guard page, and returns the region index.
    pub fn alloc(
        &mut self,
        size: u64,
        area_type: VmallocAreaType,
        flags: VmallocAreaFlags,
    ) -> Result<usize> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        // Round up to page size.
        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let total_needed = aligned_size + GUARD_SIZE;
        // Find a free hole (first-fit).
        let hole_idx = self.find_free_hole(total_needed)?;
        let hole_base = self.free_holes[hole_idx].base;
        let hole_size = self.free_holes[hole_idx].size;
        // Find a free region slot.
        let region_idx = self.find_free_region_slot()?;
        let id = self.next_id;
        self.next_id += 1;
        // Set up the region.
        self.regions[region_idx].id = id;
        self.regions[region_idx].virt_base = hole_base;
        self.regions[region_idx].size = aligned_size;
        self.regions[region_idx].nr_pages = (aligned_size / PAGE_SIZE) as usize;
        self.regions[region_idx].area_type = area_type;
        self.regions[region_idx].flags = flags;
        self.regions[region_idx].active = true;
        // Shrink or remove the free hole.
        let remaining = hole_size - total_needed;
        if remaining >= PAGE_SIZE {
            self.free_holes[hole_idx].base = hole_base + total_needed;
            self.free_holes[hole_idx].size = remaining;
        } else {
            self.free_holes[hole_idx].active = false;
            self.compact_holes();
        }
        self.nr_regions += 1;
        self.stats.total_allocs += 1;
        Ok(region_idx)
    }

    /// Maps physical pages into an allocated region.
    ///
    /// The caller provides an array of PFNs (page frame numbers).
    pub fn map_pages(&mut self, region_idx: usize, pfns: &[u64]) -> Result<()> {
        if region_idx >= MAX_REGIONS || !self.regions[region_idx].active {
            return Err(Error::InvalidArgument);
        }
        let max_pages = self.regions[region_idx].nr_pages;
        let count = if pfns.len() > max_pages {
            max_pages
        } else {
            pfns.len()
        };
        if count > MAX_PAGES_PER_REGION {
            return Err(Error::InvalidArgument);
        }
        for i in 0..count {
            self.regions[region_idx].phys_pages[i] = pfns[i];
        }
        self.regions[region_idx].nr_pages = count;
        self.stats.total_pages_mapped += count as u64;
        Ok(())
    }

    /// Frees a vmalloc region immediately.
    pub fn free(&mut self, region_idx: usize) -> Result<()> {
        if region_idx >= MAX_REGIONS || !self.regions[region_idx].active {
            return Err(Error::InvalidArgument);
        }
        if self.regions[region_idx].flags.permanent {
            return Err(Error::PermissionDenied);
        }
        let base = self.regions[region_idx].virt_base;
        let span = self.regions[region_idx].total_span();
        let nr_pages = self.regions[region_idx].nr_pages;
        self.regions[region_idx] = VmallocRegion::empty();
        self.nr_regions = self.nr_regions.saturating_sub(1);
        self.add_free_hole(base, span)?;
        self.merge_adjacent_holes();
        self.stats.total_frees += 1;
        self.stats.total_pages_unmapped += nr_pages as u64;
        Ok(())
    }

    /// Marks a region for lazy freeing. The virtual space is not
    /// reclaimed until [`purge_lazy`] is called.
    pub fn lazy_free(&mut self, region_idx: usize) -> Result<()> {
        if region_idx >= MAX_REGIONS || !self.regions[region_idx].active {
            return Err(Error::InvalidArgument);
        }
        if self.regions[region_idx].flags.permanent {
            return Err(Error::PermissionDenied);
        }
        self.regions[region_idx].flags.lazy_freed = true;
        self.stats.total_lazy_frees += 1;
        Ok(())
    }

    /// Purges all lazy-freed regions, reclaiming their virtual space.
    pub fn purge_lazy(&mut self) -> Result<u64> {
        let mut purged = 0u64;
        for i in 0..MAX_REGIONS {
            if self.regions[i].active && self.regions[i].flags.lazy_freed {
                let base = self.regions[i].virt_base;
                let span = self.regions[i].total_span();
                let nr_pages = self.regions[i].nr_pages;
                self.regions[i] = VmallocRegion::empty();
                self.nr_regions = self.nr_regions.saturating_sub(1);
                let _ = self.add_free_hole(base, span);
                self.stats.total_pages_unmapped += nr_pages as u64;
                purged += 1;
            }
        }
        self.merge_adjacent_holes();
        self.stats.total_purges += purged;
        Ok(purged)
    }

    /// Looks up a virtual address in the vmalloc space.
    pub fn lookup(&self, vaddr: u64) -> Result<VmallocLookupResult> {
        for i in 0..MAX_REGIONS {
            if self.regions[i].active && self.regions[i].contains_addr(vaddr) {
                let offset = vaddr - self.regions[i].virt_base;
                let phys = self.regions[i].phys_at_offset(offset).ok();
                return Ok(VmallocLookupResult {
                    region_id: self.regions[i].id,
                    region_idx: i,
                    offset,
                    phys_addr: phys,
                    area_type: self.regions[i].area_type,
                });
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a reference to a region by index.
    pub fn region(&self, idx: usize) -> Result<&VmallocRegion> {
        if idx >= MAX_REGIONS || !self.regions[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.regions[idx])
    }

    /// Returns the number of active regions.
    pub const fn nr_regions(&self) -> usize {
        self.nr_regions
    }

    /// Returns a snapshot of the current state.
    pub fn snapshot(&self) -> VmallocAreaSnapshot {
        let mut snap = VmallocAreaSnapshot::default();
        for i in 0..MAX_REGIONS {
            if self.regions[i].active {
                snap.active_regions += 1;
                snap.total_virt_bytes += self.regions[i].size;
                snap.total_phys_pages += self.regions[i].nr_pages as u64;
            }
        }
        for i in 0..MAX_FREE_HOLES {
            if self.free_holes[i].active {
                snap.free_holes += 1;
                snap.total_free_bytes += self.free_holes[i].size;
                if self.free_holes[i].size > snap.largest_free {
                    snap.largest_free = self.free_holes[i].size;
                }
            }
        }
        snap
    }

    /// Returns the statistics.
    pub const fn stats(&self) -> &VmallocAreaStats {
        &self.stats
    }

    /// Finds a region by ID.
    pub fn find_by_id(&self, id: u32) -> Option<usize> {
        for i in 0..MAX_REGIONS {
            if self.regions[i].active && self.regions[i].id == id {
                return Some(i);
            }
        }
        None
    }

    /// Resizes a region (grow only). The region must have free space
    /// immediately following it.
    pub fn grow_region(&mut self, region_idx: usize, additional_pages: usize) -> Result<()> {
        if region_idx >= MAX_REGIONS || !self.regions[region_idx].active {
            return Err(Error::InvalidArgument);
        }
        let new_nr = self.regions[region_idx].nr_pages + additional_pages;
        if new_nr > MAX_PAGES_PER_REGION {
            return Err(Error::OutOfMemory);
        }
        let additional_bytes = additional_pages as u64 * PAGE_SIZE;
        let region_end = self.regions[region_idx].virt_base + self.regions[region_idx].total_span();
        // Find adjacent free hole.
        let hole_idx = self.find_adjacent_hole(region_end);
        match hole_idx {
            Some(hi) if self.free_holes[hi].size >= additional_bytes => {
                self.regions[region_idx].size += additional_bytes;
                self.regions[region_idx].nr_pages = new_nr;
                self.free_holes[hi].base += additional_bytes;
                self.free_holes[hi].size -= additional_bytes;
                if self.free_holes[hi].size < PAGE_SIZE {
                    self.free_holes[hi].active = false;
                    self.compact_holes();
                }
                Ok(())
            }
            _ => Err(Error::OutOfMemory),
        }
    }

    /// Changes the flags of an existing region.
    pub fn set_flags(&mut self, region_idx: usize, flags: VmallocAreaFlags) -> Result<()> {
        if region_idx >= MAX_REGIONS || !self.regions[region_idx].active {
            return Err(Error::InvalidArgument);
        }
        self.regions[region_idx].flags = flags;
        Ok(())
    }

    /// Resets all state. Used during reinitialisation.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    /// Finds a free hole that can accommodate `size` bytes.
    fn find_free_hole(&mut self, size: u64) -> Result<usize> {
        for i in 0..MAX_FREE_HOLES {
            if self.free_holes[i].active && self.free_holes[i].size >= size {
                return Ok(i);
            }
        }
        self.stats.failed_no_vspace += 1;
        Err(Error::OutOfMemory)
    }

    /// Finds a free region slot.
    fn find_free_region_slot(&self) -> Result<usize> {
        for i in 0..MAX_REGIONS {
            if !self.regions[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Adds a free hole.
    fn add_free_hole(&mut self, base: u64, size: u64) -> Result<()> {
        for i in 0..MAX_FREE_HOLES {
            if !self.free_holes[i].active {
                self.free_holes[i] = VmallocFreeHole {
                    base,
                    size,
                    active: true,
                };
                self.nr_free_holes += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Merges adjacent free holes into larger ones.
    fn merge_adjacent_holes(&mut self) {
        // Sort active holes by base address using insertion sort.
        for i in 1..MAX_FREE_HOLES {
            if !self.free_holes[i].active {
                continue;
            }
            let mut j = i;
            while j > 0
                && self.free_holes[j - 1].active
                && self.free_holes[j - 1].base > self.free_holes[j].base
            {
                self.free_holes.swap(j, j - 1);
                j -= 1;
            }
        }
        // Merge adjacent.
        let mut i = 0;
        while i + 1 < MAX_FREE_HOLES {
            if !self.free_holes[i].active {
                i += 1;
                continue;
            }
            let next = i + 1;
            if !self.free_holes[next].active {
                i += 1;
                continue;
            }
            let end_i = self.free_holes[i].end();
            if end_i == self.free_holes[next].base {
                self.free_holes[i].size += self.free_holes[next].size;
                self.free_holes[next].active = false;
                self.nr_free_holes = self.nr_free_holes.saturating_sub(1);
                // Don't advance i — check if merged hole can merge
                // with next.
            } else {
                i += 1;
            }
        }
    }

    /// Removes inactive holes by compacting the array.
    fn compact_holes(&mut self) {
        let mut write = 0;
        for read in 0..MAX_FREE_HOLES {
            if self.free_holes[read].active {
                if write != read {
                    let hole = self.free_holes[read];
                    self.free_holes[write] = hole;
                    self.free_holes[read] = VmallocFreeHole::empty();
                }
                write += 1;
            }
        }
        self.nr_free_holes = write;
    }

    /// Finds a free hole starting at exactly `addr`.
    fn find_adjacent_hole(&self, addr: u64) -> Option<usize> {
        for i in 0..MAX_FREE_HOLES {
            if self.free_holes[i].active && self.free_holes[i].base == addr {
                return Some(i);
            }
        }
        None
    }
}

impl Default for VmallocAreaManager {
    fn default() -> Self {
        Self::new()
    }
}
