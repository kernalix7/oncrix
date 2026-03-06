// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Virtual memory map (vmemmap) page table population.
//!
//! The vmemmap is a contiguous virtual address range that maps the
//! `struct page` metadata array for every physical page frame. On
//! x86_64 with 4-level paging the vmemmap region begins at a fixed
//! virtual address and is lazily populated: only sections backed by
//! actual physical memory have their page tables filled in.
//!
//! This module handles:
//! - Populating page tables for vmemmap sections.
//! - Partial section population (only a subset of pages present).
//! - Altmap (device-memory) backing for vmemmap pages.
//! - Freeing vmemmap page table entries on memory hot-remove.
//! - Statistics on vmemmap population and teardown.
//!
//! # Key Types
//!
//! - [`VmemmapLevel`] — page table level backing a vmemmap region
//! - [`VmemmapSectionInfo`] — per-section population metadata
//! - [`AltmapDescriptor`] — device-memory altmap for vmemmap backing
//! - [`PopulateRequest`] — request to populate a PFN range
//! - [`VmemmapPopulator`] — engine that manages vmemmap population
//! - [`VmemmapPopulateStats`] — cumulative statistics
//!
//! Reference: Linux `mm/sparse-vmemmap.c`,
//! `Documentation/mm/vmemmap_dedup.rst`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Huge page size (2 MiB).
const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;

/// Gigantic page size (1 GiB).
const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

/// Size of a single struct-page descriptor (64 bytes).
const STRUCT_PAGE_SIZE: u64 = 64;

/// Number of struct-page entries per 4 KiB vmemmap page.
const PAGES_PER_VMEMMAP_4K: u64 = PAGE_SIZE / STRUCT_PAGE_SIZE;

/// Number of struct-page entries per 2 MiB vmemmap page.
const PAGES_PER_VMEMMAP_2M: u64 = PAGE_SIZE_2M / STRUCT_PAGE_SIZE;

/// Pages per memory section (128 MiB / 4 KiB = 32768).
const PAGES_PER_SECTION: u64 = 32768;

/// Maximum tracked vmemmap sections.
const MAX_VMEMMAP_SECTIONS: usize = 512;

/// Maximum pending populate requests.
const MAX_POPULATE_REQUESTS: usize = 64;

/// Maximum altmap descriptors.
const MAX_ALTMAPS: usize = 16;

/// Base virtual address of the vmemmap region (x86_64 canonical).
const VMEMMAP_BASE: u64 = 0xFFFF_EA00_0000_0000;

// -------------------------------------------------------------------
// VmemmapLevel
// -------------------------------------------------------------------

/// Page table level used to back a vmemmap region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmemmapLevel {
    /// Backed by 4 KiB PTE-level entries (unoptimized).
    #[default]
    Pte4K,
    /// Backed by 2 MiB PMD-level huge entries.
    Pmd2M,
    /// Backed by 1 GiB PUD-level gigantic entries.
    Pud1G,
}

impl VmemmapLevel {
    /// Returns the backing page size in bytes.
    pub fn page_size(self) -> u64 {
        match self {
            Self::Pte4K => PAGE_SIZE,
            Self::Pmd2M => PAGE_SIZE_2M,
            Self::Pud1G => PAGE_SIZE_1G,
        }
    }

    /// Returns the number of struct-page entries covered.
    pub fn entries_covered(self) -> u64 {
        self.page_size() / STRUCT_PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// SectionPopulateState
// -------------------------------------------------------------------

/// Population state of a vmemmap section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SectionPopulateState {
    /// Section is not populated at all.
    #[default]
    Unpopulated,
    /// Section is partially populated (some PFNs present).
    Partial,
    /// Section is fully populated.
    Full,
    /// Section uses altmap (device memory) backing.
    AltmapBacked,
}

// -------------------------------------------------------------------
// VmemmapSectionInfo
// -------------------------------------------------------------------

/// Metadata for a single vmemmap section.
#[derive(Debug, Clone, Copy)]
pub struct VmemmapSectionInfo {
    /// Section index (section_nr = start_pfn / PAGES_PER_SECTION).
    pub section_nr: u64,
    /// First PFN in this section.
    pub start_pfn: u64,
    /// Number of populated PFNs within this section.
    pub populated_pfns: u64,
    /// Current population state.
    pub state: SectionPopulateState,
    /// Page table level backing this section's vmemmap.
    pub level: VmemmapLevel,
    /// Number of physical pages consumed for vmemmap backing.
    pub backing_pages: u64,
    /// If true, an altmap descriptor provides backing memory.
    pub altmap_backed: bool,
    /// Virtual address of the vmemmap region for this section.
    pub vmemmap_addr: u64,
}

impl Default for VmemmapSectionInfo {
    fn default() -> Self {
        Self {
            section_nr: 0,
            start_pfn: 0,
            populated_pfns: 0,
            state: SectionPopulateState::Unpopulated,
            level: VmemmapLevel::Pte4K,
            backing_pages: 0,
            altmap_backed: false,
            vmemmap_addr: 0,
        }
    }
}

// -------------------------------------------------------------------
// AltmapDescriptor
// -------------------------------------------------------------------

/// Describes a device-memory altmap region used to back vmemmap pages.
///
/// When adding device memory (e.g., persistent memory), the vmemmap
/// metadata for that region can be stored in the device memory itself,
/// saving host DRAM.
#[derive(Debug, Clone, Copy)]
pub struct AltmapDescriptor {
    /// Base PFN of the altmap region.
    pub base_pfn: u64,
    /// Number of PFNs reserved for vmemmap backing.
    pub reserve_pfns: u64,
    /// Number of PFNs already allocated from the altmap.
    pub alloc_pfns: u64,
    /// Number of PFNs available for non-vmemmap use.
    pub free_pfns: u64,
    /// Whether this altmap is currently active.
    pub active: bool,
}

impl Default for AltmapDescriptor {
    fn default() -> Self {
        Self {
            base_pfn: 0,
            reserve_pfns: 0,
            alloc_pfns: 0,
            free_pfns: 0,
            active: false,
        }
    }
}

impl AltmapDescriptor {
    /// Returns the number of PFNs still available for allocation.
    pub fn remaining(&self) -> u64 {
        self.reserve_pfns.saturating_sub(self.alloc_pfns)
    }

    /// Attempts to allocate `count` PFNs from the altmap.
    pub fn allocate(&mut self, count: u64) -> Result<u64> {
        if count > self.remaining() {
            return Err(Error::OutOfMemory);
        }
        let pfn = self.base_pfn + self.alloc_pfns;
        self.alloc_pfns += count;
        Ok(pfn)
    }
}

// -------------------------------------------------------------------
// PopulateRequest
// -------------------------------------------------------------------

/// A request to populate vmemmap for a PFN range.
#[derive(Debug, Clone, Copy)]
pub struct PopulateRequest {
    /// First PFN to populate.
    pub start_pfn: u64,
    /// Number of PFNs to populate.
    pub nr_pfns: u64,
    /// Preferred backing level.
    pub preferred_level: VmemmapLevel,
    /// Index into altmap array, or `None` for host DRAM backing.
    pub altmap_idx: Option<usize>,
    /// Whether this is a partial-section populate.
    pub partial: bool,
}

impl Default for PopulateRequest {
    fn default() -> Self {
        Self {
            start_pfn: 0,
            nr_pfns: 0,
            preferred_level: VmemmapLevel::Pte4K,
            altmap_idx: None,
            partial: false,
        }
    }
}

// -------------------------------------------------------------------
// VmemmapPopulateStats
// -------------------------------------------------------------------

/// Cumulative statistics for vmemmap population and teardown.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmemmapPopulateStats {
    /// Total sections fully populated.
    pub sections_populated: u64,
    /// Total sections partially populated.
    pub sections_partial: u64,
    /// Total sections freed (hot-remove).
    pub sections_freed: u64,
    /// Total backing pages allocated from host DRAM.
    pub dram_pages_used: u64,
    /// Total backing pages allocated from altmaps.
    pub altmap_pages_used: u64,
    /// Total populate requests processed.
    pub populate_requests: u64,
    /// Total free requests processed.
    pub free_requests: u64,
    /// Number of failed populate attempts.
    pub populate_failures: u64,
}

// -------------------------------------------------------------------
// VmemmapPopulator
// -------------------------------------------------------------------

/// Engine that manages vmemmap page table population and teardown.
///
/// Maintains per-section metadata, processes populate requests,
/// handles altmap backing, and tracks statistics.
pub struct VmemmapPopulator {
    /// Per-section vmemmap information.
    sections: [VmemmapSectionInfo; MAX_VMEMMAP_SECTIONS],
    /// Number of sections registered.
    nr_sections: usize,
    /// Altmap descriptors for device-memory backing.
    altmaps: [AltmapDescriptor; MAX_ALTMAPS],
    /// Number of registered altmaps.
    nr_altmaps: usize,
    /// Pending populate requests.
    requests: [PopulateRequest; MAX_POPULATE_REQUESTS],
    /// Number of pending requests.
    nr_requests: usize,
    /// Next available host-DRAM PFN for vmemmap backing.
    next_backing_pfn: u64,
    /// Total host-DRAM pages available for vmemmap backing.
    backing_capacity: u64,
    /// Cumulative statistics.
    stats: VmemmapPopulateStats,
}

impl VmemmapPopulator {
    /// Creates a new vmemmap populator.
    ///
    /// `backing_start_pfn` is the first PFN available for host-DRAM
    /// vmemmap backing, and `backing_nr_pages` is the capacity.
    pub fn new(backing_start_pfn: u64, backing_nr_pages: u64) -> Self {
        Self {
            sections: [const {
                VmemmapSectionInfo {
                    section_nr: 0,
                    start_pfn: 0,
                    populated_pfns: 0,
                    state: SectionPopulateState::Unpopulated,
                    level: VmemmapLevel::Pte4K,
                    backing_pages: 0,
                    altmap_backed: false,
                    vmemmap_addr: 0,
                }
            }; MAX_VMEMMAP_SECTIONS],
            nr_sections: 0,
            altmaps: [const {
                AltmapDescriptor {
                    base_pfn: 0,
                    reserve_pfns: 0,
                    alloc_pfns: 0,
                    free_pfns: 0,
                    active: false,
                }
            }; MAX_ALTMAPS],
            nr_altmaps: 0,
            requests: [const {
                PopulateRequest {
                    start_pfn: 0,
                    nr_pfns: 0,
                    preferred_level: VmemmapLevel::Pte4K,
                    altmap_idx: None,
                    partial: false,
                }
            }; MAX_POPULATE_REQUESTS],
            nr_requests: 0,
            next_backing_pfn: backing_start_pfn,
            backing_capacity: backing_nr_pages,
            stats: VmemmapPopulateStats::default(),
        }
    }

    /// Returns current statistics.
    pub fn stats(&self) -> &VmemmapPopulateStats {
        &self.stats
    }

    /// Returns the number of registered sections.
    pub fn section_count(&self) -> usize {
        self.nr_sections
    }

    /// Registers an altmap descriptor for device-memory backing.
    pub fn register_altmap(&mut self, base_pfn: u64, reserve_pfns: u64) -> Result<usize> {
        if self.nr_altmaps >= MAX_ALTMAPS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.nr_altmaps;
        self.altmaps[idx] = AltmapDescriptor {
            base_pfn,
            reserve_pfns,
            alloc_pfns: 0,
            free_pfns: reserve_pfns,
            active: true,
        };
        self.nr_altmaps += 1;
        Ok(idx)
    }

    /// Computes the vmemmap virtual address for a given PFN.
    fn vmemmap_addr_for_pfn(pfn: u64) -> u64 {
        VMEMMAP_BASE + pfn * STRUCT_PAGE_SIZE
    }

    /// Computes the section number for a given PFN.
    fn section_for_pfn(pfn: u64) -> u64 {
        pfn / PAGES_PER_SECTION
    }

    /// Finds the section index for a given section number, if present.
    fn find_section(&self, section_nr: u64) -> Option<usize> {
        for i in 0..self.nr_sections {
            if self.sections[i].section_nr == section_nr {
                return Some(i);
            }
        }
        None
    }

    /// Allocates backing pages, preferring altmap if specified.
    fn alloc_backing(&mut self, nr_pages: u64, altmap_idx: Option<usize>) -> Result<u64> {
        if let Some(idx) = altmap_idx {
            if idx >= self.nr_altmaps || !self.altmaps[idx].active {
                return Err(Error::InvalidArgument);
            }
            let pfn = self.altmaps[idx].allocate(nr_pages)?;
            self.stats.altmap_pages_used += nr_pages;
            return Ok(pfn);
        }
        let needed = self.next_backing_pfn + nr_pages;
        let limit =
            self.next_backing_pfn.saturating_sub(self.next_backing_pfn) + self.backing_capacity;
        if needed > limit {
            return Err(Error::OutOfMemory);
        }
        let pfn = self.next_backing_pfn;
        self.next_backing_pfn += nr_pages;
        self.stats.dram_pages_used += nr_pages;
        Ok(pfn)
    }

    /// Computes the number of backing pages needed for `nr_pfns` at
    /// the given level.
    fn backing_pages_needed(nr_pfns: u64, level: VmemmapLevel) -> u64 {
        let entries_per_page = level.entries_covered();
        (nr_pfns + entries_per_page - 1) / entries_per_page
    }

    /// Enqueues a populate request.
    pub fn enqueue_populate(
        &mut self,
        start_pfn: u64,
        nr_pfns: u64,
        preferred_level: VmemmapLevel,
        altmap_idx: Option<usize>,
    ) -> Result<()> {
        if nr_pfns == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.nr_requests >= MAX_POPULATE_REQUESTS {
            return Err(Error::Busy);
        }
        let partial = nr_pfns < PAGES_PER_SECTION;
        self.requests[self.nr_requests] = PopulateRequest {
            start_pfn,
            nr_pfns,
            preferred_level,
            altmap_idx,
            partial,
        };
        self.nr_requests += 1;
        Ok(())
    }

    /// Processes all pending populate requests.
    ///
    /// Each request populates vmemmap page tables for its PFN range,
    /// allocating backing pages from host DRAM or altmap.
    pub fn process_requests(&mut self) -> Result<u64> {
        let mut populated = 0u64;
        let count = self.nr_requests;
        for i in 0..count {
            let req = self.requests[i];
            match self.populate_range(
                req.start_pfn,
                req.nr_pfns,
                req.preferred_level,
                req.altmap_idx,
            ) {
                Ok(n) => populated += n,
                Err(_) => {
                    self.stats.populate_failures += 1;
                }
            }
            self.stats.populate_requests += 1;
        }
        self.nr_requests = 0;
        Ok(populated)
    }

    /// Populates vmemmap for a contiguous PFN range.
    fn populate_range(
        &mut self,
        start_pfn: u64,
        nr_pfns: u64,
        level: VmemmapLevel,
        altmap_idx: Option<usize>,
    ) -> Result<u64> {
        let backing_needed = Self::backing_pages_needed(nr_pfns, level);
        let _backing_pfn = self.alloc_backing(backing_needed, altmap_idx)?;

        let section_nr = Self::section_for_pfn(start_pfn);
        let vmaddr = Self::vmemmap_addr_for_pfn(start_pfn);

        let idx = if let Some(existing) = self.find_section(section_nr) {
            existing
        } else {
            if self.nr_sections >= MAX_VMEMMAP_SECTIONS {
                return Err(Error::OutOfMemory);
            }
            let new_idx = self.nr_sections;
            self.sections[new_idx] = VmemmapSectionInfo {
                section_nr,
                start_pfn: section_nr * PAGES_PER_SECTION,
                populated_pfns: 0,
                state: SectionPopulateState::Unpopulated,
                level,
                backing_pages: 0,
                altmap_backed: altmap_idx.is_some(),
                vmemmap_addr: vmaddr,
            };
            self.nr_sections += 1;
            new_idx
        };

        self.sections[idx].populated_pfns += nr_pfns;
        self.sections[idx].backing_pages += backing_needed;
        self.sections[idx].level = level;

        if self.sections[idx].populated_pfns >= PAGES_PER_SECTION {
            self.sections[idx].state = SectionPopulateState::Full;
            self.stats.sections_populated += 1;
        } else {
            self.sections[idx].state = SectionPopulateState::Partial;
            self.stats.sections_partial += 1;
        }

        if altmap_idx.is_some() {
            self.sections[idx].altmap_backed = true;
            self.sections[idx].state = SectionPopulateState::AltmapBacked;
        }

        Ok(nr_pfns)
    }

    /// Frees vmemmap page tables for a section (memory hot-remove).
    ///
    /// Releases backing pages and marks the section as unpopulated.
    pub fn vmemmap_free(&mut self, section_nr: u64) -> Result<u64> {
        let idx = self.find_section(section_nr).ok_or(Error::NotFound)?;
        let freed = self.sections[idx].backing_pages;
        self.sections[idx].state = SectionPopulateState::Unpopulated;
        self.sections[idx].populated_pfns = 0;
        self.sections[idx].backing_pages = 0;
        self.stats.sections_freed += 1;
        self.stats.free_requests += 1;
        Ok(freed)
    }

    /// Looks up the population state of a section.
    pub fn section_state(&self, section_nr: u64) -> SectionPopulateState {
        match self.find_section(section_nr) {
            Some(idx) => self.sections[idx].state,
            None => SectionPopulateState::Unpopulated,
        }
    }

    /// Returns the vmemmap virtual address for a given PFN.
    pub fn pfn_to_vmemmap_addr(pfn: u64) -> u64 {
        Self::vmemmap_addr_for_pfn(pfn)
    }

    /// Returns whether a PFN has its vmemmap populated.
    pub fn is_pfn_populated(&self, pfn: u64) -> bool {
        let section_nr = Self::section_for_pfn(pfn);
        match self.find_section(section_nr) {
            Some(idx) => {
                let sec = &self.sections[idx];
                matches!(
                    sec.state,
                    SectionPopulateState::Full | SectionPopulateState::AltmapBacked
                ) || (sec.state == SectionPopulateState::Partial
                    && pfn >= sec.start_pfn
                    && pfn < sec.start_pfn + sec.populated_pfns)
            }
            None => false,
        }
    }

    /// Returns the backing page count for a given section.
    pub fn section_backing_pages(&self, section_nr: u64) -> u64 {
        match self.find_section(section_nr) {
            Some(idx) => self.sections[idx].backing_pages,
            None => 0,
        }
    }

    /// Returns the total number of backing pages consumed.
    pub fn total_backing_pages(&self) -> u64 {
        self.stats.dram_pages_used + self.stats.altmap_pages_used
    }

    /// Computes per-NUMA-node vmemmap backing page counts.
    ///
    /// In a simplified model, returns the backing page count for
    /// sections in the given PFN range (simulating a NUMA node).
    pub fn backing_pages_in_range(&self, range_start_pfn: u64, range_end_pfn: u64) -> u64 {
        let mut total = 0u64;
        for i in 0..self.nr_sections {
            let sec = &self.sections[i];
            let sec_end = sec.start_pfn + PAGES_PER_SECTION;
            if sec.start_pfn < range_end_pfn && sec_end > range_start_pfn {
                total += sec.backing_pages;
            }
        }
        total
    }
}
