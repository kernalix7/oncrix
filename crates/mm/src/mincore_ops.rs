// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! mincore operations for the ONCRIX memory management subsystem.
//!
//! Implements the `mincore(2)` system call, which reports whether
//! pages in a given virtual address range are resident in physical
//! memory. Returns a bitvector where each byte corresponds to one
//! page: 1 if resident, 0 if not.
//!
//! - [`MincoreOps`] — main handler with page table walk simulation
//! - [`PageResidency`] — residency status for a single page
//! - [`MincoreStats`] — operation statistics
//!
//! Reference: `.kernelORG/` — `mm/mincore.c`, POSIX `mincore(2)`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of VMAs tracked.
const MAX_VMAS: usize = 256;

/// Maximum number of page entries per VMA for residency tracking.
const MAX_PAGES_PER_VMA: usize = 512;

/// Maximum pages per single mincore query.
const MAX_QUERY_PAGES: usize = 1024;

// -------------------------------------------------------------------
// PageResidency
// -------------------------------------------------------------------

/// Residency status for a single page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PageResidency {
    /// Page is not resident (not in physical memory).
    #[default]
    NotResident,
    /// Page is resident in physical memory.
    Resident,
    /// Page is resident and referenced (hot).
    ReferencedResident,
    /// Page is resident and dirty.
    DirtyResident,
    /// Page is in swap.
    Swapped,
}

impl PageResidency {
    /// Convert to the mincore result byte (1 if resident, 0 if not).
    pub fn to_byte(self) -> u8 {
        match self {
            PageResidency::NotResident | PageResidency::Swapped => 0,
            PageResidency::Resident
            | PageResidency::ReferencedResident
            | PageResidency::DirtyResident => 1,
        }
    }

    /// Check if the page is resident.
    pub fn is_resident(self) -> bool {
        !matches!(self, PageResidency::NotResident | PageResidency::Swapped)
    }
}

// -------------------------------------------------------------------
// MincoreVma
// -------------------------------------------------------------------

/// A VMA entry for mincore tracking with per-page residency info.
#[derive(Debug, Clone, Copy)]
pub struct MincoreVma {
    /// Start address (page-aligned).
    pub start: u64,
    /// End address (page-aligned, exclusive).
    pub end: u64,
    /// Whether this VMA is file-backed.
    pub file_backed: bool,
    /// Whether this VMA is anonymous.
    pub anonymous: bool,
    /// Per-page residency tracking.
    pages: [PageResidency; MAX_PAGES_PER_VMA],
    /// Number of pages tracked.
    page_count: u32,
    /// Whether this VMA is active.
    pub active: bool,
}

impl MincoreVma {
    /// Create an empty VMA.
    pub const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            file_backed: false,
            anonymous: true,
            pages: [PageResidency::NotResident; MAX_PAGES_PER_VMA],
            page_count: 0,
            active: false,
        }
    }

    /// Size of the VMA in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Check if the VMA contains the address.
    pub fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.start && addr < self.end
    }

    /// Check if the VMA overlaps the range.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.active && self.start < end && self.end > start
    }

    /// Get the residency status of a page at the given address.
    pub fn page_residency(&self, addr: u64) -> PageResidency {
        if !self.contains(addr) {
            return PageResidency::NotResident;
        }
        let page_idx = ((addr - self.start) / PAGE_SIZE) as usize;
        if page_idx < self.page_count as usize {
            self.pages[page_idx]
        } else {
            PageResidency::NotResident
        }
    }

    /// Set the residency status of a page.
    pub fn set_page_residency(&mut self, addr: u64, status: PageResidency) -> bool {
        if !self.contains(addr) {
            return false;
        }
        let page_idx = ((addr - self.start) / PAGE_SIZE) as usize;
        if page_idx < self.page_count as usize {
            self.pages[page_idx] = status;
            true
        } else {
            false
        }
    }

    /// Count resident pages.
    pub fn resident_count(&self) -> u32 {
        let mut count = 0u32;
        for i in 0..(self.page_count as usize) {
            if self.pages[i].is_resident() {
                count += 1;
            }
        }
        count
    }
}

// -------------------------------------------------------------------
// MincoreStats
// -------------------------------------------------------------------

/// Statistics for mincore operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct MincoreStats {
    /// Total mincore calls.
    pub total_calls: u64,
    /// Total pages queried.
    pub pages_queried: u64,
    /// Total pages reported as resident.
    pub pages_resident: u64,
    /// Total pages reported as not resident.
    pub pages_not_resident: u64,
    /// Number of queries for file-backed pages.
    pub file_queries: u64,
    /// Number of queries for anonymous pages.
    pub anon_queries: u64,
    /// Number of failed queries (bad address).
    pub failures: u64,
}

// -------------------------------------------------------------------
// MincoreOps
// -------------------------------------------------------------------

/// Main mincore handler.
///
/// Processes mincore requests by walking page tables for the
/// specified range and reporting residency status for each page.
pub struct MincoreOps {
    /// VMA table.
    vmas: [MincoreVma; MAX_VMAS],
    /// Number of VMAs.
    vma_count: usize,
    /// Statistics.
    stats: MincoreStats,
}

impl MincoreOps {
    /// Create a new mincore handler.
    pub fn new() -> Self {
        Self {
            vmas: [MincoreVma::empty(); MAX_VMAS],
            vma_count: 0,
            stats: MincoreStats::default(),
        }
    }

    /// Register a VMA for mincore tracking.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the VMA table is full, or
    /// `InvalidArgument` if the range is invalid.
    pub fn register_vma(&mut self, start: u64, end: u64, file_backed: bool) -> Result<usize> {
        if start >= end || start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.vma_count >= MAX_VMAS {
            return Err(Error::OutOfMemory);
        }

        let page_count = ((end - start) / PAGE_SIZE) as usize;
        let capped_pages = page_count.min(MAX_PAGES_PER_VMA);

        let idx = self.vma_count;
        self.vmas[idx] = MincoreVma {
            start,
            end,
            file_backed,
            anonymous: !file_backed,
            pages: [PageResidency::NotResident; MAX_PAGES_PER_VMA],
            page_count: capped_pages as u32,
            active: true,
        };
        self.vma_count += 1;
        Ok(idx)
    }

    /// Set a page as resident in the given VMA.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if no VMA contains the address.
    pub fn set_page_resident(&mut self, addr: u64, status: PageResidency) -> Result<()> {
        let page_addr = addr & !(PAGE_SIZE - 1);
        for i in 0..self.vma_count {
            if self.vmas[i].set_page_residency(page_addr, status) {
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Perform a mincore query on the specified range.
    ///
    /// Walks the page tables for each page in the range and fills
    /// `out` with 1 (resident) or 0 (not resident) for each page.
    ///
    /// Returns the number of pages queried.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the range is invalid or the
    /// output buffer is too small.
    pub fn do_mincore(&mut self, start: u64, len: u64, out: &mut [u8]) -> Result<usize> {
        if len == 0 || start % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }

        let end = start.saturating_add(len);
        let aligned_end = (end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let nr_pages = ((aligned_end - start) / PAGE_SIZE) as usize;

        if nr_pages > MAX_QUERY_PAGES {
            return Err(Error::InvalidArgument);
        }
        if out.len() < nr_pages {
            return Err(Error::InvalidArgument);
        }

        self.stats.total_calls += 1;
        self.stats.pages_queried += nr_pages as u64;

        let mut resident_count = 0u64;

        for page_idx in 0..nr_pages {
            let page_addr = start + (page_idx as u64) * PAGE_SIZE;
            let residency = self.check_page_residency(page_addr);

            out[page_idx] = residency.to_byte();

            if residency.is_resident() {
                resident_count += 1;
            }
        }

        self.stats.pages_resident += resident_count;
        self.stats.pages_not_resident += (nr_pages as u64) - resident_count;

        Ok(nr_pages)
    }

    /// Check the residency of a single page.
    fn check_page_residency(&mut self, addr: u64) -> PageResidency {
        for i in 0..self.vma_count {
            let vma = &self.vmas[i];
            if !vma.contains(addr) {
                continue;
            }

            if vma.file_backed {
                self.stats.file_queries += 1;
            } else {
                self.stats.anon_queries += 1;
            }

            return vma.page_residency(addr);
        }

        // Address not in any VMA.
        self.stats.failures += 1;
        PageResidency::NotResident
    }

    /// Query residency for a single page address.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the address is not in any VMA.
    pub fn query_page(&self, addr: u64) -> Result<PageResidency> {
        let page_addr = addr & !(PAGE_SIZE - 1);
        for i in 0..self.vma_count {
            if self.vmas[i].contains(page_addr) {
                return Ok(self.vmas[i].page_residency(page_addr));
            }
        }
        Err(Error::NotFound)
    }

    /// Populate residency data for a VMA (simulate all pages resident).
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the VMA index is out of bounds.
    pub fn populate_vma(&mut self, vma_idx: usize) -> Result<u32> {
        if vma_idx >= self.vma_count || !self.vmas[vma_idx].active {
            return Err(Error::InvalidArgument);
        }

        let count = self.vmas[vma_idx].page_count;
        for i in 0..(count as usize) {
            self.vmas[vma_idx].pages[i] = PageResidency::Resident;
        }
        Ok(count)
    }

    /// Evict pages in a range (set to NotResident).
    ///
    /// Returns the number of pages evicted.
    pub fn evict_range(&mut self, start: u64, end: u64) -> u32 {
        let mut evicted = 0u32;
        let mut addr = start & !(PAGE_SIZE - 1);

        while addr < end {
            for i in 0..self.vma_count {
                if self.vmas[i].set_page_residency(addr, PageResidency::NotResident) {
                    evicted += 1;
                    break;
                }
            }
            addr += PAGE_SIZE;
        }
        evicted
    }

    /// Get statistics.
    pub fn statistics(&self) -> &MincoreStats {
        &self.stats
    }

    /// Get the number of active VMAs.
    pub fn vma_count(&self) -> usize {
        self.vmas
            .iter()
            .take(self.vma_count)
            .filter(|v| v.active)
            .count()
    }

    /// Get a VMA by index.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the index is out of bounds.
    pub fn get_vma(&self, idx: usize) -> Result<&MincoreVma> {
        if idx >= self.vma_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.vmas[idx])
    }

    /// Get total resident page count across all VMAs.
    pub fn total_resident_pages(&self) -> u32 {
        let mut total = 0u32;
        for i in 0..self.vma_count {
            if self.vmas[i].active {
                total += self.vmas[i].resident_count();
            }
        }
        total
    }
}
