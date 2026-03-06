// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! madvise operations for the ONCRIX memory management subsystem.
//!
//! Implements the `madvise(2)` system call, which allows a process to
//! advise the kernel about its expected memory access patterns. The
//! kernel uses these hints to optimize paging and memory management
//! decisions.
//!
//! - [`MadviseAdvice`] — advice values (NORMAL, SEQUENTIAL, RANDOM, etc.)
//! - [`MadviseOps`] — main madvise handler with VMA state
//! - [`MadviseResult`] — outcome of applying advice
//! - [`MadviseStats`] — usage statistics
//!
//! Reference: `.kernelORG/` — `mm/madvise.c`, POSIX `madvise(2)`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of VMAs the madvise handler tracks.
const MAX_VMAS: usize = 256;

/// Maximum number of pages to zap in a single DONTNEED pass.
const MAX_ZAP_PAGES: usize = 512;

// -------------------------------------------------------------------
// MadviseAdvice
// -------------------------------------------------------------------

/// Advice values for `madvise(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MadviseAdvice {
    /// No special treatment (default behavior).
    #[default]
    Normal,
    /// Expect sequential access (enable readahead).
    Sequential,
    /// Expect random access (disable readahead).
    Random,
    /// The range will be needed soon (prefetch).
    WillNeed,
    /// The range is not needed (can free pages).
    DontNeed,
    /// The range may be freed lazily (MADV_FREE).
    Free,
    /// Enable transparent huge pages for this range.
    HugePage,
    /// Disable transparent huge pages for this range.
    NoHugePage,
    /// Mark pages as mergeable by KSM.
    Mergeable,
    /// Unmark pages from KSM merging.
    Unmergeable,
    /// Enable soft dirty tracking.
    SoftOffline,
    /// Poison the range (for testing memory error handling).
    HwPoison,
    /// Remove the range (like DONTNEED but for shared mappings).
    Remove,
    /// Mark as cold (deprioritize in LRU).
    Cold,
    /// Mark as pageout candidate (move to inactive list).
    PageOut,
    /// Populate page tables (like MAP_POPULATE).
    Populate,
    /// Collapse small pages into huge pages.
    Collapse,
}

impl MadviseAdvice {
    /// Check if this advice is destructive (may discard data).
    pub fn is_destructive(&self) -> bool {
        matches!(
            self,
            MadviseAdvice::DontNeed
                | MadviseAdvice::Free
                | MadviseAdvice::Remove
                | MadviseAdvice::HwPoison
        )
    }

    /// Check if this advice modifies VMA flags.
    pub fn modifies_flags(&self) -> bool {
        matches!(
            self,
            MadviseAdvice::HugePage
                | MadviseAdvice::NoHugePage
                | MadviseAdvice::Mergeable
                | MadviseAdvice::Unmergeable
                | MadviseAdvice::Sequential
                | MadviseAdvice::Random
                | MadviseAdvice::Normal
        )
    }
}

// -------------------------------------------------------------------
// VmaFlags
// -------------------------------------------------------------------

/// Flags on a VMA affected by madvise.
pub struct VmaFlags;

impl VmaFlags {
    /// Sequential access hint.
    pub const SEQ_READ: u32 = 1 << 0;
    /// Random access hint.
    pub const RAND_READ: u32 = 1 << 1;
    /// Transparent huge pages enabled.
    pub const HUGEPAGE: u32 = 1 << 2;
    /// Transparent huge pages disabled.
    pub const NOHUGEPAGE: u32 = 1 << 3;
    /// KSM mergeable.
    pub const MERGEABLE: u32 = 1 << 4;
    /// Mapping is shared.
    pub const SHARED: u32 = 1 << 5;
    /// Mapping is file-backed.
    pub const FILE_BACKED: u32 = 1 << 6;
    /// Mapping has been locked (mlock).
    pub const LOCKED: u32 = 1 << 7;
}

// -------------------------------------------------------------------
// MadviseVma
// -------------------------------------------------------------------

/// A VMA entry tracked by the madvise handler.
#[derive(Debug, Clone, Copy)]
pub struct MadviseVma {
    /// Start address (page-aligned).
    pub start: u64,
    /// End address (page-aligned, exclusive).
    pub end: u64,
    /// VMA flags.
    pub flags: u32,
    /// Number of resident pages.
    pub resident_pages: u64,
    /// Number of pages zapped (freed by DONTNEED).
    pub zapped_pages: u64,
    /// Whether this VMA is active.
    pub active: bool,
}

impl MadviseVma {
    /// Create an empty VMA.
    pub const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            flags: 0,
            resident_pages: 0,
            zapped_pages: 0,
            active: false,
        }
    }

    /// Size of the VMA in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Number of pages in the VMA.
    pub fn page_count(&self) -> u64 {
        self.size() / PAGE_SIZE
    }

    /// Check if the VMA is shared.
    pub fn is_shared(&self) -> bool {
        self.flags & VmaFlags::SHARED != 0
    }

    /// Check if the VMA is file-backed.
    pub fn is_file_backed(&self) -> bool {
        self.flags & VmaFlags::FILE_BACKED != 0
    }

    /// Check if the VMA contains the address.
    pub fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.start && addr < self.end
    }

    /// Check if the VMA overlaps the given range.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.active && self.start < end && self.end > start
    }
}

// -------------------------------------------------------------------
// MadviseResult
// -------------------------------------------------------------------

/// Outcome of an madvise operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MadviseResult {
    /// Advice was successfully applied.
    Applied,
    /// No VMAs in the range needed modification.
    NoOp,
    /// Pages were zapped (freed) by DONTNEED/FREE.
    PagesZapped(u64),
    /// VMA flags were updated.
    FlagsUpdated,
    /// Pages were populated (WILLNEED/POPULATE).
    PagesPopulated(u64),
    /// Pages were moved to inactive list (COLD/PAGEOUT).
    PagesDemoted(u64),
}

// -------------------------------------------------------------------
// MadviseStats
// -------------------------------------------------------------------

/// Statistics for madvise operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct MadviseStats {
    /// Total madvise calls processed.
    pub total_calls: u64,
    /// Number of DONTNEED operations.
    pub dontneed_calls: u64,
    /// Number of WILLNEED operations.
    pub willneed_calls: u64,
    /// Number of FREE operations.
    pub free_calls: u64,
    /// Number of HUGEPAGE operations.
    pub hugepage_calls: u64,
    /// Number of NOHUGEPAGE operations.
    pub nohugepage_calls: u64,
    /// Total pages zapped.
    pub pages_zapped: u64,
    /// Total pages populated.
    pub pages_populated: u64,
    /// Number of operations rejected due to permissions.
    pub rejected: u64,
}

// -------------------------------------------------------------------
// MadviseOps
// -------------------------------------------------------------------

/// Main madvise handler.
///
/// Processes madvise requests by looking up affected VMAs, checking
/// permissions, and applying the requested advice (modifying VMA
/// flags, freeing pages, or adjusting access patterns).
pub struct MadviseOps {
    /// VMA table.
    vmas: [MadviseVma; MAX_VMAS],
    /// Number of VMAs.
    vma_count: usize,
    /// Statistics.
    stats: MadviseStats,
}

impl MadviseOps {
    /// Create a new madvise handler.
    pub fn new() -> Self {
        Self {
            vmas: [MadviseVma::empty(); MAX_VMAS],
            vma_count: 0,
            stats: MadviseStats::default(),
        }
    }

    /// Register a VMA for madvise tracking.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the VMA table is full, or
    /// `InvalidArgument` if the range is invalid.
    pub fn register_vma(&mut self, start: u64, end: u64, flags: u32) -> Result<usize> {
        if start >= end || start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.vma_count >= MAX_VMAS {
            return Err(Error::OutOfMemory);
        }

        let idx = self.vma_count;
        self.vmas[idx] = MadviseVma {
            start,
            end,
            flags,
            resident_pages: (end - start) / PAGE_SIZE,
            zapped_pages: 0,
            active: true,
        };
        self.vma_count += 1;
        Ok(idx)
    }

    /// Apply madvise advice to a memory range.
    ///
    /// Walks all VMAs overlapping the specified range and applies
    /// the requested advice to each.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the range is invalid or the
    /// advice is not applicable.
    pub fn do_madvise(
        &mut self,
        start: u64,
        len: u64,
        advice: MadviseAdvice,
    ) -> Result<MadviseResult> {
        if len == 0 {
            return Err(Error::InvalidArgument);
        }
        if start % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }

        let end = start.saturating_add(len);
        let aligned_end = (end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        self.stats.total_calls += 1;

        // Find all VMAs overlapping the range.
        let mut applied = false;
        let mut total_result = MadviseResult::NoOp;

        for i in 0..self.vma_count {
            if !self.vmas[i].overlaps(start, aligned_end) {
                continue;
            }

            let result = self.apply_advice_to_vma(i, start, aligned_end, advice)?;
            if result != MadviseResult::NoOp {
                applied = true;
                total_result = result;
            }
        }

        if !applied {
            return Ok(MadviseResult::NoOp);
        }

        Ok(total_result)
    }

    /// Apply advice to a single VMA.
    fn apply_advice_to_vma(
        &mut self,
        vma_idx: usize,
        range_start: u64,
        range_end: u64,
        advice: MadviseAdvice,
    ) -> Result<MadviseResult> {
        let vma = &self.vmas[vma_idx];

        // Calculate the overlap region.
        let overlap_start = vma.start.max(range_start);
        let overlap_end = vma.end.min(range_end);
        if overlap_start >= overlap_end {
            return Ok(MadviseResult::NoOp);
        }

        // Check permissions for destructive advice on shared mappings.
        if advice.is_destructive() && vma.is_shared() {
            if !matches!(advice, MadviseAdvice::Remove) {
                self.stats.rejected += 1;
                return Err(Error::PermissionDenied);
            }
        }

        match advice {
            MadviseAdvice::Normal => {
                self.vmas[vma_idx].flags &= !(VmaFlags::SEQ_READ | VmaFlags::RAND_READ);
                Ok(MadviseResult::FlagsUpdated)
            }
            MadviseAdvice::Sequential => {
                self.vmas[vma_idx].flags |= VmaFlags::SEQ_READ;
                self.vmas[vma_idx].flags &= !VmaFlags::RAND_READ;
                Ok(MadviseResult::FlagsUpdated)
            }
            MadviseAdvice::Random => {
                self.vmas[vma_idx].flags |= VmaFlags::RAND_READ;
                self.vmas[vma_idx].flags &= !VmaFlags::SEQ_READ;
                Ok(MadviseResult::FlagsUpdated)
            }
            MadviseAdvice::WillNeed => {
                let pages = self.populate_range(vma_idx, overlap_start, overlap_end);
                self.stats.willneed_calls += 1;
                self.stats.pages_populated += pages;
                Ok(MadviseResult::PagesPopulated(pages))
            }
            MadviseAdvice::DontNeed => {
                let zapped = self.zap_range(vma_idx, overlap_start, overlap_end);
                self.stats.dontneed_calls += 1;
                self.stats.pages_zapped += zapped;
                Ok(MadviseResult::PagesZapped(zapped))
            }
            MadviseAdvice::Free => {
                let zapped = self.lazy_free_range(vma_idx, overlap_start, overlap_end);
                self.stats.free_calls += 1;
                self.stats.pages_zapped += zapped;
                Ok(MadviseResult::PagesZapped(zapped))
            }
            MadviseAdvice::HugePage => {
                self.vmas[vma_idx].flags |= VmaFlags::HUGEPAGE;
                self.vmas[vma_idx].flags &= !VmaFlags::NOHUGEPAGE;
                self.stats.hugepage_calls += 1;
                Ok(MadviseResult::FlagsUpdated)
            }
            MadviseAdvice::NoHugePage => {
                self.vmas[vma_idx].flags |= VmaFlags::NOHUGEPAGE;
                self.vmas[vma_idx].flags &= !VmaFlags::HUGEPAGE;
                self.stats.nohugepage_calls += 1;
                Ok(MadviseResult::FlagsUpdated)
            }
            MadviseAdvice::Mergeable => {
                self.vmas[vma_idx].flags |= VmaFlags::MERGEABLE;
                Ok(MadviseResult::FlagsUpdated)
            }
            MadviseAdvice::Unmergeable => {
                self.vmas[vma_idx].flags &= !VmaFlags::MERGEABLE;
                Ok(MadviseResult::FlagsUpdated)
            }
            MadviseAdvice::Cold | MadviseAdvice::PageOut => {
                let demoted = self.demote_range(vma_idx, overlap_start, overlap_end);
                Ok(MadviseResult::PagesDemoted(demoted))
            }
            MadviseAdvice::Populate => {
                let pages = self.populate_range(vma_idx, overlap_start, overlap_end);
                self.stats.pages_populated += pages;
                Ok(MadviseResult::PagesPopulated(pages))
            }
            MadviseAdvice::Remove => {
                let zapped = self.zap_range(vma_idx, overlap_start, overlap_end);
                self.stats.pages_zapped += zapped;
                Ok(MadviseResult::PagesZapped(zapped))
            }
            MadviseAdvice::Collapse => {
                // Try to collapse small pages into huge pages.
                self.vmas[vma_idx].flags |= VmaFlags::HUGEPAGE;
                Ok(MadviseResult::FlagsUpdated)
            }
            MadviseAdvice::SoftOffline | MadviseAdvice::HwPoison => Ok(MadviseResult::Applied),
        }
    }

    /// Zap (free) page table entries in the given range.
    ///
    /// Returns the number of pages freed.
    fn zap_range(&mut self, vma_idx: usize, start: u64, end: u64) -> u64 {
        let pages = ((end - start) / PAGE_SIZE).min(MAX_ZAP_PAGES as u64);
        let vma = &mut self.vmas[vma_idx];
        vma.resident_pages = vma.resident_pages.saturating_sub(pages);
        vma.zapped_pages += pages;
        pages
    }

    /// Lazily free pages in the given range (MADV_FREE behavior).
    ///
    /// Pages are marked as freeable but not immediately reclaimed.
    fn lazy_free_range(&mut self, vma_idx: usize, start: u64, end: u64) -> u64 {
        let pages = ((end - start) / PAGE_SIZE).min(MAX_ZAP_PAGES as u64);
        let vma = &mut self.vmas[vma_idx];
        vma.zapped_pages += pages;
        pages
    }

    /// Populate (prefetch) pages in the given range.
    fn populate_range(&mut self, vma_idx: usize, start: u64, end: u64) -> u64 {
        let pages = (end - start) / PAGE_SIZE;
        let vma = &mut self.vmas[vma_idx];
        vma.resident_pages = vma.resident_pages.saturating_add(pages);
        pages
    }

    /// Demote pages in the range to the inactive list.
    fn demote_range(&self, _vma_idx: usize, start: u64, end: u64) -> u64 {
        (end - start) / PAGE_SIZE
    }

    /// Get statistics.
    pub fn statistics(&self) -> &MadviseStats {
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
    pub fn get_vma(&self, idx: usize) -> Result<&MadviseVma> {
        if idx >= self.vma_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.vmas[idx])
    }
}
