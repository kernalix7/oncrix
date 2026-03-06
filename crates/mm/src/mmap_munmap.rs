// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! munmap implementation (memory region unmapping).
//!
//! Implements the `munmap(2)` system call: removes virtual memory
//! mappings, splits VMAs if the unmap range doesn't cover the
//! entire VMA, and cleans up page tables and swap entries.
//!
//! - [`UnmapType`] — type of unmap operation
//! - [`MunmapRange`] — a range to unmap
//! - [`MunmapVma`] — VMA tracking for unmap
//! - [`MunmapStats`] — unmap statistics
//! - [`MmapMunmap`] — the munmap engine
//!
//! Reference: Linux `mm/mmap.c` (do_munmap, __do_munmap).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Maximum VMAs tracked.
const MAX_VMAS: usize = 256;

/// Maximum unmap operations per batch.
const MAX_BATCH: usize = 64;

// -------------------------------------------------------------------
// UnmapType
// -------------------------------------------------------------------

/// Type of unmap operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnmapType {
    /// Full VMA unmap.
    #[default]
    Full,
    /// Partial unmap (split VMA).
    Partial,
    /// Unmap due to mmap overlap.
    Overlap,
}

// -------------------------------------------------------------------
// MunmapRange
// -------------------------------------------------------------------

/// A range to unmap.
#[derive(Debug, Clone, Copy, Default)]
pub struct MunmapRange {
    /// Start address (page-aligned).
    pub start: u64,
    /// Length in bytes (page-aligned).
    pub length: u64,
}

impl MunmapRange {
    /// Creates a new unmap range.
    pub fn new(start: u64, length: u64) -> Result<Self> {
        if start % PAGE_SIZE != 0 || length % PAGE_SIZE != 0 || length == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { start, length })
    }

    /// Returns the end address (exclusive).
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.length)
    }

    /// Returns the number of pages.
    pub fn nr_pages(&self) -> u64 {
        self.length / PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// MunmapVma
// -------------------------------------------------------------------

/// VMA tracking for munmap.
#[derive(Debug, Clone, Copy, Default)]
pub struct MunmapVma {
    /// VMA start address.
    pub start: u64,
    /// VMA end address.
    pub end: u64,
    /// VMA flags (rwx + shared/private).
    pub flags: u32,
    /// Whether this VMA is active.
    pub active: bool,
}

impl MunmapVma {
    /// Creates a new VMA.
    pub fn new(start: u64, end: u64, flags: u32) -> Self {
        Self {
            start,
            end,
            flags,
            active: true,
        }
    }

    /// Returns the VMA size.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` if the VMA overlaps the given range.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.active && self.start < end && start < self.end
    }

    /// Returns `true` if the range fully covers this VMA.
    pub fn fully_covered(&self, start: u64, end: u64) -> bool {
        self.active && start <= self.start && end >= self.end
    }
}

// -------------------------------------------------------------------
// MunmapStats
// -------------------------------------------------------------------

/// Munmap statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MunmapStats {
    /// Total munmap calls.
    pub calls: u64,
    /// VMAs fully unmapped.
    pub full_unmaps: u64,
    /// VMAs split (partial unmap).
    pub splits: u64,
    /// Total pages unmapped.
    pub pages_unmapped: u64,
    /// Failed unmap attempts.
    pub failures: u64,
}

impl MunmapStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// MmapMunmap
// -------------------------------------------------------------------

/// The munmap engine.
pub struct MmapMunmap {
    /// Tracked VMAs.
    vmas: [MunmapVma; MAX_VMAS],
    /// Number of VMAs.
    vma_count: usize,
    /// Statistics.
    stats: MunmapStats,
}

impl Default for MmapMunmap {
    fn default() -> Self {
        Self {
            vmas: [MunmapVma::default(); MAX_VMAS],
            vma_count: 0,
            stats: MunmapStats::default(),
        }
    }
}

impl MmapMunmap {
    /// Creates a new munmap engine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a VMA for tracking.
    pub fn add_vma(&mut self, start: u64, end: u64, flags: u32) -> Result<usize> {
        if self.vma_count >= MAX_VMAS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.vma_count;
        self.vmas[idx] = MunmapVma::new(start, end, flags);
        self.vma_count += 1;
        Ok(idx)
    }

    /// Performs a munmap operation on the given range.
    pub fn munmap(&mut self, start: u64, length: u64) -> Result<u64> {
        let range = MunmapRange::new(start, length)?;
        let range_end = range.end();
        self.stats.calls += 1;

        let mut total_unmapped = 0u64;

        for i in 0..self.vma_count {
            if !self.vmas[i].overlaps(start, range_end) {
                continue;
            }

            if self.vmas[i].fully_covered(start, range_end) {
                // Full unmap.
                total_unmapped += self.vmas[i].size() / PAGE_SIZE;
                self.vmas[i].active = false;
                self.stats.full_unmaps += 1;
            } else if start <= self.vmas[i].start {
                // Trim start of VMA.
                let overlap = range_end.min(self.vmas[i].end) - self.vmas[i].start;
                total_unmapped += overlap / PAGE_SIZE;
                self.vmas[i].start = range_end.min(self.vmas[i].end);
                self.stats.splits += 1;
            } else if range_end >= self.vmas[i].end {
                // Trim end of VMA.
                let overlap = self.vmas[i].end - start.max(self.vmas[i].start);
                total_unmapped += overlap / PAGE_SIZE;
                self.vmas[i].end = start.max(self.vmas[i].start);
                self.stats.splits += 1;
            } else {
                // Split VMA in the middle.
                let overlap = range_end - start;
                total_unmapped += overlap / PAGE_SIZE;
                let old_end = self.vmas[i].end;
                self.vmas[i].end = start;
                // Create new VMA for the tail.
                if self.vma_count < MAX_VMAS {
                    self.vmas[self.vma_count] =
                        MunmapVma::new(range_end, old_end, self.vmas[i].flags);
                    self.vma_count += 1;
                }
                self.stats.splits += 1;
            }
        }

        self.stats.pages_unmapped += total_unmapped;
        Ok(total_unmapped)
    }

    /// Returns the number of active VMAs.
    pub fn active_vma_count(&self) -> usize {
        self.vmas[..self.vma_count]
            .iter()
            .filter(|v| v.active)
            .count()
    }

    /// Returns statistics.
    pub fn stats(&self) -> &MunmapStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
