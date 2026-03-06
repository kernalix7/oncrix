// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Reverse mapping (rmap) page table walk.
//!
//! Implements the reverse mapping walk that, given a physical page,
//! locates all virtual addresses mapping that page across all
//! processes. Used by page migration, CoW, and reclaim to find and
//! update all PTEs pointing to a given page.
//!
//! - [`RmapType`] — mapping type (anon / file)
//! - [`RmapEntry`] — a single reverse mapping entry
//! - [`RmapWalkControl`] — walk configuration
//! - [`RmapStats`] — walk statistics
//! - [`RmapTable`] — the reverse mapping table
//!
//! Reference: Linux `mm/rmap.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum entries in the rmap table.
const MAX_ENTRIES: usize = 1024;

/// Maximum rmap entries per page.
const MAX_MAPS_PER_PAGE: usize = 64;

// -------------------------------------------------------------------
// RmapType
// -------------------------------------------------------------------

/// Mapping type for reverse mapping entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RmapType {
    /// Anonymous mapping.
    #[default]
    Anon,
    /// File-backed mapping.
    File,
    /// Device mapping.
    Device,
}

// -------------------------------------------------------------------
// RmapEntry
// -------------------------------------------------------------------

/// A single reverse mapping entry linking a PFN to a virtual mapping.
#[derive(Debug, Clone, Copy, Default)]
pub struct RmapEntry {
    /// Page frame number.
    pub pfn: u64,
    /// Virtual address in the mapping process.
    pub vaddr: u64,
    /// Process ID owning this mapping.
    pub pid: u64,
    /// Mapping type.
    pub rmap_type: RmapType,
    /// Whether this mapping is writable.
    pub writable: bool,
    /// Whether this slot is active.
    pub active: bool,
}

impl RmapEntry {
    /// Creates a new rmap entry.
    pub fn new(pfn: u64, vaddr: u64, pid: u64, rmap_type: RmapType, writable: bool) -> Self {
        Self {
            pfn,
            vaddr,
            pid,
            rmap_type,
            writable,
            active: true,
        }
    }
}

// -------------------------------------------------------------------
// RmapWalkControl
// -------------------------------------------------------------------

/// Configuration for an rmap walk.
#[derive(Debug, Clone, Copy)]
pub struct RmapWalkControl {
    /// Target PFN to walk.
    pub target_pfn: u64,
    /// Whether to include anonymous mappings.
    pub walk_anon: bool,
    /// Whether to include file mappings.
    pub walk_file: bool,
    /// Optional PID filter (0 = all processes).
    pub pid_filter: u64,
    /// Maximum entries to return.
    pub max_results: usize,
}

impl Default for RmapWalkControl {
    fn default() -> Self {
        Self {
            target_pfn: 0,
            walk_anon: true,
            walk_file: true,
            pid_filter: 0,
            max_results: MAX_MAPS_PER_PAGE,
        }
    }
}

// -------------------------------------------------------------------
// RmapWalkResult
// -------------------------------------------------------------------

/// Result of an rmap walk.
#[derive(Debug, Clone, Copy)]
pub struct RmapWalkResult {
    /// Matching entries found.
    pub entries: [RmapEntry; MAX_MAPS_PER_PAGE],
    /// Number of entries found.
    pub count: usize,
}

impl Default for RmapWalkResult {
    fn default() -> Self {
        Self {
            entries: [RmapEntry::default(); MAX_MAPS_PER_PAGE],
            count: 0,
        }
    }
}

// -------------------------------------------------------------------
// RmapStats
// -------------------------------------------------------------------

/// Rmap walk statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct RmapStats {
    /// Total walks performed.
    pub walks: u64,
    /// Total entries scanned.
    pub entries_scanned: u64,
    /// Total matches found.
    pub matches_found: u64,
    /// Walks that found zero matches.
    pub empty_walks: u64,
    /// Unmap operations performed.
    pub unmaps: u64,
}

impl RmapStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// RmapTable
// -------------------------------------------------------------------

/// The reverse mapping table.
pub struct RmapTable {
    /// Rmap entries.
    entries: [RmapEntry; MAX_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Statistics.
    stats: RmapStats,
}

impl Default for RmapTable {
    fn default() -> Self {
        Self {
            entries: [RmapEntry::default(); MAX_ENTRIES],
            count: 0,
            stats: RmapStats::default(),
        }
    }
}

impl RmapTable {
    /// Creates a new rmap table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a reverse mapping entry.
    pub fn add(
        &mut self,
        pfn: u64,
        vaddr: u64,
        pid: u64,
        rmap_type: RmapType,
        writable: bool,
    ) -> Result<usize> {
        if self.count >= MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.entries[idx] = RmapEntry::new(pfn, vaddr, pid, rmap_type, writable);
        self.count += 1;
        Ok(idx)
    }

    /// Removes a reverse mapping entry.
    pub fn remove(&mut self, idx: usize) -> Result<()> {
        if idx >= self.count || !self.entries[idx].active {
            return Err(Error::NotFound);
        }
        self.entries[idx].active = false;
        Ok(())
    }

    /// Walks the rmap table for a given PFN.
    pub fn walk(&mut self, ctrl: &RmapWalkControl) -> RmapWalkResult {
        let mut result = RmapWalkResult::default();
        self.stats.walks += 1;

        for i in 0..self.count {
            if !self.entries[i].active {
                continue;
            }
            self.stats.entries_scanned += 1;

            if self.entries[i].pfn != ctrl.target_pfn {
                continue;
            }

            // Type filter.
            match self.entries[i].rmap_type {
                RmapType::Anon if !ctrl.walk_anon => continue,
                RmapType::File if !ctrl.walk_file => continue,
                _ => {}
            }

            // PID filter.
            if ctrl.pid_filter != 0 && self.entries[i].pid != ctrl.pid_filter {
                continue;
            }

            if result.count < ctrl.max_results && result.count < MAX_MAPS_PER_PAGE {
                result.entries[result.count] = self.entries[i];
                result.count += 1;
                self.stats.matches_found += 1;
            }
        }

        if result.count == 0 {
            self.stats.empty_walks += 1;
        }
        result
    }

    /// Unmaps all mappings for a given PFN (marks them inactive).
    pub fn unmap_pfn(&mut self, pfn: u64) -> u64 {
        let mut unmapped = 0u64;
        for i in 0..self.count {
            if self.entries[i].active && self.entries[i].pfn == pfn {
                self.entries[i].active = false;
                unmapped += 1;
            }
        }
        self.stats.unmaps += unmapped;
        unmapped
    }

    /// Returns the mapcount for a given PFN.
    pub fn mapcount(&self, pfn: u64) -> usize {
        self.entries[..self.count]
            .iter()
            .filter(|e| e.active && e.pfn == pfn)
            .count()
    }

    /// Returns the total number of entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &RmapStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
