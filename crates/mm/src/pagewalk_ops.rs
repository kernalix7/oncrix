// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page table walking operations.
//!
//! Provides a structured page-table walk interface that descends through
//! the four levels of x86_64 paging (PML4 → PDPT → PD → PT) and
//! invokes caller-supplied callbacks at each level. This separates the
//! walk logic from the action taken at each entry, enabling generic
//! visitors for dumping, permission auditing, and unmapping.
//!
//! # Design
//!
//! ```text
//!  walk_page_range(start, end, ops)
//!     │
//!     ├─ for each PML4 entry  → ops.pml4_entry(...)
//!     │   ├─ for each PDPT    → ops.pdpt_entry(...)
//!     │   │   ├─ for each PD  → ops.pd_entry(...)
//!     │   │   │   └─ for each PT → ops.pt_entry(...)
//!     │   │   │                    (leaf: 4 KiB page)
//!     │   │   └─ (huge: 1 GiB page)
//!     │   └─ (huge: 2 MiB — detected at PD level)
//!     └─ return walk result
//! ```
//!
//! # Key Types
//!
//! - [`WalkLevel`] — paging level identifier
//! - [`WalkEntry`] — snapshot of a page-table entry at any level
//! - [`WalkAction`] — action the walker should take after a callback
//! - [`PageWalkOps`] — per-address-range walk state and results
//! - [`PageWalkStats`] — walk statistics
//!
//! Reference: Linux `mm/pagewalk.c`, `include/linux/pagewalk.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Number of entries per page-table page (512 for x86_64).
const ENTRIES_PER_TABLE: usize = 512;

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// 2 MiB huge-page size.
const HUGE_2M: u64 = 2 * 1024 * 1024;

/// 1 GiB huge-page size.
const HUGE_1G: u64 = 1024 * 1024 * 1024;

/// Maximum walk depth (PML4 = 0..3 = PT).
const MAX_LEVELS: usize = 4;

/// Maximum walk ranges tracked simultaneously.
const MAX_WALK_RANGES: usize = 64;

// -------------------------------------------------------------------
// WalkLevel
// -------------------------------------------------------------------

/// Paging level identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkLevel {
    /// PML4 (level 4).
    Pml4,
    /// Page Directory Pointer Table (level 3).
    Pdpt,
    /// Page Directory (level 2).
    Pd,
    /// Page Table (level 1, leaf).
    Pt,
}

impl WalkLevel {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Pml4 => "PML4",
            Self::Pdpt => "PDPT",
            Self::Pd => "PD",
            Self::Pt => "PT",
        }
    }

    /// Return the numeric depth (0 = PML4, 3 = PT).
    pub const fn depth(&self) -> u32 {
        match self {
            Self::Pml4 => 0,
            Self::Pdpt => 1,
            Self::Pd => 2,
            Self::Pt => 3,
        }
    }

    /// Return the page size mapped at this level.
    pub const fn page_size(&self) -> u64 {
        match self {
            Self::Pml4 => HUGE_1G * ENTRIES_PER_TABLE as u64,
            Self::Pdpt => HUGE_1G,
            Self::Pd => HUGE_2M,
            Self::Pt => PAGE_SIZE,
        }
    }
}

// -------------------------------------------------------------------
// WalkAction
// -------------------------------------------------------------------

/// Action the walker should take after visiting an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkAction {
    /// Continue walking into child table.
    Continue,
    /// Skip this subtree (do not descend).
    Skip,
    /// Abort the entire walk.
    Abort,
}

// -------------------------------------------------------------------
// WalkEntry
// -------------------------------------------------------------------

/// Snapshot of a page-table entry encountered during a walk.
#[derive(Debug, Clone, Copy)]
pub struct WalkEntry {
    /// Virtual address this entry maps.
    virt_addr: u64,
    /// Physical address from the entry.
    phys_addr: u64,
    /// Paging level.
    level: WalkLevel,
    /// Raw entry value.
    raw: u64,
    /// Whether the entry is present.
    present: bool,
    /// Whether this is a huge-page entry.
    huge: bool,
    /// Whether the entry is writable.
    writable: bool,
    /// Whether the entry is user-accessible.
    user: bool,
    /// Whether no-execute is set.
    no_exec: bool,
}

impl WalkEntry {
    /// Create a new walk entry.
    pub const fn new(virt_addr: u64, phys_addr: u64, level: WalkLevel, raw: u64) -> Self {
        Self {
            virt_addr,
            phys_addr,
            level,
            raw,
            present: false,
            huge: false,
            writable: false,
            user: false,
            no_exec: false,
        }
    }

    /// Return the virtual address.
    pub const fn virt_addr(&self) -> u64 {
        self.virt_addr
    }

    /// Return the physical address.
    pub const fn phys_addr(&self) -> u64 {
        self.phys_addr
    }

    /// Return the level.
    pub const fn level(&self) -> WalkLevel {
        self.level
    }

    /// Return the raw entry value.
    pub const fn raw(&self) -> u64 {
        self.raw
    }

    /// Check present.
    pub const fn present(&self) -> bool {
        self.present
    }

    /// Check huge.
    pub const fn huge(&self) -> bool {
        self.huge
    }

    /// Check writable.
    pub const fn writable(&self) -> bool {
        self.writable
    }

    /// Check user.
    pub const fn user(&self) -> bool {
        self.user
    }

    /// Check no-execute.
    pub const fn no_exec(&self) -> bool {
        self.no_exec
    }

    /// Set present flag.
    pub fn set_present(&mut self, val: bool) {
        self.present = val;
    }

    /// Set huge flag.
    pub fn set_huge(&mut self, val: bool) {
        self.huge = val;
    }

    /// Set writable flag.
    pub fn set_writable(&mut self, val: bool) {
        self.writable = val;
    }

    /// Set user flag.
    pub fn set_user(&mut self, val: bool) {
        self.user = val;
    }

    /// Set no-execute flag.
    pub fn set_no_exec(&mut self, val: bool) {
        self.no_exec = val;
    }
}

impl Default for WalkEntry {
    fn default() -> Self {
        Self {
            virt_addr: 0,
            phys_addr: 0,
            level: WalkLevel::Pt,
            raw: 0,
            present: false,
            huge: false,
            writable: false,
            user: false,
            no_exec: false,
        }
    }
}

// -------------------------------------------------------------------
// PageWalkStats
// -------------------------------------------------------------------

/// Walk statistics.
#[derive(Debug, Clone, Copy)]
pub struct PageWalkStats {
    /// Total walks started.
    pub walks_started: u64,
    /// Total walks completed.
    pub walks_completed: u64,
    /// Total walks aborted.
    pub walks_aborted: u64,
    /// Total entries visited.
    pub entries_visited: u64,
    /// Huge pages encountered.
    pub huge_pages: u64,
    /// Not-present entries encountered.
    pub not_present: u64,
}

impl PageWalkStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            walks_started: 0,
            walks_completed: 0,
            walks_aborted: 0,
            entries_visited: 0,
            huge_pages: 0,
            not_present: 0,
        }
    }

    /// Walk completion rate as percent.
    pub const fn completion_pct(&self) -> u64 {
        if self.walks_started == 0 {
            return 0;
        }
        self.walks_completed * 100 / self.walks_started
    }
}

impl Default for PageWalkStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PageWalkOps
// -------------------------------------------------------------------

/// Per-address-range walk state and result collector.
pub struct PageWalkOps {
    /// Ranges being walked: (start_vaddr, end_vaddr).
    ranges: [(u64, u64); MAX_WALK_RANGES],
    /// Number of active ranges.
    range_count: usize,
    /// Collected entries.
    entries: [WalkEntry; ENTRIES_PER_TABLE],
    /// Number of collected entries.
    entry_count: usize,
    /// Statistics.
    stats: PageWalkStats,
}

impl PageWalkOps {
    /// Create new walk ops.
    pub const fn new() -> Self {
        Self {
            ranges: [(0u64, 0u64); MAX_WALK_RANGES],
            range_count: 0,
            entries: [const {
                WalkEntry {
                    virt_addr: 0,
                    phys_addr: 0,
                    level: WalkLevel::Pt,
                    raw: 0,
                    present: false,
                    huge: false,
                    writable: false,
                    user: false,
                    no_exec: false,
                }
            }; ENTRIES_PER_TABLE],
            entry_count: 0,
            stats: PageWalkStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &PageWalkStats {
        &self.stats
    }

    /// Return the number of collected entries.
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Add a walk range.
    pub fn add_range(&mut self, start: u64, end: u64) -> Result<()> {
        if start >= end {
            return Err(Error::InvalidArgument);
        }
        if self.range_count >= MAX_WALK_RANGES {
            return Err(Error::OutOfMemory);
        }
        self.ranges[self.range_count] = (start, end);
        self.range_count += 1;
        Ok(())
    }

    /// Record visiting an entry.
    pub fn record_entry(&mut self, entry: WalkEntry) -> Result<()> {
        if self.entry_count >= ENTRIES_PER_TABLE {
            return Err(Error::OutOfMemory);
        }
        self.stats.entries_visited += 1;
        if entry.huge() {
            self.stats.huge_pages += 1;
        }
        if !entry.present() {
            self.stats.not_present += 1;
        }
        self.entries[self.entry_count] = entry;
        self.entry_count += 1;
        Ok(())
    }

    /// Start a walk.
    pub fn begin_walk(&mut self) {
        self.stats.walks_started += 1;
    }

    /// Complete a walk.
    pub fn end_walk(&mut self, aborted: bool) {
        if aborted {
            self.stats.walks_aborted += 1;
        } else {
            self.stats.walks_completed += 1;
        }
    }

    /// Get a collected entry by index.
    pub fn get_entry(&self, index: usize) -> Option<&WalkEntry> {
        if index < self.entry_count {
            Some(&self.entries[index])
        } else {
            None
        }
    }

    /// Clear collected entries for reuse.
    pub fn clear_entries(&mut self) {
        self.entry_count = 0;
    }
}

impl Default for PageWalkOps {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the number of entries per page table.
pub const fn entries_per_table() -> usize {
    ENTRIES_PER_TABLE
}

/// Return the maximum walk depth.
pub const fn max_walk_depth() -> usize {
    MAX_LEVELS
}

/// Compute the PML4 index for a virtual address.
pub const fn pml4_index(vaddr: u64) -> usize {
    ((vaddr >> 39) & 0x1FF) as usize
}

/// Compute the PDPT index for a virtual address.
pub const fn pdpt_index(vaddr: u64) -> usize {
    ((vaddr >> 30) & 0x1FF) as usize
}

/// Compute the PD index for a virtual address.
pub const fn pd_index(vaddr: u64) -> usize {
    ((vaddr >> 21) & 0x1FF) as usize
}

/// Compute the PT index for a virtual address.
pub const fn pt_index(vaddr: u64) -> usize {
    ((vaddr >> 12) & 0x1FF) as usize
}
