// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Multi-level page table walker.
//!
//! Provides a generic walker that descends through the x86_64 4-level
//! page table hierarchy (PGD → PUD → PMD → PTE), invoking caller-
//! supplied callbacks at each level. The walker detects huge pages at
//! PMD (2 MiB) and PUD (1 GiB) levels and supports early termination.
//!
//! - [`PtWalkAction`] — callback return value controlling iteration
//! - [`PtLevel`] — page table levels (PGD/PUD/PMD/PTE)
//! - [`PtWalkEntry`] — information about a visited page table entry
//! - [`PageTableWalker`] — the main walker engine
//! - [`WalkStats`] — statistics collected during a walk

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Number of entries per page table level (512 for x86_64).
const ENTRIES_PER_TABLE: usize = 512;

/// Bits covered by each page table level.
const LEVEL_SHIFT: [u32; 4] = [39, 30, 21, 12];

/// Entry mask for extracting table index (9 bits).
const INDEX_MASK: u64 = 0x1FF;

/// PTE flag: entry is present.
const PTE_PRESENT: u64 = 1 << 0;

/// PTE flag: entry is writable.
const PTE_WRITABLE: u64 = 1 << 1;

/// PTE flag: entry is user-accessible.
const PTE_USER: u64 = 1 << 2;

/// PTE flag: entry is a huge page.
const PTE_HUGE: u64 = 1 << 7;

/// PTE flag: no-execute.
const PTE_NX: u64 = 1 << 63;

/// Mask for extracting the physical frame number from a PTE.
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Maximum walk depth (4-level paging).
const MAX_DEPTH: usize = 4;

/// Maximum number of entries in the walk log.
const MAX_WALK_LOG: usize = 256;

/// Maximum number of ranges that can be walked in a batch.
const MAX_BATCH_RANGES: usize = 16;

// -------------------------------------------------------------------
// PtWalkAction
// -------------------------------------------------------------------

/// Action returned by a walk callback to control iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PtWalkAction {
    /// Continue descending into the next level.
    #[default]
    Continue,
    /// Skip the rest of this subtree and move to the next entry.
    Skip,
    /// Stop the entire walk immediately.
    Stop,
}

// -------------------------------------------------------------------
// PtLevel
// -------------------------------------------------------------------

/// Page table levels in the x86_64 4-level hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PtLevel {
    /// Page Global Directory (level 4, PML4) — 512 GiB per entry.
    #[default]
    Pgd = 0,
    /// Page Upper Directory (level 3, PDPT) — 1 GiB per entry.
    Pud = 1,
    /// Page Middle Directory (level 2, PD) — 2 MiB per entry.
    Pmd = 2,
    /// Page Table Entry (level 1) — 4 KiB per entry.
    Pte = 3,
}

impl PtLevel {
    /// Returns the shift value for this level.
    fn shift(self) -> u32 {
        LEVEL_SHIFT[self as usize]
    }

    /// Returns the page size mapped at this level.
    fn page_size(self) -> u64 {
        1u64 << self.shift()
    }

    /// Returns the next (deeper) level, or `None` at PTE level.
    fn next(self) -> Option<PtLevel> {
        match self {
            PtLevel::Pgd => Some(PtLevel::Pud),
            PtLevel::Pud => Some(PtLevel::Pmd),
            PtLevel::Pmd => Some(PtLevel::Pte),
            PtLevel::Pte => None,
        }
    }
}

// -------------------------------------------------------------------
// PtWalkEntry
// -------------------------------------------------------------------

/// Information about a single page table entry visited during a walk.
#[derive(Debug, Clone, Copy, Default)]
pub struct PtWalkEntry {
    /// Virtual address this entry maps.
    pub vaddr: u64,
    /// Physical address (frame base) from the entry.
    pub paddr: u64,
    /// Raw PTE flags.
    pub flags: u64,
    /// Page table level at which this entry was found.
    pub level: PtLevel,
    /// Whether this entry maps a huge page (2 MiB or 1 GiB).
    pub is_huge: bool,
    /// Whether the entry is present (mapped).
    pub is_present: bool,
    /// Index within the table at this level.
    pub index: usize,
}

impl PtWalkEntry {
    /// Creates a new walk entry.
    fn new(vaddr: u64, pte_raw: u64, level: PtLevel, index: usize) -> Self {
        let is_present = pte_raw & PTE_PRESENT != 0;
        let is_huge = pte_raw & PTE_HUGE != 0;
        Self {
            vaddr,
            paddr: pte_raw & PTE_ADDR_MASK,
            flags: pte_raw,
            level,
            is_huge,
            is_present,
            index,
        }
    }

    /// Returns `true` if the entry has the writable flag set.
    pub fn is_writable(&self) -> bool {
        self.flags & PTE_WRITABLE != 0
    }

    /// Returns `true` if the entry has the user flag set.
    pub fn is_user(&self) -> bool {
        self.flags & PTE_USER != 0
    }

    /// Returns `true` if the entry has the no-execute flag set.
    pub fn is_no_execute(&self) -> bool {
        self.flags & PTE_NX != 0
    }

    /// Returns the page size mapped by this entry.
    pub fn page_size(&self) -> u64 {
        if self.is_huge {
            self.level.page_size()
        } else {
            PAGE_SIZE
        }
    }
}

// -------------------------------------------------------------------
// WalkRange
// -------------------------------------------------------------------

/// A virtual address range to walk.
#[derive(Debug, Clone, Copy, Default)]
pub struct WalkRange {
    /// Start virtual address (inclusive, page-aligned).
    pub start: u64,
    /// End virtual address (exclusive, page-aligned).
    pub end: u64,
}

impl WalkRange {
    /// Creates a new walk range.
    pub fn new(start: u64, end: u64) -> Result<Self> {
        if start >= end {
            return Err(Error::InvalidArgument);
        }
        if start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { start, end })
    }

    /// Returns the number of base (4 KiB) pages covered.
    pub fn page_count(&self) -> u64 {
        (self.end - self.start) / PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// WalkStats
// -------------------------------------------------------------------

/// Statistics collected during a page table walk.
#[derive(Debug, Clone, Copy, Default)]
pub struct WalkStats {
    /// Total entries visited.
    pub entries_visited: u64,
    /// Present entries seen.
    pub present_entries: u64,
    /// Not-present (unmapped) entries.
    pub not_present_entries: u64,
    /// Huge pages encountered (PMD level, 2 MiB).
    pub huge_2m_pages: u64,
    /// Huge pages encountered (PUD level, 1 GiB).
    pub huge_1g_pages: u64,
    /// Number of times the walk descended a level.
    pub descents: u64,
    /// Number of entries skipped via [`PtWalkAction::Skip`].
    pub skipped: u64,
    /// Whether the walk was stopped early.
    pub stopped_early: bool,
}

impl WalkStats {
    /// Resets all counters to zero.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// PtWalkCallback
// -------------------------------------------------------------------

/// Callback type for page table walk. Receives an entry and returns
/// an action controlling the walk.
pub type PtWalkCallback = fn(&PtWalkEntry) -> PtWalkAction;

// -------------------------------------------------------------------
// WalkLog
// -------------------------------------------------------------------

/// A fixed-capacity log of visited entries for post-walk analysis.
#[derive(Debug)]
pub struct WalkLog {
    /// Logged entries.
    entries: [PtWalkEntry; MAX_WALK_LOG],
    /// Number of entries currently in the log.
    count: usize,
}

impl Default for WalkLog {
    fn default() -> Self {
        Self {
            entries: [PtWalkEntry::default(); MAX_WALK_LOG],
            count: 0,
        }
    }
}

impl WalkLog {
    /// Creates a new empty walk log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an entry if space remains.
    pub fn push(&mut self, entry: PtWalkEntry) -> bool {
        if self.count < MAX_WALK_LOG {
            self.entries[self.count] = entry;
            self.count += 1;
            true
        } else {
            false
        }
    }

    /// Returns the number of logged entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the entry at the given index.
    pub fn get(&self, index: usize) -> Option<&PtWalkEntry> {
        if index < self.count {
            Some(&self.entries[index])
        } else {
            None
        }
    }

    /// Clears the log.
    pub fn clear(&mut self) {
        self.count = 0;
    }
}

// -------------------------------------------------------------------
// SimulatedTable
// -------------------------------------------------------------------

/// A simulated page table level containing raw entries.
///
/// In a real kernel this would be backed by physical memory; here we
/// keep an array of u64 entries for testing and development.
#[derive(Debug)]
pub struct SimulatedTable {
    /// Raw page table entries (512 per level).
    entries: [u64; ENTRIES_PER_TABLE],
}

impl Default for SimulatedTable {
    fn default() -> Self {
        Self {
            entries: [0u64; ENTRIES_PER_TABLE],
        }
    }
}

impl SimulatedTable {
    /// Creates a new zeroed page table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a raw entry at the given index.
    pub fn set_entry(&mut self, index: usize, value: u64) {
        if index < ENTRIES_PER_TABLE {
            self.entries[index] = value;
        }
    }

    /// Reads the raw entry at the given index.
    pub fn get_entry(&self, index: usize) -> u64 {
        if index < ENTRIES_PER_TABLE {
            self.entries[index]
        } else {
            0
        }
    }
}

// -------------------------------------------------------------------
// PageTableWalker
// -------------------------------------------------------------------

/// Multi-level page table walker.
///
/// Simulates walking through a 4-level x86_64 page table hierarchy.
/// The walker stores flat arrays of table entries indexed by level
/// for development/testing purposes.
///
/// # Example flow
///
/// ```text
/// walker.walk_range(0x1000, 0x5000, callback)
///   → for each PGD entry covering the range:
///       callback(pgd_entry) → Continue/Skip/Stop
///       → for each PUD entry:
///           callback(pud_entry)
///           (if huge page at PUD → log 1 GiB page, skip descent)
///           → for each PMD entry:
///               callback(pmd_entry)
///               (if huge page at PMD → log 2 MiB page, skip descent)
///               → for each PTE:
///                   callback(pte_entry)
/// ```
pub struct PageTableWalker {
    /// Flat entry storage per level (level → entries).
    level_entries: [[u64; ENTRIES_PER_TABLE]; MAX_DEPTH],
    /// Walk statistics.
    stats: WalkStats,
    /// Walk log for post-walk analysis.
    log: WalkLog,
    /// Whether to record entries in the walk log.
    logging_enabled: bool,
    /// Batch ranges for multi-range walks.
    batch_ranges: [WalkRange; MAX_BATCH_RANGES],
    /// Number of batch ranges queued.
    batch_count: usize,
}

impl Default for PageTableWalker {
    fn default() -> Self {
        Self {
            level_entries: [[0u64; ENTRIES_PER_TABLE]; MAX_DEPTH],
            stats: WalkStats::default(),
            log: WalkLog::new(),
            logging_enabled: false,
            batch_ranges: [WalkRange::default(); MAX_BATCH_RANGES],
            batch_count: 0,
        }
    }
}

impl PageTableWalker {
    /// Creates a new page table walker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables or disables entry logging during walks.
    pub fn set_logging(&mut self, enabled: bool) {
        self.logging_enabled = enabled;
    }

    /// Returns a reference to the walk statistics.
    pub fn stats(&self) -> &WalkStats {
        &self.stats
    }

    /// Returns a reference to the walk log.
    pub fn log(&self) -> &WalkLog {
        &self.log
    }

    /// Clears statistics and log for a fresh walk.
    pub fn reset(&mut self) {
        self.stats.reset();
        self.log.clear();
        self.batch_count = 0;
    }

    /// Sets a raw PTE at the given level and index.
    pub fn set_entry(&mut self, level: PtLevel, index: usize, value: u64) {
        let lvl = level as usize;
        if lvl < MAX_DEPTH && index < ENTRIES_PER_TABLE {
            self.level_entries[lvl][index] = value;
        }
    }

    /// Reads a raw PTE at the given level and index.
    pub fn get_entry(&self, level: PtLevel, index: usize) -> u64 {
        let lvl = level as usize;
        if lvl < MAX_DEPTH && index < ENTRIES_PER_TABLE {
            self.level_entries[lvl][index]
        } else {
            0
        }
    }

    /// Extracts the table index from a virtual address for a given
    /// level.
    fn vaddr_index(vaddr: u64, level: PtLevel) -> usize {
        ((vaddr >> level.shift()) & INDEX_MASK) as usize
    }

    /// Walks a virtual address range, invoking `callback` at each
    /// entry.
    ///
    /// The walk descends through PGD → PUD → PMD → PTE levels.
    /// Huge pages are detected at PUD and PMD levels. The callback
    /// may return [`PtWalkAction::Skip`] to skip a subtree or
    /// [`PtWalkAction::Stop`] to abort the walk.
    pub fn walk_range(&mut self, start: u64, end: u64, callback: PtWalkCallback) -> Result<()> {
        if start >= end {
            return Err(Error::InvalidArgument);
        }
        self.stats.reset();
        self.log.clear();

        let result = self.walk_level(PtLevel::Pgd, start, end, callback);

        result
    }

    /// Recursive level walker.
    fn walk_level(
        &mut self,
        level: PtLevel,
        start: u64,
        end: u64,
        callback: PtWalkCallback,
    ) -> Result<()> {
        let shift = level.shift();
        let level_size = 1u64 << shift;
        let start_idx = Self::vaddr_index(start, level);
        let end_idx = Self::vaddr_index(end.saturating_sub(1), level);

        let mut idx = start_idx;
        while idx <= end_idx && idx < ENTRIES_PER_TABLE {
            let vaddr = (idx as u64) << shift;
            let raw = self.level_entries[level as usize][idx];

            let entry = PtWalkEntry::new(vaddr, raw, level, idx);
            self.stats.entries_visited += 1;

            if entry.is_present {
                self.stats.present_entries += 1;
            } else {
                self.stats.not_present_entries += 1;
            }

            let action = callback(&entry);
            if self.logging_enabled {
                self.log.push(entry);
            }

            match action {
                PtWalkAction::Stop => {
                    self.stats.stopped_early = true;
                    return Ok(());
                }
                PtWalkAction::Skip => {
                    self.stats.skipped += 1;
                    idx += 1;
                    continue;
                }
                PtWalkAction::Continue => {}
            }

            // Check for huge pages at PUD and PMD levels.
            if entry.is_present && entry.is_huge {
                match level {
                    PtLevel::Pud => self.stats.huge_1g_pages += 1,
                    PtLevel::Pmd => self.stats.huge_2m_pages += 1,
                    _ => {}
                }
                idx += 1;
                continue;
            }

            // Descend to the next level if present and not a leaf.
            if entry.is_present {
                if let Some(next_level) = level.next() {
                    self.stats.descents += 1;
                    let child_start = if idx as u64 == (start >> shift) {
                        start
                    } else {
                        vaddr
                    };
                    let child_end_candidate = vaddr + level_size;
                    let child_end = if child_end_candidate < end {
                        child_end_candidate
                    } else {
                        end
                    };
                    self.walk_level(next_level, child_start, child_end, callback)?;
                    if self.stats.stopped_early {
                        return Ok(());
                    }
                }
            }

            idx += 1;
        }

        Ok(())
    }

    /// Queues a range for batch walking.
    pub fn add_batch_range(&mut self, start: u64, end: u64) -> Result<()> {
        if self.batch_count >= MAX_BATCH_RANGES {
            return Err(Error::OutOfMemory);
        }
        let range = WalkRange::new(start, end)?;
        self.batch_ranges[self.batch_count] = range;
        self.batch_count += 1;
        Ok(())
    }

    /// Walks all queued batch ranges.
    pub fn walk_batch(&mut self, callback: PtWalkCallback) -> Result<()> {
        for i in 0..self.batch_count {
            let start = self.batch_ranges[i].start;
            let end = self.batch_ranges[i].end;
            self.walk_level(PtLevel::Pgd, start, end, callback)?;
            if self.stats.stopped_early {
                break;
            }
        }
        self.batch_count = 0;
        Ok(())
    }

    /// Walks a single virtual address and returns the final entry
    /// found (deepest level).
    pub fn walk_addr(&mut self, vaddr: u64) -> Option<PtWalkEntry> {
        let mut current_level = PtLevel::Pgd;
        loop {
            let idx = Self::vaddr_index(vaddr, current_level);
            let raw = self.level_entries[current_level as usize][idx];
            let entry = PtWalkEntry::new(vaddr, raw, current_level, idx);

            if !entry.is_present {
                return Some(entry);
            }

            if entry.is_huge {
                return Some(entry);
            }

            match current_level.next() {
                Some(next) => current_level = next,
                None => return Some(entry),
            }
        }
    }

    /// Counts the number of present entries at a given level across
    /// the entire table.
    pub fn count_present(&self, level: PtLevel) -> usize {
        let lvl = level as usize;
        if lvl >= MAX_DEPTH {
            return 0;
        }
        self.level_entries[lvl]
            .iter()
            .filter(|&&e| e & PTE_PRESENT != 0)
            .count()
    }

    /// Counts huge page entries at the given level.
    pub fn count_huge(&self, level: PtLevel) -> usize {
        let lvl = level as usize;
        if lvl >= MAX_DEPTH {
            return 0;
        }
        self.level_entries[lvl]
            .iter()
            .filter(|&&e| e & PTE_PRESENT != 0 && e & PTE_HUGE != 0)
            .count()
    }
}
