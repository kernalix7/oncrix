// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page table walker framework.
//!
//! Provides a generic infrastructure for walking x86_64 4-level page
//! tables. Callers supply callback indices (selecting from registered
//! [`PageWalkOps`] implementations) to process entries at each level.
//! The walker handles huge-page detection, unmapped-region holes, and
//! depth tracking automatically.
//!
//! # Architecture (x86_64 4-level paging)
//!
//! ```text
//! Level 4 (PGD / PML4) — 512 entries, each covers 512 GiB
//! Level 3 (PUD / PDPT) — 512 entries, each covers 1 GiB
//! Level 2 (PMD / PD)   — 512 entries, each covers 2 MiB
//! Level 1 (PTE / PT)   — 512 entries, each covers 4 KiB
//! ```
//!
//! # Subsystems
//!
//! - [`PageWalkAction`] — action returned by callbacks
//! - [`PageWalkOps`] — trait defining per-level callbacks
//! - [`PageWalkRange`] — address range to walk
//! - [`PageWalker`] — single walk state
//! - [`PageWalkSubsystem`] — manager for concurrent walkers
//! - [`PageWalkStats`] — aggregate statistics
//!
//! Reference: Linux `mm/pagewalk.c`, `include/linux/pagewalk.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Huge page size at PMD level (2 MiB).
const PMD_HUGE_SIZE: u64 = 2 * 1024 * 1024;

/// Huge page size at PUD level (1 GiB).
const PUD_HUGE_SIZE: u64 = 1024 * 1024 * 1024;

/// Number of entries per page table level.
const ENTRIES_PER_TABLE: usize = 512;

/// Maximum concurrent walkers.
const MAX_WALKERS: usize = 16;

/// Maximum registered page-walk operations callbacks.
const MAX_OPS: usize = 16;

/// Address span per PML4 entry (512 GiB).
const PGD_SPAN: u64 = 512 * 1024 * 1024 * 1024;

/// Address span per PDPT entry (1 GiB).
const PUD_SPAN: u64 = 1024 * 1024 * 1024;

/// Address span per PD entry (2 MiB).
const PMD_SPAN: u64 = 2 * 1024 * 1024;

/// Maximum walk depth (4 levels).
const MAX_DEPTH: u8 = 4;

// -------------------------------------------------------------------
// PageWalkAction
// -------------------------------------------------------------------

/// Action returned by page-walk callbacks to control traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageWalkAction {
    /// Continue walking into the next level or next entry.
    Continue,
    /// Skip the subtree rooted at this entry (do not descend).
    Skip,
    /// Stop the walk entirely (success).
    Stop,
    /// Stop the walk with an error.
    ActionError,
}

impl Default for PageWalkAction {
    fn default() -> Self {
        Self::Continue
    }
}

// -------------------------------------------------------------------
// PageWalkLevel
// -------------------------------------------------------------------

/// Page table level identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PageWalkLevel {
    /// Level 4: PGD (PML4).
    Pgd,
    /// Level 3: PUD (PDPT).
    Pud,
    /// Level 2: PMD (PD).
    Pmd,
    /// Level 1: PTE (PT).
    Pte,
}

impl PageWalkLevel {
    /// Address span covered by one entry at this level.
    pub const fn span(self) -> u64 {
        match self {
            Self::Pgd => PGD_SPAN,
            Self::Pud => PUD_SPAN,
            Self::Pmd => PMD_SPAN,
            Self::Pte => PAGE_SIZE,
        }
    }

    /// Numeric depth (4 = PGD, 1 = PTE).
    pub const fn depth(self) -> u8 {
        match self {
            Self::Pgd => 4,
            Self::Pud => 3,
            Self::Pmd => 2,
            Self::Pte => 1,
        }
    }
}

// -------------------------------------------------------------------
// PageTableEntryInfo
// -------------------------------------------------------------------

/// Information about a single page-table entry encountered during
/// a walk.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageTableEntryInfo {
    /// Virtual address this entry maps (start of the region).
    pub virt_addr: u64,
    /// Physical address stored in the entry (if present).
    pub phys_addr: u64,
    /// Raw PTE flags.
    pub flags: u64,
    /// Whether the entry is present.
    pub present: bool,
    /// Whether the entry maps a huge page.
    pub huge: bool,
    /// Table level at which this entry was found.
    pub level: u8,
}

// -------------------------------------------------------------------
// PageWalkOps
// -------------------------------------------------------------------

/// Trait defining callbacks for each page-table level.
///
/// Implementors provide per-level processing logic. The walker calls
/// these methods as it descends through the page tables.
pub trait PageWalkOps {
    /// Called for each PUD (level 3) entry.
    ///
    /// Return [`PageWalkAction::Skip`] to avoid descending into
    /// PMD/PTE levels under this entry.
    fn pud_entry(&mut self, info: &PageTableEntryInfo) -> PageWalkAction;

    /// Called for each PMD (level 2) entry.
    ///
    /// If the entry is a huge page, the PTE walk is skipped
    /// automatically.
    fn pmd_entry(&mut self, info: &PageTableEntryInfo) -> PageWalkAction;

    /// Called for each PTE (level 1) entry.
    fn pte_entry(&mut self, info: &PageTableEntryInfo) -> PageWalkAction;

    /// Called when an unmapped region (hole) is encountered.
    fn hole(&mut self, start: u64, end: u64, level: PageWalkLevel) -> PageWalkAction;
}

// -------------------------------------------------------------------
// NullWalkOps
// -------------------------------------------------------------------

/// A no-op implementation of [`PageWalkOps`] that continues on every
/// entry. Useful as a default or base implementation.
pub struct NullWalkOps;

impl PageWalkOps for NullWalkOps {
    fn pud_entry(&mut self, _info: &PageTableEntryInfo) -> PageWalkAction {
        PageWalkAction::Continue
    }

    fn pmd_entry(&mut self, _info: &PageTableEntryInfo) -> PageWalkAction {
        PageWalkAction::Continue
    }

    fn pte_entry(&mut self, _info: &PageTableEntryInfo) -> PageWalkAction {
        PageWalkAction::Continue
    }

    fn hole(&mut self, _start: u64, _end: u64, _level: PageWalkLevel) -> PageWalkAction {
        PageWalkAction::Continue
    }
}

// -------------------------------------------------------------------
// CountingWalkOps
// -------------------------------------------------------------------

/// A walk-ops implementation that counts entries at each level.
pub struct CountingWalkOps {
    /// PUD entries visited.
    pub pud_count: u64,
    /// PMD entries visited.
    pub pmd_count: u64,
    /// PTE entries visited.
    pub pte_count: u64,
    /// Holes encountered.
    pub hole_count: u64,
    /// Huge pages found.
    pub huge_count: u64,
}

impl CountingWalkOps {
    /// Create a new counting ops with all counters at zero.
    pub const fn new() -> Self {
        Self {
            pud_count: 0,
            pmd_count: 0,
            pte_count: 0,
            hole_count: 0,
            huge_count: 0,
        }
    }
}

impl Default for CountingWalkOps {
    fn default() -> Self {
        Self::new()
    }
}

impl PageWalkOps for CountingWalkOps {
    fn pud_entry(&mut self, info: &PageTableEntryInfo) -> PageWalkAction {
        self.pud_count += 1;
        if info.huge {
            self.huge_count += 1;
        }
        PageWalkAction::Continue
    }

    fn pmd_entry(&mut self, info: &PageTableEntryInfo) -> PageWalkAction {
        self.pmd_count += 1;
        if info.huge {
            self.huge_count += 1;
        }
        PageWalkAction::Continue
    }

    fn pte_entry(&mut self, _info: &PageTableEntryInfo) -> PageWalkAction {
        self.pte_count += 1;
        PageWalkAction::Continue
    }

    fn hole(&mut self, _start: u64, _end: u64, _level: PageWalkLevel) -> PageWalkAction {
        self.hole_count += 1;
        PageWalkAction::Continue
    }
}

// -------------------------------------------------------------------
// PageWalkRange
// -------------------------------------------------------------------

/// Address range to walk.
#[derive(Debug, Clone, Copy)]
pub struct PageWalkRange {
    /// Start virtual address (inclusive, page-aligned).
    pub start: u64,
    /// End virtual address (exclusive, page-aligned).
    pub end: u64,
}

impl PageWalkRange {
    /// Create a new range.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — `start >= end`, addresses not page-aligned
    pub const fn new(start: u64, end: u64) -> Result<Self> {
        if start >= end {
            return Err(Error::InvalidArgument);
        }
        if start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { start, end })
    }

    /// Size of the range in bytes.
    pub const fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Number of 4 KiB pages spanned.
    pub const fn nr_pages(&self) -> u64 {
        self.size() / PAGE_SIZE
    }
}

impl Default for PageWalkRange {
    fn default() -> Self {
        Self { start: 0, end: 0 }
    }
}

// -------------------------------------------------------------------
// SimulatedPageTable
// -------------------------------------------------------------------

/// Simulated page-table entry for the walker.
///
/// In a real kernel the walker reads hardware page tables via
/// physical memory. This structure simulates entries for testing
/// and scaffolding.
#[derive(Debug, Clone, Copy, Default)]
struct SimulatedPte {
    /// Physical address (or next-level table address).
    phys_addr: u64,
    /// PTE flags.
    flags: u64,
    /// Whether this entry is present.
    present: bool,
    /// Whether this is a huge-page entry (PUD 1GiB or PMD 2MiB).
    huge: bool,
}

/// Flag bit: entry is present.
const PTE_PRESENT: u64 = 1 << 0;
/// Flag bit: entry is writable.
const PTE_WRITABLE: u64 = 1 << 1;
/// Flag bit: entry maps a huge page.
const PTE_HUGE: u64 = 1 << 7;

// -------------------------------------------------------------------
// PageWalkStats
// -------------------------------------------------------------------

/// Aggregate page-walk statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageWalkStats {
    /// Total walks performed.
    pub total_walks: u64,
    /// Total PTE-level entries visited.
    pub pte_entries_visited: u64,
    /// Total huge pages found (PMD or PUD level).
    pub huge_pages_found: u64,
    /// Total holes (unmapped regions) skipped.
    pub holes_skipped: u64,
    /// Walks that completed successfully.
    pub walks_completed: u64,
    /// Walks stopped early by callback.
    pub walks_stopped: u64,
    /// Walks that encountered an error.
    pub walks_errored: u64,
}

// -------------------------------------------------------------------
// WalkerState
// -------------------------------------------------------------------

/// State of a single page-table walk in progress.
#[derive(Debug, Clone, Copy)]
struct WalkerState {
    /// Address-space identifier.
    mm_id: u64,
    /// Range being walked.
    range: PageWalkRange,
    /// Current virtual address being processed.
    current_addr: u64,
    /// Current depth (4 = PGD, 1 = PTE).
    depth: u8,
    /// Whether this walker slot is in use.
    active: bool,
    /// Walker ID.
    id: u32,
}

impl WalkerState {
    /// Empty (inactive) walker.
    const fn empty() -> Self {
        Self {
            mm_id: 0,
            range: PageWalkRange { start: 0, end: 0 },
            current_addr: 0,
            depth: 0,
            active: false,
            id: 0,
        }
    }
}

impl Default for WalkerState {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// PageWalkSubsystem
// -------------------------------------------------------------------

/// Manager for concurrent page-table walks.
///
/// Tracks up to [`MAX_WALKERS`] concurrent walks and provides the
/// main `walk_page_range` entry point.
pub struct PageWalkSubsystem {
    /// Walker slots.
    walkers: [WalkerState; MAX_WALKERS],
    /// Next walker ID.
    next_id: u32,
    /// Statistics.
    stats: PageWalkStats,
}

impl PageWalkSubsystem {
    /// Create a new page-walk subsystem.
    pub const fn new() -> Self {
        Self {
            walkers: [const { WalkerState::empty() }; MAX_WALKERS],
            next_id: 0,
            stats: PageWalkStats {
                total_walks: 0,
                pte_entries_visited: 0,
                huge_pages_found: 0,
                holes_skipped: 0,
                walks_completed: 0,
                walks_stopped: 0,
                walks_errored: 0,
            },
        }
    }

    /// Return current statistics.
    pub const fn stats(&self) -> &PageWalkStats {
        &self.stats
    }

    /// Walk a page-table range using the provided ops callbacks.
    ///
    /// # Arguments
    ///
    /// * `mm_id` — address-space identifier
    /// * `start` — start virtual address (page-aligned)
    /// * `end` — end virtual address (page-aligned)
    /// * `ops` — mutable reference to a [`PageWalkOps`] implementor
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — invalid range
    /// * `Busy` — no free walker slots
    pub fn walk_page_range(
        &mut self,
        mm_id: u64,
        start: u64,
        end: u64,
        ops: &mut dyn PageWalkOps,
    ) -> Result<()> {
        let range = PageWalkRange::new(start, end)?;

        // Allocate a walker slot.
        let walker_idx = self.alloc_walker(mm_id, range)?;
        self.stats.total_walks += 1;

        // Perform the walk.
        let result = self.do_walk(walker_idx, ops);

        // Release the walker slot.
        self.walkers[walker_idx].active = false;

        match result {
            Ok(()) => {
                self.stats.walks_completed += 1;
                Ok(())
            }
            Err(e) => {
                self.stats.walks_errored += 1;
                Err(e)
            }
        }
    }

    /// Perform a walk starting at the PGD level.
    fn do_walk(&mut self, walker_idx: usize, ops: &mut dyn PageWalkOps) -> Result<()> {
        let range_start = self.walkers[walker_idx].range.start;
        let range_end = self.walkers[walker_idx].range.end;
        let mut addr = range_start;

        // Walk PGD (level 4) entries.
        while addr < range_end {
            let pgd_end = next_level_boundary(addr, PGD_SPAN).min(range_end);

            // Walk PUD (level 3) entries within this PGD entry.
            let action = self.walk_pud_range(walker_idx, addr, pgd_end, ops)?;
            if action == PageWalkAction::Stop {
                self.stats.walks_stopped += 1;
                return Ok(());
            }

            addr = pgd_end;
        }

        Ok(())
    }

    /// Walk PUD entries within a PGD entry's span.
    fn walk_pud_range(
        &mut self,
        walker_idx: usize,
        start: u64,
        end: u64,
        ops: &mut dyn PageWalkOps,
    ) -> Result<PageWalkAction> {
        let mut addr = start;

        while addr < end {
            let pud_end = next_level_boundary(addr, PUD_SPAN).min(end);

            // Simulate reading the PUD entry.
            let pte_info = self.read_simulated_entry(walker_idx, addr, PageWalkLevel::Pud);

            if !pte_info.present {
                // Hole at PUD level.
                let action = ops.hole(addr, pud_end, PageWalkLevel::Pud);
                self.stats.holes_skipped += 1;
                if action == PageWalkAction::Stop {
                    return Ok(PageWalkAction::Stop);
                }
                addr = pud_end;
                continue;
            }

            // Call PUD callback.
            let action = ops.pud_entry(&pte_info);
            match action {
                PageWalkAction::Stop => {
                    return Ok(PageWalkAction::Stop);
                }
                PageWalkAction::Skip => {
                    addr = pud_end;
                    continue;
                }
                PageWalkAction::ActionError => {
                    return Err(Error::IoError);
                }
                PageWalkAction::Continue => {}
            }

            // If huge (1 GiB), do not descend further.
            if pte_info.huge {
                self.stats.huge_pages_found += 1;
                addr = pud_end;
                continue;
            }

            // Walk PMD entries within this PUD entry.
            let action = self.walk_pmd_range(walker_idx, addr, pud_end, ops)?;
            if action == PageWalkAction::Stop {
                return Ok(PageWalkAction::Stop);
            }

            addr = pud_end;
        }

        Ok(PageWalkAction::Continue)
    }

    /// Walk PMD entries within a PUD entry's span.
    fn walk_pmd_range(
        &mut self,
        walker_idx: usize,
        start: u64,
        end: u64,
        ops: &mut dyn PageWalkOps,
    ) -> Result<PageWalkAction> {
        let mut addr = start;

        while addr < end {
            let pmd_end = next_level_boundary(addr, PMD_SPAN).min(end);

            let pte_info = self.read_simulated_entry(walker_idx, addr, PageWalkLevel::Pmd);

            if !pte_info.present {
                let action = ops.hole(addr, pmd_end, PageWalkLevel::Pmd);
                self.stats.holes_skipped += 1;
                if action == PageWalkAction::Stop {
                    return Ok(PageWalkAction::Stop);
                }
                addr = pmd_end;
                continue;
            }

            let action = ops.pmd_entry(&pte_info);
            match action {
                PageWalkAction::Stop => {
                    return Ok(PageWalkAction::Stop);
                }
                PageWalkAction::Skip => {
                    addr = pmd_end;
                    continue;
                }
                PageWalkAction::ActionError => {
                    return Err(Error::IoError);
                }
                PageWalkAction::Continue => {}
            }

            // If huge (2 MiB), do not descend to PTE level.
            if pte_info.huge {
                self.stats.huge_pages_found += 1;
                addr = pmd_end;
                continue;
            }

            // Walk PTE entries within this PMD entry.
            let action = self.walk_pte_range(walker_idx, addr, pmd_end, ops)?;
            if action == PageWalkAction::Stop {
                return Ok(PageWalkAction::Stop);
            }

            addr = pmd_end;
        }

        Ok(PageWalkAction::Continue)
    }

    /// Walk PTE entries within a PMD entry's span.
    fn walk_pte_range(
        &mut self,
        walker_idx: usize,
        start: u64,
        end: u64,
        ops: &mut dyn PageWalkOps,
    ) -> Result<PageWalkAction> {
        let mut addr = start;

        while addr < end {
            let pte_end = addr + PAGE_SIZE;

            let pte_info = self.read_simulated_entry(walker_idx, addr, PageWalkLevel::Pte);

            if !pte_info.present {
                let action = ops.hole(addr, pte_end, PageWalkLevel::Pte);
                self.stats.holes_skipped += 1;
                if action == PageWalkAction::Stop {
                    return Ok(PageWalkAction::Stop);
                }
                addr = pte_end;
                continue;
            }

            let action = ops.pte_entry(&pte_info);
            self.stats.pte_entries_visited += 1;

            match action {
                PageWalkAction::Stop => {
                    return Ok(PageWalkAction::Stop);
                }
                PageWalkAction::ActionError => {
                    return Err(Error::IoError);
                }
                _ => {}
            }

            addr = pte_end;
        }

        Ok(PageWalkAction::Continue)
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Allocate a walker slot.
    fn alloc_walker(&mut self, mm_id: u64, range: PageWalkRange) -> Result<usize> {
        let idx = self
            .walkers
            .iter()
            .position(|w| !w.active)
            .ok_or(Error::Busy)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        self.walkers[idx] = WalkerState {
            mm_id,
            range,
            current_addr: range.start,
            depth: MAX_DEPTH,
            active: true,
            id,
        };

        Ok(idx)
    }

    /// Read a simulated page-table entry.
    ///
    /// In a real kernel this would dereference physical memory.
    /// The simulation marks all entries as present with identity
    /// mapping for scaffolding purposes.
    fn read_simulated_entry(
        &self,
        _walker_idx: usize,
        virt_addr: u64,
        level: PageWalkLevel,
    ) -> PageTableEntryInfo {
        // Simulate: all entries present, no huge pages by default.
        // A real implementation reads from the actual page tables.
        let phys_addr = virt_addr & 0x0000_FFFF_FFFF_F000;
        PageTableEntryInfo {
            virt_addr,
            phys_addr,
            flags: PTE_PRESENT | PTE_WRITABLE,
            present: true,
            huge: false,
            level: level.depth(),
        }
    }
}

impl Default for PageWalkSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Free-standing helpers
// -------------------------------------------------------------------

/// Compute the next boundary at a given level span.
///
/// E.g., for addr = 0x12345000 and span = 0x200000 (2 MiB),
/// returns 0x12400000 (next 2 MiB boundary).
const fn next_level_boundary(addr: u64, span: u64) -> u64 {
    (addr + span) & !(span - 1)
}

/// Walk a page range with a counting-ops implementation and return
/// the counters.
///
/// Convenience function for diagnostics and testing.
pub fn walk_and_count(
    subsys: &mut PageWalkSubsystem,
    mm_id: u64,
    start: u64,
    end: u64,
) -> Result<CountingWalkOps> {
    let mut ops = CountingWalkOps::new();
    subsys.walk_page_range(mm_id, start, end, &mut ops)?;
    Ok(ops)
}

/// Extract the PGD index from a virtual address.
pub const fn pgd_index(vaddr: u64) -> usize {
    ((vaddr >> 39) & 0x1FF) as usize
}

/// Extract the PUD index from a virtual address.
pub const fn pud_index(vaddr: u64) -> usize {
    ((vaddr >> 30) & 0x1FF) as usize
}

/// Extract the PMD index from a virtual address.
pub const fn pmd_index(vaddr: u64) -> usize {
    ((vaddr >> 21) & 0x1FF) as usize
}

/// Extract the PTE index from a virtual address.
pub const fn pte_index(vaddr: u64) -> usize {
    ((vaddr >> 12) & 0x1FF) as usize
}

/// Extract the page offset from a virtual address.
pub const fn page_offset(vaddr: u64) -> usize {
    (vaddr & 0xFFF) as usize
}
