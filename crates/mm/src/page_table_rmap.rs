// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page table reverse mapping.
//!
//! Tracks which page tables map a given physical page, maintaining
//! an rmap chain per page for both anonymous and file-backed pages.
//! Provides `rmap_walk` for page migration and reclaim, add/remove
//! rmap entries, and `folio_referenced` counting.
//!
//! # Architecture
//!
//! Each physical page tracked by the rmap system has a
//! [`PageRmapEntry`] that records all page tables (identified by
//! address-space ID and virtual address) that contain a PTE
//! pointing to the page. Two chain types exist:
//!
//! - **Anonymous chain** — for heap/stack/CoW pages
//! - **File chain** — for page-cache-backed pages
//!
//! The [`PageTableRmap`] manager stores these entries and
//! supports walking all mappings of a page for:
//! - Reclaim (clearing PTEs and flushing TLB)
//! - Migration (installing migration PTEs)
//! - `folio_referenced` (counting access bits)
//!
//! Reference: Linux `mm/rmap.c`.

use oncrix_lib::{Error, Result};

// -- Constants

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of physical pages tracked by this rmap.
const MAX_TRACKED_PAGES: usize = 1024;

/// Maximum number of PTE entries per tracked page.
const MAX_PTES_PER_PAGE: usize = 16;

/// Maximum number of walk callbacks per invocation.
const MAX_WALK_ENTRIES: usize = 64;

// -- RmapChainType

/// Type of rmap chain a page belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RmapChainType {
    /// Anonymous page (heap, stack, CoW).
    #[default]
    Anon,
    /// File-backed page (page cache / mmap).
    File,
}

// -- PteMapping

/// A single PTE mapping record for a tracked page.
///
/// Represents one page-table entry in one address space that
/// maps the physical page.
#[derive(Debug, Clone, Copy)]
pub struct PteMapping {
    /// Address-space identifier (process or mm_struct ID).
    pub address_space_id: u64,
    /// Virtual address where the page is mapped.
    pub vaddr: u64,
    /// Page table level (0 = PTE, 1 = PMD for huge, etc.).
    pub level: u8,
    /// Whether the accessed/referenced bit is set.
    pub referenced: bool,
    /// Whether the dirty bit is set.
    pub dirty: bool,
    /// Whether this PTE is writable.
    pub writable: bool,
    /// Whether this slot is occupied.
    pub valid: bool,
}

impl PteMapping {
    const fn empty() -> Self {
        Self {
            address_space_id: 0,
            vaddr: 0,
            level: 0,
            referenced: false,
            dirty: false,
            writable: false,
            valid: false,
        }
    }
}

impl Default for PteMapping {
    fn default() -> Self {
        Self::empty()
    }
}

// -- PageRmapEntry

/// Rmap metadata for a single tracked physical page.
///
/// Stores the physical frame number, chain type, and all PTE
/// mappings that reference this page.
#[derive(Debug, Clone, Copy)]
pub struct PageRmapEntry {
    /// Physical frame number.
    pub pfn: u64,
    /// Chain type (anon or file).
    pub chain_type: RmapChainType,
    /// PTE mappings referencing this page.
    pub mappings: [PteMapping; MAX_PTES_PER_PAGE],
    /// Number of valid mappings.
    pub mapping_count: usize,
    /// Reference count (total map count).
    pub mapcount: u32,
    /// Folio order (0 = single page, 9 = 2 MiB THP).
    pub folio_order: u8,
    /// Whether this entry is active.
    pub active: bool,
}

impl PageRmapEntry {
    const fn empty() -> Self {
        Self {
            pfn: 0,
            chain_type: RmapChainType::Anon,
            mappings: [const { PteMapping::empty() }; MAX_PTES_PER_PAGE],
            mapping_count: 0,
            mapcount: 0,
            folio_order: 0,
            active: false,
        }
    }
}

impl Default for PageRmapEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -- RmapWalkAction

/// Action returned by an rmap walk step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RmapWalkAction {
    /// Continue to the next mapping.
    Continue,
    /// Stop the walk early.
    Stop,
}

// -- FolioRefResult

/// Result of a `folio_referenced` scan.
#[derive(Debug, Clone, Copy, Default)]
pub struct FolioRefResult {
    /// Number of mappings with the referenced bit set.
    pub referenced_count: u32,
    /// Total mappings checked.
    pub total_checked: u32,
    /// Number of mappings where referenced bit was cleared.
    pub cleared: u32,
}

// -- PageTableRmapStats

/// Aggregate statistics for the page-table rmap subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageTableRmapStats {
    /// Total rmap add operations.
    pub adds: u64,
    /// Total rmap remove operations.
    pub removes: u64,
    /// Total rmap walk invocations.
    pub walks: u64,
    /// Total mappings walked across all walks.
    pub mappings_walked: u64,
    /// Total folio_referenced calls.
    pub folio_referenced_calls: u64,
    /// Total pages currently tracked.
    pub tracked_pages: u64,
    /// Total TLB flushes requested.
    pub tlb_flushes: u64,
}

// -- PageTableRmap

/// Page table reverse mapping manager.
///
/// Maintains per-page rmap chains and provides the core
/// operations: add, remove, walk, and `folio_referenced`.
pub struct PageTableRmap {
    /// Tracked page entries.
    entries: [PageRmapEntry; MAX_TRACKED_PAGES],
    /// Number of active entries.
    entry_count: usize,
    /// Statistics.
    stats: PageTableRmapStats,
}

impl PageTableRmap {
    /// Create a new, empty page-table rmap manager.
    pub const fn new() -> Self {
        Self {
            entries: [const { PageRmapEntry::empty() }; MAX_TRACKED_PAGES],
            entry_count: 0,
            stats: PageTableRmapStats {
                adds: 0,
                removes: 0,
                walks: 0,
                mappings_walked: 0,
                folio_referenced_calls: 0,
                tracked_pages: 0,
                tlb_flushes: 0,
            },
        }
    }

    /// Register a physical page for rmap tracking.
    ///
    /// Returns the index of the new entry.
    pub fn register_page(
        &mut self,
        pfn: u64,
        chain_type: RmapChainType,
        folio_order: u8,
    ) -> Result<usize> {
        let idx = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx] = PageRmapEntry {
            pfn,
            chain_type,
            mappings: [const { PteMapping::empty() }; MAX_PTES_PER_PAGE],
            mapping_count: 0,
            mapcount: 0,
            folio_order,
            active: true,
        };
        self.entry_count += 1;
        self.stats.tracked_pages = self.entry_count as u64;
        Ok(idx)
    }

    /// Unregister a tracked page by PFN.
    pub fn unregister_page(&mut self, pfn: u64) -> Result<()> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.active && e.pfn == pfn)
            .ok_or(Error::NotFound)?;
        self.entries[idx].active = false;
        self.entry_count = self.entry_count.saturating_sub(1);
        self.stats.tracked_pages = self.entry_count as u64;
        Ok(())
    }

    /// Add a PTE mapping for a tracked page.
    pub fn add_rmap(
        &mut self,
        pfn: u64,
        address_space_id: u64,
        vaddr: u64,
        writable: bool,
    ) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.pfn == pfn)
            .ok_or(Error::NotFound)?;
        if entry.mapping_count >= MAX_PTES_PER_PAGE {
            return Err(Error::OutOfMemory);
        }
        entry.mappings[entry.mapping_count] = PteMapping {
            address_space_id,
            vaddr,
            level: 0,
            referenced: true,
            dirty: false,
            writable,
            valid: true,
        };
        entry.mapping_count += 1;
        entry.mapcount += 1;
        self.stats.adds += 1;
        Ok(())
    }

    /// Remove a PTE mapping from a tracked page.
    ///
    /// Identifies the mapping by address-space ID and virtual
    /// address. Requests a TLB flush for the removed entry.
    pub fn remove_rmap(&mut self, pfn: u64, address_space_id: u64, vaddr: u64) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.pfn == pfn)
            .ok_or(Error::NotFound)?;
        let pos = {
            let mut found = None;
            for i in 0..entry.mapping_count {
                let m = &entry.mappings[i];
                if m.valid && m.address_space_id == address_space_id && m.vaddr == vaddr {
                    found = Some(i);
                    break;
                }
            }
            found.ok_or(Error::NotFound)?
        };
        entry.mapping_count -= 1;
        if pos < entry.mapping_count {
            entry.mappings[pos] = entry.mappings[entry.mapping_count];
        }
        entry.mappings[entry.mapping_count] = PteMapping::empty();
        entry.mapcount = entry.mapcount.saturating_sub(1);
        self.stats.removes += 1;
        self.stats.tlb_flushes += 1;
        Ok(())
    }

    /// Walk all mappings of a page.
    ///
    /// Returns `(visited, action)` where `visited` is the number
    /// of mappings examined.
    pub fn rmap_walk(&mut self, pfn: u64) -> Result<(u64, RmapWalkAction)> {
        self.stats.walks += 1;
        let entry = self
            .entries
            .iter()
            .find(|e| e.active && e.pfn == pfn)
            .ok_or(Error::NotFound)?;
        let mut visited = 0u64;
        for m in &entry.mappings[..entry.mapping_count] {
            if m.valid {
                visited += 1;
                self.stats.mappings_walked += 1;
                if visited >= MAX_WALK_ENTRIES as u64 {
                    return Ok((visited, RmapWalkAction::Stop));
                }
            }
        }
        let action = if visited > 0 {
            RmapWalkAction::Continue
        } else {
            RmapWalkAction::Stop
        };
        Ok((visited, action))
    }

    /// Count referenced mappings for a folio (page or compound).
    ///
    /// Scans all PTE mappings of the given PFN and counts how many
    /// have the accessed/referenced bit set. Optionally clears the
    /// bit after reading.
    pub fn folio_referenced(&mut self, pfn: u64, clear: bool) -> Result<FolioRefResult> {
        self.stats.folio_referenced_calls += 1;
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.pfn == pfn)
            .ok_or(Error::NotFound)?;
        let mut result = FolioRefResult::default();
        let count = entry.mapping_count;
        for m in &mut entry.mappings[..count] {
            if !m.valid {
                continue;
            }
            result.total_checked += 1;
            if m.referenced {
                result.referenced_count += 1;
                if clear {
                    m.referenced = false;
                    result.cleared += 1;
                }
            }
        }
        Ok(result)
    }

    /// Return the page size in bytes covered by a tracked page,
    /// accounting for folio order.
    pub fn page_size(&self, pfn: u64) -> Result<u64> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.active && e.pfn == pfn)
            .ok_or(Error::NotFound)?;
        Ok(PAGE_SIZE << entry.folio_order)
    }

    /// Return the mapcount for a tracked page.
    pub fn mapcount(&self, pfn: u64) -> Result<u32> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.active && e.pfn == pfn)
            .ok_or(Error::NotFound)?;
        Ok(entry.mapcount)
    }

    /// Number of tracked pages.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Return statistics.
    pub fn stats(&self) -> &PageTableRmapStats {
        &self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = PageTableRmapStats::default();
    }
}

impl Default for PageTableRmap {
    fn default() -> Self {
        Self::new()
    }
}
