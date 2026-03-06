// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page-to-VMA reverse mapping walk (page_vma_mapped).
//!
//! When the kernel needs to find every virtual mapping of a given
//! physical page (e.g., for reclaim, migration, or KSM), it must
//! walk the reverse-mapping structures. This module provides the
//! walk machinery that iterates over all VMAs that map a page.
//!
//! # Architecture
//!
//! A physical page can be mapped in multiple address spaces
//! simultaneously:
//!
//! - **Anonymous pages**: shared via `fork()` (CoW), tracked through
//!   `anon_vma` chains.
//! - **File-backed pages**: shared via `mmap(MAP_SHARED)`, tracked
//!   through the inode's address space.
//!
//! The walker ([`PageVmaMappedWalk`]) iterates all such mappings
//! for a given page frame number (PFN). For each mapping it
//! produces a [`MappedVma`] descriptor containing the PID, virtual
//! address, PTE flags, and VMA attributes.
//!
//! # Key types
//!
//! - [`PageMapEntry`] — one mapping of a page (PID + vaddr + flags)
//! - [`PageMapInfo`] — per-page metadata (PFN, map count, type)
//! - [`MappedVma`] — result of a walk step (VMA + PTE info)
//! - [`PageVmaMappedWalk`] — stateful walk iterator
//! - [`PageVmaMappedTable`] — system-wide page-to-mapping table
//! - [`PageVmaMappedSubsystem`] — top-level subsystem
//!
//! Reference: Linux `mm/page_vma_mapped.c`,
//! `include/linux/page_vma_mapped.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of pages tracked in the reverse map table.
const MAX_PAGES: usize = 2048;

/// Maximum number of mappings per page.
const MAX_MAPPINGS_PER_PAGE: usize = 16;

/// Maximum number of walk results returned per iteration.
const MAX_WALK_RESULTS: usize = 64;

/// PTE flag: present in memory.
const PTE_PRESENT: u64 = 1 << 0;

/// PTE flag: writable.
const PTE_WRITABLE: u64 = 1 << 1;

/// PTE flag: user-accessible.
const PTE_USER: u64 = 1 << 2;

/// PTE flag: page has been accessed.
const PTE_ACCESSED: u64 = 1 << 5;

/// PTE flag: page is dirty.
const PTE_DIRTY: u64 = 1 << 6;

/// PTE flag: huge page (2 MiB / 1 GiB).
const PTE_HUGE: u64 = 1 << 7;

/// PTE flag: no-execute.
const PTE_NX: u64 = 1 << 63;

/// Special PFN value meaning "no page".
const PFN_NONE: u64 = u64::MAX;

// -------------------------------------------------------------------
// PageMapType
// -------------------------------------------------------------------

/// Classification of a page's mapping type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PageMapType {
    /// Anonymous mapping (heap, stack, CoW).
    #[default]
    Anonymous,
    /// File-backed mapping (page cache, mmap).
    FileBacked,
    /// Device mapping (DMA, MMIO).
    Device,
    /// KSM-merged page.
    Ksm,
    /// Swap entry (not currently mapped).
    Swap,
    /// Migration entry (page being migrated).
    Migration,
}

// -------------------------------------------------------------------
// PageMapEntry
// -------------------------------------------------------------------

/// One mapping of a physical page into a virtual address space.
#[derive(Debug, Clone, Copy)]
pub struct PageMapEntry {
    /// Process identifier.
    pub pid: u64,
    /// Virtual address in the process's address space.
    pub vaddr: u64,
    /// PTE flags (PTE_PRESENT, PTE_WRITABLE, etc.).
    pub pte_flags: u64,
    /// VMA start address.
    pub vma_start: u64,
    /// VMA end address (exclusive).
    pub vma_end: u64,
    /// VMA protection bits (r/w/x).
    pub vma_prot: u8,
    /// Whether this entry is valid.
    pub valid: bool,
}

impl PageMapEntry {
    /// Create an empty mapping entry.
    const fn empty() -> Self {
        Self {
            pid: 0,
            vaddr: 0,
            pte_flags: 0,
            vma_start: 0,
            vma_end: 0,
            vma_prot: 0,
            valid: false,
        }
    }

    /// Whether the PTE is present.
    pub fn is_present(&self) -> bool {
        self.pte_flags & PTE_PRESENT != 0
    }

    /// Whether the PTE is writable.
    pub fn is_writable(&self) -> bool {
        self.pte_flags & PTE_WRITABLE != 0
    }

    /// Whether the PTE has been accessed.
    pub fn is_accessed(&self) -> bool {
        self.pte_flags & PTE_ACCESSED != 0
    }

    /// Whether the PTE is dirty.
    pub fn is_dirty(&self) -> bool {
        self.pte_flags & PTE_DIRTY != 0
    }

    /// Whether this is a huge-page mapping.
    pub fn is_huge(&self) -> bool {
        self.pte_flags & PTE_HUGE != 0
    }
}

impl Default for PageMapEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// PageMapInfo
// -------------------------------------------------------------------

/// Per-page metadata in the reverse map table.
#[derive(Debug, Clone, Copy)]
pub struct PageMapInfo {
    /// Physical frame number.
    pub pfn: u64,
    /// Page type.
    pub page_type: PageMapType,
    /// Number of valid mappings.
    pub map_count: u32,
    /// Mappings array.
    pub mappings: [PageMapEntry; MAX_MAPPINGS_PER_PAGE],
    /// Whether this page entry is in use.
    pub active: bool,
    /// Reference count (total references, including non-mapped).
    pub refcount: u32,
    /// Page order (0 = base page, 9 = 2 MiB, 18 = 1 GiB).
    pub order: u8,
    /// Whether the page is pinned (cannot be migrated).
    pub pinned: bool,
}

impl PageMapInfo {
    /// Create an empty page info entry.
    const fn empty() -> Self {
        Self {
            pfn: PFN_NONE,
            page_type: PageMapType::Anonymous,
            map_count: 0,
            mappings: [const { PageMapEntry::empty() }; MAX_MAPPINGS_PER_PAGE],
            active: false,
            refcount: 0,
            order: 0,
            pinned: false,
        }
    }

    /// Add a mapping. Returns the slot index or an error.
    pub fn add_mapping(&mut self, entry: PageMapEntry) -> Result<usize> {
        if self.map_count as usize >= MAX_MAPPINGS_PER_PAGE {
            return Err(Error::OutOfMemory);
        }
        let idx = self.map_count as usize;
        self.mappings[idx] = entry;
        self.map_count += 1;
        Ok(idx)
    }

    /// Remove the mapping for `pid` + `vaddr`.
    pub fn remove_mapping(&mut self, pid: u64, vaddr: u64) -> Result<()> {
        let pos = self
            .mappings
            .iter()
            .take(self.map_count as usize)
            .position(|m| m.valid && m.pid == pid && m.vaddr == vaddr)
            .ok_or(Error::NotFound)?;

        let last = self.map_count as usize - 1;
        if pos < last {
            self.mappings[pos] = self.mappings[last];
        }
        self.mappings[last] = PageMapEntry::empty();
        self.map_count -= 1;
        Ok(())
    }

    /// Check whether the page has any writable mapping.
    pub fn has_writable_mapping(&self) -> bool {
        self.mappings
            .iter()
            .take(self.map_count as usize)
            .any(|m| m.valid && m.is_writable())
    }

    /// Check whether the page is exclusively mapped (map_count == 1).
    pub fn is_exclusively_mapped(&self) -> bool {
        self.map_count == 1
    }

    /// Iterate valid mappings.
    pub fn valid_mappings(&self) -> &[PageMapEntry] {
        &self.mappings[..self.map_count as usize]
    }
}

impl Default for PageMapInfo {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// MappedVma
// -------------------------------------------------------------------

/// Result of one step in a page_vma_mapped walk.
///
/// Combines VMA-level information with PTE-level flags for a single
/// mapping of a page.
#[derive(Debug, Clone, Copy)]
pub struct MappedVma {
    /// Physical frame number of the page.
    pub pfn: u64,
    /// Process ID.
    pub pid: u64,
    /// Virtual address.
    pub vaddr: u64,
    /// VMA start.
    pub vma_start: u64,
    /// VMA end.
    pub vma_end: u64,
    /// VMA protection (r/w/x).
    pub vma_prot: u8,
    /// PTE flags.
    pub pte_flags: u64,
    /// Page type.
    pub page_type: PageMapType,
    /// Whether this result is valid.
    pub valid: bool,
}

impl MappedVma {
    /// Create an empty result.
    const fn empty() -> Self {
        Self {
            pfn: PFN_NONE,
            pid: 0,
            vaddr: 0,
            vma_start: 0,
            vma_end: 0,
            vma_prot: 0,
            pte_flags: 0,
            page_type: PageMapType::Anonymous,
            valid: false,
        }
    }
}

impl Default for MappedVma {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// WalkAction
// -------------------------------------------------------------------

/// Action returned by a walk callback to control iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WalkAction {
    /// Continue to the next mapping.
    #[default]
    Continue,
    /// Stop walking immediately.
    Stop,
    /// Remove this mapping and continue.
    Unmap,
    /// Clear the accessed bit and continue.
    ClearAccessed,
    /// Clear the dirty bit and continue.
    ClearDirty,
}

// -------------------------------------------------------------------
// PageVmaMappedWalk
// -------------------------------------------------------------------

/// Stateful iterator that walks all mappings of a physical page.
///
/// Created via [`PageVmaMappedTable::walk()`]. The walker produces
/// [`MappedVma`] entries one at a time.
#[derive(Debug, Clone, Copy)]
pub struct PageVmaMappedWalk {
    /// PFN being walked.
    pub pfn: u64,
    /// Index into the page's mapping array.
    cursor: u32,
    /// Total mappings at walk start.
    total: u32,
    /// Number of results produced so far.
    pub produced: u32,
    /// Whether the walk has been started.
    pub started: bool,
    /// Whether the walk is finished.
    pub finished: bool,
}

impl PageVmaMappedWalk {
    /// Create a new walk for the given PFN.
    const fn new(pfn: u64, total: u32) -> Self {
        Self {
            pfn,
            cursor: 0,
            total,
            produced: 0,
            started: false,
            finished: false,
        }
    }

    /// Advance the walk cursor.
    fn advance(&mut self) {
        self.cursor += 1;
        if self.cursor >= self.total {
            self.finished = true;
        }
    }

    /// Current cursor position.
    pub fn cursor(&self) -> u32 {
        self.cursor
    }

    /// Whether the walk still has entries to produce.
    pub fn has_next(&self) -> bool {
        !self.finished && self.cursor < self.total
    }
}

impl Default for PageVmaMappedWalk {
    fn default() -> Self {
        Self::new(PFN_NONE, 0)
    }
}

// -------------------------------------------------------------------
// PageVmaMappedTable
// -------------------------------------------------------------------

/// System-wide table mapping physical pages to their virtual
/// mappings.
pub struct PageVmaMappedTable {
    /// Page info entries.
    pages: [PageMapInfo; MAX_PAGES],
    /// Number of active entries.
    active_count: usize,
}

impl PageVmaMappedTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            pages: [const { PageMapInfo::empty() }; MAX_PAGES],
            active_count: 0,
        }
    }

    /// Register a page in the table.
    pub fn register_page(&mut self, pfn: u64, page_type: PageMapType) -> Result<usize> {
        // Check for duplicate.
        for (i, p) in self.pages.iter().enumerate().take(self.active_count) {
            if p.active && p.pfn == pfn {
                return Err(Error::AlreadyExists);
            }
            let _ = i;
        }
        if self.active_count >= MAX_PAGES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.active_count;
        self.pages[idx].pfn = pfn;
        self.pages[idx].page_type = page_type;
        self.pages[idx].active = true;
        self.pages[idx].refcount = 1;
        self.active_count += 1;
        Ok(idx)
    }

    /// Unregister a page and compact the table.
    pub fn unregister_page(&mut self, pfn: u64) -> Result<()> {
        let pos = self
            .pages
            .iter()
            .take(self.active_count)
            .position(|p| p.active && p.pfn == pfn)
            .ok_or(Error::NotFound)?;

        self.active_count -= 1;
        if pos < self.active_count {
            self.pages[pos] = self.pages[self.active_count];
        }
        self.pages[self.active_count] = PageMapInfo::empty();
        Ok(())
    }

    /// Find a page by PFN.
    fn find_page(&self, pfn: u64) -> Result<usize> {
        self.pages
            .iter()
            .take(self.active_count)
            .position(|p| p.active && p.pfn == pfn)
            .ok_or(Error::NotFound)
    }

    /// Find a page by PFN (mutable).
    fn find_page_mut(&mut self, pfn: u64) -> Result<usize> {
        self.pages
            .iter()
            .take(self.active_count)
            .position(|p| p.active && p.pfn == pfn)
            .ok_or(Error::NotFound)
    }

    /// Add a mapping for a page.
    pub fn add_mapping(&mut self, pfn: u64, entry: PageMapEntry) -> Result<()> {
        let idx = self.find_page_mut(pfn)?;
        self.pages[idx].add_mapping(entry)?;
        Ok(())
    }

    /// Remove a mapping from a page.
    pub fn remove_mapping(&mut self, pfn: u64, pid: u64, vaddr: u64) -> Result<()> {
        let idx = self.find_page_mut(pfn)?;
        self.pages[idx].remove_mapping(pid, vaddr)
    }

    /// Start a walk over all mappings of a page.
    pub fn walk(&self, pfn: u64) -> Result<PageVmaMappedWalk> {
        let idx = self.find_page(pfn)?;
        let total = self.pages[idx].map_count;
        Ok(PageVmaMappedWalk::new(pfn, total))
    }

    /// Produce the next result from a walk.
    pub fn walk_next(&self, walk: &mut PageVmaMappedWalk) -> Result<Option<MappedVma>> {
        if walk.finished || !walk.has_next() {
            walk.finished = true;
            return Ok(None);
        }
        walk.started = true;
        let idx = self.find_page(walk.pfn)?;
        let page = &self.pages[idx];
        let m = &page.mappings[walk.cursor as usize];
        let result = MappedVma {
            pfn: walk.pfn,
            pid: m.pid,
            vaddr: m.vaddr,
            vma_start: m.vma_start,
            vma_end: m.vma_end,
            vma_prot: m.vma_prot,
            pte_flags: m.pte_flags,
            page_type: page.page_type,
            valid: m.valid,
        };
        walk.produced += 1;
        walk.advance();
        Ok(Some(result))
    }

    /// Collect all mappings of a page into a fixed-size array.
    pub fn walk_all(&self, pfn: u64) -> Result<([MappedVma; MAX_WALK_RESULTS], usize)> {
        let mut results = [MappedVma::empty(); MAX_WALK_RESULTS];
        let mut walk = self.walk(pfn)?;
        let mut count = 0usize;
        while let Some(vma) = self.walk_next(&mut walk)? {
            if count >= MAX_WALK_RESULTS {
                break;
            }
            results[count] = vma;
            count += 1;
        }
        Ok((results, count))
    }

    /// Count the number of mappings for a page.
    pub fn map_count(&self, pfn: u64) -> Result<u32> {
        let idx = self.find_page(pfn)?;
        Ok(self.pages[idx].map_count)
    }

    /// Check if a page has any writable mapping.
    pub fn has_writable(&self, pfn: u64) -> Result<bool> {
        let idx = self.find_page(pfn)?;
        Ok(self.pages[idx].has_writable_mapping())
    }

    /// Check if a page is exclusively mapped (single mapping).
    pub fn is_exclusively_mapped(&self, pfn: u64) -> Result<bool> {
        let idx = self.find_page(pfn)?;
        Ok(self.pages[idx].is_exclusively_mapped())
    }

    /// Number of active pages in the table.
    pub fn active_count(&self) -> usize {
        self.active_count
    }
}

impl Default for PageVmaMappedTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PageVmaMappedStats
// -------------------------------------------------------------------

/// Aggregate statistics for the page-to-VMA mapping subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageVmaMappedStats {
    /// Number of active pages.
    pub active_pages: u64,
    /// Total mappings across all pages.
    pub total_mappings: u64,
    /// Number of exclusively-mapped pages.
    pub exclusive_pages: u64,
    /// Number of pages with writable mappings.
    pub writable_pages: u64,
    /// Number of anonymous pages.
    pub anon_pages: u64,
    /// Number of file-backed pages.
    pub file_pages: u64,
    /// Total walks performed.
    pub total_walks: u64,
}

// -------------------------------------------------------------------
// PageVmaMappedSubsystem
// -------------------------------------------------------------------

/// Top-level subsystem for page-to-VMA reverse mapping walks.
pub struct PageVmaMappedSubsystem {
    /// The mapping table.
    table: PageVmaMappedTable,
    /// Whether the subsystem has been initialised.
    initialised: bool,
    /// Total walks performed since init.
    total_walks: u64,
}

impl PageVmaMappedSubsystem {
    /// Create an uninitialised subsystem.
    pub const fn new() -> Self {
        Self {
            table: PageVmaMappedTable::new(),
            initialised: false,
            total_walks: 0,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Register a physical page.
    pub fn register_page(&mut self, pfn: u64, page_type: PageMapType) -> Result<usize> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.table.register_page(pfn, page_type)
    }

    /// Unregister a physical page.
    pub fn unregister_page(&mut self, pfn: u64) -> Result<()> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.table.unregister_page(pfn)
    }

    /// Add a mapping for a page.
    pub fn add_mapping(&mut self, pfn: u64, entry: PageMapEntry) -> Result<()> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.table.add_mapping(pfn, entry)
    }

    /// Remove a mapping.
    pub fn remove_mapping(&mut self, pfn: u64, pid: u64, vaddr: u64) -> Result<()> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.table.remove_mapping(pfn, pid, vaddr)
    }

    /// Walk all mappings of a page.
    pub fn walk_all(&mut self, pfn: u64) -> Result<([MappedVma; MAX_WALK_RESULTS], usize)> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.total_walks = self.total_walks.saturating_add(1);
        self.table.walk_all(pfn)
    }

    /// Start an incremental walk.
    pub fn walk_start(&mut self, pfn: u64) -> Result<PageVmaMappedWalk> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.total_walks = self.total_walks.saturating_add(1);
        self.table.walk(pfn)
    }

    /// Get next result from an incremental walk.
    pub fn walk_next(&self, walk: &mut PageVmaMappedWalk) -> Result<Option<MappedVma>> {
        self.table.walk_next(walk)
    }

    /// Get mapping count for a page.
    pub fn map_count(&self, pfn: u64) -> Result<u32> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.table.map_count(pfn)
    }

    /// Collect aggregate statistics.
    pub fn stats(&self) -> PageVmaMappedStats {
        let mut s = PageVmaMappedStats {
            active_pages: self.table.active_count() as u64,
            total_walks: self.total_walks,
            ..PageVmaMappedStats::default()
        };
        for page in self.table.pages.iter().take(self.table.active_count) {
            if !page.active {
                continue;
            }
            s.total_mappings = s.total_mappings.saturating_add(page.map_count as u64);
            if page.is_exclusively_mapped() {
                s.exclusive_pages = s.exclusive_pages.saturating_add(1);
            }
            if page.has_writable_mapping() {
                s.writable_pages = s.writable_pages.saturating_add(1);
            }
            match page.page_type {
                PageMapType::Anonymous => {
                    s.anon_pages = s.anon_pages.saturating_add(1);
                }
                PageMapType::FileBacked => {
                    s.file_pages = s.file_pages.saturating_add(1);
                }
                _ => {}
            }
        }
        s
    }

    /// Whether the subsystem is initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }
}

impl Default for PageVmaMappedSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Unmap helpers
// -------------------------------------------------------------------

/// Result of a try_to_unmap operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnmapResult {
    /// Number of mappings successfully unmapped.
    pub unmapped: u32,
    /// Number of mappings that could not be unmapped.
    pub failed: u32,
    /// Whether the page is now completely unmapped.
    pub fully_unmapped: bool,
}

/// Attempt to unmap all mappings of a page.
///
/// Walks all mappings and removes them. Returns a summary of how
/// many were unmapped and how many failed.
pub fn try_to_unmap(table: &mut PageVmaMappedTable, pfn: u64) -> Result<UnmapResult> {
    let idx = table
        .pages
        .iter()
        .take(table.active_count)
        .position(|p| p.active && p.pfn == pfn)
        .ok_or(Error::NotFound)?;

    let mut result = UnmapResult::default();
    // Collect PIDs and vaddrs first, then remove.
    let mut to_remove: [(u64, u64); MAX_MAPPINGS_PER_PAGE] = [(0, 0); MAX_MAPPINGS_PER_PAGE];
    let count = table.pages[idx].map_count as usize;
    for i in 0..count {
        let m = &table.pages[idx].mappings[i];
        to_remove[i] = (m.pid, m.vaddr);
    }
    for &(pid, vaddr) in to_remove.iter().take(count) {
        match table.pages[idx].remove_mapping(pid, vaddr) {
            Ok(()) => result.unmapped += 1,
            Err(_) => result.failed += 1,
        }
    }
    result.fully_unmapped = table.pages[idx].map_count == 0;
    Ok(result)
}

/// Check whether any mapping of a page has the accessed bit set.
///
/// Optionally clears the bit as part of the check (for LRU ageing).
pub fn page_referenced(table: &PageVmaMappedTable, pfn: u64) -> Result<u32> {
    let idx = table
        .pages
        .iter()
        .take(table.active_count)
        .position(|p| p.active && p.pfn == pfn)
        .ok_or(Error::NotFound)?;

    let mut referenced = 0u32;
    for m in table.pages[idx]
        .mappings
        .iter()
        .take(table.pages[idx].map_count as usize)
    {
        if m.valid && m.is_accessed() {
            referenced += 1;
        }
    }
    Ok(referenced)
}

/// Count unique PIDs that map a given page.
pub fn page_mapped_pids(table: &PageVmaMappedTable, pfn: u64) -> Result<u32> {
    let idx = table
        .pages
        .iter()
        .take(table.active_count)
        .position(|p| p.active && p.pfn == pfn)
        .ok_or(Error::NotFound)?;

    let page = &table.pages[idx];
    let mut pids: [u64; MAX_MAPPINGS_PER_PAGE] = [0; MAX_MAPPINGS_PER_PAGE];
    let mut pid_count = 0usize;
    for m in page.mappings.iter().take(page.map_count as usize) {
        if !m.valid {
            continue;
        }
        let mut found = false;
        for pid in pids.iter().take(pid_count) {
            if *pid == m.pid {
                found = true;
                break;
            }
        }
        if !found && pid_count < MAX_MAPPINGS_PER_PAGE {
            pids[pid_count] = m.pid;
            pid_count += 1;
        }
    }
    Ok(pid_count as u32)
}
