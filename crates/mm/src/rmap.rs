// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Reverse mapping (rmap) subsystem.
//!
//! Maintains reverse mappings from physical pages to their virtual
//! mappings across all processes. This is essential for:
//! - Page reclaim (finding and unmapping all PTEs for a page)
//! - Migration (updating PTEs when a page moves)
//! - `page_referenced()` (checking access bits across all mappings)
//!
//! # Architecture
//!
//! ## Anonymous pages
//!
//! Anonymous pages use the `anon_vma` / `anon_vma_chain` model:
//! - [`AnonVma`] — shared structure linking all processes that
//!   CoW-share an anonymous page region
//! - [`AnonVmaChain`] — links a VMA to its `anon_vma`
//!
//! ## File-backed pages
//!
//! File-backed pages use an `address_space` rmap:
//! - [`AddressSpaceRmap`] — maps (inode, offset) to virtual mappings
//!
//! ## Common operations
//!
//! - [`page_referenced()`] — check if any mapping has the accessed bit
//! - [`try_to_unmap()`] — unmap a page from all processes
//! - [`rmap_walk()`] — walk all mappings of a page
//!
//! Reference: Linux `mm/rmap.c`, `include/linux/rmap.h`.

use oncrix_lib::{Error, Result};

// -- Constants

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of anon_vma structures.
const MAX_ANON_VMAS: usize = 256;

/// Maximum number of anon_vma_chain links.
const MAX_ANON_VMA_CHAINS: usize = 512;

/// Maximum number of address space rmap entries.
const MAX_ADDRESS_SPACE_ENTRIES: usize = 512;

/// Maximum number of virtual mappings per rmap entry.
const MAX_MAPPINGS_PER_ENTRY: usize = 8;

/// Maximum number of pages tracked by the rmap system.
const MAX_RMAP_PAGES: usize = 4096;

// -- RmapPageType

/// Type of a page from the rmap perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RmapPageType {
    /// Anonymous page (heap, stack, CoW).
    #[default]
    Anon,
    /// File-backed page (page cache).
    File,
    /// KSM-merged page.
    Ksm,
}

// -- RmapFlags

/// Flags controlling rmap walk and unmap behaviour.
#[derive(Debug, Clone, Copy, Default)]
pub struct RmapFlags {
    /// Only check referenced bit, do not clear it.
    pub check_only: bool,
    /// Clear the referenced/accessed bit after checking.
    pub clear_referenced: bool,
    /// Attempt to unmap the page from all processes.
    pub try_unmap: bool,
    /// Migration mode: install migration entries instead of
    /// unmapping.
    pub migration: bool,
    /// Reclaim mode: page is being reclaimed.
    pub reclaim: bool,
}

// -- VirtualMapping

/// A single virtual mapping of a physical page.
///
/// Represents one PTE in one process that maps the page.
#[derive(Debug, Clone, Copy)]
pub struct VirtualMapping {
    /// Process ID.
    pub pid: u64,
    /// Virtual address in the process's address space.
    pub vaddr: u64,
    /// Whether the PTE is writable.
    pub writable: bool,
    /// Whether the accessed/referenced bit is set.
    pub referenced: bool,
    /// Whether the dirty bit is set.
    pub dirty: bool,
    /// Whether this mapping slot is valid.
    pub valid: bool,
}

impl VirtualMapping {
    const fn empty() -> Self {
        Self {
            pid: 0,
            vaddr: 0,
            writable: false,
            referenced: false,
            dirty: false,
            valid: false,
        }
    }
}

impl Default for VirtualMapping {
    fn default() -> Self {
        Self::empty()
    }
}

// -- AnonVma

/// Anonymous virtual memory area — shared structure for CoW pages.
///
/// An `AnonVma` is created when a process first allocates anonymous
/// pages and is shared (via `fork()`) with child processes. All
/// processes in the CoW group reference the same `AnonVma`.
#[derive(Debug, Clone, Copy)]
pub struct AnonVma {
    /// Unique identifier for this anon_vma.
    pub id: u64,
    /// Root anon_vma ID (for the hierarchy).
    pub root_id: u64,
    /// Reference count (number of VMAs using this anon_vma).
    pub refcount: u32,
    /// Number of active chains linked to this anon_vma.
    pub chain_count: u32,
    /// Whether this anon_vma is valid.
    pub active: bool,
    /// Degree (number of child anon_vmas).
    pub degree: u32,
    /// Parent anon_vma ID (0 = root).
    pub parent_id: u64,
}

impl AnonVma {
    const fn empty() -> Self {
        Self {
            id: 0,
            root_id: 0,
            refcount: 0,
            chain_count: 0,
            active: false,
            degree: 0,
            parent_id: 0,
        }
    }

    /// Increment the reference count.
    pub fn get(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    /// Decrement the reference count. Returns true if it reached 0.
    pub fn put(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount == 0
    }
}

impl Default for AnonVma {
    fn default() -> Self {
        Self::empty()
    }
}

// -- AnonVmaChain

/// Links a VMA to its anon_vma.
///
/// Each VMA that contains anonymous pages has at least one chain
/// linking it to an `AnonVma`. After `fork()`, the child VMA gets
/// a chain to the parent's anon_vma and a chain to its own new
/// anon_vma.
#[derive(Debug, Clone, Copy)]
pub struct AnonVmaChain {
    /// VMA identifier (start address + PID composite).
    pub vma_id: u64,
    /// Process ID owning the VMA.
    pub pid: u64,
    /// anon_vma index this chain links to.
    pub anon_vma_idx: usize,
    /// Start virtual address of the VMA.
    pub vma_start: u64,
    /// End virtual address of the VMA.
    pub vma_end: u64,
    /// Whether this chain is active.
    pub active: bool,
}

impl AnonVmaChain {
    const fn empty() -> Self {
        Self {
            vma_id: 0,
            pid: 0,
            anon_vma_idx: 0,
            vma_start: 0,
            vma_end: 0,
            active: false,
        }
    }
}

impl Default for AnonVmaChain {
    fn default() -> Self {
        Self::empty()
    }
}

// -- AddressSpaceEntry

/// Entry in the address_space rmap for file-backed pages.
///
/// Maps a (file_id, page_index) pair to its virtual mappings.
#[derive(Debug, Clone, Copy)]
pub struct AddressSpaceEntry {
    /// File (inode) identifier.
    pub file_id: u64,
    /// Page index within the file.
    pub page_index: u64,
    /// Virtual mappings of this page.
    pub mappings: [VirtualMapping; MAX_MAPPINGS_PER_ENTRY],
    /// Number of valid mappings.
    pub mapping_count: usize,
    /// Whether this entry is active.
    pub active: bool,
}

impl AddressSpaceEntry {
    const fn empty() -> Self {
        Self {
            file_id: 0,
            page_index: 0,
            mappings: [const { VirtualMapping::empty() }; MAX_MAPPINGS_PER_ENTRY],
            mapping_count: 0,
            active: false,
        }
    }

    /// Add a mapping to this entry.
    pub fn add_mapping(&mut self, mapping: VirtualMapping) -> Result<()> {
        if self.mapping_count >= MAX_MAPPINGS_PER_ENTRY {
            return Err(Error::OutOfMemory);
        }
        self.mappings[self.mapping_count] = mapping;
        self.mappings[self.mapping_count].valid = true;
        self.mapping_count += 1;
        Ok(())
    }

    /// Remove a mapping by PID and virtual address.
    pub fn remove_mapping(&mut self, pid: u64, vaddr: u64) -> Result<()> {
        for i in 0..self.mapping_count {
            if self.mappings[i].valid
                && self.mappings[i].pid == pid
                && self.mappings[i].vaddr == vaddr
            {
                self.mapping_count -= 1;
                if i < self.mapping_count {
                    self.mappings[i] = self.mappings[self.mapping_count];
                }
                self.mappings[self.mapping_count] = VirtualMapping::empty();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }
}

impl Default for AddressSpaceEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -- RmapPage

/// Rmap metadata for a tracked physical page.
#[derive(Debug, Clone, Copy)]
pub struct RmapPage {
    /// Physical frame number.
    pub pfn: u64,
    /// Page type (anon, file, ksm).
    pub page_type: RmapPageType,
    /// For anon pages: index into the anon_vma array.
    pub anon_vma_idx: usize,
    /// For file pages: index into the address_space array.
    pub address_space_idx: usize,
    /// Number of current mappers (map count).
    pub mapcount: u32,
    /// Reference count.
    pub refcount: u32,
    /// Whether this rmap page entry is active.
    pub active: bool,
}

impl RmapPage {
    const fn empty() -> Self {
        Self {
            pfn: 0,
            page_type: RmapPageType::Anon,
            anon_vma_idx: 0,
            address_space_idx: 0,
            mapcount: 0,
            refcount: 0,
            active: false,
        }
    }
}

impl Default for RmapPage {
    fn default() -> Self {
        Self::empty()
    }
}

// -- RmapWalkResult

/// Result of walking one mapping during an rmap walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RmapWalkAction {
    /// Continue walking.
    Continue,
    /// Stop walking (found what we needed or no mappings).
    Stop,
}

// -- RmapStats

/// Aggregate rmap statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct RmapStats {
    /// Total anon_vma allocs / frees.
    pub anon_vmas_allocated: u64,
    /// Total anon_vma frees.
    pub anon_vmas_freed: u64,
    /// Total chains created / removed.
    pub chains_created: u64,
    /// Total chains removed.
    pub chains_removed: u64,
    /// Total address_space entries.
    pub address_space_entries: u64,
    /// Total page_referenced / try_to_unmap / rmap_walk calls.
    pub page_referenced_calls: u64,
    /// Total try_to_unmap calls.
    pub try_to_unmap_calls: u64,
    /// Successful / failed unmaps.
    pub unmaps_success: u64,
    /// Failed unmaps.
    pub unmaps_failed: u64,
    /// Total rmap_walk invocations.
    pub rmap_walks: u64,
    /// Total mappings walked.
    pub mappings_walked: u64,
    /// Total migrations.
    pub migrations: u64,
}

// -- RmapManager

/// Top-level reverse mapping manager.
///
/// Maintains the anon_vma tree, anon_vma_chain list, and
/// address_space rmap for file pages. Provides the core
/// `page_referenced()`, `try_to_unmap()`, and `rmap_walk()`
/// operations.
pub struct RmapManager {
    /// Anonymous VMA structures.
    anon_vmas: [AnonVma; MAX_ANON_VMAS],
    /// Next available anon_vma ID.
    next_anon_vma_id: u64,
    /// Number of active anon_vmas.
    anon_vma_count: usize,
    /// Anonymous VMA chain links.
    chains: [AnonVmaChain; MAX_ANON_VMA_CHAINS],
    /// Number of active chains.
    chain_count: usize,
    /// Address space rmap entries (file pages).
    address_space: [AddressSpaceEntry; MAX_ADDRESS_SPACE_ENTRIES],
    /// Number of active address_space entries.
    address_space_count: usize,
    /// Tracked rmap pages.
    pages: [RmapPage; MAX_RMAP_PAGES],
    /// Number of active rmap pages.
    page_count: usize,
    /// Statistics.
    stats: RmapStats,
}

impl RmapManager {
    /// Create a new, empty rmap manager.
    pub const fn new() -> Self {
        Self {
            anon_vmas: [const { AnonVma::empty() }; MAX_ANON_VMAS],
            next_anon_vma_id: 1,
            anon_vma_count: 0,
            chains: [const { AnonVmaChain::empty() }; MAX_ANON_VMA_CHAINS],
            chain_count: 0,
            address_space: [const { AddressSpaceEntry::empty() }; MAX_ADDRESS_SPACE_ENTRIES],
            address_space_count: 0,
            pages: [const { RmapPage::empty() }; MAX_RMAP_PAGES],
            page_count: 0,
            stats: RmapStats {
                anon_vmas_allocated: 0,
                anon_vmas_freed: 0,
                chains_created: 0,
                chains_removed: 0,
                address_space_entries: 0,
                page_referenced_calls: 0,
                try_to_unmap_calls: 0,
                unmaps_success: 0,
                unmaps_failed: 0,
                rmap_walks: 0,
                mappings_walked: 0,
                migrations: 0,
            },
        }
    }

    // ── anon_vma management ─────────────────────────────────

    /// Allocate a new anon_vma. Returns the index.
    pub fn alloc_anon_vma(&mut self, parent_id: u64) -> Result<usize> {
        let idx = self
            .anon_vmas
            .iter()
            .position(|v| !v.active)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_anon_vma_id;
        self.next_anon_vma_id += 1;
        let root_id = if parent_id == 0 {
            id
        } else {
            self.anon_vmas
                .iter()
                .find(|v| v.active && v.id == parent_id)
                .map(|v| v.root_id)
                .unwrap_or(id)
        };
        if parent_id != 0 {
            for vma in &mut self.anon_vmas {
                if vma.active && vma.id == parent_id {
                    vma.degree += 1;
                    break;
                }
            }
        }
        self.anon_vmas[idx] = AnonVma {
            id,
            root_id,
            refcount: 1,
            chain_count: 0,
            active: true,
            degree: 0,
            parent_id,
        };
        self.anon_vma_count += 1;
        self.stats.anon_vmas_allocated += 1;
        Ok(idx)
    }

    /// Free an anon_vma by index.
    pub fn free_anon_vma(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_ANON_VMAS {
            return Err(Error::InvalidArgument);
        }
        if !self.anon_vmas[idx].active {
            return Err(Error::NotFound);
        }
        if self.anon_vmas[idx].refcount > 0 {
            return Err(Error::Busy);
        }
        // Remove all chains referencing this anon_vma.
        for chain in &mut self.chains {
            if chain.active && chain.anon_vma_idx == idx {
                chain.active = false;
                self.chain_count = self.chain_count.saturating_sub(1);
                self.stats.chains_removed += 1;
            }
        }
        self.anon_vmas[idx].active = false;
        self.anon_vma_count = self.anon_vma_count.saturating_sub(1);
        self.stats.anon_vmas_freed += 1;
        Ok(())
    }

    /// Get an anon_vma by index.
    pub fn anon_vma(&self, idx: usize) -> Result<&AnonVma> {
        if idx >= MAX_ANON_VMAS {
            return Err(Error::InvalidArgument);
        }
        if !self.anon_vmas[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.anon_vmas[idx])
    }

    // ── anon_vma_chain management ───────────────────────────

    /// Create an anon_vma_chain linking a VMA to an anon_vma.
    pub fn create_chain(
        &mut self,
        pid: u64,
        anon_vma_idx: usize,
        vma_start: u64,
        vma_end: u64,
    ) -> Result<usize> {
        if anon_vma_idx >= MAX_ANON_VMAS {
            return Err(Error::InvalidArgument);
        }
        if !self.anon_vmas[anon_vma_idx].active {
            return Err(Error::NotFound);
        }
        let idx = self
            .chains
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;
        let vma_id = pid.wrapping_mul(0x1000) ^ vma_start;
        self.chains[idx] = AnonVmaChain {
            vma_id,
            pid,
            anon_vma_idx,
            vma_start,
            vma_end,
            active: true,
        };
        self.chain_count += 1;
        self.anon_vmas[anon_vma_idx].chain_count += 1;
        self.anon_vmas[anon_vma_idx].get();
        self.stats.chains_created += 1;
        Ok(idx)
    }

    /// Remove an anon_vma_chain by index.
    pub fn remove_chain(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_ANON_VMA_CHAINS {
            return Err(Error::InvalidArgument);
        }
        if !self.chains[idx].active {
            return Err(Error::NotFound);
        }
        let av_idx = self.chains[idx].anon_vma_idx;
        self.chains[idx].active = false;
        self.chain_count = self.chain_count.saturating_sub(1);
        self.stats.chains_removed += 1;
        if av_idx < MAX_ANON_VMAS && self.anon_vmas[av_idx].active {
            self.anon_vmas[av_idx].chain_count =
                self.anon_vmas[av_idx].chain_count.saturating_sub(1);
            let _ = self.anon_vmas[av_idx].put();
        }
        Ok(())
    }

    // ── Address space rmap (file pages) ─────────────────────

    /// Register a file page in the address_space rmap. Returns the entry index.
    pub fn add_file_rmap(
        &mut self,
        file_id: u64,
        page_index: u64,
        mapping: VirtualMapping,
    ) -> Result<usize> {
        // Check if an entry already exists.
        for (i, entry) in self.address_space.iter_mut().enumerate() {
            if entry.active && entry.file_id == file_id && entry.page_index == page_index {
                entry.add_mapping(mapping)?;
                return Ok(i);
            }
        }

        // Allocate a new entry.
        let idx = self
            .address_space
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        self.address_space[idx] = AddressSpaceEntry::empty();
        self.address_space[idx].file_id = file_id;
        self.address_space[idx].page_index = page_index;
        self.address_space[idx].active = true;
        self.address_space[idx].add_mapping(mapping)?;
        self.address_space_count += 1;
        self.stats.address_space_entries += 1;
        Ok(idx)
    }

    /// Remove a file mapping from the address_space rmap.
    pub fn remove_file_rmap(
        &mut self,
        file_id: u64,
        page_index: u64,
        pid: u64,
        vaddr: u64,
    ) -> Result<()> {
        for entry in &mut self.address_space {
            if entry.active && entry.file_id == file_id && entry.page_index == page_index {
                entry.remove_mapping(pid, vaddr)?;
                if entry.mapping_count == 0 {
                    entry.active = false;
                    self.address_space_count = self.address_space_count.saturating_sub(1);
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    // ── Page tracking ───────────────────────────────────────

    /// Register a page in the rmap system. Returns the page index.
    pub fn register_page(
        &mut self,
        pfn: u64,
        page_type: RmapPageType,
        assoc_idx: usize,
    ) -> Result<usize> {
        let idx = self
            .pages
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;
        let is_anon = page_type == RmapPageType::Anon;
        let is_file = page_type == RmapPageType::File;
        self.pages[idx] = RmapPage {
            pfn,
            page_type,
            anon_vma_idx: if is_anon { assoc_idx } else { 0 },
            address_space_idx: if is_file { assoc_idx } else { 0 },
            mapcount: 1,
            refcount: 1,
            active: true,
        };
        self.page_count += 1;
        Ok(idx)
    }

    /// Unregister a page from the rmap system.
    pub fn unregister_page(&mut self, pfn: u64) -> Result<()> {
        let idx = self
            .pages
            .iter()
            .position(|p| p.active && p.pfn == pfn)
            .ok_or(Error::NotFound)?;
        self.pages[idx].active = false;
        self.page_count = self.page_count.saturating_sub(1);
        Ok(())
    }

    /// Adjust a page's mapcount by `delta` (+1 for add, -1 for remove).
    pub fn adjust_mapcount(&mut self, pfn: u64, delta: i32) -> Result<()> {
        let page = self
            .pages
            .iter_mut()
            .find(|p| p.active && p.pfn == pfn)
            .ok_or(Error::NotFound)?;
        if delta > 0 {
            page.mapcount = page.mapcount.saturating_add(delta as u32);
        } else {
            page.mapcount = page.mapcount.saturating_sub((-delta) as u32);
        }
        Ok(())
    }

    // ── Core rmap operations ────────────────────────────────

    /// Check if any mapping of a page has the referenced bit set.
    /// Returns the number of references found.
    pub fn page_referenced(&mut self, pfn: u64, flags: &RmapFlags) -> Result<u32> {
        self.stats.page_referenced_calls += 1;

        let page_idx = self
            .pages
            .iter()
            .position(|p| p.active && p.pfn == pfn)
            .ok_or(Error::NotFound)?;

        let page = self.pages[page_idx];
        let mut ref_count = 0u32;

        match page.page_type {
            RmapPageType::Anon | RmapPageType::Ksm => {
                // Walk all chains for this anon_vma.
                let av_idx = page.anon_vma_idx;
                for chain in &self.chains {
                    if !chain.active || chain.anon_vma_idx != av_idx {
                        continue;
                    }
                    // Simulate checking the PTE accessed bit.
                    ref_count += 1;
                    self.stats.mappings_walked += 1;
                }
            }
            RmapPageType::File => {
                let as_idx = page.address_space_idx;
                if as_idx < MAX_ADDRESS_SPACE_ENTRIES && self.address_space[as_idx].active {
                    let entry = &self.address_space[as_idx];
                    for m in &entry.mappings[..entry.mapping_count] {
                        if m.valid && m.referenced {
                            ref_count += 1;
                        }
                        self.stats.mappings_walked += 1;
                    }
                }
            }
        }

        // Optionally clear the referenced bit.
        if flags.clear_referenced {
            if page.page_type == RmapPageType::File {
                let as_idx = page.address_space_idx;
                if as_idx < MAX_ADDRESS_SPACE_ENTRIES && self.address_space[as_idx].active {
                    let mc = self.address_space[as_idx].mapping_count;
                    for m in &mut self.address_space[as_idx].mappings[..mc] {
                        m.referenced = false;
                    }
                }
            }
        }

        self.stats.rmap_walks += 1;
        Ok(ref_count)
    }

    /// Attempt to unmap a page from all processes.
    /// Returns `true` if the page was fully unmapped (mapcount reached 0).
    pub fn try_to_unmap(&mut self, pfn: u64, flags: &RmapFlags) -> Result<bool> {
        self.stats.try_to_unmap_calls += 1;

        let page_idx = self
            .pages
            .iter()
            .position(|p| p.active && p.pfn == pfn)
            .ok_or(Error::NotFound)?;

        let page_type = self.pages[page_idx].page_type;
        let mut unmapped = 0u32;

        match page_type {
            RmapPageType::Anon | RmapPageType::Ksm => {
                let av_idx = self.pages[page_idx].anon_vma_idx;
                let mapcount = self.pages[page_idx].mapcount;

                for chain in &mut self.chains {
                    if !chain.active || chain.anon_vma_idx != av_idx {
                        continue;
                    }
                    // Simulate PTE unmap.
                    if flags.migration {
                        self.stats.migrations += 1;
                    }
                    unmapped += 1;
                    self.stats.mappings_walked += 1;
                    if unmapped >= mapcount {
                        break;
                    }
                }
            }
            RmapPageType::File => {
                let as_idx = self.pages[page_idx].address_space_idx;
                if as_idx < MAX_ADDRESS_SPACE_ENTRIES && self.address_space[as_idx].active {
                    let mc = self.address_space[as_idx].mapping_count;
                    for m in &mut self.address_space[as_idx].mappings[..mc] {
                        if m.valid {
                            m.valid = false;
                            unmapped += 1;
                            if flags.migration {
                                self.stats.migrations += 1;
                            }
                            self.stats.mappings_walked += 1;
                        }
                    }
                    // Adjust mapping count.
                    self.address_space[as_idx].mapping_count = 0;
                }
            }
        }

        // Update mapcount.
        self.pages[page_idx].mapcount = self.pages[page_idx].mapcount.saturating_sub(unmapped);

        let fully_unmapped = self.pages[page_idx].mapcount == 0;
        if fully_unmapped {
            self.stats.unmaps_success += 1;
        } else {
            self.stats.unmaps_failed += 1;
        }

        self.stats.rmap_walks += 1;
        Ok(fully_unmapped)
    }

    /// Walk all mappings of a page. Returns (visited, action).
    pub fn rmap_walk(&mut self, pfn: u64) -> Result<(u64, RmapWalkAction)> {
        self.stats.rmap_walks += 1;

        let page_idx = self
            .pages
            .iter()
            .position(|p| p.active && p.pfn == pfn)
            .ok_or(Error::NotFound)?;

        let page = self.pages[page_idx];
        let mut visited = 0u64;

        match page.page_type {
            RmapPageType::Anon | RmapPageType::Ksm => {
                let av_idx = page.anon_vma_idx;
                for chain in &self.chains {
                    if !chain.active || chain.anon_vma_idx != av_idx {
                        continue;
                    }
                    visited += 1;
                    self.stats.mappings_walked += 1;
                }
            }
            RmapPageType::File => {
                let as_idx = page.address_space_idx;
                if as_idx < MAX_ADDRESS_SPACE_ENTRIES && self.address_space[as_idx].active {
                    let entry = &self.address_space[as_idx];
                    for m in &entry.mappings[..entry.mapping_count] {
                        if m.valid {
                            visited += 1;
                            self.stats.mappings_walked += 1;
                        }
                    }
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

    // ── Accessors ───────────────────────────────────────────

    /// Return aggregate rmap statistics.
    pub fn stats(&self) -> &RmapStats {
        &self.stats
    }

    /// Number of active anon_vmas.
    pub fn anon_vma_count(&self) -> usize {
        self.anon_vma_count
    }

    /// Number of active chains.
    pub fn chain_count(&self) -> usize {
        self.chain_count
    }

    /// Number of active address_space entries.
    pub fn address_space_count(&self) -> usize {
        self.address_space_count
    }

    /// Number of tracked pages.
    pub fn page_count(&self) -> usize {
        self.page_count
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = RmapStats::default();
    }
}

impl Default for RmapManager {
    fn default() -> Self {
        Self::new()
    }
}
