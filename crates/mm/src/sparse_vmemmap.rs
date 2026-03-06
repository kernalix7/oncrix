// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Sparse virtual memory map (vmemmap) management.
//!
//! The kernel maintains a `struct page` descriptor for every physical
//! page frame. These descriptors are arranged in a virtual array called
//! the **vmemmap**. On systems with sparse physical memory (holes
//! between populated banks), only some vmemmap sections actually need
//! backing pages.
//!
//! This module manages per-section state for the sparse vmemmap,
//! supporting:
//! - Hot-add and hot-remove of memory sections
//! - Lazy population of vmemmap backing pages on first access
//! - Section state tracking (present, online, offline, being_removed)
//! - PFN-to-page translation via section lookup
//!
//! # Architecture
//!
//! - [`SectionState`] -- lifecycle state of a memory section
//! - [`SparseSection`] -- per-section metadata (PFN range, vmemmap
//!   address, NUMA node, page count)
//! - [`VmemmapEntry`] -- a single vmemmap page backing entry
//! - [`VmemmapConfig`] -- subsystem configuration
//! - [`SparseMemoryMap`] -- top-level manager holding all sections
//! - [`SparseMemoryStats`] -- aggregate statistics
//!
//! # Section Geometry
//!
//! Each section covers a fixed-size range of physical address space
//! (128 MiB by default, matching Linux `SECTION_SIZE_BITS = 27`).
//! Within each section, every page frame has a corresponding 64-byte
//! `struct page` descriptor. The vmemmap pages backing those
//! descriptors are populated lazily.
//!
//! Reference: Linux `mm/sparse.c`, `mm/sparse-vmemmap.c`,
//! `include/linux/mmzone.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Size of a `struct page` descriptor in bytes.
const STRUCT_PAGE_SIZE: usize = 64;

/// Number of page frames per section (128 MiB / 4 KiB = 32768).
const PAGES_PER_SECTION: usize = 32768;

/// Section size in bytes (128 MiB).
const SECTION_SIZE_BYTES: u64 = (PAGES_PER_SECTION as u64) * (PAGE_SIZE as u64);

/// Maximum number of sections tracked.
const MAX_SECTIONS: usize = 512;

/// Maximum number of vmemmap backing entries per section.
///
/// Each section needs `PAGES_PER_SECTION * 64 / 4096 = 512` vmemmap
/// pages.
const VMEMMAP_PAGES_PER_SECTION: usize = (PAGES_PER_SECTION * STRUCT_PAGE_SIZE) / PAGE_SIZE;

/// Maximum NUMA node count.
const MAX_NUMA_NODES: usize = 8;

/// Maximum number of pending section operations (add/remove queue).
const MAX_PENDING_OPS: usize = 32;

/// Vmemmap base virtual address (x86_64 convention).
const VMEMMAP_BASE: u64 = 0xFFFF_EA00_0000_0000;

// -------------------------------------------------------------------
// SectionState
// -------------------------------------------------------------------

/// Lifecycle state of a memory section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SectionState {
    /// Section slot is not in use.
    #[default]
    Absent,
    /// Section has been registered but vmemmap not yet populated.
    Present,
    /// Section is fully online (vmemmap populated, pages usable).
    Online,
    /// Section is offline (pages not allocatable but metadata
    /// retained).
    Offline,
    /// Section is being hot-removed.
    BeingRemoved,
    /// Section is being hot-added (transitional).
    BeingAdded,
}

// -------------------------------------------------------------------
// VmemmapEntry
// -------------------------------------------------------------------

/// A single vmemmap backing-page entry within a section.
///
/// Each entry tracks the physical frame number of the page that backs
/// a portion of the vmemmap array and whether that page has been
/// populated.
#[derive(Debug, Clone, Copy)]
pub struct VmemmapEntry {
    /// Physical frame number of the backing page.
    pub backing_pfn: u64,
    /// Virtual address within the vmemmap region.
    pub virt_addr: u64,
    /// Whether this entry has been populated (backing page allocated).
    pub populated: bool,
    /// Whether this entry uses a huge page (2 MiB) instead of 4 KiB.
    pub huge: bool,
}

impl VmemmapEntry {
    /// Creates an empty, unpopulated entry.
    const fn empty() -> Self {
        Self {
            backing_pfn: 0,
            virt_addr: 0,
            populated: false,
            huge: false,
        }
    }
}

// -------------------------------------------------------------------
// SparseSection
// -------------------------------------------------------------------

/// Metadata for a single memory section in the sparse memory model.
///
/// A section covers [`PAGES_PER_SECTION`] contiguous page frames and
/// provides a vmemmap region that maps `struct page` descriptors for
/// those frames.
#[derive(Debug, Clone, Copy)]
pub struct SparseSection {
    /// Unique section number (derived from start PFN).
    pub section_nr: u32,
    /// First page frame number in this section.
    pub start_pfn: u64,
    /// Number of page frames actually present (may be less than
    /// [`PAGES_PER_SECTION`] for partially populated sections).
    pub present_pages: usize,
    /// Virtual address of the vmemmap region for this section.
    pub vmemmap_addr: u64,
    /// Current lifecycle state.
    pub state: SectionState,
    /// NUMA node to which this section belongs.
    pub nid: u8,
    /// Number of vmemmap backing pages that have been populated.
    pub populated_vmemmap_pages: usize,
    /// Total vmemmap backing pages needed for this section.
    pub total_vmemmap_pages: usize,
    /// Whether this section is marked early (boot-time memory).
    pub early: bool,
    /// Whether this slot is active.
    pub active: bool,
    /// Usage flags (bit 0: movable, bit 1: kernel, bit 2: user).
    pub usage_flags: u8,
}

impl SparseSection {
    /// Creates an empty, inactive section slot.
    const fn empty() -> Self {
        Self {
            section_nr: 0,
            start_pfn: 0,
            present_pages: 0,
            vmemmap_addr: 0,
            state: SectionState::Absent,
            nid: 0,
            populated_vmemmap_pages: 0,
            total_vmemmap_pages: 0,
            early: false,
            active: false,
            usage_flags: 0,
        }
    }

    /// Returns the end PFN (exclusive) of this section.
    pub const fn end_pfn(&self) -> u64 {
        self.start_pfn + PAGES_PER_SECTION as u64
    }

    /// Returns `true` if the given PFN is within this section's
    /// range.
    pub const fn contains_pfn(&self, pfn: u64) -> bool {
        pfn >= self.start_pfn && pfn < self.end_pfn()
    }

    /// Returns the section size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        SECTION_SIZE_BYTES
    }

    /// Returns the fraction of vmemmap pages populated (0..100).
    pub fn vmemmap_populated_pct(&self) -> u8 {
        if self.total_vmemmap_pages == 0 {
            return 0;
        }
        ((self.populated_vmemmap_pages * 100) / self.total_vmemmap_pages) as u8
    }

    /// Returns the number of vmemmap pages still needed.
    pub fn vmemmap_remaining(&self) -> usize {
        self.total_vmemmap_pages
            .saturating_sub(self.populated_vmemmap_pages)
    }

    /// Returns `true` if the section is fully online and usable.
    pub const fn is_online(&self) -> bool {
        matches!(self.state, SectionState::Online)
    }

    /// Returns `true` if the section is present (has metadata).
    pub const fn is_present(&self) -> bool {
        matches!(
            self.state,
            SectionState::Present | SectionState::Online | SectionState::Offline
        )
    }
}

// -------------------------------------------------------------------
// PendingOp
// -------------------------------------------------------------------

/// A pending section operation (add or remove).
#[derive(Debug, Clone, Copy)]
struct PendingOp {
    /// Section number targeted.
    section_nr: u32,
    /// Whether this is an add (true) or remove (false) operation.
    is_add: bool,
    /// NUMA node (only relevant for add).
    nid: u8,
    /// Start PFN (only relevant for add).
    start_pfn: u64,
    /// Number of present pages (only relevant for add).
    present_pages: usize,
    /// Whether this slot is occupied.
    active: bool,
}

impl PendingOp {
    const fn empty() -> Self {
        Self {
            section_nr: 0,
            is_add: false,
            nid: 0,
            start_pfn: 0,
            present_pages: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// VmemmapConfig
// -------------------------------------------------------------------

/// Configuration for the sparse vmemmap subsystem.
#[derive(Debug, Clone, Copy)]
pub struct VmemmapConfig {
    /// Whether to populate vmemmap lazily (on first access) or
    /// eagerly (at section add time).
    pub lazy_populate: bool,
    /// Whether to use huge pages for vmemmap backing where possible.
    pub use_huge_vmemmap: bool,
    /// VMEMMAP base virtual address.
    pub vmemmap_base: u64,
    /// Maximum sections allowed.
    pub max_sections: usize,
}

impl Default for VmemmapConfig {
    fn default() -> Self {
        Self {
            lazy_populate: true,
            use_huge_vmemmap: false,
            vmemmap_base: VMEMMAP_BASE,
            max_sections: MAX_SECTIONS,
        }
    }
}

// -------------------------------------------------------------------
// SparseMemoryStats
// -------------------------------------------------------------------

/// Aggregate statistics for the sparse memory map subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct SparseMemoryStats {
    /// Total sections registered.
    pub total_sections: usize,
    /// Sections currently online.
    pub online_sections: usize,
    /// Sections currently offline.
    pub offline_sections: usize,
    /// Total page frames covered by all sections.
    pub total_pages: u64,
    /// Total present (populated) page frames.
    pub present_pages: u64,
    /// Total vmemmap backing pages populated.
    pub vmemmap_pages_populated: u64,
    /// Total vmemmap backing pages needed.
    pub vmemmap_pages_total: u64,
    /// Cumulative section add operations.
    pub sections_added: u64,
    /// Cumulative section remove operations.
    pub sections_removed: u64,
    /// Pending operations in queue.
    pub pending_ops: usize,
    /// Per-NUMA-node section counts.
    pub sections_per_node: [usize; MAX_NUMA_NODES],
}

// -------------------------------------------------------------------
// SparseMemoryMap
// -------------------------------------------------------------------

/// Top-level manager for the sparse virtual memory map.
///
/// Tracks all memory sections, their vmemmap backing state, and
/// provides PFN-to-section lookup. Supports hot-add and hot-remove
/// of sections for memory hotplug.
pub struct SparseMemoryMap {
    /// Section slots.
    sections: [SparseSection; MAX_SECTIONS],
    /// Number of active sections.
    section_count: usize,
    /// Pending operation queue.
    pending: [PendingOp; MAX_PENDING_OPS],
    /// Number of pending operations.
    pending_count: usize,
    /// Next section number to assign (for auto-numbering).
    next_section_nr: u32,
    /// Configuration.
    config: VmemmapConfig,
    /// Aggregate statistics.
    stats: SparseMemoryStats,
}

impl Default for SparseMemoryMap {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMemoryMap {
    /// Creates a new, empty sparse memory map with default
    /// configuration.
    pub const fn new() -> Self {
        Self {
            sections: [SparseSection::empty(); MAX_SECTIONS],
            section_count: 0,
            pending: [const { PendingOp::empty() }; MAX_PENDING_OPS],
            pending_count: 0,
            next_section_nr: 0,
            config: VmemmapConfig {
                lazy_populate: true,
                use_huge_vmemmap: false,
                vmemmap_base: VMEMMAP_BASE,
                max_sections: MAX_SECTIONS,
            },
            stats: SparseMemoryStats {
                total_sections: 0,
                online_sections: 0,
                offline_sections: 0,
                total_pages: 0,
                present_pages: 0,
                vmemmap_pages_populated: 0,
                vmemmap_pages_total: 0,
                sections_added: 0,
                sections_removed: 0,
                pending_ops: 0,
                sections_per_node: [0; MAX_NUMA_NODES],
            },
        }
    }

    /// Creates a sparse memory map with custom configuration.
    pub fn with_config(config: VmemmapConfig) -> Self {
        let mut map = Self::new();
        map.config = config;
        map
    }

    // ---------------------------------------------------------------
    // Section management: init / populate / depopulate
    // ---------------------------------------------------------------

    /// Initialises and adds a new section to the sparse map.
    ///
    /// The section covers PFNs `[start_pfn, start_pfn +
    /// PAGES_PER_SECTION)`. `present_pages` may be less than the full
    /// section (partial population).
    ///
    /// The section starts in [`SectionState::Present`]. Call
    /// [`populate_section`](Self::populate_section) to bring it
    /// online.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if all section slots are full.
    /// - [`Error::InvalidArgument`] if `present_pages` exceeds
    ///   [`PAGES_PER_SECTION`] or `nid` exceeds [`MAX_NUMA_NODES`].
    /// - [`Error::AlreadyExists`] if a section with the same
    ///   `start_pfn` already exists.
    pub fn init_section(&mut self, start_pfn: u64, present_pages: usize, nid: u8) -> Result<u32> {
        if present_pages > PAGES_PER_SECTION {
            return Err(Error::InvalidArgument);
        }
        if (nid as usize) >= MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        if self.section_count >= MAX_SECTIONS {
            return Err(Error::OutOfMemory);
        }

        // Check for duplicates.
        if self.find_section_by_pfn(start_pfn).is_some() {
            return Err(Error::AlreadyExists);
        }

        let slot_idx = self
            .sections
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;

        let section_nr = self.next_section_nr;
        self.next_section_nr = self.next_section_nr.wrapping_add(1);

        let vmemmap_addr = self.config.vmemmap_base + (start_pfn * STRUCT_PAGE_SIZE as u64);
        let total_vmemmap = VMEMMAP_PAGES_PER_SECTION;

        self.sections[slot_idx] = SparseSection {
            section_nr,
            start_pfn,
            present_pages,
            vmemmap_addr,
            state: SectionState::Present,
            nid,
            populated_vmemmap_pages: 0,
            total_vmemmap_pages: total_vmemmap,
            early: false,
            active: true,
            usage_flags: 0,
        };

        self.section_count += 1;
        self.stats.total_sections = self.section_count;
        self.stats.total_pages += PAGES_PER_SECTION as u64;
        self.stats.present_pages += present_pages as u64;
        self.stats.vmemmap_pages_total += total_vmemmap as u64;
        self.stats.sections_added += 1;

        if (nid as usize) < MAX_NUMA_NODES {
            self.stats.sections_per_node[nid as usize] += 1;
        }

        Ok(section_nr)
    }

    /// Populates a section's vmemmap backing pages, bringing it
    /// online.
    ///
    /// In a real kernel, this would allocate physical pages and set up
    /// page table mappings for the vmemmap region. Here, we simulate
    /// the state transition and page accounting.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the section does not exist.
    /// - [`Error::InvalidArgument`] if the section is not in
    ///   `Present` or `Offline` state.
    pub fn populate_section(&mut self, section_nr: u32) -> Result<()> {
        let idx = self.find_section_index(section_nr).ok_or(Error::NotFound)?;

        let state = self.sections[idx].state;
        if state != SectionState::Present && state != SectionState::Offline {
            return Err(Error::InvalidArgument);
        }

        let total = self.sections[idx].total_vmemmap_pages;
        let already = self.sections[idx].populated_vmemmap_pages;
        let to_populate = total.saturating_sub(already);

        self.sections[idx].populated_vmemmap_pages = total;
        self.sections[idx].state = SectionState::Online;

        self.stats.vmemmap_pages_populated += to_populate as u64;
        self.stats.online_sections += 1;
        if state == SectionState::Offline {
            self.stats.offline_sections = self.stats.offline_sections.saturating_sub(1);
        }

        Ok(())
    }

    /// Depopulates a section's vmemmap, taking it offline.
    ///
    /// The section transitions to `Offline` state. Vmemmap backing
    /// pages are released.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the section does not exist.
    /// - [`Error::InvalidArgument`] if the section is not `Online`.
    pub fn depopulate_section(&mut self, section_nr: u32) -> Result<usize> {
        let idx = self.find_section_index(section_nr).ok_or(Error::NotFound)?;

        if self.sections[idx].state != SectionState::Online {
            return Err(Error::InvalidArgument);
        }

        let released = self.sections[idx].populated_vmemmap_pages;
        self.sections[idx].populated_vmemmap_pages = 0;
        self.sections[idx].state = SectionState::Offline;

        self.stats.vmemmap_pages_populated -= released as u64;
        self.stats.online_sections = self.stats.online_sections.saturating_sub(1);
        self.stats.offline_sections += 1;

        Ok(released)
    }

    /// Removes a section entirely from the sparse map.
    ///
    /// The section must be in `Offline` or `Present` state. All
    /// resources are freed.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the section does not exist.
    /// - [`Error::Busy`] if the section is `Online` or in a
    ///   transitional state.
    pub fn remove_section(&mut self, section_nr: u32) -> Result<()> {
        let idx = self.find_section_index(section_nr).ok_or(Error::NotFound)?;

        let state = self.sections[idx].state;
        if state == SectionState::Online
            || state == SectionState::BeingAdded
            || state == SectionState::BeingRemoved
        {
            return Err(Error::Busy);
        }

        let nid = self.sections[idx].nid;
        let present = self.sections[idx].present_pages;
        let vmemmap_total = self.sections[idx].total_vmemmap_pages;

        self.sections[idx] = SparseSection::empty();
        self.section_count = self.section_count.saturating_sub(1);

        self.stats.total_sections = self.section_count;
        self.stats.total_pages -= PAGES_PER_SECTION as u64;
        self.stats.present_pages -= present as u64;
        self.stats.vmemmap_pages_total -= vmemmap_total as u64;
        self.stats.sections_removed += 1;

        if state == SectionState::Offline {
            self.stats.offline_sections = self.stats.offline_sections.saturating_sub(1);
        }
        if (nid as usize) < MAX_NUMA_NODES {
            self.stats.sections_per_node[nid as usize] =
                self.stats.sections_per_node[nid as usize].saturating_sub(1);
        }

        Ok(())
    }

    // ---------------------------------------------------------------
    // PFN-to-page translation
    // ---------------------------------------------------------------

    /// Translates a page frame number to the virtual address of its
    /// `struct page` descriptor in the vmemmap.
    ///
    /// Returns `None` if the PFN does not belong to any section or
    /// the section's vmemmap is not populated.
    pub fn pfn_to_page(&self, pfn: u64) -> Option<u64> {
        for section in &self.sections {
            if !section.active || !section.contains_pfn(pfn) {
                continue;
            }
            if section.state != SectionState::Online {
                return None;
            }
            let offset_within_section = pfn - section.start_pfn;
            let page_addr =
                section.vmemmap_addr + offset_within_section * (STRUCT_PAGE_SIZE as u64);
            return Some(page_addr);
        }
        None
    }

    /// Returns the section number containing a given PFN, or `None`.
    pub fn pfn_to_section_nr(&self, pfn: u64) -> Option<u32> {
        for section in &self.sections {
            if section.active && section.contains_pfn(pfn) {
                return Some(section.section_nr);
            }
        }
        None
    }

    /// Checks whether a section is active (registered and usable).
    pub fn section_active(&self, section_nr: u32) -> bool {
        self.find_section_index(section_nr)
            .map(|idx| self.sections[idx].is_online())
            .unwrap_or(false)
    }

    /// Checks whether a section is present (registered, may or may
    /// not be online).
    pub fn section_present(&self, section_nr: u32) -> bool {
        self.find_section_index(section_nr)
            .map(|idx| self.sections[idx].is_present())
            .unwrap_or(false)
    }

    // ---------------------------------------------------------------
    // Pending operations queue
    // ---------------------------------------------------------------

    /// Queues a section add operation for deferred processing.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the queue is full.
    pub fn queue_add(&mut self, start_pfn: u64, present_pages: usize, nid: u8) -> Result<()> {
        if self.pending_count >= MAX_PENDING_OPS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .pending
            .iter_mut()
            .find(|op| !op.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = PendingOp {
            section_nr: 0, // assigned on commit
            is_add: true,
            nid,
            start_pfn,
            present_pages,
            active: true,
        };
        self.pending_count += 1;
        self.stats.pending_ops = self.pending_count;

        Ok(())
    }

    /// Queues a section remove operation for deferred processing.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the queue is full.
    /// - [`Error::NotFound`] if the section does not exist.
    pub fn queue_remove(&mut self, section_nr: u32) -> Result<()> {
        if self.find_section_index(section_nr).is_none() {
            return Err(Error::NotFound);
        }
        if self.pending_count >= MAX_PENDING_OPS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .pending
            .iter_mut()
            .find(|op| !op.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = PendingOp {
            section_nr,
            is_add: false,
            nid: 0,
            start_pfn: 0,
            present_pages: 0,
            active: true,
        };
        self.pending_count += 1;
        self.stats.pending_ops = self.pending_count;

        Ok(())
    }

    /// Processes all pending operations.
    ///
    /// Returns `(added, removed)` counts.
    pub fn process_pending(&mut self) -> (usize, usize) {
        let mut added = 0usize;
        let mut removed = 0usize;

        // Collect pending ops into a local buffer to avoid borrow
        // issues.
        let mut ops = [PendingOp::empty(); MAX_PENDING_OPS];
        let mut op_count = 0usize;
        for i in 0..MAX_PENDING_OPS {
            if self.pending[i].active {
                ops[op_count] = self.pending[i];
                op_count += 1;
            }
        }

        for op in &ops[..op_count] {
            if op.is_add {
                if self
                    .init_section(op.start_pfn, op.present_pages, op.nid)
                    .is_ok()
                {
                    added += 1;
                }
            } else if self.sections_offline_and_remove(op.section_nr) {
                removed += 1;
            }
        }

        // Clear the queue.
        for entry in &mut self.pending {
            *entry = PendingOp::empty();
        }
        self.pending_count = 0;
        self.stats.pending_ops = 0;

        (added, removed)
    }

    /// Internal: offline and remove a section.
    fn sections_offline_and_remove(&mut self, section_nr: u32) -> bool {
        // First depopulate if online.
        if let Some(idx) = self.find_section_index(section_nr) {
            if self.sections[idx].state == SectionState::Online {
                if self.depopulate_section(section_nr).is_err() {
                    return false;
                }
            }
        }
        self.remove_section(section_nr).is_ok()
    }

    // ---------------------------------------------------------------
    // NUMA helpers
    // ---------------------------------------------------------------

    /// Returns the number of sections on a given NUMA node.
    pub fn sections_on_node(&self, nid: u8) -> usize {
        if (nid as usize) >= MAX_NUMA_NODES {
            return 0;
        }
        self.stats.sections_per_node[nid as usize]
    }

    /// Returns the number of online sections on a given NUMA node.
    pub fn online_sections_on_node(&self, nid: u8) -> usize {
        let mut count = 0usize;
        for section in &self.sections {
            if section.active && section.nid == nid && section.is_online() {
                count += 1;
            }
        }
        count
    }

    /// Returns the total present pages on a given NUMA node.
    pub fn present_pages_on_node(&self, nid: u8) -> u64 {
        let mut total = 0u64;
        for section in &self.sections {
            if section.active && section.nid == nid {
                total += section.present_pages as u64;
            }
        }
        total
    }

    // ---------------------------------------------------------------
    // Batch operations
    // ---------------------------------------------------------------

    /// Adds multiple sections at once.
    ///
    /// Returns the number of sections successfully added.
    pub fn init_sections_batch(
        &mut self,
        starts: &[(u64, usize, u8)], // (start_pfn, present_pages, nid)
    ) -> usize {
        let mut count = 0usize;
        for &(start_pfn, present, nid) in starts {
            match self.init_section(start_pfn, present, nid) {
                Ok(_) => count += 1,
                Err(Error::OutOfMemory) => break,
                Err(_) => continue,
            }
        }
        count
    }

    /// Populates all sections that are in `Present` state.
    ///
    /// Returns the number of sections brought online.
    pub fn populate_all_present(&mut self) -> usize {
        let mut populated = 0usize;
        // Collect section numbers first to avoid borrow issues.
        let mut section_nrs = [0u32; MAX_SECTIONS];
        let mut nr_count = 0usize;
        for section in &self.sections {
            if section.active && section.state == SectionState::Present {
                section_nrs[nr_count] = section.section_nr;
                nr_count += 1;
            }
        }
        for &snr in &section_nrs[..nr_count] {
            if self.populate_section(snr).is_ok() {
                populated += 1;
            }
        }
        populated
    }

    // ---------------------------------------------------------------
    // Configuration & queries
    // ---------------------------------------------------------------

    /// Returns the current configuration.
    pub const fn config(&self) -> &VmemmapConfig {
        &self.config
    }

    /// Updates the configuration.
    pub fn set_config(&mut self, config: VmemmapConfig) {
        self.config = config;
    }

    /// Returns aggregate statistics.
    pub const fn stats(&self) -> &SparseMemoryStats {
        &self.stats
    }

    /// Returns the number of active sections.
    pub const fn section_count(&self) -> usize {
        self.section_count
    }

    /// Returns `true` if no sections are registered.
    pub const fn is_empty(&self) -> bool {
        self.section_count == 0
    }

    /// Returns a reference to a section by its section number.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the section does not exist.
    pub fn get_section(&self, section_nr: u32) -> Result<&SparseSection> {
        let idx = self.find_section_index(section_nr).ok_or(Error::NotFound)?;
        Ok(&self.sections[idx])
    }

    /// Returns the section containing a given PFN.
    pub fn section_for_pfn(&self, pfn: u64) -> Option<&SparseSection> {
        for section in &self.sections {
            if section.active && section.contains_pfn(pfn) {
                return Some(section);
            }
        }
        None
    }

    /// Returns the total vmemmap overhead in bytes.
    pub fn vmemmap_overhead_bytes(&self) -> u64 {
        self.stats
            .vmemmap_pages_populated
            .saturating_mul(PAGE_SIZE as u64)
    }

    /// Computes the PFN for a given physical address.
    pub const fn phys_to_pfn(phys_addr: u64) -> u64 {
        phys_addr / PAGE_SIZE as u64
    }

    /// Computes the physical address for a given PFN.
    pub const fn pfn_to_phys(pfn: u64) -> u64 {
        pfn * PAGE_SIZE as u64
    }

    /// Returns the number of pending operations.
    pub const fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Marks a section as early (boot-time memory).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the section does not exist.
    pub fn mark_early(&mut self, section_nr: u32) -> Result<()> {
        let idx = self.find_section_index(section_nr).ok_or(Error::NotFound)?;
        self.sections[idx].early = true;
        Ok(())
    }

    /// Sets usage flags on a section.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the section does not exist.
    pub fn set_usage_flags(&mut self, section_nr: u32, flags: u8) -> Result<()> {
        let idx = self.find_section_index(section_nr).ok_or(Error::NotFound)?;
        self.sections[idx].usage_flags = flags;
        Ok(())
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Finds the array index of a section by its section number.
    fn find_section_index(&self, section_nr: u32) -> Option<usize> {
        self.sections
            .iter()
            .position(|s| s.active && s.section_nr == section_nr)
    }

    /// Finds a section containing the given start PFN.
    fn find_section_by_pfn(&self, start_pfn: u64) -> Option<usize> {
        self.sections
            .iter()
            .position(|s| s.active && s.start_pfn == start_pfn)
    }
}
