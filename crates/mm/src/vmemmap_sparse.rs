// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Sparse vmemmap optimization.
//!
//! The kernel maintains a `struct page` array (vmemmap) that describes
//! every physical page frame. By default, each 4 KiB page in the
//! vmemmap area maps a single 4 KiB page of `struct page` metadata.
//! This is wasteful for large-memory systems where most sections are
//! contiguous.
//!
//! This module implements sparse vmemmap optimization: remapping the
//! vmemmap backing from many small 4 KiB pages to fewer 2 MiB or
//! 1 GiB huge pages. This drastically reduces the number of TLB
//! entries required to walk the page metadata array.
//!
//! # Architecture
//!
//! - [`VmemmapPageSize`] — backing page size (4K, 2M, 1G)
//! - [`VmemmapSectionState`] — per-section mapping state
//! - [`VmemmapSection`] — a contiguous region of vmemmap backed by a
//!   single mapping granularity
//! - [`VmemmapStats`] — optimization statistics
//! - [`VmemmapOptimizer`] — engine that manages sections and performs
//!   remapping decisions
//!
//! Reference: Linux `mm/sparse-vmemmap.c`,
//! `Documentation/mm/vmemmap_dedup.rst`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard small page size (4 KiB).
const PAGE_SIZE_4K: u64 = 4096;

/// Huge page size (2 MiB).
const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;

/// Gigantic page size (1 GiB).
const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

/// Number of 4K pages covered by a single 2M vmemmap page.
/// Each `struct page` is 64 bytes, so one 2M page covers
/// 2M / 64 = 32768 page descriptors.
const PAGES_PER_2M_VMEMMAP: u64 = PAGE_SIZE_2M / 64;

/// Number of 4K pages covered by a single 1G vmemmap page.
const PAGES_PER_1G_VMEMMAP: u64 = PAGE_SIZE_1G / 64;

/// Number of 4K pages needed per 2M vmemmap mapping
/// (before optimization: 2M / 4K = 512 small pages).
const SMALL_PAGES_PER_2M: u64 = PAGE_SIZE_2M / PAGE_SIZE_4K;

/// Number of 4K pages needed per 1G vmemmap mapping.
const SMALL_PAGES_PER_1G: u64 = PAGE_SIZE_1G / PAGE_SIZE_4K;

/// Maximum number of vmemmap sections tracked.
const MAX_SECTIONS: usize = 256;

/// Maximum number of remap operations in a single batch.
const MAX_REMAP_BATCH: usize = 32;

// -------------------------------------------------------------------
// VmemmapPageSize
// -------------------------------------------------------------------

/// Granularity of the vmemmap backing page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmemmapPageSize {
    /// Standard 4 KiB pages (unoptimized).
    #[default]
    Small4K,
    /// 2 MiB huge pages.
    Huge2M,
    /// 1 GiB gigantic pages.
    Giant1G,
}

impl VmemmapPageSize {
    /// Returns the page size in bytes.
    pub const fn size_bytes(self) -> u64 {
        match self {
            Self::Small4K => PAGE_SIZE_4K,
            Self::Huge2M => PAGE_SIZE_2M,
            Self::Giant1G => PAGE_SIZE_1G,
        }
    }

    /// Returns the number of 4K small pages equivalent to this
    /// page size.
    pub const fn small_page_count(self) -> u64 {
        match self {
            Self::Small4K => 1,
            Self::Huge2M => SMALL_PAGES_PER_2M,
            Self::Giant1G => SMALL_PAGES_PER_1G,
        }
    }
}

// -------------------------------------------------------------------
// VmemmapSectionState
// -------------------------------------------------------------------

/// State of a vmemmap section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmemmapSectionState {
    /// Section is uninitialized (no vmemmap mapping).
    #[default]
    Uninitialized,
    /// Section is mapped with the default small page granularity.
    MappedSmall,
    /// Section has been remapped to a larger page granularity.
    Optimized,
    /// Section is being remapped (transitional state).
    Remapping,
    /// Section is offline (memory hotplug removed).
    Offline,
}

// -------------------------------------------------------------------
// VmemmapSection
// -------------------------------------------------------------------

/// A contiguous region of the vmemmap array.
///
/// Each section covers a range of physical page frame numbers and
/// tracks the vmemmap backing page size for that region.
#[derive(Debug, Clone, Copy)]
pub struct VmemmapSection {
    /// Section index (unique identifier).
    pub section_id: u32,
    /// Start PFN of the physical memory covered by this section.
    pub start_pfn: u64,
    /// Number of page frames covered by this section.
    pub nr_pages: u64,
    /// Virtual address of the vmemmap region for this section.
    pub vmemmap_addr: u64,
    /// Current backing page size.
    pub page_size: VmemmapPageSize,
    /// Current section state.
    pub state: VmemmapSectionState,
    /// Number of 4K backing pages currently used (before
    /// optimization).
    pub small_pages_used: u64,
    /// Number of huge/giant pages after optimization (0 if not
    /// optimized).
    pub large_pages_used: u64,
    /// Whether this section is a HugeTLB section (always huge).
    pub hugetlb: bool,
    /// Whether this section slot is in use.
    pub active: bool,
}

impl VmemmapSection {
    /// Creates an empty, inactive section slot.
    const fn empty() -> Self {
        Self {
            section_id: 0,
            start_pfn: 0,
            nr_pages: 0,
            vmemmap_addr: 0,
            page_size: VmemmapPageSize::Small4K,
            state: VmemmapSectionState::Uninitialized,
            small_pages_used: 0,
            large_pages_used: 0,
            hugetlb: false,
            active: false,
        }
    }

    /// Returns the memory saved by optimizing this section (in 4K
    /// pages).
    ///
    /// The saving is the difference between the number of small pages
    /// that would be required without optimization and the number of
    /// large pages actually used (converted to small-page
    /// equivalents).
    pub const fn pages_saved(&self) -> u64 {
        if self.large_pages_used == 0 {
            return 0;
        }
        let large_equiv = self
            .large_pages_used
            .saturating_mul(self.page_size.small_page_count());
        self.small_pages_used.saturating_sub(large_equiv)
    }

    /// Returns the end PFN (exclusive) of this section.
    pub const fn end_pfn(&self) -> u64 {
        self.start_pfn.saturating_add(self.nr_pages)
    }

    /// Returns `true` if the given PFN falls within this section.
    pub const fn contains_pfn(&self, pfn: u64) -> bool {
        pfn >= self.start_pfn && pfn < self.end_pfn()
    }
}

// -------------------------------------------------------------------
// RemapRequest
// -------------------------------------------------------------------

/// A request to remap a vmemmap section to a different page
/// granularity.
#[derive(Debug, Clone, Copy)]
pub struct RemapRequest {
    /// Section index to remap.
    pub section_id: u32,
    /// Target page size.
    pub target_size: VmemmapPageSize,
    /// Whether the remap has been processed.
    pub completed: bool,
    /// Whether the remap succeeded.
    pub success: bool,
}

impl RemapRequest {
    /// Creates an empty remap request.
    const fn empty() -> Self {
        Self {
            section_id: 0,
            target_size: VmemmapPageSize::Small4K,
            completed: false,
            success: false,
        }
    }
}

// -------------------------------------------------------------------
// VmemmapStats
// -------------------------------------------------------------------

/// Aggregate statistics for vmemmap optimization.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmemmapStats {
    /// Total sections tracked.
    pub total_sections: u64,
    /// Sections currently optimized (backed by huge/giant pages).
    pub optimized_sections: u64,
    /// Total 4K pages saved by optimization.
    pub pages_saved: u64,
    /// Total memory saved in bytes.
    pub bytes_saved: u64,
    /// Number of successful remap operations.
    pub remap_success: u64,
    /// Number of failed remap operations.
    pub remap_failed: u64,
    /// Total 4K backing pages currently in use across all sections.
    pub total_small_pages: u64,
    /// Total large backing pages in use across optimized sections.
    pub total_large_pages: u64,
}

// -------------------------------------------------------------------
// VmemmapOptimizer
// -------------------------------------------------------------------

/// Engine managing vmemmap sections and performing optimization
/// decisions.
///
/// Tracks all vmemmap sections and determines which can be remapped
/// from 4K backing to 2M or 1G backing pages. Sections must be
/// aligned and large enough for the target page size.
pub struct VmemmapOptimizer {
    /// Tracked vmemmap sections.
    sections: [VmemmapSection; MAX_SECTIONS],
    /// Number of active sections.
    section_count: usize,
    /// Pending remap requests.
    remap_queue: [RemapRequest; MAX_REMAP_BATCH],
    /// Number of pending remap requests.
    remap_count: usize,
    /// Next section ID to assign.
    next_section_id: u32,
    /// Whether 2M optimization is enabled.
    enable_2m: bool,
    /// Whether 1G optimization is enabled.
    enable_1g: bool,
    /// Aggregate statistics.
    stats: VmemmapStats,
}

impl Default for VmemmapOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl VmemmapOptimizer {
    /// Creates a new optimizer with default settings (2M enabled,
    /// 1G disabled).
    pub const fn new() -> Self {
        Self {
            sections: [VmemmapSection::empty(); MAX_SECTIONS],
            section_count: 0,
            remap_queue: [RemapRequest::empty(); MAX_REMAP_BATCH],
            remap_count: 0,
            next_section_id: 1,
            enable_2m: true,
            enable_1g: false,
            stats: VmemmapStats {
                total_sections: 0,
                optimized_sections: 0,
                pages_saved: 0,
                bytes_saved: 0,
                remap_success: 0,
                remap_failed: 0,
                total_small_pages: 0,
                total_large_pages: 0,
            },
        }
    }

    // ---------------------------------------------------------------
    // Section management
    // ---------------------------------------------------------------

    /// Registers a new vmemmap section.
    ///
    /// `start_pfn` is the first physical page frame covered, `nr_pages`
    /// is the number of page frames, and `vmemmap_addr` is the virtual
    /// address of the vmemmap region.
    ///
    /// The section is initially mapped with 4K pages. The number of
    /// small backing pages is computed as
    /// `ceil(nr_pages * 64 / 4096)` (64 bytes per struct page).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all section slots are full.
    /// Returns [`Error::InvalidArgument`] if `nr_pages` is zero.
    pub fn add_section(&mut self, start_pfn: u64, nr_pages: u64, vmemmap_addr: u64) -> Result<u32> {
        if nr_pages == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.section_count >= MAX_SECTIONS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .sections
            .iter_mut()
            .find(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_section_id;
        self.next_section_id = self.next_section_id.wrapping_add(1);

        // Compute small pages needed: each struct page is 64 bytes.
        let vmemmap_bytes = nr_pages.saturating_mul(64);
        let small_pages = vmemmap_bytes.saturating_add(PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;

        *slot = VmemmapSection::empty();
        slot.section_id = id;
        slot.start_pfn = start_pfn;
        slot.nr_pages = nr_pages;
        slot.vmemmap_addr = vmemmap_addr;
        slot.page_size = VmemmapPageSize::Small4K;
        slot.state = VmemmapSectionState::MappedSmall;
        slot.small_pages_used = small_pages;
        slot.active = true;

        self.section_count += 1;
        self.stats.total_sections += 1;
        self.stats.total_small_pages = self.stats.total_small_pages.saturating_add(small_pages);

        Ok(id)
    }

    /// Removes a vmemmap section by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no section with the given ID
    /// exists.
    /// Returns [`Error::Busy`] if the section is currently being
    /// remapped.
    pub fn remove_section(&mut self, section_id: u32) -> Result<()> {
        let idx = self.find_section_index(section_id).ok_or(Error::NotFound)?;

        let section = &self.sections[idx];
        if section.state == VmemmapSectionState::Remapping {
            return Err(Error::Busy);
        }

        // Update statistics.
        self.stats.total_small_pages = self
            .stats
            .total_small_pages
            .saturating_sub(section.small_pages_used);
        if section.state == VmemmapSectionState::Optimized {
            self.stats.optimized_sections = self.stats.optimized_sections.saturating_sub(1);
            self.stats.total_large_pages = self
                .stats
                .total_large_pages
                .saturating_sub(section.large_pages_used);
            self.stats.pages_saved = self.stats.pages_saved.saturating_sub(section.pages_saved());
            self.stats.bytes_saved = self
                .stats
                .bytes_saved
                .saturating_sub(section.pages_saved().saturating_mul(PAGE_SIZE_4K));
        }

        self.sections[idx].active = false;
        self.sections[idx].state = VmemmapSectionState::Offline;
        self.section_count = self.section_count.saturating_sub(1);
        Ok(())
    }

    /// Marks a section as a HugeTLB section (always backed by huge
    /// pages).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the section does not exist.
    pub fn mark_hugetlb(&mut self, section_id: u32) -> Result<()> {
        let idx = self.find_section_index(section_id).ok_or(Error::NotFound)?;
        self.sections[idx].hugetlb = true;
        Ok(())
    }

    // ---------------------------------------------------------------
    // Optimization engine
    // ---------------------------------------------------------------

    /// Checks whether a section can be remapped to a larger page
    /// size.
    ///
    /// Requirements:
    /// - Section must be in `MappedSmall` state
    /// - Section vmemmap address must be aligned to the target size
    /// - Section must cover enough pages for the target
    fn can_optimize(&self, section: &VmemmapSection, target: VmemmapPageSize) -> bool {
        if section.state != VmemmapSectionState::MappedSmall {
            return false;
        }

        let target_bytes = target.size_bytes();
        let align_mask = target_bytes - 1;

        // vmemmap address alignment check.
        if section.vmemmap_addr & align_mask != 0 {
            return false;
        }

        // Enough vmemmap coverage for at least one large page.
        let vmemmap_bytes = section.nr_pages.saturating_mul(64);
        vmemmap_bytes >= target_bytes
    }

    /// Queues a remap request for a section.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the remap queue is full.
    /// Returns [`Error::NotFound`] if the section does not exist.
    /// Returns [`Error::InvalidArgument`] if the section cannot be
    /// optimized to the target size.
    pub fn queue_remap(&mut self, section_id: u32, target: VmemmapPageSize) -> Result<()> {
        let idx = self.find_section_index(section_id).ok_or(Error::NotFound)?;

        if !self.can_optimize(&self.sections[idx], target) {
            return Err(Error::InvalidArgument);
        }
        if self.remap_count >= MAX_REMAP_BATCH {
            return Err(Error::OutOfMemory);
        }

        self.remap_queue[self.remap_count] = RemapRequest {
            section_id,
            target_size: target,
            completed: false,
            success: false,
        };
        self.remap_count += 1;
        Ok(())
    }

    /// Scans all sections and queues remap requests for eligible
    /// sections.
    ///
    /// Prefers 1G remapping when enabled and the section is large
    /// enough, otherwise falls back to 2M.
    ///
    /// Returns the number of remap requests queued.
    pub fn scan_and_optimize(&mut self) -> usize {
        let mut queued = 0_usize;

        for i in 0..MAX_SECTIONS {
            if !self.sections[i].active {
                continue;
            }
            if self.sections[i].state != VmemmapSectionState::MappedSmall {
                continue;
            }
            if self.remap_count >= MAX_REMAP_BATCH {
                break;
            }

            // Try 1G first, then 2M.
            let sid = self.sections[i].section_id;
            let can_1g =
                self.enable_1g && self.can_optimize(&self.sections[i], VmemmapPageSize::Giant1G);
            let can_2m =
                self.enable_2m && self.can_optimize(&self.sections[i], VmemmapPageSize::Huge2M);

            if can_1g {
                if self.queue_remap(sid, VmemmapPageSize::Giant1G).is_ok() {
                    queued += 1;
                    continue;
                }
            }
            if can_2m {
                if self.queue_remap(sid, VmemmapPageSize::Huge2M).is_ok() {
                    queued += 1;
                }
            }
        }

        queued
    }

    /// Processes all pending remap requests.
    ///
    /// For each request, transitions the section through
    /// `Remapping` state, computes the new large-page count, and
    /// updates statistics.
    ///
    /// Returns `(success, failed)`.
    pub fn process_remaps(&mut self) -> (usize, usize) {
        let mut success = 0_usize;
        let mut failed = 0_usize;

        for i in 0..self.remap_count {
            let req = &self.remap_queue[i];
            if req.completed {
                continue;
            }

            let section_id = req.section_id;
            let target_size = req.target_size;

            let idx = match self.find_section_index(section_id) {
                Some(idx) => idx,
                None => {
                    self.remap_queue[i].completed = true;
                    self.remap_queue[i].success = false;
                    self.stats.remap_failed += 1;
                    failed += 1;
                    continue;
                }
            };

            // Transition to remapping state.
            self.sections[idx].state = VmemmapSectionState::Remapping;

            // Compute how many large pages we need.
            let vmemmap_bytes = self.sections[idx].nr_pages.saturating_mul(64);
            let large_size = target_size.size_bytes();
            let large_count = vmemmap_bytes.saturating_add(large_size - 1) / large_size;

            // Apply the remap.
            let old_small = self.sections[idx].small_pages_used;
            self.sections[idx].page_size = target_size;
            self.sections[idx].large_pages_used = large_count;
            self.sections[idx].state = VmemmapSectionState::Optimized;

            // Compute savings.
            let saved = self.sections[idx].pages_saved();

            self.stats.optimized_sections += 1;
            self.stats.total_large_pages = self.stats.total_large_pages.saturating_add(large_count);
            self.stats.pages_saved = self.stats.pages_saved.saturating_add(saved);
            self.stats.bytes_saved = self
                .stats
                .bytes_saved
                .saturating_add(saved.saturating_mul(PAGE_SIZE_4K));
            self.stats.remap_success += 1;
            let _ = old_small; // Small page count is retained for
            // pages_saved() computation.

            self.remap_queue[i].completed = true;
            self.remap_queue[i].success = true;
            success += 1;
        }

        (success, failed)
    }

    /// Clears completed remap requests from the queue.
    pub fn drain_remaps(&mut self) {
        let mut write = 0_usize;
        for read in 0..self.remap_count {
            if !self.remap_queue[read].completed {
                if write != read {
                    self.remap_queue[write] = self.remap_queue[read];
                }
                write += 1;
            }
        }
        for i in write..self.remap_count {
            self.remap_queue[i] = RemapRequest::empty();
        }
        self.remap_count = write;
    }

    // ---------------------------------------------------------------
    // Configuration
    // ---------------------------------------------------------------

    /// Enables or disables 2M huge page optimization.
    pub fn set_enable_2m(&mut self, enable: bool) {
        self.enable_2m = enable;
    }

    /// Enables or disables 1G gigantic page optimization.
    pub fn set_enable_1g(&mut self, enable: bool) {
        self.enable_1g = enable;
    }

    /// Returns whether 2M optimization is enabled.
    pub const fn is_2m_enabled(&self) -> bool {
        self.enable_2m
    }

    /// Returns whether 1G optimization is enabled.
    pub const fn is_1g_enabled(&self) -> bool {
        self.enable_1g
    }

    // ---------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------

    /// Returns the number of active sections.
    pub const fn section_count(&self) -> usize {
        self.section_count
    }

    /// Returns a reference to a section by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no section with the given ID
    /// exists.
    pub fn get_section(&self, section_id: u32) -> Result<&VmemmapSection> {
        let idx = self.find_section_index(section_id).ok_or(Error::NotFound)?;
        Ok(&self.sections[idx])
    }

    /// Returns the number of pending remap requests.
    pub const fn pending_remaps(&self) -> usize {
        self.remap_count
    }

    /// Returns aggregate statistics.
    pub const fn stats(&self) -> &VmemmapStats {
        &self.stats
    }

    /// Returns `true` if no sections are tracked.
    pub const fn is_empty(&self) -> bool {
        self.section_count == 0
    }

    /// Returns the section containing a given PFN, if any.
    pub fn section_for_pfn(&self, pfn: u64) -> Option<&VmemmapSection> {
        for section in &self.sections {
            if section.active && section.contains_pfn(pfn) {
                return Some(section);
            }
        }
        None
    }

    /// Computes the total vmemmap memory overhead (in bytes) across
    /// all sections.
    ///
    /// This is the sum of `small_pages_used * 4096` for all active
    /// sections, minus any savings from optimization.
    pub fn total_overhead_bytes(&self) -> u64 {
        self.stats
            .total_small_pages
            .saturating_mul(PAGE_SIZE_4K)
            .saturating_sub(self.stats.bytes_saved)
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Finds the array index of a section by ID.
    fn find_section_index(&self, section_id: u32) -> Option<usize> {
        self.sections
            .iter()
            .position(|s| s.active && s.section_id == section_id)
    }
}
