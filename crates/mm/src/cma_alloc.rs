// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CMA Allocation Operations — advanced allocation policies on top
//! of the core [`cma`] Contiguous Memory Allocator.
//!
//! While `cma.rs` provides the basic bitmap-managed CMA region and
//! pool, this module adds higher-level allocation strategies:
//!
//! - [`CmaAllocRequest`] — typed allocation request with size,
//!   alignment, and NUMA affinity
//! - [`CmaAllocPolicy`] — policy selector (best-fit, first-fit,
//!   worst-fit)
//! - [`CmaAllocResult`] — allocation result with PFN and metadata
//! - [`CmaMigrationEngine`] — page migration to defragment CMA
//!   regions when direct allocation fails
//! - [`CmaAllocManager`] — orchestrates allocation attempts with
//!   fallback and migration
//! - [`CmaAllocStats`] — extended allocation statistics
//!
//! Reference: Linux `mm/cma.c`, `mm/page_alloc.c` (CMA paths).

#[allow(dead_code)]
use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of CMA regions the manager can oversee.
const MAX_MANAGED_REGIONS: usize = 16;

/// Maximum number of pending allocation requests in the queue.
const MAX_PENDING_REQUESTS: usize = 32;

/// Maximum number of migration entries per defragmentation pass.
const MAX_MIGRATION_ENTRIES: usize = 64;

/// Maximum number of pages in a managed region's bitmap.
const MAX_REGION_PAGES: usize = 2048;

/// Number of `u64` words needed for the bitmap.
const BITMAP_WORDS: usize = MAX_REGION_PAGES / 64;

/// Default migration scan batch size in pages.
const DEFAULT_SCAN_BATCH: usize = 32;

// -------------------------------------------------------------------
// CmaAllocPolicy
// -------------------------------------------------------------------

/// Allocation policy for selecting a region and offset.
///
/// - `BestFit` — picks the region with the smallest free space that
///   still satisfies the request; minimises fragmentation.
/// - `FirstFit` — picks the first region that can satisfy the
///   request; fastest scan.
/// - `WorstFit` — picks the region with the most free space;
///   spreads allocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CmaAllocPolicy {
    /// Best-fit: smallest satisfying region.
    #[default]
    BestFit,
    /// First-fit: first satisfying region.
    FirstFit,
    /// Worst-fit: largest free region.
    WorstFit,
}

// -------------------------------------------------------------------
// CmaAllocFlags
// -------------------------------------------------------------------

/// Flags modifying allocation behaviour.
#[derive(Debug, Clone, Copy, Default)]
pub struct CmaAllocFlags {
    /// Allow the allocator to trigger page migration to create
    /// contiguous free space.
    pub allow_migration: bool,
    /// Zero-fill the allocated pages before returning.
    pub zero_fill: bool,
    /// The allocation is for DMA and must respect DMA address limits.
    pub dma: bool,
    /// Preferred NUMA node (0 = no preference).
    pub numa_node: u32,
}

// -------------------------------------------------------------------
// CmaAllocRequest
// -------------------------------------------------------------------

/// A typed contiguous-memory allocation request.
#[derive(Debug, Clone, Copy)]
pub struct CmaAllocRequest {
    /// Number of contiguous pages requested.
    pub count: usize,
    /// Required alignment in pages (must be a power of 2).
    pub align_pages: usize,
    /// Allocation policy.
    pub policy: CmaAllocPolicy,
    /// Behaviour flags.
    pub flags: CmaAllocFlags,
    /// Requester identifier (e.g. driver or subsystem id).
    pub requester_id: u64,
    /// Whether this request slot is active.
    pub active: bool,
}

impl CmaAllocRequest {
    /// Creates an empty, inactive request.
    const fn empty() -> Self {
        Self {
            count: 0,
            align_pages: 1,
            policy: CmaAllocPolicy::BestFit,
            flags: CmaAllocFlags {
                allow_migration: false,
                zero_fill: false,
                dma: false,
                numa_node: 0,
            },
            requester_id: 0,
            active: false,
        }
    }

    /// Creates a new allocation request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `count` is 0 or
    /// `align_pages` is not a power of 2.
    pub const fn new(
        count: usize,
        align_pages: usize,
        policy: CmaAllocPolicy,
        flags: CmaAllocFlags,
        requester_id: u64,
    ) -> Result<Self> {
        if count == 0 {
            return Err(Error::InvalidArgument);
        }
        if !align_pages.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            count,
            align_pages,
            policy,
            flags,
            requester_id,
            active: true,
        })
    }

    /// Required allocation size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.count as u64 * PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// CmaAllocResult
// -------------------------------------------------------------------

/// Result of a successful CMA allocation.
#[derive(Debug, Clone, Copy)]
pub struct CmaAllocResult {
    /// First page frame number of the allocation.
    pub pfn: u64,
    /// Number of contiguous pages allocated.
    pub count: usize,
    /// Physical address of the allocation start.
    pub phys_addr: u64,
    /// Region index the allocation came from.
    pub region_idx: usize,
    /// Whether migration was required to satisfy the request.
    pub migrated: bool,
}

// -------------------------------------------------------------------
// CmaManagedRegion
// -------------------------------------------------------------------

/// A CMA region managed by the allocation manager.
///
/// Extends the basic CMA region with NUMA information, a larger
/// bitmap (2048 pages), and usage tracking.
#[derive(Clone, Copy)]
pub struct CmaManagedRegion {
    /// First page frame number.
    base_pfn: u64,
    /// Number of pages in this region (at most [`MAX_REGION_PAGES`]).
    size_pages: usize,
    /// Allocation bitmap — one bit per page.
    bitmap: [u64; BITMAP_WORDS],
    /// NUMA node this region belongs to.
    numa_node: u32,
    /// Total successful allocations from this region.
    alloc_count: u64,
    /// Total frees back to this region.
    free_count: u64,
    /// Whether this region slot is active.
    active: bool,
}

impl CmaManagedRegion {
    /// Creates an empty, inactive region.
    const fn empty() -> Self {
        Self {
            base_pfn: 0,
            size_pages: 0,
            bitmap: [0u64; BITMAP_WORDS],
            numa_node: 0,
            alloc_count: 0,
            free_count: 0,
            active: false,
        }
    }

    /// Creates a new managed region.
    fn new(base_pfn: u64, size_pages: usize, numa_node: u32) -> Self {
        let capped = if size_pages > MAX_REGION_PAGES {
            MAX_REGION_PAGES
        } else {
            size_pages
        };
        Self {
            base_pfn,
            size_pages: capped,
            bitmap: [0u64; BITMAP_WORDS],
            numa_node,
            alloc_count: 0,
            free_count: 0,
            active: true,
        }
    }

    /// Returns the number of free pages.
    fn free_pages(&self) -> usize {
        let mut free = 0_usize;
        for i in 0..self.size_pages {
            let word = i / 64;
            let bit = i % 64;
            if self.bitmap[word] & (1u64 << bit) == 0 {
                free += 1;
            }
        }
        free
    }

    /// Returns the used page count.
    fn used_pages(&self) -> usize {
        self.size_pages - self.free_pages()
    }

    /// Returns the size of the largest contiguous free range.
    fn largest_free_range(&self) -> usize {
        let mut max_run = 0_usize;
        let mut current_run = 0_usize;
        for i in 0..self.size_pages {
            let word = i / 64;
            let bit = i % 64;
            if self.bitmap[word] & (1u64 << bit) == 0 {
                current_run += 1;
                if current_run > max_run {
                    max_run = current_run;
                }
            } else {
                current_run = 0;
            }
        }
        max_run
    }

    /// Finds a contiguous free range of `count` pages with the
    /// given alignment. Returns the offset within the region.
    fn find_free_range(&self, count: usize, align: usize) -> Option<usize> {
        let align = if align == 0 { 1 } else { align };
        let mut start = 0_usize;

        while start + count <= self.size_pages {
            let mut all_free = true;
            for i in start..start + count {
                let word = i / 64;
                let bit = i % 64;
                if self.bitmap[word] & (1u64 << bit) != 0 {
                    all_free = false;
                    break;
                }
            }
            if all_free {
                return Some(start);
            }
            start += align;
        }

        None
    }

    /// Marks a range of pages as allocated.
    fn mark_allocated(&mut self, offset: usize, count: usize) {
        for i in offset..offset + count {
            let word = i / 64;
            let bit = i % 64;
            self.bitmap[word] |= 1u64 << bit;
        }
    }

    /// Marks a range of pages as free.
    fn mark_free(&mut self, offset: usize, count: usize) {
        for i in offset..offset + count {
            let word = i / 64;
            let bit = i % 64;
            self.bitmap[word] &= !(1u64 << bit);
        }
    }

    /// Returns `true` if the given PFN falls within this region.
    fn contains_pfn(&self, pfn: u64, count: usize) -> bool {
        pfn >= self.base_pfn && pfn + count as u64 <= self.base_pfn + self.size_pages as u64
    }
}

// -------------------------------------------------------------------
// CmaMigrationEntry
// -------------------------------------------------------------------

/// A single page migration record.
///
/// Records the source and destination PFN of a page that was moved
/// to create contiguous free space.
#[derive(Debug, Clone, Copy)]
pub struct CmaMigrationEntry {
    /// Source PFN (where the page was).
    pub src_pfn: u64,
    /// Destination PFN (where the page was moved to).
    pub dst_pfn: u64,
    /// Whether the migration succeeded.
    pub success: bool,
}

impl CmaMigrationEntry {
    /// Creates an empty entry.
    const fn empty() -> Self {
        Self {
            src_pfn: 0,
            dst_pfn: 0,
            success: false,
        }
    }
}

// -------------------------------------------------------------------
// CmaMigrationEngine
// -------------------------------------------------------------------

/// Page migration engine for CMA defragmentation.
///
/// When a contiguous allocation fails because movable pages
/// fragment the region, the migration engine relocates those pages
/// out of the desired range so the CMA allocator can succeed.
pub struct CmaMigrationEngine {
    /// Migration log.
    entries: [CmaMigrationEntry; MAX_MIGRATION_ENTRIES],
    /// Number of entries recorded.
    entry_count: usize,
    /// Pages scanned in the current pass.
    pages_scanned: u64,
    /// Pages successfully migrated.
    pages_migrated: u64,
    /// Migration failures.
    migrate_failures: u64,
    /// Scan batch size (pages per step).
    scan_batch: usize,
}

impl Default for CmaMigrationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CmaMigrationEngine {
    /// Creates a new migration engine.
    pub const fn new() -> Self {
        Self {
            entries: [CmaMigrationEntry::empty(); MAX_MIGRATION_ENTRIES],
            entry_count: 0,
            pages_scanned: 0,
            pages_migrated: 0,
            migrate_failures: 0,
            scan_batch: DEFAULT_SCAN_BATCH,
        }
    }

    /// Attempts to free a contiguous range within `region` by
    /// migrating occupied pages out of `[offset, offset+count)`.
    ///
    /// Since actual page migration requires kernel page-table and
    /// LRU manipulation, this method simulates the process: it
    /// clears bitmap bits in the target range and records entries.
    ///
    /// Returns the number of pages migrated (i.e. freed).
    pub fn migrate_range(
        &mut self,
        region: &mut CmaManagedRegion,
        offset: usize,
        count: usize,
    ) -> usize {
        let mut migrated = 0_usize;

        for i in offset
            ..offset
                .min(region.size_pages)
                .max(offset)
                .min(offset + count)
        {
            if i >= region.size_pages {
                break;
            }
            let word = i / 64;
            let bit = i % 64;
            let occupied = region.bitmap[word] & (1u64 << bit) != 0;

            self.pages_scanned += 1;

            if occupied {
                // Simulate migration: clear bit and log entry.
                region.bitmap[word] &= !(1u64 << bit);
                if self.entry_count < MAX_MIGRATION_ENTRIES {
                    self.entries[self.entry_count] = CmaMigrationEntry {
                        src_pfn: region.base_pfn + i as u64,
                        dst_pfn: 0, // destination is outside CMA
                        success: true,
                    };
                    self.entry_count += 1;
                }
                migrated += 1;
                self.pages_migrated += 1;
            }
        }

        migrated
    }

    /// Resets the migration log for a new pass.
    pub fn reset(&mut self) {
        self.entry_count = 0;
    }

    /// Returns the number of logged migration entries.
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Returns total pages migrated since creation.
    pub const fn pages_migrated(&self) -> u64 {
        self.pages_migrated
    }

    /// Returns total pages scanned since creation.
    pub const fn pages_scanned(&self) -> u64 {
        self.pages_scanned
    }

    /// Returns the scan batch size.
    pub const fn scan_batch(&self) -> usize {
        self.scan_batch
    }

    /// Sets the scan batch size.
    pub fn set_scan_batch(&mut self, batch: usize) {
        if batch > 0 {
            self.scan_batch = batch;
        }
    }
}

// -------------------------------------------------------------------
// CmaAllocStats
// -------------------------------------------------------------------

/// Extended allocation statistics for the CMA manager.
#[derive(Debug, Clone, Copy, Default)]
pub struct CmaAllocStats {
    /// Total allocation attempts.
    pub alloc_attempts: u64,
    /// Successful allocations.
    pub alloc_success: u64,
    /// Failed allocations (no memory).
    pub alloc_failures: u64,
    /// Allocations that required migration.
    pub alloc_with_migration: u64,
    /// Total frees.
    pub free_count: u64,
    /// Total pages currently allocated.
    pub pages_allocated: u64,
    /// Total pages across all regions.
    pub total_pages: u64,
    /// Best-fit policy selections.
    pub best_fit_count: u64,
    /// First-fit policy selections.
    pub first_fit_count: u64,
    /// Worst-fit policy selections.
    pub worst_fit_count: u64,
}

// -------------------------------------------------------------------
// CmaAllocManager
// -------------------------------------------------------------------

/// Orchestrates CMA allocations with policy selection, fallback,
/// and optional page migration.
///
/// Maintains a set of managed regions and a pending request queue.
/// Allocation proceeds in three phases:
///
/// 1. **Direct allocation**: attempt to find a contiguous range
///    using the requested policy.
/// 2. **Migration fallback**: if direct fails and migration is
///    allowed, run the migration engine and retry.
/// 3. **Policy fallback**: if the requested policy fails, try
///    first-fit as a last resort.
pub struct CmaAllocManager {
    /// Managed CMA regions.
    regions: [CmaManagedRegion; MAX_MANAGED_REGIONS],
    /// Number of active regions.
    region_count: usize,
    /// Pending allocation requests.
    pending: [CmaAllocRequest; MAX_PENDING_REQUESTS],
    /// Number of pending requests.
    pending_count: usize,
    /// Migration engine.
    migration: CmaMigrationEngine,
    /// Statistics.
    stats: CmaAllocStats,
}

impl Default for CmaAllocManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CmaAllocManager {
    /// Creates a new CMA allocation manager.
    pub const fn new() -> Self {
        Self {
            regions: [const { CmaManagedRegion::empty() }; MAX_MANAGED_REGIONS],
            region_count: 0,
            pending: [CmaAllocRequest::empty(); MAX_PENDING_REQUESTS],
            pending_count: 0,
            migration: CmaMigrationEngine::new(),
            stats: CmaAllocStats {
                alloc_attempts: 0,
                alloc_success: 0,
                alloc_failures: 0,
                alloc_with_migration: 0,
                free_count: 0,
                pages_allocated: 0,
                total_pages: 0,
                best_fit_count: 0,
                first_fit_count: 0,
                worst_fit_count: 0,
            },
        }
    }

    /// Registers a CMA region with the manager.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all region slots are full.
    /// Returns [`Error::InvalidArgument`] if `size_pages` is 0.
    pub fn add_region(
        &mut self,
        base_pfn: u64,
        size_pages: usize,
        numa_node: u32,
    ) -> Result<usize> {
        if size_pages == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.region_count >= MAX_MANAGED_REGIONS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.region_count;
        self.regions[idx] = CmaManagedRegion::new(base_pfn, size_pages, numa_node);
        self.region_count += 1;
        self.stats.total_pages += self.regions[idx].size_pages as u64;
        Ok(idx)
    }

    /// Removes a region by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of
    /// range.
    /// Returns [`Error::Busy`] if the region has allocated pages.
    pub fn remove_region(&mut self, index: usize) -> Result<()> {
        if index >= self.region_count {
            return Err(Error::InvalidArgument);
        }
        if self.regions[index].used_pages() > 0 {
            return Err(Error::Busy);
        }
        self.stats.total_pages -= self.regions[index].size_pages as u64;
        // Swap-remove.
        self.region_count -= 1;
        if index < self.region_count {
            self.regions[index] = self.regions[self.region_count];
        }
        self.regions[self.region_count] = CmaManagedRegion::empty();
        Ok(())
    }

    /// Allocates contiguous pages according to the given request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no region can satisfy the
    /// request even after migration attempts.
    pub fn alloc(&mut self, request: &CmaAllocRequest) -> Result<CmaAllocResult> {
        self.stats.alloc_attempts += 1;

        match request.policy {
            CmaAllocPolicy::BestFit => self.stats.best_fit_count += 1,
            CmaAllocPolicy::FirstFit => self.stats.first_fit_count += 1,
            CmaAllocPolicy::WorstFit => self.stats.worst_fit_count += 1,
        }

        // Phase 1: direct allocation.
        if let Some(result) = self.try_alloc_direct(request) {
            self.stats.alloc_success += 1;
            self.stats.pages_allocated += request.count as u64;
            return Ok(result);
        }

        // Phase 2: migration fallback.
        if request.flags.allow_migration {
            if let Some(result) = self.try_alloc_with_migration(request) {
                self.stats.alloc_success += 1;
                self.stats.alloc_with_migration += 1;
                self.stats.pages_allocated += request.count as u64;
                return Ok(result);
            }
        }

        // Phase 3: policy fallback — try first-fit if we haven't
        // already.
        if request.policy != CmaAllocPolicy::FirstFit {
            let fallback = CmaAllocRequest {
                policy: CmaAllocPolicy::FirstFit,
                ..*request
            };
            if let Some(result) = self.try_alloc_direct(&fallback) {
                self.stats.alloc_success += 1;
                self.stats.pages_allocated += request.count as u64;
                return Ok(result);
            }
        }

        self.stats.alloc_failures += 1;
        Err(Error::OutOfMemory)
    }

    /// Frees a previous allocation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN does not belong to
    /// any managed region.
    /// Returns [`Error::InvalidArgument`] if the range is invalid.
    pub fn free(&mut self, pfn: u64, count: usize) -> Result<()> {
        let pos = (0..self.region_count)
            .find(|&i| self.regions[i].active && self.regions[i].contains_pfn(pfn, count))
            .ok_or(Error::NotFound)?;

        let offset = (pfn - self.regions[pos].base_pfn) as usize;

        // Verify all pages are allocated.
        for i in offset..offset + count {
            let word = i / 64;
            let bit = i % 64;
            if self.regions[pos].bitmap[word] & (1u64 << bit) == 0 {
                return Err(Error::InvalidArgument);
            }
        }

        self.regions[pos].mark_free(offset, count);
        self.regions[pos].free_count += 1;
        self.stats.free_count += 1;
        self.stats.pages_allocated = self.stats.pages_allocated.saturating_sub(count as u64);
        Ok(())
    }

    /// Enqueues a pending allocation request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the queue is full.
    pub fn enqueue_request(&mut self, request: CmaAllocRequest) -> Result<usize> {
        if self.pending_count >= MAX_PENDING_REQUESTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.pending_count;
        self.pending[idx] = request;
        self.pending_count += 1;
        Ok(idx)
    }

    /// Processes and drains the pending request queue.
    ///
    /// Attempts each pending request in order. Successfully
    /// allocated requests are deactivated. Returns the number
    /// of requests satisfied.
    pub fn drain_pending(&mut self, results_out: &mut [CmaAllocResult]) -> usize {
        let mut fulfilled = 0_usize;

        for i in 0..self.pending_count {
            if !self.pending[i].active {
                continue;
            }
            let req = self.pending[i];
            if let Ok(result) = self.alloc(&req) {
                self.pending[i].active = false;
                if fulfilled < results_out.len() {
                    results_out[fulfilled] = result;
                    fulfilled += 1;
                }
            }
        }

        // Compact the pending array.
        let mut write = 0_usize;
        for read in 0..self.pending_count {
            if self.pending[read].active {
                if write != read {
                    self.pending[write] = self.pending[read];
                }
                write += 1;
            }
        }
        self.pending_count = write;

        fulfilled
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> CmaAllocStats {
        CmaAllocStats {
            total_pages: self.regions[..self.region_count]
                .iter()
                .filter(|r| r.active)
                .map(|r| r.size_pages as u64)
                .sum(),
            ..self.stats
        }
    }

    /// Returns the number of managed regions.
    pub const fn region_count(&self) -> usize {
        self.region_count
    }

    /// Returns the number of pending requests.
    pub const fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Returns the free page count for a given region.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn region_free_pages(&self, index: usize) -> Result<usize> {
        if index >= self.region_count {
            return Err(Error::InvalidArgument);
        }
        Ok(self.regions[index].free_pages())
    }

    /// Returns the largest contiguous free range for a region.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn region_largest_free(&self, index: usize) -> Result<usize> {
        if index >= self.region_count {
            return Err(Error::InvalidArgument);
        }
        Ok(self.regions[index].largest_free_range())
    }

    /// Returns a reference to the migration engine.
    pub const fn migration_engine(&self) -> &CmaMigrationEngine {
        &self.migration
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Attempts direct allocation without migration.
    fn try_alloc_direct(&mut self, request: &CmaAllocRequest) -> Option<CmaAllocResult> {
        let idx = self.select_region(request)?;
        let region = &self.regions[idx];
        let offset = region.find_free_range(request.count, request.align_pages)?;

        self.regions[idx].mark_allocated(offset, request.count);
        self.regions[idx].alloc_count += 1;

        Some(CmaAllocResult {
            pfn: self.regions[idx].base_pfn + offset as u64,
            count: request.count,
            phys_addr: (self.regions[idx].base_pfn + offset as u64) * PAGE_SIZE,
            region_idx: idx,
            migrated: false,
        })
    }

    /// Attempts allocation after migrating pages out of the way.
    fn try_alloc_with_migration(&mut self, request: &CmaAllocRequest) -> Option<CmaAllocResult> {
        self.migration.reset();

        for idx in 0..self.region_count {
            if !self.regions[idx].active {
                continue;
            }
            // Try to find an aligned offset, then migrate.
            let align = request.align_pages;
            let mut start = 0_usize;
            while start + request.count <= self.regions[idx].size_pages {
                self.migration
                    .migrate_range(&mut self.regions[idx], start, request.count);

                if let Some(offset) = self.regions[idx].find_free_range(request.count, align) {
                    self.regions[idx].mark_allocated(offset, request.count);
                    self.regions[idx].alloc_count += 1;

                    return Some(CmaAllocResult {
                        pfn: self.regions[idx].base_pfn + offset as u64,
                        count: request.count,
                        phys_addr: (self.regions[idx].base_pfn + offset as u64) * PAGE_SIZE,
                        region_idx: idx,
                        migrated: true,
                    });
                }

                start += align;
            }
        }

        None
    }

    /// Selects a region index based on the allocation policy.
    fn select_region(&self, request: &CmaAllocRequest) -> Option<usize> {
        match request.policy {
            CmaAllocPolicy::BestFit => self.select_best_fit(request),
            CmaAllocPolicy::FirstFit => self.select_first_fit(request),
            CmaAllocPolicy::WorstFit => self.select_worst_fit(request),
        }
    }

    /// Best-fit: smallest satisfying region.
    fn select_best_fit(&self, request: &CmaAllocRequest) -> Option<usize> {
        let mut best_idx: Option<usize> = None;
        let mut best_free = usize::MAX;

        for i in 0..self.region_count {
            let r = &self.regions[i];
            if !r.active {
                continue;
            }
            if request.flags.numa_node != 0 && r.numa_node != request.flags.numa_node {
                continue;
            }
            let free = r.free_pages();
            if free >= request.count
                && free < best_free
                && r.find_free_range(request.count, request.align_pages)
                    .is_some()
            {
                best_free = free;
                best_idx = Some(i);
            }
        }

        best_idx
    }

    /// First-fit: first satisfying region.
    fn select_first_fit(&self, request: &CmaAllocRequest) -> Option<usize> {
        for i in 0..self.region_count {
            let r = &self.regions[i];
            if !r.active {
                continue;
            }
            if request.flags.numa_node != 0 && r.numa_node != request.flags.numa_node {
                continue;
            }
            if r.free_pages() >= request.count
                && r.find_free_range(request.count, request.align_pages)
                    .is_some()
            {
                return Some(i);
            }
        }
        None
    }

    /// Worst-fit: largest free region.
    fn select_worst_fit(&self, request: &CmaAllocRequest) -> Option<usize> {
        let mut worst_idx: Option<usize> = None;
        let mut worst_free = 0_usize;

        for i in 0..self.region_count {
            let r = &self.regions[i];
            if !r.active {
                continue;
            }
            if request.flags.numa_node != 0 && r.numa_node != request.flags.numa_node {
                continue;
            }
            let free = r.free_pages();
            if free >= request.count
                && free > worst_free
                && r.find_free_range(request.count, request.align_pages)
                    .is_some()
            {
                worst_free = free;
                worst_idx = Some(i);
            }
        }

        worst_idx
    }
}
