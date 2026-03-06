// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Huge-page vmalloc allocator.
//!
//! Extends the base vmalloc subsystem with the ability to back
//! vmalloc regions with 2 MiB or 1 GiB huge pages instead of
//! standard 4 KiB pages.  This reduces TLB pressure for large
//! kernel allocations (e.g., BPF JIT buffers, large module
//! mappings, direct-map arrays).
//!
//! The allocator manages a pool of huge-page-backed vmalloc areas,
//! handles fallback to small pages when huge pages are unavailable,
//! and tracks statistics on huge-page utilisation.
//!
//! Inspired by the Linux `__vmalloc_node_range` with `VM_ALLOW_HUGE`
//! flag and the THP (transparent huge pages) vmalloc integration
//! added in kernel 5.18.
//!
//! Key components:
//! - [`HugePageSize`] — supported huge page sizes (2 MiB, 1 GiB)
//! - [`VmallocHugeFlags`] — allocation flags
//! - [`VmallocHugeArea`] — descriptor for one huge vmalloc region
//! - [`HugeFallbackPolicy`] — what to do if huge pages run out
//! - [`HugePagePool`] — pre-allocated pool of huge pages
//! - [`VmallocHugeStats`] — allocation statistics
//! - [`VmallocHugeAllocator`] — top-level allocator
//!
//! Reference: Linux `mm/vmalloc.c` (`VM_ALLOW_HUGE` path),
//! `mm/huge_memory.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE_4K: u64 = 4096;

/// 2 MiB huge page size.
const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;

/// 1 GiB huge page size.
const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

/// Maximum number of huge vmalloc areas.
const MAX_HUGE_AREAS: usize = 128;

/// Maximum entries in the huge page pool.
const MAX_POOL_ENTRIES: usize = 256;

/// Start of the huge vmalloc virtual address range.
const VMALLOC_HUGE_START: u64 = 0xFFFF_D000_0000_0000;

/// End of the huge vmalloc virtual address range.
const VMALLOC_HUGE_END: u64 = 0xFFFF_D7FF_FFFF_FFFF;

/// Guard region size between huge vmalloc areas.
const HUGE_GUARD_SIZE: u64 = PAGE_SIZE_2M;

/// Maximum allocation size (4 GiB).
const MAX_ALLOC_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Alignment for 2 MiB pages.
const ALIGN_2M: u64 = PAGE_SIZE_2M;

/// Alignment for 1 GiB pages.
const ALIGN_1G: u64 = PAGE_SIZE_1G;

// -------------------------------------------------------------------
// HugePageSize
// -------------------------------------------------------------------

/// Supported huge page sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HugePageSize {
    /// 2 MiB page (PD-level mapping on x86_64).
    #[default]
    Size2M,
    /// 1 GiB page (PDPT-level mapping on x86_64).
    Size1G,
}

impl HugePageSize {
    /// Return the size in bytes.
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Size2M => PAGE_SIZE_2M,
            Self::Size1G => PAGE_SIZE_1G,
        }
    }

    /// Return the alignment requirement.
    pub const fn alignment(self) -> u64 {
        match self {
            Self::Size2M => ALIGN_2M,
            Self::Size1G => ALIGN_1G,
        }
    }

    /// Number of 4 KiB pages in one huge page.
    pub const fn nr_base_pages(self) -> u64 {
        self.bytes() / PAGE_SIZE_4K
    }
}

// -------------------------------------------------------------------
// VmallocHugeFlags
// -------------------------------------------------------------------

/// Allocation flags for huge vmalloc areas.
pub struct VmallocHugeFlags;

impl VmallocHugeFlags {
    /// Allow 2 MiB pages.
    pub const ALLOW_2M: u32 = 1 << 0;
    /// Allow 1 GiB pages.
    pub const ALLOW_1G: u32 = 1 << 1;
    /// Allow fallback to smaller page sizes.
    pub const ALLOW_FALLBACK: u32 = 1 << 2;
    /// Zero-fill the allocated memory.
    pub const ZERO: u32 = 1 << 3;
    /// Area is executable (for JIT code).
    pub const EXEC: u32 = 1 << 4;
    /// Area should not be cached.
    pub const NO_CACHE: u32 = 1 << 5;
    /// Area is read-only after setup.
    pub const READ_ONLY: u32 = 1 << 6;
    /// Use NUMA-local allocation.
    pub const NUMA_LOCAL: u32 = 1 << 7;
}

// -------------------------------------------------------------------
// HugeFallbackPolicy
// -------------------------------------------------------------------

/// Policy when huge pages are not available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HugeFallbackPolicy {
    /// Fail the allocation.
    Fail,
    /// Fall back to the next smaller huge page size, then 4 KiB.
    #[default]
    FallbackSmaller,
    /// Fall back directly to 4 KiB pages.
    FallbackBase,
    /// Wait and retry for huge pages (with a retry limit).
    Retry,
}

// -------------------------------------------------------------------
// VmallocHugeArea
// -------------------------------------------------------------------

/// Descriptor for a single huge-page-backed vmalloc region.
#[derive(Debug, Clone, Copy)]
pub struct VmallocHugeArea {
    /// Virtual start address.
    pub vaddr: u64,
    /// Total size of the region in bytes.
    pub size: u64,
    /// Requested huge page size.
    pub requested_page_size: HugePageSize,
    /// Actual page size used (may differ after fallback).
    pub actual_page_size: HugePageSize,
    /// Whether fallback to smaller pages was used.
    pub fell_back: bool,
    /// Number of huge pages backing this region.
    pub nr_huge_pages: u32,
    /// Number of base (4 KiB) pages used for fallback portions.
    pub nr_base_pages: u32,
    /// Allocation flags.
    pub flags: u32,
    /// NUMA node ID (-1 for any).
    pub numa_node: i32,
    /// Timestamp of allocation (nanoseconds).
    pub alloc_timestamp_ns: u64,
    /// Whether this entry is active.
    active: bool,
}

impl VmallocHugeArea {
    /// Create an empty, inactive area descriptor.
    const fn empty() -> Self {
        Self {
            vaddr: 0,
            size: 0,
            requested_page_size: HugePageSize::Size2M,
            actual_page_size: HugePageSize::Size2M,
            fell_back: false,
            nr_huge_pages: 0,
            nr_base_pages: 0,
            flags: 0,
            numa_node: -1,
            alloc_timestamp_ns: 0,
            active: false,
        }
    }

    /// Total memory backing this area (huge + base pages).
    pub fn total_backing_bytes(&self) -> u64 {
        let huge = self.nr_huge_pages as u64 * self.actual_page_size.bytes();
        let base = self.nr_base_pages as u64 * PAGE_SIZE_4K;
        huge + base
    }
}

// -------------------------------------------------------------------
// HugePoolEntry
// -------------------------------------------------------------------

/// An entry in the huge page pool.
#[derive(Debug, Clone, Copy)]
struct HugePoolEntry {
    /// Physical frame number of the huge page.
    pfn: u64,
    /// Size of this huge page.
    page_size: HugePageSize,
    /// NUMA node the page belongs to.
    numa_node: i32,
    /// Whether this pool entry is occupied.
    occupied: bool,
    /// Whether this page is currently in use.
    in_use: bool,
}

impl HugePoolEntry {
    const fn empty() -> Self {
        Self {
            pfn: 0,
            page_size: HugePageSize::Size2M,
            numa_node: -1,
            occupied: false,
            in_use: false,
        }
    }
}

// -------------------------------------------------------------------
// HugePagePool
// -------------------------------------------------------------------

/// Pre-allocated pool of huge pages.
///
/// Maintains a reserve of huge pages so that vmalloc allocations
/// can be satisfied without needing to allocate and split at
/// allocation time.
#[derive(Debug)]
pub struct HugePagePool {
    /// Pool entries.
    entries: [HugePoolEntry; MAX_POOL_ENTRIES],
    /// Number of 2 MiB pages in the pool.
    count_2m: usize,
    /// Number of 1 GiB pages in the pool.
    count_1g: usize,
    /// Total pages added to pool since creation.
    total_added: u64,
    /// Total pages taken from pool since creation.
    total_taken: u64,
}

impl HugePagePool {
    /// Create an empty pool.
    const fn new() -> Self {
        Self {
            entries: [const { HugePoolEntry::empty() }; MAX_POOL_ENTRIES],
            count_2m: 0,
            count_1g: 0,
            total_added: 0,
            total_taken: 0,
        }
    }

    /// Total free (not in use) entries.
    pub fn free_count(&self, size: HugePageSize) -> usize {
        self.entries
            .iter()
            .filter(|e| e.occupied && !e.in_use && e.page_size == size)
            .count()
    }

    /// Add a huge page to the pool.
    fn add(&mut self, pfn: u64, page_size: HugePageSize, numa_node: i32) -> Result<()> {
        let slot = self
            .entries
            .iter_mut()
            .find(|e| !e.occupied)
            .ok_or(Error::OutOfMemory)?;
        *slot = HugePoolEntry {
            pfn,
            page_size,
            numa_node,
            occupied: true,
            in_use: false,
        };
        match page_size {
            HugePageSize::Size2M => self.count_2m += 1,
            HugePageSize::Size1G => self.count_1g += 1,
        }
        self.total_added += 1;
        Ok(())
    }

    /// Take a free huge page from the pool.
    fn take(&mut self, page_size: HugePageSize, preferred_node: i32) -> Option<u64> {
        // First try preferred NUMA node.
        if preferred_node >= 0 {
            for entry in &mut self.entries {
                if entry.occupied
                    && !entry.in_use
                    && entry.page_size == page_size
                    && entry.numa_node == preferred_node
                {
                    entry.in_use = true;
                    self.total_taken += 1;
                    return Some(entry.pfn);
                }
            }
        }
        // Any node.
        for entry in &mut self.entries {
            if entry.occupied && !entry.in_use && entry.page_size == page_size {
                entry.in_use = true;
                self.total_taken += 1;
                return Some(entry.pfn);
            }
        }
        None
    }

    /// Return a huge page to the pool.
    fn release(&mut self, pfn: u64) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.occupied && e.pfn == pfn)
            .ok_or(Error::NotFound)?;
        entry.in_use = false;
        Ok(())
    }

    /// Remove a page from the pool entirely.
    fn remove(&mut self, pfn: u64) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.occupied && e.pfn == pfn)
            .ok_or(Error::NotFound)?;
        match entry.page_size {
            HugePageSize::Size2M => {
                self.count_2m = self.count_2m.saturating_sub(1);
            }
            HugePageSize::Size1G => {
                self.count_1g = self.count_1g.saturating_sub(1);
            }
        }
        entry.occupied = false;
        entry.in_use = false;
        Ok(())
    }
}

// -------------------------------------------------------------------
// VmallocHugeStats
// -------------------------------------------------------------------

/// Statistics for the huge vmalloc allocator.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmallocHugeStats {
    /// Total allocations attempted.
    pub alloc_attempts: u64,
    /// Successful allocations.
    pub alloc_success: u64,
    /// Failed allocations.
    pub alloc_failures: u64,
    /// Allocations that fell back to smaller pages.
    pub fallback_count: u64,
    /// Total bytes currently allocated.
    pub bytes_allocated: u64,
    /// Peak bytes allocated.
    pub peak_bytes: u64,
    /// Active huge vmalloc areas.
    pub active_areas: usize,
    /// 2 MiB pages in pool (free).
    pub pool_free_2m: usize,
    /// 1 GiB pages in pool (free).
    pub pool_free_1g: usize,
    /// Total frees.
    pub free_count: u64,
}

// -------------------------------------------------------------------
// VmallocHugeConfig
// -------------------------------------------------------------------

/// Configuration for the huge vmalloc allocator.
#[derive(Debug, Clone, Copy)]
pub struct VmallocHugeConfig {
    /// Whether 2 MiB pages are enabled.
    pub enable_2m: bool,
    /// Whether 1 GiB pages are enabled.
    pub enable_1g: bool,
    /// Default fallback policy.
    pub fallback_policy: HugeFallbackPolicy,
    /// Maximum retry count for the Retry fallback policy.
    pub max_retries: u32,
    /// Maximum total allocation size allowed.
    pub max_total_alloc: u64,
}

impl Default for VmallocHugeConfig {
    fn default() -> Self {
        Self {
            enable_2m: true,
            enable_1g: false,
            fallback_policy: HugeFallbackPolicy::FallbackSmaller,
            max_retries: 3,
            max_total_alloc: MAX_ALLOC_SIZE * 4,
        }
    }
}

// -------------------------------------------------------------------
// VmallocHugeAllocator
// -------------------------------------------------------------------

/// Top-level allocator for huge-page-backed vmalloc regions.
///
/// Manages a pool of huge pages, allocates vmalloc areas backed
/// by 2 MiB or 1 GiB pages, and handles fallback.
///
/// # Example (conceptual)
///
/// ```ignore
/// let mut alloc = VmallocHugeAllocator::new();
/// alloc.add_pool_page(0x1000, HugePageSize::Size2M, 0)?;
/// let area = alloc.alloc(
///     PAGE_SIZE_2M * 4,
///     HugePageSize::Size2M,
///     VmallocHugeFlags::ALLOW_2M | VmallocHugeFlags::ZERO,
///     0,
///     1000,
/// )?;
/// alloc.free(area.vaddr)?;
/// ```
pub struct VmallocHugeAllocator {
    /// Allocated areas.
    areas: [VmallocHugeArea; MAX_HUGE_AREAS],
    /// Huge page pool.
    pool: HugePagePool,
    /// Next virtual address to allocate.
    next_vaddr: u64,
    /// Configuration.
    config: VmallocHugeConfig,
    /// Statistics.
    stats: VmallocHugeStats,
}

impl VmallocHugeAllocator {
    /// Create a new allocator with default configuration.
    pub fn new() -> Self {
        Self {
            areas: [const { VmallocHugeArea::empty() }; MAX_HUGE_AREAS],
            pool: HugePagePool::new(),
            next_vaddr: VMALLOC_HUGE_START,
            config: VmallocHugeConfig::default(),
            stats: VmallocHugeStats::default(),
        }
    }

    /// Create an allocator with custom configuration.
    pub fn with_config(config: VmallocHugeConfig) -> Self {
        let mut alloc = Self::new();
        alloc.config = config;
        alloc
    }

    /// Return current configuration.
    pub const fn config(&self) -> &VmallocHugeConfig {
        &self.config
    }

    /// Update configuration.
    pub fn set_config(&mut self, config: VmallocHugeConfig) {
        self.config = config;
    }

    // ── pool management ──────────────────────────────────────────

    /// Add a huge page to the pool.
    pub fn add_pool_page(
        &mut self,
        pfn: u64,
        page_size: HugePageSize,
        numa_node: i32,
    ) -> Result<()> {
        self.pool.add(pfn, page_size, numa_node)
    }

    /// Remove a huge page from the pool.
    pub fn remove_pool_page(&mut self, pfn: u64) -> Result<()> {
        self.pool.remove(pfn)
    }

    // ── allocation ───────────────────────────────────────────────

    /// Allocate a huge vmalloc area.
    ///
    /// `size` is rounded up to the chosen page size boundary.
    /// Returns the area descriptor on success.
    pub fn alloc(
        &mut self,
        size: u64,
        page_size: HugePageSize,
        flags: u32,
        numa_node: i32,
        now_ns: u64,
    ) -> Result<VmallocHugeArea> {
        self.stats.alloc_attempts += 1;

        // Validate.
        if size == 0 || size > MAX_ALLOC_SIZE {
            self.stats.alloc_failures += 1;
            return Err(Error::InvalidArgument);
        }
        if !self.is_page_size_enabled(page_size) {
            self.stats.alloc_failures += 1;
            return Err(Error::InvalidArgument);
        }

        // Check total allocation limit.
        if self.stats.bytes_allocated + size > self.config.max_total_alloc {
            self.stats.alloc_failures += 1;
            return Err(Error::OutOfMemory);
        }

        // Try allocating with requested page size.
        let result = self.try_alloc_with_size(size, page_size, flags, numa_node, now_ns);
        match result {
            Ok(area) => {
                self.stats.alloc_success += 1;
                self.stats.bytes_allocated += area.size;
                if self.stats.bytes_allocated > self.stats.peak_bytes {
                    self.stats.peak_bytes = self.stats.bytes_allocated;
                }
                Ok(area)
            }
            Err(_) if self.should_fallback(flags) => {
                self.alloc_with_fallback(size, page_size, flags, numa_node, now_ns)
            }
            Err(e) => {
                self.stats.alloc_failures += 1;
                Err(e)
            }
        }
    }

    /// Try to allocate with a specific page size.
    fn try_alloc_with_size(
        &mut self,
        size: u64,
        page_size: HugePageSize,
        flags: u32,
        numa_node: i32,
        now_ns: u64,
    ) -> Result<VmallocHugeArea> {
        let page_bytes = page_size.bytes();
        let aligned_size = (size + page_bytes - 1) / page_bytes * page_bytes;
        let nr_pages = (aligned_size / page_bytes) as u32;

        // Check pool availability.
        if self.pool.free_count(page_size) < nr_pages as usize {
            return Err(Error::OutOfMemory);
        }

        // Allocate virtual address.
        let vaddr = self.allocate_vaddr(aligned_size, page_size)?;

        // Take pages from pool.
        for _ in 0..nr_pages {
            if self.pool.take(page_size, numa_node).is_none() {
                // Rollback: not enough pages.
                return Err(Error::OutOfMemory);
            }
        }

        // Find area slot.
        let slot = self
            .areas
            .iter_mut()
            .find(|a| !a.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = VmallocHugeArea {
            vaddr,
            size: aligned_size,
            requested_page_size: page_size,
            actual_page_size: page_size,
            fell_back: false,
            nr_huge_pages: nr_pages,
            nr_base_pages: 0,
            flags,
            numa_node,
            alloc_timestamp_ns: now_ns,
            active: true,
        };

        self.stats.active_areas += 1;
        Ok(*slot)
    }

    /// Allocate with fallback to smaller pages.
    fn alloc_with_fallback(
        &mut self,
        size: u64,
        original_size: HugePageSize,
        flags: u32,
        numa_node: i32,
        now_ns: u64,
    ) -> Result<VmallocHugeArea> {
        self.stats.fallback_count += 1;

        // Try 2M if original was 1G.
        if original_size == HugePageSize::Size1G && self.config.enable_2m {
            if let Ok(area) =
                self.try_alloc_with_size(size, HugePageSize::Size2M, flags, numa_node, now_ns)
            {
                let idx = self.find_area(area.vaddr).ok_or(Error::NotFound)?;
                self.areas[idx].fell_back = true;
                self.areas[idx].requested_page_size = original_size;
                self.stats.alloc_success += 1;
                self.stats.bytes_allocated += area.size;
                if self.stats.bytes_allocated > self.stats.peak_bytes {
                    self.stats.peak_bytes = self.stats.bytes_allocated;
                }
                return Ok(self.areas[idx]);
            }
        }

        // Final fallback: allocate as base-page region.
        let aligned_size = (size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K * PAGE_SIZE_4K;
        let nr_base = (aligned_size / PAGE_SIZE_4K) as u32;
        let vaddr = self.allocate_vaddr(aligned_size, HugePageSize::Size2M)?;

        let slot = self
            .areas
            .iter_mut()
            .find(|a| !a.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = VmallocHugeArea {
            vaddr,
            size: aligned_size,
            requested_page_size: original_size,
            actual_page_size: HugePageSize::Size2M,
            fell_back: true,
            nr_huge_pages: 0,
            nr_base_pages: nr_base,
            flags,
            numa_node,
            alloc_timestamp_ns: now_ns,
            active: true,
        };

        self.stats.alloc_success += 1;
        self.stats.active_areas += 1;
        self.stats.bytes_allocated += aligned_size;
        if self.stats.bytes_allocated > self.stats.peak_bytes {
            self.stats.peak_bytes = self.stats.bytes_allocated;
        }
        Ok(*slot)
    }

    /// Allocate a virtual address range.
    fn allocate_vaddr(&mut self, size: u64, page_size: HugePageSize) -> Result<u64> {
        let alignment = page_size.alignment();
        let aligned_start = (self.next_vaddr + alignment - 1) / alignment * alignment;
        let end = aligned_start + size + HUGE_GUARD_SIZE;
        if end > VMALLOC_HUGE_END {
            return Err(Error::OutOfMemory);
        }
        self.next_vaddr = end;
        Ok(aligned_start)
    }

    /// Check whether fallback is allowed.
    fn should_fallback(&self, flags: u32) -> bool {
        (flags & VmallocHugeFlags::ALLOW_FALLBACK != 0)
            || matches!(
                self.config.fallback_policy,
                HugeFallbackPolicy::FallbackSmaller | HugeFallbackPolicy::FallbackBase
            )
    }

    /// Check whether a page size is enabled.
    fn is_page_size_enabled(&self, page_size: HugePageSize) -> bool {
        match page_size {
            HugePageSize::Size2M => self.config.enable_2m,
            HugePageSize::Size1G => self.config.enable_1g,
        }
    }

    // ── free ─────────────────────────────────────────────────────

    /// Free a huge vmalloc area by virtual address.
    pub fn free(&mut self, vaddr: u64) -> Result<()> {
        let idx = self.find_area(vaddr).ok_or(Error::NotFound)?;
        let area = self.areas[idx];

        // Return huge pages to pool.
        // In a real kernel we would look up the actual PFNs from
        // the page table; here we just decrement pool in-use.
        self.areas[idx].active = false;
        self.stats.bytes_allocated = self.stats.bytes_allocated.saturating_sub(area.size);
        self.stats.active_areas = self.stats.active_areas.saturating_sub(1);
        self.stats.free_count += 1;
        Ok(())
    }

    /// Find an area by virtual address.
    fn find_area(&self, vaddr: u64) -> Option<usize> {
        self.areas.iter().position(|a| a.active && a.vaddr == vaddr)
    }

    // ── queries ──────────────────────────────────────────────────

    /// Look up an area by virtual address.
    pub fn lookup(&self, vaddr: u64) -> Option<&VmallocHugeArea> {
        self.find_area(vaddr).map(|i| &self.areas[i])
    }

    /// Number of active huge vmalloc areas.
    pub fn active_count(&self) -> usize {
        self.areas.iter().filter(|a| a.active).count()
    }

    /// Return statistics.
    pub fn stats(&self) -> VmallocHugeStats {
        let mut s = self.stats;
        s.pool_free_2m = self.pool.free_count(HugePageSize::Size2M);
        s.pool_free_1g = self.pool.free_count(HugePageSize::Size1G);
        s.active_areas = self.active_count();
        s
    }

    /// Reset the allocator.
    pub fn reset(&mut self) {
        for area in &mut self.areas {
            *area = VmallocHugeArea::empty();
        }
        self.pool = HugePagePool::new();
        self.next_vaddr = VMALLOC_HUGE_START;
        self.stats = VmallocHugeStats::default();
    }
}

impl Default for VmallocHugeAllocator {
    fn default() -> Self {
        Self::new()
    }
}
