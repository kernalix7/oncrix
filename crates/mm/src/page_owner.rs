// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page ownership tracking for the ONCRIX kernel.
//!
//! Records which code path allocated and freed each physical page
//! frame, enabling post-mortem analysis of memory usage patterns
//! and leak diagnosis.
//!
//! Inspired by the Linux `mm/page_owner.c` subsystem.
//!
//! # Design
//!
//! A per-page [`PageOwnerInfo`] structure stores the allocation
//! order, GFP flags, migration type, allocation/free identifiers,
//! and a simplified 4-deep call chain (stored as function addresses).
//!
//! - [`PageOwnerInfo`] — per-page ownership metadata
//! - [`OwnerTable`] — flat array of per-page records
//! - [`OwnerStats`] — aggregated allocation-site statistics
//! - [`PageOwnerTracker`] — top-level tracker combining table and
//!   statistics

use oncrix_lib::Result;

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of pages tracked by the owner table.
const MAX_PAGES: usize = 32768;

/// Depth of the simplified call chain.
const STACK_DEPTH: usize = 4;

/// Maximum number of aggregated allocation-site statistics.
const MAX_STATS_ENTRIES: usize = 256;

// -------------------------------------------------------------------
// GfpFlags
// -------------------------------------------------------------------

/// Simplified GFP (Get Free Pages) allocation flags.
///
/// Modeled after the Linux `GFP_*` flags used to specify allocation
/// constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GfpFlags(pub u32);

impl GfpFlags {
    /// Normal kernel allocation.
    pub const GFP_KERNEL: Self = Self(0x01);
    /// Atomic context (cannot sleep).
    pub const GFP_ATOMIC: Self = Self(0x02);
    /// User-space allocation.
    pub const GFP_USER: Self = Self(0x04);
    /// High memory zone.
    pub const GFP_HIGHMEM: Self = Self(0x08);
    /// DMA-capable zone.
    pub const GFP_DMA: Self = Self(0x10);
    /// Zero-fill the page.
    pub const GFP_ZERO: Self = Self(0x20);

    /// Returns the raw flag bits.
    pub fn bits(self) -> u32 {
        self.0
    }
}

// -------------------------------------------------------------------
// MigrationType
// -------------------------------------------------------------------

/// Page migration type, used for grouping pages by mobility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrationType {
    /// Page cannot be migrated.
    #[default]
    Unmovable,
    /// Page can be migrated to another physical location.
    Movable,
    /// Page can be reclaimed (e.g., page cache).
    Reclaimable,
    /// Page is reserved by the kernel.
    Reserved,
}

// -------------------------------------------------------------------
// PageOwnerInfo
// -------------------------------------------------------------------

/// Ownership metadata for a single page frame.
#[derive(Debug, Clone, Copy)]
pub struct PageOwnerInfo {
    /// Allocation order (0 = single page, 1 = 2 pages, etc.).
    pub order: u8,
    /// GFP flags used for the allocation.
    pub gfp_flags: GfpFlags,
    /// Migration type of the page.
    pub migration_type: MigrationType,
    /// Allocation sequence number.
    pub alloc_id: u64,
    /// Free sequence number (0 if still allocated).
    pub free_id: u64,
    /// Simplified call chain at allocation time (function addresses).
    pub alloc_stack: [u64; STACK_DEPTH],
    /// Simplified call chain at free time (function addresses).
    pub free_stack: [u64; STACK_DEPTH],
    /// Whether this page is currently allocated.
    pub allocated: bool,
}

impl Default for PageOwnerInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl PageOwnerInfo {
    /// Creates an empty (unallocated) page owner record.
    pub const fn new() -> Self {
        Self {
            order: 0,
            gfp_flags: GfpFlags(0),
            migration_type: MigrationType::Unmovable,
            alloc_id: 0,
            free_id: 0,
            alloc_stack: [0; STACK_DEPTH],
            free_stack: [0; STACK_DEPTH],
            allocated: false,
        }
    }
}

// -------------------------------------------------------------------
// OwnerStats
// -------------------------------------------------------------------

/// Aggregated statistics for a single allocation site.
#[derive(Debug, Clone, Copy, Default)]
pub struct OwnerStats {
    /// Top-of-stack address identifying the allocation site.
    pub alloc_site: u64,
    /// Total number of pages allocated from this site.
    pub page_count: u64,
    /// Total number of allocations from this site.
    pub alloc_count: u64,
}

// -------------------------------------------------------------------
// OwnerTable
// -------------------------------------------------------------------

/// Per-page ownership tracking array.
///
/// Each entry corresponds to a physical page frame identified by
/// its Page Frame Number (PFN). The PFN is used as a direct index
/// into the table.
pub struct OwnerTable {
    /// Flat array indexed by PFN.
    pages: [PageOwnerInfo; MAX_PAGES],
    /// Whether tracking is currently active.
    active: bool,
    /// Monotonically increasing allocation sequence counter.
    next_alloc_id: u64,
    /// Monotonically increasing free sequence counter.
    next_free_id: u64,
}

impl Default for OwnerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl OwnerTable {
    /// Creates a new, inactive owner table.
    pub const fn new() -> Self {
        Self {
            pages: [PageOwnerInfo::new(); MAX_PAGES],
            active: false,
            next_alloc_id: 1,
            next_free_id: 1,
        }
    }

    /// Returns `true` if the given PFN is within bounds.
    fn valid_pfn(&self, pfn: usize) -> bool {
        pfn < MAX_PAGES
    }

    /// Record an allocation for the given PFN.
    ///
    /// `order` is the allocation order (0 for a single page).
    /// `gfp_flags` are the allocation constraints.
    /// `stack` is the caller-provided call chain (up to
    /// [`STACK_DEPTH`] entries).
    pub fn record_alloc(
        &mut self,
        pfn: usize,
        order: u8,
        gfp_flags: GfpFlags,
        migration_type: MigrationType,
        stack: &[u64],
    ) -> Result<()> {
        if !self.active {
            return Err(oncrix_lib::Error::NotImplemented);
        }
        if !self.valid_pfn(pfn) {
            return Err(oncrix_lib::Error::InvalidArgument);
        }

        let id = self.next_alloc_id;
        self.next_alloc_id += 1;

        let info = &mut self.pages[pfn];
        info.order = order;
        info.gfp_flags = gfp_flags;
        info.migration_type = migration_type;
        info.alloc_id = id;
        info.free_id = 0;
        info.allocated = true;

        // Copy the call chain (up to STACK_DEPTH entries).
        info.alloc_stack = [0; STACK_DEPTH];
        let copy_len = core::cmp::min(stack.len(), STACK_DEPTH);
        info.alloc_stack[..copy_len].copy_from_slice(&stack[..copy_len]);

        info.free_stack = [0; STACK_DEPTH];

        Ok(())
    }

    /// Record a free event for the given PFN.
    ///
    /// `stack` is the caller-provided call chain at free time.
    pub fn record_free(&mut self, pfn: usize, _order: u8, stack: &[u64]) -> Result<()> {
        if !self.active {
            return Err(oncrix_lib::Error::NotImplemented);
        }
        if !self.valid_pfn(pfn) {
            return Err(oncrix_lib::Error::InvalidArgument);
        }

        let info = &mut self.pages[pfn];
        if !info.allocated {
            return Err(oncrix_lib::Error::InvalidArgument);
        }

        let id = self.next_free_id;
        self.next_free_id += 1;

        info.free_id = id;
        info.allocated = false;

        info.free_stack = [0; STACK_DEPTH];
        let copy_len = core::cmp::min(stack.len(), STACK_DEPTH);
        info.free_stack[..copy_len].copy_from_slice(&stack[..copy_len]);

        Ok(())
    }

    /// Query the ownership information for a page.
    pub fn query_owner(&self, pfn: usize) -> Option<&PageOwnerInfo> {
        if !self.active || !self.valid_pfn(pfn) {
            return None;
        }
        let info = &self.pages[pfn];
        // Only return if the page has been tracked at least once.
        if info.alloc_id == 0 { None } else { Some(info) }
    }

    /// Returns the number of currently allocated pages.
    pub fn allocated_count(&self) -> usize {
        if !self.active {
            return 0;
        }
        self.pages.iter().filter(|p| p.allocated).count()
    }

    /// Returns the total capacity of the table.
    pub fn capacity(&self) -> usize {
        MAX_PAGES
    }

    /// Returns `true` if tracking is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

// -------------------------------------------------------------------
// PageOwnerTracker
// -------------------------------------------------------------------

/// Top-level page ownership tracker combining the per-page table
/// with allocation-site statistics.
pub struct PageOwnerTracker {
    /// Per-page ownership table.
    table: OwnerTable,
    /// Whether the tracker is enabled.
    enabled: bool,
}

impl Default for PageOwnerTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl PageOwnerTracker {
    /// Creates a new, disabled page ownership tracker.
    pub const fn new() -> Self {
        Self {
            table: OwnerTable::new(),
            enabled: false,
        }
    }

    /// Enable tracking.
    pub fn enable(&mut self) {
        self.enabled = true;
        self.table.active = true;
    }

    /// Disable tracking.
    pub fn disable(&mut self) {
        self.enabled = false;
        self.table.active = false;
    }

    /// Returns `true` if the tracker is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Record an allocation. See [`OwnerTable::record_alloc`].
    pub fn record_alloc(
        &mut self,
        pfn: usize,
        order: u8,
        gfp_flags: GfpFlags,
        stack: &[u64],
    ) -> Result<()> {
        self.table
            .record_alloc(pfn, order, gfp_flags, MigrationType::Unmovable, stack)
    }

    /// Record a free event. See [`OwnerTable::record_free`].
    pub fn record_free(&mut self, pfn: usize, order: u8, stack: &[u64]) -> Result<()> {
        self.table.record_free(pfn, order, stack)
    }

    /// Query page ownership. See [`OwnerTable::query_owner`].
    pub fn query_owner(&self, pfn: usize) -> Option<&PageOwnerInfo> {
        self.table.query_owner(pfn)
    }

    /// Return the top `n` allocation sites by page count.
    ///
    /// Sites are identified by the top-of-stack address in the
    /// allocation call chain. Returns a count up to `n` (or fewer
    /// if there are fewer distinct sites).
    pub fn top_allocators(&self, n: usize) -> ([OwnerStats; MAX_STATS_ENTRIES], usize) {
        let mut stats: [OwnerStats; MAX_STATS_ENTRIES] = [OwnerStats {
            alloc_site: 0,
            page_count: 0,
            alloc_count: 0,
        }; MAX_STATS_ENTRIES];
        let mut stat_count: usize = 0;

        // Aggregate by top-of-stack address.
        for page in &self.table.pages {
            if page.alloc_id == 0 || !page.allocated {
                continue;
            }
            let site = page.alloc_stack[0];
            if site == 0 {
                continue;
            }

            // Find or insert the site.
            let mut found = false;
            for s in &mut stats[..stat_count] {
                if s.alloc_site == site {
                    s.page_count += 1 << page.order;
                    s.alloc_count += 1;
                    found = true;
                    break;
                }
            }
            if !found && stat_count < MAX_STATS_ENTRIES {
                stats[stat_count] = OwnerStats {
                    alloc_site: site,
                    page_count: 1 << page.order,
                    alloc_count: 1,
                };
                stat_count += 1;
            }
        }

        // Sort descending by page_count (simple selection sort for
        // no_std).
        for i in 0..stat_count {
            let mut max_idx = i;
            for j in (i + 1)..stat_count {
                if stats[j].page_count > stats[max_idx].page_count {
                    max_idx = j;
                }
            }
            if max_idx != i {
                stats.swap(i, max_idx);
            }
        }

        let result_count = core::cmp::min(n, stat_count);
        (stats, result_count)
    }

    /// Returns an immutable reference to the owner table.
    pub fn table(&self) -> &OwnerTable {
        &self.table
    }
}
