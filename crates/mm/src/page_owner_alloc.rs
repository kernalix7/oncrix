// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page owner allocation tracking.
//!
//! Records allocation metadata (stack trace handle, order, GFP flags)
//! for each physical page, enabling post-mortem analysis of memory
//! usage patterns and leak detection.  The subsystem is gated by an
//! `enabled` flag so that tracking overhead is avoided in production.
//!
//! # Key Types
//!
//! - [`GfpFlags`] — simplified GFP allocation flag set
//! - [`StackHandle`] — compact reference to an allocation call site
//! - [`PageOwnerInfo`] — per-page ownership metadata
//! - [`OwnerTable`] — flat table of per-page owner records
//! - [`OwnerSiteStat`] — per-allocation-site leak statistics
//! - [`OwnerStats`] — aggregate allocation-site summary
//! - [`PageOwnerAllocTracker`] — top-level tracker
//!
//! Reference: Linux `mm/page_owner.c`, `include/linux/page_owner.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pages tracked.
const MAX_TRACKED_PAGES: usize = 4096;

/// Maximum allocation-site statistics entries.
const MAX_SITE_STATS: usize = 128;

/// Stack handle depth (number of return addresses).
const STACK_DEPTH: usize = 4;

/// Indicates no owner has been recorded.
const NO_OWNER: u32 = u32::MAX;

// -------------------------------------------------------------------
// GfpFlags
// -------------------------------------------------------------------

/// Simplified GFP allocation flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GfpFlags(pub u32);

impl GfpFlags {
    /// Normal kernel allocation.
    pub const KERNEL: Self = Self(0x01);
    /// Atomic context (cannot sleep).
    pub const ATOMIC: Self = Self(0x02);
    /// User-space allocation.
    pub const USER: Self = Self(0x04);
    /// High memory zone.
    pub const HIGHMEM: Self = Self(0x08);
    /// DMA-capable zone.
    pub const DMA: Self = Self(0x10);
    /// Zero-filled allocation.
    pub const ZERO: Self = Self(0x20);
    /// No reclaim allowed.
    pub const NOWAIT: Self = Self(0x40);

    /// Empty (no flags).
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Test whether specific bits are set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

// -------------------------------------------------------------------
// StackHandle
// -------------------------------------------------------------------

/// Compact reference to an allocation call site (stack trace).
///
/// Stores up to [`STACK_DEPTH`] return addresses to identify
/// the code path that allocated a page.
#[derive(Debug, Clone, Copy, Default)]
pub struct StackHandle {
    /// Return addresses (0 means unused slot).
    pub addrs: [u64; STACK_DEPTH],
    /// Number of valid entries.
    pub depth: u8,
}

impl StackHandle {
    /// Create an empty stack handle.
    pub const fn empty() -> Self {
        Self {
            addrs: [0u64; STACK_DEPTH],
            depth: 0,
        }
    }

    /// Create a handle from a slice of return addresses.
    pub fn from_addrs(addrs: &[u64]) -> Self {
        let mut handle = Self::empty();
        let n = addrs.len().min(STACK_DEPTH);
        let mut i = 0;
        while i < n {
            handle.addrs[i] = addrs[i];
            i += 1;
        }
        handle.depth = n as u8;
        handle
    }

    /// Whether this handle has any recorded addresses.
    pub const fn is_valid(&self) -> bool {
        self.depth > 0
    }

    /// Top-most (outermost caller) address, or 0.
    pub const fn top_addr(&self) -> u64 {
        if self.depth > 0 { self.addrs[0] } else { 0 }
    }
}

// -------------------------------------------------------------------
// PageOwnerInfo
// -------------------------------------------------------------------

/// Per-page ownership metadata.
#[derive(Debug, Clone, Copy)]
pub struct PageOwnerInfo {
    /// Physical frame number of the tracked page.
    pub pfn: u64,
    /// Allocation order (0 = single page, 9 = THP order).
    pub order: u8,
    /// GFP flags used at allocation time.
    pub gfp: GfpFlags,
    /// Stack handle referencing the allocation call site.
    pub alloc_handle: StackHandle,
    /// Stack handle referencing the free call site (if freed).
    pub free_handle: StackHandle,
    /// Monotonic timestamp of allocation.
    pub alloc_ts: u64,
    /// Monotonic timestamp of free (0 if still allocated).
    pub free_ts: u64,
    /// Owner identifier (e.g. PID or subsystem ID).
    pub owner_id: u32,
    /// Whether the page is currently allocated.
    pub allocated: bool,
    /// Whether this record slot is in use.
    active: bool,
}

impl PageOwnerInfo {
    /// Create an empty, inactive record.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            order: 0,
            gfp: GfpFlags::empty(),
            alloc_handle: StackHandle::empty(),
            free_handle: StackHandle::empty(),
            alloc_ts: 0,
            free_ts: 0,
            owner_id: NO_OWNER,
            allocated: false,
            active: false,
        }
    }

    /// Whether this record is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Whether the page is still allocated (not freed).
    pub const fn is_allocated(&self) -> bool {
        self.allocated
    }

    /// Duration the page has been held (0 if freed or no ts).
    pub const fn hold_duration(&self, now: u64) -> u64 {
        if self.allocated && self.alloc_ts > 0 {
            now.saturating_sub(self.alloc_ts)
        } else {
            0
        }
    }
}

impl Default for PageOwnerInfo {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// OwnerTable
// -------------------------------------------------------------------

/// Flat table of per-page owner records.
pub struct OwnerTable {
    /// Records indexed by a hashed PFN.
    records: [PageOwnerInfo; MAX_TRACKED_PAGES],
    /// Number of active records.
    count: usize,
}

impl OwnerTable {
    /// Create an empty table.
    const fn new() -> Self {
        Self {
            records: [PageOwnerInfo::empty(); MAX_TRACKED_PAGES],
            count: 0,
        }
    }

    /// Number of active records.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Look up a record by PFN.
    pub fn get(&self, pfn: u64) -> Option<&PageOwnerInfo> {
        self.records[..].iter().find(|r| r.active && r.pfn == pfn)
    }

    /// Set owner info for a page (allocation event).
    fn set_alloc(
        &mut self,
        pfn: u64,
        order: u8,
        gfp: GfpFlags,
        handle: StackHandle,
        owner_id: u32,
        ts: u64,
    ) -> Result<()> {
        // Try to reuse an existing record for this PFN first.
        let pos = self.records.iter().position(|r| r.active && r.pfn == pfn);

        let idx = if let Some(p) = pos {
            p
        } else {
            self.records
                .iter()
                .position(|r| !r.active)
                .ok_or(Error::OutOfMemory)?
        };

        let rec = &mut self.records[idx];
        let was_active = rec.active;
        rec.pfn = pfn;
        rec.order = order;
        rec.gfp = gfp;
        rec.alloc_handle = handle;
        rec.free_handle = StackHandle::empty();
        rec.alloc_ts = ts;
        rec.free_ts = 0;
        rec.owner_id = owner_id;
        rec.allocated = true;
        rec.active = true;

        if !was_active {
            self.count += 1;
        }
        Ok(())
    }

    /// Record a free event for a page.
    fn set_free(&mut self, pfn: u64, handle: StackHandle, ts: u64) -> Result<()> {
        let rec = self
            .records
            .iter_mut()
            .find(|r| r.active && r.pfn == pfn && r.allocated)
            .ok_or(Error::NotFound)?;
        rec.free_handle = handle;
        rec.free_ts = ts;
        rec.allocated = false;
        Ok(())
    }
}

// -------------------------------------------------------------------
// OwnerSiteStat
// -------------------------------------------------------------------

/// Per-allocation-site leak detection statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct OwnerSiteStat {
    /// Top-most caller address identifying the allocation site.
    pub top_addr: u64,
    /// Total allocations from this site.
    pub total_allocs: u64,
    /// Total frees from this site.
    pub total_frees: u64,
    /// Currently outstanding (allocated - freed).
    pub outstanding: u64,
    /// Total pages (considering order).
    pub total_pages: u64,
    /// Whether this slot is in use.
    active: bool,
}

impl OwnerSiteStat {
    /// Empty site stat.
    const fn empty() -> Self {
        Self {
            top_addr: 0,
            total_allocs: 0,
            total_frees: 0,
            outstanding: 0,
            total_pages: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// OwnerStats
// -------------------------------------------------------------------

/// Aggregate allocation-site statistics for leak detection.
pub struct OwnerStats {
    /// Per-site statistics.
    sites: [OwnerSiteStat; MAX_SITE_STATS],
    /// Number of active sites.
    count: usize,
}

impl OwnerStats {
    /// Create an empty statistics set.
    const fn new() -> Self {
        Self {
            sites: [OwnerSiteStat::empty(); MAX_SITE_STATS],
            count: 0,
        }
    }

    /// Number of tracked allocation sites.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Read-only access to site statistics.
    pub fn sites(&self) -> &[OwnerSiteStat] {
        &self.sites[..self.count]
    }

    /// Record an allocation from the given call site.
    fn record_alloc(&mut self, top_addr: u64, order: u8) {
        let pages = 1u64 << (order as u64);
        let pos = self.sites[..self.count]
            .iter()
            .position(|s| s.active && s.top_addr == top_addr);

        if let Some(idx) = pos {
            self.sites[idx].total_allocs += 1;
            self.sites[idx].outstanding += 1;
            self.sites[idx].total_pages += pages;
        } else if self.count < MAX_SITE_STATS {
            self.sites[self.count] = OwnerSiteStat {
                top_addr,
                total_allocs: 1,
                total_frees: 0,
                outstanding: 1,
                total_pages: pages,
                active: true,
            };
            self.count += 1;
        }
    }

    /// Record a free from the given call site.
    fn record_free(&mut self, top_addr: u64) {
        let pos = self.sites[..self.count]
            .iter()
            .position(|s| s.active && s.top_addr == top_addr);
        if let Some(idx) = pos {
            self.sites[idx].total_frees += 1;
            self.sites[idx].outstanding = self.sites[idx].outstanding.saturating_sub(1);
        }
    }
}

// -------------------------------------------------------------------
// PageOwnerAllocTracker
// -------------------------------------------------------------------

/// Top-level page owner allocation tracker.
///
/// When enabled, records allocation and free events per physical
/// page, maintaining per-site statistics for leak detection.
pub struct PageOwnerAllocTracker {
    /// Whether tracking is enabled.
    enabled: bool,
    /// Owner table.
    table: OwnerTable,
    /// Per-site statistics.
    site_stats: OwnerStats,
    /// Total allocation events.
    total_allocs: u64,
    /// Total free events.
    total_frees: u64,
}

impl Default for PageOwnerAllocTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl PageOwnerAllocTracker {
    /// Create a new tracker (disabled by default).
    pub const fn new() -> Self {
        Self {
            enabled: false,
            table: OwnerTable::new(),
            site_stats: OwnerStats::new(),
            total_allocs: 0,
            total_frees: 0,
        }
    }

    /// Enable or disable tracking.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether tracking is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Record a page allocation event.
    ///
    /// No-op if tracking is disabled.
    pub fn record_alloc(
        &mut self,
        pfn: u64,
        order: u8,
        gfp: GfpFlags,
        stack: &[u64],
        owner_id: u32,
        ts: u64,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let handle = StackHandle::from_addrs(stack);
        self.table
            .set_alloc(pfn, order, gfp, handle, owner_id, ts)?;
        self.site_stats.record_alloc(handle.top_addr(), order);
        self.total_allocs += 1;
        Ok(())
    }

    /// Record a page free event.
    ///
    /// No-op if tracking is disabled.
    pub fn record_free(&mut self, pfn: u64, stack: &[u64], ts: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let handle = StackHandle::from_addrs(stack);
        // Look up allocation site for site_stats bookkeeping.
        let alloc_top = self
            .table
            .get(pfn)
            .map(|r| r.alloc_handle.top_addr())
            .unwrap_or(0);
        self.table.set_free(pfn, handle, ts)?;
        self.site_stats.record_free(alloc_top);
        self.total_frees += 1;
        Ok(())
    }

    /// Look up owner info for a specific page.
    pub fn get_owner(&self, pfn: u64) -> Result<&PageOwnerInfo> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        self.table.get(pfn).ok_or(Error::NotFound)
    }

    /// Total allocation events recorded.
    pub const fn total_allocs(&self) -> u64 {
        self.total_allocs
    }

    /// Total free events recorded.
    pub const fn total_frees(&self) -> u64 {
        self.total_frees
    }

    /// Currently outstanding allocations (allocated - freed).
    pub const fn outstanding(&self) -> u64 {
        self.total_allocs.saturating_sub(self.total_frees)
    }

    /// Number of tracked pages in the owner table.
    pub const fn tracked_pages(&self) -> usize {
        self.table.count()
    }

    /// Read-only access to per-site statistics.
    pub fn site_stats(&self) -> &[OwnerSiteStat] {
        self.site_stats.sites()
    }
}
