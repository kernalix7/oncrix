// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page owner tracking.
//!
//! When `CONFIG_PAGE_OWNER` is enabled, every page allocation records
//! a stack trace and allocation order. This enables debugging of
//! memory leaks by answering "who allocated this page?" This module
//! provides the tracking table, query interface, and reporting.
//!
//! # Design
//!
//! ```text
//!  alloc_pages(order)
//!     │
//!     └─ record: (pfn, order, gfp_flags, call_site, timestamp)
//!
//!  cat /sys/kernel/debug/page_owner
//!     │
//!     └─ for each tracked page → print owner info
//! ```
//!
//! # Key Types
//!
//! - [`OwnerRecord`] — allocation record for a page
//! - [`PageOwnerTracker`] — tracks ownership for all pages
//! - [`PageOwnerTrackStats`] — tracking statistics
//!
//! Reference: Linux `mm/page_owner.c`, `include/linux/page_owner.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum tracked records.
const MAX_RECORDS: usize = 8192;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// OwnerRecord
// -------------------------------------------------------------------

/// Allocation record for a page.
#[derive(Debug, Clone, Copy)]
pub struct OwnerRecord {
    /// Physical frame number.
    pfn: u64,
    /// Allocation order (0 = single page, 9 = 2 MiB).
    order: u32,
    /// GFP flags used for allocation.
    gfp_flags: u32,
    /// Call site address (return address of allocator).
    call_site: u64,
    /// Timestamp of allocation.
    timestamp: u64,
    /// Process ID that allocated.
    pid: u64,
    /// Whether the page is currently allocated.
    allocated: bool,
    /// Free timestamp (0 if still allocated).
    free_timestamp: u64,
}

impl OwnerRecord {
    /// Create a new owner record.
    pub const fn new(
        pfn: u64,
        order: u32,
        gfp_flags: u32,
        call_site: u64,
        pid: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            pfn,
            order,
            gfp_flags,
            call_site,
            timestamp,
            pid,
            allocated: true,
            free_timestamp: 0,
        }
    }

    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the order.
    pub const fn order(&self) -> u32 {
        self.order
    }

    /// Return the GFP flags.
    pub const fn gfp_flags(&self) -> u32 {
        self.gfp_flags
    }

    /// Return the call site.
    pub const fn call_site(&self) -> u64 {
        self.call_site
    }

    /// Return the allocation timestamp.
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Return the PID.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Check whether the page is allocated.
    pub const fn allocated(&self) -> bool {
        self.allocated
    }

    /// Return the number of pages in this allocation.
    pub const fn page_count(&self) -> u64 {
        1u64 << self.order
    }

    /// Return the allocation size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.page_count() * PAGE_SIZE
    }

    /// Mark as freed.
    pub fn mark_freed(&mut self, free_ts: u64) {
        self.allocated = false;
        self.free_timestamp = free_ts;
    }

    /// Allocation lifetime (ticks).
    pub const fn lifetime(&self) -> u64 {
        if self.free_timestamp > 0 {
            self.free_timestamp - self.timestamp
        } else {
            0
        }
    }
}

impl Default for OwnerRecord {
    fn default() -> Self {
        Self {
            pfn: 0,
            order: 0,
            gfp_flags: 0,
            call_site: 0,
            timestamp: 0,
            pid: 0,
            allocated: false,
            free_timestamp: 0,
        }
    }
}

// -------------------------------------------------------------------
// PageOwnerTrackStats
// -------------------------------------------------------------------

/// Tracking statistics.
#[derive(Debug, Clone, Copy)]
pub struct PageOwnerTrackStats {
    /// Total allocations tracked.
    pub total_allocs: u64,
    /// Total frees tracked.
    pub total_frees: u64,
    /// Currently allocated pages (tracked).
    pub current_allocs: u64,
    /// Total pages tracked (sum of orders).
    pub total_pages_tracked: u64,
    /// Records dropped (table full).
    pub records_dropped: u64,
}

impl PageOwnerTrackStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_allocs: 0,
            total_frees: 0,
            current_allocs: 0,
            total_pages_tracked: 0,
            records_dropped: 0,
        }
    }
}

impl Default for PageOwnerTrackStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PageOwnerTracker
// -------------------------------------------------------------------

/// Tracks page ownership.
pub struct PageOwnerTracker {
    /// Records.
    records: [OwnerRecord; MAX_RECORDS],
    /// Number of records.
    count: usize,
    /// Whether tracking is enabled.
    enabled: bool,
    /// Statistics.
    stats: PageOwnerTrackStats,
}

impl PageOwnerTracker {
    /// Create a new tracker.
    pub const fn new() -> Self {
        Self {
            records: [const {
                OwnerRecord {
                    pfn: 0,
                    order: 0,
                    gfp_flags: 0,
                    call_site: 0,
                    timestamp: 0,
                    pid: 0,
                    allocated: false,
                    free_timestamp: 0,
                }
            }; MAX_RECORDS],
            count: 0,
            enabled: true,
            stats: PageOwnerTrackStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &PageOwnerTrackStats {
        &self.stats
    }

    /// Return the number of records.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Check whether tracking is enabled.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable tracking.
    pub fn set_enabled(&mut self, val: bool) {
        self.enabled = val;
    }

    /// Record an allocation.
    pub fn record_alloc(
        &mut self,
        pfn: u64,
        order: u32,
        gfp_flags: u32,
        call_site: u64,
        pid: u64,
        timestamp: u64,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.count >= MAX_RECORDS {
            self.stats.records_dropped += 1;
            return Err(Error::OutOfMemory);
        }
        self.records[self.count] =
            OwnerRecord::new(pfn, order, gfp_flags, call_site, pid, timestamp);
        self.count += 1;
        self.stats.total_allocs += 1;
        self.stats.current_allocs += 1;
        self.stats.total_pages_tracked += 1u64 << order;
        Ok(())
    }

    /// Record a free.
    pub fn record_free(&mut self, pfn: u64, timestamp: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        for idx in 0..self.count {
            if self.records[idx].pfn() == pfn && self.records[idx].allocated() {
                self.records[idx].mark_freed(timestamp);
                self.stats.total_frees += 1;
                self.stats.current_allocs = self.stats.current_allocs.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find an owner record by PFN.
    pub fn find(&self, pfn: u64) -> Option<&OwnerRecord> {
        for idx in 0..self.count {
            if self.records[idx].pfn() == pfn {
                return Some(&self.records[idx]);
            }
        }
        None
    }

    /// Count records for a given PID.
    pub fn count_by_pid(&self, pid: u64) -> usize {
        let mut n = 0;
        for idx in 0..self.count {
            if self.records[idx].pid() == pid && self.records[idx].allocated() {
                n += 1;
            }
        }
        n
    }

    /// Count allocated pages by PID.
    pub fn pages_by_pid(&self, pid: u64) -> u64 {
        let mut total: u64 = 0;
        for idx in 0..self.count {
            if self.records[idx].pid() == pid && self.records[idx].allocated() {
                total += self.records[idx].page_count();
            }
        }
        total
    }
}

impl Default for PageOwnerTracker {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum records.
pub const fn max_records() -> usize {
    MAX_RECORDS
}

/// Return the page size.
pub const fn page_size() -> u64 {
    PAGE_SIZE
}
