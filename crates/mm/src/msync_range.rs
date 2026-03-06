// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Msync range management.
//!
//! The `msync(2)` syscall synchronises a file-backed memory mapping
//! with its underlying storage. This module tracks dirty ranges within
//! mapped regions, batches them for writeback, and handles the
//! `MS_SYNC`, `MS_ASYNC`, and `MS_INVALIDATE` flags.
//!
//! # Design
//!
//! ```text
//!  msync(addr, length, MS_SYNC)
//!     │
//!     ├─ validate addr is page-aligned
//!     ├─ find VMA covering [addr, addr+length)
//!     ├─ collect dirty pages in range
//!     ├─ issue writeback (synchronous for MS_SYNC)
//!     └─ clear dirty bits on success
//! ```
//!
//! # Key Types
//!
//! - [`MsyncFlags`] — sync flag set
//! - [`DirtyRange`] — a contiguous dirty range within a mapping
//! - [`MsyncRangeTracker`] — tracks dirty ranges for msync
//! - [`MsyncRangeStats`] — writeback statistics
//!
//! Reference: Linux `mm/msync.c`, POSIX `msync(2)`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum tracked dirty ranges.
const MAX_DIRTY_RANGES: usize = 1024;

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Maximum writeback batch size in pages.
const MAX_WRITEBACK_BATCH: u64 = 256;

// -------------------------------------------------------------------
// MsyncFlags
// -------------------------------------------------------------------

/// Sync flag set for msync(2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsyncFlags {
    /// Synchronous writeback.
    Sync,
    /// Asynchronous writeback.
    Async,
    /// Invalidate cached copies.
    Invalidate,
}

impl MsyncFlags {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Sync => "MS_SYNC",
            Self::Async => "MS_ASYNC",
            Self::Invalidate => "MS_INVALIDATE",
        }
    }

    /// Check whether this requires blocking.
    pub const fn is_blocking(&self) -> bool {
        matches!(self, Self::Sync)
    }
}

// -------------------------------------------------------------------
// DirtyRange
// -------------------------------------------------------------------

/// A contiguous dirty range within a mapping.
#[derive(Debug, Clone, Copy)]
pub struct DirtyRange {
    /// Start address (page-aligned).
    start_addr: u64,
    /// End address (page-aligned, exclusive).
    end_addr: u64,
    /// Number of dirty pages.
    dirty_pages: u64,
    /// Whether writeback has been initiated.
    writeback_started: bool,
    /// Whether writeback completed.
    writeback_done: bool,
    /// Associated file inode number (0 if anonymous).
    inode: u64,
}

impl DirtyRange {
    /// Create a new dirty range.
    pub const fn new(start_addr: u64, end_addr: u64, inode: u64) -> Self {
        let dirty_pages = (end_addr - start_addr) / PAGE_SIZE;
        Self {
            start_addr,
            end_addr,
            dirty_pages,
            writeback_started: false,
            writeback_done: false,
            inode,
        }
    }

    /// Return the start address.
    pub const fn start_addr(&self) -> u64 {
        self.start_addr
    }

    /// Return the end address.
    pub const fn end_addr(&self) -> u64 {
        self.end_addr
    }

    /// Return the number of dirty pages.
    pub const fn dirty_pages(&self) -> u64 {
        self.dirty_pages
    }

    /// Check whether writeback started.
    pub const fn writeback_started(&self) -> bool {
        self.writeback_started
    }

    /// Check whether writeback completed.
    pub const fn writeback_done(&self) -> bool {
        self.writeback_done
    }

    /// Return the inode number.
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Return the range size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.end_addr - self.start_addr
    }

    /// Mark writeback as started.
    pub fn start_writeback(&mut self) {
        self.writeback_started = true;
    }

    /// Mark writeback as completed.
    pub fn complete_writeback(&mut self) {
        self.writeback_done = true;
    }

    /// Check whether this range overlaps with another.
    pub const fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start_addr < end && start < self.end_addr
    }

    /// Check whether this range is file-backed.
    pub const fn is_file_backed(&self) -> bool {
        self.inode != 0
    }
}

impl Default for DirtyRange {
    fn default() -> Self {
        Self {
            start_addr: 0,
            end_addr: 0,
            dirty_pages: 0,
            writeback_started: false,
            writeback_done: false,
            inode: 0,
        }
    }
}

// -------------------------------------------------------------------
// MsyncRangeStats
// -------------------------------------------------------------------

/// Writeback statistics for msync.
#[derive(Debug, Clone, Copy)]
pub struct MsyncRangeStats {
    /// Total msync calls.
    pub total_syncs: u64,
    /// Synchronous syncs.
    pub sync_count: u64,
    /// Asynchronous syncs.
    pub async_count: u64,
    /// Invalidations.
    pub invalidate_count: u64,
    /// Total pages written back.
    pub pages_written: u64,
    /// Writeback failures.
    pub writeback_failures: u64,
}

impl MsyncRangeStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_syncs: 0,
            sync_count: 0,
            async_count: 0,
            invalidate_count: 0,
            pages_written: 0,
            writeback_failures: 0,
        }
    }

    /// Success rate as percent.
    pub const fn success_pct(&self) -> u64 {
        if self.total_syncs == 0 {
            return 0;
        }
        (self.total_syncs - self.writeback_failures) * 100 / self.total_syncs
    }
}

impl Default for MsyncRangeStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MsyncRangeTracker
// -------------------------------------------------------------------

/// Tracks dirty ranges for msync operations.
pub struct MsyncRangeTracker {
    /// Dirty ranges.
    ranges: [DirtyRange; MAX_DIRTY_RANGES],
    /// Number of tracked ranges.
    count: usize,
    /// Statistics.
    stats: MsyncRangeStats,
}

impl MsyncRangeTracker {
    /// Create a new tracker.
    pub const fn new() -> Self {
        Self {
            ranges: [const {
                DirtyRange {
                    start_addr: 0,
                    end_addr: 0,
                    dirty_pages: 0,
                    writeback_started: false,
                    writeback_done: false,
                    inode: 0,
                }
            }; MAX_DIRTY_RANGES],
            count: 0,
            stats: MsyncRangeStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &MsyncRangeStats {
        &self.stats
    }

    /// Return the number of tracked ranges.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Add a dirty range.
    pub fn add_dirty_range(&mut self, start_addr: u64, end_addr: u64, inode: u64) -> Result<()> {
        if (start_addr % PAGE_SIZE) != 0 || (end_addr % PAGE_SIZE) != 0 {
            return Err(Error::InvalidArgument);
        }
        if start_addr >= end_addr {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_DIRTY_RANGES {
            return Err(Error::OutOfMemory);
        }
        self.ranges[self.count] = DirtyRange::new(start_addr, end_addr, inode);
        self.count += 1;
        Ok(())
    }

    /// Process an msync call on a range.
    pub fn msync(&mut self, start_addr: u64, end_addr: u64, flags: MsyncFlags) -> Result<u64> {
        if (start_addr % PAGE_SIZE) != 0 {
            return Err(Error::InvalidArgument);
        }
        self.stats.total_syncs += 1;
        match flags {
            MsyncFlags::Sync => self.stats.sync_count += 1,
            MsyncFlags::Async => self.stats.async_count += 1,
            MsyncFlags::Invalidate => self.stats.invalidate_count += 1,
        }

        let mut pages_synced: u64 = 0;
        for idx in 0..self.count {
            if self.ranges[idx].overlaps(start_addr, end_addr) {
                self.ranges[idx].start_writeback();
                let dp = self.ranges[idx].dirty_pages();
                pages_synced += dp;
                if flags.is_blocking() {
                    self.ranges[idx].complete_writeback();
                }
            }
        }
        self.stats.pages_written += pages_synced;
        Ok(pages_synced)
    }

    /// Find dirty ranges overlapping an address.
    pub fn find_overlapping(&self, addr: u64) -> Option<&DirtyRange> {
        for idx in 0..self.count {
            let range = &self.ranges[idx];
            if addr >= range.start_addr() && addr < range.end_addr() {
                return Some(range);
            }
        }
        None
    }

    /// Count pending (not yet written back) ranges.
    pub fn pending_count(&self) -> usize {
        let mut n = 0;
        for idx in 0..self.count {
            if !self.ranges[idx].writeback_done() {
                n += 1;
            }
        }
        n
    }
}

impl Default for MsyncRangeTracker {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum dirty ranges.
pub const fn max_dirty_ranges() -> usize {
    MAX_DIRTY_RANGES
}

/// Return the writeback batch size.
pub const fn max_writeback_batch() -> u64 {
    MAX_WRITEBACK_BATCH
}
