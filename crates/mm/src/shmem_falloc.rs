// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared memory fallocate operations.
//!
//! Implements `fallocate(2)` for shmem/tmpfs file systems, including
//! hole punching, range preallocation, and collapse range. These
//! operations manipulate the page cache and swap entries backing
//! shmem inodes.
//!
//! - [`FallocMode`] — fallocate operation mode
//! - [`FallocRange`] — range descriptor for operations
//! - [`ShmemFallocState`] — per-operation state tracker
//! - [`ShmemFallocStats`] — aggregate statistics
//! - [`ShmemFallocator`] — the fallocate engine
//!
//! Reference: Linux `mm/shmem.c` (shmem_fallocate).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum tracked ranges.
const MAX_RANGES: usize = 256;

/// Maximum pages per preallocation batch.
const MAX_PREALLOC_BATCH: u64 = 128;

// -------------------------------------------------------------------
// FallocMode
// -------------------------------------------------------------------

/// Fallocate operation modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FallocMode {
    /// Default: preallocate space.
    #[default]
    Allocate,
    /// Punch a hole (deallocate).
    PunchHole,
    /// Collapse a range (remove hole).
    CollapseRange,
    /// Zero-fill a range.
    ZeroRange,
    /// Insert a range (create hole).
    InsertRange,
}

// -------------------------------------------------------------------
// FallocRange
// -------------------------------------------------------------------

/// A range descriptor for fallocate operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct FallocRange {
    /// Offset in bytes.
    pub offset: u64,
    /// Length in bytes.
    pub length: u64,
    /// Operation mode.
    pub mode: FallocMode,
    /// Whether this range is active.
    pub active: bool,
}

impl FallocRange {
    /// Creates a new range.
    pub fn new(offset: u64, length: u64, mode: FallocMode) -> Self {
        Self {
            offset,
            length,
            mode,
            active: true,
        }
    }

    /// Returns the end offset (exclusive).
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }

    /// Returns the number of pages covered.
    pub fn nr_pages(&self) -> u64 {
        (self.length + PAGE_SIZE - 1) / PAGE_SIZE
    }

    /// Validates the range.
    pub fn validate(&self) -> Result<()> {
        if self.length == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.offset % PAGE_SIZE != 0 || self.length % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// -------------------------------------------------------------------
// ShmemFallocState
// -------------------------------------------------------------------

/// State for an in-progress fallocate operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShmemFallocState {
    /// Not started.
    #[default]
    Idle,
    /// In progress.
    Running,
    /// Completed successfully.
    Done,
    /// Failed.
    Failed,
}

// -------------------------------------------------------------------
// ShmemFallocStats
// -------------------------------------------------------------------

/// Aggregate shmem fallocate statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShmemFallocStats {
    /// Total allocate operations.
    pub allocates: u64,
    /// Total punch-hole operations.
    pub punch_holes: u64,
    /// Total collapse-range operations.
    pub collapses: u64,
    /// Total zero-range operations.
    pub zero_ranges: u64,
    /// Total insert-range operations.
    pub inserts: u64,
    /// Total pages allocated.
    pub pages_allocated: u64,
    /// Total pages freed (punched).
    pub pages_freed: u64,
    /// Failed operations.
    pub failures: u64,
}

impl ShmemFallocStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// ShmemFallocator
// -------------------------------------------------------------------

/// The shmem fallocate engine.
pub struct ShmemFallocator {
    /// Tracked ranges.
    ranges: [FallocRange; MAX_RANGES],
    /// Number of tracked ranges.
    count: usize,
    /// Current operation state.
    state: ShmemFallocState,
    /// Total pages in the shmem file.
    total_pages: u64,
    /// Statistics.
    stats: ShmemFallocStats,
}

impl Default for ShmemFallocator {
    fn default() -> Self {
        Self {
            ranges: [FallocRange::default(); MAX_RANGES],
            count: 0,
            state: ShmemFallocState::Idle,
            total_pages: 0,
            stats: ShmemFallocStats::default(),
        }
    }
}

impl ShmemFallocator {
    /// Creates a new shmem fallocator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Performs a fallocate operation.
    pub fn fallocate(&mut self, offset: u64, length: u64, mode: FallocMode) -> Result<u64> {
        let range = FallocRange::new(offset, length, mode);
        range.validate()?;

        self.state = ShmemFallocState::Running;

        let result = match mode {
            FallocMode::Allocate => self.do_allocate(&range),
            FallocMode::PunchHole => self.do_punch_hole(&range),
            FallocMode::CollapseRange => self.do_collapse(&range),
            FallocMode::ZeroRange => self.do_zero_range(&range),
            FallocMode::InsertRange => self.do_insert_range(&range),
        };

        match result {
            Ok(pages) => {
                self.state = ShmemFallocState::Done;
                if self.count < MAX_RANGES {
                    self.ranges[self.count] = range;
                    self.count += 1;
                }
                Ok(pages)
            }
            Err(e) => {
                self.state = ShmemFallocState::Failed;
                self.stats.failures += 1;
                Err(e)
            }
        }
    }

    /// Preallocate pages for a range.
    fn do_allocate(&mut self, range: &FallocRange) -> Result<u64> {
        let nr_pages = range.nr_pages().min(MAX_PREALLOC_BATCH);
        self.total_pages = self.total_pages.saturating_add(nr_pages);
        self.stats.allocates += 1;
        self.stats.pages_allocated += nr_pages;
        Ok(nr_pages)
    }

    /// Punch a hole (free pages in range).
    fn do_punch_hole(&mut self, range: &FallocRange) -> Result<u64> {
        let nr_pages = range.nr_pages();
        let freed = nr_pages.min(self.total_pages);
        self.total_pages = self.total_pages.saturating_sub(freed);
        self.stats.punch_holes += 1;
        self.stats.pages_freed += freed;
        Ok(freed)
    }

    /// Collapse a range (remove hole, shift pages).
    fn do_collapse(&mut self, range: &FallocRange) -> Result<u64> {
        let nr_pages = range.nr_pages();
        self.stats.collapses += 1;
        Ok(nr_pages)
    }

    /// Zero-fill a range.
    fn do_zero_range(&mut self, range: &FallocRange) -> Result<u64> {
        let nr_pages = range.nr_pages();
        self.stats.zero_ranges += 1;
        Ok(nr_pages)
    }

    /// Insert a range (create hole, shift pages).
    fn do_insert_range(&mut self, range: &FallocRange) -> Result<u64> {
        let nr_pages = range.nr_pages();
        self.total_pages = self.total_pages.saturating_add(nr_pages);
        self.stats.inserts += 1;
        Ok(nr_pages)
    }

    /// Returns the total pages in the file.
    pub fn total_pages(&self) -> u64 {
        self.total_pages
    }

    /// Returns the current operation state.
    pub fn state(&self) -> ShmemFallocState {
        self.state
    }

    /// Returns statistics.
    pub fn stats(&self) -> &ShmemFallocStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
