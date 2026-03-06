// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! mmap MAP_POPULATE handler.
//!
//! When `mmap()` is called with the `MAP_POPULATE` flag, all pages
//! within the mapped region should be faulted in eagerly rather than
//! on demand. This module drives the population process: it walks the
//! newly mapped range, allocates physical frames, installs page-table
//! entries, and records statistics on pre-faulting activity.
//!
//! # Design
//!
//! ```text
//!  mmap(MAP_POPULATE)
//!       │
//!       ▼
//!  ┌──────────────┐    for each page     ┌──────────────┐
//!  │ PopulateReq  │ ─────────────────── ▶ │ alloc frame  │
//!  │ (start, len) │                       │ install PTE  │
//!  └──────────────┘                       └──────────────┘
//!       │
//!       ▼
//!  PopulateResult { faulted, failed }
//! ```
//!
//! # Key Types
//!
//! - [`PopulateFlags`] — flags controlling populate behaviour
//! - [`PopulateRequest`] — describes a range to populate
//! - [`PopulateResult`] — result summary
//! - [`PopulateEngine`] — the populate execution engine
//!
//! Reference: Linux `mm/mmap.c` (`mm_populate`), `mm/gup.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size.
const PAGE_SIZE: u64 = 4096;

/// Maximum pages in a single populate request.
const MAX_POPULATE_PAGES: usize = 8192;

/// Maximum concurrent populate requests tracked.
const MAX_REQUESTS: usize = 64;

// -------------------------------------------------------------------
// PopulateFlags
// -------------------------------------------------------------------

/// Flags controlling populate behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PopulateFlags(u32);

impl PopulateFlags {
    /// Populate read-only pages.
    pub const READ: u32 = 1 << 0;
    /// Populate writable pages.
    pub const WRITE: u32 = 1 << 1;
    /// Lock pages after populating (MAP_LOCKED).
    pub const LOCK: u32 = 1 << 2;
    /// Non-blocking — skip pages that would block.
    pub const NONBLOCK: u32 = 1 << 3;

    /// Creates empty flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Creates flags from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if a flag is set.
    pub const fn contains(self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

impl Default for PopulateFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// PopulateRequest
// -------------------------------------------------------------------

/// Describes a memory range to be populated.
#[derive(Debug, Clone, Copy)]
pub struct PopulateRequest {
    /// Start virtual address (page-aligned).
    start: u64,
    /// Length in bytes (page-aligned).
    length: u64,
    /// Populate flags.
    flags: PopulateFlags,
    /// PID of the requesting process.
    pid: u64,
}

impl PopulateRequest {
    /// Creates a new populate request.
    pub const fn new(start: u64, length: u64, flags: PopulateFlags, pid: u64) -> Self {
        Self {
            start,
            length,
            flags,
            pid,
        }
    }

    /// Returns the start address.
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Returns the length.
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Returns the number of pages.
    pub const fn nr_pages(&self) -> u64 {
        self.length / PAGE_SIZE
    }

    /// Returns the flags.
    pub const fn flags(&self) -> PopulateFlags {
        self.flags
    }

    /// Validates the request.
    pub fn validate(&self) -> Result<()> {
        if self.start % PAGE_SIZE != 0 || self.length % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.length == 0 {
            return Err(Error::InvalidArgument);
        }
        let pages = self.length / PAGE_SIZE;
        if (pages as usize) > MAX_POPULATE_PAGES {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for PopulateRequest {
    fn default() -> Self {
        Self::new(0, PAGE_SIZE, PopulateFlags::empty(), 0)
    }
}

// -------------------------------------------------------------------
// PopulateResult
// -------------------------------------------------------------------

/// Result of a populate operation.
#[derive(Debug, Clone, Copy)]
pub struct PopulateResult {
    /// Number of pages successfully faulted in.
    pub faulted: usize,
    /// Number of pages that failed.
    pub failed: usize,
    /// Number of pages skipped (non-blocking mode).
    pub skipped: usize,
    /// Number of pages locked.
    pub locked: usize,
}

impl PopulateResult {
    /// Creates an empty result.
    pub const fn new() -> Self {
        Self {
            faulted: 0,
            failed: 0,
            skipped: 0,
            locked: 0,
        }
    }

    /// Returns the total pages processed.
    pub const fn total(&self) -> usize {
        self.faulted + self.failed + self.skipped
    }

    /// Returns `true` if all pages were successfully faulted.
    pub const fn is_complete(&self) -> bool {
        self.failed == 0 && self.skipped == 0
    }
}

impl Default for PopulateResult {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PopulateEngine
// -------------------------------------------------------------------

/// Engine for executing MAP_POPULATE operations.
pub struct PopulateEngine {
    /// Pending requests.
    requests: [Option<PopulateRequest>; MAX_REQUESTS],
    /// Number of pending requests.
    pending: usize,
    /// Total pages populated.
    total_populated: u64,
    /// Total populate operations.
    total_ops: u64,
    /// Total failures.
    total_failures: u64,
}

impl PopulateEngine {
    /// Creates a new populate engine.
    pub const fn new() -> Self {
        Self {
            requests: [const { None }; MAX_REQUESTS],
            pending: 0,
            total_populated: 0,
            total_ops: 0,
            total_failures: 0,
        }
    }

    /// Returns the number of pending requests.
    pub const fn pending(&self) -> usize {
        self.pending
    }

    /// Returns total pages populated.
    pub const fn total_populated(&self) -> u64 {
        self.total_populated
    }

    /// Submits a populate request.
    pub fn submit(&mut self, req: PopulateRequest) -> Result<()> {
        req.validate()?;
        for i in 0..MAX_REQUESTS {
            if self.requests[i].is_none() {
                self.requests[i] = Some(req);
                self.pending += 1;
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Executes the next pending populate request.
    ///
    /// In a real implementation this would walk page tables and fault
    /// in pages. Here we simulate the operation.
    pub fn execute_next(&mut self) -> Result<PopulateResult> {
        let mut req_idx = MAX_REQUESTS;
        for i in 0..MAX_REQUESTS {
            if self.requests[i].is_some() {
                req_idx = i;
                break;
            }
        }
        if req_idx >= MAX_REQUESTS {
            return Err(Error::NotFound);
        }

        let req = self.requests[req_idx].take().ok_or(Error::NotFound)?;
        self.pending -= 1;
        self.total_ops = self.total_ops.saturating_add(1);

        let nr_pages = req.nr_pages() as usize;
        let mut result = PopulateResult::new();

        for _i in 0..nr_pages {
            // Simulate successful population.
            result.faulted += 1;
            if req.flags.contains(PopulateFlags::LOCK) {
                result.locked += 1;
            }
        }

        self.total_populated = self.total_populated.saturating_add(result.faulted as u64);
        Ok(result)
    }

    /// Executes all pending requests, returning total results.
    pub fn execute_all(&mut self) -> PopulateResult {
        let mut total = PopulateResult::new();
        loop {
            match self.execute_next() {
                Ok(r) => {
                    total.faulted += r.faulted;
                    total.failed += r.failed;
                    total.skipped += r.skipped;
                    total.locked += r.locked;
                }
                Err(_) => break,
            }
        }
        total
    }
}

impl Default for PopulateEngine {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a populate request and validates it.
pub fn create_request(
    start: u64,
    length: u64,
    flags: PopulateFlags,
    pid: u64,
) -> Result<PopulateRequest> {
    let req = PopulateRequest::new(start, length, flags, pid);
    req.validate()?;
    Ok(req)
}

/// Populates a range immediately, returning the result.
pub fn populate_range(engine: &mut PopulateEngine, req: PopulateRequest) -> Result<PopulateResult> {
    engine.submit(req)?;
    engine.execute_next()
}

/// Returns the total number of pages populated by the engine.
pub fn total_populated(engine: &PopulateEngine) -> u64 {
    engine.total_populated()
}
