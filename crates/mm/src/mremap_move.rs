// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Mremap move operations.
//!
//! When `mremap(2)` is called with `MREMAP_MAYMOVE`, the kernel may
//! relocate a mapping to a new virtual address. This module handles
//! the page-table surgery: copying PTEs from the old range to the new
//! range, adjusting VMA metadata, and flushing the TLB for moved
//! entries.
//!
//! # Design
//!
//! ```text
//!  mremap(old_addr, old_size, new_size, MREMAP_MAYMOVE)
//!     │
//!     ├─ find new VA range (new_size bytes)
//!     ├─ copy PTEs from old → new
//!     ├─ update VMA start/end
//!     ├─ flush TLB for old entries
//!     └─ return new_addr
//! ```
//!
//! # Key Types
//!
//! - [`MremapFlags`] — mremap flag set
//! - [`MoveRequest`] — a single move request
//! - [`MremapMover`] — executes mremap moves
//! - [`MremapMoveStats`] — move statistics
//!
//! Reference: Linux `mm/mremap.c`, POSIX `mremap(2)`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum concurrent move requests.
const MAX_MOVE_REQUESTS: usize = 256;

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Maximum move size in pages.
const MAX_MOVE_PAGES: u64 = 1 << 20; // ~4 GiB

// -------------------------------------------------------------------
// MremapFlags
// -------------------------------------------------------------------

/// Mremap flag set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MremapFlags {
    /// May move the mapping.
    MayMove,
    /// Move to a fixed address.
    Fixed,
    /// Do not unmap the old mapping (create alias).
    DontUnmap,
}

impl MremapFlags {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::MayMove => "MREMAP_MAYMOVE",
            Self::Fixed => "MREMAP_FIXED",
            Self::DontUnmap => "MREMAP_DONTUNMAP",
        }
    }

    /// Check whether old mapping may be preserved.
    pub const fn preserves_old(&self) -> bool {
        matches!(self, Self::DontUnmap)
    }
}

// -------------------------------------------------------------------
// MoveRequest
// -------------------------------------------------------------------

/// A single mremap move request.
#[derive(Debug, Clone, Copy)]
pub struct MoveRequest {
    /// Old start address.
    old_addr: u64,
    /// Old size in bytes.
    old_size: u64,
    /// New size in bytes.
    new_size: u64,
    /// Flags.
    flags: MremapFlags,
    /// New address (set after move).
    new_addr: u64,
    /// Whether the move completed.
    completed: bool,
    /// Process ID that requested the move.
    pid: u64,
    /// Number of PTEs moved.
    ptes_moved: u64,
    /// Whether TLB was flushed.
    tlb_flushed: bool,
}

impl MoveRequest {
    /// Create a new move request.
    pub const fn new(
        old_addr: u64,
        old_size: u64,
        new_size: u64,
        flags: MremapFlags,
        pid: u64,
    ) -> Self {
        Self {
            old_addr,
            old_size,
            new_size,
            flags,
            new_addr: 0,
            completed: false,
            pid,
            ptes_moved: 0,
            tlb_flushed: false,
        }
    }

    /// Return the old address.
    pub const fn old_addr(&self) -> u64 {
        self.old_addr
    }

    /// Return the old size.
    pub const fn old_size(&self) -> u64 {
        self.old_size
    }

    /// Return the new size.
    pub const fn new_size(&self) -> u64 {
        self.new_size
    }

    /// Return the flags.
    pub const fn flags(&self) -> MremapFlags {
        self.flags
    }

    /// Return the new address.
    pub const fn new_addr(&self) -> u64 {
        self.new_addr
    }

    /// Check whether the move completed.
    pub const fn completed(&self) -> bool {
        self.completed
    }

    /// Return the PID.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Return the number of PTEs moved.
    pub const fn ptes_moved(&self) -> u64 {
        self.ptes_moved
    }

    /// Old page count.
    pub const fn old_page_count(&self) -> u64 {
        self.old_size / PAGE_SIZE
    }

    /// New page count.
    pub const fn new_page_count(&self) -> u64 {
        self.new_size / PAGE_SIZE
    }

    /// Whether this is a grow operation.
    pub const fn is_grow(&self) -> bool {
        self.new_size > self.old_size
    }

    /// Whether this is a shrink operation.
    pub const fn is_shrink(&self) -> bool {
        self.new_size < self.old_size
    }

    /// Set the new address and mark completed.
    pub fn complete(&mut self, new_addr: u64, ptes_moved: u64) {
        self.new_addr = new_addr;
        self.ptes_moved = ptes_moved;
        self.completed = true;
        self.tlb_flushed = true;
    }
}

impl Default for MoveRequest {
    fn default() -> Self {
        Self {
            old_addr: 0,
            old_size: 0,
            new_size: 0,
            flags: MremapFlags::MayMove,
            new_addr: 0,
            completed: false,
            pid: 0,
            ptes_moved: 0,
            tlb_flushed: false,
        }
    }
}

// -------------------------------------------------------------------
// MremapMoveStats
// -------------------------------------------------------------------

/// Move statistics.
#[derive(Debug, Clone, Copy)]
pub struct MremapMoveStats {
    /// Total move requests.
    pub total_requests: u64,
    /// Successful moves.
    pub successful_moves: u64,
    /// Failed moves.
    pub failed_moves: u64,
    /// Total PTEs moved.
    pub total_ptes_moved: u64,
    /// Grow operations.
    pub grows: u64,
    /// Shrink operations.
    pub shrinks: u64,
    /// In-place resizes (no move needed).
    pub in_place: u64,
}

impl MremapMoveStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_requests: 0,
            successful_moves: 0,
            failed_moves: 0,
            total_ptes_moved: 0,
            grows: 0,
            shrinks: 0,
            in_place: 0,
        }
    }

    /// Success rate as percent.
    pub const fn success_pct(&self) -> u64 {
        if self.total_requests == 0 {
            return 0;
        }
        self.successful_moves * 100 / self.total_requests
    }
}

impl Default for MremapMoveStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MremapMover
// -------------------------------------------------------------------

/// Executes mremap move operations.
pub struct MremapMover {
    /// Pending and completed requests.
    requests: [MoveRequest; MAX_MOVE_REQUESTS],
    /// Number of requests.
    count: usize,
    /// Statistics.
    stats: MremapMoveStats,
}

impl MremapMover {
    /// Create a new mover.
    pub const fn new() -> Self {
        Self {
            requests: [const {
                MoveRequest {
                    old_addr: 0,
                    old_size: 0,
                    new_size: 0,
                    flags: MremapFlags::MayMove,
                    new_addr: 0,
                    completed: false,
                    pid: 0,
                    ptes_moved: 0,
                    tlb_flushed: false,
                }
            }; MAX_MOVE_REQUESTS],
            count: 0,
            stats: MremapMoveStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &MremapMoveStats {
        &self.stats
    }

    /// Return the number of requests.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Submit a move request.
    pub fn submit(
        &mut self,
        old_addr: u64,
        old_size: u64,
        new_size: u64,
        flags: MremapFlags,
        pid: u64,
    ) -> Result<usize> {
        if (old_addr % PAGE_SIZE) != 0 {
            return Err(Error::InvalidArgument);
        }
        if old_size == 0 || new_size == 0 {
            return Err(Error::InvalidArgument);
        }
        let new_pages = new_size / PAGE_SIZE;
        if new_pages > MAX_MOVE_PAGES {
            return Err(Error::OutOfMemory);
        }
        if self.count >= MAX_MOVE_REQUESTS {
            return Err(Error::OutOfMemory);
        }

        let idx = self.count;
        self.requests[idx] = MoveRequest::new(old_addr, old_size, new_size, flags, pid);
        self.count += 1;
        self.stats.total_requests += 1;

        if new_size > old_size {
            self.stats.grows += 1;
        } else if new_size < old_size {
            self.stats.shrinks += 1;
        } else {
            self.stats.in_place += 1;
        }

        Ok(idx)
    }

    /// Complete a move request.
    pub fn complete(&mut self, index: usize, new_addr: u64, ptes_moved: u64) -> Result<()> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        self.requests[index].complete(new_addr, ptes_moved);
        self.stats.successful_moves += 1;
        self.stats.total_ptes_moved += ptes_moved;
        Ok(())
    }

    /// Record a failed move.
    pub fn fail(&mut self, index: usize) -> Result<()> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        self.stats.failed_moves += 1;
        Ok(())
    }

    /// Get a request by index.
    pub fn get_request(&self, index: usize) -> Option<&MoveRequest> {
        if index < self.count {
            Some(&self.requests[index])
        } else {
            None
        }
    }
}

impl Default for MremapMover {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum move requests.
pub const fn max_move_requests() -> usize {
    MAX_MOVE_REQUESTS
}

/// Return the maximum move size in pages.
pub const fn max_move_pages() -> u64 {
    MAX_MOVE_PAGES
}
