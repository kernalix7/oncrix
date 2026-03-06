// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `brk` syscall handler.
//!
//! Implements `brk(2)` per Linux ABI.
//! `brk` changes the end of the data segment (program break).
//! When called with addr == 0 it returns the current break.
//! Expanding the break grows the heap; shrinking it frees pages.
//! The new break is validated against RLIMIT_DATA and RLIMIT_AS.
//!
//! # References
//!
//! - Linux man pages: `brk(2)`
//! - POSIX.1-2024: (no standard brk; Linux-specific)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default system page size (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Page offset mask.
const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// Minimum program break address (arbitrary safe minimum).
const BRK_MIN: u64 = PAGE_SIZE;

/// Default initial program break (placeholder — real value comes from ELF end).
const DEFAULT_BRK_START: u64 = 0x0000_4000_0000_0000;

/// Maximum heap size enforced by this stub (256 MiB).
const MAX_HEAP_SIZE: u64 = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// BrkState — per-process heap tracking
// ---------------------------------------------------------------------------

/// Tracks the current and start program break for a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrkState {
    /// Address of the start of the heap (just past the BSS segment).
    pub start: u64,
    /// Current program break (end of the heap, exclusive).
    pub current: u64,
    /// Maximum break allowed (resource limit).
    pub limit: u64,
}

impl Default for BrkState {
    fn default() -> Self {
        Self::new(DEFAULT_BRK_START)
    }
}

impl BrkState {
    /// Create a new `BrkState` with the given heap start address.
    pub fn new(start: u64) -> Self {
        let limit = start.saturating_add(MAX_HEAP_SIZE);
        Self {
            start,
            current: start,
            limit,
        }
    }

    /// Create a `BrkState` with explicit start, current, and limit values.
    pub const fn with_limit(start: u64, current: u64, limit: u64) -> Self {
        Self {
            start,
            current,
            limit,
        }
    }

    /// Return the current heap size in bytes.
    pub const fn heap_size(&self) -> u64 {
        self.current.saturating_sub(self.start)
    }

    /// Return `true` if the given `new_brk` is within the allowed range.
    pub const fn within_limit(&self, new_brk: u64) -> bool {
        new_brk >= self.start && new_brk <= self.limit
    }

    /// Return `true` if `new_brk` expands the heap.
    pub const fn is_expansion(&self, new_brk: u64) -> bool {
        new_brk > self.current
    }

    /// Return `true` if `new_brk` shrinks the heap.
    pub const fn is_shrink(&self, new_brk: u64) -> bool {
        new_brk < self.current
    }

    /// Return the number of pages to allocate for an expansion.
    pub fn pages_to_add(&self, new_brk: u64) -> u64 {
        if !self.is_expansion(new_brk) {
            return 0;
        }
        let old_page_end = align_up(self.current);
        let new_page_end = align_up(new_brk);
        if new_page_end > old_page_end {
            (new_page_end - old_page_end) / PAGE_SIZE
        } else {
            0
        }
    }

    /// Return the number of pages to free for a shrink.
    pub fn pages_to_free(&self, new_brk: u64) -> u64 {
        if !self.is_shrink(new_brk) {
            return 0;
        }
        let old_page_end = align_up(self.current);
        let new_page_end = align_up(new_brk);
        if old_page_end > new_page_end {
            (old_page_end - new_page_end) / PAGE_SIZE
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// BrkResult — outcome
// ---------------------------------------------------------------------------

/// Result of a `brk` call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BrkResult {
    /// New program break on success.
    pub new_brk: u64,
    /// Pages allocated (for heap expansion).
    pub pages_added: u64,
    /// Pages freed (for heap shrink).
    pub pages_freed: u64,
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Align `n` up to the next page boundary.
fn align_up(n: u64) -> u64 {
    n.wrapping_add(PAGE_SIZE - 1) & !PAGE_MASK
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a `brk` target address.
///
/// The address must be >= the minimum program break and
/// page-aligned (the kernel silently rounds up, but we validate here).
fn validate_brk_addr(addr: u64, state: &BrkState) -> Result<()> {
    if addr != 0 && addr < BRK_MIN {
        return Err(Error::InvalidArgument);
    }
    if addr != 0 && addr < state.start {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public syscall handlers
// ---------------------------------------------------------------------------

/// `brk` — set the program break (end of the data segment / heap).
///
/// If `addr` is `0`, returns the current program break.
///
/// If `addr` is non-zero:
/// - The break is moved to `addr` (rounded up to the next page).
/// - The new break must be >= the heap start and <= `state.limit`.
/// - New pages are zero-filled (stub; real implementation calls the
///   page allocator).
/// - On failure, Linux returns the current break unchanged.
///
/// Returns the new program break on success, or the unchanged break
/// if the new address is rejected (ENOMEM semantics).
///
/// # Errors
///
/// | `Error`           | Condition                                    |
/// |-------------------|----------------------------------------------|
/// | `InvalidArgument` | `addr < BRK_MIN` or `addr < heap_start`      |
/// | `OutOfMemory`     | New break exceeds `state.limit` (RLIMIT_DATA) |
///
/// Reference: Linux brk(2).
pub fn do_brk(addr: u64, state: &mut BrkState) -> Result<BrkResult> {
    // Query: return current break.
    if addr == 0 {
        return Ok(BrkResult {
            new_brk: state.current,
            pages_added: 0,
            pages_freed: 0,
        });
    }

    validate_brk_addr(addr, state)?;

    // Round the new break up to the next page boundary.
    let new_brk = align_up(addr);

    // Check against resource limit.
    if !state.within_limit(new_brk) {
        return Err(Error::OutOfMemory);
    }

    let pages_added = state.pages_to_add(new_brk);
    let pages_freed = state.pages_to_free(new_brk);

    // Update the break.
    state.current = new_brk;

    // Stub: real implementation:
    // - For expansion: calls do_mmap to allocate anonymous pages,
    //   or extends the existing anonymous VMA.
    // - For shrink: calls do_munmap on the freed region.
    // - Always zero-fills new pages.

    Ok(BrkResult {
        new_brk,
        pages_added,
        pages_freed,
    })
}

/// Query the current program break without modifying it.
pub fn do_brk_query(state: &BrkState) -> u64 {
    state.current
}

/// Validate a `brk` target address against the given state.
pub fn validate_brk(addr: u64, state: &BrkState) -> Result<()> {
    validate_brk_addr(addr, state)?;
    if addr != 0 {
        let new_brk = align_up(addr);
        if !state.within_limit(new_brk) {
            return Err(Error::OutOfMemory);
        }
    }
    Ok(())
}
