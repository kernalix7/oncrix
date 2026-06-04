// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mprotect` syscall handler.
//!
//! Implements `mprotect(2)` per POSIX.1-2024.
//! Changes the access protection on pages in the range `[addr, addr+len)`.
//! VMAs that partially overlap the range are split at the boundaries, and
//! page table entries are updated with the new protection bits.
//!
//! # References
//!
//! - POSIX.1-2024: `mprotect()`
//! - Linux man pages: `mprotect(2)`

use oncrix_lib::{Error, Result};
use oncrix_mm::address_space::{USER_SPACE_END, USER_SPACE_START};

// ---------------------------------------------------------------------------
// Page size
// ---------------------------------------------------------------------------

/// Default system page size (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Page offset mask.
const PAGE_MASK: u64 = PAGE_SIZE - 1;

// ---------------------------------------------------------------------------
// Protection flags (PROT_*)
// ---------------------------------------------------------------------------

/// Pages may not be accessed.
pub const PROT_NONE: u32 = 0x0;
/// Pages may be read.
pub const PROT_READ: u32 = 0x1;
/// Pages may be written.
pub const PROT_WRITE: u32 = 0x2;
/// Pages may be executed.
pub const PROT_EXEC: u32 = 0x4;

/// Mask of all valid PROT_ bits.
const PROT_VALID: u32 = PROT_READ | PROT_WRITE | PROT_EXEC;

// ---------------------------------------------------------------------------
// VmaProtEntry — per-VMA protection update record
// ---------------------------------------------------------------------------

/// A record describing a pending protection change on a VMA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmaProtEntry {
    /// Start address of the VMA segment to update.
    pub start: u64,
    /// End address (exclusive) of the VMA segment.
    pub end: u64,
    /// New protection flags to apply.
    pub new_prot: u32,
    /// Previous protection flags (for potential rollback).
    pub old_prot: u32,
}

impl VmaProtEntry {
    /// Construct a new `VmaProtEntry`.
    pub const fn new(start: u64, end: u64, new_prot: u32, old_prot: u32) -> Self {
        Self {
            start,
            end,
            new_prot,
            old_prot,
        }
    }

    /// Return the length of this segment in bytes.
    pub const fn length(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Return the number of pages in this segment.
    pub const fn page_count(&self) -> u64 {
        self.length() / PAGE_SIZE
    }
}

// ---------------------------------------------------------------------------
// ProtRange — a validated mprotect range
// ---------------------------------------------------------------------------

/// A validated address range for `mprotect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtRange {
    /// Start address (page-aligned).
    pub addr: u64,
    /// Length in bytes (page-aligned, non-zero).
    pub length: u64,
    /// New protection to apply.
    pub prot: u32,
}

impl ProtRange {
    /// Construct and validate a `ProtRange`.
    ///
    /// Returns `Err(InvalidArgument)` if:
    /// - `addr` is not page-aligned.
    /// - `length` is zero or overflows.
    /// - `prot` contains invalid bits.
    pub fn new(addr: u64, length: u64, prot: u32) -> Result<Self> {
        if addr & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if length == 0 {
            return Err(Error::InvalidArgument);
        }
        if prot != PROT_NONE && prot & !PROT_VALID != 0 {
            return Err(Error::InvalidArgument);
        }
        // `length` is attacker-controlled: a huge value must not round up to
        // `0` (which would make an empty range validate) or overflow `u64`.
        let aligned_len = align_up(length).ok_or(Error::InvalidArgument)?;
        if aligned_len == 0 {
            return Err(Error::InvalidArgument);
        }
        let end = addr
            .checked_add(aligned_len)
            .ok_or(Error::InvalidArgument)?;
        // Confine the whole range to the canonical lower-half user window;
        // a kernel-half or non-canonical `addr` is rejected before any walk.
        if addr < USER_SPACE_START || end > USER_SPACE_END + 1 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            addr,
            length: aligned_len,
            prot,
        })
    }

    /// Return the exclusive end address of this range.
    ///
    /// Uses `saturating_add` so the method is locally sound even though
    /// [`ProtRange::new`] already bounds `addr + length` to the user
    /// window: a bare `+` could panic under debug overflow-checks (a
    /// ring-0 fault halts the machine). For every range `new` accepts the
    /// sum is `<= USER_SPACE_END + 1`, so saturation never changes the
    /// returned value.
    pub const fn end(&self) -> u64 {
        self.addr.saturating_add(self.length)
    }
}

// ---------------------------------------------------------------------------
// MprotResult — outcome
// ---------------------------------------------------------------------------

/// Result of a successful `mprotect` call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MprotResult {
    /// Number of page table entries updated.
    pub ptes_updated: u64,
    /// Number of VMA segments split at range boundaries.
    pub vmas_split: u32,
}

// ---------------------------------------------------------------------------
// VmaEntry — simplified VMA for testing
// ---------------------------------------------------------------------------

/// Simplified VMA representation for mprotect simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmaEntry {
    /// Inclusive start address.
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
    /// Current protection flags.
    pub prot: u32,
}

impl VmaEntry {
    /// Construct a new `VmaEntry`.
    pub const fn new(start: u64, end: u64, prot: u32) -> Self {
        Self { start, end, prot }
    }

    /// Return `true` if the VMA overlaps with `[addr, addr+len)`.
    pub fn overlaps_range(&self, addr: u64, len: u64) -> bool {
        let end = addr.saturating_add(len);
        self.start < end && self.end > addr
    }

    /// Compute the overlap between this VMA and the given range.
    ///
    /// Returns `(overlap_start, overlap_end)` or `None` if no overlap.
    pub fn compute_overlap(&self, range: &ProtRange) -> Option<(u64, u64)> {
        if !self.overlaps_range(range.addr, range.length) {
            return None;
        }
        let os = self.start.max(range.addr);
        let oe = self.end.min(range.end());
        if os < oe { Some((os, oe)) } else { None }
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Align `n` up to the next page boundary.
///
/// Returns [`None`] on overflow. Using `checked_add` (not `wrapping_add`)
/// stops a near-`u64::MAX` length from wrapping to `0` and making an empty
/// range pass validation.
fn align_up(n: u64) -> Option<u64> {
    n.checked_add(PAGE_SIZE - 1).map(|v| v & !PAGE_MASK)
}

// ---------------------------------------------------------------------------
// Public syscall handlers
// ---------------------------------------------------------------------------

/// `mprotect` — change access protection for memory pages.
///
/// Updates the protection of all pages in `[addr, addr+length)` to `prot`.
/// VMAs that straddle the range boundaries are conceptually split; only
/// the pages within the range change protection.
///
/// `addr` must be page-aligned and `length` is rounded up to a page
/// boundary. `prot` must be `PROT_NONE` or a combination of valid
/// `PROT_*` bits.
///
/// Returns a summary of PTEs updated and VMAs split.
///
/// # Errors
///
/// | `Error`           | Condition                                       |
/// |-------------------|-------------------------------------------------|
/// | `InvalidArgument` | `addr` not page-aligned, `length` zero/overflow |
/// | `InvalidArgument` | `prot` contains invalid bits                    |
/// | `NotFound`        | Range not covered by any mapping                |
///
/// Reference: POSIX.1-2024 §mprotect.
pub fn do_mprotect(addr: u64, length: u64, prot: u32, vmas: &[VmaEntry]) -> Result<MprotResult> {
    let range = ProtRange::new(addr, length, prot)?;

    // No mappings at all means the range is unmapped: POSIX requires ENOMEM
    // here. An empty slice must not silently succeed.
    if vmas.is_empty() {
        return Err(Error::NotFound);
    }

    let mut result = MprotResult::default();
    let mut covered = false;

    for vma in vmas {
        if let Some((os, oe)) = vma.compute_overlap(&range) {
            covered = true;
            let pages = (oe - os) / PAGE_SIZE;
            result.ptes_updated += pages;

            // Count splits: left boundary inside VMA, right boundary inside VMA.
            if os > vma.start {
                result.vmas_split += 1;
            }
            if oe < vma.end {
                result.vmas_split += 1;
            }
        }
    }

    if !covered {
        return Err(Error::NotFound);
    }

    // Stub: real implementation walks the page tables, updates PTE permission
    // bits, and calls flush_tlb_range() to propagate changes.
    Ok(result)
}

/// Validate `mprotect` arguments without applying the protection change.
pub fn validate_mprotect_args(addr: u64, length: u64, prot: u32) -> Result<()> {
    let _ = ProtRange::new(addr, length, prot)?;
    Ok(())
}

/// Compute the page-count for a given address range.
pub fn page_count_for_range(addr: u64, length: u64) -> Result<u64> {
    if addr & PAGE_MASK != 0 || length == 0 {
        return Err(Error::InvalidArgument);
    }
    let aligned = align_up(length).ok_or(Error::InvalidArgument)?;
    Ok(aligned / PAGE_SIZE)
}
