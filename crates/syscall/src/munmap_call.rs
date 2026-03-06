// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `munmap` syscall handler.
//!
//! Implements `munmap(2)` per POSIX.1-2024.
//! `munmap` removes a mapping from the process's address space.
//! If the specified range covers only part of a VMA, the VMA is split.
//! TLB entries for the unmapped range must be invalidated.
//!
//! # References
//!
//! - POSIX.1-2024: `munmap()`
//! - Linux man pages: `munmap(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Page size
// ---------------------------------------------------------------------------

/// Default system page size (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Page offset mask.
const PAGE_MASK: u64 = PAGE_SIZE - 1;

// ---------------------------------------------------------------------------
// VMA — Virtual Memory Area descriptor
// ---------------------------------------------------------------------------

/// A virtual memory area describing a contiguous mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vma {
    /// Inclusive start address of the mapping (page-aligned).
    pub start: u64,
    /// Exclusive end address of the mapping (page-aligned).
    pub end: u64,
    /// Memory protection flags (`PROT_*`).
    pub prot: u32,
    /// Mapping flags (`MAP_*`).
    pub flags: u32,
}

impl Vma {
    /// Construct a new `Vma`.
    ///
    /// Returns `Err(InvalidArgument)` if the addresses are not page-aligned
    /// or if `start >= end`.
    pub fn new(start: u64, end: u64, prot: u32, flags: u32) -> Result<Self> {
        if start & PAGE_MASK != 0 || end & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if start >= end {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            start,
            end,
            prot,
            flags,
        })
    }

    /// Return the length of this VMA in bytes.
    pub const fn length(&self) -> u64 {
        self.end - self.start
    }

    /// Return `true` if the VMA overlaps with `[addr, addr+len)`.
    pub fn overlaps(&self, addr: u64, len: u64) -> bool {
        let range_end = addr.saturating_add(len);
        self.start < range_end && self.end > addr
    }

    /// Return `true` if the VMA is fully contained within `[addr, addr+len)`.
    pub fn fully_within(&self, addr: u64, len: u64) -> bool {
        let range_end = addr.saturating_add(len);
        self.start >= addr && self.end <= range_end
    }
}

// ---------------------------------------------------------------------------
// UnmapRange — describes a munmap request
// ---------------------------------------------------------------------------

/// A validated address range for `munmap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnmapRange {
    /// Start address (page-aligned).
    pub addr: u64,
    /// Length in bytes (page-aligned, non-zero).
    pub length: u64,
}

impl UnmapRange {
    /// Construct and validate an `UnmapRange`.
    ///
    /// Returns `Err(InvalidArgument)` if:
    /// - `addr` is not page-aligned.
    /// - `length` is zero.
    /// - `addr + length` would overflow.
    pub fn new(addr: u64, length: u64) -> Result<Self> {
        if addr & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if length == 0 {
            return Err(Error::InvalidArgument);
        }
        let aligned_len = align_up(length);
        if addr.checked_add(aligned_len).is_none() {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            addr,
            length: aligned_len,
        })
    }

    /// Return the exclusive end address of this range.
    pub const fn end(&self) -> u64 {
        self.addr + self.length
    }
}

// ---------------------------------------------------------------------------
// SplitAction — describes how to handle a partially-overlapping VMA
// ---------------------------------------------------------------------------

/// What to do with a VMA that partially overlaps the unmap range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitAction {
    /// Trim the left portion of the VMA (set new start).
    TrimLeft {
        /// New start address.
        new_start: u64,
    },
    /// Trim the right portion of the VMA (set new end).
    TrimRight {
        /// New end address.
        new_end: u64,
    },
    /// Split the VMA into two pieces (range punches a hole in the middle).
    Split {
        /// End address of the left piece.
        left_end: u64,
        /// Start address of the right piece.
        right_start: u64,
    },
}

/// Determine how a VMA should be split for an unmap range.
///
/// Returns `None` if the VMA is fully within the unmap range (remove it).
pub fn compute_split(vma: &Vma, range: &UnmapRange) -> Option<SplitAction> {
    let range_end = range.end();

    // Fully contained: remove entirely.
    if vma.fully_within(range.addr, range.length) {
        return None;
    }

    let left_overlap = vma.start < range.addr && vma.end > range.addr;
    let right_overlap = vma.start < range_end && vma.end > range_end;

    if left_overlap && right_overlap {
        // Range punches a hole in the VMA.
        return Some(SplitAction::Split {
            left_end: range.addr,
            right_start: range_end,
        });
    }
    if left_overlap {
        // Unmap the right part of the VMA.
        return Some(SplitAction::TrimRight {
            new_end: range.addr,
        });
    }
    if right_overlap {
        // Unmap the left part of the VMA.
        return Some(SplitAction::TrimLeft {
            new_start: range_end,
        });
    }

    // No overlap (should not be reached if caller pre-filtered).
    None
}

// ---------------------------------------------------------------------------
// UnmapResult — outcome
// ---------------------------------------------------------------------------

/// Result of a `munmap` call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnmapResult {
    /// Number of pages that were unmapped.
    pub pages_freed: u64,
    /// Number of VMAs that were modified (split or trimmed).
    pub vmas_modified: u32,
    /// Number of VMAs that were removed entirely.
    pub vmas_removed: u32,
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Align `n` up to the next page boundary.
fn align_up(n: u64) -> u64 {
    n.wrapping_add(PAGE_SIZE - 1) & !PAGE_MASK
}

// ---------------------------------------------------------------------------
// Public syscall handlers
// ---------------------------------------------------------------------------

/// `munmap` — unmap memory from the process's address space.
///
/// Removes all pages in `[addr, addr+length)` from the process mapping.
/// VMAs that partially overlap the range are split or trimmed. After the
/// unmap, TLB entries for the affected range must be invalidated.
///
/// `addr` must be page-aligned. `length` is rounded up to the next page
/// boundary.
///
/// Returns a summary of the pages and VMAs affected.
///
/// # Errors
///
/// | `Error`           | Condition                                  |
/// |-------------------|--------------------------------------------|
/// | `InvalidArgument` | `addr` is not page-aligned                 |
/// | `InvalidArgument` | `length` is zero or `addr+length` overflows|
///
/// Reference: POSIX.1-2024 §munmap.
pub fn do_munmap(addr: u64, length: u64, vmas: &mut [Vma]) -> Result<UnmapResult> {
    let range = UnmapRange::new(addr, length)?;

    let mut result = UnmapResult::default();

    for vma in vmas.iter() {
        if !vma.overlaps(range.addr, range.length) {
            continue;
        }
        match compute_split(vma, &range) {
            None => {
                result.vmas_removed += 1;
                result.pages_freed += vma.length() / PAGE_SIZE;
            }
            Some(SplitAction::TrimLeft { new_start }) => {
                let freed = new_start.saturating_sub(vma.start) / PAGE_SIZE;
                result.pages_freed += freed;
                result.vmas_modified += 1;
            }
            Some(SplitAction::TrimRight { new_end }) => {
                let freed = vma.end.saturating_sub(new_end) / PAGE_SIZE;
                result.pages_freed += freed;
                result.vmas_modified += 1;
            }
            Some(SplitAction::Split {
                left_end,
                right_start,
            }) => {
                let freed = right_start.saturating_sub(left_end) / PAGE_SIZE;
                result.pages_freed += freed;
                result.vmas_modified += 1;
            }
        }
    }

    // Stub: real implementation also removes/updates VMAs in the mm_struct
    // and calls flush_tlb_range() to invalidate TLB entries.
    Ok(result)
}

/// Validate `munmap` arguments without performing the unmap.
pub fn validate_munmap_args(addr: u64, length: u64) -> Result<()> {
    let _ = UnmapRange::new(addr, length)?;
    Ok(())
}
