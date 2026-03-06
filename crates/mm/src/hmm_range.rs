// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! HMM (Heterogeneous Memory Management) range fault handling.
//!
//! Provides the mechanism for device drivers to fault in page-table
//! entries for a given virtual address range. The driver describes the
//! range it needs, and the HMM range fault engine walks the CPU page
//! tables, populates missing entries (triggering page faults if needed),
//! and returns an array of PFNs annotated with permission flags that
//! the device can install into its own page tables.
//!
//! # Design
//!
//! ```text
//!  Driver                  HMM Core              CPU Page Tables
//! ┌──────┐  hmm_range_   ┌──────────┐  walk   ┌──────────────┐
//! │      │──fault()──────▶│ HmmRange │────────▶│  PTE entries │
//! │      │               │          │◀────────│  (faulted in)│
//! │      │◀──pfns[]──────│          │          └──────────────┘
//! └──────┘               └──────────┘
//! ```
//!
//! # Key Types
//!
//! - [`HmmPfnFlags`] — flags describing PFN state (valid, write, device-private)
//! - [`HmmRange`] — a range request with virtual start/end and PFN output
//! - [`HmmRangeResult`] — result of a range fault operation
//!
//! Reference: Linux `mm/hmm.c`, `include/linux/hmm.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size.
const PAGE_SIZE: u64 = 4096;

/// Maximum number of pages in a single HMM range fault.
const MAX_RANGE_PAGES: usize = 1024;

// -------------------------------------------------------------------
// HmmPfnFlags
// -------------------------------------------------------------------

/// Flags annotating a PFN returned by HMM range fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HmmPfnFlags(u64);

impl HmmPfnFlags {
    /// The PFN is valid (page is present in RAM).
    pub const VALID: u64 = 1 << 0;
    /// The page is writable.
    pub const WRITE: u64 = 1 << 1;
    /// The page is device-private memory.
    pub const DEVICE_PRIVATE: u64 = 1 << 2;
    /// The page requires a fault to populate.
    pub const FAULT: u64 = 1 << 3;
    /// Compound/huge page.
    pub const COMPOUND: u64 = 1 << 4;

    /// Creates empty flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Creates flags from raw bits.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Returns the raw bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns `true` if the given flag is set.
    pub const fn contains(self, flag: u64) -> bool {
        (self.0 & flag) != 0
    }

    /// Sets a flag.
    pub fn set(&mut self, flag: u64) {
        self.0 |= flag;
    }

    /// Clears a flag.
    pub fn clear(&mut self, flag: u64) {
        self.0 &= !flag;
    }
}

impl Default for HmmPfnFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// HmmPfnEntry
// -------------------------------------------------------------------

/// A single PFN entry with associated flags.
#[derive(Debug, Clone, Copy)]
pub struct HmmPfnEntry {
    /// Physical frame number (page-aligned address >> 12).
    pfn: u64,
    /// Flags describing the PFN state.
    flags: HmmPfnFlags,
}

impl HmmPfnEntry {
    /// Creates a new PFN entry.
    pub const fn new(pfn: u64, flags: HmmPfnFlags) -> Self {
        Self { pfn, flags }
    }

    /// Creates an empty (invalid) PFN entry.
    pub const fn empty() -> Self {
        Self {
            pfn: 0,
            flags: HmmPfnFlags::empty(),
        }
    }

    /// Returns the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Returns the flags.
    pub const fn flags(&self) -> HmmPfnFlags {
        self.flags
    }

    /// Returns `true` if this entry is valid.
    pub const fn is_valid(&self) -> bool {
        self.flags.contains(HmmPfnFlags::VALID)
    }

    /// Returns `true` if writable.
    pub const fn is_writable(&self) -> bool {
        self.flags.contains(HmmPfnFlags::WRITE)
    }
}

impl Default for HmmPfnEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// HmmRange
// -------------------------------------------------------------------

/// Describes a virtual address range for HMM fault processing.
pub struct HmmRange {
    /// Start virtual address (page-aligned).
    start: u64,
    /// End virtual address (exclusive, page-aligned).
    end: u64,
    /// Whether write access is required.
    write: bool,
    /// PFN output array.
    pfns: [HmmPfnEntry; MAX_RANGE_PAGES],
    /// Number of pages in this range.
    nr_pages: usize,
    /// Sequence counter for invalidation detection.
    sequence: u64,
    /// Whether the range has been faulted.
    faulted: bool,
}

impl HmmRange {
    /// Creates a new HMM range for the given virtual addresses.
    pub const fn new(start: u64, end: u64, write: bool) -> Self {
        Self {
            start,
            end,
            write,
            pfns: [const { HmmPfnEntry::empty() }; MAX_RANGE_PAGES],
            nr_pages: 0,
            sequence: 0,
            faulted: false,
        }
    }

    /// Returns the start address.
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Returns the end address.
    pub const fn end(&self) -> u64 {
        self.end
    }

    /// Returns the number of pages.
    pub const fn nr_pages(&self) -> usize {
        self.nr_pages
    }

    /// Returns the PFN entries.
    pub fn pfns(&self) -> &[HmmPfnEntry] {
        &self.pfns[..self.nr_pages]
    }

    /// Returns whether this range has been faulted in.
    pub const fn is_faulted(&self) -> bool {
        self.faulted
    }

    /// Returns the sequence counter.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Validates the range parameters.
    pub fn validate(&self) -> Result<()> {
        if self.start >= self.end {
            return Err(Error::InvalidArgument);
        }
        if (self.start % PAGE_SIZE) != 0 || (self.end % PAGE_SIZE) != 0 {
            return Err(Error::InvalidArgument);
        }
        let pages = ((self.end - self.start) / PAGE_SIZE) as usize;
        if pages > MAX_RANGE_PAGES {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for HmmRange {
    fn default() -> Self {
        Self::new(0, PAGE_SIZE, false)
    }
}

// -------------------------------------------------------------------
// HmmRangeResult
// -------------------------------------------------------------------

/// Result of a range fault operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmmRangeResult {
    /// All pages successfully faulted in.
    Success,
    /// Some pages could not be faulted (need retry).
    NeedRetry,
    /// The mmap lock was invalidated during the walk.
    Invalidated,
    /// An error occurred.
    Failed,
}

impl Default for HmmRangeResult {
    fn default() -> Self {
        Self::Success
    }
}

// -------------------------------------------------------------------
// HmmRangeState
// -------------------------------------------------------------------

/// Tracks the state of range fault processing.
#[derive(Debug)]
pub struct HmmRangeState {
    /// Current page index being processed.
    current_page: usize,
    /// Total pages to process.
    total_pages: usize,
    /// Pages successfully faulted.
    faulted_count: usize,
    /// Pages that need retry.
    retry_count: usize,
    /// Overall result.
    result: HmmRangeResult,
}

impl HmmRangeState {
    /// Creates a new range fault state.
    pub const fn new(total_pages: usize) -> Self {
        Self {
            current_page: 0,
            total_pages,
            faulted_count: 0,
            retry_count: 0,
            result: HmmRangeResult::Success,
        }
    }

    /// Returns the overall result.
    pub const fn result(&self) -> HmmRangeResult {
        self.result
    }

    /// Returns the number of faulted pages.
    pub const fn faulted_count(&self) -> usize {
        self.faulted_count
    }

    /// Records a successfully faulted page.
    pub fn record_success(&mut self) {
        self.faulted_count += 1;
        self.current_page += 1;
    }

    /// Records a page needing retry.
    pub fn record_retry(&mut self) {
        self.retry_count += 1;
        self.current_page += 1;
        self.result = HmmRangeResult::NeedRetry;
    }
}

impl Default for HmmRangeState {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates and validates an HMM range request.
pub fn create_range(start: u64, end: u64, write: bool) -> Result<HmmRange> {
    let range = HmmRange::new(start, end, write);
    range.validate()?;
    Ok(range)
}

/// Performs a range fault, populating PFN entries.
///
/// In a real implementation this walks CPU page tables; here we
/// simulate by marking pages as needing fault or valid.
pub fn range_fault(range: &mut HmmRange) -> Result<HmmRangeResult> {
    range.validate()?;
    let nr_pages = ((range.end - range.start) / PAGE_SIZE) as usize;
    range.nr_pages = nr_pages;

    let mut state = HmmRangeState::new(nr_pages);

    for i in 0..nr_pages {
        let vaddr = range.start + (i as u64) * PAGE_SIZE;
        // Simulate: generate a PFN from the virtual address.
        let pfn = vaddr / PAGE_SIZE;
        let mut flags = HmmPfnFlags::from_bits(HmmPfnFlags::VALID);
        if range.write {
            flags.set(HmmPfnFlags::WRITE);
        }
        range.pfns[i] = HmmPfnEntry::new(pfn, flags);
        state.record_success();
    }

    range.faulted = true;
    range.sequence = range.sequence.wrapping_add(1);
    Ok(state.result())
}

/// Checks if a range needs to be re-faulted (e.g., after invalidation).
pub fn range_needs_refault(range: &HmmRange, current_seq: u64) -> bool {
    !range.faulted || range.sequence != current_seq
}
