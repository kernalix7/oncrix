// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mincore` syscall handler.
//!
//! Implements `mincore(2)` per Linux ABI.
//! `mincore` determines whether pages in a given address range are
//! present in physical memory (resident). For each page, a byte is
//! written to a user-space vector: bit 0 set means the page is resident.
//!
//! Both anonymous and file-backed pages are handled:
//! - Anonymous: resident if the page has been faulted in.
//! - File-backed: resident if the page is in the page cache.
//!
//! # References
//!
//! - Linux man pages: `mincore(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Page size
// ---------------------------------------------------------------------------

/// Default system page size (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Page offset mask.
const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// Bit flag in the mincore vec byte indicating a page is resident.
pub const MINCORE_RESIDENT: u8 = 1;

/// Maximum range that may be checked in a single call (128 MiB).
const MINCORE_MAX_RANGE: u64 = 128 * 1024 * 1024;

// ---------------------------------------------------------------------------
// MincoreArgs — validated parameter bundle
// ---------------------------------------------------------------------------

/// Validated arguments for `mincore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MincoreArgs {
    /// Start address (must be page-aligned).
    pub addr: u64,
    /// Length of the range in bytes.
    pub length: u64,
    /// Number of pages in the range.
    pub page_count: usize,
}

impl MincoreArgs {
    /// Construct and validate `MincoreArgs`.
    ///
    /// Returns `Err(InvalidArgument)` when:
    /// - `addr` is not page-aligned.
    /// - `length` is zero.
    /// - `addr + length` would overflow.
    /// - The range exceeds `MINCORE_MAX_RANGE`.
    pub fn new(addr: u64, length: u64) -> Result<Self> {
        if addr & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if length == 0 {
            return Err(Error::InvalidArgument);
        }
        let aligned_len = align_up(length);
        addr.checked_add(aligned_len)
            .ok_or(Error::InvalidArgument)?;
        if aligned_len > MINCORE_MAX_RANGE {
            return Err(Error::InvalidArgument);
        }
        let page_count = (aligned_len / PAGE_SIZE) as usize;
        Ok(Self {
            addr,
            length: aligned_len,
            page_count,
        })
    }

    /// Return the address of the Nth page in the range.
    pub fn page_addr(&self, n: usize) -> u64 {
        self.addr + (n as u64) * PAGE_SIZE
    }

    /// Return the exclusive end address of the range.
    pub const fn end(&self) -> u64 {
        self.addr + self.length
    }
}

// ---------------------------------------------------------------------------
// PageResidency — per-page residency status
// ---------------------------------------------------------------------------

/// Residency status for a single page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageResidency {
    /// The page is present in physical memory.
    Resident,
    /// The page is not present (swapped out or never faulted in).
    NotResident,
    /// The address range is not mapped.
    Unmapped,
}

impl PageResidency {
    /// Convert to the mincore vec byte (bit 0 = resident).
    pub const fn to_vec_byte(&self) -> u8 {
        match self {
            PageResidency::Resident => MINCORE_RESIDENT,
            PageResidency::NotResident => 0,
            PageResidency::Unmapped => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// PageTableWalker — simulated page table query
// ---------------------------------------------------------------------------

/// Simulated page table walker for mincore.
///
/// A production implementation walks the hardware page tables to check
/// the Present bit in each PTE. This abstraction allows testing without
/// hardware page tables.
pub struct PageTableWalker<'a> {
    /// Residency information for each page address.
    entries: &'a [(u64, PageResidency)],
}

impl<'a> PageTableWalker<'a> {
    /// Construct from a sorted array of `(page_addr, residency)` pairs.
    pub fn new(entries: &'a [(u64, PageResidency)]) -> Self {
        Self { entries }
    }

    /// Query the residency of a single page.
    pub fn query(&self, page_addr: u64) -> PageResidency {
        // Linear search; production code uses the page table directly.
        for (addr, res) in self.entries {
            if *addr == page_addr {
                return *res;
            }
        }
        PageResidency::Unmapped
    }
}

// ---------------------------------------------------------------------------
// MincoreResult — outcome
// ---------------------------------------------------------------------------

/// Result of a successful `mincore` call.
#[derive(Debug, Clone)]
pub struct MincoreResult {
    /// The residency vector (one byte per page).
    pub vec: [u8; 256],
    /// Number of valid entries in `vec`.
    pub count: usize,
    /// Number of resident pages found.
    pub resident_count: usize,
}

impl Default for MincoreResult {
    fn default() -> Self {
        Self {
            vec: [0u8; 256],
            count: 0,
            resident_count: 0,
        }
    }
}

impl MincoreResult {
    /// Fill from a page table walker over the given args.
    pub fn fill(args: &MincoreArgs, walker: &PageTableWalker<'_>) -> Self {
        let mut result = Self {
            count: args.page_count.min(256),
            ..Default::default()
        };
        for i in 0..result.count {
            let page_addr = args.page_addr(i);
            let res = walker.query(page_addr);
            result.vec[i] = res.to_vec_byte();
            if res == PageResidency::Resident {
                result.resident_count += 1;
            }
        }
        result
    }

    /// Return the residency slice (length = `count`).
    pub fn residency_slice(&self) -> &[u8] {
        &self.vec[..self.count]
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Align `n` up to the next page boundary.
fn align_up(n: u64) -> u64 {
    n.wrapping_add(PAGE_SIZE - 1) & !PAGE_MASK
}

// ---------------------------------------------------------------------------
// Public syscall handler
// ---------------------------------------------------------------------------

/// `mincore` — determine memory residency of pages.
///
/// Fills `vec` with one byte per page in `[addr, addr+length)`.
/// Bit 0 of each byte is set if the corresponding page is resident
/// in physical memory; all other bits are reserved (currently 0).
///
/// The `vec` slice must be at least `ceil(length / PAGE_SIZE)` bytes long.
///
/// # Errors
///
/// | `Error`           | Condition                                          |
/// |-------------------|----------------------------------------------------|
/// | `InvalidArgument` | `addr` not page-aligned, `length` zero, overflow  |
/// | `InvalidArgument` | `vec` is shorter than the number of pages          |
///
/// Reference: Linux mincore(2).
pub fn do_mincore(
    addr: u64,
    length: u64,
    vec: &mut [u8],
    walker: &PageTableWalker<'_>,
) -> Result<MincoreResult> {
    let args = MincoreArgs::new(addr, length)?;

    if vec.len() < args.page_count {
        return Err(Error::InvalidArgument);
    }

    let result = MincoreResult::fill(&args, walker);

    // Copy the residency data into the caller's vec.
    for (i, &byte) in result.residency_slice().iter().enumerate() {
        vec[i] = byte;
    }

    Ok(result)
}

/// Validate `mincore` arguments without querying residency.
pub fn validate_mincore_args(addr: u64, length: u64, vec_len: usize) -> Result<()> {
    let args = MincoreArgs::new(addr, length)?;
    if vec_len < args.page_count {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}
