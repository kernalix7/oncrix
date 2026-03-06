// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `msync` syscall handler.
//!
//! Implements `msync(2)` per POSIX.1-2024.
//! `msync` initiates or waits for writeback of dirty pages in a
//! file-backed shared mapping. It may also invalidate the page cache
//! for a range to force re-reading from the underlying file.
//!
//! # References
//!
//! - POSIX.1-2024: `msync()`
//! - Linux man pages: `msync(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Page size
// ---------------------------------------------------------------------------

/// Default system page size (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Page offset mask.
const PAGE_MASK: u64 = PAGE_SIZE - 1;

// ---------------------------------------------------------------------------
// Msync flags
// ---------------------------------------------------------------------------

/// Perform asynchronous writeback (schedule write, don't wait).
pub const MS_ASYNC: i32 = 1;
/// Invalidate cached mappings (force re-read from file).
pub const MS_INVALIDATE: i32 = 2;
/// Perform synchronous writeback (wait until all pages are flushed).
pub const MS_SYNC: i32 = 4;

/// Mask of all valid msync flags.
const MS_VALID_MASK: i32 = MS_ASYNC | MS_INVALIDATE | MS_SYNC;

// ---------------------------------------------------------------------------
// MsyncArgs — validated parameter bundle
// ---------------------------------------------------------------------------

/// Validated arguments for `msync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsyncArgs {
    /// Start address of the range (must be page-aligned).
    pub addr: u64,
    /// Length of the range in bytes.
    pub length: u64,
    /// Flags (`MS_ASYNC`, `MS_SYNC`, `MS_INVALIDATE`).
    pub flags: i32,
}

impl MsyncArgs {
    /// Construct and validate `MsyncArgs`.
    ///
    /// Returns `Err(InvalidArgument)` when:
    /// - `addr` is not page-aligned.
    /// - `length` is zero.
    /// - `flags` contains unrecognised bits.
    /// - Both `MS_ASYNC` and `MS_SYNC` are set simultaneously.
    pub fn new(addr: u64, length: u64, flags: i32) -> Result<Self> {
        if addr & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if length == 0 {
            return Err(Error::InvalidArgument);
        }
        if flags & !MS_VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        // MS_ASYNC and MS_SYNC are mutually exclusive.
        if flags & MS_ASYNC != 0 && flags & MS_SYNC != 0 {
            return Err(Error::InvalidArgument);
        }
        let aligned_len = align_up(length);
        addr.checked_add(aligned_len)
            .ok_or(Error::InvalidArgument)?;
        Ok(Self {
            addr,
            length: aligned_len,
            flags,
        })
    }

    /// Return `true` if synchronous writeback is requested.
    pub const fn is_sync(&self) -> bool {
        self.flags & MS_SYNC != 0
    }

    /// Return `true` if asynchronous writeback is requested.
    pub const fn is_async(&self) -> bool {
        self.flags & MS_ASYNC != 0
    }

    /// Return `true` if cache invalidation is requested.
    pub const fn is_invalidate(&self) -> bool {
        self.flags & MS_INVALIDATE != 0
    }

    /// Return the exclusive end address.
    pub const fn end(&self) -> u64 {
        self.addr + self.length
    }
}

// ---------------------------------------------------------------------------
// MappingInfo — simulated mapping descriptor
// ---------------------------------------------------------------------------

/// Information about a memory mapping, used to determine writeback scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingInfo {
    /// Start address of the mapping.
    pub start: u64,
    /// End address (exclusive) of the mapping.
    pub end: u64,
    /// Whether this is a file-backed mapping (as opposed to anonymous).
    pub file_backed: bool,
    /// Whether the mapping is shared (MAP_SHARED).
    pub shared: bool,
    /// Number of dirty pages in this mapping.
    pub dirty_pages: u64,
}

impl MappingInfo {
    /// Return `true` if writeback is applicable (file-backed and shared).
    pub const fn needs_writeback(&self) -> bool {
        self.file_backed && self.shared
    }

    /// Return the overlap between this mapping and the given range.
    pub fn overlap(&self, args: &MsyncArgs) -> Option<(u64, u64)> {
        let os = self.start.max(args.addr);
        let oe = self.end.min(args.end());
        if os < oe { Some((os, oe)) } else { None }
    }
}

// ---------------------------------------------------------------------------
// MsyncResult — outcome
// ---------------------------------------------------------------------------

/// Result of a successful `msync` call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MsyncResult {
    /// Number of pages scheduled or flushed for writeback.
    pub pages_written: u64,
    /// Number of pages invalidated from the page cache.
    pub pages_invalidated: u64,
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

/// `msync` — synchronize a file mapping with the underlying file.
///
/// For file-backed shared mappings that overlap `[addr, addr+length)`:
/// - `MS_SYNC`:  write all dirty pages synchronously.
/// - `MS_ASYNC`: schedule writes; return immediately.
/// - `MS_INVALIDATE`: invalidate cached pages (mark for re-read).
///
/// Anonymous mappings are silently ignored (they have no backing file).
///
/// Returns the number of pages written/invalidated on success.
///
/// # Errors
///
/// | `Error`           | Condition                                       |
/// |-------------------|-------------------------------------------------|
/// | `InvalidArgument` | `addr` not page-aligned, `length` zero, invalid flags |
/// | `InvalidArgument` | `MS_ASYNC` and `MS_SYNC` both set               |
///
/// Reference: POSIX.1-2024 §msync.
pub fn do_msync(
    addr: u64,
    length: u64,
    flags: i32,
    mappings: &[MappingInfo],
) -> Result<MsyncResult> {
    let args = MsyncArgs::new(addr, length, flags)?;

    let mut result = MsyncResult::default();

    for mapping in mappings {
        if let Some((os, oe)) = mapping.overlap(&args) {
            let pages = (oe - os) / PAGE_SIZE;

            if mapping.needs_writeback() {
                let dirty = pages.min(mapping.dirty_pages);
                if args.is_sync() || args.is_async() {
                    result.pages_written += dirty;
                }
            }

            if args.is_invalidate() {
                result.pages_invalidated += pages;
            }
        }
    }

    // Stub: real implementation calls filemap_write_and_wait_range() for MS_SYNC,
    // filemap_fdatawrite_range() for MS_ASYNC, and invalidate_mapping_pages() for
    // MS_INVALIDATE.

    Ok(result)
}

/// Validate `msync` arguments without performing the sync.
pub fn validate_msync_args(addr: u64, length: u64, flags: i32) -> Result<()> {
    let _ = MsyncArgs::new(addr, length, flags)?;
    Ok(())
}
