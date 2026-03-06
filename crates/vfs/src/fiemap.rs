// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FIEMAP — file extent mapping ioctl.
//!
//! The `FIEMAP` ioctl allows applications to query the physical layout of a
//! file on disk.  Each extent returned describes a contiguous range of logical
//! file offset mapped to a contiguous run of physical blocks.
//!
//! # Usage pattern
//!
//! ```text
//! // User-space pseudo-code
//! struct fiemap fm = {
//!     .fm_start  = 0,
//!     .fm_length = UINT64_MAX,    // query whole file
//!     .fm_flags  = 0,
//!     .fm_extent_count = 64,
//! };
//! ioctl(fd, FS_IOC_FIEMAP, &fm);
//! for i in 0..fm.fm_mapped_extents:
//!     print(fm.fm_extents[i])
//! ```
//!
//! # Architecture
//!
//! ```text
//! ioctl(fd, FS_IOC_FIEMAP, user_fiemap)
//!     │
//!     ▼
//! FiemapSubsystem::process()
//!     ├── fiemap_check_ranges()   — validate start/length
//!     ├── FiemapOps::fiemap_query()  — filesystem fills extents
//!     └── return FiemapResult
//! ```
//!
//! # References
//!
//! - Linux `fs/ioctl.c` — `ioctl_fiemap()`
//! - Linux `include/uapi/linux/fiemap.h`
//! - `man 2 ioctl_fiemap`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of extents returned in a single FIEMAP query.
pub const FIEMAP_MAX_EXTENTS: usize = 64;

/// `FS_IOC_FIEMAP` ioctl command number (Linux value).
pub const FS_IOC_FIEMAP: u32 = 0xC020_660B;

// ── FiemapExtentFlags ─────────────────────────────────────────────────────────

/// Flags that qualify a single [`FiemapExtent`].
#[derive(Debug, Clone, Copy, Default)]
pub struct FiemapExtentFlags(pub u32);

impl FiemapExtentFlags {
    /// This is the last extent in the file.
    pub const LAST: u32 = 0x0001;
    /// The location of the extent is unknown (e.g., inline, fragmented).
    pub const UNKNOWN: u32 = 0x0002;
    /// Extent is delayed-allocated (not yet assigned physical blocks).
    pub const DELALLOC: u32 = 0x0004;
    /// Extent data is encoded (e.g., compressed or encrypted at FS level).
    pub const ENCODED: u32 = 0x0008;
    /// Extent data is encrypted at the block layer.
    pub const DATA_ENCRYPTED: u32 = 0x0080;
    /// The extent is not aligned to the filesystem block size.
    pub const NOT_ALIGNED: u32 = 0x0100;
    /// Data is stored inline within the inode.
    pub const DATA_INLINE: u32 = 0x0200;
    /// Data is stored in the last block, sharing space with another file.
    pub const DATA_TAIL: u32 = 0x0400;
    /// Extent has been allocated but not yet written (unwritten extent).
    pub const UNWRITTEN: u32 = 0x0800;
    /// Extent was merged with an adjacent extent to reduce output count.
    pub const MERGED: u32 = 0x1000;
    /// Extent is shared (CoW) between multiple files.
    pub const SHARED: u32 = 0x2000;

    /// Returns `true` if this is the last extent.
    pub fn is_last(self) -> bool {
        self.0 & Self::LAST != 0
    }

    /// Returns `true` if the extent is delayed-allocated.
    pub fn is_delalloc(self) -> bool {
        self.0 & Self::DELALLOC != 0
    }

    /// Returns `true` if the extent is unwritten (allocated but not written).
    pub fn is_unwritten(self) -> bool {
        self.0 & Self::UNWRITTEN != 0
    }

    /// Returns `true` if the extent is shared (CoW).
    pub fn is_shared(self) -> bool {
        self.0 & Self::SHARED != 0
    }

    /// Returns `true` if data is stored inline.
    pub fn is_inline(self) -> bool {
        self.0 & Self::DATA_INLINE != 0
    }
}

// ── FiemapExtent ──────────────────────────────────────────────────────────────

/// A single file extent as returned by FIEMAP.
#[derive(Debug, Clone, Copy, Default)]
pub struct FiemapExtent {
    /// Logical file offset (bytes from beginning of file).
    pub logical: u64,
    /// Physical block offset on the block device (bytes).
    pub physical: u64,
    /// Length of the extent in bytes.
    pub length: u64,
    /// Flags qualifying this extent.
    pub flags: FiemapExtentFlags,
}

impl FiemapExtent {
    /// Construct a simple data extent.
    pub const fn data(logical: u64, physical: u64, length: u64) -> Self {
        Self {
            logical,
            physical,
            length,
            flags: FiemapExtentFlags(0),
        }
    }

    /// Construct a hole (unallocated) extent.
    ///
    /// Holes are represented with `physical = 0` and the `UNKNOWN` flag.
    pub const fn hole(logical: u64, length: u64) -> Self {
        Self {
            logical,
            physical: 0,
            length,
            flags: FiemapExtentFlags(FiemapExtentFlags::UNKNOWN),
        }
    }

    /// Mark this extent as the last in the file.
    pub fn mark_last(&mut self) {
        self.flags.0 |= FiemapExtentFlags::LAST;
    }

    /// Returns `true` if `pos` falls within this extent.
    pub fn contains(&self, pos: u64) -> bool {
        pos >= self.logical && pos < self.logical + self.length
    }
}

// ── FiemapRequest ─────────────────────────────────────────────────────────────

/// Input parameters for a FIEMAP query.
#[derive(Debug, Clone, Copy)]
pub struct FiemapRequest {
    /// Start of the range to query (logical file offset in bytes).
    pub start: u64,
    /// Length of the range to query in bytes.
    pub length: u64,
    /// Query flags (currently unused; reserved for `FIEMAP_FLAG_SYNC` etc.).
    pub flags: u32,
    /// Maximum number of extents the caller can receive.
    pub max_extents: u32,
}

impl FiemapRequest {
    /// Construct a request covering the entire file.
    pub const fn whole_file() -> Self {
        Self {
            start: 0,
            length: u64::MAX,
            flags: 0,
            max_extents: FIEMAP_MAX_EXTENTS as u32,
        }
    }

    /// Construct a request for a specific byte range.
    pub const fn range(start: u64, length: u64) -> Self {
        Self {
            start,
            length,
            flags: 0,
            max_extents: FIEMAP_MAX_EXTENTS as u32,
        }
    }
}

// ── FiemapResult ──────────────────────────────────────────────────────────────

/// Output of a FIEMAP query: an array of extents describing the file layout.
#[derive(Debug, Clone, Copy)]
pub struct FiemapResult {
    /// Extents returned by the filesystem.
    pub extents: [FiemapExtent; FIEMAP_MAX_EXTENTS],
    /// Number of valid extents in `extents`.
    pub extent_count: usize,
    /// Number of extents that would have been returned if `max_extents` were
    /// large enough (may exceed `FIEMAP_MAX_EXTENTS`).
    pub mapped_extents: u32,
}

impl FiemapResult {
    /// Create an empty result.
    pub const fn empty() -> Self {
        Self {
            extents: [const {
                FiemapExtent {
                    logical: 0,
                    physical: 0,
                    length: 0,
                    flags: FiemapExtentFlags(0),
                }
            }; FIEMAP_MAX_EXTENTS],
            extent_count: 0,
            mapped_extents: 0,
        }
    }

    /// Return a slice of the valid extents.
    pub fn valid_extents(&self) -> &[FiemapExtent] {
        &self.extents[..self.extent_count]
    }

    /// Return the total length covered by all returned extents.
    pub fn total_mapped_bytes(&self) -> u64 {
        self.valid_extents()
            .iter()
            .map(|e| e.length)
            .fold(0u64, u64::saturating_add)
    }
}

// ── FiemapOps ─────────────────────────────────────────────────────────────────

/// Filesystem-provided callback for FIEMAP extent enumeration.
pub trait FiemapOps {
    /// Fill `result` with extents covering `[request.start, request.start + request.length)`.
    ///
    /// The filesystem must call [`fiemap_fill_next_extent`] for each extent
    /// within the requested range.  Extent enumeration stops when `result` is
    /// full or the entire range has been covered.
    fn fiemap_query(
        &self,
        inode_id: u64,
        request: &FiemapRequest,
        result: &mut FiemapResult,
    ) -> Result<()>;
}

// ── Validation and helper functions ───────────────────────────────────────────

/// Validate FIEMAP request parameters.
///
/// Returns [`Error::InvalidArgument`] if:
/// - `length` is zero, or
/// - `start + length` would overflow `u64`, or
/// - `max_extents` is zero.
pub fn fiemap_check_ranges(request: &FiemapRequest) -> Result<()> {
    if request.length == 0 {
        return Err(Error::InvalidArgument);
    }
    if request.max_extents == 0 {
        return Err(Error::InvalidArgument);
    }
    // Check for overflow: start + length must not wrap.
    if request.start.checked_add(request.length).is_none() && request.length != u64::MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Append a single extent to a [`FiemapResult`].
///
/// Returns `true` if the extent was added, `false` if the result buffer is
/// full.  The caller should stop iterating when this function returns `false`.
///
/// If `is_last` is `true`, the [`FiemapExtentFlags::LAST`] flag is set on the
/// appended extent.
pub fn fiemap_fill_next_extent(
    result: &mut FiemapResult,
    mut extent: FiemapExtent,
    is_last: bool,
    max_extents: usize,
) -> bool {
    result.mapped_extents += 1;
    if result.extent_count >= max_extents.min(FIEMAP_MAX_EXTENTS) {
        return false;
    }
    if is_last {
        extent.mark_last();
    }
    result.extents[result.extent_count] = extent;
    result.extent_count += 1;
    true
}

// ── FiemapSubsystem ───────────────────────────────────────────────────────────

/// The FIEMAP subsystem: validates requests, invokes per-filesystem callbacks,
/// and returns extent results.
pub struct FiemapSubsystem {
    /// Total FIEMAP ioctls processed.
    pub total_queries: u64,
    /// Total extents returned across all queries.
    pub total_extents_returned: u64,
    /// Queries that failed validation.
    pub validation_errors: u64,
}

impl FiemapSubsystem {
    /// Create a new FIEMAP subsystem.
    pub const fn new() -> Self {
        Self {
            total_queries: 0,
            total_extents_returned: 0,
            validation_errors: 0,
        }
    }

    /// Process a FIEMAP ioctl for the given inode.
    ///
    /// 1. Validates the request via [`fiemap_check_ranges`].
    /// 2. Calls `ops.fiemap_query()` to let the filesystem fill extents.
    /// 3. Returns the populated [`FiemapResult`].
    pub fn process<F: FiemapOps>(
        &mut self,
        ops: &F,
        inode_id: u64,
        request: &FiemapRequest,
    ) -> Result<FiemapResult> {
        if let Err(e) = fiemap_check_ranges(request) {
            self.validation_errors += 1;
            return Err(e);
        }
        let mut result = FiemapResult::empty();
        ops.fiemap_query(inode_id, request, &mut result)?;
        self.total_queries += 1;
        self.total_extents_returned += result.extent_count as u64;
        Ok(result)
    }
}

impl Default for FiemapSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
