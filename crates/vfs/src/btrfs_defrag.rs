// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs defragmentation subsystem.
//!
//! Btrfs defragmentation rewrites fragmented file extents as larger, more
//! contiguous allocations.  It can be triggered per-file (`ioctl BTRFS_IOC_DEFRAG`)
//! or recursively on a directory tree.  This module models the defrag control
//! arguments, progress tracking, and the range-selection logic.

use oncrix_lib::{Error, Result};

/// Default target extent size after defragmentation (128 KiB).
pub const BTRFS_DEFRAG_DEFAULT_EXTENT_SIZE: u64 = 128 * 1024;

/// Maximum extent size hint accepted from userspace (256 MiB).
pub const BTRFS_DEFRAG_MAX_EXTENT_SIZE: u64 = 256 * 1024 * 1024;

/// Defrag flags as defined in the kernel ioctl interface.
pub mod defrag_flags {
    /// Do not compress the defragmented extents.
    pub const COMPRESS: u32 = 0x0001;
    /// Flush pages to disk after defrag.
    pub const FLUSH: u32 = 0x0002;
}

/// Compression algorithm hint for defrag (mirrors btrfs_compress_type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DefragCompress {
    #[default]
    None,
    Zlib,
    Lzo,
    Zstd,
}

/// Defragmentation arguments (from `btrfs_ioctl_defrag_range_args`).
#[derive(Debug, Clone, Default)]
pub struct BtrfsDefragArgs {
    /// File byte offset to start defragmenting from.
    pub start: u64,
    /// Length in bytes (0 = to end of file).
    pub len: u64,
    /// Target extent size hint in bytes (0 = use default).
    pub extent_thresh: u64,
    /// Defrag flags.
    pub flags: u32,
    /// Compression algorithm hint.
    pub compress: DefragCompress,
}

impl BtrfsDefragArgs {
    /// Validate and normalise the args.
    pub fn validate(&mut self) -> Result<()> {
        if self.extent_thresh == 0 {
            self.extent_thresh = BTRFS_DEFRAG_DEFAULT_EXTENT_SIZE;
        }
        if self.extent_thresh > BTRFS_DEFRAG_MAX_EXTENT_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.len == 0 {
            self.len = u64::MAX;
        }
        Ok(())
    }

    /// The effective end offset (saturating).
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }

    /// Whether compression is requested.
    pub fn wants_compress(&self) -> bool {
        self.flags & defrag_flags::COMPRESS != 0 && self.compress != DefragCompress::None
    }
}

/// A single fragmented extent candidate for defragmentation.
#[derive(Debug, Clone, Copy)]
pub struct DefragCandidate {
    /// Logical file offset (in bytes).
    pub offset: u64,
    /// Physical block address.
    pub phys: u64,
    /// Extent length in bytes.
    pub len: u64,
    /// Whether this extent is already compressed.
    pub compressed: bool,
    /// Whether this extent is shared (copy-on-write reference).
    pub shared: bool,
}

impl DefragCandidate {
    /// Whether this extent is worth defragmenting given `thresh`.
    pub fn should_defrag(&self, thresh: u64) -> bool {
        !self.shared && self.len < thresh
    }
}

/// Progress tracker for an ongoing defrag operation.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefragProgress {
    /// Bytes scanned (including skipped extents).
    pub bytes_scanned: u64,
    /// Bytes actually rewritten.
    pub bytes_rewritten: u64,
    /// Number of extents rewritten.
    pub extents_rewritten: u64,
    /// Number of extents skipped (shared / already large).
    pub extents_skipped: u64,
    /// Whether the operation has completed.
    pub done: bool,
}

impl DefragProgress {
    /// Record that an extent was rewritten.
    pub fn record_rewrite(&mut self, len: u64) {
        self.bytes_scanned += len;
        self.bytes_rewritten += len;
        self.extents_rewritten += 1;
    }

    /// Record that an extent was skipped.
    pub fn record_skip(&mut self, len: u64) {
        self.bytes_scanned += len;
        self.extents_skipped += 1;
    }

    /// Mark as completed.
    pub fn finish(&mut self) {
        self.done = true;
    }
}

/// Defragmentation run state.
pub struct DefragRun {
    pub args: BtrfsDefragArgs,
    pub progress: DefragProgress,
    /// Whether the run was cancelled.
    pub cancelled: bool,
}

impl DefragRun {
    /// Start a new defrag run.
    pub fn new(mut args: BtrfsDefragArgs) -> Result<Self> {
        args.validate()?;
        Ok(Self {
            args,
            progress: DefragProgress::default(),
            cancelled: false,
        })
    }

    /// Process one candidate extent.
    pub fn process(&mut self, candidate: DefragCandidate) -> Result<bool> {
        if self.cancelled {
            return Err(Error::Interrupted);
        }
        // Skip extents outside the requested range.
        if candidate.offset >= self.args.end() {
            self.progress.finish();
            return Ok(false);
        }
        if candidate.offset + candidate.len <= self.args.start {
            return Ok(false);
        }
        if candidate.should_defrag(self.args.extent_thresh) {
            self.progress.record_rewrite(candidate.len);
            Ok(true)
        } else {
            self.progress.record_skip(candidate.len);
            Ok(false)
        }
    }

    /// Cancel the defrag run.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }
}
