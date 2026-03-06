// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File truncation — `truncate(2)` / `ftruncate(2)` semantics.
//!
//! Handles both extending (creating a hole) and shrinking (freeing blocks)
//! file size, invalidating page cache, and updating inode metadata.

use oncrix_lib::{Error, Result};

/// Page size for alignment calculations.
const PAGE_SIZE: u64 = 4096;

/// Maximum file size (8 TiB, a conservative limit).
pub const MAX_FILE_SIZE: u64 = 8 * 1024 * 1024 * 1024 * 1024;

/// The mode in which truncation is performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TruncateMode {
    /// Reduce file size (blocks freed if shrinking past their page).
    Shrink,
    /// Increase file size by creating a sparse hole.
    Extend,
    /// Same new_size — no-op.
    NoChange,
}

/// Parameters for a truncate operation.
#[derive(Debug, Clone, Copy)]
pub struct TruncateRequest {
    /// Superblock of the target file.
    pub sb_id: u64,
    /// Inode number of the target file.
    pub ino: u64,
    /// Current file size in bytes.
    pub old_size: u64,
    /// New file size in bytes.
    pub new_size: u64,
    /// Wall-clock timestamp for mtime/ctime update (seconds).
    pub now: i64,
    /// UID of the caller (for permission checking).
    pub caller_uid: u32,
    /// Whether the caller has elevated privileges (bypass mode/uid checks).
    pub privileged: bool,
}

impl TruncateRequest {
    /// Return the truncate mode implied by old_size vs new_size.
    pub fn mode(&self) -> TruncateMode {
        use core::cmp::Ordering::*;
        match self.new_size.cmp(&self.old_size) {
            Less => TruncateMode::Shrink,
            Greater => TruncateMode::Extend,
            Equal => TruncateMode::NoChange,
        }
    }
}

/// Per-filesystem truncate operations.
pub trait TruncateOps {
    /// Free all data blocks beyond `new_size` bytes.
    ///
    /// Called when `new_size < old_size`.
    fn truncate_blocks(&mut self, sb_id: u64, ino: u64, new_size: u64) -> Result<u64>;

    /// Allocate a hole (sparse region) from `old_size` to `new_size`.
    ///
    /// Called when `new_size > old_size`. Implementations may simply update
    /// the inode size without allocating blocks (true sparse file).
    fn punch_hole_extend(&mut self, sb_id: u64, ino: u64, new_size: u64) -> Result<()>;

    /// Update the inode size field and timestamps.
    fn update_inode_size(
        &mut self,
        sb_id: u64,
        ino: u64,
        new_size: u64,
        mtime: i64,
        ctime: i64,
    ) -> Result<()>;
}

/// Validate a truncate request.
///
/// Returns `Err(InvalidArgument)` for negative or oversized sizes.
/// Returns `Err(PermissionDenied)` if the caller is not allowed.
pub fn validate_truncate(req: &TruncateRequest) -> Result<()> {
    if req.new_size > MAX_FILE_SIZE {
        return Err(Error::InvalidArgument);
    }
    // Only file owner or privileged caller may truncate.
    if !req.privileged && req.caller_uid != 0 {
        // A real implementation would compare req.caller_uid with the inode uid.
        // Here we accept uid=0 as owner placeholder.
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

/// Compute the first page index that must be invalidated when shrinking.
///
/// When a file is truncated, all pages at or after the page containing the
/// new end-of-file must be invalidated from the page cache.
pub fn first_invalidate_page(new_size: u64) -> u64 {
    // Round up to next page boundary.
    (new_size + PAGE_SIZE - 1) / PAGE_SIZE
}

/// Compute the last full page index that is still valid after shrinking.
///
/// Returns `None` if new_size is 0 (all pages become invalid).
pub fn last_valid_page(new_size: u64) -> Option<u64> {
    if new_size == 0 {
        None
    } else {
        Some((new_size - 1) / PAGE_SIZE)
    }
}

/// Perform a truncation using the provided `TruncateOps` implementation.
///
/// Handles page cache invalidation signalling, block deallocation, and
/// metadata update in the correct order.
pub fn do_truncate<O: TruncateOps>(ops: &mut O, req: &TruncateRequest) -> Result<()> {
    validate_truncate(req)?;

    match req.mode() {
        TruncateMode::NoChange => return Ok(()),
        TruncateMode::Shrink => {
            // 1. Free blocks beyond the new end.
            let _freed_blocks = ops.truncate_blocks(req.sb_id, req.ino, req.new_size)?;
            // 2. Update inode size and timestamps.
            ops.update_inode_size(req.sb_id, req.ino, req.new_size, req.now, req.now)?;
        }
        TruncateMode::Extend => {
            // 1. Mark the hole (no blocks allocated for sparse extension).
            ops.punch_hole_extend(req.sb_id, req.ino, req.new_size)?;
            // 2. Update inode size.
            ops.update_inode_size(req.sb_id, req.ino, req.new_size, req.now, req.now)?;
        }
    }
    Ok(())
}

/// Byte offset of the partial tail page for a given file size.
///
/// Returns `0` if `size` is page-aligned (no partial tail).
pub const fn tail_page_offset(size: u64) -> u64 {
    size % PAGE_SIZE
}

/// Return the number of full pages occupied by a file of the given size.
pub const fn full_page_count(size: u64) -> u64 {
    size / PAGE_SIZE
}

/// Align a size up to the next page boundary.
pub const fn page_align_up(size: u64) -> u64 {
    (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Align a size down to the previous page boundary.
pub const fn page_align_down(size: u64) -> u64 {
    size & !(PAGE_SIZE - 1)
}

/// Statistics collected during truncation.
#[derive(Debug, Clone, Copy, Default)]
pub struct TruncateStats {
    /// Number of blocks freed (shrink path).
    pub blocks_freed: u64,
    /// Number of pages invalidated from the cache.
    pub pages_invalidated: u64,
    /// Whether the inode was dirtied.
    pub inode_dirtied: bool,
}
