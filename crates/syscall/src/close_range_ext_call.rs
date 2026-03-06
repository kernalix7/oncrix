// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended `close_range` syscall with additional semantics.
//!
//! `close_range` closes all file descriptors in [first, last] atomically.
//! This extended module adds tracking of closed counts, CLOEXEC-only mode,
//! and per-process file descriptor table statistics.
//!
//! Linux-specific. Not in POSIX.

use oncrix_lib::{Error, Result};

/// CLOSE_RANGE_UNSHARE: unshare the file descriptor table before closing.
pub const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
/// CLOSE_RANGE_CLOEXEC: set close-on-exec instead of closing immediately.
pub const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

/// Maximum valid file descriptor number (Linux ABI limit).
pub const MAX_FD: u32 = u32::MAX;

/// Arguments for the extended `close_range` syscall.
#[derive(Debug, Clone, Copy)]
pub struct CloseRangeExtArgs {
    /// First fd in the range to close (inclusive).
    pub first: u32,
    /// Last fd in the range to close (inclusive; use MAX_FD for "all").
    pub last: u32,
    /// Flags: CLOSE_RANGE_UNSHARE and/or CLOSE_RANGE_CLOEXEC.
    pub flags: u32,
}

/// Result of a close_range_ext operation.
#[derive(Debug, Default)]
pub struct CloseRangeExtResult {
    /// Number of file descriptors actually closed (or marked CLOEXEC).
    pub closed_count: u32,
    /// Number of file descriptors skipped (already closed).
    pub skipped_count: u32,
    /// Whether the fd table was unshared before the operation.
    pub unshared: bool,
}

impl CloseRangeExtResult {
    /// Create an empty result.
    pub const fn new() -> Self {
        Self {
            closed_count: 0,
            skipped_count: 0,
            unshared: false,
        }
    }

    /// Total file descriptors examined (closed + skipped).
    pub fn total_examined(&self) -> u32 {
        self.closed_count.saturating_add(self.skipped_count)
    }
}

/// Validate extended close_range arguments.
///
/// Checks that first <= last and that only known flags are set.
pub fn validate_close_range_ext_args(args: &CloseRangeExtArgs) -> Result<()> {
    if args.first > args.last {
        return Err(Error::InvalidArgument);
    }
    let known = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;
    if args.flags & !known != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Compute the size of the fd range (number of fds to examine).
///
/// Returns `None` if the range would overflow a `u32`.
pub fn range_size(args: &CloseRangeExtArgs) -> Option<u32> {
    args.last
        .checked_sub(args.first)
        .and_then(|d| d.checked_add(1))
}

/// Handle the extended `close_range` syscall.
///
/// Closes or CLOEXEC-marks all open file descriptors in [first, last].
/// With CLOSE_RANGE_UNSHARE, unshares the fd table first (copy-on-write).
/// With CLOSE_RANGE_CLOEXEC, sets the close-on-exec flag instead of closing.
///
/// Returns the number of file descriptors affected, or an error.
pub fn sys_close_range_ext(args: &CloseRangeExtArgs) -> Result<i64> {
    validate_close_range_ext_args(args)?;
    // Stub: real implementation would:
    // 1. If CLOSE_RANGE_UNSHARE: dup the fd table (copy-on-write for threads).
    // 2. Iterate over [first, last] in the fd table.
    // 3. If CLOSE_RANGE_CLOEXEC: set FD_CLOEXEC on each open fd.
    //    Else: call do_close on each open fd.
    // 4. Return count of affected fds.
    Err(Error::NotImplemented)
}

/// Build a summary of open file descriptors in a range.
///
/// In the real kernel this scans the fd table bitmap. Here it is a stub
/// that returns (open_count, total_slots) for the range.
pub fn count_open_fds_in_range(first: u32, last: u32) -> Result<(u32, u32)> {
    if first > last {
        return Err(Error::InvalidArgument);
    }
    let total = last.saturating_sub(first).saturating_add(1);
    // Stub: real implementation scans the fd table bitmap.
    Ok((0, total))
}

/// Check whether setting CLOEXEC on fd range is allowed for the caller.
///
/// CLOEXEC mode does not require any special privilege.
pub fn cloexec_mode_allowed() -> bool {
    true
}

/// Check whether unsharing the fd table is allowed for the caller.
///
/// Unsharing is only meaningful when the fd table is shared with other
/// threads (i.e., the process has called `clone(CLONE_FILES)`).
pub fn unshare_allowed() -> bool {
    // Stub: real check queries whether CLONE_FILES is active.
    true
}
