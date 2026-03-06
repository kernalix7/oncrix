// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `close_range(2)` syscall handler.
//!
//! `close_range` closes all open file descriptors in the range `[first, last]`
//! (both ends inclusive) in one atomic operation.  It was introduced in Linux 5.9
//! as a more efficient alternative to looping over `close(2)` and is particularly
//! useful in `exec`-path clean-up.
//!
//! # POSIX / Linux Reference
//!
//! - Linux man page: `close_range(2)`
//! - Kernel source: `fs/file.c` (`__close_range`), `include/uapi/linux/close_range.h`
//!
//! # Flags
//!
//! | Flag                          | Meaning                                                  |
//! |-------------------------------|----------------------------------------------------------|
//! | [`CLOSE_RANGE_UNSHARE`]       | Unshare the file descriptor table before closing         |
//! | [`CLOSE_RANGE_CLOEXEC`]       | Set `O_CLOEXEC` instead of closing the descriptors       |
//!
//! # Usage patterns
//!
//! ```text
//! // Close all fds >= 3 (leave stdin/stdout/stderr).
//! close_range(3, u32::MAX, 0)
//!
//! // Mark all fds >= 3 as close-on-exec.
//! close_range(3, u32::MAX, CLOSE_RANGE_CLOEXEC)
//! ```

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Unshare the file descriptor table of the current process before
/// applying the range operation.  This prevents the changes from
/// affecting other threads that share the same file descriptor table.
pub const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;

/// Set the `O_CLOEXEC` flag on all file descriptors in the range
/// instead of closing them immediately.  The descriptors will be
/// closed automatically when the process calls `exec`.
pub const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

/// All recognised `close_range` flag bits.
const CLOSE_RANGE_FLAGS_KNOWN: u32 = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;

// ---------------------------------------------------------------------------
// FD table abstraction
// ---------------------------------------------------------------------------

/// Maximum number of file descriptors that a process may have open.
///
/// This matches the Linux default `NR_OPEN_DEFAULT` of 1 024.  In the real
/// kernel this limit is configurable via `RLIMIT_NOFILE`.
pub const MAX_OPEN_FILES: usize = 1024;

/// State of a single file descriptor slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdState {
    /// Slot is empty — not open.
    Empty,
    /// Slot is open and `O_CLOEXEC` is NOT set.
    Open,
    /// Slot is open and `O_CLOEXEC` IS set.
    OpenCloexec,
}

impl FdState {
    /// Return `true` if the slot holds an open file description.
    pub const fn is_open(self) -> bool {
        matches!(self, FdState::Open | FdState::OpenCloexec)
    }

    /// Return `true` if `O_CLOEXEC` is set on this slot.
    pub const fn is_cloexec(self) -> bool {
        matches!(self, FdState::OpenCloexec)
    }
}

/// A minimal per-process file descriptor table.
///
/// Holds up to [`MAX_OPEN_FILES`] slots.  In the real kernel this is
/// `struct fdtable` / `struct files_struct`.
pub struct FdTable {
    slots: [FdState; MAX_OPEN_FILES],
    /// Number of currently open descriptors.
    open_count: usize,
}

impl FdTable {
    /// Create a new, empty file descriptor table.
    pub const fn new() -> Self {
        Self {
            slots: [FdState::Empty; MAX_OPEN_FILES],
            open_count: 0,
        }
    }

    /// Return the state of file descriptor `fd`.
    ///
    /// Returns `FdState::Empty` for any `fd >= MAX_OPEN_FILES`.
    pub fn get(&self, fd: usize) -> FdState {
        if fd < MAX_OPEN_FILES {
            self.slots[fd]
        } else {
            FdState::Empty
        }
    }

    /// Mark file descriptor `fd` as open (without `O_CLOEXEC`).
    ///
    /// Returns `Err(InvalidArgument)` if `fd >= MAX_OPEN_FILES`.
    pub fn open(&mut self, fd: usize) -> Result<()> {
        if fd >= MAX_OPEN_FILES {
            return Err(Error::InvalidArgument);
        }
        if !self.slots[fd].is_open() {
            self.open_count += 1;
        }
        self.slots[fd] = FdState::Open;
        Ok(())
    }

    /// Close file descriptor `fd`.
    ///
    /// Returns `Err(InvalidArgument)` if `fd >= MAX_OPEN_FILES` or
    /// `Err(NotFound)` if the descriptor is not open.
    pub fn close(&mut self, fd: usize) -> Result<()> {
        if fd >= MAX_OPEN_FILES {
            return Err(Error::InvalidArgument);
        }
        if !self.slots[fd].is_open() {
            return Err(Error::NotFound);
        }
        self.slots[fd] = FdState::Empty;
        self.open_count -= 1;
        Ok(())
    }

    /// Set or clear `O_CLOEXEC` on file descriptor `fd`.
    ///
    /// Returns `Err(NotFound)` if the descriptor is not open.
    pub fn set_cloexec(&mut self, fd: usize, cloexec: bool) -> Result<()> {
        if fd >= MAX_OPEN_FILES {
            return Err(Error::InvalidArgument);
        }
        if !self.slots[fd].is_open() {
            return Err(Error::NotFound);
        }
        self.slots[fd] = if cloexec {
            FdState::OpenCloexec
        } else {
            FdState::Open
        };
        Ok(())
    }

    /// Return the number of currently open file descriptors.
    pub const fn open_count(&self) -> usize {
        self.open_count
    }
}

// ---------------------------------------------------------------------------
// Unshare stub
// ---------------------------------------------------------------------------

/// Outcome of an unshare operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnshareResult {
    /// The table was already private; no copy was needed.
    AlreadyPrivate,
    /// A new copy of the table was made for the calling process.
    Copied,
}

/// Simulate unsharing the file descriptor table.
///
/// In the real kernel this calls `dup_fd` to COW-copy `files_struct`.
/// Here we record that an unshare was requested so that callers can
/// verify the flag was honoured.
fn unshare_fd_table() -> UnshareResult {
    // In a real implementation: if refcount > 1, copy the table.
    // For this stub we always report that a copy was made.
    UnshareResult::Copied
}

// ---------------------------------------------------------------------------
// Statistics returned by the handler
// ---------------------------------------------------------------------------

/// Counters from a `close_range` operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CloseRangeStats {
    /// Number of file descriptors actually closed (or marked cloexec).
    pub affected: u32,
    /// Whether the FD table was unshared.
    pub unshared: bool,
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for the `close_range(2)` syscall.
///
/// Closes (or marks close-on-exec) every open file descriptor in the
/// range `[first, last]`.  Both `first` and `last` are file descriptor
/// numbers (`u32`); pass `u32::MAX` for `last` to mean "all remaining".
///
/// # Arguments
///
/// * `table`  — The calling process's file descriptor table.
/// * `first`  — Lowest file descriptor to affect.
/// * `last`   — Highest file descriptor to affect (inclusive).
/// * `flags`  — Bitmask of [`CLOSE_RANGE_UNSHARE`] / [`CLOSE_RANGE_CLOEXEC`].
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — `first > last` or unknown flag bits set.
///
/// # POSIX / Linux conformance
///
/// - `first > last` → `EINVAL`.
/// - Unknown flags → `EINVAL`.
/// - Descriptors that are not open in `[first, last]` are silently skipped
///   (no `EBADF`), matching Linux semantics.
/// - `CLOSE_RANGE_UNSHARE` causes the FD table to be copied if it is shared.
/// - `CLOSE_RANGE_CLOEXEC` sets `O_CLOEXEC` rather than closing descriptors.
pub fn do_close_range(
    table: &mut FdTable,
    first: u32,
    last: u32,
    flags: u32,
) -> Result<CloseRangeStats> {
    // Reject unknown flags.
    if flags & !CLOSE_RANGE_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate range ordering.
    if first > last {
        return Err(Error::InvalidArgument);
    }

    let mut stats = CloseRangeStats::default();

    // Unshare the FD table if requested.
    if flags & CLOSE_RANGE_UNSHARE != 0 {
        unshare_fd_table();
        stats.unshared = true;
    }

    // Clamp `last` to the maximum representable fd index.
    let end = (last as usize).min(MAX_OPEN_FILES - 1);
    let start = first as usize;

    if start >= MAX_OPEN_FILES {
        // Nothing to do — range is entirely beyond valid fd space.
        return Ok(stats);
    }

    if flags & CLOSE_RANGE_CLOEXEC != 0 {
        // Set O_CLOEXEC on each open descriptor in range.
        for fd in start..=end {
            if table.get(fd).is_open() {
                // Ignore individual errors; kernel silently skips non-open fds.
                let _ = table.set_cloexec(fd, true);
                stats.affected += 1;
            }
        }
    } else {
        // Close each open descriptor in range.
        for fd in start..=end {
            if table.get(fd).is_open() {
                let _ = table.close(fd);
                stats.affected += 1;
            }
        }
    }

    Ok(stats)
}

// ---------------------------------------------------------------------------
// Convenience: close a single fd via close_range
// ---------------------------------------------------------------------------

/// Close a single file descriptor using `close_range` semantics.
///
/// Equivalent to `close_range(fd, fd, 0)` — provided as a helper.
pub fn do_close(table: &mut FdTable, fd: u32) -> Result<()> {
    let stats = do_close_range(table, fd, fd, 0)?;
    if stats.affected == 0 {
        // fd was not open.
        return Err(Error::NotFound);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn table_with_fds(fds: &[usize]) -> FdTable {
        let mut t = FdTable::new();
        for &fd in fds {
            t.open(fd).unwrap();
        }
        t
    }

    #[test]
    fn close_range_rejects_unknown_flags() {
        let mut t = FdTable::new();
        let result = do_close_range(&mut t, 0, 10, 0xFF);
        assert_eq!(result, Err(Error::InvalidArgument));
    }

    #[test]
    fn close_range_rejects_first_gt_last() {
        let mut t = FdTable::new();
        let result = do_close_range(&mut t, 10, 5, 0);
        assert_eq!(result, Err(Error::InvalidArgument));
    }

    #[test]
    fn close_range_closes_all_in_range() {
        let mut t = table_with_fds(&[3, 5, 7, 100]);
        let stats = do_close_range(&mut t, 3, 10, 0).unwrap();
        assert_eq!(stats.affected, 3); // fds 3, 5, 7
        assert!(t.get(3) == FdState::Empty);
        assert!(t.get(5) == FdState::Empty);
        assert!(t.get(7) == FdState::Empty);
        assert!(t.get(100).is_open()); // outside range — untouched
    }

    #[test]
    fn close_range_skips_empty_slots() {
        let mut t = table_with_fds(&[5]);
        let stats = do_close_range(&mut t, 0, 100, 0).unwrap();
        assert_eq!(stats.affected, 1);
    }

    #[test]
    fn close_range_cloexec_flag() {
        let mut t = table_with_fds(&[4, 8]);
        let stats = do_close_range(&mut t, 0, 9, CLOSE_RANGE_CLOEXEC).unwrap();
        assert_eq!(stats.affected, 2);
        assert_eq!(t.get(4), FdState::OpenCloexec);
        assert_eq!(t.get(8), FdState::OpenCloexec);
        // Files should still be open.
        assert!(t.get(4).is_open());
    }

    #[test]
    fn close_range_unshare_flag() {
        let mut t = table_with_fds(&[3]);
        let stats = do_close_range(&mut t, 3, 3, CLOSE_RANGE_UNSHARE).unwrap();
        assert!(stats.unshared);
        assert_eq!(stats.affected, 1);
    }

    #[test]
    fn close_range_last_is_u32_max() {
        let mut t = table_with_fds(&[0, 1, 2, 500, 1023]);
        let stats = do_close_range(&mut t, 3, u32::MAX, 0).unwrap();
        // Only fds 500 and 1023 are in range [3, 1023].
        assert_eq!(stats.affected, 2);
        assert!(t.get(0).is_open()); // below range
        assert!(t.get(1).is_open());
        assert!(t.get(2).is_open());
        assert!(t.get(500) == FdState::Empty);
        assert!(t.get(1023) == FdState::Empty);
    }

    #[test]
    fn close_range_empty_range_returns_zero() {
        let mut t = FdTable::new();
        let stats = do_close_range(&mut t, 5, 10, 0).unwrap();
        assert_eq!(stats.affected, 0);
    }

    #[test]
    fn do_close_helper_works() {
        let mut t = table_with_fds(&[7]);
        assert_eq!(do_close(&mut t, 7), Ok(()));
        assert_eq!(t.get(7), FdState::Empty);
    }

    #[test]
    fn do_close_returns_not_found_for_empty() {
        let mut t = FdTable::new();
        assert_eq!(do_close(&mut t, 7), Err(Error::NotFound));
    }

    #[test]
    fn fd_table_open_count() {
        let mut t = FdTable::new();
        t.open(0).unwrap();
        t.open(1).unwrap();
        assert_eq!(t.open_count(), 2);
        t.close(0).unwrap();
        assert_eq!(t.open_count(), 1);
    }
}
