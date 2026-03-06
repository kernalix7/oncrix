// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `close_range(2)` extended syscall handler.
//!
//! This module extends the core `close_range` implementation in
//! [`crate::close_range`] with:
//!
//! - FD-table unshare before bulk-close (`CLOSE_RANGE_UNSHARE`)
//! - `O_CLOEXEC` bulk-set mode (`CLOSE_RANGE_CLOEXEC`)
//! - Efficient batch iteration with early termination
//! - Integration with the exec path for post-exec cleanup
//!
//! # Usage patterns
//!
//! ```text
//! // 1. Close all fds >= 3 (leave stdin/stdout/stderr):
//! close_range(3, u32::MAX, 0)
//!
//! // 2. Mark all fds >= 3 as close-on-exec:
//! close_range(3, u32::MAX, CLOSE_RANGE_CLOEXEC)
//!
//! // 3. Unshare fd table, then close 3..=9:
//! close_range(3, 9, CLOSE_RANGE_UNSHARE)
//! ```
//!
//! # Exec-path integration
//!
//! At `execve` time the kernel calls `do_close_on_exec()` to close all fds
//! with `O_CLOEXEC` set.  This is internally equivalent to:
//! `close_range(0, u32::MAX, CLOSE_RANGE_CLOEXEC)` followed by a flush.
//!
//! # References
//!
//! - Linux: `fs/file.c` — `__close_range()`, `do_close_on_exec()`
//! - `include/uapi/linux/close_range.h`
//! - man: `close_range(2)`

use oncrix_lib::{Error, Result};

// Re-export core items from the lower-level module.
pub use crate::close_range::{
    CLOSE_RANGE_CLOEXEC, CLOSE_RANGE_UNSHARE, CloseRangeStats, FdState, FdTable, MAX_OPEN_FILES,
    do_close, do_close_range,
};

// ---------------------------------------------------------------------------
// Extended statistics
// ---------------------------------------------------------------------------

/// Extended statistics from a `close_range` operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExtCloseRangeStats {
    /// Base statistics (affected count, unshare flag).
    pub base: CloseRangeStats,
    /// Number of fds skipped because they were already empty.
    pub skipped: u32,
    /// Highest fd number that was processed (or 0 if none).
    pub highest_processed: u32,
}

// ---------------------------------------------------------------------------
// Extended close_range entry point
// ---------------------------------------------------------------------------

/// Extended handler for `close_range(2)`.
///
/// Wraps the core handler with extended statistics gathering.
///
/// # Arguments
///
/// * `table` — File descriptor table.
/// * `first` — First fd in the range (inclusive).
/// * `last`  — Last fd in the range (inclusive); `u32::MAX` = all remaining.
/// * `flags` — [`CLOSE_RANGE_UNSHARE`] and/or [`CLOSE_RANGE_CLOEXEC`].
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `first > last` or unknown flags.
pub fn do_close_range_ext(
    table: &mut FdTable,
    first: u32,
    last: u32,
    flags: u32,
) -> Result<ExtCloseRangeStats> {
    let base = do_close_range(table, first, last, flags)?;

    // Compute skipped and highest_processed by scanning the affected range.
    let start = first as usize;
    let end = (last as usize).min(MAX_OPEN_FILES - 1);
    let total_slots = if start < MAX_OPEN_FILES {
        end.saturating_sub(start) + 1
    } else {
        0
    };
    let skipped = (total_slots as u32).saturating_sub(base.affected);
    let highest_processed = if base.affected > 0 { end as u32 } else { 0 };

    Ok(ExtCloseRangeStats {
        base,
        skipped,
        highest_processed,
    })
}

// ---------------------------------------------------------------------------
// Exec-path close-on-exec helper
// ---------------------------------------------------------------------------

/// Close all file descriptors with `O_CLOEXEC` set.
///
/// Called at `execve` time to close descriptors that should not be inherited
/// by the new program image.  Equivalent to iterating the entire fd table and
/// closing any slot in `FdState::OpenCloexec`.
///
/// # Returns
///
/// Number of file descriptors closed.
pub fn do_close_on_exec(table: &mut FdTable) -> u32 {
    let mut closed = 0u32;
    for fd in 0..MAX_OPEN_FILES {
        if table.get(fd) == FdState::OpenCloexec {
            // Ignore individual errors — already-closed fds are silently skipped.
            let _ = table.close(fd);
            closed += 1;
        }
    }
    closed
}

// ---------------------------------------------------------------------------
// Batch close helper
// ---------------------------------------------------------------------------

/// Close a specific list of file descriptor numbers.
///
/// Silently skips fds that are not open.  Returns the number of descriptors
/// that were actually closed.
///
/// # Arguments
///
/// * `table` — File descriptor table.
/// * `fds`   — Slice of fd numbers to close.
pub fn close_list(table: &mut FdTable, fds: &[u32]) -> u32 {
    let mut count = 0u32;
    for &fd in fds {
        if (fd as usize) < MAX_OPEN_FILES && table.get(fd as usize).is_open() {
            let _ = table.close(fd as usize);
            count += 1;
        }
    }
    count
}

// ---------------------------------------------------------------------------
// Post-fork cleanup
// ---------------------------------------------------------------------------

/// Unshare-and-mark scenario: used after `fork(2)` when the child needs to
/// close the parent's extra fds.
///
/// This closes all fds in `[first, last]` in the child's newly-copied table.
/// The table has already been duplicated by the fork path, so no explicit
/// unshare is required here.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `first > last`.
pub fn do_fork_close_range(table: &mut FdTable, first: u32, last: u32) -> Result<u32> {
    if first > last {
        return Err(Error::InvalidArgument);
    }
    let stats = do_close_range(table, first, last, 0)?;
    Ok(stats.affected)
}

// ---------------------------------------------------------------------------
// Guard range — protect a set of fds from bulk close
// ---------------------------------------------------------------------------

/// Guard a range of file descriptors from `close_range`.
///
/// The `[guard_first, guard_last]` range is excluded from the bulk-close
/// operation.  This is useful when a caller wants to close all fds except
/// a specific set.
///
/// This is implemented by calling `close_range` twice: once for
/// `[first, guard_first - 1]` and once for `[guard_last + 1, last]`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `first > last` or unknown flags.
pub fn do_close_range_guarded(
    table: &mut FdTable,
    first: u32,
    last: u32,
    guard_first: u32,
    guard_last: u32,
    flags: u32,
) -> Result<CloseRangeStats> {
    if first > last {
        return Err(Error::InvalidArgument);
    }

    let mut total = CloseRangeStats::default();

    // Close [first, guard_first - 1] if non-empty.
    if first < guard_first {
        let end = guard_first.saturating_sub(1);
        let s = do_close_range(table, first, end.min(last), flags)?;
        total.affected += s.affected;
        total.unshared |= s.unshared;
    }

    // Close [guard_last + 1, last] if non-empty.
    if guard_last < last {
        let start = guard_last.saturating_add(1);
        if start <= last {
            let s = do_close_range(table, start, last, flags)?;
            total.affected += s.affected;
            total.unshared |= s.unshared;
        }
    }

    Ok(total)
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

    // --- do_close_range_ext ---

    #[test]
    fn ext_basic_close() {
        let mut t = table_with_fds(&[3, 5, 10]);
        let s = do_close_range_ext(&mut t, 3, 10, 0).unwrap();
        assert_eq!(s.base.affected, 3);
        assert!(s.highest_processed > 0);
    }

    #[test]
    fn ext_skipped_count() {
        let mut t = table_with_fds(&[5]);
        // Range 3..=10 has 8 slots, only 1 is open → 7 skipped.
        let s = do_close_range_ext(&mut t, 3, 10, 0).unwrap();
        assert_eq!(s.skipped, 7);
    }

    #[test]
    fn ext_empty_range_zero_affected() {
        let mut t = FdTable::new();
        let s = do_close_range_ext(&mut t, 0, 100, 0).unwrap();
        assert_eq!(s.base.affected, 0);
        assert_eq!(s.highest_processed, 0);
    }

    // --- do_close_on_exec ---

    #[test]
    fn close_on_exec_closes_only_cloexec() {
        let mut t = FdTable::new();
        t.open(0).unwrap(); // no cloexec
        t.open(1).unwrap();
        t.set_cloexec(1, true).unwrap(); // cloexec
        t.open(2).unwrap();
        t.set_cloexec(2, true).unwrap(); // cloexec
        let closed = do_close_on_exec(&mut t);
        assert_eq!(closed, 2);
        assert!(t.get(0).is_open()); // preserved
        assert_eq!(t.get(1), FdState::Empty);
        assert_eq!(t.get(2), FdState::Empty);
    }

    #[test]
    fn close_on_exec_all_open_no_cloexec() {
        let mut t = table_with_fds(&[0, 1, 2]);
        let closed = do_close_on_exec(&mut t);
        assert_eq!(closed, 0);
        assert!(t.get(0).is_open());
    }

    // --- close_list ---

    #[test]
    fn close_list_closes_specified_fds() {
        let mut t = table_with_fds(&[3, 5, 7, 9]);
        let count = close_list(&mut t, &[3, 7]);
        assert_eq!(count, 2);
        assert_eq!(t.get(3), FdState::Empty);
        assert_eq!(t.get(7), FdState::Empty);
        assert!(t.get(5).is_open());
        assert!(t.get(9).is_open());
    }

    #[test]
    fn close_list_skips_empty_fds() {
        let mut t = FdTable::new();
        let count = close_list(&mut t, &[0, 1, 2]);
        assert_eq!(count, 0);
    }

    // --- do_fork_close_range ---

    #[test]
    fn fork_close_range_basic() {
        let mut t = table_with_fds(&[3, 4, 5]);
        let n = do_fork_close_range(&mut t, 3, 5).unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn fork_close_range_first_gt_last_rejected() {
        let mut t = FdTable::new();
        assert_eq!(
            do_fork_close_range(&mut t, 10, 5),
            Err(Error::InvalidArgument)
        );
    }

    // --- do_close_range_guarded ---

    #[test]
    fn guarded_close_skips_guard_range() {
        // Open fds 0, 1, 2, 3, 4, 5.
        let mut t = table_with_fds(&[0, 1, 2, 3, 4, 5]);
        // Close all except [2, 3].
        let s = do_close_range_guarded(&mut t, 0, 5, 2, 3, 0).unwrap();
        assert_eq!(s.affected, 4); // 0, 1, 4, 5
        assert_eq!(t.get(0), FdState::Empty);
        assert_eq!(t.get(1), FdState::Empty);
        assert!(t.get(2).is_open()); // guarded
        assert!(t.get(3).is_open()); // guarded
        assert_eq!(t.get(4), FdState::Empty);
        assert_eq!(t.get(5), FdState::Empty);
    }

    #[test]
    fn guarded_close_guard_covers_all() {
        let mut t = table_with_fds(&[0, 1, 2]);
        // Guard covers entire range — nothing should be closed.
        let s = do_close_range_guarded(&mut t, 0, 2, 0, 2, 0).unwrap();
        assert_eq!(s.affected, 0);
    }

    #[test]
    fn guarded_close_first_gt_last_rejected() {
        let mut t = FdTable::new();
        assert_eq!(
            do_close_range_guarded(&mut t, 10, 5, 6, 7, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn cloexec_mode_with_guarded_close() {
        let mut t = table_with_fds(&[0, 1, 2, 3]);
        // Set cloexec on all except guarded 1..=2.
        let s = do_close_range_guarded(&mut t, 0, 3, 1, 2, CLOSE_RANGE_CLOEXEC).unwrap();
        assert_eq!(s.affected, 2); // fds 0 and 3
        assert_eq!(t.get(0), FdState::OpenCloexec);
        assert_eq!(t.get(1), FdState::Open); // guarded
        assert_eq!(t.get(2), FdState::Open); // guarded
        assert_eq!(t.get(3), FdState::OpenCloexec);
    }
}
