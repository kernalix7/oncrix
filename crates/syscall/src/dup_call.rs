// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `dup(2)`, `dup2(2)`, and `dup3(2)` syscall handlers.
//!
//! These syscalls duplicate an open file descriptor, creating a new descriptor
//! that refers to the same open file description.  The three variants differ in
//! how the new descriptor number is chosen and what flags are applied:
//!
//! | Syscall  | New fd      | Flags support             |
//! |----------|-------------|---------------------------|
//! | `dup`    | Lowest free | None                      |
//! | `dup2`   | Specified   | None (closes target first) |
//! | `dup3`   | Specified   | `O_CLOEXEC`               |
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `dup()` and `dup2()` specifications.  `dup3` is a
//! Linux extension adding the `O_CLOEXEC` flag.
//!
//! Key behaviours:
//! - The new descriptor shares the same open file description (offset, mode,
//!   status flags) as the old one.
//! - `dup2` is a no-op when `oldfd == newfd` (returns `newfd`).
//! - `dup3` returns `EINVAL` when `oldfd == newfd`.
//! - `dup3` returns `EINVAL` if flags other than `O_CLOEXEC` are specified.
//! - All variants return `EBADF` if `oldfd` is not a valid open descriptor.
//! - `dup2`/`dup3` return `EBADF` if `newfd` is out of range.
//!
//! # References
//!
//! - POSIX.1-2024: `dup()`, `dup2()`
//! - Linux man pages: `dup(2)`, `dup2(2)`, `dup3(2)`
//! - Linux source: `fs/file.c` (`do_dup2`, `ksys_dup`, `__sys_dup3`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of file descriptors per process.
pub const MAX_OPEN_FDS: usize = 1024;

/// Flag: set close-on-exec on the new file descriptor.
pub const O_CLOEXEC: u32 = 0x80000;

/// All valid `dup3` flag bits.
const DUP3_VALID_FLAGS: u32 = O_CLOEXEC;

// ---------------------------------------------------------------------------
// File descriptor state
// ---------------------------------------------------------------------------

/// State of a single file descriptor slot in the process descriptor table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdSlot {
    /// Slot is empty — no open file description attached.
    Empty,
    /// Slot is open; `O_CLOEXEC` is NOT set.
    Open,
    /// Slot is open; `O_CLOEXEC` IS set.
    OpenCloexec,
}

impl FdSlot {
    /// Returns `true` if this slot holds an open file description.
    pub const fn is_open(self) -> bool {
        matches!(self, FdSlot::Open | FdSlot::OpenCloexec)
    }

    /// Returns `true` if `O_CLOEXEC` is set on this slot.
    pub const fn is_cloexec(self) -> bool {
        matches!(self, FdSlot::OpenCloexec)
    }
}

// ---------------------------------------------------------------------------
// Descriptor table
// ---------------------------------------------------------------------------

/// Per-process open file descriptor table.
///
/// Holds up to [`MAX_OPEN_FDS`] slots.  In the real kernel this maps to
/// `struct files_struct` / `struct fdtable`.
pub struct DupFdTable {
    slots: [FdSlot; MAX_OPEN_FDS],
    /// Cached count of open file descriptors.
    open_count: usize,
}

impl DupFdTable {
    /// Create a new, empty file descriptor table.
    pub const fn new() -> Self {
        Self {
            slots: [FdSlot::Empty; MAX_OPEN_FDS],
            open_count: 0,
        }
    }

    /// Return the state of file descriptor `fd`.
    ///
    /// Returns `FdSlot::Empty` for any `fd >= MAX_OPEN_FDS`.
    pub fn get(&self, fd: usize) -> FdSlot {
        if fd < MAX_OPEN_FDS {
            self.slots[fd]
        } else {
            FdSlot::Empty
        }
    }

    /// Open (or replace) slot `fd` with the given state.
    ///
    /// Returns `Err(InvalidArgument)` if `fd >= MAX_OPEN_FDS`.
    pub fn set(&mut self, fd: usize, state: FdSlot) -> Result<()> {
        if fd >= MAX_OPEN_FDS {
            return Err(Error::InvalidArgument);
        }
        if !self.slots[fd].is_open() && state.is_open() {
            self.open_count += 1;
        } else if self.slots[fd].is_open() && !state.is_open() {
            self.open_count -= 1;
        }
        self.slots[fd] = state;
        Ok(())
    }

    /// Mark file descriptor `fd` as open (without `O_CLOEXEC`).
    pub fn open(&mut self, fd: usize) -> Result<()> {
        self.set(fd, FdSlot::Open)
    }

    /// Close file descriptor `fd`.
    ///
    /// Returns `Err(NotFound)` if `fd` is not open.
    pub fn close(&mut self, fd: usize) -> Result<()> {
        if fd >= MAX_OPEN_FDS || !self.slots[fd].is_open() {
            return Err(Error::NotFound);
        }
        self.slots[fd] = FdSlot::Empty;
        self.open_count -= 1;
        Ok(())
    }

    /// Return the lowest-numbered empty slot, or `None` if table is full.
    pub fn find_lowest_free(&self) -> Option<usize> {
        self.slots.iter().position(|s| !s.is_open())
    }

    /// Return the number of currently open file descriptors.
    pub const fn open_count(&self) -> usize {
        self.open_count
    }
}

// ---------------------------------------------------------------------------
// Result type for dup operations
// ---------------------------------------------------------------------------

/// Result returned by `do_dup`, `do_dup2`, and `do_dup3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DupResult {
    /// The new file descriptor number.
    pub new_fd: i32,
    /// Whether `O_CLOEXEC` is set on the new descriptor.
    pub cloexec: bool,
    /// Whether an existing descriptor was closed (only relevant for `dup2`/`dup3`).
    pub closed_existing: bool,
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `dup(2)`.
///
/// Duplicates `oldfd` to the lowest-numbered available file descriptor.
/// The new descriptor does NOT have `O_CLOEXEC` set, even if `oldfd` does.
///
/// # Errors
///
/// - `Error::NotFound` — `oldfd` is not an open file descriptor (`EBADF`).
/// - `Error::OutOfMemory` — No free file descriptor slots remain (`EMFILE`).
///
/// # POSIX conformance
///
/// The new descriptor shares the same open file description as `oldfd`,
/// including any file status flags.  `FD_CLOEXEC` is NOT inherited.
pub fn do_dup(table: &mut DupFdTable, oldfd: i32) -> Result<DupResult> {
    let old = validate_open_fd(table, oldfd)?;

    let new_idx = table.find_lowest_free().ok_or(Error::OutOfMemory)?;

    // The new fd is always opened without O_CLOEXEC regardless of oldfd.
    table.set(
        new_idx,
        if old.is_cloexec() {
            FdSlot::Open
        } else {
            FdSlot::Open
        },
    )?;
    let _ = old;

    Ok(DupResult {
        new_fd: new_idx as i32,
        cloexec: false,
        closed_existing: false,
    })
}

/// Handler for `dup2(2)`.
///
/// Duplicates `oldfd` to `newfd`.  If `newfd` is already open, it is
/// silently closed first (atomically from the caller's perspective).
/// If `oldfd == newfd` and `oldfd` is open, the call is a no-op.
///
/// # Errors
///
/// - `Error::NotFound` — `oldfd` is not an open file descriptor (`EBADF`).
/// - `Error::InvalidArgument` — `newfd` is out of the valid range (`EBADF`).
///
/// # POSIX conformance
///
/// POSIX specifies that `FD_CLOEXEC` is cleared on `newfd` — the new
/// descriptor will NOT be closed-on-exec even if `oldfd` is.
pub fn do_dup2(table: &mut DupFdTable, oldfd: i32, newfd: i32) -> Result<DupResult> {
    validate_open_fd(table, oldfd)?;
    let new_idx = validate_fd_range(newfd)?;

    // POSIX: if oldfd == newfd and oldfd is open, return newfd unchanged.
    if oldfd == newfd {
        return Ok(DupResult {
            new_fd: newfd,
            cloexec: table.get(new_idx).is_cloexec(),
            closed_existing: false,
        });
    }

    let closed_existing = table.get(new_idx).is_open();

    // Close newfd if it is currently open.
    if closed_existing {
        table.close(new_idx)?;
    }

    // Install without O_CLOEXEC — POSIX mandates FD_CLOEXEC is cleared.
    table.set(new_idx, FdSlot::Open)?;

    Ok(DupResult {
        new_fd: newfd,
        cloexec: false,
        closed_existing,
    })
}

/// Handler for `dup3(2)`.
///
/// Like `dup2`, but additionally allows setting `O_CLOEXEC` on the new
/// descriptor via the `flags` argument.  Unlike `dup2`, returns `EINVAL`
/// when `oldfd == newfd`.
///
/// # Arguments
///
/// * `table`  — The calling process's file descriptor table.
/// * `oldfd`  — Source file descriptor to duplicate.
/// * `newfd`  — Desired file descriptor number for the duplicate.
/// * `flags`  — Must be `0` or `O_CLOEXEC`; other bits return `EINVAL`.
///
/// # Errors
///
/// - `Error::NotFound` — `oldfd` is not an open file descriptor (`EBADF`).
/// - `Error::InvalidArgument` — `newfd` is out of range, or `oldfd == newfd`,
///   or unknown flag bits are set (`EBADF` / `EINVAL`).
///
/// # POSIX / Linux conformance
///
/// `dup3` is a Linux extension (not in POSIX).  It was introduced to allow
/// atomic `dup2` + `O_CLOEXEC` without a separate `fcntl` call in
/// multi-threaded programs.
pub fn do_dup3(table: &mut DupFdTable, oldfd: i32, newfd: i32, flags: u32) -> Result<DupResult> {
    // Reject unknown flags.
    if flags & !DUP3_VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }

    validate_open_fd(table, oldfd)?;
    let new_idx = validate_fd_range(newfd)?;

    // dup3 returns EINVAL when oldfd == newfd (unlike dup2 which is a no-op).
    if oldfd == newfd {
        return Err(Error::InvalidArgument);
    }

    let closed_existing = table.get(new_idx).is_open();

    // Close newfd if currently open.
    if closed_existing {
        table.close(new_idx)?;
    }

    let cloexec = flags & O_CLOEXEC != 0;
    let new_state = if cloexec {
        FdSlot::OpenCloexec
    } else {
        FdSlot::Open
    };
    table.set(new_idx, new_state)?;

    Ok(DupResult {
        new_fd: newfd,
        cloexec,
        closed_existing,
    })
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that `fd` is non-negative, in range, and currently open.
///
/// Returns the current slot state on success or `Err(NotFound)` on failure.
fn validate_open_fd(table: &DupFdTable, fd: i32) -> Result<FdSlot> {
    if fd < 0 {
        return Err(Error::NotFound);
    }
    let idx = fd as usize;
    let slot = table.get(idx);
    if !slot.is_open() {
        return Err(Error::NotFound);
    }
    Ok(slot)
}

/// Validate that `fd` is a non-negative value within descriptor range.
///
/// Returns the `usize` index on success or `Err(InvalidArgument)` on failure.
fn validate_fd_range(fd: i32) -> Result<usize> {
    if fd < 0 || fd as usize >= MAX_OPEN_FDS {
        return Err(Error::InvalidArgument);
    }
    Ok(fd as usize)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table(open_fds: &[usize]) -> DupFdTable {
        let mut t = DupFdTable::new();
        for &fd in open_fds {
            t.open(fd).unwrap();
        }
        t
    }

    // --- dup ---

    #[test]
    fn dup_returns_lowest_free() {
        let mut t = make_table(&[0, 1, 2]);
        let r = do_dup(&mut t, 2).unwrap();
        assert_eq!(r.new_fd, 3);
        assert!(!r.cloexec);
        assert!(!r.closed_existing);
    }

    #[test]
    fn dup_rejects_closed_fd() {
        let mut t = DupFdTable::new();
        assert_eq!(do_dup(&mut t, 0), Err(Error::NotFound));
    }

    #[test]
    fn dup_rejects_negative_fd() {
        let mut t = DupFdTable::new();
        assert_eq!(do_dup(&mut t, -1), Err(Error::NotFound));
    }

    #[test]
    fn dup_clears_cloexec_on_new_fd() {
        // Open fd 0 with cloexec, dup should not inherit cloexec.
        let mut t = DupFdTable::new();
        t.set(0, FdSlot::OpenCloexec).unwrap();
        let r = do_dup(&mut t, 0).unwrap();
        assert!(!r.cloexec);
    }

    // --- dup2 ---

    #[test]
    fn dup2_duplicates_to_specified_fd() {
        let mut t = make_table(&[3]);
        let r = do_dup2(&mut t, 3, 7).unwrap();
        assert_eq!(r.new_fd, 7);
        assert!(!r.cloexec);
        assert!(!r.closed_existing);
        assert!(t.get(7).is_open());
    }

    #[test]
    fn dup2_closes_existing_target() {
        let mut t = make_table(&[3, 7]);
        let r = do_dup2(&mut t, 3, 7).unwrap();
        assert_eq!(r.new_fd, 7);
        assert!(r.closed_existing);
        assert!(t.get(7).is_open()); // still open after dup2
    }

    #[test]
    fn dup2_noop_when_same_fd() {
        let mut t = make_table(&[5]);
        let r = do_dup2(&mut t, 5, 5).unwrap();
        assert_eq!(r.new_fd, 5);
        assert!(!r.closed_existing);
    }

    #[test]
    fn dup2_rejects_closed_oldfd() {
        let mut t = DupFdTable::new();
        assert_eq!(do_dup2(&mut t, 0, 1), Err(Error::NotFound));
    }

    #[test]
    fn dup2_rejects_out_of_range_newfd() {
        let mut t = make_table(&[0]);
        assert_eq!(
            do_dup2(&mut t, 0, MAX_OPEN_FDS as i32),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn dup2_clears_cloexec_on_target() {
        let mut t = DupFdTable::new();
        t.set(0, FdSlot::OpenCloexec).unwrap();
        t.set(5, FdSlot::OpenCloexec).unwrap();
        let r = do_dup2(&mut t, 0, 5).unwrap();
        // POSIX: FD_CLOEXEC cleared on new fd
        assert!(!r.cloexec);
        assert_eq!(t.get(5), FdSlot::Open);
    }

    // --- dup3 ---

    #[test]
    fn dup3_without_flags() {
        let mut t = make_table(&[2]);
        let r = do_dup3(&mut t, 2, 9, 0).unwrap();
        assert_eq!(r.new_fd, 9);
        assert!(!r.cloexec);
        assert!(t.get(9).is_open());
        assert!(!t.get(9).is_cloexec());
    }

    #[test]
    fn dup3_with_cloexec_flag() {
        let mut t = make_table(&[2]);
        let r = do_dup3(&mut t, 2, 9, O_CLOEXEC).unwrap();
        assert_eq!(r.new_fd, 9);
        assert!(r.cloexec);
        assert_eq!(t.get(9), FdSlot::OpenCloexec);
    }

    #[test]
    fn dup3_rejects_same_fd() {
        let mut t = make_table(&[5]);
        assert_eq!(do_dup3(&mut t, 5, 5, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn dup3_rejects_unknown_flags() {
        let mut t = make_table(&[0]);
        assert_eq!(do_dup3(&mut t, 0, 1, 0xFF), Err(Error::InvalidArgument));
    }

    #[test]
    fn dup3_closes_existing_target() {
        let mut t = make_table(&[0, 4]);
        let r = do_dup3(&mut t, 0, 4, 0).unwrap();
        assert!(r.closed_existing);
        assert!(t.get(4).is_open());
    }

    #[test]
    fn dup3_rejects_closed_oldfd() {
        let mut t = DupFdTable::new();
        assert_eq!(do_dup3(&mut t, 0, 1, 0), Err(Error::NotFound));
    }

    // --- DupFdTable helpers ---

    #[test]
    fn fd_table_find_lowest_free() {
        let mut t = make_table(&[0, 1, 3]);
        assert_eq!(t.find_lowest_free(), Some(2));
        t.open(2).unwrap();
        assert_eq!(t.find_lowest_free(), Some(4));
    }

    #[test]
    fn fd_table_open_count() {
        let mut t = DupFdTable::new();
        t.open(0).unwrap();
        t.open(1).unwrap();
        assert_eq!(t.open_count(), 2);
        t.close(0).unwrap();
        assert_eq!(t.open_count(), 1);
    }
}
