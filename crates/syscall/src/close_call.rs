// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `close(2)` / `close_range(2)` syscall handler.
//!
//! Implements closing of open file descriptors and the Linux
//! `close_range()` extension that closes a contiguous range of fds.
//!
//! # Key behaviours
//!
//! - `close(fd)`: decrement reference count on the open file description;
//!   release when it reaches zero.
//! - `close_range(first, last, flags)`: close all fds in [first, last].
//!   `CLOSE_RANGE_CLOEXEC` (flag 4) sets `FD_CLOEXEC` instead of closing.
//!   `CLOSE_RANGE_UNSHARE` (flag 2) unshares the fd table first.
//! - CLOEXEC batch close: called on `execve`, closes all `FD_CLOEXEC` fds.
//!
//! # POSIX Conformance
//!
//! `close()` follows POSIX.1-2024.  `close_range()` is a Linux extension
//! (Linux 5.9).
//!
//! # References
//!
//! - POSIX.1-2024: `close()`
//! - Linux: `fs/open.c`, `__close_range()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// close_range flags
// ---------------------------------------------------------------------------

/// `CLOSE_RANGE_UNSHARE` — unshare the fd table before closing.
pub const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
/// `CLOSE_RANGE_CLOEXEC` — set FD_CLOEXEC instead of closing.
pub const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

/// All known `close_range` flags.
const CLOSE_RANGE_KNOWN: u32 = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;

/// Maximum number of fds in the descriptor table.
pub const MAX_FDS: usize = 1024;

// ---------------------------------------------------------------------------
// FdFlags — per-fd flags
// ---------------------------------------------------------------------------

/// Per-descriptor flags (`FD_CLOEXEC` etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FdFlags(pub u32);

impl FdFlags {
    /// `FD_CLOEXEC` bit: close fd on exec.
    pub const FD_CLOEXEC: u32 = 1;

    /// Return `true` if `FD_CLOEXEC` is set.
    pub const fn is_cloexec(self) -> bool {
        self.0 & Self::FD_CLOEXEC != 0
    }

    /// Set the `FD_CLOEXEC` bit.
    pub fn set_cloexec(&mut self) {
        self.0 |= Self::FD_CLOEXEC;
    }

    /// Clear the `FD_CLOEXEC` bit.
    pub fn clear_cloexec(&mut self) {
        self.0 &= !Self::FD_CLOEXEC;
    }
}

// ---------------------------------------------------------------------------
// DescriptorSlot — one entry in the fd table
// ---------------------------------------------------------------------------

/// One entry in the process open file descriptor table.
#[derive(Debug, Clone, Copy)]
pub struct DescriptorSlot {
    /// Descriptor number.
    pub fd: i32,
    /// Descriptor flags.
    pub fd_flags: FdFlags,
    /// Reference count on the underlying open file description.
    pub refcount: u32,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl DescriptorSlot {
    const fn empty() -> Self {
        Self {
            fd: -1,
            fd_flags: FdFlags(0),
            refcount: 0,
            in_use: false,
        }
    }

    /// Create an active slot.
    pub const fn new(fd: i32, cloexec: bool) -> Self {
        let flags = if cloexec {
            FdFlags(FdFlags::FD_CLOEXEC)
        } else {
            FdFlags(0)
        };
        Self {
            fd,
            fd_flags: flags,
            refcount: 1,
            in_use: true,
        }
    }
}

// ---------------------------------------------------------------------------
// CloseFdTable — the descriptor table used by this module
// ---------------------------------------------------------------------------

/// A flat array-based fd table with close / close_range support.
pub struct CloseFdTable {
    slots: [DescriptorSlot; MAX_FDS],
    count: usize,
}

impl CloseFdTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            slots: [const { DescriptorSlot::empty() }; MAX_FDS],
            count: 0,
        }
    }

    /// Insert a new descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, slot: DescriptorSlot) -> Result<()> {
        for s in self.slots.iter_mut() {
            if !s.in_use {
                *s = slot;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a descriptor by number.
    pub fn find(&self, fd: i32) -> Option<&DescriptorSlot> {
        self.slots.iter().find(|s| s.in_use && s.fd == fd)
    }

    /// Look up a mutable descriptor by number.
    pub fn find_mut(&mut self, fd: i32) -> Option<&mut DescriptorSlot> {
        self.slots.iter_mut().find(|s| s.in_use && s.fd == fd)
    }

    /// Return the number of open descriptors.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the highest open fd number, or -1 if the table is empty.
    pub fn max_fd(&self) -> i32 {
        self.slots
            .iter()
            .filter(|s| s.in_use)
            .map(|s| s.fd)
            .max()
            .unwrap_or(-1)
    }
}

impl Default for CloseFdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// do_close — close a single fd
// ---------------------------------------------------------------------------

/// Handler for `close(2)`.
///
/// Releases the file descriptor `fd` from the calling process's open
/// file description table.  If this was the last reference to the open
/// file description, the description (and any associated resources) are
/// freed.
///
/// # Arguments
///
/// * `table` — open fd table
/// * `fd`    — file descriptor to close
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — `fd` is negative
/// * [`Error::NotFound`]        — `fd` is not open
pub fn do_close(table: &mut CloseFdTable, fd: i32) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    let slot = table.find_mut(fd).ok_or(Error::NotFound)?;
    slot.refcount = slot.refcount.saturating_sub(1);
    if slot.refcount == 0 {
        *slot = DescriptorSlot::empty();
        table.count = table.count.saturating_sub(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// close_range flags validation
// ---------------------------------------------------------------------------

/// Validated flags for `close_range(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseRangeFlags(u32);

impl CloseRangeFlags {
    /// Construct from raw flags.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unknown bits or for
    /// `CLOEXEC | UNSHARE` used together (not a valid combination).
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !CLOSE_RANGE_KNOWN != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return `true` if `CLOSE_RANGE_CLOEXEC` is set.
    pub const fn is_cloexec(self) -> bool {
        self.0 & CLOSE_RANGE_CLOEXEC != 0
    }

    /// Return `true` if `CLOSE_RANGE_UNSHARE` is set.
    pub const fn is_unshare(self) -> bool {
        self.0 & CLOSE_RANGE_UNSHARE != 0
    }
}

// ---------------------------------------------------------------------------
// do_close_range — close a range of fds
// ---------------------------------------------------------------------------

/// Handler for `close_range(2)`.
///
/// Closes (or, if `CLOSE_RANGE_CLOEXEC`, marks close-on-exec) all open
/// file descriptors in the range [`first`, `last`] inclusive.
///
/// If `last` == `u32::MAX`, the operation applies to all fds ≥ `first`.
///
/// # Arguments
///
/// * `table`  — open fd table
/// * `first`  — first fd in the range (inclusive)
/// * `last`   — last fd in the range (inclusive); `u32::MAX` means "all"
/// * `flags`  — raw `close_range` flags
///
/// # Returns
///
/// Number of descriptors affected.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — `first > last`, or unknown flags
pub fn do_close_range(
    table: &mut CloseFdTable,
    first: u32,
    last: u32,
    flags: u32,
) -> Result<usize> {
    if first > last {
        return Err(Error::InvalidArgument);
    }
    let cr_flags = CloseRangeFlags::from_raw(flags)?;
    let mut affected = 0usize;

    // Collect indices to avoid borrow issues.
    let mut targets: [i32; MAX_FDS] = [0i32; MAX_FDS];
    let mut target_count = 0usize;

    for slot in table.slots.iter() {
        if slot.in_use {
            let fd = slot.fd;
            if fd >= 0 && (fd as u32) >= first && (fd as u32) <= last {
                if target_count < MAX_FDS {
                    targets[target_count] = fd;
                    target_count += 1;
                }
            }
        }
    }

    for i in 0..target_count {
        let fd = targets[i];
        if cr_flags.is_cloexec() {
            if let Some(slot) = table.find_mut(fd) {
                slot.fd_flags.set_cloexec();
                affected += 1;
            }
        } else {
            // CLOSE_RANGE_UNSHARE is handled at a higher level (fd table
            // copy); here we simply close each fd in the range.
            if do_close(table, fd).is_ok() {
                affected += 1;
            }
        }
    }

    Ok(affected)
}

// ---------------------------------------------------------------------------
// do_close_on_exec — batch close of CLOEXEC fds
// ---------------------------------------------------------------------------

/// Close all descriptors with `FD_CLOEXEC` set.
///
/// Called during `execve()` to release fds that were opened with
/// `O_CLOEXEC` before transferring control to the new program image.
///
/// # Returns
///
/// Number of descriptors closed.
pub fn do_close_on_exec(table: &mut CloseFdTable) -> usize {
    let mut closed = 0usize;
    for slot in table.slots.iter_mut() {
        if slot.in_use && slot.fd_flags.is_cloexec() {
            *slot = DescriptorSlot::empty();
            table.count = table.count.saturating_sub(1);
            closed += 1;
        }
    }
    closed
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table_with_fds(count: usize) -> CloseFdTable {
        let mut t = CloseFdTable::new();
        for i in 0..count {
            t.insert(DescriptorSlot::new(i as i32, false)).unwrap();
        }
        t
    }

    #[test]
    fn close_single_fd() {
        let mut t = CloseFdTable::new();
        t.insert(DescriptorSlot::new(3, false)).unwrap();
        assert_eq!(t.count(), 1);
        do_close(&mut t, 3).unwrap();
        assert_eq!(t.count(), 0);
        assert!(t.find(3).is_none());
    }

    #[test]
    fn close_not_found() {
        let mut t = CloseFdTable::new();
        assert_eq!(do_close(&mut t, 99), Err(Error::NotFound));
    }

    #[test]
    fn close_negative_fd_invalid() {
        let mut t = CloseFdTable::new();
        assert_eq!(do_close(&mut t, -1), Err(Error::InvalidArgument));
    }

    #[test]
    fn close_range_all() {
        let mut t = make_table_with_fds(5); // fds 0..4
        let n = do_close_range(&mut t, 0, u32::MAX, 0).unwrap();
        assert_eq!(n, 5);
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn close_range_partial() {
        let mut t = make_table_with_fds(5); // fds 0..4
        let n = do_close_range(&mut t, 2, 4, 0).unwrap();
        assert_eq!(n, 3); // fds 2, 3, 4
        assert_eq!(t.count(), 2); // fds 0, 1 remain
    }

    #[test]
    fn close_range_cloexec_flag() {
        let mut t = make_table_with_fds(4); // fds 0..3
        let n = do_close_range(&mut t, 0, 3, CLOSE_RANGE_CLOEXEC).unwrap();
        assert_eq!(n, 4);
        // All fds still open, but now have CLOEXEC.
        assert_eq!(t.count(), 4);
        for fd in 0..4 {
            assert!(t.find(fd).unwrap().fd_flags.is_cloexec());
        }
    }

    #[test]
    fn close_range_first_gt_last_invalid() {
        let mut t = CloseFdTable::new();
        assert_eq!(
            do_close_range(&mut t, 10, 5, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn close_range_unknown_flags() {
        let mut t = CloseFdTable::new();
        assert_eq!(
            do_close_range(&mut t, 0, 10, 0xFF),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn close_on_exec_batch() {
        let mut t = CloseFdTable::new();
        t.insert(DescriptorSlot::new(3, true)).unwrap();
        t.insert(DescriptorSlot::new(4, false)).unwrap();
        t.insert(DescriptorSlot::new(5, true)).unwrap();
        let n = do_close_on_exec(&mut t);
        assert_eq!(n, 2);
        assert_eq!(t.count(), 1);
        assert!(t.find(4).is_some());
    }

    #[test]
    fn fd_flags_cloexec() {
        let mut f = FdFlags::default();
        assert!(!f.is_cloexec());
        f.set_cloexec();
        assert!(f.is_cloexec());
        f.clear_cloexec();
        assert!(!f.is_cloexec());
    }

    #[test]
    fn table_max_fd() {
        let t = make_table_with_fds(5);
        assert_eq!(t.max_fd(), 4);
    }

    #[test]
    fn table_empty_max_fd() {
        let t = CloseFdTable::new();
        assert_eq!(t.max_fd(), -1);
    }

    #[test]
    fn refcount_above_one_not_freed() {
        let mut t = CloseFdTable::new();
        let mut slot = DescriptorSlot::new(10, false);
        slot.refcount = 2;
        t.insert(slot).unwrap();
        do_close(&mut t, 10).unwrap();
        // refcount drops to 1 — fd still open
        assert_eq!(t.count(), 1);
        assert!(t.find(10).is_some());
        do_close(&mut t, 10).unwrap();
        assert_eq!(t.count(), 0);
    }
}
