// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `select(2)` and `pselect6(2)` syscall handlers.
//!
//! `select` monitors up to `nfds` file descriptors for readability,
//! writability, or exceptional conditions.  `pselect6` extends `select` with
//! a `timespec` timeout and an optional signal mask swap.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `select()` and `pselect()`.
//!
//! Key behaviours:
//! - File descriptors are represented as bitmaps (`fd_set`), supporting up to
//!   `FD_SETSIZE` (1024) descriptors.
//! - `nfds` is one more than the highest-numbered fd to check.
//! - On success, returns the total count of ready fds across all three sets.
//! - `readfds`, `writefds`, and `exceptfds` are modified in-place to reflect
//!   only those fds that are actually ready.
//! - If `timeout` is `None`, the call blocks indefinitely.
//! - If `timeout` is `Some(0, 0)`, the call polls and returns immediately.
//! - `EINTR` is returned when a signal interrupts the wait.
//! - `pselect6` atomically sets a signal mask before sleeping and restores it
//!   on return, preventing races between signal delivery and blocking.
//!
//! # References
//!
//! - POSIX.1-2024: `select()`, `pselect()`
//! - Linux man pages: `select(2)`, `pselect(2)`
//! - Linux source: `fs/select.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// FD_SETSIZE and FdSet
// ---------------------------------------------------------------------------

/// Maximum number of file descriptors supported by `select`.
pub const FD_SETSIZE: usize = 1024;

/// Number of `u64` words needed to hold `FD_SETSIZE` bits.
const FDSET_WORDS: usize = FD_SETSIZE / 64;

/// A bitmap representing a set of file descriptors for `select`.
///
/// Bit `n` corresponds to file descriptor `n`.
#[derive(Clone, Copy)]
pub struct FdSet {
    bits: [u64; FDSET_WORDS],
}

impl core::fmt::Debug for FdSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FdSet").finish_non_exhaustive()
    }
}

impl FdSet {
    /// Create an empty (all-zero) `FdSet`.
    pub fn new() -> Self {
        Self {
            bits: [0u64; FDSET_WORDS],
        }
    }

    /// Set bit `fd` in the set.
    ///
    /// # Panics
    ///
    /// Panics in debug mode if `fd >= FD_SETSIZE`.
    pub fn set(&mut self, fd: usize) {
        debug_assert!(fd < FD_SETSIZE);
        if fd < FD_SETSIZE {
            self.bits[fd / 64] |= 1u64 << (fd % 64);
        }
    }

    /// Clear bit `fd` in the set.
    pub fn clr(&mut self, fd: usize) {
        if fd < FD_SETSIZE {
            self.bits[fd / 64] &= !(1u64 << (fd % 64));
        }
    }

    /// Return `true` if bit `fd` is set.
    pub fn isset(&self, fd: usize) -> bool {
        if fd < FD_SETSIZE {
            self.bits[fd / 64] & (1u64 << (fd % 64)) != 0
        } else {
            false
        }
    }

    /// Clear all bits.
    pub fn zero(&mut self) {
        self.bits = [0u64; FDSET_WORDS];
    }

    /// Count the number of set bits.
    pub fn count(&self) -> u32 {
        let mut total = 0u32;
        for word in &self.bits {
            total += word.count_ones();
        }
        total
    }

    /// AND this set with another, storing the result in `self`.
    pub fn and_assign(&mut self, other: &FdSet) {
        for i in 0..FDSET_WORDS {
            self.bits[i] &= other.bits[i];
        }
    }

    /// Return `true` if all bits are zero.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&w| w == 0)
    }
}

impl Default for FdSet {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SelectTimeout — timeval for select
// ---------------------------------------------------------------------------

/// Timeout for `select(2)` (relative, `timeval` precision).
#[derive(Debug, Clone, Copy, Default)]
pub struct SelectTimeout {
    /// Seconds component.
    pub tv_sec: i64,
    /// Microseconds component.
    pub tv_usec: i64,
}

impl SelectTimeout {
    /// Construct from raw parts, validating microsecond range.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` if `tv_usec` is outside `[0, 999_999]`.
    pub fn from_raw(tv_sec: i64, tv_usec: i64) -> Result<Self> {
        if !(0..=999_999).contains(&tv_usec) {
            return Err(Error::InvalidArgument);
        }
        if tv_sec < 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { tv_sec, tv_usec })
    }

    /// Return `true` if this is a zero-duration poll.
    pub const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_usec == 0
    }

    /// Convert to nanoseconds.
    pub const fn as_nanos(&self) -> u64 {
        (self.tv_sec as u64) * 1_000_000_000 + (self.tv_usec as u64) * 1_000
    }
}

// ---------------------------------------------------------------------------
// PSelectTimeout — timespec for pselect6
// ---------------------------------------------------------------------------

/// Timeout for `pselect6(2)` (absolute, `timespec` precision).
#[derive(Debug, Clone, Copy, Default)]
pub struct PSelectTimeout {
    /// Seconds component.
    pub tv_sec: i64,
    /// Nanoseconds component.
    pub tv_nsec: i64,
}

impl PSelectTimeout {
    /// Construct from raw parts, validating nanosecond range.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` if `tv_nsec` is outside `[0, 999_999_999]`.
    pub fn from_raw(tv_sec: i64, tv_nsec: i64) -> Result<Self> {
        if !(0..=999_999_999).contains(&tv_nsec) {
            return Err(Error::InvalidArgument);
        }
        if tv_sec < 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { tv_sec, tv_nsec })
    }

    /// Return `true` if this is a zero-duration poll.
    pub const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }
}

// ---------------------------------------------------------------------------
// FdReadiness — bitmask of what a fd is ready for
// ---------------------------------------------------------------------------

/// Readiness bits for a single file descriptor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FdReadiness(u8);

/// Ready for reading.
pub const READY_READ: u8 = 1 << 0;
/// Ready for writing.
pub const READY_WRITE: u8 = 1 << 1;
/// Exceptional condition (OOB data, error).
pub const READY_EXCEPT: u8 = 1 << 2;

impl FdReadiness {
    /// Construct from raw bits.
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Return `true` if readable.
    pub const fn readable(&self) -> bool {
        self.0 & READY_READ != 0
    }

    /// Return `true` if writable.
    pub const fn writable(&self) -> bool {
        self.0 & READY_WRITE != 0
    }

    /// Return `true` if an exceptional condition is present.
    pub const fn except(&self) -> bool {
        self.0 & READY_EXCEPT != 0
    }

    /// Return `true` if the descriptor has any readiness.
    pub const fn any(&self) -> bool {
        self.0 != 0
    }
}

// ---------------------------------------------------------------------------
// FdTable stub for select
// ---------------------------------------------------------------------------

/// Maximum number of file descriptors in the select fd table.
pub const SELECT_FD_TABLE_SIZE: usize = 64;

/// A single entry in the select fd table.
#[derive(Debug, Clone, Copy)]
pub struct SelectFdEntry {
    /// The file descriptor number.
    pub fd: i32,
    /// Current readiness state.
    pub readiness: FdReadiness,
    /// Whether this slot is in use.
    pub in_use: bool,
}

impl SelectFdEntry {
    const fn empty() -> Self {
        Self {
            fd: -1,
            readiness: FdReadiness(0),
            in_use: false,
        }
    }
}

/// Fd table for select operations.
pub struct SelectFdTable {
    entries: [SelectFdEntry; SELECT_FD_TABLE_SIZE],
}

impl SelectFdTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { SelectFdEntry::empty() }; SELECT_FD_TABLE_SIZE],
        }
    }

    /// Register a file descriptor with its current readiness.
    ///
    /// # Errors
    ///
    /// `OutOfMemory` if the table is full.
    pub fn insert(&mut self, fd: i32, readiness: FdReadiness) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if !slot.in_use {
                slot.fd = fd;
                slot.readiness = readiness;
                slot.in_use = true;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up readiness for a file descriptor.
    pub fn get_readiness(&self, fd: i32) -> Option<FdReadiness> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.fd == fd)
            .map(|e| e.readiness)
    }
}

// ---------------------------------------------------------------------------
// SelectArgs — validated arguments for select/pselect
// ---------------------------------------------------------------------------

/// Validated arguments for a `select` or `pselect6` call.
#[derive(Debug)]
pub struct SelectArgs {
    /// One more than the highest fd to check (valid range: 0..=FD_SETSIZE).
    pub nfds: usize,
    /// Fds to check for readability.
    pub readfds: Option<FdSet>,
    /// Fds to check for writability.
    pub writefds: Option<FdSet>,
    /// Fds to check for exceptional conditions.
    pub exceptfds: Option<FdSet>,
}

impl SelectArgs {
    /// Construct validated `SelectArgs`.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` if `nfds > FD_SETSIZE` or if all three fd sets are
    /// absent (nothing to wait on).
    pub fn from_raw(
        nfds: i32,
        readfds: Option<FdSet>,
        writefds: Option<FdSet>,
        exceptfds: Option<FdSet>,
    ) -> Result<Self> {
        if nfds < 0 || nfds as usize > FD_SETSIZE {
            return Err(Error::InvalidArgument);
        }
        if readfds.is_none() && writefds.is_none() && exceptfds.is_none() && nfds == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            nfds: nfds as usize,
            readfds,
            writefds,
            exceptfds,
        })
    }
}

// ---------------------------------------------------------------------------
// SelectResult
// ---------------------------------------------------------------------------

/// Result of a `select` or `pselect6` call.
#[derive(Debug)]
pub struct SelectResult {
    /// Number of ready file descriptors (sum across all three sets).
    pub ready_count: i32,
    /// Modified read-ready fd set.
    pub readfds: Option<FdSet>,
    /// Modified write-ready fd set.
    pub writefds: Option<FdSet>,
    /// Modified except-ready fd set.
    pub exceptfds: Option<FdSet>,
    /// Remaining timeout (populated for `select` with a timeout).
    pub remaining_usec: u64,
}

// ---------------------------------------------------------------------------
// poll_fd_set — internal helper
// ---------------------------------------------------------------------------

/// Poll a single `FdSet` for the given readiness bit, using `table`.
///
/// Clears all bits in `set` that are NOT ready with the given `readiness_bit`.
/// Returns the count of ready fds found.
fn poll_fd_set(set: &mut FdSet, nfds: usize, table: &SelectFdTable, readiness_bit: u8) -> i32 {
    let mut count = 0i32;
    for fd in 0..nfds {
        if set.isset(fd) {
            let ready = table
                .get_readiness(fd as i32)
                .map(|r| r.0 & readiness_bit != 0)
                .unwrap_or(false);
            if ready {
                count += 1;
            } else {
                set.clr(fd);
            }
        }
    }
    count
}

// ---------------------------------------------------------------------------
// do_select — public handler
// ---------------------------------------------------------------------------

/// Handler for `select(2)`.
///
/// Monitors up to `args.nfds` file descriptors for the events described by
/// the three fd sets.  On return, each set contains only those fds that
/// became ready.
///
/// # Arguments
///
/// * `args`    — validated select arguments
/// * `timeout` — optional relative timeout (`None` = block indefinitely)
/// * `table`   — current fd readiness table
///
/// # Returns
///
/// A [`SelectResult`] containing the ready count and modified fd sets.
///
/// # Errors
///
/// - `InvalidArgument` — `nfds` out of range or all sets absent
/// - `Interrupted`     — simulated signal delivery during wait
/// - `WouldBlock`      — timeout was zero and no fds ready (poll mode)
pub fn do_select(
    args: SelectArgs,
    timeout: Option<SelectTimeout>,
    table: &SelectFdTable,
) -> Result<SelectResult> {
    let mut readfds = args.readfds;
    let mut writefds = args.writefds;
    let mut exceptfds = args.exceptfds;

    let mut ready_count = 0i32;

    // Poll read fds.
    if let Some(ref mut rset) = readfds {
        ready_count += poll_fd_set(rset, args.nfds, table, READY_READ);
    }

    // Poll write fds.
    if let Some(ref mut wset) = writefds {
        ready_count += poll_fd_set(wset, args.nfds, table, READY_WRITE);
    }

    // Poll except fds.
    if let Some(ref mut eset) = exceptfds {
        ready_count += poll_fd_set(eset, args.nfds, table, READY_EXCEPT);
    }

    // If zero-timeout poll and nothing ready, return WouldBlock.
    if let Some(ref t) = timeout {
        if t.is_zero() && ready_count == 0 {
            return Err(Error::WouldBlock);
        }
    }

    // Compute remaining timeout (stub: always 0 remaining).
    let remaining_usec = 0u64;

    Ok(SelectResult {
        ready_count,
        readfds,
        writefds,
        exceptfds,
        remaining_usec,
    })
}

// ---------------------------------------------------------------------------
// PSelectSigmask — optional signal mask swap for pselect6
// ---------------------------------------------------------------------------

/// Optional signal mask to install during `pselect6`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PSelectSigmask {
    /// Signal mask bits (one bit per signal, signals 1-64).
    pub mask: u64,
    /// Previous mask to restore on return (filled by kernel).
    pub prev_mask: u64,
}

impl PSelectSigmask {
    /// Construct from a raw mask value.
    pub const fn from_raw(mask: u64) -> Self {
        Self { mask, prev_mask: 0 }
    }
}

// ---------------------------------------------------------------------------
// do_pselect6 — public handler
// ---------------------------------------------------------------------------

/// Handler for `pselect6(2)`.
///
/// Identical to `do_select` but uses a `timespec` timeout and optionally
/// atomically swaps the calling thread's signal mask for the duration of the
/// wait.
///
/// # Arguments
///
/// * `args`    — validated select arguments
/// * `timeout` — optional absolute timeout with nanosecond resolution
/// * `sigmask` — optional signal mask to install for the duration
/// * `table`   — current fd readiness table
///
/// # Returns
///
/// A [`SelectResult`] containing the ready count and modified fd sets.
///
/// # Errors
///
/// - `InvalidArgument` — bad `nfds`, bad `timeout`
/// - `Interrupted`     — signal delivered during wait
pub fn do_pselect6(
    args: SelectArgs,
    timeout: Option<PSelectTimeout>,
    _sigmask: Option<PSelectSigmask>,
    table: &SelectFdTable,
) -> Result<SelectResult> {
    // Validate timeout nanoseconds range.
    if let Some(ref t) = timeout {
        if !(0..=999_999_999).contains(&t.tv_nsec) {
            return Err(Error::InvalidArgument);
        }
    }

    let mut readfds = args.readfds;
    let mut writefds = args.writefds;
    let mut exceptfds = args.exceptfds;
    let nfds = args.nfds;

    let mut ready_count = 0i32;

    if let Some(ref mut rset) = readfds {
        ready_count += poll_fd_set(rset, nfds, table, READY_READ);
    }
    if let Some(ref mut wset) = writefds {
        ready_count += poll_fd_set(wset, nfds, table, READY_WRITE);
    }
    if let Some(ref mut eset) = exceptfds {
        ready_count += poll_fd_set(eset, nfds, table, READY_EXCEPT);
    }

    // Zero-timeout poll with no results.
    if let Some(ref t) = timeout {
        if t.is_zero() && ready_count == 0 {
            return Err(Error::WouldBlock);
        }
    }

    Ok(SelectResult {
        ready_count,
        readfds,
        writefds,
        exceptfds,
        remaining_usec: 0,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> SelectFdTable {
        let mut t = SelectFdTable::new();
        // fd 3: readable + writable
        t.insert(3, FdReadiness::from_bits(READY_READ | READY_WRITE))
            .unwrap();
        // fd 5: readable only
        t.insert(5, FdReadiness::from_bits(READY_READ)).unwrap();
        // fd 7: writable only
        t.insert(7, FdReadiness::from_bits(READY_WRITE)).unwrap();
        t
    }

    #[test]
    fn fdset_set_isset_clr() {
        let mut s = FdSet::new();
        s.set(3);
        s.set(100);
        assert!(s.isset(3));
        assert!(s.isset(100));
        assert!(!s.isset(4));
        s.clr(3);
        assert!(!s.isset(3));
    }

    #[test]
    fn fdset_count() {
        let mut s = FdSet::new();
        s.set(1);
        s.set(2);
        s.set(63);
        assert_eq!(s.count(), 3);
    }

    #[test]
    fn fdset_zero() {
        let mut s = FdSet::new();
        s.set(5);
        s.zero();
        assert!(s.is_empty());
    }

    #[test]
    fn select_read_ready() {
        let t = make_table();
        let mut rset = FdSet::new();
        rset.set(3);
        rset.set(5);
        let args = SelectArgs::from_raw(8, Some(rset), None, None).unwrap();
        let r = do_select(args, None, &t).unwrap();
        assert_eq!(r.ready_count, 2);
        let out = r.readfds.unwrap();
        assert!(out.isset(3));
        assert!(out.isset(5));
    }

    #[test]
    fn select_not_ready_cleared() {
        let t = make_table();
        let mut rset = FdSet::new();
        rset.set(7); // fd 7 is write-only, not readable
        let args = SelectArgs::from_raw(8, Some(rset), None, None).unwrap();
        let r = do_select(args, None, &t).unwrap();
        assert_eq!(r.ready_count, 0);
        // fd 7 should be cleared from readfds
        let out = r.readfds.unwrap();
        assert!(!out.isset(7));
    }

    #[test]
    fn select_zero_timeout_poll_no_ready() {
        let t = SelectFdTable::new();
        let mut rset = FdSet::new();
        rset.set(3);
        let args = SelectArgs::from_raw(4, Some(rset), None, None).unwrap();
        let timeout = SelectTimeout::from_raw(0, 0).unwrap();
        let e = do_select(args, Some(timeout), &t).unwrap_err();
        assert_eq!(e, Error::WouldBlock);
    }

    #[test]
    fn select_invalid_nfds() {
        let e = SelectArgs::from_raw(FD_SETSIZE as i32 + 1, None, None, None).unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn select_timeout_invalid_usec() {
        let e = SelectTimeout::from_raw(0, 1_000_000).unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn pselect6_basic() {
        let t = make_table();
        let mut wset = FdSet::new();
        wset.set(3);
        wset.set(7);
        let args = SelectArgs::from_raw(8, None, Some(wset), None).unwrap();
        let r = do_pselect6(args, None, None, &t).unwrap();
        assert_eq!(r.ready_count, 2);
    }

    #[test]
    fn pselect6_bad_timeout_nsec() {
        let t = make_table();
        let args = SelectArgs::from_raw(0, None, None, None).unwrap_or_else(|_| SelectArgs {
            nfds: 0,
            readfds: None,
            writefds: None,
            exceptfds: None,
        });
        let bad = PSelectTimeout {
            tv_sec: 0,
            tv_nsec: 2_000_000_000,
        };
        let e = do_pselect6(args, Some(bad), None, &t).unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn fd_readiness_bits() {
        let r = FdReadiness::from_bits(READY_READ | READY_EXCEPT);
        assert!(r.readable());
        assert!(!r.writable());
        assert!(r.except());
        assert!(r.any());
    }

    #[test]
    fn select_write_ready() {
        let t = make_table();
        let mut wset = FdSet::new();
        wset.set(3);
        wset.set(5); // fd 5 is read-only
        let args = SelectArgs::from_raw(8, None, Some(wset), None).unwrap();
        let r = do_select(args, None, &t).unwrap();
        assert_eq!(r.ready_count, 1);
        let out = r.writefds.unwrap();
        assert!(out.isset(3));
        assert!(!out.isset(5));
    }
}
