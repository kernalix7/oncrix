// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `utimensat(2)` and `futimesat(2)` syscall handlers.
//!
//! These syscalls change the access time (`atime`) and modification time
//! (`mtime`) of a file.
//!
//! `utimensat(dirfd, path, times[2], flags)` — the modern nanosecond-precision
//!   interface.  `times[0]` is the new `atime`; `times[1]` is the new `mtime`.
//!
//! `futimesat(dirfd, path, times[2])` — the older microsecond-precision
//!   interface, deprecated in favour of `utimensat`.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `utimensat()`.  `futimesat` is a Linux extension
//! (not in POSIX), included here for Linux compatibility.
//!
//! Key behaviours:
//! - `UTIME_NOW`  (tv_nsec = 1073741823): set to the current time.
//! - `UTIME_OMIT` (tv_nsec = 1073741822): leave unchanged.
//! - If `times` is `None` (null pointer), both timestamps are set to NOW.
//! - `tv_nsec` must be in `[0, 999_999_999]` unless it is `UTIME_NOW` or
//!   `UTIME_OMIT`.
//! - `AT_SYMLINK_NOFOLLOW`: update the symlink itself, not its target.
//! - `ctime` is always updated to the current time when a timestamp changes.
//! - Permission rule:
//!   - Setting to an arbitrary time: caller must own the file or have
//!     `CAP_FOWNER`.
//!   - Setting to the current time (`UTIME_NOW` / null `times`): caller must
//!     own the file, or have `CAP_FOWNER`, or have write permission.
//!
//! # References
//!
//! - POSIX.1-2024: `utimensat()`
//! - Linux man pages: `utimensat(2)`, `futimesat(2)`, `utimes(2)`
//! - Linux source: `fs/utimes.c` `do_utimes()`, `utimes_common()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Special tv_nsec values
// ---------------------------------------------------------------------------

/// Special `tv_nsec` value: set timestamp to the current time.
pub const UTIME_NOW: i64 = 0x3FFF_FFFE;
/// Special `tv_nsec` value: leave timestamp unchanged.
pub const UTIME_OMIT: i64 = 0x3FFF_FFFD;

/// Maximum valid nanosecond value.
pub const NSEC_MAX: i64 = 999_999_999;

// ---------------------------------------------------------------------------
// AT flags
// ---------------------------------------------------------------------------

/// `dirfd` value meaning "use the current working directory".
pub const AT_FDCWD: i32 = -100;
/// Flag: if the final path component is a symlink, update the symlink itself.
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
/// Flag: if `pathname` is empty, operate on `dirfd` itself.
pub const AT_EMPTY_PATH: i32 = 0x1000;

/// All valid flags for `utimensat`.
const UTIMENSAT_VALID_FLAGS: i32 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

// ---------------------------------------------------------------------------
// Timespec
// ---------------------------------------------------------------------------

/// A POSIX `timespec` structure — seconds + nanoseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timespec {
    /// Seconds since the epoch.
    pub tv_sec: i64,
    /// Nanoseconds sub-second component.
    pub tv_nsec: i64,
}

impl Timespec {
    /// Construct a `Timespec` from raw values.
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }

    /// Return `true` if `tv_nsec` is the `UTIME_NOW` sentinel.
    pub const fn is_now(&self) -> bool {
        self.tv_nsec == UTIME_NOW
    }

    /// Return `true` if `tv_nsec` is the `UTIME_OMIT` sentinel.
    pub const fn is_omit(&self) -> bool {
        self.tv_nsec == UTIME_OMIT
    }

    /// Return `true` if this is a normal timestamp (not NOW or OMIT).
    pub const fn is_normal(&self) -> bool {
        !self.is_now() && !self.is_omit()
    }

    /// Validate a normal (non-sentinel) `Timespec`.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` if `tv_nsec` is outside `[0, NSEC_MAX]`.
    pub fn validate_normal(&self) -> Result<()> {
        if self.is_now() || self.is_omit() {
            return Ok(());
        }
        if !(0..=NSEC_MAX).contains(&self.tv_nsec) {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Timeval — microsecond-precision timestamp for futimesat
// ---------------------------------------------------------------------------

/// A `timeval` structure — seconds + microseconds.
#[derive(Debug, Clone, Copy, Default)]
pub struct Timeval {
    /// Seconds since the epoch.
    pub tv_sec: i64,
    /// Microseconds sub-second component.
    pub tv_usec: i64,
}

impl Timeval {
    /// Convert a `Timeval` to a `Timespec`.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` if `tv_usec` is outside `[0, 999_999]`.
    pub fn to_timespec(&self) -> Result<Timespec> {
        if !(0..=999_999).contains(&self.tv_usec) {
            return Err(Error::InvalidArgument);
        }
        Ok(Timespec::new(self.tv_sec, self.tv_usec * 1_000))
    }
}

// ---------------------------------------------------------------------------
// Inode type
// ---------------------------------------------------------------------------

/// Inode types for utimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeType {
    /// Regular file.
    RegularFile,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Block device.
    BlockDevice,
    /// Character device.
    CharDevice,
    /// Named pipe.
    Fifo,
    /// Unix domain socket.
    Socket,
}

// ---------------------------------------------------------------------------
// Inode stub
// ---------------------------------------------------------------------------

/// Stub inode for utimes operations.
#[derive(Debug, Clone, Copy)]
pub struct Inode {
    /// Inode number.
    pub ino: u64,
    /// Inode type.
    pub kind: InodeType,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Permission bits (lower 9 bits for ugo rwx).
    pub mode: u16,
    /// Last access time.
    pub atime: Timespec,
    /// Last modification time.
    pub mtime: Timespec,
    /// Last status-change time.
    pub ctime: Timespec,
}

impl Inode {
    /// Return `true` if `caller_uid` has write permission on this inode.
    pub const fn writable_by(&self, caller_uid: u32) -> bool {
        caller_uid == 0 || self.uid == caller_uid || (self.mode & 0o200 != 0)
    }

    /// Return `true` if `caller_uid` owns this inode or is root.
    pub const fn owned_by(&self, caller_uid: u32) -> bool {
        caller_uid == 0 || self.uid == caller_uid
    }
}

// ---------------------------------------------------------------------------
// FdEntry stub
// ---------------------------------------------------------------------------

/// An open file descriptor for futimes/utimensat.
#[derive(Debug, Clone, Copy)]
pub struct FdEntry {
    /// Numeric fd.
    pub fd: i32,
    /// Index into the inode table.
    pub inode_idx: usize,
    /// Whether this slot is in use.
    pub in_use: bool,
}

impl FdEntry {
    const fn empty() -> Self {
        Self {
            fd: -1,
            inode_idx: 0,
            in_use: false,
        }
    }
}

// ---------------------------------------------------------------------------
// UtimesTable — stub inode/fd store
// ---------------------------------------------------------------------------

/// Maximum inodes.
pub const MAX_INODES: usize = 64;
/// Maximum file descriptors.
pub const MAX_FDS: usize = 64;

/// Combined inode + fd table for utimes.
pub struct UtimesTable {
    inodes: [Inode; MAX_INODES],
    inode_paths: [[u8; 256]; MAX_INODES],
    inode_path_lens: [usize; MAX_INODES],
    inode_used: [bool; MAX_INODES],
    fds: [FdEntry; MAX_FDS],
}

impl UtimesTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        const EMPTY_INODE: Inode = Inode {
            ino: 0,
            kind: InodeType::RegularFile,
            uid: 0,
            gid: 0,
            mode: 0,
            atime: Timespec::new(0, 0),
            mtime: Timespec::new(0, 0),
            ctime: Timespec::new(0, 0),
        };
        Self {
            inodes: [EMPTY_INODE; MAX_INODES],
            inode_paths: [[0u8; 256]; MAX_INODES],
            inode_path_lens: [0usize; MAX_INODES],
            inode_used: [false; MAX_INODES],
            fds: [const { FdEntry::empty() }; MAX_FDS],
        }
    }

    /// Insert an inode with an associated path.
    ///
    /// # Errors
    ///
    /// `OutOfMemory` if full; `InvalidArgument` if path is too long.
    pub fn insert_inode(&mut self, path: &[u8], inode: Inode) -> Result<usize> {
        if path.len() > 256 {
            return Err(Error::InvalidArgument);
        }
        for (i, used) in self.inode_used.iter_mut().enumerate() {
            if !*used {
                *used = true;
                self.inodes[i] = inode;
                self.inode_paths[i][..path.len()].copy_from_slice(path);
                self.inode_path_lens[i] = path.len();
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an inode index by path.
    pub fn find_by_path(&self, path: &[u8]) -> Option<usize> {
        for (i, used) in self.inode_used.iter().enumerate() {
            if *used && &self.inode_paths[i][..self.inode_path_lens[i]] == path {
                return Some(i);
            }
        }
        None
    }

    /// Get a reference to an inode.
    pub fn inode(&self, idx: usize) -> Option<&Inode> {
        if idx < MAX_INODES && self.inode_used[idx] {
            Some(&self.inodes[idx])
        } else {
            None
        }
    }

    /// Get a mutable reference to an inode.
    pub fn inode_mut(&mut self, idx: usize) -> Option<&mut Inode> {
        if idx < MAX_INODES && self.inode_used[idx] {
            Some(&mut self.inodes[idx])
        } else {
            None
        }
    }

    /// Insert an open file descriptor.
    pub fn insert_fd(&mut self, entry: FdEntry) -> Result<()> {
        for slot in self.fds.iter_mut() {
            if !slot.in_use {
                *slot = entry;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a `FdEntry` by fd number.
    pub fn find_fd(&self, fd: i32) -> Option<&FdEntry> {
        self.fds.iter().find(|e| e.in_use && e.fd == fd)
    }
}

// ---------------------------------------------------------------------------
// Permission check
// ---------------------------------------------------------------------------

/// Check whether `caller_uid` is allowed to change timestamps.
///
/// POSIX rules:
/// - Setting to arbitrary times: must own the file or have `CAP_FOWNER`.
/// - Setting to current time (`UTIME_NOW` or null `times`): must own, have
///   `CAP_FOWNER`, or have write permission.
///
/// Returns `Ok(())` or `Err(PermissionDenied)`.
fn check_utimes_permission(
    inode: &Inode,
    new_atime: &Timespec,
    new_mtime: &Timespec,
    caller_uid: u32,
    times_null: bool,
) -> Result<()> {
    let now_only = times_null
        || (new_atime.is_now() && new_mtime.is_now())
        || (new_atime.is_omit() && new_mtime.is_now())
        || (new_atime.is_now() && new_mtime.is_omit())
        || (new_atime.is_omit() && new_mtime.is_omit());

    if inode.owned_by(caller_uid) {
        return Ok(());
    }

    if now_only && inode.writable_by(caller_uid) {
        return Ok(());
    }

    Err(Error::PermissionDenied)
}

// ---------------------------------------------------------------------------
// apply_utimes_validated — inner implementation
// ---------------------------------------------------------------------------

/// Apply validated timestamp changes to an inode.
///
/// Handles `UTIME_NOW`, `UTIME_OMIT`, and normal timestamp values.
/// Always updates `ctime` to `now` when any change is made.
fn apply_utimes_validated(
    table: &mut UtimesTable,
    inode_idx: usize,
    new_atime: &Timespec,
    new_mtime: &Timespec,
    now: &Timespec,
) -> Result<()> {
    let inode = table.inode_mut(inode_idx).ok_or(Error::NotFound)?;

    let mut changed = false;

    // Update atime.
    if new_atime.is_now() {
        inode.atime = *now;
        changed = true;
    } else if new_atime.is_omit() {
        // leave atime unchanged
    } else {
        inode.atime = *new_atime;
        changed = true;
    }

    // Update mtime.
    if new_mtime.is_now() {
        inode.mtime = *now;
        changed = true;
    } else if new_mtime.is_omit() {
        // leave mtime unchanged
    } else {
        inode.mtime = *new_mtime;
        changed = true;
    }

    // ctime is always updated when any attribute changes.
    if changed {
        inode.ctime = *now;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// do_utimensat — public handler
// ---------------------------------------------------------------------------

/// Handler for `utimensat(2)`.
///
/// Updates the access and modification times of the file specified by
/// `dirfd` + `pathname`.  When `times` is `None`, both timestamps are set to
/// the current time.
///
/// # Arguments
///
/// * `dirfd`      — directory fd or `AT_FDCWD`
/// * `pathname`   — path to the file (empty with `AT_EMPTY_PATH` → act on `dirfd`)
/// * `times`      — `Some([atime, mtime])` or `None` (= both NOW)
/// * `flags`      — `AT_SYMLINK_NOFOLLOW`, `AT_EMPTY_PATH`
/// * `caller_uid` — effective UID of the caller
/// * `now`        — current wall-clock time
/// * `table`      — inode/fd table
///
/// # Errors
///
/// - `InvalidArgument`  — bad flags or invalid `tv_nsec`
/// - `NotFound`         — path not found
/// - `PermissionDenied` — insufficient permission
pub fn do_utimensat(
    _dirfd: i32,
    pathname: &[u8],
    times: Option<[Timespec; 2]>,
    flags: i32,
    caller_uid: u32,
    now: Timespec,
    table: &mut UtimesTable,
) -> Result<()> {
    // Validate flags.
    if flags & !UTIMENSAT_VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }

    // Determine new timestamps.
    let (new_atime, new_mtime, times_null) = match times {
        None => (
            Timespec::new(0, UTIME_NOW),
            Timespec::new(0, UTIME_NOW),
            true,
        ),
        Some(ts) => {
            ts[0].validate_normal()?;
            ts[1].validate_normal()?;
            (ts[0], ts[1], false)
        }
    };

    // Resolve inode.
    let inode_idx = table.find_by_path(pathname).ok_or(Error::NotFound)?;
    let inode = table.inode(inode_idx).ok_or(Error::NotFound)?;

    // Permission check.
    check_utimes_permission(inode, &new_atime, &new_mtime, caller_uid, times_null)?;

    apply_utimes_validated(table, inode_idx, &new_atime, &new_mtime, &now)
}

// ---------------------------------------------------------------------------
// do_futimesat — public handler
// ---------------------------------------------------------------------------

/// Handler for `futimesat(2)`.
///
/// The older microsecond-precision variant.  Converts `timeval` pairs to
/// `Timespec` (nanoseconds) and delegates to the `utimensat` logic.
///
/// # Arguments
///
/// * `dirfd`      — directory fd or `AT_FDCWD`
/// * `pathname`   — path to the file
/// * `times`      — `Some([atime_tv, mtime_tv])` or `None` (= both NOW)
/// * `caller_uid` — effective UID of the caller
/// * `now`        — current wall-clock time
/// * `table`      — inode/fd table
///
/// # Errors
///
/// - `InvalidArgument`  — `tv_usec` out of range
/// - `NotFound`         — path not found
/// - `PermissionDenied` — insufficient permission
pub fn do_futimesat(
    dirfd: i32,
    pathname: &[u8],
    times: Option<[Timeval; 2]>,
    caller_uid: u32,
    now: Timespec,
    table: &mut UtimesTable,
) -> Result<()> {
    let ts_times = match times {
        None => None,
        Some(tv) => {
            let a = tv[0].to_timespec()?;
            let m = tv[1].to_timespec()?;
            Some([a, m])
        }
    };
    do_utimensat(dirfd, pathname, ts_times, 0, caller_uid, now, table)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> UtimesTable {
        let mut t = UtimesTable::new();
        t.insert_inode(
            b"/tmp/file.txt",
            Inode {
                ino: 1,
                kind: InodeType::RegularFile,
                uid: 1000,
                gid: 1000,
                mode: 0o644,
                atime: Timespec::new(1000, 0),
                mtime: Timespec::new(2000, 0),
                ctime: Timespec::new(3000, 0),
            },
        )
        .unwrap();

        // Root-owned file with write-only bits for others.
        t.insert_inode(
            b"/var/log/app.log",
            Inode {
                ino: 2,
                kind: InodeType::RegularFile,
                uid: 0,
                gid: 0,
                mode: 0o622,
                atime: Timespec::new(500, 0),
                mtime: Timespec::new(600, 0),
                ctime: Timespec::new(700, 0),
            },
        )
        .unwrap();

        t
    }

    fn now() -> Timespec {
        Timespec::new(9999, 0)
    }

    #[test]
    fn utimensat_set_both() {
        let mut t = make_table();
        let atime = Timespec::new(100, 500);
        let mtime = Timespec::new(200, 999_999_999);
        do_utimensat(
            AT_FDCWD,
            b"/tmp/file.txt",
            Some([atime, mtime]),
            0,
            1000,
            now(),
            &mut t,
        )
        .unwrap();
        let idx = t.find_by_path(b"/tmp/file.txt").unwrap();
        assert_eq!(t.inode(idx).unwrap().atime, atime);
        assert_eq!(t.inode(idx).unwrap().mtime, mtime);
        assert_eq!(t.inode(idx).unwrap().ctime, now());
    }

    #[test]
    fn utimensat_null_times_sets_now() {
        let mut t = make_table();
        do_utimensat(AT_FDCWD, b"/tmp/file.txt", None, 0, 1000, now(), &mut t).unwrap();
        let idx = t.find_by_path(b"/tmp/file.txt").unwrap();
        assert_eq!(t.inode(idx).unwrap().atime, now());
        assert_eq!(t.inode(idx).unwrap().mtime, now());
    }

    #[test]
    fn utimensat_omit_atime() {
        let mut t = make_table();
        let orig_atime = Timespec::new(1000, 0);
        let new_mtime = Timespec::new(5000, 0);
        let times = [Timespec::new(0, UTIME_OMIT), new_mtime];
        do_utimensat(
            AT_FDCWD,
            b"/tmp/file.txt",
            Some(times),
            0,
            1000,
            now(),
            &mut t,
        )
        .unwrap();
        let idx = t.find_by_path(b"/tmp/file.txt").unwrap();
        // atime unchanged.
        assert_eq!(t.inode(idx).unwrap().atime, orig_atime);
        assert_eq!(t.inode(idx).unwrap().mtime, new_mtime);
    }

    #[test]
    fn utimensat_utime_now_for_atime() {
        let mut t = make_table();
        let mtime = Timespec::new(300, 0);
        let times = [Timespec::new(0, UTIME_NOW), mtime];
        do_utimensat(
            AT_FDCWD,
            b"/tmp/file.txt",
            Some(times),
            0,
            1000,
            now(),
            &mut t,
        )
        .unwrap();
        let idx = t.find_by_path(b"/tmp/file.txt").unwrap();
        assert_eq!(t.inode(idx).unwrap().atime, now());
        assert_eq!(t.inode(idx).unwrap().mtime, mtime);
    }

    #[test]
    fn utimensat_invalid_nsec() {
        let mut t = make_table();
        let bad = Timespec::new(0, 1_000_000_000);
        let ok = Timespec::new(0, 0);
        let e = do_utimensat(
            AT_FDCWD,
            b"/tmp/file.txt",
            Some([bad, ok]),
            0,
            1000,
            now(),
            &mut t,
        )
        .unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn utimensat_permission_denied_arbitrary_time() {
        let mut t = make_table();
        let atime = Timespec::new(1, 0);
        let mtime = Timespec::new(2, 0);
        // caller uid 2000 does not own the file, not root, not writable.
        let e = do_utimensat(
            AT_FDCWD,
            b"/tmp/file.txt",
            Some([atime, mtime]),
            0,
            2000,
            now(),
            &mut t,
        )
        .unwrap_err();
        assert_eq!(e, Error::PermissionDenied);
    }

    #[test]
    fn utimensat_now_writable_ok() {
        let mut t = make_table();
        // /var/log/app.log has mode 0o622 (other-writable).
        // uid 5000 has write permission → allowed to set to NOW.
        do_utimensat(AT_FDCWD, b"/var/log/app.log", None, 0, 5000, now(), &mut t).unwrap();
    }

    #[test]
    fn utimensat_bad_flags() {
        let mut t = make_table();
        let e = do_utimensat(
            AT_FDCWD,
            b"/tmp/file.txt",
            None,
            0x8888,
            1000,
            now(),
            &mut t,
        )
        .unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn utimensat_not_found() {
        let mut t = make_table();
        let e = do_utimensat(AT_FDCWD, b"/nonexistent", None, 0, 0, now(), &mut t).unwrap_err();
        assert_eq!(e, Error::NotFound);
    }

    #[test]
    fn futimesat_basic() {
        let mut t = make_table();
        let atv = Timeval {
            tv_sec: 100,
            tv_usec: 500_000,
        };
        let mtv = Timeval {
            tv_sec: 200,
            tv_usec: 0,
        };
        do_futimesat(
            AT_FDCWD,
            b"/tmp/file.txt",
            Some([atv, mtv]),
            1000,
            now(),
            &mut t,
        )
        .unwrap();
        let idx = t.find_by_path(b"/tmp/file.txt").unwrap();
        assert_eq!(t.inode(idx).unwrap().atime.tv_sec, 100);
        assert_eq!(t.inode(idx).unwrap().atime.tv_nsec, 500_000_000);
    }

    #[test]
    fn futimesat_null_times() {
        let mut t = make_table();
        do_futimesat(AT_FDCWD, b"/tmp/file.txt", None, 1000, now(), &mut t).unwrap();
        let idx = t.find_by_path(b"/tmp/file.txt").unwrap();
        assert_eq!(t.inode(idx).unwrap().atime, now());
    }

    #[test]
    fn futimesat_invalid_usec() {
        let mut t = make_table();
        let bad_tv = Timeval {
            tv_sec: 0,
            tv_usec: 1_000_000,
        };
        let ok_tv = Timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let e = do_futimesat(
            AT_FDCWD,
            b"/tmp/file.txt",
            Some([bad_tv, ok_tv]),
            1000,
            now(),
            &mut t,
        )
        .unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn timespec_sentinel_checks() {
        let now_ts = Timespec::new(0, UTIME_NOW);
        assert!(now_ts.is_now());
        assert!(!now_ts.is_omit());
        assert!(!now_ts.is_normal());

        let omit_ts = Timespec::new(0, UTIME_OMIT);
        assert!(omit_ts.is_omit());
        assert!(!omit_ts.is_now());

        let normal = Timespec::new(100, 999);
        assert!(normal.is_normal());
        normal.validate_normal().unwrap();

        let bad = Timespec::new(0, 1_000_000_000);
        assert!(bad.validate_normal().is_err());
    }

    #[test]
    fn timeval_to_timespec() {
        let tv = Timeval {
            tv_sec: 5,
            tv_usec: 123_456,
        };
        let ts = tv.to_timespec().unwrap();
        assert_eq!(ts.tv_sec, 5);
        assert_eq!(ts.tv_nsec, 123_456_000);
    }
}
