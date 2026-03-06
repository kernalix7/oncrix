// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fcntl(2)` syscall handler.
//!
//! Performs operations on an open file descriptor: duplicating descriptors,
//! getting and setting descriptor flags, getting and setting file status
//! flags, and POSIX advisory record locking.
//!
//! # Supported commands
//!
//! | Command | Value | Description |
//! |---------|-------|-------------|
//! | `F_DUPFD`        | 0 | Duplicate fd ≥ arg |
//! | `F_GETFD`        | 1 | Get fd flags (`FD_CLOEXEC`) |
//! | `F_SETFD`        | 2 | Set fd flags |
//! | `F_GETFL`        | 3 | Get file status flags (`O_APPEND`, `O_NONBLOCK`, …) |
//! | `F_SETFL`        | 4 | Set file status flags |
//! | `F_GETLK`        | 5 | Get first conflicting lock |
//! | `F_SETLK`        | 6 | Set/release advisory lock (non-blocking) |
//! | `F_SETLKW`       | 7 | Set/release advisory lock (blocking) |
//! | `F_DUPFD_CLOEXEC`| 1030 | Duplicate fd ≥ arg, set `FD_CLOEXEC` |
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `fcntl()`.
//!
//! # References
//!
//! - POSIX.1-2024: `fcntl()`
//! - Linux: `fs/fcntl.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Command constants
// ---------------------------------------------------------------------------

/// Duplicate fd, using lowest available fd ≥ `arg`.
pub const F_DUPFD: i32 = 0;
/// Get fd flags.
pub const F_GETFD: i32 = 1;
/// Set fd flags.
pub const F_SETFD: i32 = 2;
/// Get file status flags.
pub const F_GETFL: i32 = 3;
/// Set file status flags.
pub const F_SETFL: i32 = 4;
/// Get lock (returns first blocking lock).
pub const F_GETLK: i32 = 5;
/// Set/release lock (non-blocking).
pub const F_SETLK: i32 = 6;
/// Set/release lock (blocking).
pub const F_SETLKW: i32 = 7;
/// Duplicate fd with `FD_CLOEXEC`.
pub const F_DUPFD_CLOEXEC: i32 = 1030;

/// `FD_CLOEXEC` fd flag.
pub const FD_CLOEXEC: i32 = 1;

// ---------------------------------------------------------------------------
// Lock type constants
// ---------------------------------------------------------------------------

/// Read lock.
pub const F_RDLCK: i16 = 0;
/// Write lock.
pub const F_WRLCK: i16 = 1;
/// Unlock.
pub const F_UNLCK: i16 = 2;

/// Maximum number of fds in the stub table.
pub const MAX_FCNTL_FDS: usize = 256;
/// Maximum advisory locks per fd.
pub const MAX_LOCKS_PER_FD: usize = 8;

// ---------------------------------------------------------------------------
// FcntlFlock — POSIX advisory lock record
// ---------------------------------------------------------------------------

/// A POSIX advisory lock record (`struct flock`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FcntlFlock {
    /// Lock type: `F_RDLCK`, `F_WRLCK`, or `F_UNLCK`.
    pub l_type: i16,
    /// Whence: `SEEK_SET`, `SEEK_CUR`, or `SEEK_END` (simplified as i16).
    pub l_whence: i16,
    /// Starting offset.
    pub l_start: i64,
    /// Number of bytes (0 = to EOF).
    pub l_len: i64,
    /// PID of process holding lock (filled in by `F_GETLK`).
    pub l_pid: i32,
}

impl FcntlFlock {
    /// Return `true` if this is an unlock request.
    pub const fn is_unlock(&self) -> bool {
        self.l_type == F_UNLCK
    }
}

// ---------------------------------------------------------------------------
// LockRecord — one active advisory lock
// ---------------------------------------------------------------------------

/// An active advisory lock held on an fd.
#[derive(Clone, Copy)]
struct LockRecord {
    lock: FcntlFlock,
    owner_pid: i32,
    in_use: bool,
}

impl LockRecord {
    const fn empty() -> Self {
        Self {
            lock: FcntlFlock {
                l_type: F_UNLCK,
                l_whence: 0,
                l_start: 0,
                l_len: 0,
                l_pid: 0,
            },
            owner_pid: 0,
            in_use: false,
        }
    }
}

// ---------------------------------------------------------------------------
// FcntlFdEntry — one entry in the fcntl fd table
// ---------------------------------------------------------------------------

/// An open fd entry for the fcntl handler.
#[derive(Clone, Copy)]
pub struct FcntlFdEntry {
    /// File descriptor number.
    pub fd: i32,
    /// Fd flags (FD_CLOEXEC).
    pub fd_flags: i32,
    /// File status flags (O_APPEND, O_NONBLOCK, …).
    pub file_flags: i32,
    /// Advisory locks on this fd.
    locks: [LockRecord; MAX_LOCKS_PER_FD],
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl FcntlFdEntry {
    const fn empty() -> Self {
        Self {
            fd: -1,
            fd_flags: 0,
            file_flags: 0,
            locks: [const { LockRecord::empty() }; MAX_LOCKS_PER_FD],
            in_use: false,
        }
    }

    /// Add or replace an advisory lock.
    fn set_lock(&mut self, flock: FcntlFlock, pid: i32) -> Result<()> {
        if flock.is_unlock() {
            // Remove matching lock.
            for lr in self.locks.iter_mut() {
                if lr.in_use && lr.owner_pid == pid {
                    *lr = LockRecord::empty();
                }
            }
            return Ok(());
        }
        // Replace existing lock from same PID or add new.
        for lr in self.locks.iter_mut() {
            if lr.in_use && lr.owner_pid == pid {
                lr.lock = flock;
                return Ok(());
            }
        }
        for lr in self.locks.iter_mut() {
            if !lr.in_use {
                *lr = LockRecord {
                    lock: flock,
                    owner_pid: pid,
                    in_use: true,
                };
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a conflicting lock for `F_GETLK`.
    fn get_conflicting_lock(&self, flock: &FcntlFlock, pid: i32) -> Option<FcntlFlock> {
        for lr in self.locks.iter() {
            if !lr.in_use || lr.owner_pid == pid {
                continue;
            }
            // Simplified: any overlapping write lock conflicts.
            if lr.lock.l_type == F_WRLCK || flock.l_type == F_WRLCK {
                let mut result = lr.lock;
                result.l_pid = lr.owner_pid;
                return Some(result);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// FcntlFdTable — fd table
// ---------------------------------------------------------------------------

/// A stub fd table for the fcntl handler.
pub struct FcntlFdTable {
    entries: [FcntlFdEntry; MAX_FCNTL_FDS],
    count: usize,
    next_fd: i32,
}

impl FcntlFdTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { FcntlFdEntry::empty() }; MAX_FCNTL_FDS],
            count: 0,
            next_fd: 3,
        }
    }

    /// Insert a new fd entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, entry: FcntlFdEntry) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if !slot.in_use {
                *slot = entry;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an fd entry by number.
    pub fn find(&self, fd: i32) -> Option<&FcntlFdEntry> {
        self.entries.iter().find(|e| e.in_use && e.fd == fd)
    }

    /// Find a mutable fd entry by number.
    pub fn find_mut(&mut self, fd: i32) -> Option<&mut FcntlFdEntry> {
        self.entries.iter_mut().find(|e| e.in_use && e.fd == fd)
    }

    /// Allocate a new fd number ≥ `min_fd`.
    fn alloc_fd(&mut self, min_fd: i32) -> Option<i32> {
        let mut candidate = min_fd.max(0);
        loop {
            if candidate > 65535 {
                return None;
            }
            if self.entries.iter().all(|e| !e.in_use || e.fd != candidate) {
                return Some(candidate);
            }
            candidate += 1;
        }
    }

    /// Return the number of open fds.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for FcntlFdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FcntlResult — return value of an fcntl call
// ---------------------------------------------------------------------------

/// The return value of a successful `fcntl` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FcntlResult {
    /// A newly duplicated file descriptor number.
    Fd(i32),
    /// Integer value (flags).
    Int(i32),
    /// Lock record (for `F_GETLK`).
    Lock(FcntlFlock),
    /// Success with no specific return value.
    Ok,
}

// ---------------------------------------------------------------------------
// do_fcntl — main handler
// ---------------------------------------------------------------------------

/// Handler for `fcntl(2)`.
///
/// # Arguments
///
/// * `table`   — fd table
/// * `fd`      — file descriptor to operate on
/// * `cmd`     — command (`F_DUPFD`, `F_GETFD`, etc.)
/// * `arg`     — command argument (meaning depends on `cmd`)
/// * `caller_pid` — PID of the calling process (for locking)
///
/// # Returns
///
/// A [`FcntlResult`] whose variant depends on `cmd`.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — unknown `cmd`, or invalid `arg`
/// * [`Error::NotFound`]        — `fd` not in the table
/// * [`Error::OutOfMemory`]     — no free fd available for `F_DUPFD`
pub fn do_fcntl(
    table: &mut FcntlFdTable,
    fd: i32,
    cmd: i32,
    arg: i64,
    caller_pid: i32,
) -> Result<FcntlResult> {
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            if arg < 0 {
                return Err(Error::InvalidArgument);
            }
            let src = *table.find(fd).ok_or(Error::NotFound)?;
            let new_fd = table.alloc_fd(arg as i32).ok_or(Error::OutOfMemory)?;
            let cloexec = if cmd == F_DUPFD_CLOEXEC {
                FD_CLOEXEC
            } else {
                0
            };
            let new_entry = FcntlFdEntry {
                fd: new_fd,
                fd_flags: cloexec,
                file_flags: src.file_flags,
                locks: [const { LockRecord::empty() }; MAX_LOCKS_PER_FD],
                in_use: true,
            };
            table.insert(new_entry)?;
            Ok(FcntlResult::Fd(new_fd))
        }

        F_GETFD => {
            let e = table.find(fd).ok_or(Error::NotFound)?;
            Ok(FcntlResult::Int(e.fd_flags))
        }

        F_SETFD => {
            let e = table.find_mut(fd).ok_or(Error::NotFound)?;
            e.fd_flags = arg as i32;
            Ok(FcntlResult::Ok)
        }

        F_GETFL => {
            let e = table.find(fd).ok_or(Error::NotFound)?;
            Ok(FcntlResult::Int(e.file_flags))
        }

        F_SETFL => {
            let e = table.find_mut(fd).ok_or(Error::NotFound)?;
            // Only changeable flags: O_APPEND, O_NONBLOCK.  Keep access mode.
            let access_mode = e.file_flags & 3;
            let new_flags = (arg as i32 & !3) | access_mode;
            e.file_flags = new_flags;
            Ok(FcntlResult::Ok)
        }

        F_GETLK => {
            let flock_arg = decode_flock_arg(arg);
            let e = table.find(fd).ok_or(Error::NotFound)?;
            let conflict = e.get_conflicting_lock(&flock_arg, caller_pid);
            let result = conflict.unwrap_or(FcntlFlock {
                l_type: F_UNLCK,
                l_whence: flock_arg.l_whence,
                l_start: flock_arg.l_start,
                l_len: flock_arg.l_len,
                l_pid: -1,
            });
            Ok(FcntlResult::Lock(result))
        }

        F_SETLK | F_SETLKW => {
            let flock_arg = decode_flock_arg(arg);
            let e = table.find_mut(fd).ok_or(Error::NotFound)?;
            e.set_lock(flock_arg, caller_pid)?;
            Ok(FcntlResult::Ok)
        }

        _ => Err(Error::InvalidArgument),
    }
}

/// Decode a packed `i64` stub encoding of an `FcntlFlock`.
///
/// In the real kernel this would be a pointer to user space.  In the stub
/// we pack the `l_type` into the high 16 bits of `arg`.
fn decode_flock_arg(arg: i64) -> FcntlFlock {
    let l_type = ((arg >> 48) & 0xFFFF) as i16;
    let l_start = (arg & 0x0000_FFFF_FFFF) as i64;
    FcntlFlock {
        l_type,
        l_whence: 0,
        l_start,
        l_len: 0,
        l_pid: 0,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn open_fd(table: &mut FcntlFdTable, fd: i32, file_flags: i32) {
        table
            .insert(FcntlFdEntry {
                fd,
                fd_flags: 0,
                file_flags,
                locks: [const { LockRecord::empty() }; MAX_LOCKS_PER_FD],
                in_use: true,
            })
            .unwrap();
    }

    #[test]
    fn dupfd_allocates_new_fd() {
        let mut t = FcntlFdTable::new();
        open_fd(&mut t, 3, 0);
        let r = do_fcntl(&mut t, 3, F_DUPFD, 4, 1).unwrap();
        assert_eq!(r, FcntlResult::Fd(4));
        assert_eq!(t.count(), 2);
    }

    #[test]
    fn dupfd_cloexec_sets_flag() {
        let mut t = FcntlFdTable::new();
        open_fd(&mut t, 3, 0);
        let r = do_fcntl(&mut t, 3, F_DUPFD_CLOEXEC, 4, 1).unwrap();
        if let FcntlResult::Fd(new_fd) = r {
            assert_eq!(t.find(new_fd).unwrap().fd_flags, FD_CLOEXEC);
        } else {
            panic!("expected Fd variant");
        }
    }

    #[test]
    fn getfd_returns_fd_flags() {
        let mut t = FcntlFdTable::new();
        t.insert(FcntlFdEntry {
            fd: 5,
            fd_flags: FD_CLOEXEC,
            file_flags: 0,
            locks: [const { LockRecord::empty() }; MAX_LOCKS_PER_FD],
            in_use: true,
        })
        .unwrap();
        assert_eq!(
            do_fcntl(&mut t, 5, F_GETFD, 0, 1),
            Ok(FcntlResult::Int(FD_CLOEXEC))
        );
    }

    #[test]
    fn setfd_updates_fd_flags() {
        let mut t = FcntlFdTable::new();
        open_fd(&mut t, 3, 0);
        do_fcntl(&mut t, 3, F_SETFD, FD_CLOEXEC as i64, 1).unwrap();
        assert_eq!(t.find(3).unwrap().fd_flags, FD_CLOEXEC);
    }

    #[test]
    fn getfl_returns_file_flags() {
        let mut t = FcntlFdTable::new();
        open_fd(&mut t, 3, 0o2000); // O_APPEND
        assert_eq!(
            do_fcntl(&mut t, 3, F_GETFL, 0, 1),
            Ok(FcntlResult::Int(0o2000))
        );
    }

    #[test]
    fn setfl_preserves_access_mode() {
        let mut t = FcntlFdTable::new();
        open_fd(&mut t, 3, 1); // O_WRONLY = 1
        do_fcntl(&mut t, 3, F_SETFL, 0o2001, 1).unwrap(); // O_APPEND | O_WRONLY
        let flags = t.find(3).unwrap().file_flags;
        assert_eq!(flags & 3, 1); // access mode preserved
        assert_ne!(flags & 0o2000, 0); // O_APPEND set
    }

    #[test]
    fn setlk_and_getlk() {
        let mut t = FcntlFdTable::new();
        open_fd(&mut t, 3, 2); // O_RDWR
        // Set a write lock from pid 10.
        let lock_arg: i64 = (F_WRLCK as i64) << 48 | 0;
        do_fcntl(&mut t, 3, F_SETLK, lock_arg, 10).unwrap();
        // Query from pid 20 — should find a conflict.
        let query: i64 = (F_WRLCK as i64) << 48 | 0;
        let r = do_fcntl(&mut t, 3, F_GETLK, query, 20).unwrap();
        if let FcntlResult::Lock(fl) = r {
            assert_eq!(fl.l_pid, 10);
        } else {
            panic!("expected Lock variant");
        }
    }

    #[test]
    fn fcntl_unknown_cmd_rejected() {
        let mut t = FcntlFdTable::new();
        open_fd(&mut t, 3, 0);
        assert_eq!(do_fcntl(&mut t, 3, 999, 0, 1), Err(Error::InvalidArgument));
    }

    #[test]
    fn fcntl_not_found() {
        let mut t = FcntlFdTable::new();
        assert_eq!(do_fcntl(&mut t, 99, F_GETFD, 0, 1), Err(Error::NotFound));
    }
}
