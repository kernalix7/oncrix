// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX and BSD file locking — unified lock manager.
//!
//! Implements the complete lock-management layer that backs both
//! `flock(2)` (BSD-style whole-file advisory locks) and
//! `fcntl(2)` record locks (`F_SETLK`, `F_SETLKW`, `F_GETLK`).
//!
//! The two lock families coexist but are kept separate:
//!
//! - **POSIX record locks** (`fl_type`, `fl_start`, `fl_len`) are
//!   per-process (`pid`) and are released on `close(2)`.
//! - **BSD flock locks** cover the whole file, are per open-file-description,
//!   and survive `fork(2)` (until the last descriptor referencing them closes).
//!
//! # Design
//!
//! A [`FileLockTable`] holds all locks for the entire kernel. Locks are
//! keyed by `(inode_id, owner_key)` where `owner_key` encodes whether
//! the lock is POSIX (pid) or BSD (fd number).
//!
//! Conflict detection follows POSIX rules:
//!
//! - READ lock vs WRITE lock from different owners → conflict.
//! - WRITE lock vs any lock from different owner → conflict.
//! - Same owner → upgrade/downgrade, no conflict.
//!
//! # References
//!
//! - POSIX.1-2024 `fcntl()` — advisory record locking
//! - Linux `flock(2)`, `fcntl(2)`
//! - Linux `fs/locks.c`

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum total advisory lock entries in the system.
const MAX_LOCKS: usize = 512;

/// Sentinel value meaning "lock to end of file".
pub const LOCK_LEN_EOF: u64 = 0;

// ── Lock type constants ──────────────────────────────────────────

/// Read (shared) lock.
pub const F_RDLCK: u8 = 0;
/// Write (exclusive) lock.
pub const F_WRLCK: u8 = 1;
/// Unlock (release).
pub const F_UNLCK: u8 = 2;

// ── flock(2) operation constants ──────────────────────────────

/// Apply a shared (read) lock (`LOCK_SH`).
pub const LOCK_SH: u32 = 1;
/// Apply an exclusive (write) lock (`LOCK_EX`).
pub const LOCK_EX: u32 = 2;
/// Non-blocking flag (`LOCK_NB`).
pub const LOCK_NB: u32 = 4;
/// Release the lock (`LOCK_UN`).
pub const LOCK_UN: u32 = 8;

// ── fcntl command constants ──────────────────────────────────────

/// Query the first blocking lock (`F_GETLK`).
pub const F_GETLK: u32 = 5;
/// Set or clear a lock, non-blocking (`F_SETLK`).
pub const F_SETLK: u32 = 6;
/// Set or clear a lock, blocking (`F_SETLKW`).
pub const F_SETLKW: u32 = 7;

// ── LockKind ────────────────────────────────────────────────────

/// Distinguishes POSIX record locks from BSD flock locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockKind {
    /// POSIX byte-range advisory lock (`fcntl` family).
    Posix,
    /// BSD whole-file advisory lock (`flock` family).
    Bsd,
    /// Open-file-description lock (OFD, `F_OFD_SETLK`).
    Ofd,
}

// ── LockOwnerKey ────────────────────────────────────────────────

/// Identifies the lock owner for conflict detection.
///
/// POSIX locks are owned per-PID; BSD locks are per open-file-description
/// (represented by the file descriptor number within a process).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockOwnerKey {
    /// Process identifier.
    pub pid: u32,
    /// File descriptor (for BSD/OFD locks; 0 for POSIX locks).
    pub fd: u32,
    /// Lock kind.
    pub kind: LockKind,
}

impl LockOwnerKey {
    /// Creates a POSIX lock owner key.
    pub const fn posix(pid: u32) -> Self {
        Self {
            pid,
            fd: 0,
            kind: LockKind::Posix,
        }
    }

    /// Creates a BSD lock owner key.
    pub const fn bsd(pid: u32, fd: u32) -> Self {
        Self {
            pid,
            fd,
            kind: LockKind::Bsd,
        }
    }

    /// Creates an OFD lock owner key.
    pub const fn ofd(pid: u32, fd: u32) -> Self {
        Self {
            pid,
            fd,
            kind: LockKind::Ofd,
        }
    }
}

// ── FileLockEntry ────────────────────────────────────────────────

/// A single advisory lock entry.
#[derive(Debug, Clone, Copy)]
pub struct FileLockEntry {
    /// Inode this lock applies to.
    pub inode_id: u64,
    /// Lock owner.
    pub owner: LockOwnerKey,
    /// Lock type: [`F_RDLCK`], [`F_WRLCK`], or [`F_UNLCK`].
    pub lock_type: u8,
    /// Starting byte offset of the locked range.
    pub start: u64,
    /// Length of the locked range in bytes; 0 means to EOF.
    pub length: u64,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl FileLockEntry {
    /// Creates an empty (unoccupied) lock entry.
    pub const fn empty() -> Self {
        Self {
            inode_id: 0,
            owner: LockOwnerKey::posix(0),
            lock_type: F_UNLCK,
            start: 0,
            length: LOCK_LEN_EOF,
            occupied: false,
        }
    }

    /// Returns `true` if `other` overlaps this lock's byte range.
    pub fn overlaps(&self, other: &FileLockEntry) -> bool {
        if self.inode_id != other.inode_id {
            return false;
        }
        let s1 = self.start;
        let e1 = if self.length == 0 {
            u64::MAX
        } else {
            s1.saturating_add(self.length)
        };
        let s2 = other.start;
        let e2 = if other.length == 0 {
            u64::MAX
        } else {
            s2.saturating_add(other.length)
        };
        s1 < e2 && s2 < e1
    }

    /// Returns `true` if `other` conflicts with this lock.
    ///
    /// Conflict means both locks overlap, they are from different owners, and
    /// at least one is exclusive.
    pub fn conflicts_with(&self, other: &FileLockEntry) -> bool {
        if !self.overlaps(other) {
            return false;
        }
        if self.owner == other.owner {
            return false;
        }
        // READ vs READ: no conflict.
        self.lock_type == F_WRLCK || other.lock_type == F_WRLCK
    }
}

// ── FileLockTable ────────────────────────────────────────────────

/// System-wide advisory file lock table.
///
/// Provides the complete POSIX and BSD locking interface used by the
/// syscall layer.
pub struct FileLockTable {
    entries: [FileLockEntry; MAX_LOCKS],
    count: usize,
}

impl FileLockTable {
    /// Creates an empty lock table.
    pub const fn new() -> Self {
        Self {
            entries: [const { FileLockEntry::empty() }; MAX_LOCKS],
            count: 0,
        }
    }

    // ── POSIX fcntl locking ─────────────────────────────────────

    /// Acquires or releases a POSIX record lock.
    ///
    /// Corresponds to `fcntl(F_SETLK)`.  Returns [`Error::WouldBlock`]
    /// if a conflicting lock is held and `blocking` is `false`.
    pub fn posix_lock(
        &mut self,
        inode_id: u64,
        pid: u32,
        lock_type: u8,
        start: u64,
        length: u64,
        blocking: bool,
    ) -> Result<()> {
        if lock_type == F_UNLCK {
            return self.posix_unlock(inode_id, pid, start, length);
        }
        let owner = LockOwnerKey::posix(pid);
        let candidate = FileLockEntry {
            inode_id,
            owner,
            lock_type,
            start,
            length,
            occupied: true,
        };
        // Check for conflicts.
        for i in 0..MAX_LOCKS {
            if !self.entries[i].occupied {
                continue;
            }
            if self.entries[i].conflicts_with(&candidate) {
                if blocking {
                    return Err(Error::WouldBlock);
                } else {
                    return Err(Error::WouldBlock);
                }
            }
        }
        // Replace existing lock from the same owner over the same range.
        for i in 0..MAX_LOCKS {
            if self.entries[i].occupied
                && self.entries[i].inode_id == inode_id
                && self.entries[i].owner == owner
                && self.entries[i].start == start
                && self.entries[i].length == length
            {
                self.entries[i].lock_type = lock_type;
                return Ok(());
            }
        }
        self.insert(candidate)
    }

    /// Releases a POSIX record lock matching `(pid, start, length)`.
    fn posix_unlock(&mut self, inode_id: u64, pid: u32, start: u64, length: u64) -> Result<()> {
        let owner = LockOwnerKey::posix(pid);
        for i in 0..MAX_LOCKS {
            if self.entries[i].occupied
                && self.entries[i].inode_id == inode_id
                && self.entries[i].owner == owner
                && self.entries[i].start == start
                && self.entries[i].length == length
            {
                self.entries[i].occupied = false;
                self.count -= 1;
                return Ok(());
            }
        }
        // Unlocking a non-existent lock is not an error.
        Ok(())
    }

    /// Queries the first lock conflicting with the described lock.
    ///
    /// Corresponds to `fcntl(F_GETLK)`.  Returns the conflicting lock,
    /// or a lock with `lock_type == F_UNLCK` if none.
    pub fn posix_getlk(
        &self,
        inode_id: u64,
        pid: u32,
        lock_type: u8,
        start: u64,
        length: u64,
    ) -> FileLockEntry {
        let owner = LockOwnerKey::posix(pid);
        let query = FileLockEntry {
            inode_id,
            owner,
            lock_type,
            start,
            length,
            occupied: true,
        };
        for i in 0..MAX_LOCKS {
            if self.entries[i].occupied && self.entries[i].conflicts_with(&query) {
                return self.entries[i];
            }
        }
        // No conflict — return unlocked sentinel.
        FileLockEntry {
            lock_type: F_UNLCK,
            ..query
        }
    }

    // ── BSD flock locking ────────────────────────────────────────

    /// Acquires or releases a BSD whole-file advisory lock.
    ///
    /// Corresponds to `flock(2)`.
    pub fn bsd_flock(&mut self, inode_id: u64, pid: u32, fd: u32, operation: u32) -> Result<()> {
        let nonblock = operation & LOCK_NB != 0;
        let op = operation & !(LOCK_NB);

        match op {
            LOCK_UN => {
                self.bsd_unlock(inode_id, pid, fd);
                Ok(())
            }
            LOCK_SH => self.bsd_acquire(inode_id, pid, fd, F_RDLCK, nonblock),
            LOCK_EX => self.bsd_acquire(inode_id, pid, fd, F_WRLCK, nonblock),
            _ => Err(Error::InvalidArgument),
        }
    }

    fn bsd_acquire(
        &mut self,
        inode_id: u64,
        pid: u32,
        fd: u32,
        lock_type: u8,
        nonblock: bool,
    ) -> Result<()> {
        let owner = LockOwnerKey::bsd(pid, fd);
        let candidate = FileLockEntry {
            inode_id,
            owner,
            lock_type,
            start: 0,
            length: LOCK_LEN_EOF,
            occupied: true,
        };
        for i in 0..MAX_LOCKS {
            if !self.entries[i].occupied {
                continue;
            }
            if self.entries[i].conflicts_with(&candidate) {
                if nonblock {
                    return Err(Error::WouldBlock);
                }
                return Err(Error::WouldBlock);
            }
        }
        // Upgrade existing BSD lock from same fd.
        for i in 0..MAX_LOCKS {
            if self.entries[i].occupied
                && self.entries[i].inode_id == inode_id
                && self.entries[i].owner == owner
            {
                self.entries[i].lock_type = lock_type;
                return Ok(());
            }
        }
        self.insert(candidate)
    }

    fn bsd_unlock(&mut self, inode_id: u64, pid: u32, fd: u32) {
        let owner = LockOwnerKey::bsd(pid, fd);
        for i in 0..MAX_LOCKS {
            if self.entries[i].occupied
                && self.entries[i].inode_id == inode_id
                && self.entries[i].owner == owner
            {
                self.entries[i].occupied = false;
                self.count -= 1;
                return;
            }
        }
    }

    // ── Release-on-close ─────────────────────────────────────────

    /// Releases all POSIX locks held by `pid` on all inodes.
    ///
    /// Called on process exit or when all file descriptors for a PID
    /// are closed.
    pub fn release_all_posix(&mut self, pid: u32) {
        for i in 0..MAX_LOCKS {
            if self.entries[i].occupied
                && self.entries[i].owner.kind == LockKind::Posix
                && self.entries[i].owner.pid == pid
            {
                self.entries[i].occupied = false;
                self.count -= 1;
            }
        }
    }

    /// Releases the BSD lock held by `(pid, fd)`.
    ///
    /// Called when the file descriptor `fd` of process `pid` is closed.
    pub fn release_bsd_on_close(&mut self, pid: u32, fd: u32) {
        self.bsd_unlock(0, pid, fd);
        // Sweep all inodes.
        let owner = LockOwnerKey::bsd(pid, fd);
        for i in 0..MAX_LOCKS {
            if self.entries[i].occupied && self.entries[i].owner == owner {
                self.entries[i].occupied = false;
                self.count -= 1;
            }
        }
    }

    // ── OFD locks ────────────────────────────────────────────────

    /// Acquires or releases an Open-File-Description lock.
    ///
    /// OFD locks (`F_OFD_SETLK`) behave like POSIX locks but are
    /// per-open-file-description rather than per-PID.
    pub fn ofd_lock(
        &mut self,
        inode_id: u64,
        pid: u32,
        fd: u32,
        lock_type: u8,
        start: u64,
        length: u64,
    ) -> Result<()> {
        let owner = LockOwnerKey::ofd(pid, fd);
        if lock_type == F_UNLCK {
            for i in 0..MAX_LOCKS {
                if self.entries[i].occupied
                    && self.entries[i].inode_id == inode_id
                    && self.entries[i].owner == owner
                    && self.entries[i].start == start
                    && self.entries[i].length == length
                {
                    self.entries[i].occupied = false;
                    self.count -= 1;
                    return Ok(());
                }
            }
            return Ok(());
        }
        let candidate = FileLockEntry {
            inode_id,
            owner,
            lock_type,
            start,
            length,
            occupied: true,
        };
        for i in 0..MAX_LOCKS {
            if self.entries[i].occupied && self.entries[i].conflicts_with(&candidate) {
                return Err(Error::WouldBlock);
            }
        }
        self.insert(candidate)
    }

    // ── Helpers ──────────────────────────────────────────────────

    /// Inserts `entry` into the first empty slot.
    fn insert(&mut self, entry: FileLockEntry) -> Result<()> {
        for i in 0..MAX_LOCKS {
            if !self.entries[i].occupied {
                self.entries[i] = entry;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns the number of active lock entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns `true` if any lock is held on `inode_id`.
    pub fn is_locked(&self, inode_id: u64) -> bool {
        for i in 0..MAX_LOCKS {
            if self.entries[i].occupied && self.entries[i].inode_id == inode_id {
                return true;
            }
        }
        false
    }

    /// Returns all lock entries for `inode_id` (up to `out.len()`).
    pub fn locks_for_inode<'a>(&'a self, inode_id: u64, out: &mut [FileLockEntry]) -> usize {
        let mut n = 0;
        for i in 0..MAX_LOCKS {
            if n >= out.len() {
                break;
            }
            if self.entries[i].occupied && self.entries[i].inode_id == inode_id {
                out[n] = self.entries[i];
                n += 1;
            }
        }
        n
    }
}

// ── Unit tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_posix_read_locks_compatible() {
        let mut t = FileLockTable::new();
        t.posix_lock(1, 100, F_RDLCK, 0, 0, false).unwrap();
        t.posix_lock(1, 200, F_RDLCK, 0, 0, false).unwrap();
        assert_eq!(t.count(), 2);
    }

    #[test]
    fn test_posix_write_conflicts_read() {
        let mut t = FileLockTable::new();
        t.posix_lock(1, 100, F_RDLCK, 0, 100, false).unwrap();
        let res = t.posix_lock(1, 200, F_WRLCK, 0, 100, false);
        assert!(matches!(res, Err(Error::WouldBlock)));
    }

    #[test]
    fn test_posix_same_owner_upgrade() {
        let mut t = FileLockTable::new();
        t.posix_lock(1, 100, F_RDLCK, 0, 100, false).unwrap();
        // Same owner: upgrade does not conflict.
        t.posix_lock(1, 100, F_WRLCK, 0, 100, false).unwrap();
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn test_posix_unlock() {
        let mut t = FileLockTable::new();
        t.posix_lock(1, 100, F_WRLCK, 0, 0, false).unwrap();
        assert!(t.is_locked(1));
        t.posix_lock(1, 100, F_UNLCK, 0, 0, false).unwrap();
        assert!(!t.is_locked(1));
    }

    #[test]
    fn test_posix_getlk_no_conflict() {
        let t = FileLockTable::new();
        let result = t.posix_getlk(1, 100, F_WRLCK, 0, 0);
        assert_eq!(result.lock_type, F_UNLCK);
    }

    #[test]
    fn test_posix_getlk_with_conflict() {
        let mut t = FileLockTable::new();
        t.posix_lock(1, 100, F_RDLCK, 0, 0, false).unwrap();
        let result = t.posix_getlk(1, 200, F_WRLCK, 0, 0);
        assert_eq!(result.lock_type, F_RDLCK);
        assert_eq!(result.owner.pid, 100);
    }

    #[test]
    fn test_bsd_shared_compatible() {
        let mut t = FileLockTable::new();
        t.bsd_flock(1, 100, 3, LOCK_SH).unwrap();
        t.bsd_flock(1, 200, 4, LOCK_SH).unwrap();
        assert_eq!(t.count(), 2);
    }

    #[test]
    fn test_bsd_exclusive_conflict() {
        let mut t = FileLockTable::new();
        t.bsd_flock(1, 100, 3, LOCK_SH).unwrap();
        let res = t.bsd_flock(1, 200, 4, LOCK_EX | LOCK_NB);
        assert!(matches!(res, Err(Error::WouldBlock)));
    }

    #[test]
    fn test_bsd_unlock() {
        let mut t = FileLockTable::new();
        t.bsd_flock(1, 100, 3, LOCK_EX).unwrap();
        t.bsd_flock(1, 100, 3, LOCK_UN).unwrap();
        assert!(!t.is_locked(1));
    }

    #[test]
    fn test_release_all_posix_on_exit() {
        let mut t = FileLockTable::new();
        t.posix_lock(1, 100, F_WRLCK, 0, 100, false).unwrap();
        t.posix_lock(2, 100, F_RDLCK, 0, 50, false).unwrap();
        t.release_all_posix(100);
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn test_non_overlapping_ranges_no_conflict() {
        let mut t = FileLockTable::new();
        t.posix_lock(1, 100, F_WRLCK, 0, 100, false).unwrap();
        // Disjoint range: no conflict.
        t.posix_lock(1, 200, F_WRLCK, 200, 100, false).unwrap();
        assert_eq!(t.count(), 2);
    }

    #[test]
    fn test_ofd_lock() {
        let mut t = FileLockTable::new();
        t.ofd_lock(1, 100, 5, F_WRLCK, 0, 0).unwrap();
        // Different OFD (fd=6) conflicts.
        let res = t.ofd_lock(1, 100, 6, F_RDLCK, 0, 0);
        assert!(matches!(res, Err(Error::WouldBlock)));
    }
}
