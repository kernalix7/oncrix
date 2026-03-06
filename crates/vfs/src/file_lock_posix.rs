// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX advisory file locks (F_SETLK / F_GETLK / F_SETLKW).
//!
//! Implements per-process advisory locking as specified by POSIX.1-2024
//! `fcntl()` locking. POSIX locks are associated with (pid, file) pairs
//! and are released when any file descriptor for the file is closed.

use oncrix_lib::{Error, Result};

/// Lock type constants matching POSIX `struct flock`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i16)]
pub enum PosixLockType {
    /// Read (shared) lock.
    ReadLock = 0,
    /// Write (exclusive) lock.
    WriteLock = 1,
    /// Unlock.
    Unlock = 2,
}

/// Whence values for lock range interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i16)]
pub enum LockWhence {
    /// Offset from beginning of file.
    SeekSet = 0,
    /// Offset from current position.
    SeekCur = 1,
    /// Offset from end of file.
    SeekEnd = 2,
}

/// POSIX `struct flock` equivalent.
#[derive(Debug, Clone, Copy)]
pub struct FlockStruct {
    /// Lock type: read, write, or unlock.
    pub l_type: PosixLockType,
    /// Offset interpretation.
    pub l_whence: LockWhence,
    /// Starting offset.
    pub l_start: i64,
    /// Length (0 = to end of file).
    pub l_len: i64,
    /// PID of process holding lock (output for F_GETLK).
    pub l_pid: u32,
}

impl FlockStruct {
    /// Create a new flock structure.
    pub const fn new(l_type: PosixLockType) -> Self {
        FlockStruct {
            l_type,
            l_whence: LockWhence::SeekSet,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        }
    }
}

/// A single POSIX advisory lock record.
#[derive(Debug, Clone, Copy)]
pub struct PosixLock {
    /// Lock type.
    pub lock_type: PosixLockType,
    /// Byte range start (absolute file offset).
    pub start: u64,
    /// Byte range end (inclusive). `u64::MAX` means end of file.
    pub end: u64,
    /// Owner PID.
    pub pid: u32,
    /// Open file description owner (fd table index).
    pub owner: u64,
}

impl PosixLock {
    /// Create a new POSIX lock.
    pub fn new(lock_type: PosixLockType, start: u64, end: u64, pid: u32, owner: u64) -> Self {
        PosixLock {
            lock_type,
            start,
            end,
            pid,
            owner,
        }
    }

    /// Check if two lock ranges overlap.
    pub fn overlaps(&self, other: &PosixLock) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// Check if this lock conflicts with another.
    ///
    /// Two locks conflict if their ranges overlap AND at least one is a write lock.
    pub fn conflicts(&self, other: &PosixLock) -> bool {
        if !self.overlaps(other) {
            return false;
        }
        // Same owner never conflicts.
        if self.owner == other.owner {
            return false;
        }
        matches!(
            (self.lock_type, other.lock_type),
            (PosixLockType::WriteLock, _) | (_, PosixLockType::WriteLock)
        )
    }
}

/// POSIX file lock table for a single inode.
///
/// Stores up to 64 concurrent POSIX advisory locks.
pub struct PosixLockTable {
    locks: [Option<PosixLock>; 64],
    count: usize,
}

impl PosixLockTable {
    /// Create an empty lock table.
    pub const fn new() -> Self {
        PosixLockTable {
            locks: [None; 64],
            count: 0,
        }
    }

    /// Attempt to set a POSIX lock.
    ///
    /// Returns `Err(WouldBlock)` if a conflicting lock exists and blocking is not allowed.
    pub fn set_lock(&mut self, lock: PosixLock) -> Result<()> {
        if lock.lock_type == PosixLockType::Unlock {
            return self.release_lock(lock.start, lock.end, lock.owner);
        }
        // Check for conflicts.
        for entry in self.locks.iter().flatten() {
            if lock.conflicts(entry) {
                return Err(Error::WouldBlock);
            }
        }
        // Find free slot.
        for slot in &mut self.locks {
            if slot.is_none() {
                *slot = Some(lock);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Query whether a proposed lock would be blocked.
    ///
    /// Returns `Some(blocking_lock)` if there is a conflict, `None` if the
    /// lock can be granted.
    pub fn get_lock(&self, query: &PosixLock) -> Option<PosixLock> {
        for entry in self.locks.iter().flatten() {
            if query.conflicts(entry) {
                return Some(*entry);
            }
        }
        None
    }

    /// Release all locks in the given range owned by `owner`.
    fn release_lock(&mut self, start: u64, end: u64, owner: u64) -> Result<()> {
        for slot in &mut self.locks {
            if let Some(lock) = slot {
                if lock.owner == owner && lock.start <= end && start <= lock.end {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                }
            }
        }
        Ok(())
    }

    /// Release all locks held by a process (called on process exit).
    pub fn release_all_by_pid(&mut self, pid: u32) {
        for slot in &mut self.locks {
            if let Some(lock) = slot {
                if lock.pid == pid {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                }
            }
        }
    }

    /// Release all locks held by an open file description.
    pub fn release_all_by_owner(&mut self, owner: u64) {
        for slot in &mut self.locks {
            if let Some(lock) = slot {
                if lock.owner == owner {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                }
            }
        }
    }

    /// Return current lock count.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for PosixLockTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a flock structure to an absolute byte range.
///
/// `file_size` is the current file size for `SeekEnd` interpretation.
/// `current_pos` is used for `SeekCur`.
pub fn flock_to_range(flock: &FlockStruct, file_size: u64, current_pos: u64) -> Result<(u64, u64)> {
    let base: i64 = match flock.l_whence {
        LockWhence::SeekSet => 0,
        LockWhence::SeekCur => current_pos as i64,
        LockWhence::SeekEnd => file_size as i64,
    };
    let start = base
        .checked_add(flock.l_start)
        .ok_or(Error::InvalidArgument)?;
    if start < 0 {
        return Err(Error::InvalidArgument);
    }
    let start = start as u64;
    let end = if flock.l_len == 0 {
        u64::MAX
    } else if flock.l_len < 0 {
        let e = start as i64 + flock.l_len - 1;
        if e < 0 {
            return Err(Error::InvalidArgument);
        }
        e as u64
    } else {
        start + (flock.l_len as u64) - 1
    };
    if start > end {
        return Err(Error::InvalidArgument);
    }
    Ok((start, end))
}

/// Process an `F_SETLK` / `F_SETLKW` request.
///
/// `blocking` — if true, the caller would block (not yet implemented in no_std).
pub fn fcntl_setlk(
    table: &mut PosixLockTable,
    flock: &FlockStruct,
    file_size: u64,
    current_pos: u64,
    pid: u32,
    owner: u64,
    blocking: bool,
) -> Result<()> {
    let (start, end) = flock_to_range(flock, file_size, current_pos)?;
    let lock = PosixLock::new(flock.l_type, start, end, pid, owner);
    let result = table.set_lock(lock);
    if blocking && result == Err(Error::WouldBlock) {
        // In a full implementation this would sleep on a wait queue.
        return Err(Error::WouldBlock);
    }
    result
}

/// Process an `F_GETLK` request — test if a lock would be blocked.
pub fn fcntl_getlk(
    table: &PosixLockTable,
    flock: &mut FlockStruct,
    file_size: u64,
    current_pos: u64,
    pid: u32,
    owner: u64,
) -> Result<()> {
    let (start, end) = flock_to_range(flock, file_size, current_pos)?;
    let query = PosixLock::new(flock.l_type, start, end, pid, owner);
    match table.get_lock(&query) {
        Some(blocker) => {
            flock.l_type = blocker.lock_type;
            flock.l_pid = blocker.pid;
            flock.l_start = blocker.start as i64;
            flock.l_len = if blocker.end == u64::MAX {
                0
            } else {
                (blocker.end - blocker.start + 1) as i64
            };
            flock.l_whence = LockWhence::SeekSet;
        }
        None => {
            flock.l_type = PosixLockType::Unlock;
        }
    }
    Ok(())
}
