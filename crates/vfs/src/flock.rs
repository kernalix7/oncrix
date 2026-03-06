// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX file locking: `flock(2)` and `fcntl(2)` advisory locks.
//!
//! Provides whole-file locks (`flock`) and byte-range advisory record
//! locks (`fcntl` with `F_GETLK`/`F_SETLK`/`F_SETLKW`).
//!
//! # Conflict rules
//!
//! - A shared (read) lock conflicts with an exclusive (write) lock
//!   held by a **different** owner.
//! - An exclusive (write) lock conflicts with both shared and
//!   exclusive locks held by a **different** owner.
//! - Locks held by the **same** owner never conflict with each other.
//!
//! # References
//!
//! - POSIX.1-2024 `fcntl()` — advisory record locking
//! - Linux `flock(2)` — BSD-style whole-file advisory locking

use oncrix_lib::{Error, Result};

// ── flock(2) operation constants ──────────────────────────────

/// Apply a shared (read) lock.
pub const LOCK_SH: u32 = 1;
/// Apply an exclusive (write) lock.
pub const LOCK_EX: u32 = 2;
/// Non-blocking flag (combine with `LOCK_SH` or `LOCK_EX`).
pub const LOCK_NB: u32 = 4;
/// Release the lock.
pub const LOCK_UN: u32 = 8;

// ── fcntl(2) lock-type constants ──────────────────────────────

/// Shared (read) lock.
pub const F_RDLCK: i16 = 0;
/// Exclusive (write) lock.
pub const F_WRLCK: i16 = 1;
/// Unlock (release).
pub const F_UNLCK: i16 = 2;

// ── fcntl(2) command constants for record locking ─────────────

/// Get the first lock that blocks the described lock.
pub const F_GETLK: u32 = 5;
/// Set or clear a lock (non-blocking).
pub const F_SETLK: u32 = 6;
/// Set or clear a lock (blocking — wait if necessary).
pub const F_SETLKW: u32 = 7;

// ── POSIX `struct flock` ──────────────────────────────────────

/// POSIX `struct flock` as used by `fcntl(F_GETLK/F_SETLK/F_SETLKW)`.
///
/// Layout matches the C ABI so the struct can be passed directly
/// between user space and the kernel via `copy_from_user`/`copy_to_user`.
///
/// # Fields
///
/// - `l_type`   — lock type: [`F_RDLCK`], [`F_WRLCK`], or [`F_UNLCK`]
/// - `l_whence` — offset origin: `SEEK_SET` (0), `SEEK_CUR` (1),
///   or `SEEK_END` (2)
/// - `l_start`  — starting byte offset (relative to `l_whence`)
/// - `l_len`    — number of bytes to lock; **0 means to EOF**
/// - `l_pid`    — PID of the process holding the lock (set by
///   `F_GETLK` only)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Flock {
    /// Lock type.
    pub l_type: i16,
    /// Offset base.
    pub l_whence: i16,
    /// Starting offset.
    pub l_start: i64,
    /// Number of bytes (0 = to EOF).
    pub l_len: i64,
    /// PID of lock holder (returned by `F_GETLK`).
    pub l_pid: i32,
}

// ── Internal kernel lock representation ──────────────────────

/// Maximum number of concurrent file locks system-wide.
const MAX_LOCKS: usize = 256;

/// An active file lock (kernel-internal representation).
///
/// Represents either a whole-file `flock`-style lock (where
/// `start == 0` and `len == 0`) or a byte-range `fcntl`-style
/// record lock.
#[derive(Debug, Clone, Copy)]
pub struct FileLock {
    /// Inode number the lock applies to.
    pub inode: u64,
    /// Lock type: [`LOCK_SH`] or [`LOCK_EX`] for `flock`;
    /// [`F_RDLCK`] or [`F_WRLCK`] (cast to `u8`) for `fcntl`.
    pub lock_type: u8,
    /// PID of the lock owner.
    pub owner_pid: u64,
    /// Start offset of the locked region (0 for whole-file locks).
    pub start: u64,
    /// Length of the locked region (0 means to EOF).
    pub len: u64,
}

/// Test whether two byte ranges overlap.
///
/// A length of 0 means "to end of file" (i.e., unbounded above).
fn ranges_overlap(a_start: u64, a_len: u64, b_start: u64, b_len: u64) -> bool {
    let a_end = if a_len == 0 {
        u64::MAX
    } else {
        a_start.saturating_add(a_len)
    };
    let b_end = if b_len == 0 {
        u64::MAX
    } else {
        b_start.saturating_add(b_len)
    };
    a_start < b_end && b_start < a_end
}

/// Test whether a lock type represents a shared (read) lock.
const fn is_shared(lock_type: u8) -> bool {
    lock_type == LOCK_SH as u8 || lock_type == F_RDLCK as u8
}

/// Test whether a lock type represents an exclusive (write) lock.
const fn is_exclusive(lock_type: u8) -> bool {
    lock_type == LOCK_EX as u8 || lock_type == F_WRLCK as u8
}

// ── File lock table ──────────────────────────────────────────

/// System-wide file lock table.
///
/// Stores up to [`MAX_LOCKS`] concurrent locks. Both `flock`-style
/// whole-file locks and `fcntl`-style byte-range locks share a
/// single flat table.
pub struct FileLockTable {
    /// Lock slots.
    locks: [Option<FileLock>; MAX_LOCKS],
}

impl Default for FileLockTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FileLockTable {
    /// Create an empty file lock table.
    pub const fn new() -> Self {
        const NONE: Option<FileLock> = None;
        Self {
            locks: [NONE; MAX_LOCKS],
        }
    }

    /// Apply a BSD-style `flock` lock (whole-file, advisory).
    ///
    /// # Arguments
    ///
    /// - `inode` — inode number of the file to lock
    /// - `pid` — PID of the calling process
    /// - `operation` — bitmask of [`LOCK_SH`], [`LOCK_EX`],
    ///   [`LOCK_UN`], and optionally [`LOCK_NB`]
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — invalid operation flags
    /// - [`Error::WouldBlock`] — `LOCK_NB` was set and a
    ///   conflicting lock exists
    /// - [`Error::OutOfMemory`] — no free lock slots
    pub fn flock_lock(&mut self, inode: u64, pid: u64, operation: u32) -> Result<()> {
        let non_blocking = (operation & LOCK_NB) != 0;
        let base_op = operation & !LOCK_NB;

        match base_op {
            LOCK_UN => {
                self.release_flock(inode, pid);
                Ok(())
            }
            LOCK_SH | LOCK_EX => {
                // Release any existing flock held by this pid on
                // this inode before acquiring the new one (upgrade
                // / downgrade semantics).
                self.release_flock(inode, pid);

                let new_type = if base_op == LOCK_SH {
                    LOCK_SH as u8
                } else {
                    LOCK_EX as u8
                };

                // Check for conflicts with other owners.
                if self.has_flock_conflict(inode, pid, new_type) {
                    if non_blocking {
                        return Err(Error::WouldBlock);
                    }
                    // Blocking semantics: in a full implementation
                    // the caller would be put to sleep here. For
                    // now, return WouldBlock as well (the scheduler
                    // integration will retry).
                    return Err(Error::WouldBlock);
                }

                self.insert_lock(FileLock {
                    inode,
                    lock_type: new_type,
                    owner_pid: pid,
                    start: 0,
                    len: 0,
                })
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Query for a conflicting lock (`F_GETLK`).
    ///
    /// If a lock exists that would prevent the described lock from
    /// being placed, the conflicting lock is returned (with `l_pid`
    /// set to the owner). Otherwise the returned [`Flock`] has
    /// `l_type` set to [`F_UNLCK`].
    pub fn fcntl_getlk(&self, inode: u64, lock: &Flock) -> Flock {
        let req_start = if lock.l_start >= 0 {
            lock.l_start as u64
        } else {
            0
        };
        let req_len = if lock.l_len >= 0 {
            lock.l_len as u64
        } else {
            0
        };
        let req_type = lock.l_type as u8;
        let req_pid = if lock.l_pid >= 0 {
            lock.l_pid as u64
        } else {
            0
        };

        for existing in self.locks.iter().flatten() {
            if existing.inode != inode {
                continue;
            }
            if existing.owner_pid == req_pid {
                continue;
            }
            if !ranges_overlap(existing.start, existing.len, req_start, req_len) {
                continue;
            }
            if Self::types_conflict(req_type, existing.lock_type) {
                return Flock {
                    l_type: if is_shared(existing.lock_type) {
                        F_RDLCK
                    } else {
                        F_WRLCK
                    },
                    l_whence: 0, // SEEK_SET
                    l_start: existing.start as i64,
                    l_len: existing.len as i64,
                    l_pid: existing.owner_pid as i32,
                };
            }
        }

        // No conflict — return F_UNLCK.
        Flock {
            l_type: F_UNLCK,
            l_whence: lock.l_whence,
            l_start: lock.l_start,
            l_len: lock.l_len,
            l_pid: lock.l_pid,
        }
    }

    /// Set or release a byte-range lock (`F_SETLK` semantics).
    ///
    /// # Arguments
    ///
    /// - `inode` — inode number
    /// - `pid` — PID of the calling process
    /// - `lock` — lock description (from user space)
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — invalid lock type
    /// - [`Error::WouldBlock`] — a conflicting lock exists
    /// - [`Error::OutOfMemory`] — no free lock slots
    pub fn fcntl_setlk(&mut self, inode: u64, pid: u64, lock: &Flock) -> Result<()> {
        let start = if lock.l_start >= 0 {
            lock.l_start as u64
        } else {
            0
        };
        let len = if lock.l_len >= 0 {
            lock.l_len as u64
        } else {
            0
        };

        match lock.l_type {
            F_UNLCK => {
                self.release_range(inode, pid, start, len);
                Ok(())
            }
            F_RDLCK | F_WRLCK => {
                let new_type = lock.l_type as u8;

                // Remove any existing locks by the same owner that
                // overlap the requested range (POSIX: replaced).
                self.release_range(inode, pid, start, len);

                // Check for conflicts with other owners.
                for existing in self.locks.iter().flatten() {
                    if existing.inode != inode {
                        continue;
                    }
                    if existing.owner_pid == pid {
                        continue;
                    }
                    if !ranges_overlap(existing.start, existing.len, start, len) {
                        continue;
                    }
                    if Self::types_conflict(new_type, existing.lock_type) {
                        return Err(Error::WouldBlock);
                    }
                }

                self.insert_lock(FileLock {
                    inode,
                    lock_type: new_type,
                    owner_pid: pid,
                    start,
                    len,
                })
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Release **all** locks held by `pid`.
    ///
    /// Called during process exit cleanup to ensure no stale locks
    /// remain.
    pub fn release_all(&mut self, pid: u64) {
        for slot in &mut self.locks {
            if let Some(lock) = slot {
                if lock.owner_pid == pid {
                    *slot = None;
                }
            }
        }
    }

    /// Count the number of locks on a given inode.
    pub fn count_locks(&self, inode: u64) -> usize {
        self.locks
            .iter()
            .filter(|s| s.as_ref().is_some_and(|l| l.inode == inode))
            .count()
    }

    // ── Private helpers ──────────────────────────────────────

    /// Insert a lock into the first available slot.
    fn insert_lock(&mut self, lock: FileLock) -> Result<()> {
        for slot in &mut self.locks {
            if slot.is_none() {
                *slot = Some(lock);
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove all `flock`-style (whole-file) locks held by `pid`
    /// on `inode`.
    fn release_flock(&mut self, inode: u64, pid: u64) {
        for slot in &mut self.locks {
            if let Some(lock) = slot {
                if lock.inode == inode && lock.owner_pid == pid && lock.start == 0 && lock.len == 0
                {
                    *slot = None;
                }
            }
        }
    }

    /// Remove all locks by `pid` on `inode` that overlap
    /// `[start, start+len)`.
    fn release_range(&mut self, inode: u64, pid: u64, start: u64, len: u64) {
        for slot in &mut self.locks {
            if let Some(lock) = slot {
                if lock.inode == inode
                    && lock.owner_pid == pid
                    && ranges_overlap(lock.start, lock.len, start, len)
                {
                    *slot = None;
                }
            }
        }
    }

    /// Check whether a flock-style whole-file conflict exists.
    fn has_flock_conflict(&self, inode: u64, pid: u64, new_type: u8) -> bool {
        for existing in self.locks.iter().flatten() {
            if existing.inode != inode {
                continue;
            }
            if existing.owner_pid == pid {
                continue;
            }
            if Self::types_conflict(new_type, existing.lock_type) {
                return true;
            }
        }
        false
    }

    /// Determine whether two lock types conflict.
    ///
    /// - Shared vs. shared: no conflict
    /// - Shared vs. exclusive: conflict
    /// - Exclusive vs. anything: conflict
    fn types_conflict(a: u8, b: u8) -> bool {
        if is_exclusive(a) || is_exclusive(b) {
            return true;
        }
        // Both shared — no conflict.
        false
    }
}
