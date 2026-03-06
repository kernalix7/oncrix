// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `flock(2)` — apply or remove an advisory file lock.
//!
//! `flock()` provides whole-file advisory locking using file descriptors.
//! Unlike POSIX record locks (`fcntl(F_SETLK)`), `flock()` locks are
//! associated with the open file description (not the process), so they
//! are inherited across `fork(2)` and duplicated file descriptors share
//! the same lock.
//!
//! # Lock types
//!
//! | Flag | Value | Description |
//! |------|-------|-------------|
//! | `LOCK_SH` | 1 | Shared (read) lock — multiple holders allowed |
//! | `LOCK_EX` | 2 | Exclusive (write) lock — only one holder allowed |
//! | `LOCK_NB` | 4 | Non-blocking — return `EWOULDBLOCK` instead of blocking |
//! | `LOCK_UN` | 8 | Unlock |
//!
//! # Semantics
//!
//! - A process may hold at most one type of lock per file.
//! - Upgrading (`LOCK_SH` → `LOCK_EX`) and downgrading are atomic.
//! - `LOCK_NB` can be OR-ed with `LOCK_SH` or `LOCK_EX`.
//! - Locks are released on the last `close(2)` of any descriptor
//!   referring to the file, or on process exit.
//!
//! # POSIX / Linux
//!
//! `flock(2)` is a Linux-specific (BSD-derived) system call.  POSIX
//! specifies `fcntl(F_SETLK/F_SETLKW)` for advisory locking.  This
//! module implements both the `flock(2)` syscall and advisory-lock state
//! management compatible with open-file-description semantics.
//!
//! # References
//!
//! - Linux: `fs/locks.c`
//! - man: `flock(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Lock flags
// ---------------------------------------------------------------------------

/// Request a shared (read) lock.
pub const LOCK_SH: u32 = 1;

/// Request an exclusive (write) lock.
pub const LOCK_EX: u32 = 2;

/// Non-blocking flag — do not block if the lock cannot be acquired.
pub const LOCK_NB: u32 = 4;

/// Release the lock.
pub const LOCK_UN: u32 = 8;

/// Mask of valid `flock` operation bits.
const LOCK_VALID_MASK: u32 = LOCK_SH | LOCK_EX | LOCK_NB | LOCK_UN;

// ---------------------------------------------------------------------------
// Lock type
// ---------------------------------------------------------------------------

/// The type of an advisory flock.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlockType {
    /// No lock held.
    #[default]
    Unlocked = 0,
    /// Shared (read) lock.
    Shared = 1,
    /// Exclusive (write) lock.
    Exclusive = 2,
}

impl FlockType {
    /// Returns `true` if this lock type conflicts with `other` when
    /// acquired by a different holder.
    pub const fn conflicts_with(&self, other: &FlockType) -> bool {
        matches!(
            (self, other),
            (FlockType::Exclusive, FlockType::Shared)
                | (FlockType::Exclusive, FlockType::Exclusive)
                | (FlockType::Shared, FlockType::Exclusive)
        )
    }

    /// Parse a lock type from raw `flock(2)` flags.
    ///
    /// Returns [`None`] if the flags are invalid or mutually exclusive.
    pub fn from_flags(flags: u32) -> Option<(FlockType, bool)> {
        if flags & !LOCK_VALID_MASK != 0 {
            return None;
        }
        let op = flags & !LOCK_NB;
        let nonblock = (flags & LOCK_NB) != 0;
        let lock_type = match op {
            LOCK_SH => FlockType::Shared,
            LOCK_EX => FlockType::Exclusive,
            LOCK_UN => FlockType::Unlocked,
            _ => return None,
        };
        Some((lock_type, nonblock))
    }
}

// ---------------------------------------------------------------------------
// Open file description lock slot
// ---------------------------------------------------------------------------

/// Unique identifier for an open file description.
pub type OfdId = u64;

/// A single advisory flock held by one open file description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlockEntry {
    /// The open file description that holds this lock.
    pub ofd_id: OfdId,
    /// The type of lock held.
    pub lock_type: FlockType,
    /// PID of the process that acquired the lock (informational).
    pub owner_pid: u32,
}

impl FlockEntry {
    /// Create a new lock entry.
    pub const fn new(ofd_id: OfdId, lock_type: FlockType, owner_pid: u32) -> Self {
        Self {
            ofd_id,
            lock_type,
            owner_pid,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-inode flock state
// ---------------------------------------------------------------------------

/// Maximum number of concurrent flock holders per inode.
const MAX_FLOCK_HOLDERS: usize = 128;

/// Advisory flock state for a single inode.
///
/// Tracks all `flock(2)` locks held on one file, using an open-file-
/// description model: each lock entry is identified by its [`OfdId`].
pub struct FlockState {
    /// Active lock entries.
    entries: [Option<FlockEntry>; MAX_FLOCK_HOLDERS],
    /// Total number of locks currently held.
    count: usize,
    /// Number of exclusive locks (should be 0 or 1).
    exclusive_count: usize,
    /// Number of shared locks.
    shared_count: usize,
    /// Number of waiters blocked trying to acquire an exclusive lock.
    exclusive_waiters: u32,
}

impl FlockState {
    /// Create empty per-inode flock state.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_FLOCK_HOLDERS],
            count: 0,
            exclusive_count: 0,
            shared_count: 0,
            exclusive_waiters: 0,
        }
    }

    /// Returns `true` if `lock_type` can be acquired without conflict given
    /// the current state (ignoring the requesting `ofd_id`'s existing lock).
    pub fn can_acquire(&self, ofd_id: OfdId, lock_type: &FlockType) -> bool {
        match lock_type {
            FlockType::Unlocked => true,
            FlockType::Shared => {
                // Shared lock allowed if there are no exclusive holders
                // from *other* OFDs.
                !self
                    .entries
                    .iter()
                    .flatten()
                    .any(|e| e.ofd_id != ofd_id && e.lock_type == FlockType::Exclusive)
            }
            FlockType::Exclusive => {
                // Exclusive lock allowed if no other OFD holds any lock.
                !self.entries.iter().flatten().any(|e| e.ofd_id != ofd_id)
            }
        }
    }

    /// Find the slot index for `ofd_id`, if any.
    fn find_slot(&self, ofd_id: OfdId) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.map_or(false, |e| e.ofd_id == ofd_id))
    }

    /// Find a free slot.
    fn free_slot(&self) -> Option<usize> {
        self.entries.iter().position(|e| e.is_none())
    }

    /// Insert or update a lock for `ofd_id`.
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn set_lock(&mut self, entry: FlockEntry) -> Result<()> {
        if let Some(idx) = self.find_slot(entry.ofd_id) {
            // Update existing entry.
            let old = self.entries[idx].take().unwrap();
            match old.lock_type {
                FlockType::Exclusive => {
                    self.exclusive_count = self.exclusive_count.saturating_sub(1)
                }
                FlockType::Shared => self.shared_count = self.shared_count.saturating_sub(1),
                FlockType::Unlocked => {}
            }
            if entry.lock_type != FlockType::Unlocked {
                match entry.lock_type {
                    FlockType::Exclusive => self.exclusive_count += 1,
                    FlockType::Shared => self.shared_count += 1,
                    FlockType::Unlocked => {}
                }
                self.entries[idx] = Some(entry);
            } else {
                self.count = self.count.saturating_sub(1);
            }
        } else if entry.lock_type != FlockType::Unlocked {
            let slot = self.free_slot().ok_or(Error::OutOfMemory)?;
            match entry.lock_type {
                FlockType::Exclusive => self.exclusive_count += 1,
                FlockType::Shared => self.shared_count += 1,
                FlockType::Unlocked => {}
            }
            self.entries[slot] = Some(entry);
            self.count += 1;
        }
        Ok(())
    }

    /// Release the lock held by `ofd_id`.
    ///
    /// Returns `true` if a lock was actually removed.
    pub fn unlock(&mut self, ofd_id: OfdId) -> bool {
        if let Some(idx) = self.find_slot(ofd_id) {
            let entry = self.entries[idx].take().unwrap();
            match entry.lock_type {
                FlockType::Exclusive => {
                    self.exclusive_count = self.exclusive_count.saturating_sub(1)
                }
                FlockType::Shared => self.shared_count = self.shared_count.saturating_sub(1),
                FlockType::Unlocked => {}
            }
            self.count = self.count.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Query the current lock type held by `ofd_id`.
    pub fn query(&self, ofd_id: OfdId) -> FlockType {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.ofd_id == ofd_id)
            .map_or(FlockType::Unlocked, |e| e.lock_type)
    }

    /// Number of active lock holders.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Number of exclusive lock holders (0 or 1 under correct use).
    pub const fn exclusive_count(&self) -> usize {
        self.exclusive_count
    }

    /// Number of shared lock holders.
    pub const fn shared_count(&self) -> usize {
        self.shared_count
    }

    /// Increment the exclusive-waiter counter.
    pub fn add_waiter(&mut self) {
        self.exclusive_waiters = self.exclusive_waiters.saturating_add(1);
    }

    /// Decrement the exclusive-waiter counter.
    pub fn remove_waiter(&mut self) {
        self.exclusive_waiters = self.exclusive_waiters.saturating_sub(1);
    }

    /// Number of processes waiting for an exclusive lock.
    pub const fn exclusive_waiters(&self) -> u32 {
        self.exclusive_waiters
    }
}

impl Default for FlockState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// flock result
// ---------------------------------------------------------------------------

/// Outcome of a `flock(2)` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlockOutcome {
    /// Lock was acquired (or already held by this OFD).
    Acquired,
    /// Lock was upgraded (shared → exclusive).
    Upgraded,
    /// Lock was downgraded (exclusive → shared).
    Downgraded,
    /// Lock was released.
    Released,
    /// No lock was held; unlock was a no-op.
    AlreadyUnlocked,
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// Implement `flock(2)` — acquire, upgrade, downgrade, or release an
/// advisory file lock.
///
/// # Arguments
///
/// - `state` — The per-inode flock state to modify.
/// - `ofd_id` — Unique ID of the open file description.
/// - `owner_pid` — PID of the calling process.
/// - `flags` — `flock(2)` operation flags (`LOCK_SH | LOCK_EX | LOCK_UN`,
///   optionally OR-ed with `LOCK_NB`).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Invalid or mutually exclusive flags.
/// - [`Error::WouldBlock`] — `LOCK_NB` was set and the lock cannot be
///   acquired immediately.
/// - [`Error::OutOfMemory`] — Flock table is full.
///
/// # POSIX
///
/// `flock(2)` is not strictly POSIX but is widely implemented.
/// See `fcntl(2)` `F_SETLK`/`F_SETLKW` for the POSIX equivalent.
pub fn sys_flock(
    state: &mut FlockState,
    ofd_id: OfdId,
    owner_pid: u32,
    flags: u32,
) -> Result<FlockOutcome> {
    let (lock_type, nonblock) = FlockType::from_flags(flags).ok_or(Error::InvalidArgument)?;

    match lock_type {
        FlockType::Unlocked => {
            let removed = state.unlock(ofd_id);
            if removed {
                Ok(FlockOutcome::Released)
            } else {
                Ok(FlockOutcome::AlreadyUnlocked)
            }
        }
        _ => {
            let current = state.query(ofd_id);

            if !state.can_acquire(ofd_id, &lock_type) {
                if nonblock {
                    return Err(Error::WouldBlock);
                }
                // In a real implementation this would block; here we
                // track the waiter count and return WouldBlock as the
                // kernel-space representation of "must reschedule".
                state.add_waiter();
                return Err(Error::WouldBlock);
            }

            let entry = FlockEntry::new(ofd_id, lock_type, owner_pid);
            state.set_lock(entry)?;

            let outcome = match (current, lock_type) {
                (FlockType::Unlocked, _) => FlockOutcome::Acquired,
                (FlockType::Shared, FlockType::Exclusive) => FlockOutcome::Upgraded,
                (FlockType::Exclusive, FlockType::Shared) => FlockOutcome::Downgraded,
                _ => FlockOutcome::Acquired,
            };
            Ok(outcome)
        }
    }
}

/// Query the current lock type held by an open file description.
///
/// # Arguments
///
/// - `state` — The per-inode flock state.
/// - `ofd_id` — Open file description identifier.
///
/// # Returns
///
/// The [`FlockType`] currently held by `ofd_id`, or [`FlockType::Unlocked`]
/// if no lock is held.
pub fn sys_flock_query(state: &FlockState, ofd_id: OfdId) -> FlockType {
    state.query(ofd_id)
}

/// Release all locks held by an open file description (called on `close`).
///
/// Must be called when the last reference to an open file description is
/// dropped, to ensure stale locks do not persist.
///
/// # Arguments
///
/// - `state` — The per-inode flock state.
/// - `ofd_id` — Open file description being closed.
pub fn sys_flock_release_on_close(state: &mut FlockState, ofd_id: OfdId) {
    state.unlock(ofd_id);
}

/// Check whether a lock can be acquired without blocking.
///
/// Used by `fcntl(F_GETLK)` to report conflicting locks.
///
/// # Arguments
///
/// - `state` — The per-inode flock state.
/// - `ofd_id` — Caller's OFD.
/// - `lock_type` — Desired lock type.
///
/// # Returns
///
/// `true` if the lock can be acquired immediately.
pub fn sys_flock_can_acquire(state: &FlockState, ofd_id: OfdId, lock_type: FlockType) -> bool {
    state.can_acquire(ofd_id, &lock_type)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_lock() {
        let mut state = FlockState::new();
        let result = sys_flock(&mut state, 1, 100, LOCK_SH).unwrap();
        assert_eq!(result, FlockOutcome::Acquired);
        assert_eq!(state.shared_count(), 1);
    }

    #[test]
    fn test_exclusive_lock() {
        let mut state = FlockState::new();
        sys_flock(&mut state, 1, 100, LOCK_EX).unwrap();
        assert_eq!(state.exclusive_count(), 1);
    }

    #[test]
    fn test_unlock() {
        let mut state = FlockState::new();
        sys_flock(&mut state, 1, 100, LOCK_SH).unwrap();
        let result = sys_flock(&mut state, 1, 100, LOCK_UN).unwrap();
        assert_eq!(result, FlockOutcome::Released);
        assert_eq!(state.count(), 0);
    }

    #[test]
    fn test_upgrade() {
        let mut state = FlockState::new();
        sys_flock(&mut state, 1, 100, LOCK_SH).unwrap();
        let result = sys_flock(&mut state, 1, 100, LOCK_EX).unwrap();
        assert_eq!(result, FlockOutcome::Upgraded);
    }

    #[test]
    fn test_exclusive_conflict_nonblock() {
        let mut state = FlockState::new();
        sys_flock(&mut state, 1, 100, LOCK_EX).unwrap();
        let result = sys_flock(&mut state, 2, 101, LOCK_SH | LOCK_NB);
        assert!(matches!(result, Err(Error::WouldBlock)));
    }

    #[test]
    fn test_multiple_shared() {
        let mut state = FlockState::new();
        sys_flock(&mut state, 1, 100, LOCK_SH).unwrap();
        sys_flock(&mut state, 2, 101, LOCK_SH).unwrap();
        assert_eq!(state.shared_count(), 2);
    }

    #[test]
    fn test_invalid_flags() {
        let mut state = FlockState::new();
        let result = sys_flock(&mut state, 1, 100, 0xFF);
        assert!(result.is_err());
    }
}
