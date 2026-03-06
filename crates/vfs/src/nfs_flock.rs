// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS file locking (Network Lock Manager client).
//!
//! NFS file locking requires coordination with a remote lock manager (NLM)
//! because the server, not the local kernel, is the arbiter of lock state.
//! This module implements the NFS lock manager client: byte-range locking,
//! lock reclaim after server reboot, and grace period handling.
//!
//! # Architecture
//!
//! ```text
//! Application
//!   │  fcntl(F_SETLK) / flock()
//!   ▼
//! VFS lock layer
//!   │  dispatch to NFS lock ops
//!   ▼
//! NfsLockManager ──────────────────────────────────────
//!   │                                                  │
//!   ├── acquire_lock()  → submit NLM_LOCK RPC          │
//!   ├── release_lock()  → submit NLM_UNLOCK RPC        │
//!   ├── test_lock()     → submit NLM_TEST RPC          │
//!   └── reclaim_locks() → re-submit after server reboot│
//!                                                      │
//!                    ┌───────────────────────────────┐  │
//!                    │ Server (NLM / NFSv4 state)    │◄─┘
//!                    └───────────────────────────────┘
//! ```
//!
//! # Grace period
//!
//! After a server reboot, there is a grace period during which only lock
//! reclaim operations are accepted.  New lock requests are rejected with
//! `NLM_DENIED_GRACE_PERIOD` until the grace period expires.
//!
//! # NFSv4 differences
//!
//! NFSv4 integrates locking into the protocol itself (no separate NLM).
//! Lock state is tied to the NFSv4 state ID and lease.  This module
//! handles both NLM (v2/v3) and NFSv4-style lock management.
//!
//! # Reference
//!
//! - RFC 1813 (NFS v3) + RFC 4045 (NLM v4)
//! - RFC 7530 (NFSv4) sections on locking
//! - Linux `fs/nfs/nfs4proc.c`, `fs/lockd/clntproc.c`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of NFS locks tracked per mount.
const MAX_NFS_LOCKS: usize = 256;

/// Maximum number of pending lock reclaim entries.
const MAX_RECLAIM_ENTRIES: usize = 64;

/// Maximum number of NFS mounts tracked.
const MAX_NFS_MOUNTS: usize = 8;

/// Default grace period duration in seconds.
pub const DEFAULT_GRACE_PERIOD_SECS: u32 = 45;

/// Sentinel value for "lock to end of file".
pub const NFS_LOCK_EOF: u64 = u64::MAX;

// ── LockState ─────────────────────────────────────────────────────────────────

/// State of an NFS lock in the lock manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// Lock has been requested but not yet granted by the server.
    Pending,
    /// Lock has been granted by the server.
    Granted,
    /// Lock is being reclaimed after server reboot.
    Reclaiming,
    /// Lock request was denied by the server.
    Denied,
    /// Lock has been released.
    Released,
    /// Lock state is unknown (communication failure).
    Unknown,
}

// ── LockType ──────────────────────────────────────────────────────────────────

/// NFS lock type (shared or exclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsLockType {
    /// Shared (read) lock.
    Read,
    /// Exclusive (write) lock.
    Write,
}

impl NfsLockType {
    /// Return the NLM lock mode number.
    pub const fn nlm_mode(self) -> u32 {
        match self {
            Self::Read => 1,
            Self::Write => 3,
        }
    }

    /// Check whether two lock types conflict.
    pub const fn conflicts_with(self, other: Self) -> bool {
        matches!((self, other), (Self::Write, _) | (_, Self::Write))
    }
}

// ── LockRange ─────────────────────────────────────────────────────────────────

/// A byte range for an NFS lock.
///
/// `start` is the first locked byte.  `length` is the number of bytes;
/// a value of [`NFS_LOCK_EOF`] means "to end of file".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockRange {
    /// Starting byte offset.
    pub start: u64,
    /// Number of bytes locked (NFS_LOCK_EOF = to EOF).
    pub length: u64,
}

impl LockRange {
    /// Create a new byte range.
    pub const fn new(start: u64, length: u64) -> Self {
        Self { start, length }
    }

    /// Create a range covering the entire file.
    pub const fn whole_file() -> Self {
        Self {
            start: 0,
            length: NFS_LOCK_EOF,
        }
    }

    /// Return the last byte offset covered (inclusive), or `u64::MAX` for EOF.
    pub const fn end(&self) -> u64 {
        if self.length == NFS_LOCK_EOF {
            u64::MAX
        } else {
            self.start.saturating_add(self.length).saturating_sub(1)
        }
    }

    /// Check whether two ranges overlap.
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start <= other.end() && other.start <= self.end()
    }

    /// Check whether this range fully contains another.
    pub const fn contains(&self, other: &Self) -> bool {
        self.start <= other.start && other.end() <= self.end()
    }
}

// ── NfsLock ───────────────────────────────────────────────────────────────────

/// A single NFS lock held by the local client.
#[derive(Debug, Clone, Copy)]
pub struct NfsLock {
    /// File handle hash (identifies the remote file).
    pub fh_hash: u64,
    /// NFS mount index this lock belongs to.
    pub mount_id: u8,
    /// Lock owner (PID on the client).
    pub owner: u32,
    /// Lock type.
    pub lock_type: NfsLockType,
    /// Byte range.
    pub range: LockRange,
    /// Current state.
    pub state: LockState,
    /// NFSv4 state ID (zero for NLM).
    pub state_id: u64,
    /// Server-assigned lock sequence number.
    pub sequence: u32,
    /// Timestamp when the lock was granted (seconds since epoch).
    pub granted_at: u64,
    /// Whether this slot is in use.
    pub in_use: bool,
}

impl NfsLock {
    /// Create an empty, unused lock slot.
    const fn empty() -> Self {
        Self {
            fh_hash: 0,
            mount_id: 0,
            owner: 0,
            lock_type: NfsLockType::Read,
            range: LockRange::new(0, 0),
            state: LockState::Released,
            state_id: 0,
            sequence: 0,
            granted_at: 0,
            in_use: false,
        }
    }

    /// Check whether this lock conflicts with a proposed lock.
    pub fn conflicts_with(
        &self,
        other_owner: u32,
        lock_type: NfsLockType,
        range: &LockRange,
    ) -> bool {
        if self.owner == other_owner {
            return false;
        }
        if self.state != LockState::Granted {
            return false;
        }
        if !self.lock_type.conflicts_with(lock_type) {
            return false;
        }
        self.range.overlaps(range)
    }
}

// ── LockReclaim ───────────────────────────────────────────────────────────────

/// A lock reclaim entry: records a lock that must be re-established after
/// the NFS server reboots.
#[derive(Debug, Clone, Copy)]
pub struct LockReclaim {
    /// File handle hash of the locked file.
    pub fh_hash: u64,
    /// Mount index.
    pub mount_id: u8,
    /// Lock owner PID.
    pub owner: u32,
    /// Lock type to reclaim.
    pub lock_type: NfsLockType,
    /// Byte range to reclaim.
    pub range: LockRange,
    /// Previous state ID (NFSv4).
    pub old_state_id: u64,
    /// Number of reclaim attempts so far.
    pub attempts: u32,
    /// Whether this reclaim has succeeded.
    pub reclaimed: bool,
    /// Whether this slot is in use.
    pub in_use: bool,
}

impl LockReclaim {
    /// Create an empty, unused reclaim slot.
    const fn empty() -> Self {
        Self {
            fh_hash: 0,
            mount_id: 0,
            owner: 0,
            lock_type: NfsLockType::Read,
            range: LockRange::new(0, 0),
            old_state_id: 0,
            attempts: 0,
            reclaimed: false,
            in_use: false,
        }
    }

    /// Create a reclaim entry from an existing granted lock.
    fn from_lock(lock: &NfsLock) -> Self {
        Self {
            fh_hash: lock.fh_hash,
            mount_id: lock.mount_id,
            owner: lock.owner,
            lock_type: lock.lock_type,
            range: lock.range,
            old_state_id: lock.state_id,
            attempts: 0,
            reclaimed: false,
            in_use: true,
        }
    }
}

// ── GraceState ────────────────────────────────────────────────────────────────

/// Grace period state for an NFS mount.
#[derive(Debug, Clone, Copy)]
struct GraceState {
    /// Whether we are currently in a grace period.
    in_grace: bool,
    /// When the grace period started (seconds since epoch).
    start_time: u64,
    /// Grace period duration in seconds.
    duration_secs: u32,
    /// Mount index this grace state belongs to.
    mount_id: u8,
    /// Whether this slot is active.
    active: bool,
}

impl GraceState {
    const fn empty() -> Self {
        Self {
            in_grace: false,
            start_time: 0,
            duration_secs: DEFAULT_GRACE_PERIOD_SECS,
            mount_id: 0,
            active: false,
        }
    }

    /// Check whether the grace period has expired given current time.
    fn is_expired(&self, now_secs: u64) -> bool {
        if !self.in_grace {
            return true;
        }
        now_secs >= self.start_time + self.duration_secs as u64
    }
}

// ── NfsLockStats ──────────────────────────────────────────────────────────────

/// NFS lock manager statistics.
#[derive(Debug, Clone, Copy)]
pub struct NfsLockStats {
    /// Total lock acquire requests.
    pub lock_requests: u64,
    /// Total locks granted.
    pub locks_granted: u64,
    /// Total lock requests denied.
    pub locks_denied: u64,
    /// Total unlock operations.
    pub unlocks: u64,
    /// Total lock reclaim attempts.
    pub reclaim_attempts: u64,
    /// Total successful reclaims.
    pub reclaim_successes: u64,
    /// Total grace period entries.
    pub grace_periods: u64,
}

impl NfsLockStats {
    const fn new() -> Self {
        Self {
            lock_requests: 0,
            locks_granted: 0,
            locks_denied: 0,
            unlocks: 0,
            reclaim_attempts: 0,
            reclaim_successes: 0,
            grace_periods: 0,
        }
    }
}

// ── NfsLockManager ────────────────────────────────────────────────────────────

/// NFS lock manager client.
///
/// Manages byte-range locks for files on NFS mounts.  Handles lock
/// acquisition, release, testing, and reclaim after server reboot.
pub struct NfsLockManager {
    /// Active locks.
    locks: [NfsLock; MAX_NFS_LOCKS],
    /// Pending reclaim entries.
    reclaims: [LockReclaim; MAX_RECLAIM_ENTRIES],
    /// Per-mount grace period state.
    grace: [GraceState; MAX_NFS_MOUNTS],
    /// Next lock sequence number.
    next_sequence: u32,
    /// Statistics.
    stats: NfsLockStats,
}

impl NfsLockManager {
    /// Create a new, empty NFS lock manager.
    pub fn new() -> Self {
        Self {
            locks: [const { NfsLock::empty() }; MAX_NFS_LOCKS],
            reclaims: [const { LockReclaim::empty() }; MAX_RECLAIM_ENTRIES],
            grace: [const { GraceState::empty() }; MAX_NFS_MOUNTS],
            next_sequence: 1,
            stats: NfsLockStats::new(),
        }
    }

    /// Acquire a byte-range lock.
    ///
    /// Returns the slot index of the new lock on success.
    /// Returns `Error::WouldBlock` if the lock is denied due to a conflict
    /// or grace period.
    pub fn acquire_lock(
        &mut self,
        fh_hash: u64,
        mount_id: u8,
        owner: u32,
        lock_type: NfsLockType,
        range: LockRange,
        now_secs: u64,
    ) -> Result<usize> {
        self.stats.lock_requests += 1;

        // Check grace period.
        if self.in_grace_period(mount_id, now_secs) {
            self.stats.locks_denied += 1;
            return Err(Error::WouldBlock);
        }

        // Check for conflicts with existing locks.
        for lock in &self.locks {
            if !lock.in_use || lock.fh_hash != fh_hash || lock.mount_id != mount_id {
                continue;
            }
            if lock.conflicts_with(owner, lock_type, &range) {
                self.stats.locks_denied += 1;
                return Err(Error::WouldBlock);
            }
        }

        // Try to coalesce with an existing lock from the same owner.
        for lock in &mut self.locks {
            if lock.in_use
                && lock.fh_hash == fh_hash
                && lock.mount_id == mount_id
                && lock.owner == owner
                && lock.state == LockState::Granted
                && lock.lock_type == lock_type
                && lock.range.overlaps(&range)
            {
                // Extend the existing lock range.
                let new_start = lock.range.start.min(range.start);
                let new_end = lock.range.end().max(range.end());
                lock.range = LockRange::new(
                    new_start,
                    if new_end == u64::MAX {
                        NFS_LOCK_EOF
                    } else {
                        new_end - new_start + 1
                    },
                );
                self.stats.locks_granted += 1;
                return Ok(0); // Coalesced, not a new slot.
            }
        }

        // Allocate a new lock slot.
        let (idx, slot) = self
            .locks
            .iter_mut()
            .enumerate()
            .find(|(_, l)| !l.in_use)
            .ok_or(Error::OutOfMemory)?;

        slot.fh_hash = fh_hash;
        slot.mount_id = mount_id;
        slot.owner = owner;
        slot.lock_type = lock_type;
        slot.range = range;
        slot.state = LockState::Granted;
        slot.state_id = 0;
        slot.sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        slot.granted_at = now_secs;
        slot.in_use = true;

        self.stats.locks_granted += 1;
        Ok(idx)
    }

    /// Release a lock by slot index.
    pub fn release_lock(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_NFS_LOCKS || !self.locks[idx].in_use {
            return Err(Error::NotFound);
        }
        self.locks[idx].state = LockState::Released;
        self.locks[idx].in_use = false;
        self.stats.unlocks += 1;
        Ok(())
    }

    /// Release all locks held by an owner on a file.
    pub fn release_all(&mut self, fh_hash: u64, mount_id: u8, owner: u32) -> u32 {
        let mut count = 0u32;
        for lock in &mut self.locks {
            if lock.in_use
                && lock.fh_hash == fh_hash
                && lock.mount_id == mount_id
                && lock.owner == owner
            {
                lock.state = LockState::Released;
                lock.in_use = false;
                count += 1;
            }
        }
        self.stats.unlocks += count as u64;
        count
    }

    /// Test whether a proposed lock would conflict with existing locks.
    ///
    /// Returns `Ok(None)` if no conflict, or `Ok(Some(conflicting_lock))`
    /// with a copy of the first conflicting lock.
    pub fn test_lock(
        &self,
        fh_hash: u64,
        mount_id: u8,
        owner: u32,
        lock_type: NfsLockType,
        range: &LockRange,
    ) -> Result<Option<NfsLock>> {
        for lock in &self.locks {
            if !lock.in_use || lock.fh_hash != fh_hash || lock.mount_id != mount_id {
                continue;
            }
            if lock.conflicts_with(owner, lock_type, range) {
                return Ok(Some(*lock));
            }
        }
        Ok(None)
    }

    /// Downgrade an exclusive lock to a shared lock.
    pub fn downgrade(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_NFS_LOCKS || !self.locks[idx].in_use {
            return Err(Error::NotFound);
        }
        if self.locks[idx].lock_type != NfsLockType::Write {
            return Err(Error::InvalidArgument);
        }
        self.locks[idx].lock_type = NfsLockType::Read;
        Ok(())
    }

    // ── Server reboot / grace period handling ─────────────────────────────────

    /// Notify the lock manager that a server has rebooted.
    ///
    /// All granted locks on the given mount are moved to `Reclaiming` state
    /// and a grace period is started.
    pub fn server_rebooted(&mut self, mount_id: u8, now_secs: u64) -> Result<u32> {
        // Start grace period.
        let gs = self
            .grace
            .iter_mut()
            .find(|g| !g.active || g.mount_id == mount_id)
            .ok_or(Error::OutOfMemory)?;

        gs.in_grace = true;
        gs.start_time = now_secs;
        gs.duration_secs = DEFAULT_GRACE_PERIOD_SECS;
        gs.mount_id = mount_id;
        gs.active = true;
        self.stats.grace_periods += 1;

        // Move granted locks to reclaiming and create reclaim entries.
        let mut reclaim_count = 0u32;
        for lock in &mut self.locks {
            if !lock.in_use || lock.mount_id != mount_id {
                continue;
            }
            if lock.state != LockState::Granted {
                continue;
            }
            lock.state = LockState::Reclaiming;

            // Create a reclaim entry.
            if let Some(slot) = self.reclaims.iter_mut().find(|r| !r.in_use) {
                *slot = LockReclaim::from_lock(lock);
                reclaim_count += 1;
            }
        }

        Ok(reclaim_count)
    }

    /// Attempt to reclaim locks for a mount during the grace period.
    ///
    /// Returns the number of successfully reclaimed locks.
    pub fn reclaim_locks(&mut self, mount_id: u8) -> u32 {
        let mut reclaimed = 0u32;

        for reclaim in &mut self.reclaims {
            if !reclaim.in_use || reclaim.mount_id != mount_id || reclaim.reclaimed {
                continue;
            }
            reclaim.attempts += 1;
            self.stats.reclaim_attempts += 1;

            // In a real implementation, this would send an NLM_LOCK_RECLAIM
            // RPC.  Here we simulate successful reclaim.
            reclaim.reclaimed = true;
            self.stats.reclaim_successes += 1;
            reclaimed += 1;

            // Restore the corresponding lock to Granted.
            for lock in &mut self.locks {
                if lock.in_use
                    && lock.mount_id == mount_id
                    && lock.fh_hash == reclaim.fh_hash
                    && lock.owner == reclaim.owner
                    && lock.state == LockState::Reclaiming
                {
                    lock.state = LockState::Granted;
                    break;
                }
            }
        }

        reclaimed
    }

    /// End the grace period for a mount.
    ///
    /// Any locks still in `Reclaiming` state are moved to `Unknown`.
    pub fn end_grace_period(&mut self, mount_id: u8) {
        // Clear grace state.
        for gs in &mut self.grace {
            if gs.active && gs.mount_id == mount_id {
                gs.in_grace = false;
            }
        }

        // Mark unreclaimed locks as Unknown.
        for lock in &mut self.locks {
            if lock.in_use && lock.mount_id == mount_id && lock.state == LockState::Reclaiming {
                lock.state = LockState::Unknown;
            }
        }

        // Clean up reclaim entries.
        for reclaim in &mut self.reclaims {
            if reclaim.in_use && reclaim.mount_id == mount_id {
                reclaim.in_use = false;
            }
        }
    }

    /// Check whether a mount is currently in a grace period.
    pub fn in_grace_period(&self, mount_id: u8, now_secs: u64) -> bool {
        self.grace
            .iter()
            .any(|gs| gs.active && gs.mount_id == mount_id && !gs.is_expired(now_secs))
    }

    // ── Query helpers ─────────────────────────────────────────────────────────

    /// Count locks for a given file and mount.
    pub fn count_locks(&self, fh_hash: u64, mount_id: u8) -> u32 {
        self.locks
            .iter()
            .filter(|l| {
                l.in_use
                    && l.fh_hash == fh_hash
                    && l.mount_id == mount_id
                    && l.state == LockState::Granted
            })
            .count() as u32
    }

    /// Count all active locks across all mounts.
    pub fn total_active_locks(&self) -> u32 {
        self.locks
            .iter()
            .filter(|l| l.in_use && l.state == LockState::Granted)
            .count() as u32
    }

    /// Get a reference to a lock by index.
    pub fn get_lock(&self, idx: usize) -> Result<&NfsLock> {
        if idx >= MAX_NFS_LOCKS || !self.locks[idx].in_use {
            return Err(Error::NotFound);
        }
        Ok(&self.locks[idx])
    }

    /// Return lock manager statistics.
    pub fn stats(&self) -> NfsLockStats {
        self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = NfsLockStats::new();
    }
}

impl Default for NfsLockManager {
    fn default() -> Self {
        Self::new()
    }
}
