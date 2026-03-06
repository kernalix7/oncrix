// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 fsync implementation.
//!
//! Implements `fsync(2)` and `fdatasync(2)` for ext4 inodes.  The primary
//! responsibility is to ensure that all dirty data and (for fsync) dirty
//! metadata reach stable storage before the call returns.
//!
//! # Design
//!
//! - [`Ext4FsyncState`] — per-inode sync state flags and journal tracking
//! - [`Ext4FsyncOps`] — trait with `fsync` and `fdatasync` entry points
//! - Journal commit path: barrier → journal commit → barrier
//! - Fast-commit optimisation: for small metadata-only changes, only the
//!   fast-commit area of the journal is flushed, skipping a full transaction
//! - `fdatasync` skips the journal commit when no metadata is dirty
//!
//! # References
//!
//! - Linux `fs/ext4/fsync.c`
//! - POSIX `fdatasync(2)`, `fsync(2)` — `susv5-html/functions/fdatasync.html`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Bit in [`Ext4FsyncState::flags`]: inode has dirty data pages.
pub const EXT4_FSYNC_DATA_DIRTY: u32 = 1 << 0;

/// Bit in [`Ext4FsyncState::flags`]: inode has dirty metadata (size, mtime…).
pub const EXT4_FSYNC_META_DIRTY: u32 = 1 << 1;

/// Bit in [`Ext4FsyncState::flags`]: a journal commit is already in flight.
pub const EXT4_FSYNC_COMMIT_INFLIGHT: u32 = 1 << 2;

/// Bit in [`Ext4FsyncState::flags`]: fast-commit is eligible for this inode.
pub const EXT4_FSYNC_FAST_COMMIT: u32 = 1 << 3;

/// Bit in [`Ext4FsyncState::flags`]: ordered-data mode (data before metadata).
pub const EXT4_FSYNC_ORDERED: u32 = 1 << 4;

/// Maximum in-flight commit retries before returning [`Error::IoError`].
const MAX_COMMIT_RETRIES: u32 = 8;

/// Sentinel transaction ID meaning "no transaction".
pub const EXT4_NO_TID: u64 = 0;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Sync mode requested by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Full `fsync`: flush data *and* all metadata to stable storage.
    Full,
    /// `fdatasync`: flush data and metadata required to read back the data;
    /// skip non-essential metadata updates (atime, mtime on unchanged data).
    DataOnly,
}

/// State machine for an in-flight journal commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CommitState {
    /// No commit is pending.
    #[default]
    Idle,
    /// Waiting for the journal to accept the commit.
    Queued,
    /// The commit record has been written; waiting for the storage barrier.
    Committing,
    /// Commit is complete; the barrier has been issued.
    Done,
    /// The commit was aborted due to an I/O error.
    Aborted,
}

/// Per-inode ext4 fsync state.
#[derive(Debug, Default)]
pub struct Ext4FsyncState {
    /// Combination of `EXT4_FSYNC_*` bit flags.
    pub flags: u32,
    /// Transaction ID of the last full commit that covered this inode.
    pub last_commit_tid: u64,
    /// Transaction ID of the last fast-commit that covered this inode.
    pub last_fast_commit_tid: u64,
    /// Number of consecutive fast-commits since the last full commit.
    pub fast_commit_count: u32,
    /// Current state of any in-flight commit.
    pub commit_state: CommitState,
    /// Cumulative I/O error code; non-zero means fsync must fail.
    pub io_error: i32,
}

impl Ext4FsyncState {
    /// Create a new, clean fsync state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark the inode's data pages dirty.
    pub fn mark_data_dirty(&mut self) {
        self.flags |= EXT4_FSYNC_DATA_DIRTY;
    }

    /// Mark the inode's metadata dirty.
    pub fn mark_meta_dirty(&mut self) {
        self.flags |= EXT4_FSYNC_META_DIRTY;
    }

    /// Returns `true` when there is nothing to flush.
    pub fn is_clean(&self) -> bool {
        self.flags & (EXT4_FSYNC_DATA_DIRTY | EXT4_FSYNC_META_DIRTY) == 0
    }

    /// Returns `true` when only metadata is dirty (data pages are clean).
    pub fn only_meta_dirty(&self) -> bool {
        self.flags & EXT4_FSYNC_DATA_DIRTY == 0 && self.flags & EXT4_FSYNC_META_DIRTY != 0
    }

    /// Returns `true` when a fast-commit is eligible.
    pub fn fast_commit_eligible(&self) -> bool {
        self.flags & EXT4_FSYNC_FAST_COMMIT != 0
    }

    /// Clear the dirty flags after a successful sync.
    pub fn clear_dirty(&mut self) {
        self.flags &= !(EXT4_FSYNC_DATA_DIRTY | EXT4_FSYNC_META_DIRTY);
        self.commit_state = CommitState::Done;
    }

    /// Record a persistent I/O error for this inode.
    pub fn set_io_error(&mut self, errno: i32) {
        if self.io_error == 0 {
            self.io_error = errno;
        }
        self.commit_state = CommitState::Aborted;
    }
}

// ---------------------------------------------------------------------------
// Journal handle stub
// ---------------------------------------------------------------------------

/// Lightweight handle representing a journal transaction in flight.
///
/// In a real kernel this maps to `jbd2_journal_handle`.
#[derive(Debug)]
pub struct JournalHandle {
    /// Transaction ID.
    pub tid: u64,
    /// Number of block credits reserved.
    pub credits: u32,
    /// Whether the transaction has been started.
    pub started: bool,
}

impl JournalHandle {
    /// Allocate a new handle with the given transaction ID and credit count.
    pub fn new(tid: u64, credits: u32) -> Self {
        Self {
            tid,
            credits,
            started: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Core fsync logic
// ---------------------------------------------------------------------------

/// Simulation of issuing a storage barrier.
///
/// Returns `Ok(())` on success or [`Error::IoError`] if the device rejects it.
pub fn issue_barrier() -> Result<()> {
    // In production this becomes a block-layer FLUSH+FUA command.
    Ok(())
}

/// Commit the journal up to and including `tid`.
///
/// Returns the committed transaction ID or an error.
pub fn journal_commit(handle: &mut JournalHandle) -> Result<u64> {
    if !handle.started {
        return Err(Error::InvalidArgument);
    }
    // Simulate commit: write commit record and barrier.
    handle.started = false;
    Ok(handle.tid)
}

/// Issue a fast-commit for metadata-only changes on `state`.
///
/// Fast commits only write the changed metadata items (inode table delta)
/// rather than a full journal transaction.
pub fn fast_commit(state: &mut Ext4FsyncState, tid: u64) -> Result<()> {
    if state.commit_state == CommitState::Aborted {
        return Err(Error::IoError);
    }
    state.commit_state = CommitState::Committing;
    issue_barrier()?;
    state.last_fast_commit_tid = tid;
    state.fast_commit_count = state.fast_commit_count.saturating_add(1);
    state.commit_state = CommitState::Done;
    Ok(())
}

/// Perform the full fsync or fdatasync flow for an ext4 inode.
///
/// # Parameters
///
/// - `state` — mutable reference to the inode's sync state
/// - `mode` — [`SyncMode::Full`] for `fsync`, [`SyncMode::DataOnly`] for `fdatasync`
/// - `next_tid` — the next transaction ID to assign to a commit
///
/// # Errors
///
/// Returns [`Error::IoError`] if the journal commit or barrier fails, or if the
/// inode has a previously recorded I/O error.
pub fn ext4_do_fsync(state: &mut Ext4FsyncState, mode: SyncMode, next_tid: u64) -> Result<()> {
    // Surface any previously recorded error.
    if state.io_error != 0 {
        return Err(Error::IoError);
    }

    // Nothing to do.
    if state.is_clean() {
        return Ok(());
    }

    // fdatasync: if only metadata is dirty and data is unchanged, we can skip
    // the data barrier and the full journal commit.
    if mode == SyncMode::DataOnly && state.only_meta_dirty() {
        state.clear_dirty();
        return Ok(());
    }

    // Try a fast commit first when eligible and no data is dirty.
    if state.fast_commit_eligible() && mode == SyncMode::DataOnly {
        return fast_commit(state, next_tid);
    }

    // Full journal commit path.
    let mut retries = 0u32;
    loop {
        state.commit_state = CommitState::Queued;
        issue_barrier()?;

        let mut handle = JournalHandle::new(next_tid, 8);
        match journal_commit(&mut handle) {
            Ok(tid) => {
                state.last_commit_tid = tid;
                issue_barrier()?;
                state.clear_dirty();
                state.fast_commit_count = 0;
                return Ok(());
            }
            Err(Error::Interrupted) if retries < MAX_COMMIT_RETRIES => {
                retries += 1;
                state.commit_state = CommitState::Queued;
            }
            Err(e) => {
                state.set_io_error(-1);
                return Err(e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Operations exposed by the ext4 fsync subsystem.
pub trait Ext4FsyncOps {
    /// Flush all dirty data and metadata to stable storage (`fsync`).
    fn fsync(&mut self, next_tid: u64) -> Result<()>;

    /// Flush data and required metadata only (`fdatasync`).
    fn fdatasync(&mut self, next_tid: u64) -> Result<()>;
}

impl Ext4FsyncOps for Ext4FsyncState {
    fn fsync(&mut self, next_tid: u64) -> Result<()> {
        ext4_do_fsync(self, SyncMode::Full, next_tid)
    }

    fn fdatasync(&mut self, next_tid: u64) -> Result<()> {
        ext4_do_fsync(self, SyncMode::DataOnly, next_tid)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_inode_is_noop() {
        let mut state = Ext4FsyncState::new();
        assert!(state.fsync(1).is_ok());
        assert!(state.fdatasync(1).is_ok());
    }

    #[test]
    fn data_dirty_fsync_clears() {
        let mut state = Ext4FsyncState::new();
        state.mark_data_dirty();
        state.fsync(1).unwrap();
        assert!(state.is_clean());
    }

    #[test]
    fn meta_only_fdatasync_skips_commit() {
        let mut state = Ext4FsyncState::new();
        state.mark_meta_dirty();
        state.fdatasync(1).unwrap();
        assert!(state.is_clean());
        // last_commit_tid should remain 0 (no real commit happened).
        assert_eq!(state.last_commit_tid, 0);
    }

    #[test]
    fn io_error_propagates() {
        let mut state = Ext4FsyncState::new();
        state.mark_data_dirty();
        state.set_io_error(-5);
        assert!(state.fsync(2).is_err());
    }
}
