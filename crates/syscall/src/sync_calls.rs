// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File synchronization syscall handlers.
//!
//! Implements `fsync(2)`, `fdatasync(2)`, `sync(2)`, `syncfs(2)`, and
//! `sync_file_range(2)`.  These syscalls ensure that modified file data and
//! metadata are written to durable storage.
//!
//! # Semantics
//!
//! | Syscall           | What is flushed                                  |
//! |-------------------|--------------------------------------------------|
//! | `fsync(fd)`       | Data + metadata for file `fd`                    |
//! | `fdatasync(fd)`   | Data only for file `fd` (skip non-critical meta) |
//! | `sync()`          | All dirty buffers in the system                  |
//! | `syncfs(fd)`      | All dirty buffers on the filesystem of `fd`      |
//! | `sync_file_range` | Subset of dirty pages for `fd` in byte range     |
//!
//! # POSIX reference
//!
//! - `fsync`: `.TheOpenGroup/susv5-html/functions/fsync.html`
//! - `fdatasync`: `.TheOpenGroup/susv5-html/functions/fdatasync.html`
//! - `sync`: Linux extension; not in POSIX, but widely supported.
//! - `syncfs`: Linux extension (`syncfs(2)` man page).
//!
//! # Implementation note
//!
//! The actual I/O is stubbed — a real kernel would flush dirty page-cache
//! pages to block devices via the writeback subsystem.  This module
//! establishes the request queuing, validation, and statistics infrastructure.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of pending sync requests in the queue.
pub const SYNC_QUEUE_SIZE: usize = 32;

/// Syscall number for `fsync` (x86_64 Linux ABI).
pub const SYS_FSYNC: u64 = 74;

/// Syscall number for `fdatasync` (x86_64 Linux ABI).
pub const SYS_FDATASYNC: u64 = 75;

/// Syscall number for `sync` (x86_64 Linux ABI).
pub const SYS_SYNC: u64 = 162;

/// Syscall number for `syncfs` (x86_64 Linux ABI).
pub const SYS_SYNCFS: u64 = 306;

/// Syscall number for `sync_file_range` (x86_64 Linux ABI).
pub const SYS_SYNC_FILE_RANGE: u64 = 277;

// ---------------------------------------------------------------------------
// SyncFlags — for sync_file_range
// ---------------------------------------------------------------------------

/// Flags for `sync_file_range(2)`.
///
/// Controls which phases of the sync operation are performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncFlags(u32);

impl SyncFlags {
    /// Wait for I/O on already-submitted write-back to complete before issuing
    /// any new write-back.
    pub const WAIT_BEFORE: u32 = 1 << 0;
    /// Initiate write-back for the specified range.
    pub const WRITE: u32 = 1 << 1;
    /// Wait for all I/O on the specified range to complete before returning.
    pub const WAIT_AFTER: u32 = 1 << 2;

    /// Mask of all valid flag bits.
    const VALID_MASK: u32 = Self::WAIT_BEFORE | Self::WRITE | Self::WAIT_AFTER;

    /// Parse flags from a raw `u32`.
    ///
    /// Returns `InvalidArgument` if unknown bits are set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !Self::VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether `WAIT_BEFORE` is set.
    pub const fn wait_before(self) -> bool {
        self.0 & Self::WAIT_BEFORE != 0
    }

    /// Whether `WRITE` is set.
    pub const fn write(self) -> bool {
        self.0 & Self::WRITE != 0
    }

    /// Whether `WAIT_AFTER` is set.
    pub const fn wait_after(self) -> bool {
        self.0 & Self::WAIT_AFTER != 0
    }
}

// ---------------------------------------------------------------------------
// SyncScope
// ---------------------------------------------------------------------------

/// Scope of a sync operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncScope {
    /// Flush data and metadata for a single file (`fsync`).
    Full,
    /// Flush data only for a single file (`fdatasync`).
    Data,
    /// Flush all dirty buffers on a single filesystem (`syncfs`).
    FileSystem,
    /// Flush all dirty buffers in the system (`sync`).
    Global,
}

// ---------------------------------------------------------------------------
// SyncRequest
// ---------------------------------------------------------------------------

/// A pending synchronization request.
#[derive(Debug, Clone, Copy)]
pub struct SyncRequest {
    /// File descriptor this request targets (`-1` for `Global` scope).
    pub fd: i32,
    /// Scope of the operation.
    pub scope: SyncScope,
    /// Kernel tick at the time the request was submitted.
    pub submitted_tick: u64,
    /// Whether the operation has completed.
    pub completed: bool,
    /// For `sync_file_range`: start offset.
    pub range_offset: u64,
    /// For `sync_file_range`: byte count (0 = entire file).
    pub range_nbytes: u64,
    /// For `sync_file_range`: flags.
    pub range_flags: SyncFlags,
}

impl SyncRequest {
    /// Create a request for `fsync` or `fdatasync`.
    pub const fn new(fd: i32, scope: SyncScope, tick: u64) -> Self {
        Self {
            fd,
            scope,
            submitted_tick: tick,
            completed: false,
            range_offset: 0,
            range_nbytes: 0,
            range_flags: SyncFlags(0),
        }
    }

    /// Create a `sync_file_range` request.
    pub const fn new_range(fd: i32, tick: u64, offset: u64, nbytes: u64, flags: SyncFlags) -> Self {
        Self {
            fd,
            scope: SyncScope::Data,
            submitted_tick: tick,
            completed: false,
            range_offset: offset,
            range_nbytes: nbytes,
            range_flags: flags,
        }
    }
}

// ---------------------------------------------------------------------------
// SyncQueue
// ---------------------------------------------------------------------------

/// Fixed-capacity queue for pending sync requests.
///
/// Uses a simple ring-buffer with head and tail pointers.
#[derive(Debug)]
pub struct SyncQueue {
    /// Request slots.
    slots: [Option<SyncRequest>; SYNC_QUEUE_SIZE],
    /// Number of occupied slots.
    count: usize,
    /// Index to insert the next request.
    head: usize,
}

impl SyncQueue {
    /// Create an empty queue.
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; SYNC_QUEUE_SIZE],
            count: 0,
            head: 0,
        }
    }

    /// Enqueue a sync request.
    ///
    /// Returns `Busy` if the queue is full.
    pub fn enqueue(&mut self, req: SyncRequest) -> Result<()> {
        if self.count >= SYNC_QUEUE_SIZE {
            return Err(Error::Busy);
        }
        self.slots[self.head] = Some(req);
        self.head = (self.head + 1) % SYNC_QUEUE_SIZE;
        self.count += 1;
        Ok(())
    }

    /// Mark all pending requests for `fd` as completed.
    pub fn complete_fd(&mut self, fd: i32) {
        for slot in self.slots.iter_mut() {
            if let Some(req) = slot {
                if req.fd == fd {
                    req.completed = true;
                }
            }
        }
    }

    /// Mark all pending requests as completed (for global sync).
    pub fn complete_all(&mut self) {
        for slot in self.slots.iter_mut() {
            if let Some(req) = slot {
                req.completed = true;
            }
        }
    }

    /// Drain completed requests, freeing their slots.
    ///
    /// Returns the number of requests drained.
    pub fn drain_completed(&mut self) -> usize {
        let mut drained = 0usize;
        for slot in self.slots.iter_mut() {
            if slot.map_or(false, |r| r.completed) {
                *slot = None;
                drained += 1;
                self.count = self.count.saturating_sub(1);
            }
        }
        drained
    }

    /// Return the number of pending (not yet completed) requests.
    pub fn pending_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.map_or(false, |r| !r.completed))
            .count()
    }

    /// Return the total number of occupied slots.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for SyncQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SyncStats
// ---------------------------------------------------------------------------

/// Accumulated statistics for the sync subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyncStats {
    /// Total `fsync` calls.
    pub total_fsync: u64,
    /// Total `fdatasync` calls.
    pub total_fdatasync: u64,
    /// Total `sync` calls.
    pub total_sync: u64,
    /// Total `syncfs` calls.
    pub total_syncfs: u64,
    /// Total `sync_file_range` calls.
    pub total_sync_file_range: u64,
    /// Estimated bytes submitted for writeback.
    pub bytes_synced: u64,
}

impl SyncStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_fsync: 0,
            total_fdatasync: 0,
            total_sync: 0,
            total_syncfs: 0,
            total_sync_file_range: 0,
            bytes_synced: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Simulated writeback
// ---------------------------------------------------------------------------

/// Simulate flushing data for `fd`.
///
/// Returns an estimated byte count for statistics.  In a real kernel this
/// would call the filesystem's `->sync_fs` or `->fsync` method.
fn simulate_flush_fd(_fd: i32, _scope: SyncScope) -> u64 {
    // Model 4 KiB of dirty data per flush.
    4096
}

/// Simulate a global sync.
///
/// Returns an estimated byte count.  In a real kernel this would call
/// `sync_inodes_sb` and `writeback_inodes_sb` for every mounted filesystem.
fn simulate_global_sync() -> u64 {
    // Model 64 KiB written back globally.
    65536
}

// ---------------------------------------------------------------------------
// do_fsync
// ---------------------------------------------------------------------------

/// Handler for `fsync(2)`.
///
/// Requests that all data and metadata for file descriptor `fd` be written
/// to durable storage.  The call does not return until the operation completes.
///
/// # Arguments
///
/// * `queue` — Pending sync request queue.
/// * `stats` — Statistics accumulator.
/// * `tick`  — Current kernel tick (used for timestamp).
/// * `fd`    — Open file descriptor.
///
/// # Errors
///
/// * `InvalidArgument` — `fd` is negative.
/// * `Busy`            — Sync queue is full.
///
/// # POSIX conformance
///
/// POSIX.1-2024 `fsync()` shall cause any pending writes to the file
/// associated with `fd` to be written to the underlying storage device.
/// The call blocks until the I/O completes.
pub fn do_fsync(queue: &mut SyncQueue, stats: &mut SyncStats, tick: u64, fd: i32) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    let req = SyncRequest::new(fd, SyncScope::Full, tick);
    queue.enqueue(req)?;

    // Simulate immediate completion.
    queue.complete_fd(fd);
    let flushed = simulate_flush_fd(fd, SyncScope::Full);
    queue.drain_completed();

    stats.total_fsync += 1;
    stats.bytes_synced += flushed;
    Ok(())
}

// ---------------------------------------------------------------------------
// do_fdatasync
// ---------------------------------------------------------------------------

/// Handler for `fdatasync(2)`.
///
/// Like `fsync` but does not flush metadata that is not needed to retrieve
/// the file data (e.g., `atime`, `ctime`).  This is faster than `fsync`
/// when only the data needs to be durable.
///
/// # Errors
///
/// * `InvalidArgument` — `fd` is negative.
/// * `Busy`            — Sync queue is full.
///
/// # POSIX conformance
///
/// POSIX.1-2024 `fdatasync()` flushes data, plus sufficient metadata to
/// allow retrieval of that data.
pub fn do_fdatasync(
    queue: &mut SyncQueue,
    stats: &mut SyncStats,
    tick: u64,
    fd: i32,
) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    let req = SyncRequest::new(fd, SyncScope::Data, tick);
    queue.enqueue(req)?;

    queue.complete_fd(fd);
    let flushed = simulate_flush_fd(fd, SyncScope::Data);
    queue.drain_completed();

    stats.total_fdatasync += 1;
    stats.bytes_synced += flushed;
    Ok(())
}

// ---------------------------------------------------------------------------
// do_sync
// ---------------------------------------------------------------------------

/// Handler for `sync(2)`.
///
/// Flushes all modified page-cache pages, file metadata, and journal data
/// to their underlying storage devices.  The call does not wait for all
/// I/O to complete on Linux (it merely schedules it); here we model
/// synchronous completion for simplicity.
///
/// # POSIX conformance
///
/// `sync` is a Linux/BSD extension.  POSIX does not define `sync(2)`.
pub fn do_sync(queue: &mut SyncQueue, stats: &mut SyncStats, tick: u64) -> Result<()> {
    let req = SyncRequest::new(-1, SyncScope::Global, tick);
    queue.enqueue(req)?;

    queue.complete_all();
    let flushed = simulate_global_sync();
    queue.drain_completed();

    stats.total_sync += 1;
    stats.bytes_synced += flushed;
    Ok(())
}

// ---------------------------------------------------------------------------
// do_syncfs
// ---------------------------------------------------------------------------

/// Handler for `syncfs(2)`.
///
/// Flushes all dirty data and metadata on the filesystem to which `fd`
/// belongs.  Unlike `sync`, only the filesystem of `fd` is flushed.
///
/// # Errors
///
/// * `InvalidArgument` — `fd` is negative.
/// * `Busy`            — Sync queue is full.
pub fn do_syncfs(queue: &mut SyncQueue, stats: &mut SyncStats, tick: u64, fd: i32) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    let req = SyncRequest::new(fd, SyncScope::FileSystem, tick);
    queue.enqueue(req)?;

    queue.complete_fd(fd);
    let flushed = simulate_flush_fd(fd, SyncScope::FileSystem);
    queue.drain_completed();

    stats.total_syncfs += 1;
    stats.bytes_synced += flushed;
    Ok(())
}

// ---------------------------------------------------------------------------
// sync_file_range
// ---------------------------------------------------------------------------

/// Handler for `sync_file_range(2)`.
///
/// Initiates or waits for writeback of a byte range within a file.
/// The `flags` argument controls which phases of writeback to perform:
///
/// - `WAIT_BEFORE` — wait for any already-running writeback of the range.
/// - `WRITE`       — start writeback of dirty pages in the range.
/// - `WAIT_AFTER`  — wait for all writeback in the range to complete.
///
/// # Arguments
///
/// * `queue`   — Pending sync request queue.
/// * `stats`   — Statistics accumulator.
/// * `tick`    — Current kernel tick.
/// * `fd`      — Open file descriptor.
/// * `offset`  — Start of the byte range.
/// * `nbytes`  — Length of the byte range (0 = to end-of-file).
/// * `flags`   — Raw `sync_file_range` flags.
///
/// # Errors
///
/// * `InvalidArgument` — Negative `fd`, overflow in `offset+nbytes`, or
///   unknown flag bits.
/// * `Busy`            — Sync queue is full.
pub fn sync_file_range(
    queue: &mut SyncQueue,
    stats: &mut SyncStats,
    tick: u64,
    fd: i32,
    offset: u64,
    nbytes: u64,
    flags: u32,
) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if nbytes > 0 {
        offset.checked_add(nbytes).ok_or(Error::InvalidArgument)?;
    }
    let sync_flags = SyncFlags::from_raw(flags)?;

    let req = SyncRequest::new_range(fd, tick, offset, nbytes, sync_flags);
    queue.enqueue(req)?;

    queue.complete_fd(fd);
    let flushed = nbytes.min(4096); // Model partial flush.
    queue.drain_completed();

    stats.total_sync_file_range += 1;
    stats.bytes_synced += flushed;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_flags_valid() {
        assert!(SyncFlags::from_raw(0).is_ok());
        assert!(SyncFlags::from_raw(SyncFlags::WAIT_BEFORE).is_ok());
        assert!(SyncFlags::from_raw(SyncFlags::WRITE).is_ok());
        assert!(SyncFlags::from_raw(SyncFlags::WAIT_AFTER).is_ok());
        let all = SyncFlags::WAIT_BEFORE | SyncFlags::WRITE | SyncFlags::WAIT_AFTER;
        assert!(SyncFlags::from_raw(all).is_ok());
    }

    #[test]
    fn test_sync_flags_invalid() {
        assert_eq!(SyncFlags::from_raw(0x08), Err(Error::InvalidArgument));
    }

    #[test]
    fn test_do_fsync_success() {
        let mut q = SyncQueue::new();
        let mut stats = SyncStats::new();
        do_fsync(&mut q, &mut stats, 100, 3).unwrap();
        assert_eq!(stats.total_fsync, 1);
        assert!(stats.bytes_synced > 0);
    }

    #[test]
    fn test_do_fsync_negative_fd() {
        let mut q = SyncQueue::new();
        let mut stats = SyncStats::new();
        assert_eq!(
            do_fsync(&mut q, &mut stats, 100, -1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn test_do_fdatasync_success() {
        let mut q = SyncQueue::new();
        let mut stats = SyncStats::new();
        do_fdatasync(&mut q, &mut stats, 200, 5).unwrap();
        assert_eq!(stats.total_fdatasync, 1);
    }

    #[test]
    fn test_do_fdatasync_negative_fd() {
        let mut q = SyncQueue::new();
        let mut stats = SyncStats::new();
        assert_eq!(
            do_fdatasync(&mut q, &mut stats, 200, -5),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn test_do_sync() {
        let mut q = SyncQueue::new();
        let mut stats = SyncStats::new();
        do_sync(&mut q, &mut stats, 300).unwrap();
        assert_eq!(stats.total_sync, 1);
        assert_eq!(stats.bytes_synced, 65536);
    }

    #[test]
    fn test_do_syncfs_success() {
        let mut q = SyncQueue::new();
        let mut stats = SyncStats::new();
        do_syncfs(&mut q, &mut stats, 400, 7).unwrap();
        assert_eq!(stats.total_syncfs, 1);
    }

    #[test]
    fn test_do_syncfs_negative_fd() {
        let mut q = SyncQueue::new();
        let mut stats = SyncStats::new();
        assert_eq!(
            do_syncfs(&mut q, &mut stats, 400, -2),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn test_sync_file_range_success() {
        let mut q = SyncQueue::new();
        let mut stats = SyncStats::new();
        let flags = SyncFlags::WRITE | SyncFlags::WAIT_AFTER;
        sync_file_range(&mut q, &mut stats, 500, 4, 0, 8192, flags).unwrap();
        assert_eq!(stats.total_sync_file_range, 1);
    }

    #[test]
    fn test_sync_file_range_overflow() {
        let mut q = SyncQueue::new();
        let mut stats = SyncStats::new();
        let result = sync_file_range(&mut q, &mut stats, 500, 4, u64::MAX, 1, SyncFlags::WRITE);
        assert_eq!(result, Err(Error::InvalidArgument));
    }

    #[test]
    fn test_sync_file_range_bad_flags() {
        let mut q = SyncQueue::new();
        let mut stats = SyncStats::new();
        let result = sync_file_range(&mut q, &mut stats, 500, 4, 0, 0, 0xFF);
        assert_eq!(result, Err(Error::InvalidArgument));
    }

    #[test]
    fn test_queue_full() {
        let mut q = SyncQueue::new();
        let mut stats = SyncStats::new();
        // Fill queue without draining.
        for fd in 0..SYNC_QUEUE_SIZE as i32 {
            // Enqueue directly without completing so slots stay occupied.
            q.enqueue(SyncRequest::new(fd, SyncScope::Full, 0)).unwrap();
        }
        // Next enqueue should fail with Busy.
        assert_eq!(
            q.enqueue(SyncRequest::new(99, SyncScope::Full, 0)),
            Err(Error::Busy)
        );
        // But stats-based calls should relay the Busy error.
        let result = do_fsync(&mut q, &mut stats, 0, 99);
        assert_eq!(result, Err(Error::Busy));
    }

    #[test]
    fn test_queue_drain() {
        let mut q = SyncQueue::new();
        q.enqueue(SyncRequest::new(1, SyncScope::Full, 0)).unwrap();
        q.enqueue(SyncRequest::new(2, SyncScope::Data, 0)).unwrap();
        assert_eq!(q.count(), 2);
        q.complete_all();
        let drained = q.drain_completed();
        assert_eq!(drained, 2);
        assert_eq!(q.count(), 0);
    }

    #[test]
    fn test_pending_count() {
        let mut q = SyncQueue::new();
        q.enqueue(SyncRequest::new(1, SyncScope::Full, 0)).unwrap();
        q.enqueue(SyncRequest::new(2, SyncScope::Data, 0)).unwrap();
        assert_eq!(q.pending_count(), 2);
        q.complete_fd(1);
        assert_eq!(q.pending_count(), 1);
    }

    #[test]
    fn test_stats_accumulate() {
        let mut q = SyncQueue::new();
        let mut stats = SyncStats::new();
        do_fsync(&mut q, &mut stats, 0, 1).unwrap();
        do_fdatasync(&mut q, &mut stats, 0, 2).unwrap();
        do_sync(&mut q, &mut stats, 0).unwrap();
        do_syncfs(&mut q, &mut stats, 0, 3).unwrap();
        assert_eq!(stats.total_fsync, 1);
        assert_eq!(stats.total_fdatasync, 1);
        assert_eq!(stats.total_sync, 1);
        assert_eq!(stats.total_syncfs, 1);
    }
}
