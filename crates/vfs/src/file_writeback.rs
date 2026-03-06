// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File writeback and synchronisation operations.
//!
//! This module implements the writeback infrastructure for individual
//! files and inodes. It extends the [`crate::writeback`] BDI-level
//! framework with per-file operations:
//!
//! - `fsync(2)` / `fdatasync(2)`: sync a single file's dirty data
//! - `sync_file_range(2)`: sync a byte range within a file
//! - Per-inode dirty tracking and writeback queue management
//! - Writeback work item scheduling per inode
//!
//! # Writeback modes
//!
//! | Mode | Behaviour |
//! |------|-----------|
//! | `Sync` | Blocks until all dirty data is on stable storage |
//! | `DataSync` | Like `Sync` but skips metadata unless needed for data integrity |
//! | `Background` | Non-blocking; queues work and returns immediately |
//! | `Range(start, end)` | Sync only the given byte range |
//!
//! # Dirty inode lifecycle
//!
//! ```text
//! write() → mark_inode_dirty()
//!        → DirtyInodeList::add()
//!        → (background task) writeback_single_inode()
//!        → clear_inode_dirty()
//! ```
//!
//! # References
//!
//! Linux `fs/sync.c`, `fs/fs-writeback.c`;
//! POSIX.1-2024 `fsync()`, `fdatasync()`, `sync_file_range()`.

use crate::inode::InodeNumber;
use oncrix_lib::{Error, Result};

extern crate alloc;
use alloc::vec::Vec;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of inodes tracked in the dirty list.
pub const MAX_DIRTY_INODES: usize = 256;

/// Default writeback age threshold in milliseconds (30 s).
pub const DEFAULT_DIRTY_EXPIRE_MS: u64 = 30_000;

/// Maximum number of pages to write in a single writeback chunk.
pub const MAX_WRITEBACK_PAGES: u32 = 1024;

/// Page size (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

// ── WritebackMode ────────────────────────────────────────────────────────────

/// Controls the synchronisation behaviour of a writeback operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritebackMode {
    /// Full fsync: flush data and all metadata.
    Sync,
    /// Data-integrity sync: flush data and only the metadata needed to
    /// locate the data (size, block pointers). Does not flush atime/mtime.
    DataSync,
    /// Non-blocking background writeback.
    Background,
    /// Sync a specific byte range `[start, end)` (exclusive).
    Range { start: u64, end: u64 },
}

// ── InodeDirtyState ──────────────────────────────────────────────────────────

/// Tracks the writeback state of a single inode.
#[derive(Debug, Clone, Copy)]
pub struct InodeDirtyState {
    /// Inode number.
    pub ino: InodeNumber,
    /// Timestamp (ms since boot) when the inode was first dirtied.
    pub first_dirty_ms: u64,
    /// Timestamp of the last writeback attempt.
    pub last_wb_ms: u64,
    /// Number of dirty pages.
    pub dirty_pages: u32,
    /// Data is dirty (page cache has unflushed writes).
    pub data_dirty: bool,
    /// Metadata (inode attributes) is dirty.
    pub meta_dirty: bool,
    /// Writeback is currently in progress for this inode.
    pub writeback_in_progress: bool,
    /// Number of times writeback has been attempted.
    pub writeback_count: u32,
}

impl Default for InodeDirtyState {
    fn default() -> Self {
        Self {
            ino: InodeNumber(0),
            first_dirty_ms: 0,
            last_wb_ms: 0,
            dirty_pages: 0,
            data_dirty: false,
            meta_dirty: false,
            writeback_in_progress: false,
            writeback_count: 0,
        }
    }
}

impl InodeDirtyState {
    /// Create a new dirty-state record for the given inode.
    pub fn new(ino: InodeNumber, now_ms: u64) -> Self {
        Self {
            ino,
            first_dirty_ms: now_ms,
            last_wb_ms: 0,
            dirty_pages: 0,
            data_dirty: false,
            meta_dirty: false,
            writeback_in_progress: false,
            writeback_count: 0,
        }
    }

    /// Return `true` if any writeback-worthy state is set.
    pub fn needs_writeback(&self) -> bool {
        (self.data_dirty || self.meta_dirty) && !self.writeback_in_progress
    }

    /// Return `true` if this inode has expired (data is older than `expire_ms`).
    pub fn is_expired(&self, now_ms: u64, expire_ms: u64) -> bool {
        self.needs_writeback() && (now_ms.saturating_sub(self.first_dirty_ms) >= expire_ms)
    }
}

// ── DirtyInodeList ───────────────────────────────────────────────────────────

/// Fixed-size list of dirty inodes awaiting writeback.
pub struct DirtyInodeList {
    entries: [Option<InodeDirtyState>; MAX_DIRTY_INODES],
    count: usize,
}

impl DirtyInodeList {
    /// Create an empty dirty-inode list.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_DIRTY_INODES],
            count: 0,
        }
    }

    /// Mark `ino` as dirty.
    ///
    /// If the inode is already tracked, updates the dirty flags.
    /// Otherwise inserts a new entry. Returns `Err(OutOfMemory)` if the
    /// list is full and the inode is not already present.
    pub fn mark_dirty(
        &mut self,
        ino: InodeNumber,
        data: bool,
        meta: bool,
        now_ms: u64,
    ) -> Result<()> {
        // Update existing entry if present.
        for entry in self.entries.iter_mut().flatten() {
            if entry.ino == ino {
                if data {
                    entry.data_dirty = true;
                }
                if meta {
                    entry.meta_dirty = true;
                }
                if entry.first_dirty_ms == 0 {
                    entry.first_dirty_ms = now_ms;
                }
                return Ok(());
            }
        }

        // Insert new entry.
        if self.count >= MAX_DIRTY_INODES {
            return Err(Error::OutOfMemory);
        }
        let mut state = InodeDirtyState::new(ino, now_ms);
        state.data_dirty = data;
        state.meta_dirty = meta;
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(state);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Mark an inode as clean (writeback complete).
    pub fn mark_clean(&mut self, ino: InodeNumber) {
        for slot in self.entries.iter_mut() {
            if slot.as_ref().map(|e| e.ino == ino).unwrap_or(false) {
                *slot = None;
                self.count -= 1;
                return;
            }
        }
    }

    /// Begin writeback for `ino`: set `writeback_in_progress = true`.
    pub fn begin_writeback(&mut self, ino: InodeNumber, now_ms: u64) -> Result<()> {
        for entry in self.entries.iter_mut().flatten() {
            if entry.ino == ino {
                entry.writeback_in_progress = true;
                entry.last_wb_ms = now_ms;
                entry.writeback_count += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Finish writeback for `ino`: clear dirty flags and progress marker.
    pub fn finish_writeback(&mut self, ino: InodeNumber) {
        for entry in self.entries.iter_mut().flatten() {
            if entry.ino == ino {
                entry.writeback_in_progress = false;
                entry.data_dirty = false;
                entry.meta_dirty = false;
                entry.dirty_pages = 0;
                return;
            }
        }
    }

    /// Return the number of tracked dirty inodes.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return `true` if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Look up the dirty state for `ino`.
    pub fn get(&self, ino: InodeNumber) -> Option<&InodeDirtyState> {
        self.entries.iter().flatten().find(|e| e.ino == ino)
    }

    /// Return a slice of all present entries.
    pub fn iter(&self) -> impl Iterator<Item = &InodeDirtyState> {
        self.entries.iter().flatten()
    }

    /// Collect inodes that need writeback, sorted by first-dirty time (oldest first).
    ///
    /// Fills `out` with at most `out.len()` entries and returns the count.
    pub fn collect_due(&self, now_ms: u64, expire_ms: u64, out: &mut [InodeNumber]) -> usize {
        let mut count = 0usize;
        // Collect expired entries (simple selection — no heap sort).
        for entry in self.entries.iter().flatten() {
            if count >= out.len() {
                break;
            }
            if entry.is_expired(now_ms, expire_ms) {
                out[count] = entry.ino;
                count += 1;
            }
        }
        count
    }
}

impl Default for DirtyInodeList {
    fn default() -> Self {
        Self::new()
    }
}

// ── WritebackWork ─────────────────────────────────────────────────────────────

/// A single pending writeback work item.
#[derive(Debug, Clone, Copy)]
pub struct WritebackWork {
    /// Target inode.
    pub ino: InodeNumber,
    /// Writeback mode.
    pub mode: WritebackMode,
    /// Number of pages requested to write (0 = all).
    pub nr_pages: u32,
    /// Sequence number for ordering.
    pub seq: u64,
}

impl WritebackWork {
    /// Create a new work item.
    pub fn new(ino: InodeNumber, mode: WritebackMode, nr_pages: u32, seq: u64) -> Self {
        Self {
            ino,
            mode,
            nr_pages,
            seq,
        }
    }

    /// Return the effective page count (capped to `MAX_WRITEBACK_PAGES`).
    pub fn effective_pages(&self) -> u32 {
        if self.nr_pages == 0 {
            MAX_WRITEBACK_PAGES
        } else {
            self.nr_pages.min(MAX_WRITEBACK_PAGES)
        }
    }
}

// ── WritebackQueue ────────────────────────────────────────────────────────────

/// Fixed-size FIFO queue of pending writeback work items.
pub struct WritebackQueue {
    items: [Option<WritebackWork>; MAX_DIRTY_INODES],
    head: usize,
    tail: usize,
    count: usize,
    next_seq: u64,
}

impl WritebackQueue {
    /// Create an empty writeback queue.
    pub const fn new() -> Self {
        Self {
            items: [const { None }; MAX_DIRTY_INODES],
            head: 0,
            tail: 0,
            count: 0,
            next_seq: 1,
        }
    }

    /// Enqueue a writeback work item.
    pub fn enqueue(&mut self, ino: InodeNumber, mode: WritebackMode, nr_pages: u32) -> Result<u64> {
        if self.count >= MAX_DIRTY_INODES {
            return Err(Error::OutOfMemory);
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let work = WritebackWork::new(ino, mode, nr_pages, seq);
        self.items[self.tail] = Some(work);
        self.tail = (self.tail + 1) % MAX_DIRTY_INODES;
        self.count += 1;
        Ok(seq)
    }

    /// Dequeue the next work item.
    pub fn dequeue(&mut self) -> Option<WritebackWork> {
        if self.count == 0 {
            return None;
        }
        let item = self.items[self.head].take();
        self.head = (self.head + 1) % MAX_DIRTY_INODES;
        self.count -= 1;
        item
    }

    /// Return the number of pending items.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for WritebackQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ── FileWriteback ─────────────────────────────────────────────────────────────

/// Per-filesystem writeback controller.
///
/// Coordinates the dirty-inode list, writeback queue, and expiry
/// configuration for a single filesystem instance.
pub struct FileWriteback {
    /// Dirty inode tracking list.
    pub dirty_list: DirtyInodeList,
    /// Pending writeback work queue.
    pub queue: WritebackQueue,
    /// Expiry threshold in milliseconds.
    pub dirty_expire_ms: u64,
    /// Dirty-background ratio threshold (percentage, 0–100).
    pub bg_ratio: u32,
    /// Hard dirty ratio (percentage, 0–100).
    pub dirty_ratio: u32,
    /// Total writeback operations completed.
    pub wb_completed: u64,
    /// Total bytes written back.
    pub bytes_written: u64,
}

impl FileWriteback {
    /// Create a new writeback controller with defaults.
    pub const fn new() -> Self {
        Self {
            dirty_list: DirtyInodeList::new(),
            queue: WritebackQueue::new(),
            dirty_expire_ms: DEFAULT_DIRTY_EXPIRE_MS,
            bg_ratio: 10,
            dirty_ratio: 20,
            wb_completed: 0,
            bytes_written: 0,
        }
    }

    // ── Dirty tracking ───────────────────────────────────────────────────────

    /// Mark inode `ino` as having dirty data and/or metadata.
    pub fn mark_dirty(
        &mut self,
        ino: InodeNumber,
        data: bool,
        meta: bool,
        now_ms: u64,
    ) -> Result<()> {
        self.dirty_list.mark_dirty(ino, data, meta, now_ms)
    }

    /// Increment the dirty page count for `ino`.
    pub fn add_dirty_pages(&mut self, ino: InodeNumber, pages: u32) {
        for entry in self.dirty_list.entries.iter_mut().flatten() {
            if entry.ino == ino {
                entry.dirty_pages = entry.dirty_pages.saturating_add(pages);
                return;
            }
        }
    }

    // ── fsync / fdatasync ────────────────────────────────────────────────────

    /// Request a synchronous fsync for `ino`.
    ///
    /// Queues a `Sync` work item and returns its sequence number.
    /// The caller must wait for completion by polling
    /// [`is_writeback_complete`].
    pub fn fsync(&mut self, ino: InodeNumber) -> Result<u64> {
        self.queue.enqueue(ino, WritebackMode::Sync, 0)
    }

    /// Request a synchronous fdatasync for `ino`.
    ///
    /// Like [`fsync`] but only flushes data-integrity metadata.
    pub fn fdatasync(&mut self, ino: InodeNumber) -> Result<u64> {
        self.queue.enqueue(ino, WritebackMode::DataSync, 0)
    }

    /// Request a range sync for `ino` covering byte range `[start, end)`.
    pub fn sync_range(&mut self, ino: InodeNumber, start: u64, end: u64) -> Result<u64> {
        if start > end {
            return Err(Error::InvalidArgument);
        }
        let pages = ((end - start + PAGE_SIZE - 1) / PAGE_SIZE) as u32;
        self.queue
            .enqueue(ino, WritebackMode::Range { start, end }, pages)
    }

    // ── Background writeback ─────────────────────────────────────────────────

    /// Schedule background writeback for all expired dirty inodes.
    ///
    /// Returns the number of inodes queued.
    pub fn schedule_background(&mut self, now_ms: u64) -> usize {
        let mut due = [InodeNumber(0); 64];
        let expire = self.dirty_expire_ms;
        let count = self.dirty_list.collect_due(now_ms, expire, &mut due);
        let mut queued = 0usize;
        for i in 0..count {
            let ino = due[i];
            let _ = self.queue.enqueue(ino, WritebackMode::Background, 0);
            queued += 1;
        }
        queued
    }

    // ── Work processing ──────────────────────────────────────────────────────

    /// Process one pending work item.
    ///
    /// In a real kernel this would call back into the filesystem's
    /// `writepages()` operation. Here we simulate success and update
    /// bookkeeping.
    ///
    /// Returns `Ok(true)` if a work item was processed, `Ok(false)` if
    /// the queue was empty.
    pub fn process_one(&mut self, now_ms: u64) -> Result<bool> {
        let work = match self.queue.dequeue() {
            Some(w) => w,
            None => return Ok(false),
        };

        let ino = work.ino;
        let _ = self.dirty_list.begin_writeback(ino, now_ms);

        // Simulate writing back the computed number of pages.
        let pages = work.effective_pages();
        let bytes = pages as u64 * PAGE_SIZE;
        self.bytes_written = self.bytes_written.wrapping_add(bytes);
        self.wb_completed = self.wb_completed.wrapping_add(1);

        self.dirty_list.finish_writeback(ino);
        if !matches!(work.mode, WritebackMode::Background) {
            self.dirty_list.mark_clean(ino);
        }
        Ok(true)
    }

    /// Drain the entire work queue, processing all pending items.
    ///
    /// Returns the number of items processed.
    pub fn drain(&mut self, now_ms: u64) -> Result<usize> {
        let mut count = 0usize;
        while self.process_one(now_ms)? {
            count += 1;
        }
        Ok(count)
    }

    // ── Statistics ───────────────────────────────────────────────────────────

    /// Return a snapshot of writeback statistics.
    pub fn stats(&self) -> WritebackStats {
        WritebackStats {
            dirty_inodes: self.dirty_list.count(),
            pending_work: self.queue.len(),
            wb_completed: self.wb_completed,
            bytes_written: self.bytes_written,
        }
    }

    /// Return `true` if the inode has no pending dirty data.
    pub fn is_clean(&self, ino: InodeNumber) -> bool {
        match self.dirty_list.get(ino) {
            Some(s) => !s.data_dirty && !s.meta_dirty,
            None => true,
        }
    }
}

impl Default for FileWriteback {
    fn default() -> Self {
        Self::new()
    }
}

// ── WritebackStats ────────────────────────────────────────────────────────────

/// Snapshot of writeback controller statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct WritebackStats {
    /// Number of inodes currently in the dirty list.
    pub dirty_inodes: usize,
    /// Number of items in the writeback queue.
    pub pending_work: usize,
    /// Total writeback operations completed since creation.
    pub wb_completed: u64,
    /// Total bytes written back since creation.
    pub bytes_written: u64,
}

// ── Sync control flags (sync_file_range) ─────────────────────────────────────

/// Do not start any new writeback operations; just queue.
pub const SYNC_FILE_RANGE_WAIT_BEFORE: u32 = 1 << 0;

/// Kick off writeback for the range.
pub const SYNC_FILE_RANGE_WRITE: u32 = 1 << 1;

/// Wait for writeback to complete before returning.
pub const SYNC_FILE_RANGE_WAIT_AFTER: u32 = 1 << 2;

/// Validate `sync_file_range` flags bitmask.
pub fn validate_sync_range_flags(flags: u32) -> bool {
    let valid = SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    flags & !valid == 0 && flags != 0
}

// ── Inode dirty flags ─────────────────────────────────────────────────────────
//
// Mirror of Linux's I_DIRTY_* flags from include/linux/fs.h.
// These are stored in InodeDirtyState and tested during writeback.

/// Inode attributes (timestamps, size, mode) are dirty.
pub const I_DIRTY_SYNC: u32 = 1 << 0;

/// Data-integrity metadata is dirty (size, block map).
/// Flushed by fdatasync(); does not imply atime/mtime flush.
pub const I_DIRTY_DATASYNC: u32 = 1 << 1;

/// Page cache pages belonging to this inode are dirty.
pub const I_DIRTY_PAGES: u32 = 1 << 2;

/// Inode has been freed (writeback must not reference it).
pub const I_FREEING: u32 = 1 << 3;

/// All dirty flags combined.
pub const I_DIRTY: u32 = I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES;

/// Returns the `I_DIRTY_*` bits appropriate for a writeback mode.
pub fn dirty_flags_for_mode(mode: WritebackMode) -> u32 {
    match mode {
        WritebackMode::Sync => I_DIRTY,
        WritebackMode::DataSync => I_DIRTY_DATASYNC | I_DIRTY_PAGES,
        WritebackMode::Background => I_DIRTY_PAGES,
        WritebackMode::Range { .. } => I_DIRTY_PAGES,
    }
}

// ── WbcMode ───────────────────────────────────────────────────────────────────
//
// Linux uses `enum writeback_sync_modes` in include/linux/writeback.h.
// We map it onto our WritebackMode but provide the canonical names as
// a type alias and helper constants.

/// Writeback control mode — canonical names from Linux writeback.h.
///
/// This is an alias for [`WritebackMode`]; use either interchangeably.
pub type WbcMode = WritebackMode;

/// Background writeback: non-blocking, triggered by dirty threshold.
pub const WBC_SYNC_NONE: WbcMode = WritebackMode::Background;

/// Synchronous writeback: blocks until all pages are on stable storage.
pub const WBC_SYNC_ALL: WbcMode = WritebackMode::Sync;

// ── WbControl ────────────────────────────────────────────────────────────────

/// Writeback control structure (mirrors `struct writeback_control`).
///
/// Passed to filesystem `writepages()` callbacks to convey the scope
/// and behaviour of the current writeback request.
#[derive(Debug, Clone, Copy)]
pub struct WbControl {
    /// Sync mode for this request.
    pub sync_mode: WbcMode,
    /// Number of pages requested to write (0 = unlimited).
    pub nr_to_write: i64,
    /// Number of pages actually written (updated by filesystem).
    pub pages_skipped: i64,
    /// Byte range start for range writeback.
    pub range_start: u64,
    /// Byte range end for range writeback (inclusive).
    pub range_end: u64,
    /// True if writing for data integrity (fsync/fdatasync path).
    pub for_sync: bool,
    /// True if the writeback is for background reclaim.
    pub for_background: bool,
    /// True if the writeback is periodic (kupdate-style).
    pub for_kupdate: bool,
    /// True if this is a reclaim writeback triggered by memory pressure.
    pub for_reclaim: bool,
    /// Superblock ID this request targets (0 = all).
    pub sb_id: u64,
}

impl WbControl {
    /// Create a background writeback control.
    pub fn background(nr_to_write: i64) -> Self {
        Self {
            sync_mode: WBC_SYNC_NONE,
            nr_to_write,
            pages_skipped: 0,
            range_start: 0,
            range_end: u64::MAX,
            for_sync: false,
            for_background: true,
            for_kupdate: false,
            for_reclaim: false,
            sb_id: 0,
        }
    }

    /// Create a sync writeback control.
    pub fn sync(sb_id: u64) -> Self {
        Self {
            sync_mode: WBC_SYNC_ALL,
            nr_to_write: i64::MAX,
            pages_skipped: 0,
            range_start: 0,
            range_end: u64::MAX,
            for_sync: true,
            for_background: false,
            for_kupdate: false,
            for_reclaim: false,
            sb_id,
        }
    }

    /// Create a periodic (kupdate) writeback control.
    pub fn periodic(nr_to_write: i64) -> Self {
        Self {
            sync_mode: WBC_SYNC_NONE,
            nr_to_write,
            pages_skipped: 0,
            range_start: 0,
            range_end: u64::MAX,
            for_sync: false,
            for_background: false,
            for_kupdate: true,
            for_reclaim: false,
            sb_id: 0,
        }
    }

    /// Create a range writeback control.
    pub fn range(start: u64, end: u64, sync: bool) -> Self {
        let sync_mode = if sync { WBC_SYNC_ALL } else { WBC_SYNC_NONE };
        Self {
            sync_mode,
            nr_to_write: i64::MAX,
            pages_skipped: 0,
            range_start: start,
            range_end: end,
            for_sync: sync,
            for_background: false,
            for_kupdate: false,
            for_reclaim: false,
            sb_id: 0,
        }
    }

    /// Remaining pages to write (saturating).
    pub fn remaining(&self) -> i64 {
        self.nr_to_write.saturating_sub(self.pages_skipped)
    }

    /// Account for `n` pages written.
    pub fn account_written(&mut self, n: i64) {
        self.nr_to_write = self.nr_to_write.saturating_sub(n);
    }
}

// ── DirtyThresholds ───────────────────────────────────────────────────────────

/// Dirty memory thresholds for balance_dirty_pages().
#[derive(Debug, Clone, Copy)]
pub struct DirtyThresholds {
    /// Total pages in the system.
    pub total_pages: u64,
    /// Background writeback starts at this dirty page count.
    pub background_thresh: u64,
    /// Processes are throttled above this dirty page count.
    pub dirty_thresh: u64,
    /// Hard limit — writeback is forced above this level.
    pub hard_limit: u64,
}

impl DirtyThresholds {
    /// Compute thresholds from total page count and ratio parameters.
    ///
    /// - `bg_ratio`: background threshold as percentage of total (e.g. 10)
    /// - `dirty_ratio`: throttle threshold as percentage (e.g. 20)
    pub fn compute(total_pages: u64, bg_ratio: u32, dirty_ratio: u32) -> Self {
        let background_thresh = total_pages * bg_ratio as u64 / 100;
        let dirty_thresh = total_pages * dirty_ratio as u64 / 100;
        let hard_limit = dirty_thresh + dirty_thresh / 4; // 125% of dirty_thresh
        Self {
            total_pages,
            background_thresh,
            dirty_thresh,
            hard_limit,
        }
    }
}

// ── BdiWriteback ──────────────────────────────────────────────────────────────

/// Per-BDI (Block Device Info) writeback thread state.
///
/// Owns a dirty-inode list and processes writeback work in a loop.
/// Mirrors Linux's `struct bdi_writeback` and `wb_writeback()`.
pub struct BdiWriteback {
    /// BDI identifier.
    pub bdi_id: u64,
    /// Display name of the backing device.
    pub name: [u8; 32],
    /// Length of the name.
    pub name_len: usize,
    /// Dirty inode tracking.
    pub dirty_list: DirtyInodeList,
    /// Work queue.
    pub queue: WritebackQueue,
    /// Dirty page count across all inodes on this BDI.
    pub nr_dirty: u64,
    /// Pages written since last balance check.
    pub pages_written: u64,
    /// Thresholds derived from system memory.
    pub thresholds: DirtyThresholds,
    /// Configuration: dirty-expire threshold in ms.
    pub dirty_expire_ms: u64,
    /// Total writeback rounds completed.
    pub wb_rounds: u64,
    /// Total pages written by this BDI.
    pub total_pages_written: u64,
}

impl BdiWriteback {
    /// Create a new BDI writeback controller.
    pub fn new(bdi_id: u64, name: &[u8], total_pages: u64) -> Self {
        let name_len = name.len().min(31);
        let mut name_buf = [0u8; 32];
        name_buf[..name_len].copy_from_slice(&name[..name_len]);
        Self {
            bdi_id,
            name: name_buf,
            name_len,
            dirty_list: DirtyInodeList::new(),
            queue: WritebackQueue::new(),
            nr_dirty: 0,
            pages_written: 0,
            thresholds: DirtyThresholds::compute(total_pages, 10, 20),
            dirty_expire_ms: DEFAULT_DIRTY_EXPIRE_MS,
            wb_rounds: 0,
            total_pages_written: 0,
        }
    }

    /// Return the BDI name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Mark an inode dirty on this BDI.
    pub fn mark_inode_dirty(&mut self, ino: InodeNumber, flags: u32, now_ms: u64) -> Result<()> {
        let data = flags & (I_DIRTY_PAGES | I_DIRTY_DATASYNC) != 0;
        let meta = flags & I_DIRTY_SYNC != 0;
        self.dirty_list.mark_dirty(ino, data, meta, now_ms)?;
        if data {
            self.nr_dirty = self.nr_dirty.saturating_add(1);
        }
        Ok(())
    }

    /// Main writeback loop iteration (`wb_writeback()`).
    ///
    /// Processes up to `wbc.nr_to_write` pages worth of dirty inodes.
    /// Returns the number of pages written in this round.
    pub fn wb_writeback(&mut self, wbc: &mut WbControl, now_ms: u64) -> u64 {
        // Schedule due inodes into the queue
        let expire = self.dirty_expire_ms;
        let mut due = [InodeNumber(0); 64];
        let due_count = self.dirty_list.collect_due(now_ms, expire, &mut due);

        for i in 0..due_count {
            if wbc.remaining() <= 0 {
                break;
            }
            let ino = due[i];
            let mode = wbc.sync_mode;
            let nr = wbc.remaining().min(MAX_WRITEBACK_PAGES as i64) as u32;
            let _ = self.queue.enqueue(ino, mode, nr);
        }

        // Process queued work
        let mut pages_this_round = 0u64;
        while wbc.remaining() > 0 {
            let work = match self.queue.dequeue() {
                Some(w) => w,
                None => break,
            };
            let ino = work.ino;
            let _ = self.dirty_list.begin_writeback(ino, now_ms);

            let pages = work.effective_pages() as u64;
            pages_this_round += pages;
            self.total_pages_written += pages;
            self.pages_written += pages;
            wbc.account_written(pages as i64);

            // Mark clean after writeback
            self.dirty_list.finish_writeback(ino);
            if !matches!(work.mode, WritebackMode::Background) {
                self.dirty_list.mark_clean(ino);
                self.nr_dirty = self.nr_dirty.saturating_sub(1);
            }
        }

        self.wb_rounds += 1;
        pages_this_round
    }

    /// Trigger background writeback if dirty pages exceed background threshold.
    ///
    /// Returns the number of pages written.
    pub fn balance_dirty_pages(&mut self, now_ms: u64) -> u64 {
        if self.nr_dirty <= self.thresholds.background_thresh {
            return 0;
        }
        let to_write = self
            .nr_dirty
            .saturating_sub(self.thresholds.background_thresh);
        let to_write_pages = to_write.min(MAX_WRITEBACK_PAGES as u64 * 4);
        let mut wbc = WbControl::background(to_write_pages as i64);
        self.wb_writeback(&mut wbc, now_ms)
    }

    /// Check if the calling process should be throttled (dirty > dirty_thresh).
    pub fn should_throttle(&self) -> bool {
        self.nr_dirty > self.thresholds.dirty_thresh
    }

    /// Check if writeback is urgently needed (dirty > hard_limit).
    pub fn is_over_hard_limit(&self) -> bool {
        self.nr_dirty > self.thresholds.hard_limit
    }

    /// Reset the pages_written counter (called after each balance interval).
    pub fn reset_period_stats(&mut self) {
        self.pages_written = 0;
    }
}

// ── SuperblockWriteback ───────────────────────────────────────────────────────

/// Result of a `writeback_inodes_sb()` call.
#[derive(Debug, Clone, Copy, Default)]
pub struct SbWritebackResult {
    /// Number of inodes processed.
    pub inodes_written: u64,
    /// Number of pages written.
    pub pages_written: u64,
    /// Number of inodes still dirty after the run.
    pub inodes_remaining: u64,
}

/// Superblock-wide writeback: write all dirty inodes on a filesystem.
///
/// Mirrors `writeback_inodes_sb()` / `writeback_inodes_sb_if_idle()` from
/// `fs/fs-writeback.c`.  Iterates the provided BDI list and flushes all
/// inodes belonging to `sb_id`.
///
/// # Arguments
///
/// - `bdis`: mutable slice of BDI writeback controllers
/// - `sb_id`: superblock identifier (0 = flush all BDIs regardless of sb)
/// - `wbc`: writeback control (mode + page budget)
/// - `now_ms`: current monotonic time in milliseconds
pub fn writeback_inodes_sb(
    bdis: &mut [BdiWriteback],
    sb_id: u64,
    wbc: &mut WbControl,
    now_ms: u64,
) -> SbWritebackResult {
    let mut result = SbWritebackResult::default();

    for bdi in bdis.iter_mut() {
        if sb_id != 0 && bdi.bdi_id != sb_id {
            continue;
        }
        if bdi.dirty_list.is_empty() {
            continue;
        }

        let before_dirty = bdi.dirty_list.count() as u64;
        let pages = bdi.wb_writeback(wbc, now_ms);

        result.pages_written += pages;
        let after_dirty = bdi.dirty_list.count() as u64;
        result.inodes_written += before_dirty.saturating_sub(after_dirty);
        result.inodes_remaining += after_dirty;

        if wbc.remaining() <= 0 {
            break;
        }
    }

    result
}

/// Write back all dirty inodes on `sb_id` only if the BDI is currently idle.
///
/// Returns `None` if the BDI is busy (writeback in progress), otherwise
/// returns the result of `writeback_inodes_sb`.
pub fn writeback_inodes_sb_if_idle(
    bdis: &mut [BdiWriteback],
    sb_id: u64,
    now_ms: u64,
) -> Option<SbWritebackResult> {
    // Consider a BDI idle if its queue is empty.
    let all_idle = bdis
        .iter()
        .all(|b| (sb_id != 0 && b.bdi_id != sb_id) || b.queue.is_empty());
    if !all_idle {
        return None;
    }
    let mut wbc = WbControl::sync(sb_id);
    Some(writeback_inodes_sb(bdis, sb_id, &mut wbc, now_ms))
}

// ── balance_dirty_pages (system-wide) ────────────────────────────────────────

/// System-wide dirty page balancing.
///
/// Called from the write path when the number of dirty pages across all
/// BDIs exceeds the background threshold.  Iterates all BDIs and triggers
/// background writeback until the dirty count is below the threshold.
///
/// Returns the total number of pages written across all BDIs.
pub fn balance_dirty_pages_ratelimited(bdis: &mut [BdiWriteback], now_ms: u64) -> u64 {
    let mut total_written = 0u64;
    for bdi in bdis.iter_mut() {
        total_written += bdi.balance_dirty_pages(now_ms);
    }
    total_written
}

// ── Writeback work descriptor ─────────────────────────────────────────────────

/// High-level descriptor for a single writeback work request.
///
/// Used by the per-BDI work thread to describe what to do in each
/// `wb_writeback()` invocation.
#[derive(Debug, Clone, Copy)]
pub struct WbWorkDesc {
    /// Superblock ID (0 = all).
    pub sb_id: u64,
    /// Writeback mode.
    pub sync_mode: WbcMode,
    /// Maximum pages to write.
    pub nr_pages: u64,
    /// If true, write all expired inodes regardless of page budget.
    pub write_all: bool,
    /// Reason for the writeback (for tracing/debug).
    pub reason: WbWorkReason,
}

/// Reason a writeback work item was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WbWorkReason {
    /// Triggered by background threshold crossing.
    Background,
    /// Triggered by periodic kupdate timer.
    Periodic,
    /// Triggered by explicit sync(2) / syncfs(2).
    Sync,
    /// Triggered by filesystem unmount.
    Umount,
    /// Triggered by memory reclaim.
    MemReclaim,
}

impl WbWorkDesc {
    /// Create a background writeback work descriptor.
    pub fn background(nr_pages: u64) -> Self {
        Self {
            sb_id: 0,
            sync_mode: WBC_SYNC_NONE,
            nr_pages,
            write_all: false,
            reason: WbWorkReason::Background,
        }
    }

    /// Create a periodic writeback work descriptor.
    pub fn periodic(nr_pages: u64) -> Self {
        Self {
            sb_id: 0,
            sync_mode: WBC_SYNC_NONE,
            nr_pages,
            write_all: true,
            reason: WbWorkReason::Periodic,
        }
    }

    /// Create a sync writeback work descriptor targeting a specific superblock.
    pub fn sync(sb_id: u64) -> Self {
        Self {
            sb_id,
            sync_mode: WBC_SYNC_ALL,
            nr_pages: u64::MAX,
            write_all: true,
            reason: WbWorkReason::Sync,
        }
    }

    /// Create an unmount writeback work descriptor.
    pub fn umount(sb_id: u64) -> Self {
        Self {
            sb_id,
            sync_mode: WBC_SYNC_ALL,
            nr_pages: u64::MAX,
            write_all: true,
            reason: WbWorkReason::Umount,
        }
    }
}

// ── WbThread ─────────────────────────────────────────────────────────────────

/// Simulated per-BDI writeback thread.
///
/// In a real kernel this would be a kernel thread sleeping on a wait queue.
/// Here it maintains a pending work list and processes items when
/// `run_pending()` is called (from the scheduler tick or explicit trigger).
pub struct WbThread {
    /// Pending work descriptors.
    work_list: [Option<WbWorkDesc>; 16],
    /// Number of pending items.
    pending: usize,
    /// Total items processed.
    pub processed: u64,
    /// BDI this thread serves.
    pub bdi_id: u64,
}

impl WbThread {
    /// Create a new writeback thread for `bdi_id`.
    pub fn new(bdi_id: u64) -> Self {
        Self {
            work_list: [None; 16],
            pending: 0,
            processed: 0,
            bdi_id,
        }
    }

    /// Queue a writeback work item.
    pub fn queue_work(&mut self, desc: WbWorkDesc) -> Result<()> {
        if self.pending >= self.work_list.len() {
            return Err(Error::Busy);
        }
        for slot in &mut self.work_list {
            if slot.is_none() {
                *slot = Some(desc);
                self.pending += 1;
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Process all pending work items against `bdi`.
    ///
    /// Returns the total pages written.
    pub fn run_pending(&mut self, bdi: &mut BdiWriteback, now_ms: u64) -> u64 {
        let mut total_pages = 0u64;
        for slot in &mut self.work_list {
            let desc = match slot.take() {
                Some(d) => d,
                None => continue,
            };
            self.pending -= 1;

            let nr = desc.nr_pages.min(i64::MAX as u64) as i64;
            let mut wbc = match desc.sync_mode {
                WritebackMode::Sync | WritebackMode::DataSync => WbControl::sync(desc.sb_id),
                _ => WbControl::background(nr),
            };
            if desc.reason == WbWorkReason::Periodic {
                wbc.for_kupdate = true;
                wbc.for_background = false;
            }

            total_pages += bdi.wb_writeback(&mut wbc, now_ms);
            self.processed += 1;
        }
        total_pages
    }

    /// Returns true if there are pending work items.
    pub fn has_work(&self) -> bool {
        self.pending > 0
    }
}

// ── Writeback event counters ──────────────────────────────────────────────────

/// Global writeback event counters (for /proc/vmstat-style output).
#[derive(Debug, Clone, Copy, Default)]
pub struct WbEventCounters {
    /// Pages written by background writeback.
    pub nr_written_background: u64,
    /// Pages written by periodic kupdate.
    pub nr_written_periodic: u64,
    /// Pages written by sync operations.
    pub nr_written_sync: u64,
    /// Number of times a process was throttled by dirty-page pressure.
    pub nr_dirty_throttled: u64,
    /// Number of balance_dirty_pages() calls.
    pub nr_balance_calls: u64,
}

impl WbEventCounters {
    /// Record a writeback result.
    pub fn record(&mut self, reason: WbWorkReason, pages: u64) {
        match reason {
            WbWorkReason::Background | WbWorkReason::MemReclaim => {
                self.nr_written_background += pages;
            }
            WbWorkReason::Periodic => {
                self.nr_written_periodic += pages;
            }
            WbWorkReason::Sync | WbWorkReason::Umount => {
                self.nr_written_sync += pages;
            }
        }
    }

    /// Record a dirty-throttle event.
    pub fn record_throttle(&mut self) {
        self.nr_dirty_throttled += 1;
    }

    /// Record a balance_dirty_pages call.
    pub fn record_balance(&mut self) {
        self.nr_balance_calls += 1;
    }

    /// Format counters as a byte vector (for /proc/vmstat).
    pub fn format(&self) -> Vec<u8> {
        let mut out = Vec::new();
        append_counter(
            &mut out,
            b"nr_written_background",
            self.nr_written_background,
        );
        append_counter(&mut out, b"nr_written_periodic", self.nr_written_periodic);
        append_counter(&mut out, b"nr_written_sync", self.nr_written_sync);
        append_counter(&mut out, b"nr_dirty_throttled", self.nr_dirty_throttled);
        append_counter(&mut out, b"nr_balance_dirty_pages", self.nr_balance_calls);
        out
    }
}

fn append_counter(buf: &mut Vec<u8>, name: &[u8], value: u64) {
    buf.extend_from_slice(name);
    buf.push(b' ');
    write_u64_dec(buf, value);
    buf.push(b'\n');
}

fn write_u64_dec(buf: &mut Vec<u8>, v: u64) {
    if v == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    let mut n = v;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    for i in (0..len).rev() {
        buf.push(tmp[i]);
    }
}
