// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FUSE writeback caching — deferred write-back for FUSE filesystems.
//!
//! When the FUSE daemon enables writeback mode (`FUSE_WRITEBACK_CACHE`),
//! the kernel caches writes in the page cache and flushes them to the
//! daemon asynchronously.  This improves write throughput by batching
//! small writes and allowing the application to return before the daemon
//! has acknowledged the data.
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |  Application write(fd, buf, n)                               |
//! |       |                                                      |
//! |       v                                                      |
//! |  VFS -> FUSE file_operations.write_iter()                    |
//! |       |                                                      |
//! |       v                                                      |
//! |  +----------------------------------------------+            |
//! |  | WritebackCache                               |            |
//! |  | +------------------------------------------+ |            |
//! |  | | Dirty pages (per-inode tracking)         | |            |
//! |  | | inode 42: pages [0,1,5,6,7]              | |            |
//! |  | | inode 99: pages [0,2,3]                  | |            |
//! |  | +------------------------------------------+ |            |
//! |  |       |                                      |            |
//! |  |       v (flush timer / sync / memory press.) |            |
//! |  | +------------------------------------------+ |            |
//! |  | | FuseWriteReq                             | |            |
//! |  | | batch pages -> FUSE_WRITE to daemon      | |            |
//! |  | +------------------------------------------+ |            |
//! |  +----------------------------------------------+            |
//! |       |                                                      |
//! |       v                                                      |
//! |  FUSE daemon acknowledges write                              |
//! +-------------------------------------------------------------+
//! ```
//!
//! # Flush policy
//!
//! - **Timer**: Dirty pages are flushed after a configurable timeout.
//! - **Threshold**: Flush when dirty page count exceeds a high-water mark.
//! - **Sync**: `fsync(2)` or `sync(2)` forces immediate flush.
//! - **Close**: `close(2)` flushes all dirty pages for that file.
//! - **Memory pressure**: The writeback engine flushes when the system
//!   is under memory pressure.
//!
//! # Reference
//!
//! Linux `fs/fuse/file.c` (writeback cache mode), `fs/fuse/inode.c`,
//! `include/linux/fuse.h` (`FUSE_WRITEBACK_CACHE`).

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of inodes with dirty pages tracked simultaneously.
const MAX_DIRTY_INODES: usize = 64;

/// Maximum dirty pages tracked per inode.
const MAX_DIRTY_PAGES_PER_INODE: usize = 128;

/// Maximum pending write requests.
const MAX_WRITE_REQS: usize = 32;

/// Maximum pages per single FUSE write request.
const MAX_PAGES_PER_REQ: usize = 32;

/// Page size in bytes.
const PAGE_SIZE: u64 = 4096;

/// Default flush timeout in milliseconds.
const DEFAULT_FLUSH_TIMEOUT_MS: u64 = 5000;

/// Default dirty-page high watermark (per-inode).
const DEFAULT_DIRTY_HIGH: usize = 64;

/// Default dirty-page low watermark (per-inode) — target after flush.
const DEFAULT_DIRTY_LOW: usize = 16;

/// Sentinel for "no entry".
const NONE_IDX: u32 = u32::MAX;

// ── WritebackState ───────────────────────────────────────────────────────────

/// State of the writeback system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritebackState {
    /// Writeback caching is disabled; writes go directly to daemon.
    Disabled,
    /// Writeback caching is enabled and idle (no pending flushes).
    Idle,
    /// Currently flushing dirty pages to the daemon.
    Flushing,
    /// Error state — daemon failed to acknowledge writes.
    Error,
}

// ── FlushReason ──────────────────────────────────────────────────────────────

/// Reason for triggering a writeback flush.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushReason {
    /// Periodic timer expiry.
    Timer,
    /// Dirty page count exceeded threshold.
    Threshold,
    /// Explicit fsync/sync call.
    Sync,
    /// File being closed.
    Close,
    /// System memory pressure.
    MemoryPressure,
    /// Explicit user/admin request.
    Manual,
}

// ── FlushPolicy ──────────────────────────────────────────────────────────────

/// Configuration for when and how dirty pages are flushed.
#[derive(Debug, Clone, Copy)]
pub struct FlushPolicy {
    /// Flush timeout in milliseconds.
    pub timeout_ms: u64,
    /// High watermark: flush when dirty pages exceed this count.
    pub dirty_high: usize,
    /// Low watermark: target after flushing.
    pub dirty_low: usize,
    /// Maximum pages to flush in a single batch.
    pub max_batch: usize,
    /// Whether to flush on close.
    pub flush_on_close: bool,
    /// Whether to honour sync requests immediately.
    pub honour_sync: bool,
}

impl FlushPolicy {
    /// Default flush policy.
    pub const fn default_policy() -> Self {
        Self {
            timeout_ms: DEFAULT_FLUSH_TIMEOUT_MS,
            dirty_high: DEFAULT_DIRTY_HIGH,
            dirty_low: DEFAULT_DIRTY_LOW,
            max_batch: MAX_PAGES_PER_REQ,
            flush_on_close: true,
            honour_sync: true,
        }
    }
}

// ── DirtyPage ────────────────────────────────────────────────────────────────

/// A dirty page tracked in the writeback cache.
#[derive(Debug, Clone, Copy)]
struct DirtyPage {
    /// Page index (file offset / PAGE_SIZE).
    page_index: u64,
    /// When this page was first dirtied (monotonic ms).
    dirtied_at: u64,
    /// When this page was last written (monotonic ms).
    last_write: u64,
    /// Number of writes to this page since it became dirty.
    write_count: u32,
    /// Whether this slot is in use.
    in_use: bool,
}

impl DirtyPage {
    /// Create an empty, unused slot.
    const fn empty() -> Self {
        Self {
            page_index: 0,
            dirtied_at: 0,
            last_write: 0,
            write_count: 0,
            in_use: false,
        }
    }
}

// ── DirtyInode ───────────────────────────────────────────────────────────────

/// Per-inode dirty page tracking.
struct DirtyInode {
    /// Inode number.
    inode: u64,
    /// Dirty pages.
    pages: [DirtyPage; MAX_DIRTY_PAGES_PER_INODE],
    /// Number of active dirty pages.
    dirty_count: usize,
    /// File size (to validate writes).
    file_size: u64,
    /// Time of first dirty page (for timeout).
    first_dirty_at: u64,
    /// Whether this slot is in use.
    in_use: bool,
    /// Whether a flush is currently in progress for this inode.
    flushing: bool,
}

impl DirtyInode {
    /// Create an empty, unused slot.
    const fn empty() -> Self {
        Self {
            inode: 0,
            pages: [const { DirtyPage::empty() }; MAX_DIRTY_PAGES_PER_INODE],
            dirty_count: 0,
            file_size: 0,
            first_dirty_at: 0,
            in_use: false,
            flushing: false,
        }
    }

    /// Find a dirty page by page index.
    fn find_page(&self, page_index: u64) -> Option<usize> {
        for (i, page) in self.pages.iter().enumerate() {
            if page.in_use && page.page_index == page_index {
                return Some(i);
            }
        }
        None
    }

    /// Find a free page slot.
    fn find_free_page(&self) -> Option<usize> {
        self.pages.iter().position(|p| !p.in_use)
    }

    /// Get the oldest dirty page index (for flushing).
    fn oldest_dirty_page(&self) -> Option<usize> {
        let mut oldest: Option<usize> = None;
        let mut oldest_time = u64::MAX;
        for (i, page) in self.pages.iter().enumerate() {
            if page.in_use && page.dirtied_at < oldest_time {
                oldest_time = page.dirtied_at;
                oldest = Some(i);
            }
        }
        oldest
    }
}

// ── FuseWriteReq ─────────────────────────────────────────────────────────────

/// A FUSE write request batching multiple dirty pages.
#[derive(Clone, Copy)]
pub struct FuseWriteReq {
    /// Request ID.
    pub req_id: u32,
    /// Inode number.
    pub inode: u64,
    /// Starting file offset.
    pub offset: u64,
    /// Page indices included in this request.
    pub page_indices: [u64; MAX_PAGES_PER_REQ],
    /// Number of pages in this request.
    pub page_count: usize,
    /// Total bytes in this write.
    pub total_bytes: u64,
    /// Reason for the flush.
    pub reason: FlushReason,
    /// Timestamp when the request was created.
    pub created_at: u64,
    /// Whether the daemon has acknowledged this request.
    pub acknowledged: bool,
    /// Whether this slot is in use.
    pub in_use: bool,
}

impl FuseWriteReq {
    /// Create an empty, unused request.
    const fn empty() -> Self {
        Self {
            req_id: 0,
            inode: 0,
            offset: 0,
            page_indices: [0; MAX_PAGES_PER_REQ],
            page_count: 0,
            total_bytes: 0,
            reason: FlushReason::Timer,
            created_at: 0,
            acknowledged: false,
            in_use: false,
        }
    }
}

// ── WritebackStats ───────────────────────────────────────────────────────────

/// Statistics for the writeback cache.
#[derive(Debug, Clone, Copy, Default)]
pub struct WritebackStats {
    /// Total pages dirtied.
    pub pages_dirtied: u64,
    /// Total pages flushed (written back).
    pub pages_flushed: u64,
    /// Total write requests sent to daemon.
    pub write_reqs_sent: u64,
    /// Total write requests acknowledged.
    pub write_reqs_acked: u64,
    /// Total write requests that failed.
    pub write_reqs_failed: u64,
    /// Current number of dirty pages.
    pub current_dirty: u32,
    /// Current number of dirty inodes.
    pub current_dirty_inodes: u32,
    /// Number of flushes triggered by timer.
    pub flush_timer: u64,
    /// Number of flushes triggered by threshold.
    pub flush_threshold: u64,
    /// Number of flushes triggered by sync.
    pub flush_sync: u64,
}

// ── WritebackCache ───────────────────────────────────────────────────────────

/// FUSE writeback cache engine.
///
/// Manages dirty pages for FUSE-mounted filesystems, batching writes
/// and flushing them to the FUSE daemon asynchronously.
pub struct WritebackCache {
    /// Per-inode dirty page tracking.
    inodes: [DirtyInode; MAX_DIRTY_INODES],
    /// Pending write requests.
    requests: [FuseWriteReq; MAX_WRITE_REQS],
    /// Next request ID.
    next_req_id: u32,
    /// Current state.
    state: WritebackState,
    /// Flush policy.
    policy: FlushPolicy,
    /// Current monotonic time in milliseconds.
    current_time_ms: u64,
    /// Statistics.
    stats: WritebackStats,
}

impl WritebackCache {
    /// Create a new writeback cache.
    pub const fn new() -> Self {
        Self {
            inodes: [const { DirtyInode::empty() }; MAX_DIRTY_INODES],
            requests: [const { FuseWriteReq::empty() }; MAX_WRITE_REQS],
            next_req_id: 1,
            state: WritebackState::Disabled,
            policy: FlushPolicy::default_policy(),
            current_time_ms: 0,
            stats: WritebackStats {
                pages_dirtied: 0,
                pages_flushed: 0,
                write_reqs_sent: 0,
                write_reqs_acked: 0,
                write_reqs_failed: 0,
                current_dirty: 0,
                current_dirty_inodes: 0,
                flush_timer: 0,
                flush_threshold: 0,
                flush_sync: 0,
            },
        }
    }

    /// Create a writeback cache with a custom flush policy.
    pub fn with_policy(policy: FlushPolicy) -> Self {
        let mut cache = Self::new();
        cache.policy = policy;
        cache
    }

    /// Enable writeback caching.
    pub fn enable(&mut self) {
        if self.state == WritebackState::Disabled {
            self.state = WritebackState::Idle;
        }
    }

    /// Disable writeback caching.
    ///
    /// All dirty pages should be flushed before calling this.
    pub fn disable(&mut self) {
        self.state = WritebackState::Disabled;
    }

    /// Update the current monotonic time.
    pub fn set_time(&mut self, now_ms: u64) {
        self.current_time_ms = now_ms;
    }

    /// Return the current state.
    pub fn state(&self) -> WritebackState {
        self.state
    }

    // ── Write begin / end ────────────────────────────────────────

    /// Begin a write: mark the affected page(s) as dirty.
    ///
    /// Called when user writes data to a FUSE file in writeback mode.
    /// The write is absorbed into the page cache and the pages are
    /// marked dirty for later flushing.
    pub fn write_begin(
        &mut self,
        inode: u64,
        offset: u64,
        length: u64,
        file_size: u64,
    ) -> Result<usize> {
        if self.state == WritebackState::Disabled {
            return Err(Error::NotImplemented);
        }
        if length == 0 {
            return Ok(0);
        }

        let inode_idx = self.get_or_create_inode(inode, file_size)?;
        let start_page = offset / PAGE_SIZE;
        let end_page = (offset + length + PAGE_SIZE - 1) / PAGE_SIZE;
        let mut pages_dirtied = 0usize;

        for page_idx in start_page..end_page {
            if let Some(existing) = self.inodes[inode_idx].find_page(page_idx) {
                // Page already dirty — update timestamps.
                self.inodes[inode_idx].pages[existing].last_write = self.current_time_ms;
                self.inodes[inode_idx].pages[existing].write_count += 1;
            } else {
                // New dirty page.
                let slot = self.inodes[inode_idx]
                    .find_free_page()
                    .ok_or(Error::OutOfMemory)?;

                self.inodes[inode_idx].pages[slot] = DirtyPage {
                    page_index: page_idx,
                    dirtied_at: self.current_time_ms,
                    last_write: self.current_time_ms,
                    write_count: 1,
                    in_use: true,
                };
                self.inodes[inode_idx].dirty_count += 1;
                pages_dirtied += 1;
                self.stats.pages_dirtied += 1;
                self.stats.current_dirty += 1;
            }
        }

        // Update file size if the write extends the file.
        let new_end = offset + length;
        if new_end > self.inodes[inode_idx].file_size {
            self.inodes[inode_idx].file_size = new_end;
        }

        // Check if threshold flush is needed.
        if self.inodes[inode_idx].dirty_count >= self.policy.dirty_high {
            // The caller should check and trigger a flush.
            self.stats.flush_threshold += 1;
        }

        Ok(pages_dirtied)
    }

    /// End a write (commit phase).
    ///
    /// Called after the data has been copied into the page cache.
    /// In our model this is a no-op confirmation.
    pub fn write_end(&mut self, _inode: u64, _offset: u64, _length: u64) -> Result<()> {
        // Write-end is a no-op in the model; the dirty tracking
        // was done in write_begin.
        Ok(())
    }

    // ── Flushing ─────────────────────────────────────────────────

    /// Flush dirty pages for a specific inode.
    ///
    /// Creates write requests for batches of dirty pages and returns
    /// the number of pages queued for flushing.
    pub fn writeback_pages(&mut self, inode: u64, reason: FlushReason) -> Result<usize> {
        let inode_idx = self
            .inodes
            .iter()
            .position(|d| d.in_use && d.inode == inode)
            .ok_or(Error::NotFound)?;

        if self.inodes[inode_idx].dirty_count == 0 {
            return Ok(0);
        }

        self.inodes[inode_idx].flushing = true;
        self.state = WritebackState::Flushing;

        let mut total_flushed = 0usize;
        let target = match reason {
            FlushReason::Sync | FlushReason::Close => 0, // flush all
            _ => self.policy.dirty_low,
        };

        while self.inodes[inode_idx].dirty_count > target {
            // Collect a batch of pages.
            let mut batch_pages = [0u64; MAX_PAGES_PER_REQ];
            let mut batch_count = 0usize;
            let mut min_offset = u64::MAX;

            for page in &self.inodes[inode_idx].pages {
                if batch_count >= self.policy.max_batch {
                    break;
                }
                if page.in_use {
                    batch_pages[batch_count] = page.page_index;
                    if page.page_index < min_offset {
                        min_offset = page.page_index;
                    }
                    batch_count += 1;
                }
            }

            if batch_count == 0 {
                break;
            }

            // Sort pages by index for sequential write.
            for i in 0..batch_count {
                for j in (i + 1)..batch_count {
                    if batch_pages[i] > batch_pages[j] {
                        batch_pages.swap(i, j);
                    }
                }
            }

            // Create write request.
            let req_slot = self
                .requests
                .iter_mut()
                .find(|r| !r.in_use)
                .ok_or(Error::Busy)?;

            let req_id = self.next_req_id;
            self.next_req_id += 1;

            req_slot.req_id = req_id;
            req_slot.inode = inode;
            req_slot.offset = batch_pages[0] * PAGE_SIZE;
            req_slot.page_indices[..batch_count].copy_from_slice(&batch_pages[..batch_count]);
            req_slot.page_count = batch_count;
            req_slot.total_bytes = batch_count as u64 * PAGE_SIZE;
            req_slot.reason = reason;
            req_slot.created_at = self.current_time_ms;
            req_slot.acknowledged = false;
            req_slot.in_use = true;

            self.stats.write_reqs_sent += 1;

            // Mark pages as clean (optimistic).
            for &page_idx in &batch_pages[..batch_count] {
                if let Some(slot) = self.inodes[inode_idx].find_page(page_idx) {
                    self.inodes[inode_idx].pages[slot].in_use = false;
                    self.inodes[inode_idx].dirty_count =
                        self.inodes[inode_idx].dirty_count.saturating_sub(1);
                    self.stats.pages_flushed += 1;
                    self.stats.current_dirty = self.stats.current_dirty.saturating_sub(1);
                }
            }

            total_flushed += batch_count;
        }

        self.inodes[inode_idx].flushing = false;

        // Clean up inode if no more dirty pages.
        if self.inodes[inode_idx].dirty_count == 0 && matches!(reason, FlushReason::Close) {
            self.inodes[inode_idx].in_use = false;
            self.stats.current_dirty_inodes = self.stats.current_dirty_inodes.saturating_sub(1);
        }

        // Update state.
        let any_dirty = self.inodes.iter().any(|d| d.in_use && d.dirty_count > 0);
        if !any_dirty {
            self.state = WritebackState::Idle;
        }

        Ok(total_flushed)
    }

    /// Flush all dirty pages across all inodes.
    pub fn flush_all(&mut self, reason: FlushReason) -> Result<usize> {
        let mut total = 0usize;
        // Collect inode numbers first to avoid borrow issues.
        let mut inode_ids = [0u64; MAX_DIRTY_INODES];
        let mut inode_count = 0usize;

        for di in &self.inodes {
            if di.in_use && di.dirty_count > 0 {
                inode_ids[inode_count] = di.inode;
                inode_count += 1;
            }
        }

        for &ino in &inode_ids[..inode_count] {
            match self.writeback_pages(ino, reason) {
                Ok(n) => total += n,
                Err(Error::Busy) => continue,
                Err(e) => return Err(e),
            }
        }

        Ok(total)
    }

    /// Acknowledge a completed write request from the FUSE daemon.
    pub fn acknowledge_write(&mut self, req_id: u32) -> Result<()> {
        let req = self
            .requests
            .iter_mut()
            .find(|r| r.in_use && r.req_id == req_id)
            .ok_or(Error::NotFound)?;

        req.acknowledged = true;
        req.in_use = false;
        self.stats.write_reqs_acked += 1;
        Ok(())
    }

    /// Report a failed write request.
    pub fn fail_write(&mut self, req_id: u32) -> Result<()> {
        let req = self
            .requests
            .iter_mut()
            .find(|r| r.in_use && r.req_id == req_id)
            .ok_or(Error::NotFound)?;

        // Mark pages as dirty again (they were optimistically cleaned).
        // In a real implementation we would re-dirty the pages.
        req.in_use = false;
        self.stats.write_reqs_failed += 1;
        self.state = WritebackState::Error;
        Ok(())
    }

    // ── Cache invalidation ───────────────────────────────────────

    /// Invalidate all dirty pages for an inode (data loss).
    ///
    /// Used when the daemon reports that the file was modified externally
    /// and our cached data is stale.
    pub fn invalidate_cache(&mut self, inode: u64) -> Result<usize> {
        let inode_idx = self
            .inodes
            .iter()
            .position(|d| d.in_use && d.inode == inode)
            .ok_or(Error::NotFound)?;

        let count = self.inodes[inode_idx].dirty_count;
        for page in &mut self.inodes[inode_idx].pages {
            page.in_use = false;
        }
        self.stats.current_dirty = self.stats.current_dirty.saturating_sub(count as u32);
        self.inodes[inode_idx].dirty_count = 0;
        self.inodes[inode_idx].in_use = false;
        self.stats.current_dirty_inodes = self.stats.current_dirty_inodes.saturating_sub(1);

        Ok(count)
    }

    // ── Timer-driven flush ───────────────────────────────────────

    /// Check for inodes whose dirty pages have exceeded the flush timeout,
    /// and flush them.
    ///
    /// Should be called periodically by the writeback timer.
    pub fn tick(&mut self) -> Result<usize> {
        if self.state == WritebackState::Disabled {
            return Ok(0);
        }

        let timeout = self.policy.timeout_ms;
        let now = self.current_time_ms;
        let mut total = 0usize;

        let mut inode_ids = [0u64; MAX_DIRTY_INODES];
        let mut flush_count = 0usize;

        for di in &self.inodes {
            if di.in_use
                && di.dirty_count > 0
                && !di.flushing
                && now.saturating_sub(di.first_dirty_at) >= timeout
            {
                inode_ids[flush_count] = di.inode;
                flush_count += 1;
            }
        }

        for &ino in &inode_ids[..flush_count] {
            match self.writeback_pages(ino, FlushReason::Timer) {
                Ok(n) => {
                    total += n;
                    self.stats.flush_timer += 1;
                }
                Err(_) => continue,
            }
        }

        Ok(total)
    }

    // ── Queries ──────────────────────────────────────────────────

    /// Return the number of dirty pages for a specific inode.
    pub fn dirty_pages(&self, inode: u64) -> usize {
        self.inodes
            .iter()
            .find(|d| d.in_use && d.inode == inode)
            .map_or(0, |d| d.dirty_count)
    }

    /// Return the total number of dirty pages across all inodes.
    pub fn total_dirty_pages(&self) -> usize {
        self.stats.current_dirty as usize
    }

    /// Return the number of pending (unacknowledged) write requests.
    pub fn pending_requests(&self) -> usize {
        self.requests
            .iter()
            .filter(|r| r.in_use && !r.acknowledged)
            .count()
    }

    /// Return current statistics.
    pub fn stats(&self) -> WritebackStats {
        self.stats
    }

    /// Reset statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats.pages_dirtied = 0;
        self.stats.pages_flushed = 0;
        self.stats.write_reqs_sent = 0;
        self.stats.write_reqs_acked = 0;
        self.stats.write_reqs_failed = 0;
        self.stats.flush_timer = 0;
        self.stats.flush_threshold = 0;
        self.stats.flush_sync = 0;
    }

    // ── Internal helpers ─────────────────────────────────────────

    /// Get or create a dirty inode tracking slot.
    fn get_or_create_inode(&mut self, inode: u64, file_size: u64) -> Result<usize> {
        // Check if already tracked.
        for (i, di) in self.inodes.iter().enumerate() {
            if di.in_use && di.inode == inode {
                return Ok(i);
            }
        }

        // Allocate a new slot.
        let idx = self
            .inodes
            .iter()
            .position(|d| !d.in_use)
            .ok_or(Error::OutOfMemory)?;

        self.inodes[idx].inode = inode;
        self.inodes[idx].dirty_count = 0;
        self.inodes[idx].file_size = file_size;
        self.inodes[idx].first_dirty_at = self.current_time_ms;
        self.inodes[idx].in_use = true;
        self.inodes[idx].flushing = false;
        self.stats.current_dirty_inodes += 1;

        Ok(idx)
    }
}
