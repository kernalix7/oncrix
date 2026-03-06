// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Dirty page writeback engine.
//!
//! Flushes dirty pages from the page cache to their backing store.
//! Manages writeback threads, bandwidth throttling, and prioritized
//! flush scheduling. Cooperates with the VFS layer to ensure data
//! integrity while minimizing I/O latency impact on foreground
//! workloads.
//!
//! # Features
//!
//! - **Background writeback** -- asynchronous flush when dirty
//!   pages exceed the background threshold.
//! - **Foreground throttling** -- synchronous writeback when dirty
//!   pages exceed the foreground threshold, blocking writers.
//! - **Per-BDI tracking** -- each backing device has independent
//!   dirty page counts and write bandwidth estimation.
//! - **Periodic flush** -- old dirty pages are written back
//!   periodically even if thresholds are not exceeded.
//! - **Flush requests** -- explicit sync/fsync requests are
//!   dispatched through a priority queue.
//! - **Bandwidth throttling** -- limits write rate to avoid
//!   overwhelming the I/O subsystem.
//!
//! # Architecture
//!
//! - [`FlushPriority`] -- priority level for flush requests
//! - [`FlushRequest`] -- a single flush work item
//! - [`WbState`] -- per-backing-device writeback state
//! - [`WbThread`] -- writeback thread descriptor
//! - [`WritebackEngine`] -- the writeback manager
//! - [`WbStats`] -- aggregate statistics
//!
//! Reference: Linux `mm/page-writeback.c`, `mm/backing-dev.c`,
//! `fs/fs-writeback.c`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of backing devices tracked.
const MAX_BDI: usize = 16;

/// Maximum number of writeback threads.
const MAX_WB_THREADS: usize = 8;

/// Maximum number of flush requests queued.
const MAX_FLUSH_REQUESTS: usize = 64;

/// Maximum number of dirty pages tracked per BDI.
const MAX_DIRTY_PAGES_PER_BDI: u64 = 16384;

/// Default dirty ratio (percentage of total memory).
const DEFAULT_DIRTY_RATIO: u32 = 20;

/// Default background dirty ratio.
const DEFAULT_BG_DIRTY_RATIO: u32 = 10;

/// Default writeback interval in milliseconds.
const DEFAULT_WB_INTERVAL_MS: u64 = 5000;

/// Dirty page age threshold for periodic writeback (30 seconds).
const DEFAULT_DIRTY_EXPIRE_MS: u64 = 30000;

/// Bandwidth estimation window (200 ms).
const BW_WINDOW_MS: u64 = 200;

// ── FlushPriority ───────────────────────────────────────────────

/// Priority level for flush requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FlushPriority {
    /// Background -- low priority, asynchronous.
    Background = 0,
    /// Normal -- standard writeback.
    Normal = 1,
    /// High -- foreground throttling or sync.
    High = 2,
    /// Critical -- fsync, shutdown, or OOM.
    Critical = 3,
}

impl Default for FlushPriority {
    fn default() -> Self {
        Self::Normal
    }
}

// ── FlushReason ─────────────────────────────────────────────────

/// Reason a flush was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushReason {
    /// Background dirty ratio exceeded.
    BackgroundThreshold,
    /// Foreground dirty ratio exceeded.
    ForegroundThreshold,
    /// Periodic timer expired.
    Periodic,
    /// Explicit `sync(2)` / `syncfs(2)` call.
    Sync,
    /// Explicit `fsync(2)` / `fdatasync(2)` on a file.
    Fsync,
    /// Memory pressure / OOM.
    Reclaim,
    /// Filesystem unmount / shutdown.
    Shutdown,
}

impl Default for FlushReason {
    fn default() -> Self {
        Self::BackgroundThreshold
    }
}

// ── FlushRequest ────────────────────────────────────────────────

/// A single flush work item.
///
/// Describes a writeback request dispatched to the writeback
/// engine for processing.
#[derive(Debug, Clone, Copy)]
pub struct FlushRequest {
    /// Target BDI index (u32::MAX = all BDIs).
    pub bdi_index: u32,
    /// Number of pages to write back (0 = all dirty).
    pub nr_pages: u64,
    /// Flush priority.
    pub priority: FlushPriority,
    /// Reason for this flush.
    pub reason: FlushReason,
    /// Specific inode/file ID to flush (0 = all).
    pub inode_id: u64,
    /// Timestamp when the request was created (ms).
    pub created_at: u64,
    /// Whether this request is active.
    pub active: bool,
}

impl FlushRequest {
    /// Create an empty, inactive flush request.
    const fn empty() -> Self {
        Self {
            bdi_index: 0,
            nr_pages: 0,
            priority: FlushPriority::Background,
            reason: FlushReason::BackgroundThreshold,
            inode_id: 0,
            created_at: 0,
            active: false,
        }
    }
}

// ── WbState ─────────────────────────────────────────────────────

/// Per-backing-device writeback state.
///
/// Tracks dirty page counts, writeback progress, and write
/// bandwidth estimation for a single backing device.
#[derive(Debug, Clone, Copy)]
pub struct WbState {
    /// BDI identifier.
    pub id: u32,
    /// BDI name.
    name: [u8; 32],
    /// Name length.
    name_len: usize,
    /// Whether this BDI is active.
    pub active: bool,
    /// Number of dirty pages.
    pub dirty_pages: u64,
    /// Number of pages under writeback (in-flight).
    pub writeback_pages: u64,
    /// Total pages written since BDI creation.
    pub written_total: u64,
    /// Estimated write bandwidth (pages/second).
    pub bandwidth_pps: u64,
    /// Bandwidth measurement start time (ms).
    bw_start_time: u64,
    /// Pages written since bandwidth measurement start.
    bw_written: u64,
    /// Proportional dirty limit for this BDI.
    pub dirty_limit: u64,
    /// Timestamp of last completed writeback (ms).
    pub last_writeback: u64,
    /// Whether writeback is currently in progress.
    pub wb_active: bool,
}

impl WbState {
    /// Create an empty, inactive BDI state.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; 32],
            name_len: 0,
            active: false,
            dirty_pages: 0,
            writeback_pages: 0,
            written_total: 0,
            bandwidth_pps: 0,
            bw_start_time: 0,
            bw_written: 0,
            dirty_limit: MAX_DIRTY_PAGES_PER_BDI,
            last_writeback: 0,
            wb_active: false,
        }
    }

    /// Get the BDI name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Dirty ratio for this BDI (percentage of its limit).
    pub fn dirty_ratio(&self) -> u32 {
        if self.dirty_limit == 0 {
            return 0;
        }
        ((self.dirty_pages * 100) / self.dirty_limit) as u32
    }

    /// Whether this BDI has exceeded its dirty limit.
    pub fn over_limit(&self) -> bool {
        self.dirty_pages >= self.dirty_limit
    }
}

// ── WbThread ────────────────────────────────────────────────────

/// Writeback thread descriptor.
///
/// Tracks the state of a kernel writeback thread (analogous to
/// Linux's `bdi-default` or `flush-X:Y` threads).
#[derive(Debug, Clone, Copy)]
pub struct WbThread {
    /// Thread identifier.
    pub id: u32,
    /// Assigned BDI index (u32::MAX = any).
    pub bdi_index: u32,
    /// Whether the thread is active.
    pub active: bool,
    /// Whether the thread is currently processing work.
    pub busy: bool,
    /// Pages written by this thread.
    pub pages_written: u64,
    /// Number of flush operations completed.
    pub flush_ops: u64,
    /// Last activity timestamp (ms).
    pub last_active: u64,
}

impl WbThread {
    /// Create an empty, inactive thread.
    const fn empty() -> Self {
        Self {
            id: 0,
            bdi_index: u32::MAX,
            active: false,
            busy: false,
            pages_written: 0,
            flush_ops: 0,
            last_active: 0,
        }
    }
}

// ── WbStats ─────────────────────────────────────────────────────

/// Aggregate writeback statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct WbStats {
    /// Total flush requests processed.
    pub total_flush_requests: u64,
    /// Total pages written back.
    pub total_pages_written: u64,
    /// Background flushes triggered.
    pub background_flushes: u64,
    /// Foreground (throttling) flushes triggered.
    pub foreground_flushes: u64,
    /// Periodic flushes triggered.
    pub periodic_flushes: u64,
    /// Explicit sync/fsync flushes.
    pub sync_flushes: u64,
    /// Reclaim-triggered flushes.
    pub reclaim_flushes: u64,
    /// Global dirty pages.
    pub global_dirty_pages: u64,
    /// Global writeback pages (in-flight).
    pub global_writeback_pages: u64,
    /// Active BDI count.
    pub active_bdi_count: u32,
    /// Active writeback thread count.
    pub active_threads: u32,
}

// ── WritebackEngine ─────────────────────────────────────────────

/// The dirty page writeback engine.
///
/// Manages per-BDI dirty page tracking, writeback threads, flush
/// request queuing, and bandwidth throttling. Coordinates
/// background and foreground writeback to maintain dirty page
/// ratios within configured thresholds.
pub struct WritebackEngine {
    /// Per-BDI writeback state.
    bdis: [WbState; MAX_BDI],
    /// Number of active BDIs.
    bdi_count: usize,
    /// Writeback threads.
    threads: [WbThread; MAX_WB_THREADS],
    /// Number of active threads.
    thread_count: usize,
    /// Flush request queue.
    flush_queue: [FlushRequest; MAX_FLUSH_REQUESTS],
    /// Number of active flush requests.
    flush_count: usize,
    /// Global dirty page threshold (ratio, 0..100).
    dirty_ratio: u32,
    /// Background dirty threshold (ratio, 0..100).
    bg_dirty_ratio: u32,
    /// Writeback interval in milliseconds.
    wb_interval_ms: u64,
    /// Dirty page expiry age in milliseconds.
    dirty_expire_ms: u64,
    /// Total memory pages (for ratio calculation).
    total_memory_pages: u64,
    /// Statistics.
    stats: WbStats,
}

impl Default for WritebackEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl WritebackEngine {
    /// Creates a new writeback engine with default thresholds.
    pub const fn new() -> Self {
        Self {
            bdis: [const { WbState::empty() }; MAX_BDI],
            bdi_count: 0,
            threads: [const { WbThread::empty() }; MAX_WB_THREADS],
            thread_count: 0,
            flush_queue: [const { FlushRequest::empty() }; MAX_FLUSH_REQUESTS],
            flush_count: 0,
            dirty_ratio: DEFAULT_DIRTY_RATIO,
            bg_dirty_ratio: DEFAULT_BG_DIRTY_RATIO,
            wb_interval_ms: DEFAULT_WB_INTERVAL_MS,
            dirty_expire_ms: DEFAULT_DIRTY_EXPIRE_MS,
            total_memory_pages: 262144, // 1 GiB default
            stats: WbStats {
                total_flush_requests: 0,
                total_pages_written: 0,
                background_flushes: 0,
                foreground_flushes: 0,
                periodic_flushes: 0,
                sync_flushes: 0,
                reclaim_flushes: 0,
                global_dirty_pages: 0,
                global_writeback_pages: 0,
                active_bdi_count: 0,
                active_threads: 0,
            },
        }
    }

    // ── BDI management ──────────────────────────────────────────

    /// Register a backing device.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if BDI table is full.
    /// - [`Error::AlreadyExists`] if ID already registered.
    pub fn register_bdi(&mut self, id: u32, name: &[u8], dirty_limit: u64) -> Result<usize> {
        if self.bdis.iter().any(|b| b.active && b.id == id) {
            return Err(Error::AlreadyExists);
        }

        let idx = self
            .bdis
            .iter()
            .position(|b| !b.active)
            .ok_or(Error::OutOfMemory)?;

        let mut bdi = WbState::empty();
        bdi.id = id;
        bdi.active = true;
        bdi.dirty_limit = if dirty_limit > 0 {
            dirty_limit
        } else {
            MAX_DIRTY_PAGES_PER_BDI
        };

        let copy_len = name.len().min(32);
        bdi.name[..copy_len].copy_from_slice(&name[..copy_len]);
        bdi.name_len = copy_len;

        self.bdis[idx] = bdi;
        self.bdi_count += 1;
        self.update_stats();
        Ok(idx)
    }

    /// Unregister a backing device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no BDI with this ID.
    pub fn unregister_bdi(&mut self, id: u32) -> Result<()> {
        let idx = self
            .bdis
            .iter()
            .position(|b| b.active && b.id == id)
            .ok_or(Error::NotFound)?;

        self.bdis[idx].active = false;
        self.bdi_count = self.bdi_count.saturating_sub(1);
        self.update_stats();
        Ok(())
    }

    // ── Dirty page tracking ─────────────────────────────────────

    /// Mark pages as dirty for a BDI.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if BDI not found.
    pub fn mark_dirty(&mut self, bdi_id: u32, nr_pages: u64) -> Result<()> {
        let bdi = self
            .bdis
            .iter_mut()
            .find(|b| b.active && b.id == bdi_id)
            .ok_or(Error::NotFound)?;

        bdi.dirty_pages = bdi.dirty_pages.saturating_add(nr_pages);
        self.update_stats();
        Ok(())
    }

    /// Mark pages as clean (written back) for a BDI.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if BDI not found.
    pub fn mark_clean(&mut self, bdi_id: u32, nr_pages: u64, timestamp: u64) -> Result<()> {
        let bdi = self
            .bdis
            .iter_mut()
            .find(|b| b.active && b.id == bdi_id)
            .ok_or(Error::NotFound)?;

        bdi.dirty_pages = bdi.dirty_pages.saturating_sub(nr_pages);
        bdi.writeback_pages = bdi.writeback_pages.saturating_sub(nr_pages);
        bdi.written_total += nr_pages;
        bdi.last_writeback = timestamp;

        // Update bandwidth estimation.
        bdi.bw_written += nr_pages;
        let elapsed = timestamp.saturating_sub(bdi.bw_start_time);
        if elapsed >= BW_WINDOW_MS && elapsed > 0 {
            bdi.bandwidth_pps = (bdi.bw_written * 1000) / elapsed;
            bdi.bw_start_time = timestamp;
            bdi.bw_written = 0;
        }

        self.stats.total_pages_written += nr_pages;
        self.update_stats();
        Ok(())
    }

    /// Begin writeback for pages on a BDI (move dirty -> writeback).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if BDI not found.
    pub fn begin_writeback(&mut self, bdi_id: u32, nr_pages: u64) -> Result<u64> {
        let bdi = self
            .bdis
            .iter_mut()
            .find(|b| b.active && b.id == bdi_id)
            .ok_or(Error::NotFound)?;

        let actual = nr_pages.min(bdi.dirty_pages);
        bdi.dirty_pages -= actual;
        bdi.writeback_pages += actual;
        bdi.wb_active = true;
        self.update_stats();
        Ok(actual)
    }

    // ── Flush request management ────────────────────────────────

    /// Submit a flush request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if flush queue is full.
    pub fn submit_flush(
        &mut self,
        bdi_index: u32,
        nr_pages: u64,
        priority: FlushPriority,
        reason: FlushReason,
        inode_id: u64,
        timestamp: u64,
    ) -> Result<()> {
        let slot = self
            .flush_queue
            .iter_mut()
            .find(|f| !f.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = FlushRequest {
            bdi_index,
            nr_pages,
            priority,
            reason,
            inode_id,
            created_at: timestamp,
            active: true,
        };
        self.flush_count += 1;
        self.stats.total_flush_requests += 1;

        match reason {
            FlushReason::BackgroundThreshold => self.stats.background_flushes += 1,
            FlushReason::ForegroundThreshold => self.stats.foreground_flushes += 1,
            FlushReason::Periodic => self.stats.periodic_flushes += 1,
            FlushReason::Sync | FlushReason::Fsync => self.stats.sync_flushes += 1,
            FlushReason::Reclaim => self.stats.reclaim_flushes += 1,
            FlushReason::Shutdown => self.stats.sync_flushes += 1,
        }

        Ok(())
    }

    /// Dequeue the highest-priority flush request.
    ///
    /// Returns `None` if the queue is empty.
    pub fn dequeue_flush(&mut self) -> Option<FlushRequest> {
        // Find the highest-priority active request.
        let mut best_idx: Option<usize> = None;
        let mut best_priority = FlushPriority::Background;

        for (i, req) in self.flush_queue.iter().enumerate() {
            if !req.active {
                continue;
            }
            if best_idx.is_none() || req.priority > best_priority {
                best_idx = Some(i);
                best_priority = req.priority;
            }
        }

        if let Some(idx) = best_idx {
            let req = self.flush_queue[idx];
            self.flush_queue[idx].active = false;
            self.flush_count = self.flush_count.saturating_sub(1);
            Some(req)
        } else {
            None
        }
    }

    // ── Writeback thread management ─────────────────────────────

    /// Register a writeback thread.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if thread table is full.
    pub fn register_thread(&mut self, id: u32, bdi_index: u32) -> Result<()> {
        let slot = self
            .threads
            .iter_mut()
            .find(|t| !t.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = WbThread {
            id,
            bdi_index,
            active: true,
            busy: false,
            pages_written: 0,
            flush_ops: 0,
            last_active: 0,
        };
        self.thread_count += 1;
        self.update_stats();
        Ok(())
    }

    /// Mark a thread as busy/idle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if thread not found.
    pub fn set_thread_busy(&mut self, id: u32, busy: bool, timestamp: u64) -> Result<()> {
        let thread = self
            .threads
            .iter_mut()
            .find(|t| t.active && t.id == id)
            .ok_or(Error::NotFound)?;

        thread.busy = busy;
        thread.last_active = timestamp;
        Ok(())
    }

    /// Record pages written by a thread.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if thread not found.
    pub fn thread_wrote_pages(&mut self, id: u32, nr_pages: u64, timestamp: u64) -> Result<()> {
        let thread = self
            .threads
            .iter_mut()
            .find(|t| t.active && t.id == id)
            .ok_or(Error::NotFound)?;

        thread.pages_written += nr_pages;
        thread.flush_ops += 1;
        thread.last_active = timestamp;
        Ok(())
    }

    // ── Threshold checks ────────────────────────────────────────

    /// Check if the global dirty page ratio exceeds the background
    /// threshold.
    pub fn needs_background_writeback(&self) -> bool {
        let threshold = (self.total_memory_pages * u64::from(self.bg_dirty_ratio)) / 100;
        self.global_dirty_pages() >= threshold
    }

    /// Check if the global dirty page ratio exceeds the foreground
    /// threshold (writers should be throttled).
    pub fn needs_foreground_throttle(&self) -> bool {
        let threshold = (self.total_memory_pages * u64::from(self.dirty_ratio)) / 100;
        self.global_dirty_pages() >= threshold
    }

    /// Compute the global dirty page count.
    pub fn global_dirty_pages(&self) -> u64 {
        self.bdis
            .iter()
            .filter(|b| b.active)
            .map(|b| b.dirty_pages)
            .sum()
    }

    /// Compute the global writeback page count.
    pub fn global_writeback_pages(&self) -> u64 {
        self.bdis
            .iter()
            .filter(|b| b.active)
            .map(|b| b.writeback_pages)
            .sum()
    }

    // ── Configuration ───────────────────────────────────────────

    /// Set the global dirty ratio threshold.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if ratio > 100 or
    /// ratio <= bg_dirty_ratio.
    pub fn set_dirty_ratio(&mut self, ratio: u32) -> Result<()> {
        if ratio > 100 || ratio <= self.bg_dirty_ratio {
            return Err(Error::InvalidArgument);
        }
        self.dirty_ratio = ratio;
        Ok(())
    }

    /// Set the background dirty ratio threshold.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if ratio >= dirty_ratio
    /// or ratio > 100.
    pub fn set_bg_dirty_ratio(&mut self, ratio: u32) -> Result<()> {
        if ratio >= self.dirty_ratio || ratio > 100 {
            return Err(Error::InvalidArgument);
        }
        self.bg_dirty_ratio = ratio;
        Ok(())
    }

    /// Set the total memory page count (for ratio calculation).
    pub fn set_total_memory_pages(&mut self, pages: u64) {
        self.total_memory_pages = pages;
    }

    /// Set the writeback interval.
    pub fn set_wb_interval(&mut self, interval_ms: u64) {
        self.wb_interval_ms = interval_ms;
    }

    /// Set the dirty page expiry age.
    pub fn set_dirty_expire(&mut self, expire_ms: u64) {
        self.dirty_expire_ms = expire_ms;
    }

    // ── Accessors ───────────────────────────────────────────────

    /// Returns aggregate statistics.
    pub fn stats(&self) -> &WbStats {
        &self.stats
    }

    /// Number of active BDIs.
    pub fn bdi_count(&self) -> usize {
        self.bdi_count
    }

    /// Number of active writeback threads.
    pub fn thread_count(&self) -> usize {
        self.thread_count
    }

    /// Number of pending flush requests.
    pub fn flush_queue_len(&self) -> usize {
        self.flush_count
    }

    /// Current dirty ratio.
    pub fn dirty_ratio(&self) -> u32 {
        self.dirty_ratio
    }

    /// Current background dirty ratio.
    pub fn bg_dirty_ratio(&self) -> u32 {
        self.bg_dirty_ratio
    }

    /// Writeback interval in ms.
    pub fn wb_interval_ms(&self) -> u64 {
        self.wb_interval_ms
    }

    /// Dirty page expiry in ms.
    pub fn dirty_expire_ms(&self) -> u64 {
        self.dirty_expire_ms
    }

    /// Look up BDI state by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no BDI with this ID.
    pub fn bdi_state(&self, id: u32) -> Result<&WbState> {
        self.bdis
            .iter()
            .find(|b| b.active && b.id == id)
            .ok_or(Error::NotFound)
    }

    // ── Internal helpers ────────────────────────────────────────

    /// Update derived statistics.
    fn update_stats(&mut self) {
        self.stats.global_dirty_pages = self.global_dirty_pages();
        self.stats.global_writeback_pages = self.global_writeback_pages();
        self.stats.active_bdi_count = self.bdi_count as u32;
        self.stats.active_threads = self.threads.iter().filter(|t| t.active).count() as u32;
    }
}
