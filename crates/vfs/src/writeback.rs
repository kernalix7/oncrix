// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Dirty page writeback — flushing modified page cache data to storage.
//!
//! When user writes modify pages in the page cache, those pages become
//! "dirty" and must eventually be written back to the underlying storage.
//! This module implements the writeback framework: scheduling, throttling,
//! and inode dirty-list management.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Page cache (dirty pages)                                  │
//! │       │                                                    │
//! │       ▼                                                    │
//! │  ┌──────────────────────────────────────────┐              │
//! │  │  Writeback control                       │              │
//! │  │  ┌────────────┐ ┌──────────────────────┐ │              │
//! │  │  │ Work queue  │ │  Inode dirty lists   │ │              │
//! │  │  │ (pending    │ │  (dirty / io /       │ │              │
//! │  │  │  work items)│ │   more_io)           │ │              │
//! │  │  └────────────┘ └──────────────────────┘ │              │
//! │  │         │                │                │              │
//! │  │         ▼                ▼                │              │
//! │  │  ┌────────────────────────────┐          │              │
//! │  │  │  bdi_writeback             │          │              │
//! │  │  │  (per-BDI worker thread)   │          │              │
//! │  │  └────────────────────────────┘          │              │
//! │  │         │                                │              │
//! │  │         ▼                                │              │
//! │  │  ┌──────────────────────┐                │              │
//! │  │  │  balance_dirty_pages │ ← throttling   │              │
//! │  │  │  (per-process)       │                │              │
//! │  │  └──────────────────────┘                │              │
//! │  └──────────────────────────────────────────┘              │
//! │       │                                                    │
//! │       ▼                                                    │
//! │  Block device / filesystem                                 │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Sync modes
//!
//! - **WB_SYNC_NONE**: Background writeback for memory pressure relief;
//!   may skip locked or congested inodes.
//! - **WB_SYNC_ALL**: Synchronous writeback for `sync(2)` / `fsync(2)`;
//!   must write all dirty pages and wait for completion.
//!
//! # Dirty ratios
//!
//! - `dirty_background_ratio`: Percentage of memory at which background
//!   writeback kicks in (default 10%).
//! - `dirty_ratio`: Hard limit; processes writing new data are throttled
//!   (put to sleep) until dirty pages drop below this (default 20%).
//!
//! # Inode lists
//!
//! Each BDI writeback worker manages three lists:
//! - **dirty**: Inodes with dirty pages, waiting for writeback.
//! - **io**: Inodes currently being written back.
//! - **more_io**: Inodes that could not be fully written and need retry.
//!
//! # Reference
//!
//! Linux `fs/fs-writeback.c`, `mm/page-writeback.c`, `include/linux/writeback.h`.

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Default dirty background ratio (percentage of total memory).
pub const DEFAULT_DIRTY_BG_RATIO: u32 = 10;

/// Default dirty ratio (hard throttle threshold).
pub const DEFAULT_DIRTY_RATIO: u32 = 20;

/// Default writeback timer interval in milliseconds.
const WB_TIMER_INTERVAL_MS: u64 = 5000;

/// Maximum number of tracked dirty inodes.
const MAX_DIRTY_INODES: usize = 256;

/// Maximum number of pending writeback work items.
const MAX_WORK_ITEMS: usize = 64;

/// Maximum number of BDI (backing device info) writeback workers.
const MAX_BDI_WORKERS: usize = 8;

/// Maximum pages to write per work item batch.
const MAX_PAGES_PER_BATCH: u64 = 1024;

/// Page size in bytes.
const PAGE_SIZE: u64 = 4096;

// ── Sync mode ────────────────────────────────────────────────────────────────

/// Writeback synchronization mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WbSyncMode {
    /// Background writeback; skip locked/congested inodes.
    None,
    /// Synchronous writeback; write everything and wait.
    All,
}

// ── Dirty inode state ────────────────────────────────────────────────────────

/// Which dirty list an inode is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeDirtyList {
    /// Inode has dirty pages waiting for writeback.
    Dirty,
    /// Inode is currently being written back.
    Io,
    /// Inode needs additional writeback (partial write).
    MoreIo,
    /// Inode is clean (not on any dirty list).
    Clean,
}

/// Dirty inode tracking entry.
struct DirtyInode {
    /// Inode number.
    inode: u64,
    /// Superblock/device ID this inode belongs to.
    device_id: u32,
    /// Current dirty list placement.
    list: InodeDirtyList,
    /// Number of dirty pages.
    dirty_pages: u64,
    /// Timestamp when inode first became dirty (tick counter).
    dirtied_when: u64,
    /// Whether writeback is currently in progress for this inode.
    writeback_active: bool,
    /// Number of pages written so far in current writeback pass.
    pages_written: u64,
    /// Whether this slot is in use.
    in_use: bool,
}

impl DirtyInode {
    /// Create an empty, unused slot.
    const fn empty() -> Self {
        Self {
            inode: 0,
            device_id: 0,
            list: InodeDirtyList::Clean,
            dirty_pages: 0,
            dirtied_when: 0,
            writeback_active: false,
            pages_written: 0,
            in_use: false,
        }
    }
}

// ── Writeback work item ──────────────────────────────────────────────────────

/// Reason for initiating writeback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WbReason {
    /// Background writeback due to dirty page threshold.
    Background,
    /// Explicit sync(2) or fsync(2) call.
    Sync,
    /// Memory pressure from the page allocator.
    MemoryPressure,
    /// Periodic timer expiry.
    Periodic,
    /// Filesystem-initiated (e.g., unmount).
    FsRequest,
    /// Laptop mode writeback.
    LaptopTimer,
}

/// A writeback work item.
///
/// Describes a unit of writeback work to be processed by a BDI worker.
struct WbWorkItem {
    /// Sync mode for this work item.
    sync_mode: WbSyncMode,
    /// Reason this writeback was triggered.
    reason: WbReason,
    /// Target number of pages to write.
    nr_pages: u64,
    /// Specific inode to writeback (0 = all dirty inodes).
    inode: u64,
    /// Device/BDI to target.
    device_id: u32,
    /// Whether to writeback all inodes older than a threshold.
    for_kupdate: bool,
    /// Age threshold in ticks (only writeback inodes dirtied before this).
    older_than: u64,
    /// Pages actually written.
    pages_done: u64,
    /// Whether this slot is in use.
    in_use: bool,
}

impl WbWorkItem {
    /// Create an empty, unused work item.
    const fn empty() -> Self {
        Self {
            sync_mode: WbSyncMode::None,
            reason: WbReason::Background,
            nr_pages: 0,
            inode: 0,
            device_id: 0,
            for_kupdate: false,
            older_than: 0,
            pages_done: 0,
            in_use: false,
        }
    }
}

// ── BDI writeback worker ─────────────────────────────────────────────────────

/// Per-BDI writeback worker state.
///
/// Each backing device (block device, NFS server, etc.) has its own
/// writeback worker that processes work items and manages the dirty
/// inode lists.
struct BdiWriteback {
    /// Device/BDI identifier.
    device_id: u32,
    /// Whether the worker is active.
    active: bool,
    /// Current tick counter for timing.
    current_tick: u64,
    /// Last writeback timer fire tick.
    last_timer_tick: u64,
    /// Total pages written by this worker.
    pages_written: u64,
    /// Whether this slot is in use.
    in_use: bool,
}

impl BdiWriteback {
    /// Create an empty, unused BDI worker slot.
    const fn empty() -> Self {
        Self {
            device_id: 0,
            active: false,
            current_tick: 0,
            last_timer_tick: 0,
            pages_written: 0,
            in_use: false,
        }
    }
}

// ── Writeback control ────────────────────────────────────────────────────────

/// Control parameters passed to filesystem writeback callbacks.
#[derive(Debug, Clone, Copy)]
pub struct WritebackControl {
    /// Sync mode.
    pub sync_mode: WbSyncMode,
    /// Maximum number of pages to write.
    pub nr_to_write: u64,
    /// Pages actually written (output).
    pub pages_written: u64,
    /// Range start offset (bytes). `0` for "from the beginning".
    pub range_start: u64,
    /// Range end offset (bytes). `u64::MAX` for "to the end".
    pub range_end: u64,
    /// Skip pages that are currently under writeback.
    pub skip_writeback: bool,
    /// Only write pages older than this tick.
    pub older_than: u64,
}

impl WritebackControl {
    /// Create a new writeback control for background writeback.
    pub const fn background(nr_pages: u64) -> Self {
        Self {
            sync_mode: WbSyncMode::None,
            nr_to_write: nr_pages,
            pages_written: 0,
            range_start: 0,
            range_end: u64::MAX,
            skip_writeback: true,
            older_than: 0,
        }
    }

    /// Create a new writeback control for synchronous writeback.
    pub const fn sync_all() -> Self {
        Self {
            sync_mode: WbSyncMode::All,
            nr_to_write: u64::MAX,
            pages_written: 0,
            range_start: 0,
            range_end: u64::MAX,
            skip_writeback: false,
            older_than: 0,
        }
    }

    /// Create a writeback control for a specific byte range.
    pub const fn range(start: u64, end: u64) -> Self {
        Self {
            sync_mode: WbSyncMode::All,
            nr_to_write: u64::MAX,
            pages_written: 0,
            range_start: start,
            range_end: end,
            skip_writeback: false,
            older_than: 0,
        }
    }
}

// ── Statistics ───────────────────────────────────────────────────────────────

/// Writeback subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct WritebackStats {
    /// Total pages written back.
    pub pages_written: u64,
    /// Background writeback invocations.
    pub bg_writeback: u64,
    /// Sync writeback invocations.
    pub sync_writeback: u64,
    /// Number of balance_dirty_pages throttle events.
    pub throttle_events: u64,
    /// Work items processed.
    pub work_items_processed: u64,
    /// Current global dirty page count.
    pub dirty_pages: u64,
    /// Current dirty pages under writeback.
    pub writeback_pages: u64,
}

impl WritebackStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            pages_written: 0,
            bg_writeback: 0,
            sync_writeback: 0,
            throttle_events: 0,
            work_items_processed: 0,
            dirty_pages: 0,
            writeback_pages: 0,
        }
    }
}

// ── Writeback manager ────────────────────────────────────────────────────────

/// The central writeback manager.
///
/// Coordinates dirty page tracking, writeback scheduling, and
/// process throttling across all devices.
pub struct WritebackManager {
    /// Dirty inode tracking table.
    inodes: [DirtyInode; MAX_DIRTY_INODES],
    /// Pending writeback work items.
    work_queue: [WbWorkItem; MAX_WORK_ITEMS],
    /// Per-BDI writeback workers.
    bdi_workers: [BdiWriteback; MAX_BDI_WORKERS],
    /// Dirty background ratio (percent).
    dirty_bg_ratio: u32,
    /// Dirty hard ratio (percent).
    dirty_ratio: u32,
    /// Total system memory in pages (for ratio calculations).
    total_memory_pages: u64,
    /// Current tick counter.
    current_tick: u64,
    /// Writeback timer interval in ticks.
    timer_interval: u64,
    /// Cumulative statistics.
    stats: WritebackStats,
}

impl WritebackManager {
    /// Create a new writeback manager.
    ///
    /// `total_memory_pages` is used for dirty ratio threshold computation.
    pub fn new(total_memory_pages: u64) -> Self {
        Self {
            inodes: [const { DirtyInode::empty() }; MAX_DIRTY_INODES],
            work_queue: [const { WbWorkItem::empty() }; MAX_WORK_ITEMS],
            bdi_workers: [const { BdiWriteback::empty() }; MAX_BDI_WORKERS],
            dirty_bg_ratio: DEFAULT_DIRTY_BG_RATIO,
            dirty_ratio: DEFAULT_DIRTY_RATIO,
            total_memory_pages,
            current_tick: 0,
            timer_interval: WB_TIMER_INTERVAL_MS,
            stats: WritebackStats::new(),
        }
    }

    // ── Configuration ────────────────────────────────────────────────────

    /// Set the dirty background ratio (percentage).
    pub fn set_dirty_bg_ratio(&mut self, ratio: u32) -> Result<()> {
        if ratio == 0 || ratio >= 100 {
            return Err(Error::InvalidArgument);
        }
        self.dirty_bg_ratio = ratio;
        Ok(())
    }

    /// Set the dirty hard ratio (percentage).
    pub fn set_dirty_ratio(&mut self, ratio: u32) -> Result<()> {
        if ratio == 0 || ratio >= 100 {
            return Err(Error::InvalidArgument);
        }
        self.dirty_ratio = ratio;
        Ok(())
    }

    /// Return the dirty background threshold in pages.
    pub fn dirty_bg_threshold(&self) -> u64 {
        self.total_memory_pages * self.dirty_bg_ratio as u64 / 100
    }

    /// Return the dirty hard threshold in pages.
    pub fn dirty_threshold(&self) -> u64 {
        self.total_memory_pages * self.dirty_ratio as u64 / 100
    }

    // ── BDI worker management ────────────────────────────────────────────

    /// Register a BDI writeback worker for a device.
    pub fn register_bdi(&mut self, device_id: u32) -> Result<()> {
        // Check for duplicate.
        if self
            .bdi_workers
            .iter()
            .any(|w| w.in_use && w.device_id == device_id)
        {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .bdi_workers
            .iter_mut()
            .find(|w| !w.in_use)
            .ok_or(Error::OutOfMemory)?;

        slot.device_id = device_id;
        slot.active = true;
        slot.current_tick = self.current_tick;
        slot.last_timer_tick = self.current_tick;
        slot.pages_written = 0;
        slot.in_use = true;
        Ok(())
    }

    /// Unregister a BDI writeback worker.
    pub fn unregister_bdi(&mut self, device_id: u32) -> Result<()> {
        let slot = self
            .bdi_workers
            .iter_mut()
            .find(|w| w.in_use && w.device_id == device_id)
            .ok_or(Error::NotFound)?;
        slot.in_use = false;
        Ok(())
    }

    // ── Dirty inode management ───────────────────────────────────────────

    /// Mark an inode as dirty (add to the dirty list).
    pub fn mark_inode_dirty(
        &mut self,
        inode: u64,
        device_id: u32,
        nr_dirty_pages: u64,
    ) -> Result<()> {
        // Check if already tracked.
        for entry in &mut self.inodes {
            if entry.in_use && entry.inode == inode && entry.device_id == device_id {
                entry.dirty_pages = entry.dirty_pages.saturating_add(nr_dirty_pages);
                if entry.list == InodeDirtyList::Clean {
                    entry.list = InodeDirtyList::Dirty;
                    entry.dirtied_when = self.current_tick;
                }
                self.stats.dirty_pages = self.stats.dirty_pages.saturating_add(nr_dirty_pages);
                return Ok(());
            }
        }

        // Allocate a new entry.
        let slot = self
            .inodes
            .iter_mut()
            .find(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;

        slot.inode = inode;
        slot.device_id = device_id;
        slot.list = InodeDirtyList::Dirty;
        slot.dirty_pages = nr_dirty_pages;
        slot.dirtied_when = self.current_tick;
        slot.writeback_active = false;
        slot.pages_written = 0;
        slot.in_use = true;

        self.stats.dirty_pages = self.stats.dirty_pages.saturating_add(nr_dirty_pages);
        Ok(())
    }

    /// Mark an inode as clean after successful writeback.
    pub fn mark_inode_clean(&mut self, inode: u64, device_id: u32) -> Result<()> {
        let entry = self
            .inodes
            .iter_mut()
            .find(|e| e.in_use && e.inode == inode && e.device_id == device_id)
            .ok_or(Error::NotFound)?;

        self.stats.dirty_pages = self.stats.dirty_pages.saturating_sub(entry.dirty_pages);
        entry.list = InodeDirtyList::Clean;
        entry.dirty_pages = 0;
        entry.writeback_active = false;
        entry.in_use = false;
        Ok(())
    }

    /// Move an inode from the dirty list to the I/O list.
    pub fn move_to_io(&mut self, inode: u64, device_id: u32) -> Result<()> {
        let entry = self
            .inodes
            .iter_mut()
            .find(|e| e.in_use && e.inode == inode && e.device_id == device_id)
            .ok_or(Error::NotFound)?;

        if entry.list != InodeDirtyList::Dirty {
            return Err(Error::InvalidArgument);
        }
        entry.list = InodeDirtyList::Io;
        entry.writeback_active = true;
        self.stats.writeback_pages = self.stats.writeback_pages.saturating_add(entry.dirty_pages);
        Ok(())
    }

    /// Move an inode to the more_io list (partial writeback).
    pub fn move_to_more_io(&mut self, inode: u64, device_id: u32) -> Result<()> {
        let entry = self
            .inodes
            .iter_mut()
            .find(|e| e.in_use && e.inode == inode && e.device_id == device_id)
            .ok_or(Error::NotFound)?;

        if entry.list != InodeDirtyList::Io {
            return Err(Error::InvalidArgument);
        }
        entry.list = InodeDirtyList::MoreIo;
        entry.writeback_active = false;
        Ok(())
    }

    /// Record that pages were written for an inode.
    pub fn record_pages_written(&mut self, inode: u64, device_id: u32, count: u64) -> Result<()> {
        let entry = self
            .inodes
            .iter_mut()
            .find(|e| e.in_use && e.inode == inode && e.device_id == device_id)
            .ok_or(Error::NotFound)?;

        entry.pages_written = entry.pages_written.saturating_add(count);
        entry.dirty_pages = entry.dirty_pages.saturating_sub(count);
        self.stats.pages_written = self.stats.pages_written.saturating_add(count);
        self.stats.writeback_pages = self.stats.writeback_pages.saturating_sub(count);
        self.stats.dirty_pages = self.stats.dirty_pages.saturating_sub(count);
        Ok(())
    }

    // ── Work item submission ─────────────────────────────────────────────

    /// Queue background writeback work.
    pub fn queue_background_work(&mut self, device_id: u32, nr_pages: u64) -> Result<()> {
        self.queue_work(
            WbSyncMode::None,
            WbReason::Background,
            device_id,
            nr_pages,
            0,
        )
    }

    /// Queue synchronous writeback work (sync/fsync).
    pub fn queue_sync_work(&mut self, device_id: u32, inode: u64) -> Result<()> {
        self.queue_work(WbSyncMode::All, WbReason::Sync, device_id, u64::MAX, inode)
    }

    /// Queue writeback due to memory pressure.
    pub fn queue_pressure_work(&mut self, device_id: u32, nr_pages: u64) -> Result<()> {
        self.queue_work(
            WbSyncMode::None,
            WbReason::MemoryPressure,
            device_id,
            nr_pages,
            0,
        )
    }

    /// Internal work-item queuing.
    fn queue_work(
        &mut self,
        sync_mode: WbSyncMode,
        reason: WbReason,
        device_id: u32,
        nr_pages: u64,
        inode: u64,
    ) -> Result<()> {
        let slot = self
            .work_queue
            .iter_mut()
            .find(|w| !w.in_use)
            .ok_or(Error::Busy)?;

        slot.sync_mode = sync_mode;
        slot.reason = reason;
        slot.device_id = device_id;
        slot.nr_pages = nr_pages;
        slot.inode = inode;
        slot.for_kupdate = reason == WbReason::Periodic;
        slot.older_than = if slot.for_kupdate {
            self.current_tick.saturating_sub(30)
        } else {
            0
        };
        slot.pages_done = 0;
        slot.in_use = true;

        match sync_mode {
            WbSyncMode::None => self.stats.bg_writeback += 1,
            WbSyncMode::All => self.stats.sync_writeback += 1,
        }
        Ok(())
    }

    // ── Writeback processing ─────────────────────────────────────────────

    /// Process pending writeback work items.
    ///
    /// Simulates the BDI writeback worker loop: dequeue a work item,
    /// move dirty inodes to the I/O list, and "write" pages.
    /// Returns the total number of pages written.
    pub fn process_work(&mut self) -> u64 {
        let mut total_written = 0u64;

        // Snapshot work items to avoid borrow issues.
        let mut work_snapshot: [(bool, u32, u64, u64, WbSyncMode); MAX_WORK_ITEMS] =
            [(false, 0, 0, 0, WbSyncMode::None); MAX_WORK_ITEMS];

        for (i, item) in self.work_queue.iter().enumerate() {
            if item.in_use {
                work_snapshot[i] = (
                    true,
                    item.device_id,
                    item.nr_pages,
                    item.inode,
                    item.sync_mode,
                );
            }
        }

        for (i, &(active, device_id, nr_pages, target_inode, _sync_mode)) in
            work_snapshot.iter().enumerate()
        {
            if !active {
                continue;
            }

            let mut pages_left = nr_pages.min(MAX_PAGES_PER_BATCH);
            let mut pages_done = 0u64;

            // Process dirty inodes for this device.
            for entry in &mut self.inodes {
                if pages_left == 0 {
                    break;
                }
                if !entry.in_use || entry.device_id != device_id {
                    continue;
                }
                if target_inode != 0 && entry.inode != target_inode {
                    continue;
                }
                if entry.list == InodeDirtyList::Clean {
                    continue;
                }

                let to_write = entry.dirty_pages.min(pages_left);
                entry.pages_written = entry.pages_written.saturating_add(to_write);
                entry.dirty_pages = entry.dirty_pages.saturating_sub(to_write);
                pages_done += to_write;
                pages_left = pages_left.saturating_sub(to_write);

                if entry.dirty_pages == 0 {
                    entry.list = InodeDirtyList::Clean;
                    entry.writeback_active = false;
                    entry.in_use = false;
                } else {
                    entry.list = InodeDirtyList::MoreIo;
                }
            }

            self.work_queue[i].pages_done = pages_done;
            self.work_queue[i].in_use = false;
            total_written += pages_done;
            self.stats.work_items_processed += 1;
        }

        self.stats.pages_written = self.stats.pages_written.saturating_add(total_written);
        self.stats.dirty_pages = self.stats.dirty_pages.saturating_sub(total_written);
        total_written
    }

    // ── Throttling ───────────────────────────────────────────────────────

    /// Check if a process should be throttled due to dirty page limits.
    ///
    /// Returns `true` if the caller should sleep before dirtying more
    /// pages (dirty pages exceed `dirty_ratio`).
    pub fn balance_dirty_pages(&mut self) -> bool {
        let threshold = self.dirty_threshold();
        if self.stats.dirty_pages > threshold {
            self.stats.throttle_events += 1;
            return true;
        }
        false
    }

    /// Check if background writeback should be triggered.
    ///
    /// Returns `true` if dirty pages exceed `dirty_background_ratio`.
    pub fn should_start_background_writeback(&self) -> bool {
        self.stats.dirty_pages > self.dirty_bg_threshold()
    }

    // ── Timer ────────────────────────────────────────────────────────────

    /// Advance the tick counter and check if the periodic writeback
    /// timer should fire.
    pub fn tick(&mut self, elapsed_ms: u64) -> bool {
        self.current_tick = self.current_tick.wrapping_add(elapsed_ms);
        let delta = self.current_tick.wrapping_sub(
            self.bdi_workers
                .iter()
                .filter(|w| w.in_use)
                .map(|w| w.last_timer_tick)
                .min()
                .unwrap_or(self.current_tick),
        );
        delta >= self.timer_interval
    }

    /// Fire the periodic writeback timer for all BDI workers.
    pub fn fire_timer(&mut self) {
        for worker in &mut self.bdi_workers {
            if worker.in_use {
                worker.last_timer_tick = self.current_tick;
            }
        }
    }

    // ── Queries ──────────────────────────────────────────────────────────

    /// Return the number of dirty inodes.
    pub fn dirty_inode_count(&self) -> usize {
        self.inodes
            .iter()
            .filter(|e| e.in_use && e.list != InodeDirtyList::Clean)
            .count()
    }

    /// Return the dirty page count for a specific inode.
    pub fn inode_dirty_pages(&self, inode: u64, device_id: u32) -> u64 {
        self.inodes
            .iter()
            .find(|e| e.in_use && e.inode == inode && e.device_id == device_id)
            .map(|e| e.dirty_pages)
            .unwrap_or(0)
    }

    /// Return current writeback statistics.
    pub fn stats(&self) -> WritebackStats {
        self.stats
    }

    /// Reset statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats = WritebackStats::new();
    }
}
