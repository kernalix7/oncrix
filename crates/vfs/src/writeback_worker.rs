// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Writeback worker — background dirty-page and dirty-inode flusher.
//!
//! Manages a pool of writeback work items and expiry-based flush scheduling,
//! mirroring the Linux `bdi_writeback` / `wb_workfn` model.

use oncrix_lib::{Error, Result};

/// Maximum number of pending writeback items.
pub const MAX_WB_ITEMS: usize = 256;

/// Maximum number of registered writeback queues (one per backing device).
pub const MAX_WB_QUEUES: usize = 16;

/// Reason a writeback was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WbReason {
    /// Periodic background flush.
    Background,
    /// `sync()` / `fsync()` call.
    Sync,
    /// Memory pressure — shrink dirty pages.
    MemoryPressure,
    /// Dirty ratio exceeded.
    DirtyRatio,
    /// Explicit `pdflush`-style wake.
    Wakeup,
}

/// State of a single writeback work item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WbItemState {
    /// Free / unused slot.
    Free,
    /// Queued, waiting to be processed.
    Queued,
    /// Currently being written back.
    InProgress,
    /// Completed (success or error).
    Done,
}

/// A single writeback work item.
#[derive(Debug, Clone, Copy)]
pub struct WbItem {
    /// Superblock ID of the filesystem owning the dirty data.
    pub sb_id: u64,
    /// Inode number to write back (`0` = write all inodes for this sb).
    pub ino: u64,
    /// Number of pages to write (0 = unlimited / sync all).
    pub nr_pages: u32,
    /// Reason this writeback was requested.
    pub reason: WbReason,
    /// Wall-clock time when this item was enqueued (seconds).
    pub queued_at: i64,
    /// State of this item.
    pub state: WbItemState,
    /// Result code (0 = OK, negative = error).
    pub result: i32,
}

impl WbItem {
    /// Create a free (empty) item.
    const fn free() -> Self {
        Self {
            sb_id: 0,
            ino: 0,
            nr_pages: 0,
            reason: WbReason::Background,
            queued_at: 0,
            state: WbItemState::Free,
            result: 0,
        }
    }
}

/// Configuration for writeback behaviour.
#[derive(Debug, Clone, Copy)]
pub struct WbConfig {
    /// Minimum dirty age before background writeback triggers (seconds).
    pub dirty_expire_secs: u32,
    /// Writeback interval for periodic flush (seconds).
    pub writeback_interval_secs: u32,
    /// Maximum pages to write per work item run.
    pub max_pages_per_run: u32,
}

impl Default for WbConfig {
    fn default() -> Self {
        Self {
            dirty_expire_secs: 30,
            writeback_interval_secs: 5,
            max_pages_per_run: 1024,
        }
    }
}

/// Statistics for a writeback queue.
#[derive(Debug, Clone, Copy, Default)]
pub struct WbStats {
    /// Total pages written.
    pub pages_written: u64,
    /// Total inodes written.
    pub inodes_written: u64,
    /// Total writeback runs completed.
    pub runs: u64,
    /// Total errors during writeback.
    pub errors: u64,
    /// Number of items currently queued.
    pub queued: u32,
}

/// A writeback queue for a single backing device / filesystem.
pub struct WbQueue {
    /// Backing device identifier (e.g., block device number).
    pub dev: u64,
    items: [WbItem; MAX_WB_ITEMS],
    head: usize,
    tail: usize,
    count: usize,
    pub config: WbConfig,
    pub stats: WbStats,
}

impl WbQueue {
    /// Create an empty writeback queue for the given device.
    pub fn new(dev: u64) -> Self {
        Self {
            dev,
            items: [const { WbItem::free() }; MAX_WB_ITEMS],
            head: 0,
            tail: 0,
            count: 0,
            config: WbConfig::default(),
            stats: WbStats::default(),
        }
    }

    /// Enqueue a new writeback item.
    pub fn enqueue(&mut self, item: WbItem) -> Result<()> {
        if self.count >= MAX_WB_ITEMS {
            return Err(Error::OutOfMemory);
        }
        self.items[self.tail] = item;
        self.items[self.tail].state = WbItemState::Queued;
        self.tail = (self.tail + 1) % MAX_WB_ITEMS;
        self.count += 1;
        self.stats.queued += 1;
        Ok(())
    }

    /// Dequeue the next item (FIFO order).
    pub fn dequeue(&mut self) -> Option<&mut WbItem> {
        if self.count == 0 {
            return None;
        }
        let item = &mut self.items[self.head];
        item.state = WbItemState::InProgress;
        self.head = (self.head + 1) % MAX_WB_ITEMS;
        self.count -= 1;
        self.stats.queued = self.stats.queued.saturating_sub(1);
        Some(item)
    }

    /// Report completion of an item (called by the writeback engine after I/O).
    pub fn complete(&mut self, pages: u64, inodes: u64, error: bool) {
        self.stats.pages_written += pages;
        self.stats.inodes_written += inodes;
        self.stats.runs += 1;
        if error {
            self.stats.errors += 1;
        }
    }

    /// Return number of items currently queued.
    pub fn queued_count(&self) -> usize {
        self.count
    }

    /// Return whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Drain all items for a given superblock (called on unmount).
    pub fn drain_super(&mut self, sb_id: u64) {
        for item in self.items.iter_mut() {
            if item.sb_id == sb_id && item.state == WbItemState::Queued {
                *item = WbItem::free();
                self.count = self.count.saturating_sub(1);
                self.stats.queued = self.stats.queued.saturating_sub(1);
            }
        }
    }
}

/// The global writeback worker controller.
pub struct WritebackWorker {
    queues: [Option<WbQueue>; MAX_WB_QUEUES],
    queue_count: usize,
    /// Last time the periodic flush ran (seconds since epoch).
    pub last_flush: i64,
}

impl WritebackWorker {
    /// Create an empty writeback worker.
    pub const fn new() -> Self {
        Self {
            queues: [const { None }; MAX_WB_QUEUES],
            queue_count: 0,
            last_flush: 0,
        }
    }

    /// Register a writeback queue for a device.
    pub fn register(&mut self, dev: u64) -> Result<()> {
        if self.queue_count >= MAX_WB_QUEUES {
            return Err(Error::OutOfMemory);
        }
        for slot in self.queues.iter_mut() {
            if slot.is_none() {
                *slot = Some(WbQueue::new(dev));
                self.queue_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister the writeback queue for a device.
    pub fn unregister(&mut self, dev: u64) -> Result<()> {
        for slot in self.queues.iter_mut() {
            if let Some(q) = slot {
                if q.dev == dev {
                    *slot = None;
                    self.queue_count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Submit a writeback item for a filesystem on a device.
    pub fn submit(
        &mut self,
        dev: u64,
        sb_id: u64,
        ino: u64,
        nr_pages: u32,
        reason: WbReason,
        now: i64,
    ) -> Result<()> {
        let queue = self.find_queue_mut(dev)?;
        let item = WbItem {
            sb_id,
            ino,
            nr_pages,
            reason,
            queued_at: now,
            state: WbItemState::Queued,
            result: 0,
        };
        queue.enqueue(item)
    }

    /// Run one step of the writeback worker for `dev`, processing up to
    /// `max_items` queued items.
    ///
    /// The `write_fn` callback performs the actual I/O:
    /// ```ignore
    /// fn write_fn(item: &WbItem) -> Result<(u64, u64)>
    /// // Returns (pages_written, inodes_written) on success.
    /// ```
    pub fn run_step<F>(&mut self, dev: u64, max_items: usize, mut write_fn: F) -> Result<()>
    where
        F: FnMut(&WbItem) -> Result<(u64, u64)>,
    {
        let queue = self.find_queue_mut(dev)?;
        let mut processed = 0;
        while processed < max_items {
            let item_copy = match queue.dequeue() {
                None => break,
                Some(item) => *item,
            };
            match write_fn(&item_copy) {
                Ok((pages, inodes)) => queue.complete(pages, inodes, false),
                Err(_) => queue.complete(0, 0, true),
            }
            processed += 1;
        }
        Ok(())
    }

    fn find_queue_mut(&mut self, dev: u64) -> Result<&mut WbQueue> {
        for slot in self.queues.iter_mut() {
            if let Some(q) = slot {
                if q.dev == dev {
                    return Ok(q);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Return aggregate stats across all registered queues.
    pub fn aggregate_stats(&self) -> WbStats {
        let mut agg = WbStats::default();
        for slot in self.queues.iter() {
            if let Some(q) = slot {
                agg.pages_written += q.stats.pages_written;
                agg.inodes_written += q.stats.inodes_written;
                agg.runs += q.stats.runs;
                agg.errors += q.stats.errors;
                agg.queued += q.stats.queued;
            }
        }
        agg
    }
}

impl Default for WritebackWorker {
    fn default() -> Self {
        Self::new()
    }
}
