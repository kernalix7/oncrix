// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Swap writeback management.
//!
//! When dirty anonymous pages must be paged out, the writeback subsystem
//! batches them for efficient I/O to the swap device. This module tracks
//! pending writeback requests, manages the writeback queue, and enforces
//! throttling so the swap device is not overwhelmed.
//!
//! # Design
//!
//! ```text
//!  reclaim selects page
//!       │
//!       ▼
//!  SwapWritebackQueue::submit(page_pfn, slot)
//!       │
//!       ├─ queue full? → throttle caller
//!       │
//!       └─ queue entry ──▶ SwapWritebackWorker
//!                              │
//!                              ├─ batch I/O to swap device
//!                              └─ on completion → free page
//! ```
//!
//! # Key Types
//!
//! - [`WritebackEntry`] — a single page awaiting writeback
//! - [`SwapWritebackQueue`] — the writeback request queue
//! - [`WritebackStats`] — statistics for writeback activity
//!
//! Reference: Linux `mm/swap_state.c`, `mm/page-writeback.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum entries in the writeback queue.
const MAX_QUEUE_SIZE: usize = 1024;

/// Default batch size for grouped I/O.
const DEFAULT_BATCH: usize = 16;

/// Throttle threshold — queue usage fraction (numerator/256).
const THROTTLE_THRESHOLD: usize = 192; // 75%

// -------------------------------------------------------------------
// WritebackEntry
// -------------------------------------------------------------------

/// State of a writeback entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritebackState {
    /// Queued and waiting for I/O.
    Pending,
    /// I/O is in progress.
    InFlight,
    /// Writeback completed successfully.
    Completed,
    /// Writeback failed.
    Failed,
}

impl Default for WritebackState {
    fn default() -> Self {
        Self::Pending
    }
}

/// A single swap writeback request.
#[derive(Debug, Clone, Copy)]
pub struct WritebackEntry {
    /// Page frame number being written back.
    pfn: u64,
    /// Swap slot (device_id:offset).
    swap_slot: u64,
    /// Current state.
    state: WritebackState,
    /// Timestamp (tick counter) when queued.
    queued_at: u64,
}

impl WritebackEntry {
    /// Create a new pending writeback entry.
    pub const fn new(pfn: u64, swap_slot: u64, timestamp: u64) -> Self {
        Self {
            pfn,
            swap_slot,
            state: WritebackState::Pending,
            queued_at: timestamp,
        }
    }

    /// Return the page frame number.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the swap slot.
    pub const fn swap_slot(&self) -> u64 {
        self.swap_slot
    }

    /// Return the current state.
    pub const fn state(&self) -> WritebackState {
        self.state
    }

    /// Return when this entry was queued.
    pub const fn queued_at(&self) -> u64 {
        self.queued_at
    }

    /// Transition to in-flight.
    pub fn start_io(&mut self) {
        self.state = WritebackState::InFlight;
    }

    /// Mark as completed.
    pub fn complete(&mut self) {
        self.state = WritebackState::Completed;
    }

    /// Mark as failed.
    pub fn fail(&mut self) {
        self.state = WritebackState::Failed;
    }
}

impl Default for WritebackEntry {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// -------------------------------------------------------------------
// SwapWritebackQueue
// -------------------------------------------------------------------

/// Queue of pages pending swap writeback.
pub struct SwapWritebackQueue {
    /// Ring buffer of entries.
    entries: [WritebackEntry; MAX_QUEUE_SIZE],
    /// Write index (next insert position).
    head: usize,
    /// Read index (next process position).
    tail: usize,
    /// Number of entries currently in the queue.
    count: usize,
    /// Batch size for grouped I/O.
    batch_size: usize,
}

impl SwapWritebackQueue {
    /// Create a new empty queue.
    pub const fn new() -> Self {
        Self {
            entries: [const { WritebackEntry::new(0, 0, 0) }; MAX_QUEUE_SIZE],
            head: 0,
            tail: 0,
            count: 0,
            batch_size: DEFAULT_BATCH,
        }
    }

    /// Create a queue with a custom batch size.
    pub const fn with_batch_size(batch_size: usize) -> Self {
        Self {
            entries: [const { WritebackEntry::new(0, 0, 0) }; MAX_QUEUE_SIZE],
            head: 0,
            tail: 0,
            count: 0,
            batch_size,
        }
    }

    /// Return current queue depth.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Check whether the queue is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check whether the queue is full.
    pub const fn is_full(&self) -> bool {
        self.count >= MAX_QUEUE_SIZE
    }

    /// Check whether the caller should be throttled.
    pub const fn should_throttle(&self) -> bool {
        (self.count * 256 / MAX_QUEUE_SIZE) >= THROTTLE_THRESHOLD
    }

    /// Submit a page for writeback.
    pub fn submit(&mut self, pfn: u64, swap_slot: u64, timestamp: u64) -> Result<()> {
        if self.is_full() {
            return Err(Error::WouldBlock);
        }
        self.entries[self.head] = WritebackEntry::new(pfn, swap_slot, timestamp);
        self.head = (self.head + 1) % MAX_QUEUE_SIZE;
        self.count += 1;
        Ok(())
    }

    /// Dequeue the next pending entry for I/O.
    pub fn dequeue(&mut self) -> Option<WritebackEntry> {
        if self.is_empty() {
            return None;
        }
        let entry = self.entries[self.tail];
        self.tail = (self.tail + 1) % MAX_QUEUE_SIZE;
        self.count -= 1;
        Some(entry)
    }

    /// Dequeue up to `batch_size` entries at once.
    pub fn dequeue_batch(&mut self, out: &mut [WritebackEntry]) -> usize {
        let to_take = self.count.min(self.batch_size).min(out.len());
        for slot in out.iter_mut().take(to_take) {
            if let Some(entry) = self.dequeue() {
                *slot = entry;
            }
        }
        to_take
    }

    /// Drain all completed/failed entries and return count removed.
    pub fn drain_completed(&mut self) -> usize {
        // Simple compaction: we only track queue bounds, so completed
        // entries are naturally dequeued in order. This returns 0
        // as our ring buffer already removes entries on dequeue.
        0
    }
}

impl Default for SwapWritebackQueue {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// WritebackStats
// -------------------------------------------------------------------

/// Statistics for swap writeback activity.
#[derive(Debug, Clone, Copy)]
pub struct WritebackStats {
    /// Total pages submitted for writeback.
    pub submitted: u64,
    /// Total pages successfully written back.
    pub completed: u64,
    /// Total pages that failed writeback.
    pub failed: u64,
    /// Total times a caller was throttled.
    pub throttle_count: u64,
}

impl WritebackStats {
    /// Create zero-initialised stats.
    pub const fn new() -> Self {
        Self {
            submitted: 0,
            completed: 0,
            failed: 0,
            throttle_count: 0,
        }
    }

    /// Record a successful submission.
    pub fn record_submit(&mut self) {
        self.submitted += 1;
    }

    /// Record a completed writeback.
    pub fn record_complete(&mut self) {
        self.completed += 1;
    }

    /// Record a failed writeback.
    pub fn record_failure(&mut self) {
        self.failed += 1;
    }

    /// Record a throttle event.
    pub fn record_throttle(&mut self) {
        self.throttle_count += 1;
    }

    /// Return the success rate as a percentage (0-100).
    pub const fn success_rate(&self) -> u64 {
        if self.submitted == 0 {
            return 100;
        }
        self.completed * 100 / self.submitted
    }
}

impl Default for WritebackStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Submit a page for swap writeback, recording stats.
pub fn submit_writeback(
    queue: &mut SwapWritebackQueue,
    stats: &mut WritebackStats,
    pfn: u64,
    swap_slot: u64,
    timestamp: u64,
) -> Result<()> {
    if queue.should_throttle() {
        stats.record_throttle();
        return Err(Error::WouldBlock);
    }
    queue.submit(pfn, swap_slot, timestamp)?;
    stats.record_submit();
    Ok(())
}

/// Process the next batch of writeback entries.
///
/// Returns the number of entries processed.
pub fn process_writeback_batch(
    queue: &mut SwapWritebackQueue,
    stats: &mut WritebackStats,
) -> usize {
    let mut buf = [WritebackEntry::default(); 64];
    let limit = buf.len();
    let count = queue.dequeue_batch(&mut buf[..limit]);
    for entry in buf.iter().take(count) {
        // In a real implementation this would issue I/O.
        let _ = entry.pfn();
        stats.record_complete();
    }
    count
}

/// Return a human-readable description of writeback stats.
pub fn writeback_summary(stats: &WritebackStats) -> &'static str {
    if stats.submitted == 0 {
        "swap writeback: idle"
    } else if stats.failed > 0 {
        "swap writeback: active (errors present)"
    } else {
        "swap writeback: active (healthy)"
    }
}
