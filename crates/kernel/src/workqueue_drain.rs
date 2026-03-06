// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Workqueue drain — orderly workqueue flush and drain operations.
//!
//! Provides the mechanism to flush all pending work items on a
//! workqueue (wait for completion) or drain the workqueue (flush
//! and ensure no new items are queued). Used during module unload,
//! device removal, and orderly shutdown.
//!
//! # Architecture
//!
//! ```text
//! WorkqueueDrain
//!  ├── queues[MAX_DRAIN_QUEUES]
//!  │    ├── id, name, state: DrainState
//!  │    ├── pending_count, flushing
//!  │    └── drain_waiters
//!  └── stats: DrainStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/workqueue.c` — `drain_workqueue()`, `flush_workqueue()`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum drainable workqueues.
const MAX_DRAIN_QUEUES: usize = 64;

/// Maximum name length.
const MAX_NAME_LEN: usize = 32;

// ══════════════════════════════════════════════════════════════
// DrainState
// ══════════════════════════════════════════════════════════════

/// State of a drainable workqueue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DrainState {
    /// Slot is free.
    Free = 0,
    /// Normal operation — accepting new work.
    Active = 1,
    /// Flushing — waiting for pending work to complete.
    Flushing = 2,
    /// Draining — flushing + rejecting new work.
    Draining = 3,
    /// Drained — no pending work, no new work accepted.
    Drained = 4,
}

// ══════════════════════════════════════════════════════════════
// DrainableQueue
// ══════════════════════════════════════════════════════════════

/// A workqueue with drain support.
#[derive(Clone, Copy)]
pub struct DrainableQueue {
    /// Queue identifier.
    pub id: u32,
    /// Queue name.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Current state.
    pub state: DrainState,
    /// Number of pending (not yet started) work items.
    pub pending_count: u32,
    /// Number of currently executing work items.
    pub active_count: u32,
    /// Number of tasks waiting for drain/flush completion.
    pub drain_waiters: u32,
    /// Total items flushed.
    pub total_flushed: u64,
    /// Total items processed.
    pub total_processed: u64,
    /// Flush generation counter.
    pub flush_generation: u64,
}

impl DrainableQueue {
    /// Create a free queue slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            state: DrainState::Free,
            pending_count: 0,
            active_count: 0,
            drain_waiters: 0,
            total_flushed: 0,
            total_processed: 0,
            flush_generation: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// DrainStats
// ══════════════════════════════════════════════════════════════

/// Drain subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct DrainStats {
    /// Total flush operations.
    pub total_flushes: u64,
    /// Total drain operations.
    pub total_drains: u64,
    /// Total work items rejected during drain.
    pub total_rejected: u64,
    /// Total queues created.
    pub total_created: u64,
}

impl DrainStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_flushes: 0,
            total_drains: 0,
            total_rejected: 0,
            total_created: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// WorkqueueDrain
// ══════════════════════════════════════════════════════════════

/// Manages workqueue flush and drain operations.
pub struct WorkqueueDrain {
    /// Queue table.
    queues: [DrainableQueue; MAX_DRAIN_QUEUES],
    /// Next queue ID.
    next_id: u32,
    /// Statistics.
    stats: DrainStats,
}

impl WorkqueueDrain {
    /// Create a new drain manager.
    pub const fn new() -> Self {
        Self {
            queues: [const { DrainableQueue::empty() }; MAX_DRAIN_QUEUES],
            next_id: 1,
            stats: DrainStats::new(),
        }
    }

    /// Register a workqueue for drain support.
    pub fn register_queue(&mut self, name: &[u8]) -> Result<u32> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .queues
            .iter()
            .position(|q| matches!(q.state, DrainState::Free))
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id += 1;
        let queue = &mut self.queues[slot];
        queue.id = id;
        queue.name[..name.len()].copy_from_slice(name);
        queue.name_len = name.len();
        queue.state = DrainState::Active;
        self.stats.total_created += 1;
        Ok(id)
    }

    /// Enqueue a work item. Fails if the queue is draining/drained.
    pub fn enqueue_work(&mut self, queue_id: u32) -> Result<()> {
        let slot = self.find_queue(queue_id)?;
        match self.queues[slot].state {
            DrainState::Active | DrainState::Flushing => {
                self.queues[slot].pending_count += 1;
                Ok(())
            }
            DrainState::Draining | DrainState::Drained => {
                self.stats.total_rejected += 1;
                Err(Error::Busy)
            }
            DrainState::Free => Err(Error::NotFound),
        }
    }

    /// Mark a work item as started (moved from pending to active).
    pub fn start_work(&mut self, queue_id: u32) -> Result<()> {
        let slot = self.find_queue(queue_id)?;
        if self.queues[slot].pending_count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.queues[slot].pending_count -= 1;
        self.queues[slot].active_count += 1;
        Ok(())
    }

    /// Mark a work item as completed.
    pub fn complete_work(&mut self, queue_id: u32) -> Result<()> {
        let slot = self.find_queue(queue_id)?;
        self.queues[slot].active_count = self.queues[slot].active_count.saturating_sub(1);
        self.queues[slot].total_processed += 1;

        // Check if flush/drain is complete.
        if self.queues[slot].pending_count == 0 && self.queues[slot].active_count == 0 {
            match self.queues[slot].state {
                DrainState::Flushing => {
                    self.queues[slot].state = DrainState::Active;
                    self.queues[slot].flush_generation += 1;
                    self.queues[slot].drain_waiters = 0;
                }
                DrainState::Draining => {
                    self.queues[slot].state = DrainState::Drained;
                    self.queues[slot].drain_waiters = 0;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Initiate a flush — wait for all current work to complete.
    /// New work can still be submitted.
    pub fn flush(&mut self, queue_id: u32) -> Result<()> {
        let slot = self.find_queue(queue_id)?;
        if !matches!(self.queues[slot].state, DrainState::Active) {
            return Err(Error::Busy);
        }
        if self.queues[slot].pending_count == 0 && self.queues[slot].active_count == 0 {
            // Already empty — no-op.
            self.queues[slot].flush_generation += 1;
            self.queues[slot].total_flushed += self.queues[slot].total_processed;
        } else {
            self.queues[slot].state = DrainState::Flushing;
            self.queues[slot].drain_waiters += 1;
        }
        self.stats.total_flushes += 1;
        Ok(())
    }

    /// Initiate a drain — flush + reject new work.
    pub fn drain(&mut self, queue_id: u32) -> Result<()> {
        let slot = self.find_queue(queue_id)?;
        if matches!(
            self.queues[slot].state,
            DrainState::Draining | DrainState::Drained
        ) {
            return Err(Error::Busy);
        }
        if self.queues[slot].pending_count == 0 && self.queues[slot].active_count == 0 {
            self.queues[slot].state = DrainState::Drained;
        } else {
            self.queues[slot].state = DrainState::Draining;
            self.queues[slot].drain_waiters += 1;
        }
        self.stats.total_drains += 1;
        Ok(())
    }

    /// Destroy a drained queue.
    pub fn destroy(&mut self, queue_id: u32) -> Result<()> {
        let slot = self.find_queue(queue_id)?;
        if !matches!(
            self.queues[slot].state,
            DrainState::Drained | DrainState::Active
        ) {
            return Err(Error::Busy);
        }
        if self.queues[slot].pending_count > 0 || self.queues[slot].active_count > 0 {
            return Err(Error::Busy);
        }
        self.queues[slot] = DrainableQueue::empty();
        Ok(())
    }

    /// Return queue info.
    pub fn get_queue(&self, queue_id: u32) -> Result<&DrainableQueue> {
        let slot = self.find_queue(queue_id)?;
        Ok(&self.queues[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> DrainStats {
        self.stats
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_queue(&self, id: u32) -> Result<usize> {
        self.queues
            .iter()
            .position(|q| !matches!(q.state, DrainState::Free) && q.id == id)
            .ok_or(Error::NotFound)
    }
}
