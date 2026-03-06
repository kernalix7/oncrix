// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Lock contention statistics.
//!
//! Collects and reports statistics about lock acquisitions, hold times,
//! and contention events. Helps identify hot locks and potential
//! scalability bottlenecks. Each tracked lock records acquisition
//! counts, wait times, and hold times.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of tracked locks.
const MAX_TRACKED_LOCKS: usize = 256;

/// Maximum contention events in the ring buffer.
const MAX_CONTENTION_EVENTS: usize = 512;

/// Lock name maximum length.
const MAX_LOCK_NAME_LEN: usize = 48;

// ── Types ────────────────────────────────────────────────────────────

/// Identifies a tracked lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockStatId(u64);

impl LockStatId {
    /// Creates a new lock stat identifier.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw identifier.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Type of lock being tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockType {
    /// Spinlock.
    Spinlock,
    /// Mutex.
    Mutex,
    /// Read-write lock (reader).
    RwLockRead,
    /// Read-write lock (writer).
    RwLockWrite,
    /// Semaphore.
    Semaphore,
}

impl Default for LockType {
    fn default() -> Self {
        Self::Spinlock
    }
}

/// Per-lock statistics record.
#[derive(Debug, Clone)]
pub struct LockStatRecord {
    /// Lock identifier.
    id: LockStatId,
    /// Lock type.
    lock_type: LockType,
    /// Lock name.
    name: [u8; MAX_LOCK_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Total acquisition count.
    acquisitions: u64,
    /// Total contention count (acquisition had to wait).
    contentions: u64,
    /// Total wait time in nanoseconds.
    total_wait_ns: u64,
    /// Maximum wait time in nanoseconds.
    max_wait_ns: u64,
    /// Total hold time in nanoseconds.
    total_hold_ns: u64,
    /// Maximum hold time in nanoseconds.
    max_hold_ns: u64,
    /// Whether tracking is active.
    active: bool,
}

impl LockStatRecord {
    /// Creates a new lock stat record.
    pub const fn new(id: LockStatId, lock_type: LockType) -> Self {
        Self {
            id,
            lock_type,
            name: [0u8; MAX_LOCK_NAME_LEN],
            name_len: 0,
            acquisitions: 0,
            contentions: 0,
            total_wait_ns: 0,
            max_wait_ns: 0,
            total_hold_ns: 0,
            max_hold_ns: 0,
            active: true,
        }
    }

    /// Returns the acquisition count.
    pub const fn acquisitions(&self) -> u64 {
        self.acquisitions
    }

    /// Returns the contention count.
    pub const fn contentions(&self) -> u64 {
        self.contentions
    }

    /// Returns the contention ratio (contentions / acquisitions).
    pub fn contention_ratio(&self) -> f64 {
        if self.acquisitions == 0 {
            return 0.0;
        }
        self.contentions as f64 / self.acquisitions as f64
    }
}

/// A contention event record.
#[derive(Debug, Clone)]
pub struct ContentionEvent {
    /// Lock that was contended.
    lock_id: LockStatId,
    /// Wait time in nanoseconds.
    wait_ns: u64,
    /// CPU that waited.
    cpu: u32,
    /// PID of waiting task.
    pid: u64,
    /// Timestamp of the event.
    timestamp_ns: u64,
}

impl ContentionEvent {
    /// Creates a new contention event.
    pub const fn new(lock_id: LockStatId, wait_ns: u64, cpu: u32, pid: u64) -> Self {
        Self {
            lock_id,
            wait_ns,
            cpu,
            pid,
            timestamp_ns: 0,
        }
    }

    /// Returns the wait time in nanoseconds.
    pub const fn wait_ns(&self) -> u64 {
        self.wait_ns
    }
}

/// Aggregate lock statistics summary.
#[derive(Debug, Clone)]
pub struct LockStatSummary {
    /// Total tracked locks.
    pub total_locks: u32,
    /// Total acquisitions across all locks.
    pub total_acquisitions: u64,
    /// Total contentions across all locks.
    pub total_contentions: u64,
    /// Aggregate wait time in nanoseconds.
    pub total_wait_ns: u64,
    /// Aggregate hold time in nanoseconds.
    pub total_hold_ns: u64,
    /// Maximum single wait time observed.
    pub max_wait_ns: u64,
}

impl Default for LockStatSummary {
    fn default() -> Self {
        Self::new()
    }
}

impl LockStatSummary {
    /// Creates zeroed summary.
    pub const fn new() -> Self {
        Self {
            total_locks: 0,
            total_acquisitions: 0,
            total_contentions: 0,
            total_wait_ns: 0,
            total_hold_ns: 0,
            max_wait_ns: 0,
        }
    }
}

/// Central lock statistics collector.
#[derive(Debug)]
pub struct LockStatCollector {
    /// Tracked lock records.
    locks: [Option<LockStatRecord>; MAX_TRACKED_LOCKS],
    /// Contention event ring buffer.
    events: [Option<ContentionEvent>; MAX_CONTENTION_EVENTS],
    /// Event ring write position.
    event_pos: usize,
    /// Number of tracked locks.
    lock_count: usize,
    /// Next lock identifier.
    next_id: u64,
    /// Whether collection is globally enabled.
    enabled: bool,
}

impl Default for LockStatCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl LockStatCollector {
    /// Creates a new lock stat collector.
    pub const fn new() -> Self {
        Self {
            locks: [const { None }; MAX_TRACKED_LOCKS],
            events: [const { None }; MAX_CONTENTION_EVENTS],
            event_pos: 0,
            lock_count: 0,
            next_id: 1,
            enabled: false,
        }
    }

    /// Enables lock statistics collection.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disables lock statistics collection.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Returns whether collection is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Registers a lock for tracking.
    pub fn register_lock(&mut self, lock_type: LockType) -> Result<LockStatId> {
        if self.lock_count >= MAX_TRACKED_LOCKS {
            return Err(Error::OutOfMemory);
        }
        let id = LockStatId::new(self.next_id);
        self.next_id += 1;
        let record = LockStatRecord::new(id, lock_type);
        if let Some(slot) = self.locks.iter_mut().find(|s| s.is_none()) {
            *slot = Some(record);
            self.lock_count += 1;
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Records a lock acquisition.
    pub fn record_acquire(
        &mut self,
        lock_id: LockStatId,
        wait_ns: u64,
        hold_ns: u64,
        contended: bool,
        cpu: u32,
        pid: u64,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let record = self
            .locks
            .iter_mut()
            .flatten()
            .find(|r| r.id == lock_id)
            .ok_or(Error::NotFound)?;
        record.acquisitions += 1;
        record.total_hold_ns += hold_ns;
        if hold_ns > record.max_hold_ns {
            record.max_hold_ns = hold_ns;
        }
        if contended {
            record.contentions += 1;
            record.total_wait_ns += wait_ns;
            if wait_ns > record.max_wait_ns {
                record.max_wait_ns = wait_ns;
            }
            let event = ContentionEvent::new(lock_id, wait_ns, cpu, pid);
            self.events[self.event_pos] = Some(event);
            self.event_pos = (self.event_pos + 1) % MAX_CONTENTION_EVENTS;
        }
        Ok(())
    }

    /// Unregisters a lock from tracking.
    pub fn unregister_lock(&mut self, lock_id: LockStatId) -> Result<()> {
        let slot = self
            .locks
            .iter_mut()
            .find(|s| s.as_ref().map_or(false, |r| r.id == lock_id))
            .ok_or(Error::NotFound)?;
        *slot = None;
        self.lock_count -= 1;
        Ok(())
    }

    /// Resets all statistics for all tracked locks.
    pub fn reset_all(&mut self) {
        for record in self.locks.iter_mut().flatten() {
            record.acquisitions = 0;
            record.contentions = 0;
            record.total_wait_ns = 0;
            record.max_wait_ns = 0;
            record.total_hold_ns = 0;
            record.max_hold_ns = 0;
        }
        for slot in self.events.iter_mut() {
            *slot = None;
        }
        self.event_pos = 0;
    }

    /// Returns aggregate statistics summary.
    pub fn summary(&self) -> LockStatSummary {
        let mut s = LockStatSummary::new();
        for record in self.locks.iter().flatten() {
            s.total_locks += 1;
            s.total_acquisitions += record.acquisitions;
            s.total_contentions += record.contentions;
            s.total_wait_ns += record.total_wait_ns;
            s.total_hold_ns += record.total_hold_ns;
            if record.max_wait_ns > s.max_wait_ns {
                s.max_wait_ns = record.max_wait_ns;
            }
        }
        s
    }

    /// Returns the number of tracked locks.
    pub const fn lock_count(&self) -> usize {
        self.lock_count
    }
}
