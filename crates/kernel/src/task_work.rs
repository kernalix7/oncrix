// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Task work queue — deferred work in task context.
//!
//! Implements a mechanism for scheduling work that runs in task
//! context just before returning to user space. This is used for
//! deferred signal delivery, file descriptor operations, and
//! other work that requires a process context but should not run
//! in the current system call path.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                     TaskWorkTable                             │
//! │                                                              │
//! │  TaskWorkQueue[0..MAX_TASK_QUEUES]  (per-PID queues)         │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  pid, entries [TaskWorkEntry; MAX_ENTRIES_PER_TASK]     │  │
//! │  │  head, pending_count                                   │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  TaskWorkStats (global counters)                             │
//! │  - total_added, total_executed, total_cancelled              │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Notification Model
//!
//! When task work is added, the caller specifies notification flags:
//!
//! - `NOTIFY_SIGNAL`: Set `TIF_NOTIFY_SIGNAL` on the target task
//!   so it wakes from interruptible sleep.
//! - `NOTIFY_RESUME`: Set `TIF_NOTIFY_RESUME` so the work runs
//!   before the next return to user space.
//!
//! # Execution
//!
//! `task_work_run(pid)` executes all pending entries in FIFO order
//! for the given PID. Entries are consumed (removed) after
//! execution. The return value indicates how many entries ran.
//!
//! # Reference
//!
//! Linux `kernel/task_work.c`, `include/linux/task_work.h`.

use oncrix_lib::{Error, Result};
use oncrix_process::pid::Pid;

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum entries per task's work queue.
const MAX_ENTRIES_PER_TASK: usize = 32;

/// Maximum per-PID queues in the table.
const MAX_TASK_QUEUES: usize = 256;

/// TIF flag: notify via signal.
const TIF_NOTIFY_SIGNAL: u32 = 1 << 0;

/// TIF flag: notify on return to user space.
const TIF_NOTIFY_RESUME: u32 = 1 << 1;

// ══════════════════════════════════════════════════════════════
// TaskWorkFlags
// ══════════════════════════════════════════════════════════════

/// Notification flags for task work entries.
///
/// Controls how the target task is notified that work is pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskWorkFlags(u32);

impl TaskWorkFlags {
    /// No notification — work will run on next voluntary check.
    pub const NONE: Self = Self(0);

    /// Set TIF_NOTIFY_SIGNAL to wake the task from sleep.
    pub const NOTIFY_SIGNAL: Self = Self(TIF_NOTIFY_SIGNAL);

    /// Set TIF_NOTIFY_RESUME for return-to-user notification.
    pub const NOTIFY_RESUME: Self = Self(TIF_NOTIFY_RESUME);

    /// Both signal and resume notification.
    pub const NOTIFY_BOTH: Self = Self(TIF_NOTIFY_SIGNAL | TIF_NOTIFY_RESUME);

    /// Create flags from a raw u32.
    pub const fn from_raw(val: u32) -> Self {
        Self(val)
    }

    /// Return the raw flags value.
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Check whether NOTIFY_SIGNAL is set.
    pub const fn has_signal(self) -> bool {
        (self.0 & TIF_NOTIFY_SIGNAL) != 0
    }

    /// Check whether NOTIFY_RESUME is set.
    pub const fn has_resume(self) -> bool {
        (self.0 & TIF_NOTIFY_RESUME) != 0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// ══════════════════════════════════════════════════════════════
// TaskWorkFn
// ══════════════════════════════════════════════════════════════

/// Callback identifier for task work.
///
/// In a full implementation, this would be a function pointer.
/// Here we use an index into a dispatch table to remain safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskWorkFn {
    /// Callback index into the dispatch table.
    pub callback_id: u32,
}

impl TaskWorkFn {
    /// Create a new callback reference.
    pub const fn new(callback_id: u32) -> Self {
        Self { callback_id }
    }
}

// ══════════════════════════════════════════════════════════════
// TaskWorkEntry
// ══════════════════════════════════════════════════════════════

/// A single deferred work entry in a task's queue.
///
/// Contains the callback to invoke, notification flags, an
/// opaque data payload, and linked-list metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskWorkEntry {
    /// Callback to invoke.
    pub callback_fn: TaskWorkFn,
    /// Notification flags.
    pub flags: TaskWorkFlags,
    /// Index of next entry in the queue (-1 = end).
    pub next_idx: i32,
    /// Opaque data passed to the callback.
    pub data: u64,
    /// Whether this entry is active (pending execution).
    pub active: bool,
    /// Unique entry identifier for cancellation.
    pub entry_id: u32,
    /// Tick at which this entry was added.
    pub enqueue_tick: u64,
}

impl TaskWorkEntry {
    /// Create an empty (inactive) entry.
    pub const fn new() -> Self {
        Self {
            callback_fn: TaskWorkFn::new(0),
            flags: TaskWorkFlags::NONE,
            next_idx: -1,
            data: 0,
            active: false,
            entry_id: 0,
            enqueue_tick: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TaskWorkQueue
// ══════════════════════════════════════════════════════════════

/// Per-task work queue.
///
/// Maintains a FIFO queue of pending work entries for a single
/// task (identified by PID).
pub struct TaskWorkQueue {
    /// The PID this queue belongs to.
    pid: Pid,
    /// Work entries (fixed-size pool).
    entries: [TaskWorkEntry; MAX_ENTRIES_PER_TASK],
    /// Index of the head entry (-1 = empty).
    head: i32,
    /// Index of the tail entry (-1 = empty).
    tail: i32,
    /// Number of pending entries.
    pending_count: usize,
    /// Whether this queue slot is allocated.
    allocated: bool,
    /// TIF flags currently set on this task.
    tif_flags: u32,
    /// Next entry ID to assign.
    next_entry_id: u32,
    /// Total entries ever added.
    total_added: u64,
    /// Total entries ever executed.
    total_executed: u64,
    /// Total entries ever cancelled.
    total_cancelled: u64,
}

impl TaskWorkQueue {
    /// Create an empty unallocated queue.
    pub const fn new() -> Self {
        Self {
            pid: Pid::new(0),
            entries: [const { TaskWorkEntry::new() }; MAX_ENTRIES_PER_TASK],
            head: -1,
            tail: -1,
            pending_count: 0,
            allocated: false,
            tif_flags: 0,
            next_entry_id: 1,
            total_added: 0,
            total_executed: 0,
            total_cancelled: 0,
        }
    }

    /// Allocate this queue for a PID.
    pub fn allocate(&mut self, pid: Pid) {
        self.pid = pid;
        self.allocated = true;
        self.head = -1;
        self.tail = -1;
        self.pending_count = 0;
        self.tif_flags = 0;
        self.next_entry_id = 1;
    }

    /// Release this queue.
    pub fn release(&mut self) {
        self.allocated = false;
        self.head = -1;
        self.tail = -1;
        self.pending_count = 0;
        self.tif_flags = 0;
    }

    /// Return the PID.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Return the number of pending entries.
    pub fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Check whether there is pending work.
    pub fn has_pending(&self) -> bool {
        self.pending_count > 0
    }

    /// Return the current TIF flags.
    pub fn tif_flags(&self) -> u32 {
        self.tif_flags
    }

    /// Add a work entry to the queue.
    ///
    /// Returns the assigned entry ID.
    pub fn add(
        &mut self,
        callback_fn: TaskWorkFn,
        flags: TaskWorkFlags,
        data: u64,
        current_tick: u64,
    ) -> Result<u32> {
        if !self.allocated {
            return Err(Error::NotFound);
        }
        // Find a free slot
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        let entry_id = self.next_entry_id;
        self.next_entry_id = self.next_entry_id.wrapping_add(1);

        self.entries[slot] = TaskWorkEntry {
            callback_fn,
            flags,
            next_idx: -1,
            data,
            active: true,
            entry_id,
            enqueue_tick: current_tick,
        };

        // Append to linked list
        if self.tail >= 0 {
            let tail_idx = self.tail as usize;
            self.entries[tail_idx].next_idx = slot as i32;
        } else {
            self.head = slot as i32;
        }
        self.tail = slot as i32;

        self.pending_count += 1;
        self.total_added += 1;

        // Set TIF flags for notification
        if flags.has_signal() {
            self.tif_flags |= TIF_NOTIFY_SIGNAL;
        }
        if flags.has_resume() {
            self.tif_flags |= TIF_NOTIFY_RESUME;
        }

        Ok(entry_id)
    }

    /// Cancel a pending work entry by its entry ID.
    ///
    /// Returns `true` if the entry was found and cancelled.
    pub fn cancel(&mut self, entry_id: u32) -> Result<bool> {
        if !self.allocated {
            return Err(Error::NotFound);
        }

        // Find the entry and its predecessor
        let mut prev: i32 = -1;
        let mut current = self.head;

        while current >= 0 {
            let idx = current as usize;
            if self.entries[idx].entry_id == entry_id && self.entries[idx].active {
                // Unlink from list
                let next = self.entries[idx].next_idx;
                if prev >= 0 {
                    self.entries[prev as usize].next_idx = next;
                } else {
                    self.head = next;
                }
                if current == self.tail {
                    self.tail = prev;
                }

                self.entries[idx].active = false;
                self.entries[idx].next_idx = -1;
                self.pending_count = self.pending_count.saturating_sub(1);
                self.total_cancelled += 1;

                // Recalculate TIF flags
                self.recalculate_tif();
                return Ok(true);
            }
            prev = current;
            current = self.entries[idx].next_idx;
        }

        Ok(false)
    }

    /// Execute all pending work entries in FIFO order.
    ///
    /// Returns the number of entries executed. In a real
    /// implementation, each entry's callback would be invoked
    /// via the dispatch table.
    pub fn run(&mut self) -> Result<usize> {
        if !self.allocated {
            return Err(Error::NotFound);
        }

        let mut executed = 0usize;
        let mut current = self.head;

        while current >= 0 {
            let idx = current as usize;
            let next = self.entries[idx].next_idx;

            if self.entries[idx].active {
                // Execute the callback (stub — just mark as done)
                self.entries[idx].active = false;
                executed += 1;
                self.total_executed += 1;
            }

            self.entries[idx].next_idx = -1;
            current = next;
        }

        self.head = -1;
        self.tail = -1;
        self.pending_count = 0;
        self.tif_flags = 0;

        Ok(executed)
    }

    /// Recalculate TIF flags from remaining entries.
    fn recalculate_tif(&mut self) {
        let mut flags = 0u32;
        let mut current = self.head;
        while current >= 0 {
            let idx = current as usize;
            if self.entries[idx].active {
                flags |= self.entries[idx].flags.as_raw();
            }
            current = self.entries[idx].next_idx;
        }
        self.tif_flags = flags;
    }

    /// Return per-queue statistics.
    pub fn queue_stats(&self) -> (u64, u64, u64) {
        (self.total_added, self.total_executed, self.total_cancelled)
    }
}

// ══════════════════════════════════════════════════════════════
// TaskWorkStats
// ══════════════════════════════════════════════════════════════

/// Global statistics for the task work subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskWorkStats {
    /// Total entries added across all tasks.
    pub total_added: u64,
    /// Total entries executed across all tasks.
    pub total_executed: u64,
    /// Total entries cancelled across all tasks.
    pub total_cancelled: u64,
    /// Currently allocated task queues.
    pub queues_allocated: u32,
    /// Total signal notifications sent.
    pub signal_notifies: u64,
    /// Total resume notifications sent.
    pub resume_notifies: u64,
}

impl TaskWorkStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_added: 0,
            total_executed: 0,
            total_cancelled: 0,
            queues_allocated: 0,
            signal_notifies: 0,
            resume_notifies: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TaskWorkTable
// ══════════════════════════════════════════════════════════════

/// System-wide table of per-PID task work queues.
///
/// Provides the primary interface for adding, cancelling, and
/// running task work.
pub struct TaskWorkTable {
    /// Per-PID queues.
    queues: [TaskWorkQueue; MAX_TASK_QUEUES],
    /// Global statistics.
    stats: TaskWorkStats,
}

impl TaskWorkTable {
    /// Create a new empty task work table.
    pub const fn new() -> Self {
        Self {
            queues: [const { TaskWorkQueue::new() }; MAX_TASK_QUEUES],
            stats: TaskWorkStats::new(),
        }
    }

    /// Allocate a work queue for a PID.
    pub fn alloc_queue(&mut self, pid: Pid) -> Result<usize> {
        // Check for duplicate
        if self
            .queues
            .iter()
            .any(|q| q.allocated && q.pid().as_u64() == pid.as_u64())
        {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .queues
            .iter()
            .position(|q| !q.allocated)
            .ok_or(Error::OutOfMemory)?;

        self.queues[slot].allocate(pid);
        self.stats.queues_allocated += 1;
        Ok(slot)
    }

    /// Free a work queue for a PID.
    pub fn free_queue(&mut self, pid: Pid) -> Result<()> {
        let slot = self.find_queue_idx(pid)?;
        self.queues[slot].release();
        self.stats.queues_allocated = self.stats.queues_allocated.saturating_sub(1);
        Ok(())
    }

    /// Add work to a task's queue.
    ///
    /// This is the primary entry point for scheduling deferred
    /// task work.
    pub fn task_work_add(
        &mut self,
        pid: Pid,
        callback_fn: TaskWorkFn,
        flags: TaskWorkFlags,
        data: u64,
        current_tick: u64,
    ) -> Result<u32> {
        let slot = self.find_queue_idx(pid)?;
        let entry_id = self.queues[slot].add(callback_fn, flags, data, current_tick)?;

        self.stats.total_added += 1;
        if flags.has_signal() {
            self.stats.signal_notifies += 1;
        }
        if flags.has_resume() {
            self.stats.resume_notifies += 1;
        }

        Ok(entry_id)
    }

    /// Cancel a pending work entry for a task.
    pub fn task_work_cancel(&mut self, pid: Pid, entry_id: u32) -> Result<bool> {
        let slot = self.find_queue_idx(pid)?;
        let cancelled = self.queues[slot].cancel(entry_id)?;
        if cancelled {
            self.stats.total_cancelled += 1;
        }
        Ok(cancelled)
    }

    /// Run all pending task work for a PID.
    ///
    /// Returns the number of entries executed.
    pub fn task_work_run(&mut self, pid: Pid) -> Result<usize> {
        let slot = self.find_queue_idx(pid)?;
        let executed = self.queues[slot].run()?;
        self.stats.total_executed += executed as u64;
        Ok(executed)
    }

    /// Check whether a task has pending work.
    pub fn has_pending(&self, pid: Pid) -> Result<bool> {
        let slot = self.find_queue_idx(pid)?;
        Ok(self.queues[slot].has_pending())
    }

    /// Return the pending count for a task.
    pub fn pending_count(&self, pid: Pid) -> Result<usize> {
        let slot = self.find_queue_idx(pid)?;
        Ok(self.queues[slot].pending_count())
    }

    /// Return the TIF flags for a task.
    pub fn tif_flags(&self, pid: Pid) -> Result<u32> {
        let slot = self.find_queue_idx(pid)?;
        Ok(self.queues[slot].tif_flags())
    }

    /// Return global statistics.
    pub fn stats(&self) -> &TaskWorkStats {
        &self.stats
    }

    /// Find the queue index for a PID.
    fn find_queue_idx(&self, pid: Pid) -> Result<usize> {
        self.queues
            .iter()
            .position(|q| q.allocated && q.pid().as_u64() == pid.as_u64())
            .ok_or(Error::NotFound)
    }

    /// Return a reference to a queue by PID.
    pub fn find_queue(&self, pid: Pid) -> Result<&TaskWorkQueue> {
        let slot = self.find_queue_idx(pid)?;
        Ok(&self.queues[slot])
    }
}

/// Add task work for a given PID.
///
/// Convenience wrapper around `TaskWorkTable::task_work_add`.
pub fn task_work_add(
    table: &mut TaskWorkTable,
    pid: Pid,
    callback_fn: TaskWorkFn,
    notify: TaskWorkFlags,
    data: u64,
    current_tick: u64,
) -> Result<u32> {
    table.task_work_add(pid, callback_fn, notify, data, current_tick)
}

/// Cancel task work by callback function ID.
pub fn task_work_cancel(table: &mut TaskWorkTable, pid: Pid, entry_id: u32) -> Result<bool> {
    table.task_work_cancel(pid, entry_id)
}

/// Run all pending task work for a PID.
pub fn task_work_run(table: &mut TaskWorkTable, pid: Pid) -> Result<usize> {
    table.task_work_run(pid)
}
