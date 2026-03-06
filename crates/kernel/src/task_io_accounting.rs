// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-task I/O accounting.
//!
//! Tracks I/O statistics on a per-task (thread/process) basis.
//! This data is exposed through `/proc/<pid>/io` on Linux and used
//! by monitoring tools like `iotop`.
//!
//! # Tracked Metrics
//!
//! | Counter | Description |
//! |---------|-------------|
//! | `rchar` | Bytes read via `read()` / `pread()` syscalls |
//! | `wchar` | Bytes written via `write()` / `pwrite()` syscalls |
//! | `syscr` | Number of read syscalls |
//! | `syscw` | Number of write syscalls |
//! | `read_bytes` | Bytes actually fetched from storage |
//! | `write_bytes` | Bytes actually sent to storage |
//! | `cancelled_write_bytes` | Bytes written then truncated/deleted |
//!
//! The distinction between `rchar`/`wchar` and `read_bytes`/
//! `write_bytes` is that the former counts all bytes passing through
//! the VFS layer (including page cache hits), while the latter counts
//! only bytes that required actual disk I/O.
//!
//! # Hierarchy
//!
//! When a child task exits, its counters are merged into the parent's
//! `cumulative` counters, preserving total I/O attribution.
//!
//! # Reference
//!
//! Linux `include/linux/task_io_accounting.h`,
//! `fs/proc/base.c` (`proc_pid_io_accounting`).

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of tasks tracked simultaneously.
const MAX_TASKS: usize = 1024;

/// Maximum number of I/O snapshots retained per task.
const MAX_SNAPSHOTS: usize = 8;

// ======================================================================
// IoCounters — raw counter set
// ======================================================================

/// A set of I/O counters for a single task.
///
/// All values are cumulative since the task was created (or since
/// the last explicit reset).
#[derive(Debug, Clone, Copy)]
pub struct IoCounters {
    /// Bytes read via VFS read syscalls.
    pub rchar: u64,
    /// Bytes written via VFS write syscalls.
    pub wchar: u64,
    /// Number of read syscalls.
    pub syscr: u64,
    /// Number of write syscalls.
    pub syscw: u64,
    /// Bytes actually read from storage (bypassing page cache).
    pub read_bytes: u64,
    /// Bytes actually written to storage.
    pub write_bytes: u64,
    /// Bytes written but subsequently cancelled (truncate/unlink).
    pub cancelled_write_bytes: u64,
}

impl IoCounters {
    /// Create zeroed counters.
    pub const fn new() -> Self {
        Self {
            rchar: 0,
            wchar: 0,
            syscr: 0,
            syscw: 0,
            read_bytes: 0,
            write_bytes: 0,
            cancelled_write_bytes: 0,
        }
    }

    /// Add another counter set into this one (merge).
    pub fn merge(&mut self, other: &IoCounters) {
        self.rchar = self.rchar.wrapping_add(other.rchar);
        self.wchar = self.wchar.wrapping_add(other.wchar);
        self.syscr = self.syscr.wrapping_add(other.syscr);
        self.syscw = self.syscw.wrapping_add(other.syscw);
        self.read_bytes = self.read_bytes.wrapping_add(other.read_bytes);
        self.write_bytes = self.write_bytes.wrapping_add(other.write_bytes);
        self.cancelled_write_bytes = self
            .cancelled_write_bytes
            .wrapping_add(other.cancelled_write_bytes);
    }

    /// Reset all counters to zero.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Compute the difference between two counter snapshots.
    pub fn delta(&self, previous: &IoCounters) -> IoCounters {
        IoCounters {
            rchar: self.rchar.wrapping_sub(previous.rchar),
            wchar: self.wchar.wrapping_sub(previous.wchar),
            syscr: self.syscr.wrapping_sub(previous.syscr),
            syscw: self.syscw.wrapping_sub(previous.syscw),
            read_bytes: self.read_bytes.wrapping_sub(previous.read_bytes),
            write_bytes: self.write_bytes.wrapping_sub(previous.write_bytes),
            cancelled_write_bytes: self
                .cancelled_write_bytes
                .wrapping_sub(previous.cancelled_write_bytes),
        }
    }

    /// Total bytes processed (read + write through VFS).
    pub fn total_vfs_bytes(&self) -> u64 {
        self.rchar.wrapping_add(self.wchar)
    }

    /// Total bytes through storage (read + write).
    pub fn total_storage_bytes(&self) -> u64 {
        self.read_bytes.wrapping_add(self.write_bytes)
    }

    /// Total syscalls (read + write).
    pub fn total_syscalls(&self) -> u64 {
        self.syscr.wrapping_add(self.syscw)
    }
}

// ======================================================================
// IoSnapshot — point-in-time counter snapshot
// ======================================================================

/// A timestamped snapshot of I/O counters.
#[derive(Debug, Clone, Copy)]
pub struct IoSnapshot {
    /// Counter values at snapshot time.
    pub counters: IoCounters,
    /// Monotonic tick when the snapshot was taken.
    pub timestamp: u64,
    /// Whether this snapshot is valid.
    pub valid: bool,
}

impl IoSnapshot {
    /// Create an empty (invalid) snapshot.
    const fn empty() -> Self {
        Self {
            counters: IoCounters::new(),
            timestamp: 0,
            valid: false,
        }
    }
}

// ======================================================================
// IoTaskStats — combined stats for reporting
// ======================================================================

/// Combined I/O statistics for a single task, including both direct
/// and cumulative (from exited children) counters.
#[derive(Debug, Clone, Copy)]
pub struct IoTaskStats {
    /// Task ID.
    pub tid: u64,
    /// Direct I/O counters for this task.
    pub direct: IoCounters,
    /// Cumulative counters from exited child tasks.
    pub cumulative: IoCounters,
    /// Combined total (direct + cumulative).
    pub total: IoCounters,
}

impl IoTaskStats {
    /// Create stats for a task by combining direct and cumulative.
    fn from_entry(entry: &TaskIoEntry) -> Self {
        let mut total = entry.counters;
        total.merge(&entry.cumulative);
        Self {
            tid: entry.tid,
            direct: entry.counters,
            cumulative: entry.cumulative,
            total,
        }
    }
}

// ======================================================================
// TaskIoEntry — internal per-task tracking
// ======================================================================

/// Internal per-task I/O accounting entry.
#[derive(Debug, Clone, Copy)]
struct TaskIoEntry {
    /// Task ID.
    tid: u64,
    /// Parent task ID (for child merging).
    parent_tid: u64,
    /// Direct I/O counters.
    counters: IoCounters,
    /// Cumulative counters from exited children.
    cumulative: IoCounters,
    /// Snapshot history (circular buffer).
    snapshots: [IoSnapshot; MAX_SNAPSHOTS],
    /// Next write index in snapshot buffer.
    snapshot_head: usize,
    /// Number of snapshots taken.
    snapshot_count: usize,
    /// Whether this entry is in use.
    active: bool,
}

impl TaskIoEntry {
    /// Create an empty (inactive) entry.
    const fn empty() -> Self {
        Self {
            tid: 0,
            parent_tid: 0,
            counters: IoCounters::new(),
            cumulative: IoCounters::new(),
            snapshots: [const { IoSnapshot::empty() }; MAX_SNAPSHOTS],
            snapshot_head: 0,
            snapshot_count: 0,
            active: false,
        }
    }

    /// Take a snapshot of the current counters.
    fn take_snapshot(&mut self, timestamp: u64) {
        self.snapshots[self.snapshot_head] = IoSnapshot {
            counters: self.counters,
            timestamp,
            valid: true,
        };
        self.snapshot_head = (self.snapshot_head + 1) % MAX_SNAPSHOTS;
        if self.snapshot_count < MAX_SNAPSHOTS {
            self.snapshot_count += 1;
        }
    }
}

// ======================================================================
// IoAccountingStats — aggregate statistics
// ======================================================================

/// Aggregate statistics for the I/O accounting subsystem.
#[derive(Debug, Clone, Copy)]
pub struct IoAccountingStats {
    /// Number of tasks currently tracked.
    pub active_tasks: u32,
    /// Total read operations accounted.
    pub total_read_ops: u64,
    /// Total write operations accounted.
    pub total_write_ops: u64,
    /// Total bytes read across all tasks.
    pub total_bytes_read: u64,
    /// Total bytes written across all tasks.
    pub total_bytes_written: u64,
    /// Number of child-to-parent merges performed.
    pub merge_count: u64,
}

impl IoAccountingStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            active_tasks: 0,
            total_read_ops: 0,
            total_write_ops: 0,
            total_bytes_read: 0,
            total_bytes_written: 0,
            merge_count: 0,
        }
    }
}

// ======================================================================
// IoAccountingData — top-level I/O accounting manager
// ======================================================================

/// Top-level per-task I/O accounting manager.
///
/// Tracks I/O counters for all active tasks and handles counter
/// merging when child tasks exit.
pub struct IoAccountingData {
    /// Per-task entries.
    entries: [TaskIoEntry; MAX_TASKS],
    /// Number of active entries.
    num_entries: usize,
    /// Aggregate statistics.
    stats: IoAccountingStats,
    /// Current monotonic tick.
    current_tick: u64,
}

impl IoAccountingData {
    /// Create a new I/O accounting manager.
    pub const fn new() -> Self {
        Self {
            entries: [const { TaskIoEntry::empty() }; MAX_TASKS],
            num_entries: 0,
            stats: IoAccountingStats::new(),
            current_tick: 0,
        }
    }

    /// Register a new task for I/O accounting.
    pub fn register_task(&mut self, tid: u64, parent_tid: u64) -> Result<()> {
        if self.num_entries >= MAX_TASKS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate.
        if self.entries.iter().any(|e| e.active && e.tid == tid) {
            return Err(Error::AlreadyExists);
        }

        let slot_idx = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        self.entries[slot_idx] = TaskIoEntry {
            tid,
            parent_tid,
            counters: IoCounters::new(),
            cumulative: IoCounters::new(),
            snapshots: [const { IoSnapshot::empty() }; MAX_SNAPSHOTS],
            snapshot_head: 0,
            snapshot_count: 0,
            active: true,
        };
        self.num_entries += 1;
        self.stats.active_tasks += 1;

        Ok(())
    }

    /// Unregister a task and merge its counters into the parent.
    pub fn unregister_task(&mut self, tid: u64) -> Result<()> {
        // Find the entry and extract the counters and parent TID.
        let (counters, cumulative, parent_tid) = {
            let entry = self
                .entries
                .iter()
                .find(|e| e.active && e.tid == tid)
                .ok_or(Error::NotFound)?;
            (entry.counters, entry.cumulative, entry.parent_tid)
        };

        // Merge into parent if one exists.
        let mut merged_counters = counters;
        merged_counters.merge(&cumulative);

        if let Some(parent) = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.tid == parent_tid)
        {
            parent.cumulative.merge(&merged_counters);
            self.stats.merge_count += 1;
        }

        // Deactivate the entry.
        if let Some(entry) = self.entries.iter_mut().find(|e| e.active && e.tid == tid) {
            entry.active = false;
            if self.num_entries > 0 {
                self.num_entries -= 1;
            }
            if self.stats.active_tasks > 0 {
                self.stats.active_tasks -= 1;
            }
        }

        Ok(())
    }

    /// Account a read operation.
    ///
    /// `bytes` is the number of bytes read through the VFS.
    /// `storage_bytes` is the number of bytes actually fetched from
    /// storage (may be less due to page cache hits).
    pub fn account_read(&mut self, tid: u64, bytes: u64, storage_bytes: u64) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.tid == tid)
            .ok_or(Error::NotFound)?;

        entry.counters.rchar = entry.counters.rchar.wrapping_add(bytes);
        entry.counters.syscr = entry.counters.syscr.wrapping_add(1);
        entry.counters.read_bytes = entry.counters.read_bytes.wrapping_add(storage_bytes);

        self.stats.total_read_ops += 1;
        self.stats.total_bytes_read = self.stats.total_bytes_read.wrapping_add(bytes);

        Ok(())
    }

    /// Account a write operation.
    ///
    /// `bytes` is the number of bytes written through the VFS.
    /// `storage_bytes` is the number of bytes actually sent to
    /// storage (may differ due to write-back caching).
    pub fn account_write(&mut self, tid: u64, bytes: u64, storage_bytes: u64) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.tid == tid)
            .ok_or(Error::NotFound)?;

        entry.counters.wchar = entry.counters.wchar.wrapping_add(bytes);
        entry.counters.syscw = entry.counters.syscw.wrapping_add(1);
        entry.counters.write_bytes = entry.counters.write_bytes.wrapping_add(storage_bytes);

        self.stats.total_write_ops += 1;
        self.stats.total_bytes_written = self.stats.total_bytes_written.wrapping_add(bytes);

        Ok(())
    }

    /// Account cancelled writes (e.g., truncated/deleted file).
    pub fn account_cancelled_write(&mut self, tid: u64, bytes: u64) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.tid == tid)
            .ok_or(Error::NotFound)?;

        entry.counters.cancelled_write_bytes =
            entry.counters.cancelled_write_bytes.wrapping_add(bytes);

        Ok(())
    }

    /// Get the combined I/O statistics for a task.
    pub fn get_stats(&self, tid: u64) -> Result<IoTaskStats> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.active && e.tid == tid)
            .ok_or(Error::NotFound)?;
        Ok(IoTaskStats::from_entry(entry))
    }

    /// Get the raw counters for a task (direct only).
    pub fn get_counters(&self, tid: u64) -> Result<&IoCounters> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.active && e.tid == tid)
            .ok_or(Error::NotFound)?;
        Ok(&entry.counters)
    }

    /// Reset the direct counters for a task.
    pub fn reset_counters(&mut self, tid: u64) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.tid == tid)
            .ok_or(Error::NotFound)?;

        // Take a snapshot before resetting.
        entry.take_snapshot(self.current_tick);
        entry.counters.reset();
        Ok(())
    }

    /// Merge counters from a source task into a destination task.
    ///
    /// Used for process group or cgroup aggregation.
    pub fn merge_stats(&mut self, src_tid: u64, dst_tid: u64) -> Result<()> {
        if src_tid == dst_tid {
            return Err(Error::InvalidArgument);
        }

        // Read the source counters.
        let src_counters = {
            let src = self
                .entries
                .iter()
                .find(|e| e.active && e.tid == src_tid)
                .ok_or(Error::NotFound)?;
            src.counters
        };

        // Merge into destination.
        let dst = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.tid == dst_tid)
            .ok_or(Error::NotFound)?;

        dst.cumulative.merge(&src_counters);
        self.stats.merge_count += 1;

        Ok(())
    }

    /// Take a snapshot of a task's current counters.
    pub fn take_snapshot(&mut self, tid: u64) -> Result<()> {
        let tick = self.current_tick;
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.tid == tid)
            .ok_or(Error::NotFound)?;

        entry.take_snapshot(tick);
        Ok(())
    }

    /// Get the most recent snapshot for a task.
    pub fn get_latest_snapshot(&self, tid: u64) -> Result<&IoSnapshot> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.active && e.tid == tid)
            .ok_or(Error::NotFound)?;

        if entry.snapshot_count == 0 {
            return Err(Error::NotFound);
        }

        let idx = if entry.snapshot_head == 0 {
            MAX_SNAPSHOTS - 1
        } else {
            entry.snapshot_head - 1
        };

        if entry.snapshots[idx].valid {
            Ok(&entry.snapshots[idx])
        } else {
            Err(Error::NotFound)
        }
    }

    /// Set the current monotonic tick.
    pub fn set_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Get aggregate statistics.
    pub fn aggregate_stats(&self) -> &IoAccountingStats {
        &self.stats
    }

    /// Get the number of active tasks.
    pub fn active_tasks(&self) -> u32 {
        self.stats.active_tasks
    }

    /// Compute I/O rate (bytes/tick) for a task based on the most
    /// recent snapshot delta.
    pub fn compute_rate(&self, tid: u64) -> Result<(u64, u64)> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.active && e.tid == tid)
            .ok_or(Error::NotFound)?;

        if entry.snapshot_count < 2 {
            return Err(Error::NotFound);
        }

        // Get the two most recent snapshots.
        let newest_idx = if entry.snapshot_head == 0 {
            MAX_SNAPSHOTS - 1
        } else {
            entry.snapshot_head - 1
        };
        let older_idx = if newest_idx == 0 {
            MAX_SNAPSHOTS - 1
        } else {
            newest_idx - 1
        };

        let newest = &entry.snapshots[newest_idx];
        let older = &entry.snapshots[older_idx];

        if !newest.valid || !older.valid {
            return Err(Error::NotFound);
        }

        let dt = newest.timestamp.saturating_sub(older.timestamp);
        if dt == 0 {
            return Err(Error::InvalidArgument);
        }

        let delta = newest.counters.delta(&older.counters);
        let read_rate = delta.rchar / dt;
        let write_rate = delta.wchar / dt;

        Ok((read_rate, write_rate))
    }
}
