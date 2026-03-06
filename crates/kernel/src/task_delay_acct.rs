// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-task delay accounting.
//!
//! Tracks how long each task spends waiting in various kernel paths
//! (scheduler runqueue, block I/O, page faults, memory reclaim,
//! thrashing, futex, etc.). This data is exposed to userspace via
//! taskstats and is used by tools like `iotop` and `latencytop`.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                    DelayAcctSubsystem                            │
//! │                                                                  │
//! │  [TaskDelayInfo; MAX_TASKS]  — per-task delay statistics         │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │  TaskDelayInfo                                             │  │
//! │  │    pid, state                                              │  │
//! │  │    DelayStat × N — one per delay category                  │  │
//! │  │    ┌──────────────────────────────────────────────────┐    │  │
//! │  │    │  DelayStat                                       │    │  │
//! │  │    │    count: u64           — number of delays         │    │  │
//! │  │    │    total_ns: u64        — cumulative delay         │    │  │
//! │  │    │    max_ns: u64          — worst-case delay         │    │  │
//! │  │    │    start_ns: u64        — in-flight marker         │    │  │
//! │  │    └──────────────────────────────────────────────────┘    │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! │                                                                  │
//! │  DelayCategory — enum of all delay types                         │
//! │  AggregateStats — system-wide rollup                             │
//! │  DelayAcctStats — global counters                                │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage Pattern
//!
//! 1. When a task enters a wait path, call `start(pid, category)`.
//! 2. When the task resumes, call `finish(pid, category)`.
//! 3. The subsystem computes the elapsed time and updates the
//!    per-category counters.
//!
//! # Reference
//!
//! Linux `kernel/delayacct.c`, `include/linux/delayacct.h`,
//! `include/uapi/linux/taskstats.h`,
//! `Documentation/accounting/delay-accounting.rst`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum tasks tracked.
const MAX_TASKS: usize = 512;

/// Number of delay categories.
const CATEGORY_COUNT: usize = 10;

/// Maximum history entries per task.
const MAX_HISTORY: usize = 16;

/// Maximum system-wide log entries.
const MAX_LOG_ENTRIES: usize = 256;

/// Threshold for "high latency" warning (10 ms in ns).
const HIGH_LATENCY_THRESHOLD_NS: u64 = 10_000_000;

/// Threshold for "extreme latency" warning (100 ms in ns).
const EXTREME_LATENCY_THRESHOLD_NS: u64 = 100_000_000;

// ── DelayCategory ───────────────────────────────────────────────────────────

/// Categories of kernel wait paths that are accounted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelayCategory {
    /// Waiting on the CPU runqueue (scheduler delay).
    CpuRunqueue,
    /// Waiting for block I/O completion.
    BlockIo,
    /// Waiting for page fault resolution (swapped pages).
    SwapIn,
    /// Waiting for memory reclaim (direct reclaim).
    MemReclaim,
    /// Thrashing — re-faulting recently evicted pages.
    Thrashing,
    /// Waiting on a futex / mutex.
    Futex,
    /// Waiting for compact (memory compaction).
    Compact,
    /// Waiting for writeback to complete.
    Writeback,
    /// Waiting for IPC message.
    Ipc,
    /// Waiting for network I/O.
    NetworkIo,
}

impl DelayCategory {
    /// Convert to an array index.
    const fn as_index(self) -> usize {
        match self {
            Self::CpuRunqueue => 0,
            Self::BlockIo => 1,
            Self::SwapIn => 2,
            Self::MemReclaim => 3,
            Self::Thrashing => 4,
            Self::Futex => 5,
            Self::Compact => 6,
            Self::Writeback => 7,
            Self::Ipc => 8,
            Self::NetworkIo => 9,
        }
    }

    /// All categories for iteration.
    const ALL: [Self; CATEGORY_COUNT] = [
        Self::CpuRunqueue,
        Self::BlockIo,
        Self::SwapIn,
        Self::MemReclaim,
        Self::Thrashing,
        Self::Futex,
        Self::Compact,
        Self::Writeback,
        Self::Ipc,
        Self::NetworkIo,
    ];

    /// Human-readable name.
    pub const fn name(self) -> &'static [u8] {
        match self {
            Self::CpuRunqueue => b"cpu_runqueue",
            Self::BlockIo => b"block_io",
            Self::SwapIn => b"swap_in",
            Self::MemReclaim => b"mem_reclaim",
            Self::Thrashing => b"thrashing",
            Self::Futex => b"futex",
            Self::Compact => b"compact",
            Self::Writeback => b"writeback",
            Self::Ipc => b"ipc",
            Self::NetworkIo => b"network_io",
        }
    }
}

// ── DelayStat ───────────────────────────────────────────────────────────────

/// Statistics for a single delay category.
#[derive(Debug, Clone, Copy)]
pub struct DelayStat {
    /// Number of delay events.
    count: u64,
    /// Cumulative delay in nanoseconds.
    total_ns: u64,
    /// Maximum single delay in nanoseconds.
    max_ns: u64,
    /// Timestamp when the current delay started (0 = not in delay).
    start_ns: u64,
    /// Number of delays exceeding the high-latency threshold.
    high_latency_count: u64,
    /// Number of delays exceeding the extreme-latency threshold.
    extreme_latency_count: u64,
}

impl DelayStat {
    /// Create a zeroed delay stat.
    const fn new() -> Self {
        Self {
            count: 0,
            total_ns: 0,
            max_ns: 0,
            start_ns: 0,
            high_latency_count: 0,
            extreme_latency_count: 0,
        }
    }

    /// Check whether a delay is currently in progress.
    pub fn is_active(&self) -> bool {
        self.start_ns != 0
    }

    /// Get the total delay count.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Get the total delay in nanoseconds.
    pub fn total_ns(&self) -> u64 {
        self.total_ns
    }

    /// Get the maximum delay in nanoseconds.
    pub fn max_ns(&self) -> u64 {
        self.max_ns
    }

    /// Get the average delay in nanoseconds (0 if no delays).
    pub fn avg_ns(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.total_ns / self.count
        }
    }
}

// ── DelayHistoryEntry ───────────────────────────────────────────────────────

/// A single entry in the per-task delay history ring buffer.
#[derive(Debug, Clone, Copy)]
pub struct DelayHistoryEntry {
    /// Timestamp when the delay started.
    start_ns: u64,
    /// Duration of the delay in nanoseconds.
    duration_ns: u64,
    /// Which category this delay belongs to.
    category: DelayCategory,
}

impl DelayHistoryEntry {
    /// Create an empty history entry.
    const fn new() -> Self {
        Self {
            start_ns: 0,
            duration_ns: 0,
            category: DelayCategory::CpuRunqueue,
        }
    }
}

// ── TaskDelayState ──────────────────────────────────────────────────────────

/// Lifecycle state of a task's delay tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskDelayState {
    /// Slot is free.
    Free,
    /// Tracking is active.
    Active,
    /// Task exited; stats are frozen.
    Exited,
}

impl Default for TaskDelayState {
    fn default() -> Self {
        Self::Free
    }
}

// ── TaskDelayInfo ───────────────────────────────────────────────────────────

/// Per-task delay accounting data.
#[derive(Debug, Clone, Copy)]
pub struct TaskDelayInfo {
    /// Task PID.
    pid: u64,
    /// Current tracking state.
    state: TaskDelayState,
    /// Per-category delay stats.
    stats: [DelayStat; CATEGORY_COUNT],
    /// Recent delay history (ring buffer).
    history: [DelayHistoryEntry; MAX_HISTORY],
    /// Next write position in history.
    history_head: usize,
    /// Total history entries written.
    history_total: u64,
    /// Task creation timestamp.
    created_ns: u64,
    /// Task exit timestamp (0 if still running).
    exited_ns: u64,
    /// Flags (bitmask of active categories).
    active_mask: u16,
}

impl TaskDelayInfo {
    /// Create an empty slot.
    const fn new() -> Self {
        Self {
            pid: 0,
            state: TaskDelayState::Free,
            stats: [const { DelayStat::new() }; CATEGORY_COUNT],
            history: [const { DelayHistoryEntry::new() }; MAX_HISTORY],
            history_head: 0,
            history_total: 0,
            created_ns: 0,
            exited_ns: 0,
            active_mask: 0,
        }
    }

    /// Check whether this slot is free.
    fn is_free(&self) -> bool {
        matches!(self.state, TaskDelayState::Free)
    }

    /// Get the task PID.
    pub fn pid(&self) -> u64 {
        self.pid
    }

    /// Get a reference to the delay stats array.
    pub fn delay_stats(&self) -> &[DelayStat; CATEGORY_COUNT] {
        &self.stats
    }

    /// Get a specific category stat.
    pub fn stat(&self, cat: DelayCategory) -> &DelayStat {
        &self.stats[cat.as_index()]
    }

    /// Compute total delay across all categories.
    pub fn total_delay_ns(&self) -> u64 {
        self.stats.iter().map(|s| s.total_ns).sum()
    }

    /// Compute total delay event count across all categories.
    pub fn total_delay_count(&self) -> u64 {
        self.stats.iter().map(|s| s.count).sum()
    }

    /// Number of currently active delays.
    fn active_count(&self) -> u32 {
        self.active_mask.count_ones()
    }
}

// ── SystemLogEntry ──────────────────────────────────────────────────────────

/// A system-wide delay log entry for extreme latency events.
#[derive(Debug, Clone, Copy)]
pub struct SystemLogEntry {
    /// Timestamp.
    timestamp_ns: u64,
    /// Task PID.
    pid: u64,
    /// Delay category.
    category: DelayCategory,
    /// Duration in nanoseconds.
    duration_ns: u64,
}

impl SystemLogEntry {
    /// Create an empty log entry.
    const fn new() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            category: DelayCategory::CpuRunqueue,
            duration_ns: 0,
        }
    }
}

// ── AggregateStats ──────────────────────────────────────────────────────────

/// System-wide aggregate delay statistics.
#[derive(Debug, Clone, Copy)]
pub struct AggregateStats {
    /// Per-category aggregate counts.
    pub counts: [u64; CATEGORY_COUNT],
    /// Per-category aggregate totals (nanoseconds).
    pub totals: [u64; CATEGORY_COUNT],
    /// Per-category max delays.
    pub maxes: [u64; CATEGORY_COUNT],
}

impl AggregateStats {
    /// Create zeroed aggregates.
    const fn new() -> Self {
        Self {
            counts: [0u64; CATEGORY_COUNT],
            totals: [0u64; CATEGORY_COUNT],
            maxes: [0u64; CATEGORY_COUNT],
        }
    }
}

// ── DelayAcctStats ──────────────────────────────────────────────────────────

/// Global counters for the delay accounting subsystem.
#[derive(Debug, Clone, Copy)]
pub struct DelayAcctStats {
    /// Total tasks tracked.
    pub tasks_tracked: u64,
    /// Total tasks exited.
    pub tasks_exited: u64,
    /// Total delay start events.
    pub delay_starts: u64,
    /// Total delay finish events.
    pub delay_finishes: u64,
    /// Total high-latency events.
    pub high_latency_events: u64,
    /// Total extreme-latency events.
    pub extreme_latency_events: u64,
    /// Missed events (start without matching finish).
    pub missed_events: u64,
    /// Active tasks currently tracked.
    pub active_tasks: u64,
}

impl DelayAcctStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            tasks_tracked: 0,
            tasks_exited: 0,
            delay_starts: 0,
            delay_finishes: 0,
            high_latency_events: 0,
            extreme_latency_events: 0,
            missed_events: 0,
            active_tasks: 0,
        }
    }
}

// ── DelayAcctSubsystem ──────────────────────────────────────────────────────

/// Top-level delay accounting subsystem.
///
/// Tracks per-task delay statistics for scheduler, I/O, memory, and
/// other wait paths. Provides APIs for starting/finishing delay
/// windows, querying per-task stats, and computing system-wide
/// aggregates.
pub struct DelayAcctSubsystem {
    /// Per-task delay info.
    tasks: [TaskDelayInfo; MAX_TASKS],
    /// System-wide extreme latency log.
    log: [SystemLogEntry; MAX_LOG_ENTRIES],
    /// Log head position.
    log_head: usize,
    /// Total log entries.
    log_total: u64,
    /// Global statistics.
    stats: DelayAcctStats,
    /// Whether the subsystem is enabled.
    enabled: bool,
    /// Current time.
    now_ns: u64,
}

impl DelayAcctSubsystem {
    /// Create a new delay accounting subsystem.
    pub const fn new() -> Self {
        Self {
            tasks: [const { TaskDelayInfo::new() }; MAX_TASKS],
            log: [const { SystemLogEntry::new() }; MAX_LOG_ENTRIES],
            log_head: 0,
            log_total: 0,
            stats: DelayAcctStats::new(),
            enabled: true,
            now_ns: 0,
        }
    }

    /// Update the internal time.
    pub fn set_time_ns(&mut self, ns: u64) {
        self.now_ns = ns;
    }

    /// Enable or disable the subsystem.
    pub fn set_enabled(&mut self, on: bool) {
        self.enabled = on;
    }

    /// Check whether the subsystem is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get global statistics.
    pub fn stats(&self) -> &DelayAcctStats {
        &self.stats
    }

    // ── Task lifecycle ──────────────────────────────────────────────

    /// Start tracking a task.
    pub fn track_task(&mut self, pid: u64) -> Result<usize> {
        if self.find_task(pid).is_some() {
            return Err(Error::AlreadyExists);
        }
        let idx = self
            .tasks
            .iter()
            .position(|t| t.is_free())
            .ok_or(Error::OutOfMemory)?;

        self.tasks[idx] = TaskDelayInfo::new();
        self.tasks[idx].pid = pid;
        self.tasks[idx].state = TaskDelayState::Active;
        self.tasks[idx].created_ns = self.now_ns;
        self.stats.tasks_tracked += 1;
        self.stats.active_tasks += 1;

        Ok(idx)
    }

    /// Mark a task as exited, freezing its stats.
    pub fn exit_task(&mut self, pid: u64) -> Result<()> {
        let idx = self.find_task(pid).ok_or(Error::NotFound)?;
        let task = &mut self.tasks[idx];

        // Finish any active delays.
        for cat in &DelayCategory::ALL {
            let ci = cat.as_index();
            if task.stats[ci].start_ns != 0 {
                let duration = self.now_ns.saturating_sub(task.stats[ci].start_ns);
                task.stats[ci].total_ns += duration;
                task.stats[ci].count += 1;
                if duration > task.stats[ci].max_ns {
                    task.stats[ci].max_ns = duration;
                }
                task.stats[ci].start_ns = 0;
            }
        }

        task.state = TaskDelayState::Exited;
        task.exited_ns = self.now_ns;
        task.active_mask = 0;
        self.stats.tasks_exited += 1;
        self.stats.active_tasks = self.stats.active_tasks.saturating_sub(1);

        Ok(())
    }

    /// Free a task slot (only valid for exited tasks).
    pub fn free_task(&mut self, pid: u64) -> Result<()> {
        let idx = self.find_task_any(pid).ok_or(Error::NotFound)?;
        if !matches!(self.tasks[idx].state, TaskDelayState::Exited) {
            return Err(Error::Busy);
        }
        self.tasks[idx].state = TaskDelayState::Free;
        Ok(())
    }

    // ── Delay start/finish ──────────────────────────────────────────

    /// Begin a delay window for a task.
    pub fn start(&mut self, pid: u64, category: DelayCategory) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let idx = self.find_task(pid).ok_or(Error::NotFound)?;
        let ci = category.as_index();
        let task = &mut self.tasks[idx];

        if task.stats[ci].start_ns != 0 {
            // Already in a delay of this category — record as missed.
            self.stats.missed_events += 1;
            return Ok(());
        }

        task.stats[ci].start_ns = self.now_ns;
        task.active_mask |= 1 << ci;
        self.stats.delay_starts += 1;

        Ok(())
    }

    /// Finish a delay window for a task.
    ///
    /// Computes the elapsed time and updates the per-category counters.
    pub fn finish(&mut self, pid: u64, category: DelayCategory) -> Result<u64> {
        if !self.enabled {
            return Ok(0);
        }
        let idx = self.find_task(pid).ok_or(Error::NotFound)?;
        let ci = category.as_index();

        if self.tasks[idx].stats[ci].start_ns == 0 {
            self.stats.missed_events += 1;
            return Err(Error::InvalidArgument);
        }

        let duration = self
            .now_ns
            .saturating_sub(self.tasks[idx].stats[ci].start_ns);
        self.tasks[idx].stats[ci].count += 1;
        self.tasks[idx].stats[ci].total_ns += duration;
        if duration > self.tasks[idx].stats[ci].max_ns {
            self.tasks[idx].stats[ci].max_ns = duration;
        }
        self.tasks[idx].stats[ci].start_ns = 0;
        self.tasks[idx].active_mask &= !(1 << ci);
        self.stats.delay_finishes += 1;

        // Check latency thresholds.
        if duration >= EXTREME_LATENCY_THRESHOLD_NS {
            self.tasks[idx].stats[ci].extreme_latency_count += 1;
            self.stats.extreme_latency_events += 1;
            self.log_extreme(pid, category, duration);
        } else if duration >= HIGH_LATENCY_THRESHOLD_NS {
            self.tasks[idx].stats[ci].high_latency_count += 1;
            self.stats.high_latency_events += 1;
        }

        // Record in per-task history.
        let head = self.tasks[idx].history_head;
        self.tasks[idx].history[head].start_ns = self.now_ns.saturating_sub(duration);
        self.tasks[idx].history[head].duration_ns = duration;
        self.tasks[idx].history[head].category = category;
        self.tasks[idx].history_head = (head + 1) % MAX_HISTORY;
        self.tasks[idx].history_total += 1;

        Ok(duration)
    }

    // ── Query ───────────────────────────────────────────────────────

    /// Get delay info for a task.
    pub fn task_info(&self, pid: u64) -> Result<&TaskDelayInfo> {
        let idx = self.find_task_any(pid).ok_or(Error::NotFound)?;
        Ok(&self.tasks[idx])
    }

    /// Get a specific delay stat for a task.
    pub fn task_stat(&self, pid: u64, category: DelayCategory) -> Result<&DelayStat> {
        let idx = self.find_task_any(pid).ok_or(Error::NotFound)?;
        Ok(&self.tasks[idx].stats[category.as_index()])
    }

    /// Compute system-wide aggregate statistics.
    pub fn aggregate(&self) -> AggregateStats {
        let mut agg = AggregateStats::new();
        for task in &self.tasks {
            if matches!(task.state, TaskDelayState::Free) {
                continue;
            }
            for (i, stat) in task.stats.iter().enumerate() {
                agg.counts[i] += stat.count;
                agg.totals[i] += stat.total_ns;
                if stat.max_ns > agg.maxes[i] {
                    agg.maxes[i] = stat.max_ns;
                }
            }
        }
        agg
    }

    /// Find the task with the highest total delay.
    pub fn top_delayed_task(&self) -> Option<u64> {
        let mut best_pid = None;
        let mut best_delay = 0u64;
        for task in &self.tasks {
            if !matches!(task.state, TaskDelayState::Active) {
                continue;
            }
            let total = task.total_delay_ns();
            if total > best_delay {
                best_delay = total;
                best_pid = Some(task.pid);
            }
        }
        best_pid
    }

    /// Find the task with the highest delay in a specific category.
    pub fn top_delayed_in_category(&self, category: DelayCategory) -> Option<(u64, u64)> {
        let ci = category.as_index();
        let mut best_pid = None;
        let mut best_ns = 0u64;
        for task in &self.tasks {
            if !matches!(task.state, TaskDelayState::Active) {
                continue;
            }
            if task.stats[ci].total_ns > best_ns {
                best_ns = task.stats[ci].total_ns;
                best_pid = Some((task.pid, best_ns));
            }
        }
        best_pid
    }

    /// Read recent delay history for a task (most recent first).
    pub fn read_history(&self, pid: u64, out: &mut [DelayHistoryEntry]) -> Result<usize> {
        let idx = self.find_task_any(pid).ok_or(Error::NotFound)?;
        let task = &self.tasks[idx];
        let available = (task.history_total as usize).min(MAX_HISTORY);
        let to_copy = available.min(out.len());

        for i in 0..to_copy {
            let ring_idx = if task.history_head >= i + 1 {
                task.history_head - i - 1
            } else {
                MAX_HISTORY - (i + 1 - task.history_head)
            };
            out[i] = task.history[ring_idx];
        }

        Ok(to_copy)
    }

    /// Get the count of active delays for a task.
    pub fn active_delay_count(&self, pid: u64) -> Result<u32> {
        let idx = self.find_task(pid).ok_or(Error::NotFound)?;
        Ok(self.tasks[idx].active_count())
    }

    /// Read the extreme latency log.
    pub fn read_log(&self, index: usize) -> Result<&SystemLogEntry> {
        if self.log_total == 0 {
            return Err(Error::NotFound);
        }
        let available = (self.log_total as usize).min(MAX_LOG_ENTRIES);
        if index >= available {
            return Err(Error::InvalidArgument);
        }
        let start = if self.log_total as usize > MAX_LOG_ENTRIES {
            self.log_head
        } else {
            0
        };
        let real = (start + index) % MAX_LOG_ENTRIES;
        Ok(&self.log[real])
    }

    /// Get total log entries.
    pub fn log_total(&self) -> u64 {
        self.log_total
    }

    // ── Bulk operations ─────────────────────────────────────────────

    /// Reset all stats for a task (while keeping it tracked).
    pub fn reset_task_stats(&mut self, pid: u64) -> Result<()> {
        let idx = self.find_task(pid).ok_or(Error::NotFound)?;
        let task = &mut self.tasks[idx];
        task.stats = [const { DelayStat::new() }; CATEGORY_COUNT];
        task.history = [const { DelayHistoryEntry::new() }; MAX_HISTORY];
        task.history_head = 0;
        task.history_total = 0;
        task.active_mask = 0;
        Ok(())
    }

    /// Count currently tracked tasks.
    pub fn tracked_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| matches!(t.state, TaskDelayState::Active | TaskDelayState::Exited))
            .count()
    }

    // ── Internal helpers ────────────────────────────────────────────

    /// Find an active task by PID.
    fn find_task(&self, pid: u64) -> Option<usize> {
        self.tasks
            .iter()
            .position(|t| matches!(t.state, TaskDelayState::Active) && t.pid == pid)
    }

    /// Find a task in any non-free state.
    fn find_task_any(&self, pid: u64) -> Option<usize> {
        self.tasks
            .iter()
            .position(|t| !matches!(t.state, TaskDelayState::Free) && t.pid == pid)
    }

    /// Log an extreme latency event.
    fn log_extreme(&mut self, pid: u64, category: DelayCategory, duration_ns: u64) {
        let entry = &mut self.log[self.log_head];
        entry.timestamp_ns = self.now_ns;
        entry.pid = pid;
        entry.category = category;
        entry.duration_ns = duration_ns;
        self.log_head = (self.log_head + 1) % MAX_LOG_ENTRIES;
        self.log_total += 1;
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_track_and_delay() {
        let mut sys = DelayAcctSubsystem::new();
        sys.set_time_ns(1000);
        sys.track_task(42).unwrap();

        sys.set_time_ns(1000);
        sys.start(42, DelayCategory::CpuRunqueue).unwrap();
        sys.set_time_ns(2000);
        let dur = sys.finish(42, DelayCategory::CpuRunqueue).unwrap();
        assert_eq!(dur, 1000);

        let stat = sys.task_stat(42, DelayCategory::CpuRunqueue).unwrap();
        assert_eq!(stat.count(), 1);
        assert_eq!(stat.total_ns(), 1000);
    }

    #[test]
    fn test_multiple_categories() {
        let mut sys = DelayAcctSubsystem::new();
        sys.track_task(1).unwrap();
        sys.set_time_ns(100);
        sys.start(1, DelayCategory::BlockIo).unwrap();
        sys.set_time_ns(200);
        sys.finish(1, DelayCategory::BlockIo).unwrap();
        sys.set_time_ns(300);
        sys.start(1, DelayCategory::Futex).unwrap();
        sys.set_time_ns(500);
        sys.finish(1, DelayCategory::Futex).unwrap();

        let info = sys.task_info(1).unwrap();
        assert_eq!(info.total_delay_ns(), 300);
        assert_eq!(info.total_delay_count(), 2);
    }

    #[test]
    fn test_exit_finishes_active() {
        let mut sys = DelayAcctSubsystem::new();
        sys.set_time_ns(0);
        sys.track_task(10).unwrap();
        sys.start(10, DelayCategory::SwapIn).unwrap();
        sys.set_time_ns(5000);
        sys.exit_task(10).unwrap();

        let info = sys.task_info(10).unwrap();
        assert_eq!(info.stat(DelayCategory::SwapIn).count(), 1);
        assert_eq!(info.stat(DelayCategory::SwapIn).total_ns(), 5000);
    }

    #[test]
    fn test_aggregate() {
        let mut sys = DelayAcctSubsystem::new();
        sys.track_task(1).unwrap();
        sys.track_task(2).unwrap();
        sys.set_time_ns(0);
        sys.start(1, DelayCategory::BlockIo).unwrap();
        sys.start(2, DelayCategory::BlockIo).unwrap();
        sys.set_time_ns(100);
        sys.finish(1, DelayCategory::BlockIo).unwrap();
        sys.set_time_ns(200);
        sys.finish(2, DelayCategory::BlockIo).unwrap();

        let agg = sys.aggregate();
        assert_eq!(agg.counts[DelayCategory::BlockIo.as_index()], 2);
    }

    #[test]
    fn test_extreme_latency_log() {
        let mut sys = DelayAcctSubsystem::new();
        sys.track_task(5).unwrap();
        sys.set_time_ns(0);
        sys.start(5, DelayCategory::MemReclaim).unwrap();
        sys.set_time_ns(EXTREME_LATENCY_THRESHOLD_NS + 1);
        sys.finish(5, DelayCategory::MemReclaim).unwrap();

        assert_eq!(sys.stats().extreme_latency_events, 1);
        assert_eq!(sys.log_total(), 1);
    }
}
