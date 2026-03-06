// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Scheduler statistics — per-task and per-CPU performance counters
//! for scheduling analysis.
//!
//! Collects fine-grained metrics about task scheduling behaviour,
//! context switches, idle periods, and load balancing activity.
//! Data is exposed via `/proc/<pid>/schedstat` and `/proc/schedstat`
//! compatible formats.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                  SchedStatsCollector                          │
//! │                                                              │
//! │  TaskSchedStats[0..MAX_TASKS]                                │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  total_run_time_ns, total_wait_time_ns                 │  │
//! │  │  nr_switches, nr_voluntary, nr_involuntary             │  │
//! │  │  nr_wakeups, last_arrival_tick, last_queued_tick        │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  CpuSchedStats[0..MAX_CPUS]                                  │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  nr_running, total_idle_ns, total_busy_ns              │  │
//! │  │  nr_context_switches, nr_load_balances, nr_migrations  │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  SchedStatsGlobal                                            │
//! │  - total_forks, total_context_switches, total_running        │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/sched/stats.c`, `include/linux/sched/stat.h`,
//! `Documentation/scheduler/sched-stats.rst`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum tasks tracked for scheduling statistics.
const MAX_TASKS: usize = 256;

/// Maximum CPUs tracked.
const MAX_CPUS: usize = 64;

/// Format buffer size for /proc output.
const FORMAT_BUF_SIZE: usize = 256;

// ══════════════════════════════════════════════════════════════
// TaskSchedStats
// ══════════════════════════════════════════════════════════════

/// Per-task scheduler statistics.
///
/// Tracks how long a task has been running, waiting, how many
/// context switches it has experienced, and wakeup events.
#[derive(Clone, Copy)]
pub struct TaskSchedStats {
    /// Total time spent running on a CPU (nanoseconds).
    pub total_run_time_ns: u64,
    /// Total time spent waiting in the run queue (nanoseconds).
    pub total_wait_time_ns: u64,
    /// Total context switches (voluntary + involuntary).
    pub nr_switches: u64,
    /// Voluntary context switches (task yielded or slept).
    pub nr_voluntary_switches: u64,
    /// Involuntary context switches (preempted by scheduler).
    pub nr_involuntary_switches: u64,
    /// Number of times this task was woken up.
    pub nr_wakeups: u64,
    /// Tick when this task last arrived on a CPU.
    pub last_arrival_tick: u64,
    /// Tick when this task was last enqueued in the run queue.
    pub last_queued_tick: u64,
    /// Whether this task stats slot is in use.
    pub active: bool,
    /// Task ID (PID) for this stats entry.
    pub task_id: u64,
    /// Number of migrations between CPUs.
    pub nr_migrations: u64,
    /// Last CPU this task ran on.
    pub last_cpu: u32,
}

impl TaskSchedStats {
    /// Create an empty task stats entry.
    pub const fn new() -> Self {
        Self {
            total_run_time_ns: 0,
            total_wait_time_ns: 0,
            nr_switches: 0,
            nr_voluntary_switches: 0,
            nr_involuntary_switches: 0,
            nr_wakeups: 0,
            last_arrival_tick: 0,
            last_queued_tick: 0,
            active: false,
            task_id: 0,
            nr_migrations: 0,
            last_cpu: 0,
        }
    }

    /// Reset all counters for this task.
    pub fn reset(&mut self) {
        self.total_run_time_ns = 0;
        self.total_wait_time_ns = 0;
        self.nr_switches = 0;
        self.nr_voluntary_switches = 0;
        self.nr_involuntary_switches = 0;
        self.nr_wakeups = 0;
        self.nr_migrations = 0;
    }
}

impl Default for TaskSchedStats {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// CpuSchedStats
// ══════════════════════════════════════════════════════════════

/// Per-CPU scheduler statistics.
///
/// Tracks aggregate scheduling information for a single CPU,
/// including time spent idle/busy, context switch counts, and
/// load balancing activity.
#[derive(Clone, Copy)]
pub struct CpuSchedStats {
    /// Number of tasks currently in the run queue.
    pub nr_running: u32,
    /// Total time spent in idle state (nanoseconds).
    pub total_idle_ns: u64,
    /// Total time spent running tasks (nanoseconds).
    pub total_busy_ns: u64,
    /// Total context switches on this CPU.
    pub nr_context_switches: u64,
    /// Number of load balancing attempts involving this CPU.
    pub nr_load_balances: u64,
    /// Number of tasks migrated to/from this CPU.
    pub nr_migrations: u64,
    /// Whether this CPU is currently idle.
    pub idle: bool,
    /// Tick when this CPU last entered idle.
    pub idle_entry_tick: u64,
    /// Tick when this CPU last exited idle.
    pub idle_exit_tick: u64,
    /// Whether this CPU stats slot is active.
    pub active: bool,
    /// Number of tasks that woke up on this CPU.
    pub nr_wakeups_local: u64,
    /// Number of remote wakeups (task woken on different CPU).
    pub nr_wakeups_remote: u64,
}

impl CpuSchedStats {
    /// Create an empty CPU stats entry.
    pub const fn new() -> Self {
        Self {
            nr_running: 0,
            total_idle_ns: 0,
            total_busy_ns: 0,
            nr_context_switches: 0,
            nr_load_balances: 0,
            nr_migrations: 0,
            idle: true,
            idle_entry_tick: 0,
            idle_exit_tick: 0,
            active: false,
            nr_wakeups_local: 0,
            nr_wakeups_remote: 0,
        }
    }

    /// Reset all counters for this CPU.
    pub fn reset(&mut self) {
        self.nr_running = 0;
        self.total_idle_ns = 0;
        self.total_busy_ns = 0;
        self.nr_context_switches = 0;
        self.nr_load_balances = 0;
        self.nr_migrations = 0;
        self.nr_wakeups_local = 0;
        self.nr_wakeups_remote = 0;
    }
}

impl Default for CpuSchedStats {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// SchedStatsGlobal
// ══════════════════════════════════════════════════════════════

/// System-wide scheduler statistics.
#[derive(Clone, Copy)]
pub struct SchedStatsGlobal {
    /// Total number of fork() operations.
    pub total_forks: u64,
    /// Total context switches across all CPUs.
    pub total_context_switches: u64,
    /// Current total number of runnable tasks.
    pub total_running: u32,
    /// Total migrations across all CPUs.
    pub total_migrations: u64,
    /// Total load balancing operations.
    pub total_load_balances: u64,
    /// Total task wakeups.
    pub total_wakeups: u64,
}

impl SchedStatsGlobal {
    /// Create zeroed global statistics.
    pub const fn new() -> Self {
        Self {
            total_forks: 0,
            total_context_switches: 0,
            total_running: 0,
            total_migrations: 0,
            total_load_balances: 0,
            total_wakeups: 0,
        }
    }
}

impl Default for SchedStatsGlobal {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// SchedStatsCollector
// ══════════════════════════════════════════════════════════════

/// Scheduler statistics collector managing per-task, per-CPU,
/// and global counters.
pub struct SchedStatsCollector {
    /// Per-task statistics.
    pub tasks: [TaskSchedStats; MAX_TASKS],
    /// Number of active task entries.
    pub task_count: u32,
    /// Per-CPU statistics.
    pub cpus: [CpuSchedStats; MAX_CPUS],
    /// Number of active CPUs.
    pub cpu_count: u32,
    /// Global aggregated statistics.
    pub global: SchedStatsGlobal,
    /// Whether the collector is enabled.
    pub enabled: bool,
    /// Tick-to-nanosecond conversion factor.
    pub ns_per_tick: u64,
}

impl SchedStatsCollector {
    /// Create a new statistics collector.
    pub const fn new() -> Self {
        Self {
            tasks: [const { TaskSchedStats::new() }; MAX_TASKS],
            task_count: 0,
            cpus: [const { CpuSchedStats::new() }; MAX_CPUS],
            cpu_count: 0,
            global: SchedStatsGlobal::new(),
            enabled: false,
            ns_per_tick: 1_000_000, // Default: 1ms per tick.
        }
    }

    /// Initialize the collector for a given number of CPUs.
    pub fn init(&mut self, cpu_count: u32, ns_per_tick: u64) -> Result<()> {
        if cpu_count == 0 || cpu_count as usize > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if ns_per_tick == 0 {
            return Err(Error::InvalidArgument);
        }
        self.cpu_count = cpu_count;
        self.ns_per_tick = ns_per_tick;
        for i in 0..cpu_count as usize {
            self.cpus[i].active = true;
        }
        self.enabled = true;
        Ok(())
    }

    /// Register a task for statistics tracking.
    pub fn register_task(&mut self, task_id: u64) -> Result<usize> {
        if self.task_count as usize >= MAX_TASKS {
            return Err(Error::OutOfMemory);
        }
        // Find free slot.
        let pos = self.tasks.iter().position(|t| !t.active);
        match pos {
            Some(idx) => {
                self.tasks[idx] = TaskSchedStats::new();
                self.tasks[idx].active = true;
                self.tasks[idx].task_id = task_id;
                self.task_count += 1;
                self.global.total_forks += 1;
                Ok(idx)
            }
            None => Err(Error::OutOfMemory),
        }
    }

    /// Unregister a task.
    pub fn unregister_task(&mut self, task_id: u64) -> Result<()> {
        let pos = self
            .tasks
            .iter()
            .position(|t| t.active && t.task_id == task_id);
        match pos {
            Some(idx) => {
                self.tasks[idx].active = false;
                self.task_count = self.task_count.saturating_sub(1);
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Record a task arriving on a CPU (scheduled to run).
    pub fn task_arrive(&mut self, task_id: u64, cpu: u32, current_tick: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let idx = self.find_task(task_id)?;

        // Compute wait time: from when it was queued to now.
        let queued = self.tasks[idx].last_queued_tick;
        if queued > 0 && current_tick > queued {
            let wait_ns = (current_tick - queued) * self.ns_per_tick;
            self.tasks[idx].total_wait_time_ns += wait_ns;
        }

        self.tasks[idx].last_arrival_tick = current_tick;
        self.tasks[idx].last_cpu = cpu;

        if cpu < self.cpu_count {
            self.cpus[cpu as usize].nr_running =
                self.cpus[cpu as usize].nr_running.saturating_add(1);
            self.global.total_running = self.global.total_running.saturating_add(1);
        }

        Ok(())
    }

    /// Record a task departing a CPU (descheduled).
    pub fn task_depart(&mut self, task_id: u64, cpu: u32, current_tick: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let idx = self.find_task(task_id)?;

        // Compute run time: from arrival to now.
        let arrival = self.tasks[idx].last_arrival_tick;
        if arrival > 0 && current_tick > arrival {
            let run_ns = (current_tick - arrival) * self.ns_per_tick;
            self.tasks[idx].total_run_time_ns += run_ns;
        }

        if cpu < self.cpu_count {
            self.cpus[cpu as usize].nr_running =
                self.cpus[cpu as usize].nr_running.saturating_sub(1);
            self.global.total_running = self.global.total_running.saturating_sub(1);
        }

        Ok(())
    }

    /// Record a context switch (task_prev → task_next on a CPU).
    pub fn task_switch(
        &mut self,
        prev_task_id: u64,
        next_task_id: u64,
        cpu: u32,
        current_tick: u64,
        voluntary: bool,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        // Update prev task.
        if let Ok(prev_idx) = self.find_task(prev_task_id) {
            self.tasks[prev_idx].nr_switches += 1;
            if voluntary {
                self.tasks[prev_idx].nr_voluntary_switches += 1;
            } else {
                self.tasks[prev_idx].nr_involuntary_switches += 1;
            }

            // Compute run time for prev task.
            let arrival = self.tasks[prev_idx].last_arrival_tick;
            if arrival > 0 && current_tick > arrival {
                let run_ns = (current_tick - arrival) * self.ns_per_tick;
                self.tasks[prev_idx].total_run_time_ns += run_ns;
            }
        }

        // Update next task.
        if let Ok(next_idx) = self.find_task(next_task_id) {
            let queued = self.tasks[next_idx].last_queued_tick;
            if queued > 0 && current_tick > queued {
                let wait_ns = (current_tick - queued) * self.ns_per_tick;
                self.tasks[next_idx].total_wait_time_ns += wait_ns;
            }
            self.tasks[next_idx].last_arrival_tick = current_tick;
            self.tasks[next_idx].last_cpu = cpu;
        }

        // Update CPU stats.
        if cpu < self.cpu_count {
            self.cpus[cpu as usize].nr_context_switches += 1;
        }
        self.global.total_context_switches += 1;

        Ok(())
    }

    /// Record a task wakeup event.
    pub fn task_wakeup(
        &mut self,
        task_id: u64,
        cpu: u32,
        current_tick: u64,
        local: bool,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let idx = self.find_task(task_id)?;

        self.tasks[idx].nr_wakeups += 1;
        self.tasks[idx].last_queued_tick = current_tick;

        if cpu < self.cpu_count {
            if local {
                self.cpus[cpu as usize].nr_wakeups_local += 1;
            } else {
                self.cpus[cpu as usize].nr_wakeups_remote += 1;
            }
        }
        self.global.total_wakeups += 1;

        Ok(())
    }

    /// Record a CPU entering idle state.
    pub fn cpu_idle_enter(&mut self, cpu: u32, current_tick: u64) -> Result<()> {
        if !self.enabled || cpu >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        let stats = &mut self.cpus[cpu as usize];

        // Accumulate busy time from last exit to now.
        if !stats.idle && stats.idle_exit_tick > 0 {
            let busy_ns = current_tick.saturating_sub(stats.idle_exit_tick) * self.ns_per_tick;
            stats.total_busy_ns += busy_ns;
        }

        stats.idle = true;
        stats.idle_entry_tick = current_tick;
        Ok(())
    }

    /// Record a CPU exiting idle state.
    pub fn cpu_idle_exit(&mut self, cpu: u32, current_tick: u64) -> Result<()> {
        if !self.enabled || cpu >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        let stats = &mut self.cpus[cpu as usize];

        // Accumulate idle time from entry to now.
        if stats.idle && stats.idle_entry_tick > 0 {
            let idle_ns = current_tick.saturating_sub(stats.idle_entry_tick) * self.ns_per_tick;
            stats.total_idle_ns += idle_ns;
        }

        stats.idle = false;
        stats.idle_exit_tick = current_tick;
        Ok(())
    }

    /// Record a task migration between CPUs.
    pub fn task_migrate(&mut self, task_id: u64, from_cpu: u32, to_cpu: u32) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let idx = self.find_task(task_id)?;
        self.tasks[idx].nr_migrations += 1;
        self.tasks[idx].last_cpu = to_cpu;

        if from_cpu < self.cpu_count {
            self.cpus[from_cpu as usize].nr_migrations += 1;
        }
        if to_cpu < self.cpu_count {
            self.cpus[to_cpu as usize].nr_migrations += 1;
        }
        self.global.total_migrations += 1;

        Ok(())
    }

    /// Record a load balancing operation.
    pub fn load_balance(&mut self, cpu: u32) -> Result<()> {
        if !self.enabled || cpu >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        self.cpus[cpu as usize].nr_load_balances += 1;
        self.global.total_load_balances += 1;
        Ok(())
    }

    /// Get per-task statistics.
    pub fn get_task_stats(&self, task_id: u64) -> Result<&TaskSchedStats> {
        let idx = self.find_task_const(task_id)?;
        Ok(&self.tasks[idx])
    }

    /// Get per-CPU statistics.
    pub fn get_cpu_stats(&self, cpu: u32) -> Result<&CpuSchedStats> {
        if cpu >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.cpus[cpu as usize])
    }

    /// Get global statistics.
    pub fn get_global_stats(&self) -> &SchedStatsGlobal {
        &self.global
    }

    /// Format per-task schedstat into a buffer.
    ///
    /// Output matches Linux `/proc/<pid>/schedstat`:
    /// `<run_time_ns> <wait_time_ns> <nr_switches>`
    pub fn format_task_stat(&self, task_id: u64, buf: &mut [u8]) -> Result<usize> {
        let idx = self.find_task_const(task_id)?;
        let stats = &self.tasks[idx];
        let mut pos = 0usize;

        pos += write_u64_to_buf(&mut buf[pos..], stats.total_run_time_ns);
        if pos < buf.len() {
            buf[pos] = b' ';
            pos += 1;
        }
        pos += write_u64_to_buf(&mut buf[pos..], stats.total_wait_time_ns);
        if pos < buf.len() {
            buf[pos] = b' ';
            pos += 1;
        }
        pos += write_u64_to_buf(&mut buf[pos..], stats.nr_switches);
        if pos < buf.len() {
            buf[pos] = b'\n';
            pos += 1;
        }

        Ok(pos)
    }

    /// Format per-CPU schedstat into a buffer.
    ///
    /// Output matches Linux `/proc/schedstat` per-CPU lines.
    pub fn format_cpu_stat(&self, cpu_id: u32, buf: &mut [u8]) -> Result<usize> {
        if cpu_id >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        let stats = &self.cpus[cpu_id as usize];
        let mut pos = 0usize;

        // "cpuN"
        if pos + 3 <= buf.len() {
            buf[pos] = b'c';
            buf[pos + 1] = b'p';
            buf[pos + 2] = b'u';
            pos += 3;
        }
        pos += write_u32_to_buf(&mut buf[pos..], cpu_id);

        if pos < buf.len() {
            buf[pos] = b' ';
            pos += 1;
        }

        // nr_running
        pos += write_u32_to_buf(&mut buf[pos..], stats.nr_running);
        if pos < buf.len() {
            buf[pos] = b' ';
            pos += 1;
        }

        // nr_context_switches
        pos += write_u64_to_buf(&mut buf[pos..], stats.nr_context_switches);
        if pos < buf.len() {
            buf[pos] = b' ';
            pos += 1;
        }

        // total_idle_ns
        pos += write_u64_to_buf(&mut buf[pos..], stats.total_idle_ns);
        if pos < buf.len() {
            buf[pos] = b' ';
            pos += 1;
        }

        // total_busy_ns
        pos += write_u64_to_buf(&mut buf[pos..], stats.total_busy_ns);
        if pos < buf.len() {
            buf[pos] = b' ';
            pos += 1;
        }

        // nr_migrations
        pos += write_u64_to_buf(&mut buf[pos..], stats.nr_migrations);
        if pos < buf.len() {
            buf[pos] = b'\n';
            pos += 1;
        }

        Ok(pos)
    }

    /// Reset all statistics.
    pub fn reset_all(&mut self) {
        for task in &mut self.tasks {
            if task.active {
                task.reset();
            }
        }
        for cpu in &mut self.cpus[..self.cpu_count as usize] {
            cpu.reset();
        }
        self.global = SchedStatsGlobal::new();
    }

    /// Find a task's index (mutable search context).
    fn find_task(&self, task_id: u64) -> Result<usize> {
        self.tasks
            .iter()
            .position(|t| t.active && t.task_id == task_id)
            .ok_or(Error::NotFound)
    }

    /// Find a task's index (const context).
    fn find_task_const(&self, task_id: u64) -> Result<usize> {
        self.tasks
            .iter()
            .position(|t| t.active && t.task_id == task_id)
            .ok_or(Error::NotFound)
    }
}

impl Default for SchedStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// Formatting helpers
// ══════════════════════════════════════════════════════════════

/// Write a u64 as decimal into a buffer, returning bytes written.
fn write_u64_to_buf(buf: &mut [u8], value: u64) -> usize {
    if buf.is_empty() {
        return 0;
    }
    if value == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = value;
    let mut len = 0;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let copy_len = len.min(buf.len());
    for i in 0..copy_len {
        buf[i] = tmp[len - 1 - i];
    }
    copy_len
}

/// Write a u32 as decimal into a buffer, returning bytes written.
fn write_u32_to_buf(buf: &mut [u8], value: u32) -> usize {
    write_u64_to_buf(buf, value as u64)
}

/// Format complete `/proc/schedstat` output into a buffer.
///
/// Writes version header and one line per CPU.
pub fn format_proc_schedstat(
    collector: &SchedStatsCollector,
    buf: &mut [u8; FORMAT_BUF_SIZE],
) -> usize {
    let mut pos = 0usize;

    // Version header.
    let header = b"version 15\ntimestamp ";
    let copy_len = header.len().min(FORMAT_BUF_SIZE - pos);
    buf[pos..pos + copy_len].copy_from_slice(&header[..copy_len]);
    pos += copy_len;

    // Timestamp placeholder (0).
    if pos < FORMAT_BUF_SIZE {
        buf[pos] = b'0';
        pos += 1;
    }
    if pos < FORMAT_BUF_SIZE {
        buf[pos] = b'\n';
        pos += 1;
    }

    // Per-CPU lines.
    for cpu in 0..collector.cpu_count {
        if pos >= FORMAT_BUF_SIZE - 20 {
            break;
        }
        let remaining = &mut buf[pos..];
        match collector.format_cpu_stat(cpu, remaining) {
            Ok(written) => pos += written,
            Err(_) => break,
        }
    }

    pos
}
