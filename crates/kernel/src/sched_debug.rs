// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Scheduler debug information.
//!
//! Provides detailed scheduler state dumps for debugging and
//! performance analysis, modeled after Linux's `/proc/sched_debug`.
//! Includes per-CPU runqueue statistics, per-task scheduling info,
//! and per-class (CFS/RT/DL) aggregated metrics.
//!
//! # Output Format
//!
//! ```text
//! cpu#0
//!   .nr_running      : 3
//!   .load             : 3072
//!   .nr_switches      : 1048576
//!   .nr_uninterruptible: 0
//!
//!   cfs_rq
//!     .exec_clock     : 5000000.123456
//!     .nr_running     : 2
//!     .load.weight    : 2048
//!     .min_vruntime   : 123456789
//!
//!   rt_rq
//!     .rt_nr_running  : 1
//!     .rt_throttled   : 0
//!
//!   runnable tasks:
//!     task  PID  prio  vruntime  sum_exec  switches
//!     init   1    120  12345678   500000    100
//!     kworker 42  120  12345700   300000     80
//! ```
//!
//! # Reference
//!
//! Linux `kernel/sched/debug.c`, `/proc/sched_debug`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of CPUs supported.
const MAX_CPUS: usize = 64;

/// Maximum number of tasks per CPU runqueue dump.
const MAX_TASKS_PER_RQ: usize = 128;

/// Maximum length of a task name.
const MAX_TASK_NAME_LEN: usize = 16;

/// Default scheduler tick rate in Hz.
const _SCHED_TICK_HZ: u32 = 250;

/// CFS default nice-0 weight.
const _CFS_NICE0_WEIGHT: u32 = 1024;

// ======================================================================
// Scheduling policy
// ======================================================================

/// Scheduling policy for a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedPolicy {
    /// Completely Fair Scheduler (SCHED_OTHER).
    Normal = 0,
    /// FIFO real-time (SCHED_FIFO).
    Fifo = 1,
    /// Round-robin real-time (SCHED_RR).
    RoundRobin = 2,
    /// Batch scheduling (SCHED_BATCH).
    Batch = 3,
    /// Idle class (SCHED_IDLE).
    Idle = 5,
    /// Deadline scheduling (SCHED_DEADLINE).
    Deadline = 6,
}

impl SchedPolicy {
    /// Returns the policy name as bytes.
    pub fn name(&self) -> &[u8] {
        match self {
            Self::Normal => b"NORMAL",
            Self::Fifo => b"FIFO",
            Self::RoundRobin => b"RR",
            Self::Batch => b"BATCH",
            Self::Idle => b"IDLE",
            Self::Deadline => b"DEADLINE",
        }
    }
}

// ======================================================================
// Task debug info
// ======================================================================

/// Scheduling debug information for a single task.
#[derive(Debug, Clone, Copy)]
pub struct TaskSchedInfo {
    /// Task name (comm).
    name: [u8; MAX_TASK_NAME_LEN],
    /// Length of the name.
    name_len: usize,
    /// Process ID.
    pid: u32,
    /// Thread group ID.
    tgid: u32,
    /// Static priority (100-139 for normal, 0-99 for RT).
    prio: u32,
    /// Scheduling policy.
    policy: SchedPolicy,
    /// Virtual runtime (CFS).
    vruntime: u64,
    /// Sum of execution time in nanoseconds.
    sum_exec_runtime_ns: u64,
    /// Number of voluntary context switches.
    nr_voluntary_switches: u64,
    /// Number of involuntary context switches.
    nr_involuntary_switches: u64,
    /// CFS load weight.
    weight: u32,
    /// Current CPU.
    cpu: u32,
    /// Task state (0=running, 1=sleeping, 2=disk sleep, etc.).
    state: u8,
    /// Whether this entry is valid.
    valid: bool,
    /// Deadline parameters (for SCHED_DEADLINE).
    dl_runtime_ns: u64,
    dl_deadline_ns: u64,
    dl_period_ns: u64,
}

impl TaskSchedInfo {
    /// Creates an empty task info.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_TASK_NAME_LEN],
            name_len: 0,
            pid: 0,
            tgid: 0,
            prio: 120,
            policy: SchedPolicy::Normal,
            vruntime: 0,
            sum_exec_runtime_ns: 0,
            nr_voluntary_switches: 0,
            nr_involuntary_switches: 0,
            weight: 1024,
            cpu: 0,
            state: 0,
            valid: false,
            dl_runtime_ns: 0,
            dl_deadline_ns: 0,
            dl_period_ns: 0,
        }
    }

    /// Sets the task name.
    pub fn set_name(&mut self, name: &[u8]) -> Result<()> {
        if name.len() > MAX_TASK_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len();
        Ok(())
    }

    /// Returns the task name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the PID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the priority.
    pub fn prio(&self) -> u32 {
        self.prio
    }

    /// Returns the scheduling policy.
    pub fn policy(&self) -> SchedPolicy {
        self.policy
    }

    /// Returns the virtual runtime.
    pub fn vruntime(&self) -> u64 {
        self.vruntime
    }

    /// Returns the total execution time in nanoseconds.
    pub fn sum_exec_runtime_ns(&self) -> u64 {
        self.sum_exec_runtime_ns
    }

    /// Returns total context switches.
    pub fn total_switches(&self) -> u64 {
        self.nr_voluntary_switches
            .saturating_add(self.nr_involuntary_switches)
    }
}

// ======================================================================
// CFS runqueue stats
// ======================================================================

/// CFS (Completely Fair Scheduler) runqueue statistics.
#[derive(Debug, Clone, Copy)]
pub struct CfsRqStats {
    /// Number of CFS tasks currently runnable.
    nr_running: u32,
    /// Total CFS load weight.
    load_weight: u64,
    /// Minimum virtual runtime in the tree.
    min_vruntime: u64,
    /// Total execution clock in nanoseconds.
    exec_clock_ns: u64,
    /// Number of CFS task spreads (migrations).
    nr_spread_over: u64,
    /// Total runnable weight.
    runnable_weight: u64,
    /// Total blocked weight (sleeping tasks that still count).
    blocked_weight: u64,
}

impl CfsRqStats {
    /// Creates zeroed CFS stats.
    pub const fn new() -> Self {
        Self {
            nr_running: 0,
            load_weight: 0,
            min_vruntime: 0,
            exec_clock_ns: 0,
            nr_spread_over: 0,
            runnable_weight: 0,
            blocked_weight: 0,
        }
    }

    /// Returns the number of running CFS tasks.
    pub fn nr_running(&self) -> u32 {
        self.nr_running
    }

    /// Returns the CFS load weight.
    pub fn load_weight(&self) -> u64 {
        self.load_weight
    }

    /// Returns the minimum vruntime.
    pub fn min_vruntime(&self) -> u64 {
        self.min_vruntime
    }

    /// Returns the execution clock in nanoseconds.
    pub fn exec_clock_ns(&self) -> u64 {
        self.exec_clock_ns
    }
}

// ======================================================================
// RT runqueue stats
// ======================================================================

/// Real-time runqueue statistics.
#[derive(Debug, Clone, Copy)]
pub struct RtRqStats {
    /// Number of RT tasks currently runnable.
    rt_nr_running: u32,
    /// Whether RT bandwidth throttling is active.
    rt_throttled: bool,
    /// RT time consumed in the current period (ns).
    rt_time_ns: u64,
    /// RT runtime limit per period (ns).
    rt_runtime_ns: u64,
    /// RT period (ns).
    rt_period_ns: u64,
    /// Highest priority RT task queued.
    highest_prio: u32,
}

impl RtRqStats {
    /// Creates zeroed RT stats.
    pub const fn new() -> Self {
        Self {
            rt_nr_running: 0,
            rt_throttled: false,
            rt_time_ns: 0,
            rt_runtime_ns: 950_000_000,  // Default: 0.95s
            rt_period_ns: 1_000_000_000, // Default: 1s
            highest_prio: 100,
        }
    }

    /// Returns the number of running RT tasks.
    pub fn rt_nr_running(&self) -> u32 {
        self.rt_nr_running
    }

    /// Returns whether RT is throttled.
    pub fn is_throttled(&self) -> bool {
        self.rt_throttled
    }

    /// Returns the RT time consumed in nanoseconds.
    pub fn rt_time_ns(&self) -> u64 {
        self.rt_time_ns
    }
}

// ======================================================================
// Deadline runqueue stats
// ======================================================================

/// SCHED_DEADLINE runqueue statistics.
#[derive(Debug, Clone, Copy)]
pub struct DlRqStats {
    /// Number of deadline tasks runnable.
    dl_nr_running: u32,
    /// Whether any DL task has overrun its runtime.
    dl_throttled: bool,
    /// Earliest deadline in the queue (ns).
    earliest_deadline_ns: u64,
    /// Total DL bandwidth used (fraction * 2^20).
    dl_bw: u64,
}

impl DlRqStats {
    /// Creates zeroed DL stats.
    pub const fn new() -> Self {
        Self {
            dl_nr_running: 0,
            dl_throttled: false,
            earliest_deadline_ns: u64::MAX,
            dl_bw: 0,
        }
    }

    /// Returns the number of running DL tasks.
    pub fn dl_nr_running(&self) -> u32 {
        self.dl_nr_running
    }

    /// Returns the earliest deadline.
    pub fn earliest_deadline_ns(&self) -> u64 {
        self.earliest_deadline_ns
    }
}

// ======================================================================
// Per-CPU runqueue dump
// ======================================================================

/// Complete per-CPU runqueue debug dump.
pub struct CpuRqDump {
    /// CPU index.
    cpu: u32,
    /// Total number of runnable tasks (all classes).
    nr_running: u32,
    /// Aggregate CPU load.
    load: u64,
    /// Total context switches on this CPU.
    nr_switches: u64,
    /// Number of tasks in uninterruptible sleep.
    nr_uninterruptible: u32,
    /// Current timestamp in nanoseconds.
    timestamp_ns: u64,
    /// CFS stats.
    cfs: CfsRqStats,
    /// RT stats.
    rt: RtRqStats,
    /// DL stats.
    dl: DlRqStats,
    /// Task list.
    tasks: [TaskSchedInfo; MAX_TASKS_PER_RQ],
    /// Number of valid tasks.
    nr_tasks: usize,
    /// Whether this CPU is online.
    online: bool,
    /// Whether this CPU is idle.
    idle: bool,
}

impl CpuRqDump {
    /// Creates an empty CPU runqueue dump.
    pub const fn new() -> Self {
        Self {
            cpu: 0,
            nr_running: 0,
            load: 0,
            nr_switches: 0,
            nr_uninterruptible: 0,
            timestamp_ns: 0,
            cfs: CfsRqStats::new(),
            rt: RtRqStats::new(),
            dl: DlRqStats::new(),
            tasks: [const { TaskSchedInfo::new() }; MAX_TASKS_PER_RQ],
            nr_tasks: 0,
            online: false,
            idle: false,
        }
    }

    /// Returns the CPU index.
    pub fn cpu(&self) -> u32 {
        self.cpu
    }

    /// Returns the number of running tasks.
    pub fn nr_running(&self) -> u32 {
        self.nr_running
    }

    /// Returns the CPU load.
    pub fn load(&self) -> u64 {
        self.load
    }

    /// Returns the total context switches.
    pub fn nr_switches(&self) -> u64 {
        self.nr_switches
    }

    /// Returns the CFS stats.
    pub fn cfs(&self) -> &CfsRqStats {
        &self.cfs
    }

    /// Returns the RT stats.
    pub fn rt(&self) -> &RtRqStats {
        &self.rt
    }

    /// Returns the DL stats.
    pub fn dl(&self) -> &DlRqStats {
        &self.dl
    }

    /// Returns the number of tasks in the dump.
    pub fn nr_tasks(&self) -> usize {
        self.nr_tasks
    }

    /// Returns a task by index.
    pub fn task(&self, index: usize) -> Option<&TaskSchedInfo> {
        if index >= self.nr_tasks {
            return None;
        }
        Some(&self.tasks[index])
    }

    /// Adds a task to the dump.
    pub fn add_task(&mut self, task: TaskSchedInfo) -> Result<()> {
        if self.nr_tasks >= MAX_TASKS_PER_RQ {
            return Err(Error::OutOfMemory);
        }
        self.tasks[self.nr_tasks] = task;
        self.nr_tasks += 1;
        Ok(())
    }

    /// Returns whether this CPU is online.
    pub fn is_online(&self) -> bool {
        self.online
    }

    /// Returns whether this CPU is idle.
    pub fn is_idle(&self) -> bool {
        self.idle
    }
}

// ======================================================================
// Scheduler debug manager
// ======================================================================

/// Collects and presents scheduler debug information.
pub struct SchedDebug {
    /// Per-CPU runqueue dumps.
    cpus: [CpuRqDump; MAX_CPUS],
    /// Number of online CPUs.
    nr_online: u32,
    /// Kernel scheduler version string.
    version: [u8; 32],
    /// Version string length.
    version_len: usize,
    /// Global scheduler clock in nanoseconds.
    sched_clock_ns: u64,
    /// Total number of forks since boot.
    total_forks: u64,
    /// Total number of context switches since boot.
    total_switches: u64,
}

impl SchedDebug {
    /// Creates a new scheduler debug instance.
    pub const fn new() -> Self {
        Self {
            cpus: [const { CpuRqDump::new() }; MAX_CPUS],
            nr_online: 0,
            version: [0u8; 32],
            version_len: 0,
            sched_clock_ns: 0,
            total_forks: 0,
            total_switches: 0,
        }
    }

    /// Sets the version string.
    pub fn set_version(&mut self, ver: &[u8]) -> Result<()> {
        if ver.len() > 32 {
            return Err(Error::InvalidArgument);
        }
        self.version[..ver.len()].copy_from_slice(ver);
        self.version_len = ver.len();
        Ok(())
    }

    /// Returns the version string.
    pub fn version(&self) -> &[u8] {
        &self.version[..self.version_len]
    }

    /// Returns the number of online CPUs.
    pub fn nr_online(&self) -> u32 {
        self.nr_online
    }

    /// Returns the global scheduler clock.
    pub fn sched_clock_ns(&self) -> u64 {
        self.sched_clock_ns
    }

    /// Returns the total fork count.
    pub fn total_forks(&self) -> u64 {
        self.total_forks
    }

    /// Returns the total context switch count.
    pub fn total_switches(&self) -> u64 {
        self.total_switches
    }

    /// Returns a reference to a CPU's dump.
    pub fn cpu_dump(&self, cpu: u32) -> Result<&CpuRqDump> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.cpus[cpu as usize])
    }

    /// Returns a mutable reference to a CPU's dump.
    pub fn cpu_dump_mut(&mut self, cpu: u32) -> Result<&mut CpuRqDump> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.cpus[cpu as usize])
    }

    /// Refreshes the debug snapshot for all CPUs.
    pub fn refresh(&mut self, nr_online: u32, sched_clock_ns: u64) -> Result<()> {
        if nr_online as usize > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.nr_online = nr_online;
        self.sched_clock_ns = sched_clock_ns;
        // Reset counters from per-CPU data.
        self.total_switches = 0;
        for i in 0..nr_online as usize {
            if self.cpus[i].online {
                self.total_switches = self.total_switches.saturating_add(self.cpus[i].nr_switches);
            }
        }
        Ok(())
    }

    /// Sets a CPU as online and initializes its dump.
    pub fn set_cpu_online(&mut self, cpu: u32, nr_running: u32, load: u64) -> Result<()> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let idx = cpu as usize;
        self.cpus[idx].cpu = cpu;
        self.cpus[idx].online = true;
        self.cpus[idx].nr_running = nr_running;
        self.cpus[idx].load = load;
        self.cpus[idx].nr_tasks = 0;
        Ok(())
    }

    /// Sets a CPU as offline.
    pub fn set_cpu_offline(&mut self, cpu: u32) -> Result<()> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[cpu as usize].online = false;
        Ok(())
    }

    /// Updates CFS stats for a CPU.
    pub fn update_cfs(&mut self, cpu: u32, stats: CfsRqStats) -> Result<()> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[cpu as usize].cfs = stats;
        Ok(())
    }

    /// Updates RT stats for a CPU.
    pub fn update_rt(&mut self, cpu: u32, stats: RtRqStats) -> Result<()> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[cpu as usize].rt = stats;
        Ok(())
    }

    /// Updates DL stats for a CPU.
    pub fn update_dl(&mut self, cpu: u32, stats: DlRqStats) -> Result<()> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[cpu as usize].dl = stats;
        Ok(())
    }
}
