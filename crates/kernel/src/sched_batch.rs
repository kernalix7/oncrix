// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCHED_BATCH scheduling policy.
//!
//! Implements the SCHED_BATCH scheduling class for throughput-oriented
//! workloads. Batch tasks never preempt interactive tasks and receive
//! a longer time-slice to reduce context-switch overhead, at the cost
//! of higher latency.
//!
//! # Design
//!
//! ```text
//! BatchScheduler
//!  ├── run_queue: [BatchTask; MAX_BATCH_TASKS]
//!  ├── nr_running: u32
//!  └── total_weight: u64
//!
//! BatchTask
//!  ├── pid: u64
//!  ├── nice: i8            (-20 .. 19)
//!  ├── vruntime: u64       (virtual runtime in ns)
//!  ├── timeslice_ns: u64   (remaining slice)
//!  └── state: BatchTaskState
//! ```
//!
//! Batch tasks use CFS-like virtual runtime tracking but with a
//! longer base slice (10ms vs 4ms for normal SCHED_OTHER tasks).

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum batch tasks in the run queue.
const MAX_BATCH_TASKS: usize = 256;

/// Base time slice for batch tasks (10 ms in nanoseconds).
const BASE_TIMESLICE_NS: u64 = 10_000_000;

/// Minimum nice value.
const NICE_MIN: i8 = -20;

/// Maximum nice value.
const NICE_MAX: i8 = 19;

/// Weight table for nice values (-20..19 mapped to indices 0..39).
const NICE_TO_WEIGHT: [u64; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

// ======================================================================
// Types
// ======================================================================

/// State of a batch task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchTaskState {
    /// Task is runnable and in the run queue.
    Runnable,
    /// Task is currently executing on a CPU.
    Running,
    /// Task is sleeping / blocked.
    Sleeping,
    /// Task has exited.
    Dead,
}

impl Default for BatchTaskState {
    fn default() -> Self {
        Self::Runnable
    }
}

/// A single batch-scheduled task.
#[derive(Debug, Clone, Copy)]
pub struct BatchTask {
    /// Process identifier.
    pub pid: u64,
    /// Nice value (-20..19).
    pub nice: i8,
    /// Virtual runtime in nanoseconds.
    pub vruntime: u64,
    /// Remaining time slice in nanoseconds.
    pub timeslice_ns: u64,
    /// Current task state.
    pub state: BatchTaskState,
    /// Scheduling weight derived from nice value.
    pub weight: u64,
    /// Wall-clock time consumed so far (ns).
    pub sum_exec_ns: u64,
}

impl BatchTask {
    /// Creates a new batch task with default settings.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            nice: 0,
            vruntime: 0,
            timeslice_ns: BASE_TIMESLICE_NS,
            state: BatchTaskState::Runnable,
            weight: 1024,
            sum_exec_ns: 0,
        }
    }

    /// Creates a batch task with the given PID and nice value.
    pub fn with_pid_nice(pid: u64, nice: i8) -> Result<Self> {
        if nice < NICE_MIN || nice > NICE_MAX {
            return Err(Error::InvalidArgument);
        }
        let idx = (nice - NICE_MIN) as usize;
        Ok(Self {
            pid,
            nice,
            vruntime: 0,
            timeslice_ns: BASE_TIMESLICE_NS,
            state: BatchTaskState::Runnable,
            weight: NICE_TO_WEIGHT[idx],
            sum_exec_ns: 0,
        })
    }
}

impl Default for BatchTask {
    fn default() -> Self {
        Self::new()
    }
}

/// SCHED_BATCH run-queue and scheduler.
pub struct BatchScheduler {
    /// Task array acting as a run queue.
    tasks: [BatchTask; MAX_BATCH_TASKS],
    /// Number of tasks currently in the run queue.
    nr_running: u32,
    /// Total scheduling weight of all runnable tasks.
    total_weight: u64,
    /// Minimum virtual runtime (for new task placement).
    min_vruntime: u64,
}

impl BatchScheduler {
    /// Creates a new empty batch scheduler.
    pub const fn new() -> Self {
        Self {
            tasks: [BatchTask::new(); MAX_BATCH_TASKS],
            nr_running: 0,
            total_weight: 0,
            min_vruntime: 0,
        }
    }

    /// Enqueues a new batch task.
    pub fn enqueue(&mut self, pid: u64, nice: i8) -> Result<()> {
        if (self.nr_running as usize) >= MAX_BATCH_TASKS {
            return Err(Error::OutOfMemory);
        }
        let mut task = BatchTask::with_pid_nice(pid, nice)?;
        task.vruntime = self.min_vruntime;
        let idx = self.nr_running as usize;
        self.tasks[idx] = task;
        self.nr_running += 1;
        self.total_weight += task.weight;
        Ok(())
    }

    /// Dequeues a task by PID.
    pub fn dequeue(&mut self, pid: u64) -> Result<BatchTask> {
        let pos = self.tasks[..self.nr_running as usize]
            .iter()
            .position(|t| t.pid == pid)
            .ok_or(Error::NotFound)?;

        let task = self.tasks[pos];
        self.total_weight = self.total_weight.saturating_sub(task.weight);

        // Compact: move last element into the vacated slot.
        let last = (self.nr_running as usize) - 1;
        if pos != last {
            self.tasks[pos] = self.tasks[last];
        }
        self.tasks[last] = BatchTask::new();
        self.nr_running -= 1;
        Ok(task)
    }

    /// Picks the task with the smallest virtual runtime.
    pub fn pick_next(&mut self) -> Result<u64> {
        if self.nr_running == 0 {
            return Err(Error::NotFound);
        }
        let mut best_idx = 0;
        let mut best_vrt = u64::MAX;
        for i in 0..(self.nr_running as usize) {
            if self.tasks[i].state == BatchTaskState::Runnable && self.tasks[i].vruntime < best_vrt
            {
                best_vrt = self.tasks[i].vruntime;
                best_idx = i;
            }
        }
        if best_vrt == u64::MAX {
            return Err(Error::NotFound);
        }
        self.tasks[best_idx].state = BatchTaskState::Running;
        Ok(self.tasks[best_idx].pid)
    }

    /// Updates a running task after it consumed `delta_ns` of CPU.
    pub fn task_tick(&mut self, pid: u64, delta_ns: u64) -> Result<bool> {
        let pos = self.tasks[..self.nr_running as usize]
            .iter()
            .position(|t| t.pid == pid)
            .ok_or(Error::NotFound)?;

        let task = &mut self.tasks[pos];
        task.sum_exec_ns += delta_ns;

        // Scale vruntime by inverse weight (higher weight → slower).
        let weighted_delta = if task.weight > 0 {
            (delta_ns * 1024) / task.weight
        } else {
            delta_ns
        };
        task.vruntime += weighted_delta;

        // Update global min_vruntime.
        if task.vruntime > self.min_vruntime {
            self.min_vruntime = task.vruntime;
        }

        // Check if timeslice exhausted.
        if delta_ns >= task.timeslice_ns {
            task.timeslice_ns = BASE_TIMESLICE_NS;
            task.state = BatchTaskState::Runnable;
            return Ok(true); // needs reschedule
        }
        task.timeslice_ns -= delta_ns;
        Ok(false)
    }

    /// Returns the number of running tasks.
    pub fn nr_running(&self) -> u32 {
        self.nr_running
    }

    /// Returns the current minimum virtual runtime.
    pub fn min_vruntime(&self) -> u64 {
        self.min_vruntime
    }
}

impl Default for BatchScheduler {
    fn default() -> Self {
        Self::new()
    }
}
