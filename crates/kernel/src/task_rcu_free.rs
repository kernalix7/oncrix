// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Task struct RCU-delayed freeing.
//!
//! When a task exits, its `task_struct` equivalent cannot be freed
//! immediately because other CPUs may still hold RCU-read-side
//! references (e.g. iterating the task list, reading `/proc`).
//! Instead, the task is enqueued in an RCU callback queue and its
//! memory is released only after the current RCU grace period
//! completes.
//!
//! # Design
//!
//! ```text
//! TaskRcuFreeSubsystem
//! ├── per_cpu_queues[MAX_CPUS]
//! │   ├── pending[MAX_PER_CPU]    queued task descriptors
//! │   ├── head / tail / count     FIFO management
//! │   └── generation              current RCU generation
//! ├── global_generation           latest committed GP
//! ├── stats: TaskRcuStats
//! └── Methods:
//!     ├── enqueue_task(pid, cpu)      queue for deferred free
//!     ├── advance_grace_period()      commit current GP
//!     ├── process_callbacks(cpu)      free expired tasks
//!     └── pending_count(cpu)          per-CPU query
//! ```
//!
//! # Reference
//!
//! Linux `kernel/fork.c` (`delayed_put_task_struct`,
//! `call_rcu`), `include/linux/rcupdate.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum CPUs supported.
const MAX_CPUS: usize = 64;

/// Maximum pending tasks per CPU queue.
const MAX_PER_CPU: usize = 128;

/// Batch limit when processing callbacks to avoid holding the
/// CPU for too long.
const PROCESS_BATCH_LIMIT: usize = 32;

// ══════════════════════════════════════════════════════════════
// TaskFreeState
// ══════════════════════════════════════════════════════════════

/// State of a queued task-free callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum TaskFreeState {
    /// Slot is empty.
    #[default]
    Empty = 0,
    /// Task is queued, waiting for its grace period to expire.
    Queued = 1,
    /// Grace period has elapsed; ready to be freed.
    Ready = 2,
    /// Freed (callback executed).
    Freed = 3,
}

// ══════════════════════════════════════════════════════════════
// TaskFreeEntry
// ══════════════════════════════════════════════════════════════

/// A single queued task awaiting RCU-deferred freeing.
#[derive(Debug, Clone, Copy)]
struct TaskFreeEntry {
    /// PID of the exited task (for identification / logging).
    pid: u64,
    /// The RCU generation at which this entry was enqueued.
    enqueue_generation: u64,
    /// Timestamp (nanoseconds) when the task exited.
    exit_timestamp_ns: u64,
    /// Size in bytes of the task struct memory.
    task_size: usize,
    /// Current state.
    state: TaskFreeState,
}

impl TaskFreeEntry {
    const fn empty() -> Self {
        Self {
            pid: 0,
            enqueue_generation: 0,
            exit_timestamp_ns: 0,
            task_size: 0,
            state: TaskFreeState::Empty,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PerCpuQueue
// ══════════════════════════════════════════════════════════════

/// Per-CPU queue of pending task-free callbacks.
struct PerCpuQueue {
    /// Circular buffer of entries.
    entries: [TaskFreeEntry; MAX_PER_CPU],
    /// Read (head) position — next to process.
    head: usize,
    /// Write (tail) position — next insert.
    tail: usize,
    /// Current number of queued (non-freed) entries.
    count: u32,
    /// RCU generation observed when last callback was enqueued.
    last_enqueue_generation: u64,
    /// Total entries ever enqueued on this CPU.
    total_enqueued: u64,
    /// Total entries freed on this CPU.
    total_freed: u64,
}

impl PerCpuQueue {
    const fn new() -> Self {
        Self {
            entries: [const { TaskFreeEntry::empty() }; MAX_PER_CPU],
            head: 0,
            tail: 0,
            count: 0,
            last_enqueue_generation: 0,
            total_enqueued: 0,
            total_freed: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TaskRcuStats
// ══════════════════════════════════════════════════════════════

/// Aggregate statistics for the task RCU free subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct TaskRcuStats {
    /// Total tasks enqueued for deferred freeing.
    pub total_enqueued: u64,
    /// Total tasks whose memory has been freed.
    pub total_freed: u64,
    /// Grace periods completed.
    pub grace_periods_completed: u64,
    /// Process-callback invocations.
    pub process_calls: u64,
    /// Tasks freed in the most recent process call.
    pub last_batch_freed: u32,
    /// Enqueue rejections (queue full).
    pub enqueue_rejected: u64,
    /// Peak pending count observed across all CPUs.
    pub peak_pending: u32,
    /// Total bytes of task memory freed.
    pub bytes_freed: u64,
}

// ══════════════════════════════════════════════════════════════
// TaskRcuFreeSubsystem
// ══════════════════════════════════════════════════════════════

/// Manages RCU-deferred freeing of exited task structures.
pub struct TaskRcuFreeSubsystem {
    /// Per-CPU callback queues.
    queues: [PerCpuQueue; MAX_CPUS],
    /// Global RCU generation counter. Incremented each time
    /// [`advance_grace_period`] is called.
    global_generation: u64,
    /// Number of online CPUs.
    online_cpus: u32,
    /// Aggregate statistics.
    stats: TaskRcuStats,
    /// Whether the subsystem has been initialised.
    initialised: bool,
}

impl Default for TaskRcuFreeSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskRcuFreeSubsystem {
    /// Create a new, uninitialised subsystem.
    pub const fn new() -> Self {
        Self {
            queues: [const { PerCpuQueue::new() }; MAX_CPUS],
            global_generation: 0,
            online_cpus: 1,
            stats: TaskRcuStats {
                total_enqueued: 0,
                total_freed: 0,
                grace_periods_completed: 0,
                process_calls: 0,
                last_batch_freed: 0,
                enqueue_rejected: 0,
                peak_pending: 0,
                bytes_freed: 0,
            },
            initialised: false,
        }
    }

    /// Initialise the subsystem with the given number of online
    /// CPUs.
    pub fn init(&mut self, online_cpus: u32) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        if online_cpus == 0 || online_cpus as usize > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.online_cpus = online_cpus;
        self.initialised = true;
        Ok(())
    }

    /// Enqueue an exited task for RCU-deferred freeing.
    ///
    /// `pid` identifies the task, `cpu` is the CPU on whose queue
    /// the callback is placed, `task_size` is the memory footprint
    /// to free, and `exit_ts_ns` is the exit timestamp.
    pub fn enqueue_task(
        &mut self,
        pid: u64,
        cpu: u32,
        task_size: usize,
        exit_ts_ns: u64,
    ) -> Result<()> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        if cpu >= self.online_cpus || (cpu as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        let q = &mut self.queues[cpu as usize];

        if q.count as usize >= MAX_PER_CPU {
            self.stats.enqueue_rejected += 1;
            return Err(Error::OutOfMemory);
        }

        let slot = q.tail % MAX_PER_CPU;
        q.entries[slot] = TaskFreeEntry {
            pid,
            enqueue_generation: self.global_generation,
            exit_timestamp_ns: exit_ts_ns,
            task_size,
            state: TaskFreeState::Queued,
        };

        q.tail += 1;
        q.count += 1;
        q.last_enqueue_generation = self.global_generation;
        q.total_enqueued += 1;

        self.stats.total_enqueued += 1;

        if q.count > self.stats.peak_pending {
            self.stats.peak_pending = q.count;
        }

        Ok(())
    }

    /// Advance the global RCU grace period.
    ///
    /// After this call, all entries enqueued before the previous
    /// generation become eligible for freeing.
    pub fn advance_grace_period(&mut self) -> Result<u64> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }

        self.global_generation += 1;
        self.stats.grace_periods_completed += 1;

        // Mark entries whose grace period has elapsed as Ready.
        let committed = self.global_generation;
        for cpu_idx in 0..self.online_cpus as usize {
            let q = &mut self.queues[cpu_idx];
            let mut idx = q.head;
            let end = q.tail;

            while idx < end {
                let slot = idx % MAX_PER_CPU;
                let entry = &mut q.entries[slot];
                if entry.state == TaskFreeState::Queued && entry.enqueue_generation < committed {
                    entry.state = TaskFreeState::Ready;
                }
                idx += 1;
            }
        }

        Ok(committed)
    }

    /// Process callbacks on a specific CPU, freeing tasks whose
    /// grace period has elapsed.
    ///
    /// Returns the number of tasks freed in this invocation.
    pub fn process_callbacks(&mut self, cpu: u32) -> Result<u32> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        if cpu >= self.online_cpus || (cpu as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        self.stats.process_calls += 1;

        let q = &mut self.queues[cpu as usize];
        let mut freed: u32 = 0;
        let mut processed: usize = 0;

        while q.head < q.tail && processed < PROCESS_BATCH_LIMIT {
            let slot = q.head % MAX_PER_CPU;
            let entry = &mut q.entries[slot];

            match entry.state {
                TaskFreeState::Ready => {
                    let size = entry.task_size;
                    entry.state = TaskFreeState::Freed;
                    q.head += 1;
                    q.count = q.count.saturating_sub(1);
                    q.total_freed += 1;
                    freed += 1;
                    self.stats.total_freed += 1;
                    self.stats.bytes_freed += size as u64;
                }
                TaskFreeState::Queued => {
                    // Not yet eligible — stop processing
                    // (FIFO ordering guarantee).
                    break;
                }
                _ => {
                    // Skip freed/empty entries.
                    q.head += 1;
                    q.count = q.count.saturating_sub(1);
                }
            }
            processed += 1;
        }

        self.stats.last_batch_freed = freed;
        Ok(freed)
    }

    /// Return the number of pending (not yet freed) entries on a
    /// specific CPU.
    pub fn pending_count(&self, cpu: u32) -> Result<u32> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.queues[cpu as usize].count)
    }

    /// Return the total pending count across all online CPUs.
    pub fn total_pending(&self) -> u32 {
        let mut total: u32 = 0;
        for i in 0..self.online_cpus as usize {
            total += self.queues[i].count;
        }
        total
    }

    /// Return the current global RCU generation.
    pub fn global_generation(&self) -> u64 {
        self.global_generation
    }

    /// Return the number of online CPUs.
    pub fn online_cpus(&self) -> u32 {
        self.online_cpus
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> &TaskRcuStats {
        &self.stats
    }

    /// Drain all pending callbacks on all CPUs regardless of
    /// grace period state. Used during shutdown.
    ///
    /// Returns the total number of entries drained.
    pub fn drain_all(&mut self) -> u64 {
        let mut drained: u64 = 0;

        for cpu_idx in 0..self.online_cpus as usize {
            let q = &mut self.queues[cpu_idx];

            while q.head < q.tail {
                let slot = q.head % MAX_PER_CPU;
                let entry = &mut q.entries[slot];

                if entry.state == TaskFreeState::Queued || entry.state == TaskFreeState::Ready {
                    let size = entry.task_size;
                    entry.state = TaskFreeState::Freed;
                    q.total_freed += 1;
                    self.stats.total_freed += 1;
                    self.stats.bytes_freed += size as u64;
                    drained += 1;
                }
                q.head += 1;
                q.count = q.count.saturating_sub(1);
            }
        }

        drained
    }

    /// Reset the subsystem (for testing / reinitialisation).
    pub fn reset(&mut self) {
        for cpu_idx in 0..MAX_CPUS {
            let q = &mut self.queues[cpu_idx];
            q.head = 0;
            q.tail = 0;
            q.count = 0;
            q.total_enqueued = 0;
            q.total_freed = 0;
            q.last_enqueue_generation = 0;
        }
        self.global_generation = 0;
        self.stats = TaskRcuStats::default();
        self.initialised = false;
    }
}
