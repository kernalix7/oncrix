// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Stop-task scheduling class.
//!
//! The stop class is the highest-priority scheduling class in the kernel.
//! It is used for stop-machine operations, CPU hotplug, and other tasks that
//! must run before any other task — including real-time and deadline tasks.
//!
//! Each CPU has at most one stop task. When a stop task is queued, it
//! preempts everything and runs to completion before any other task resumes.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use oncrix_lib::{Error, Result};

/// Maximum CPUs supported.
pub const STOP_MAX_CPUS: usize = 256;

/// Stop task priority level (higher than RT, deadline, fair, idle).
pub const STOP_SCHED_PRIO: i32 = -1;

/// A work item to be executed by a stop task.
pub type StopFn = fn(data: u64) -> i32;

/// Single stop-machine work item.
#[derive(Clone, Copy)]
pub struct StopWork {
    /// Callback to invoke on the target CPU.
    pub func: Option<StopFn>,
    /// Opaque argument passed to `func`.
    pub arg: u64,
    /// Target CPU index.
    pub cpu: u32,
    /// Return code after execution.
    pub ret: i32,
    /// Whether this work item has been completed.
    pub done: bool,
}

impl StopWork {
    /// Creates a new work item targeting `cpu`.
    pub const fn new(cpu: u32, func: StopFn, arg: u64) -> Self {
        Self {
            func: Some(func),
            arg,
            cpu,
            ret: 0,
            done: false,
        }
    }

    /// Creates an empty / unused work item.
    pub const fn empty() -> Self {
        Self {
            func: None,
            arg: 0,
            cpu: 0,
            ret: 0,
            done: false,
        }
    }
}

/// Per-CPU stop-task state.
pub struct StopCpu {
    /// Pending work item (one at a time per CPU).
    pending: Option<StopWork>,
    /// Number of stop operations executed on this CPU.
    executions: u64,
    /// Whether this CPU is currently stopped.
    stopped: AtomicBool,
}

impl StopCpu {
    /// Creates a new idle stop-CPU state.
    pub const fn new() -> Self {
        Self {
            pending: None,
            executions: 0,
            stopped: AtomicBool::new(false),
        }
    }

    /// Queues work for this CPU. Returns `Err(Busy)` if already occupied.
    pub fn queue(&mut self, work: StopWork) -> Result<()> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        self.pending = Some(work);
        Ok(())
    }

    /// Executes the pending work item and returns its return code.
    /// Returns `Err(NotFound)` if there is nothing queued.
    pub fn execute(&mut self) -> Result<i32> {
        let work = self.pending.take().ok_or(Error::NotFound)?;
        self.stopped.store(true, Ordering::SeqCst);
        let ret = if let Some(func) = work.func {
            func(work.arg)
        } else {
            0
        };
        self.stopped.store(false, Ordering::SeqCst);
        self.executions += 1;
        Ok(ret)
    }

    /// Returns `true` if this CPU is currently executing a stop task.
    #[inline]
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// Returns the total number of stop executions on this CPU.
    #[inline]
    pub fn executions(&self) -> u64 {
        self.executions
    }

    /// Returns `true` if there is a pending work item.
    #[inline]
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
}

impl Default for StopCpu {
    fn default() -> Self {
        Self::new()
    }
}

/// Global stop-machine state tracking active CPUs.
static STOP_ACTIVE_CPUS: AtomicU64 = AtomicU64::new(0);

/// Per-CPU stop task array (indexed by CPU id).
pub struct StopMachine {
    cpus: [StopCpu; STOP_MAX_CPUS],
    nr_cpus: usize,
}

impl StopMachine {
    /// Creates a new stop-machine context for `nr_cpus` CPUs.
    pub const fn new(nr_cpus: usize) -> Self {
        Self {
            cpus: [const { StopCpu::new() }; STOP_MAX_CPUS],
            nr_cpus,
        }
    }

    /// Queues `work` on the target CPU specified in `work.cpu`.
    pub fn queue_on_cpu(&mut self, work: StopWork) -> Result<()> {
        let cpu = work.cpu as usize;
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        self.cpus[cpu].queue(work)
    }

    /// Runs the pending stop work on `cpu_id`.
    pub fn run_on_cpu(&mut self, cpu_id: usize) -> Result<i32> {
        if cpu_id >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        STOP_ACTIVE_CPUS.fetch_or(1 << (cpu_id % 64), Ordering::SeqCst);
        let ret = self.cpus[cpu_id].execute();
        STOP_ACTIVE_CPUS.fetch_and(!(1 << (cpu_id % 64)), Ordering::SeqCst);
        ret
    }

    /// Returns `true` if any CPU is currently running a stop task.
    pub fn any_stopped(&self) -> bool {
        STOP_ACTIVE_CPUS.load(Ordering::Acquire) != 0
    }

    /// Returns `true` if the given CPU has a pending stop work item.
    pub fn cpu_has_pending(&self, cpu_id: usize) -> bool {
        if cpu_id >= self.nr_cpus {
            return false;
        }
        self.cpus[cpu_id].has_pending()
    }

    /// Returns the execution count for the given CPU.
    pub fn cpu_executions(&self, cpu_id: usize) -> u64 {
        if cpu_id >= self.nr_cpus {
            return 0;
        }
        self.cpus[cpu_id].executions()
    }

    /// Stops all CPUs, executes the provided function on each, then restarts.
    /// In a real system this would involve IPI delivery; here we simulate it.
    pub fn stop_cpus_sync(&mut self, func: StopFn, arg: u64) -> Result<()> {
        for cpu in 0..self.nr_cpus {
            let work = StopWork::new(cpu as u32, func, arg);
            self.queue_on_cpu(work)?;
        }
        for cpu in 0..self.nr_cpus {
            self.run_on_cpu(cpu)?;
        }
        Ok(())
    }
}

/// Stop-class priority check: always higher priority than everything else.
#[inline]
pub fn is_stop_class_prio(prio: i32) -> bool {
    prio == STOP_SCHED_PRIO
}
