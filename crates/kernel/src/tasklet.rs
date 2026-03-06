// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Tasklet mechanism — deferred work running in softirq context.
//!
//! Tasklets are the classic Linux bottom-half mechanism built on top of
//! the `TASKLET_SOFTIRQ` and `HI_SOFTIRQ` vectors.  Each tasklet has:
//! - A callback function (`TaskletFn`)
//! - A 64-bit data argument
//! - An atomic state (disabled, pending, running)
//!
//! Tasklets are guaranteed single-threaded: a tasklet never runs on more
//! than one CPU at a time. High-priority tasklets use the `HI_SOFTIRQ`
//! vector and are processed before normal ones.

use core::sync::atomic::{AtomicU32, Ordering};

use oncrix_lib::{Error, Result};

/// Maximum number of tasklets in a per-CPU run list.
pub const TASKLET_MAX_PER_CPU: usize = 256;

/// Tasklet callback function signature.
pub type TaskletFn = fn(data: u64);

/// Tasklet state bits.
mod state {
    /// Set while the tasklet is running.
    pub const RUNNING: u32 = 1 << 0;
    /// Set when the tasklet has been scheduled (pending execution).
    pub const PENDING: u32 = 1 << 1;
    /// Set to prevent the tasklet from running.
    pub const DISABLED: u32 = 1 << 2;
}

/// A single tasklet descriptor.
pub struct Tasklet {
    /// Callback invoked when the tasklet runs.
    pub func: Option<TaskletFn>,
    /// Opaque data passed to `func`.
    pub data: u64,
    /// Atomic state: RUNNING | PENDING | DISABLED.
    state: AtomicU32,
    /// Whether this is a high-priority tasklet.
    pub hi_prio: bool,
}

impl Tasklet {
    /// Creates a new tasklet (initially disabled, not pending).
    pub const fn new(func: TaskletFn, data: u64, hi_prio: bool) -> Self {
        Self {
            func: Some(func),
            data,
            state: AtomicU32::new(state::DISABLED),
            hi_prio,
        }
    }

    /// Creates an uninitialized (no-op) tasklet.
    pub const fn empty() -> Self {
        Self {
            func: None,
            data: 0,
            state: AtomicU32::new(0),
            hi_prio: false,
        }
    }

    /// Enables the tasklet (allows it to run when pending).
    #[inline]
    pub fn enable(&self) {
        self.state.fetch_and(!state::DISABLED, Ordering::Release);
    }

    /// Disables the tasklet. Returns `true` if it was previously enabled.
    #[inline]
    pub fn disable(&self) -> bool {
        let old = self.state.fetch_or(state::DISABLED, Ordering::Acquire);
        old & state::DISABLED == 0
    }

    /// Schedules the tasklet for execution. Does nothing if already pending.
    ///
    /// Returns `true` if the tasklet was newly scheduled.
    pub fn schedule(&self) -> bool {
        let old = self.state.fetch_or(state::PENDING, Ordering::Release);
        old & state::PENDING == 0
    }

    /// Returns `true` if the tasklet is currently pending.
    #[inline]
    pub fn is_pending(&self) -> bool {
        self.state.load(Ordering::Acquire) & state::PENDING != 0
    }

    /// Returns `true` if the tasklet is disabled.
    #[inline]
    pub fn is_disabled(&self) -> bool {
        self.state.load(Ordering::Acquire) & state::DISABLED != 0
    }

    /// Attempts to execute the tasklet. Returns `true` if it ran.
    ///
    /// The tasklet runs only if: pending AND not disabled AND not already running.
    pub fn try_run(&self) -> bool {
        // Atomically clear PENDING and set RUNNING.
        let old = self.state.load(Ordering::Acquire);
        if old & state::PENDING == 0 || old & state::DISABLED != 0 {
            return false;
        }
        // Try to transition to RUNNING (clear PENDING).
        match self.state.compare_exchange(
            old,
            (old & !state::PENDING) | state::RUNNING,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => {}
            Err(_) => return false,
        }

        // Execute callback.
        if let Some(func) = self.func {
            func(self.data);
        }

        // Clear RUNNING.
        self.state.fetch_and(!state::RUNNING, Ordering::Release);
        true
    }
}

impl Default for Tasklet {
    fn default() -> Self {
        Self::empty()
    }
}

/// Per-CPU tasklet run list.
///
/// Maintains two separate queues: normal priority and high priority.
pub struct TaskletCpu {
    /// High-priority pending tasklets.
    hi_list: [*const Tasklet; TASKLET_MAX_PER_CPU],
    hi_count: usize,
    /// Normal-priority pending tasklets.
    lo_list: [*const Tasklet; TASKLET_MAX_PER_CPU],
    lo_count: usize,
    /// Total executions (for stats).
    executions: u64,
}

// SAFETY: TaskletCpu contains raw pointers to Tasklets that are managed by
// the caller. The caller must ensure Tasklets outlive the per-CPU list.
unsafe impl Send for TaskletCpu {}

impl TaskletCpu {
    /// Creates an empty per-CPU tasklet context.
    pub const fn new() -> Self {
        Self {
            hi_list: [core::ptr::null(); TASKLET_MAX_PER_CPU],
            hi_count: 0,
            lo_list: [core::ptr::null(); TASKLET_MAX_PER_CPU],
            lo_count: 0,
            executions: 0,
        }
    }

    /// Adds a tasklet pointer to the appropriate run list.
    ///
    /// # Safety
    ///
    /// `tasklet` must outlive this `TaskletCpu` and must not be added twice
    /// before being processed.
    pub unsafe fn add(&mut self, tasklet: *const Tasklet) -> Result<()> {
        // SAFETY: Caller guarantees the pointer is valid.
        let hi = unsafe { (*tasklet).hi_prio };
        if hi {
            if self.hi_count >= TASKLET_MAX_PER_CPU {
                return Err(Error::OutOfMemory);
            }
            self.hi_list[self.hi_count] = tasklet;
            self.hi_count += 1;
        } else {
            if self.lo_count >= TASKLET_MAX_PER_CPU {
                return Err(Error::OutOfMemory);
            }
            self.lo_list[self.lo_count] = tasklet;
            self.lo_count += 1;
        }
        Ok(())
    }

    /// Runs all pending tasklets — high-priority first, then normal.
    ///
    /// Returns the total number of tasklets that executed.
    pub fn run_all(&mut self) -> usize {
        let mut ran = 0usize;

        // Process hi-priority.
        let hi_count = self.hi_count;
        self.hi_count = 0;
        for i in 0..hi_count {
            let ptr = self.hi_list[i];
            if ptr.is_null() {
                continue;
            }
            // SAFETY: Caller guarantees the pointer is valid for the lifetime
            // of this TaskletCpu. We only dereference to call try_run().
            if unsafe { (*ptr).try_run() } {
                ran += 1;
                self.executions += 1;
            } else {
                // Re-queue: tasklet was disabled or lost CAS race.
                if self.hi_count < TASKLET_MAX_PER_CPU {
                    self.hi_list[self.hi_count] = ptr;
                    self.hi_count += 1;
                }
            }
        }

        // Process normal priority.
        let lo_count = self.lo_count;
        self.lo_count = 0;
        for i in 0..lo_count {
            let ptr = self.lo_list[i];
            if ptr.is_null() {
                continue;
            }
            // SAFETY: Same as above.
            if unsafe { (*ptr).try_run() } {
                ran += 1;
                self.executions += 1;
            } else {
                if self.lo_count < TASKLET_MAX_PER_CPU {
                    self.lo_list[self.lo_count] = ptr;
                    self.lo_count += 1;
                }
            }
        }

        ran
    }

    /// Returns total tasklet executions on this CPU.
    #[inline]
    pub fn executions(&self) -> u64 {
        self.executions
    }

    /// Returns number of hi-priority tasklets pending.
    #[inline]
    pub fn hi_pending(&self) -> usize {
        self.hi_count
    }

    /// Returns number of normal-priority tasklets pending.
    #[inline]
    pub fn lo_pending(&self) -> usize {
        self.lo_count
    }
}

impl Default for TaskletCpu {
    fn default() -> Self {
        Self::new()
    }
}
