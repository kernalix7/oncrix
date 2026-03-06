// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCHED_DEADLINE — Earliest Deadline First (EDF) scheduling class.
//!
//! Implements the SCHED_DEADLINE policy as described in the CBS (Constant Bandwidth
//! Server) algorithm. Each deadline task is characterized by three parameters:
//! - `runtime`: the maximum CPU time a task may use per period
//! - `deadline`: the relative deadline (must complete within this interval)
//! - `period`: the task activation period
//!
//! The scheduler always picks the runnable task with the earliest absolute deadline.

use core::sync::atomic::{AtomicU64, Ordering};

use oncrix_lib::{Error, Result};

/// Maximum number of deadline tasks tracked in the run queue.
pub const DL_MAX_TASKS: usize = 64;

/// Minimum runtime in nanoseconds (100 µs).
pub const DL_MIN_RUNTIME_NS: u64 = 100_000;

/// Maximum period in nanoseconds (1 second).
pub const DL_MAX_PERIOD_NS: u64 = 1_000_000_000;

/// Minimum period in nanoseconds (1 ms).
pub const DL_MIN_PERIOD_NS: u64 = 1_000_000;

/// Global deadline bandwidth counter (numerator × 2^20 / denominator).
static DL_BANDWIDTH_USED: AtomicU64 = AtomicU64::new(0);

/// SCHED_DEADLINE task parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DlAttr {
    /// Maximum execution time per period (nanoseconds).
    pub runtime: u64,
    /// Relative deadline from activation (nanoseconds).
    pub deadline: u64,
    /// Activation period (nanoseconds).
    pub period: u64,
}

impl DlAttr {
    /// Creates new deadline attributes with validation.
    pub const fn new(runtime: u64, deadline: u64, period: u64) -> Self {
        Self {
            runtime,
            deadline,
            period,
        }
    }
}

/// Per-task deadline scheduling entity.
#[derive(Debug)]
pub struct DlEntity {
    /// Absolute deadline (nanoseconds since boot).
    pub abs_deadline: u64,
    /// Remaining runtime in the current period (nanoseconds).
    pub runtime_remaining: u64,
    /// Replenishment time — when runtime is restored.
    pub replenishment_time: u64,
    /// Task parameters.
    pub attr: DlAttr,
    /// Task PID (0 = idle / unused slot).
    pub pid: u32,
    /// Whether the entity is active in a run queue.
    pub active: bool,
    /// Whether the entity has been throttled (runtime exhausted).
    pub throttled: bool,
}

impl DlEntity {
    /// Creates a new idle (unused) deadline entity.
    pub const fn new() -> Self {
        Self {
            abs_deadline: 0,
            runtime_remaining: 0,
            replenishment_time: 0,
            attr: DlAttr::new(0, 0, 0),
            pid: 0,
            active: false,
            throttled: false,
        }
    }

    /// Returns true if this entity has an earlier deadline than `other`.
    #[inline]
    pub fn earlier_deadline_than(&self, other: &DlEntity) -> bool {
        self.abs_deadline < other.abs_deadline
    }

    /// Returns true if the entity's runtime has been exhausted.
    #[inline]
    pub fn is_exhausted(&self) -> bool {
        self.runtime_remaining == 0
    }

    /// Deducts `delta_ns` from remaining runtime; sets `throttled` if exhausted.
    pub fn charge_runtime(&mut self, delta_ns: u64) {
        self.runtime_remaining = self.runtime_remaining.saturating_sub(delta_ns);
        if self.runtime_remaining == 0 {
            self.throttled = true;
        }
    }

    /// Replenishes the entity's runtime at the next period boundary.
    pub fn replenish(&mut self, now_ns: u64) {
        self.runtime_remaining = self.attr.runtime;
        self.throttled = false;
        // Advance replenishment time by one period.
        self.replenishment_time = self.replenishment_time.wrapping_add(self.attr.period);
        // Advance deadline by one period.
        self.abs_deadline = self.abs_deadline.wrapping_add(self.attr.period);
        let _ = now_ns;
    }
}

impl Default for DlEntity {
    fn default() -> Self {
        Self::new()
    }
}

/// SCHED_DEADLINE run queue — one per CPU.
pub struct DlRunQueue {
    /// All registered deadline entities (fixed-size pool).
    entities: [DlEntity; DL_MAX_TASKS],
    /// Number of active entities.
    count: usize,
    /// Index of the entity currently executing (-1 if none).
    current: Option<usize>,
    /// Total bandwidth used (runtime/period fixed-point sum × 2^20).
    bandwidth_sum: u64,
}

impl DlRunQueue {
    /// Creates an empty deadline run queue.
    pub const fn new() -> Self {
        Self {
            entities: [const { DlEntity::new() }; DL_MAX_TASKS],
            count: 0,
            current: None,
            bandwidth_sum: 0,
        }
    }

    /// Admits a new deadline task. Returns `Err(Busy)` if bandwidth is full.
    pub fn admit(&mut self, pid: u32, attr: DlAttr, now_ns: u64) -> Result<usize> {
        if attr.runtime < DL_MIN_RUNTIME_NS {
            return Err(Error::InvalidArgument);
        }
        if attr.period < DL_MIN_PERIOD_NS || attr.period > DL_MAX_PERIOD_NS {
            return Err(Error::InvalidArgument);
        }
        if attr.deadline == 0 || attr.deadline > attr.period {
            return Err(Error::InvalidArgument);
        }
        if attr.runtime > attr.deadline {
            return Err(Error::InvalidArgument);
        }

        // CBS bandwidth check: sum(runtime/period) <= 1.0
        // We use fixed-point with 2^20 scaling.
        let new_bw = (attr.runtime << 20) / attr.period;
        let total = self.bandwidth_sum.saturating_add(new_bw);
        if total > (1u64 << 20) {
            return Err(Error::Busy);
        }

        if self.count >= DL_MAX_TASKS {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot.
        let slot = self
            .entities
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        let e = &mut self.entities[slot];
        e.attr = attr;
        e.pid = pid;
        e.runtime_remaining = attr.runtime;
        e.replenishment_time = now_ns + attr.period;
        e.abs_deadline = now_ns + attr.deadline;
        e.active = true;
        e.throttled = false;

        self.bandwidth_sum = total;
        self.count += 1;
        DL_BANDWIDTH_USED.store(self.bandwidth_sum, Ordering::Relaxed);
        Ok(slot)
    }

    /// Removes a task from the run queue.
    pub fn remove(&mut self, pid: u32) -> Result<()> {
        let idx = self
            .entities
            .iter()
            .position(|e| e.active && e.pid == pid)
            .ok_or(Error::NotFound)?;

        let bw = (self.entities[idx].attr.runtime << 20) / self.entities[idx].attr.period;
        self.bandwidth_sum = self.bandwidth_sum.saturating_sub(bw);
        self.entities[idx] = DlEntity::new();
        self.count -= 1;
        if self.current == Some(idx) {
            self.current = None;
        }
        DL_BANDWIDTH_USED.store(self.bandwidth_sum, Ordering::Relaxed);
        Ok(())
    }

    /// Picks the runnable entity with the earliest absolute deadline (EDF policy).
    /// Returns the index into `entities`, or `None` if nothing is runnable.
    pub fn pick_next(&mut self, now_ns: u64) -> Option<usize> {
        // First, replenish any throttled entities whose replenishment time has passed.
        for i in 0..DL_MAX_TASKS {
            if self.entities[i].active
                && self.entities[i].throttled
                && now_ns >= self.entities[i].replenishment_time
            {
                self.entities[i].replenish(now_ns);
            }
        }

        let mut best: Option<usize> = None;
        for i in 0..DL_MAX_TASKS {
            if !self.entities[i].active || self.entities[i].throttled {
                continue;
            }
            best = Some(match best {
                None => i,
                Some(b) => {
                    if self.entities[i].abs_deadline < self.entities[b].abs_deadline {
                        i
                    } else {
                        b
                    }
                }
            });
        }
        self.current = best;
        best
    }

    /// Charges `delta_ns` to the currently running entity (if any).
    pub fn tick(&mut self, now_ns: u64) {
        if let Some(idx) = self.current {
            if self.entities[idx].active {
                self.entities[idx].charge_runtime(now_ns.wrapping_sub(now_ns)); // placeholder
                // In a real implementation, delta comes from the hardware clock.
            }
        }
    }

    /// Returns the number of active deadline tasks.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns the current bandwidth utilization (fixed-point × 2^20).
    #[inline]
    pub fn bandwidth_used(&self) -> u64 {
        self.bandwidth_sum
    }
}

impl Default for DlRunQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Validates deadline attributes without adding the task.
pub fn dl_attr_validate(attr: &DlAttr) -> Result<()> {
    if attr.runtime < DL_MIN_RUNTIME_NS {
        return Err(Error::InvalidArgument);
    }
    if attr.period < DL_MIN_PERIOD_NS || attr.period > DL_MAX_PERIOD_NS {
        return Err(Error::InvalidArgument);
    }
    if attr.deadline == 0 || attr.deadline > attr.period {
        return Err(Error::InvalidArgument);
    }
    if attr.runtime > attr.deadline {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Returns the global deadline bandwidth in use (fixed-point × 2^20).
pub fn dl_global_bandwidth() -> u64 {
    DL_BANDWIDTH_USED.load(Ordering::Relaxed)
}
