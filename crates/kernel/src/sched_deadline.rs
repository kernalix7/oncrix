// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCHED_DEADLINE scheduling class -- Earliest Deadline First with CBS.
//!
//! Implements the SCHED_DEADLINE policy using the Constant Bandwidth
//! Server (CBS) algorithm, modelled after Linux `kernel/sched/deadline.c`.
//!
//! Each task declares three parameters:
//! - **runtime**: maximum CPU time per period (budget)
//! - **deadline**: relative deadline from activation
//! - **period**: task activation period
//!
//! The CBS ensures bandwidth isolation: when a task exhausts its budget
//! its absolute deadline is postponed rather than allowing it to steal
//! time from other tasks.  Admission control rejects tasks whose
//! cumulative utilisation exceeds a configurable cap.
//!
//! # Architecture
//!
//! ```text
//! DeadlineScheduler
//!  +-- DlRunqueue[MAX_CPUS]
//!  |    +-- entries: [DlEntry; MAX_DL_TASKS]
//!  |    +-- sorted: [u16; MAX_DL_TASKS]  (earliest-deadline-first order)
//!  |    +-- AdmissionCtrl (per-cpu utilisation tracking)
//!  +-- DlGlobalStats (aggregate counters)
//! ```
//!
//! Reference: Linux `kernel/sched/deadline.c`,
//! `Documentation/scheduler/sched-deadline.rst`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum CPUs supported.
const MAX_CPUS: usize = 64;

/// Maximum deadline tasks per run-queue.
const MAX_DL_TASKS: usize = 128;

/// Maximum bandwidth (parts per million, 950000 = 95%).
const MAX_BW_PPM: u64 = 950_000;

/// Minimum allowed runtime in nanoseconds (100 us).
const _MIN_RUNTIME_NS: u64 = 100_000;

/// Minimum allowed period in nanoseconds (1 ms).
const _MIN_PERIOD_NS: u64 = 1_000_000;

// ── Task State ─────────────────────────────────────────────────────

/// Lifecycle state of a deadline task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlState {
    /// Slot is free.
    Inactive,
    /// Task is queued and eligible for execution.
    Runnable,
    /// Task is the currently executing entity on its CPU.
    Running,
    /// Task exhausted its budget and awaits replenishment.
    Throttled,
    /// Task is blocked on a resource or I/O.
    Blocked,
}

// ── DlEntry ────────────────────────────────────────────────────────

/// A single SCHED_DEADLINE task entry.
#[derive(Clone, Copy)]
pub struct DlEntry {
    /// Process identifier.
    pid: u64,
    /// Runtime budget per period (ns).
    runtime_ns: u64,
    /// Relative deadline (ns from activation).
    deadline_ns: u64,
    /// Activation period (ns).
    period_ns: u64,
    /// Remaining runtime in the current period.
    remaining_ns: u64,
    /// Absolute deadline of the current period.
    abs_deadline: u64,
    /// Start of the current activation window.
    activation_ns: u64,
    /// Lifecycle state.
    state: DlState,
    /// Total accumulated execution time.
    exec_total_ns: u64,
    /// Number of deadline misses.
    miss_count: u64,
    /// Timestamp of the most recent miss.
    last_miss_ns: u64,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl DlEntry {
    /// Creates an empty, inactive entry.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            runtime_ns: 0,
            deadline_ns: 0,
            period_ns: 0,
            remaining_ns: 0,
            abs_deadline: 0,
            activation_ns: 0,
            state: DlState::Inactive,
            exec_total_ns: 0,
            miss_count: 0,
            last_miss_ns: 0,
            occupied: false,
        }
    }

    /// Returns the utilisation in parts per million.
    pub fn utilisation_ppm(&self) -> u64 {
        if self.period_ns == 0 {
            return 0;
        }
        self.runtime_ns.saturating_mul(1_000_000) / self.period_ns
    }

    /// Returns the PID.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Returns the current state.
    pub const fn state(&self) -> DlState {
        self.state
    }

    /// Returns the absolute deadline.
    pub const fn abs_deadline(&self) -> u64 {
        self.abs_deadline
    }

    /// Returns the remaining runtime.
    pub const fn remaining_ns(&self) -> u64 {
        self.remaining_ns
    }

    /// Returns whether this entry is occupied.
    pub const fn is_occupied(&self) -> bool {
        self.occupied
    }

    /// Returns the total number of deadline misses.
    pub const fn miss_count(&self) -> u64 {
        self.miss_count
    }
}

// ── AdmissionCtrl ──────────────────────────────────────────────────

/// Per-CPU admission control tracking cumulative utilisation.
#[derive(Clone, Copy)]
pub struct AdmissionCtrl {
    /// Aggregate utilisation (ppm).
    total_ppm: u64,
    /// Maximum allowed utilisation (ppm).
    cap_ppm: u64,
    /// Number of admitted tasks.
    admitted: u32,
}

impl AdmissionCtrl {
    /// Creates a new admission controller with default cap.
    pub const fn new() -> Self {
        Self {
            total_ppm: 0,
            cap_ppm: MAX_BW_PPM,
            admitted: 0,
        }
    }

    /// Attempts to admit a task with the given parameters.
    pub fn admit(&mut self, runtime_ns: u64, period_ns: u64) -> Result<()> {
        if period_ns == 0 || runtime_ns > period_ns {
            return Err(Error::InvalidArgument);
        }
        let util = runtime_ns.saturating_mul(1_000_000) / period_ns;
        if self.total_ppm.saturating_add(util) > self.cap_ppm {
            return Err(Error::Busy);
        }
        self.total_ppm = self.total_ppm.saturating_add(util);
        self.admitted += 1;
        Ok(())
    }

    /// Releases the bandwidth reserved by a task.
    pub fn release(&mut self, runtime_ns: u64, period_ns: u64) {
        if period_ns == 0 {
            return;
        }
        let util = runtime_ns.saturating_mul(1_000_000) / period_ns;
        self.total_ppm = self.total_ppm.saturating_sub(util);
        self.admitted = self.admitted.saturating_sub(1);
    }

    /// Returns the remaining bandwidth headroom (ppm).
    pub const fn headroom_ppm(&self) -> u64 {
        self.cap_ppm.saturating_sub(self.total_ppm)
    }

    /// Returns current total utilisation (ppm).
    pub const fn total_ppm(&self) -> u64 {
        self.total_ppm
    }
}

// ── DlRunqueue ─────────────────────────────────────────────────────

/// Per-CPU deadline run-queue.
pub struct DlRunqueue {
    /// Task entries.
    entries: [DlEntry; MAX_DL_TASKS],
    /// Indices sorted by ascending absolute deadline.
    sorted: [u16; MAX_DL_TASKS],
    /// Number of active (non-Inactive) entries.
    nr_active: usize,
    /// CPU identifier owning this run-queue.
    cpu_id: u32,
    /// Admission controller.
    admission: AdmissionCtrl,
}

impl DlRunqueue {
    /// Creates an empty run-queue for the given CPU.
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            entries: [const { DlEntry::new() }; MAX_DL_TASKS],
            sorted: [0u16; MAX_DL_TASKS],
            nr_active: 0,
            cpu_id,
            admission: AdmissionCtrl::new(),
        }
    }

    /// Enqueues a new deadline task.  Performs admission control.
    pub fn enqueue(
        &mut self,
        pid: u64,
        runtime_ns: u64,
        deadline_ns: u64,
        period_ns: u64,
        now_ns: u64,
    ) -> Result<()> {
        self.admission.admit(runtime_ns, period_ns)?;

        let slot = self.find_free_slot().ok_or(Error::OutOfMemory)?;

        let entry = &mut self.entries[slot];
        entry.pid = pid;
        entry.runtime_ns = runtime_ns;
        entry.deadline_ns = deadline_ns;
        entry.period_ns = period_ns;
        entry.remaining_ns = runtime_ns;
        entry.abs_deadline = now_ns.saturating_add(deadline_ns);
        entry.activation_ns = now_ns;
        entry.state = DlState::Runnable;
        entry.occupied = true;
        entry.exec_total_ns = 0;
        entry.miss_count = 0;
        entry.last_miss_ns = 0;

        self.nr_active += 1;
        self.resort();
        Ok(())
    }

    /// Dequeues and removes a task by PID.
    pub fn dequeue(&mut self, pid: u64) -> Result<()> {
        let idx = self.find_pid(pid).ok_or(Error::NotFound)?;

        let entry = &self.entries[idx];
        self.admission.release(entry.runtime_ns, entry.period_ns);

        self.entries[idx] = DlEntry::new();
        self.nr_active = self.nr_active.saturating_sub(1);
        self.resort();
        Ok(())
    }

    /// Picks the task with the earliest absolute deadline.
    pub fn pick_next(&self) -> Option<u64> {
        if self.nr_active == 0 {
            return None;
        }
        let idx = self.sorted[0] as usize;
        let entry = &self.entries[idx];
        if entry.occupied && entry.state == DlState::Runnable {
            Some(entry.pid)
        } else {
            None
        }
    }

    /// Accounts `delta_ns` of execution to a running task.
    pub fn account_runtime(&mut self, pid: u64, delta_ns: u64, now_ns: u64) -> Result<()> {
        let idx = self.find_pid(pid).ok_or(Error::NotFound)?;
        let entry = &mut self.entries[idx];

        entry.exec_total_ns = entry.exec_total_ns.saturating_add(delta_ns);
        entry.remaining_ns = entry.remaining_ns.saturating_sub(delta_ns);

        if entry.remaining_ns == 0 {
            self.throttle(idx, now_ns);
        }
        Ok(())
    }

    /// CBS replenishment: refill budget and postpone deadline.
    pub fn replenish(&mut self, pid: u64, now_ns: u64) -> Result<()> {
        let idx = self.find_pid(pid).ok_or(Error::NotFound)?;
        let entry = &mut self.entries[idx];

        if entry.state != DlState::Throttled {
            return Err(Error::InvalidArgument);
        }

        // CBS rule: push deadline forward by one period
        entry.abs_deadline = now_ns.saturating_add(entry.deadline_ns);
        entry.activation_ns = now_ns;
        entry.remaining_ns = entry.runtime_ns;
        entry.state = DlState::Runnable;

        self.resort();
        Ok(())
    }

    /// Checks for and records deadline misses across all entries.
    pub fn check_misses(&mut self, now_ns: u64) -> u32 {
        let mut count = 0u32;
        for entry in &mut self.entries {
            if !entry.occupied {
                continue;
            }
            if entry.state == DlState::Runnable && now_ns > entry.abs_deadline {
                entry.miss_count += 1;
                entry.last_miss_ns = now_ns;
                count += 1;
            }
        }
        count
    }

    /// Returns the number of active tasks.
    pub const fn nr_active(&self) -> usize {
        self.nr_active
    }

    /// Returns the CPU identifier.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns the admission controller (read-only).
    pub const fn admission(&self) -> &AdmissionCtrl {
        &self.admission
    }

    // ── internal helpers ───────────────────────────────────────────

    fn find_free_slot(&self) -> Option<usize> {
        self.entries.iter().position(|e| !e.occupied)
    }

    fn find_pid(&self, pid: u64) -> Option<usize> {
        self.entries.iter().position(|e| e.occupied && e.pid == pid)
    }

    fn throttle(&mut self, idx: usize, now_ns: u64) {
        let entry = &mut self.entries[idx];
        entry.state = DlState::Throttled;
        // Record miss if budget exhausted past deadline
        if now_ns > entry.abs_deadline {
            entry.miss_count += 1;
            entry.last_miss_ns = now_ns;
        }
    }

    fn resort(&mut self) {
        // Collect occupied indices
        let mut count = 0usize;
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.occupied {
                self.sorted[count] = i as u16;
                count += 1;
            }
        }
        // Zero remaining slots
        for s in &mut self.sorted[count..] {
            *s = 0;
        }
        // Insertion sort by absolute deadline (small N)
        let sorted = &mut self.sorted[..count];
        for i in 1..sorted.len() {
            let key = sorted[i];
            let key_dl = self.entries[key as usize].abs_deadline;
            let mut j = i;
            while j > 0 {
                let prev_dl = self.entries[sorted[j - 1] as usize].abs_deadline;
                if prev_dl <= key_dl {
                    break;
                }
                sorted[j] = sorted[j - 1];
                j -= 1;
            }
            sorted[j] = key;
        }
    }
}

// ── DlGlobalStats ──────────────────────────────────────────────────

/// Aggregate statistics across all deadline run-queues.
#[derive(Clone, Copy)]
pub struct DlGlobalStats {
    /// Total enqueue operations.
    pub enqueues: u64,
    /// Total dequeue operations.
    pub dequeues: u64,
    /// Total replenishments.
    pub replenishments: u64,
    /// Total deadline misses.
    pub misses: u64,
    /// Total admission rejections.
    pub rejections: u64,
}

impl DlGlobalStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            enqueues: 0,
            dequeues: 0,
            replenishments: 0,
            misses: 0,
            rejections: 0,
        }
    }

    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

// ── DeadlineScheduler ──────────────────────────────────────────────

/// Top-level SCHED_DEADLINE scheduler managing per-CPU run-queues.
pub struct DeadlineScheduler {
    /// Per-CPU deadline run-queues.
    runqueues: [DlRunqueue; MAX_CPUS],
    /// Number of online CPUs.
    nr_cpus: u32,
    /// Global statistics.
    stats: DlGlobalStats,
}

impl DeadlineScheduler {
    /// Creates a new scheduler with `nr_cpus` run-queues.
    pub fn new(nr_cpus: u32) -> Result<Self> {
        if nr_cpus == 0 || nr_cpus as usize > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        const INIT_RQ: DlRunqueue = DlRunqueue::new(0);
        let mut runqueues = [INIT_RQ; MAX_CPUS];
        for (i, rq) in runqueues.iter_mut().enumerate() {
            rq.cpu_id = i as u32;
        }

        Ok(Self {
            runqueues,
            nr_cpus,
            stats: DlGlobalStats::new(),
        })
    }

    /// Enqueues a deadline task on the specified CPU.
    pub fn enqueue(
        &mut self,
        cpu: u32,
        pid: u64,
        runtime_ns: u64,
        deadline_ns: u64,
        period_ns: u64,
        now_ns: u64,
    ) -> Result<()> {
        let rq = self.get_rq_mut(cpu)?;
        match rq.enqueue(pid, runtime_ns, deadline_ns, period_ns, now_ns) {
            Ok(()) => {
                self.stats.enqueues += 1;
                Ok(())
            }
            Err(Error::Busy) => {
                self.stats.rejections += 1;
                Err(Error::Busy)
            }
            Err(e) => Err(e),
        }
    }

    /// Dequeues a task from the specified CPU.
    pub fn dequeue(&mut self, cpu: u32, pid: u64) -> Result<()> {
        let rq = self.get_rq_mut(cpu)?;
        rq.dequeue(pid)?;
        self.stats.dequeues += 1;
        Ok(())
    }

    /// Picks the next task to run on a CPU.
    pub fn pick_next(&self, cpu: u32) -> Result<Option<u64>> {
        let rq = self.get_rq(cpu)?;
        Ok(rq.pick_next())
    }

    /// Accounts execution time.
    pub fn account(&mut self, cpu: u32, pid: u64, delta_ns: u64, now_ns: u64) -> Result<()> {
        let rq = self.get_rq_mut(cpu)?;
        rq.account_runtime(pid, delta_ns, now_ns)
    }

    /// CBS replenishment for a throttled task.
    pub fn replenish(&mut self, cpu: u32, pid: u64, now_ns: u64) -> Result<()> {
        let rq = self.get_rq_mut(cpu)?;
        rq.replenish(pid, now_ns)?;
        self.stats.replenishments += 1;
        Ok(())
    }

    /// Scans all CPUs for deadline misses.
    pub fn check_all_misses(&mut self, now_ns: u64) -> u64 {
        let mut total = 0u64;
        for i in 0..self.nr_cpus as usize {
            let n = self.runqueues[i].check_misses(now_ns);
            total = total.saturating_add(n as u64);
        }
        self.stats.misses = self.stats.misses.saturating_add(total);
        total
    }

    /// Finds the least-loaded CPU (fewest active deadline tasks).
    pub fn find_least_loaded(&self) -> u32 {
        let mut best_cpu = 0u32;
        let mut best_count = usize::MAX;
        for i in 0..self.nr_cpus as usize {
            let count = self.runqueues[i].nr_active();
            if count < best_count {
                best_count = count;
                best_cpu = i as u32;
            }
        }
        best_cpu
    }

    /// Returns a read-only reference to global statistics.
    pub const fn stats(&self) -> &DlGlobalStats {
        &self.stats
    }

    /// Returns the number of online CPUs.
    pub const fn nr_cpus(&self) -> u32 {
        self.nr_cpus
    }

    // ── internal helpers ───────────────────────────────────────────

    fn get_rq(&self, cpu: u32) -> Result<&DlRunqueue> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.runqueues[cpu as usize])
    }

    fn get_rq_mut(&mut self, cpu: u32) -> Result<&mut DlRunqueue> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.runqueues[cpu as usize])
    }
}
