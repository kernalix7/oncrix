// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCHED_DEADLINE real-time scheduling policy.
//!
//! Implements the Earliest Deadline First (EDF) scheduler with
//! Constant Bandwidth Server (CBS) reservation, following the
//! Linux SCHED_DEADLINE model.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────┐
//! │              DeadlineScheduler                     │
//! │  EDF run-queue sorted by absolute deadline         │
//! │  ┌──────────────────────────────────────────────┐  │
//! │  │  DeadlineTask[0..MAX_DEADLINE_TASKS]         │  │
//! │  │  - runtime / deadline / period (CBS params)  │  │
//! │  │  - remaining_runtime (server budget)         │  │
//! │  │  - absolute_deadline (ordering key)          │  │
//! │  │  - state machine (Inactive→Ready→Running→…)  │  │
//! │  └──────────────────────────────────────────────┘  │
//! │                                                    │
//! │  AdmissionController                               │
//! │  - total utilisation ≤ bandwidth cap               │
//! │  - per-task U = runtime / period                   │
//! │                                                    │
//! │  DeadlineMissTracker                               │
//! │  - per-task miss count + last miss timestamp       │
//! │  - global miss counter                             │
//! └────────────────────────────────────────────────────┘
//! ```
//!
//! # CBS Algorithm
//!
//! Each task is associated with a Constant Bandwidth Server that
//! guarantees a fraction `runtime / period` of the CPU. When a
//! server exhausts its budget, the absolute deadline is postponed
//! by one period (replenishment) and the task is re-inserted into
//! the EDF queue at the new position.
//!
//! # Integration
//!
//! The scheduler integrates with the cgroup CPU controller via
//! optional group-level bandwidth caps. Each cgroup may set a
//! ceiling on the total utilisation of SCHED_DEADLINE tasks
//! belonging to that group.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────

/// Maximum number of SCHED_DEADLINE tasks in the system.
const MAX_DEADLINE_TASKS: usize = 128;

/// Maximum number of cgroup bandwidth groups.
const MAX_CGROUP_GROUPS: usize = 32;

/// Default total bandwidth cap (fraction × 1_000_000).
/// 950_000 means 95% of a single CPU.
const DEFAULT_BANDWIDTH_CAP: u64 = 950_000;

/// Scale factor for fixed-point utilisation (parts per million).
const UTIL_SCALE: u64 = 1_000_000;

/// Minimum runtime in nanoseconds (100 µs).
const MIN_RUNTIME_NS: u64 = 100_000;

/// Minimum period in nanoseconds (1 ms).
const MIN_PERIOD_NS: u64 = 1_000_000;

/// Maximum period in nanoseconds (1 s).
const MAX_PERIOD_NS: u64 = 1_000_000_000;

/// Maximum number of consecutive deadline misses before a task
/// is throttled.
const MAX_CONSECUTIVE_MISSES: u32 = 5;

/// Sentinel value for unused PID slots.
const PID_NONE: u64 = 0;

/// Sentinel value for unused timestamps.
const TIME_NONE: u64 = 0;

// ── DeadlineState ──────────────────────────────────────────────

/// State machine for a SCHED_DEADLINE task.
///
/// ```text
///   Inactive ──► Ready ──► Running ──► Depleted ──► Ready
///       ▲                                │
///       └────────────────────────────────┘ (release / exit)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineState {
    /// Task is not participating in deadline scheduling.
    Inactive,
    /// Task is in the EDF queue, eligible to run.
    Ready,
    /// Task is currently executing on a CPU.
    Running,
    /// Task has exhausted its CBS budget for this period.
    Depleted,
    /// Task has been throttled due to repeated deadline misses.
    Throttled,
}

impl Default for DeadlineState {
    fn default() -> Self {
        Self::Inactive
    }
}

// ── DeadlineParams ─────────────────────────────────────────────

/// CBS scheduling parameters for a single task.
///
/// These are set at task admission time and define the bandwidth
/// reservation: `utilisation = runtime / period`.
#[derive(Debug, Clone, Copy)]
pub struct DeadlineParams {
    /// Guaranteed CPU time per period, in nanoseconds.
    pub runtime_ns: u64,
    /// Relative deadline from the start of each period, in
    /// nanoseconds.  Must be ≥ `runtime_ns` and ≤ `period_ns`.
    pub deadline_ns: u64,
    /// Period length in nanoseconds.
    pub period_ns: u64,
}

impl Default for DeadlineParams {
    fn default() -> Self {
        Self {
            runtime_ns: 0,
            deadline_ns: 0,
            period_ns: 0,
        }
    }
}

impl DeadlineParams {
    /// Validate the parameter triple.
    ///
    /// Returns `Ok(())` when `runtime ≤ deadline ≤ period` and
    /// the values are within allowed ranges.
    pub fn validate(&self) -> Result<()> {
        if self.runtime_ns < MIN_RUNTIME_NS {
            return Err(Error::InvalidArgument);
        }
        if self.period_ns < MIN_PERIOD_NS || self.period_ns > MAX_PERIOD_NS {
            return Err(Error::InvalidArgument);
        }
        if self.runtime_ns > self.deadline_ns {
            return Err(Error::InvalidArgument);
        }
        if self.deadline_ns > self.period_ns {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Compute the utilisation as a fixed-point fraction
    /// (parts per million).
    pub fn utilisation(&self) -> u64 {
        if self.period_ns == 0 {
            return 0;
        }
        self.runtime_ns.saturating_mul(UTIL_SCALE) / self.period_ns
    }
}

// ── DeadlineTask ───────────────────────────────────────────────

/// Per-task deadline scheduling state.
#[derive(Debug, Clone, Copy)]
pub struct DeadlineTask {
    /// Process identifier.
    pid: u64,
    /// CBS parameters.
    params: DeadlineParams,
    /// Current state in the deadline state machine.
    state: DeadlineState,
    /// Remaining runtime budget in the current period (ns).
    remaining_runtime_ns: u64,
    /// Absolute deadline for EDF ordering (ns since boot).
    absolute_deadline_ns: u64,
    /// Start of the current CBS period (ns since boot).
    period_start_ns: u64,
    /// Number of deadline misses for this task.
    miss_count: u64,
    /// Timestamp of the last deadline miss.
    last_miss_ns: u64,
    /// Consecutive misses without a successful completion.
    consecutive_misses: u32,
    /// Optional cgroup group index (u32::MAX = none).
    cgroup_idx: u32,
    /// Total CPU time consumed by this task (ns).
    total_runtime_ns: u64,
    /// Number of periods completed.
    periods_completed: u64,
}

impl Default for DeadlineTask {
    fn default() -> Self {
        Self {
            pid: PID_NONE,
            params: DeadlineParams::default(),
            state: DeadlineState::Inactive,
            remaining_runtime_ns: 0,
            absolute_deadline_ns: 0,
            period_start_ns: 0,
            miss_count: 0,
            last_miss_ns: TIME_NONE,
            consecutive_misses: 0,
            cgroup_idx: u32::MAX,
            total_runtime_ns: 0,
            periods_completed: 0,
        }
    }
}

impl DeadlineTask {
    /// Create an empty (inactive) deadline task slot.
    pub const fn empty() -> Self {
        Self {
            pid: PID_NONE,
            params: DeadlineParams {
                runtime_ns: 0,
                deadline_ns: 0,
                period_ns: 0,
            },
            state: DeadlineState::Inactive,
            remaining_runtime_ns: 0,
            absolute_deadline_ns: 0,
            period_start_ns: 0,
            miss_count: 0,
            last_miss_ns: TIME_NONE,
            consecutive_misses: 0,
            cgroup_idx: u32::MAX,
            total_runtime_ns: 0,
            periods_completed: 0,
        }
    }

    /// Whether this slot is unused.
    fn is_free(&self) -> bool {
        self.pid == PID_NONE && self.state == DeadlineState::Inactive
    }
}

// ── DeadlineMissTracker ────────────────────────────────────────

/// Global deadline miss statistics.
#[derive(Debug, Clone, Copy)]
pub struct DeadlineMissStats {
    /// Total deadline misses across all tasks.
    pub total_misses: u64,
    /// Total throttle events (task disabled after repeated misses).
    pub total_throttles: u64,
    /// Timestamp of the most recent miss.
    pub last_miss_ns: u64,
    /// PID of the task that most recently missed a deadline.
    pub last_miss_pid: u64,
}

impl Default for DeadlineMissStats {
    fn default() -> Self {
        Self {
            total_misses: 0,
            total_throttles: 0,
            last_miss_ns: TIME_NONE,
            last_miss_pid: PID_NONE,
        }
    }
}

impl DeadlineMissStats {
    /// Create zero-initialised stats.
    pub const fn new() -> Self {
        Self {
            total_misses: 0,
            total_throttles: 0,
            last_miss_ns: TIME_NONE,
            last_miss_pid: PID_NONE,
        }
    }
}

// ── CgroupBandwidthCap ────────────────────────────────────────

/// Per-cgroup bandwidth cap for SCHED_DEADLINE tasks.
#[derive(Debug, Clone, Copy)]
pub struct CgroupBandwidthCap {
    /// Whether this cgroup slot is active.
    active: bool,
    /// Group identifier.
    group_id: u32,
    /// Maximum aggregate utilisation (parts per million).
    max_utilisation: u64,
    /// Current aggregate utilisation of admitted tasks.
    current_utilisation: u64,
    /// Number of tasks in this group.
    task_count: u32,
}

impl Default for CgroupBandwidthCap {
    fn default() -> Self {
        Self {
            active: false,
            group_id: 0,
            max_utilisation: DEFAULT_BANDWIDTH_CAP,
            current_utilisation: 0,
            task_count: 0,
        }
    }
}

impl CgroupBandwidthCap {
    /// Create an empty cgroup bandwidth slot.
    pub const fn empty() -> Self {
        Self {
            active: false,
            group_id: 0,
            max_utilisation: DEFAULT_BANDWIDTH_CAP,
            current_utilisation: 0,
            task_count: 0,
        }
    }
}

// ── AdmissionController ────────────────────────────────────────

/// Admission control for SCHED_DEADLINE tasks.
///
/// Ensures the total system utilisation (and per-cgroup utilisation)
/// does not exceed the configured bandwidth cap.
pub struct AdmissionController {
    /// System-wide bandwidth cap (parts per million).
    system_cap: u64,
    /// Current total utilisation of all admitted tasks.
    current_utilisation: u64,
    /// Number of admitted tasks.
    admitted_count: u32,
    /// Per-cgroup bandwidth caps.
    cgroups: [CgroupBandwidthCap; MAX_CGROUP_GROUPS],
}

impl Default for AdmissionController {
    fn default() -> Self {
        Self::new()
    }
}

impl AdmissionController {
    /// Create a new admission controller with default caps.
    pub const fn new() -> Self {
        Self {
            system_cap: DEFAULT_BANDWIDTH_CAP,
            current_utilisation: 0,
            admitted_count: 0,
            cgroups: [CgroupBandwidthCap::empty(); MAX_CGROUP_GROUPS],
        }
    }

    /// Set the system-wide bandwidth cap.
    pub fn set_system_cap(&mut self, cap: u64) -> Result<()> {
        if cap == 0 || cap > UTIL_SCALE {
            return Err(Error::InvalidArgument);
        }
        if cap < self.current_utilisation {
            return Err(Error::Busy);
        }
        self.system_cap = cap;
        Ok(())
    }

    /// Register a cgroup bandwidth group.
    pub fn register_cgroup(&mut self, group_id: u32, max_util: u64) -> Result<usize> {
        if max_util == 0 || max_util > UTIL_SCALE {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate.
        for cg in &self.cgroups {
            if cg.active && cg.group_id == group_id {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self
            .cgroups
            .iter()
            .position(|cg| !cg.active)
            .ok_or(Error::OutOfMemory)?;
        self.cgroups[idx] = CgroupBandwidthCap {
            active: true,
            group_id,
            max_utilisation: max_util,
            current_utilisation: 0,
            task_count: 0,
        };
        Ok(idx)
    }

    /// Unregister a cgroup bandwidth group.
    pub fn unregister_cgroup(&mut self, group_id: u32) -> Result<()> {
        let cg = self
            .cgroups
            .iter_mut()
            .find(|cg| cg.active && cg.group_id == group_id)
            .ok_or(Error::NotFound)?;
        if cg.task_count > 0 {
            return Err(Error::Busy);
        }
        self.current_utilisation = self
            .current_utilisation
            .saturating_sub(cg.current_utilisation);
        *cg = CgroupBandwidthCap::empty();
        Ok(())
    }

    /// Check whether a task with given utilisation can be admitted.
    ///
    /// Also checks per-cgroup cap when `cgroup_idx` is valid.
    fn can_admit(&self, util: u64, cgroup_idx: Option<usize>) -> Result<()> {
        if self.current_utilisation.saturating_add(util) > self.system_cap {
            return Err(Error::Busy);
        }
        if let Some(idx) = cgroup_idx {
            if idx >= MAX_CGROUP_GROUPS {
                return Err(Error::InvalidArgument);
            }
            let cg = &self.cgroups[idx];
            if !cg.active {
                return Err(Error::NotFound);
            }
            if cg.current_utilisation.saturating_add(util) > cg.max_utilisation {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }

    /// Record admission of a task.
    fn admit(&mut self, util: u64, cgroup_idx: Option<usize>) {
        self.current_utilisation = self.current_utilisation.saturating_add(util);
        self.admitted_count = self.admitted_count.saturating_add(1);
        if let Some(idx) = cgroup_idx {
            if idx < MAX_CGROUP_GROUPS && self.cgroups[idx].active {
                self.cgroups[idx].current_utilisation =
                    self.cgroups[idx].current_utilisation.saturating_add(util);
                self.cgroups[idx].task_count = self.cgroups[idx].task_count.saturating_add(1);
            }
        }
    }

    /// Record release of a task.
    fn release(&mut self, util: u64, cgroup_idx: Option<usize>) {
        self.current_utilisation = self.current_utilisation.saturating_sub(util);
        self.admitted_count = self.admitted_count.saturating_sub(1);
        if let Some(idx) = cgroup_idx {
            if idx < MAX_CGROUP_GROUPS && self.cgroups[idx].active {
                self.cgroups[idx].current_utilisation =
                    self.cgroups[idx].current_utilisation.saturating_sub(util);
                self.cgroups[idx].task_count = self.cgroups[idx].task_count.saturating_sub(1);
            }
        }
    }

    /// Return the current system utilisation (parts per million).
    pub fn system_utilisation(&self) -> u64 {
        self.current_utilisation
    }
}

// ── DeadlineScheduler ──────────────────────────────────────────

/// EDF-based deadline scheduler with CBS bandwidth servers.
pub struct DeadlineScheduler {
    /// Per-task deadline state.
    tasks: [DeadlineTask; MAX_DEADLINE_TASKS],
    /// Admission controller.
    admission: AdmissionController,
    /// Global miss statistics.
    miss_stats: DeadlineMissStats,
    /// Current monotonic time in nanoseconds.
    now_ns: u64,
    /// Number of active (non-Inactive) tasks.
    active_count: u32,
    /// Index of the currently running task (or u32::MAX if none).
    running_idx: u32,
}

impl Default for DeadlineScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl DeadlineScheduler {
    /// Create a new deadline scheduler.
    pub const fn new() -> Self {
        Self {
            tasks: [DeadlineTask::empty(); MAX_DEADLINE_TASKS],
            admission: AdmissionController::new(),
            miss_stats: DeadlineMissStats::new(),
            now_ns: 0,
            active_count: 0,
            running_idx: u32::MAX,
        }
    }

    /// Advance the scheduler's notion of current time.
    pub fn update_time(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
    }

    /// Admit a new task with the given deadline parameters.
    ///
    /// The task is placed into the `Ready` state and inserted into
    /// the EDF queue. Admission control is performed first.
    pub fn admit_task(
        &mut self,
        pid: u64,
        params: DeadlineParams,
        cgroup_idx: Option<usize>,
    ) -> Result<usize> {
        if pid == PID_NONE {
            return Err(Error::InvalidArgument);
        }
        params.validate()?;

        // Ensure no duplicate PID.
        for t in &self.tasks {
            if t.pid == pid && t.state != DeadlineState::Inactive {
                return Err(Error::AlreadyExists);
            }
        }

        let util = params.utilisation();
        let cg = cgroup_idx.filter(|&i| i < MAX_CGROUP_GROUPS);
        self.admission.can_admit(util, cg)?;

        let idx = self
            .tasks
            .iter()
            .position(|t| t.is_free())
            .ok_or(Error::OutOfMemory)?;

        self.admission.admit(util, cg);

        self.tasks[idx] = DeadlineTask {
            pid,
            params,
            state: DeadlineState::Ready,
            remaining_runtime_ns: params.runtime_ns,
            absolute_deadline_ns: self.now_ns.saturating_add(params.deadline_ns),
            period_start_ns: self.now_ns,
            miss_count: 0,
            last_miss_ns: TIME_NONE,
            consecutive_misses: 0,
            cgroup_idx: cg.map_or(u32::MAX, |i| i as u32),
            total_runtime_ns: 0,
            periods_completed: 0,
        };

        self.active_count = self.active_count.saturating_add(1);
        Ok(idx)
    }

    /// Remove a task from deadline scheduling.
    pub fn release_task(&mut self, pid: u64) -> Result<()> {
        let idx = self
            .tasks
            .iter()
            .position(|t| t.pid == pid && !t.is_free())
            .ok_or(Error::NotFound)?;

        let task = &self.tasks[idx];
        let util = task.params.utilisation();
        let cg = if task.cgroup_idx == u32::MAX {
            None
        } else {
            Some(task.cgroup_idx as usize)
        };
        self.admission.release(util, cg);

        if self.running_idx == idx as u32 {
            self.running_idx = u32::MAX;
        }

        self.tasks[idx] = DeadlineTask::empty();
        self.active_count = self.active_count.saturating_sub(1);
        Ok(())
    }

    /// Select the next task to run using EDF.
    ///
    /// Returns the index and PID of the task with the earliest
    /// absolute deadline among all `Ready` tasks, or `None` if
    /// no task is eligible.
    pub fn pick_next(&mut self) -> Option<(usize, u64)> {
        let mut best_idx: Option<usize> = None;
        let mut best_deadline = u64::MAX;

        for (i, task) in self.tasks.iter().enumerate() {
            if task.state == DeadlineState::Ready && task.absolute_deadline_ns < best_deadline {
                best_deadline = task.absolute_deadline_ns;
                best_idx = Some(i);
            }
        }

        if let Some(idx) = best_idx {
            self.tasks[idx].state = DeadlineState::Running;
            self.running_idx = idx as u32;
            Some((idx, self.tasks[idx].pid))
        } else {
            self.running_idx = u32::MAX;
            None
        }
    }

    /// Account for CPU time consumed by the running task.
    ///
    /// Called periodically (e.g., on timer tick). `elapsed_ns` is the
    /// time since the last accounting call. Returns `true` if the
    /// task has depleted its budget and should be preempted.
    pub fn account_runtime(&mut self, elapsed_ns: u64) -> bool {
        let idx = self.running_idx;
        if idx == u32::MAX || idx as usize >= MAX_DEADLINE_TASKS {
            return false;
        }
        let task = &mut self.tasks[idx as usize];
        if task.state != DeadlineState::Running {
            return false;
        }

        task.total_runtime_ns = task.total_runtime_ns.saturating_add(elapsed_ns);
        task.remaining_runtime_ns = task.remaining_runtime_ns.saturating_sub(elapsed_ns);

        if task.remaining_runtime_ns == 0 {
            task.state = DeadlineState::Depleted;
            self.running_idx = u32::MAX;
            true
        } else {
            false
        }
    }

    /// Perform CBS replenishment for depleted tasks.
    ///
    /// A depleted task whose period has elapsed gets a new budget
    /// and a new absolute deadline, then transitions back to `Ready`.
    /// If the task missed its deadline, the miss is recorded.
    pub fn replenish(&mut self) {
        for task in &mut self.tasks {
            if task.state != DeadlineState::Depleted {
                continue;
            }

            // Check for deadline miss.
            let missed = self.now_ns > task.absolute_deadline_ns;
            if missed {
                task.miss_count = task.miss_count.saturating_add(1);
                task.consecutive_misses = task.consecutive_misses.saturating_add(1);
                task.last_miss_ns = self.now_ns;

                self.miss_stats.total_misses = self.miss_stats.total_misses.saturating_add(1);
                self.miss_stats.last_miss_ns = self.now_ns;
                self.miss_stats.last_miss_pid = task.pid;
            } else {
                task.consecutive_misses = 0;
            }

            // Throttle if too many consecutive misses.
            if task.consecutive_misses >= MAX_CONSECUTIVE_MISSES {
                task.state = DeadlineState::Throttled;
                self.miss_stats.total_throttles = self.miss_stats.total_throttles.saturating_add(1);
                continue;
            }

            // CBS replenishment: advance period and deadline.
            task.period_start_ns = task.period_start_ns.saturating_add(task.params.period_ns);
            task.absolute_deadline_ns =
                task.period_start_ns.saturating_add(task.params.deadline_ns);
            task.remaining_runtime_ns = task.params.runtime_ns;
            task.periods_completed = task.periods_completed.saturating_add(1);
            task.state = DeadlineState::Ready;
        }
    }

    /// Unthrottle a previously throttled task.
    pub fn unthrottle(&mut self, pid: u64) -> Result<()> {
        let task = self
            .tasks
            .iter_mut()
            .find(|t| t.pid == pid && t.state == DeadlineState::Throttled)
            .ok_or(Error::NotFound)?;

        task.consecutive_misses = 0;
        task.period_start_ns = self.now_ns;
        task.absolute_deadline_ns = self.now_ns.saturating_add(task.params.deadline_ns);
        task.remaining_runtime_ns = task.params.runtime_ns;
        task.state = DeadlineState::Ready;
        Ok(())
    }

    /// Yield the currently running task back to `Ready` state,
    /// surrendering the remaining budget.
    pub fn yield_task(&mut self) -> Result<()> {
        let idx = self.running_idx;
        if idx == u32::MAX || idx as usize >= MAX_DEADLINE_TASKS {
            return Err(Error::NotFound);
        }
        let task = &mut self.tasks[idx as usize];
        if task.state != DeadlineState::Running {
            return Err(Error::InvalidArgument);
        }
        task.state = DeadlineState::Ready;
        self.running_idx = u32::MAX;
        Ok(())
    }

    /// Query the deadline scheduling parameters for a task.
    pub fn get_params(&self, pid: u64) -> Result<DeadlineParams> {
        let task = self
            .tasks
            .iter()
            .find(|t| t.pid == pid && !t.is_free())
            .ok_or(Error::NotFound)?;
        Ok(task.params)
    }

    /// Update the deadline parameters for an already-admitted task.
    ///
    /// Re-runs admission control with the new parameters.
    pub fn set_params(&mut self, pid: u64, new_params: DeadlineParams) -> Result<()> {
        new_params.validate()?;

        let idx = self
            .tasks
            .iter()
            .position(|t| t.pid == pid && !t.is_free())
            .ok_or(Error::NotFound)?;

        let old_util = self.tasks[idx].params.utilisation();
        let new_util = new_params.utilisation();
        let cg = if self.tasks[idx].cgroup_idx == u32::MAX {
            None
        } else {
            Some(self.tasks[idx].cgroup_idx as usize)
        };

        // Temporarily release old utilisation, check new, re-admit.
        self.admission.release(old_util, cg);
        if let Err(e) = self.admission.can_admit(new_util, cg) {
            // Roll back.
            self.admission.admit(old_util, cg);
            return Err(e);
        }
        self.admission.admit(new_util, cg);

        self.tasks[idx].params = new_params;
        // Reset budget for new parameters.
        self.tasks[idx].remaining_runtime_ns = new_params.runtime_ns;
        self.tasks[idx].absolute_deadline_ns = self.now_ns.saturating_add(new_params.deadline_ns);
        self.tasks[idx].period_start_ns = self.now_ns;
        Ok(())
    }

    /// Return global deadline miss statistics.
    pub fn miss_stats(&self) -> &DeadlineMissStats {
        &self.miss_stats
    }

    /// Return the number of active deadline tasks.
    pub fn active_count(&self) -> u32 {
        self.active_count
    }

    /// Return the current system utilisation (parts per million).
    pub fn system_utilisation(&self) -> u64 {
        self.admission.system_utilisation()
    }

    /// Return a reference to the admission controller.
    pub fn admission(&self) -> &AdmissionController {
        &self.admission
    }

    /// Return a mutable reference to the admission controller.
    pub fn admission_mut(&mut self) -> &mut AdmissionController {
        &mut self.admission
    }

    /// Query the state of a specific task.
    pub fn task_state(&self, pid: u64) -> Result<DeadlineState> {
        let task = self
            .tasks
            .iter()
            .find(|t| t.pid == pid && !t.is_free())
            .ok_or(Error::NotFound)?;
        Ok(task.state)
    }

    /// Snapshot of a single task's runtime statistics.
    pub fn task_stats(&self, pid: u64) -> Result<DeadlineTaskStats> {
        let task = self
            .tasks
            .iter()
            .find(|t| t.pid == pid && !t.is_free())
            .ok_or(Error::NotFound)?;
        Ok(DeadlineTaskStats {
            pid: task.pid,
            state: task.state,
            total_runtime_ns: task.total_runtime_ns,
            remaining_runtime_ns: task.remaining_runtime_ns,
            absolute_deadline_ns: task.absolute_deadline_ns,
            miss_count: task.miss_count,
            periods_completed: task.periods_completed,
        })
    }

    /// Perform a full scheduling tick: account runtime, replenish
    /// depleted tasks, and pick the next task to run.
    ///
    /// Returns the PID of the task to run, or `None` if idle.
    pub fn tick(&mut self, now_ns: u64, elapsed_ns: u64) -> Option<u64> {
        self.update_time(now_ns);
        let depleted = self.account_runtime(elapsed_ns);
        self.replenish();

        if depleted || self.running_idx == u32::MAX {
            self.pick_next().map(|(_, pid)| pid)
        } else {
            // Continue running the current task.
            let idx = self.running_idx as usize;
            if idx < MAX_DEADLINE_TASKS {
                Some(self.tasks[idx].pid)
            } else {
                None
            }
        }
    }
}

// ── DeadlineTaskStats ──────────────────────────────────────────

/// Read-only snapshot of a deadline task's statistics.
#[derive(Debug, Clone, Copy)]
pub struct DeadlineTaskStats {
    /// Process identifier.
    pub pid: u64,
    /// Current scheduling state.
    pub state: DeadlineState,
    /// Total CPU time consumed (ns).
    pub total_runtime_ns: u64,
    /// Remaining budget in current period (ns).
    pub remaining_runtime_ns: u64,
    /// Current absolute deadline (ns since boot).
    pub absolute_deadline_ns: u64,
    /// Number of deadline misses.
    pub miss_count: u64,
    /// Number of completed periods.
    pub periods_completed: u64,
}
