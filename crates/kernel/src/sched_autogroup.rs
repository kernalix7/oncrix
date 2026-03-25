// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Scheduler autogroup for session-based task grouping.
//!
//! Implements the Linux autogroup feature (`CONFIG_SCHED_AUTOGROUP`)
//! which automatically groups tasks by session (setsid) into separate
//! CFS scheduling groups. This prevents a single session running many
//! CPU-intensive tasks (e.g., `make -jN`) from starving interactive
//! sessions.
//!
//! # How It Works
//!
//! 1. When a process calls `setsid()`, a new autogroup is created.
//! 2. All tasks in the same session share one autogroup.
//! 3. Each autogroup gets a fair share of CPU time via CFS bandwidth.
//! 4. The autogroup's nice value can be adjusted via
//!    `/proc/<pid>/autogroup` to change its CPU priority relative
//!    to other autogroups.
//!
//! # Example
//!
//! ```text
//! Session A (interactive): 1 task,  autogroup nice 0
//! Session B (build):       32 tasks, autogroup nice 0
//!
//! Without autogroup: Session B gets 32/(32+1) = 97% CPU
//! With autogroup:    Each session gets ~50% CPU (fair per-group)
//! ```
//!
//! # /proc Interface
//!
//! - `/proc/<pid>/autogroup`: shows group ID and nice value
//! - Writing a nice value (`echo 5 > /proc/<pid>/autogroup`)
//!   adjusts the group's priority
//!
//! Reference: Linux `kernel/sched/autogroup.c`,
//! `kernel/sched/autogroup.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of autogroups in the system.
const MAX_AUTOGROUPS: usize = 128;

/// Maximum tasks per autogroup.
const MAX_TASKS_PER_GROUP: usize = 64;

/// Minimum nice value.
const MIN_NICE: i32 = -20;

/// Maximum nice value.
const MAX_NICE: i32 = 19;

/// Default nice value for new autogroups.
const DEFAULT_NICE: i32 = 0;

/// Default CFS bandwidth weight (proportional to 1024).
const DEFAULT_WEIGHT: u32 = 1024;

/// Minimum CFS bandwidth weight.
const MIN_WEIGHT: u32 = 1;

/// Maximum CFS bandwidth weight.
const MAX_WEIGHT: u32 = 88_761;

/// Weight scaling factor for nice-to-weight conversion.
/// Each nice level approximately scales by 1.25x.
/// Table: nice 0 = 1024, nice -20 = 88761, nice 19 = 15.
const NICE_TO_WEIGHT: [u32; 40] = [
    88_761, 71_755, 56_483, 46_273, 36_291, // -20..-16
    29_154, 23_254, 18_705, 14_949, 11_916, // -15..-11
    9_548, 7_620, 6_100, 4_904, 3_906, // -10..-6
    3_121, 2_501, 1_991, 1_586, 1_277, // -5..-1
    1_024, 820, 655, 526, 423, //  0..4
    335, 272, 215, 172, 137, //  5..9
    110, 87, 70, 56, 45, // 10..14
    36, 29, 23, 18, 15, // 15..19
];

// ── Autogroup State ────────────────────────────────────────────────

/// Operational state of an autogroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AutogroupState {
    /// Group is not allocated.
    #[default]
    Free,
    /// Group is active with at least one task.
    Active,
    /// Group is being torn down (no new tasks accepted).
    Exiting,
}

// ── Per-task Autogroup Info ────────────────────────────────────────

/// Autogroup association for a single task.
#[derive(Debug, Clone, Copy)]
pub struct TaskAutogroupInfo {
    /// Task PID.
    pub pid: u64,
    /// Session ID (setsid).
    pub session_id: u64,
    /// Autogroup index in the registry.
    pub group_idx: u32,
    /// Whether this task is the session leader.
    pub session_leader: bool,
}

impl TaskAutogroupInfo {
    /// Create an empty task info.
    const fn empty() -> Self {
        Self {
            pid: 0,
            session_id: 0,
            group_idx: 0,
            session_leader: false,
        }
    }
}

// ── CFS Bandwidth Parameters ───────────────────────────────────────

/// CFS bandwidth parameters for an autogroup.
///
/// Controls the CPU share this autogroup receives relative to other
/// autogroups.
#[derive(Debug, Clone, Copy)]
pub struct AutogroupBandwidth {
    /// CFS weight (derived from nice value).
    pub weight: u32,
    /// CPU quota in microseconds per period (-1 = unlimited).
    pub quota_us: i64,
    /// CFS period in microseconds.
    pub period_us: u64,
    /// Accumulated CPU usage in the current period (microseconds).
    pub usage_us: u64,
    /// Whether this group is throttled (quota exceeded).
    pub throttled: bool,
    /// Number of times this group was throttled.
    pub throttle_count: u64,
}

impl AutogroupBandwidth {
    /// Create default bandwidth parameters.
    const fn new() -> Self {
        Self {
            weight: DEFAULT_WEIGHT,
            quota_us: -1,
            period_us: 100_000,
            usage_us: 0,
            throttled: false,
            throttle_count: 0,
        }
    }
}

// ── Autogroup ──────────────────────────────────────────────────────

/// A single autogroup (one per session).
///
/// Groups all tasks in a session for fair CFS scheduling. The group's
/// nice value can be adjusted to change its CPU priority.
pub struct Autogroup {
    /// Unique autogroup ID.
    group_id: u64,
    /// Session ID (matches the session leader's PID).
    session_id: u64,
    /// Current nice value.
    nice: i32,
    /// Current state.
    state: AutogroupState,
    /// CFS bandwidth parameters.
    bandwidth: AutogroupBandwidth,
    /// Tasks in this group.
    tasks: [TaskAutogroupInfo; MAX_TASKS_PER_GROUP],
    /// Number of tasks.
    task_count: usize,
    /// Reference count (tasks + 1 for the session itself).
    ref_count: u32,
    /// Total CPU time consumed by this group (microseconds).
    total_cpu_us: u64,
    /// Creation timestamp (ticks).
    create_time: u64,
    /// Whether this slot is in use.
    active: bool,
}

impl Autogroup {
    /// Create an empty (inactive) autogroup.
    const fn empty() -> Self {
        Self {
            group_id: 0,
            session_id: 0,
            nice: DEFAULT_NICE,
            state: AutogroupState::Free,
            bandwidth: AutogroupBandwidth::new(),
            tasks: [TaskAutogroupInfo::empty(); MAX_TASKS_PER_GROUP],
            task_count: 0,
            ref_count: 0,
            total_cpu_us: 0,
            create_time: 0,
            active: false,
        }
    }
}

// ── /proc Interface Data ───────────────────────────────────────────

/// Data returned when reading `/proc/<pid>/autogroup`.
#[derive(Debug, Clone, Copy)]
pub struct AutogroupProcInfo {
    /// Autogroup ID.
    pub group_id: u64,
    /// Nice value.
    pub nice: i32,
    /// CFS weight.
    pub weight: u32,
    /// Number of tasks in the group.
    pub task_count: usize,
    /// Total CPU time (microseconds).
    pub total_cpu_us: u64,
}

// ── Statistics ─────────────────────────────────────────────────────

/// Aggregate autogroup subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct AutogroupStats {
    /// Total autogroups created.
    pub groups_created: u64,
    /// Total autogroups destroyed.
    pub groups_destroyed: u64,
    /// Currently active autogroups.
    pub active_groups: u64,
    /// Total task migrations between groups.
    pub task_migrations: u64,
    /// Total nice value changes.
    pub nice_changes: u64,
    /// Total throttle events across all groups.
    pub total_throttles: u64,
}

impl AutogroupStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            groups_created: 0,
            groups_destroyed: 0,
            active_groups: 0,
            task_migrations: 0,
            nice_changes: 0,
            total_throttles: 0,
        }
    }
}

// ── Manager ────────────────────────────────────────────────────────

/// System-wide autogroup manager.
///
/// Manages autogroup creation, task assignment, nice value
/// adjustment, and CPU accounting. Integrates with the CFS scheduler
/// to provide per-session fair scheduling.
pub struct AutogroupManager {
    /// All autogroups.
    groups: [Autogroup; MAX_AUTOGROUPS],
    /// Number of active autogroups.
    active_count: usize,
    /// Next autogroup ID.
    next_group_id: u64,
    /// Whether the autogroup feature is enabled system-wide.
    enabled: bool,
    /// Subsystem statistics.
    stats: AutogroupStats,
}

impl AutogroupManager {
    /// Create a new autogroup manager.
    pub const fn new() -> Self {
        Self {
            groups: [const { Autogroup::empty() }; MAX_AUTOGROUPS],
            active_count: 0,
            next_group_id: 1,
            enabled: true,
            stats: AutogroupStats::new(),
        }
    }

    /// Enable or disable the autogroup feature system-wide.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if autogroup is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Create a new autogroup for a session.
    ///
    /// Called when a process invokes `setsid()`. The session leader
    /// is automatically added to the new group.
    pub fn create_group(&mut self, session_id: u64, leader_pid: u64, now: u64) -> Result<u64> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        if self.active_count >= MAX_AUTOGROUPS {
            return Err(Error::OutOfMemory);
        }
        // Check for existing group for this session
        if self.find_by_session(session_id).is_some() {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .groups
            .iter()
            .position(|g| !g.active)
            .ok_or(Error::OutOfMemory)?;

        let group_id = self.next_group_id;
        self.next_group_id += 1;

        let grp = &mut self.groups[slot];
        grp.group_id = group_id;
        grp.session_id = session_id;
        grp.nice = DEFAULT_NICE;
        grp.state = AutogroupState::Active;
        grp.bandwidth = AutogroupBandwidth::new();
        grp.task_count = 1;
        grp.ref_count = 2; // session + leader task
        grp.total_cpu_us = 0;
        grp.create_time = now;
        grp.active = true;

        // Add the session leader
        grp.tasks[0] = TaskAutogroupInfo {
            pid: leader_pid,
            session_id,
            group_idx: slot as u32,
            session_leader: true,
        };

        self.active_count += 1;
        self.stats.groups_created += 1;
        self.stats.active_groups = self.active_count as u64;

        Ok(group_id)
    }

    /// Destroy an autogroup (all tasks must have exited).
    pub fn destroy_group(&mut self, group_id: u64) -> Result<()> {
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        if self.groups[idx].task_count > 0 {
            return Err(Error::Busy);
        }
        self.groups[idx] = Autogroup::empty();
        self.active_count = self.active_count.saturating_sub(1);
        self.stats.groups_destroyed += 1;
        self.stats.active_groups = self.active_count as u64;
        Ok(())
    }

    /// Add a task to an autogroup (fork/clone inherits parent's
    /// group).
    pub fn add_task(&mut self, group_id: u64, pid: u64, session_id: u64) -> Result<()> {
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        let grp = &mut self.groups[idx];
        if grp.state != AutogroupState::Active {
            return Err(Error::InvalidArgument);
        }
        if grp.task_count >= MAX_TASKS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        grp.tasks[grp.task_count] = TaskAutogroupInfo {
            pid,
            session_id,
            group_idx: idx as u32,
            session_leader: false,
        };
        grp.task_count += 1;
        grp.ref_count += 1;
        Ok(())
    }

    /// Remove a task from its autogroup (task exit).
    pub fn remove_task(&mut self, group_id: u64, pid: u64) -> Result<()> {
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        let grp = &mut self.groups[idx];
        let pos = grp.tasks[..grp.task_count]
            .iter()
            .position(|t| t.pid == pid)
            .ok_or(Error::NotFound)?;

        // Shift remaining tasks
        for i in pos..grp.task_count.saturating_sub(1) {
            grp.tasks[i] = grp.tasks[i + 1];
        }
        if grp.task_count > 0 {
            grp.tasks[grp.task_count - 1] = TaskAutogroupInfo::empty();
            grp.task_count -= 1;
        }
        grp.ref_count = grp.ref_count.saturating_sub(1);

        // Auto-destroy if no tasks and state is exiting
        if grp.task_count == 0 && grp.state == AutogroupState::Exiting {
            self.groups[idx] = Autogroup::empty();
            self.active_count = self.active_count.saturating_sub(1);
            self.stats.groups_destroyed += 1;
            self.stats.active_groups = self.active_count as u64;
        }

        Ok(())
    }

    /// Migrate a task from one autogroup to another (e.g., setsid).
    pub fn migrate_task(
        &mut self,
        pid: u64,
        from_group_id: u64,
        to_group_id: u64,
        session_id: u64,
    ) -> Result<()> {
        self.remove_task(from_group_id, pid)?;
        self.add_task(to_group_id, pid, session_id)?;
        self.stats.task_migrations += 1;
        Ok(())
    }

    /// Set the nice value for an autogroup.
    ///
    /// Adjusts the CFS weight for all tasks in the group.
    /// Nice range: -20 (highest priority) to 19 (lowest).
    pub fn set_nice(&mut self, group_id: u64, nice: i32) -> Result<()> {
        if nice < MIN_NICE || nice > MAX_NICE {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        self.groups[idx].nice = nice;
        self.groups[idx].bandwidth.weight = nice_to_weight(nice);
        self.stats.nice_changes += 1;
        Ok(())
    }

    /// Get the nice value for an autogroup.
    pub fn get_nice(&self, group_id: u64) -> Result<i32> {
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        Ok(self.groups[idx].nice)
    }

    /// Account CPU time to an autogroup.
    ///
    /// Called by the scheduler tick to charge CPU time to the group.
    /// Checks bandwidth throttling if a quota is set.
    pub fn account_cpu(&mut self, group_id: u64, delta_us: u64) -> Result<bool> {
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        let grp = &mut self.groups[idx];
        grp.total_cpu_us += delta_us;
        grp.bandwidth.usage_us += delta_us;

        // Check throttling
        if grp.bandwidth.quota_us >= 0 {
            if grp.bandwidth.usage_us >= grp.bandwidth.quota_us as u64 {
                grp.bandwidth.throttled = true;
                grp.bandwidth.throttle_count += 1;
                self.stats.total_throttles += 1;
                return Ok(true); // throttled
            }
        }
        Ok(false)
    }

    /// Reset bandwidth accounting for a new period.
    ///
    /// Called periodically (every period_us) to reset usage counters
    /// and unthrottle groups.
    pub fn reset_period(&mut self) {
        for grp in &mut self.groups {
            if grp.active {
                grp.bandwidth.usage_us = 0;
                grp.bandwidth.throttled = false;
            }
        }
    }

    /// Set a CPU quota for an autogroup.
    ///
    /// `quota_us = -1` means unlimited (no throttling).
    pub fn set_quota(&mut self, group_id: u64, quota_us: i64) -> Result<()> {
        if quota_us < -1 {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        self.groups[idx].bandwidth.quota_us = quota_us;
        Ok(())
    }

    /// Get the /proc autogroup information for a task.
    pub fn proc_info(&self, pid: u64) -> Result<AutogroupProcInfo> {
        // Find which group this task belongs to
        for grp in &self.groups {
            if !grp.active {
                continue;
            }
            let has_task = grp.tasks[..grp.task_count].iter().any(|t| t.pid == pid);
            if has_task {
                return Ok(AutogroupProcInfo {
                    group_id: grp.group_id,
                    nice: grp.nice,
                    weight: grp.bandwidth.weight,
                    task_count: grp.task_count,
                    total_cpu_us: grp.total_cpu_us,
                });
            }
        }
        Err(Error::NotFound)
    }

    /// Find the autogroup for a given session ID.
    pub fn find_by_session_id(&self, session_id: u64) -> Option<u64> {
        self.find_by_session(session_id)
            .map(|idx| self.groups[idx].group_id)
    }

    /// Mark a group as exiting (session leader exited).
    pub fn mark_exiting(&mut self, group_id: u64) -> Result<()> {
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        self.groups[idx].state = AutogroupState::Exiting;
        self.groups[idx].ref_count = self.groups[idx].ref_count.saturating_sub(1);
        // If no tasks remain, destroy immediately
        if self.groups[idx].task_count == 0 {
            self.groups[idx] = Autogroup::empty();
            self.active_count = self.active_count.saturating_sub(1);
            self.stats.groups_destroyed += 1;
            self.stats.active_groups = self.active_count as u64;
        }
        Ok(())
    }

    /// Get the CFS weight for an autogroup.
    pub fn get_weight(&self, group_id: u64) -> Result<u32> {
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        Ok(self.groups[idx].bandwidth.weight)
    }

    /// Check if a group is currently throttled.
    pub fn is_throttled(&self, group_id: u64) -> Result<bool> {
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        Ok(self.groups[idx].bandwidth.throttled)
    }

    /// Get aggregate autogroup statistics.
    pub fn statistics(&self) -> &AutogroupStats {
        &self.stats
    }

    /// Return the number of active autogroups.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Find an autogroup by ID.
    fn find_group(&self, group_id: u64) -> Option<usize> {
        self.groups
            .iter()
            .position(|g| g.active && g.group_id == group_id)
    }

    /// Find an autogroup by session ID.
    fn find_by_session(&self, session_id: u64) -> Option<usize> {
        self.groups
            .iter()
            .position(|g| g.active && g.session_id == session_id)
    }
}

// ── Helper Functions ───────────────────────────────────────────────

/// Convert a nice value (-20..19) to a CFS weight.
///
/// Uses the standard Linux nice-to-weight mapping table where nice 0
/// corresponds to weight 1024.
fn nice_to_weight(nice: i32) -> u32 {
    let idx = (nice + 20) as usize;
    if idx < NICE_TO_WEIGHT.len() {
        NICE_TO_WEIGHT[idx]
    } else {
        DEFAULT_WEIGHT
    }
}

/// Convert a CFS weight to the nearest nice value.
///
/// Finds the nice value whose weight is closest to the given weight.
pub fn weight_to_nice(weight: u32) -> i32 {
    if weight >= NICE_TO_WEIGHT[0] {
        return MIN_NICE;
    }
    if weight <= NICE_TO_WEIGHT[39] {
        return MAX_NICE;
    }
    // Binary search for the closest weight
    let mut best_idx = 0usize;
    let mut best_diff = u32::MAX;
    for (i, &w) in NICE_TO_WEIGHT.iter().enumerate() {
        let diff = if weight >= w { weight - w } else { w - weight };
        if diff < best_diff {
            best_diff = diff;
            best_idx = i;
        }
    }
    (best_idx as i32) - 20
}
