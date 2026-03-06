// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OOM (Out-Of-Memory) killer implementation.
//!
//! When the system runs critically low on memory and reclaim cannot
//! free enough pages, the OOM killer selects the "worst" process
//! (highest badness score) and sends it SIGKILL to free memory.
//!
//! # Subsystems
//!
//! - [`OomScoreAdj`] — per-task OOM score adjustment (-1000..1000)
//! - [`TaskOomInfo`] — per-task memory accounting for scoring
//! - [`OomControl`] — per-cgroup OOM control knobs
//! - [`OomKillRecord`] — history record of an OOM kill event
//! - [`OomKiller`] — main OOM killer state machine
//!
//! # Scoring
//!
//! The badness score is based on:
//! 1. Resident set size (RSS) as proportion of total memory
//! 2. Swap usage
//! 3. Per-task `oom_score_adj` (-1000 disables, +1000 always first)
//! 4. Per-cgroup OOM priority
//!
//! Reference: Linux `mm/oom_kill.c`, `include/linux/oom.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Minimum oom_score_adj value (disables OOM kill for this task).
const OOM_SCORE_ADJ_MIN: i32 = -1000;

/// Maximum oom_score_adj value (always killed first).
const OOM_SCORE_ADJ_MAX: i32 = 1000;

/// Score that marks a task as OOM-immune.
const OOM_IMMUNE_SCORE: i32 = OOM_SCORE_ADJ_MIN;

/// Maximum number of tracked tasks.
const MAX_TASKS: usize = 512;

/// Maximum number of cgroup OOM controls.
const MAX_CGROUPS: usize = 64;

/// Maximum OOM kill history records.
const MAX_KILL_RECORDS: usize = 64;

/// Base score for badness calculation.
const BADNESS_BASE: u64 = 1000;

// -------------------------------------------------------------------
// OomScoreAdj
// -------------------------------------------------------------------

/// Per-task OOM score adjustment, clamped to [-1000, 1000].
///
/// - -1000: task is immune from OOM killer
/// - 0: default, no adjustment
/// - +1000: task is always killed first
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OomScoreAdj(i32);

impl OomScoreAdj {
    /// Creates a new score adjustment, clamping to valid range.
    pub const fn new(adj: i32) -> Self {
        let clamped = if adj < OOM_SCORE_ADJ_MIN {
            OOM_SCORE_ADJ_MIN
        } else if adj > OOM_SCORE_ADJ_MAX {
            OOM_SCORE_ADJ_MAX
        } else {
            adj
        };
        Self(clamped)
    }

    /// Returns the raw adjustment value.
    pub const fn value(self) -> i32 {
        self.0
    }

    /// Returns true if this task is OOM-immune.
    pub const fn is_immune(self) -> bool {
        self.0 == OOM_IMMUNE_SCORE
    }

    /// Returns the default (zero) adjustment.
    pub const fn default_value() -> Self {
        Self(0)
    }
}

impl Default for OomScoreAdj {
    fn default() -> Self {
        Self::default_value()
    }
}

// -------------------------------------------------------------------
// TaskOomInfo
// -------------------------------------------------------------------

/// Per-task memory accounting data used for OOM scoring.
#[derive(Debug, Clone, Copy)]
pub struct TaskOomInfo {
    /// Process ID.
    pub pid: u32,
    /// RSS (resident set size) in pages.
    pub rss_pages: u64,
    /// Swap usage in pages.
    pub swap_pages: u64,
    /// Page table memory in pages.
    pub pgtable_pages: u64,
    /// OOM score adjustment.
    pub score_adj: OomScoreAdj,
    /// Cgroup ID this task belongs to (0 = root).
    pub cgroup_id: u32,
    /// Whether this task is a kernel thread (immune).
    pub is_kernel: bool,
    /// Whether this task is already being killed.
    pub being_killed: bool,
    /// Computed badness score (cached).
    computed_badness: u64,
}

impl TaskOomInfo {
    /// Creates new task OOM info.
    pub const fn new(pid: u32) -> Self {
        Self {
            pid,
            rss_pages: 0,
            swap_pages: 0,
            pgtable_pages: 0,
            score_adj: OomScoreAdj::default_value(),
            cgroup_id: 0,
            is_kernel: false,
            being_killed: false,
            computed_badness: 0,
        }
    }

    /// Returns the total memory usage in pages.
    pub const fn total_pages(&self) -> u64 {
        self.rss_pages + self.swap_pages + self.pgtable_pages
    }

    /// Computes the badness score for this task.
    ///
    /// Higher = more likely to be killed.
    pub fn compute_badness(&mut self, total_ram_pages: u64) -> u64 {
        // Immune tasks get score 0
        if self.score_adj.is_immune() || self.is_kernel {
            self.computed_badness = 0;
            return 0;
        }

        // Base score = proportion of total RAM used × BADNESS_BASE
        let usage = self.total_pages();
        let base = if total_ram_pages > 0 {
            (usage * BADNESS_BASE) / total_ram_pages
        } else {
            0
        };

        // Apply adjustment: adj maps linearly over BADNESS_BASE
        let adj = self.score_adj.value() as i64;
        let adjusted = base as i64 + adj;

        // Clamp to [1, 2 * BADNESS_BASE] for non-immune tasks
        let score = if adjusted < 1 {
            1
        } else if adjusted > (BADNESS_BASE * 2) as i64 {
            BADNESS_BASE * 2
        } else {
            adjusted as u64
        };

        self.computed_badness = score;
        score
    }

    /// Returns the last computed badness score.
    pub const fn badness(&self) -> u64 {
        self.computed_badness
    }
}

impl Default for TaskOomInfo {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// OomCgroupPolicy
// -------------------------------------------------------------------

/// Per-cgroup OOM handling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OomCgroupPolicy {
    /// Kill the highest-scored process in the cgroup.
    #[default]
    KillProcess,
    /// Kill all processes in the cgroup.
    KillAll,
    /// Pause processes and wait for user intervention.
    Pause,
}

// -------------------------------------------------------------------
// OomControl
// -------------------------------------------------------------------

/// Per-cgroup OOM control knobs.
#[derive(Debug, Clone, Copy)]
pub struct OomControl {
    /// Cgroup identifier.
    pub cgroup_id: u32,
    /// OOM policy for this cgroup.
    pub policy: OomCgroupPolicy,
    /// Memory limit in pages (0 = unlimited).
    pub mem_limit_pages: u64,
    /// Current memory usage in pages.
    pub mem_usage_pages: u64,
    /// Whether OOM killer is enabled for this cgroup.
    pub oom_enabled: bool,
    /// Number of OOM events in this cgroup.
    pub oom_events: u64,
    /// Cgroup oom_score_adj override (applied to all tasks).
    pub group_score_adj: OomScoreAdj,
}

impl OomControl {
    /// Creates a new cgroup OOM control with defaults.
    pub const fn new(cgroup_id: u32) -> Self {
        Self {
            cgroup_id,
            policy: OomCgroupPolicy::KillProcess,
            mem_limit_pages: 0,
            mem_usage_pages: 0,
            oom_enabled: true,
            oom_events: 0,
            group_score_adj: OomScoreAdj::default_value(),
        }
    }

    /// Returns whether this cgroup is over its memory limit.
    pub const fn is_over_limit(&self) -> bool {
        self.mem_limit_pages > 0 && self.mem_usage_pages > self.mem_limit_pages
    }
}

impl Default for OomControl {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// OomKillRecord
// -------------------------------------------------------------------

/// Record of a single OOM kill event.
#[derive(Debug, Clone, Copy)]
pub struct OomKillRecord {
    /// Timestamp (monotonic counter).
    pub timestamp: u64,
    /// PID of the killed process.
    pub killed_pid: u32,
    /// Badness score at time of kill.
    pub badness_score: u64,
    /// RSS in pages at time of kill.
    pub rss_pages: u64,
    /// Cgroup ID (0 = system-wide OOM).
    pub cgroup_id: u32,
    /// Whether this was a cgroup-scoped OOM.
    pub cgroup_scoped: bool,
    /// Free pages at time of OOM.
    pub free_pages_at_oom: u64,
}

impl OomKillRecord {
    /// Creates a new kill record.
    pub const fn new() -> Self {
        Self {
            timestamp: 0,
            killed_pid: 0,
            badness_score: 0,
            rss_pages: 0,
            cgroup_id: 0,
            cgroup_scoped: false,
            free_pages_at_oom: 0,
        }
    }
}

impl Default for OomKillRecord {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// OomKiller
// -------------------------------------------------------------------

/// The OOM killer state machine.
///
/// Maintains task and cgroup information, selects victims based
/// on badness scores, and records kill history.
pub struct OomKiller {
    /// Tracked tasks.
    tasks: [TaskOomInfo; MAX_TASKS],
    /// Number of registered tasks.
    task_count: usize,
    /// Per-cgroup OOM controls.
    cgroups: [OomControl; MAX_CGROUPS],
    /// Number of registered cgroups.
    cgroup_count: usize,
    /// Kill history ring buffer.
    kill_records: [OomKillRecord; MAX_KILL_RECORDS],
    /// Next write position in kill_records.
    record_head: usize,
    /// Total OOM kill events since boot.
    total_kills: u64,
    /// Total system RAM in pages.
    total_ram_pages: u64,
    /// Monotonic timestamp counter.
    timestamp: u64,
    /// Whether OOM killer is globally enabled.
    enabled: bool,
}

impl OomKiller {
    /// Creates a new OOM killer.
    pub const fn new() -> Self {
        Self {
            tasks: [const { TaskOomInfo::new(0) }; MAX_TASKS],
            task_count: 0,
            cgroups: [const { OomControl::new(0) }; MAX_CGROUPS],
            cgroup_count: 0,
            kill_records: [const { OomKillRecord::new() }; MAX_KILL_RECORDS],
            record_head: 0,
            total_kills: 0,
            total_ram_pages: 0,
            timestamp: 0,
            enabled: true,
        }
    }

    /// Initializes the OOM killer with total system RAM.
    pub fn init(&mut self, total_ram_pages: u64) {
        self.total_ram_pages = total_ram_pages;
        self.enabled = true;
    }

    /// Registers a task for OOM tracking.
    pub fn register_task(&mut self, info: TaskOomInfo) -> Result<()> {
        if self.task_count >= MAX_TASKS {
            return Err(Error::OutOfMemory);
        }
        self.tasks[self.task_count] = info;
        self.task_count += 1;
        Ok(())
    }

    /// Updates a task's memory accounting by PID.
    pub fn update_task(&mut self, pid: u32, rss_pages: u64, swap_pages: u64) -> Result<()> {
        let idx = self.find_task(pid)?;
        self.tasks[idx].rss_pages = rss_pages;
        self.tasks[idx].swap_pages = swap_pages;
        Ok(())
    }

    /// Sets the oom_score_adj for a task by PID.
    pub fn set_score_adj(&mut self, pid: u32, adj: i32) -> Result<()> {
        let idx = self.find_task(pid)?;
        self.tasks[idx].score_adj = OomScoreAdj::new(adj);
        Ok(())
    }

    /// Removes a task by PID (e.g., on exit).
    pub fn unregister_task(&mut self, pid: u32) -> Result<()> {
        let idx = self.find_task(pid)?;
        if idx < self.task_count.saturating_sub(1) {
            self.tasks[idx] = self.tasks[self.task_count - 1];
        }
        self.task_count -= 1;
        Ok(())
    }

    /// Registers a cgroup OOM control.
    pub fn register_cgroup(&mut self, control: OomControl) -> Result<()> {
        if self.cgroup_count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        self.cgroups[self.cgroup_count] = control;
        self.cgroup_count += 1;
        Ok(())
    }

    /// Selects the best OOM victim (system-wide).
    ///
    /// Returns the index of the task with the highest badness score.
    /// Recomputes all badness scores before selection.
    pub fn select_bad_process(&mut self) -> Result<u32> {
        if !self.enabled || self.task_count == 0 {
            return Err(Error::NotFound);
        }

        let mut worst_idx = usize::MAX;
        let mut worst_score: u64 = 0;

        for i in 0..self.task_count {
            if self.tasks[i].being_killed {
                continue;
            }
            let score = self.tasks[i].compute_badness(self.total_ram_pages);
            if score > worst_score {
                worst_score = score;
                worst_idx = i;
            }
        }

        if worst_idx == usize::MAX || worst_score == 0 {
            return Err(Error::NotFound);
        }

        Ok(self.tasks[worst_idx].pid)
    }

    /// Selects the best OOM victim within a cgroup.
    pub fn select_bad_process_cgroup(&mut self, cgroup_id: u32) -> Result<u32> {
        if !self.enabled || self.task_count == 0 {
            return Err(Error::NotFound);
        }

        let mut worst_idx = usize::MAX;
        let mut worst_score: u64 = 0;

        for i in 0..self.task_count {
            if self.tasks[i].cgroup_id != cgroup_id {
                continue;
            }
            if self.tasks[i].being_killed {
                continue;
            }
            let score = self.tasks[i].compute_badness(self.total_ram_pages);
            if score > worst_score {
                worst_score = score;
                worst_idx = i;
            }
        }

        if worst_idx == usize::MAX || worst_score == 0 {
            return Err(Error::NotFound);
        }

        Ok(self.tasks[worst_idx].pid)
    }

    /// Kills the process with the given PID (marks it for killing
    /// and records the event).
    ///
    /// The actual SIGKILL delivery is done by the caller; this
    /// method handles bookkeeping.
    pub fn oom_kill_process(&mut self, pid: u32, free_pages: u64) -> Result<OomKillRecord> {
        let idx = self.find_task(pid)?;
        if self.tasks[idx].being_killed {
            return Err(Error::AlreadyExists);
        }

        self.tasks[idx].being_killed = true;
        self.timestamp += 1;

        let record = OomKillRecord {
            timestamp: self.timestamp,
            killed_pid: pid,
            badness_score: self.tasks[idx].computed_badness,
            rss_pages: self.tasks[idx].rss_pages,
            cgroup_id: self.tasks[idx].cgroup_id,
            cgroup_scoped: false,
            free_pages_at_oom: free_pages,
        };

        // Record in ring buffer
        self.kill_records[self.record_head] = record;
        self.record_head = (self.record_head + 1) % MAX_KILL_RECORDS;
        self.total_kills += 1;

        // Increment cgroup event counter
        let cgroup_id = self.tasks[idx].cgroup_id;
        for c in 0..self.cgroup_count {
            if self.cgroups[c].cgroup_id == cgroup_id {
                self.cgroups[c].oom_events += 1;
                break;
            }
        }

        Ok(record)
    }

    /// Runs the full OOM kill cycle: select victim and kill.
    pub fn invoke_oom_killer(&mut self, free_pages: u64) -> Result<OomKillRecord> {
        let pid = self.select_bad_process()?;
        self.oom_kill_process(pid, free_pages)
    }

    /// Runs a cgroup-scoped OOM kill cycle.
    pub fn invoke_cgroup_oom(&mut self, cgroup_id: u32, free_pages: u64) -> Result<OomKillRecord> {
        let pid = self.select_bad_process_cgroup(cgroup_id)?;
        let mut record = self.oom_kill_process(pid, free_pages)?;
        record.cgroup_scoped = true;
        // Update stored record too
        let prev = if self.record_head == 0 {
            MAX_KILL_RECORDS - 1
        } else {
            self.record_head - 1
        };
        self.kill_records[prev].cgroup_scoped = true;
        Ok(record)
    }

    /// Returns the total number of OOM kills since boot.
    pub const fn total_kills(&self) -> u64 {
        self.total_kills
    }

    /// Returns the number of registered tasks.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Enables or disables the OOM killer globally.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns the most recent kill records (up to `count`).
    pub fn recent_kills(&self, count: usize) -> &[OomKillRecord] {
        let actual = count.min(MAX_KILL_RECORDS);
        &self.kill_records[..actual]
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Finds a task by PID, returns its index.
    fn find_task(&self, pid: u32) -> Result<usize> {
        for i in 0..self.task_count {
            if self.tasks[i].pid == pid {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }
}

impl Default for OomKiller {
    fn default() -> Self {
        Self::new()
    }
}
