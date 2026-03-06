// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory cgroup OOM handling.
//!
//! Extends the base OOM killer with cgroup-aware victim selection.
//! When a memory cgroup exceeds its limit, only processes within
//! that cgroup (and its children) are candidates for killing.
//!
//! # Key Types
//!
//! - [`MemcgOomControl`] — per-cgroup OOM configuration
//! - [`MemcgOomEvent`] — OOM event types for `cgroup.events`
//! - [`MemcgOomGroupMode`] — single-victim vs. group-kill mode
//! - [`MemcgTask`] — per-task OOM accounting within a cgroup
//! - [`MemcgOomKiller`] — the cgroup-aware OOM killer
//! - [`MemcgOomStats`] — OOM event statistics
//!
//! Reference: Linux `mm/memcontrol.c`, `mm/oom_kill.c`,
//! `include/linux/memcontrol.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of memory cgroups tracked.
const MAX_MEMCGS: usize = 64;

/// Maximum tasks per cgroup for OOM selection.
const MAX_TASKS_PER_CG: usize = 128;

/// Maximum cgroup hierarchy depth.
const MAX_HIERARCHY_DEPTH: usize = 8;

/// Default OOM score adjustment.
const DEFAULT_OOM_SCORE_ADJ: i32 = 0;

/// Minimum oom_score_adj (prevents OOM killing).
const OOM_SCORE_ADJ_MIN: i32 = -1000;

/// Maximum oom_score_adj (most likely to be killed).
const OOM_SCORE_ADJ_MAX: i32 = 1000;

/// Score value that completely disables OOM for a task.
const OOM_DISABLE_SCORE: i32 = -1000;

/// Maximum recorded OOM kill events.
const MAX_OOM_EVENTS: usize = 64;

// -------------------------------------------------------------------
// MemcgOomGroupMode
// -------------------------------------------------------------------

/// How the OOM killer selects victims within a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemcgOomGroupMode {
    /// Kill only the single worst-scoring task (default).
    #[default]
    Single,
    /// Kill all tasks in the cgroup (memory.oom.group = 1).
    Group,
}

// -------------------------------------------------------------------
// MemcgOomEvent
// -------------------------------------------------------------------

/// OOM event types reported via `cgroup.events`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemcgOomEvent {
    /// An OOM condition occurred (may or may not kill).
    Oom,
    /// A task was actually killed by the OOM killer.
    OomKill,
    /// OOM was resolved without killing (reclaim succeeded).
    OomRecovered,
}

// -------------------------------------------------------------------
// MemcgOomControl
// -------------------------------------------------------------------

/// Per-cgroup OOM configuration.
#[derive(Debug, Clone, Copy)]
pub struct MemcgOomControl {
    /// Whether OOM killing is disabled for this cgroup.
    /// If true, tasks sleep until memory is available.
    pub oom_kill_disable: bool,
    /// Whether the cgroup is currently under OOM pressure.
    pub under_oom: bool,
    /// Total number of OOM kills in this cgroup.
    pub oom_kill_count: u32,
    /// Total number of OOM events (including non-kill).
    pub oom_event_count: u32,
    /// Group kill mode.
    pub group_mode: MemcgOomGroupMode,
    /// OOM priority for this cgroup (lower = less likely to OOM).
    pub priority: i32,
}

impl MemcgOomControl {
    /// Create a default OOM control.
    pub const fn new() -> Self {
        Self {
            oom_kill_disable: false,
            under_oom: false,
            oom_kill_count: 0,
            oom_event_count: 0,
            group_mode: MemcgOomGroupMode::Single,
            priority: 0,
        }
    }
}

impl Default for MemcgOomControl {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MemcgTask
// -------------------------------------------------------------------

/// Per-task OOM accounting within a cgroup.
#[derive(Debug, Clone, Copy)]
pub struct MemcgTask {
    /// Task (process) ID.
    pub pid: u32,
    /// Cgroup ID this task belongs to.
    pub cgroup_id: u32,
    /// Resident set size in pages.
    pub rss_pages: u64,
    /// Swap usage in pages.
    pub swap_pages: u64,
    /// oom_score_adj set by userspace (-1000..1000).
    pub oom_score_adj: i32,
    /// Whether this task is still alive.
    pub alive: bool,
    /// Computed OOM score (higher = more likely to be killed).
    pub oom_score: u32,
}

impl MemcgTask {
    /// Create an empty task entry.
    const fn empty() -> Self {
        Self {
            pid: 0,
            cgroup_id: 0,
            rss_pages: 0,
            swap_pages: 0,
            oom_score_adj: DEFAULT_OOM_SCORE_ADJ,
            alive: false,
            oom_score: 0,
        }
    }

    /// Compute the OOM score for this task.
    ///
    /// Score = (rss_pages + swap_pages) * (1000 + oom_score_adj) / 2000.
    /// A task with oom_score_adj = -1000 is immune.
    fn compute_score(&mut self) {
        if self.oom_score_adj == OOM_DISABLE_SCORE {
            self.oom_score = 0;
            return;
        }
        let mem = self.rss_pages + self.swap_pages;
        let adj = (self.oom_score_adj + 1000) as u64;
        // Scale: mem * adj / 2000, clamped to u32.
        let score = mem.saturating_mul(adj) / 2000;
        self.oom_score = if score > u32::MAX as u64 {
            u32::MAX
        } else {
            score as u32
        };
    }
}

// -------------------------------------------------------------------
// MemcgDescriptor
// -------------------------------------------------------------------

/// Per-cgroup descriptor for OOM purposes.
struct MemcgDescriptor {
    /// Cgroup ID.
    cgroup_id: u32,
    /// Parent cgroup ID (0 = root).
    parent_id: u32,
    /// OOM control settings.
    oom_control: MemcgOomControl,
    /// Memory limit in pages.
    limit_pages: u64,
    /// Current usage in pages.
    usage_pages: u64,
    /// Tasks in this cgroup.
    tasks: [MemcgTask; MAX_TASKS_PER_CG],
    /// Number of active tasks.
    task_count: usize,
    /// Whether this descriptor is in use.
    active: bool,
    /// Hierarchy depth (0 = root).
    depth: u8,
}

impl MemcgDescriptor {
    /// Create an empty descriptor.
    const fn empty() -> Self {
        Self {
            cgroup_id: 0,
            parent_id: 0,
            oom_control: MemcgOomControl::new(),
            limit_pages: 0,
            usage_pages: 0,
            tasks: [const { MemcgTask::empty() }; MAX_TASKS_PER_CG],
            task_count: 0,
            active: false,
            depth: 0,
        }
    }

    /// Check whether this cgroup is over its memory limit.
    fn is_over_limit(&self) -> bool {
        self.limit_pages > 0 && self.usage_pages > self.limit_pages
    }
}

// -------------------------------------------------------------------
// OomKillRecord
// -------------------------------------------------------------------

/// Record of an OOM kill event.
#[derive(Debug, Clone, Copy)]
pub struct OomKillRecord {
    /// Cgroup ID where the OOM occurred.
    pub cgroup_id: u32,
    /// PID of the killed task.
    pub killed_pid: u32,
    /// OOM score of the killed task.
    pub score: u32,
    /// RSS at time of kill.
    pub rss_pages: u64,
    /// Whether group kill mode was used.
    pub group_kill: bool,
    /// Number of tasks killed (>1 in group mode).
    pub tasks_killed: u32,
    /// Timestamp (tick counter).
    pub timestamp: u64,
}

impl OomKillRecord {
    /// Create an empty record.
    const fn empty() -> Self {
        Self {
            cgroup_id: 0,
            killed_pid: 0,
            score: 0,
            rss_pages: 0,
            group_kill: false,
            tasks_killed: 0,
            timestamp: 0,
        }
    }
}

// -------------------------------------------------------------------
// MemcgOomStats
// -------------------------------------------------------------------

/// OOM statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemcgOomStats {
    /// Total OOM events across all cgroups.
    pub total_oom_events: u64,
    /// Total tasks killed.
    pub total_kills: u64,
    /// Total group kills.
    pub total_group_kills: u64,
    /// Total OOM events where killing was disabled.
    pub total_disabled_events: u64,
    /// Total OOM events recovered by reclaim.
    pub total_recovered: u64,
}

// -------------------------------------------------------------------
// MemcgOomKiller
// -------------------------------------------------------------------

/// Cgroup-aware OOM killer.
///
/// Manages per-cgroup OOM controls, selects victims within cgroup
/// hierarchies, and tracks OOM kill events.
pub struct MemcgOomKiller {
    /// Cgroup descriptors.
    cgroups: [MemcgDescriptor; MAX_MEMCGS],
    /// OOM kill event log.
    events: [OomKillRecord; MAX_OOM_EVENTS],
    /// Number of recorded events.
    event_count: usize,
    /// Global tick counter (simulated timestamp).
    tick: u64,
    /// Statistics.
    stats: MemcgOomStats,
}

impl MemcgOomKiller {
    /// Create a new cgroup OOM killer.
    pub const fn new() -> Self {
        Self {
            cgroups: [const { MemcgDescriptor::empty() }; MAX_MEMCGS],
            events: [const { OomKillRecord::empty() }; MAX_OOM_EVENTS],
            event_count: 0,
            tick: 0,
            stats: MemcgOomStats {
                total_oom_events: 0,
                total_kills: 0,
                total_group_kills: 0,
                total_disabled_events: 0,
                total_recovered: 0,
            },
        }
    }

    /// Register a cgroup for OOM tracking.
    ///
    /// # Errors
    /// - `OutOfMemory` — no free cgroup slots.
    /// - `AlreadyExists` — cgroup_id already registered.
    pub fn register_cgroup(
        &mut self,
        cgroup_id: u32,
        parent_id: u32,
        limit_pages: u64,
    ) -> Result<usize> {
        // Check duplicates.
        if self.find_cgroup(cgroup_id).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let parent_depth = if parent_id == 0 {
            0u8
        } else {
            let pi = self.find_cgroup(parent_id)?;
            let d = self.cgroups[pi].depth;
            if d as usize >= MAX_HIERARCHY_DEPTH - 1 {
                return Err(Error::InvalidArgument);
            }
            d + 1
        };

        for i in 0..MAX_MEMCGS {
            if !self.cgroups[i].active {
                self.cgroups[i].cgroup_id = cgroup_id;
                self.cgroups[i].parent_id = parent_id;
                self.cgroups[i].limit_pages = limit_pages;
                self.cgroups[i].usage_pages = 0;
                self.cgroups[i].oom_control = MemcgOomControl::new();
                self.cgroups[i].task_count = 0;
                self.cgroups[i].active = true;
                self.cgroups[i].depth = parent_depth;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a cgroup.
    ///
    /// # Errors
    /// - `NotFound` — cgroup not registered.
    /// - `Busy` — cgroup still has tasks.
    pub fn unregister_cgroup(&mut self, cgroup_id: u32) -> Result<()> {
        let idx = self.find_cgroup(cgroup_id)?;
        if self.cgroups[idx].task_count > 0 {
            return Err(Error::Busy);
        }
        self.cgroups[idx] = MemcgDescriptor::empty();
        Ok(())
    }

    /// Find a cgroup by ID.
    fn find_cgroup(&self, cgroup_id: u32) -> Result<usize> {
        for i in 0..MAX_MEMCGS {
            if self.cgroups[i].active && self.cgroups[i].cgroup_id == cgroup_id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Add a task to a cgroup for OOM tracking.
    ///
    /// # Errors
    /// - `NotFound` — cgroup not registered.
    /// - `OutOfMemory` — task array full.
    pub fn add_task(
        &mut self,
        cgroup_id: u32,
        pid: u32,
        rss_pages: u64,
        swap_pages: u64,
        oom_score_adj: i32,
    ) -> Result<()> {
        let idx = self.find_cgroup(cgroup_id)?;
        let adj = oom_score_adj.clamp(OOM_SCORE_ADJ_MIN, OOM_SCORE_ADJ_MAX);

        let tc = self.cgroups[idx].task_count;
        if tc >= MAX_TASKS_PER_CG {
            return Err(Error::OutOfMemory);
        }
        self.cgroups[idx].tasks[tc] = MemcgTask {
            pid,
            cgroup_id,
            rss_pages,
            swap_pages,
            oom_score_adj: adj,
            alive: true,
            oom_score: 0,
        };
        self.cgroups[idx].tasks[tc].compute_score();
        self.cgroups[idx].task_count += 1;
        self.cgroups[idx].usage_pages += rss_pages + swap_pages;
        Ok(())
    }

    /// Remove a task from a cgroup.
    ///
    /// # Errors
    /// - `NotFound` — cgroup or task not found.
    pub fn remove_task(&mut self, cgroup_id: u32, pid: u32) -> Result<()> {
        let idx = self.find_cgroup(cgroup_id)?;
        for t in 0..self.cgroups[idx].task_count {
            if self.cgroups[idx].tasks[t].pid == pid {
                let pages =
                    self.cgroups[idx].tasks[t].rss_pages + self.cgroups[idx].tasks[t].swap_pages;
                self.cgroups[idx].usage_pages = self.cgroups[idx].usage_pages.saturating_sub(pages);

                // Compact: swap with last.
                let last = self.cgroups[idx].task_count - 1;
                if t != last {
                    self.cgroups[idx].tasks.swap(t, last);
                }
                self.cgroups[idx].tasks[last] = MemcgTask::empty();
                self.cgroups[idx].task_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Set the OOM control for a cgroup.
    ///
    /// # Errors
    /// - `NotFound` — cgroup not registered.
    pub fn set_oom_control(&mut self, cgroup_id: u32, control: MemcgOomControl) -> Result<()> {
        let idx = self.find_cgroup(cgroup_id)?;
        self.cgroups[idx].oom_control = control;
        Ok(())
    }

    /// Get the OOM control for a cgroup.
    ///
    /// # Errors
    /// - `NotFound` — cgroup not registered.
    pub fn get_oom_control(&self, cgroup_id: u32) -> Result<MemcgOomControl> {
        let idx = self.find_cgroup(cgroup_id)?;
        Ok(self.cgroups[idx].oom_control)
    }

    /// Select the worst process within a cgroup for OOM killing.
    ///
    /// Computes scores for all alive tasks and returns the PID
    /// of the one with the highest score.
    ///
    /// # Errors
    /// - `NotFound` — cgroup not found or no eligible tasks.
    pub fn select_bad_process(&mut self, cgroup_id: u32) -> Result<u32> {
        let idx = self.find_cgroup(cgroup_id)?;

        // Recompute scores.
        for t in 0..self.cgroups[idx].task_count {
            self.cgroups[idx].tasks[t].compute_score();
        }

        let mut best_pid = 0u32;
        let mut best_score = 0u32;
        let mut found = false;

        for t in 0..self.cgroups[idx].task_count {
            let task = &self.cgroups[idx].tasks[t];
            if !task.alive {
                continue;
            }
            if task.oom_score_adj == OOM_DISABLE_SCORE {
                continue;
            }
            if task.oom_score > best_score || !found {
                best_score = task.oom_score;
                best_pid = task.pid;
                found = true;
            }
        }

        if !found {
            return Err(Error::NotFound);
        }
        Ok(best_pid)
    }

    /// Entry point: handle OOM for a cgroup.
    ///
    /// If OOM killing is disabled, marks the cgroup as under_oom
    /// and returns `WouldBlock`. Otherwise, selects and kills
    /// the worst task (or all tasks in group mode).
    ///
    /// Returns the number of tasks killed.
    ///
    /// # Errors
    /// - `NotFound` — cgroup not found.
    /// - `WouldBlock` — OOM killing disabled for this cgroup.
    pub fn out_of_memory(&mut self, cgroup_id: u32) -> Result<u32> {
        let idx = self.find_cgroup(cgroup_id)?;
        self.tick += 1;
        self.stats.total_oom_events += 1;
        self.cgroups[idx].oom_control.oom_event_count += 1;

        // Check if OOM killing is disabled.
        if self.cgroups[idx].oom_control.oom_kill_disable {
            self.cgroups[idx].oom_control.under_oom = true;
            self.stats.total_disabled_events += 1;
            return Err(Error::WouldBlock);
        }

        // Check if cgroup is actually over limit.
        if !self.cgroups[idx].is_over_limit() {
            self.stats.total_recovered += 1;
            return Ok(0);
        }

        let group_mode = self.cgroups[idx].oom_control.group_mode;

        match group_mode {
            MemcgOomGroupMode::Single => self.kill_single(idx),
            MemcgOomGroupMode::Group => self.kill_group(idx),
        }
    }

    /// Kill the single worst-scoring task in a cgroup.
    fn kill_single(&mut self, cg_idx: usize) -> Result<u32> {
        let cgroup_id = self.cgroups[cg_idx].cgroup_id;

        // Find worst task.
        let victim_pid = self.select_bad_process(cgroup_id)?;

        // Mark as killed.
        for t in 0..self.cgroups[cg_idx].task_count {
            if self.cgroups[cg_idx].tasks[t].pid == victim_pid {
                let rss = self.cgroups[cg_idx].tasks[t].rss_pages;
                let score = self.cgroups[cg_idx].tasks[t].oom_score;
                self.cgroups[cg_idx].tasks[t].alive = false;

                // Record event.
                self.record_event(OomKillRecord {
                    cgroup_id,
                    killed_pid: victim_pid,
                    score,
                    rss_pages: rss,
                    group_kill: false,
                    tasks_killed: 1,
                    timestamp: self.tick,
                });

                self.cgroups[cg_idx].oom_control.oom_kill_count += 1;
                self.stats.total_kills += 1;
                return Ok(1);
            }
        }
        Err(Error::NotFound)
    }

    /// Kill all tasks in a cgroup (group OOM mode).
    fn kill_group(&mut self, cg_idx: usize) -> Result<u32> {
        let cgroup_id = self.cgroups[cg_idx].cgroup_id;
        let mut killed = 0u32;

        for t in 0..self.cgroups[cg_idx].task_count {
            if self.cgroups[cg_idx].tasks[t].alive
                && self.cgroups[cg_idx].tasks[t].oom_score_adj != OOM_DISABLE_SCORE
            {
                self.cgroups[cg_idx].tasks[t].alive = false;
                killed += 1;
            }
        }

        if killed > 0 {
            self.record_event(OomKillRecord {
                cgroup_id,
                killed_pid: 0, // group kill
                score: 0,
                rss_pages: self.cgroups[cg_idx].usage_pages,
                group_kill: true,
                tasks_killed: killed,
                timestamp: self.tick,
            });
            self.cgroups[cg_idx].oom_control.oom_kill_count += killed;
            self.stats.total_kills += killed as u64;
            self.stats.total_group_kills += 1;
        }

        Ok(killed)
    }

    /// Record an OOM kill event in the event log.
    fn record_event(&mut self, record: OomKillRecord) {
        if self.event_count < MAX_OOM_EVENTS {
            self.events[self.event_count] = record;
            self.event_count += 1;
        }
    }

    /// Hierarchical OOM: check this cgroup and all ancestors.
    ///
    /// Walks up the hierarchy and triggers OOM on the first
    /// over-limit cgroup found.
    ///
    /// # Errors
    /// - `NotFound` — no over-limit cgroup in hierarchy.
    pub fn hierarchical_oom(&mut self, cgroup_id: u32) -> Result<u32> {
        let mut current_id = cgroup_id;
        for _ in 0..MAX_HIERARCHY_DEPTH {
            let idx = self.find_cgroup(current_id)?;
            if self.cgroups[idx].is_over_limit() {
                return self.out_of_memory(current_id);
            }
            let parent = self.cgroups[idx].parent_id;
            if parent == 0 || parent == current_id {
                break;
            }
            current_id = parent;
        }
        Err(Error::NotFound)
    }

    /// Update a task's memory usage.
    ///
    /// # Errors
    /// - `NotFound` — cgroup or task not found.
    pub fn update_task_usage(
        &mut self,
        cgroup_id: u32,
        pid: u32,
        rss_pages: u64,
        swap_pages: u64,
    ) -> Result<()> {
        let idx = self.find_cgroup(cgroup_id)?;
        for t in 0..self.cgroups[idx].task_count {
            if self.cgroups[idx].tasks[t].pid == pid {
                let old =
                    self.cgroups[idx].tasks[t].rss_pages + self.cgroups[idx].tasks[t].swap_pages;
                self.cgroups[idx].tasks[t].rss_pages = rss_pages;
                self.cgroups[idx].tasks[t].swap_pages = swap_pages;
                self.cgroups[idx].tasks[t].compute_score();
                let new_total = rss_pages + swap_pages;
                self.cgroups[idx].usage_pages =
                    self.cgroups[idx].usage_pages.saturating_sub(old) + new_total;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return OOM statistics.
    pub const fn stats(&self) -> &MemcgOomStats {
        &self.stats
    }

    /// Return the event log as a slice.
    pub fn events(&self) -> &[OomKillRecord] {
        &self.events[..self.event_count]
    }

    /// Return the number of recorded OOM events.
    pub const fn event_count(&self) -> usize {
        self.event_count
    }
}
