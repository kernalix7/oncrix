// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Task grouping for the CFS scheduler.
//!
//! Organises tasks into hierarchical groups so that CPU bandwidth is
//! distributed fairly at the group level. This prevents a single user
//! or cgroup with many threads from starving others.
//!
//! # Hierarchy
//!
//! ```text
//! Root TaskGroup (shares = 1024)
//!  ├── Group A (shares = 512)
//!  │    ├── Task 1
//!  │    └── Task 2
//!  └── Group B (shares = 512)
//!       ├── Task 3
//!       ├── Task 4
//!       └── Task 5
//! ```
//!
//! Groups A and B each get 50% of CPU time regardless of how many
//! tasks they contain.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum task groups.
const MAX_GROUPS: usize = 128;

/// Maximum tasks per group.
const MAX_TASKS_PER_GROUP: usize = 256;

/// Default CFS shares for a new group.
const DEFAULT_SHARES: u64 = 1024;

/// Minimum shares value.
const MIN_SHARES: u64 = 2;

/// Maximum shares value.
const MAX_SHARES: u64 = 262_144;

// ======================================================================
// Types
// ======================================================================

/// A task entry within a group.
#[derive(Debug, Clone, Copy)]
pub struct GroupTask {
    /// PID of the task.
    pub pid: u64,
    /// Virtual runtime contribution.
    pub vruntime: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl GroupTask {
    /// Creates an empty group task.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            vruntime: 0,
            active: false,
        }
    }
}

impl Default for GroupTask {
    fn default() -> Self {
        Self::new()
    }
}

/// Task group state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupState {
    /// Group is active and scheduling.
    Active,
    /// Group is throttled (bandwidth exhausted).
    Throttled,
    /// Group is empty (no runnable tasks).
    Empty,
    /// Group has been removed.
    Removed,
}

impl Default for GroupState {
    fn default() -> Self {
        Self::Empty
    }
}

/// A CFS task group.
pub struct TaskGroup {
    /// Group identifier.
    group_id: u64,
    /// Parent group identifier (0 = root).
    parent_id: u64,
    /// CFS shares (weight).
    shares: u64,
    /// Tasks belonging to this group.
    tasks: [GroupTask; MAX_TASKS_PER_GROUP],
    /// Number of active tasks.
    nr_tasks: u32,
    /// Group-level virtual runtime.
    group_vruntime: u64,
    /// Total CPU time consumed by the group (ns).
    sum_exec_ns: u64,
    /// Current group state.
    state: GroupState,
    /// Whether this slot is occupied.
    active: bool,
}

impl TaskGroup {
    /// Creates a new empty task group.
    pub const fn new() -> Self {
        Self {
            group_id: 0,
            parent_id: 0,
            shares: DEFAULT_SHARES,
            tasks: [GroupTask::new(); MAX_TASKS_PER_GROUP],
            nr_tasks: 0,
            group_vruntime: 0,
            sum_exec_ns: 0,
            state: GroupState::Empty,
            active: false,
        }
    }

    /// Returns this group's identifier.
    pub fn group_id(&self) -> u64 {
        self.group_id
    }

    /// Returns the parent group identifier.
    pub fn parent_id(&self) -> u64 {
        self.parent_id
    }

    /// Returns the current shares value.
    pub fn shares(&self) -> u64 {
        self.shares
    }

    /// Returns the number of active tasks.
    pub fn nr_tasks(&self) -> u32 {
        self.nr_tasks
    }

    /// Returns total CPU time consumed (ns).
    pub fn sum_exec_ns(&self) -> u64 {
        self.sum_exec_ns
    }

    /// Returns the group state.
    pub fn state(&self) -> GroupState {
        self.state
    }
}

impl Default for TaskGroup {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages all task groups in the system.
pub struct TaskGroupManager {
    /// Array of task groups.
    groups: [TaskGroup; MAX_GROUPS],
    /// Number of active groups.
    nr_groups: usize,
    /// Next group ID to allocate.
    next_id: u64,
}

impl TaskGroupManager {
    /// Creates a new task group manager with a root group.
    pub const fn new() -> Self {
        Self {
            groups: [const { TaskGroup::new() }; MAX_GROUPS],
            nr_groups: 0,
            next_id: 1,
        }
    }

    /// Creates a new task group under the given parent.
    pub fn create_group(&mut self, parent_id: u64, shares: u64) -> Result<u64> {
        if shares < MIN_SHARES || shares > MAX_SHARES {
            return Err(Error::InvalidArgument);
        }
        if self.nr_groups >= MAX_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let gid = self.next_id;
        self.next_id += 1;

        for group in &mut self.groups {
            if !group.active {
                group.group_id = gid;
                group.parent_id = parent_id;
                group.shares = shares;
                group.nr_tasks = 0;
                group.group_vruntime = 0;
                group.sum_exec_ns = 0;
                group.state = GroupState::Empty;
                group.active = true;
                self.nr_groups += 1;
                return Ok(gid);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes a task group (must be empty).
    pub fn remove_group(&mut self, group_id: u64) -> Result<()> {
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        if self.groups[idx].nr_tasks > 0 {
            return Err(Error::Busy);
        }
        self.groups[idx].state = GroupState::Removed;
        self.groups[idx].active = false;
        self.nr_groups = self.nr_groups.saturating_sub(1);
        Ok(())
    }

    /// Adds a task to a group.
    pub fn add_task(&mut self, group_id: u64, pid: u64) -> Result<()> {
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        let group = &mut self.groups[idx];
        if (group.nr_tasks as usize) >= MAX_TASKS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        for task in &mut group.tasks {
            if !task.active {
                task.pid = pid;
                task.vruntime = group.group_vruntime;
                task.active = true;
                group.nr_tasks += 1;
                if group.state == GroupState::Empty {
                    group.state = GroupState::Active;
                }
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes a task from a group.
    pub fn remove_task(&mut self, group_id: u64, pid: u64) -> Result<()> {
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        let group = &mut self.groups[idx];
        let task_pos = group
            .tasks
            .iter()
            .position(|t| t.active && t.pid == pid)
            .ok_or(Error::NotFound)?;
        group.tasks[task_pos].active = false;
        group.nr_tasks = group.nr_tasks.saturating_sub(1);
        if group.nr_tasks == 0 {
            group.state = GroupState::Empty;
        }
        Ok(())
    }

    /// Updates the CFS shares for a group.
    pub fn set_shares(&mut self, group_id: u64, shares: u64) -> Result<()> {
        if shares < MIN_SHARES || shares > MAX_SHARES {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        self.groups[idx].shares = shares;
        Ok(())
    }

    /// Accounts CPU time for a group.
    pub fn charge_exec(&mut self, group_id: u64, delta_ns: u64) -> Result<()> {
        let idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        let group = &mut self.groups[idx];
        group.sum_exec_ns += delta_ns;
        let weighted = if group.shares > 0 {
            (delta_ns * DEFAULT_SHARES) / group.shares
        } else {
            delta_ns
        };
        group.group_vruntime += weighted;
        Ok(())
    }

    /// Returns the number of active groups.
    pub fn nr_groups(&self) -> usize {
        self.nr_groups
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn find_group(&self, group_id: u64) -> Option<usize> {
        self.groups
            .iter()
            .position(|g| g.active && g.group_id == group_id)
    }
}

impl Default for TaskGroupManager {
    fn default() -> Self {
        Self::new()
    }
}
