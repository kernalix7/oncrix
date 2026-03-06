// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 freezer controller.
//!
//! Implements process freezing/thawing via the cgroup v2 freezer
//! interface, modeled after the Linux kernel cgroup freezer
//! (`kernel/cgroup/freezer.c`).
//!
//! # Features
//!
//! - **Per-cgroup freeze state**: [`FreezerState`] tracks whether
//!   a cgroup is `Thawed`, `Freezing`, or `Frozen`.
//! - **Hierarchical propagation**: freezing a parent cgroup
//!   automatically propagates to all descendant cgroups.
//! - **Task freeze/thaw hooks**: individual tasks are marked as
//!   frozen/unfrozen via the [`TaskFreezeState`] enum.
//! - **Registry**: [`FreezerRegistry`] tracks up to 64 cgroups
//!   with full lifecycle management.
//!
//! # Usage
//!
//! ```ignore
//! let mut registry = FreezerRegistry::new();
//! let cg = registry.register(1, None)?;  // root freezer
//! let child = registry.register(2, Some(1))?;
//!
//! freeze_cgroup(&mut registry, 1)?;   // freezes cg 1 and child 2
//! thaw_cgroup(&mut registry, 1)?;     // thaws both
//! ```
//!
//! Reference: Linux `kernel/cgroup/freezer.c`,
//! `include/linux/cgroup.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of cgroups tracked by the freezer registry.
const MAX_FREEZER_CGROUPS: usize = 64;

/// Maximum number of tasks per freezer cgroup.
const MAX_TASKS_PER_CGROUP: usize = 64;

/// Maximum children per cgroup (for hierarchical propagation).
const MAX_CHILDREN: usize = 16;

// ── FreezerState ───────────────────────────────────────────────────

/// State of a cgroup freezer.
///
/// The state machine transitions:
/// ```text
/// Thawed ──freeze()──► Freezing ──all_frozen()──► Frozen
///   ▲                                               │
///   └──────────────── thaw() ◄──────────────────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FreezerState {
    /// All tasks in the cgroup are runnable.
    #[default]
    Thawed,
    /// Freeze has been requested; waiting for all tasks to freeze.
    Freezing,
    /// All tasks have been frozen.
    Frozen,
}

impl core::fmt::Display for FreezerState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Thawed => write!(f, "THAWED"),
            Self::Freezing => write!(f, "FREEZING"),
            Self::Frozen => write!(f, "FROZEN"),
        }
    }
}

// ── TaskFreezeState ────────────────────────────────────────────────

/// Freeze state of an individual task within a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TaskFreezeState {
    /// Task is running normally.
    #[default]
    Running,
    /// Task has been marked for freezing.
    FreezeRequested,
    /// Task is frozen (stopped execution).
    Frozen,
}

// ── FreezerTask ────────────────────────────────────────────────────

/// A task tracked by the freezer controller.
#[derive(Debug, Clone, Copy)]
struct FreezerTask {
    /// Task PID.
    pid: u64,
    /// Current freeze state.
    state: TaskFreezeState,
    /// Whether this slot is occupied.
    in_use: bool,
}

impl FreezerTask {
    /// Create an empty task slot.
    const fn empty() -> Self {
        Self {
            pid: 0,
            state: TaskFreezeState::Running,
            in_use: false,
        }
    }
}

// ── CgroupFreezer ──────────────────────────────────────────────────

/// Per-cgroup freezer controller state.
///
/// Tracks the freeze state and all member tasks for a single
/// cgroup. Parent ID enables hierarchical propagation.
pub struct CgroupFreezer {
    /// Cgroup identifier.
    cgroup_id: u64,
    /// Parent cgroup ID (`None` for root-level freezer).
    parent_id: Option<u64>,
    /// Current freezer state.
    state: FreezerState,
    /// Whether a self-freeze was requested (vs. inherited from
    /// parent).
    self_freezing: bool,
    /// Tasks tracked by this freezer.
    tasks: [FreezerTask; MAX_TASKS_PER_CGROUP],
    /// Number of active tasks.
    task_count: usize,
    /// Number of tasks currently frozen.
    frozen_count: usize,
    /// Whether this slot is in use.
    in_use: bool,
}

impl CgroupFreezer {
    /// Create an empty (inactive) freezer slot.
    const fn empty() -> Self {
        const EMPTY_TASK: FreezerTask = FreezerTask::empty();
        Self {
            cgroup_id: 0,
            parent_id: None,
            state: FreezerState::Thawed,
            self_freezing: false,
            tasks: [EMPTY_TASK; MAX_TASKS_PER_CGROUP],
            task_count: 0,
            frozen_count: 0,
            in_use: false,
        }
    }

    /// Return the cgroup ID.
    pub const fn cgroup_id(&self) -> u64 {
        self.cgroup_id
    }

    /// Return the parent cgroup ID.
    pub const fn parent_id(&self) -> Option<u64> {
        self.parent_id
    }

    /// Return the current freezer state.
    pub const fn state(&self) -> FreezerState {
        self.state
    }

    /// Return the number of active tasks.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Return the number of frozen tasks.
    pub const fn frozen_count(&self) -> usize {
        self.frozen_count
    }

    /// Return whether this freezer was explicitly frozen (vs.
    /// inherited from parent).
    pub const fn is_self_freezing(&self) -> bool {
        self.self_freezing
    }

    /// Add a task to this freezer.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] — task is already tracked.
    /// - [`Error::OutOfMemory`] — task list is full.
    pub fn add_task(&mut self, pid: u64) -> Result<()> {
        // Check duplicate.
        for i in 0..MAX_TASKS_PER_CGROUP {
            if self.tasks[i].in_use && self.tasks[i].pid == pid {
                return Err(Error::AlreadyExists);
            }
        }
        if self.task_count >= MAX_TASKS_PER_CGROUP {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot.
        let slot = self
            .tasks
            .iter()
            .position(|t| !t.in_use)
            .ok_or(Error::OutOfMemory)?;

        // If the cgroup is frozen/freezing, new tasks inherit the
        // freeze request.
        let initial_state = if self.state != FreezerState::Thawed {
            TaskFreezeState::FreezeRequested
        } else {
            TaskFreezeState::Running
        };

        self.tasks[slot] = FreezerTask {
            pid,
            state: initial_state,
            in_use: true,
        };
        self.task_count += 1;
        Ok(())
    }

    /// Remove a task from this freezer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the task is not tracked.
    pub fn remove_task(&mut self, pid: u64) -> Result<()> {
        for task in &mut self.tasks {
            if task.in_use && task.pid == pid {
                if task.state == TaskFreezeState::Frozen {
                    self.frozen_count = self.frozen_count.saturating_sub(1);
                }
                task.in_use = false;
                self.task_count = self.task_count.saturating_sub(1);
                self.update_state();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Mark a task as having completed its freeze.
    ///
    /// Called by the scheduler when a task enters a frozen wait
    /// state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the task is not tracked.
    pub fn task_frozen(&mut self, pid: u64) -> Result<()> {
        for task in &mut self.tasks {
            if task.in_use && task.pid == pid {
                if task.state != TaskFreezeState::Frozen {
                    task.state = TaskFreezeState::Frozen;
                    self.frozen_count += 1;
                    self.update_state();
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Initiate freezing of all tasks in this cgroup.
    fn begin_freeze(&mut self) {
        self.state = FreezerState::Freezing;
        self.self_freezing = true;
        for task in &mut self.tasks {
            if task.in_use && task.state == TaskFreezeState::Running {
                task.state = TaskFreezeState::FreezeRequested;
            }
        }
        self.update_state();
    }

    /// Thaw all tasks in this cgroup.
    fn begin_thaw(&mut self) {
        self.self_freezing = false;
        for task in &mut self.tasks {
            if task.in_use {
                if task.state == TaskFreezeState::Frozen {
                    self.frozen_count = self.frozen_count.saturating_sub(1);
                }
                task.state = TaskFreezeState::Running;
            }
        }
        self.state = FreezerState::Thawed;
    }

    /// Re-evaluate the freezer state based on task states.
    fn update_state(&mut self) {
        if !self.self_freezing {
            return;
        }
        if self.task_count == 0 {
            // Empty cgroup with freeze request is considered
            // frozen.
            self.state = FreezerState::Frozen;
        } else if self.frozen_count >= self.task_count {
            self.state = FreezerState::Frozen;
        } else {
            self.state = FreezerState::Freezing;
        }
    }
}

// ── FreezerRegistry ────────────────────────────────────────────────

/// System-wide registry of cgroup freezer controllers.
///
/// Manages up to [`MAX_FREEZER_CGROUPS`] freezer instances,
/// supporting hierarchical freeze/thaw propagation.
pub struct FreezerRegistry {
    /// Fixed-size array of freezer slots.
    freezers: [CgroupFreezer; MAX_FREEZER_CGROUPS],
    /// Number of active freezers.
    count: usize,
}

impl Default for FreezerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FreezerRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const EMPTY: CgroupFreezer = CgroupFreezer::empty();
        Self {
            freezers: [EMPTY; MAX_FREEZER_CGROUPS],
            count: 0,
        }
    }

    /// Return the number of active freezers.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Register a new cgroup with the freezer.
    ///
    /// `cgroup_id` is the cgroup identifier. `parent_id` is the
    /// parent cgroup's ID, or `None` for a root-level freezer.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] — cgroup is already registered.
    /// - [`Error::OutOfMemory`] — registry is full.
    /// - [`Error::NotFound`] — `parent_id` is specified but does
    ///   not exist in the registry.
    pub fn register(&mut self, cgroup_id: u64, parent_id: Option<u64>) -> Result<()> {
        // Check duplicate.
        if self.find_index(cgroup_id).is_some() {
            return Err(Error::AlreadyExists);
        }

        // Validate parent exists.
        if let Some(pid) = parent_id {
            if self.find_index(pid).is_none() {
                return Err(Error::NotFound);
            }
        }

        if self.count >= MAX_FREEZER_CGROUPS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .freezers
            .iter()
            .position(|f| !f.in_use)
            .ok_or(Error::OutOfMemory)?;

        let freezer = &mut self.freezers[slot];
        *freezer = CgroupFreezer::empty();
        freezer.cgroup_id = cgroup_id;
        freezer.parent_id = parent_id;
        freezer.in_use = true;

        // If parent is frozen/freezing, inherit the freeze.
        if let Some(pid) = parent_id {
            if let Some(pi) = self.find_index(pid) {
                if self.freezers[pi].state != FreezerState::Thawed {
                    self.freezers[slot].state = FreezerState::Frozen;
                    self.freezers[slot].self_freezing = true;
                }
            }
        }

        self.count += 1;
        Ok(())
    }

    /// Unregister a cgroup from the freezer.
    ///
    /// The cgroup must have no tasks and no children.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — cgroup is not registered.
    /// - [`Error::Busy`] — cgroup still has tasks or children.
    pub fn unregister(&mut self, cgroup_id: u64) -> Result<()> {
        let idx = self.find_index(cgroup_id).ok_or(Error::NotFound)?;

        if self.freezers[idx].task_count > 0 {
            return Err(Error::Busy);
        }

        // Check for children.
        for f in &self.freezers {
            if f.in_use && f.parent_id == Some(cgroup_id) {
                return Err(Error::Busy);
            }
        }

        self.freezers[idx].in_use = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Return an immutable reference to a cgroup freezer by ID.
    pub fn get(&self, cgroup_id: u64) -> Option<&CgroupFreezer> {
        self.find_index(cgroup_id).map(|i| &self.freezers[i])
    }

    /// Return a mutable reference to a cgroup freezer by ID.
    pub fn get_mut(&mut self, cgroup_id: u64) -> Option<&mut CgroupFreezer> {
        self.find_index(cgroup_id).map(|i| &mut self.freezers[i])
    }

    /// Add a task to a cgroup's freezer.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — cgroup not registered.
    /// - [`Error::AlreadyExists`] — task already tracked.
    /// - [`Error::OutOfMemory`] — task list full.
    pub fn add_task(&mut self, cgroup_id: u64, pid: u64) -> Result<()> {
        let idx = self.find_index(cgroup_id).ok_or(Error::NotFound)?;
        self.freezers[idx].add_task(pid)
    }

    /// Remove a task from a cgroup's freezer.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — cgroup not registered or task not
    ///   tracked.
    pub fn remove_task(&mut self, cgroup_id: u64, pid: u64) -> Result<()> {
        let idx = self.find_index(cgroup_id).ok_or(Error::NotFound)?;
        self.freezers[idx].remove_task(pid)
    }

    /// Notify the freezer that a task has frozen.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — cgroup not registered or task not
    ///   tracked.
    pub fn task_frozen(&mut self, cgroup_id: u64, pid: u64) -> Result<()> {
        let idx = self.find_index(cgroup_id).ok_or(Error::NotFound)?;
        self.freezers[idx].task_frozen(pid)
    }

    /// Collect child cgroup IDs for the given parent.
    ///
    /// Returns the number of children found. Results are written
    /// into `buf`.
    fn collect_children(&self, parent_id: u64, buf: &mut [u64; MAX_CHILDREN]) -> usize {
        let mut count = 0;
        for f in &self.freezers {
            if f.in_use && f.parent_id == Some(parent_id) && count < MAX_CHILDREN {
                buf[count] = f.cgroup_id;
                count += 1;
            }
        }
        count
    }

    /// Find the index of a cgroup in the freezer array.
    fn find_index(&self, cgroup_id: u64) -> Option<usize> {
        self.freezers
            .iter()
            .position(|f| f.in_use && f.cgroup_id == cgroup_id)
    }
}

// ── Public API ─────────────────────────────────────────────────────

/// Freeze a cgroup and all its descendants.
///
/// Initiates the freeze for the specified cgroup and recursively
/// propagates to all child cgroups in the hierarchy. Each cgroup
/// enters the `Freezing` state; tasks are individually frozen by
/// the scheduler calling [`FreezerRegistry::task_frozen`].
///
/// # Errors
///
/// Returns [`Error::NotFound`] if the cgroup is not registered.
pub fn freeze_cgroup(registry: &mut FreezerRegistry, cgroup_id: u64) -> Result<()> {
    let idx = registry.find_index(cgroup_id).ok_or(Error::NotFound)?;
    registry.freezers[idx].begin_freeze();

    // Collect and freeze children (iterative to avoid deep
    // recursion in a no_std environment).
    let mut stack = [0u64; MAX_CHILDREN];
    let mut stack_top: usize = 0;

    // Push direct children.
    let mut children = [0u64; MAX_CHILDREN];
    let n = registry.collect_children(cgroup_id, &mut children);
    for child_id in children.iter().take(n) {
        if stack_top < MAX_CHILDREN {
            stack[stack_top] = *child_id;
            stack_top += 1;
        }
    }

    while stack_top > 0 {
        stack_top -= 1;
        let child_id = stack[stack_top];

        if let Some(ci) = registry.find_index(child_id) {
            registry.freezers[ci].begin_freeze();

            // Push grandchildren.
            let mut grandchildren = [0u64; MAX_CHILDREN];
            let gc = registry.collect_children(child_id, &mut grandchildren);
            for gid in grandchildren.iter().take(gc) {
                if stack_top < MAX_CHILDREN {
                    stack[stack_top] = *gid;
                    stack_top += 1;
                }
            }
        }
    }

    Ok(())
}

/// Thaw a cgroup and all its descendants.
///
/// Reverses a prior freeze for the specified cgroup and
/// recursively propagates to all child cgroups. All tasks are
/// returned to the `Running` state.
///
/// # Errors
///
/// Returns [`Error::NotFound`] if the cgroup is not registered.
pub fn thaw_cgroup(registry: &mut FreezerRegistry, cgroup_id: u64) -> Result<()> {
    let idx = registry.find_index(cgroup_id).ok_or(Error::NotFound)?;
    registry.freezers[idx].begin_thaw();

    // Collect and thaw children (iterative).
    let mut stack = [0u64; MAX_CHILDREN];
    let mut stack_top: usize = 0;

    let mut children = [0u64; MAX_CHILDREN];
    let n = registry.collect_children(cgroup_id, &mut children);
    for child_id in children.iter().take(n) {
        if stack_top < MAX_CHILDREN {
            stack[stack_top] = *child_id;
            stack_top += 1;
        }
    }

    while stack_top > 0 {
        stack_top -= 1;
        let child_id = stack[stack_top];

        if let Some(ci) = registry.find_index(child_id) {
            registry.freezers[ci].begin_thaw();

            let mut grandchildren = [0u64; MAX_CHILDREN];
            let gc = registry.collect_children(child_id, &mut grandchildren);
            for gid in grandchildren.iter().take(gc) {
                if stack_top < MAX_CHILDREN {
                    stack[stack_top] = *gid;
                    stack_top += 1;
                }
            }
        }
    }

    Ok(())
}
