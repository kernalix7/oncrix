// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Core Scheduling for SMT-safe co-scheduling.
//!
//! Prevents simultaneous execution of tasks from different security
//! domains on SMT sibling CPUs. Each task carries a
//! [`CoreSchedCookie`] that identifies its scheduling domain. Only
//! tasks with matching cookies (or the idle task, cookie = 0) may
//! run concurrently on the same physical core.
//!
//! # prctl Interface
//!
//! The `PR_SCHED_CORE` prctl operations map to:
//!
//! | Operation                     | Method                                    |
//! |-------------------------------|-------------------------------------------|
//! | `PR_SCHED_CORE_CREATE`        | [`CoreSchedRegistry::create_cookie`]      |
//! | `PR_SCHED_CORE_SHARE_TO`      | [`CoreSchedRegistry::share_cookie`]       |
//! | `PR_SCHED_CORE_SHARE_FROM`    | [`CoreSchedRegistry::share_cookie`]       |
//! | `PR_SCHED_CORE_GET`           | [`CoreSchedRegistry::get_cookie`]         |
//!
//! # Safety Model
//!
//! Cookies are opaque 64-bit values. Cookie `0` means "no core
//! scheduling" — the task may share a core with any other task.
//! A non-zero cookie restricts co-scheduling to siblings with
//! the same cookie or cookie 0.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of tasks tracked by the core scheduling registry.
const MAX_TASKS: usize = 256;

/// Maximum number of physical cores tracked for sibling pairing.
const MAX_CORES: usize = 64;

/// Maximum number of SMT threads per physical core.
const MAX_SMT_SIBLINGS: usize = 4;

/// Cookie value meaning "no core scheduling constraint".
const COOKIE_NONE: u64 = 0;

// ---------------------------------------------------------------------------
// CoreSchedCookie
// ---------------------------------------------------------------------------

/// Opaque core scheduling cookie.
///
/// Two tasks may run simultaneously on the same physical core only
/// if their cookies match, or if either cookie is zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct CoreSchedCookie(u64);

impl CoreSchedCookie {
    /// The "none" cookie — no co-scheduling constraint.
    pub const NONE: Self = Self(COOKIE_NONE);

    /// Create a cookie from a raw value.
    pub const fn from_raw(val: u64) -> Self {
        Self(val)
    }

    /// Return the raw cookie value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Whether this is the "none" cookie.
    pub const fn is_none(self) -> bool {
        self.0 == COOKIE_NONE
    }

    /// Whether two cookies are compatible for co-scheduling.
    ///
    /// Compatible means: either cookie is NONE, or both are equal.
    pub const fn compatible(self, other: Self) -> bool {
        self.0 == COOKIE_NONE || other.0 == COOKIE_NONE || self.0 == other.0
    }
}

impl Default for CoreSchedCookie {
    fn default() -> Self {
        Self::NONE
    }
}

// ---------------------------------------------------------------------------
// PR_SCHED_CORE operation enum
// ---------------------------------------------------------------------------

/// `PR_SCHED_CORE` prctl operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CoreSchedOp {
    /// Create a new unique cookie for the calling task.
    Create = 0,
    /// Share the calling task's cookie to another task.
    ShareTo = 1,
    /// Copy another task's cookie to the calling task.
    ShareFrom = 2,
    /// Get the current cookie value for a task.
    Get = 3,
}

impl CoreSchedOp {
    /// Convert from a raw `u32`.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Create),
            1 => Some(Self::ShareTo),
            2 => Some(Self::ShareFrom),
            3 => Some(Self::Get),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-task entry
// ---------------------------------------------------------------------------

/// Per-task core scheduling state tracked in the registry.
#[derive(Debug, Clone, Copy)]
struct TaskEntry {
    /// Process/task ID.
    pid: u64,
    /// Assigned core scheduling cookie.
    cookie: CoreSchedCookie,
    /// Whether this slot is active.
    active: bool,
}

impl TaskEntry {
    const fn empty() -> Self {
        Self {
            pid: 0,
            cookie: CoreSchedCookie::NONE,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// CoreState — per physical core
// ---------------------------------------------------------------------------

/// Per-physical-core state for sibling pairing decisions.
#[derive(Debug, Clone, Copy)]
pub struct CoreState {
    /// Core ID.
    pub core_id: u32,
    /// PIDs currently running on each SMT sibling (0 = idle).
    pub siblings: [u64; MAX_SMT_SIBLINGS],
    /// Number of hardware threads on this core.
    pub nr_siblings: usize,
    /// Whether this core slot is in use.
    pub in_use: bool,
}

impl CoreState {
    /// Create an empty core state.
    const fn empty() -> Self {
        Self {
            core_id: 0,
            siblings: [0; MAX_SMT_SIBLINGS],
            nr_siblings: 0,
            in_use: false,
        }
    }

    /// Check whether a task with the given cookie may be scheduled
    /// on this core, given the cookies of already-running siblings.
    ///
    /// Returns `true` if all running siblings are compatible.
    pub fn can_schedule(&self, candidate: CoreSchedCookie, registry: &CoreSchedRegistry) -> bool {
        for &sibling_pid in &self.siblings[..self.nr_siblings] {
            if sibling_pid == 0 {
                // Idle sibling — always compatible.
                continue;
            }
            let sibling_cookie = registry.get_cookie(sibling_pid);
            if !candidate.compatible(sibling_cookie) {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// CoreSchedRegistry
// ---------------------------------------------------------------------------

/// System-wide core scheduling registry.
///
/// Tracks per-task cookies and per-core sibling state. Provides
/// the `PR_SCHED_CORE` prctl interface and scheduling queries.
pub struct CoreSchedRegistry {
    /// Per-task cookie entries.
    tasks: [TaskEntry; MAX_TASKS],
    /// Per-physical-core sibling state.
    cores: [CoreState; MAX_CORES],
    /// Number of active task entries.
    task_count: usize,
    /// Number of registered cores.
    core_count: usize,
    /// Next cookie value to assign.
    next_cookie: u64,
}

impl CoreSchedRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const EMPTY_TASK: TaskEntry = TaskEntry::empty();
        const EMPTY_CORE: CoreState = CoreState::empty();
        Self {
            tasks: [EMPTY_TASK; MAX_TASKS],
            cores: [EMPTY_CORE; MAX_CORES],
            task_count: 0,
            core_count: 0,
            next_cookie: 1,
        }
    }

    /// Number of tracked tasks.
    pub fn task_count(&self) -> usize {
        self.task_count
    }

    /// Number of registered cores.
    pub fn core_count(&self) -> usize {
        self.core_count
    }

    // -- Cookie management --------------------------------------------------

    /// Create a new unique cookie for a task (PR_SCHED_CORE_CREATE).
    ///
    /// If the task is not yet tracked, it is registered.
    ///
    /// Returns the newly assigned cookie.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no free task slots.
    pub fn create_cookie(&mut self, pid: u64) -> Result<CoreSchedCookie> {
        let cookie_val = self.next_cookie;
        self.next_cookie = self.next_cookie.wrapping_add(1);
        if self.next_cookie == COOKIE_NONE {
            // Skip zero.
            self.next_cookie = 1;
        }
        let cookie = CoreSchedCookie::from_raw(cookie_val);

        match self.task_index(pid) {
            Some(idx) => {
                self.tasks[idx].cookie = cookie;
            }
            None => {
                let idx = self.alloc_task(pid)?;
                self.tasks[idx].cookie = cookie;
            }
        }

        Ok(cookie)
    }

    /// Share a cookie between two tasks
    /// (PR_SCHED_CORE_SHARE_TO / SHARE_FROM).
    ///
    /// Copies the cookie of `from_pid` to `to_pid`. If `to_pid`
    /// is not yet tracked, it is registered.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — `from_pid` not tracked.
    /// - [`Error::OutOfMemory`] — no free task slots for `to_pid`.
    pub fn share_cookie(&mut self, from_pid: u64, to_pid: u64) -> Result<()> {
        let from_idx = self.task_index(from_pid).ok_or(Error::NotFound)?;
        let cookie = self.tasks[from_idx].cookie;

        match self.task_index(to_pid) {
            Some(idx) => {
                self.tasks[idx].cookie = cookie;
            }
            None => {
                let idx = self.alloc_task(to_pid)?;
                self.tasks[idx].cookie = cookie;
            }
        }
        Ok(())
    }

    /// Get the current cookie for a task (PR_SCHED_CORE_GET).
    ///
    /// Returns [`CoreSchedCookie::NONE`] if the task is not tracked.
    pub fn get_cookie(&self, pid: u64) -> CoreSchedCookie {
        self.task_index(pid)
            .map(|idx| self.tasks[idx].cookie)
            .unwrap_or(CoreSchedCookie::NONE)
    }

    /// Remove a task from the registry (e.g. on exit).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the task is not tracked.
    pub fn remove_task(&mut self, pid: u64) -> Result<()> {
        let idx = self.task_index(pid).ok_or(Error::NotFound)?;
        self.tasks[idx].active = false;
        self.task_count = self.task_count.saturating_sub(1);
        Ok(())
    }

    /// Clear the cookie for a task (reset to NONE).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the task is not tracked.
    pub fn clear_cookie(&mut self, pid: u64) -> Result<()> {
        let idx = self.task_index(pid).ok_or(Error::NotFound)?;
        self.tasks[idx].cookie = CoreSchedCookie::NONE;
        Ok(())
    }

    // -- Core topology management -------------------------------------------

    /// Register a physical core with `nr_siblings` SMT threads.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] — no free core slots.
    /// - [`Error::InvalidArgument`] — `nr_siblings` is zero or
    ///   exceeds [`MAX_SMT_SIBLINGS`].
    pub fn register_core(&mut self, core_id: u32, nr_siblings: usize) -> Result<()> {
        if nr_siblings == 0 || nr_siblings > MAX_SMT_SIBLINGS {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .cores
            .iter()
            .position(|c| !c.in_use)
            .ok_or(Error::OutOfMemory)?;

        self.cores[slot] = CoreState {
            core_id,
            siblings: [0; MAX_SMT_SIBLINGS],
            nr_siblings,
            in_use: true,
        };
        self.core_count += 1;
        Ok(())
    }

    /// Assign a task to an SMT sibling slot on a core.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — core not registered.
    /// - [`Error::InvalidArgument`] — `sibling_idx` out of range.
    pub fn assign_sibling(&mut self, core_id: u32, sibling_idx: usize, pid: u64) -> Result<()> {
        let core = self
            .cores
            .iter_mut()
            .find(|c| c.in_use && c.core_id == core_id)
            .ok_or(Error::NotFound)?;
        if sibling_idx >= core.nr_siblings {
            return Err(Error::InvalidArgument);
        }
        core.siblings[sibling_idx] = pid;
        Ok(())
    }

    /// Check whether a task may be scheduled on a given core.
    ///
    /// Returns `true` if the task's cookie is compatible with all
    /// currently running siblings on the core.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the core is not registered.
    pub fn can_schedule_on(&self, pid: u64, core_id: u32) -> Result<bool> {
        let core = self
            .cores
            .iter()
            .find(|c| c.in_use && c.core_id == core_id)
            .ok_or(Error::NotFound)?;
        let candidate = self.get_cookie(pid);
        Ok(core.can_schedule(candidate, self))
    }

    /// Find a compatible core for a task.
    ///
    /// Returns the `core_id` of the first registered core where
    /// the task's cookie is compatible with all running siblings.
    /// Returns `None` if no compatible core is found.
    pub fn find_compatible_core(&self, pid: u64) -> Option<u32> {
        let candidate = self.get_cookie(pid);
        self.cores
            .iter()
            .find(|c| c.in_use && c.can_schedule(candidate, self))
            .map(|c| c.core_id)
    }

    // -- Dispatch: prctl handler -------------------------------------------

    /// Handle a `PR_SCHED_CORE` prctl request.
    ///
    /// # Arguments
    ///
    /// * `op` — operation code
    /// * `pid` — target PID (may be caller or other task)
    /// * `other_pid` — second PID for share operations
    ///
    /// # Returns
    ///
    /// On `Get`, returns the cookie value. On other operations,
    /// returns 0 on success.
    ///
    /// # Errors
    ///
    /// Propagates errors from the underlying operation.
    pub fn prctl_core_sched(&mut self, op: CoreSchedOp, pid: u64, other_pid: u64) -> Result<u64> {
        match op {
            CoreSchedOp::Create => {
                let cookie = self.create_cookie(pid)?;
                Ok(cookie.as_u64())
            }
            CoreSchedOp::ShareTo => {
                self.share_cookie(pid, other_pid)?;
                Ok(0)
            }
            CoreSchedOp::ShareFrom => {
                self.share_cookie(other_pid, pid)?;
                Ok(0)
            }
            CoreSchedOp::Get => Ok(self.get_cookie(pid).as_u64()),
        }
    }

    // -- Internal helpers ---------------------------------------------------

    /// Find the index of a task by PID.
    fn task_index(&self, pid: u64) -> Option<usize> {
        self.tasks.iter().position(|t| t.active && t.pid == pid)
    }

    /// Allocate a new task slot and return its index.
    fn alloc_task(&mut self, pid: u64) -> Result<usize> {
        let idx = self
            .tasks
            .iter()
            .position(|t| !t.active)
            .ok_or(Error::OutOfMemory)?;
        self.tasks[idx] = TaskEntry {
            pid,
            cookie: CoreSchedCookie::NONE,
            active: true,
        };
        self.task_count += 1;
        Ok(idx)
    }
}

impl Default for CoreSchedRegistry {
    fn default() -> Self {
        Self::new()
    }
}
