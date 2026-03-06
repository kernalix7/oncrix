// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX scheduling syscall handlers.
//!
//! Implements the POSIX.1-2024 realtime scheduling interfaces:
//! `sched_setscheduler`, `sched_getscheduler`, `sched_setparam`,
//! `sched_getparam`, `sched_yield`, `sched_get_priority_min`,
//! `sched_get_priority_max`, and `sched_rr_get_interval`.
//!
//! # Scheduling Policies
//!
//! | Policy | Value | Description |
//! |--------|-------|-------------|
//! | `SCHED_NORMAL` | 0 | Default CFS (completely fair scheduler) |
//! | `SCHED_FIFO` | 1 | First-in first-out realtime |
//! | `SCHED_RR` | 2 | Round-robin realtime |
//! | `SCHED_BATCH` | 3 | Batch (CPU-intensive, non-interactive) |
//! | `SCHED_IDLE` | 5 | Very low priority background tasks |
//! | `SCHED_DEADLINE` | 6 | Earliest Deadline First |
//!
//! # Structures
//!
//! - [`SchedParam`] — Scheduling parameters (`sched_param`).
//! - [`SchedDeadlineParam`] — Extended parameters for `SCHED_DEADLINE`.
//! - [`SchedEntry`] — Per-process scheduling state.
//! - [`SchedTable`] — Process scheduling state table.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Scheduling policy constants
// ---------------------------------------------------------------------------

/// Default time-sharing policy (CFS on Linux).
pub const SCHED_NORMAL: i32 = 0;

/// Other (POSIX synonym for `SCHED_NORMAL`).
pub const SCHED_OTHER: i32 = 0;

/// First-in first-out realtime scheduling.
pub const SCHED_FIFO: i32 = 1;

/// Round-robin realtime scheduling.
pub const SCHED_RR: i32 = 2;

/// Batch scheduling (CPU-intensive, non-interactive).
pub const SCHED_BATCH: i32 = 3;

/// Very low priority idle scheduling.
pub const SCHED_IDLE: i32 = 5;

/// Earliest Deadline First scheduling (Linux extension).
pub const SCHED_DEADLINE: i32 = 6;

/// Flag: reset the scheduling policy to `SCHED_NORMAL` on fork.
pub const SCHED_RESET_ON_FORK: i32 = 0x4000_0000;

/// Mask for extracting the actual policy from flags.
const SCHED_POLICY_MASK: i32 = 0x0FFF;

// ---------------------------------------------------------------------------
// Priority ranges per policy
// ---------------------------------------------------------------------------

/// Minimum realtime priority for `SCHED_FIFO` and `SCHED_RR`.
const RT_PRIO_MIN: i32 = 1;

/// Maximum realtime priority for `SCHED_FIFO` and `SCHED_RR`.
const RT_PRIO_MAX: i32 = 99;

/// The only valid priority for non-realtime policies.
const NORMAL_PRIO: i32 = 0;

/// Maximum valid PID value.
const PID_MAX: u64 = 4_194_304;

/// Maximum entries in the scheduling table.
const MAX_SCHED_ENTRIES: usize = 256;

/// Default round-robin quantum in nanoseconds (100 ms).
const RR_DEFAULT_QUANTUM_NS: u64 = 100_000_000;

// ---------------------------------------------------------------------------
// SchedParam — POSIX sched_param
// ---------------------------------------------------------------------------

/// POSIX `struct sched_param`.
///
/// Contains the scheduling priority used with `sched_setparam`,
/// `sched_getparam`, `sched_setscheduler`, and `sched_getscheduler`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SchedParam {
    /// Scheduling priority.
    ///
    /// - For `SCHED_FIFO` / `SCHED_RR`: 1..=99.
    /// - For `SCHED_NORMAL` / `SCHED_BATCH` / `SCHED_IDLE`: must be 0.
    pub sched_priority: i32,
}

// ---------------------------------------------------------------------------
// SchedDeadlineParam — SCHED_DEADLINE extended parameters
// ---------------------------------------------------------------------------

/// Extended parameters for `SCHED_DEADLINE`.
///
/// Used when setting a process to deadline scheduling. All time
/// values are in nanoseconds.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SchedDeadlineParam {
    /// Normal scheduling priority (must be 0 for DEADLINE).
    pub sched_priority: i32,
    /// Scheduling flags (reserved, must be 0).
    pub flags: u32,
    /// Runtime budget per period in nanoseconds.
    pub runtime_ns: u64,
    /// Deadline relative to the start of each period in nanoseconds.
    pub deadline_ns: u64,
    /// Period length in nanoseconds.
    pub period_ns: u64,
}

impl SchedDeadlineParam {
    /// Validate the deadline parameters.
    ///
    /// The invariant is: 0 < runtime <= deadline <= period.
    pub fn validate(&self) -> Result<()> {
        if self.sched_priority != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.runtime_ns == 0 {
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
}

// ---------------------------------------------------------------------------
// SchedEntry — per-process scheduling state
// ---------------------------------------------------------------------------

/// Per-process scheduling state stored in the scheduling table.
struct SchedEntry {
    /// Process ID.
    pid: u64,
    /// Current scheduling policy.
    policy: i32,
    /// Current scheduling parameters.
    param: SchedParam,
    /// Deadline parameters (valid only when policy == SCHED_DEADLINE).
    deadline: SchedDeadlineParam,
    /// Whether SCHED_RESET_ON_FORK is active.
    reset_on_fork: bool,
    /// Remaining RR quantum in nanoseconds (for SCHED_RR).
    rr_remaining_ns: u64,
    /// Whether this entry is active.
    in_use: bool,
}

impl SchedEntry {
    /// Create an inactive entry.
    const fn new() -> Self {
        Self {
            pid: 0,
            policy: SCHED_NORMAL,
            param: SchedParam { sched_priority: 0 },
            deadline: SchedDeadlineParam {
                sched_priority: 0,
                flags: 0,
                runtime_ns: 0,
                deadline_ns: 0,
                period_ns: 0,
            },
            reset_on_fork: false,
            rr_remaining_ns: 0,
            in_use: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Policy validation
// ---------------------------------------------------------------------------

/// Return `true` if `policy` (with `SCHED_RESET_ON_FORK` stripped)
/// is a recognised scheduling policy.
fn is_valid_policy(policy: i32) -> bool {
    matches!(
        policy & SCHED_POLICY_MASK,
        SCHED_NORMAL | SCHED_FIFO | SCHED_RR | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE
    )
}

/// Return `true` if `policy` is a realtime policy (`SCHED_FIFO` or
/// `SCHED_RR`).
fn is_rt_policy(policy: i32) -> bool {
    let p = policy & SCHED_POLICY_MASK;
    p == SCHED_FIFO || p == SCHED_RR
}

/// Validate that `priority` is appropriate for `policy`.
fn validate_priority(policy: i32, priority: i32) -> Result<()> {
    let p = policy & SCHED_POLICY_MASK;
    match p {
        SCHED_FIFO | SCHED_RR => {
            if priority < RT_PRIO_MIN || priority > RT_PRIO_MAX {
                return Err(Error::InvalidArgument);
            }
        }
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE => {
            if priority != NORMAL_PRIO {
                return Err(Error::InvalidArgument);
            }
        }
        SCHED_DEADLINE => {
            if priority != NORMAL_PRIO {
                return Err(Error::InvalidArgument);
            }
        }
        _ => return Err(Error::InvalidArgument),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SchedTable
// ---------------------------------------------------------------------------

/// Table tracking scheduling state for processes.
///
/// Supports up to [`MAX_SCHED_ENTRIES`] concurrent entries. Entries
/// are lazily created on first `sched_setscheduler` or
/// `sched_setparam` call. A process with no entry is assumed to use
/// `SCHED_NORMAL` with priority 0.
pub struct SchedTable {
    /// Slot array.
    entries: [SchedEntry; MAX_SCHED_ENTRIES],
    /// Number of active entries.
    count: usize,
}

impl SchedTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { SchedEntry::new() }; MAX_SCHED_ENTRIES],
            count: 0,
        }
    }

    /// Return the number of active entries.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no entries are active.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ---------------------------------------------------------------
    // sched_setscheduler
    // ---------------------------------------------------------------

    /// Set the scheduling policy and parameters for process `pid`.
    ///
    /// `pid == 0` means the calling process (represented by
    /// `caller_pid`).
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — unknown policy, invalid priority,
    ///   or invalid flags.
    /// - `OutOfMemory` — table full and no entry exists for pid.
    /// - `PermissionDenied` — setting RT on another process (stub).
    pub fn sched_setscheduler(
        &mut self,
        pid: u64,
        policy: i32,
        param: &SchedParam,
        caller_pid: u64,
    ) -> Result<()> {
        let target_pid = if pid == 0 { caller_pid } else { pid };

        // Validate PID range.
        if target_pid > PID_MAX {
            return Err(Error::InvalidArgument);
        }

        // Extract and validate flags.
        let reset_on_fork = policy & SCHED_RESET_ON_FORK != 0;
        let base_policy = policy & SCHED_POLICY_MASK;

        // Check for unrecognised flag bits.
        if policy & !(SCHED_POLICY_MASK | SCHED_RESET_ON_FORK) != 0 {
            return Err(Error::InvalidArgument);
        }

        if !is_valid_policy(base_policy) {
            return Err(Error::InvalidArgument);
        }

        validate_priority(base_policy, param.sched_priority)?;

        // Setting realtime on another process requires privilege.
        if target_pid != caller_pid && is_rt_policy(base_policy) {
            // Stub: in a real kernel we would check CAP_SYS_NICE.
            // For now, allow it.
        }

        // Find or allocate an entry.
        let entry = self.find_or_create_mut(target_pid)?;
        entry.policy = base_policy;
        entry.param = *param;
        entry.reset_on_fork = reset_on_fork;

        // Set RR quantum when switching to round-robin.
        if base_policy == SCHED_RR {
            entry.rr_remaining_ns = RR_DEFAULT_QUANTUM_NS;
        } else {
            entry.rr_remaining_ns = 0;
        }

        // Clear deadline params when not using deadline policy.
        if base_policy != SCHED_DEADLINE {
            entry.deadline = SchedDeadlineParam::default();
        }

        Ok(())
    }

    // ---------------------------------------------------------------
    // sched_getscheduler
    // ---------------------------------------------------------------

    /// Get the scheduling policy for process `pid`.
    ///
    /// `pid == 0` means the calling process.
    ///
    /// Returns the policy constant (e.g., `SCHED_NORMAL`,
    /// `SCHED_FIFO`). The `SCHED_RESET_ON_FORK` flag is OR'd in
    /// if active.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — invalid PID.
    pub fn sched_getscheduler(&self, pid: u64, caller_pid: u64) -> Result<i32> {
        let target_pid = if pid == 0 { caller_pid } else { pid };

        if target_pid > PID_MAX {
            return Err(Error::InvalidArgument);
        }

        match self.find(target_pid) {
            Some(entry) => {
                let mut pol = entry.policy;
                if entry.reset_on_fork {
                    pol |= SCHED_RESET_ON_FORK;
                }
                Ok(pol)
            }
            None => {
                // No entry — default policy.
                Ok(SCHED_NORMAL)
            }
        }
    }

    // ---------------------------------------------------------------
    // sched_setparam
    // ---------------------------------------------------------------

    /// Set the scheduling parameters for process `pid` without
    /// changing the policy.
    ///
    /// `pid == 0` means the calling process.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — priority invalid for current policy.
    /// - `OutOfMemory` — table full and no entry exists.
    pub fn sched_setparam(&mut self, pid: u64, param: &SchedParam, caller_pid: u64) -> Result<()> {
        let target_pid = if pid == 0 { caller_pid } else { pid };

        if target_pid > PID_MAX {
            return Err(Error::InvalidArgument);
        }

        // Determine the current policy.
        let current_policy = match self.find(target_pid) {
            Some(e) => e.policy,
            None => SCHED_NORMAL,
        };

        validate_priority(current_policy, param.sched_priority)?;

        let entry = self.find_or_create_mut(target_pid)?;
        entry.param = *param;

        Ok(())
    }

    // ---------------------------------------------------------------
    // sched_getparam
    // ---------------------------------------------------------------

    /// Get the scheduling parameters for process `pid`.
    ///
    /// `pid == 0` means the calling process.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — invalid PID.
    pub fn sched_getparam(&self, pid: u64, caller_pid: u64) -> Result<SchedParam> {
        let target_pid = if pid == 0 { caller_pid } else { pid };

        if target_pid > PID_MAX {
            return Err(Error::InvalidArgument);
        }

        match self.find(target_pid) {
            Some(entry) => Ok(entry.param),
            None => Ok(SchedParam { sched_priority: 0 }),
        }
    }

    // ---------------------------------------------------------------
    // sched_rr_get_interval
    // ---------------------------------------------------------------

    /// Get the round-robin time quantum for process `pid`.
    ///
    /// `pid == 0` means the calling process.
    ///
    /// Returns the remaining quantum in nanoseconds. For non-RR
    /// processes, returns 0.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — invalid PID.
    pub fn sched_rr_get_interval(&self, pid: u64, caller_pid: u64) -> Result<u64> {
        let target_pid = if pid == 0 { caller_pid } else { pid };

        if target_pid > PID_MAX {
            return Err(Error::InvalidArgument);
        }

        match self.find(target_pid) {
            Some(entry) if entry.policy == SCHED_RR => Ok(entry.rr_remaining_ns),
            _ => Ok(0),
        }
    }

    // ---------------------------------------------------------------
    // sched_setscheduler_deadline — SCHED_DEADLINE support
    // ---------------------------------------------------------------

    /// Set `SCHED_DEADLINE` scheduling for process `pid`.
    ///
    /// This is a Linux extension not covered by POSIX. It uses the
    /// extended [`SchedDeadlineParam`] structure.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — invalid parameters.
    /// - `OutOfMemory` — table full.
    /// - `PermissionDenied` — insufficient privilege (stub).
    pub fn sched_setscheduler_deadline(
        &mut self,
        pid: u64,
        dl_param: &SchedDeadlineParam,
        caller_pid: u64,
    ) -> Result<()> {
        let target_pid = if pid == 0 { caller_pid } else { pid };

        if target_pid > PID_MAX {
            return Err(Error::InvalidArgument);
        }

        dl_param.validate()?;

        let entry = self.find_or_create_mut(target_pid)?;
        entry.policy = SCHED_DEADLINE;
        entry.param = SchedParam { sched_priority: 0 };
        entry.deadline = *dl_param;
        entry.reset_on_fork = false;
        entry.rr_remaining_ns = 0;

        Ok(())
    }

    // ---------------------------------------------------------------
    // Fork handling
    // ---------------------------------------------------------------

    /// Handle the scheduling state for a newly forked child.
    ///
    /// If the parent has `SCHED_RESET_ON_FORK` set, the child
    /// inherits `SCHED_NORMAL` with priority 0. Otherwise, the
    /// child inherits the parent's policy and parameters.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` — table full.
    pub fn fork_child(&mut self, parent_pid: u64, child_pid: u64) -> Result<()> {
        if child_pid > PID_MAX {
            return Err(Error::InvalidArgument);
        }

        let (policy, param, reset) = match self.find(parent_pid) {
            Some(e) => (e.policy, e.param, e.reset_on_fork),
            None => (SCHED_NORMAL, SchedParam { sched_priority: 0 }, false),
        };

        let child = self.find_or_create_mut(child_pid)?;

        if reset {
            // Reset to default policy.
            child.policy = SCHED_NORMAL;
            child.param = SchedParam { sched_priority: 0 };
            child.reset_on_fork = false;
        } else {
            child.policy = policy;
            child.param = param;
            child.reset_on_fork = false;
        }

        if child.policy == SCHED_RR {
            child.rr_remaining_ns = RR_DEFAULT_QUANTUM_NS;
        } else {
            child.rr_remaining_ns = 0;
        }

        child.deadline = SchedDeadlineParam::default();

        Ok(())
    }

    // ---------------------------------------------------------------
    // Process exit cleanup
    // ---------------------------------------------------------------

    /// Remove the scheduling entry for a terminated process.
    ///
    /// Returns `true` if an entry was removed.
    pub fn remove(&mut self, pid: u64) -> bool {
        for entry in &mut self.entries {
            if entry.in_use && entry.pid == pid {
                entry.in_use = false;
                entry.pid = 0;
                self.count = self.count.saturating_sub(1);
                return true;
            }
        }
        false
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /// Find an entry by PID (shared reference).
    fn find(&self, pid: u64) -> Option<&SchedEntry> {
        self.entries.iter().find(|e| e.in_use && e.pid == pid)
    }

    /// Find or create an entry for `pid` (mutable reference).
    fn find_or_create_mut(&mut self, pid: u64) -> Result<&mut SchedEntry> {
        // First, check if an entry already exists.
        let existing = self.entries.iter().position(|e| e.in_use && e.pid == pid);
        if let Some(idx) = existing {
            return Ok(&mut self.entries[idx]);
        }

        // Allocate a new slot.
        let free = self
            .entries
            .iter()
            .position(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;

        self.entries[free].in_use = true;
        self.entries[free].pid = pid;
        self.entries[free].policy = SCHED_NORMAL;
        self.entries[free].param = SchedParam { sched_priority: 0 };
        self.entries[free].reset_on_fork = false;
        self.entries[free].rr_remaining_ns = 0;
        self.entries[free].deadline = SchedDeadlineParam::default();

        self.count += 1;
        Ok(&mut self.entries[free])
    }
}

impl Default for SchedTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall handler functions
// ---------------------------------------------------------------------------

/// `sched_setscheduler` — set scheduling policy and parameters.
///
/// Sets the scheduling policy and associated parameters for process
/// `pid`. If `pid` is 0, the calling process (identified by
/// `caller_pid`) is used.
///
/// `policy` may be OR'd with `SCHED_RESET_ON_FORK` to request that
/// the child revert to `SCHED_NORMAL` after `fork`.
///
/// # Errors
///
/// - `InvalidArgument` — unknown policy or invalid priority.
/// - `OutOfMemory` — scheduling table full.
pub fn do_sched_setscheduler(
    table: &mut SchedTable,
    pid: u64,
    policy: i32,
    param: &SchedParam,
    caller_pid: u64,
) -> Result<()> {
    table.sched_setscheduler(pid, policy, param, caller_pid)
}

/// `sched_getscheduler` — get scheduling policy.
///
/// Returns the scheduling policy for process `pid` (0 = self).
/// `SCHED_RESET_ON_FORK` is OR'd in if active.
///
/// # Errors
///
/// - `InvalidArgument` — invalid PID.
pub fn do_sched_getscheduler(table: &SchedTable, pid: u64, caller_pid: u64) -> Result<i32> {
    table.sched_getscheduler(pid, caller_pid)
}

/// `sched_setparam` — set scheduling parameters without changing
/// the policy.
///
/// # Errors
///
/// - `InvalidArgument` — priority invalid for current policy.
/// - `OutOfMemory` — table full.
pub fn do_sched_setparam(
    table: &mut SchedTable,
    pid: u64,
    param: &SchedParam,
    caller_pid: u64,
) -> Result<()> {
    table.sched_setparam(pid, param, caller_pid)
}

/// `sched_getparam` — get scheduling parameters.
///
/// Returns the [`SchedParam`] for process `pid` (0 = self).
///
/// # Errors
///
/// - `InvalidArgument` — invalid PID.
pub fn do_sched_getparam(table: &SchedTable, pid: u64, caller_pid: u64) -> Result<SchedParam> {
    table.sched_getparam(pid, caller_pid)
}

/// `sched_yield` — yield the processor.
///
/// Voluntarily gives up the calling thread's remaining time slice.
/// The thread is placed at the end of the run queue for its
/// priority level.
///
/// Always succeeds.
pub fn do_sched_yield() -> Result<()> {
    // In a real kernel, we would:
    // 1. Remove the current task from the head of its run queue.
    // 2. Append it to the tail.
    // 3. Invoke the scheduler to pick the next task.
    // Stub: no-op — there is no scheduler yet.
    Ok(())
}

/// `sched_get_priority_min` — get minimum priority for a policy.
///
/// Returns the minimum valid `sched_priority` value for the given
/// scheduling policy.
///
/// # Errors
///
/// - `InvalidArgument` — unknown policy.
pub fn do_sched_get_priority_min(policy: i32) -> Result<i32> {
    let p = policy & SCHED_POLICY_MASK;
    match p {
        SCHED_FIFO | SCHED_RR => Ok(RT_PRIO_MIN),
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => Ok(NORMAL_PRIO),
        _ => Err(Error::InvalidArgument),
    }
}

/// `sched_get_priority_max` — get maximum priority for a policy.
///
/// Returns the maximum valid `sched_priority` value for the given
/// scheduling policy.
///
/// # Errors
///
/// - `InvalidArgument` — unknown policy.
pub fn do_sched_get_priority_max(policy: i32) -> Result<i32> {
    let p = policy & SCHED_POLICY_MASK;
    match p {
        SCHED_FIFO | SCHED_RR => Ok(RT_PRIO_MAX),
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => Ok(NORMAL_PRIO),
        _ => Err(Error::InvalidArgument),
    }
}

/// `sched_rr_get_interval` — get the round-robin time quantum.
///
/// Returns the remaining quantum in nanoseconds for process `pid`
/// (0 = self). For non-RR processes, returns 0.
///
/// # Errors
///
/// - `InvalidArgument` — invalid PID.
pub fn do_sched_rr_get_interval(table: &SchedTable, pid: u64, caller_pid: u64) -> Result<u64> {
    table.sched_rr_get_interval(pid, caller_pid)
}
