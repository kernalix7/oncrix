// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sched_setscheduler(2)` and `sched_getscheduler(2)` syscall handlers.
//!
//! Sets or retrieves the scheduling policy and associated parameters for a
//! process.  `sched_setscheduler` is the combined set-policy+params call;
//! `sched_getscheduler` returns the current policy.
//!
//! # Syscall signatures
//!
//! ```text
//! int sched_setscheduler(pid_t pid, int policy,
//!                        const struct sched_param *param);
//! int sched_getscheduler(pid_t pid);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §sched_setscheduler, §sched_getscheduler — `<sched.h>`.
//!
//! # References
//!
//! - Linux: `kernel/sched/syscalls.c` `sys_sched_setscheduler()`
//! - `sched_setscheduler(2)`, `sched_getscheduler(2)` man pages

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Policy constants
// ---------------------------------------------------------------------------

/// Default CFS policy.
pub const SCHED_NORMAL: i32 = 0;
/// POSIX synonym for SCHED_NORMAL.
pub const SCHED_OTHER: i32 = 0;
/// First-in first-out realtime.
pub const SCHED_FIFO: i32 = 1;
/// Round-robin realtime.
pub const SCHED_RR: i32 = 2;
/// Batch (CPU-intensive, non-interactive).
pub const SCHED_BATCH: i32 = 3;
/// Very low priority idle.
pub const SCHED_IDLE: i32 = 5;
/// Earliest Deadline First.
pub const SCHED_DEADLINE: i32 = 6;

/// Reset-on-fork flag may be OR'd with the policy.
pub const SCHED_RESET_ON_FORK: i32 = 0x4000_0000;

/// Mask of the policy bits (without flags).
const SCHED_POLICY_MASK: i32 = !SCHED_RESET_ON_FORK;

/// Minimum realtime priority.
const RT_MIN_PRIO: u32 = 1;
/// Maximum realtime priority.
const RT_MAX_PRIO: u32 = 99;

/// Maximum valid PID.
const PID_MAX: u64 = 4_194_304;

// ---------------------------------------------------------------------------
// SchedParam — basic priority wrapper
// ---------------------------------------------------------------------------

/// POSIX `struct sched_param`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SchedParam {
    /// Scheduling priority.
    pub sched_priority: u32,
}

// ---------------------------------------------------------------------------
// PolicyRecord — per-process record
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct PolicyRecord {
    pid: u64,
    policy: i32,
    param: SchedParam,
    reset_on_fork: bool,
    active: bool,
}

impl PolicyRecord {
    const fn inactive() -> Self {
        Self {
            pid: 0,
            policy: SCHED_NORMAL,
            param: SchedParam { sched_priority: 0 },
            reset_on_fork: false,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SchedPolicyTable
// ---------------------------------------------------------------------------

/// Maximum tracked processes.
const MAX_ENTRIES: usize = 256;

/// Per-process scheduling policy store.
pub struct SchedPolicyTable {
    entries: [PolicyRecord; MAX_ENTRIES],
}

impl SchedPolicyTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { PolicyRecord::inactive() }; MAX_ENTRIES],
        }
    }

    /// Get the current policy for `pid`.  Returns `SCHED_NORMAL` if not set.
    pub fn get_policy(&self, pid: u64) -> i32 {
        self.entries
            .iter()
            .find(|e| e.active && e.pid == pid)
            .map(|e| e.policy)
            .unwrap_or(SCHED_NORMAL)
    }

    /// Set policy and parameters for `pid`.
    pub fn set_policy(
        &mut self,
        pid: u64,
        policy: i32,
        param: SchedParam,
        reset_on_fork: bool,
    ) -> Result<()> {
        if let Some(e) = self.entries.iter_mut().find(|e| e.active && e.pid == pid) {
            e.policy = policy;
            e.param = param;
            e.reset_on_fork = reset_on_fork;
            return Ok(());
        }
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot] = PolicyRecord {
            pid,
            policy,
            param,
            reset_on_fork,
            active: true,
        };
        Ok(())
    }
}

impl Default for SchedPolicyTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate_pid(pid: u64) -> Result<()> {
    if pid > PID_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

fn validate_policy_and_param(policy: i32, param: &SchedParam) -> Result<()> {
    let base = policy & SCHED_POLICY_MASK;
    match base {
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE => {
            if param.sched_priority != 0 {
                return Err(Error::InvalidArgument);
            }
        }
        SCHED_FIFO | SCHED_RR => {
            if param.sched_priority < RT_MIN_PRIO || param.sched_priority > RT_MAX_PRIO {
                return Err(Error::InvalidArgument);
            }
        }
        SCHED_DEADLINE => {
            if param.sched_priority != 0 {
                return Err(Error::InvalidArgument);
            }
        }
        _ => return Err(Error::InvalidArgument),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// sys_sched_setscheduler — entry point
// ---------------------------------------------------------------------------

/// Handler for `sched_setscheduler(2)`.
///
/// Sets the scheduling policy and parameters for `pid` (0 = caller).
///
/// # Arguments
///
/// * `table`      — Policy table.
/// * `pid`        — Target process (0 = caller).
/// * `policy`     — New scheduling policy (optionally OR'd with `SCHED_RESET_ON_FORK`).
/// * `param`      — New scheduling parameters.
/// * `caller_pid` — Calling thread's PID.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — bad PID, policy, or priority.
/// * [`Error::OutOfMemory`]     — table full.
pub fn sys_sched_setscheduler(
    table: &mut SchedPolicyTable,
    pid: u64,
    policy: i32,
    param: &SchedParam,
    caller_pid: u64,
) -> Result<i32> {
    validate_pid(pid)?;
    validate_policy_and_param(policy, param)?;
    let target = if pid == 0 { caller_pid } else { pid };
    let old_policy = table.get_policy(target);
    let base_policy = policy & SCHED_POLICY_MASK;
    let reset_on_fork = policy & SCHED_RESET_ON_FORK != 0;
    table.set_policy(target, base_policy, *param, reset_on_fork)?;
    Ok(old_policy)
}

// ---------------------------------------------------------------------------
// sys_sched_getscheduler — entry point
// ---------------------------------------------------------------------------

/// Handler for `sched_getscheduler(2)`.
///
/// Returns the current scheduling policy for `pid` (0 = caller).
///
/// # Arguments
///
/// * `table`      — Policy table.
/// * `pid`        — Target process (0 = caller).
/// * `caller_pid` — Calling thread's PID.
///
/// # Returns
///
/// The scheduling policy constant (`SCHED_*`).
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — out-of-range PID.
pub fn sys_sched_getscheduler(table: &SchedPolicyTable, pid: u64, caller_pid: u64) -> Result<i32> {
    validate_pid(pid)?;
    let target = if pid == 0 { caller_pid } else { pid };
    Ok(table.get_policy(target))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_param() -> SchedParam {
        SchedParam { sched_priority: 0 }
    }
    fn rt_param(prio: u32) -> SchedParam {
        SchedParam {
            sched_priority: prio,
        }
    }

    #[test]
    fn set_and_get_normal() {
        let mut t = SchedPolicyTable::new();
        sys_sched_setscheduler(&mut t, 1, SCHED_NORMAL, &zero_param(), 1).unwrap();
        assert_eq!(sys_sched_getscheduler(&t, 1, 1).unwrap(), SCHED_NORMAL);
    }

    #[test]
    fn set_fifo_returns_old() {
        let mut t = SchedPolicyTable::new();
        let old = sys_sched_setscheduler(&mut t, 2, SCHED_FIFO, &rt_param(50), 2).unwrap();
        assert_eq!(old, SCHED_NORMAL);
    }

    #[test]
    fn fifo_zero_prio_rejected() {
        let mut t = SchedPolicyTable::new();
        assert_eq!(
            sys_sched_setscheduler(&mut t, 1, SCHED_FIFO, &zero_param(), 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn reset_on_fork_flag_stripped() {
        let mut t = SchedPolicyTable::new();
        sys_sched_setscheduler(
            &mut t,
            3,
            SCHED_NORMAL | SCHED_RESET_ON_FORK,
            &zero_param(),
            3,
        )
        .unwrap();
        // Base policy should be SCHED_NORMAL.
        assert_eq!(sys_sched_getscheduler(&t, 3, 3).unwrap(), SCHED_NORMAL);
    }

    #[test]
    fn pid_zero_uses_caller() {
        let mut t = SchedPolicyTable::new();
        sys_sched_setscheduler(&mut t, 0, SCHED_BATCH, &zero_param(), 99).unwrap();
        assert_eq!(sys_sched_getscheduler(&t, 99, 99).unwrap(), SCHED_BATCH);
    }

    #[test]
    fn bad_pid_rejected() {
        let mut t = SchedPolicyTable::new();
        assert_eq!(
            sys_sched_setscheduler(&mut t, 10_000_000, SCHED_NORMAL, &zero_param(), 1),
            Err(Error::InvalidArgument)
        );
    }
}
