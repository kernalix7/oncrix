// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sched_setparam(2)` and `sched_getparam(2)` syscall handlers.
//!
//! These are the original POSIX scheduling parameter interfaces operating on
//! the basic `struct sched_param` (a single `sched_priority` field).  They
//! are simpler than `sched_setattr`/`sched_getattr` and exist for POSIX
//! compatibility.
//!
//! # Syscall signatures
//!
//! ```text
//! int sched_setparam(pid_t pid, const struct sched_param *param);
//! int sched_getparam(pid_t pid, struct sched_param *param);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §sched_setparam, §sched_getparam — `<sched.h>`.
//!
//! # References
//!
//! - Linux: `kernel/sched/syscalls.c`
//! - `sched_setparam(2)`, `sched_getparam(2)` man pages

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum realtime priority (POSIX minimum for FIFO/RR is 1).
pub const SCHED_RR_MIN_PRIORITY: u32 = 1;
/// Maximum realtime priority.
pub const SCHED_RR_MAX_PRIORITY: u32 = 99;
/// Normal (CFS) scheduling priority — must be 0.
pub const SCHED_NORMAL_PRIORITY: u32 = 0;

/// Maximum valid PID.
const PID_MAX: u64 = 4_194_304;

// ---------------------------------------------------------------------------
// Scheduling policies
// ---------------------------------------------------------------------------

/// Default CFS policy.
pub const SCHED_NORMAL: u32 = 0;
/// FIFO realtime.
pub const SCHED_FIFO: u32 = 1;
/// Round-robin realtime.
pub const SCHED_RR: u32 = 2;
/// Batch.
pub const SCHED_BATCH: u32 = 3;
/// Idle.
pub const SCHED_IDLE: u32 = 5;
/// EDF.
pub const SCHED_DEADLINE: u32 = 6;

// ---------------------------------------------------------------------------
// SchedParam — basic POSIX structure
// ---------------------------------------------------------------------------

/// POSIX `struct sched_param`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SchedParam {
    /// Scheduling priority.
    pub sched_priority: u32,
}

// ---------------------------------------------------------------------------
// ParamEntry — per-process record
// ---------------------------------------------------------------------------

/// Per-process scheduling parameter record.
#[derive(Debug, Clone, Copy)]
struct ParamEntry {
    pid: u64,
    policy: u32,
    param: SchedParam,
    active: bool,
}

impl ParamEntry {
    const fn inactive() -> Self {
        Self {
            pid: 0,
            policy: SCHED_NORMAL,
            param: SchedParam { sched_priority: 0 },
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SchedParamTable — per-process store
// ---------------------------------------------------------------------------

/// Maximum tracked processes.
const MAX_ENTRIES: usize = 256;

/// Per-process scheduling parameter store.
pub struct SchedParamTable {
    entries: [ParamEntry; MAX_ENTRIES],
}

impl SchedParamTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { ParamEntry::inactive() }; MAX_ENTRIES],
        }
    }

    /// Get the current parameters for `pid`.  Returns default if not set.
    pub fn get(&self, pid: u64) -> (u32, SchedParam) {
        self.entries
            .iter()
            .find(|e| e.active && e.pid == pid)
            .map(|e| (e.policy, e.param))
            .unwrap_or((SCHED_NORMAL, SchedParam::default()))
    }

    /// Set parameters for `pid`.
    pub fn set(&mut self, pid: u64, policy: u32, param: SchedParam) -> Result<()> {
        if let Some(e) = self.entries.iter_mut().find(|e| e.active && e.pid == pid) {
            e.policy = policy;
            e.param = param;
            return Ok(());
        }
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot] = ParamEntry {
            pid,
            policy,
            param,
            active: true,
        };
        Ok(())
    }

    /// Remove the entry for a terminated process.
    pub fn remove(&mut self, pid: u64) -> bool {
        for e in &mut self.entries {
            if e.active && e.pid == pid {
                e.active = false;
                return true;
            }
        }
        false
    }
}

impl Default for SchedParamTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `(policy, param)` pair.
///
/// - For Normal/Batch/Idle: priority must be 0.
/// - For FIFO/RR: priority must be in 1..=99.
/// - For Deadline: priority must be 0 (param-based interface doesn't set
///   deadlines).
fn validate_param(policy: u32, param: &SchedParam) -> Result<()> {
    match policy {
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => {
            if param.sched_priority != 0 {
                return Err(Error::InvalidArgument);
            }
        }
        SCHED_FIFO | SCHED_RR => {
            if param.sched_priority < SCHED_RR_MIN_PRIORITY
                || param.sched_priority > SCHED_RR_MAX_PRIORITY
            {
                return Err(Error::InvalidArgument);
            }
        }
        _ => return Err(Error::InvalidArgument),
    }
    Ok(())
}

fn validate_pid(pid: u64) -> Result<()> {
    if pid > PID_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// sys_sched_setparam — entry point
// ---------------------------------------------------------------------------

/// Handler for `sched_setparam(2)`.
///
/// # Arguments
///
/// * `table`      — Scheduling parameter table.
/// * `pid`        — Target process (0 = caller).
/// * `policy`     — Scheduling policy currently applied to the process.
/// * `param`      — New scheduling parameters.
/// * `caller_pid` — PID of the calling process.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — bad PID, policy, or priority value.
/// * [`Error::OutOfMemory`]     — table full.
pub fn sys_sched_setparam(
    table: &mut SchedParamTable,
    pid: u64,
    policy: u32,
    param: &SchedParam,
    caller_pid: u64,
) -> Result<()> {
    validate_pid(pid)?;
    validate_param(policy, param)?;
    let target = if pid == 0 { caller_pid } else { pid };
    table.set(target, policy, *param)
}

// ---------------------------------------------------------------------------
// sys_sched_getparam — entry point
// ---------------------------------------------------------------------------

/// Handler for `sched_getparam(2)`.
///
/// # Arguments
///
/// * `table`      — Scheduling parameter table.
/// * `pid`        — Target process (0 = caller).
/// * `caller_pid` — PID of the calling process.
///
/// # Returns
///
/// `(policy, SchedParam)` for the target process.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — out-of-range PID.
pub fn sys_sched_getparam(
    table: &SchedParamTable,
    pid: u64,
    caller_pid: u64,
) -> Result<(u32, SchedParam)> {
    validate_pid(pid)?;
    let target = if pid == 0 { caller_pid } else { pid };
    Ok(table.get(target))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_get_normal() {
        let mut t = SchedParamTable::new();
        let p = SchedParam { sched_priority: 0 };
        sys_sched_setparam(&mut t, 0, SCHED_NORMAL, &p, 1).unwrap();
        let (pol, param) = sys_sched_getparam(&t, 0, 1).unwrap();
        assert_eq!(pol, SCHED_NORMAL);
        assert_eq!(param.sched_priority, 0);
    }

    #[test]
    fn set_fifo() {
        let mut t = SchedParamTable::new();
        let p = SchedParam { sched_priority: 50 };
        sys_sched_setparam(&mut t, 1, SCHED_FIFO, &p, 1).unwrap();
        let (pol, param) = sys_sched_getparam(&t, 1, 1).unwrap();
        assert_eq!(pol, SCHED_FIFO);
        assert_eq!(param.sched_priority, 50);
    }

    #[test]
    fn fifo_zero_priority_rejected() {
        let mut t = SchedParamTable::new();
        let p = SchedParam { sched_priority: 0 };
        assert_eq!(
            sys_sched_setparam(&mut t, 1, SCHED_FIFO, &p, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn normal_nonzero_priority_rejected() {
        let mut t = SchedParamTable::new();
        let p = SchedParam { sched_priority: 5 };
        assert_eq!(
            sys_sched_setparam(&mut t, 1, SCHED_NORMAL, &p, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_policy_rejected() {
        let mut t = SchedParamTable::new();
        let p = SchedParam { sched_priority: 0 };
        assert_eq!(
            sys_sched_setparam(&mut t, 1, 99, &p, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn get_default_for_unknown_pid() {
        let t = SchedParamTable::new();
        let (pol, p) = sys_sched_getparam(&t, 999, 1).unwrap();
        assert_eq!(pol, SCHED_NORMAL);
        assert_eq!(p.sched_priority, 0);
    }

    #[test]
    fn remove_entry() {
        let mut t = SchedParamTable::new();
        let p = SchedParam { sched_priority: 30 };
        sys_sched_setparam(&mut t, 5, SCHED_RR, &p, 5).unwrap();
        assert!(t.remove(5));
        let (pol, _) = sys_sched_getparam(&t, 5, 5).unwrap();
        assert_eq!(pol, SCHED_NORMAL);
    }
}
