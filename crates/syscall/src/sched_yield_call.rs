// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sched_yield` / `sched_getscheduler` / `sched_setscheduler` syscall handlers.
//!
//! Implements process scheduler policy management per POSIX.1-2024:
//! - `sched_yield(2)`: voluntarily relinquish the CPU.
//! - `sched_getscheduler(2)`: query the scheduling policy of a process.
//! - `sched_setscheduler(2)`: set the scheduling policy and priority.
//!
//! # References
//!
//! - POSIX.1-2024: `sched_yield()`, `sched_getscheduler()`, `sched_setscheduler()`
//! - Linux man pages: `sched_yield(2)`, `sched_setscheduler(2)`
//! - Linux include/uapi/linux/sched.h

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Scheduling policy constants
// ---------------------------------------------------------------------------

/// Normal (default) scheduling: time-sharing via CFS.
pub const SCHED_NORMAL: i32 = 0;
/// Alias for `SCHED_NORMAL` (POSIX standard name).
pub const SCHED_OTHER: i32 = 0;
/// First-In, First-Out real-time scheduling.
pub const SCHED_FIFO: i32 = 1;
/// Round-Robin real-time scheduling.
pub const SCHED_RR: i32 = 2;
/// Batch scheduling (lower priority than SCHED_NORMAL).
pub const SCHED_BATCH: i32 = 3;
/// Idle scheduling (lowest priority).
pub const SCHED_IDLE: i32 = 5;
/// Deadline scheduling (EDF/CBS).
pub const SCHED_DEADLINE: i32 = 6;

/// Flag: reset scheduling policy to SCHED_NORMAL on exec.
pub const SCHED_RESET_ON_FORK: i32 = 0x4000_0000;

/// Mask to extract the base policy (without flags).
const SCHED_POLICY_MASK: i32 = 0x0FFF_FFFF;

// ---------------------------------------------------------------------------
// Priority ranges
// ---------------------------------------------------------------------------

/// Minimum realtime priority (for SCHED_FIFO and SCHED_RR).
pub const SCHED_RT_MIN_PRIO: i32 = 1;
/// Maximum realtime priority.
pub const SCHED_RT_MAX_PRIO: i32 = 99;

/// Priority for non-realtime policies (SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE).
pub const SCHED_NONRT_PRIO: i32 = 0;

// ---------------------------------------------------------------------------
// SchedPolicy — type-safe policy enum
// ---------------------------------------------------------------------------

/// Scheduling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SchedPolicy {
    /// Normal CFS time-sharing.
    #[default]
    Normal,
    /// First-In, First-Out real-time.
    Fifo,
    /// Round-Robin real-time.
    Rr,
    /// Batch CFS scheduling.
    Batch,
    /// Idle-priority CFS scheduling.
    Idle,
    /// Deadline (EDF/CBS) scheduling.
    Deadline,
}

impl SchedPolicy {
    /// Decode from a raw Linux policy integer.
    ///
    /// The `SCHED_RESET_ON_FORK` flag bit is masked off before matching.
    pub fn from_raw(raw: i32) -> Result<Self> {
        let base = raw & SCHED_POLICY_MASK;
        match base {
            SCHED_NORMAL => Ok(SchedPolicy::Normal),
            SCHED_FIFO => Ok(SchedPolicy::Fifo),
            SCHED_RR => Ok(SchedPolicy::Rr),
            SCHED_BATCH => Ok(SchedPolicy::Batch),
            SCHED_IDLE => Ok(SchedPolicy::Idle),
            SCHED_DEADLINE => Ok(SchedPolicy::Deadline),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Encode to the raw Linux policy integer.
    pub const fn to_raw(&self) -> i32 {
        match self {
            SchedPolicy::Normal => SCHED_NORMAL,
            SchedPolicy::Fifo => SCHED_FIFO,
            SchedPolicy::Rr => SCHED_RR,
            SchedPolicy::Batch => SCHED_BATCH,
            SchedPolicy::Idle => SCHED_IDLE,
            SchedPolicy::Deadline => SCHED_DEADLINE,
        }
    }

    /// Return `true` if this is a real-time policy.
    pub const fn is_realtime(&self) -> bool {
        matches!(self, SchedPolicy::Fifo | SchedPolicy::Rr)
    }

    /// Return `true` if this policy requires a numeric priority.
    pub const fn requires_priority(&self) -> bool {
        self.is_realtime()
    }
}

// ---------------------------------------------------------------------------
// SchedParam — scheduling parameters
// ---------------------------------------------------------------------------

/// POSIX `struct sched_param`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SchedParam {
    /// Static scheduling priority.
    ///
    /// For real-time policies: must be in `[SCHED_RT_MIN_PRIO, SCHED_RT_MAX_PRIO]`.
    /// For normal policies: must be 0.
    pub sched_priority: i32,
}

impl SchedParam {
    /// Construct a `SchedParam` with the given priority.
    pub const fn new(priority: i32) -> Self {
        Self {
            sched_priority: priority,
        }
    }

    /// Validate the priority for the given policy.
    pub fn validate_for_policy(&self, policy: &SchedPolicy) -> Result<()> {
        if policy.requires_priority() {
            if self.sched_priority < SCHED_RT_MIN_PRIO || self.sched_priority > SCHED_RT_MAX_PRIO {
                return Err(Error::InvalidArgument);
            }
        } else {
            if self.sched_priority != SCHED_NONRT_PRIO {
                return Err(Error::InvalidArgument);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SchedEntry — per-process scheduler state
// ---------------------------------------------------------------------------

/// Scheduler state for a single process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedEntry {
    /// Process ID.
    pub pid: u64,
    /// Current scheduling policy.
    pub policy: SchedPolicy,
    /// Current scheduling parameters.
    pub param: SchedParam,
    /// Whether SCHED_RESET_ON_FORK is set.
    pub reset_on_fork: bool,
    /// Nice value for normal policy (`-20` to `+19`).
    pub nice: i8,
}

impl SchedEntry {
    /// Construct with default (SCHED_NORMAL, priority 0, nice 0).
    pub fn new(pid: u64) -> Self {
        Self {
            pid,
            policy: SchedPolicy::Normal,
            param: SchedParam::new(0),
            reset_on_fork: false,
            nice: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a PID argument (must be non-negative; 0 means the calling process).
fn validate_pid(pid: u64) -> Result<()> {
    // pid is already u64 (non-negative); 0 is valid (means self).
    let _ = pid;
    Ok(())
}

// ---------------------------------------------------------------------------
// Runqueue simulation
// ---------------------------------------------------------------------------

/// Represents the position in a runqueue after a yield.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunqueuePos {
    /// Whether the task was moved to the back of its run queue.
    pub moved_to_back: bool,
    /// Policy of the task that yielded.
    pub policy: SchedPolicy,
}

// ---------------------------------------------------------------------------
// Public syscall handlers
// ---------------------------------------------------------------------------

/// `sched_yield` — relinquish the CPU voluntarily.
///
/// Moves the calling task to the back of its run queue, allowing other
/// tasks at the same or higher priority to run.
///
/// Returns a `RunqueuePos` indicating the outcome.
///
/// Reference: POSIX.1-2024 §sched_yield.
pub fn do_sched_yield(current_policy: SchedPolicy) -> Result<RunqueuePos> {
    // Stub: real implementation calls resched_curr() and schedule().
    Ok(RunqueuePos {
        moved_to_back: true,
        policy: current_policy,
    })
}

/// `sched_getscheduler` — get the scheduling policy of a process.
///
/// `pid == 0` refers to the calling process.
/// Returns the scheduling policy as a raw integer (`SCHED_*` constant).
///
/// Reference: POSIX.1-2024 §sched_getscheduler.
pub fn do_sched_getscheduler(pid: u64, entries: &[SchedEntry]) -> Result<i32> {
    validate_pid(pid)?;

    if pid == 0 {
        // Return the calling process's policy.
        return Ok(SchedPolicy::Normal.to_raw());
    }

    match entries.iter().find(|e| e.pid == pid) {
        Some(entry) => {
            let mut raw = entry.policy.to_raw();
            if entry.reset_on_fork {
                raw |= SCHED_RESET_ON_FORK;
            }
            Ok(raw)
        }
        None => Err(Error::NotFound),
    }
}

/// `sched_setscheduler` — set the scheduling policy and parameters of a process.
///
/// `pid == 0` refers to the calling process.
/// Returns the previous policy on success.
///
/// Reference: POSIX.1-2024 §sched_setscheduler.
pub fn do_sched_setscheduler(
    pid: u64,
    policy_raw: i32,
    param: &SchedParam,
    entries: &mut [SchedEntry],
) -> Result<i32> {
    validate_pid(pid)?;

    let reset_on_fork = policy_raw & SCHED_RESET_ON_FORK != 0;
    let policy = SchedPolicy::from_raw(policy_raw)?;
    param.validate_for_policy(&policy)?;

    if pid == 0 {
        // Stub: real implementation would modify the current task's sched_class.
        return Ok(SchedPolicy::Normal.to_raw());
    }

    match entries.iter_mut().find(|e| e.pid == pid) {
        Some(entry) => {
            let prev_policy = entry.policy.to_raw();
            entry.policy = policy;
            entry.param = *param;
            entry.reset_on_fork = reset_on_fork;
            Ok(prev_policy)
        }
        None => Err(Error::NotFound),
    }
}

/// `sched_getparam` — get the scheduling parameters of a process.
pub fn do_sched_getparam(pid: u64, entries: &[SchedEntry]) -> Result<SchedParam> {
    validate_pid(pid)?;

    if pid == 0 {
        return Ok(SchedParam::new(0));
    }

    match entries.iter().find(|e| e.pid == pid) {
        Some(entry) => Ok(entry.param),
        None => Err(Error::NotFound),
    }
}

/// Validate a raw scheduling policy integer.
pub fn validate_sched_policy(policy_raw: i32) -> Result<SchedPolicy> {
    SchedPolicy::from_raw(policy_raw)
}
