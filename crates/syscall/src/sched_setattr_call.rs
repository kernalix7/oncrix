// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended scheduler attribute management syscalls.
//!
//! Provides higher-level scheduling policy operations built on top of the
//! raw `sched_setattr`/`sched_getattr` primitives in `sched_getattr.rs`.
//! This module focuses on policy application logic, batch operations,
//! CPU bandwidth control, and scheduling policy validation.
//!
//! # Operations
//!
//! | Operation            | Function                  | Purpose                        |
//! |----------------------|---------------------------|--------------------------------|
//! | Set policy           | [`sys_sched_setattr`]     | Apply policy + parameters      |
//! | Get policy           | [`sys_sched_getattr`]     | Query current policy           |
//! | Validate attrs       | [`validate_attr`]         | Pre-validate before applying   |
//! | Apply policy change  | [`apply_policy`]          | Execute policy transition      |
//!
//! # Scheduling policies
//!
//! | Policy            | Value | Description                          |
//! |-------------------|-------|--------------------------------------|
//! | `SCHED_NORMAL`    | 0     | CFS (default)                        |
//! | `SCHED_FIFO`      | 1     | First-in first-out realtime          |
//! | `SCHED_RR`        | 2     | Round-robin realtime                 |
//! | `SCHED_BATCH`     | 3     | Batch, non-interactive               |
//! | `SCHED_IDLE`      | 5     | Very low priority                    |
//! | `SCHED_DEADLINE`  | 6     | Earliest Deadline First              |
//!
//! # References
//!
//! - Linux: `kernel/sched/syscalls.c`, `kernel/sched/core.c`
//! - `include/uapi/linux/sched/types.h` — `struct sched_attr`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Scheduling policy constants
// ---------------------------------------------------------------------------

/// Default time-sharing policy (CFS on Linux).
pub const SCHED_NORMAL: u32 = 0;
/// POSIX synonym for `SCHED_NORMAL`.
pub const SCHED_OTHER: u32 = 0;
/// First-in first-out realtime scheduling.
pub const SCHED_FIFO: u32 = 1;
/// Round-robin realtime scheduling.
pub const SCHED_RR: u32 = 2;
/// Batch scheduling (CPU-intensive, non-interactive).
pub const SCHED_BATCH: u32 = 3;
/// Very low priority idle scheduling.
pub const SCHED_IDLE: u32 = 5;
/// Earliest Deadline First scheduling (Linux extension).
pub const SCHED_DEADLINE: u32 = 6;

// ---------------------------------------------------------------------------
// SchedPolicy — type-safe policy enum
// ---------------------------------------------------------------------------

/// Type-safe scheduling policy enumeration.
///
/// Provides conversion to/from the raw `u32` constants and policy
/// classification helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedPolicy {
    /// Default CFS scheduling.
    Normal,
    /// First-in first-out realtime.
    Fifo,
    /// Round-robin realtime.
    RoundRobin,
    /// Batch (CPU-intensive, non-interactive).
    Batch,
    /// Very low priority idle.
    Idle,
    /// Earliest Deadline First.
    Deadline,
}

impl SchedPolicy {
    /// Convert from a raw `u32` policy constant.
    ///
    /// Returns `Err(Error::InvalidArgument)` for unrecognised values.
    pub fn from_u32(val: u32) -> Result<Self> {
        match val {
            0 => Ok(Self::Normal),
            1 => Ok(Self::Fifo),
            2 => Ok(Self::RoundRobin),
            3 => Ok(Self::Batch),
            5 => Ok(Self::Idle),
            6 => Ok(Self::Deadline),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Convert to the raw `u32` constant.
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Normal => SCHED_NORMAL,
            Self::Fifo => SCHED_FIFO,
            Self::RoundRobin => SCHED_RR,
            Self::Batch => SCHED_BATCH,
            Self::Idle => SCHED_IDLE,
            Self::Deadline => SCHED_DEADLINE,
        }
    }

    /// Return `true` if this is a realtime policy (FIFO or RR).
    pub const fn is_realtime(self) -> bool {
        matches!(self, Self::Fifo | Self::RoundRobin)
    }

    /// Return `true` if this is a deadline policy.
    pub const fn is_deadline(self) -> bool {
        matches!(self, Self::Deadline)
    }

    /// Return `true` if this is a normal-class policy (Normal, Batch, Idle).
    pub const fn is_normal_class(self) -> bool {
        matches!(self, Self::Normal | Self::Batch | Self::Idle)
    }
}

// ---------------------------------------------------------------------------
// SchedParam — basic scheduling parameters
// ---------------------------------------------------------------------------

/// Basic scheduling parameters (POSIX `struct sched_param`).
///
/// Used with `sched_setparam`/`sched_getparam` and as a component
/// of the full [`SchedAttr`] structure.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SchedParam {
    /// Scheduling priority.
    ///
    /// - For FIFO/RR: 1..=99
    /// - For Normal/Batch/Idle: must be 0
    /// - For Deadline: must be 0
    pub sched_priority: u32,
}

// ---------------------------------------------------------------------------
// SchedAttr — extended scheduling attributes
// ---------------------------------------------------------------------------

/// Minimum realtime priority.
const RT_PRIO_MIN: u32 = 1;
/// Maximum realtime priority.
const RT_PRIO_MAX: u32 = 99;
/// Maximum nice value (+19 POSIX).
const NICE_MAX: i32 = 19;
/// Minimum nice value (-20 POSIX).
const NICE_MIN: i32 = -20;
/// Maximum utilization clamp value.
const UCLAMP_MAX_VALUE: u32 = 1024;
/// Maximum accepted PID.
const PID_MAX_LIMIT: u64 = 4_194_304;
/// Minimum valid `sched_attr` size (version 0).
const SCHED_ATTR_SIZE_VER0: usize = 48;
/// Extended size including utilization clamping (version 1).
const SCHED_ATTR_SIZE_VER1: usize = 56;
/// Default round-robin quantum in nanoseconds (100 ms).
const RR_DEFAULT_QUANTUM_NS: u64 = 100_000_000;
/// Maximum entries in the scheduling state table.
const MAX_ENTRIES: usize = 256;

/// Scheduling flags.
pub const SCHED_FLAG_RESET_ON_FORK: u64 = 1 << 0;
/// Allow reclaiming unused runtime.
pub const SCHED_FLAG_RECLAIM: u64 = 1 << 1;
/// Enable deadline bandwidth overrun notification.
pub const SCHED_FLAG_DL_OVERRUN: u64 = 1 << 2;
/// Keep current policy when setting util clamps.
pub const SCHED_FLAG_KEEP_POLICY: u64 = 1 << 3;
/// Keep current parameters when setting util clamps.
pub const SCHED_FLAG_KEEP_PARAMS: u64 = 1 << 4;
/// Set utilization minimum clamp.
pub const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 1 << 5;
/// Set utilization maximum clamp.
pub const SCHED_FLAG_UTIL_CLAMP_MAX: u64 = 1 << 6;

/// All recognised flag bits.
const SCHED_FLAGS_ALL: u64 = SCHED_FLAG_RESET_ON_FORK
    | SCHED_FLAG_RECLAIM
    | SCHED_FLAG_DL_OVERRUN
    | SCHED_FLAG_KEEP_POLICY
    | SCHED_FLAG_KEEP_PARAMS
    | SCHED_FLAG_UTIL_CLAMP_MIN
    | SCHED_FLAG_UTIL_CLAMP_MAX;

/// Extended scheduling attribute structure.
///
/// Matches `struct sched_attr` from the Linux UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SchedAttr {
    /// Structure size in bytes.
    pub size: u32,
    /// Scheduling policy (one of `SCHED_*`).
    pub sched_policy: u32,
    /// Scheduling flags (combination of `SCHED_FLAG_*`).
    pub sched_flags: u64,
    /// Nice value for Normal/Batch (-20..=19).
    pub sched_nice: i32,
    /// Priority for FIFO/RR (1..=99).
    pub sched_priority: u32,
    /// SCHED_DEADLINE: runtime budget (nanoseconds).
    pub sched_runtime: u64,
    /// SCHED_DEADLINE: deadline (nanoseconds).
    pub sched_deadline: u64,
    /// SCHED_DEADLINE: period (nanoseconds).
    pub sched_period: u64,
    /// Minimum utilization clamp (0..=1024).
    pub sched_util_min: u32,
    /// Maximum utilization clamp (0..=1024).
    pub sched_util_max: u32,
}

impl Default for SchedAttr {
    fn default() -> Self {
        Self {
            size: SCHED_ATTR_SIZE_VER1 as u32,
            sched_policy: SCHED_NORMAL,
            sched_flags: 0,
            sched_nice: 0,
            sched_priority: 0,
            sched_runtime: 0,
            sched_deadline: 0,
            sched_period: 0,
            sched_util_min: 0,
            sched_util_max: UCLAMP_MAX_VALUE,
        }
    }
}

// ---------------------------------------------------------------------------
// validate_attr — comprehensive attribute validation
// ---------------------------------------------------------------------------

/// Validate a [`SchedAttr`] structure for `sched_setattr`.
///
/// Checks policy-specific constraints on priority, nice, deadline params,
/// flags, and utilization clamp values.
///
/// # Errors
///
/// [`Error::InvalidArgument`] for any constraint violation.
pub fn validate_attr(attr: &SchedAttr, size: usize) -> Result<()> {
    let max_size = core::mem::size_of::<SchedAttr>();
    if size < SCHED_ATTR_SIZE_VER0 || size > max_size {
        return Err(Error::InvalidArgument);
    }

    // Unknown flags.
    if attr.sched_flags & !SCHED_FLAGS_ALL != 0 {
        return Err(Error::InvalidArgument);
    }

    let policy = SchedPolicy::from_u32(attr.sched_policy)?;

    match policy {
        SchedPolicy::Normal | SchedPolicy::Batch | SchedPolicy::Idle => {
            if attr.sched_priority != 0 {
                return Err(Error::InvalidArgument);
            }
            if attr.sched_nice < NICE_MIN || attr.sched_nice > NICE_MAX {
                return Err(Error::InvalidArgument);
            }
        }
        SchedPolicy::Fifo | SchedPolicy::RoundRobin => {
            if attr.sched_priority < RT_PRIO_MIN || attr.sched_priority > RT_PRIO_MAX {
                return Err(Error::InvalidArgument);
            }
            if attr.sched_nice != 0 {
                return Err(Error::InvalidArgument);
            }
        }
        SchedPolicy::Deadline => {
            if attr.sched_priority != 0 {
                return Err(Error::InvalidArgument);
            }
            if attr.sched_runtime == 0 {
                return Err(Error::InvalidArgument);
            }
            if attr.sched_runtime > attr.sched_deadline {
                return Err(Error::InvalidArgument);
            }
            if attr.sched_deadline > attr.sched_period {
                return Err(Error::InvalidArgument);
            }
        }
    }

    // Utilization clamp checks for version 1+ structures.
    if size >= SCHED_ATTR_SIZE_VER1 {
        if attr.sched_util_min > UCLAMP_MAX_VALUE {
            return Err(Error::InvalidArgument);
        }
        if attr.sched_util_max > UCLAMP_MAX_VALUE {
            return Err(Error::InvalidArgument);
        }
        if attr.sched_util_min > attr.sched_util_max {
            return Err(Error::InvalidArgument);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// PolicyEntry — per-process scheduling state
// ---------------------------------------------------------------------------

/// Per-process scheduling state tracked by the policy table.
struct PolicyEntry {
    /// Process ID.
    pid: u64,
    /// Current scheduling attributes.
    attr: SchedAttr,
    /// Remaining RR quantum in nanoseconds.
    rr_remaining_ns: u64,
    /// Whether this entry is active.
    in_use: bool,
}

impl PolicyEntry {
    /// Create an inactive entry.
    const fn new() -> Self {
        Self {
            pid: 0,
            attr: SchedAttr {
                size: SCHED_ATTR_SIZE_VER1 as u32,
                sched_policy: SCHED_NORMAL,
                sched_flags: 0,
                sched_nice: 0,
                sched_priority: 0,
                sched_runtime: 0,
                sched_deadline: 0,
                sched_period: 0,
                sched_util_min: 0,
                sched_util_max: UCLAMP_MAX_VALUE,
            },
            rr_remaining_ns: 0,
            in_use: false,
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyTable — scheduling policy table
// ---------------------------------------------------------------------------

/// Table tracking scheduling policy state for all processes.
pub struct PolicyTable {
    entries: [PolicyEntry; MAX_ENTRIES],
    count: usize,
}

impl PolicyTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { PolicyEntry::new() }; MAX_ENTRIES],
            count: 0,
        }
    }

    /// Return the number of tracked processes.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the table is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Remove the entry for a terminated process.
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

    /// Find an entry by PID (shared reference).
    fn find(&self, pid: u64) -> Option<&PolicyEntry> {
        self.entries.iter().find(|e| e.in_use && e.pid == pid)
    }

    /// Find or create an entry (mutable reference).
    fn find_or_create_mut(&mut self, pid: u64) -> Result<&mut PolicyEntry> {
        let existing = self.entries.iter().position(|e| e.in_use && e.pid == pid);
        if let Some(idx) = existing {
            return Ok(&mut self.entries[idx]);
        }

        let free = self
            .entries
            .iter()
            .position(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;

        self.entries[free].in_use = true;
        self.entries[free].pid = pid;
        self.entries[free].attr = SchedAttr::default();
        self.entries[free].rr_remaining_ns = 0;
        self.count += 1;
        Ok(&mut self.entries[free])
    }
}

impl Default for PolicyTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// apply_policy — execute a policy transition
// ---------------------------------------------------------------------------

/// Apply a scheduling policy change to a process entry.
///
/// This is the core function that actually modifies the scheduling state.
/// It handles RR quantum initialization, deadline parameter copying,
/// and RESET_ON_FORK flag management.
///
/// # Arguments
///
/// * `entry` — mutable reference to the process's scheduling state.
/// * `attr`  — validated new scheduling attributes.
fn apply_policy_to_entry(entry: &mut PolicyEntry, attr: &SchedAttr) {
    let mut new_attr = *attr;
    new_attr.size = core::mem::size_of::<SchedAttr>() as u32;

    // Handle KEEP_POLICY and KEEP_PARAMS flags.
    if attr.sched_flags & SCHED_FLAG_KEEP_POLICY != 0 {
        new_attr.sched_policy = entry.attr.sched_policy;
    }
    if attr.sched_flags & SCHED_FLAG_KEEP_PARAMS != 0 {
        new_attr.sched_priority = entry.attr.sched_priority;
        new_attr.sched_nice = entry.attr.sched_nice;
        new_attr.sched_runtime = entry.attr.sched_runtime;
        new_attr.sched_deadline = entry.attr.sched_deadline;
        new_attr.sched_period = entry.attr.sched_period;
    }

    entry.attr = new_attr;

    // Initialize RR quantum when switching to round-robin.
    if entry.attr.sched_policy == SCHED_RR {
        entry.rr_remaining_ns = RR_DEFAULT_QUANTUM_NS;
    } else {
        entry.rr_remaining_ns = 0;
    }
}

/// Apply a validated scheduling policy change.
///
/// High-level entry point that validates the target PID, finds or
/// creates the scheduling entry, and applies the policy.
///
/// # Arguments
///
/// * `table`      — Policy table.
/// * `pid`        — Target process (0 = caller).
/// * `attr`       — Validated scheduling attributes.
/// * `caller_pid` — PID of the calling process.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — invalid PID.
/// * [`Error::OutOfMemory`]     — table full.
pub fn apply_policy(
    table: &mut PolicyTable,
    pid: u64,
    attr: &SchedAttr,
    caller_pid: u64,
) -> Result<()> {
    let target_pid = if pid == 0 { caller_pid } else { pid };
    if target_pid > PID_MAX_LIMIT {
        return Err(Error::InvalidArgument);
    }
    let entry = table.find_or_create_mut(target_pid)?;
    apply_policy_to_entry(entry, attr);
    Ok(())
}

// ---------------------------------------------------------------------------
// sys_sched_setattr — set scheduling attributes
// ---------------------------------------------------------------------------

/// Handler for `sched_setattr(2)`.
///
/// Validates and applies scheduling attributes for the target process.
///
/// # Arguments
///
/// * `table`      — Policy table.
/// * `pid`        — Target process (0 = caller).
/// * `attr`       — New scheduling attributes.
/// * `attr_size`  — Caller-provided structure size (version check).
/// * `flags`      — Reserved; must be 0.
/// * `caller_pid` — PID of the calling process.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — invalid policy, priority, deadline params,
///   unrecognised flags, or bad `attr_size`.
/// * [`Error::OutOfMemory`]     — table full.
pub fn sys_sched_setattr(
    table: &mut PolicyTable,
    pid: u64,
    attr: &SchedAttr,
    attr_size: usize,
    flags: u32,
    caller_pid: u64,
) -> Result<()> {
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    validate_attr(attr, attr_size)?;
    apply_policy(table, pid, attr, caller_pid)
}

// ---------------------------------------------------------------------------
// sys_sched_getattr — get scheduling attributes
// ---------------------------------------------------------------------------

/// Handler for `sched_getattr(2)`.
///
/// Returns the current scheduling attributes for the target process.
/// Processes with no explicit entry return default `SCHED_NORMAL` attributes.
///
/// # Arguments
///
/// * `table`      — Policy table.
/// * `pid`        — Target process (0 = caller).
/// * `size`       — Size of the caller's buffer.
/// * `flags`      — Reserved; must be 0.
/// * `caller_pid` — PID of the calling process.
///
/// # Returns
///
/// The current [`SchedAttr`] for the target process.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — `size` too small, non-zero flags, or bad PID.
pub fn sys_sched_getattr(
    table: &PolicyTable,
    pid: u64,
    size: u32,
    flags: u32,
    caller_pid: u64,
) -> Result<SchedAttr> {
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    if (size as usize) < SCHED_ATTR_SIZE_VER0 {
        return Err(Error::InvalidArgument);
    }
    let target_pid = if pid == 0 { caller_pid } else { pid };
    if target_pid > PID_MAX_LIMIT {
        return Err(Error::InvalidArgument);
    }

    match table.find(target_pid) {
        Some(entry) => Ok(entry.attr),
        None => {
            let mut a = SchedAttr::default();
            a.size = core::mem::size_of::<SchedAttr>() as u32;
            Ok(a)
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn normal_attr() -> SchedAttr {
        SchedAttr::default()
    }

    fn rt_attr(policy: u32, priority: u32) -> SchedAttr {
        SchedAttr {
            sched_policy: policy,
            sched_priority: priority,
            ..SchedAttr::default()
        }
    }

    fn deadline_attr(runtime: u64, deadline: u64, period: u64) -> SchedAttr {
        SchedAttr {
            sched_policy: SCHED_DEADLINE,
            sched_runtime: runtime,
            sched_deadline: deadline,
            sched_period: period,
            ..SchedAttr::default()
        }
    }

    // --- SchedPolicy ---

    #[test]
    fn policy_roundtrip() {
        for raw in [0u32, 1, 2, 3, 5, 6] {
            let p = SchedPolicy::from_u32(raw).unwrap();
            assert_eq!(p.as_u32(), raw);
        }
    }

    #[test]
    fn policy_invalid() {
        assert_eq!(SchedPolicy::from_u32(4), Err(Error::InvalidArgument));
        assert_eq!(SchedPolicy::from_u32(7), Err(Error::InvalidArgument));
    }

    #[test]
    fn policy_classification() {
        assert!(SchedPolicy::Fifo.is_realtime());
        assert!(SchedPolicy::RoundRobin.is_realtime());
        assert!(!SchedPolicy::Normal.is_realtime());
        assert!(SchedPolicy::Deadline.is_deadline());
        assert!(SchedPolicy::Normal.is_normal_class());
        assert!(SchedPolicy::Batch.is_normal_class());
        assert!(SchedPolicy::Idle.is_normal_class());
    }

    // --- validate_attr ---

    #[test]
    fn validate_normal_ok() {
        let attr = normal_attr();
        assert!(validate_attr(&attr, SCHED_ATTR_SIZE_VER1).is_ok());
    }

    #[test]
    fn validate_fifo_ok() {
        let attr = rt_attr(SCHED_FIFO, 50);
        assert!(validate_attr(&attr, SCHED_ATTR_SIZE_VER1).is_ok());
    }

    #[test]
    fn validate_fifo_zero_priority_rejected() {
        let attr = rt_attr(SCHED_FIFO, 0);
        assert_eq!(
            validate_attr(&attr, SCHED_ATTR_SIZE_VER1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_rr_priority_too_high() {
        let attr = rt_attr(SCHED_RR, 100);
        assert_eq!(
            validate_attr(&attr, SCHED_ATTR_SIZE_VER1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_deadline_ok() {
        let attr = deadline_attr(1_000_000, 5_000_000, 10_000_000);
        assert!(validate_attr(&attr, SCHED_ATTR_SIZE_VER1).is_ok());
    }

    #[test]
    fn validate_deadline_runtime_gt_deadline() {
        let attr = deadline_attr(6_000_000, 5_000_000, 10_000_000);
        assert_eq!(
            validate_attr(&attr, SCHED_ATTR_SIZE_VER1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_deadline_zero_runtime() {
        let attr = deadline_attr(0, 5_000_000, 10_000_000);
        assert_eq!(
            validate_attr(&attr, SCHED_ATTR_SIZE_VER1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_size_too_small() {
        let attr = normal_attr();
        assert_eq!(validate_attr(&attr, 8), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_nice_out_of_range() {
        let mut attr = normal_attr();
        attr.sched_nice = 20;
        assert_eq!(
            validate_attr(&attr, SCHED_ATTR_SIZE_VER1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_unknown_flags() {
        let mut attr = normal_attr();
        attr.sched_flags = 0xFFFF_0000;
        assert_eq!(
            validate_attr(&attr, SCHED_ATTR_SIZE_VER1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_uclamp_min_gt_max() {
        let mut attr = normal_attr();
        attr.sched_util_min = 512;
        attr.sched_util_max = 256;
        assert_eq!(
            validate_attr(&attr, SCHED_ATTR_SIZE_VER1),
            Err(Error::InvalidArgument)
        );
    }

    // --- sys_sched_setattr / sys_sched_getattr ---

    #[test]
    fn setattr_and_getattr_normal() {
        let mut t = PolicyTable::new();
        let attr = normal_attr();
        sys_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1).unwrap();
        let got = sys_sched_getattr(&t, 1, SCHED_ATTR_SIZE_VER1 as u32, 0, 1).unwrap();
        assert_eq!(got.sched_policy, SCHED_NORMAL);
    }

    #[test]
    fn setattr_fifo() {
        let mut t = PolicyTable::new();
        let attr = rt_attr(SCHED_FIFO, 50);
        sys_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1).unwrap();
        let got = sys_sched_getattr(&t, 1, SCHED_ATTR_SIZE_VER1 as u32, 0, 1).unwrap();
        assert_eq!(got.sched_policy, SCHED_FIFO);
        assert_eq!(got.sched_priority, 50);
    }

    #[test]
    fn setattr_deadline() {
        let mut t = PolicyTable::new();
        let attr = deadline_attr(1_000_000, 5_000_000, 10_000_000);
        sys_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1).unwrap();
        let got = sys_sched_getattr(&t, 1, SCHED_ATTR_SIZE_VER1 as u32, 0, 1).unwrap();
        assert_eq!(got.sched_policy, SCHED_DEADLINE);
        assert_eq!(got.sched_runtime, 1_000_000);
    }

    #[test]
    fn setattr_nonzero_flags_rejected() {
        let mut t = PolicyTable::new();
        let attr = normal_attr();
        assert_eq!(
            sys_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 1, 1,),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn getattr_nonzero_flags_rejected() {
        let t = PolicyTable::new();
        assert_eq!(
            sys_sched_getattr(&t, 1, SCHED_ATTR_SIZE_VER1 as u32, 1, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn getattr_defaults_for_unknown() {
        let t = PolicyTable::new();
        let got = sys_sched_getattr(&t, 9999, SCHED_ATTR_SIZE_VER1 as u32, 0, 1).unwrap();
        assert_eq!(got.sched_policy, SCHED_NORMAL);
        assert_eq!(got.sched_priority, 0);
    }

    #[test]
    fn setattr_pid_zero_means_caller() {
        let mut t = PolicyTable::new();
        let attr = normal_attr();
        sys_sched_setattr(&mut t, 0, &attr, SCHED_ATTR_SIZE_VER1, 0, 42).unwrap();
        let got = sys_sched_getattr(&t, 42, SCHED_ATTR_SIZE_VER1 as u32, 0, 42).unwrap();
        assert_eq!(got.sched_policy, SCHED_NORMAL);
    }

    #[test]
    fn table_remove_reduces_count() {
        let mut t = PolicyTable::new();
        let attr = normal_attr();
        sys_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1).unwrap();
        assert_eq!(t.len(), 1);
        t.remove(1);
        assert_eq!(t.len(), 0);
    }

    // --- apply_policy ---

    #[test]
    fn apply_policy_rr_sets_quantum() {
        let mut t = PolicyTable::new();
        let attr = rt_attr(SCHED_RR, 50);
        apply_policy(&mut t, 1, &attr, 1).unwrap();
        let entry = t.find(1).unwrap();
        assert_eq!(entry.rr_remaining_ns, RR_DEFAULT_QUANTUM_NS);
    }

    #[test]
    fn apply_policy_fifo_no_quantum() {
        let mut t = PolicyTable::new();
        let attr = rt_attr(SCHED_FIFO, 50);
        apply_policy(&mut t, 1, &attr, 1).unwrap();
        let entry = t.find(1).unwrap();
        assert_eq!(entry.rr_remaining_ns, 0);
    }

    #[test]
    fn apply_policy_keep_policy_flag() {
        let mut t = PolicyTable::new();
        // First set to FIFO.
        let fifo = rt_attr(SCHED_FIFO, 50);
        apply_policy(&mut t, 1, &fifo, 1).unwrap();

        // Then apply with KEEP_POLICY: policy should stay FIFO.
        let mut attr = normal_attr();
        attr.sched_flags = SCHED_FLAG_KEEP_POLICY;
        apply_policy(&mut t, 1, &attr, 1).unwrap();

        let entry = t.find(1).unwrap();
        assert_eq!(entry.attr.sched_policy, SCHED_FIFO);
    }
}
