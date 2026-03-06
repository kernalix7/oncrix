// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sched_getattr(2)` and `sched_setattr(2)` syscall handlers.
//!
//! These syscalls (introduced in Linux 3.14) extend the older
//! `sched_getscheduler`/`sched_setscheduler` interface with a versioned
//! in-memory structure (`SchedAttr`) that can be extended to carry more
//! information in future kernel versions.  Notably, they are the primary
//! interface for the `SCHED_DEADLINE` policy.
//!
//! # Key differences from `sched_setscheduler`
//!
//! | Feature                  | `sched_setscheduler` | `sched_setattr`    |
//! |--------------------------|----------------------|--------------------|
//! | Versioned structure      | No                   | Yes (`size` field) |
//! | SCHED_DEADLINE support   | Limited              | Full               |
//! | `nice` value             | No                   | Yes                |
//! | Utilization hints        | No                   | Yes (util_min/max) |
//!
//! # Scheduling policies
//!
//! | Constant          | Value | Description                          |
//! |-------------------|-------|--------------------------------------|
//! | `SCHED_NORMAL`    | 0     | CFS (default)                        |
//! | `SCHED_FIFO`      | 1     | First-in first-out realtime           |
//! | `SCHED_RR`        | 2     | Round-robin realtime                  |
//! | `SCHED_BATCH`     | 3     | Batch, non-interactive                |
//! | `SCHED_IDLE`      | 5     | Very low priority                     |
//! | `SCHED_DEADLINE`  | 6     | Earliest Deadline First               |
//!
//! # References
//!
//! - Linux: `kernel/sched/syscalls.c` — `sched_setattr()`, `sched_getattr()`
//! - `include/uapi/linux/sched/types.h` — `struct sched_attr`
//! - man-pages: `sched_setattr(2)`, `sched_getattr(2)`

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

/// Flag: reset the scheduling policy to `SCHED_NORMAL` on fork.
pub const SCHED_FLAG_RESET_ON_FORK: u64 = 1 << 0;
/// Flag: reclaim unused runtime from other DEADLINE tasks.
pub const SCHED_FLAG_RECLAIM: u64 = 1 << 1;
/// Flag: allow DEADLINE bandwidth monitoring.
pub const SCHED_FLAG_DL_OVERRUN: u64 = 1 << 2;
/// Flag: keep FIFO/RR priority even after setting util clamps.
pub const SCHED_FLAG_KEEP_POLICY: u64 = 1 << 3;
/// Flag: keep parameters when setting util clamps.
pub const SCHED_FLAG_KEEP_PARAMS: u64 = 1 << 4;
/// Flag: set utilization minimum clamp.
pub const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 1 << 5;
/// Flag: set utilization maximum clamp.
pub const SCHED_FLAG_UTIL_CLAMP_MAX: u64 = 1 << 6;

/// All recognised `sched_attr.flags` bits.
const SCHED_FLAGS_KNOWN: u64 = SCHED_FLAG_RESET_ON_FORK
    | SCHED_FLAG_RECLAIM
    | SCHED_FLAG_DL_OVERRUN
    | SCHED_FLAG_KEEP_POLICY
    | SCHED_FLAG_KEEP_PARAMS
    | SCHED_FLAG_UTIL_CLAMP_MIN
    | SCHED_FLAG_UTIL_CLAMP_MAX;

// ---------------------------------------------------------------------------
// Priority limits
// ---------------------------------------------------------------------------

/// Minimum realtime priority (for `SCHED_FIFO` / `SCHED_RR`).
const RT_PRIO_MIN: u32 = 1;
/// Maximum realtime priority.
const RT_PRIO_MAX: u32 = 99;
/// Maximum nice value (lowest priority, `+19` in POSIX terms).
const NICE_MAX: i32 = 19;
/// Minimum nice value (highest non-RT priority, `-20` in POSIX terms).
const NICE_MIN: i32 = -20;
/// Maximum utilization clamp value (SCHED_CAPACITY_SCALE).
const UCLAMP_MAX_VALUE: u32 = 1024;
/// Maximum PID accepted.
const PID_MAX_LIMIT: u64 = 4_194_304;

// ---------------------------------------------------------------------------
// SchedAttr — the in-memory argument structure
// ---------------------------------------------------------------------------

/// Minimum valid size for a `sched_attr` structure (version 0).
///
/// Version 0 (Linux 3.14) covers `size` through `sched_period`.
pub const SCHED_ATTR_SIZE_VER0: usize = 48;

/// Extended minimum size including utilization clamping fields (Linux 5.3).
pub const SCHED_ATTR_SIZE_VER1: usize = 56;

/// Argument structure for `sched_getattr(2)` and `sched_setattr(2)`.
///
/// Matches `struct sched_attr` from `include/uapi/linux/sched/types.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SchedAttr {
    /// Structure size in bytes (caller fills in for `setattr`; kernel fills in for `getattr`).
    pub size: u32,
    /// Scheduling policy (one of `SCHED_*`).
    pub sched_policy: u32,
    /// Scheduling flags (combination of `SCHED_FLAG_*`).
    pub sched_flags: u64,
    /// `nice` value for `SCHED_NORMAL` / `SCHED_BATCH` (range: `NICE_MIN`..=`NICE_MAX`).
    pub sched_nice: i32,
    /// Priority for `SCHED_FIFO` / `SCHED_RR` (range: 1..=99).
    pub sched_priority: u32,
    /// `SCHED_DEADLINE`: runtime budget per period (nanoseconds).
    pub sched_runtime: u64,
    /// `SCHED_DEADLINE`: deadline relative to period start (nanoseconds).
    pub sched_deadline: u64,
    /// `SCHED_DEADLINE`: period length (nanoseconds).
    pub sched_period: u64,
    // Version 1 fields (Linux 5.3+):
    /// Minimum utilization clamp (0..=`UCLAMP_MAX_VALUE`).
    pub sched_util_min: u32,
    /// Maximum utilization clamp (0..=`UCLAMP_MAX_VALUE`).
    pub sched_util_max: u32,
}

// ---------------------------------------------------------------------------
// Process scheduling state (stub)
// ---------------------------------------------------------------------------

/// Maximum number of entries in the per-process scheduling state table.
pub const MAX_SCHED_ENTRIES: usize = 256;

/// Per-process scheduling state stored in the table.
struct SchedEntry {
    pid: u64,
    attr: SchedAttr,
    in_use: bool,
}

impl SchedEntry {
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
            in_use: false,
        }
    }
}

/// Table tracking `SchedAttr` for all processes.
pub struct SchedAttrTable {
    entries: [SchedEntry; MAX_SCHED_ENTRIES],
    count: usize,
}

impl SchedAttrTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { SchedEntry::new() }; MAX_SCHED_ENTRIES],
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

    fn find(&self, pid: u64) -> Option<&SchedEntry> {
        self.entries.iter().find(|e| e.in_use && e.pid == pid)
    }

    fn find_or_create_mut(&mut self, pid: u64) -> Result<&mut SchedEntry> {
        let existing = self.entries.iter().position(|e| e.in_use && e.pid == pid);
        if let Some(idx) = existing {
            return Ok(&mut self.entries[idx]);
        }
        let free = self
            .entries
            .iter()
            .position(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;

        let default_attr = SchedEntry::new().attr;
        self.entries[free].in_use = true;
        self.entries[free].pid = pid;
        self.entries[free].attr = default_attr;
        self.count += 1;
        Ok(&mut self.entries[free])
    }

    /// Remove the entry for a terminated process.
    pub fn remove(&mut self, pid: u64) -> bool {
        for e in &mut self.entries {
            if e.in_use && e.pid == pid {
                e.in_use = false;
                e.pid = 0;
                self.count = self.count.saturating_sub(1);
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a `sched_attr` structure for `sched_setattr`.
fn validate_attr(attr: &SchedAttr, size: usize) -> Result<()> {
    // Size check.
    let max_size = core::mem::size_of::<SchedAttr>();
    if size < SCHED_ATTR_SIZE_VER0 || size > max_size {
        return Err(Error::InvalidArgument);
    }

    // Unknown flags.
    if attr.sched_flags & !SCHED_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }

    match attr.sched_policy {
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE => {
            // Priority must be 0.
            if attr.sched_priority != 0 {
                return Err(Error::InvalidArgument);
            }
            // Nice range check.
            if attr.sched_nice < NICE_MIN || attr.sched_nice > NICE_MAX {
                return Err(Error::InvalidArgument);
            }
        }
        SCHED_FIFO | SCHED_RR => {
            // RT priority range.
            if attr.sched_priority < RT_PRIO_MIN || attr.sched_priority > RT_PRIO_MAX {
                return Err(Error::InvalidArgument);
            }
            // Nice is irrelevant for RT; must be 0.
            if attr.sched_nice != 0 {
                return Err(Error::InvalidArgument);
            }
        }
        SCHED_DEADLINE => {
            // Priority must be 0.
            if attr.sched_priority != 0 {
                return Err(Error::InvalidArgument);
            }
            // Deadline constraints: 0 < runtime <= deadline <= period.
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
        _ => return Err(Error::InvalidArgument),
    }

    // Utilization clamp validation (version 1 fields).
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
// do_sched_setattr
// ---------------------------------------------------------------------------

/// Handler for `sched_setattr(2)`.
///
/// Sets the scheduling policy and attributes for process `pid`.
/// `pid == 0` means the calling process.
///
/// # Arguments
///
/// * `table`      — Per-process scheduling attribute table.
/// * `pid`        — Target process (0 = caller).
/// * `attr`       — New scheduling attributes.
/// * `attr_size`  — Size the caller specified (version check).
/// * `flags`      — Reserved; must be 0.
/// * `caller_pid` — PID of the calling process.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Invalid policy, priority, deadline params,
///   unrecognised flags, or bad `attr_size`.
/// - [`Error::OutOfMemory`]     — Table full.
pub fn do_sched_setattr(
    table: &mut SchedAttrTable,
    pid: u64,
    attr: &SchedAttr,
    attr_size: usize,
    flags: u32,
    caller_pid: u64,
) -> Result<()> {
    // `flags` argument to sched_setattr must be 0 (reserved).
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }

    let target_pid = if pid == 0 { caller_pid } else { pid };

    if target_pid > PID_MAX_LIMIT {
        return Err(Error::InvalidArgument);
    }

    validate_attr(attr, attr_size)?;

    let entry = table.find_or_create_mut(target_pid)?;
    let mut new_attr = *attr;
    // Kernel always reports the full structure size.
    new_attr.size = core::mem::size_of::<SchedAttr>() as u32;
    entry.attr = new_attr;

    Ok(())
}

// ---------------------------------------------------------------------------
// do_sched_getattr
// ---------------------------------------------------------------------------

/// Handler for `sched_getattr(2)`.
///
/// Returns the current scheduling attributes for process `pid`.
/// `pid == 0` means the calling process.
///
/// The `size` argument specifies how many bytes the caller's buffer can
/// accept.  The kernel truncates the response to `size` bytes but always
/// sets `attr.size` to the full kernel structure size so the caller can
/// detect extensions.
///
/// # Arguments
///
/// * `table`      — Per-process scheduling attribute table.
/// * `pid`        — Target process (0 = caller).
/// * `size`       — Size of the caller's buffer.
/// * `flags`      — Reserved; must be 0.
/// * `caller_pid` — PID of the calling process.
///
/// # Returns
///
/// The [`SchedAttr`] for the target process.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `size` too small, non-zero flags, or invalid pid.
/// - [`Error::NotFound`]        — No process with the given PID.
pub fn do_sched_getattr(
    table: &SchedAttrTable,
    pid: u64,
    size: u32,
    flags: u32,
    caller_pid: u64,
) -> Result<SchedAttr> {
    // `flags` must be 0.
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }

    // Size must be at least version-0 minimum.
    if (size as usize) < SCHED_ATTR_SIZE_VER0 {
        return Err(Error::InvalidArgument);
    }

    let target_pid = if pid == 0 { caller_pid } else { pid };

    if target_pid > PID_MAX_LIMIT {
        return Err(Error::InvalidArgument);
    }

    let attr = match table.find(target_pid) {
        Some(entry) => entry.attr,
        None => {
            // Process has never called sched_setattr: return defaults.
            let mut a = SchedEntry::new().attr;
            a.size = core::mem::size_of::<SchedAttr>() as u32;
            a
        }
    };

    Ok(attr)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn normal_attr() -> SchedAttr {
        SchedAttr {
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

    fn rt_attr(policy: u32, priority: u32) -> SchedAttr {
        SchedAttr {
            size: SCHED_ATTR_SIZE_VER1 as u32,
            sched_policy: policy,
            sched_flags: 0,
            sched_nice: 0,
            sched_priority: priority,
            sched_runtime: 0,
            sched_deadline: 0,
            sched_period: 0,
            sched_util_min: 0,
            sched_util_max: UCLAMP_MAX_VALUE,
        }
    }

    fn deadline_attr(runtime: u64, deadline: u64, period: u64) -> SchedAttr {
        SchedAttr {
            size: SCHED_ATTR_SIZE_VER1 as u32,
            sched_policy: SCHED_DEADLINE,
            sched_flags: 0,
            sched_nice: 0,
            sched_priority: 0,
            sched_runtime: runtime,
            sched_deadline: deadline,
            sched_period: period,
            sched_util_min: 0,
            sched_util_max: UCLAMP_MAX_VALUE,
        }
    }

    #[test]
    fn setattr_and_getattr_normal() {
        let mut t = SchedAttrTable::new();
        let attr = normal_attr();
        do_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1).unwrap();
        let got = do_sched_getattr(&t, 1, SCHED_ATTR_SIZE_VER1 as u32, 0, 1).unwrap();
        assert_eq!(got.sched_policy, SCHED_NORMAL);
        assert_eq!(got.sched_nice, 0);
    }

    #[test]
    fn setattr_fifo_valid_priority() {
        let mut t = SchedAttrTable::new();
        let attr = rt_attr(SCHED_FIFO, 50);
        do_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1).unwrap();
        let got = do_sched_getattr(&t, 1, SCHED_ATTR_SIZE_VER1 as u32, 0, 1).unwrap();
        assert_eq!(got.sched_policy, SCHED_FIFO);
        assert_eq!(got.sched_priority, 50);
    }

    #[test]
    fn setattr_rr_priority_out_of_range() {
        let mut t = SchedAttrTable::new();
        let attr = rt_attr(SCHED_RR, 100); // 100 > RT_PRIO_MAX (99)
        assert_eq!(
            do_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setattr_fifo_zero_priority_rejected() {
        let mut t = SchedAttrTable::new();
        let attr = rt_attr(SCHED_FIFO, 0);
        assert_eq!(
            do_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setattr_deadline_valid() {
        let mut t = SchedAttrTable::new();
        let attr = deadline_attr(1_000_000, 5_000_000, 10_000_000);
        do_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1).unwrap();
        let got = do_sched_getattr(&t, 1, SCHED_ATTR_SIZE_VER1 as u32, 0, 1).unwrap();
        assert_eq!(got.sched_policy, SCHED_DEADLINE);
        assert_eq!(got.sched_runtime, 1_000_000);
    }

    #[test]
    fn setattr_deadline_runtime_exceeds_deadline() {
        let mut t = SchedAttrTable::new();
        let attr = deadline_attr(6_000_000, 5_000_000, 10_000_000);
        assert_eq!(
            do_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setattr_deadline_zero_runtime_rejected() {
        let mut t = SchedAttrTable::new();
        let attr = deadline_attr(0, 5_000_000, 10_000_000);
        assert_eq!(
            do_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setattr_nonzero_flags_rejected() {
        let mut t = SchedAttrTable::new();
        let attr = normal_attr();
        assert_eq!(
            do_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 1, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn getattr_nonzero_flags_rejected() {
        let t = SchedAttrTable::new();
        assert_eq!(
            do_sched_getattr(&t, 1, SCHED_ATTR_SIZE_VER1 as u32, 1, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn getattr_returns_defaults_for_unknown_process() {
        let t = SchedAttrTable::new();
        let got = do_sched_getattr(&t, 9999, SCHED_ATTR_SIZE_VER1 as u32, 0, 1).unwrap();
        assert_eq!(got.sched_policy, SCHED_NORMAL);
        assert_eq!(got.sched_priority, 0);
    }

    #[test]
    fn getattr_too_small_size_rejected() {
        let t = SchedAttrTable::new();
        assert_eq!(
            do_sched_getattr(&t, 1, 8, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setattr_pid_zero_means_caller() {
        let mut t = SchedAttrTable::new();
        let attr = normal_attr();
        do_sched_setattr(&mut t, 0, &attr, SCHED_ATTR_SIZE_VER1, 0, 42).unwrap();
        // Should have stored under PID 42.
        let got = do_sched_getattr(&t, 42, SCHED_ATTR_SIZE_VER1 as u32, 0, 42).unwrap();
        assert_eq!(got.sched_policy, SCHED_NORMAL);
    }

    #[test]
    fn setattr_nice_out_of_range_rejected() {
        let mut t = SchedAttrTable::new();
        let mut attr = normal_attr();
        attr.sched_nice = 20; // > NICE_MAX (19)
        assert_eq!(
            do_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setattr_uclamp_min_exceeds_max_rejected() {
        let mut t = SchedAttrTable::new();
        let mut attr = normal_attr();
        attr.sched_util_min = 512;
        attr.sched_util_max = 256; // min > max
        assert_eq!(
            do_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setattr_unknown_sched_flag_rejected() {
        let mut t = SchedAttrTable::new();
        let mut attr = normal_attr();
        attr.sched_flags = 0xFFFF_0000;
        assert_eq!(
            do_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn table_remove_reduces_count() {
        let mut t = SchedAttrTable::new();
        let attr = normal_attr();
        do_sched_setattr(&mut t, 1, &attr, SCHED_ATTR_SIZE_VER1, 0, 1).unwrap();
        assert_eq!(t.len(), 1);
        t.remove(1);
        assert_eq!(t.len(), 0);
    }
}
