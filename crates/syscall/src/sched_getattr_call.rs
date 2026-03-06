// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sched_getattr(2)` syscall dispatch shim.
//!
//! Thin entry-point that validates the raw syscall arguments for
//! `sched_getattr` before delegating to the full implementation in
//! [`crate::sched_setattr_call`].
//!
//! # Syscall signature
//!
//! ```text
//! int sched_getattr(pid_t pid, struct sched_attr *attr,
//!                   unsigned int size, unsigned int flags);
//! ```
//!
//! # POSIX reference
//!
//! `sched_getattr` is a Linux extension (not in POSIX.1-2024).  It extends
//! the POSIX `sched_getparam(3)` behaviour with deadline scheduling and
//! utilization clamping support.
//!
//! # References
//!
//! - Linux: `kernel/sched/syscalls.c` `sys_sched_getattr()`
//! - `sched_getattr(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum accepted `size` value (version 0 structure).
const SCHED_ATTR_SIZE_VER0: usize = 48;

/// Maximum accepted `size` value.
const SCHED_ATTR_SIZE_MAX: usize = 56;

/// Maximum valid PID.
const PID_MAX: u64 = 4_194_304;

/// `sched_getattr` flags must be zero.
const GETATTR_FLAGS_KNOWN: u32 = 0;

// ---------------------------------------------------------------------------
// SchedAttrSnapshot — returned attribute set
// ---------------------------------------------------------------------------

/// Scheduling policy constants (mirrors `sched_setattr_call`).
pub const SCHED_NORMAL: u32 = 0;
/// Round-robin realtime.
pub const SCHED_RR: u32 = 2;
/// FIFO realtime.
pub const SCHED_FIFO: u32 = 1;
/// Batch scheduling.
pub const SCHED_BATCH: u32 = 3;
/// Idle scheduling.
pub const SCHED_IDLE: u32 = 5;
/// Earliest Deadline First.
pub const SCHED_DEADLINE: u32 = 6;

/// Snapshot of scheduling attributes returned by `sched_getattr`.
///
/// Field layout matches `struct sched_attr` from the Linux UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SchedAttrSnapshot {
    /// Structure size (set to `SCHED_ATTR_SIZE_VER1` by kernel).
    pub size: u32,
    /// Scheduling policy.
    pub sched_policy: u32,
    /// Scheduling flags.
    pub sched_flags: u64,
    /// Nice value (for Normal/Batch/Idle).
    pub sched_nice: i32,
    /// Priority (for FIFO/RR).
    pub sched_priority: u32,
    /// DEADLINE runtime budget (ns).
    pub sched_runtime: u64,
    /// DEADLINE period (ns).
    pub sched_deadline: u64,
    /// DEADLINE period (ns, must be >= deadline).
    pub sched_period: u64,
    /// Minimum utilization clamp (0..=1024).
    pub sched_util_min: u32,
    /// Maximum utilization clamp (0..=1024).
    pub sched_util_max: u32,
}

impl Default for SchedAttrSnapshot {
    fn default() -> Self {
        Self {
            size: SCHED_ATTR_SIZE_MAX as u32,
            sched_policy: SCHED_NORMAL,
            sched_flags: 0,
            sched_nice: 0,
            sched_priority: 0,
            sched_runtime: 0,
            sched_deadline: 0,
            sched_period: 0,
            sched_util_min: 0,
            sched_util_max: 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-thread scheduling state store
// ---------------------------------------------------------------------------

/// Maximum number of threads tracked.
const MAX_THREADS: usize = 256;

/// Per-thread entry.
#[derive(Clone, Copy)]
struct ThreadEntry {
    pid: u64,
    attr: SchedAttrSnapshot,
    active: bool,
}

impl ThreadEntry {
    const fn inactive() -> Self {
        Self {
            pid: 0,
            attr: SchedAttrSnapshot {
                size: SCHED_ATTR_SIZE_MAX as u32,
                sched_policy: SCHED_NORMAL,
                sched_flags: 0,
                sched_nice: 0,
                sched_priority: 0,
                sched_runtime: 0,
                sched_deadline: 0,
                sched_period: 0,
                sched_util_min: 0,
                sched_util_max: 1024,
            },
            active: false,
        }
    }
}

/// Store of per-thread scheduling attributes.
pub struct SchedAttrStore {
    entries: [ThreadEntry; MAX_THREADS],
}

impl SchedAttrStore {
    /// Create an empty store.
    pub const fn new() -> Self {
        Self {
            entries: [const { ThreadEntry::inactive() }; MAX_THREADS],
        }
    }

    /// Insert or update attributes for `pid`.
    pub fn set(&mut self, pid: u64, attr: SchedAttrSnapshot) -> Result<()> {
        if let Some(e) = self.entries.iter_mut().find(|e| e.active && e.pid == pid) {
            e.attr = attr;
            return Ok(());
        }
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot] = ThreadEntry {
            pid,
            attr,
            active: true,
        };
        Ok(())
    }

    /// Retrieve attributes for `pid`.  Returns default if not found.
    pub fn get(&self, pid: u64) -> SchedAttrSnapshot {
        self.entries
            .iter()
            .find(|e| e.active && e.pid == pid)
            .map(|e| e.attr)
            .unwrap_or_default()
    }
}

impl Default for SchedAttrStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `sched_getattr` arguments.
pub fn validate_getattr_args(pid: u64, size: u32, flags: u32) -> Result<()> {
    if pid > PID_MAX {
        return Err(Error::InvalidArgument);
    }
    let sz = size as usize;
    if sz < SCHED_ATTR_SIZE_VER0 || sz > SCHED_ATTR_SIZE_MAX {
        return Err(Error::InvalidArgument);
    }
    if flags & !GETATTR_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// sys_sched_getattr — entry point
// ---------------------------------------------------------------------------

/// Handler for `sched_getattr(2)`.
///
/// Returns the current scheduling attributes for thread `pid` (0 = caller).
///
/// # Arguments
///
/// * `store`      — Scheduling attribute store.
/// * `pid`        — Target process/thread (0 = caller).
/// * `size`       — Size of the caller's buffer (version check).
/// * `flags`      — Reserved; must be 0.
/// * `caller_pid` — PID of the calling thread.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — out-of-range `pid`, bad `size`, non-zero
///   `flags`.
pub fn sys_sched_getattr(
    store: &SchedAttrStore,
    pid: u64,
    size: u32,
    flags: u32,
    caller_pid: u64,
) -> Result<SchedAttrSnapshot> {
    validate_getattr_args(pid, size, flags)?;
    let target = if pid == 0 { caller_pid } else { pid };
    Ok(store.get(target))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_default_when_not_set() {
        let store = SchedAttrStore::new();
        let snap = sys_sched_getattr(&store, 0, SCHED_ATTR_SIZE_VER0 as u32, 0, 42).unwrap();
        assert_eq!(snap.sched_policy, SCHED_NORMAL);
        assert_eq!(snap.sched_priority, 0);
    }

    #[test]
    fn get_after_set() {
        let mut store = SchedAttrStore::new();
        let mut attr = SchedAttrSnapshot::default();
        attr.sched_policy = SCHED_FIFO;
        attr.sched_priority = 50;
        store.set(7, attr).unwrap();
        let snap = sys_sched_getattr(&store, 7, SCHED_ATTR_SIZE_MAX as u32, 0, 1).unwrap();
        assert_eq!(snap.sched_policy, SCHED_FIFO);
        assert_eq!(snap.sched_priority, 50);
    }

    #[test]
    fn pid_zero_uses_caller() {
        let mut store = SchedAttrStore::new();
        let mut attr = SchedAttrSnapshot::default();
        attr.sched_policy = SCHED_BATCH;
        store.set(99, attr).unwrap();
        let snap = sys_sched_getattr(&store, 0, SCHED_ATTR_SIZE_VER0 as u32, 0, 99).unwrap();
        assert_eq!(snap.sched_policy, SCHED_BATCH);
    }

    #[test]
    fn nonzero_flags_rejected() {
        let store = SchedAttrStore::new();
        assert_eq!(
            sys_sched_getattr(&store, 0, SCHED_ATTR_SIZE_VER0 as u32, 1, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn size_too_small() {
        let store = SchedAttrStore::new();
        assert_eq!(
            sys_sched_getattr(&store, 0, 16, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn size_too_large() {
        let store = SchedAttrStore::new();
        assert_eq!(
            sys_sched_getattr(&store, 0, 1024, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn pid_out_of_range() {
        let store = SchedAttrStore::new();
        assert_eq!(
            sys_sched_getattr(&store, 10_000_000, SCHED_ATTR_SIZE_VER0 as u32, 0, 1),
            Err(Error::InvalidArgument)
        );
    }
}
