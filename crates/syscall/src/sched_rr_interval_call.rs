// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sched_rr_get_interval(2)` syscall handler.
//!
//! Returns the round-robin quantum for the given process.  If the process is
//! not running under `SCHED_RR`, the call returns `EINVAL` (or a
//! zero-duration interval, depending on implementation).  ONCRIX returns a
//! default 100 ms quantum for all `SCHED_RR` processes.
//!
//! # Syscall signature
//!
//! ```text
//! int sched_rr_get_interval(pid_t pid, struct timespec *interval);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §sched_rr_get_interval — `<sched.h>`.
//!
//! # References
//!
//! - Linux: `kernel/sched/syscalls.c` `sys_sched_rr_get_interval()`
//! - `sched_rr_get_interval(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum valid PID.
const PID_MAX: u64 = 4_194_304;

/// Default RR quantum: 100 ms in nanoseconds.
pub const RR_DEFAULT_QUANTUM_NS: u64 = 100_000_000;

/// Nanoseconds per second.
const NS_PER_SEC: u64 = 1_000_000_000;

/// SCHED_RR policy value.
pub const SCHED_RR: u32 = 2;

// ---------------------------------------------------------------------------
// Timespec — interval representation
// ---------------------------------------------------------------------------

/// POSIX `struct timespec` for the interval.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0..999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Construct from a nanosecond count.
    pub const fn from_ns(ns: u64) -> Self {
        Self {
            tv_sec: (ns / NS_PER_SEC) as i64,
            tv_nsec: (ns % NS_PER_SEC) as i64,
        }
    }

    /// Convert to total nanoseconds (may overflow for very large values).
    pub const fn to_ns(&self) -> u64 {
        self.tv_sec as u64 * NS_PER_SEC + self.tv_nsec as u64
    }
}

// ---------------------------------------------------------------------------
// RrEntry — per-process RR quantum record
// ---------------------------------------------------------------------------

/// Per-process RR quantum record.
#[derive(Clone, Copy)]
struct RrEntry {
    pid: u64,
    /// Current quantum in nanoseconds.
    quantum_ns: u64,
    policy: u32,
    active: bool,
}

impl RrEntry {
    const fn inactive() -> Self {
        Self {
            pid: 0,
            quantum_ns: RR_DEFAULT_QUANTUM_NS,
            policy: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// RrIntervalTable
// ---------------------------------------------------------------------------

/// Maximum tracked processes.
const MAX_ENTRIES: usize = 256;

/// Table of per-process RR quantum configurations.
pub struct RrIntervalTable {
    entries: [RrEntry; MAX_ENTRIES],
}

impl RrIntervalTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { RrEntry::inactive() }; MAX_ENTRIES],
        }
    }

    /// Register `pid` with the given policy and optional quantum override.
    ///
    /// Only meaningful for `SCHED_RR` processes; other policies still get
    /// stored so they can report `InvalidArgument` correctly.
    pub fn set(&mut self, pid: u64, policy: u32, quantum_ns: u64) -> Result<()> {
        if let Some(e) = self.entries.iter_mut().find(|e| e.active && e.pid == pid) {
            e.policy = policy;
            e.quantum_ns = quantum_ns;
            return Ok(());
        }
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot] = RrEntry {
            pid,
            quantum_ns,
            policy,
            active: true,
        };
        Ok(())
    }

    /// Look up the quantum for `pid`.  Returns `None` if not registered.
    fn get_entry(&self, pid: u64) -> Option<&RrEntry> {
        self.entries.iter().find(|e| e.active && e.pid == pid)
    }
}

impl Default for RrIntervalTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_sched_rr_get_interval — entry point
// ---------------------------------------------------------------------------

/// Handler for `sched_rr_get_interval(2)`.
///
/// Returns the round-robin quantum for process `pid` (0 = caller).
///
/// # Arguments
///
/// * `table`      — RR interval table.
/// * `pid`        — Target process (0 = caller).
/// * `caller_pid` — PID of the calling thread.
///
/// # Returns
///
/// `Timespec` interval on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — PID out of range or process is not
///   `SCHED_RR`.
/// * [`Error::NotFound`]        — PID not found in table (not a tracked
///   process).
pub fn sys_sched_rr_get_interval(
    table: &RrIntervalTable,
    pid: u64,
    caller_pid: u64,
) -> Result<Timespec> {
    if pid > PID_MAX {
        return Err(Error::InvalidArgument);
    }
    let target = if pid == 0 { caller_pid } else { pid };

    match table.get_entry(target) {
        None => {
            // Not registered → assume SCHED_NORMAL, which has no interval.
            Err(Error::InvalidArgument)
        }
        Some(e) if e.policy != SCHED_RR => {
            // Not an RR process.
            Err(Error::InvalidArgument)
        }
        Some(e) => Ok(Timespec::from_ns(e.quantum_ns)),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rr_process_returns_quantum() {
        let mut t = RrIntervalTable::new();
        t.set(10, SCHED_RR, RR_DEFAULT_QUANTUM_NS).unwrap();
        let ts = sys_sched_rr_get_interval(&t, 10, 1).unwrap();
        assert_eq!(ts.to_ns(), RR_DEFAULT_QUANTUM_NS);
    }

    #[test]
    fn rr_quantum_split() {
        let ts = Timespec::from_ns(1_100_000_000);
        assert_eq!(ts.tv_sec, 1);
        assert_eq!(ts.tv_nsec, 100_000_000);
    }

    #[test]
    fn non_rr_process_rejected() {
        let mut t = RrIntervalTable::new();
        t.set(5, 0 /* SCHED_NORMAL */, 0).unwrap();
        assert_eq!(
            sys_sched_rr_get_interval(&t, 5, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_pid_rejected() {
        let t = RrIntervalTable::new();
        assert_eq!(
            sys_sched_rr_get_interval(&t, 9999, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn pid_zero_uses_caller() {
        let mut t = RrIntervalTable::new();
        t.set(42, SCHED_RR, 50_000_000).unwrap();
        let ts = sys_sched_rr_get_interval(&t, 0, 42).unwrap();
        assert_eq!(ts.to_ns(), 50_000_000);
    }

    #[test]
    fn pid_too_large() {
        let t = RrIntervalTable::new();
        assert_eq!(
            sys_sched_rr_get_interval(&t, 10_000_000, 1),
            Err(Error::InvalidArgument)
        );
    }
}
