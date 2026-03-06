// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `times(2)` syscall handler and clock-tick accounting.
//!
//! Returns the times for the current process and its children in clock ticks.
//! Also provides helper routines for converting between nanoseconds and
//! POSIX `clock_t` units.
//!
//! # Syscall signature
//!
//! ```text
//! clock_t times(struct tms *buf);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §times — `<sys/times.h>`.
//!
//! # References
//!
//! - Linux: `kernel/sys.c` `sys_times()`
//! - `times(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Clock tick constants
// ---------------------------------------------------------------------------

/// POSIX `sysconf(_SC_CLK_TCK)` — clock ticks per second.
pub const CLK_TCK: u64 = 100;
/// Nanoseconds per clock tick.
pub const NS_PER_TICK: u64 = 1_000_000_000 / CLK_TCK;

// ---------------------------------------------------------------------------
// Tms — POSIX tms structure
// ---------------------------------------------------------------------------

/// POSIX `struct tms`.
///
/// All values are in clock ticks.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tms {
    /// User CPU time of the calling process.
    pub tms_utime: i64,
    /// System CPU time of the calling process.
    pub tms_stime: i64,
    /// User CPU time of all waited-for children.
    pub tms_cutime: i64,
    /// System CPU time of all waited-for children.
    pub tms_cstime: i64,
}

impl Tms {
    /// Construct from nanosecond measurements.
    pub const fn from_ns(utime_ns: u64, stime_ns: u64, cutime_ns: u64, cstime_ns: u64) -> Self {
        Self {
            tms_utime: (utime_ns / NS_PER_TICK) as i64,
            tms_stime: (stime_ns / NS_PER_TICK) as i64,
            tms_cutime: (cutime_ns / NS_PER_TICK) as i64,
            tms_cstime: (cstime_ns / NS_PER_TICK) as i64,
        }
    }
}

// ---------------------------------------------------------------------------
// ProcessTimeRecord — per-process CPU time counters
// ---------------------------------------------------------------------------

/// Per-process CPU time record (in nanoseconds).
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessTimeRecord {
    /// Process ID.
    pub pid: u64,
    /// User time (ns).
    pub utime_ns: u64,
    /// System time (ns).
    pub stime_ns: u64,
    /// Cumulative children user time (ns).
    pub cutime_ns: u64,
    /// Cumulative children system time (ns).
    pub cstime_ns: u64,
    /// Whether this slot is active.
    pub active: bool,
}

impl ProcessTimeRecord {
    /// Produce a `Tms` for this record.
    pub const fn to_tms(&self) -> Tms {
        Tms::from_ns(self.utime_ns, self.stime_ns, self.cutime_ns, self.cstime_ns)
    }
}

// ---------------------------------------------------------------------------
// TimesStore — per-process time registry
// ---------------------------------------------------------------------------

/// Maximum tracked processes.
const MAX_PROCS: usize = 256;

/// Process time registry.
pub struct TimesStore {
    records: [ProcessTimeRecord; MAX_PROCS],
}

impl TimesStore {
    /// Create an empty store.
    pub const fn new() -> Self {
        Self {
            records: [const {
                ProcessTimeRecord {
                    pid: 0,
                    utime_ns: 0,
                    stime_ns: 0,
                    cutime_ns: 0,
                    cstime_ns: 0,
                    active: false,
                }
            }; MAX_PROCS],
        }
    }

    /// Look up a record.
    pub fn get(&self, pid: u64) -> Option<&ProcessTimeRecord> {
        self.records.iter().find(|r| r.active && r.pid == pid)
    }

    /// Get or create a record for `pid`.
    pub fn get_or_create_mut(&mut self, pid: u64) -> Result<&mut ProcessTimeRecord> {
        let existing = self.records.iter().position(|r| r.active && r.pid == pid);
        if let Some(idx) = existing {
            return Ok(&mut self.records[idx]);
        }
        let slot = self
            .records
            .iter()
            .position(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;
        self.records[slot] = ProcessTimeRecord {
            pid,
            active: true,
            ..Default::default()
        };
        Ok(&mut self.records[slot])
    }

    /// Accumulate user-time increment.
    pub fn add_utime(&mut self, pid: u64, ns: u64) -> Result<()> {
        let rec = self.get_or_create_mut(pid)?;
        rec.utime_ns = rec.utime_ns.saturating_add(ns);
        Ok(())
    }

    /// Accumulate system-time increment.
    pub fn add_stime(&mut self, pid: u64, ns: u64) -> Result<()> {
        let rec = self.get_or_create_mut(pid)?;
        rec.stime_ns = rec.stime_ns.saturating_add(ns);
        Ok(())
    }

    /// Accumulate a reaped child's times into the parent's cumulative counters.
    pub fn add_child_times(
        &mut self,
        parent_pid: u64,
        child_utime_ns: u64,
        child_stime_ns: u64,
    ) -> Result<()> {
        let rec = self.get_or_create_mut(parent_pid)?;
        rec.cutime_ns = rec.cutime_ns.saturating_add(child_utime_ns);
        rec.cstime_ns = rec.cstime_ns.saturating_add(child_stime_ns);
        Ok(())
    }
}

impl Default for TimesStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ns_to_ticks / ticks_to_ns — conversion helpers
// ---------------------------------------------------------------------------

/// Convert nanoseconds to clock ticks.
pub const fn ns_to_ticks(ns: u64) -> u64 {
    ns / NS_PER_TICK
}

/// Convert clock ticks to nanoseconds.
pub const fn ticks_to_ns(ticks: u64) -> u64 {
    ticks * NS_PER_TICK
}

// ---------------------------------------------------------------------------
// sys_times — entry point
// ---------------------------------------------------------------------------

/// Handler for `times(2)`.
///
/// Returns the `Tms` for process `pid` and the elapsed wall-clock ticks.
///
/// # Arguments
///
/// * `store`          — Process time registry.
/// * `pid`            — Calling process PID.
/// * `elapsed_ticks`  — Monotonic wall-clock tick count since boot.
///
/// # Returns
///
/// `(Tms, elapsed_ticks)` — the process times and elapsed system time.
///
/// On Linux `times()` returns the elapsed real time in clock ticks since an
/// arbitrary point in the past (boot time).
///
/// # Errors
///
/// Currently infallible but returns `Result` for API consistency.
pub fn sys_times(store: &TimesStore, pid: u64, elapsed_ticks: i64) -> Result<(Tms, i64)> {
    let tms = store.get(pid).map(|r| r.to_tms()).unwrap_or_default();
    Ok((tms, elapsed_ticks))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tms_from_ns() {
        // 1.5 seconds user, 0.1 seconds system.
        let tms = Tms::from_ns(1_500_000_000, 100_000_000, 0, 0);
        assert_eq!(tms.tms_utime, 150);
        assert_eq!(tms.tms_stime, 10);
    }

    #[test]
    fn ns_to_ticks_roundtrip() {
        assert_eq!(ns_to_ticks(1_000_000_000), 100);
        assert_eq!(ticks_to_ns(100), 1_000_000_000);
    }

    #[test]
    fn sys_times_no_record() {
        let store = TimesStore::new();
        let (tms, _) = sys_times(&store, 99, 1000).unwrap();
        assert_eq!(tms, Tms::default());
    }

    #[test]
    fn sys_times_with_record() {
        let mut store = TimesStore::new();
        store.add_utime(1, 2_000_000_000).unwrap(); // 2 s user.
        store.add_stime(1, 500_000_000).unwrap(); // 0.5 s sys.
        let (tms, _) = sys_times(&store, 1, 0).unwrap();
        assert_eq!(tms.tms_utime, 200);
        assert_eq!(tms.tms_stime, 50);
    }

    #[test]
    fn child_times_accumulate() {
        let mut store = TimesStore::new();
        store
            .add_child_times(1, 1_000_000_000, 200_000_000)
            .unwrap();
        store.add_child_times(1, 500_000_000, 100_000_000).unwrap();
        let (tms, _) = sys_times(&store, 1, 0).unwrap();
        assert_eq!(tms.tms_cutime, 150); // (1.5 s → 150 ticks)
        assert_eq!(tms.tms_cstime, 30); // (0.3 s → 30 ticks)
    }
}
