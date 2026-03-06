// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended `getrusage(2)` and resource accounting helpers.
//!
//! Provides the full `struct rusage` definition, who-constants, and
//! aggregation helpers for collecting resource usage across threads and
//! children.  The basic `getrusage_call.rs` provides the entry-point shim;
//! this module provides the data model and aggregation logic.
//!
//! # Syscall signature
//!
//! ```text
//! int getrusage(int who, struct rusage *usage);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §getrusage — `<sys/resource.h>`.
//!
//! # References
//!
//! - Linux: `kernel/sys.c` `sys_getrusage()`, `kernel/resource.c`
//! - `getrusage(2)` man page
//! - `include/uapi/linux/resource.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Who constants
// ---------------------------------------------------------------------------

/// Report resource usage for the calling process.
pub const RUSAGE_SELF: i32 = 0;
/// Report resource usage for all waited-for children.
pub const RUSAGE_CHILDREN: i32 = -1;
/// Report resource usage for the calling thread.
pub const RUSAGE_THREAD: i32 = 1;

// ---------------------------------------------------------------------------
// Timeval — seconds + microseconds
// ---------------------------------------------------------------------------

/// `struct timeval` — seconds + microseconds.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timeval {
    /// Seconds.
    pub tv_sec: i64,
    /// Microseconds (0..999_999).
    pub tv_usec: i64,
}

impl Timeval {
    /// Add two timevals.
    pub const fn add(self, other: Self) -> Self {
        let usec = self.tv_usec + other.tv_usec;
        let carry = usec / 1_000_000;
        Self {
            tv_sec: self.tv_sec + other.tv_sec + carry,
            tv_usec: usec % 1_000_000,
        }
    }

    /// Convert from microseconds.
    pub const fn from_us(us: u64) -> Self {
        Self {
            tv_sec: (us / 1_000_000) as i64,
            tv_usec: (us % 1_000_000) as i64,
        }
    }

    /// Convert to total microseconds.
    pub const fn to_us(&self) -> u64 {
        self.tv_sec as u64 * 1_000_000 + self.tv_usec as u64
    }
}

// ---------------------------------------------------------------------------
// Rusage — full POSIX struct rusage
// ---------------------------------------------------------------------------

/// Full POSIX `struct rusage`.
///
/// Contains the complete set of resource usage counters.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rusage {
    /// User time used.
    pub ru_utime: Timeval,
    /// System time used.
    pub ru_stime: Timeval,
    /// Maximum resident set size in kilobytes.
    pub ru_maxrss: i64,
    /// Integral shared memory size.
    pub ru_ixrss: i64,
    /// Integral unshared data size.
    pub ru_idrss: i64,
    /// Integral unshared stack size.
    pub ru_isrss: i64,
    /// Page reclaims (soft faults).
    pub ru_minflt: i64,
    /// Page faults (hard faults).
    pub ru_majflt: i64,
    /// Swaps.
    pub ru_nswap: i64,
    /// Block input operations.
    pub ru_inblock: i64,
    /// Block output operations.
    pub ru_oublock: i64,
    /// IPC messages sent.
    pub ru_msgsnd: i64,
    /// IPC messages received.
    pub ru_msgrcv: i64,
    /// Signals received.
    pub ru_nsignals: i64,
    /// Voluntary context switches.
    pub ru_nvcsw: i64,
    /// Involuntary context switches.
    pub ru_nivcsw: i64,
}

impl Rusage {
    /// Accumulate another `Rusage` into this one (add all fields).
    pub fn accumulate(&mut self, other: &Self) {
        self.ru_utime = self.ru_utime.add(other.ru_utime);
        self.ru_stime = self.ru_stime.add(other.ru_stime);
        if other.ru_maxrss > self.ru_maxrss {
            self.ru_maxrss = other.ru_maxrss;
        }
        self.ru_minflt += other.ru_minflt;
        self.ru_majflt += other.ru_majflt;
        self.ru_nswap += other.ru_nswap;
        self.ru_inblock += other.ru_inblock;
        self.ru_oublock += other.ru_oublock;
        self.ru_msgsnd += other.ru_msgsnd;
        self.ru_msgrcv += other.ru_msgrcv;
        self.ru_nsignals += other.ru_nsignals;
        self.ru_nvcsw += other.ru_nvcsw;
        self.ru_nivcsw += other.ru_nivcsw;
    }
}

// ---------------------------------------------------------------------------
// ProcessRusageStore — resource usage registry
// ---------------------------------------------------------------------------

/// Maximum tracked processes.
const MAX_PROCS: usize = 256;

/// Per-process resource usage record.
#[derive(Clone, Copy, Default)]
struct RusageRecord {
    pid: u64,
    /// `RUSAGE_SELF` accounting.
    self_usage: Rusage,
    /// `RUSAGE_CHILDREN` — reaped children's cumulative usage.
    children_usage: Rusage,
    /// `RUSAGE_THREAD` — current thread's usage (same as self for single-thread).
    thread_usage: Rusage,
    active: bool,
}

/// Registry of per-process resource usage.
pub struct ProcessRusageStore {
    records: [RusageRecord; MAX_PROCS],
}

impl ProcessRusageStore {
    /// Create an empty store.
    pub const fn new() -> Self {
        Self {
            records: [const {
                RusageRecord {
                    pid: 0,
                    self_usage: Rusage {
                        ru_utime: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                        ru_stime: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                        ru_maxrss: 0,
                        ru_ixrss: 0,
                        ru_idrss: 0,
                        ru_isrss: 0,
                        ru_minflt: 0,
                        ru_majflt: 0,
                        ru_nswap: 0,
                        ru_inblock: 0,
                        ru_oublock: 0,
                        ru_msgsnd: 0,
                        ru_msgrcv: 0,
                        ru_nsignals: 0,
                        ru_nvcsw: 0,
                        ru_nivcsw: 0,
                    },
                    children_usage: Rusage {
                        ru_utime: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                        ru_stime: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                        ru_maxrss: 0,
                        ru_ixrss: 0,
                        ru_idrss: 0,
                        ru_isrss: 0,
                        ru_minflt: 0,
                        ru_majflt: 0,
                        ru_nswap: 0,
                        ru_inblock: 0,
                        ru_oublock: 0,
                        ru_msgsnd: 0,
                        ru_msgrcv: 0,
                        ru_nsignals: 0,
                        ru_nvcsw: 0,
                        ru_nivcsw: 0,
                    },
                    thread_usage: Rusage {
                        ru_utime: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                        ru_stime: Timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                        ru_maxrss: 0,
                        ru_ixrss: 0,
                        ru_idrss: 0,
                        ru_isrss: 0,
                        ru_minflt: 0,
                        ru_majflt: 0,
                        ru_nswap: 0,
                        ru_inblock: 0,
                        ru_oublock: 0,
                        ru_msgsnd: 0,
                        ru_msgrcv: 0,
                        ru_nsignals: 0,
                        ru_nvcsw: 0,
                        ru_nivcsw: 0,
                    },
                    active: false,
                }
            }; MAX_PROCS],
        }
    }

    /// Get or create the record for `pid`.
    fn get_or_create_mut(&mut self, pid: u64) -> Result<&mut RusageRecord> {
        let existing = self.records.iter().position(|r| r.active && r.pid == pid);
        if let Some(idx) = existing {
            return Ok(&mut self.records[idx]);
        }
        let slot = self
            .records
            .iter()
            .position(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;
        self.records[slot] = RusageRecord {
            pid,
            active: true,
            ..Default::default()
        };
        Ok(&mut self.records[slot])
    }

    /// Look up the record for `pid`.
    fn get(&self, pid: u64) -> Option<&RusageRecord> {
        self.records.iter().find(|r| r.active && r.pid == pid)
    }

    /// Update the self-usage for `pid`.
    pub fn update_self(&mut self, pid: u64, usage: &Rusage) -> Result<()> {
        let rec = self.get_or_create_mut(pid)?;
        rec.self_usage.accumulate(usage);
        Ok(())
    }

    /// Add a reaped child's usage to `pid`'s children accumulator.
    pub fn add_child_usage(&mut self, pid: u64, child_usage: &Rusage) -> Result<()> {
        let rec = self.get_or_create_mut(pid)?;
        rec.children_usage.accumulate(child_usage);
        Ok(())
    }
}

impl Default for ProcessRusageStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_getrusage — entry point
// ---------------------------------------------------------------------------

/// Handler for `getrusage(2)`.
///
/// Returns the resource usage for the specified `who` target.
///
/// # Arguments
///
/// * `store`  — Resource usage registry.
/// * `pid`    — Calling process PID.
/// * `who`    — `RUSAGE_SELF`, `RUSAGE_CHILDREN`, or `RUSAGE_THREAD`.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — unrecognised `who`.
pub fn sys_getrusage(store: &ProcessRusageStore, pid: u64, who: i32) -> Result<Rusage> {
    match who {
        RUSAGE_SELF => Ok(store.get(pid).map(|r| r.self_usage).unwrap_or_default()),
        RUSAGE_CHILDREN => Ok(store.get(pid).map(|r| r.children_usage).unwrap_or_default()),
        RUSAGE_THREAD => Ok(store.get(pid).map(|r| r.thread_usage).unwrap_or_default()),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_usage(utime_us: u64, minflt: i64) -> Rusage {
        let mut r = Rusage::default();
        r.ru_utime = Timeval::from_us(utime_us);
        r.ru_minflt = minflt;
        r
    }

    #[test]
    fn get_self_default() {
        let store = ProcessRusageStore::new();
        let r = sys_getrusage(&store, 1, RUSAGE_SELF).unwrap();
        assert_eq!(r.ru_minflt, 0);
    }

    #[test]
    fn update_self() {
        let mut store = ProcessRusageStore::new();
        store.update_self(1, &simple_usage(1_000_000, 5)).unwrap();
        let r = sys_getrusage(&store, 1, RUSAGE_SELF).unwrap();
        assert_eq!(r.ru_minflt, 5);
        assert_eq!(r.ru_utime.tv_sec, 1);
    }

    #[test]
    fn accumulate_children() {
        let mut store = ProcessRusageStore::new();
        store
            .add_child_usage(1, &simple_usage(500_000, 10))
            .unwrap();
        store
            .add_child_usage(1, &simple_usage(500_000, 20))
            .unwrap();
        let r = sys_getrusage(&store, 1, RUSAGE_CHILDREN).unwrap();
        assert_eq!(r.ru_minflt, 30);
    }

    #[test]
    fn invalid_who() {
        let store = ProcessRusageStore::new();
        assert_eq!(sys_getrusage(&store, 1, 99), Err(Error::InvalidArgument));
    }

    #[test]
    fn timeval_add() {
        let a = Timeval {
            tv_sec: 1,
            tv_usec: 600_000,
        };
        let b = Timeval {
            tv_sec: 0,
            tv_usec: 500_000,
        };
        let s = a.add(b);
        assert_eq!(s.tv_sec, 2);
        assert_eq!(s.tv_usec, 100_000);
    }
}
