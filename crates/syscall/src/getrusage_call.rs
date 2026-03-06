// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getrusage(2)` syscall handler.
//!
//! Returns resource usage statistics for the calling process, its children, or
//! the calling thread.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `getrusage()` specification.  Key behaviours:
//! - `RUSAGE_SELF`     — statistics for the calling process.
//! - `RUSAGE_CHILDREN` — statistics for terminated and waited-for children.
//! - `RUSAGE_THREAD`   — statistics for the calling thread (Linux extension).
//! - `EINVAL` for unknown `who` values.
//! - Field `ru_maxrss` is in kilobytes on Linux.
//! - Voluntary/involuntary context switches in `ru_nvcsw`/`ru_nivcsw`.
//!
//! # References
//!
//! - POSIX.1-2024: `getrusage()`
//! - Linux man pages: `getrusage(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Who constants
// ---------------------------------------------------------------------------

/// Report for the calling process.
pub const RUSAGE_SELF: i32 = 0;
/// Report for waited-for children.
pub const RUSAGE_CHILDREN: i32 = -1;
/// Report for the calling thread (Linux extension).
pub const RUSAGE_THREAD: i32 = 1;

// ---------------------------------------------------------------------------
// Timeval
// ---------------------------------------------------------------------------

/// POSIX `struct timeval` (seconds + microseconds).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timeval {
    /// Seconds.
    pub tv_sec: i64,
    /// Microseconds (0–999999).
    pub tv_usec: i64,
}

impl Timeval {
    /// Construct from microseconds total.
    pub const fn from_usec(usec: u64) -> Self {
        Self {
            tv_sec: (usec / 1_000_000) as i64,
            tv_usec: (usec % 1_000_000) as i64,
        }
    }

    /// Add two `Timeval`s, carrying microseconds into seconds.
    pub fn saturating_add(self, other: Self) -> Self {
        let usec = self.tv_usec + other.tv_usec;
        let carry = usec / 1_000_000;
        Self {
            tv_sec: self
                .tv_sec
                .saturating_add(other.tv_sec)
                .saturating_add(carry),
            tv_usec: usec % 1_000_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Rusage struct
// ---------------------------------------------------------------------------

/// POSIX `struct rusage` — resource usage statistics.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rusage {
    /// User CPU time used.
    pub ru_utime: Timeval,
    /// System CPU time used.
    pub ru_stime: Timeval,
    /// Maximum resident set size (kilobytes).
    pub ru_maxrss: i64,
    /// Integral shared text memory size (unused).
    pub ru_ixrss: i64,
    /// Integral unshared data size (unused).
    pub ru_idrss: i64,
    /// Integral unshared stack size (unused).
    pub ru_isrss: i64,
    /// Page reclaims (soft page faults).
    pub ru_minflt: i64,
    /// Page faults (hard page faults).
    pub ru_majflt: i64,
    /// Number of times swapped out.
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

// ---------------------------------------------------------------------------
// Task statistics (kernel-side)
// ---------------------------------------------------------------------------

/// Per-task resource accounting data maintained by the scheduler.
#[derive(Debug, Clone, Copy, Default)]
pub struct TaskStats {
    /// User CPU time in microseconds.
    pub utime_usec: u64,
    /// System CPU time in microseconds.
    pub stime_usec: u64,
    /// Peak RSS in kilobytes.
    pub maxrss_kb: i64,
    /// Minor faults.
    pub minflt: i64,
    /// Major faults.
    pub majflt: i64,
    /// Block reads.
    pub inblock: i64,
    /// Block writes.
    pub oublock: i64,
    /// Voluntary context switches.
    pub nvcsw: i64,
    /// Involuntary context switches.
    pub nivcsw: i64,
}

impl TaskStats {
    /// Accumulate another `TaskStats` into `self`.
    pub fn accumulate(&mut self, other: &Self) {
        self.utime_usec = self.utime_usec.saturating_add(other.utime_usec);
        self.stime_usec = self.stime_usec.saturating_add(other.stime_usec);
        self.maxrss_kb = self.maxrss_kb.max(other.maxrss_kb);
        self.minflt = self.minflt.saturating_add(other.minflt);
        self.majflt = self.majflt.saturating_add(other.majflt);
        self.inblock = self.inblock.saturating_add(other.inblock);
        self.oublock = self.oublock.saturating_add(other.oublock);
        self.nvcsw = self.nvcsw.saturating_add(other.nvcsw);
        self.nivcsw = self.nivcsw.saturating_add(other.nivcsw);
    }
}

/// Convert [`TaskStats`] to [`Rusage`].
fn stats_to_rusage(stats: &TaskStats) -> Rusage {
    Rusage {
        ru_utime: Timeval::from_usec(stats.utime_usec),
        ru_stime: Timeval::from_usec(stats.stime_usec),
        ru_maxrss: stats.maxrss_kb,
        ru_minflt: stats.minflt,
        ru_majflt: stats.majflt,
        ru_inblock: stats.inblock,
        ru_oublock: stats.oublock,
        ru_nvcsw: stats.nvcsw,
        ru_nivcsw: stats.nivcsw,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `getrusage(2)`.
///
/// # Arguments
///
/// * `who`           — `RUSAGE_SELF`, `RUSAGE_CHILDREN`, or `RUSAGE_THREAD`.
/// * `self_stats`    — Current process/thread statistics.
/// * `children_stats`— Accumulated stats of terminated waited-for children.
///
/// # Errors
///
/// | `Error`    | Condition                            |
/// |------------|--------------------------------------|
/// | `InvalidArg` | Unknown `who` value (`EINVAL`)     |
pub fn do_getrusage(
    who: i32,
    self_stats: &TaskStats,
    children_stats: &TaskStats,
) -> Result<Rusage> {
    match who {
        RUSAGE_SELF | RUSAGE_THREAD => Ok(stats_to_rusage(self_stats)),
        RUSAGE_CHILDREN => Ok(stats_to_rusage(children_stats)),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn self_stats() -> TaskStats {
        TaskStats {
            utime_usec: 1_500_000,
            stime_usec: 250_000,
            maxrss_kb: 8192,
            minflt: 100,
            majflt: 2,
            nvcsw: 50,
            nivcsw: 10,
            ..Default::default()
        }
    }

    fn child_stats() -> TaskStats {
        TaskStats {
            utime_usec: 500_000,
            stime_usec: 100_000,
            maxrss_kb: 4096,
            ..Default::default()
        }
    }

    #[test]
    fn rusage_self() {
        let r = do_getrusage(RUSAGE_SELF, &self_stats(), &child_stats()).unwrap();
        assert_eq!(r.ru_utime.tv_sec, 1);
        assert_eq!(r.ru_utime.tv_usec, 500_000);
        assert_eq!(r.ru_stime.tv_sec, 0);
        assert_eq!(r.ru_stime.tv_usec, 250_000);
        assert_eq!(r.ru_maxrss, 8192);
    }

    #[test]
    fn rusage_children() {
        let r = do_getrusage(RUSAGE_CHILDREN, &self_stats(), &child_stats()).unwrap();
        assert_eq!(r.ru_utime.tv_sec, 0);
        assert_eq!(r.ru_utime.tv_usec, 500_000);
    }

    #[test]
    fn rusage_thread() {
        // RUSAGE_THREAD returns same as RUSAGE_SELF in this simplified model.
        let r = do_getrusage(RUSAGE_THREAD, &self_stats(), &child_stats()).unwrap();
        assert_eq!(r.ru_maxrss, 8192);
    }

    #[test]
    fn invalid_who() {
        assert_eq!(
            do_getrusage(99, &self_stats(), &child_stats()),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn timeval_from_usec() {
        let t = Timeval::from_usec(2_500_000);
        assert_eq!(t.tv_sec, 2);
        assert_eq!(t.tv_usec, 500_000);
    }
}
