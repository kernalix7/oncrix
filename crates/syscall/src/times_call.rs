// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `times(2)` syscall handler.
//!
//! Returns process times — the user and system CPU time consumed by the
//! calling process and its children, measured in clock ticks.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `times()` specification.  Key behaviours:
//! - Returns a `TmsBuf` filled with `clock_t` tick values.
//! - Returns the elapsed real time since an arbitrary point in the past
//!   (usually system boot) as the syscall return value.
//! - `tms_cutime` and `tms_cstime` accumulate from waited-for children only.
//! - Clock tick rate: `CLK_TCK` (typically 100 Hz on Linux).
//! - On overflow of `clock_t`, values wrap.
//!
//! # References
//!
//! - POSIX.1-2024: `times()`
//! - Linux man pages: `times(2)`

use oncrix_lib::Result;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Kernel clock tick frequency (100 ticks/second on Linux x86_64).
pub const CLK_TCK: u64 = 100;

/// Nanoseconds per clock tick at `CLK_TCK = 100`.
pub const NSEC_PER_TICK: u64 = 1_000_000_000 / CLK_TCK;

// ---------------------------------------------------------------------------
// TmsBuf
// ---------------------------------------------------------------------------

/// Process times returned by `times(2)` (`struct tms`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TmsBuf {
    /// User CPU time of the calling process.
    pub tms_utime: i64,
    /// System CPU time of the calling process.
    pub tms_stime: i64,
    /// User CPU time of waited-for children.
    pub tms_cutime: i64,
    /// System CPU time of waited-for children.
    pub tms_cstime: i64,
}

// ---------------------------------------------------------------------------
// Process time data (kernel-side)
// ---------------------------------------------------------------------------

/// Kernel-side process time accounting data.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessTimes {
    /// User time in nanoseconds.
    pub utime_ns: u64,
    /// System time in nanoseconds.
    pub stime_ns: u64,
    /// Children user time in nanoseconds.
    pub cutime_ns: u64,
    /// Children system time in nanoseconds.
    pub cstime_ns: u64,
}

/// Convert nanoseconds to `clock_t` ticks at `CLK_TCK`.
pub const fn ns_to_ticks(ns: u64) -> i64 {
    (ns / NSEC_PER_TICK) as i64
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `times(2)`.
///
/// Fills `buf` with the current process times and returns the elapsed clock
/// ticks since boot.
///
/// # Arguments
///
/// * `proc_times`    — Current process/thread time accounting.
/// * `uptime_ns`     — System uptime in nanoseconds (for the return value).
///
/// # Errors
///
/// This function is infallible under normal operation.  `Err` is returned
/// only if `uptime_ns` conversion would produce a meaningless value (not
/// possible in practice).
pub fn do_times(proc_times: &ProcessTimes, uptime_ns: u64) -> Result<(TmsBuf, i64)> {
    let buf = TmsBuf {
        tms_utime: ns_to_ticks(proc_times.utime_ns),
        tms_stime: ns_to_ticks(proc_times.stime_ns),
        tms_cutime: ns_to_ticks(proc_times.cutime_ns),
        tms_cstime: ns_to_ticks(proc_times.cstime_ns),
    };
    let elapsed_ticks = ns_to_ticks(uptime_ns);
    Ok((buf, elapsed_ticks))
}

/// Accumulate child times into parent's `cutime`/`cstime` after `wait`.
///
/// Called when a child is reaped via `wait4`/`waitpid`.
pub fn accumulate_child_times(parent: &mut ProcessTimes, child: &ProcessTimes) {
    parent.cutime_ns = parent.cutime_ns.saturating_add(child.utime_ns);
    parent.cstime_ns = parent.cstime_ns.saturating_add(child.stime_ns);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_basic() {
        let pt = ProcessTimes {
            utime_ns: 1_500_000_000, // 1.5 s → 150 ticks
            stime_ns: 500_000_000,   // 0.5 s → 50 ticks
            cutime_ns: 200_000_000,  // 0.2 s → 20 ticks
            cstime_ns: 100_000_000,  // 0.1 s → 10 ticks
        };
        let uptime_ns = 60_000_000_000u64; // 60 s → 6000 ticks
        let (buf, elapsed) = do_times(&pt, uptime_ns).unwrap();
        assert_eq!(buf.tms_utime, 150);
        assert_eq!(buf.tms_stime, 50);
        assert_eq!(buf.tms_cutime, 20);
        assert_eq!(buf.tms_cstime, 10);
        assert_eq!(elapsed, 6000);
    }

    #[test]
    fn ns_to_ticks_rounding() {
        // 15 ms → 1 tick (100 ticks/s means 10 ms/tick; 15 ms rounds down to 1)
        assert_eq!(ns_to_ticks(15_000_000), 1);
        // 9 ms → 0 ticks
        assert_eq!(ns_to_ticks(9_000_000), 0);
    }

    #[test]
    fn accumulate_child() {
        let mut parent = ProcessTimes {
            utime_ns: 0,
            stime_ns: 0,
            cutime_ns: 0,
            cstime_ns: 0,
        };
        let child = ProcessTimes {
            utime_ns: 300_000_000,
            stime_ns: 100_000_000,
            ..Default::default()
        };
        accumulate_child_times(&mut parent, &child);
        assert_eq!(parent.cutime_ns, 300_000_000);
        assert_eq!(parent.cstime_ns, 100_000_000);
    }
}
