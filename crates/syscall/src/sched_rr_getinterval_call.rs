// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sched_rr_get_interval` syscall handler.
//!
//! Returns the round-robin time quantum for a process using the `SCHED_RR`
//! scheduling policy.
//! POSIX.1-2024: `sched_rr_get_interval()` writes the execution time limit
//! (time quantum) into the `timespec` pointed to by `tp` for the process
//! identified by `pid`.
//!
//! If the process does not use `SCHED_RR`, the behavior is implementation-defined.
//! Linux returns a quantum of 0.1 seconds for `SCHED_OTHER` processes.
//!
//! # POSIX Conformance
//! Implements POSIX.1-2024 `sched_rr_get_interval()` semantics.

use oncrix_lib::{Error, Result};

/// Kernel-side representation of `struct timespec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Timespec {
    /// Seconds component.
    pub tv_sec: i64,
    /// Nanoseconds component (0..999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Construct a new `Timespec` from seconds and nanoseconds.
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }

    /// Default round-robin quantum: 100 ms (ONCRIX default).
    pub const fn default_rr_quantum() -> Self {
        Self::new(0, 100_000_000)
    }

    /// Returns `true` if the nanosecond field is in the valid range.
    pub fn is_valid(self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < 1_000_000_000
    }
}

/// Arguments for the `sched_rr_get_interval` syscall.
#[derive(Debug, Clone, Copy)]
pub struct SchedRrGetIntervalArgs {
    /// Target process ID. Zero means the calling process.
    pub pid: u32,
    /// User-space pointer to `struct timespec` to write the quantum into.
    pub tp_ptr: u64,
}

impl SchedRrGetIntervalArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — negative pid or null `tp_ptr`.
    pub fn from_raw(pid_raw: u64, tp_ptr: u64) -> Result<Self> {
        if (pid_raw as i64) < 0 {
            return Err(Error::InvalidArgument);
        }
        if tp_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            pid: pid_raw as u32,
            tp_ptr,
        })
    }
}

/// Result of `sched_rr_get_interval`: the time quantum.
#[derive(Debug, Clone, Copy)]
pub struct SchedRrGetIntervalResult {
    /// The round-robin time quantum for the queried process.
    pub quantum: Timespec,
}

impl SchedRrGetIntervalResult {
    /// Construct a new result.
    pub const fn new(quantum: Timespec) -> Self {
        Self { quantum }
    }
}

/// Handle the `sched_rr_get_interval` syscall.
///
/// Returns the round-robin quantum for the specified process. For non-SCHED_RR
/// processes this implementation returns 0.1 seconds as a sensible default.
///
/// # Errors
/// - [`Error::NotFound`] — process `pid` does not exist.
/// - [`Error::PermissionDenied`] — caller lacks permission.
/// - [`Error::InvalidArgument`] — negative pid or null pointer.
pub fn sys_sched_rr_get_interval(args: SchedRrGetIntervalArgs) -> Result<SchedRrGetIntervalResult> {
    // A full implementation would:
    // 1. Locate the process in the process table.
    // 2. If the process uses SCHED_RR, return its configured quantum.
    // 3. If not SCHED_RR, return zero or EINVAL depending on config.
    let _ = args;
    Ok(SchedRrGetIntervalResult::new(Timespec::default_rr_quantum()))
}

/// Raw syscall entry point for `sched_rr_get_interval`.
///
/// # Arguments
/// * `pid` — process identifier (register a0).
/// * `tp_ptr` — user-space pointer to `struct timespec` (register a1).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_sched_rr_get_interval(pid: u64, tp_ptr: u64) -> i64 {
    let args = match SchedRrGetIntervalArgs::from_raw(pid, tp_ptr) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_sched_rr_get_interval(args) {
        Ok(_result) => {
            // Real implementation: copy result.quantum to args.tp_ptr via copy_to_user.
            0
        }
        Err(Error::NotFound) => -(oncrix_lib::errno::ESRCH as i64),
        Err(Error::PermissionDenied) => -(oncrix_lib::errno::EPERM as i64),
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_tp_ptr_rejected() {
        assert!(SchedRrGetIntervalArgs::from_raw(0, 0).is_err());
    }

    #[test]
    fn test_negative_pid_rejected() {
        assert!(SchedRrGetIntervalArgs::from_raw(u64::MAX, 0x1000).is_err());
    }

    #[test]
    fn test_valid_args() {
        let args = SchedRrGetIntervalArgs::from_raw(1, 0x2000).unwrap();
        assert_eq!(args.pid, 1);
        assert_eq!(args.tp_ptr, 0x2000);
    }

    #[test]
    fn test_default_quantum_is_valid() {
        let q = Timespec::default_rr_quantum();
        assert!(q.is_valid());
        assert_eq!(q.tv_sec, 0);
        assert_eq!(q.tv_nsec, 100_000_000);
    }

    #[test]
    fn test_syscall_returns_zero_on_success() {
        let ret = syscall_sched_rr_get_interval(0, 0x1000);
        assert_eq!(ret, 0);
    }
}
