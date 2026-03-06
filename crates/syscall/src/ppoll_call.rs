// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `poll(2)`, `ppoll(2)` syscall handlers.
//!
//! Wait for events on a set of file descriptors.
//!
//! # Key behaviours
//!
//! - `poll` monitors up to `RLIMIT_NOFILE` fds.
//! - `ppoll` adds an atomically applied signal mask and a `timespec` timeout.
//! - `POLLIN`, `POLLOUT`, `POLLERR`, `POLLHUP`, `POLLNVAL` are the main event
//!   flags.
//! - Returns the number of fds with non-zero `revents`, or 0 on timeout.
//!
//! # References
//!
//! - POSIX.1-2024: `poll()`
//! - Linux man pages: `poll(2)`, `ppoll(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Event flags
// ---------------------------------------------------------------------------

/// Data available to read.
pub const POLLIN: u16 = 0x0001;
/// Writing will not block.
pub const POLLOUT: u16 = 0x0004;
/// Error condition.
pub const POLLERR: u16 = 0x0008;
/// Hang up (peer closed).
pub const POLLHUP: u16 = 0x0010;
/// Invalid file descriptor.
pub const POLLNVAL: u16 = 0x0020;
/// Priority data available.
pub const POLLPRI: u16 = 0x0002;
/// Normal data available (alias).
pub const POLLRDNORM: u16 = 0x0040;
/// Priority data writable.
pub const POLLWRNORM: u16 = 0x0100;

/// Maximum poll fds per call.
pub const POLL_MAX_FDS: usize = 1024;

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

/// `struct pollfd`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Pollfd {
    /// File descriptor.
    pub fd: i32,
    /// Requested events.
    pub events: u16,
    /// Returned events (filled by kernel).
    pub revents: u16,
}

/// `struct timespec` for ppoll timeout.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds.
    pub tv_nsec: i64,
}

impl Timespec {
    /// Convert to nanoseconds (saturating).
    pub fn to_nanos(&self) -> u64 {
        (self.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(self.tv_nsec as u64)
    }

    /// Returns `true` if the timespec values are in range.
    pub fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < 1_000_000_000
    }
}

// ---------------------------------------------------------------------------
// Fd readiness (simulated)
// ---------------------------------------------------------------------------

/// Simulated readiness for a single fd.
#[derive(Debug, Clone, Copy)]
pub struct FdReadiness {
    /// File descriptor.
    pub fd: i32,
    /// Ready event flags.
    pub ready: u16,
    /// Whether the fd is valid.
    pub valid: bool,
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `poll(2)` / `ppoll(2)`.
///
/// Fills `revents` for each `Pollfd` entry and returns the count of fds
/// with non-zero `revents`.
///
/// `timeout_ms` < 0 means infinite; 0 means return immediately.
///
/// # Errors
///
/// | `Error`           | Condition                          |
/// |-------------------|------------------------------------|
/// | `InvalidArgument` | `nfds` exceeds `POLL_MAX_FDS`      |
pub fn do_poll(fds: &mut [Pollfd], ready_set: &[FdReadiness], timeout_ms: i32) -> Result<usize> {
    if fds.len() > POLL_MAX_FDS {
        return Err(Error::InvalidArgument);
    }
    let mut count = 0usize;
    for pfd in fds.iter_mut() {
        pfd.revents = 0;
        if pfd.fd < 0 {
            continue;
        }
        // Find readiness.
        let readiness = ready_set.iter().find(|r| r.fd == pfd.fd);
        match readiness {
            None => {
                // fd not in ready set — no events.
            }
            Some(r) if !r.valid => {
                pfd.revents = POLLNVAL;
                count += 1;
            }
            Some(r) => {
                let triggered = r.ready & (pfd.events | POLLERR | POLLHUP);
                if triggered != 0 {
                    pfd.revents = triggered;
                    count += 1;
                }
            }
        }
    }
    // For timeout == 0 with no events, return 0 (caller handles blocking).
    let _ = timeout_ms;
    Ok(count)
}

/// Handler for `ppoll(2)`.
///
/// Like `do_poll` but validates the `timespec` and ignores `sigmask` at this
/// layer (signal mask management is done by the kernel before calling here).
///
/// # Errors
///
/// | `Error`           | Condition                          |
/// |-------------------|------------------------------------|
/// | `InvalidArgument` | Invalid `timeout` or `nfds` too large |
pub fn do_ppoll(
    fds: &mut [Pollfd],
    ready_set: &[FdReadiness],
    timeout: Option<&Timespec>,
    timeout_ms: i32,
) -> Result<usize> {
    if let Some(ts) = timeout {
        if !ts.is_valid() {
            return Err(Error::InvalidArgument);
        }
    }
    do_poll(fds, ready_set, timeout_ms)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_ready_fd() {
        let mut fds = [Pollfd {
            fd: 3,
            events: POLLIN,
            revents: 0,
        }];
        let ready = [FdReadiness {
            fd: 3,
            ready: POLLIN,
            valid: true,
        }];
        let n = do_poll(&mut fds, &ready, -1).unwrap();
        assert_eq!(n, 1);
        assert_eq!(fds[0].revents, POLLIN);
    }

    #[test]
    fn poll_negative_fd_skipped() {
        let mut fds = [Pollfd {
            fd: -1,
            events: POLLIN,
            revents: 0,
        }];
        let n = do_poll(&mut fds, &[], -1).unwrap();
        assert_eq!(n, 0);
        assert_eq!(fds[0].revents, 0);
    }

    #[test]
    fn poll_invalid_fd_pollnval() {
        let mut fds = [Pollfd {
            fd: 9,
            events: POLLIN,
            revents: 0,
        }];
        let ready = [FdReadiness {
            fd: 9,
            ready: 0,
            valid: false,
        }];
        let n = do_poll(&mut fds, &ready, 0).unwrap();
        assert_eq!(n, 1);
        assert_eq!(fds[0].revents, POLLNVAL);
    }

    #[test]
    fn ppoll_invalid_timespec_fails() {
        let mut fds = [Pollfd {
            fd: 1,
            events: POLLIN,
            revents: 0,
        }];
        let ts = Timespec {
            tv_sec: 1,
            tv_nsec: 2_000_000_000,
        };
        assert_eq!(
            do_ppoll(&mut fds, &[], Some(&ts), 0),
            Err(Error::InvalidArgument)
        );
    }
}
