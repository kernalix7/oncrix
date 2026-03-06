// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `nanosleep(2)` syscall handler.
//!
//! Suspends execution of the calling thread for at least the duration
//! specified in `req`.  If interrupted by a signal, the remaining time
//! is written to `rem`.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `nanosleep()` specification.  Key behaviours:
//! - `EINVAL` if `req->tv_nsec` is not in `[0, 999_999_999]`.
//! - `EINTR` if a signal interrupts the sleep; `rem` receives the
//!   unslept portion.
//! - A zero-duration request (`{0, 0}`) is valid and returns immediately.
//!
//! # References
//!
//! - POSIX.1-2024: `nanosleep()`
//! - Linux man pages: `nanosleep(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Nanoseconds per second.
pub const NANOS_PER_SEC: i64 = 1_000_000_000;

// ---------------------------------------------------------------------------
// Timespec
// ---------------------------------------------------------------------------

/// POSIX `struct timespec`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    /// Whole seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0–999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Construct a new `Timespec`.
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }

    /// Returns `true` if the nanoseconds field is in range.
    pub fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < NANOS_PER_SEC
    }

    /// Convert to total nanoseconds.  Returns `None` on overflow.
    pub fn to_nanos(&self) -> Option<i64> {
        self.tv_sec
            .checked_mul(NANOS_PER_SEC)
            .and_then(|s| s.checked_add(self.tv_nsec))
    }

    /// Subtract `elapsed_ns` from this duration; saturates at zero.
    pub fn subtract_nanos(&self, elapsed_ns: i64) -> Self {
        let total = self.to_nanos().unwrap_or(i64::MAX);
        let remaining = (total - elapsed_ns).max(0);
        Self::new(remaining / NANOS_PER_SEC, remaining % NANOS_PER_SEC)
    }
}

// ---------------------------------------------------------------------------
// Sleep outcome
// ---------------------------------------------------------------------------

/// Outcome of a `nanosleep` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleepOutcome {
    /// Sleep completed normally.
    Completed,
    /// Sleep was interrupted by a signal; `remaining` is unslept time.
    Interrupted { remaining: Timespec },
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `nanosleep(2)`.
///
/// # Arguments
///
/// * `req`          — Requested sleep duration.
/// * `elapsed_ns`   — Nanoseconds that actually elapsed before return
///                    (may be less than requested if interrupted).
/// * `interrupted`  — Whether a signal interrupted the sleep.
///
/// # Errors
///
/// | `Error`         | Condition                              |
/// |-----------------|----------------------------------------|
/// | `InvalidArgument` | `req.tv_nsec` out of range           |
pub fn do_nanosleep(req: Timespec, elapsed_ns: i64, interrupted: bool) -> Result<SleepOutcome> {
    if !req.is_valid() {
        return Err(Error::InvalidArgument);
    }

    if interrupted {
        let remaining = req.subtract_nanos(elapsed_ns);
        return Ok(SleepOutcome::Interrupted { remaining });
    }

    Ok(SleepOutcome::Completed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_ok() {
        let req = Timespec::new(0, 500_000_000);
        assert_eq!(
            do_nanosleep(req, 500_000_000, false).unwrap(),
            SleepOutcome::Completed
        );
    }

    #[test]
    fn sleep_interrupted() {
        let req = Timespec::new(1, 0);
        let out = do_nanosleep(req, 400_000_000, true).unwrap();
        if let SleepOutcome::Interrupted { remaining } = out {
            assert_eq!(remaining.tv_sec, 0);
            assert_eq!(remaining.tv_nsec, 600_000_000);
        } else {
            panic!("expected Interrupted");
        }
    }

    #[test]
    fn invalid_nsec() {
        let req = Timespec::new(0, 2_000_000_000);
        assert_eq!(do_nanosleep(req, 0, false), Err(Error::InvalidArgument));
    }

    #[test]
    fn zero_duration_ok() {
        let req = Timespec::new(0, 0);
        assert_eq!(
            do_nanosleep(req, 0, false).unwrap(),
            SleepOutcome::Completed
        );
    }
}
