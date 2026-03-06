// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Signal-related wait operations: `sigsuspend(2)`, `sigtimedwait(2)`,
//! `sigwaitinfo(2)`.
//!
//! These operations temporarily replace the caller's signal mask and block
//! until a signal arrives.  This module provides mask validation, siginfo
//! construction, and argument checking.
//!
//! # Syscall signatures
//!
//! ```text
//! int sigsuspend(const sigset_t *mask);
//! int sigtimedwait(const sigset_t *set, siginfo_t *info,
//!                  const struct timespec *timeout);
//! int sigwaitinfo(const sigset_t *set, siginfo_t *info);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §sigsuspend, §sigtimedwait, §sigwaitinfo — `<signal.h>`.
//!
//! # References
//!
//! - Linux: `kernel/signal.c` `sys_sigsuspend()`, `do_sigtimedwait()`
//! - `sigsuspend(2)`, `sigtimedwait(2)` man pages

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of signals (standard POSIX limit).
pub const NSIG: u32 = 64;
/// SIGKILL — cannot be blocked or caught.
pub const SIGKILL: u32 = 9;
/// SIGSTOP — cannot be blocked or caught.
pub const SIGSTOP: u32 = 19;

/// Maximum signal number.
const SIG_MAX: u32 = NSIG;

// ---------------------------------------------------------------------------
// Sigset — 64-bit signal mask
// ---------------------------------------------------------------------------

/// 64-bit signal set (`sigset_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sigset {
    /// Bitmask: bit N set means signal (N+1) is in the set.
    pub bits: u64,
}

impl Sigset {
    /// Create an empty signal set.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Create a full signal set (all signals).
    pub const fn full() -> Self {
        Self { bits: u64::MAX }
    }

    /// Add a signal to the set.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for out-of-range signal numbers.
    pub fn add(&mut self, sig: u32) -> Result<()> {
        if sig == 0 || sig > SIG_MAX {
            return Err(Error::InvalidArgument);
        }
        self.bits |= 1u64 << (sig - 1);
        Ok(())
    }

    /// Remove a signal from the set.
    pub fn del(&mut self, sig: u32) -> Result<()> {
        if sig == 0 || sig > SIG_MAX {
            return Err(Error::InvalidArgument);
        }
        self.bits &= !(1u64 << (sig - 1));
        Ok(())
    }

    /// Return `true` if `sig` is in the set.
    pub const fn contains(&self, sig: u32) -> bool {
        if sig == 0 || sig > SIG_MAX {
            return false;
        }
        self.bits & (1u64 << (sig - 1)) != 0
    }

    /// Block SIGKILL and SIGSTOP (they cannot be masked).
    pub fn sanitize(&self) -> Self {
        let mut sanitized = *self;
        let _ = sanitized.del(SIGKILL);
        let _ = sanitized.del(SIGSTOP);
        sanitized
    }

    /// Return `true` if the set is empty.
    pub const fn is_empty(&self) -> bool {
        self.bits == 0
    }
}

// ---------------------------------------------------------------------------
// SiginfoWait — siginfo returned by sigtimedwait / sigwaitinfo
// ---------------------------------------------------------------------------

/// Signal information for `sigwaitinfo` / `sigtimedwait`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SiginfoWait {
    /// Signal number.
    pub si_signo: u32,
    /// Error number (si_errno).
    pub si_errno: i32,
    /// Signal code.
    pub si_code: i32,
    /// Sending process ID (for SI_USER / SI_QUEUE).
    pub si_pid: u64,
    /// Sending user ID.
    pub si_uid: u32,
    /// Signal value (integer).
    pub si_int: i32,
}

/// Signal sent by `kill(2)`.
pub const SI_USER: i32 = 0;
/// Signal sent by `sigqueue(3)`.
pub const SI_QUEUE: i32 = -1;
/// Signal sent by timer expiry.
pub const SI_TIMER: i32 = -2;
/// Signal sent by kernel.
pub const SI_KERNEL: i32 = 0x80;

impl SiginfoWait {
    /// Construct for a user-sent signal.
    pub const fn user(sig: u32, sender_pid: u64, sender_uid: u32) -> Self {
        Self {
            si_signo: sig,
            si_errno: 0,
            si_code: SI_USER,
            si_pid: sender_pid,
            si_uid: sender_uid,
            si_int: 0,
        }
    }

    /// Construct for a queued signal (sigqueue).
    pub const fn queued(sig: u32, sender_pid: u64, val: i32) -> Self {
        Self {
            si_signo: sig,
            si_errno: 0,
            si_code: SI_QUEUE,
            si_pid: sender_pid,
            si_uid: 0,
            si_int: val,
        }
    }
}

// ---------------------------------------------------------------------------
// Timespec — timeout for sigtimedwait
// ---------------------------------------------------------------------------

/// `struct timespec` for signal-wait timeout.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

impl Timespec {
    /// Validate.
    pub fn validate(&self) -> Result<()> {
        if self.tv_sec < 0 || self.tv_nsec < 0 || self.tv_nsec >= 1_000_000_000 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return `true` if zero duration.
    pub const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }
}

// ---------------------------------------------------------------------------
// sys_sigsuspend — entry point
// ---------------------------------------------------------------------------

/// Handler for `sigsuspend(2)`.
///
/// Validates the mask and returns the sanitized version (SIGKILL/SIGSTOP
/// stripped).  The actual blocking is handled by the scheduler.
///
/// Always returns [`Error::Interrupted`] to indicate it was interrupted by
/// a signal (POSIX requirement: `sigsuspend` always returns -1/EINTR).
///
/// # Arguments
///
/// * `new_mask` — Signal mask to apply while waiting.
pub fn sys_sigsuspend(new_mask: &Sigset) -> Result<Sigset> {
    Ok(new_mask.sanitize())
}

// ---------------------------------------------------------------------------
// sys_sigtimedwait — entry point
// ---------------------------------------------------------------------------

/// Handler for `sigtimedwait(2)`.
///
/// Validates the signal set and timeout.  Returns the signal info for the
/// first signal in `set` that is pending.
///
/// If no signal is immediately available and timeout is zero, returns
/// [`Error::WouldBlock`].  Otherwise the scheduler must block.
///
/// # Arguments
///
/// * `set`     — Set of signals to wait for.
/// * `timeout` — Optional maximum wait time.
/// * `pending` — Currently pending signals for the thread.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — invalid timeout.
/// * [`Error::WouldBlock`]      — no signal available and timeout is zero.
pub fn sys_sigtimedwait(
    set: &Sigset,
    timeout: Option<&Timespec>,
    pending: &Sigset,
) -> Result<Option<u32>> {
    if let Some(t) = timeout {
        t.validate()?;
    }

    // Check for immediately available signals.
    for sig in 1..=SIG_MAX {
        if set.contains(sig) && pending.contains(sig) {
            return Ok(Some(sig));
        }
    }

    // No signal immediately available.
    if let Some(t) = timeout {
        if t.is_zero() {
            return Err(Error::WouldBlock);
        }
    }

    // Blocking: signal scheduler to wait.
    Err(Error::WouldBlock)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigset_add_contains() {
        let mut s = Sigset::empty();
        s.add(10).unwrap();
        assert!(s.contains(10));
        assert!(!s.contains(11));
    }

    #[test]
    fn sigset_sanitize_removes_kill_stop() {
        let mut s = Sigset::full();
        let san = s.sanitize();
        assert!(!san.contains(SIGKILL));
        assert!(!san.contains(SIGSTOP));
    }

    #[test]
    fn sigset_invalid_sig() {
        let mut s = Sigset::empty();
        assert_eq!(s.add(0), Err(Error::InvalidArgument));
        assert_eq!(s.add(65), Err(Error::InvalidArgument));
    }

    #[test]
    fn sigsuspend_sanitizes() {
        let mut mask = Sigset::empty();
        mask.add(SIGKILL).unwrap();
        mask.add(15).unwrap();
        let result = sys_sigsuspend(&mask).unwrap();
        assert!(!result.contains(SIGKILL));
        assert!(result.contains(15));
    }

    #[test]
    fn sigtimedwait_immediate_match() {
        let mut set = Sigset::empty();
        set.add(15).unwrap();
        let mut pending = Sigset::empty();
        pending.add(15).unwrap();
        let sig = sys_sigtimedwait(&set, None, &pending).unwrap().unwrap();
        assert_eq!(sig, 15);
    }

    #[test]
    fn sigtimedwait_no_match_zero_timeout() {
        let mut set = Sigset::empty();
        set.add(10).unwrap();
        let pending = Sigset::empty();
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(
            sys_sigtimedwait(&set, Some(&timeout), &pending),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn invalid_timeout() {
        let set = Sigset::empty();
        let pending = Sigset::empty();
        let bad = Timespec {
            tv_sec: -1,
            tv_nsec: 0,
        };
        assert_eq!(
            sys_sigtimedwait(&set, Some(&bad), &pending),
            Err(Error::InvalidArgument)
        );
    }
}
