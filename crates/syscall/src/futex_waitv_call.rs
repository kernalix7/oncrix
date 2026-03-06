// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `futex_waitv(2)` syscall handler.
//!
//! Waits on a vector of futexes simultaneously.  The call blocks until any
//! futex in the vector matches its expected value, a timeout elapses, or a
//! signal is delivered.  This is the multi-wait variant introduced in
//! Linux 5.16 to support D3D12 / Proton synchronisation primitives.
//!
//! # Syscall signature
//!
//! ```text
//! int futex_waitv(struct futex_waitv *waiters, unsigned int nr_futexes,
//!                 unsigned int flags, struct timespec *timeout,
//!                 clockid_t clockid);
//! ```
//!
//! # POSIX reference
//!
//! Not part of POSIX.1-2024; Linux 5.16+ extension.  The individual futex
//! words follow the POSIX `pthread_mutex_t` locking protocol.
//!
//! # References
//!
//! - Linux: `kernel/futex/waitv.c`
//! - `futex_waitv(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of futexes in one `futex_waitv` call.
pub const FUTEX_WAITV_MAX: usize = 128;

/// Flag: the futex is in shared (inter-process) memory.
pub const FUTEX_32: u32 = 2;

/// Flag: private (intra-process) futex.
pub const FUTEX_PRIVATE_FLAG: u32 = 128;

/// Private 32-bit futex.
pub const FUTEX_32_PRIVATE: u32 = FUTEX_32 | FUTEX_PRIVATE_FLAG;

/// Mask of recognised per-futex flags.
const FUTEX_FLAGS_MASK: u32 = FUTEX_32 | FUTEX_PRIVATE_FLAG;

/// Top-level `futex_waitv` call flags (currently reserved; must be 0).
const FUTEX_WAITV_FLAGS_KNOWN: u32 = 0;

/// Maximum accepted clock ID value.
const CLOCKID_MAX: u32 = 11;

// ---------------------------------------------------------------------------
// FutexWaiter — single waiter descriptor
// ---------------------------------------------------------------------------

/// Descriptor for a single futex in a `futex_waitv` call.
///
/// Mirrors `struct futex_waitv` from the Linux UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FutexWaiter {
    /// User-space address of the futex word.
    pub uaddr: u64,
    /// Expected value of the futex word.
    pub val: u64,
    /// Futex type flags (`FUTEX_32`, `FUTEX_32_PRIVATE`, …).
    pub flags: u32,
    /// Reserved padding; must be 0.
    pub __reserved: u32,
}

impl FutexWaiter {
    /// Return `true` if this is a private (non-shared) futex.
    pub const fn is_private(&self) -> bool {
        self.flags & FUTEX_PRIVATE_FLAG != 0
    }

    /// Return `true` if this is a 32-bit futex.
    pub const fn is_32bit(&self) -> bool {
        self.flags & FUTEX_32 != 0
    }
}

// ---------------------------------------------------------------------------
// WaitvTimeout — optional timeout
// ---------------------------------------------------------------------------

/// Timeout specification for `futex_waitv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitvTimeout {
    /// Seconds component.
    pub tv_sec: i64,
    /// Nanoseconds component (0..=999_999_999).
    pub tv_nsec: i64,
    /// Clock ID (e.g. `CLOCK_MONOTONIC = 1`, `CLOCK_REALTIME = 0`).
    pub clockid: u32,
}

impl WaitvTimeout {
    /// Validate the timeout fields.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] if `tv_nsec` is out of range or `clockid`
    /// is unrecognised.
    pub fn validate(&self) -> Result<()> {
        if self.tv_nsec < 0 || self.tv_nsec >= 1_000_000_000 {
            return Err(Error::InvalidArgument);
        }
        if self.tv_sec < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.clockid > CLOCKID_MAX {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return `true` if the timeout has already expired (both fields zero).
    pub const fn is_immediate(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a single [`FutexWaiter`] entry.
///
/// Checks:
/// - Known flags only.
/// - Reserved field is zero.
/// - Address is non-null and naturally aligned (32-bit → 4-byte).
fn validate_waiter(w: &FutexWaiter) -> Result<()> {
    if w.flags & !FUTEX_FLAGS_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    if w.__reserved != 0 {
        return Err(Error::InvalidArgument);
    }
    if w.uaddr == 0 {
        return Err(Error::InvalidArgument);
    }
    // 32-bit futex word must be 4-byte aligned.
    if w.uaddr % 4 != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate the complete set of arguments to `futex_waitv`.
///
/// # Arguments
///
/// * `waiters`    — Slice of [`FutexWaiter`] descriptors.
/// * `flags`      — Top-level call flags (must be 0).
/// * `timeout`    — Optional timeout specification.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — empty or oversized waiter list, unknown
///   flags, invalid individual waiter, or invalid timeout.
pub fn validate_futex_waitv(
    waiters: &[FutexWaiter],
    flags: u32,
    timeout: Option<&WaitvTimeout>,
) -> Result<()> {
    if waiters.is_empty() || waiters.len() > FUTEX_WAITV_MAX {
        return Err(Error::InvalidArgument);
    }
    if flags & !FUTEX_WAITV_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    for w in waiters {
        validate_waiter(w)?;
    }
    if let Some(t) = timeout {
        t.validate()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WaitvResult — result of a wait operation
// ---------------------------------------------------------------------------

/// Result of a `futex_waitv` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitvResult {
    /// The futex at index `idx` woke us.
    Woken { idx: usize },
    /// Timed out before any futex was ready.
    TimedOut,
    /// All futexes already matched on entry; index of first match.
    AlreadyReady { idx: usize },
    /// A signal interrupted the wait.
    Interrupted,
}

// ---------------------------------------------------------------------------
// check_initial_values — optimistic check before blocking
// ---------------------------------------------------------------------------

/// Compare each futex's user-supplied expected value against `current_vals`.
///
/// Returns `Some(idx)` if the first futex whose value does not match its
/// expected value is found (meaning it has already been modified and we
/// should wake immediately), or `None` if all values match (block required).
///
/// In a real kernel this function would read the futex words from user memory.
/// Here we receive the current values as a slice for testability.
pub fn check_initial_values(waiters: &[FutexWaiter], current_vals: &[u64]) -> Option<usize> {
    debug_assert_eq!(waiters.len(), current_vals.len());
    for (idx, (w, &cv)) in waiters.iter().zip(current_vals.iter()).enumerate() {
        if cv != w.val {
            return Some(idx);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// sys_futex_waitv — entry point
// ---------------------------------------------------------------------------

/// Handler for `futex_waitv(2)`.
///
/// Validates the argument vector and performs an optimistic pre-check.
/// If any futex already has a value different from its expected value,
/// returns [`WaitvResult::AlreadyReady`] immediately.  Otherwise the caller
/// must arrange for the actual blocking wait (scheduler integration).
///
/// # Arguments
///
/// * `waiters`       — Validated futex descriptors.
/// * `flags`         — Top-level flags (must be 0).
/// * `timeout`       — Optional timeout.
/// * `current_vals`  — Current values of each futex word (from user memory).
///
/// # Errors
///
/// See [`validate_futex_waitv`].
pub fn sys_futex_waitv(
    waiters: &[FutexWaiter],
    flags: u32,
    timeout: Option<&WaitvTimeout>,
    current_vals: &[u64],
) -> Result<WaitvResult> {
    validate_futex_waitv(waiters, flags, timeout)?;

    if let Some(idx) = check_initial_values(waiters, current_vals) {
        return Ok(WaitvResult::AlreadyReady { idx });
    }

    if let Some(t) = timeout {
        if t.is_immediate() {
            return Ok(WaitvResult::TimedOut);
        }
    }

    // Blocking wait: deferred to scheduler.
    Err(Error::WouldBlock)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn waiter(uaddr: u64, val: u64) -> FutexWaiter {
        FutexWaiter {
            uaddr,
            val,
            flags: FUTEX_32_PRIVATE,
            __reserved: 0,
        }
    }

    #[test]
    fn validate_ok() {
        let ws = [waiter(0x1000, 0), waiter(0x2000, 1)];
        assert!(validate_futex_waitv(&ws, 0, None).is_ok());
    }

    #[test]
    fn empty_waiters_rejected() {
        assert_eq!(
            validate_futex_waitv(&[], 0, None),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn nonzero_flags_rejected() {
        let ws = [waiter(0x1000, 0)];
        assert_eq!(
            validate_futex_waitv(&ws, 1, None),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn null_uaddr_rejected() {
        let ws = [FutexWaiter {
            uaddr: 0,
            val: 0,
            flags: FUTEX_32_PRIVATE,
            __reserved: 0,
        }];
        assert_eq!(
            validate_futex_waitv(&ws, 0, None),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unaligned_uaddr_rejected() {
        let ws = [FutexWaiter {
            uaddr: 0x1001,
            val: 0,
            flags: FUTEX_32_PRIVATE,
            __reserved: 0,
        }];
        assert_eq!(
            validate_futex_waitv(&ws, 0, None),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn already_ready_first_mismatch() {
        let ws = [waiter(0x1000, 42), waiter(0x2000, 99)];
        let vals = [0u64, 99]; // first doesn't match
        match sys_futex_waitv(&ws, 0, None, &vals) {
            Ok(WaitvResult::AlreadyReady { idx: 0 }) => {}
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn all_match_returns_would_block() {
        let ws = [waiter(0x1000, 7), waiter(0x2000, 8)];
        let vals = [7u64, 8];
        assert_eq!(sys_futex_waitv(&ws, 0, None, &vals), Err(Error::WouldBlock));
    }

    #[test]
    fn immediate_timeout() {
        let ws = [waiter(0x1000, 7)];
        let vals = [7u64];
        let timeout = WaitvTimeout {
            tv_sec: 0,
            tv_nsec: 0,
            clockid: 1,
        };
        assert_eq!(
            sys_futex_waitv(&ws, 0, Some(&timeout), &vals),
            Ok(WaitvResult::TimedOut)
        );
    }

    #[test]
    fn invalid_timeout_nsec() {
        let ws = [waiter(0x1000, 0)];
        let vals = [0u64];
        let timeout = WaitvTimeout {
            tv_sec: 0,
            tv_nsec: 1_000_000_000,
            clockid: 1,
        };
        assert_eq!(
            sys_futex_waitv(&ws, 0, Some(&timeout), &vals),
            Err(Error::InvalidArgument)
        );
    }
}
