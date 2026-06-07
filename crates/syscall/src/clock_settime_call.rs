// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `clock_settime(2)` syscall dispatch layer.
//!
//! Sets the time of the specified clock.  Only `CLOCK_REALTIME` can be set
//! by unprivileged processes; other clocks require `CAP_SYS_TIME`.
//!
//! # Syscall signature
//!
//! ```text
//! int clock_settime(clockid_t clockid, const struct timespec *tp);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `clock_settime()` in `<time.h>`
//! - `.TheOpenGroup/susv5-html/functions/clock_settime.html`
//!
//! # References
//!
//! - Linux: `kernel/time/posix-timers.c` (`sys_clock_settime`)
//! - `clock_settime(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Clock ID constants
// ---------------------------------------------------------------------------

/// System-wide real-time clock.
pub const CLOCK_REALTIME: u32 = 0;
/// Monotonic clock (can only be set indirectly via adjtime).
pub const CLOCK_MONOTONIC: u32 = 1;
/// CPU-time clock for the calling process.
pub const CLOCK_PROCESS_CPUTIME_ID: u32 = 2;
/// CPU-time clock for the calling thread.
pub const CLOCK_THREAD_CPUTIME_ID: u32 = 3;

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

/// Capability bit required to set a system clock.
///
/// Mirrors `oncrix-kernel`'s canonical `crate::capability::CAP_SYS_TIME`
/// (value `25`). It is re-declared here because the `syscall` crate does not
/// depend on `oncrix-kernel`; the dispatcher passes the caller's capability
/// set so this layer can enforce the check. Do **not** change the value
/// independently of the kernel definition.
pub const CAP_SYS_TIME: u8 = 25;

/// The caller's effective capability set, threaded from the dispatcher.
///
/// `bits` is a bitmask indexed by capability number (bit `n` set ⇒ the
/// caller holds capability `n`). A default-constructed value holds **no**
/// capabilities, so callers that have not yet wired real credentials
/// fail closed.
#[derive(Debug, Clone, Copy, Default)]
pub struct CapabilitySet {
    /// Bitmask of held capabilities (bit `n` ⇒ capability `n`).
    pub bits: u64,
}

impl CapabilitySet {
    /// Construct from a raw capability bitmask.
    pub const fn from_bits(bits: u64) -> Self {
        Self { bits }
    }

    /// Returns `true` if capability `cap` is held.
    pub const fn has(&self, cap: u8) -> bool {
        (self.bits & (1u64 << cap)) != 0
    }
}

// ---------------------------------------------------------------------------
// Timespec
// ---------------------------------------------------------------------------

/// A `struct timespec` as passed from user space.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Timespec {
    /// Seconds since the epoch.
    pub tv_sec: i64,
    /// Nanoseconds [0, 999_999_999].
    pub tv_nsec: i64,
}

impl Timespec {
    /// Returns `true` if the nanosecond field is in the valid range.
    pub fn is_valid(&self) -> bool {
        self.tv_sec >= 0 && (0..1_000_000_000).contains(&self.tv_nsec)
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `clockid` is a settable clock.
pub fn is_settable_clock(clockid: u32) -> bool {
    // Only CLOCK_REALTIME can be set (others are kernel-maintained or read-only).
    clockid == CLOCK_REALTIME
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `clock_settime(2)`.
///
/// Setting any system clock is a privileged operation: the caller must hold
/// `CAP_SYS_TIME`. The capability set is threaded from the dispatcher via
/// `caps`; a caller with no credentials wired yet (default `CapabilitySet`)
/// is denied, so the operation fails closed.
///
/// # Errors
///
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_TIME`.
/// - [`Error::InvalidArgument`] — unknown or non-settable `clockid`, null
///   `tp_ptr`, or `tv_nsec` out of range.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_clock_settime(clockid: u32, tp_ptr: u64, caps: CapabilitySet) -> Result<i64> {
    // SECURITY: fail closed. Setting a clock requires CAP_SYS_TIME; deny
    // before touching any argument so an unprivileged caller cannot set the
    // wall clock. The check is first so a missing capability is reported as
    // PermissionDenied regardless of argument validity.
    if !caps.has(CAP_SYS_TIME) {
        return Err(Error::PermissionDenied);
    }
    if !is_settable_clock(clockid) {
        return Err(Error::InvalidArgument);
    }
    if tp_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: pointer validation is caller's responsibility; stub reads for validation.
    let ts = unsafe { &*(tp_ptr as *const Timespec) };
    if !ts.is_valid() {
        return Err(Error::InvalidArgument);
    }
    let _ = (clockid, tp_ptr);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
///
/// `caps` carries the calling task's effective capability set; the
/// dispatcher is responsible for populating it from the current task's
/// credentials before calling.
pub fn do_clock_settime_call(clockid: u32, tp_ptr: u64, caps: CapabilitySet) -> Result<i64> {
    sys_clock_settime(clockid, tp_ptr, caps)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A capability set holding only CAP_SYS_TIME.
    fn caps_with_time() -> CapabilitySet {
        CapabilitySet::from_bits(1u64 << CAP_SYS_TIME)
    }

    #[test]
    fn monotonic_clock_not_settable() {
        assert_eq!(
            sys_clock_settime(CLOCK_MONOTONIC, 0x1000, caps_with_time()).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_tp_rejected() {
        assert_eq!(
            sys_clock_settime(CLOCK_REALTIME, 0, caps_with_time()).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn no_cap_sys_time_denied() {
        // Fail closed: an empty capability set is rejected, and the denial
        // takes priority over argument validity (settable clock + null ptr).
        assert_eq!(
            sys_clock_settime(CLOCK_REALTIME, 0, CapabilitySet::default()).unwrap_err(),
            Error::PermissionDenied
        );
        assert_eq!(
            sys_clock_settime(CLOCK_REALTIME, 0x1000, CapabilitySet::default()).unwrap_err(),
            Error::PermissionDenied
        );
    }

    #[test]
    fn cap_set_has_bit() {
        let caps = caps_with_time();
        assert!(caps.has(CAP_SYS_TIME));
        assert!(!CapabilitySet::default().has(CAP_SYS_TIME));
    }

    #[test]
    fn is_settable_only_realtime() {
        assert!(is_settable_clock(CLOCK_REALTIME));
        assert!(!is_settable_clock(CLOCK_MONOTONIC));
    }

    #[test]
    fn timespec_validation() {
        let valid = Timespec {
            tv_sec: 1_000_000,
            tv_nsec: 500_000_000,
        };
        assert!(valid.is_valid());
        let invalid = Timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000_000,
        };
        assert!(!invalid.is_valid());
    }
}
