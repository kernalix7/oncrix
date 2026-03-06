// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `eventfd2(2)` syscall handler — create a file descriptor for event notification.
//!
//! `eventfd2` creates an event object that can be used as an event wait/notify
//! mechanism by user-space applications, and by the kernel to notify user-space
//! applications of events.  The `initval` argument sets the initial value of
//! the kernel counter associated with the new file descriptor.
//!
//! # Linux reference
//!
//! Linux-specific: `eventfd(2)` man page (eventfd2 is the kernel-level syscall).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Set the close-on-exec (`FD_CLOEXEC`) flag on the new fd.
pub const EFD_CLOEXEC: i32 = 0o2000000;

/// Set the `O_NONBLOCK` flag on the new fd.
pub const EFD_NONBLOCK: i32 = 0o0004000;

/// Use semaphore-like semantics — each read decrements the counter by one.
pub const EFD_SEMAPHORE: i32 = 1;

/// All valid flags for `eventfd2`.
const VALID_FLAGS: i32 = EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Parsed `eventfd2` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Eventfd2Flags {
    /// Whether to set `FD_CLOEXEC` on the new fd.
    pub cloexec: bool,
    /// Whether to set `O_NONBLOCK` on the new fd.
    pub nonblock: bool,
    /// Whether to use semaphore semantics.
    pub semaphore: bool,
}

impl Eventfd2Flags {
    /// Create a default (no-flags) value.
    pub const fn new() -> Self {
        Self {
            cloexec: false,
            nonblock: false,
            semaphore: false,
        }
    }

    /// Parse from a raw integer.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if unknown bits are set.
    pub fn from_raw(flags: i32) -> Result<Self> {
        if flags & !VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            cloexec: flags & EFD_CLOEXEC != 0,
            nonblock: flags & EFD_NONBLOCK != 0,
            semaphore: flags & EFD_SEMAPHORE != 0,
        })
    }

    /// Convert back to a raw integer.
    pub fn to_raw(&self) -> i32 {
        let mut raw = 0i32;
        if self.cloexec {
            raw |= EFD_CLOEXEC;
        }
        if self.nonblock {
            raw |= EFD_NONBLOCK;
        }
        if self.semaphore {
            raw |= EFD_SEMAPHORE;
        }
        raw
    }
}

/// Parsed `eventfd2` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eventfd2Request {
    /// Initial value of the kernel counter (must be `<= u64::MAX`).
    pub initval: u32,
    /// Parsed flags.
    pub flags: Eventfd2Flags,
}

impl Eventfd2Request {
    /// Construct a new request.
    pub const fn new(initval: u32, flags: Eventfd2Flags) -> Self {
        Self { initval, flags }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `eventfd2(2)`.
///
/// Validates the `flags` argument and returns a parsed request.  The kernel
/// allocates an anonymous inode backed by an eventfd context and returns a
/// file descriptor.
///
/// # Arguments
///
/// - `initval` — initial value of the 64-bit counter (passed as `u32` on the
///   Linux ABI; the kernel widens it)
/// - `flags`   — combination of `EFD_CLOEXEC`, `EFD_NONBLOCK`, `EFD_SEMAPHORE`
///
/// # Errors
///
/// | `Error`           | Condition                   |
/// |-------------------|-----------------------------|
/// | `InvalidArgument` | Unknown bits set in `flags` |
/// | `OutOfMemory`     | Kernel cannot allocate the eventfd |
pub fn do_eventfd2(initval: u32, flags: i32) -> Result<Eventfd2Request> {
    let parsed_flags = Eventfd2Flags::from_raw(flags)?;
    Ok(Eventfd2Request::new(initval, parsed_flags))
}

/// Validate the `flags` argument for `eventfd2`.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` if any unknown bits are set.
pub fn validate_eventfd2_flags(flags: i32) -> Result<()> {
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Return `true` if the eventfd should use semaphore semantics.
pub fn is_semaphore_mode(flags: &Eventfd2Flags) -> bool {
    flags.semaphore
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_flags_ok() {
        let req = do_eventfd2(0, 0).unwrap();
        assert!(!req.flags.cloexec);
        assert!(!req.flags.nonblock);
        assert!(!req.flags.semaphore);
        assert_eq!(req.initval, 0);
    }

    #[test]
    fn all_flags_ok() {
        let all = EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE;
        let req = do_eventfd2(42, all).unwrap();
        assert!(req.flags.cloexec);
        assert!(req.flags.nonblock);
        assert!(req.flags.semaphore);
        assert_eq!(req.initval, 42);
    }

    #[test]
    fn unknown_flag_rejected() {
        assert_eq!(do_eventfd2(0, 0x1000), Err(Error::InvalidArgument));
    }

    #[test]
    fn semaphore_detection() {
        let flags = Eventfd2Flags::from_raw(EFD_SEMAPHORE).unwrap();
        assert!(is_semaphore_mode(&flags));
        let no_sem = Eventfd2Flags::new();
        assert!(!is_semaphore_mode(&no_sem));
    }

    #[test]
    fn flags_roundtrip() {
        let flags = Eventfd2Flags {
            cloexec: true,
            nonblock: false,
            semaphore: true,
        };
        let raw = flags.to_raw();
        let parsed = Eventfd2Flags::from_raw(raw).unwrap();
        assert_eq!(parsed, flags);
    }
}
