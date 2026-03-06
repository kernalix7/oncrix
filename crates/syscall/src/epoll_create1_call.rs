// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `epoll_create1(2)` syscall handler — create an epoll file descriptor with flags.
//!
//! `epoll_create1` is an extension of `epoll_create` that accepts flags to
//! control properties of the new epoll file descriptor.  The only currently
//! defined flag is `EPOLL_CLOEXEC` which sets the close-on-exec flag.
//!
//! # Linux reference
//!
//! Linux-specific: `epoll_create1(2)` man page.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Set the close-on-exec (`FD_CLOEXEC`) flag on the new epoll fd.
pub const EPOLL_CLOEXEC: i32 = 0o2000000;

/// All valid `epoll_create1` flags.
const VALID_FLAGS: i32 = EPOLL_CLOEXEC;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Options parsed from the `flags` argument of `epoll_create1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EpollCreate1Flags {
    /// Whether the new fd should have `FD_CLOEXEC` set.
    pub cloexec: bool,
}

impl EpollCreate1Flags {
    /// Create a default (no-flags) value.
    pub const fn new() -> Self {
        Self { cloexec: false }
    }

    /// Parse from the raw integer flags.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if unknown bits are set.
    pub fn from_raw(flags: i32) -> Result<Self> {
        if flags & !VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            cloexec: flags & EPOLL_CLOEXEC != 0,
        })
    }
}

/// Result of a validated `epoll_create1` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpollCreate1Request {
    /// Parsed flags.
    pub flags: EpollCreate1Flags,
}

impl EpollCreate1Request {
    /// Construct a new request.
    pub const fn new(flags: EpollCreate1Flags) -> Self {
        Self { flags }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `epoll_create1(2)`.
///
/// Validates the `flags` argument and returns a parsed request.  The kernel
/// allocates a new epoll instance and returns a file descriptor.
///
/// Unlike `epoll_create(size)`, this variant does not accept a `size` hint;
/// the kernel automatically sizes the underlying data structure.
///
/// # Arguments
///
/// - `flags` — zero or `EPOLL_CLOEXEC`
///
/// # Errors
///
/// | `Error`           | Condition              |
/// |-------------------|------------------------|
/// | `InvalidArgument` | Unknown bits set in flags |
/// | `OutOfMemory`     | Kernel cannot allocate the epoll instance |
pub fn do_epoll_create1(flags: i32) -> Result<EpollCreate1Request> {
    let parsed_flags = EpollCreate1Flags::from_raw(flags)?;
    Ok(EpollCreate1Request::new(parsed_flags))
}

/// Check whether the provided flags value is valid for `epoll_create1`.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` if any unknown bits are set.
pub fn validate_epoll_create1_flags(flags: i32) -> Result<()> {
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Build the raw flags integer from a `EpollCreate1Flags` struct.
pub fn flags_to_raw(flags: &EpollCreate1Flags) -> i32 {
    let mut raw = 0i32;
    if flags.cloexec {
        raw |= EPOLL_CLOEXEC;
    }
    raw
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_flags_ok() {
        let req = do_epoll_create1(0).unwrap();
        assert!(!req.flags.cloexec);
    }

    #[test]
    fn cloexec_flag_ok() {
        let req = do_epoll_create1(EPOLL_CLOEXEC).unwrap();
        assert!(req.flags.cloexec);
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(do_epoll_create1(0xFF), Err(Error::InvalidArgument));
    }

    #[test]
    fn roundtrip() {
        let flags = EpollCreate1Flags { cloexec: true };
        let raw = flags_to_raw(&flags);
        let parsed = EpollCreate1Flags::from_raw(raw).unwrap();
        assert_eq!(parsed, flags);
    }

    #[test]
    fn validate_ok() {
        assert!(validate_epoll_create1_flags(EPOLL_CLOEXEC).is_ok());
        assert!(validate_epoll_create1_flags(0).is_ok());
    }

    #[test]
    fn validate_invalid() {
        assert_eq!(
            validate_epoll_create1_flags(0x1),
            Err(Error::InvalidArgument)
        );
    }
}
