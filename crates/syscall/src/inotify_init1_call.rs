// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `inotify_init1(2)` syscall handler — create an inotify instance with flags.
//!
//! `inotify_init1` creates a new inotify instance and returns a file descriptor
//! associated with it.  The `flags` argument allows setting `O_CLOEXEC` and
//! `O_NONBLOCK` on the fd atomically at creation time.
//!
//! # Linux reference
//!
//! Linux-specific: `inotify_init(2)` man page.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Set `FD_CLOEXEC` on the new inotify fd.
pub const IN_CLOEXEC: i32 = 0o2000000;

/// Set `O_NONBLOCK` on the new inotify fd.
pub const IN_NONBLOCK: i32 = 0o0004000;

/// All valid flags for `inotify_init1`.
const VALID_FLAGS: i32 = IN_CLOEXEC | IN_NONBLOCK;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Parsed `inotify_init1` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InotifyInit1Flags {
    /// Whether the new fd should have `FD_CLOEXEC` set.
    pub cloexec: bool,
    /// Whether the new fd should be in non-blocking mode.
    pub nonblock: bool,
}

impl InotifyInit1Flags {
    /// Create a default (no-flags) value.
    pub const fn new() -> Self {
        Self {
            cloexec: false,
            nonblock: false,
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
            cloexec: flags & IN_CLOEXEC != 0,
            nonblock: flags & IN_NONBLOCK != 0,
        })
    }

    /// Convert to a raw integer.
    pub fn to_raw(&self) -> i32 {
        let mut raw = 0i32;
        if self.cloexec {
            raw |= IN_CLOEXEC;
        }
        if self.nonblock {
            raw |= IN_NONBLOCK;
        }
        raw
    }
}

/// Validated `inotify_init1` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InotifyInit1Request {
    /// Parsed flags.
    pub flags: InotifyInit1Flags,
}

impl InotifyInit1Request {
    /// Construct a new request.
    pub const fn new(flags: InotifyInit1Flags) -> Self {
        Self { flags }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `inotify_init1(2)`.
///
/// Validates flags and returns a parsed request.  The kernel allocates a new
/// inotify instance and returns a file descriptor the caller can use to add
/// watches with `inotify_add_watch(2)`.
///
/// # Arguments
///
/// - `flags` — zero, `IN_CLOEXEC`, `IN_NONBLOCK`, or a combination
///
/// # Errors
///
/// | `Error`           | Condition                    |
/// |-------------------|------------------------------|
/// | `InvalidArgument` | Unknown bits set in `flags`  |
/// | `OutOfMemory`     | Kernel cannot allocate inotify instance |
pub fn do_inotify_init1(flags: i32) -> Result<InotifyInit1Request> {
    let parsed_flags = InotifyInit1Flags::from_raw(flags)?;
    Ok(InotifyInit1Request::new(parsed_flags))
}

/// Validate the `flags` argument.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` for any unknown bits.
pub fn validate_inotify_init1_flags(flags: i32) -> Result<()> {
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Build the effective open flags for the underlying file description.
///
/// Maps inotify flags to the corresponding `O_*` flags used when creating
/// the underlying file description.
pub fn inotify_flags_to_open_flags(flags: &InotifyInit1Flags) -> u32 {
    let mut open_flags = 0u32;
    if flags.cloexec {
        open_flags |= 0o2000000u32;
    }
    if flags.nonblock {
        open_flags |= 0o0004000u32;
    }
    open_flags
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_flags_ok() {
        let req = do_inotify_init1(0).unwrap();
        assert!(!req.flags.cloexec);
        assert!(!req.flags.nonblock);
    }

    #[test]
    fn cloexec_flag_ok() {
        let req = do_inotify_init1(IN_CLOEXEC).unwrap();
        assert!(req.flags.cloexec);
        assert!(!req.flags.nonblock);
    }

    #[test]
    fn nonblock_flag_ok() {
        let req = do_inotify_init1(IN_NONBLOCK).unwrap();
        assert!(!req.flags.cloexec);
        assert!(req.flags.nonblock);
    }

    #[test]
    fn both_flags_ok() {
        let req = do_inotify_init1(IN_CLOEXEC | IN_NONBLOCK).unwrap();
        assert!(req.flags.cloexec);
        assert!(req.flags.nonblock);
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(do_inotify_init1(0x1), Err(Error::InvalidArgument));
    }

    #[test]
    fn flags_roundtrip() {
        let flags = InotifyInit1Flags {
            cloexec: true,
            nonblock: true,
        };
        let raw = flags.to_raw();
        let parsed = InotifyInit1Flags::from_raw(raw).unwrap();
        assert_eq!(parsed, flags);
    }
}
