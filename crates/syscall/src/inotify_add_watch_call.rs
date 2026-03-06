// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `inotify_add_watch(2)` syscall handler — add a watch to an inotify instance.
//!
//! `inotify_add_watch` adds a new watch, or modifies an existing watch, for
//! the file identified by `pathname` in the inotify instance `fd`.  The `mask`
//! argument specifies the events to watch for.
//!
//! # Linux reference
//!
//! Linux-specific: `inotify(7)` and `inotify_add_watch(2)` man pages.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Event mask constants (IN_* flags)
// ---------------------------------------------------------------------------

/// File was accessed (e.g., `read(2)`, `execve(2)`).
pub const IN_ACCESS: u32 = 0x0000_0001;
/// File was modified.
pub const IN_MODIFY: u32 = 0x0000_0002;
/// Metadata changed (e.g., permissions, timestamps).
pub const IN_ATTRIB: u32 = 0x0000_0004;
/// Writable file was closed.
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
/// Non-writable file was closed.
pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
/// File was opened.
pub const IN_OPEN: u32 = 0x0000_0020;
/// File was moved out of watched directory.
pub const IN_MOVED_FROM: u32 = 0x0000_0040;
/// File was moved into watched directory.
pub const IN_MOVED_TO: u32 = 0x0000_0080;
/// File created in watched directory.
pub const IN_CREATE: u32 = 0x0000_0100;
/// File deleted from watched directory.
pub const IN_DELETE: u32 = 0x0000_0200;
/// Watched file itself was deleted.
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
/// Watched file itself was moved.
pub const IN_MOVE_SELF: u32 = 0x0000_0800;

// Convenience combinations.
/// Both close events.
pub const IN_CLOSE: u32 = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
/// Both move events.
pub const IN_MOVE: u32 = IN_MOVED_FROM | IN_MOVED_TO;
/// All events that can be returned.
pub const IN_ALL_EVENTS: u32 = IN_ACCESS
    | IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE
    | IN_OPEN
    | IN_MOVE
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF;

// Special flags.
/// Do not follow symbolic links.
pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;
/// Only watch path if it is a directory.
pub const IN_ONLYDIR: u32 = 0x0100_0000;
/// Remove watch after one event.
pub const IN_ONESHOT: u32 = 0x8000_0000;
/// Add events to existing mask rather than replacing it.
pub const IN_MASK_ADD: u32 = 0x2000_0000;
/// Report only directory events.
pub const IN_ISDIR: u32 = 0x4000_0000;

/// All valid user-settable bits.
const VALID_MASK: u32 = IN_ALL_EVENTS | IN_DONT_FOLLOW | IN_ONLYDIR | IN_ONESHOT | IN_MASK_ADD;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A watch descriptor returned by `inotify_add_watch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchDescriptor(pub i32);

impl WatchDescriptor {
    /// Construct a new watch descriptor.
    pub const fn new(wd: i32) -> Self {
        Self(wd)
    }

    /// Return the raw integer watch descriptor.
    pub fn as_i32(self) -> i32 {
        self.0
    }
}

/// Validated `inotify_add_watch` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InotifyAddWatchRequest {
    /// Inotify instance file descriptor.
    pub fd: i32,
    /// Path length in bytes (user-space string; validated non-null).
    pub pathname_ptr: usize,
    /// Event mask.
    pub mask: u32,
}

impl InotifyAddWatchRequest {
    /// Construct a new request.
    pub const fn new(fd: i32, pathname_ptr: usize, mask: u32) -> Self {
        Self {
            fd,
            pathname_ptr,
            mask,
        }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `inotify_add_watch(2)`.
///
/// Validates arguments and returns a parsed request.  The kernel then looks up
/// the inode for `pathname` and registers a watch in the inotify instance.
///
/// If `IN_MASK_ADD` is set, the provided mask is ORed with the existing watch
/// mask instead of replacing it.
///
/// # Arguments
///
/// - `fd`          — inotify instance file descriptor
/// - `pathname`    — pointer to the null-terminated path string (user-space)
/// - `mask`        — event mask (`IN_*` flags)
///
/// # Errors
///
/// | `Error`           | Condition                                  |
/// |-------------------|--------------------------------------------|
/// | `InvalidArgument` | Bad fd, null pathname, invalid mask bits   |
/// | `NotFound`        | `fd` does not refer to an inotify instance |
pub fn do_inotify_add_watch(fd: i32, pathname: usize, mask: u32) -> Result<InotifyAddWatchRequest> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if pathname == 0 {
        return Err(Error::InvalidArgument);
    }
    validate_inotify_mask(mask)?;
    Ok(InotifyAddWatchRequest::new(fd, pathname, mask))
}

/// Validate an inotify event mask.
///
/// The mask must have at least one event bit set and must not contain any
/// bits outside `VALID_MASK`.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` on violations.
pub fn validate_inotify_mask(mask: u32) -> Result<()> {
    if mask & !VALID_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    // At least one event bit must be set.
    if mask & IN_ALL_EVENTS == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Return `true` if the mask includes the `IN_MASK_ADD` flag.
pub fn is_mask_add(mask: u32) -> bool {
    mask & IN_MASK_ADD != 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_request_ok() {
        let req = do_inotify_add_watch(3, 0xDEAD_BEEF, IN_CREATE | IN_DELETE).unwrap();
        assert_eq!(req.fd, 3);
        assert_eq!(req.mask, IN_CREATE | IN_DELETE);
    }

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(
            do_inotify_add_watch(-1, 0xDEAD_BEEF, IN_CREATE),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn null_pathname_rejected() {
        assert_eq!(
            do_inotify_add_watch(3, 0, IN_CREATE),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn zero_event_bits_rejected() {
        // Only special flags, no event bits.
        assert_eq!(
            do_inotify_add_watch(3, 0x1000, IN_DONT_FOLLOW),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_bits_rejected() {
        assert_eq!(
            do_inotify_add_watch(3, 0x1000, IN_CREATE | 0x0001_0000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn mask_add_detection() {
        assert!(is_mask_add(IN_CREATE | IN_MASK_ADD));
        assert!(!is_mask_add(IN_CREATE));
    }

    #[test]
    fn all_events_valid() {
        assert!(validate_inotify_mask(IN_ALL_EVENTS).is_ok());
    }
}
