// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `inotify_rm_watch(2)` syscall handler — remove a watch from an inotify instance.
//!
//! `inotify_rm_watch` removes the watch associated with the watch descriptor `wd`
//! from the inotify instance `fd`.  Removing a watch causes an `IN_IGNORED` event
//! to be generated for this watch descriptor.
//!
//! # Linux reference
//!
//! Linux-specific: `inotify_rm_watch(2)` man page.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Status of the watch after a removal attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchRemoveStatus {
    /// The watch was successfully removed.
    Removed,
    /// The watch was not found in the inotify instance.
    NotFound,
}

/// Validated `inotify_rm_watch` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InotifyRmWatchRequest {
    /// Inotify instance file descriptor.
    pub fd: i32,
    /// Watch descriptor to remove.
    pub wd: i32,
}

impl InotifyRmWatchRequest {
    /// Construct a new request.
    pub const fn new(fd: i32, wd: i32) -> Self {
        Self { fd, wd }
    }
}

/// Inotify event emitted after a watch is removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InIgnoredEvent {
    /// The watch descriptor that was removed.
    pub wd: i32,
    /// Mask always contains `IN_IGNORED`.
    pub mask: u32,
}

impl InIgnoredEvent {
    /// `IN_IGNORED` flag — watch was removed.
    pub const IN_IGNORED: u32 = 0x0000_8000;

    /// Construct the event for the given watch descriptor.
    pub const fn new(wd: i32) -> Self {
        Self {
            wd,
            mask: Self::IN_IGNORED,
        }
    }

    /// Return whether the mask has the `IN_IGNORED` bit set.
    pub fn is_ignored(&self) -> bool {
        self.mask & Self::IN_IGNORED != 0
    }
}

impl Default for InIgnoredEvent {
    fn default() -> Self {
        Self::new(-1)
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `inotify_rm_watch(2)`.
///
/// Validates arguments and returns a parsed request.  The kernel then removes
/// the watch from the inotify instance and generates an `IN_IGNORED` event.
///
/// # Arguments
///
/// - `fd` — inotify instance file descriptor
/// - `wd` — watch descriptor to remove
///
/// # Errors
///
/// | `Error`           | Condition                                         |
/// |-------------------|---------------------------------------------------|
/// | `InvalidArgument` | `fd` or `wd` is negative                          |
/// | `NotFound`        | `fd` is not an inotify fd or `wd` is not in it   |
pub fn do_inotify_rm_watch(fd: i32, wd: i32) -> Result<InotifyRmWatchRequest> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if wd < 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(InotifyRmWatchRequest::new(fd, wd))
}

/// Simulate a watch lookup and removal.
///
/// This is a stub for kernel-side lookup logic.  Returns `WatchRemoveStatus`
/// based on whether the watch descriptor exists in a provided set.
pub fn remove_watch_from_set(wd: i32, watches: &[i32]) -> WatchRemoveStatus {
    if watches.contains(&wd) {
        WatchRemoveStatus::Removed
    } else {
        WatchRemoveStatus::NotFound
    }
}

/// Build the `IN_IGNORED` event that must be emitted after removing a watch.
pub fn build_ignored_event(wd: i32) -> InIgnoredEvent {
    InIgnoredEvent::new(wd)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_request_ok() {
        let req = do_inotify_rm_watch(3, 1).unwrap();
        assert_eq!(req.fd, 3);
        assert_eq!(req.wd, 1);
    }

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(do_inotify_rm_watch(-1, 1), Err(Error::InvalidArgument));
    }

    #[test]
    fn negative_wd_rejected() {
        assert_eq!(do_inotify_rm_watch(3, -1), Err(Error::InvalidArgument));
    }

    #[test]
    fn remove_found() {
        let watches = [1, 2, 3];
        assert_eq!(
            remove_watch_from_set(2, &watches),
            WatchRemoveStatus::Removed
        );
    }

    #[test]
    fn remove_not_found() {
        let watches = [1, 2, 3];
        assert_eq!(
            remove_watch_from_set(99, &watches),
            WatchRemoveStatus::NotFound
        );
    }

    #[test]
    fn ignored_event_has_correct_mask() {
        let ev = build_ignored_event(5);
        assert_eq!(ev.wd, 5);
        assert!(ev.is_ignored());
        assert_eq!(ev.mask, InIgnoredEvent::IN_IGNORED);
    }
}
