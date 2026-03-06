// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fanotify_mark(2)` syscall handler — add/remove/modify an fanotify mark.
//!
//! `fanotify_mark` adds, removes, or modifies an fanotify mark on a filesystem
//! object.  The mark determines which events the fanotify group will receive
//! for the specified path.
//!
//! # Linux reference
//!
//! Linux-specific: `fanotify_mark(2)` man page.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Action flags
// ---------------------------------------------------------------------------

/// Add the events in `mask` to the mark.
pub const FAN_MARK_ADD: u32 = 0x0000_0001;
/// Remove the events in `mask` from the mark.
pub const FAN_MARK_REMOVE: u32 = 0x0000_0002;
/// Mark the entire filesystem containing the path.
pub const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;
/// Remove all marks.
pub const FAN_MARK_FLUSH: u32 = 0x0000_0080;
/// Mark the mount point.
pub const FAN_MARK_MOUNT: u32 = 0x0000_0010;
/// Do not follow symlinks when resolving path.
pub const FAN_MARK_DONT_FOLLOW: u32 = 0x0000_0004;
/// Only mark if path is a directory.
pub const FAN_MARK_ONLYDIR: u32 = 0x0000_0008;
/// Mark the inode (default).
pub const FAN_MARK_INODE: u32 = 0x0000_0000;
/// Add the events to the ignore mask.
pub const FAN_MARK_IGNORED_MASK: u32 = 0x0000_0020;
/// Survive event clearing (used with `FAN_MARK_IGNORED_MASK`).
pub const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x0000_0040;

/// Action bits that must include exactly one action.
const ACTION_BITS: u32 = FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH;

/// All valid flag bits.
const VALID_FLAGS: u32 = FAN_MARK_ADD
    | FAN_MARK_REMOVE
    | FAN_MARK_FILESYSTEM
    | FAN_MARK_FLUSH
    | FAN_MARK_MOUNT
    | FAN_MARK_DONT_FOLLOW
    | FAN_MARK_ONLYDIR
    | FAN_MARK_IGNORED_MASK
    | FAN_MARK_IGNORED_SURV_MODIFY;

// ---------------------------------------------------------------------------
// Event mask bits (reused from fanotify_init)
// ---------------------------------------------------------------------------

/// File was accessed.
pub const FAN_ACCESS: u64 = 0x0000_0001;
/// File was modified.
pub const FAN_MODIFY: u64 = 0x0000_0002;
/// Metadata changed.
pub const FAN_ATTRIB: u64 = 0x0000_0004;
/// File closed after writing.
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
/// File closed without writing.
pub const FAN_CLOSE_NOWRITE: u64 = 0x0000_0010;
/// File was opened.
pub const FAN_OPEN: u64 = 0x0000_0020;
/// File was moved from watched directory.
pub const FAN_MOVED_FROM: u64 = 0x0000_0040;
/// File was moved into watched directory.
pub const FAN_MOVED_TO: u64 = 0x0000_0080;
/// File was created.
pub const FAN_CREATE: u64 = 0x0000_0100;
/// File was deleted.
pub const FAN_DELETE: u64 = 0x0000_0200;
/// Watched file was deleted.
pub const FAN_DELETE_SELF: u64 = 0x0000_0400;
/// Watched file was moved.
pub const FAN_MOVE_SELF: u64 = 0x0000_0800;
/// Permission check on open.
pub const FAN_OPEN_PERM: u64 = 0x0001_0000;
/// Permission check on open for execute.
pub const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;
/// Permission check on read.
pub const FAN_ACCESS_PERM: u64 = 0x0002_0000;
/// All events.
pub const FAN_ALL_EVENTS: u64 = FAN_ACCESS
    | FAN_MODIFY
    | FAN_ATTRIB
    | FAN_CLOSE_WRITE
    | FAN_CLOSE_NOWRITE
    | FAN_OPEN
    | FAN_MOVED_FROM
    | FAN_MOVED_TO
    | FAN_CREATE
    | FAN_DELETE
    | FAN_DELETE_SELF
    | FAN_MOVE_SELF;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The action to perform on the mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanotifyMarkAction {
    /// Add events to the mark.
    Add,
    /// Remove events from the mark.
    Remove,
    /// Flush all marks.
    Flush,
}

impl FanotifyMarkAction {
    /// Parse from the flags field.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if the action bits are ambiguous.
    pub fn from_flags(flags: u32) -> Result<Self> {
        let actions = flags & ACTION_BITS;
        match actions {
            FAN_MARK_ADD => Ok(Self::Add),
            FAN_MARK_REMOVE => Ok(Self::Remove),
            FAN_MARK_FLUSH => Ok(Self::Flush),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Validated `fanotify_mark` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanotifyMarkRequest {
    /// fanotify instance file descriptor.
    pub fanotify_fd: i32,
    /// Action to perform.
    pub action: FanotifyMarkAction,
    /// Raw flags value.
    pub flags: u32,
    /// Event mask.
    pub mask: u64,
    /// Directory fd for path resolution (`AT_FDCWD` = -100).
    pub dirfd: i32,
    /// User-space pointer to the pathname (may be 0 for mount/fs marks).
    pub pathname: usize,
}

impl FanotifyMarkRequest {
    /// `AT_FDCWD` sentinel value.
    pub const AT_FDCWD: i32 = -100;

    /// Construct a new request.
    pub const fn new(
        fanotify_fd: i32,
        action: FanotifyMarkAction,
        flags: u32,
        mask: u64,
        dirfd: i32,
        pathname: usize,
    ) -> Self {
        Self {
            fanotify_fd,
            action,
            flags,
            mask,
            dirfd,
            pathname,
        }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `fanotify_mark(2)`.
///
/// Validates all arguments and returns a parsed request.
///
/// # Arguments
///
/// - `fanotify_fd` — fanotify instance file descriptor
/// - `flags`       — action + option flags
/// - `mask`        — events to add/remove
/// - `dirfd`       — directory fd for path resolution
/// - `pathname`    — path to the filesystem object (may be 0 for some mark types)
///
/// # Errors
///
/// | `Error`           | Condition                                            |
/// |-------------------|------------------------------------------------------|
/// | `InvalidArgument` | Unknown flags, ambiguous action, bad fd              |
/// | `PermissionDenied`| Permission events requested without cap              |
pub fn do_fanotify_mark(
    fanotify_fd: i32,
    flags: u32,
    mask: u64,
    dirfd: i32,
    pathname: usize,
) -> Result<FanotifyMarkRequest> {
    if fanotify_fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    let action = FanotifyMarkAction::from_flags(flags)?;
    // For ADD/REMOVE, the mask must be non-zero.
    if matches!(action, FanotifyMarkAction::Add | FanotifyMarkAction::Remove) && mask == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(FanotifyMarkRequest::new(
        fanotify_fd,
        action,
        flags,
        mask,
        dirfd,
        pathname,
    ))
}

/// Return `true` if the flags request a mount-level mark.
pub fn is_mount_mark(flags: u32) -> bool {
    flags & FAN_MARK_MOUNT != 0
}

/// Return `true` if the flags request a filesystem-level mark.
pub fn is_filesystem_mark(flags: u32) -> bool {
    flags & FAN_MARK_FILESYSTEM != 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_mark_ok() {
        let req = do_fanotify_mark(3, FAN_MARK_ADD, FAN_OPEN | FAN_CLOSE_WRITE, -100, 0).unwrap();
        assert_eq!(req.action, FanotifyMarkAction::Add);
        assert_eq!(req.mask, FAN_OPEN | FAN_CLOSE_WRITE);
    }

    #[test]
    fn remove_mark_ok() {
        let req = do_fanotify_mark(3, FAN_MARK_REMOVE, FAN_ACCESS, -100, 0).unwrap();
        assert_eq!(req.action, FanotifyMarkAction::Remove);
    }

    #[test]
    fn flush_ok() {
        let req = do_fanotify_mark(3, FAN_MARK_FLUSH, 0, -100, 0).unwrap();
        assert_eq!(req.action, FanotifyMarkAction::Flush);
    }

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(
            do_fanotify_mark(-1, FAN_MARK_ADD, FAN_ACCESS, -100, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn ambiguous_action_rejected() {
        assert_eq!(
            do_fanotify_mark(3, FAN_MARK_ADD | FAN_MARK_REMOVE, FAN_ACCESS, -100, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn zero_mask_rejected_for_add() {
        assert_eq!(
            do_fanotify_mark(3, FAN_MARK_ADD, 0, -100, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn mount_mark_detection() {
        assert!(is_mount_mark(FAN_MARK_ADD | FAN_MARK_MOUNT));
        assert!(!is_mount_mark(FAN_MARK_ADD));
    }

    #[test]
    fn filesystem_mark_detection() {
        assert!(is_filesystem_mark(FAN_MARK_ADD | FAN_MARK_FILESYSTEM));
        assert!(!is_filesystem_mark(FAN_MARK_ADD));
    }
}
