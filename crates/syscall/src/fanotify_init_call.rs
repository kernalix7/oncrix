// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fanotify_init(2)` syscall handler — create an fanotify group.
//!
//! `fanotify_init` initializes a new fanotify group and returns a file
//! descriptor associated with it.  The fanotify subsystem provides a mechanism
//! to receive notification of file system events and optionally intercept them
//! to make access control decisions.
//!
//! # Linux reference
//!
//! Linux-specific: `fanotify_init(2)` man page.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags (class + option flags)
// ---------------------------------------------------------------------------

/// Fanotify class: receive notification events.
pub const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
/// Fanotify class: receive events for content that the kernel intends to
/// execute.  Requires `CAP_SYS_ADMIN`.
pub const FAN_CLASS_CONTENT: u32 = 0x0000_0004;
/// Fanotify class: similar to `FAN_CLASS_CONTENT` but also for pre-content.
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;

/// Class mask for extracting the class bits.
const FAN_CLASS_MASK: u32 = 0x0000_000C;

/// All class values.
const VALID_CLASSES: &[u32] = &[FAN_CLASS_NOTIF, FAN_CLASS_CONTENT, FAN_CLASS_PRE_CONTENT];

/// Report a file access event with a file descriptor.
pub const FAN_REPORT_FID: u32 = 0x0000_0200;
/// Report a file access event with a file descriptor and inode information.
pub const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;
/// Include file name in event information.
pub const FAN_REPORT_NAME: u32 = 0x0000_0800;
/// Report thread ID rather than thread group ID.
pub const FAN_REPORT_TID: u32 = 0x0000_0100;
/// Generate events for itself.
pub const FAN_UNLIMITED_QUEUE: u32 = 0x0000_0010;
/// Allow unlimited marks.
pub const FAN_UNLIMITED_MARKS: u32 = 0x0000_0020;
/// Set `FD_CLOEXEC` on the new fd.
pub const FAN_CLOEXEC: u32 = 0x0000_0001;
/// Set `O_NONBLOCK` on the new fd.
pub const FAN_NONBLOCK: u32 = 0x0000_0002;

/// All valid option bits.
const VALID_FLAGS: u32 = FAN_CLASS_MASK
    | FAN_REPORT_FID
    | FAN_REPORT_DIR_FID
    | FAN_REPORT_NAME
    | FAN_REPORT_TID
    | FAN_UNLIMITED_QUEUE
    | FAN_UNLIMITED_MARKS
    | FAN_CLOEXEC
    | FAN_NONBLOCK;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Fanotify notification class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanotifyClass {
    /// Notification only (no access decisions).
    Notif,
    /// Content access — permission events for opened files.
    Content,
    /// Pre-content access — permission events before the file is fully opened.
    PreContent,
}

impl FanotifyClass {
    /// Parse from raw class bits.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` for unknown class values.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw & FAN_CLASS_MASK {
            FAN_CLASS_NOTIF => Ok(Self::Notif),
            FAN_CLASS_CONTENT => Ok(Self::Content),
            FAN_CLASS_PRE_CONTENT => Ok(Self::PreContent),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Whether this class allows permission decisions.
    pub fn allows_permission(&self) -> bool {
        match self {
            Self::Notif => false,
            Self::Content | Self::PreContent => true,
        }
    }
}

/// Parsed `fanotify_init` option flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FanotifyInitFlags {
    /// Whether the new fd should have `FD_CLOEXEC` set.
    pub cloexec: bool,
    /// Whether the new fd should be non-blocking.
    pub nonblock: bool,
    /// Whether to report with file ID.
    pub report_fid: bool,
    /// Whether to report with directory FID.
    pub report_dir_fid: bool,
    /// Whether to include file names in events.
    pub report_name: bool,
    /// Whether to report thread ID instead of thread group ID.
    pub report_tid: bool,
}

impl FanotifyInitFlags {
    /// Create a default (no-flags) value.
    pub const fn new() -> Self {
        Self {
            cloexec: false,
            nonblock: false,
            report_fid: false,
            report_dir_fid: false,
            report_name: false,
            report_tid: false,
        }
    }
}

/// Validated `fanotify_init` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanotifyInitRequest {
    /// The notification class.
    pub class: FanotifyClass,
    /// Parsed option flags.
    pub flags: FanotifyInitFlags,
    /// Raw `event_f_flags` (flags for file descriptors passed in events).
    pub event_f_flags: u32,
}

impl FanotifyInitRequest {
    /// Construct a new request.
    pub const fn new(class: FanotifyClass, flags: FanotifyInitFlags, event_f_flags: u32) -> Self {
        Self {
            class,
            flags,
            event_f_flags,
        }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `fanotify_init(2)`.
///
/// Validates `flags` and `event_f_flags`, parses the notification class, and
/// returns a structured request.  Caller must hold `CAP_SYS_ADMIN` for
/// `FAN_CLASS_CONTENT` or `FAN_CLASS_PRE_CONTENT`.
///
/// # Arguments
///
/// - `flags`        — combination of class bits and option flags
/// - `event_f_flags`— flags (e.g. `O_RDONLY`, `O_LARGEFILE`) for fds created
///   in event records
///
/// # Errors
///
/// | `Error`           | Condition                               |
/// |-------------------|-----------------------------------------|
/// | `InvalidArgument` | Unknown bits in `flags`                 |
/// | `PermissionDenied`| Privileged class requested without cap  |
pub fn do_fanotify_init(flags: u32, event_f_flags: u32) -> Result<FanotifyInitRequest> {
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    // Verify the class field is one of the valid values.
    let class_raw = flags & FAN_CLASS_MASK;
    if !VALID_CLASSES.contains(&class_raw) {
        return Err(Error::InvalidArgument);
    }
    let class = FanotifyClass::from_raw(flags)?;
    let parsed_flags = FanotifyInitFlags {
        cloexec: flags & FAN_CLOEXEC != 0,
        nonblock: flags & FAN_NONBLOCK != 0,
        report_fid: flags & FAN_REPORT_FID != 0,
        report_dir_fid: flags & FAN_REPORT_DIR_FID != 0,
        report_name: flags & FAN_REPORT_NAME != 0,
        report_tid: flags & FAN_REPORT_TID != 0,
    };
    Ok(FanotifyInitRequest::new(class, parsed_flags, event_f_flags))
}

/// Return `true` if the flags request an unlimited event queue.
pub fn is_unlimited_queue(flags: u32) -> bool {
    flags & FAN_UNLIMITED_QUEUE != 0
}

/// Return `true` if the flags request an unlimited number of marks.
pub fn is_unlimited_marks(flags: u32) -> bool {
    flags & FAN_UNLIMITED_MARKS != 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notif_class_ok() {
        let req = do_fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, 0).unwrap();
        assert_eq!(req.class, FanotifyClass::Notif);
        assert!(req.flags.cloexec);
    }

    #[test]
    fn content_class_ok() {
        let req = do_fanotify_init(FAN_CLASS_CONTENT, 0).unwrap();
        assert_eq!(req.class, FanotifyClass::Content);
        assert!(req.class.allows_permission());
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            do_fanotify_init(0xFFFF_0000, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unlimited_queue_detection() {
        assert!(is_unlimited_queue(FAN_CLASS_NOTIF | FAN_UNLIMITED_QUEUE));
        assert!(!is_unlimited_queue(FAN_CLASS_NOTIF));
    }

    #[test]
    fn unlimited_marks_detection() {
        assert!(is_unlimited_marks(FAN_UNLIMITED_MARKS));
        assert!(!is_unlimited_marks(0));
    }

    #[test]
    fn notif_class_no_permission() {
        let class = FanotifyClass::Notif;
        assert!(!class.allows_permission());
    }

    #[test]
    fn pre_content_class_allows_permission() {
        let class = FanotifyClass::PreContent;
        assert!(class.allows_permission());
    }
}
