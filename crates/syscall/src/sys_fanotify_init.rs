// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fanotify_init(2)` syscall handler — create a fanotify notification group.
//!
//! fanotify (file access notification) is a Linux subsystem that delivers
//! notification and permission events for filesystem activity.  A fanotify
//! group is the top-level handle: events are accumulated in the group's queue
//! and read by the user-space listener.
//!
//! # Syscall signature
//!
//! ```text
//! int fanotify_init(unsigned int flags, unsigned int event_f_flags);
//! ```
//!
//! # Priority classes
//!
//! | Constant | Description |
//! |----------|-------------|
//! | `FAN_CLASS_NOTIF` | Pure notification (no decision authority) |
//! | `FAN_CLASS_CONTENT` | Can veto file-open events (e.g. virus scanners) |
//! | `FAN_CLASS_PRE_CONTENT` | Can veto before data is available (e.g. HSM) |
//!
//! # Flags
//!
//! | Flag | Effect |
//! |------|--------|
//! | `FAN_CLOEXEC` | Set O_CLOEXEC on the group fd |
//! | `FAN_NONBLOCK` | Set O_NONBLOCK on the group fd |
//! | `FAN_UNLIMITED_QUEUE` | No limit on event queue depth (privileged) |
//! | `FAN_UNLIMITED_MARKS` | No limit on mark count (privileged) |
//! | `FAN_ENABLE_AUDIT` | Emit audit records for permission decisions |
//! | `FAN_REPORT_TID` | Report thread ID instead of PID |
//! | `FAN_REPORT_FID` | Report file identifier instead of fd |
//!
//! # POSIX conformance
//!
//! `fanotify_init` is a Linux extension (since Linux 2.6.36).  Not part of
//! POSIX.1-2024.  The closest POSIX primitive is the optional `<aio.h>`
//! notification model, but fanotify covers filesystem-scope monitoring.
//!
//! # References
//!
//! - Linux: `fs/notify/fanotify/fanotify_user.c`
//! - `fanotify_init(2)`, `fanotify(7)` man pages

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Priority class — bits 0-3 of flags
// ---------------------------------------------------------------------------

/// No content decision; pure notification listener.
pub const FAN_CLASS_NOTIF: u32 = 0x0000_0000;

/// Content class — can issue allow/deny decisions for file-open events.
pub const FAN_CLASS_CONTENT: u32 = 0x0000_0004;

/// Pre-content class — decisions before data pages are populated (HSM).
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;

/// Mask to extract the class bits.
const FAN_CLASS_MASK: u32 = 0x0000_000C;

// ---------------------------------------------------------------------------
// Init flags
// ---------------------------------------------------------------------------

/// Set `O_CLOEXEC` on the returned file descriptor.
pub const FAN_CLOEXEC: u32 = 0x0000_0001;

/// Set `O_NONBLOCK` on the returned file descriptor.
pub const FAN_NONBLOCK: u32 = 0x0000_0002;

/// Allow unlimited event queue depth (requires `CAP_SYS_ADMIN`).
pub const FAN_UNLIMITED_QUEUE: u32 = 0x0000_0010;

/// Allow unlimited mark count (requires `CAP_SYS_ADMIN`).
pub const FAN_UNLIMITED_MARKS: u32 = 0x0000_0020;

/// Emit audit records for permission decisions.
pub const FAN_ENABLE_AUDIT: u32 = 0x0000_0040;

/// Report thread ID in events instead of process ID.
pub const FAN_REPORT_TID: u32 = 0x0000_0100;

/// Report file identifier (fsid + file_handle) in events.
pub const FAN_REPORT_FID: u32 = 0x0000_0200;

/// Report directory file identifier in events.
pub const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;

/// Report event file name in events (requires `FAN_REPORT_DIR_FID`).
pub const FAN_REPORT_NAME: u32 = 0x0000_0800;

/// All valid init flag bits.
const FLAGS_VALID: u32 = FAN_CLOEXEC
    | FAN_NONBLOCK
    | FAN_UNLIMITED_QUEUE
    | FAN_UNLIMITED_MARKS
    | FAN_ENABLE_AUDIT
    | FAN_REPORT_TID
    | FAN_REPORT_FID
    | FAN_REPORT_DIR_FID
    | FAN_REPORT_NAME
    | FAN_CLASS_MASK;

// ---------------------------------------------------------------------------
// Capability constant
// ---------------------------------------------------------------------------

/// Linux capability required for `FAN_UNLIMITED_QUEUE` / `FAN_UNLIMITED_MARKS`.
const CAP_SYS_ADMIN: u32 = 21;

// ---------------------------------------------------------------------------
// Default queue / mark limits
// ---------------------------------------------------------------------------

/// Default maximum number of queued events (when not UNLIMITED).
const DEFAULT_QUEUE_LIMIT: u32 = 16_384;

/// Default maximum number of marks (when not UNLIMITED).
const DEFAULT_MARK_LIMIT: u32 = 8_192;

/// Sentinel for no limit.
const UNLIMITED: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// FanotifyClass — validated priority class
// ---------------------------------------------------------------------------

/// Priority class for a fanotify group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanotifyClass {
    /// Pure notification; no permission decisions.
    Notif,
    /// Content-level decisions (virus scanner use case).
    Content,
    /// Pre-content decisions (HSM / tiered-storage use case).
    PreContent,
}

impl FanotifyClass {
    /// Parse from the class bits of the `flags` argument.
    pub fn from_flags(flags: u32) -> Result<Self> {
        match flags & FAN_CLASS_MASK {
            0 => Ok(FanotifyClass::Notif),
            FAN_CLASS_CONTENT => Ok(FanotifyClass::Content),
            FAN_CLASS_PRE_CONTENT => Ok(FanotifyClass::PreContent),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// FanotifyGroupConfig — parsed and validated group configuration
// ---------------------------------------------------------------------------

/// Configuration of a newly created fanotify group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanotifyGroupConfig {
    /// Priority class.
    pub class: FanotifyClass,
    /// Whether `O_CLOEXEC` is set on the group fd.
    pub cloexec: bool,
    /// Whether `O_NONBLOCK` is set on the group fd.
    pub nonblock: bool,
    /// Whether audit records are emitted for decisions.
    pub audit: bool,
    /// Report thread IDs rather than process IDs.
    pub report_tid: bool,
    /// Report file identifiers in events.
    pub report_fid: bool,
    /// Report directory file identifiers.
    pub report_dir_fid: bool,
    /// Report file names.
    pub report_name: bool,
    /// Event queue depth limit (UNLIMITED = no limit).
    pub queue_limit: u32,
    /// Mark count limit (UNLIMITED = no limit).
    pub mark_limit: u32,
    /// Flags to apply to file descriptors in events (`event_f_flags`).
    pub event_f_flags: u32,
}

// ---------------------------------------------------------------------------
// FanotifyGroup — a live fanotify group
// ---------------------------------------------------------------------------

/// Maximum number of fanotify groups the subsystem tracks simultaneously.
const MAX_GROUPS: usize = 64;

/// A live fanotify notification group.
#[derive(Debug, Clone, Copy)]
pub struct FanotifyGroup {
    /// Unique group identifier (simulated fd).
    pub id: u32,
    /// Validated group configuration.
    pub config: FanotifyGroupConfig,
    /// Number of events currently queued.
    pub queued: u32,
    /// Number of marks currently installed.
    pub mark_count: u32,
    /// Whether this slot is active.
    pub active: bool,
}

impl FanotifyGroup {
    const fn inactive() -> Self {
        Self {
            id: 0,
            config: FanotifyGroupConfig {
                class: FanotifyClass::Notif,
                cloexec: false,
                nonblock: false,
                audit: false,
                report_tid: false,
                report_fid: false,
                report_dir_fid: false,
                report_name: false,
                queue_limit: DEFAULT_QUEUE_LIMIT,
                mark_limit: DEFAULT_MARK_LIMIT,
                event_f_flags: 0,
            },
            queued: 0,
            mark_count: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// FanotifySubsystem — global subsystem state
// ---------------------------------------------------------------------------

/// Global fanotify subsystem state.
pub struct FanotifySubsystem {
    groups: [FanotifyGroup; MAX_GROUPS],
    next_id: u32,
    /// Number of active groups.
    pub group_count: u32,
}

impl FanotifySubsystem {
    /// Create an empty subsystem.
    pub const fn new() -> Self {
        Self {
            groups: [const { FanotifyGroup::inactive() }; MAX_GROUPS],
            next_id: 1,
            group_count: 0,
        }
    }

    /// Allocate and initialise a new group.
    fn alloc_group(&mut self, config: FanotifyGroupConfig) -> Result<u32> {
        let slot = self
            .groups
            .iter()
            .position(|g| !g.active)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.groups[slot] = FanotifyGroup {
            id,
            config,
            queued: 0,
            mark_count: 0,
            active: true,
        };
        self.group_count += 1;
        Ok(id)
    }

    /// Retrieve a group by its fd/id.
    pub fn get_group(&self, id: u32) -> Option<&FanotifyGroup> {
        self.groups.iter().find(|g| g.active && g.id == id)
    }

    /// Destroy a group (called on fd close).
    pub fn destroy_group(&mut self, id: u32) {
        for g in self.groups.iter_mut() {
            if g.active && g.id == id {
                g.active = false;
                self.group_count = self.group_count.saturating_sub(1);
                return;
            }
        }
    }
}

impl Default for FanotifySubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_fanotify_init_handler — main entry point
// ---------------------------------------------------------------------------

/// Handle the `fanotify_init(2)` syscall.
///
/// Validates `flags` and `event_f_flags`, checks privileges for unlimited
/// resource flags, and creates a new fanotify group returning its identifier.
///
/// # Arguments
///
/// * `sys`          — Mutable fanotify subsystem state.
/// * `flags`        — Init flags: class + behaviour modifiers.
/// * `event_f_flags`— Open flags applied to file descriptors in delivered events.
/// * `caller_caps`  — Caller capability bitmask (for `CAP_SYS_ADMIN` check).
///
/// # Returns
///
/// Group identifier (simulating an fd) on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Unknown flag bits or invalid class combination.
/// * [`Error::PermissionDenied`] — `FAN_UNLIMITED_*` requested without `CAP_SYS_ADMIN`.
/// * [`Error::OutOfMemory`]      — Group table is full.
pub fn sys_fanotify_init_handler(
    sys: &mut FanotifySubsystem,
    flags: u32,
    event_f_flags: u32,
    caller_caps: u64,
) -> Result<u32> {
    // Reject unknown flag bits.
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }

    // FAN_REPORT_NAME requires FAN_REPORT_DIR_FID.
    if flags & FAN_REPORT_NAME != 0 && flags & FAN_REPORT_DIR_FID == 0 {
        return Err(Error::InvalidArgument);
    }

    // Unlimited resource flags require CAP_SYS_ADMIN.
    let needs_admin = (flags & FAN_UNLIMITED_QUEUE != 0) || (flags & FAN_UNLIMITED_MARKS != 0);
    if needs_admin && caller_caps & (1u64 << CAP_SYS_ADMIN) == 0 {
        return Err(Error::PermissionDenied);
    }

    let class = FanotifyClass::from_flags(flags)?;

    let queue_limit = if flags & FAN_UNLIMITED_QUEUE != 0 {
        UNLIMITED
    } else {
        DEFAULT_QUEUE_LIMIT
    };
    let mark_limit = if flags & FAN_UNLIMITED_MARKS != 0 {
        UNLIMITED
    } else {
        DEFAULT_MARK_LIMIT
    };

    let config = FanotifyGroupConfig {
        class,
        cloexec: flags & FAN_CLOEXEC != 0,
        nonblock: flags & FAN_NONBLOCK != 0,
        audit: flags & FAN_ENABLE_AUDIT != 0,
        report_tid: flags & FAN_REPORT_TID != 0,
        report_fid: flags & FAN_REPORT_FID != 0,
        report_dir_fid: flags & FAN_REPORT_DIR_FID != 0,
        report_name: flags & FAN_REPORT_NAME != 0,
        queue_limit,
        mark_limit,
        event_f_flags,
    };

    sys.alloc_group(config)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const CAP_ADMIN: u64 = 1u64 << CAP_SYS_ADMIN;

    #[test]
    fn basic_notif_group() {
        let mut sys = FanotifySubsystem::new();
        let id = sys_fanotify_init_handler(&mut sys, FAN_CLOEXEC, 0, 0).unwrap();
        let g = sys.get_group(id).unwrap();
        assert_eq!(g.config.class, FanotifyClass::Notif);
        assert!(g.config.cloexec);
        assert_eq!(g.config.queue_limit, DEFAULT_QUEUE_LIMIT);
        assert_eq!(sys.group_count, 1);
    }

    #[test]
    fn content_class() {
        let mut sys = FanotifySubsystem::new();
        let id =
            sys_fanotify_init_handler(&mut sys, FAN_CLASS_CONTENT | FAN_NONBLOCK, 0, 0).unwrap();
        let g = sys.get_group(id).unwrap();
        assert_eq!(g.config.class, FanotifyClass::Content);
        assert!(g.config.nonblock);
    }

    #[test]
    fn pre_content_class() {
        let mut sys = FanotifySubsystem::new();
        let id = sys_fanotify_init_handler(&mut sys, FAN_CLASS_PRE_CONTENT, 0, CAP_ADMIN).unwrap();
        let g = sys.get_group(id).unwrap();
        assert_eq!(g.config.class, FanotifyClass::PreContent);
    }

    #[test]
    fn unlimited_queue_requires_cap() {
        let mut sys = FanotifySubsystem::new();
        assert_eq!(
            sys_fanotify_init_handler(&mut sys, FAN_UNLIMITED_QUEUE, 0, 0),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn unlimited_queue_with_cap() {
        let mut sys = FanotifySubsystem::new();
        let id = sys_fanotify_init_handler(&mut sys, FAN_UNLIMITED_QUEUE, 0, CAP_ADMIN).unwrap();
        let g = sys.get_group(id).unwrap();
        assert_eq!(g.config.queue_limit, UNLIMITED);
    }

    #[test]
    fn unlimited_marks_with_cap() {
        let mut sys = FanotifySubsystem::new();
        let id = sys_fanotify_init_handler(&mut sys, FAN_UNLIMITED_MARKS, 0, CAP_ADMIN).unwrap();
        let g = sys.get_group(id).unwrap();
        assert_eq!(g.config.mark_limit, UNLIMITED);
    }

    #[test]
    fn unknown_flag_rejected() {
        let mut sys = FanotifySubsystem::new();
        assert_eq!(
            sys_fanotify_init_handler(&mut sys, 0x8000_0000, 0, CAP_ADMIN),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn report_name_without_dir_fid_rejected() {
        let mut sys = FanotifySubsystem::new();
        assert_eq!(
            sys_fanotify_init_handler(&mut sys, FAN_REPORT_NAME, 0, CAP_ADMIN),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn report_name_with_dir_fid_accepted() {
        let mut sys = FanotifySubsystem::new();
        let r =
            sys_fanotify_init_handler(&mut sys, FAN_REPORT_NAME | FAN_REPORT_DIR_FID, 0, CAP_ADMIN);
        assert!(r.is_ok());
    }

    #[test]
    fn event_f_flags_stored() {
        let mut sys = FanotifySubsystem::new();
        let id = sys_fanotify_init_handler(&mut sys, 0, 0o2000000, 0).unwrap();
        let g = sys.get_group(id).unwrap();
        assert_eq!(g.config.event_f_flags, 0o2000000);
    }

    #[test]
    fn destroy_group() {
        let mut sys = FanotifySubsystem::new();
        let id = sys_fanotify_init_handler(&mut sys, 0, 0, 0).unwrap();
        assert_eq!(sys.group_count, 1);
        sys.destroy_group(id);
        assert_eq!(sys.group_count, 0);
        assert!(sys.get_group(id).is_none());
    }

    #[test]
    fn multiple_groups_independent_ids() {
        let mut sys = FanotifySubsystem::new();
        let id1 = sys_fanotify_init_handler(&mut sys, 0, 0, 0).unwrap();
        let id2 = sys_fanotify_init_handler(&mut sys, FAN_CLOEXEC, 0, 0).unwrap();
        assert_ne!(id1, id2);
        assert_eq!(sys.group_count, 2);
    }
}
