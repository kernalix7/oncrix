// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fsmount(2)` syscall handler — create a mount for a filesystem context.
//!
//! `fsmount` creates a mount object for the filesystem created by a prior
//! `fsopen(2)` + `fsconfig(2)` sequence.  The returned fd can be passed to
//! `move_mount(2)` to attach the mount tree to the filesystem hierarchy.
//!
//! # Linux reference
//!
//! Linux-specific: `fsmount(2)` man page (added in Linux 5.2).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Set `FD_CLOEXEC` on the returned mount fd.
pub const FSMOUNT_CLOEXEC: u32 = 0x0000_0001;

/// All valid `fsmount` flags.
const VALID_FLAGS: u32 = FSMOUNT_CLOEXEC;

// ---------------------------------------------------------------------------
// Mount attribute flags (subset, for mount-time options)
// ---------------------------------------------------------------------------

/// Make the mount read-only.
pub const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
/// Don't honor set-user-ID and set-group-ID bits.
pub const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
/// Don't allow access to device special files.
pub const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
/// Don't allow program execution.
pub const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;
/// Don't update access times.
pub const MOUNT_ATTR_NOATIME: u64 = 0x0000_0010;
/// Don't update directory access times.
pub const MOUNT_ATTR_NODIRATIME: u64 = 0x0000_0080;

/// All valid mount attribute bits for `fsmount`.
const VALID_ATTR: u64 = MOUNT_ATTR_RDONLY
    | MOUNT_ATTR_NOSUID
    | MOUNT_ATTR_NODEV
    | MOUNT_ATTR_NOEXEC
    | MOUNT_ATTR_NOATIME
    | MOUNT_ATTR_NODIRATIME;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Parsed `fsmount` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsmountFlags {
    /// Set `FD_CLOEXEC` on the returned fd.
    pub cloexec: bool,
}

impl FsmountFlags {
    /// Create a default (no-flags) value.
    pub const fn new() -> Self {
        Self { cloexec: false }
    }

    /// Parse from a raw integer.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if unknown bits are set.
    pub fn from_raw(flags: u32) -> Result<Self> {
        if flags & !VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            cloexec: flags & FSMOUNT_CLOEXEC != 0,
        })
    }
}

/// Mount attributes supplied at `fsmount` time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsmountAttr {
    /// Mount attribute bits to set.
    pub attr_set: u64,
}

impl FsmountAttr {
    /// Construct a new (empty) attribute set.
    pub const fn new() -> Self {
        Self { attr_set: 0 }
    }

    /// Validate that only known bits are set.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if unknown bits are present.
    pub fn validate(&self) -> Result<()> {
        if self.attr_set & !VALID_ATTR != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

/// Validated `fsmount` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsmountRequest {
    /// Filesystem context fd (from `fsopen`).
    pub fs_fd: i32,
    /// Parsed flags.
    pub flags: FsmountFlags,
    /// Mount attributes to apply.
    pub attr: FsmountAttr,
}

impl FsmountRequest {
    /// Construct a new request.
    pub const fn new(fs_fd: i32, flags: FsmountFlags, attr: FsmountAttr) -> Self {
        Self { fs_fd, flags, attr }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `fsmount(2)`.
///
/// Validates arguments and returns a structured request.  The kernel creates
/// a detached mount from the filesystem context and returns an fd that can be
/// passed to `move_mount(2)`.
///
/// # Arguments
///
/// - `fs_fd`  — filesystem context fd (created with `fsopen`)
/// - `flags`  — `FSMOUNT_CLOEXEC` or zero
/// - `attr`   — mount attributes to apply at mount time
///
/// # Errors
///
/// | `Error`           | Condition                                      |
/// |-------------------|------------------------------------------------|
/// | `InvalidArgument` | Negative fs_fd, unknown flags, bad attr bits   |
/// | `NotFound`        | `fs_fd` is not a valid filesystem context      |
/// | `Busy`            | Context is not in the created phase            |
pub fn do_fsmount(fs_fd: i32, flags: u32, attr: FsmountAttr) -> Result<FsmountRequest> {
    if fs_fd < 0 {
        return Err(Error::InvalidArgument);
    }
    let parsed_flags = FsmountFlags::from_raw(flags)?;
    attr.validate()?;
    Ok(FsmountRequest::new(fs_fd, parsed_flags, attr))
}

/// Return `true` if the mount will be read-only.
pub fn is_readonly(attr: &FsmountAttr) -> bool {
    attr.attr_set & MOUNT_ATTR_RDONLY != 0
}

/// Return `true` if the mount disallows execution.
pub fn is_noexec(attr: &FsmountAttr) -> bool {
    attr.attr_set & MOUNT_ATTR_NOEXEC != 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_fsmount_ok() {
        let attr = FsmountAttr::new();
        let req = do_fsmount(3, 0, attr).unwrap();
        assert_eq!(req.fs_fd, 3);
        assert!(!req.flags.cloexec);
    }

    #[test]
    fn cloexec_ok() {
        let attr = FsmountAttr::new();
        let req = do_fsmount(3, FSMOUNT_CLOEXEC, attr).unwrap();
        assert!(req.flags.cloexec);
    }

    #[test]
    fn negative_fd_rejected() {
        let attr = FsmountAttr::new();
        assert_eq!(do_fsmount(-1, 0, attr), Err(Error::InvalidArgument));
    }

    #[test]
    fn unknown_flags_rejected() {
        let attr = FsmountAttr::new();
        assert_eq!(do_fsmount(3, 0xFF, attr), Err(Error::InvalidArgument));
    }

    #[test]
    fn invalid_attr_bits_rejected() {
        let attr = FsmountAttr {
            attr_set: 0xFFFF_FFFF_0000_0000,
        };
        assert_eq!(do_fsmount(3, 0, attr), Err(Error::InvalidArgument));
    }

    #[test]
    fn readonly_attr_ok() {
        let attr = FsmountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
        };
        let req = do_fsmount(5, 0, attr).unwrap();
        assert!(is_readonly(&req.attr));
        assert!(!is_noexec(&req.attr));
    }

    #[test]
    fn noexec_attr_ok() {
        let attr = FsmountAttr {
            attr_set: MOUNT_ATTR_NOEXEC,
        };
        let req = do_fsmount(5, 0, attr).unwrap();
        assert!(is_noexec(&req.attr));
    }
}
