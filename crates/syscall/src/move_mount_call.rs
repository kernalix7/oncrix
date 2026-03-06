// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `move_mount(2)` syscall handler — move a mount from one place to another.
//!
//! `move_mount` moves a mount or an open mount fd to a destination path.  It
//! was added in Linux 5.2 as part of the new mount API alongside `open_tree`,
//! `fsopen`, and `fsmount`.
//!
//! # Linux reference
//!
//! Linux-specific: `move_mount(2)` man page.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Do not follow symlinks for the from path.
pub const MOVE_MOUNT_F_SYMLINKS: u32 = 0x0000_0001;
/// Do not automount the from path.
pub const MOVE_MOUNT_F_AUTOMOUNTS: u32 = 0x0000_0002;
/// Allow an empty from path (use `from_dfd` directly).
pub const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x0000_0004;
/// Do not follow symlinks for the to path.
pub const MOVE_MOUNT_T_SYMLINKS: u32 = 0x0000_0010;
/// Do not automount the to path.
pub const MOVE_MOUNT_T_AUTOMOUNTS: u32 = 0x0000_0020;
/// Allow an empty to path (use `to_dfd` directly).
pub const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0x0000_0040;
/// Set the group ID of the mount to match the destination.
pub const MOVE_MOUNT_SET_GROUP: u32 = 0x0000_0100;
/// Beneath mode — attach under the destination.
pub const MOVE_MOUNT_BENEATH: u32 = 0x0000_0200;

/// All valid flags.
const VALID_FLAGS: u32 = MOVE_MOUNT_F_SYMLINKS
    | MOVE_MOUNT_F_AUTOMOUNTS
    | MOVE_MOUNT_F_EMPTY_PATH
    | MOVE_MOUNT_T_SYMLINKS
    | MOVE_MOUNT_T_AUTOMOUNTS
    | MOVE_MOUNT_T_EMPTY_PATH
    | MOVE_MOUNT_SET_GROUP
    | MOVE_MOUNT_BENEATH;

/// `AT_FDCWD` sentinel.
pub const AT_FDCWD: i32 = -100;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Describes the source path of a `move_mount` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveMountFrom {
    /// Directory fd or `AT_FDCWD`.
    pub from_dfd: i32,
    /// User-space pointer to the path string (may be 0 with `MOVE_MOUNT_F_EMPTY_PATH`).
    pub from_pathname: usize,
}

impl MoveMountFrom {
    /// Construct a new source descriptor.
    pub const fn new(from_dfd: i32, from_pathname: usize) -> Self {
        Self {
            from_dfd,
            from_pathname,
        }
    }
}

impl Default for MoveMountFrom {
    fn default() -> Self {
        Self::new(AT_FDCWD, 0)
    }
}

/// Describes the destination path of a `move_mount` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveMountTo {
    /// Directory fd or `AT_FDCWD`.
    pub to_dfd: i32,
    /// User-space pointer to the path string (may be 0 with `MOVE_MOUNT_T_EMPTY_PATH`).
    pub to_pathname: usize,
}

impl MoveMountTo {
    /// Construct a new destination descriptor.
    pub const fn new(to_dfd: i32, to_pathname: usize) -> Self {
        Self {
            to_dfd,
            to_pathname,
        }
    }
}

impl Default for MoveMountTo {
    fn default() -> Self {
        Self::new(AT_FDCWD, 0)
    }
}

/// Validated `move_mount` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveMountRequest {
    /// Source descriptor.
    pub from: MoveMountFrom,
    /// Destination descriptor.
    pub to: MoveMountTo,
    /// Validated flags.
    pub flags: u32,
}

impl MoveMountRequest {
    /// Construct a new request.
    pub const fn new(from: MoveMountFrom, to: MoveMountTo, flags: u32) -> Self {
        Self { from, to, flags }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `move_mount(2)`.
///
/// Validates arguments and returns a parsed request.  The caller requires
/// `CAP_SYS_ADMIN` or appropriate user namespace privileges.
///
/// # Arguments
///
/// - `from_dfd`      — source directory fd or `AT_FDCWD`
/// - `from_pathname` — source path pointer
/// - `to_dfd`        — destination directory fd or `AT_FDCWD`
/// - `to_pathname`   — destination path pointer
/// - `flags`         — combination of `MOVE_MOUNT_*` flags
///
/// # Errors
///
/// | `Error`           | Condition                                       |
/// |-------------------|-------------------------------------------------|
/// | `InvalidArgument` | Unknown flags, empty path without empty-path flag |
/// | `PermissionDenied`| Insufficient privileges                         |
pub fn do_move_mount(
    from_dfd: i32,
    from_pathname: usize,
    to_dfd: i32,
    to_pathname: usize,
    flags: u32,
) -> Result<MoveMountRequest> {
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    // If from_pathname is null, `MOVE_MOUNT_F_EMPTY_PATH` must be set.
    if from_pathname == 0 && flags & MOVE_MOUNT_F_EMPTY_PATH == 0 {
        return Err(Error::InvalidArgument);
    }
    // If to_pathname is null, `MOVE_MOUNT_T_EMPTY_PATH` must be set.
    if to_pathname == 0 && flags & MOVE_MOUNT_T_EMPTY_PATH == 0 {
        return Err(Error::InvalidArgument);
    }
    let from = MoveMountFrom::new(from_dfd, from_pathname);
    let to = MoveMountTo::new(to_dfd, to_pathname);
    Ok(MoveMountRequest::new(from, to, flags))
}

/// Return `true` if the request sets the mount group.
pub fn sets_group(flags: u32) -> bool {
    flags & MOVE_MOUNT_SET_GROUP != 0
}

/// Return `true` if the request uses beneath-mode attachment.
pub fn is_beneath(flags: u32) -> bool {
    flags & MOVE_MOUNT_BENEATH != 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_move_ok() {
        let req = do_move_mount(AT_FDCWD, 0xDEAD, AT_FDCWD, 0xBEEF, 0).unwrap();
        assert_eq!(req.from.from_pathname, 0xDEAD);
        assert_eq!(req.to.to_pathname, 0xBEEF);
    }

    #[test]
    fn empty_from_path_with_flag_ok() {
        let req = do_move_mount(5, 0, AT_FDCWD, 0xBEEF, MOVE_MOUNT_F_EMPTY_PATH).unwrap();
        assert_eq!(req.from.from_dfd, 5);
    }

    #[test]
    fn empty_from_path_without_flag_rejected() {
        assert_eq!(
            do_move_mount(5, 0, AT_FDCWD, 0xBEEF, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn empty_to_path_without_flag_rejected() {
        assert_eq!(
            do_move_mount(AT_FDCWD, 0xDEAD, 5, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            do_move_mount(AT_FDCWD, 0xDEAD, AT_FDCWD, 0xBEEF, 0xFFFF_0000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn beneath_detection() {
        assert!(is_beneath(MOVE_MOUNT_BENEATH));
        assert!(!is_beneath(0));
    }

    #[test]
    fn sets_group_detection() {
        assert!(sets_group(MOVE_MOUNT_SET_GROUP));
        assert!(!sets_group(0));
    }
}
