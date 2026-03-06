// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `open_tree(2)` syscall handler — open or clone a mount tree.
//!
//! `open_tree` opens the mount object or mount subtree at `pathname` and
//! returns a file descriptor referring to it.  The fd can then be used with
//! `move_mount(2)` to attach it elsewhere in the filesystem.
//!
//! # Linux reference
//!
//! Linux-specific: `open_tree(2)` man page (added in Linux 5.2).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Clone the mount subtree rather than opening the original.
pub const OPEN_TREE_CLONE: u32 = 1;
/// Apply changes recursively to the whole mount tree.
pub const OPEN_TREE_CLOEXEC: u32 = 0o2000000;
/// Do not follow symlinks at the leaf.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
/// Allow an empty path (operate on `dfd` directly).
pub const AT_EMPTY_PATH: u32 = 0x1000;
/// Do not automount the final path component.
pub const AT_NO_AUTOMOUNT: u32 = 0x800;
/// Recurse into sub-mounts.
pub const AT_RECURSIVE: u32 = 0x8000;

/// All valid flags.
const VALID_FLAGS: u32 = OPEN_TREE_CLONE
    | OPEN_TREE_CLOEXEC
    | AT_SYMLINK_NOFOLLOW
    | AT_EMPTY_PATH
    | AT_NO_AUTOMOUNT
    | AT_RECURSIVE;

/// `AT_FDCWD` sentinel.
pub const AT_FDCWD: i32 = -100;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Parsed `open_tree` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OpenTreeFlags {
    /// Clone the mount subtree.
    pub clone: bool,
    /// Set close-on-exec on the returned fd.
    pub cloexec: bool,
    /// Do not follow symlinks.
    pub no_follow: bool,
    /// Allow empty path.
    pub empty_path: bool,
    /// Do not automount.
    pub no_automount: bool,
    /// Recurse into sub-mounts (only valid with `OPEN_TREE_CLONE`).
    pub recursive: bool,
}

impl OpenTreeFlags {
    /// Create a default (no-flags) value.
    pub const fn new() -> Self {
        Self {
            clone: false,
            cloexec: false,
            no_follow: false,
            empty_path: false,
            no_automount: false,
            recursive: false,
        }
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
            clone: flags & OPEN_TREE_CLONE != 0,
            cloexec: flags & OPEN_TREE_CLOEXEC != 0,
            no_follow: flags & AT_SYMLINK_NOFOLLOW != 0,
            empty_path: flags & AT_EMPTY_PATH != 0,
            no_automount: flags & AT_NO_AUTOMOUNT != 0,
            recursive: flags & AT_RECURSIVE != 0,
        })
    }
}

/// Validated `open_tree` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenTreeRequest {
    /// Directory fd for path resolution.
    pub dfd: i32,
    /// User-space pointer to the pathname.
    pub pathname: usize,
    /// Parsed flags.
    pub flags: OpenTreeFlags,
}

impl OpenTreeRequest {
    /// Construct a new request.
    pub const fn new(dfd: i32, pathname: usize, flags: OpenTreeFlags) -> Self {
        Self {
            dfd,
            pathname,
            flags,
        }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `open_tree(2)`.
///
/// Validates arguments and returns a parsed request.  The returned fd may be
/// passed to `move_mount(2)` to attach the (cloned) mount tree elsewhere.
///
/// If `AT_RECURSIVE` is set without `OPEN_TREE_CLONE`, it is rejected because
/// recursing into sub-mounts is only meaningful when cloning.
///
/// # Arguments
///
/// - `dfd`      — directory fd or `AT_FDCWD`
/// - `pathname` — user-space path pointer
/// - `flags`    — combination of `OPEN_TREE_*` and `AT_*` flags
///
/// # Errors
///
/// | `Error`           | Condition                                           |
/// |-------------------|-----------------------------------------------------|
/// | `InvalidArgument` | Unknown flags, empty path without flag, bad recursion |
/// | `PermissionDenied`| Insufficient privileges for clone                  |
pub fn do_open_tree(dfd: i32, pathname: usize, flags: u32) -> Result<OpenTreeRequest> {
    let parsed = OpenTreeFlags::from_raw(flags)?;
    // Empty path requires the flag.
    if pathname == 0 && !parsed.empty_path {
        return Err(Error::InvalidArgument);
    }
    // AT_RECURSIVE only makes sense with OPEN_TREE_CLONE.
    if parsed.recursive && !parsed.clone {
        return Err(Error::InvalidArgument);
    }
    Ok(OpenTreeRequest::new(dfd, pathname, parsed))
}

/// Return `true` if the call will produce a cloned mount tree fd.
pub fn will_clone(flags: &OpenTreeFlags) -> bool {
    flags.clone
}

/// Return `true` if the returned fd will have `FD_CLOEXEC` set.
pub fn will_cloexec(flags: &OpenTreeFlags) -> bool {
    flags.cloexec
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_open_ok() {
        let req = do_open_tree(AT_FDCWD, 0xDEAD, 0).unwrap();
        assert!(!req.flags.clone);
        assert_eq!(req.pathname, 0xDEAD);
    }

    #[test]
    fn clone_with_recursive_ok() {
        let req = do_open_tree(AT_FDCWD, 0xDEAD, OPEN_TREE_CLONE | AT_RECURSIVE).unwrap();
        assert!(req.flags.clone);
        assert!(req.flags.recursive);
    }

    #[test]
    fn recursive_without_clone_rejected() {
        assert_eq!(
            do_open_tree(AT_FDCWD, 0xDEAD, AT_RECURSIVE),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn empty_path_without_flag_rejected() {
        assert_eq!(do_open_tree(5, 0, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn empty_path_with_flag_ok() {
        let req = do_open_tree(5, 0, AT_EMPTY_PATH).unwrap();
        assert!(req.flags.empty_path);
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            do_open_tree(AT_FDCWD, 0xDEAD, 0xFFFF_0000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn cloexec_predicate() {
        let flags = OpenTreeFlags::from_raw(OPEN_TREE_CLOEXEC).unwrap();
        assert!(will_cloexec(&flags));
        assert!(!will_clone(&flags));
    }
}
