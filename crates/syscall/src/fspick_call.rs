// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fspick(2)` syscall handler — select an existing mounted filesystem.
//!
//! `fspick` opens an existing mounted filesystem and returns a filesystem
//! context fd that can be used with `fsconfig(2)` to reconfigure it, similar
//! to how `fsopen(2)` creates a new filesystem context.
//!
//! # Linux reference
//!
//! Linux-specific: `fspick(2)` man page (added in Linux 5.2).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Set `FD_CLOEXEC` on the returned context fd.
pub const FSPICK_CLOEXEC: u32 = 0x0000_0001;
/// Do not follow symlinks when resolving the path.
pub const FSPICK_SYMLINK_NOFOLLOW: u32 = 0x0000_0002;
/// Do not automount the final path component.
pub const FSPICK_NO_AUTOMOUNT: u32 = 0x0000_0004;
/// Allow an empty path (operate on `dfd` directly).
pub const FSPICK_EMPTY_PATH: u32 = 0x0000_0008;

/// All valid flags.
const VALID_FLAGS: u32 =
    FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH;

/// `AT_FDCWD` sentinel.
pub const AT_FDCWD: i32 = -100;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Parsed `fspick` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FspickFlags {
    /// Set `FD_CLOEXEC` on the context fd.
    pub cloexec: bool,
    /// Do not follow symlinks.
    pub no_follow: bool,
    /// Do not automount.
    pub no_automount: bool,
    /// Allow empty path.
    pub empty_path: bool,
}

impl FspickFlags {
    /// Create a default (no-flags) value.
    pub const fn new() -> Self {
        Self {
            cloexec: false,
            no_follow: false,
            no_automount: false,
            empty_path: false,
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
            cloexec: flags & FSPICK_CLOEXEC != 0,
            no_follow: flags & FSPICK_SYMLINK_NOFOLLOW != 0,
            no_automount: flags & FSPICK_NO_AUTOMOUNT != 0,
            empty_path: flags & FSPICK_EMPTY_PATH != 0,
        })
    }

    /// Convert to a raw integer.
    pub fn to_raw(&self) -> u32 {
        let mut raw = 0u32;
        if self.cloexec {
            raw |= FSPICK_CLOEXEC;
        }
        if self.no_follow {
            raw |= FSPICK_SYMLINK_NOFOLLOW;
        }
        if self.no_automount {
            raw |= FSPICK_NO_AUTOMOUNT;
        }
        if self.empty_path {
            raw |= FSPICK_EMPTY_PATH;
        }
        raw
    }
}

/// Validated `fspick` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FspickRequest {
    /// Directory fd or `AT_FDCWD`.
    pub dfd: i32,
    /// User-space pointer to the pathname.
    pub pathname: usize,
    /// Parsed flags.
    pub flags: FspickFlags,
}

impl FspickRequest {
    /// Construct a new request.
    pub const fn new(dfd: i32, pathname: usize, flags: FspickFlags) -> Self {
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

/// Handler for `fspick(2)`.
///
/// Validates arguments and returns a structured request.  The kernel opens
/// the mounted filesystem at the given path and returns a reconfiguration
/// context fd.
///
/// # Arguments
///
/// - `dfd`      — directory fd or `AT_FDCWD`
/// - `pathname` — user-space path pointer
/// - `flags`    — combination of `FSPICK_*` flags
///
/// # Errors
///
/// | `Error`           | Condition                                        |
/// |-------------------|--------------------------------------------------|
/// | `InvalidArgument` | Unknown flags, null path without empty_path flag |
/// | `NotFound`        | Path does not refer to a mounted filesystem      |
/// | `PermissionDenied`| Insufficient privileges                          |
pub fn do_fspick(dfd: i32, pathname: usize, flags: u32) -> Result<FspickRequest> {
    let parsed = FspickFlags::from_raw(flags)?;
    if pathname == 0 && !parsed.empty_path {
        return Err(Error::InvalidArgument);
    }
    Ok(FspickRequest::new(dfd, pathname, parsed))
}

/// Return `true` if the context fd will have `FD_CLOEXEC` set.
pub fn is_cloexec(flags: &FspickFlags) -> bool {
    flags.cloexec
}

/// Return `true` if the resolution should skip automounting.
pub fn skips_automount(flags: &FspickFlags) -> bool {
    flags.no_automount
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_pick_ok() {
        let req = do_fspick(AT_FDCWD, 0xDEAD, 0).unwrap();
        assert_eq!(req.pathname, 0xDEAD);
        assert!(!req.flags.cloexec);
    }

    #[test]
    fn all_flags_ok() {
        let all =
            FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH;
        let req = do_fspick(5, 0, all).unwrap();
        assert!(req.flags.cloexec);
        assert!(req.flags.no_follow);
        assert!(req.flags.no_automount);
        assert!(req.flags.empty_path);
    }

    #[test]
    fn empty_path_without_flag_rejected() {
        assert_eq!(do_fspick(5, 0, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            do_fspick(AT_FDCWD, 0x1000, 0xFF00),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn cloexec_predicate() {
        let flags = FspickFlags::from_raw(FSPICK_CLOEXEC).unwrap();
        assert!(is_cloexec(&flags));
    }

    #[test]
    fn automount_predicate() {
        let flags = FspickFlags::from_raw(FSPICK_NO_AUTOMOUNT).unwrap();
        assert!(skips_automount(&flags));
    }

    #[test]
    fn flags_roundtrip() {
        let flags = FspickFlags {
            cloexec: true,
            no_follow: true,
            no_automount: false,
            empty_path: true,
        };
        let raw = flags.to_raw();
        let parsed = FspickFlags::from_raw(raw).unwrap();
        assert_eq!(parsed, flags);
    }
}
