// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `renameat(2)` syscall handler — rename a file using directory file descriptors.
//!
//! `renameat` renames a file, moving it from `oldpath` (relative to `olddirfd`)
//! to `newpath` (relative to `newdirfd`).  Using `AT_FDCWD` for either fd
//! makes the path relative to the current working directory, exactly as for
//! `rename(2)`.
//!
//! # Syscall signature
//!
//! ```text
//! int renameat(int olddirfd, const char *oldpath,
//!              int newdirfd, const char *newpath);
//! ```
//!
//! # POSIX Compliance
//!
//! Conforms to POSIX.1-2024 `renameat()` specification.
//!
//! # References
//!
//! - POSIX.1-2024: `stdio.h`, `renameat()`
//! - Linux: `fs/namei.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Use the current working directory instead of a directory fd.
pub const AT_FDCWD: i32 = -100;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Parameters for a `renameat` call.
#[derive(Debug, Clone, Copy)]
pub struct RenameatRequest {
    /// Directory fd for the old path, or `AT_FDCWD`.
    pub olddirfd: i32,
    /// User-space pointer to NUL-terminated old path.
    pub oldpath: u64,
    /// Directory fd for the new path, or `AT_FDCWD`.
    pub newdirfd: i32,
    /// User-space pointer to NUL-terminated new path.
    pub newpath: u64,
}

impl RenameatRequest {
    /// Create a new request.
    pub const fn new(olddirfd: i32, oldpath: u64, newdirfd: i32, newpath: u64) -> Self {
        Self {
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
        }
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<()> {
        // fd must be non-negative or exactly AT_FDCWD.
        if self.olddirfd != AT_FDCWD && self.olddirfd < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.newdirfd != AT_FDCWD && self.newdirfd < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.oldpath == 0 || self.newpath == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return whether the old path is relative to CWD.
    pub fn old_is_cwd_relative(&self) -> bool {
        self.olddirfd == AT_FDCWD
    }

    /// Return whether the new path is relative to CWD.
    pub fn new_is_cwd_relative(&self) -> bool {
        self.newdirfd == AT_FDCWD
    }
}

impl Default for RenameatRequest {
    fn default() -> Self {
        Self::new(AT_FDCWD, 0, AT_FDCWD, 0)
    }
}

/// Result of a rename operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct RenameatResult {
    /// Whether an existing target was replaced.
    pub replaced: bool,
}

impl RenameatResult {
    /// Create a new result.
    pub const fn new(replaced: bool) -> Self {
        Self { replaced }
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `renameat(2)` syscall.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid fd values or null path pointers.
/// - [`Error::NotFound`] — source path does not exist.
/// - [`Error::PermissionDenied`] — write permission denied on directory.
/// - [`Error::NotImplemented`] — VFS rename not yet wired.
pub fn sys_renameat(olddirfd: i32, oldpath: u64, newdirfd: i32, newpath: u64) -> Result<i64> {
    let req = RenameatRequest::new(olddirfd, oldpath, newdirfd, newpath);
    req.validate()?;
    do_renameat(&req)
}

fn do_renameat(req: &RenameatRequest) -> Result<i64> {
    let _ = req;
    // TODO: Resolve olddirfd + oldpath and newdirfd + newpath, perform VFS
    // rename with appropriate locking, update directory entries.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_renameat_syscall(
    olddirfd: i32,
    oldpath: u64,
    newdirfd: i32,
    newpath: u64,
) -> Result<i64> {
    sys_renameat(olddirfd, oldpath, newdirfd, newpath)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_oldpath_rejected() {
        assert_eq!(
            sys_renameat(AT_FDCWD, 0, AT_FDCWD, 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_newpath_rejected() {
        assert_eq!(
            sys_renameat(AT_FDCWD, 1, AT_FDCWD, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn invalid_olddirfd_rejected() {
        assert_eq!(
            sys_renameat(-5, 1, AT_FDCWD, 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn invalid_newdirfd_rejected() {
        assert_eq!(
            sys_renameat(AT_FDCWD, 1, -5, 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn at_fdcwd_both_valid() {
        let req = RenameatRequest::new(AT_FDCWD, 1, AT_FDCWD, 2);
        assert!(req.validate().is_ok());
        assert!(req.old_is_cwd_relative());
        assert!(req.new_is_cwd_relative());
    }

    #[test]
    fn positive_fds_valid() {
        let req = RenameatRequest::new(3, 1, 4, 2);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn result_default() {
        let r = RenameatResult::default();
        assert!(!r.replaced);
    }
}
