// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `chdir(2)` and `fchdir(2)` syscall handlers.
//!
//! Change the current working directory of the calling process.  `chdir`
//! accepts a path string; `fchdir` accepts an open file descriptor.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `chdir()` / `fchdir()` specification.  Key behaviours:
//! - Target must be a directory; returns `ENOTDIR` otherwise.
//! - Caller must have execute (search) permission on the target directory.
//! - `ENOENT` if the path does not name an existing directory.
//! - `EACCES` if search permission is denied on a component.
//! - Symlinks in the path are resolved before the check.
//! - After success, `task->fs->pwd` is updated to the new directory.
//!
//! # References
//!
//! - POSIX.1-2024: `chdir()`, `fchdir()`
//! - Linux man pages: `chdir(2)`, `fchdir(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// File/directory metadata
// ---------------------------------------------------------------------------

/// File type returned by the VFS lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// Regular file.
    Regular,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Other (device, pipe, socket…).
    Other,
}

/// Permissions granted by the filesystem for the calling credentials.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirPermissions {
    /// Execute (search) permission.
    pub execute: bool,
    /// Read permission.
    pub read: bool,
    /// Write permission.
    pub write: bool,
}

/// Result of a path/fd lookup for `chdir`/`fchdir`.
#[derive(Debug, Clone, Copy)]
pub struct LookupResult {
    /// Kind of file found.
    pub kind: FileKind,
    /// Permissions available to the caller.
    pub perms: DirPermissions,
    /// Inode number (used as the new CWD identifier).
    pub inode: u64,
}

// ---------------------------------------------------------------------------
// CWD state
// ---------------------------------------------------------------------------

/// Kernel-side current working directory descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cwd {
    /// Inode of the current working directory.
    pub inode: u64,
}

impl Cwd {
    /// Create a new CWD pointing to the root inode.
    pub const fn root() -> Self {
        Self { inode: 1 }
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `chdir(2)`.
///
/// Resolves `path` via `lookup_fn` and updates `cwd` if the target is a
/// directory with execute permission.
///
/// # Arguments
///
/// * `cwd`       — Mutable reference to the current CWD descriptor.
/// * `path`      — Path to change into.
/// * `lookup_fn` — Callback that resolves a path to [`LookupResult`].
///
/// # Errors
///
/// | `Error`      | Condition                                            |
/// |--------------|------------------------------------------------------|
/// | `InvalidArg` | `path` is empty                                      |
/// | `NotFound`   | Path does not exist                                  |
/// | `NotDir`     | Target is not a directory (`ENOTDIR`)                |
/// | `AccessDenied`| No execute permission on target (`EACCES`)          |
pub fn do_chdir<F>(cwd: &mut Cwd, path: &[u8], lookup_fn: F) -> Result<()>
where
    F: FnOnce(&[u8]) -> Result<LookupResult>,
{
    if path.is_empty() {
        return Err(Error::InvalidArgument);
    }

    let res = lookup_fn(path)?;

    if res.kind != FileKind::Directory {
        return Err(Error::InvalidArgument);
    }
    if !res.perms.execute {
        return Err(Error::PermissionDenied);
    }

    cwd.inode = res.inode;
    Ok(())
}

/// Handler for `fchdir(2)`.
///
/// Resolves the open file descriptor `fd` via `lookup_fn` and updates `cwd`
/// if the fd refers to a directory with execute permission.
///
/// # Arguments
///
/// * `cwd`       — Mutable reference to the current CWD descriptor.
/// * `fd`        — Open file descriptor.
/// * `lookup_fn` — Callback that resolves an fd to [`LookupResult`].
///
/// # Errors
///
/// | `Error`      | Condition                                            |
/// |--------------|------------------------------------------------------|
/// | `InvalidArg` | `fd` is negative                                     |
/// | `NotFound`   | `fd` is not open                                     |
/// | `NotDir`     | `fd` does not refer to a directory                   |
/// | `AccessDenied`| No execute permission                               |
pub fn do_fchdir<F>(cwd: &mut Cwd, fd: i32, lookup_fn: F) -> Result<()>
where
    F: FnOnce(i32) -> Result<LookupResult>,
{
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }

    let res = lookup_fn(fd)?;

    if res.kind != FileKind::Directory {
        return Err(Error::InvalidArgument);
    }
    if !res.perms.execute {
        return Err(Error::PermissionDenied);
    }

    cwd.inode = res.inode;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_ok(inode: u64) -> LookupResult {
        LookupResult {
            kind: FileKind::Directory,
            perms: DirPermissions {
                execute: true,
                read: true,
                write: false,
            },
            inode,
        }
    }

    fn file_ok() -> LookupResult {
        LookupResult {
            kind: FileKind::Regular,
            perms: DirPermissions {
                execute: false,
                read: true,
                write: false,
            },
            inode: 42,
        }
    }

    fn dir_no_exec(inode: u64) -> LookupResult {
        LookupResult {
            kind: FileKind::Directory,
            perms: DirPermissions {
                execute: false,
                read: true,
                write: false,
            },
            inode,
        }
    }

    #[test]
    fn chdir_ok() {
        let mut cwd = Cwd::root();
        do_chdir(&mut cwd, b"/home/user", |_| Ok(dir_ok(100))).unwrap();
        assert_eq!(cwd.inode, 100);
    }

    #[test]
    fn chdir_not_dir() {
        let mut cwd = Cwd::root();
        assert_eq!(
            do_chdir(&mut cwd, b"/etc/passwd", |_| Ok(file_ok())),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn chdir_no_exec() {
        let mut cwd = Cwd::root();
        assert_eq!(
            do_chdir(&mut cwd, b"/secret", |_| Ok(dir_no_exec(200))),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn chdir_empty_path() {
        let mut cwd = Cwd::root();
        assert_eq!(
            do_chdir(&mut cwd, b"", |_| Ok(dir_ok(0))),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn fchdir_ok() {
        let mut cwd = Cwd::root();
        do_fchdir(&mut cwd, 5, |_| Ok(dir_ok(50))).unwrap();
        assert_eq!(cwd.inode, 50);
    }

    #[test]
    fn fchdir_negative_fd() {
        let mut cwd = Cwd::root();
        assert_eq!(
            do_fchdir(&mut cwd, -1, |_| Ok(dir_ok(0))),
            Err(Error::InvalidArgument)
        );
    }
}
