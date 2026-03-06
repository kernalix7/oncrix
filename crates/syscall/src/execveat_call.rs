// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `execveat(2)` syscall handler.
//!
//! `execveat` is the directory-file-descriptor form of `execve`.  It executes
//! the program at `pathname` relative to the open directory `dirfd`, with the
//! same semantics as `execve` for argument and environment validation.
//!
//! When `pathname` is an empty string and `flags` contains `AT_EMPTY_PATH`,
//! the file referred to by `dirfd` itself is executed.
//!
//! # Syscall signature
//!
//! ```text
//! int execveat(int dirfd, const char *pathname,
//!              const char *const argv[], const char *const envp[],
//!              int flags);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 does not yet standardise `execveat`; this is a Linux 3.19+
//! extension.  The semantics of the path-resolution step follow POSIX
//! `openat(2)` conventions.
//!
//! # References
//!
//! - Linux: `fs/exec.c` `do_execveat_common()`
//! - `execveat(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flag constants
// ---------------------------------------------------------------------------

/// Use `dirfd` itself as the program file when `pathname` is empty.
pub const AT_EMPTY_PATH: i32 = 0x1000;

/// Do not dereference a symlink at the last path component.
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x0100;

/// Mask of all flags recognised by `execveat`.
const EXECVEAT_FLAGS_KNOWN: i32 = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW;

/// Sentinel for `dirfd` meaning the current working directory.
pub const AT_FDCWD: i32 = -100;

/// Maximum length of the pathname component (including NUL).
const PATHNAME_MAX: usize = 4096;

/// Maximum combined argv/envp string data (2 MiB + 4096).
const MAX_ARG_STRLEN: usize = 2 * 1024 * 1024 + 4096;

/// Maximum individual argument count.
const MAX_ARG_COUNT: usize = 0x7FFF_FFFF;

// ---------------------------------------------------------------------------
// ExecveatFlags — type-safe flag set
// ---------------------------------------------------------------------------

/// Validated flags passed to `execveat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecveatFlags {
    /// When true and pathname is empty, execute dirfd itself.
    pub empty_path: bool,
    /// When true, do not follow a trailing symlink.
    pub symlink_nofollow: bool,
}

impl ExecveatFlags {
    /// Parse and validate a raw flags integer.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] if unrecognised flag bits are set.
    pub fn from_raw(raw: i32) -> Result<Self> {
        if raw & !EXECVEAT_FLAGS_KNOWN != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            empty_path: raw & AT_EMPTY_PATH != 0,
            symlink_nofollow: raw & AT_SYMLINK_NOFOLLOW != 0,
        })
    }
}

// ---------------------------------------------------------------------------
// ExecveatArgs — validated argument set
// ---------------------------------------------------------------------------

/// Validated arguments for an `execveat` invocation.
///
/// This structure is constructed after all user-supplied arguments pass
/// validation and before the actual process image replacement begins.
#[derive(Debug, Clone, Copy)]
pub struct ExecveatArgs {
    /// Directory file descriptor (or `AT_FDCWD`).
    pub dirfd: i32,
    /// Flags controlling path resolution and execution.
    pub flags: ExecveatFlags,
    /// Length of `pathname` in bytes (not counting NUL).
    pub pathname_len: usize,
    /// Total byte length of all argv strings.
    pub argv_total_bytes: usize,
    /// Total byte length of all envp strings.
    pub envp_total_bytes: usize,
    /// Number of argv strings.
    pub argc: usize,
    /// Number of envp strings.
    pub envc: usize,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `dirfd`.
///
/// Accepts `AT_FDCWD` and any non-negative file descriptor.
fn validate_dirfd(dirfd: i32) -> Result<()> {
    if dirfd != AT_FDCWD && dirfd < 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate a pathname.
///
/// An empty pathname is only allowed when `AT_EMPTY_PATH` is set.
fn validate_pathname(pathname: &[u8], flags: &ExecveatFlags) -> Result<()> {
    if pathname.len() > PATHNAME_MAX {
        return Err(Error::InvalidArgument);
    }
    if pathname.is_empty() && !flags.empty_path {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate argv/envp argument lists.
///
/// Checks argument count and total string length.
fn validate_arg_list(args: &[&[u8]]) -> Result<(usize, usize)> {
    if args.len() > MAX_ARG_COUNT {
        return Err(Error::InvalidArgument);
    }
    let mut total: usize = 0;
    for arg in args {
        total = total.checked_add(arg.len()).ok_or(Error::InvalidArgument)?;
        if total > MAX_ARG_STRLEN {
            return Err(Error::InvalidArgument);
        }
    }
    Ok((args.len(), total))
}

// ---------------------------------------------------------------------------
// Public validation API
// ---------------------------------------------------------------------------

/// Validate all arguments to `execveat` and return a verified descriptor.
///
/// This is the kernel entry-point validation step.  If all arguments are
/// acceptable it returns [`ExecveatArgs`]; otherwise it returns the
/// appropriate `errno` equivalent.
///
/// # Arguments
///
/// * `dirfd`    — Directory file descriptor or `AT_FDCWD`.
/// * `pathname` — Path of the program relative to `dirfd`.
/// * `argv`     — Argument strings (including `argv[0]`).
/// * `envp`     — Environment strings.
/// * `flags`    — Raw `AT_*` flag bits.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — invalid `dirfd`, unknown flags,
///   pathname too long, empty pathname without `AT_EMPTY_PATH`, or
///   argument list too large.
pub fn validate_execveat(
    dirfd: i32,
    pathname: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
    flags_raw: i32,
) -> Result<ExecveatArgs> {
    validate_dirfd(dirfd)?;
    let flags = ExecveatFlags::from_raw(flags_raw)?;
    validate_pathname(pathname, &flags)?;
    let (argc, argv_bytes) = validate_arg_list(argv)?;
    let (envc, envp_bytes) = validate_arg_list(envp)?;

    Ok(ExecveatArgs {
        dirfd,
        flags,
        pathname_len: pathname.len(),
        argv_total_bytes: argv_bytes,
        envp_total_bytes: envp_bytes,
        argc,
        envc,
    })
}

// ---------------------------------------------------------------------------
// ResolvedExecPath — result of path resolution
// ---------------------------------------------------------------------------

/// How the program path was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedExecPath {
    /// Path was resolved relative to `dirfd`.
    RelativeToDir { dirfd: i32 },
    /// Path was resolved relative to the current working directory.
    RelativeToCwd,
    /// `dirfd` itself was used as the program file (`AT_EMPTY_PATH`).
    Fd { dirfd: i32 },
}

/// Compute the path resolution strategy for `execveat`.
///
/// Does not perform any actual file I/O; returns the resolution strategy
/// that the VFS layer should apply.
pub fn resolve_exec_path(dirfd: i32, pathname: &[u8], flags: &ExecveatFlags) -> ResolvedExecPath {
    if pathname.is_empty() && flags.empty_path {
        return ResolvedExecPath::Fd { dirfd };
    }
    if dirfd == AT_FDCWD {
        return ResolvedExecPath::RelativeToCwd;
    }
    ResolvedExecPath::RelativeToDir { dirfd }
}

// ---------------------------------------------------------------------------
// sys_execveat — entry point
// ---------------------------------------------------------------------------

/// Syscall entry point for `execveat(2)`.
///
/// Validates all arguments and returns the path resolution strategy.
/// Actual process image replacement is handled by the process subsystem.
///
/// # Errors
///
/// See [`validate_execveat`].
pub fn sys_execveat(
    dirfd: i32,
    pathname: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
    flags_raw: i32,
) -> Result<(ExecveatArgs, ResolvedExecPath)> {
    let args = validate_execveat(dirfd, pathname, argv, envp, flags_raw)?;
    let path = resolve_exec_path(dirfd, pathname, &args.flags);
    Ok((args, path))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_relative_path() {
        let (args, path) = sys_execveat(3, b"bin/sh", &[b"sh".as_ref()], &[], 0).unwrap();
        assert_eq!(args.dirfd, 3);
        assert_eq!(args.argc, 1);
        assert_eq!(path, ResolvedExecPath::RelativeToDir { dirfd: 3 });
    }

    #[test]
    fn at_fdcwd() {
        let (_, path) = sys_execveat(AT_FDCWD, b"/usr/bin/ls", &[b"ls".as_ref()], &[], 0).unwrap();
        assert_eq!(path, ResolvedExecPath::RelativeToCwd);
    }

    #[test]
    fn at_empty_path() {
        let (args, path) = sys_execveat(5, b"", &[b"prog".as_ref()], &[], AT_EMPTY_PATH).unwrap();
        assert!(args.flags.empty_path);
        assert_eq!(path, ResolvedExecPath::Fd { dirfd: 5 });
    }

    #[test]
    fn empty_pathname_without_flag_rejected() {
        assert_eq!(
            sys_execveat(3, b"", &[b"prog".as_ref()], &[], 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_execveat(3, b"prog", &[b"prog".as_ref()], &[], 0x0001),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn negative_dirfd_rejected() {
        assert_eq!(
            sys_execveat(-2, b"prog", &[b"prog".as_ref()], &[], 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn flags_symlink_nofollow() {
        let (args, _) =
            sys_execveat(3, b"prog", &[b"prog".as_ref()], &[], AT_SYMLINK_NOFOLLOW).unwrap();
        assert!(args.flags.symlink_nofollow);
    }

    #[test]
    fn pathname_too_long() {
        let long = [b'a'; 4097];
        assert_eq!(
            sys_execveat(AT_FDCWD, &long, &[b"prog".as_ref()], &[], 0),
            Err(Error::InvalidArgument)
        );
    }
}
