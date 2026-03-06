// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `execveat(2)` syscall handler.
//!
//! Implements fd-relative program execution per Linux `execveat(2)`.
//! This is the modern replacement for `execve` that supports
//! `AT_FDCWD`-relative paths, `AT_EMPTY_PATH` for fexecve-style
//! execution by file descriptor, and `AT_SYMLINK_NOFOLLOW`.
//!
//! Reference: Linux `execveat(2)`, POSIX.1-2024 `fexecve()` / `exec`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// AT_* flag constants
// ---------------------------------------------------------------------------

/// Special `dirfd` value meaning "use the current working directory".
pub const AT_FDCWD: i32 = -100;

/// If `pathname` is empty, operate on the file referred to by `dirfd`.
/// This enables fexecve-style execution.
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// Do not follow symbolic links when resolving `pathname`.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x0100;

/// Mask of all valid `execveat` flags.
const EXECVEAT_FLAGS_ALL: u32 = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW;

// ---------------------------------------------------------------------------
// ExecveAtArgs — repr(C) argument block
// ---------------------------------------------------------------------------

/// Arguments for the `execveat` system call.
///
/// Packed as `repr(C)` so it can be copied directly from user space
/// via `copy_from_user`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecveAtArgs {
    /// Directory file descriptor (or [`AT_FDCWD`]).
    pub dirfd: i32,
    /// User-space pointer to the pathname string.
    pub pathname_ptr: u64,
    /// User-space pointer to the argv array.
    pub argv_ptr: u64,
    /// User-space pointer to the envp array.
    pub envp_ptr: u64,
    /// Flags bitmask (`AT_EMPTY_PATH`, `AT_SYMLINK_NOFOLLOW`).
    pub flags: u32,
}

impl Default for ExecveAtArgs {
    fn default() -> Self {
        Self {
            dirfd: AT_FDCWD,
            pathname_ptr: 0,
            argv_ptr: 0,
            envp_ptr: 0,
            flags: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ResolvedPath — resolved pathname buffer
// ---------------------------------------------------------------------------

/// Maximum number of bytes in a resolved path (including NUL).
const RESOLVED_PATH_MAX: usize = 256;

/// A resolved absolute pathname produced by [`resolve_at`].
///
/// Contains up to [`RESOLVED_PATH_MAX`] bytes of the final path
/// after fd-relative resolution.
#[derive(Debug, Clone)]
pub struct ResolvedPath {
    /// Path bytes (not necessarily NUL-terminated within `len`).
    buf: [u8; RESOLVED_PATH_MAX],
    /// Number of valid bytes in `buf`.
    len: usize,
}

impl Default for ResolvedPath {
    fn default() -> Self {
        Self {
            buf: [0u8; RESOLVED_PATH_MAX],
            len: 0,
        }
    }
}

impl ResolvedPath {
    /// Return the resolved path as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Return the length of the resolved path in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return whether the resolved path is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ---------------------------------------------------------------------------
// Flag validation
// ---------------------------------------------------------------------------

/// Validate `execveat` flags.
///
/// Returns `Err(Error::InvalidArgument)` if any unknown flag bits are set.
pub fn validate_execveat_flags(flags: u32) -> Result<()> {
    if flags & !EXECVEAT_FLAGS_ALL != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// resolve_at — fd-relative path resolution
// ---------------------------------------------------------------------------

/// Resolve a pathname relative to a directory file descriptor.
///
/// Implements the `AT_FDCWD` and `AT_EMPTY_PATH` semantics:
///
/// - If `dirfd` is [`AT_FDCWD`] and `pathname` is non-empty, the
///   pathname is interpreted relative to the process CWD (standard
///   `execve` behavior).
/// - If `flags` includes [`AT_EMPTY_PATH`] and `pathname` is empty,
///   the file referred to by `dirfd` is used directly (fexecve
///   semantics).
/// - If `dirfd` refers to an open directory and `pathname` is
///   relative, the pathname is resolved relative to that directory.
/// - Absolute pathnames (starting with `b'/'`) ignore `dirfd`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `pathname` is empty without
///   `AT_EMPTY_PATH`, or `pathname` exceeds [`RESOLVED_PATH_MAX`].
pub fn resolve_at(dirfd: i32, pathname: &[u8], flags: u32) -> Result<ResolvedPath> {
    validate_execveat_flags(flags)?;

    // AT_EMPTY_PATH: pathname must be empty; use dirfd directly.
    if flags & AT_EMPTY_PATH != 0 {
        if !pathname.is_empty() {
            return Err(Error::InvalidArgument);
        }
        // In a real kernel we would look up the file backing `dirfd`
        // and use its path. Stub: produce a placeholder path.
        let placeholder = b"/proc/self/fd/";
        let mut resolved = ResolvedPath::default();
        let copy_len = placeholder.len().min(RESOLVED_PATH_MAX);
        resolved.buf[..copy_len].copy_from_slice(&placeholder[..copy_len]);
        resolved.len = copy_len;
        return Ok(resolved);
    }

    // Pathname must not be empty when AT_EMPTY_PATH is absent.
    if pathname.is_empty() {
        return Err(Error::InvalidArgument);
    }

    // Pathname must fit in the resolved buffer.
    if pathname.len() > RESOLVED_PATH_MAX {
        return Err(Error::InvalidArgument);
    }

    let mut resolved = ResolvedPath::default();

    if pathname.first() == Some(&b'/') {
        // Absolute path — dirfd is ignored.
        resolved.buf[..pathname.len()].copy_from_slice(pathname);
        resolved.len = pathname.len();
    } else if dirfd == AT_FDCWD {
        // Relative to CWD. Stub: prefix with "/cwd/".
        let prefix = b"/cwd/";
        let total = prefix.len() + pathname.len();
        if total > RESOLVED_PATH_MAX {
            return Err(Error::InvalidArgument);
        }
        resolved.buf[..prefix.len()].copy_from_slice(prefix);
        resolved.buf[prefix.len()..total].copy_from_slice(pathname);
        resolved.len = total;
    } else {
        // Relative to dirfd. Stub: prefix with "/fd/<dirfd>/".
        // In a real kernel we would look up the directory path from
        // the process file table.
        let prefix = b"/fd/";
        let total = prefix.len() + pathname.len();
        if total > RESOLVED_PATH_MAX {
            return Err(Error::InvalidArgument);
        }
        resolved.buf[..prefix.len()].copy_from_slice(prefix);
        resolved.buf[prefix.len()..total].copy_from_slice(pathname);
        resolved.len = total;
    }

    Ok(resolved)
}

// ---------------------------------------------------------------------------
// do_execveat — main syscall handler
// ---------------------------------------------------------------------------

/// `execveat` — execute a program relative to a directory file descriptor.
///
/// Validates the arguments, resolves the pathname via [`resolve_at`],
/// and delegates to the exec subsystem to load the new process image.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid flags, null pointers for
///   required fields, or path resolution failure.
/// - [`Error::NotFound`] — the resolved path does not exist.
/// - [`Error::PermissionDenied`] — insufficient permissions.
pub fn do_execveat(args: &ExecveAtArgs) -> Result<()> {
    // Validate flags first.
    validate_execveat_flags(args.flags)?;

    // argv_ptr must not be null (POSIX: argv[0] is required).
    if args.argv_ptr == 0 {
        return Err(Error::InvalidArgument);
    }

    // When AT_EMPTY_PATH is not set, pathname_ptr must be valid.
    if args.flags & AT_EMPTY_PATH == 0 && args.pathname_ptr == 0 {
        return Err(Error::InvalidArgument);
    }

    // Stub: in a real kernel we would copy_from_user to get the
    // pathname bytes. Use an empty slice for AT_EMPTY_PATH or a
    // placeholder for the non-empty case.
    let pathname: &[u8] = if args.flags & AT_EMPTY_PATH != 0 {
        b""
    } else {
        b"/stub/pathname"
    };

    // Resolve the path.
    let _resolved = resolve_at(args.dirfd, pathname, args.flags)?;

    // Stub: a real kernel would:
    // 1. Look up the inode from the resolved path.
    // 2. Check execute permission.
    // 3. Read the ELF header / shebang line.
    // 4. Set up the new address space, stack, argv, envp.
    // 5. Clear signal dispositions, close O_CLOEXEC fds.
    // 6. Jump to the entry point (no return on success).

    // For now, return NotImplemented to signal the stub nature.
    Err(Error::NotImplemented)
}
