// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Open flags — O_* constant definitions and flag validation utilities.
//!
//! Centralises POSIX `open(2)` flag semantics: access mode, creation flags,
//! and status flags, including validation and translation to internal VFS
//! representations.

use oncrix_lib::{Error, Result};

/// Access mode mask (O_RDONLY / O_WRONLY / O_RDWR occupy bits 0-1).
pub const O_ACCMODE: u32 = 0o000_003;

/// Open for reading only.
pub const O_RDONLY: u32 = 0o000_000;
/// Open for writing only.
pub const O_WRONLY: u32 = 0o000_001;
/// Open for reading and writing.
pub const O_RDWR: u32 = 0o000_002;

/// Creation and truncation flags (evaluated at `open` time).
/// Create file if it does not exist.
pub const O_CREAT: u32 = 0o000_100;
/// Exclusive create — fail if file exists (must be combined with O_CREAT).
pub const O_EXCL: u32 = 0o000_200;
/// Do not set the controlling terminal.
pub const O_NOCTTY: u32 = 0o000_400;
/// Truncate file to zero length on open.
pub const O_TRUNC: u32 = 0o001_000;

/// File status flags (may be changed after open via fcntl F_SETFL).
/// Writes append to end of file.
pub const O_APPEND: u32 = 0o002_000;
/// Non-blocking I/O.
pub const O_NONBLOCK: u32 = 0o004_000;
/// Synchronise writes to disk before returning.
pub const O_DSYNC: u32 = 0o010_000;
/// Full synchronisation (data + metadata).
pub const O_SYNC: u32 = 0o4_010_000;
/// Direct I/O — bypass page cache.
pub const O_DIRECT: u32 = 0o040_000;
/// Set close-on-exec flag atomically.
pub const O_CLOEXEC: u32 = 0o2_000_000;
/// Open directory (fail if not a directory).
pub const O_DIRECTORY: u32 = 0o200_000;
/// Do not follow symlinks in the final path component.
pub const O_NOFOLLOW: u32 = 0o400_000;
/// Open without updating atime.
pub const O_NOATIME: u32 = 0o1_000_000;
/// Open for path resolution only (no I/O).
pub const O_PATH: u32 = 0o10_000_000;

/// Combined set of flags that are valid for `open(2)`.
pub const VALID_OPEN_FLAGS: u32 = O_RDONLY
    | O_WRONLY
    | O_RDWR
    | O_CREAT
    | O_EXCL
    | O_NOCTTY
    | O_TRUNC
    | O_APPEND
    | O_NONBLOCK
    | O_DSYNC
    | O_SYNC
    | O_DIRECT
    | O_CLOEXEC
    | O_DIRECTORY
    | O_NOFOLLOW
    | O_NOATIME
    | O_PATH;

/// Decoded open flags in a structured form.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenFlags {
    /// Access mode: `O_RDONLY`, `O_WRONLY`, or `O_RDWR`.
    pub access: u32,
    /// Whether to create the file if missing.
    pub creat: bool,
    /// Whether to fail if the file already exists.
    pub excl: bool,
    /// Whether to truncate the file to zero length.
    pub trunc: bool,
    /// Whether writes append.
    pub append: bool,
    /// Whether I/O is non-blocking.
    pub nonblock: bool,
    /// Whether writes are synchronous.
    pub sync: bool,
    /// Whether to use direct I/O.
    pub direct: bool,
    /// Whether to set close-on-exec.
    pub cloexec: bool,
    /// Whether the target must be a directory.
    pub directory: bool,
    /// Whether to refuse symlink in final component.
    pub nofollow: bool,
    /// Whether to skip atime update.
    pub noatime: bool,
    /// Path-only open (no data I/O).
    pub path: bool,
}

impl OpenFlags {
    /// Decode a raw `open(2)` flags integer into a structured form.
    pub const fn from_raw(flags: u32) -> Self {
        Self {
            access: flags & O_ACCMODE,
            creat: (flags & O_CREAT) != 0,
            excl: (flags & O_EXCL) != 0,
            trunc: (flags & O_TRUNC) != 0,
            append: (flags & O_APPEND) != 0,
            nonblock: (flags & O_NONBLOCK) != 0,
            sync: (flags & O_SYNC) != 0,
            direct: (flags & O_DIRECT) != 0,
            cloexec: (flags & O_CLOEXEC) != 0,
            directory: (flags & O_DIRECTORY) != 0,
            nofollow: (flags & O_NOFOLLOW) != 0,
            noatime: (flags & O_NOATIME) != 0,
            path: (flags & O_PATH) != 0,
        }
    }

    /// Return `true` if the access mode allows reads.
    pub const fn readable(&self) -> bool {
        self.access == O_RDONLY || self.access == O_RDWR
    }

    /// Return `true` if the access mode allows writes.
    pub const fn writable(&self) -> bool {
        self.access == O_WRONLY || self.access == O_RDWR
    }

    /// Re-encode the flags as a raw integer.
    pub fn to_raw(&self) -> u32 {
        let mut f = self.access;
        if self.creat {
            f |= O_CREAT;
        }
        if self.excl {
            f |= O_EXCL;
        }
        if self.trunc {
            f |= O_TRUNC;
        }
        if self.append {
            f |= O_APPEND;
        }
        if self.nonblock {
            f |= O_NONBLOCK;
        }
        if self.sync {
            f |= O_SYNC;
        }
        if self.direct {
            f |= O_DIRECT;
        }
        if self.cloexec {
            f |= O_CLOEXEC;
        }
        if self.directory {
            f |= O_DIRECTORY;
        }
        if self.nofollow {
            f |= O_NOFOLLOW;
        }
        if self.noatime {
            f |= O_NOATIME;
        }
        if self.path {
            f |= O_PATH;
        }
        f
    }
}

/// Validate raw open flags from userspace.
///
/// Returns `Err(InvalidArgument)` for illegal flag combinations.
pub fn validate_open_flags(flags: u32) -> Result<OpenFlags> {
    // Reject unknown flags.
    if (flags & !VALID_OPEN_FLAGS) != 0 {
        return Err(Error::InvalidArgument);
    }

    let decoded = OpenFlags::from_raw(flags);

    // O_EXCL without O_CREAT is meaningless (not an error per POSIX, but
    // O_TRUNC on a non-writable open is).
    if decoded.trunc && !decoded.writable() && !decoded.path {
        return Err(Error::InvalidArgument);
    }

    // O_PATH is incompatible with O_CREAT, O_TRUNC, O_DIRECT.
    if decoded.path && (decoded.creat || decoded.trunc || decoded.direct) {
        return Err(Error::InvalidArgument);
    }

    Ok(decoded)
}

/// Return the status flags (those changeable via fcntl F_SETFL) from a raw flags value.
pub const fn status_flags(flags: u32) -> u32 {
    flags & (O_APPEND | O_NONBLOCK | O_DSYNC | O_SYNC | O_DIRECT | O_NOATIME)
}

/// Return the access mode from a raw flags value.
pub const fn access_mode(flags: u32) -> u32 {
    flags & O_ACCMODE
}

/// Check that an open file allows the given access (read or write).
pub fn check_access_mode(open_flags: &OpenFlags, want_read: bool, want_write: bool) -> Result<()> {
    if want_read && !open_flags.readable() && !open_flags.path {
        return Err(Error::PermissionDenied);
    }
    if want_write && !open_flags.writable() {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}
