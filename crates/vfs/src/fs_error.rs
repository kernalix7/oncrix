// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VFS error classification and context types.
//!
//! Provides structured error context for VFS operations, extending
//! the base `oncrix_lib::Error` with filesystem-specific error codes
//! and operation context for better diagnostic information.

use oncrix_lib::{Error, Result};

/// VFS operation types for error context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsOp {
    /// Read data from a file.
    Read,
    /// Write data to a file.
    Write,
    /// Open a file.
    Open,
    /// Create a file.
    Create,
    /// Delete a file or directory.
    Unlink,
    /// Rename a file.
    Rename,
    /// Look up a path component.
    Lookup,
    /// Mount a filesystem.
    Mount,
    /// Unmount a filesystem.
    Umount,
    /// Stat a file.
    Stat,
    /// Change file permissions.
    Chmod,
    /// Change file ownership.
    Chown,
    /// Truncate a file.
    Truncate,
    /// Create a hard link.
    Link,
    /// Create a symbolic link.
    Symlink,
    /// Read a directory.
    Readdir,
    /// Sync file data.
    Fsync,
    /// Get/set extended attributes.
    Xattr,
    /// File locking.
    Flock,
}

impl VfsOp {
    /// Return a short string name for the operation.
    pub fn name(self) -> &'static str {
        match self {
            VfsOp::Read => "read",
            VfsOp::Write => "write",
            VfsOp::Open => "open",
            VfsOp::Create => "create",
            VfsOp::Unlink => "unlink",
            VfsOp::Rename => "rename",
            VfsOp::Lookup => "lookup",
            VfsOp::Mount => "mount",
            VfsOp::Umount => "umount",
            VfsOp::Stat => "stat",
            VfsOp::Chmod => "chmod",
            VfsOp::Chown => "chown",
            VfsOp::Truncate => "truncate",
            VfsOp::Link => "link",
            VfsOp::Symlink => "symlink",
            VfsOp::Readdir => "readdir",
            VfsOp::Fsync => "fsync",
            VfsOp::Xattr => "xattr",
            VfsOp::Flock => "flock",
        }
    }
}

/// Error context for a VFS operation failure.
#[derive(Debug, Clone, Copy)]
pub struct VfsError {
    /// Underlying error code.
    pub error: Error,
    /// Operation that failed.
    pub op: VfsOp,
    /// Inode number involved (0 = unknown).
    pub ino: u64,
    /// Mount ID involved (0 = unknown).
    pub mount_id: u32,
}

impl VfsError {
    /// Create a new VFS error.
    pub const fn new(error: Error, op: VfsOp, ino: u64, mount_id: u32) -> Self {
        VfsError {
            error,
            op,
            ino,
            mount_id,
        }
    }

    /// Create a permission denied error for an operation.
    pub const fn permission(op: VfsOp, ino: u64) -> Self {
        VfsError {
            error: Error::PermissionDenied,
            op,
            ino,
            mount_id: 0,
        }
    }

    /// Create a not found error for an operation.
    pub const fn not_found(op: VfsOp, ino: u64) -> Self {
        VfsError {
            error: Error::NotFound,
            op,
            ino,
            mount_id: 0,
        }
    }

    /// Create a busy error for an operation.
    pub const fn busy(op: VfsOp, ino: u64) -> Self {
        VfsError {
            error: Error::Busy,
            op,
            ino,
            mount_id: 0,
        }
    }

    /// Convert to an `oncrix_lib::Error`.
    pub fn into_error(self) -> Error {
        self.error
    }
}

/// Error counter for a filesystem or VFS subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct ErrorCounter {
    /// Number of permission denied errors.
    pub perm_denied: u64,
    /// Number of not found errors.
    pub not_found: u64,
    /// Number of I/O errors.
    pub io_errors: u64,
    /// Number of out-of-memory errors.
    pub oom: u64,
    /// Number of other errors.
    pub other: u64,
    /// Total error count.
    pub total: u64,
}

impl ErrorCounter {
    /// Create a new zeroed counter.
    pub const fn new() -> Self {
        ErrorCounter {
            perm_denied: 0,
            not_found: 0,
            io_errors: 0,
            oom: 0,
            other: 0,
            total: 0,
        }
    }

    /// Record an error.
    pub fn record(&mut self, error: Error) {
        self.total = self.total.saturating_add(1);
        match error {
            Error::PermissionDenied => self.perm_denied = self.perm_denied.saturating_add(1),
            Error::NotFound => self.not_found = self.not_found.saturating_add(1),
            Error::IoError => self.io_errors = self.io_errors.saturating_add(1),
            Error::OutOfMemory => self.oom = self.oom.saturating_add(1),
            _ => self.other = self.other.saturating_add(1),
        }
    }

    /// Reset all counters to zero.
    pub fn reset(&mut self) {
        *self = ErrorCounter::new();
    }
}

/// Error recovery hints for VFS errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryHint {
    /// The error is permanent; no retry should be attempted.
    Fatal,
    /// The error may be transient; caller may retry.
    Retryable,
    /// The caller should wait and retry.
    WaitAndRetry,
    /// The caller should reduce the request size.
    ReduceSize,
}

/// Classify an error to determine if it is recoverable.
pub fn classify_error(error: Error) -> RecoveryHint {
    match error {
        Error::WouldBlock | Error::Interrupted => RecoveryHint::WaitAndRetry,
        Error::Busy => RecoveryHint::Retryable,
        Error::OutOfMemory => RecoveryHint::ReduceSize,
        Error::IoError => RecoveryHint::Retryable,
        _ => RecoveryHint::Fatal,
    }
}

/// Wrap an operation result with VFS error context.
///
/// On success, passes through the value. On failure, records the error.
pub fn with_context<T>(
    result: Result<T>,
    op: VfsOp,
    ino: u64,
    counter: &mut ErrorCounter,
) -> core::result::Result<T, VfsError> {
    match result {
        Ok(v) => Ok(v),
        Err(e) => {
            counter.record(e);
            Err(VfsError::new(e, op, ino, 0))
        }
    }
}

/// Filesystem-level health indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsHealth {
    /// Filesystem is operating normally.
    Healthy,
    /// Filesystem has recoverable errors.
    Degraded,
    /// Filesystem is in a read-only error state.
    ReadOnly,
    /// Filesystem is failed and must be unmounted.
    Failed,
}

/// Evaluate filesystem health based on error counters.
pub fn evaluate_health(counter: &ErrorCounter, total_ops: u64) -> FsHealth {
    if total_ops == 0 {
        return FsHealth::Healthy;
    }
    let error_rate = (counter.io_errors * 100)
        .checked_div(total_ops)
        .unwrap_or(0);
    match error_rate {
        0 => FsHealth::Healthy,
        1..=5 => FsHealth::Degraded,
        6..=50 => FsHealth::ReadOnly,
        _ => FsHealth::Failed,
    }
}
