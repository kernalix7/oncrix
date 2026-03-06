// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended `pidfd_getfd` syscall with access control and auditing.
//!
//! `pidfd_getfd` duplicates a file descriptor from another process
//! identified by a pidfd. This extended module adds privilege checks,
//! audit logging, and fd type filtering.
//!
//! Linux-specific. Not in POSIX.

use oncrix_lib::{Error, Result};

/// File descriptor type filter flags for pidfd_getfd_ext.
pub struct FdTypeFilter;

impl FdTypeFilter {
    /// Allow duplicating regular file fds.
    pub const REGULAR: u32 = 0x01;
    /// Allow duplicating socket fds.
    pub const SOCKET: u32 = 0x02;
    /// Allow duplicating pipe fds.
    pub const PIPE: u32 = 0x04;
    /// Allow duplicating epoll fds.
    pub const EPOLL: u32 = 0x08;
    /// Allow all fd types (default for compatibility).
    pub const ALL: u32 = Self::REGULAR | Self::SOCKET | Self::PIPE | Self::EPOLL;
}

/// Arguments for the base `pidfd_getfd` syscall.
#[derive(Debug, Clone, Copy)]
pub struct PidfdGetfdArgs {
    /// Pidfd of the target process.
    pub pidfd: i32,
    /// Target file descriptor number to duplicate.
    pub targetfd: i32,
    /// Flags (must be 0 in the current ABI).
    pub flags: u32,
}

/// Arguments for the extended `pidfd_getfd` variant.
#[derive(Debug, Clone, Copy)]
pub struct PidfdGetfdExtArgs {
    /// Pidfd of the target process.
    pub pidfd: i32,
    /// Target file descriptor number to duplicate.
    pub targetfd: i32,
    /// Reserved flags (must be 0).
    pub flags: u32,
    /// FdTypeFilter bitmask restricting which fd types may be duplicated.
    pub type_filter: u32,
}

/// Metadata about the duplicated fd returned to the caller.
#[derive(Debug, Default)]
pub struct DupFdInfo {
    /// The new fd number in the calling process.
    pub new_fd: i32,
    /// Type classification of the duplicated fd.
    pub fd_type: FdType,
    /// Whether the fd has the close-on-exec flag set.
    pub cloexec: bool,
}

impl DupFdInfo {
    /// Create a new DupFdInfo with given values.
    pub const fn new(new_fd: i32, fd_type: FdType, cloexec: bool) -> Self {
        Self {
            new_fd,
            fd_type,
            cloexec,
        }
    }
}

/// File descriptor type classification.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FdType {
    /// Unknown or unclassified fd type.
    #[default]
    Unknown,
    /// Regular file.
    Regular,
    /// Socket fd.
    Socket,
    /// Pipe fd.
    Pipe,
    /// Epoll fd.
    Epoll,
    /// Eventfd.
    Eventfd,
    /// Timer fd.
    Timerfd,
}

impl FdType {
    /// Map this fd type to its filter bit for comparison with FdTypeFilter.
    pub fn filter_bit(&self) -> u32 {
        match self {
            FdType::Regular => FdTypeFilter::REGULAR,
            FdType::Socket => FdTypeFilter::SOCKET,
            FdType::Pipe => FdTypeFilter::PIPE,
            FdType::Epoll => FdTypeFilter::EPOLL,
            _ => 0,
        }
    }
}

/// Validate base `pidfd_getfd` arguments.
pub fn validate_pidfd_getfd_args(args: &PidfdGetfdArgs) -> Result<()> {
    if args.pidfd < 0 {
        return Err(Error::InvalidArgument);
    }
    if args.targetfd < 0 {
        return Err(Error::InvalidArgument);
    }
    if args.flags != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate extended `pidfd_getfd` arguments.
pub fn validate_pidfd_getfd_ext_args(args: &PidfdGetfdExtArgs) -> Result<()> {
    if args.pidfd < 0 || args.targetfd < 0 {
        return Err(Error::InvalidArgument);
    }
    if args.flags != 0 {
        return Err(Error::InvalidArgument);
    }
    let known_filter = FdTypeFilter::ALL;
    if args.type_filter & !known_filter != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Check if the caller has `process_vm_read` permission on the target.
///
/// `pidfd_getfd` requires the calling process to have ptrace read access
/// to the target identified by `pidfd`.
pub fn check_ptrace_read_permission(_pidfd: i32) -> Result<()> {
    // Stub: real check calls ptrace_may_access(target, PTRACE_MODE_ATTACH_REALCREDS).
    Err(Error::PermissionDenied)
}

/// Handle the base `pidfd_getfd` syscall.
///
/// Duplicates `targetfd` from the process identified by `pidfd` into the
/// calling process. Requires ptrace read access to the target.
///
/// Returns the new fd number on success, or an error.
pub fn sys_pidfd_getfd(args: &PidfdGetfdArgs) -> Result<i64> {
    validate_pidfd_getfd_args(args)?;
    check_ptrace_read_permission(args.pidfd)?;
    // Stub: real implementation would:
    // 1. Resolve pidfd to the target task_struct.
    // 2. Lock the target's fd table.
    // 3. Get a reference to targetfd.
    // 4. Allocate a new fd in the caller's table.
    // 5. Install the reference and return the new fd.
    Err(Error::NotImplemented)
}

/// Handle the extended `pidfd_getfd` syscall with type filtering.
///
/// Same as `sys_pidfd_getfd` but additionally checks that the duplicated
/// fd type is allowed by `type_filter`.
///
/// Returns the new fd number, or `Err(PermissionDenied)` if the type
/// is not in the filter.
pub fn sys_pidfd_getfd_ext(args: &PidfdGetfdExtArgs) -> Result<i64> {
    validate_pidfd_getfd_ext_args(args)?;
    check_ptrace_read_permission(args.pidfd)?;
    // Stub: real implementation checks fd type against type_filter.
    Err(Error::NotImplemented)
}

/// Check whether a given fd type is permitted by the filter bitmask.
pub fn fd_type_allowed(fd_type: &FdType, filter: u32) -> bool {
    let bit = fd_type.filter_bit();
    if bit == 0 {
        // Unknown types: only allow if ALL is set.
        return filter == FdTypeFilter::ALL;
    }
    (filter & bit) != 0
}
