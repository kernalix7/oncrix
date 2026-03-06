// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX errno constants.
//!
//! Standard error numbers used by the syscall layer to convert
//! [`crate::Error`] values into negative return codes.
//!
//! Reference: POSIX.1-2024, `<errno.h>`.

/// Operation not permitted.
pub const EPERM: i32 = 1;
/// No such file or directory.
pub const ENOENT: i32 = 2;
/// No such process.
pub const ESRCH: i32 = 3;
/// Interrupted system call.
pub const EINTR: i32 = 4;
/// I/O error.
pub const EIO: i32 = 5;
/// Bad file descriptor.
pub const EBADF: i32 = 9;
/// Try again / would block.
pub const EAGAIN: i32 = 11;
/// Out of memory.
pub const ENOMEM: i32 = 12;
/// Permission denied.
pub const EACCES: i32 = 13;
/// Bad address.
pub const EFAULT: i32 = 14;
/// Device or resource busy.
pub const EBUSY: i32 = 16;
/// File exists.
pub const EEXIST: i32 = 17;
/// Invalid argument.
pub const EINVAL: i32 = 22;
/// No space left on device.
pub const ENOSPC: i32 = 28;
/// Function not implemented.
pub const ENOSYS: i32 = 38;
/// No data available.
pub const ENODATA: i32 = 61;
/// Operation would block (same as EAGAIN on Linux).
pub const EWOULDBLOCK: i32 = EAGAIN;
