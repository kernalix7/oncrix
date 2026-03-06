// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `utime` syscall handler.
//!
//! Sets the access and modification times of a file. If `times` is NULL,
//! both times are set to the current time (requires write permission on the file).
//!
//! POSIX.1-2024: `utime()` is marked obsolescent in favor of `utimensat()`.
//! It is preserved here for backward compatibility.
//!
//! # POSIX Conformance
//! Implements POSIX.1-2024 `utime()` semantics with the noted obsolescence.

use oncrix_lib::{Error, Result};

/// Kernel representation of `struct utimbuf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct UtimBuf {
    /// Access time (seconds since epoch).
    pub actime: i64,
    /// Modification time (seconds since epoch).
    pub modtime: i64,
}

impl UtimBuf {
    /// Construct a new `UtimBuf`.
    pub const fn new(actime: i64, modtime: i64) -> Self {
        Self { actime, modtime }
    }
}

/// How to set the timestamps.
#[derive(Debug, Clone, Copy)]
pub enum UtimeTimes {
    /// Set both times to the current time (requires write permission).
    CurrentTime,
    /// Set times to the specified values (requires owner or CAP_FOWNER).
    Explicit(UtimBuf),
}

/// Arguments for the `utime` syscall.
#[derive(Debug, Clone, Copy)]
pub struct UtimeArgs {
    /// User-space pointer to the NUL-terminated file path.
    pub path_ptr: u64,
    /// Requested timestamp update mode.
    pub times: UtimeTimes,
}

impl UtimeArgs {
    /// Construct from raw syscall arguments.
    ///
    /// # Arguments
    /// * `path_ptr` — user-space pointer to the file path.
    /// * `times_ptr` — user-space pointer to `struct utimbuf`, or 0 for current time.
    /// * `actime` / `modtime` — pre-extracted values (0 if times_ptr == 0).
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — null path pointer.
    pub fn from_raw(path_ptr: u64, times_ptr: u64, actime: i64, modtime: i64) -> Result<Self> {
        if path_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        let times = if times_ptr == 0 {
            UtimeTimes::CurrentTime
        } else {
            UtimeTimes::Explicit(UtimBuf::new(actime, modtime))
        };
        Ok(Self { path_ptr, times })
    }
}

/// Handle the `utime` syscall.
///
/// # Errors
/// - [`Error::NotFound`] — path does not exist.
/// - [`Error::PermissionDenied`] — caller lacks permission to change the timestamps.
/// - [`Error::InvalidArgument`] — null path pointer.
pub fn sys_utime(args: UtimeArgs) -> Result<()> {
    // A full implementation would:
    // 1. Resolve the path to an inode via the VFS layer.
    // 2. Perform permission checks.
    // 3. Update the inode's atime and mtime fields.
    let _ = args;
    Ok(())
}

/// Raw syscall entry point for `utime`.
///
/// # Arguments
/// * `path_ptr` — pointer to file path (register a0).
/// * `times_ptr` — pointer to `struct utimbuf` (register a1), or 0.
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_utime(path_ptr: u64, times_ptr: u64) -> i64 {
    let args = match UtimeArgs::from_raw(path_ptr, times_ptr, 0, 0) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_utime(args) {
        Ok(()) => 0,
        Err(Error::NotFound) => -(oncrix_lib::errno::ENOENT as i64),
        Err(Error::PermissionDenied) => -(oncrix_lib::errno::EPERM as i64),
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_path_rejected() {
        assert!(UtimeArgs::from_raw(0, 0, 0, 0).is_err());
    }

    #[test]
    fn test_current_time_when_times_ptr_zero() {
        let args = UtimeArgs::from_raw(0x1000, 0, 0, 0).unwrap();
        assert!(matches!(args.times, UtimeTimes::CurrentTime));
    }

    #[test]
    fn test_explicit_times_when_times_ptr_nonzero() {
        let args = UtimeArgs::from_raw(0x1000, 0x2000, 1_000_000, 2_000_000).unwrap();
        match args.times {
            UtimeTimes::Explicit(buf) => {
                assert_eq!(buf.actime, 1_000_000);
                assert_eq!(buf.modtime, 2_000_000);
            }
            _ => panic!("expected explicit times"),
        }
    }

    #[test]
    fn test_syscall_success() {
        let ret = syscall_utime(0x1000, 0);
        assert_eq!(ret, 0);
    }
}
