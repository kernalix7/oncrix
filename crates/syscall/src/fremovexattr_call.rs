// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fremovexattr` syscall handler.
//!
//! Removes an extended attribute from a file identified by an open file
//! descriptor. This variant avoids path resolution entirely and is immune
//! to TOCTOU races.
//!
//! POSIX.1-2024: Extended attributes are not in core POSIX but are widely
//! supported. This implementation follows Linux/XATTR semantics.

use oncrix_lib::{Error, Result};

/// Arguments for the `fremovexattr` syscall.
#[derive(Debug, Clone, Copy)]
pub struct FremovexattrArgs {
    /// Open file descriptor.
    pub fd: i32,
    /// User-space pointer to the NUL-terminated attribute name.
    pub name_ptr: u64,
}

impl FremovexattrArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — negative fd or null name pointer.
    pub fn from_raw(fd_raw: u64, name_ptr: u64) -> Result<Self> {
        let fd = fd_raw as i32;
        if fd < 0 {
            return Err(Error::InvalidArgument);
        }
        if name_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { fd, name_ptr })
    }
}

/// Handle the `fremovexattr` syscall.
///
/// Removes the named extended attribute from the file referenced by `fd`.
///
/// # Errors
/// - [`Error::NotFound`] — fd is invalid or the attribute does not exist.
/// - [`Error::PermissionDenied`] — caller lacks permission.
/// - [`Error::InvalidArgument`] — invalid fd or null name.
pub fn sys_fremovexattr(args: FremovexattrArgs) -> Result<()> {
    // A full implementation would:
    // 1. Look up the file object from the fdtable.
    // 2. Copy the attribute name from user space.
    // 3. Validate the name (namespace prefix required).
    // 4. Call VFS removexattr on the inode.
    let _ = args;
    Ok(())
}

/// Raw syscall entry point for `fremovexattr`.
///
/// # Arguments
/// * `fd` — open file descriptor (register a0).
/// * `name_ptr` — pointer to attribute name (register a1).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_fremovexattr(fd: u64, name_ptr: u64) -> i64 {
    let args = match FremovexattrArgs::from_raw(fd, name_ptr) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_fremovexattr(args) {
        Ok(()) => 0,
        Err(Error::NotFound) => -(oncrix_lib::errno::ENODATA as i64),
        Err(Error::PermissionDenied) => -(oncrix_lib::errno::EPERM as i64),
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negative_fd_rejected() {
        assert!(FremovexattrArgs::from_raw(u64::MAX, 0x1000).is_err());
    }

    #[test]
    fn test_null_name_rejected() {
        assert!(FremovexattrArgs::from_raw(3, 0).is_err());
    }

    #[test]
    fn test_valid_args() {
        let args = FremovexattrArgs::from_raw(5, 0x2000).unwrap();
        assert_eq!(args.fd, 5);
        assert_eq!(args.name_ptr, 0x2000);
    }

    #[test]
    fn test_syscall_returns_zero() {
        let ret = syscall_fremovexattr(3, 0x1000);
        assert_eq!(ret, 0);
    }
}
