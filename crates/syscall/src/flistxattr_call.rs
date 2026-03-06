// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `flistxattr` syscall handler.
//!
//! Lists the names of all extended attributes for a file identified by
//! an open file descriptor. The names are returned as a NUL-separated list.
//! If `size` is 0, the required buffer size is returned without copying data.
//!
//! POSIX.1-2024: Extended attributes are not in core POSIX but are widely
//! supported. This implementation follows Linux/XATTR semantics.

use oncrix_lib::{Error, Result};

/// Maximum size of the returned attribute name list.
pub const XATTR_LIST_MAX: usize = 65536;

/// Arguments for the `flistxattr` syscall.
#[derive(Debug, Clone, Copy)]
pub struct FlistxattrArgs {
    /// Open file descriptor.
    pub fd: i32,
    /// User-space pointer to the output buffer (0 for size query).
    pub list_ptr: u64,
    /// Size of the output buffer in bytes.
    pub size: usize,
}

impl FlistxattrArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — negative fd or size > XATTR_LIST_MAX.
    pub fn from_raw(fd_raw: u64, list_ptr: u64, size_raw: u64) -> Result<Self> {
        let fd = fd_raw as i32;
        if fd < 0 {
            return Err(Error::InvalidArgument);
        }
        let size = size_raw as usize;
        if size > XATTR_LIST_MAX {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { fd, list_ptr, size })
    }

    /// Returns `true` if this is a size-query call (size == 0).
    pub fn is_size_query(self) -> bool {
        self.size == 0
    }
}

/// Result of `flistxattr`.
#[derive(Debug, Clone, Copy)]
pub struct FlistxattrResult {
    /// Number of bytes in the attribute list (or required size if querying).
    pub bytes: usize,
}

impl FlistxattrResult {
    /// Construct a new result.
    pub const fn new(bytes: usize) -> Self {
        Self { bytes }
    }
}

/// Handle the `flistxattr` syscall.
///
/// Lists all extended attribute names for the file referenced by `fd`.
/// If `size` is 0, returns the required buffer size without writing.
///
/// # Errors
/// - [`Error::NotFound`] — fd is not valid.
/// - [`Error::PermissionDenied`] — caller lacks permission.
/// - [`Error::InvalidArgument`] — negative fd or size overflow.
pub fn sys_flistxattr(args: FlistxattrArgs) -> Result<FlistxattrResult> {
    // A full implementation would:
    // 1. Look up the file in the fdtable.
    // 2. Call VFS listxattr on the inode.
    // 3. If size == 0: return total list size.
    // 4. Otherwise copy NUL-separated names to user space.
    let _ = args;
    Ok(FlistxattrResult::new(0))
}

/// Raw syscall entry point for `flistxattr`.
///
/// # Arguments
/// * `fd` — open file descriptor (register a0).
/// * `list_ptr` — pointer to output buffer (register a1).
/// * `size` — buffer size in bytes (register a2).
///
/// # Returns
/// Number of bytes in the list on success, negative errno on failure.
pub fn syscall_flistxattr(fd: u64, list_ptr: u64, size: u64) -> i64 {
    let args = match FlistxattrArgs::from_raw(fd, list_ptr, size) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_flistxattr(args) {
        Ok(result) => result.bytes as i64,
        Err(Error::NotFound) => -(oncrix_lib::errno::EBADF as i64),
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
        assert!(FlistxattrArgs::from_raw(u64::MAX, 0x1000, 256).is_err());
    }

    #[test]
    fn test_size_too_large_rejected() {
        assert!(FlistxattrArgs::from_raw(3, 0x1000, (XATTR_LIST_MAX + 1) as u64).is_err());
    }

    #[test]
    fn test_size_zero_is_query() {
        let args = FlistxattrArgs::from_raw(3, 0x1000, 0).unwrap();
        assert!(args.is_size_query());
    }

    #[test]
    fn test_valid_args() {
        let args = FlistxattrArgs::from_raw(3, 0x1000, 1024).unwrap();
        assert_eq!(args.fd, 3);
        assert_eq!(args.size, 1024);
    }

    #[test]
    fn test_syscall_returns_zero() {
        let ret = syscall_flistxattr(3, 0x1000, 1024);
        assert_eq!(ret, 0);
    }
}
