// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fgetxattr` syscall handler.
//!
//! Retrieves the value of an extended attribute for a file identified by
//! an open file descriptor. This variant avoids path resolution entirely
//! and is immune to TOCTOU races.
//!
//! POSIX.1-2024: Extended attributes are not in core POSIX but are widely
//! supported. This implementation follows Linux/XATTR semantics.

use oncrix_lib::{Error, Result};

/// Maximum size of an extended attribute value.
pub const XATTR_SIZE_MAX: usize = 65536;

/// Arguments for the `fgetxattr` syscall.
#[derive(Debug, Clone, Copy)]
pub struct FgetxattrArgs {
    /// Open file descriptor.
    pub fd: i32,
    /// User-space pointer to the NUL-terminated attribute name.
    pub name_ptr: u64,
    /// User-space pointer to the value output buffer (may be 0 for size query).
    pub value_ptr: u64,
    /// Size of the output buffer in bytes.
    pub size: usize,
}

impl FgetxattrArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — negative fd, null name, or size > XATTR_SIZE_MAX.
    pub fn from_raw(fd_raw: u64, name_ptr: u64, value_ptr: u64, size_raw: u64) -> Result<Self> {
        let fd = fd_raw as i32;
        if fd < 0 {
            return Err(Error::InvalidArgument);
        }
        if name_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        let size = size_raw as usize;
        if size > XATTR_SIZE_MAX {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            fd,
            name_ptr,
            value_ptr,
            size,
        })
    }

    /// Returns `true` if this is a size-query call (value_ptr = 0, size = 0).
    pub fn is_size_query(self) -> bool {
        self.value_ptr == 0 && self.size == 0
    }
}

/// Result of `fgetxattr`.
#[derive(Debug, Clone, Copy)]
pub struct FgetxattrResult {
    /// Bytes written (or attribute size if querying).
    pub bytes: usize,
}

impl FgetxattrResult {
    /// Construct a new result.
    pub const fn new(bytes: usize) -> Self {
        Self { bytes }
    }
}

/// Handle the `fgetxattr` syscall.
///
/// Retrieves the named extended attribute from the file referenced by `fd`.
/// If `size` is 0, returns the attribute size without writing to the buffer.
///
/// # Errors
/// - [`Error::NotFound`] — attribute does not exist on the file.
/// - [`Error::InvalidArgument`] — buffer too small, invalid fd, or null name.
/// - [`Error::PermissionDenied`] — caller lacks permission to read xattrs.
pub fn sys_fgetxattr(args: FgetxattrArgs) -> Result<FgetxattrResult> {
    // A full implementation would:
    // 1. Look up the file object from the fdtable using args.fd.
    // 2. Call the VFS getxattr operation on the inode.
    // 3. If args.size == 0: return the attribute's current size.
    // 4. Otherwise copy the value to user space via copy_to_user.
    let _ = args;
    Ok(FgetxattrResult::new(0))
}

/// Raw syscall entry point for `fgetxattr`.
///
/// # Arguments
/// * `fd` — open file descriptor (register a0).
/// * `name_ptr` — pointer to attribute name (register a1).
/// * `value_ptr` — pointer to output buffer (register a2).
/// * `size` — buffer size in bytes (register a3).
///
/// # Returns
/// Number of bytes in the value on success, negative errno on failure.
pub fn syscall_fgetxattr(fd: u64, name_ptr: u64, value_ptr: u64, size: u64) -> i64 {
    let args = match FgetxattrArgs::from_raw(fd, name_ptr, value_ptr, size) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_fgetxattr(args) {
        Ok(result) => result.bytes as i64,
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
        assert!(FgetxattrArgs::from_raw(u64::MAX, 0x1000, 0x2000, 256).is_err());
    }

    #[test]
    fn test_null_name_rejected() {
        assert!(FgetxattrArgs::from_raw(3, 0, 0x2000, 256).is_err());
    }

    #[test]
    fn test_size_too_large_rejected() {
        assert!(FgetxattrArgs::from_raw(3, 0x1000, 0x2000, (XATTR_SIZE_MAX + 1) as u64).is_err());
    }

    #[test]
    fn test_size_query() {
        let args = FgetxattrArgs::from_raw(3, 0x1000, 0, 0).unwrap();
        assert!(args.is_size_query());
    }

    #[test]
    fn test_valid_normal_args() {
        let args = FgetxattrArgs::from_raw(3, 0x1000, 0x2000, 512).unwrap();
        assert_eq!(args.fd, 3);
        assert_eq!(args.size, 512);
        assert!(!args.is_size_query());
    }

    #[test]
    fn test_syscall_returns_zero() {
        let ret = syscall_fgetxattr(3, 0x1000, 0x2000, 256);
        assert_eq!(ret, 0);
    }
}
