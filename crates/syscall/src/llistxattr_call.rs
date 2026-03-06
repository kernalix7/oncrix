// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `llistxattr` syscall handler.
//!
//! Lists the names of all extended attributes for a file, without following
//! symbolic links. If the path refers to a symlink, the attributes of the
//! symlink itself are listed.
//!
//! The names are returned as a NUL-separated list in the output buffer.
//! If `size` is 0, the required buffer size is returned.
//!
//! POSIX.1-2024: Extended attributes are not in core POSIX but are widely
//! supported. This implementation follows Linux/XATTR semantics.

use oncrix_lib::{Error, Result};

/// Maximum size of the returned attribute name list.
pub const XATTR_LIST_MAX: usize = 65536;

/// Arguments for the `llistxattr` syscall.
#[derive(Debug, Clone, Copy)]
pub struct LlistxattrArgs {
    /// User-space pointer to the NUL-terminated file path.
    pub path_ptr: u64,
    /// User-space pointer to the output buffer (may be 0 for size query).
    pub list_ptr: u64,
    /// Size of the output buffer in bytes (0 to query required size).
    pub size: usize,
}

impl LlistxattrArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — null path pointer, or size > XATTR_LIST_MAX.
    pub fn from_raw(path_ptr: u64, list_ptr: u64, size_raw: u64) -> Result<Self> {
        if path_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        let size = size_raw as usize;
        if size > XATTR_LIST_MAX {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            path_ptr,
            list_ptr,
            size,
        })
    }

    /// Returns `true` if this is a size-query call.
    pub fn is_size_query(self) -> bool {
        self.size == 0
    }
}

/// Result of `llistxattr`.
#[derive(Debug, Clone, Copy)]
pub struct LlistxattrResult {
    /// Number of bytes in the attribute list (or required size if querying).
    pub bytes: usize,
}

impl LlistxattrResult {
    /// Construct a new result.
    pub const fn new(bytes: usize) -> Self {
        Self { bytes }
    }
}

/// Handle the `llistxattr` syscall.
///
/// Lists all extended attribute names for the file at `path` without
/// following the final path component if it is a symlink.
///
/// # Errors
/// - [`Error::NotFound`] — path does not exist.
/// - [`Error::PermissionDenied`] — caller lacks permission to list xattrs.
/// - [`Error::InvalidArgument`] — null path or size overflow.
pub fn sys_llistxattr(args: LlistxattrArgs) -> Result<LlistxattrResult> {
    // A full implementation would:
    // 1. Resolve path WITHOUT following the final symlink component.
    // 2. Call VFS listxattr on the inode.
    // 3. If args.list_ptr == 0 or args.size == 0: return the required size.
    // 4. Otherwise copy the NUL-separated name list to user space.
    let _ = args;
    Ok(LlistxattrResult::new(0))
}

/// Raw syscall entry point for `llistxattr`.
///
/// # Arguments
/// * `path_ptr` — pointer to file path (register a0).
/// * `list_ptr` — pointer to output buffer (register a1).
/// * `size` — buffer size in bytes (register a2).
///
/// # Returns
/// Number of bytes in the list on success, negative errno on failure.
pub fn syscall_llistxattr(path_ptr: u64, list_ptr: u64, size: u64) -> i64 {
    let args = match LlistxattrArgs::from_raw(path_ptr, list_ptr, size) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_llistxattr(args) {
        Ok(result) => result.bytes as i64,
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
        assert!(LlistxattrArgs::from_raw(0, 0x1000, 256).is_err());
    }

    #[test]
    fn test_size_too_large_rejected() {
        assert!(LlistxattrArgs::from_raw(0x1000, 0x2000, (XATTR_LIST_MAX + 1) as u64).is_err());
    }

    #[test]
    fn test_zero_size_is_size_query() {
        let args = LlistxattrArgs::from_raw(0x1000, 0, 0).unwrap();
        assert!(args.is_size_query());
    }

    #[test]
    fn test_valid_args() {
        let args = LlistxattrArgs::from_raw(0x1000, 0x2000, 512).unwrap();
        assert_eq!(args.size, 512);
        assert!(!args.is_size_query());
    }

    #[test]
    fn test_syscall_returns_zero() {
        let ret = syscall_llistxattr(0x1000, 0x2000, 512);
        assert_eq!(ret, 0);
    }
}
