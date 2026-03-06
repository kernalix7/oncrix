// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `lgetxattr` syscall handler.
//!
//! Retrieves the value of an extended attribute for a file. Unlike `getxattr`,
//! `lgetxattr` does not follow symbolic links: if the path refers to a symlink,
//! the attribute is retrieved from the symlink itself.
//!
//! POSIX.1-2024: Extended attributes are not in core POSIX but are widely
//! supported. This implementation follows Linux/XATTR semantics.

use oncrix_lib::{Error, Result};

/// Maximum length of an extended attribute name (including namespace prefix).
pub const XATTR_NAME_MAX: usize = 255;
/// Maximum size of an extended attribute value.
pub const XATTR_SIZE_MAX: usize = 65536;

/// Arguments for the `lgetxattr` syscall.
#[derive(Debug, Clone, Copy)]
pub struct LgetxattrArgs {
    /// User-space pointer to the NUL-terminated file path.
    pub path_ptr: u64,
    /// User-space pointer to the NUL-terminated attribute name.
    pub name_ptr: u64,
    /// User-space pointer to the value output buffer.
    pub value_ptr: u64,
    /// Size of the output buffer in bytes.
    pub size: usize,
}

impl LgetxattrArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — null path or name pointer, or size > XATTR_SIZE_MAX.
    pub fn from_raw(path_ptr: u64, name_ptr: u64, value_ptr: u64, size_raw: u64) -> Result<Self> {
        if path_ptr == 0 {
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
            path_ptr,
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

/// Result of `lgetxattr`.
#[derive(Debug, Clone, Copy)]
pub struct LgetxattrResult {
    /// Number of bytes written to the value buffer (or needed if size was 0).
    pub bytes_written: usize,
}

impl LgetxattrResult {
    /// Construct a new result.
    pub const fn new(bytes_written: usize) -> Self {
        Self { bytes_written }
    }
}

/// Handle the `lgetxattr` syscall.
///
/// Retrieves the named extended attribute from the file at `path`, without
/// following symlinks. If `size` is 0, returns the attribute size without
/// writing to the buffer.
///
/// # Errors
/// - [`Error::NotFound`] — path or attribute does not exist.
/// - [`Error::InvalidArgument`] — invalid path, name, or buffer parameters.
/// - [`Error::PermissionDenied`] — caller lacks permission.
pub fn sys_lgetxattr(args: LgetxattrArgs) -> Result<LgetxattrResult> {
    // A full implementation would:
    // 1. Resolve the path WITHOUT following the final symlink component (NOFOLLOW).
    // 2. Look up the xattr by name in the file's xattr store.
    // 3. If size == 0, return the attribute's size.
    // 4. Otherwise copy the value to the user buffer via copy_to_user.
    let _ = args;
    Ok(LgetxattrResult::new(0))
}

/// Raw syscall entry point for `lgetxattr`.
///
/// # Arguments
/// * `path_ptr` — pointer to file path (register a0).
/// * `name_ptr` — pointer to attribute name (register a1).
/// * `value_ptr` — pointer to output buffer (register a2).
/// * `size` — buffer size in bytes (register a3).
///
/// # Returns
/// Number of bytes in the value on success, negative errno on failure.
pub fn syscall_lgetxattr(path_ptr: u64, name_ptr: u64, value_ptr: u64, size: u64) -> i64 {
    let args = match LgetxattrArgs::from_raw(path_ptr, name_ptr, value_ptr, size) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_lgetxattr(args) {
        Ok(result) => result.bytes_written as i64,
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
    fn test_null_path_rejected() {
        assert!(LgetxattrArgs::from_raw(0, 0x1000, 0x2000, 256).is_err());
    }

    #[test]
    fn test_null_name_rejected() {
        assert!(LgetxattrArgs::from_raw(0x1000, 0, 0x2000, 256).is_err());
    }

    #[test]
    fn test_size_exceeds_max_rejected() {
        assert!(
            LgetxattrArgs::from_raw(0x1000, 0x2000, 0x3000, (XATTR_SIZE_MAX + 1) as u64).is_err()
        );
    }

    #[test]
    fn test_size_query_detection() {
        let args = LgetxattrArgs::from_raw(0x1000, 0x2000, 0, 0).unwrap();
        assert!(args.is_size_query());
    }

    #[test]
    fn test_valid_args() {
        let args = LgetxattrArgs::from_raw(0x1000, 0x2000, 0x3000, 1024).unwrap();
        assert_eq!(args.size, 1024);
        assert!(!args.is_size_query());
    }

    #[test]
    fn test_syscall_returns_zero_for_empty() {
        let ret = syscall_lgetxattr(0x1000, 0x2000, 0x3000, 256);
        assert_eq!(ret, 0);
    }
}
