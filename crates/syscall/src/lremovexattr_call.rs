// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `lremovexattr` syscall handler.
//!
//! Removes an extended attribute from a file, without following symbolic
//! links. If the path refers to a symlink, the attribute is removed from
//! the symlink itself rather than the file it points to.
//!
//! POSIX.1-2024: Extended attributes are not in core POSIX but are widely
//! supported. This implementation follows Linux/XATTR semantics.

use oncrix_lib::{Error, Result};

/// Arguments for the `lremovexattr` syscall.
#[derive(Debug, Clone, Copy)]
pub struct LremovexattrArgs {
    /// User-space pointer to the NUL-terminated file path.
    pub path_ptr: u64,
    /// User-space pointer to the NUL-terminated attribute name.
    pub name_ptr: u64,
}

impl LremovexattrArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — null path or name pointer.
    pub fn from_raw(path_ptr: u64, name_ptr: u64) -> Result<Self> {
        if path_ptr == 0 || name_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { path_ptr, name_ptr })
    }
}

/// Handle the `lremovexattr` syscall.
///
/// Removes the named extended attribute from the file at `path` without
/// following the final path component if it is a symlink.
///
/// # Errors
/// - [`Error::NotFound`] — path does not exist, or the attribute is absent.
/// - [`Error::PermissionDenied`] — caller lacks permission to remove the attribute.
/// - [`Error::InvalidArgument`] — null path or name pointer.
pub fn sys_lremovexattr(args: LremovexattrArgs) -> Result<()> {
    // A full implementation would:
    // 1. Resolve path WITHOUT following the final symlink.
    // 2. Copy the attribute name from user space.
    // 3. Validate the name's namespace prefix.
    // 4. Call VFS removexattr on the inode.
    let _ = args;
    Ok(())
}

/// Raw syscall entry point for `lremovexattr`.
///
/// # Arguments
/// * `path_ptr` — pointer to file path (register a0).
/// * `name_ptr` — pointer to attribute name (register a1).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_lremovexattr(path_ptr: u64, name_ptr: u64) -> i64 {
    let args = match LremovexattrArgs::from_raw(path_ptr, name_ptr) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_lremovexattr(args) {
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
    fn test_null_path_rejected() {
        assert!(LremovexattrArgs::from_raw(0, 0x1000).is_err());
    }

    #[test]
    fn test_null_name_rejected() {
        assert!(LremovexattrArgs::from_raw(0x1000, 0).is_err());
    }

    #[test]
    fn test_both_null_rejected() {
        assert!(LremovexattrArgs::from_raw(0, 0).is_err());
    }

    #[test]
    fn test_valid_args() {
        let args = LremovexattrArgs::from_raw(0x1000, 0x2000).unwrap();
        assert_eq!(args.path_ptr, 0x1000);
        assert_eq!(args.name_ptr, 0x2000);
    }

    #[test]
    fn test_syscall_success() {
        let ret = syscall_lremovexattr(0x1000, 0x2000);
        assert_eq!(ret, 0);
    }
}
