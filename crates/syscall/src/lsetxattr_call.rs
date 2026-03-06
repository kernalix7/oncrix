// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `lsetxattr` syscall handler.
//!
//! Sets the value of an extended attribute for a file, without following
//! symbolic links. If the path refers to a symlink, the attribute is set on
//! the symlink itself rather than the file it points to.
//!
//! POSIX.1-2024: Extended attributes are not in core POSIX but are widely
//! supported. This implementation follows Linux/XATTR semantics.

use oncrix_lib::{Error, Result};

/// Maximum size of an extended attribute value.
pub const XATTR_SIZE_MAX: usize = 65536;

/// `lsetxattr` flag: create attribute (fail if already exists).
pub const XATTR_CREATE: u32 = 1;
/// `lsetxattr` flag: replace attribute (fail if does not exist).
pub const XATTR_REPLACE: u32 = 2;

/// Validated flags for `lsetxattr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XattrSetFlag {
    /// Create or replace (no restriction).
    #[default]
    CreateOrReplace,
    /// Create only — fail with EEXIST if attribute already exists.
    CreateOnly,
    /// Replace only — fail with ENODATA if attribute does not exist.
    ReplaceOnly,
}

impl XattrSetFlag {
    /// Construct from raw flags.
    ///
    /// # Errors
    /// Returns [`Error::InvalidArgument`] if both XATTR_CREATE and XATTR_REPLACE are set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            0 => Ok(Self::CreateOrReplace),
            XATTR_CREATE => Ok(Self::CreateOnly),
            XATTR_REPLACE => Ok(Self::ReplaceOnly),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Arguments for the `lsetxattr` syscall.
#[derive(Debug, Clone, Copy)]
pub struct LsetxattrArgs {
    /// User-space pointer to the NUL-terminated file path.
    pub path_ptr: u64,
    /// User-space pointer to the NUL-terminated attribute name.
    pub name_ptr: u64,
    /// User-space pointer to the attribute value buffer.
    pub value_ptr: u64,
    /// Size of the value in bytes.
    pub size: usize,
    /// How to handle existing attributes.
    pub flag: XattrSetFlag,
}

impl LsetxattrArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — null pointers, size > XATTR_SIZE_MAX, or invalid flags.
    pub fn from_raw(
        path_ptr: u64,
        name_ptr: u64,
        value_ptr: u64,
        size_raw: u64,
        flags_raw: u64,
    ) -> Result<Self> {
        if path_ptr == 0 || name_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        if value_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        let size = size_raw as usize;
        if size > XATTR_SIZE_MAX {
            return Err(Error::InvalidArgument);
        }
        let flag = XattrSetFlag::from_raw(flags_raw as u32)?;
        Ok(Self {
            path_ptr,
            name_ptr,
            value_ptr,
            size,
            flag,
        })
    }
}

/// Handle the `lsetxattr` syscall.
///
/// Sets the named extended attribute on the file at `path` without following
/// symlinks.
///
/// # Errors
/// - [`Error::NotFound`] — path does not exist.
/// - [`Error::PermissionDenied`] — caller lacks permission to set xattr.
/// - [`Error::InvalidArgument`] — invalid arguments or conflicting flags.
/// - [`Error::AlreadyExists`] — XATTR_CREATE but attribute already exists.
pub fn sys_lsetxattr(args: LsetxattrArgs) -> Result<()> {
    // A full implementation would:
    // 1. Resolve path WITHOUT following the final symlink (AT_SYMLINK_NOFOLLOW).
    // 2. Copy name and value from user space.
    // 3. Validate name (namespace prefix required: "user.", "security.", etc.).
    // 4. Apply flag semantics (XATTR_CREATE / XATTR_REPLACE checks).
    // 5. Call VFS setxattr on the inode.
    let _ = args;
    Ok(())
}

/// Raw syscall entry point for `lsetxattr`.
///
/// # Arguments
/// * `path_ptr` — pointer to file path (register a0).
/// * `name_ptr` — pointer to attribute name (register a1).
/// * `value_ptr` — pointer to attribute value (register a2).
/// * `size` — value size in bytes (register a3).
/// * `flags` — XATTR_CREATE / XATTR_REPLACE flags (register a4).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_lsetxattr(
    path_ptr: u64,
    name_ptr: u64,
    value_ptr: u64,
    size: u64,
    flags: u64,
) -> i64 {
    let args = match LsetxattrArgs::from_raw(path_ptr, name_ptr, value_ptr, size, flags) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_lsetxattr(args) {
        Ok(()) => 0,
        Err(Error::NotFound) => -(oncrix_lib::errno::ENOENT as i64),
        Err(Error::PermissionDenied) => -(oncrix_lib::errno::EPERM as i64),
        Err(Error::AlreadyExists) => -(oncrix_lib::errno::EEXIST as i64),
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_path_rejected() {
        assert!(LsetxattrArgs::from_raw(0, 0x1000, 0x2000, 10, 0).is_err());
    }

    #[test]
    fn test_null_value_rejected() {
        assert!(LsetxattrArgs::from_raw(0x1000, 0x2000, 0, 10, 0).is_err());
    }

    #[test]
    fn test_both_create_and_replace_rejected() {
        let combined = (XATTR_CREATE | XATTR_REPLACE) as u64;
        assert!(LsetxattrArgs::from_raw(0x1000, 0x2000, 0x3000, 10, combined).is_err());
    }

    #[test]
    fn test_create_only_flag() {
        let args =
            LsetxattrArgs::from_raw(0x1000, 0x2000, 0x3000, 10, XATTR_CREATE as u64).unwrap();
        assert!(matches!(args.flag, XattrSetFlag::CreateOnly));
    }

    #[test]
    fn test_replace_only_flag() {
        let args =
            LsetxattrArgs::from_raw(0x1000, 0x2000, 0x3000, 10, XATTR_REPLACE as u64).unwrap();
        assert!(matches!(args.flag, XattrSetFlag::ReplaceOnly));
    }

    #[test]
    fn test_size_too_large_rejected() {
        assert!(
            LsetxattrArgs::from_raw(0x1000, 0x2000, 0x3000, (XATTR_SIZE_MAX + 1) as u64, 0)
                .is_err()
        );
    }

    #[test]
    fn test_syscall_success() {
        let ret = syscall_lsetxattr(0x1000, 0x2000, 0x3000, 10, 0);
        assert_eq!(ret, 0);
    }
}
