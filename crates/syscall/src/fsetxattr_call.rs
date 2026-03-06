// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fsetxattr` syscall handler.
//!
//! Sets the value of an extended attribute for a file identified by an open
//! file descriptor. This variant avoids path resolution entirely.
//!
//! POSIX.1-2024: Extended attributes are not in core POSIX but are widely
//! supported. This implementation follows Linux/XATTR semantics.

use oncrix_lib::{Error, Result};

/// Maximum size of an extended attribute value.
pub const XATTR_SIZE_MAX: usize = 65536;

/// `fsetxattr` flag: create attribute only (fail if already exists).
pub const XATTR_CREATE: u32 = 1;
/// `fsetxattr` flag: replace attribute only (fail if does not exist).
pub const XATTR_REPLACE: u32 = 2;

/// Validated set semantics flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XattrSetMode {
    /// Create or replace (no restriction).
    #[default]
    Any,
    /// Create only — fail if attribute exists.
    CreateOnly,
    /// Replace only — fail if attribute is absent.
    ReplaceOnly,
}

impl XattrSetMode {
    /// Construct from raw flags.
    ///
    /// # Errors
    /// Returns [`Error::InvalidArgument`] if both flags are set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            0 => Ok(Self::Any),
            XATTR_CREATE => Ok(Self::CreateOnly),
            XATTR_REPLACE => Ok(Self::ReplaceOnly),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Arguments for the `fsetxattr` syscall.
#[derive(Debug, Clone, Copy)]
pub struct FsetxattrArgs {
    /// Open file descriptor.
    pub fd: i32,
    /// User-space pointer to the NUL-terminated attribute name.
    pub name_ptr: u64,
    /// User-space pointer to the attribute value buffer.
    pub value_ptr: u64,
    /// Size of the value buffer in bytes.
    pub size: usize,
    /// Set mode (create/replace semantics).
    pub mode: XattrSetMode,
}

impl FsetxattrArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — negative fd, null pointers, size overflow, or invalid flags.
    pub fn from_raw(
        fd_raw: u64,
        name_ptr: u64,
        value_ptr: u64,
        size_raw: u64,
        flags_raw: u64,
    ) -> Result<Self> {
        let fd = fd_raw as i32;
        if fd < 0 {
            return Err(Error::InvalidArgument);
        }
        if name_ptr == 0 || value_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        let size = size_raw as usize;
        if size > XATTR_SIZE_MAX {
            return Err(Error::InvalidArgument);
        }
        let mode = XattrSetMode::from_raw(flags_raw as u32)?;
        Ok(Self {
            fd,
            name_ptr,
            value_ptr,
            size,
            mode,
        })
    }
}

/// Handle the `fsetxattr` syscall.
///
/// Sets the named extended attribute on the file referenced by `fd`.
///
/// # Errors
/// - [`Error::NotFound`] — fd is invalid or attribute absent (for XATTR_REPLACE).
/// - [`Error::PermissionDenied`] — caller lacks permission.
/// - [`Error::AlreadyExists`] — XATTR_CREATE but attribute already exists.
/// - [`Error::InvalidArgument`] — invalid fd, name, or conflicting flags.
pub fn sys_fsetxattr(args: FsetxattrArgs) -> Result<()> {
    // A full implementation would:
    // 1. Look up the file object in the fdtable.
    // 2. Copy name and value from user space.
    // 3. Validate the xattr name's namespace prefix.
    // 4. Apply XATTR_CREATE / XATTR_REPLACE semantics.
    // 5. Call the VFS setxattr operation on the inode.
    let _ = args;
    Ok(())
}

/// Raw syscall entry point for `fsetxattr`.
///
/// # Arguments
/// * `fd` — open file descriptor (register a0).
/// * `name_ptr` — pointer to attribute name (register a1).
/// * `value_ptr` — pointer to attribute value (register a2).
/// * `size` — value size in bytes (register a3).
/// * `flags` — XATTR_CREATE / XATTR_REPLACE flags (register a4).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_fsetxattr(fd: u64, name_ptr: u64, value_ptr: u64, size: u64, flags: u64) -> i64 {
    let args = match FsetxattrArgs::from_raw(fd, name_ptr, value_ptr, size, flags) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_fsetxattr(args) {
        Ok(()) => 0,
        Err(Error::NotFound) => -(oncrix_lib::errno::ENODATA as i64),
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
    fn test_negative_fd_rejected() {
        assert!(FsetxattrArgs::from_raw(u64::MAX, 0x1000, 0x2000, 10, 0).is_err());
    }

    #[test]
    fn test_null_name_rejected() {
        assert!(FsetxattrArgs::from_raw(3, 0, 0x2000, 10, 0).is_err());
    }

    #[test]
    fn test_null_value_rejected() {
        assert!(FsetxattrArgs::from_raw(3, 0x1000, 0, 10, 0).is_err());
    }

    #[test]
    fn test_conflicting_flags_rejected() {
        let both = (XATTR_CREATE | XATTR_REPLACE) as u64;
        assert!(FsetxattrArgs::from_raw(3, 0x1000, 0x2000, 10, both).is_err());
    }

    #[test]
    fn test_create_only_mode() {
        let args = FsetxattrArgs::from_raw(3, 0x1000, 0x2000, 10, XATTR_CREATE as u64).unwrap();
        assert!(matches!(args.mode, XattrSetMode::CreateOnly));
    }

    #[test]
    fn test_syscall_returns_zero() {
        let ret = syscall_fsetxattr(3, 0x1000, 0x2000, 10, 0);
        assert_eq!(ret, 0);
    }
}
