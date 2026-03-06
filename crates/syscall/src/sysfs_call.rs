// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sysfs` syscall handler.
//!
//! Returns information about the filesystem types currently present in the
//! kernel. This is a legacy syscall (largely superseded by procfs/sysfs VFS)
//! that operates with three sub-commands (`option`):
//!
//! - Option 1: Return the name of a filesystem indexed by `fsindex`.
//! - Option 2: Return the `fsindex` of a named filesystem.
//! - Option 3: Return the total number of filesystem types in the kernel.
//!
//! # POSIX Conformance
//! `sysfs` is a Linux-specific syscall not in POSIX.1-2024. It is retained
//! here for historical compatibility.

use oncrix_lib::{Error, Result};

/// Option 1: get filesystem name by index.
pub const SYSFS_GET_FSNAME: u32 = 1;
/// Option 2: get filesystem index by name.
pub const SYSFS_GET_FSINDEX: u32 = 2;
/// Option 3: get total filesystem count.
pub const SYSFS_GET_FSCOUNT: u32 = 3;

/// Sub-command for the `sysfs` syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysfsOption {
    /// Get filesystem name by index.
    GetFsName {
        /// Filesystem type index.
        fsindex: u32,
        /// User-space pointer to write the name string.
        buf_ptr: u64,
    },
    /// Get filesystem index by name.
    GetFsIndex {
        /// User-space pointer to the NUL-terminated filesystem name.
        name_ptr: u64,
    },
    /// Get total number of filesystem types.
    GetFsCount,
}

impl SysfsOption {
    /// Construct from raw syscall arguments.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — unknown option value or null pointers where required.
    pub fn from_raw(option: u32, arg1: u64, arg2: u64) -> Result<Self> {
        match option {
            SYSFS_GET_FSNAME => {
                if arg2 == 0 {
                    return Err(Error::InvalidArgument);
                }
                Ok(Self::GetFsName {
                    fsindex: arg1 as u32,
                    buf_ptr: arg2,
                })
            }
            SYSFS_GET_FSINDEX => {
                if arg1 == 0 {
                    return Err(Error::InvalidArgument);
                }
                Ok(Self::GetFsIndex { name_ptr: arg1 })
            }
            SYSFS_GET_FSCOUNT => Ok(Self::GetFsCount),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Handle the `sysfs` syscall.
///
/// # Errors
/// - [`Error::NotFound`] — filesystem index out of range or name not found.
/// - [`Error::InvalidArgument`] — unknown option or null pointer.
pub fn sys_sysfs(option: SysfsOption) -> Result<i32> {
    // A full implementation would:
    // Option 1: walk the filesystem type list; write name at buf_ptr.
    // Option 2: look up by name; return the index.
    // Option 3: count all registered filesystem types.
    match option {
        SysfsOption::GetFsCount => Ok(0),
        SysfsOption::GetFsName { .. } => Err(Error::NotFound),
        SysfsOption::GetFsIndex { .. } => Err(Error::NotFound),
    }
}

/// Raw syscall entry point for `sysfs`.
///
/// # Arguments
/// * `option` — sub-command (register a0): 1, 2, or 3.
/// * `arg1` — first argument (register a1): index for opt 1, name ptr for opt 2.
/// * `arg2` — second argument (register a2): buf ptr for opt 1, unused otherwise.
///
/// # Returns
/// Result value on success (non-negative), negative errno on failure.
pub fn syscall_sysfs(option: u64, arg1: u64, arg2: u64) -> i64 {
    let opt = match SysfsOption::from_raw(option as u32, arg1, arg2) {
        Ok(o) => o,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_sysfs(opt) {
        Ok(val) => val as i64,
        Err(Error::NotFound) => -(oncrix_lib::errno::EINVAL as i64),
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_option_rejected() {
        assert!(SysfsOption::from_raw(0, 0, 0).is_err());
        assert!(SysfsOption::from_raw(99, 0, 0).is_err());
    }

    #[test]
    fn test_get_fsname_null_buf_rejected() {
        assert!(SysfsOption::from_raw(SYSFS_GET_FSNAME, 0, 0).is_err());
    }

    #[test]
    fn test_get_fsindex_null_name_rejected() {
        assert!(SysfsOption::from_raw(SYSFS_GET_FSINDEX, 0, 0).is_err());
    }

    #[test]
    fn test_get_fscount_option() {
        let opt = SysfsOption::from_raw(SYSFS_GET_FSCOUNT, 0, 0).unwrap();
        assert!(matches!(opt, SysfsOption::GetFsCount));
    }

    #[test]
    fn test_get_fsname_construction() {
        let opt = SysfsOption::from_raw(SYSFS_GET_FSNAME, 3, 0x1000).unwrap();
        match opt {
            SysfsOption::GetFsName { fsindex, buf_ptr } => {
                assert_eq!(fsindex, 3);
                assert_eq!(buf_ptr, 0x1000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_syscall_get_fscount() {
        let ret = syscall_sysfs(SYSFS_GET_FSCOUNT as u64, 0, 0);
        assert_eq!(ret, 0);
    }
}
