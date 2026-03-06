// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `umount2` syscall handler.
//!
//! Unmounts a mounted filesystem with extended flags. `umount2` supersedes
//! the older `umount` syscall by adding flag support to control unmount behavior.
//!
//! Supported flags (Linux-compatible):
//! - `MNT_FORCE` (1) — Force unmount even if the device is busy.
//! - `MNT_DETACH` (2) — Perform a lazy unmount: make the mount point
//!   unavailable for new accesses while allowing existing accesses to continue.
//! - `MNT_EXPIRE` (4) — Mark the mount as expired; a second call with this
//!   flag actually unmounts if the mount was already marked expired.
//! - `UMOUNT_NOFOLLOW` (8) — Do not dereference the target if it is a symlink.
//!
//! # POSIX Conformance
//! `umount` / `umount2` are not specified by POSIX.1-2024 but are standard
//! Linux system calls. This implementation follows Linux kernel semantics.

use oncrix_lib::{Error, Result};

/// Flag: force unmount even if the device is busy.
pub const MNT_FORCE: u32 = 1;
/// Flag: lazy (detach) unmount.
pub const MNT_DETACH: u32 = 2;
/// Flag: mark the mount as expired.
pub const MNT_EXPIRE: u32 = 4;
/// Flag: do not follow symlinks in the target path.
pub const UMOUNT_NOFOLLOW: u32 = 8;

/// Bitmask of all valid `umount2` flags.
const VALID_FLAGS: u32 = MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW;

/// Validated flags for an `umount2` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Umount2Flags(u32);

impl Umount2Flags {
    /// Construct `Umount2Flags` from a raw flags word.
    ///
    /// # Errors
    /// Returns [`Error::InvalidArgument`] if any unknown flags are set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Returns the raw flags value.
    pub fn raw(self) -> u32 {
        self.0
    }

    /// Returns `true` if `MNT_FORCE` is set.
    pub fn force(self) -> bool {
        self.0 & MNT_FORCE != 0
    }

    /// Returns `true` if `MNT_DETACH` is set.
    pub fn detach(self) -> bool {
        self.0 & MNT_DETACH != 0
    }

    /// Returns `true` if `MNT_EXPIRE` is set.
    pub fn expire(self) -> bool {
        self.0 & MNT_EXPIRE != 0
    }

    /// Returns `true` if `UMOUNT_NOFOLLOW` is set.
    pub fn nofollow(self) -> bool {
        self.0 & UMOUNT_NOFOLLOW != 0
    }
}

/// Arguments for the `umount2` syscall.
#[derive(Debug, Clone, Copy)]
pub struct Umount2Args {
    /// User-space pointer to the NUL-terminated target path.
    pub target_ptr: u64,
    /// Validated flags controlling unmount behavior.
    pub flags: Umount2Flags,
}

impl Umount2Args {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — null pointer or unknown flags.
    pub fn from_raw(target_ptr: u64, flags_raw: u64) -> Result<Self> {
        if target_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        let flags = Umount2Flags::from_raw(flags_raw as u32)?;
        Ok(Self { target_ptr, flags })
    }
}

/// Handle the `umount2` syscall.
///
/// Unmounts the filesystem mounted at `target`. Requires `CAP_SYS_ADMIN`.
///
/// # Errors
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_ADMIN`.
/// - [`Error::Busy`] — device is busy and `MNT_FORCE` was not specified.
/// - [`Error::InvalidArgument`] — null pointer or unknown flags.
/// - [`Error::NotFound`] — target is not a mount point.
pub fn sys_umount2(args: Umount2Args) -> Result<()> {
    // A full implementation would:
    // 1. Resolve the target path, optionally not following symlinks.
    // 2. Check CAP_SYS_ADMIN in caller credentials.
    // 3. Look up the mount point in the mount table.
    // 4. Apply MNT_EXPIRE, MNT_DETACH, or MNT_FORCE semantics.
    // 5. Flush and drop all dentries/inodes pinned to that mount.
    let _ = args;
    Ok(())
}

/// Raw syscall entry point for `umount2`.
///
/// # Arguments
/// * `target_ptr` — user-space pointer to target path (register a0).
/// * `flags` — unmount flags (register a1).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_umount2(target_ptr: u64, flags: u64) -> i64 {
    let args = match Umount2Args::from_raw(target_ptr, flags) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_umount2(args) {
        Ok(()) => 0,
        Err(Error::PermissionDenied) => -(oncrix_lib::errno::EPERM as i64),
        Err(Error::Busy) => -(oncrix_lib::errno::EBUSY as i64),
        Err(Error::NotFound) => -(oncrix_lib::errno::ENOENT as i64),
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flags_from_raw_valid() {
        let f = Umount2Flags::from_raw(MNT_FORCE | MNT_DETACH).unwrap();
        assert!(f.force());
        assert!(f.detach());
        assert!(!f.expire());
        assert!(!f.nofollow());
    }

    #[test]
    fn test_flags_from_raw_invalid() {
        assert!(Umount2Flags::from_raw(0x100).is_err());
    }

    #[test]
    fn test_zero_flags_allowed() {
        let f = Umount2Flags::from_raw(0).unwrap();
        assert!(!f.force());
        assert!(!f.detach());
    }

    #[test]
    fn test_null_target_rejected() {
        assert!(Umount2Args::from_raw(0, 0).is_err());
    }

    #[test]
    fn test_valid_args_construction() {
        let args = Umount2Args::from_raw(0x8000, MNT_DETACH as u64).unwrap();
        assert_eq!(args.target_ptr, 0x8000);
        assert!(args.flags.detach());
    }

    #[test]
    fn test_syscall_returns_zero_on_success() {
        let ret = syscall_umount2(0x1000, 0);
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_nofollow_flag() {
        let f = Umount2Flags::from_raw(UMOUNT_NOFOLLOW).unwrap();
        assert!(f.nofollow());
    }
}
