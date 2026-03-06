// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mount_setattr(2)` syscall handler — change properties of a mount.
//!
//! `mount_setattr` changes the mount properties of a mount or an entire mount
//! tree.  Unlike the older `mount(2)` with `MS_REMOUNT`, this syscall
//! operates on individual mounts or trees and supports an extensible
//! attributes structure.
//!
//! # Linux reference
//!
//! Linux-specific: `mount_setattr(2)` man page (added in Linux 5.12).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Mount attribute flags (attr_set / attr_clr)
// ---------------------------------------------------------------------------

/// Make the mount read-only.
pub const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
/// Don't honor `set-user-ID` and `set-group-ID` bits.
pub const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
/// Don't allow access to device special files.
pub const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
/// Don't allow program execution.
pub const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;
/// Respect atime mask — use sub-bits below.
pub const MOUNT_ATTR__ATIME: u64 = 0x0000_0070;
/// Do not update access times.
pub const MOUNT_ATTR_NOATIME: u64 = 0x0000_0010;
/// Always update access times.
pub const MOUNT_ATTR_STRICTATIME: u64 = 0x0000_0020;
/// Update relative access time.
pub const MOUNT_ATTR_RELATIME: u64 = 0x0000_0030;
/// Don't update directory access times.
pub const MOUNT_ATTR_NODIRATIME: u64 = 0x0000_0080;
/// Idmapped mount — requires `userns_fd`.
pub const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
/// Disable following symbolic links.
pub const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x0020_0000;

/// All valid attribute bits.
const VALID_ATTRS: u64 = MOUNT_ATTR_RDONLY
    | MOUNT_ATTR_NOSUID
    | MOUNT_ATTR_NODEV
    | MOUNT_ATTR_NOEXEC
    | MOUNT_ATTR__ATIME
    | MOUNT_ATTR_NODIRATIME
    | MOUNT_ATTR_IDMAP
    | MOUNT_ATTR_NOSYMFOLLOW;

// ---------------------------------------------------------------------------
// `mount_setattr` flags
// ---------------------------------------------------------------------------

/// Apply changes recursively to the whole mount tree.
pub const AT_RECURSIVE: u32 = 0x8000;
/// `AT_FDCWD` sentinel.
pub const AT_FDCWD: i32 = -100;
/// Do not follow symlinks when looking up path.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
/// Do not automount the final path component.
pub const AT_NO_AUTOMOUNT: u32 = 0x800;
/// Allow an empty path string (operate on `dirfd` itself).
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// All valid `flags` bits.
const VALID_FLAGS: u32 = AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH;

// ---------------------------------------------------------------------------
// mount_attr structure
// ---------------------------------------------------------------------------

/// Mirrors `struct mount_attr` from `<linux/mount.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MountAttr {
    /// Attributes to set.
    pub attr_set: u64,
    /// Attributes to clear.
    pub attr_clr: u64,
    /// Access-time propagation mode (see `MOUNT_ATTR_*_ATIME`).
    pub propagation: u64,
    /// User namespace fd for idmapped mounts (only when `MOUNT_ATTR_IDMAP` set).
    pub userns_fd: u64,
}

impl MountAttr {
    /// Create a zeroed `MountAttr`.
    pub const fn new() -> Self {
        Self {
            attr_set: 0,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        }
    }
}

/// Validated `mount_setattr` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountSetattrRequest {
    /// Directory fd for path resolution.
    pub dirfd: i32,
    /// User-space pointer to the pathname.
    pub pathname: usize,
    /// Operation flags.
    pub flags: u32,
    /// Mount attribute specification.
    pub attr: MountAttr,
    /// Size of the `mount_attr` struct passed by user (for extensibility).
    pub usize: usize,
}

impl MountSetattrRequest {
    /// Minimum size of `struct mount_attr` accepted.
    pub const MIN_SIZE: usize = 32;

    /// Construct a new request.
    pub const fn new(
        dirfd: i32,
        pathname: usize,
        flags: u32,
        attr: MountAttr,
        usize: usize,
    ) -> Self {
        Self {
            dirfd,
            pathname,
            flags,
            attr,
            usize,
        }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `mount_setattr(2)`.
///
/// Validates all arguments and returns a structured request.  The caller must
/// hold appropriate capabilities (`CAP_SYS_ADMIN` or a user namespace with
/// sufficient privileges).
///
/// # Arguments
///
/// - `dirfd`    — directory fd or `AT_FDCWD`
/// - `pathname` — user-space path pointer
/// - `flags`    — combination of `AT_*` flags
/// - `attr`     — mount attribute specification
/// - `usize`    — `sizeof(struct mount_attr)` as passed by user
///
/// # Errors
///
/// | `Error`           | Condition                                         |
/// |-------------------|---------------------------------------------------|
/// | `InvalidArgument` | Unknown flags, conflicting attrs, bad struct size |
/// | `PermissionDenied`| Insufficient privileges                           |
pub fn do_mount_setattr(
    dirfd: i32,
    pathname: usize,
    flags: u32,
    attr: MountAttr,
    usize: usize,
) -> Result<MountSetattrRequest> {
    // Validate flags.
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    // Struct size must be at least the minimum.
    if usize < MountSetattrRequest::MIN_SIZE {
        return Err(Error::InvalidArgument);
    }
    // Cannot set and clear the same bits simultaneously.
    if attr.attr_set & attr.attr_clr != 0 {
        return Err(Error::InvalidArgument);
    }
    // Validate attribute bits.
    if attr.attr_set & !VALID_ATTRS != 0 || attr.attr_clr & !VALID_ATTRS != 0 {
        return Err(Error::InvalidArgument);
    }
    // `MOUNT_ATTR_IDMAP` requires a valid user namespace fd.
    if attr.attr_set & MOUNT_ATTR_IDMAP != 0 && attr.userns_fd == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(MountSetattrRequest::new(
        dirfd, pathname, flags, attr, usize,
    ))
}

/// Return `true` if the request applies changes recursively.
pub fn is_recursive(flags: u32) -> bool {
    flags & AT_RECURSIVE != 0
}

/// Return `true` if the request configures an idmapped mount.
pub fn is_idmapped(attr: &MountAttr) -> bool {
    attr.attr_set & MOUNT_ATTR_IDMAP != 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_setattr_ok() {
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: 0,
            ..MountAttr::new()
        };
        let req = do_mount_setattr(AT_FDCWD, 0x1000, 0, attr, 32).unwrap();
        assert_eq!(req.attr.attr_set, MOUNT_ATTR_RDONLY);
    }

    #[test]
    fn unknown_flags_rejected() {
        let attr = MountAttr::new();
        assert_eq!(
            do_mount_setattr(AT_FDCWD, 0, 0xFFFF_0000, attr, 32),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn conflicting_attrs_rejected() {
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: MOUNT_ATTR_RDONLY,
            ..MountAttr::new()
        };
        assert_eq!(
            do_mount_setattr(AT_FDCWD, 0, 0, attr, 32),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn struct_too_small_rejected() {
        let attr = MountAttr::new();
        assert_eq!(
            do_mount_setattr(AT_FDCWD, 0, 0, attr, 8),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn idmap_without_userns_rejected() {
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_IDMAP,
            userns_fd: 0,
            ..MountAttr::new()
        };
        assert_eq!(
            do_mount_setattr(AT_FDCWD, 0, 0, attr, 32),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn recursive_detection() {
        assert!(is_recursive(AT_RECURSIVE));
        assert!(!is_recursive(0));
    }

    #[test]
    fn idmapped_detection() {
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_IDMAP,
            userns_fd: 5,
            ..MountAttr::new()
        };
        assert!(is_idmapped(&attr));
        assert!(!is_idmapped(&MountAttr::new()));
    }
}
