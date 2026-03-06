// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fchmodat2(2)` — change file mode with extended flags.
//!
//! `fchmodat2` extends `fchmodat(2)` by adding a `flags` parameter that
//! supports `AT_SYMLINK_NOFOLLOW`, allowing the caller to change the
//! permission bits of a symbolic link itself rather than the target it
//! refers to. It also supports `AT_EMPTY_PATH` to operate on the file
//! referred to by an open file descriptor.
//!
//! # Syscall signature
//!
//! ```text
//! int fchmodat2(int dirfd, const char *pathname, mode_t mode, int flags);
//! ```
//!
//! # Flags
//!
//! - `AT_SYMLINK_NOFOLLOW` — If `pathname` is a symlink, change the symlink
//!   itself instead of the file it points to.
//! - `AT_EMPTY_PATH` — If `pathname` is an empty string, operate on the
//!   file referred to by `dirfd` (which must be `O_PATH`).
//!
//! # Mode bits
//!
//! Only the lower 12 bits of `mode` are meaningful:
//! - Bits 0..8:  `rwxrwxrwx` permission bits.
//! - Bits 9..11: `setuid`, `setgid`, sticky bits.
//!
//! # Errors
//!
//! - `EINVAL` — Unknown flags or `pathname` is empty without `AT_EMPTY_PATH`.
//! - `EPERM`  — Insufficient privilege to set setuid/setgid.
//! - `ENOENT` — The path does not exist.
//! - `ENOTDIR` — `dirfd` is not a directory (when `pathname` is relative).
//!
//! # References
//!
//! - Linux: `fs/attr.c`, `fs/open.c`, `include/linux/fcntl.h`
//! - Linux syscall number x86_64: 452

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants — AT_* flags
// ---------------------------------------------------------------------------

/// Use `dirfd` itself when `pathname` is empty.
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// Do not follow symlinks; operate on the symlink node itself.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x0100;

/// Pseudo-value for `dirfd`: use the current working directory.
pub const AT_FDCWD: i32 = -100;

/// Mask of all valid `fchmodat2` flags.
const FCHMODAT2_FLAGS_MASK: u32 = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW;

/// Mask of valid permission bits (rwxrwxrwx + setuid/setgid/sticky).
const MODE_VALID_MASK: u32 = 0o7777;

/// Syscall number for `fchmodat2` (x86_64 Linux ABI).
pub const SYS_FCHMODAT2: u64 = 452;

// ---------------------------------------------------------------------------
// FileType — simplified inode kind
// ---------------------------------------------------------------------------

/// Kind of filesystem node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// Regular file.
    RegularFile,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Block device.
    BlockDevice,
    /// Character device.
    CharDevice,
    /// FIFO (named pipe).
    Fifo,
    /// Unix domain socket.
    Socket,
}

impl FileType {
    /// Return `true` if this node type supports `chmod`.
    ///
    /// Symlinks do not have permission bits on most filesystems, but
    /// `fchmodat2` with `AT_SYMLINK_NOFOLLOW` still requires the kernel
    /// to accept the call — the filesystem may silently ignore it or
    /// return `EOPNOTSUPP`.
    pub const fn supports_chmod(self) -> bool {
        !matches!(self, FileType::Socket)
    }
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// Minimal credential set for permission enforcement.
#[derive(Debug, Clone, Copy)]
pub struct Creds {
    /// Effective user ID.
    pub euid: u32,
    /// Whether the caller holds `CAP_FOWNER`.
    pub cap_fowner: bool,
    /// Whether the caller holds `CAP_FSETID`.
    pub cap_fsetid: bool,
}

impl Creds {
    /// Construct root credentials (all capabilities).
    pub const fn root() -> Self {
        Self {
            euid: 0,
            cap_fowner: true,
            cap_fsetid: true,
        }
    }

    /// Construct unprivileged credentials.
    pub const fn user(euid: u32) -> Self {
        Self {
            euid,
            cap_fowner: false,
            cap_fsetid: false,
        }
    }
}

// ---------------------------------------------------------------------------
// InodeMeta — minimal inode metadata for the operation
// ---------------------------------------------------------------------------

/// Minimal inode attributes required by `fchmodat2`.
#[derive(Debug, Clone, Copy)]
pub struct InodeMeta {
    /// Inode number (for error messages / identity).
    pub ino: u64,
    /// Inode owner UID.
    pub uid: u32,
    /// File type.
    pub kind: FileType,
    /// Current permission bits.
    pub mode: u32,
    /// Whether the filesystem is mounted read-only.
    pub read_only_fs: bool,
}

impl InodeMeta {
    /// Construct inode metadata.
    pub const fn new(ino: u64, uid: u32, kind: FileType, mode: u32) -> Self {
        Self {
            ino,
            uid,
            kind,
            mode,
            read_only_fs: false,
        }
    }

    /// Construct read-only-filesystem inode metadata.
    pub const fn read_only(ino: u64, uid: u32, kind: FileType, mode: u32) -> Self {
        Self {
            ino,
            uid,
            kind,
            mode,
            read_only_fs: true,
        }
    }
}

// ---------------------------------------------------------------------------
// PathResolutionResult — outcome of path lookup
// ---------------------------------------------------------------------------

/// Result of resolving a pathname in the context of `fchmodat2`.
#[derive(Debug, Clone, Copy)]
pub enum PathResolutionResult {
    /// The path resolved to a concrete inode.
    Resolved(InodeMeta),
    /// The path component does not exist.
    NotFound,
    /// `dirfd` is not a directory (relative path case).
    NotDirectory,
    /// The path resolves to a symlink and `AT_SYMLINK_NOFOLLOW` was set.
    Symlink(InodeMeta),
}

// ---------------------------------------------------------------------------
// Fchmodat2Args — validated argument bundle
// ---------------------------------------------------------------------------

/// Validated arguments for `fchmodat2`.
#[derive(Debug, Clone, Copy)]
pub struct Fchmodat2Args {
    /// Directory file descriptor, or `AT_FDCWD`.
    pub dirfd: i32,
    /// Permission mode bits.
    pub mode: u32,
    /// Flags (`AT_EMPTY_PATH`, `AT_SYMLINK_NOFOLLOW`).
    pub flags: u32,
}

impl Fchmodat2Args {
    /// Validate flags and mode.
    ///
    /// # Checks
    ///
    /// - No unknown flag bits.
    /// - No unknown mode bits.
    pub fn validate(&self) -> Result<()> {
        if self.flags & !FCHMODAT2_FLAGS_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.mode & !MODE_VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return `true` if `AT_SYMLINK_NOFOLLOW` is set.
    pub const fn nofollow(&self) -> bool {
        self.flags & AT_SYMLINK_NOFOLLOW != 0
    }

    /// Return `true` if `AT_EMPTY_PATH` is set.
    pub const fn empty_path(&self) -> bool {
        self.flags & AT_EMPTY_PATH != 0
    }
}

// ---------------------------------------------------------------------------
// Permission check
// ---------------------------------------------------------------------------

/// Check whether `creds` may `chmod` the given inode to `new_mode`.
///
/// # Rules (mirrors Linux `security_inode_setattr` + `inode_change_ok`)
///
/// 1. Read-only filesystem → `EROFS`.
/// 2. Not the owner and not `CAP_FOWNER` → `EPERM`.
/// 3. Setting setgid on a file not in the caller's group without `CAP_FSETID`
///    → the setgid bit is silently cleared (we flag it as `PermissionDenied`
///    in the stub to keep the API clean).
/// 4. Symbolic links do not have meaningful permission bits — return `Ok` but
///    the caller should propagate to the VFS which may return `EOPNOTSUPP`.
fn check_chmod_permission(creds: &Creds, inode: &InodeMeta, new_mode: u32) -> Result<()> {
    if inode.read_only_fs {
        return Err(Error::PermissionDenied);
    }

    // Must be owner or have CAP_FOWNER.
    if creds.euid != inode.uid && !creds.cap_fowner {
        return Err(Error::PermissionDenied);
    }

    // Attempting to set setuid/setgid without CAP_FSETID is not immediately an
    // error (Linux clears the bits silently), but we track it.
    let setid_bits = new_mode & 0o6000;
    if setid_bits != 0 && !creds.cap_fsetid && creds.euid != 0 {
        // In a real kernel these bits would be silently stripped.
        // Here we return PermissionDenied to make the policy observable.
        return Err(Error::PermissionDenied);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Chmod result
// ---------------------------------------------------------------------------

/// The new mode that should be applied to the inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChmodResult {
    /// Inode number the chmod applies to.
    pub ino: u64,
    /// The sanitized mode bits to write.
    pub new_mode: u32,
    /// `true` if setuid/setgid bits were stripped.
    pub setid_stripped: bool,
}

// ---------------------------------------------------------------------------
// do_fchmodat2
// ---------------------------------------------------------------------------

/// Core logic for `fchmodat2(2)`.
///
/// # Arguments
///
/// - `creds`      — Caller credentials.
/// - `args`       — Validated argument bundle.
/// - `resolution` — Result of pathname resolution by the VFS layer.
/// - `pathname_empty` — `true` when the user passed an empty string.
///
/// # Returns
///
/// A [`ChmodResult`] describing the mode change on success.
///
/// # Errors
///
/// - [`Error::InvalidArgument`]   — Bad flags/mode.
/// - [`Error::PermissionDenied`]  — Caller is not owner / lacks capability.
/// - [`Error::NotFound`]          — Path does not exist.
/// - [`Error::PermissionDenied`] — Filesystem is read-only.
/// - [`Error::InvalidArgument`]      — `dirfd` is not a directory.
pub fn do_fchmodat2(
    creds: &Creds,
    args: &Fchmodat2Args,
    resolution: PathResolutionResult,
    pathname_empty: bool,
) -> Result<ChmodResult> {
    args.validate()?;

    // Empty pathname without AT_EMPTY_PATH is an error.
    if pathname_empty && !args.empty_path() {
        return Err(Error::NotFound);
    }

    let inode = match resolution {
        PathResolutionResult::Resolved(m) => m,
        PathResolutionResult::Symlink(m) => {
            // AT_SYMLINK_NOFOLLOW: operate on the symlink inode itself.
            if !args.nofollow() {
                // Should not happen (VFS follows symlinks normally), but
                // guard anyway.
                return Err(Error::InvalidArgument);
            }
            m
        }
        PathResolutionResult::NotFound => return Err(Error::NotFound),
        PathResolutionResult::NotDirectory => return Err(Error::InvalidArgument),
    };

    // Permission check.
    check_chmod_permission(creds, &inode, args.mode)?;

    // Compute the sanitized mode.
    // Only owner/root may set setuid/setgid. If the caller does not have
    // CAP_FSETID, those bits are cleared in the result.
    let setid_bits = args.mode & 0o6000;
    let strip_setid = setid_bits != 0 && !creds.cap_fsetid && creds.euid != 0;
    let new_mode = if strip_setid {
        args.mode & !0o6000
    } else {
        args.mode
    };

    Ok(ChmodResult {
        ino: inode.ino,
        new_mode: new_mode & MODE_VALID_MASK,
        setid_stripped: strip_setid,
    })
}

// ---------------------------------------------------------------------------
// Syscall entry point
// ---------------------------------------------------------------------------

/// Process a raw `fchmodat2` syscall.
///
/// # Arguments
///
/// - `creds`      — Caller credentials.
/// - `dirfd`      — Raw `dirfd` register value (interpreted as `i32`).
/// - `mode`       — Raw `mode` register value.
/// - `flags`      — Raw `flags` register value.
/// - `resolution` — VFS path resolution result.
/// - `pathname_empty` — Whether the path string was empty.
///
/// # Returns
///
/// 0 on success (POSIX `chmod` returns 0 on success).
pub fn sys_fchmodat2(
    creds: &Creds,
    dirfd: u64,
    mode: u64,
    flags: u64,
    resolution: PathResolutionResult,
    pathname_empty: bool,
) -> Result<i32> {
    let dirfd_i32 = i32::try_from(dirfd as i64).unwrap_or(dirfd as i32);
    let mode_u32 = u32::try_from(mode).map_err(|_| Error::InvalidArgument)?;
    let flags_u32 = u32::try_from(flags).map_err(|_| Error::InvalidArgument)?;

    let args = Fchmodat2Args {
        dirfd: dirfd_i32,
        mode: mode_u32,
        flags: flags_u32,
    };

    do_fchmodat2(creds, &args, resolution, pathname_empty)?;
    Ok(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn owner_creds() -> Creds {
        Creds::user(1000)
    }

    fn other_creds() -> Creds {
        Creds::user(2000)
    }

    fn regular_inode() -> InodeMeta {
        InodeMeta::new(42, 1000, FileType::RegularFile, 0o644)
    }

    fn symlink_inode() -> InodeMeta {
        InodeMeta::new(99, 1000, FileType::Symlink, 0o777)
    }

    fn ro_inode() -> InodeMeta {
        InodeMeta::read_only(10, 1000, FileType::RegularFile, 0o644)
    }

    // --- Basic success cases ---

    #[test]
    fn chmod_owner_regular_file() {
        let creds = owner_creds();
        let args = Fchmodat2Args {
            dirfd: AT_FDCWD,
            mode: 0o755,
            flags: 0,
        };
        let res = do_fchmodat2(
            &creds,
            &args,
            PathResolutionResult::Resolved(regular_inode()),
            false,
        )
        .unwrap();
        assert_eq!(res.new_mode, 0o755);
        assert!(!res.setid_stripped);
    }

    #[test]
    fn chmod_root_can_change_any_file() {
        let args = Fchmodat2Args {
            dirfd: AT_FDCWD,
            mode: 0o700,
            flags: 0,
        };
        let inode = InodeMeta::new(5, 9999, FileType::RegularFile, 0o644);
        let res = do_fchmodat2(
            &Creds::root(),
            &args,
            PathResolutionResult::Resolved(inode),
            false,
        )
        .unwrap();
        assert_eq!(res.new_mode, 0o700);
    }

    // --- AT_SYMLINK_NOFOLLOW ---

    #[test]
    fn chmod_symlink_nofollow() {
        let creds = owner_creds();
        let args = Fchmodat2Args {
            dirfd: AT_FDCWD,
            mode: 0o644,
            flags: AT_SYMLINK_NOFOLLOW,
        };
        let res = do_fchmodat2(
            &creds,
            &args,
            PathResolutionResult::Symlink(symlink_inode()),
            false,
        )
        .unwrap();
        assert_eq!(res.ino, 99);
        assert_eq!(res.new_mode, 0o644);
    }

    #[test]
    fn chmod_resolved_node_with_nofollow_flag() {
        // A regular file resolved with AT_SYMLINK_NOFOLLOW is still allowed.
        let creds = owner_creds();
        let args = Fchmodat2Args {
            dirfd: AT_FDCWD,
            mode: 0o600,
            flags: AT_SYMLINK_NOFOLLOW,
        };
        let res = do_fchmodat2(
            &creds,
            &args,
            PathResolutionResult::Resolved(regular_inode()),
            false,
        )
        .unwrap();
        assert_eq!(res.new_mode, 0o600);
    }

    // --- AT_EMPTY_PATH ---

    #[test]
    fn chmod_empty_path_with_flag() {
        let creds = owner_creds();
        let args = Fchmodat2Args {
            dirfd: 5,
            mode: 0o400,
            flags: AT_EMPTY_PATH,
        };
        let res = do_fchmodat2(
            &creds,
            &args,
            PathResolutionResult::Resolved(regular_inode()),
            true,
        )
        .unwrap();
        assert_eq!(res.new_mode, 0o400);
    }

    #[test]
    fn chmod_empty_path_without_flag_fails() {
        let creds = owner_creds();
        let args = Fchmodat2Args {
            dirfd: AT_FDCWD,
            mode: 0o644,
            flags: 0,
        };
        // empty pathname but no AT_EMPTY_PATH
        assert_eq!(
            do_fchmodat2(
                &creds,
                &args,
                PathResolutionResult::Resolved(regular_inode()),
                true
            ),
            Err(Error::NotFound)
        );
    }

    // --- Permission errors ---

    #[test]
    fn chmod_non_owner_fails() {
        let creds = other_creds();
        let args = Fchmodat2Args {
            dirfd: AT_FDCWD,
            mode: 0o777,
            flags: 0,
        };
        assert_eq!(
            do_fchmodat2(
                &creds,
                &args,
                PathResolutionResult::Resolved(regular_inode()),
                false
            ),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn chmod_cap_fowner_allows_non_owner() {
        let creds = Creds {
            euid: 2000,
            cap_fowner: true,
            cap_fsetid: false,
        };
        let args = Fchmodat2Args {
            dirfd: AT_FDCWD,
            mode: 0o644,
            flags: 0,
        };
        let res = do_fchmodat2(
            &creds,
            &args,
            PathResolutionResult::Resolved(regular_inode()),
            false,
        )
        .unwrap();
        assert_eq!(res.new_mode, 0o644);
    }

    #[test]
    fn chmod_setuid_without_cap_fsetid_denied() {
        let creds = Creds {
            euid: 1000,
            cap_fowner: true,
            cap_fsetid: false,
        };
        let args = Fchmodat2Args {
            dirfd: AT_FDCWD,
            mode: 0o4755, // setuid bit
            flags: 0,
        };
        assert_eq!(
            do_fchmodat2(
                &creds,
                &args,
                PathResolutionResult::Resolved(regular_inode()),
                false
            ),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn chmod_setuid_root_allowed() {
        let args = Fchmodat2Args {
            dirfd: AT_FDCWD,
            mode: 0o4755,
            flags: 0,
        };
        let res = do_fchmodat2(
            &Creds::root(),
            &args,
            PathResolutionResult::Resolved(regular_inode()),
            false,
        )
        .unwrap();
        assert_eq!(res.new_mode, 0o4755);
        assert!(!res.setid_stripped);
    }

    // --- Filesystem errors ---

    #[test]
    fn chmod_read_only_filesystem_fails() {
        let creds = owner_creds();
        let args = Fchmodat2Args {
            dirfd: AT_FDCWD,
            mode: 0o644,
            flags: 0,
        };
        assert_eq!(
            do_fchmodat2(
                &creds,
                &args,
                PathResolutionResult::Resolved(ro_inode()),
                false
            ),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn chmod_path_not_found() {
        let creds = owner_creds();
        let args = Fchmodat2Args {
            dirfd: AT_FDCWD,
            mode: 0o644,
            flags: 0,
        };
        assert_eq!(
            do_fchmodat2(&creds, &args, PathResolutionResult::NotFound, false),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn chmod_not_directory() {
        let creds = owner_creds();
        let args = Fchmodat2Args {
            dirfd: 5,
            mode: 0o644,
            flags: 0,
        };
        assert_eq!(
            do_fchmodat2(&creds, &args, PathResolutionResult::NotDirectory, false),
            Err(Error::InvalidArgument)
        );
    }

    // --- Validation ---

    #[test]
    fn invalid_flags_rejected() {
        let creds = owner_creds();
        let args = Fchmodat2Args {
            dirfd: AT_FDCWD,
            mode: 0o644,
            flags: 0xFFFF_FFFF, // all bits
        };
        assert_eq!(
            do_fchmodat2(
                &creds,
                &args,
                PathResolutionResult::Resolved(regular_inode()),
                false
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn invalid_mode_bits_rejected() {
        let creds = owner_creds();
        let args = Fchmodat2Args {
            dirfd: AT_FDCWD,
            mode: 0o17777, // bit 13 set — invalid
            flags: 0,
        };
        assert_eq!(
            do_fchmodat2(
                &creds,
                &args,
                PathResolutionResult::Resolved(regular_inode()),
                false
            ),
            Err(Error::InvalidArgument)
        );
    }

    // --- Syscall entry point ---

    #[test]
    fn sys_fchmodat2_success() {
        let res = sys_fchmodat2(
            &owner_creds(),
            AT_FDCWD as u64,
            0o755,
            0,
            PathResolutionResult::Resolved(regular_inode()),
            false,
        )
        .unwrap();
        assert_eq!(res, 0);
    }

    #[test]
    fn sys_fchmodat2_invalid_mode() {
        let result = sys_fchmodat2(
            &owner_creds(),
            AT_FDCWD as u64,
            u64::MAX, // overflows u32
            0,
            PathResolutionResult::Resolved(regular_inode()),
            false,
        );
        assert_eq!(result, Err(Error::InvalidArgument));
    }
}
