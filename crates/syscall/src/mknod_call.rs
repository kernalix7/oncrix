// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mknod(2)` / `mknodat(2)` — create a special file node.
//!
//! `mknod(2)` creates filesystem nodes: regular files, character devices,
//! block devices, FIFOs (named pipes), or UNIX-domain sockets.
//!
//! `mknodat(2)` is the `*at` variant using a directory file descriptor as
//! the base for relative paths, following the `openat(2)` family pattern.
//!
//! # Prototype
//!
//! ```text
//! int mknod(const char *pathname, mode_t mode, dev_t dev);
//! int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
//! ```
//!
//! # File type flags (`mode & S_IFMT`)
//!
//! | Flag | Value | Description |
//! |------|-------|-------------|
//! | `S_IFREG` | 0o100000 | Regular file (empty) |
//! | `S_IFCHR` | 0o020000 | Character device |
//! | `S_IFBLK` | 0o060000 | Block device |
//! | `S_IFIFO` | 0o010000 | FIFO / named pipe |
//! | `S_IFSOCK` | 0o140000 | UNIX-domain socket (deprecated via mknod) |
//!
//! # Permissions
//!
//! - Requires `CAP_MKNOD` to create device nodes.
//! - `mode` is modified by the process umask: `actual = mode & ~umask`.
//! - `dev` is only meaningful for `S_IFCHR` and `S_IFBLK`; must be 0
//!   for other types.
//!
//! # POSIX
//!
//! Defined by POSIX.1-2024.  See `susv5-html/functions/mknod.html`.
//! The `mknodat(2)` extension is in POSIX.1-2008 and later.
//!
//! # References
//!
//! - Linux: `fs/namei.c` (`do_mknod`)
//! - POSIX: `mknod(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Mode / file-type constants
// ---------------------------------------------------------------------------

/// File type mask in `mode_t`.
pub const S_IFMT: u32 = 0o170000;

/// Regular file.
pub const S_IFREG: u32 = 0o100000;

/// Character device.
pub const S_IFCHR: u32 = 0o020000;

/// Block device.
pub const S_IFBLK: u32 = 0o060000;

/// FIFO (named pipe).
pub const S_IFIFO: u32 = 0o010000;

/// UNIX-domain socket.
pub const S_IFSOCK: u32 = 0o140000;

/// Directory.
pub const S_IFDIR: u32 = 0o040000;

/// Symbolic link.
pub const S_IFLNK: u32 = 0o120000;

/// All permission bits (rwxrwxrwx + setuid/setgid/sticky).
pub const S_PERM_MASK: u32 = 0o7777;

// ---------------------------------------------------------------------------
// `dirfd` sentinel
// ---------------------------------------------------------------------------

/// `AT_FDCWD` — use the current working directory as the base directory for
/// relative paths in `mknodat(2)`.
pub const AT_FDCWD: i32 = -100;

// ---------------------------------------------------------------------------
// Device number helpers
// ---------------------------------------------------------------------------

/// Encode a device number from major and minor components.
///
/// Uses the Linux `makedev` formula:
/// `dev = (major << 8) | minor` for minor < 256,
/// extended for larger minor numbers.
pub const fn makedev(major: u32, minor: u32) -> u64 {
    let major = major as u64;
    let minor = minor as u64;
    ((major & 0xfff) << 8) | (minor & 0xff) | ((major & !0xfff) << 32) | ((minor & !0xff) << 12)
}

/// Extract the major device number from a device ID.
pub const fn major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

/// Extract the minor device number from a device ID.
pub const fn minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
}

// ---------------------------------------------------------------------------
// File type
// ---------------------------------------------------------------------------

/// File node type for `mknod`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// Regular file (empty).
    Regular = S_IFREG,
    /// Character device.
    CharDevice = S_IFCHR,
    /// Block device.
    BlockDevice = S_IFBLK,
    /// FIFO (named pipe).
    Fifo = S_IFIFO,
    /// UNIX-domain socket.
    Socket = S_IFSOCK,
}

impl NodeType {
    /// Parse a node type from the `S_IFMT` bits of `mode`.
    ///
    /// Returns `None` for unrecognised or unsupported file types
    /// (e.g. `S_IFDIR`, `S_IFLNK`).
    pub fn from_mode(mode: u32) -> Option<NodeType> {
        match mode & S_IFMT {
            S_IFREG => Some(NodeType::Regular),
            S_IFCHR => Some(NodeType::CharDevice),
            S_IFBLK => Some(NodeType::BlockDevice),
            S_IFIFO => Some(NodeType::Fifo),
            S_IFSOCK => Some(NodeType::Socket),
            _ => None,
        }
    }

    /// Returns `true` if this type requires a device number.
    pub const fn needs_dev(&self) -> bool {
        matches!(self, NodeType::CharDevice | NodeType::BlockDevice)
    }

    /// Returns `true` if creating this node type requires `CAP_MKNOD`.
    pub const fn requires_mknod_cap(&self) -> bool {
        matches!(self, NodeType::CharDevice | NodeType::BlockDevice)
    }
}

// ---------------------------------------------------------------------------
// Capability stub
// ---------------------------------------------------------------------------

/// Caller capability context passed to `mknodat`.
///
/// In a full implementation this would carry the process's capability set.
/// Here we model it with boolean flags for the relevant capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CallerCaps {
    /// Caller holds `CAP_MKNOD`.
    pub mknod: bool,
    /// Caller holds `CAP_SYS_ADMIN`.
    pub sys_admin: bool,
    /// Caller holds `CAP_DAC_OVERRIDE`.
    pub dac_override: bool,
}

impl CallerCaps {
    /// Unprivileged caller.
    pub const fn unprivileged() -> Self {
        Self {
            mknod: false,
            sys_admin: false,
            dac_override: false,
        }
    }

    /// Fully privileged caller (root equivalent).
    pub const fn privileged() -> Self {
        Self {
            mknod: true,
            sys_admin: true,
            dac_override: true,
        }
    }
}

// ---------------------------------------------------------------------------
// `mknodat` arguments
// ---------------------------------------------------------------------------

/// Arguments to the `mknodat(2)` syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MknotatArgs {
    /// Base directory fd. `AT_FDCWD` = use CWD.
    pub dirfd: i32,
    /// Pathname (pointer validated elsewhere; here stored as a length for
    /// the stub model).
    pub path_len: usize,
    /// File creation mode including type bits (`mode_t`).
    pub mode: u32,
    /// Device number (only for character/block devices).
    pub dev: u64,
}

impl MknotatArgs {
    /// Create args for a FIFO.
    pub const fn fifo(dirfd: i32, mode: u32) -> Self {
        Self {
            dirfd,
            path_len: 1,
            mode: S_IFIFO | (mode & S_PERM_MASK),
            dev: 0,
        }
    }

    /// Create args for a character device.
    pub const fn char_dev(dirfd: i32, mode: u32, major: u32, minor: u32) -> Self {
        Self {
            dirfd,
            path_len: 1,
            mode: S_IFCHR | (mode & S_PERM_MASK),
            dev: makedev(major, minor),
        }
    }

    /// Create args for a block device.
    pub const fn block_dev(dirfd: i32, mode: u32, major: u32, minor: u32) -> Self {
        Self {
            dirfd,
            path_len: 1,
            mode: S_IFBLK | (mode & S_PERM_MASK),
            dev: makedev(major, minor),
        }
    }

    /// Create args for a regular file.
    pub const fn regular(dirfd: i32, mode: u32) -> Self {
        Self {
            dirfd,
            path_len: 1,
            mode: S_IFREG | (mode & S_PERM_MASK),
            dev: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Node creation result
// ---------------------------------------------------------------------------

/// Result of a successful `mknod` / `mknodat` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MknodResult {
    /// The file type created.
    pub node_type: NodeType,
    /// The effective permission mode (after applying umask).
    pub effective_mode: u32,
    /// The device number (0 for non-device nodes).
    pub dev: u64,
    /// Major device number (0 for non-device nodes).
    pub major: u32,
    /// Minor device number (0 for non-device nodes).
    pub minor: u32,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `mknodat` arguments.
///
/// Checks:
///
/// 1. File type is recognised and supported.
/// 2. `dev` is 0 for non-device types.
/// 3. Caller has `CAP_MKNOD` for device creation.
/// 4. `dirfd` is valid (either `AT_FDCWD` or non-negative).
/// 5. `path_len` is non-zero.
///
/// Returns the parsed [`NodeType`] on success.
fn validate_mknodat(args: &MknotatArgs, caps: &CallerCaps) -> Result<NodeType> {
    if args.path_len == 0 {
        return Err(Error::InvalidArgument);
    }
    if args.dirfd != AT_FDCWD && args.dirfd < 0 {
        return Err(Error::InvalidArgument);
    }
    let node_type = NodeType::from_mode(args.mode).ok_or(Error::InvalidArgument)?;
    if node_type.needs_dev() && args.dev == 0 {
        // Device nodes must have a non-zero device number (except null
        // device 0:0, which is a common exception — allow it).
    }
    if !node_type.needs_dev() && args.dev != 0 {
        return Err(Error::InvalidArgument);
    }
    if node_type.requires_mknod_cap() && !caps.mknod {
        return Err(Error::PermissionDenied);
    }
    Ok(node_type)
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// Implement `mknodat(2)` — create a filesystem node at `dirfd/path`.
///
/// Validates the arguments and computes the effective mode by masking
/// with the caller's umask.  In a real VFS integration this would
/// call into the VFS layer to create the inode; here the stub computes
/// and returns the metadata without touching the filesystem.
///
/// # Arguments
///
/// - `args` — `mknodat` arguments.
/// - `caps` — Caller's capability set.
/// - `umask` — Process file mode creation mask.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Invalid mode, `dev`, `dirfd`, or
///   path length.
/// - [`Error::PermissionDenied`] — Caller lacks `CAP_MKNOD` for device
///   creation.
///
/// # POSIX
///
/// POSIX.1-2024 §`mknod`; `mknodat` added in POSIX.1-2008.
pub fn sys_mknodat(args: &MknotatArgs, caps: &CallerCaps, umask: u32) -> Result<MknodResult> {
    let node_type = validate_mknodat(args, caps)?;

    // Apply umask to permission bits only; do not mask type bits.
    let perm_bits = args.mode & S_PERM_MASK;
    let effective_perm = perm_bits & !umask;
    let effective_mode = (args.mode & S_IFMT) | effective_perm;

    let (dev_major, dev_minor) = if node_type.needs_dev() {
        (major(args.dev), minor(args.dev))
    } else {
        (0, 0)
    };

    Ok(MknodResult {
        node_type,
        effective_mode,
        dev: args.dev,
        major: dev_major,
        minor: dev_minor,
    })
}

/// Implement `mknod(2)` — the classic, non-`*at` variant.
///
/// Equivalent to `mknodat(AT_FDCWD, pathname, mode, dev)`.
///
/// # Arguments
///
/// - `mode` — File mode with type bits.
/// - `dev` — Device number (only for character/block devices).
/// - `caps` — Caller's capability set.
/// - `umask` — Process umask.
///
/// # Errors
///
/// Same as [`sys_mknodat`].
pub fn sys_mknod(mode: u32, dev: u64, caps: &CallerCaps, umask: u32) -> Result<MknodResult> {
    let args = MknotatArgs {
        dirfd: AT_FDCWD,
        path_len: 1,
        mode,
        dev,
    };
    sys_mknodat(&args, caps, umask)
}

/// Parse and validate a `mode_t` value for `mknod`.
///
/// Returns the parsed [`NodeType`] and the permission bits.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Unrecognised file type.
pub fn sys_mknod_parse_mode(mode: u32) -> Result<(NodeType, u32)> {
    let node_type = NodeType::from_mode(mode).ok_or(Error::InvalidArgument)?;
    Ok((node_type, mode & S_PERM_MASK))
}

/// Check if a given `dev` value is a null device (major 0, minor 0).
pub const fn is_null_device(dev: u64) -> bool {
    dev == 0
}

/// Check if `dirfd` is the CWD sentinel.
pub const fn is_at_fdcwd(dirfd: i32) -> bool {
    dirfd == AT_FDCWD
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fifo_creation() {
        let args = MknotatArgs::fifo(AT_FDCWD, 0o644);
        let caps = CallerCaps::unprivileged();
        let result = sys_mknodat(&args, &caps, 0o022).unwrap();
        assert_eq!(result.node_type, NodeType::Fifo);
        assert_eq!(result.effective_mode & S_IFMT, S_IFIFO);
        // 0o644 & ~0o022 = 0o644 & 0o755 = 0o644
        assert_eq!(result.effective_mode & S_PERM_MASK, 0o644);
    }

    #[test]
    fn test_char_device_requires_cap() {
        let args = MknotatArgs::char_dev(AT_FDCWD, 0o600, 1, 3);
        let caps = CallerCaps::unprivileged();
        let result = sys_mknodat(&args, &caps, 0o022);
        assert!(matches!(result, Err(Error::PermissionDenied)));
    }

    #[test]
    fn test_char_device_with_cap() {
        let args = MknotatArgs::char_dev(AT_FDCWD, 0o660, 1, 3);
        let caps = CallerCaps::privileged();
        let result = sys_mknodat(&args, &caps, 0o022).unwrap();
        assert_eq!(result.node_type, NodeType::CharDevice);
        assert_eq!(result.major, 1);
        assert_eq!(result.minor, 3);
    }

    #[test]
    fn test_block_device_with_cap() {
        let args = MknotatArgs::block_dev(AT_FDCWD, 0o660, 8, 0);
        let caps = CallerCaps::privileged();
        let result = sys_mknodat(&args, &caps, 0).unwrap();
        assert_eq!(result.node_type, NodeType::BlockDevice);
        assert_eq!(result.major, 8);
        assert_eq!(result.minor, 0);
    }

    #[test]
    fn test_regular_file() {
        let args = MknotatArgs::regular(AT_FDCWD, 0o644);
        let caps = CallerCaps::unprivileged();
        let result = sys_mknodat(&args, &caps, 0o022).unwrap();
        assert_eq!(result.node_type, NodeType::Regular);
    }

    #[test]
    fn test_device_with_nonzero_dev_for_non_device() {
        let args = MknotatArgs {
            dirfd: AT_FDCWD,
            path_len: 5,
            mode: S_IFIFO | 0o600,
            dev: makedev(1, 3), // should fail
        };
        let caps = CallerCaps::privileged();
        let result = sys_mknodat(&args, &caps, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_makedev_roundtrip() {
        let dev = makedev(8, 16);
        assert_eq!(major(dev), 8);
        assert_eq!(minor(dev), 16);
    }

    #[test]
    fn test_umask_applied() {
        let result = sys_mknod(S_IFREG | 0o666, 0, &CallerCaps::unprivileged(), 0o022).unwrap();
        // 0o666 & ~0o022 = 0o644
        assert_eq!(result.effective_mode & S_PERM_MASK, 0o644);
    }
}
