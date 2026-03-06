// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `statfs(2)` and `fstatfs(2)` syscall handlers.
//!
//! Return filesystem statistics for the filesystem containing the named file
//! (`statfs`) or the file referred to by a file descriptor (`fstatfs`).
//!
//! # POSIX Conformance
//!
//! `statfs`/`fstatfs` are not part of POSIX but are present on all major UNIX
//! systems.  The `struct statfs` fields follow the Linux ABI.  Key behaviours:
//! - `ENOENT` if the path does not exist.
//! - `ENOTDIR` if a non-final component of the path is not a directory.
//! - `EACCES` if search permission is denied for a directory component.
//! - `f_bsize` is the filesystem's preferred I/O block size.
//! - `f_frsize` is the fundamental block size (used for `f_blocks` etc.).
//! - Flags in `f_flags` reflect the mount options (ST_RDONLY, ST_NOSUID…).
//!
//! # References
//!
//! - Linux man pages: `statfs(2)`
//! - POSIX.1-2024: `statvfs()` (analogous POSIX function)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Mount flags (f_flags)
// ---------------------------------------------------------------------------

/// Filesystem is mounted read-only.
pub const ST_RDONLY: u64 = 0x0001;
/// `setuid`/`setgid` bits are ignored.
pub const ST_NOSUID: u64 = 0x0002;
/// Devices are not interpreted on this filesystem.
pub const ST_NODEV: u64 = 0x0004;
/// Programs may not be executed on this filesystem.
pub const ST_NOEXEC: u64 = 0x0008;
/// Writes are synchronised.
pub const ST_SYNCHRONOUS: u64 = 0x0010;
/// Access times are not updated.
pub const ST_NOATIME: u64 = 0x0400;

// ---------------------------------------------------------------------------
// Filesystem type magic numbers
// ---------------------------------------------------------------------------

/// Magic number for `tmpfs`.
pub const TMPFS_MAGIC: i64 = 0x0102_1994;
/// Magic number for `ext2`/`ext3`/`ext4`.
pub const EXT4_MAGIC: i64 = 0xEF53;
/// Magic number for `ramfs`.
pub const RAMFS_MAGIC: i64 = 0x8584_58F6u32 as i64;
/// Magic number for `procfs`.
pub const PROC_MAGIC: i64 = 0x9FA0;

// ---------------------------------------------------------------------------
// Statfs struct
// ---------------------------------------------------------------------------

/// Filesystem statistics — mirrors Linux `struct statfs64`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Statfs {
    /// Filesystem type magic number.
    pub f_type: i64,
    /// Optimal transfer block size.
    pub f_bsize: i64,
    /// Total data blocks in filesystem.
    pub f_blocks: u64,
    /// Free blocks in filesystem.
    pub f_bfree: u64,
    /// Free blocks available to unprivileged user.
    pub f_bavail: u64,
    /// Total inodes in filesystem.
    pub f_files: u64,
    /// Free inodes in filesystem.
    pub f_ffree: u64,
    /// Filesystem ID.
    pub f_fsid: [i32; 2],
    /// Maximum length of filenames.
    pub f_namelen: i64,
    /// Fragment size (fundamental block size).
    pub f_frsize: i64,
    /// Mount flags.
    pub f_flags: u64,
    /// Spare (for future use).
    pub f_spare: [i64; 4],
}

impl Default for Statfs {
    fn default() -> Self {
        Self {
            f_type: 0,
            f_bsize: 4096,
            f_blocks: 0,
            f_bfree: 0,
            f_bavail: 0,
            f_files: 0,
            f_ffree: 0,
            f_fsid: [0; 2],
            f_namelen: 255,
            f_frsize: 4096,
            f_flags: 0,
            f_spare: [0; 4],
        }
    }
}

// ---------------------------------------------------------------------------
// Filesystem info (kernel-side)
// ---------------------------------------------------------------------------

/// Kernel-side filesystem descriptor used to populate `Statfs`.
#[derive(Debug, Clone, Copy)]
pub struct FsInfo {
    /// Filesystem type magic.
    pub fs_type: i64,
    /// Block size.
    pub block_size: u64,
    /// Total blocks.
    pub total_blocks: u64,
    /// Free blocks (all users).
    pub free_blocks: u64,
    /// Free blocks (unprivileged users; may be less than `free_blocks`).
    pub avail_blocks: u64,
    /// Total inodes.
    pub total_inodes: u64,
    /// Free inodes.
    pub free_inodes: u64,
    /// Filesystem ID.
    pub fsid: [i32; 2],
    /// Maximum filename length.
    pub max_namelen: u64,
    /// Mount flags.
    pub flags: u64,
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Build a [`Statfs`] struct from kernel [`FsInfo`].
fn build_statfs(info: &FsInfo) -> Statfs {
    Statfs {
        f_type: info.fs_type,
        f_bsize: info.block_size as i64,
        f_blocks: info.total_blocks,
        f_bfree: info.free_blocks,
        f_bavail: info.avail_blocks,
        f_files: info.total_inodes,
        f_ffree: info.free_inodes,
        f_fsid: info.fsid,
        f_namelen: info.max_namelen as i64,
        f_frsize: info.block_size as i64,
        f_flags: info.flags,
        f_spare: [0; 4],
    }
}

/// Handler for `statfs(2)`.
///
/// Returns filesystem statistics for the filesystem containing `path`.
/// The `lookup_fn` callback resolves a path to an [`FsInfo`]; it returns
/// `Err(NotFound)` for non-existent paths or `Err(AccessDenied)` for
/// permission errors.
///
/// # Errors
///
/// Propagates errors from `lookup_fn`.
pub fn do_statfs<F>(path: &[u8], lookup_fn: F) -> Result<Statfs>
where
    F: FnOnce(&[u8]) -> Result<FsInfo>,
{
    if path.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let info = lookup_fn(path)?;
    Ok(build_statfs(&info))
}

/// Handler for `fstatfs(2)`.
///
/// Returns filesystem statistics for the filesystem containing the open file
/// `fd`.  The `lookup_fn` callback resolves an fd to an [`FsInfo`].
///
/// # Errors
///
/// Propagates errors from `lookup_fn`.
pub fn do_fstatfs<F>(fd: i32, lookup_fn: F) -> Result<Statfs>
where
    F: FnOnce(i32) -> Result<FsInfo>,
{
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    let info = lookup_fn(fd)?;
    Ok(build_statfs(&info))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpfs_info() -> FsInfo {
        FsInfo {
            fs_type: TMPFS_MAGIC,
            block_size: 4096,
            total_blocks: 262144,
            free_blocks: 200000,
            avail_blocks: 200000,
            total_inodes: 65536,
            free_inodes: 65000,
            fsid: [1, 0],
            max_namelen: 255,
            flags: ST_NOSUID,
        }
    }

    #[test]
    fn statfs_path_ok() {
        let st = do_statfs(b"/tmp", |_| Ok(tmpfs_info())).unwrap();
        assert_eq!(st.f_type, TMPFS_MAGIC);
        assert_eq!(st.f_bsize, 4096);
        assert_eq!(st.f_blocks, 262144);
    }

    #[test]
    fn fstatfs_fd_ok() {
        let st = do_fstatfs(3, |_| Ok(tmpfs_info())).unwrap();
        assert_eq!(st.f_type, TMPFS_MAGIC);
        assert!(st.f_flags & ST_NOSUID != 0);
    }

    #[test]
    fn statfs_empty_path_fails() {
        assert_eq!(
            do_statfs(b"", |_| Ok(tmpfs_info())),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn fstatfs_negative_fd_fails() {
        assert_eq!(
            do_fstatfs(-1, |_| Ok(tmpfs_info())),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn statfs_not_found() {
        assert_eq!(
            do_statfs(b"/nonexistent", |_| Err(Error::NotFound)),
            Err(Error::NotFound)
        );
    }
}
