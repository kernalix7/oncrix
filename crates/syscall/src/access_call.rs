// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `access(2)` / `faccessat(2)` syscall handler.
//!
//! Checks whether the calling process can access a file using the
//! real (or effective) user and group IDs.
//!
//! # Access modes
//!
//! | Mode | Value | Meaning |
//! |------|-------|---------|
//! | `F_OK` | 0 | File exists |
//! | `X_OK` | 1 | Execute permission |
//! | `W_OK` | 2 | Write permission |
//! | `R_OK` | 4 | Read permission |
//!
//! # Key behaviours
//!
//! - `access()` uses the **real** UID/GID (not effective).
//! - `faccessat()` with `AT_EACCESS` uses the **effective** UID/GID.
//! - Superuser (uid 0) always has read and write access; execute
//!   requires at least one execute bit to be set.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `access()` / `faccessat()`.
//!
//! # References
//!
//! - POSIX.1-2024: `access()`, `faccessat()`
//! - Linux: `fs/open.c`, `do_faccessat()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Access mode constants
// ---------------------------------------------------------------------------

/// Check for file existence.
pub const F_OK: u32 = 0;
/// Check for execute permission.
pub const X_OK: u32 = 1;
/// Check for write permission.
pub const W_OK: u32 = 2;
/// Check for read permission.
pub const R_OK: u32 = 4;

/// All known access mode bits.
const ACCESS_MASK: u32 = F_OK | R_OK | W_OK | X_OK;

// ---------------------------------------------------------------------------
// faccessat flags
// ---------------------------------------------------------------------------

/// `AT_FDCWD` — resolve relative paths against cwd.
pub const AT_FDCWD: i32 = -100;
/// `AT_EACCESS` — use effective IDs instead of real IDs.
pub const AT_EACCESS: u32 = 0x200;
/// `AT_SYMLINK_NOFOLLOW` — do not follow symlinks.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
/// `AT_EMPTY_PATH` — target is the open fd itself.
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// Known faccessat flags.
const FACCESSAT_KNOWN: u32 = AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

/// Maximum path length.
pub const PATH_MAX: usize = 4096;
/// Maximum entries in the access table.
pub const MAX_ACCESS_ENTRIES: usize = 256;

// ---------------------------------------------------------------------------
// FilePermission — inode permission bits
// ---------------------------------------------------------------------------

/// Permission bits for a filesystem entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FilePermission {
    /// Full mode bits (including type bits in upper nibble).
    pub mode: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
}

impl FilePermission {
    /// Owner read.
    const S_IRUSR: u32 = 0o400;
    /// Owner write.
    const S_IWUSR: u32 = 0o200;
    /// Owner execute.
    const S_IXUSR: u32 = 0o100;
    /// Group read.
    const S_IRGRP: u32 = 0o040;
    /// Group write.
    const S_IWGRP: u32 = 0o020;
    /// Group execute.
    const S_IXGRP: u32 = 0o010;
    /// Other read.
    const S_IROTH: u32 = 0o004;
    /// Other write.
    const S_IWOTH: u32 = 0o002;
    /// Other execute.
    const S_IXOTH: u32 = 0o001;
    /// Any execute bit.
    const S_IXANY: u32 = Self::S_IXUSR | Self::S_IXGRP | Self::S_IXOTH;

    /// Check whether `uid`/`gid` have the requested access mode.
    ///
    /// Returns `Ok(())` if access is permitted, `PermissionDenied` otherwise.
    pub fn check(&self, uid: u32, gid: u32, mode: u32) -> Result<()> {
        // Root (uid 0) has all permissions except execute if no exec bit is set.
        if uid == 0 {
            if mode & X_OK != 0 && self.mode & Self::S_IXANY == 0 {
                return Err(Error::PermissionDenied);
            }
            return Ok(());
        }

        // Determine which permission class applies.
        let (r_bit, w_bit, x_bit) = if uid == self.uid {
            (Self::S_IRUSR, Self::S_IWUSR, Self::S_IXUSR)
        } else if gid == self.gid {
            (Self::S_IRGRP, Self::S_IWGRP, Self::S_IXGRP)
        } else {
            (Self::S_IROTH, Self::S_IWOTH, Self::S_IXOTH)
        };

        if mode & R_OK != 0 && self.mode & r_bit == 0 {
            return Err(Error::PermissionDenied);
        }
        if mode & W_OK != 0 && self.mode & w_bit == 0 {
            return Err(Error::PermissionDenied);
        }
        if mode & X_OK != 0 && self.mode & x_bit == 0 {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AccessEntry — stub inode record
// ---------------------------------------------------------------------------

/// A stub inode record for the access handler.
#[derive(Clone, Copy)]
pub struct AccessEntry {
    /// Inode number.
    pub ino: u64,
    /// Path hash (stub dentry key).
    pub path_hash: u64,
    /// Permission bits.
    pub perm: FilePermission,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl AccessEntry {
    const fn empty() -> Self {
        Self {
            ino: 0,
            path_hash: 0,
            perm: FilePermission {
                mode: 0,
                uid: 0,
                gid: 0,
            },
            in_use: false,
        }
    }
}

// ---------------------------------------------------------------------------
// AccessTable — stub table
// ---------------------------------------------------------------------------

/// A stub table for the access handler.
pub struct AccessTable {
    entries: [AccessEntry; MAX_ACCESS_ENTRIES],
    count: usize,
}

impl AccessTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { AccessEntry::empty() }; MAX_ACCESS_ENTRIES],
            count: 0,
        }
    }

    /// Insert an entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, e: AccessEntry) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if !slot.in_use {
                *slot = e;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find by path hash.
    pub fn find_by_hash(&self, hash: u64) -> Option<&AccessEntry> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.path_hash == hash)
    }

    /// Return the number of entries.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for AccessTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// FNV-1a hash.
fn path_hash(path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ---------------------------------------------------------------------------
// do_access — handler
// ---------------------------------------------------------------------------

/// Handler for `access(2)`.
///
/// Checks whether the calling process (identified by its **real** UID/GID)
/// has the requested access `mode` to `path`.
///
/// # Arguments
///
/// * `table`    — stub inode table
/// * `path`     — file path
/// * `mode`     — access mode (`F_OK`, `R_OK`, `W_OK`, `X_OK`, or combination)
/// * `real_uid` — real UID of the caller
/// * `real_gid` — real GID of the caller
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — unknown mode bits, or empty path
/// * [`Error::NotFound`]         — `path` not found
/// * [`Error::PermissionDenied`] — access denied
pub fn do_access(
    table: &AccessTable,
    path: &[u8],
    mode: u32,
    real_uid: u32,
    real_gid: u32,
) -> Result<()> {
    if mode & !ACCESS_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    if path.is_empty() || path.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }

    // F_OK: just check existence.
    let hash = path_hash(path);
    let entry = table.find_by_hash(hash).ok_or(Error::NotFound)?;

    if mode == F_OK {
        return Ok(());
    }

    entry.perm.check(real_uid, real_gid, mode)
}

/// Handler for `faccessat(2)`.
///
/// Like [`do_access`] but with directory-fd, AT_EACCESS, and other flags.
///
/// # Arguments
///
/// * `table`      — stub inode table
/// * `_dirfd`     — directory fd (stub: ignored for absolute paths)
/// * `path`       — file path
/// * `mode`       — access mode
/// * `flags`      — `AT_EACCESS`, `AT_SYMLINK_NOFOLLOW`, `AT_EMPTY_PATH`
/// * `real_uid`   — real UID
/// * `real_gid`   — real GID
/// * `euid`       — effective UID (used when `AT_EACCESS` is set)
/// * `egid`       — effective GID (used when `AT_EACCESS` is set)
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — unknown flags or unknown mode bits
/// * Same as [`do_access`]
pub fn do_faccessat(
    table: &AccessTable,
    _dirfd: i32,
    path: &[u8],
    mode: u32,
    flags: u32,
    real_uid: u32,
    real_gid: u32,
    euid: u32,
    egid: u32,
) -> Result<()> {
    if flags & !FACCESSAT_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    if mode & !ACCESS_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    if path.is_empty() || path.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }

    let hash = path_hash(path);
    let entry = table.find_by_hash(hash).ok_or(Error::NotFound)?;

    if mode == F_OK {
        return Ok(());
    }

    let (check_uid, check_gid) = if flags & AT_EACCESS != 0 {
        (euid, egid)
    } else {
        (real_uid, real_gid)
    };

    entry.perm.check(check_uid, check_gid, mode)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn insert_file(t: &mut AccessTable, path: &[u8], mode: u32, uid: u32, gid: u32) {
        t.insert(AccessEntry {
            ino: path_hash(path),
            path_hash: path_hash(path),
            perm: FilePermission { mode, uid, gid },
            in_use: true,
        })
        .unwrap();
    }

    #[test]
    fn access_fok_exists() {
        let mut t = AccessTable::new();
        insert_file(&mut t, b"/etc/passwd", 0o644, 0, 0);
        do_access(&t, b"/etc/passwd", F_OK, 1000, 1000).unwrap();
    }

    #[test]
    fn access_fok_not_found() {
        let t = AccessTable::new();
        assert_eq!(do_access(&t, b"/missing", F_OK, 0, 0), Err(Error::NotFound));
    }

    #[test]
    fn access_read_owner() {
        let mut t = AccessTable::new();
        insert_file(&mut t, b"/file", 0o644, 1000, 1000);
        do_access(&t, b"/file", R_OK, 1000, 1000).unwrap();
    }

    #[test]
    fn access_write_denied() {
        let mut t = AccessTable::new();
        insert_file(&mut t, b"/ro", 0o444, 0, 0);
        assert_eq!(
            do_access(&t, b"/ro", W_OK, 1000, 1000),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn access_execute_owner() {
        let mut t = AccessTable::new();
        insert_file(&mut t, b"/bin/ls", 0o755, 0, 0);
        do_access(&t, b"/bin/ls", X_OK, 1000, 1000).unwrap();
    }

    #[test]
    fn access_execute_no_exec_bit() {
        let mut t = AccessTable::new();
        insert_file(&mut t, b"/noexec", 0o644, 1000, 1000);
        assert_eq!(
            do_access(&t, b"/noexec", X_OK, 1000, 1000),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn access_root_read_write() {
        let mut t = AccessTable::new();
        insert_file(&mut t, b"/root_only", 0o600, 0, 0);
        // Root gets r/w even on a file owned by root with no other perms.
        do_access(&t, b"/root_only", R_OK | W_OK, 0, 0).unwrap();
    }

    #[test]
    fn access_root_exec_requires_exec_bit() {
        let mut t = AccessTable::new();
        insert_file(&mut t, b"/noexec_root", 0o644, 0, 0);
        assert_eq!(
            do_access(&t, b"/noexec_root", X_OK, 0, 0),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn access_invalid_mode() {
        let t = AccessTable::new();
        assert_eq!(
            do_access(&t, b"/f", 0xFF, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn faccessat_eaccess_uses_effective() {
        let mut t = AccessTable::new();
        insert_file(&mut t, b"/priv", 0o600, 0, 0); // only root readable
        // real_uid=1000 but euid=0: AT_EACCESS → use effective → allowed.
        do_faccessat(&t, AT_FDCWD, b"/priv", R_OK, AT_EACCESS, 1000, 1000, 0, 0).unwrap();
    }

    #[test]
    fn faccessat_unknown_flags_rejected() {
        let t = AccessTable::new();
        assert_eq!(
            do_faccessat(&t, AT_FDCWD, b"/f", F_OK, 0xFFFF, 0, 0, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn access_empty_path_rejected() {
        let t = AccessTable::new();
        assert_eq!(do_access(&t, b"", F_OK, 0, 0), Err(Error::InvalidArgument));
    }
}
