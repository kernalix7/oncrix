// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `rmdir(2)` syscall handler.
//!
//! Removes an empty directory.
//!
//! # Key behaviours
//!
//! - The directory must be empty (only `.` and `..` may remain).
//! - Removing `.` or `..` directly is rejected with `InvalidArgument`.
//! - Removing a mount-point directory returns `Busy`.
//! - Requires write + execute permission on the parent directory.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `rmdir()`.
//!
//! # References
//!
//! - POSIX.1-2024: `rmdir()`
//! - Linux: `fs/namei.c`, `vfs_rmdir()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum path length.
pub const PATH_MAX: usize = 4096;
/// Maximum number of directory entries in the stub.
pub const MAX_RMDIR_ENTRIES: usize = 256;

// ---------------------------------------------------------------------------
// RmdirEntry — stub directory descriptor
// ---------------------------------------------------------------------------

/// A stub directory descriptor for the rmdir handler.
#[derive(Clone, Copy)]
pub struct RmdirEntry {
    /// Inode number.
    pub ino: u64,
    /// Path hash (stub dentry key).
    pub path_hash: u64,
    /// Number of children (not counting `.` and `..`).
    pub child_count: u32,
    /// Whether this directory is a mount point.
    pub is_mount_point: bool,
    /// Owner UID of the parent directory.
    pub parent_uid: u32,
    /// Parent directory write permission.
    pub parent_writable: bool,
    /// Parent directory execute permission.
    pub parent_executable: bool,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl RmdirEntry {
    const fn empty() -> Self {
        Self {
            ino: 0,
            path_hash: 0,
            child_count: 0,
            is_mount_point: false,
            parent_uid: 0,
            parent_writable: true,
            parent_executable: true,
            in_use: false,
        }
    }

    /// Return `true` if the directory can be removed (empty, not a mount point).
    pub const fn is_removable(&self) -> bool {
        self.child_count == 0 && !self.is_mount_point
    }
}

// ---------------------------------------------------------------------------
// RmdirTable — stub directory table
// ---------------------------------------------------------------------------

/// A stub directory table for the rmdir handler.
pub struct RmdirTable {
    entries: [RmdirEntry; MAX_RMDIR_ENTRIES],
    count: usize,
}

impl RmdirTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { RmdirEntry::empty() }; MAX_RMDIR_ENTRIES],
            count: 0,
        }
    }

    /// Insert a directory entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, entry: RmdirEntry) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if !slot.in_use {
                *slot = entry;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a directory by path hash.
    pub fn find_by_hash(&self, hash: u64) -> Option<&RmdirEntry> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.path_hash == hash)
    }

    /// Remove a directory by path hash.  Returns `true` if found.
    pub fn remove_by_hash(&mut self, hash: u64) -> bool {
        for slot in self.entries.iter_mut() {
            if slot.in_use && slot.path_hash == hash {
                *slot = RmdirEntry::empty();
                self.count = self.count.saturating_sub(1);
                return true;
            }
        }
        false
    }

    /// Return the number of entries.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for RmdirTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Path helpers
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

/// Return `true` if the final component of `path` is `.` or `..`.
fn is_dot_or_dotdot(path: &[u8]) -> bool {
    let stripped = if path.last() == Some(&b'/') {
        &path[..path.len() - 1]
    } else {
        path
    };
    match stripped.iter().rposition(|&b| b == b'/') {
        Some(pos) => {
            let name = &stripped[pos + 1..];
            name == b"." || name == b".."
        }
        None => stripped == b"." || stripped == b"..",
    }
}

// ---------------------------------------------------------------------------
// do_rmdir — main handler
// ---------------------------------------------------------------------------

/// Handler for `rmdir(2)`.
///
/// Removes the directory at `path`.  The caller must have write and
/// execute permission on the parent directory.
///
/// # Arguments
///
/// * `table` — stub directory table
/// * `path`  — path of the directory to remove
/// * `uid`   — caller UID
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — empty/overlong path, or path ends in `.`/`..`
/// * [`Error::NotFound`]         — directory does not exist
/// * [`Error::Busy`]             — directory is a mount point
/// * [`Error::NotImplemented`]   — directory is not empty (`ENOTEMPTY`)
/// * [`Error::PermissionDenied`] — caller lacks write/exec on parent
pub fn do_rmdir(table: &mut RmdirTable, path: &[u8], uid: u32) -> Result<()> {
    if path.is_empty() || path.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    if is_dot_or_dotdot(path) {
        return Err(Error::InvalidArgument);
    }

    let hash = path_hash(path);
    let entry = table.find_by_hash(hash).ok_or(Error::NotFound)?;

    // Mount-point check.
    if entry.is_mount_point {
        return Err(Error::Busy);
    }

    // Non-empty check.
    if entry.child_count > 0 {
        return Err(Error::NotImplemented); // ENOTEMPTY
    }

    // Parent permission check.
    let can_write = uid == 0 || (uid == entry.parent_uid && entry.parent_writable);
    let can_exec = uid == 0 || (uid == entry.parent_uid && entry.parent_executable);
    if !can_write || !can_exec {
        return Err(Error::PermissionDenied);
    }

    table.remove_by_hash(hash);
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn insert_dir(table: &mut RmdirTable, path: &[u8], children: u32, mount: bool) {
        table
            .insert(RmdirEntry {
                ino: path_hash(path),
                path_hash: path_hash(path),
                child_count: children,
                is_mount_point: mount,
                parent_uid: 1000,
                parent_writable: true,
                parent_executable: true,
                in_use: true,
            })
            .unwrap();
    }

    #[test]
    fn rmdir_empty_dir() {
        let mut t = RmdirTable::new();
        insert_dir(&mut t, b"/empty", 0, false);
        do_rmdir(&mut t, b"/empty", 1000).unwrap();
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn rmdir_not_found() {
        let mut t = RmdirTable::new();
        assert_eq!(do_rmdir(&mut t, b"/missing", 0), Err(Error::NotFound));
    }

    #[test]
    fn rmdir_not_empty() {
        let mut t = RmdirTable::new();
        insert_dir(&mut t, b"/nonempty", 3, false);
        assert_eq!(
            do_rmdir(&mut t, b"/nonempty", 0),
            Err(Error::NotImplemented)
        );
    }

    #[test]
    fn rmdir_mount_point_busy() {
        let mut t = RmdirTable::new();
        insert_dir(&mut t, b"/mnt", 0, true);
        assert_eq!(do_rmdir(&mut t, b"/mnt", 0), Err(Error::Busy));
    }

    #[test]
    fn rmdir_dot_rejected() {
        let mut t = RmdirTable::new();
        assert_eq!(do_rmdir(&mut t, b".", 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn rmdir_dotdot_rejected() {
        let mut t = RmdirTable::new();
        assert_eq!(do_rmdir(&mut t, b"..", 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn rmdir_empty_path_rejected() {
        let mut t = RmdirTable::new();
        assert_eq!(do_rmdir(&mut t, b"", 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn rmdir_permission_denied() {
        let mut t = RmdirTable::new();
        t.insert(RmdirEntry {
            ino: 1,
            path_hash: path_hash(b"/protected"),
            child_count: 0,
            is_mount_point: false,
            parent_uid: 1000,
            parent_writable: false,
            parent_executable: true,
            in_use: true,
        })
        .unwrap();
        assert_eq!(
            do_rmdir(&mut t, b"/protected", 2000),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn rmdir_root_bypasses_permission() {
        let mut t = RmdirTable::new();
        t.insert(RmdirEntry {
            ino: 2,
            path_hash: path_hash(b"/root_only"),
            child_count: 0,
            is_mount_point: false,
            parent_uid: 1000,
            parent_writable: false,
            parent_executable: false,
            in_use: true,
        })
        .unwrap();
        do_rmdir(&mut t, b"/root_only", 0).unwrap();
    }

    #[test]
    fn is_dot_or_dotdot_detection() {
        assert!(is_dot_or_dotdot(b"."));
        assert!(is_dot_or_dotdot(b".."));
        assert!(is_dot_or_dotdot(b"/foo/."));
        assert!(is_dot_or_dotdot(b"/foo/.."));
        assert!(!is_dot_or_dotdot(b"/foo/bar"));
    }
}
