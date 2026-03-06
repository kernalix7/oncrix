// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `unlink(2)` / `unlinkat(2)` syscall handler.
//!
//! Removes a filesystem name and possibly the file it refers to.
//! When the hard-link count drops to zero and no process holds the file
//! open, the file's data is freed.
//!
//! # Key behaviours
//!
//! - Removes the dentry (directory entry) from its parent directory.
//! - Decrements the hard-link count (`nlink`) of the inode.
//! - `AT_REMOVEDIR` flag causes `unlinkat` to behave like `rmdir`.
//! - Sticky bit on the parent directory: only file owner or parent owner
//!   or root may remove the entry.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `unlink()` / `unlinkat()`.
//!
//! # References
//!
//! - POSIX.1-2024: `unlink()`
//! - Linux: `fs/namei.c`, `vfs_unlink()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `AT_FDCWD` — relative paths resolved against cwd.
pub const AT_FDCWD: i32 = -100;
/// `AT_REMOVEDIR` — act like `rmdir` rather than `unlink`.
pub const AT_REMOVEDIR: u32 = 0x200;
/// Maximum path length.
pub const PATH_MAX: usize = 4096;
/// Maximum number of entries in the stub table.
pub const MAX_UNLINK_ENTRIES: usize = 256;

// ---------------------------------------------------------------------------
// UnlinkEntry — one file entry in the stub
// ---------------------------------------------------------------------------

/// A stub file entry for the unlink handler.
#[derive(Clone, Copy)]
pub struct UnlinkEntry {
    /// Inode number.
    pub ino: u64,
    /// Path hash (stub dentry key).
    pub path_hash: u64,
    /// Hard-link count.
    pub nlink: u32,
    /// File type: `false` = regular file, `true` = directory.
    pub is_dir: bool,
    /// Owner UID of the file.
    pub file_uid: u32,
    /// Owner UID of the parent directory.
    pub parent_uid: u32,
    /// Whether the parent directory has the sticky bit set.
    pub parent_sticky: bool,
    /// Whether the caller has write permission on the parent directory.
    pub parent_writable: bool,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl UnlinkEntry {
    const fn empty() -> Self {
        Self {
            ino: 0,
            path_hash: 0,
            nlink: 1,
            is_dir: false,
            file_uid: 0,
            parent_uid: 0,
            parent_sticky: false,
            parent_writable: true,
            in_use: false,
        }
    }
}

// ---------------------------------------------------------------------------
// UnlinkTable — stub file table
// ---------------------------------------------------------------------------

/// A stub file table for the unlink handler.
pub struct UnlinkTable {
    entries: [UnlinkEntry; MAX_UNLINK_ENTRIES],
    count: usize,
}

impl UnlinkTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { UnlinkEntry::empty() }; MAX_UNLINK_ENTRIES],
            count: 0,
        }
    }

    /// Insert an entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, entry: UnlinkEntry) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if !slot.in_use {
                *slot = entry;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an entry by path hash.
    pub fn find_by_hash(&self, hash: u64) -> Option<&UnlinkEntry> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.path_hash == hash)
    }

    /// Find a mutable entry by path hash.
    fn find_by_hash_mut(&mut self, hash: u64) -> Option<&mut UnlinkEntry> {
        self.entries
            .iter_mut()
            .find(|e| e.in_use && e.path_hash == hash)
    }

    /// Remove an entry by path hash (returns `true` if found).
    fn remove_by_hash(&mut self, hash: u64) -> bool {
        for slot in self.entries.iter_mut() {
            if slot.in_use && slot.path_hash == hash {
                *slot = UnlinkEntry::empty();
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

impl Default for UnlinkTable {
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

/// Check sticky-bit removal permission.
///
/// If the parent has the sticky bit set, only the file owner, the
/// directory owner, or root may remove the entry.
fn check_sticky(entry: &UnlinkEntry, uid: u32) -> Result<()> {
    if !entry.parent_sticky {
        return Ok(());
    }
    if uid == 0 || uid == entry.file_uid || uid == entry.parent_uid {
        return Ok(());
    }
    Err(Error::PermissionDenied)
}

// ---------------------------------------------------------------------------
// do_unlink — handler for unlink / unlinkat without AT_REMOVEDIR
// ---------------------------------------------------------------------------

/// Handler for `unlink(2)` / `unlinkat(2)` (without `AT_REMOVEDIR`).
///
/// Removes the directory entry for `path` and decrements the inode's
/// link count.  When the count reaches zero and no open file descriptors
/// refer to the inode, the inode is freed (stub: removed from the table).
///
/// # Arguments
///
/// * `table` — stub file table
/// * `path`  — path of the file to remove
/// * `uid`   — caller UID
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — empty or overlong path
/// * [`Error::NotFound`]         — path not found
/// * [`Error::InvalidArgument`]  — path refers to a directory (use `rmdir`)
/// * [`Error::PermissionDenied`] — sticky bit check failed, or no write
///   permission on the parent directory
pub fn do_unlink(table: &mut UnlinkTable, path: &[u8], uid: u32) -> Result<()> {
    if path.is_empty() || path.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }

    let hash = path_hash(path);
    let entry = table.find_by_hash(hash).ok_or(Error::NotFound)?;

    // Cannot unlink a directory (use rmdir).
    if entry.is_dir {
        return Err(Error::InvalidArgument);
    }

    // Parent write permission.
    if uid != 0 && !entry.parent_writable {
        return Err(Error::PermissionDenied);
    }

    // Sticky bit check.
    check_sticky(entry, uid)?;

    // Decrement nlink.
    {
        let e = table.find_by_hash_mut(hash).ok_or(Error::NotFound)?;
        e.nlink = e.nlink.saturating_sub(1);
        if e.nlink > 0 {
            // Other hard links exist; dentry removed but inode stays.
            return Ok(());
        }
    }

    // nlink == 0: remove the inode (no open fds in the stub).
    table.remove_by_hash(hash);
    Ok(())
}

// ---------------------------------------------------------------------------
// do_unlinkat — unlinkat with flags
// ---------------------------------------------------------------------------

/// Handler for `unlinkat(2)`.
///
/// When `flags` includes `AT_REMOVEDIR`, behaves like `rmdir`.
/// Otherwise behaves like [`do_unlink`].
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — unknown flag bits set
/// * Same as [`do_unlink`] otherwise
pub fn do_unlinkat(
    table: &mut UnlinkTable,
    _dirfd: i32,
    path: &[u8],
    flags: u32,
    uid: u32,
) -> Result<()> {
    let unknown = flags & !AT_REMOVEDIR;
    if unknown != 0 {
        return Err(Error::InvalidArgument);
    }

    if flags & AT_REMOVEDIR != 0 {
        // Act like rmdir: only allow directories.
        if path.is_empty() || path.len() >= PATH_MAX {
            return Err(Error::InvalidArgument);
        }
        let hash = path_hash(path);
        let entry = table.find_by_hash(hash).ok_or(Error::NotFound)?;
        if !entry.is_dir {
            return Err(Error::InvalidArgument); // ENOTDIR
        }
        if uid != 0 && !entry.parent_writable {
            return Err(Error::PermissionDenied);
        }
        check_sticky(entry, uid)?;
        table.remove_by_hash(hash);
        Ok(())
    } else {
        do_unlink(table, path, uid)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn plain_file(path: &[u8], uid: u32) -> UnlinkEntry {
        UnlinkEntry {
            ino: path_hash(path),
            path_hash: path_hash(path),
            nlink: 1,
            is_dir: false,
            file_uid: uid,
            parent_uid: uid,
            parent_sticky: false,
            parent_writable: true,
            in_use: true,
        }
    }

    #[test]
    fn unlink_removes_file() {
        let mut t = UnlinkTable::new();
        t.insert(plain_file(b"/tmp/x", 1000)).unwrap();
        do_unlink(&mut t, b"/tmp/x", 1000).unwrap();
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn unlink_not_found() {
        let mut t = UnlinkTable::new();
        assert_eq!(do_unlink(&mut t, b"/missing", 0), Err(Error::NotFound));
    }

    #[test]
    fn unlink_directory_rejected() {
        let mut t = UnlinkTable::new();
        t.insert(UnlinkEntry {
            ino: 1,
            path_hash: path_hash(b"/somedir"),
            nlink: 1,
            is_dir: true,
            file_uid: 0,
            parent_uid: 0,
            parent_sticky: false,
            parent_writable: true,
            in_use: true,
        })
        .unwrap();
        assert_eq!(
            do_unlink(&mut t, b"/somedir", 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unlink_nlink_above_one() {
        let mut t = UnlinkTable::new();
        t.insert(UnlinkEntry {
            ino: 2,
            path_hash: path_hash(b"/hard"),
            nlink: 2,
            is_dir: false,
            file_uid: 1000,
            parent_uid: 1000,
            parent_sticky: false,
            parent_writable: true,
            in_use: true,
        })
        .unwrap();
        do_unlink(&mut t, b"/hard", 1000).unwrap();
        // nlink dropped to 1 but entry still present.
        assert_eq!(t.count(), 1);
        assert_eq!(t.find_by_hash(path_hash(b"/hard")).unwrap().nlink, 1);
    }

    #[test]
    fn unlink_sticky_bit_file_owner_allowed() {
        let mut t = UnlinkTable::new();
        t.insert(UnlinkEntry {
            ino: 3,
            path_hash: path_hash(b"/sticky/f"),
            nlink: 1,
            is_dir: false,
            file_uid: 1000,
            parent_uid: 0,
            parent_sticky: true,
            parent_writable: true,
            in_use: true,
        })
        .unwrap();
        // File owner can remove despite sticky.
        do_unlink(&mut t, b"/sticky/f", 1000).unwrap();
    }

    #[test]
    fn unlink_sticky_bit_other_denied() {
        let mut t = UnlinkTable::new();
        t.insert(UnlinkEntry {
            ino: 4,
            path_hash: path_hash(b"/sticky/g"),
            nlink: 1,
            is_dir: false,
            file_uid: 1000,
            parent_uid: 0,
            parent_sticky: true,
            parent_writable: true,
            in_use: true,
        })
        .unwrap();
        assert_eq!(
            do_unlink(&mut t, b"/sticky/g", 2000),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn unlinkat_removedir() {
        let mut t = UnlinkTable::new();
        t.insert(UnlinkEntry {
            ino: 5,
            path_hash: path_hash(b"/d"),
            nlink: 1,
            is_dir: true,
            file_uid: 0,
            parent_uid: 0,
            parent_sticky: false,
            parent_writable: true,
            in_use: true,
        })
        .unwrap();
        do_unlinkat(&mut t, AT_FDCWD, b"/d", AT_REMOVEDIR, 0).unwrap();
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn unlinkat_unknown_flags_rejected() {
        let mut t = UnlinkTable::new();
        assert_eq!(
            do_unlinkat(&mut t, AT_FDCWD, b"/f", 0xFF, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unlink_empty_path_rejected() {
        let mut t = UnlinkTable::new();
        assert_eq!(do_unlink(&mut t, b"", 0), Err(Error::InvalidArgument));
    }
}
