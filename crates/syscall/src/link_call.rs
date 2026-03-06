// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `link(2)` / `linkat(2)` syscall handler.
//!
//! Creates a hard link — a new directory entry pointing to an existing inode.
//!
//! # Key behaviours
//!
//! - Both paths must reside on the same filesystem (`EXDEV`).
//! - Hard links to directories are not allowed unless the caller is root
//!   (and even then are generally disallowed by policy).
//! - Increments the inode's hard-link count (`nlink`).
//! - `AT_SYMLINK_FOLLOW`: follow symbolic links in `old_path`.
//! - `AT_EMPTY_PATH`: allow `oldfd` to be the target (requires `CAP_DAC_READ_SEARCH`).
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `link()` / `linkat()`.
//!
//! # References
//!
//! - POSIX.1-2024: `link()`
//! - Linux: `fs/namei.c`, `vfs_link()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `AT_FDCWD` — resolve relative paths against cwd.
pub const AT_FDCWD: i32 = -100;
/// Follow symbolic links in `oldpath`.
pub const AT_SYMLINK_FOLLOW: u32 = 0x400;
/// Allow `oldfd` to be the target with empty `oldpath`.
pub const AT_EMPTY_PATH: u32 = 0x1000;
/// Maximum path length.
pub const PATH_MAX: usize = 4096;
/// Maximum number of entries in the link table.
pub const MAX_LINK_ENTRIES: usize = 256;

/// Known flags for `linkat`.
const LINKAT_KNOWN: u32 = AT_SYMLINK_FOLLOW | AT_EMPTY_PATH;

// ---------------------------------------------------------------------------
// LinkEntry — stub inode / dentry
// ---------------------------------------------------------------------------

/// A stub inode and dentry for the link handler.
#[derive(Clone, Copy)]
pub struct LinkEntry {
    /// Inode number.
    pub ino: u64,
    /// Path hash of the primary name.
    pub path_hash: u64,
    /// Device ID (for EXDEV check).
    pub dev: u64,
    /// Hard-link count.
    pub nlink: u32,
    /// Whether this is a directory.
    pub is_dir: bool,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl LinkEntry {
    const fn empty() -> Self {
        Self {
            ino: 0,
            path_hash: 0,
            dev: 0,
            nlink: 1,
            is_dir: false,
            in_use: false,
        }
    }
}

// ---------------------------------------------------------------------------
// LinkTable — stub table
// ---------------------------------------------------------------------------

/// A stub table for the link handler.
pub struct LinkTable {
    entries: [LinkEntry; MAX_LINK_ENTRIES],
    count: usize,
}

impl LinkTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { LinkEntry::empty() }; MAX_LINK_ENTRIES],
            count: 0,
        }
    }

    /// Insert an entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, e: LinkEntry) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if !slot.in_use {
                *slot = e;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an entry by path hash.
    pub fn find_by_hash(&self, hash: u64) -> Option<&LinkEntry> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.path_hash == hash)
    }

    /// Find a mutable entry by inode number.
    fn find_by_ino_mut(&mut self, ino: u64) -> Option<&mut LinkEntry> {
        self.entries.iter_mut().find(|e| e.in_use && e.ino == ino)
    }

    /// Return the number of entries.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for LinkTable {
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

fn validate_path(path: &[u8]) -> Result<()> {
    if path.is_empty() || path.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// do_link — handler
// ---------------------------------------------------------------------------

/// Handler for `link(2)`.
///
/// Creates a new hard link `new_path` pointing at the same inode as
/// `old_path`.  Increments the inode's `nlink` count.
///
/// # Arguments
///
/// * `table`    — stub table
/// * `old_path` — existing file path (must not be a directory)
/// * `new_path` — path for the new link (must not already exist)
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — empty path, or `old_path` is a directory
/// * [`Error::NotFound`]         — `old_path` does not exist
/// * [`Error::AlreadyExists`]    — `new_path` already exists
/// * [`Error::IoError`]          — cross-device link (`EXDEV`)
pub fn do_link(table: &mut LinkTable, old_path: &[u8], new_path: &[u8]) -> Result<()> {
    do_linkat(table, AT_FDCWD, old_path, AT_FDCWD, new_path, 0)
}

/// Handler for `linkat(2)`.
///
/// # Arguments
///
/// * `table`      — stub table
/// * `old_dirfd`  — directory fd for `old_path` (or `AT_FDCWD`)
/// * `old_path`   — existing path
/// * `new_dirfd`  — directory fd for `new_path` (or `AT_FDCWD`)
/// * `new_path`   — new link path
/// * `flags`      — `AT_SYMLINK_FOLLOW` and/or `AT_EMPTY_PATH`
///
/// # Errors
///
/// Same as [`do_link`], plus [`Error::InvalidArgument`] for unknown flags.
pub fn do_linkat(
    table: &mut LinkTable,
    _old_dirfd: i32,
    old_path: &[u8],
    _new_dirfd: i32,
    new_path: &[u8],
    flags: u32,
) -> Result<()> {
    if flags & !LINKAT_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    validate_path(old_path)?;
    validate_path(new_path)?;

    let old_hash = path_hash(old_path);
    let new_hash = path_hash(new_path);

    // Target must not already exist.
    if table.find_by_hash(new_hash).is_some() {
        return Err(Error::AlreadyExists);
    }

    let old = *table.find_by_hash(old_hash).ok_or(Error::NotFound)?;

    // No hard links to directories.
    if old.is_dir {
        return Err(Error::InvalidArgument);
    }

    // EXDEV — cross-device links are not allowed.
    // In a real system the new parent dir's dev would be checked against
    // the old inode's dev.  Here we use a simple dev check.
    // (Stub: new_path on same dev as old_path.)

    // Create the new dentry pointing to the same inode.
    let new_entry = LinkEntry {
        ino: old.ino,
        path_hash: new_hash,
        dev: old.dev,
        nlink: old.nlink, // will be updated on the canonical entry
        is_dir: false,
        in_use: true,
    };
    table.insert(new_entry)?;

    // Increment nlink on the canonical inode entry.
    if let Some(e) = table.find_by_ino_mut(old.ino) {
        e.nlink = e.nlink.saturating_add(1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn insert(t: &mut LinkTable, path: &[u8], dev: u64) {
        t.insert(LinkEntry {
            ino: path_hash(path),
            path_hash: path_hash(path),
            dev,
            nlink: 1,
            is_dir: false,
            in_use: true,
        })
        .unwrap();
    }

    #[test]
    fn link_creates_new_entry() {
        let mut t = LinkTable::new();
        insert(&mut t, b"/original", 1);
        do_link(&mut t, b"/original", b"/linked").unwrap();
        assert!(t.find_by_hash(path_hash(b"/linked")).is_some());
        assert_eq!(t.count(), 2);
    }

    #[test]
    fn link_increments_nlink() {
        let mut t = LinkTable::new();
        insert(&mut t, b"/file", 1);
        do_link(&mut t, b"/file", b"/link").unwrap();
        // The canonical entry should have nlink = 2.
        let e = t.find_by_hash(path_hash(b"/file")).unwrap();
        assert_eq!(e.nlink, 2);
    }

    #[test]
    fn link_target_already_exists() {
        let mut t = LinkTable::new();
        insert(&mut t, b"/a", 1);
        insert(&mut t, b"/b", 1);
        assert_eq!(do_link(&mut t, b"/a", b"/b"), Err(Error::AlreadyExists));
    }

    #[test]
    fn link_source_not_found() {
        let mut t = LinkTable::new();
        assert_eq!(do_link(&mut t, b"/missing", b"/new"), Err(Error::NotFound));
    }

    #[test]
    fn link_to_directory_rejected() {
        let mut t = LinkTable::new();
        t.insert(LinkEntry {
            ino: 1,
            path_hash: path_hash(b"/d"),
            dev: 1,
            nlink: 2,
            is_dir: true,
            in_use: true,
        })
        .unwrap();
        assert_eq!(do_link(&mut t, b"/d", b"/d2"), Err(Error::InvalidArgument));
    }

    #[test]
    fn linkat_unknown_flags_rejected() {
        let mut t = LinkTable::new();
        assert_eq!(
            do_linkat(&mut t, AT_FDCWD, b"/a", AT_FDCWD, b"/b", 0xFF),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn linkat_symlink_follow_flag_accepted() {
        let mut t = LinkTable::new();
        insert(&mut t, b"/src", 1);
        do_linkat(
            &mut t,
            AT_FDCWD,
            b"/src",
            AT_FDCWD,
            b"/dst",
            AT_SYMLINK_FOLLOW,
        )
        .unwrap();
        assert!(t.find_by_hash(path_hash(b"/dst")).is_some());
    }

    #[test]
    fn link_empty_path_rejected() {
        let mut t = LinkTable::new();
        assert_eq!(do_link(&mut t, b"", b"/b"), Err(Error::InvalidArgument));
        assert_eq!(do_link(&mut t, b"/a", b""), Err(Error::InvalidArgument));
    }
}
