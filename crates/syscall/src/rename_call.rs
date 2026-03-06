// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `rename(2)` / `renameat2(2)` syscall handler.
//!
//! Renames a file, directory, or symbolic link.
//!
//! # renameat2 flags
//!
//! | Flag | Value | Description |
//! |------|-------|-------------|
//! | `RENAME_NOREPLACE` | 1 | Fail if target already exists |
//! | `RENAME_EXCHANGE`  | 2 | Atomically swap old and new |
//! | `RENAME_WHITEOUT`  | 4 | Leave a whiteout at the old location |
//!
//! # Key behaviours
//!
//! - Renaming `old` to `new` where both exist replaces `new` atomically.
//! - Cross-directory rename: requires write permission on both directories.
//! - Renaming a directory to an existing empty directory replaces it.
//! - Cannot rename a directory into itself (`EINVAL`).
//! - Same-file rename (old == new) is a no-op.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `rename()`.  `RENAME_EXCHANGE` / `RENAME_WHITEOUT`
//! are Linux extensions.
//!
//! # References
//!
//! - POSIX.1-2024: `rename()`
//! - Linux: `fs/namei.c`, `vfs_rename()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `AT_FDCWD` — resolve relative paths against cwd.
pub const AT_FDCWD: i32 = -100;
/// Fail if target already exists.
pub const RENAME_NOREPLACE: u32 = 1;
/// Atomically exchange old and new names.
pub const RENAME_EXCHANGE: u32 = 2;
/// Leave a whiteout at old path.
pub const RENAME_WHITEOUT: u32 = 4;
/// Maximum path length.
pub const PATH_MAX: usize = 4096;
/// Maximum entries in the stub rename table.
pub const MAX_RENAME_ENTRIES: usize = 256;

/// All known rename flags.
const RENAME_KNOWN: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT;

// ---------------------------------------------------------------------------
// RenameEntry — stub filesystem entry
// ---------------------------------------------------------------------------

/// A stub filesystem entry for the rename handler.
#[derive(Clone, Copy)]
pub struct RenameEntry {
    /// Inode number.
    pub ino: u64,
    /// Path hash (dentry stub key).
    pub path_hash: u64,
    /// Whether this is a directory.
    pub is_dir: bool,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl RenameEntry {
    const fn empty() -> Self {
        Self {
            ino: 0,
            path_hash: 0,
            is_dir: false,
            in_use: false,
        }
    }
}

// ---------------------------------------------------------------------------
// RenameTable — stub
// ---------------------------------------------------------------------------

/// A stub filesystem table for the rename handler.
pub struct RenameTable {
    entries: [RenameEntry; MAX_RENAME_ENTRIES],
    count: usize,
}

impl RenameTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { RenameEntry::empty() }; MAX_RENAME_ENTRIES],
            count: 0,
        }
    }

    /// Insert an entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, e: RenameEntry) -> Result<()> {
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
    pub fn find_by_hash(&self, hash: u64) -> Option<&RenameEntry> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.path_hash == hash)
    }

    /// Find a mutable entry by path hash.
    fn find_by_hash_mut(&mut self, hash: u64) -> Option<&mut RenameEntry> {
        self.entries
            .iter_mut()
            .find(|e| e.in_use && e.path_hash == hash)
    }

    /// Remove an entry by path hash.
    fn remove_by_hash(&mut self, hash: u64) {
        for slot in self.entries.iter_mut() {
            if slot.in_use && slot.path_hash == hash {
                *slot = RenameEntry::empty();
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Return the number of entries.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for RenameTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RenameFlags — validated flags
// ---------------------------------------------------------------------------

/// Validated flags for `renameat2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RenameFlags(u32);

impl RenameFlags {
    /// Construct from raw flags.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unknown flags or for
    /// `NOREPLACE | EXCHANGE` together (mutually exclusive).
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !RENAME_KNOWN != 0 {
            return Err(Error::InvalidArgument);
        }
        if raw & RENAME_NOREPLACE != 0 && raw & RENAME_EXCHANGE != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return `true` if `RENAME_NOREPLACE` is set.
    pub const fn is_noreplace(self) -> bool {
        self.0 & RENAME_NOREPLACE != 0
    }

    /// Return `true` if `RENAME_EXCHANGE` is set.
    pub const fn is_exchange(self) -> bool {
        self.0 & RENAME_EXCHANGE != 0
    }

    /// Return `true` if `RENAME_WHITEOUT` is set.
    pub const fn is_whiteout(self) -> bool {
        self.0 & RENAME_WHITEOUT != 0
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

/// Validate a path (non-empty, < PATH_MAX, no NUL).
fn validate_path(path: &[u8]) -> Result<()> {
    if path.is_empty() || path.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    if path.contains(&0) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// do_rename — main handler
// ---------------------------------------------------------------------------

/// Handler for `rename(2)` (zero flags).
///
/// Renames `old_path` to `new_path`.  If `new_path` already exists it
/// is replaced atomically.
///
/// # Arguments
///
/// * `table`    — stub filesystem table
/// * `old_path` — existing path
/// * `new_path` — destination path
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — empty or overlong path, or old == new
///   (same-file, treated as no-op), or type mismatch (dir vs non-dir)
/// * [`Error::NotFound`]        — `old_path` does not exist
pub fn do_rename(table: &mut RenameTable, old_path: &[u8], new_path: &[u8]) -> Result<()> {
    do_renameat2(table, AT_FDCWD, old_path, AT_FDCWD, new_path, 0)
}

// ---------------------------------------------------------------------------
// do_renameat2 — main handler with flags
// ---------------------------------------------------------------------------

/// Handler for `renameat2(2)`.
///
/// # Arguments
///
/// * `table`     — stub filesystem table
/// * `old_dirfd` — directory fd for `old_path` (or `AT_FDCWD`)
/// * `old_path`  — existing path
/// * `new_dirfd` — directory fd for `new_path` (or `AT_FDCWD`)
/// * `new_path`  — destination path
/// * `flags`     — raw rename flags
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — invalid paths, conflicting flags,
///   old == new rename to itself, EISDIR / ENOTDIR mismatch
/// * [`Error::NotFound`]         — `old_path` not found
/// * [`Error::AlreadyExists`]    — `RENAME_NOREPLACE` and target exists
pub fn do_renameat2(
    table: &mut RenameTable,
    _old_dirfd: i32,
    old_path: &[u8],
    _new_dirfd: i32,
    new_path: &[u8],
    raw_flags: u32,
) -> Result<()> {
    validate_path(old_path)?;
    validate_path(new_path)?;

    let flags = RenameFlags::from_raw(raw_flags)?;

    let old_hash = path_hash(old_path);
    let new_hash = path_hash(new_path);

    // Same-file no-op.
    if old_hash == new_hash {
        return Ok(());
    }

    let old_entry = *table.find_by_hash(old_hash).ok_or(Error::NotFound)?;
    let new_entry_opt = table.find_by_hash(new_hash).copied();

    // RENAME_NOREPLACE: fail if target exists.
    if flags.is_noreplace() {
        if new_entry_opt.is_some() {
            return Err(Error::AlreadyExists);
        }
    }

    // Type-mismatch checks.
    if let Some(ne) = new_entry_opt {
        // Replacing dir with non-dir or vice versa is an error.
        if old_entry.is_dir && !ne.is_dir {
            return Err(Error::InvalidArgument); // EISDIR
        }
        if !old_entry.is_dir && ne.is_dir {
            return Err(Error::InvalidArgument); // ENOTDIR
        }
    }

    if flags.is_exchange() {
        // Atomically swap the two dentries' path hashes.
        // Both must exist.
        let ne = new_entry_opt.ok_or(Error::NotFound)?;
        {
            let old_mut = table.find_by_hash_mut(old_hash).ok_or(Error::NotFound)?;
            old_mut.path_hash = new_hash;
        }
        {
            let new_mut = table.find_by_hash_mut(new_hash).ok_or(Error::NotFound)?;
            new_mut.path_hash = old_hash;
            let _ = ne; // consumed above
        }
        return Ok(());
    }

    // Standard rename: remove target if present, move old to new.
    if new_entry_opt.is_some() {
        table.remove_by_hash(new_hash);
    }

    {
        let old_mut = table.find_by_hash_mut(old_hash).ok_or(Error::NotFound)?;
        old_mut.path_hash = new_hash;
    }

    // RENAME_WHITEOUT: leave an opaque entry at old_hash.
    if flags.is_whiteout() {
        let whiteout = RenameEntry {
            ino: u64::MAX,
            path_hash: old_hash,
            is_dir: false,
            in_use: true,
        };
        // Best-effort; ignore table-full error for stub.
        let _ = table.insert(whiteout);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn insert(t: &mut RenameTable, path: &[u8], is_dir: bool) {
        t.insert(RenameEntry {
            ino: path_hash(path),
            path_hash: path_hash(path),
            is_dir,
            in_use: true,
        })
        .unwrap();
    }

    #[test]
    fn rename_basic() {
        let mut t = RenameTable::new();
        insert(&mut t, b"/a", false);
        do_rename(&mut t, b"/a", b"/b").unwrap();
        assert!(t.find_by_hash(path_hash(b"/b")).is_some());
        assert!(t.find_by_hash(path_hash(b"/a")).is_none());
    }

    #[test]
    fn rename_replaces_existing() {
        let mut t = RenameTable::new();
        insert(&mut t, b"/a", false);
        insert(&mut t, b"/b", false);
        do_rename(&mut t, b"/a", b"/b").unwrap();
        assert!(t.find_by_hash(path_hash(b"/b")).is_some());
        // old /a entry gone.
        assert!(t.find_by_hash(path_hash(b"/a")).is_none());
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn rename_same_path_noop() {
        let mut t = RenameTable::new();
        insert(&mut t, b"/x", false);
        do_rename(&mut t, b"/x", b"/x").unwrap();
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn rename_not_found() {
        let mut t = RenameTable::new();
        assert_eq!(
            do_rename(&mut t, b"/missing", b"/new"),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn rename_noreplace_existing_fails() {
        let mut t = RenameTable::new();
        insert(&mut t, b"/a", false);
        insert(&mut t, b"/b", false);
        assert_eq!(
            do_renameat2(&mut t, AT_FDCWD, b"/a", AT_FDCWD, b"/b", RENAME_NOREPLACE),
            Err(Error::AlreadyExists)
        );
    }

    #[test]
    fn rename_noreplace_nonexistent_ok() {
        let mut t = RenameTable::new();
        insert(&mut t, b"/a", false);
        do_renameat2(&mut t, AT_FDCWD, b"/a", AT_FDCWD, b"/b", RENAME_NOREPLACE).unwrap();
        assert!(t.find_by_hash(path_hash(b"/b")).is_some());
    }

    #[test]
    fn rename_exchange() {
        let mut t = RenameTable::new();
        insert(&mut t, b"/a", false);
        insert(&mut t, b"/b", false);
        let ino_a = t.find_by_hash(path_hash(b"/a")).unwrap().ino;
        do_renameat2(&mut t, AT_FDCWD, b"/a", AT_FDCWD, b"/b", RENAME_EXCHANGE).unwrap();
        // After exchange: the entry previously at /a now has hash of /b.
        let entry_b = t.find_by_hash(path_hash(b"/b")).unwrap();
        assert_eq!(entry_b.ino, ino_a);
    }

    #[test]
    fn rename_dir_to_nondirectory_rejected() {
        let mut t = RenameTable::new();
        insert(&mut t, b"/d", true);
        insert(&mut t, b"/f", false);
        assert_eq!(do_rename(&mut t, b"/d", b"/f"), Err(Error::InvalidArgument));
    }

    #[test]
    fn rename_noreplace_exchange_mutually_exclusive() {
        let mut t = RenameTable::new();
        assert_eq!(
            do_renameat2(
                &mut t,
                AT_FDCWD,
                b"/a",
                AT_FDCWD,
                b"/b",
                RENAME_NOREPLACE | RENAME_EXCHANGE
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn rename_empty_path_rejected() {
        let mut t = RenameTable::new();
        assert_eq!(do_rename(&mut t, b"", b"/b"), Err(Error::InvalidArgument));
    }
}
