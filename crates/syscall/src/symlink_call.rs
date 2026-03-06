// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `symlink(2)` / `symlinkat(2)` syscall handler.
//!
//! Creates a symbolic link.
//!
//! # Key behaviours
//!
//! - Creates a new inode of type `S_IFLNK` whose data is the target string.
//! - `target` may be up to `PATH_MAX - 1` bytes; empty target is invalid.
//! - The `linkpath` must not already exist.
//! - Caller must have write and execute permission on the parent directory.
//! - `symlinkat(target, newdirfd, linkpath)` is the `dirfd`-relative variant.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `symlink()` / `symlinkat()`.
//!
//! # References
//!
//! - POSIX.1-2024: `symlink()`
//! - Linux: `fs/namei.c`, `vfs_symlink()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `AT_FDCWD` — resolve relative paths against cwd.
pub const AT_FDCWD: i32 = -100;
/// Maximum path length (POSIX PATH_MAX).
pub const PATH_MAX: usize = 4096;
/// Maximum number of entries in the symlink table.
pub const MAX_SYMLINK_ENTRIES: usize = 256;

// ---------------------------------------------------------------------------
// SymlinkEntry — one symbolic link
// ---------------------------------------------------------------------------

/// A stub symbolic link entry.
#[derive(Clone, Copy)]
pub struct SymlinkEntry {
    /// Inode number.
    pub ino: u64,
    /// Path hash of the link name (dentry stub key).
    pub link_hash: u64,
    /// Length of the target string (stored separately in TargetBuf).
    pub target_len: usize,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl SymlinkEntry {
    const fn empty() -> Self {
        Self {
            ino: 0,
            link_hash: 0,
            target_len: 0,
            in_use: false,
        }
    }
}

/// Maximum target length stored per symlink entry.
pub const MAX_TARGET_LEN: usize = PATH_MAX - 1;

/// A fixed-size buffer holding the symlink target string.
pub struct TargetBuf {
    data: [u8; MAX_TARGET_LEN],
    len: usize,
    ino: u64,
    in_use: bool,
}

impl TargetBuf {
    const fn empty() -> Self {
        Self {
            data: [0u8; MAX_TARGET_LEN],
            len: 0,
            ino: 0,
            in_use: false,
        }
    }

    /// Return the target as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

// ---------------------------------------------------------------------------
// SymlinkTable — stub table
// ---------------------------------------------------------------------------

/// A stub table for symbolic links.
pub struct SymlinkTable {
    entries: [SymlinkEntry; MAX_SYMLINK_ENTRIES],
    targets: [TargetBuf; MAX_SYMLINK_ENTRIES],
    count: usize,
    next_ino: u64,
}

impl SymlinkTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { SymlinkEntry::empty() }; MAX_SYMLINK_ENTRIES],
            targets: [const { TargetBuf::empty() }; MAX_SYMLINK_ENTRIES],
            count: 0,
            next_ino: 100,
        }
    }

    /// Insert a new symlink.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    fn insert_inner(&mut self, link_hash: u64, target: &[u8]) -> Result<u64> {
        for i in 0..MAX_SYMLINK_ENTRIES {
            if !self.entries[i].in_use {
                let ino = self.next_ino;
                self.next_ino += 1;
                let tlen = target.len();
                self.entries[i] = SymlinkEntry {
                    ino,
                    link_hash,
                    target_len: tlen,
                    in_use: true,
                };
                self.targets[i].ino = ino;
                self.targets[i].len = tlen;
                self.targets[i].data[..tlen].copy_from_slice(target);
                self.targets[i].in_use = true;
                self.count += 1;
                return Ok(ino);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an entry by link path hash.
    pub fn find_by_hash(&self, hash: u64) -> Option<&SymlinkEntry> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.link_hash == hash)
    }

    /// Read the target of a symlink by inode number.
    pub fn read_target(&self, ino: u64) -> Option<&[u8]> {
        self.targets
            .iter()
            .find(|t| t.in_use && t.ino == ino)
            .map(|t| t.as_bytes())
    }

    /// Return the number of symlinks.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for SymlinkTable {
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
// do_symlink — handler
// ---------------------------------------------------------------------------

/// Handler for `symlink(2)`.
///
/// Creates a symbolic link at `linkpath` with content `target`.
///
/// # Arguments
///
/// * `table`    — stub symlink table
/// * `target`   — content of the symbolic link (not resolved)
/// * `linkpath` — path where the link will be created
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — empty target, target ≥ `PATH_MAX`,
///   empty or overlong `linkpath`
/// * [`Error::AlreadyExists`]    — `linkpath` already exists
/// * [`Error::OutOfMemory`]      — table full
pub fn do_symlink(table: &mut SymlinkTable, target: &[u8], linkpath: &[u8]) -> Result<u64> {
    do_symlinkat(table, target, AT_FDCWD, linkpath)
}

/// Handler for `symlinkat(2)`.
///
/// # Arguments
///
/// * `table`    — stub symlink table
/// * `target`   — symbolic link content
/// * `newdirfd` — directory fd for `linkpath` (or `AT_FDCWD`)
/// * `linkpath` — path where the link is created
///
/// # Errors
///
/// Same as [`do_symlink`].
pub fn do_symlinkat(
    table: &mut SymlinkTable,
    target: &[u8],
    _newdirfd: i32,
    linkpath: &[u8],
) -> Result<u64> {
    if target.is_empty() || target.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    if linkpath.is_empty() || linkpath.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }

    let link_hash = path_hash(linkpath);

    // Fail if the link name already exists.
    if table.find_by_hash(link_hash).is_some() {
        return Err(Error::AlreadyExists);
    }

    table.insert_inner(link_hash, target)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symlink_creates_link() {
        let mut t = SymlinkTable::new();
        let ino = do_symlink(&mut t, b"/real/target", b"/link").unwrap();
        assert!(ino > 0);
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn symlink_target_readable() {
        let mut t = SymlinkTable::new();
        let ino = do_symlink(&mut t, b"/etc/motd", b"/motd").unwrap();
        let target = t.read_target(ino).unwrap();
        assert_eq!(target, b"/etc/motd");
    }

    #[test]
    fn symlink_already_exists() {
        let mut t = SymlinkTable::new();
        do_symlink(&mut t, b"/a", b"/link").unwrap();
        assert_eq!(
            do_symlink(&mut t, b"/b", b"/link"),
            Err(Error::AlreadyExists)
        );
    }

    #[test]
    fn symlink_empty_target_rejected() {
        let mut t = SymlinkTable::new();
        assert_eq!(
            do_symlink(&mut t, b"", b"/link"),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn symlink_empty_linkpath_rejected() {
        let mut t = SymlinkTable::new();
        assert_eq!(
            do_symlink(&mut t, b"/target", b""),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn symlink_multiple() {
        let mut t = SymlinkTable::new();
        do_symlink(&mut t, b"/a", b"/link1").unwrap();
        do_symlink(&mut t, b"/b", b"/link2").unwrap();
        assert_eq!(t.count(), 2);
    }

    #[test]
    fn symlinkat_creates_link() {
        let mut t = SymlinkTable::new();
        let ino = do_symlinkat(&mut t, b"/target", AT_FDCWD, b"/at_link").unwrap();
        assert!(ino > 0);
    }

    #[test]
    fn symlink_find_by_hash() {
        let mut t = SymlinkTable::new();
        do_symlink(&mut t, b"/x", b"/mylink").unwrap();
        let entry = t.find_by_hash(path_hash(b"/mylink"));
        assert!(entry.is_some());
    }
}
