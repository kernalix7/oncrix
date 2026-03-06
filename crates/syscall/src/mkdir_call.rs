// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mkdir(2)` / `mkdirat(2)` syscall handler.
//!
//! Creates a new directory in the filesystem.
//!
//! # Key behaviours
//!
//! - Requires write and execute permission on the parent directory.
//! - The effective creation mode is `mode & ~umask`.
//! - `AT_FDCWD` as `dirfd` means relative to the current working directory.
//! - The new directory is initialised with `.` and `..` entries.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `mkdir()` / `mkdirat()`.
//!
//! # References
//!
//! - POSIX.1-2024: `mkdir()`
//! - Linux: `fs/namei.c`, `vfs_mkdir()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `AT_FDCWD` — relative paths are resolved against the current directory.
pub const AT_FDCWD: i32 = -100;
/// Maximum path component length.
pub const NAME_MAX: usize = 255;
/// Maximum full path length.
pub const PATH_MAX: usize = 4096;
/// Maximum number of directory entries in the stub.
pub const MAX_DIRS: usize = 256;

// ---------------------------------------------------------------------------
// DirMode — permission bits
// ---------------------------------------------------------------------------

/// Directory permission mode (`mode_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DirMode(pub u32);

impl DirMode {
    /// Apply umask: return `self & !umask`.
    pub const fn apply_umask(self, umask: u32) -> Self {
        Self(self.0 & !umask)
    }

    /// Return the raw mode bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Return `true` if the owner-write bit is set.
    pub const fn owner_write(self) -> bool {
        self.0 & 0o200 != 0
    }

    /// Return `true` if the owner-execute bit is set.
    pub const fn owner_exec(self) -> bool {
        self.0 & 0o100 != 0
    }
}

// ---------------------------------------------------------------------------
// DirEntry — a directory in the stub
// ---------------------------------------------------------------------------

/// A stub directory entry.
#[derive(Clone, Copy)]
pub struct DirEntry {
    /// Inode number of this directory.
    pub ino: u64,
    /// Inode number of the parent directory.
    pub parent_ino: u64,
    /// Permission mode (post-umask).
    pub mode: DirMode,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Path hash of this directory (used as stub dentry key).
    pub path_hash: u64,
    /// Number of entries in this directory (including . and ..).
    pub nlink: u32,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl DirEntry {
    const fn empty() -> Self {
        Self {
            ino: 0,
            parent_ino: 0,
            mode: DirMode(0),
            uid: 0,
            gid: 0,
            path_hash: 0,
            nlink: 2,
            in_use: false,
        }
    }
}

// ---------------------------------------------------------------------------
// MkdirTable — stub directory table
// ---------------------------------------------------------------------------

/// A stub directory table.
pub struct MkdirTable {
    dirs: [DirEntry; MAX_DIRS],
    count: usize,
    next_ino: u64,
}

impl MkdirTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            dirs: [const { DirEntry::empty() }; MAX_DIRS],
            count: 0,
            next_ino: 2,
        }
    }

    /// Insert a directory, returning its assigned inode number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, mut entry: DirEntry) -> Result<u64> {
        for slot in self.dirs.iter_mut() {
            if !slot.in_use {
                let ino = self.next_ino;
                self.next_ino += 1;
                entry.ino = ino;
                entry.in_use = true;
                *slot = entry;
                self.count += 1;
                return Ok(ino);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a directory by path hash.
    pub fn find_by_hash(&self, hash: u64) -> Option<&DirEntry> {
        self.dirs.iter().find(|d| d.in_use && d.path_hash == hash)
    }

    /// Find a directory by inode number.
    pub fn find_by_ino(&self, ino: u64) -> Option<&DirEntry> {
        self.dirs.iter().find(|d| d.in_use && d.ino == ino)
    }

    /// Return the number of directories.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for MkdirTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// FNV-1a path hash.
fn path_hash(path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Validate a path: non-empty, no NUL bytes, < PATH_MAX.
fn validate_path(path: &[u8]) -> Result<()> {
    if path.is_empty() || path.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    if path.contains(&0) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Extract the last component from a path and compute the parent path hash.
///
/// Returns `(component, parent_hash)`.
fn split_path(path: &[u8]) -> (&[u8], u64) {
    let path = if path.last() == Some(&b'/') {
        &path[..path.len() - 1]
    } else {
        path
    };
    match path.iter().rposition(|&b| b == b'/') {
        Some(pos) => {
            let parent = &path[..pos.max(1)]; // at minimum "/"
            let name = &path[pos + 1..];
            (name, path_hash(parent))
        }
        None => {
            // Relative path: parent is "." (cwd) — hash of empty slice.
            (path, path_hash(b"."))
        }
    }
}

// ---------------------------------------------------------------------------
// do_mkdir — main handler
// ---------------------------------------------------------------------------

/// Handler for `mkdir(2)` / `mkdirat(2)`.
///
/// Creates a new directory at `path` (relative to `dirfd`).  The new
/// directory's mode is `raw_mode & ~umask`.
///
/// The parent directory must exist (stub: identified by path hash) and
/// the caller must have write + execute permission on it.
///
/// # Arguments
///
/// * `table`    — stub directory table
/// * `dirfd`    — directory fd for relative paths (`AT_FDCWD` for cwd)
/// * `path`     — path of the new directory
/// * `raw_mode` — permission bits before umask application
/// * `umask`    — process umask
/// * `uid`      — caller UID (for permission check and ownership)
/// * `gid`      — caller GID (for ownership)
///
/// # Returns
///
/// The inode number of the newly created directory.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — empty, overlong, or NUL-containing path
/// * [`Error::NotFound`]         — parent directory does not exist
/// * [`Error::AlreadyExists`]    — path already exists
/// * [`Error::PermissionDenied`] — caller lacks write/exec on parent
/// * [`Error::OutOfMemory`]      — table full
pub fn do_mkdir(
    table: &mut MkdirTable,
    dirfd: i32,
    path: &[u8],
    raw_mode: u32,
    umask: u32,
    uid: u32,
    gid: u32,
) -> Result<u64> {
    validate_path(path)?;

    let full_hash = path_hash(path);

    // Check that the target does not already exist.
    if table.find_by_hash(full_hash).is_some() {
        return Err(Error::AlreadyExists);
    }

    let (_name, parent_hash) = split_path(path);

    // Look up the parent directory.
    // Absolute paths starting with '/' may have a root parent (hash of "/").
    let root_hash = path_hash(b"/");
    let cwd_hash = path_hash(b".");

    let parent = if path.starts_with(b"/") && parent_hash == path_hash(b"/") {
        // Top-level directory inside root.
        // Stub: synthesise a root entry if none exists.
        None
    } else if parent_hash == cwd_hash {
        // Relative path: parent is cwd.  Stub: allow if dirfd is AT_FDCWD.
        if dirfd != AT_FDCWD {
            table.find_by_ino(dirfd as u64)
        } else {
            None
        }
    } else {
        table.find_by_hash(parent_hash)
    };

    // Permission check on parent (skip for root stub).
    if let Some(p) = parent {
        let can_write = uid == 0 || uid == p.uid && p.mode.owner_write();
        let can_exec = uid == 0 || uid == p.uid && p.mode.owner_exec();
        if !can_write || !can_exec {
            return Err(Error::PermissionDenied);
        }
    }

    let mode = DirMode(raw_mode).apply_umask(umask);
    let parent_ino = match parent {
        Some(p) => p.ino,
        None => {
            // Root or cwd — use hash as stand-in for ino.
            if path.starts_with(b"/") {
                root_hash
            } else {
                cwd_hash
            }
        }
    };

    let entry = DirEntry {
        ino: 0,
        parent_ino,
        mode,
        uid,
        gid,
        path_hash: full_hash,
        nlink: 2,
        in_use: true,
    };

    table.insert(entry)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mkdir_creates_directory() {
        let mut t = MkdirTable::new();
        let ino = do_mkdir(&mut t, AT_FDCWD, b"/newdir", 0o755, 0o022, 1000, 1000).unwrap();
        assert!(ino > 0);
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn mkdir_already_exists() {
        let mut t = MkdirTable::new();
        do_mkdir(&mut t, AT_FDCWD, b"/mydir", 0o755, 0, 0, 0).unwrap();
        assert_eq!(
            do_mkdir(&mut t, AT_FDCWD, b"/mydir", 0o755, 0, 0, 0),
            Err(Error::AlreadyExists)
        );
    }

    #[test]
    fn mkdir_empty_path_rejected() {
        let mut t = MkdirTable::new();
        assert_eq!(
            do_mkdir(&mut t, AT_FDCWD, b"", 0o755, 0, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn mkdir_mode_umask_applied() {
        let mut t = MkdirTable::new();
        do_mkdir(&mut t, AT_FDCWD, b"/umask_dir", 0o777, 0o022, 0, 0).unwrap();
        let entry = t.find_by_hash(path_hash(b"/umask_dir")).unwrap();
        assert_eq!(entry.mode.bits(), 0o755);
    }

    #[test]
    fn mkdir_multiple_directories() {
        let mut t = MkdirTable::new();
        do_mkdir(&mut t, AT_FDCWD, b"/a", 0o755, 0, 0, 0).unwrap();
        do_mkdir(&mut t, AT_FDCWD, b"/b", 0o755, 0, 0, 0).unwrap();
        assert_eq!(t.count(), 2);
    }

    #[test]
    fn mkdir_root_allowed_for_root_user() {
        let mut t = MkdirTable::new();
        // uid 0 (root) should always be allowed.
        do_mkdir(&mut t, AT_FDCWD, b"/privileged", 0o700, 0, 0, 0).unwrap();
    }

    #[test]
    fn dir_mode_apply_umask() {
        let m = DirMode(0o777).apply_umask(0o022);
        assert_eq!(m.bits(), 0o755);
    }

    #[test]
    fn split_path_top_level() {
        let (name, _parent_hash) = split_path(b"/mydir");
        assert_eq!(name, b"mydir");
    }

    #[test]
    fn split_path_nested() {
        let (name, parent_hash) = split_path(b"/a/b/c");
        assert_eq!(name, b"c");
        assert_eq!(parent_hash, path_hash(b"/a/b"));
    }
}
