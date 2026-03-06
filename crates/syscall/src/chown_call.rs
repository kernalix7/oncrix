// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `chown(2)` / `fchown(2)` / `lchown(2)` / `fchownat(2)` syscall handler.
//!
//! Changes ownership (user and group) of a filesystem entry.
//!
//! # Key behaviours
//!
//! - Requires `CAP_CHOWN` (root) to change UID/GID to an arbitrary value.
//! - Unprivileged owner may only change the GID to a group it belongs to.
//! - `-1` for UID or GID means "no change".
//! - Changing ownership of a non-root-owned file clears the `setuid` /
//!   `setgid` bits (security requirement).
//! - `AT_SYMLINK_NOFOLLOW` operates on the symlink itself.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `chown()` / `fchown()` / `lchown()` / `fchownat()`.
//!
//! # References
//!
//! - POSIX.1-2024: `chown()`, `fchown()`
//! - Linux: `fs/attr.c`, `chown_common()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `AT_FDCWD` — relative paths resolved against cwd.
pub const AT_FDCWD: i32 = -100;
/// `AT_SYMLINK_NOFOLLOW` — operate on symlink itself.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
/// `AT_EMPTY_PATH` — target is the open fd.
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// Known `fchownat` flags.
const CHOWNAT_KNOWN: u32 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

/// UID / GID value meaning "no change".
pub const NOCHG: u32 = u32::MAX;

/// `setuid` bit.
const S_ISUID: u32 = 0o4000;
/// `setgid` bit.
const S_ISGID: u32 = 0o2000;

/// Maximum path length.
pub const PATH_MAX: usize = 4096;
/// Maximum entries in the chown table.
pub const MAX_CHOWN_ENTRIES: usize = 256;

// ---------------------------------------------------------------------------
// ChownEntry — stub inode
// ---------------------------------------------------------------------------

/// A stub inode for the chown handler.
#[derive(Clone, Copy)]
pub struct ChownEntry {
    /// Inode number.
    pub ino: u64,
    /// Path hash (dentry stub key).
    pub path_hash: u64,
    /// Current owner UID.
    pub uid: u32,
    /// Current owner GID.
    pub gid: u32,
    /// Mode bits (for clearing setuid/setgid).
    pub mode: u32,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl ChownEntry {
    const fn empty() -> Self {
        Self {
            ino: 0,
            path_hash: 0,
            uid: 0,
            gid: 0,
            mode: 0,
            in_use: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ChownTable — stub table
// ---------------------------------------------------------------------------

/// A stub table for the chown handler.
pub struct ChownTable {
    entries: [ChownEntry; MAX_CHOWN_ENTRIES],
    count: usize,
}

impl ChownTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { ChownEntry::empty() }; MAX_CHOWN_ENTRIES],
            count: 0,
        }
    }

    /// Insert an entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, e: ChownEntry) -> Result<()> {
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
    pub fn find_by_hash(&self, hash: u64) -> Option<&ChownEntry> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.path_hash == hash)
    }

    /// Find a mutable entry by path hash.
    pub fn find_by_hash_mut(&mut self, hash: u64) -> Option<&mut ChownEntry> {
        self.entries
            .iter_mut()
            .find(|e| e.in_use && e.path_hash == hash)
    }

    /// Find a mutable entry by inode number.
    pub fn find_by_ino_mut(&mut self, ino: u64) -> Option<&mut ChownEntry> {
        self.entries.iter_mut().find(|e| e.in_use && e.ino == ino)
    }

    /// Return the number of entries.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for ChownTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CallerCreds — identity of the calling process
// ---------------------------------------------------------------------------

/// Identity of the calling process for permission checks.
#[derive(Debug, Clone, Copy)]
pub struct CallerCreds {
    /// Effective UID.
    pub euid: u32,
    /// Effective GID.
    pub egid: u32,
    /// Supplementary groups the caller belongs to (up to 32).
    pub groups: [u32; 32],
    /// Number of supplementary groups.
    pub ngroups: usize,
}

impl CallerCreds {
    /// Return `true` if this caller has root / `CAP_CHOWN`.
    pub const fn is_privileged(&self) -> bool {
        self.euid == 0
    }

    /// Return `true` if the caller belongs to `gid`.
    pub fn has_group(&self, gid: u32) -> bool {
        if self.egid == gid {
            return true;
        }
        self.groups[..self.ngroups].contains(&gid)
    }
}

// ---------------------------------------------------------------------------
// Path helper
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
// apply_chown — core logic
// ---------------------------------------------------------------------------

/// Apply a chown operation to a mutable [`ChownEntry`].
///
/// # Arguments
///
/// * `entry`    — target inode entry
/// * `new_uid`  — new UID (`NOCHG` = no change)
/// * `new_gid`  — new GID (`NOCHG` = no change)
/// * `caller`   — caller credentials
///
/// # Errors
///
/// * [`Error::PermissionDenied`] — caller lacks permission
pub fn apply_chown(
    entry: &mut ChownEntry,
    new_uid: u32,
    new_gid: u32,
    caller: &CallerCreds,
) -> Result<()> {
    // Changing UID requires CAP_CHOWN.
    if new_uid != NOCHG && new_uid != entry.uid {
        if !caller.is_privileged() {
            return Err(Error::PermissionDenied);
        }
    }

    // Changing GID: privileged may set any value; unprivileged may
    // only set a GID they belong to, and only on files they own.
    if new_gid != NOCHG && new_gid != entry.gid {
        if !caller.is_privileged() {
            if entry.uid != caller.euid {
                return Err(Error::PermissionDenied);
            }
            if !caller.has_group(new_gid) {
                return Err(Error::PermissionDenied);
            }
        }
    }

    // Clear setuid/setgid when ownership changes (and caller is not root).
    let uid_changes = new_uid != NOCHG && new_uid != entry.uid;
    let gid_changes = new_gid != NOCHG && new_gid != entry.gid;
    if (uid_changes || gid_changes) && !caller.is_privileged() {
        entry.mode &= !(S_ISUID | S_ISGID);
    }

    if new_uid != NOCHG {
        entry.uid = new_uid;
    }
    if new_gid != NOCHG {
        entry.gid = new_gid;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// do_chown / fchown / lchown / fchownat
// ---------------------------------------------------------------------------

/// Handler for `chown(2)`.
///
/// Changes ownership of the file at `path` (follows symlinks).
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — empty or overlong path
/// * [`Error::NotFound`]        — path not found
/// * [`Error::PermissionDenied`] — insufficient privilege
pub fn do_chown(
    table: &mut ChownTable,
    path: &[u8],
    new_uid: u32,
    new_gid: u32,
    caller: &CallerCreds,
) -> Result<()> {
    if path.is_empty() || path.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    let hash = path_hash(path);
    let entry = table.find_by_hash_mut(hash).ok_or(Error::NotFound)?;
    apply_chown(entry, new_uid, new_gid, caller)
}

/// Handler for `fchown(2)`.
///
/// Changes ownership of the open file `fd`.
///
/// # Errors
///
/// * [`Error::NotFound`]         — `fd` not found (stub uses ino as fd)
/// * [`Error::PermissionDenied`] — insufficient privilege
pub fn do_fchown(
    table: &mut ChownTable,
    fd_ino: u64,
    new_uid: u32,
    new_gid: u32,
    caller: &CallerCreds,
) -> Result<()> {
    let entry = table.find_by_ino_mut(fd_ino).ok_or(Error::NotFound)?;
    apply_chown(entry, new_uid, new_gid, caller)
}

/// Handler for `lchown(2)`.
///
/// Like `chown` but does not follow symlinks.
/// Stub: identical to `do_chown` since the table does not distinguish
/// symlinks from their targets.
///
/// # Errors
///
/// Same as [`do_chown`].
pub fn do_lchown(
    table: &mut ChownTable,
    path: &[u8],
    new_uid: u32,
    new_gid: u32,
    caller: &CallerCreds,
) -> Result<()> {
    do_chown(table, path, new_uid, new_gid, caller)
}

/// Handler for `fchownat(2)`.
///
/// # Arguments
///
/// * `table`   — stub table
/// * `_dirfd`  — directory fd (stub: ignored for absolute paths)
/// * `path`    — file path
/// * `new_uid` — new UID
/// * `new_gid` — new GID
/// * `flags`   — `AT_SYMLINK_NOFOLLOW` or `AT_EMPTY_PATH`
/// * `caller`  — caller credentials
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — unknown flags
/// * Same as [`do_chown`]
pub fn do_fchownat(
    table: &mut ChownTable,
    _dirfd: i32,
    path: &[u8],
    new_uid: u32,
    new_gid: u32,
    flags: u32,
    caller: &CallerCreds,
) -> Result<()> {
    if flags & !CHOWNAT_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    // AT_SYMLINK_NOFOLLOW → lchown semantics (stub: same behaviour).
    do_chown(table, path, new_uid, new_gid, caller)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn root_caller() -> CallerCreds {
        CallerCreds {
            euid: 0,
            egid: 0,
            groups: [0u32; 32],
            ngroups: 0,
        }
    }

    fn user_caller(euid: u32, egid: u32) -> CallerCreds {
        CallerCreds {
            euid,
            egid,
            groups: [0u32; 32],
            ngroups: 0,
        }
    }

    fn insert(t: &mut ChownTable, path: &[u8], uid: u32, gid: u32, mode: u32) {
        t.insert(ChownEntry {
            ino: path_hash(path),
            path_hash: path_hash(path),
            uid,
            gid,
            mode,
            in_use: true,
        })
        .unwrap();
    }

    #[test]
    fn chown_root_can_change_uid() {
        let mut t = ChownTable::new();
        insert(&mut t, b"/file", 1000, 1000, 0o644);
        do_chown(&mut t, b"/file", 2000, NOCHG, &root_caller()).unwrap();
        assert_eq!(t.find_by_hash(path_hash(b"/file")).unwrap().uid, 2000);
    }

    #[test]
    fn chown_non_root_uid_denied() {
        let mut t = ChownTable::new();
        insert(&mut t, b"/file", 1000, 1000, 0o644);
        assert_eq!(
            do_chown(&mut t, b"/file", 2000, NOCHG, &user_caller(1000, 1000)),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn chown_nochg_preserves_values() {
        let mut t = ChownTable::new();
        insert(&mut t, b"/file", 1000, 1000, 0o644);
        do_chown(&mut t, b"/file", NOCHG, NOCHG, &root_caller()).unwrap();
        let e = t.find_by_hash(path_hash(b"/file")).unwrap();
        assert_eq!(e.uid, 1000);
        assert_eq!(e.gid, 1000);
    }

    #[test]
    fn chown_clears_setuid_on_ownership_change() {
        let mut t = ChownTable::new();
        insert(&mut t, b"/suid", 1000, 1000, 0o4755); // setuid set
        let mut caller = user_caller(1000, 2000);
        caller.groups[0] = 2000;
        caller.ngroups = 1;
        do_chown(&mut t, b"/suid", NOCHG, 2000, &caller).unwrap();
        let e = t.find_by_hash(path_hash(b"/suid")).unwrap();
        // setuid bit must be cleared.
        assert_eq!(e.mode & 0o4000, 0);
    }

    #[test]
    fn chown_root_preserves_setuid() {
        let mut t = ChownTable::new();
        insert(&mut t, b"/suid", 1000, 1000, 0o4755);
        // Root changing owner does NOT clear setuid (behaviour varies; our
        // stub only clears for non-root callers).
        do_chown(&mut t, b"/suid", 2000, NOCHG, &root_caller()).unwrap();
        let e = t.find_by_hash(path_hash(b"/suid")).unwrap();
        assert_ne!(e.mode & 0o4000, 0);
    }

    #[test]
    fn fchown_by_ino() {
        let mut t = ChownTable::new();
        let ino = path_hash(b"/byfd");
        t.insert(ChownEntry {
            ino,
            path_hash: path_hash(b"/byfd"),
            uid: 1000,
            gid: 1000,
            mode: 0o644,
            in_use: true,
        })
        .unwrap();
        do_fchown(&mut t, ino, 0, NOCHG, &root_caller()).unwrap();
        assert_eq!(t.find_by_ino_mut(ino).unwrap().uid, 0);
    }

    #[test]
    fn fchownat_unknown_flags_rejected() {
        let mut t = ChownTable::new();
        assert_eq!(
            do_fchownat(&mut t, AT_FDCWD, b"/f", 0, 0, 0xFF, &root_caller()),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn chown_not_found() {
        let mut t = ChownTable::new();
        assert_eq!(
            do_chown(&mut t, b"/missing", 0, 0, &root_caller()),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn chown_empty_path_rejected() {
        let mut t = ChownTable::new();
        assert_eq!(
            do_chown(&mut t, b"", 0, 0, &root_caller()),
            Err(Error::InvalidArgument)
        );
    }
}
