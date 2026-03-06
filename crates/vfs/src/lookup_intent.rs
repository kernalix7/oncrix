// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intent-based path lookup optimization.
//!
//! This module models the *intent* that drives a path lookup — whether the caller
//! wants to open, create, rename, or stat an object.  Carrying the intent through
//! the VFS lookup machinery allows the path walker to skip redundant permission
//! checks and optimize last-component handling.
//!
//! # Design
//!
//! ```text
//! lookup_path_at(dirfd, path, intent, flags)
//!   │
//!   ├── NameiData { path, intent, flags, depth=0 }
//!   │
//!   ├── PathWalker::walk_component() × N   ← each path component
//!   │     ├── follow_symlink() if needed
//!   │     └── resolve_dotdot() for ".."
//!   │
//!   └── LookupResult { inode_id, parent_inode_id, name, found }
//! ```
//!
//! Symlink loop detection aborts after [`MAX_SYMLINK_FOLLOW`] follows,
//! returning [`Error::InvalidArgument`] (ELOOP).
//!
//! # References
//!
//! - Linux `fs/namei.c` — `path_lookupat()`, `do_filp_open()`, `nameidata`
//! - Linux `include/linux/namei.h` — `LOOKUP_*` flags
//! - POSIX.1-2024 `open(3)`, `symlink(3)` semantics

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of concurrent path walks held in a [`PathWalker`].
pub const MAX_CONCURRENT_LOOKUPS: usize = 16;

/// Maximum depth of path components before returning [`Error::InvalidArgument`].
pub const MAX_PATH_DEPTH: u8 = 64;

/// Maximum path length in bytes (including the null terminator if any).
pub const MAX_PATH_LEN: usize = 256;

/// Maximum number of symlink follows before ELOOP.
pub const MAX_SYMLINK_FOLLOW: u32 = 40;

/// Maximum name component length (single path element, excluding `/`).
pub const MAX_NAME_COMPONENT: usize = 256;

// ── LookupIntent ─────────────────────────────────────────────────────────────

/// The caller's intent driving a path lookup.
///
/// Carrying the intent into [`NameiData`] allows the VFS to short-circuit
/// work that is irrelevant for the specific operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupIntent {
    /// Open an existing file; the u32 field carries the O_* open flags.
    Open(u32),
    /// Create a new file with the given mode if it does not exist.
    Create(u32),
    /// Unlink (delete) the last component.
    Unlink,
    /// Rename: the last component is the destination name.
    Rename,
    /// Retrieve attributes (`stat(2)`).
    Getattr,
    /// Modify attributes (`chmod`, `chown`, `utimes`).
    Setattr,
    /// Read the target of a symlink (`readlink(2)`).
    ReadLink,
}

impl LookupIntent {
    /// Return `true` when this intent may create a new directory entry.
    pub fn may_create(&self) -> bool {
        matches!(self, Self::Create(_) | Self::Rename)
    }

    /// Return `true` when this intent requires the target to already exist.
    pub fn requires_existing(&self) -> bool {
        matches!(
            self,
            Self::Unlink | Self::Getattr | Self::Setattr | Self::ReadLink
        )
    }
}

// ── LookupFlags ──────────────────────────────────────────────────────────────

/// Bit-flag set controlling how a path walk behaves.
///
/// These mirror the `LOOKUP_*` constants from the Linux VFS.
pub mod lookup_flags {
    /// Follow trailing symlinks in the last component.
    pub const FOLLOW: u32 = 0x0001;
    /// Require the last component to be (or resolve to) a directory.
    pub const DIRECTORY: u32 = 0x0002;
    /// Do *not* follow trailing symlinks — complement of [`FOLLOW`].
    pub const NOFOLLOW: u32 = 0x0004;
    /// Trigger automount when a mount trigger is encountered.
    pub const AUTOMOUNT: u32 = 0x0010;
    /// Allow `path` to be an empty string; operate on `dirfd` itself.
    pub const EMPTY_PATH: u32 = 0x0020;
    /// Refuse to follow magic-link symlinks (e.g. `/proc/self/exe`).
    pub const NO_MAGICLINKS: u32 = 0x0040;
    /// Require every component to be beneath `root_dir` (RESOLVE_BENEATH).
    pub const BENEATH: u32 = 0x0080;
    /// Pin the root to the lookup root (RESOLVE_IN_ROOT).
    pub const IN_ROOT: u32 = 0x0100;
}

// ── NameiData ─────────────────────────────────────────────────────────────────

/// All state carried through a single path-walk traversal.
///
/// `NameiData` is allocated on the stack for each `lookup_path_at` call and
/// threaded through every component walk.
#[derive(Debug, Clone, Copy)]
pub struct NameiData {
    /// Raw path bytes being walked (null-padded).
    pub path: [u8; MAX_PATH_LEN],
    /// Number of bytes populated in `path`.
    pub path_len: usize,
    /// Current recursion depth into the path string.
    pub depth: u8,
    /// Total number of symlinks followed so far in this walk.
    pub total_link_count: u32,
    /// The caller's lookup intent.
    pub intent: LookupIntent,
    /// Combination of [`lookup_flags`] constants.
    pub flags: u32,
    /// Inode id of the logical root for this walk (governs `..` escape prevention).
    pub root_dir: u64,
    /// Inode id of the current working directory at walk start.
    pub current_dir: u64,
}

impl NameiData {
    /// Build a new `NameiData` from a path slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `path` is longer than [`MAX_PATH_LEN`].
    pub fn new(
        path: &[u8],
        intent: LookupIntent,
        flags: u32,
        root_dir: u64,
        current_dir: u64,
    ) -> Result<Self> {
        if path.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_PATH_LEN];
        buf[..path.len()].copy_from_slice(path);
        Ok(Self {
            path: buf,
            path_len: path.len(),
            depth: 0,
            total_link_count: 0,
            intent,
            flags,
            root_dir,
            current_dir,
        })
    }

    /// Return the raw path as a byte slice (trimming null padding).
    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Return `true` when the `BENEATH` flag requires the walk to stay below `root_dir`.
    pub fn must_stay_beneath(&self) -> bool {
        (self.flags & lookup_flags::BENEATH) != 0
    }
}

// ── LookupResult ─────────────────────────────────────────────────────────────

/// The outcome of a completed path walk.
#[derive(Debug, Clone, Copy)]
pub struct LookupResult {
    /// Inode id of the resolved target (meaningful only when `found` is `true`).
    pub inode_id: u64,
    /// Inode id of the parent directory of the last component.
    pub parent_inode_id: u64,
    /// Last path component name (null-padded to [`MAX_NAME_COMPONENT`] bytes).
    pub name: [u8; MAX_NAME_COMPONENT],
    /// Number of bytes populated in `name`.
    pub name_len: usize,
    /// `true` when the target inode was found.
    pub found: bool,
}

impl Default for LookupResult {
    fn default() -> Self {
        Self {
            inode_id: 0,
            parent_inode_id: 0,
            name: [0u8; MAX_NAME_COMPONENT],
            name_len: 0,
            found: false,
        }
    }
}

impl LookupResult {
    /// Return the last-component name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Set the `name` field from a slice, truncating to `MAX_NAME_COMPONENT`.
    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(MAX_NAME_COMPONENT);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len;
    }
}

// ── WalkSlot ─────────────────────────────────────────────────────────────────

/// One concurrent-walk slot inside a [`PathWalker`].
#[derive(Clone, Copy)]
struct WalkSlot {
    /// `true` when this slot holds an active walk.
    active: bool,
    /// Snapshot of the `NameiData` for this walk.
    nd: NameiData,
    /// Partial result accumulated so far.
    result: LookupResult,
}

impl Default for WalkSlot {
    fn default() -> Self {
        Self {
            active: false,
            nd: NameiData {
                path: [0u8; MAX_PATH_LEN],
                path_len: 0,
                depth: 0,
                total_link_count: 0,
                intent: LookupIntent::Getattr,
                flags: 0,
                root_dir: 0,
                current_dir: 0,
            },
            result: LookupResult::default(),
        }
    }
}

// ── PathWalker ────────────────────────────────────────────────────────────────

/// Path walker capable of holding up to [`MAX_CONCURRENT_LOOKUPS`] active walks.
///
/// A single `PathWalker` instance is typically held per-CPU or per-task.
pub struct PathWalker {
    /// Slot pool.
    slots: [WalkSlot; MAX_CONCURRENT_LOOKUPS],
    /// Accumulated statistics.
    stats: LookupStats,
}

impl Default for PathWalker {
    fn default() -> Self {
        Self::new()
    }
}

impl PathWalker {
    /// Construct an idle `PathWalker` with all slots free.
    pub const fn new() -> Self {
        Self {
            slots: [const {
                WalkSlot {
                    active: false,
                    nd: NameiData {
                        path: [0u8; MAX_PATH_LEN],
                        path_len: 0,
                        depth: 0,
                        total_link_count: 0,
                        intent: LookupIntent::Getattr,
                        flags: 0,
                        root_dir: 0,
                        current_dir: 0,
                    },
                    result: LookupResult {
                        inode_id: 0,
                        parent_inode_id: 0,
                        name: [0u8; MAX_NAME_COMPONENT],
                        name_len: 0,
                        found: false,
                    },
                }
            }; MAX_CONCURRENT_LOOKUPS],
            stats: LookupStats::new(),
        }
    }

    /// Walk a single path component `name` from parent inode `parent_id`.
    ///
    /// This stub simulates a dentry-cache lookup and inode resolution.  A real
    /// implementation would call into the filesystem's `lookup` inode op.
    ///
    /// # Returns
    ///
    /// The child inode id on success.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — component not present.
    /// - [`Error::InvalidArgument`] — component name is empty or too long.
    pub fn walk_component(
        &mut self,
        parent_id: u64,
        name: &[u8],
        _nd: &mut NameiData,
    ) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_NAME_COMPONENT {
            return Err(Error::InvalidArgument);
        }
        // Simulate a trivial lookup: synthesise child ino from parent and name hash.
        let hash = simple_hash(name);
        let child_id = parent_id
            .wrapping_mul(0x9e37_79b9)
            .wrapping_add(hash as u64);
        self.stats.total_lookups += 1;
        Ok(child_id)
    }

    /// Follow a symlink whose target is `target` from within `nd`.
    ///
    /// Updates `nd.total_link_count` and returns `Error::InvalidArgument` on ELOOP.
    pub fn follow_symlink(&mut self, target: &[u8], nd: &mut NameiData) -> Result<()> {
        nd.total_link_count += 1;
        self.stats.symlinks_followed += 1;
        if nd.total_link_count > MAX_SYMLINK_FOLLOW {
            self.stats.loops_detected += 1;
            return Err(Error::InvalidArgument); // ELOOP
        }
        // In a real VFS this would re-enter the path walk with the symlink target.
        // For stub purposes we simply validate the target length.
        if target.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Resolve a `..` component, clamping to `nd.root_dir` if `BENEATH` is set.
    ///
    /// Returns the parent inode id after resolving dotdot.
    pub fn resolve_dotdot(&mut self, current_id: u64, nd: &NameiData) -> Result<u64> {
        if nd.must_stay_beneath() && current_id == nd.root_dir {
            // Already at the constrained root — `..` stays here.
            return Ok(nd.root_dir);
        }
        // Stub: synthesise the parent inode id deterministically.
        if current_id == 0 {
            return Ok(0);
        }
        Ok(current_id - 1)
    }

    /// Return a reference to accumulated statistics.
    pub fn stats(&self) -> &LookupStats {
        &self.stats
    }

    // -- private helpers ------------------------------------------------------

    fn alloc_slot(&mut self) -> Option<usize> {
        for (i, s) in self.slots.iter().enumerate() {
            if !s.active {
                return Some(i);
            }
        }
        None
    }

    fn free_slot(&mut self, idx: usize) {
        if idx < MAX_CONCURRENT_LOOKUPS {
            self.slots[idx] = WalkSlot::default();
        }
    }
}

// ── lookup_path_at ────────────────────────────────────────────────────────────

/// Resolve `path` relative to `dirfd` using `intent` and `flags`.
///
/// This is the primary entry point for VFS path resolution.
///
/// # Parameters
///
/// - `dirfd`       — base directory fd (`AT_FDCWD` = −100 for cwd).
/// - `path`        — path bytes to resolve.
/// - `intent`      — caller's [`LookupIntent`].
/// - `flags`       — combination of [`lookup_flags`] constants.
/// - `root_dir`    — inode id of the namespace root (escape boundary).
/// - `current_dir` — inode id of the current working directory.
/// - `walker`      — the `PathWalker` to use for this resolution.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — path too long, ELOOP, or bad flags.
/// - [`Error::NotFound`]        — path does not exist and intent is not `Create`.
pub fn lookup_path_at(
    _dirfd: i32,
    path: &[u8],
    intent: LookupIntent,
    flags: u32,
    root_dir: u64,
    current_dir: u64,
    walker: &mut PathWalker,
) -> Result<LookupResult> {
    let mut nd = NameiData::new(path, intent, flags, root_dir, current_dir)?;

    let slot_idx = walker.alloc_slot().ok_or(Error::Busy)?;
    walker.slots[slot_idx].active = true;
    walker.slots[slot_idx].nd = nd;

    // Determine starting inode.
    let start_ino = if path.first() == Some(&b'/') {
        root_dir
    } else {
        current_dir
    };

    let mut current_ino = start_ino;
    let mut parent_ino = start_ino;
    // Copy the path into a local owned buffer so we can mutate `nd` freely
    // while still iterating over path components.
    let mut path_buf = [0u8; MAX_PATH_LEN];
    let path_len = nd.path_len.min(MAX_PATH_LEN);
    path_buf[..path_len].copy_from_slice(&nd.path[..path_len]);
    let path_slice = &path_buf[..path_len];

    let skip = if path_slice.first() == Some(&b'/') {
        1
    } else {
        0
    };
    let remaining = &path_slice[skip..];

    // We need to own last_name as a fixed-size buffer rather than a slice into
    // `remaining`, because `remaining` borrows `path_buf` which we cannot move.
    let mut last_name_buf = [0u8; MAX_NAME_COMPONENT];
    let mut last_name_len = 0usize;

    let mut pos = 0usize;
    while pos < remaining.len() {
        let end = remaining[pos..]
            .iter()
            .position(|&b| b == b'/')
            .map(|i| pos + i)
            .unwrap_or(remaining.len());
        let component = &remaining[pos..end];
        pos = (end + 1).min(remaining.len());

        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            nd.depth = nd.depth.saturating_sub(1);
            parent_ino = walker.resolve_dotdot(current_ino, &nd)?;
            current_ino = parent_ino;
            continue;
        }

        nd.depth += 1;
        if nd.depth > MAX_PATH_DEPTH {
            walker.free_slot(slot_idx);
            return Err(Error::InvalidArgument);
        }

        parent_ino = current_ino;
        // Copy component into our owned name buffer.
        let clen = component.len().min(MAX_NAME_COMPONENT);
        last_name_buf[..clen].copy_from_slice(&component[..clen]);
        last_name_len = clen;

        current_ino = walker.walk_component(current_ino, component, &mut nd)?;
    }

    let mut result = LookupResult::default();
    result.inode_id = current_ino;
    result.parent_inode_id = parent_ino;
    result.set_name(&last_name_buf[..last_name_len]);
    result.found = true;

    // Honour NOFOLLOW: if the last component turned out to be a symlink we don't
    // follow it.  Here we stub that as always resolving successfully.
    if (flags & lookup_flags::FOLLOW) != 0 && (flags & lookup_flags::NOFOLLOW) == 0 {
        // Would follow trailing symlink — no-op in the stub.
    }

    walker.free_slot(slot_idx);
    Ok(result)
}

// ── Utility ───────────────────────────────────────────────────────────────────

/// Fast, non-cryptographic hash of a byte slice.
fn simple_hash(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in data {
        h = h.wrapping_mul(0x0100_0193).wrapping_add(b as u32);
    }
    h
}

// ── LookupStats ──────────────────────────────────────────────────────────────

/// Cumulative statistics for the path-lookup subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct LookupStats {
    /// Total number of path-component lookups attempted.
    pub total_lookups: u64,
    /// Lookups satisfied from the dentry cache without filesystem I/O.
    pub cache_hits: u64,
    /// Total symlinks followed across all walks.
    pub symlinks_followed: u64,
    /// Number of times the ELOOP limit was reached.
    pub loops_detected: u64,
}

impl LookupStats {
    /// Construct a zeroed stats object.
    pub const fn new() -> Self {
        Self {
            total_lookups: 0,
            cache_hits: 0,
            symlinks_followed: 0,
            loops_detected: 0,
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_path_walk() {
        let mut walker = PathWalker::new();
        let result = lookup_path_at(
            -100,
            b"/usr/lib/test",
            LookupIntent::Getattr,
            lookup_flags::FOLLOW,
            1,
            1,
            &mut walker,
        )
        .unwrap();
        assert!(result.found);
        assert_eq!(result.name_bytes(), b"test");
    }

    #[test]
    fn relative_path_walk() {
        let mut walker = PathWalker::new();
        let result = lookup_path_at(
            -100,
            b"foo/bar",
            LookupIntent::Open(0),
            0,
            1,
            10,
            &mut walker,
        )
        .unwrap();
        assert!(result.found);
        assert_eq!(result.name_bytes(), b"bar");
    }

    #[test]
    fn symlink_loop_detection() {
        let mut walker = PathWalker::new();
        let mut nd = NameiData::new(b"loop", LookupIntent::ReadLink, 0, 1, 1).unwrap();
        for _ in 0..MAX_SYMLINK_FOLLOW {
            walker.follow_symlink(b"loop", &mut nd).unwrap();
        }
        let result = walker.follow_symlink(b"loop", &mut nd);
        assert!(result.is_err());
        assert_eq!(walker.stats().loops_detected, 1);
    }

    #[test]
    fn dotdot_clamped_beneath() {
        let mut walker = PathWalker::new();
        let nd = NameiData::new(b"", LookupIntent::Getattr, lookup_flags::BENEATH, 5, 5).unwrap();
        let parent = walker.resolve_dotdot(5, &nd).unwrap();
        assert_eq!(parent, 5); // cannot escape root
    }
}
