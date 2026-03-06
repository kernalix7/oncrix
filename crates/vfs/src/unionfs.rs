// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Union filesystem (unionfs) — stack-based filesystem union mount.
//!
//! UnionFS presents a unified directory tree composed of multiple *branches*
//! stacked from bottom (read-only) to top (read-write). It is an alternative
//! to overlayfs with simpler copy-up semantics:
//!
//! - [`Branch`] — an individual filesystem branch (path + RO/RW mode)
//! - [`BranchMode`] — read-only or read-write
//! - [`UnionFs`] — the mounted union with ordered branch list
//! - [`lookup`] — find a file, searching top-to-bottom through branches
//! - [`create`] — create a file in the topmost writable branch
//! - [`copy_up`] — copy a file from a lower branch to the topmost RW branch
//! - [`whiteout`] — record a deletion in the topmost branch
//! - [`readdir`] — merge directory entries across all branches
//! - [`BranchEntry`] — resolved file in a specific branch
//!
//! # Branch Order
//!
//! ```text
//! Index 0  → Topmost (writable, checked first for writes)
//! Index 1  → ...
//! Index N  → Bottom-most (oldest, usually read-only base)
//! ```
//!
//! # Whiteout Files
//!
//! A whiteout entry `.wh.<name>` in a higher branch hides all occurrences
//! of `<name>` in lower branches.
//!
//! # References
//!
//! - Linux `fs/unionfs/` (removed from mainline; preserved in staging patches)
//! - UnionFS 2.x FUSE implementation

extern crate alloc;
use alloc::{string::String, vec::Vec};
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of branches in a union mount.
pub const MAX_BRANCHES: usize = 16;

/// Maximum path component length.
pub const MAX_NAME: usize = 255;

/// Whiteout prefix.
pub const WHITEOUT_PREFIX: &[u8] = b".wh.";

/// Maximum entries returned by `readdir`.
const MAX_DIR_ENTRIES: usize = 1024;

// ── Branch Mode ───────────────────────────────────────────────────────────────

/// Whether a branch allows writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchMode {
    /// Read-only branch — never written.
    ReadOnly,
    /// Read-write branch — receives copies and new files.
    ReadWrite,
}

// ── Branch ────────────────────────────────────────────────────────────────────

/// An individual filesystem branch in a union mount.
#[derive(Debug, Clone)]
pub struct Branch {
    /// Branch index (0 = topmost).
    pub index: usize,
    /// Mount path of this branch (UTF-8).
    pub path: String,
    /// Access mode.
    pub mode: BranchMode,
    /// Number of files visible in this branch.
    pub file_count: u64,
}

impl Branch {
    /// Create a new branch descriptor.
    pub fn new(index: usize, path: String, mode: BranchMode) -> Self {
        Self {
            index,
            path,
            mode,
            file_count: 0,
        }
    }

    /// Return `true` if this branch accepts writes.
    pub fn is_writable(&self) -> bool {
        self.mode == BranchMode::ReadWrite
    }
}

// ── Directory Entry ───────────────────────────────────────────────────────────

/// A directory entry visible in the union view.
#[derive(Debug, Clone)]
pub struct UnionDirEntry {
    /// File name.
    pub name: [u8; MAX_NAME],
    /// Actual name length.
    pub name_len: usize,
    /// Branch index where the file was found.
    pub branch: usize,
    /// `true` if this entry is a directory.
    pub is_dir: bool,
    /// `true` if this entry has been whited-out by a higher branch.
    pub whiteout: bool,
}

impl UnionDirEntry {
    /// Return the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return `true` if this entry's name is a whiteout marker.
    pub fn is_whiteout_entry(&self) -> bool {
        self.name_len > WHITEOUT_PREFIX.len()
            && self.name[..WHITEOUT_PREFIX.len()] == *WHITEOUT_PREFIX
    }
}

// ── Resolved File ─────────────────────────────────────────────────────────────

/// A file resolved from the union view — points to a specific branch.
#[derive(Debug, Clone, Copy)]
pub struct BranchEntry {
    /// Branch index where the file lives.
    pub branch_index: usize,
    /// File size in the branch.
    pub file_size: u64,
    /// `true` if the entry is a directory.
    pub is_dir: bool,
}

// ── Union Filesystem ──────────────────────────────────────────────────────────

/// A mounted union filesystem composed of multiple branches.
pub struct UnionFs {
    /// Branches, ordered topmost-first.
    branches: Vec<Branch>,
    /// Number of active branches.
    pub branch_count: usize,
}

impl UnionFs {
    /// Create a new empty union mount.
    pub fn new() -> Self {
        Self {
            branches: Vec::new(),
            branch_count: 0,
        }
    }

    /// Add a branch to the bottom of the stack.
    pub fn add_branch(&mut self, path: String, mode: BranchMode) -> Result<usize> {
        if self.branch_count >= MAX_BRANCHES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.branch_count;
        self.branches.push(Branch::new(idx, path, mode));
        self.branch_count += 1;
        Ok(idx)
    }

    /// Return `true` if `name` is a whiteout filename for `target`.
    fn is_whiteout(name: &[u8], target: &[u8]) -> bool {
        if name.len() != WHITEOUT_PREFIX.len() + target.len() {
            return false;
        }
        if &name[..WHITEOUT_PREFIX.len()] != WHITEOUT_PREFIX {
            return false;
        }
        &name[WHITEOUT_PREFIX.len()..] == target
    }

    /// Lookup a file by name in the union tree.
    ///
    /// Searches branches top-to-bottom; returns the first match that is not
    /// whited-out by a higher branch. `file_info_fn` is called per branch to
    /// check file existence and metadata.
    pub fn lookup(
        &self,
        name: &[u8],
        file_info_fn: &dyn Fn(usize, &[u8]) -> Option<BranchEntry>,
        whiteout_exists_fn: &dyn Fn(usize, &[u8]) -> bool,
    ) -> Option<BranchEntry> {
        for branch in &self.branches {
            // Check for whiteout in this branch.
            if whiteout_exists_fn(branch.index, name) {
                return None; // whited-out
            }
            if let Some(entry) = file_info_fn(branch.index, name) {
                return Some(entry);
            }
        }
        None
    }

    /// Create a new file in the topmost writable branch.
    ///
    /// Returns the branch index where the file was created.
    pub fn create(&self, name: &[u8], is_dir: bool) -> Result<usize> {
        for branch in &self.branches {
            if branch.is_writable() {
                // Validate the name (no whiteout prefix).
                if name.starts_with(WHITEOUT_PREFIX) {
                    return Err(Error::InvalidArgument);
                }
                let _ = (name, is_dir); // actual creation deferred to VFS
                return Ok(branch.index);
            }
        }
        Err(Error::PermissionDenied)
    }

    /// Copy a file from `src_branch` to the topmost writable branch.
    ///
    /// `copy_fn(src, dst, name)` performs the actual data copy.
    /// Returns the destination branch index.
    pub fn copy_up(
        &self,
        src_branch: usize,
        name: &[u8],
        copy_fn: &mut dyn FnMut(usize, usize, &[u8]) -> Result<()>,
    ) -> Result<usize> {
        let dst_branch = self
            .branches
            .iter()
            .find(|b| b.is_writable())
            .map(|b| b.index)
            .ok_or(Error::PermissionDenied)?;
        if dst_branch == src_branch {
            return Ok(dst_branch); // already in top branch
        }
        copy_fn(src_branch, dst_branch, name)?;
        Ok(dst_branch)
    }

    /// Record a deletion by creating a whiteout entry in the topmost writable branch.
    ///
    /// `create_whiteout_fn(branch, whiteout_name)` must create the `.wh.<name>` file.
    pub fn whiteout(
        &self,
        name: &[u8],
        create_whiteout_fn: &mut dyn FnMut(usize, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let dst_branch = self
            .branches
            .iter()
            .find(|b| b.is_writable())
            .map(|b| b.index)
            .ok_or(Error::PermissionDenied)?;
        // Construct whiteout name: ".wh." + name.
        let wh_len = WHITEOUT_PREFIX.len() + name.len();
        if wh_len > MAX_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut wh_name = [0u8; MAX_NAME];
        wh_name[..WHITEOUT_PREFIX.len()].copy_from_slice(WHITEOUT_PREFIX);
        wh_name[WHITEOUT_PREFIX.len()..wh_len].copy_from_slice(name);
        create_whiteout_fn(dst_branch, &wh_name[..wh_len])
    }

    /// Merge directory entries from all branches.
    ///
    /// `list_dir_fn(branch, entries, max)` fills in raw entries for the branch.
    /// Whited-out entries and duplicates (already seen in higher branches) are
    /// suppressed. Returns the number of merged entries written into `out`.
    pub fn readdir(
        &self,
        list_dir_fn: &dyn Fn(usize, &mut Vec<UnionDirEntry>),
        out: &mut [UnionDirEntry; MAX_DIR_ENTRIES],
    ) -> Result<usize> {
        // Collect all raw entries per branch.
        let mut seen: Vec<[u8; MAX_NAME]> = Vec::new();
        let mut whiteouts: Vec<[u8; MAX_NAME]> = Vec::new();
        let mut result_count = 0usize;

        for branch in &self.branches {
            let mut branch_entries: Vec<UnionDirEntry> = Vec::new();
            list_dir_fn(branch.index, &mut branch_entries);
            for entry in branch_entries {
                // Collect whiteouts from this branch.
                if entry.is_whiteout_entry() {
                    let mut wh_name = [0u8; MAX_NAME];
                    let wh_len = entry.name_len.saturating_sub(WHITEOUT_PREFIX.len());
                    if wh_len > 0 {
                        let src = &entry.name[WHITEOUT_PREFIX.len()..entry.name_len];
                        wh_name[..wh_len].copy_from_slice(src);
                    }
                    whiteouts.push(wh_name);
                    continue;
                }
                // Check if this name is whited-out.
                let is_wo = whiteouts.iter().any(|wh| {
                    Self::is_whiteout(
                        entry.name_bytes(),
                        &wh[..entry.name_len.saturating_sub(WHITEOUT_PREFIX.len())],
                    ) || wh[..entry.name_len] == entry.name[..entry.name_len]
                });
                if is_wo {
                    continue;
                }
                // Check for duplicates (higher branch already added this name).
                let already_seen = seen
                    .iter()
                    .any(|s| s[..entry.name_len] == entry.name[..entry.name_len]);
                if already_seen {
                    continue;
                }
                if result_count >= MAX_DIR_ENTRIES {
                    break;
                }
                let mut seen_name = [0u8; MAX_NAME];
                seen_name[..entry.name_len].copy_from_slice(&entry.name[..entry.name_len]);
                seen.push(seen_name);
                out[result_count] = entry;
                result_count += 1;
            }
        }
        Ok(result_count)
    }

    /// Return the topmost writable branch index, or `None`.
    pub fn top_writable(&self) -> Option<usize> {
        self.branches
            .iter()
            .find(|b| b.is_writable())
            .map(|b| b.index)
    }

    /// Return an iterator over branches.
    pub fn branches(&self) -> impl Iterator<Item = &Branch> {
        self.branches.iter()
    }
}

impl Default for UnionFs {
    fn default() -> Self {
        Self::new()
    }
}
