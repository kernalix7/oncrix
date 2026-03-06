// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Symlink operations — create, read, and resolve symbolic links.
//!
//! Implements POSIX `symlink(2)` and `readlink(2)` semantics, including
//! inline target storage for short symlinks and indirect storage for long ones.

use oncrix_lib::{Error, Result};

/// Maximum length of a symlink target path (POSIX PATH_MAX).
pub const SYMLINK_MAX_LEN: usize = 4096;

/// Length threshold below which the target is stored inline in the inode.
pub const INLINE_SYMLINK_LEN: usize = 60;

/// Maximum symlinks followed in one resolution chain.
pub const MAX_SYMLINK_CHAIN: usize = 40;

/// Storage representation for a symlink target.
#[derive(Debug, Clone, Copy)]
pub enum SymlinkTarget {
    /// Target fits inside the inode itself.
    Inline {
        data: [u8; INLINE_SYMLINK_LEN],
        len: u8,
    },
    /// Target is stored in a data block; only the length is cached here.
    Indirect {
        /// Block address / data buffer index.
        block: u64,
        len: u16,
    },
}

impl SymlinkTarget {
    /// Create a new inline target from a byte slice.
    pub fn new_inline(target: &[u8]) -> Result<Self> {
        if target.len() > INLINE_SYMLINK_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut data = [0u8; INLINE_SYMLINK_LEN];
        data[..target.len()].copy_from_slice(target);
        Ok(Self::Inline {
            data,
            len: target.len() as u8,
        })
    }

    /// Create an indirect target reference.
    pub const fn new_indirect(block: u64, len: u16) -> Self {
        Self::Indirect { block, len }
    }

    /// Return the length of the symlink target in bytes.
    pub const fn len(&self) -> usize {
        match self {
            Self::Inline { len, .. } => *len as usize,
            Self::Indirect { len, .. } => *len as usize,
        }
    }

    /// Return `true` if the target is empty.
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// For inline targets, return a byte slice of the target.
    /// Returns `None` for indirect targets (need block read).
    pub fn inline_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Inline { data, len } => Some(&data[..*len as usize]),
            Self::Indirect { .. } => None,
        }
    }
}

/// An entry in the symlink resolution cache (a simple fast-path table).
#[derive(Clone, Copy)]
pub struct SymlinkCacheEntry {
    /// Source inode (the symlink inode).
    pub src_ino: u64,
    /// Source superblock.
    pub src_sb_id: u64,
    /// Inline copy of the target (up to INLINE_SYMLINK_LEN bytes).
    pub target: [u8; INLINE_SYMLINK_LEN],
    /// Actual length of the target.
    pub target_len: u8,
    /// Generation counter for cache invalidation.
    pub generation: u32,
    /// Whether this entry is valid.
    pub valid: bool,
}

impl SymlinkCacheEntry {
    const fn empty() -> Self {
        Self {
            src_ino: 0,
            src_sb_id: 0,
            target: [0u8; INLINE_SYMLINK_LEN],
            target_len: 0,
            generation: 0,
            valid: false,
        }
    }
}

/// Maximum number of entries in the symlink cache.
pub const SYMLINK_CACHE_SIZE: usize = 64;

/// A cache for recently resolved short symlink targets.
pub struct SymlinkCache {
    entries: [SymlinkCacheEntry; SYMLINK_CACHE_SIZE],
    hits: u64,
    misses: u64,
}

impl SymlinkCache {
    /// Create an empty symlink cache.
    pub fn new() -> Self {
        Self {
            entries: [const { SymlinkCacheEntry::empty() }; SYMLINK_CACHE_SIZE],
            hits: 0,
            misses: 0,
        }
    }

    fn hash(sb_id: u64, ino: u64) -> usize {
        ((sb_id ^ ino.wrapping_mul(0x9e3779b97f4a7c15)) as usize) % SYMLINK_CACHE_SIZE
    }

    /// Look up a symlink target in the cache.
    ///
    /// Returns the target slice if found (and still valid).
    pub fn lookup<'a>(
        &'a mut self,
        sb_id: u64,
        ino: u64,
        generation: u32,
        out: &mut [u8],
    ) -> Option<usize> {
        let idx = Self::hash(sb_id, ino);
        let entry = &self.entries[idx];
        if entry.valid
            && entry.src_sb_id == sb_id
            && entry.src_ino == ino
            && entry.generation == generation
        {
            let len = entry.target_len as usize;
            let to_copy = len.min(out.len());
            out[..to_copy].copy_from_slice(&entry.target[..to_copy]);
            self.hits += 1;
            return Some(len);
        }
        self.misses += 1;
        None
    }

    /// Insert a symlink target into the cache.
    pub fn insert(&mut self, sb_id: u64, ino: u64, generation: u32, target: &[u8]) {
        if target.len() > INLINE_SYMLINK_LEN {
            return; // Only cache short symlinks.
        }
        let idx = Self::hash(sb_id, ino);
        let entry = &mut self.entries[idx];
        entry.src_sb_id = sb_id;
        entry.src_ino = ino;
        entry.generation = generation;
        entry.target[..target.len()].copy_from_slice(target);
        entry.target_len = target.len() as u8;
        entry.valid = true;
    }

    /// Invalidate the cache entry for a given inode.
    pub fn invalidate(&mut self, sb_id: u64, ino: u64) {
        let idx = Self::hash(sb_id, ino);
        if self.entries[idx].src_sb_id == sb_id && self.entries[idx].src_ino == ino {
            self.entries[idx].valid = false;
        }
    }

    /// Return cache statistics `(hits, misses)`.
    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }
}

impl Default for SymlinkCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate a symlink target string.
///
/// Returns `Err(InvalidArgument)` if the target is empty, too long, or
/// contains embedded NUL bytes.
pub fn validate_symlink_target(target: &[u8]) -> Result<()> {
    if target.is_empty() {
        return Err(Error::InvalidArgument);
    }
    if target.len() >= SYMLINK_MAX_LEN {
        return Err(Error::InvalidArgument);
    }
    if target.iter().any(|&b| b == 0) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Check whether a symlink target is absolute.
pub const fn is_absolute_target(target: &[u8]) -> bool {
    matches!(target.first(), Some(&b'/'))
}

/// Concatenate the directory path of a symlink source with a relative target.
///
/// `dir_path` — directory containing the symlink (e.g., b"/foo/bar").
/// `target`   — relative symlink target (e.g., b"../baz").
/// `out`      — output buffer for the resolved path.
///
/// Returns the length written to `out`, or `Err(InvalidArgument)` if the
/// combined length exceeds `out.len()` or `SYMLINK_MAX_LEN`.
pub fn join_symlink_path(dir_path: &[u8], target: &[u8], out: &mut [u8]) -> Result<usize> {
    if is_absolute_target(target) {
        // Absolute target — ignore the directory.
        if target.len() > out.len() {
            return Err(Error::InvalidArgument);
        }
        out[..target.len()].copy_from_slice(target);
        return Ok(target.len());
    }

    // Strip trailing '/' from dir_path.
    let dir_end = dir_path
        .iter()
        .rposition(|&b| b != b'/')
        .map(|i| i + 1)
        .unwrap_or(0);

    // Find the last '/' to get the containing directory.
    let parent_end = dir_path[..dir_end]
        .iter()
        .rposition(|&b| b == b'/')
        .map(|i| i + 1)
        .unwrap_or(0);

    let total = parent_end + target.len();
    if total > out.len() || total > SYMLINK_MAX_LEN {
        return Err(Error::InvalidArgument);
    }
    out[..parent_end].copy_from_slice(&dir_path[..parent_end]);
    out[parent_end..total].copy_from_slice(target);
    Ok(total)
}
