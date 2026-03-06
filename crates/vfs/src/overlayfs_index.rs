// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Overlayfs index directory.
//!
//! The overlayfs index directory (`<upper>/.overlay/index/`) is used to track
//! hardlinks and provide stable NFS file handles. Each entry maps an origin
//! file handle to its upper layer counterpart.
//!
//! # Design
//!
//! - Each indexed inode has an [`IndexEntry`] keyed by origin file handle.
//! - `lookup_index` finds an existing index entry.
//! - `create_index` creates a new entry on copy-up.
//! - `remove_index` removes an entry on unlink.
//! - `verify_index_entry` checks that the entry still points to a valid inode.
//! - `cleanup_stale` purges entries that no longer have a backing file.
//!
//! # References
//!
//! - Linux `fs/overlayfs/namei.c`, `fs/overlayfs/index.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of index entries.
pub const MAX_INDEX_ENTRIES: usize = 512;

/// Maximum size of an origin file handle (opaque bytes).
pub const MAX_FH_LEN: usize = 128;

/// Maximum name length for index entry names.
pub const MAX_INDEX_NAME: usize = 255;

/// Entry type: regular file.
pub const INDEX_FTYPE_REG: u8 = 0;
/// Entry type: directory.
pub const INDEX_FTYPE_DIR: u8 = 1;
/// Entry type: symlink.
pub const INDEX_FTYPE_LNK: u8 = 2;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// An index directory entry.
#[derive(Clone)]
pub struct IndexEntry {
    /// Origin file handle (opaque bytes from the lower/origin filesystem).
    pub origin_fh: [u8; MAX_FH_LEN],
    /// Length of the origin file handle.
    pub origin_fh_len: usize,
    /// File type of the indexed inode.
    pub ftype: u8,
    /// Upper layer inode number.
    pub upper_ino: u64,
    /// Entry name in the index directory (hex of origin fh hash).
    pub name: [u8; MAX_INDEX_NAME],
    /// Length of `name`.
    pub name_len: usize,
    /// Link count of the upper inode at index time.
    pub nlink: u32,
    /// Whether this slot is occupied.
    in_use: bool,
    /// Whether this entry is verified.
    pub verified: bool,
}

impl IndexEntry {
    fn empty() -> Self {
        Self {
            origin_fh: [0u8; MAX_FH_LEN],
            origin_fh_len: 0,
            ftype: INDEX_FTYPE_REG,
            upper_ino: 0,
            name: [0u8; MAX_INDEX_NAME],
            name_len: 0,
            nlink: 0,
            in_use: false,
            verified: false,
        }
    }
}

/// The overlayfs index directory state.
pub struct IndexDir {
    entries: [IndexEntry; MAX_INDEX_ENTRIES],
    count: usize,
}

impl IndexDir {
    /// Create an empty index directory.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| IndexEntry::empty()),
            count: 0,
        }
    }

    fn find_by_fh(&self, fh: &[u8]) -> Option<usize> {
        for i in 0..MAX_INDEX_ENTRIES {
            if !self.entries[i].in_use {
                continue;
            }
            let len = self.entries[i].origin_fh_len;
            if len == fh.len() && self.entries[i].origin_fh[..len] == *fh {
                return Some(i);
            }
        }
        None
    }

    fn find_by_upper_ino(&self, upper_ino: u64) -> Option<usize> {
        for i in 0..MAX_INDEX_ENTRIES {
            if self.entries[i].in_use && self.entries[i].upper_ino == upper_ino {
                return Some(i);
            }
        }
        None
    }

    fn free_slot(&self) -> Option<usize> {
        for i in 0..MAX_INDEX_ENTRIES {
            if !self.entries[i].in_use {
                return Some(i);
            }
        }
        None
    }
}

impl Default for IndexDir {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Index name helpers
// ---------------------------------------------------------------------------

/// Compute a simple hex name for an origin file handle.
///
/// Writes up to `MAX_INDEX_NAME` hex characters into `out`. Returns length.
fn fh_to_name(fh: &[u8], out: &mut [u8; MAX_INDEX_NAME]) -> usize {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut len = 0;
    for &b in fh.iter().take((MAX_INDEX_NAME / 2).min(fh.len())) {
        if len + 2 > MAX_INDEX_NAME {
            break;
        }
        out[len] = HEX[(b >> 4) as usize];
        out[len + 1] = HEX[(b & 0xf) as usize];
        len += 2;
    }
    len
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Look up an index entry by origin file handle.
pub fn lookup_index<'a>(index: &'a IndexDir, origin_fh: &[u8]) -> Option<&'a IndexEntry> {
    let slot = index.find_by_fh(origin_fh)?;
    Some(&index.entries[slot])
}

/// Create a new index entry for an upper layer inode.
///
/// `origin_fh` is the lower/origin file handle. `upper_ino` is the inode
/// number in the upper layer. Returns `Err(AlreadyExists)` if already indexed.
pub fn create_index(
    index: &mut IndexDir,
    origin_fh: &[u8],
    upper_ino: u64,
    ftype: u8,
    nlink: u32,
) -> Result<()> {
    if origin_fh.is_empty() || origin_fh.len() > MAX_FH_LEN {
        return Err(Error::InvalidArgument);
    }
    if index.find_by_fh(origin_fh).is_some() {
        return Err(Error::AlreadyExists);
    }
    let slot = index.free_slot().ok_or(Error::OutOfMemory)?;

    let mut entry = IndexEntry::empty();
    entry.origin_fh_len = origin_fh.len();
    entry.origin_fh[..origin_fh.len()].copy_from_slice(origin_fh);
    entry.upper_ino = upper_ino;
    entry.ftype = ftype;
    entry.nlink = nlink;
    entry.in_use = true;
    entry.name_len = fh_to_name(origin_fh, &mut entry.name);

    index.entries[slot] = entry;
    index.count += 1;
    Ok(())
}

/// Remove an index entry identified by its origin file handle.
pub fn remove_index(index: &mut IndexDir, origin_fh: &[u8]) -> Result<()> {
    let slot = index.find_by_fh(origin_fh).ok_or(Error::NotFound)?;
    index.entries[slot] = IndexEntry::empty();
    index.count = index.count.saturating_sub(1);
    Ok(())
}

/// Remove an index entry by upper inode number.
pub fn remove_index_by_ino(index: &mut IndexDir, upper_ino: u64) -> Result<()> {
    let slot = index.find_by_upper_ino(upper_ino).ok_or(Error::NotFound)?;
    index.entries[slot] = IndexEntry::empty();
    index.count = index.count.saturating_sub(1);
    Ok(())
}

/// Verify an index entry.
///
/// Marks the entry as verified (i.e. the upper inode is reachable and
/// the nlink count matches). Returns `Err(NotFound)` if no entry found.
pub fn verify_index_entry(index: &mut IndexDir, origin_fh: &[u8], nlink: u32) -> Result<()> {
    let slot = index.find_by_fh(origin_fh).ok_or(Error::NotFound)?;
    if index.entries[slot].nlink != nlink {
        return Err(Error::InvalidArgument);
    }
    index.entries[slot].verified = true;
    Ok(())
}

/// Cleanup stale index entries.
///
/// Calls `is_valid` for each entry. Entries for which `is_valid` returns
/// `false` are removed. Returns the number removed.
pub fn cleanup_stale<F>(index: &mut IndexDir, is_valid: F) -> usize
where
    F: Fn(u64) -> bool,
{
    let mut removed = 0;
    for i in 0..MAX_INDEX_ENTRIES {
        if !index.entries[i].in_use {
            continue;
        }
        if !is_valid(index.entries[i].upper_ino) {
            index.entries[i] = IndexEntry::empty();
            index.count = index.count.saturating_sub(1);
            removed += 1;
        }
    }
    removed
}

/// Collect all index entry names into `out`.
///
/// Returns the number of entries written.
pub fn readdir_index(index: &IndexDir, out: &mut [([u8; MAX_INDEX_NAME], usize, u64)]) -> usize {
    let mut written = 0;
    for i in 0..MAX_INDEX_ENTRIES {
        if written >= out.len() {
            break;
        }
        if index.entries[i].in_use {
            out[written] = (
                index.entries[i].name,
                index.entries[i].name_len,
                index.entries[i].upper_ino,
            );
            written += 1;
        }
    }
    written
}

/// Return the number of active index entries.
pub fn index_count(index: &IndexDir) -> usize {
    index.count
}

/// Look up an index entry by upper inode number.
pub fn lookup_by_upper_ino(index: &IndexDir, upper_ino: u64) -> Option<&IndexEntry> {
    let slot = index.find_by_upper_ino(upper_ino)?;
    Some(&index.entries[slot])
}
