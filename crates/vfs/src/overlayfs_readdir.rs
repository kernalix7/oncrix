// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Overlayfs merged readdir.
//!
//! When reading a directory in an overlay mount, entries from the upper layer
//! are returned first, then entries from the lower layer that are not hidden
//! by upper-layer entries or whiteouts.
//!
//! # Design
//!
//! - [`OverlayDirEntry`] — a merged directory entry with layer provenance
//! - [`OverlayReaddirState`] — per-getdents session state
//! - Upper layer entries shadow lower layer entries of the same name
//! - Whiteout entries in the upper layer hide lower layer entries
//! - Seek/tell support via entry offset cookies
//!
//! # References
//!
//! - Linux `fs/overlayfs/readdir.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum name length.
pub const MAX_NAME: usize = 255;

/// Maximum entries in the merged directory.
pub const MAX_MERGED_ENTRIES: usize = 512;

/// Source layer for entries.
pub const LAYER_UPPER: u8 = 0;
pub const LAYER_LOWER: u8 = 1;

/// File type constants (d_type).
pub const DT_UNKNOWN: u8 = 0;
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_WHT: u8 = 14; // Whiteout marker (internal use).

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single merged directory entry.
#[derive(Clone)]
pub struct OverlayDirEntry {
    /// Entry name.
    pub name: [u8; MAX_NAME],
    /// Name length.
    pub name_len: usize,
    /// Inode number (from the effective layer).
    pub ino: u64,
    /// File type (`DT_*`).
    pub dtype: u8,
    /// Which layer this entry came from.
    pub layer: u8,
    /// Whether this is a whiteout (hides lower entry; not returned to user).
    pub is_whiteout: bool,
    /// Offset cookie for seek support.
    pub offset: u64,
    /// Slot in use.
    pub in_use: bool,
}

impl OverlayDirEntry {
    fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            ino: 0,
            dtype: DT_UNKNOWN,
            layer: LAYER_UPPER,
            is_whiteout: false,
            offset: 0,
            in_use: false,
        }
    }

    fn new(name: &[u8], ino: u64, dtype: u8, layer: u8, offset: u64) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut e = Self::empty();
        e.name[..name.len()].copy_from_slice(name);
        e.name_len = name.len();
        e.ino = ino;
        e.dtype = dtype;
        e.layer = layer;
        e.offset = offset;
        e.in_use = true;
        Ok(e)
    }

    /// Return entry name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// State for a single overlayfs readdir operation.
pub struct OverlayReaddirState {
    /// Directory inode.
    pub dir_ino: u64,
    /// Merged entries (built once, iterated on successive getdents calls).
    entries: [OverlayDirEntry; MAX_MERGED_ENTRIES],
    /// Total merged entries.
    pub total: usize,
    /// Whether upper layer has been fully scanned.
    pub upper_done: bool,
    /// Current position (index into `entries`).
    pub pos: usize,
    /// Whether the merge pass has been completed.
    pub merged: bool,
}

impl OverlayReaddirState {
    /// Create a new readdir state for `dir_ino`.
    pub fn new(dir_ino: u64) -> Self {
        Self {
            dir_ino,
            entries: core::array::from_fn(|_| OverlayDirEntry::empty()),
            total: 0,
            upper_done: false,
            pos: 0,
            merged: false,
        }
    }

    /// Reset state to re-read from the beginning.
    pub fn rewind(&mut self) {
        self.pos = 0;
        self.total = 0;
        self.upper_done = false;
        self.merged = false;
        for e in self.entries.iter_mut() {
            *e = OverlayDirEntry::empty();
        }
    }
}

// ---------------------------------------------------------------------------
// Merge logic
// ---------------------------------------------------------------------------

/// Add entries from the upper layer.
///
/// `entries` is a list of `(name, ino, dtype, is_whiteout)` tuples.
pub fn add_upper_entries(
    state: &mut OverlayReaddirState,
    entries: &[(&[u8], u64, u8, bool)],
) -> Result<()> {
    for (i, &(name, ino, dtype, is_whiteout)) in entries.iter().enumerate() {
        if state.total >= MAX_MERGED_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let mut e = OverlayDirEntry::new(name, ino, dtype, LAYER_UPPER, state.total as u64)?;
        e.is_whiteout = is_whiteout;
        state.entries[state.total] = e;
        state.total += 1;
        let _ = i;
    }
    state.upper_done = true;
    Ok(())
}

/// Add entries from the lower layer, filtering whiteouts and shadows.
///
/// `entries` is a list of `(name, ino, dtype)` tuples from the lower layer.
pub fn add_lower_entries(
    state: &mut OverlayReaddirState,
    entries: &[(&[u8], u64, u8)],
) -> Result<()> {
    for &(name, ino, dtype) in entries {
        if state.total >= MAX_MERGED_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        // Check if this name is shadowed by an upper entry or whiteout.
        let mut shadowed = false;
        for j in 0..state.total {
            if state.entries[j].in_use && state.entries[j].name_bytes() == name {
                shadowed = true;
                break;
            }
        }
        if shadowed {
            continue;
        }
        // Not shadowed: add lower entry.
        let e = OverlayDirEntry::new(name, ino, dtype, LAYER_LOWER, state.total as u64)?;
        state.entries[state.total] = e;
        state.total += 1;
    }
    state.merged = true;
    Ok(())
}

/// Finalise the merge: remove whiteout entries (they must not be returned
/// to userspace).
pub fn finalise_merge(state: &mut OverlayReaddirState) {
    let mut write = 0;
    for read in 0..state.total {
        if !state.entries[read].is_whiteout {
            if write != read {
                state.entries.swap(write, read);
            }
            write += 1;
        }
    }
    // Blank the unused slots.
    for i in write..state.total {
        state.entries[i] = OverlayDirEntry::empty();
    }
    state.total = write;
    // Re-assign offsets sequentially.
    for i in 0..state.total {
        state.entries[i].offset = i as u64;
    }
    state.merged = true;
}

// ---------------------------------------------------------------------------
// Iteration API
// ---------------------------------------------------------------------------

/// Read the next batch of directory entries into `out`.
///
/// Returns the number of entries written. Returns 0 when the directory is
/// exhausted.
pub fn readdir_next(state: &mut OverlayReaddirState, out: &mut [OverlayDirEntry]) -> Result<usize> {
    if !state.merged {
        return Err(Error::InvalidArgument);
    }
    let mut written = 0;
    while state.pos < state.total && written < out.len() {
        out[written] = state.entries[state.pos].clone();
        state.pos += 1;
        written += 1;
    }
    Ok(written)
}

/// Seek the readdir position to the entry at `offset`.
///
/// Sets `pos` to the index of the first entry with `offset >= seek_offset`.
pub fn readdir_seek(state: &mut OverlayReaddirState, seek_offset: u64) {
    for i in 0..state.total {
        if state.entries[i].offset >= seek_offset {
            state.pos = i;
            return;
        }
    }
    state.pos = state.total;
}

/// Return the current position offset (telldir).
pub fn readdir_tell(state: &OverlayReaddirState) -> u64 {
    if state.pos < state.total {
        state.entries[state.pos].offset
    } else {
        state.total as u64
    }
}

/// Return the total number of visible entries in the merged directory.
pub fn merged_entry_count(state: &OverlayReaddirState) -> usize {
    state.total
}

/// Filter a d_type value for whiteout entries.
///
/// Whiteout entries have `DT_WHT` d_type; this should not be returned to
/// userspace.
pub fn filter_dtype(dtype: u8) -> u8 {
    if dtype == DT_WHT { DT_UNKNOWN } else { dtype }
}
