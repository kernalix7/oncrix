// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OverlayFS directory merge operations.
//!
//! Implements merged directory reading for overlayfs, combining entries from
//! upper and lower layers while handling whiteout entries and opaque directories.
//!
//! # Algorithm
//!
//! When `readdir()` is called on a merged directory:
//! 1. Collect all entries from the upper layer.
//! 2. For each lower-layer entry not present in upper (and not whiteout'd), add it.
//! 3. Filter out any upper-layer whiteout entries.
//! 4. For opaque directories, stop at the upper layer only.
//!
//! # Reference
//!
//! Linux `fs/overlayfs/readdir.c`, `fs/overlayfs/dir.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum directory entries returned from a single readdir.
const MAX_MERGE_ENTRIES: usize = 256;

/// Maximum file name length.
const MAX_NAME_LEN: usize = 255;

/// Maximum number of layers in an overlay stack.
const MAX_LAYERS: usize = 8;

/// Whiteout character device major:minor (0:0) — used internally.
const WHITEOUT_DEV_MAJOR: u32 = 0;
const WHITEOUT_DEV_MINOR: u32 = 0;

// ---------------------------------------------------------------------------
// Layer index
// ---------------------------------------------------------------------------

/// Source layer for a merged directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Entry comes from the upper (writable) layer.
    Upper,
    /// Entry comes from a lower (read-only) layer at the given index.
    Lower(usize),
}

// ---------------------------------------------------------------------------
// Merge entry
// ---------------------------------------------------------------------------

/// A single entry in a merged directory listing.
#[derive(Debug, Clone)]
pub struct MergeEntry {
    /// File name (UTF-8, null-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Valid bytes in `name`.
    pub name_len: usize,
    /// Inode number (from the authoritative layer).
    pub ino: u64,
    /// Layer this entry originates from.
    pub layer: Layer,
    /// Whether this entry is a whiteout (marks deletion).
    pub is_whiteout: bool,
    /// Whether this is a directory entry.
    pub is_dir: bool,
    /// File mode.
    pub mode: u32,
}

impl MergeEntry {
    /// Creates a new merge entry.
    pub fn new(name: &[u8], ino: u64, layer: Layer, is_dir: bool, mode: u32) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_NAME_LEN];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            name: buf,
            name_len: name.len(),
            ino,
            layer,
            is_whiteout: false,
            is_dir,
            mode,
        })
    }

    /// Creates a whiteout entry.
    pub fn whiteout(name: &[u8], layer: Layer) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_NAME_LEN];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            name: buf,
            name_len: name.len(),
            ino: 0,
            layer,
            is_whiteout: true,
            is_dir: false,
            mode: 0,
        })
    }

    /// Returns the entry name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns whether this entry has the given name.
    pub fn has_name(&self, other: &[u8]) -> bool {
        self.name_bytes() == other
    }
}

// ---------------------------------------------------------------------------
// Input layer entries
// ---------------------------------------------------------------------------

/// A raw directory listing from a single layer.
#[derive(Debug)]
pub struct LayerEntries {
    /// The layer index.
    pub layer: Layer,
    /// Whether this directory is opaque (ignore lower layers).
    pub is_opaque: bool,
    /// Directory entries.
    pub entries: [Option<MergeEntry>; MAX_MERGE_ENTRIES],
    /// Number of valid entries.
    pub count: usize,
}

impl LayerEntries {
    /// Creates an empty layer entry set for the upper layer.
    pub fn upper() -> Self {
        Self {
            layer: Layer::Upper,
            is_opaque: false,
            entries: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Creates an empty layer entry set for a lower layer.
    pub fn lower(index: usize) -> Self {
        Self {
            layer: Layer::Lower(index),
            is_opaque: false,
            entries: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Adds an entry to this layer.
    pub fn add(&mut self, entry: MergeEntry) -> Result<()> {
        if self.count >= MAX_MERGE_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Returns entries as a slice of valid entries.
    pub fn iter(&self) -> impl Iterator<Item = &MergeEntry> {
        self.entries[..self.count].iter().flatten()
    }
}

// ---------------------------------------------------------------------------
// Merged directory context
// ---------------------------------------------------------------------------

/// Result of merging entries from multiple layers.
pub struct MergedDir {
    /// Final merged entries (no whiteouts, no duplicates).
    pub entries: [Option<MergeEntry>; MAX_MERGE_ENTRIES],
    /// Number of valid merged entries.
    pub count: usize,
    /// Whether the directory was opaque (lower layers suppressed).
    pub was_opaque: bool,
}

impl MergedDir {
    /// Creates an empty merged directory.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
            was_opaque: false,
        }
    }

    /// Adds a final entry to the merged result.
    fn add(&mut self, entry: MergeEntry) -> Result<()> {
        if self.count >= MAX_MERGE_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Returns whether a name already exists in the merged result.
    fn has_name(&self, name: &[u8]) -> bool {
        self.entries[..self.count]
            .iter()
            .flatten()
            .any(|e| e.has_name(name))
    }

    /// Returns an iterator over the merged entries.
    pub fn iter(&self) -> impl Iterator<Item = &MergeEntry> {
        self.entries[..self.count].iter().flatten()
    }
}

impl Default for MergedDir {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Merge algorithm
// ---------------------------------------------------------------------------

/// Merges a readdir from upper and lower layers.
///
/// Algorithm:
/// 1. Collect whiteout names from upper layer.
/// 2. Add non-whiteout upper entries to result.
/// 3. For each lower entry not in whiteout set and not in result, add it.
/// 4. If any layer is opaque, skip remaining lower layers.
pub fn merge_readdir(
    upper: &LayerEntries,
    lowers: &[LayerEntries; MAX_LAYERS],
    lower_count: usize,
) -> Result<MergedDir> {
    if lower_count > MAX_LAYERS {
        return Err(Error::InvalidArgument);
    }

    let mut result = MergedDir::new();

    // Step 1: collect whiteout names from upper.
    // We track whiteout names inline by checking is_whiteout.

    // Step 2: add non-whiteout upper entries.
    for entry in upper.iter() {
        if !entry.is_whiteout {
            result.add(entry.clone())?;
        }
    }

    // If upper layer is opaque, stop here.
    if upper.is_opaque {
        result.was_opaque = true;
        return Ok(result);
    }

    // Step 3: add lower entries not whiteout'd and not already present.
    for i in 0..lower_count {
        let layer = &lowers[i];

        for entry in layer.iter() {
            if entry.is_whiteout {
                continue;
            }
            // Skip if upper has a whiteout for this name.
            let upper_has_whiteout = upper
                .iter()
                .any(|e| e.is_whiteout && e.has_name(entry.name_bytes()));
            if upper_has_whiteout {
                continue;
            }
            // Skip if already in result.
            if result.has_name(entry.name_bytes()) {
                continue;
            }
            result.add(entry.clone())?;
        }

        // Opaque lower: skip deeper layers.
        if layer.is_opaque {
            break;
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Opaque directory check
// ---------------------------------------------------------------------------

/// Returns whether a directory entry has the opaque xattr set.
///
/// In overlayfs, a directory with `trusted.overlay.opaque=y` suppresses
/// any lower-layer entries with the same name.
pub fn is_opaque_dir(xattr_opaque: bool) -> bool {
    xattr_opaque
}

/// Checks whether a given entry name corresponds to a whiteout.
///
/// Whiteouts are character devices with dev (0, 0), or entries with the
/// name prefix `.wh.` in older implementations.
pub fn is_whiteout_entry(name: &[u8], is_char_dev: bool, major: u32, minor: u32) -> bool {
    if is_char_dev && major == WHITEOUT_DEV_MAJOR && minor == WHITEOUT_DEV_MINOR {
        return true;
    }
    // Check `.wh.` prefix.
    name.starts_with(b".wh.")
}

/// Returns the real name behind a `.wh.` whiteout entry.
///
/// For example, `.wh.foo` → `foo`.
pub fn whiteout_name<'a>(name: &'a [u8]) -> Option<&'a [u8]> {
    name.strip_prefix(b".wh.")
}

// ---------------------------------------------------------------------------
// Upper layer entry management
// ---------------------------------------------------------------------------

/// Creates a whiteout entry in the upper layer for the given name.
///
/// This is called when a lower-layer file is deleted via the upper layer.
pub fn create_whiteout(upper: &mut LayerEntries, name: &[u8]) -> Result<()> {
    let entry = MergeEntry::whiteout(name, Layer::Upper)?;
    upper.add(entry)
}

/// Removes a whiteout from the upper layer (used when re-creating a file).
pub fn remove_whiteout(upper: &mut LayerEntries, name: &[u8]) -> bool {
    for i in 0..upper.count {
        if let Some(entry) = &upper.entries[i] {
            if entry.is_whiteout && entry.has_name(name) {
                upper.entries[i] = None;
                // Compact: shift remaining entries down.
                for j in i..upper.count.saturating_sub(1) {
                    upper.entries[j] = upper.entries[j + 1].take();
                }
                upper.count = upper.count.saturating_sub(1);
                return true;
            }
        }
    }
    false
}
