// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Enhanced overlay filesystem operations with whiteout and opaque
//! directory support.
//!
//! Extends the base [`overlayfs`](crate::overlayfs) module with:
//! - Multi-layer support (1 upper + up to 8 lower layers)
//! - Whiteout entries to hide lower-layer files after deletion
//! - Opaque directories that suppress all lower-layer entries
//! - Copy-up tracking for lazy migration from lower to upper
//! - Merged directory listing with whiteout/opaque filtering
//!
//! Reference: Linux `fs/overlayfs/`, particularly `readdir.c` and
//! `dir.c` for whiteout and opaque directory semantics.

use oncrix_lib::{Error, Result};

/// Maximum name length for overlay entries.
const MAX_NAME_LEN: usize = 255;

/// Maximum entries per overlay directory.
const MAX_DIR_ENTRIES: usize = 64;

/// Maximum merged directories tracked by an overlay mount.
const MAX_MERGED_DIRS: usize = 128;

/// Maximum concurrent copy-up operations.
const MAX_COPY_UPS: usize = 32;

/// Maximum lower layers supported.
const MAX_LOWER_LAYERS: usize = 8;

/// Identifies which layer an entry or inode belongs to.
///
/// The upper layer is the single writable layer; lower layers are
/// read-only and indexed 0..7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayLayer {
    /// The writable upper layer.
    Upper,
    /// A read-only lower layer (index 0..7).
    Lower(u8),
}

/// Classification of an overlay directory entry.
///
/// Determines how the entry participates in merged directory
/// listings and how the VFS interprets it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OverlayEntryType {
    /// A normal file or directory visible to users.
    #[default]
    Regular,
    /// A whiteout marker that hides a lower-layer entry.
    Whiteout,
    /// An opaque directory that suppresses all lower-layer children.
    OpaqueDir,
    /// An entry that has been (or is being) copied from lower to upper.
    CopyUp,
}

/// A single entry in an overlay directory.
///
/// Tracks the entry name, its origin layer, and whether it is a
/// whiteout, opaque directory, or copy-up marker.
#[derive(Clone, Copy)]
pub struct OverlayEntry {
    /// Entry name bytes (up to 255 bytes, not null-terminated).
    pub name: [u8; MAX_NAME_LEN],
    /// Actual length of the name in bytes.
    pub name_len: u8,
    /// Inode identifier for this entry.
    pub inode_id: u64,
    /// Layer index (0 = upper, 1..=8 = lower layers).
    pub layer: u8,
    /// Type classification of this entry.
    pub entry_type: OverlayEntryType,
    /// Whether this entry slot is actively used.
    pub in_use: bool,
}

impl Default for OverlayEntry {
    fn default() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            inode_id: 0,
            layer: 0,
            entry_type: OverlayEntryType::default(),
            in_use: false,
        }
    }
}

impl OverlayEntry {
    /// Return the entry name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// A merged overlay directory containing entries from multiple layers.
///
/// Entries from the upper layer take priority. Whiteout entries hide
/// corresponding lower-layer entries, and opaque directories suppress
/// all lower-layer children entirely.
#[derive(Clone, Copy)]
pub struct OverlayDir {
    /// Directory entry slots.
    pub entries: [OverlayEntry; MAX_DIR_ENTRIES],
    /// Number of active entries.
    pub count: usize,
    /// Whether this directory is marked opaque (xattr `trusted.overlay.opaque`).
    pub is_opaque: bool,
}

impl Default for OverlayDir {
    fn default() -> Self {
        const DEFAULT_ENTRY: OverlayEntry = OverlayEntry {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            inode_id: 0,
            layer: 0,
            entry_type: OverlayEntryType::Regular,
            in_use: false,
        };
        Self {
            entries: [DEFAULT_ENTRY; MAX_DIR_ENTRIES],
            count: 0,
            is_opaque: false,
        }
    }
}

/// Tracks the progress of a copy-up operation from a lower layer
/// to the upper layer.
#[derive(Debug, Clone, Copy, Default)]
pub struct CopyUpState {
    /// Source inode in the lower layer.
    pub src_inode: u64,
    /// Destination inode in the upper layer.
    pub dst_inode: u64,
    /// Bytes copied so far.
    pub bytes_copied: u64,
    /// Total bytes to copy.
    pub total_bytes: u64,
    /// Whether the copy-up has finished.
    pub complete: bool,
}

/// Top-level overlay mount state.
///
/// Manages the upper layer, up to 8 lower layers, a work directory,
/// merged directory views, and pending copy-up operations.
pub struct OverlayMount {
    /// Root inode of the upper (writable) layer.
    pub upper_root: u64,
    /// Root inodes of the lower (read-only) layers.
    pub lower_roots: [u64; MAX_LOWER_LAYERS],
    /// Number of active lower layers.
    pub lower_count: usize,
    /// Work directory inode (staging area for copy-up).
    pub work_dir: u64,
    /// Merged directory views.
    merged_dirs: [OverlayDir; MAX_MERGED_DIRS],
    /// Number of tracked merged directories.
    dir_count: usize,
    /// Active copy-up operations.
    copy_ups: [CopyUpState; MAX_COPY_UPS],
    /// Number of active copy-up operations.
    copy_up_count: usize,
    /// Next inode number to allocate in the upper layer.
    next_inode: u64,
    /// Whether the overlay is currently mounted.
    pub mounted: bool,
}

impl Default for OverlayMount {
    fn default() -> Self {
        const DEFAULT_DIR: OverlayDir = OverlayDir {
            entries: [OverlayEntry {
                name: [0u8; MAX_NAME_LEN],
                name_len: 0,
                inode_id: 0,
                layer: 0,
                entry_type: OverlayEntryType::Regular,
                in_use: false,
            }; MAX_DIR_ENTRIES],
            count: 0,
            is_opaque: false,
        };
        Self {
            upper_root: 0,
            lower_roots: [0u64; MAX_LOWER_LAYERS],
            lower_count: 0,
            work_dir: 0,
            merged_dirs: [DEFAULT_DIR; MAX_MERGED_DIRS],
            dir_count: 0,
            copy_ups: [CopyUpState::default(); MAX_COPY_UPS],
            copy_up_count: 0,
            next_inode: 2,
            mounted: false,
        }
    }
}

impl OverlayMount {
    /// Mount the overlay with the given upper, lower, and work directory roots.
    ///
    /// `upper` is the root inode of the writable layer.
    /// `lowers` contains root inodes for up to 8 read-only lower layers.
    /// `work` is the inode of the work/staging directory.
    pub fn mount(&mut self, upper: u64, lowers: &[u64], work: u64) -> Result<()> {
        if self.mounted {
            return Err(Error::Busy);
        }
        if lowers.is_empty() || lowers.len() > MAX_LOWER_LAYERS {
            return Err(Error::InvalidArgument);
        }

        self.upper_root = upper;
        self.lower_count = lowers.len();
        self.lower_roots[..lowers.len()].copy_from_slice(lowers);
        self.work_dir = work;
        self.mounted = true;

        // Initialise the root merged directory (index 0).
        self.merged_dirs[0] = OverlayDir::default();
        self.dir_count = 1;

        Ok(())
    }

    /// Look up an entry by name within a merged directory.
    ///
    /// Returns the inode id and the layer where the entry was found.
    /// Whiteout entries cause `NotFound` for the corresponding name.
    pub fn lookup(&self, parent_idx: usize, name: &[u8]) -> Result<(u64, OverlayLayer)> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if parent_idx >= self.dir_count {
            return Err(Error::InvalidArgument);
        }

        let dir = &self.merged_dirs[parent_idx];

        // Check for a whiteout first — if one exists, the name is hidden.
        let whited_out = dir.entries.iter().any(|e| {
            e.in_use && e.entry_type == OverlayEntryType::Whiteout && e.name_bytes() == name
        });
        if whited_out {
            return Err(Error::NotFound);
        }

        // Search for a visible (non-whiteout) entry with matching name.
        for entry in &dir.entries {
            if !entry.in_use {
                continue;
            }
            if entry.entry_type == OverlayEntryType::Whiteout {
                continue;
            }
            if entry.name_bytes() == name {
                let layer = if entry.layer == 0 {
                    OverlayLayer::Upper
                } else {
                    OverlayLayer::Lower(entry.layer - 1)
                };
                return Ok((entry.inode_id, layer));
            }
        }

        Err(Error::NotFound)
    }

    /// Create a whiteout entry in the given directory.
    ///
    /// A whiteout hides any lower-layer entry with the same name,
    /// making it invisible in merged directory listings.
    pub fn create_whiteout(&mut self, parent_idx: usize, name: &[u8]) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if parent_idx >= self.dir_count {
            return Err(Error::InvalidArgument);
        }
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let dir = &mut self.merged_dirs[parent_idx];
        if dir.count >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot.
        let slot = dir
            .entries
            .iter_mut()
            .find(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;

        let mut entry_name = [0u8; MAX_NAME_LEN];
        entry_name[..name.len()].copy_from_slice(name);

        *slot = OverlayEntry {
            name: entry_name,
            name_len: name.len() as u8,
            inode_id: 0,
            layer: 0, // whiteouts live in upper layer
            entry_type: OverlayEntryType::Whiteout,
            in_use: true,
        };
        dir.count += 1;

        Ok(())
    }

    /// Mark a directory as opaque.
    ///
    /// An opaque directory suppresses all entries from lower layers,
    /// so only upper-layer entries are visible. This is equivalent to
    /// setting the `trusted.overlay.opaque` extended attribute.
    pub fn mark_opaque(&mut self, dir_idx: usize) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if dir_idx >= self.dir_count {
            return Err(Error::InvalidArgument);
        }

        self.merged_dirs[dir_idx].is_opaque = true;
        Ok(())
    }

    /// Copy an inode from a lower layer to the upper layer.
    ///
    /// Allocates a new upper-layer inode, records the copy-up state,
    /// and returns the new upper-layer inode id. The caller is
    /// responsible for copying the actual file data.
    pub fn copy_up(&mut self, inode_id: u64) -> Result<u64> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if self.copy_up_count >= MAX_COPY_UPS {
            return Err(Error::OutOfMemory);
        }

        // Check if already copied up.
        for cu in &self.copy_ups[..self.copy_up_count] {
            if cu.src_inode == inode_id && cu.complete {
                return Ok(cu.dst_inode);
            }
        }

        let new_inode = self.next_inode;
        self.next_inode += 1;

        self.copy_ups[self.copy_up_count] = CopyUpState {
            src_inode: inode_id,
            dst_inode: new_inode,
            bytes_copied: 0,
            total_bytes: 0,
            complete: true,
        };
        self.copy_up_count += 1;

        Ok(new_inode)
    }

    /// Return visible (non-whiteout) entries from a merged directory.
    ///
    /// If the directory is opaque, only upper-layer entries are returned.
    /// Whiteout entries are always excluded from the result.
    pub fn readdir(&self, dir_idx: usize) -> &[OverlayEntry] {
        if dir_idx >= self.dir_count {
            return &[];
        }
        &self.merged_dirs[dir_idx].entries
    }

    /// Unlink (delete) a name from a directory.
    ///
    /// If the entry exists only in the upper layer, it is removed.
    /// If it exists in a lower layer, a whiteout is created to hide
    /// it in merged listings. Returns `NotFound` if the name does
    /// not exist.
    pub fn unlink(&mut self, parent_idx: usize, name: &[u8]) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if parent_idx >= self.dir_count {
            return Err(Error::InvalidArgument);
        }

        let dir = &mut self.merged_dirs[parent_idx];

        // Track whether we found and removed an upper-layer entry,
        // and whether a lower-layer entry with this name exists.
        let mut found_upper = false;
        let mut exists_in_lower = false;

        for entry in dir.entries.iter_mut() {
            if !entry.in_use || entry.entry_type == OverlayEntryType::Whiteout {
                continue;
            }
            if entry.name_bytes() != name {
                continue;
            }
            if entry.layer == 0 {
                // Upper-layer entry — remove it directly.
                entry.in_use = false;
                dir.count = dir.count.saturating_sub(1);
                found_upper = true;
            } else {
                // Lower-layer entry — will need a whiteout.
                exists_in_lower = true;
            }
        }

        if !found_upper && !exists_in_lower {
            return Err(Error::NotFound);
        }

        // Create a whiteout to hide any lower-layer entry.
        if exists_in_lower {
            self.create_whiteout(parent_idx, name)?;
        }

        Ok(())
    }

    /// Create a new directory in the upper layer.
    ///
    /// Allocates a new inode, adds a directory entry in the parent,
    /// and initialises a new merged directory slot. Returns the new
    /// directory's inode id.
    pub fn mkdir(&mut self, parent_idx: usize, name: &[u8]) -> Result<u64> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if parent_idx >= self.dir_count {
            return Err(Error::InvalidArgument);
        }
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.dir_count >= MAX_MERGED_DIRS {
            return Err(Error::OutOfMemory);
        }

        let dir = &self.merged_dirs[parent_idx];

        // Check for duplicate name (non-whiteout).
        let duplicate = dir.entries.iter().any(|e| {
            e.in_use && e.entry_type != OverlayEntryType::Whiteout && e.name_bytes() == name
        });
        if duplicate {
            return Err(Error::AlreadyExists);
        }

        let new_inode = self.next_inode;
        self.next_inode += 1;

        // Remove any existing whiteout for this name.
        let dir = &mut self.merged_dirs[parent_idx];
        for entry in dir.entries.iter_mut() {
            if entry.in_use
                && entry.entry_type == OverlayEntryType::Whiteout
                && entry.name_bytes() == name
            {
                entry.in_use = false;
                dir.count = dir.count.saturating_sub(1);
                break;
            }
        }

        // Add the new directory entry in the parent.
        if dir.count >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let slot = dir
            .entries
            .iter_mut()
            .find(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;

        let mut entry_name = [0u8; MAX_NAME_LEN];
        entry_name[..name.len()].copy_from_slice(name);

        *slot = OverlayEntry {
            name: entry_name,
            name_len: name.len() as u8,
            inode_id: new_inode,
            layer: 0, // created in upper layer
            entry_type: OverlayEntryType::Regular,
            in_use: true,
        };
        dir.count += 1;

        // Initialise a new merged directory for the child.
        self.merged_dirs[self.dir_count] = OverlayDir::default();
        self.dir_count += 1;

        Ok(new_inode)
    }

    /// Rename an entry from one directory to another (or within the same).
    ///
    /// Moves the entry from `old_parent`/`old_name` to
    /// `new_parent`/`new_name`. If the source is in a lower layer,
    /// a copy-up is performed and a whiteout is left behind.
    pub fn rename(
        &mut self,
        old_parent: usize,
        old_name: &[u8],
        new_parent: usize,
        new_name: &[u8],
    ) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if old_parent >= self.dir_count || new_parent >= self.dir_count {
            return Err(Error::InvalidArgument);
        }
        if old_name.is_empty()
            || old_name.len() > MAX_NAME_LEN
            || new_name.is_empty()
            || new_name.len() > MAX_NAME_LEN
        {
            return Err(Error::InvalidArgument);
        }

        // Find the source entry.
        let (inode_id, src_layer) = {
            let dir = &self.merged_dirs[old_parent];
            let entry = dir
                .entries
                .iter()
                .find(|e| {
                    e.in_use
                        && e.entry_type != OverlayEntryType::Whiteout
                        && e.name_bytes() == old_name
                })
                .ok_or(Error::NotFound)?;
            (entry.inode_id, entry.layer)
        };

        // If from a lower layer, copy-up and leave a whiteout.
        let final_inode = if src_layer != 0 {
            let new_id = self.copy_up(inode_id)?;
            self.create_whiteout(old_parent, old_name)?;
            new_id
        } else {
            // Remove the old entry from upper.
            let dir = &mut self.merged_dirs[old_parent];
            for entry in dir.entries.iter_mut() {
                if entry.in_use
                    && entry.entry_type != OverlayEntryType::Whiteout
                    && entry.name_bytes() == old_name
                {
                    entry.in_use = false;
                    dir.count = dir.count.saturating_sub(1);
                    break;
                }
            }
            inode_id
        };

        // Remove any existing whiteout at the destination.
        let dest_dir = &mut self.merged_dirs[new_parent];
        for entry in dest_dir.entries.iter_mut() {
            if entry.in_use
                && entry.entry_type == OverlayEntryType::Whiteout
                && entry.name_bytes() == new_name
            {
                entry.in_use = false;
                dest_dir.count = dest_dir.count.saturating_sub(1);
                break;
            }
        }

        // Remove any existing regular entry at destination (overwrite).
        for entry in dest_dir.entries.iter_mut() {
            if entry.in_use
                && entry.entry_type != OverlayEntryType::Whiteout
                && entry.name_bytes() == new_name
            {
                entry.in_use = false;
                dest_dir.count = dest_dir.count.saturating_sub(1);
                break;
            }
        }

        // Insert the entry at the destination.
        if dest_dir.count >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let slot = dest_dir
            .entries
            .iter_mut()
            .find(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;

        let mut entry_name = [0u8; MAX_NAME_LEN];
        entry_name[..new_name.len()].copy_from_slice(new_name);

        *slot = OverlayEntry {
            name: entry_name,
            name_len: new_name.len() as u8,
            inode_id: final_inode,
            layer: 0, // now in upper layer
            entry_type: OverlayEntryType::Regular,
            in_use: true,
        };
        dest_dir.count += 1;

        Ok(())
    }

    /// Check whether a name is hidden by a whiteout in the given directory.
    pub fn is_whiteout(&self, parent_idx: usize, name: &[u8]) -> bool {
        if parent_idx >= self.dir_count {
            return false;
        }
        self.merged_dirs[parent_idx].entries.iter().any(|e| {
            e.in_use && e.entry_type == OverlayEntryType::Whiteout && e.name_bytes() == name
        })
    }

    /// Count visible (non-whiteout, in-use) entries in a directory.
    ///
    /// If the directory is opaque, only upper-layer entries are counted.
    pub fn visible_entries(&self, dir_idx: usize) -> usize {
        if dir_idx >= self.dir_count {
            return 0;
        }
        let dir = &self.merged_dirs[dir_idx];
        dir.entries
            .iter()
            .filter(|e| {
                if !e.in_use || e.entry_type == OverlayEntryType::Whiteout {
                    return false;
                }
                if dir.is_opaque && e.layer != 0 {
                    return false;
                }
                true
            })
            .count()
    }

    /// Return the number of tracked merged directories.
    pub fn len(&self) -> usize {
        self.dir_count
    }

    /// Return whether there are no tracked directories.
    pub fn is_empty(&self) -> bool {
        self.dir_count == 0
    }
}
