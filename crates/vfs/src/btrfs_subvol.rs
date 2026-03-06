// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs subvolume management.
//!
//! A btrfs subvolume is an independently snapshotable tree within a btrfs
//! filesystem. Each subvolume has its own root and can be mounted, cloned
//! (snapshotted), and deleted independently.
//!
//! # Key concepts
//!
//! - [`SubvolInfo`] — static metadata for a subvolume
//! - [`SubvolFlags`] — read-only, default, snapshot markers
//! - [`create_subvolume`] — create a new empty subvolume
//! - [`snapshot`] — clone a subvolume (writable or read-only)
//! - [`delete_subvolume`] — mark a subvolume for deletion
//! - [`set_default_subvol`] — set the mount-time default subvolume
//!
//! # References
//!
//! - Linux `fs/btrfs/ioctl.c` (`BTRFS_IOC_SUBVOL_CREATE`, `_SNAP_CREATE`)
//! - Btrfs on-disk format documentation

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum subvolumes tracked per filesystem instance.
pub const MAX_SUBVOLS: usize = 64;

/// Maximum name length for a subvolume.
pub const MAX_SUBVOL_NAME: usize = 255;

/// Root objectid for the top-level filesystem tree (BTRFS_FS_TREE_OBJECTID).
pub const BTRFS_FS_TREE_OBJECTID: u64 = 5;

/// First valid user-visible subvolume ID.
pub const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;

/// Snapshot flag: subvolume is read-only.
pub const SUBVOL_FLAG_READONLY: u32 = 1 << 0;
/// Flag: this is a snapshot of another subvolume.
pub const SUBVOL_FLAG_SNAPSHOT: u32 = 1 << 1;
/// Flag: this is the default mount subvolume.
pub const SUBVOL_FLAG_DEFAULT: u32 = 1 << 2;
/// Flag: subvolume is pending deletion.
pub const SUBVOL_FLAG_DEAD: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Subvolume flags bitfield.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubvolFlags(pub u32);

impl SubvolFlags {
    /// Returns true if the subvolume is read-only.
    pub fn is_readonly(self) -> bool {
        self.0 & SUBVOL_FLAG_READONLY != 0
    }

    /// Returns true if this is a snapshot.
    pub fn is_snapshot(self) -> bool {
        self.0 & SUBVOL_FLAG_SNAPSHOT != 0
    }

    /// Returns true if this is the default subvolume.
    pub fn is_default(self) -> bool {
        self.0 & SUBVOL_FLAG_DEFAULT != 0
    }

    /// Returns true if the subvolume is dead (pending removal).
    pub fn is_dead(self) -> bool {
        self.0 & SUBVOL_FLAG_DEAD != 0
    }
}

/// Metadata for a single btrfs subvolume.
#[derive(Debug, Clone)]
pub struct SubvolInfo {
    /// Unique subvolume ID (objectid in the root tree).
    pub id: u64,
    /// Parent subvolume ID (0 if top-level).
    pub parent_id: u64,
    /// Generation number at last modification.
    pub generation: u64,
    /// Objectid of the subvolume's root inode.
    pub root_objectid: u64,
    /// Subvolume flags.
    pub flags: SubvolFlags,
    /// Name (null-terminated at `name_len`).
    pub name: [u8; MAX_SUBVOL_NAME],
    /// Length of `name`.
    pub name_len: usize,
    /// Source subvolume ID if this is a snapshot, else 0.
    pub snapshot_source_id: u64,
    /// Generation at which the snapshot was taken.
    pub snapshot_gen: u64,
}

impl SubvolInfo {
    fn new(id: u64, parent_id: u64, generation: u64, name: &[u8]) -> Result<Self> {
        if name.len() > MAX_SUBVOL_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut info = Self {
            id,
            parent_id,
            generation,
            root_objectid: id, // root_objectid == id by convention
            flags: SubvolFlags::default(),
            name: [0u8; MAX_SUBVOL_NAME],
            name_len: name.len(),
            snapshot_source_id: 0,
            snapshot_gen: 0,
        };
        info.name[..name.len()].copy_from_slice(name);
        Ok(info)
    }

    /// Return the subvolume name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// A btrfs filesystem with subvolume tracking.
pub struct BtrfsSubvolTable {
    /// All subvolumes in this filesystem.
    entries: [Option<SubvolInfo>; MAX_SUBVOLS],
    /// Total number of active subvolumes.
    count: usize,
    /// ID of the default subvolume.
    default_id: u64,
    /// Next auto-assigned subvolume ID.
    next_id: u64,
    /// Current global generation counter.
    cur_generation: u64,
}

impl BtrfsSubvolTable {
    /// Create a new table with the top-level FS tree as the sole subvolume.
    pub fn new() -> Self {
        let mut table = Self {
            entries: [const { None }; MAX_SUBVOLS],
            count: 0,
            default_id: BTRFS_FS_TREE_OBJECTID,
            next_id: BTRFS_FIRST_FREE_OBJECTID,
            cur_generation: 1,
        };
        // Pre-populate top-level subvolume.
        let top = SubvolInfo::new(BTRFS_FS_TREE_OBJECTID, 0, 1, b"<FS_TREE>")
            .expect("top-level subvol init");
        table.entries[0] = Some(top);
        table.count = 1;
        table
    }

    fn find_slot(&self, id: u64) -> Option<usize> {
        for i in 0..MAX_SUBVOLS {
            if let Some(ref sv) = self.entries[i] {
                if sv.id == id {
                    return Some(i);
                }
            }
        }
        None
    }

    fn free_slot(&mut self) -> Option<usize> {
        for i in 0..MAX_SUBVOLS {
            if self.entries[i].is_none() {
                return Some(i);
            }
        }
        None
    }

    fn next_generation(&mut self) -> u64 {
        self.cur_generation += 1;
        self.cur_generation
    }
}

impl Default for BtrfsSubvolTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Create a new empty subvolume under `parent_id`.
///
/// Returns the ID of the newly created subvolume.
pub fn create_subvolume(table: &mut BtrfsSubvolTable, parent_id: u64, name: &[u8]) -> Result<u64> {
    if name.is_empty() || name.len() > MAX_SUBVOL_NAME {
        return Err(Error::InvalidArgument);
    }
    // Parent must exist.
    if table.find_slot(parent_id).is_none() {
        return Err(Error::NotFound);
    }
    // Name must be unique among siblings.
    for i in 0..MAX_SUBVOLS {
        if let Some(ref sv) = table.entries[i] {
            if sv.parent_id == parent_id && sv.name_bytes() == name && !sv.flags.is_dead() {
                return Err(Error::AlreadyExists);
            }
        }
    }

    let slot = table.free_slot().ok_or(Error::OutOfMemory)?;
    let id = table.next_id;
    table.next_id += 1;
    let generation = table.next_generation();

    let sv = SubvolInfo::new(id, parent_id, generation, name)?;
    table.entries[slot] = Some(sv);
    table.count += 1;
    Ok(id)
}

/// Delete a subvolume by ID.
///
/// Marks it dead; actual reclamation is deferred.
/// Returns `Err(Busy)` if the subvolume has live children.
pub fn delete_subvolume(table: &mut BtrfsSubvolTable, id: u64) -> Result<()> {
    if id == BTRFS_FS_TREE_OBJECTID {
        return Err(Error::PermissionDenied);
    }
    // Check for live children.
    for i in 0..MAX_SUBVOLS {
        if let Some(ref sv) = table.entries[i] {
            if sv.parent_id == id && !sv.flags.is_dead() {
                return Err(Error::Busy);
            }
        }
    }
    let slot = table.find_slot(id).ok_or(Error::NotFound)?;
    if let Some(ref mut sv) = table.entries[slot] {
        sv.flags.0 |= SUBVOL_FLAG_DEAD;
    }
    Ok(())
}

/// Create a snapshot of `src_id`.
///
/// - `readonly`: if true the snapshot is read-only.
/// - Returns the new subvolume ID.
pub fn snapshot(
    table: &mut BtrfsSubvolTable,
    src_id: u64,
    parent_id: u64,
    name: &[u8],
    readonly: bool,
) -> Result<u64> {
    if name.is_empty() || name.len() > MAX_SUBVOL_NAME {
        return Err(Error::InvalidArgument);
    }
    let src_slot = table.find_slot(src_id).ok_or(Error::NotFound)?;
    let src_gen = table.entries[src_slot].as_ref().unwrap().generation;

    // Parent must exist.
    if table.find_slot(parent_id).is_none() {
        return Err(Error::NotFound);
    }

    let slot = table.free_slot().ok_or(Error::OutOfMemory)?;
    let id = table.next_id;
    table.next_id += 1;
    let generation = table.next_generation();

    let mut sv = SubvolInfo::new(id, parent_id, generation, name)?;
    sv.flags.0 |= SUBVOL_FLAG_SNAPSHOT;
    if readonly {
        sv.flags.0 |= SUBVOL_FLAG_READONLY;
    }
    sv.snapshot_source_id = src_id;
    sv.snapshot_gen = src_gen;

    table.entries[slot] = Some(sv);
    table.count += 1;
    Ok(id)
}

/// Set the default subvolume for mount.
///
/// The default subvolume is used when no `subvol=` mount option is given.
pub fn set_default_subvol(table: &mut BtrfsSubvolTable, id: u64) -> Result<()> {
    let _slot = table.find_slot(id).ok_or(Error::NotFound)?;
    // Clear old default flag.
    if let Some(old_slot) = table.find_slot(table.default_id) {
        if let Some(ref mut sv) = table.entries[old_slot] {
            sv.flags.0 &= !SUBVOL_FLAG_DEFAULT;
        }
    }
    // Set new default.
    let slot = table.find_slot(id).unwrap();
    if let Some(ref mut sv) = table.entries[slot] {
        sv.flags.0 |= SUBVOL_FLAG_DEFAULT;
    }
    table.default_id = id;
    Ok(())
}

/// Return the default subvolume ID.
pub fn get_default_subvol(table: &BtrfsSubvolTable) -> u64 {
    table.default_id
}

/// Look up a subvolume by ID.
pub fn find_subvol(table: &BtrfsSubvolTable, id: u64) -> Option<&SubvolInfo> {
    let slot = table.find_slot(id)?;
    table.entries[slot].as_ref()
}

/// List all live subvolume IDs into `out`.
///
/// Returns the number written.
pub fn list_subvols(table: &BtrfsSubvolTable, out: &mut [u64]) -> usize {
    let mut written = 0;
    for i in 0..MAX_SUBVOLS {
        if written >= out.len() {
            break;
        }
        if let Some(ref sv) = table.entries[i] {
            if !sv.flags.is_dead() {
                out[written] = sv.id;
                written += 1;
            }
        }
    }
    written
}

/// Find a subvolume by name under `parent_id`.
pub fn find_subvol_by_name(table: &BtrfsSubvolTable, parent_id: u64, name: &[u8]) -> Option<u64> {
    for i in 0..MAX_SUBVOLS {
        if let Some(ref sv) = table.entries[i] {
            if sv.parent_id == parent_id && sv.name_bytes() == name && !sv.flags.is_dead() {
                return Some(sv.id);
            }
        }
    }
    None
}

/// Purge all subvolumes marked dead from the table.
///
/// Returns the number purged.
pub fn purge_dead_subvols(table: &mut BtrfsSubvolTable) -> usize {
    let mut purged = 0;
    for i in 0..MAX_SUBVOLS {
        if let Some(ref sv) = table.entries[i] {
            if sv.flags.is_dead() {
                table.entries[i] = None;
                table.count = table.count.saturating_sub(1);
                purged += 1;
            }
        }
    }
    purged
}
