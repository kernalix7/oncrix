// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! btrfs snapshot and subvolume management.
//!
//! Implements btrfs subvolume creation, deletion, and snapshot operations.
//! Each subvolume is a separate root tree, and snapshots are copy-on-write
//! clones of existing subvolumes or snapshots.

use oncrix_lib::{Error, Result};

/// Maximum length of a subvolume name (including null terminator).
pub const BTRFS_SUBVOL_NAME_MAX: usize = 255;

/// Object ID for the top-level/default subvolume.
pub const BTRFS_FS_TREE_OBJECTID: u64 = 5;

/// First valid user subvolume object ID.
pub const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;

/// Flag: snapshot is read-only.
pub const BTRFS_SUBVOL_RDONLY: u64 = 1 << 1;

/// Flag: snapshot should be created with read-only semantics.
pub const BTRFS_SNAP_RDONLY: u64 = 1 << 0;

/// State of a subvolume root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubvolState {
    /// Normal, fully accessible subvolume.
    Active,
    /// Being deleted (dead reference).
    Dead,
    /// Snapshot in progress.
    Snapshotting,
}

/// Key used to identify btrfs tree items by (objectid, type, offset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BtrfsKey {
    /// Object identifier.
    pub objectid: u64,
    /// Item type byte.
    pub item_type: u8,
    /// Offset within the object.
    pub offset: u64,
}

impl BtrfsKey {
    /// Create a new BtrfsKey.
    pub const fn new(objectid: u64, item_type: u8, offset: u64) -> Self {
        Self {
            objectid,
            item_type,
            offset,
        }
    }
}

/// btrfs inode reference — maps an inode to its parent and name.
#[derive(Debug, Clone)]
pub struct BtrfsInodeRef {
    /// Index in the parent directory.
    pub index: u64,
    /// Name length.
    pub name_len: u16,
    /// Name bytes.
    pub name: [u8; BTRFS_SUBVOL_NAME_MAX],
}

/// Root item describing a subvolume or snapshot root.
#[derive(Debug, Clone)]
pub struct BtrfsRootItem {
    /// Root object ID (subvolume ID).
    pub root_id: u64,
    /// Block number of the root tree node.
    pub bytenr: u64,
    /// Generation number of the root.
    pub generation: u64,
    /// Last transid that modified this root.
    pub last_snapshot: u64,
    /// Flags (BTRFS_SUBVOL_RDONLY etc.).
    pub flags: u64,
    /// UUID of this root.
    pub uuid: [u8; 16],
    /// UUID of the parent snapshot, all zeros if none.
    pub parent_uuid: [u8; 16],
    /// UUID of the received snapshot, all zeros if none.
    pub received_uuid: [u8; 16],
    /// Current state.
    pub state: SubvolState,
}

impl BtrfsRootItem {
    /// Create a new empty root item.
    pub const fn new(root_id: u64) -> Self {
        Self {
            root_id,
            bytenr: 0,
            generation: 0,
            last_snapshot: 0,
            flags: 0,
            uuid: [0u8; 16],
            parent_uuid: [0u8; 16],
            received_uuid: [0u8; 16],
            state: SubvolState::Active,
        }
    }

    /// Return true if this root is read-only.
    pub fn is_rdonly(&self) -> bool {
        self.flags & BTRFS_SUBVOL_RDONLY != 0
    }

    /// Set the read-only flag.
    pub fn set_rdonly(&mut self, rdonly: bool) {
        if rdonly {
            self.flags |= BTRFS_SUBVOL_RDONLY;
        } else {
            self.flags &= !BTRFS_SUBVOL_RDONLY;
        }
    }
}

/// Parameters for creating a new snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotCreateArgs {
    /// Source subvolume root ID.
    pub src_root_id: u64,
    /// Parent directory inode of the new snapshot.
    pub dest_parent_ino: u64,
    /// Name of the new snapshot.
    pub name: [u8; BTRFS_SUBVOL_NAME_MAX],
    /// Length of the name.
    pub name_len: usize,
    /// Creation flags (BTRFS_SNAP_RDONLY).
    pub flags: u64,
}

impl SnapshotCreateArgs {
    /// Create snapshot args with a name slice.
    pub fn new(src_root_id: u64, dest_parent_ino: u64, name: &[u8], rdonly: bool) -> Result<Self> {
        if name.is_empty() || name.len() >= BTRFS_SUBVOL_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut name_buf = [0u8; BTRFS_SUBVOL_NAME_MAX];
        name_buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            src_root_id,
            dest_parent_ino,
            name: name_buf,
            name_len: name.len(),
            flags: if rdonly { BTRFS_SNAP_RDONLY } else { 0 },
        })
    }
}

/// Registry of all subvolumes and snapshots in a btrfs filesystem.
///
/// In a real implementation this would be backed by the extent tree and
/// root tree. Here we maintain a flat in-memory table for the VFS layer.
#[derive(Debug)]
pub struct SubvolManager {
    /// All registered roots indexed by root ID.
    roots: [Option<BtrfsRootItem>; 64],
    /// Next root ID to assign.
    next_root_id: u64,
    /// Current transaction ID.
    pub transid: u64,
}

impl SubvolManager {
    /// Create a new manager with the default top-level subvolume.
    pub const fn new() -> Self {
        Self {
            roots: [const { None }; 64],
            next_root_id: BTRFS_FIRST_FREE_OBJECTID,
            transid: 1,
        }
    }

    /// Allocate the next available root ID.
    fn alloc_root_id(&mut self) -> Result<u64> {
        let id = self.next_root_id;
        self.next_root_id = id.checked_add(1).ok_or(Error::OutOfMemory)?;
        Ok(id)
    }

    /// Find a free slot in the roots table.
    fn find_free_slot(&self) -> Option<usize> {
        self.roots.iter().position(|r| r.is_none())
    }

    /// Find the index of a root by ID.
    fn find_root_index(&self, root_id: u64) -> Option<usize> {
        self.roots
            .iter()
            .position(|r| r.as_ref().map_or(false, |ri| ri.root_id == root_id))
    }

    /// Create a new empty subvolume.
    ///
    /// Returns the new subvolume's root ID.
    pub fn create_subvolume(&mut self, name: &[u8]) -> Result<u64> {
        if name.is_empty() || name.len() >= BTRFS_SUBVOL_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let slot = self.find_free_slot().ok_or(Error::OutOfMemory)?;
        let root_id = self.alloc_root_id()?;
        let mut item = BtrfsRootItem::new(root_id);
        item.generation = self.transid;
        self.roots[slot] = Some(item);
        Ok(root_id)
    }

    /// Create a snapshot of an existing subvolume.
    ///
    /// The snapshot shares all current extents via copy-on-write semantics.
    /// Returns the new snapshot's root ID.
    pub fn create_snapshot(&mut self, args: &SnapshotCreateArgs) -> Result<u64> {
        let src_idx = self
            .find_root_index(args.src_root_id)
            .ok_or(Error::NotFound)?;

        let src = self.roots[src_idx].as_ref().unwrap();
        if src.state != SubvolState::Active {
            return Err(Error::Busy);
        }

        let src_bytenr = src.bytenr;
        let src_generation = src.generation;
        let src_uuid = src.uuid;

        let slot = self.find_free_slot().ok_or(Error::OutOfMemory)?;
        let snap_id = self.alloc_root_id()?;

        // Update parent's last_snapshot generation.
        if let Some(src_item) = self.roots[src_idx].as_mut() {
            src_item.last_snapshot = self.transid;
        }

        let mut snap = BtrfsRootItem::new(snap_id);
        snap.bytenr = src_bytenr;
        snap.generation = self.transid;
        snap.last_snapshot = src_generation;
        snap.parent_uuid = src_uuid;
        if args.flags & BTRFS_SNAP_RDONLY != 0 {
            snap.set_rdonly(true);
        }
        self.roots[slot] = Some(snap);
        Ok(snap_id)
    }

    /// Delete a subvolume or snapshot by root ID.
    ///
    /// The root must have no active references. In practice, the caller
    /// ensures all dentries referring to the subvolume are gone.
    pub fn delete_subvolume(&mut self, root_id: u64) -> Result<()> {
        if root_id < BTRFS_FIRST_FREE_OBJECTID {
            // Cannot delete the default subvolume.
            return Err(Error::PermissionDenied);
        }
        let idx = self.find_root_index(root_id).ok_or(Error::NotFound)?;
        if let Some(item) = self.roots[idx].as_mut() {
            item.state = SubvolState::Dead;
        }
        self.roots[idx] = None;
        Ok(())
    }

    /// Get a reference to a root item.
    pub fn get_root(&self, root_id: u64) -> Option<&BtrfsRootItem> {
        let idx = self.find_root_index(root_id)?;
        self.roots[idx].as_ref()
    }

    /// Get a mutable reference to a root item.
    pub fn get_root_mut(&mut self, root_id: u64) -> Option<&mut BtrfsRootItem> {
        let idx = self.find_root_index(root_id)?;
        self.roots[idx].as_mut()
    }

    /// Set or clear the read-only flag on a subvolume.
    pub fn set_rdonly(&mut self, root_id: u64, rdonly: bool) -> Result<()> {
        let item = self.get_root_mut(root_id).ok_or(Error::NotFound)?;
        item.set_rdonly(rdonly);
        Ok(())
    }

    /// List all active subvolume IDs.
    pub fn list_subvolumes<F>(&self, mut cb: F)
    where
        F: FnMut(u64),
    {
        for slot in &self.roots {
            if let Some(item) = slot {
                if item.state == SubvolState::Active {
                    cb(item.root_id);
                }
            }
        }
    }

    /// Advance the transaction ID.
    pub fn commit_transaction(&mut self) {
        self.transid = self.transid.wrapping_add(1);
    }
}

impl Default for SubvolManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot send/receive state for incremental sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendRecvState {
    /// No active send/receive.
    Idle,
    /// Send in progress from this root.
    Sending,
    /// Receive in progress into this root.
    Receiving,
}

/// Context for a btrfs send operation.
#[derive(Debug)]
pub struct SendContext {
    /// Root being sent.
    pub root_id: u64,
    /// Optional parent snapshot root ID for incremental sends.
    pub parent_root_id: Option<u64>,
    /// Current state.
    pub state: SendRecvState,
    /// Bytes sent so far.
    pub bytes_sent: u64,
}

impl SendContext {
    /// Create a new send context.
    pub const fn new(root_id: u64, parent_root_id: Option<u64>) -> Self {
        Self {
            root_id,
            parent_root_id,
            state: SendRecvState::Idle,
            bytes_sent: 0,
        }
    }

    /// Mark the send as started.
    pub fn start(&mut self) -> Result<()> {
        if self.state != SendRecvState::Idle {
            return Err(Error::Busy);
        }
        self.state = SendRecvState::Sending;
        Ok(())
    }

    /// Mark the send as finished.
    pub fn finish(&mut self) {
        self.state = SendRecvState::Idle;
    }
}
