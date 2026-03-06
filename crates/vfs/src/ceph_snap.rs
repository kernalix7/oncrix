// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CephFS snapshot operations.
//!
//! Implements the client-side snapshot subsystem mirroring `fs/ceph/snap.c`.
//!
//! # Snapshot realms
//!
//! A **snap realm** is a subtree of the CephFS directory hierarchy that shares
//! snapshot state. Realms form a parent–child tree rooted at the global realm.
//! Each realm carries a [`SnapContext`] listing the snapshot IDs (seqs) that
//! are visible within it.
//!
//! # Snap contexts
//!
//! A [`SnapContext`] is an ordered sequence of snapshot sequence numbers. When
//! an object write occurs the client attaches the current snap context so that
//! the OSD can create copy-on-write clones for all listed snapshots.
//!
//! # Snapshot lifecycle
//!
//! 1. `snap_create` — allocates a new snapshot ID and inserts it into the
//!    realm's context.
//! 2. Write flush — before writing a dirty page the client checks whether the
//!    page's snap context is stale (the realm has a newer context) and, if so,
//!    flushes the old data as a snapshot clone.
//! 3. `snap_delete` — removes a snapshot ID from the context.
//!
//! # References
//!
//! - Linux `fs/ceph/snap.c`
//! - Ceph documentation: <https://docs.ceph.com/en/latest/dev/cephfs-snapshots/>

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of snapshot IDs in a single [`SnapContext`].
pub const SNAP_CTX_MAX_SNAPS: usize = 64;

/// Maximum number of snap realms tracked concurrently.
pub const MAX_SNAP_REALMS: usize = 64;

/// Maximum number of child realms a single realm may have.
pub const MAX_REALM_CHILDREN: usize = 16;

/// Maximum byte length of a snapshot name.
pub const SNAP_NAME_MAX: usize = 64;

/// Sentinel snap sequence meaning "no snapshot".
pub const SNAP_HEAD_ID: u64 = u64::MAX;

/// Snap sequence of the NOSNAP (unsnapped) state.
pub const SNAP_NOSNAP_ID: u64 = 0;

// ── SnapContext ───────────────────────────────────────────────────────────────

/// An ordered sequence of snapshot IDs representing the visible snapshots at a
/// point in time.
///
/// Snap IDs are stored in **descending** order (newest first), matching the
/// Ceph OSD protocol.
#[derive(Debug, Clone, Copy)]
pub struct SnapContext {
    /// Sequence number of this context (bumped each time the realm changes).
    pub seq: u64,
    /// Snapshot IDs included in this context, newest first.
    snaps: [u64; SNAP_CTX_MAX_SNAPS],
    /// Number of valid snap IDs.
    pub num_snaps: usize,
}

impl Default for SnapContext {
    fn default() -> Self {
        Self {
            seq: 0,
            snaps: [0u64; SNAP_CTX_MAX_SNAPS],
            num_snaps: 0,
        }
    }
}

impl SnapContext {
    /// Creates a new snap context with the given sequence number and no snaps.
    pub const fn new(seq: u64) -> Self {
        Self {
            seq,
            snaps: [0u64; SNAP_CTX_MAX_SNAPS],
            num_snaps: 0,
        }
    }

    /// Returns the snapshot IDs in descending order.
    pub fn snaps(&self) -> &[u64] {
        &self.snaps[..self.num_snaps]
    }

    /// Returns `true` if `snap_id` is present in this context.
    pub fn contains(&self, snap_id: u64) -> bool {
        self.snaps[..self.num_snaps].contains(&snap_id)
    }

    /// Inserts `snap_id`, maintaining descending order.
    ///
    /// Returns [`Error::OutOfMemory`] if the context is full.
    pub fn insert(&mut self, snap_id: u64) -> Result<()> {
        if self.num_snaps >= SNAP_CTX_MAX_SNAPS {
            return Err(Error::OutOfMemory);
        }
        // Find insertion position (keep descending order).
        let pos = self.snaps[..self.num_snaps].partition_point(|&s| s > snap_id);
        // Shift tail right.
        let mut i = self.num_snaps;
        while i > pos {
            self.snaps[i] = self.snaps[i - 1];
            i -= 1;
        }
        self.snaps[pos] = snap_id;
        self.num_snaps += 1;
        Ok(())
    }

    /// Removes `snap_id` from this context.
    ///
    /// Returns [`Error::NotFound`] if not present.
    pub fn remove(&mut self, snap_id: u64) -> Result<()> {
        let pos = self.snaps[..self.num_snaps]
            .iter()
            .position(|&s| s == snap_id)
            .ok_or(Error::NotFound)?;
        for i in pos..self.num_snaps - 1 {
            self.snaps[i] = self.snaps[i + 1];
        }
        self.num_snaps -= 1;
        Ok(())
    }

    /// Returns `true` if this context is newer than `other` (has a higher seq).
    pub const fn is_newer_than(&self, other: &SnapContext) -> bool {
        self.seq > other.seq
    }
}

// ── SnapEntry ────────────────────────────────────────────────────────────────

/// A single named snapshot within a realm.
#[derive(Clone, Copy)]
pub struct SnapEntry {
    /// Snapshot sequence (ID) assigned by the MDS.
    pub snap_id: u64,
    /// Human-readable snapshot name.
    name: [u8; SNAP_NAME_MAX],
    /// Length of the name.
    name_len: usize,
    /// Whether this slot is active.
    pub active: bool,
}

impl Default for SnapEntry {
    fn default() -> Self {
        Self {
            snap_id: 0,
            name: [0u8; SNAP_NAME_MAX],
            name_len: 0,
            active: false,
        }
    }
}

impl core::fmt::Debug for SnapEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SnapEntry")
            .field("snap_id", &self.snap_id)
            .field("name", &self.name())
            .finish()
    }
}

impl SnapEntry {
    /// Creates a new snap entry with the given name.
    pub fn new(snap_id: u64, name: &[u8]) -> Result<Self> {
        if name.len() > SNAP_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut e = Self::default();
        e.snap_id = snap_id;
        e.name[..name.len()].copy_from_slice(name);
        e.name_len = name.len();
        e.active = true;
        Ok(e)
    }

    /// Returns the snapshot name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ── SnapRealm ────────────────────────────────────────────────────────────────

/// A CephFS snapshot realm — a subtree with a shared snapshot namespace.
pub struct SnapRealm {
    /// Realm inode number (globally unique).
    pub ino: u64,
    /// Inode number of the parent realm (0 = root).
    pub parent_ino: u64,
    /// Current snap context.
    pub context: SnapContext,
    /// Named snapshots owned by this realm.
    snaps: [SnapEntry; 32],
    /// Number of named snapshots.
    snap_count: usize,
    /// Child realm inode numbers.
    children: [u64; MAX_REALM_CHILDREN],
    /// Number of children.
    child_count: usize,
    /// Whether this realm slot is active.
    pub active: bool,
    /// Generation counter used for cap invalidation.
    pub cap_gen: u32,
}

impl Default for SnapRealm {
    fn default() -> Self {
        Self {
            ino: 0,
            parent_ino: 0,
            context: SnapContext::default(),
            snaps: [const {
                SnapEntry {
                    snap_id: 0,
                    name: [0u8; SNAP_NAME_MAX],
                    name_len: 0,
                    active: false,
                }
            }; 32],
            snap_count: 0,
            children: [0u64; MAX_REALM_CHILDREN],
            child_count: 0,
            active: false,
            cap_gen: 0,
        }
    }
}

impl SnapRealm {
    /// Creates a new realm for `ino` with parent `parent_ino`.
    pub const fn new(ino: u64, parent_ino: u64) -> Self {
        Self {
            ino,
            parent_ino,
            context: SnapContext::new(0),
            snaps: [const {
                SnapEntry {
                    snap_id: 0,
                    name: [0u8; SNAP_NAME_MAX],
                    name_len: 0,
                    active: false,
                }
            }; 32],
            snap_count: 0,
            children: [0u64; MAX_REALM_CHILDREN],
            child_count: 0,
            active: true,
            cap_gen: 0,
        }
    }

    // ── Snapshot create / delete ───────────────────────────────────────────────

    /// Creates a new named snapshot in this realm.
    ///
    /// Allocates a new snap ID (one above the current maximum), inserts it
    /// into the snap context, and records the named entry.
    pub fn create_snap(&mut self, name: &[u8]) -> Result<u64> {
        if self.snap_count >= 32 {
            return Err(Error::OutOfMemory);
        }
        // Derive a new snap ID: max existing + 1.
        let new_id = self.context.snaps().iter().copied().max().unwrap_or(0) + 1;
        self.context.insert(new_id)?;
        self.context.seq += 1;
        let entry = SnapEntry::new(new_id, name)?;
        self.snaps[self.snap_count] = entry;
        self.snap_count += 1;
        self.cap_gen = self.cap_gen.wrapping_add(1);
        Ok(new_id)
    }

    /// Deletes a snapshot by name.
    ///
    /// Removes the named entry and the snap ID from the context.
    pub fn delete_snap(&mut self, name: &[u8]) -> Result<()> {
        let pos = self.snaps[..self.snap_count]
            .iter()
            .position(|s| s.active && s.name() == name)
            .ok_or(Error::NotFound)?;
        let snap_id = self.snaps[pos].snap_id;
        self.snaps[pos] = self.snaps[self.snap_count - 1];
        self.snaps[self.snap_count - 1] = SnapEntry::default();
        self.snap_count -= 1;
        self.context.remove(snap_id)?;
        self.context.seq += 1;
        self.cap_gen = self.cap_gen.wrapping_add(1);
        Ok(())
    }

    /// Looks up a snapshot entry by name.
    pub fn get_snap(&self, name: &[u8]) -> Option<&SnapEntry> {
        self.snaps[..self.snap_count]
            .iter()
            .find(|s| s.active && s.name() == name)
    }

    // ── Snap flush ────────────────────────────────────────────────────────────

    /// Returns `true` if `page_ctx` is stale relative to the realm's current
    /// context, meaning a snap flush is required before writing.
    ///
    /// A stale context has a sequence number lower than the realm's current
    /// context sequence.
    pub fn needs_snap_flush(&self, page_ctx: &SnapContext) -> bool {
        page_ctx.seq < self.context.seq
    }

    /// Calculates the snap context that should be associated with a new write.
    ///
    /// Returns the realm's current context.
    pub fn write_context(&self) -> &SnapContext {
        &self.context
    }

    // ── Child realm management ────────────────────────────────────────────────

    /// Registers a child realm by its inode number.
    pub fn add_child(&mut self, child_ino: u64) -> Result<()> {
        if self.child_count >= MAX_REALM_CHILDREN {
            return Err(Error::OutOfMemory);
        }
        if self.children[..self.child_count].contains(&child_ino) {
            return Err(Error::AlreadyExists);
        }
        self.children[self.child_count] = child_ino;
        self.child_count += 1;
        Ok(())
    }

    /// Removes a child realm by its inode number.
    pub fn remove_child(&mut self, child_ino: u64) -> Result<()> {
        let pos = self.children[..self.child_count]
            .iter()
            .position(|&c| c == child_ino)
            .ok_or(Error::NotFound)?;
        self.children[pos] = self.children[self.child_count - 1];
        self.child_count -= 1;
        Ok(())
    }

    /// Returns the child realm inode numbers.
    pub fn children(&self) -> &[u64] {
        &self.children[..self.child_count]
    }

    /// Returns the number of named snapshots in this realm.
    pub const fn snap_count(&self) -> usize {
        self.snap_count
    }

    /// Iterates over all active named snapshots.
    pub fn iter_snaps<F: FnMut(&SnapEntry)>(&self, mut f: F) {
        for s in &self.snaps[..self.snap_count] {
            if s.active {
                f(s);
            }
        }
    }
}

// ── SnapRealmTree ─────────────────────────────────────────────────────────────

/// Global registry of all snap realms, forming the snapshot realm tree.
pub struct SnapRealmTree {
    /// Flat array of realm slots.
    realms: [SnapRealm; MAX_SNAP_REALMS],
    /// Number of active realms.
    count: usize,
    /// Inode number of the root realm (0 = not yet initialised).
    pub root_ino: u64,
}

impl Default for SnapRealmTree {
    fn default() -> Self {
        Self {
            realms: [const { SnapRealm::new(0, 0) }; MAX_SNAP_REALMS],
            count: 0,
            root_ino: 0,
        }
    }
}

impl SnapRealmTree {
    /// Creates a new, empty realm tree.
    pub fn new() -> Self {
        Self::default()
    }

    // ── Realm registration ────────────────────────────────────────────────────

    /// Adds a new realm to the tree.
    ///
    /// Returns [`Error::AlreadyExists`] if a realm with the same `ino` already
    /// exists, or [`Error::OutOfMemory`] if the table is full.
    pub fn add_realm(&mut self, realm: SnapRealm) -> Result<()> {
        if self.realms[..self.count]
            .iter()
            .any(|r| r.active && r.ino == realm.ino)
        {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_SNAP_REALMS {
            return Err(Error::OutOfMemory);
        }
        let ino = realm.ino;
        let parent_ino = realm.parent_ino;
        self.realms[self.count] = realm;
        self.count += 1;
        // Register as child of parent.
        if parent_ino != 0 {
            let parent_pos = self.realms[..self.count - 1]
                .iter()
                .position(|r| r.active && r.ino == parent_ino);
            if let Some(p) = parent_pos {
                let _ = self.realms[p].add_child(ino);
            }
        } else {
            self.root_ino = ino;
        }
        Ok(())
    }

    /// Returns a reference to the realm with the given inode number.
    pub fn get(&self, ino: u64) -> Option<&SnapRealm> {
        self.realms[..self.count]
            .iter()
            .find(|r| r.active && r.ino == ino)
    }

    /// Returns a mutable reference to the realm with the given inode number.
    pub fn get_mut(&mut self, ino: u64) -> Option<&mut SnapRealm> {
        self.realms[..self.count]
            .iter_mut()
            .find(|r| r.active && r.ino == ino)
    }

    /// Removes a realm from the tree.
    ///
    /// Does not recursively remove children — callers must re-parent them.
    pub fn remove_realm(&mut self, ino: u64) -> Result<()> {
        let pos = self.realms[..self.count]
            .iter()
            .position(|r| r.active && r.ino == ino)
            .ok_or(Error::NotFound)?;
        let parent_ino = self.realms[pos].parent_ino;
        let last = core::mem::replace(&mut self.realms[self.count - 1], SnapRealm::new(0, 0));
        self.realms[pos] = last;
        self.count -= 1;
        // Unregister from parent.
        if parent_ino != 0 {
            let parent_pos = self.realms[..self.count]
                .iter()
                .position(|r| r.active && r.ino == parent_ino);
            if let Some(p) = parent_pos {
                let _ = self.realms[p].remove_child(ino);
            }
        }
        Ok(())
    }

    // ── Hierarchy navigation ──────────────────────────────────────────────────

    /// Walks the parent chain from `ino` towards the root, calling `f` for
    /// each realm in order (starting at `ino`).
    ///
    /// Stops when the root is reached or `f` returns `false`.
    pub fn walk_to_root<F: FnMut(&SnapRealm) -> bool>(&self, ino: u64, mut f: F) {
        let mut current = ino;
        loop {
            if let Some(r) = self.get(current) {
                if !f(r) {
                    break;
                }
                if r.parent_ino == 0 {
                    break;
                }
                current = r.parent_ino;
            } else {
                break;
            }
        }
    }

    /// Builds a merged [`SnapContext`] for `ino` by collecting all snap IDs
    /// visible from `ino` up to the root.
    pub fn merged_context(&self, ino: u64) -> SnapContext {
        let mut merged = SnapContext::default();
        self.walk_to_root(ino, |r| {
            for &snap_id in r.context.snaps() {
                if !merged.contains(snap_id) && merged.num_snaps < SNAP_CTX_MAX_SNAPS {
                    // Ignore insertion errors (context full).
                    let _ = merged.insert(snap_id);
                }
            }
            if r.context.seq > merged.seq {
                merged.seq = r.context.seq;
            }
            true // keep walking
        });
        merged
    }

    /// Returns the total number of active realms.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the tree contains no realms.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}
