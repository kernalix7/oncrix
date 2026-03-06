// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs extent tree management.
//!
//! Implements the extent tree subsystem used by btrfs to track physical block
//! allocations, back-references, and block group accounting.
//!
//! # Design
//!
//! - [`ExtentItem`] — on-disk extent record (refs, generation, flags)
//! - [`InlineRef`] — back-reference variants (tree-block, shared, data, shared-data)
//! - [`ExtentKey`] — B-tree key: (bytenr, EXTENT_ITEM, size)
//! - [`BlockGroup`] — block group accounting (total/used/pinned/reserved)
//! - [`DelayedRef`] — delayed reference processing queue entry
//! - [`ExtentTree`] — full extent tree with alloc/free and back-ref walking

use oncrix_lib::{Error, Result};

extern crate alloc;
use alloc::vec::Vec;

// ── Constants ───────────────────────────────────────────────────────────────

/// Extent item type key value (in B-tree key).
pub const EXTENT_ITEM_KEY: u8 = 168;

/// Metadata extent item type.
pub const METADATA_ITEM_KEY: u8 = 169;

/// Block group item type.
pub const BLOCK_GROUP_ITEM_KEY: u8 = 192;

/// Maximum number of inline back-references per extent.
const MAX_INLINE_REFS: usize = 8;

/// Maximum tracked block groups.
const MAX_BLOCK_GROUPS: usize = 64;

/// Maximum entries in the delayed-ref queue.
const MAX_DELAYED_REFS: usize = 256;

/// Maximum tracked extents.
const MAX_EXTENTS: usize = 512;

// ── Extent flags ────────────────────────────────────────────────────────────

/// Flag: this extent holds file data.
pub const EXTENT_FLAG_DATA: u64 = 1 << 0;

/// Flag: this extent is a tree block (metadata).
pub const EXTENT_FLAG_TREE_BLOCK: u64 = 1 << 1;

/// Flag: this extent uses full back-reference (not compressed).
pub const EXTENT_FLAG_FULL_BACKREF: u64 = 1 << 8;

// ── InlineRef ────────────────────────────────────────────────────────────────

/// Back-reference variant stored inline in an [`ExtentItem`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InlineRef {
    /// Tree-block back-reference: the tree that owns this block.
    TreeBlockRef {
        /// Root object ID of the owning tree.
        root: u64,
    },
    /// Shared tree-block back-reference (snapshot/clone).
    SharedBlockRef {
        /// Byte offset of the parent block.
        parent: u64,
    },
    /// Data extent back-reference: file inode + offset.
    ExtentDataRef {
        /// Root ID of the filesystem tree.
        root: u64,
        /// Inode object ID.
        objectid: u64,
        /// Byte offset within the inode.
        offset: u64,
        /// Reference count for this (root, ino, offset) triple.
        count: u32,
    },
    /// Shared data back-reference via parent block.
    SharedDataRef {
        /// Byte offset of the parent data block.
        parent: u64,
        /// Reference count.
        count: u32,
    },
}

impl InlineRef {
    /// Returns the reference count contributed by this inline ref.
    pub fn ref_count(&self) -> u32 {
        match self {
            InlineRef::TreeBlockRef { .. } => 1,
            InlineRef::SharedBlockRef { .. } => 1,
            InlineRef::ExtentDataRef { count, .. } => *count,
            InlineRef::SharedDataRef { count, .. } => *count,
        }
    }
}

// ── ExtentItem ───────────────────────────────────────────────────────────────

/// On-disk extent record (mirrors `struct btrfs_extent_item`).
#[derive(Debug, Clone)]
pub struct ExtentItem {
    /// Physical byte number of this extent.
    pub bytenr: u64,
    /// Size of this extent in bytes.
    pub num_bytes: u64,
    /// Reference count (sum of all back-refs).
    pub refs: u64,
    /// Generation at which the extent was allocated.
    pub generation: u64,
    /// Extent flags (EXTENT_FLAG_* constants).
    pub flags: u64,
    /// Inline back-references (up to MAX_INLINE_REFS).
    pub inline_refs: Vec<InlineRef>,
}

impl ExtentItem {
    /// Create a new extent item.
    pub fn new(bytenr: u64, num_bytes: u64, generation: u64, flags: u64) -> Self {
        Self {
            bytenr,
            num_bytes,
            refs: 0,
            generation,
            flags,
            inline_refs: Vec::new(),
        }
    }

    /// Returns true if this is a data extent.
    pub fn is_data(&self) -> bool {
        self.flags & EXTENT_FLAG_DATA != 0
    }

    /// Returns true if this is a tree-block (metadata) extent.
    pub fn is_tree_block(&self) -> bool {
        self.flags & EXTENT_FLAG_TREE_BLOCK != 0
    }

    /// Returns true if this extent uses full back-references.
    pub fn has_full_backref(&self) -> bool {
        self.flags & EXTENT_FLAG_FULL_BACKREF != 0
    }

    /// Add an inline back-reference, merging with existing if possible.
    pub fn add_ref(&mut self, iref: InlineRef) -> Result<()> {
        // Try to merge with existing matching ref
        for existing in &mut self.inline_refs {
            match (existing, &iref) {
                (
                    InlineRef::ExtentDataRef {
                        root: er,
                        objectid: eo,
                        offset: ef,
                        count: ec,
                    },
                    InlineRef::ExtentDataRef {
                        root: nr,
                        objectid: no,
                        offset: nf,
                        count: nc,
                    },
                ) if er == nr && eo == no && ef == nf => {
                    *ec += nc;
                    self.refs += *nc as u64;
                    return Ok(());
                }
                (
                    InlineRef::SharedDataRef {
                        parent: ep,
                        count: ec,
                    },
                    InlineRef::SharedDataRef {
                        parent: np,
                        count: nc,
                    },
                ) if ep == np => {
                    *ec += nc;
                    self.refs += *nc as u64;
                    return Ok(());
                }
                _ => {}
            }
        }
        if self.inline_refs.len() >= MAX_INLINE_REFS {
            return Err(Error::OutOfMemory);
        }
        self.refs += iref.ref_count() as u64;
        self.inline_refs.push(iref);
        Ok(())
    }

    /// Drop a back-reference. Returns true if the extent should be freed.
    pub fn drop_ref(&mut self, iref: &InlineRef) -> Result<bool> {
        let mut found = false;
        let mut idx = 0;
        while idx < self.inline_refs.len() {
            let remove = match (&mut self.inline_refs[idx], iref) {
                (
                    InlineRef::ExtentDataRef {
                        root: er,
                        objectid: eo,
                        offset: ef,
                        count: ec,
                    },
                    InlineRef::ExtentDataRef {
                        root: nr,
                        objectid: no,
                        offset: nf,
                        count: nc,
                    },
                ) if er == nr && eo == no && ef == nf => {
                    if *ec <= *nc {
                        self.refs -= *ec as u64;
                        found = true;
                        true
                    } else {
                        *ec -= nc;
                        self.refs -= *nc as u64;
                        found = true;
                        false
                    }
                }
                (
                    InlineRef::SharedDataRef {
                        parent: ep,
                        count: ec,
                    },
                    InlineRef::SharedDataRef {
                        parent: np,
                        count: nc,
                    },
                ) if ep == np => {
                    if *ec <= *nc {
                        self.refs -= *ec as u64;
                        found = true;
                        true
                    } else {
                        *ec -= nc;
                        self.refs -= *nc as u64;
                        found = true;
                        false
                    }
                }
                (InlineRef::TreeBlockRef { root: er }, InlineRef::TreeBlockRef { root: nr })
                    if er == nr =>
                {
                    self.refs -= 1;
                    found = true;
                    true
                }
                (
                    InlineRef::SharedBlockRef { parent: ep },
                    InlineRef::SharedBlockRef { parent: np },
                ) if ep == np => {
                    self.refs -= 1;
                    found = true;
                    true
                }
                _ => false,
            };
            if remove {
                self.inline_refs.swap_remove(idx);
            } else {
                idx += 1;
            }
        }
        if !found {
            return Err(Error::NotFound);
        }
        Ok(self.refs == 0)
    }
}

// ── ExtentKey ────────────────────────────────────────────────────────────────

/// B-tree key for an extent tree entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExtentKey {
    /// Byte number of the extent (objectid in btrfs terms).
    pub bytenr: u64,
    /// Key type (EXTENT_ITEM_KEY or METADATA_ITEM_KEY).
    pub key_type: u8,
    /// Size of the extent in bytes (the "offset" field of the btrfs key).
    pub num_bytes: u64,
}

impl ExtentKey {
    /// Create a data/tree-block extent key.
    pub fn new(bytenr: u64, num_bytes: u64) -> Self {
        Self {
            bytenr,
            key_type: EXTENT_ITEM_KEY,
            num_bytes,
        }
    }

    /// Create a metadata extent key.
    pub fn metadata(bytenr: u64, num_bytes: u64) -> Self {
        Self {
            bytenr,
            key_type: METADATA_ITEM_KEY,
            num_bytes,
        }
    }
}

// ── BlockGroup ───────────────────────────────────────────────────────────────

/// Btrfs block group accounting.
#[derive(Debug, Clone, Copy)]
pub struct BlockGroup {
    /// Starting byte offset of this block group.
    pub start: u64,
    /// Length of this block group in bytes.
    pub length: u64,
    /// Total bytes available.
    pub total: u64,
    /// Bytes currently used (allocated extents).
    pub used: u64,
    /// Bytes pinned (freed but not yet reusable — pending transaction commit).
    pub pinned: u64,
    /// Bytes reserved for delalloc / prealloc.
    pub reserved: u64,
    /// Block group type flags (DATA/METADATA/SYSTEM).
    pub flags: u64,
    /// True if this block group is read-only.
    pub ro: bool,
}

impl BlockGroup {
    /// Create a new empty block group.
    pub fn new(start: u64, length: u64, flags: u64) -> Self {
        Self {
            start,
            length,
            total: length,
            used: 0,
            pinned: 0,
            reserved: 0,
            flags,
            ro: false,
        }
    }

    /// Bytes effectively available for new allocations.
    pub fn available(&self) -> u64 {
        self.total
            .saturating_sub(self.used + self.pinned + self.reserved)
    }

    /// Account for bytes being allocated in this group.
    pub fn account_alloc(&mut self, bytes: u64) -> Result<()> {
        if bytes > self.available() {
            return Err(Error::OutOfMemory);
        }
        self.used += bytes;
        Ok(())
    }

    /// Account for bytes being freed in this group (moves to pinned).
    pub fn account_free(&mut self, bytes: u64) {
        self.used = self.used.saturating_sub(bytes);
        self.pinned += bytes;
    }

    /// Unpin bytes after a transaction commits.
    pub fn unpin(&mut self, bytes: u64) {
        self.pinned = self.pinned.saturating_sub(bytes);
    }
}

// ── DelayedRef ───────────────────────────────────────────────────────────────

/// Action for a delayed reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelayedAction {
    /// Add a reference.
    Add,
    /// Drop a reference.
    Drop,
}

/// A delayed reference — an extent tree modification deferred to transaction commit.
#[derive(Debug, Clone)]
pub struct DelayedRef {
    /// Byte number of the extent being modified.
    pub bytenr: u64,
    /// Size of the extent.
    pub num_bytes: u64,
    /// The back-reference involved.
    pub iref: InlineRef,
    /// Action: add or drop.
    pub action: DelayedAction,
    /// Transaction ID that created this delayed ref.
    pub transid: u64,
}

impl DelayedRef {
    /// Create an add delayed ref.
    pub fn new_add(bytenr: u64, num_bytes: u64, iref: InlineRef, transid: u64) -> Self {
        Self {
            bytenr,
            num_bytes,
            iref,
            action: DelayedAction::Add,
            transid,
        }
    }

    /// Create a drop delayed ref.
    pub fn new_drop(bytenr: u64, num_bytes: u64, iref: InlineRef, transid: u64) -> Self {
        Self {
            bytenr,
            num_bytes,
            iref,
            action: DelayedAction::Drop,
            transid,
        }
    }
}

// ── ExtentTree ───────────────────────────────────────────────────────────────

/// Btrfs extent tree.
pub struct ExtentTree {
    extents: Vec<ExtentItem>,
    block_groups: [Option<BlockGroup>; MAX_BLOCK_GROUPS],
    delayed_refs: [Option<DelayedRef>; MAX_DELAYED_REFS],
    num_block_groups: usize,
    num_delayed_refs: usize,
    /// Current transaction ID.
    pub current_transid: u64,
    /// Total allocated bytes.
    pub total_allocated: u64,
}

impl ExtentTree {
    /// Create a new, empty extent tree.
    pub fn new() -> Self {
        Self {
            extents: Vec::new(),
            block_groups: core::array::from_fn(|_| None),
            delayed_refs: core::array::from_fn(|_| None),
            num_block_groups: 0,
            num_delayed_refs: 0,
            current_transid: 1,
            total_allocated: 0,
        }
    }

    /// Add a block group.
    pub fn add_block_group(&mut self, bg: BlockGroup) -> Result<usize> {
        if self.num_block_groups >= MAX_BLOCK_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.num_block_groups;
        self.block_groups[idx] = Some(bg);
        self.num_block_groups += 1;
        Ok(idx)
    }

    /// Allocate an extent.
    ///
    /// Finds a block group with sufficient space, allocates `num_bytes`
    /// from it, and inserts an [`ExtentItem`] into the tree.
    pub fn alloc_extent(
        &mut self,
        num_bytes: u64,
        flags: u64,
        iref: InlineRef,
    ) -> Result<ExtentKey> {
        // Find a suitable block group
        let mut found_bg: Option<usize> = None;
        let mut found_start = 0u64;

        for i in 0..self.num_block_groups {
            if let Some(bg) = &self.block_groups[i] {
                if !bg.ro && bg.flags & flags == flags && bg.available() >= num_bytes {
                    found_bg = Some(i);
                    found_start = bg.start + bg.used;
                    break;
                }
            }
        }

        let bg_idx = found_bg.ok_or(Error::OutOfMemory)?;
        if let Some(bg) = &mut self.block_groups[bg_idx] {
            bg.account_alloc(num_bytes)?;
        }

        // Compute bytenr and create extent item
        let bytenr = found_start;
        let mut item = ExtentItem::new(bytenr, num_bytes, self.current_transid, flags);
        item.add_ref(iref)?;

        self.total_allocated += num_bytes;

        // Insert sorted by bytenr
        let pos = self.extents.partition_point(|e| e.bytenr < bytenr);
        self.extents.insert(pos, item);

        Ok(ExtentKey::new(bytenr, num_bytes))
    }

    /// Free an extent by adding a drop delayed ref.
    ///
    /// The extent is not immediately removed; it is added to the delayed-ref
    /// queue and processed at transaction commit.
    pub fn free_extent(&mut self, key: &ExtentKey, iref: InlineRef) -> Result<()> {
        if self.num_delayed_refs >= MAX_DELAYED_REFS {
            // Flush a batch of delayed refs first
            self.flush_delayed_refs_batch(32)?;
        }
        let dref = DelayedRef::new_drop(key.bytenr, key.num_bytes, iref, self.current_transid);
        let idx = self.num_delayed_refs;
        self.delayed_refs[idx] = Some(dref);
        self.num_delayed_refs += 1;
        Ok(())
    }

    /// Process all pending delayed references.
    pub fn run_delayed_refs(&mut self) -> Result<()> {
        self.flush_delayed_refs_batch(MAX_DELAYED_REFS)
    }

    /// Look up an extent by byte number.
    pub fn lookup_extent(&self, bytenr: u64) -> Option<&ExtentItem> {
        let pos = self.extents.partition_point(|e| e.bytenr < bytenr);
        if pos < self.extents.len() && self.extents[pos].bytenr == bytenr {
            Some(&self.extents[pos])
        } else {
            None
        }
    }

    /// Walk all back-references of an extent.
    pub fn walk_backrefs(&self, bytenr: u64) -> Vec<InlineRef> {
        if let Some(item) = self.lookup_extent(bytenr) {
            item.inline_refs.clone()
        } else {
            Vec::new()
        }
    }

    /// Return the total bytes used across all block groups.
    pub fn used_bytes(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.num_block_groups {
            if let Some(bg) = &self.block_groups[i] {
                total += bg.used;
            }
        }
        total
    }

    /// Return the total bytes pinned across all block groups.
    pub fn pinned_bytes(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.num_block_groups {
            if let Some(bg) = &self.block_groups[i] {
                total += bg.pinned;
            }
        }
        total
    }

    /// Commit the current transaction: unpin freed extents, advance transid.
    pub fn commit_transaction(&mut self) -> Result<()> {
        self.run_delayed_refs()?;
        // Unpin all pinned bytes (simplified: unpin everything)
        for i in 0..self.num_block_groups {
            if let Some(bg) = &mut self.block_groups[i] {
                let pinned = bg.pinned;
                bg.unpin(pinned);
            }
        }
        self.current_transid += 1;
        Ok(())
    }

    // ── Private ──────────────────────────────────────────────────────────────

    fn flush_delayed_refs_batch(&mut self, count: usize) -> Result<()> {
        let to_process = count.min(self.num_delayed_refs);
        for i in 0..to_process {
            let dref = match self.delayed_refs[i].take() {
                Some(d) => d,
                None => continue,
            };
            self.apply_delayed_ref(dref)?;
        }
        // Compact
        let remaining = self.num_delayed_refs - to_process;
        for i in 0..remaining {
            self.delayed_refs[i] = self.delayed_refs[i + to_process].take();
        }
        self.num_delayed_refs = remaining;
        Ok(())
    }

    fn apply_delayed_ref(&mut self, dref: DelayedRef) -> Result<()> {
        let pos = self.extents.partition_point(|e| e.bytenr < dref.bytenr);
        if pos >= self.extents.len() || self.extents[pos].bytenr != dref.bytenr {
            return Err(Error::NotFound);
        }

        match dref.action {
            DelayedAction::Add => {
                self.extents[pos].add_ref(dref.iref)?;
            }
            DelayedAction::Drop => {
                let should_free = self.extents[pos].drop_ref(&dref.iref)?;
                if should_free {
                    let item = self.extents.remove(pos);
                    self.total_allocated -= item.num_bytes;
                    // Free space in the owning block group
                    for i in 0..self.num_block_groups {
                        if let Some(bg) = &mut self.block_groups[i] {
                            if item.bytenr >= bg.start && item.bytenr < bg.start + bg.length {
                                bg.account_free(item.num_bytes);
                                break;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl Default for ExtentTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the block group start for a given byte offset and group size.
pub fn bg_start(bytenr: u64, bg_size: u64) -> u64 {
    (bytenr / bg_size) * bg_size
}

/// Returns true if an extent item has full back-reference semantics.
pub fn extent_has_full_backref(flags: u64) -> bool {
    flags & EXTENT_FLAG_FULL_BACKREF != 0
}
