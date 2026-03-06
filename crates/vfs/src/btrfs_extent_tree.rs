// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs extent tree management.
//!
//! Tracks the allocation state of every byte range on disk through a
//! B-tree keyed by `(bytenr, EXTENT_ITEM_KEY, num_bytes)`.  Each extent
//! item carries an inline back-reference list so the filesystem can find
//! all logical addresses that map to a given physical range.
//!
//! # Architecture
//!
//! ```text
//! ExtentTree (B-tree, key = bytenr)
//!   ├─ ExtentItem  bytenr=0x0010_0000  len=0x0004_0000  refs=1
//!   │    └─ DataRef { root=5, objectid=256, offset=0 }
//!   ├─ ExtentItem  bytenr=0x0014_0000  len=0x0001_0000  refs=2
//!   │    ├─ TreeRef { root=1 }
//!   │    └─ DataRef { root=5, objectid=300, offset=4096 }
//!   └─ …
//! ```
//!
//! # Delayed References
//!
//! Btrfs batches back-reference updates into a delayed-ref list to reduce
//! B-tree churn during a transaction.  [`DelayedRef`] and [`DelayedRefHead`]
//! model this mechanism; [`ExtentTree::process_delayed_refs`] drains the
//! list at transaction commit.
//!
//! # Structures
//!
//! - [`ExtentKey`]       — (bytenr, num_bytes) lookup key
//! - [`BackRefKind`]     — data ref vs tree block ref
//! - [`BackRef`]         — a single back-reference record
//! - [`ExtentItem`]      — one extent record with ref count and back-ref list
//! - [`DelayedRefOp`]    — add or drop a delayed reference
//! - [`DelayedRef`]      — a pending reference update
//! - [`DelayedRefHead`]  — per-extent delayed-ref queue
//! - [`ExtentTree`]      — the full extent tree

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────────────

/// Maximum extents in the tree.
const MAX_EXTENTS: usize = 256;

/// Maximum back-references per extent item.
const MAX_BACKREFS: usize = 8;

/// Maximum delayed-ref heads in the pending queue.
const MAX_DELAYED_HEADS: usize = 128;

/// Maximum delayed refs per head.
const MAX_DELAYED_REFS: usize = 16;

/// Minimum allocation unit (leaf block size = 4 KiB).
const MIN_ALLOC_UNIT: u64 = 4096;

// ── ExtentKey ───────────────────────────────────────────────────────────────

/// Lookup key for an extent item: physical byte range start + length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExtentKey {
    /// Physical byte offset on the block device.
    pub bytenr: u64,
    /// Length of the extent in bytes.
    pub num_bytes: u64,
}

impl ExtentKey {
    /// Construct a new extent key.
    pub const fn new(bytenr: u64, num_bytes: u64) -> Self {
        Self { bytenr, num_bytes }
    }
}

// ── BackRefKind ─────────────────────────────────────────────────────────────

/// Discriminates data back-references from tree-block back-references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackRefKind {
    /// Reference from a file data extent (root + objectid + offset).
    Data,
    /// Reference from a tree block (root only).
    Tree,
}

// ── BackRef ──────────────────────────────────────────────────────────────────

/// A single back-reference attached to an extent item.
#[derive(Debug, Clone, Copy)]
pub struct BackRef {
    /// Whether this back-ref slot is occupied.
    pub in_use: bool,
    /// Kind of reference.
    pub kind: BackRefKind,
    /// Subvolume/tree root that holds this reference.
    pub root: u64,
    /// Object ID (inode number) — only valid for [`BackRefKind::Data`].
    pub objectid: u64,
    /// File offset — only valid for [`BackRefKind::Data`].
    pub offset: u64,
}

impl BackRef {
    /// Create an empty (unused) back-ref slot.
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            kind: BackRefKind::Data,
            root: 0,
            objectid: 0,
            offset: 0,
        }
    }

    /// Create a data back-reference.
    pub const fn data(root: u64, objectid: u64, offset: u64) -> Self {
        Self {
            in_use: true,
            kind: BackRefKind::Data,
            root,
            objectid,
            offset,
        }
    }

    /// Create a tree-block back-reference.
    pub const fn tree(root: u64) -> Self {
        Self {
            in_use: true,
            kind: BackRefKind::Tree,
            root,
            objectid: 0,
            offset: 0,
        }
    }
}

impl Default for BackRef {
    fn default() -> Self {
        Self::empty()
    }
}

// ── ExtentItem ───────────────────────────────────────────────────────────────

/// One record in the extent tree describing a single physical byte range.
#[derive(Debug, Clone, Copy)]
pub struct ExtentItem {
    /// Physical location and size.
    pub key: ExtentKey,
    /// Total reference count (sum of all back-ref multiplicities).
    pub refs: u64,
    /// Inline back-reference array.
    pub backrefs: [BackRef; MAX_BACKREFS],
    /// Number of valid back-ref entries.
    pub backref_count: usize,
    /// Generation of the transaction that created this extent.
    pub generation: u64,
    /// Flags (data extent vs. tree block extent).
    pub flags: u64,
    /// Whether this slot in the tree is occupied.
    pub in_use: bool,
}

impl ExtentItem {
    /// Create an empty (unused) extent slot.
    pub fn empty() -> Self {
        Self {
            key: ExtentKey::new(0, 0),
            refs: 0,
            backrefs: [const { BackRef::empty() }; MAX_BACKREFS],
            backref_count: 0,
            generation: 0,
            flags: 0,
            in_use: false,
        }
    }

    /// Create a new live extent item.
    pub fn new(key: ExtentKey, generation: u64, flags: u64) -> Self {
        Self {
            key,
            refs: 1,
            backrefs: [const { BackRef::empty() }; MAX_BACKREFS],
            backref_count: 0,
            generation,
            flags,
            in_use: true,
        }
    }

    /// Add a back-reference to this extent.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the back-ref array is full.
    pub fn add_backref(&mut self, bref: BackRef) -> Result<()> {
        if self.backref_count >= MAX_BACKREFS {
            return Err(Error::OutOfMemory);
        }
        self.backrefs[self.backref_count] = bref;
        self.backref_count += 1;
        self.refs += 1;
        Ok(())
    }

    /// Remove a back-reference matching `root`, `objectid`, `offset`.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no matching back-ref exists.
    pub fn drop_backref(&mut self, root: u64, objectid: u64, offset: u64) -> Result<()> {
        let pos = self.backrefs[..self.backref_count]
            .iter()
            .position(|b| {
                b.in_use && b.root == root && b.objectid == objectid && b.offset == offset
            })
            .ok_or(Error::NotFound)?;
        self.backrefs[pos] = BackRef::empty();
        // Compact the array.
        self.backrefs.copy_within(pos + 1..self.backref_count, pos);
        self.backrefs[self.backref_count - 1] = BackRef::empty();
        self.backref_count -= 1;
        self.refs = self.refs.saturating_sub(1);
        Ok(())
    }
}

// ── DelayedRefOp ─────────────────────────────────────────────────────────────

/// Whether a delayed reference adds or removes a reference count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelayedRefOp {
    /// Increment reference count.
    Add,
    /// Decrement reference count (free if reaches zero).
    Drop,
}

// ── DelayedRef ───────────────────────────────────────────────────────────────

/// A single pending reference update, queued until transaction commit.
#[derive(Debug, Clone, Copy)]
pub struct DelayedRef {
    /// Whether this slot is occupied.
    pub in_use: bool,
    /// Add or drop.
    pub op: DelayedRefOp,
    /// Kind of back-reference.
    pub kind: BackRefKind,
    /// Owning tree root.
    pub root: u64,
    /// Object identifier (inode).
    pub objectid: u64,
    /// File byte offset.
    pub offset: u64,
}

impl DelayedRef {
    /// Create an empty delayed-ref slot.
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            op: DelayedRefOp::Add,
            kind: BackRefKind::Data,
            root: 0,
            objectid: 0,
            offset: 0,
        }
    }
}

impl Default for DelayedRef {
    fn default() -> Self {
        Self::empty()
    }
}

// ── DelayedRefHead ───────────────────────────────────────────────────────────

/// Per-extent queue of pending reference updates.
#[derive(Debug)]
pub struct DelayedRefHead {
    /// Physical extent start.
    pub bytenr: u64,
    /// Physical extent length.
    pub num_bytes: u64,
    /// Whether this head slot is occupied.
    pub in_use: bool,
    /// Pending refs for this extent.
    pub refs: [DelayedRef; MAX_DELAYED_REFS],
    /// Number of occupied ref slots.
    pub ref_count: usize,
}

impl DelayedRefHead {
    /// Create an empty head slot.
    pub fn empty() -> Self {
        Self {
            bytenr: 0,
            num_bytes: 0,
            in_use: false,
            refs: [const { DelayedRef::empty() }; MAX_DELAYED_REFS],
            ref_count: 0,
        }
    }

    /// Create a new live head for the extent `(bytenr, num_bytes)`.
    pub fn new(bytenr: u64, num_bytes: u64) -> Self {
        Self {
            bytenr,
            num_bytes,
            in_use: true,
            refs: [const { DelayedRef::empty() }; MAX_DELAYED_REFS],
            ref_count: 0,
        }
    }

    /// Append a delayed ref to this head.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the per-head queue is full.
    pub fn push(&mut self, dr: DelayedRef) -> Result<()> {
        if self.ref_count >= MAX_DELAYED_REFS {
            return Err(Error::OutOfMemory);
        }
        self.refs[self.ref_count] = dr;
        self.ref_count += 1;
        Ok(())
    }
}

// ── ExtentTree ───────────────────────────────────────────────────────────────

/// The btrfs extent tree: sorted array of [`ExtentItem`]s plus a delayed-ref
/// queue.
///
/// In production btrfs this is a persistent on-disk B-tree; here we use a
/// fixed in-memory array for zero-alloc kernel operation.
pub struct ExtentTree {
    /// Sorted extent item storage (sorted by `key.bytenr`).
    items: [ExtentItem; MAX_EXTENTS],
    /// Number of live items.
    count: usize,
    /// Current transaction generation.
    generation: u64,
    /// Delayed-ref head queue.
    delayed_heads: [DelayedRefHead; MAX_DELAYED_HEADS],
    /// Number of live delayed-ref heads.
    delayed_count: usize,
    /// Total bytes allocated (sum of all live extent lengths).
    allocated_bytes: u64,
}

impl ExtentTree {
    /// Create an empty extent tree.
    pub fn new() -> Self {
        Self {
            items: core::array::from_fn(|_| ExtentItem::empty()),
            count: 0,
            generation: 1,
            delayed_heads: core::array::from_fn(|_| DelayedRefHead::empty()),
            delayed_count: 0,
            allocated_bytes: 0,
        }
    }

    /// Current transaction generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Total allocated bytes tracked by this tree.
    pub fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes
    }

    // ── Lookup ──────────────────────────────────────────────────────────────

    /// Look up the extent item at exactly `bytenr`.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no item with the given `bytenr` exists.
    pub fn lookup(&self, bytenr: u64) -> Result<&ExtentItem> {
        let pos = self.items[..self.count]
            .iter()
            .position(|it| it.in_use && it.key.bytenr == bytenr)
            .ok_or(Error::NotFound)?;
        Ok(&self.items[pos])
    }

    /// Look up for mutation.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no item with the given `bytenr` exists.
    pub fn lookup_mut(&mut self, bytenr: u64) -> Result<&mut ExtentItem> {
        let pos = self.items[..self.count]
            .iter()
            .position(|it| it.in_use && it.key.bytenr == bytenr)
            .ok_or(Error::NotFound)?;
        Ok(&mut self.items[pos])
    }

    // ── Insert ──────────────────────────────────────────────────────────────

    /// Insert a new extent item.
    ///
    /// # Errors
    ///
    /// - `AlreadyExists` if an extent at `bytenr` already exists.
    /// - `OutOfMemory` if the item array is full.
    /// - `InvalidArgument` if `num_bytes` is not a multiple of the minimum
    ///   allocation unit.
    pub fn insert(&mut self, bytenr: u64, num_bytes: u64, flags: u64) -> Result<()> {
        if num_bytes % MIN_ALLOC_UNIT != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.items[..self.count]
            .iter()
            .any(|it| it.in_use && it.key.bytenr == bytenr)
        {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_EXTENTS {
            return Err(Error::OutOfMemory);
        }
        let key = ExtentKey::new(bytenr, num_bytes);
        let item = ExtentItem::new(key, self.generation, flags);
        // Insert in sorted bytenr order.
        let insert_pos = self.items[..self.count]
            .iter()
            .position(|it| !it.in_use || it.key.bytenr > bytenr)
            .unwrap_or(self.count);
        if insert_pos < self.count {
            self.items
                .copy_within(insert_pos..self.count, insert_pos + 1);
        }
        self.items[insert_pos] = item;
        self.count += 1;
        self.allocated_bytes = self.allocated_bytes.saturating_add(num_bytes);
        Ok(())
    }

    // ── Delete ──────────────────────────────────────────────────────────────

    /// Delete an extent item entirely (reference count reaches zero).
    ///
    /// # Errors
    ///
    /// - `NotFound` if no item at `bytenr` exists.
    /// - `Busy` if the extent still has outstanding references.
    pub fn delete(&mut self, bytenr: u64) -> Result<()> {
        let pos = self.items[..self.count]
            .iter()
            .position(|it| it.in_use && it.key.bytenr == bytenr)
            .ok_or(Error::NotFound)?;
        if self.items[pos].refs > 0 {
            return Err(Error::Busy);
        }
        let freed = self.items[pos].key.num_bytes;
        self.items.copy_within(pos + 1..self.count, pos);
        self.count -= 1;
        self.allocated_bytes = self.allocated_bytes.saturating_sub(freed);
        Ok(())
    }

    // ── Back-reference operations ────────────────────────────────────────────

    /// Add a data back-reference to an existing extent.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the extent does not exist.
    /// - `OutOfMemory` if the back-ref array is full.
    pub fn add_data_ref(
        &mut self,
        bytenr: u64,
        root: u64,
        objectid: u64,
        offset: u64,
    ) -> Result<()> {
        let item = self.lookup_mut(bytenr)?;
        item.add_backref(BackRef::data(root, objectid, offset))
    }

    /// Drop a data back-reference from an existing extent.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the extent or the back-ref does not exist.
    pub fn drop_data_ref(
        &mut self,
        bytenr: u64,
        root: u64,
        objectid: u64,
        offset: u64,
    ) -> Result<()> {
        let item = self.lookup_mut(bytenr)?;
        item.drop_backref(root, objectid, offset)
    }

    // ── Delayed references ───────────────────────────────────────────────────

    /// Queue a delayed reference update for `(bytenr, num_bytes)`.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the delayed-head queue or per-head queue is full.
    pub fn queue_delayed_ref(&mut self, bytenr: u64, num_bytes: u64, dr: DelayedRef) -> Result<()> {
        // Find or create the head for this extent.
        let head_pos = self.delayed_heads[..self.delayed_count]
            .iter()
            .position(|h| h.in_use && h.bytenr == bytenr && h.num_bytes == num_bytes);
        let pos = if let Some(p) = head_pos {
            p
        } else {
            if self.delayed_count >= MAX_DELAYED_HEADS {
                return Err(Error::OutOfMemory);
            }
            let p = self.delayed_count;
            self.delayed_heads[p] = DelayedRefHead::new(bytenr, num_bytes);
            self.delayed_count += 1;
            p
        };
        self.delayed_heads[pos].push(dr)
    }

    /// Drain all delayed references into the extent tree.
    ///
    /// Should be called at transaction commit.  Each queued ref is applied
    /// to the corresponding extent item; extents whose ref count reaches zero
    /// are deleted.
    ///
    /// Returns the number of references processed.
    pub fn process_delayed_refs(&mut self) -> usize {
        let mut processed = 0usize;
        for hi in 0..self.delayed_count {
            if !self.delayed_heads[hi].in_use {
                continue;
            }
            let bytenr = self.delayed_heads[hi].bytenr;
            let num_bytes = self.delayed_heads[hi].num_bytes;
            let ref_count = self.delayed_heads[hi].ref_count;
            for ri in 0..ref_count {
                let dr = self.delayed_heads[hi].refs[ri];
                if !dr.in_use {
                    continue;
                }
                match dr.op {
                    DelayedRefOp::Add => {
                        let bref = if dr.kind == BackRefKind::Data {
                            BackRef::data(dr.root, dr.objectid, dr.offset)
                        } else {
                            BackRef::tree(dr.root)
                        };
                        // Best-effort; ignore errors (item may not exist yet).
                        if let Ok(item) = self.lookup_mut(bytenr) {
                            let _ = item.add_backref(bref);
                        }
                    }
                    DelayedRefOp::Drop => {
                        // Decrement; delete if zero.
                        let zero_refs = if let Ok(item) = self.lookup_mut(bytenr) {
                            let _ = item.drop_backref(dr.root, dr.objectid, dr.offset);
                            item.refs == 0
                        } else {
                            false
                        };
                        if zero_refs {
                            // Force-delete by zeroing ref count before calling delete.
                            if let Ok(item) = self.lookup_mut(bytenr) {
                                item.refs = 0;
                            }
                            let _ = self.delete(bytenr);
                        }
                    }
                }
                processed += 1;
            }
            // Mark head as processed.
            self.delayed_heads[hi] = DelayedRefHead::empty();
            let _ = num_bytes; // used in head construction above
        }
        self.delayed_count = 0;
        self.generation = self.generation.wrapping_add(1);
        processed
    }

    /// Number of live extent items.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for ExtentTree {
    fn default() -> Self {
        Self::new()
    }
}
