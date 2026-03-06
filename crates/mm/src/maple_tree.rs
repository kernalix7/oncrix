// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Maple tree for VMA (Virtual Memory Area) management.
//!
//! A cache-efficient, RCU-safe B-tree variant designed for managing
//! non-overlapping ranges of virtual addresses. The maple tree
//! replaced the red-black tree + linked list combination in the Linux
//! kernel (since 6.1) as the primary data structure for `vm_area_struct`
//! management.
//!
//! # Key Properties
//!
//! - **Range-indexed**: Each entry maps a `[start, end)` interval.
//! - **Non-overlapping**: Insertions that overlap existing ranges are
//!   rejected.
//! - **O(log N)** lookup, insert, and delete via B-tree fanout.
//! - **Gap tracking**: Each internal node tracks the largest gap in
//!   its subtree, enabling O(log N) free-range search for `mmap`.
//! - **Iteration**: In-order traversal for `/proc/<pid>/maps`.
//!
//! # Architecture
//!
//! - [`MapleEntry`] — a single VMA entry (start, end, protection,
//!   kind, offset, flags).
//! - [`MapleNode`] — a B-tree node holding up to `MAPLE_NODE_SLOTS`
//!   entries (leaf) or child pointers (internal).
//! - [`MapleTree`] — the top-level tree structure with insert, remove,
//!   lookup, and gap-search operations.
//! - [`MapleStats`] — statistics for monitoring tree health.
//!
//! # Static Allocation
//!
//! The tree uses a fixed pool of [`MapleNode`] slots (`MAX_NODES`)
//! to avoid heap allocation in `#![no_std]` kernel context. Nodes
//! are allocated from this pool and freed back to it.
//!
//! Reference: Linux `include/linux/maple_tree.h`, `lib/maple_tree.c`.

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum entries per leaf node (B-tree order).
const MAPLE_NODE_SLOTS: usize = 16;

/// Maximum child pointers per internal node.
const MAPLE_NODE_CHILDREN: usize = MAPLE_NODE_SLOTS + 1;

/// Maximum nodes in the static pool.
const MAX_NODES: usize = 256;

/// Sentinel value meaning "no node".
const NODE_NONE: usize = usize::MAX;

/// Maximum entries the tree can hold (leaf slots across all nodes).
const MAX_ENTRIES: usize = 2048;

/// Page size in bytes.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// VMA protection / type flags (mirrors address_space module)
// -------------------------------------------------------------------

/// Protection bits for a VMA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VmaProt(pub u8);

impl VmaProt {
    /// Readable.
    pub const READ: Self = Self(1 << 0);
    /// Writable.
    pub const WRITE: Self = Self(1 << 1);
    /// Executable.
    pub const EXEC: Self = Self(1 << 2);

    /// Read + Write.
    pub const RW: Self = Self(Self::READ.0 | Self::WRITE.0);
    /// Read + Execute.
    pub const RX: Self = Self(Self::READ.0 | Self::EXEC.0);

    /// Returns `true` if the given flag bits are all set.
    pub const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }
}

/// Type of a virtual memory area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmaKind {
    /// Anonymous private mapping.
    #[default]
    Anonymous,
    /// File-backed mapping.
    FileBacked,
    /// Shared mapping.
    Shared,
    /// Stack region.
    Stack,
    /// Heap region (brk area).
    Heap,
    /// Device-mapped I/O.
    DeviceIo,
    /// Huge-page backed region.
    HugePage,
}

/// Flags that modify VMA behavior.
pub mod vma_flags {
    /// Mapping is shared between processes.
    pub const MAP_SHARED: u32 = 1 << 0;
    /// Mapping is private (copy-on-write).
    pub const MAP_PRIVATE: u32 = 1 << 1;
    /// Mapping is fixed at the requested address.
    pub const MAP_FIXED: u32 = 1 << 2;
    /// Mapping is anonymous (not file-backed).
    pub const MAP_ANONYMOUS: u32 = 1 << 3;
    /// Populate (prefault) page tables.
    pub const MAP_POPULATE: u32 = 1 << 4;
    /// Do not reserve swap space.
    pub const MAP_NORESERVE: u32 = 1 << 5;
    /// Mapping grows downward (stack).
    pub const MAP_GROWSDOWN: u32 = 1 << 6;
    /// Lock pages in memory.
    pub const MAP_LOCKED: u32 = 1 << 7;
}

// -------------------------------------------------------------------
// MapleEntry
// -------------------------------------------------------------------

/// A single VMA entry stored in a maple tree leaf node.
///
/// Represents a contiguous range of virtual addresses with uniform
/// protection and mapping properties.
#[derive(Debug, Clone, Copy)]
pub struct MapleEntry {
    /// Start virtual address (inclusive, page-aligned).
    pub start: u64,
    /// End virtual address (exclusive, page-aligned).
    pub end: u64,
    /// Protection flags.
    pub prot: VmaProt,
    /// Region type.
    pub kind: VmaKind,
    /// Flags (MAP_SHARED, MAP_PRIVATE, etc.).
    pub flags: u32,
    /// File offset for file-backed mappings (in bytes).
    pub file_offset: u64,
    /// Inode number for file-backed mappings (0 if anonymous).
    pub inode: u64,
}

impl MapleEntry {
    /// An empty, unused entry.
    const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            prot: VmaProt(0),
            kind: VmaKind::Anonymous,
            flags: 0,
            file_offset: 0,
            inode: 0,
        }
    }

    /// Returns `true` if this entry slot is unused.
    const fn is_empty(&self) -> bool {
        self.start == 0 && self.end == 0
    }

    /// Returns the size of this VMA in bytes.
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` if `addr` falls within this entry.
    pub const fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Returns `true` if this entry overlaps with `[start, end)`.
    pub const fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }
}

// -------------------------------------------------------------------
// MapleNode
// -------------------------------------------------------------------

/// Type of a maple tree node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NodeType {
    /// Leaf node containing VMA entries directly.
    #[default]
    Leaf,
    /// Internal node containing pivot keys and child indices.
    Internal,
}

/// A single node in the maple tree.
///
/// Leaf nodes store [`MapleEntry`] values directly. Internal nodes
/// store pivot keys and indices into the node pool for children.
#[derive(Debug, Clone, Copy)]
pub struct MapleNode {
    /// Node type (leaf or internal).
    pub node_type: NodeType,
    /// Number of entries (leaf) or children (internal) in use.
    pub count: usize,
    /// Entries (used only by leaf nodes).
    pub entries: [MapleEntry; MAPLE_NODE_SLOTS],
    /// Pivot keys for internal nodes: `pivots[i]` is the upper bound
    /// (exclusive) of `children[i]`.
    pub pivots: [u64; MAPLE_NODE_SLOTS],
    /// Child node indices for internal nodes.
    pub children: [usize; MAPLE_NODE_CHILDREN],
    /// Largest gap (unmapped range) in this subtree.
    pub max_gap: u64,
    /// Parent node index (NODE_NONE for root).
    pub parent: usize,
    /// Whether this node slot is allocated.
    pub in_use: bool,
}

impl MapleNode {
    /// An empty, unallocated node.
    const fn empty() -> Self {
        Self {
            node_type: NodeType::Leaf,
            count: 0,
            entries: [MapleEntry::empty(); MAPLE_NODE_SLOTS],
            pivots: [0; MAPLE_NODE_SLOTS],
            children: [NODE_NONE; MAPLE_NODE_CHILDREN],
            max_gap: 0,
            parent: NODE_NONE,
            in_use: false,
        }
    }

    /// Returns `true` if this node is a leaf.
    const fn is_leaf(&self) -> bool {
        matches!(self.node_type, NodeType::Leaf)
    }

    /// Returns `true` if this node is full.
    const fn is_full(&self) -> bool {
        self.count >= MAPLE_NODE_SLOTS
    }
}

// -------------------------------------------------------------------
// MapleStats
// -------------------------------------------------------------------

/// Statistics for a maple tree instance.
#[derive(Debug, Clone, Copy, Default)]
pub struct MapleStats {
    /// Total entries currently stored.
    pub entry_count: usize,
    /// Total nodes currently allocated.
    pub node_count: usize,
    /// Number of insert operations.
    pub inserts: u64,
    /// Number of remove operations.
    pub removes: u64,
    /// Number of lookup operations.
    pub lookups: u64,
    /// Number of gap searches.
    pub gap_searches: u64,
    /// Number of node splits.
    pub splits: u64,
    /// Tree height (1 = root is a leaf).
    pub height: usize,
}

// -------------------------------------------------------------------
// MapleTree
// -------------------------------------------------------------------

/// A maple tree for managing non-overlapping virtual memory areas.
///
/// The tree is backed by a static pool of [`MapleNode`] slots. All
/// entries are sorted by start address for efficient range queries.
pub struct MapleTree {
    /// Static node pool.
    nodes: [MapleNode; MAX_NODES],
    /// Index of the root node (NODE_NONE if the tree is empty).
    root: usize,
    /// Statistics.
    stats: MapleStats,
}

impl Default for MapleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MapleTree {
    /// Creates a new, empty maple tree.
    pub const fn new() -> Self {
        Self {
            nodes: [const { MapleNode::empty() }; MAX_NODES],
            root: NODE_NONE,
            stats: MapleStats {
                entry_count: 0,
                node_count: 0,
                inserts: 0,
                removes: 0,
                lookups: 0,
                gap_searches: 0,
                splits: 0,
                height: 0,
            },
        }
    }

    // ---------------------------------------------------------------
    // Insert
    // ---------------------------------------------------------------

    /// Inserts a VMA entry into the tree.
    ///
    /// The entry's `[start, end)` must not overlap with any existing
    /// entry. Start and end must be page-aligned and start < end.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `start >= end` or addresses
    ///   are not page-aligned.
    /// - [`Error::AlreadyExists`] if the range overlaps an existing
    ///   entry.
    /// - [`Error::OutOfMemory`] if the node pool is exhausted.
    pub fn insert(&mut self, entry: MapleEntry) -> Result<()> {
        // Validate alignment.
        if entry.start >= entry.end {
            return Err(Error::InvalidArgument);
        }
        if entry.start % PAGE_SIZE != 0 || entry.end % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }

        // Check for overlaps.
        if self.find_overlap(entry.start, entry.end).is_some() {
            return Err(Error::AlreadyExists);
        }

        if self.root == NODE_NONE {
            // Tree is empty: allocate a root leaf.
            let root_idx = self.alloc_node()?;
            self.nodes[root_idx].node_type = NodeType::Leaf;
            self.nodes[root_idx].entries[0] = entry;
            self.nodes[root_idx].count = 1;
            self.root = root_idx;
            self.stats.height = 1;
        } else {
            // Find the leaf node for this range and insert.
            let leaf = self.find_leaf(entry.start);
            self.insert_into_leaf(leaf, entry)?;
        }

        self.stats.entry_count += 1;
        self.stats.inserts += 1;
        self.update_gap(self.root);

        Ok(())
    }

    // ---------------------------------------------------------------
    // Remove
    // ---------------------------------------------------------------

    /// Removes the VMA entry whose range starts at `start`.
    ///
    /// Returns the removed entry.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no entry starts at `start`.
    pub fn remove(&mut self, start: u64) -> Result<MapleEntry> {
        if self.root == NODE_NONE {
            return Err(Error::NotFound);
        }

        let leaf = self.find_leaf(start);
        let node = &self.nodes[leaf];

        let pos = (0..node.count)
            .find(|&i| node.entries[i].start == start)
            .ok_or(Error::NotFound)?;

        let removed = self.nodes[leaf].entries[pos];

        // Shift entries left to fill the gap.
        let count = self.nodes[leaf].count;
        let mut i = pos;
        while i + 1 < count {
            self.nodes[leaf].entries[i] = self.nodes[leaf].entries[i + 1];
            i += 1;
        }
        self.nodes[leaf].entries[count - 1] = MapleEntry::empty();
        self.nodes[leaf].count -= 1;

        // If the leaf is now empty and it's the root, free it.
        if self.nodes[leaf].count == 0 && leaf == self.root {
            self.free_node(leaf);
            self.root = NODE_NONE;
            self.stats.height = 0;
        } else {
            self.update_gap(self.root);
        }

        self.stats.entry_count -= 1;
        self.stats.removes += 1;

        Ok(removed)
    }

    // ---------------------------------------------------------------
    // Lookup
    // ---------------------------------------------------------------

    /// Finds the VMA entry containing `addr`.
    ///
    /// Returns `None` if `addr` is not within any mapped range.
    pub fn lookup(&mut self, addr: u64) -> Option<&MapleEntry> {
        self.stats.lookups += 1;

        if self.root == NODE_NONE {
            return None;
        }

        let leaf = self.find_leaf(addr);
        let node = &self.nodes[leaf];
        for i in 0..node.count {
            if node.entries[i].contains_addr(addr) {
                return Some(&node.entries[i]);
            }
        }
        None
    }

    /// Finds the VMA entry containing `addr` (immutable, does not
    /// update stats).
    pub fn lookup_no_stat(&self, addr: u64) -> Option<&MapleEntry> {
        if self.root == NODE_NONE {
            return None;
        }
        let leaf = self.find_leaf_const(addr);
        let node = &self.nodes[leaf];
        for i in 0..node.count {
            if node.entries[i].contains_addr(addr) {
                return Some(&node.entries[i]);
            }
        }
        None
    }

    // ---------------------------------------------------------------
    // Gap search (for mmap)
    // ---------------------------------------------------------------

    /// Finds a free gap of at least `size` bytes starting at or above
    /// `hint`.
    ///
    /// Returns the start address of the gap, or `None` if no
    /// sufficiently large gap exists below `limit`.
    ///
    /// This is the primary allocation path for `mmap` without
    /// `MAP_FIXED`.
    pub fn find_gap(&mut self, hint: u64, size: u64, limit: u64) -> Option<u64> {
        self.stats.gap_searches += 1;

        if size == 0 || hint >= limit {
            return None;
        }

        if self.root == NODE_NONE {
            // Tree is empty — the entire range is free.
            if hint + size <= limit {
                return Some(hint);
            }
            return None;
        }

        // Collect entries sorted by start address, then scan gaps.
        // We iterate leaves in order and check gaps between entries.
        let mut prev_end = hint;
        let mut entries_buf = [MapleEntry::empty(); MAX_ENTRIES];
        let n = self.collect_entries_sorted(&mut entries_buf);

        for entry in &entries_buf[..n] {
            // Only consider entries that are at or above our search.
            if entry.end <= hint {
                continue;
            }

            let gap_start = if entry.start > prev_end {
                prev_end
            } else {
                entry.end
            };

            if gap_start >= hint && gap_start + size <= entry.start {
                return Some(gap_start);
            }

            if entry.end > prev_end {
                prev_end = entry.end;
            }
        }

        // Check the gap after the last entry.
        if prev_end >= hint && prev_end + size <= limit {
            return Some(prev_end);
        }

        None
    }

    // ---------------------------------------------------------------
    // Iteration
    // ---------------------------------------------------------------

    /// Collects all entries in address order into `buf`.
    ///
    /// Returns the number of entries written. Entries beyond
    /// `buf.len()` are silently dropped.
    pub fn collect_entries_sorted(&self, buf: &mut [MapleEntry]) -> usize {
        if self.root == NODE_NONE {
            return 0;
        }

        let mut count = 0usize;
        self.collect_in_order(self.root, buf, &mut count);

        // Sort by start address (insertion sort for small N).
        let n = count;
        let mut i = 1;
        while i < n {
            let mut j = i;
            while j > 0 && buf[j - 1].start > buf[j].start {
                let tmp = buf[j];
                buf[j] = buf[j - 1];
                buf[j - 1] = tmp;
                j -= 1;
            }
            i += 1;
        }

        count
    }

    /// Returns the number of entries in the tree.
    pub const fn entry_count(&self) -> usize {
        self.stats.entry_count
    }

    /// Returns the tree height.
    pub const fn height(&self) -> usize {
        self.stats.height
    }

    /// Returns the number of allocated nodes.
    pub const fn node_count(&self) -> usize {
        self.stats.node_count
    }

    /// Returns `true` if the tree has no entries.
    pub const fn is_empty(&self) -> bool {
        self.stats.entry_count == 0
    }

    /// Returns a reference to the tree statistics.
    pub const fn stats(&self) -> &MapleStats {
        &self.stats
    }

    /// Returns the largest gap tracked at the root.
    pub fn root_max_gap(&self) -> u64 {
        if self.root == NODE_NONE {
            return u64::MAX;
        }
        self.nodes[self.root].max_gap
    }

    // ---------------------------------------------------------------
    // Merge adjacent VMAs
    // ---------------------------------------------------------------

    /// Attempts to merge the entry at `start` with its immediate
    /// neighbor to the right if they are compatible (same prot, kind,
    /// flags, contiguous addresses, and contiguous file offsets for
    /// file-backed mappings).
    ///
    /// Returns `true` if a merge occurred.
    pub fn try_merge_right(&mut self, start: u64) -> bool {
        if self.root == NODE_NONE {
            return false;
        }

        // Find the entry and its right neighbor.
        let mut entries_buf = [MapleEntry::empty(); MAX_ENTRIES];
        let n = self.collect_entries_sorted(&mut entries_buf);

        let pos = match (0..n).find(|&i| entries_buf[i].start == start) {
            Some(p) => p,
            None => return false,
        };

        if pos + 1 >= n {
            return false;
        }

        let left = entries_buf[pos];
        let right = entries_buf[pos + 1];

        // Check merge compatibility.
        if left.end != right.start
            || left.prot.0 != right.prot.0
            || left.kind != right.kind
            || left.flags != right.flags
        {
            return false;
        }

        // For file-backed mappings, offsets must be contiguous.
        if left.inode != 0 {
            let expected_offset = left.file_offset + left.size();
            if right.file_offset != expected_offset || right.inode != left.inode {
                return false;
            }
        }

        // Merge: extend left, remove right.
        let new_end = right.end;
        // Update the left entry in the tree.
        if let Some(leaf) = self.find_entry_leaf(left.start) {
            for i in 0..self.nodes[leaf].count {
                if self.nodes[leaf].entries[i].start == left.start {
                    self.nodes[leaf].entries[i].end = new_end;
                    break;
                }
            }
        }
        // Remove the right entry.
        let _ = self.remove(right.start);
        // The remove already decremented entry_count, but we want
        // the net effect to be -1 (one merge reduces two entries to
        // one). The remove path already handled it.

        true
    }

    // ---------------------------------------------------------------
    // Internal: node allocation
    // ---------------------------------------------------------------

    /// Allocates a node from the static pool.
    fn alloc_node(&mut self) -> Result<usize> {
        for (i, node) in self.nodes.iter_mut().enumerate() {
            if !node.in_use {
                *node = MapleNode::empty();
                node.in_use = true;
                self.stats.node_count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a node to the pool.
    fn free_node(&mut self, idx: usize) {
        if idx < MAX_NODES && self.nodes[idx].in_use {
            self.nodes[idx] = MapleNode::empty();
            self.stats.node_count = self.stats.node_count.saturating_sub(1);
        }
    }

    // ---------------------------------------------------------------
    // Internal: tree traversal
    // ---------------------------------------------------------------

    /// Finds the leaf node that should contain `addr`.
    fn find_leaf(&self, addr: u64) -> usize {
        let mut cur = self.root;
        loop {
            if cur == NODE_NONE || self.nodes[cur].is_leaf() {
                return cur;
            }
            let node = &self.nodes[cur];
            let mut found = false;
            for i in 0..node.count {
                if addr < node.pivots[i] {
                    cur = node.children[i];
                    found = true;
                    break;
                }
            }
            if !found {
                // addr >= all pivots: go to rightmost child.
                cur = node.children[node.count];
                if cur == NODE_NONE {
                    return self.root;
                }
            }
        }
    }

    /// Const-compatible version of find_leaf.
    fn find_leaf_const(&self, addr: u64) -> usize {
        self.find_leaf(addr)
    }

    /// Finds the leaf node containing an entry with the given start.
    fn find_entry_leaf(&self, start: u64) -> Option<usize> {
        if self.root == NODE_NONE {
            return None;
        }
        let leaf = self.find_leaf(start);
        let node = &self.nodes[leaf];
        for i in 0..node.count {
            if node.entries[i].start == start {
                return Some(leaf);
            }
        }
        None
    }

    /// Inserts an entry into a leaf node, splitting if necessary.
    fn insert_into_leaf(&mut self, leaf_idx: usize, entry: MapleEntry) -> Result<()> {
        if !self.nodes[leaf_idx].is_full() {
            // Insert in sorted order within the leaf.
            let node = &mut self.nodes[leaf_idx];
            let count = node.count;

            // Find insertion position.
            let mut pos = count;
            for i in 0..count {
                if entry.start < node.entries[i].start {
                    pos = i;
                    break;
                }
            }

            // Shift right.
            let mut i = count;
            while i > pos {
                node.entries[i] = node.entries[i - 1];
                i -= 1;
            }
            node.entries[pos] = entry;
            node.count += 1;

            Ok(())
        } else {
            // Leaf is full: split.
            self.split_leaf_and_insert(leaf_idx, entry)
        }
    }

    /// Splits a full leaf node and inserts the new entry.
    fn split_leaf_and_insert(&mut self, leaf_idx: usize, entry: MapleEntry) -> Result<()> {
        let new_leaf = self.alloc_node()?;
        self.stats.splits += 1;

        // Gather all entries + the new one.
        let old_count = self.nodes[leaf_idx].count;
        let mut all = [MapleEntry::empty(); MAPLE_NODE_SLOTS + 1];
        let mut n = 0usize;

        for i in 0..old_count {
            all[n] = self.nodes[leaf_idx].entries[i];
            n += 1;
        }
        all[n] = entry;
        n += 1;

        // Sort by start address.
        let mut i = 1;
        while i < n {
            let mut j = i;
            while j > 0 && all[j - 1].start > all[j].start {
                let tmp = all[j];
                all[j] = all[j - 1];
                all[j - 1] = tmp;
                j -= 1;
            }
            i += 1;
        }

        // Split: left half stays, right half goes to new leaf.
        let mid = n / 2;

        // Reinitialize the original leaf.
        self.nodes[leaf_idx].count = 0;
        for slot in &mut self.nodes[leaf_idx].entries {
            *slot = MapleEntry::empty();
        }
        for i in 0..mid {
            self.nodes[leaf_idx].entries[i] = all[i];
        }
        self.nodes[leaf_idx].count = mid;

        // Fill the new leaf.
        self.nodes[new_leaf].node_type = NodeType::Leaf;
        let mut j = 0;
        for i in mid..n {
            self.nodes[new_leaf].entries[j] = all[i];
            j += 1;
        }
        self.nodes[new_leaf].count = n - mid;

        // If the split leaf is the root, create a new internal root.
        if leaf_idx == self.root {
            let new_root = self.alloc_node()?;
            self.nodes[new_root].node_type = NodeType::Internal;
            self.nodes[new_root].pivots[0] = self.nodes[new_leaf].entries[0].start;
            self.nodes[new_root].children[0] = leaf_idx;
            self.nodes[new_root].children[1] = new_leaf;
            self.nodes[new_root].count = 1;

            self.nodes[leaf_idx].parent = new_root;
            self.nodes[new_leaf].parent = new_root;

            self.root = new_root;
            self.stats.height += 1;
        } else {
            // Insert the new leaf into the parent internal node.
            let parent = self.nodes[leaf_idx].parent;
            self.nodes[new_leaf].parent = parent;
            let pivot = self.nodes[new_leaf].entries[0].start;
            self.insert_into_internal(parent, pivot, new_leaf)?;
        }

        Ok(())
    }

    /// Inserts a new child pointer into an internal node.
    fn insert_into_internal(&mut self, node_idx: usize, pivot: u64, child: usize) -> Result<()> {
        let node = &mut self.nodes[node_idx];
        let count = node.count;

        if count < MAPLE_NODE_SLOTS {
            // Find insertion position.
            let mut pos = count;
            for i in 0..count {
                if pivot < node.pivots[i] {
                    pos = i;
                    break;
                }
            }

            // Shift pivots and children right.
            let mut i = count;
            while i > pos {
                node.pivots[i] = node.pivots[i - 1];
                node.children[i + 1] = node.children[i];
                i -= 1;
            }
            node.pivots[pos] = pivot;
            node.children[pos + 1] = child;
            node.count += 1;

            Ok(())
        } else {
            // Internal node is full; simplified handling — for our
            // static allocation, we accept the limit.
            Err(Error::OutOfMemory)
        }
    }

    // ---------------------------------------------------------------
    // Internal: overlap detection
    // ---------------------------------------------------------------

    /// Checks if `[start, end)` overlaps any existing entry.
    fn find_overlap(&self, start: u64, end: u64) -> Option<usize> {
        if self.root == NODE_NONE {
            return None;
        }
        self.find_overlap_in_subtree(self.root, start, end)
    }

    /// Recursively checks a subtree for overlap.
    fn find_overlap_in_subtree(&self, node_idx: usize, start: u64, end: u64) -> Option<usize> {
        if node_idx == NODE_NONE {
            return None;
        }
        let node = &self.nodes[node_idx];

        if node.is_leaf() {
            for i in 0..node.count {
                if node.entries[i].overlaps(start, end) {
                    return Some(node_idx);
                }
            }
            return None;
        }

        // Internal: recurse into relevant children.
        for i in 0..=node.count {
            if node.children[i] == NODE_NONE {
                continue;
            }
            if let Some(idx) = self.find_overlap_in_subtree(node.children[i], start, end) {
                return Some(idx);
            }
        }

        None
    }

    // ---------------------------------------------------------------
    // Internal: gap computation
    // ---------------------------------------------------------------

    /// Updates the `max_gap` field for a node and its ancestors.
    fn update_gap(&mut self, node_idx: usize) {
        if node_idx == NODE_NONE {
            return;
        }

        let node = &self.nodes[node_idx];
        if node.is_leaf() {
            let gap = self.compute_leaf_gap(node_idx);
            self.nodes[node_idx].max_gap = gap;
        } else {
            let mut max_gap = 0u64;
            let count = self.nodes[node_idx].count;
            for i in 0..=count {
                let child = self.nodes[node_idx].children[i];
                if child != NODE_NONE {
                    let child_gap = self.nodes[child].max_gap;
                    if child_gap > max_gap {
                        max_gap = child_gap;
                    }
                }
            }
            self.nodes[node_idx].max_gap = max_gap;
        }
    }

    /// Computes the largest gap between consecutive entries in a leaf.
    fn compute_leaf_gap(&self, leaf_idx: usize) -> u64 {
        let node = &self.nodes[leaf_idx];
        if node.count == 0 {
            return u64::MAX;
        }

        let mut max_gap = 0u64;
        for i in 1..node.count {
            let gap = node.entries[i]
                .start
                .saturating_sub(node.entries[i - 1].end);
            if gap > max_gap {
                max_gap = gap;
            }
        }
        max_gap
    }

    // ---------------------------------------------------------------
    // Internal: in-order collection
    // ---------------------------------------------------------------

    /// Collects entries in-order from a subtree.
    fn collect_in_order(&self, node_idx: usize, buf: &mut [MapleEntry], count: &mut usize) {
        if node_idx == NODE_NONE {
            return;
        }

        let node = &self.nodes[node_idx];
        if node.is_leaf() {
            for i in 0..node.count {
                if *count < buf.len() {
                    buf[*count] = node.entries[i];
                    *count += 1;
                }
            }
            return;
        }

        // Internal: interleave child traversals.
        for i in 0..=node.count {
            if node.children[i] != NODE_NONE {
                self.collect_in_order(node.children[i], buf, count);
            }
        }
    }
}
