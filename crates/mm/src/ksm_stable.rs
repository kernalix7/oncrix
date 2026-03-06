// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! KSM stable tree management.
//!
//! Kernel Same-page Merging (KSM) maintains a "stable tree" of pages
//! that have been verified identical and merged into single copy-on-
//! write pages. The stable tree is a red-black tree keyed by page
//! content checksum. This module manages the stable tree nodes, tracks
//! merged page mappings, and handles CoW break-out for writes to
//! merged pages.
//!
//! # Design
//!
//! ```text
//!  KSM scanner finds identical pages A, B
//!       → compute checksum of A
//!       → insert/find in stable tree
//!       → merge B into A's physical page (CoW)
//!       → StableNode tracks A's PFN + list of virtual mappings
//!
//!  write to merged page
//!       → CoW fault → allocate new page → copy → unmerge from node
//! ```
//!
//! # Key Types
//!
//! - [`StableNode`] — a node in the stable tree
//! - [`StableMergeEntry`] — a VMA mapping merged into a stable node
//! - [`StableTree`] — the stable tree (flat sorted array)
//! - [`StableTreeStats`] — merge statistics
//!
//! Reference: Linux `mm/ksm.c` (stable_tree_*).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum nodes in the stable tree.
const MAX_STABLE_NODES: usize = 512;

/// Maximum merge entries per stable node.
const MAX_MERGES_PER_NODE: usize = 16;

/// Checksum indicating uninitialized.
const INVALID_CHECKSUM: u64 = 0;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// StableMergeEntry
// -------------------------------------------------------------------

/// A VMA mapping that shares a merged stable page.
#[derive(Debug, Clone, Copy)]
pub struct StableMergeEntry {
    /// Process ID owning this mapping.
    pid: u64,
    /// Virtual address in the process's address space.
    vaddr: u64,
    /// Whether this entry is valid.
    valid: bool,
}

impl StableMergeEntry {
    /// Create a new merge entry.
    pub const fn new(pid: u64, vaddr: u64) -> Self {
        Self {
            pid,
            vaddr,
            valid: true,
        }
    }

    /// Return the process ID.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Return the virtual address.
    pub const fn vaddr(&self) -> u64 {
        self.vaddr
    }

    /// Check whether the entry is valid.
    pub const fn is_valid(&self) -> bool {
        self.valid
    }

    /// Invalidate this entry.
    pub fn invalidate(&mut self) {
        self.valid = false;
    }
}

impl Default for StableMergeEntry {
    fn default() -> Self {
        Self {
            pid: 0,
            vaddr: 0,
            valid: false,
        }
    }
}

// -------------------------------------------------------------------
// StableNode
// -------------------------------------------------------------------

/// A node in the KSM stable tree.
pub struct StableNode {
    /// Content checksum (key for tree lookup).
    checksum: u64,
    /// Physical frame number of the shared page.
    pfn: u64,
    /// Merge entries (virtual mappings sharing this page).
    merges: [StableMergeEntry; MAX_MERGES_PER_NODE],
    /// Number of valid merge entries.
    merge_count: usize,
    /// Whether this node is active.
    active: bool,
}

impl StableNode {
    /// Create a new stable node.
    pub const fn new(checksum: u64, pfn: u64) -> Self {
        Self {
            checksum,
            pfn,
            merges: [const {
                StableMergeEntry {
                    pid: 0,
                    vaddr: 0,
                    valid: false,
                }
            }; MAX_MERGES_PER_NODE],
            merge_count: 0,
            active: true,
        }
    }

    /// Return the checksum.
    pub const fn checksum(&self) -> u64 {
        self.checksum
    }

    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the number of merge entries.
    pub const fn merge_count(&self) -> usize {
        self.merge_count
    }

    /// Check whether the node is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Return the physical address.
    pub const fn phys_addr(&self) -> u64 {
        self.pfn * PAGE_SIZE
    }

    /// Add a merge entry.
    pub fn add_merge(&mut self, pid: u64, vaddr: u64) -> Result<()> {
        if self.merge_count >= MAX_MERGES_PER_NODE {
            return Err(Error::OutOfMemory);
        }
        // Find a free slot.
        for idx in 0..MAX_MERGES_PER_NODE {
            if !self.merges[idx].is_valid() {
                self.merges[idx] = StableMergeEntry::new(pid, vaddr);
                self.merge_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a merge entry by pid+vaddr.
    pub fn remove_merge(&mut self, pid: u64, vaddr: u64) -> Result<()> {
        for idx in 0..MAX_MERGES_PER_NODE {
            if self.merges[idx].is_valid()
                && self.merges[idx].pid() == pid
                && self.merges[idx].vaddr() == vaddr
            {
                self.merges[idx].invalidate();
                self.merge_count = self.merge_count.saturating_sub(1);
                if self.merge_count == 0 {
                    self.active = false;
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Get a merge entry by index.
    pub fn get_merge(&self, index: usize) -> Option<&StableMergeEntry> {
        if index < MAX_MERGES_PER_NODE && self.merges[index].is_valid() {
            Some(&self.merges[index])
        } else {
            None
        }
    }

    /// Deactivate the node (remove all merges).
    pub fn deactivate(&mut self) {
        for idx in 0..MAX_MERGES_PER_NODE {
            self.merges[idx].invalidate();
        }
        self.merge_count = 0;
        self.active = false;
    }
}

impl Default for StableNode {
    fn default() -> Self {
        Self {
            checksum: INVALID_CHECKSUM,
            pfn: 0,
            merges: [const {
                StableMergeEntry {
                    pid: 0,
                    vaddr: 0,
                    valid: false,
                }
            }; MAX_MERGES_PER_NODE],
            merge_count: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// StableTreeStats
// -------------------------------------------------------------------

/// KSM stable tree statistics.
#[derive(Debug, Clone, Copy)]
pub struct StableTreeStats {
    /// Number of active stable nodes.
    pub nodes: u64,
    /// Total merge entries across all nodes.
    pub total_merges: u64,
    /// Pages saved by merging.
    pub pages_saved: u64,
    /// Merge operations performed.
    pub merge_ops: u64,
    /// Unmerge operations (CoW break-out).
    pub unmerge_ops: u64,
}

impl StableTreeStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            nodes: 0,
            total_merges: 0,
            pages_saved: 0,
            merge_ops: 0,
            unmerge_ops: 0,
        }
    }

    /// Memory saved in bytes.
    pub const fn bytes_saved(&self) -> u64 {
        self.pages_saved * PAGE_SIZE
    }
}

impl Default for StableTreeStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// StableTree
// -------------------------------------------------------------------

/// The KSM stable tree (flat sorted array implementation).
pub struct StableTree {
    /// Nodes sorted by checksum.
    nodes: [StableNode; MAX_STABLE_NODES],
    /// Number of active nodes.
    count: usize,
    /// Statistics.
    stats: StableTreeStats,
}

impl StableTree {
    /// Create a new empty stable tree.
    pub fn new() -> Self {
        Self {
            nodes: core::array::from_fn(|_| StableNode::default()),
            count: 0,
            stats: StableTreeStats::new(),
        }
    }

    /// Return the number of active nodes.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &StableTreeStats {
        &self.stats
    }

    /// Find a node by checksum using binary search.
    pub fn find(&self, checksum: u64) -> Option<usize> {
        let mut lo = 0usize;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let mid_chk = self.nodes[mid].checksum();
            if mid_chk == checksum {
                return Some(mid);
            } else if mid_chk < checksum {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        None
    }

    /// Insert a new node or find existing.
    pub fn insert_or_find(&mut self, checksum: u64, pfn: u64) -> Result<usize> {
        // Check if already exists.
        if let Some(idx) = self.find(checksum) {
            return Ok(idx);
        }

        if self.count >= MAX_STABLE_NODES {
            return Err(Error::OutOfMemory);
        }

        // Find insertion point (keep sorted).
        let mut pos = self.count;
        for idx in 0..self.count {
            if self.nodes[idx].checksum() > checksum {
                pos = idx;
                break;
            }
        }

        // Shift elements to make room.
        let mut idx = self.count;
        while idx > pos {
            self.nodes.swap(idx, idx - 1);
            idx -= 1;
        }

        self.nodes[pos] = StableNode::new(checksum, pfn);
        self.count += 1;
        self.stats.nodes += 1;
        Ok(pos)
    }

    /// Merge a mapping into a stable node.
    pub fn merge(&mut self, checksum: u64, pfn: u64, pid: u64, vaddr: u64) -> Result<()> {
        let idx = self.insert_or_find(checksum, pfn)?;
        self.nodes[idx].add_merge(pid, vaddr)?;
        self.stats.total_merges += 1;
        self.stats.pages_saved += 1;
        self.stats.merge_ops += 1;
        Ok(())
    }

    /// Unmerge a mapping (CoW break-out).
    pub fn unmerge(&mut self, checksum: u64, pid: u64, vaddr: u64) -> Result<()> {
        let idx = match self.find(checksum) {
            Some(i) => i,
            None => return Err(Error::NotFound),
        };
        self.nodes[idx].remove_merge(pid, vaddr)?;
        self.stats.total_merges = self.stats.total_merges.saturating_sub(1);
        self.stats.pages_saved = self.stats.pages_saved.saturating_sub(1);
        self.stats.unmerge_ops += 1;

        if !self.nodes[idx].is_active() {
            self.stats.nodes = self.stats.nodes.saturating_sub(1);
        }
        Ok(())
    }

    /// Get a node by index.
    pub fn get(&self, index: usize) -> Result<&StableNode> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.nodes[index])
    }
}

impl Default for StableTree {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Compute a simple checksum for page content.
pub fn page_checksum(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset
    for byte in data {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3); // FNV prime
    }
    hash
}

/// Return the memory saved by KSM in bytes.
pub const fn memory_saved(tree: &StableTree) -> u64 {
    tree.stats().bytes_saved()
}

/// Return the number of shared pages.
pub const fn shared_pages(tree: &StableTree) -> u64 {
    tree.stats().pages_saved
}
