// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Anonymous VMA chain management.
//!
//! Implements the `anon_vma` / `anon_vma_chain` model used for
//! copy-on-write (CoW) fork sharing of anonymous pages. Each
//! process VMA containing anonymous pages links to one or more
//! `anon_vma` structures through `anon_vma_chain` nodes.
//!
//! # Architecture
//!
//! - [`AnonVmaNode`] — shared structure representing a CoW group
//! - [`AnonVmaChainEntry`] — links a VMA to its `anon_vma`
//! - [`AnonVmaInterval`] — interval-tree node for efficient
//!   range lookup
//! - [`AnonVmaChainManager`] — top-level manager for fork
//!   prepare/link and munmap unlink
//!
//! ## Fork workflow
//!
//! 1. Parent calls `prepare_fork` — allocates child anon_vma
//! 2. For each VMA, `link_chain` creates a chain from the child
//!    VMA to both parent and child anon_vma structures
//! 3. On munmap, `unlink_chain` removes the chain and decrements
//!    refcounts; when an anon_vma's refcount reaches zero it is
//!    freed
//!
//! Reference: Linux `mm/rmap.c` (anon_vma sections).

use oncrix_lib::{Error, Result};

// -- Constants

/// Maximum number of anon_vma nodes.
const MAX_ANON_VMAS: usize = 256;

/// Maximum number of chain entries.
const MAX_CHAINS: usize = 512;

/// Maximum number of interval-tree entries.
const MAX_INTERVALS: usize = 256;

// -- AnonVmaNode

/// An anonymous VMA node representing a CoW sharing group.
///
/// Created when a process first touches anonymous memory and
/// inherited/shared across `fork()`.
#[derive(Debug, Clone, Copy)]
pub struct AnonVmaNode {
    /// Unique identifier.
    pub id: u64,
    /// Root anon_vma ID (top of the hierarchy).
    pub root_id: u64,
    /// Parent anon_vma ID (0 if root).
    pub parent_id: u64,
    /// Reference count (chains pointing here).
    pub refcount: u32,
    /// Degree (number of child anon_vma nodes).
    pub degree: u32,
    /// Number of chains linked to this node.
    pub chain_count: u32,
    /// Whether this node is active.
    pub active: bool,
}

impl AnonVmaNode {
    const fn empty() -> Self {
        Self {
            id: 0,
            root_id: 0,
            parent_id: 0,
            refcount: 0,
            degree: 0,
            chain_count: 0,
            active: false,
        }
    }

    /// Increment refcount.
    pub fn get(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    /// Decrement refcount. Returns true if zero.
    pub fn put(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount == 0
    }
}

impl Default for AnonVmaNode {
    fn default() -> Self {
        Self::empty()
    }
}

// -- AnonVmaChainEntry

/// A chain entry linking a VMA to an anon_vma.
///
/// After fork the child VMA has chains to both parent's and
/// its own anon_vma.
#[derive(Debug, Clone, Copy)]
pub struct AnonVmaChainEntry {
    /// Owning process ID.
    pub pid: u64,
    /// Start address of the VMA.
    pub vma_start: u64,
    /// End address of the VMA.
    pub vma_end: u64,
    /// Index into the anon_vma array.
    pub anon_vma_idx: usize,
    /// Composite VMA identifier.
    pub vma_id: u64,
    /// Whether this entry is active.
    pub active: bool,
}

impl AnonVmaChainEntry {
    const fn empty() -> Self {
        Self {
            pid: 0,
            vma_start: 0,
            vma_end: 0,
            anon_vma_idx: 0,
            vma_id: 0,
            active: false,
        }
    }
}

impl Default for AnonVmaChainEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -- AnonVmaInterval

/// Interval-tree node for range-based anon_vma lookup.
///
/// Allows efficient queries of the form "which anon_vma chains
/// overlap the virtual address range [start, end)?"
#[derive(Debug, Clone, Copy)]
pub struct AnonVmaInterval {
    /// Start of the interval (virtual address).
    pub start: u64,
    /// End of the interval (exclusive).
    pub end: u64,
    /// Chain entry index this interval covers.
    pub chain_idx: usize,
    /// Subtree maximum end (for interval-tree queries).
    pub max_end: u64,
    /// Whether this node is active.
    pub active: bool,
}

impl AnonVmaInterval {
    const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            chain_idx: 0,
            max_end: 0,
            active: false,
        }
    }
}

impl Default for AnonVmaInterval {
    fn default() -> Self {
        Self::empty()
    }
}

// -- AnonVmaChainStats

/// Statistics for the anon_vma chain subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct AnonVmaChainStats {
    /// Total anon_vma allocations.
    pub vma_allocs: u64,
    /// Total anon_vma frees.
    pub vma_frees: u64,
    /// Total chain links created.
    pub chains_linked: u64,
    /// Total chain unlinks.
    pub chains_unlinked: u64,
    /// Total fork prepare calls.
    pub fork_prepares: u64,
    /// Total interval-tree lookups.
    pub interval_lookups: u64,
}

// -- AnonVmaChainManager

/// Top-level manager for anon_vma and anon_vma_chain structures.
pub struct AnonVmaChainManager {
    /// Anon_vma nodes.
    nodes: [AnonVmaNode; MAX_ANON_VMAS],
    /// Next node ID.
    next_id: u64,
    /// Number of active nodes.
    node_count: usize,
    /// Chain entries.
    chains: [AnonVmaChainEntry; MAX_CHAINS],
    /// Number of active chains.
    chain_count: usize,
    /// Interval-tree entries.
    intervals: [AnonVmaInterval; MAX_INTERVALS],
    /// Number of active intervals.
    interval_count: usize,
    /// Statistics.
    stats: AnonVmaChainStats,
}

impl AnonVmaChainManager {
    /// Create a new, empty manager.
    pub const fn new() -> Self {
        Self {
            nodes: [const { AnonVmaNode::empty() }; MAX_ANON_VMAS],
            next_id: 1,
            node_count: 0,
            chains: [const { AnonVmaChainEntry::empty() }; MAX_CHAINS],
            chain_count: 0,
            intervals: [const { AnonVmaInterval::empty() }; MAX_INTERVALS],
            interval_count: 0,
            stats: AnonVmaChainStats {
                vma_allocs: 0,
                vma_frees: 0,
                chains_linked: 0,
                chains_unlinked: 0,
                fork_prepares: 0,
                interval_lookups: 0,
            },
        }
    }

    /// Allocate a new anon_vma node. Returns its index.
    pub fn alloc_anon_vma(&mut self, parent_id: u64) -> Result<usize> {
        let idx = self
            .nodes
            .iter()
            .position(|n| !n.active)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id += 1;
        let root_id = if parent_id == 0 {
            id
        } else {
            self.nodes
                .iter()
                .find(|n| n.active && n.id == parent_id)
                .map(|n| n.root_id)
                .unwrap_or(id)
        };
        if parent_id != 0 {
            for node in &mut self.nodes {
                if node.active && node.id == parent_id {
                    node.degree += 1;
                    break;
                }
            }
        }
        self.nodes[idx] = AnonVmaNode {
            id,
            root_id,
            parent_id,
            refcount: 1,
            degree: 0,
            chain_count: 0,
            active: true,
        };
        self.node_count += 1;
        self.stats.vma_allocs += 1;
        Ok(idx)
    }

    /// Free an anon_vma node by index.
    pub fn free_anon_vma(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_ANON_VMAS {
            return Err(Error::InvalidArgument);
        }
        if !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        if self.nodes[idx].refcount > 0 {
            return Err(Error::Busy);
        }
        self.nodes[idx].active = false;
        self.node_count = self.node_count.saturating_sub(1);
        self.stats.vma_frees += 1;
        Ok(())
    }

    /// Link a VMA to an anon_vma via a chain entry.
    ///
    /// Also inserts an interval-tree entry for the VMA range.
    pub fn link_chain(
        &mut self,
        pid: u64,
        anon_vma_idx: usize,
        vma_start: u64,
        vma_end: u64,
    ) -> Result<usize> {
        if anon_vma_idx >= MAX_ANON_VMAS || !self.nodes[anon_vma_idx].active {
            return Err(Error::InvalidArgument);
        }
        let chain_idx = self
            .chains
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;
        let vma_id = pid.wrapping_mul(0x1000) ^ vma_start;
        self.chains[chain_idx] = AnonVmaChainEntry {
            pid,
            vma_start,
            vma_end,
            anon_vma_idx,
            vma_id,
            active: true,
        };
        self.chain_count += 1;
        self.nodes[anon_vma_idx].chain_count += 1;
        self.nodes[anon_vma_idx].get();
        self.stats.chains_linked += 1;
        // Insert interval entry.
        self.insert_interval(vma_start, vma_end, chain_idx)?;
        Ok(chain_idx)
    }

    /// Unlink a chain entry by index.
    pub fn unlink_chain(&mut self, chain_idx: usize) -> Result<()> {
        if chain_idx >= MAX_CHAINS {
            return Err(Error::InvalidArgument);
        }
        if !self.chains[chain_idx].active {
            return Err(Error::NotFound);
        }
        let av_idx = self.chains[chain_idx].anon_vma_idx;
        self.chains[chain_idx].active = false;
        self.chain_count = self.chain_count.saturating_sub(1);
        self.stats.chains_unlinked += 1;
        // Remove interval for this chain.
        self.remove_interval(chain_idx);
        if av_idx < MAX_ANON_VMAS && self.nodes[av_idx].active {
            self.nodes[av_idx].chain_count = self.nodes[av_idx].chain_count.saturating_sub(1);
            let _ = self.nodes[av_idx].put();
        }
        Ok(())
    }

    /// Prepare for fork: allocate a child anon_vma under the
    /// parent, link the child VMA to both parent and child.
    ///
    /// Returns `(child_anon_vma_idx, parent_chain, child_chain)`.
    pub fn prepare_fork(
        &mut self,
        parent_anon_vma_idx: usize,
        child_pid: u64,
        vma_start: u64,
        vma_end: u64,
    ) -> Result<(usize, usize, usize)> {
        self.stats.fork_prepares += 1;
        if parent_anon_vma_idx >= MAX_ANON_VMAS || !self.nodes[parent_anon_vma_idx].active {
            return Err(Error::InvalidArgument);
        }
        let parent_id = self.nodes[parent_anon_vma_idx].id;
        let child_av_idx = self.alloc_anon_vma(parent_id)?;
        // Chain child VMA to parent anon_vma.
        let parent_chain = self.link_chain(child_pid, parent_anon_vma_idx, vma_start, vma_end)?;
        // Chain child VMA to child anon_vma.
        let child_chain = self.link_chain(child_pid, child_av_idx, vma_start, vma_end)?;
        Ok((child_av_idx, parent_chain, child_chain))
    }

    /// Lookup chains overlapping a virtual address range.
    ///
    /// Returns a count of matching chains (up to `max`).
    pub fn interval_lookup(&mut self, start: u64, end: u64, max: usize) -> usize {
        self.stats.interval_lookups += 1;
        let mut count = 0usize;
        for iv in &self.intervals {
            if !iv.active {
                continue;
            }
            if iv.start < end && iv.end > start {
                count += 1;
                if count >= max {
                    break;
                }
            }
        }
        count
    }

    /// Return the anon_vma node at a given index.
    pub fn node(&self, idx: usize) -> Result<&AnonVmaNode> {
        if idx >= MAX_ANON_VMAS {
            return Err(Error::InvalidArgument);
        }
        if !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.nodes[idx])
    }

    /// Number of active anon_vma nodes.
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Number of active chain entries.
    pub fn chain_count(&self) -> usize {
        self.chain_count
    }

    /// Return statistics.
    pub fn stats(&self) -> &AnonVmaChainStats {
        &self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = AnonVmaChainStats::default();
    }

    // -- Internal helpers

    fn insert_interval(&mut self, start: u64, end: u64, chain_idx: usize) -> Result<()> {
        let idx = self
            .intervals
            .iter()
            .position(|iv| !iv.active)
            .ok_or(Error::OutOfMemory)?;
        self.intervals[idx] = AnonVmaInterval {
            start,
            end,
            chain_idx,
            max_end: end,
            active: true,
        };
        self.interval_count += 1;
        Ok(())
    }

    fn remove_interval(&mut self, chain_idx: usize) {
        for iv in &mut self.intervals {
            if iv.active && iv.chain_idx == chain_idx {
                iv.active = false;
                self.interval_count = self.interval_count.saturating_sub(1);
                break;
            }
        }
    }
}

impl Default for AnonVmaChainManager {
    fn default() -> Self {
        Self::new()
    }
}
