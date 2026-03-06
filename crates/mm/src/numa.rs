// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA-aware memory allocation.
//!
//! Provides topology-aware physical frame allocation across multiple
//! NUMA nodes. Each node manages its own bitmap of physical frames,
//! and the [`NumaTopology`] structure tracks inter-node distances to
//! enable intelligent fallback when a preferred node is exhausted.

use crate::addr::PhysAddr;
use oncrix_lib::{Error, Result};

/// Maximum number of NUMA nodes supported.
pub const MAX_NUMA_NODES: usize = 8;

/// Number of 4 KiB frames managed per NUMA node (16 MiB per node).
pub const FRAMES_PER_NODE: usize = 4096;

/// NUMA distance value for local (same-node) access.
pub const LOCAL_DISTANCE: u8 = 10;

/// NUMA distance value for remote (cross-node) access.
pub const REMOTE_DISTANCE: u8 = 20;

/// Number of `u64` words needed for the per-node bitmap.
const BITMAP_WORDS: usize = FRAMES_PER_NODE / 64;

/// NUMA memory allocation policy.
///
/// Determines how the allocator selects a node when allocating
/// physical frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumaPolicy {
    /// Allocate from the local (current) NUMA node only.
    Local,
    /// Round-robin allocation across all available nodes.
    Interleave,
    /// Prefer a specific node, falling back to nearest if exhausted.
    Preferred(u8),
    /// Bind allocation exclusively to a specific node; no fallback.
    Bind(u8),
}

/// A single NUMA node with its own bitmap frame allocator.
///
/// Manages up to [`FRAMES_PER_NODE`] physical frames starting at a
/// base physical address. Bit semantics: `0` = free, `1` = allocated.
#[derive(Clone)]
pub struct NumaNode {
    /// NUMA node identifier (0..MAX_NUMA_NODES-1).
    id: u8,
    /// Base physical address of this node's memory region.
    base: PhysAddr,
    /// Total number of frames managed by this node.
    frame_count: usize,
    /// Number of currently free frames.
    free_count: usize,
    /// Bitmap storage — one bit per frame.
    bitmap: [u64; BITMAP_WORDS],
    /// Whether this node slot is active (has been added).
    active: bool,
}

impl NumaNode {
    /// Create an inactive (empty) node placeholder.
    const fn inactive() -> Self {
        Self {
            id: 0,
            base: PhysAddr::new(0),
            frame_count: 0,
            free_count: 0,
            bitmap: [0u64; BITMAP_WORDS],
            active: false,
        }
    }

    /// Initialize this node with the given parameters.
    ///
    /// All frames start as free (bitmap bits = 0).
    fn init(&mut self, id: u8, base: PhysAddr, frame_count: usize) {
        let count = if frame_count > FRAMES_PER_NODE {
            FRAMES_PER_NODE
        } else {
            frame_count
        };
        self.id = id;
        self.base = base;
        self.frame_count = count;
        self.free_count = count;
        self.bitmap = [0u64; BITMAP_WORDS];
        self.active = true;

        // Mark frames beyond frame_count as allocated so they
        // are never handed out.
        let full_words = count / 64;
        let remaining_bits = count % 64;
        if remaining_bits != 0 {
            self.bitmap[full_words] = !((1u64 << remaining_bits) - 1);
        }
        for word in &mut self.bitmap[full_words + 1..] {
            *word = !0u64;
        }
    }

    /// Allocate a single frame from this node.
    ///
    /// Returns the physical address of the allocated frame, or
    /// `None` if no free frames remain.
    fn allocate(&mut self) -> Option<u64> {
        let words_needed = words_for(self.frame_count);
        for (word_idx, word) in self.bitmap[..words_needed].iter_mut().enumerate() {
            if *word == !0u64 {
                continue;
            }
            let bit = (*word).trailing_ones() as usize;
            let frame_idx = word_idx * 64 + bit;
            if frame_idx >= self.frame_count {
                return None;
            }
            *word |= 1 << bit;
            self.free_count = self.free_count.saturating_sub(1);
            return Some(self.base.as_u64() + (frame_idx as u64 * 4096));
        }
        None
    }

    /// Free a frame at the given physical address.
    ///
    /// Returns `true` if the address belonged to this node and was
    /// successfully freed, `false` otherwise.
    fn free(&mut self, addr: u64) -> bool {
        if addr < self.base.as_u64() {
            return false;
        }
        let offset = addr - self.base.as_u64();
        if offset % 4096 != 0 {
            return false;
        }
        let idx = (offset / 4096) as usize;
        if idx >= self.frame_count {
            return false;
        }
        let word = idx / 64;
        let bit = idx % 64;
        if self.bitmap[word] & (1 << bit) != 0 {
            self.bitmap[word] &= !(1 << bit);
            self.free_count += 1;
        }
        true
    }

    /// Check whether a physical address falls within this node.
    fn contains(&self, addr: u64) -> bool {
        if !self.active {
            return false;
        }
        if addr < self.base.as_u64() {
            return false;
        }
        let offset = addr - self.base.as_u64();
        (offset / 4096) < self.frame_count as u64
    }
}

/// NUMA topology manager with per-node frame allocators.
///
/// Tracks up to [`MAX_NUMA_NODES`] nodes and an inter-node distance
/// matrix. Supports allocation on a specific node or with automatic
/// nearest-node fallback.
pub struct NumaTopology {
    /// Per-node allocators.
    nodes: [NumaNode; MAX_NUMA_NODES],
    /// Number of active nodes.
    count: usize,
    /// Distance matrix: `distance[from * MAX_NUMA_NODES + to]`.
    ///
    /// Symmetric: `distance(a, b) == distance(b, a)`.
    /// Self-distance is [`LOCAL_DISTANCE`].
    distances: [u8; MAX_NUMA_NODES * MAX_NUMA_NODES],
}

impl Default for NumaTopology {
    fn default() -> Self {
        Self::new()
    }
}

impl NumaTopology {
    /// Create an empty NUMA topology with no nodes.
    pub const fn new() -> Self {
        // Initialize distance matrix: local = LOCAL_DISTANCE,
        // remote = REMOTE_DISTANCE.
        let mut distances = [REMOTE_DISTANCE; MAX_NUMA_NODES * MAX_NUMA_NODES];
        let mut i = 0;
        while i < MAX_NUMA_NODES {
            distances[i * MAX_NUMA_NODES + i] = LOCAL_DISTANCE;
            i += 1;
        }
        Self {
            nodes: [const { NumaNode::inactive() }; MAX_NUMA_NODES],
            count: 0,
            distances,
        }
    }

    /// Add a NUMA node to the topology.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the node ID exceeds
    /// [`MAX_NUMA_NODES`] or the slot is already occupied.
    /// Returns [`Error::OutOfMemory`] if `frame_count` is zero.
    pub fn add_node(&mut self, id: u8, base_addr: PhysAddr, frame_count: usize) -> Result<()> {
        let idx = id as usize;
        if idx >= MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        if self.nodes[idx].active {
            return Err(Error::InvalidArgument);
        }
        if frame_count == 0 {
            return Err(Error::OutOfMemory);
        }
        self.nodes[idx].init(id, base_addr, frame_count);
        self.count += 1;
        Ok(())
    }

    /// Set the NUMA distance between two nodes.
    ///
    /// The distance is set symmetrically: `distance(from, to)` and
    /// `distance(to, from)` are both updated.
    ///
    /// # Panics
    ///
    /// This method does not panic. Out-of-range node IDs are
    /// silently ignored.
    pub fn set_distance(&mut self, from: u8, to: u8, distance: u8) {
        let f = from as usize;
        let t = to as usize;
        if f >= MAX_NUMA_NODES || t >= MAX_NUMA_NODES {
            return;
        }
        self.distances[f * MAX_NUMA_NODES + t] = distance;
        self.distances[t * MAX_NUMA_NODES + f] = distance;
    }

    /// Allocate a physical frame on a specific NUMA node.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the node ID is invalid
    /// or inactive.
    /// Returns [`Error::OutOfMemory`] if the node has no free frames.
    pub fn alloc_on_node(&mut self, node_id: u8) -> Result<u64> {
        let idx = node_id as usize;
        if idx >= MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        let node = &mut self.nodes[idx];
        if !node.active {
            return Err(Error::InvalidArgument);
        }
        node.allocate().ok_or(Error::OutOfMemory)
    }

    /// Allocate a frame preferring `preferred_node`, falling back to
    /// the nearest node with available frames.
    ///
    /// Nodes are tried in order of increasing NUMA distance from the
    /// preferred node.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no node has free frames.
    /// Returns [`Error::InvalidArgument`] if `preferred_node` is
    /// out of range.
    pub fn alloc_nearest(&mut self, preferred_node: u8) -> Result<u64> {
        let pref = preferred_node as usize;
        if pref >= MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }

        // Try preferred node first.
        if self.nodes[pref].active {
            if let Some(addr) = self.nodes[pref].allocate() {
                return Ok(addr);
            }
        }

        // Build a list of candidate nodes sorted by distance.
        let mut candidates: [(u8, u8); MAX_NUMA_NODES] = [(0, u8::MAX); MAX_NUMA_NODES];
        let mut candidate_count = 0;

        for i in 0..MAX_NUMA_NODES {
            if i == pref || !self.nodes[i].active {
                continue;
            }
            if self.nodes[i].free_count == 0 {
                continue;
            }
            let dist = self.distances[pref * MAX_NUMA_NODES + i];
            candidates[candidate_count] = (i as u8, dist);
            candidate_count += 1;
        }

        // Sort by distance (simple insertion sort, max 7 elements).
        for i in 1..candidate_count {
            let mut j = i;
            while j > 0 && candidates[j].1 < candidates[j - 1].1 {
                candidates.swap(j, j - 1);
                j -= 1;
            }
        }

        // Try each candidate in distance order.
        for c in &candidates[..candidate_count] {
            let idx = c.0 as usize;
            if let Some(addr) = self.nodes[idx].allocate() {
                return Ok(addr);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Free a physical frame, returning it to its owning node.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the address does not
    /// belong to any known NUMA node.
    pub fn free(&mut self, addr: u64) -> Result<()> {
        for node in &mut self.nodes {
            if !node.active {
                continue;
            }
            if node.free(addr) {
                return Ok(());
            }
        }
        Err(Error::InvalidArgument)
    }

    /// Determine which NUMA node owns a physical address.
    ///
    /// Returns `None` if the address is not managed by any node.
    pub fn node_for_addr(&self, addr: u64) -> Option<u8> {
        for node in &self.nodes {
            if node.contains(addr) {
                return Some(node.id);
            }
        }
        None
    }

    /// Return the number of active NUMA nodes.
    pub fn node_count(&self) -> usize {
        self.count
    }

    /// Return the number of free frames on a specific node.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the node ID is invalid
    /// or inactive.
    pub fn available_frames(&self, node_id: u8) -> Result<usize> {
        let idx = node_id as usize;
        if idx >= MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        if !self.nodes[idx].active {
            return Err(Error::InvalidArgument);
        }
        Ok(self.nodes[idx].free_count)
    }
}

/// How many `u64` words are needed to cover `n` frames.
const fn words_for(n: usize) -> usize {
    n.div_ceil(64)
}
