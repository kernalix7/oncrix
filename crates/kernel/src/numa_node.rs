// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA node topology management.
//!
//! Models Non-Uniform Memory Access (NUMA) topology where each
//! node has local CPUs and memory ranges. Memory accesses to local
//! memory are faster than cross-node (remote) accesses. The
//! scheduler and memory allocator use this information for
//! placement decisions.
//!
//! # Architecture
//!
//! ```text
//! NumaTopology
//! ├── nodes: [NumaNode; MAX_NODES]
//! │   ├── cpu_mask: bitmask of CPUs on this node
//! │   ├── memory_ranges: [MemoryRange; MAX_RANGES_PER_NODE]
//! │   └── distance: [u16; MAX_NODES]  (SLIT table)
//! └── stats: NumaStats
//! ```
//!
//! # Distance Matrix
//!
//! The distance between two nodes is read from the ACPI SLIT
//! (System Locality Information Table). Convention: local access
//! distance = 10. Values are symmetric: distance(A,B) =
//! distance(B,A).
//!
//! # Reference
//!
//! Linux `mm/page_alloc.c` (NUMA), `drivers/acpi/numa/`,
//! `include/linux/nodemask.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of NUMA nodes.
pub const MAX_NODES: usize = 8;

/// Maximum memory ranges per node.
const MAX_RANGES_PER_NODE: usize = 8;

/// Maximum CPUs tracked per node (bitmask supports 256).
const MAX_CPUS: usize = 256;

/// Words in the CPU bitmask.
const MASK_WORDS: usize = 4;

/// Local (self) distance value.
const LOCAL_DISTANCE: u16 = 10;

/// Remote distance threshold (typically > 20 means remote).
const _REMOTE_THRESHOLD: u16 = 20;

/// Maximum node name length.
const MAX_NAME_LEN: usize = 16;

// ── MemoryRange ─────────────────────────────────────────────

/// A contiguous physical memory range belonging to a NUMA node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRange {
    /// Start physical address (page-aligned).
    pub start: u64,
    /// End physical address (exclusive, page-aligned).
    pub end: u64,
    /// Whether this range is hotpluggable.
    pub hotpluggable: bool,
    /// Whether this range slot is active.
    pub active: bool,
}

impl MemoryRange {
    /// Create an empty range.
    pub const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            hotpluggable: false,
            active: false,
        }
    }

    /// Size of the range in bytes.
    pub const fn size(&self) -> u64 {
        if self.end > self.start {
            self.end - self.start
        } else {
            0
        }
    }

    /// Whether an address falls within this range.
    pub fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.start && addr < self.end
    }
}

// ── NodeCpuMask ─────────────────────────────────────────────

/// CPU bitmask for a NUMA node (up to 256 CPUs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeCpuMask {
    /// Bitmask words.
    bits: [u64; MASK_WORDS],
}

impl NodeCpuMask {
    /// Create an empty mask.
    pub const fn empty() -> Self {
        Self {
            bits: [0; MASK_WORDS],
        }
    }

    /// Set a CPU.
    pub fn set(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            self.bits[cpu / 64] |= 1u64 << (cpu % 64);
        }
    }

    /// Clear a CPU.
    pub fn clear(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            self.bits[cpu / 64] &= !(1u64 << (cpu % 64));
        }
    }

    /// Test whether a CPU is set.
    pub fn test(&self, cpu: usize) -> bool {
        if cpu >= MAX_CPUS {
            return false;
        }
        (self.bits[cpu / 64] & (1u64 << (cpu % 64))) != 0
    }

    /// Count set CPUs.
    pub fn count(&self) -> usize {
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Whether the mask is empty.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&w| w == 0)
    }

    /// First set CPU.
    pub fn first_set(&self) -> Option<usize> {
        for (i, &w) in self.bits.iter().enumerate() {
            if w != 0 {
                return Some(i * 64 + w.trailing_zeros() as usize);
            }
        }
        None
    }
}

impl Default for NodeCpuMask {
    fn default() -> Self {
        Self::empty()
    }
}

// ── NodeState ───────────────────────────────────────────────

/// Online/offline state of a NUMA node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NodeState {
    /// Node is offline / not populated.
    #[default]
    Offline,
    /// Node has memory but no CPUs.
    MemoryOnly,
    /// Node has CPUs but no memory.
    CpuOnly,
    /// Node is fully online (CPU + memory).
    Online,
}

// ── NumaNode ────────────────────────────────────────────────

/// A single NUMA node with CPUs, memory, and distance info.
pub struct NumaNode {
    /// Node identifier.
    node_id: u32,
    /// Node name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// CPU mask.
    cpu_mask: NodeCpuMask,
    /// Memory ranges.
    memory_ranges: [MemoryRange; MAX_RANGES_PER_NODE],
    /// Number of active memory ranges.
    range_count: usize,
    /// Distance to each other node.
    distance: [u16; MAX_NODES],
    /// Node state.
    state: NodeState,
    /// Total memory in bytes.
    total_memory: u64,
    /// Free memory in bytes.
    free_memory: u64,
    /// Whether this node slot is active.
    active: bool,
}

impl NumaNode {
    /// Create an empty node.
    pub const fn empty() -> Self {
        Self {
            node_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            cpu_mask: NodeCpuMask::empty(),
            memory_ranges: [MemoryRange::empty(); MAX_RANGES_PER_NODE],
            range_count: 0,
            distance: [0u16; MAX_NODES],
            state: NodeState::Offline,
            total_memory: 0,
            free_memory: 0,
            active: false,
        }
    }

    /// Node ID.
    pub fn node_id(&self) -> u32 {
        self.node_id
    }

    /// Node state.
    pub fn state(&self) -> NodeState {
        self.state
    }

    /// CPU mask.
    pub fn cpu_mask(&self) -> &NodeCpuMask {
        &self.cpu_mask
    }

    /// Number of CPUs on this node.
    pub fn cpu_count(&self) -> usize {
        self.cpu_mask.count()
    }

    /// Total memory on this node.
    pub fn total_memory(&self) -> u64 {
        self.total_memory
    }

    /// Free memory on this node.
    pub fn free_memory(&self) -> u64 {
        self.free_memory
    }

    /// Distance to another node.
    pub fn distance_to(&self, other_node: usize) -> u16 {
        if other_node < MAX_NODES {
            self.distance[other_node]
        } else {
            u16::MAX
        }
    }

    /// Number of memory ranges.
    pub fn range_count(&self) -> usize {
        self.range_count
    }

    /// Get a memory range by index.
    pub fn get_range(&self, index: usize) -> Option<&MemoryRange> {
        if index < self.range_count {
            Some(&self.memory_ranges[index])
        } else {
            None
        }
    }
}

// ── NumaStats ───────────────────────────────────────────────

/// Statistics for the NUMA topology.
#[derive(Debug, Clone, Copy, Default)]
pub struct NumaStats {
    /// Number of active nodes.
    pub active_nodes: u32,
    /// Total CPUs across all nodes.
    pub total_cpus: u32,
    /// Total memory across all nodes.
    pub total_memory: u64,
    /// Total free memory across all nodes.
    pub total_free_memory: u64,
    /// Maximum inter-node distance observed.
    pub max_distance: u16,
    /// Number of node lookups performed.
    pub lookups: u64,
}

// ── NumaTopology ────────────────────────────────────────────

/// Global NUMA topology database.
///
/// Manages all NUMA nodes, their CPUs, memory ranges, and the
/// inter-node distance matrix.
pub struct NumaTopology {
    /// NUMA nodes.
    nodes: [NumaNode; MAX_NODES],
    /// Number of active nodes.
    node_count: u32,
    /// Next node ID.
    next_node_id: u32,
    /// Whether initialized.
    initialized: bool,
    /// Lookup counter.
    lookups: u64,
}

impl NumaTopology {
    /// Create a new, empty topology.
    pub const fn new() -> Self {
        Self {
            nodes: [const { NumaNode::empty() }; MAX_NODES],
            node_count: 0,
            next_node_id: 0,
            initialized: false,
            lookups: 0,
        }
    }

    /// Initialize the NUMA topology subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Register a NUMA node.
    pub fn register_node(&mut self, name: &str) -> Result<u32> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .nodes
            .iter()
            .position(|n| !n.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_node_id;
        if id as usize >= MAX_NODES {
            return Err(Error::OutOfMemory);
        }
        self.next_node_id += 1;

        self.nodes[slot] = NumaNode::empty();
        self.nodes[slot].node_id = id;
        self.nodes[slot].active = true;

        // Set self-distance.
        self.nodes[slot].distance[id as usize] = LOCAL_DISTANCE;

        let copy_len = name.len().min(MAX_NAME_LEN);
        self.nodes[slot].name[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);
        self.nodes[slot].name_len = copy_len;

        self.node_count += 1;
        Ok(id)
    }

    /// Add a CPU to a node.
    pub fn add_cpu(&mut self, node_id: u32, cpu: u32) -> Result<()> {
        let node = self.find_node_mut(node_id)?;
        let cpu_idx = cpu as usize;
        if cpu_idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if node.cpu_mask.test(cpu_idx) {
            return Err(Error::AlreadyExists);
        }
        node.cpu_mask.set(cpu_idx);
        self.update_node_state(node_id);
        Ok(())
    }

    /// Remove a CPU from a node.
    pub fn remove_cpu(&mut self, node_id: u32, cpu: u32) -> Result<()> {
        let node = self.find_node_mut(node_id)?;
        let cpu_idx = cpu as usize;
        if cpu_idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        node.cpu_mask.clear(cpu_idx);
        self.update_node_state(node_id);
        Ok(())
    }

    /// Add a memory range to a node.
    pub fn add_memory_range(
        &mut self,
        node_id: u32,
        start: u64,
        end: u64,
        hotpluggable: bool,
    ) -> Result<()> {
        if end <= start {
            return Err(Error::InvalidArgument);
        }
        let node = self.find_node_mut(node_id)?;
        if node.range_count >= MAX_RANGES_PER_NODE {
            return Err(Error::OutOfMemory);
        }
        let idx = node.range_count;
        node.memory_ranges[idx] = MemoryRange {
            start,
            end,
            hotpluggable,
            active: true,
        };
        node.range_count += 1;
        node.total_memory += end - start;
        node.free_memory += end - start;
        self.update_node_state(node_id);
        Ok(())
    }

    /// Set the distance between two nodes (symmetric).
    pub fn set_distance(&mut self, from: u32, to: u32, distance: u16) -> Result<()> {
        if distance == 0 {
            return Err(Error::InvalidArgument);
        }
        let from_idx = self.find_slot(from)?;
        let to_idx = self.find_slot(to)?;

        let from_nid = from as usize;
        let to_nid = to as usize;
        if from_nid >= MAX_NODES || to_nid >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }

        self.nodes[from_idx].distance[to_nid] = distance;
        self.nodes[to_idx].distance[from_nid] = distance;
        Ok(())
    }

    /// Query distance between two nodes.
    pub fn distance(&mut self, from: u32, to: u32) -> Result<u16> {
        self.lookups += 1;
        let from_idx = self.find_slot(from)?;
        let to_nid = to as usize;
        if to_nid >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }
        Ok(self.nodes[from_idx].distance[to_nid])
    }

    /// Find the NUMA node for a given CPU.
    pub fn node_of_cpu(&mut self, cpu: u32) -> Option<u32> {
        self.lookups += 1;
        let cpu_idx = cpu as usize;
        for node in &self.nodes {
            if node.active && node.cpu_mask.test(cpu_idx) {
                return Some(node.node_id);
            }
        }
        None
    }

    /// Find the NUMA node for a physical address.
    pub fn node_of_addr(&mut self, addr: u64) -> Option<u32> {
        self.lookups += 1;
        for node in &self.nodes {
            if !node.active {
                continue;
            }
            for range in &node.memory_ranges {
                if range.contains(addr) {
                    return Some(node.node_id);
                }
            }
        }
        None
    }

    /// Get a reference to a node.
    pub fn get_node(&self, node_id: u32) -> Result<&NumaNode> {
        let idx = self.find_slot(node_id)?;
        Ok(&self.nodes[idx])
    }

    /// Find the nearest node to a given node (excluding self).
    pub fn nearest_node(&mut self, node_id: u32) -> Option<u32> {
        self.lookups += 1;
        let idx = match self.find_slot(node_id) {
            Ok(i) => i,
            Err(_) => return None,
        };

        let mut best_dist = u16::MAX;
        let mut best_node = None;

        for other in &self.nodes {
            if !other.active || other.node_id == node_id {
                continue;
            }
            let nid = other.node_id as usize;
            if nid < MAX_NODES {
                let d = self.nodes[idx].distance[nid];
                if d > 0 && d < best_dist {
                    best_dist = d;
                    best_node = Some(other.node_id);
                }
            }
        }
        best_node
    }

    /// Update memory usage for a node.
    pub fn update_free_memory(&mut self, node_id: u32, free_bytes: u64) -> Result<()> {
        let node = self.find_node_mut(node_id)?;
        node.free_memory = free_bytes;
        Ok(())
    }

    /// Return the number of active nodes.
    pub fn node_count(&self) -> u32 {
        self.node_count
    }

    /// Return statistics.
    pub fn stats(&self) -> NumaStats {
        let mut stats = NumaStats::default();
        stats.active_nodes = self.node_count;
        stats.lookups = self.lookups;

        for node in &self.nodes {
            if !node.active {
                continue;
            }
            stats.total_cpus += node.cpu_mask.count() as u32;
            stats.total_memory += node.total_memory;
            stats.total_free_memory += node.free_memory;

            for &d in &node.distance {
                if d > stats.max_distance {
                    stats.max_distance = d;
                }
            }
        }
        stats
    }

    // ── Internal helpers ────────────────────────────────────

    /// Find a node slot by ID.
    fn find_slot(&self, node_id: u32) -> Result<usize> {
        self.nodes
            .iter()
            .position(|n| n.active && n.node_id == node_id)
            .ok_or(Error::NotFound)
    }

    /// Find a mutable node by ID.
    fn find_node_mut(&mut self, node_id: u32) -> Result<&mut NumaNode> {
        self.nodes
            .iter_mut()
            .find(|n| n.active && n.node_id == node_id)
            .ok_or(Error::NotFound)
    }

    /// Update a node's state based on its CPU and memory.
    fn update_node_state(&mut self, node_id: u32) {
        if let Some(node) = self
            .nodes
            .iter_mut()
            .find(|n| n.active && n.node_id == node_id)
        {
            let has_cpus = !node.cpu_mask.is_empty();
            let has_memory = node.total_memory > 0;
            node.state = match (has_cpus, has_memory) {
                (true, true) => NodeState::Online,
                (true, false) => NodeState::CpuOnly,
                (false, true) => NodeState::MemoryOnly,
                (false, false) => NodeState::Offline,
            };
        }
    }
}

impl Default for NumaTopology {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for NumaTopology {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let stats = self.stats();
        f.debug_struct("NumaTopology")
            .field("nodes", &stats.active_nodes)
            .field("cpus", &stats.total_cpus)
            .field("memory", &stats.total_memory)
            .finish()
    }
}
