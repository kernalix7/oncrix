// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA hardware topology and node distance management.
//!
//! Provides the hardware-level NUMA topology as seen from ACPI SRAT/SLIT
//! tables: which CPUs and memory ranges belong to which proximity domain
//! (NUMA node), and the relative access latencies between nodes.
//!
//! # Architecture
//!
//! - Each NUMA node has an ID (proximity domain, 0-based).
//! - CPUs are assigned to nodes via SRAT Local APIC affinity entries.
//! - Memory ranges are assigned to nodes via SRAT memory affinity entries.
//! - Inter-node latencies come from the SLIT matrix.
//!
//! Reference: ACPI Specification 6.5 §6.2 (SRAT), §6.3 (SLIT).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of NUMA nodes supported.
pub const MAX_NUMA_NODES: usize = 8;

/// Maximum number of CPUs tracked per node.
pub const MAX_CPUS_PER_NODE: usize = 64;

/// Maximum memory ranges per node.
pub const MAX_MEM_RANGES_PER_NODE: usize = 8;

/// Local (same-node) access latency in SLIT units.
pub const SLIT_LOCAL_LATENCY: u8 = 10;

/// Unreachable node marker in SLIT.
pub const SLIT_UNREACHABLE: u8 = 255;

// ---------------------------------------------------------------------------
// NumaMemRange
// ---------------------------------------------------------------------------

/// A physical memory range assigned to a NUMA node.
#[derive(Debug, Clone, Copy, Default)]
pub struct NumaMemRange {
    /// Base physical address.
    pub base: u64,
    /// Length in bytes.
    pub length: u64,
    /// Whether this range is hot-pluggable.
    pub hotplug: bool,
    /// Whether this range is active (non-volatile / PMEM).
    pub persistent: bool,
}

impl NumaMemRange {
    /// Returns the exclusive end address.
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.length)
    }
}

// ---------------------------------------------------------------------------
// NumaNode
// ---------------------------------------------------------------------------

/// A single NUMA node.
#[derive(Debug)]
pub struct NumaNode {
    /// Proximity domain (node ID).
    pub node_id: u32,
    /// APIC IDs of CPUs in this node.
    pub cpus: [u32; MAX_CPUS_PER_NODE],
    /// Number of CPUs.
    pub cpu_count: usize,
    /// Memory ranges assigned to this node.
    pub mem_ranges: [NumaMemRange; MAX_MEM_RANGES_PER_NODE],
    /// Number of memory ranges.
    pub mem_range_count: usize,
    /// Whether this node is present.
    pub present: bool,
}

impl NumaNode {
    const fn empty() -> Self {
        Self {
            node_id: u32::MAX,
            cpus: [u32::MAX; MAX_CPUS_PER_NODE],
            cpu_count: 0,
            mem_ranges: [NumaMemRange {
                base: 0,
                length: 0,
                hotplug: false,
                persistent: false,
            }; MAX_MEM_RANGES_PER_NODE],
            mem_range_count: 0,
            present: false,
        }
    }

    /// Adds a CPU (APIC ID) to this node.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the CPU list is full.
    pub fn add_cpu(&mut self, apic_id: u32) -> Result<()> {
        if self.cpu_count >= MAX_CPUS_PER_NODE {
            return Err(Error::OutOfMemory);
        }
        self.cpus[self.cpu_count] = apic_id;
        self.cpu_count += 1;
        Ok(())
    }

    /// Adds a memory range to this node.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the range list is full.
    pub fn add_mem_range(&mut self, range: NumaMemRange) -> Result<()> {
        if self.mem_range_count >= MAX_MEM_RANGES_PER_NODE {
            return Err(Error::OutOfMemory);
        }
        self.mem_ranges[self.mem_range_count] = range;
        self.mem_range_count += 1;
        Ok(())
    }

    /// Returns the total memory in bytes assigned to this node.
    pub fn total_memory(&self) -> u64 {
        self.mem_ranges[..self.mem_range_count]
            .iter()
            .map(|r| r.length)
            .fold(0u64, |a, b| a.saturating_add(b))
    }

    /// Returns CPU slice.
    pub fn cpus(&self) -> &[u32] {
        &self.cpus[..self.cpu_count]
    }

    /// Returns memory range slice.
    pub fn mem_ranges(&self) -> &[NumaMemRange] {
        &self.mem_ranges[..self.mem_range_count]
    }
}

// ---------------------------------------------------------------------------
// NumaDistanceMatrix
// ---------------------------------------------------------------------------

/// Inter-node access latency matrix (from SLIT).
///
/// `matrix[from][to]` is the relative latency from node `from` to node `to`.
/// Value 10 = local (same node). Higher = greater latency. 255 = unreachable.
#[derive(Debug, Clone, Copy)]
pub struct NumaDistanceMatrix {
    matrix: [[u8; MAX_NUMA_NODES]; MAX_NUMA_NODES],
    num_nodes: usize,
}

impl Default for NumaDistanceMatrix {
    fn default() -> Self {
        // Initialize all to unreachable, diagonal to local.
        let mut m = Self {
            matrix: [[SLIT_UNREACHABLE; MAX_NUMA_NODES]; MAX_NUMA_NODES],
            num_nodes: 0,
        };
        for i in 0..MAX_NUMA_NODES {
            m.matrix[i][i] = SLIT_LOCAL_LATENCY;
        }
        m
    }
}

impl NumaDistanceMatrix {
    /// Sets the latency from `from` to `to`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if indices are out of range.
    pub fn set(&mut self, from: usize, to: usize, latency: u8) -> Result<()> {
        if from >= MAX_NUMA_NODES || to >= MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        self.matrix[from][to] = latency;
        if from + 1 > self.num_nodes {
            self.num_nodes = from + 1;
        }
        if to + 1 > self.num_nodes {
            self.num_nodes = to + 1;
        }
        Ok(())
    }

    /// Returns the latency from `from` to `to`.
    pub fn get(&self, from: usize, to: usize) -> u8 {
        if from >= MAX_NUMA_NODES || to >= MAX_NUMA_NODES {
            return SLIT_UNREACHABLE;
        }
        self.matrix[from][to]
    }

    /// Returns `true` if the two nodes can reach each other.
    pub fn is_reachable(&self, from: usize, to: usize) -> bool {
        self.get(from, to) != SLIT_UNREACHABLE
    }

    /// Returns the nearest node to `from` (excluding `from` itself).
    pub fn nearest_node(&self, from: usize) -> Option<usize> {
        (0..self.num_nodes)
            .filter(|&to| to != from && self.matrix[from][to] != SLIT_UNREACHABLE)
            .min_by_key(|&to| self.matrix[from][to])
    }
}

// ---------------------------------------------------------------------------
// NumaTopology
// ---------------------------------------------------------------------------

/// Complete NUMA hardware topology.
pub struct NumaTopology {
    nodes: [NumaNode; MAX_NUMA_NODES],
    node_count: usize,
    /// Inter-node distance matrix.
    pub distances: NumaDistanceMatrix,
}

impl Default for NumaTopology {
    fn default() -> Self {
        Self::new()
    }
}

impl NumaTopology {
    /// Creates an empty topology.
    pub fn new() -> Self {
        Self {
            nodes: core::array::from_fn(|_| NumaNode::empty()),
            node_count: 0,
            distances: NumaDistanceMatrix::default(),
        }
    }

    /// Adds or retrieves the node for `proximity_domain`.
    ///
    /// Returns a mutable reference to the node slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if `MAX_NUMA_NODES` is exhausted.
    pub fn get_or_create_node(&mut self, proximity_domain: u32) -> Result<&mut NumaNode> {
        // Find existing.
        for i in 0..self.node_count {
            if self.nodes[i].node_id == proximity_domain {
                return Ok(&mut self.nodes[i]);
            }
        }
        // Create new.
        if self.node_count >= MAX_NUMA_NODES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.node_count;
        self.nodes[idx] = NumaNode::empty();
        self.nodes[idx].node_id = proximity_domain;
        self.nodes[idx].present = true;
        self.node_count += 1;
        Ok(&mut self.nodes[idx])
    }

    /// Returns the node for `proximity_domain`, if it exists.
    pub fn node(&self, proximity_domain: u32) -> Option<&NumaNode> {
        self.nodes[..self.node_count]
            .iter()
            .find(|n| n.node_id == proximity_domain)
    }

    /// Returns the node index (0-based sequential) for a proximity domain.
    pub fn node_index(&self, proximity_domain: u32) -> Option<usize> {
        self.nodes[..self.node_count]
            .iter()
            .position(|n| n.node_id == proximity_domain)
    }

    /// Returns the node that owns the physical address `phys`.
    pub fn node_for_phys(&self, phys: u64) -> Option<&NumaNode> {
        self.nodes[..self.node_count].iter().find(|n| {
            n.mem_ranges()
                .iter()
                .any(|r| phys >= r.base && phys < r.end())
        })
    }

    /// Returns the number of NUMA nodes.
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Returns a slice of all nodes.
    pub fn nodes(&self) -> &[NumaNode] {
        &self.nodes[..self.node_count]
    }
}
