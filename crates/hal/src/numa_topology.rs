// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA topology discovery.
//!
//! Parses ACPI SRAT (System Resource Affinity Table) and SLIT (System
//! Locality Information Table) to build a machine-wide NUMA topology map:
//! which CPUs belong to which NUMA node, which memory ranges map to which
//! node, and the relative access distances between nodes.
//!
//! # ACPI Tables Used
//!
//! - **SRAT** (`"SRAT"`) — System Resource Affinity Table.
//!   Contains affinity structures that associate CPU APIC IDs and memory
//!   address ranges with proximity domains (NUMA node IDs).
//! - **SLIT** (`"SLIT"`) — System Locality Information Table.
//!   A matrix of distance values between each pair of proximity domains.
//!   The diagonal (local) distance is defined as 10.
//!
//! # Architecture
//!
//! - [`NumaNode`] — a single NUMA node (proximity domain, CPU mask, memory ranges).
//! - [`MemoryRange`] — a contiguous physical memory range belonging to a node.
//! - [`NumaDistance`] — distance between two nodes (from SLIT).
//! - [`NumaTopology`] — the complete parsed topology.
//!
//! Reference: ACPI Specification 6.5 §5.2.16 (SRAT), §5.2.17 (SLIT).

use oncrix_lib::{Error, Result};

use crate::acpi::{SdtHeader, validate_sdt_checksum};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ACPI SRAT table signature.
const SRAT_SIGNATURE: [u8; 4] = *b"SRAT";

/// ACPI SLIT table signature.
const SLIT_SIGNATURE: [u8; 4] = *b"SLIT";

/// Minimum SRAT table length (SDT header 36 + reserved 8 bytes).
const SRAT_MIN_LEN: usize = 44;

/// Minimum SLIT table length (SDT header 36 + number of localities 8).
const SLIT_MIN_LEN: usize = 44;

/// SRAT sub-structure type: Processor Local APIC/SAPIC Affinity.
const SRAT_TYPE_CPU_APIC: u8 = 0;

/// SRAT sub-structure type: Memory Affinity.
const SRAT_TYPE_MEMORY: u8 = 1;

/// SRAT sub-structure type: Processor Local x2APIC Affinity.
const SRAT_TYPE_CPU_X2APIC: u8 = 2;

/// SRAT CPU Affinity flag: enabled.
const SRAT_CPU_ENABLED: u32 = 1;

/// SRAT Memory Affinity flag: enabled.
const SRAT_MEM_ENABLED: u32 = 1;

/// SRAT Memory Affinity flag: hot-pluggable.
const SRAT_MEM_HOT_PLUGGABLE: u32 = 1 << 1;

/// SRAT Memory Affinity flag: non-volatile (persistent) memory.
const SRAT_MEM_NON_VOLATILE: u32 = 1 << 2;

/// Maximum NUMA nodes supported.
pub const MAX_NUMA_NODES: usize = 16;

/// Maximum CPUs per NUMA node.
pub const MAX_CPUS_PER_NODE: usize = 64;

/// Maximum memory ranges per NUMA node.
pub const MAX_MEM_RANGES_PER_NODE: usize = 8;

/// Local NUMA distance (diagonal of the SLIT matrix).
pub const NUMA_LOCAL_DISTANCE: u8 = 10;

/// Maximum distance matrix entries (MAX_NODES × MAX_NODES).
const MAX_DISTANCE_ENTRIES: usize = MAX_NUMA_NODES * MAX_NUMA_NODES;

// ---------------------------------------------------------------------------
// MemoryRange
// ---------------------------------------------------------------------------

/// A contiguous physical memory range belonging to a NUMA node.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryRange {
    /// Physical start address (page-aligned).
    pub base: u64,
    /// Length in bytes.
    pub length: u64,
    /// Whether this range is hot-pluggable.
    pub hot_pluggable: bool,
    /// Whether this range is non-volatile (NVDIMM/persistent).
    pub non_volatile: bool,
}

impl MemoryRange {
    /// Return `true` if the range contains the given physical address.
    #[inline]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base.saturating_add(self.length)
    }

    /// Return the exclusive end address of the range.
    #[inline]
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.length)
    }
}

// ---------------------------------------------------------------------------
// NumaNode
// ---------------------------------------------------------------------------

/// A single NUMA proximity domain.
#[derive(Debug, Clone)]
pub struct NumaNode {
    /// NUMA node ID (proximity domain).
    pub node_id: u32,
    /// APIC IDs of CPUs in this node.
    pub cpu_apic_ids: [u32; MAX_CPUS_PER_NODE],
    /// Number of valid entries in `cpu_apic_ids`.
    pub cpu_count: usize,
    /// Physical memory ranges in this node.
    pub mem_ranges: [MemoryRange; MAX_MEM_RANGES_PER_NODE],
    /// Number of valid entries in `mem_ranges`.
    pub mem_range_count: usize,
}

impl NumaNode {
    /// Create an empty NUMA node with the given ID.
    pub const fn new(node_id: u32) -> Self {
        Self {
            node_id,
            cpu_apic_ids: [0; MAX_CPUS_PER_NODE],
            cpu_count: 0,
            mem_ranges: [MemoryRange {
                base: 0,
                length: 0,
                hot_pluggable: false,
                non_volatile: false,
            }; MAX_MEM_RANGES_PER_NODE],
            mem_range_count: 0,
        }
    }

    /// Add a CPU APIC ID to this node.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the CPU array is full.
    pub fn add_cpu(&mut self, apic_id: u32) -> Result<()> {
        if self.cpu_count >= MAX_CPUS_PER_NODE {
            return Err(Error::OutOfMemory);
        }
        self.cpu_apic_ids[self.cpu_count] = apic_id;
        self.cpu_count += 1;
        Ok(())
    }

    /// Add a memory range to this node.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the memory range array is full.
    pub fn add_memory_range(&mut self, range: MemoryRange) -> Result<()> {
        if self.mem_range_count >= MAX_MEM_RANGES_PER_NODE {
            return Err(Error::OutOfMemory);
        }
        self.mem_ranges[self.mem_range_count] = range;
        self.mem_range_count += 1;
        Ok(())
    }

    /// Total usable (non-hot-plug, non-NVDIMM) memory in bytes.
    pub fn total_memory_bytes(&self) -> u64 {
        let mut total: u64 = 0;
        for i in 0..self.mem_range_count {
            let r = &self.mem_ranges[i];
            if !r.hot_pluggable && !r.non_volatile {
                total = total.saturating_add(r.length);
            }
        }
        total
    }

    /// Return the CPU APIC IDs slice.
    pub fn cpus(&self) -> &[u32] {
        &self.cpu_apic_ids[..self.cpu_count]
    }

    /// Return the memory ranges slice.
    pub fn memory_ranges(&self) -> &[MemoryRange] {
        &self.mem_ranges[..self.mem_range_count]
    }
}

// ---------------------------------------------------------------------------
// NumaDistance
// ---------------------------------------------------------------------------

/// Distance matrix between NUMA nodes.
///
/// Sourced from the ACPI SLIT. The local distance (node to itself) is
/// [`NUMA_LOCAL_DISTANCE`] (10). Values ≥ 254 indicate unreachable.
#[derive(Clone)]
pub struct NumaDistance {
    /// Flattened `node_count × node_count` distance matrix.
    distances: [u8; MAX_DISTANCE_ENTRIES],
    /// Number of nodes in the matrix.
    node_count: usize,
}

impl NumaDistance {
    /// Create an identity distance matrix (all local, no inter-node data).
    pub const fn new() -> Self {
        Self {
            distances: [u8::MAX; MAX_DISTANCE_ENTRIES],
            node_count: 0,
        }
    }

    /// Set the distance between two nodes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if either node index exceeds
    /// `MAX_NUMA_NODES`.
    pub fn set(&mut self, from: usize, to: usize, dist: u8) -> Result<()> {
        if from >= MAX_NUMA_NODES || to >= MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        self.distances[from * MAX_NUMA_NODES + to] = dist;
        let max_node = from.max(to) + 1;
        if max_node > self.node_count {
            self.node_count = max_node;
        }
        Ok(())
    }

    /// Get the distance between two nodes.
    ///
    /// Returns `u8::MAX` if the nodes are unreachable or indices are
    /// out of range.
    pub fn get(&self, from: usize, to: usize) -> u8 {
        if from >= MAX_NUMA_NODES || to >= MAX_NUMA_NODES {
            return u8::MAX;
        }
        self.distances[from * MAX_NUMA_NODES + to]
    }

    /// Return the number of nodes recorded in the matrix.
    pub fn node_count(&self) -> usize {
        self.node_count
    }
}

impl Default for NumaDistance {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// NumaTopology
// ---------------------------------------------------------------------------

/// Complete NUMA topology parsed from ACPI SRAT/SLIT.
pub struct NumaTopology {
    /// Parsed NUMA nodes.
    nodes: [Option<NumaNode>; MAX_NUMA_NODES],
    /// Number of populated node slots.
    node_count: usize,
    /// Inter-node distance matrix.
    distances: NumaDistance,
}

impl NumaTopology {
    /// Create an empty topology.
    pub const fn new() -> Self {
        const EMPTY_NODE: Option<NumaNode> = None;
        Self {
            nodes: [EMPTY_NODE; MAX_NUMA_NODES],
            node_count: 0,
            distances: NumaDistance::new(),
        }
    }

    /// Parse NUMA topology from an ACPI SRAT table.
    ///
    /// `data` must be the raw bytes of the SRAT table starting from the
    /// SDT header.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the table is too short,
    /// the signature doesn't match, or the checksum fails.
    pub fn parse_srat(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < SRAT_MIN_LEN {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: data.len() >= SRAT_MIN_LEN > size_of::<SdtHeader>().
        let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const SdtHeader) };

        if header.signature != SRAT_SIGNATURE {
            return Err(Error::InvalidArgument);
        }

        let length = (header.length as usize).min(data.len());
        if !validate_sdt_checksum(data, length) {
            return Err(Error::InvalidArgument);
        }

        // Walk sub-structures starting at offset 44 (after SDT header + 8 reserved bytes).
        let mut offset = 44usize;

        while offset + 2 <= length {
            let sub_type = data[offset];
            let sub_len = data[offset + 1] as usize;

            if sub_len < 2 || offset + sub_len > length {
                break;
            }

            match sub_type {
                SRAT_TYPE_CPU_APIC => {
                    self.parse_cpu_apic_affinity(&data[offset..offset + sub_len])?
                }
                SRAT_TYPE_MEMORY => self.parse_memory_affinity(&data[offset..offset + sub_len])?,
                SRAT_TYPE_CPU_X2APIC => {
                    self.parse_x2apic_affinity(&data[offset..offset + sub_len])?
                }
                _ => {}
            }

            offset += sub_len;
        }

        Ok(())
    }

    /// Parse NUMA distance matrix from an ACPI SLIT table.
    ///
    /// `data` must be the raw bytes of the SLIT table starting from the
    /// SDT header.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the table is too short,
    /// the signature doesn't match, or the checksum fails.
    pub fn parse_slit(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < SLIT_MIN_LEN {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: data.len() >= SLIT_MIN_LEN > size_of::<SdtHeader>().
        let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const SdtHeader) };

        if header.signature != SLIT_SIGNATURE {
            return Err(Error::InvalidArgument);
        }

        let length = (header.length as usize).min(data.len());
        if !validate_sdt_checksum(data, length) {
            return Err(Error::InvalidArgument);
        }

        // Number of localities at offset 36 (8-byte field).
        // SAFETY: offset 36 + 8 = 44 <= SLIT_MIN_LEN.
        let localities =
            unsafe { core::ptr::read_unaligned(data.as_ptr().add(36) as *const u64) } as usize;

        if localities > MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }

        // Distance matrix starts at offset 44.
        let matrix_start = 44;
        let expected = matrix_start + localities * localities;
        if data.len() < expected {
            return Err(Error::InvalidArgument);
        }

        for from in 0..localities {
            for to in 0..localities {
                let dist = data[matrix_start + from * localities + to];
                self.distances.set(from, to, dist)?;
            }
        }

        Ok(())
    }

    /// Return the distance between two nodes.
    pub fn distance(&self, from: usize, to: usize) -> u8 {
        self.distances.get(from, to)
    }

    /// Return the number of discovered nodes.
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Return a reference to a node by its NUMA node ID.
    pub fn node(&self, node_id: u32) -> Option<&NumaNode> {
        for i in 0..self.node_count {
            if let Some(ref n) = self.nodes[i] {
                if n.node_id == node_id {
                    return Some(n);
                }
            }
        }
        None
    }

    /// Return the NUMA node that contains the given physical address.
    pub fn node_for_address(&self, addr: u64) -> Option<&NumaNode> {
        for i in 0..self.node_count {
            if let Some(ref n) = self.nodes[i] {
                for r in n.memory_ranges() {
                    if r.contains(addr) {
                        return Some(n);
                    }
                }
            }
        }
        None
    }

    /// Return the NUMA node that owns the given APIC ID.
    pub fn node_for_cpu(&self, apic_id: u32) -> Option<&NumaNode> {
        for i in 0..self.node_count {
            if let Some(ref n) = self.nodes[i] {
                if n.cpus().contains(&apic_id) {
                    return Some(n);
                }
            }
        }
        None
    }

    /// Iterate over all populated nodes.
    pub fn nodes(&self) -> impl Iterator<Item = &NumaNode> {
        self.nodes[..self.node_count]
            .iter()
            .filter_map(|n| n.as_ref())
    }

    // -----------------------------------------------------------------------
    // Private parse helpers
    // -----------------------------------------------------------------------

    /// Find or create a node slot for `node_id`.
    fn get_or_create_node(&mut self, node_id: u32) -> Result<&mut NumaNode> {
        // Find existing.
        for i in 0..self.node_count {
            if let Some(ref n) = self.nodes[i] {
                if n.node_id == node_id {
                    return Ok(self.nodes[i].as_mut().unwrap());
                }
            }
        }

        // Create new slot.
        if self.node_count >= MAX_NUMA_NODES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.node_count;
        self.nodes[idx] = Some(NumaNode::new(node_id));
        self.node_count += 1;
        Ok(self.nodes[idx].as_mut().unwrap())
    }

    /// Parse a Processor Local APIC Affinity sub-structure (type 0, len 16).
    fn parse_cpu_apic_affinity(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 16 {
            return Ok(());
        }

        // Byte 0: type, byte 1: length
        // Byte 2: proximity domain [7:0]
        // Byte 3: APIC ID
        // Bytes 4-7: flags (u32 LE)
        // Byte 8: Local SAPIC EID
        // Bytes 9-11: proximity domain [31:8] (combine with byte 2)
        let prox_lo = data[2] as u32;
        let apic_id = data[3] as u32;
        let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let prox_hi = u32::from_le_bytes([data[9], data[10], data[11], 0]);
        let node_id = prox_lo | (prox_hi << 8);

        if flags & SRAT_CPU_ENABLED == 0 {
            return Ok(());
        }

        let node = self.get_or_create_node(node_id)?;
        node.add_cpu(apic_id)
    }

    /// Parse a Memory Affinity sub-structure (type 1, len 40).
    fn parse_memory_affinity(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 40 {
            return Ok(());
        }

        // Bytes 2-5: proximity domain (u32 LE)
        // Bytes 8-15: base address (u64 LE)
        // Bytes 16-23: length (u64 LE)
        // Bytes 28-31: flags (u32 LE)
        let node_id = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        // SAFETY: offsets 8..16, 16..24, 28..32 all within the 40-byte sub-struct.
        let base = unsafe { core::ptr::read_unaligned(data.as_ptr().add(8) as *const u64) };
        let length = unsafe { core::ptr::read_unaligned(data.as_ptr().add(16) as *const u64) };
        let flags = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        if flags & SRAT_MEM_ENABLED == 0 || length == 0 {
            return Ok(());
        }

        let range = MemoryRange {
            base,
            length,
            hot_pluggable: flags & SRAT_MEM_HOT_PLUGGABLE != 0,
            non_volatile: flags & SRAT_MEM_NON_VOLATILE != 0,
        };

        let node = self.get_or_create_node(node_id)?;
        node.add_memory_range(range)
    }

    /// Parse a Processor Local x2APIC Affinity sub-structure (type 2, len 24).
    fn parse_x2apic_affinity(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 24 {
            return Ok(());
        }

        // Bytes 2-3: reserved
        // Bytes 4-7: proximity domain (u32 LE)
        // Bytes 8-11: x2APIC ID (u32 LE)
        // Bytes 12-15: flags (u32 LE)
        let node_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let apic_id = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let flags = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

        if flags & SRAT_CPU_ENABLED == 0 {
            return Ok(());
        }

        let node = self.get_or_create_node(node_id)?;
        node.add_cpu(apic_id)
    }
}

impl Default for NumaTopology {
    fn default() -> Self {
        Self::new()
    }
}
