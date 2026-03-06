// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA memory policy binding.
//!
//! Implements per-process and per-VMA memory allocation policies
//! that control which NUMA nodes pages are allocated from. Supports
//! the full set of Linux-compatible policy types: default, preferred,
//! bind, interleave, local, and preferred_many.
//!
//! # Architecture
//!
//! - [`MemPolicyType`] — policy discriminant
//! - [`NodeMask`] — bitmask of allowed NUMA nodes
//! - [`MemPolicy`] — a complete policy (type + node mask + flags)
//! - [`VmaPolicy`] — per-VMA policy binding
//! - [`ProcessPolicy`] — per-process default policy
//! - [`MemPolicyManager`] — top-level manager for policy lookup
//!   and allocation decisions
//!
//! ## Policy-based allocation
//!
//! When a page fault triggers allocation, the allocator calls
//! [`MemPolicyManager::select_node`] which consults the VMA policy
//! (if set) or falls back to the process policy, then returns the
//! preferred NUMA node for the allocation.
//!
//! Reference: Linux `mm/mempolicy.c`.

use oncrix_lib::{Error, Result};

// -- Constants

/// Maximum number of NUMA nodes supported.
const MAX_NODES: usize = 16;

/// Maximum number of per-VMA policies.
const MAX_VMA_POLICIES: usize = 256;

/// Maximum number of per-process policies.
const MAX_PROCESS_POLICIES: usize = 64;

/// Node mask word count (16 nodes / 64 bits per word).
const NODE_MASK_WORDS: usize = 1;

// -- MemPolicyType

/// NUMA memory policy types.
///
/// Each type governs how allocation nodes are selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemPolicyType {
    /// System default: allocate from the node the CPU runs on.
    #[default]
    Default,
    /// Prefer a single node; fall back to others if exhausted.
    Preferred,
    /// Bind to a set of nodes; fail if none have memory.
    Bind,
    /// Round-robin across a set of nodes.
    Interleave,
    /// Allocate from the local (current CPU) node.
    Local,
    /// Prefer multiple nodes (weighted or unweighted).
    PreferredMany,
}

// -- MemPolicyFlags

/// Flags modifying policy behaviour.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemPolicyFlags {
    /// Policy applies to all future children (inherited).
    pub relative_nodes: bool,
    /// Nodes specified are relative to cpuset.
    pub static_nodes: bool,
}

// -- NodeMask

/// Bitmask representing a set of NUMA nodes.
#[derive(Debug, Clone, Copy)]
pub struct NodeMask {
    /// Bitmask words (one bit per node).
    pub bits: [u64; NODE_MASK_WORDS],
}

impl NodeMask {
    /// Empty mask (no nodes).
    pub const fn empty() -> Self {
        Self {
            bits: [0; NODE_MASK_WORDS],
        }
    }

    /// Create a mask with a single node set.
    pub const fn single(node: u8) -> Self {
        let mut mask = Self::empty();
        if (node as usize) < MAX_NODES {
            mask.bits[0] = 1u64 << node;
        }
        mask
    }

    /// Create a mask with all nodes up to `count` set.
    pub fn all(count: u8) -> Self {
        let mut mask = Self::empty();
        let n = if (count as usize) > MAX_NODES {
            MAX_NODES
        } else {
            count as usize
        };
        if n > 0 {
            mask.bits[0] = (1u64 << n) - 1;
        }
        mask
    }

    /// Test whether a node is set.
    pub fn test(&self, node: u8) -> bool {
        if (node as usize) >= MAX_NODES {
            return false;
        }
        (self.bits[0] >> node) & 1 != 0
    }

    /// Set a node bit.
    pub fn set(&mut self, node: u8) {
        if (node as usize) < MAX_NODES {
            self.bits[0] |= 1u64 << node;
        }
    }

    /// Clear a node bit.
    pub fn clear(&mut self, node: u8) {
        if (node as usize) < MAX_NODES {
            self.bits[0] &= !(1u64 << node);
        }
    }

    /// Count the number of set nodes.
    pub fn weight(&self) -> u32 {
        self.bits[0].count_ones()
    }

    /// Return the first set node, or None.
    pub fn first_set(&self) -> Option<u8> {
        if self.bits[0] == 0 {
            None
        } else {
            Some(self.bits[0].trailing_zeros() as u8)
        }
    }

    /// Return whether the mask is empty.
    pub fn is_empty(&self) -> bool {
        self.bits[0] == 0
    }
}

impl Default for NodeMask {
    fn default() -> Self {
        Self::empty()
    }
}

// -- MemPolicy

/// A complete NUMA memory policy.
#[derive(Debug, Clone, Copy)]
pub struct MemPolicy {
    /// Policy type.
    pub policy_type: MemPolicyType,
    /// Node mask (nodes this policy covers).
    pub nodes: NodeMask,
    /// Policy flags.
    pub flags: MemPolicyFlags,
    /// Reference count.
    pub refcount: u32,
    /// Whether this policy is active.
    pub active: bool,
}

impl MemPolicy {
    const fn empty() -> Self {
        Self {
            policy_type: MemPolicyType::Default,
            nodes: NodeMask::empty(),
            flags: MemPolicyFlags {
                relative_nodes: false,
                static_nodes: false,
            },
            refcount: 0,
            active: false,
        }
    }
}

impl Default for MemPolicy {
    fn default() -> Self {
        Self::empty()
    }
}

// -- VmaPolicy

/// Per-VMA policy binding.
#[derive(Debug, Clone, Copy)]
pub struct VmaPolicy {
    /// Process owning the VMA.
    pub pid: u64,
    /// VMA start address.
    pub vma_start: u64,
    /// VMA end address.
    pub vma_end: u64,
    /// The policy applied to this VMA.
    pub policy: MemPolicy,
    /// Whether this binding is active.
    pub active: bool,
}

impl VmaPolicy {
    const fn empty() -> Self {
        Self {
            pid: 0,
            vma_start: 0,
            vma_end: 0,
            policy: MemPolicy::empty(),
            active: false,
        }
    }
}

impl Default for VmaPolicy {
    fn default() -> Self {
        Self::empty()
    }
}

// -- ProcessPolicy

/// Per-process default NUMA policy.
#[derive(Debug, Clone, Copy)]
pub struct ProcessPolicy {
    /// Process ID.
    pub pid: u64,
    /// The process-wide default policy.
    pub policy: MemPolicy,
    /// Whether this entry is active.
    pub active: bool,
}

impl ProcessPolicy {
    const fn empty() -> Self {
        Self {
            pid: 0,
            policy: MemPolicy::empty(),
            active: false,
        }
    }
}

impl Default for ProcessPolicy {
    fn default() -> Self {
        Self::empty()
    }
}

// -- MemPolicyStats

/// Statistics for the mempolicy subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemPolicyStats {
    /// Total set_mempolicy calls.
    pub set_calls: u64,
    /// Total get_mempolicy calls.
    pub get_calls: u64,
    /// Total mbind calls.
    pub mbind_calls: u64,
    /// Total node selection queries.
    pub node_selects: u64,
    /// Interleave round-robin counter.
    pub interleave_counter: u64,
}

// -- MemPolicyManager

/// Top-level NUMA memory policy manager.
pub struct MemPolicyManager {
    /// Per-VMA policies.
    vma_policies: [VmaPolicy; MAX_VMA_POLICIES],
    /// Number of active VMA policies.
    vma_count: usize,
    /// Per-process policies.
    process_policies: [ProcessPolicy; MAX_PROCESS_POLICIES],
    /// Number of active process policies.
    process_count: usize,
    /// Number of online NUMA nodes.
    online_nodes: u8,
    /// Interleave index (for round-robin).
    interleave_idx: u8,
    /// Statistics.
    stats: MemPolicyStats,
}

impl MemPolicyManager {
    /// Create a new manager with a given number of online nodes.
    pub const fn new(online_nodes: u8) -> Self {
        Self {
            vma_policies: [const { VmaPolicy::empty() }; MAX_VMA_POLICIES],
            vma_count: 0,
            process_policies: [const { ProcessPolicy::empty() }; MAX_PROCESS_POLICIES],
            process_count: 0,
            online_nodes,
            interleave_idx: 0,
            stats: MemPolicyStats {
                set_calls: 0,
                get_calls: 0,
                mbind_calls: 0,
                node_selects: 0,
                interleave_counter: 0,
            },
        }
    }

    /// Set the process-wide default policy.
    pub fn set_mempolicy(
        &mut self,
        pid: u64,
        policy_type: MemPolicyType,
        nodes: NodeMask,
    ) -> Result<()> {
        self.stats.set_calls += 1;
        if policy_type == MemPolicyType::Bind && nodes.is_empty() {
            return Err(Error::InvalidArgument);
        }
        // Find existing or allocate new.
        let idx = self.find_or_alloc_process(pid)?;
        self.process_policies[idx].policy = MemPolicy {
            policy_type,
            nodes,
            flags: MemPolicyFlags::default(),
            refcount: 1,
            active: true,
        };
        Ok(())
    }

    /// Get the process-wide default policy.
    pub fn get_mempolicy(&mut self, pid: u64) -> Result<&MemPolicy> {
        self.stats.get_calls += 1;
        let pp = self
            .process_policies
            .iter()
            .find(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;
        Ok(&pp.policy)
    }

    /// Bind a policy to a VMA range (mbind).
    pub fn mbind(
        &mut self,
        pid: u64,
        vma_start: u64,
        vma_end: u64,
        policy_type: MemPolicyType,
        nodes: NodeMask,
    ) -> Result<()> {
        self.stats.mbind_calls += 1;
        if vma_end <= vma_start {
            return Err(Error::InvalidArgument);
        }
        let idx = self
            .vma_policies
            .iter()
            .position(|v| !v.active)
            .ok_or(Error::OutOfMemory)?;
        self.vma_policies[idx] = VmaPolicy {
            pid,
            vma_start,
            vma_end,
            policy: MemPolicy {
                policy_type,
                nodes,
                flags: MemPolicyFlags::default(),
                refcount: 1,
                active: true,
            },
            active: true,
        };
        self.vma_count += 1;
        Ok(())
    }

    /// Select the preferred NUMA node for an allocation at the
    /// given virtual address in the given process.
    ///
    /// Checks VMA policy first, then process policy, then
    /// defaults to local node.
    pub fn select_node(&mut self, pid: u64, vaddr: u64, local_node: u8) -> u8 {
        self.stats.node_selects += 1;
        // Check VMA policy, then process policy. Copy to break borrow.
        let policy = self
            .vma_policies
            .iter()
            .find(|v| v.active && v.pid == pid && vaddr >= v.vma_start && vaddr < v.vma_end)
            .map(|vp| vp.policy)
            .or_else(|| {
                self.process_policies
                    .iter()
                    .find(|p| p.active && p.pid == pid)
                    .map(|pp| pp.policy)
            });
        match policy {
            Some(p) => self.apply_policy(&p, local_node),
            None => local_node,
        }
    }

    /// Remove all policies for a process (on exit).
    pub fn remove_process(&mut self, pid: u64) {
        for vp in &mut self.vma_policies {
            if vp.active && vp.pid == pid {
                vp.active = false;
                self.vma_count = self.vma_count.saturating_sub(1);
            }
        }
        for pp in &mut self.process_policies {
            if pp.active && pp.pid == pid {
                pp.active = false;
                self.process_count = self.process_count.saturating_sub(1);
            }
        }
    }

    /// Number of active VMA policies.
    pub fn vma_count(&self) -> usize {
        self.vma_count
    }

    /// Number of active process policies.
    pub fn process_count(&self) -> usize {
        self.process_count
    }

    /// Return statistics.
    pub fn stats(&self) -> &MemPolicyStats {
        &self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = MemPolicyStats::default();
    }

    // -- Internal helpers

    fn find_or_alloc_process(&mut self, pid: u64) -> Result<usize> {
        // Existing entry.
        let existing = self
            .process_policies
            .iter()
            .position(|p| p.active && p.pid == pid);
        if let Some(idx) = existing {
            return Ok(idx);
        }
        // Allocate new.
        let idx = self
            .process_policies
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;
        self.process_policies[idx] = ProcessPolicy {
            pid,
            policy: MemPolicy::empty(),
            active: true,
        };
        self.process_count += 1;
        Ok(idx)
    }

    fn apply_policy(&mut self, policy: &MemPolicy, local_node: u8) -> u8 {
        match policy.policy_type {
            MemPolicyType::Default | MemPolicyType::Local => local_node,
            MemPolicyType::Preferred => policy.nodes.first_set().unwrap_or(local_node),
            MemPolicyType::PreferredMany => policy.nodes.first_set().unwrap_or(local_node),
            MemPolicyType::Bind => {
                if policy.nodes.test(local_node) {
                    local_node
                } else {
                    policy.nodes.first_set().unwrap_or(local_node)
                }
            }
            MemPolicyType::Interleave => {
                let w = policy.nodes.weight();
                if w == 0 {
                    return local_node;
                }
                let target = self.interleave_idx % (w as u8);
                self.interleave_idx = self.interleave_idx.wrapping_add(1);
                self.stats.interleave_counter += 1;
                let mut seen = 0u8;
                for node in 0..self.online_nodes {
                    if policy.nodes.test(node) {
                        if seen == target {
                            return node;
                        }
                        seen += 1;
                    }
                }
                local_node
            }
        }
    }
}

impl Default for MemPolicyManager {
    fn default() -> Self {
        Self::new(4)
    }
}
