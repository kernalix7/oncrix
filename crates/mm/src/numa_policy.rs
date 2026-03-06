// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA memory allocation policy.
//!
//! Implements per-process and per-VMA NUMA memory policies that
//! control which NUMA nodes are preferred for page allocation.
//! Supports bind, interleave, preferred, and local policies
//! as defined by `set_mempolicy(2)` and `mbind(2)`.
//!
//! - [`NumaPolicy`] — policy type
//! - [`NodeMask`] — bitmask of NUMA nodes
//! - [`MempolicyEntry`] — a policy bound to a process/VMA
//! - [`NumaPolicyStats`] — policy statistics
//! - [`NumaPolicyManager`] — the policy manager
//!
//! Reference: Linux `mm/mempolicy.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum NUMA nodes.
const MAX_NODES: usize = 64;

/// Maximum policy entries.
const MAX_POLICIES: usize = 128;

// -------------------------------------------------------------------
// NumaPolicy
// -------------------------------------------------------------------

/// NUMA memory allocation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NumaPolicy {
    /// Default — allocate from the local node.
    #[default]
    Default,
    /// Preferred — prefer a specific node, fallback to others.
    Preferred,
    /// Bind — restrict to specified nodes only.
    Bind,
    /// Interleave — round-robin across specified nodes.
    Interleave,
    /// Local — always allocate from the faulting CPU's node.
    Local,
}

// -------------------------------------------------------------------
// NodeMask
// -------------------------------------------------------------------

/// Bitmask of NUMA nodes.
#[derive(Debug, Clone, Copy, Default)]
pub struct NodeMask {
    /// Bitmask (bit N = node N).
    bits: u64,
}

impl NodeMask {
    /// Creates an empty mask.
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates a mask with a single node set.
    pub fn single(node: usize) -> Result<Self> {
        if node >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { bits: 1u64 << node })
    }

    /// Creates a mask with all nodes set.
    pub fn all(nr_nodes: usize) -> Self {
        if nr_nodes >= 64 {
            Self { bits: u64::MAX }
        } else {
            Self {
                bits: (1u64 << nr_nodes) - 1,
            }
        }
    }

    /// Tests if a node is set.
    pub fn test(&self, node: usize) -> bool {
        if node >= MAX_NODES {
            return false;
        }
        self.bits & (1u64 << node) != 0
    }

    /// Sets a node.
    pub fn set(&mut self, node: usize) -> Result<()> {
        if node >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }
        self.bits |= 1u64 << node;
        Ok(())
    }

    /// Clears a node.
    pub fn clear(&mut self, node: usize) -> Result<()> {
        if node >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }
        self.bits &= !(1u64 << node);
        Ok(())
    }

    /// Returns the number of set nodes.
    pub fn weight(&self) -> u32 {
        self.bits.count_ones()
    }

    /// Returns the first set node, or `None`.
    pub fn first(&self) -> Option<usize> {
        if self.bits == 0 {
            None
        } else {
            Some(self.bits.trailing_zeros() as usize)
        }
    }

    /// Returns the raw bits.
    pub fn bits(&self) -> u64 {
        self.bits
    }
}

// -------------------------------------------------------------------
// MempolicyEntry
// -------------------------------------------------------------------

/// A NUMA policy bound to a process or VMA.
#[derive(Debug, Clone, Copy, Default)]
pub struct MempolicyEntry {
    /// Policy owner (PID or VMA identifier).
    pub owner_id: u64,
    /// Policy type.
    pub policy: NumaPolicy,
    /// Node mask.
    pub nodes: NodeMask,
    /// Preferred node (for Preferred policy).
    pub preferred_node: u32,
    /// Interleave index (for Interleave policy).
    pub interleave_idx: u32,
    /// Whether this entry is active.
    pub active: bool,
}

impl MempolicyEntry {
    /// Creates a new policy entry.
    pub fn new(owner_id: u64, policy: NumaPolicy, nodes: NodeMask) -> Self {
        Self {
            owner_id,
            policy,
            nodes,
            preferred_node: nodes.first().unwrap_or(0) as u32,
            interleave_idx: 0,
            active: true,
        }
    }

    /// Returns the next node for allocation.
    pub fn next_node(&mut self) -> Option<usize> {
        match self.policy {
            NumaPolicy::Default | NumaPolicy::Local => None,
            NumaPolicy::Preferred => Some(self.preferred_node as usize),
            NumaPolicy::Bind => self.nodes.first(),
            NumaPolicy::Interleave => {
                let weight = self.nodes.weight();
                if weight == 0 {
                    return None;
                }
                let mut count = 0u32;
                let target = self.interleave_idx % weight;
                for n in 0..MAX_NODES {
                    if self.nodes.test(n) {
                        if count == target {
                            self.interleave_idx = self.interleave_idx.wrapping_add(1);
                            return Some(n);
                        }
                        count += 1;
                    }
                }
                None
            }
        }
    }
}

// -------------------------------------------------------------------
// NumaPolicyStats
// -------------------------------------------------------------------

/// NUMA policy statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct NumaPolicyStats {
    /// Total policy lookups.
    pub lookups: u64,
    /// Allocations using preferred node.
    pub preferred_allocs: u64,
    /// Allocations using interleave.
    pub interleave_allocs: u64,
    /// Allocations using bind policy.
    pub bind_allocs: u64,
    /// Allocations using default/local policy.
    pub local_allocs: u64,
}

impl NumaPolicyStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// NumaPolicyManager
// -------------------------------------------------------------------

/// The NUMA policy manager.
pub struct NumaPolicyManager {
    /// Policy entries.
    entries: [MempolicyEntry; MAX_POLICIES],
    /// Number of entries.
    count: usize,
    /// Statistics.
    stats: NumaPolicyStats,
}

impl Default for NumaPolicyManager {
    fn default() -> Self {
        Self {
            entries: [MempolicyEntry::default(); MAX_POLICIES],
            count: 0,
            stats: NumaPolicyStats::default(),
        }
    }
}

impl NumaPolicyManager {
    /// Creates a new policy manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a policy for the given owner.
    pub fn set_policy(
        &mut self,
        owner_id: u64,
        policy: NumaPolicy,
        nodes: NodeMask,
    ) -> Result<usize> {
        // Update existing policy if found.
        for i in 0..self.count {
            if self.entries[i].active && self.entries[i].owner_id == owner_id {
                self.entries[i].policy = policy;
                self.entries[i].nodes = nodes;
                self.entries[i].preferred_node = nodes.first().unwrap_or(0) as u32;
                return Ok(i);
            }
        }
        if self.count >= MAX_POLICIES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.entries[idx] = MempolicyEntry::new(owner_id, policy, nodes);
        self.count += 1;
        Ok(idx)
    }

    /// Gets the target node for an allocation.
    pub fn get_node(&mut self, owner_id: u64) -> Option<usize> {
        self.stats.lookups += 1;
        for i in 0..self.count {
            if self.entries[i].active && self.entries[i].owner_id == owner_id {
                let node = self.entries[i].next_node();
                match self.entries[i].policy {
                    NumaPolicy::Preferred => self.stats.preferred_allocs += 1,
                    NumaPolicy::Interleave => self.stats.interleave_allocs += 1,
                    NumaPolicy::Bind => self.stats.bind_allocs += 1,
                    _ => self.stats.local_allocs += 1,
                }
                return node;
            }
        }
        self.stats.local_allocs += 1;
        None
    }

    /// Removes a policy.
    pub fn remove_policy(&mut self, owner_id: u64) -> Result<()> {
        for i in 0..self.count {
            if self.entries[i].active && self.entries[i].owner_id == owner_id {
                self.entries[i].active = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of active policies.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &NumaPolicyStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
