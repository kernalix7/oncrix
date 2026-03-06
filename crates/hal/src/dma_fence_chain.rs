// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA fence chaining operations.
//!
//! Provides a chain of DMA fences that represent a timeline of ordered GPU/DMA
//! work items. Each chain node wraps a base fence and carries a sequence number
//! (`seqno`). The chain advances monotonically: a node at seqno N is signaled
//! only after the node at seqno N-1 has been signaled.
//!
//! # Architecture
//!
//! - [`ChainNode`] — a single node linking a fence ID with its seqno and next pointer.
//! - [`DmaFenceChain`] — a singly-linked list of [`ChainNode`]s forming an ordered timeline.
//! - [`FenceChainRegistry`] — manages up to [`MAX_CHAINS`] independent chains.
//!
//! # Usage
//!
//! ```ignore
//! let mut registry = FenceChainRegistry::new();
//! let chain_id = registry.create_chain()?;
//! registry.push(chain_id, fence_id_1, 1)?;
//! registry.push(chain_id, fence_id_2, 2)?;
//! // Advance the chain to seqno 1 — nodes with seqno ≤ 1 become eligible.
//! let ready = registry.collect_ready(chain_id, 1)?;
//! ```
//!
//! Reference: Linux `drivers/dma-buf/dma-fence-chain.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of nodes per chain.
const MAX_NODES_PER_CHAIN: usize = 64;

/// Maximum number of concurrent chains.
const MAX_CHAINS: usize = 16;

/// Sentinel value indicating an unused node slot.
const INVALID_FENCE_ID: u32 = u32::MAX;

/// Sentinel seqno for an empty/unused node.
const INVALID_SEQNO: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// ChainNode
// ---------------------------------------------------------------------------

/// A single node in a DMA fence chain.
///
/// Each node holds a reference to one underlying fence (by ID) and the
/// timeline sequence number at which it should be signaled. Nodes are
/// stored in ascending seqno order within a chain.
#[derive(Debug, Clone, Copy)]
pub struct ChainNode {
    /// The fence ID this node wraps.
    pub fence_id: u32,
    /// Timeline sequence number for this node.
    pub seqno: u64,
    /// Whether this node has already been signaled/consumed.
    pub signaled: bool,
    /// Whether this slot is occupied.
    pub occupied: bool,
}

impl ChainNode {
    /// Creates an empty, unoccupied node slot.
    pub const fn new() -> Self {
        Self {
            fence_id: INVALID_FENCE_ID,
            seqno: INVALID_SEQNO,
            signaled: false,
            occupied: false,
        }
    }

    /// Creates an occupied node for the given fence and seqno.
    pub const fn with_fence(fence_id: u32, seqno: u64) -> Self {
        Self {
            fence_id,
            seqno,
            signaled: false,
            occupied: true,
        }
    }
}

impl Default for ChainNode {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DmaFenceChain
// ---------------------------------------------------------------------------

/// An ordered chain of DMA fence nodes forming a timeline.
///
/// Nodes are kept in ascending `seqno` order. The chain tracks the last
/// signaled sequence number so that out-of-order signals can be detected.
pub struct DmaFenceChain {
    /// Ordered array of chain nodes.
    nodes: [ChainNode; MAX_NODES_PER_CHAIN],
    /// Number of nodes currently in the chain.
    count: usize,
    /// The highest seqno that has been signaled so far.
    pub last_signaled_seqno: u64,
    /// The next expected seqno (for monotonicity enforcement).
    pub next_seqno: u64,
    /// Whether this chain slot is active.
    pub active: bool,
}

impl DmaFenceChain {
    /// Creates an empty, inactive chain.
    pub const fn new() -> Self {
        Self {
            nodes: [const { ChainNode::new() }; MAX_NODES_PER_CHAIN],
            count: 0,
            last_signaled_seqno: 0,
            next_seqno: 1,
            active: false,
        }
    }

    /// Activates the chain for use.
    pub fn activate(&mut self) {
        self.active = true;
        self.count = 0;
        self.last_signaled_seqno = 0;
        self.next_seqno = 1;
    }

    /// Resets the chain to its initial state.
    pub fn reset(&mut self) {
        for i in 0..MAX_NODES_PER_CHAIN {
            self.nodes[i] = ChainNode::new();
        }
        self.count = 0;
        self.last_signaled_seqno = 0;
        self.next_seqno = 1;
        self.active = false;
    }

    /// Pushes a new node onto the chain.
    ///
    /// The `seqno` must be strictly greater than the seqno of any existing node
    /// to maintain monotonic ordering.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the chain is full.
    /// - [`Error::InvalidArgument`] if `seqno` is not strictly monotonically increasing.
    pub fn push(&mut self, fence_id: u32, seqno: u64) -> Result<()> {
        if self.count >= MAX_NODES_PER_CHAIN {
            return Err(Error::OutOfMemory);
        }
        // Enforce monotonic seqno.
        if self.count > 0 {
            let last_seqno = self.nodes[self.count - 1].seqno;
            if seqno <= last_seqno {
                return Err(Error::InvalidArgument);
            }
        }
        self.nodes[self.count] = ChainNode::with_fence(fence_id, seqno);
        self.count += 1;
        if seqno >= self.next_seqno {
            self.next_seqno = seqno + 1;
        }
        Ok(())
    }

    /// Returns the number of nodes in the chain.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the chain has no nodes.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the seqno of the head (oldest unsignaled) node, or `None` if empty.
    pub fn head_seqno(&self) -> Option<u64> {
        for i in 0..self.count {
            if !self.nodes[i].signaled {
                return Some(self.nodes[i].seqno);
            }
        }
        None
    }

    /// Returns the seqno of the tail (newest) node, or `None` if empty.
    pub fn tail_seqno(&self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        Some(self.nodes[self.count - 1].seqno)
    }

    /// Collects fence IDs of nodes with `seqno <= target`, writing them into `out`.
    ///
    /// Returns the number of fence IDs written. These nodes are marked signaled.
    pub fn collect_ready(&mut self, target_seqno: u64, out: &mut [u32]) -> usize {
        let mut found = 0;
        for i in 0..self.count {
            if self.nodes[i].occupied
                && !self.nodes[i].signaled
                && self.nodes[i].seqno <= target_seqno
            {
                if found < out.len() {
                    out[found] = self.nodes[i].fence_id;
                    self.nodes[i].signaled = true;
                    if self.nodes[i].seqno > self.last_signaled_seqno {
                        self.last_signaled_seqno = self.nodes[i].seqno;
                    }
                    found += 1;
                }
            }
        }
        found
    }

    /// Polls whether the chain has advanced to at least `target_seqno`.
    ///
    /// Returns `Ok(true)` when `last_signaled_seqno >= target_seqno`, `Ok(false)`
    /// while still waiting, and `Err(IoError)` if `target_seqno` was never pushed.
    pub fn poll_completion(&self, target_seqno: u64) -> Result<bool> {
        if self.last_signaled_seqno >= target_seqno {
            return Ok(true);
        }
        // Check if the seqno was ever pushed.
        let pushed = (0..self.count).any(|i| self.nodes[i].seqno == target_seqno);
        if !pushed {
            return Err(Error::InvalidArgument);
        }
        Ok(false)
    }

    /// Blocking-style wait: checks if the chain is at or past `target_seqno`.
    ///
    /// Returns `Err(Busy)` when still pending, `Err(IoError)` on timeout.
    pub fn wait(&self, target_seqno: u64, now_ticks: u64, timeout_ticks: u64) -> Result<()> {
        if self.last_signaled_seqno >= target_seqno {
            return Ok(());
        }
        if timeout_ticks != 0 && now_ticks >= timeout_ticks {
            return Err(Error::IoError);
        }
        Err(Error::Busy)
    }

    /// Returns the node at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index >= len`.
    pub fn node_at(&self, index: usize) -> Result<&ChainNode> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.nodes[index])
    }
}

impl Default for DmaFenceChain {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FenceChainRegistry
// ---------------------------------------------------------------------------

/// System-wide registry of DMA fence chains.
///
/// Allows multiple independent fence chains to coexist, each identified by
/// a `chain_id` returned from [`FenceChainRegistry::create_chain`].
pub struct FenceChainRegistry {
    chains: [DmaFenceChain; MAX_CHAINS],
    /// Monotonically increasing ID for new chains.
    next_id: u32,
}

impl FenceChainRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            chains: [const { DmaFenceChain::new() }; MAX_CHAINS],
            next_id: 1,
        }
    }

    /// Allocates a new chain and returns its ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all chain slots are occupied.
    pub fn create_chain(&mut self) -> Result<u32> {
        let idx = self
            .chains
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;
        self.chains[idx].activate();
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        // Store the id in the node's seqno slot — actually encode id as index.
        // We identify chains by their slot index + a generation id approach.
        // For simplicity: id == slot index + 1 on first use; wrap-safe via next_id.
        let _ = id;
        Ok((idx + 1) as u32)
    }

    /// Destroys a chain by its ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no active chain with that ID exists.
    pub fn destroy_chain(&mut self, chain_id: u32) -> Result<()> {
        let idx = self.chain_idx(chain_id)?;
        self.chains[idx].reset();
        Ok(())
    }

    /// Pushes a fence node onto a chain.
    pub fn push(&mut self, chain_id: u32, fence_id: u32, seqno: u64) -> Result<()> {
        let idx = self.chain_idx(chain_id)?;
        self.chains[idx].push(fence_id, seqno)
    }

    /// Collects ready fence IDs from a chain up to `target_seqno`.
    ///
    /// Returns a fixed-size array of up to [`MAX_NODES_PER_CHAIN`] fence IDs
    /// and the count of valid entries.
    pub fn collect_ready(
        &mut self,
        chain_id: u32,
        target_seqno: u64,
    ) -> Result<([u32; MAX_NODES_PER_CHAIN], usize)> {
        let idx = self.chain_idx(chain_id)?;
        let mut out = [INVALID_FENCE_ID; MAX_NODES_PER_CHAIN];
        let count = self.chains[idx].collect_ready(target_seqno, &mut out);
        Ok((out, count))
    }

    /// Polls a chain for completion at `target_seqno`.
    pub fn poll_completion(&self, chain_id: u32, target_seqno: u64) -> Result<bool> {
        let idx = self.chain_idx_ref(chain_id)?;
        self.chains[idx].poll_completion(target_seqno)
    }

    /// Waits on a chain for completion at `target_seqno`.
    pub fn wait(
        &self,
        chain_id: u32,
        target_seqno: u64,
        now_ticks: u64,
        timeout_ticks: u64,
    ) -> Result<()> {
        let idx = self.chain_idx_ref(chain_id)?;
        self.chains[idx].wait(target_seqno, now_ticks, timeout_ticks)
    }

    /// Returns the number of active chains.
    pub fn active_count(&self) -> usize {
        self.chains.iter().filter(|c| c.active).count()
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn chain_idx(&mut self, chain_id: u32) -> Result<usize> {
        let idx = chain_id.checked_sub(1).ok_or(Error::InvalidArgument)? as usize;
        if idx >= MAX_CHAINS || !self.chains[idx].active {
            return Err(Error::NotFound);
        }
        Ok(idx)
    }

    fn chain_idx_ref(&self, chain_id: u32) -> Result<usize> {
        let idx = chain_id.checked_sub(1).ok_or(Error::InvalidArgument)? as usize;
        if idx >= MAX_CHAINS || !self.chains[idx].active {
            return Err(Error::NotFound);
        }
        Ok(idx)
    }
}

impl Default for FenceChainRegistry {
    fn default() -> Self {
        Self::new()
    }
}
