// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VMA memory policy (NUMA mempolicy).
//!
//! Implements NUMA memory allocation policies attached to VMAs or tasks.
//! Policies control which NUMA nodes are preferred for page allocation.
//! Modes include Default, Preferred, Bind, Interleave, and LocalAlloc.
//! Policy rebinding handles NUMA topology changes (hotplug).
//!
//! - [`MempolicyMode`] — policy mode enumeration
//! - [`NodeMask`] — bitmask of NUMA nodes
//! - [`MempolicyFlags`] — policy modifier flags
//! - [`Mempolicy`] — the memory policy structure
//! - [`MempolicyManager`] — policy creation and lookup
//!
//! Reference: `.kernelORG/` — `mm/mempolicy.c`, `include/linux/mempolicy.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of NUMA nodes.
const MAX_NODES: usize = 64;

/// Maximum policies per manager.
const MAX_POLICIES: usize = 128;

/// Invalid policy ID.
const INVALID_POLICY_ID: u32 = u32::MAX;

/// Policy flag: apply policy relative to VMA, not task.
const MPOL_F_RELATIVE_NODES: u32 = 1 << 0;

/// Policy flag: static node mask (no rebinding).
const MPOL_F_STATIC_NODES: u32 = 1 << 1;

/// Policy flag: local allocation on empty node mask.
const MPOL_F_LOCAL: u32 = 1 << 2;

/// Policy flag: shared between processes.
const MPOL_F_SHARED: u32 = 1 << 3;

/// Policy flag: modbind (soft binding).
const MPOL_F_MOD_BIND: u32 = 1 << 4;

// -------------------------------------------------------------------
// MempolicyMode
// -------------------------------------------------------------------

/// NUMA memory policy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MempolicyMode {
    /// Default system policy (usually local allocation).
    #[default]
    Default,
    /// Prefer a specific node, fall back to others.
    Preferred,
    /// Bind to a set of nodes; fail if none available.
    Bind,
    /// Interleave allocations across nodes in round-robin.
    Interleave,
    /// Allocate on the local (current CPU's) node.
    LocalAlloc,
}

impl MempolicyMode {
    /// Returns a human-readable name for the mode.
    pub fn as_str(self) -> &'static str {
        match self {
            MempolicyMode::Default => "default",
            MempolicyMode::Preferred => "prefer",
            MempolicyMode::Bind => "bind",
            MempolicyMode::Interleave => "interleave",
            MempolicyMode::LocalAlloc => "local",
        }
    }

    /// Creates from integer (for syscall interface).
    pub fn from_raw(val: u32) -> Result<Self> {
        match val {
            0 => Ok(MempolicyMode::Default),
            1 => Ok(MempolicyMode::Preferred),
            2 => Ok(MempolicyMode::Bind),
            3 => Ok(MempolicyMode::Interleave),
            4 => Ok(MempolicyMode::LocalAlloc),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// -------------------------------------------------------------------
// NodeMask
// -------------------------------------------------------------------

/// Bitmask representing a set of NUMA nodes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NodeMask {
    /// Bitmask (bit N = node N is included).
    bits: u64,
}

impl NodeMask {
    /// Creates an empty node mask.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates a node mask with all nodes up to `nr_nodes`.
    pub fn all(nr_nodes: usize) -> Self {
        if nr_nodes == 0 || nr_nodes > MAX_NODES {
            return Self::empty();
        }
        let bits = if nr_nodes >= 64 {
            u64::MAX
        } else {
            (1u64 << nr_nodes) - 1
        };
        Self { bits }
    }

    /// Creates a single-node mask.
    pub fn single(node: usize) -> Self {
        if node >= MAX_NODES {
            return Self::empty();
        }
        Self { bits: 1u64 << node }
    }

    /// Returns the raw bits.
    pub const fn bits(self) -> u64 {
        self.bits
    }

    /// Tests if a node is set.
    pub fn contains(self, node: usize) -> bool {
        if node >= MAX_NODES {
            return false;
        }
        self.bits & (1u64 << node) != 0
    }

    /// Sets a node.
    pub fn set(&mut self, node: usize) {
        if node < MAX_NODES {
            self.bits |= 1u64 << node;
        }
    }

    /// Clears a node.
    pub fn clear(&mut self, node: usize) {
        if node < MAX_NODES {
            self.bits &= !(1u64 << node);
        }
    }

    /// Returns true if the mask is empty.
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// Returns the number of nodes set.
    pub fn weight(self) -> u32 {
        self.bits.count_ones()
    }

    /// Returns the first set node, or None.
    pub fn first(self) -> Option<usize> {
        if self.bits == 0 {
            None
        } else {
            Some(self.bits.trailing_zeros() as usize)
        }
    }

    /// Returns the next set node after `prev`, or None.
    pub fn next_after(self, prev: usize) -> Option<usize> {
        if prev + 1 >= MAX_NODES {
            return None;
        }
        let shifted = self.bits >> (prev + 1);
        if shifted == 0 {
            None
        } else {
            Some(prev + 1 + shifted.trailing_zeros() as usize)
        }
    }

    /// Intersects with another mask.
    pub fn and(self, other: Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }

    /// Union with another mask.
    pub fn or(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Complements the mask.
    pub fn not(self) -> Self {
        Self { bits: !self.bits }
    }
}

impl Default for NodeMask {
    fn default() -> Self {
        Self::empty()
    }
}

impl core::fmt::Debug for NodeMask {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NodeMask({:#018x})", self.bits)
    }
}

// -------------------------------------------------------------------
// Mempolicy
// -------------------------------------------------------------------

/// A NUMA memory policy.
///
/// Controls how pages are allocated across NUMA nodes for a VMA or task.
#[derive(Debug, Clone)]
pub struct Mempolicy {
    /// Policy mode.
    mode: MempolicyMode,
    /// Allowed/preferred NUMA nodes.
    nodemask: NodeMask,
    /// Policy flags.
    flags: u32,
    /// Reference count.
    refcount: u32,
    /// Policy ID for management.
    id: u32,
    /// Interleave state: next node index (for round-robin).
    interleave_idx: usize,
}

impl Mempolicy {
    /// Creates a new Default policy.
    pub fn new_default() -> Self {
        Self {
            mode: MempolicyMode::Default,
            nodemask: NodeMask::empty(),
            flags: 0,
            refcount: 1,
            id: INVALID_POLICY_ID,
            interleave_idx: 0,
        }
    }

    /// Creates a new Preferred policy for the given node.
    pub fn new_preferred(node: usize) -> Self {
        Self {
            mode: MempolicyMode::Preferred,
            nodemask: NodeMask::single(node),
            flags: 0,
            refcount: 1,
            id: INVALID_POLICY_ID,
            interleave_idx: 0,
        }
    }

    /// Creates a new Bind policy for the given node mask.
    pub fn new_bind(nodemask: NodeMask) -> Self {
        Self {
            mode: MempolicyMode::Bind,
            nodemask,
            flags: 0,
            refcount: 1,
            id: INVALID_POLICY_ID,
            interleave_idx: 0,
        }
    }

    /// Creates a new Interleave policy for the given node mask.
    pub fn new_interleave(nodemask: NodeMask) -> Self {
        let first = nodemask.first().unwrap_or(0);
        Self {
            mode: MempolicyMode::Interleave,
            nodemask,
            flags: 0,
            refcount: 1,
            id: INVALID_POLICY_ID,
            interleave_idx: first,
        }
    }

    /// Creates a new LocalAlloc policy.
    pub fn new_local() -> Self {
        Self {
            mode: MempolicyMode::LocalAlloc,
            nodemask: NodeMask::empty(),
            flags: MPOL_F_LOCAL,
            refcount: 1,
            id: INVALID_POLICY_ID,
            interleave_idx: 0,
        }
    }

    /// Returns the policy mode.
    pub fn mode(&self) -> MempolicyMode {
        self.mode
    }

    /// Returns the node mask.
    pub fn nodemask(&self) -> NodeMask {
        self.nodemask
    }

    /// Returns the policy flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Sets policy flags.
    pub fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }

    /// Returns the reference count.
    pub fn refcount(&self) -> u32 {
        self.refcount
    }

    /// Increments reference count.
    pub fn get_ref(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    /// Decrements reference count. Returns true if dropped to zero.
    pub fn put_ref(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount == 0
    }

    /// Returns the preferred node for allocation.
    ///
    /// For Preferred: returns the single preferred node.
    /// For Bind: returns the first allowed node.
    /// For Interleave: returns the next node in round-robin.
    /// For LocalAlloc/Default: returns the given local node.
    pub fn preferred_node(&mut self, local_node: usize) -> usize {
        match self.mode {
            MempolicyMode::Default | MempolicyMode::LocalAlloc => local_node,
            MempolicyMode::Preferred => self.nodemask.first().unwrap_or(local_node),
            MempolicyMode::Bind => {
                if self.nodemask.contains(local_node) {
                    local_node
                } else {
                    self.nodemask.first().unwrap_or(local_node)
                }
            }
            MempolicyMode::Interleave => {
                let node = self.interleave_idx;
                // Advance to next node in mask.
                self.interleave_idx = self
                    .nodemask
                    .next_after(node)
                    .or_else(|| self.nodemask.first())
                    .unwrap_or(0);
                node
            }
        }
    }

    /// Checks if allocation from the given node is allowed.
    pub fn node_allowed(&self, node: usize) -> bool {
        match self.mode {
            MempolicyMode::Default | MempolicyMode::LocalAlloc => true,
            MempolicyMode::Preferred => true, // preferred is soft
            MempolicyMode::Bind => self.nodemask.contains(node),
            MempolicyMode::Interleave => self.nodemask.contains(node),
        }
    }

    /// Rebinds the policy to a new set of online nodes.
    ///
    /// Called when NUMA topology changes (hotplug). Updates the node mask
    /// to intersect with available nodes.
    pub fn rebind(&mut self, online_nodes: NodeMask) {
        if self.flags & MPOL_F_STATIC_NODES != 0 {
            // Static nodes are not rebound.
            return;
        }
        match self.mode {
            MempolicyMode::Default | MempolicyMode::LocalAlloc => {}
            MempolicyMode::Preferred => {
                let new_mask = self.nodemask.and(online_nodes);
                if !new_mask.is_empty() {
                    self.nodemask = new_mask;
                }
                // If preferred node went offline, keep it (soft preference).
            }
            MempolicyMode::Bind | MempolicyMode::Interleave => {
                let new_mask = self.nodemask.and(online_nodes);
                if !new_mask.is_empty() {
                    self.nodemask = new_mask;
                }
                // Reset interleave index.
                if self.mode == MempolicyMode::Interleave {
                    self.interleave_idx = self.nodemask.first().unwrap_or(0);
                }
            }
        }
    }
}

// -------------------------------------------------------------------
// MempolicyManager
// -------------------------------------------------------------------

/// Manages memory policies for the system.
///
/// Creates, stores, and looks up policies by ID. VMA policy lookup
/// falls back to task policy if no VMA-specific policy is set.
pub struct MempolicyManager {
    /// Policy storage.
    policies: [Option<Mempolicy>; MAX_POLICIES],
    /// Next policy ID to assign.
    next_id: u32,
    /// Default system policy.
    default_policy: Mempolicy,
    /// Online node mask.
    online_nodes: NodeMask,
}

impl MempolicyManager {
    /// Creates a new policy manager.
    pub fn new(online_nodes: NodeMask) -> Self {
        const NONE: Option<Mempolicy> = None;
        Self {
            policies: [NONE; MAX_POLICIES],
            next_id: 0,
            default_policy: Mempolicy::new_default(),
            online_nodes,
        }
    }

    /// Creates and registers a new policy.
    pub fn mpol_new(&mut self, mode: MempolicyMode, nodemask: NodeMask, flags: u32) -> Result<u32> {
        let id = self.next_id;
        if id as usize >= MAX_POLICIES {
            return Err(Error::OutOfMemory);
        }

        let mut policy = match mode {
            MempolicyMode::Default => Mempolicy::new_default(),
            MempolicyMode::Preferred => {
                let node = nodemask.first().ok_or(Error::InvalidArgument)?;
                Mempolicy::new_preferred(node)
            }
            MempolicyMode::Bind => {
                if nodemask.is_empty() {
                    return Err(Error::InvalidArgument);
                }
                Mempolicy::new_bind(nodemask)
            }
            MempolicyMode::Interleave => {
                if nodemask.is_empty() {
                    return Err(Error::InvalidArgument);
                }
                Mempolicy::new_interleave(nodemask)
            }
            MempolicyMode::LocalAlloc => Mempolicy::new_local(),
        };
        policy.set_flags(flags);
        policy.id = id;
        self.policies[id as usize] = Some(policy);
        self.next_id += 1;
        Ok(id)
    }

    /// Frees a policy (decrements refcount, removes if zero).
    pub fn mpol_free(&mut self, id: u32) -> Result<()> {
        let idx = id as usize;
        if idx >= MAX_POLICIES {
            return Err(Error::InvalidArgument);
        }
        let policy = self.policies[idx].as_mut().ok_or(Error::NotFound)?;
        if policy.put_ref() {
            self.policies[idx] = None;
        }
        Ok(())
    }

    /// Looks up a policy by ID.
    pub fn get(&self, id: u32) -> Option<&Mempolicy> {
        let idx = id as usize;
        if idx >= MAX_POLICIES {
            return None;
        }
        self.policies[idx].as_ref()
    }

    /// Looks up a mutable policy by ID.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut Mempolicy> {
        let idx = id as usize;
        if idx >= MAX_POLICIES {
            return None;
        }
        self.policies[idx].as_mut()
    }

    /// VMA policy lookup: returns the VMA policy if set, otherwise
    /// the task policy, otherwise the system default.
    pub fn vma_policy(
        &self,
        vma_policy_id: Option<u32>,
        task_policy_id: Option<u32>,
    ) -> &Mempolicy {
        if let Some(id) = vma_policy_id {
            if let Some(policy) = self.get(id) {
                return policy;
            }
        }
        if let Some(id) = task_policy_id {
            if let Some(policy) = self.get(id) {
                return policy;
            }
        }
        &self.default_policy
    }

    /// Rebinds all policies to new online nodes (hotplug event).
    pub fn mpol_rebind(&mut self, new_online: NodeMask) {
        self.online_nodes = new_online;
        for slot in &mut self.policies {
            if let Some(policy) = slot.as_mut() {
                policy.rebind(new_online);
            }
        }
    }

    /// Returns the system default policy.
    pub fn default_policy(&self) -> &Mempolicy {
        &self.default_policy
    }

    /// Returns the online node mask.
    pub fn online_nodes(&self) -> NodeMask {
        self.online_nodes
    }

    /// Returns the number of active policies.
    pub fn active_count(&self) -> usize {
        self.policies.iter().filter(|p| p.is_some()).count()
    }
}
