// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA memory policy — `set_mempolicy(2)`, `get_mempolicy(2)`, `mbind(2)`.
//!
//! This module implements the NUMA memory policy system calls that
//! control how memory is allocated across NUMA nodes. Policies can
//! be set per-task (default allocation policy) or per-VMA (via
//! `mbind`).
//!
//! # Syscall signatures
//!
//! ```text
//! long set_mempolicy(int mode, const unsigned long *nodemask,
//!                    unsigned long maxnode);
//! long get_mempolicy(int *mode, unsigned long *nodemask,
//!                    unsigned long maxnode, void *addr,
//!                    unsigned long flags);
//! long mbind(void *addr, unsigned long len, int mode,
//!            const unsigned long *nodemask, unsigned long maxnode,
//!            unsigned flags);
//! ```
//!
//! # Policies
//!
//! | Policy | Description |
//! |--------|-------------|
//! | `MPOL_DEFAULT` | System default — allocate from local node |
//! | `MPOL_BIND` | Restrict allocation to specified nodes only |
//! | `MPOL_INTERLEAVE` | Round-robin across specified nodes |
//! | `MPOL_PREFERRED` | Prefer allocation from a specific node |
//! | `MPOL_LOCAL` | Allocate from the CPU's local node |
//!
//! # Flags for `get_mempolicy`
//!
//! | Flag | Description |
//! |------|-------------|
//! | `MPOL_F_NODE` | Return the node ID for a specific address |
//! | `MPOL_F_ADDR` | Look up the policy for a specific address |
//! | `MPOL_F_MEMS_ALLOWED` | Return the set of allowed nodes |
//!
//! # References
//!
//! - Linux: `mm/mempolicy.c`, `include/uapi/linux/mempolicy.h`
//! - `set_mempolicy(2)`, `get_mempolicy(2)`, `mbind(2)` man pages

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants — policy modes
// ---------------------------------------------------------------------------

/// Default policy: allocate from the local node.
pub const MPOL_DEFAULT: u32 = 0;
/// Restrict allocation to specified nodes only.
pub const MPOL_PREFERRED: u32 = 1;
/// Strict binding: only allocate from the nodemask.
pub const MPOL_BIND: u32 = 2;
/// Interleave allocations round-robin across nodes.
pub const MPOL_INTERLEAVE: u32 = 3;
/// Allocate from the CPU's local NUMA node.
pub const MPOL_LOCAL: u32 = 4;

/// Maximum valid policy mode.
const MPOL_MAX: u32 = 5;

// ---------------------------------------------------------------------------
// Constants — mode flags (combined with mode in set_mempolicy)
// ---------------------------------------------------------------------------

/// Return policy in static form (strip node info).
pub const MPOL_F_STATIC_NODES: u32 = 1 << 15;
/// Remap nodes relative to task's allowed set.
pub const MPOL_F_RELATIVE_NODES: u32 = 1 << 14;

/// Mask of mode flags (bits 14-15).
const MPOL_MODE_FLAGS_MASK: u32 = MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES;

// ---------------------------------------------------------------------------
// Constants — get_mempolicy flags
// ---------------------------------------------------------------------------

/// Return the node ID that would be used for the address.
pub const MPOL_F_NODE: u32 = 1 << 0;
/// Look up policy for a specific address (per-VMA policy).
pub const MPOL_F_ADDR: u32 = 1 << 1;
/// Return the set of memory nodes allowed by cpuset.
pub const MPOL_F_MEMS_ALLOWED: u32 = 1 << 2;

/// Mask of valid get_mempolicy flags.
const MPOL_F_GET_VALID_MASK: u32 = MPOL_F_NODE | MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED;

// ---------------------------------------------------------------------------
// Constants — mbind flags
// ---------------------------------------------------------------------------

/// Verify existing pages match policy (strict).
pub const MPOL_MF_STRICT: u32 = 1 << 0;
/// Move pages to conform to policy.
pub const MPOL_MF_MOVE: u32 = 1 << 1;
/// Move all pages (not just those owned by the process).
pub const MPOL_MF_MOVE_ALL: u32 = 1 << 2;

/// Mask of valid mbind flags.
const MPOL_MF_VALID_MASK: u32 = MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_MOVE_ALL;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum number of NUMA nodes.
pub const MAX_NUMA_NODES: usize = 64;

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page mask (low 12 bits).
const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// User-space address limit.
const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

/// Maximum per-VMA policies.
const MAX_VMA_POLICIES: usize = 128;

// ---------------------------------------------------------------------------
// NodeMask — NUMA node bitmask
// ---------------------------------------------------------------------------

/// A bitmask of NUMA node IDs.
///
/// Supports up to [`MAX_NUMA_NODES`] nodes. Used to specify which
/// nodes a memory policy applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeMask {
    /// Bitmask where bit `i` represents node `i`.
    bits: u64,
}

impl NodeMask {
    /// Create an empty node mask (no nodes).
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Create a node mask from a raw bitmask.
    pub const fn from_raw(bits: u64) -> Self {
        Self { bits }
    }

    /// Create a node mask with a single node.
    pub fn single(node: u32) -> Result<Self> {
        if node >= MAX_NUMA_NODES as u32 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { bits: 1u64 << node })
    }

    /// Return the raw bitmask.
    pub const fn raw(&self) -> u64 {
        self.bits
    }

    /// Return `true` if the mask is empty.
    pub const fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// Return the number of nodes in the mask.
    pub const fn count(&self) -> u32 {
        self.bits.count_ones()
    }

    /// Return `true` if the given node is in the mask.
    pub const fn contains(&self, node: u32) -> bool {
        if node >= MAX_NUMA_NODES as u32 {
            return false;
        }
        self.bits & (1u64 << node) != 0
    }

    /// Add a node to the mask.
    pub fn set(&mut self, node: u32) -> Result<()> {
        if node >= MAX_NUMA_NODES as u32 {
            return Err(Error::InvalidArgument);
        }
        self.bits |= 1u64 << node;
        Ok(())
    }

    /// Remove a node from the mask.
    pub fn clear(&mut self, node: u32) -> Result<()> {
        if node >= MAX_NUMA_NODES as u32 {
            return Err(Error::InvalidArgument);
        }
        self.bits &= !(1u64 << node);
        Ok(())
    }

    /// Intersect with another mask.
    pub const fn intersect(&self, other: &NodeMask) -> NodeMask {
        NodeMask {
            bits: self.bits & other.bits,
        }
    }

    /// Union with another mask.
    pub const fn union(&self, other: &NodeMask) -> NodeMask {
        NodeMask {
            bits: self.bits | other.bits,
        }
    }

    /// Return the first set node, or `None` if empty.
    pub fn first_node(&self) -> Option<u32> {
        if self.bits == 0 {
            None
        } else {
            Some(self.bits.trailing_zeros())
        }
    }

    /// Get the Nth set node (for interleave round-robin).
    pub fn nth_node(&self, n: u32) -> Option<u32> {
        let count = self.count();
        if count == 0 {
            return None;
        }
        let idx = n % count;
        let mut seen = 0u32;
        for bit in 0..MAX_NUMA_NODES as u32 {
            if self.contains(bit) {
                if seen == idx {
                    return Some(bit);
                }
                seen += 1;
            }
        }
        None
    }

    /// Validate that the mask only contains nodes from the allowed set.
    pub fn validate_against(&self, allowed: &NodeMask) -> Result<()> {
        if self.bits & !allowed.bits != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for NodeMask {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// MemPolicy — a single memory policy
// ---------------------------------------------------------------------------

/// A NUMA memory policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemPolicy {
    /// Policy mode (MPOL_DEFAULT, MPOL_BIND, etc.).
    pub mode: u32,
    /// Mode flags (MPOL_F_STATIC_NODES, MPOL_F_RELATIVE_NODES).
    pub mode_flags: u32,
    /// Node mask for this policy.
    pub nodemask: NodeMask,
}

impl MemPolicy {
    /// Create the default policy (local allocation).
    pub const fn default_policy() -> Self {
        Self {
            mode: MPOL_DEFAULT,
            mode_flags: 0,
            nodemask: NodeMask::empty(),
        }
    }

    /// Create a new policy.
    pub fn new(mode: u32, mode_flags: u32, nodemask: NodeMask) -> Result<Self> {
        let policy = Self {
            mode,
            mode_flags,
            nodemask,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validate the policy.
    pub fn validate(&self) -> Result<()> {
        if self.mode >= MPOL_MAX {
            return Err(Error::InvalidArgument);
        }
        if self.mode_flags & !MPOL_MODE_FLAGS_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        // STATIC_NODES and RELATIVE_NODES are mutually exclusive.
        if self.mode_flags & MPOL_F_STATIC_NODES != 0
            && self.mode_flags & MPOL_F_RELATIVE_NODES != 0
        {
            return Err(Error::InvalidArgument);
        }
        match self.mode {
            MPOL_DEFAULT | MPOL_LOCAL => {
                // No nodemask required (it's ignored).
            }
            MPOL_PREFERRED => {
                // At most one node should be set.
                if self.nodemask.count() > 1 {
                    return Err(Error::InvalidArgument);
                }
            }
            MPOL_BIND | MPOL_INTERLEAVE => {
                // At least one node must be set.
                if self.nodemask.is_empty() {
                    return Err(Error::InvalidArgument);
                }
            }
            _ => return Err(Error::InvalidArgument),
        }
        Ok(())
    }

    /// Determine which node to allocate from.
    ///
    /// `local_node` is the CPU's local NUMA node.
    /// `interleave_index` is the round-robin counter for INTERLEAVE.
    pub fn target_node(&self, local_node: u32, interleave_index: u32) -> u32 {
        match self.mode {
            MPOL_DEFAULT | MPOL_LOCAL => local_node,
            MPOL_PREFERRED => self.nodemask.first_node().unwrap_or(local_node),
            MPOL_BIND => {
                // Prefer local if it's in the mask.
                if self.nodemask.contains(local_node) {
                    local_node
                } else {
                    self.nodemask.first_node().unwrap_or(local_node)
                }
            }
            MPOL_INTERLEAVE => self
                .nodemask
                .nth_node(interleave_index)
                .unwrap_or(local_node),
            _ => local_node,
        }
    }
}

impl Default for MemPolicy {
    fn default() -> Self {
        Self::default_policy()
    }
}

// ---------------------------------------------------------------------------
// VmaPolicy — per-VMA memory policy
// ---------------------------------------------------------------------------

/// A per-VMA memory policy binding.
#[derive(Debug, Clone, Copy)]
pub struct VmaPolicy {
    /// Start address (page-aligned).
    pub addr: u64,
    /// Length in bytes (page-aligned).
    pub len: u64,
    /// Memory policy for this VMA.
    pub policy: MemPolicy,
    /// mbind flags used.
    pub mbind_flags: u32,
}

// ---------------------------------------------------------------------------
// MemPolicyContext — per-task memory policy context
// ---------------------------------------------------------------------------

/// Per-task NUMA memory policy context.
///
/// Manages the task's default policy and per-VMA policies.
pub struct MemPolicyContext {
    /// Task default memory policy.
    pub default_policy: MemPolicy,
    /// Per-VMA policies.
    vma_policies: [Option<VmaPolicy>; MAX_VMA_POLICIES],
    /// Number of VMA policies.
    vma_policy_count: usize,
    /// Allowed nodes (from cpuset/cgroup constraints).
    allowed_nodes: NodeMask,
    /// Interleave counter for round-robin.
    interleave_index: u32,
}

impl MemPolicyContext {
    /// Create a new policy context with all nodes allowed.
    pub fn new(node_count: u32) -> Self {
        let mut allowed = NodeMask::empty();
        for i in 0..node_count.min(MAX_NUMA_NODES as u32) {
            let _ = allowed.set(i);
        }
        Self {
            default_policy: MemPolicy::default_policy(),
            vma_policies: [const { None }; MAX_VMA_POLICIES],
            vma_policy_count: 0,
            allowed_nodes: allowed,
            interleave_index: 0,
        }
    }

    /// Set the task's default memory policy.
    ///
    /// Implements `set_mempolicy(2)`.
    pub fn set_mempolicy(&mut self, mode: u32, nodemask: NodeMask) -> Result<()> {
        let mode_val = mode & !MPOL_MODE_FLAGS_MASK;
        let mode_flags = mode & MPOL_MODE_FLAGS_MASK;

        // Validate nodemask against allowed nodes.
        if !nodemask.is_empty() {
            nodemask.validate_against(&self.allowed_nodes)?;
        }

        let policy = MemPolicy::new(mode_val, mode_flags, nodemask)?;
        self.default_policy = policy;
        Ok(())
    }

    /// Get the effective memory policy for an address.
    ///
    /// Implements `get_mempolicy(2)`.
    pub fn get_mempolicy(&self, addr: u64, flags: u32) -> Result<GetMempolicyResult> {
        if flags & !MPOL_F_GET_VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if flags & MPOL_F_MEMS_ALLOWED != 0 {
            return Ok(GetMempolicyResult {
                mode: MPOL_DEFAULT,
                nodemask: self.allowed_nodes,
            });
        }
        if flags & MPOL_F_ADDR != 0 {
            // Look up per-VMA policy.
            if let Some(vp) = self.find_vma_policy(addr) {
                return Ok(GetMempolicyResult {
                    mode: vp.policy.mode | vp.policy.mode_flags,
                    nodemask: vp.policy.nodemask,
                });
            }
        }
        // Return task default.
        Ok(GetMempolicyResult {
            mode: self.default_policy.mode | self.default_policy.mode_flags,
            nodemask: self.default_policy.nodemask,
        })
    }

    /// Bind a memory policy to a VMA range.
    ///
    /// Implements `mbind(2)`.
    pub fn mbind(
        &mut self,
        addr: u64,
        len: u64,
        mode: u32,
        nodemask: NodeMask,
        flags: u32,
    ) -> Result<()> {
        // Validate address range.
        if addr & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if len == 0 || len & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        let end = addr.checked_add(len).ok_or(Error::InvalidArgument)?;
        if end > USER_SPACE_END {
            return Err(Error::InvalidArgument);
        }
        if flags & !MPOL_MF_VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        // MOVE_ALL requires additional privilege (not checked here).
        let mode_val = mode & !MPOL_MODE_FLAGS_MASK;
        let mode_flags = mode & MPOL_MODE_FLAGS_MASK;

        if !nodemask.is_empty() {
            nodemask.validate_against(&self.allowed_nodes)?;
        }

        let policy = MemPolicy::new(mode_val, mode_flags, nodemask)?;

        // Find or allocate a VMA policy slot.
        if self.vma_policy_count >= MAX_VMA_POLICIES {
            return Err(Error::OutOfMemory);
        }
        for slot in &mut self.vma_policies {
            if slot.is_none() {
                *slot = Some(VmaPolicy {
                    addr,
                    len,
                    policy,
                    mbind_flags: flags,
                });
                self.vma_policy_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Determine the allocation node for a given address.
    pub fn allocation_node(&mut self, addr: u64, local_node: u32) -> u32 {
        let policy = if let Some(vp) = self.find_vma_policy(addr) {
            &vp.policy
        } else {
            &self.default_policy
        };
        let node = policy.target_node(local_node, self.interleave_index);
        if policy.mode == MPOL_INTERLEAVE {
            self.interleave_index = self.interleave_index.wrapping_add(1);
        }
        node
    }

    /// Return the allowed node mask.
    pub const fn allowed_nodes(&self) -> &NodeMask {
        &self.allowed_nodes
    }

    /// Set the allowed node mask (e.g., from cpuset update).
    pub fn set_allowed_nodes(&mut self, mask: NodeMask) {
        self.allowed_nodes = mask;
    }

    /// Return the number of per-VMA policies.
    pub const fn vma_policy_count(&self) -> usize {
        self.vma_policy_count
    }

    /// Find the VMA policy covering an address.
    fn find_vma_policy(&self, addr: u64) -> Option<&VmaPolicy> {
        for slot in &self.vma_policies {
            if let Some(vp) = slot {
                if addr >= vp.addr && addr < vp.addr.saturating_add(vp.len) {
                    return Some(vp);
                }
            }
        }
        None
    }
}

impl Default for MemPolicyContext {
    fn default() -> Self {
        Self::new(4)
    }
}

// ---------------------------------------------------------------------------
// GetMempolicyResult
// ---------------------------------------------------------------------------

/// Result of `get_mempolicy(2)`.
#[derive(Debug, Clone, Copy)]
pub struct GetMempolicyResult {
    /// Policy mode (including mode flags).
    pub mode: u32,
    /// Node mask.
    pub nodemask: NodeMask,
}

// ---------------------------------------------------------------------------
// Syscall entry points
// ---------------------------------------------------------------------------

/// Process the `set_mempolicy(2)` syscall.
///
/// # Arguments
///
/// - `ctx` — Per-task policy context.
/// - `mode` — Policy mode plus optional mode flags.
/// - `nodemask` — Node bitmask.
///
/// # Errors
///
/// - `InvalidArgument` — Invalid mode, flags, or nodemask.
pub fn sys_set_mempolicy(ctx: &mut MemPolicyContext, mode: u32, nodemask: NodeMask) -> Result<()> {
    ctx.set_mempolicy(mode, nodemask)
}

/// Process the `get_mempolicy(2)` syscall.
///
/// # Arguments
///
/// - `ctx` — Per-task policy context.
/// - `addr` — Address to query (if MPOL_F_ADDR is set).
/// - `flags` — MPOL_F_NODE, MPOL_F_ADDR, MPOL_F_MEMS_ALLOWED.
///
/// # Returns
///
/// [`GetMempolicyResult`] with the policy mode and nodemask.
pub fn sys_get_mempolicy(
    ctx: &MemPolicyContext,
    addr: u64,
    flags: u32,
) -> Result<GetMempolicyResult> {
    ctx.get_mempolicy(addr, flags)
}

/// Process the `mbind(2)` syscall.
///
/// # Arguments
///
/// - `ctx` — Per-task policy context.
/// - `addr` — Start address (page-aligned).
/// - `len` — Length (page-aligned).
/// - `mode` — Policy mode plus optional mode flags.
/// - `nodemask` — Node bitmask.
/// - `flags` — MPOL_MF_STRICT, MPOL_MF_MOVE, MPOL_MF_MOVE_ALL.
///
/// # Errors
///
/// - `InvalidArgument` — Bad address, mode, or flags.
/// - `OutOfMemory` — No free VMA policy slots.
pub fn sys_mbind(
    ctx: &mut MemPolicyContext,
    addr: u64,
    len: u64,
    mode: u32,
    nodemask: NodeMask,
    flags: u32,
) -> Result<()> {
    ctx.mbind(addr, len, mode, nodemask, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nodemask_basic() {
        let mut mask = NodeMask::empty();
        assert!(mask.is_empty());
        mask.set(0).unwrap();
        mask.set(2).unwrap();
        assert!(mask.contains(0));
        assert!(!mask.contains(1));
        assert!(mask.contains(2));
        assert_eq!(mask.count(), 2);
    }

    #[test]
    fn test_nodemask_single() {
        let mask = NodeMask::single(3).unwrap();
        assert!(mask.contains(3));
        assert_eq!(mask.count(), 1);
    }

    #[test]
    fn test_nodemask_first_node() {
        let mask = NodeMask::from_raw(0b1010); // nodes 1, 3
        assert_eq!(mask.first_node(), Some(1));
    }

    #[test]
    fn test_nodemask_nth_node() {
        let mask = NodeMask::from_raw(0b1010); // nodes 1, 3
        assert_eq!(mask.nth_node(0), Some(1));
        assert_eq!(mask.nth_node(1), Some(3));
        assert_eq!(mask.nth_node(2), Some(1)); // wraps
    }

    #[test]
    fn test_nodemask_set_clear() {
        let mut mask = NodeMask::empty();
        mask.set(5).unwrap();
        assert!(mask.contains(5));
        mask.clear(5).unwrap();
        assert!(!mask.contains(5));
    }

    #[test]
    fn test_nodemask_out_of_range() {
        assert_eq!(
            NodeMask::single(MAX_NUMA_NODES as u32).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_policy_default() {
        let p = MemPolicy::default_policy();
        assert_eq!(p.mode, MPOL_DEFAULT);
        assert!(p.nodemask.is_empty());
    }

    #[test]
    fn test_policy_bind() {
        let mask = NodeMask::from_raw(0b11); // nodes 0, 1
        let p = MemPolicy::new(MPOL_BIND, 0, mask);
        assert!(p.is_ok());
    }

    #[test]
    fn test_policy_bind_empty_mask() {
        let p = MemPolicy::new(MPOL_BIND, 0, NodeMask::empty());
        assert_eq!(p.unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_policy_preferred_multi_node() {
        let mask = NodeMask::from_raw(0b11);
        let p = MemPolicy::new(MPOL_PREFERRED, 0, mask);
        assert_eq!(p.unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_policy_bad_mode() {
        let p = MemPolicy::new(99, 0, NodeMask::empty());
        assert_eq!(p.unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_policy_conflicting_flags() {
        let p = MemPolicy::new(
            MPOL_DEFAULT,
            MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES,
            NodeMask::empty(),
        );
        assert_eq!(p.unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_target_node_default() {
        let p = MemPolicy::default_policy();
        assert_eq!(p.target_node(3, 0), 3);
    }

    #[test]
    fn test_target_node_preferred() {
        let mask = NodeMask::single(2).unwrap();
        let p = MemPolicy::new(MPOL_PREFERRED, 0, mask).unwrap();
        assert_eq!(p.target_node(0, 0), 2);
    }

    #[test]
    fn test_target_node_interleave() {
        let mask = NodeMask::from_raw(0b101); // nodes 0, 2
        let p = MemPolicy::new(MPOL_INTERLEAVE, 0, mask).unwrap();
        assert_eq!(p.target_node(0, 0), 0);
        assert_eq!(p.target_node(0, 1), 2);
        assert_eq!(p.target_node(0, 2), 0);
    }

    #[test]
    fn test_target_node_bind_local() {
        let mask = NodeMask::from_raw(0b11); // nodes 0, 1
        let p = MemPolicy::new(MPOL_BIND, 0, mask).unwrap();
        assert_eq!(p.target_node(1, 0), 1); // local in mask
    }

    #[test]
    fn test_target_node_bind_not_local() {
        let mask = NodeMask::from_raw(0b10); // node 1 only
        let p = MemPolicy::new(MPOL_BIND, 0, mask).unwrap();
        assert_eq!(p.target_node(0, 0), 1); // local not in mask
    }

    #[test]
    fn test_set_mempolicy() {
        let mut ctx = MemPolicyContext::new(4);
        let mask = NodeMask::from_raw(0b11);
        assert!(sys_set_mempolicy(&mut ctx, MPOL_BIND, mask).is_ok());
        assert_eq!(ctx.default_policy.mode, MPOL_BIND);
    }

    #[test]
    fn test_set_mempolicy_invalid_node() {
        let mut ctx = MemPolicyContext::new(4);
        // Node 10 not in allowed set (0-3).
        let mask = NodeMask::from_raw(1 << 10);
        assert_eq!(
            sys_set_mempolicy(&mut ctx, MPOL_BIND, mask).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_get_mempolicy_default() {
        let ctx = MemPolicyContext::new(4);
        let result = sys_get_mempolicy(&ctx, 0, 0).unwrap();
        assert_eq!(result.mode, MPOL_DEFAULT);
    }

    #[test]
    fn test_get_mempolicy_mems_allowed() {
        let ctx = MemPolicyContext::new(4);
        let result = sys_get_mempolicy(&ctx, 0, MPOL_F_MEMS_ALLOWED).unwrap();
        assert!(result.nodemask.contains(0));
        assert!(result.nodemask.contains(3));
    }

    #[test]
    fn test_mbind() {
        let mut ctx = MemPolicyContext::new(4);
        let mask = NodeMask::from_raw(0b11);
        assert!(sys_mbind(&mut ctx, 0x1000, 0x2000, MPOL_BIND, mask, 0).is_ok());
        assert_eq!(ctx.vma_policy_count(), 1);
    }

    #[test]
    fn test_mbind_bad_alignment() {
        let mut ctx = MemPolicyContext::new(4);
        let mask = NodeMask::from_raw(0b1);
        assert_eq!(
            sys_mbind(&mut ctx, 0x1001, 0x1000, MPOL_BIND, mask, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_mbind_bad_flags() {
        let mut ctx = MemPolicyContext::new(4);
        let mask = NodeMask::from_raw(0b1);
        assert_eq!(
            sys_mbind(&mut ctx, 0x1000, 0x1000, MPOL_BIND, mask, 0xFF).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_get_mempolicy_per_vma() {
        let mut ctx = MemPolicyContext::new(4);
        let mask = NodeMask::from_raw(0b10);
        ctx.mbind(0x1000, 0x2000, MPOL_BIND, mask, 0).unwrap();
        let result = sys_get_mempolicy(&ctx, 0x1500, MPOL_F_ADDR).unwrap();
        assert_eq!(result.mode, MPOL_BIND);
    }

    #[test]
    fn test_allocation_node_vma() {
        let mut ctx = MemPolicyContext::new(4);
        let mask = NodeMask::single(2).unwrap();
        ctx.mbind(0x1000, 0x2000, MPOL_PREFERRED, mask, 0).unwrap();
        assert_eq!(ctx.allocation_node(0x1500, 0), 2);
    }

    #[test]
    fn test_allocation_node_default() {
        let mut ctx = MemPolicyContext::new(4);
        assert_eq!(ctx.allocation_node(0x5000, 1), 1);
    }

    #[test]
    fn test_interleave_round_robin() {
        let mut ctx = MemPolicyContext::new(4);
        let mask = NodeMask::from_raw(0b101); // nodes 0, 2
        ctx.set_mempolicy(MPOL_INTERLEAVE, mask).unwrap();
        let n0 = ctx.allocation_node(0x5000, 0);
        let n1 = ctx.allocation_node(0x6000, 0);
        let n2 = ctx.allocation_node(0x7000, 0);
        assert_eq!(n0, 0);
        assert_eq!(n1, 2);
        assert_eq!(n2, 0);
    }

    #[test]
    fn test_nodemask_intersect_union() {
        let a = NodeMask::from_raw(0b1010);
        let b = NodeMask::from_raw(0b0110);
        assert_eq!(a.intersect(&b).raw(), 0b0010);
        assert_eq!(a.union(&b).raw(), 0b1110);
    }
}
