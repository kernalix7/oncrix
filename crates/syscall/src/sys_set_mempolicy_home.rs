// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `set_mempolicy_home_node(2)` — set preferred NUMA home node for a VMA range.
//!
//! This syscall complements `MPOL_PREFERRED_MANY` and `MPOL_BIND` by allowing
//! user space to designate a specific NUMA node as the preferred allocation
//! node for one or more virtual memory areas.  The kernel walks the VMA tree
//! for the specified address range and updates the memory policy on each VMA
//! to record the home node preference.
//!
//! # Syscall signature
//!
//! ```text
//! long set_mempolicy_home_node(unsigned long start, unsigned long len,
//!                              unsigned long home_node, unsigned long flags);
//! ```
//!
//! # Semantics
//!
//! - `start` must be page-aligned.
//! - `len` must be non-zero and page-aligned.
//! - `home_node` must refer to a valid NUMA node (0 .. `MAX_NUMA_NODES - 1`).
//! - `flags` must be 0 (reserved).
//! - The syscall does not change the policy *mode*; only the home-node
//!   preference is updated.  The VMA must already have `MPOL_PREFERRED_MANY`
//!   or `MPOL_BIND` — applying this syscall to a VMA with `MPOL_DEFAULT` or
//!   `MPOL_LOCAL` returns `InvalidArgument`.
//! - VMAs not covered by the range are left unmodified.
//!
//! # Linux reference
//!
//! Linux `mm/mempolicy.c` — `sys_set_mempolicy_home_node()` (since Linux 5.17,
//! x86_64 syscall number 450).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// x86_64 Linux ABI syscall number for `set_mempolicy_home_node`.
pub const SYS_SET_MEMPOLICY_HOME_NODE: u64 = 450;

/// Maximum supported NUMA nodes.
pub const MAX_NUMA_NODES: u32 = 128;

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page-offset mask.
const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// Maximum number of VMAs tracked per process.
const MAX_VMAS: usize = 256;

// ---------------------------------------------------------------------------
// Memory policy modes (subset needed for validation)
// ---------------------------------------------------------------------------

/// NUMA policy mode: default allocation from local node.
pub const MPOL_DEFAULT: u32 = 0;
/// NUMA policy mode: prefer a specific node but fall back.
pub const MPOL_PREFERRED: u32 = 1;
/// NUMA policy mode: bind strictly to the node set.
pub const MPOL_BIND: u32 = 2;
/// NUMA policy mode: interleave allocations round-robin.
pub const MPOL_INTERLEAVE: u32 = 3;
/// NUMA policy mode: allocate on the thread-local node.
pub const MPOL_LOCAL: u32 = 4;
/// NUMA policy mode: prefer any node in the set (Linux 5.15+).
pub const MPOL_PREFERRED_MANY: u32 = 5;

// ---------------------------------------------------------------------------
// VmaRecord — a single virtual memory area entry
// ---------------------------------------------------------------------------

/// A virtual memory area record for `set_mempolicy_home_node`.
///
/// In a real kernel this would be the `vm_area_struct`.  This stub captures
/// just the fields required for home-node policy tracking.
#[derive(Debug, Clone, Copy)]
pub struct VmaRecord {
    /// Start address of the VMA (page-aligned, inclusive).
    pub start: u64,
    /// End address of the VMA (page-aligned, exclusive).
    pub end: u64,
    /// Current NUMA policy mode for this VMA.
    pub policy_mode: u32,
    /// Home node preference (u32::MAX = unset).
    pub home_node: u32,
    /// Whether this slot is active.
    pub active: bool,
}

impl VmaRecord {
    /// Create an inactive record.
    const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            policy_mode: MPOL_DEFAULT,
            home_node: u32::MAX,
            active: false,
        }
    }

    /// Return `true` if this VMA overlaps `[addr, addr+len)`.
    pub const fn overlaps(&self, addr: u64, len: u64) -> bool {
        if len == 0 {
            return false;
        }
        let req_end = addr.saturating_add(len);
        self.start < req_end && self.end > addr
    }

    /// Return `true` if `home_node` can be applied to this VMA's policy.
    ///
    /// Only `MPOL_BIND` and `MPOL_PREFERRED_MANY` support the home-node
    /// hint; all others are rejected.
    pub const fn supports_home_node(&self) -> bool {
        matches!(self.policy_mode, MPOL_BIND | MPOL_PREFERRED_MANY)
    }
}

impl Default for VmaRecord {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// VmaTable — per-process VMA collection
// ---------------------------------------------------------------------------

/// Per-process collection of VMA records used by `set_mempolicy_home_node`.
pub struct VmaTable {
    vmas: [VmaRecord; MAX_VMAS],
    count: usize,
    /// Total home-node update operations applied.
    pub updates_applied: u64,
    /// Number of VMAs skipped because their policy did not support home node.
    pub skipped_incompatible: u64,
}

impl VmaTable {
    /// Create an empty VMA table.
    pub const fn new() -> Self {
        Self {
            vmas: [const { VmaRecord::empty() }; MAX_VMAS],
            count: 0,
            updates_applied: 0,
            skipped_incompatible: 0,
        }
    }

    /// Return the number of active VMAs.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Insert a new VMA.  Returns `OutOfMemory` if the table is full.
    pub fn insert(&mut self, start: u64, end: u64, policy_mode: u32) -> Result<usize> {
        let slot = self
            .vmas
            .iter()
            .position(|v| !v.active)
            .ok_or(Error::OutOfMemory)?;
        self.vmas[slot] = VmaRecord {
            start,
            end,
            policy_mode,
            home_node: u32::MAX,
            active: true,
        };
        self.count += 1;
        Ok(slot)
    }

    /// Remove a VMA by slot index.
    pub fn remove(&mut self, idx: usize) {
        if idx < MAX_VMAS && self.vmas[idx].active {
            self.vmas[idx].active = false;
            self.count = self.count.saturating_sub(1);
        }
    }

    /// Apply the home-node update for `[addr, addr+len)`.
    ///
    /// Iterates all active VMAs that overlap the range.  If a VMA's policy
    /// supports home-node hints, its `home_node` field is set.  If any
    /// overlapping VMA has an incompatible policy, that VMA is skipped and
    /// counted in `skipped_incompatible`.
    ///
    /// Returns the number of VMAs updated.
    fn apply_home_node(&mut self, addr: u64, len: u64, node: u32) -> u32 {
        let mut updated = 0u32;
        for vma in self.vmas.iter_mut() {
            if !vma.active {
                continue;
            }
            if !vma.overlaps(addr, len) {
                continue;
            }
            if vma.supports_home_node() {
                vma.home_node = node;
                updated += 1;
                self.updates_applied = self.updates_applied.saturating_add(1);
            } else {
                self.skipped_incompatible = self.skipped_incompatible.saturating_add(1);
            }
        }
        updated
    }

    /// Return a reference to the VMA at slot `idx`.
    pub fn get(&self, idx: usize) -> Option<&VmaRecord> {
        if idx < MAX_VMAS && self.vmas[idx].active {
            Some(&self.vmas[idx])
        } else {
            None
        }
    }
}

impl Default for VmaTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `set_mempolicy_home_node` arguments.
///
/// # Checks
///
/// - `start` is page-aligned.
/// - `len` is non-zero and page-aligned.
/// - `start + len` does not overflow.
/// - `home_node` is in `[0, MAX_NUMA_NODES)`.
/// - `flags` is 0.
pub fn validate_home_node_args(start: u64, len: u64, home_node: u32, flags: u64) -> Result<()> {
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    if start & PAGE_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    if len == 0 || len & PAGE_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    start.checked_add(len).ok_or(Error::InvalidArgument)?;
    if home_node >= MAX_NUMA_NODES {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HomeNodeResult
// ---------------------------------------------------------------------------

/// Result of a successful `set_mempolicy_home_node` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HomeNodeResult {
    /// Number of VMAs whose home-node preference was updated.
    pub vmas_updated: u32,
    /// Number of overlapping VMAs that were skipped (incompatible policy).
    pub vmas_skipped: u32,
}

// ---------------------------------------------------------------------------
// sys_set_mempolicy_home_node — primary handler
// ---------------------------------------------------------------------------

/// `set_mempolicy_home_node(2)` syscall handler.
///
/// Sets the preferred NUMA home node for all VMAs that overlap the range
/// `[start, start+len)` and whose policy mode is `MPOL_BIND` or
/// `MPOL_PREFERRED_MANY`.
///
/// # Arguments
///
/// * `table`     — Per-process VMA table (mutable).
/// * `start`     — Page-aligned range start.
/// * `len`       — Page-aligned range length (non-zero).
/// * `home_node` — Target NUMA node index (`0..MAX_NUMA_NODES`).
/// * `flags`     — Must be 0.
///
/// # Returns
///
/// A [`HomeNodeResult`] on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Misaligned start/len, zero len, overflow,
///   out-of-range node, or non-zero flags.
pub fn sys_set_mempolicy_home_node(
    table: &mut VmaTable,
    start: u64,
    len: u64,
    home_node: u32,
    flags: u64,
) -> Result<HomeNodeResult> {
    validate_home_node_args(start, len, home_node, flags)?;

    let before_skipped = table.skipped_incompatible;
    let vmas_updated = table.apply_home_node(start, len, home_node);
    let after_skipped = table.skipped_incompatible;
    let vmas_skipped = (after_skipped - before_skipped) as u32;

    Ok(HomeNodeResult {
        vmas_updated,
        vmas_skipped,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> VmaTable {
        VmaTable::new()
    }

    #[test]
    fn validate_ok() {
        assert_eq!(validate_home_node_args(0x0000, 0x1000, 0, 0), Ok(()));
    }

    #[test]
    fn validate_nonzero_flags_rejected() {
        assert_eq!(
            validate_home_node_args(0x1000, 0x1000, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_misaligned_start_rejected() {
        assert_eq!(
            validate_home_node_args(0x1001, 0x1000, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_zero_len_rejected() {
        assert_eq!(
            validate_home_node_args(0x1000, 0, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_misaligned_len_rejected() {
        assert_eq!(
            validate_home_node_args(0x1000, 0x1001, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_overflow_rejected() {
        assert_eq!(
            validate_home_node_args(u64::MAX - 0xFFF, 0x2000, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_node_out_of_range_rejected() {
        assert_eq!(
            validate_home_node_args(0x1000, 0x1000, MAX_NUMA_NODES, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn update_bind_vma() {
        let mut t = make_table();
        t.insert(0x1000, 0x3000, MPOL_BIND).unwrap();
        let res = sys_set_mempolicy_home_node(&mut t, 0x1000, 0x2000, 3, 0).unwrap();
        assert_eq!(res.vmas_updated, 1);
        assert_eq!(res.vmas_skipped, 0);
        assert_eq!(t.vmas[0].home_node, 3);
    }

    #[test]
    fn update_preferred_many_vma() {
        let mut t = make_table();
        t.insert(0x4000, 0x8000, MPOL_PREFERRED_MANY).unwrap();
        let res = sys_set_mempolicy_home_node(&mut t, 0x4000, 0x4000, 7, 0).unwrap();
        assert_eq!(res.vmas_updated, 1);
        assert_eq!(t.vmas[0].home_node, 7);
    }

    #[test]
    fn incompatible_vma_skipped() {
        let mut t = make_table();
        // MPOL_DEFAULT VMAs are not eligible.
        t.insert(0x1000, 0x3000, MPOL_DEFAULT).unwrap();
        let res = sys_set_mempolicy_home_node(&mut t, 0x1000, 0x2000, 0, 0).unwrap();
        assert_eq!(res.vmas_updated, 0);
        assert_eq!(res.vmas_skipped, 1);
        // Home node must remain unset.
        assert_eq!(t.vmas[0].home_node, u32::MAX);
    }

    #[test]
    fn non_overlapping_vma_not_touched() {
        let mut t = make_table();
        t.insert(0x8000, 0xA000, MPOL_BIND).unwrap();
        // Range [0x1000, 0x3000) does not overlap [0x8000, 0xA000).
        let res = sys_set_mempolicy_home_node(&mut t, 0x1000, 0x2000, 1, 0).unwrap();
        assert_eq!(res.vmas_updated, 0);
        assert_eq!(t.vmas[0].home_node, u32::MAX);
    }

    #[test]
    fn multiple_vmas_partially_updated() {
        let mut t = make_table();
        t.insert(0x1000, 0x3000, MPOL_BIND).unwrap();
        t.insert(0x3000, 0x5000, MPOL_LOCAL).unwrap(); // incompatible
        t.insert(0x5000, 0x7000, MPOL_PREFERRED_MANY).unwrap();
        let res = sys_set_mempolicy_home_node(&mut t, 0x1000, 0x6000, 2, 0).unwrap();
        assert_eq!(res.vmas_updated, 2);
        assert_eq!(res.vmas_skipped, 1);
    }

    #[test]
    fn no_vmas_results_in_zero_updates() {
        let mut t = make_table();
        let res = sys_set_mempolicy_home_node(&mut t, 0x1000, 0x1000, 0, 0).unwrap();
        assert_eq!(res.vmas_updated, 0);
        assert_eq!(res.vmas_skipped, 0);
    }

    #[test]
    fn home_node_max_valid_node() {
        let mut t = make_table();
        t.insert(0x1000, 0x2000, MPOL_BIND).unwrap();
        let max_valid = MAX_NUMA_NODES - 1;
        let res = sys_set_mempolicy_home_node(&mut t, 0x1000, 0x1000, max_valid, 0).unwrap();
        assert_eq!(res.vmas_updated, 1);
        assert_eq!(t.vmas[0].home_node, max_valid);
    }

    #[test]
    fn vma_overlaps_partial_range() {
        let rec = VmaRecord {
            start: 0x2000,
            end: 0x4000,
            policy_mode: MPOL_BIND,
            home_node: u32::MAX,
            active: true,
        };
        // Request overlaps the tail of the VMA.
        assert!(rec.overlaps(0x3000, 0x2000));
        // Request does not overlap.
        assert!(!rec.overlaps(0x4000, 0x1000));
    }

    #[test]
    fn update_counter_increments() {
        let mut t = make_table();
        t.insert(0x1000, 0x2000, MPOL_BIND).unwrap();
        t.insert(0x2000, 0x3000, MPOL_PREFERRED_MANY).unwrap();
        sys_set_mempolicy_home_node(&mut t, 0x1000, 0x2000, 0, 0).unwrap();
        assert_eq!(t.updates_applied, 2);
    }
}
