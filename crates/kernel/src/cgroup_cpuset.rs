// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 cpuset controller for CPU and memory node affinity.
//!
//! Implements the `cpuset` controller from Linux cgroups v2 with:
//! - CPU affinity bitmask (`cpuset.cpus`) for up to 64 CPUs
//! - Memory node affinity bitmask (`cpuset.mems`) for up to 8 NUMA nodes
//! - Effective mask computation inheriting from parent
//! - PID attachment/detachment with deduplication
//! - CPU/memory migration on mask change
//!
//! # Types
//!
//! - [`CpusetMask`] — bitmask for CPU or memory node selection
//! - [`CpusetController`] — per-group cpuset configuration
//! - [`CpusetGroup`] — a single cpuset cgroup instance with PIDs
//! - [`CpusetRegistry`] — system-wide registry of cpuset groups
//!
//! Reference: Linux `Documentation/admin-guide/cgroup-v2.rst`,
//! `kernel/cgroup/cpuset.c`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of CPUs supported by the cpuset bitmask.
const MAX_CPUS: usize = 64;

/// Maximum number of NUMA memory nodes supported.
const MAX_MEMS: usize = 8;

/// Maximum number of PIDs per cpuset group.
const MAX_PIDS: usize = 32;

/// Maximum number of cpuset groups in the registry.
const MAX_GROUPS: usize = 64;

/// Maximum name length in bytes.
const MAX_NAME_LEN: usize = 64;

// ── CpusetMask ─────────────────────────────────────────────────────

/// Bitmask for CPU or memory node selection.
///
/// Stores up to 64 bits in a single `u64`. Bit `n` being set means
/// CPU (or memory node) `n` is included in the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpusetMask {
    /// Raw bitmask value.
    bits: u64,
}

impl CpusetMask {
    /// Create an empty mask (no CPUs/nodes selected).
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Create a mask with all bits set up to `count`.
    ///
    /// Returns `Error::InvalidArgument` if `count` exceeds 64.
    pub const fn all(count: usize) -> Result<Self> {
        if count == 0 {
            return Ok(Self { bits: 0 });
        }
        if count > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if count == 64 {
            return Ok(Self { bits: u64::MAX });
        }
        Ok(Self {
            bits: (1u64 << count) - 1,
        })
    }

    /// Create a mask from a raw `u64` value.
    pub const fn from_raw(bits: u64) -> Self {
        Self { bits }
    }

    /// Return the raw bitmask value.
    pub const fn as_raw(&self) -> u64 {
        self.bits
    }

    /// Set bit `n` in the mask.
    ///
    /// Returns `Error::InvalidArgument` if `n >= 64`.
    pub fn set(&mut self, n: usize) -> Result<()> {
        if n >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.bits |= 1u64 << n;
        Ok(())
    }

    /// Clear bit `n` in the mask.
    ///
    /// Returns `Error::InvalidArgument` if `n >= 64`.
    pub fn clear(&mut self, n: usize) -> Result<()> {
        if n >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.bits &= !(1u64 << n);
        Ok(())
    }

    /// Test whether bit `n` is set.
    ///
    /// Returns `false` if `n >= 64`.
    pub const fn test(&self, n: usize) -> bool {
        if n >= MAX_CPUS {
            return false;
        }
        (self.bits & (1u64 << n)) != 0
    }

    /// Return the number of set bits.
    pub const fn count(&self) -> u32 {
        self.bits.count_ones()
    }

    /// Return whether the mask is empty (no bits set).
    pub const fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// Compute the intersection of two masks.
    pub const fn intersect(&self, other: &Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }

    /// Compute the union of two masks.
    pub const fn union(&self, other: &Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Return the index of the first set bit, or `None` if empty.
    pub const fn first_set(&self) -> Option<usize> {
        if self.bits == 0 {
            None
        } else {
            Some(self.bits.trailing_zeros() as usize)
        }
    }
}

impl Default for CpusetMask {
    fn default() -> Self {
        Self::empty()
    }
}

impl core::fmt::Display for CpusetMask {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{:016x}", self.bits)
    }
}

// ── CpusetController ──────────────────────────────────────────────

/// Per-group cpuset configuration.
///
/// Stores the requested CPU and memory node masks along with the
/// effective masks that result from intersecting with the parent.
#[derive(Debug, Clone, Copy)]
pub struct CpusetController {
    /// Requested CPU mask (`cpuset.cpus`).
    pub cpus: CpusetMask,
    /// Requested memory node mask (`cpuset.mems`).
    pub mems: CpusetMask,
    /// Effective CPU mask after parent intersection
    /// (`cpuset.cpus.effective`).
    pub cpus_effective: CpusetMask,
    /// Effective memory node mask after parent intersection
    /// (`cpuset.mems.effective`).
    pub mems_effective: CpusetMask,
}

impl CpusetController {
    /// Create a controller with all CPUs and memory nodes available.
    pub const fn new() -> Self {
        // Default: all 64 CPUs, all 8 NUMA nodes.
        let all_cpus = CpusetMask::from_raw(u64::MAX);
        let all_mems = CpusetMask::from_raw((1u64 << MAX_MEMS) - 1);
        Self {
            cpus: all_cpus,
            mems: all_mems,
            cpus_effective: all_cpus,
            mems_effective: all_mems,
        }
    }

    /// Recompute effective masks by intersecting with a parent's
    /// effective masks.
    pub fn update_effective(&mut self, parent_cpus: &CpusetMask, parent_mems: &CpusetMask) {
        self.cpus_effective = self.cpus.intersect(parent_cpus);
        self.mems_effective = self.mems.intersect(parent_mems);
    }
}

impl Default for CpusetController {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Display for CpusetController {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "CpusetController {{ cpus: {}, mems: {} }}",
            self.cpus_effective, self.mems_effective,
        )
    }
}

// ── CpusetGroup ───────────────────────────────────────────────────

/// A single cpuset cgroup instance.
///
/// Contains the cpuset controller configuration and a list of
/// attached PIDs whose scheduling affinity is constrained by the
/// effective CPU/memory masks.
#[derive(Debug, Clone, Copy)]
pub struct CpusetGroup {
    /// Unique group identifier.
    id: u64,
    /// Group name (UTF-8 bytes, null-padded).
    name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    name_len: usize,
    /// Parent group ID (`None` for root).
    parent_id: Option<u64>,
    /// Cpuset controller configuration.
    pub controller: CpusetController,
    /// Attached process IDs.
    pids: [u64; MAX_PIDS],
    /// Number of attached PIDs.
    pid_count: usize,
    /// Whether this group is actively in use.
    in_use: bool,
}

impl CpusetGroup {
    /// Create an empty (inactive) group slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            parent_id: None,
            controller: CpusetController::new(),
            pids: [0u64; MAX_PIDS],
            pid_count: 0,
            in_use: false,
        }
    }

    /// Return the group's unique identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Return the group name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the parent group ID, or `None` for root.
    pub const fn parent_id(&self) -> Option<u64> {
        self.parent_id
    }

    /// Return whether this group is active.
    pub const fn is_active(&self) -> bool {
        self.in_use
    }

    /// Return the number of attached PIDs.
    pub const fn pid_count(&self) -> usize {
        self.pid_count
    }

    /// Return the attached PIDs as a slice.
    pub fn pids(&self) -> &[u64] {
        &self.pids[..self.pid_count]
    }

    /// Add a PID to this group.
    ///
    /// # Errors
    ///
    /// - `Error::AlreadyExists` — PID is already attached.
    /// - `Error::OutOfMemory` — PID list is full.
    pub fn add_pid(&mut self, pid: u64) -> Result<()> {
        if self.pids[..self.pid_count].contains(&pid) {
            return Err(Error::AlreadyExists);
        }
        if self.pid_count >= MAX_PIDS {
            return Err(Error::OutOfMemory);
        }
        self.pids[self.pid_count] = pid;
        self.pid_count += 1;
        Ok(())
    }

    /// Remove a PID from this group.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the PID is not attached.
    pub fn remove_pid(&mut self, pid: u64) -> Result<()> {
        let pos = self.pids[..self.pid_count]
            .iter()
            .position(|&p| p == pid)
            .ok_or(Error::NotFound)?;

        // Swap-remove: move last element into the vacated slot.
        self.pid_count -= 1;
        if pos < self.pid_count {
            self.pids[pos] = self.pids[self.pid_count];
        }
        self.pids[self.pid_count] = 0;
        Ok(())
    }

    /// Check whether a PID is attached to this group.
    pub fn has_pid(&self, pid: u64) -> bool {
        self.pids[..self.pid_count].contains(&pid)
    }

    /// Set the CPU affinity mask for this group.
    ///
    /// Returns `Error::InvalidArgument` if the mask is empty.
    pub fn set_cpus(&mut self, mask: CpusetMask) -> Result<()> {
        if mask.is_empty() {
            return Err(Error::InvalidArgument);
        }
        self.controller.cpus = mask;
        Ok(())
    }

    /// Set the memory node affinity mask for this group.
    ///
    /// Returns `Error::InvalidArgument` if the mask is empty.
    pub fn set_mems(&mut self, mask: CpusetMask) -> Result<()> {
        if mask.is_empty() {
            return Err(Error::InvalidArgument);
        }
        self.controller.mems = mask;
        Ok(())
    }

    /// Return the effective CPU mask for this group.
    pub const fn effective_cpus(&self) -> &CpusetMask {
        &self.controller.cpus_effective
    }

    /// Return the effective memory node mask for this group.
    pub const fn effective_mems(&self) -> &CpusetMask {
        &self.controller.mems_effective
    }
}

// ── CpusetRegistry ────────────────────────────────────────────────

/// System-wide registry of cpuset cgroup groups.
///
/// Manages up to [`MAX_GROUPS`] cpuset groups in a fixed-size array.
/// Each group is identified by a unique `u64` ID assigned at
/// creation time.
pub struct CpusetRegistry {
    /// Fixed-size array of group slots.
    groups: [CpusetGroup; MAX_GROUPS],
    /// Next group ID to assign.
    next_id: u64,
    /// Number of active groups.
    count: usize,
}

impl Default for CpusetRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CpusetRegistry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        const EMPTY: CpusetGroup = CpusetGroup::empty();
        Self {
            groups: [EMPTY; MAX_GROUPS],
            next_id: 1,
            count: 0,
        }
    }

    /// Return the number of active groups.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Create a new cpuset group with the given name and optional
    /// parent.
    ///
    /// Returns the new group's unique ID.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — name is empty or too long.
    /// - `Error::OutOfMemory` — no free slots available.
    /// - `Error::NotFound` — parent ID specified but not found.
    pub fn create(&mut self, name: &[u8], parent_id: Option<u64>) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_GROUPS {
            return Err(Error::OutOfMemory);
        }

        // Validate parent exists if specified.
        if let Some(pid) = parent_id {
            if self.index_of(pid).is_err() {
                return Err(Error::NotFound);
            }
        }

        // Read parent effective masks before mutating the array.
        let parent_effective = if let Some(pid) = parent_id {
            self.get(pid)
                .map(|p| (p.controller.cpus_effective, p.controller.mems_effective))
        } else {
            None
        };

        let slot = self
            .groups
            .iter()
            .position(|g| !g.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let grp = &mut self.groups[slot];
        *grp = CpusetGroup::empty();
        grp.id = id;
        grp.in_use = true;
        grp.name_len = name.len();
        grp.name[..name.len()].copy_from_slice(name);
        grp.parent_id = parent_id;

        // Inherit effective masks from parent if available.
        if let Some((cpus_eff, mems_eff)) = parent_effective {
            grp.controller.update_effective(&cpus_eff, &mems_eff);
        }

        self.count += 1;
        Ok(id)
    }

    /// Destroy a cpuset group by ID.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — group does not exist.
    /// - `Error::Busy` — group still has attached PIDs.
    pub fn destroy(&mut self, id: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        if self.groups[idx].pid_count > 0 {
            return Err(Error::Busy);
        }
        self.groups[idx].in_use = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Return an immutable reference to a group by ID.
    pub fn get(&self, id: u64) -> Option<&CpusetGroup> {
        self.groups.iter().find(|g| g.in_use && g.id == id)
    }

    /// Return a mutable reference to a group by ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut CpusetGroup> {
        self.groups.iter_mut().find(|g| g.in_use && g.id == id)
    }

    /// Attach a PID to a cpuset group.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — group does not exist.
    /// - `Error::AlreadyExists` — PID is already attached.
    /// - `Error::OutOfMemory` — PID list is full.
    pub fn attach(&mut self, group_id: u64, pid: u64) -> Result<()> {
        let idx = self.index_of(group_id)?;
        self.groups[idx].add_pid(pid)
    }

    /// Detach a PID from a cpuset group.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — group does not exist or PID is not
    ///   attached.
    pub fn detach(&mut self, group_id: u64, pid: u64) -> Result<()> {
        let idx = self.index_of(group_id)?;
        self.groups[idx].remove_pid(pid)
    }

    /// Set the CPU affinity mask for a group and recompute effective
    /// masks for it and its children.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — group does not exist.
    /// - `Error::InvalidArgument` — mask is empty.
    pub fn set_cpus(&mut self, group_id: u64, mask: CpusetMask) -> Result<()> {
        let idx = self.index_of(group_id)?;
        self.groups[idx].set_cpus(mask)?;
        self.recompute_effective(group_id);
        Ok(())
    }

    /// Set the memory node affinity mask for a group and recompute
    /// effective masks for it and its children.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — group does not exist.
    /// - `Error::InvalidArgument` — mask is empty.
    pub fn set_mems(&mut self, group_id: u64, mask: CpusetMask) -> Result<()> {
        let idx = self.index_of(group_id)?;
        self.groups[idx].set_mems(mask)?;
        self.recompute_effective(group_id);
        Ok(())
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Return the index of an active group by ID.
    fn index_of(&self, id: u64) -> Result<usize> {
        self.groups
            .iter()
            .position(|g| g.in_use && g.id == id)
            .ok_or(Error::NotFound)
    }

    /// Recompute effective masks for a group and propagate to
    /// children.
    ///
    /// After changing a group's requested CPU or memory mask, the
    /// effective mask must be recomputed by intersecting with the
    /// parent's effective mask, then propagated to all child groups.
    fn recompute_effective(&mut self, group_id: u64) {
        // Compute this group's effective masks.
        let (parent_cpus, parent_mems) = if let Some(idx) = self
            .groups
            .iter()
            .position(|g| g.in_use && g.id == group_id)
        {
            if let Some(pid) = self.groups[idx].parent_id {
                if let Some(parent) = self.groups.iter().find(|g| g.in_use && g.id == pid) {
                    (
                        parent.controller.cpus_effective,
                        parent.controller.mems_effective,
                    )
                } else {
                    // No parent found — this is effectively root.
                    return;
                }
            } else {
                // Root group: effective = requested.
                self.groups[idx].controller.cpus_effective = self.groups[idx].controller.cpus;
                self.groups[idx].controller.mems_effective = self.groups[idx].controller.mems;
                // Still need to propagate to children below.
                let cpus = self.groups[idx].controller.cpus_effective;
                let mems = self.groups[idx].controller.mems_effective;
                self.propagate_to_children(group_id, &cpus, &mems);
                return;
            }
        } else {
            return;
        };

        // Update this group's effective masks.
        if let Some(grp) = self
            .groups
            .iter_mut()
            .find(|g| g.in_use && g.id == group_id)
        {
            grp.controller.update_effective(&parent_cpus, &parent_mems);
        }

        // Read back the newly computed effective masks for
        // propagation to children.
        let (eff_cpus, eff_mems) =
            if let Some(grp) = self.groups.iter().find(|g| g.in_use && g.id == group_id) {
                (grp.controller.cpus_effective, grp.controller.mems_effective)
            } else {
                return;
            };

        self.propagate_to_children(group_id, &eff_cpus, &eff_mems);
    }

    /// Propagate effective masks to all direct children of a group.
    fn propagate_to_children(
        &mut self,
        parent_id: u64,
        parent_cpus: &CpusetMask,
        parent_mems: &CpusetMask,
    ) {
        // Collect child IDs first to avoid borrow issues.
        let mut child_ids = [0u64; MAX_GROUPS];
        let mut child_count = 0;
        for grp in &self.groups {
            if grp.in_use && grp.parent_id == Some(parent_id) && child_count < MAX_GROUPS {
                child_ids[child_count] = grp.id;
                child_count += 1;
            }
        }

        // Update each child's effective masks and recurse.
        for &child_id in &child_ids[..child_count] {
            if let Some(child) = self
                .groups
                .iter_mut()
                .find(|g| g.in_use && g.id == child_id)
            {
                child.controller.update_effective(parent_cpus, parent_mems);
            }
            // Read the child's new effective masks for its children.
            let (child_cpus, child_mems) =
                if let Some(c) = self.groups.iter().find(|g| g.in_use && g.id == child_id) {
                    (c.controller.cpus_effective, c.controller.mems_effective)
                } else {
                    continue;
                };
            self.propagate_to_children(child_id, &child_cpus, &child_mems);
        }
    }
}

impl core::fmt::Debug for CpusetRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CpusetRegistry")
            .field("active_groups", &self.count)
            .field("capacity", &MAX_GROUPS)
            .finish()
    }
}
