// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 cpuset controller with partition support.
//!
//! Extends the basic cpuset controller in [`super::cgroup_cpuset`] with
//! cgroup v2 partition semantics, exclusive CPU/memory assignment, and
//! dynamic migration on assignment change.
//!
//! # Partition types
//!
//! - **Root**: Owns a set of CPUs exclusively; child partitions draw
//!   from the root's pool. A root partition removes its CPUs from the
//!   parent's scheduling domain.
//! - **Member**: A regular cpuset group that inherits its effective
//!   masks from the parent (default).
//!
//! # Interface files
//!
//! | File                      | Description                       |
//! |---------------------------|-----------------------------------|
//! | `cpuset.cpus`             | Requested CPU mask                |
//! | `cpuset.mems`             | Requested memory node mask        |
//! | `cpuset.cpus.effective`   | Effective CPU mask after parents   |
//! | `cpuset.mems.effective`   | Effective memory node mask         |
//! | `cpuset.cpus.partition`   | Partition type (root/member)       |
//! | `cpuset.cpus.exclusive`   | Exclusive CPU mask for partition   |
//!
//! # Types
//!
//! - [`PartitionType`] -- root vs. member classification
//! - [`CpusetV2Mask`] -- 64-bit bitmask for CPUs or NUMA nodes
//! - [`CpusetV2Stats`] -- per-group migration and usage counters
//! - [`CpusetV2Group`] -- a single cpuset v2 cgroup instance
//! - [`CpusetV2Registry`] -- system-wide registry of cpuset v2 groups
//!
//! Reference: Linux `Documentation/admin-guide/cgroup-v2.rst`,
//! `kernel/cgroup/cpuset.c`.

#[allow(dead_code)]
use oncrix_lib::{Error, Result};

// -- Constants ---------------------------------------------------------------

/// Maximum number of CPUs in the bitmask.
const MAX_CPUS: usize = 64;

/// Maximum number of NUMA memory nodes.
const MAX_MEMS: usize = 8;

/// Maximum number of PIDs per group.
const MAX_PIDS: usize = 32;

/// Maximum number of cpuset v2 groups.
const MAX_GROUPS: usize = 64;

/// Maximum name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Maximum number of child groups tracked per parent for propagation.
const MAX_CHILDREN: usize = 64;

// -- PartitionType -----------------------------------------------------------

/// Partition type for cgroup v2 cpuset.
///
/// Controls whether a group owns CPUs exclusively (root partition)
/// or shares them with siblings (member).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PartitionType {
    /// Regular member group -- inherits effective masks from parent.
    #[default]
    Member,
    /// Root partition -- owns CPUs exclusively, removed from parent's
    /// scheduling domain.
    Root,
    /// Invalid partition state -- set when constraints are violated
    /// (e.g., exclusive CPUs overlap with siblings).
    Invalid,
}

// -- CpusetV2Mask ------------------------------------------------------------

/// 64-bit bitmask for CPU or memory node selection.
///
/// Wraps a `u64` where bit `n` being set means CPU (or NUMA node) `n`
/// is in the set. Supports up to 64 entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpusetV2Mask {
    /// Raw bitmask value.
    bits: u64,
}

impl CpusetV2Mask {
    /// Create an empty mask (no bits set).
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Create a mask from a raw `u64` value.
    pub const fn from_raw(bits: u64) -> Self {
        Self { bits }
    }

    /// Return the raw bitmask value.
    pub const fn as_raw(&self) -> u64 {
        self.bits
    }

    /// Create a mask with all bits set up to `count`.
    ///
    /// # Errors
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

    /// Set bit `n`.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if `n >= 64`.
    pub fn set(&mut self, n: usize) -> Result<()> {
        if n >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.bits |= 1u64 << n;
        Ok(())
    }

    /// Clear bit `n`.
    ///
    /// # Errors
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

    /// Return whether the mask is empty.
    pub const fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// Compute the intersection (AND) of two masks.
    pub const fn intersect(&self, other: &Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }

    /// Compute the union (OR) of two masks.
    pub const fn union(&self, other: &Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Compute the difference (self AND NOT other).
    pub const fn subtract(&self, other: &Self) -> Self {
        Self {
            bits: self.bits & !other.bits,
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

impl Default for CpusetV2Mask {
    fn default() -> Self {
        Self::empty()
    }
}

// -- CpusetV2Stats -----------------------------------------------------------

/// Per-group statistics for the cpuset v2 controller.
///
/// Tracks migration events and scheduling accounting.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpusetV2Stats {
    /// Number of times PIDs were migrated due to mask changes.
    pub migration_count: u64,
    /// Number of times the effective mask was recomputed.
    pub recompute_count: u64,
    /// Number of partition constraint violations detected.
    pub violation_count: u64,
}

// -- CpusetV2Group -----------------------------------------------------------

/// A single cgroup v2 cpuset instance.
///
/// Combines CPU/memory affinity masks, partition type, exclusive CPU
/// tracking, PID attachment, and migration accounting.
#[derive(Clone, Copy)]
pub struct CpusetV2Group {
    /// Unique group identifier.
    id: u64,
    /// Group name (UTF-8 bytes, null-padded).
    name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    name_len: usize,
    /// Parent group ID (`0` means root / no parent).
    parent_id: u64,
    /// Whether this group has a parent.
    has_parent: bool,
    /// Partition type (root/member/invalid).
    partition: PartitionType,
    /// Requested CPU mask (`cpuset.cpus`).
    cpus_requested: CpusetV2Mask,
    /// Requested memory node mask (`cpuset.mems`).
    mems_requested: CpusetV2Mask,
    /// Effective CPU mask (`cpuset.cpus.effective`).
    cpus_effective: CpusetV2Mask,
    /// Effective memory node mask (`cpuset.mems.effective`).
    mems_effective: CpusetV2Mask,
    /// Exclusive CPU mask for root partitions (`cpuset.cpus.exclusive`).
    cpus_exclusive: CpusetV2Mask,
    /// Attached process IDs.
    pids: [u64; MAX_PIDS],
    /// Number of attached PIDs.
    pid_count: usize,
    /// Whether this slot is in use.
    in_use: bool,
    /// Per-group statistics.
    stats: CpusetV2Stats,
}

impl CpusetV2Group {
    /// Create an empty (inactive) group slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            parent_id: 0,
            has_parent: false,
            partition: PartitionType::Member,
            cpus_requested: CpusetV2Mask::empty(),
            mems_requested: CpusetV2Mask::empty(),
            cpus_effective: CpusetV2Mask::empty(),
            mems_effective: CpusetV2Mask::empty(),
            cpus_exclusive: CpusetV2Mask::empty(),
            pids: [0u64; MAX_PIDS],
            pid_count: 0,
            in_use: false,
            stats: CpusetV2Stats {
                migration_count: 0,
                recompute_count: 0,
                violation_count: 0,
            },
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

    /// Return the parent group ID, or `None` if this is a root.
    pub const fn parent_id(&self) -> Option<u64> {
        if self.has_parent {
            Some(self.parent_id)
        } else {
            None
        }
    }

    /// Return the partition type.
    pub const fn partition(&self) -> PartitionType {
        self.partition
    }

    /// Return the requested CPU mask.
    pub const fn cpus_requested(&self) -> &CpusetV2Mask {
        &self.cpus_requested
    }

    /// Return the requested memory node mask.
    pub const fn mems_requested(&self) -> &CpusetV2Mask {
        &self.mems_requested
    }

    /// Return the effective CPU mask.
    pub const fn cpus_effective(&self) -> &CpusetV2Mask {
        &self.cpus_effective
    }

    /// Return the effective memory node mask.
    pub const fn mems_effective(&self) -> &CpusetV2Mask {
        &self.mems_effective
    }

    /// Return the exclusive CPU mask.
    pub const fn cpus_exclusive(&self) -> &CpusetV2Mask {
        &self.cpus_exclusive
    }

    /// Return the number of attached PIDs.
    pub const fn pid_count(&self) -> usize {
        self.pid_count
    }

    /// Return the attached PIDs as a slice.
    pub fn pids(&self) -> &[u64] {
        &self.pids[..self.pid_count]
    }

    /// Return whether this group is active.
    pub const fn is_active(&self) -> bool {
        self.in_use
    }

    /// Return a reference to the statistics.
    pub const fn stats(&self) -> &CpusetV2Stats {
        &self.stats
    }

    /// Set the requested CPU mask.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if the mask is empty.
    pub fn set_cpus(&mut self, mask: CpusetV2Mask) -> Result<()> {
        if mask.is_empty() {
            return Err(Error::InvalidArgument);
        }
        self.cpus_requested = mask;
        Ok(())
    }

    /// Set the requested memory node mask.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if the mask is empty.
    pub fn set_mems(&mut self, mask: CpusetV2Mask) -> Result<()> {
        if mask.is_empty() {
            return Err(Error::InvalidArgument);
        }
        self.mems_requested = mask;
        Ok(())
    }

    /// Set the partition type.
    ///
    /// Changing to `Root` requires that `cpus_exclusive` is non-empty.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if promoting to `Root` with
    /// an empty exclusive mask.
    pub fn set_partition(&mut self, partition: PartitionType) -> Result<()> {
        if partition == PartitionType::Root && self.cpus_exclusive.is_empty() {
            return Err(Error::InvalidArgument);
        }
        self.partition = partition;
        Ok(())
    }

    /// Set the exclusive CPU mask for root partitions.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if the mask is empty.
    pub fn set_cpus_exclusive(&mut self, mask: CpusetV2Mask) -> Result<()> {
        if mask.is_empty() {
            return Err(Error::InvalidArgument);
        }
        self.cpus_exclusive = mask;
        Ok(())
    }

    /// Add a PID to this group.
    ///
    /// # Errors
    ///
    /// - `Error::AlreadyExists` -- PID is already attached.
    /// - `Error::OutOfMemory` -- PID list is full.
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

        self.pid_count -= 1;
        if pos < self.pid_count {
            self.pids[pos] = self.pids[self.pid_count];
        }
        self.pids[self.pid_count] = 0;
        Ok(())
    }

    /// Check whether a PID is attached.
    pub fn has_pid(&self, pid: u64) -> bool {
        self.pids[..self.pid_count].contains(&pid)
    }

    /// Update the effective masks by intersecting with parent masks.
    ///
    /// For root partitions, the effective CPU mask is the exclusive
    /// mask intersected with the parent's effective mask instead.
    fn update_effective(&mut self, parent_cpus: &CpusetV2Mask, parent_mems: &CpusetV2Mask) {
        if self.partition == PartitionType::Root {
            self.cpus_effective = self.cpus_exclusive.intersect(parent_cpus);
        } else {
            self.cpus_effective = self.cpus_requested.intersect(parent_cpus);
        }
        self.mems_effective = self.mems_requested.intersect(parent_mems);
        self.stats.recompute_count = self.stats.recompute_count.saturating_add(1);
    }
}

impl Default for CpusetV2Group {
    fn default() -> Self {
        Self::empty()
    }
}

// -- CpusetV2Registry --------------------------------------------------------

/// System-wide registry of cgroup v2 cpuset groups.
///
/// Manages up to [`MAX_GROUPS`] groups with partition support,
/// effective mask propagation, and PID migration on mask change.
pub struct CpusetV2Registry {
    /// Fixed-size array of group slots.
    groups: [CpusetV2Group; MAX_GROUPS],
    /// Next group ID to assign.
    next_id: u64,
    /// Number of active groups.
    count: usize,
}

impl Default for CpusetV2Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl CpusetV2Registry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        const EMPTY: CpusetV2Group = CpusetV2Group::empty();
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

    /// Create a new cpuset v2 group.
    ///
    /// Returns the new group's unique ID. If `parent_id` is `Some`,
    /// the parent must exist and the child inherits its effective
    /// masks.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` -- name is empty or too long.
    /// - `Error::OutOfMemory` -- no free slots available.
    /// - `Error::NotFound` -- parent ID specified but not found.
    pub fn create(&mut self, name: &[u8], parent_id: Option<u64>) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_GROUPS {
            return Err(Error::OutOfMemory);
        }

        // Validate parent exists and read its effective masks.
        let parent_effective = if let Some(pid) = parent_id {
            let parent = self
                .groups
                .iter()
                .find(|g| g.in_use && g.id == pid)
                .ok_or(Error::NotFound)?;
            Some((parent.cpus_effective, parent.mems_effective))
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
        *grp = CpusetV2Group::empty();
        grp.id = id;
        grp.in_use = true;
        grp.name_len = name.len();
        grp.name[..name.len()].copy_from_slice(name);

        if let Some(pid) = parent_id {
            grp.parent_id = pid;
            grp.has_parent = true;
        }

        // Default masks: inherit from parent or all CPUs/nodes.
        if let Some((cpus_eff, mems_eff)) = parent_effective {
            grp.cpus_requested = cpus_eff;
            grp.mems_requested = mems_eff;
            grp.cpus_effective = cpus_eff;
            grp.mems_effective = mems_eff;
        } else {
            let all_cpus = CpusetV2Mask::from_raw(u64::MAX);
            let all_mems = CpusetV2Mask::from_raw((1u64 << MAX_MEMS) - 1);
            grp.cpus_requested = all_cpus;
            grp.mems_requested = all_mems;
            grp.cpus_effective = all_cpus;
            grp.mems_effective = all_mems;
        }

        self.count += 1;
        Ok(id)
    }

    /// Destroy a cpuset v2 group by ID.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` -- group does not exist.
    /// - `Error::Busy` -- group still has attached PIDs.
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
    pub fn get(&self, id: u64) -> Option<&CpusetV2Group> {
        self.groups.iter().find(|g| g.in_use && g.id == id)
    }

    /// Return a mutable reference to a group by ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut CpusetV2Group> {
        self.groups.iter_mut().find(|g| g.in_use && g.id == id)
    }

    /// Attach a PID to a cpuset v2 group.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` -- group does not exist.
    /// - `Error::AlreadyExists` -- PID is already attached.
    /// - `Error::OutOfMemory` -- PID list is full.
    pub fn attach(&mut self, group_id: u64, pid: u64) -> Result<()> {
        let idx = self.index_of(group_id)?;
        self.groups[idx].add_pid(pid)
    }

    /// Detach a PID from a cpuset v2 group.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` -- group does not exist or PID is not
    ///   attached.
    pub fn detach(&mut self, group_id: u64, pid: u64) -> Result<()> {
        let idx = self.index_of(group_id)?;
        self.groups[idx].remove_pid(pid)
    }

    /// Set the CPU mask for a group and recompute effective masks.
    ///
    /// All attached PIDs are counted as migrated if the effective
    /// mask changes.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` -- group does not exist.
    /// - `Error::InvalidArgument` -- mask is empty.
    pub fn set_cpus(&mut self, group_id: u64, mask: CpusetV2Mask) -> Result<()> {
        let idx = self.index_of(group_id)?;
        let old_effective = self.groups[idx].cpus_effective;
        self.groups[idx].set_cpus(mask)?;
        self.recompute_effective(group_id);

        // Track migration if effective mask changed.
        let new_idx = self.index_of(group_id)?;
        if self.groups[new_idx].cpus_effective != old_effective {
            let pid_count = self.groups[new_idx].pid_count as u64;
            self.groups[new_idx].stats.migration_count = self.groups[new_idx]
                .stats
                .migration_count
                .saturating_add(pid_count);
        }
        Ok(())
    }

    /// Set the memory node mask for a group and recompute effective
    /// masks.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` -- group does not exist.
    /// - `Error::InvalidArgument` -- mask is empty.
    pub fn set_mems(&mut self, group_id: u64, mask: CpusetV2Mask) -> Result<()> {
        let idx = self.index_of(group_id)?;
        let old_effective = self.groups[idx].mems_effective;
        self.groups[idx].set_mems(mask)?;
        self.recompute_effective(group_id);

        let new_idx = self.index_of(group_id)?;
        if self.groups[new_idx].mems_effective != old_effective {
            let pid_count = self.groups[new_idx].pid_count as u64;
            self.groups[new_idx].stats.migration_count = self.groups[new_idx]
                .stats
                .migration_count
                .saturating_add(pid_count);
        }
        Ok(())
    }

    /// Set the partition type for a group.
    ///
    /// Promotes or demotes a group between root and member partition
    /// types. Root partitions require a non-empty exclusive CPU mask.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` -- group does not exist.
    /// - `Error::InvalidArgument` -- promoting to root with empty
    ///   exclusive mask.
    pub fn set_partition(&mut self, group_id: u64, partition: PartitionType) -> Result<()> {
        let idx = self.index_of(group_id)?;
        self.groups[idx].set_partition(partition)?;
        self.recompute_effective(group_id);
        Ok(())
    }

    /// Set the exclusive CPU mask for a group (root partitions).
    ///
    /// Validates that the exclusive mask does not overlap with
    /// sibling root partitions.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` -- group does not exist.
    /// - `Error::InvalidArgument` -- mask is empty.
    /// - `Error::Busy` -- exclusive CPUs overlap with a sibling
    ///   root partition.
    pub fn set_cpus_exclusive(&mut self, group_id: u64, mask: CpusetV2Mask) -> Result<()> {
        let idx = self.index_of(group_id)?;
        let parent_id_val = self.groups[idx].parent_id;
        let has_parent = self.groups[idx].has_parent;

        // Check for overlap with sibling root partitions.
        if has_parent {
            for grp in &self.groups {
                if !grp.in_use || grp.id == group_id {
                    continue;
                }
                if grp.has_parent
                    && grp.parent_id == parent_id_val
                    && grp.partition == PartitionType::Root
                {
                    if !mask.intersect(&grp.cpus_exclusive).is_empty() {
                        // Record violation and reject.
                        let vi = self.index_of(group_id)?;
                        self.groups[vi].stats.violation_count =
                            self.groups[vi].stats.violation_count.saturating_add(1);
                        return Err(Error::Busy);
                    }
                }
            }
        }

        let idx2 = self.index_of(group_id)?;
        self.groups[idx2].set_cpus_exclusive(mask)?;
        self.recompute_effective(group_id);
        Ok(())
    }

    /// Validate all partition constraints in the registry.
    ///
    /// Marks groups as `Invalid` if their exclusive CPUs overlap
    /// with siblings. Returns the number of violations found.
    pub fn validate_partitions(&mut self) -> usize {
        let mut violations = 0usize;

        // Collect all root partition (id, parent_id, exclusive mask).
        let mut roots = [(0u64, 0u64, CpusetV2Mask::empty()); MAX_GROUPS];
        let mut root_count = 0usize;

        for grp in &self.groups {
            if grp.in_use && grp.partition == PartitionType::Root && root_count < MAX_GROUPS {
                roots[root_count] = (grp.id, grp.parent_id, grp.cpus_exclusive);
                root_count += 1;
            }
        }

        // Check each pair of roots sharing a parent for overlap.
        for i in 0..root_count {
            for j in (i + 1)..root_count {
                if roots[i].1 == roots[j].1 {
                    if !roots[i].2.intersect(&roots[j].2).is_empty() {
                        // Mark both as invalid.
                        if let Some(g) = self
                            .groups
                            .iter_mut()
                            .find(|g| g.in_use && g.id == roots[i].0)
                        {
                            g.partition = PartitionType::Invalid;
                            g.stats.violation_count = g.stats.violation_count.saturating_add(1);
                        }
                        if let Some(g) = self
                            .groups
                            .iter_mut()
                            .find(|g| g.in_use && g.id == roots[j].0)
                        {
                            g.partition = PartitionType::Invalid;
                            g.stats.violation_count = g.stats.violation_count.saturating_add(1);
                        }
                        violations += 1;
                    }
                }
            }
        }

        violations
    }

    // -- Internal helpers ----------------------------------------------------

    /// Return the index of an active group by ID.
    fn index_of(&self, id: u64) -> Result<usize> {
        self.groups
            .iter()
            .position(|g| g.in_use && g.id == id)
            .ok_or(Error::NotFound)
    }

    /// Recompute effective masks for a group and propagate to children.
    fn recompute_effective(&mut self, group_id: u64) {
        // Find the group and determine parent effective masks.
        let group_idx = match self
            .groups
            .iter()
            .position(|g| g.in_use && g.id == group_id)
        {
            Some(idx) => idx,
            None => return,
        };

        if self.groups[group_idx].has_parent {
            let parent_id_val = self.groups[group_idx].parent_id;
            let parent_masks = self
                .groups
                .iter()
                .find(|g| g.in_use && g.id == parent_id_val)
                .map(|p| (p.cpus_effective, p.mems_effective));

            if let Some((pcpus, pmems)) = parent_masks {
                self.groups[group_idx].update_effective(&pcpus, &pmems);
            }
        } else {
            // Root group: effective = requested (or exclusive for
            // root partitions).
            if self.groups[group_idx].partition == PartitionType::Root {
                self.groups[group_idx].cpus_effective = self.groups[group_idx].cpus_exclusive;
            } else {
                self.groups[group_idx].cpus_effective = self.groups[group_idx].cpus_requested;
            }
            self.groups[group_idx].mems_effective = self.groups[group_idx].mems_requested;
            self.groups[group_idx].stats.recompute_count = self.groups[group_idx]
                .stats
                .recompute_count
                .saturating_add(1);
        }

        // Propagate to children.
        let eff_cpus = self.groups[group_idx].cpus_effective;
        let eff_mems = self.groups[group_idx].mems_effective;
        self.propagate_to_children(group_id, &eff_cpus, &eff_mems);
    }

    /// Propagate effective masks to all direct children of a group.
    fn propagate_to_children(
        &mut self,
        parent_id: u64,
        parent_cpus: &CpusetV2Mask,
        parent_mems: &CpusetV2Mask,
    ) {
        // Collect child IDs first to avoid borrow conflicts.
        let mut child_ids = [0u64; MAX_CHILDREN];
        let mut child_count = 0;
        for grp in &self.groups {
            if grp.in_use
                && grp.has_parent
                && grp.parent_id == parent_id
                && child_count < MAX_CHILDREN
            {
                child_ids[child_count] = grp.id;
                child_count += 1;
            }
        }

        for &child_id in &child_ids[..child_count] {
            if let Some(child) = self
                .groups
                .iter_mut()
                .find(|g| g.in_use && g.id == child_id)
            {
                child.update_effective(parent_cpus, parent_mems);
            }

            // Read child's new effective masks for further
            // propagation.
            let (child_cpus, child_mems) =
                match self.groups.iter().find(|g| g.in_use && g.id == child_id) {
                    Some(c) => (c.cpus_effective, c.mems_effective),
                    None => continue,
                };
            self.propagate_to_children(child_id, &child_cpus, &child_mems);
        }
    }
}
