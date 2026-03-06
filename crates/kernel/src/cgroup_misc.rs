// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup miscellaneous resource controller.
//!
//! Implements the `misc` cgroup controller from Linux cgroups v2,
//! which manages non-standard, finite scalar resources that do not
//! fit into the standard CPU/memory/IO/PID controllers.
//!
//! # Resource Model
//!
//! Each miscellaneous resource type is identified by a
//! [`MiscResourceType`] and has:
//! - **Capacity**: system-wide total available units
//! - **Current**: per-cgroup current usage
//! - **Max**: per-cgroup maximum allowed usage
//!
//! Resources are charged when acquired and uncharged when released.
//! If charging would exceed the cgroup's max, the operation fails.
//!
//! # Hierarchy
//!
//! Limits are hierarchical: a child cgroup cannot use more than its
//! parent allows. The effective limit is `min(own_max, parent_max)`.
//!
//! # Interface Files
//!
//! | File          | Description                            |
//! |---------------|----------------------------------------|
//! | misc.capacity | System-wide capacity per resource type |
//! | misc.current  | Current usage per resource type        |
//! | misc.max      | Maximum allowed usage (writeable)      |
//! | misc.events   | Event counters (max exceeded)          |
//!
//! Reference: Linux `kernel/cgroup/misc.c`,
//! `Documentation/admin-guide/cgroup-v2.rst`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of miscellaneous resource types.
const MAX_RESOURCE_TYPES: usize = 16;

/// Maximum number of cgroup misc controllers in the system.
const MAX_CGROUPS: usize = 64;

/// Maximum cgroup name length.
const MAX_NAME_LEN: usize = 64;

/// Resource type name maximum length.
const MAX_TYPE_NAME_LEN: usize = 32;

/// Value representing unlimited (no max enforced).
const UNLIMITED: u64 = u64::MAX;

/// Maximum hierarchy depth for effective limit computation.
const MAX_HIERARCHY_DEPTH: usize = 8;

// ── Resource Type ──────────────────────────────────────────────────

/// Known miscellaneous resource types.
///
/// Each variant represents a class of finite, countable resources
/// managed by the misc controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MiscResourceType {
    /// AMD SEV (Secure Encrypted Virtualization) ASIDs.
    SevAsid = 0,
    /// AMD SEV-ES (Encrypted State) ASIDs.
    SevEsAsid = 1,
    /// Intel TDX (Trust Domain Extensions) guest instances.
    TdxGuest = 2,
    /// Hardware crypto accelerator contexts.
    CryptoAccel = 3,
    /// FPGA reconfiguration slots.
    FpgaSlot = 4,
    /// GPU compute contexts.
    GpuContext = 5,
    /// DMA channel allocations.
    DmaChannel = 6,
    /// Hardware performance counter groups.
    PerfCounterGroup = 7,
}

impl MiscResourceType {
    /// Convert from a raw u32 value.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::SevAsid),
            1 => Some(Self::SevEsAsid),
            2 => Some(Self::TdxGuest),
            3 => Some(Self::CryptoAccel),
            4 => Some(Self::FpgaSlot),
            5 => Some(Self::GpuContext),
            6 => Some(Self::DmaChannel),
            7 => Some(Self::PerfCounterGroup),
            _ => None,
        }
    }

    /// Return the array index for this resource type.
    fn index(self) -> usize {
        self as usize
    }

    /// Return the string name of this resource type.
    pub fn name(self) -> &'static str {
        match self {
            Self::SevAsid => "res_sev",
            Self::SevEsAsid => "res_sev_es",
            Self::TdxGuest => "res_tdx",
            Self::CryptoAccel => "res_crypto",
            Self::FpgaSlot => "res_fpga",
            Self::GpuContext => "res_gpu",
            Self::DmaChannel => "res_dma",
            Self::PerfCounterGroup => "res_perf",
        }
    }
}

// ── System-wide Resource Capacity ──────────────────────────────────

/// System-wide capacity for a single miscellaneous resource type.
#[derive(Debug, Clone, Copy)]
pub struct MiscResourceCapacity {
    /// Resource type.
    pub res_type: MiscResourceType,
    /// Total system-wide capacity (units).
    pub capacity: u64,
    /// Currently allocated system-wide (sum of all cgroup usage).
    pub allocated: u64,
    /// Whether this resource type is registered.
    pub registered: bool,
}

impl MiscResourceCapacity {
    /// Create an empty (unregistered) capacity entry.
    const fn empty() -> Self {
        Self {
            res_type: MiscResourceType::SevAsid,
            capacity: 0,
            allocated: 0,
            registered: false,
        }
    }
}

// ── Per-cgroup Per-resource State ──────────────────────────────────

/// Per-resource-type usage and limits within a cgroup.
#[derive(Debug, Clone, Copy)]
pub struct MiscResourceUsage {
    /// Current usage (units charged to this cgroup).
    pub current: u64,
    /// Maximum allowed usage (UNLIMITED = no limit).
    pub max: u64,
    /// Number of times a charge was denied (max exceeded).
    pub events_max: u64,
    /// Whether this resource type is configured for this cgroup.
    pub configured: bool,
}

impl MiscResourceUsage {
    /// Create a default (unconfigured) usage entry.
    const fn empty() -> Self {
        Self {
            current: 0,
            max: UNLIMITED,
            events_max: 0,
            configured: false,
        }
    }
}

// ── Per-cgroup Misc Controller State ───────────────────────────────

/// Misc controller state for a single cgroup.
///
/// Tracks per-resource-type usage and limits for one cgroup.
pub struct MiscCgroupController {
    /// Cgroup identifier.
    cgroup_id: u64,
    /// Human-readable name.
    name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    name_len: usize,
    /// Index of parent cgroup in the registry (u64::MAX = root).
    parent_idx: u64,
    /// Hierarchy depth (0 = root).
    depth: u32,
    /// Per-resource-type usage and limits.
    resources: [MiscResourceUsage; MAX_RESOURCE_TYPES],
    /// Whether this controller is active.
    active: bool,
}

impl MiscCgroupController {
    /// Create an empty (inactive) controller.
    const fn empty() -> Self {
        Self {
            cgroup_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            parent_idx: u64::MAX,
            depth: 0,
            resources: [MiscResourceUsage::empty(); MAX_RESOURCE_TYPES],
            active: false,
        }
    }
}

// ── Charge Result ──────────────────────────────────────────────────

/// Result of a charge operation.
#[derive(Debug, Clone, Copy)]
pub struct ChargeResult {
    /// Whether the charge was successful.
    pub success: bool,
    /// Current usage after the charge (or attempted charge).
    pub current: u64,
    /// The max limit that was checked.
    pub max: u64,
    /// Effective limit considering hierarchy.
    pub effective_max: u64,
}

// ── Statistics ─────────────────────────────────────────────────────

/// Aggregate statistics for the misc cgroup subsystem.
#[derive(Debug, Clone, Copy)]
pub struct MiscCgroupStats {
    /// Total charge operations performed.
    pub charge_ops: u64,
    /// Total uncharge operations performed.
    pub uncharge_ops: u64,
    /// Total charge denials.
    pub charge_denials: u64,
    /// Number of active cgroups.
    pub active_cgroups: u64,
    /// Number of registered resource types.
    pub registered_types: u32,
}

impl MiscCgroupStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            charge_ops: 0,
            uncharge_ops: 0,
            charge_denials: 0,
            active_cgroups: 0,
            registered_types: 0,
        }
    }
}

// ── Registry ───────────────────────────────────────────────────────

/// System-wide misc cgroup resource controller registry.
///
/// Manages resource types, their system-wide capacities, and
/// per-cgroup usage/limits across the cgroup hierarchy.
pub struct MiscCgroupRegistry {
    /// System-wide resource capacities.
    capacities: [MiscResourceCapacity; MAX_RESOURCE_TYPES],
    /// Per-cgroup misc controllers.
    cgroups: [MiscCgroupController; MAX_CGROUPS],
    /// Number of active cgroups.
    active_count: usize,
    /// Subsystem statistics.
    stats: MiscCgroupStats,
}

impl MiscCgroupRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        Self {
            capacities: [MiscResourceCapacity::empty(); MAX_RESOURCE_TYPES],
            cgroups: [
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
                MiscCgroupController::empty(),
            ],
            active_count: 0,
            stats: MiscCgroupStats::new(),
        }
    }

    /// Register a miscellaneous resource type with system capacity.
    ///
    /// Must be called before any cgroup can charge this resource.
    pub fn register_resource(&mut self, res_type: MiscResourceType, capacity: u64) -> Result<()> {
        let idx = res_type.index();
        if self.capacities[idx].registered {
            return Err(Error::AlreadyExists);
        }
        if capacity == 0 {
            return Err(Error::InvalidArgument);
        }
        self.capacities[idx] = MiscResourceCapacity {
            res_type,
            capacity,
            allocated: 0,
            registered: true,
        };
        self.stats.registered_types += 1;
        Ok(())
    }

    /// Update the capacity of a registered resource type.
    ///
    /// The new capacity must not be less than the current total
    /// allocation.
    pub fn update_capacity(&mut self, res_type: MiscResourceType, new_capacity: u64) -> Result<()> {
        let idx = res_type.index();
        if !self.capacities[idx].registered {
            return Err(Error::NotFound);
        }
        if new_capacity < self.capacities[idx].allocated {
            return Err(Error::Busy);
        }
        self.capacities[idx].capacity = new_capacity;
        Ok(())
    }

    /// Get the system-wide capacity for a resource type.
    pub fn get_capacity(&self, res_type: MiscResourceType) -> Result<&MiscResourceCapacity> {
        let idx = res_type.index();
        if !self.capacities[idx].registered {
            return Err(Error::NotFound);
        }
        Ok(&self.capacities[idx])
    }

    /// Register a cgroup with the misc controller.
    pub fn register_cgroup(
        &mut self,
        cgroup_id: u64,
        name: &[u8],
        parent_idx: u64,
        depth: u32,
    ) -> Result<usize> {
        if self.active_count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        if self.find_cgroup(cgroup_id).is_some() {
            return Err(Error::AlreadyExists);
        }
        let slot = self.find_free_slot()?;
        let cg = &mut self.cgroups[slot];
        cg.cgroup_id = cgroup_id;
        let copy_len = name.len().min(MAX_NAME_LEN);
        cg.name[..copy_len].copy_from_slice(&name[..copy_len]);
        cg.name_len = copy_len;
        cg.parent_idx = parent_idx;
        cg.depth = depth;
        cg.active = true;
        self.active_count += 1;
        self.stats.active_cgroups = self.active_count as u64;
        Ok(slot)
    }

    /// Unregister a cgroup, releasing all charged resources.
    pub fn unregister_cgroup(&mut self, cgroup_id: u64) -> Result<()> {
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        // Release all charged resources
        for ri in 0..MAX_RESOURCE_TYPES {
            let current = self.cgroups[idx].resources[ri].current;
            if current > 0 && self.capacities[ri].registered {
                self.capacities[ri].allocated =
                    self.capacities[ri].allocated.saturating_sub(current);
            }
        }
        self.cgroups[idx] = MiscCgroupController::empty();
        self.active_count = self.active_count.saturating_sub(1);
        self.stats.active_cgroups = self.active_count as u64;
        Ok(())
    }

    /// Set the maximum limit for a resource type in a cgroup.
    pub fn set_max(&mut self, cgroup_id: u64, res_type: MiscResourceType, max: u64) -> Result<()> {
        let ri = res_type.index();
        if !self.capacities[ri].registered {
            return Err(Error::NotFound);
        }
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        self.cgroups[idx].resources[ri].max = max;
        self.cgroups[idx].resources[ri].configured = true;
        Ok(())
    }

    /// Get the current usage for a resource type in a cgroup.
    pub fn get_current(&self, cgroup_id: u64, res_type: MiscResourceType) -> Result<u64> {
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        Ok(self.cgroups[idx].resources[res_type.index()].current)
    }

    /// Get the max limit for a resource type in a cgroup.
    pub fn get_max(&self, cgroup_id: u64, res_type: MiscResourceType) -> Result<u64> {
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        Ok(self.cgroups[idx].resources[res_type.index()].max)
    }

    /// Compute the effective limit considering the hierarchy.
    ///
    /// The effective limit is the minimum of this cgroup's max and
    /// all ancestor cgroups' maxes.
    pub fn effective_max(&self, cgroup_id: u64, res_type: MiscResourceType) -> Result<u64> {
        let ri = res_type.index();
        let mut effective = UNLIMITED;
        let mut current_id = cgroup_id;
        let mut depth = 0;

        loop {
            let idx = self.find_cgroup(current_id).ok_or(Error::NotFound)?;
            let max = self.cgroups[idx].resources[ri].max;
            if max < effective {
                effective = max;
            }
            let parent = self.cgroups[idx].parent_idx;
            if parent == u64::MAX || depth >= MAX_HIERARCHY_DEPTH {
                break;
            }
            current_id = self.cgroups[parent as usize].cgroup_id;
            depth += 1;
        }

        Ok(effective)
    }

    /// Charge resource units to a cgroup.
    ///
    /// Checks the cgroup's effective limit and system-wide capacity
    /// before allowing the charge. Returns a [`ChargeResult`]
    /// indicating success or failure with diagnostic details.
    pub fn charge(
        &mut self,
        cgroup_id: u64,
        res_type: MiscResourceType,
        amount: u64,
    ) -> Result<ChargeResult> {
        let ri = res_type.index();
        if !self.capacities[ri].registered {
            return Err(Error::NotFound);
        }

        // Check system-wide capacity
        let cap = &self.capacities[ri];
        if cap.allocated + amount > cap.capacity {
            self.stats.charge_denials += 1;
            return Ok(ChargeResult {
                success: false,
                current: 0,
                max: cap.capacity,
                effective_max: cap.capacity,
            });
        }

        // Compute effective max
        let eff_max = self.effective_max(cgroup_id, res_type)?;
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        let current = self.cgroups[idx].resources[ri].current;
        let max = self.cgroups[idx].resources[ri].max;

        if current + amount > eff_max {
            // Charge would exceed effective limit
            self.cgroups[idx].resources[ri].events_max += 1;
            self.stats.charge_denials += 1;
            return Ok(ChargeResult {
                success: false,
                current,
                max,
                effective_max: eff_max,
            });
        }

        // Apply the charge
        self.cgroups[idx].resources[ri].current += amount;
        self.capacities[ri].allocated += amount;
        self.stats.charge_ops += 1;

        Ok(ChargeResult {
            success: true,
            current: self.cgroups[idx].resources[ri].current,
            max: self.cgroups[idx].resources[ri].max,
            effective_max: eff_max,
        })
    }

    /// Uncharge resource units from a cgroup.
    ///
    /// Releases previously charged resources back to the system pool.
    pub fn uncharge(
        &mut self,
        cgroup_id: u64,
        res_type: MiscResourceType,
        amount: u64,
    ) -> Result<u64> {
        let ri = res_type.index();
        if !self.capacities[ri].registered {
            return Err(Error::NotFound);
        }
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        let usage = &mut self.cgroups[idx].resources[ri];
        if amount > usage.current {
            return Err(Error::InvalidArgument);
        }
        usage.current -= amount;
        self.capacities[ri].allocated = self.capacities[ri].allocated.saturating_sub(amount);
        self.stats.uncharge_ops += 1;
        Ok(usage.current)
    }

    /// Get event counters for a resource type in a cgroup.
    pub fn get_events(&self, cgroup_id: u64, res_type: MiscResourceType) -> Result<u64> {
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        Ok(self.cgroups[idx].resources[res_type.index()].events_max)
    }

    /// Get all resource usage for a cgroup.
    ///
    /// Returns an array of (resource_type_index, current, max) for
    /// all registered resource types.
    pub fn get_all_usage(&self, cgroup_id: u64, buf: &mut [(u32, u64, u64)]) -> Result<usize> {
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        let mut count = 0;
        for ri in 0..MAX_RESOURCE_TYPES {
            if self.capacities[ri].registered && count < buf.len() {
                let usage = &self.cgroups[idx].resources[ri];
                buf[count] = (ri as u32, usage.current, usage.max);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Get aggregate subsystem statistics.
    pub fn statistics(&self) -> &MiscCgroupStats {
        &self.stats
    }

    /// Return the number of active cgroups.
    pub fn active_cgroup_count(&self) -> usize {
        self.active_count
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Find a cgroup by its ID.
    fn find_cgroup(&self, cgroup_id: u64) -> Option<usize> {
        self.cgroups
            .iter()
            .position(|cg| cg.active && cg.cgroup_id == cgroup_id)
    }

    /// Find a free slot in the cgroup array.
    fn find_free_slot(&self) -> Result<usize> {
        self.cgroups
            .iter()
            .position(|cg| !cg.active)
            .ok_or(Error::OutOfMemory)
    }
}
