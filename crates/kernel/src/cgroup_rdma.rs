// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! cgroup RDMA resource controller.
//!
//! Provides per-cgroup accounting and enforcement of RDMA (Remote Direct
//! Memory Access) resources. Prevents a single cgroup from monopolising
//! RDMA hardware resources that are shared across the system.
//!
//! # Controlled Resources (per HCA device)
//!
//! | Resource     | Description                                          |
//! |--------------|------------------------------------------------------|
//! | `hca_handle` | RDMA HCA (Host Channel Adapter) handles (QP, CQ, MR) |
//! | `hca_object` | Total RDMA objects (WR, SGE, PD, AH, …)             |
//!
//! # Interface (cgroupfs)
//!
//! ```text
//! /sys/fs/cgroup/<cgroup>/rdma.max
//!     mlx4_0 hca_handle=2 hca_object=2000
//!     ocrdma1 hca_handle=3 hca_object=max
//!
//! /sys/fs/cgroup/<cgroup>/rdma.current
//!     mlx4_0 hca_handle=1 hca_object=1023
//!     ocrdma1 hca_handle=2 hca_object=40
//! ```
//!
//! Setting a limit to the sentinel value [`RDMA_NO_LIMIT`] disables the
//! limit for that resource.
//!
//! Reference: Linux `kernel/cgroup/rdma.c`, `Documentation/admin-guide/cgroup-v2.rst`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sentinel value meaning "no limit" for an RDMA resource.
pub const RDMA_NO_LIMIT: u64 = u64::MAX;

/// Maximum number of cgroups in the RDMA controller.
const MAX_RDMA_CGROUPS: usize = 32;

/// Maximum number of RDMA devices tracked.
const MAX_RDMA_DEVICES: usize = 8;

/// Maximum length of an RDMA device name.
const MAX_DEV_NAME_LEN: usize = 32;

/// Maximum number of children per cgroup.
const MAX_CHILDREN: usize = 16;

// ---------------------------------------------------------------------------
// RDMA resource limits/usage for a single device
// ---------------------------------------------------------------------------

/// Per-device RDMA resource limits for one cgroup.
///
/// Each field stores either a hard limit or [`RDMA_NO_LIMIT`] if unrestricted.
#[derive(Debug, Clone, Copy)]
pub struct RdmaDevLimit {
    /// Maximum HCA handle count (0 = use parent limit).
    pub hca_handle: u64,
    /// Maximum HCA object count.
    pub hca_object: u64,
}

impl Default for RdmaDevLimit {
    fn default() -> Self {
        Self {
            hca_handle: RDMA_NO_LIMIT,
            hca_object: RDMA_NO_LIMIT,
        }
    }
}

impl RdmaDevLimit {
    /// Construct with explicit values.
    pub const fn new(hca_handle: u64, hca_object: u64) -> Self {
        Self {
            hca_handle,
            hca_object,
        }
    }

    /// Returns `true` if both resources are unlimited.
    pub fn is_unlimited(&self) -> bool {
        self.hca_handle == RDMA_NO_LIMIT && self.hca_object == RDMA_NO_LIMIT
    }
}

/// Per-device current RDMA resource usage for one cgroup.
#[derive(Debug, Clone, Copy, Default)]
pub struct RdmaDevUsage {
    /// Currently allocated HCA handles.
    pub hca_handle: u64,
    /// Currently allocated HCA objects.
    pub hca_object: u64,
}

impl RdmaDevUsage {
    /// Returns `true` if all resources are at zero.
    pub fn is_zero(&self) -> bool {
        self.hca_handle == 0 && self.hca_object == 0
    }
}

// ---------------------------------------------------------------------------
// RDMA device descriptor
// ---------------------------------------------------------------------------

/// A registered RDMA device (HCA) tracked by the controller.
#[derive(Debug, Clone, Copy)]
pub struct RdmaDevice {
    /// Device index (used as array key).
    pub idx: usize,
    /// Human-readable device name (e.g. `mlx5_0`).
    pub name: [u8; MAX_DEV_NAME_LEN],
    /// Valid bytes in `name`.
    pub name_len: usize,
    /// Total HCA handles available on this device.
    pub total_hca_handles: u64,
    /// Total HCA objects available on this device.
    pub total_hca_objects: u64,
}

impl RdmaDevice {
    /// Construct a new device descriptor.
    pub fn new(idx: usize, name: &[u8], total_hca_handles: u64, total_hca_objects: u64) -> Self {
        let mut d = Self {
            idx,
            name: [0u8; MAX_DEV_NAME_LEN],
            name_len: 0,
            total_hca_handles,
            total_hca_objects,
        };
        let len = name.len().min(MAX_DEV_NAME_LEN);
        d.name[..len].copy_from_slice(&name[..len]);
        d.name_len = len;
        d
    }
}

// ---------------------------------------------------------------------------
// RDMA cgroup entry
// ---------------------------------------------------------------------------

/// RDMA accounting state for a single cgroup.
#[derive(Debug)]
pub struct RdmaCgroup {
    /// Cgroup ID (matches cgroup subsystem ID).
    pub id: u32,
    /// Parent cgroup ID (0 = root).
    pub parent_id: u32,
    /// Per-device resource limits (indexed by device idx).
    pub limits: [RdmaDevLimit; MAX_RDMA_DEVICES],
    /// Per-device current usage (indexed by device idx).
    pub usage: [RdmaDevUsage; MAX_RDMA_DEVICES],
    /// Child cgroup IDs.
    pub children: [u32; MAX_CHILDREN],
    /// Number of children.
    pub child_count: usize,
    /// Whether this cgroup entry is active.
    pub active: bool,
}

impl RdmaCgroup {
    /// Create a new cgroup entry with all limits set to unlimited.
    pub fn new(id: u32, parent_id: u32) -> Self {
        Self {
            id,
            parent_id,
            limits: [RdmaDevLimit::default(); MAX_RDMA_DEVICES],
            usage: [RdmaDevUsage::default(); MAX_RDMA_DEVICES],
            children: [0u32; MAX_CHILDREN],
            child_count: 0,
            active: true,
        }
    }

    /// Set the limit for a specific device.
    pub fn set_limit(&mut self, dev_idx: usize, limit: RdmaDevLimit) -> Result<()> {
        if dev_idx >= MAX_RDMA_DEVICES {
            return Err(Error::InvalidArgument);
        }
        self.limits[dev_idx] = limit;
        Ok(())
    }

    /// Get the limit for a specific device.
    pub fn get_limit(&self, dev_idx: usize) -> Result<RdmaDevLimit> {
        if dev_idx >= MAX_RDMA_DEVICES {
            return Err(Error::InvalidArgument);
        }
        Ok(self.limits[dev_idx])
    }

    /// Get the current usage for a specific device.
    pub fn get_usage(&self, dev_idx: usize) -> Result<RdmaDevUsage> {
        if dev_idx >= MAX_RDMA_DEVICES {
            return Err(Error::InvalidArgument);
        }
        Ok(self.usage[dev_idx])
    }

    /// Register a child cgroup.
    pub fn add_child(&mut self, child_id: u32) -> Result<()> {
        if self.child_count >= MAX_CHILDREN {
            return Err(Error::OutOfMemory);
        }
        self.children[self.child_count] = child_id;
        self.child_count += 1;
        Ok(())
    }

    /// Deregister a child cgroup.
    pub fn remove_child(&mut self, child_id: u32) -> Result<()> {
        let pos = self.children[..self.child_count]
            .iter()
            .position(|&c| c == child_id)
            .ok_or(Error::NotFound)?;
        for i in pos..self.child_count - 1 {
            self.children[i] = self.children[i + 1];
        }
        self.child_count -= 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Charge / uncharge logic
// ---------------------------------------------------------------------------

/// Resources to charge or uncharge in a single operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct RdmaCharge {
    /// RDMA device index.
    pub dev_idx: usize,
    /// Number of HCA handles to charge.
    pub hca_handle: u64,
    /// Number of HCA objects to charge.
    pub hca_object: u64,
}

impl RdmaCharge {
    /// Convenience constructor.
    pub const fn new(dev_idx: usize, hca_handle: u64, hca_object: u64) -> Self {
        Self {
            dev_idx,
            hca_handle,
            hca_object,
        }
    }
}

// ---------------------------------------------------------------------------
// RDMA controller
// ---------------------------------------------------------------------------

/// The RDMA cgroup resource controller.
///
/// Tracks registered RDMA devices and per-cgroup resource usage and limits.
/// Enforces limits on `charge()`, walking up the cgroup ancestor chain to
/// verify that none of the hierarchy limits would be exceeded.
pub struct RdmaController {
    /// Registered RDMA devices.
    devices: [Option<RdmaDevice>; MAX_RDMA_DEVICES],
    /// Number of registered devices.
    device_count: usize,
    /// Per-cgroup RDMA state.
    cgroups: [Option<RdmaCgroup>; MAX_RDMA_CGROUPS],
    /// Number of active cgroups.
    cgroup_count: usize,
    /// Next cgroup ID to assign.
    next_id: u32,
}

impl RdmaController {
    /// Create a new, empty RDMA controller (with the root cgroup pre-created).
    pub fn new() -> Self {
        let mut ctrl = Self {
            devices: [const { None }; MAX_RDMA_DEVICES],
            device_count: 0,
            cgroups: [const { None }; MAX_RDMA_CGROUPS],
            cgroup_count: 0,
            next_id: 1,
        };
        // Root cgroup: id=1, parent_id=0
        let root = RdmaCgroup::new(1, 0);
        ctrl.cgroups[0] = Some(root);
        ctrl.cgroup_count = 1;
        ctrl.next_id = 2;
        ctrl
    }

    // ── Device registration ──────────────────────────────────────────────

    /// Register an RDMA device with the controller.
    ///
    /// Returns the assigned device index.
    pub fn register_device(
        &mut self,
        name: &[u8],
        total_hca_handles: u64,
        total_hca_objects: u64,
    ) -> Result<usize> {
        if self.device_count >= MAX_RDMA_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.device_count;
        self.devices[idx] = Some(RdmaDevice::new(
            idx,
            name,
            total_hca_handles,
            total_hca_objects,
        ));
        self.device_count += 1;
        Ok(idx)
    }

    /// Unregister a device.
    pub fn unregister_device(&mut self, dev_idx: usize) -> Result<()> {
        if dev_idx >= MAX_RDMA_DEVICES {
            return Err(Error::InvalidArgument);
        }
        self.devices[dev_idx].take().ok_or(Error::NotFound)?;
        // Device count stays; holes are allowed in the device table
        Ok(())
    }

    /// Look up a device by name.
    pub fn find_device(&self, name: &[u8]) -> Option<usize> {
        self.devices.iter().position(|d| {
            d.as_ref()
                .map(|d| d.name[..d.name_len] == name[..name.len().min(d.name_len)])
                .unwrap_or(false)
        })
    }

    /// Get device information.
    pub fn get_device(&self, dev_idx: usize) -> Option<&RdmaDevice> {
        self.devices.get(dev_idx)?.as_ref()
    }

    // ── Cgroup lifecycle ─────────────────────────────────────────────────

    /// Create a new cgroup as a child of `parent_id`.
    ///
    /// Returns the new cgroup's ID.
    pub fn create_cgroup(&mut self, parent_id: u32) -> Result<u32> {
        if self.cgroup_count >= MAX_RDMA_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        // Verify parent exists
        let parent_pos = self
            .cgroups
            .iter()
            .position(|c| c.as_ref().map(|c| c.id == parent_id).unwrap_or(false))
            .ok_or(Error::NotFound)?;

        let id = self.next_id;
        self.next_id += 1;

        // Find an empty slot
        let slot_pos = self
            .cgroups
            .iter()
            .position(|c| c.is_none())
            .ok_or(Error::OutOfMemory)?;

        self.cgroups[slot_pos] = Some(RdmaCgroup::new(id, parent_id));
        self.cgroup_count += 1;

        // Register as child of parent
        if let Some(parent) = self.cgroups[parent_pos].as_mut() {
            parent.add_child(id)?;
        }
        Ok(id)
    }

    /// Destroy a cgroup.
    ///
    /// Fails if the cgroup still has children or non-zero usage.
    pub fn destroy_cgroup(&mut self, cgroup_id: u32) -> Result<()> {
        let pos = self
            .cgroups
            .iter()
            .position(|c| c.as_ref().map(|c| c.id == cgroup_id).unwrap_or(false))
            .ok_or(Error::NotFound)?;

        {
            let cg = self.cgroups[pos].as_ref().ok_or(Error::NotFound)?;
            if cg.child_count > 0 {
                return Err(Error::Busy);
            }
            // Verify usage is zero on all devices
            for dev_idx in 0..MAX_RDMA_DEVICES {
                if !cg.usage[dev_idx].is_zero() {
                    return Err(Error::Busy);
                }
            }
            let parent_id = cg.parent_id;
            // We'll update parent after dropping borrow
            let _ = cg;

            // Remove from parent's children
            let parent_pos = self
                .cgroups
                .iter()
                .position(|c| c.as_ref().map(|c| c.id == parent_id).unwrap_or(false));
            if let Some(pp) = parent_pos {
                if let Some(parent) = self.cgroups[pp].as_mut() {
                    let _ = parent.remove_child(cgroup_id);
                }
            }
        }

        self.cgroups[pos] = None;
        self.cgroup_count -= 1;
        Ok(())
    }

    // ── Limit configuration ──────────────────────────────────────────────

    /// Set the resource limit for `(cgroup_id, dev_idx)`.
    pub fn set_limit(&mut self, cgroup_id: u32, dev_idx: usize, limit: RdmaDevLimit) -> Result<()> {
        if dev_idx >= MAX_RDMA_DEVICES {
            return Err(Error::InvalidArgument);
        }
        // Validate that the limit doesn't exceed device capacity
        if let Some(dev) = self.devices[dev_idx].as_ref() {
            if limit.hca_handle != RDMA_NO_LIMIT && limit.hca_handle > dev.total_hca_handles {
                return Err(Error::InvalidArgument);
            }
            if limit.hca_object != RDMA_NO_LIMIT && limit.hca_object > dev.total_hca_objects {
                return Err(Error::InvalidArgument);
            }
        }
        let cg = self
            .cgroups
            .iter_mut()
            .find_map(|c| c.as_mut().filter(|c| c.id == cgroup_id))
            .ok_or(Error::NotFound)?;
        cg.set_limit(dev_idx, limit)
    }

    /// Get the configured limit for `(cgroup_id, dev_idx)`.
    pub fn get_limit(&self, cgroup_id: u32, dev_idx: usize) -> Result<RdmaDevLimit> {
        let cg = self
            .cgroups
            .iter()
            .find_map(|c| c.as_ref().filter(|c| c.id == cgroup_id))
            .ok_or(Error::NotFound)?;
        cg.get_limit(dev_idx)
    }

    // ── Charge / uncharge ────────────────────────────────────────────────

    /// Charge RDMA resources to a cgroup hierarchy.
    ///
    /// Walks from `cgroup_id` up to the root, verifying that no ancestor
    /// limit would be exceeded. If all checks pass, resources are charged at
    /// every level. On failure, no resources are modified.
    pub fn charge(&mut self, cgroup_id: u32, charge: &RdmaCharge) -> Result<()> {
        let dev_idx = charge.dev_idx;
        if dev_idx >= MAX_RDMA_DEVICES {
            return Err(Error::InvalidArgument);
        }

        // Build ancestor chain (current cgroup → root)
        let mut ancestor_chain: [u32; MAX_RDMA_CGROUPS] = [0u32; MAX_RDMA_CGROUPS];
        let mut chain_len = 0usize;
        let mut current_id = cgroup_id;

        loop {
            let cg = self
                .cgroups
                .iter()
                .find_map(|c| c.as_ref().filter(|c| c.id == current_id))
                .ok_or(Error::NotFound)?;

            // Check limit at this level
            let limit = cg.limits[dev_idx];
            let usage = cg.usage[dev_idx];

            if limit.hca_handle != RDMA_NO_LIMIT {
                let new_val = usage
                    .hca_handle
                    .checked_add(charge.hca_handle)
                    .ok_or(Error::OutOfMemory)?;
                if new_val > limit.hca_handle {
                    return Err(Error::OutOfMemory);
                }
            }
            if limit.hca_object != RDMA_NO_LIMIT {
                let new_val = usage
                    .hca_object
                    .checked_add(charge.hca_object)
                    .ok_or(Error::OutOfMemory)?;
                if new_val > limit.hca_object {
                    return Err(Error::OutOfMemory);
                }
            }

            if chain_len < MAX_RDMA_CGROUPS {
                ancestor_chain[chain_len] = current_id;
                chain_len += 1;
            }

            if cg.parent_id == 0 {
                break;
            }
            current_id = cg.parent_id;
        }

        // All checks passed — apply the charge
        for i in 0..chain_len {
            let ancestor_id = ancestor_chain[i];
            if let Some(cg) = self
                .cgroups
                .iter_mut()
                .find_map(|c| c.as_mut().filter(|c| c.id == ancestor_id))
            {
                cg.usage[dev_idx].hca_handle += charge.hca_handle;
                cg.usage[dev_idx].hca_object += charge.hca_object;
            }
        }
        Ok(())
    }

    /// Uncharge RDMA resources from a cgroup hierarchy.
    ///
    /// Walks from `cgroup_id` up to the root, decrementing usage counters.
    /// Saturates at zero rather than underflowing.
    pub fn uncharge(&mut self, cgroup_id: u32, charge: &RdmaCharge) -> Result<()> {
        let dev_idx = charge.dev_idx;
        if dev_idx >= MAX_RDMA_DEVICES {
            return Err(Error::InvalidArgument);
        }

        // Build ancestor chain
        let mut ancestor_chain: [u32; MAX_RDMA_CGROUPS] = [0u32; MAX_RDMA_CGROUPS];
        let mut chain_len = 0usize;
        let mut current_id = cgroup_id;

        loop {
            let (parent_id, is_root) = self
                .cgroups
                .iter()
                .find_map(|c| c.as_ref().filter(|c| c.id == current_id))
                .map(|cg| (cg.parent_id, cg.parent_id == 0))
                .ok_or(Error::NotFound)?;

            if chain_len < MAX_RDMA_CGROUPS {
                ancestor_chain[chain_len] = current_id;
                chain_len += 1;
            }
            if is_root {
                break;
            }
            current_id = parent_id;
        }

        for i in 0..chain_len {
            let ancestor_id = ancestor_chain[i];
            if let Some(cg) = self
                .cgroups
                .iter_mut()
                .find_map(|c| c.as_mut().filter(|c| c.id == ancestor_id))
            {
                cg.usage[dev_idx].hca_handle = cg.usage[dev_idx]
                    .hca_handle
                    .saturating_sub(charge.hca_handle);
                cg.usage[dev_idx].hca_object = cg.usage[dev_idx]
                    .hca_object
                    .saturating_sub(charge.hca_object);
            }
        }
        Ok(())
    }

    // ── Introspection ────────────────────────────────────────────────────

    /// Get current usage for `(cgroup_id, dev_idx)`.
    pub fn get_usage(&self, cgroup_id: u32, dev_idx: usize) -> Result<RdmaDevUsage> {
        let cg = self
            .cgroups
            .iter()
            .find_map(|c| c.as_ref().filter(|c| c.id == cgroup_id))
            .ok_or(Error::NotFound)?;
        cg.get_usage(dev_idx)
    }

    /// Number of registered devices.
    pub fn device_count(&self) -> usize {
        self.devices.iter().filter(|d| d.is_some()).count()
    }

    /// Number of active cgroups.
    pub fn cgroup_count(&self) -> usize {
        self.cgroup_count
    }

    /// Return the root cgroup ID (always 1).
    pub const fn root_id(&self) -> u32 {
        1
    }

    /// Collect aggregate stats for the controller.
    pub fn stats(&self) -> RdmaStats {
        let mut stats = RdmaStats::default();
        stats.devices = self.device_count();
        stats.cgroups = self.cgroup_count;
        for cg in self.cgroups.iter().flatten() {
            for dev_idx in 0..MAX_RDMA_DEVICES {
                stats.total_hca_handles += cg.usage[dev_idx].hca_handle;
                stats.total_hca_objects += cg.usage[dev_idx].hca_object;
            }
        }
        // Avoid double-counting by dividing by hierarchy depth (approximate)
        // In a real kernel we'd only sum leaf cgroups; here we report raw sums.
        stats
    }
}

impl Default for RdmaController {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Aggregate statistics snapshot for the RDMA cgroup controller.
#[derive(Debug, Clone, Copy, Default)]
pub struct RdmaStats {
    /// Number of registered RDMA devices.
    pub devices: usize,
    /// Number of active cgroups.
    pub cgroups: usize,
    /// Sum of `hca_handle` usage across all cgroups (includes hierarchy).
    pub total_hca_handles: u64,
    /// Sum of `hca_object` usage across all cgroups (includes hierarchy).
    pub total_hca_objects: u64,
}
