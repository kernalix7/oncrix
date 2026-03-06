// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IOMMU group management.
//!
//! IOMMU groups represent the granularity at which the IOMMU can provide
//! isolation. Devices in the same IOMMU group share the same IOMMU domain
//! and cannot be independently isolated from each other.
//!
//! # Group Assignment
//!
//! Groups are determined by hardware topology (ACS groups, PCIe topology).
//! Devices behind a PCIe switch without ACS support share a group.

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// Maximum number of devices per IOMMU group.
pub const IOMMU_GROUP_MAX_DEVICES: usize = 16;

/// Maximum number of IOMMU groups.
pub const IOMMU_MAX_GROUPS: usize = 64;

/// IOMMU group identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(pub u32);

/// A device entry within an IOMMU group.
#[derive(Debug, Clone, Copy)]
pub struct GroupDevice {
    /// PCI BDF (Bus:Device.Function) or platform device ID.
    pub device_id: u32,
    /// Whether this device has been assigned to a userspace driver.
    pub assigned: bool,
}

/// An IOMMU group — a set of devices sharing the same translation domain.
pub struct IommuGroup {
    /// Group identifier.
    pub id: GroupId,
    /// Devices in this group.
    devices: [Option<GroupDevice>; IOMMU_GROUP_MAX_DEVICES],
    /// Number of devices.
    device_count: usize,
    /// IOMMU domain ID associated with this group.
    pub domain_id: Option<u32>,
}

impl IommuGroup {
    /// Creates a new empty IOMMU group.
    pub const fn new(id: GroupId) -> Self {
        Self {
            id,
            devices: [None; IOMMU_GROUP_MAX_DEVICES],
            device_count: 0,
            domain_id: None,
        }
    }

    /// Adds a device to this group.
    pub fn add_device(&mut self, device_id: u32) -> Result<()> {
        if self.device_count >= IOMMU_GROUP_MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate
        for i in 0..self.device_count {
            if let Some(dev) = &self.devices[i] {
                if dev.device_id == device_id {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        self.devices[self.device_count] = Some(GroupDevice {
            device_id,
            assigned: false,
        });
        self.device_count += 1;
        Ok(())
    }

    /// Removes a device from this group.
    pub fn remove_device(&mut self, device_id: u32) -> Result<()> {
        for i in 0..self.device_count {
            if self.devices[i].map_or(false, |d| d.device_id == device_id) {
                self.devices[i] = self.devices[self.device_count - 1];
                self.devices[self.device_count - 1] = None;
                self.device_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the device count.
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    /// Returns whether all devices in the group can be safely assigned to a domain.
    pub fn is_assignable(&self) -> bool {
        self.devices[..self.device_count]
            .iter()
            .all(|d| d.map_or(true, |dev| !dev.assigned))
    }

    /// Iterates device IDs.
    pub fn device_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.devices[..self.device_count]
            .iter()
            .filter_map(|d| d.map(|dev| dev.device_id))
    }
}

impl Default for IommuGroup {
    fn default() -> Self {
        Self::new(GroupId(0))
    }
}

/// Registry of all IOMMU groups in the system.
pub struct IommuGroupRegistry {
    groups: [Option<IommuGroup>; IOMMU_MAX_GROUPS],
    count: usize,
    next_id: u32,
}

impl IommuGroupRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<IommuGroup> = None;
        Self {
            groups: [NONE; IOMMU_MAX_GROUPS],
            count: 0,
            next_id: 0,
        }
    }

    /// Creates a new group and returns its ID.
    pub fn create_group(&mut self) -> Result<GroupId> {
        if self.count >= IOMMU_MAX_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let id = GroupId(self.next_id);
        self.next_id += 1;
        self.groups[self.count] = Some(IommuGroup::new(id));
        self.count += 1;
        Ok(id)
    }

    /// Returns a mutable reference to a group by ID.
    pub fn get_mut(&mut self, id: GroupId) -> Option<&mut IommuGroup> {
        self.groups[..self.count]
            .iter_mut()
            .find_map(|g| g.as_mut().filter(|grp| grp.id == id))
    }

    /// Returns a reference to a group by ID.
    pub fn get(&self, id: GroupId) -> Option<&IommuGroup> {
        self.groups[..self.count]
            .iter()
            .find_map(|g| g.as_ref().filter(|grp| grp.id == id))
    }

    /// Finds the group containing a given device ID.
    pub fn find_device_group(&self, device_id: u32) -> Option<GroupId> {
        for g in self.groups[..self.count].iter() {
            if let Some(grp) = g.as_ref() {
                if grp.device_ids().any(|d| d == device_id) {
                    return Some(grp.id);
                }
            }
        }
        None
    }

    /// Returns the number of groups.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns whether there are no groups.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for IommuGroupRegistry {
    fn default() -> Self {
        Self::new()
    }
}
