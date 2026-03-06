// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Device driver registry.
//!
//! Tracks registered devices and their drivers. Provides lookup
//! by device ID, class, or IRQ number.

use crate::device::{DeviceClass, DeviceId, DeviceInfo, DeviceStatus};
use oncrix_lib::{Error, Result};

/// Maximum number of registered devices.
const MAX_DEVICES: usize = 64;

/// A registered device entry.
#[derive(Debug, Clone, Copy)]
pub struct DeviceEntry {
    /// Device metadata.
    pub info: DeviceInfo,
}

/// Device registry — tracks all known devices in the system.
pub struct DeviceRegistry {
    /// Device entries.
    devices: [Option<DeviceEntry>; MAX_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl core::fmt::Debug for DeviceRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceRegistry")
            .field("count", &self.count)
            .finish()
    }
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<DeviceEntry> = None;
        Self {
            devices: [NONE; MAX_DEVICES],
            count: 0,
        }
    }

    /// Register a new device.
    pub fn register(&mut self, info: DeviceInfo) -> Result<()> {
        if self.count >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate ID.
        if self.find(info.id).is_some() {
            return Err(Error::AlreadyExists);
        }

        for slot in self.devices.iter_mut() {
            if slot.is_none() {
                *slot = Some(DeviceEntry { info });
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a device by ID.
    pub fn unregister(&mut self, id: DeviceId) -> Result<()> {
        for slot in self.devices.iter_mut() {
            if let Some(entry) = slot {
                if entry.info.id == id {
                    *slot = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Find a device entry by ID.
    pub fn find(&self, id: DeviceId) -> Option<&DeviceEntry> {
        self.devices
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| e.info.id == id)
    }

    /// Find all devices of a given class.
    pub fn find_by_class(&self, class: DeviceClass) -> impl Iterator<Item = &DeviceEntry> {
        self.devices
            .iter()
            .filter_map(|s| s.as_ref())
            .filter(move |e| e.info.class == class)
    }

    /// Find a device by IRQ number.
    pub fn find_by_irq(&self, irq: u8) -> Option<&DeviceEntry> {
        self.devices
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| e.info.irq == irq)
    }

    /// Update device status.
    pub fn set_status(&mut self, id: DeviceId, status: DeviceStatus) -> Result<()> {
        for entry in self.devices.iter_mut().flatten() {
            if entry.info.id == id {
                entry.info.status = status;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of registered devices.
    pub fn count(&self) -> usize {
        self.count
    }
}
