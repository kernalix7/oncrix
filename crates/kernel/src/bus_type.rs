// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Device bus type.
//!
//! A bus type represents a communication channel between the CPU
//! and devices (e.g. PCI, USB, I2C, platform). Each bus type
//! defines how devices are discovered, how drivers are matched
//! to devices, and how probing/removal is handled.
//!
//! # Design
//!
//! ```text
//!   BusType
//!   +-------------------+
//!   | name              |
//!   | match_fn          |  (device_id, driver_id) → bool
//!   | devices[]         |  registered device indices
//!   | drivers[]         |  registered driver indices
//!   +-------------------+
//!
//!   BusDevice: { id, name, driver_idx, bus_idx }
//!   BusDriver: { id, name, bus_idx }
//! ```
//!
//! # Lifecycle
//!
//! 1. `bus_register()` — register a new bus type.
//! 2. `bus_add_device()` / `bus_remove_device()`.
//! 3. `bus_add_driver()` / `bus_remove_driver()`.
//! 4. `bus_for_each_dev()` / `bus_for_each_drv()` — iteration.
//! 5. `bus_unregister()` — tear down.
//!
//! # Reference
//!
//! Linux `drivers/base/bus.c`, `include/linux/device/bus.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum bus types.
const MAX_BUS_TYPES: usize = 32;

/// Maximum devices per bus.
const MAX_DEVICES_PER_BUS: usize = 128;

/// Maximum drivers per bus.
const MAX_DRIVERS_PER_BUS: usize = 64;

/// Maximum name length.
const MAX_NAME_LEN: usize = 32;

/// No index sentinel.
const NO_IDX: u32 = u32::MAX;

// ======================================================================
// BusDevice
// ======================================================================

/// A device registered on a bus.
#[derive(Debug, Clone, Copy)]
pub struct BusDevice {
    /// Device ID.
    id: u32,
    /// Device name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Bound driver index (NO_IDX if unbound).
    driver_idx: u32,
    /// Bus index.
    bus_idx: u32,
    /// Whether this slot is active.
    active: bool,
    /// Vendor ID (for matching).
    vendor_id: u32,
    /// Device class ID (for matching).
    class_id: u32,
}

impl BusDevice {
    /// Creates a new empty device.
    pub const fn new() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            driver_idx: NO_IDX,
            bus_idx: NO_IDX,
            active: false,
            vendor_id: 0,
            class_id: 0,
        }
    }

    /// Returns the device ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Returns the device name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the bound driver index.
    pub fn driver_idx(&self) -> u32 {
        self.driver_idx
    }

    /// Returns the bus index.
    pub fn bus_idx(&self) -> u32 {
        self.bus_idx
    }

    /// Returns whether active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the vendor ID.
    pub fn vendor_id(&self) -> u32 {
        self.vendor_id
    }

    /// Returns the class ID.
    pub fn class_id(&self) -> u32 {
        self.class_id
    }
}

// ======================================================================
// BusDriver
// ======================================================================

/// A driver registered on a bus.
#[derive(Debug, Clone, Copy)]
pub struct BusDriver {
    /// Driver ID.
    id: u32,
    /// Driver name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Bus index.
    bus_idx: u32,
    /// Whether active.
    active: bool,
    /// Supported vendor ID (0 = any).
    supported_vendor: u32,
    /// Supported class ID (0 = any).
    supported_class: u32,
}

impl BusDriver {
    /// Creates a new empty driver.
    pub const fn new() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            bus_idx: NO_IDX,
            active: false,
            supported_vendor: 0,
            supported_class: 0,
        }
    }

    /// Returns the driver ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Returns the driver name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns whether active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the supported vendor ID.
    pub fn supported_vendor(&self) -> u32 {
        self.supported_vendor
    }

    /// Returns the supported class ID.
    pub fn supported_class(&self) -> u32 {
        self.supported_class
    }
}

// ======================================================================
// BusType
// ======================================================================

/// A bus type in the device model.
pub struct BusType {
    /// Bus name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Whether registered.
    registered: bool,
    /// Whether allocated.
    allocated: bool,
    /// Device slots.
    devices: [BusDevice; MAX_DEVICES_PER_BUS],
    /// Number of devices.
    device_count: usize,
    /// Driver slots.
    drivers: [BusDriver; MAX_DRIVERS_PER_BUS],
    /// Number of drivers.
    driver_count: usize,
    /// Next device ID.
    next_dev_id: u32,
    /// Next driver ID.
    next_drv_id: u32,
    /// Generation counter.
    generation: u64,
}

impl BusType {
    /// Creates a new empty bus type.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            registered: false,
            allocated: false,
            devices: [const { BusDevice::new() }; MAX_DEVICES_PER_BUS],
            device_count: 0,
            drivers: [const { BusDriver::new() }; MAX_DRIVERS_PER_BUS],
            driver_count: 0,
            next_dev_id: 1,
            next_drv_id: 1,
            generation: 0,
        }
    }

    /// Returns the bus name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns whether registered.
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// Returns the device count.
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    /// Returns the driver count.
    pub fn driver_count(&self) -> usize {
        self.driver_count
    }

    /// Returns the generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

// ======================================================================
// BusManager
// ======================================================================

/// Manages the global bus type registry.
pub struct BusManager {
    /// Bus types.
    buses: [BusType; MAX_BUS_TYPES],
    /// Number of allocated bus types.
    count: usize,
}

impl BusManager {
    /// Creates a new empty manager.
    pub const fn new() -> Self {
        Self {
            buses: [const { BusType::new() }; MAX_BUS_TYPES],
            count: 0,
        }
    }

    /// Registers a new bus type.
    pub fn bus_register(&mut self, name: &[u8]) -> Result<usize> {
        if self.count >= MAX_BUS_TYPES {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .buses
            .iter()
            .position(|b| !b.allocated)
            .ok_or(Error::OutOfMemory)?;
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.buses[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.buses[idx].name_len = copy_len;
        self.buses[idx].allocated = true;
        self.buses[idx].registered = true;
        self.buses[idx].generation += 1;
        self.count += 1;
        Ok(idx)
    }

    /// Unregisters a bus type.
    pub fn bus_unregister(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_BUS_TYPES || !self.buses[idx].allocated {
            return Err(Error::NotFound);
        }
        self.buses[idx] = BusType::new();
        self.count -= 1;
        Ok(())
    }

    /// Adds a device to a bus.
    pub fn bus_add_device(
        &mut self,
        bus_idx: usize,
        name: &[u8],
        vendor_id: u32,
        class_id: u32,
    ) -> Result<u32> {
        if bus_idx >= MAX_BUS_TYPES || !self.buses[bus_idx].allocated {
            return Err(Error::NotFound);
        }
        let dc = self.buses[bus_idx].device_count;
        if dc >= MAX_DEVICES_PER_BUS {
            return Err(Error::OutOfMemory);
        }
        let slot = self.buses[bus_idx].devices[..MAX_DEVICES_PER_BUS]
            .iter()
            .position(|d| !d.active)
            .ok_or(Error::OutOfMemory)?;
        let dev_id = self.buses[bus_idx].next_dev_id;
        self.buses[bus_idx].next_dev_id += 1;
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.buses[bus_idx].devices[slot].id = dev_id;
        self.buses[bus_idx].devices[slot].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.buses[bus_idx].devices[slot].name_len = copy_len;
        self.buses[bus_idx].devices[slot].bus_idx = bus_idx as u32;
        self.buses[bus_idx].devices[slot].vendor_id = vendor_id;
        self.buses[bus_idx].devices[slot].class_id = class_id;
        self.buses[bus_idx].devices[slot].active = true;
        self.buses[bus_idx].device_count += 1;
        self.buses[bus_idx].generation += 1;

        // Try auto-match.
        self.try_match_device(bus_idx, slot);
        Ok(dev_id)
    }

    /// Removes a device from a bus by device ID.
    pub fn bus_remove_device(&mut self, bus_idx: usize, dev_id: u32) -> Result<()> {
        if bus_idx >= MAX_BUS_TYPES || !self.buses[bus_idx].allocated {
            return Err(Error::NotFound);
        }
        let pos = self.buses[bus_idx]
            .devices
            .iter()
            .position(|d| d.active && d.id == dev_id);
        match pos {
            Some(slot) => {
                self.buses[bus_idx].devices[slot] = BusDevice::new();
                self.buses[bus_idx].device_count -= 1;
                self.buses[bus_idx].generation += 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Adds a driver to a bus.
    pub fn bus_add_driver(
        &mut self,
        bus_idx: usize,
        name: &[u8],
        vendor: u32,
        class: u32,
    ) -> Result<u32> {
        if bus_idx >= MAX_BUS_TYPES || !self.buses[bus_idx].allocated {
            return Err(Error::NotFound);
        }
        let dc = self.buses[bus_idx].driver_count;
        if dc >= MAX_DRIVERS_PER_BUS {
            return Err(Error::OutOfMemory);
        }
        let slot = self.buses[bus_idx]
            .drivers
            .iter()
            .position(|d| !d.active)
            .ok_or(Error::OutOfMemory)?;
        let drv_id = self.buses[bus_idx].next_drv_id;
        self.buses[bus_idx].next_drv_id += 1;
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.buses[bus_idx].drivers[slot].id = drv_id;
        self.buses[bus_idx].drivers[slot].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.buses[bus_idx].drivers[slot].name_len = copy_len;
        self.buses[bus_idx].drivers[slot].bus_idx = bus_idx as u32;
        self.buses[bus_idx].drivers[slot].supported_vendor = vendor;
        self.buses[bus_idx].drivers[slot].supported_class = class;
        self.buses[bus_idx].drivers[slot].active = true;
        self.buses[bus_idx].driver_count += 1;
        self.buses[bus_idx].generation += 1;
        Ok(drv_id)
    }

    /// Removes a driver from a bus by driver ID.
    pub fn bus_remove_driver(&mut self, bus_idx: usize, drv_id: u32) -> Result<()> {
        if bus_idx >= MAX_BUS_TYPES || !self.buses[bus_idx].allocated {
            return Err(Error::NotFound);
        }
        let pos = self.buses[bus_idx]
            .drivers
            .iter()
            .position(|d| d.active && d.id == drv_id);
        match pos {
            Some(slot) => {
                self.buses[bus_idx].drivers[slot] = BusDriver::new();
                self.buses[bus_idx].driver_count -= 1;
                self.buses[bus_idx].generation += 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Iterates over all devices on a bus.
    ///
    /// Returns device IDs into `out`.
    pub fn bus_for_each_dev(&self, bus_idx: usize, out: &mut [u32]) -> Result<usize> {
        if bus_idx >= MAX_BUS_TYPES || !self.buses[bus_idx].allocated {
            return Err(Error::NotFound);
        }
        let mut collected = 0;
        for dev in &self.buses[bus_idx].devices {
            if dev.active && collected < out.len() {
                out[collected] = dev.id;
                collected += 1;
            }
        }
        Ok(collected)
    }

    /// Iterates over all drivers on a bus.
    pub fn bus_for_each_drv(&self, bus_idx: usize, out: &mut [u32]) -> Result<usize> {
        if bus_idx >= MAX_BUS_TYPES || !self.buses[bus_idx].allocated {
            return Err(Error::NotFound);
        }
        let mut collected = 0;
        for drv in &self.buses[bus_idx].drivers {
            if drv.active && collected < out.len() {
                out[collected] = drv.id;
                collected += 1;
            }
        }
        Ok(collected)
    }

    /// Returns a reference to a bus type.
    pub fn get(&self, idx: usize) -> Result<&BusType> {
        if idx >= MAX_BUS_TYPES || !self.buses[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.buses[idx])
    }

    /// Returns the number of registered buses.
    pub fn count(&self) -> usize {
        self.count
    }

    // ------------------------------------------------------------------
    // Internal: auto-match
    // ------------------------------------------------------------------

    /// Tries to match a device with a driver on the same bus.
    fn try_match_device(&mut self, bus_idx: usize, dev_slot: usize) {
        let vendor = self.buses[bus_idx].devices[dev_slot].vendor_id;
        let class = self.buses[bus_idx].devices[dev_slot].class_id;

        for i in 0..MAX_DRIVERS_PER_BUS {
            if !self.buses[bus_idx].drivers[i].active {
                continue;
            }
            let drv_vendor = self.buses[bus_idx].drivers[i].supported_vendor;
            let drv_class = self.buses[bus_idx].drivers[i].supported_class;
            let vendor_match = drv_vendor == 0 || drv_vendor == vendor;
            let class_match = drv_class == 0 || drv_class == class;
            if vendor_match && class_match {
                self.buses[bus_idx].devices[dev_slot].driver_idx = i as u32;
                return;
            }
        }
    }
}
