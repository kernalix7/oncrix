// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Device class management.
//!
//! A device class groups devices that share a common user-space
//! interface (e.g. "input", "net", "block", "tty"). Classes
//! provide devnode naming, permission control, and release
//! callbacks.
//!
//! # Design
//!
//! ```text
//!   DeviceClass
//!   +------------------+
//!   | name             |
//!   | dev_major        |  (major device number)
//!   | devnode_prefix   |  (e.g. "/dev/input/")
//!   | devices[]        |  registered devices
//!   +------------------+
//! ```
//!
//! # Lifecycle
//!
//! 1. `class_create()` — register a new class.
//! 2. `class_register()` — make visible to sysfs.
//! 3. `class_find_device()` — lookup a device.
//! 4. `class_for_each_device()` — iterate over devices.
//! 5. `class_destroy()` — tear down.
//!
//! # Reference
//!
//! Linux `drivers/base/class.c`,
//! `include/linux/device/class.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum device classes.
const MAX_CLASSES: usize = 64;

/// Maximum devices per class.
const MAX_DEVICES_PER_CLASS: usize = 128;

/// Maximum name length.
const MAX_NAME_LEN: usize = 32;

// ======================================================================
// ClassDevice
// ======================================================================

/// A device registered in a class.
#[derive(Debug, Clone, Copy)]
pub struct ClassDevice {
    /// Device ID.
    dev_id: u32,
    /// Device name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Minor device number.
    minor: u32,
    /// Whether active.
    active: bool,
    /// Kobject index (reference).
    kobj_idx: u32,
    /// Parent device ID (0 = none).
    parent_dev_id: u32,
}

impl ClassDevice {
    /// Creates a new empty class device.
    pub const fn new() -> Self {
        Self {
            dev_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            minor: 0,
            active: false,
            kobj_idx: u32::MAX,
            parent_dev_id: 0,
        }
    }

    /// Returns the device ID.
    pub fn dev_id(&self) -> u32 {
        self.dev_id
    }

    /// Returns the device name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the minor number.
    pub fn minor(&self) -> u32 {
        self.minor
    }

    /// Returns whether active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the parent device ID.
    pub fn parent_dev_id(&self) -> u32 {
        self.parent_dev_id
    }
}

// ======================================================================
// DeviceClass
// ======================================================================

/// A device class.
pub struct DeviceClass {
    /// Class name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Whether registered.
    registered: bool,
    /// Whether allocated.
    allocated: bool,
    /// Major device number.
    dev_major: u32,
    /// Devnode prefix (e.g. "/dev/input/").
    devnode_prefix: [u8; MAX_NAME_LEN],
    /// Devnode prefix length.
    devnode_prefix_len: usize,
    /// Default file permissions.
    default_mode: u32,
    /// Registered devices.
    devices: [ClassDevice; MAX_DEVICES_PER_CLASS],
    /// Number of devices.
    device_count: usize,
    /// Next device ID.
    next_dev_id: u32,
    /// Generation counter.
    generation: u64,
}

impl DeviceClass {
    /// Creates a new empty class.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            registered: false,
            allocated: false,
            dev_major: 0,
            devnode_prefix: [0u8; MAX_NAME_LEN],
            devnode_prefix_len: 0,
            default_mode: 0o660,
            devices: [const { ClassDevice::new() }; MAX_DEVICES_PER_CLASS],
            device_count: 0,
            next_dev_id: 1,
            generation: 0,
        }
    }

    /// Returns the class name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns whether registered.
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// Returns the major device number.
    pub fn dev_major(&self) -> u32 {
        self.dev_major
    }

    /// Returns the device count.
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    /// Returns the default mode.
    pub fn default_mode(&self) -> u32 {
        self.default_mode
    }

    /// Returns the generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

// ======================================================================
// ClassManager
// ======================================================================

/// Manages the global device class registry.
pub struct ClassManager {
    /// Class pool.
    classes: [DeviceClass; MAX_CLASSES],
    /// Number of allocated classes.
    count: usize,
}

impl ClassManager {
    /// Creates a new empty manager.
    pub const fn new() -> Self {
        Self {
            classes: [const { DeviceClass::new() }; MAX_CLASSES],
            count: 0,
        }
    }

    /// Creates a new device class.
    pub fn class_create(&mut self, name: &[u8], major: u32) -> Result<usize> {
        if self.count >= MAX_CLASSES {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .classes
            .iter()
            .position(|c| !c.allocated)
            .ok_or(Error::OutOfMemory)?;
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.classes[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.classes[idx].name_len = copy_len;
        self.classes[idx].dev_major = major;
        self.classes[idx].allocated = true;
        self.count += 1;
        Ok(idx)
    }

    /// Destroys a device class.
    pub fn class_destroy(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_CLASSES || !self.classes[idx].allocated {
            return Err(Error::NotFound);
        }
        self.classes[idx] = DeviceClass::new();
        self.count -= 1;
        Ok(())
    }

    /// Registers a class (makes it visible).
    pub fn class_register(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_CLASSES || !self.classes[idx].allocated {
            return Err(Error::NotFound);
        }
        if self.classes[idx].registered {
            return Err(Error::AlreadyExists);
        }
        self.classes[idx].registered = true;
        self.classes[idx].generation += 1;
        Ok(())
    }

    /// Unregisters a class.
    pub fn class_unregister(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_CLASSES || !self.classes[idx].allocated {
            return Err(Error::NotFound);
        }
        self.classes[idx].registered = false;
        self.classes[idx].generation += 1;
        Ok(())
    }

    /// Adds a device to a class.
    pub fn class_add_device(&mut self, class_idx: usize, name: &[u8], minor: u32) -> Result<u32> {
        if class_idx >= MAX_CLASSES || !self.classes[class_idx].allocated {
            return Err(Error::NotFound);
        }
        if self.classes[class_idx].device_count >= MAX_DEVICES_PER_CLASS {
            return Err(Error::OutOfMemory);
        }
        let slot = self.classes[class_idx]
            .devices
            .iter()
            .position(|d| !d.active)
            .ok_or(Error::OutOfMemory)?;
        let dev_id = self.classes[class_idx].next_dev_id;
        self.classes[class_idx].next_dev_id += 1;
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.classes[class_idx].devices[slot].dev_id = dev_id;
        self.classes[class_idx].devices[slot].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.classes[class_idx].devices[slot].name_len = copy_len;
        self.classes[class_idx].devices[slot].minor = minor;
        self.classes[class_idx].devices[slot].active = true;
        self.classes[class_idx].device_count += 1;
        self.classes[class_idx].generation += 1;
        Ok(dev_id)
    }

    /// Removes a device from a class by device ID.
    pub fn class_remove_device(&mut self, class_idx: usize, dev_id: u32) -> Result<()> {
        if class_idx >= MAX_CLASSES || !self.classes[class_idx].allocated {
            return Err(Error::NotFound);
        }
        let pos = self.classes[class_idx]
            .devices
            .iter()
            .position(|d| d.active && d.dev_id == dev_id);
        match pos {
            Some(slot) => {
                self.classes[class_idx].devices[slot] = ClassDevice::new();
                self.classes[class_idx].device_count -= 1;
                self.classes[class_idx].generation += 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Finds a device by name in a class.
    pub fn class_find_device(&self, class_idx: usize, name: &[u8]) -> Result<u32> {
        if class_idx >= MAX_CLASSES || !self.classes[class_idx].allocated {
            return Err(Error::NotFound);
        }
        for dev in &self.classes[class_idx].devices {
            if dev.active && dev.name_len == name.len() && dev.name[..dev.name_len] == name[..] {
                return Ok(dev.dev_id);
            }
        }
        Err(Error::NotFound)
    }

    /// Iterates over all devices in a class.
    pub fn class_for_each_device(&self, class_idx: usize, out: &mut [u32]) -> Result<usize> {
        if class_idx >= MAX_CLASSES || !self.classes[class_idx].allocated {
            return Err(Error::NotFound);
        }
        let mut collected = 0;
        for dev in &self.classes[class_idx].devices {
            if dev.active && collected < out.len() {
                out[collected] = dev.dev_id;
                collected += 1;
            }
        }
        Ok(collected)
    }

    /// Returns a reference to a class.
    pub fn get(&self, idx: usize) -> Result<&DeviceClass> {
        if idx >= MAX_CLASSES || !self.classes[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.classes[idx])
    }

    /// Returns the number of allocated classes.
    pub fn count(&self) -> usize {
        self.count
    }
}
