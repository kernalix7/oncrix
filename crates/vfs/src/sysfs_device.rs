// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! sysfs device representation.
//!
//! Each device registered with the kernel is represented in sysfs under
//! `/sys/devices/<bus>/<name>/`. The device directory contains standard
//! attribute files and may contain subdirectories for power management,
//! driver links, and bus-specific attributes.
//!
//! # Design
//!
//! - [`DeviceAttr`] — a single sysfs attribute (name + string value)
//! - [`DeviceSysfs`] — device directory with standard attributes
//! - `sysfs_create_device_files` — populate a device's attribute set
//! - `sysfs_remove_device_files` — tear down a device's attribute set
//!
//! # References
//!
//! - Linux `drivers/base/core.c`
//! - Linux `lib/kobject.c`, `fs/sysfs/`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of a sysfs attribute name.
const ATTR_NAME_LEN: usize = 64;

/// Maximum length of a sysfs attribute value.
const ATTR_VALUE_LEN: usize = 256;

/// Maximum number of attributes per device.
const MAX_DEVICE_ATTRS: usize = 16;

/// Maximum device name length.
const DEVICE_NAME_LEN: usize = 64;

/// Maximum subsystem name length.
const SUBSYSTEM_NAME_LEN: usize = 32;

// ---------------------------------------------------------------------------
// DeviceAttr
// ---------------------------------------------------------------------------

/// A single sysfs attribute file for a device.
#[derive(Clone, Debug)]
pub struct DeviceAttr {
    /// Attribute file name (e.g., `"uevent"`, `"power/control"`).
    pub name: [u8; ATTR_NAME_LEN],
    /// Current string value (NUL-terminated).
    pub value: [u8; ATTR_VALUE_LEN],
    /// Number of valid bytes in `name`.
    pub name_len: usize,
    /// Number of valid bytes in `value`.
    pub value_len: usize,
    /// POSIX mode bits for this attribute file.
    pub mode: u16,
    /// Whether this slot is populated.
    pub active: bool,
}

impl DeviceAttr {
    const fn empty() -> Self {
        Self {
            name: [0u8; ATTR_NAME_LEN],
            value: [0u8; ATTR_VALUE_LEN],
            name_len: 0,
            value_len: 0,
            mode: 0o444,
            active: false,
        }
    }

    /// Return the attribute name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the attribute value as a byte slice.
    pub fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_len]
    }

    /// Set the attribute value from `src`.
    ///
    /// Returns `Err(InvalidArgument)` if `src` is longer than `ATTR_VALUE_LEN`.
    pub fn set_value(&mut self, src: &[u8]) -> Result<()> {
        if src.len() > ATTR_VALUE_LEN {
            return Err(Error::InvalidArgument);
        }
        self.value[..src.len()].copy_from_slice(src);
        self.value_len = src.len();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DeviceSysfs
// ---------------------------------------------------------------------------

/// sysfs representation of a kernel device.
///
/// Mirrors the `/sys/devices/<bus>/<name>/` directory with its standard
/// attribute files.
pub struct DeviceSysfs {
    /// Device name (e.g., `"eth0"`, `"sda"`).
    pub name: [u8; DEVICE_NAME_LEN],
    /// Length of `name`.
    pub name_len: usize,
    /// Subsystem this device belongs to (e.g., `"net"`, `"block"`).
    pub subsystem: [u8; SUBSYSTEM_NAME_LEN],
    /// Length of `subsystem`.
    pub subsystem_len: usize,
    /// Driver name bound to this device (empty if unbound).
    pub driver: [u8; SUBSYSTEM_NAME_LEN],
    /// Length of `driver`.
    pub driver_len: usize,
    /// Power management control value (`"auto"` or `"on"`).
    pub power_control: [u8; 8],
    /// Length of `power_control`.
    pub power_control_len: usize,
    /// Device-specific attributes.
    attrs: [DeviceAttr; MAX_DEVICE_ATTRS],
    /// Number of active attrs.
    attr_count: usize,
    /// Whether this device is currently registered in sysfs.
    pub registered: bool,
}

impl DeviceSysfs {
    /// Create an empty `DeviceSysfs`.
    pub const fn new() -> Self {
        Self {
            name: [0u8; DEVICE_NAME_LEN],
            name_len: 0,
            subsystem: [0u8; SUBSYSTEM_NAME_LEN],
            subsystem_len: 0,
            driver: [0u8; SUBSYSTEM_NAME_LEN],
            driver_len: 0,
            power_control: [b'a', b'u', b't', b'o', 0, 0, 0, 0],
            power_control_len: 4,
            attrs: [const { DeviceAttr::empty() }; MAX_DEVICE_ATTRS],
            attr_count: 0,
            registered: false,
        }
    }

    /// Set the device name from a byte slice.
    pub fn set_name(&mut self, name: &[u8]) -> Result<()> {
        if name.len() > DEVICE_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len();
        Ok(())
    }

    /// Set the subsystem name.
    pub fn set_subsystem(&mut self, subsystem: &[u8]) -> Result<()> {
        if subsystem.len() > SUBSYSTEM_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.subsystem[..subsystem.len()].copy_from_slice(subsystem);
        self.subsystem_len = subsystem.len();
        Ok(())
    }

    /// Bind a driver to this device.
    pub fn set_driver(&mut self, driver: &[u8]) -> Result<()> {
        if driver.len() > SUBSYSTEM_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.driver[..driver.len()].copy_from_slice(driver);
        self.driver_len = driver.len();
        Ok(())
    }

    /// Add a device-specific attribute.
    ///
    /// Returns `Err(OutOfMemory)` if the attribute table is full.
    pub fn add_attr(&mut self, name: &[u8], value: &[u8], mode: u16) -> Result<()> {
        if name.len() > ATTR_NAME_LEN || value.len() > ATTR_VALUE_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.attr_count >= MAX_DEVICE_ATTRS {
            return Err(Error::OutOfMemory);
        }
        let slot = &mut self.attrs[self.attr_count];
        slot.name[..name.len()].copy_from_slice(name);
        slot.name_len = name.len();
        slot.set_value(value)?;
        slot.mode = mode;
        slot.active = true;
        self.attr_count += 1;
        Ok(())
    }

    /// Read the value of the attribute named `name`.
    ///
    /// Returns the value bytes or `Err(NotFound)`.
    pub fn read_attr(&self, name: &[u8]) -> Result<&[u8]> {
        for a in &self.attrs[..self.attr_count] {
            if a.active && a.name_bytes() == name {
                return Ok(a.value_bytes());
            }
        }
        Err(Error::NotFound)
    }

    /// Write `value` to the attribute named `name`.
    ///
    /// Returns `Err(NotFound)` if the attribute does not exist.
    /// Returns `Err(PermissionDenied)` if the attribute is read-only.
    pub fn write_attr(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        for a in &mut self.attrs[..self.attr_count] {
            if a.active && a.name_bytes() == name {
                if a.mode & 0o200 == 0 {
                    return Err(Error::PermissionDenied);
                }
                return a.set_value(value);
            }
        }
        Err(Error::NotFound)
    }

    /// Return the device name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the attribute count.
    pub fn attr_count(&self) -> usize {
        self.attr_count
    }
}

// ---------------------------------------------------------------------------
// Registration helpers
// ---------------------------------------------------------------------------

/// Populate the standard sysfs attribute files for a device.
///
/// Creates the following files:
/// - `uevent` (0o200): write-only, triggers udev events
/// - `subsystem` (0o444): read-only, subsystem name
/// - `driver` (0o444): read-only, bound driver or empty
/// - `power/control` (0o644): power management control
pub fn sysfs_create_device_files(dev: &mut DeviceSysfs) -> Result<()> {
    dev.add_attr(b"uevent", b"", 0o200)?;

    let subsystem = {
        let mut tmp = [0u8; SUBSYSTEM_NAME_LEN];
        let len = dev.subsystem_len;
        tmp[..len].copy_from_slice(&dev.subsystem[..len]);
        (tmp, len)
    };
    dev.add_attr(b"subsystem", &subsystem.0[..subsystem.1], 0o444)?;

    let driver = {
        let mut tmp = [0u8; SUBSYSTEM_NAME_LEN];
        let len = dev.driver_len;
        tmp[..len].copy_from_slice(&dev.driver[..len]);
        (tmp, len)
    };
    dev.add_attr(b"driver", &driver.0[..driver.1], 0o444)?;

    let power_control = {
        let mut tmp = [0u8; 8];
        let len = dev.power_control_len;
        tmp[..len].copy_from_slice(&dev.power_control[..len]);
        (tmp, len)
    };
    dev.add_attr(b"power/control", &power_control.0[..power_control.1], 0o644)?;

    dev.registered = true;
    Ok(())
}

/// Remove all sysfs attribute files from a device.
///
/// Marks all attribute slots as inactive and sets `registered = false`.
pub fn sysfs_remove_device_files(dev: &mut DeviceSysfs) {
    for a in &mut dev.attrs {
        *a = DeviceAttr::empty();
    }
    dev.attr_count = 0;
    dev.registered = false;
}
