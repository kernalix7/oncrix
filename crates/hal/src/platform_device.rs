// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Platform device registration framework.
//!
//! Provides a platform bus device model for registering non-discoverable
//! devices (those not found via PCI/USB enumeration) with resource
//! descriptors for MMIO regions, IRQ lines, DMA channels, and I/O ports.
//! Devices are typically described by firmware tables (ACPI, device tree)
//! or hard-coded board configurations.
//!
//! # Architecture
//!
//! - [`ResourceType`] -- classification of a hardware resource.
//! - [`DeviceResource`] -- a single MMIO, IRQ, DMA, or I/O port resource.
//! - [`PlatformDevice`] -- a non-discoverable device with its resources
//!   and compatible string for driver matching.
//! - [`PlatformDriver`] -- a driver descriptor with a compatible-string
//!   table for device-tree style matching.
//! - [`PlatformDeviceRegistry`] -- manages device and driver registration,
//!   matching, probe/remove lifecycle, and power management.
//!
//! This module complements [`crate::platform_dev`] by providing a
//! lighter-weight registration path focused on resource descriptors
//! and driver matching rather than full bus semantics.
//!
//! Reference: Linux `drivers/base/platform.c`,
//!            `include/linux/platform_device.h`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of resources per device.
const MAX_RESOURCES: usize = 8;

/// Maximum number of platform devices in the registry.
const MAX_DEVICES: usize = 32;

/// Maximum number of platform drivers in the registry.
const MAX_DRIVERS: usize = 16;

/// Maximum number of compatible strings per driver.
const MAX_COMPAT: usize = 4;

/// Maximum length of a name or compatible string.
const MAX_NAME_LEN: usize = 32;

/// Maximum platform data size in bytes.
const MAX_PLAT_DATA: usize = 64;

// ---------------------------------------------------------------------------
// ResourceType
// ---------------------------------------------------------------------------

/// Type of a platform device resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResourceType {
    /// Memory-mapped I/O region.
    #[default]
    Mmio,
    /// I/O port region (x86-specific legacy).
    IoPort,
    /// Interrupt line (IRQ number).
    Irq,
    /// DMA channel identifier.
    Dma,
    /// Clock source reference (index into the clock tree).
    Clock,
    /// GPIO pin reference.
    Gpio,
}

// ---------------------------------------------------------------------------
// DeviceResource
// ---------------------------------------------------------------------------

/// A single hardware resource associated with a platform device.
///
/// Resources describe the physical hardware backing of a device:
/// MMIO regions, interrupt lines, DMA channels, etc.
#[derive(Debug, Clone, Copy)]
pub struct DeviceResource {
    /// Type of this resource.
    pub resource_type: ResourceType,
    /// Start address or identifier.
    pub start: u64,
    /// End address (inclusive) for regions, same as start for scalars.
    pub end: u64,
    /// Additional flags (resource-type-specific).
    pub flags: u32,
    /// Resource index within the device (for ordered lookup).
    pub index: u32,
}

/// Constant empty resource for array initialisation.
const EMPTY_RESOURCE: DeviceResource = DeviceResource {
    resource_type: ResourceType::Mmio,
    start: 0,
    end: 0,
    flags: 0,
    index: 0,
};

impl DeviceResource {
    /// Creates an MMIO resource.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `end < start`.
    pub fn mmio(start: u64, end: u64, flags: u32) -> Result<Self> {
        if end < start {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            resource_type: ResourceType::Mmio,
            start,
            end,
            flags,
            index: 0,
        })
    }

    /// Creates an I/O port resource.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `end < start`.
    pub fn io_port(start: u64, end: u64, flags: u32) -> Result<Self> {
        if end < start {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            resource_type: ResourceType::IoPort,
            start,
            end,
            flags,
            index: 0,
        })
    }

    /// Creates an IRQ resource.
    pub fn irq(irq_num: u32, flags: u32) -> Self {
        Self {
            resource_type: ResourceType::Irq,
            start: u64::from(irq_num),
            end: u64::from(irq_num),
            flags,
            index: 0,
        }
    }

    /// Creates a DMA channel resource.
    pub fn dma(channel: u32, flags: u32) -> Self {
        Self {
            resource_type: ResourceType::Dma,
            start: u64::from(channel),
            end: u64::from(channel),
            flags,
            index: 0,
        }
    }

    /// Creates a clock reference resource.
    pub fn clock(clock_id: u32, flags: u32) -> Self {
        Self {
            resource_type: ResourceType::Clock,
            start: u64::from(clock_id),
            end: u64::from(clock_id),
            flags,
            index: 0,
        }
    }

    /// Creates a GPIO reference resource.
    pub fn gpio(gpio_num: u32, flags: u32) -> Self {
        Self {
            resource_type: ResourceType::Gpio,
            start: u64::from(gpio_num),
            end: u64::from(gpio_num),
            flags,
            index: 0,
        }
    }

    /// Returns the size of the resource region in bytes.
    ///
    /// For single-value resources (IRQ, DMA) this returns 1.
    pub fn size(&self) -> u64 {
        self.end - self.start + 1
    }
}

// ---------------------------------------------------------------------------
// NameBuf (local)
// ---------------------------------------------------------------------------

/// Fixed-size name buffer.
#[derive(Clone, Copy)]
struct NameBuf {
    bytes: [u8; MAX_NAME_LEN],
    len: usize,
}

impl NameBuf {
    const fn empty() -> Self {
        Self {
            bytes: [0u8; MAX_NAME_LEN],
            len: 0,
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        let b = s.as_bytes();
        if b.is_empty() || b.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_NAME_LEN];
        buf[..b.len()].copy_from_slice(b);
        Ok(Self {
            bytes: buf,
            len: b.len(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn matches(&self, other: &str) -> bool {
        self.as_bytes() == other.as_bytes()
    }

    fn matches_buf(&self, other: &NameBuf) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl core::fmt::Debug for NameBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Ok(s) = core::str::from_utf8(self.as_bytes()) {
            write!(f, "\"{}\"", s)
        } else {
            write!(f, "{:?}", self.as_bytes())
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceState
// ---------------------------------------------------------------------------

/// Lifecycle state of a platform device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceState {
    /// Registered but no driver bound.
    #[default]
    Unbound,
    /// Driver probe is in progress.
    Probing,
    /// Bound to a driver and operational.
    Bound,
    /// Suspended (low-power state).
    Suspended,
    /// Error state (probe failed or runtime fault).
    Error,
}

// ---------------------------------------------------------------------------
// PlatformDevice
// ---------------------------------------------------------------------------

/// A non-discoverable device on the platform bus.
///
/// Each device carries an array of hardware resources and a
/// compatible string for matching against registered drivers.
pub struct PlatformDevice {
    /// Unique device identifier.
    pub id: u32,
    /// Human-readable device name.
    name: NameBuf,
    /// Compatible string for driver matching.
    compatible: NameBuf,
    /// Hardware resources (MMIO, IRQ, DMA, etc.).
    resources: [DeviceResource; MAX_RESOURCES],
    /// Number of valid resources.
    resource_count: usize,
    /// Current lifecycle state.
    pub state: DeviceState,
    /// ID of the bound driver (0 = none).
    pub driver_id: u32,
    /// Opaque platform-specific data.
    plat_data: [u8; MAX_PLAT_DATA],
    /// Length of valid bytes in `plat_data`.
    plat_data_len: usize,
    /// Whether this device is active.
    pub active: bool,
}

/// Constant empty device for array initialisation.
const EMPTY_DEVICE: PlatformDevice = PlatformDevice {
    id: 0,
    name: NameBuf {
        bytes: [0u8; MAX_NAME_LEN],
        len: 0,
    },
    compatible: NameBuf {
        bytes: [0u8; MAX_NAME_LEN],
        len: 0,
    },
    resources: [EMPTY_RESOURCE; MAX_RESOURCES],
    resource_count: 0,
    state: DeviceState::Unbound,
    driver_id: 0,
    plat_data: [0u8; MAX_PLAT_DATA],
    plat_data_len: 0,
    active: false,
};

impl PlatformDevice {
    /// Creates a new platform device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` or `compatible`
    /// are empty or exceed the maximum length.
    pub fn new(id: u32, name: &str, compatible: &str) -> Result<Self> {
        let mut dev = EMPTY_DEVICE;
        dev.id = id;
        dev.name = NameBuf::from_str(name)?;
        dev.compatible = NameBuf::from_str(compatible)?;
        dev.active = true;
        Ok(dev)
    }

    /// Returns the device name as a byte slice.
    pub fn name(&self) -> &[u8] {
        self.name.as_bytes()
    }

    /// Returns the compatible string as a byte slice.
    pub fn compatible(&self) -> &[u8] {
        self.compatible.as_bytes()
    }

    /// Adds a hardware resource to this device.
    ///
    /// The resource index is set automatically based on insertion order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the resource array is full.
    pub fn add_resource(&mut self, mut resource: DeviceResource) -> Result<()> {
        if self.resource_count >= MAX_RESOURCES {
            return Err(Error::OutOfMemory);
        }
        resource.index = self.resource_count as u32;
        self.resources[self.resource_count] = resource;
        self.resource_count += 1;
        Ok(())
    }

    /// Returns the slice of hardware resources.
    pub fn resources(&self) -> &[DeviceResource] {
        &self.resources[..self.resource_count]
    }

    /// Returns the first resource of the given type, if any.
    pub fn resource_by_type(&self, rtype: ResourceType) -> Option<&DeviceResource> {
        self.resources().iter().find(|r| r.resource_type == rtype)
    }

    /// Returns the Nth resource of the given type, if any.
    pub fn resource_by_type_index(&self, rtype: ResourceType, n: usize) -> Option<&DeviceResource> {
        self.resources()
            .iter()
            .filter(|r| r.resource_type == rtype)
            .nth(n)
    }

    /// Returns the number of resources.
    pub fn resource_count(&self) -> usize {
        self.resource_count
    }

    /// Sets opaque platform data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` exceeds the
    /// maximum size.
    pub fn set_platform_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_PLAT_DATA {
            return Err(Error::InvalidArgument);
        }
        self.plat_data[..data.len()].copy_from_slice(data);
        self.plat_data_len = data.len();
        Ok(())
    }

    /// Returns the platform data, or an empty slice if none.
    pub fn platform_data(&self) -> &[u8] {
        &self.plat_data[..self.plat_data_len]
    }
}

// ---------------------------------------------------------------------------
// PlatformDriver
// ---------------------------------------------------------------------------

/// A driver that binds to platform devices via name or compatible
/// string matching.
pub struct PlatformDriver {
    /// Unique driver identifier.
    pub id: u32,
    /// Driver name.
    name: NameBuf,
    /// Compatible-string table for matching.
    compat_table: [NameBuf; MAX_COMPAT],
    /// Number of valid entries in `compat_table`.
    compat_count: usize,
    /// Whether this driver supports suspend/resume.
    pub supports_pm: bool,
    /// Number of devices currently bound.
    pub bound_count: u32,
}

/// Constant empty driver for array initialisation.
const EMPTY_DRIVER: PlatformDriver = PlatformDriver {
    id: 0,
    name: NameBuf {
        bytes: [0u8; MAX_NAME_LEN],
        len: 0,
    },
    compat_table: [NameBuf {
        bytes: [0u8; MAX_NAME_LEN],
        len: 0,
    }; MAX_COMPAT],
    compat_count: 0,
    supports_pm: false,
    bound_count: 0,
};

impl PlatformDriver {
    /// Creates a new platform driver.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is invalid.
    pub fn new(id: u32, name: &str) -> Result<Self> {
        let mut drv = EMPTY_DRIVER;
        drv.id = id;
        drv.name = NameBuf::from_str(name)?;
        Ok(drv)
    }

    /// Returns the driver name as a byte slice.
    pub fn name(&self) -> &[u8] {
        self.name.as_bytes()
    }

    /// Adds a compatible string to the match table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full, or
    /// [`Error::InvalidArgument`] if the string is invalid.
    pub fn add_compatible(&mut self, compat: &str) -> Result<()> {
        if self.compat_count >= MAX_COMPAT {
            return Err(Error::OutOfMemory);
        }
        self.compat_table[self.compat_count] = NameBuf::from_str(compat)?;
        self.compat_count += 1;
        Ok(())
    }

    /// Checks whether this driver matches a device.
    ///
    /// Matching is attempted first by name, then by compatible string.
    pub fn matches_device(&self, device: &PlatformDevice) -> bool {
        // Name-based matching.
        if !self.name.as_bytes().is_empty() && self.name.matches_buf(&device.name) {
            return true;
        }
        // Compatible-string matching.
        let dev_compat = &device.compatible;
        if dev_compat.as_bytes().is_empty() {
            return false;
        }
        self.compat_table[..self.compat_count]
            .iter()
            .any(|c| c.matches_buf(dev_compat))
    }
}

// ---------------------------------------------------------------------------
// PlatformDeviceRegistry
// ---------------------------------------------------------------------------

/// Registry for platform devices and drivers.
///
/// Manages registration, matching, probe/remove lifecycle, and
/// power management transitions for non-discoverable devices.
pub struct PlatformDeviceRegistry {
    /// Registered devices.
    devices: [PlatformDevice; MAX_DEVICES],
    /// Number of registered devices.
    device_count: usize,
    /// Registered drivers.
    drivers: [PlatformDriver; MAX_DRIVERS],
    /// Number of registered drivers.
    driver_count: usize,
}

impl PlatformDeviceRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [EMPTY_DEVICE; MAX_DEVICES],
            device_count: 0,
            drivers: [EMPTY_DRIVER; MAX_DRIVERS],
            driver_count: 0,
        }
    }

    /// Registers a platform device.
    ///
    /// After registration, attempts to match and probe the device
    /// with an existing driver.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if a device with the same
    /// ID exists, or [`Error::OutOfMemory`] if the array is full.
    pub fn register_device(&mut self, device: PlatformDevice) -> Result<()> {
        for d in &self.devices[..self.device_count] {
            if d.id == device.id && d.active {
                return Err(Error::AlreadyExists);
            }
        }
        if self.device_count >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.device_count;
        self.devices[idx] = device;
        self.device_count += 1;

        // Auto-match with existing drivers.
        let dev = &self.devices[idx];
        let mut matched_drv_id = None;
        for drv in &self.drivers[..self.driver_count] {
            if drv.matches_device(dev) {
                matched_drv_id = Some(drv.id);
                break;
            }
        }
        if let Some(drv_id) = matched_drv_id {
            let _ = self.probe_device(self.devices[idx].id, drv_id);
        }
        Ok(())
    }

    /// Unregisters a platform device by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the device does not exist.
    pub fn unregister_device(&mut self, device_id: u32) -> Result<()> {
        let idx = self.device_index(device_id)?;
        // Unbind from driver if bound.
        if self.devices[idx].driver_id != 0 {
            let _ = self.remove_device(device_id);
        }
        // Compact the array.
        let last = self.device_count - 1;
        if idx != last {
            self.devices.swap(idx, last);
        }
        self.devices[last] = EMPTY_DEVICE;
        self.device_count -= 1;
        Ok(())
    }

    /// Returns a reference to a device by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get_device(&self, device_id: u32) -> Result<&PlatformDevice> {
        let idx = self.device_index(device_id)?;
        Ok(&self.devices[idx])
    }

    /// Registers a platform driver.
    ///
    /// After registration, attempts to match and probe all unbound
    /// devices.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if a driver with the same
    /// ID exists, or [`Error::OutOfMemory`] if the array is full.
    pub fn register_driver(&mut self, driver: PlatformDriver) -> Result<()> {
        for d in &self.drivers[..self.driver_count] {
            if d.id == driver.id {
                return Err(Error::AlreadyExists);
            }
        }
        if self.driver_count >= MAX_DRIVERS {
            return Err(Error::OutOfMemory);
        }
        let drv_id = driver.id;
        self.drivers[self.driver_count] = driver;
        self.driver_count += 1;

        // Probe unbound devices that match.
        let mut to_probe = [0u32; MAX_DEVICES];
        let mut probe_count = 0;
        let drv = &self.drivers[self.driver_count - 1];
        for dev in &self.devices[..self.device_count] {
            if dev.state == DeviceState::Unbound && drv.matches_device(dev) {
                to_probe[probe_count] = dev.id;
                probe_count += 1;
            }
        }
        for &dev_id in &to_probe[..probe_count] {
            let _ = self.probe_device(dev_id, drv_id);
        }
        Ok(())
    }

    /// Unregisters a platform driver by ID.
    ///
    /// All devices bound to this driver are unbound first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the driver does not exist.
    pub fn unregister_driver(&mut self, driver_id: u32) -> Result<()> {
        let idx = self.driver_index(driver_id)?;
        // Unbind all devices bound to this driver.
        let mut to_remove = [0u32; MAX_DEVICES];
        let mut count = 0;
        for dev in &self.devices[..self.device_count] {
            if dev.driver_id == driver_id {
                to_remove[count] = dev.id;
                count += 1;
            }
        }
        for &dev_id in &to_remove[..count] {
            let _ = self.remove_device(dev_id);
        }
        // Compact the driver array.
        let last = self.driver_count - 1;
        if idx != last {
            self.drivers.swap(idx, last);
        }
        self.drivers[last] = EMPTY_DRIVER;
        self.driver_count -= 1;
        Ok(())
    }

    /// Probes a device with the specified driver.
    ///
    /// # Errors
    ///
    /// Returns errors if the device/driver is not found, device is
    /// already bound, or the driver does not match.
    pub fn probe_device(&mut self, device_id: u32, driver_id: u32) -> Result<()> {
        let didx = self.device_index(device_id)?;
        let dridx = self.driver_index(driver_id)?;

        if self.devices[didx].state == DeviceState::Bound {
            return Err(Error::Busy);
        }
        if !self.drivers[dridx].matches_device(&self.devices[didx]) {
            return Err(Error::IoError);
        }

        self.devices[didx].state = DeviceState::Probing;
        self.devices[didx].driver_id = driver_id;
        self.devices[didx].state = DeviceState::Bound;
        self.drivers[dridx].bound_count += 1;
        Ok(())
    }

    /// Removes (unbinds) a device from its driver.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] or [`Error::InvalidArgument`].
    pub fn remove_device(&mut self, device_id: u32) -> Result<()> {
        let didx = self.device_index(device_id)?;
        let drv_id = self.devices[didx].driver_id;
        if drv_id == 0 {
            return Err(Error::InvalidArgument);
        }
        if let Ok(dridx) = self.driver_index(drv_id) {
            if self.drivers[dridx].bound_count > 0 {
                self.drivers[dridx].bound_count -= 1;
            }
        }
        self.devices[didx].state = DeviceState::Unbound;
        self.devices[didx].driver_id = 0;
        Ok(())
    }

    /// Suspends a bound device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the device is not bound.
    pub fn suspend_device(&mut self, device_id: u32) -> Result<()> {
        let idx = self.device_index(device_id)?;
        if self.devices[idx].state != DeviceState::Bound {
            return Err(Error::InvalidArgument);
        }
        self.devices[idx].state = DeviceState::Suspended;
        Ok(())
    }

    /// Resumes a suspended device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the device is not suspended.
    pub fn resume_device(&mut self, device_id: u32) -> Result<()> {
        let idx = self.device_index(device_id)?;
        if self.devices[idx].state != DeviceState::Suspended {
            return Err(Error::InvalidArgument);
        }
        self.devices[idx].state = DeviceState::Bound;
        Ok(())
    }

    /// Finds a device by compatible string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching device exists.
    pub fn find_by_compatible(&self, compat: &str) -> Result<&PlatformDevice> {
        self.devices[..self.device_count]
            .iter()
            .find(|d| d.active && d.compatible.matches(compat))
            .ok_or(Error::NotFound)
    }

    /// Finds a device by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching device exists.
    pub fn find_by_name(&self, name: &str) -> Result<&PlatformDevice> {
        self.devices[..self.device_count]
            .iter()
            .find(|d| d.active && d.name.matches(name))
            .ok_or(Error::NotFound)
    }

    /// Returns the number of registered devices.
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    /// Returns the number of registered drivers.
    pub fn driver_count(&self) -> usize {
        self.driver_count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.device_count == 0
    }

    // -- internal ---------------------------------------------------------

    fn device_index(&self, id: u32) -> Result<usize> {
        self.devices[..self.device_count]
            .iter()
            .position(|d| d.id == id && d.active)
            .ok_or(Error::NotFound)
    }

    fn driver_index(&self, id: u32) -> Result<usize> {
        self.drivers[..self.driver_count]
            .iter()
            .position(|d| d.id == id)
            .ok_or(Error::NotFound)
    }
}

impl Default for PlatformDeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}
