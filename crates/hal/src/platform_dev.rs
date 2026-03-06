// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Platform device model for the ONCRIX kernel.
//!
//! Provides a Linux-style platform bus abstraction for devices that are
//! not discoverable via standard enumeration protocols (PCI, USB).
//! Platform devices are typically described by firmware tables (ACPI,
//! device tree) or hard-coded board files.
//!
//! # Architecture
//!
//! - [`PlatformResource`] — a single hardware resource (memory region,
//!   IRQ line, or DMA channel) owned by a device.
//! - [`PlatformDevice`] — a device on the platform bus with resources,
//!   a compatible string for driver matching, and optional platform data.
//! - [`PlatformDriver`] — a driver that binds to platform devices by
//!   name or compatible-string matching.
//! - [`PlatformBus`] — the bus that holds registered devices and
//!   drivers, performs matching, and invokes probe/remove callbacks.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of resources per platform device.
const MAX_RESOURCES: usize = 8;

/// Maximum number of platform devices in the bus.
const MAX_DEVICES: usize = 32;

/// Maximum number of platform drivers in the bus.
const MAX_DRIVERS: usize = 16;

/// Maximum number of compatible strings per driver.
const MAX_COMPAT_STRINGS: usize = 4;

/// Maximum length of a device or driver name.
const MAX_NAME_LEN: usize = 32;

/// Maximum number of children per device.
const MAX_CHILDREN: usize = 8;

/// Maximum size of platform data blob in bytes.
const MAX_PLATFORM_DATA: usize = 128;

// -------------------------------------------------------------------
// ResourceType
// -------------------------------------------------------------------

/// Type of a platform device resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResourceType {
    /// Memory-mapped I/O region.
    #[default]
    Memory,
    /// I/O port region (x86-specific).
    IoPort,
    /// Interrupt line (IRQ number).
    Irq,
    /// DMA channel identifier.
    Dma,
}

// -------------------------------------------------------------------
// DeviceState
// -------------------------------------------------------------------

/// Lifecycle state of a platform device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceState {
    /// Device is registered but no driver is bound.
    #[default]
    Unbound,
    /// Driver probe is in progress.
    Probing,
    /// Device is bound to a driver and operational.
    Bound,
    /// Device is suspended (low-power state).
    Suspended,
    /// Device encountered an error during probe or operation.
    Error,
}

// -------------------------------------------------------------------
// PlatformResource
// -------------------------------------------------------------------

/// A single hardware resource associated with a platform device.
#[derive(Debug, Clone, Copy)]
pub struct PlatformResource {
    /// Type of resource (memory, I/O port, IRQ, DMA).
    pub resource_type: ResourceType,
    /// Start address or number of the resource.
    pub start: u64,
    /// End address (inclusive) or same as start for single-value
    /// resources like IRQs.
    pub end: u64,
    /// Flags providing additional resource attributes.
    pub flags: u32,
}

/// Constant empty resource for array initialisation.
const EMPTY_RESOURCE: PlatformResource = PlatformResource {
    resource_type: ResourceType::Memory,
    start: 0,
    end: 0,
    flags: 0,
};

impl PlatformResource {
    /// Creates a new memory-mapped I/O resource.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `end < start`.
    pub fn memory(start: u64, end: u64, flags: u32) -> Result<Self> {
        if end < start {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            resource_type: ResourceType::Memory,
            start,
            end,
            flags,
        })
    }

    /// Creates a new I/O port resource.
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
        })
    }

    /// Creates a new IRQ resource.
    pub fn irq(irq_num: u32, flags: u32) -> Self {
        Self {
            resource_type: ResourceType::Irq,
            start: u64::from(irq_num),
            end: u64::from(irq_num),
            flags,
        }
    }

    /// Creates a new DMA channel resource.
    pub fn dma(channel: u32, flags: u32) -> Self {
        Self {
            resource_type: ResourceType::Dma,
            start: u64::from(channel),
            end: u64::from(channel),
            flags,
        }
    }

    /// Returns the size of the resource region in bytes.
    ///
    /// For single-value resources (IRQ, DMA) this returns 1.
    pub fn size(&self) -> u64 {
        self.end - self.start + 1
    }
}

// -------------------------------------------------------------------
// NameBuf — fixed-size name buffer
// -------------------------------------------------------------------

/// A fixed-size name buffer for device and driver names.
#[derive(Clone, Copy)]
pub struct NameBuf {
    /// Raw bytes of the name (null-padded).
    bytes: [u8; MAX_NAME_LEN],
    /// Actual length of the name (excluding padding).
    len: usize,
}

impl NameBuf {
    /// Creates a new `NameBuf` from a string slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the name is empty or
    /// exceeds [`MAX_NAME_LEN`].
    pub fn new(name: &str) -> Result<Self> {
        let bytes_slice = name.as_bytes();
        if bytes_slice.is_empty() || bytes_slice.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut bytes = [0u8; MAX_NAME_LEN];
        bytes[..bytes_slice.len()].copy_from_slice(bytes_slice);
        Ok(Self {
            bytes,
            len: bytes_slice.len(),
        })
    }

    /// Returns the name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Returns `true` if this name matches the given string.
    pub fn matches(&self, other: &str) -> bool {
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

/// Constant empty name for array initialisation.
const EMPTY_NAME: NameBuf = NameBuf {
    bytes: [0u8; MAX_NAME_LEN],
    len: 0,
};

// -------------------------------------------------------------------
// PlatformDevice
// -------------------------------------------------------------------

/// A device on the platform bus.
///
/// Platform devices represent non-discoverable hardware typically
/// described by firmware tables or board files. Each device carries
/// an array of hardware resources, a compatible string for driver
/// matching, and an optional opaque data blob.
#[derive(Debug, Clone)]
pub struct PlatformDevice {
    /// Unique device identifier.
    pub id: u32,
    /// Human-readable device name.
    pub name: NameBuf,
    /// Compatible string for device-tree style matching.
    pub compatible: NameBuf,
    /// Hardware resources (MMIO regions, IRQs, DMA channels).
    resources: [PlatformResource; MAX_RESOURCES],
    /// Number of valid entries in `resources`.
    resource_count: usize,
    /// Current lifecycle state.
    pub state: DeviceState,
    /// ID of the driver currently bound to this device (0 = none).
    pub driver_id: u32,
    /// ID of the parent device (0 = root / no parent).
    pub parent_id: u32,
    /// IDs of child devices.
    children: [u32; MAX_CHILDREN],
    /// Number of valid entries in `children`.
    child_count: usize,
    /// Opaque platform data blob.
    platform_data: [u8; MAX_PLATFORM_DATA],
    /// Length of valid bytes in `platform_data`.
    platform_data_len: usize,
}

/// Constant empty device for array initialisation.
const EMPTY_DEVICE: PlatformDevice = PlatformDevice {
    id: 0,
    name: EMPTY_NAME,
    compatible: EMPTY_NAME,
    resources: [EMPTY_RESOURCE; MAX_RESOURCES],
    resource_count: 0,
    state: DeviceState::Unbound,
    driver_id: 0,
    parent_id: 0,
    children: [0u32; MAX_CHILDREN],
    child_count: 0,
    platform_data: [0u8; MAX_PLATFORM_DATA],
    platform_data_len: 0,
};

impl PlatformDevice {
    /// Creates a new platform device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` or `compatible`
    /// are invalid (empty or too long).
    pub fn new(id: u32, name: &str, compatible: &str) -> Result<Self> {
        let mut dev = EMPTY_DEVICE;
        dev.id = id;
        dev.name = NameBuf::new(name)?;
        dev.compatible = NameBuf::new(compatible)?;
        Ok(dev)
    }

    /// Adds a hardware resource to this device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the resource array is full.
    pub fn add_resource(&mut self, resource: PlatformResource) -> Result<()> {
        if self.resource_count >= MAX_RESOURCES {
            return Err(Error::OutOfMemory);
        }
        self.resources[self.resource_count] = resource;
        self.resource_count += 1;
        Ok(())
    }

    /// Returns the slice of hardware resources for this device.
    pub fn resources(&self) -> &[PlatformResource] {
        &self.resources[..self.resource_count]
    }

    /// Returns the first resource of the given type, if any.
    pub fn resource_by_type(&self, rtype: ResourceType) -> Option<&PlatformResource> {
        self.resources().iter().find(|r| r.resource_type == rtype)
    }

    /// Returns the number of resources.
    pub fn resource_count(&self) -> usize {
        self.resource_count
    }

    /// Sets the opaque platform data blob.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` exceeds
    /// [`MAX_PLATFORM_DATA`] bytes.
    pub fn set_platform_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_PLATFORM_DATA {
            return Err(Error::InvalidArgument);
        }
        self.platform_data[..data.len()].copy_from_slice(data);
        self.platform_data_len = data.len();
        Ok(())
    }

    /// Returns the platform data blob, or an empty slice if none.
    pub fn platform_data(&self) -> &[u8] {
        &self.platform_data[..self.platform_data_len]
    }

    /// Adds a child device ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the children array is full.
    fn add_child(&mut self, child_id: u32) -> Result<()> {
        if self.child_count >= MAX_CHILDREN {
            return Err(Error::OutOfMemory);
        }
        self.children[self.child_count] = child_id;
        self.child_count += 1;
        Ok(())
    }

    /// Returns the IDs of all child devices.
    pub fn children(&self) -> &[u32] {
        &self.children[..self.child_count]
    }

    /// Returns the number of child devices.
    pub fn child_count(&self) -> usize {
        self.child_count
    }
}

// -------------------------------------------------------------------
// PlatformDriver
// -------------------------------------------------------------------

/// A driver that binds to platform devices.
///
/// Drivers are matched to devices by name or by compatible string.
/// When a match is found, the bus invokes the driver's probe entry
/// which transitions the device to the [`DeviceState::Bound`] state.
#[derive(Debug, Clone)]
pub struct PlatformDriver {
    /// Unique driver identifier.
    pub id: u32,
    /// Driver name (used for name-based matching).
    pub name: NameBuf,
    /// Compatible strings for device-tree style matching.
    compat_table: [NameBuf; MAX_COMPAT_STRINGS],
    /// Number of valid entries in `compat_table`.
    compat_count: usize,
    /// Whether this driver supports power management suspend.
    pub supports_suspend: bool,
    /// Number of devices currently bound to this driver.
    pub bound_count: u32,
}

/// Constant empty driver for array initialisation.
const EMPTY_DRIVER: PlatformDriver = PlatformDriver {
    id: 0,
    name: EMPTY_NAME,
    compat_table: [EMPTY_NAME; MAX_COMPAT_STRINGS],
    compat_count: 0,
    supports_suspend: false,
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
        drv.name = NameBuf::new(name)?;
        Ok(drv)
    }

    /// Adds a compatible string to the driver's match table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full, or
    /// [`Error::InvalidArgument`] if the string is invalid.
    pub fn add_compatible(&mut self, compat: &str) -> Result<()> {
        if self.compat_count >= MAX_COMPAT_STRINGS {
            return Err(Error::OutOfMemory);
        }
        self.compat_table[self.compat_count] = NameBuf::new(compat)?;
        self.compat_count += 1;
        Ok(())
    }

    /// Returns the slice of compatible strings.
    pub fn compatible_table(&self) -> &[NameBuf] {
        &self.compat_table[..self.compat_count]
    }

    /// Checks whether this driver matches the given device.
    ///
    /// Matching is attempted first by name, then by compatible
    /// string (device-tree style).
    pub fn matches_device(&self, device: &PlatformDevice) -> bool {
        // Name-based matching.
        if self.name.as_bytes() == device.name.as_bytes() && !self.name.as_bytes().is_empty() {
            return true;
        }
        // Compatible-string matching.
        let dev_compat = device.compatible.as_bytes();
        if dev_compat.is_empty() {
            return false;
        }
        self.compat_table[..self.compat_count]
            .iter()
            .any(|c| c.as_bytes() == dev_compat)
    }
}

// -------------------------------------------------------------------
// PlatformBus
// -------------------------------------------------------------------

/// The platform bus manages devices and drivers, performs matching,
/// and coordinates the probe/remove lifecycle.
#[derive(Debug)]
pub struct PlatformBus {
    /// Registered platform devices.
    devices: [PlatformDevice; MAX_DEVICES],
    /// Number of registered devices.
    device_count: usize,
    /// Registered platform drivers.
    drivers: [PlatformDriver; MAX_DRIVERS],
    /// Number of registered drivers.
    driver_count: usize,
}

impl PlatformBus {
    /// Creates a new empty platform bus.
    pub const fn new() -> Self {
        Self {
            devices: [EMPTY_DEVICE; MAX_DEVICES],
            device_count: 0,
            drivers: [EMPTY_DRIVER; MAX_DRIVERS],
            driver_count: 0,
        }
    }

    // ── Device management ──────────────────────────────────────

    /// Registers a platform device on the bus.
    ///
    /// After registration the bus attempts to match the device with
    /// an existing driver and, if successful, automatically probes
    /// the device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if a device with the same
    /// ID is already registered, or [`Error::OutOfMemory`] if the
    /// device array is full.
    pub fn register_device(&mut self, device: PlatformDevice) -> Result<()> {
        // Duplicate check.
        for d in &self.devices[..self.device_count] {
            if d.id == device.id {
                return Err(Error::AlreadyExists);
            }
        }
        if self.device_count >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.device_count;
        self.devices[idx] = device;
        self.device_count += 1;

        // Attempt auto-match with existing drivers.
        let dev = &self.devices[idx];
        let mut matched_drv_id = None;
        for drv in &self.drivers[..self.driver_count] {
            if drv.matches_device(dev) {
                matched_drv_id = Some(drv.id);
                break;
            }
        }
        if let Some(drv_id) = matched_drv_id {
            self.probe_device(self.devices[idx].id, drv_id)?;
        }
        Ok(())
    }

    /// Unregisters a platform device from the bus.
    ///
    /// If the device is bound to a driver, it is removed first.
    /// The device is also detached from its parent.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no device with the given ID
    /// exists.
    pub fn unregister_device(&mut self, device_id: u32) -> Result<()> {
        let idx = self.device_index(device_id)?;
        let drv_id = self.devices[idx].driver_id;
        if drv_id != 0 {
            self.remove_device(device_id)?;
        }
        // Detach from parent.
        let parent_id = self.devices[idx].parent_id;
        if parent_id != 0 {
            if let Ok(pidx) = self.device_index(parent_id) {
                self.remove_child_from(pidx, device_id);
            }
        }
        // Compact the array.
        let last = self.device_count - 1;
        if idx != last {
            self.devices[idx] = self.devices[last].clone();
        }
        self.devices[last] = EMPTY_DEVICE;
        self.device_count -= 1;
        Ok(())
    }

    /// Looks up a device by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the device is not registered.
    pub fn get_device(&self, device_id: u32) -> Result<&PlatformDevice> {
        let idx = self.device_index(device_id)?;
        Ok(&self.devices[idx])
    }

    /// Establishes a parent-child relationship between two devices.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if either device is not
    /// registered, or [`Error::OutOfMemory`] if the parent already
    /// has the maximum number of children.
    pub fn set_parent(&mut self, child_id: u32, parent_id: u32) -> Result<()> {
        let cidx = self.device_index(child_id)?;
        let pidx = self.device_index(parent_id)?;
        self.devices[cidx].parent_id = parent_id;
        self.devices[pidx].add_child(child_id)
    }

    /// Returns a slice of all registered devices.
    pub fn devices(&self) -> &[PlatformDevice] {
        &self.devices[..self.device_count]
    }

    // ── Driver management ──────────────────────────────────────

    /// Registers a platform driver on the bus.
    ///
    /// After registration the bus attempts to match the driver with
    /// all unbound devices and probes any that match.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if a driver with the same
    /// ID is already registered, or [`Error::OutOfMemory`] if the
    /// driver array is full.
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

    /// Unregisters a platform driver from the bus.
    ///
    /// All devices currently bound to this driver are removed
    /// (transitioned to [`DeviceState::Unbound`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no driver with the given ID
    /// exists.
    pub fn unregister_driver(&mut self, driver_id: u32) -> Result<()> {
        let idx = self.driver_index(driver_id)?;
        // Remove all devices bound to this driver.
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
            self.drivers[idx] = self.drivers[last].clone();
        }
        self.drivers[last] = EMPTY_DRIVER;
        self.driver_count -= 1;
        Ok(())
    }

    /// Looks up a driver by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the driver is not registered.
    pub fn get_driver(&self, driver_id: u32) -> Result<&PlatformDriver> {
        let idx = self.driver_index(driver_id)?;
        Ok(&self.drivers[idx])
    }

    /// Returns a slice of all registered drivers.
    pub fn drivers(&self) -> &[PlatformDriver] {
        &self.drivers[..self.driver_count]
    }

    // ── Probe / Remove lifecycle ───────────────────────────────

    /// Probes a device with the specified driver.
    ///
    /// Transitions the device through `Probing` → `Bound` on
    /// success, or to `Error` on failure.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the device or driver is not
    /// registered, [`Error::Busy`] if the device is already bound,
    /// or [`Error::IoError`] if the driver does not match the
    /// device.
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

    /// Removes (unbinds) a device from its currently bound driver.
    ///
    /// Transitions the device back to [`DeviceState::Unbound`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the device or its driver is
    /// not registered, or [`Error::InvalidArgument`] if the device
    /// is not currently bound.
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
    /// Returns [`Error::NotFound`] if the device is not registered,
    /// or [`Error::InvalidArgument`] if the device is not bound.
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
    /// Returns [`Error::NotFound`] if the device is not registered,
    /// or [`Error::InvalidArgument`] if the device is not suspended.
    pub fn resume_device(&mut self, device_id: u32) -> Result<()> {
        let idx = self.device_index(device_id)?;
        if self.devices[idx].state != DeviceState::Suspended {
            return Err(Error::InvalidArgument);
        }
        self.devices[idx].state = DeviceState::Bound;
        Ok(())
    }

    // ── Query helpers ──────────────────────────────────────────

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

    /// Finds all devices matching a given compatible string.
    ///
    /// Returns the number of matching device IDs written to `out`.
    pub fn find_compatible(&self, compat: &str, out: &mut [u32]) -> usize {
        let mut count = 0;
        for dev in &self.devices[..self.device_count] {
            if dev.compatible.matches(compat) && count < out.len() {
                out[count] = dev.id;
                count += 1;
            }
        }
        count
    }

    /// Finds a device by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no device with that name exists.
    pub fn find_by_name(&self, name: &str) -> Result<&PlatformDevice> {
        self.devices[..self.device_count]
            .iter()
            .find(|d| d.name.matches(name))
            .ok_or(Error::NotFound)
    }

    // ── Internal helpers ───────────────────────────────────────

    /// Returns the index of a device by ID.
    fn device_index(&self, id: u32) -> Result<usize> {
        self.devices[..self.device_count]
            .iter()
            .position(|d| d.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns the index of a driver by ID.
    fn driver_index(&self, id: u32) -> Result<usize> {
        self.drivers[..self.driver_count]
            .iter()
            .position(|d| d.id == id)
            .ok_or(Error::NotFound)
    }

    /// Removes a child ID from a parent device's children array.
    fn remove_child_from(&mut self, parent_idx: usize, child_id: u32) {
        let parent = &mut self.devices[parent_idx];
        let mut found = false;
        for i in 0..parent.child_count {
            if parent.children[i] == child_id {
                found = true;
            }
            if found && i + 1 < parent.child_count {
                parent.children[i] = parent.children[i + 1];
            }
        }
        if found && parent.child_count > 0 {
            parent.child_count -= 1;
            parent.children[parent.child_count] = 0;
        }
    }
}
