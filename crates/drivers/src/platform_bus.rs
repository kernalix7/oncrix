// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Platform bus device and driver model.
//!
//! The platform bus handles devices that are not discoverable via PCI or USB
//! but are described by firmware (ACPI, Device Tree, or hard-coded board files).
//! Examples include: UART, I2C controllers, GPIO banks, RTC, watchdog timers.
//!
//! The model mirrors the Linux `platform_device` / `platform_driver` pattern:
//!
//! 1. Platform devices are registered with a name, MMIO resources, and IRQs.
//! 2. Platform drivers register with a list of compatible strings.
//! 3. The bus matches devices to drivers by name/compatible string.
//! 4. On match, the driver's `probe()` is called.
//!
//! Reference: Linux kernel Documentation/driver-api/driver-model/platform.rst.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Resource
// ---------------------------------------------------------------------------

/// Type of a platform device resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceType {
    /// Memory-mapped I/O region.
    Mmio,
    /// I/O port range (x86 port I/O).
    Io,
    /// Hardware interrupt line.
    Irq,
    /// DMA channel number.
    Dma,
}

/// A single resource associated with a platform device.
#[derive(Clone, Copy, Debug)]
pub struct PlatformResource {
    /// Resource type.
    pub kind: ResourceType,
    /// Start address (for MMIO/IO) or number (for IRQ/DMA).
    pub start: u64,
    /// End address (inclusive for MMIO/IO), or same as start for IRQ/DMA.
    pub end: u64,
    /// Human-readable resource name.
    pub name: &'static str,
}

impl PlatformResource {
    /// Creates an MMIO resource.
    pub const fn mmio(name: &'static str, start: u64, size: u64) -> Self {
        Self {
            kind: ResourceType::Mmio,
            start,
            end: start + size - 1,
            name,
        }
    }

    /// Creates an IRQ resource.
    pub const fn irq(name: &'static str, irq: u64) -> Self {
        Self {
            kind: ResourceType::Irq,
            start: irq,
            end: irq,
            name,
        }
    }

    /// Creates an I/O port resource.
    pub const fn io(name: &'static str, start: u64, size: u64) -> Self {
        Self {
            kind: ResourceType::Io,
            start,
            end: start + size - 1,
            name,
        }
    }

    /// Returns the size of this resource in bytes (for MMIO/IO).
    pub const fn size(&self) -> u64 {
        self.end - self.start + 1
    }
}

// ---------------------------------------------------------------------------
// Platform Device
// ---------------------------------------------------------------------------

/// Maximum resources per platform device.
pub const MAX_PLATFORM_RESOURCES: usize = 8;

/// Platform device descriptor.
#[derive(Clone, Copy, Debug)]
pub struct PlatformDevice {
    /// Device name used for driver matching (e.g., "ns16550a", "arm-pl011").
    pub name: &'static str,
    /// Platform-unique device ID (used to disambiguate multiple instances).
    pub id: i32,
    /// Resources (MMIO, IRQ, DMA, etc.).
    pub resources: [Option<PlatformResource>; MAX_PLATFORM_RESOURCES],
    /// Number of valid resources.
    pub resource_count: usize,
}

impl PlatformDevice {
    /// Creates a platform device with no resources.
    pub const fn new(name: &'static str, id: i32) -> Self {
        Self {
            name,
            id,
            resources: [const { None }; MAX_PLATFORM_RESOURCES],
            resource_count: 0,
        }
    }

    /// Adds a resource to the device.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the resource list is full.
    pub fn add_resource(&mut self, res: PlatformResource) -> Result<()> {
        if self.resource_count >= MAX_PLATFORM_RESOURCES {
            return Err(Error::InvalidArgument);
        }
        self.resources[self.resource_count] = Some(res);
        self.resource_count += 1;
        Ok(())
    }

    /// Returns the first MMIO resource.
    pub fn mmio_resource(&self) -> Option<&PlatformResource> {
        for i in 0..self.resource_count {
            if let Some(ref r) = self.resources[i] {
                if r.kind == ResourceType::Mmio {
                    return Some(r);
                }
            }
        }
        None
    }

    /// Returns the first IRQ resource.
    pub fn irq_resource(&self) -> Option<&PlatformResource> {
        for i in 0..self.resource_count {
            if let Some(ref r) = self.resources[i] {
                if r.kind == ResourceType::Irq {
                    return Some(r);
                }
            }
        }
        None
    }

    /// Returns the MMIO base address (from the first MMIO resource), or 0.
    pub fn mmio_base(&self) -> u64 {
        self.mmio_resource().map(|r| r.start).unwrap_or(0)
    }

    /// Returns the IRQ number (from the first IRQ resource), or 0.
    pub fn irq(&self) -> u64 {
        self.irq_resource().map(|r| r.start).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Platform Driver
// ---------------------------------------------------------------------------

/// Maximum number of compatible strings per platform driver.
pub const MAX_COMPATIBLES: usize = 8;

/// Platform driver descriptor.
pub struct PlatformDriver {
    /// Driver name.
    pub name: &'static str,
    /// Compatible strings (null-terminated entries; first empty = end).
    pub compatible: &'static [&'static str],
    /// Probe callback.
    pub probe: fn(dev: &PlatformDevice) -> Result<()>,
    /// Remove callback.
    pub remove: fn(dev: &PlatformDevice),
}

impl PlatformDriver {
    /// Returns `true` if this driver is compatible with `device_name`.
    pub fn is_compatible(&self, device_name: &str) -> bool {
        for compat in self.compatible {
            if *compat == device_name {
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Platform Bus
// ---------------------------------------------------------------------------

/// Maximum number of registered platform devices.
pub const MAX_PLATFORM_DEVICES: usize = 64;

/// Maximum number of registered platform drivers.
pub const MAX_PLATFORM_DRIVERS: usize = 64;

/// Platform bus registry — holds all registered devices and drivers.
pub struct PlatformBus {
    devices: [Option<PlatformDevice>; MAX_PLATFORM_DEVICES],
    device_count: usize,
    drivers: [Option<&'static PlatformDriver>; MAX_PLATFORM_DRIVERS],
    driver_count: usize,
}

impl PlatformBus {
    /// Creates an empty platform bus.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_PLATFORM_DEVICES],
            device_count: 0,
            drivers: [const { None }; MAX_PLATFORM_DRIVERS],
            driver_count: 0,
        }
    }

    /// Registers a platform device.
    ///
    /// If a compatible driver is already registered, `probe()` is called immediately.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the device list is full.
    pub fn register_device(&mut self, dev: PlatformDevice) -> Result<()> {
        if self.device_count >= MAX_PLATFORM_DEVICES {
            return Err(Error::InvalidArgument);
        }
        // Check for an already-registered driver.
        for i in 0..self.driver_count {
            if let Some(drv) = self.drivers[i] {
                if drv.is_compatible(dev.name) {
                    (drv.probe)(&dev)?;
                }
            }
        }
        self.devices[self.device_count] = Some(dev);
        self.device_count += 1;
        Ok(())
    }

    /// Registers a platform driver.
    ///
    /// Probes all currently registered devices that are compatible.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the driver list is full.
    pub fn register_driver(&mut self, drv: &'static PlatformDriver) -> Result<()> {
        if self.driver_count >= MAX_PLATFORM_DRIVERS {
            return Err(Error::InvalidArgument);
        }
        // Probe existing devices.
        for i in 0..self.device_count {
            if let Some(ref dev) = self.devices[i] {
                if drv.is_compatible(dev.name) {
                    (drv.probe)(dev)?;
                }
            }
        }
        self.drivers[self.driver_count] = Some(drv);
        self.driver_count += 1;
        Ok(())
    }

    /// Finds a registered device by name and id.
    pub fn find_device(&self, name: &str, id: i32) -> Option<&PlatformDevice> {
        for i in 0..self.device_count {
            if let Some(ref dev) = self.devices[i] {
                if dev.name == name && dev.id == id {
                    return Some(dev);
                }
            }
        }
        None
    }

    /// Returns the number of registered devices.
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    /// Returns the number of registered drivers.
    pub fn driver_count(&self) -> usize {
        self.driver_count
    }
}

impl Default for PlatformBus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Platform Device Builder (convenience)
// ---------------------------------------------------------------------------

/// Convenience builder for creating platform devices with multiple resources.
pub struct PlatformDeviceBuilder {
    dev: PlatformDevice,
}

impl PlatformDeviceBuilder {
    /// Creates a builder for a device with the given name and ID.
    pub const fn new(name: &'static str, id: i32) -> Self {
        Self {
            dev: PlatformDevice::new(name, id),
        }
    }

    /// Adds an MMIO resource.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the resource list is full.
    pub fn mmio(mut self, name: &'static str, base: u64, size: u64) -> Result<Self> {
        self.dev
            .add_resource(PlatformResource::mmio(name, base, size))?;
        Ok(self)
    }

    /// Adds an IRQ resource.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the resource list is full.
    pub fn irq(mut self, irq: u64) -> Result<Self> {
        self.dev.add_resource(PlatformResource::irq("irq", irq))?;
        Ok(self)
    }

    /// Finishes building and returns the `PlatformDevice`.
    pub fn build(self) -> PlatformDevice {
        self.dev
    }
}
