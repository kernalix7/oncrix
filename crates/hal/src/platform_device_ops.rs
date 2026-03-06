// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Platform device operations framework.
//!
//! Implements a platform bus device model for registering non-discoverable
//! devices — those not found via PCI or USB enumeration — alongside their
//! hardware resources (IOMEM regions, IRQ lines). Supports:
//!
//! - Platform device registration with typed resource descriptors
//! - Platform driver matching by device name or ID-table entry
//! - Probe / remove lifecycle management
//! - Device-managed (devm) resource tracking (up to 8 resources per device)
//! - `platform_get_resource` queries by type and index
//!
//! # Architecture
//!
//! - [`ResType`] — IOMEM, IO port, IRQ, or DMA.
//! - [`PlatRes`] — a single resource with start/end/flags.
//! - [`DevmToken`] — opaque handle returned by devm resource allocation.
//! - [`PlatDev`] — a platform device with resource list and devm table.
//! - [`PlatDrv`] — a platform driver with ID-table entries.
//! - [`PlatformOps`] — the registry coordinating matching and lifecycle.
//!
//! Reference: Linux `drivers/base/platform.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of resources per device.
const MAX_RES: usize = 8;
/// Maximum number of devm-tracked resources per device.
const MAX_DEVM: usize = 8;
/// Maximum number of devices in the registry.
const MAX_DEVS: usize = 32;
/// Maximum number of drivers in the registry.
const MAX_DRVS: usize = 16;
/// Maximum entries in the driver ID table.
const MAX_IDS: usize = 8;
/// Maximum length of a name or ID-table string.
const NAME_LEN: usize = 32;

// ---------------------------------------------------------------------------
// ResType / PlatRes
// ---------------------------------------------------------------------------

/// Type of a platform resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResType {
    /// Memory-mapped I/O region (IOMEM).
    #[default]
    Iomem,
    /// Legacy I/O port region (x86-specific).
    IoPort,
    /// Interrupt line.
    Irq,
    /// DMA channel.
    Dma,
}

/// A single hardware resource owned by a platform device.
#[derive(Debug, Clone, Copy)]
pub struct PlatRes {
    /// Resource classification.
    pub res_type: ResType,
    /// Start address or scalar identifier.
    pub start: u64,
    /// End address (inclusive) or same as `start` for scalars.
    pub end: u64,
    /// Resource-type-specific flags.
    pub flags: u32,
    /// Index within the device's resource array.
    pub index: u32,
}

/// Constant empty resource for array initialisation.
const EMPTY_RES: PlatRes = PlatRes {
    res_type: ResType::Iomem,
    start: 0,
    end: 0,
    flags: 0,
    index: 0,
};

impl PlatRes {
    /// Creates an IOMEM resource.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `end < start`.
    pub fn iomem(start: u64, end: u64, flags: u32) -> Result<Self> {
        if end < start {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            res_type: ResType::Iomem,
            start,
            end,
            flags,
            index: 0,
        })
    }

    /// Creates an IRQ resource.
    pub fn irq(irq: u32, flags: u32) -> Self {
        Self {
            res_type: ResType::Irq,
            start: u64::from(irq),
            end: u64::from(irq),
            flags,
            index: 0,
        }
    }

    /// Creates a DMA channel resource.
    pub fn dma(channel: u32, flags: u32) -> Self {
        Self {
            res_type: ResType::Dma,
            start: u64::from(channel),
            end: u64::from(channel),
            flags,
            index: 0,
        }
    }

    /// Returns the size of the resource region in bytes (1 for scalars).
    pub fn size(&self) -> u64 {
        self.end - self.start + 1
    }
}

// ---------------------------------------------------------------------------
// DevmToken
// ---------------------------------------------------------------------------

/// Opaque handle identifying a device-managed resource allocation.
///
/// Returned by `PlatDev::devm_register`; passed to `PlatDev::devm_release`
/// to free a specific managed resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevmToken(u8);

// ---------------------------------------------------------------------------
// DevmEntry
// ---------------------------------------------------------------------------

/// A device-managed resource entry stored in the device's devm table.
#[derive(Clone, Copy)]
struct DevmEntry {
    /// Opaque 64-bit key identifying the allocated object (e.g., address).
    key: u64,
    /// Whether this slot is active.
    active: bool,
}

const EMPTY_DEVM: DevmEntry = DevmEntry {
    key: 0,
    active: false,
};

// ---------------------------------------------------------------------------
// NameBuf
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct NameBuf {
    bytes: [u8; NAME_LEN],
    len: usize,
}

impl NameBuf {
    const fn empty() -> Self {
        Self {
            bytes: [0u8; NAME_LEN],
            len: 0,
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        let b = s.as_bytes();
        if b.is_empty() || b.len() > NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; NAME_LEN];
        buf[..b.len()].copy_from_slice(b);
        Ok(Self {
            bytes: buf,
            len: b.len(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn matches(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }

    fn matches_str(&self, s: &str) -> bool {
        self.as_bytes() == s.as_bytes()
    }
}

// ---------------------------------------------------------------------------
// DevState
// ---------------------------------------------------------------------------

/// Lifecycle state of a platform device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DevState {
    /// Registered but no driver bound.
    #[default]
    Unbound,
    /// Driver probe in progress.
    Probing,
    /// Bound to a driver and operational.
    Bound,
    /// Probe failed or runtime error.
    Error,
}

// ---------------------------------------------------------------------------
// PlatDev
// ---------------------------------------------------------------------------

/// A platform device with resource descriptors and devm tracking.
pub struct PlatDev {
    /// Unique device ID.
    pub id: u32,
    /// Device name used for driver matching.
    name: NameBuf,
    /// Hardware resources.
    resources: [PlatRes; MAX_RES],
    /// Number of valid resource entries.
    res_count: usize,
    /// Device-managed resource table.
    devm: [DevmEntry; MAX_DEVM],
    /// Number of active devm entries.
    devm_count: usize,
    /// Current lifecycle state.
    pub state: DevState,
    /// ID of the bound driver (0 = none).
    pub driver_id: u32,
    /// Whether this device slot is active.
    pub active: bool,
}

/// Constant empty device for array initialisation.
const EMPTY_DEV: PlatDev = PlatDev {
    id: 0,
    name: NameBuf {
        bytes: [0u8; NAME_LEN],
        len: 0,
    },
    resources: [EMPTY_RES; MAX_RES],
    res_count: 0,
    devm: [EMPTY_DEVM; MAX_DEVM],
    devm_count: 0,
    state: DevState::Unbound,
    driver_id: 0,
    active: false,
};

impl PlatDev {
    /// Creates a new platform device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is invalid.
    pub fn new(id: u32, name: &str) -> Result<Self> {
        let mut dev = EMPTY_DEV;
        dev.id = id;
        dev.name = NameBuf::from_str(name)?;
        dev.active = true;
        Ok(dev)
    }

    /// Returns the device name as a byte slice.
    pub fn name(&self) -> &[u8] {
        self.name.as_bytes()
    }

    /// Adds a hardware resource to the device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the resource array is full.
    pub fn add_resource(&mut self, mut res: PlatRes) -> Result<()> {
        if self.res_count >= MAX_RES {
            return Err(Error::OutOfMemory);
        }
        res.index = self.res_count as u32;
        self.resources[self.res_count] = res;
        self.res_count += 1;
        Ok(())
    }

    /// Returns the `n`-th resource of the given type (Linux `platform_get_resource`).
    pub fn get_resource(&self, res_type: ResType, n: usize) -> Option<&PlatRes> {
        self.resources[..self.res_count]
            .iter()
            .filter(|r| r.res_type == res_type)
            .nth(n)
    }

    /// Returns all resources as a slice.
    pub fn resources(&self) -> &[PlatRes] {
        &self.resources[..self.res_count]
    }

    /// Registers a device-managed resource, returning an opaque token.
    ///
    /// The `key` uniquely identifies the allocation (e.g., the mapped address).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the devm table is full.
    pub fn devm_register(&mut self, key: u64) -> Result<DevmToken> {
        if self.devm_count >= MAX_DEVM {
            return Err(Error::OutOfMemory);
        }
        let slot = self.devm_count as u8;
        self.devm[self.devm_count] = DevmEntry { key, active: true };
        self.devm_count += 1;
        Ok(DevmToken(slot))
    }

    /// Releases a device-managed resource identified by `token`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the token is invalid or already released.
    pub fn devm_release(&mut self, token: DevmToken) -> Result<()> {
        let slot = token.0 as usize;
        if slot >= self.devm_count || !self.devm[slot].active {
            return Err(Error::NotFound);
        }
        self.devm[slot].active = false;
        Ok(())
    }

    /// Releases all active device-managed resources (called on device removal).
    pub fn devm_release_all(&mut self) {
        for entry in &mut self.devm[..self.devm_count] {
            entry.active = false;
        }
    }
}

// ---------------------------------------------------------------------------
// IdEntry / PlatDrv
// ---------------------------------------------------------------------------

/// A single entry in a platform driver's ID match table.
#[derive(Clone, Copy)]
pub struct IdEntry {
    /// Name string to match against a device name.
    name: NameBuf,
}

const EMPTY_ID: IdEntry = IdEntry {
    name: NameBuf {
        bytes: [0u8; NAME_LEN],
        len: 0,
    },
};

impl IdEntry {
    /// Creates an ID table entry matching `name`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is invalid.
    pub fn new(name: &str) -> Result<Self> {
        Ok(Self {
            name: NameBuf::from_str(name)?,
        })
    }
}

/// A platform driver with name and ID-table matching.
pub struct PlatDrv {
    /// Unique driver ID.
    pub id: u32,
    /// Driver name for direct name-based matching.
    name: NameBuf,
    /// ID-table for compatible-string matching.
    id_table: [IdEntry; MAX_IDS],
    /// Number of valid ID-table entries.
    id_count: usize,
    /// Number of devices currently bound to this driver.
    pub bound_count: u32,
}

const EMPTY_DRV: PlatDrv = PlatDrv {
    id: 0,
    name: NameBuf {
        bytes: [0u8; NAME_LEN],
        len: 0,
    },
    id_table: [EMPTY_ID; MAX_IDS],
    id_count: 0,
    bound_count: 0,
};

impl PlatDrv {
    /// Creates a new platform driver.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is invalid.
    pub fn new(id: u32, name: &str) -> Result<Self> {
        let mut drv = EMPTY_DRV;
        drv.id = id;
        drv.name = NameBuf::from_str(name)?;
        Ok(drv)
    }

    /// Adds an entry to the driver's ID match table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn add_id(&mut self, entry: IdEntry) -> Result<()> {
        if self.id_count >= MAX_IDS {
            return Err(Error::OutOfMemory);
        }
        self.id_table[self.id_count] = entry;
        self.id_count += 1;
        Ok(())
    }

    /// Checks whether this driver matches the given device.
    ///
    /// Matching precedence: driver name == device name first, then
    /// ID-table entries.
    pub fn matches(&self, dev: &PlatDev) -> bool {
        if self.name.matches(&dev.name) {
            return true;
        }
        self.id_table[..self.id_count].iter().any(|e| {
            e.name
                .matches_str(core::str::from_utf8(dev.name.as_bytes()).unwrap_or(""))
        })
    }
}

// ---------------------------------------------------------------------------
// PlatformOps
// ---------------------------------------------------------------------------

/// Registry coordinating platform devices, drivers, and their lifecycle.
pub struct PlatformOps {
    devs: [PlatDev; MAX_DEVS],
    dev_count: usize,
    drvs: [PlatDrv; MAX_DRVS],
    drv_count: usize,
}

impl PlatformOps {
    /// Creates an empty platform operations registry.
    pub const fn new() -> Self {
        Self {
            devs: [EMPTY_DEV; MAX_DEVS],
            dev_count: 0,
            drvs: [EMPTY_DRV; MAX_DRVS],
            drv_count: 0,
        }
    }

    /// Registers a platform device, then attempts to match and probe it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] or [`Error::OutOfMemory`].
    pub fn register_device(&mut self, dev: PlatDev) -> Result<()> {
        for d in &self.devs[..self.dev_count] {
            if d.id == dev.id && d.active {
                return Err(Error::AlreadyExists);
            }
        }
        if self.dev_count >= MAX_DEVS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.dev_count;
        self.devs[idx] = dev;
        self.dev_count += 1;
        self.try_probe_device(idx);
        Ok(())
    }

    /// Unregisters a platform device, running remove lifecycle first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the device does not exist.
    pub fn unregister_device(&mut self, dev_id: u32) -> Result<()> {
        let idx = self.dev_index(dev_id)?;
        self.run_remove(idx);
        let last = self.dev_count - 1;
        if idx != last {
            self.devs.swap(idx, last);
        }
        self.devs[last] = EMPTY_DEV;
        self.dev_count -= 1;
        Ok(())
    }

    /// Registers a platform driver, probing all matching unbound devices.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] or [`Error::OutOfMemory`].
    pub fn register_driver(&mut self, drv: PlatDrv) -> Result<()> {
        for d in &self.drvs[..self.drv_count] {
            if d.id == drv.id {
                return Err(Error::AlreadyExists);
            }
        }
        if self.drv_count >= MAX_DRVS {
            return Err(Error::OutOfMemory);
        }
        self.drvs[self.drv_count] = drv;
        self.drv_count += 1;

        // Probe all matching unbound devices.
        let mut indices = [0usize; MAX_DEVS];
        let mut count = 0;
        for i in 0..self.dev_count {
            if self.devs[i].state == DevState::Unbound {
                indices[count] = i;
                count += 1;
            }
        }
        for i in 0..count {
            self.try_probe_device(indices[i]);
        }
        Ok(())
    }

    /// Unregisters a platform driver, removing all bound devices first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the driver does not exist.
    pub fn unregister_driver(&mut self, drv_id: u32) -> Result<()> {
        let drv_idx = self.drv_index(drv_id)?;
        let mut to_remove = [0usize; MAX_DEVS];
        let mut count = 0;
        for i in 0..self.dev_count {
            if self.devs[i].driver_id == drv_id {
                to_remove[count] = i;
                count += 1;
            }
        }
        for i in 0..count {
            self.run_remove(to_remove[i]);
        }
        let last = self.drv_count - 1;
        if drv_idx != last {
            self.drvs.swap(drv_idx, last);
        }
        self.drvs[last] = EMPTY_DRV;
        self.drv_count -= 1;
        Ok(())
    }

    /// Returns a reference to a device by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not present.
    pub fn get_device(&self, dev_id: u32) -> Result<&PlatDev> {
        let idx = self.dev_index(dev_id)?;
        Ok(&self.devs[idx])
    }

    /// Returns the number of registered devices.
    pub fn device_count(&self) -> usize {
        self.dev_count
    }

    /// Returns the number of registered drivers.
    pub fn driver_count(&self) -> usize {
        self.drv_count
    }

    // -- internal -----------------------------------------------------------

    fn dev_index(&self, id: u32) -> Result<usize> {
        self.devs[..self.dev_count]
            .iter()
            .position(|d| d.id == id && d.active)
            .ok_or(Error::NotFound)
    }

    fn drv_index(&self, id: u32) -> Result<usize> {
        self.drvs[..self.drv_count]
            .iter()
            .position(|d| d.id == id)
            .ok_or(Error::NotFound)
    }

    fn try_probe_device(&mut self, dev_idx: usize) {
        let mut matched_drv = None;
        for i in 0..self.drv_count {
            if self.drvs[i].matches(&self.devs[dev_idx]) {
                matched_drv = Some(i);
                break;
            }
        }
        if let Some(drv_idx) = matched_drv {
            let drv_id = self.drvs[drv_idx].id;
            self.devs[dev_idx].state = DevState::Probing;
            self.devs[dev_idx].driver_id = drv_id;
            self.devs[dev_idx].state = DevState::Bound;
            self.drvs[drv_idx].bound_count += 1;
        }
    }

    fn run_remove(&mut self, dev_idx: usize) {
        let drv_id = self.devs[dev_idx].driver_id;
        if drv_id != 0 {
            if let Ok(drv_idx) = self.drv_index(drv_id) {
                if self.drvs[drv_idx].bound_count > 0 {
                    self.drvs[drv_idx].bound_count -= 1;
                }
            }
        }
        self.devs[dev_idx].devm_release_all();
        self.devs[dev_idx].state = DevState::Unbound;
        self.devs[dev_idx].driver_id = 0;
    }
}

impl Default for PlatformOps {
    fn default() -> Self {
        Self::new()
    }
}
