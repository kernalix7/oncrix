// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Non-Volatile DIMM (NVDIMM) driver abstraction.
//!
//! Manages persistent memory regions exposed by NVDIMMs, including
//! namespace creation, region mapping, health monitoring, and DAX
//! (Direct Access) support. The driver parses NFIT (NVDIMM Firmware
//! Interface Table) entries from ACPI to discover persistent memory
//! ranges and constructs namespaces over them.
//!
//! # Architecture
//!
//! - [`PmemMode`] — operating mode for a persistent memory region
//! - [`NvdimmHealthStatus`] — health state of an NVDIMM module
//! - [`NvdimmRegion`] — a contiguous physical address range of pmem
//! - [`NvdimmNamespace`] — a logical partition within a region
//! - [`NvdimmDevice`] — a single NVDIMM module with health telemetry
//! - [`NvdimmController`] — manages regions, namespaces, and devices
//! - [`NvdimmRegistry`] — system-wide registry of NVDIMM controllers
//!
//! Reference: ACPI 6.4, Table 5-137 (NFIT); UEFI 2.10, Section 13.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of NVDIMM devices per controller.
const MAX_DEVICES: usize = 16;

/// Maximum number of persistent memory regions per controller.
const MAX_REGIONS: usize = 16;

/// Maximum number of namespaces per controller.
const MAX_NAMESPACES: usize = 32;

/// Maximum number of NVDIMM controllers in the registry.
const MAX_CONTROLLERS: usize = 4;

/// Maximum length of a namespace label in bytes.
const MAX_LABEL_LEN: usize = 64;

/// Page size for DAX mappings (2 MiB huge page).
const DAX_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// NFIT signature bytes ("NFIT").
const NFIT_SIGNATURE: [u8; 4] = [b'N', b'F', b'I', b'T'];

// ---------------------------------------------------------------------------
// PmemMode
// ---------------------------------------------------------------------------

/// Operating mode for a persistent memory region.
///
/// Determines how the persistent memory is exposed to the kernel
/// and user space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PmemMode {
    /// Raw block device mode; accessed through the block I/O layer.
    #[default]
    Raw,
    /// Filesystem-DAX mode; memory-mapped directly into user space
    /// without page cache involvement.
    FsDax,
    /// Device-DAX mode; presented as a character device for
    /// application-managed persistent allocations.
    DevDax,
    /// Sector mode; emulates 512-byte sector access for legacy
    /// filesystem compatibility.
    Sector,
}

// ---------------------------------------------------------------------------
// NvdimmHealthStatus
// ---------------------------------------------------------------------------

/// Health status of an NVDIMM module.
///
/// Reflects the current operational state as reported by the
/// NVDIMM firmware through the _DSM (Device Specific Method).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NvdimmHealthStatus {
    /// Module is operating normally.
    #[default]
    Healthy,
    /// Module has detected correctable errors; monitoring advised.
    Warning,
    /// Module has detected uncorrectable errors; data may be at risk.
    Critical,
    /// Module firmware reports an internal fault.
    Fatal,
    /// Health status could not be determined.
    Unknown,
}

// ---------------------------------------------------------------------------
// NvdimmRegion
// ---------------------------------------------------------------------------

/// A contiguous physical address range of persistent memory.
///
/// Regions are discovered from the NFIT SPA (System Physical Address)
/// range structure during ACPI table parsing.
#[derive(Debug, Clone, Copy)]
pub struct NvdimmRegion {
    /// Region identifier (unique within a controller).
    pub region_id: u32,
    /// Physical base address of the region.
    pub base_addr: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Whether the region supports DAX (direct access).
    pub dax_capable: bool,
    /// Number of interleave ways (1 = non-interleaved).
    pub interleave_ways: u8,
    /// Whether the region has been mapped into virtual address space.
    pub mapped: bool,
    /// Virtual address assigned when mapped (0 if unmapped).
    pub virt_addr: u64,
}

impl Default for NvdimmRegion {
    fn default() -> Self {
        Self {
            region_id: 0,
            base_addr: 0,
            size: 0,
            dax_capable: false,
            interleave_ways: 1,
            mapped: false,
            virt_addr: 0,
        }
    }
}

impl NvdimmRegion {
    /// Create a new persistent memory region.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `base_addr` is zero or
    /// `size` is zero.
    pub fn new(region_id: u32, base_addr: u64, size: u64) -> Result<Self> {
        if base_addr == 0 || size == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            region_id,
            base_addr,
            size,
            dax_capable: true,
            interleave_ways: 1,
            mapped: false,
            virt_addr: 0,
        })
    }

    /// Return the end address (exclusive) of this region.
    pub fn end_addr(&self) -> u64 {
        self.base_addr.saturating_add(self.size)
    }

    /// Return the number of DAX-sized pages that fit in this region.
    pub fn dax_page_count(&self) -> u64 {
        if DAX_PAGE_SIZE == 0 {
            return 0;
        }
        self.size / DAX_PAGE_SIZE
    }

    /// Check whether a physical address falls within this region.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base_addr && addr < self.end_addr()
    }

    /// Map this region into virtual address space.
    ///
    /// In a real implementation this would configure page tables
    /// with write-combining or uncacheable attributes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if the region is already
    /// mapped, or [`Error::InvalidArgument`] if `virt_addr` is zero.
    pub fn map(&mut self, virt_addr: u64) -> Result<()> {
        if self.mapped {
            return Err(Error::AlreadyExists);
        }
        if virt_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        self.virt_addr = virt_addr;
        self.mapped = true;
        Ok(())
    }

    /// Unmap this region from virtual address space.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the region is not
    /// currently mapped.
    pub fn unmap(&mut self) -> Result<()> {
        if !self.mapped {
            return Err(Error::InvalidArgument);
        }
        self.virt_addr = 0;
        self.mapped = false;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// NvdimmNamespace
// ---------------------------------------------------------------------------

/// A logical partition within a persistent memory region.
///
/// Namespaces divide a region into independently addressable units,
/// each with its own mode and label. This is analogous to partitions
/// on a conventional block device.
#[derive(Debug, Clone, Copy)]
pub struct NvdimmNamespace {
    /// Namespace identifier (unique within a controller).
    pub namespace_id: u32,
    /// Parent region identifier.
    pub region_id: u32,
    /// Offset within the parent region (bytes).
    pub offset: u64,
    /// Size of this namespace in bytes.
    pub size: u64,
    /// Operating mode of this namespace.
    pub mode: PmemMode,
    /// Human-readable label (null-padded).
    pub label: [u8; MAX_LABEL_LEN],
    /// Length of the valid portion of `label`.
    label_len: usize,
    /// Whether this namespace is currently active.
    pub active: bool,
    /// Unique UUID stored as 16 raw bytes.
    pub uuid: [u8; 16],
}

impl Default for NvdimmNamespace {
    fn default() -> Self {
        Self {
            namespace_id: 0,
            region_id: 0,
            offset: 0,
            size: 0,
            mode: PmemMode::Raw,
            label: [0u8; MAX_LABEL_LEN],
            label_len: 0,
            active: false,
            uuid: [0u8; 16],
        }
    }
}

impl NvdimmNamespace {
    /// Create a new namespace within a region.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `size` is zero.
    pub fn new(
        namespace_id: u32,
        region_id: u32,
        offset: u64,
        size: u64,
        mode: PmemMode,
    ) -> Result<Self> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            namespace_id,
            region_id,
            offset,
            size,
            mode,
            label: [0u8; MAX_LABEL_LEN],
            label_len: 0,
            active: false,
            uuid: [0u8; 16],
        })
    }

    /// Set the human-readable label for this namespace.
    ///
    /// The label is truncated to [`MAX_LABEL_LEN`] bytes.
    pub fn set_label(&mut self, name: &[u8]) {
        let len = if name.len() > MAX_LABEL_LEN {
            MAX_LABEL_LEN
        } else {
            name.len()
        };
        self.label[..len].copy_from_slice(&name[..len]);
        if len < MAX_LABEL_LEN {
            self.label[len..].fill(0);
        }
        self.label_len = len;
    }

    /// Return the label as a byte slice.
    pub fn label_bytes(&self) -> &[u8] {
        &self.label[..self.label_len]
    }

    /// Set the UUID for this namespace.
    pub fn set_uuid(&mut self, uuid: [u8; 16]) {
        self.uuid = uuid;
    }

    /// Activate this namespace, making it visible to the block layer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if the namespace is already
    /// active.
    pub fn activate(&mut self) -> Result<()> {
        if self.active {
            return Err(Error::AlreadyExists);
        }
        self.active = true;
        Ok(())
    }

    /// Deactivate this namespace.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the namespace is not
    /// currently active.
    pub fn deactivate(&mut self) -> Result<()> {
        if !self.active {
            return Err(Error::InvalidArgument);
        }
        self.active = false;
        Ok(())
    }

    /// Return the end offset (exclusive) within the parent region.
    pub fn end_offset(&self) -> u64 {
        self.offset.saturating_add(self.size)
    }
}

// ---------------------------------------------------------------------------
// NvdimmDevice
// ---------------------------------------------------------------------------

/// A single NVDIMM module with health telemetry.
///
/// Represents the physical hardware module and exposes health
/// monitoring, temperature, and remaining lifetime information
/// through the NVDIMM firmware interface (_DSM methods).
#[derive(Debug, Clone, Copy)]
pub struct NvdimmDevice {
    /// Device handle (NFIT handle from ACPI).
    pub handle: u32,
    /// Vendor identifier.
    pub vendor_id: u16,
    /// Device identifier.
    pub device_id: u16,
    /// Serial number.
    pub serial_number: u32,
    /// Current health status.
    pub health: NvdimmHealthStatus,
    /// Temperature in degrees Celsius (0 if unavailable).
    pub temperature_celsius: u16,
    /// Remaining lifetime percentage (0-100, 0xFF if unavailable).
    pub remaining_life_pct: u8,
    /// Total capacity in bytes.
    pub total_capacity: u64,
    /// Whether the NVDIMM is armed for persistence (save on power loss).
    pub armed: bool,
    /// Number of unsafe shutdown events recorded.
    pub unsafe_shutdown_count: u32,
}

impl Default for NvdimmDevice {
    fn default() -> Self {
        Self {
            handle: 0,
            vendor_id: 0,
            device_id: 0,
            serial_number: 0,
            health: NvdimmHealthStatus::Unknown,
            temperature_celsius: 0,
            remaining_life_pct: 0xFF,
            total_capacity: 0,
            armed: false,
            unsafe_shutdown_count: 0,
        }
    }
}

impl NvdimmDevice {
    /// Create a new NVDIMM device descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `handle` is zero.
    pub fn new(handle: u32, vendor_id: u16, device_id: u16) -> Result<Self> {
        if handle == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            handle,
            vendor_id,
            device_id,
            serial_number: 0,
            health: NvdimmHealthStatus::Unknown,
            temperature_celsius: 0,
            remaining_life_pct: 0xFF,
            total_capacity: 0,
            armed: false,
            unsafe_shutdown_count: 0,
        })
    }

    /// Check the health status of this NVDIMM.
    ///
    /// In a real implementation this would issue a _DSM command
    /// to the NVDIMM firmware and parse the response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the health query fails.
    pub fn check_health(&mut self) -> Result<NvdimmHealthStatus> {
        // Stub: a real driver would issue ACPI _DSM function 1
        // (Get Smart and Health Info) and parse the result.
        if self.health == NvdimmHealthStatus::Fatal {
            return Err(Error::IoError);
        }
        Ok(self.health)
    }

    /// Update the health status from a raw firmware status byte.
    ///
    /// Mapping: 0 = Healthy, 1 = Warning, 2 = Critical,
    /// 3 = Fatal, anything else = Unknown.
    pub fn update_health(&mut self, raw_status: u8) {
        self.health = match raw_status {
            0 => NvdimmHealthStatus::Healthy,
            1 => NvdimmHealthStatus::Warning,
            2 => NvdimmHealthStatus::Critical,
            3 => NvdimmHealthStatus::Fatal,
            _ => NvdimmHealthStatus::Unknown,
        };
    }

    /// Update the temperature reading.
    pub fn update_temperature(&mut self, celsius: u16) {
        self.temperature_celsius = celsius;
    }

    /// Update the remaining lifetime percentage.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pct` exceeds 100
    /// (values above 100 are reserved).
    pub fn update_remaining_life(&mut self, pct: u8) -> Result<()> {
        if pct > 100 {
            return Err(Error::InvalidArgument);
        }
        self.remaining_life_pct = pct;
        Ok(())
    }

    /// Arm the NVDIMM for persistence (enable save-on-power-loss).
    pub fn arm(&mut self) {
        self.armed = true;
    }

    /// Disarm the NVDIMM (disable save-on-power-loss).
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// Return `true` if the device is in a healthy or warning state.
    pub fn is_operational(&self) -> bool {
        matches!(
            self.health,
            NvdimmHealthStatus::Healthy | NvdimmHealthStatus::Warning
        )
    }
}

// ---------------------------------------------------------------------------
// NvdimmController
// ---------------------------------------------------------------------------

/// NVDIMM controller managing regions, namespaces, and devices.
///
/// Discovered via the ACPI NFIT table. The controller maintains the
/// mapping between physical NVDIMM modules, memory regions, and
/// logical namespaces.
pub struct NvdimmController {
    /// Controller identifier.
    pub controller_id: u8,
    /// Whether the controller has been initialised.
    initialized: bool,
    /// NFIT table signature verified.
    nfit_valid: bool,
    /// Persistent memory regions.
    regions: [NvdimmRegion; MAX_REGIONS],
    /// Number of configured regions.
    region_count: usize,
    /// Namespaces.
    namespaces: [NvdimmNamespace; MAX_NAMESPACES],
    /// Number of configured namespaces.
    namespace_count: usize,
    /// Registered NVDIMM devices.
    devices: [Option<NvdimmDevice>; MAX_DEVICES],
    /// Number of registered devices.
    device_count: usize,
    /// Monotonic namespace ID generator.
    next_namespace_id: u32,
}

impl Default for NvdimmController {
    fn default() -> Self {
        Self::new()
    }
}

impl NvdimmController {
    /// Create an uninitialised NVDIMM controller.
    pub const fn new() -> Self {
        const NONE_DEVICE: Option<NvdimmDevice> = None;
        Self {
            controller_id: 0,
            initialized: false,
            nfit_valid: false,
            regions: [NvdimmRegion {
                region_id: 0,
                base_addr: 0,
                size: 0,
                dax_capable: false,
                interleave_ways: 1,
                mapped: false,
                virt_addr: 0,
            }; MAX_REGIONS],
            region_count: 0,
            namespaces: [NvdimmNamespace {
                namespace_id: 0,
                region_id: 0,
                offset: 0,
                size: 0,
                mode: PmemMode::Raw,
                label: [0u8; MAX_LABEL_LEN],
                label_len: 0,
                active: false,
                uuid: [0u8; 16],
            }; MAX_NAMESPACES],
            namespace_count: 0,
            devices: [NONE_DEVICE; MAX_DEVICES],
            device_count: 0,
            next_namespace_id: 1,
        }
    }

    /// Initialise the NVDIMM controller.
    ///
    /// Validates the NFIT signature from the provided 4-byte header
    /// and marks the controller as ready.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the NFIT signature does
    /// not match.
    pub fn init(&mut self, controller_id: u8, nfit_signature: &[u8; 4]) -> Result<()> {
        if *nfit_signature != NFIT_SIGNATURE {
            return Err(Error::InvalidArgument);
        }
        self.controller_id = controller_id;
        self.nfit_valid = true;
        self.initialized = true;
        Ok(())
    }

    /// Return `true` if the controller has been initialised.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Add a persistent memory region to the controller.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the controller is not
    ///   initialised.
    /// - [`Error::OutOfMemory`] if the region table is full.
    /// - [`Error::AlreadyExists`] if a region with the same
    ///   `region_id` already exists.
    pub fn add_region(&mut self, region: NvdimmRegion) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if self.region_count >= MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate region IDs.
        for r in &self.regions[..self.region_count] {
            if r.region_id == region.region_id {
                return Err(Error::AlreadyExists);
            }
        }
        self.regions[self.region_count] = region;
        self.region_count += 1;
        Ok(())
    }

    /// Find a region by its identifier.
    pub fn find_region(&self, region_id: u32) -> Option<&NvdimmRegion> {
        self.regions[..self.region_count]
            .iter()
            .find(|r| r.region_id == region_id)
    }

    /// Find a mutable reference to a region by its identifier.
    pub fn find_region_mut(&mut self, region_id: u32) -> Option<&mut NvdimmRegion> {
        self.regions[..self.region_count]
            .iter_mut()
            .find(|r| r.region_id == region_id)
    }

    /// Map a region into virtual address space.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no region with `region_id` exists.
    /// - [`Error::AlreadyExists`] if the region is already mapped.
    /// - [`Error::InvalidArgument`] if `virt_addr` is zero.
    pub fn map_region(&mut self, region_id: u32, virt_addr: u64) -> Result<()> {
        let region = self.find_region_mut(region_id).ok_or(Error::NotFound)?;
        region.map(virt_addr)
    }

    /// Create a new namespace within a region.
    ///
    /// The namespace is allocated starting at `offset` within the
    /// specified region. The caller must ensure the requested range
    /// does not overlap with existing namespaces.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the controller is not
    ///   initialised, `size` is zero, or the namespace would
    ///   exceed the region bounds.
    /// - [`Error::NotFound`] if the specified region does not exist.
    /// - [`Error::OutOfMemory`] if the namespace table is full.
    pub fn create_namespace(
        &mut self,
        region_id: u32,
        offset: u64,
        size: u64,
        mode: PmemMode,
    ) -> Result<u32> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if self.namespace_count >= MAX_NAMESPACES {
            return Err(Error::OutOfMemory);
        }

        // Validate the region exists and the range is in bounds.
        let region = self.find_region(region_id).ok_or(Error::NotFound)?;
        let end = offset.saturating_add(size);
        if end > region.size || size == 0 {
            return Err(Error::InvalidArgument);
        }

        let ns_id = self.next_namespace_id;
        self.next_namespace_id += 1;

        let ns = NvdimmNamespace::new(ns_id, region_id, offset, size, mode)?;
        self.namespaces[self.namespace_count] = ns;
        self.namespace_count += 1;
        Ok(ns_id)
    }

    /// Find a namespace by its identifier.
    pub fn find_namespace(&self, namespace_id: u32) -> Option<&NvdimmNamespace> {
        self.namespaces[..self.namespace_count]
            .iter()
            .find(|ns| ns.namespace_id == namespace_id)
    }

    /// Find a mutable reference to a namespace by its identifier.
    pub fn find_namespace_mut(&mut self, namespace_id: u32) -> Option<&mut NvdimmNamespace> {
        self.namespaces[..self.namespace_count]
            .iter_mut()
            .find(|ns| ns.namespace_id == namespace_id)
    }

    /// Activate a namespace, making it visible to the block layer.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the namespace does not exist.
    /// - [`Error::AlreadyExists`] if it is already active.
    pub fn activate_namespace(&mut self, namespace_id: u32) -> Result<()> {
        let ns = self
            .find_namespace_mut(namespace_id)
            .ok_or(Error::NotFound)?;
        ns.activate()
    }

    /// Deactivate a namespace.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the namespace does not exist.
    /// - [`Error::InvalidArgument`] if it is not currently active.
    pub fn deactivate_namespace(&mut self, namespace_id: u32) -> Result<()> {
        let ns = self
            .find_namespace_mut(namespace_id)
            .ok_or(Error::NotFound)?;
        ns.deactivate()
    }

    /// Register an NVDIMM device.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the controller is not
    ///   initialised.
    /// - [`Error::OutOfMemory`] if the device table is full.
    /// - [`Error::AlreadyExists`] if a device with the same handle
    ///   is already registered.
    pub fn register_device(&mut self, device: NvdimmDevice) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        for slot in self.devices.iter().flatten() {
            if slot.handle == device.handle {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.devices {
            if slot.is_none() {
                *slot = Some(device);
                self.device_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a device by its NFIT handle.
    pub fn find_device(&self, handle: u32) -> Option<&NvdimmDevice> {
        self.devices
            .iter()
            .find_map(|slot| slot.as_ref().filter(|d| d.handle == handle))
    }

    /// Find a mutable reference to a device by its NFIT handle.
    pub fn find_device_mut(&mut self, handle: u32) -> Option<&mut NvdimmDevice> {
        self.devices
            .iter_mut()
            .find_map(|slot| slot.as_mut().filter(|d| d.handle == handle))
    }

    /// Issue a cache flush (CLFLUSH/CLWB equivalent) for the
    /// specified region.
    ///
    /// Ensures all stores to persistent memory within the region
    /// have been flushed from CPU caches to the NVDIMM media.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the region does not exist.
    /// - [`Error::InvalidArgument`] if the region is not mapped.
    pub fn flush(&self, region_id: u32) -> Result<()> {
        let region = self.find_region(region_id).ok_or(Error::NotFound)?;
        if !region.mapped {
            return Err(Error::InvalidArgument);
        }
        // Stub: a real implementation would iterate over the
        // virtual address range and issue CLWB + SFENCE.
        Ok(())
    }

    /// Check health of all registered NVDIMM devices.
    ///
    /// Returns the number of devices reporting a non-healthy state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the controller is not
    /// initialised.
    pub fn check_all_health(&mut self) -> Result<usize> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        let mut unhealthy = 0usize;
        for slot in &mut self.devices {
            if let Some(dev) = slot {
                if let Ok(status) = dev.check_health() {
                    if status != NvdimmHealthStatus::Healthy {
                        unhealthy += 1;
                    }
                } else {
                    unhealthy += 1;
                }
            }
        }
        Ok(unhealthy)
    }

    /// Return the number of configured regions.
    pub fn region_count(&self) -> usize {
        self.region_count
    }

    /// Return the number of configured namespaces.
    pub fn namespace_count(&self) -> usize {
        self.namespace_count
    }

    /// Return the number of registered devices.
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    /// Return the total persistent memory capacity across all regions
    /// in bytes.
    pub fn total_capacity(&self) -> u64 {
        let mut total: u64 = 0;
        for r in &self.regions[..self.region_count] {
            total = total.saturating_add(r.size);
        }
        total
    }
}

// ---------------------------------------------------------------------------
// NvdimmRegistry
// ---------------------------------------------------------------------------

/// System-wide registry of NVDIMM controllers.
///
/// Tracks up to [`MAX_CONTROLLERS`] controllers discovered via ACPI
/// NFIT table parsing. Provides lookup by controller ID and aggregate
/// capacity reporting.
pub struct NvdimmRegistry {
    /// Registered controllers.
    controllers: [Option<NvdimmController>; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for NvdimmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NvdimmRegistry {
    /// Create an empty NVDIMM controller registry.
    pub const fn new() -> Self {
        const NONE: Option<NvdimmController> = None;
        Self {
            controllers: [NONE; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Register a new NVDIMM controller.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::AlreadyExists`] if a controller with the same
    ///   `controller_id` is already registered.
    pub fn register(&mut self, controller: NvdimmController) -> Result<()> {
        for slot in self.controllers.iter().flatten() {
            if slot.controller_id == controller.controller_id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.controllers {
            if slot.is_none() {
                *slot = Some(controller);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a controller by its identifier.
    pub fn find(&self, controller_id: u8) -> Option<&NvdimmController> {
        self.controllers
            .iter()
            .find_map(|slot| slot.as_ref().filter(|c| c.controller_id == controller_id))
    }

    /// Find a mutable reference to a controller by its identifier.
    pub fn find_mut(&mut self, controller_id: u8) -> Option<&mut NvdimmController> {
        self.controllers
            .iter_mut()
            .find_map(|slot| slot.as_mut().filter(|c| c.controller_id == controller_id))
    }

    /// Return the total persistent memory capacity across all
    /// controllers in bytes.
    pub fn total_capacity(&self) -> u64 {
        let mut total: u64 = 0;
        for ctrl in self.controllers.iter().flatten() {
            total = total.saturating_add(ctrl.total_capacity());
        }
        total
    }

    /// Return the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
