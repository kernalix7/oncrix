// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVDIMM persistent memory driver.
//!
//! Provides support for Non-Volatile Dual In-line Memory Module (NVDIMM)
//! devices that offer byte-addressable persistent storage. NVDIMMs retain
//! data across power cycles and can be accessed using standard load/store
//! instructions (DAX mode) or through a block device interface.
//!
//! # Architecture
//!
//! - **NvdimmRegion** — a physical persistent memory region exposed by
//!   firmware (e.g., ACPI NFIT). Regions may be interleaved across
//!   multiple DIMMs.
//! - **NvdimmNamespace** — a logical partition within a region, analogous
//!   to a partition on a disk. Namespaces can operate in raw, sector,
//!   DAX, or filesystem-DAX modes.
//! - **DaxMapping** — a direct-access mapping that bypasses the page cache,
//!   allowing user space to `mmap` persistent memory directly.
//! - **NvdimmDevice** — represents a single NVDIMM with its regions,
//!   namespaces, and health/flush capabilities.
//! - **NvdimmRegistry** — manages up to [`MAX_NVDIMMS`] devices.
//!
//! # References
//!
//! - ACPI 6.4, §5.2.25 (NVDIMM Firmware Interface Table — NFIT)
//! - UEFI 2.9, §13.6 (Block Translation Table)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of NVDIMM devices in the registry.
const MAX_NVDIMMS: usize = 8;

/// Maximum regions per NVDIMM device.
const MAX_REGIONS: usize = 8;

/// Maximum namespaces per NVDIMM device.
const MAX_NAMESPACES: usize = 16;

/// Maximum DAX mappings per device.
const MAX_DAX_MAPPINGS: usize = 16;

/// Label size in bytes.
const LABEL_SIZE: usize = 64;

/// UUID size in bytes.
const UUID_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// NvdimmType
// ---------------------------------------------------------------------------

/// Type of NVDIMM access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NvdimmType {
    /// Persistent memory (byte-addressable, load/store access).
    #[default]
    Pmem,
    /// Block-mode access (via BIOS block window).
    Block,
    /// Byte-addressable aperture (control region).
    Byte,
}

// ---------------------------------------------------------------------------
// NvdimmHealth
// ---------------------------------------------------------------------------

/// Health status of an NVDIMM device or region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NvdimmHealth {
    /// Device is healthy and operating normally.
    #[default]
    Ok,
    /// Device is degraded but still functional.
    Degraded,
    /// Device has failed or is not responding.
    Failed,
    /// Health status is unknown.
    Unknown,
}

// ---------------------------------------------------------------------------
// NamespaceMode
// ---------------------------------------------------------------------------

/// Operating mode of an NVDIMM namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NamespaceMode {
    /// Raw mode — no metadata, direct access to persistent memory.
    #[default]
    Raw,
    /// Sector mode — 4 KiB atomic sector writes with BTT.
    Sector,
    /// DAX mode — direct access mapping for `mmap`.
    Dax,
    /// Filesystem-DAX — filesystem with direct access support.
    Fsdax,
}

// ---------------------------------------------------------------------------
// NvdimmRegion
// ---------------------------------------------------------------------------

/// A physical persistent memory region.
///
/// Regions are discovered via firmware tables (e.g., ACPI NFIT) and
/// represent contiguous ranges of persistent memory that may span
/// multiple interleaved DIMMs.
#[derive(Debug, Clone, Copy)]
pub struct NvdimmRegion {
    /// Region identifier.
    pub id: u32,
    /// Physical base address of the region.
    pub base_addr: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Access type for this region.
    pub nvdimm_type: NvdimmType,
    /// Number of interleave ways (1 = no interleaving).
    pub interleave_ways: u32,
    /// Health status of this region.
    pub health: NvdimmHealth,
    /// Whether this region is active.
    pub active: bool,
}

impl NvdimmRegion {
    /// Creates a new persistent memory region.
    pub const fn new(id: u32, base_addr: u64, size: u64, nvdimm_type: NvdimmType) -> Self {
        Self {
            id,
            base_addr,
            size,
            nvdimm_type,
            interleave_ways: 1,
            health: NvdimmHealth::Ok,
            active: true,
        }
    }

    /// Returns the end address (exclusive) of this region.
    pub const fn end_addr(&self) -> u64 {
        self.base_addr + self.size
    }

    /// Checks whether an address falls within this region.
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base_addr && addr < self.end_addr()
    }
}

// ---------------------------------------------------------------------------
// NvdimmNamespace
// ---------------------------------------------------------------------------

/// A logical namespace within a persistent memory region.
///
/// Namespaces partition a region into independently addressable
/// units, each with its own label, UUID, and operating mode.
#[derive(Debug, Clone, Copy)]
pub struct NvdimmNamespace {
    /// Namespace identifier.
    pub id: u32,
    /// Region that contains this namespace.
    pub region_id: u32,
    /// Byte offset within the parent region.
    pub offset: u64,
    /// Size of the namespace in bytes.
    pub size: u64,
    /// Human-readable label (null-padded).
    pub label: [u8; LABEL_SIZE],
    /// Number of valid bytes in [`label`](Self::label).
    pub label_len: usize,
    /// Universally unique identifier.
    pub uuid: [u8; UUID_SIZE],
    /// Operating mode.
    pub mode: NamespaceMode,
    /// Whether this namespace is active.
    pub active: bool,
}

impl NvdimmNamespace {
    /// Creates a new namespace within the given region.
    pub const fn new(id: u32, region_id: u32, offset: u64, size: u64) -> Self {
        Self {
            id,
            region_id,
            offset,
            size,
            label: [0u8; LABEL_SIZE],
            label_len: 0,
            uuid: [0u8; UUID_SIZE],
            mode: NamespaceMode::Raw,
            active: true,
        }
    }

    /// Sets the label from a byte slice, truncating to [`LABEL_SIZE`].
    pub fn set_label(&mut self, name: &[u8]) {
        let copy_len = name.len().min(LABEL_SIZE);
        self.label[..copy_len].copy_from_slice(&name[..copy_len]);
        if copy_len < LABEL_SIZE {
            self.label[copy_len..].fill(0);
        }
        self.label_len = copy_len;
    }

    /// Sets the UUID.
    pub fn set_uuid(&mut self, uuid: &[u8; UUID_SIZE]) {
        self.uuid = *uuid;
    }
}

// ---------------------------------------------------------------------------
// DaxMapping
// ---------------------------------------------------------------------------

/// A direct-access (DAX) mapping that bypasses the page cache.
///
/// DAX mappings allow user-space processes to `mmap` persistent memory
/// directly, enabling load/store access without any file-system or
/// block-layer overhead.
#[derive(Debug, Clone, Copy)]
pub struct DaxMapping {
    /// Virtual address of the mapping.
    pub virtual_addr: u64,
    /// Physical address of the backing persistent memory.
    pub phys_addr: u64,
    /// Size of the mapping in bytes.
    pub size: u64,
    /// Whether this mapping is active.
    pub active: bool,
}

impl DaxMapping {
    /// Creates a new DAX mapping.
    pub const fn new(virtual_addr: u64, phys_addr: u64, size: u64) -> Self {
        Self {
            virtual_addr,
            phys_addr,
            size,
            active: true,
        }
    }

    /// Returns the end virtual address (exclusive).
    pub const fn virtual_end(&self) -> u64 {
        self.virtual_addr + self.size
    }

    /// Checks whether a virtual address falls within this mapping.
    pub const fn contains_virtual(&self, addr: u64) -> bool {
        addr >= self.virtual_addr && addr < self.virtual_end()
    }

    /// Translates a virtual address to the corresponding physical address.
    ///
    /// Returns [`None`] if the address is outside this mapping.
    pub const fn translate(&self, vaddr: u64) -> Option<u64> {
        if self.contains_virtual(vaddr) {
            Some(self.phys_addr + (vaddr - self.virtual_addr))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// NvdimmDevice
// ---------------------------------------------------------------------------

/// An NVDIMM persistent memory device.
///
/// Represents a single NVDIMM with its regions, namespaces, DAX
/// mappings, and health/flush capabilities.
pub struct NvdimmDevice {
    /// Device identifier.
    pub id: u32,
    /// Persistent memory regions.
    regions: [Option<NvdimmRegion>; MAX_REGIONS],
    /// Number of active regions.
    region_count: usize,
    /// Namespaces.
    namespaces: [Option<NvdimmNamespace>; MAX_NAMESPACES],
    /// Number of active namespaces.
    namespace_count: usize,
    /// DAX mappings.
    dax_mappings: [Option<DaxMapping>; MAX_DAX_MAPPINGS],
    /// Number of active DAX mappings.
    dax_mapping_count: usize,
    /// Overall device health.
    pub health: NvdimmHealth,
    /// Whether the device has been initialized.
    initialized: bool,
}

impl NvdimmDevice {
    /// Creates a new NVDIMM device.
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            regions: [const { None }; MAX_REGIONS],
            region_count: 0,
            namespaces: [const { None }; MAX_NAMESPACES],
            namespace_count: 0,
            dax_mappings: [const { None }; MAX_DAX_MAPPINGS],
            dax_mapping_count: 0,
            health: NvdimmHealth::Ok,
            initialized: false,
        }
    }

    /// Initializes the NVDIMM device.
    ///
    /// This should be called after regions and namespaces have been
    /// configured from firmware tables.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::Busy);
        }
        self.health = NvdimmHealth::Ok;
        self.initialized = true;
        Ok(())
    }

    /// Returns whether the device is initialized.
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -- Region management -------------------------------------------------

    /// Adds a persistent memory region to this device.
    pub fn add_region(&mut self, region: NvdimmRegion) -> Result<()> {
        // Check for duplicate region ID.
        for slot in &self.regions {
            if let Some(ref r) = *slot {
                if r.id == region.id {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        for slot in &mut self.regions {
            if slot.is_none() {
                *slot = Some(region);
                self.region_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to the region with the given `id`.
    pub fn get_region(&self, id: u32) -> Option<&NvdimmRegion> {
        self.regions.iter().flatten().find(|r| r.id == id)
    }

    /// Returns the number of active regions.
    pub const fn region_count(&self) -> usize {
        self.region_count
    }

    // -- Namespace management -----------------------------------------------

    /// Adds a namespace to this device.
    ///
    /// The namespace's `region_id` must refer to a region that has
    /// already been added to this device.
    pub fn add_namespace(&mut self, ns: NvdimmNamespace) -> Result<()> {
        // Verify region exists.
        if self.get_region(ns.region_id).is_none() {
            return Err(Error::NotFound);
        }
        // Check for duplicate namespace ID.
        for slot in &self.namespaces {
            if let Some(ref n) = *slot {
                if n.id == ns.id {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        for slot in &mut self.namespaces {
            if slot.is_none() {
                *slot = Some(ns);
                self.namespace_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to the namespace with the given `id`.
    pub fn get_namespace(&self, id: u32) -> Option<&NvdimmNamespace> {
        self.namespaces.iter().flatten().find(|n| n.id == id)
    }

    /// Returns the number of active namespaces.
    pub const fn namespace_count(&self) -> usize {
        self.namespace_count
    }

    // -- DAX mapping management ---------------------------------------------

    /// Creates a DAX mapping for direct access to persistent memory.
    pub fn add_dax_mapping(&mut self, mapping: DaxMapping) -> Result<()> {
        for slot in &mut self.dax_mappings {
            if slot.is_none() {
                *slot = Some(mapping);
                self.dax_mapping_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns the DAX mapping that contains the given virtual address.
    pub fn find_dax_mapping(&self, vaddr: u64) -> Option<&DaxMapping> {
        self.dax_mappings
            .iter()
            .flatten()
            .find(|m| m.active && m.contains_virtual(vaddr))
    }

    /// Returns the number of active DAX mappings.
    pub const fn dax_mapping_count(&self) -> usize {
        self.dax_mapping_count
    }

    // -- Persistence operations ---------------------------------------------

    /// Flushes a cache line to ensure data reaches persistent media.
    ///
    /// On x86_64 this would use `CLFLUSH` / `CLWB` + `SFENCE`.
    /// Here we issue a memory barrier as a placeholder.
    pub fn flush(&self, addr: u64, size: u64) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        // Verify the address falls within a known region.
        let in_region = self
            .regions
            .iter()
            .flatten()
            .any(|r| r.active && r.contains(addr));
        if !in_region {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Memory fence to order stores before flush.
        // On real hardware this would be CLWB + SFENCE sequences.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("sfence", options(nostack, preserves_flags));
        }
        let _ = (addr, size); // used in real flush loop
        Ok(())
    }

    /// Persists all outstanding writes to this device.
    ///
    /// Equivalent to flushing the entire address range of all
    /// active regions.
    pub fn persist(&self) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        for region in self.regions.iter().flatten() {
            if region.active && region.size > 0 {
                self.flush(region.base_addr, region.size)?;
            }
        }
        Ok(())
    }

    // -- Health check -------------------------------------------------------

    /// Performs a health check on this NVDIMM device.
    ///
    /// Inspects all regions and returns the worst health status found.
    pub fn health_check(&mut self) -> NvdimmHealth {
        let mut worst = NvdimmHealth::Ok;
        for region in self.regions.iter().flatten() {
            if !region.active {
                continue;
            }
            match region.health {
                NvdimmHealth::Failed => {
                    worst = NvdimmHealth::Failed;
                    break; // cannot be worse
                }
                NvdimmHealth::Degraded => {
                    worst = NvdimmHealth::Degraded;
                }
                NvdimmHealth::Unknown if worst == NvdimmHealth::Ok => {
                    worst = NvdimmHealth::Unknown;
                }
                _ => {}
            }
        }
        self.health = worst;
        worst
    }

    /// Returns the total persistent memory size across all active regions.
    pub fn total_persistent_bytes(&self) -> u64 {
        self.regions
            .iter()
            .flatten()
            .filter(|r| r.active)
            .map(|r| r.size)
            .sum()
    }
}

impl core::fmt::Debug for NvdimmDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NvdimmDevice")
            .field("id", &self.id)
            .field("regions", &self.region_count)
            .field("namespaces", &self.namespace_count)
            .field("dax_mappings", &self.dax_mapping_count)
            .field("health", &self.health)
            .field("initialized", &self.initialized)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// NvdimmRegistry
// ---------------------------------------------------------------------------

/// Registry that manages multiple [`NvdimmDevice`] instances.
///
/// Supports up to [`MAX_NVDIMMS`] concurrently registered devices and
/// provides aggregate statistics for total persistent memory.
pub struct NvdimmRegistry {
    /// Registered NVDIMM devices.
    devices: [Option<NvdimmDevice>; MAX_NVDIMMS],
    /// Number of currently registered devices.
    count: usize,
}

impl Default for NvdimmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NvdimmRegistry {
    /// Creates a new, empty NVDIMM registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_NVDIMMS],
            count: 0,
        }
    }

    /// Registers an NVDIMM device.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same id exists.
    pub fn register(&mut self, device: NvdimmDevice) -> Result<()> {
        for slot in &self.devices {
            if let Some(ref d) = *slot {
                if d.id == device.id {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        for slot in &mut self.devices {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters the device with the given `id`.
    ///
    /// Returns [`Error::NotFound`] if no device with that id exists.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        for slot in &mut self.devices {
            if let Some(ref d) = *slot {
                if d.id == id {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a shared reference to the device with the given `id`.
    pub fn find(&self, id: u32) -> Option<&NvdimmDevice> {
        self.devices.iter().flatten().find(|d| d.id == id)
    }

    /// Returns a mutable reference to the device with the given `id`.
    pub fn find_mut(&mut self, id: u32) -> Option<&mut NvdimmDevice> {
        self.devices.iter_mut().flatten().find(|d| d.id == id)
    }

    /// Returns the total persistent memory across all registered devices.
    pub fn total_persistent_bytes(&self) -> u64 {
        self.devices
            .iter()
            .flatten()
            .map(|d| d.total_persistent_bytes())
            .sum()
    }

    /// Returns the number of registered devices.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}
