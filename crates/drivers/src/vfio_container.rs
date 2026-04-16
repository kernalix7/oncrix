// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VFIO (Virtual Function I/O) container driver for device passthrough.
//!
//! Implements the VFIO framework that allows user-space processes to own
//! and drive PCI/PCIe devices directly, bypassing the kernel driver stack,
//! while leveraging the IOMMU for DMA isolation and safety.
//!
//! # Architecture
//!
//! ```text
//! User space          Kernel (this module)         Hardware
//! ──────────          ────────────────────         ────────
//! VfioContainer  ←──► VfioContainer (kernel) ←──► IOMMU
//!   │                   │                          PCI device
//!   └── VfioGroup       └── VfioGroup
//!         │                   │
//!         └── VfioDevice      └── DMA mappings (IOVA → PA)
//! ```
//!
//! - **[`VfioContainer`]** — top-level object; an IOMMU domain.
//!   Holds up to [`MAX_GROUPS`] IOMMU groups and [`MAX_DMA_MAPS`] DMA
//!   mappings.  The container selects an IOMMU type before groups are
//!   bound.
//! - **[`VfioGroup`]** — an IOMMU group, i.e. the smallest set of
//!   devices that share a single IOMMU translation context.  Holds up
//!   to [`MAX_DEVICES_PER_GROUP`] device identifiers.
//! - **[`VfioDmaMap`]** — a single IOVA→physical-address mapping entry.
//! - **[`VfioRegionInfo`]** — describes a device BAR region accessible
//!   from user space.
//! - **[`VfioIrqInfo`]** — describes an interrupt vector forwarded to
//!   user space via an eventfd-like notification.
//! - **[`VfioContainerRegistry`]** — manages up to [`MAX_CONTAINERS`]
//!   active containers.
//!
//! # IOMMU types
//!
//! | Type | Description |
//! |------|-------------|
//! | `Type1Dma` | Intel VT-d / AMD-Vi — standard Type 1 IOMMU DMA remapping |
//! | `SpaprTce` | IBM SPAPR TCE — used on IBM POWER platforms |
//!
//! # DMA map/unmap protocol
//!
//! 1. Open/obtain a container (`VfioContainerRegistry::create`).
//! 2. Set the IOMMU type (`VfioContainer::set_iommu_type`).
//! 3. Add IOMMU group(s) (`VfioContainer::add_group`).
//! 4. Map device memory into the IOVA space (`VfioContainer::map_dma`).
//! 5. Drive the device from user space using BAR regions.
//! 6. Unmap and destroy when done (`VfioContainer::unmap_dma`,
//!    `VfioContainerRegistry::destroy`).
//!
//! # Reference
//!
//! - Linux kernel Documentation/driver-api/vfio.rst
//! - Intel VT-d Specification, rev 4.0
//! - VFIO UAPI headers: `include/uapi/linux/vfio.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Size constants
// ---------------------------------------------------------------------------

/// Maximum number of concurrent containers.
pub const MAX_CONTAINERS: usize = 16;

/// Maximum number of IOMMU groups per container.
pub const MAX_GROUPS: usize = 8;

/// Maximum number of DMA mappings per container.
pub const MAX_DMA_MAPS: usize = 256;

/// Maximum number of device identifiers per group.
pub const MAX_DEVICES_PER_GROUP: usize = 8;

/// Maximum number of BAR regions per device descriptor.
pub const MAX_REGIONS: usize = 6;

/// Maximum number of IRQ vectors per device descriptor.
pub const MAX_IRQ_VECTORS: usize = 32;

/// Length of a device name / BDF string (e.g. "0000:01:00.0").
const DEV_NAME_LEN: usize = 16;

// ---------------------------------------------------------------------------
// IommuType
// ---------------------------------------------------------------------------

/// IOMMU backend type for a VFIO container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IommuType {
    /// Not yet configured.
    None,
    /// Standard Type 1 DMA IOMMU (Intel VT-d, AMD-Vi).
    Type1Dma,
    /// IBM SPAPR TCE IOMMU (POWER platforms).
    SpaprTce,
}

impl Default for IommuType {
    fn default() -> Self {
        IommuType::None
    }
}

// ---------------------------------------------------------------------------
// DmaFlags
// ---------------------------------------------------------------------------

/// Flags controlling DMA mapping attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DmaFlags(pub u32);

impl DmaFlags {
    /// Allow device to read from this mapping.
    pub const READ: u32 = 1 << 0;
    /// Allow device to write to this mapping.
    pub const WRITE: u32 = 1 << 1;

    /// Mapping is readable.
    pub const fn readable(self) -> bool {
        self.0 & Self::READ != 0
    }

    /// Mapping is writable.
    pub const fn writable(self) -> bool {
        self.0 & Self::WRITE != 0
    }

    /// Both read and write.
    pub const fn rw() -> Self {
        Self(Self::READ | Self::WRITE)
    }
}

// ---------------------------------------------------------------------------
// VfioDmaMap
// ---------------------------------------------------------------------------

/// A single DMA mapping: IOVA → physical address.
///
/// The IOMMU is programmed to translate device bus-addresses (IOVA)
/// in the range `[iova, iova + size)` to host physical addresses in
/// the range `[phys_addr, phys_addr + size)`.
#[derive(Debug, Clone, Copy)]
pub struct VfioDmaMap {
    /// I/O Virtual Address — the address the device will use.
    pub iova: u64,
    /// Host physical address backing this mapping.
    pub phys_addr: u64,
    /// Size of the mapping in bytes. Must be page-aligned.
    pub size: u64,
    /// Access flags.
    pub flags: DmaFlags,
    /// Whether this mapping entry is active.
    pub active: bool,
}

impl VfioDmaMap {
    /// Creates a new DMA mapping entry.
    pub const fn new(iova: u64, phys_addr: u64, size: u64, flags: DmaFlags) -> Self {
        Self {
            iova,
            phys_addr,
            size,
            flags,
            active: true,
        }
    }

    /// Returns the end IOVA (exclusive).
    pub const fn iova_end(&self) -> u64 {
        self.iova.saturating_add(self.size)
    }

    /// Returns `true` if `iova_addr` falls within this mapping.
    pub const fn contains_iova(&self, iova_addr: u64) -> bool {
        iova_addr >= self.iova && iova_addr < self.iova_end()
    }

    /// Translates an IOVA to the host physical address.
    ///
    /// Returns `None` if the address is outside this mapping.
    pub const fn translate(&self, iova_addr: u64) -> Option<u64> {
        if self.contains_iova(iova_addr) {
            Some(self.phys_addr + (iova_addr - self.iova))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// RegionFlags
// ---------------------------------------------------------------------------

/// Flags for a device BAR region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegionFlags(pub u32);

impl RegionFlags {
    /// Region is readable.
    pub const READ: u32 = 1 << 0;
    /// Region is writable.
    pub const WRITE: u32 = 1 << 1;
    /// Region supports mmap (memory-mapped).
    pub const MMAP: u32 = 1 << 2;

    /// Region is readable.
    pub const fn readable(self) -> bool {
        self.0 & Self::READ != 0
    }

    /// Region is writable.
    pub const fn writable(self) -> bool {
        self.0 & Self::WRITE != 0
    }

    /// Region can be mmap'd.
    pub const fn mmapable(self) -> bool {
        self.0 & Self::MMAP != 0
    }
}

// ---------------------------------------------------------------------------
// VfioRegionInfo
// ---------------------------------------------------------------------------

/// Information about a device BAR (Base Address Register) region.
///
/// Describes the size, offset within the device's address space, and
/// access flags for a single BAR.  User space uses this to mmap or
/// pread/pwrite the BAR through the device fd.
#[derive(Debug, Clone, Copy)]
pub struct VfioRegionInfo {
    /// BAR index (0–5 for PCI standard BARs).
    pub index: u32,
    /// Byte offset of this region within the device descriptor space.
    /// User space uses this offset when issuing mmap on the device fd.
    pub offset: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Access flags.
    pub flags: RegionFlags,
    /// Whether this region entry is populated.
    pub valid: bool,
}

impl VfioRegionInfo {
    /// Creates a new region info entry.
    pub const fn new(index: u32, offset: u64, size: u64, flags: RegionFlags) -> Self {
        Self {
            index,
            offset,
            size,
            flags,
            valid: true,
        }
    }

    /// Returns an invalid/empty region info entry.
    pub const fn empty() -> Self {
        Self {
            index: 0,
            offset: 0,
            size: 0,
            flags: RegionFlags(0),
            valid: false,
        }
    }
}

// ---------------------------------------------------------------------------
// IrqType
// ---------------------------------------------------------------------------

/// Interrupt type for a VFIO IRQ vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqType {
    /// Legacy INTx interrupt.
    Intx,
    /// MSI interrupt.
    Msi,
    /// MSI-X interrupt.
    MsiX,
    /// Error interrupt.
    Err,
}

// ---------------------------------------------------------------------------
// VfioIrqInfo
// ---------------------------------------------------------------------------

/// Interrupt vector information for a VFIO device.
///
/// VFIO forwards device interrupts to user space via eventfd-style
/// notifications.  Each `VfioIrqInfo` entry describes one interrupt
/// vector and the associated notification channel.
#[derive(Debug, Clone, Copy)]
pub struct VfioIrqInfo {
    /// Interrupt index (vector number within the device's IRQ set).
    pub index: u32,
    /// IRQ type (INTx, MSI, MSI-X, error).
    pub irq_type: IrqType,
    /// Number of sub-vectors in this set (1 for INTx/MSI, N for MSI-X).
    pub count: u32,
    /// Eventfd handle for user-space notification.
    /// Conceptually maps to an eventfd file descriptor; here stored as
    /// an opaque 32-bit handle (0 = not configured).
    pub eventfd: u32,
    /// Whether this IRQ entry is configured.
    pub active: bool,
}

impl VfioIrqInfo {
    /// Creates a new IRQ info entry.
    pub const fn new(index: u32, irq_type: IrqType, count: u32) -> Self {
        Self {
            index,
            irq_type,
            count,
            eventfd: 0,
            active: true,
        }
    }

    /// Returns an inactive/empty IRQ info entry.
    pub const fn empty() -> Self {
        Self {
            index: 0,
            irq_type: IrqType::Intx,
            count: 0,
            eventfd: 0,
            active: false,
        }
    }

    /// Associates an eventfd handle with this interrupt.
    pub fn set_eventfd(&mut self, handle: u32) {
        self.eventfd = handle;
    }
}

// ---------------------------------------------------------------------------
// VfioGroup
// ---------------------------------------------------------------------------

/// An IOMMU group — the smallest isolatable set of devices.
///
/// All devices in a group share an IOMMU translation context; they must
/// all be bound to the same container before any can be used.
#[derive(Debug)]
pub struct VfioGroup {
    /// Group identifier (matches the kernel IOMMU group number).
    pub group_id: u32,
    /// Device names (PCI BDF strings) bound to this group.
    devices: [[u8; DEV_NAME_LEN]; MAX_DEVICES_PER_GROUP],
    /// Number of valid bytes in each device name entry.
    device_name_lens: [usize; MAX_DEVICES_PER_GROUP],
    /// Number of devices bound.
    device_count: usize,
    /// Region info for the first device in this group (simplified:
    /// a real implementation would index by device).
    pub regions: [VfioRegionInfo; MAX_REGIONS],
    /// IRQ vectors for the first device in this group.
    pub irqs: [VfioIrqInfo; MAX_IRQ_VECTORS],
    /// Whether this group is valid/active.
    pub active: bool,
}

impl VfioGroup {
    /// Creates a new, empty group with the given `group_id`.
    pub fn new(group_id: u32) -> Self {
        Self {
            group_id,
            devices: [[0u8; DEV_NAME_LEN]; MAX_DEVICES_PER_GROUP],
            device_name_lens: [0usize; MAX_DEVICES_PER_GROUP],
            device_count: 0,
            regions: [const { VfioRegionInfo::empty() }; MAX_REGIONS],
            irqs: [const { VfioIrqInfo::empty() }; MAX_IRQ_VECTORS],
            active: true,
        }
    }

    /// Binds a device (identified by its BDF string) to this group.
    ///
    /// Returns [`Error::OutOfMemory`] if the group is full.
    /// Returns [`Error::AlreadyExists`] if the device is already bound.
    pub fn bind_device(&mut self, bdf: &[u8]) -> Result<()> {
        let copy_len = bdf.len().min(DEV_NAME_LEN);
        // Check for duplicate.
        for (i, name_len) in self.device_name_lens[..self.device_count]
            .iter()
            .enumerate()
        {
            if *name_len == copy_len && self.devices[i][..copy_len] == bdf[..copy_len] {
                return Err(Error::AlreadyExists);
            }
        }
        if self.device_count >= MAX_DEVICES_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        let idx = self.device_count;
        self.devices[idx][..copy_len].copy_from_slice(&bdf[..copy_len]);
        self.device_name_lens[idx] = copy_len;
        self.device_count += 1;
        Ok(())
    }

    /// Returns the number of devices bound to this group.
    pub const fn device_count(&self) -> usize {
        self.device_count
    }

    /// Registers a region info entry for this group's device.
    ///
    /// `info.index` must be in `0..MAX_REGIONS`.
    pub fn set_region(&mut self, info: VfioRegionInfo) -> Result<()> {
        let idx = info.index as usize;
        if idx >= MAX_REGIONS {
            return Err(Error::InvalidArgument);
        }
        self.regions[idx] = info;
        Ok(())
    }

    /// Returns the region info for BAR `index`.
    pub fn get_region(&self, index: u32) -> Option<&VfioRegionInfo> {
        let idx = index as usize;
        if idx < MAX_REGIONS && self.regions[idx].valid {
            Some(&self.regions[idx])
        } else {
            None
        }
    }

    /// Registers an IRQ info entry for this group's device.
    ///
    /// `info.index` must be in `0..MAX_IRQ_VECTORS`.
    pub fn set_irq(&mut self, info: VfioIrqInfo) -> Result<()> {
        let idx = info.index as usize;
        if idx >= MAX_IRQ_VECTORS {
            return Err(Error::InvalidArgument);
        }
        self.irqs[idx] = info;
        Ok(())
    }

    /// Returns the IRQ info for vector `index`.
    pub fn get_irq(&self, index: u32) -> Option<&VfioIrqInfo> {
        let idx = index as usize;
        if idx < MAX_IRQ_VECTORS && self.irqs[idx].active {
            Some(&self.irqs[idx])
        } else {
            None
        }
    }

    /// Delivers an interrupt notification for vector `index`.
    ///
    /// In a real implementation this would signal the user-space process
    /// via the configured eventfd.  Here it validates the vector and
    /// returns the configured eventfd handle.
    ///
    /// Returns [`Error::NotFound`] if the vector is not configured.
    pub fn notify_irq(&self, index: u32) -> Result<u32> {
        let info = self.get_irq(index).ok_or(Error::NotFound)?;
        if info.eventfd == 0 {
            return Err(Error::NotFound);
        }
        // Real impl: write(1) to the eventfd fd.
        Ok(info.eventfd)
    }
}

// ---------------------------------------------------------------------------
// VfioIoctl
// ---------------------------------------------------------------------------

/// VFIO container ioctl command codes.
///
/// These mirror the `VFIO_` ioctl constants from `<linux/vfio.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfioIoctl {
    /// `VFIO_SET_IOMMU` — configure the IOMMU type for the container.
    SetIommu,
    /// `VFIO_IOMMU_MAP_DMA` — add a DMA mapping.
    MapDma,
    /// `VFIO_IOMMU_UNMAP_DMA` — remove a DMA mapping.
    UnmapDma,
    /// `VFIO_IOMMU_GET_INFO` — query IOMMU capabilities.
    GetInfo,
}

// ---------------------------------------------------------------------------
// VfioContainer
// ---------------------------------------------------------------------------

/// A VFIO container — an IOMMU domain that owns a set of groups and
/// their DMA address space.
///
/// # DMA mapping invariants
///
/// - IOVA ranges of active mappings must not overlap.
/// - `size` must be greater than zero.
/// - Adding a mapping while the IOMMU type is `None` returns
///   [`Error::InvalidArgument`].
pub struct VfioContainer {
    /// Container identifier.
    pub id: u32,
    /// Selected IOMMU type.
    pub iommu_type: IommuType,
    /// IOMMU groups bound to this container.
    groups: [Option<VfioGroup>; MAX_GROUPS],
    /// Number of bound groups.
    group_count: usize,
    /// DMA mappings.
    dma_maps: [Option<VfioDmaMap>; MAX_DMA_MAPS],
    /// Number of active DMA mappings.
    dma_map_count: usize,
    /// Whether this container is open/active.
    pub active: bool,
}

impl VfioContainer {
    /// Creates a new container with the given `id`.
    pub fn new(id: u32) -> Self {
        Self {
            id,
            iommu_type: IommuType::None,
            groups: [const { None }; MAX_GROUPS],
            group_count: 0,
            dma_maps: [const { None }; MAX_DMA_MAPS],
            dma_map_count: 0,
            active: true,
        }
    }

    // -- IOMMU type selection -----------------------------------------------

    /// Sets the IOMMU type for this container.
    ///
    /// Can only be called when no groups are bound (`group_count == 0`).
    /// Returns [`Error::Busy`] if groups are already attached.
    /// Returns [`Error::InvalidArgument`] if `iommu_type` is `None`.
    pub fn set_iommu_type(&mut self, iommu_type: IommuType) -> Result<()> {
        if iommu_type == IommuType::None {
            return Err(Error::InvalidArgument);
        }
        if self.group_count > 0 {
            return Err(Error::Busy);
        }
        self.iommu_type = iommu_type;
        Ok(())
    }

    // -- Group management ---------------------------------------------------

    /// Adds an IOMMU group to this container.
    ///
    /// Requires that an IOMMU type has been selected.
    /// Returns [`Error::InvalidArgument`] if the IOMMU type is `None`.
    /// Returns [`Error::AlreadyExists`] if a group with the same id is
    /// already bound.
    /// Returns [`Error::OutOfMemory`] if [`MAX_GROUPS`] groups are bound.
    pub fn add_group(&mut self, group: VfioGroup) -> Result<()> {
        if self.iommu_type == IommuType::None {
            return Err(Error::InvalidArgument);
        }
        for slot in &self.groups {
            if let Some(ref g) = *slot {
                if g.group_id == group.group_id {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        for slot in &mut self.groups {
            if slot.is_none() {
                *slot = Some(group);
                self.group_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes the group with `group_id` from this container.
    ///
    /// Returns [`Error::NotFound`] if no such group is bound.
    pub fn remove_group(&mut self, group_id: u32) -> Result<()> {
        for slot in &mut self.groups {
            if let Some(ref g) = *slot {
                if g.group_id == group_id {
                    *slot = None;
                    self.group_count = self.group_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a shared reference to the group with `group_id`.
    pub fn get_group(&self, group_id: u32) -> Option<&VfioGroup> {
        self.groups
            .iter()
            .flatten()
            .find(|g| g.group_id == group_id)
    }

    /// Returns a mutable reference to the group with `group_id`.
    pub fn get_group_mut(&mut self, group_id: u32) -> Option<&mut VfioGroup> {
        self.groups
            .iter_mut()
            .flatten()
            .find(|g| g.group_id == group_id)
    }

    /// Returns the number of bound groups.
    pub const fn group_count(&self) -> usize {
        self.group_count
    }

    // -- DMA mapping --------------------------------------------------------

    /// Adds a DMA mapping (VFIO_IOMMU_MAP_DMA).
    ///
    /// Validates that:
    /// - The IOMMU type is not `None`.
    /// - `size` is greater than zero.
    /// - The IOVA range does not overlap with any existing active mapping.
    ///
    /// Returns [`Error::InvalidArgument`] for invalid arguments.
    /// Returns [`Error::AlreadyExists`] if the IOVA range overlaps.
    /// Returns [`Error::OutOfMemory`] if [`MAX_DMA_MAPS`] are exhausted.
    pub fn map_dma(&mut self, mapping: VfioDmaMap) -> Result<()> {
        if self.iommu_type == IommuType::None {
            return Err(Error::InvalidArgument);
        }
        if mapping.size == 0 {
            return Err(Error::InvalidArgument);
        }
        // Check for IOVA overlap with existing active mappings.
        for slot in self.dma_maps.iter().flatten() {
            if !slot.active {
                continue;
            }
            // Overlap check: [a.iova, a.iova_end) intersects [b.iova, b.iova_end)?
            if mapping.iova < slot.iova_end() && slot.iova < mapping.iova_end() {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.dma_maps {
            if slot.is_none() {
                *slot = Some(mapping);
                self.dma_map_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes the DMA mapping starting at `iova` (VFIO_IOMMU_UNMAP_DMA).
    ///
    /// Returns [`Error::NotFound`] if no active mapping starts at `iova`.
    pub fn unmap_dma(&mut self, iova: u64) -> Result<()> {
        for slot in &mut self.dma_maps {
            if let Some(ref m) = *slot {
                if m.active && m.iova == iova {
                    *slot = None;
                    self.dma_map_count = self.dma_map_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Finds the DMA mapping that covers `iova_addr`.
    ///
    /// Returns `None` if no active mapping contains the address.
    pub fn find_dma_map(&self, iova_addr: u64) -> Option<&VfioDmaMap> {
        self.dma_maps
            .iter()
            .flatten()
            .find(|m| m.active && m.contains_iova(iova_addr))
    }

    /// Translates an IOVA to a host physical address.
    ///
    /// Returns `None` if no mapping covers `iova_addr`.
    pub fn iova_to_phys(&self, iova_addr: u64) -> Option<u64> {
        self.find_dma_map(iova_addr)?.translate(iova_addr)
    }

    /// Returns the number of active DMA mappings.
    pub const fn dma_map_count(&self) -> usize {
        self.dma_map_count
    }

    // -- Ioctl dispatch -----------------------------------------------------

    /// Dispatches a VFIO container ioctl command.
    ///
    /// | Command | Argument semantics | Action |
    /// |---------|-------------------|--------|
    /// | `SetIommu` | `arg` = `IommuType` discriminant (1=Type1Dma, 2=SpaprTce) | Sets IOMMU type |
    /// | `MapDma` | `arg` = IOVA (physical address same as IOVA in stub) | Adds identity mapping (stub) |
    /// | `UnmapDma` | `arg` = IOVA to unmap | Removes mapping |
    /// | `GetInfo` | `arg` ignored | Returns `Ok(0)` |
    ///
    /// This is a simplified dispatch — a production driver would accept
    /// typed `ioctl_arg` structures via user-space pointers.
    pub fn ioctl(&mut self, cmd: VfioIoctl, arg: u64) -> Result<u64> {
        match cmd {
            VfioIoctl::SetIommu => {
                let iommu_type = match arg {
                    1 => IommuType::Type1Dma,
                    2 => IommuType::SpaprTce,
                    _ => return Err(Error::InvalidArgument),
                };
                self.set_iommu_type(iommu_type)?;
                Ok(0)
            }
            VfioIoctl::MapDma => {
                // Stub: map an identity IOVA=arg → phys=arg, 4 KiB, R/W.
                if arg == 0 {
                    return Err(Error::InvalidArgument);
                }
                let mapping = VfioDmaMap::new(arg, arg, 4096, DmaFlags::rw());
                self.map_dma(mapping)?;
                Ok(0)
            }
            VfioIoctl::UnmapDma => {
                self.unmap_dma(arg)?;
                Ok(0)
            }
            VfioIoctl::GetInfo => {
                // Return IOMMU type discriminant as info.
                let val = match self.iommu_type {
                    IommuType::None => 0u64,
                    IommuType::Type1Dma => 1u64,
                    IommuType::SpaprTce => 2u64,
                };
                Ok(val)
            }
        }
    }
}

impl core::fmt::Debug for VfioContainer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VfioContainer")
            .field("id", &self.id)
            .field("iommu_type", &self.iommu_type)
            .field("group_count", &self.group_count)
            .field("dma_map_count", &self.dma_map_count)
            .field("active", &self.active)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// VfioContainerRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_CONTAINERS`] active [`VfioContainer`]s.
///
/// Each container is keyed by its `id`.  The registry provides create,
/// destroy, and lookup operations.
pub struct VfioContainerRegistry {
    /// Container slots.
    containers: [Option<VfioContainer>; MAX_CONTAINERS],
    /// Number of active containers.
    count: usize,
    /// Next container id to assign (monotonically increasing).
    next_id: u32,
}

impl VfioContainerRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            containers: [const { None }; MAX_CONTAINERS],
            count: 0,
            next_id: 1,
        }
    }

    /// Creates a new container and returns its assigned id.
    ///
    /// Returns [`Error::OutOfMemory`] if [`MAX_CONTAINERS`] are active.
    pub fn create(&mut self) -> Result<u32> {
        if self.count >= MAX_CONTAINERS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        for slot in &mut self.containers {
            if slot.is_none() {
                *slot = Some(VfioContainer::new(id));
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Destroys the container with `id`.
    ///
    /// Returns [`Error::Busy`] if the container still has active groups
    /// or DMA mappings.
    /// Returns [`Error::NotFound`] if no container with `id` exists.
    pub fn destroy(&mut self, id: u32) -> Result<()> {
        for slot in &mut self.containers {
            if let Some(ref c) = *slot {
                if c.id == id {
                    if c.group_count > 0 || c.dma_map_count > 0 {
                        return Err(Error::Busy);
                    }
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a shared reference to the container with `id`.
    pub fn get(&self, id: u32) -> Option<&VfioContainer> {
        self.containers.iter().flatten().find(|c| c.id == id)
    }

    /// Returns a mutable reference to the container with `id`.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut VfioContainer> {
        self.containers.iter_mut().flatten().find(|c| c.id == id)
    }

    /// Returns the number of active containers.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no containers are active.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for VfioContainerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for VfioContainerRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VfioContainerRegistry")
            .field("count", &self.count)
            .field("next_id", &self.next_id)
            .finish()
    }
}
