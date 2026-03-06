// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IOMMU domain management.
//!
//! Provides IOMMU domain creation, device attachment, and IOVA-to-PA mapping
//! for DMA isolation. Supports identity-mapped and DMA-remapping domain types.
//!
//! # Domain Types
//!
//! - **Identity**: device physical addresses = IOVA (bypass mode)
//! - **DMA**: full IOVA translation via page tables
//! - **Unmanaged**: driver manages the page tables directly
//!
//! # IOVA Allocator
//!
//! A simple bitmap-based IOVA allocator manages 4 KiB page granularity
//! within a fixed IOVA address space window.
//!
//! Reference: Intel VT-d Specification, AMD-Vi Architecture Specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Page size used by IOMMU page tables (4 KiB).
pub const IOMMU_PAGE_SIZE: u64 = 4096;

/// Page shift (log2 of page size).
pub const IOMMU_PAGE_SHIFT: u32 = 12;

/// Page mask for aligning addresses.
pub const IOMMU_PAGE_MASK: u64 = !(IOMMU_PAGE_SIZE - 1);

/// Default IOVA space start (1 MiB, avoids identity-map conflicts).
pub const IOVA_SPACE_START: u64 = 0x0010_0000;

/// Default IOVA space end (4 GiB).
pub const IOVA_SPACE_END: u64 = 0xFFFF_F000;

/// Maximum number of pages tracked in the IOVA bitmap.
pub const IOVA_BITMAP_PAGES: usize = 1024;

/// Maximum number of devices attached to a single domain.
pub const DOMAIN_MAX_DEVICES: usize = 64;

/// Maximum number of IOMMU domains.
pub const MAX_DOMAINS: usize = 256;

/// Maximum domain ID value.
pub const DOMAIN_ID_MAX: u32 = 65535;

/// IOMMU capability: hardware cache coherency for DMA.
pub const IOMMU_CAP_CACHE_COHERENCY: u32 = 1 << 0;

/// IOMMU capability: hardware dirty tracking.
pub const IOMMU_CAP_DIRTY_TRACKING: u32 = 1 << 1;

/// IOMMU capability: large page (2 MiB) support.
pub const IOMMU_CAP_HUGE_PAGE: u32 = 1 << 2;

/// IOMMU capability: nested translation support.
pub const IOMMU_CAP_NESTED: u32 = 1 << 3;

/// IOMMU capability: PASID (process address space ID) support.
pub const IOMMU_CAP_PASID: u32 = 1 << 4;

// ---------------------------------------------------------------------------
// Page Table Entry
// ---------------------------------------------------------------------------

/// IOMMU page table entry flags.
pub const IOPTE_PRESENT: u64 = 1 << 0;
/// Read permission.
pub const IOPTE_READ: u64 = 1 << 1;
/// Write permission.
pub const IOPTE_WRITE: u64 = 1 << 2;
/// Execute permission.
pub const IOPTE_EXEC: u64 = 1 << 3;
/// Accessed bit (set by hardware on access).
pub const IOPTE_ACCESSED: u64 = 1 << 8;
/// Dirty bit (set by hardware on write).
pub const IOPTE_DIRTY: u64 = 1 << 9;
/// Physical address mask (bits 51:12 for 4-KiB pages).
pub const IOPTE_PFN_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// An IOMMU page table entry.
///
/// Contains a physical frame number and access flags for a mapped IOVA page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct IoPte(pub u64);

impl IoPte {
    /// Creates a new invalid (not-present) PTE.
    pub const fn invalid() -> Self {
        Self(0)
    }

    /// Creates a new PTE mapping `phys_addr` with `flags`.
    pub fn new(phys_addr: u64, flags: u64) -> Self {
        Self((phys_addr & IOPTE_PFN_MASK) | flags | IOPTE_PRESENT)
    }

    /// Returns whether this PTE is present (valid).
    pub fn is_present(self) -> bool {
        self.0 & IOPTE_PRESENT != 0
    }

    /// Returns whether this PTE grants read access.
    pub fn is_readable(self) -> bool {
        self.0 & IOPTE_READ != 0
    }

    /// Returns whether this PTE grants write access.
    pub fn is_writable(self) -> bool {
        self.0 & IOPTE_WRITE != 0
    }

    /// Returns the physical address from this PTE.
    pub fn phys_addr(self) -> u64 {
        self.0 & IOPTE_PFN_MASK
    }

    /// Sets the accessed bit.
    pub fn set_accessed(&mut self) {
        self.0 |= IOPTE_ACCESSED;
    }

    /// Sets the dirty bit.
    pub fn set_dirty(&mut self) {
        self.0 |= IOPTE_DIRTY;
    }

    /// Clears this PTE (marks not-present).
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

// ---------------------------------------------------------------------------
// Domain Types
// ---------------------------------------------------------------------------

/// IOMMU domain type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainType {
    /// Identity-mapped: DMA addresses equal physical addresses.
    Identity,
    /// DMA-remapping: full IOVA-to-PA translation via page tables.
    Dma,
    /// Unmanaged: caller manages page tables directly.
    Unmanaged,
}

// ---------------------------------------------------------------------------
// BDF (Bus:Device:Function) identifier
// ---------------------------------------------------------------------------

/// PCI Bus:Device:Function identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bdf {
    /// PCI bus number (0-255).
    pub bus: u8,
    /// Device number (0-31).
    pub device: u8,
    /// Function number (0-7).
    pub function: u8,
}

impl Bdf {
    /// Creates a new BDF identifier.
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    /// Returns the BDF packed into a 16-bit value (bus[15:8], dev[7:3], fn[2:0]).
    pub fn to_u16(self) -> u16 {
        ((self.bus as u16) << 8) | ((self.device as u16) << 3) | (self.function as u16)
    }

    /// Creates a BDF from a packed 16-bit value.
    pub fn from_u16(val: u16) -> Self {
        Self {
            bus: (val >> 8) as u8,
            device: ((val >> 3) & 0x1F) as u8,
            function: (val & 0x07) as u8,
        }
    }
}

// ---------------------------------------------------------------------------
// IOVA Bitmap Allocator
// ---------------------------------------------------------------------------

/// Simple bitmap-based IOVA page allocator.
///
/// Tracks a window of `IOVA_BITMAP_PAGES` pages using a flat bitmap.
/// Each bit represents one 4-KiB page of IOVA space.
pub struct IovaAllocator {
    /// Bitmap: bit N set = page N is allocated.
    bitmap: [u64; IOVA_BITMAP_PAGES / 64],
    /// Base IOVA address for page 0.
    base: u64,
    /// Number of free pages remaining.
    free_pages: usize,
}

impl IovaAllocator {
    /// Creates a new IOVA allocator starting at `base`.
    pub const fn new(base: u64) -> Self {
        Self {
            bitmap: [0u64; IOVA_BITMAP_PAGES / 64],
            base,
            free_pages: IOVA_BITMAP_PAGES,
        }
    }

    /// Allocates `npages` contiguous IOVA pages.
    ///
    /// Returns the starting IOVA on success.
    pub fn alloc(&mut self, npages: usize) -> Result<u64> {
        if npages == 0 || npages > self.free_pages {
            return Err(Error::OutOfMemory);
        }

        // Linear scan for `npages` contiguous free pages.
        let mut run_start = 0usize;
        let mut run_len = 0usize;

        for i in 0..IOVA_BITMAP_PAGES {
            if !self.is_allocated(i) {
                if run_len == 0 {
                    run_start = i;
                }
                run_len += 1;
                if run_len >= npages {
                    // Found a sufficient run — mark all pages as allocated.
                    for j in run_start..run_start + npages {
                        self.set_bit(j);
                    }
                    self.free_pages -= npages;
                    return Ok(self.base + (run_start as u64) * IOMMU_PAGE_SIZE);
                }
            } else {
                run_len = 0;
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Frees `npages` pages starting at IOVA `addr`.
    pub fn free(&mut self, addr: u64, npages: usize) -> Result<()> {
        if addr < self.base {
            return Err(Error::InvalidArgument);
        }
        let start_page = ((addr - self.base) / IOMMU_PAGE_SIZE) as usize;
        if start_page + npages > IOVA_BITMAP_PAGES {
            return Err(Error::InvalidArgument);
        }
        for i in start_page..start_page + npages {
            if !self.is_allocated(i) {
                return Err(Error::InvalidArgument);
            }
            self.clear_bit(i);
        }
        self.free_pages += npages;
        Ok(())
    }

    /// Returns the number of free pages.
    pub fn free_pages(&self) -> usize {
        self.free_pages
    }

    fn is_allocated(&self, page: usize) -> bool {
        let word = page / 64;
        let bit = page % 64;
        self.bitmap[word] & (1u64 << bit) != 0
    }

    fn set_bit(&mut self, page: usize) {
        let word = page / 64;
        let bit = page % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    fn clear_bit(&mut self, page: usize) {
        let word = page / 64;
        let bit = page % 64;
        self.bitmap[word] &= !(1u64 << bit);
    }
}

// ---------------------------------------------------------------------------
// IOMMU Mapping Entry
// ---------------------------------------------------------------------------

/// A single IOMMU mapping (IOVA range → physical range).
#[derive(Debug, Clone, Copy)]
pub struct IoMapping {
    /// Starting IOVA for this mapping.
    pub iova: u64,
    /// Starting physical address.
    pub phys: u64,
    /// Length in bytes.
    pub length: u64,
    /// Access flags (IOPTE_READ | IOPTE_WRITE etc.).
    pub flags: u64,
}

impl IoMapping {
    /// Creates a new mapping entry.
    pub const fn new(iova: u64, phys: u64, length: u64, flags: u64) -> Self {
        Self {
            iova,
            phys,
            length,
            flags,
        }
    }

    /// Returns true if `iova` falls within this mapping.
    pub fn contains_iova(&self, iova: u64) -> bool {
        iova >= self.iova && iova < self.iova + self.length
    }

    /// Translates an IOVA within this mapping to a physical address.
    pub fn iova_to_phys(&self, iova: u64) -> Option<u64> {
        if self.contains_iova(iova) {
            Some(self.phys + (iova - self.iova))
        } else {
            None
        }
    }
}

/// Maximum number of active mappings per domain.
pub const DOMAIN_MAX_MAPPINGS: usize = 256;

// ---------------------------------------------------------------------------
// IOMMU Domain
// ---------------------------------------------------------------------------

/// An IOMMU domain representing an isolated DMA address space.
///
/// Devices attached to the same domain share an IOVA space and page tables.
/// The domain tracks attached BDFs and active IOVA-to-PA mappings.
pub struct IommuDomain {
    /// Unique domain identifier.
    pub domain_id: u32,
    /// Domain type (Identity, DMA, or Unmanaged).
    pub domain_type: DomainType,
    /// Capability flags supported for this domain.
    capabilities: u32,
    /// IOVA allocator for this domain.
    iova_alloc: IovaAllocator,
    /// Active mappings in this domain.
    mappings: [Option<IoMapping>; DOMAIN_MAX_MAPPINGS],
    /// Number of active mappings.
    mapping_count: usize,
    /// BDFs of devices attached to this domain.
    attached_devices: [Option<Bdf>; DOMAIN_MAX_DEVICES],
    /// Number of attached devices.
    device_count: usize,
}

impl IommuDomain {
    /// Creates a new IOMMU domain of the given type.
    pub fn new(domain_id: u32, domain_type: DomainType) -> Self {
        const EMPTY_MAPPING: Option<IoMapping> = None;
        const EMPTY_BDF: Option<Bdf> = None;
        Self {
            domain_id,
            domain_type,
            capabilities: IOMMU_CAP_CACHE_COHERENCY,
            iova_alloc: IovaAllocator::new(IOVA_SPACE_START),
            mappings: [EMPTY_MAPPING; DOMAIN_MAX_MAPPINGS],
            mapping_count: 0,
            attached_devices: [EMPTY_BDF; DOMAIN_MAX_DEVICES],
            device_count: 0,
        }
    }

    /// Enables a capability flag for this domain.
    pub fn set_capability(&mut self, cap: u32) {
        self.capabilities |= cap;
    }

    /// Returns whether the given capability is supported.
    pub fn has_capability(&self, cap: u32) -> bool {
        self.capabilities & cap != 0
    }

    // -----------------------------------------------------------------------
    // Device Attachment
    // -----------------------------------------------------------------------

    /// Attaches a device (identified by BDF) to this domain.
    ///
    /// After attachment, DMA from the device will be subject to this domain's
    /// page tables and IOVA address space.
    pub fn attach_device(&mut self, bdf: Bdf) -> Result<()> {
        // Check for duplicate.
        for entry in self.attached_devices[..self.device_count].iter() {
            if let Some(existing) = entry {
                if *existing == bdf {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        if self.device_count >= DOMAIN_MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        self.attached_devices[self.device_count] = Some(bdf);
        self.device_count += 1;
        Ok(())
    }

    /// Detaches a device from this domain.
    pub fn detach_device(&mut self, bdf: Bdf) -> Result<()> {
        for i in 0..self.device_count {
            if self.attached_devices[i] == Some(bdf) {
                // Shift remaining entries down.
                for j in i..self.device_count - 1 {
                    self.attached_devices[j] = self.attached_devices[j + 1];
                }
                self.attached_devices[self.device_count - 1] = None;
                self.device_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of devices attached to this domain.
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    /// Returns true if the given BDF is attached to this domain.
    pub fn is_device_attached(&self, bdf: Bdf) -> bool {
        self.attached_devices[..self.device_count]
            .iter()
            .any(|e| *e == Some(bdf))
    }

    // -----------------------------------------------------------------------
    // Mapping Operations
    // -----------------------------------------------------------------------

    /// Maps a physical memory region into the IOVA space.
    ///
    /// Allocates IOVA pages from the internal allocator and records the mapping.
    /// Returns the allocated IOVA base address.
    pub fn map(&mut self, phys: u64, length: u64, flags: u64) -> Result<u64> {
        if length == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.mapping_count >= DOMAIN_MAX_MAPPINGS {
            return Err(Error::OutOfMemory);
        }
        let npages = ((length + IOMMU_PAGE_SIZE - 1) / IOMMU_PAGE_SIZE) as usize;
        let iova = match self.domain_type {
            DomainType::Identity => phys,
            DomainType::Dma | DomainType::Unmanaged => self.iova_alloc.alloc(npages)?,
        };
        self.mappings[self.mapping_count] = Some(IoMapping::new(iova, phys, length, flags));
        self.mapping_count += 1;
        Ok(iova)
    }

    /// Unmaps the IOVA region starting at `iova`.
    pub fn unmap(&mut self, iova: u64) -> Result<()> {
        for i in 0..self.mapping_count {
            if let Some(m) = self.mappings[i] {
                if m.iova == iova {
                    let npages = ((m.length + IOMMU_PAGE_SIZE - 1) / IOMMU_PAGE_SIZE) as usize;
                    if self.domain_type == DomainType::Dma {
                        self.iova_alloc.free(iova, npages)?;
                    }
                    // Shift remaining mappings down.
                    for j in i..self.mapping_count - 1 {
                        self.mappings[j] = self.mappings[j + 1];
                    }
                    self.mappings[self.mapping_count - 1] = None;
                    self.mapping_count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Translates an IOVA to its corresponding physical address.
    pub fn iova_to_phys(&self, iova: u64) -> Result<u64> {
        for entry in self.mappings[..self.mapping_count].iter() {
            if let Some(m) = entry {
                if let Some(phys) = m.iova_to_phys(iova) {
                    return Ok(phys);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of active mappings.
    pub fn mapping_count(&self) -> usize {
        self.mapping_count
    }

    /// Returns the number of free IOVA pages in the allocator.
    pub fn free_iova_pages(&self) -> usize {
        self.iova_alloc.free_pages()
    }
}

// ---------------------------------------------------------------------------
// Fault Handler
// ---------------------------------------------------------------------------

/// IOMMU fault information.
#[derive(Debug, Clone, Copy)]
pub struct IommuFault {
    /// The IOVA that caused the fault.
    pub iova: u64,
    /// The BDF of the faulting device.
    pub bdf: Bdf,
    /// Whether the fault was caused by a write (true) or read (false).
    pub is_write: bool,
    /// Domain ID associated with the faulting device.
    pub domain_id: u32,
}

impl IommuFault {
    /// Creates a new fault record.
    pub const fn new(iova: u64, bdf: Bdf, is_write: bool, domain_id: u32) -> Self {
        Self {
            iova,
            bdf,
            is_write,
            domain_id,
        }
    }
}

/// Maximum number of fault records kept in the ring.
pub const FAULT_LOG_SIZE: usize = 32;

/// IOMMU fault log ring buffer.
pub struct FaultLog {
    entries: [Option<IommuFault>; FAULT_LOG_SIZE],
    head: usize,
    count: u64,
}

impl FaultLog {
    /// Creates an empty fault log.
    pub const fn new() -> Self {
        const EMPTY: Option<IommuFault> = None;
        Self {
            entries: [EMPTY; FAULT_LOG_SIZE],
            head: 0,
            count: 0,
        }
    }

    /// Records a new fault.
    pub fn record(&mut self, fault: IommuFault) {
        self.entries[self.head] = Some(fault);
        self.head = (self.head + 1) % FAULT_LOG_SIZE;
        self.count += 1;
    }

    /// Returns the total number of faults recorded.
    pub fn total_faults(&self) -> u64 {
        self.count
    }

    /// Returns a reference to the fault entry at `index`.
    pub fn get(&self, index: usize) -> Option<&IommuFault> {
        self.entries[index].as_ref()
    }
}

// ---------------------------------------------------------------------------
// Domain Registry
// ---------------------------------------------------------------------------

/// Global IOMMU domain registry.
pub struct IommuDomainRegistry {
    domains: [Option<IommuDomain>; MAX_DOMAINS],
    count: usize,
    next_id: u32,
    fault_log: FaultLog,
    global_caps: u32,
}

impl IommuDomainRegistry {
    /// Creates a new empty domain registry.
    pub const fn new() -> Self {
        const EMPTY: Option<IommuDomain> = None;
        Self {
            domains: [EMPTY; MAX_DOMAINS],
            count: 0,
            next_id: 1,
            fault_log: FaultLog::new(),
            global_caps: 0,
        }
    }

    /// Sets the global IOMMU hardware capabilities.
    pub fn set_capabilities(&mut self, caps: u32) {
        self.global_caps = caps;
    }

    /// Returns the global IOMMU hardware capabilities.
    pub fn capabilities(&self) -> u32 {
        self.global_caps
    }

    /// Creates and registers a new domain of the given type.
    ///
    /// Returns the domain ID on success.
    pub fn create_domain(&mut self, domain_type: DomainType) -> Result<u32> {
        if self.count >= MAX_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        if self.next_id > DOMAIN_ID_MAX {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.domains[self.count] = Some(IommuDomain::new(id, domain_type));
        self.count += 1;
        Ok(id)
    }

    /// Returns a mutable reference to the domain with the given ID.
    pub fn get_domain_mut(&mut self, domain_id: u32) -> Result<&mut IommuDomain> {
        for entry in self.domains[..self.count].iter_mut() {
            if let Some(d) = entry {
                if d.domain_id == domain_id {
                    return Ok(d);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns an immutable reference to the domain with the given ID.
    pub fn get_domain(&self, domain_id: u32) -> Result<&IommuDomain> {
        for entry in self.domains[..self.count].iter() {
            if let Some(d) = entry {
                if d.domain_id == domain_id {
                    return Ok(d);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Destroys the domain with the given ID.
    pub fn destroy_domain(&mut self, domain_id: u32) -> Result<()> {
        for i in 0..self.count {
            if self.domains[i]
                .as_ref()
                .map_or(false, |d| d.domain_id == domain_id)
            {
                for j in i..self.count - 1 {
                    self.domains.swap(j, j + 1);
                }
                self.domains[self.count - 1] = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Records an IOMMU fault.
    pub fn record_fault(&mut self, fault: IommuFault) {
        self.fault_log.record(fault);
    }

    /// Returns a reference to the fault log.
    pub fn fault_log(&self) -> &FaultLog {
        &self.fault_log
    }

    /// Returns the number of active domains.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no domains are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
